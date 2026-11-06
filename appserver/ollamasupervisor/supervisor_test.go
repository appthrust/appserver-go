package ollamasupervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type helperEvent struct {
	Kind string            `json:"kind"`
	PID  int               `json:"pid"`
	Env  map[string]string `json:"env"`
}

func testWarmup(ctx context.Context, client *http.Client, upstream string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream+"/warm", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("warm-up returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// This test is also the fake ollama executable. The shell wrapper execs the
// current test binary, so tests exercise real process exit and signal handling
// without compiling a second program or depending on an installed Ollama.
func TestOllamaHelper(t *testing.T) {
	if os.Getenv("SUPERVISOR_TEST_OLLAMA") != "1" {
		return
	}
	if os.Args[len(os.Args)-1] != "serve" || os.Getenv("OLLAMA_HOST") != "127.0.0.1:11434" {
		fmt.Fprintln(os.Stderr, "helper requires serve and loopback OLLAMA_HOST")
		os.Exit(2)
	}
	event := func(kind string) {
		payload, _ := json.Marshal(helperEvent{Kind: kind, PID: os.Getpid(), Env: map[string]string{
			"LLAMA_ARG_THREADS":        os.Getenv("LLAMA_ARG_THREADS"),
			"LLAMA_ARG_CACHE_RAM":      os.Getenv("LLAMA_ARG_CACHE_RAM"),
			"OLLAMA_KEEP_ALIVE":        os.Getenv("OLLAMA_KEEP_ALIVE"),
			"OLLAMA_NO_CLOUD":          os.Getenv("OLLAMA_NO_CLOUD"),
			"OLLAMA_NUM_PARALLEL":      os.Getenv("OLLAMA_NUM_PARALLEL"),
			"OLLAMA_MAX_LOADED_MODELS": os.Getenv("OLLAMA_MAX_LOADED_MODELS"),
			"OLLAMA_CONTEXT_LENGTH":    os.Getenv("OLLAMA_CONTEXT_LENGTH"),
		}})
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Post(os.Getenv("SUPERVISOR_TEST_EVENTS"), "application/json", bytes.NewReader(payload))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		_ = resp.Body.Close()
	}
	terminated := make(chan os.Signal, 1)
	signal.Notify(terminated, syscall.SIGTERM)
	listener, err := net.Listen("tcp", os.Getenv("SUPERVISOR_TEST_LISTEN"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/tags", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"models":[]}`)
	})
	mux.HandleFunc("POST /warm", func(w http.ResponseWriter, _ *http.Request) {
		event("warm")
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	event("start")
	go func() { _ = server.Serve(listener) }()
	<-terminated
	event("term")
	_ = server.Close()
	os.Exit(0)
}

func TestSupervisorRestartsAndForwardsSIGTERM(t *testing.T) {
	events := make(chan helperEvent, 16)
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event helperEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Errorf("decoding helper event: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		events <- event
		w.WriteHeader(http.StatusNoContent)
	}))
	defer callback.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	executable, err := os.Executable()
	require.NoError(t, err)
	t.Setenv("SUPERVISOR_TEST_OLLAMA", "1")
	t.Setenv("SUPERVISOR_TEST_EXECUTABLE", executable)
	t.Setenv("SUPERVISOR_TEST_LISTEN", address)
	t.Setenv("SUPERVISOR_TEST_EVENTS", callback.URL)
	t.Setenv("LLAMA_ARG_THREADS", "999")
	t.Setenv("LLAMA_ARG_CACHE_RAM", "8192")
	t.Setenv("OLLAMA_KEEP_ALIVE", "0")
	t.Setenv("OLLAMA_NO_CLOUD", "0")
	t.Setenv("OLLAMA_NUM_PARALLEL", "999")
	t.Setenv("OLLAMA_MAX_LOADED_MODELS", "999")
	t.Setenv("OLLAMA_CONTEXT_LENGTH", "1")
	// The supervisor must replace an inherited externally bound Ollama host.
	t.Setenv("OLLAMA_HOST", "0.0.0.0:9999")
	script := filepath.Join(t.TempDir(), "ollama")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nexec \"$SUPERVISOR_TEST_EXECUTABLE\" -test.run '^TestOllamaHelper$' -- \"$@\"\n"), 0700))
	s := New(Config{
		Bin: script, Upstream: "http://" + address, Warmup: testWarmup,
		ExtraEnv: []string{"OLLAMA_CONTEXT_LENGTH=16384", "LLAMA_ARG_CACHE_RAM=1024"},
	})
	s.threads = 2
	s.pollInterval = 5 * time.Millisecond
	s.restartDelay = 200 * time.Millisecond
	s.stopTimeout = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("supervisor failed to stop")
		}
	}()
	nextEvent := func(kind string) helperEvent {
		t.Helper()
		select {
		case event := <-events:
			require.Equal(t, kind, event.Kind)
			return event
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s event from child", kind)
			return helperEvent{}
		}
	}
	first := nextEvent("start")
	require.Equal(t, map[string]string{
		"LLAMA_ARG_THREADS": "2", "LLAMA_ARG_CACHE_RAM": "1024", "OLLAMA_KEEP_ALIVE": "-1",
		"OLLAMA_NO_CLOUD":     "1",
		"OLLAMA_NUM_PARALLEL": "1", "OLLAMA_MAX_LOADED_MODELS": "1", "OLLAMA_CONTEXT_LENGTH": "16384",
	}, first.Env)
	require.Equal(t, first.PID, nextEvent("warm").PID)
	require.Eventually(t, s.Ready, 5*time.Second, time.Millisecond)
	crashed := time.Now()
	require.NoError(t, syscall.Kill(first.PID, syscall.SIGKILL))
	require.Eventually(t, func() bool { return !s.Ready() }, time.Second, time.Millisecond)
	second := nextEvent("start")
	require.NotEqual(t, first.PID, second.PID)
	require.Equal(t, first.Env, second.Env, "restarted child must retain its environment overrides")
	require.GreaterOrEqual(t, time.Since(crashed), s.restartDelay)
	require.Equal(t, second.PID, nextEvent("warm").PID)
	require.Eventually(t, s.Ready, 5*time.Second, time.Millisecond)
	cancel()
	require.Equal(t, second.PID, nextEvent("term").PID)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not reap terminated child")
	}
	require.False(t, s.Ready())
	require.ErrorIs(t, syscall.Kill(second.PID, 0), syscall.ESRCH)
	require.Empty(t, events, "shutdown must not restart Ollama")
}
