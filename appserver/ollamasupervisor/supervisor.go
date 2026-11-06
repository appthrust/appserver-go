// Package ollamasupervisor owns an Ollama child and model readiness.
package ollamasupervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

// Config supplies the process and model-specific warm-up. Warmup must return nil
// only after a successful inference with the baked model. An empty Bin monitors
// an external upstream without spawning or signalling a process.
type Config struct {
	Bin          string
	Upstream     string
	ExtraEnv     []string
	Client       *http.Client
	Warmup       func(context.Context, *http.Client, string) error
	PollInterval time.Duration
}

// Supervisor owns one process lifecycle. Run must be called only once; Ready is
// safe to call concurrently. The caller owns HTTP draining before cancelling Run.
type Supervisor struct {
	bin          string
	upstream     string
	extraEnv     []string
	client       *http.Client
	warmup       func(context.Context, *http.Client, string) error
	threads      int
	alive        atomic.Bool
	warmed       atomic.Bool
	pollInterval time.Duration
	restartDelay time.Duration
	stopTimeout  time.Duration
}

// New constructs an initially unready supervisor. A nil Client uses a
// redirect-disabled, 300-second client; a missing Warmup never becomes ready.
// Nonpositive PollInterval uses one second.
func New(cfg Config) *Supervisor {
	client := cfg.Client
	if client == nil {
		client = &http.Client{
			Timeout: 300 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	interval := cfg.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	return &Supervisor{
		bin: cfg.Bin, upstream: cfg.Upstream, extraEnv: cfg.ExtraEnv,
		client: client, warmup: cfg.Warmup, threads: cpuThreads(os.ReadFile),
		pollInterval: interval, restartDelay: time.Second, stopTimeout: 10 * time.Second,
	}
}

// Ready reports whether the current lifecycle is healthy and warmed.
func (s *Supervisor) Ready() bool { return s.alive.Load() && s.warmed.Load() }

// Run owns the child and does not return until shutdown has reaped it. The
// external-upstream mode uses the same health/warm-up loop without a child.
func (s *Supervisor) Run(ctx context.Context) {
	defer s.alive.Store(false)
	defer s.warmed.Store(false)
	if s.bin == "" {
		s.alive.Store(true)
		s.monitor(ctx)
		return
	}
	backoff := s.restartDelay
	for ctx.Err() == nil {
		cmd := exec.Command(s.bin, "serve")
		cmd.Env = append(os.Environ(), s.extraEnv...)
		cmd.Env = append(cmd.Env,
			"OLLAMA_HOST=127.0.0.1:11434",
			"OLLAMA_KEEP_ALIVE=-1",
			"OLLAMA_NO_CLOUD=1",
			"OLLAMA_NUM_PARALLEL=1",
			"OLLAMA_MAX_LOADED_MODELS=1",
			"LLAMA_ARG_THREADS="+strconv.Itoa(s.threads),
		)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		// Ollama starts model runners; signal the entire child process group so
		// none outlive the Go entrypoint, including after an Ollama crash.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		started := time.Now()
		if err := cmd.Start(); err != nil {
			log.Printf("starting ollama: %v", err)
		} else {
			s.alive.Store(true)
			childCtx, cancel := context.WithCancel(ctx)
			monitored := make(chan struct{})
			go func() {
				defer close(monitored)
				s.monitor(childCtx)
			}()
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()
			select {
			case err := <-exited:
				s.alive.Store(false)
				// A dead parent cannot clean up its model runners.
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				log.Printf("ollama exited: %v", err)
			case <-ctx.Done():
				s.alive.Store(false)
				cancel()
				s.stop(cmd, exited)
			}
			cancel()
			<-monitored
			s.warmed.Store(false)
			if time.Since(started) >= time.Minute {
				backoff = s.restartDelay
			}
		}
		if !waitContext(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (s *Supervisor) stop(cmd *exec.Cmd, exited <-chan error) {
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(s.stopTimeout)
	defer timer.Stop()
	select {
	case <-exited:
	case <-timer.C:
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-exited
	}
	// The parent may exit before a runner. Reclaim only our process group.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func (s *Supervisor) monitor(ctx context.Context) {
	defer s.warmed.Store(false)
	for ctx.Err() == nil {
		if err := s.probe(ctx); err != nil {
			s.warmed.Store(false)
		} else if !s.warmed.Load() {
			var err error
			if s.warmup == nil {
				err = errors.New("model warm-up is required")
			} else {
				err = s.warmup(ctx, s.client, s.upstream)
			}
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("warming ollama model: %v", err)
				}
			} else if ctx.Err() == nil {
				s.warmed.Store(true)
				log.Printf("ollama model ready (threads=%d)", s.threads)
			}
		}
		if !waitContext(ctx, s.pollInterval) {
			return
		}
	}
}

func (s *Supervisor) probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.upstream+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama health returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func waitContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}
