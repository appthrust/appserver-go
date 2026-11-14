package originguard_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/appthrust/appserver-go/appserver/httpx"
	"github.com/appthrust/appserver-go/appserver/originguard"
)

func TestCheckOriginWebSocketUpgrade(t *testing.T) {
	const origin = "https://dashboard.example.com"
	trusted, err := originguard.NewTrustedOrigins([]string{origin}, originguard.Options{})
	if err != nil {
		t.Fatal(err)
	}

	// A real signed credential accepted by the fixture authenticator, not merely
	// an Authorization header whose presence is treated as verification.
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("originguard HTTP/WebSocket test viewer")
	bearer := "Bearer " + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	authenticate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			signature, err := base64.RawURLEncoding.DecodeString(token)
			if !ok || err != nil || !ed25519.Verify(publicKey, message, signature) {
				httpx.WriteJSON(w, http.StatusUnauthorized, &httpx.Error{
					Code: "unauthorized", Message: "A valid bearer is required",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	for _, tc := range []struct {
		name          string
		method        string
		headers       http.Header
		unready       bool
		invalidBearer bool
		status        int
		reason        string
	}{
		{name: "legitimate browser upgrade", method: "GET", headers: http.Header{"Origin": {origin}, "Cookie": {"session=viewer"}, "Sec-Fetch-Site": {"same-origin"}}, status: 101},
		{name: "legitimate CLI upgrade with explicit origin", method: "GET", headers: http.Header{"Origin": {origin}}, status: 101},
		{name: "normalized legitimate origin", method: "GET", headers: http.Header{"Origin": {"HTTPS://DASHBOARD.EXAMPLE.COM:443"}}, status: 101},
		{name: "sibling with valid bearer", method: "GET", headers: http.Header{"Origin": {"https://preview.example.com"}, "Cookie": {"session=viewer"}, "Sec-Fetch-Site": {"same-site"}}, status: 403, reason: originguard.RequestOriginNotAllowed},
		{name: "evil external origin with valid bearer", method: "GET", headers: http.Header{"Origin": {"https://evil.test"}}, status: 403, reason: originguard.RequestOriginNotAllowed},
		{name: "null", method: "GET", headers: http.Header{"Origin": {"null"}}, status: 403, reason: originguard.RequestOriginNotAllowed},
		{name: "missing with cookie", method: "GET", headers: http.Header{"Cookie": {"session=viewer"}}, status: 403, reason: originguard.RequestOriginRequired},
		{name: "missing with fetch metadata", method: "GET", headers: http.Header{"Sec-Fetch-Site": {"same-origin"}}, status: 403, reason: originguard.RequestOriginRequired},
		{name: "missing with empty cookie", method: "GET", headers: http.Header{"Cookie": {""}}, status: 403, reason: originguard.RequestOriginRequired},
		{name: "missing with empty fetch metadata", method: "GET", headers: http.Header{"Sec-Fetch-Site": {""}}, status: 403, reason: originguard.RequestOriginRequired},
		{name: "CLI upgrade without origin", method: "GET", status: 403, reason: originguard.RequestOriginRequired},
		{name: "multiple origins", method: "GET", headers: http.Header{"Origin": {origin, "https://evil.test"}}, status: 403, reason: originguard.RequestOriginNotAllowed},
		{name: "duplicate trusted origin", method: "GET", headers: http.Header{"Origin": {origin, origin}}, status: 403, reason: originguard.RequestOriginNotAllowed},
		{name: "comma combined origins", method: "GET", headers: http.Header{"Origin": {origin + ",https://evil.test"}}, status: 403, reason: originguard.RequestOriginNotAllowed},
		{name: "other port", method: "GET", headers: http.Header{"Origin": {origin + ":8443"}}, status: 403, reason: originguard.RequestOriginNotAllowed},
		{name: "suffix spoof", method: "GET", headers: http.Header{"Origin": {origin + ".evil.test"}}, status: 403, reason: originguard.RequestOriginNotAllowed},
		{name: "empty origin", method: "GET", headers: http.Header{"Origin": {""}}, status: 403, reason: originguard.RequestOriginNotAllowed},
		{name: "unready snapshot", method: "GET", headers: http.Header{"Origin": {origin}}, unready: true, status: 503, reason: originguard.TrustedOriginsUnavailable},
		{name: "unready CLI upgrade", method: "GET", unready: true, status: 503, reason: originguard.TrustedOriginsUnavailable},
		{name: "trusted origin still needs valid bearer", method: "GET", headers: http.Header{"Origin": {origin}}, invalidBearer: true, status: 401, reason: "unauthorized"},
		{name: "CLI POST without browser metadata", method: "POST", status: 204},
		{name: "CLI POST still needs valid bearer", method: "POST", invalidBearer: true, status: 401, reason: "unauthorized"},
		{name: "sibling POST with valid bearer", method: "POST", headers: http.Header{"Origin": {"https://preview.example.com"}}, status: 403, reason: originguard.RequestOriginNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var source originguard.Snapshot
			if !tc.unready {
				source.Store(trusted)
			}
			var handlerCalls atomic.Int32
			upgrade := authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalls.Add(1)
				serveTestWebSocketUpgrade(t, w, r)
			}))
			mux := http.NewServeMux()
			mux.Handle("/ws", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// This is the consumer's mandatory upgrade check. Guard below
				// deliberately passes GET through; it cannot protect this route.
				origins, ready := source.Load()
				if !ready {
					httpx.WriteJSON(w, http.StatusServiceUnavailable, &httpx.Error{
						Code: originguard.TrustedOriginsUnavailable, Message: "Trusted request origins are not available",
					})
					return
				}
				decision := originguard.CheckOrigin(r.Header.Values("Origin"), origins)
				if !decision.Allowed {
					httpx.WriteJSON(w, http.StatusForbidden, &httpx.Error{
						Code: decision.Reason, Message: "A trusted request origin is required for WebSocket upgrades",
					})
					return
				}
				upgrade.ServeHTTP(w, r)
			}))
			mux.Handle("/mutation", authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handlerCalls.Add(1)
				w.WriteHeader(http.StatusNoContent)
			})))
			server := httptest.NewServer(originguard.Guard(mux, &source))
			defer server.Close()

			path := "/mutation"
			if tc.method == http.MethodGet {
				path = "/ws"
			}
			request, err := http.NewRequestWithContext(t.Context(), tc.method, server.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			for name, values := range tc.headers {
				request.Header[name] = values
			}
			request.Header.Set("Authorization", bearer)
			if tc.invalidBearer {
				request.Header.Set("Authorization", "Bearer invalid")
			}
			if tc.method == http.MethodGet {
				request.Header.Set("Connection", "Upgrade")
				request.Header.Set("Upgrade", "websocket")
				request.Header.Set("Sec-WebSocket-Version", "13")
				request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			}
			client := server.Client()
			client.Timeout = 5 * time.Second
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, tc.status)
			}
			wantCalls := int32(0)
			if tc.status == http.StatusSwitchingProtocols || tc.status == http.StatusNoContent {
				wantCalls = 1
			}
			if got := handlerCalls.Load(); got != wantCalls {
				t.Fatalf("protected handler calls = %d, want %d", got, wantCalls)
			}
			if tc.status == http.StatusSwitchingProtocols {
				if response.Header.Get("Connection") != "Upgrade" || response.Header.Get("Upgrade") != "websocket" || response.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
					t.Fatalf("invalid WebSocket handshake response: %v", response.Header)
				}
			} else if tc.reason != "" {
				var body httpx.Error
				if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body.Code != tc.reason || body.Message == "" {
					t.Fatalf("error = %+v, want %q and a message", body, tc.reason)
				}
				if response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Sec-WebSocket-Accept") != "" {
					t.Fatalf("invalid denial headers: %v", response.Header)
				}
			}
		})
	}
}

// A standard-library RFC 6455 handshake over a real TCP connection. No frames
// are needed to prove the origin decision precedes the protocol switch.
func serveTestWebSocketUpgrade(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	key := r.Header.Get("Sec-WebSocket-Key")
	nonce, err := base64.StdEncoding.DecodeString(key)
	if r.Method != http.MethodGet || r.Header.Get("Connection") != "Upgrade" || r.Header.Get("Upgrade") != "websocket" || r.Header.Get("Sec-WebSocket-Version") != "13" || err != nil || len(nonce) != 16 {
		t.Error("invalid WebSocket test handshake request")
		http.Error(w, "Invalid handshake", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		t.Error("HTTP server does not support hijacking")
		http.Error(w, "Cannot upgrade", http.StatusInternalServerError)
		return
	}
	conn, buffer, err := hijacker.Hijack()
	if err != nil {
		t.Errorf("hijack: %v", err)
		return
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Errorf("handshake deadline: %v", err)
		return
	}
	digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(digest[:])
	if _, err := fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		t.Errorf("write handshake: %v", err)
		return
	}
	if err := buffer.Flush(); err != nil {
		t.Errorf("flush handshake: %v", err)
	}
}
