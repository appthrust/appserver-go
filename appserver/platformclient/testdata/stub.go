// This loopback-only stub is for disposable console development, never deployment.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(401)
			return
		}
		var body any
		switch r.URL.Path {
		case "/api/v1/projects/pj-console-dev":
			body = map[string]any{"id": "pj-console-dev", "name": "Console development"}
		case "/api/v1/projects/pj-console-dev/access":
			body = map[string]any{"projectId": "pj-console-dev", "member": true, "role": "Admin", "platformRoles": []string{}}
		case "/api/v1/identity/search":
			if strings.TrimSpace(r.URL.Query().Get("q")) == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			body = []any{map[string]string{"issuer": "dev", "subject": "dev-admin", "email": "admin@example.test", "displayName": "Demo Admin"}}
		case "/api/v1/projects/pj-console-dev/source-connections":
			body = map[string]any{"data": []any{map[string]string{"id": "github-dev", "status": "ready"}}}
		case "/api/v1/registry-connections":
			body = map[string]any{"data": []any{map[string]string{"id": "registry-dev", "status": "ready"}}}
		default:
			w.WriteHeader(404)
			body = map[string]string{"error": "not_found"}
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	server := &http.Server{Addr: "127.0.0.1:55441", Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	log.Print("console platform stub listening on 127.0.0.1:55441")
	log.Fatal(server.ListenAndServe())
}
