// Package releaseidentity serves app artifact identity from environment
// values or a mounted release file. Delivery identity is not injected into apps.
package releaseidentity

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/appthrust/appserver-go/appserver/httpx"
)

// NewHandler snapshots <prefix>_{RELEASE_VERSION,ARTIFACT_DIGEST}, optional
// <prefix>_SOURCE_REVISION and <prefix>_RELEASE_FILE. Version and digest together
// take precedence over the file, which is otherwise read verbatim per request.
// The caller supplies its error envelope.
func NewHandler(prefix string, unavailable http.HandlerFunc) http.Handler {
	release, complete, file := snapshot(prefix)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if complete {
			httpx.WriteJSON(w, http.StatusOK, release)
			return
		}
		if file != "" {
			if stamp, err := os.ReadFile(file); err == nil {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(stamp)
				return
			}
		}
		unavailable(w, r)
	})
}

// HealthIdentity uses the same environment/file precedence as /releasez.
// The returned function contains no workload or caller credentials.
func HealthIdentity(prefix string) func() (digest, version string) {
	release, complete, file := snapshot(prefix)
	return func() (string, string) {
		if complete {
			return release["artifactDigest"], release["releaseVersion"]
		}
		var stamp map[string]string
		if file != "" {
			if body, err := os.ReadFile(file); err == nil && json.Unmarshal(body, &stamp) == nil {
				return stamp["artifactDigest"], stamp["releaseVersion"]
			}
		}
		return "", ""
	}
}

func snapshot(prefix string) (map[string]string, bool, string) {
	release := map[string]string{
		"releaseVersion": os.Getenv(prefix + "_RELEASE_VERSION"),
		"artifactDigest": os.Getenv(prefix + "_ARTIFACT_DIGEST"),
	}
	if revision := os.Getenv(prefix + "_SOURCE_REVISION"); revision != "" {
		release["sourceRevision"] = revision
	}
	complete := release["releaseVersion"] != "" && release["artifactDigest"] != ""
	return release, complete, os.Getenv(prefix + "_RELEASE_FILE")
}
