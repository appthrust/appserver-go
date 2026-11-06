package releaseidentity

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompleteArtifactIdentityWinsAndIsSnapshotted(t *testing.T) {
	file := filepath.Join(t.TempDir(), "release.json")
	require.NoError(t, os.WriteFile(file, []byte(`{"sourceRevision":"file-revision"}`), 0600))
	for key, value := range map[string]string{
		"TEST_RELEASE_VERSION": "release",
		"TEST_SOURCE_REVISION": "revision",
		"TEST_ARTIFACT_DIGEST": "digest",
		"TEST_RELEASE_FILE":    file,
	} {
		t.Setenv(key, value)
	}
	handler := NewHandler("TEST", func(http.ResponseWriter, *http.Request) {
		t.Fatal("complete artifact identity is unavailable")
	})
	t.Setenv("TEST_SOURCE_REVISION", "")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/releasez", nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.JSONEq(t, `{"releaseVersion":"release","sourceRevision":"revision","artifactDigest":"digest"}`, w.Body.String())
}

func TestIncompleteArtifactIdentityReadsFileVerbatimPerRequest(t *testing.T) {
	for _, missing := range []string{"RELEASE_VERSION", "ARTIFACT_DIGEST"} {
		t.Run(missing, func(t *testing.T) {
			for _, key := range []string{"RELEASE_VERSION", "SOURCE_REVISION", "ARTIFACT_DIGEST"} {
				t.Setenv("TEST_"+key, "present")
			}
			t.Setenv("TEST_"+missing, "")
			file := filepath.Join(t.TempDir(), "release.json")
			t.Setenv("TEST_RELEASE_FILE", file)
			handler := NewHandler("TEST", func(http.ResponseWriter, *http.Request) {
				t.Fatal("readable release file is unavailable")
			})
			// Both the incomplete identity and file path are captured at creation.
			t.Setenv("TEST_"+missing, "now-present")
			t.Setenv("TEST_RELEASE_FILE", file+".missing")
			for _, stamp := range []string{"{\n  \"sourceRevision\": \"file-revision\"\n}\n", "{\n  \"sourceRevision\": \"updated-revision\"\n}\n"} {
				require.NoError(t, os.WriteFile(file, []byte(stamp), 0600))
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/releasez", nil))
				require.Equal(t, http.StatusOK, w.Code)
				require.Equal(t, "application/json", w.Header().Get("Content-Type"))
				require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
				require.Equal(t, stamp, w.Body.String())
			}
		})
	}
}

func TestIncompleteArtifactIdentityUsesCallerUnavailableHandler(t *testing.T) {
	for _, file := range []string{"", filepath.Join(t.TempDir(), "missing.json")} {
		t.Run(file, func(t *testing.T) {
			for _, key := range []string{"RELEASE_VERSION", "SOURCE_REVISION", "ARTIFACT_DIGEST"} {
				t.Setenv("TEST_"+key, "")
			}
			t.Setenv("TEST_RELEASE_FILE", file)
			request := httptest.NewRequest(http.MethodGet, "/releasez", nil)
			called := false
			handler := NewHandler("TEST", func(w http.ResponseWriter, r *http.Request) {
				called = true
				require.Same(t, request, r)
				http.Error(w, "release status unavailable", http.StatusServiceUnavailable)
			})
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, request)
			require.True(t, called)
			require.Equal(t, http.StatusServiceUnavailable, w.Code)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.Equal(t, "release status unavailable\n", w.Body.String())
		})
	}
}

func TestHealthIdentityMatchesReleaseHandler(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "environment"}[complete], func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "release.json")
			require.NoError(t, os.WriteFile(file, []byte(`{"artifactDigest":"file-digest","releaseVersion":"file-version"}`), 0600))
			t.Setenv("TEST_RELEASE_FILE", file)
			t.Setenv("TEST_ARTIFACT_DIGEST", "env-digest")
			t.Setenv("TEST_RELEASE_VERSION", "env-version")
			t.Setenv("TEST_SOURCE_REVISION", "")
			if !complete {
				t.Setenv("TEST_ARTIFACT_DIGEST", "")
			}
			digest, version := HealthIdentity("TEST")()
			wantDigest, wantVersion := "file-digest", "file-version"
			if complete {
				wantDigest, wantVersion = "env-digest", "env-version"
			}
			require.Equal(t, wantDigest, digest)
			require.Equal(t, wantVersion, version)
			w := httptest.NewRecorder()
			NewHandler("TEST", func(http.ResponseWriter, *http.Request) { t.Fatal("release unavailable") }).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/releasez", nil))
			require.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func TestVersionAndDigestAreCompleteWithoutSourceRevision(t *testing.T) {
	t.Setenv("TEST_RELEASE_VERSION", "1.4.0")
	t.Setenv("TEST_ARTIFACT_DIGEST", "sha256:catalog-digest")
	t.Setenv("TEST_SOURCE_REVISION", "")
	t.Setenv("TEST_RELEASE_FILE", filepath.Join(t.TempDir(), "missing.json"))
	handler := NewHandler("TEST", func(http.ResponseWriter, *http.Request) {
		t.Fatal("catalog version and digest must be complete")
	})
	identity := HealthIdentity("TEST")
	t.Setenv("TEST_RELEASE_VERSION", "changed-after-snapshot")
	t.Setenv("TEST_ARTIFACT_DIGEST", "")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/releasez", nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, `{"releaseVersion":"1.4.0","artifactDigest":"sha256:catalog-digest"}`, w.Body.String())
	digest, version := identity()
	require.Equal(t, "sha256:catalog-digest", digest)
	require.Equal(t, "1.4.0", version)
}
