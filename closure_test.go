package appservergo_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestDependencyClosure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	list := func(args ...string) []string {
		t.Helper()
		command := exec.CommandContext(ctx, "go", append([]string{"list"}, args...)...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("go %s: %v\n%s", strings.Join(command.Args[1:], " "), err, output)
		}
		return strings.Fields(string(output))
	}

	standard := make(map[string]bool)
	for _, path := range list("std") {
		standard[path] = true
	}
	allowed := []string{
		"github.com/appthrust/appserver-go",
		"github.com/coreos/go-oidc/v3",
		"github.com/go-jose/go-jose/v4",
		"github.com/lib/pq",
		"github.com/google/uuid",
		"golang.org/x/oauth2",
		"k8s.io/apimachinery",
		"k8s.io/klog/v2",
		"github.com/go-logr/logr",
		"k8s.io/utils",
	}
	// This is the shipped package closure, not dependencies of copied tests.
	// Testify remains a test-only dependency and is not permitted at runtime.
	for _, path := range list("-deps", "-f", "{{.ImportPath}}", "./...") {
		if strings.HasPrefix(path, "github.com/appthrust/platform") {
			t.Errorf("SDK must not depend on platform: %s", path)
			continue
		}
		if standard[path] {
			continue
		}
		permitted := false
		for _, prefix := range allowed {
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				permitted = true
				break
			}
		}
		if !permitted {
			t.Errorf("SDK dependency is outside the reviewed allowlist: %s", path)
		}
	}
}
