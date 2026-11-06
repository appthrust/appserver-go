// Package testutil provides isolated schemas for opt-in Postgres tests.
package testutil

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

func Database[T interface{ Close() error }](t *testing.T, open func(context.Context, string) (T, error)) (T, string) {
	t.Helper()
	dsn := os.Getenv("BUILTIN_APPSERVER_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("BUILDER_CONSOLE_TEST_DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("BUILTIN_APPSERVER_TEST_DATABASE_URL (or BUILDER_CONSOLE_TEST_DATABASE_URL) is unset; Postgres integration test skipped")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("Test database URL must be a postgres:// URL")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	schema := "builtin_app_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+pq.QuoteIdentifier(schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(ctx, `DROP SCHEMA `+pq.QuoteIdentifier(schema)+` CASCADE`); err != nil {
			t.Errorf("clean isolated test schema: %v", err)
		}
	})
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	database, err := open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database, parsed.String()
}
