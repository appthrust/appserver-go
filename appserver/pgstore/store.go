// Package pgstore provides project-local Postgres transactions and embedded migrations.
package pgstore

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/lib/pq"
)

// Store owns one built-in app database; callers supply their own embedded migration set.
type Store struct{ db *sql.DB }
type Tx struct {
	SQL     *sql.Tx
	Context context.Context
}

func Open(ctx context.Context, dsn string, migrations fs.FS, migrationTable string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	s := &Store{db: db}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrate(ctx, migrations, migrationTable); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// All catalog writers share a transaction-scoped lock, making path allocation,
// group moves, permission checks and their dependent writes one atomic operation.
// Readers use a consistent snapshot without blocking writers.
func (s *Store) Do(ctx context.Context, write bool, fn func(*Tx) error) error {
	options := &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: !write}
	if write {
		options.Isolation = sql.LevelReadCommitted
	}
	tx, err := s.db.BeginTx(ctx, options)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if write {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(170106, 1)`); err != nil {
			return err
		}
	}
	if err := fn(&Tx{SQL: tx, Context: ctx}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) migrate(ctx context.Context, migrations fs.FS, migrationTable string) error {
	table := pq.QuoteIdentifier(migrationTable)
	return s.Do(ctx, true, func(tx *Tx) error {
		if err := tx.Exec(`CREATE TABLE IF NOT EXISTS ` + table + ` (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
			return err
		}
		entries, err := fs.ReadDir(migrations, "migrations")
		if err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			var applied bool
			if err := tx.SQL.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM `+table+` WHERE version=$1)`, entry.Name()).Scan(&applied); err != nil {
				return err
			}
			if applied {
				continue
			}
			source, err := fs.ReadFile(migrations, "migrations/"+entry.Name())
			if err != nil {
				return err
			}
			if err := tx.Exec(string(source)); err != nil {
				return fmt.Errorf("migration %s: %w", entry.Name(), err)
			}
			if err := tx.Exec(`INSERT INTO `+table+`(version) VALUES($1)`, entry.Name()); err != nil {
				return err
			}
		}
		return nil
	})
}

func (t *Tx) Exec(query string, args ...any) error {
	_, err := t.SQL.ExecContext(t.Context, query, args...)
	return err
}
