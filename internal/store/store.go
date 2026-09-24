// Package store is the SQLite-backed persistence layer.
//
// Invariants:
//   - Sources, rule versions and commits are append-only; nothing is overwritten.
//   - A derivation write is one transaction: node rows and the current-pointer
//     switch commit together, so a crash leaves either the old or the complete
//     new version, never a half-written graph.
//   - Concurrent commits from the same parent version are detected and one side
//     receives ErrConflict that it must resolve (never a silent overwrite).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	_ "modernc.org/sqlite"
)

// ErrConflict is returned when two commits fork from the same parent and both
// attempt to advance the pointer; the loser keeps its branch for resolution.
var ErrConflict = errors.New("store: conflicting commits from same parent")

// Store wraps a database handle.
type Store struct {
	db *sql.DB
	mu sync.Mutex // serialises writers within the process
}

// Open opens (creating if needed) the database at path and runs migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx,
		`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=10000; PRAGMA foreign_keys=ON;`); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// DB exposes the handle for migration seeding / export tooling.
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) migrate(ctx context.Context) error {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='schema_version'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := s.db.ExecContext(ctx, schemaV2); err != nil {
			return fmt.Errorf("create schema: %w", err)
		}
		return nil
	}
	if err != nil {
		if _, err2 := s.db.ExecContext(ctx, schemaV2); err2 != nil {
			return err2
		}
		return nil
	}
	switch v {
	case "1":
		if _, err := s.db.ExecContext(ctx, schemaV2Additions); err != nil {
			return fmt.Errorf("migrate v1->v2: %w", err)
		}
	case "2":
	default:
		return fmt.Errorf("store: unknown schema_version %q", v)
	}
	return nil
}

// Close releases the handle.
func (s *Store) Close() error { return s.db.Close() }

// WithTx runs fn inside a single transaction committed atomically.
func (s *Store) WithTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
