package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	_ "modernc.org/sqlite"
)

// Store wraps one SQLite database file.
type Store struct {
	db *sql.DB
}

const currentSchema = 2

// Open opens (creating if needed) the database and runs migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	var v int
	row := s.db.QueryRow(`SELECT value FROM schema_meta WHERE key='schema_version'`)
	switch err := row.Scan(&v); err {
	case nil:
		if v < currentSchema {
			if err := Migrate(s.db, v, currentSchema); err != nil {
				return err
			}
		}
	case sql.ErrNoRows:
		if _, err := s.db.Exec(`INSERT INTO schema_meta(key,value) VALUES('schema_version', ?)`,
			fmt.Sprint(currentSchema)); err != nil {
			return err
		}
		v = currentSchema
	default:
		return err
	}
	return nil
}

func (s *Store) Begin(ctx context.Context) (*sql.Tx, error) { return s.db.BeginTx(ctx, nil) }

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
