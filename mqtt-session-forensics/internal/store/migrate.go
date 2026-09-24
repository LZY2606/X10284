package store

import (
	"database/sql"
	"fmt"
)

// Migrate upgrades an old database. Old versions are never rewritten; the
// migration only adds missing bookkeeping so historical versions stay readable.
func Migrate(db *sql.DB, from, to int) error {
	if from < 2 {
		// v1 -> v2: reports table (derived propagation reports) was added.
		if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS reports (
		  branch TEXT NOT NULL, version INTEGER NOT NULL, report TEXT NOT NULL,
		  PRIMARY KEY (branch, version))`); err != nil {
			return fmt.Errorf("migration v1->v2: %w", err)
		}
	}
	if _, err := db.Exec(`UPDATE schema_meta SET value=? WHERE key='schema_version'`, fmt.Sprint(to)); err != nil {
		return err
	}
	return nil
}

// SchemaVersion reports the stored schema version.
func (s *Store) SchemaVersion() (int, error) {
	var v int
	err := s.db.QueryRow(`SELECT value FROM schema_meta WHERE key='schema_version'`).Scan(&v)
	return v, err
}
