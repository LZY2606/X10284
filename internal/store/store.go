// Package store provides the versioned SQLite persistence layer. Every
// mutation produces an immutable version plus an appended event; the current
// pointer is switched only inside the same transaction that writes the full
// new version, so a crash mid-write leaves either the old or the complete
// new version visible — never a partial one.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schemaVersion = 2

// Version is an immutable snapshot of the full application state.
type Version struct {
	ID        string `json:"id"`
	Parent    string `json:"parent"`
	Label     string `json:"label"`
	StateJSON []byte `json:"state"`
	Seq       int64  `json:"seq"`
}

// Event is one machine-readable entry in the append-only log.
type Event struct {
	Seq       int64           `json:"seq"`
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	VersionID string          `json:"version_id"`
}

// Conflict records two edits that started from the same base version. Both
// branches are preserved until a resolution event chooses one; the unchosen
// candidate remains stored.
type Conflict struct {
	ID          string `json:"id"`
	BaseVersion string `json:"base_version"`
	FirstEvent  string `json:"first_event"`
	SecondEvent string `json:"second_event"`
	Status      string `json:"status"` // "open" | "resolved"
	Resolution  string `json:"resolution,omitempty"`
}

// ErrConflict is returned when an edit's base version is not current.
var ErrConflict = errors.New("base version is not current: conflict recorded")

type Store struct {
	db *sql.DB
	// Failpoint, when non-nil, runs inside the mutation transaction right
	// before commit. Tests use it to simulate an interrupted write.
	Failpoint func() error
}

// Open opens (or creates) the database and applies migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)`); err != nil {
		return err
	}
	var v int
	row := s.db.QueryRow(`SELECT v FROM meta WHERE k='schema_version'`)
	if err := row.Scan(&v); err != nil {
		v = 0
	}
	if v < 1 {
		// v1: versions + events without labels.
		if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS versions (
			id TEXT PRIMARY KEY, parent TEXT, state BLOB, seq INTEGER)`); err != nil {
			return err
		}
		if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS events (
			seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT, kind TEXT,
			payload TEXT, version_id TEXT)`); err != nil {
			return err
		}
		v = 1
	}
	if v < 2 {
		// v2: human-readable labels on versions, conflict journal.
		if !hasColumn(s.db, "versions", "label") {
			if _, err := s.db.Exec(`ALTER TABLE versions ADD COLUMN label TEXT DEFAULT ''`); err != nil {
				return err
			}
		}
		if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS conflicts (
			id TEXT PRIMARY KEY, base_version TEXT, first_event TEXT,
			second_event TEXT, status TEXT, resolution TEXT DEFAULT '')`); err != nil {
			return err
		}
		v = 2
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO meta (k,v) VALUES ('schema_version', ?)`, fmt.Sprint(v))
	return err
}

func hasColumn(db *sql.DB, table, col string) bool {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk) == nil && name == col {
			return true
		}
	}
	return false
}

// Current returns the current version id and its state.
func (s *Store) Current() (Version, error) {
	var v Version
	var label sql.NullString
	err := s.db.QueryRow(`SELECT v.id, v.parent, v.state, v.seq, v.label FROM versions v
		JOIN meta m ON m.k='current' AND m.v=v.id`).Scan(&v.ID, &v.Parent, &v.StateJSON, &v.Seq, &label)
	if errors.Is(err, sql.ErrNoRows) {
		return Version{}, nil
	}
	v.Label = label.String
	return v, err
}

// VersionAt loads any historical version by id.
func (s *Store) VersionAt(id string) (Version, error) {
	var v Version
	var label sql.NullString
	err := s.db.QueryRow(`SELECT id, parent, state, seq, label FROM versions WHERE id=?`, id).
		Scan(&v.ID, &v.Parent, &v.StateJSON, &v.Seq, &label)
	v.Label = label.String
	return v, err
}

// Versions lists all versions in sequence order.
func (s *Store) Versions() ([]Version, error) {
	rows, err := s.db.Query(`SELECT id, parent, state, seq, label FROM versions ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		var v Version
		var label sql.NullString
		if err := rows.Scan(&v.ID, &v.Parent, &v.StateJSON, &v.Seq, &label); err != nil {
			return nil, err
		}
		v.Label = label.String
		out = append(out, v)
	}
	return out, rows.Err()
}

// Events returns the append-only log in order.
func (s *Store) Events() ([]Event, error) {
	rows, err := s.db.Query(`SELECT seq, id, kind, payload, version_id FROM events ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.Seq, &e.ID, &e.Kind, &e.Payload, &e.VersionID); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Commit atomically writes a new immutable version, appends its event and
// switches the current pointer. If baseVersion is non-empty and does not
// match the current pointer, the mutation is rejected and a conflict is
// journaled instead. If s.Failpoint errors, the whole transaction rolls
// back and the old version stays current.
func (s *Store) Commit(baseVersion, label, kind string, payload any, state []byte) (Event, Version, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Event{}, Version{}, err
	}
	defer tx.Rollback()

	var curID string
	row := tx.QueryRow(`SELECT v FROM meta WHERE k='current'`)
	_ = row.Scan(&curID)

	if baseVersion != "" && baseVersion != curID {
		// Journal the conflict with both branches preserved.
		payloadJSON, _ := json.Marshal(payload)
		cid := fmt.Sprintf("conf-%d", time.Now().UnixNano())
		secondID := fmt.Sprintf("ev-conflict-%d", time.Now().UnixNano())
		_, _ = tx.Exec(`INSERT INTO events (id, kind, payload, version_id) VALUES (?,?,?,?)`,
			secondID, "conflict", payloadJSON, curID)
		_, _ = tx.Exec(`INSERT INTO conflicts (id, base_version, first_event, second_event, status)
			VALUES (?,?,?,?, 'open')`, cid, baseVersion, curID, secondID)
		if err := tx.Commit(); err != nil {
			return Event{}, Version{}, err
		}
		return Event{}, Version{}, ErrConflict
	}

	var seq int64
	_ = tx.QueryRow(`SELECT COALESCE(MAX(seq),0)+1 FROM versions`).Scan(&seq)
	ver := Version{ID: fmt.Sprintf("v-%04d", seq), Parent: curID, Label: label, StateJSON: state, Seq: seq}
	if _, err := tx.Exec(`INSERT INTO versions (id, parent, state, seq, label) VALUES (?,?,?,?,?)`,
		ver.ID, ver.Parent, ver.StateJSON, ver.Seq, ver.Label); err != nil {
		return Event{}, Version{}, err
	}
	payloadJSON, _ := json.Marshal(payload)
	evID := fmt.Sprintf("ev-%04d", seq)
	if _, err := tx.Exec(`INSERT INTO events (id, kind, payload, version_id) VALUES (?,?,?,?)`,
		evID, kind, payloadJSON, ver.ID); err != nil {
		return Event{}, Version{}, err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO meta (k,v) VALUES ('current', ?)`, ver.ID); err != nil {
		return Event{}, Version{}, err
	}
	if s.Failpoint != nil {
		if err := s.Failpoint(); err != nil {
			return Event{}, Version{}, fmt.Errorf("write interrupted: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Event{}, Version{}, err
	}
	return Event{ID: evID, Kind: kind, Payload: payloadJSON, VersionID: ver.ID}, ver, nil
}

// Conflicts lists the conflict journal.
func (s *Store) Conflicts() ([]Conflict, error) {
	rows, err := s.db.Query(`SELECT id, base_version, first_event, second_event, status, resolution FROM conflicts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Conflict
	for rows.Next() {
		var c Conflict
		if err := rows.Scan(&c.ID, &c.BaseVersion, &c.FirstEvent, &c.SecondEvent, &c.Status, &c.Resolution); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ResolveConflict marks a conflict resolved, keeping the unchosen branch.
func (s *Store) ResolveConflict(id, resolution string) error {
	_, err := s.db.Exec(`UPDATE conflicts SET status='resolved', resolution=? WHERE id=?`, resolution, id)
	return err
}

// dump is the export document. Identity, order and provenance are all
// explicit so a delete+import round trip preserves them.
type dump struct {
	SchemaVersion int        `json:"schema_version"`
	Current       string     `json:"current"`
	Versions      []Version  `json:"versions"`
	Events        []Event    `json:"events"`
	Conflicts     []Conflict `json:"conflicts"`
}

// Export serialises the whole database as JSON.
func (s *Store) Export() ([]byte, error) {
	cur, _ := s.Current()
	versions, err := s.Versions()
	if err != nil {
		return nil, err
	}
	events, err := s.Events()
	if err != nil {
		return nil, err
	}
	conflicts, err := s.Conflicts()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(dump{schemaVersion, cur.ID, versions, events, conflicts}, "", "  ")
}

// Import replaces the database contents with an exported document,
// preserving every stable id, sequence and provenance link.
func (s *Store) Import(data []byte) error {
	var d dump
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		`DELETE FROM conflicts`, `DELETE FROM events`, `DELETE FROM versions`, `DELETE FROM meta`,
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	for _, v := range d.Versions {
		if _, err := tx.Exec(`INSERT INTO versions (id, parent, state, seq, label) VALUES (?,?,?,?,?)`,
			v.ID, v.Parent, v.StateJSON, v.Seq, v.Label); err != nil {
			return err
		}
	}
	for _, e := range d.Events {
		if _, err := tx.Exec(`INSERT INTO events (seq, id, kind, payload, version_id) VALUES (?,?,?,?,?)`,
			e.Seq, e.ID, e.Kind, e.Payload, e.VersionID); err != nil {
			return err
		}
	}
	for _, c := range d.Conflicts {
		if _, err := tx.Exec(`INSERT INTO conflicts (id, base_version, first_event, second_event, status, resolution)
			VALUES (?,?,?,?,?,?)`, c.ID, c.BaseVersion, c.FirstEvent, c.SecondEvent, c.Status, c.Resolution); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO meta (k,v) VALUES ('schema_version', ?)`, fmt.Sprint(d.SchemaVersion)); err != nil {
		return err
	}
	if d.Current != "" {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO meta (k,v) VALUES ('current', ?)`, d.Current); err != nil {
			return err
		}
	}
	return tx.Commit()
}
