// Package store is the versioned SQLite store. Objects are immutable and
// content-addressed. Every derivation produces a new version; the current
// pointer only switches inside the same transaction that persists the
// version, so after an interrupted write a restart sees either the old
// version or a complete new one.
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

const schemaVersion = 2

var ErrConflict = errors.New("head moved: conflict recorded")

// ArtifactState pins one derived artifact inside a version.
type ArtifactState struct {
	ObjectID string            `json:"object_id"`
	Status   string            `json:"status"` // source|valid|recomputed|identical
	Reason   string            `json:"reason"`
	Inputs   map[string]string `json:"inputs,omitempty"` // input name -> object id
}

type Event struct {
	ID      string          `json:"id"`
	Version string          `json:"version"`
	Seq     int             `json:"seq"`
	Kind    string          `json:"kind"`
	Body    json.RawMessage `json:"body"`
}

type Version struct {
	ID        string                   `json:"id"`
	Parent    string                   `json:"parent"`
	Seq       int                      `json:"seq"`
	Label     string                   `json:"label"`
	Artifacts map[string]ArtifactState `json:"artifacts"`
}

type Conflict struct {
	ID         string `json:"id"`
	Branch     string `json:"branch"`
	Base       string `json:"base"`
	Ours       string `json:"ours"`
	Theirs     string `json:"theirs"`
	Status     string `json:"status"` // open|resolved
	Resolution string `json:"resolution"`
}

type Branch struct {
	Name string `json:"name"`
	Head string `json:"head"`
	Base string `json:"base"`
}

func Hash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func ObjectID(body []byte) string { return "obj-" + Hash(string(body)) }

type Store struct {
	db *sql.DB
	// FailAfterWrites, when >0, makes the next commit fail after that many
	// statements and roll back. Test hook for interrupted writes.
	FailAfterWrites int
	writes          int
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var v int
	row := s.db.QueryRow(`SELECT value FROM meta WHERE key='schema_version'`)
	if err := row.Scan(&v); err != nil {
		if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)`); err != nil {
			return err
		}
		v = 0
	}
	if v < 1 {
		stmts := []string{
			`CREATE TABLE IF NOT EXISTS objects (id TEXT PRIMARY KEY, kind TEXT NOT NULL, body TEXT NOT NULL)`,
			`CREATE TABLE IF NOT EXISTS versions (id TEXT PRIMARY KEY, parent TEXT, seq INTEGER, label TEXT, artifacts TEXT NOT NULL)`,
			`CREATE TABLE IF NOT EXISTS current (name TEXT PRIMARY KEY, version TEXT NOT NULL)`,
			`CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, version TEXT, seq INTEGER, kind TEXT, body TEXT)`,
		}
		for _, q := range stmts {
			if _, err := s.db.Exec(q); err != nil {
				return err
			}
		}
		v = 1
	}
	if v < 2 {
		stmts := []string{
			`CREATE TABLE IF NOT EXISTS branches (name TEXT PRIMARY KEY, head TEXT NOT NULL, base TEXT NOT NULL)`,
			`CREATE TABLE IF NOT EXISTS conflicts (id TEXT PRIMARY KEY, branch TEXT, base TEXT, ours TEXT, theirs TEXT, status TEXT, resolution TEXT)`,
		}
		for _, q := range stmts {
			if _, err := s.db.Exec(q); err != nil {
				return err
			}
		}
		v = 2
	}
	_, err := s.db.Exec(`INSERT INTO meta (key, value) VALUES ('schema_version', ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, fmt.Sprint(schemaVersion))
	return err
}

func (s *Store) checkFail() error {
	if s.FailAfterWrites > 0 {
		s.writes++
		if s.writes > s.FailAfterWrites {
			s.writes = 0
			return errors.New("injected write failure")
		}
	}
	return nil
}

// Commit persists objects, a version and its events, then swings the pointer
// (mainline current or a branch head) in the same transaction. If the
// expected head no longer matches, the version is still persisted (the
// candidate is never lost) and a conflict row is recorded.
func (s *Store) Commit(label, branch, expectHead string, artifacts map[string]ArtifactState, objects map[string]json.RawMessage, events []Event) (string, error) {
	s.writes = 0
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	rollback := func(e error) (string, error) { tx.Rollback(); return "", e }

	var head string
	if branch == "" {
		err = tx.QueryRow(`SELECT version FROM current WHERE name='main'`).Scan(&head)
		if err == sql.ErrNoRows {
			head = ""
		} else if err != nil {
			return rollback(err)
		}
	} else {
		err = tx.QueryRow(`SELECT head FROM branches WHERE name=?`, branch).Scan(&head)
		if err == sql.ErrNoRows {
			head = expectHead // new branch starts at the caller's base
		} else if err != nil {
			return rollback(err)
		}
	}

	artJSON, err := json.Marshal(artifacts)
	if err != nil {
		return rollback(err)
	}
	var seq int
	_ = tx.QueryRow(`SELECT COALESCE(MAX(seq),0) FROM versions`).Scan(&seq)
	seq++
	verID := "ver-" + Hash(head, label, string(artJSON), fmt.Sprint(seq))
	for id, body := range objects {
		if err := s.checkFail(); err != nil {
			return rollback(err)
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO objects (id, kind, body) VALUES (?,?,?)`, id, "artifact", string(body)); err != nil {
			return rollback(err)
		}
	}
	if err := s.checkFail(); err != nil {
		return rollback(err)
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO versions (id, parent, seq, label, artifacts) VALUES (?,?,?,?,?)`,
		verID, head, seq, label, string(artJSON)); err != nil {
		return rollback(err)
	}
	for _, ev := range events {
		if err := s.checkFail(); err != nil {
			return rollback(err)
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO events (id, version, seq, kind, body) VALUES (?,?,?,?,?)`,
			ev.ID, verID, ev.Seq, ev.Kind, string(ev.Body)); err != nil {
			return rollback(err)
		}
	}
	if err := s.checkFail(); err != nil {
		return rollback(err)
	}

	conflict := false
	if branch == "" {
		if head == "" {
			_, err = tx.Exec(`INSERT INTO current (name, version) VALUES ('main', ?)`, verID)
		} else {
			var res sql.Result
			res, err = tx.Exec(`UPDATE current SET version=? WHERE name='main' AND version=?`, verID, expectHead)
			if err == nil {
				if n, _ := res.RowsAffected(); n == 0 {
					conflict = true
				}
			}
		}
	} else {
		var res sql.Result
		res, err = tx.Exec(`UPDATE branches SET head=? WHERE name=? AND head=?`, verID, branch, expectHead)
		if err == nil {
			if n, _ := res.RowsAffected(); n == 0 {
				var exists int
				_ = tx.QueryRow(`SELECT COUNT(1) FROM branches WHERE name=?`, branch).Scan(&exists)
				if exists == 0 {
					_, err = tx.Exec(`INSERT INTO branches (name, head, base) VALUES (?,?,?)`, branch, verID, expectHead)
				} else {
					conflict = true
				}
			}
		}
	}
	if err != nil {
		return rollback(err)
	}
	if conflict {
		actual := s.headInTx(tx, branch)
		cid := "conf-" + Hash(branch, expectHead, verID)
		if _, err := tx.Exec(`INSERT OR IGNORE INTO conflicts (id, branch, base, ours, theirs, status, resolution)
			VALUES (?,?,?,?,?,'open','')`, cid, branch, expectHead, verID, actual); err != nil {
			return rollback(err)
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return verID, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return verID, nil
}

func (s *Store) headInTx(tx *sql.Tx, branch string) string {
	var h string
	if branch == "" {
		_ = tx.QueryRow(`SELECT version FROM current WHERE name='main'`).Scan(&h)
	} else {
		_ = tx.QueryRow(`SELECT head FROM branches WHERE name=?`, branch).Scan(&h)
	}
	return h
}

// ResolveConflict picks one side of an open conflict. The unchosen candidate
// version stays in the store; the conflict row records the resolution.
func (s *Store) ResolveConflict(id, choice string) error {
	var c Conflict
	err := s.db.QueryRow(`SELECT id, branch, base, ours, theirs, status FROM conflicts WHERE id=?`, id).
		Scan(&c.ID, &c.Branch, &c.Base, &c.Ours, &c.Theirs, &c.Status)
	if err != nil {
		return err
	}
	if c.Status != "open" {
		return fmt.Errorf("conflict %s already resolved", id)
	}
	pick := c.Ours
	if choice == "theirs" {
		pick = c.Theirs
	} else if choice != "ours" {
		return fmt.Errorf("choice must be ours or theirs")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if c.Branch == "" {
		if _, err := tx.Exec(`UPDATE current SET version=? WHERE name='main'`, pick); err != nil {
			tx.Rollback()
			return err
		}
	} else {
		if _, err := tx.Exec(`UPDATE branches SET head=? WHERE name=?`, pick, c.Branch); err != nil {
			tx.Rollback()
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE conflicts SET status='resolved', resolution=? WHERE id=?`, choice, id); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) Head(branch string) (string, error) {
	var h string
	var err error
	if branch == "" {
		err = s.db.QueryRow(`SELECT version FROM current WHERE name='main'`).Scan(&h)
	} else {
		err = s.db.QueryRow(`SELECT head FROM branches WHERE name=?`, branch).Scan(&h)
	}
	if err == sql.ErrNoRows {
		return "", nil
	}
	return h, err
}

func (s *Store) Version(id string) (Version, error) {
	var v Version
	var arts string
	err := s.db.QueryRow(`SELECT id, parent, seq, label, artifacts FROM versions WHERE id=?`, id).
		Scan(&v.ID, &v.Parent, &v.Seq, &v.Label, &arts)
	if err != nil {
		return v, err
	}
	return v, json.Unmarshal([]byte(arts), &v.Artifacts)
}

func (s *Store) Versions() ([]Version, error) {
	rows, err := s.db.Query(`SELECT id, parent, seq, label, artifacts FROM versions ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		var v Version
		var arts string
		if err := rows.Scan(&v.ID, &v.Parent, &v.Seq, &v.Label, &arts); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(arts), &v.Artifacts)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) Object(id string) (json.RawMessage, error) {
	var body string
	err := s.db.QueryRow(`SELECT body FROM objects WHERE id=?`, id).Scan(&body)
	return json.RawMessage(body), err
}

func (s *Store) Events() ([]Event, error) {
	rows, err := s.db.Query(`SELECT id, version, seq, kind, body FROM events ORDER BY seq, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var body string
		if err := rows.Scan(&e.ID, &e.Version, &e.Seq, &e.Kind, &body); err != nil {
			return nil, err
		}
		e.Body = json.RawMessage(body)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Conflicts() ([]Conflict, error) {
	rows, err := s.db.Query(`SELECT id, branch, base, ours, theirs, status, resolution FROM conflicts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Conflict
	for rows.Next() {
		var c Conflict
		if err := rows.Scan(&c.ID, &c.Branch, &c.Base, &c.Ours, &c.Theirs, &c.Status, &c.Resolution); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Branches() ([]Branch, error) {
	rows, err := s.db.Query(`SELECT name, head, base FROM branches ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Branch
	for rows.Next() {
		var b Branch
		if err := rows.Scan(&b.Name, &b.Head, &b.Base); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
