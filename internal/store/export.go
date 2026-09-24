package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// Export writes the whole database as JSONL. Identities (object ids, version
// ids, event ids), ordering (seq) and provenance (parent links, artifact
// pins) are part of the payload, so deleting the local database and
// re-importing restores them exactly.
func (s *Store) Export(w io.Writer) error {
	bw := bufio.NewWriter(w)
	write := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if _, err := bw.Write(append(b, '\n')); err != nil {
			return err
		}
		return nil
	}
	if err := write(map[string]any{"type": "header", "format": "mqttlab-export", "schema": schemaVersion}); err != nil {
		return err
	}
	rows, err := s.db.Query(`SELECT id, kind, body FROM objects ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type obj struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		Kind string `json:"kind"`
		Body string `json:"body"`
	}
	for rows.Next() {
		var o obj
		o.Type = "object"
		if err := rows.Scan(&o.ID, &o.Kind, &o.Body); err != nil {
			return err
		}
		if err := write(o); err != nil {
			return err
		}
	}
	rows.Close()
	versions, err := s.Versions()
	if err != nil {
		return err
	}
	for _, v := range versions {
		if err := write(map[string]any{"type": "version", "version": v}); err != nil {
			return err
		}
	}
	events, err := s.Events()
	if err != nil {
		return err
	}
	for _, e := range events {
		if err := write(map[string]any{"type": "event", "event": e}); err != nil {
			return err
		}
	}
	branches, err := s.Branches()
	if err != nil {
		return err
	}
	for _, b := range branches {
		if err := write(map[string]any{"type": "branch", "branch": b}); err != nil {
			return err
		}
	}
	conflicts, err := s.Conflicts()
	if err != nil {
		return err
	}
	for _, c := range conflicts {
		if err := write(map[string]any{"type": "conflict", "conflict": c}); err != nil {
			return err
		}
	}
	head, err := s.Head("")
	if err != nil {
		return err
	}
	if err := write(map[string]any{"type": "current", "version": head}); err != nil {
		return err
	}
	return bw.Flush()
}

// Import loads an export into an empty database, verifying object hashes.
func (s *Store) Import(r io.Reader) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		var env struct {
			Type string `json:"type"`
			ID   string `json:"id"`
			Kind string `json:"kind"`
			Body string `json:"body"`
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(line, &raw); err != nil {
			tx.Rollback()
			return err
		}
		var typ string
		_ = json.Unmarshal(raw["type"], &typ)
		switch typ {
		case "header":
		case "object":
			_ = json.Unmarshal(line, &env)
			if ObjectID([]byte(env.Body)) != env.ID {
				tx.Rollback()
				return fmt.Errorf("object %s fails hash check", env.ID)
			}
			if _, err := tx.Exec(`INSERT OR IGNORE INTO objects (id, kind, body) VALUES (?,?,?)`, env.ID, env.Kind, env.Body); err != nil {
				tx.Rollback()
				return err
			}
		case "version":
			var v struct {
				Version Version `json:"version"`
			}
			_ = json.Unmarshal(line, &v)
			arts, _ := json.Marshal(v.Version.Artifacts)
			if _, err := tx.Exec(`INSERT OR IGNORE INTO versions (id, parent, seq, label, artifacts) VALUES (?,?,?,?,?)`,
				v.Version.ID, v.Version.Parent, v.Version.Seq, v.Version.Label, string(arts)); err != nil {
				tx.Rollback()
				return err
			}
		case "event":
			var e struct {
				Event Event `json:"event"`
			}
			_ = json.Unmarshal(line, &e)
			if _, err := tx.Exec(`INSERT OR IGNORE INTO events (id, version, seq, kind, body) VALUES (?,?,?,?,?)`,
				e.Event.ID, e.Event.Version, e.Event.Seq, e.Event.Kind, string(e.Event.Body)); err != nil {
				tx.Rollback()
				return err
			}
		case "branch":
			var b struct {
				Branch Branch `json:"branch"`
			}
			_ = json.Unmarshal(line, &b)
			if _, err := tx.Exec(`INSERT OR IGNORE INTO branches (name, head, base) VALUES (?,?,?)`,
				b.Branch.Name, b.Branch.Head, b.Branch.Base); err != nil {
				tx.Rollback()
				return err
			}
		case "conflict":
			var c struct {
				Conflict Conflict `json:"conflict"`
			}
			_ = json.Unmarshal(line, &c)
			if _, err := tx.Exec(`INSERT OR IGNORE INTO conflicts (id, branch, base, ours, theirs, status, resolution) VALUES (?,?,?,?,?,?,?)`,
				c.Conflict.ID, c.Conflict.Branch, c.Conflict.Base, c.Conflict.Ours, c.Conflict.Theirs, c.Conflict.Status, c.Conflict.Resolution); err != nil {
				tx.Rollback()
				return err
			}
		case "current":
			var c struct {
				Version string `json:"version"`
			}
			_ = json.Unmarshal(line, &c)
			if _, err := tx.Exec(`INSERT INTO current (name, version) VALUES ('main', ?)
				ON CONFLICT(name) DO UPDATE SET version=excluded.version`, c.Version); err != nil {
				tx.Rollback()
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
