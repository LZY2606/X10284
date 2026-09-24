package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/example/mqtt-session-forensics/internal/archive"
	"github.com/example/mqtt-session-forensics/internal/engine"
	"github.com/example/mqtt-session-forensics/internal/model"
)

// BundleAt reconstructs the full input bundle at a branch version. Raw bytes,
// directions and original time representations are read back verbatim.
func (s *Store) BundleAt(ctx context.Context, branch string, version int) (*model.Bundle, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	b := &model.Bundle{Params: map[string]model.ParamRecord{}}
	rows, err := tx.QueryContext(ctx,
		`SELECT id,direction,raw_hex,COALESCE(capsule_hex,''),connection_id,COALESCE(client_hint,''),ingest_order,time_orig,time_unit
		 FROM packets WHERE branch=? AND version=? ORDER BY ingest_order, id`, branch, version)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p model.RawPacket
		var dir string
		if err := rows.Scan(&p.ID, &dir, &p.RawHex, &p.CapsuleBytes, &p.ConnectionID,
			&p.ClientIDHint, &p.IngestOrder, &p.ObservedAt.Original, &p.ObservedAt.Unit); err != nil {
			return nil, err
		}
		p.Direction = model.Direction(dir)
		b.Packets = append(b.Packets, p)
	}
	rows.Close()

	srows, err := tx.QueryContext(ctx,
		`SELECT id,client_id,COALESCE(connection_id,''),time_orig,time_unit,json_text
		 FROM snapshots_tbl WHERE branch=? AND version=? ORDER BY id`, branch, version)
	if err != nil {
		return nil, err
	}
	for srows.Next() {
		var sn model.SnapshotRecord
		var js string
		if err := srows.Scan(&sn.ID, &sn.ClientID, &sn.ConnectionID,
			&sn.ObservedAt.Original, &sn.ObservedAt.Unit, &js); err != nil {
			return nil, err
		}
		sn.JSON = json.RawMessage(js)
		b.Snapshots = append(b.Snapshots, sn)
	}
	srows.Close()

	prows, err := tx.QueryContext(ctx,
		`SELECT name,value,COALESCE(unit,'') FROM params_tbl WHERE branch=? AND version=? ORDER BY name`,
		branch, version)
	if err != nil {
		return nil, err
	}
	for prows.Next() {
		var pr model.ParamRecord
		if err := prows.Scan(&pr.Name, &pr.Value, &pr.Unit); err != nil {
			return nil, err
		}
		b.Params[pr.Name] = pr
	}
	prows.Close()
	return b, nil
}

// GraphAt reads one committed derived graph.
func (s *Store) GraphAt(ctx context.Context, branch string, version int) (*model.Graph, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT graph FROM versions WHERE branch=? AND version=?`,
		branch, version).Scan(&raw)
	if err != nil {
		return nil, fmt.Errorf("graph %s@v%d: %w", branch, version, err)
	}
	g := &model.Graph{}
	if err := json.Unmarshal([]byte(raw), g); err != nil {
		return nil, err
	}
	return g, nil
}

// ReportAt reads the propagation report for a version.
func (s *Store) ReportAt(ctx context.Context, branch string, version int) (*engine.PropagationReport, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT report FROM reports WHERE branch=? AND version=?`,
		branch, version).Scan(&raw)
	if err != nil {
		return nil, err
	}
	r := &engine.PropagationReport{}
	if err := json.Unmarshal([]byte(raw), r); err != nil {
		return nil, err
	}
	return r, nil
}

// Events returns the immutable events on a branch in order.
func (s *Store) Events(ctx context.Context, branch string) ([]archive.Event, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq,branch,parent_seq,kind,at_ns,COALESCE(actor,''),title,COALESCE(summary,''),COALESCE(payload,''),COALESCE(labels,'')
		 FROM events WHERE branch=? ORDER BY seq`, branch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []archive.Event
	for rows.Next() {
		var ev archive.Event
		var payload, labels sql.NullString
		if err := rows.Scan(&ev.Seq, &ev.Branch, &ev.ParentSeq, &ev.Kind, &ev.AtNS,
			&ev.Actor, &ev.Title, &ev.Summary, &payload, &labels); err != nil {
			return nil, err
		}
		ev.Payload = []byte(payload.String)
		if labels.Valid && labels.String != "" {
			_ = json.Unmarshal([]byte(labels.String), &ev.Labels)
		}
		out = append(out, ev)
	}
	return out, nil
}

type BranchInfo struct {
	Name       string `json:"name"`
	Parent     string `json:"parent_branch"`
	ParentSeq  int64  `json:"parent_seq"`
	BaseVersion int   `json:"base_version"`
	HeadSeq    int64  `json:"head_seq"`
	HeadVersion int   `json:"head_version"`
	Note       string `json:"note"`
}

func (s *Store) ListBranches(ctx context.Context) ([]BranchInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name,COALESCE(parent_branch,''),COALESCE(parent_seq,0),base_version,head_seq,head_version,COALESCE(note,'')
		 FROM branches ORDER BY created_ns, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BranchInfo
	for rows.Next() {
		var b BranchInfo
		if err := rows.Scan(&b.Name, &b.Parent, &b.ParentSeq, &b.BaseVersion,
			&b.HeadSeq, &b.HeadVersion, &b.Note); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// Versions returns the committed versions of a branch (never gapped after commit).
func (s *Store) Versions(ctx context.Context, branch string) ([]int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT version FROM versions WHERE branch=? ORDER BY version`, branch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
