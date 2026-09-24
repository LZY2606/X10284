package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/example/mqtt-session-forensics/internal/archive"
	"github.com/example/mqtt-session-forensics/internal/engine"
	"github.com/example/mqtt-session-forensics/internal/model"
)

// ErrConflict means the branch advanced between expectedVersion and commit; the
// two concurrent edits can be resolved by the caller.
var ErrConflict = errors.New("branch version conflict (expected version stale)")

// CommitInput fully describes one append: the rebuilt bundle state, event and
// precomputed graph. The switch of the current pointer happens only after the
// graph is written, inside one transaction.
type CommitInput struct {
	Branch          string
	ExpectedVersion int // optimistic concurrency base
	Event           archive.Event
	Bundle          *model.Bundle
	Graph           *model.Graph
	Report          *engine.PropagationReport
	CrashAfterGraph bool // test hook: kill the transaction after graph insert, before pointer switch
}

// Head returns the current pointer of a branch.
func (s *Store) Head(ctx context.Context, branch string) (version int, headSeq int64, err error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT head_version, head_seq FROM branches WHERE name=?`, branch)
	err = row.Scan(&version, &headSeq)
	return
}

// EnsureBranch creates a branch row (idempotent).
func (s *Store) EnsureBranch(ctx context.Context, name, parent string, parentSeq int64, baseVersion int, note string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO branches(name,parent_branch,parent_seq,base_version,head_seq,head_version,created_ns,note)
		VALUES(?,?,?, ?,0,0, ?,?)
		ON CONFLICT(name) DO NOTHING`, name, nullStr(parent), nullInt(parentSeq), baseVersion,
		archive.NowNSExternal(), note)
	return err
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func nullInt(i int64) any {
	if i == 0 {
		return nil
	}
	return i
}

// CommitVersion is the atomic "write all derived versions, then switch current
// pointer" operation.
func (s *Store) CommitVersion(ctx context.Context, in CommitInput) (newVersion int, eventSeq int64, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var cur int
	row := tx.QueryRowContext(ctx, `SELECT head_version FROM branches WHERE name=?`, in.Branch)
	if err = row.Scan(&cur); err != nil {
		return 0, 0, fmt.Errorf("branch %s: %w", in.Branch, err)
	}
	if cur != in.ExpectedVersion {
		return 0, 0, fmt.Errorf("%w: expected v%d, current v%d", ErrConflict, in.ExpectedVersion, cur)
	}
	newVersion = cur + 1

	// 1) immutable input rows at the new version
	if err = insertBundleTx(ctx, tx, in.Branch, newVersion, in.Bundle); err != nil {
		return 0, 0, err
	}

	// 2) event
	in.Event.Branch = in.Branch
	in.Event.ParentSeq = in.Event.Seq // preserve supplied parent
	res, err := tx.ExecContext(ctx,
		`INSERT INTO events(branch,parent_seq,kind,at_ns,actor,title,summary,payload,labels)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		in.Event.Branch, in.Event.ParentSeq, in.Event.Kind, in.Event.AtNS,
		in.Event.Actor, in.Event.Title, in.Event.Summary,
		jsonBytes(in.Event.Payload), jsonBytes(in.Event.Labels))
	if err != nil {
		return 0, 0, err
	}
	eventSeq, _ = res.LastInsertId()

	// 3) derived graph + report
	graphJSON := mustJSON(in.Graph)
	bundleJSON := mustJSON(in.Bundle)
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO versions(branch,version,graph,bundle,computed_ns) VALUES(?,?,?,?,?)`,
		in.Branch, newVersion, string(graphJSON), string(bundleJSON), archive.NowNSExternal()); err != nil {
		return 0, 0, err
	}
	if in.Report != nil {
		if _, err = tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO reports(branch,version,report) VALUES(?,?,?)`,
			in.Branch, newVersion, string(mustJSON(in.Report))); err != nil {
			return 0, 0, err
		}
	}
	if in.CrashAfterGraph {
		// Simulated process death: roll back everything (no pointer switch).
		_ = tx.Rollback()
		return 0, eventSeq, errors.New("simulated crash before pointer switch")
	}

	// 4) switch current pointer only now
	if _, err = tx.ExecContext(ctx,
		`UPDATE branches SET head_version=?, head_seq=? WHERE name=?`,
		newVersion, eventSeq, in.Branch); err != nil {
		return 0, 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, 0, err
	}
	return newVersion, eventSeq, nil
}

func jsonBytes(v any) []byte {
	if v == nil {
		return nil
	}
	b, _ := json.Marshal(v)
	return b
}

func insertBundleTx(ctx context.Context, tx *sql.Tx, branch string, version int, b *model.Bundle) error {
	for _, p := range b.Packets {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO packets(id,version,branch,direction,raw_hex,capsule_hex,connection_id,client_hint,ingest_order,time_orig,time_unit)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			p.ID, version, branch, string(p.Direction), p.RawHex, p.CapsuleBytes,
			p.ConnectionID, p.ClientIDHint, p.IngestOrder, p.ObservedAt.Original, p.ObservedAt.Unit); err != nil {
			return err
		}
	}
	for _, sn := range b.Snapshots {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO snapshots_tbl(id,version,branch,client_id,connection_id,time_orig,time_unit,json_text)
			 VALUES(?,?,?,?,?,?,?,?)`,
			sn.ID, version, branch, sn.ClientID, sn.ConnectionID,
			sn.ObservedAt.Original, sn.ObservedAt.Unit, string(sn.JSON)); err != nil {
			return err
		}
	}
	for name, pr := range b.Params {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO params_tbl(version,branch,name,value,unit) VALUES(?,?,?,?,?)`,
			version, branch, name, pr.Value, pr.Unit); err != nil {
			return err
		}
	}
	return nil
}
