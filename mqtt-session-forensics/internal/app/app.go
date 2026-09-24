// Package app orchestrates the store, engine and archive: each user action
// produces one independent, atomically committed derivation version.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/example/mqtt-session-forensics/internal/archive"
	"github.com/example/mqtt-session-forensics/internal/engine"
	"github.com/example/mqtt-session-forensics/internal/model"
	"github.com/example/mqtt-session-forensics/internal/store"
)

// DefaultBranch is the baseline archive branch.
const DefaultBranch = "baseline"

type App struct{ Store *store.Store }

func New(st *store.Store) *App { return &App{Store: st} }

// ActionResult reports the new pointer and which inputs changed.
type ActionResult struct {
	Branch        string                     `json:"branch"`
	NewVersion    int                        `json:"new_version"`
	EventSeq      int64                      `json:"event_seq"`
	ChangedInputs []string                   `json:"changed_inputs"`
	Report        *engine.PropagationReport `json:"report"`
}

func (a *App) ensureBranch(ctx context.Context, name, parent string, parentSeq int64, base int, note string) error {
	return a.Store.EnsureBranch(ctx, name, parent, parentSeq, base, note)
}

func (a *App) headOrZero(ctx context.Context, branch string) (int, int64, error) {
	v, seq, err := a.Store.Head(ctx, branch)
	if err != nil {
		// missing branch => treat as 0
		return 0, 0, nil
	}
	return v, seq, nil
}

// Baseline imports the initial case pack as v1.
func (a *App) Baseline(ctx context.Context, b *model.Bundle, note string) (*ActionResult, error) {
	if err := a.ensureBranch(ctx, DefaultBranch, "", 0, 0, note); err != nil {
		return nil, err
	}
	g := engine.Compute(b, 1)
	payload := archive.BaselinePayload{
		CaseTitle: b.CaseTitle,
		Preserved: []string{"raw_hex", "direction", "packet_id", "dup", "retain",
			"clean_start", "session_expiry", "topic_alias", "observed_at",
			"connection_id", "client_id", "capsule_hex"},
	}
	pj, _ := json.Marshal(payload)
	ev := archive.Event{
		Kind: archive.EvBaseline, Branch: DefaultBranch, ParentSeq: 0,
		AtNS: archive.NowNSExternal(), Actor: "ingest", Title: "Baseline import",
		Summary: "Original packets, snapshots and parameters preserved verbatim",
		RuleRefs: []string{}, Payload: pj,
	}
	v, seq, err := a.Store.CommitVersion(ctx, store.CommitInput{
		Branch: DefaultBranch, ExpectedVersion: 0, Event: ev,
		Bundle: b, Graph: g,
	})
	if err != nil {
		return nil, err
	}
	return &ActionResult{Branch: DefaultBranch, NewVersion: v, EventSeq: seq,
		ChangedInputs: allInputs(b)}, nil
}

func allInputs(b *model.Bundle) []string {
	out := make([]string, 0, len(b.Packets))
	for _, p := range b.Packets {
		out = append(out, "packet:"+p.ID)
	}
	for _, s := range b.Snapshots {
		out = append(out, "snapshot:"+s.ID)
	}
	for name := range b.Params {
		out = append(out, "param:"+name)
	}
	return out
}

// ReviseParam changes one reconstruction parameter.
func (a *App) ReviseParam(ctx context.Context, branch, actor, name, newValue, unit, summary string) (*ActionResult, error) {
	cur, _, err := a.headOrZero(ctx, branch)
	if err != nil {
		return nil, err
	}
	b, err := a.Store.BundleAt(ctx, branch, cur)
	if err != nil {
		return nil, err
	}
	old := b.Params[name]
	b.Params[name] = model.ParamRecord{Name: name, Value: newValue, Unit: unit,
		ChangedBy: actor, ChangedAt: archive.NowNSExternal()}
	res, err := a.commitRecompute(ctx, branch, cur, b,
		archive.EvParamRevise, actor, "Parameter revision: "+name, summary,
		archive.ParamPayload{Name: name, OldValue: old.Value, NewValue: newValue, Unit: unit},
		map[string]bool{"param:" + name: true})
	return res, err
}

// PatchPacketField changes exactly one direct-source field of one packet.
func (a *App) PatchPacketField(ctx context.Context, branch, actor, packetID, field, newValue, summary string) (*ActionResult, error) {
	cur, _, err := a.headOrZero(ctx, branch)
	if err != nil {
		return nil, err
	}
	b, err := a.Store.BundleAt(ctx, branch, cur)
	if err != nil {
		return nil, err
	}
	old := ""
	found := false
	for i := range b.Packets {
		if b.Packets[i].ID != packetID {
			continue
		}
		found = true
		old, err = applyField(&b.Packets[i], field, newValue)
		if err != nil {
			return nil, err
		}
	}
	if !found {
		return nil, fmt.Errorf("packet %s not found", packetID)
	}
	return a.commitRecompute(ctx, branch, cur, b,
		archive.EvSourcePatch, actor, "Single-source patch: "+packetID+"."+field, summary,
		archive.SourcePatchPayload{PacketID: packetID, Field: field, OldValue: old, NewValue: newValue},
		map[string]bool{"packet:" + packetID: true})
}

// Decision records an accept/reject of candidates on a branch. Unselected
// candidates remain in the event payload; a confirmation never overwrites.
func (a *App) Decision(ctx context.Context, branch, actor, nodeUID, adopted, title, summary string, candidates []string) (*ActionResult, error) {
	cur, _, err := a.headOrZero(ctx, branch)
	if err != nil {
		return nil, err
	}
	b, err := a.Store.BundleAt(ctx, branch, cur)
	if err != nil {
		return nil, err
	}
	rejected := []string{}
	for _, c := range candidates {
		if c != adopted {
			rejected = append(rejected, c)
		}
	}
	payload := archive.DecisionPayload{NodeUID: nodeUID, Candidates: candidates,
		Adopted: adopted, Rejected: rejected,
		RuleRefs: []string{archive.RuleNoCollapse}}
	return a.commitRecompute(ctx, branch, cur, b,
		archive.EvDecision, actor, title, summary, payload, map[string]bool{})
}

// ForkFromEvent creates a child branch whose starting bundle is the state at
// (branch,version). Visiting an old event therefore restores that version's
// inputs and conclusions rather than overlaying the newest computation.
func (a *App) ForkFromEvent(ctx context.Context, parent string, version int, child, actor, note string) error {
	if err := a.ensureBranch(ctx, child, parent, 0, version, note); err != nil {
		return err
	}
	// Copy the chosen version graph+bundle as the child's v0..version snapshot
	// by importing through a lightweight transaction: easiest is to write
	// versions row directly.
	b, err := a.Store.BundleAt(ctx, parent, version)
	if err != nil {
		return err
	}
	g, err := a.Store.GraphAt(ctx, parent, version)
	if err != nil {
		return err
	}
	g2 := *g
	g2.Version = version
	st := a.Store.DB()
	tx, err := st.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	gb, _ := json.Marshal(b)
	gg, _ := json.Marshal(g2)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO versions(branch,version,graph,bundle,computed_ns) VALUES(?,?,?,?,?)`,
		child, version, string(gg), string(gb), archive.NowNSExternal()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE branches SET head_version=? WHERE name=?`, version, child); err != nil {
		return err
	}
	ev := archive.Event{Kind: archive.EvDecision, Branch: child, ParentSeq: 0,
		AtNS: archive.NowNSExternal(), Actor: actor,
		Title: "Fork at historical version", Summary: note}
	pj, _ := json.Marshal(map[string]any{"parent": parent, "version": version})
	ev.Payload = pj
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO events(branch,parent_seq,kind,at_ns,actor,title,summary,payload)
		 VALUES(?,?,?,?,?,?,?,?)`,
		child, 0, ev.Kind, ev.AtNS, ev.Actor, ev.Title, ev.Summary, string(pj)); err != nil {
		return err
	}
	return tx.Commit()
}

func (a *App) commitRecompute(ctx context.Context, branch string, cur int, b *model.Bundle,
	kind, actor, title, summary string, payload any, changed map[string]bool) (*ActionResult, error) {
	prev, err := a.Store.GraphAt(ctx, branch, cur)
	if err != nil {
		return nil, err
	}
	g := engine.Compute(b, cur+1)
	rep := engine.Propagate(prev, g, changed)
	pj, _ := json.Marshal(payload)
	ev := archive.Event{Kind: kind, Branch: branch, AtNS: archive.NowNSExternal(),
		Actor: actor, Title: title, Summary: summary, Payload: pj}
	v, seq, err := a.Store.CommitVersion(ctx, store.CommitInput{
		Branch: branch, ExpectedVersion: cur, Event: ev, Bundle: b, Graph: g, Report: rep})
	if err != nil {
		return nil, err
	}
	changes := make([]string, 0, len(changed))
	for k := range changed {
		changes = append(changes, k)
	}
	return &ActionResult{Branch: branch, NewVersion: v, EventSeq: seq,
		ChangedInputs: changes, Report: rep}, nil
}

// IsConflict reports whether an error is the resolvable optimistic conflict.
func IsConflict(err error) bool { return errors.Is(err, store.ErrConflict) }
