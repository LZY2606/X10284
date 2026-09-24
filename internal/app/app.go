// Package app wires the engine, the versioned store and the offline case
// pack into the application the HTTP layer serves.
package app

import (
	"encoding/json"
	"fmt"

	"pairwise-gsb/mqttsession/internal/casepack"
	"pairwise-gsb/mqttsession/internal/engine"
	"pairwise-gsb/mqttsession/internal/mqtt"
	"pairwise-gsb/mqttsession/internal/store"
)

// State is the full application state persisted inside each version.
type State struct {
	Packets   []engine.Packet         `json:"packets"`
	Params    engine.Params           `json:"params"`
	Decisions []engine.Decision       `json:"decisions"`
	Derived   *engine.Derived         `json:"derived"`
	Notes     []engine.RecomputeNote  `json:"notes"`
	Archive   []casepack.ArchiveEntry `json:"archive"`
	Snapshot  casepack.BrokerSnapshot `json:"snapshot"`
}

// App orchestrates mutations: every change recomputes the derived state
// through the dependency graph and commits one immutable version.
type App struct {
	Store *store.Store
}

func New(st *store.Store) *App { return &App{Store: st} }

// Current loads the current version and its state.
func (a *App) Current() (*State, store.Version, error) {
	v, err := a.Store.Current()
	if err != nil || v.ID == "" {
		return nil, v, err
	}
	var s State
	if err := json.Unmarshal(v.StateJSON, &s); err != nil {
		return nil, v, err
	}
	return &s, v, nil
}

// At loads the state of any historical version: reviewing an old event
// restores the dependency versions and visible conclusions of that moment
// instead of overwriting them with the latest computation.
func (a *App) At(versionID string) (*State, error) {
	v, err := a.Store.VersionAt(versionID)
	if err != nil {
		return nil, err
	}
	var s State
	return &s, json.Unmarshal(v.StateJSON, &s)
}

func (a *App) commit(base, label, kind string, payload any, s *State) (store.Version, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return store.Version{}, err
	}
	_, v, err := a.Store.Commit(base, label, kind, payload, data)
	return v, err
}

// ImportCase performs the initial import of the offline case pack: raw
// packet bytes, direction, packet ids, DUP/retain flags, clean
// start/session expiry, topic aliases and clocks are all preserved; the
// counterexample archive is computed from the baseline.
func (a *App) ImportCase() (store.Version, error) {
	s := &State{
		Packets:  casepack.Trace(),
		Params:   engine.Params{RuleSetID: "rules-v1"},
		Snapshot: casepack.Snapshot(),
		Archive:  casepack.BuildArchive(),
	}
	s.Derived = engine.Reconstruct(s.Packets, s.Params, s.Decisions)
	s.Notes = engine.DiffRecompute(&engine.Derived{}, s.Derived, engine.ChangedInputs{
		ChangedBy: "initial import of case pack",
	})
	return a.commit("", "初始导入：MQTT 双向包轨迹 + broker 会话快照", "import",
		map[string]any{"client_id": casepack.ClientID, "packets": len(s.Packets)}, s)
}

// ReviseParams applies a parameter revision (session-expiry override,
// seconds, virtual-time basis) and recomputes only the affected subgraph.
func (a *App) ReviseParams(expiryOverrideSec int64) (store.Version, error) {
	s, _, err := a.Current()
	if err != nil || s == nil {
		return store.Version{}, fmt.Errorf("no current state: %w", err)
	}
	prev := s.Derived
	next := *s
	next.Params.SessionExpiryOverride = &expiryOverrideSec
	next.Derived = engine.Reconstruct(next.Packets, next.Params, next.Decisions)
	next.Notes = engine.DiffRecompute(prev, next.Derived, engine.ChangedInputs{
		Params: true, ChangedBy: fmt.Sprintf("parameter revision: session expiry override %ds", expiryOverrideSec),
	})
	return a.commit("", fmt.Sprintf("参数修订：session expiry override=%ds", expiryOverrideSec),
		"param_revision", map[string]any{"session_expiry_override_sec": expiryOverrideSec}, &next)
}

// MutateSource changes exactly one direct source (clears the DUP flag of
// one PUBLISH, re-encoding its raw bytes) so the impact is limited to the
// correct dependency scope.
func (a *App) MutateSource(packetID string) (store.Version, error) {
	s, _, err := a.Current()
	if err != nil || s == nil {
		return store.Version{}, fmt.Errorf("no current state: %w", err)
	}
	prev := s.Derived
	next := *s
	next.Packets = append([]engine.Packet(nil), s.Packets...)
	found := false
	for i := range next.Packets {
		if next.Packets[i].ID != packetID {
			continue
		}
		p := &next.Packets[i]
		if len(p.Raw) > 0 && p.Dec.Type == mqtt.TypePUBLISH {
			p.Raw = append([]byte(nil), p.Raw...)
			p.Raw[0] &^= 0x08 // clear DUP
			p.Dec = mqtt.Decode(p.Raw)
			found = true
		}
	}
	if !found {
		return store.Version{}, fmt.Errorf("packet %s not found or not a PUBLISH", packetID)
	}
	next.Derived = engine.Reconstruct(next.Packets, next.Params, next.Decisions)
	next.Notes = engine.DiffRecompute(prev, next.Derived, engine.ChangedInputs{
		Packets: []string{packetID}, ChangedBy: "source mutation: DUP flag cleared on " + packetID,
	})
	return a.commit("", "源数据改动：清除 "+packetID+" 的 DUP 标志", "source_mutation",
		map[string]any{"packet_id": packetID, "change": "dup-cleared"}, &next)
}

// Decide records a human decision from a known base version. Two users
// editing from the same version produce a resolvable conflict; the unchosen
// candidate is preserved.
func (a *App) Decide(baseVersion string, dec engine.Decision) (store.Version, error) {
	s, _, err := a.Current()
	if err != nil || s == nil {
		return store.Version{}, fmt.Errorf("no current state: %w", err)
	}
	prev := s.Derived
	next := *s
	dec.Status = "adopted"
	next.Decisions = append(append([]engine.Decision(nil), s.Decisions...), dec)
	next.Derived = engine.Reconstruct(next.Packets, next.Params, next.Decisions)
	next.Notes = engine.DiffRecompute(prev, next.Derived, engine.ChangedInputs{
		Decisions: []string{dec.ID}, ChangedBy: "human decision by " + dec.Author,
	})
	return a.commit(baseVersion, "人工决定："+dec.ID+" on "+dec.TargetID, "decision", dec, &next)
}

// ResolveConflict resolves a journaled conflict. keep="first" keeps the
// adopted decision and records the challenger's as superseded; keep="second"
// swaps them. Both candidates remain stored either way.
func (a *App) ResolveConflict(conflictID, keep string, challenger engine.Decision) (store.Version, error) {
	s, _, err := a.Current()
	if err != nil || s == nil {
		return store.Version{}, fmt.Errorf("no current state: %w", err)
	}
	prev := s.Derived
	next := *s
	challenger.Status = "superseded"
	if keep == "second" {
		for i := range next.Decisions {
			if next.Decisions[i].TargetID == challenger.TargetID && next.Decisions[i].Status == "adopted" {
				next.Decisions[i].Status = "superseded"
			}
		}
		challenger.Status = "adopted"
	}
	next.Decisions = append(append([]engine.Decision(nil), s.Decisions...), challenger)
	next.Derived = engine.Reconstruct(next.Packets, next.Params, next.Decisions)
	next.Notes = engine.DiffRecompute(prev, next.Derived, engine.ChangedInputs{
		Decisions: []string{challenger.ID}, ChangedBy: "conflict resolution " + conflictID + " keep=" + keep,
	})
	v, err := a.commit("", "冲突解决："+conflictID+" 保留 "+keep, "conflict_resolution",
		map[string]any{"conflict": conflictID, "keep": keep}, &next)
	if err != nil {
		return v, err
	}
	return v, a.Store.ResolveConflict(conflictID, keep)
}

// Replay re-runs one counterexample mutation live and returns the mutated
// derived state plus dependency notes, without committing anything.
func (a *App) Replay(archiveID string) (*engine.Derived, []engine.RecomputeNote, *casepack.ArchiveEntry, error) {
	s, _, err := a.Current()
	if err != nil || s == nil {
		return nil, nil, nil, fmt.Errorf("no current state: %w", err)
	}
	for i := range s.Archive {
		e := &s.Archive[i]
		if e.ID != archiveID {
			continue
		}
		mutated, changed, err := casepack.ApplyMutation(archiveID, casepack.Trace())
		if err != nil {
			return nil, nil, nil, err
		}
		d := engine.Reconstruct(mutated, s.Params, s.Decisions)
		base := engine.Reconstruct(casepack.Trace(), s.Params, s.Decisions)
		notes := engine.DiffRecompute(base, d,
			engine.ChangedInputs{Packets: changed, ChangedBy: "replay of " + archiveID})
		return d, notes, e, nil
	}
	return nil, nil, nil, fmt.Errorf("archive entry %s not found", archiveID)
}
