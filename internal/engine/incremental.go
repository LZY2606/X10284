package engine

import (
	"encoding/json"
	"fmt"
	"sort"
)

// ChangedInputs describes what actually changed between two runs: the
// direct source of a recompute. Only nodes whose dependency closure
// intersects ChangedInputs are recomputed; everything else is carried over
// by identity with a "still-valid" note.
type ChangedInputs struct {
	Packets      []string `json:"packets"`       // packet ids added/mutated/removed
	Params       bool     `json:"params"`        // rule parameters revised
	Decisions    []string `json:"decisions"`     // decision ids added
	ChangedBy    string   `json:"changed_by"`    // human-readable origin
}

// nodePackets maps a derived node to the packet ids it depends on.
func nodePackets(d *Derived) map[NodeRef][]string {
	out := map[NodeRef][]string{}
	for _, g := range d.Generations {
		out[NodeRef{Kind: "generation", ID: g.ID}] = nil // depends on params+connects
	}
	for _, x := range d.Exchanges {
		out[NodeRef{Kind: "exchange", ID: x.ID}] = append([]string(nil), x.Packets...)
	}
	for _, r := range d.Retained {
		ids := []string{}
		if r.SetBy != "" {
			ids = append(ids, r.SetBy)
		}
		if r.DeletedBy != "" {
			ids = append(ids, r.DeletedBy)
		}
		out[NodeRef{Kind: "retained", ID: r.ID}] = ids
	}
	for _, s := range d.Subs {
		out[NodeRef{Kind: "sub", ID: s.ID}] = []string{s.PacketID}
	}
	for _, e := range d.Expiries {
		out[NodeRef{Kind: "expiry", ID: e.ID}] = nil // depends on params+clock
	}
	return out
}

func hashNode(v any) string {
	b, _ := json.Marshal(v)
	return fmt.Sprintf("%x", fnv(b))
}

func fnv(b []byte) uint64 {
	h := uint64(1469598103934665603)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func nodeValues(d *Derived) map[NodeRef]string {
	out := map[NodeRef]string{}
	for _, g := range d.Generations {
		out[NodeRef{Kind: "generation", ID: g.ID}] = hashNode(g)
	}
	for _, x := range d.Exchanges {
		out[NodeRef{Kind: "exchange", ID: x.ID}] = hashNode(x)
	}
	for _, r := range d.Retained {
		out[NodeRef{Kind: "retained", ID: r.ID}] = hashNode(r)
	}
	for _, s := range d.Subs {
		out[NodeRef{Kind: "sub", ID: s.ID}] = hashNode(s)
	}
	for _, e := range d.Expiries {
		out[NodeRef{Kind: "expiry", ID: e.ID}] = hashNode(e)
	}
	return out
}

// DiffRecompute compares prev and next derived states against the changed
// inputs and explains, per node, why it is still valid or was recomputed.
// Nodes whose dependency closure is untouched keep their prior identity and
// are reported "still-valid"; they are not rewritten by the store.
func DiffRecompute(prev, next *Derived, ch ChangedInputs) []RecomputeNote {
	prevVals := nodeValues(prev)
	nextVals := nodeValues(next)
	prevDeps := nodePackets(prev)
	nextDeps := nodePackets(next)
	changedPkt := map[string]bool{}
	for _, id := range ch.Packets {
		changedPkt[id] = true
	}

	var notes []RecomputeNote
	refs := map[NodeRef]bool{}
	for r := range prevVals {
		refs[r] = true
	}
	for r := range nextVals {
		refs[r] = true
	}
	sorted := make([]NodeRef, 0, len(refs))
	for r := range refs {
		sorted = append(sorted, r)
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Kind != sorted[j].Kind {
			return sorted[i].Kind < sorted[j].Kind
		}
		return sorted[i].ID < sorted[j].ID
	})

	for _, ref := range sorted {
		_, inPrev := prevVals[ref]
		_, inNext := nextVals[ref]
		switch {
		case inPrev && !inNext:
			notes = append(notes, RecomputeNote{Node: ref, Status: "removed",
				Reason: "inputs changed (" + ch.ChangedBy + "); node no longer derivable"})
		case !inPrev && inNext:
			notes = append(notes, RecomputeNote{Node: ref, Status: "new",
				Reason: "introduced by changed inputs (" + ch.ChangedBy + ")"})
		case prevVals[ref] == nextVals[ref]:
			notes = append(notes, RecomputeNote{Node: ref, Status: "still-valid",
				Reason: stillValidReason(ref, nextDeps[ref], changedPkt, ch)})
		default:
			notes = append(notes, RecomputeNote{Node: ref, Status: "recomputed",
				Reason: recomputeReason(ref, prevDeps[ref], nextDeps[ref], changedPkt, ch)})
		}
	}
	return notes
}

func stillValidReason(ref NodeRef, deps []string, changed map[string]bool, ch ChangedInputs) string {
	hit := []string{}
	for _, d := range deps {
		if changed[d] {
			hit = append(hit, d)
		}
	}
	if len(hit) == 0 && !ch.Params && len(ch.Decisions) == 0 {
		return fmt.Sprintf("dependency closure untouched by %s; carried over by identity", ch.ChangedBy)
	}
	if len(hit) == 0 && !ch.Params {
		return "no dependency on changed packets; decisions do not reach this node"
	}
	if len(hit) == 0 {
		return "parameter revision does not reach this node's dependency closure"
	}
	return "dependencies changed but derived value is invariant under the change"
}

func recomputeReason(ref NodeRef, prevDeps, nextDeps []string, changed map[string]bool, ch ChangedInputs) string {
	hit := map[string]bool{}
	for _, d := range append(append([]string(nil), prevDeps...), nextDeps...) {
		if changed[d] {
			hit[d] = true
		}
	}
	ids := []string{}
	for id := range hit {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	reason := "dependency closure changed by " + ch.ChangedBy
	if len(ids) > 0 {
		reason += fmt.Sprintf("; changed packets: %v", ids)
	}
	if ch.Params {
		reason += "; rule parameters revised"
	}
	if len(ch.Decisions) > 0 {
		reason += fmt.Sprintf("; decisions applied: %v", ch.Decisions)
	}
	return reason
}
