package engine

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/example/mqtt-session-forensics/internal/model"
)

func canonicalJSON(v any) []byte {
	// encoding/json sorts map keys deterministically.
	b, _ := json.Marshal(v)
	return b
}

// Propagate compares the previous graph with the freshly computed one and
// marks only nodes affected by changed inputs. The changed-input set is walked
// through the dependency graph: anything not reachable remains "valid" with the
// reason that its dependency closure is unchanged.
func Propagate(prev, next *model.Graph, changedInputs map[string]bool) *PropagationReport {
	rep := &PropagationReport{FromVersion: prev.Version, ToVersion: next.Version}
	all := map[string]*model.Graph{"prev": prev, "next": next}
	_ = all

	uids := map[string]bool{}
	for u := range prev.Generations {
		uids[u] = true
	}
	collectUids(prev, uids)
	collectUids(next, uids)

	// Reachability through dependency edges of the next graph.
	reachable := map[string]bool{}
	var walk func(string)
	walk = func(uid string) {
		full := "node:" + uid
		if changedInputs[full] || changedInputs[uid] {
			reachable[uid] = true
		}
		for _, dep := range DependsOn(next, uid) {
			if changedInputs[dep] {
				reachable[uid] = true
			}
		}
		if reachable[uid] {
			return
		}
	}

	ordered := append([]string(nil), next.Order...)
	// include removed nodes from prev
	for u := range uids {
		if _, ok := nodeOf(next, u); !ok {
			ordered = append(ordered, u)
		}
	}
	sort.Strings(ordered)
	seen := map[string]bool{}
	for _, uid := range ordered {
		if seen[uid] {
			continue
		}
		seen[uid] = true
		og, inPrev := nodeOf(prev, uid)
		ng, inNext := nodeOf(next, uid)
		if !inNext && inPrev {
			rep.Reports = append(rep.Reports, NodeReport{NodeUID: uid, Kind: kindOf(prev, uid),
				Status: StatusRemoved, Reason: "its input material disappeared", DependsOn: DependsOn(prev, uid)})
			continue
		}
		walk(uid)
		r := NodeReport{NodeUID: uid, Kind: kindOf(next, uid), DependsOn: DependsOn(next, uid),
			StableValueID: StableValueID(next, uid)}
		switch {
		case !inPrev:
			r.Status = StatusNew
			r.Reason = "newly derived from current inputs"
		case reachable[uid]:
			oldID := StableValueID(prev, uid)
			if bytes.Equal(canonicalJSON(stripVersion(og)), canonicalJSON(stripVersion(ng))) {
				r.Status = StatusRecomputed
				r.Reason = "an input changed but this value is unaffected after recomputation"
			} else {
				r.Status = StatusChanged
				r.Reason = "reached from a changed dependency: " + joinChanged(next, uid, changedInputs)
			}
			r.StableValueID = StableValueID(next, uid)
			_ = oldID
		default:
			r.Status = StatusValid
			r.Reason = "dependency closure unchanged; result still valid without recomputation"
		}
		rep.Reports = append(rep.Reports, r)
	}
	return rep
}

func joinChanged(g *model.Graph, uid string, changed map[string]bool) string {
	deps := DependsOn(g, uid)
	hit := []string{}
	for _, d := range deps {
		if changed[d] {
			hit = append(hit, d)
		}
	}
	if len(hit) == 0 {
		return "indirect dependency"
	}
	out := hit[0]
	if len(hit) > 1 {
		out += ", ..."
	}
	return out
}

func stripVersion(v any) any {
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func collectUids(g *model.Graph, into map[string]bool) {
	for u := range g.Generations {
		into[u] = true
	}
	for u := range g.Flows {
		into[u] = true
	}
	for u := range g.Correspondence {
		into[u] = true
	}
	for u := range g.Subscriptions {
		into[u] = true
	}
	for u := range g.Retained {
		into[u] = true
	}
	for u := range g.Aliases {
		into[u] = true
	}
	for u := range g.Expiries {
		into[u] = true
	}
	for u := range g.Confusions {
		into[u] = true
	}
}

func nodeOf(g *model.Graph, uid string) (any, bool) {
	if n, ok := g.Generations[uid]; ok {
		return n, true
	}
	if n, ok := g.Flows[uid]; ok {
		return n, true
	}
	if n, ok := g.Correspondence[uid]; ok {
		return n, true
	}
	if n, ok := g.Subscriptions[uid]; ok {
		return n, true
	}
	if n, ok := g.Retained[uid]; ok {
		return n, true
	}
	if n, ok := g.Aliases[uid]; ok {
		return n, true
	}
	if n, ok := g.Expiries[uid]; ok {
		return n, true
	}
	if n, ok := g.Confusions[uid]; ok {
		return n, true
	}
	return nil, false
}

func kindOf(g *model.Graph, uid string) string {
	if n, ok := g.Generations[uid]; ok {
		return n.Kind
	}
	if n, ok := g.Flows[uid]; ok {
		return n.Kind
	}
	if n, ok := g.Correspondence[uid]; ok {
		return n.Kind
	}
	if n, ok := g.Subscriptions[uid]; ok {
		return n.Kind
	}
	if n, ok := g.Retained[uid]; ok {
		return n.Kind
	}
	if n, ok := g.Aliases[uid]; ok {
		return n.Kind
	}
	if n, ok := g.Expiries[uid]; ok {
		return n.Kind
	}
	if n, ok := g.Confusions[uid]; ok {
		return n.Kind
	}
	return ""
}
