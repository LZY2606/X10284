package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/example/mqtt-session-forensics/internal/model"
)

func (e *Engine) finalize(version int) *model.Graph {
	// Expiry boundaries are decided at CONNECT time (virtual clock).
	// Broker snapshot cross-checks: a snapshot citing a packet id must agree on
	// the generation it belongs to (multi-generation confusion guard).
	e.checkSnapshots()

	g := &model.Graph{
		Version:        version,
		Generations:    map[string]*model.GenerationNode{},
		Flows:          map[string]*model.FlowNode{},
		Correspondence: map[string]*model.CorrespondenceNode{},
		Subscriptions:  e.subOut,
		Retained:       e.retained,
		Aliases:        e.aliasOut,
		Expiries:       e.expiryOut,
		Confusions:     e.confusionOut,
		Diagnostics:    e.diag,
	}
	for uid, gr := range e.gens {
		g.Generations[uid] = gr.node
		for _, byDir := range gr.flows {
			for _, incs := range byDir {
				for _, f := range incs {
					g.Flows[f.UID] = f
				}
			}
		}
	}
	g.Order = append(g.Order, e.order...)
	// Stable within-kind ordering of node lists for export reproducibility.
	g.Order = sortOrder(g.Order)
	return g
}

type prefixRank struct{ p string; r int }

var ranks = []prefixRank{
	{"G:", 0}, {"A:", 1}, {"F:", 2}, {"C:", 3}, {"S:", 4},
	{"R:", 5}, {"E:", 6}, {"X:", 7},
}

func rankOf(k string) int {
	for _, pr := range ranks {
		if len(k) >= 2 && k[:2] == pr.p {
			return pr.r
		}
	}
	return 9
}

func sortOrder(in []string) []string {
	out := append([]string(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rankOf(out[i]), rankOf(out[j])
		if ri != rj {
			return ri < rj
		}
		return out[i] < out[j]
	})
	return out
}

func (e *Engine) checkSnapshots() {
	// Group snapshot evidence by (client, packet id). The same numeric id in
	// several session generations is the multi-generation confusion surface;
	// both generations stay candidates.
	type hit struct {
		genUID string
		snapID string
	}
	groups := map[string][]hit{}
	var orderKeys []string
	for _, snap := range e.bundle.Snapshots {
		var doc map[string]any
		if err := json.Unmarshal(snap.JSON, &doc); err != nil {
			e.addDiag(model.SevCritical, "snapshot_malformed_json",
				snap.ID+": "+err.Error(), "", "")
			continue
		}
		inflight, _ := doc["inflight_packet_ids"].([]any)
		for _, item := range inflight {
			num, ok := toUint16(item)
			if !ok {
				continue
			}
			key := snap.ClientID + "|" + strconv.Itoa(int(num))
			if len(groups[key]) == 0 {
				orderKeys = append(orderKeys, key)
			}
			groups[key] = append(groups[key], hit{genUID: snapshotGenHint(doc), snapID: snap.ID})
		}
	}
	for _, key := range orderKeys {
		hits := groups[key]
		ci := strings.IndexByte(key, '|')
		client, pidStr := key[:ci], key[ci+1:]
		pid, _ := strconv.Atoi(pidStr)
		var gens []string
		for uid, gr := range e.gens {
			if gr.node.ClientID != client {
				continue
			}
			if _, ok := gr.flows[uint16(pid)]; ok {
				gens = append(gens, uid)
			}
		}
		sort.Strings(gens)
		if len(gens) >= 2 {
			cuid := "conf:snap:" + client + ":" + pidStr
			if _, exists := e.confusionOut[cuid]; !exists {
				var srcs []model.SourceRef
				for _, h := range hits {
					srcs = append(srcs, model.SourceRef{Kind: "snapshot", ID: h.snapID})
				}
				e.confusionOut[cuid] = &model.ConfusionNode{
					UID: cuid, Kind: model.NodeConfusion, PacketID: uint16(pid),
					PacketRef:  srcs[0],
					Candidates: gens, Chosen: gens[len(gens)-1],
					Rule:       "packet id is meaningful only within one session generation; broker snapshots disagree across generations, both retained",
					Sources:    srcs,
					Diagnostics: []model.Diagnostic{{Severity: model.SevWarning,
						Code: "snapshot_pid_multigeneration",
						Message: fmt.Sprintf("packet id %d for %s appears in generations %v", pid, client, gens)}},
				}
				e.order = append(e.order, "X:"+cuid)
			}
		}
	}
}

func snapshotGenHint(doc map[string]any) string {
	if v, ok := doc["generation_serial"].(float64); ok {
		return "#" + strconv.Itoa(int(v))
	}
	return ""
}

func toUint16(v any) (uint16, bool) {
	switch x := v.(type) {
	case float64:
		return uint16(x), x >= 0 && x <= 65535
	case string:
		if n, err := strconv.ParseUint(x, 10, 16); err == nil {
			return uint16(n), true
		}
	}
	return 0, false
}

