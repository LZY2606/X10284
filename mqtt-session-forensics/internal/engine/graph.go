package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/example/mqtt-session-forensics/internal/model"
)

// NodeStatus explains why a node is still valid or needs recomputation.
type NodeStatus string

const (
	StatusValid     NodeStatus = "valid"        // inputs unchanged, result still valid
	StatusRecomputed NodeStatus = "recomputed"  // recomputed, value identical
	StatusChanged   NodeStatus = "changed"      // recomputed, value differs
	StatusNew       NodeStatus = "new"          // newly introduced
	StatusRemoved   NodeStatus = "removed"      // existed only in the prior graph
)

// NodeReport is one entry of the change propagation report.
type NodeReport struct {
	NodeUID        string     `json:"node_uid"`
	Kind           string     `json:"kind"`
	Status         NodeStatus `json:"status"`
	Reason         string     `json:"reason"`
	DependsOn      []string   `json:"depends_on"`
	StableValueID  string     `json:"stable_value_id"`
}

// PropagationReport explains every node after a recomputation.
type PropagationReport struct {
	FromVersion int          `json:"from_version"`
	ToVersion   int          `json:"to_version"`
	Reports     []NodeReport `json:"reports"`
}

// DependsOn returns the direct input dependencies of a node. Dependency edges
// always point from a derived node to source material (packets, snapshots,
// parameters) or to an earlier derived node.
func DependsOn(g *model.Graph, uid string) []string {
	out := map[string]bool{}
	addSrc := func(refs []model.SourceRef) {
		for _, r := range refs {
			out[r.Kind+":"+r.ID] = true
		}
	}
	switch {
	case g.Generations[uid] != nil:
		addSrc(g.Generations[uid].Sources)
	case g.Flows[uid] != nil:
		f := g.Flows[uid]
		out["node:"+f.GenUID] = true
		addSrc(f.Sources)
	case g.Correspondence[uid] != nil:
		addSrc(g.Correspondence[uid].Sources)
	case g.Subscriptions[uid] != nil:
		n := g.Subscriptions[uid]
		out["node:"+n.GenUID] = true
		addSrc(n.Sources)
	case g.Retained[uid] != nil:
		addSrc(g.Retained[uid].Sources)
	case g.Aliases[uid] != nil:
		addSrc(g.Aliases[uid].Sources)
	case g.Expiries[uid] != nil:
		n := g.Expiries[uid]
		out["node:"+n.GenUID] = true
		out["param:mqtt311_session_expiry_seconds"] = true
		addSrc(n.Sources)
	case g.Confusions[uid] != nil:
		addSrc(g.Confusions[uid].Sources)
	}
	res := make([]string, 0, len(out))
	for k := range out {
		res = append(res, k)
	}
	sort.Strings(res)
	return res
}

// StableValueID is a content hash used as the stable identity of a derived
// value; it survives export/delete/import because it depends only on content.
func StableValueID(g *model.Graph, uid string) string {
	var node any
	switch {
	case g.Generations[uid] != nil:
		node = g.Generations[uid]
	case g.Flows[uid] != nil:
		node = g.Flows[uid]
	case g.Correspondence[uid] != nil:
		node = g.Correspondence[uid]
	case g.Subscriptions[uid] != nil:
		node = g.Subscriptions[uid]
	case g.Retained[uid] != nil:
		node = g.Retained[uid]
	case g.Aliases[uid] != nil:
		node = g.Aliases[uid]
	case g.Expiries[uid] != nil:
		node = g.Expiries[uid]
	case g.Confusions[uid] != nil:
		node = g.Confusions[uid]
	default:
		return ""
	}
	sum := sha256.Sum256(canonicalJSON(node))
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}
