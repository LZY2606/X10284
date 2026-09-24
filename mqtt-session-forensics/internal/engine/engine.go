// Package engine reconstructs MQTT session generations, QoS 1/2 handshakes,
// subscription state, retained store, topic alias maps and session-expiry
// verdicts from a raw Bundle. Reconstruction is pure/deterministic: the same
// (bundle, version) always yields the same Graph.
//
// Guarded semantics:
//   - a packet id is interpreted only within one session generation;
//   - repeated QoS 2 packets are idempotent but never collapse handshake phase;
//   - session-expiry boundaries are evaluated on virtual time, keeping every
//     legal candidate when the boundary is exactly on the edge;
//   - retained messages are stored independently of session generations.
package engine

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/example/mqtt-session-forensics/internal/model"
	"github.com/example/mqtt-session-forensics/internal/mqtt"
)

const nsPerS = int64(1_000_000_000)

// NormalizeTime keeps the original representation and adds a virtual-time
// coordinate. Values that cannot be converted stay in place with a diagnosis;
// they never get dropped to make a chart render.
func NormalizeTime(t model.TimeRef) model.TimeRef {
	out := t
	if t.Unit == "virtual-ns" {
		if v, err := strconv.ParseInt(strings.TrimSpace(t.Original), 10, 64); err == nil {
			out.EpochNS = v
		} else {
			out.Unconvertible = true
			out.Diagnosis = "virtual-ns value is not an int64: " + err.Error()
		}
		return out
	}
	mult := int64(0)
	switch t.Unit {
	case "ns":
		mult = 1
	case "us":
		mult = 1_000
	case "ms":
		mult = 1_000_000
	case "s":
		mult = nsPerS
	default:
		out.Unconvertible = true
		out.Diagnosis = "unknown time unit/coordinate basis: " + t.Unit
		return out
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(t.Original), 10, 64); err == nil {
		out.EpochNS = v * mult
	} else {
		out.Unconvertible = true
		out.Diagnosis = "timestamp is not an int64: " + err.Error()
	}
	return out
}

type genRuntime struct {
	node      *model.GenerationNode
	flows     map[uint16]map[model.Direction][]*model.FlowNode // pid -> dir -> incarnations
	flowOrder map[string]*model.FlowNode
	subs      map[string]*model.SubscriptionNode
}

type connRuntime struct {
	id        string
	genUID    string
	clientID  string
	aliases   map[uint16]string
	aliasNode *model.AliasNode
	level     byte
}

// Engine holds reconstructed state during one replay.
type Engine struct {
	bundle *model.Bundle

	gens      map[string]*genRuntime
	genByClientSerial map[string]*genRuntime // clientID#serial
	conns     map[string]*connRuntime
	lastGen   map[string]*genRuntime // client -> most recent generation
	retained  map[string]*model.RetainedNode
	flowUIDs  map[string]bool

	diag      []model.Diagnostic
	order     []string

	// outputs
	genOut      map[string]*model.GenerationNode
	corrOut     map[string]*model.CorrespondenceNode
	subOut      map[string]*model.SubscriptionNode
	aliasOut    map[string]*model.AliasNode
	expiryOut   map[string]*model.ExpiryNode
	confusionOut map[string]*model.ConfusionNode
	expiryTracked map[string]bool
}

// Compute rebuilds the whole graph deterministically.
func Compute(b *model.Bundle, version int) *model.Graph {
	e := &Engine{
		bundle:            b,
		gens:              map[string]*genRuntime{},
		genByClientSerial: map[string]*genRuntime{},
		conns:             map[string]*connRuntime{},
		lastGen:           map[string]*genRuntime{},
		retained:          map[string]*model.RetainedNode{},
		flowUIDs:          map[string]bool{},
		genOut:            map[string]*model.GenerationNode{},
		corrOut:           map[string]*model.CorrespondenceNode{},
		subOut:            map[string]*model.SubscriptionNode{},
		aliasOut:          map[string]*model.AliasNode{},
		expiryOut:         map[string]*model.ExpiryNode{},
		confusionOut:      map[string]*model.ConfusionNode{},
		expiryTracked:     map[string]bool{},
	}

	pkts := make([]model.RawPacket, len(b.Packets))
	copy(pkts, b.Packets)
	sort.SliceStable(pkts, func(i, j int) bool {
		ti := NormalizeTime(pkts[i].ObservedAt)
		tj := NormalizeTime(pkts[j].ObservedAt)
		if ti.Unconvertible || tj.Unconvertible {
			return pkts[i].IngestOrder < pkts[j].IngestOrder
		}
		if ti.EpochNS != tj.EpochNS {
			return ti.EpochNS < tj.EpochNS
		}
		return pkts[i].IngestOrder < pkts[j].IngestOrder
	})

	for i := range pkts {
		p := &pkts[i]
		p.ObservedAt = NormalizeTime(p.ObservedAt)
		raw, err := hex.DecodeString(p.RawHex)
		if err != nil {
			e.addDiag(model.SevCritical, "raw_hex_invalid", "raw bytes could not be hex-decoded", p.ID, "")
			continue
		}
		view := mqtt.Decode(raw)
		p.View = &view
		e.replay(p, raw)
	}

	g := e.finalize(version)
	return g
}

func (e *Engine) addDiag(sev model.Severity, code, msg, node, pkt string) {
	d := model.Diagnostic{Severity: sev, Code: code, Message: msg, NodeID: node, PacketID: pkt}
	e.diag = append(e.diag, d)
}

func pktVerID(p *model.RawPacket, version int) string { return fmt.Sprintf("%s@v%d", p.ID, version) }
func srcPkt(p *model.RawPacket, field string) model.SourceRef {
	return model.SourceRef{Kind: "packet", ID: p.ID, Field: field}
}
