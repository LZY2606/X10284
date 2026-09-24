// Package engine replays MQTT packet traces plus broker snapshots into
// derived session-imprint nodes. Core semantics:
//
//   - packet ids are interpreted only inside one session generation;
//   - QoS 2 duplicates are idempotent without losing handshake stage;
//   - session-expiry boundaries are evaluated on virtual time;
//   - retained messages are kept separate from session messages.
//
// Derivation is deterministic and dependency based: every node carries a
// basis hash, and Run classifies each node as reused / recomputed / added /
// removed relative to the parent version.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"mqtttrace/internal/domain"
)

const (
	RuleVersionCorrect = "correct@3"
	// RuleVersionNaive is an intentionally wrong rule set kept as an
	// unadopted candidate so counter-examples can demonstrate scoping.
	RuleVersionNaive = "naive@1"
)

// Input is one derivation request.
type Input struct {
	Bundle    domain.Bundle
	Params    domain.Params
	RuleSet   string // "correct" | "naive"
	VersionID string
	BaseNodes []domain.Node
}

// Run replays the bundle and returns derived nodes and machine-readable events.
func Run(in Input) (domain.Result, error) {
	if in.RuleSet == "" {
		in.RuleSet = "correct"
	}
	if in.RuleSet != "correct" && in.RuleSet != "naive" {
		return domain.Result{}, fmt.Errorf("unknown rule set %q", in.RuleSet)
	}
	if in.Params.BoundaryRule == "" {
		return domain.Result{}, fmt.Errorf("params.boundary_rule is required")
	}
	e := &engine{
		in:       in,
		naive:    in.RuleSet == "naive",
		ruleVer:  map[bool]string{true: RuleVersionNaive, false: RuleVersionCorrect}[in.RuleSet == "naive"],
		nodes:    map[string]*domain.Node{},
		retained: map[string]*domain.Node{},
		flows:    map[string]*flowState{},
		completed: map[string][]*flowState{},
		subs:     map[string]*domain.Node{},
	}
	if err := e.replay(); err != nil {
		return domain.Result{}, err
	}
	e.finalizeGenerations()
	e.finalizeSnapshots()
	e.finalizeExpiry()
	e.classifyReuse()

	res := domain.Result{}
	for _, n := range e.nodes {
		res.Nodes = append(res.Nodes, *n)
	}
	sort.SliceStable(res.Nodes, func(i, j int) bool {
		if res.Nodes[i].GenID != res.Nodes[j].GenID {
			return res.Nodes[i].GenID < res.Nodes[j].GenID
		}
		return res.Nodes[i].ID < res.Nodes[j].ID
	})
	res.Events = e.events
	return res, nil
}

type engine struct {
	in      Input
	naive   bool
	ruleVer string

	nodes map[string]*domain.Node
	order []string

	gens    []*genCtx
	current *genCtx

	retained  map[string]*domain.Node
	subs      map[string]*domain.Node
	flows     map[string]*flowState
	completed map[string][]*flowState

	snapshots []domain.Snapshot
	events    []domain.Event
	evSeq     int
}

type flowState struct {
	node      *domain.Node
	pid       int
	dir       string
	genID     string
	stage     string
	kinds     map[string]bool
	delivery  string // "" | retained-delivery | queued-offline
	interrupt bool
}

type genCtx struct {
	id          string
	seq         int
	clientID    string
	connect     *domain.Packet
	connack     *domain.Packet
	disconnect  *domain.Packet
	cleanStart  bool
	expirySec   uint32
	overrideSec *uint32
	aliasMaxUp  int
	aliasMaxDn  int
	aliasUp     map[int]string // client -> broker
	aliasDn     map[int]string // broker -> client
	unresolved  []map[string]any
	lastVTime   int64
	closeVTime  int64
	closeKind   string
}

func (g *genCtx) effectiveExpirySec() uint32 {
	if g.overrideSec != nil {
		return *g.overrideSec
	}
	return g.expirySec
}

func (g *genCtx) closeTime() int64 {
	if g.closeVTime != 0 {
		return g.closeVTime
	}
	return g.lastVTime
}

// ---- identity / hashing helpers ----

func h8(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:4])
}

func basis(ruleVer string, items ...any) string {
	core := append([]any{ruleVer}, items...)
	b, _ := json.Marshal(core)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:12])
}

func genID(seq int, clientID string, connectID string) string {
	return fmt.Sprintf("gen-%02d-%s-%s", seq, clientID, h8(clientID, connectID))
}

func flowID(genID, dir string, pid int) string {
	return fmt.Sprintf("flow-%s-%s-%05d", h8(genID), dir, pid)
}

func (e *engine) addNode(kind, id, genID, label string, payload map[string]any,
	evidence, deps []domain.Ref, b string) *domain.Node {
	n := &domain.Node{
		ID: id, Kind: kind, VersionID: e.in.VersionID, GenID: genID,
		Label: label, Payload: payload, Evidence: evidence, DependsOn: deps,
		BasisHash: b, Status: domain.StatusRecomputed,
	}
	if _, dup := e.nodes[id]; dup {
		id = fmt.Sprintf("%s-x%d", id, len(e.nodes))
		n.ID = id
	}
	e.nodes[id] = n
	e.order = append(e.order, id)
	return n
}

func (e *engine) ev(kind, principle, summary string, details map[string]any, evidence []domain.Ref, vtime int64) string {
	e.evSeq++
	id := fmt.Sprintf("evt-%03d-%s", e.evSeq, h8(summary, strconv.Itoa(e.evSeq)))
	e.events = append(e.events, domain.Event{
		ID: id, Seq: e.evSeq, Kind: kind, VersionID: e.in.VersionID,
		Principle: principle, Summary: summary, Details: details,
		Evidence: evidence, WallTime: time.Now().UTC().Format(time.RFC3339Nano),
		VTimeMs: vtime,
	})
	return id
}

func pktRef(p *domain.Packet) domain.Ref { return domain.Ref{Kind: "packet", ID: p.ID} }
func nodeRef(n *domain.Node) domain.Ref  { return domain.Ref{Kind: "node", ID: n.ID} }
func snapRef(s *domain.Snapshot) domain.Ref {
	return domain.Ref{Kind: "snapshot", ID: s.ID}
}

func vtimeOf(p *domain.Packet) int64 {
	if p.Clock.Convertible {
		return p.Clock.VTimeMs
	}
	return -1
}
