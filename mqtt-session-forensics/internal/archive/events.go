// Package archive implements the append-only counter-example archive: an
// immutable baseline plus single-source events. Every accept/reject/parameter
// decision is itself an event carrying machine-readable rule references and
// every legal candidate, adopted or not.
package archive

import "time"

// Event kinds.
const (
	EvBaseline     = "baseline_import"
	EvParamRevise  = "param_revise"
	EvSourcePatch  = "source_patch"
	EvDecision     = "manual_decision"
	EvBoundaryHit  = "boundary_experiment"
	EvReplayMarker = "replay_step"
)

// Event is one immutable archive entry.
type Event struct {
	Seq        int64           `json:"seq"`
	Branch     string          `json:"branch"`
	ParentSeq  int64           `json:"parent_seq"`
	Kind       string          `json:"kind"`
	AtNS       int64           `json:"at_ns"`
	Actor      string          `json:"actor,omitempty"`
	Title      string          `json:"title"`
	Summary    string          `json:"summary"`
	RuleRefs   []string        `json:"rule_refs,omitempty"`
	Payload    []byte          `json:"payload,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// BaselinePayload records the "one direct source only" change shape.
type BaselinePayload struct {
	CaseTitle   string                  `json:"case_title"`
	Bundle      []byte                  `json:"bundle_json"`
	Preserved   []string                `json:"preserved_fields"`
}

// ParamPayload describes a parameter revision.
type ParamPayload struct {
	Name      string `json:"name"`
	OldValue  string `json:"old_value"`
	NewValue  string `json:"new_value"`
	Unit      string `json:"unit"`
}

// SourcePatchPayload changes exactly one direct source field.
type SourcePatchPayload struct {
	PacketID string `json:"packet_id"`
	Field    string `json:"field"`
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`
}

// DecisionPayload keeps adopted AND rejected candidates.
type DecisionPayload struct {
	NodeUID        string   `json:"node_uid"`
	Issue          string   `json:"issue"`
	Candidates     []string `json:"candidates"`
	Adopted        string   `json:"adopted"`
	Rejected       []string `json:"rejected"`
	RuleRefs       []string `json:"rule_refs"`
}

// BoundaryPayload describes one counter-example boundary exercise.
type BoundaryPayload struct {
	Name         string   `json:"name"`
	Symbols      []string `json:"symbols"`
	AffectedKinds []string `json:"affected_node_kinds"`
	InputPacketID string   `json:"input_packet_id,omitempty"`
	ResultNodeID  string   `json:"result_node_id,omitempty"`
	Adopted      bool     `json:"adopted"`
	Note         string   `json:"note"`
}

// Machine-readable rule anchors referenced by decisions.
const (
	RuleGenScopedPacketID = "rule.packetid.generation-scoped"
	RuleQoS2Idempotent    = "rule.qos2.duplicate-idempotent-preserves-phase"
	RuleExpiryVirtualTime = "rule.session-expiry.virtual-time-boundary"
	RuleRetainSeparate    = "rule.retained.separate-from-session"
	RuleAliasConnection   = "rule.topic-alias.connection-scoped"
	RuleNoCollapse        = "rule.ambiguity.keep-all-candidates"
)

func nowNS() int64 { return time.Now().UnixNano() }

func NewEvent(seq int64, branch string, parent int64, kind, title, summary string, payload any) Event {
	ev := Event{Seq: seq, Branch: branch, ParentSeq: parent, Kind: kind,
		AtNS: nowNS(), Title: title, Summary: summary}
	ev.Payload = marshal(payload)
	return ev
}
