// Package engine reconstructs MQTT session state (QoS handshakes,
// subscriptions, retained messages) from captured packet traces. Core
// invariants enforced here:
//   - packet ids are interpreted only within a single session generation;
//   - QoS 2 duplicates are idempotent but never drop handshake phase;
//   - session-expiry boundaries use virtual time;
//   - retained messages are kept separate from session (inflight) messages.
package engine

import (
	"fmt"

	"pairwise-gsb/mqttsession/internal/mqtt"
)

// Packet is one captured frame. Raw bytes, direction, flags and both clock
// representations are preserved exactly as imported.
type Packet struct {
	ID          string         `json:"id"` // stable identity, e.g. "pkt-0001"
	Raw         []byte         `json:"raw"`
	Dir         mqtt.Direction `json:"dir"`
	VirtualTime int64          `json:"virtual_time_ms"` // virtual clock, ms
	ClockRaw    string         `json:"clock_raw"`       // original wall-clock text, unparsed
	Dec         mqtt.Decoded   `json:"dec"`
}

// Params are the revisable rule parameters of a reconstruction run.
type Params struct {
	RuleSetID string `json:"rule_set_id"`
	// SessionExpirySec, when non-nil, overrides the CONNECT-declared expiry
	// for boundary judgements (seconds, virtual-time basis).
	SessionExpiryOverride *int64 `json:"session_expiry_override,omitempty"`
}

// Candidate is one legal interpretation of an ambiguous packet. Unchosen
// candidates are never deleted.
type Candidate struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Target string `json:"target"` // exchange id this candidate binds to
}

// Exchange is one QoS handshake state machine instance.
type Exchange struct {
	ID         string         `json:"id"` // "xch-gen1-c2s-0042-a"
	Generation string         `json:"generation"`
	Dir        mqtt.Direction `json:"dir"`
	PacketID   int            `json:"packet_id"`
	QoS        int            `json:"qos"`
	Topic      string         `json:"topic"`
	Phase      string         `json:"phase"`      // see Phase* constants
	Packets    []string       `json:"packets"`    // packet record ids, in order
	Duplicates []string       `json:"duplicates"` // DUP packets folded in idempotently
	Orphaned   bool           `json:"orphaned"`   // left incomplete by a generation boundary
	ReusedID   bool           `json:"reused_id"`  // packet id reused after completion
	Ambiguous  bool           `json:"ambiguous"`
	Candidates []Candidate    `json:"candidates,omitempty"`
	ResolvedBy string         `json:"resolved_by,omitempty"` // decision id
}

// QoS handshake phases.
const (
	PhaseAwaitPubAck  = "await-puback"
	PhaseAwaitPubRec  = "await-pubrec"
	PhaseAwaitPubRel  = "await-pubrel"
	PhaseAwaitPubComp = "await-pubcomp"
	PhaseComplete     = "complete"
)

// Generation is one session generation: packet ids are only meaningful
// inside exactly one of these.
type Generation struct {
	ID           string         `json:"id"` // "gen-1"
	Index        int            `json:"index"`
	ClientID     string         `json:"client_id"`
	CleanStart   bool           `json:"clean_start"`
	ExpirySec    int64          `json:"expiry_sec"`
	StartVT      int64          `json:"start_vt_ms"`
	EndVT        int64          `json:"end_vt_ms"`
	Cause        string         `json:"cause"`         // why this generation began
	TopicAliases map[int]string `json:"topic_aliases"` // reset per connection
}

// RetainedEntry is the retained-message store, kept apart from inflight
// session state.
type RetainedEntry struct {
	ID        string `json:"id"`
	Topic     string `json:"topic"`
	SetBy     string `json:"set_by"`     // packet id
	DeletedBy string `json:"deleted_by"` // packet id of zero-payload retain delete
	Active    bool   `json:"active"`
}

// SubChange is one subscription mutation.
type SubChange struct {
	ID         string `json:"id"`
	Generation string `json:"generation"`
	Filter     string `json:"filter"`
	Op         string `json:"op"` // "subscribe" | "unsubscribe"
	PacketID   string `json:"packet_id"`
	VT         int64  `json:"vt_ms"`
}

// ExpiryDecision records a session-expiry boundary judgement on the
// virtual-time basis.
type ExpiryDecision struct {
	ID       string `json:"id"`
	FromGen  string `json:"from_gen"`
	ToGen    string `json:"to_gen"`
	GapMs    int64  `json:"gap_ms"`
	ExpiryMs int64  `json:"expiry_ms"`
	Verdict  string `json:"verdict"` // "session-continued" | "session-expired"
	Basis    string `json:"basis"`   // always "virtual-time"
}

// Diagnostic is attached to values that could not be normalised; the raw
// value stays in place.
type Diagnostic struct {
	ID       string `json:"id"`
	PacketID string `json:"packet_id"`
	Detail   string `json:"detail"`
}

// Decision is a human ruling stored as an event; it resolves an ambiguous
// candidate set without deleting the unchosen candidates.
type Decision struct {
	ID        string   `json:"id"`
	Status    string   `json:"status"` // "adopted" | "superseded" (kept, not applied)
	TargetID  string   `json:"target_id"` // exchange id
	Chosen    string   `json:"chosen"`    // candidate id
	Rejected  []string `json:"rejected"`  // candidate ids kept but unadopted
	Author    string   `json:"author"`
	Rationale string   `json:"rationale"`
}

// Derived is the full reconstructed state.
type Derived struct {
	Generations []Generation     `json:"generations"`
	Exchanges   []Exchange       `json:"exchanges"`
	Retained    []RetainedEntry  `json:"retained"`
	Subs        []SubChange      `json:"subs"`
	Expiries    []ExpiryDecision `json:"expiries"`
	Diagnostics []Diagnostic     `json:"diagnostics"`
}

// NodeRef identifies one derived node for dependency reporting.
type NodeRef struct {
	Kind string `json:"kind"` // "generation"|"exchange"|"retained"|"sub"|"expiry"
	ID   string `json:"id"`
}

// RecomputeNote explains why a node is still valid or was recomputed.
type RecomputeNote struct {
	Node   NodeRef `json:"node"`
	Status string  `json:"status"` // "still-valid" | "recomputed" | "new" | "removed"
	Reason string  `json:"reason"`
}

func exchangeID(gen string, dir mqtt.Direction, packetID, seq int) string {
	return fmt.Sprintf("xch-%s-%s-%04d-%c", gen, dir, packetID, 'a'+seq)
}
