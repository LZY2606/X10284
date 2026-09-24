// Package domain holds the stable, storage-independent model of an MQTT
// session-imprint archive: original capture material, derived nodes,
// immutable events and version pointers.
package domain

import "encoding/json"

// Directions on the wire, relative to the broker.
const (
	DirToBroker = "to_broker" // client -> broker
	DirToClient = "to_client" // broker -> client
)

// MQTT control packet type names.
const (
	PKCONNECT     = "CONNECT"
	PKCONNACK     = "CONNACK"
	PKPUBLISH     = "PUBLISH"
	PKPUBACK      = "PUBACK"
	PKPUBREC      = "PUBREC"
	PKPUBREL      = "PUBREL"
	PKPUBCOMP     = "PUBCOMP"
	PKSUBSCRIBE   = "SUBSCRIBE"
	PKSUBACK      = "SUBACK"
	PKUNSUBSCRIBE = "UNSUBSCRIBE"
	PKUNSUBACK    = "UNSUBACK"
	PKPINGREQ     = "PINGREQ"
	PKPINGRESP    = "PINGRESP"
	PKDISCONNECT  = "DISCONNECT"
)

// Clock preserves the original time representation of a capture point and
// only optionally normalizes it onto the replay virtual timeline.
type Clock struct {
	Source string          `json:"source"`            // clock coordinate basis, e.g. "clientA@monotonic_ms"
	Unit   string          `json:"unit"`              // original unit, e.g. "ms-since-capture-start", "unix-ns"
	Epoch  string          `json:"epoch,omitempty"`   // epoch basis when absolute
	Raw    json.RawMessage `json:"raw"`               // original representation, verbatim
	VTimeMs int64          `json:"vtime_ms"`          // normalized virtual timeline coordinate
	VTimeBasis string       `json:"vtime_basis"`       // basis of VTimeMs, e.g. "virtual:case-clock/ms"
	Convertible bool        `json:"convertible"`       // false => Raw stays in place with a diagnostic
	Diag   string          `json:"diag,omitempty"`
}

// Packet is one captured MQTT packet. Raw is authoritative; decoded fields are
// a derived view and never replace the bytes.
type Packet struct {
	ID         string            `json:"id"`
	Seq        int               `json:"seq"`
	Raw        []byte            `json:"raw_hex"`
	Dir        string            `json:"dir"`
	Type       string            `json:"type"`
	DUP        bool              `json:"dup"`
	RETAIN     bool             `json:"retain"`
	QoS        int               `json:"qos"`
	PacketID   int               `json:"packet_id"`
	Topic      string            `json:"topic,omitempty"`
	TopicAlias int               `json:"topic_alias,omitempty"`
	Payload    []byte            `json:"payload_hex,omitempty"`
	Props      map[string]any    `json:"props,omitempty"`
	// AliasUnresolved marks a PUBLISH whose topic alias cannot be mapped in
	// the connection in which it appears.
	AliasUnresolved bool     `json:"alias_unresolved,omitempty"`
	Diag            []string `json:"diag,omitempty"`
	Clock           Clock    `json:"clock"`
}

// SubState is one row of a broker subscription snapshot.
type SubState struct {
	Filter string `json:"filter"`
	QoS    int    `json:"qos"`
	SubID  int    `json:"sub_id,omitempty"`
}

// Inflight is a QoS handshakes row in a broker session snapshot.
type Inflight struct {
	Kind     string `json:"kind"` // publish | pubrel
	PacketID int    `json:"packet_id"`
	Stage    string `json:"stage"`
	Topic    string `json:"topic,omitempty"`
}

// QueuedMsg is a queued (offline) message row in a broker session snapshot.
type QueuedMsg struct {
	PacketID         int    `json:"packet_id"`
	QoS              int    `json:"qos"`
	Topic            string `json:"topic"`
	Payload          []byte `json:"payload_hex,omitempty"`
	RetainedDelivery bool   `json:"retained_delivery,omitempty"`
}

// Snapshot is one broker/client session snapshot taken at a virtual instant.
// Structured fields are a view; the raw JSON map is preserved.
type Snapshot struct {
	ID              string            `json:"id"`
	Seq             int               `json:"seq"`
	ClientID        string            `json:"client_id"`
	SessionPresent  *bool             `json:"session_present"` // nil = not observed (ambiguity kept)
	Subscriptions   []SubState        `json:"subscriptions,omitempty"`
	Inflight        []Inflight        `json:"inflight,omitempty"`
	Queued          []QueuedMsg       `json:"queued,omitempty"`
	KeepAliveSec    int               `json:"keepalive_sec,omitempty"`
	Raw             map[string]any    `json:"raw"`
	Clock           Clock             `json:"clock"`
	Diag            []string          `json:"diag,omitempty"`
}

// Params are the rule parameters of a derivation. A parameter revision is a
// first-class event; derived nodes carry the params id they were computed
// under.
type Params struct {
	ID           string         `json:"id"`
	Label        string         `json:"label"`
	ClockBasis   string         `json:"clock_basis"` // authoritative clock coordinate basis
	// BoundaryRule decides expiry exactly at the deadline:
	// "present_is_expired" means t == deadline => session gone (MQTT uses a
	// closed session-expiry interval on the broker side).
	BoundaryRule string         `json:"boundary_rule"`
	Values       map[string]any `json:"values,omitempty"`
}

// Ref is a stable reference from a derived value to its source material.
type Ref struct {
	Kind string `json:"kind"` // packet|snapshot|param|node|event|version
	ID   string `json:"id"`
}

// Diag attaches an unconvertible/ambiguous value to the node it belongs to;
// such values are never dropped to make a picture look clean.
type Diag struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	At      string `json:"at,omitempty"`
}

// Node status after an incremental recompute.
const (
	StatusReused     = "reused"
	StatusRecomputed = "recomputed"
	StatusAdded      = "added"
	StatusRemoved    = "removed"
)

// Node is one unit of derived state with a stable identity. Every visible
// value is addressed as "<nodeID>#<field path>" in the review UI.
type Node struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	VersionID string         `json:"version_id"`
	GenID     string         `json:"gen_id,omitempty"`
	Label     string         `json:"label"`
	Payload   map[string]any `json:"payload"`
	Evidence  []Ref          `json:"evidence"`
	Diags     []Diag         `json:"diags,omitempty"`
	DependsOn []Ref          `json:"depends_on"`
	BasisHash string         `json:"basis_hash"`
	Status    string         `json:"status"`
	Reason    string         `json:"reason,omitempty"`
}

// Machine-readable principle tags. Every adjudication that depends on one of
// the core semantics records its tag.
const (
	PrinciplePacketIDScope       = "packetid.scoped_by_generation"
	PrincipleQoS2IdemStage       = "qos2.duplicate_idempotent_preserve_stage"
	PrincipleExpiryVirtualTime   = "expiry.virtual_time_boundary"
	PrincipleRetainedSeparate    = "retained.separate_from_session"
	PrincipleAliasPerConnection  = "alias.scoped_per_connection"
	PrincipleAllCandidates       = "ambiguity.all_legal_candidates_retained"
	PrincipleUnconvertibleKept   = "value.unconvertible_kept_in_place"
)

// Event kinds.
const (
	EvImport        = "import"
	EvDerive        = "derive"
	EvReplay        = "replay"
	EvVerdict       = "verdict"
	EvDecision      = "decision"     // human accept/reject/adjust
	EvBranchSelect  = "branch_select"
	EvParamRevision = "param_revision"
)

// Event is an immutable, machine-readable fact in the archive.
type Event struct {
	ID         string         `json:"id"`
	Seq        int            `json:"seq"`
	Kind       string         `json:"kind"`
	VersionID  string         `json:"version_id"`
	Principle  string         `json:"principle,omitempty"`
	Summary    string         `json:"summary"`
	Details    map[string]any `json:"details,omitempty"`
	Evidence   []Ref          `json:"evidence,omitempty"`
	WallTime   string         `json:"wall_time"`
	VTimeMs    int64          `json:"vtime_ms"`
}

// Version is one complete derivation. Only a fully committed version can
// become the current pointer of its branch.
type Version struct {
	ID         string   `json:"id"`
	Branch     string   `json:"branch"`
	ParentID   string   `json:"parent_id,omitempty"`
	BundleID   string   `json:"bundle_id"`
	ParamsID   string   `json:"params_id"`
	RuleSet    string   `json:"rule_set"` // correct | naive
	Label      string   `json:"label"`
	NodeIDs    []string `json:"node_ids"`
	EventIDs   []string `json:"event_ids"`
	Complete   bool     `json:"complete"`
	WallTime   string   `json:"wall_time"`
}

// Bundle is an immutable set of original capture material.
type Bundle struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Origin      string     `json:"origin"`
	BaseBundleID string    `json:"base_bundle_id,omitempty"`
	ChangeNote  string     `json:"change_note,omitempty"`
	Packets     []Packet   `json:"packets"`
	Snapshots   []Snapshot `json:"snapshots,omitempty"`
}

// Result is the full output of a derivation.
type Result struct {
	Nodes  []Node
	Events []Event // VersionID/Seq filled when materialized
}
