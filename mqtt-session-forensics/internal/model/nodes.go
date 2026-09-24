package model

// Node kinds emitted by the reconstruction engine.
const (
	NodeGeneration   = "session_generation"
	NodeFlow         = "qos_flow"
	NodeCorrespond   = "duplicate_correspondence"
	NodeSubscription = "subscription"
	NodeRetained     = "retained_slot"
	NodeAlias        = "alias_map"
	NodeExpiry       = "expiry_decision"
	NodeConfusion    = "cross_generation_confusion"
)

// GenState for a session generation.
type GenState string

const (
	GenOpened      GenState = "opened"       // CONNECT seen
	GenResumed     GenState = "resumed"      // CONNACK session present
	GenFresh       GenState = "fresh"        // CONNACK no session
	GenDisconnected GenState = "disconnected"
	GenExpired     GenState = "expired"
)

// GenerationNode groups all packets sharing one client-id + connect epoch.
type GenerationNode struct {
	UID            string          `json:"uid"`
	Kind           string          `json:"kind"`
	ClientID       string          `json:"client_id"`
	GenSerial      int             `json:"gen_serial"`     // per client, 1-based
	ConnectionID   string          `json:"connection_id"`
	Connections    []string        `json:"connections,omitempty"` // transport connections bound to this generation
	Reconnected    bool            `json:"reconnected,omitempty"`
	ProtoLevel     byte            `json:"proto_level"`
	CleanStart     bool            `json:"clean_start"`
	SessionExpiryS uint32          `json:"session_expiry_seconds"`
	State          GenState        `json:"state"`
	OpenAtNS       int64           `json:"open_at_ns"`
	CloseAtNS      int64           `json:"close_at_ns,omitempty"`
	Sources        []SourceRef     `json:"sources"`
	Diagnostics    []Diagnostic    `json:"diagnostics,omitempty"`
}

// FlowPhase models QoS 1/2 handshake progress.
type FlowPhase string

const (
	PhasePub      FlowPhase = "PUBLISH"
	PhaseQ1Done   FlowPhase = "PUBACK_DONE"
	PhaseRecd     FlowPhase = "PUBREC_RCVD"
	PhaseRelSent  FlowPhase = "PUBREL_SENT"
	PhaseQ2Done   FlowPhase = "PUBCOMP_DONE"
	PhaseStuck    FlowPhase = "STUCK_INTERRUPTED" // QoS 2 disconnect mid-handshake
)

// FlowDirection: publish originated by client (OUT from client) or broker (IN).
type FlowNode struct {
	UID          string       `json:"uid"`
	Kind         string       `json:"kind"`
	GenUID       string       `json:"gen_uid"`     // packet id interpreted within this generation only
	ClientID     string       `json:"client_id"`
	PacketID     uint16       `json:"packet_id"`
	Direction    Direction    `json:"direction"`
	QoS          uint8        `json:"qos"`
	Topic        string       `json:"topic"`
	Retain       bool         `json:"retain"`
	Phase        FlowPhase    `json:"phase"`
	Observations []FlowObs    `json:"observations"`
	Interrupted  bool         `json:"interrupted,omitempty"`
	Resumed      bool         `json:"resumed,omitempty"`
	IdempotentDup bool        `json:"idempotent_dup,omitempty"` // repeated PUBLISH absorbed, handshake kept
	Sources      []SourceRef  `json:"sources"`
	Diagnostics  []Diagnostic `json:"diagnostics,omitempty"`
}

// FlowObs is one wire observation attached to a flow, ordered by virtual time.
type FlowObs struct {
	PacketVersionID string    `json:"packet_version_id"` // e.g. pkt-0004@v2
	PacketID        string    `json:"packet_id"`
	Type            string    `json:"type"`
	DUP             bool      `json:"dup"`
	AtNS            int64     `json:"at_ns"`
	TimeOriginal    string    `json:"time_original"`
	TimeUnit        string    `json:"time_unit"`
	Note            string    `json:"note,omitempty"`
}

// CorrespondenceNode groups identical (gen, packet-id) DUP retransmissions.
type CorrespondenceNode struct {
	UID       string      `json:"uid"`
	Kind      string      `json:"kind"`
	GenUID    string      `json:"gen_uid"`
	PacketID  uint16      `json:"packet_id"`
	Members   []SourceRef `json:"members"`
	Count     int         `json:"count"`
	Outcome   string      `json:"outcome"` // idempotent|new_handshake|ambiguous
	Sources   []SourceRef `json:"sources"`
}

// SubscriptionNode is one client/filter subscription with change history.
type SubscriptionNode struct {
	UID       string            `json:"uid"`
	Kind      string            `json:"kind"`
	GenUID    string            `json:"gen_uid"`
	ClientID  string            `json:"client_id"`
	Filter    string            `json:"filter"`
	Active    bool              `json:"active"`
	MaxQoS    uint8             `json:"max_qos"`
	Changes   []SubChange       `json:"changes"`
	Sources   []SourceRef       `json:"sources"`
}

type SubChange struct {
	Action        string `json:"action"` // subscribe|unsubscribe|grant
	QoS           uint8  `json:"qos"`
	PacketVersion string `json:"packet_version"`
	AtNS          int64  `json:"at_ns"`
}

// RetainedNode tracks retained-store state per exact topic (independent of
// sessions). A zero-length payload with retain is a tombstone.
type RetainedNode struct {
	UID       string         `json:"uid"`
	Kind      string         `json:"kind"`
	Topic     string         `json:"topic"`
	Alive     bool           `json:"alive"`
	Payload   string         `json:"payload"`
	History   []RetainChange `json:"history"`
	Sources   []SourceRef    `json:"sources"`
}

type RetainChange struct {
	Action        string `json:"action"` // store|delete
	PacketVersion string `json:"packet_version"`
	AtNS          int64  `json:"at_ns"`
}

// AliasNode records a per-connection MQTT5 topic alias map lifecycle.
type AliasNode struct {
	UID          string             `json:"uid"`
	Kind         string             `json:"kind"`
	ConnectionID string             `json:"connection_id"`
	GenUID       string             `json:"gen_uid,omitempty"`
	Mappings     map[uint16]string  `json:"mappings"`
	Reset        bool               `json:"reset"`
	Events       []AliasEvent       `json:"events"`
	Sources      []SourceRef        `json:"sources"`
	Diagnostics  []Diagnostic       `json:"diagnostics,omitempty"`
}

type AliasEvent struct {
	Alias         uint16 `json:"alias"`
	Topic         string `json:"topic"`
	Action        string `json:"action"` // map|reset|use_unknown
	PacketVersion string `json:"packet_version"`
	AtNS          int64  `json:"at_ns"`
}

// ExpiryNode records the session expiry verdict at a virtual-time boundary.
type ExpiryNode struct {
	UID        string         `json:"uid"`
	Kind       string         `json:"kind"`
	ClientID   string         `json:"client_id"`
	GenUID     string         `json:"gen_uid"`
	CloseAtNS  int64          `json:"close_at_ns"`
	ExpiryAtNS int64          `json:"expiry_at_ns"`
	ReopenAtNS int64          `json:"reopen_at_ns"`
	WindowNS   int64          `json:"window_ns"`
	VerdictStr string         `json:"verdict"` // resumed|expired|boundary_ambiguous
	Candidates []string       `json:"candidates,omitempty"`
	Reason     string         `json:"reason"`
	Parameter  string         `json:"parameter,omitempty"`
	Sources    []SourceRef    `json:"sources"`
}

// ConfusionNode is emitted when a packet id could be misattributed across
// generations; it keeps both legal interpretations.
type ConfusionNode struct {
	UID         string      `json:"uid"`
	Kind        string      `json:"kind"`
	PacketID    uint16      `json:"packet_id"`
	PacketRef   SourceRef   `json:"packet_ref"`
	Candidates  []string    `json:"candidates"` // gen uids the id exists in
	Chosen      string      `json:"chosen"`
	Rule        string      `json:"rule"`
	Sources     []SourceRef `json:"sources"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// Graph is the complete derivation output for one version.
type Graph struct {
	Version        int                          `json:"version"`
	Generations    map[string]*GenerationNode   `json:"generations"`
	Flows          map[string]*FlowNode         `json:"flows"`
	Correspondence map[string]*CorrespondenceNode `json:"correspondence"`
	Subscriptions  map[string]*SubscriptionNode `json:"subscriptions"`
	Retained       map[string]*RetainedNode     `json:"retained"`
	Aliases        map[string]*AliasNode        `json:"aliases"`
	Expiries       map[string]*ExpiryNode       `json:"expiries"`
	Confusions     map[string]*ConfusionNode    `json:"confusions"`
	Order          []string                     `json:"order"` // stable node order
	Diagnostics    []Diagnostic                 `json:"diagnostics"`
}
