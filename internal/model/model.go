// Package model defines the forensic domain types: imported source artifacts
// (raw packet bytes, broker session snapshots) and the machine-readable events
// that record how a derived verdict was reached.
//
// Every domain quantity carries its unit or coordinate basis. Import preserves
// the original representation; normalisation happens only in the derivation
// layer, and values that cannot be converted stay in place with a diagnostic.
package model

import "encoding/json"

// Direction is the wire direction, recorded at capture time.
type Direction string

const (
	C2B Direction = "C2B" // client -> broker
	B2C Direction = "B2C" // broker -> client
)

// SourceKind distinguishes the two direct-source families.
type SourceKind string

const (
	KindPacket   SourceKind = "packet"
	KindSnapshot SourceKind = "broker_snapshot"
	KindParam    SourceKind = "rule_parameter"
)

// Clock is the coordinate basis for every timestamp.
type Clock string

const (
	ClockVirtual   Clock = "virtual"   // the replay clock, unit "ns" since epoch 0
	ClockCaptureMs Clock = "capture_ms"
	ClockUTC       Clock = "wall_utc_ns"
)

// Timestamp preserves the original representation and its coordinate basis.
type Timestamp struct {
	Value int64  `json:"value"`
	Unit  string `json:"unit"` // "ns", "ms", "s"
	Clock Clock  `json:"clock"`
	// Original is the unmodified imported token (e.g. "1700000000123").
	Original string `json:"original,omitempty"`
}

// Source is a single direct-source record. Stable identity comes from the
// imported ID (id namespace), so export/delete/re-import preserves identity.
type Source struct {
	ID        string          `json:"id"`
	TraceID   string          `json:"traceId"`
	Revision  int             `json:"revision"` // increments on direct-source edit
	Supersedes string         `json:"supersedes,omitempty"`
	Kind      SourceKind      `json:"kind"`
	Direction Direction       `json:"direction,omitempty"`
	Order     int             `json:"order"`
	Time      Timestamp       `json:"time"`
	// Payload is kind-specific JSON (SourcePacket / Snapshot / Parameter).
	Payload   json.RawMessage `json:"payload"`
	// Origin keeps the original textual/hex representation on import.
	Origin    string          `json:"origin,omitempty"`
	// Diagnostics holds unconvertible values that were left in place.
	Diagnostics []Diagnostic  `json:"diagnostics,omitempty"`
}

// Diagnostic mirrors mqtt.Diagnostic but kept at model layer to avoid cycles.
type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Offset  int    `json:"offset,omitempty"`
	Path    string `json:"path,omitempty"`
}

// SourcePacket is the payload of a packet source. It mirrors the preserved
// field list demanded by the domain: original bytes, direction, packet id,
// DUP/retain flags, clean start/session expiry, topic alias and the clock.
type SourcePacket struct {
	Hex       string   `json:"hex"`
	ByteCount int      `json:"byteCount"`
	ProtocolLevel byte  `json:"protocolLevel"`
	Type      string   `json:"type"`
	Flags     byte     `json:"flags"`
	DUP       bool     `json:"dup"`
	QoS       byte     `json:"qos"`
	Retain    bool     `json:"retain"`
	PacketID  uint16   `json:"packetId,omitempty"`
	Topic     string   `json:"topic,omitempty"`
	TopicAlias uint16  `json:"topicAlias,omitempty"`
	TopicAliasMax uint16 `json:"topicAliasMaximum,omitempty"`
	ClientID  string   `json:"clientId,omitempty"`
	CleanStart bool    `json:"cleanStart,omitempty"`
	CleanSession311 bool `json:"cleanSession311,omitempty"`
	SessionExpirySeconds uint32 `json:"sessionExpirySeconds,omitempty"`
	KeepAliveSeconds uint16 `json:"keepAliveSeconds,omitempty"`
	WillTopic string   `json:"willTopic,omitempty"`
	Filters   []string `json:"filters,omitempty"`
	Reason    byte     `json:"reason,omitempty"`
	PayloadASCII string `json:"payloadAscii,omitempty"`
}

// Snapshot is a broker session snapshot taken at a virtual time.
type Snapshot struct {
	ClientID         string         `json:"clientId"`
	SessionGeneration int           `json:"sessionGeneration,omitempty"`
	Connected        bool           `json:"connected"`
	// PendingOutbound lists QoS1/2 flows the broker still owes the client.
	PendingOutbound  []PendingFlow  `json:"pendingOutbound,omitempty"`
	// PendingInbound lists flows awaiting completion from the client.
	PendingInbound   []PendingFlow  `json:"pendingInbound,omitempty"`
	Subscriptions    []SnapSub      `json:"subscriptions,omitempty"`
	RetainedTopics   []string       `json:"retainedTopics,omitempty"`
	// SessionExpiresAt is on the virtual clock; nil means session does not expire.
	SessionExpiresAt *Timestamp     `json:"sessionExpiresAt,omitempty"`
}

// PendingFlow describes an in-flight QoS flow seen in the broker snapshot.
type PendingFlow struct {
	Key      string `json:"key"` // "gen/direction/packetId"
	PacketID uint16 `json:"packetId"`
	QoS      byte   `json:"qos"`
	Stage    string `json:"stage"`
	Topic    string `json:"topic,omitempty"`
}

// SnapSub is a subscription row in a broker snapshot.
type SnapSub struct {
	Filter string `json:"filter"`
	QoS    byte   `json:"qos"`
}

// Parameter is a revision-controlled rule parameter (the "parameter revision").
type Parameter struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
	Unit  string          `json:"unit,omitempty"`
}

// VerdictKind enumerates machine-readable event types.
type VerdictKind string

const (
	VGenerationStart VerdictKind = "session_generation_start"
	VGenerationResume VerdictKind = "session_generation_resumed"
	VTransportOpen   VerdictKind = "transport_opened"
	VTransportClose  VerdictKind = "transport_closed"
	VQoSStage        VerdictKind = "qos_stage_transition"
	VQoSDuplicate    VerdictKind = "qos_duplicate_packet"
	VQoSStuck        VerdictKind = "qos_flow_interrupted"
	VPacketIDReuse   VerdictKind = "packet_id_reuse"
	VGenKeyRejected  VerdictKind = "cross_generation_key_rejected"
	VDecision        VerdictKind = "hand_decision"
	VExpiryBoundary  VerdictKind = "session_expiry_boundary"
	VExpiryExpired   VerdictKind = "session_expired"
	VRetainedSet     VerdictKind = "retained_set"
	VRetainedDeleted VerdictKind = "retained_deleted"
	VRetainedDelivered VerdictKind = "retained_delivered"
	VSubChange       VerdictKind = "subscription_change"
	VAliasMapping    VerdictKind = "topic_alias_mapping"
	VAliasReset      VerdictKind = "topic_alias_reset"
	VUnconvertible   VerdictKind = "unconvertible_value"
	VAmbiguity       VerdictKind = "ambiguity_candidates"
)

// Verdict is a machine-readable evidence event. IDs are stable and every value
// carries its own stable identity so UI rows can be addressed deterministically.
type Verdict struct {
	ID       string          `json:"id"`
	NodeID   string          `json:"nodeId"`
	Kind     VerdictKind     `json:"kind"`
	Time     Timestamp       `json:"time"`
	Severity string          `json:"severity"` // info | warn | anomaly
	Summary  string          `json:"summary"`
	Detail   json.RawMessage `json:"detail,omitempty"`
	// Evidence lists source IDs (direct) and node IDs (derived) supporting this.
	Evidence []EvidenceRef   `json:"evidence,omitempty"`
	// Candidates holds all legal readings when the answer is not unique.
	Candidates []Candidate    `json:"candidates,omitempty"`
}

// EvidenceRef is one link in a provenance chain.
type EvidenceRef struct {
	Kind string `json:"kind"` // "source" | "node" | "verdict"
	ID   string `json:"id"`
	Role string `json:"role,omitempty"`
}

// Candidate is one legal interpretation that was not collapsed away.
type Candidate struct {
	ID        string          `json:"id"`
	Label     string          `json:"label"`
	Chosen    bool            `json:"chosen"`
	Reason    string          `json:"reason,omitempty"`
	Detail    json.RawMessage `json:"detail,omitempty"`
}
