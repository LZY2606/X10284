// Package model defines the domain types for the MQTT session-imprint
// replay system: raw packet traces, session generations, QoS handshake
// state machines, subscriptions, retained state and judgment events.
package model

// Direction of a packet on the wire. All clocks are virtual milliseconds
// (coordinate basis: monotonic virtual clock of the trace, unit = ms).
type Direction string

const (
	C2B Direction = "C2B" // client to broker
	B2C Direction = "B2C" // broker to client
	NA  Direction = "NA"  // trace annotation (e.g. LINKDOWN), not a packet
)

// Packet is one imported trace record. The original bytes (RawHex),
// direction, packet id, DUP/retain flags, clean-start/session-expiry,
// topic alias and clock are all preserved exactly as imported. Decoded
// fields are a derived view; if decoding fails DecodeErr is set and the
// raw value stays in place (never dropped for the sake of rendering).
type Packet struct {
	ID      string    `json:"id"` // stable identity, e.g. "p01"
	Seq     int       `json:"seq"`
	ClockMs int64     `json:"clock_ms"` // virtual time, unit: ms
	Dir     Direction `json:"dir"`
	RawHex  string    `json:"raw_hex"` // original bytes, preserved

	Type          string   `json:"type"` // CONNECT, PUBLISH, ... LINKDOWN (annotation)
	DUP           bool     `json:"dup"`
	QoS           int      `json:"qos"`
	Retain        bool     `json:"retain"`
	PacketID      *uint16  `json:"packet_id,omitempty"`
	CleanStart    *bool    `json:"clean_start,omitempty"`
	SessionExpS   *uint32  `json:"session_expiry_s,omitempty"` // unit: seconds
	ClientID      string   `json:"client_id,omitempty"`
	SessionPresent *bool   `json:"session_present,omitempty"`
	Topic         string   `json:"topic,omitempty"`
	TopicAlias    *uint16  `json:"topic_alias,omitempty"`
	PayloadHex    string   `json:"payload_hex,omitempty"`
	SubTopics     []string `json:"sub_topics,omitempty"`
	ReasonCode    *byte    `json:"reason_code,omitempty"`
	DecodeErr     string   `json:"decode_err,omitempty"` // diagnostic; raw kept
}

// Generation is a session-state epoch for one client id. A new generation
// starts when session state is discarded (clean start, expiry, broker
// reset). Reconnects within a live session are new connections inside the
// same generation. Packet ids are only interpreted inside one generation.
type Generation struct {
	ID           string `json:"id"` // "gen-1"
	Index        int    `json:"index"`
	ClientID     string `json:"client_id"`
	StartClockMs int64  `json:"start_clock_ms"`
	EndClockMs   int64  `json:"end_clock_ms"`
	SessionExpS  uint32 `json:"session_expiry_s"`
	Cause        string `json:"cause"` // initial | clean-start | expired | broker-reset
	Connections  int    `json:"connections"`
	Src          []string `json:"src"` // packet ids this derivation depends on
}

// Exchange is one QoS 1/2 handshake state machine, keyed by
// (generation, initiator direction, packet id). Duplicate deliveries are
// idempotent: they never create a second message and never drop a
// handshake phase.
type Exchange struct {
	ID        string   `json:"id"` // "exch-g1-p7-q2"
	GenID     string   `json:"gen_id"`
	PacketID  uint16   `json:"packet_id"`
	QoS       int      `json:"qos"`
	Initiator Direction `json:"initiator"`
	Topic     string   `json:"topic"`
	State     string   `json:"state"` // AWAIT_PUBACK | AWAIT_PUBREC | AWAIT_PUBCOMP | COMPLETE | SUSPENDED
	Phases    []Phase  `json:"phases"` // full handshake phase history, preserved
	MessageID string   `json:"message_id"`
	Src       []string `json:"src"`
}

// Phase is one step of a QoS handshake.
type Phase struct {
	Name    string `json:"name"` // PUBLISH, PUBACK, PUBREC, PUBREL, PUBCOMP
	Packet  string `json:"packet"` // packet id (stable identity)
	ClockMs int64  `json:"clock_ms"`
	DUP     bool   `json:"dup"`
}

// DupLink records the correspondence between a retransmission (DUP=1)
// and its original exchange.
type DupLink struct {
	ID         string   `json:"id"`
	ExchangeID string   `json:"exchange_id"`
	DupPacket  string   `json:"dup_packet"`
	Kind       string   `json:"kind"`   // publish-dup | pubrel-dup
	Effect     string   `json:"effect"` // idempotent-no-new-message | handshake-phase-preserved
	Stale      bool     `json:"stale"`  // outside dup window (param)
	Src        []string `json:"src"`
}

// SubChange is one subscription-state transition.
type SubChange struct {
	ID      string   `json:"id"`
	GenID   string   `json:"gen_id"`
	Topic   string   `json:"topic"`
	Op      string   `json:"op"` // add | remove | reset
	ClockMs int64    `json:"clock_ms"`
	Src     []string `json:"src"`
}

// RetainedMsg is the retained store, kept strictly separate from
// session (queued/in-flight) messages.
type RetainedMsg struct {
	ID         string   `json:"id"` // "ret-<topic>"
	Topic      string   `json:"topic"`
	Present    bool     `json:"present"`
	PayloadHex string   `json:"payload_hex,omitempty"`
	SetBy      string   `json:"set_by,omitempty"`
	DeletedBy  string   `json:"deleted_by,omitempty"`
	ClockMs    int64    `json:"clock_ms"`
	Src        []string `json:"src"`
}

// ExpiryDecision records a session-expiry boundary judgment made on the
// virtual clock. When the gap lands exactly on the boundary the outcome
// is undecidable and all legal candidates are kept.
type ExpiryDecision struct {
	ID         string   `json:"id"` // "exp-<connect-pkt>"
	AtGenID    string   `json:"at_gen_id"`
	GapMs      int64    `json:"gap_ms"`    // virtual ms since previous session end
	ExpiryMs   int64    `json:"expiry_ms"` // negotiated expiry, unit: ms (from seconds)
	Outcome    string   `json:"outcome"`   // expired | alive | undecided
	Candidates []string `json:"candidates,omitempty"`
	Rule       string   `json:"rule"` // "session-expiry-virtual-time"
	Src        []string `json:"src"`
}

// Diagnostic marks a value that could not be converted/decoded. The
// original representation stays in place; the diagnostic travels with it.
type Diagnostic struct {
	ID      string `json:"id"` // "diag-<pkt>"
	Packet  string `json:"packet"`
	Kind    string `json:"kind"` // decode | unknown-topic-alias | protocol-anomaly
	Detail  string `json:"detail"`
}

// Event is a machine-readable judgment record. Every accept, reject or
// parameter adjustment produces one. Events carry the rule citation and
// both the adopted and the non-adopted results.
type Event struct {
	ID        string   `json:"id"` // "ev-<n>"
	VersionID string   `json:"version_id"`
	Seq       int      `json:"seq"`
	Kind      string   `json:"kind"` // import | param-revision | source-edit | decision | restore | archive
	Rule      string   `json:"rule"` // e.g. "packet-id-scope:generation"
	Subject   string   `json:"subject"`
	Summary   string   `json:"summary"`
	Accepted  []string `json:"accepted,omitempty"`
	Rejected  []string `json:"rejected,omitempty"`
}
