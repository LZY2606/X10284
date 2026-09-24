// Package mqtt implements the domain rules for reconstructing MQTT QoS 1/2
// handshakes, persistent-session generations, subscriptions and retained
// state from captured packet traces.
//
// Core semantics enforced here:
//   - R1: a packet id is only interpreted inside the same session generation.
//   - R2: QoS 2 duplicate packets are idempotent but never drop the
//     handshake stage already reached.
//   - R3: session-expiry boundaries are evaluated on the virtual clock.
//   - R4: retained messages are kept apart from session (in-flight) state.
package mqtt

import "fmt"

// Direction of a captured packet.
type Direction string

const (
	C2B Direction = "c2b" // client -> broker
	B2C Direction = "b2c" // broker -> client
)

// Packet is one captured MQTT packet. The raw bytes, direction, packet id,
// DUP/retain flags, clean-start/session-expiry fields, topic alias and the
// original clock representation are all preserved; Vtick is the derived
// normalized virtual-time coordinate (basis: virtual milliseconds).
type Packet struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	Direction Direction `json:"direction"`
	Seq       int       `json:"seq"` // arrival order, independent of clock convertibility
	RawHex    string    `json:"raw_hex"`
	RawClock  string    `json:"raw_clock"`   // original representation, never rewritten
	ClockBasis string   `json:"clock_basis"` // e.g. "iso8601", "vtick-ms"
	Vtick     int64     `json:"vtick"`       // normalized virtual ms; valid only if VtickOK
	VtickOK   bool      `json:"vtick_ok"`
	Diag      string    `json:"diag,omitempty"` // diagnostic when a value cannot be converted
	SupersededBy string `json:"superseded_by,omitempty"`

	// Fields decoded from RawHex by the parser (derived layer).
	Type          string `json:"ptype"`
	PacketID      int    `json:"packet_id"`
	DUP           bool   `json:"dup"`
	Retain        bool   `json:"retain"`
	QoS           int    `json:"qos"`
	Topic         string `json:"topic"`
	TopicAlias    int    `json:"topic_alias"` // 0 = absent
	CleanStart    bool   `json:"clean_start"`
	SessionExpRaw string `json:"session_expiry_raw"` // original representation e.g. "30s"
	SessionExpS   int64  `json:"session_expiry_s"`   // normalized seconds, -1 = absent
	PayloadHex    string `json:"payload_hex"`
}

// Params are rule parameters. A parameter revision creates a new derivation
// version; only dependent derived nodes are recomputed.
type Params struct {
	// ExpiryBoundary: "exclusive" => a reconnect exactly at the expiry
	// endpoint counts as expired; "inclusive" => it still resumes.
	ExpiryBoundary string `json:"expiry.boundary"`
	RuleVersion    string `json:"rule.version"`
}

func DefaultParams() Params {
	return Params{ExpiryBoundary: "exclusive", RuleVersion: "mqtt-gsb/1"}
}

// Node is a derived artifact with a stable identity (Key), the inputs it was
// derived from (Deps) and a human/machine readable validity Reason.
type Node struct {
	Key     string         `json:"key"`
	Kind    string         `json:"kind"`
	Payload map[string]any `json:"payload"`
	Deps    []string       `json:"deps"`
	Reason  string         `json:"reason"`
}

func (n Node) String() string { return fmt.Sprintf("%s(%s)", n.Kind, n.Key) }

// Judgment is a machine-readable record of a rule application.
type Judgment struct {
	Rule   string `json:"rule"` // R1..R4
	Note   string `json:"note"`
	Packet string `json:"packet,omitempty"`
	Node   string `json:"node,omitempty"`
}
