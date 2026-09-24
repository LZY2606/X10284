// Package model defines the stable domain vocabulary of the MQTT session
// forensics archive: raw observations, derived nodes, decisions and bundles.
package model

import "encoding/json"

// Direction is observed on the wire, relative to the broker.
type Direction string

const (
	DirC2B Direction = "C2B" // client -> broker
	DirB2C Direction = "B2C" // broker -> client
)

func (d Direction) Valid() bool { return d == DirC2B || d == DirB2C }

// TimeRef preserves the original timestamp representation. Normalisation to
// virtual nanoseconds happens only in the derivation layer.
type TimeRef struct {
	Original string `json:"original"`           // original textual representation
	Unit     string `json:"unit"`               // unit or coordinate basis, e.g. "ms","us","ns","s","virtual-ns","bad"
	EpochNS   int64  `json:"epoch_ns"`           // normalised virtual time, 0 when Unconvertible
	Unconvertible bool `json:"unconvertible,omitempty"`
	Diagnosis string `json:"diagnosis,omitempty"` // set when Unconvertible
}

// RawPacket is one observed wire frame. RawHex is authoritative original bytes.
type RawPacket struct {
	ID             string          `json:"id"`              // stable identity, e.g. pkt-0007
	RawHex         string          `json:"raw_hex"`         // original packet bytes
	Direction      Direction       `json:"direction"`
	ObservedAt     TimeRef         `json:"observed_at"`
	ConnectionID   string          `json:"connection_id"`   // TCP/transport connection coordinate
	ClientIDHint   string          `json:"client_id_hint,omitempty"`
	IngestOrder    int             `json:"ingest_order"`
	// CapsuleBytes preserves any outer capture framing that wrapped RawHex.
	CapsuleBytes   string          `json:"capsule_hex,omitempty"`
	View           *PacketView     `json:"view,omitempty"` // populated by derivation layer
}

// PacketView is the decoded view of a RawPacket. Decode failure never drops the
// raw bytes; Malformed carries the diagnosis.
type PacketView struct {
	Type        byte   `json:"type"`        // control packet type 1..14
	TypeName    string `json:"type_name"`
	Flags       byte   `json:"flags"`
	DUP         bool   `json:"dup"`
	QoS         uint8  `json:"qos"`
	Retain      bool   `json:"retain"`
	PacketID    uint16 `json:"packet_id"`
	HasPacketID bool   `json:"has_packet_id"`
	ProtoLevel  byte   `json:"proto_level"` // 4=MQTT3.1.1, 5=MQTT5.0
	CleanStart  bool   `json:"clean_start"`
	ClientID    string `json:"client_id"`
	SessionExpiry uint32 `json:"session_expiry"`
	HasSessionExpiry bool `json:"has_session_expiry"`
	SessionPresent bool `json:"session_present"`
	Topic       string `json:"topic"`
	Payload     string `json:"payload,omitempty"` // payload shown as string (fixtures are text)
	TopicAlias  uint16 `json:"topic_alias"`
	TopicAliasSet bool `json:"topic_alias_set"` // PUBLISH alias mapping defined
	ReasonCode  byte   `json:"reason_code,omitempty"`
	Filters     []SubFilter `json:"filters,omitempty"`
	Malformed   string `json:"malformed,omitempty"`
	Grants      []byte `json:"grants,omitempty"`
}

// SubFilter is one filter inside a SUBSCRIBE packet.
type SubFilter struct {
	Topic string `json:"topic"`
	QoS   uint8  `json:"qos"`
}

// SnapshotRecord is a broker-side session snapshot observation. JSON is kept
// verbatim so unconvertible fields stay in place with diagnostics.
type SnapshotRecord struct {
	ID           string          `json:"id"`
	ClientID     string          `json:"client_id"`
	ObservedAt   TimeRef         `json:"observed_at"`
	ConnectionID string          `json:"connection_id,omitempty"`
	JSON         json.RawMessage `json:"json"`
}

// ParamRecord is a named reconstruction parameter (rules version input).
type ParamRecord struct {
	Name      string `json:"name"`
	Value     string `json:"value"`             // original representation
	Unit      string `json:"unit,omitempty"`    // unit/coordinate basis
	ChangedBy string `json:"changed_by,omitempty"`
	ChangedAt int64  `json:"changed_at,omitempty"`
}

// Severity of a diagnostic.
type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
)

// Diagnostic keeps ambiguous/illegal situations visible instead of collapsing
// them into a single answer.
type Diagnostic struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	NodeID   string   `json:"node_id,omitempty"`
	PacketID string   `json:"packet_id,omitempty"`
}

// SourceRef points at the exact material that fed a derived value.
type SourceRef struct {
	Kind       string `json:"kind"` // packet|snapshot|param|decision|node
	ID         string `json:"id"`   // stable identity of the source
	Version    int    `json:"version,omitempty"`
	PacketObs  int    `json:"packet_obs,omitempty"` // ordinal within packet
	Field      string `json:"field,omitempty"`
}

// Bundle is the full input material of a branch at one point in time.
type Bundle struct {
	Packets     []RawPacket                 `json:"packets"`
	Snapshots   []SnapshotRecord            `json:"snapshots"`
	Params      map[string]ParamRecord      `json:"params"`
	CaseTitle   string                      `json:"case_title,omitempty"`
}

func (b *Bundle) Clone() *Bundle {
	c := &Bundle{CaseTitle: b.CaseTitle, Params: map[string]ParamRecord{}}
	c.Packets = append(c.Packets, b.Packets...)
	c.Snapshots = append(c.Snapshots, b.Snapshots...)
	for k, v := range b.Params {
		c.Params[k] = v
	}
	return c
}
