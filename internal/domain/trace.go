package domain

import "mqttsession/internal/mqttwire"

// RecordKind distinguishes wire packets from synthetic evidence such as
// observed transport gaps and broker snapshot rows.
type RecordKind string

const (
	KindPacket  RecordKind = "packet"
	KindGap     RecordKind = "gap"
	KindSnapshot RecordKind = "snapshot"
)

// Direction mirrors mqttwire.Direction but keeps domain decoupled.
type Direction string

const (
	C2S Direction = "c2s"
	S2C Direction = "s2c"
)

// Quantity preserves the original textual representation plus unit/coordinate
// basis. Normalization happens only in the derivation layer; a value that
// cannot be converted stays in Raw with a diagnostic instead of being dropped.
type Quantity struct {
	Raw      string `json:"raw"`
	Unit     string `json:"unit"`
	Basis    string `json:"basis,omitempty"`
	NormalNs *int64 `json:"normal_ns,omitempty"`
	Diag     string `json:"diag,omitempty"`
}

// Record is one immutable input evidence row.
type Record struct {
	ID        string             `json:"id"`
	ClientID  string             `json:"client_id"`
	Conn      int                `json:"conn"`
	Kind      RecordKind         `json:"kind"`
	Direction Direction          `json:"direction"`
	Clock     Quantity           `json:"clock"`
	RawHex    string             `json:"raw_hex,omitempty"`
	Packet    *mqttwire.Packet   `json:"packet,omitempty"`
	Note      string             `json:"note,omitempty"`
	// Snapshot payload (JSON-encoded broker view), kept verbatim.
	Snapshot map[string]any `json:"snapshot,omitempty"`
}
