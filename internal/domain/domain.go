// Package domain defines the core facts and derived objects of an MQTT
// session-forensics reconstruction.
//
// Two layers are kept strictly apart:
//
//   - the source layer (facts): original packet bytes, direction, packet id,
//     DUP/RETAIN flags, clean start / session expiry, topic aliases and the
//     clock are preserved in their original representation;
//   - the derived layer: normalized values used by the QoS / session rules.
//
// A value that cannot be normalized stays in place (Raw) with a diagnostic;
// it is never dropped for the sake of producing a clean picture.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Direction of a frame on the wire.
type Direction string

const (
	// C2B is client -> broker. B2C is broker -> client.
	C2B Direction = "c2b"
	B2C Direction = "b2c"
)

func (d Direction) Valid() bool { return d == C2B || d == B2C }

// Clock preserves the original textual clock and, when convertible, a
// normalized nanosecond value on a declared coordinate basis.
type Clock struct {
	// Raw is the original representation exactly as found in the source.
	Raw string `json:"raw"`
	// Basis declares the coordinate system, e.g.
	// "virtual:unix-ns" (scenario virtual time, unix nanoseconds) or
	// "wall:rfc3339" (host wall clock).
	Basis string `json:"basis"`
	// Unit is the unit of Nanos ("ns"); empty when not normalized.
	Unit string `json:"unit,omitempty"`
	// Nanos is the normalized value; nil when not convertible.
	Nanos *int64 `json:"nanos,omitempty"`
	// Diagnostic explains why the value could not be normalized.
	Diagnostic string `json:"diagnostic,omitempty"`
}

// VirtualBasis marks scenario virtual time (session-expiry boundaries are
// always decided on virtual time, never on the host clock).
const VirtualBasis = "virtual:unix-ns"

// ParseClock keeps raw verbatim and normalizes when possible.
func ParseClock(raw, basis string) Clock {
	c := Clock{Raw: raw, Basis: basis}
	ns, err := decodeNanos(raw)
	if err != nil {
		c.Diagnostic = "clock not normalized: " + err.Error()
		return c
	}
	c.Nanos = &ns
	c.Unit = "ns"
	return c
}

func decodeNanos(raw string) (int64, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, fmt.Errorf("empty clock")
	}
	// fractional epoch seconds, e.g. 1700000000.125
	if strings.ContainsAny(s, ".") {
		f, err := strconv.ParseFloat(s, 64)
		if err == nil {
			return int64(f * 1e9), nil
		}
	}
	// pure integer: nanoseconds under the virtual basis, seconds otherwise.
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	return 0, fmt.Errorf("unrecognized clock representation %q", raw)
}

// PacketFact is an immutable source fact: one captured MQTT frame.
type PacketFact struct {
	ID          string    `json:"id"`
	CaptureID   string    `json:"capture_id"`
	Seq         int       `json:"seq"`
	ClientID    string    `json:"client_id"`
	Direction   Direction `json:"direction"`
	Bytes       HexBytes  `json:"bytes"`
	Clock       Clock     `json:"clock"`
	SourceLabel string    `json:"source_label"`
}

// StablePacketID is content-derived so it survives export/import.
func StablePacketID(p PacketFact) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%s|%s|%x|%s|%s",
		p.CaptureID, p.Seq, p.ClientID, p.Direction, []byte(p.Bytes),
		p.Clock.Raw, p.SourceLabel)
	return "p-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// SnapshotFact is a broker-side session snapshot preserved in its original
// JSON representation.
type SnapshotFact struct {
	ID          string          `json:"id"`
	CaptureID   string          `json:"capture_id"`
	ClientID    string          `json:"client_id"`
	Clock       Clock           `json:"clock"`
	SourceLabel string          `json:"source_label"`
	Raw         json.RawMessage `json:"raw"`
}

func StableSnapshotID(s SnapshotFact) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s", s.CaptureID, s.ClientID, s.Clock.Raw, s.SourceLabel, string(s.Raw))
	return "s-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// HexBytes is a byte slice that always round-trips as lowercase hex, keeping
// the original packet bytes visible rather than base64-obscured.
type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%x", []byte(h)))
}

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = b
	return nil
}

// Issue severity levels.
type Severity string

const (
	SevInfo    Severity = "info"
	SevWarning Severity = "warning"
	SevError   Severity = "error"
)

// Issue is a machine-readable diagnostic attached to a derived node.
type Issue struct {
	Code     string         `json:"code"`
	Severity Severity       `json:"severity"`
	Message  string         `json:"message"`
	Subject  string         `json:"subject,omitempty"`
	Detail   map[string]any `json:"detail,omitempty"`
}

// Candidate is one of several legal interpretations that cannot be unified
// from the available evidence. The engine never collapses ambiguity silently.
type Candidate struct {
	ID       string          `json:"id"`
	Label    string          `json:"label"`
	Basis    string          `json:"basis"`
	Value    json.RawMessage `json:"value"`
	Chosen   bool            `json:"chosen"`
	Rejected bool            `json:"rejected"`
}
