// Package mqtt models MQTT v5 packets captured in a bidirectional trace and
// reconstructs session generations, QoS 1/2 handshakes, subscriptions and
// retained state. Raw packet bytes are always preserved; parsing is a
// derived layer and malformed values stay raw with diagnostics.
package mqtt

import (
	"encoding/hex"
	"fmt"
	"strings"

	"mqttreplay/internal/units"
)

// Direction of a captured packet.
type Direction string

const (
	C2B Direction = "c2b" // client to broker
	B2C Direction = "b2c" // broker to client
)

// Type is the MQTT control packet type.
type Type string

const (
	CONNECT     Type = "CONNECT"
	CONNACK     Type = "CONNACK"
	PUBLISH     Type = "PUBLISH"
	PUBACK      Type = "PUBACK"
	PUBREC      Type = "PUBREC"
	PUBREL      Type = "PUBREL"
	PUBCOMP     Type = "PUBCOMP"
	SUBSCRIBE   Type = "SUBSCRIBE"
	SUBACK      Type = "SUBACK"
	UNSUBSCRIBE Type = "UNSUBSCRIBE"
	UNSUBACK    Type = "UNSUBACK"
	DISCONNECT  Type = "DISCONNECT"
	UNKNOWN     Type = "UNKNOWN"
)

// Packet is one captured MQTT packet. RawHex and every flag are preserved
// exactly as captured; parsed fields are derived and may carry diagnostics.
type Packet struct {
	ID        string         `json:"id"` // stable identity, e.g. P-0007
	Dir       Direction      `json:"dir"`
	RawHex    string         `json:"raw_hex"` // original bytes, hex encoded
	Tick      units.Quantity `json:"tick"`    // virtual replay clock, ms, basis virtual-tick
	Clock     string         `json:"clock"`   // captured wall clock string, preserved verbatim
	ClientID  string         `json:"client_id"`

	// derived fields (filled by Decode)
	Type        Type   `json:"type"`
	DUP         bool   `json:"dup"`
	QoS         int    `json:"qos"`
	Retain      bool   `json:"retain"`
	PacketID    uint16 `json:"packet_id"` // meaningful only within one session generation
	HasPacketID bool   `json:"has_packet_id"`

	CleanStart    bool   `json:"clean_start"`
	SessionExpiry *int64 `json:"session_expiry_s,omitempty"` // seconds, from CONNECT/DISCONNECT props
	SessionPresent bool  `json:"session_present"`            // CONNACK
	Topic         string `json:"topic,omitempty"`
	TopicAlias    *uint16 `json:"topic_alias,omitempty"`
	PayloadHex    string `json:"payload_hex,omitempty"`
	ReasonCode    int    `json:"reason_code"`

	Diagnostics []string `json:"diagnostics,omitempty"`
}

// Raw returns the decoded raw bytes.
func (p *Packet) Raw() ([]byte, error) {
	return hex.DecodeString(p.RawHex)
}

// Decode parses the raw bytes of p in place, preserving RawHex. Any parse
// failure is appended to Diagnostics and the packet remains usable in raw
// form; parsing never destroys the original bytes.
func (p *Packet) Decode() {
	b, err := p.Raw()
	if err != nil {
		p.Type = UNKNOWN
		p.Diagnostics = append(p.Diagnostics, "raw hex undecodable: "+err.Error())
		return
	}
	if len(b) < 2 {
		p.Type = UNKNOWN
		p.Diagnostics = append(p.Diagnostics, "packet shorter than fixed header")
		return
	}
	r := &reader{buf: b}
	b1 := r.byte()
	rem, ok := r.varint()
	if !ok {
		p.Type = UNKNOWN
		p.Diagnostics = append(p.Diagnostics, "malformed remaining-length varint")
		return
	}
	if int(rem) != r.remaining() {
		p.Diagnostics = append(p.Diagnostics,
			fmt.Sprintf("remaining-length %d != actual %d; raw preserved", rem, r.remaining()))
	}
	switch b1 >> 4 {
	case 1:
		p.Type = CONNECT
		p.decodeConnect(r)
	case 2:
		p.Type = CONNACK
		if r.remaining() >= 1 {
			p.SessionPresent = r.byte()&0x01 == 1
		}
		if r.remaining() >= 1 {
			p.ReasonCode = int(r.byte())
		}
		p.decodeProps(r)
	case 3:
		p.Type = PUBLISH
		p.DUP = b1&0x08 != 0
		p.QoS = int(b1>>1) & 0x03
		p.Retain = b1&0x01 != 0
		p.decodePublish(r)
	case 4:
		p.Type, p.HasPacketID = PUBACK, true
		p.decodeAck(r)
	case 5:
		p.Type, p.HasPacketID = PUBREC, true
		p.decodeAck(r)
	case 6:
		p.Type, p.HasPacketID = PUBREL, true
		p.decodeAck(r)
	case 7:
		p.Type, p.HasPacketID = PUBCOMP, true
		p.decodeAck(r)
	case 8:
		p.Type = SUBSCRIBE
		p.decodeSubscribe(r)
	case 9:
		p.Type = SUBACK
		p.decodeAck(r)
	case 10:
		p.Type = UNSUBSCRIBE
		p.decodeSubscribe(r)
	case 11:
		p.Type = UNSUBACK
		p.decodeAck(r)
	case 14:
		p.Type = DISCONNECT
		if r.remaining() >= 1 {
			p.ReasonCode = int(r.byte())
		}
		p.decodeProps(r)
	default:
		p.Type = UNKNOWN
		p.Diagnostics = append(p.Diagnostics, fmt.Sprintf("unhandled packet type nibble %d", b1>>4))
	}
}

func (p *Packet) decodeConnect(r *reader) {
	proto := r.str()
	level := r.byte()
	flags := r.byte()
	_ = r.uint16() // keepalive
	if proto != "MQTT" || level != 5 {
		p.Diagnostics = append(p.Diagnostics, fmt.Sprintf("unexpected protocol %q level %d", proto, level))
	}
	p.CleanStart = flags&0x02 != 0
	p.decodeProps(r)
	p.ClientID = r.str()
}

func (p *Packet) decodePublish(r *reader) {
	p.Topic = r.str()
	if p.QoS > 0 {
		p.PacketID = r.uint16()
		p.HasPacketID = true
	}
	p.decodeProps(r)
	if r.remaining() > 0 {
		p.PayloadHex = hex.EncodeToString(r.buf[r.pos:])
	}
	r.pos = len(r.buf)
}

func (p *Packet) decodeAck(r *reader) {
	if r.remaining() >= 2 {
		p.PacketID = r.uint16()
	}
	if r.remaining() >= 1 {
		p.ReasonCode = int(r.byte())
	}
}

func (p *Packet) decodeSubscribe(r *reader) {
	p.PacketID = r.uint16()
	p.HasPacketID = true
	p.decodeProps(r)
	p.Topic = r.str() // first topic filter; full list kept in raw bytes
	if r.remaining() >= 1 {
		p.ReasonCode = int(r.byte()) // subscription options
	}
}

// decodeProps reads the MQTT v5 property block, extracting session expiry
// and topic alias. Unknown properties are skipped by best effort.
func (p *Packet) decodeProps(r *reader) {
	plen, ok := r.varint()
	if !ok {
		p.Diagnostics = append(p.Diagnostics, "malformed property length")
		return
	}
	end := r.pos + int(plen)
	if end > len(r.buf) {
		p.Diagnostics = append(p.Diagnostics, "property block overruns packet")
		return
	}
	for r.pos < end {
		id := r.byte()
		switch id {
		case 0x11: // Session Expiry Interval, 4 bytes
			v := r.uint32()
			se := int64(v)
			p.SessionExpiry = &se
		case 0x23: // Topic Alias, 2 bytes
			v := r.uint16()
			p.TopicAlias = &v
		case 0x01, 0x17, 0x19, 0x26: // payload-format/request-response/user-prop…
			// user property: two strings; others single byte — best effort
			if id == 0x26 {
				_ = r.str()
				_ = r.str()
			} else {
				r.pos++
			}
		case 0x21, 0x22, 0x27, 0x13: // receive max, topic-alias max, max packet, server keepalive
			if id == 0x27 {
				r.pos += 4
			} else {
				r.pos += 2
			}
		case 0x18, 0x28, 0x29, 0x03, 0x08, 0x12, 0x15, 0x16, 0x1A, 0x1C, 0x1F, 0x02, 0x09, 0x0B:
			// string/binary/byte-ish properties: skip conservatively
			if id == 0x02 || id == 0x0B {
				_, _ = r.varint()
			} else if id == 0x18 || id == 0x28 || id == 0x29 {
				r.pos++
			} else {
				_ = r.str()
			}
		default:
			p.Diagnostics = append(p.Diagnostics, fmt.Sprintf("unknown property 0x%02x; skipping rest of props", id))
			r.pos = end
		}
	}
	r.pos = end
}

// reader is a bounds-checked cursor over a packet body.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) remaining() int { return len(r.buf) - r.pos }

func (r *reader) byte() byte {
	if r.pos >= len(r.buf) {
		return 0
	}
	b := r.buf[r.pos]
	r.pos++
	return b
}

func (r *reader) uint16() uint16 {
	hi, lo := r.byte(), r.byte()
	return uint16(hi)<<8 | uint16(lo)
}

func (r *reader) uint32() uint32 {
	var v uint32
	for i := 0; i < 4; i++ {
		v = v<<8 | uint32(r.byte())
	}
	return v
}

func (r *reader) varint() (int, bool) {
	mult, val := 1, 0
	for i := 0; i < 4; i++ {
		if r.pos >= len(r.buf) {
			return 0, false
		}
		b := r.buf[r.pos]
		r.pos++
		val += int(b&0x7F) * mult
		if b&0x80 == 0 {
			return val, true
		}
		mult *= 128
	}
	return 0, false
}

func (r *reader) str() string {
	n := int(r.uint16())
	if r.pos+n > len(r.buf) {
		n = len(r.buf) - r.pos
	}
	s := string(r.buf[r.pos : r.pos+n])
	r.pos += n
	return s
}

// HexBytes is a helper for building fixture packets.
func HexBytes(b ...byte) string { return hex.EncodeToString(b) }

// Hex joins hex fragments, ignoring spaces, for fixture readability.
func Hex(parts ...string) string {
	return strings.ReplaceAll(strings.Join(parts, ""), " ", "")
}
