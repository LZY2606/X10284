// Package mqtt models MQTT 5 packet traces with raw bytes preserved.
// Import keeps the original representation; normalization happens in the
// derived layer. Values that cannot be converted stay in place and carry a
// diagnostic instead of being dropped.
package mqtt

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type Direction string

const (
	C2B Direction = "c2b" // client to broker
	B2C Direction = "b2c" // broker to client
)

// BasisVirtual is the coordinate basis for all trace clocks: virtual
// milliseconds since trace start. Session-expiry boundaries are evaluated
// against this virtual clock, never wall time.
const BasisVirtual = "virtual-ms/trace-start"

type PacketType int

const (
	INVALID PacketType = iota
	CONNECT
	CONNACK
	PUBLISH
	PUBACK
	PUBREC
	PUBREL
	PUBCOMP
	SUBSCRIBE
	SUBACK
	UNSUBSCRIBE
	UNSUBACK
	PINGREQ
	PINGRESP
	DISCONNECT
)

func (t PacketType) String() string {
	switch t {
	case CONNECT:
		return "CONNECT"
	case CONNACK:
		return "CONNACK"
	case PUBLISH:
		return "PUBLISH"
	case PUBACK:
		return "PUBACK"
	case PUBREC:
		return "PUBREC"
	case PUBREL:
		return "PUBREL"
	case PUBCOMP:
		return "PUBCOMP"
	case SUBSCRIBE:
		return "SUBSCRIBE"
	case SUBACK:
		return "SUBACK"
	case UNSUBSCRIBE:
		return "UNSUBSCRIBE"
	case UNSUBACK:
		return "UNSUBACK"
	case PINGREQ:
		return "PINGREQ"
	case PINGRESP:
		return "PINGRESP"
	case DISCONNECT:
		return "DISCONNECT"
	}
	return "INVALID"
}

// Diagnostic is attached to a value that could not be normalized. The raw
// representation remains in place on the packet.
type Diagnostic struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Quantity is a domain value carrying its unit and coordinate basis.
type Quantity struct {
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
	Basis string  `json:"basis"`
}

func MS(v int64) Quantity { return Quantity{Value: float64(v), Unit: "ms", Basis: BasisVirtual} }
func Sec(v uint32) Quantity {
	return Quantity{Value: float64(v), Unit: "s", Basis: "session-expiry-interval"}
}

type Subscription struct {
	Topic string `json:"topic"`
	QoS   int    `json:"qos"`
}

// Packet is one traced MQTT packet. Raw bytes, direction, packet id,
// DUP/retain flags, clean start / session expiry, topic alias and the
// virtual clock are all preserved.
type Packet struct {
	ID             string         `json:"id"` // stable identity: pkt-<seq>
	Seq            int            `json:"seq"`
	RawHex         string         `json:"raw_hex"`
	Dir            Direction      `json:"dir"`
	ClockMS        int64          `json:"clock_ms"` // BasisVirtual
	Type           PacketType     `json:"type"`
	Dup            bool           `json:"dup"`
	Retain         bool           `json:"retain"`
	QoS            int            `json:"qos"`
	PacketID       *uint16        `json:"packet_id,omitempty"`
	ClientID       string         `json:"client_id,omitempty"`
	CleanStart     *bool          `json:"clean_start,omitempty"`
	SessionExpiryS *uint32        `json:"session_expiry_s,omitempty"`
	KeepAliveS     uint16         `json:"keep_alive_s,omitempty"`
	SessionPresent *bool          `json:"session_present,omitempty"`
	Topic          string         `json:"topic,omitempty"`
	TopicAlias     *uint16        `json:"topic_alias,omitempty"`
	PayloadHex     string         `json:"payload_hex,omitempty"`
	Subs           []Subscription `json:"subs,omitempty"`
	Diagnostics    []Diagnostic   `json:"diagnostics,omitempty"`
}

func (p *Packet) diag(code, detail string) {
	p.Diagnostics = append(p.Diagnostics, Diagnostic{Code: code, Detail: detail})
}

// TraceEntry is the import representation: raw bytes + direction + clock.
type TraceEntry struct {
	Dir     Direction `json:"dir"`
	ClockMS int64     `json:"clock_ms"`
	Hex     string    `json:"hex"`
}

type cursor struct {
	b   []byte
	pos int
	err error
}

func (c *cursor) u8() int {
	if c.err != nil || c.pos+1 > len(c.b) {
		c.err = fmt.Errorf("truncated")
		return 0
	}
	v := c.b[c.pos]
	c.pos++
	return int(v)
}

func (c *cursor) u16() int {
	if c.err != nil || c.pos+2 > len(c.b) {
		c.err = fmt.Errorf("truncated")
		return 0
	}
	v := int(c.b[c.pos])<<8 | int(c.b[c.pos+1])
	c.pos += 2
	return v
}

func (c *cursor) u32() int64 {
	if c.err != nil || c.pos+4 > len(c.b) {
		c.err = fmt.Errorf("truncated")
		return 0
	}
	v := int64(c.b[c.pos])<<24 | int64(c.b[c.pos+1])<<16 | int64(c.b[c.pos+2])<<8 | int64(c.b[c.pos+3])
	c.pos += 4
	return v
}

func (c *cursor) varint() int {
	mul, val := 1, 0
	for i := 0; i < 4; i++ {
		d := c.u8()
		if c.err != nil {
			return 0
		}
		val += (d & 0x7f) * mul
		if d&0x80 == 0 {
			return val
		}
		mul *= 128
	}
	c.err = fmt.Errorf("malformed varint")
	return 0
}

func (c *cursor) str() string {
	n := c.u16()
	if c.err != nil || c.pos+n > len(c.b) {
		c.err = fmt.Errorf("truncated string")
		return ""
	}
	s := string(c.b[c.pos : c.pos+n])
	c.pos += n
	return s
}

func (c *cursor) rest() []byte {
	if c.err != nil || c.pos > len(c.b) {
		return nil
	}
	r := c.b[c.pos:]
	c.pos = len(c.b)
	return r
}

// Parse decodes one packet. Unconvertible parts never drop the packet: the
// raw bytes stay and a diagnostic is attached.
func Parse(e TraceEntry, seq int) Packet {
	raw, err := hex.DecodeString(strings.TrimSpace(e.Hex))
	p := Packet{
		ID:      fmt.Sprintf("pkt-%04d", seq),
		Seq:     seq,
		Dir:     e.Dir,
		ClockMS: e.ClockMS,
	}
	if err != nil {
		p.RawHex = e.Hex
		p.Type = INVALID
		p.diag("bad-hex", "trace entry is not valid hex; raw representation kept")
		return p
	}
	p.RawHex = hex.EncodeToString(raw)
	if len(raw) < 2 {
		p.Type = INVALID
		p.diag("truncated", "fixed header incomplete")
		return p
	}
	typeNib := raw[0] >> 4
	flags := raw[0] & 0x0f
	c := &cursor{b: raw, pos: 1}
	remLen := c.varint()
	if c.err != nil || c.pos+remLen > len(raw) {
		p.Type = INVALID
		p.diag("bad-remaining-length", "remaining length exceeds buffer")
		return p
	}
	body := &cursor{b: raw[c.pos : c.pos+remLen]}
	switch typeNib {
	case 1:
		p.Type = CONNECT
		proto := body.str()
		level := body.u8()
		connFlags := body.u8()
		cs := connFlags&0x02 != 0
		p.CleanStart = &cs
		p.KeepAliveS = uint16(body.u16())
		pr := parseProps(body)
		if pr.hasExpiry {
			v := pr.sessionExpiry
			p.SessionExpiryS = &v
		}
		p.ClientID = body.str()
		if body.err != nil {
			p.diag("connect-parse", "CONNECT variable header truncated: "+body.err.Error())
		}
		if proto != "MQTT" || level != 5 {
			p.diag("protocol", fmt.Sprintf("unexpected proto=%q level=%d", proto, level))
		}
	case 2:
		p.Type = CONNACK
		ack := body.u8()
		sp := ack&0x01 != 0
		p.SessionPresent = &sp
		_ = body.u8() // reason code
		if body.err != nil {
			p.diag("connack-parse", body.err.Error())
		}
	case 3:
		p.Type = PUBLISH
		p.Dup = flags&0x08 != 0
		p.QoS = int((flags & 0x06) >> 1)
		p.Retain = flags&0x01 != 0
		p.Topic = body.str()
		if p.QoS > 0 {
			pid := uint16(body.u16())
			p.PacketID = &pid
		}
		pr := parseProps(body)
		if pr.hasAlias {
			v := pr.topicAlias
			p.TopicAlias = &v
		}
		pl := body.rest()
		p.PayloadHex = hex.EncodeToString(pl)
		if body.err != nil {
			p.diag("publish-parse", body.err.Error())
		}
		if p.Topic == "" && p.TopicAlias == nil {
			p.diag("empty-topic", "PUBLISH has neither topic nor topic alias")
		}
	case 4, 5, 6, 7:
		p.Type = []PacketType{PUBACK, PUBREC, PUBREL, PUBCOMP}[typeNib-4]
		pid := uint16(body.u16())
		p.PacketID = &pid
		if body.err != nil {
			p.diag("ack-parse", body.err.Error())
		}
	case 8:
		p.Type = SUBSCRIBE
		pid := uint16(body.u16())
		p.PacketID = &pid
		parseProps(body)
		for body.err == nil && body.pos < len(body.b) {
			t := body.str()
			if body.err != nil {
				break
			}
			q := body.u8() & 0x03
			p.Subs = append(p.Subs, Subscription{Topic: t, QoS: q})
		}
		if len(p.Subs) == 0 {
			p.diag("subscribe-parse", "no topic filters decoded")
		}
	case 9:
		p.Type = SUBACK
		pid := uint16(body.u16())
		p.PacketID = &pid
	case 10:
		p.Type = UNSUBSCRIBE
		pid := uint16(body.u16())
		p.PacketID = &pid
		parseProps(body)
		for body.err == nil && body.pos < len(body.b) {
			t := body.str()
			if body.err != nil {
				break
			}
			p.Subs = append(p.Subs, Subscription{Topic: t})
		}
	case 11:
		p.Type = UNSUBACK
		pid := uint16(body.u16())
		p.PacketID = &pid
	case 12:
		p.Type = PINGREQ
	case 13:
		p.Type = PINGRESP
	case 14:
		p.Type = DISCONNECT
		if len(body.b) > 0 {
			_ = body.u8() // reason
			pr := parseProps(body)
			if pr.hasExpiry {
				v := pr.sessionExpiry
				p.SessionExpiryS = &v
			}
		}
	default:
		p.Type = INVALID
		p.diag("unknown-type", fmt.Sprintf("packet type nibble %d not decodable; raw kept", typeNib))
	}
	return p
}

type props struct {
	sessionExpiry uint32
	hasExpiry     bool
	topicAlias    uint16
	hasAlias      bool
}

// parseProps reads the MQTT 5 property block. Unknown property ids abort
// property parsing with an error recorded on the cursor; the caller keeps
// whatever was decoded and attaches a diagnostic.
func parseProps(c *cursor) props {
	var out props
	n := c.varint()
	if c.err != nil || c.pos+n > len(c.b) {
		c.err = fmt.Errorf("bad property length")
		return out
	}
	end := c.pos + n
	for c.pos < end {
		id := c.u8()
		switch id {
		case 0x11: // session expiry interval, 4 bytes
			out.sessionExpiry = uint32(c.u32())
			out.hasExpiry = true
		case 0x23: // topic alias, 2 bytes
			out.topicAlias = uint16(c.u16())
			out.hasAlias = true
		case 0x26: // user property
			_ = c.str()
			_ = c.str()
		case 0x01, 0x17, 0x19, 0x21, 0x22, 0x27, 0x28, 0x29:
			// best-effort skip of common scalar properties
			c.err = fmt.Errorf("unsupported property id 0x%02x", id)
			return out
		default:
			c.err = fmt.Errorf("unknown property id 0x%02x", id)
			return out
		}
		if c.err != nil {
			return out
		}
	}
	return out
}

func (p props) expiry() (uint32, bool) { return p.sessionExpiry, p.hasExpiry }
