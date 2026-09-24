// Package mqtt implements a minimal MQTT v5 wire codec used to build and
// decode the packet traces in the offline case pack. Raw bytes are always
// preserved; decoding is a derived view and may carry diagnostics.
package mqtt

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Direction of a captured packet on the wire.
type Direction string

const (
	C2S Direction = "c2s" // client -> broker
	S2C Direction = "s2c" // broker -> client
)

// Packet types (MQTT v5 fixed header high nibble).
const (
	TypeCONNECT     = 1
	TypeCONNACK     = 2
	TypePUBLISH     = 3
	TypePUBACK      = 4
	TypePUBREC      = 5
	TypePUBREL      = 6
	TypePUBCOMP     = 7
	TypeSUBSCRIBE   = 8
	TypeSUBACK      = 9
	TypeUNSUBSCRIBE = 10
	TypeUNSUBACK    = 11
	TypePINGREQ     = 12
	TypePINGRESP    = 13
	TypeDISCONNECT  = 14
)

var typeNames = map[int]string{
	TypeCONNECT: "CONNECT", TypeCONNACK: "CONNACK", TypePUBLISH: "PUBLISH",
	TypePUBACK: "PUBACK", TypePUBREC: "PUBREC", TypePUBREL: "PUBREL",
	TypePUBCOMP: "PUBCOMP", TypeSUBSCRIBE: "SUBSCRIBE", TypeSUBACK: "SUBACK",
	TypeUNSUBSCRIBE: "UNSUBSCRIBE", TypeUNSUBACK: "UNSUBACK",
	TypePINGREQ: "PINGREQ", TypePINGRESP: "PINGRESP", TypeDISCONNECT: "DISCONNECT",
}

// TypeName renders a packet type number.
func TypeName(t int) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE-%d", t)
}

// Decoded is the derived view of a raw packet. Every field keeps its original
// unit/basis: times are virtual milliseconds unless noted, payload is bytes.
type Decoded struct {
	Type          int
	TypeName      string
	DUP           bool
	QoS           int
	Retain        bool
	PacketID      int    // 0 when not present
	Topic         string // as written on the wire ("" when alias-only)
	TopicAlias    int    // 0 when absent
	Payload       []byte
	ClientID      string
	CleanStart    *bool
	SessionExpiry *int64 // seconds, as declared in CONNECT properties
	Diag          string // non-empty when the packet could not be fully decoded
}

// Encode builds a raw MQTT packet from a fixed-header type/flags and body.
func Encode(pktType, flags int, body []byte) []byte {
	out := []byte{byte(pktType<<4 | flags)}
	out = append(out, encodeVarint(len(body))...)
	out = append(out, body...)
	return out
}

func encodeVarint(n int) []byte {
	var out []byte
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			break
		}
	}
	return out
}

func putU16(b []byte, v int) []byte {
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], uint16(v))
	return append(b, tmp[:]...)
}

func putU32(b []byte, v int64) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(v))
	return append(b, tmp[:]...)
}

func putStr(b []byte, s string) []byte {
	b = putU16(b, len(s))
	return append(b, s...)
}

// ConnectBody builds a CONNECT body (protocol name MQTT, level 5).
func ConnectBody(clientID string, cleanStart bool, sessionExpirySec int64) []byte {
	var body []byte
	body = putStr(body, "MQTT")
	body = append(body, 5) // protocol level
	flags := byte(0x02)    // clean start flag position
	if !cleanStart {
		flags = 0x00
	}
	body = append(body, flags)
	body = putU16(body, 60) // keep alive
	// properties: session expiry interval (0x11, 4 bytes)
	var props []byte
	props = append(props, 0x11)
	props = putU32(props, sessionExpirySec)
	body = append(body, encodeVarint(len(props))...)
	body = append(body, props...)
	body = putStr(body, clientID)
	return body
}

// PublishBody builds a PUBLISH body. topicAlias>0 adds a topic-alias property.
func PublishBody(topic string, packetID, topicAlias int, payload []byte) []byte {
	var body []byte
	body = putStr(body, topic)
	if packetID > 0 {
		body = putU16(body, packetID)
	}
	var props []byte
	if topicAlias > 0 {
		props = append(props, 0x23)
		props = putU16(props, topicAlias)
	}
	body = append(body, encodeVarint(len(props))...)
	body = append(body, props...)
	body = append(body, payload...)
	return body
}

// AckBody builds a PUBACK/PUBREC/PUBREL/PUBCOMP body.
func AckBody(packetID int) []byte { return putU16(nil, packetID) }

// SubscribeBody builds a SUBSCRIBE body for a single topic filter.
func SubscribeBody(packetID int, filter string, qos int) []byte {
	var body []byte
	body = putU16(body, packetID)
	body = append(body, 0) // no properties
	body = putStr(body, filter)
	body = append(body, byte(qos))
	return body
}

// UnsubscribeBody builds an UNSUBSCRIBE body for a single filter.
func UnsubscribeBody(packetID int, filter string) []byte {
	var body []byte
	body = putU16(body, packetID)
	body = append(body, 0)
	body = putStr(body, filter)
	return body
}

// Decode parses a raw packet. Failures never discard data: the returned
// Decoded carries what could be read plus a diagnostic, and callers keep the
// original bytes in place.
func Decode(raw []byte) Decoded {
	d := Decoded{}
	if len(raw) < 2 {
		d.Diag = "truncated fixed header"
		return d
	}
	d.Type = int(raw[0]) >> 4
	d.TypeName = TypeName(d.Type)
	flags := int(raw[0]) & 0x0f
	d.DUP = flags&0x08 != 0
	d.QoS = (flags >> 1) & 0x03
	d.Retain = flags&0x01 != 0

	remLen, n, ok := decodeVarint(raw[1:])
	if !ok {
		d.Diag = "malformed remaining-length varint"
		return d
	}
	body := raw[1+n:]
	if remLen > len(body) {
		d.Diag = fmt.Sprintf("remaining length %d exceeds captured %d bytes", remLen, len(body))
		return d
	}
	body = body[:remLen]

	switch d.Type {
	case TypeCONNECT:
		decodeConnect(body, &d)
	case TypePUBLISH:
		decodePublish(body, &d)
	case TypePUBACK, TypePUBREC, TypePUBREL, TypePUBCOMP, TypeSUBACK, TypeUNSUBACK:
		if len(body) < 2 {
			d.Diag = "ack body shorter than packet id"
			return d
		}
		d.PacketID = int(binary.BigEndian.Uint16(body))
	case TypeSUBSCRIBE, TypeUNSUBSCRIBE:
		decodeSubscribe(body, &d)
	}
	return d
}

func decodeVarint(b []byte) (val, consumed int, ok bool) {
	mult := 1
	for i := 0; i < 4 && i < len(b); i++ {
		val += int(b[i]&0x7f) * mult
		consumed++
		if b[i]&0x80 == 0 {
			return val, consumed, true
		}
		mult *= 128
	}
	return 0, 0, false
}

func readStr(b []byte) (string, []byte, bool) {
	if len(b) < 2 {
		return "", b, false
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b) < 2+n {
		return "", b, false
	}
	return string(b[2 : 2+n]), b[2+n:], true
}

func decodeConnect(body []byte, d *Decoded) {
	proto, rest, ok := readStr(body)
	if !ok || proto != "MQTT" {
		d.Diag = "unreadable CONNECT protocol name"
		return
	}
	if len(rest) < 4 {
		d.Diag = "truncated CONNECT flags"
		return
	}
	// rest[0]=level, rest[1]=flags, rest[2:4]=keepalive
	clean := rest[1]&0x02 != 0
	d.CleanStart = &clean
	rest = rest[4:]
	propLen, n, ok := decodeVarint(rest)
	if !ok || len(rest) < n+propLen {
		d.Diag = "unreadable CONNECT properties"
		return
	}
	props := rest[n : n+propLen]
	rest = rest[n+propLen:]
	for len(props) > 0 {
		switch props[0] {
		case 0x11: // session expiry interval
			if len(props) < 5 {
				d.Diag = "truncated session-expiry property"
				return
			}
			exp := int64(binary.BigEndian.Uint32(props[1:5]))
			d.SessionExpiry = &exp
			props = props[5:]
		default:
			// skip unknown 1-byte-identifier properties conservatively
			d.Diag = fmt.Sprintf("unknown CONNECT property 0x%02x preserved raw", props[0])
			return
		}
	}
	cid, _, ok := readStr(rest)
	if !ok {
		d.Diag = "unreadable client id"
		return
	}
	d.ClientID = cid
}

func decodePublish(body []byte, d *Decoded) {
	topic, rest, ok := readStr(body)
	if !ok {
		d.Diag = "unreadable PUBLISH topic"
		return
	}
	d.Topic = topic
	if d.QoS > 0 {
		if len(rest) < 2 {
			d.Diag = "missing packet id on QoS>0 PUBLISH"
			return
		}
		d.PacketID = int(binary.BigEndian.Uint16(rest))
		rest = rest[2:]
	}
	propLen, n, ok := decodeVarint(rest)
	if !ok || len(rest) < n+propLen {
		d.Diag = "unreadable PUBLISH properties"
		return
	}
	props := rest[n : n+propLen]
	rest = rest[n+propLen:]
	for len(props) > 0 {
		switch props[0] {
		case 0x23: // topic alias
			if len(props) < 3 {
				d.Diag = "truncated topic-alias property"
				return
			}
			d.TopicAlias = int(binary.BigEndian.Uint16(props[1:3]))
			props = props[3:]
		default:
			d.Diag = fmt.Sprintf("unknown PUBLISH property 0x%02x preserved raw", props[0])
			return
		}
	}
	d.Payload = rest
}

func decodeSubscribe(body []byte, d *Decoded) {
	if len(body) < 3 {
		d.Diag = "truncated SUBSCRIBE"
		return
	}
	d.PacketID = int(binary.BigEndian.Uint16(body))
	rest := body[2:]
	propLen, n, ok := decodeVarint(rest)
	if !ok || len(rest) < n+propLen {
		d.Diag = "unreadable SUBSCRIBE properties"
		return
	}
	rest = rest[n+propLen:]
	filter, _, ok := readStr(rest)
	if !ok {
		d.Diag = "unreadable topic filter"
		return
	}
	d.Topic = filter
}

// Hex renders raw bytes compactly for display.
func Hex(raw []byte) string {
	var sb strings.Builder
	for i, b := range raw {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", b)
	}
	return sb.String()
}
