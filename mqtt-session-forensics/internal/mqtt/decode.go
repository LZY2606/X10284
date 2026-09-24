// Package mqtt decodes the subset of MQTT 3.1.1 / 5.0 control packets used by
// the forensics fixtures. The decoder never rejects a frame by dropping it:
// malformed content yields a PacketView with Malformed populated while the raw
// bytes remain stored separately.
package mqtt

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/example/mqtt-session-forensics/internal/model"
)

var typeNames = map[byte]string{
	1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
	6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK",
	10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP",
	14: "DISCONNECT",
}

func TypeName(t byte) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("RESERVED-%d", t)
}

type cursor struct {
	b   []byte
	pos int
	err error
}

func (c *cursor) byte() byte {
	if c.pos >= len(c.b) {
		c.err = errors.New("truncated packet")
		return 0
	}
	v := c.b[c.pos]
	c.pos++
	return v
}

func (c *cursor) u16() uint16 {
	hi := c.byte()
	lo := c.byte()
	return uint16(hi)<<8 | uint16(lo)
}

func (c *cursor) str() string {
	n := c.u16()
	if c.pos+int(n) > len(c.b) {
		c.err = errors.New("truncated string")
		return ""
	}
	s := string(c.b[c.pos : c.pos+int(n)])
	c.pos += int(n)
	return s
}

func (c *cursor) bytes(n int) []byte {
	if c.pos+n > len(c.b) {
		c.err = errors.New("truncated property block")
		return nil
	}
	v := c.b[c.pos : c.pos+n]
	c.pos += n
	return v
}

func decodeVarInt(b []byte, start int) (val int64, next int, err error) {
	var mult int64 = 1
	pos := start
	for {
		if pos >= len(b) {
			return 0, pos, errors.New("truncated variable byte integer")
		}
		x := b[pos]
		pos++
		val += int64(x&0x7f) * mult
		if x&0x80 == 0 {
			return val, pos, nil
		}
		mult *= 128
		if mult > 128*128*128 {
			return 0, pos, errors.New("malformed variable byte integer")
		}
	}
}

// Decode parses one complete MQTT frame (fixed header included).
func Decode(raw []byte) model.PacketView {
	v := model.PacketView{TypeName: "UNKNOWN"}
	if len(raw) < 2 {
		v.Malformed = "frame shorter than 2 bytes"
		return v
	}
	fixed := raw[0]
	v.Type = fixed >> 4
	v.TypeName = TypeName(v.Type)
	v.Flags = fixed & 0x0f
	v.DUP = fixed&0x08 != 0
	v.QoS = (fixed >> 1) & 0x03
	v.Retain = fixed&0x01 != 0

	remLen, hdrLen, err := decodeVarInt(raw, 1)
	if err != nil {
		v.Malformed = err.Error()
		return v
	}
	if int64(len(raw)-hdrLen) < remLen {
		v.Malformed = fmt.Sprintf("declared remaining length %d exceeds %d body bytes", remLen, len(raw)-hdrLen)
		return v
	}
	c := &cursor{b: raw[hdrLen : hdrLen+int(remLen)]}

	switch v.Type {
	case 1:
		decodeConnect(c, &v)
	case 2:
		decodeConnack(c, &v)
	case 3:
		decodePublish(c, &v)
	case 4, 5, 6, 7:
		decodeAckLike(c, &v)
	case 8:
		decodeSubscribe(c, &v)
	case 10:
		decodeUnsubscribe(c, &v)
	case 9:
		decodeSuback(c, &v)
	case 11:
		decodeUnsuback(c, &v)
	case 14:
		decodeDisconnect(c, &v)
	}
	if c.err != nil && v.Malformed == "" {
		v.Malformed = c.err.Error()
	}
	return v
}

func decodeConnect(c *cursor, v *model.PacketView) {
	proto := c.str()
	if !strings.HasPrefix(proto, "MQTT") {
		c.err = errors.New("bad protocol name")
		return
	}
	level := c.byte()
	v.ProtoLevel = level
	flags := c.byte()
	v.CleanStart = flags&0x02 != 0
	_ = c.u16() // keep-alive
	if level == 5 {
		decodeProps(c, v)
	}
	// payload
	cid := c.str()
	v.ClientID = cid
}

func decodeConnack(c *cursor, v *model.PacketView) {
	ackFlags := c.byte()
	v.SessionPresent = ackFlags&0x01 != 0
	v.ReasonCode = c.byte()
	if v.ProtoLevel == 0 {
		v.ProtoLevel = 5 // refined during replay using the matching CONNECT
	}
}

func decodePublish(c *cursor, v *model.PacketView) {
	v.Topic = c.str()
	if v.QoS > 0 {
		v.PacketID = c.u16()
		v.HasPacketID = true
	}
	// Properties exist only for MQTT5; replay retries decode when protocol level
	// becomes known. We cannot tell 3.1.1 from 5 here, so properties are parsed
	// optimistically by the caller via DecodePublishPropsAtLevel.
	v.Payload = string(remaining(c))
}

// DecodeAtLevel re-parses a raw frame once the protocol level is known (a
// PUBLISH cannot carry its own level). Only MQTT5 PUBLISH properties differ.
func DecodeAtLevel(prev model.PacketView, raw []byte, level byte) model.PacketView {
	v := prev
	if v.Type != 3 || level != 5 || len(raw) < 2 {
		return v
	}
	_, hdrLen, err := decodeVarInt(raw, 1)
	if err != nil {
		return v
	}
	c := &cursor{b: raw[hdrLen:]}
	_ = c.str()
	if v.QoS > 0 {
		_ = c.u16()
	}
	start := c.pos
	if p, err := decodeProps(c, &v); err == nil {
		_ = p
		if c.pos < len(c.b) {
			v.Payload = string(c.b[c.pos:])
		}
	} else {
		c.pos = start
		v.Payload = string(c.b[start:])
	}
	v.ProtoLevel = level
	return v
}

func remaining(c *cursor) []byte {
	if c.pos >= len(c.b) {
		return nil
	}
	return c.b[c.pos:]
}

func decodeAckLike(c *cursor, v *model.PacketView) {
	if c.pos+2 <= len(c.b) {
		v.PacketID = c.u16()
		v.HasPacketID = true
	}
	if c.pos < len(c.b) {
		v.ReasonCode = c.byte()
	}
}

func decodeSubscribe(c *cursor, v *model.PacketView) {
	v.PacketID = c.u16()
	v.HasPacketID = true
	// MQTT5: property length + properties (none of interest), then filters.
	if c.pos < len(c.b) {
		pl := c.byte()
		c.pos += int(pl)
	}
	for c.pos < len(c.b) && c.err == nil {
		topic := c.str()
		opts := c.byte()
		v.Filters = append(v.Filters, model.SubFilter{Topic: topic, QoS: opts & 0x03})
	}
}

func decodeUnsubscribe(c *cursor, v *model.PacketView) {
	v.PacketID = c.u16()
	v.HasPacketID = true
	if c.pos < len(c.b) {
		pl := c.byte()
		c.pos += int(pl)
	}
	for c.pos < len(c.b) && c.err == nil {
		topic := c.str()
		v.Filters = append(v.Filters, model.SubFilter{Topic: topic})
	}
}

func decodeSuback(c *cursor, v *model.PacketView) {
	v.PacketID = c.u16()
	v.HasPacketID = true
	if c.pos < len(c.b) {
		pl := c.byte()
		c.pos += int(pl)
	}
	for c.pos < len(c.b) {
		v.Grants = append(v.Grants, c.byte())
	}
}

func decodeUnsuback(c *cursor, v *model.PacketView) {
	v.PacketID = c.u16()
	v.HasPacketID = true
}

func decodeDisconnect(c *cursor, v *model.PacketView) {
	if c.pos < len(c.b) {
		v.ReasonCode = c.byte()
	}
	if v.ProtoLevel == 5 {
		decodeProps(c, v)
	}
}

// decodeProps reads one MQTT5 property block. It records only the properties
// relevant to forensics (session expiry interval 17, topic alias 35).
func decodeProps(c *cursor, v *model.PacketView) (map[int][]byte, error) {
	if c.pos >= len(c.b) {
		return nil, nil // empty property length is legal when positioned at end
	}
	total := c.byte()
	end := c.pos + int(total)
	if end > len(c.b) {
		return nil, errors.New("truncated properties")
	}
	props := map[int][]byte{}
	for c.pos < end {
		id := c.byte()
		switch id {
		case 17: // Session Expiry Interval (uint32, seconds)
			x := c.bytes(4)
			v.SessionExpiry = uint32(x[0])<<24 | uint32(x[1])<<16 | uint32(x[2])<<8 | uint32(x[3])
			v.HasSessionExpiry = true
			props[17] = x
		case 35: // Topic Alias (uint16)
			x := c.bytes(2)
			v.TopicAlias = uint16(x[0])<<8 | uint16(x[1])
			v.TopicAliasSet = true
			props[35] = x
		default:
			skipProp(c, id)
		}
		if c.err != nil {
			return nil, c.err
		}
	}
	return props, nil
}

func skipProp(c *cursor, id byte) {
	// Sizes for the property identifiers that may appear in our fixtures.
	switch id {
	case 1, 3, 4, 26, 28, 31, 33, 34, 38, 42, 43, 49, 50: // 2-byte
		_ = c.u16()
	case 2, 17, 39, 41: // 4-byte
		_ = c.bytes(4)
	case 0: // 1-byte
		_ = c.byte()
	case 11, 21: // variable byte int -> skip leniently one byte
		_ = c.byte()
	case 18: // will delay 4
		_ = c.bytes(4)
	case 23, 24: // 1-byte
		_ = c.byte()
	case 25, 27: // 2-byte
		_ = c.u16()
	case 36, 37: // 4-byte
		_ = c.bytes(4)
	case 40: // subscription ids variable int (lenient)
		_ = c.byte()
	default:
		c.err = fmt.Errorf("unsupported property id %d", id)
	}
}

// DecodeHex is a convenience helper for fixtures/tests.
func DecodeHex(h string) (model.PacketView, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return model.PacketView{}, err
	}
	return Decode(raw), nil
}
