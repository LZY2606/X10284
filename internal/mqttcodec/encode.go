package mqttcodec

import (
	"encoding/binary"
	"errors"
)

func (r *reader) u32() (uint32, error) {
	if r.pos+4 > len(r.b) {
		return 0, errors.New("truncated u32")
	}
	v := binary.BigEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v, nil
}

func encodeVarInt(v int) []byte {
	var out []byte
	for {
		b := byte(v % 128)
		v /= 128
		if v > 0 {
			b |= 128
		}
		out = append(out, b)
		if v == 0 {
			return out
		}
	}
}

func str16(s string) []byte {
	b := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	copy(b[2:], s)
	return b
}

func u16b(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func u32b(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

func frame(pType byte, flags byte, body []byte) []byte {
	h := []byte{(pType << 4) | flags}
	h = append(h, encodeVarInt(len(body))...)
	return append(h, body...)
}

// Builder describes a frame to encode (MQTT 5 unless noted).
type Builder struct {
	Type       byte
	DUP        bool
	QoS        byte
	RETAIN     bool
	PacketID   uint16
	Topic      string
	Payload    []byte
	ClientID   string
	CleanStart bool
	KeepAlive  uint16
	Level      byte
	Reason     byte
	Subs       []SubFilter
	Unsubs     []string
	Props      map[byte][]byte
}

func propsBody(props map[byte][]byte) []byte {
	var p []byte
	for id, v := range props {
		p = append(p, id)
		p = append(p, v...)
	}
	out := encodeVarInt(len(p))
	return append(out, p...)
}

// Encode builds a wire frame.
func Encode(b Builder) []byte {
	var flags byte
	if b.DUP {
		flags |= 0x08
	}
	flags |= (b.QoS & 3) << 1
	if b.RETAIN {
		flags |= 0x01
	}
	var body []byte
	switch b.Type {
	case CONNECT:
		level := b.Level
		if level == 0 {
			level = 5
		}
		body = append(body, str16("MQTT")...)
		body = append(body, level)
		var f byte
		if b.CleanStart {
			f |= 0x02
		}
		body = append(body, f)
		body = append(body, u16b(b.KeepAlive)...)
		if level == 5 {
			body = append(body, propsBody(b.Props)...)
		}
		body = append(body, str16(b.ClientID)...)
	case CONNACK:
		body = append(body, 0x00, b.Reason)
		body = append(body, propsBody(b.Props)...)
	case PUBLISH:
		body = append(body, str16(b.Topic)...)
		if b.QoS > 0 {
			body = append(body, u16b(b.PacketID)...)
		}
		body = append(body, propsBody(b.Props)...)
		body = append(body, b.Payload...)
		if b.QoS == 1 || b.QoS == 2 {
			flags |= 0
		}
	case PUBACK, PUBREC, PUBCOMP:
		body = u16b(b.PacketID)
		if b.Reason != 0 || len(b.Props) > 0 {
			body = append(body, b.Reason)
			body = append(body, propsBody(b.Props)...)
		}
	case PUBREL:
		flags |= 0x02
		body = u16b(b.PacketID)
		if b.Reason != 0 || len(b.Props) > 0 {
			body = append(body, b.Reason)
			body = append(body, propsBody(b.Props)...)
		}
	case SUBSCRIBE:
		flags |= 0x02
		body = u16b(b.PacketID)
		body = append(body, propsBody(b.Props)...)
		for _, s := range b.Subs {
			body = append(body, str16(s.Filter)...)
			body = append(body, s.QoS)
		}
	case SUBACK:
		body = u16b(b.PacketID)
		body = append(body, propsBody(b.Props)...)
		for _, s := range b.Subs {
			body = append(body, s.QoS)
		}
	case UNSUBSCRIBE:
		flags |= 0x02
		body = u16b(b.PacketID)
		body = append(body, propsBody(b.Props)...)
		for _, f := range b.Unsubs {
			body = append(body, str16(f)...)
		}
	case UNSUBACK:
		body = u16b(b.PacketID)
		body = append(body, propsBody(b.Props)...)
		for range b.Unsubs {
			body = append(body, 0x00)
		}
	case DISCONNECT:
		body = append(body, b.Reason)
		body = append(body, propsBody(b.Props)...)
	}
	return frame(b.Type, flags, body)
}

// Convenience constructors for the properties the case pack exercises.
func PropSessionExpiry(seconds uint32) map[byte][]byte {
	return map[byte][]byte{0x11: u32b(seconds)}
}
func PropTopicAlias(alias uint16) map[byte][]byte {
	return map[byte][]byte{0x23: u16b(alias)}
}
func PropAliasMaximum(max uint16) map[byte][]byte {
	return map[byte][]byte{0x22: u16b(max)}
}
