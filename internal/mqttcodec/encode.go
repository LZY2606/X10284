package mqttcodec

import (
	"encoding/binary"
)

// Builder assembles MQTT 5 frames from high-level fields. It is intentionally
// small and covers exactly the packets the replay scenario emits.
type Builder struct {
	Type     byte
	Flags    byte
	DUP      bool
	QoS      byte
	Retain   bool
	PacketID uint16
	Topic    string
	Payload  []byte
	Reason   byte

	CleanStart     bool
	ClientID       string
	KeepAlive      uint16
	SessionExpiry  *uint32
	TopicAliasMax  *uint16
	TopicAlias     *uint16
	WillQoS        byte
	WillRetain     bool
	WillTopic      string
	WillPayload    []byte
	SubFilters     []SubFilter
	SubAckCodes    []byte
	UnsubFilters   []string
	ConnAckSession bool
}

func encVarInt(v uint32) []byte {
	var out []byte
	for {
		c := byte(v % 128)
		v /= 128
		if v > 0 {
			c |= 0x80
		}
		out = append(out, c)
		if v == 0 {
			return out
		}
	}
}

func encString(s string) []byte {
	b := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	copy(b[2:], s)
	return b
}

func (b Builder) Build() []byte {
	var body []byte
	flags := b.Flags
	switch b.Type {
	case CONNECT:
		body = b.buildConnect()
	case CONNACK:
		body = b.buildConnack()
	case PUBLISH:
		body = b.buildPublish()
		flags |= b.QoS << 1
		if b.DUP {
			flags |= 0x08
		}
		if b.Retain {
			flags |= 0x01
		}
	case PUBACK, PUBREC, PUBCOMP:
		body = u16b(b.PacketID)
		if b.Reason != 0 {
			body = append(body, b.Reason)
		}
	case PUBREL:
		flags |= 0x02
		body = u16b(b.PacketID)
		if b.Reason != 0 {
			body = append(body, b.Reason)
		}
	case SUBSCRIBE:
		flags |= 0x02
		body = u16b(b.PacketID)
		body = append(body, 0x00) // empty property length
		for _, sf := range b.SubFilters {
			body = append(body, encString(sf.Filter)...)
			body = append(body, sf.QoS&0x03)
		}
	case SUBACK:
		body = u16b(b.PacketID)
		body = append(body, 0x00)
		body = append(body, b.SubAckCodes...)
	case UNSUBSCRIBE:
		flags |= 0x02
		body = u16b(b.PacketID)
		body = append(body, 0x00)
		for _, f := range b.UnsubFilters {
			body = append(body, encString(f)...)
		}
	case UNSUBACK:
		body = u16b(b.PacketID)
		body = append(body, 0x00)
		body = append(body, b.SubAckCodes...)
	case DISCONNECT:
		body = []byte{b.Reason}
		if b.SessionExpiry != nil {
			p := []byte{PropSessionExpiryInterval, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(p[1:], *b.SessionExpiry)
			body = append(body, encVarInt(uint32(len(p)))...)
			body = append(body, p...)
		} else {
			body = append(body, 0x00)
		}
	case PINGREQ, PINGRESP:
		// empty body
	}
	head := []byte{(b.Type << 4) | (flags & 0x0f)}
	head = append(head, encVarInt(uint32(len(body)))...)
	return append(head, body...)
}

func u16b(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func connectProps(b Builder) []byte {
	var p []byte
	if b.SessionExpiry != nil {
		p = append(p, PropSessionExpiryInterval)
		p = append(p, u32b(*b.SessionExpiry)...)
	}
	if b.TopicAliasMax != nil {
		p = append(p, PropTopicAliasMaximum)
		p = append(p, u16b(*b.TopicAliasMax)...)
	}
	return p
}

func u32b(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func (b Builder) buildConnect() []byte {
	body := encString("MQTT")
	body = append(body, 5) // MQTT 5
	var f byte
	if b.CleanStart {
		f |= 0x02
	}
	if b.WillTopic != "" {
		f |= 0x04 | (b.WillQoS&3)<<3
		if b.WillRetain {
			f |= 0x20
		}
	}
	body = append(body, f)
	body = append(body, u16b(b.KeepAlive)...)
	props := connectProps(b)
	body = append(body, encVarInt(uint32(len(props)))...)
	body = append(body, props...)
	body = append(body, encString(b.ClientID)...)
	if b.WillTopic != "" {
		body = append(body, 0x00) // empty will properties
		body = append(body, encString(b.WillTopic)...)
		pl := make([]byte, 2+len(b.WillPayload))
		copy(pl[2:], b.WillPayload)
		body = append(body, pl...)
	}
	return body
}

func (b Builder) buildConnack() []byte {
	var sp byte
	if b.ConnAckSession {
		sp = 1
	}
	body := []byte{sp, 0} // success
	var props []byte
	if b.SessionExpiry != nil {
		props = append(props, PropSessionExpiryInterval)
		props = append(props, u32b(*b.SessionExpiry)...)
	}
	if b.TopicAliasMax != nil {
		props = append(props, PropTopicAliasMaximum)
		props = append(props, u16b(*b.TopicAliasMax)...)
	}
	body = append(body, encVarInt(uint32(len(props)))...)
	body = append(body, props...)
	return body
}

func (b Builder) buildPublish() []byte {
	body := encString(b.Topic)
	if b.QoS > 0 {
		body = append(body, u16b(b.PacketID)...)
	}
	var props []byte
	if b.TopicAlias != nil {
		props = append(props, PropTopicAlias)
		props = append(props, u16b(*b.TopicAlias)...)
	}
	body = append(body, encVarInt(uint32(len(props)))...)
	body = append(body, props...)
	body = append(body, b.Payload...)
	return body
}
