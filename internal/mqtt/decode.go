package mqtt

import (
	"encoding/binary"
	"fmt"
)

// Decode parses one MQTT control packet from b. The raw slice is retained on
// the result. A non-nil packet may be returned together with diagnostics for
// partially understood frames.
func Decode(b []byte) (*Packet, error) {
	if len(b) < 2 {
		return nil, ErrShort
	}
	p := &Packet{Raw: append([]byte(nil), b...)}
	p.Type = Type(b[0] >> 4)
	p.Flags = b[0] & 0x0f
	p.DUP = p.Flags&0x08 != 0
	p.QoS = (p.Flags >> 1) & 0x03
	p.Retain = p.Flags&0x01 != 0

	bodyLen, used, err := decodeVarInt(b[1:])
	if err != nil {
		p.Diagnostics = append(p.Diagnostics, Diagnostic{Code: "REMAINING_LENGTH", Message: err.Error(), Offset: 1})
		return p, err
	}
	total := 1 + used + bodyLen
	if len(b) < total {
		p.Diagnostics = append(p.Diagnostics, Diagnostic{Code: "FRAME_TRUNCATED",
			Message: fmt.Sprintf("remaining length %d but %d bytes available", bodyLen, len(b)-1-used)})
		return p, ErrShort
	}
	body := b[1+used : total]
	rest := &reader{b: body}

	switch p.Type {
	case CONNECT:
		err = parseConnect(p, rest)
	case CONNACK:
		err = parseConnack(p, rest)
	case PUBLISH:
		err = parsePublish(p, rest)
	case PUBACK, PUBREC, PUBREL, PUBCOMP:
		err = parseAck(p, rest)
	case SUBSCRIBE:
		err = parseSubscribe(p, rest)
	case SUBACK:
		err = parseSuback(p, rest)
	case UNSUBSCRIBE:
		err = parseUnsubscribe(p, rest)
	case UNSUBACK:
		err = parseUnsuback(p, rest)
	case PINGREQ, PINGRESP:
	case DISCONNECT, AUTH:
		err = parseDisconnect(p, rest)
	default:
		p.Diagnostics = append(p.Diagnostics, Diagnostic{Code: "RESERVED_TYPE", Message: fmt.Sprintf("type %d", p.Type)})
	}
	if err != nil && len(p.Diagnostics) == 0 {
		p.Diagnostics = append(p.Diagnostics, Diagnostic{Code: "PARSE", Message: err.Error()})
	}
	return p, err
}

func parseConnect(p *Packet, r *reader) error {
	proto, err := r.str()
	if err != nil {
		return err
	}
	if len(r.b) < 1 {
		return ErrShort
	}
	level := r.b[0]
	r.b = r.b[1:]
	p.Protocol = level
	if proto != "MQTT" && level != 4 {
		p.Diagnostics = append(p.Diagnostics, Diagnostic{Code: "PROTOCOL_NAME", Message: proto})
	}
	if level != 4 && level != 5 {
		p.Diagnostics = append(p.Diagnostics, Diagnostic{Code: "PROTOCOL_LEVEL", Message: fmt.Sprintf("level %d unsupported, retaining raw", level)})
	}
	if len(r.b) < 2 {
		return ErrShort
	}
	flags := r.b[0]
	r.b = r.b[1:]
	p.CleanSession311 = flags&0x02 != 0
	p.CleanStart = p.CleanSession311
	p.WillRetain = flags&0x20 != 0
	p.WillQoS = (flags >> 3) & 0x03
	p.KeepAlive = binary.BigEndian.Uint16(r.b[:2])
	r.b = r.b[2:]
	if level == 5 {
		props, rem, diags := decodeProperties(r.b)
		p.Props = props
		p.Diagnostics = append(p.Diagnostics, diags...)
		consumed := len(r.b) - len(rem)
		r.b = rem
		_ = consumed
	}
	cid, err := r.str()
	if err != nil {
		return err
	}
	p.ClientID = cid
	if flags&0x04 != 0 {
		if level == 5 {
			_, rem, diags := decodeProperties(r.b)
			p.Diagnostics = append(p.Diagnostics, diags...)
			r.b = rem
		}
		if p.WillTopic, err = r.str(); err != nil {
			return err
		}
		if p.WillPayload, err = r.rawBytes(); err != nil {
			return err
		}
	}
	if flags&0x80 != 0 {
		if p.Username, err = r.str(); err != nil {
			return err
		}
	}
	if flags&0x40 != 0 {
		if p.Password, err = r.rawBytes(); err != nil {
			return err
		}
	}
	return nil
}

func parseConnack(p *Packet, r *reader) error {
	if len(r.b) < 2 {
		return ErrShort
	}
	p.SessionPresent = r.b[0]&1 != 0
	p.ReturnCode = r.b[1]
	r.b = r.b[2:]
	// Protocol level for CONNACK is inferred at capture level; if a reason-code
	// style payload remains we treat it as MQTT5 properties.
	if len(r.b) > 0 {
		p.Protocol = 5
		p.Reason = r.b[0]
		r.b = r.b[1:]
		if len(r.b) > 0 {
			props, rem, diags := decodeProperties(r.b)
			p.Props = props
			p.Diagnostics = append(p.Diagnostics, diags...)
			r.b = rem
		}
	}
	return nil
}

func parsePublish(p *Packet, r *reader) error {
	topic, err := r.str()
	if err != nil {
		return err
	}
	p.Topic = topic
	if p.QoS > 0 {
		id, err := r.u16()
		if err != nil {
			return err
		}
		p.PacketID = id
	}
	// MQTT5 properties can only be distinguished from payload when the capture
	// marks the level; captures set Protocol on every packet. If it parses as a
	// valid property block whose length exactly precedes payload end, accept it.
	if p.Protocol == 5 && len(r.b) > 0 {
		props, rem, diags := decodeProperties(r.b)
		p.Props = props
		p.Diagnostics = append(p.Diagnostics, diags...)
		r.b = rem
	}
	p.Payload = append([]byte(nil), r.b...)
	return nil
}

func parseAck(p *Packet, r *reader) error {
	if len(r.b) < 2 {
		return ErrShort
	}
	p.PacketID = binary.BigEndian.Uint16(r.b[:2])
	r.b = r.b[2:]
	if len(r.b) > 0 {
		p.Protocol = 5
		p.Reason = r.b[0]
		r.b = r.b[1:]
		if len(r.b) > 0 {
			props, rem, diags := decodeProperties(r.b)
			p.AckProps = props
			p.Diagnostics = append(p.Diagnostics, diags...)
			r.b = rem
		}
	}
	return nil
}

func parseSubscribe(p *Packet, r *reader) error {
	id, err := r.u16()
	if err != nil {
		return err
	}
	p.PacketID = id
	if len(r.b) > 0 {
		// MQTT5 properties; a zero-length property field also occurs in 5.0.
		props, rem, diags := decodeProperties(r.b)
		p.Props = props
		p.Diagnostics = append(p.Diagnostics, diags...)
		r.b = rem
		p.Protocol = 5
	}
	for len(r.b) > 0 {
		t, err := r.str()
		if err != nil {
			return err
		}
		if len(r.b) < 1 {
			return ErrShort
		}
		opt := r.b[0]
		r.b = r.b[1:]
		p.Filters = append(p.Filters, Filter{
			Topic:             t,
			QoS:               opt & 0x03,
			NoLocal:           opt&0x04 != 0,
			RetainAsPublished: opt&0x08 != 0,
			RetainHandling:    (opt >> 4) & 0x03,
		})
	}
	return nil
}

func parseSuback(p *Packet, r *reader) error {
	id, err := r.u16()
	if err != nil {
		return err
	}
	p.PacketID = id
	if len(r.b) > 0 {
		saved := r.b
		props, rem, diags := decodeProperties(r.b)
		// Heuristic: property block must leave at least one granted byte.
		if len(rem) >= 1 {
			p.Props = props
			p.Diagnostics = append(p.Diagnostics, diags...)
			r.b = rem
			p.Protocol = 5
		} else {
			r.b = saved
		}
	}
	p.Granted = append([]byte(nil), r.b...)
	return nil
}

func parseUnsubscribe(p *Packet, r *reader) error {
	id, err := r.u16()
	if err != nil {
		return err
	}
	p.PacketID = id
	if len(r.b) > 0 {
		_, rem, diags := decodeProperties(r.b)
		p.Diagnostics = append(p.Diagnostics, diags...)
		r.b = rem
	}
	for len(r.b) > 0 {
		t, err := r.str()
		if err != nil {
			return err
		}
		p.Filters = append(p.Filters, Filter{Topic: t})
	}
	return nil
}

func parseUnsuback(p *Packet, r *reader) error {
	id, err := r.u16()
	if err != nil {
		return err
	}
	p.PacketID = id
	if len(r.b) > 0 {
		_, rem, diags := decodeProperties(r.b)
		p.Diagnostics = append(p.Diagnostics, diags...)
		r.b = rem
		p.Protocol = 5
	}
	p.Granted = append([]byte(nil), r.b...)
	return nil
}

func parseDisconnect(p *Packet, r *reader) error {
	if len(r.b) == 0 {
		return nil
	}
	p.Protocol = 5
	p.Reason = r.b[0]
	r.b = r.b[1:]
	if len(r.b) > 0 {
		props, rem, diags := decodeProperties(r.b)
		p.Props = props
		p.Diagnostics = append(p.Diagnostics, diags...)
		r.b = rem
	}
	return nil
}
