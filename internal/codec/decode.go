package codec

import "encoding/binary"

// Decoded is a decoded packet view with non-fatal diagnostics.
type Decoded struct {
	Frame Frame
	Proto byte
	Diags []string
}

// Decode parses one complete MQTT packet from b.
func Decode(b []byte) (Decoded, error) {
	var d Decoded
	if len(b) < 2 {
		return d, ErrMalformed
	}
	hdr := b[0]
	ptype := int(hdr >> 4)
	if ptype < 1 || ptype > 14 {
		return d, ErrMalformed
	}
	rlen, used, err := decRL(b[1:])
	if err != nil {
		return d, err
	}
	if len(b) < 1+used+rlen {
		return d, ErrMalformed
	}
	vh := b[1+used : 1+used+rlen]
	f := Frame{Type: ptype, DUP: hdr&0x08 != 0, QoS: int((hdr>>1)&0x03), RETAIN: hdr&0x01 != 0}

	switch ptype {
	case CONNECT:
		name, rest, err := decString(vh)
		if err != nil {
			return d, err
		}
		if len(rest) < 3 {
			return d, ErrMalformed
		}
		proto := rest[0]
		if name != "MQTT" || (proto != 4 && proto != 5) {
			return d, ErrMalformed
		}
		d.Proto = proto
		f.Protocol = proto
		f.CleanStart = rest[1]&0x02 != 0
		f.KeepAlive = binary.BigEndian.Uint16(rest[2:])
		rest = rest[4:]
		if proto == 5 {
			p, r2, err := decodeProps(rest)
			if err != nil {
				d.Diags = append(d.Diags, "connect-props: "+err.Error())
				rest = nil
			} else {
				rest = r2
				f.SessionExpirySec = u32val(p.SessionExpirySec)
				f.AliasMax = u16val(p.TopicAliasMax)
				f.PropsExtra = p
			}
		}
		if len(rest) > 0 {
			cid, _, err := decString(rest)
			if err != nil {
				return d, err
			}
			f.ClientID = cid
		}
	case CONNACK:
		if len(vh) < 2 {
			return d, ErrMalformed
		}
		f.SessionPresent = vh[0] == 1
		f.ReasonCode = vh[1]
		d.Proto = 5
		if len(vh) > 2 {
			if _, _, err := decodeProps(vh[2:]); err != nil {
				d.Diags = append(d.Diags, "connack-props: "+err.Error())
			}
		} else {
			d.Proto = 4
		}
		f.Protocol = d.Proto
	case PUBLISH:
		topic, rest, err := decString(vh)
		if err != nil {
			return d, err
		}
		f.Topic = topic
		if f.QoS > 0 {
			if len(rest) < 2 {
				return d, ErrMalformed
			}
			f.PacketID = binary.BigEndian.Uint16(rest)
			rest = rest[2:]
		}
		d.Proto = 4
		if len(rest) > 0 && looksLikeV5Props(rest) {
			if p, r2, err := decodeProps(rest); err == nil {
				d.Proto = 5
				rest = r2
				f.Alias = u16val(p.TopicAlias)
				f.PropsExtra = p
			}
		}
		f.Payload = rest
	case PUBACK, PUBREC, PUBREL, PUBCOMP:
		if len(vh) < 2 {
			return d, ErrMalformed
		}
		f.PacketID = binary.BigEndian.Uint16(vh)
		rest := vh[2:]
		if len(rest) > 0 {
			d.Proto = 5
			f.Protocol = 5
			f.HasReason = true
			f.ReasonCode = rest[0]
		} else {
			d.Proto = 4
			f.Protocol = 4
		}
	case SUBSCRIBE:
		if len(vh) < 2 {
			return d, ErrMalformed
		}
		f.PacketID = binary.BigEndian.Uint16(vh)
		rest := vh[2:]
		d.Proto = 5
		if p, r2, err := decodeProps(rest); err == nil {
			rest = r2
			f.PropsExtra = p
		} else {
			d.Proto = 4
		}
		f.Protocol = d.Proto
		for len(rest) >= 2 {
			fl, r2, err := decString(rest)
			if err != nil {
				return d, err
			}
			rest = r2
			if len(rest) < 1 {
				return d, ErrMalformed
			}
			q := rest[0]
			rest = rest[1:]
			sf := SubFilter{Filter: fl, QoS: q}
			if f.PropsExtra.SubscriptionID != nil {
				sf.SubID = *f.PropsExtra.SubscriptionID
			}
			f.Filters = append(f.Filters, sf)
		}
	case SUBACK:
		if len(vh) < 2 {
			return d, ErrMalformed
		}
		f.PacketID = binary.BigEndian.Uint16(vh)
		rest := vh[2:]
		d.Proto = 4
		if len(rest) > 1 {
			if _, r2, err := decodeProps(rest); err == nil {
				rest = r2
				d.Proto = 5
			}
		}
		f.SubAckQoS = rest
	case UNSUBSCRIBE:
		if len(vh) < 2 {
			return d, ErrMalformed
		}
		f.PacketID = binary.BigEndian.Uint16(vh)
		rest := vh[2:]
		if p, r2, err := decodeProps(rest); err == nil {
			rest = r2
			f.PropsExtra = p
			d.Proto = 5
		} else {
			d.Proto = 4
		}
		f.Protocol = d.Proto
		for len(rest) >= 2 {
			t, r2, err := decString(rest)
			if err != nil {
				return d, err
			}
			rest = r2
			f.UnsubTopics = append(f.UnsubTopics, t)
		}
	case UNSUBACK:
		if len(vh) < 2 {
			return d, ErrMalformed
		}
		f.PacketID = binary.BigEndian.Uint16(vh)
		rest := vh[2:]
		d.Proto = 4
		if len(rest) > 1 {
			if _, r2, err := decodeProps(rest); err == nil {
				rest = r2
				d.Proto = 5
			}
		}
		f.SubAckQoS = rest
	case DISCONNECT:
		d.Proto = 4
		if len(vh) >= 1 {
			d.Proto = 5
			f.Protocol = 5
			f.HasReason = true
			f.ReasonCode = vh[0]
			if p, r2, err := decodeProps(vh[1:]); err == nil {
				f.SessionExpirySec = u32val(p.SessionExpirySec)
				f.PropsExtra = p
				_ = r2
			}
		}
	}
	d.Frame = f
	return d, nil
}

func u32val(p *uint32) uint32 {
	if p != nil {
		return *p
	}
	return 0
}
func u16val(p *uint16) uint16 {
	if p != nil {
		return *p
	}
	return 0
}

// looksLikeV5Props guards against treating a v3.1.1 PUBLISH payload as v5
// properties. A valid property length prefix plus supported property ids
// that fully consume the prefix length is required.
func looksLikeV5Props(rest []byte) bool {
	total, after, err := decVarInt(rest)
	if err != nil || total > len(after) {
		return false
	}
	body := after[:total]
	for len(body) > 0 {
		id := body[0]
		var skip int
		switch id {
		case 0x11:
			skip = 5
		case 0x22, 0x23:
			skip = 3
		case 0x1F, 0x03:
			if len(body) < 3 {
				return false
			}
			n := int(binary.BigEndian.Uint16(body[1:]))
			skip = 3 + n
		case 0x0B:
			_, rem, err := decVarInt(body[1:])
			if err != nil {
				return false
			}
			skip = len(body) - len(rem)
		default:
			return false
		}
		if skip > len(body) {
			return false
		}
		body = body[skip:]
	}
	return true
}
