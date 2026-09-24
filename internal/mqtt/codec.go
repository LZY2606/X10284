package mqtt

import (
	"encoding/binary"
	"fmt"
)

// ---------- low-level primitives ----------

func encodeVarInt(n int) []byte {
	var b [4]byte
	i := 0
	for {
		d := byte(n % 128)
		n /= 128
		if n > 0 {
			d |= 0x80
		}
		b[i] = d
		i++
		if n == 0 {
			return b[:i]
		}
	}
}

func decodeVarInt(b []byte) (value int, used int, err error) {
	multiplier := 1
	for i := 0; i < 4; i++ {
		if i >= len(b) {
			return 0, i, ErrShort
		}
		d := b[i]
		value += int(d&0x7f) * multiplier
		if d&0x80 == 0 {
			return value, i + 1, nil
		}
		multiplier *= 128
	}
	return 0, 4, Diagnostic{Code: "VARINT_MALFORMED", Message: "variable byte integer exceeds 4 bytes"}
}

func encString(s string) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(len(s)))
	out := append(b[:], s...)
	return out
}

func encBytes(v []byte) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(len(v)))
	return append(b[:], v...)
}

func (r *reader) u16() (uint16, error) {
	if len(r.b) < 2 {
		return 0, ErrShort
	}
	v := binary.BigEndian.Uint16(r.b[:2])
	r.b = r.b[2:]
	return v, nil
}

func (r *reader) str() (string, error) {
	n, err := r.u16()
	if err != nil {
		return "", err
	}
	if len(r.b) < int(n) {
		return "", ErrShort
	}
	s := string(r.b[:n])
	r.b = r.b[n:]
	return s, nil
}

func (r *reader) rawBytes() ([]byte, error) {
	n, err := r.u16()
	if err != nil {
		return nil, err
	}
	if len(r.b) < int(n) {
		return nil, ErrShort
	}
	v := append([]byte(nil), r.b[:n]...)
	r.b = r.b[n:]
	return v, nil
}

type reader struct {
	b []byte
}

// frame wraps header + variable body.
func encodePacket(pType byte, flags byte, body []byte) []byte {
	out := []byte{(pType << 4) | (flags & 0x0f)}
	out = append(out, encodeVarInt(len(body))...)
	out = append(out, body...)
	return out
}

// ---------- property encoding (MQTT5) ----------

const (
	propPayloadFormat   = 0x01
	propMessageExpiry   = 0x02
	propContentType     = 0x03
	propResponseTopic   = 0x08
	propCorrelationData = 0x09
	propSubscriptionID  = 0x0B
	propSessionExpiry   = 0x11
	propWillDelay       = 0x18
	propTopicAlias      = 0x23
	propReceiveMaximum  = 0x21
	propMaxPacketSize   = 0x27
	propTopicAliasMax   = 0x22
	propRequestRespInfo = 0x19
	propRequestProblem  = 0x17
	propUserProperty    = 0x26
)

func encVarIntProp(id byte, v int) []byte {
	out := []byte{id}
	return append(out, encodeVarInt(v)...)
}

func encU16Prop(id byte, v uint16) []byte {
	out := []byte{id, 0, 0}
	binary.BigEndian.PutUint16(out[1:], v)
	return out
}

func encU32Prop(id byte, v uint32) []byte {
	out := []byte{id, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], v)
	return out
}

func encByteProp(id byte, v byte) []byte { return []byte{id, v} }

func encStrProp(id byte, s string) []byte {
	out := []byte{id}
	out = append(out, encString(s)...)
	return out
}

func encBinProp(id byte, v []byte) []byte {
	out := []byte{id}
	out = append(out, encBytes(v)...)
	return out
}

func encodeProperties(p *Properties) []byte {
	if p == nil {
		return []byte{0}
	}
	var body []byte
	if p.PayloadFormat != 0 {
		body = append(body, encByteProp(propPayloadFormat, p.PayloadFormat)...)
	}
	if p.MessageExpiry != 0 {
		body = append(body, encU32Prop(propMessageExpiry, p.MessageExpiry)...)
	}
	if p.ContentType != "" {
		body = append(body, encStrProp(propContentType, p.ContentType)...)
	}
	if p.ResponseTopic != "" {
		body = append(body, encStrProp(propResponseTopic, p.ResponseTopic)...)
	}
	if p.CorrelationData != nil {
		body = append(body, encBinProp(propCorrelationData, p.CorrelationData)...)
	}
	for _, sid := range p.SubscriptionID {
		body = append(body, encVarIntProp(propSubscriptionID, sid)...)
	}
	if p.SessionExpiry != 0 {
		body = append(body, encU32Prop(propSessionExpiry, p.SessionExpiry)...)
	}
	if p.WillDelay != 0 {
		body = append(body, encU32Prop(propWillDelay, p.WillDelay)...)
	}
	if p.ReceiveMaximum != 0 {
		body = append(body, encU16Prop(propReceiveMaximum, p.ReceiveMaximum)...)
	}
	if p.MaxPacketSize != 0 {
		body = append(body, encU32Prop(propMaxPacketSize, p.MaxPacketSize)...)
	}
	if p.TopicAliasMax != 0 {
		body = append(body, encU16Prop(propTopicAliasMax, p.TopicAliasMax)...)
	}
	if p.RequestRespInfo != 0 {
		body = append(body, encByteProp(propRequestRespInfo, p.RequestRespInfo)...)
	}
	if p.RequestProblem != 0 {
		body = append(body, encByteProp(propRequestProblem, p.RequestProblem)...)
	}
	if p.TopicAlias != 0 {
		body = append(body, encU16Prop(propTopicAlias, p.TopicAlias)...)
	}
	for _, kv := range p.UserProperty {
		body = append(body, propUserProperty)
		body = append(body, encString(kv[0])...)
		body = append(body, encString(kv[1])...)
	}
	return append(encodeVarInt(len(body)), body...)
}

// ---------- property decoding (MQTT5) ----------

// propSizes: 0=byte,1=u16,2=u32,3=varint,4=string,5=binary
var propSizes = map[byte]int{
	0x01: 0, 0x02: 2, 0x03: 4, 0x08: 4, 0x09: 5, 0x0B: 3,
	0x11: 2, 0x18: 2, 0x21: 1, 0x27: 2, 0x22: 1, 0x19: 0,
	0x17: 0, 0x23: 1, 0x26: 4, 0x24: 4, 0x25: 0, 0x28: 0,
	0x2A: 0, 0x12: 0, 0x1A: 4, 0x1C: 4, 0x1F: 4,
}

func decodeProperties(b []byte) (*Properties, []byte, []Diagnostic) {
	ln, used, err := decodeVarInt(b)
	var diags []Diagnostic
	if err != nil {
		diags = append(diags, Diagnostic{Code: "PROP_LENGTH_BAD", Message: err.Error()})
		return nil, b, diags
	}
	b = b[used:]
	if len(b) < ln {
		diags = append(diags, Diagnostic{Code: "PROP_TRUNCATED", Message: fmt.Sprintf("declared %d property bytes, have %d", ln, len(b))})
		return nil, b, diags
	}
	rest := b[ln:]
	pb := b[:ln]
	p := &Properties{}
	for len(pb) > 0 {
		id := pb[0]
		pb = pb[1:]
		size, known := propSizes[id]
		if !known {
			diags = append(diags, Diagnostic{Code: "PROP_UNKNOWN_ID", Message: fmt.Sprintf("property id 0x%02x", id)})
			return p, rest, diags
		}
		readU := func(w int) (uint64, bool) {
			if len(pb) < w {
				return 0, false
			}
			var v uint64
			for _, x := range pb[:w] {
				v = v<<8 | uint64(x)
			}
			pb = pb[w:]
			return v, true
		}
		switch size {
		case 0:
			if len(pb) < 1 {
				diags = append(diags, Diagnostic{Code: "PROP_SHORT", Message: "byte property"})
				return p, rest, diags
			}
			v := pb[0]
			pb = pb[1:]
			switch id {
			case 0x01:
				p.PayloadFormat = v
			case 0x19:
				p.RequestRespInfo = v
			case 0x17:
				p.RequestProblem = v
			}
		case 1:
			v, ok := readU(2)
			if !ok {
				break
			}
			switch id {
			case 0x21:
				p.ReceiveMaximum = uint16(v)
			case 0x22:
				p.TopicAliasMax = uint16(v)
			case 0x23:
				p.TopicAlias = uint16(v)
			}
		case 2:
			v, ok := readU(4)
			if !ok {
				break
			}
			switch id {
			case 0x02:
				p.MessageExpiry = uint32(v)
			case 0x11:
				p.SessionExpiry = uint32(v)
			case 0x18:
				p.WillDelay = uint32(v)
			case 0x27:
				p.MaxPacketSize = uint32(v)
			}
		case 3:
			val, n, err := decodeVarInt(pb)
			if err != nil {
				diags = append(diags, Diagnostic{Code: "PROP_VARINT", Message: err.Error()})
				return p, rest, diags
			}
			pb = pb[n:]
			if id == 0x0B {
				p.SubscriptionID = append(p.SubscriptionID, val)
			}
		case 4:
			rr := &reader{b: pb}
			s, err := rr.str()
			pb = rr.b
			if err != nil {
				diags = append(diags, Diagnostic{Code: "PROP_STRING", Message: err.Error()})
				return p, rest, diags
			}
			switch id {
			case 0x03:
				p.ContentType = s
			case 0x08:
				p.ResponseTopic = s
			case 0x26:
				// user property: key followed by value
				rr2 := &reader{b: pb}
				v2, err2 := rr2.str()
				pb = rr2.b
				if err2 != nil {
					diags = append(diags, Diagnostic{Code: "PROP_USERPROP", Message: err2.Error()})
					return p, rest, diags
				}
				p.UserProperty = append(p.UserProperty, [2]string{s, v2})
			}
		case 5:
			rr := &reader{b: pb}
			v, err := rr.rawBytes()
			pb = rr.b
			if err != nil {
				diags = append(diags, Diagnostic{Code: "PROP_BINARY", Message: err.Error()})
				return p, rest, diags
			}
			p.CorrelationData = v
		}
	}
	return p, rest, diags
}
