package mqttcodec

import (
	"encoding/binary"
	"fmt"
)

// Decode parses exactly one MQTT frame. It returns the frame and the number of
// raw bytes consumed. Malformed variable bodies are reported through
// Frame.Warnings while fixed-header information remains usable.
func Decode(b []byte) (*Frame, int, error) {
	if len(b) < 2 {
		return nil, 0, errShort
	}
	f := &Frame{
		Type:       b[0] >> 4,
		Flags:      b[0] & 0x0f,
		Properties: map[byte][]Byte{},
		UserProps:  map[string][]string{},
	}
	f.DUP = f.Flags&0x08 != 0
	f.QoS = (f.Flags >> 1) & 0x03
	f.Retain = f.Flags&0x01 != 0

	rem, n, err := decodeVarInt(b[1:])
	if err != nil {
		return nil, 0, err
	}
	total := 1 + n + int(rem)
	if len(b) < total {
		return nil, 0, errShort
	}
	f.Raw = append([]byte(nil), b[:total]...)
	f.RemainingLen = int(rem)
	body := b[1+n : total]
	f.VarPayload = []Byte{{B: append([]byte(nil), body...)}}

	if perr := f.parseBody(body); perr != nil {
		f.Warnings = append(f.Warnings, perr.Error())
	}
	return f, total, nil
}

func decodeVarInt(b []byte) (uint32, int, error) {
	var v uint32
	for i := 0; i < 4; i++ {
		if i >= len(b) {
			return 0, 0, errShort
		}
		c := b[i]
		v |= uint32(c&0x7f) << (7 * i)
		if c&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("mqttcodec: malformed variable byte integer")
}

type reader struct {
	b   []byte
	pos int
	err error
}

func (r *reader) u8() byte {
	if r.pos+1 > len(r.b) {
		r.err = errShort
		return 0
	}
	v := r.b[r.pos]
	r.pos++
	return v
}

func (r *reader) u16() uint16 {
	if r.pos+2 > len(r.b) {
		r.err = errShort
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v
}

func (r *reader) u32() uint32 {
	if r.pos+4 > len(r.b) {
		r.err = errShort
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v
}

func (r *reader) bytesN(n int) []byte {
	if r.pos+n > len(r.b) {
		r.err = errShort
		return nil
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v
}

func (r *reader) str() string {
	n := int(r.u16())
	if r.err != nil {
		return ""
	}
	return string(r.bytesN(n))
}

func (r *reader) vbint() uint32 {
	if r.pos >= len(r.b) {
		r.err = errShort
		return 0
	}
	v, n, err := decodeVarInt(r.b[r.pos:])
	if err != nil {
		r.err = err
		return 0
	}
	r.pos += n
	return v
}

func (f *Frame) parseBody(body []byte) error {
	r := &reader{b: body}
	switch f.Type {
	case CONNECT:
		f.parseConnect(r)
	case CONNACK:
		f.parseConnack(r)
	case PUBLISH:
		f.parsePublish(r)
	case PUBACK, PUBREC, PUBREL, PUBCOMP:
		f.parseAck(r)
	case SUBSCRIBE:
		f.parseSubscribe(r)
	case SUBACK:
		f.parseSuback(r)
	case UNSUBSCRIBE:
		f.parseUnsubscribe(r)
	case UNSUBACK:
		f.parseUnsuback(r)
	case DISCONNECT:
		f.parseDisconnect(r)
	case PINGREQ, PINGRESP:
		// no variable header / payload
	case AUTH:
		f.parseAuth(r)
	default:
		return fmt.Errorf("mqttcodec: reserved/unknown control type %d", f.Type)
	}
	return r.err
}

func (f *Frame) parseConnect(r *reader) {
	if name := r.str(); name != "MQTT" {
		r.err = fmt.Errorf("mqttcodec: bad protocol name %q", name)
		return
	}
	f.ProtocolLevel = r.u8()
	flags := r.u8()
	f.CleanStart = flags&0x02 != 0
	f.WillRetain = flags&0x20 != 0
	f.WillQoS = (flags >> 3) & 0x03
	f.KeepAlive = r.u16()

	props := f.readProps(r)
	if v, ok := props[PropSessionExpiryInterval]; ok {
		f.SessionExpiry = binary.BigEndian.Uint32(v[0].B)
	}
	if v, ok := props[PropTopicAliasMaximum]; ok {
		f.TopicAliasMax = binary.BigEndian.Uint16(v[0].B)
	}
	f.ClientID = r.str()
	if flags&0x04 != 0 { // will flag
		willProps := f.readProps(r)
		f.WillTopic = r.str()
		plen := int(r.u16())
		f.WillPayload = r.bytesN(plen)
		_ = willProps
	}
	if flags&0x80 != 0 {
		_ = r.str() // username
	}
	if flags&0x40 != 0 {
		_ = r.bytesN(int(r.u16())) // password
	}
}

func (f *Frame) parseConnack(r *reader) {
	ackFlags := r.u8()
	_ = ackFlags // bit 0: session present
	f.ReasonCode = r.u8()
	props := f.readProps(r)
	if v, ok := props[PropSessionExpiryInterval]; ok {
		f.SessionExpiry = binary.BigEndian.Uint32(v[0].B)
	}
	if v, ok := props[PropTopicAliasMaximum]; ok {
		f.TopicAliasMax = binary.BigEndian.Uint16(v[0].B)
	}
	if v, ok := props[PropAssignedClientID]; ok {
		f.ClientID = string(v[0].B)
	}
}

func (f *Frame) parsePublish(r *reader) {
	f.Topic = r.str()
	if f.QoS > 0 {
		f.PacketID = r.u16()
	}
	f.readProps(r)
}

func (f *Frame) parseAck(r *reader) {
	f.PacketID = r.u16()
	if r.pos < len(r.b) {
		f.ReasonCode = r.u8()
		f.readProps(r)
	}
}

func (f *Frame) parseSubscribe(r *reader) {
	f.PacketID = r.u16()
	f.readProps(r) // subscription identifier may live here
	for r.err == nil && r.pos < len(r.b) {
		filter := r.str()
		opts := r.u8()
		f.SubFilters = append(f.SubFilters, SubFilter{
			Filter:            filter,
			QoS:               opts & 0x03,
			NoLocal:           opts&0x04 != 0,
			RetainAsPublished: opts&0x08 != 0,
			RetainHandling:    (opts >> 4) & 0x03,
		})
	}
	if len(f.SubFilters) == 0 && r.err != nil {
		r.err = errShort
	}
}

func (f *Frame) parseSuback(r *reader) {
	f.PacketID = r.u16()
	f.readProps(r)
	for r.err == nil && r.pos < len(r.b) {
		f.SubAcks = append(f.SubAcks, SubAck{ReasonCode: r.u8()})
	}
}

func (f *Frame) parseUnsubscribe(r *reader) {
	f.PacketID = r.u16()
	f.readProps(r)
	for r.err == nil && r.pos < len(r.b) {
		_ = r.str()
	}
}

func (f *Frame) parseUnsuback(r *reader) {
	f.PacketID = r.u16()
	f.readProps(r)
	for r.err == nil && r.pos < len(r.b) {
		_ = r.u8()
	}
}

func (f *Frame) parseDisconnect(r *reader) {
	if r.pos < len(r.b) {
		f.DisReason = r.u8()
		f.ReasonCode = f.DisReason
		props := f.readProps(r)
		if v, ok := props[PropSessionExpiryInterval]; ok {
			f.SessionExpiry = binary.BigEndian.Uint32(v[0].B)
		}
	}
}

func (f *Frame) parseAuth(r *reader) {
	if r.pos < len(r.b) {
		_ = r.u8()
		f.readProps(r)
	}
}

// readProps consumes a property length plus properties and stores raw value
// spans keyed by property id; user properties are decoded separately.
func (f *Frame) readProps(r *reader) map[byte][]Byte {
	plen := int(r.vbint())
	if r.err != nil || plen == 0 {
		return map[byte][]Byte{}
	}
	end := r.pos + plen
	out := map[byte][]Byte{}
	for r.err == nil && r.pos < end {
		id := r.u8()
		var raw []byte
		switch id {
		case PropPayloadFormat, PropRequestProblemInfo, PropRequestResponseInfo,
			PropMaximumQoS, PropRetainAvailable, PropWildcardSubAvailable,
			PropSubIDAvailable, PropSharedSubAvailable, PropCleanStart:
			raw = r.bytesN(1)
		case PropServerKeepAlive, PropReceiveMaximum, PropTopicAliasMaximum,
			PropTopicAlias:
			raw = r.bytesN(2)
		case PropMessageExpiry, PropSessionExpiryInterval, PropWillDelayInterval,
			PropMaximumPacketSize:
			raw = r.bytesN(4)
		case PropSubscriptionID:
			start := r.pos
			_ = r.vbint()
			raw = r.b[start:r.pos]
		case PropContentType, PropResponseTopic, PropAssignedClientID,
			PropAuthMethod, PropResponseInfo, PropServerReference,
			PropReasonString:
			n := int(r.u16())
			raw = r.bytesN(n)
		case PropCorrelationData, PropAuthData:
			n := int(r.u16())
			raw = r.bytesN(n)
		case PropUserProperty:
			k := r.str()
			v := r.str()
			f.UserProps[k] = append(f.UserProps[k], v)
			continue
		default:
			r.err = fmt.Errorf("mqttcodec: unknown property id %d", id)
			return out
		}
		out[id] = append(out[id], Byte{B: append([]byte(nil), raw...)})
	}
	if r.pos != end && r.err == nil {
		r.err = fmt.Errorf("mqttcodec: property length mismatch")
	}
	f.Properties = mergeProps(f.Properties, out)
	return out
}

func mergeProps(dst, src map[byte][]Byte) map[byte][]Byte {
	for k, v := range src {
		dst[k] = append(dst[k], v...)
	}
	return dst
}
