// Package codec encodes and decodes the subset of MQTT 3.1.1 / 5.0 packets
// used by the offline capture fixtures. Raw bytes are always authoritative;
// decoding is a best-effort view and reports diagnostics instead of failing
// the import.
package codec

import (
	"encoding/binary"
	"errors"
	"fmt"

	"mqtttrace/internal/domain"
)

const (
	CONNECT     = 1
	CONNACK     = 2
	PUBLISH     = 3
	PUBACK      = 4
	PUBREC      = 5
	PUBREL      = 6
	PUBCOMP     = 7
	SUBSCRIBE   = 8
	SUBACK      = 9
	UNSUBSCRIBE = 10
	UNSUBACK    = 11
	PINGREQ     = 12
	PINGRESP    = 13
	DISCONNECT  = 14
)

var typeName = map[int]string{
	CONNECT: domain.PKCONNECT, CONNACK: domain.PKCONNACK, PUBLISH: domain.PKPUBLISH,
	PUBACK: domain.PKPUBACK, PUBREC: domain.PKPUBREC, PUBREL: domain.PKPUBREL,
	PUBCOMP: domain.PKPUBCOMP, SUBSCRIBE: domain.PKSUBSCRIBE, SUBACK: domain.PKSUBACK,
	UNSUBSCRIBE: domain.PKUNSUBSCRIBE, UNSUBACK: domain.PKUNSUBACK,
	PINGREQ: domain.PKPINGREQ, PINGRESP: domain.PKPINGRESP, DISCONNECT: domain.PKDISCONNECT,
}

func TypeName(t int) string { return typeName[t] }

var ErrMalformed = errors.New("malformed mqtt packet")

func encRL(n int) []byte {
	out := []byte{}
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			return out
		}
	}
}

func decRL(b []byte) (int, int, error) {
	mult := 1
	val := 0
	for i := 0; i < 4; i++ {
		if i >= len(b) {
			return 0, 0, ErrMalformed
		}
		val += int(b[i]&0x7f) * mult
		mult *= 128
		if b[i]&0x80 == 0 {
			return val, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("%w: bad remaining length", ErrMalformed)
}

func encString(s string) []byte {
	out := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(out, uint16(len(s)))
	copy(out[2:], s)
	return out
}

func decString(b []byte) (string, []byte, error) {
	if len(b) < 2 {
		return "", nil, ErrMalformed
	}
	n := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) < n {
		return "", nil, ErrMalformed
	}
	return string(b[:n]), b[n:], nil
}

func encVarInt(n int) []byte {
	return encRL(n)
}

func decVarInt(b []byte) (int, []byte, error) {
	v, used, err := decRL(b)
	if err != nil {
		return 0, nil, err
	}
	return v, b[used:], nil
}

// Props is the subset of MQTT 5.0 properties the fixtures use.
type Props struct {
	SessionExpirySec *uint32 `json:",omitempty"`
	TopicAliasMax    *uint16 `json:",omitempty"`
	TopicAlias       *uint16 `json:",omitempty"`
	SubscriptionID   *int    `json:",omitempty"`
	ReasonString     string  `json:",omitempty"`
	ContentType      string  `json:",omitempty"`
}

func (p Props) encode() []byte {
	var b []byte
	if p.SessionExpirySec != nil {
		b = append(b, 0x11)
		var t [4]byte
		binary.BigEndian.PutUint32(t[:], *p.SessionExpirySec)
		b = append(b, t[:]...)
	}
	if p.TopicAliasMax != nil {
		b = append(b, 0x22)
		var t [2]byte
		binary.BigEndian.PutUint16(t[:], *p.TopicAliasMax)
		b = append(b, t[:]...)
	}
	if p.TopicAlias != nil {
		b = append(b, 0x23)
		var t [2]byte
		binary.BigEndian.PutUint16(t[:], *p.TopicAlias)
		b = append(b, t[:]...)
	}
	if p.SubscriptionID != nil {
		b = append(b, 0x0B)
		b = append(b, encVarInt(*p.SubscriptionID)...)
	}
	if p.ReasonString != "" {
		b = append(b, 0x1F)
		b = append(b, encString(p.ReasonString)...)
	}
	if p.ContentType != "" {
		b = append(b, 0x03)
		b = append(b, encString(p.ContentType)...)
	}
	return append(encVarInt(len(b)), b...)
}

func decodeProps(b []byte) (Props, []byte, error) {
	var p Props
	total, rest, err := decVarInt(b)
	if err != nil {
		return p, nil, err
	}
	body, rest := rest[:total], rest[total:]
	for len(body) > 0 {
		id := body[0]
		body = body[1:]
		switch id {
		case 0x11:
			if len(body) < 4 {
				return p, rest, ErrMalformed
			}
			v := binary.BigEndian.Uint32(body)
			p.SessionExpirySec = &v
			body = body[4:]
		case 0x22:
			if len(body) < 2 {
				return p, rest, ErrMalformed
			}
			v := binary.BigEndian.Uint16(body)
			p.TopicAliasMax = &v
			body = body[2:]
		case 0x23:
			if len(body) < 2 {
				return p, rest, ErrMalformed
			}
			v := binary.BigEndian.Uint16(body)
			p.TopicAlias = &v
			body = body[2:]
		case 0x0B:
			v, r2, err := decVarInt(body)
			if err != nil {
				return p, rest, err
			}
			p.SubscriptionID = &v
			body = r2
		case 0x1F:
			s, r2, err := decString(body)
			if err != nil {
				return p, rest, err
			}
			p.ReasonString = s
			body = r2
		case 0x03:
			s, r2, err := decString(body)
			if err != nil {
				return p, rest, err
			}
			p.ContentType = s
			body = r2
		default:
			return p, rest, fmt.Errorf("%w: unsupported property id 0x%02x", ErrMalformed, id)
		}
	}
	return p, rest, nil
}

// Frame is an encodable/decodable packet view.
type Frame struct {
	Type       int
	DUP        bool
	QoS        int
	RETAIN     bool
	Protocol   byte // 4 = MQTT 3.1.1, 5 = MQTT 5 (default 5)
	ClientID   string
	CleanStart bool
	KeepAlive  uint16
	SessionPresent bool
	ReasonCode byte
	Topic      string
	PacketID   uint16
	Alias      uint16
	AliasMax   uint16
	SessionExpirySec uint32
	Payload    []byte
	Filters    []SubFilter
	SubAckQoS  []byte
	PropsExtra Props
	UnsubTopics []string
	HasReason  bool // v5 ack/disconnect carries explicit reason byte
}

// SubFilter is one SUBSCRIBE filter with options.
type SubFilter struct {
	Filter string
	QoS    byte
	SubID  int // encoded in header props
}

func (f Frame) proto() byte {
	if f.Protocol == 0 {
		return 5
	}
	return f.Protocol
}

// Encode produces the on-the-wire bytes.
func Encode(f Frame) ([]byte, error) {
	var vh []byte
	switch f.Type {
	case CONNECT:
		vh = append(vh, encString("MQTT")...)
		vh = append(vh, f.proto())
		flags := byte(0)
		if f.CleanStart {
			flags |= 0x02
		}
		vh = append(vh, flags)
		var ka [2]byte
		binary.BigEndian.PutUint16(ka[:], f.KeepAlive)
		vh = append(vh, ka[:]...)
		if f.proto() == 5 {
			p := f.PropsExtra
			p.SessionExpirySec = nonZeroU32(f.SessionExpirySec, p.SessionExpirySec)
			p.TopicAliasMax = nonZeroU16(f.AliasMax, p.TopicAliasMax)
			vh = append(vh, p.encode()...)
			vh = append(vh, encString(f.ClientID)...)
		} else {
			vh = append(vh, encString(f.ClientID)...)
		}
	case CONNACK:
		vh = append(vh, boolByte(f.SessionPresent), f.ReasonCode)
		if f.proto() == 5 {
			pp := f.PropsExtra
			pp.TopicAliasMax = nonZeroU16(f.AliasMax, pp.TopicAliasMax)
			vh = append(vh, pp.encode()...)
		}
	case PUBLISH:
		vh = append(vh, encString(f.Topic)...)
		if f.QoS > 0 {
			var p [2]byte
			binary.BigEndian.PutUint16(p[:], f.PacketID)
			vh = append(vh, p[:]...)
		}
		if f.proto() == 5 {
			p := f.PropsExtra
			p.TopicAlias = nonZeroU16(f.Alias, p.TopicAlias)
			vh = append(vh, p.encode()...)
		}
		vh = append(vh, f.Payload...)
	case PUBACK, PUBREC, PUBREL, PUBCOMP:
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], f.PacketID)
		vh = append(vh, p[:]...)
		if f.proto() == 5 && (f.HasReason || len(f.PropsExtra.ReasonString) > 0) {
			vh = append(vh, f.ReasonCode)
			vh = append(vh, f.PropsExtra.encode()...)
		}
	case SUBSCRIBE:
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], f.PacketID)
		vh = append(vh, p[:]...)
		pid := f.PropsExtra
		if f.SubID(f.Filters) != 0 {
			id := f.SubID(f.Filters)
			pid.SubscriptionID = &id
		}
		if f.AliasMax > 0 {
			pid.TopicAliasMax = &f.AliasMax
		}
		vh = append(vh, pid.encode()...)
		for _, fl := range f.Filters {
			vh = append(vh, encString(fl.Filter)...)
			vh = append(vh, fl.QoS)
		}
	case SUBACK:
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], f.PacketID)
		vh = append(vh, p[:]...)
		if f.proto() == 5 {
			vh = append(vh, Props{}.encode()...)
		}
		vh = append(vh, f.SubAckQoS...)
	case UNSUBSCRIBE:
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], f.PacketID)
		vh = append(vh, p[:]...)
		vh = append(vh, Props{}.encode()...)
		for _, t := range f.UnsubTopics {
			vh = append(vh, encString(t)...)
		}
	case UNSUBACK:
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], f.PacketID)
		vh = append(vh, p[:]...)
		if f.proto() == 5 {
			vh = append(vh, Props{}.encode()...)
		}
		vh = append(vh, f.SubAckQoS...)
	case DISCONNECT:
		if f.proto() == 5 {
			if f.HasReason || f.SessionExpirySec > 0 {
				vh = append(vh, f.ReasonCode)
				p := f.PropsExtra
				if f.SessionExpirySec > 0 {
					p.SessionExpirySec = &f.SessionExpirySec
				}
				vh = append(vh, p.encode()...)
			}
		}
	case PINGREQ, PINGRESP:
		// empty
	default:
		return nil, fmt.Errorf("unsupported packet type %d", f.Type)
	}
	hdr := byte(f.Type) << 4
	if f.DUP {
		hdr |= 0x08
	}
	hdr |= byte(f.QoS&0x03) << 1
	if f.RETAIN {
		hdr |= 0x01
	}
	out := append([]byte{hdr}, encRL(len(vh))...)
	out = append(out, vh...)
	return out, nil
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}
func nonZeroU32(v uint32, p *uint32) *uint32 {
	if v > 0 {
		return &v
	}
	return p
}
func nonZeroU16(v uint16, p *uint16) *uint16 {
	if v > 0 {
		return &v
	}
	return p
}

func (f Frame) SubID(fs []SubFilter) int {
	for _, fl := range fs {
		if fl.SubID != 0 {
			return fl.SubID
		}
	}
	return 0
}
