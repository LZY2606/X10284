package mqttwire

import "errors"

type reader struct {
	b   []byte
	pos int
}

func newReader(b []byte) *reader { return &reader{b: b} }

func (r *reader) remaining() int { return len(r.b) - r.pos }

func (r *reader) byte() (byte, error) {
	if r.pos >= len(r.b) {
		return 0, errors.New("truncated: expected byte")
	}
	v := r.b[r.pos]
	r.pos++
	return v, nil
}

func (r *reader) u16() (uint16, error) {
	if r.pos+2 > len(r.b) {
		return 0, errors.New("truncated: expected uint16")
	}
	v := uint16(r.b[r.pos])<<8 | uint16(r.b[r.pos+1])
	r.pos += 2
	return v, nil
}

func (r *reader) u32() (uint32, error) {
	if r.pos+4 > len(r.b) {
		return 0, errors.New("truncated: expected uint32")
	}
	v := uint32(r.b[r.pos])<<24 | uint32(r.b[r.pos+1])<<16 |
		uint32(r.b[r.pos+2])<<8 | uint32(r.b[r.pos+3])
	r.pos += 4
	return v, nil
}

func (r *reader) bytes(n int) ([]byte, error) {
	if r.pos+n > len(r.b) {
		return nil, errors.New("truncated: expected bytes")
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v, nil
}

func (r *reader) s() (string, error) {
	n, err := r.u16()
	if err != nil {
		return "", err
	}
	b, err := r.bytes(int(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (r *reader) varInt() (int, error) {
	value, used, err := DecodeVarInt(r.b[r.pos:])
	if err != nil {
		return 0, err
	}
	r.pos += used
	return value, nil
}

// DecodeVarInt decodes an MQTT variable byte integer.
func DecodeVarInt(b []byte) (value int, used int, err error) {
	mult := 1
	for i := 0; i < 4 && i < len(b); i++ {
		value += int(b[i]&0x7f) * mult
		used = i + 1
		if b[i]&0x80 == 0 {
			return value, used, nil
		}
		mult *= 128
	}
	return 0, 0, errors.New("malformed variable byte integer")
}

// propKind classifies MQTT 5.0 property wire encodings.
type propKind int

const (
	pkByte propKind = iota
	pkU16
	pkU32
	pkVBI
	pkString
	pkBinary
	pkStringPair
)

var propTable = map[byte]struct {
	name string
	kind propKind
}{
	1:  {"PayloadFormatIndicator", pkByte},
	2:  {"MessageExpiryInterval", pkU32},
	3:  {"ContentType", pkString},
	8:  {"ResponseTopic", pkString},
	9:  {"CorrelationData", pkBinary},
	11: {"SubscriptionIdentifier", pkVBI},
	17: {"SessionExpiryInterval", pkU32},
	18: {"AssignedClientIdentifier", pkString},
	19: {"ServerKeepAlive", pkU16},
	21: {"AuthenticationMethod", pkString},
	22: {"AuthenticationData", pkBinary},
	23: {"RequestProblemInformation", pkByte},
	24: {"WillDelayInterval", pkU32},
	25: {"RequestResponseInformation", pkByte},
	26: {"ResponseInformation", pkString},
	28: {"ServerReference", pkString},
	31: {"ReasonString", pkString},
	33: {"ReceiveMaximum", pkU16},
	34: {"TopicAliasMaximum", pkU16},
	35: {"TopicAlias", pkU16},
	36: {"MaximumQoS", pkByte},
	37: {"RetainAvailable", pkByte},
	38: {"UserProperty", pkStringPair},
	39: {"MaximumPacketSize", pkU32},
	40: {"WildcardSubscriptionAvailable", pkByte},
	41: {"SubscriptionIdentifiersAvailable", pkByte},
	42: {"SharedSubscriptionAvailable", pkByte},
}

func readProps(r *reader) ([]Property, error) {
	if r.remaining() == 0 {
		return nil, errors.New("missing property length")
	}
	plen, err := r.varInt()
	if err != nil {
		return nil, err
	}
	if r.remaining() < plen {
		return nil, errors.New("truncated: property section")
	}
	end := r.pos + plen
	var out []Property
	for r.pos < end {
		id, err := r.byte()
		if err != nil {
			return nil, err
		}
		spec, known := propTable[id]
		pr := Property{ID: id, Name: spec.name}
		if !known {
			raw := r.b[r.pos:end]
			pr.Raw = append([]byte(nil), raw...)
			out = append(out, pr)
			r.pos = end
			break
		}
		switch spec.kind {
		case pkByte:
			v, err := r.byte()
			if err != nil {
				return nil, err
			}
			pr.Value = v
		case pkU16:
			v, err := r.u16()
			if err != nil {
				return nil, err
			}
			pr.Value = v
		case pkU32:
			v, err := r.u32()
			if err != nil {
				return nil, err
			}
			pr.Value = v
		case pkVBI:
			v, err := r.varInt()
			if err != nil {
				return nil, err
			}
			pr.Value = v
		case pkString:
			v, err := r.s()
			if err != nil {
				return nil, err
			}
			pr.Value = v
		case pkBinary:
			if r.pos+2 > end {
				return nil, errors.New("truncated: binary property")
			}
			n, err := r.u16()
			if err != nil {
				return nil, err
			}
			v, err := r.bytes(int(n))
			if err != nil {
				return nil, err
			}
			pr.Value = v
		case pkStringPair:
			k, err := r.s()
			if err != nil {
				return nil, err
			}
			v, err := r.s()
			if err != nil {
				return nil, err
			}
			pr.Value = [2]string{k, v}
		}
		out = append(out, pr)
	}
	return out, nil
}
