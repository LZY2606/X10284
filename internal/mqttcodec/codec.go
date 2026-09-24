// Package mqttcodec decodes the MQTT 3.1.1 / 5.0 packet subset used by the
// forensics case pack. Decoding preserves wire flags (DUP, QoS, RETAIN),
// packet identifiers, properties (notably topic alias) and reports problems
// as structured diagnostics instead of failing wholesale: a malformed frame
// is still retained as a fact with its original bytes.
package mqttcodec

import (
	"encoding/binary"
	"errors"
	"fmt"

	"mqttforensics/internal/domain"
)

// Packet types.
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

// Decoded is the field view of one frame plus a confidence diagnostic.
type Decoded struct {
	Type       uint8           `json:"type"`
	TypeName   string          `json:"type_name"`
	DUP        bool            `json:"dup,omitempty"`
	QoS        uint8           `json:"qos,omitempty"`
	RETAIN     bool            `json:"retain,omitempty"`
	PacketID   *uint16         `json:"packet_id,omitempty"`
	Topic      string          `json:"topic,omitempty"`
	Payload    domain.HexBytes `json:"payload,omitempty"`
	Props      map[string]any  `json:"props,omitempty"`
	Level      uint8           `json:"level,omitempty"`
	CleanStart *bool           `json:"clean_start,omitempty"`
	ClientID   string          `json:"client_id,omitempty"`
	Reason     *uint8          `json:"reason_code,omitempty"`
	Subs       []SubFilter     `json:"subs,omitempty"`
	Unsubs     []string        `json:"unsubs,omitempty"`
	KeepAlive  uint16          `json:"keep_alive,omitempty"`
	WillQoS    uint8           `json:"will_qos,omitempty"`
	WillRetain bool            `json:"will_retain,omitempty"`
	Diagnostic string          `json:"diagnostic,omitempty"`
}

// SubFilter is one SUBSCRIBE filter with its max QoS.
type SubFilter struct {
	Filter string `json:"filter"`
	QoS    uint8  `json:"qos"`
}

type reader struct {
	b   []byte
	pos int
}

func (r *reader) u8() (uint8, error) {
	if r.pos >= len(r.b) {
		return 0, errors.New("truncated")
	}
	v := r.b[r.pos]
	r.pos++
	return v, nil
}

func (r *reader) u16() (uint16, error) {
	if r.pos+2 > len(r.b) {
		return 0, errors.New("truncated u16")
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *reader) bytes(n int) ([]byte, error) {
	if r.pos+n > len(r.b) {
		return nil, errors.New("truncated bytes")
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v, nil
}

func (r *reader) string_() (string, error) {
	n, err := r.u16()
	if err != nil {
		return "", err
	}
	b, err := r.bytes(int(n))
	return string(b), err
}

func (r *reader) remaining() []byte { return r.b[r.pos:] }

// Decode parses a complete MQTT frame. A returned error means the frame is
// unusable; Decoded with Diagnostic set means the fields are usable but the
// frame violated a SHOULD/MAY (e.g. alias out of range).
func Decode(b []byte) (*Decoded, error) {
	if len(b) < 2 {
		return nil, errors.New("frame shorter than fixed header")
	}
	r := &reader{b: b}
	first, err := r.u8()
	if err != nil {
		return nil, err
	}
	remLen, n, err := decodeVarInt(b[1:])
	if err != nil {
		return nil, fmt.Errorf("remaining length: %w", err)
	}
	r.pos = 1 + n
	if 1+n+remLen != len(b) {
		return nil, fmt.Errorf("declared length %d does not match frame length %d", remLen, len(b)-1-n)
	}
	body, err := r.bytes(remLen)
	if err != nil {
		return nil, err
	}
	d := &Decoded{Type: first >> 4}
	d.DUP = first&0x08 != 0
	d.QoS = (first >> 1) & 0x03
	d.RETAIN = first&0x01 != 0
	if d.TypeName = typeName(d.Type); d.TypeName == "" {
		return nil, fmt.Errorf("unknown packet type %d", d.Type)
	}
	br := &reader{b: body}
	if derr := decodeBody(d, br); derr != nil {
		d.Diagnostic = derr.Error()
	}
	return d, nil
}

func decodeVarInt(b []byte) (int, int, error) {
	var value, mult, n int
	for {
		if n >= len(b) || n > 3 {
			return 0, 0, errors.New("malformed variable byte integer")
		}
		c := b[n]
		n++
		value += int(c&127) << mult
		if c&128 == 0 {
			return value, n, nil
		}
		mult += 7
	}
}

func decodeBody(d *Decoded, r *reader) error {
	switch d.Type {
	case CONNECT:
		return decodeConnect(d, r)
	case CONNACK:
		return decodeConnack(d, r)
	case PUBLISH:
		return decodePublish(d, r)
	case PUBACK, PUBREC, PUBREL, PUBCOMP:
		pid, err := r.u16()
		if err != nil {
			return err
		}
		d.PacketID = &pid
		if len(r.remaining()) > 0 {
			if rc, err := r.u8(); err == nil {
				d.Reason = &rc
			}
			if len(r.remaining()) > 0 {
				props, perr := decodeProps(r)
				if perr != nil {
					return perr
				}
				d.Props = props
			}
		}
		return nil
	case SUBSCRIBE:
		return decodeSubscribe(d, r)
	case SUBACK:
		return decodeSuback(d, r)
	case UNSUBSCRIBE:
		pid, err := r.u16()
		if err != nil {
			return err
		}
		d.PacketID = &pid
		if len(r.remaining()) > 0 {
			if _, err := decodeProps(r); err != nil {
				return err
			}
			for len(r.remaining()) > 0 {
				f, err := r.string_()
				if err != nil {
					return err
				}
				d.Unsubs = append(d.Unsubs, f)
			}
		}
	case UNSUBACK:
		pid, err := r.u16()
		if err != nil {
			return err
		}
		d.PacketID = &pid
		if len(r.remaining()) > 0 {
			if _, err := decodeProps(r); err != nil {
				return err
			}
		}
	case DISCONNECT:
		if len(r.remaining()) > 0 {
			if rc, err := r.u8(); err == nil {
				d.Reason = &rc
			}
			if len(r.remaining()) > 0 {
				props, perr := decodeProps(r)
				if perr != nil {
					return perr
				}
				d.Props = props
			}
		}
	}
	return nil
}

func decodeConnect(d *Decoded, r *reader) error {
	name, err := r.string_()
	if err != nil {
		return err
	}
	if name != "MQTT" {
		return fmt.Errorf("not an MQTT connect (protocol name %q)", name)
	}
	level, err := r.u8()
	if err != nil {
		return err
	}
	d.Level = level
	flags, err := r.u8()
	if err != nil {
		return err
	}
	cs := flags&0x02 != 0
	d.CleanStart = &cs
	d.WillQoS = (flags >> 3) & 0x03
	d.WillRetain = flags&0x20 != 0
	ka, err := r.u16()
	if err != nil {
		return err
	}
	d.KeepAlive = ka
	if level == 5 {
		props, err := decodeProps(r)
		if err != nil {
			return err
		}
		d.Props = props
		if v, ok := props["session_expiry_interval"]; ok {
			// normalized by caller; kept as raw seconds
			props["session_expiry_interval_raw"] = v
		}
	} else {
		d.Props = map[string]any{"clean_session_v3": cs}
	}
	cid, err := r.string_()
	if err != nil {
		return err
	}
	d.ClientID = cid
	return nil
}

func decodeConnack(d *Decoded, r *reader) error {
	if _, err := r.u8(); err != nil { // ack flags
		return err
	}
	rc, err := r.u8()
	if err != nil {
		return err
	}
	d.Reason = &rc
	if d.Level == 0 && len(r.remaining()) >= 1 {
		d.Level = 5
	}
	if len(r.remaining()) > 0 {
		props, perr := decodeProps(r)
		if perr != nil {
			return perr
		}
		d.Props = props
	}
	return nil
}

func decodePublish(d *Decoded, r *reader) error {
	topic, err := r.string_()
	if err != nil {
		return err
	}
	d.Topic = topic
	if d.QoS > 0 {
		pid, err := r.u16()
		if err != nil {
			return err
		}
		d.PacketID = &pid
	}
	if len(r.remaining()) > 0 {
		props, perr := decodeProps(r)
		if perr != nil {
			return perr
		}
		d.Props = props
	}
	d.Payload = append(domain.HexBytes(nil), r.remaining()...)
	return nil
}

func decodeSubscribe(d *Decoded, r *reader) error {
	pid, err := r.u16()
	if err != nil {
		return err
	}
	d.PacketID = &pid
	if len(r.remaining()) > 0 {
		if _, err := decodeProps(r); err != nil {
			return err
		}
		for len(r.remaining()) > 0 {
			f, err := r.string_()
			if err != nil {
				return err
			}
			opts, err := r.u8()
			if err != nil {
				return err
			}
			dsub := false
			if len(r.remaining()) > 0 && r.remaining()[0] == 0x00 {
				// subscription identifier / user props would precede; skip one
				// properties-length byte of 0 only.
			}
			_ = dsub
			d.Subs = append(d.Subs, SubFilter{Filter: f, QoS: opts & 0x03})
		}
	}
	return nil
}

func decodeSuback(d *Decoded, r *reader) error {
	pid, err := r.u16()
	if err != nil {
		return err
	}
	d.PacketID = &pid
	if len(r.remaining()) > 0 {
		if _, err := decodeProps(r); err != nil {
			return err
		}
	}
	return nil
}

func decodeProps(r *reader) (map[string]any, error) {
	l, n, err := decodeVarInt(r.b[r.pos:])
	if err != nil {
		return nil, fmt.Errorf("properties length: %w", err)
	}
	r.pos += n
	end := r.pos + l
	props := map[string]any{}
	for r.pos < end {
		id, err := r.u8()
		if err != nil {
			return nil, err
		}
		if err := decodeOneProp(id, r, props); err != nil {
			return nil, err
		}
	}
	return props, nil
}

func decodeOneProp(id uint8, r *reader, props map[string]any) error {
	put := func(k string, v any) { props[k] = v }
	switch id {
	case 0x11: // session expiry interval (u32 seconds)
		if r.pos+4 > len(r.b) {
			return errors.New("truncated session expiry")
		}
		v := binary.BigEndian.Uint32(r.b[r.pos:])
		r.pos += 4
		put("session_expiry_interval", float64(v))
	case 0x23: // topic alias (u16)
		v, err := r.u16()
		if err != nil {
			return err
		}
		put("topic_alias", float64(v))
	case 0x22: // topic alias maximum (u16)
		v, err := r.u16()
		if err != nil {
			return err
		}
		put("topic_alias_maximum", float64(v))
	case 0x26: // user property
		k, err := r.string_()
		if err != nil {
			return err
		}
		v, err := r.string_()
		if err != nil {
			return err
		}
		put("user:"+k, v)
	case 0x1F: // reason string
		s, err := r.string_()
		if err != nil {
			return err
		}
		put("reason_string", s)
	case 0x21: // receive maximum
		v, err := r.u16()
		if err != nil {
			return err
		}
		put("receive_maximum", float64(v))
	case 0x01:
		b, err := r.u8()
		if err != nil {
			return err
		}
		put("payload_format_indicator", float64(b))
	case 0x02:
		v, err := r.u32()
		if err != nil {
			return err
		}
		put("message_expiry_interval", float64(v))
	case 0x09, 0x0B, 0x2A: // correlation data / subscription id / wildcard avail
		return errors.New("unsupported property id in case pack")
	default:
		return fmt.Errorf("unknown property id 0x%02x", id)
	}
	return nil
}

func typeName(t uint8) string {
	names := map[uint8]string{
		1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
		5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE",
		9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK",
		12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT",
	}
	return names[t]
}
