package mqttwire

import (
	"errors"
	"fmt"
)

type Direction string

const (
	DirC2S Direction = "c2s"
	DirS2C Direction = "s2c"
)

// Property keeps one decoded MQTT 5.0 property. Unknown properties are
// preserved raw so importing never silently discards wire information.
type Property struct {
	ID    byte   `json:"id"`
	Name  string `json:"name,omitempty"`
	Value any    `json:"value,omitempty"`
	Raw   []byte `json:"raw,omitempty"`
}

type Packet struct {
	Type      byte       `json:"type"`
	TypeName  string     `json:"type_name"`
	Flags     byte       `json:"flags"`
	DUP       bool       `json:"dup"`
	QoS       byte       `json:"qos"`
	Retain    bool       `json:"retain"`
	PacketID  uint16     `json:"packet_id,omitempty"`
	Topic     string     `json:"topic,omitempty"`
	Payload   []byte     `json:"payload,omitempty"`
	Reason    *byte      `json:"reason,omitempty"`
	Props     []Property `json:"props,omitempty"`
	Raw       []byte     `json:"raw"`
	ParseNote string     `json:"parse_note,omitempty"`
}

const (
	TypeCONNECT     = 1
	TypeCONNACK     = 2
	TypePUBLISH     = 3
	TypePUBACK      = 4
	TypePUBREC      = 5
	TypePUBREL      = 6
	TypePUBCOMP     = 7
	TypeSUBSCRIBE   = 8
	TypeSUBACK      = 9
	TypeUNSUBSCRIBE = 10
	TypeUNSUBACK    = 11
	TypePINGREQ     = 12
	TypePINGRESP    = 13
	TypeDISCONNECT  = 14
	TypeAUTH        = 15
)

func typeName(t byte) string {
	names := map[byte]string{
		1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
		6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK",
		10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP",
		14: "DISCONNECT", 15: "AUTH",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return "RESERVED"
}

func Parse(raw []byte) (*Packet, error) {
	if len(raw) < 2 {
		return nil, errors.New("packet shorter than fixed header")
	}
	p := &Packet{
		Type:  raw[0] >> 4,
		Flags: raw[0] & 0x0f,
		Raw:   append([]byte(nil), raw...),
	}
	p.TypeName = typeName(p.Type)
	p.DUP = p.Flags&0x08 != 0
	p.QoS = (p.Flags >> 1) & 0x03
	p.Retain = p.Flags&0x01 != 0

	r := newReader(raw[2:])
	var note error
	switch p.Type {
	case TypeCONNECT:
		note = p.parseConnect(r)
	case TypeCONNACK:
		note = p.parseConnack(r)
	case TypePUBLISH:
		note = p.parsePublish(r)
	case TypePUBACK, TypePUBREC, TypePUBREL, TypePUBCOMP:
		note = p.parseAck(r)
	case TypeSUBSCRIBE:
		note = p.parseSubscribe(r)
	case TypeSUBACK:
		note = p.parseSuback(r)
	case TypeUNSUBSCRIBE:
		note = p.parseUnsubscribe(r)
	case TypeUNSUBACK, TypeDISCONNECT, TypeAUTH:
		note = p.parseReasonProps(r)
	}
	if note != nil {
		p.ParseNote = note.Error()
	}
	return p, nil
}

func (p *Packet) Prop(id byte) (any, bool) {
	for _, pr := range p.Props {
		if pr.ID == id {
			return pr.Value, true
		}
	}
	return nil, false
}

func (p *Packet) UintProp(id byte) (uint64, bool) {
	v, ok := p.Prop(id)
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case uint64:
		return n, true
	case int:
		return uint64(n), true
	}
	return 0, false
}

func (p *Packet) StringProp(id byte) (string, bool) {
	v, ok := p.Prop(id)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func (p *Packet) String() string {
	return fmt.Sprintf("%s flags=%04b qos=%d pid=%d topic=%q note=%q",
		p.TypeName, p.Flags, p.QoS, p.PacketID, p.Topic, p.ParseNote)
}
