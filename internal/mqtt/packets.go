package mqtt

import (
	"encoding/binary"
)

// Encode serialises a packet. It supports the fields the forensic domain needs
// across protocol levels 4 (3.1.1) and 5 (5.0).
func Encode(p *Packet) []byte {
	switch p.Type {
	case CONNECT:
		return encodeConnect(p)
	case CONNACK:
		return encodeConnack(p)
	case PUBLISH:
		return encodePublish(p)
	case PUBACK, PUBREC, PUBCOMP:
		flags := byte(0)
		return encodeAck(p, flags)
	case PUBREL:
		return encodeAck(p, 0x02)
	case SUBSCRIBE:
		return encodeSubscribe(p)
	case SUBACK:
		return encodeSuback(p)
	case UNSUBSCRIBE:
		return encodeUnsubscribe(p)
	case UNSUBACK:
		return encodeUnsuback(p)
	case PINGREQ, PINGRESP:
		return encodePacket(byte(p.Type), 0, nil)
	case DISCONNECT, AUTH:
		return encodeDisconnect(p)
	}
	return nil
}

func encodeConnect(p *Packet) []byte {
	var body []byte
	if p.Protocol == 5 {
		body = append(body, encString("MQTT")...)
		body = append(body, 5)
	} else {
		body = append(body, encString("MQTT")...)
		body = append(body, 4)
	}
	var flags byte
	if p.CleanStart || p.CleanSession311 {
		flags |= 0x02
	}
	if p.WillTopic != "" {
		flags |= 0x04
		flags |= (p.WillQoS & 0x03) << 3
		if p.WillRetain {
			flags |= 0x20
		}
	}
	if p.Username != "" {
		flags |= 0x80
	}
	if p.Password != nil {
		flags |= 0x40
	}
	body = append(body, flags)
	var ka [2]byte
	binary.BigEndian.PutUint16(ka[:], p.KeepAlive)
	body = append(body, ka[:]...)
	if p.Protocol == 5 {
		body = append(body, encodeProperties(p.Props)...)
	}
	body = append(body, encString(p.ClientID)...)
	if p.WillTopic != "" {
		if p.Protocol == 5 {
			body = append(body, encodeProperties(nil)...)
		}
		body = append(body, encString(p.WillTopic)...)
		body = append(body, encBytes(p.WillPayload)...)
	}
	if p.Username != "" {
		body = append(body, encString(p.Username)...)
	}
	if p.Password != nil {
		body = append(body, encBytes(p.Password)...)
	}
	return encodePacket(1, 0, body)
}

func encodeConnack(p *Packet) []byte {
	var body []byte
	if p.SessionPresent {
		body = append(body, 1)
	} else {
		body = append(body, 0)
	}
	body = append(body, p.ReturnCode)
	if p.Protocol == 5 {
		body = append(body, encodeProperties(p.Props)...)
	}
	return encodePacket(2, 0, body)
}

func encodePublish(p *Packet) []byte {
	flags := byte(0)
	if p.DUP {
		flags |= 0x08
	}
	flags |= (p.QoS & 0x03) << 1
	if p.Retain {
		flags |= 0x01
	}
	var body []byte
	body = append(body, encString(p.Topic)...)
	if p.QoS > 0 {
		var id [2]byte
		binary.BigEndian.PutUint16(id[:], p.PacketID)
		body = append(body, id[:]...)
	}
	if p.Protocol == 5 {
		body = append(body, encodeProperties(p.Props)...)
	}
	body = append(body, p.Payload...)
	return encodePacket(3, flags, body)
}

func encodeAck(p *Packet, flags byte) []byte {
	var body [2]byte
	binary.BigEndian.PutUint16(body[:], p.PacketID)
	out := encodePacket(byte(p.Type), flags, body[:])
	if p.Protocol == 5 {
		rest := []byte{p.Reason}
		rest = append(rest, encodeProperties(p.AckProps)...)
		out = append(out[:len(out)], rest...)
		// rebuild with corrected remaining length
		hdr := out[:1]
		body2 := make([]byte, 2+len(rest))
		binary.BigEndian.PutUint16(body2, p.PacketID)
		copy(body2[2:], rest)
		out = append([]byte{}, hdr...)
		out = append(out, encodeVarInt(len(body2))...)
		out = append(out, body2...)
	}
	return out
}

func encodeSubscribe(p *Packet) []byte {
	var body [2]byte
	binary.BigEndian.PutUint16(body[:], p.PacketID)
	out := body[:]
	if p.Protocol == 5 {
		out = append(out, encodeProperties(p.Props)...)
	}
	for _, f := range p.Filters {
		out = append(out, encString(f.Topic)...)
		opt := f.QoS & 0x03
		if f.NoLocal {
			opt |= 0x04
		}
		if f.RetainAsPublished {
			opt |= 0x08
		}
		opt |= (f.RetainHandling & 0x03) << 4
		out = append(out, opt)
	}
	return encodePacket(8, 0x02, out)
}

func encodeSuback(p *Packet) []byte {
	var body [2]byte
	binary.BigEndian.PutUint16(body[:], p.PacketID)
	out := body[:]
	if p.Protocol == 5 {
		out = append(out, encodeProperties(p.Props)...)
	}
	out = append(out, p.Granted...)
	return encodePacket(9, 0, out)
}

func encodeUnsubscribe(p *Packet) []byte {
	var body [2]byte
	binary.BigEndian.PutUint16(body[:], p.PacketID)
	out := body[:]
	if p.Protocol == 5 {
		out = append(out, encodeProperties(nil)...)
	}
	for _, f := range p.Filters {
		out = append(out, encString(f.Topic)...)
	}
	return encodePacket(10, 0x02, out)
}

func encodeUnsuback(p *Packet) []byte {
	var body [2]byte
	binary.BigEndian.PutUint16(body[:], p.PacketID)
	out := body[:]
	if p.Protocol == 5 {
		out = append(out, encodeProperties(nil)...)
		out = append(out, p.Granted...)
	}
	return encodePacket(11, 0, out)
}

func encodeDisconnect(p *Packet) []byte {
	if p.Protocol != 5 {
		return encodePacket(14, 0, nil)
	}
	body := []byte{p.Reason}
	body = append(body, encodeProperties(p.Props)...)
	return encodePacket(14, 0, body)
}
