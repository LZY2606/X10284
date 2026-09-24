package mqtt

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ParsePacket decodes the MQTT 5 fields we depend on from RawHex. The raw
// bytes are always kept untouched; decoding only fills derived fields. Values
// that cannot be decoded stay empty and a diagnostic is attached instead of
// being silently dropped.
func ParsePacket(p *Packet) {
	raw, err := hex.DecodeString(strings.ReplaceAll(p.RawHex, " ", ""))
	if err != nil || len(raw) < 2 {
		p.Diag = joinDiag(p.Diag, "raw bytes not decodable as mqtt fixed header")
		return
	}
	b1 := raw[0]
	ptype := b1 >> 4
	flags := b1 & 0x0f
	body, _, err := readRemaining(raw[1:])
	if err != nil {
		p.Diag = joinDiag(p.Diag, "remaining length varint invalid")
		return
	}
	p.SessionExpS = -1
	switch ptype {
	case 1: // CONNECT
		p.Type = "CONNECT"
		parseConnect(p, body)
	case 2:
		p.Type = "CONNACK"
		if len(body) >= 1 {
			p.PayloadHex = hex.EncodeToString(body)
		}
	case 3: // PUBLISH
		p.Type = "PUBLISH"
		p.DUP = flags&0x08 != 0
		p.QoS = int((flags >> 1) & 0x03)
		p.Retain = flags&0x01 != 0
		parsePublish(p, body)
	case 4:
		p.Type = "PUBACK"
		parseAck(p, body)
	case 5:
		p.Type = "PUBREC"
		parseAck(p, body)
	case 6:
		p.Type = "PUBREL"
		parseAck(p, body)
	case 7:
		p.Type = "PUBCOMP"
		parseAck(p, body)
	case 8:
		p.Type = "SUBSCRIBE"
		parseSubscribe(p, body)
	case 9:
		p.Type = "SUBACK"
		parseAck(p, body)
	case 10:
		p.Type = "UNSUBSCRIBE"
		parseSubscribe(p, body) // same wire shape for our purposes
	case 11:
		p.Type = "UNSUBACK"
		parseAck(p, body)
	case 14:
		p.Type = "DISCONNECT"
		parseDisconnect(p, body)
	default:
		p.Type = fmt.Sprintf("TYPE_%d", ptype)
		p.Diag = joinDiag(p.Diag, "unsupported packet type in minimal codec")
	}
}

func joinDiag(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func readRemaining(b []byte) ([]byte, int, error) {
	mult, val, n := 1, 0, 0
	for {
		if n >= len(b) || n > 3 {
			return nil, 0, fmt.Errorf("bad varint")
		}
		d := b[n]
		n++
		val += int(d&0x7f) * mult
		if d&0x80 == 0 {
			break
		}
		mult *= 128
	}
	if val > len(b)-n {
		return nil, 0, fmt.Errorf("remaining length %d exceeds buffer", val)
	}
	return b[n : n+val], n + val, nil
}

func readUTF(b []byte, i int) (string, int, error) {
	if i+2 > len(b) {
		return "", i, fmt.Errorf("utf length truncated")
	}
	l := int(b[i])<<8 | int(b[i+1])
	i += 2
	if i+l > len(b) {
		return "", i, fmt.Errorf("utf payload truncated")
	}
	return string(b[i : i+l]), i + l, nil
}

// readProps scans MQTT5 properties; we only interpret session-expiry (0x11)
// and topic-alias (0x23). Unknown property ids abort scanning with a
// diagnostic instead of guessing lengths.
func readProps(p *Packet, b []byte, i int) int {
	if i >= len(b) {
		return i
	}
	plen := int(b[i])
	i++
	end := i + plen
	if end > len(b) {
		p.Diag = joinDiag(p.Diag, "properties length exceeds packet")
		return len(b)
	}
	for i < end {
		id := b[i]
		i++
		switch id {
		case 0x11: // Session Expiry Interval, 4 bytes
			if i+4 > end {
				p.Diag = joinDiag(p.Diag, "session expiry property truncated")
				return end
			}
			v := int64(b[i])<<24 | int64(b[i+1])<<16 | int64(b[i+2])<<8 | int64(b[i+3])
			i += 4
			p.SessionExpS = v
			p.SessionExpRaw = fmt.Sprintf("%ds", v)
		case 0x23: // Topic Alias, 2 bytes
			if i+2 > end {
				p.Diag = joinDiag(p.Diag, "topic alias property truncated")
				return end
			}
			p.TopicAlias = int(b[i])<<8 | int(b[i+1])
			i += 2
		default:
			p.Diag = joinDiag(p.Diag, fmt.Sprintf("unknown property 0x%02x: rest of properties left unparsed", id))
			return end
		}
	}
	return end
}

func parseConnect(p *Packet, b []byte) {
	i := 0
	proto, ni, err := readUTF(b, i)
	if err != nil || proto != "MQTT" {
		p.Diag = joinDiag(p.Diag, "connect protocol name unreadable")
		return
	}
	i = ni
	if i+4 > len(b) {
		p.Diag = joinDiag(p.Diag, "connect variable header truncated")
		return
	}
	i++ // protocol level
	cflags := b[i]
	i++
	p.CleanStart = cflags&0x02 != 0
	i += 2 // keepalive
	i = readProps(p, b, i)
	if i < len(b) {
		_, _, err := readUTF(b, i) // client id already known from capture metadata
		if err != nil {
			p.Diag = joinDiag(p.Diag, "connect client id unreadable")
		}
	}
}

func parsePublish(p *Packet, b []byte) {
	topic, ni, err := readUTF(b, 0)
	if err != nil {
		p.Diag = joinDiag(p.Diag, "publish topic unreadable")
		return
	}
	p.Topic = topic
	i := ni
	if p.QoS > 0 {
		if i+2 > len(b) {
			p.Diag = joinDiag(p.Diag, "publish packet id truncated")
			return
		}
		p.PacketID = int(b[i])<<8 | int(b[i+1])
		i += 2
	}
	i = readProps(p, b, i)
	if i <= len(b) {
		p.PayloadHex = hex.EncodeToString(b[i:])
	}
}

func parseAck(p *Packet, b []byte) {
	if len(b) >= 2 {
		p.PacketID = int(b[0])<<8 | int(b[1])
	}
}

func parseSubscribe(p *Packet, b []byte) {
	if len(b) < 3 {
		p.Diag = joinDiag(p.Diag, "subscribe truncated")
		return
	}
	p.PacketID = int(b[0])<<8 | int(b[1])
	i := 2
	i = readProps(p, b, i)
	topic, _, err := readUTF(b, i)
	if err != nil {
		p.Diag = joinDiag(p.Diag, "subscribe topic unreadable")
		return
	}
	p.Topic = topic
	if p.Type == "SUBSCRIBE" {
		// last byte of the first filter carries requested qos
		_, ni, _ := readUTF(b, i)
		if ni < len(b) {
			p.QoS = int(b[ni] & 0x03)
		}
	}
}

func parseDisconnect(p *Packet, b []byte) {
	if len(b) == 0 {
		return
	}
	i := 1 // reason code
	readProps(p, b, i)
}
