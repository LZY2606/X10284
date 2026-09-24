// Package fixtures builds the dedicated offline case pack
// "MQTT 会话印迹：QoS 握手、持久状态与重连去重回放". The material is domain
// specific: real MQTT wire bytes, directions, packet ids, DUP/retain flags,
// clean start/session expiry, topic aliases and virtual clocks.
package fixtures

import (
	"encoding/hex"

	"github.com/example/mqtt-session-forensics/internal/model"
	"github.com/example/mqtt-session-forensics/internal/mqtt"
)

func t(orig, unit string) model.TimeRef {
	return model.TimeRef{Original: orig, Unit: unit}
}

type builder struct {
	pkts []model.RawPacket
	seq  int
}

func (b *builder) add(conn, hint string, dir model.Direction, raw []byte, orig, unit string) {
	b.seq++
	b.pkts = append(b.pkts, model.RawPacket{
		ID:           pid(b.seq),
		RawHex:       hex.EncodeToString(raw),
		Direction:    dir,
		ObservedAt:   t(orig, unit),
		ConnectionID: conn,
		ClientIDHint: hint,
		IngestOrder:  b.seq,
	})
}

func pid(n int) string {
	const digits = "0000"
	s := itoa(n)
	return "pkt-" + digits[:len(digits)-len(s)] + s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// Baseline builds the v1 case material. Virtual time is expressed in
// milliseconds ("ms") to prove normalisation happens only in the derivation
// layer; one deliberately bad clock stays in place with a diagnosis.
func Baseline() *model.Bundle {
	b := &builder{}

	// === sensor-a: MQTT5, persistent session, QoS2 interrupted mid-handshake ===
	c1 := "tcp-10.0.0.10:4401"
	b.add(c1, "sensor-a", model.DirC2B, mqtt.Connect(5, "sensor-a", false, 30, 60, true), "1000", "ms")
	b.add(c1, "sensor-a", model.DirB2C, mqtt.Connack(false, 0), "1010", "ms")
	// topic alias mapping: defines alias 7 -> dt/temp
	b.add(c1, "sensor-a", model.DirC2B, mqtt.Publish(false, 1, false, "dt/temp", 100,
		[]byte("21.5"), 5, 7, false), "1100", "ms")
	b.add(c1, "sensor-a", model.DirB2C, mqtt.Puback(100), "1105", "ms")
	// QoS 2 publish packet id 200, reaches PUBREC only
	b.add(c1, "sensor-a", model.DirC2B, mqtt.Publish(false, 2, false, "alarm/door", 200,
		[]byte("open"), 5, 0, false), "1200", "ms")
	b.add(c1, "sensor-a", model.DirB2C, mqtt.Pubrec(200), "1210", "ms")
	// transport disappears mid QoS2
	b.add(c1, "sensor-a", model.DirB2C, mqtt.Disconnect(5, 0x99), "1220", "ms")

	// reconnect on a new connection but same session generation lineage
	c2 := "tcp-10.0.0.10:4402"
	b.add(c2, "sensor-a", model.DirC2B, mqtt.Connect(5, "sensor-a", false, 30, 60, true), "1300", "ms")
	b.add(c2, "sensor-a", model.DirB2C, mqtt.Connack(true, 0), "1310", "ms") // session present
	// broker re-sends PUBREC (duplicate, idempotent); client resumes with PUBREL
	b.add(c2, "sensor-a", model.DirB2C, mqtt.Pubrec(200), "1320", "ms")
	b.add(c2, "sensor-a", model.DirC2B, mqtt.Pubrel(200), "1330", "ms")
	b.add(c2, "sensor-a", model.DirB2C, mqtt.Pubcomp(200), "1340", "ms")
	// DUP retransmission of the opening QoS1 publish AFTER it completed,
	// followed by packet id reuse of 100 for a new QoS1 flow
	b.add(c2, "sensor-a", model.DirC2B, mqtt.Publish(true, 1, false, "dt/temp", 100,
		[]byte("21.5"), 5, 0, false), "1400", "ms")
	b.add(c2, "sensor-a", model.DirB2C, mqtt.Puback(100), "1405", "ms")
	b.add(c2, "sensor-a", model.DirC2B, mqtt.Publish(false, 1, false, "dt/temp", 100,
		[]byte("22.0"), 5, 0, false), "1500", "ms")
	b.add(c2, "sensor-a", model.DirB2C, mqtt.Puback(100), "1505", "ms")
	// alias-only publish after reset: new connection reset aliases at CONNECT,
	// then re-establishes alias 7, then uses it alias-only
	b.add(c2, "sensor-a", model.DirC2B, mqtt.Publish(false, 1, false, "dt/temp", 101,
		[]byte("22.1"), 5, 7, false), "1600", "ms")
	b.add(c2, "sensor-a", model.DirB2C, mqtt.Puback(101), "1605", "ms")
	b.add(c2, "sensor-a", model.DirC2B, mqtt.Publish(false, 1, false, "dt/temp", 102,
		[]byte("22.2"), 5, 7, true), "1610", "ms")
	b.add(c2, "sensor-a", model.DirB2C, mqtt.Puback(102), "1615", "ms")
	// retained store then retained delete (zero payload)
	b.add(c2, "sensor-a", model.DirC2B, mqtt.Publish(false, 1, true, "cfg/mode", 103,
		[]byte("armed"), 5, 0, false), "1700", "ms")
	b.add(c2, "sensor-a", model.DirB2C, mqtt.Puback(103), "1705", "ms")
	b.add(c2, "sensor-a", model.DirC2B, mqtt.Publish(false, 1, true, "cfg/mode", 104,
		[]byte(""), 5, 0, false), "1710", "ms")
	b.add(c2, "sensor-a", model.DirB2C, mqtt.Puback(104), "1715", "ms")
	// subscribe + unsubscribe
	b.add(c2, "sensor-a", model.DirC2B, mqtt.Subscribe(300, map[string]uint8{"cmd/#": 1}), "1800", "ms")
	b.add(c2, "sensor-a", model.DirB2C, mqtt.Suback(300, []byte{1}), "1805", "ms")
	b.add(c2, "sensor-a", model.DirC2B, mqtt.Unsubscribe(301, []string{"cmd/#"}), "1810", "ms")

	// === gateway-b: MQTT3.1.1, session expiry endpoint boundary ===
	c3 := "tcp-10.0.0.20:5101"
	b.add(c3, "gateway-b", model.DirC2B, mqtt.Connect(4, "gateway-b", false, 60, 0, false), "2000", "ms")
	b.add(c3, "gateway-b", model.DirB2C, mqtt.Connack(false, 0), "2010", "ms")
	b.add(c3, "gateway-b", model.DirC2B, mqtt.Publish(false, 1, false, "gw/up", 50,
		[]byte("a"), 4, 0, false), "2100", "ms")
	b.add(c3, "gateway-b", model.DirB2C, mqtt.Puback(50), "2105", "ms")
	b.add(c3, "gateway-b", model.DirC2B, mqtt.Disconnect(4, 0), "2200", "ms")
	// reconnect exactly at the expiry boundary (default expiry parameter = 2s;
	// close 2200ms + 2000ms = 4200ms == reopen 4200ms => ambiguous candidates)
	c4 := "tcp-10.0.0.20:5102"
	b.add(c4, "gateway-b", model.DirC2B, mqtt.Connect(4, "gateway-b", false, 60, 0, false), "4200", "ms")
	b.add(c4, "gateway-b", model.DirB2C, mqtt.Connack(true, 0), "4210", "ms")

	// === device-c: multi-generation packet id reuse / confusion surface ===
	c5 := "tcp-10.0.0.30:6101"
	b.add(c5, "device-c", model.DirC2B, mqtt.Connect(5, "device-c", true, 30, 0, true), "5000", "ms")
	b.add(c5, "device-c", model.DirB2C, mqtt.Connack(false, 0), "5010", "ms")
	// QoS2 publish 900 in a clean-start generation; interrupt without resolution.
	b.add(c5, "device-c", model.DirC2B, mqtt.Publish(false, 2, false, "d/a", 900,
		[]byte("x"), 5, 0, false), "5100", "ms")
	b.add(c5, "device-c", model.DirB2C, mqtt.Disconnect(5, 0x99), "5110", "ms")
	// new clean-start generation reuses packet id 900 for a different topic.
	c6 := "tcp-10.0.0.30:6102"
	b.add(c6, "device-c", model.DirC2B, mqtt.Connect(5, "device-c", true, 30, 0, true), "6000", "ms")
	b.add(c6, "device-c", model.DirB2C, mqtt.Connack(false, 0), "6010", "ms")
	b.add(c6, "device-c", model.DirC2B, mqtt.Publish(false, 2, false, "d/b", 900,
		[]byte("y"), 5, 0, false), "6100", "ms")
	b.add(c6, "device-c", model.DirB2C, mqtt.Pubrec(900), "6105", "ms")
	b.add(c6, "device-c", model.DirC2B, mqtt.Pubrel(900), "6110", "ms")
	b.add(c6, "device-c", model.DirB2C, mqtt.Pubcomp(900), "6115", "ms")

	// One unconvertible clock: original representation is retained and a
	// diagnosis is attached instead of dropping the frame.
	b.add("tcp-10.0.0.20:5102", "gateway-b", model.DirC2B, mqtt.Pingreq(),
		"soon-ish", "bad")

	return &model.Bundle{
		Packets:   b.pkts,
		Snapshots: Snapshots(),
		Params: map[string]model.ParamRecord{
			"mqtt311_session_expiry_seconds": {
				Name: "mqtt311_session_expiry_seconds", Value: "2", Unit: "s",
			},
		},
		CaseTitle: "MQTT 会话印迹：QoS 握手、持久状态与重连去重回放",
	}
}
