// Package casepack ships the offline domain case "MQTT 会话印迹：QoS 握手、
// 持久状态与重连去重回放". An IoT team imports a bidirectional packet
// trace, the client id and a broker session snapshot, and reconstructs
// QoS 1/2 handshakes, subscriptions and retained state. The trace actually
// exercises: packet id reuse, DUP retransmission, QoS 2 mid-disconnect,
// the session-expiry endpoint, topic-alias reset, retained deletion and
// multi-generation confusion.
package casepack

import (
	"fmt"

	"pairwise-gsb/mqttsession/internal/engine"
	"pairwise-gsb/mqttsession/internal/mqtt"
)

// ClientID is the client whose session is reconstructed.
const ClientID = "sensor-042"

// BrokerSnapshot is the broker-side session state imported alongside the
// trace. Times are seconds (session expiry) as declared by the broker.
type BrokerSnapshot struct {
	ClientID        string   `json:"client_id"`
	SessionPresent  bool     `json:"session_present"`
	ExpirySec       int64    `json:"expiry_sec"`
	Subscriptions   []string `json:"subscriptions"`
	InflightQoS2    []int    `json:"inflight_qos2_packet_ids"`
	RetainedTopics  []string `json:"retained_topics"`
	SnapshotClock   string   `json:"snapshot_clock"` // original broker clock text
}

// Snapshot is the broker session snapshot shipped with the case.
func Snapshot() BrokerSnapshot {
	return BrokerSnapshot{
		ClientID:       ClientID,
		SessionPresent: true,
		ExpirySec:      30,
		Subscriptions:  []string{"factory/line1/temp"},
		InflightQoS2:   []int{3},
		RetainedTopics: []string{"factory/line1/status"},
		SnapshotClock:  "broker-clock:2026-09-24T09:15:00+09:00",
	}
}

type builder struct {
	pkts []engine.Packet
	n    int
}

func (b *builder) add(vt int64, clock string, dir mqtt.Direction, raw []byte) {
	b.n++
	b.pkts = append(b.pkts, engine.Packet{
		ID: fmt.Sprintf("pkt-%04d", b.n), Raw: raw, Dir: dir,
		VirtualTime: vt, ClockRaw: clock, Dec: mqtt.Decode(raw),
	})
}

// Trace builds the baseline packet trace. Virtual time is milliseconds from
// capture start; ClockRaw preserves the original wall-clock text of each
// frame (one frame carries an unconvertible clock, kept raw with a
// diagnostic at import).
func Trace() []engine.Packet {
	b := &builder{}
	clk := func(vt int64) string { return fmt.Sprintf("capture+%dms", vt) }

	// --- generation 1, connection 1 ---
	b.add(0, clk(0), mqtt.C2S, mqtt.Encode(mqtt.TypeCONNECT, 0, mqtt.ConnectBody(ClientID, true, 30)))
	b.add(50, clk(50), mqtt.S2C, mqtt.Encode(mqtt.TypeCONNACK, 0, []byte{0x00, 0x00}))
	b.add(100, clk(100), mqtt.C2S, mqtt.Encode(mqtt.TypeSUBSCRIBE, 2, mqtt.SubscribeBody(10, "factory/line1/temp", 1)))
	b.add(110, clk(110), mqtt.S2C, mqtt.Encode(mqtt.TypeSUBACK, 0, mqtt.AckBody(10)))
	// QoS 1 exchange, packet id 1.
	b.add(200, clk(200), mqtt.C2S, mqtt.Encode(mqtt.TypePUBLISH, 0x02, mqtt.PublishBody("factory/line1/temp", 1, 0, []byte("21.5"))))
	b.add(210, clk(210), mqtt.S2C, mqtt.Encode(mqtt.TypePUBACK, 0, mqtt.AckBody(1)))
	// QoS 2 exchange, packet id 2, with a DUP retransmission folded in.
	b.add(300, clk(300), mqtt.C2S, mqtt.Encode(mqtt.TypePUBLISH, 0x04, mqtt.PublishBody("factory/line1/pressure", 2, 0, []byte("101.3"))))
	b.add(310, clk(310), mqtt.S2C, mqtt.Encode(mqtt.TypePUBREC, 0, mqtt.AckBody(2)))
	b.add(320, clk(320), mqtt.C2S, mqtt.Encode(mqtt.TypePUBLISH, 0x0c, mqtt.PublishBody("factory/line1/pressure", 2, 0, []byte("101.3")))) // DUP=1
	b.add(330, clk(330), mqtt.C2S, mqtt.Encode(mqtt.TypePUBREL, 2, mqtt.AckBody(2)))
	b.add(340, clk(340), mqtt.S2C, mqtt.Encode(mqtt.TypePUBCOMP, 0, mqtt.AckBody(2)))
	// Packet id 1 reused after its exchange completed.
	b.add(400, clk(400), mqtt.C2S, mqtt.Encode(mqtt.TypePUBLISH, 0x02, mqtt.PublishBody("factory/line1/temp", 1, 0, []byte("21.7"))))
	b.add(410, clk(410), mqtt.S2C, mqtt.Encode(mqtt.TypePUBACK, 0, mqtt.AckBody(1)))
	// Retained set.
	b.add(500, clk(500), mqtt.C2S, mqtt.Encode(mqtt.TypePUBLISH, 0x01, mqtt.PublishBody("factory/line1/status", 0, 0, []byte("online"))))
	// QoS 2 with topic alias registration; disconnects mid-handshake.
	b.add(600, clk(600), mqtt.C2S, mqtt.Encode(mqtt.TypePUBLISH, 0x04, mqtt.PublishBody("factory/line1/humidity", 3, 1, []byte("45"))))
	b.add(610, clk(610), mqtt.S2C, mqtt.Encode(mqtt.TypePUBREC, 0, mqtt.AckBody(3)))
	// QoS 1 exchange that will be orphaned by the generation boundary.
	b.add(650, clk(650), mqtt.C2S, mqtt.Encode(mqtt.TypePUBLISH, 0x02, mqtt.PublishBody("factory/line1/vibration", 5, 0, []byte("0.4"))))
	b.add(700, clk(700), mqtt.C2S, mqtt.Encode(mqtt.TypeDISCONNECT, 0, nil))

	// --- generation 1, connection 2: session continued (gap 1300ms < 30s) ---
	b.add(2000, clk(2000), mqtt.C2S, mqtt.Encode(mqtt.TypeCONNECT, 0, mqtt.ConnectBody(ClientID, false, 30)))
	b.add(2050, clk(2050), mqtt.S2C, mqtt.Encode(mqtt.TypeCONNACK, 0, []byte{0x01, 0x00})) // session present
	// QoS 2 resume: DUP PUBLISH uses alias 1, but the alias table reset on
	// the new connection -> diagnostic, handshake phase still preserved.
	b.add(2100, clk(2100), mqtt.C2S, mqtt.Encode(mqtt.TypePUBLISH, 0x0c, mqtt.PublishBody("", 3, 1, []byte("45"))))
	b.add(2110, clk(2110), mqtt.C2S, mqtt.Encode(mqtt.TypePUBREL, 2, mqtt.AckBody(3)))
	b.add(2120, clk(2120), mqtt.S2C, mqtt.Encode(mqtt.TypePUBCOMP, 0, mqtt.AckBody(3)))
	// Re-register alias 1, then use it.
	b.add(2200, clk(2200), mqtt.C2S, mqtt.Encode(mqtt.TypePUBLISH, 0x00, mqtt.PublishBody("factory/line1/humidity", 0, 1, []byte("46"))))
	b.add(2300, clk(2300), mqtt.C2S, mqtt.Encode(mqtt.TypePUBLISH, 0x02, mqtt.PublishBody("", 4, 1, []byte("46.2"))))
	b.add(2310, clk(2310), mqtt.S2C, mqtt.Encode(mqtt.TypePUBACK, 0, mqtt.AckBody(4)))
	// Retained delete: zero-payload retained publish.
	b.add(2400, clk(2400), mqtt.C2S, mqtt.Encode(mqtt.TypePUBLISH, 0x01, mqtt.PublishBody("factory/line1/status", 0, 0, nil)))
	b.add(2500, clk(2500), mqtt.C2S, mqtt.Encode(mqtt.TypeDISCONNECT, 0, nil))

	// --- session-expiry endpoint: reconnect exactly at gap == expiry ---
	b.add(32500, clk(32500), mqtt.C2S, mqtt.Encode(mqtt.TypeCONNECT, 0, mqtt.ConnectBody(ClientID, false, 30)))
	b.add(32550, clk(32550), mqtt.S2C, mqtt.Encode(mqtt.TypeCONNACK, 0, []byte{0x00, 0x00})) // no session

	// --- generation 2 ---
	// Packet id 1 again: interpreted only inside gen-2, no cross-generation
	// confusion.
	b.add(32600, clk(32600), mqtt.C2S, mqtt.Encode(mqtt.TypePUBLISH, 0x02, mqtt.PublishBody("factory/line1/temp", 1, 0, []byte("22.0"))))
	b.add(32610, clk(32610), mqtt.S2C, mqtt.Encode(mqtt.TypePUBACK, 0, mqtt.AckBody(1)))
	// Multi-generation confusion: PUBACK for packet id 5, whose exchange was
	// orphaned in gen-1. Ambiguous: two legal candidates kept.
	b.add(32700, clk(32700), mqtt.S2C, mqtt.Encode(mqtt.TypePUBACK, 0, mqtt.AckBody(5)))
	// Subscription change in the new generation.
	b.add(32800, clk(32800), mqtt.C2S, mqtt.Encode(mqtt.TypeUNSUBSCRIBE, 2, mqtt.UnsubscribeBody(11, "factory/line1/temp")))
	b.add(32810, clk(32810), mqtt.S2C, mqtt.Encode(mqtt.TypeUNSUBACK, 0, mqtt.AckBody(11)))
	// Unconvertible frame: truncated remaining length. Kept raw + diagnostic.
	b.add(32900, "clock-unavailable", mqtt.C2S, []byte{0x32, 0x7f, 0x00, 0x05})
	return b.pkts
}
