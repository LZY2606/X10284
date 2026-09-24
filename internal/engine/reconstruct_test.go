package engine_test

import (
	"testing"

	"pairwise-gsb/mqttsession/internal/engine"
	"pairwise-gsb/mqttsession/internal/mqtt"
)

var seq int

func pkt(vt int64, dir mqtt.Direction, raw []byte) engine.Packet {
	seq++
	return engine.Packet{
		ID: "t-" + string(rune('a'+seq-1)), Raw: raw, Dir: dir,
		VirtualTime: vt, ClockRaw: "test-clock", Dec: mqtt.Decode(raw),
	}
}

func resetSeq() { seq = 0 }

func connect(clean bool, expiry int64) []byte {
	return mqtt.Encode(mqtt.TypeCONNECT, 0, mqtt.ConnectBody("c1", clean, expiry))
}

func publish(topic string, id, qos int, dup, retain bool, payload string) []byte {
	flags := qos << 1
	if dup {
		flags |= 0x08
	}
	if retain {
		flags |= 0x01
	}
	pid := id
	if qos == 0 {
		pid = 0
	}
	return mqtt.Encode(mqtt.TypePUBLISH, flags, mqtt.PublishBody(topic, pid, 0, []byte(payload)))
}

func ack(t, id int) []byte { return mqtt.Encode(t, 2, mqtt.AckBody(id)) }

func findExchange(d *engine.Derived, gen string, packetID int) *engine.Exchange {
	for i := range d.Exchanges {
		if d.Exchanges[i].Generation == gen && d.Exchanges[i].PacketID == packetID {
			return &d.Exchanges[i]
		}
	}
	return nil
}

func TestQoS1HandshakeCompletes(t *testing.T) {
	resetSeq()
	d := engine.Reconstruct([]engine.Packet{
		pkt(0, mqtt.C2S, connect(true, 30)),
		pkt(10, mqtt.C2S, publish("a/b", 7, 1, false, false, "x")),
		pkt(20, mqtt.S2C, ack(mqtt.TypePUBACK, 7)),
	}, engine.Params{}, nil)
	x := findExchange(d, "gen-1", 7)
	if x == nil || x.Phase != engine.PhaseComplete {
		t.Fatalf("expected complete QoS1 exchange, got %+v", x)
	}
}

func TestQoS2DupIdempotentPhaseKept(t *testing.T) {
	resetSeq()
	d := engine.Reconstruct([]engine.Packet{
		pkt(0, mqtt.C2S, connect(true, 30)),
		pkt(10, mqtt.C2S, publish("a/b", 3, 2, false, false, "x")),
		pkt(20, mqtt.S2C, ack(mqtt.TypePUBREC, 3)),
		pkt(30, mqtt.C2S, publish("a/b", 3, 2, true, false, "x")), // DUP retransmit
		pkt(40, mqtt.C2S, ack(mqtt.TypePUBREL, 3)),
		pkt(50, mqtt.S2C, ack(mqtt.TypePUBCOMP, 3)),
	}, engine.Params{}, nil)
	x := findExchange(d, "gen-1", 3)
	if x == nil {
		t.Fatal("exchange missing")
	}
	if x.Phase != engine.PhaseComplete {
		t.Fatalf("phase = %s, want complete", x.Phase)
	}
	if len(x.Duplicates) != 1 {
		t.Fatalf("duplicates = %v, want 1 entry", x.Duplicates)
	}
}

func TestQoS2MidDisconnectPhasePreserved(t *testing.T) {
	resetSeq()
	d := engine.Reconstruct([]engine.Packet{
		pkt(0, mqtt.C2S, connect(true, 30)),
		pkt(10, mqtt.C2S, publish("a/b", 3, 2, false, false, "x")),
		pkt(20, mqtt.S2C, ack(mqtt.TypePUBREC, 3)),
		pkt(30, mqtt.C2S, mqtt.Encode(mqtt.TypeDISCONNECT, 0, nil)),
		pkt(1000, mqtt.C2S, connect(false, 30)), // session continued
		pkt(1010, mqtt.C2S, publish("a/b", 3, 2, true, false, "x")), // DUP after reconnect
		pkt(1020, mqtt.C2S, ack(mqtt.TypePUBREL, 3)),
		pkt(1030, mqtt.S2C, ack(mqtt.TypePUBCOMP, 3)),
	}, engine.Params{}, nil)
	if len(d.Generations) != 1 {
		t.Fatalf("generations = %d, want 1 (session continued)", len(d.Generations))
	}
	x := findExchange(d, "gen-1", 3)
	if x == nil || x.Phase != engine.PhaseComplete {
		t.Fatalf("phase = %+v, want complete after resume", x)
	}
	if len(x.Duplicates) != 1 {
		t.Fatalf("expected reconnected DUP folded idempotently, got %v", x.Duplicates)
	}
}

func TestSessionExpiryEndpointVirtualTime(t *testing.T) {
	resetSeq()
	base := []engine.Packet{
		pkt(0, mqtt.C2S, connect(true, 10)), // 10s expiry
		pkt(100, mqtt.C2S, mqtt.Encode(mqtt.TypeDISCONNECT, 0, nil)),
	}
	// gap == expiry exactly -> expired
	atEndpoint := append(append([]engine.Packet{}, base...),
		pkt(10100, mqtt.C2S, connect(false, 10)))
	d := engine.Reconstruct(atEndpoint, engine.Params{}, nil)
	if len(d.Expiries) != 1 || d.Expiries[0].Verdict != "session-expired" {
		t.Fatalf("endpoint verdict = %+v, want session-expired", d.Expiries)
	}
	if d.Expiries[0].Basis != "virtual-time" {
		t.Fatalf("basis = %s", d.Expiries[0].Basis)
	}
	// 1ms inside -> continued
	inside := append(append([]engine.Packet{}, base...),
		pkt(10099, mqtt.C2S, connect(false, 10)))
	d2 := engine.Reconstruct(inside, engine.Params{}, nil)
	if d2.Expiries[0].Verdict != "session-continued" {
		t.Fatalf("inside verdict = %s, want session-continued", d2.Expiries[0].Verdict)
	}
}

func TestTopicAliasResetPerConnection(t *testing.T) {
	resetSeq()
	aliasReg := mqtt.Encode(mqtt.TypePUBLISH, 0, mqtt.PublishBody("a/b", 0, 1, []byte("v")))
	aliasUse := mqtt.Encode(mqtt.TypePUBLISH, 0, mqtt.PublishBody("", 0, 1, []byte("v")))
	d := engine.Reconstruct([]engine.Packet{
		pkt(0, mqtt.C2S, connect(true, 30)),
		pkt(10, mqtt.C2S, aliasReg),
		pkt(20, mqtt.C2S, mqtt.Encode(mqtt.TypeDISCONNECT, 0, nil)),
		pkt(100, mqtt.C2S, connect(false, 30)), // alias table resets
		pkt(110, mqtt.C2S, aliasUse),           // alias 1 unknown now
	}, engine.Params{}, nil)
	found := false
	for _, dg := range d.Diagnostics {
		if dg.PacketID != "" && len(dg.Detail) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected diagnostic for unregistered topic alias after reconnect")
	}
}

func TestRetainedSeparateAndDelete(t *testing.T) {
	resetSeq()
	d := engine.Reconstruct([]engine.Packet{
		pkt(0, mqtt.C2S, connect(true, 30)),
		pkt(10, mqtt.C2S, publish("a/retained", 0, 0, false, true, "on")),
		pkt(20, mqtt.C2S, publish("a/b", 1, 1, false, false, "x")),
		pkt(30, mqtt.S2C, ack(mqtt.TypePUBACK, 1)),
		pkt(40, mqtt.C2S, publish("a/retained", 0, 0, false, true, "")), // delete
	}, engine.Params{}, nil)
	if len(d.Retained) != 1 {
		t.Fatalf("retained entries = %d, want 1", len(d.Retained))
	}
	r := d.Retained[0]
	if r.Active || r.DeletedBy == "" {
		t.Fatalf("retained = %+v, want deleted", r)
	}
	// retained traffic must not appear in session exchanges
	for _, x := range d.Exchanges {
		if x.Topic == "a/retained" {
			t.Fatal("retained message leaked into session exchanges")
		}
	}
}

func TestPacketIDGenerationScoped(t *testing.T) {
	resetSeq()
	d := engine.Reconstruct([]engine.Packet{
		pkt(0, mqtt.C2S, connect(true, 10)),
		pkt(10, mqtt.C2S, publish("a/b", 1, 1, false, false, "x")),
		pkt(20, mqtt.S2C, ack(mqtt.TypePUBACK, 1)),
		pkt(30, mqtt.C2S, mqtt.Encode(mqtt.TypeDISCONNECT, 0, nil)),
		pkt(20000, mqtt.C2S, connect(false, 10)), // expired -> gen-2
		pkt(20010, mqtt.C2S, publish("a/b", 1, 1, false, false, "y")),
		pkt(20020, mqtt.S2C, ack(mqtt.TypePUBACK, 1)),
	}, engine.Params{}, nil)
	if len(d.Generations) != 2 {
		t.Fatalf("generations = %d, want 2", len(d.Generations))
	}
	x1 := findExchange(d, "gen-1", 1)
	x2 := findExchange(d, "gen-2", 1)
	if x1 == nil || x2 == nil || x1.ID == x2.ID {
		t.Fatalf("packet id 1 must yield independent exchanges per generation: %v %v", x1, x2)
	}
}

func TestMultiGenerationConfusionKeepsCandidates(t *testing.T) {
	resetSeq()
	pkts := []engine.Packet{
		pkt(0, mqtt.C2S, connect(true, 10)),
		pkt(10, mqtt.C2S, publish("a/b", 5, 1, false, false, "x")), // never acked
		pkt(20, mqtt.C2S, mqtt.Encode(mqtt.TypeDISCONNECT, 0, nil)),
		pkt(20000, mqtt.C2S, connect(false, 10)), // expired -> gen-2, pkt 5 orphaned
		pkt(20010, mqtt.S2C, ack(mqtt.TypePUBACK, 5)),
	}
	d := engine.Reconstruct(pkts, engine.Params{}, nil)
	var amb *engine.Exchange
	for i := range d.Exchanges {
		if d.Exchanges[i].Ambiguous {
			amb = &d.Exchanges[i]
		}
	}
	if amb == nil || len(amb.Candidates) != 2 {
		t.Fatalf("expected ambiguous exchange with 2 candidates, got %+v", amb)
	}
	// Unresolved: no candidate collapsed.
	if amb.ResolvedBy != "" {
		t.Fatal("ambiguity must not be collapsed without a decision")
	}
	// A decision resolves it; the unchosen candidate stays on record.
	d2 := engine.Reconstruct(pkts, engine.Params{}, []engine.Decision{{
		ID: "dec-1", Status: "adopted", TargetID: amb.ID, Chosen: amb.Candidates[0].ID,
		Rejected: []string{amb.Candidates[1].ID}, Author: "reviewer",
	}})
	var resolved *engine.Exchange
	for i := range d2.Exchanges {
		if d2.Exchanges[i].ID == amb.ID {
			resolved = &d2.Exchanges[i]
		}
	}
	if resolved == nil || resolved.ResolvedBy != "dec-1" {
		t.Fatalf("decision not applied: %+v", resolved)
	}
	if len(resolved.Candidates) != 2 {
		t.Fatal("unchosen candidate must be preserved")
	}
}

func TestIncrementalNotesLimitScope(t *testing.T) {
	resetSeq()
	mk := func(dup bool) []engine.Packet {
		return []engine.Packet{
			pkt(0, mqtt.C2S, connect(true, 30)),
			pkt(10, mqtt.C2S, publish("a/b", 2, 2, false, false, "x")),
			pkt(20, mqtt.S2C, ack(mqtt.TypePUBREC, 2)),
			pkt(30, mqtt.C2S, publish("a/b", 2, 2, dup, false, "x")),
			pkt(40, mqtt.C2S, publish("a/c", 9, 1, false, false, "y")),
			pkt(50, mqtt.S2C, ack(mqtt.TypePUBACK, 9)),
		}
	}
	before := engine.Reconstruct(mk(true), engine.Params{}, nil)
	resetSeq()
	after := engine.Reconstruct(mk(false), engine.Params{}, nil)
	notes := engine.DiffRecompute(before, after, engine.ChangedInputs{
		Packets: []string{"t-c"}, ChangedBy: "test",
	})
	var recomputed, stillValid int
	for _, n := range notes {
		switch n.Status {
		case "recomputed":
			recomputed++
			if n.Node.Kind == "exchange" && n.Node.ID != "xch-gen-1-c2s-0002-a" {
				t.Fatalf("unexpected recomputed node %v", n.Node)
			}
		case "still-valid":
			stillValid++
		}
	}
	if recomputed == 0 || stillValid == 0 {
		t.Fatalf("notes = %+v", notes)
	}
}
