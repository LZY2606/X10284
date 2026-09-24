package engine_test

import (
	"encoding/json"
	"testing"

	"github.com/example/mqtt-session-forensics/internal/engine"
	"github.com/example/mqtt-session-forensics/internal/fixtures"
	"github.com/example/mqtt-session-forensics/internal/model"
)

func loadBundle(t *testing.T) *model.Bundle {
	t.Helper()
	b := &model.Bundle{}
	if err := json.Unmarshal(fixtures.Load(), b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBaselineReconstruction(t *testing.T) {
	g := engine.Compute(loadBundle(t), 1)

	// three clients, expected generation counts
	if len(g.Generations) != 4 {
		t.Fatalf("want 4 generations, got %d", len(g.Generations))
	}
	// QoS2 interrupted then resumed for sensor-a packet id 200
	var sawStuck, sawDone bool
	for _, f := range g.Flows {
		if f.ClientID == "sensor-a" && f.PacketID == 200 && f.QoS == 2 {
			if f.Interrupted {
				sawStuck = true
			}
			if f.Phase == model.PhaseQ2Done && f.Resumed {
				sawDone = true
			}
		}
	}
	if !sawStuck || !sawDone {
		t.Fatalf("qos2 interruption/resume not reconstructed: stuck=%v done=%v", sawStuck, sawDone)
	}
	// duplicate PUBREC idempotent flag appears somewhere on flow 200
	var idem bool
	for _, f := range g.Flows {
		if f.PacketID == 200 && f.IdempotentDup {
			idem = true
		}
	}
	if !idem {
		t.Fatal("expected idempotent duplicate marker on QoS2 flow 200")
	}
	// packet id 100 reused -> two incarnations for sensor-a
	count := 0
	for _, f := range g.Flows {
		if f.ClientID == "sensor-a" && f.PacketID == 100 {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("want 2 incarnations of packet id 100, got %d", count)
	}
	// device-c: same numeric id 900 in two generations, distinct flows
	genFlows := map[string]int{}
	for _, f := range g.Flows {
		if f.ClientID == "device-c" && f.PacketID == 900 {
			genFlows[f.GenUID]++
		}
	}
	if len(genFlows) != 2 {
		t.Fatalf("packet id 900 must be scoped per generation, got %d gens", len(genFlows))
	}
	// retained store: cfg/mode deleted, not alive
	if r := g.Retained["retain:cfg/mode"]; r == nil || r.Alive {
		t.Fatalf("cfg/mode retained slot should be a deleted tombstone: %+v", r)
	}
	// expiry boundary exactly equal => ambiguous with two candidates
	var amb *model.ExpiryNode
	for _, e := range g.Expiries {
		if e.ClientID == "gateway-b" {
			amb = e
		}
	}
	if amb == nil || amb.VerdictStr != "boundary_ambiguous" || len(amb.Candidates) != 2 {
		t.Fatalf("want boundary_ambiguous with 2 candidates, got %+v", amb)
	}
	// topic alias reset+use on second connection
	an := g.Aliases["alias:tcp-10.0.0.10:4402"]
	if an == nil || !an.Reset || an.Mappings[7] != "dt/temp" {
		t.Fatalf("alias map wrong: %+v", an)
	}
	// diagnostics include the unconvertible clock
	var foundBad bool
	for _, d := range g.Diagnostics {
		if d.Code == "packet_malformed" || d.Code == "raw_hex_invalid" {
			t.Fatalf("unexpected hard failure: %+v", d)
		}
	}
	for _, p := range loadBundle(t).Packets {
		if p.ObservedAt.Unit == "bad" {
			nt := engine.NormalizeTime(p.ObservedAt)
			if !nt.Unconvertible {
				t.Fatal("bad clock should be unconvertible")
			}
			foundBad = true
		}
	}
	if !foundBad {
		t.Fatal("fixture lost its unconvertible clock case")
	}
}

func TestPropagationScoping(t *testing.T) {
	b := loadBundle(t)
	g1 := engine.Compute(b, 1)
	// flip only the DUP flag on sensor-a pkt 1400 (pkt-0003 DUP retransmit)
	for i := range b.Packets {
		if b.Packets[i].ID == "pkt-0003" {
			b.Packets[i].RawHex = flipDUP(t, b.Packets[i].RawHex)
		}
	}
	g2 := engine.Compute(b, 2)
	rep := engine.Propagate(g1, g2, map[string]bool{"packet:pkt-0003": true})
	changed := 0
	valid := 0
	for _, r := range rep.Reports {
		if r.Status == engine.StatusChanged {
			changed++
		}
		if r.Status == engine.StatusValid {
			valid++
		}
	}
	if changed == 0 {
		t.Fatal("expected at least one changed node from the single-source patch")
	}
	if valid == 0 {
		t.Fatal("expected unaffected nodes to remain valid")
	}
	// expiry nodes must remain valid (unrelated dependency)
	for _, r := range rep.Reports {
		if r.Kind == model.NodeExpiry && r.Status != engine.StatusValid {
			t.Fatalf("expiry node affected by unrelated DUP patch: %s %s", r.NodeUID, r.Status)
		}
	}
}

func flipDUP(t *testing.T, hexStr string) string {
	t.Helper()
	raw := h2b(t, hexStr)
	raw[0] ^= 0x08
	return b2h(raw)
}
