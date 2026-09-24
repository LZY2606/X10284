package casepack

import (
	"strings"
	"testing"

	"pairwise-gsb/mqttsession/internal/engine"
)

func reconstruct(t *testing.T) *engine.Derived {
	t.Helper()
	return engine.Reconstruct(Trace(), engine.Params{RuleSetID: "rules-v1"}, nil)
}

func xch(d *engine.Derived, id string) *engine.Exchange {
	for i := range d.Exchanges {
		if d.Exchanges[i].ID == id {
			return &d.Exchanges[i]
		}
	}
	return nil
}

func TestBaselineNarrative(t *testing.T) {
	d := reconstruct(t)

	// Two generations: expiry endpoint splits the session.
	if len(d.Generations) != 2 {
		t.Fatalf("generations = %d, want 2", len(d.Generations))
	}
	if d.Generations[1].Cause == "" || !strings.Contains(d.Generations[1].Cause, "expired") {
		t.Fatalf("gen-2 cause = %q", d.Generations[1].Cause)
	}

	// QoS 2 with DUP retransmit: idempotent fold, phase completes.
	x2 := xch(d, "xch-gen-1-c2s-0002-a")
	if x2 == nil || x2.Phase != engine.PhaseComplete || len(x2.Duplicates) != 1 {
		t.Fatalf("qos2 dup exchange = %+v", x2)
	}

	// QoS 2 mid-disconnect resumes and completes after reconnect.
	x3 := xch(d, "xch-gen-1-c2s-0003-a")
	if x3 == nil || x3.Phase != engine.PhaseComplete {
		t.Fatalf("qos2 mid-disconnect exchange = %+v", x3)
	}

	// Packet id reuse inside gen-1 yields a second, independent exchange.
	if xch(d, "xch-gen-1-c2s-0001-b") == nil {
		t.Fatal("packet id reuse exchange missing")
	}

	// Orphaned exchange from gen-1 (packet id 5, never acked).
	x5 := xch(d, "xch-gen-1-c2s-0005-a")
	if x5 == nil || !x5.Orphaned {
		t.Fatalf("orphan = %+v", x5)
	}

	// Multi-generation confusion: PUBACK 5 in gen-2 stays ambiguous with
	// both legal candidates.
	amb := xch(d, "amb-gen-2-0005")
	if amb == nil || !amb.Ambiguous || len(amb.Candidates) != 2 || amb.ResolvedBy != "" {
		t.Fatalf("ambiguity = %+v", amb)
	}

	// Packet id 1 in gen-2 is a fresh exchange, not confused with gen-1.
	if xch(d, "xch-gen-2-c2s-0001-a") == nil {
		t.Fatal("gen-2 packet id 1 exchange missing")
	}

	// Session-expiry endpoint uses virtual time: gap 30000ms == expiry.
	var exp2 *engine.ExpiryDecision
	for i := range d.Expiries {
		if d.Expiries[i].ID == "exp-2" {
			exp2 = &d.Expiries[i]
		}
	}
	if exp2 == nil || exp2.Verdict != "session-expired" || exp2.GapMs != 30000 || exp2.Basis != "virtual-time" {
		t.Fatalf("exp-2 = %+v", exp2)
	}
	if d.Expiries[0].Verdict != "session-continued" || d.Expiries[0].GapMs != 1300 {
		t.Fatalf("exp-1 = %+v", d.Expiries[0])
	}

	// Retained store: set then deleted, separate from session exchanges.
	if len(d.Retained) != 1 || d.Retained[0].Active || d.Retained[0].DeletedBy == "" {
		t.Fatalf("retained = %+v", d.Retained)
	}

	// Diagnostics: topic alias used after reset; unconvertible frame kept.
	var aliasDiag, rawDiag bool
	for _, dg := range d.Diagnostics {
		if strings.Contains(dg.Detail, "topic alias 1 not registered") {
			aliasDiag = true
		}
		if strings.Contains(dg.Detail, "remaining length") {
			rawDiag = true
		}
	}
	if !aliasDiag || !rawDiag {
		t.Fatalf("diagnostics = %+v", d.Diagnostics)
	}

	// Subscription changes across generations.
	if len(d.Subs) != 2 || d.Subs[1].Op != "unsubscribe" || d.Subs[1].Generation != "gen-2" {
		t.Fatalf("subs = %+v", d.Subs)
	}
}

func TestArchiveCoversAllBoundaryCases(t *testing.T) {
	arch := BuildArchive()
	want := []string{
		"ce-packet-id-reuse", "ce-dup-retransmit", "ce-qos2-mid-disconnect",
		"ce-session-expiry-endpoint", "ce-topic-alias-reset", "ce-retained-delete",
		"ce-multi-generation-confusion",
	}
	if len(arch) != len(want) {
		t.Fatalf("archive entries = %d", len(arch))
	}
	for i, id := range want {
		e := arch[i]
		if e.ID != id {
			t.Fatalf("entry %d = %s, want %s", i, e.ID, id)
		}
		if len(e.Judgments) == 0 || e.Adopted.Label == "" || len(e.Unadopted) == 0 {
			t.Fatalf("entry %s incomplete: %+v", id, e)
		}
		for _, j := range e.Judgments {
			if j.Rule == "" || j.Detail == "" {
				t.Fatalf("judgment not machine-readable: %+v", j)
			}
		}
	}
}

func TestExpiryEndpointMutationFlipsVerdict(t *testing.T) {
	mutated, changed, err := ApplyMutation("ce-session-expiry-endpoint", Trace())
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 {
		t.Fatalf("changed = %v", changed)
	}
	d := engine.Reconstruct(mutated, engine.Params{RuleSetID: "rules-v1"}, nil)
	var exp2 *engine.ExpiryDecision
	for i := range d.Expiries {
		if d.Expiries[i].ID == "exp-2" {
			exp2 = &d.Expiries[i]
		}
	}
	if exp2 == nil || exp2.Verdict != "session-continued" || exp2.GapMs != 29999 {
		t.Fatalf("mutated exp-2 = %+v, want session-continued at 29999ms", exp2)
	}
	if len(d.Generations) != 1 {
		t.Fatalf("generations = %d, want 1 (no split inside endpoint)", len(d.Generations))
	}
}

func TestRawBytesPreserved(t *testing.T) {
	for _, p := range Trace() {
		if len(p.Raw) == 0 {
			t.Fatalf("packet %s lost raw bytes", p.ID)
		}
		if p.ClockRaw == "" || p.VirtualTime < 0 {
			t.Fatalf("packet %s lost clock basis", p.ID)
		}
	}
}

func TestFixtureMatchesBuilder(t *testing.T) {
	f, err := LoadFixture()
	if err != nil {
		t.Fatal(err)
	}
	if f.Case == "" || len(f.Basis) == 0 {
		t.Fatal("fixture missing case narrative or unit basis")
	}
	built := Trace()
	if len(f.Packets) != len(built) {
		t.Fatalf("fixture packets = %d, builder = %d", len(f.Packets), len(built))
	}
	for i := range built {
		a, b := f.Packets[i], built[i]
		if a.ID != b.ID || a.VirtualTime != b.VirtualTime || a.ClockRaw != b.ClockRaw ||
			a.Dir != b.Dir || len(a.Raw) != len(b.Raw) {
			t.Fatalf("fixture packet %d diverges from builder", i)
		}
	}
	if f.Snapshot.ClientID != ClientID {
		t.Fatalf("snapshot = %+v", f.Snapshot)
	}
}
