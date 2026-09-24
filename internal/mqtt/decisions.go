package mqtt

import "fmt"

// Decision is a machine-readable judgment record. Every candidate is kept;
// the rule choice is only the default. Human rulings are separate events and
// never overwrite this record.
type Decision struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"` // session-expiry|packet-id-reuse|dup-correspondence|alias-reset|retained-delete|multi-gen-confusion|anomaly
	Subject    string   `json:"subject"`
	Candidates []string `json:"candidates"`
	RuleChoice string   `json:"rule_choice"`
	Basis      string   `json:"basis"`    // coordinate basis of the evidence, e.g. BasisVirtual
	Evidence   []string `json:"evidence"` // stable ids: pkt-XXXX, flow ids, gen ids
	Rationale  string   `json:"rationale"`
}

type Decisions struct {
	Decisions []Decision `json:"decisions"`
}

// BuildDecisions folds boundaries, flow anomalies and retained mutations into
// judgment records. Nothing is collapsed to a single answer: ambiguous
// outcomes keep every legal candidate.
func BuildDecisions(s Sessions, f Flows, r Retained) Decisions {
	var out Decisions
	n := 0
	next := func() string { n++; return fmt.Sprintf("dec-%02d", n) }

	for _, b := range s.Boundaries {
		out.Decisions = append(out.Decisions, Decision{
			ID: next(), Kind: "session-expiry",
			Subject:    b.NextGen,
			Candidates: b.Candidates,
			RuleChoice: b.RuleOutcome,
			Basis:      BasisVirtual,
			Evidence:   []string{b.PrevGen, b.NextGen},
			Rationale:  b.Rationale,
		})
	}
	for _, fl := range f.Flows {
		for _, ev := range fl.Events {
			if ev.Kind == "dup-publish" || ev.Kind == "dup-pubrec" {
				out.Decisions = append(out.Decisions, Decision{
					ID: next(), Kind: "dup-correspondence",
					Subject:    fl.ID,
					Candidates: []string{"idempotent-retransmission"},
					RuleChoice: "idempotent-retransmission",
					Basis:      BasisVirtual,
					Evidence:   []string{fl.ID, ev.Packet},
					Rationale:  "duplicate matches inflight flow in the same generation; delivery counted once, handshake phase kept",
				})
			}
		}
		if fl.Carried {
			out.Decisions = append(out.Decisions, Decision{
				ID: next(), Kind: "qos2-mid-disconnect",
				Subject:    fl.ID,
				Candidates: []string{"resume-handshake"},
				RuleChoice: "resume-handshake",
				Basis:      BasisVirtual,
				Evidence:   []string{fl.CarriedFrom, fl.ID},
				Rationale:  "QoS 2 handshake interrupted by reconnect; state carried across the persisted session boundary",
			})
		}
	}
	for _, a := range f.Anomalies {
		kind := "anomaly"
		switch a.Code {
		case "packet-id-reuse", "packet-id-reuse-while-inflight":
			kind = "packet-id-reuse"
		case "unknown-topic-alias":
			kind = "alias-reset"
		}
		out.Decisions = append(out.Decisions, Decision{
			ID: next(), Kind: kind,
			Subject:    a.FlowID,
			Candidates: []string{"flagged"},
			RuleChoice: "flagged",
			Basis:      BasisVirtual,
			Evidence:   a.PacketIDs,
			Rationale:  a.Detail,
		})
	}
	for _, chg := range r.Changes {
		if chg.Op == "delete" {
			out.Decisions = append(out.Decisions, Decision{
				ID: next(), Kind: "retained-delete",
				Subject:    chg.Topic,
				Candidates: []string{"deleted"},
				RuleChoice: "deleted",
				Basis:      BasisVirtual,
				Evidence:   []string{chg.Packet},
				Rationale:  "zero-length retained PUBLISH removes the retained entry; retained store stays separate from session messages",
			})
		}
	}
	// multi-generation confusion: the same packet id may legitimately recur
	// across generations, but flows are only linked through an explicit
	// carry-over edge. Equal ids without that edge stay separate flows.
	linked := map[string]bool{}
	for _, fl := range f.Flows {
		if fl.CarriedFrom != "" {
			linked[fl.CarriedFrom+"->"+fl.ID] = true
		}
	}
	seen := map[string]Flow{}
	for _, fl := range f.Flows {
		k := string(fl.Dir) + "/" + fmt.Sprint(fl.PacketID)
		if prev, ok := seen[k]; ok && prev.Gen != fl.Gen && !linked[prev.ID+"->"+fl.ID] && !linked[fl.ID+"->"+prev.ID] {
			out.Decisions = append(out.Decisions, Decision{
				ID: next(), Kind: "multi-gen-confusion",
				Subject:    k,
				Candidates: []string{"not-linked"},
				RuleChoice: "not-linked",
				Basis:      BasisVirtual,
				Evidence:   []string{prev.ID, fl.ID},
				Rationale:  "packet id only interpreted inside one session generation; no carry-over edge, flows stay separate",
			})
		}
		seen[k] = fl
	}
	return Decisions{Decisions: out.Decisions}
}
