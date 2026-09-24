package mqtt

import "fmt"

// Params are rule parameters. Revising them produces a new source version and
// only re-derives dependent artifacts.
type Params struct {
	// ClockSkewToleranceMS widens the session-expiry boundary: when the
	// reconnect gap is within tolerance of the expiry interval, the outcome
	// is not unique and all legal candidates are preserved.
	ClockSkewToleranceMS int64 `json:"clock_skew_tolerance_ms"`
}

// Boundary is a session-expiry decision point between two generations,
// evaluated on the virtual clock.
type Boundary struct {
	ID          string   `json:"id"`
	PrevGen     string   `json:"prev_gen"`
	NextGen     string   `json:"next_gen"`
	Gap         Quantity `json:"gap"`
	Expiry      Quantity `json:"expiry"`
	CleanStart  bool     `json:"clean_start"`
	AtBoundary  bool     `json:"at_boundary"` // gap == expiry exactly
	Ambiguous   bool     `json:"ambiguous"`   // within clock-skew tolerance
	Candidates  []string `json:"candidates"`  // "expired" and/or "persisted"
	RuleOutcome string   `json:"rule_outcome"`
	Rationale   string   `json:"rationale"`
}

type Generation struct {
	ID             string   `json:"id"`
	Index          int      `json:"index"`
	ClientID       string   `json:"client_id"`
	CleanStart     bool     `json:"clean_start"`
	SessionExpiryS uint32   `json:"session_expiry_s"`
	SessionPresent bool     `json:"session_present"`
	StartMS        int64    `json:"start_ms"`
	EndMS          int64    `json:"end_ms"`
	CarriedFrom    string   `json:"carried_from,omitempty"`
	Packets        []string `json:"packets"`
}

type Sessions struct {
	Generations []Generation `json:"generations"`
	Boundaries  []Boundary   `json:"boundaries"`
}

// Sessionize splits a trace into generations. A packet id is only meaningful
// inside one generation; generations never share flow state unless the
// session persisted across the boundary.
func Sessionize(pkts []Packet, p Params) Sessions {
	var s Sessions
	var cur *Generation
	closeGen := func(endMS int64) {
		if cur != nil {
			cur.EndMS = endMS
			s.Generations = append(s.Generations, *cur)
			cur = nil
		}
	}
	for _, pkt := range pkts {
		if pkt.Type == CONNECT && pkt.Dir == C2B {
			prevEnd := int64(0)
			var prev *Generation
			if cur != nil {
				prevEnd = cur.EndMS
				p := *cur
				prev = &p
			}
			closeGen(pkt.ClockMS)
			idx := len(s.Generations) + 1
			cs := pkt.CleanStart != nil && *pkt.CleanStart
			exp := uint32(0)
			if pkt.SessionExpiryS != nil {
				exp = *pkt.SessionExpiryS
			}
			gen := Generation{
				ID:             fmt.Sprintf("gen-%d", idx),
				Index:          idx,
				ClientID:       pkt.ClientID,
				CleanStart:     cs,
				SessionExpiryS: exp,
				StartMS:        pkt.ClockMS,
				EndMS:          pkt.ClockMS,
			}
			if prev != nil {
				gap := pkt.ClockMS - prevEnd
				expiryMS := int64(prev.SessionExpiryS) * 1000
				b := Boundary{
					ID:         fmt.Sprintf("boundary-%s", gen.ID),
					PrevGen:    prev.ID,
					NextGen:    gen.ID,
					Gap:        MS(gap),
					Expiry:     Sec(prev.SessionExpiryS),
					CleanStart: cs,
				}
				switch {
				case cs:
					b.Candidates = []string{"expired"}
					b.RuleOutcome = "expired"
					b.Rationale = "clean start requested; previous session state discarded"
				case gap < expiryMS:
					b.Candidates = []string{"persisted"}
					b.RuleOutcome = "persisted"
					b.Rationale = fmt.Sprintf("gap %dms < expiry %dms on virtual clock; session state carries over", gap, expiryMS)
				case gap == expiryMS:
					b.AtBoundary = true
					if gap <= expiryMS+p.ClockSkewToleranceMS && p.ClockSkewToleranceMS > 0 {
						b.Ambiguous = true
						b.Candidates = []string{"expired", "persisted"}
						b.Rationale = fmt.Sprintf("gap %dms equals expiry %dms within tolerance %dms; outcome not unique", gap, expiryMS, p.ClockSkewToleranceMS)
					} else {
						b.Candidates = []string{"expired"}
						b.Rationale = fmt.Sprintf("gap %dms reaches expiry %dms exactly; session ends when the interval elapses", gap, expiryMS)
					}
					b.RuleOutcome = "expired"
				default:
					b.Candidates = []string{"expired"}
					b.RuleOutcome = "expired"
					b.Rationale = fmt.Sprintf("gap %dms > expiry %dms on virtual clock; session expired", gap, expiryMS)
				}
				if b.RuleOutcome == "persisted" {
					gen.CarriedFrom = prev.ID
				}
				s.Boundaries = append(s.Boundaries, b)
			}
			cur = &gen
		}
		if cur != nil {
			cur.Packets = append(cur.Packets, pkt.ID)
			if pkt.ClockMS > cur.EndMS {
				cur.EndMS = pkt.ClockMS
			}
			if pkt.Type == CONNACK && pkt.SessionPresent != nil {
				cur.SessionPresent = *pkt.SessionPresent
			}
		}
	}
	closeGen(0)
	if n := len(s.Generations); n > 0 && s.Generations[n-1].EndMS == 0 {
		s.Generations[n-1].EndMS = s.Generations[n-1].StartMS
	}
	return s
}

// Persisted reports whether gen carried state from its predecessor according
// to the rule outcome (human rulings may override at the decision layer).
func (s Sessions) Persisted(genID string) bool {
	for _, b := range s.Boundaries {
		if b.NextGen == genID {
			return b.RuleOutcome == "persisted"
		}
	}
	return false
}
