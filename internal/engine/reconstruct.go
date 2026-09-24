package engine

import (
	"fmt"
	"sort"

	"pairwise-gsb/mqttsession/internal/mqtt"
)

// Reconstruct deterministically rebuilds the full derived state from
// packets, params and human decisions. It never collapses ambiguity: when a
// packet cannot be uniquely bound, all legal candidates are kept and the
// affected exchange is marked ambiguous until a decision resolves it.
func Reconstruct(packets []Packet, params Params, decisions []Decision) *Derived {
	d := &Derived{}
	ordered := append([]Packet(nil), packets...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].VirtualTime != ordered[j].VirtualTime {
			return ordered[i].VirtualTime < ordered[j].VirtualTime
		}
		return ordered[i].ID < ordered[j].ID
	})

	// Internal pointer collections; converted to value slices at the end so
	// no pointer into a growing slice is ever kept.
	var gens []*Generation
	var exchanges []*Exchange
	var retained []*RetainedEntry
	retainedByTopic := map[string]*RetainedEntry{}
	inflight := map[string]*Exchange{} // key dir|packetID, current generation
	reuseSeq := map[string]int{}
	var gen *Generation
	lastActivityVT := int64(-1)
	diagSeq := 0
	addDiag := func(pktID, detail string) {
		diagSeq++
		d.Diagnostics = append(d.Diagnostics, Diagnostic{
			ID: fmt.Sprintf("diag-%03d", diagSeq), PacketID: pktID, Detail: detail,
		})
	}

	startGeneration := func(p Packet, cause string) {
		// Orphan incomplete exchanges of the previous generation: packet ids
		// must not be interpreted across generations.
		for _, x := range inflight {
			if x.Phase != PhaseComplete {
				x.Orphaned = true
			}
		}
		inflight = map[string]*Exchange{}
		reuseSeq = map[string]int{}
		expiry := int64(0)
		if p.Dec.SessionExpiry != nil {
			expiry = *p.Dec.SessionExpiry
		}
		if params.SessionExpiryOverride != nil {
			expiry = *params.SessionExpiryOverride
		}
		clean := false
		if p.Dec.CleanStart != nil {
			clean = *p.Dec.CleanStart
		}
		g := &Generation{
			ID: fmt.Sprintf("gen-%d", len(gens)+1), Index: len(gens) + 1,
			ClientID: p.Dec.ClientID, CleanStart: clean, ExpirySec: expiry,
			StartVT: p.VirtualTime, EndVT: p.VirtualTime, Cause: cause,
			TopicAliases: map[int]string{},
		}
		gens = append(gens, g)
		gen = g
	}

	for _, p := range ordered {
		if p.Dec.Diag != "" {
			addDiag(p.ID, p.Dec.Diag)
		}
		switch p.Dec.Type {
		case mqtt.TypeCONNECT:
			if p.Dir != mqtt.C2S {
				break
			}
			clean := p.Dec.CleanStart != nil && *p.Dec.CleanStart
			switch {
			case gen == nil:
				startGeneration(p, "initial-connect")
			case clean:
				startGeneration(p, "clean-start=1 forces new generation")
			default:
				// Session resumption: judge expiry on the virtual-time basis.
				gap := p.VirtualTime - lastActivityVT
				expiryMs := gen.ExpirySec * 1000
				verdict := "session-continued"
				if lastActivityVT < 0 || gap >= expiryMs {
					verdict = "session-expired"
				}
				exp := ExpiryDecision{
					ID: fmt.Sprintf("exp-%d", len(d.Expiries)+1),
					FromGen: gen.ID, GapMs: gap, ExpiryMs: expiryMs,
					Verdict: verdict, Basis: "virtual-time",
				}
				if verdict == "session-expired" {
					startGeneration(p, fmt.Sprintf("session expired: gap %dms >= expiry %dms (virtual time)", gap, expiryMs))
					exp.ToGen = gen.ID
				} else {
					// Same generation, new connection: alias table resets.
					gen.TopicAliases = map[int]string{}
					gen.EndVT = p.VirtualTime
					exp.ToGen = gen.ID
				}
				d.Expiries = append(d.Expiries, exp)
			}

		case mqtt.TypePUBLISH:
			if gen == nil {
				addDiag(p.ID, "PUBLISH before any CONNECT; kept raw, not reconstructed")
				break
			}
			topic := p.Dec.Topic
			if p.Dec.TopicAlias > 0 {
				switch {
				case topic != "":
					gen.TopicAliases[p.Dec.TopicAlias] = topic
				default:
					if t, ok := gen.TopicAliases[p.Dec.TopicAlias]; ok {
						topic = t
					} else {
						addDiag(p.ID, fmt.Sprintf("topic alias %d not registered in %s (alias table resets per connection); topic left unresolved", p.Dec.TopicAlias, gen.ID))
					}
				}
			}
			// Retained messages live in their own store, never in inflight.
			if p.Dec.Retain && p.Dir == mqtt.C2S {
				if len(p.Dec.Payload) == 0 {
					if e, ok := retainedByTopic[topic]; ok && e.Active {
						e.Active = false
						e.DeletedBy = p.ID
					} else {
						e := &RetainedEntry{ID: fmt.Sprintf("ret-%d", len(retained)+1), Topic: topic, DeletedBy: p.ID}
						retained = append(retained, e)
						retainedByTopic[topic] = e
					}
				} else if e, ok := retainedByTopic[topic]; ok {
					e.Active = true
					e.SetBy = p.ID
					e.DeletedBy = ""
				} else {
					e := &RetainedEntry{ID: fmt.Sprintf("ret-%d", len(retained)+1), Topic: topic, SetBy: p.ID, Active: true}
					retained = append(retained, e)
					retainedByTopic[topic] = e
				}
			}
			if p.Dec.QoS == 0 || p.Dir != mqtt.C2S {
				break
			}
			key := fmt.Sprintf("%s|%d", p.Dir, p.Dec.PacketID)
			if x, ok := inflight[key]; ok && x.Phase != PhaseComplete {
				if p.Dec.DUP {
					// QoS duplicate: idempotent fold, handshake phase kept.
					x.Duplicates = append(x.Duplicates, p.ID)
					x.Packets = append(x.Packets, p.ID)
				} else {
					// Non-DUP repeat of an inflight id: genuinely ambiguous.
					seq := reuseSeq[key] + 1
					newID := exchangeID(gen.ID, p.Dir, p.Dec.PacketID, seq)
					x.Ambiguous = true
					x.Candidates = append(x.Candidates,
						Candidate{ID: fmt.Sprintf("cand-%s-fold", x.ID),
							Label: "retransmission without DUP flag: fold into inflight exchange"},
						Candidate{ID: fmt.Sprintf("cand-%s-new", newID),
							Label: "packet id reused while inflight: start new exchange " + newID,
							Target: newID})
					x.Packets = append(x.Packets, p.ID)
					for _, dec := range decisions {
						if dec.Status == "superseded" {
							continue
						}
						if dec.TargetID == x.ID {
							x.ResolvedBy = dec.ID
						}
					}
				}
			} else {
				seq := reuseSeq[key]
				if ok && inflight[key].Phase == PhaseComplete {
					seq++
					reuseSeq[key] = seq
				}
				x := &Exchange{
					ID: exchangeID(gen.ID, p.Dir, p.Dec.PacketID, seq),
					Generation: gen.ID, Dir: p.Dir, PacketID: p.Dec.PacketID,
					QoS: p.Dec.QoS, Topic: topic, Packets: []string{p.ID},
					ReusedID: seq > 0,
				}
				if p.Dec.QoS == 1 {
					x.Phase = PhaseAwaitPubAck
				} else {
					x.Phase = PhaseAwaitPubRec
				}
				exchanges = append(exchanges, x)
				inflight[key] = x
			}

		case mqtt.TypePUBACK, mqtt.TypePUBREC, mqtt.TypePUBREL, mqtt.TypePUBCOMP:
			if gen == nil {
				addDiag(p.ID, "ack before any CONNECT; kept raw")
				break
			}
			key := fmt.Sprintf("%s|%d", mqtt.C2S, p.Dec.PacketID)
			x, ok := inflight[key]
			if !ok || x.Phase == PhaseComplete {
				// Multi-generation confusion: an orphan from an older
				// generation could claim this ack. Keep all candidates.
				if old := findOrphan(exchanges, p.Dec.PacketID); old != nil {
					ax := &Exchange{
						ID: fmt.Sprintf("amb-%s-%04d", gen.ID, p.Dec.PacketID),
						Generation: gen.ID, Dir: mqtt.C2S, PacketID: p.Dec.PacketID,
						Phase: "unbound-ack", Packets: []string{p.ID}, Ambiguous: true,
						Candidates: []Candidate{
							{ID: fmt.Sprintf("cand-amb-%04d-old", p.Dec.PacketID),
								Label:  "ack belongs to orphaned exchange " + old.ID + " (cross-generation)",
								Target: old.ID},
							{ID: fmt.Sprintf("cand-amb-%04d-late", p.Dec.PacketID),
								Label: "ack is stray/late within " + gen.ID + "; binds to nothing"},
						},
					}
					exchanges = append(exchanges, ax)
					for _, dec := range decisions {
						if dec.Status == "superseded" {
							continue
						}
						if dec.TargetID != ax.ID {
							continue
						}
						ax.ResolvedBy = dec.ID
						for _, c := range ax.Candidates {
							if c.ID == dec.Chosen && c.Target == old.ID {
								old.Packets = append(old.Packets, p.ID)
								old.Orphaned = false
								ax.Phase = "bound-to-orphan"
							}
						}
					}
				} else {
					addDiag(p.ID, fmt.Sprintf("ack for packet id %d has no inflight exchange in %s; kept raw", p.Dec.PacketID, gen.ID))
				}
				break
			}
			advance(x, p)

		case mqtt.TypeSUBSCRIBE:
			if gen != nil {
				d.Subs = append(d.Subs, SubChange{
					ID: fmt.Sprintf("sub-%d", len(d.Subs)+1), Generation: gen.ID,
					Filter: p.Dec.Topic, Op: "subscribe", PacketID: p.ID, VT: p.VirtualTime,
				})
			}
		case mqtt.TypeUNSUBSCRIBE:
			if gen != nil {
				d.Subs = append(d.Subs, SubChange{
					ID: fmt.Sprintf("sub-%d", len(d.Subs)+1), Generation: gen.ID,
					Filter: p.Dec.Topic, Op: "unsubscribe", PacketID: p.ID, VT: p.VirtualTime,
				})
			}
		}
		if gen != nil && p.VirtualTime > gen.EndVT {
			gen.EndVT = p.VirtualTime
		}
		if p.Dec.Type != 0 {
			lastActivityVT = p.VirtualTime
		}
	}

	for _, g := range gens {
		d.Generations = append(d.Generations, *g)
	}
	for _, x := range exchanges {
		d.Exchanges = append(d.Exchanges, *x)
	}
	for _, r := range retained {
		d.Retained = append(d.Retained, *r)
	}
	return d
}

// advance moves a QoS state machine one step. Duplicate acks are idempotent:
// recorded, but they never regress or skip the handshake phase.
func advance(x *Exchange, p Packet) {
	x.Packets = append(x.Packets, p.ID)
	step := func(wantDir mqtt.Direction, from, to string, types ...int) {
		match := false
		for _, t := range types {
			if p.Dec.Type == t {
				match = true
			}
		}
		if !match || p.Dir != wantDir {
			return
		}
		switch x.Phase {
		case from:
			x.Phase = to
		case to:
			x.Duplicates = append(x.Duplicates, p.ID) // idempotent repeat
		}
	}
	switch x.QoS {
	case 1:
		step(mqtt.S2C, PhaseAwaitPubAck, PhaseComplete, mqtt.TypePUBACK)
	case 2:
		step(mqtt.S2C, PhaseAwaitPubRec, PhaseAwaitPubRel, mqtt.TypePUBREC)
		step(mqtt.C2S, PhaseAwaitPubRel, PhaseAwaitPubComp, mqtt.TypePUBREL)
		step(mqtt.S2C, PhaseAwaitPubComp, PhaseComplete, mqtt.TypePUBCOMP)
	}
}

func findOrphan(exchanges []*Exchange, packetID int) *Exchange {
	for _, x := range exchanges {
		if x.Orphaned && x.PacketID == packetID {
			return x
		}
	}
	return nil
}
