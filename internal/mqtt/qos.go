package mqtt

import "fmt"

// Anomaly is a machine-readable finding. It keeps references to the stable
// identities of every packet/flow involved so the UI can link provenance.
type Anomaly struct {
	ID        string   `json:"id"`
	Code      string   `json:"code"`
	Detail    string   `json:"detail"`
	Gen       string   `json:"gen"`
	FlowID    string   `json:"flow_id,omitempty"`
	PacketIDs []string `json:"packet_ids"`
}

type FlowEvent struct {
	Packet  string `json:"packet"` // pkt-XXXX
	ClockMS int64  `json:"clock_ms"`
	Kind    string `json:"kind"` // publish|dup-publish|puback|pubrec|dup-pubrec|pubrel|pubcomp|carry|discard
	Note    string `json:"note,omitempty"`
}

// Flow is one QoS handshake. Its identity is scoped to a session generation:
// the same packet id in another generation is a different flow.
type Flow struct {
	ID          string      `json:"id"` // gen-N/<dir>/<pid>#occ
	Gen         string      `json:"gen"`
	Dir         Direction   `json:"dir"`
	PacketID    uint16      `json:"packet_id"`
	Occurrence  int         `json:"occurrence"`
	QoS         int         `json:"qos"`
	Topic       string      `json:"topic"`
	Phase       string      `json:"phase"` // published|pubrec|pubrel|complete
	Carried     bool        `json:"carried"`
	CarriedFrom string      `json:"carried_from,omitempty"`
	Events      []FlowEvent `json:"events"`
	Deliveries  int         `json:"deliveries"` // idempotent: duplicates do not increase this
	Complete    bool        `json:"complete"`
	Discarded   bool        `json:"discarded"`
}

type Flows struct {
	Flows     []Flow    `json:"flows"`
	Anomalies []Anomaly `json:"anomalies"`
}

func flowKey(dir Direction, pid uint16) string { return fmt.Sprintf("%s/%d", dir, pid) }

// AnalyzeFlows rebuilds QoS 1/2 handshakes per generation. Duplicate
// retransmissions are idempotent (delivery counted once) but every handshake
// phase is kept as an event. Topic aliases are resolved per generation and
// reset on reconnect.
func AnalyzeFlows(pkts []Packet, s Sessions) Flows {
	byID := map[string]Packet{}
	for _, p := range pkts {
		byID[p.ID] = p
	}
	var out Flows
	anoN := 0
	addAnomaly := func(code, detail, gen, flow string, ids ...string) {
		anoN++
		out.Anomalies = append(out.Anomalies, Anomaly{
			ID: fmt.Sprintf("ano-%02d", anoN), Code: code, Detail: detail,
			Gen: gen, FlowID: flow, PacketIDs: ids,
		})
	}

	var carry []Flow // incomplete flows carried into the next persisted gen
	for gi, gen := range s.Generations {
		_ = gi
		inflight := map[string]*Flow{}
		completed := map[string]int{} // flowKey -> occurrence count
		alias := map[uint16]string{}  // topic alias map: reset per generation
		var order []*Flow

		// seed carried flows (QoS 2 mid-disconnect resume)
		if gen.CarriedFrom != "" {
			for _, cf := range carry {
				nf := cf
				nf.ID = fmt.Sprintf("%s/%s/%d#%d", gen.ID, cf.Dir, cf.PacketID, cf.Occurrence)
				nf.Gen = gen.ID
				nf.Carried = true
				nf.CarriedFrom = cf.ID
				nf.Events = append([]FlowEvent{{Packet: "", ClockMS: gen.StartMS, Kind: "carry",
					Note: fmt.Sprintf("resumed from %s after reconnect; handshake phase %q kept", cf.ID, cf.Phase)}}, nf.Events...)
				inflight[flowKey(nf.Dir, nf.PacketID)] = &nf
				order = append(order, &nf)
			}
		}
		carry = nil

		flush := func() {
			for _, f := range order {
				out.Flows = append(out.Flows, *f)
			}
			order = nil
		}

		for _, pid := range gen.Packets {
			p := byID[pid]
			switch p.Type {
			case PUBLISH:
				topic := p.Topic
				if p.TopicAlias != nil {
					if p.Topic != "" {
						alias[*p.TopicAlias] = p.Topic
					} else if t, ok := alias[*p.TopicAlias]; ok {
						topic = t
					} else {
						addAnomaly("unknown-topic-alias",
							fmt.Sprintf("alias %d used without registration; alias map resets on reconnect", *p.TopicAlias),
							gen.ID, "", p.ID)
					}
				}
				if p.QoS == 0 || p.PacketID == nil {
					continue
				}
				key := flowKey(p.Dir, *p.PacketID)
				if f, ok := inflight[key]; ok {
					if p.Dup {
						// idempotent: recorded, phase kept, not re-delivered
						f.Events = append(f.Events, FlowEvent{Packet: p.ID, ClockMS: p.ClockMS, Kind: "dup-publish",
							Note: "DUP retransmission; idempotent, handshake phase preserved"})
					} else {
						addAnomaly("packet-id-reuse-while-inflight",
							fmt.Sprintf("packet id %d reused while flow %s in phase %q", *p.PacketID, f.ID, f.Phase),
							gen.ID, f.ID, p.ID)
					}
					continue
				}
				occ := completed[key] + 1
				if completed[key] > 0 {
					addAnomaly("packet-id-reuse",
						fmt.Sprintf("packet id %d reused after completion (occurrence %d) within %s", *p.PacketID, occ, gen.ID),
						gen.ID, "", p.ID)
				}
				f := &Flow{
					ID:  fmt.Sprintf("%s/%s/%d#%d", gen.ID, p.Dir, *p.PacketID, occ),
					Gen: gen.ID, Dir: p.Dir, PacketID: *p.PacketID, Occurrence: occ,
					QoS: p.QoS, Topic: topic, Phase: "published", Deliveries: 1,
					Events: []FlowEvent{{Packet: p.ID, ClockMS: p.ClockMS, Kind: "publish"}},
				}
				inflight[key] = f
				order = append(order, f)
			case PUBACK, PUBREC, PUBREL, PUBCOMP:
				if p.PacketID == nil {
					continue
				}
				// ack travels opposite to the publish it answers
				dir := C2B
				if p.Dir == C2B {
					dir = B2C
				}
				key := flowKey(dir, *p.PacketID)
				f, ok := inflight[key]
				if !ok {
					addAnomaly("unexpected-ack",
						fmt.Sprintf("%s for packet id %d has no inflight flow in %s", p.Type, *p.PacketID, gen.ID),
						gen.ID, "", p.ID)
					continue
				}
				switch p.Type {
				case PUBACK:
					f.Events = append(f.Events, FlowEvent{Packet: p.ID, ClockMS: p.ClockMS, Kind: "puback"})
					f.Phase, f.Complete = "complete", true
					delete(inflight, key)
					completed[key]++
				case PUBREC:
					if f.Phase == "pubrec" || f.Phase == "pubrel" {
						f.Events = append(f.Events, FlowEvent{Packet: p.ID, ClockMS: p.ClockMS, Kind: "dup-pubrec",
							Note: "retransmitted PUBREC; idempotent"})
					} else {
						f.Events = append(f.Events, FlowEvent{Packet: p.ID, ClockMS: p.ClockMS, Kind: "pubrec"})
						f.Phase = "pubrec"
					}
				case PUBREL:
					f.Events = append(f.Events, FlowEvent{Packet: p.ID, ClockMS: p.ClockMS, Kind: "pubrel"})
					f.Phase = "pubrel"
				case PUBCOMP:
					f.Events = append(f.Events, FlowEvent{Packet: p.ID, ClockMS: p.ClockMS, Kind: "pubcomp"})
					f.Phase, f.Complete = "complete", true
					delete(inflight, key)
					completed[key]++
				}
			}
		}

		// generation ended: incomplete flows either carry over (persisted
		// session) or are discarded (expired / clean start).
		persisted := false
		if gi+1 < len(s.Generations) {
			persisted = s.Generations[gi+1].CarriedFrom == gen.ID
		}
		for key, f := range inflight {
			delete(inflight, key)
			if persisted {
				carry = append(carry, *f)
			} else {
				f.Discarded = true
				f.Events = append(f.Events, FlowEvent{ClockMS: gen.EndMS, Kind: "discard",
					Note: "session state discarded at generation boundary"})
			}
		}
		flush()
	}
	return out
}
