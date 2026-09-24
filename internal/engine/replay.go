package engine

import (
	"fmt"
	"strconv"

	"mqtttrace/internal/codec"
	"mqtttrace/internal/domain"
)

func (e *engine) replay() error {
	pkts := e.in.Bundle.Packets
	for i := range pkts {
		p := &pkts[i]
		if !p.Clock.Convertible {
			e.ev(domain.EvReplay, domain.PrincipleUnconvertibleKept,
				"packet carries an unconvertible clock; raw value retained in place",
				map[string]any{
					"packet": p.ID, "clock_source": p.Clock.Source,
					"unit": p.Clock.Unit, "diag": p.Clock.Diag,
				}, []domain.Ref{pktRef(p)}, -1)
		}
		if e.current != nil && p.Clock.Convertible {
			e.current.lastVTime = p.Clock.VTimeMs
		}
		switch p.Type {
		case domain.PKCONNECT:
			e.openGen(p)
		case domain.PKCONNACK:
			if e.current == nil {
				e.diagPacket(p, "orphan-connack", "CONNACK without a preceding CONNECT")
				continue
			}
			e.current.connack = p
		case domain.PKDISCONNECT:
			e.handleDisconnect(p)
		case domain.PKPUBLISH:
			e.handlePublish(p)
		case domain.PKPUBACK, domain.PKPUBREC, domain.PKPUBREL, domain.PKPUBCOMP:
			e.handleAck(p)
		case domain.PKSUBSCRIBE, domain.PKSUBACK, domain.PKUNSUBSCRIBE, domain.PKUNSUBACK:
			e.handleSub(p)
		case domain.PKPINGREQ, domain.PKPINGRESP:
			// keepalive: bytes preserved, nothing derived
		default:
			why := "packet type not recognized"
			if len(p.Diag) > 0 {
				why = p.Diag[0]
			}
			e.diagPacket(p, "undecodable-bytes", why)
		}
	}
	for _, s := range e.in.Bundle.Snapshots {
		e.snapshots = append(e.snapshots, s)
	}
	return nil
}

func (e *engine) openGen(p *domain.Packet) {
	if e.current != nil && !e.current.closeVTimeSet() {
		e.current.closeVTime = p.Clock.VTimeMs
		e.current.closeKind = "inferred-at-reconnect"
		e.ev(domain.EvReplay, "", "connection ended without DISCONNECT; close inferred at next CONNECT",
			map[string]any{"generation": e.current.id, "close_vtime_ms": e.current.closeVTime,
				"unit": "ms", "clock_basis": e.in.Params.ClockBasis},
			[]domain.Ref{pktRef(p), {Kind: "node", ID: e.current.id}}, p.Clock.VTimeMs)
	}
	seq := len(e.gens) + 1
	d, err := codec.Decode(p.Raw)
	clean := false
	var expiry uint32
	var aliasMax int
	if err == nil {
		clean = d.Frame.CleanStart
		expiry = d.Frame.SessionExpirySec
		if d.Frame.AliasMax > 0 {
			aliasMax = int(d.Frame.AliasMax)
		}
	}
	g := &genCtx{
		id: genID(seq, d.Frame.ClientID, p.ID), seq: seq, clientID: d.Frame.ClientID,
		connect: p, cleanStart: clean, expirySec: expiry,
		aliasMaxUp: aliasMax,
		aliasUp:   map[int]string{}, aliasDn: map[int]string{},
		lastVTime: p.Clock.VTimeMs,
	}
	e.gens = append(e.gens, g)
	e.current = g

	payload := map[string]any{
		"client_id":        g.clientID,
		"seq":              g.seq,
		"clean_start":      clean,
		"session_expiry_s": expiry,
		"session_expiry_unit": "second",
		"topic_alias_max_c2s": aliasMax,
		"connect_vtime_ms": p.Clock.VTimeMs,
		"connect_clock_basis": p.Clock.VTimeBasis,
		"connect_clock_source": p.Clock.Source,
		"connect_clock_unit":   p.Clock.Unit,
	}
	b := basis(e.ruleVer, "gen-open", g.clientID, g.seq, clean, expiry, aliasMax,
		p.ID, p.Clock.VTimeMs, e.in.Params.ID)
	n := e.addNode("generation", g.id, g.id,
		fmt.Sprintf("session generation %d (%s)", g.seq, g.clientID),
		payload, []domain.Ref{pktRef(p)},
		[]domain.Ref{{Kind: "param", ID: e.in.Params.ID}}, b)
	_ = n
}

func (g *genCtx) closeVTimeSet() bool { return g.closeVTime != 0 || g.closeKind != "" }

func (e *engine) handleDisconnect(p *domain.Packet) {
	if e.current == nil {
		e.diagPacket(p, "orphan-disconnect", "DISCONNECT without an open generation")
		return
	}
	g := e.current
	g.disconnect = p
	g.closed = true
	g.closeVTime = p.Clock.VTimeMs
	g.closeKind = "disconnect-packet"
	d, err := codec.Decode(p.Raw)
	if err == nil && d.Frame.SessionExpirySec > 0 {
		v := d.Frame.SessionExpirySec
		g.overrideSec = &v
	}
}

func (e *engine) diagPacket(p *domain.Packet, code, msg string) {
	id := "diag-" + p.ID
	var genID string
	if e.current != nil {
		genID = e.current.id
	}
	payload := map[string]any{
		"packet": p.ID, "code": code, "message": msg,
		"vtime_ms": vtimeOf(p), "clock_basis": e.in.Params.ClockBasis,
	}
	b := basis(e.ruleVer, "diag", p.ID, code, msg, p.Raw)
	n := e.addNode("diagnostic", id, genID, "diagnostic: "+code, payload,
		[]domain.Ref{pktRef(p)}, nil, b)
	e.ev(domain.EvReplay, domain.PrincipleUnconvertibleKept, msg,
		map[string]any{"code": code, "packet": p.ID, "node": n.ID},
		[]domain.Ref{pktRef(p), nodeRef(n)}, vtimeOf(p))
}

func (e *engine) genScope(g *genCtx) string {
	if e.naive {
		return "GLOBAL"
	}
	return g.id
}

func (e *engine) flowKey(g *genCtx, dir string, pid int) string {
	if e.naive {
		return fmt.Sprintf("GLOBAL|%s|%d", dir, pid)
	}
	return fmt.Sprintf("%s|%s|%d", g.id, dir, pid)
}

func (e *engine) pidNote(g *genCtx, dir string, pid int, p *domain.Packet) {
	if g.seq == 1 || pid == 0 {
		return
	}
	if e.naive {
		return
	}
	for _, prev := range e.gens[:g.seq-1] {
		key := e.flowKey(prev, dir, pid)
		if fl, ok := e.flows[key]; ok {
			e.ev(domain.EvReplay, domain.PrinciplePacketIDScope,
				fmt.Sprintf("packet id %d reused in a new generation; not matched to generation %s", pid, prev.seq),
				map[string]any{
					"packet": p.ID, "packet_id": pid, "direction": dir,
					"generation": g.id, "previous_generation": prev.id,
					"previous_flow": fl.node.ID, "scope": "session-generation",
				},
				[]domain.Ref{pktRef(p), nodeRef(fl.node)}, p.Clock.VTimeMs)
		}
	}
}

var _ = strconv.Itoa
