package engine

import (
	"fmt"

	"github.com/example/mqtt-session-forensics/internal/model"
	"github.com/example/mqtt-session-forensics/internal/mqtt"
)

func (e *Engine) replay(p *model.RawPacket, raw []byte) {
	v := p.View
	if v == nil {
		return
	}
	if v.Malformed != "" {
		e.addDiag(model.SevCritical, "packet_malformed",
			fmt.Sprintf("%s: %s", p.ID, v.Malformed), "", p.ID)
	}
	switch v.Type {
	case 1:
		e.onConnect(p, raw)
	case 2:
		e.onConnack(p)
	case 3:
		e.onPublish(p, raw)
	case 4, 5, 6, 7:
		e.onAck(p)
	case 8:
		e.onSubscribe(p)
	case 9:
		e.onSuback(p)
	case 10:
		e.onUnsubscribe(p)
	case 14:
		e.onDisconnect(p)
	}
}

func (e *Engine) onConnect(p *model.RawPacket, raw []byte) {
	v := p.View
	cid := v.ClientID
	if cid == "" {
		cid = p.ClientIDHint
	}
	if cid == "" {
		e.addDiag(model.SevWarning, "connect_without_clientid",
			p.ID+" has no client id; assigning synthetic id", "", p.ID)
		cid = "synthetic:" + p.ConnectionID
	}
	expiry := uint32(0)
	switch {
	case v.HasSessionExpiry:
		expiry = v.SessionExpiry
	case v.ProtoLevel == 4:
		expiry = e.defaultLegacyExpiry()
	}

	prev := e.lastGen[cid]
	verdict := e.resumeVerdict(prev, v.CleanStart, p.ObservedAt.EpochNS)
	var gr *genRuntime
	switch verdict {
	case "resume", "attach", "boundary_ambiguous":
		gr = prev
		gr.node.Connections = append(gr.node.Connections, p.ConnectionID)
		gr.node.Reconnected = true
		gr.node.State = model.GenOpened
		gr.node.Sources = append(gr.node.Sources, srcPkt(p, "session_expiry"))
		an := e.aliasNode(p.ConnectionID, gr.node.UID)
		e.bindConn(p, gr, an, v.ProtoLevel)
		an.Reset = true
		an.Events = append(an.Events, model.AliasEvent{Action: "reset", PacketVersion: p.ID, AtNS: p.ObservedAt.EpochNS})
		n := e.recordExpiryNode(prev, gr.node.UID, p.ObservedAt.EpochNS, verdict,
			e.expiryParamName(prev.node.ProtoLevel))
		if verdict == "resume" {
			e.addDiag(model.SevInfo, "session_resume",
				p.ID+" resumes persistent generation "+gr.node.UID+" ("+n.Reason+")",
				gr.node.UID, p.ID)
		}
		if verdict == "boundary_ambiguous" {
			e.addDiag(model.SevWarning, "expiry_boundary_ambiguous",
				p.ID+" lands exactly on the expiry instant; candidates retained", gr.node.UID, p.ID)
		}
	default: // new_clean_start | new_no_prior | new_expired | boundary handled as new below
		serial := 1
		if prev != nil {
			serial = prev.node.GenSerial + 1
		}
		gr = e.openGeneration(p, cid, serial, expiry)
		an := e.aliasNode(p.ConnectionID, gr.node.UID)
		e.bindConn(p, gr, an, v.ProtoLevel)
		an.Reset = true
		an.Events = append(an.Events, model.AliasEvent{Action: "reset", PacketVersion: p.ID, AtNS: p.ObservedAt.EpochNS})
		if prev != nil {
			n := e.recordExpiryNode(prev, gr.node.UID, p.ObservedAt.EpochNS, verdict,
				e.expiryParamName(prev.node.ProtoLevel))
			if verdict == "new_expired" || verdict == "new_clean_start" {
				prev.node.State = model.GenExpired
				if verdict == "new_clean_start" {
					n.VerdictStr = "discarded_by_clean_start"
					n.Reason = "clean start discards any existing session state immediately"
				} else {
					e.addDiag(model.SevInfo, "session_expired",
						p.ID+" starts a new generation because the prior one expired (virtual time)",
						gr.node.UID, p.ID)
				}
			}
			_ = n
		}
		if v.CleanStart {
			e.addDiag(model.SevInfo, "clean_start",
				p.ID+" opens "+gr.node.UID+" with clean start", gr.node.UID, p.ID)
		}
	}
}

func (e *Engine) expiryParamName(level byte) string {
	if level == 4 {
		return "mqtt311_session_expiry_seconds"
	}
	return "connect.session_expiry_interval"
}

func (e *Engine) bindConn(p *model.RawPacket, gr *genRuntime, an *model.AliasNode, level byte) {
	cr := &connRuntime{id: p.ConnectionID, genUID: gr.node.UID, clientID: gr.node.ClientID,
		aliases: map[uint16]string{}, aliasNode: an, level: level}
	e.conns[p.ConnectionID] = cr
	an.GenUID = gr.node.UID
}

func (e *Engine) onConnack(p *model.RawPacket) {
	cr := e.conns[p.ConnectionID]
	if cr == nil {
		e.addDiag(model.SevWarning, "connack_without_connect",
			p.ID+" CONNACK with no CONNECT on connection", "", p.ID)
		return
	}
	gr := e.gens[cr.genUID]
	v := p.View
	if v.SessionPresent {
		// Resumed transport bound to an existing generation; a fresh generation
		// claiming session present is broker evidence worth surfacing.
		if gr.node.Reconnected {
			gr.node.State = model.GenResumed
		} else {
			e.addDiag(model.SevWarning, "session_present_unexpected",
				p.ID+" CONNACK session present on a brand-new generation", gr.node.UID, p.ID)
			gr.node.State = model.GenResumed
		}
	} else if gr.node.State == model.GenOpened && !gr.node.Reconnected {
		gr.node.State = model.GenFresh
	}
	gr.node.Sources = append(gr.node.Sources, srcPkt(p, "session_present"))
	if v.SessionPresent && gr.node.CleanStart && gr.node.ProtoLevel == 5 && !gr.node.Reconnected {
		e.addDiag(model.SevWarning, "session_present_with_clean_start",
			"MQTT5 CONNACK session present although clean start was set", gr.node.UID, p.ID)
	}
}

func (e *Engine) onPublish(p *model.RawPacket, raw []byte) {
	cr := e.conns[p.ConnectionID]
	v := p.View
	if cr != nil && cr.level == 5 {
		view := mqtt.DecodeAtLevel(*v, raw, 5)
		v = &view
		p.View = v
	}
	topic := v.Topic
	if cr != nil {
		if v.TopicAliasSet {
			if v.TopicAlias == 0 {
				e.addDiag(model.SevCritical, "alias_zero",
					p.ID+" uses topic alias 0", cr.aliasNode.UID, p.ID)
			} else {
				cr.aliases[v.TopicAlias] = v.Topic
				if v.Topic != "" {
					cr.aliasNode.Mappings[v.TopicAlias] = v.Topic
					cr.aliasNode.Events = append(cr.aliasNode.Events, model.AliasEvent{
						Alias: v.TopicAlias, Topic: v.Topic, Action: "map",
						PacketVersion: p.ID, AtNS: p.ObservedAt.EpochNS})
				}
			}
		} else if v.TopicAlias > 0 {
			mapped, ok := cr.aliases[v.TopicAlias]
			if !ok {
				topic = ""
				cr.aliasNode.Events = append(cr.aliasNode.Events, model.AliasEvent{
					Alias: v.TopicAlias, Action: "use_unknown",
					PacketVersion: p.ID, AtNS: p.ObservedAt.EpochNS})
				e.addDiag(model.SevCritical, "alias_unknown",
					fmt.Sprintf("%s references undefined topic alias %d", p.ID, v.TopicAlias),
					cr.aliasNode.UID, p.ID)
			} else {
				topic = mapped
				cr.aliasNode.Events = append(cr.aliasNode.Events, model.AliasEvent{
					Alias: v.TopicAlias, Topic: mapped, Action: "use",
					PacketVersion: p.ID, AtNS: p.ObservedAt.EpochNS})
			}
		}
	}
	if v.Retain {
		e.applyRetained(p, topic)
	}
	if v.QoS == 0 || !v.HasPacketID {
		return
	}
	gr, chosen, candidates, confusion := e.resolveGeneration(p, cr)
	if gr == nil {
		return
	}
	if confusion {
		e.emitConfusion(p, chosen, candidates)
	}
	flow := e.flowFor(gr, v.PacketID, p.Direction, v.QoS, topic, v.Retain, p)
	obs := model.FlowObs{PacketVersionID: p.ID, Type: "PUBLISH", DUP: v.DUP,
		AtNS: p.ObservedAt.EpochNS, TimeOriginal: p.ObservedAt.Original, TimeUnit: p.ObservedAt.Unit}
	if v.DUP {
		if flow.Phase != model.PhasePub {
			// Retransmission after progress: idempotent, but the previously
			// reached handshake phase must not be rolled back.
			flow.IdempotentDup = true
			obs.Note = "DUP retransmission: absorbed as idempotent; phase preserved (" + string(flow.Phase) + ")"
		} else {
			obs.Note = "DUP retransmission of the opening PUBLISH"
		}
		e.correspondence(gr, v.PacketID, p, "idempotent")
	}
	flow.Observations = append(flow.Observations, obs)
}

func (e *Engine) onAck(p *model.RawPacket) {
	cr := e.conns[p.ConnectionID]
	v := p.View
	gr, chosen, candidates, confusion := e.resolveGeneration(p, cr)
	if gr == nil {
		return
	}
	if confusion {
		e.emitConfusion(p, chosen, candidates)
	}
	dir := ackDirection(p.Direction, v.Type)
	flow := e.findFlow(gr, v.PacketID, dir)
	if flow == nil {
		// An ack without its PUBLISH on this generation: packet id from another
		// generation must never be interpreted here.
		e.addDiag(model.SevCritical, "orphan_ack",
			fmt.Sprintf("%s %s packet id %d has no open flow in %s",
				p.ID, v.TypeName, v.PacketID, gr.node.UID),
			gr.node.UID, p.ID)
		return
	}
	advance(flow, v.Type, p)
}

func advance(flow *model.FlowNode, ackType byte, p *model.RawPacket) {
	note := ""
	switch ackType {
	case 4: // PUBACK
		if flow.QoS != 1 {
			note = "PUBACK on non-QoS1 flow"
		}
		flow.Phase = model.PhaseQ1Done
	case 5: // PUBREC
		if flow.Phase == model.PhaseRecd || flow.Phase == model.PhaseRelSent || flow.Phase == model.PhaseQ2Done {
			flow.IdempotentDup = true // duplicate PUBREC keeps phase
		}
		if flow.Phase == model.PhasePub || flow.Phase == model.PhaseStuck {
			// First PUBREC after open, or broker re-driving a handshake that
			// was interrupted before PUBREL: idempotent resume, never restart.
			flow.Phase = model.PhaseRecd
			flow.Resumed = flow.Interrupted
		}
	case 6: // PUBREL
		if flow.Phase == model.PhaseQ2Done {
			flow.IdempotentDup = true
		}
		flow.Phase = model.PhaseRelSent
		flow.Resumed = true
	case 7: // PUBCOMP
		if flow.Phase == model.PhaseQ2Done {
			flow.IdempotentDup = true
		}
		flow.Phase = model.PhaseQ2Done
		flow.Interrupted = false
	}
	flow.Observations = append(flow.Observations, model.FlowObs{
		PacketVersionID: p.ID, Type: p.View.TypeName, DUP: p.View.DUP,
		AtNS: p.ObservedAt.EpochNS, TimeOriginal: p.ObservedAt.Original,
		TimeUnit: p.ObservedAt.Unit, Note: note})
}

// ackDirection maps an acknowledgement packet to the direction of the flow it
// belongs to. PUBACK/PUBREC/PUBCOMP received C2B acknowledge a broker-published
// (B2C) flow; PUBREL received C2B belongs to the client-published (C2B) flow.
func ackDirection(d model.Direction, ackType byte) model.Direction {
	if d == model.DirC2B {
		if ackType == 6 {
			return model.DirC2B
		}
		return model.DirB2C
	}
	if ackType == 6 {
		return model.DirB2C
	}
	return model.DirC2B
}
