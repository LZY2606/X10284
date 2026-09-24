package engine

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/example/mqtt-session-forensics/internal/model"
)

func itoa(i int) string { return strconv.Itoa(i) }

func (e *Engine) aliasNode(connID, genUID string) *model.AliasNode {
	uid := "alias:" + connID
	if n, ok := e.aliasOut[uid]; ok {
		return n
	}
	n := &model.AliasNode{
		UID: uid, Kind: model.NodeAlias, ConnectionID: connID, GenUID: genUID,
		Mappings: map[uint16]string{},
	}
	e.aliasOut[uid] = n
	e.order = append(e.order, "A:"+uid)
	return n
}

// resolveGeneration finds the generation in whose scope a packet id must be
// interpreted. When the same id is live in more than one generation, every
// candidate is retained and the connection-scoped generation is chosen
// provisionally (never silently merged).
func (e *Engine) resolveGeneration(p *model.RawPacket, cr *connRuntime) (*genRuntime, string, []string, bool) {
	var candidates []string
	chosen := ""
	if cr != nil {
		chosen = cr.genUID
		if _, ok := e.gens[cr.genUID]; ok {
			candidates = append(candidates, cr.genUID)
		}
	}
	hint := p.ClientIDHint
	if cr != nil {
		hint = cr.clientID
	}
	keys := make([]string, 0, len(e.gens))
	for k := range e.gens {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		gr := e.gens[k]
		if chosen != "" && gr.node.UID == chosen {
			continue
		}
		if hint != "" && gr.node.ClientID != hint {
			continue
		}
		if gr.node.State == model.GenOpened || gr.node.State == model.GenDisconnected {
			candidates = append(candidates, gr.node.UID)
		}
	}
	if chosen == "" && len(candidates) > 0 {
		chosen = candidates[0]
	}
	if chosen == "" {
		e.addDiag(model.SevCritical, "no_generation_scope",
			p.ID+" packet id cannot be bound to any session generation", "", p.ID)
		return nil, "", nil, false
	}
	return e.gens[chosen], chosen, candidates, len(candidates) > 1
}

func (e *Engine) emitConfusion(p *model.RawPacket, chosen string, candidates []string) {
	uid := "conf:" + p.ID
	if _, exists := e.confusionOut[uid]; exists {
		return
	}
	n := &model.ConfusionNode{
		UID: uid, Kind: model.NodeConfusion, PacketID: p.View.PacketID,
		PacketRef:  model.SourceRef{Kind: "packet", ID: p.ID},
		Candidates: candidates, Chosen: chosen,
		Rule: "packet id is interpreted only within the connection's current session generation; other generations stay candidates",
		Sources: []model.SourceRef{{Kind: "packet", ID: p.ID}},
		Diagnostics: []model.Diagnostic{{Severity: model.SevWarning, Code: "packetid_cross_generation",
			Message: fmt.Sprintf("%s packet id %d is live in multiple generations", p.ID, p.View.PacketID), PacketID: p.ID}},
	}
	e.confusionOut[uid] = n
	e.order = append(e.order, "X:"+uid)
}

// findFlow returns the incarnation an ack belongs to: prefer a non-completed
// flow, otherwise the most recently opened incarnation (packet id reuse).
func (e *Engine) findFlow(gr *genRuntime, pid uint16, dir model.Direction) *model.FlowNode {
	incarnations := gr.flows[pid][dir]
	var recent *model.FlowNode
	for i := range incarnations {
		f := incarnations[i]
		recent = f
		if f.Phase != model.PhaseQ1Done && f.Phase != model.PhaseQ2Done {
			return f
		}
	}
	return recent
}

func (e *Engine) flowFor(gr *genRuntime, pid uint16, dir model.Direction, qos uint8,
	topic string, retain bool, p *model.RawPacket) *model.FlowNode {
	byDir, ok := gr.flows[pid]
	if !ok {
		byDir = map[model.Direction][]*model.FlowNode{}
		gr.flows[pid] = byDir
	}
	// Packet id reuse: opening PUBLISH after the previous incarnation completed
	// starts a new incarnation rather than corrupting the old one.
	var existing *model.FlowNode
	if incs := byDir[dir]; len(incs) > 0 {
		existing = incs[len(incs)-1]
	}
	if existing != nil && !p.View.DUP &&
		(existing.Phase == model.PhaseQ1Done || existing.Phase == model.PhaseQ2Done) {
		existing = nil
	}
	if existing != nil {
		return existing
	}
	uid := fmt.Sprintf("flow:%s:%d:%s:%d", gr.node.UID, pid, dir, len(byDir[dir])+1)
	f := &model.FlowNode{
		UID: uid, Kind: model.NodeFlow, GenUID: gr.node.UID, ClientID: gr.node.ClientID,
		PacketID: pid, Direction: dir, QoS: qos, Topic: topic, Retain: retain,
		Phase: model.PhasePub,
		Sources: []model.SourceRef{srcPkt(p, "packet_id"), srcPkt(p, "dup"),
			srcPkt(p, "qos"), srcPkt(p, "retain"), srcPkt(p, "observed_at")},
	}
	byDir[dir] = append(byDir[dir], f)
	gr.flowOrder[uid] = f
	e.flowUIDs[uid] = true
	e.order = append(e.order, "F:"+uid)
	return f
}

func (e *Engine) correspondence(gr *genRuntime, pid uint16, p *model.RawPacket, outcome string) {
	uid := fmt.Sprintf("corr:%s:%d", gr.node.UID, pid)
	n, ok := e.corrOut[uid]
	if !ok {
		n = &model.CorrespondenceNode{
			UID: uid, Kind: model.NodeCorrespond, GenUID: gr.node.UID,
			PacketID: pid, Outcome: outcome,
		}
		e.corrOut[uid] = n
		e.order = append(e.order, "C:"+uid)
	}
	ref := model.SourceRef{Kind: "packet", ID: p.ID}
	n.Members = append(n.Members, ref)
	n.Sources = append(n.Sources, ref)
	n.Count = len(n.Members)
}

func (e *Engine) applyRetained(p *model.RawPacket, topic string) {
	if topic == "" {
		e.addDiag(model.SevWarning, "retained_no_topic",
			p.ID+" retained PUBLISH has no resolvable topic", "", p.ID)
		return
	}
	n, ok := e.retained[topic]
	if !ok {
		n = &model.RetainedNode{UID: "retain:" + topic, Kind: model.NodeRetained, Topic: topic}
		e.retained[topic] = n
		e.order = append(e.order, "R:"+n.UID)
	}
	ch := model.RetainChange{PacketVersion: p.ID, AtNS: p.ObservedAt.EpochNS}
	if len(p.View.Payload) == 0 && p.View.Payload == "" {
		n.Alive = false
		n.Payload = ""
		ch.Action = "delete"
	} else {
		n.Alive = true
		n.Payload = p.View.Payload
		ch.Action = "store"
	}
	n.History = append(n.History, ch)
	n.Sources = append(n.Sources, srcPkt(p, "retain"))
}

func (e *Engine) defaultLegacyExpiry() uint32 {
	if v, ok := e.bundle.Params["mqtt311_session_expiry_seconds"]; ok {
		if n, err := strconv.ParseUint(v.Value, 10, 32); err == nil {
			return uint32(n)
		}
	}
	return 0
}

// splitFilter handles trivial comma-free filters; fixtures use literal filters.
func filterKey(clientID, filter string) string {
	return clientID + "|" + filter
}
