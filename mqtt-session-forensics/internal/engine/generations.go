package engine

import (
	"fmt"
	"sort"

	"github.com/example/mqtt-session-forensics/internal/model"
)

// resumeVerdict classifies a CONNECT against the previous generation of the
// same client using virtual-time expiry semantics.
func (e *Engine) resumeVerdict(prev *genRuntime, cleanStart bool, openNS int64) string {
	if cleanStart {
		return "new_clean_start"
	}
	if prev == nil {
		return "new_no_prior"
	}
	if prev.node.State == model.GenOpened || prev.node.State == model.GenResumed || prev.node.State == model.GenFresh {
		// Previous transport never observed a close: treat as continuation.
		return "attach"
	}
	window := int64(prev.node.SessionExpiryS) * nsPerS
	expiryAt := prev.node.CloseAtNS + window
	switch {
	case openNS < expiryAt:
		return "resume"
	case openNS > expiryAt:
		return "new_expired"
	default:
		return "boundary_ambiguous"
	}
}

func (e *Engine) openGeneration(p *model.RawPacket, cid string, serial int, expiry uint32) *genRuntime {
	v := p.View
	uid := fmt.Sprintf("gen:%s#%d", cid, serial)
	gn := &model.GenerationNode{
		UID: uid, Kind: model.NodeGeneration, ClientID: cid, GenSerial: serial,
		ConnectionID: p.ConnectionID, Connections: []string{p.ConnectionID},
		ProtoLevel: v.ProtoLevel, CleanStart: v.CleanStart, SessionExpiryS: expiry,
		State: model.GenOpened, OpenAtNS: p.ObservedAt.EpochNS,
		Sources: []model.SourceRef{srcPkt(p, "clean_start"), srcPkt(p, "session_expiry"), srcPkt(p, "observed_at")},
	}
	gr := &genRuntime{node: gn,
		flows:     map[uint16]map[model.Direction][]*model.FlowNode{},
		flowOrder: map[string]*model.FlowNode{}, subs: map[string]*model.SubscriptionNode{}}
	e.gens[uid] = gr
	e.genByClientSerial[cid+"#"+itoa(serial)] = gr
	e.lastGen[cid] = gr
	e.genOut[uid] = gn
	e.order = append(e.order, "G:"+uid)
	return gr
}

func (e *Engine) recordExpiryNode(prev *genRuntime, nextUID string, reopenAt int64, verdict string, paramName string) *model.ExpiryNode {
	window := int64(prev.node.SessionExpiryS) * nsPerS
	expiryAt := prev.node.CloseAtNS + window
	uid := fmt.Sprintf("expiry:%s:to:%s", prev.node.UID, nextUID)
	n := &model.ExpiryNode{
		UID: uid, Kind: model.NodeExpiry, ClientID: prev.node.ClientID, GenUID: prev.node.UID,
		CloseAtNS: prev.node.CloseAtNS, ExpiryAtNS: expiryAt, ReopenAtNS: reopenAt,
		WindowNS: window, Parameter: paramName,
		Sources: []model.SourceRef{
			{Kind: "node", ID: prev.node.UID},
			{Kind: "node", ID: nextUID},
			{Kind: "param", ID: paramName},
		},
	}
	switch verdict {
	case "resume", "attach":
		n.VerdictStr = "resumed"
		n.Reason = "reconnect precedes virtual-time expiry instant"
	case "new_expired":
		n.VerdictStr = "expired"
		n.Reason = "reconnect follows virtual-time expiry instant"
	case "boundary_ambiguous":
		n.VerdictStr = "boundary_ambiguous"
		n.Candidates = []string{"resumed", "expired"}
		n.Reason = "reconnect coincides exactly with the expiry instant; MQTT leaves the boundary unspecified, both candidates retained"
	}
	e.expiryOut[uid] = n
	if _, tracked := e.expiryTracked[uid]; !tracked {
		e.order = append(e.order, "E:"+uid)
		e.expiryTracked[uid] = true
	}
	return n
}

func (e *Engine) generationsOf(client string) []*genRuntime {
	var out []*genRuntime
	for _, gr := range e.gens {
		if gr.node.ClientID == client {
			out = append(out, gr)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].node.GenSerial < out[j].node.GenSerial })
	return out
}
