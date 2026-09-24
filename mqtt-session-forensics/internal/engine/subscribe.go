package engine

import (
	"fmt"
	"sort"

	"github.com/example/mqtt-session-forensics/internal/model"
)

func (e *Engine) onSubscribe(p *model.RawPacket) {
	cr := e.conns[p.ConnectionID]
	if cr == nil {
		e.addDiag(model.SevWarning, "subscribe_without_generation", p.ID+" has no generation", "", p.ID)
		return
	}
	gr := e.gens[cr.genUID]
	v := p.View
	for _, f := range v.Filters {
		key := filterKey(cr.clientID, f.Topic)
		n, ok := gr.subs[key]
		if !ok {
			n = &model.SubscriptionNode{
				UID: "sub:" + key, Kind: model.NodeSubscription, GenUID: gr.node.UID,
				ClientID: cr.clientID, Filter: f.Topic,
			}
			gr.subs[key] = n
			e.subOut[n.UID] = n
			e.order = append(e.order, "S:"+n.UID)
		}
		n.Active = true
		n.MaxQoS = f.QoS
		n.Changes = append(n.Changes, model.SubChange{
			Action: "subscribe", QoS: f.QoS, PacketVersion: p.ID, AtNS: p.ObservedAt.EpochNS})
		n.Sources = append(n.Sources, srcPkt(p, "filters"))
	}
}

func (e *Engine) onSuback(p *model.RawPacket) {
	cr := e.conns[p.ConnectionID]
	if cr == nil || len(p.View.Grants) == 0 {
		return
	}
	gr := e.gens[cr.genUID]
	// Map grants by filter ordinal onto the currently-pending subscriptions.
	var pending []*model.SubscriptionNode
	for _, n := range gr.subs {
		if len(n.Changes) > 0 && n.Changes[len(n.Changes)-1].Action == "subscribe" {
			pending = append(pending, n)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].Changes[len(pending[i].Changes)-1].AtNS <
			pending[j].Changes[len(pending[j].Changes)-1].AtNS
	})
	for i, g := range p.View.Grants {
		if i >= len(pending) {
			break
		}
		n := pending[i]
		last := &n.Changes[len(n.Changes)-1]
		last.QoS = g & 0x03
		n.MaxQoS = g & 0x03
	}
}

func (e *Engine) onUnsubscribe(p *model.RawPacket) {
	cr := e.conns[p.ConnectionID]
	if cr == nil {
		return
	}
	gr := e.gens[cr.genUID]
	for _, f := range vFilters(p) {
		key := filterKey(cr.clientID, f.Topic)
		n, ok := gr.subs[key]
		if !ok {
			e.addDiag(model.SevInfo, "unsubscribe_unknown_filter",
				fmt.Sprintf("%s unsubscribes unknown filter %s", p.ID, f.Topic), gr.node.UID, p.ID)
			continue
		}
		n.Active = false
		n.Changes = append(n.Changes, model.SubChange{
			Action: "unsubscribe", PacketVersion: p.ID, AtNS: p.ObservedAt.EpochNS})
		n.Sources = append(n.Sources, srcPkt(p, "filters"))
	}
}

func vFilters(p *model.RawPacket) []model.SubFilter {
	if p.View == nil {
		return nil
	}
	return p.View.Filters
}
