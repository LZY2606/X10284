package mqtt

import (
	"fmt"
	"strings"
)

// BrokerSnapshot is the imported broker session snapshot: retained messages
// and live subscriptions known before the trace starts.
type BrokerSnapshot struct {
	ClientID string            `json:"client_id"`
	Retained map[string]string `json:"retained"` // topic -> payload hex
}

type RetainedChange struct {
	ID         string `json:"id"`
	Gen        string `json:"gen"`
	Packet     string `json:"packet"`
	ClockMS    int64  `json:"clock_ms"`
	Topic      string `json:"topic"`
	Op         string `json:"op"` // set|delete
	PayloadHex string `json:"payload_hex,omitempty"`
}

type RetainedEntry struct {
	Topic      string `json:"topic"`
	PayloadHex string `json:"payload_hex"`
	SetBy      string `json:"set_by"` // packet id
	Gen        string `json:"gen"`
}

// RetainedDelivery is a retained message sent because of a subscription.
// Retained deliveries are kept strictly separate from queued session
// messages.
type RetainedDelivery struct {
	ID      string `json:"id"`
	Gen     string `json:"gen"`
	Packet  string `json:"packet"` // subscribe packet that triggered it
	Topic   string `json:"topic"`
	ClockMS int64  `json:"clock_ms"`
}

type Retained struct {
	Changes    []RetainedChange   `json:"changes"`
	Deliveries []RetainedDelivery `json:"deliveries"`
	Final      []RetainedEntry    `json:"final"`
}

type SubChange struct {
	ID      string `json:"id"`
	Gen     string `json:"gen"`
	Packet  string `json:"packet"`
	ClockMS int64  `json:"clock_ms"`
	Op      string `json:"op"` // subscribe|unsubscribe
	Topic   string `json:"topic"`
	QoS     int    `json:"qos"`
}

type Subs struct {
	Changes []SubChange    `json:"changes"`
	Active  []Subscription `json:"active"` // carried across persisted generations
}

func topicMatch(filter, topic string) bool {
	f, t := strings.Split(filter, "/"), strings.Split(topic, "/")
	for i, part := range f {
		if part == "#" {
			return true
		}
		if i >= len(t) {
			return false
		}
		if part != "+" && part != t[i] {
			return false
		}
	}
	return len(f) == len(t)
}

// AnalyzeState replays retained mutations and subscription changes. A
// retained PUBLISH with an empty payload deletes the retained entry.
// Subscriptions persist across generations only when the session persisted.
func AnalyzeState(pkts []Packet, s Sessions, snap BrokerSnapshot) (Retained, Subs) {
	byID := map[string]Packet{}
	for _, p := range pkts {
		byID[p.ID] = p
	}
	var ret Retained
	var subs Subs
	store := map[string]RetainedEntry{}
	for topic, payload := range snap.Retained {
		store[topic] = RetainedEntry{Topic: topic, PayloadHex: payload, SetBy: "snapshot", Gen: "gen-0"}
	}
	active := map[string]Subscription{}
	chgN, delN := 0, 0
	for _, gen := range s.Generations {
		if gen.CarriedFrom == "" && gen.Index > 1 {
			active = map[string]Subscription{} // session expired: subscriptions gone
		}
		for _, pid := range gen.Packets {
			p := byID[pid]
			switch p.Type {
			case PUBLISH:
				if !p.Retain || p.Dir != C2B {
					continue
				}
				chgN++
				op := "set"
				if p.PayloadHex == "" {
					op = "delete"
					delete(store, p.Topic)
				} else {
					store[p.Topic] = RetainedEntry{Topic: p.Topic, PayloadHex: p.PayloadHex, SetBy: p.ID, Gen: gen.ID}
				}
				ret.Changes = append(ret.Changes, RetainedChange{
					ID: fmt.Sprintf("ret-%02d", chgN), Gen: gen.ID, Packet: p.ID,
					ClockMS: p.ClockMS, Topic: p.Topic, Op: op, PayloadHex: p.PayloadHex,
				})
			case SUBSCRIBE:
				for _, sub := range p.Subs {
					chgN++
					active[sub.Topic] = sub
					subs.Changes = append(subs.Changes, SubChange{
						ID: fmt.Sprintf("sub-%02d", chgN), Gen: gen.ID, Packet: p.ID,
						ClockMS: p.ClockMS, Op: "subscribe", Topic: sub.Topic, QoS: sub.QoS,
					})
					for topic := range store {
						if topicMatch(sub.Topic, topic) {
							delN++
							ret.Deliveries = append(ret.Deliveries, RetainedDelivery{
								ID: fmt.Sprintf("rdel-%02d", delN), Gen: gen.ID, Packet: p.ID,
								Topic: topic, ClockMS: p.ClockMS,
							})
						}
					}
				}
			case UNSUBSCRIBE:
				for _, sub := range p.Subs {
					chgN++
					delete(active, sub.Topic)
					subs.Changes = append(subs.Changes, SubChange{
						ID: fmt.Sprintf("sub-%02d", chgN), Gen: gen.ID, Packet: p.ID,
						ClockMS: p.ClockMS, Op: "unsubscribe", Topic: sub.Topic,
					})
				}
			}
		}
	}
	for _, e := range store {
		ret.Final = append(ret.Final, e)
	}
	for _, sub := range active {
		subs.Active = append(subs.Active, sub)
	}
	return ret, subs
}
