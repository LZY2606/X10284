// Package casepack is the offline case "MQTT 会话印迹：QoS 握手、持久状态与
// 重连去重回放". An IoT team imports a bidirectional MQTT packet trace, a
// client id and a broker session snapshot, and rebuilds QoS 1/2 handshakes,
// subscriptions and retained state. The trace deliberately walks through
// packet id reuse, DUP retransmission, a QoS 2 mid-disconnect, the session
// expiry endpoint, a topic alias reset, a retained delete and
// multi-generation confusion.
package casepack

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"mqttlab/internal/derive"
	"mqttlab/internal/mqtt"
	"mqttlab/internal/store"
)

func u16(v int) *uint16  { x := uint16(v); return &x }
func u32(v int) *uint32  { x := uint32(v); return &x }
func hx(b []byte) string { return hex.EncodeToString(b) }

// Trace is the imported bidirectional packet trace. Clocks are virtual
// milliseconds (mqtt.BasisVirtual); raw bytes are real MQTT 5 wire encoding.
func Trace() []mqtt.TraceEntry {
	e := func(dir mqtt.Direction, clock int64, b []byte) mqtt.TraceEntry {
		return mqtt.TraceEntry{Dir: dir, ClockMS: clock, Hex: hx(b)}
	}
	C, B := mqtt.C2B, mqtt.B2C
	return []mqtt.TraceEntry{
		// generation 1: clean start, QoS 1 + QoS 2 handshakes, DUP retransmit
		e(C, 0, mqtt.EncodeCONNECT("sensor-01", true, 30, u32(60))),
		e(B, 5, mqtt.EncodeCONNACK(false)),
		e(C, 10, mqtt.EncodeSUBSCRIBE(1, mqtt.Subscription{Topic: "site/a/#", QoS: 1})),
		e(B, 15, mqtt.EncodeSUBACK(1)),
		e(B, 20, mqtt.EncodePUBLISH(false, 0, true, "site/a/temp", nil, nil, []byte("21.5"))),
		e(C, 30, mqtt.EncodePUBLISH(false, 1, false, "site/a/temp", u16(10), nil, []byte("22.0"))),
		e(B, 35, mqtt.EncodeAck(4, 10)),
		e(C, 40, mqtt.EncodePUBLISH(false, 2, false, "site/a/status", u16(11), nil, []byte("online"))),
		e(B, 45, mqtt.EncodeAck(5, 11)),
		e(C, 50, mqtt.EncodeAck(6, 11)),
		e(B, 55, mqtt.EncodeAck(7, 11)),
		e(C, 60, mqtt.EncodePUBLISH(false, 2, false, "site/a/hum", u16(12), nil, []byte("40"))),
		e(B, 65, mqtt.EncodeAck(5, 12)),
		e(C, 70, mqtt.EncodePUBLISH(true, 2, false, "site/a/hum", u16(12), nil, []byte("40"))), // DUP retransmission
		e(C, 75, mqtt.EncodeAck(6, 12)),
		e(B, 80, mqtt.EncodeAck(7, 12)),
		// QoS 2 mid-disconnect: PUBREC received, link drops before PUBREL
		e(C, 90, mqtt.EncodePUBLISH(false, 2, false, "site/a/batt", u16(13), nil, []byte("3.7"))),
		e(B, 95, mqtt.EncodeAck(5, 13)),
		// generation 2: session persisted (gap 4905ms < 60s expiry)
		e(C, 5000, mqtt.EncodeCONNECT("sensor-01", false, 30, u32(60))),
		e(B, 5005, mqtt.EncodeCONNACK(true)),
		e(C, 5010, mqtt.EncodePUBLISH(true, 2, false, "site/a/batt", u16(13), nil, []byte("3.7"))), // resume
		e(B, 5015, mqtt.EncodeAck(5, 13)),                                                          // duplicate PUBREC
		e(C, 5020, mqtt.EncodeAck(6, 13)),
		e(B, 5025, mqtt.EncodeAck(7, 13)),
		// topic alias registered then used
		e(C, 5030, mqtt.EncodePUBLISH(false, 1, false, "site/a/temp", u16(14), u16(1), []byte("22.4"))),
		e(B, 5035, mqtt.EncodeAck(4, 14)),
		e(C, 5040, mqtt.EncodePUBLISH(false, 1, false, "", u16(15), u16(1), []byte("22.6"))),
		e(B, 5045, mqtt.EncodeAck(4, 15)),
		// retained delete + retained set
		e(C, 5050, mqtt.EncodePUBLISH(false, 0, true, "site/a/status", nil, nil, nil)),
		e(C, 5060, mqtt.EncodePUBLISH(false, 0, true, "site/a/cfg", nil, nil, []byte(`{"rate":5}`))),
		// packet id reuse after completion inside one generation
		e(C, 5070, mqtt.EncodePUBLISH(false, 1, false, "site/a/temp", u16(14), u16(1), []byte("22.8"))),
		e(B, 5080, mqtt.EncodeAck(4, 14)),
		// generation 3: gap exactly 60000ms == session expiry endpoint
		e(C, 65080, mqtt.EncodeCONNECT("sensor-01", false, 30, u32(60))),
		e(B, 65085, mqtt.EncodeCONNACK(false)),
		// alias reset: alias 1 unknown in the new generation; packet id 14
		// reappears but must not be linked to generation 2 (multi-generation
		// confusion guard)
		e(C, 65090, mqtt.EncodePUBLISH(false, 1, false, "", u16(14), u16(1), []byte("23.0"))),
		e(B, 65095, mqtt.EncodeAck(4, 14)),
		e(C, 65100, mqtt.EncodePUBLISH(false, 1, false, "site/a/temp", u16(15), nil, []byte("23.1"))),
		e(B, 65105, mqtt.EncodeAck(4, 15)),
	}
}

// SnapshotV1 is the imported broker session snapshot (retained store before
// the trace). V3 is the localized source correction: one retained payload
// was mis-captured.
func SnapshotV1() mqtt.BrokerSnapshot {
	return mqtt.BrokerSnapshot{ClientID: "sensor-01", Retained: map[string]string{
		"site/a/temp": hx([]byte("21.5")),
	}}
}

func SnapshotV3() mqtt.BrokerSnapshot {
	return mqtt.BrokerSnapshot{ClientID: "sensor-01", Retained: map[string]string{
		"site/a/temp": hx([]byte("21.4")), // corrected capture
	}}
}

func ParamsV1() mqtt.Params { return mqtt.Params{ClockSkewToleranceMS: 0} }

// ParamsV2 is the parameter revision: clock-skew tolerance widens the
// session-expiry endpoint so the exactly-at-boundary reconnect becomes
// ambiguous and keeps both legal candidates.
func ParamsV2() mqtt.Params { return mqtt.Params{ClockSkewToleranceMS: 100} }

func decode[T any](raw json.RawMessage) T {
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		panic(fmt.Sprintf("casepack decode: %v", err))
	}
	return v
}

// Engine wires the dependency graph: sources are trace/snapshot/params,
// everything else is derived and only recomputed when its inputs change.
func Engine() *derive.Engine {
	return derive.New(
		derive.Node{Name: "packets", Inputs: []string{"trace"}, Compute: func(in map[string]json.RawMessage) (any, error) {
			entries := decode[[]mqtt.TraceEntry](in["trace"])
			pkts := make([]mqtt.Packet, 0, len(entries))
			for i, e := range entries {
				pkts = append(pkts, mqtt.Parse(e, i))
			}
			return pkts, nil
		}},
		derive.Node{Name: "sessions", Inputs: []string{"packets", "params"}, Compute: func(in map[string]json.RawMessage) (any, error) {
			return mqtt.Sessionize(decode[[]mqtt.Packet](in["packets"]), mqtt.Params{
				ClockSkewToleranceMS: decode[mqtt.Params](in["params"]).ClockSkewToleranceMS,
			}), nil
		}},
		derive.Node{Name: "flows", Inputs: []string{"packets", "sessions"}, Compute: func(in map[string]json.RawMessage) (any, error) {
			return mqtt.AnalyzeFlows(decode[[]mqtt.Packet](in["packets"]), decode[mqtt.Sessions](in["sessions"])), nil
		}},
		derive.Node{Name: "state", Inputs: []string{"packets", "sessions", "snapshot"}, Compute: func(in map[string]json.RawMessage) (any, error) {
			ret, subs := mqtt.AnalyzeState(decode[[]mqtt.Packet](in["packets"]), decode[mqtt.Sessions](in["sessions"]), decode[mqtt.BrokerSnapshot](in["snapshot"]))
			return struct {
				Retained mqtt.Retained `json:"retained"`
				Subs     mqtt.Subs     `json:"subs"`
			}{ret, subs}, nil
		}},
		derive.Node{Name: "decisions", Inputs: []string{"sessions", "flows", "state"}, Compute: func(in map[string]json.RawMessage) (any, error) {
			st := decode[struct {
				Retained mqtt.Retained `json:"retained"`
				Subs     mqtt.Subs     `json:"subs"`
			}](in["state"])
			return mqtt.BuildDecisions(decode[mqtt.Sessions](in["sessions"]), decode[mqtt.Flows](in["flows"]), st.Retained), nil
		}},
	)
}

func marshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func decisionEvents(arts map[string]store.ArtifactState, objs map[string]json.RawMessage, label string) []store.Event {
	var evs []store.Event
	st, ok := arts["decisions"]
	if !ok {
		return nil
	}
	body, ok := objs[st.ObjectID]
	if !ok {
		return nil
	}
	var d mqtt.Decisions
	if err := json.Unmarshal(body, &d); err != nil {
		return nil
	}
	for i, dec := range d.Decisions {
		b, _ := json.Marshal(dec)
		evs = append(evs, store.Event{
			ID: "ev-" + store.Hash("decision", dec.ID, st.ObjectID), Seq: i + 1,
			Kind: "decision", Body: b,
		})
	}
	return evs
}

// Load runs the case scenario into an empty store: initial import, a
// parameter revision, a localized source change, and two conflicting human
// rulings (the second one is left as an open conflict for the reviewer).
func Load(st *store.Store) error {
	head, err := st.Head("")
	if err != nil {
		return err
	}
	if head != "" {
		return nil // already loaded
	}
	eng := Engine()
	trace := marshal(Trace())
	params1 := marshal(ParamsV1())
	params2 := marshal(ParamsV2())
	snap1 := marshal(SnapshotV1())
	snap3 := marshal(SnapshotV3())

	commit := func(label, branch, expect string, srcs map[string]json.RawMessage, prev map[string]store.ArtifactState, extra []store.Event) (string, *derive.Result, error) {
		res, err := eng.Run(srcs, prev)
		if err != nil {
			return "", nil, err
		}
		evs := append(decisionEvents(res.Artifacts, res.Objects, label), extra...)
		id, err := st.Commit(label, branch, expect, res.Artifacts, res.Objects, evs)
		return id, res, err
	}

	// v1: initial import
	v1, r1, err := commit("v1 initial import: trace + broker snapshot + rule params", "", "",
		map[string]json.RawMessage{"trace": trace, "snapshot": snap1, "params": params1}, nil, nil)
	if err != nil {
		return err
	}
	// v2: parameter revision (clock-skew tolerance) — only sessions/decisions
	// and their dependents recompute
	v2, r2, err := commit("v2 parameter revision: clock-skew tolerance 0 -> 100ms", "", v1,
		map[string]json.RawMessage{"trace": trace, "snapshot": snap1, "params": params2}, r1.Artifacts, nil)
	if err != nil {
		return err
	}
	// v3: localized source change (one retained payload in the snapshot) —
	// only state/decisions recompute
	v3, r3, err := commit("v3 source fix: broker snapshot retained payload corrected", "", v2,
		map[string]json.RawMessage{"trace": trace, "snapshot": snap3, "params": params2}, r2.Artifacts, nil)
	if err != nil {
		return err
	}
	// conflicting human rulings on the ambiguous session-expiry endpoint.
	// Reviewer A rules on the mainline; reviewer B branches from the same
	// version and also tries the mainline — the second commit conflicts and
	// both candidates are preserved.
	ruling := func(decisionID, choice, reviewer string) store.Event {
		b, _ := json.Marshal(map[string]string{
			"decision": decisionID, "choice": choice, "reviewer": reviewer,
		})
		return store.Event{ID: "ev-" + store.Hash("ruling", decisionID, choice, reviewer), Seq: 100, Kind: "ruling", Body: b}
	}
	// find the ambiguous boundary decision id from v3
	var boundaryDec string
	if body, ok := r3.Objects[r3.Artifacts["decisions"].ObjectID]; ok {
		var d mqtt.Decisions
		_ = json.Unmarshal(body, &d)
		for _, dec := range d.Decisions {
			if dec.Kind == "session-expiry" && len(dec.Candidates) > 1 {
				boundaryDec = dec.ID
			}
		}
	}
	if boundaryDec == "" {
		return fmt.Errorf("casepack: expected an ambiguous session-expiry decision")
	}
	v4a, _, err := commit("v4 ruling: reviewer A adopts 'expired' at the expiry endpoint", "", v3,
		map[string]json.RawMessage{"trace": trace, "snapshot": snap3, "params": params2}, r3.Artifacts,
		[]store.Event{ruling(boundaryDec, "expired", "reviewer-a")})
	if err != nil {
		return err
	}
	// reviewer B's branch, kept for comparison
	if _, _, err := commit("v4b ruling: reviewer B adopts 'persisted'", "review-b", v3,
		map[string]json.RawMessage{"trace": trace, "snapshot": snap3, "params": params2}, r3.Artifacts,
		[]store.Event{ruling(boundaryDec, "persisted", "reviewer-b")}); err != nil {
		return err
	}
	// reviewer B also tries the mainline from the stale base: conflict
	_, _, err = commit("v4c ruling: reviewer B pushes 'persisted' to mainline", "", v3,
		map[string]json.RawMessage{"trace": trace, "snapshot": snap3, "params": params2}, r3.Artifacts,
		[]store.Event{ruling(boundaryDec, "persisted", "reviewer-b")})
	if err != nil && err != store.ErrConflict {
		return err
	}
	_ = v4a
	return nil
}
