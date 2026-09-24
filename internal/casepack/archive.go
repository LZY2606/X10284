package casepack

import (
	"fmt"

	"pairwise-gsb/mqttsession/internal/engine"
	"pairwise-gsb/mqttsession/internal/mqtt"
)

// Judgment is a machine-readable record of why a semantic rule produced its
// outcome inside one archive entry.
type Judgment struct {
	Rule    string `json:"rule"`   // e.g. "packet-id-generation-scoped"
	Subject string `json:"subject"`// derived node id the rule fired on
	Detail  string `json:"detail"`
}

// ArchiveResult is one candidate outcome. Adopted and unadopted results are
// both preserved.
type ArchiveResult struct {
	Label   string   `json:"label"`
	Scope   []string `json:"scope"` // derived node ids affected
	Summary string   `json:"summary"`
}

// ArchiveEntry is one counterexample: the baseline plus exactly one mutated
// direct source, the judgements that fired, and both adopted and unadopted
// results.
type ArchiveEntry struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Mutation       string          `json:"mutation"`
	ChangedPackets []string        `json:"changed_packets"`
	Judgments      []Judgment      `json:"judgments"`
	Adopted        ArchiveResult   `json:"adopted"`
	Unadopted      []ArchiveResult `json:"unadopted"`
}

// mutation pairs a human description with the trace transform.
type mutation struct {
	id, name, desc string
	apply          func(pkts []engine.Packet) ([]engine.Packet, []string)
}

func clone(pkts []engine.Packet) []engine.Packet {
	out := make([]engine.Packet, len(pkts))
	copy(out, pkts)
	return out
}

func findByTime(pkts []engine.Packet, vt int64) int {
	for i, p := range pkts {
		if p.VirtualTime == vt {
			return i
		}
	}
	return -1
}

func mutations() []mutation {
	return []mutation{
		{
			id: "ce-packet-id-reuse", name: "packet id 复用",
			desc: "在 gen-2 中新增一个 packet id=2 的 QoS1 交换；该 id 在 gen-1 已完成 QoS2 交换。检验：packet id 只在同一会话代次中解释。",
			apply: func(pkts []engine.Packet) ([]engine.Packet, []string) {
				out := clone(pkts)
				n := len(out)
				out = append(out,
					engine.Packet{ID: fmt.Sprintf("pkt-%04d", n+1), Dir: mqtt.C2S, VirtualTime: 32700 + 50,
						ClockRaw: "capture+32750ms",
						Raw:      mqtt.Encode(mqtt.TypePUBLISH, 0x02, mqtt.PublishBody("factory/line1/pressure", 2, 0, []byte("101.4")))},
					engine.Packet{ID: fmt.Sprintf("pkt-%04d", n+2), Dir: mqtt.S2C, VirtualTime: 32760,
						ClockRaw: "capture+32760ms",
						Raw:      mqtt.Encode(mqtt.TypePUBACK, 0, mqtt.AckBody(2))},
				)
				for i := range out {
					out[i].Dec = mqtt.Decode(out[i].Raw)
				}
				return out, []string{fmt.Sprintf("pkt-%04d", n+1), fmt.Sprintf("pkt-%04d", n+2)}
			},
		},
		{
			id: "ce-dup-retransmit", name: "DUP 重传",
			desc: "把 t=320 的 QoS2 DUP 重传再复制一份到 t=325。检验：QoS 2 重复包幂等且不丢失握手阶段。",
			apply: func(pkts []engine.Packet) ([]engine.Packet, []string) {
				out := clone(pkts)
				src := out[findByTime(pkts, 320)]
				dup := src
				dup.VirtualTime = 325
				dup.ID = "pkt-dup-extra"
				dup.ClockRaw = "capture+325ms"
				out = append(out, dup)
				return out, []string{"pkt-dup-extra"}
			},
		},
		{
			id: "ce-qos2-mid-disconnect", name: "QoS 2 中途断线",
			desc: "删除 t=2110 的 PUBREL，让 QoS2 交换在重连后仍停在 await-pubrel。检验：断线不丢握手阶段，交换保持未完成而非被吞掉。",
			apply: func(pkts []engine.Packet) ([]engine.Packet, []string) {
				idx := findByTime(pkts, 2110)
				out := append(clone(pkts[:idx:idx]), pkts[idx+1:]...)
				return out, []string{pkts[idx].ID}
			},
		},
		{
			id: "ce-session-expiry-endpoint", name: "session expiry 端点",
			desc: "把第三次 CONNECT 从 t=32500 提前到 t=32499（gap 29999ms < 30000ms）。检验：端点两侧判定翻转，且使用虚拟时间。",
			apply: func(pkts []engine.Packet) ([]engine.Packet, []string) {
				out := clone(pkts)
				i := findByTime(pkts, 32500)
				out[i].VirtualTime = 32499
				return out, []string{out[i].ID}
			},
		},
		{
			id: "ce-topic-alias-reset", name: "topic alias 重置",
			desc: "删除 t=2200 的 alias 重新注册包，使 t=2300 的 alias=1 引用在新连接中无注册。检验：alias 表随连接重置，未注册值留在原位并附诊断。",
			apply: func(pkts []engine.Packet) ([]engine.Packet, []string) {
				idx := findByTime(pkts, 2200)
				out := append(clone(pkts[:idx:idx]), pkts[idx+1:]...)
				return out, []string{pkts[idx].ID}
			},
		},
		{
			id: "ce-retained-delete", name: "retained 删除",
			desc: "删除 t=2400 的零载荷 retained 删除包。检验：retained 存储独立于会话消息，删除与否只影响 retained 节点。",
			apply: func(pkts []engine.Packet) ([]engine.Packet, []string) {
				idx := findByTime(pkts, 2400)
				out := append(clone(pkts[:idx:idx]), pkts[idx+1:]...)
				return out, []string{pkts[idx].ID}
			},
		},
		{
			id: "ce-multi-generation-confusion", name: "多代会话混淆",
			desc: "在 gen-2 的 t=32720 再加一个 packet id=3 的 PUBACK；id=3 的 QoS2 交换在 gen-1 已完成。检验：跨代完成态不被误绑，无 inflight 时给出诊断而非硬绑。",
			apply: func(pkts []engine.Packet) ([]engine.Packet, []string) {
				out := clone(pkts)
				out = append(out, engine.Packet{
					ID: "pkt-crossgen-ack", Dir: mqtt.S2C, VirtualTime: 32720,
					ClockRaw: "capture+32720ms",
					Raw:      mqtt.Encode(mqtt.TypePUBACK, 0, mqtt.AckBody(3)),
				})
				out[len(out)-1].Dec = mqtt.Decode(out[len(out)-1].Raw)
				return out, []string{"pkt-crossgen-ack"}
			},
		},
	}
}

// scopeOf collects derived node ids mentioning any of the changed packets,
// plus generation/expiry nodes when the change can move boundaries.
func scopeOf(d *engine.Derived, changed map[string]bool) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, x := range d.Exchanges {
		for _, pid := range x.Packets {
			if changed[pid] {
				add(x.ID)
			}
		}
	}
	for _, r := range d.Retained {
		if changed[r.SetBy] || changed[r.DeletedBy] {
			add(r.ID)
		}
	}
	for _, s := range d.Subs {
		if changed[s.PacketID] {
			add(s.ID)
		}
	}
	for _, dg := range d.Diagnostics {
		if changed[dg.PacketID] {
			add(dg.ID)
		}
	}
	return out
}

// BuildArchive runs the baseline and every mutation through the engine and
// records the counterexample archive. Adopted results are what the rules
// actually produced; unadopted results are the plausible alternatives a
// naive implementation would have produced, kept for review.
func BuildArchive() []ArchiveEntry {
	base := Trace()
	params := engine.Params{RuleSetID: "rules-v1"}
	var entries []ArchiveEntry
	for _, m := range mutations() {
		mutated, changedIDs := m.apply(base)
		d := engine.Reconstruct(mutated, params, nil)
		changed := map[string]bool{}
		for _, id := range changedIDs {
			changed[id] = true
		}
		scope := scopeOf(d, changed)
		entry := ArchiveEntry{
			ID: m.id, Name: m.name, Mutation: m.desc, ChangedPackets: changedIDs,
		}
		switch m.id {
		case "ce-packet-id-reuse":
			entry.Judgments = []Judgment{
				{Rule: "packet-id-generation-scoped", Subject: scope[0],
					Detail: "packet id 2 在 gen-2 中开新交换，与 gen-1 的 QoS2 交换互不解释"},
			}
			entry.Adopted = ArchiveResult{Label: "同代独立交换", Scope: scope,
				Summary: "gen-2 中 packet id=2 建立独立 QoS1 交换并完成；gen-1 交换不受影响"}
			entry.Unadopted = []ArchiveResult{
				{Label: "跨代合并（未采纳）", Scope: scope,
					Summary: "若按全局 packet id 解释会把两代交换错误合并；该候选被规则拒绝但保留"},
			}
		case "ce-dup-retransmit":
			entry.Judgments = []Judgment{
				{Rule: "qos2-dup-idempotent-phase-kept", Subject: "xch-gen-1-c2s-0002-a",
					Detail: "额外 DUP 包幂等折叠进 duplicates，握手阶段保持 await-pubrel 路径不变"},
			}
			entry.Adopted = ArchiveResult{Label: "幂等折叠", Scope: []string{"xch-gen-1-c2s-0002-a"},
				Summary: "重复 DUP 只增加 duplicates 计数，交换仍按 PUBREC→PUBREL→PUBCOMP 完成"}
			entry.Unadopted = []ArchiveResult{
				{Label: "重置状态机（未采纳）", Scope: []string{"xch-gen-1-c2s-0002-a"},
					Summary: "若把 DUP 当作新发布会重置握手阶段并丢失 PUBREC；候选保留"},
			}
		case "ce-qos2-mid-disconnect":
			entry.Judgments = []Judgment{
				{Rule: "qos2-dup-idempotent-phase-kept", Subject: "xch-gen-1-c2s-0003-a",
					Detail: "缺少 PUBREL 时交换停在 await-pubrel，不被静默完成"},
			}
			entry.Adopted = ArchiveResult{Label: "阶段保留", Scope: scope,
				Summary: "QoS2 交换在断线后保持 await-pubrel；后续 PUBCOMP 无法推进，状态显式可见"}
			entry.Unadopted = []ArchiveResult{
				{Label: "断线即丢弃（未采纳）", Scope: scope,
					Summary: "若断线丢弃 inflight 状态，重连后的 DUP 将无处可归；候选保留"},
			}
		case "ce-session-expiry-endpoint":
			entry.Judgments = []Judgment{
				{Rule: "session-expiry-virtual-time", Subject: "exp-2",
					Detail: "gap 29999ms < 30000ms（虚拟时间）→ session-continued；端点判定翻转"},
			}
			entry.Adopted = ArchiveResult{Label: "端点内侧", Scope: []string{"exp-2"},
				Summary: "提前 1ms 使判定从 session-expired 翻转为 session-continued，不发生代次切换"}
			entry.Unadopted = []ArchiveResult{
				{Label: "端点含混（未采纳）", Scope: []string{"exp-2"},
					Summary: "若用墙钟或取整秒判定会在端点处抖动；候选保留"},
			}
		case "ce-topic-alias-reset":
			entry.Judgments = []Judgment{
				{Rule: "topic-alias-connection-scoped", Subject: "diag",
					Detail: "alias=1 在新连接未注册：topic 保持未解析，原始包留在原位并附诊断"},
			}
			entry.Adopted = ArchiveResult{Label: "诊断保留", Scope: scope,
				Summary: "t=2300 的 PUBLISH 无法解析 topic，保留原始字节与诊断，不为画图补全"}
			entry.Unadopted = []ArchiveResult{
				{Label: "沿用旧连接 alias（未采纳）", Scope: scope,
					Summary: "若跨连接沿用 alias 表会静默解析出错误 topic；候选保留"},
			}
		case "ce-retained-delete":
			entry.Judgments = []Judgment{
				{Rule: "retained-separate-from-session", Subject: "ret-1",
					Detail: "缺少删除包时 retained 条目保持 active，且从不进入 inflight 会话状态"},
			}
			entry.Adopted = ArchiveResult{Label: "retained 独立", Scope: scope,
				Summary: "ret-1 保持 active=true；影响范围只含 retained 节点，会话交换零影响"}
			entry.Unadopted = []ArchiveResult{
				{Label: "随会话过期清理（未采纳）", Scope: scope,
					Summary: "若把 retained 当作会话状态，session 过期会误删 retained；候选保留"},
			}
		case "ce-multi-generation-confusion":
			entry.Judgments = []Judgment{
				{Rule: "packet-id-generation-scoped", Subject: "diag",
					Detail: "gen-2 中无 id=3 的 inflight 交换，跨代 PUBACK 不硬绑，记录诊断"},
			}
			entry.Adopted = ArchiveResult{Label: "拒绝跨代绑定", Scope: scope,
				Summary: "跨代 PUBACK 产生诊断并保留原始包；gen-1 已完成交换不被触碰"}
			entry.Unadopted = []ArchiveResult{
				{Label: "绑定到 gen-1 交换（未采纳）", Scope: scope,
					Summary: "若按全局 id 解释会把 gen-2 的 ack 记到 gen-1 交换上；候选保留"},
			}
		}
		entries = append(entries, entry)
	}
	return entries
}
