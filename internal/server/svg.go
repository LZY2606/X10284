package server

import (
	"fmt"
	"html/template"

	"pairwise-gsb/mqttsession/internal/engine"
)

func init() {
	funcs["fsmSVG"] = fsmSVG
}

// fsmSVG renders one QoS handshake state machine as inline SVG. Completed
// steps are green, the current handshake phase is orange, later steps stay
// grey. A duplicate badge shows idempotently folded packets.
func fsmSVG(x engine.Exchange) template.HTML {
	if x.Phase == "unbound-ack" || x.Phase == "bound-to-orphan" {
		return template.HTML(fmt.Sprintf(`<svg width="560" height="64" xmlns="http://www.w3.org/2000/svg">
<rect x="10" y="14" width="540" height="36" rx="8" fill="#fff4e5" stroke="#d97706"/>
<text x="280" y="38" text-anchor="middle" font-size="14" fill="#92400e">无绑定 ACK（%s）·%s，保留 %d 个候选</text></svg>`,
			x.Phase, x.ID, len(x.Candidates)))
	}
	steps := []string{"PUBLISH", "PUBACK"}
	if x.QoS == 2 {
		steps = []string{"PUBLISH", "PUBREC", "PUBREL", "PUBCOMP"}
	}
	done := 0
	switch x.Phase {
	case engine.PhaseAwaitPubAck, engine.PhaseAwaitPubRec:
		done = 1
	case engine.PhaseAwaitPubRel:
		done = 2
	case engine.PhaseAwaitPubComp:
		done = 3
	case engine.PhaseComplete:
		done = len(steps)
	}
	const w, h, bw, bh, gap = 640, 86, 118, 40, 30
	x0 := 20
	var s string
	for i, label := range steps {
		x := x0 + i*(bw+gap)
		fill, stroke, tcol := "#f3f4f6", "#9ca3af", "#374151"
		switch {
		case i < done:
			fill, stroke, tcol = "#dcfce7", "#16a34a", "#14532d"
		case i == done && x.Phase != engine.PhaseComplete:
			fill, stroke, tcol = "#ffedd5", "#ea580c", "#9a3412"
		}
		s += fmt.Sprintf(`<rect x="%d" y="22" width="%d" height="%d" rx="8" fill="%s" stroke="%s" stroke-width="2"/>`, x, bw, bh, fill, stroke)
		s += fmt.Sprintf(`<text x="%d" y="47" text-anchor="middle" font-size="13" fill="%s">%s</text>`, x+bw/2, tcol, label)
		if i < len(steps)-1 {
			ax := x + bw
			s += fmt.Sprintf(`<line x1="%d" y1="42" x2="%d" y2="42" stroke="#6b7280" stroke-width="2" marker-end="url(#a)"/>`, ax, ax+gap)
		}
	}
	s += fmt.Sprintf(`<text x="20" y="78" font-size="12" fill="#374151">阶段：%s · packet id=%d · 代次 %s</text>`, x.Phase, x.PacketID, x.Generation)
	if len(x.Duplicates) > 0 {
		s += fmt.Sprintf(`<g><rect x="470" y="66" width="150" height="20" rx="10" fill="#ede9fe" stroke="#7c3aed"/>
<text x="545" y="80" text-anchor="middle" font-size="11" fill="#5b21b6">DUP 幂等折叠 ×%d</text></g>`, len(x.Duplicates))
	}
	return template.HTML(fmt.Sprintf(`<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg"><defs>
<marker id="a" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#6b7280"/></marker>
</defs>%s</svg>`, w, h, s))
}
