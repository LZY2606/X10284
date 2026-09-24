package web

import (
	"fmt"
	"strings"

	"mqttlab/internal/mqtt"
)

// timelineSVG renders session generations on the virtual clock.
func timelineSVG(s mqtt.Sessions, currentGen string) string {
	if len(s.Generations) == 0 {
		return "<p class='muted'>no generations</p>"
	}
	max := s.Generations[len(s.Generations)-1].EndMS
	if max == 0 {
		max = 1
	}
	W, H := 860.0, 120.0
	scale := func(ms int64) float64 { return 40 + float64(ms)/float64(max)*(W-80) }
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="svg" viewBox="0 0 %.0f %.0f" role="img">`, W, H)
	b.WriteString(`<line x1="40" y1="60" x2="820" y2="60" stroke="#888"/>`)
	for _, g := range s.Generations {
		x0, x1 := scale(g.StartMS), scale(g.EndMS)
		if x1-x0 < 4 {
			x1 = x0 + 4
		}
		fill := "#d8ecff"
		if g.ID == currentGen {
			fill = "#ffd9a0"
		}
		active := "ok"
		if g.CarriedFrom == "" && g.Index > 1 {
			active = "expired"
		} else if g.CarriedFrom != "" {
			active = "persisted"
		}
		fmt.Fprintf(&b, `<a xlink:href="/gen?n=%d"><rect x="%.1f" y="42" width="%.1f" height="36" rx="6" fill="%s" stroke="#2b6cb0" data-id="%s" class="svghit"/>`,
			g.Index, x0, x1-x0, fill, g.ID)
		fmt.Fprintf(&b, `<text x="%.1f" y="65" text-anchor="middle" font-size="12">%s</text></a>`, (x0+x1)/2, g.ID)
		fmt.Fprintf(&b, `<text x="%.1f" y="96" text-anchor="middle" font-size="10" fill="#555">%s · %dms</text>`,
			(x0+x1)/2, active, g.StartMS)
	}
	b.WriteString(`<text x="40" y="115" font-size="10" fill="#555">0ms</text>`)
	fmt.Fprintf(&b, `<text x="820" y="115" text-anchor="end" font-size="10" fill="#555">%dms (virtual clock: %s)</text>`, max, mqtt.BasisVirtual)
	b.WriteString(`</svg>`)
	return b.String()
}

// flowSVG renders one QoS handshake state machine with its event history.
func flowSVG(f mqtt.Flow, ver string) string {
	// QoS 2 has 4 states; QoS 1 has 2.
	states := []string{"published", "pubrec", "pubrel", "complete"}
	if f.QoS == 1 {
		states = []string{"published", "complete"}
	}
	W, H := 100.0+180.0*float64(len(states)-1)+60, 150.0
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="svg" viewBox="0 0 %.0f %.0f" role="img">`, W, H)
	pos := map[string]float64{}
	for i, st := range states {
		x := 80 + 180*float64(i)
		pos[st] = x
		active := st == f.Phase
		stroke, sw := "#cbd5e0", 2
		if active {
			stroke, sw = "#dd6b20", 4
		}
		if f.Complete && st == "complete" {
			stroke, sw = "#2f855a", 4
		}
		fmt.Fprintf(&b, `<circle cx="%.0f" cy="50" r="26" fill="#fff" stroke="%s" stroke-width="%d" data-id="%s/state/%s"/>`, x, stroke, sw, f.ID, st)
		fmt.Fprintf(&b, `<text x="%.0f" y="46" text-anchor="middle" font-size="10">%s</text>`, x, st)
	}
	for i := 0; i+1 < len(states); i++ {
		x0, x1 := pos[states[i]]+26, pos[states[i+1]]-26
		fmt.Fprintf(&b, `<line x1="%.0f" y1="50" x2="%.0f" y2="50" stroke="#888" marker-end="url(#a)"/>`, x0, x1)
	}
	b.WriteString(`<defs><marker id="a" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 z" fill="#888"/></marker></defs>`)
	// event rail
	y := 108.0
	for _, ev := range f.Events {
		pkt := ev.Packet
		if pkt == "" {
			pkt = ev.Kind
		}
		color := "#2b6cb0"
		switch ev.Kind {
		case "dup-publish", "dup-pubrec":
			color = "#b7791f"
		case "carry":
			color = "#6b46c1"
		case "discard":
			color = "#c53030"
		}
		fmt.Fprintf(&b, `<g data-id="%s"><circle cx="60" cy="%.0f" r="5" fill="%s"/>`, pkt, y, color)
		fmt.Fprintf(&b, `<text x="74" y="%.0f" font-size="10">%dms %s <a href="/packet?id=%s&v=%s">%s</a> %s</text></g>`, y+3, ev.ClockMS, ev.Kind, ev.Packet, ver, pkt, ev.Note)
		y += 18
		if y > 145 {
			fmt.Fprintf(&b, `<text x="60" y="%.0f" font-size="10" fill="#888">…</text>`, y)
			break
		}
	}
	b.WriteString(`</svg>`)
	return b.String()
}

func flowsSVG(flows []mqtt.Flow, ver string) string {
	var b strings.Builder
	for _, f := range flows {
		fmt.Fprintf(&b, `<div class="card"><h4><a href="/flow?id=%s">%s</a> <span class="tag">QoS%d</span> <span class="tag">phase:%s</span> <span class="muted" data-id="%s">%s</span></h4>%s</div>`,
			f.ID, f.ID, f.QoS, f.Phase, f.ID, f.Topic, "", flowSVG(f, ver))
	}
	return b.String()
}
