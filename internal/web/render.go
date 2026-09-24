package web

import (
	"encoding/json"
	"html/template"
	"strings"

	"mqttlab/internal/mqtt"
)

// hrefFor maps a stable evidence identity to the page that shows it.
func hrefFor(id string) string {
	switch {
	case strings.HasPrefix(id, "pkt-"):
		return "/packet?id=" + id
	case strings.HasPrefix(id, "gen-"):
		return "/gen?n=" + strings.TrimPrefix(id, "gen-")
	case strings.HasPrefix(id, "ano-"), strings.HasPrefix(id, "boundary-"):
		return "/provenance/" + id
	case strings.Contains(id, "/"):
		return "/flow?id=" + id
	default:
		return "/provenance/" + id
	}
}

func FlowSVGHTML(f *mqtt.Flow, ver string) template.HTML {
	if f == nil {
		return template.HTML("")
	}
	return template.HTML(flowSVG(*f, ver))
}

type decisionRow struct {
	Dec          mqtt.Decision
	Effective    string
	Reviewer     string
	Overridden   bool
	CandidateTag []template.HTML
}

func (s *Server) decisionRows(vw *view) []decisionRow {
	var rows []decisionRow
	for _, d := range vw.decisions.Decisions {
		choice, ev := s.effectiveChoice(vw, d)
		row := decisionRow{Dec: d, Effective: choice, Overridden: ev.ID != ""}
		if row.Overridden {
			var r struct {
				Reviewer string `json:"reviewer"`
			}
			_ = json.Unmarshal(ev.Body, &r)
			row.Reviewer = r.Reviewer
		}
		for _, c := range d.Candidates {
			cls := "tag"
			if c == d.RuleChoice {
				cls = "tag ok"
			}
			if c == choice && row.Overridden {
				cls = "tag purple"
			}
			row.CandidateTag = append(row.CandidateTag,
				template.HTML("<span class='"+cls+"'>"+c+"</span>"))
		}
		rows = append(rows, row)
	}
	return rows
}
