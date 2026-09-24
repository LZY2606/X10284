// Package web renders the review UI (HTML + inline SVG). Every displayed
// value carries its stable identity; views are pinned to a version and read
// back the versioned artifact snapshot, so historical views are never
// overwritten by the latest computation.
package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"

	"mqttlab/internal/mqtt"
	"mqttlab/internal/store"
)

type Server struct {
	st  *store.Store
	tpl *template.Template
	mux *http.ServeMux
}

func New(st *store.Store) *Server {
	s := &Server{st: st}
	s.tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"sub": func(a, b int) int { return a - b },
		"add": func(a, b int) int { return a + b },
		"timeline": timelineSVG,
		"flowsSvg": flowsSVG,
		"flowSvg":   FlowSVGHTML,
		"hrefFor":   hrefFor,
		"decisionRows": func(vw *view) []decisionRow { return s.decisionRows(vw) },
		"safe":      func(s string) template.HTML { return template.HTML(s) },
		"json": func(v any) template.JS {
			b, _ := json.MarshalIndent(v, "", "  ")
			return template.JS(string(b))
		},
	}).Parse(sharedTemplate + indexTemplate + versionTemplate + genTemplate + flowTemplate +
		provenanceTemplate + branchesTemplate + eventsTemplate + packetTemplate + tourTemplate))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /tour", s.handleTour)
	mux.HandleFunc("GET /version/{id}", s.handleVersion)
	mux.HandleFunc("GET /gen", s.handleGen)
	mux.HandleFunc("GET /flow", s.handleFlow)
	mux.HandleFunc("GET /packet", s.handlePacket)
	mux.HandleFunc("GET /provenance/{id}", s.handleProvenance)
	mux.HandleFunc("GET /branches", s.handleBranches)
	mux.HandleFunc("POST /resolve", s.handleResolve)
	mux.HandleFunc("GET /events", s.handleEvents)
	mux.HandleFunc("GET /events/{id}", s.handleEvent)
	mux.HandleFunc("GET /export", s.handleExport)
	mux.HandleFunc("GET /import", s.handleImportForm)
	mux.HandleFunc("POST /import", s.handleImport)
	s.mux = mux
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

// view is the data pinned to one version.
type view struct {
	HeadID    string
	Version   store.Version
	Versions  []store.Version
	Artifacts map[string]store.ArtifactState
	packets   []mqtt.Packet
	sessions  mqtt.Sessions
	flows     mqtt.Flows
	state     struct {
		Retained mqtt.Retained `json:"retained"`
		Subs     mqtt.Subs     `json:"subs"`
	}
	decisions mqtt.Decisions
	rulings   map[string]store.Event // decision id -> effective ruling in this version
	events    []store.Event
}

func (s *Server) loadView(verID string) (*view, error) {
	head, err := s.st.Head("")
	if err != nil {
		return nil, err
	}
	if verID == "" {
		verID = head
	}
	v, err := s.st.Version(verID)
	if err != nil {
		return nil, err
	}
	versions, err := s.st.Versions()
	if err != nil {
		return nil, err
	}
	allEvents, err := s.st.Events()
	if err != nil {
		return nil, err
	}
	vw := &view{HeadID: head, Version: v, Versions: versions, Artifacts: v.Artifacts, rulings: map[string]store.Event{}}
	get := func(name string, out any) error {
		a, ok := v.Artifacts[name]
		if !ok {
			return fmt.Errorf("artifact %s missing", name)
		}
		body, err := s.st.Object(a.ObjectID)
		if err != nil {
			return err
		}
		return json.Unmarshal(body, out)
	}
	if _, ok := v.Artifacts["packets"]; ok {
		if err := get("packets", &vw.packets); err != nil {
			return nil, err
		}
		if err := get("sessions", &vw.sessions); err != nil {
			return nil, err
		}
		if err := get("flows", &vw.flows); err != nil {
			return nil, err
		}
		if err := get("state", &vw.state); err != nil {
			return nil, err
		}
		if err := get("decisions", &vw.decisions); err != nil {
			return nil, err
		}
	}
	for _, ev := range allEvents {
		if ev.Version == verID && ev.Kind == "ruling" {
			var r struct {
				Decision string `json:"decision"`
			}
			_ = json.Unmarshal(ev.Body, &r)
			if _, exists := vw.rulings[r.Decision]; !exists {
				vw.rulings[r.Decision] = ev
			}
		}
		if ev.Version == verID {
			vw.events = append(vw.events, ev)
		}
	}
	return vw, nil
}

func (s *Server) packetByID(vw *view, id string) *mqtt.Packet {
	for i := range vw.packets {
		if vw.packets[i].ID == id {
			return &vw.packets[i]
		}
	}
	return nil
}

func (s *Server) flowByID(vw *view, id string) *mqtt.Flow {
	for i := range vw.flows.Flows {
		if vw.flows.Flows[i].ID == id {
			return &vw.flows.Flows[i]
		}
	}
	return nil
}

func (s *Server) decisionByID(vw *view, id string) *mqtt.Decision {
	for i := range vw.decisions.Decisions {
		if vw.decisions.Decisions[i].ID == id {
			return &vw.decisions.Decisions[i]
		}
	}
	return nil
}

func (s *Server) effectiveChoice(vw *view, dec mqtt.Decision) (string, store.Event) {
	if ev, ok := vw.rulings[dec.ID]; ok {
		var r struct {
			Choice   string `json:"choice"`
			Reviewer string `json:"reviewer"`
		}
		_ = json.Unmarshal(ev.Body, &r)
		return r.Choice, ev
	}
	return dec.RuleChoice, store.Event{}
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.Copy(w, &buf)
}
