// Package server renders the review UI: session generations, QoS state
// machines (SVG), duplicate mapping, subscription changes and expiry
// decisions, each with stable identities. Provenance chains, branch
// comparison, the counterexample archive and replay are all linked from the
// same narrative.
package server

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"pairwise-gsb/mqttsession/internal/app"
	"pairwise-gsb/mqttsession/internal/engine"
	"pairwise-gsb/mqttsession/internal/mqtt"
	"pairwise-gsb/mqttsession/internal/store"
)

type Server struct {
	App *app.App
	DB  *store.Store
}

func New(a *app.App) *Server { return &Server{App: a, DB: a.Store} }

// Handler wires routes. Any view can be pinned to a historical version
// with ?v=<version-id>.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.home)
	mux.HandleFunc("/sessions", s.sessions)
	mux.HandleFunc("/qos", s.qos)
	mux.HandleFunc("/dups", s.dups)
	mux.HandleFunc("/subs", s.subs)
	mux.HandleFunc("/expiry", s.expiry)
	mux.HandleFunc("/retained", s.retained)
	mux.HandleFunc("/diags", s.diags)
	mux.HandleFunc("/packet/", s.packet)
	mux.HandleFunc("/anomaly/", s.anomaly)
	mux.HandleFunc("/branches", s.branches)
	mux.HandleFunc("/compare", s.compare)
	mux.HandleFunc("/decide", s.decide)
	mux.HandleFunc("/resolve", s.resolveConflict)
	mux.HandleFunc("/archive", s.archive)
	mux.HandleFunc("/replay", s.replay)
	mux.HandleFunc("/events", s.events)
	mux.HandleFunc("/conflicts", s.conflicts)
	mux.HandleFunc("/walk", s.walk)
	mux.HandleFunc("/demo/import", s.demoImport)
	mux.HandleFunc("/demo/revise", s.demoRevise)
	mux.HandleFunc("/demo/mutate", s.demoMutate)
	mux.HandleFunc("/demo/decide-a", s.demoDecideA)
	mux.HandleFunc("/demo/decide-b", s.demoDecideB)
	mux.HandleFunc("/export", s.doExport)
	mux.HandleFunc("/import", s.doImport)
	return mux
}

func (s *Server) view(r *http.Request) (*app.State, store.Version, error) {
	if v := r.URL.Query().Get("v"); v != "" {
		st, err := s.App.At(v)
		return st, store.Version{ID: v}, err
	}
	return s.App.Current()
}

var funcs = template.FuncMap{
	"hex":      mqtt.Hex,
	"typename": mqtt.TypeName,
	"q":        url.QueryEscape,
	"notesOf": func(notes []engine.RecomputeNote, kind string) []engine.RecomputeNote {
		var out []engine.RecomputeNote
		for _, n := range notes {
			if n.Node.Kind == kind {
				out = append(out, n)
			}
		}
		return out
	},
	"seq": func(n int) []int {
		out := make([]int, n)
		for i := range out {
			out[i] = i
		}
		return out
	},
}

func (s *Server) render(w http.ResponseWriter, name string, data pageData) {
	t := template.Must(template.New("layout").Funcs(funcs).Parse(layout))
	t = template.Must(t.New("body").Parse(partials[name]))
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

type pageData struct {
	Title   string
	Active  string
	Current store.Version
	State   *app.State
	Extra   map[string]any
}

func (s *Server) fail(w http.ResponseWriter, code int, err error) {
	w.WriteHeader(code)
	fmt.Fprintf(w, "%v", err)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	st, v, _ := s.view(r)
	events, _ := s.DB.Events()
	versions, _ := s.DB.Versions()
	s.render(w, "home", pageData{Title: "MQTT 会话印迹复核台", Current: v, State: st,
		Extra: map[string]any{"Events": events, "Versions": versions}})
}

func (s *Server) walk(w http.ResponseWriter, r *http.Request) {
	st, v, _ := s.view(r)
	events, _ := s.DB.Events()
	s.render(w, "walk", pageData{Title: "90 秒样例路径", Current: v, State: st,
		Extra: map[string]any{"Events": events}})
}

func (s *Server) sessions(w http.ResponseWriter, r *http.Request) {
	st, v, _ := s.view(r)
	s.render(w, "sessions", pageData{Title: "会话代次", Active: "sessions", Current: v, State: st})
}

func (s *Server) qos(w http.ResponseWriter, r *http.Request) {
	st, v, _ := s.view(r)
	s.render(w, "qos", pageData{Title: "QoS 状态机", Active: "qos", Current: v, State: st})
}

func (s *Server) dups(w http.ResponseWriter, r *http.Request) {
	st, v, _ := s.view(r)
	s.render(w, "dups", pageData{Title: "重复包对应", Active: "dups", Current: v, State: st})
}

func (s *Server) subs(w http.ResponseWriter, r *http.Request) {
	st, v, _ := s.view(r)
	s.render(w, "subs", pageData{Title: "Subscription 变更", Active: "subs", Current: v, State: st})
}

func (s *Server) expiry(w http.ResponseWriter, r *http.Request) {
	st, v, _ := s.view(r)
	s.render(w, "expiry", pageData{Title: "到期决定（虚拟时间）", Active: "expiry", Current: v, State: st})
}

func (s *Server) retained(w http.ResponseWriter, r *http.Request) {
	st, v, _ := s.view(r)
	s.render(w, "retained", pageData{Title: "Retained 存储（独立于会话消息）", Active: "retained", Current: v, State: st})
}

func (s *Server) diags(w http.ResponseWriter, r *http.Request) {
	st, v, _ := s.view(r)
	s.render(w, "diags", pageData{Title: "无法转换的值与诊断", Active: "diags", Current: v, State: st})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	st, v, _ := s.view(r)
	events, _ := s.DB.Events()
	versions, _ := s.DB.Versions()
	s.render(w, "events", pageData{Title: "机器可读事件日志", Active: "events", Current: v, State: st,
		Extra: map[string]any{"Events": events, "Versions": versions}})
}

func (s *Server) conflicts(w http.ResponseWriter, r *http.Request) {
	st, v, _ := s.view(r)
	confs, _ := s.DB.Conflicts()
	s.render(w, "conflicts", pageData{Title: "并发编辑冲突", Active: "conflicts", Current: v, State: st,
		Extra: map[string]any{"Conflicts": confs, "Q": r.URL.Query()}})
}

func (s *Server) archive(w http.ResponseWriter, r *http.Request) {
	st, v, _ := s.view(r)
	s.render(w, "archive", pageData{Title: "反例档案", Active: "archive", Current: v, State: st})
}

func (s *Server) replay(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Redirect(w, r, "/archive", http.StatusSeeOther)
		return
	}
	st, v, _ := s.view(r)
	d, notes, entry, err := s.App.Replay(id)
	if err != nil {
		s.fail(w, 404, err)
		return
	}
	mutView := *st
	mutView.Derived = d
	mutView.Notes = notes
	s.render(w, "replay", pageData{Title: "重放：" + entry.Name, Active: "archive", Current: v, State: &mutView,
		Extra: map[string]any{"Entry": entry, "Base": st}})
}
