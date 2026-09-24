package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"pairwise-gsb/mqttsession/internal/engine"
	"pairwise-gsb/mqttsession/internal/mqtt"
	"pairwise-gsb/mqttsession/internal/store"
)

// packet shows one captured frame: original bytes, direction, packet id,
// flags, clean-start/session-expiry, topic alias and both clocks, followed
// by the provenance chain (every derived node using this source).
func (s *Server) packet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/packet/")
	st, v, _ := s.view(r)
	for _, p := range st.Packets {
		if p.ID != id {
			continue
		}
		var uses []string
		for _, x := range st.Derived.Exchanges {
			for _, pid := range x.Packets {
				if pid == p.ID {
					uses = append(uses, "exchange:"+x.ID)
				}
			}
		}
		for _, sub := range st.Derived.Subs {
			if sub.PacketID == p.ID {
				uses = append(uses, "sub:"+sub.ID)
			}
		}
		for _, ret := range st.Derived.Retained {
			if ret.SetBy == p.ID || ret.DeletedBy == p.ID {
				uses = append(uses, "retained:"+ret.ID)
			}
		}
		s.render(w, "packet", pageData{Title: "原包 " + p.ID, Current: v, State: st,
			Extra: map[string]any{"Packet": p, "Uses": uses}})
		return
	}
	http.NotFound(w, r)
}

// anomaly enters a derived node from its anomaly: source packets, rule
// decisions and candidates are shown as one provenance chain.
func (s *Server) anomaly(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/anomaly/")
	st, v, _ := s.view(r)
	for _, x := range st.Derived.Exchanges {
		if x.ID != id {
			continue
		}
		var packets []engine.Packet
		for _, p := range st.Packets {
			for _, pid := range x.Packets {
				if p.ID == pid {
					packets = append(packets, p)
				}
			}
		}
		s.render(w, "anomaly", pageData{Title: "异常来源链 " + id, Current: v, State: st,
			Extra: map[string]any{"Exchange": x, "Packets": packets}})
		return
	}
	http.NotFound(w, r)
}

func (s *Server) branches(w http.ResponseWriter, r *http.Request) {
	st, v, _ := s.view(r)
	versions, _ := s.DB.Versions()
	events, _ := s.DB.Events()
	s.render(w, "branches", pageData{Title: "版本与分支", Active: "branches", Current: v, State: st,
		Extra: map[string]any{"Versions": versions, "Events": events}})
}

func (s *Server) compare(w http.ResponseWriter, r *http.Request) {
	a, b := r.URL.Query().Get("a"), r.URL.Query().Get("b")
	if a == "" || b == "" {
		http.Redirect(w, r, "/branches", http.StatusSeeOther)
		return
	}
	stA, errA := s.App.At(a)
	stB, errB := s.App.At(b)
	if errA != nil || errB != nil {
		s.fail(w, 404, fmt.Errorf("version not found"))
		return
	}
	notes := engine.DiffRecompute(stA.Derived, stB.Derived,
		engine.ChangedInputs{ChangedBy: "branch comparison " + a + " -> " + b})
	_, cv, _ := s.App.Current()
	s.render(w, "compare", pageData{Title: "比较 " + a + " 与 " + b, Active: "branches", Current: cv, State: stB,
		Extra: map[string]any{"A": stA, "B": stB, "AID": a, "BID": b, "Notes": notes}})
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.fail(w, 400, err)
		return
	}
	dec := engine.Decision{
		ID: fmt.Sprintf("dec-%s", r.FormValue("author")),
		TargetID:  r.FormValue("target"),
		Chosen:    r.FormValue("chosen"),
		Rejected:  []string{r.FormValue("rejected")},
		Author:    r.FormValue("author"),
		Rationale: r.FormValue("rationale"),
	}
	if dec.ID == "dec-" {
		dec.ID = "dec-anonymous"
	}
	_, err := s.App.Decide(r.FormValue("base"), dec)
	if errors.Is(err, store.ErrConflict) {
		http.Redirect(w, r, "/conflicts?err=1&target="+r.FormValue("target"), http.StatusSeeOther)
		return
	}
	if err != nil {
		s.fail(w, 500, err)
		return
	}
	http.Redirect(w, r, "/anomaly/"+r.FormValue("target"), http.StatusSeeOther)
}

func (s *Server) resolveConflict(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/conflicts", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	challenger := engine.Decision{
		ID: fmt.Sprintf("dec-%s", r.FormValue("author")),
		TargetID:  r.FormValue("target"),
		Chosen:    r.FormValue("chosen"),
		Rejected:  []string{r.FormValue("rejected")},
		Author:    r.FormValue("author"),
		Rationale: r.FormValue("rationale"),
	}
	if challenger.ID == "dec-" {
		challenger.ID = "dec-anonymous"
	}
	if _, err := s.App.ResolveConflict(r.FormValue("conflict"), r.FormValue("keep"), challenger); err != nil {
		s.fail(w, 500, err)
		return
	}
	http.Redirect(w, r, "/conflicts", http.StatusSeeOther)
}

func (s *Server) doExport(w http.ResponseWriter, r *http.Request) {
	data, err := s.DB.Export()
	if err != nil {
		s.fail(w, 500, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="mqtt-session-export.json"`)
	_, _ = w.Write(data)
}

func (s *Server) doImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/events", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	data := []byte(r.FormValue("dump"))
	if f, _, err := r.FormFile("file"); err == nil {
		data, _ = io.ReadAll(f)
		f.Close()
	}
	if err := s.DB.Import(data); err != nil {
		s.fail(w, 400, fmt.Errorf("import failed (identities/order preserved on failure): %w", err))
		return
	}
	http.Redirect(w, r, "/events", http.StatusSeeOther)
}

// --- guided sample path ---

func hasEvent(st *store.Store, kind string) bool {
	evs, err := st.Events()
	if err != nil {
		return false
	}
	for _, e := range evs {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func (s *Server) demoImport(w http.ResponseWriter, r *http.Request) {
	if !hasEvent(s.DB, "import") {
		if _, err := s.App.ImportCase(); err != nil {
			s.fail(w, 500, err)
			return
		}
	}
	http.Redirect(w, r, "/walk?step=1", http.StatusSeeOther)
}

func (s *Server) demoRevise(w http.ResponseWriter, r *http.Request) {
	if !hasEvent(s.DB, "import") {
		s.App.ImportCase()
	}
	if !hasEvent(s.DB, "param_revision") {
		if _, err := s.App.ReviseParams(1); err != nil {
			s.fail(w, 500, err)
			return
		}
	}
	http.Redirect(w, r, "/walk?step=2", http.StatusSeeOther)
}

func (s *Server) demoMutate(w http.ResponseWriter, r *http.Request) {
	if !hasEvent(s.DB, "source_mutation") {
		// pkt-0009 is the t=320 QoS2 DUP retransmit.
		if _, err := s.App.MutateSource("pkt-0009"); err != nil {
			s.fail(w, 500, err)
			return
		}
	}
	http.Redirect(w, r, "/walk?step=3", http.StatusSeeOther)
}

func (s *Server) demoDecideA(w http.ResponseWriter, r *http.Request) {
	s.decideReviewer(w, r, "reviewer-A", "cand-amb-0005-old")
}

func (s *Server) demoDecideB(w http.ResponseWriter, r *http.Request) {
	s.decideReviewer(w, r, "reviewer-B", "cand-amb-0005-late")
}

func (s *Server) decideReviewer(w http.ResponseWriter, r *http.Request, author, chosen string) {
	if !hasEvent(s.DB, "import") {
		s.App.ImportCase()
	}
	_, v, err := s.App.Current()
	if err != nil {
		s.fail(w, 500, err)
		return
	}
	dec := engine.Decision{
		ID: "dec-" + author, TargetID: "amb-gen-2-0005", Chosen: chosen,
		Rejected: []string{"cand-amb-0005-other"}, Author: author,
		Rationale: author + " 的合法候选裁定（另一候选保留为未采纳）",
	}
	_, err = s.App.Decide(v.ID, dec)
	if errors.Is(err, store.ErrConflict) {
		http.Redirect(w, r, "/conflicts?err=1&target=amb-gen-2-0005", http.StatusSeeOther)
		return
	}
	if err != nil && !strings.Contains(err.Error(), "already") {
		s.fail(w, 500, err)
		return
	}
	http.Redirect(w, r, "/conflicts", http.StatusSeeOther)
}

// avoid unused import when mqtt is only referenced here
var _ = mqtt.TypeCONNECT
