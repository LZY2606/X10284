package web

import (
	"net/http"
	"strconv"
	"time"

	"mqttlab/internal/mqtt"
	"mqttlab/internal/store"
)

type baseData struct {
	HeadID   string
	VerID    string
	Versions []store.Version
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	vw, err := s.loadView("")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	conflicts, _ := s.st.Conflicts()
	branches, _ := s.st.Branches()
	s.render(w, "index", struct {
		*view
		Conflicts []store.Conflict
		Branches  []store.Branch
	}{vw, conflicts, branches})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	vw, err := s.loadView(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.render(w, "version", struct{ *view }{vw})
}

func (s *Server) handleGen(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	ver := r.URL.Query().Get("v")
	vw, err := s.loadView(ver)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var genPktIDs map[string]bool
	for _, g := range vw.sessions.Generations {
		if g.Index == n {
			genPktIDs = map[string]bool{}
			for _, id := range g.Packets {
				genPktIDs[id] = true
			}
		}
	}
	s.render(w, "gen", struct {
		*view
		N         int
		GenPktIDs map[string]bool
	}{vw, n, genPktIDs})
}

func (s *Server) handleFlow(w http.ResponseWriter, r *http.Request) {
	vw, err := s.loadView(r.URL.Query().Get("v"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.render(w, "flow", struct {
		*view
		FlowID string
		Flow   *mqtt.Flow
	}{vw, r.URL.Query().Get("id"), s.flowByID(vw, r.URL.Query().Get("id"))})
}

func (s *Server) handlePacket(w http.ResponseWriter, r *http.Request) {
	vw, err := s.loadView(r.URL.Query().Get("v"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.render(w, "packet", struct {
		*view
		PacketID string
		Packet   *mqtt.Packet
	}{vw, r.URL.Query().Get("id"), s.packetByID(vw, r.URL.Query().Get("id"))})
}

func (s *Server) handleProvenance(w http.ResponseWriter, r *http.Request) {
	vw, err := s.loadView("")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	id := r.PathValue("id")
	s.render(w, "provenance", struct {
		*view
		ID string
	}{vw, id})
}

func (s *Server) handleBranches(w http.ResponseWriter, r *http.Request) {
	vw, err := s.loadView("")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	conflicts, _ := s.st.Conflicts()
	branches, _ := s.st.Branches()
	s.render(w, "branches", struct {
		*view
		Conflicts []store.Conflict
		Branches  []store.Branch
	}{vw, conflicts, branches})
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	id := r.FormValue("conflict")
	choice := r.FormValue("choice")
	if err := s.st.ResolveConflict(id, choice); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	http.Redirect(w, r, "/branches", http.StatusSeeOther)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	vw, err := s.loadView("")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	all, _ := s.st.Events()
	s.render(w, "events", struct {
		*view
		AllEvents []store.Event
	}{vw, all})
}

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	all, err := s.st.Events()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var ev *store.Event
	for i := range all {
		if all[i].ID == id {
			ev = &all[i]
		}
	}
	if ev == nil {
		http.NotFound(w, r)
		return
	}
	vw, err := s.loadView(ev.Version)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.render(w, "events", struct {
		*view
		AllEvents []store.Event
		Focus     string
	}{vw, all, id})
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", "attachment; filename=mqttlab-export.ndjson")
	if err := s.st.Export(w); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (s *Server) handleImportForm(w http.ResponseWriter, r *http.Request) {
	vw, _ := s.loadView("")
	s.render(w, "branches", struct {
		*view
		Conflicts []store.Conflict
		Branches  []store.Branch
		ImportMsg string
	}{vw, nil, nil, ""})
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	f, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer f.Close()
	if err := s.st.Import(f); err != nil {
		http.Error(w, "import failed: "+err.Error(), 400)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleTour(w http.ResponseWriter, r *http.Request) {
	vw, err := s.loadView("")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.render(w, "tour", struct {
		*view
		Started string
	}{vw, time.Now().Format("15:04:05")})
}
