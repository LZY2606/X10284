package casepack

import (
	"errors"

	"pairwise-gsb/mqttsession/internal/engine"
)

// Mutation is one archived single-source change, replayable on demand.
type Mutation struct {
	ID    string
	Name  string
	Desc  string
	Apply func(pkts []engine.Packet) ([]engine.Packet, []string)
}

// Mutations exposes the archived mutations for live replay.
func Mutations() []Mutation {
	var out []Mutation
	for _, m := range mutations() {
		out = append(out, Mutation{ID: m.id, Name: m.name, Desc: m.desc, Apply: m.apply})
	}
	return out
}

// ApplyMutation re-applies one archived mutation to a baseline trace.
func ApplyMutation(id string, base []engine.Packet) ([]engine.Packet, []string, error) {
	for _, m := range Mutations() {
		if m.ID == id {
			pkts, changed := m.Apply(base)
			return pkts, changed, nil
		}
	}
	return nil, nil, errors.New("unknown mutation " + id)
}
