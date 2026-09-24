// Package derive recomputes derived artifacts through a dependency graph.
// Only nodes whose inputs changed are recomputed; every artifact records why
// it is still valid or why it had to be recomputed.
package derive

import (
	"encoding/json"
	"fmt"

	"mqttlab/internal/store"
)

// Node is one derivation step. Inputs are artifact names; Compute receives
// the decoded input objects and returns the new artifact value.
type Node struct {
	Name    string
	Inputs  []string
	Compute func(inputs map[string]json.RawMessage) (any, error)
}

type Engine struct {
	nodes []Node // topological order
}

func New(nodes ...Node) *Engine { return &Engine{nodes: nodes} }

// Result of one run: artifact states for the new version plus the object
// bodies that must be persisted.
type Result struct {
	Artifacts map[string]store.ArtifactState
	Objects   map[string]json.RawMessage
	Changed   []string
}

// Run evaluates the graph. sources maps source artifact names to their
// (already hashed) object bodies; prev is the previous version's artifact
// states and may be nil.
func (e *Engine) Run(sources map[string]json.RawMessage, prev map[string]store.ArtifactState) (*Result, error) {
	res := &Result{
		Artifacts: map[string]store.ArtifactState{},
		Objects:   map[string]json.RawMessage{},
	}
	ids := map[string]string{} // artifact name -> object id this run
	bodies := map[string]json.RawMessage{}
	for name, body := range sources {
		id := store.ObjectID(body)
		ids[name] = id
		bodies[name] = body
		res.Objects[id] = body
		res.Artifacts[name] = store.ArtifactState{ObjectID: id, Status: "source", Reason: "source object"}
	}
	for _, n := range e.nodes {
		inputs := map[string]string{}
		raw := map[string]json.RawMessage{}
		missing := false
		for _, in := range n.Inputs {
			id, ok := ids[in]
			if !ok {
				missing = true
				break
			}
			inputs[in] = id
			raw[in] = bodies[in]
		}
		if missing {
			return nil, fmt.Errorf("node %s: missing input", n.Name)
		}
		p, hadPrev := prev[n.Name]
		unchanged := hadPrev && sameInputs(p.Inputs, inputs)
		if unchanged {
			res.Artifacts[n.Name] = store.ArtifactState{
				ObjectID: p.ObjectID, Status: "valid",
				Reason: "inputs unchanged since " + p.ObjectID, Inputs: inputs,
			}
			ids[n.Name] = p.ObjectID
			continue
		}
		val, err := n.Compute(raw)
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", n.Name, err)
		}
		body, err := json.Marshal(val)
		if err != nil {
			return nil, err
		}
		id := store.ObjectID(body)
		ids[n.Name] = id
		bodies[n.Name] = body
		res.Objects[id] = body
		st := store.ArtifactState{ObjectID: id, Inputs: inputs}
		if hadPrev && id == p.ObjectID {
			st.Status = "identical"
			st.Reason = "recomputed after input change; result identical to " + p.ObjectID
		} else {
			st.Status = "recomputed"
			st.Reason = diffReason(p.Inputs, inputs)
			res.Changed = append(res.Changed, n.Name)
		}
		res.Artifacts[n.Name] = st
	}
	return res, nil
}

func sameInputs(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func diffReason(old, new map[string]string) string {
	for k, v := range new {
		if ov, ok := old[k]; !ok || ov != v {
			return fmt.Sprintf("input %s changed (%s -> %s)", k, short(ov), short(v))
		}
	}
	return "inputs changed"
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
