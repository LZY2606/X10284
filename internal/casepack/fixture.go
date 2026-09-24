package casepack

import (
	_ "embed"
	"encoding/json"

	"pairwise-gsb/mqttsession/internal/engine"
)

//go:embed pack/trace.json
var fixtureJSON []byte

// Fixture is the offline case pack shipped in the repository.
type Fixture struct {
	Case     string            `json:"case"`
	Basis    map[string]string `json:"units_and_basis"`
	Snapshot BrokerSnapshot    `json:"broker_snapshot"`
	Packets  []engine.Packet   `json:"packets"`
}

// LoadFixture reads the repository-shipped offline case pack.
func LoadFixture() (*Fixture, error) {
	var f Fixture
	if err := json.Unmarshal(fixtureJSON, &f); err != nil {
		return nil, err
	}
	return &f, nil
}
