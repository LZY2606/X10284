package fixtures

import _ "embed"

//go:embed casepack.json
var casepackJSON []byte

// Load reads the committed offline case pack.
func Load() []byte { return casepackJSON }
