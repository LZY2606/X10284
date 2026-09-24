// Command genfixture regenerates the committed offline case pack JSON. Tests
// use only this in-repo fixture, never external/network data.
package main

import (
	"encoding/json"
	"flag"
	"os"

	"github.com/example/mqtt-session-forensics/internal/fixtures"
)

func main() {
	out := flag.String("o", "internal/fixtures/casepack.json", "output path")
	flag.Parse()
	b := fixtures.Baseline()
	f, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(b); err != nil {
		panic(err)
	}
}
