// Package units keeps every domain quantity together with its unit and
// coordinate basis. The raw representation seen at import time is always
// preserved; normalization happens only in the derived layer. Values that
// cannot be converted stay in place with a diagnostic attached.
package units

import (
	"fmt"
	"strconv"
	"strings"
)

// Basis names the coordinate system a quantity is expressed in.
type Basis string

const (
	BasisVirtualTick Basis = "virtual-tick" // deterministic replay clock, unit ms
	BasisWallClock   Basis = "wallclock"    // captured wall time, informational only
	BasisNone        Basis = "none"
)

// Quantity is a domain value with unit and coordinate basis.
type Quantity struct {
	Raw   string `json:"raw"`   // original representation, never rewritten
	Unit  string `json:"unit"`  // "s", "ms", "bytes", "count", ...
	Basis Basis  `json:"basis"` // coordinate basis
}

// Normalized is the derived-layer view of a Quantity.
type Normalized struct {
	Value float64 `json:"value"`
	Unit  string  `json:"unit"` // canonical unit
	Basis Basis  `json:"basis"`
	OK    bool    `json:"ok"`
	Diag  string  `json:"diag,omitempty"` // why conversion failed, if it did
}

// conversion factors into the canonical unit of each family
var toCanonical = map[string]struct {
	canonical string
	factor    float64
}{
	"ms":    {"ms", 1},
	"s":     {"ms", 1000},
	"min":   {"ms", 60000},
	"bytes": {"bytes", 1},
	"count": {"count", 1},
	"flag":  {"flag", 1},
	"id":    {"id", 1},
}

// Normalize converts the raw representation into the canonical unit of its
// family. It never mutates the original Quantity. Unconvertible values are
// reported with a diagnostic and OK=false instead of being dropped.
func (q Quantity) Normalize() Normalized {
	n := Normalized{Unit: q.Unit, Basis: q.Basis}
	conv, known := toCanonical[q.Unit]
	if !known {
		n.Diag = fmt.Sprintf("unknown unit %q; value left in raw form", q.Unit)
		return n
	}
	raw := strings.TrimSpace(q.Raw)
	if raw == "" {
		n.Diag = "empty raw value"
		return n
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		n.Diag = fmt.Sprintf("cannot parse %q as number: %v", q.Raw, err)
		return n
	}
	if v < 0 {
		n.Diag = fmt.Sprintf("negative value %v not meaningful for unit %q", v, q.Unit)
		return n
	}
	n.Value = v * conv.factor
	n.Unit = conv.canonical
	n.OK = true
	return n
}

// Q is a small constructor helper.
func Q(raw, unit string, basis Basis) Quantity {
	return Quantity{Raw: raw, Unit: unit, Basis: basis}
}
