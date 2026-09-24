package app

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/example/mqtt-session-forensics/internal/model"
)

// applyField mutates exactly one direct-source field. Flag patches rewrite the
// authoritative raw bytes so the derivation layer re-decodes them, instead of
// maintaining a parallel "override" column.
func applyField(p *model.RawPacket, field, value string) (string, error) {
	switch field {
	case "dup":
		raw, err := hex.DecodeString(p.RawHex)
		if err != nil {
			return "", err
		}
		if len(raw) == 0 {
			return "", errors.New("empty raw packet")
		}
		old := raw[0]&0x08 != 0
		if value == "true" || value == "1" {
			raw[0] |= 0x08
		} else {
			raw[0] &^= 0x08
		}
		p.RawHex = hex.EncodeToString(raw)
		return boolStr(old), nil
	case "retain":
		raw, err := hex.DecodeString(p.RawHex)
		if err != nil {
			return "", err
		}
		old := raw[0]&0x01 != 0
		if value == "true" || value == "1" {
			raw[0] |= 0x01
		} else {
			raw[0] &^= 0x01
		}
		p.RawHex = hex.EncodeToString(raw)
		return boolStr(old), nil
	case "direction":
		old := string(p.Direction)
		p.Direction = model.Direction(strings.ToUpper(value))
		if !p.Direction.Valid() {
			return "", errors.New("direction must be C2B or B2C")
		}
		return old, nil
	case "observed_at.original":
		old := p.ObservedAt.Original
		p.ObservedAt.Original = value
		return old, nil
	case "observed_at.unit":
		old := p.ObservedAt.Unit
		p.ObservedAt.Unit = value
		return old, nil
	case "raw_hex":
		old := p.RawHex
		if _, err := hex.DecodeString(value); err != nil {
			return "", errors.New("new raw_hex is not valid hex")
		}
		p.RawHex = value
		return old, nil
	}
	return "", errors.New("unsupported packet field: " + field)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
