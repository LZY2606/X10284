package engine_test

import (
	"encoding/hex"
	"testing"
)

func h2b(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func b2h(b []byte) string { return hex.EncodeToString(b) }
