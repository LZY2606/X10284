package archive

import "encoding/json"

func marshal(v any) []byte {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// NowNSExternal exposes virtual-independent wall clock for bookkeeping rows.
func NowNSExternal() int64 { return nowNS() }
