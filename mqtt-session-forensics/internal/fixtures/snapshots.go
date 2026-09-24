package fixtures

import (
	"encoding/json"

	"github.com/example/mqtt-session-forensics/internal/model"
)

// Snapshots returns broker session snapshots embedded in the case pack. They
// are evidence independent of packet capture: inflight packet ids are given
// with their original virtual-time text and coordinate basis preserved.
func Snapshots() []model.SnapshotRecord {
	mk := func(id, client, conn, orig, unit string, doc map[string]any) model.SnapshotRecord {
		doc["virtual_time_original"] = orig
		doc["virtual_time_unit"] = unit
		j, _ := json.Marshal(doc)
		s := model.SnapshotRecord{ID: id, ClientID: client, ConnectionID: conn,
			JSON: json.RawMessage(j)}
		s.ObservedAt = t(orig, unit)
		return s
	}
	return []model.SnapshotRecord{
		mk("snap-001", "sensor-a", "tcp-10.0.0.10:4401", "1215", "ms", map[string]any{
			"source": "broker-session-dump",
			"inflight_packet_ids": []any{200},
			"session_present":     true,
		}),
		mk("snap-002", "device-c", "tcp-10.0.0.30:6101", "5105", "ms", map[string]any{
			"source": "broker-session-dump",
			"inflight_packet_ids": []any{900},
			"generation_serial":  1,
			"clean_start":        true,
		}),
		mk("snap-003", "device-c", "tcp-10.0.0.30:6102", "6108", "ms", map[string]any{
			"source": "broker-session-dump",
			"inflight_packet_ids": []any{900},
			"generation_serial":  2,
			"clean_start":        true,
			"note": "same numeric packet id as snap-002, different session generation",
		}),
	}
}
