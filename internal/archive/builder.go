// Package archive builds the in-repository offline MQTT case pack: real
// packet bytes, direction, packet ids, DUP/retain flags, clean start /
// session expiry, topic aliases, clocks with coordinate bases, and broker
// session snapshots.
package archive

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"mqtttrace/internal/codec"
	"mqtttrace/internal/domain"
)

const (
	// ClockBasis is the single clock coordinate basis of the offline pack.
	ClockBasis = "virtual:bench-rig-7/ms"
	ClientID   = "sensor-gw-04"
)

// Builder accumulates packets and snapshots into a Bundle.
type Builder struct {
	bundle domain.Bundle
	pn     int
	sn     int
}

func NewBuilder(name, origin string) *Builder {
	return &Builder{bundle: domain.Bundle{Name: name, Origin: origin}}
}

func (b *Builder) SetBase(baseID, note string) {
	b.bundle.BaseBundleID = baseID
	b.bundle.ChangeNote = note
}

// Clock makes a clock with the pack basis. Pass the original representation
// raw (numbers here are ms-since-rig-reset).
func Clock(tMs int64, src string) domain.Clock {
	raw, _ := json.Marshal(tMs)
	return domain.Clock{
		Source: src, Unit: "ms-since-rig-reset", Epoch: "rig-reset#0",
		Raw: raw, VTimeMs: tMs, VTimeBasis: ClockBasis, Convertible: true,
	}
}

// UnconvertibleClock preserves a value the importer cannot put on the
// normalized timeline; it stays in place with a diagnostic.
func UnconvertibleClock(src, rawNum, why string) domain.Clock {
	return domain.Clock{
		Source: src, Unit: "unknown", Raw: json.RawMessage(`"` + rawNum + `"`),
		VTimeMs: -1, Convertible: false, Diag: why,
	}
}

func (b *Builder) pid() string {
	h := sha1.Sum([]byte(fmt.Sprintf("%s/%d/%s", b.bundle.Name, b.bundle.packetCount(), b.bundle.Origin)))
	return "pkt-" + hex.EncodeToString(h[:6])
}

// P adds a packet encoded from f at virtual time tMs.
func (b *Builder) P(f codec.Frame, dir string, tMs int64, src string) *domain.Packet {
	if f.Protocol == 0 {
		f.Protocol = 5
	}
	raw, err := codec.Encode(f)
	if err != nil {
		panic(err)
	}
	b.pn++
	pkt := &domain.Packet{
		ID: b.pid(), Seq: b.pn, Raw: raw, Dir: dir,
		Type: codec.TypeName(f.Type), DUP: f.DUP, RETAIN: f.RETAIN,
		QoS: f.QoS, PacketID: int(f.PacketID), Topic: f.Topic,
		TopicAlias: int(f.Alias), Clock: Clock(tMs, src),
	}
	if len(f.Payload) > 0 {
		pkt.Payload = append([]byte(nil), f.Payload...)
	}
	b.bundle.Packets = append(b.bundle.Packets, *pkt)
	return &b.bundle.Packets[len(b.bundle.Packets)-1]
}

// PRaw attaches a packet whose bytes were captured verbatim (still decoded
// for the view). Used to prove bytes are the authority.
func (b *Builder) PRaw(raw []byte, dir string, tMs int64, src string) *domain.Packet {
	d, err := codec.Decode(raw)
	if err != nil {
		panic(err)
	}
	f := d.Frame
	b.pn++
	pkt := &domain.Packet{
		ID: b.pid(), Seq: b.pn, Raw: append([]byte(nil), raw...), Dir: dir,
		Type: codec.TypeName(f.Type), DUP: f.DUP, RETAIN: f.RETAIN,
		QoS: f.QoS, PacketID: int(f.PacketID), Topic: f.Topic,
		TopicAlias: int(f.Alias), Clock: Clock(tMs, src), Diag: d.Diags,
	}
	if len(f.Payload) > 0 {
		pkt.Payload = append([]byte(nil), f.Payload...)
	}
	b.bundle.Packets = append(b.bundle.Packets, *pkt)
	return &b.bundle.Packets[len(b.bundle.Packets)-1]
}

// PBad adds bytes that are deliberately malformed/ambiguous; the raw bytes
// are retained and the view row carries the diagnostic.
func (b *Builder) PBad(raw []byte, dir string, tMs int64, src, why string) *domain.Packet {
	b.pn++
	pkt := &domain.Packet{
		ID: b.pid(), Seq: b.pn, Raw: append([]byte(nil), raw...), Dir: dir,
		Type: "UNKNOWN", Clock: Clock(tMs, src),
		Diag: []string{why},
	}
	b.bundle.Packets = append(b.bundle.Packets, *pkt)
	return &b.bundle.Packets[len(b.bundle.Packets)-1]
}

// Snap starts a broker session snapshot at tMs.
func (b *Builder) Snap(clientID string, present *bool, tMs int64, src string) *domain.Snapshot {
	b.sn++
	id := "snap-" + strconv.Itoa(b.sn)
	s := domain.Snapshot{
		ID: id, Seq: b.sn, ClientID: clientID, SessionPresent: present,
		Clock: Clock(tMs, src), Raw: map[string]any{},
	}
	b.bundle.Snapshots = append(b.bundle.Snapshots, s)
	return &b.bundle.Snapshots[len(b.bundle.Snapshots)-1]
}

func (b *Builder) Build() domain.Bundle {
	if b.bundle.ID == "" {
		h := sha1.Sum([]byte(b.bundle.Name + "|" + b.bundle.Origin))
		b.bundle.ID = "bundle-" + hex.EncodeToString(h[:8])
	}
	return b.bundle
}

func (b *Builder) packetCount() int { return b.pn }

// Mutate returns a copy of the bundle with a new id/name, carrying the
// base-bundle provenance and a human-readable change note.
func Mutate(base domain.Bundle, name, note string, edit func(pkts []domain.Packet) []domain.Packet) domain.Bundle {
	out := base
	h := sha1.Sum([]byte(name + "|" + note + "|" + base.ID))
	out.ID = "bundle-" + hex.EncodeToString(h[:8])
	out.Name = name
	out.BaseBundleID = base.ID
	out.ChangeNote = note
	out.Packets = nil
	for _, p := range base.Packets {
		out.Packets = append(out.Packets, *clonePkt(&p))
	}
	snaps := append([]domain.Snapshot(nil), base.Snapshots...)
	out.Packets = edit(out.Packets)
	out.Snapshots = snaps
	return out
}

func clonePkt(p *domain.Packet) *domain.Packet {
	q := *p
	q.Raw = append([]byte(nil), p.Raw...)
	q.Payload = append([]byte(nil), p.Payload...)
	return &q
}
