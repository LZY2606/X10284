package store

import (
	"context"
	"encoding/json"
	"os"

	"github.com/example/mqtt-session-forensics/internal/archive"
)

// PortableArchive is the export/import representation. It carries the baseline
// bundles and the committed graphs plus the event ledger. Stable identities are
// content-derived (node UIDs + value hashes), so deleting the local database
// and re-importing preserves identity, order and source relations.
type PortableArchive struct {
	Format    string                 `json:"format"`
	SchemaV   int                    `json:"schema_version"`
	Branches  []PortableBranch       `json:"branches"`
}

type PortableBranch struct {
	Info     BranchInfo       `json:"info"`
	Events   []json.RawMessage `json:"events"`
	Versions []PortableVersion `json:"versions"`
}

type PortableVersion struct {
	Version  int             `json:"version"`
	Bundle   json.RawMessage `json:"bundle"`
	Graph    json.RawMessage `json:"graph"`
	Report   json.RawMessage `json:"report,omitempty"`
}

// Export writes the portable archive for the given branches (or all).
func (s *Store) Export(ctx context.Context, path string, branches []string) error {
	if len(branches) == 0 {
		infos, err := s.ListBranches(ctx)
		if err != nil {
			return err
		}
		for _, b := range infos {
			branches = append(branches, b.Name)
		}
	}
	pa := PortableArchive{Format: "mqtt-session-forensics/1", SchemaV: currentSchema}
	for _, name := range branches {
		pb := PortableBranch{}
		infos, err := s.ListBranches(ctx)
		if err != nil {
			return err
		}
		for _, bi := range infos {
			if bi.Name == name {
				pb.Info = bi
			}
		}
		events, err := s.Events(ctx, name)
		if err != nil {
			return err
		}
		for i := range events {
			ev := events[i]
			var labels json.RawMessage
			if ev.Labels != nil {
				labels, _ = json.Marshal(ev.Labels)
			}
			type evRow struct {
				Seq       int64           `json:"seq"`
				Branch    string          `json:"branch"`
				ParentSeq int64           `json:"parent_seq"`
				Kind      string          `json:"kind"`
				AtNS      int64           `json:"at_ns"`
				Actor     string          `json:"actor"`
				Title     string          `json:"title"`
				Summary   string          `json:"summary"`
				Payload   json.RawMessage `json:"payload"`
				Labels    json.RawMessage `json:"labels,omitempty"`
			}
			row := evRow{Seq: ev.Seq, Branch: ev.Branch, ParentSeq: ev.ParentSeq,
				Kind: ev.Kind, AtNS: ev.AtNS, Actor: ev.Actor, Title: ev.Title,
				Summary: ev.Summary, Payload: json.RawMessage(ev.Payload), Labels: labels}
			b, _ := json.Marshal(row)
			pb.Events = append(pb.Events, b)
		}
		versions, err := s.Versions(ctx, name)
		if err != nil {
			return err
		}
		for _, v := range versions {
			b, err := s.BundleAt(ctx, name, v)
			if err != nil {
				return err
			}
			g, err := s.GraphAt(ctx, name, v)
			if err != nil {
				return err
			}
			bj, _ := json.Marshal(b)
			gj, _ := json.Marshal(g)
			pv := PortableVersion{Version: v, Bundle: bj, Graph: gj}
			if r, err := s.ReportAt(ctx, name, v); err == nil {
				pv.Report, _ = json.Marshal(r)
			}
			pb.Versions = append(pb.Versions, pv)
		}
		pa.Branches = append(pa.Branches, pb)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(pa)
}

// Import loads a portable archive into an (ideally empty) database, rebuilding
// the same branch pointers, versions, events and materialised rows.
func (s *Store) Import(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var pa PortableArchive
	if err := json.NewDecoder(f).Decode(&pa); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, pb := range pa.Branches {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO branches(name,parent_branch,parent_seq,base_version,head_seq,head_version,created_ns,note)
			 VALUES(?,?,?,?,?,?,?,?)
			 ON CONFLICT(name) DO NOTHING`,
			pb.Info.Name, nullStr(pb.Info.Parent), nullInt(pb.Info.ParentSeq),
			pb.Info.BaseVersion, pb.Info.HeadSeq, pb.Info.HeadVersion,
			archive.NowNSExternal(), pb.Info.Note); err != nil {
			return err
		}
		for _, raw := range pb.Events {
			var ev struct {
				Seq       int64           `json:"seq"`
				Branch    string          `json:"branch"`
				ParentSeq int64           `json:"parent_seq"`
				Kind      string          `json:"kind"`
				AtNS      int64           `json:"at_ns"`
				Actor     string          `json:"actor"`
				Title     string          `json:"title"`
				Summary   string          `json:"summary"`
				Payload   json.RawMessage `json:"payload"`
				Labels    json.RawMessage `json:"labels"`
			}
			if err := json.Unmarshal(raw, &ev); err != nil {
				return err
			}
			var labels any
			if len(ev.Labels) > 0 {
				_ = json.Unmarshal(ev.Labels, &labels)
			}
			lb, _ := json.Marshal(labels)
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO events(seq,branch,parent_seq,kind,at_ns,actor,title,summary,payload,labels)
				 VALUES(?,?,?,?,?,?,?,?,?,?)`,
				ev.Seq, ev.Branch, ev.ParentSeq, ev.Kind, ev.AtNS, ev.Actor,
				ev.Title, ev.Summary, optionalJSON(ev.Payload), string(lb)); err != nil {
				return err
			}
		}
		for _, pv := range pb.Versions {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO versions(branch,version,graph,bundle,computed_ns) VALUES(?,?,?,?,?)`,
				pb.Info.Name, pv.Version, string(pv.Graph), string(pv.Bundle), archive.NowNSExternal()); err != nil {
				return err
			}
			if len(pv.Report) > 0 {
				if _, err := tx.ExecContext(ctx,
					`INSERT OR REPLACE INTO reports(branch,version,report) VALUES(?,?,?)`,
					pb.Info.Name, pv.Version, string(pv.Report)); err != nil {
					return err
				}
			}
			var b struct {
				Packets []struct {
					ID           string `json:"id"`
					Direction    string `json:"direction"`
					RawHex       string `json:"raw_hex"`
					CapsuleBytes string `json:"capsule_hex"`
					ConnectionID string `json:"connection_id"`
					ClientIDHint string `json:"client_id_hint"`
					IngestOrder  int    `json:"ingest_order"`
					ObservedAt   struct {
						Original string `json:"original"`
						Unit     string `json:"unit"`
					} `json:"observed_at"`
				} `json:"packets"`
				Snapshots []struct {
					ID           string          `json:"id"`
					ClientID     string          `json:"client_id"`
					ConnectionID string          `json:"connection_id"`
					JSON         json.RawMessage `json:"json"`
					ObservedAt   struct {
						Original string `json:"original"`
						Unit     string `json:"unit"`
					} `json:"observed_at"`
				} `json:"snapshots"`
				Params map[string]struct {
					Value string `json:"value"`
					Unit  string `json:"unit"`
				} `json:"params"`
			}
			if err := json.Unmarshal(pv.Bundle, &b); err != nil {
				return err
			}
			for _, p := range b.Packets {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO packets(id,version,branch,direction,raw_hex,capsule_hex,connection_id,client_hint,ingest_order,time_orig,time_unit)
					 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
					p.ID, p.Direction, p.RawHex, p.CapsuleBytes, p.ConnectionID,
					p.ClientIDHint, p.IngestOrder, p.ObservedAt.Original, p.ObservedAt.Unit,
					pb.Info.Name); err != nil {
					return err
				}
			}
			for _, sn := range b.Snapshots {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO snapshots_tbl(id,version,branch,client_id,connection_id,time_orig,time_unit,json_text)
					 VALUES(?,?,?,?,?,?,?,?)`,
					sn.ID, pv.Version, pb.Info.Name, sn.ClientID, sn.ConnectionID,
					sn.ObservedAt.Original, sn.ObservedAt.Unit, string(sn.JSON)); err != nil {
					return err
				}
			}
			for name, pr := range b.Params {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO params_tbl(version,branch,name,value,unit) VALUES(?,?,?,?,?)`,
					pv.Version, pb.Info.Name, name, pr.Value, pr.Unit); err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit()
}

func optionalJSON(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}
