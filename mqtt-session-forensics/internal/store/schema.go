// Package store is the SQLite-backed, crash-safe archive and version store.
//
// Atomicity: a new derivation version is written completely inside one
// transaction; the branch head pointer is advanced in the same transaction. A
// process killed mid-write therefore exposes either the old version or the
// complete new version, never a partial graph.
package store

const schemaSQL = `
CREATE TABLE IF NOT EXISTS schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS packets (
  id           TEXT NOT NULL,
  version      INTEGER NOT NULL,
  branch       TEXT NOT NULL,
  direction    TEXT NOT NULL,
  raw_hex      TEXT NOT NULL,
  capsule_hex  TEXT,
  connection_id TEXT NOT NULL,
  client_hint  TEXT,
  ingest_order INTEGER NOT NULL,
  time_orig    TEXT NOT NULL,
  time_unit    TEXT NOT NULL,
  superseded_by INTEGER,
  PRIMARY KEY (id, version, branch)
);

CREATE TABLE IF NOT EXISTS snapshots_tbl (
  id TEXT NOT NULL, version INTEGER NOT NULL, branch TEXT NOT NULL,
  client_id TEXT NOT NULL, connection_id TEXT,
  time_orig TEXT NOT NULL, time_unit TEXT NOT NULL, json_text TEXT NOT NULL,
  PRIMARY KEY (id, version, branch)
);

CREATE TABLE IF NOT EXISTS params_tbl (
  version INTEGER NOT NULL, branch TEXT NOT NULL, name TEXT NOT NULL,
  value TEXT NOT NULL, unit TEXT,
  PRIMARY KEY (version, branch, name)
);

CREATE TABLE IF NOT EXISTS branches (
  name        TEXT PRIMARY KEY,
  parent_branch TEXT,
  parent_seq  INTEGER,
  base_version INTEGER NOT NULL DEFAULT 0,
  head_seq    INTEGER NOT NULL DEFAULT 0,
  head_version INTEGER NOT NULL DEFAULT 0,
  created_ns  INTEGER NOT NULL,
  note        TEXT
);

CREATE TABLE IF NOT EXISTS events (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  branch     TEXT NOT NULL,
  parent_seq INTEGER NOT NULL,
  kind       TEXT NOT NULL,
  at_ns      INTEGER NOT NULL,
  actor      TEXT,
  title      TEXT NOT NULL,
  summary    TEXT,
  payload    TEXT,
  labels     TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_branch ON events(branch, seq);

CREATE TABLE IF NOT EXISTS versions (
  branch    TEXT NOT NULL,
  version   INTEGER NOT NULL,
  graph     TEXT NOT NULL,
  bundle    TEXT NOT NULL,
  computed_ns INTEGER NOT NULL,
  PRIMARY KEY (branch, version)
);

CREATE TABLE IF NOT EXISTS reports (
  branch   TEXT NOT NULL,
  version  INTEGER NOT NULL,
  report   TEXT NOT NULL,
  PRIMARY KEY (branch, version)
);
`
