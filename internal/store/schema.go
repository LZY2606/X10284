package store

// schemaV1 is the original shipped schema. Migration tests build a database at
// v1 and confirm Open upgrades it without losing identity, order or provenance.
const schemaV1 = `
CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE source (
  id TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  supersedes TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,
  direction TEXT NOT NULL DEFAULT '',
  ord INTEGER NOT NULL,
  time_ns INTEGER NOT NULL,
  payload TEXT NOT NULL,
  origin TEXT NOT NULL DEFAULT '',
  diagnostics TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY (id, revision)
);
CREATE TABLE rule_version (
  version TEXT PRIMARY KEY,
  created_ns INTEGER NOT NULL,
  params TEXT NOT NULL
);
CREATE TABLE commit (
  version TEXT PRIMARY KEY,
  parent TEXT NOT NULL,
  branch TEXT NOT NULL,
  label TEXT NOT NULL,
  created_ns INTEGER NOT NULL,
  rule_version TEXT NOT NULL,
  source_cut_ns INTEGER NOT NULL,
  root_hash TEXT NOT NULL,
  closed INTEGER NOT NULL DEFAULT 0,
  resolution_of TEXT NOT NULL DEFAULT '',
  resolution_kind TEXT NOT NULL DEFAULT ''
);
CREATE TABLE node_version (
  commit_version TEXT NOT NULL,
  node_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (commit_version, node_id)
);
CREATE TABLE current_pointer (
  singlerow INTEGER PRIMARY KEY CHECK (singlerow = 1),
  version TEXT NOT NULL,
  updated_ns INTEGER NOT NULL
);
CREATE TABLE event_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  commit_version TEXT NOT NULL,
  time_ns INTEGER NOT NULL,
  actor TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL
);
CREATE TABLE pending_mutation (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT INTO meta(key,value) VALUES ('schema_version','1');
`

// schemaV2Additions is applied when upgrading a v1 database.
const schemaV2Additions = `
ALTER TABLE node_version ADD COLUMN verdicts TEXT NOT NULL DEFAULT '[]';
ALTER TABLE node_version ADD COLUMN dependencies TEXT NOT NULL DEFAULT '[]';
ALTER TABLE node_version ADD COLUMN status TEXT NOT NULL DEFAULT 'ok';
ALTER TABLE node_version ADD COLUMN recompute_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE source ADD COLUMN trace_time TEXT NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS kv_blob (
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL
);
UPDATE meta SET value='2' WHERE key='schema_version';
`

// schemaV2 is the full current schema used for fresh databases.
const schemaV2 = schemaV1 + `
ALTER TABLE node_version ADD COLUMN verdicts TEXT NOT NULL DEFAULT '[]';
ALTER TABLE node_version ADD COLUMN dependencies TEXT NOT NULL DEFAULT '[]';
ALTER TABLE node_version ADD COLUMN status TEXT NOT NULL DEFAULT 'ok';
ALTER TABLE node_version ADD COLUMN recompute_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE source ADD COLUMN trace_time TEXT NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS kv_blob (
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL
);
UPDATE meta SET value='2' WHERE key='schema_version';
`
