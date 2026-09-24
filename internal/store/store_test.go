package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCommitAndCurrent(t *testing.T) {
	s := open(t)
	_, v, err := s.Commit("", "first", "import", map[string]int{"n": 1}, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	cur, err := s.Current()
	if err != nil || cur.ID != v.ID {
		t.Fatalf("current = %v %v", cur, err)
	}
	if string(cur.StateJSON) != `{"a":1}` {
		t.Fatalf("state = %s", cur.StateJSON)
	}
}

func TestInterruptedWriteKeepsOldVersion(t *testing.T) {
	s := open(t)
	if _, _, err := s.Commit("", "v1", "import", nil, []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash mid-write: failpoint fires inside the transaction.
	s.Failpoint = func() error { return errors.New("simulated crash") }
	if _, _, err := s.Commit("", "v2", "edit", nil, []byte(`{"v":2}`)); err == nil {
		t.Fatal("expected interrupted write to fail")
	}
	s.Failpoint = nil
	cur, err := s.Current()
	if err != nil {
		t.Fatal(err)
	}
	if cur.ID != "v-0001" || string(cur.StateJSON) != `{"v":1}` {
		t.Fatalf("after crash current = %s %s, want v-0001", cur.ID, cur.StateJSON)
	}
	// And a subsequent full write still succeeds cleanly.
	if _, v, err := s.Commit("", "v2", "edit", nil, []byte(`{"v":2}`)); err != nil {
		t.Fatal(err)
	} else if v.ID != "v-0002" {
		t.Fatalf("version id = %s", v.ID)
	}
}

func TestConflictOnStaleBase(t *testing.T) {
	s := open(t)
	_, v1, _ := s.Commit("", "v1", "import", nil, []byte(`1`))
	// User A commits from v1.
	if _, _, err := s.Commit(v1.ID, "A", "decision", "A", []byte(`2`)); err != nil {
		t.Fatal(err)
	}
	// User B commits from the same base v1 -> conflict.
	_, _, err := s.Commit(v1.ID, "B", "decision", "B", []byte(`3`))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	confs, err := s.Conflicts()
	if err != nil || len(confs) != 1 || confs[0].Status != "open" {
		t.Fatalf("conflicts = %+v %v", confs, err)
	}
	if err := s.ResolveConflict(confs[0].ID, "first"); err != nil {
		t.Fatal(err)
	}
	confs, _ = s.Conflicts()
	if confs[0].Status != "resolved" || confs[0].Resolution != "first" {
		t.Fatalf("resolution = %+v", confs[0])
	}
}

func TestConcurrentSaveExactlyOneConflict(t *testing.T) {
	s := open(t)
	_, v1, _ := s.Commit("", "v1", "import", nil, []byte(`1`))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conflicts, commits int
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := s.Commit(v1.ID, fmt.Sprintf("u%d", i), "edit", i, []byte(fmt.Sprintf(`{"u":%d}`, i)))
			mu.Lock()
			if errors.Is(err, ErrConflict) {
				conflicts++
			} else if err == nil {
				commits++
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if commits != 1 || conflicts != 7 {
		t.Fatalf("commits=%d conflicts=%d, want 1 and 7", commits, conflicts)
	}
}

func TestMigrationFromV1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.db")
	// Build a v1 database by hand.
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM meta WHERE k='schema_version'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO meta (k,v) VALUES ('schema_version','1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TABLE conflicts`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TABLE v1vers AS SELECT id,parent,state,seq FROM versions`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TABLE versions`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE v1vers RENAME TO versions`); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen with migration: %v", err)
	}
	defer s2.Close()
	if !hasColumn(s2.db, "versions", "label") {
		t.Fatal("migration did not add label column")
	}
	if _, _, err := s2.Commit("", "after-migration", "edit", nil, []byte(`9`)); err != nil {
		t.Fatalf("commit after migration: %v", err)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	s := open(t)
	_, v1, _ := s.Commit("", "v1", "import", map[string]string{"src": "case"}, []byte(`{"n":1}`))
	s.Commit(v1.ID, "v2", "edit", nil, []byte(`{"n":2}`))
	s.Commit(v1.ID, "v2-conflict", "edit", nil, []byte(`{"n":3}`)) // conflict
	data, err := s.Export()
	if err != nil {
		t.Fatal(err)
	}
	// Delete the local database and import into a fresh one.
	s2 := open(t)
	if err := s2.Import(data); err != nil {
		t.Fatal(err)
	}
	ev1, _ := s.Events()
	ev2, _ := s2.Events()
	if len(ev1) != len(ev2) {
		t.Fatalf("events %d vs %d", len(ev1), len(ev2))
	}
	for i := range ev1 {
		if ev1[i].ID != ev2[i].ID || ev1[i].Seq != ev2[i].Seq || ev1[i].VersionID != ev2[i].VersionID {
			t.Fatalf("event %d mismatch: %+v vs %+v", i, ev1[i], ev2[i])
		}
	}
	vs1, _ := s.Versions()
	vs2, _ := s2.Versions()
	if len(vs1) != len(vs2) {
		t.Fatalf("versions %d vs %d", len(vs1), len(vs2))
	}
	for i := range vs1 {
		if vs1[i].ID != vs2[i].ID || vs1[i].Parent != vs2[i].Parent || string(vs1[i].StateJSON) != string(vs2[i].StateJSON) {
			t.Fatalf("version %d mismatch", i)
		}
	}
	c1, _ := s.Conflicts()
	c2, _ := s2.Conflicts()
	if len(c1) != len(c2) {
		t.Fatalf("conflicts %d vs %d", len(c1), len(c2))
	}
	cur, _ := s2.Current()
	if cur.ID == "" {
		t.Fatal("current pointer lost after import")
	}
}
