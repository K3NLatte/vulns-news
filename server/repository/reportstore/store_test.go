package reportstore_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"vulns-news/server/repository/reportstore"
)

func fixtureInput(t testing.TB) reportstore.Input {
	t.Helper()
	raw, err := os.ReadFile("testdata/feed-item.json")
	if err != nil {
		t.Fatal(err)
	}
	in, err := reportstore.FromFeedJSON(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func openStore(t testing.TB, path string) *reportstore.Store {
	t.Helper()
	s, err := reportstore.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func createReport(t testing.TB, s *reportstore.Store, in reportstore.Input) reportstore.Report {
	t.Helper()
	r, err := s.Create(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mutateBody(t testing.TB, in reportstore.Input, mutate func(map[string]json.RawMessage)) reportstore.Input {
	t.Helper()
	var body map[string]json.RawMessage
	if err := json.Unmarshal(in.Body, &body); err != nil {
		t.Fatal(err)
	}
	mutate(body)
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	in.Body = raw
	return in
}

func assertJSONEqual(t testing.TB, want, got []byte) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(want, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("JSON differs:\nwant: %s\n got: %s", want, got)
	}
}

func assertReportEqual(t testing.TB, want, got reportstore.Report) {
	t.Helper()
	wantBody, gotBody := want.Body, got.Body
	want.Body, got.Body = nil, nil
	if !reflect.DeepEqual(want, got) {
		t.Errorf("report differs:\nwant: %#v\n got: %#v", want, got)
	}
	assertJSONEqual(t, wantBody, gotBody)
}

func listOptions(in reportstore.Input) reportstore.ListOptions {
	return reportstore.ListOptions{RepositoryID: in.RepositoryID, RepositoryCommit: in.RepositoryCommit}
}

func unrelatedInput(t testing.TB, in reportstore.Input) reportstore.Input {
	t.Helper()
	in.Status, in.Relevance = reportstore.Screened, reportstore.Unrelated
	return mutateBody(t, in, func(body map[string]json.RawMessage) {
		for _, key := range []string{"summary", "repository_impact", "applicability", "missing_information", "recommended_actions"} {
			delete(body, key)
		}
		body["screening_reason"] = json.RawMessage(`"対象の実行経路を使用していません。"`)
		body["screening_evidence_ids"] = json.RawMessage(`["EVD-REPO-DEP-001"]`)
	})
}

func TestCRUDPersistsAndReanalysisAppends(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "reports.db")
	s := openStore(t, path)
	in := fixtureInput(t)
	first := createReport(t, s, in)
	if first.ID <= 0 {
		t.Fatalf("invalid generated ID: %d", first.ID)
	}
	if _, err := time.Parse(time.RFC3339Nano, first.StoredAt); err != nil {
		t.Fatalf("stored_at is not RFC3339: %q: %v", first.StoredAt, err)
	}
	got, err := s.Get(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertReportEqual(t, first, got)
	assertJSONEqual(t, in.Body, got.Body)

	secondInput := mutateBody(t, in, func(body map[string]json.RawMessage) {
		body["recommended_actions"] = json.RawMessage(`["依存関係を更新して再確認する。"]`)
	})
	second := createReport(t, s, secondInput)
	if second.ID <= first.ID {
		t.Fatalf("reanalysis must append: first=%d second=%d", first.ID, second.ID)
	}
	got, err = s.GetLatest(ctx, in.ContextKey)
	if err != nil {
		t.Fatal(err)
	}
	assertReportEqual(t, second, got)

	correctedInput := mutateBody(t, in, func(body map[string]json.RawMessage) {
		body["screening_reason"] = json.RawMessage(`"判定理由の誤記を訂正しました。"`)
	})
	correctedInput.Severity = "MEDIUM"
	corrected, err := s.Update(ctx, first.ID, correctedInput)
	if err != nil {
		t.Fatal(err)
	}
	if corrected.ID != first.ID || corrected.StoredAt != first.StoredAt || corrected.ContextKey != first.ContextKey {
		t.Fatalf("update changed immutable metadata: before=%#v after=%#v", first, corrected)
	}
	assertJSONEqual(t, correctedInput.Body, corrected.Body)
	if corrected.Severity != "MEDIUM" {
		t.Errorf("severity was not updated: %q", corrected.Severity)
	}
	got, err = s.GetLatest(ctx, in.ContextKey)
	if err != nil {
		t.Fatal(err)
	}
	assertReportEqual(t, second, got)

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path) // 既存データベースへのマイグレーションの再実行も確認する。
	got, err = s.Get(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertReportEqual(t, corrected, got)
	if err := s.Delete(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, second.ID); !errors.Is(err, reportstore.ErrNotFound) {
		t.Fatalf("deleted report: got %v, want ErrNotFound", err)
	}
	got, err = s.GetLatest(ctx, in.ContextKey)
	if err != nil {
		t.Fatal(err)
	}
	assertReportEqual(t, corrected, got) // 最新のレコードを削除すると、保持されていた過去のレコードを取得できる。
	if err := s.Delete(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetLatest(ctx, in.ContextKey); !errors.Is(err, reportstore.ErrNotFound) {
		t.Fatalf("empty history: got %v, want ErrNotFound", err)
	}
	third := createReport(t, s, in)
	if third.ID <= second.ID {
		t.Fatalf("deleted report IDs must never be reused: %d <= %d", third.ID, second.ID)
	}
}

func TestOptionalFactsAndParameterTextSurviveStorage(t *testing.T) {
	ctx := context.Background()
	s := openStore(t, filepath.Join(t.TempDir(), "reports.db"))
	in := fixtureInput(t)
	in.RepositoryID = "owner/repo'; DROP TABLE reports; --"
	in.RepositoryCommit = "revision' OR 1=1 --"
	in.VulnerabilityID = "GHSA-no-cve"
	in.VulnerabilityRevision = "2026-09-24T12:00:00.123456789Z"
	in.PublishedAt = "2026-09-24T10:00:00.987654321Z"
	in.CVEID, in.CVERevision, in.Severity, in.CVSS = "", "", "", nil
	in = mutateBody(t, in, func(body map[string]json.RawMessage) {
		body["screening_reason"] = json.RawMessage(`"日本語の理由 '); DROP TABLE reports; --\n次の行"`)
	})
	unknown := createReport(t, s, in)
	zero := 0.0
	in.CVSS = &zero
	known := createReport(t, s, in)
	for _, want := range []reportstore.Report{unknown, known} {
		got, err := s.Get(ctx, want.ID)
		if err != nil {
			t.Fatal(err)
		}
		assertReportEqual(t, want, got)
		if got.CVEID != "" || got.CVERevision != "" || got.Severity != "" {
			t.Errorf("missing facts were fabricated: %#v", got.Input)
		}
	}
	if unknown.CVSS != nil || known.CVSS == nil || *known.CVSS != 0 {
		t.Errorf("unknown and zero CVSS not distinguished: nil=%v zero=%v", unknown.CVSS, known.CVSS)
	}
	rows, err := s.ListLatest(ctx, listOptions(in))
	if err != nil || len(rows) != 1 || rows[0].ID != known.ID {
		t.Fatalf("parameterized lookup failed: rows=%v err=%v", rows, err)
	}
}

func TestLatestSelectionPrecedesFilteringAndPagination(t *testing.T) {
	ctx := context.Background()
	s := openStore(t, filepath.Join(t.TempDir(), "reports.db"))
	base := fixtureInput(t)
	old := createReport(t, s, base)
	b := base
	b.VulnerabilityID, b.CVEID, b.CVERevision = "GHSA-second", "", ""
	otherVulnerability := createReport(t, s, b)
	c := base
	c.VulnerabilityRevision = "2026-09-25T12:00:00Z"
	otherRevision := createReport(t, s, c)
	latest := createReport(t, s, unrelatedInput(t, base))
	for _, alter := range []func(*reportstore.Input){
		func(in *reportstore.Input) { in.RepositoryID = "another/repository" },
		func(in *reportstore.Input) { in.RepositoryCommit = "another-commit" },
	} {
		isolated := base
		alter(&isolated)
		createReport(t, s, isolated)
	}
	rows, err := s.ListLatest(ctx, listOptions(base))
	if err != nil {
		t.Fatal(err)
	}
	assertIDs(t, rows, otherRevision.ID, otherVulnerability.ID)
	got, err := s.GetLatest(ctx, base.ContextKey)
	if err != nil || got.ID != latest.ID || got.Relevance != reportstore.Unrelated {
		t.Fatalf("latest unrelated decision must stay available: report=%#v err=%v", got, err)
	}

	opts := listOptions(base)
	opts.IncludeUnrelated, opts.Limit = true, 1
	var paged []reportstore.Report
	for i := 0; i < 4; i++ {
		page, err := s.ListLatest(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		if len(page) != 1 {
			t.Fatalf("limit not respected: %d", len(page))
		}
		paged = append(paged, page...)
		opts.BeforeID = page[len(page)-1].ID
	}
	assertIDs(t, paged, latest.ID, otherRevision.ID, otherVulnerability.ID)
	// 最新の行がカーソルより前にあるコンテキストでは、その最新行が unrelated として
	// 除外されても、カーソルによって同じコンテキストの古い行が再び取得されてはならない。
	opts = listOptions(base)
	opts.BeforeID = latest.ID
	rows, err = s.ListLatest(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	assertIDs(t, rows, otherRevision.ID, otherVulnerability.ID)
	if err := s.Delete(ctx, latest.ID); err != nil {
		t.Fatal(err)
	}
	rows, err = s.ListLatest(ctx, listOptions(base))
	if err != nil {
		t.Fatal(err)
	}
	assertIDs(t, rows, otherRevision.ID, otherVulnerability.ID, old.ID)
}

func assertIDs(t testing.TB, reports []reportstore.Report, want ...int64) {
	t.Helper()
	got := make([]int64, len(reports))
	for i, report := range reports {
		got[i] = report.ID
	}
	if !slices.Equal(want, got) {
		t.Errorf("report IDs: want %v, got %v", want, got)
	}
}

func TestInvalidMutationsLeaveExistingDataUntouched(t *testing.T) {
	ctx := context.Background()
	s := openStore(t, filepath.Join(t.TempDir(), "reports.db"))
	base := fixtureInput(t)
	original := createReport(t, s, base)
	for name, alter := range map[string]func(*reportstore.Input){
		"repository":    func(in *reportstore.Input) { in.RepositoryID = "different/repository" },
		"commit":        func(in *reportstore.Input) { in.RepositoryCommit = "different-commit" },
		"vulnerability": func(in *reportstore.Input) { in.VulnerabilityID = "GHSA-different" },
		"revision":      func(in *reportstore.Input) { in.VulnerabilityRevision = "2026-09-25T12:00:00Z" },
		"invalid body":  func(in *reportstore.Input) { in.Body = json.RawMessage(`{"evidence":`) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			alter(&changed)
			if _, err := s.Update(ctx, original.ID, changed); !errors.Is(err, reportstore.ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
			got, err := s.Get(ctx, original.ID)
			if err != nil {
				t.Fatal(err)
			}
			assertReportEqual(t, original, got)
		})
	}
	invalid := base
	invalid.Body = json.RawMessage(`{}`)
	if _, err := s.Create(ctx, invalid); !errors.Is(err, reportstore.ErrInvalid) {
		t.Fatalf("invalid create: got %v, want ErrInvalid", err)
	}
	rows, err := s.ListLatest(ctx, listOptions(base))
	if err != nil {
		t.Fatal(err)
	}
	assertIDs(t, rows, original.ID)
	latest, err := s.GetLatest(ctx, base.ContextKey)
	if err != nil {
		t.Fatal(err)
	}
	assertReportEqual(t, original, latest)
}

func TestNotFoundAndInvalidLookupInputs(t *testing.T) {
	ctx := context.Background()
	s := openStore(t, filepath.Join(t.TempDir(), "reports.db"))
	in := fixtureInput(t)
	for name, call := range map[string]func() error{
		"get":    func() error { _, err := s.Get(ctx, 1); return err },
		"latest": func() error { _, err := s.GetLatest(ctx, in.ContextKey); return err },
		"update": func() error { _, err := s.Update(ctx, 1, in); return err },
		"delete": func() error { return s.Delete(ctx, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, reportstore.ErrNotFound) {
				t.Errorf("got %v, want ErrNotFound", err)
			}
		})
	}
	for _, id := range []int64{0, -1} {
		for name, call := range map[string]func() error{
			"get":    func() error { _, err := s.Get(ctx, id); return err },
			"update": func() error { _, err := s.Update(ctx, id, in); return err },
			"delete": func() error { return s.Delete(ctx, id) },
		} {
			if err := call(); !errors.Is(err, reportstore.ErrInvalid) {
				t.Errorf("%s id=%d: got %v, want ErrInvalid", name, id, err)
			}
		}
	}
	if _, err := s.GetLatest(ctx, reportstore.ContextKey{}); !errors.Is(err, reportstore.ErrInvalid) {
		t.Errorf("empty context: got %v, want ErrInvalid", err)
	}
	for name, opts := range map[string]reportstore.ListOptions{
		"missing repository": {RepositoryCommit: in.RepositoryCommit},
		"missing commit":     {RepositoryID: in.RepositoryID},
		"negative limit":     {RepositoryID: in.RepositoryID, RepositoryCommit: in.RepositoryCommit, Limit: -1},
		"excessive limit":    {RepositoryID: in.RepositoryID, RepositoryCommit: in.RepositoryCommit, Limit: 201},
		"negative cursor":    {RepositoryID: in.RepositoryID, RepositoryCommit: in.RepositoryCommit, BeforeID: -1},
	} {
		if _, err := s.ListLatest(ctx, opts); !errors.Is(err, reportstore.ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestCanceledContextDoesNotMutateReports(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "reports.db"))
	in := fixtureInput(t)
	original := createReport(t, s, in)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, call := range map[string]func() error{
		"create": func() error { _, err := s.Create(ctx, in); return err },
		"get":    func() error { _, err := s.Get(ctx, original.ID); return err },
		"latest": func() error { _, err := s.GetLatest(ctx, in.ContextKey); return err },
		"list":   func() error { _, err := s.ListLatest(ctx, listOptions(in)); return err },
		"update": func() error { _, err := s.Update(ctx, original.ID, in); return err },
		"delete": func() error { return s.Delete(ctx, original.ID) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, context.Canceled) {
				t.Errorf("got %v, want context.Canceled", err)
			}
		})
	}
	if canceledStore, err := reportstore.Open(ctx, filepath.Join(t.TempDir(), "canceled.db")); !errors.Is(err, context.Canceled) {
		if canceledStore != nil {
			_ = canceledStore.Close()
		}
		t.Errorf("open: got %v, want context.Canceled", err)
	}
	latest, err := s.GetLatest(context.Background(), in.ContextKey)
	if err != nil {
		t.Fatal(err)
	}
	assertReportEqual(t, original, latest)
}

func TestConcurrentCreateAndReadAcrossStoreInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports.db")
	stores := []*reportstore.Store{openStore(t, path), openStore(t, path)}
	in := fixtureInput(t)
	ctx := context.Background()
	const count = 24
	var wg sync.WaitGroup
	errs := make(chan error, count)
	ids := make(chan int64, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			writer := stores[i%len(stores)]
			reader := stores[(i+1)%len(stores)]
			created, err := writer.Create(ctx, in)
			if err != nil {
				errs <- fmt.Errorf("create %d: %w", i, err)
				return
			}
			ids <- created.ID
			got, err := reader.Get(ctx, created.ID)
			if err != nil || got.ID != created.ID {
				errs <- fmt.Errorf("read %d: ID=%d err=%v", created.ID, got.ID, err)
				return
			}
			latest, err := reader.GetLatest(ctx, in.ContextKey)
			if err != nil || latest.ID < created.ID {
				errs <- fmt.Errorf("latest after %d: ID=%d err=%v", created.ID, latest.ID, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		t.Error(err)
	}
	seen := make(map[int64]bool)
	var maxID int64
	for id := range ids {
		if seen[id] {
			t.Errorf("duplicate ID %d", id)
		}
		seen[id] = true
		maxID = max(maxID, id)
	}
	if len(seen) != count {
		t.Errorf("created %d/%d records", len(seen), count)
	}
	rows, err := stores[0].ListLatest(ctx, listOptions(in))
	if err != nil {
		t.Fatal(err)
	}
	assertIDs(t, rows, maxID)
}

func TestOpenRejectsUnknownDatabaseSchemaWithoutChangingIt(t *testing.T) {
	for name, setup := range map[string][]string{
		"legacy reports without migration metadata": {
			"CREATE TABLE reports (report_id INTEGER PRIMARY KEY, note TEXT)",
			"INSERT INTO reports VALUES (42, 'existing data')",
		},
		"future migration version": {
			"CREATE TABLE reportstore_schema (version INTEGER NOT NULL)",
			"INSERT INTO reportstore_schema (version) VALUES (999)",
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "reports.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			for _, statement := range setup {
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			if s, err := reportstore.Open(context.Background(), path); err == nil {
				_ = s.Close()
				t.Fatal("incompatible schema was accepted")
			}
			if name == "legacy reports without migration metadata" {
				var note string
				if err := db.QueryRow("SELECT note FROM reports WHERE report_id = 42").Scan(&note); err != nil || note != "existing data" {
					t.Fatalf("existing data changed: note=%q err=%v", note, err)
				}
			} else {
				var version int
				if err := db.QueryRow("SELECT version FROM reportstore_schema").Scan(&version); err != nil || version != 999 {
					t.Fatalf("future version changed: version=%d err=%v", version, err)
				}
			}
		})
	}
}
