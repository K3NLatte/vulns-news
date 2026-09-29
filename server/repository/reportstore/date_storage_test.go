package reportstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestUnknownDatesPersistAsNullThroughCRUD(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "reports.db")
	store := openDateStore(t, path)
	input := dateFixture(t)
	input.VulnerabilityRevision, input.PublishedAt, input.CVERevision = "", "", ""
	original, err := store.Create(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	assertStoredDates(t, store, original.ID, input)
	if !reflect.DeepEqual(original.Input, input) {
		t.Fatalf("create changed unknown source dates: want %#v, got %#v", input, original.Input)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openDateStore(t, path)
	got, err := store.Get(ctx, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Errorf("reopen changed report: want %#v, got %#v", original, got)
	}
	assertStoredDates(t, store, original.ID, input)

	// ソースのメタデータを修正すると、公開日を追加し、後から再び削除できる。
	// その際も、レポートの不変の識別情報と stored_at は変わらない。
	for _, date := range []string{"2026-09-28T12:34:56.123456789Z", ""} {
		input.PublishedAt, input.CVERevision = date, date
		updated, err := store.Update(ctx, original.ID, input)
		if err != nil {
			t.Fatal(err)
		}
		if updated.ID != original.ID || updated.StoredAt != original.StoredAt || updated.ContextKey != original.ContextKey {
			t.Errorf("date correction changed immutable metadata: %#v", updated)
		}
		if !reflect.DeepEqual(updated.Input, input) {
			t.Errorf("date correction changed input: want %#v, got %#v", input, updated.Input)
		}
		assertStoredDates(t, store, original.ID, input)
	}
	if err := store.Delete(ctx, original.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, original.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted unknown-date report: got %v, want ErrNotFound", err)
	}
}

func TestUnknownRevisionLatestSelectionStaysSeparateFromKnownRevision(t *testing.T) {
	ctx := context.Background()
	store := openDateStore(t, filepath.Join(t.TempDir(), "reports.db"))
	known := dateFixture(t)
	unknown := known
	unknown.VulnerabilityRevision, unknown.PublishedAt, unknown.CVERevision = "", "", ""
	oldUnknown := createDateReport(t, store, unknown)
	knownReport := createDateReport(t, store, known)

	unrelated := unknown
	unrelated.Status, unrelated.Relevance = Screened, Unrelated
	var body map[string]json.RawMessage
	if err := json.Unmarshal(unrelated.Body, &body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"summary", "repository_impact", "applicability", "missing_information", "recommended_actions"} {
		delete(body, key)
	}
	body["screening_reason"] = json.RawMessage(`"The affected execution path is not used."`)
	body["screening_evidence_ids"] = json.RawMessage(`["EVD-REPO-DEP-001"]`)
	var err error
	unrelated.Body, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	latestUnknown := createDateReport(t, store, unrelated)

	for _, want := range []Report{knownReport, latestUnknown} {
		got, err := store.GetLatest(ctx, want.ContextKey)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("latest for revision %q: want %#v, got %#v", want.VulnerabilityRevision, want, got)
		}
	}
	options := ListOptions{RepositoryID: known.RepositoryID, RepositoryCommit: known.RepositoryCommit}
	assertDateListIDs(t, store, options, knownReport.ID)
	options.IncludeUnrelated = true
	assertDateListIDs(t, store, options, latestUnknown.ID, knownReport.ID)
	options.IncludeUnrelated, options.BeforeID = false, latestUnknown.ID
	assertDateListIDs(t, store, options, knownReport.ID)
	// フィルタリングやカーソルによって、リビジョンが不明な古いレコードが再び取得されてはならない。
	if err := store.Delete(ctx, latestUnknown.ID); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetLatest(ctx, unknown.ContextKey)
	if err != nil || got.ID != oldUnknown.ID {
		t.Fatalf("unknown revision history after deletion: ID=%d err=%v", got.ID, err)
	}
	options.BeforeID = 0
	assertDateListIDs(t, store, options, knownReport.ID, oldUnknown.ID)
}

func TestMigrateVersion1PreservesReportsAndDeletedIDs(t *testing.T) {
	for _, empty := range []bool{false, true} {
		name := "retained report"
		if empty {
			name = "all reports deleted"
		}
		t.Run(name, func(t *testing.T) {
			path, original := createVersion1DateDB(t, empty, false)
			store := openDateStore(t, path)
			var version, count int
			if err := store.db.QueryRow("SELECT version FROM reportstore_schema").Scan(&version); err != nil || version != 3 {
				t.Fatalf("migration version=%d err=%v, want 3", version, err)
			}
			if err := store.db.QueryRow("SELECT count(*) FROM reports").Scan(&count); err != nil {
				t.Fatal(err)
			}
			wantCount := 1
			if empty {
				wantCount = 0
			} else {
				got, err := store.Get(context.Background(), original.ID)
				if err != nil || !reflect.DeepEqual(got, original) {
					t.Fatalf("migration changed report: want %#v, got %#v, err=%v", original, got, err)
				}
			}
			if count != wantCount {
				t.Errorf("migration report count=%d, want %d", count, wantCount)
			}
			input := original.Input
			input.VulnerabilityRevision, input.PublishedAt, input.CVERevision = "", "", ""
			created := createDateReport(t, store, input)
			if created.ID <= 99 {
				t.Errorf("migration reused a deleted ID: new ID=%d, deleted maximum=99", created.ID)
			}
			assertStoredDates(t, store, created.ID, input)
		})
	}
}

func TestMigrationFailureRestoresVersion1SchemaAndData(t *testing.T) {
	path, original := createVersion1DateDB(t, false, true)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var originalSQL string
	if err := db.QueryRow("SELECT sql FROM sqlite_schema WHERE name = 'reports'").Scan(&originalSQL); err != nil {
		t.Fatal(err)
	}
	store, err := Open(context.Background(), path)
	if store != nil {
		_ = store.Close()
		t.Fatal("failed migration returned a Store")
	}
	if err == nil || !strings.Contains(err.Error(), "migration blocked for test") {
		t.Fatalf("expected the injected end-of-migration failure, got %v", err)
	}
	var version, count int
	var sequence int64
	var gotSQL string
	if err := db.QueryRow("SELECT version FROM reportstore_schema").Scan(&version); err != nil || version != 1 {
		t.Errorf("failed migration changed version: version=%d err=%v", version, err)
	}
	if err := db.QueryRow("SELECT sql FROM sqlite_schema WHERE name = 'reports'").Scan(&gotSQL); err != nil || gotSQL != originalSQL {
		t.Errorf("failed migration changed original table definition: SQL=%q err=%v", gotSQL, err)
	}
	if err := db.QueryRow("SELECT count(*) FROM sqlite_schema WHERE name = 'reports_v1'").Scan(&count); err != nil || count != 0 {
		t.Errorf("failed migration retained temporary table: count=%d err=%v", count, err)
	}
	if err := db.QueryRow("SELECT count(*) FROM sqlite_schema WHERE type = 'index' AND name = 'reports_by_context' AND tbl_name = 'reports'").Scan(&count); err != nil || count != 1 {
		t.Errorf("failed migration lost original index: count=%d err=%v", count, err)
	}
	if err := db.QueryRow("SELECT seq FROM sqlite_sequence WHERE name = 'reports'").Scan(&sequence); err != nil || sequence != 99 {
		t.Errorf("failed migration changed deleted-ID watermark: sequence=%d err=%v", sequence, err)
	}
	if err := db.QueryRow("SELECT count(*) FROM reports").Scan(&count); err != nil || count != 1 {
		t.Errorf("failed migration changed original report count: count=%d err=%v", count, err)
	}
	got, err := scanReport(db.QueryRow("SELECT "+reportColumns+" FROM reports WHERE report_id = ?", original.ID))
	if err != nil || !reflect.DeepEqual(got, original) {
		t.Errorf("failed migration changed original report: want %#v, got %#v, err=%v", original, got, err)
	}
}

func dateFixture(t *testing.T) Input {
	t.Helper()
	raw, err := os.ReadFile("testdata/feed-item.json")
	if err != nil {
		t.Fatal(err)
	}
	input, err := FromFeedJSON(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func openDateStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func createDateReport(t *testing.T, store *Store, input Input) Report {
	t.Helper()
	report, err := store.Create(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func assertStoredDates(t *testing.T, store *Store, id int64, want Input) {
	t.Helper()
	var vulnerabilityRevision, publishedAt, cveRevision sql.NullString
	var cveID string
	err := store.db.QueryRow(`SELECT vulnerability_revision, published_at, cve_revision, cve_id
		FROM reports WHERE report_id = ?`, id).Scan(&vulnerabilityRevision, &publishedAt, &cveRevision, &cveID)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []struct {
		name string
		got  sql.NullString
		want string
	}{
		{"vulnerability_revision", vulnerabilityRevision, want.VulnerabilityRevision},
		{"published_at", publishedAt, want.PublishedAt},
		{"cve_revision", cveRevision, want.CVERevision},
	} {
		if field.got.Valid != (field.want != "") || field.got.String != field.want {
			t.Errorf("stored %s = %#v, want %q (SQL NULL when empty)", field.name, field.got, field.want)
		}
	}
	if cveID != want.CVEID {
		t.Errorf("missing dates changed CVE ID: got %q, want %q", cveID, want.CVEID)
	}
}

func assertDateListIDs(t *testing.T, store *Store, options ListOptions, want ...int64) {
	t.Helper()
	reports, err := store.ListLatest(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]int64, len(reports))
	for i, report := range reports {
		got[i] = report.ID
	}
	if !slices.Equal(got, want) {
		t.Errorf("latest report IDs=%v, want %v", got, want)
	}
}

func createVersion1DateDB(t *testing.T, empty, failMigration bool) (string, Report) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reports-v1.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	legacySchema, err := os.ReadFile("testdata/schema-v1.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(legacySchema)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE reportstore_schema (version INTEGER PRIMARY KEY) STRICT; INSERT INTO reportstore_schema VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	input := dateFixture(t)
	original := Report{ID: 41, Input: input, StoredAt: "2026-09-24T01:02:03.456Z"}
	for _, id := range []int64{original.ID, 99} {
		_, err := db.Exec(`INSERT INTO reports (
			report_id, repository_id, repository_commit, vulnerability_id, vulnerability_revision,
			cve_id, cve_revision, published_at, severity, cvss, status, relevance, report_json, stored_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, input.RepositoryID, input.RepositoryCommit, input.VulnerabilityID, input.VulnerabilityRevision,
			input.CVEID, input.CVERevision, input.PublishedAt, input.Severity, input.CVSS,
			input.Status, input.Relevance, string(input.Body), original.StoredAt)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("DELETE FROM reports WHERE report_id = 99 OR ?", empty); err != nil {
		t.Fatal(err)
	}
	if failMigration {
		// 置き換え先のテーブルへのデータ投入と旧テーブルの削除が済んだ後に失敗させる。
		// ロールバックでは、それまでのスキーマとデータの変更をすべて元に戻す必要がある。
		if _, err := db.Exec(`CREATE TRIGGER prevent_version_upgrade
			BEFORE UPDATE OF version ON reportstore_schema WHEN NEW.version = 2
			BEGIN SELECT RAISE(ABORT, 'migration blocked for test'); END`); err != nil {
			t.Fatal(err)
		}
	}
	return path, original
}
