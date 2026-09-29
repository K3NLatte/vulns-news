package reportstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func TestEquivalentRevisionSpellingsShareHistory(t *testing.T) {
	for _, dates := range []struct{ spelling, canonical, next string }{
		{"2026-09-24T12:00:00.000Z", "2026-09-24T12:00:00Z", "2026-09-24T12:00:00.000000001Z"},
		{"2026-09-24T12:00:00.1200Z", "2026-09-24T12:00:00.12Z", "2026-09-24T12:00:00.120000001Z"},
	} {
		t.Run(dates.spelling, func(t *testing.T) {
			ctx := context.Background()
			store := openDateStore(t, filepath.Join(t.TempDir(), "reports.db"))
			input := dateFixture(t)
			input.VulnerabilityRevision, input.PublishedAt, input.CVERevision = dates.spelling, dates.spelling, dates.spelling
			original := createDateReport(t, store, input)
			canonical := input
			canonical.VulnerabilityRevision, canonical.PublishedAt, canonical.CVERevision = dates.canonical, dates.canonical, dates.canonical
			if !reflect.DeepEqual(original.Input, canonical) {
				t.Fatalf("create must normalize dates and preserve body: want %#v, got %#v", canonical, original.Input)
			}
			assertStoredDates(t, store, original.ID, canonical)
			for _, revision := range []string{dates.spelling, dates.canonical} {
				key := original.ContextKey
				key.VulnerabilityRevision = revision
				got, err := store.GetLatest(ctx, key)
				if err != nil || !reflect.DeepEqual(got, original) {
					t.Fatalf("equivalent lookup %q: got %#v, err=%v", revision, got, err)
				}
			}

			input.Severity = "MEDIUM"
			corrected, err := store.Update(ctx, original.ID, input)
			if err != nil {
				t.Fatalf("correction with equivalent revision: %v", err)
			}
			canonical.Severity = input.Severity
			if corrected.ID != original.ID || corrected.StoredAt != original.StoredAt || !reflect.DeepEqual(corrected.Input, canonical) {
				t.Fatalf("correction changed identity or failed to normalize dates: %#v", corrected)
			}
			assertStoredDates(t, store, original.ID, canonical)
			input.VulnerabilityRevision = dates.next
			if _, err := store.Update(ctx, original.ID, input); !errors.Is(err, ErrInvalid) {
				t.Fatalf("one-nanosecond identity change accepted: %v", err)
			}
			next := createDateReport(t, store, input)
			input.VulnerabilityRevision = ""
			unknown := createDateReport(t, store, input)
			unrelated := createDateReport(t, store, revisionUnrelated(t, canonical))
			for _, want := range []Report{next, unknown, unrelated} {
				got, err := store.GetLatest(ctx, want.ContextKey)
				if err != nil || got.ID != want.ID {
					t.Errorf("revision %q was merged incorrectly: ID=%d want=%d err=%v", want.VulnerabilityRevision, got.ID, want.ID, err)
				}
			}
			options := ListOptions{RepositoryID: input.RepositoryID, RepositoryCommit: input.RepositoryCommit}
			assertDateListIDs(t, store, options, unknown.ID, next.ID)
			options.IncludeUnrelated = true
			assertDateListIDs(t, store, options, unrelated.ID, unknown.ID, next.ID)
			options.IncludeUnrelated, options.BeforeID = false, unrelated.ID
			assertDateListIDs(t, store, options, unknown.ID, next.ID)
			if err := store.Delete(ctx, unrelated.ID); err != nil {
				t.Fatal(err)
			}
			got, err := store.GetLatest(ctx, corrected.ContextKey)
			if err != nil || !reflect.DeepEqual(got, corrected) {
				t.Errorf("deleting latest did not expose retained history: got %#v err=%v", got, err)
			}
		})
	}
}

func TestFeedApplicabilityAcceptsEquivalentRevisionSpellings(t *testing.T) {
	raw, err := os.ReadFile("testdata/feed-item.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, dates := range []struct{ column, applicability, canonical string }{
		{"2026-09-24T12:00:00Z", "2026-09-24T12:00:00.000Z", "2026-09-24T12:00:00Z"},
		{"2026-09-24T12:00:00.1200Z", "2026-09-24T12:00:00.12Z", "2026-09-24T12:00:00.12Z"},
	} {
		t.Run(dates.column, func(t *testing.T) {
			var feed map[string]any
			if err := json.Unmarshal(raw, &feed); err != nil {
				t.Fatal(err)
			}
			feed["vulnerability_revision"], feed["cve_revision"], feed["published_at"] = dates.column, dates.column, dates.column
			app := feed["applicability"].(map[string]any)
			app["vulnerability_revision"] = dates.applicability
			data, err := json.Marshal(feed)
			if err != nil {
				t.Fatal(err)
			}
			input, err := FromFeedJSON(data, nil)
			if err != nil || input.VulnerabilityRevision != dates.canonical || input.CVERevision != dates.canonical || input.PublishedAt != dates.canonical {
				t.Fatalf("equivalent applicability identity: dates=%#v input=%#v err=%v", dates, input, err)
			}
			for _, different := range []any{"2026-09-24T12:00:00.120000001Z", nil} {
				app["vulnerability_revision"] = different
				data, err := json.Marshal(feed)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := FromFeedJSON(data, nil); !errors.Is(err, ErrInvalid) {
					t.Errorf("different applicability revision %v accepted: %v", different, err)
				}
			}
		})
	}
}

func TestMigrateVersion2NormalizesDatesWithoutLosingHistory(t *testing.T) {
	path, originals := revisionVersion2DB(t)
	store := openDateStore(t, path)
	var version int
	if err := store.db.QueryRow("SELECT version FROM reportstore_schema").Scan(&version); err != nil || version != 3 {
		t.Fatalf("migration version=%d err=%v, want 3", version, err)
	}
	wants := append([]Report(nil), originals...)
	wants[1].VulnerabilityRevision = wants[0].VulnerabilityRevision
	wants[2].VulnerabilityRevision = "2026-09-24T12:00:00.12Z"
	wants[2].CVERevision = "2026-09-24T12:00:00.12Z"
	wants[2].PublishedAt = "2026-09-24T12:00:00Z"
	for _, want := range wants {
		got, err := store.Get(context.Background(), want.ID)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("migration changed report beyond source dates: want %#v, got %#v err=%v", want, got, err)
		}
		assertStoredDates(t, store, want.ID, want.Input)
	}
	options := ListOptions{RepositoryID: wants[0].RepositoryID, RepositoryCommit: wants[0].RepositoryCommit}
	assertDateListIDs(t, store, options, wants[3].ID, wants[2].ID)
	options.IncludeUnrelated = true
	assertDateListIDs(t, store, options, wants[3].ID, wants[2].ID, wants[1].ID)
	if err := store.Delete(context.Background(), wants[1].ID); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetLatest(context.Background(), wants[0].ContextKey)
	if err != nil || !reflect.DeepEqual(got, wants[0]) {
		t.Errorf("migration lost earlier same-instant report: got %#v err=%v", got, err)
	}
	if created := createDateReport(t, store, wants[0].Input); created.ID <= 99 {
		t.Errorf("migration reused deleted report ID: %d", created.ID)
	}
}

func TestInvalidVersion2DatesRollBackMigration(t *testing.T) {
	for _, column := range []string{"vulnerability_revision", "cve_revision", "published_at"} {
		t.Run(column, func(t *testing.T) {
			path, _ := revisionVersion2DB(t)
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			// 後続の行が不正なら、それまでの正常な行に対する正規化も取り消されなければならない。
			if _, err := db.Exec("UPDATE reports SET "+column+" = ? WHERE report_id = 41", "2026-02-30T12:00:00Z"); err != nil {
				t.Fatal(err)
			}
			before := revisionDatabaseSnapshot(t, db)
			store, err := Open(context.Background(), path)
			if store != nil {
				_ = store.Close()
				t.Fatal("failed migration returned a Store")
			}
			if err == nil {
				t.Fatal("invalid source timestamp did not fail migration")
			}
			after := revisionDatabaseSnapshot(t, db)
			if !reflect.DeepEqual(after, before) {
				t.Errorf("failed migration changed schema, version, sequence or rows:\nbefore=%#v\n after=%#v", before, after)
			}
		})
	}
}

func TestConcurrentUpdatesAcrossStoreInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports.db")
	stores := []*Store{openDateStore(t, path), openDateStore(t, path)}
	input := dateFixture(t)
	originals := []Report{createDateReport(t, stores[0], input)}
	input.VulnerabilityID = "GHSA-another-report"
	originals = append(originals, createDateReport(t, stores[0], input))
	const perStore = 100
	start := make(chan struct{})
	errs := make(chan error, len(stores)*perStore)
	var wg sync.WaitGroup
	for writer, store := range stores {
		for i := 0; i < perStore; i++ {
			original := originals[i%len(originals)]
			correction := original.Input
			correction.Severity = fmt.Sprintf("correction-%d-%d", writer, i)
			wg.Add(1)
			go func(store *Store, original Report, correction Input) {
				defer wg.Done()
				<-start
				updated, err := store.Update(context.Background(), original.ID, correction)
				if err != nil {
					errs <- fmt.Errorf("%s: %w", correction.Severity, err)
					return
				}
				if updated.ID != original.ID || updated.ContextKey != original.ContextKey || updated.StoredAt != original.StoredAt || !reflect.DeepEqual(updated.Input, correction) {
					errs <- fmt.Errorf("%s changed identity or returned another writer's result: %#v", correction.Severity, updated)
				}
			}(store, original, correction)
		}
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for _, original := range originals {
		got, err := stores[1].Get(context.Background(), original.ID)
		if err != nil {
			t.Fatal(err)
		}
		// この処理で変更するのは severity だけであり、ほかのフィールドはすべて維持されなければならない。
		got.Severity = original.Severity
		if !reflect.DeepEqual(got, original) {
			t.Errorf("concurrent updates changed immutable data or body: want %#v, got %#v", original, got)
		}
	}
	var count int
	if err := stores[0].db.QueryRow("SELECT count(*) FROM reports").Scan(&count); err != nil || count != len(originals) {
		t.Errorf("corrections changed history size: count=%d err=%v", count, err)
	}
}

func revisionUnrelated(t *testing.T, input Input) Input {
	t.Helper()
	input.Status, input.Relevance = Screened, Unrelated
	var body map[string]json.RawMessage
	if err := json.Unmarshal(input.Body, &body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"summary", "repository_impact", "applicability", "missing_information", "recommended_actions"} {
		delete(body, key)
	}
	body["screening_evidence_ids"] = json.RawMessage(`["EVD-REPO-DEP-001"]`)
	var err error
	input.Body, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func revisionVersion2DB(t *testing.T) (string, []Report) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reports-v2.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// バージョン 2 と 3 のテーブル構造は同じ。Create による正規化で移行テスト用データが
	// 変わらないよう、旧バージョンの保存形式に従って直接データを投入する。
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE reportstore_schema (version INTEGER PRIMARY KEY) STRICT; INSERT INTO reportstore_schema VALUES (2)"); err != nil {
		t.Fatal(err)
	}
	input := dateFixture(t)
	originals := []Report{{ID: 11, Input: input, StoredAt: "2026-09-25T01:02:03.1200Z"}}
	input = revisionUnrelated(t, input)
	input.VulnerabilityRevision = "2026-09-24T12:00:00.000Z"
	originals = append(originals, Report{ID: 21, Input: input, StoredAt: "2026-09-25T02:03:04.000Z"})
	input = dateFixture(t)
	input.VulnerabilityRevision, input.CVERevision, input.PublishedAt = "2026-09-24T12:00:00.1200Z", "2026-09-24T12:00:00.1200Z", "2026-09-24T12:00:00.000Z"
	originals = append(originals, Report{ID: 31, Input: input, StoredAt: "2026-09-25T03:04:05Z"})
	input.VulnerabilityRevision, input.CVERevision, input.PublishedAt = "", "", ""
	originals = append(originals, Report{ID: 41, Input: input, StoredAt: "2026-09-25T04:05:06Z"})
	for _, report := range originals {
		_, err := db.Exec(`INSERT INTO reports (`+reportColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			report.ID, report.RepositoryID, report.RepositoryCommit, report.VulnerabilityID, nullText(report.VulnerabilityRevision),
			nullText(report.CVEID), nullText(report.CVERevision), nullText(report.PublishedAt), nullText(report.Severity), report.CVSS,
			report.Status, report.Relevance, string(report.Body), report.StoredAt)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("UPDATE sqlite_sequence SET seq = 99 WHERE name = 'reports'"); err != nil {
		t.Fatal(err)
	}
	return path, originals
}

func revisionDatabaseSnapshot(t *testing.T, db *sql.DB) [][]any {
	t.Helper()
	var snapshot [][]any
	for _, query := range []string{
		"SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name",
		"SELECT version FROM reportstore_schema",
		"SELECT name, seq FROM sqlite_sequence ORDER BY name",
		"SELECT " + reportColumns + " FROM reports ORDER BY report_id",
	} {
		rows, err := db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(columns))
			targets := make([]any, len(columns))
			for i := range values {
				targets[i] = &values[i]
			}
			if err := rows.Scan(targets...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			snapshot = append(snapshot, values)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return snapshot
}
