package reportstore_test

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vulns-news/server/repository/reportstore"
)

// TestAnalysisArchiveCRUD は、元の分析アーカイブをリポジトリ内のテストデータではなく
// ローカルの入力として使うため、明示的に有効にした場合だけ実行する。
// API や LLM へのリクエストは行わず、新規のテスト用データベースにだけ書き込む。
// 除外された 9 件にはフィードも正規化済みの入力・証拠もなく、この ZIP からは復元できない。
func TestAnalysisArchiveCRUD(t *testing.T) {
	path := os.Getenv("VULNS_ANALYSIS_ARCHIVE")
	if path == "" {
		t.Skip("set VULNS_ANALYSIS_ARCHIVE to the original analysis-results.zip to verify 582 feeds")
	}
	archive, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	var feeds []json.RawMessage
	readArchiveJSON(t, archive, "feeds.json", &feeds)
	var analysis struct {
		Excluded int `json:"excluded"`
		Entries  []struct {
			Feed      json.RawMessage `json:"feed"`
			Screening struct {
				Result reportstore.Screening `json:"result"`
			} `json:"screening"`
		} `json:"entries"`
	}
	readArchiveJSON(t, archive, "analysis-results.json", &analysis)
	if len(feeds) != 582 || len(analysis.Entries) != 591 || analysis.Excluded != 9 {
		t.Fatalf("unexpected archive shape: feeds=%d entries=%d excluded=%d", len(feeds), len(analysis.Entries), analysis.Excluded)
	}

	// 2 つのアーカイブファイルの並び順に依存せず、JSON 値全体の一致によって
	// エクスポートされたフィードとスクリーニング結果を対応付ける。
	decisions := make(map[string][]reportstore.Screening)
	excluded := 0
	for _, entry := range analysis.Entries {
		if len(entry.Feed) == 0 || string(entry.Feed) == "null" {
			excluded++
			continue
		}
		key := canonicalArchiveJSON(t, entry.Feed)
		decisions[key] = append(decisions[key], entry.Screening.Result)
	}
	if excluded != 9 {
		t.Fatalf("expected nine excluded entries without feeds, got %d", excluded)
	}

	ctx := context.Background()
	store := openStore(t, filepath.Join(t.TempDir(), "archive-reports.db"))
	for i, feed := range feeds {
		key := canonicalArchiveJSON(t, feed)
		matches := decisions[key]
		if len(matches) == 0 {
			t.Fatalf("feed %d has no identical analysis entry", i)
		}
		decision := matches[0]
		decisions[key] = matches[1:]
		input, err := reportstore.FromFeedJSON(feed, &decision)
		if err != nil {
			t.Fatalf("feed %d conversion: %v", i, err)
		}
		created, err := store.Create(ctx, input)
		if err != nil {
			t.Fatalf("feed %d create: %v", i, err)
		}
		got, err := store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("feed %d read: %v", i, err)
		}
		assertReportEqual(t, created, got)
		restored, err := reportstore.ToFeedJSON(got)
		if err != nil {
			t.Fatalf("feed %d restore: %v", i, err)
		}
		want := normalizedArchiveFeed(t, feed)
		want["screening_evidence_ids"] = decision.EvidenceIDs
		assertArchiveFeed(t, i, want, restored)

		var reason string
		if err := json.Unmarshal(want["screening_reason"].(json.RawMessage), &reason); err != nil {
			t.Fatalf("feed %d screening reason: %v", i, err)
		}
		changedReason, err := json.Marshal(reason + " [保存検証の訂正]")
		if err != nil {
			t.Fatal(err)
		}
		input = mutateBody(t, input, func(body map[string]json.RawMessage) {
			body["screening_reason"] = changedReason
		})
		updated, err := store.Update(ctx, created.ID, input)
		if err != nil {
			t.Fatalf("feed %d update: %v", i, err)
		}
		if updated.ID != created.ID || updated.StoredAt != created.StoredAt || updated.ContextKey != created.ContextKey {
			t.Fatalf("feed %d update changed immutable metadata", i)
		}
		updated, err = store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("feed %d read update: %v", i, err)
		}
		restored, err = reportstore.ToFeedJSON(updated)
		if err != nil {
			t.Fatalf("feed %d restore update: %v", i, err)
		}
		want["screening_reason"] = json.RawMessage(changedReason)
		assertArchiveFeed(t, i, want, restored)
		if err := store.Delete(ctx, created.ID); err != nil {
			t.Fatalf("feed %d delete: %v", i, err)
		}
		if _, err := store.Get(ctx, created.ID); !errors.Is(err, reportstore.ErrNotFound) {
			t.Fatalf("feed %d after delete: got %v, want ErrNotFound", i, err)
		}
	}
	for _, unmatched := range decisions {
		if len(unmatched) != 0 {
			t.Fatal("analysis entries remain unmatched after all feed roundtrips")
		}
	}
	t.Logf("verified create/read/update/delete and selected-field restoration for %d feeds; %d excluded entries lack normalized input and evidence", len(feeds), excluded)
}

func readArchiveJSON(t testing.TB, archive *zip.ReadCloser, name string, into any) {
	t.Helper()
	for _, file := range archive.File {
		if file.Name != name {
			continue
		}
		const maxBytes = 64 << 20
		if file.UncompressedSize64 > maxBytes {
			t.Fatalf("%s exceeds the archive test's 64 MiB per-file limit", name)
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
		closeErr := reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		if len(raw) > maxBytes {
			t.Fatalf("%s exceeds the archive test's 64 MiB per-file limit", name)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return
	}
	t.Fatalf("archive does not contain %s", name)
}

func canonicalArchiveJSON(t testing.TB, raw []byte) string {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(canonical)
}

func normalizedArchiveFeed(t testing.TB, raw []byte) map[string]any {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "generation")
	if len(fields["cve_id"]) == 0 || string(fields["cve_id"]) == "null" || string(fields["cve_id"]) == `""` {
		if string(fields["cve_revision"]) == `"0001-01-01T00:00:00Z"` {
			delete(fields, "cve_revision")
		}
	}
	for _, key := range []string{"cve_id", "cve_revision", "severity", "cvss"} {
		if string(fields[key]) == "null" || string(fields[key]) == `""` {
			delete(fields, key)
		}
	}
	result := make(map[string]any, len(fields))
	for key, value := range fields {
		result[key] = value
	}
	return result
}

func assertArchiveFeed(t testing.TB, index int, want map[string]any, restored []byte) {
	t.Helper()
	wantRaw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var expected, got any
	if err := json.Unmarshal(wantRaw, &expected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(restored, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("feed %d selected facts, report fields, null/array states, or evidence references changed during roundtrip", index)
	}
}
