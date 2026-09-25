package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMockAPIFlow(t *testing.T) {
	router := newRouterWithRepository(NewMockRepository("mockdata"))
	all := requestJSON[FeedResult](t, router, "GET", "/api/cves?limit=200", "", http.StatusOK)
	if len(all.Items) != 12 || all.Total != 12 || all.MatchedTotal != 12 {
		t.Fatalf("全体の一覧件数が不正です: %+v", all)
	}
	// 詳細サンプル以外の記事も URL の ID で選べることを確認する。
	item := all.Items[len(all.Items)-1]
	detail := requestJSON[FeedItem](t, router, "GET", "/api/cves/"+item.ID, "", http.StatusOK)
	if !reflect.DeepEqual(detail, item) {
		t.Fatal("CVE 詳細が一覧と一致しません")
	}

	registration := requestJSON[CreateRepositoryResponse](t, router, "POST", "/api/repositories",
		`{"url":"https://github.com/example/mock-service"}`, http.StatusAccepted)
	if registration.RepositoryID != "repo-001" || registration.JobID != "job-001" {
		t.Fatalf("登録結果が不正です: %+v", registration)
	}
	job := requestJSON[JobResponse](t, router, "GET", "/api/jobs/"+registration.JobID, "", http.StatusOK)
	if job.RepositoryID != registration.RepositoryID || job.Stage != "completed" ||
		job.HasAvailableResults == nil || !*job.HasAvailableResults {
		t.Fatalf("ジョブの応答が不正です: %+v", job)
	}
	feedURL := "/api/repositories/" + registration.RepositoryID + "/feed"
	related := requestJSON[FeedResult](t, router, "GET", feedURL, "", http.StatusOK)
	if len(related.Items) != 6 || related.Total != 6 || related.MatchedTotal != 6 {
		t.Fatalf("リポジトリ別の一覧件数が不正です: %+v", related)
	}
	relatedDetail := requestJSON[FeedItem](t, router, "GET", feedURL+"/"+related.Items[0].ID, "", http.StatusOK)
	if !reflect.DeepEqual(relatedDetail, related.Items[0]) {
		t.Fatal("リポジトリ別の詳細が一覧と一致しません")
	}
}

func TestMockAPIListLimits(t *testing.T) {
	router := newRouterWithRepository(NewMockRepository("mockdata"))
	for _, tc := range []struct {
		query string
		count int
	}{
		{"", 10},
		{"?limit=", 10},
		{"?limit=1", 1},
		{"?limit=5", 5},
		{"?limit=200", 12},
	} {
		t.Run(tc.query, func(t *testing.T) {
			feed := requestJSON[FeedResult](t, router, "GET", "/api/cves"+tc.query, "", http.StatusOK)
			if len(feed.Items) != tc.count || feed.MatchedTotal != tc.count || feed.Total != 12 {
				t.Fatalf("件数が不正です: items=%d matchedTotal=%d total=%d", len(feed.Items), feed.MatchedTotal, feed.Total)
			}
		})
	}
	for _, value := range []string{"0", "-1", "201", "abc", "1.5"} {
		t.Run(value, func(t *testing.T) {
			response := request(t, router, "GET", "/api/cves?limit="+value, "", http.StatusBadRequest)
			if !strings.Contains(response.Body.String(), "1以上200以下") {
				t.Fatalf("limit の範囲が応答に含まれません: %s", response.Body.String())
			}
		})
	}
}

func TestMockAPIErrorStatuses(t *testing.T) {
	router := newRouterWithRepository(NewMockRepository("mockdata"))
	for _, path := range []string{
		"/api/cves/missing",
		"/api/jobs/missing",
		"/api/repositories/missing/feed",
		"/api/repositories/missing/feed/demo-001",
		"/api/repositories/repo-001/feed/demo-012",
	} {
		t.Run(path, func(t *testing.T) {
			request(t, router, "GET", path, "", http.StatusNotFound)
		})
	}
	request(t, router, "GET", "/api/repositories", "", http.StatusMethodNotAllowed)
	request(t, router, "POST", "/api/jobs/job-001", "", http.StatusMethodNotAllowed)

	directory := t.TempDir()
	brokenRouter := newRouterWithRepository(NewMockRepository(directory))
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/cves"},
		{"GET", "/api/cves/demo-001"},
		{"POST", "/api/repositories"},
		{"GET", "/api/jobs/job-001"},
		{"GET", "/api/repositories/repo-001/feed"},
		{"GET", "/api/repositories/repo-001/feed/demo-001"},
	} {
		t.Run("missing file "+tc.method+" "+tc.path, func(t *testing.T) {
			response := request(t, brokenRouter, tc.method, tc.path, "", http.StatusInternalServerError)
			if strings.TrimSpace(response.Body.String()) != "データの取得に失敗しました" {
				t.Fatalf("内部のエラー詳細がレスポンスに含まれています: %s", response.Body.String())
			}
		})
	}
	if err := os.WriteFile(filepath.Join(directory, "cves.json"), []byte(`{"items":`), 0600); err != nil {
		t.Fatal(err)
	}
	request(t, brokenRouter, "GET", "/api/cves", "", http.StatusInternalServerError)
}

func TestMockAPIDefaultDataDirectory(t *testing.T) {
	serverDirectory, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MOCK_DATA_DIR", "")
	for _, directory := range []string{serverDirectory, filepath.Dir(serverDirectory)} {
		t.Run(directory, func(t *testing.T) {
			t.Chdir(directory)
			feed := requestJSON[FeedResult](t, newRouter(), "GET", "/api/cves?limit=1", "", http.StatusOK)
			if len(feed.Items) != 1 {
				t.Fatal("起動ディレクトリに対応するモックを読み込めません")
			}
		})
	}
}

func TestMockAPIConfiguredDataDirectory(t *testing.T) {
	directory, err := filepath.Abs("mockdata")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MOCK_DATA_DIR", directory)
	t.Chdir(t.TempDir())
	requestJSON[FeedResult](t, newRouter(), "GET", "/api/cves", "", http.StatusOK)
}

func request(t *testing.T, handler http.Handler, method, path, body string, status int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != status {
		t.Fatalf("%s %s: status=%d, want %d; body=%s", method, path, response.Code, status, response.Body.String())
	}
	return response
}

func requestJSON[T any](t *testing.T, handler http.Handler, method, path, body string, status int) T {
	t.Helper()
	response := request(t, handler, method, path, body, status)
	if contentType := response.Header().Get("Content-Type"); contentType != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", contentType)
	}
	var result T
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
