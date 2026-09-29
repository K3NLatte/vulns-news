package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestFetchNewestFirst(t *testing.T) {
	requests := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := r.URL.Query().Get("startIndex")
		size := r.URL.Query().Get("resultsPerPage")
		requests <- start + ":" + size
		if r.Header.Get("apiKey") != "" {
			t.Error("APIキーが送信されました")
		}
		if start == "0" {
			fmt.Fprint(w, `{"totalResults":5,"vulnerabilities":[{"cve":{"id":"CVE-1","published":"2026-09-20T01:00:00.000","lastModified":"2026-09-20T02:00:00.000"}}]}`)
			return
		}
		fmt.Fprint(w, `{"totalResults":5,"vulnerabilities":[{"cve":{"id":"CVE-3","published":"2026-09-22T01:00:00.000","lastModified":"2026-09-22T02:00:00.000","descriptions":[{"lang":"ja","value":"三"}]}},{"cve":{"id":"CVE-4","published":"2026-09-23T01:00:00.000","lastModified":"2026-09-23T02:00:00.000","descriptions":[]}},{"cve":{"id":"CVE-5","published":"2026-09-24T01:00:00.000","lastModified":"2026-09-24T02:00:00.000","descriptions":[{"lang":"ja","value":"五"},{"lang":"en","value":"Five"}]}}]}`)
	}))
	defer server.Close()

	client := NewClient()
	client.httpClient = server.Client()
	client.endpoint = server.URL
	client.interval = 0
	got, err := client.Fetch(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].ID != "CVE-5" || got[0].Description != "Five" || got[1].ID != "CVE-4" || got[2].ID != "CVE-3" || got[2].Description != "三" {
		t.Fatalf("取得結果 = %+v", got)
	}
	if first, second := <-requests, <-requests; first != "0:1" || second != "2:3" {
		t.Fatalf("リクエスト = %s, %s", first, second)
	}
}

func TestFetchAcrossPageBoundary(t *testing.T) {
	requests := make(chan string, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		size, _ := strconv.Atoi(r.URL.Query().Get("resultsPerPage"))
		requests <- fmt.Sprintf("%d:%d", start, size)
		items := make([]map[string]any, size)
		for i := range items {
			items[i] = map[string]any{"cve": map[string]any{"id": fmt.Sprintf("CVE-%d", start+i), "published": "2026-09-24T01:00:00.000", "lastModified": "2026-09-24T02:00:00.000"}}
		}
		json.NewEncoder(w).Encode(map[string]any{"totalResults": 2001, "vulnerabilities": items})
	}))
	defer server.Close()

	client := NewClient()
	client.httpClient = server.Client()
	client.endpoint = server.URL
	client.interval = 0
	got, err := client.Fetch(context.Background(), 2001)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2001 || got[0].ID != "CVE-2000" || got[2000].ID != "CVE-0" {
		t.Fatalf("件数・順序が不正です: %d 件", len(got))
	}
	want := []string{"0:1", "1:2000", "0:1"}
	for _, expected := range want {
		if actual := <-requests; actual != expected {
			t.Fatalf("リクエスト = %s, want %s", actual, expected)
		}
	}
}
