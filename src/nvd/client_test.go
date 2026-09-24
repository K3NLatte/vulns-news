package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
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
			fmt.Fprint(w, `{"totalResults":5,"vulnerabilities":[{"cve":{"id":"CVE-1"}}]}`)
			return
		}
		fmt.Fprint(w, `{"totalResults":5,"vulnerabilities":[{"cve":{"id":"CVE-3","descriptions":[{"lang":"ja","value":"三"}]}},{"cve":{"id":"CVE-4","descriptions":[]}},{"cve":{"id":"CVE-5","descriptions":[{"lang":"ja","value":"五"},{"lang":"en","value":"Five"}]}}]}`)
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
	want := []CVE{{"CVE-5", "Five"}, {"CVE-4", ""}, {"CVE-3", "三"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("取得結果 = %+v, want %+v", got, want)
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
			items[i] = map[string]any{"cve": map[string]any{"id": fmt.Sprintf("CVE-%d", start+i)}}
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
