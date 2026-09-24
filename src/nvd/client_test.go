package nvd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchPageSendsWindowPaginationAndAPIKey(t *testing.T) {
	publishedStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	publishedEnd := publishedStart.Add(24 * time.Hour)
	modifiedStart := publishedEnd
	modifiedEnd := modifiedStart.Add(2 * time.Hour)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Errorf("method = %s", request.Method)
		}
		if got := request.Header.Get("apiKey"); got != "secret" {
			t.Errorf("apiKey = %q", got)
		}
		query := request.URL.Query()
		checks := map[string]string{
			"pubStartDate":     publishedStart.Format(time.RFC3339Nano),
			"pubEndDate":       publishedEnd.Format(time.RFC3339Nano),
			"lastModStartDate": modifiedStart.Format(time.RFC3339Nano),
			"lastModEndDate":   modifiedEnd.Format(time.RFC3339Nano),
			"startIndex":       "200",
			"resultsPerPage":   "100",
		}
		for key, want := range checks {
			if got := query.Get(key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"resultsPerPage":100,"startIndex":200,"totalResults":301,"vulnerabilities":[{"cve":{"id":"CVE-2026-0001"}}]}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{BaseURL: server.URL, APIKey: " secret ", HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	page, err := client.FetchPage(context.Background(), Query{
		PublishedStart: publishedStart,
		PublishedEnd:   publishedEnd,
		ModifiedStart:  modifiedStart,
		ModifiedEnd:    modifiedEnd,
		StartIndex:     200,
		ResultsPerPage: 100,
	})
	if err != nil {
		t.Fatalf("FetchPage: %v", err)
	}
	if page.TotalResults != 301 || len(page.Vulnerabilities) != 1 || page.Vulnerabilities[0].CVE.ID != "CVE-2026-0001" {
		t.Fatalf("unexpected page: %#v", page)
	}
}

func TestFetchPageDefaultsAndCapsPageSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.URL.Query().Get("resultsPerPage"); got != "200" {
			t.Errorf("resultsPerPage = %q", got)
		}
		_, _ = response.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := client.FetchPage(context.Background(), Query{PublishedStart: start, PublishedEnd: start.Add(time.Hour)}); err != nil {
		t.Fatalf("FetchPage default size: %v", err)
	}
	if _, err := client.FetchPage(context.Background(), Query{PublishedStart: start, PublishedEnd: start.Add(time.Hour), ResultsPerPage: 201}); err == nil {
		t.Fatal("FetchPage accepted more than 200 results")
	}
}

func TestFetchPageReportsStatusAndLimitsBody(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("message", "rate limit exceeded")
			response.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()
		client, err := NewClient(Config{BaseURL: server.URL, HTTPClient: server.Client()})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		start := time.Now()
		_, err = client.FetchPage(context.Background(), Query{ModifiedStart: start, ModifiedEnd: start.Add(time.Hour)})
		var httpError *HTTPError
		if !errors.As(err, &httpError) || httpError.StatusCode != http.StatusTooManyRequests || httpError.Message != "rate limit exceeded" {
			t.Fatalf("error = %#v", err)
		}
	})

	t.Run("body limit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = response.Write([]byte(strings.Repeat("x", 33)))
		}))
		defer server.Close()
		client, err := NewClient(Config{BaseURL: server.URL, HTTPClient: server.Client(), MaxResponseBytes: 32})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		start := time.Now()
		_, err = client.FetchPage(context.Background(), Query{ModifiedStart: start, ModifiedEnd: start.Add(time.Hour)})
		if err == nil || !strings.Contains(err.Error(), "exceeds 32 bytes") {
			t.Fatalf("error = %v", err)
		}
	})
}
