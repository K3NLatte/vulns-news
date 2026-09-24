package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func noLatestWait(context.Context, time.Duration) error { return nil }

func latestTestClient(t *testing.T, records []Vulnerability, queries *[]Query) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()
		start, err := time.Parse(time.RFC3339Nano, values.Get("pubStartDate"))
		if err != nil {
			t.Error(err)
		}
		end, err := time.Parse(time.RFC3339Nano, values.Get("pubEndDate"))
		if err != nil {
			t.Error(err)
		}
		index, _ := strconv.Atoi(values.Get("startIndex"))
		size, _ := strconv.Atoi(values.Get("resultsPerPage"))
		if end.Sub(start) > maxPublicationWindow || size > 200 {
			t.Errorf("invalid NVD query: %v", values)
		}
		*queries = append(*queries, Query{PublishedStart: start, PublishedEnd: end, StartIndex: index, ResultsPerPage: size})
		var matches []Vulnerability
		for _, item := range records {
			published, _ := latestPublicationTime(item.CVE.Published)
			if !published.Before(start) && !published.After(end) {
				matches = append(matches, item)
			}
		}
		page := Page{StartIndex: index, TotalResults: len(matches)}
		if index < len(matches) {
			page.Vulnerabilities = matches[index:min(index+size, len(matches))]
		}
		page.ResultsPerPage = len(page.Vulnerabilities)
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func latestItem(id int, published time.Time) Vulnerability {
	return Vulnerability{CVE: CVE{ID: fmt.Sprintf("CVE-2026-%04d", id), Published: published.Format("2006-01-02T15:04:05.000")}}
}

func TestFetchLatestSeeksAscendingTail(t *testing.T) {
	asOf := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	var records []Vulnerability
	for i := 0; i < 550; i++ {
		records = append(records, latestItem(i, asOf.Add(time.Duration(i-549)*time.Minute)))
	}
	records = append(records, latestItem(9999, asOf.Add(time.Minute)))
	var queries []Query
	client := latestTestClient(t, records, &queries)
	page, err := client.fetchLatest(context.Background(), LatestOptions{AsOf: asOf}, noLatestWait)
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || queries[0].ResultsPerPage != 1 || queries[1].StartIndex != 350 || queries[1].ResultsPerPage != 200 {
		t.Fatalf("queries = %#v", queries)
	}
	if len(page.Vulnerabilities) != 200 || page.Vulnerabilities[0].CVE.ID != "CVE-2026-0549" || page.Vulnerabilities[199].CVE.ID != "CVE-2026-0350" {
		t.Fatalf("wrong latest selection: %#v", page)
	}
	for _, q := range queries {
		if q.PublishedEnd.After(asOf) {
			t.Fatal("cutoff moved")
		}
	}
}

func TestFetchLatestWalksOlderWindowsAndDeduplicatesBoundary(t *testing.T) {
	asOf := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	records := []Vulnerability{latestItem(1, asOf.Add(-49*time.Hour)), latestItem(2, asOf.Add(-24*time.Hour)), latestItem(3, asOf.Add(-time.Hour))}
	var queries []Query
	client := latestTestClient(t, records, &queries)
	page, err := client.fetchLatest(context.Background(), LatestOptions{AsOf: asOf, Limit: 3, Window: 24 * time.Hour}, noLatestWait)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Vulnerabilities) != 3 || page.Vulnerabilities[0].CVE.ID != records[2].CVE.ID || page.Vulnerabilities[2].CVE.ID != records[0].CVE.ID {
		t.Fatalf("page = %#v", page)
	}
	if !queries[len(queries)-1].PublishedEnd.Equal(asOf.Add(-48 * time.Hour)) {
		t.Fatalf("queries = %#v", queries)
	}
}

func TestFetchLatestSkipsEmptyRecentWindows(t *testing.T) {
	asOf := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	var queries []Query
	client := latestTestClient(t, []Vulnerability{latestItem(1, asOf.Add(-50*time.Hour))}, &queries)
	page, err := client.fetchLatest(context.Background(), LatestOptions{AsOf: asOf, Limit: 1, Window: 24 * time.Hour}, noLatestWait)
	if err != nil || len(page.Vulnerabilities) != 1 || len(queries) != 3 {
		t.Fatalf("page=%#v queries=%#v err=%v", page, queries, err)
	}
	page, err = client.FetchLatest(context.Background(), LatestOptions{AsOf: asOf, PublishedStart: asOf.Add(-time.Hour), PublishedEnd: asOf})
	if err != nil || len(page.Vulnerabilities) != 0 {
		t.Fatalf("empty explicit range: page=%#v err=%v", page, err)
	}
}

func TestFetchLatestReadsEarlierTailForDuplicates(t *testing.T) {
	asOf := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	var records []Vulnerability
	for i := 0; i < 210; i++ {
		records = append(records, latestItem(i, asOf.Add(-time.Hour)))
	}
	for i := 0; i < 10; i++ {
		records = append(records, records[209])
	}
	var queries []Query
	client := latestTestClient(t, records, &queries)
	page, err := client.fetchLatest(context.Background(), LatestOptions{AsOf: asOf}, noLatestWait)
	if err != nil || len(page.Vulnerabilities) != 200 || len(queries) != 3 || queries[2].StartIndex != 0 {
		t.Fatalf("count=%d queries=%#v err=%v", len(page.Vulnerabilities), queries, err)
	}
	seen := map[string]bool{}
	for _, item := range page.Vulnerabilities {
		if seen[item.CVE.ID] {
			t.Fatal("duplicate returned")
		}
		seen[item.CVE.ID] = true
	}
}

func TestFetchLatestExplicitWindowSplitsAndExhausts(t *testing.T) {
	asOf := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	start := asOf.Add(-250 * 24 * time.Hour)
	var queries []Query
	client := latestTestClient(t, []Vulnerability{latestItem(1, start.Add(-time.Second)), latestItem(2, start)}, &queries)
	page, err := client.fetchLatest(context.Background(), LatestOptions{AsOf: asOf, PublishedStart: start, PublishedEnd: asOf.Add(time.Hour), Window: maxPublicationWindow}, noLatestWait)
	if err != nil || len(page.Vulnerabilities) != 1 || len(queries) != 3 {
		t.Fatalf("page=%#v queries=%#v err=%v", page, queries, err)
	}
	if !queries[0].PublishedEnd.Equal(asOf) || !queries[2].PublishedStart.Equal(start) {
		t.Fatalf("queries=%#v", queries)
	}
}

func TestFetchLatestBudgetAndCancellation(t *testing.T) {
	asOf := time.Now().UTC().Truncate(time.Second)
	var queries []Query
	client := latestTestClient(t, []Vulnerability{latestItem(1, asOf)}, &queries)
	page, err := client.fetchLatest(context.Background(), LatestOptions{AsOf: asOf, MaxRequests: 2}, noLatestWait)
	var incomplete *IncompleteError
	if !errors.As(err, &incomplete) || incomplete.Requests != 2 || len(page.Vulnerabilities) != 1 || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = client.fetchLatest(ctx, LatestOptions{AsOf: asOf}, func(ctx context.Context, delay time.Duration) error {
		if delay != 6*time.Second {
			t.Errorf("delay = %v", delay)
		}
		cancel()
		return waitLatest(ctx, time.Hour)
	})
	if !errors.Is(err, context.Canceled) || !errors.As(err, &incomplete) {
		t.Fatalf("err=%v", err)
	}
	client.apiKey = "test"
	_, err = client.fetchLatest(context.Background(), LatestOptions{AsOf: asOf}, func(_ context.Context, delay time.Duration) error {
		if delay != 650*time.Millisecond {
			t.Errorf("keyed delay = %v", delay)
		}
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestFetchLatestRejectsUnreliablePages(t *testing.T) {
	asOf := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	for _, mode := range []string{"changed count", "short page", "wrong index", "bad timestamp", "wrong order", "outside window", "HTTP 429"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if mode == "HTTP 429" {
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				page := Page{TotalResults: 3, ResultsPerPage: 1, Vulnerabilities: []Vulnerability{latestItem(1, asOf.Add(-time.Hour))}}
				if calls > 1 {
					page.ResultsPerPage = 3
					page.Vulnerabilities = []Vulnerability{latestItem(1, asOf.Add(-time.Hour)), latestItem(2, asOf), latestItem(3, asOf)}
					switch mode {
					case "changed count":
						page.TotalResults = 4
					case "short page":
						page.Vulnerabilities = page.Vulnerabilities[:1]
					case "wrong index":
						page.StartIndex = 1
					case "bad timestamp":
						page.Vulnerabilities[0].CVE.Published = "bad"
					case "wrong order":
						page.Vulnerabilities[2] = latestItem(3, asOf.Add(-2*time.Hour))
					case "outside window":
						page.Vulnerabilities[2] = latestItem(3, asOf.Add(time.Hour))
					}
				}
				_ = json.NewEncoder(w).Encode(page)
			}))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL, HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.fetchLatest(context.Background(), LatestOptions{AsOf: asOf}, noLatestWait)
			var incomplete *IncompleteError
			if !errors.As(err, &incomplete) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestFetchLatestValidatesOptionsBeforeHTTP(t *testing.T) {
	asOf := time.Now()
	for _, options := range []LatestOptions{
		{}, {AsOf: asOf, Limit: 201}, {AsOf: asOf, Limit: -1},
		{AsOf: asOf, MaxRequests: -1}, {AsOf: asOf, Window: maxPublicationWindow + time.Second},
		{AsOf: asOf, PublishedStart: asOf},
		{AsOf: asOf, PublishedStart: asOf.Add(time.Hour), PublishedEnd: asOf.Add(2 * time.Hour)},
	} {
		client := &Client{}
		if _, err := client.FetchLatest(context.Background(), options); err == nil {
			t.Fatalf("accepted %#v", options)
		}
	}
}
