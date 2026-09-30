package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func globalTestPage(start, total int, sizes ...int) Page {
	size := 200
	if len(sizes) > 0 {
		size = sizes[0]
	}
	page := Page{StartIndex: start, TotalResults: total}
	for i := start; i < total && i < start+size; i++ {
		stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		page.Vulnerabilities = append(page.Vulnerabilities, Vulnerability{CVE: CVERecord{
			ID: fmt.Sprintf("CVE-2026-%04d", i), Published: stamp, LastModified: stamp,
		}})
	}
	page.ResultsPerPage = len(page.Vulnerabilities)
	return page
}

func globalTestClient(t *testing.T, key string, handler http.HandlerFunc) *AnalysisClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewAnalysisClient(Config{BaseURL: server.URL, HTTPClient: server.Client(), APIKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func globalNoWait(ctx context.Context, _ time.Duration) error { return ctx.Err() }

func TestFetchGlobalExactTailLatest(t *testing.T) {
	for _, key := range []string{"", "configured-key"} {
		t.Run("key="+key, func(t *testing.T) {
			var queries []string
			client := globalTestClient(t, key, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("apiKey") != key || (key == "" && len(r.Header.Values("apiKey")) != 0) {
					t.Error("unexpected API key header")
				}
				q := r.URL.Query()
				if len(q) != 2 {
					t.Errorf("unexpected query (must not include dates): %v", q)
				}
				start, _ := strconv.Atoi(q.Get("startIndex"))
				size, _ := strconv.Atoi(q.Get("resultsPerPage"))
				queries = append(queries, fmt.Sprintf("%d:%d", start, size))
				_ = json.NewEncoder(w).Encode(globalTestPage(start, 2480, size))
			})
			var delays []time.Duration
			got, err := client.fetch(context.Background(), 200, func(_ context.Context, d time.Duration) error {
				delays = append(delays, d)
				return nil
			})
			if err != nil || len(got) != 200 {
				t.Fatalf("count=%d error=%v", len(got), err)
			}
			for i, item := range got {
				if want := fmt.Sprintf("CVE-2026-%04d", 2479-i); item.ID != want {
					t.Fatalf("item %d = %s, want %s", i, item.ID, want)
				}
			}
			if !reflect.DeepEqual(queries, []string{"0:1", "2280:200"}) {
				t.Fatalf("queries=%v", queries)
			}
			delay := 6 * time.Second
			if key != "" {
				delay = 650 * time.Millisecond
			}
			if !reflect.DeepEqual(delays, []time.Duration{delay}) {
				t.Fatalf("delays=%v", delays)
			}
		})
	}
}

func TestFetchGlobalFailsClosed(t *testing.T) {
	for _, scenario := range []string{"short page", "changed total", "bad metadata", "publication", "normalization", "descending", "cross page", "duplicates", "empty", "too few", "HTTP"} {
		t.Run(scenario, func(t *testing.T) {
			client := globalTestClient(t, "", func(w http.ResponseWriter, r *http.Request) {
				start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
				size, _ := strconv.Atoi(r.URL.Query().Get("resultsPerPage"))
				page := globalTestPage(start, 480, size)
				if scenario == "empty" {
					page = globalTestPage(0, 0)
				}
				if scenario == "too few" {
					page = globalTestPage(0, 1)
				}

				if scenario == "duplicates" {
					for i := range page.Vulnerabilities {
						page.Vulnerabilities[i].CVE.ID = "CVE-2026-0001"
					}
				}
				if start == 280 {
					if scenario == "cross page" {
						for i := range page.Vulnerabilities {
							page.Vulnerabilities[i].CVE.ID = "CVE-2026-duplicate"
						}
					}
					switch scenario {
					case "short page":
						page.Vulnerabilities = page.Vulnerabilities[:199]
					case "changed total":
						page.TotalResults++
					case "bad metadata":
						page.StartIndex++
					case "publication":
						page.Vulnerabilities[0].CVE.Published = "invalid"
					case "normalization":
						page.Vulnerabilities[0].CVE.LastModified = "invalid"
					case "descending":
						page.Vulnerabilities[0], page.Vulnerabilities[1] = page.Vulnerabilities[1], page.Vulnerabilities[0]
					case "HTTP":
						http.Error(w, "unavailable", 503)
						return
					}
				}
				if start == 81 && scenario == "cross page" {
					page.Vulnerabilities[198].CVE.Published = "2027-01-01T00:00:00Z"
				}
				_ = json.NewEncoder(w).Encode(page)
			})
			got, err := client.fetch(context.Background(), 200, globalNoWait)
			var incomplete *IncompleteError
			if got != nil || !errors.As(err, &incomplete) {
				t.Fatalf("result=%v error=%v", got, err)
			}
		})
	}
}

func TestFetchGlobalPaginationDiagnostics(t *testing.T) {
	const key = "diagnostics-secret-key"
	for _, scenario := range []string{"short page", "wrong size", "wrong index", "changed total"} {
		t.Run(scenario, func(t *testing.T) {
			client := globalTestClient(t, key, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("apiKey") != key {
					t.Error("configured API key header missing")
				}
				if strings.Contains(r.URL.String(), key) || r.URL.Query().Has("apiKey") {
					t.Error("API key leaked into request URL")
				}
				start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
				size, _ := strconv.Atoi(r.URL.Query().Get("resultsPerPage"))
				page := globalTestPage(start, 480, size)
				if start == 280 {
					switch scenario {
					case "short page":
						page.Vulnerabilities = page.Vulnerabilities[:199]
					case "wrong size":
						page.ResultsPerPage = 80
					case "wrong index":
						page.StartIndex = 281
					case "changed total":
						page.TotalResults = 481
					}
				}
				_ = json.NewEncoder(w).Encode(page)
			})
			got, err := client.fetch(context.Background(), 200, globalNoWait)
			var incomplete *IncompleteError
			if got != nil || !errors.As(err, &incomplete) || incomplete.Requests != 2 {
				t.Fatal("expected no records and a two-request IncompleteError")
			}
			message := err.Error()
			if strings.Contains(message, key) || strings.Contains(incomplete.Cause.Error(), key) {
				t.Fatal("API key leaked into pagination diagnostics")
			}
			want := "inconsistent NVD pagination metadata: requested startIndex=280 resultsPerPage=200; expected response startIndex=280 resultsPerPage=200 vulnerability_count=200; got "
			switch scenario {
			case "short page":
				want += "startIndex=280 resultsPerPage=200 totalResults=480 vulnerability_count=199"
			case "wrong size":
				want += "startIndex=280 resultsPerPage=80 totalResults=480 vulnerability_count=200"
			case "wrong index":
				want += "startIndex=281 resultsPerPage=200 totalResults=480 vulnerability_count=200"
			case "changed total":
				want = "NVD result count changed during pagination: before totalResults=480; after totalResults=481; requested startIndex=280 resultsPerPage=200; got startIndex=280 resultsPerPage=200 vulnerability_count=200"
			}
			if incomplete.Cause.Error() != want {
				t.Fatalf("diagnostic = %q, want %q", incomplete.Cause.Error(), want)
			}
		})
	}
}

func TestFetchGlobalCountAndCancellation(t *testing.T) {
	requests := 0
	client := globalTestClient(t, "", func(w http.ResponseWriter, r *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(globalTestPage(0, 480, 1))
	})
	for _, count := range []int{-1, 0, 201} {
		if got, err := client.Fetch(context.Background(), count); got != nil || err == nil || !strings.Contains(err.Error(), "between 1 and 200") {
			t.Fatalf("count=%d error=%v", count, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := client.Fetch(ctx, 1); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("result=%v error=%v", got, err)
	}
	if requests != 0 {
		t.Fatalf("requests=%d", requests)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	got, err := client.fetch(ctx, 200, func(ctx context.Context, d time.Duration) error {
		cancel()
		return waitLatest(ctx, d)
	})
	if got != nil || !errors.Is(err, context.Canceled) || requests != 1 {
		t.Fatalf("result=%v error=%v requests=%d", got, err, requests)
	}
}

func TestFetchGlobalDeduplicatesAndBudget(t *testing.T) {
	for _, budget := range []bool{false, true} {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			requests := 0
			client := globalTestClient(t, "", func(w http.ResponseWriter, r *http.Request) {
				requests++
				start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
				total := 480
				if budget {
					total = 26000
				}
				size, _ := strconv.Atoi(r.URL.Query().Get("resultsPerPage"))
				page := globalTestPage(start, total, size)
				for i := range page.Vulnerabilities {
					if budget || start == 280 {
						page.Vulnerabilities[i].CVE.ID = "CVE-2026-duplicate"
					}
				}
				_ = json.NewEncoder(w).Encode(page)
			})
			got, err := client.fetch(context.Background(), 200, globalNoWait)
			if budget {
				if got != nil || err == nil || !strings.Contains(err.Error(), "budget exhausted") || requests != 128 {
					t.Fatalf("count=%d error=%v requests=%d", len(got), err, requests)
				}
				return
			}
			if err != nil || len(got) != 200 || got[0].ID != "CVE-2026-duplicate" || got[199].ID != "CVE-2026-0081" {
				t.Fatalf("count=%d error=%v", len(got), err)
			}
		})
	}
}

func TestFetchGlobalProbeAndTailSizes(t *testing.T) {
	for _, tc := range []struct {
		name         string
		total, count int
		duplicate    bool
		queries      []string
	}{
		{"singleton refetches data", 1, 1, false, []string{"0:1", "0:1"}},
		{"one newest", 2480, 1, false, []string{"0:1", "2479:1"}},
		{"small full database refetches", 3, 3, false, []string{"0:1", "0:3"}},
		{"dedup fills missing count", 480, 200, true, []string{"0:1", "280:200", "81:199"}},
		{"dedup exhausts remaining upper", 3, 3, true, []string{"0:1", "0:3"}},
		{"dedup caps size at upper", 4, 3, true, []string{"0:1", "1:3", "0:1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var queries []string
			client := globalTestClient(t, "", func(w http.ResponseWriter, r *http.Request) {
				start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
				size, _ := strconv.Atoi(r.URL.Query().Get("resultsPerPage"))
				queries = append(queries, fmt.Sprintf("%d:%d", start, size))
				page := globalTestPage(start, tc.total, size)
				if tc.duplicate && (start == tc.total-tc.count || tc.total < 10) {
					for i := range page.Vulnerabilities {
						page.Vulnerabilities[i].CVE.ID = "CVE-2026-duplicate"
					}
				}
				_ = json.NewEncoder(w).Encode(page)
			})
			got, err := client.fetch(context.Background(), tc.count, globalNoWait)
			if tc.duplicate && tc.total < 10 {
				if got != nil || err == nil {
					t.Fatal("expected incomplete unique count")
				}
			} else if err != nil || len(got) != tc.count {
				t.Fatalf("count=%d error=%v", len(got), err)
			}
			if !reflect.DeepEqual(queries, tc.queries) {
				t.Fatalf("queries=%v, want %v", queries, tc.queries)
			}
		})
	}
}

func TestFetchGlobalUsesProbeCountOnly(t *testing.T) {
	for _, invalidTime := range []bool{false, true} {
		t.Run(fmt.Sprint(invalidTime), func(t *testing.T) {
			requests := 0
			client := globalTestClient(t, "", func(w http.ResponseWriter, r *http.Request) {
				requests++
				start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
				size, _ := strconv.Atoi(r.URL.Query().Get("resultsPerPage"))
				page := globalTestPage(start, 2480, size)
				if requests == 1 {
					if invalidTime {
						page.Vulnerabilities[0].CVE.Published = "invalid"
					} else {
						page.ResultsPerPage = 0
						page.Vulnerabilities = nil
					}
				}
				_ = json.NewEncoder(w).Encode(page)
			})
			got, err := client.fetch(context.Background(), 200, globalNoWait)
			if len(got) != 200 || err != nil || requests != 2 || got[0].ID != "CVE-2026-2479" {
				t.Fatalf("count=%d error=%v requests=%d", len(got), err, requests)
			}
		})
	}
}

func TestFetchNormalizedLatestPreservesWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint(invalid), func(t *testing.T) {
			client := globalTestClient(t, "", func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if q.Get("pubStartDate") != start.Format(time.RFC3339) || q.Get("pubEndDate") != end.Format(time.RFC3339) {
					t.Errorf("query=%v", q)
				}
				page := globalTestPage(0, 1)
				if invalid {
					page.Vulnerabilities[0].CVE.LastModified = "invalid"
				}
				_ = json.NewEncoder(w).Encode(page)
			})
			got, err := client.FetchNormalizedLatest(context.Background(), LatestOptions{AsOf: end, PublishedStart: start, PublishedEnd: end, Limit: 200})
			if invalid {
				if got != nil || err == nil {
					t.Fatalf("result=%v error=%v", got, err)
				}
			} else if err != nil || len(got) != 1 || !got[0].PublishedAt.Equal(start) || !got[0].ModifiedAt.Equal(start) {
				t.Fatalf("result=%v error=%v", got, err)
			}
		})
	}
}

func TestFetchNormalizedLatestDiscardsPartial(t *testing.T) {
	end := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	client := globalTestClient(t, "", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(globalTestPage(0, 1)) })
	got, err := client.fetchNormalizedLatest(context.Background(), LatestOptions{AsOf: end, Limit: 2, MaxRequests: 1}, globalNoWait)
	if got != nil || err == nil {
		t.Fatalf("result=%v error=%v", got, err)
	}
}
