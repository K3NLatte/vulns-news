package nvd

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const lookupTestID = "CVE-2026-12345"
const lookupTestRaw = `{"id":"CVE-2026-12345", "unknown":{"large":9007199254740993,"nested":[true,null]},"providerField":"retained"}`
const lookupTestPage = `{"totalResults":1,"startIndex":0,"resultsPerPage":1,"vulnerabilities":[{"cve":` + lookupTestRaw + `}]}`

func newLookupTestClient(t *testing.T, server *httptest.Server, maximum int64) *Client {
	t.Helper()
	client, err := NewClient(Config{BaseURL: server.URL, APIKey: "test-secret", HTTPClient: server.Client(), MaxResponseBytes: maximum})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestLookupCVEFound(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.RawQuery != "cveId="+lookupTestID {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		if r.Header.Get("apiKey") != "test-secret" || strings.Contains(r.URL.String(), "test-secret") {
			t.Error("API key must appear only in the header")
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Error("missing JSON accept header")
		}
		fmt.Fprint(w, lookupTestPage)
	}))
	defer server.Close()
	for _, maximum := range []int64{0, int64(len(lookupTestPage)), math.MaxInt64} {
		client := newLookupTestClient(t, server, maximum)
		raw, err := client.LookupCVE(context.Background(), lookupTestID)
		if err != nil || string(raw) != lookupTestRaw {
			t.Fatalf("raw = %s, err = %v", raw, err)
		}
		if client.endpoint.RawQuery != "" {
			t.Fatal("lookup mutated endpoint")
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestLookupCVEResponses(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		notFound bool
	}{
		{"missing", `{"totalResults":0,"vulnerabilities":[]}`, true},
		{"empty positive", `{"totalResults":1,"vulnerabilities":[]}`, false},
		{"zero with record", strings.Replace(lookupTestPage, `"totalResults":1`, `"totalResults":0`, 1), false},
		{"multiple total", strings.Replace(lookupTestPage, `"totalResults":1`, `"totalResults":2`, 1), false},
		{"multiple records", `{"totalResults":1,"vulnerabilities":[{"cve":` + lookupTestRaw + `},{"cve":` + lookupTestRaw + `}]}`, false},
		{"negative total", `{"totalResults":-1,"vulnerabilities":[]}`, false},
		{"wrong id", strings.Replace(lookupTestPage, lookupTestID, "CVE-2026-9999", 1), false},
		{"wrong offset", strings.Replace(lookupTestPage, `"startIndex":0`, `"startIndex":1`, 1), false},
		{"wrong page size", strings.Replace(lookupTestPage, `"resultsPerPage":1`, `"resultsPerPage":0`, 1), false},
		{"truncated", lookupTestPage[:len(lookupTestPage)-1], false},
		{"trailing JSON", lookupTestPage + ` {}`, false},
		{"trailing garbage", lookupTestPage + ` broken`, false},
		{"null", `null`, false},
		{"empty object", `{}`, false},
		{"missing total", `{"vulnerabilities":[]}`, false},
		{"missing array", `{"totalResults":0}`, false},
		{"null array", `{"totalResults":0,"vulnerabilities":null}`, false},
		{"null CVE", `{"totalResults":1,"vulnerabilities":[{"cve":null}]}`, false},
		{"missing CVE", `{"totalResults":1,"vulnerabilities":[{}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.body) }))
			defer server.Close()
			raw, err := newLookupTestClient(t, server, 0).LookupCVE(context.Background(), lookupTestID)
			if err == nil || raw != nil || errors.Is(err, ErrCVENotFound) != tc.notFound {
				t.Fatalf("raw = %s, err = %v, want notFound=%v", raw, err, tc.notFound)
			}
		})
	}
}

func TestLookupCVEInvalidID(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := newLookupTestClient(t, server, 0)
	for _, id := range []string{"", "cve-2026-12345", " CVE-2026-12345", "CVE-2026-12345\n", "CVE-26-12345", "CVE-2026-123", "CVE-2026-1234&x=y", "CVE-２０２６-12345"} {
		if raw, err := client.LookupCVE(context.Background(), id); err == nil || raw != nil {
			t.Errorf("accepted invalid ID %q", id)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid IDs made %d HTTP calls", calls.Load())
	}
}

func TestLookupCVEHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("message", "rate limited")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"message":"fallback"}`)
	}))
	defer server.Close()
	raw, err := newLookupTestClient(t, server, 0).LookupCVE(context.Background(), lookupTestID)
	var httpErr *HTTPError
	if raw != nil || !errors.As(err, &httpErr) || httpErr.StatusCode != 429 || httpErr.Message != "rate limited" {
		t.Fatalf("raw = %s, err = %v", raw, err)
	}
}

func TestLookupCVEResponseBounds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, lookupTestPage) }))
	defer server.Close()
	raw, err := newLookupTestClient(t, server, int64(len(lookupTestPage)-1)).LookupCVE(context.Background(), lookupTestID)
	if raw != nil || err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("raw = %s, err = %v", raw, err)
	}
}

func TestLookupCVECancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	client := newLookupTestClient(t, server, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := client.LookupCVE(ctx, lookupTestID); done <- err }()
	select {
	case <-started:
		cancel()
	case <-ctx.Done():
		t.Fatal("request did not start")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestLookupCVERedirectNotFollowed(t *testing.T) {
	var redirected, callback atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); fmt.Fprint(w, lookupTestPage) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer server.Close()
	client := newLookupTestClient(t, server, 0)
	client.httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { callback.Add(1); return nil }
	raw, err := client.LookupCVE(context.Background(), lookupTestID)
	var httpErr *HTTPError
	if raw != nil || !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusFound {
		t.Fatalf("raw = %s, err = %v", raw, err)
	}
	if redirected.Load() != 0 || callback.Load() != 0 {
		t.Fatal("lookup followed redirect or called shared redirect policy")
	}
	if client.httpClient.CheckRedirect == nil {
		t.Fatal("shared redirect policy removed")
	}
	client.httpClient.CheckRedirect(nil, nil)
	if callback.Load() != 1 {
		t.Fatal("shared redirect policy mutated")
	}
}
