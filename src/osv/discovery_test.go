package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func discoveryTestClient(t *testing.T, handler http.HandlerFunc, config DiscoveryConfig) *DiscoveryClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	config.BaseURL = server.URL
	c, err := NewDiscoveryClient(config)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func discoveryInputs(n int) []PackageVersion {
	q := make([]PackageVersion, n)
	for i := range q {
		q[i] = PackageVersion{"Go", fmt.Sprintf("example.org/pkg%d", i), "v1.0.0"}
	}
	return q
}

func TestDiscoveryBatchOrderAndNoTotalLimit(t *testing.T) {
	var sizes []int
	c := discoveryTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/querybatch" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		var payload struct {
			Queries []struct {
				Package map[string]string `json:"package"`
				Version string            `json:"version"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		sizes = append(sizes, len(payload.Queries))
		results := make([]any, len(payload.Queries))
		for i, q := range payload.Queries {
			if len(q.Package) != 2 || q.Package["ecosystem"] != "Go" || q.Version != "v1.0.0" {
				t.Errorf("invalid query: %+v", q)
			}
			results[i] = map[string]any{"vulns": []any{map[string]string{"id": q.Package["name"]}}}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": results})
	}, DiscoveryConfig{})
	inputs := discoveryInputs(10001)
	got := c.Query(context.Background(), inputs)
	if len(sizes) != 101 || sizes[0] != 100 || sizes[100] != 1 {
		t.Fatalf("batch sizes: %v", sizes)
	}
	for i, r := range got {
		if !r.Complete || r.Error != "" || r.Query != inputs[i] || !reflect.DeepEqual(r.IDs, []string{inputs[i].Name}) {
			t.Fatalf("result %d: %+v", i, r)
		}
	}
}

func TestDiscoveryPerQueryPaging(t *testing.T) {
	calls := 0
	c := discoveryTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		var p struct {
			Queries []discoveryQuery `json:"queries"`
		}
		json.NewDecoder(r.Body).Decode(&p)
		switch calls {
		case 1:
			fmt.Fprint(w, `{"results":[{"vulns":[{"id":"Z"},{"id":"A"}],"next_page_token":"one"},{},{"next_page_token":"other"}]}`)
		case 2:
			if len(p.Queries) != 2 || p.Queries[0].PageToken != "one" || p.Queries[1].PageToken != "other" || p.Queries[1].Package.Name != "example.org/pkg2" {
				t.Errorf("paging: %+v", p)
			}
			fmt.Fprint(w, `{"results":[{"vulns":[{"id":"A"},{"id":"B"}]},{"vulns":[{"id":"C"}]}]}`)
		default:
			t.Error("unexpected request")
		}
	}, DiscoveryConfig{})
	got := c.Query(context.Background(), discoveryInputs(3))
	want := [][]string{{"A", "B", "Z"}, {}, {"C"}}
	for i, r := range got {
		if !r.Complete || r.Error != "" || !reflect.DeepEqual(r.IDs, want[i]) {
			t.Fatalf("result %d: %+v", i, r)
		}
	}
}

func TestDiscoveryFailuresAndPartialResults(t *testing.T) {
	for _, tc := range []struct {
		name, reply      string
		status, maxPages int
		partial          bool
	}{
		{"short", `{"results":[]}`, 200, 0, false},
		{"long", `{"results":[{},{}]}`, 200, 0, false},
		{"null", `{"results":[null]}`, 200, 0, false},
		{"malformed", `{`, 200, 0, false},
		{"invalid ID", `{"results":[{"vulns":[{}]}]}`, 200, 0, false},
		{"http", ``, 503, 0, false},
		{"repeated", `{"results":[{"vulns":[{"id":"A"}],"next_page_token":"same"}]}`, 200, 0, true},
		{"page limit", `{"results":[{"vulns":[{"id":"A"}],"next_page_token":"same"}]}`, 200, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := discoveryTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.reply)
			}, DiscoveryConfig{MaxPages: tc.maxPages})
			r := c.Query(context.Background(), discoveryInputs(1))[0]
			if r.Complete || r.Error == "" {
				t.Fatalf("failure became success: %+v", r)
			}
			if tc.partial && !reflect.DeepEqual(r.IDs, []string{"A"}) {
				t.Fatalf("lost IDs: %+v", r)
			}
			if calls > 2 {
				t.Fatalf("unbounded pagination: %d", calls)
			}
		})
	}
}

func TestDiscoveryPageFailureRetainsIDs(t *testing.T) {
	calls := 0
	c := discoveryTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			fmt.Fprint(w, `{"results":[{"vulns":[{"id":"A"}],"next_page_token":"next"}]}`)
		} else {
			w.WriteHeader(500)
		}
	}, DiscoveryConfig{})
	r := c.Query(context.Background(), discoveryInputs(1))[0]
	if r.Complete || r.Error == "" || !reflect.DeepEqual(r.IDs, []string{"A"}) {
		t.Fatal(r)
	}
}

func TestDiscoveryTimeoutAndCancellation(t *testing.T) {
	var calls atomic.Int32
	c := discoveryTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-r.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
	}, DiscoveryConfig{HTTPClient: &http.Client{Timeout: 20 * time.Millisecond}, BatchSize: 1})
	got := c.Query(context.Background(), discoveryInputs(2))
	for _, r := range got {
		if r.Complete || r.Error == "" {
			t.Fatal(r)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := calls.Load()
	got = c.Query(ctx, discoveryInputs(3))
	if calls.Load() != before {
		t.Fatal("canceled queries reached server")
	}
	for _, r := range got {
		if r.Complete || !strings.Contains(r.Error, "context canceled") {
			t.Fatal(r)
		}
	}
}

func TestDiscoveryAdvisory(t *testing.T) {
	id := "OSV/a b?c#d%"
	raw := `{"id":"OSV/a b?c#d%","unknown":{"retained":true}}`
	for _, tc := range []struct {
		name, body string
		limit      int64
		ok         bool
	}{
		{"escaped and retained", raw, 0, true},
		{"mismatch", `{"id":"other"}`, 0, false},
		{"oversize", raw, 10, false},
		{"exact size", raw, int64(len(raw)), true},
		{"null", `null`, 0, false},
		{"array", `[]`, 0, false},
		{"trailing JSON", raw + `{}`, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := discoveryTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.RequestURI != "/v1/vulns/"+url.PathEscape(id) {
					t.Errorf("bad escaped URI: %s", r.RequestURI)
				}
				fmt.Fprint(w, tc.body)
			}, DiscoveryConfig{MaxResponseBytes: tc.limit})
			data, err := c.Advisory(context.Background(), id)
			if (err == nil) != tc.ok {
				t.Fatalf("data=%s err=%v", data, err)
			}
			if tc.ok && string(data) != raw {
				t.Fatalf("raw JSON changed: %s", data)
			}
		})
	}
}

func TestDiscoveryValidationAndRedirectPrivacy(t *testing.T) {
	for _, base := range []string{"ftp://example.org", "//example.org", "https://user:pass@example.org", "https://example.org?", "https://example.org#", "https://example.org/a/../b", "https://example.org/%2f"} {
		if _, err := NewDiscoveryClient(DiscoveryConfig{BaseURL: base}); err == nil {
			t.Errorf("accepted %s", base)
		}
	}
	var forwarded atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1) }))
	defer destination.Close()
	original := &http.Client{}
	c := discoveryTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}, DiscoveryConfig{HTTPClient: original})
	if original.Timeout != 0 || original.CheckRedirect != nil {
		t.Fatal("modified caller client")
	}
	if c.httpClient.Timeout != 30*time.Second {
		t.Fatal("missing default timeout")
	}
	r := c.Query(context.Background(), discoveryInputs(1))[0]
	if r.Complete || r.Error == "" {
		t.Fatal(r)
	}
	if _, err := c.Advisory(context.Background(), "A"); err == nil {
		t.Fatal("redirect accepted")
	}
	if forwarded.Load() != 0 {
		t.Fatal("redirect disclosed dependency")
	}
	inputs := []PackageVersion{{"Go", "", "1"}, {"Go", "x", ""}, {"Go", "x\n", "1"}, {"Go", "x", "1\x00"}, {"", "x", "1"}}
	for _, r := range c.Query(context.Background(), inputs) {
		if r.Complete || !strings.Contains(r.Error, "invalid") {
			t.Fatal(r)
		}
	}
}

func TestDiscoveryBatchOversize(t *testing.T) {
	c := discoveryTestClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"results":[{}]}`) }, DiscoveryConfig{MaxResponseBytes: 5})
	r := c.Query(context.Background(), discoveryInputs(1))[0]
	if r.Complete || !strings.Contains(r.Error, "maximum bytes") {
		t.Fatal(r)
	}
}
