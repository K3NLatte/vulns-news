package osv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/versions"
)

func profile(eco, version string) domain.RepositoryProfile {
	return domain.RepositoryProfile{Components: []domain.Component{{Ecosystem: eco, Name: "example", Version: version}}}
}
func vulnerability() domain.NormalizedVulnerability {
	return domain.NormalizedVulnerability{ID: "CVE-2025-12345"}
}
func client(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c, err := NewClient(Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEnrichLinkage(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
		count         int
	}{
		{"alias", `{"vulns":[{"id":"GHSA-example","aliases":["CVE-2025-12345"]}]}`, 1},
		{"id", `{"vulns":[{"id":"CVE-2025-12345"}]}`, 1},
		{"no alias", `{"vulns":[{"id":"GHSA-other"}]}`, 0},
		{"other alias", `{"vulns":[{"id":"GHSA-other","aliases":["CVE-2025-99999"]}]}`, 0},
		{"withdrawn", `{"vulns":[{"id":"CVE-2025-12345","withdrawn":"2025-01-01T00:00:00Z"}]}`, 0},
		{"empty", `{}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := client(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "POST" || r.URL.Path != "/v1/query" || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("unexpected request: %v", r)
				}
				var q query
				if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
					t.Error(err)
				}
				if q != (query{Package: packageKey{Ecosystem: "npm", Name: "example"}, Version: "1.2.3"}) {
					t.Errorf("query: %+v", q)
				}
				io.WriteString(w, tc.payload)
			})
			p := profile("npm", "1.2.3")
			p.Components = append(p.Components, p.Components[0])
			original := vulnerability()
			original.Affected = make([]domain.AffectedTarget, 1, 10)
			original.Affected[0].ID = "existing"
			got, err := c.Enrich(context.Background(), p, original)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || len(got.Affected) != 1+tc.count || len(got.References) != tc.count {
				t.Fatalf("calls=%d result=%+v", calls, got)
			}
			if original.Affected[:2][1].ID != "" {
				t.Fatal("mutated input backing array")
			}
			if tc.count == 0 {
				return
			}
			target := got.Affected[1]
			if target.Kind != domain.AffectedPackage || target.PackageName != "example" || target.Ecosystem != "npm" || target.Constraints[0].Expression != "1.2.3" || target.Constraints[0].Scheme != "osv" {
				t.Fatalf("target: %+v", target)
			}
			status, err := (versions.Versions{}).Evaluate("npm", "1.2.3", target.Constraints)
			if err != nil || status != domain.VersionAffected {
				t.Fatalf("status=%s err=%v", status, err)
			}
			status, _ = (versions.Versions{}).Evaluate("npm", "", target.Constraints)
			if status != domain.VersionUnknown {
				t.Fatal("confirmed unresolved version")
			}
			again, err := c.Enrich(context.Background(), p, got)
			if err != nil || !reflect.DeepEqual(got, again) {
				t.Fatalf("not idempotent: %v", err)
			}
		})
	}
}

func TestNonNPMEvidence(t *testing.T) {
	for _, tc := range []struct{ eco, osv, version string }{{"Go", "Go", "v1.2.3"}, {"go", "Go", "v1.2.3"}, {"pypi", "PyPI", "1.2.3"}, {"PyPI", "PyPI", "1.2.3rc1"}} {
		t.Run(tc.eco, func(t *testing.T) {
			c := client(t, func(w http.ResponseWriter, r *http.Request) {
				var q query
				json.NewDecoder(r.Body).Decode(&q)
				if q.Package.Ecosystem != tc.osv || q.Version != tc.version {
					t.Errorf("query: %+v", q)
				}
				io.WriteString(w, `{"vulns":[{"id":"CVE-2025-12345"}]}`)
			})
			got, err := c.Enrich(context.Background(), profile(tc.eco, tc.version), vulnerability())
			if err != nil || len(got.Affected) != 1 {
				t.Fatalf("%+v %v", got, err)
			}
			constraint := got.Affected[0].Constraints[0]
			if constraint.Scheme != "osv" || constraint.Expression != tc.version || !strings.HasPrefix(got.Affected[0].ID, "osv:") || !contains(got.References[0].Tags, "osv_match") {
				t.Fatalf("missing evidence: %+v", got)
			}
			status, _ := (versions.Versions{}).Evaluate(tc.eco, tc.version, []domain.VersionConstraint{constraint})
			if status != domain.VersionAffected {
				t.Fatal(status)
			}
		})
	}
}

func TestSkipUnresolved(t *testing.T) {
	c := client(t, func(http.ResponseWriter, *http.Request) { t.Error("unexpected disclosure") })
	for _, eco := range []string{"npm", "Go", "go", "pypi", "unsupported"} {
		for _, version := range []string{"", "^1.2.3", "~1.2.3", "*", "latest", ">=1.2.3", "1.x", "git+https://example.com/repo", "file:../foo"} {
			got, err := c.Enrich(context.Background(), profile(eco, version), vulnerability())
			if err != nil || len(got.Affected) != 0 {
				t.Fatalf("%s %s: %+v %v", eco, version, got, err)
			}
		}
	}
}

func TestErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		limit      bool
	}{
		{"non2xx", "secret", 429, false},
		{"redirect", "", 307, false},
		{"malformed", "{", 200, false},
		{"trailing", "{} {}", 200, false},
		{"oversized", strings.Repeat(" ", maxBodyBytes+1), 200, true},
		{"pagination", `{"next_page_token":"next"}`, 200, true},
		{"results", `{"vulns":[` + strings.Repeat(`{},`, maxResults) + `{}]}`, 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := client(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) })
			original := vulnerability()
			got, err := c.Enrich(context.Background(), profile("npm", "1.2.3"), original)
			if err == nil || !reflect.DeepEqual(got, original) {
				t.Fatalf("%+v %v", got, err)
			}
			if tc.limit && !errors.Is(err, ErrLimit) {
				t.Fatal(err)
			}
			if tc.status >= 300 {
				var httpErr *HTTPError
				if !errors.As(err, &httpErr) || httpErr.StatusCode != tc.status {
					t.Fatal(err)
				}
			}
		})
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestContextAndTransport(t *testing.T) {
	sentinel := errors.New("transport failure")
	for _, wait := range []bool{false, true} {
		c, err := NewClient(Config{HTTPClient: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			if _, ok := r.Context().Deadline(); !ok {
				t.Error("missing deadline")
			}
			if wait {
				<-r.Context().Done()
				return nil, r.Context().Err()
			}
			return nil, sentinel
		})}})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if wait {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		}
		_, err = c.Enrich(ctx, profile("npm", "1.2.3"), vulnerability())
		expected := sentinel
		if wait {
			expected = context.Canceled
		}
		if !errors.Is(err, expected) {
			t.Fatalf("%v", err)
		}
	}
}

func TestDeadlineAndAtomicFailure(t *testing.T) {
	t.Run("in flight deadline", func(t *testing.T) {
		started := make(chan struct{})
		c := client(t, func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			close(started)
			<-r.Context().Done()
		})
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := c.Enrich(ctx, profile("npm", "1.2.3"), vulnerability())
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		select {
		case <-started:
		default:
			t.Fatal("request never started")
		}
	})
	t.Run("no partial success", func(t *testing.T) {
		calls := 0
		c := client(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				io.WriteString(w, `{"vulns":[{"id":"CVE-2025-12345"}]}`)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		p := profile("npm", "1.2.3")
		p.Components = append(p.Components, domain.Component{Ecosystem: "Go", Name: "example.org/module", Version: "v1.2.3"})
		original := vulnerability()
		got, err := c.Enrich(context.Background(), p, original)
		if err == nil || calls != 2 || !reflect.DeepEqual(got, original) {
			t.Fatalf("%+v %v calls=%d", got, err, calls)
		}
	})
}

func TestQueryBudgetAndConfig(t *testing.T) {
	c := client(t, func(http.ResponseWriter, *http.Request) { t.Error("budget must be checked before disclosure") })
	p := profile("npm", "1.2.3")
	for i := 0; i < maxQueries; i++ {
		p.Components = append(p.Components, domain.Component{Ecosystem: "npm", Name: fmt.Sprintf("package-%d", i), Version: "1.2.3"})
	}
	if _, err := c.Enrich(context.Background(), p, vulnerability()); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	for _, base := range []string{"relative", "ftp://example.com", "https://user:pass@example.com", "https://example.com?secret=yes", "https://example.com/#fragment"} {
		if _, err := NewClient(Config{BaseURL: base}); err == nil {
			t.Errorf("accepted %q", base)
		}
	}
	if _, err := NewClient(Config{}); err != nil {
		t.Fatal(err)
	}
}
