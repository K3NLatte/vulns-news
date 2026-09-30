package reposcan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/nvd"
	"vulns-news/src/osv"
)

type fakeOSV struct {
	query  func(context.Context, []osv.PackageVersion) []osv.QueryResult
	detail func(context.Context, string) (json.RawMessage, error)
}

func (f fakeOSV) Query(c context.Context, q []osv.PackageVersion) []osv.QueryResult {
	return f.query(c, q)
}
func (f fakeOSV) Advisory(c context.Context, id string) (json.RawMessage, error) {
	return f.detail(c, id)
}

type fakeNVD func(context.Context, string) (json.RawMessage, error)

func (f fakeNVD) LookupCVE(c context.Context, id string) (json.RawMessage, error) { return f(c, id) }
func profile() domain.RepositoryProfile {
	return domain.RepositoryProfile{Repository: domain.RepositoryIdentity{ID: "repo", CommitSHA: "abc123"}, Components: []domain.Component{{ID: "one", Ecosystem: "npm", Name: "pkg", Version: "1.0.0", SourcePath: "package-lock.json", Scope: "production"}}}
}
func emptyOSV() fakeOSV {
	return fakeOSV{query: func(_ context.Context, qs []osv.PackageVersion) []osv.QueryResult {
		out := []osv.QueryResult{}
		for _, q := range qs {
			out = append(out, osv.QueryResult{Query: q, Complete: true})
		}
		return out
	}}
}

const rawAdvisory = `{"id":"GHSA-example","aliases":["CVE-2026-12345"],"affected":[{"package":{"ecosystem":"npm","name":"other"},"ranges":[{"events":[{"fixed":"99.0.0"}]}]},{"package":{"ecosystem":"npm","name":"pkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}],"unknown":{"large":9007199254740993}}`

func positiveOSV() fakeOSV {
	f := emptyOSV()
	base := f.query
	f.query = func(c context.Context, qs []osv.PackageVersion) []osv.QueryResult {
		r := base(c, qs)
		for i := range r {
			r[i].IDs = []string{"GHSA-example"}
		}
		return r
	}
	f.detail = func(context.Context, string) (json.RawMessage, error) { return json.RawMessage(rawAdvisory), nil }
	return f
}

func TestPlanOriginsVersionsAndAmbiguity(t *testing.T) {
	p := profile()
	copy := p.Components[0]
	copy.ID = "two"
	copy.SourcePath = "nested/package-lock.json"
	copy.Scope = "development"
	other := copy
	other.ID = "three"
	other.Version = "2.0.0"
	p.Components = append(p.Components, copy, other,
		domain.Component{Ecosystem: "maven", Namespace: "org.example", Name: "lib", Version: "1.2"},
		domain.Component{Ecosystem: "packagist", Namespace: "vendor", Name: "lib", Version: "1.2.3"},
		domain.Component{Ecosystem: "os", Name: "linux", Version: "1.0.0"},
		domain.Component{Ecosystem: "npm", Name: "range", Version: "^1.0.0"})
	plan := Plan(p)
	if len(plan.Queries) != 4 || len(plan.Unqueried) != 2 {
		t.Fatalf("plan: %+v", plan)
	}
	found := false
	for _, q := range plan.Queries {
		if q.Query.Name == "pkg" && q.Query.Version == "1.0.0" {
			found = true
			if len(q.Origins) != 2 || q.Origins[0].ID != "one" || q.Workspace != "unavailable" {
				t.Fatalf("origins lost: %+v", q)
			}
		}
	}
	if !found {
		t.Fatal("missing version")
	}
	for _, eco := range []string{"maven", "packagist"} {
		a := profile()
		a.Components = []domain.Component{{Ecosystem: eco, Namespace: "a", Name: "lib", Version: "1.0.0"}, {Ecosystem: eco, Namespace: "b", Name: "lib", Version: "2.0.0"}}
		got := Plan(a)
		if len(got.Queries) != 2 || len(got.Unqueried) != 0 {
			t.Fatalf("distinct qualified identities were excluded: %+v", got)
		}
	}
	p.Components = append(p.Components, domain.Component{Ecosystem: "maven", Namespace: "wrong", Name: "org.example:lib", Version: "1.0.0"})
	if got := Plan(p); got.Unqueried[len(got.Unqueried)-1].Reason != "invalid/ambiguous identity" {
		t.Fatal(got)
	}
}

func TestEmptyErrorsAndWarnings(t *testing.T) {
	r := Run(context.Background(), profile(), Config{OSV: emptyOSV()})
	if r.Status != "complete" || r.Acquisition != "complete" || r.Queries[0].Outcome != "no_advisory_found" || r.RuntimeImpact != "unknown" {
		t.Fatal(r)
	}
	bad := emptyOSV()
	bad.query = func(_ context.Context, qs []osv.PackageVersion) []osv.QueryResult {
		return []osv.QueryResult{{Query: qs[0], Error: "HTTP 503"}}
	}
	r = Run(context.Background(), profile(), Config{OSV: bad})
	if r.Status != "incomplete" || r.Queries[0].Outcome != "unknown" {
		t.Fatal(r)
	}
	p := profile()
	p.Warnings = []string{"lockfile unavailable"}
	p.Components = append(p.Components, domain.Component{Ecosystem: "unknown", Name: "x"})
	r = Run(context.Background(), p, Config{OSV: emptyOSV()})
	if r.Status != "incomplete" || r.Warnings[0] != p.Warnings[0] || len(r.Unqueried) != 1 {
		t.Fatal(r)
	}
	r = Run(context.Background(), domain.RepositoryProfile{}, Config{OSV: bad})
	if r.Acquisition == "complete" || r.Status != "incomplete" {
		t.Fatal(r)
	}
	r = Run(context.Background(), profile(), Config{})
	if r.Status != "incomplete" {
		t.Fatal(r)
	}
}

func TestEvidenceRawGroupsAndFailures(t *testing.T) {
	p := profile()
	c := p.Components[0]
	c.Version = "2.0.0"
	p.Components = append(p.Components, c)
	f := positiveOSV()
	calls := 0
	base := f.detail
	f.detail = func(ctx context.Context, id string) (json.RawMessage, error) { calls++; return base(ctx, id) }
	n := fakeNVD(func(_ context.Context, id string) (json.RawMessage, error) {
		return json.RawMessage(`{"id":"` + id + `","configurations":[{"unknown":true}]}`), nil
	})
	r := Run(context.Background(), p, Config{OSV: f, NVD: n})
	if calls != 1 || len(r.Records) != 2 || len(r.Groups) != 1 || len(r.Groups[0].IDs) != 2 || r.Status != "complete" {
		t.Fatal(r, calls)
	}
	if string(r.Records["osv:GHSA-example"].Raw) != rawAdvisory {
		t.Fatal("raw changed")
	}
	for _, q := range r.Queries {
		if q.Outcome != "affected_version_match" || !reflect.DeepEqual(q.Matches[0].FixedVersions, []string{"2.0.0"}) {
			t.Fatal(q)
		}
	}
	f.query = func(_ context.Context, qs []osv.PackageVersion) []osv.QueryResult {
		out := []osv.QueryResult{}
		for _, q := range qs {
			out = append(out, osv.QueryResult{Query: q, IDs: []string{"GHSA-example", "broken"}, Error: "pagination failed"})
		}
		return out
	}
	f.detail = func(_ context.Context, id string) (json.RawMessage, error) {
		if id == "broken" {
			return nil, errors.New("HTTP 500")
		}
		return json.RawMessage(rawAdvisory), nil
	}
	r = Run(context.Background(), p, Config{OSV: f})
	if r.Status != "incomplete" || r.Queries[0].Outcome != "affected_version_match" || !strings.Contains(r.Queries[0].Error, "HTTP 500") {
		t.Fatal(r)
	}
	f = positiveOSV()
	f.detail = func(context.Context, string) (json.RawMessage, error) {
		return json.RawMessage(strings.Replace(rawAdvisory, `"aliases":`, `"withdrawn":"2026-01-01T00:00:00Z","aliases":`, 1)), nil
	}
	r = Run(context.Background(), profile(), Config{OSV: f})
	if r.Queries[0].Outcome != "unknown" || !r.Records["osv:GHSA-example"].Withdrawn || len(r.Queries[0].Matches[0].FixedVersions) != 0 {
		t.Fatal(r)
	}
	f.detail = func(context.Context, string) (json.RawMessage, error) {
		return json.RawMessage(`{"id":"GHSA-example","affected":[{"package":{"ecosystem":"npm","name":"other"}}]}`), nil
	}
	r = Run(context.Background(), profile(), Config{OSV: f})
	if r.Queries[0].Outcome != "unknown" || len(r.Groups[0].IDs) != 1 || len(r.Enrichment) != 0 {
		t.Fatal(r)
	}
}

func TestNVDMissingFailureAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		err          error
		status, scan string
	}{{nvd.ErrCVENotFound, "not_found", "complete"}, {errors.New("HTTP 429"), "error", "incomplete"}} {
		r := Run(context.Background(), profile(), Config{OSV: positiveOSV(), NVD: fakeNVD(func(context.Context, string) (json.RawMessage, error) { return nil, tc.err })})
		if r.Enrichment[0].Status != tc.status || r.Status != tc.scan || r.Queries[0].Outcome != "affected_version_match" {
			t.Fatal(r)
		}
	}
	f := positiveOSV()
	f.detail = func(context.Context, string) (json.RawMessage, error) {
		return json.RawMessage(strings.Replace(rawAdvisory, `"CVE-2026-12345"`, `"CVE-2026-99999","CVE-2026-12345","CVE-2026-12345"`, 1)), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan struct{})
	calls := []string{}
	n := fakeNVD(func(_ context.Context, id string) (json.RawMessage, error) {
		calls = append(calls, id)
		close(first)
		return json.RawMessage(`{"id":"` + id + `"}`), nil
	})
	done := make(chan Report, 1)
	go func() { done <- Run(ctx, profile(), Config{OSV: f, NVD: n, NVDInterval: time.Hour}) }()
	<-first
	cancel()
	select {
	case r := <-done:
		if r.Status != "incomplete" || len(calls) != 1 || calls[0] != "CVE-2026-12345" || len(r.Enrichment) != 2 {
			t.Fatal(r, calls)
		}
	case <-time.After(time.Second):
		t.Fatal("rate wait was not cancellable")
	}
}

func TestStateRoundtripAndBaselineProtection(t *testing.T) {
	p := profile()
	s := State{SchemaVersion: SchemaVersion, Profile: p, Report: Run(context.Background(), p, Config{OSV: positiveOSV()})}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, s); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !sameJSON(got.Report.Records["osv:GHSA-example"].Raw, s.Report.Records["osv:GHSA-example"].Raw) || !reflect.DeepEqual(got.Profile, p) {
		t.Fatal(got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	before, _ := os.ReadFile(path)
	bad := s
	bad.Report = Run(context.Background(), p, Config{})
	if err := Save(path, bad); err == nil {
		t.Fatal("overwrote baseline with failed scan")
	}
	bad = s
	bad.SchemaVersion = 2
	if err := Save(path, bad); err == nil {
		t.Fatal("accepted future schema")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("baseline changed on error")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatal("temporary file leaked")
	}
	s.Report = Run(context.Background(), p, Config{OSV: emptyOSV()})
	if err := Save(path, s); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{`{`, string(before) + ` {}`, strings.Replace(string(before), `"schema_version": 1`, `"schema_version": 9`, 1), `{"schema_version":1}`} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("accepted corrupt state")
		}
		if err := Save(path, s); err == nil {
			t.Fatal("overwrote corrupt baseline")
		}
		unchanged, _ := os.ReadFile(path)
		if string(unchanged) != text {
			t.Fatal("corrupt baseline changed")
		}
	}
}

func TestMonitoringRechecksAndChanges(t *testing.T) {
	p := profile()
	a := Run(context.Background(), p, Config{OSV: emptyOSV()})
	b := Run(context.Background(), p, Config{OSV: positiveOSV()})
	has := func(changes []Change, kind, key string) bool {
		for _, c := range changes {
			if c.Kind == kind && c.Key == key {
				return true
			}
		}
		return false
	}
	if !has(Changes(a, b), "added", "osv:GHSA-example") {
		t.Fatal("new advisory missed")
	}
	f := positiveOSV()
	f.detail = func(context.Context, string) (json.RawMessage, error) {
		return json.RawMessage(strings.Replace(rawAdvisory, `"unknown":`, `"summary":"updated","unknown":`, 1)), nil
	}
	c := Run(context.Background(), p, Config{OSV: f})
	if !has(Changes(b, c), "modified", "osv:GHSA-example") {
		t.Fatal("modified missed")
	}
	d := Run(context.Background(), p, Config{})
	if has(Changes(c, d), "no_longer_observed", "osv:GHSA-example") {
		t.Fatal("failure treated as removal")
	}
	if !has(Changes(c, a), "no_longer_observed", "osv:GHSA-example") {
		t.Fatal("complete absence missed")
	}
	if len(Changes(c, c)) != 0 {
		t.Fatal("spurious changes")
	}
	if sameJSON(json.RawMessage(`{"x":9007199254740993}`), json.RawMessage(`{"x":9007199254740992}`)) {
		t.Fatal("large number change lost")
	}
}

func TestHTTPIntegrationThreeEcosystemsAndMonitoring(t *testing.T) {
	var batches, details, nvdCalls atomic.Int32
	var phase atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			batches.Add(1)
			var body struct {
				Queries []struct {
					Package struct{ Ecosystem, Name string }
					Version string
				}
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			results := []any{}
			for _, q := range body.Queries {
				if phase.Load() == 0 || q.Package.Ecosystem != "npm" || q.Version != "1.0.0" {
					results = append(results, map[string]any{})
				} else {
					results = append(results, map[string]any{"vulns": []any{map[string]string{"id": "GHSA-example"}}})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case "/v1/vulns/GHSA-example":
			details.Add(1)
			fmt.Fprint(w, rawAdvisory)
		default:
			nvdCalls.Add(1)
			if r.URL.Query().Get("cveId") != "CVE-2026-12345" {
				t.Errorf("unexpected NVD lookup: %s", r.URL)
			}
			fmt.Fprint(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-12345","extra":"retained"}}]}`)
		}
	}))
	defer server.Close()
	o, err := osv.NewDiscoveryClient(osv.DiscoveryConfig{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	n, err := nvd.NewAnalysisClient(nvd.Config{BaseURL: server.URL + "/nvd", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	p := profile()
	c := p.Components[0]
	c.SourcePath = "nested/package-lock.json"
	p.Components = append(p.Components, c)
	c.Version = "2.0.0"
	p.Components = append(p.Components, c, domain.Component{Ecosystem: "maven", Name: "org.example:pkg", Version: "1.0"}, domain.Component{Ecosystem: "packagist", Name: "vendor/pkg", Version: "1.0.0"})
	cfg := Config{OSV: o, NVD: n}
	a := Run(context.Background(), p, cfg)
	phase.Store(1)
	b := Run(context.Background(), p, cfg)
	if a.Status != "complete" || b.Status != "complete" || batches.Load() != 2 || details.Load() != 1 || nvdCalls.Load() != 1 || len(b.Queries) != 4 || len(b.Records) != 2 {
		t.Fatalf("a=%+v b=%+v calls=%d/%d/%d", a, b, batches.Load(), details.Load(), nvdCalls.Load())
	}
	for _, q := range b.Queries {
		if q.Query.Ecosystem == "npm" && q.Query.Version == "1.0.0" {
			if q.Outcome != "affected_version_match" || len(q.Origins) != 2 {
				t.Fatal(q)
			}
		} else if q.Outcome != "no_advisory_found" {
			t.Fatal("evidence crossed query identity", q)
		}
	}
	if len(Changes(a, b)) == 0 {
		t.Fatal("monitor missed new advisory")
	}
}
