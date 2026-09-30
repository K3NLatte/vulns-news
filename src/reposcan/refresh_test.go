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
	"testing"

	"vulns-news/src/domain"
	"vulns-news/src/nvd"
	"vulns-news/src/osv"
)

func coverageProfile() domain.RepositoryProfile {
	p := profile()
	p.Warnings = []string{"static inventory; runtime environment not evaluated"}
	p.Components = append(p.Components, domain.Component{ID: "unknown", Ecosystem: "unrecognized", Name: "inventory", SourcePath: "manifest"})
	return p
}

func hasChange(changes []Change, kind, key string) bool {
	for _, c := range changes {
		if c.Kind == kind && c.Key == key {
			return true
		}
	}
	return false
}

func TestRefreshAdvancesBaselineDespiteCoverage(t *testing.T) {
	p := coverageProfile()
	initial := State{SchemaVersion: SchemaVersion, Profile: p, Report: Run(context.Background(), p, Config{OSV: emptyOSV()})}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, initial); err != nil {
		t.Fatal(err)
	}
	for _, client := range []fakeOSV{positiveOSV(), emptyOSV()} {
		previous, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		current := Run(context.Background(), previous.Profile, Config{OSV: client})
		if !current.RefreshComplete || current.Status != "incomplete" || len(current.Unqueried) != 1 || current.Warnings[0] != p.Warnings[0] {
			t.Fatal(current)
		}
		changes := Changes(previous.Report, current)
		kind := "added"
		if len(current.Records) == 0 {
			kind = "no_longer_observed"
		}
		if !hasChange(changes, kind, "osv:GHSA-example") {
			t.Fatal(changes)
		}
		if err := Save(path, State{SchemaVersion: SchemaVersion, Profile: previous.Profile, Report: current}); err != nil {
			t.Fatal(err)
		}
		saved, err := Load(path)
		if err != nil || !saved.Report.RefreshComplete || saved.Report.Status != "incomplete" || !reflect.DeepEqual(saved.Profile, p) {
			t.Fatal(saved, err)
		}
	}
	// Query removals also use refresh completeness rather than coverage status.
	previous := initial.Report
	current := Run(context.Background(), domain.RepositoryProfile{Repository: p.Repository, Warnings: p.Warnings}, Config{})
	if !current.RefreshComplete || current.Status != "incomplete" || !hasChange(Changes(previous, current), "query_changed", "query:"+queryKey(previous.Queries[0].Query)) {
		t.Fatal(current)
	}
	current.RefreshComplete = false
	if len(Changes(previous, current)) != 0 {
		t.Fatal("incomplete refresh reported a removed query")
	}
}

func TestRefreshFailuresPreserveBaseline(t *testing.T) {
	p := coverageProfile()
	base := State{SchemaVersion: SchemaVersion, Profile: p, Report: Run(context.Background(), p, Config{OSV: positiveOSV()})}
	for _, mode := range []string{"query", "pagination", "detail", "nvd", "nvd_identity", "cancelled", "missing_client", "invalid_interval", "discrepancy"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := Save(path, base); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			f := positiveOSV()
			ctx := context.Background()
			cfg := Config{}
			switch mode {
			case "query", "pagination":
				f.query = func(_ context.Context, qs []osv.PackageVersion) []osv.QueryResult {
					r := osv.QueryResult{Query: qs[0], Error: "HTTP failure"}
					if mode == "pagination" {
						r.IDs = []string{"GHSA-example"}
					}
					return []osv.QueryResult{r}
				}
			case "detail":
				f.detail = func(context.Context, string) (json.RawMessage, error) { return nil, errors.New("detail failed") }
			case "nvd":
				cfg.NVD = fakeNVD(func(context.Context, string) (json.RawMessage, error) { return nil, errors.New("NVD failed") })
			case "nvd_identity":
				cfg.NVD = fakeNVD(func(context.Context, string) (json.RawMessage, error) {
					return json.RawMessage(`{"id":"CVE-2026-99999"}`), nil
				})
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "invalid_interval":
				cfg.NVDInterval = -1
			case "discrepancy":
				f.detail = func(context.Context, string) (json.RawMessage, error) {
					return json.RawMessage(`{"id":"GHSA-example","affected":[]}`), nil
				}
			}
			if mode != "missing_client" {
				cfg.OSV = f
			}
			current := Run(ctx, p, cfg)
			if current.RefreshComplete || current.Status != "incomplete" {
				t.Fatal(current)
			}
			state := State{SchemaVersion: SchemaVersion, Profile: p, Report: current}
			if err := validateState(state); err != nil {
				t.Fatal("failed reports must remain valid for inspection", err)
			}
			if err := Save(path, state); err == nil {
				t.Fatal("advanced failed refresh")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(before) != string(after) {
				t.Fatal("baseline changed", err)
			}
			for _, change := range Changes(base.Report, current) {
				if change.Kind == "no_longer_observed" {
					t.Fatal(change)
				}
			}
			if mode != "invalid_interval" {
				state.Report.RefreshComplete = true
				if err := validateState(state); err == nil {
					t.Fatal("accepted false refresh completion")
				}
			}
		})
	}
}

func TestChangesSuppressUncheckedNVD(t *testing.T) {
	p := coverageProfile()
	found := fakeNVD(func(_ context.Context, id string) (json.RawMessage, error) {
		return json.RawMessage(`{"id":"` + id + `"}`), nil
	})
	previous := Run(context.Background(), p, Config{OSV: positiveOSV(), NVD: found})
	for _, f := range []fakeOSV{positiveOSV(), emptyOSV()} {
		current := Run(context.Background(), p, Config{OSV: f})
		if !current.RefreshComplete {
			t.Fatal(current)
		}
		if hasChange(Changes(previous, current), "no_longer_observed", "nvd:CVE-2026-12345") {
			t.Fatal("disabled NVD appeared to disappear")
		}
		if len(current.Records) == 0 && !hasChange(Changes(previous, current), "no_longer_observed", "osv:GHSA-example") {
			t.Fatal("NVD opt-out suppressed OSV removal")
		}
	}
	missing := fakeNVD(func(context.Context, string) (json.RawMessage, error) { return nil, nvd.ErrCVENotFound })
	current := Run(context.Background(), p, Config{OSV: positiveOSV(), NVD: missing})
	if !current.RefreshComplete || !hasChange(Changes(previous, current), "no_longer_observed", "nvd:CVE-2026-12345") {
		t.Fatal(current)
	}
	// Even mixed per-ID states must conservatively honor a source opt-out.
	current.Enrichment = append(current.Enrichment, EnrichmentResult{Source: "nvd", ID: "CVE-2026-99999", Status: "not_checked"})
	if hasChange(Changes(previous, current), "no_longer_observed", "nvd:CVE-2026-12345") {
		t.Fatal("ignored source not_checked")
	}
}

func TestPlanExcludesUnsupportedAndUnverifiedWithoutBatchPoisoning(t *testing.T) {
	p := profile()
	p.Components = append(p.Components,
		domain.Component{ID: "pod", Ecosystem: "CocoaPods", Name: "AFNetworking", Version: "4.0.1", SourcePath: "Podfile.lock"},
		domain.Component{ID: "nuget-lower", Ecosystem: "nuget", Name: "newtonsoft.json", Version: "13.0.1", SourcePath: "packages.lock.json", Scope: "runtime"},
		domain.Component{ID: "nuget-case", Ecosystem: "NuGet", Name: "Newtonsoft.Json", Version: "13.0.1", SourcePath: "other/packages.lock.json"},
		domain.Component{ID: "maven", Ecosystem: "maven", Namespace: "org.example", Name: "pkg", Version: "1.0", SourcePath: "pom.xml"},
		domain.Component{ID: "php", Ecosystem: "packagist", Name: "vendor/pkg", Version: "1.0.0", SourcePath: "composer.lock"})
	other := p.Components[0]
	other.ID = "second-version"
	other.Version = "2.0.0"
	p.Components = append(p.Components, other)
	duplicate := p.Components[0]
	duplicate.ID = "second-origin"
	duplicate.SourcePath = "nested/package-lock.json"
	p.Components = append(p.Components, duplicate)
	plan := Plan(p)
	want := []osv.PackageVersion{{Ecosystem: "Maven", Name: "org.example:pkg", Version: "1.0"}, {Ecosystem: "Packagist", Name: "vendor/pkg", Version: "1.0.0"}, {Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}, {Ecosystem: "npm", Name: "pkg", Version: "2.0.0"}}
	got := []osv.PackageVersion{}
	for _, q := range plan.Queries {
		got = append(got, q.Query)
	}
	if !reflect.DeepEqual(got, want) || len(plan.Unqueried) != 3 || len(plan.Queries[2].Origins) != 2 {
		t.Fatal(plan)
	}
	for i, u := range plan.Unqueried {
		reason := "OSV canonical package identity unavailable"
		if i == 0 {
			reason = "unsupported ecosystem"
		}
		if u.Reason != reason || u.Component != p.Components[i+1] {
			t.Fatal(u)
		}
	}
	reversed := p
	reversed.Components = append([]domain.Component(nil), p.Components...)
	for i, j := 0, len(reversed.Components)-1; i < j; i, j = i+1, j-1 {
		reversed.Components[i], reversed.Components[j] = reversed.Components[j], reversed.Components[i]
	}
	if !reflect.DeepEqual(plan.Queries, Plan(reversed).Queries) {
		t.Fatal("query grouping depends on inventory order")
	}
	batches := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		batches++
		if r.URL.Path != "/v1/querybatch" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			http.Error(w, "unexpected", 400)
			return
		}
		var body struct {
			Queries []struct {
				Package struct{ Ecosystem, Name string }
				Version string
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			http.Error(w, "bad request", 400)
			return
		}
		for _, q := range body.Queries {
			if q.Package.Ecosystem == "CocoaPods" || q.Package.Ecosystem == "NuGet" {
				t.Error("unsafe component poisoned batch")
				http.Error(w, "unsupported", 400)
				return
			}
		}
		if len(body.Queries) != len(want) {
			t.Errorf("query count %d", len(body.Queries))
		}
		fmt.Fprint(w, `{"results":[{},{},{},{}]}`)
	}))
	defer server.Close()
	client, err := osv.NewDiscoveryClient(osv.DiscoveryConfig{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	report := Run(context.Background(), p, Config{OSV: client})
	if !report.RefreshComplete || report.Status != "incomplete" || batches != 1 || len(report.Unqueried) != 3 {
		t.Fatal(report, batches)
	}
	for _, q := range report.Queries {
		if !q.Complete || q.Outcome != "no_advisory_found" {
			t.Fatal(q)
		}
	}
	p.Components = p.Components[1:4]
	report = Run(context.Background(), p, Config{OSV: client})
	if !report.RefreshComplete || len(report.Queries) != 0 || batches != 1 {
		t.Fatal("unqueried-only inventory sent a batch", report, batches)
	}
}

func TestDetailMismatchHasReasonAndBlocksRefresh(t *testing.T) {
	for _, affected := range []string{`[]`, `[{"package":{"ecosystem":"npm","name":"other"}}]`, `[{"package":{"ecosystem":"PyPI","name":"pkg"}}]`} {
		raw := json.RawMessage(`{"id":"GHSA-example","affected":` + affected + `}`)
		f := positiveOSV()
		f.detail = func(context.Context, string) (json.RawMessage, error) { return raw, nil }
		p := profile()
		r := Run(context.Background(), p, Config{OSV: f})
		q := r.Queries[0]
		m := q.Matches[0]
		if r.RefreshComplete || q.Complete || r.Status != "incomplete" || q.Outcome != "unknown" || m.Outcome != "unknown" || m.Reason == "" || !strings.Contains(q.Error, m.Reason) {
			t.Fatal(r)
		}
		if !strings.Contains(strings.Join(r.Warnings, "\n"), m.Reason) || string(r.Records[m.RecordKey].Raw) != string(raw) {
			t.Fatal("discrepancy lost provenance", r)
		}
		s := State{SchemaVersion: SchemaVersion, Profile: p, Report: r}
		path := filepath.Join(t.TempDir(), "mismatch.json")
		if err := Save(path, s); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err != nil {
			t.Fatal(err)
		}
		s.Report.Queries[0].Matches[0].Reason = ""
		if err := validateState(s); err == nil {
			t.Fatal("accepted missing discrepancy reason")
		}
	}
}

func TestLegacyRefreshFlagIsConservative(t *testing.T) {
	p := profile()
	s := State{SchemaVersion: SchemaVersion, Profile: p, Report: Run(context.Background(), p, Config{OSV: emptyOSV()})}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `"refresh_complete":true,`, "", 1))
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	legacy, err := Load(path)
	if err != nil || legacy.Report.RefreshComplete {
		t.Fatal(legacy, err)
	}
	if err := Save(path, s); err != nil {
		t.Fatal("fresh refresh could not advance legacy baseline", err)
	}
}
