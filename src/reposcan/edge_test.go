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
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/nvd"
	"vulns-news/src/osv"
)

func TestPlanRejectsEmptyAndConflictingNames(t *testing.T) {
	for _, c := range []domain.Component{
		{Ecosystem: "npm", Namespace: "@scope", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "bad\tname", Version: "1.0.0"},
		{Ecosystem: "Maven", Namespace: "wrong", Name: "group:artifact", Version: "1.0"},
		{Ecosystem: "Packagist", Namespace: "wrong", Name: "vendor/pkg", Version: "1.0.0"},
	} {
		p := profile()
		p.Components = []domain.Component{c}
		got := Plan(p)
		if len(got.Queries) != 0 || len(got.Unqueried) != 1 || got.Unqueried[0].Reason != "invalid/ambiguous identity" {
			t.Fatal(got)
		}
	}
}

func TestHTTPPartialDiscoveryAndDetailFailure(t *testing.T) {
	for _, mode := range []string{"pagination", "detail", "empty", "http_error"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/querybatch":
					switch mode {
					case "pagination":
						fmt.Fprint(w, `{"results":[{"vulns":[{"id":"GHSA-example"}],"next_page_token":"more"}]}`)
					case "empty":
						fmt.Fprint(w, `{"results":[{}]}`)
					case "http_error":
						http.Error(w, "unavailable", 503)
					default:
						fmt.Fprint(w, `{"results":[{"vulns":[{"id":"GHSA-example"}]}]}`)
					}
				default:
					if mode == "detail" {
						http.Error(w, "unavailable", 503)
					} else {
						fmt.Fprint(w, rawAdvisory)
					}
				}
			}))
			defer server.Close()
			client, err := osv.NewDiscoveryClient(osv.DiscoveryConfig{BaseURL: server.URL, HTTPClient: server.Client(), MaxPages: 1})
			if err != nil {
				t.Fatal(err)
			}
			r := Run(context.Background(), profile(), Config{OSV: client})
			switch mode {
			case "empty":
				if r.Status != "complete" || r.Queries[0].Outcome != "no_advisory_found" {
					t.Fatal(r)
				}
			case "pagination":
				if r.Status != "incomplete" || r.Queries[0].Outcome != "affected_version_match" || len(r.Records) != 1 {
					t.Fatal(r)
				}
			default:
				if r.Status != "incomplete" || r.Queries[0].Outcome != "unknown" || r.Queries[0].Error == "" {
					t.Fatal(r)
				}
			}
		})
	}
}

func TestHTTPNVDNotFoundAndError(t *testing.T) {
	for _, code := range []int{200, 429} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("cveId") != "CVE-2026-12345" {
					t.Error("wrong ID")
				}
				w.WriteHeader(code)
				fmt.Fprint(w, `{"totalResults":0,"vulnerabilities":[]}`)
			}))
			defer server.Close()
			client, err := nvd.NewClient(nvd.Config{BaseURL: server.URL, HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			r := Run(context.Background(), profile(), Config{OSV: positiveOSV(), NVD: client})
			if code == 200 {
				if r.Status != "complete" || r.Enrichment[0].Status != "not_found" {
					t.Fatal(r)
				}
			} else if r.Status != "incomplete" || r.Enrichment[0].Status != "error" {
				t.Fatal(r)
			}
		})
	}
}

func TestNVDPacingSortedUniqueAndExplicitOnly(t *testing.T) {
	f := positiveOSV()
	f.detail = func(context.Context, string) (json.RawMessage, error) {
		return json.RawMessage(strings.Replace(rawAdvisory, `"CVE-2026-12345"`, `"CVE-2026-99999","CVE-2026-12345","CVE-2026-99999","GHSA-other"`, 1)), nil
	}
	var calls []string
	var times []time.Time
	client := fakeNVD(func(_ context.Context, id string) (json.RawMessage, error) {
		calls = append(calls, id)
		times = append(times, time.Now())
		return nil, nvd.ErrCVENotFound
	})
	interval := 20 * time.Millisecond
	r := Run(context.Background(), profile(), Config{OSV: f, NVD: client, NVDInterval: interval})
	if !reflect.DeepEqual(calls, []string{"CVE-2026-12345", "CVE-2026-99999"}) || len(times) != 2 || times[1].Sub(times[0]) < interval || r.Status != "complete" {
		t.Fatal(calls, times, r)
	}
	calls = nil
	r = Run(context.Background(), profile(), Config{OSV: f, NVD: client, NVDInterval: -1})
	if len(calls) != 0 || r.Status != "incomplete" {
		t.Fatal("invalid pacing triggered requests", r)
	}
}

func TestGroupsTransitiveAliasesNotDescriptions(t *testing.T) {
	records := map[string]SourceRecord{
		"osv:GHSA-one":       {Source: "osv", ID: "GHSA-one", Aliases: []string{"CVE-2026-12345"}},
		"osv:ALT":            {Source: "osv", ID: "ALT", Aliases: []string{"GHSA-one", "CVE-2026-99999"}},
		"nvd:CVE-2026-12345": {Source: "nvd", ID: "CVE-2026-12345"},
		"osv:GHSA-only":      {Source: "osv", ID: "GHSA-only"},
	}
	groups := groupRecords(records)
	if len(groups) != 2 {
		t.Fatal(groups)
	}
	for _, g := range groups {
		if len(g.RecordKeys) == 3 && len(g.IDs) != 4 {
			t.Fatal(g)
		}
		if len(g.RecordKeys) == 1 && !reflect.DeepEqual(g.IDs, []string{"GHSA-only"}) {
			t.Fatal(g)
		}
	}
}

func TestQueryContractAndCancelledRun(t *testing.T) {
	for _, mode := range []string{"count", "identity", "invalid_id"} {
		t.Run(mode, func(t *testing.T) {
			f := emptyOSV()
			f.query = func(_ context.Context, q []osv.PackageVersion) []osv.QueryResult {
				if mode == "count" {
					return nil
				}
				result := osv.QueryResult{Query: q[0], Complete: true}
				if mode == "identity" {
					result.Query.Version = "9.0.0"
				}
				if mode == "invalid_id" {
					result.IDs = []string{""}
				}
				return []osv.QueryResult{result}
			}
			r := Run(context.Background(), profile(), Config{OSV: f})
			if r.Status != "incomplete" || r.Queries[0].Outcome != "unknown" {
				t.Fatal(r)
			}
		})
	}
	f := emptyOSV()
	f.query = func(context.Context, []osv.PackageVersion) []osv.QueryResult {
		t.Fatal("called on cancelled context")
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Run(ctx, profile(), Config{OSV: f})
	if r.Queries[0].Error != context.Canceled.Error() {
		t.Fatal(r)
	}
}

func TestStateSemanticCorruptionAndAtomicReplacement(t *testing.T) {
	p := profile()
	base := State{SchemaVersion: SchemaVersion, Profile: p, Report: Run(context.Background(), p, Config{OSV: positiveOSV()})}
	for _, mutate := range []func(*State){
		func(s *State) { s.Report.Repository.CommitSHA = "different" },
		func(s *State) { s.Report.Queries[0].Origins[0].SourcePath = "wrong" },
		func(s *State) { s.Report.Queries[0].Matches[0].FixedVersions = []string{"99.0.0"} },
		func(s *State) { s.Report.Queries[0].Outcome = "safe" },
		func(s *State) { s.Report.Groups = nil },
		func(s *State) {
			s.Report.Records["osv:GHSA-example"] = SourceRecord{Source: "osv", ID: "GHSA-example", Raw: json.RawMessage(`null`)}
		},
	} {
		data, _ := json.Marshal(base)
		var s State
		json.Unmarshal(data, &s)
		mutate(&s)
		data, _ = json.Marshal(s)
		path := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("accepted inconsistent state")
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := Save(path, base); err != nil {
		t.Fatal(err)
	}
	// An open reader must retain the old inode/content across replacement.
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	oldInfo, _ := reader.Stat()
	next := base
	next.Report = Run(context.Background(), p, Config{OSV: emptyOSV()})
	if err := Save(path, next); err != nil {
		t.Fatal(err)
	}
	newInfo, _ := os.Stat(path)
	if os.SameFile(oldInfo, newInfo) {
		t.Fatal("state was truncated in place")
	}
	if newInfo.Mode().Perm() != 0600 {
		t.Fatal(newInfo.Mode())
	}
	fresh, err := Load(path)
	if err != nil || len(fresh.Report.Records) != 0 {
		t.Fatal(fresh, err)
	}
	if err := Save(filepath.Join(dir, "missing", "state.json"), base); err == nil {
		t.Fatal("expected destination error")
	}
	different := base
	different.Profile.Repository.ID = "other"
	different.Report.Repository = different.Profile.Repository
	if err := Save(path, different); err == nil {
		t.Fatal("replaced unrelated baseline")
	}
	if err := Save(dir, base); err == nil {
		t.Fatal("replaced directory")
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err == nil {
		if err = Save(link, base); err == nil {
			t.Fatal("followed destination symlink")
		}
	}
	if got, err := Load(filepath.Join(dir, "absent")); !errors.Is(err, os.ErrNotExist) || got.SchemaVersion != 0 {
		t.Fatal(got, err)
	}
}

func TestStateRetainsFullProfileAndInitialIncomplete(t *testing.T) {
	p := profile()
	p.Warnings = []string{"partial inventory"}
	p.Languages = []domain.LanguageUsage{{Name: "JavaScript", SourcePaths: []string{"src/a.js"}}}
	p.Components = append(p.Components, domain.Component{Ecosystem: "unknown", Name: "unknown"})
	p.SourceObservations = []domain.SourceObservation{{Kind: "import", File: "a.js", Line: 1, Package: "pkg"}}
	s := State{SchemaVersion: SchemaVersion, Profile: p, Report: Run(context.Background(), p, Config{OSV: emptyOSV()})}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, s); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || !reflect.DeepEqual(p, got.Profile) || got.Report.Status != "incomplete" {
		t.Fatal(got, err)
	}
}
