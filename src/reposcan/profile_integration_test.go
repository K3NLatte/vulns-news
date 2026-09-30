package reposcan_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/nvd"
	"vulns-news/src/osv"
	"vulns-news/src/reposcan"
	"vulns-news/src/repository"
)

func TestProfileIntegrationDiscoveryAndState(t *testing.T) {
	root := t.TempDir()
	for path, body := range map[string]string{
		"node/package-lock.json": `{"name":"web","lockfileVersion":3,"packages":{
			"node_modules/shared-lib":{"version":"1.0.0"},
			"node_modules/parent/node_modules/shared-lib":{"version":"2.0.0"},
			"node_modules/other-lib":{"version":"1.0.0"}
		}}`,
		"tests/pnpm-lock.yaml":    "lockfileVersion: '9.0'\npackages:\n  shared-lib@1.0.0:\n    resolution: {integrity: sha512-example}\n",
		"python/requirements.txt": "Shared_Lib==1.0.0\nflask>=3\n",
		"python/poetry.lock":      "[metadata]\nlock-version = '2.0'\n[[package]]\nname = 'Shared.Lib'\nversion = '1.0.0'\n",
		"go/go.mod":               "module example.org/app\ngo 1.25\nrequire example.org/library v1.2.3\n",
		"java/pom.xml":            `<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>app</artifactId><version>1.0</version><dependencies><dependency><groupId>org.example</groupId><artifactId>shared-lib</artifactId><version>1.0.0</version></dependency></dependencies></project>`,
		"rust/Cargo.lock":         "version = 3\n[[package]]\nname = 'serde'\nversion = '1.0.200'\nsource = 'registry+https://github.com/rust-lang/crates.io-index'\n",
		"ios/Podfile.lock":        "PODS:\n  - Public/Core (1.2.3)\nSPEC REPOS:\n  trunk:\n    - Public\n",
		"ios/Podfile":             "raise 'dependency manifests must not execute'\n",
		"node/index.js":           "export const ready = true;\n",
		"python/main.py":          "import shared_lib\n",
		"go/main.go":              "package api\nimport dep \"example.org/library\"\nfunc serve() { dep.Run() }\n",
		"java/Main.java":          "class Main {}\n",
		"rust/main.rs":            "fn main() {}\n",
	} {
		name := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}

	identity := domain.RepositoryIdentity{
		ID: "example/polyglot", CanonicalURL: "https://example.test/polyglot",
		Ref: "integration", CommitSHA: "0123456789abcdef0123456789abcdef01234567",
	}
	at := time.Date(2026, 9, 26, 12, 0, 0, 0, time.FixedZone("JST", 9*60*60))
	profile, err := repository.Profile(&repository.AcquiredRepository{Path: root, Identity: identity}, at)
	if err != nil {
		t.Fatalf("extract repository profile: %v", err)
	}
	if profile.Repository != identity || profile.ProfiledAt != at.UTC() {
		t.Fatalf("extraction lost snapshot identity/time: %+v / %v", profile.Repository, profile.ProfiledAt)
	}
	if len(profile.Components) != 11 {
		t.Fatalf("extracted %d components, want 11: %+v", len(profile.Components), profile.Components)
	}
	components := make(map[string]domain.Component)
	for _, c := range profile.Components {
		if _, exists := components[c.ID]; c.ID == "" || exists || c.PURL == "" {
			t.Fatalf("missing/duplicate extracted identity: %+v", c)
		}
		components[c.ID] = c
	}
	for language, path := range map[string]string{
		"JavaScript": "node/index.js", "Python": "python/main.py", "Go": "go/main.go",
		"Java": "java/Main.java", "Rust": "rust/main.rs",
	} {
		if !slices.ContainsFunc(profile.Languages, func(l domain.LanguageUsage) bool {
			return l.Name == language && slices.Contains(l.SourcePaths, path)
		}) {
			t.Errorf("missing extracted %s source %s: %+v", language, path, profile.Languages)
		}
	}
	if !slices.ContainsFunc(profile.SourceObservations, func(o domain.SourceObservation) bool {
		return o.Kind == "imported_selector_call" && o.File == "go/main.go" && o.Package == "example.org/library" && o.Symbol == "Run"
	}) {
		t.Errorf("missing Go source observation: %+v", profile.SourceObservations)
	}
	for _, warning := range []string{"python/requirements.txt:2:", "ios/Podfile: unsupported dependency format"} {
		if !strings.Contains(strings.Join(profile.Warnings, "\n"), warning) {
			t.Errorf("missing extracted warning %q: %v", warning, profile.Warnings)
		}
	}

	// These expectations come from the files, not Plan: every identity dimension
	// must survive extraction and batching without merging unrelated evidence.
	type expectedQuery struct {
		paths []string
		id    string
		fixes []string
	}
	wantQueries := map[osv.PackageVersion]expectedQuery{
		{Ecosystem: "npm", Name: "shared-lib", Version: "1.0.0"}: {
			paths: []string{"node/package-lock.json", "tests/pnpm-lock.yaml"}, id: "GHSA-shared", fixes: []string{"3.0.0"},
		},
		{Ecosystem: "npm", Name: "shared-lib", Version: "2.0.0"}: {
			paths: []string{"node/package-lock.json"}, id: "GHSA-shared", fixes: []string{"3.0.0"},
		},
		{Ecosystem: "npm", Name: "other-lib", Version: "1.0.0"}: {paths: []string{"node/package-lock.json"}},
		{Ecosystem: "PyPI", Name: "shared-lib", Version: "1.0.0"}: {
			paths: []string{"python/poetry.lock", "python/requirements.txt"}, id: "PYSEC-shared", fixes: []string{"1.1.0"},
		},
		{Ecosystem: "Go", Name: "example.org/library", Version: "v1.2.3"}:      {paths: []string{"go/go.mod"}},
		{Ecosystem: "Maven", Name: "org.example:shared-lib", Version: "1.0.0"}: {paths: []string{"java/pom.xml"}},
		{Ecosystem: "crates.io", Name: "serde", Version: "1.0.200"}: {
			paths: []string{"rust/Cargo.lock"}, id: "RUSTSEC-2026-0001", fixes: []string{},
		},
	}
	advisories := map[string]string{
		"GHSA-shared":       `{"id":"GHSA-shared","aliases":["PYSEC-shared","CVE-2026-12345","CVE-2026-12345"],"affected":[{"package":{"ecosystem":"npm","name":"shared-lib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"3.0.0"}]}]},{"package":{"ecosystem":"npm","name":"other-lib"},"ranges":[{"events":[{"fixed":"99.0.0"}]}]}],"provider_extra":{"revision":9007199254740993,"provenance":"npm registry"}}`,
		"PYSEC-shared":      `{"id":"PYSEC-shared","aliases":["GHSA-shared","CVE-2026-12345"],"affected":[{"package":{"ecosystem":"PyPI","name":"shared-lib"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.1.0"}]}]}],"provider_extra":{"provenance":"Python registry"}}`,
		"RUSTSEC-2026-0001": `{"id":"RUSTSEC-2026-0001","aliases":[],"affected":[{"package":{"ecosystem":"crates.io","name":"serde"}}],"provider_extra":{"without_cve":true}}`,
	}
	const nvdRaw = `{"id":"CVE-2026-12345","vulnStatus":"Received","descriptions":[{"lang":"en","value":"Shared alias metadata"}],"configurations":[],"provider_extra":{"revision":9007199254740993,"provenance":"NVD"}}`
	var mu sync.Mutex
	wireQueries := make(map[osv.PackageVersion]int)
	detailCalls := make(map[string]int)
	batchCalls, nvdCalls := 0, 0
	failBatch := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/querybatch":
			batchCalls++
			if r.Method != http.MethodPost {
				t.Errorf("OSV batch method = %s, want POST", r.Method)
				http.Error(w, "wrong method", http.StatusMethodNotAllowed)
				return
			}
			if failBatch {
				http.Error(w, "mock discovery unavailable", http.StatusServiceUnavailable)
				return
			}
			var body struct {
				Queries []struct {
					Package struct {
						Ecosystem string `json:"ecosystem"`
						Name      string `json:"name"`
					} `json:"package"`
					Version string `json:"version"`
				} `json:"queries"`
			}
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&body); err != nil {
				t.Errorf("decode OSV request: %v", err)
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			if len(body.Queries) == 0 || len(body.Queries) > 2 {
				t.Errorf("OSV batch size = %d, want 1..2", len(body.Queries))
			}
			results := make([]any, len(body.Queries))
			for i, q := range body.Queries {
				key := osv.PackageVersion{Ecosystem: q.Package.Ecosystem, Name: q.Package.Name, Version: q.Version}
				wireQueries[key]++
				want, ok := wantQueries[key]
				if !ok {
					t.Errorf("unexpected wire query (unsupported/unresolved or incorrect identity): %+v", key)
				}
				results[i] = map[string]any{}
				if want.id != "" {
					results[i] = map[string]any{"vulns": []map[string]string{{"id": want.id}}}
				}
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"results": results}); err != nil {
				t.Errorf("write OSV batch response: %v", err)
			}
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			detailCalls[id]++
			raw, ok := advisories[id]
			if r.Method != http.MethodGet || !ok {
				t.Errorf("unexpected advisory request: %s %s", r.Method, r.URL)
				http.NotFound(w, r)
				return
			}
			fmt.Fprint(w, raw)
		case r.URL.Path == "/nvd":
			nvdCalls++
			if r.Method != http.MethodGet || r.URL.RawQuery != "cveId=CVE-2026-12345" {
				t.Errorf("NVD must use exact CVE lookup only: %s %s", r.Method, r.URL)
				http.Error(w, "not an exact lookup", http.StatusBadRequest)
				return
			}
			fmt.Fprintf(w, `{"totalResults":1,"resultsPerPage":1,"startIndex":0,"vulnerabilities":[{"cve":%s}]}`, nvdRaw)
		default:
			t.Errorf("unexpected HTTP request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = 5 * time.Second
	discovery, err := osv.NewDiscoveryClient(osv.DiscoveryConfig{BaseURL: server.URL, HTTPClient: httpClient, BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	nvdClient, err := nvd.NewAnalysisClient(nvd.Config{BaseURL: server.URL + "/nvd", HTTPClient: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	cfg := reposcan.Config{OSV: discovery, NVD: nvdClient}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	report := reposcan.Run(ctx, profile, cfg)
	if report.Repository != identity || report.Acquisition != "complete" || report.Status != "incomplete" || !report.RefreshComplete || report.RuntimeImpact != "unknown" {
		t.Fatalf("coverage uncertainty must not become an operational failure or a clean scan: %+v", report)
	}
	mu.Lock()
	if batchCalls != 4 || nvdCalls != 1 || len(wireQueries) != len(wantQueries) || len(detailCalls) != len(advisories) {
		t.Errorf("HTTP calls: batches=%d NVD=%d queries=%v details=%v", batchCalls, nvdCalls, wireQueries, detailCalls)
	}
	for q := range wantQueries {
		if wireQueries[q] != 1 {
			t.Errorf("wire query %+v sent %d times, want exactly once across all origins", q, wireQueries[q])
		}
	}
	for id := range advisories {
		if detailCalls[id] != 1 {
			t.Errorf("advisory %s fetched %d times, want once across versions", id, detailCalls[id])
		}
	}
	mu.Unlock()

	if len(report.Queries) != len(wantQueries) {
		t.Fatalf("reported queries = %+v, want %d distinct identities", report.Queries, len(wantQueries))
	}
	seenQueries := make(map[osv.PackageVersion]bool)
	seenOrigins := make(map[string]int)
	checkOrigin := func(c domain.Component) {
		t.Helper()
		if original, ok := components[c.ID]; !ok || original != c {
			t.Errorf("origin differs from extracted component: %+v", c)
		}
		seenOrigins[c.ID]++
	}
	for _, q := range report.Queries {
		want, ok := wantQueries[q.Query]
		if !ok || seenQueries[q.Query] {
			t.Errorf("unexpected/duplicate reported query: %+v", q)
			continue
		}
		seenQueries[q.Query] = true
		if !q.Complete || q.Error != "" || q.RuntimeImpact != "unknown" || q.Workspace != "unavailable" || q.DependencyPath != "unavailable" {
			t.Errorf("incorrect query completeness/provenance limits: %+v", q)
		}
		originEcosystem := q.Query.Ecosystem
		switch originEcosystem {
		case "PyPI":
			originEcosystem = "pypi"
		case "Maven":
			originEcosystem = "maven"
		}
		paths := make([]string, 0, len(q.Origins))
		for _, c := range q.Origins {
			checkOrigin(c)
			if c.Ecosystem != originEcosystem || c.Name != q.Query.Name || c.Version != q.Query.Version {
				t.Errorf("origin %+v attached to wrong query %+v", c, q.Query)
			}
			paths = append(paths, c.SourcePath)
		}
		slices.Sort(paths)
		if !reflect.DeepEqual(paths, want.paths) {
			t.Errorf("origins for %+v = %v, want %v", q.Query, paths, want.paths)
		}
		if want.id == "" {
			if q.Outcome != "no_advisory_found" || len(q.IDs) != 0 || len(q.Matches) != 0 {
				t.Errorf("evidence crossed ecosystem/name/version identity: %+v", q)
			}
		} else {
			matches := []reposcan.Match{{RecordKey: "osv:" + want.id, Outcome: "affected_version_match", FixedVersions: want.fixes}}
			if q.Outcome != "affected_version_match" || !reflect.DeepEqual(q.IDs, []string{want.id}) || !reflect.DeepEqual(q.Matches, matches) {
				t.Errorf("wrong package-specific advisory/fix evidence: %+v; want %+v", q, matches)
			}
		}
	}
	if len(report.Unqueried) != 2 {
		t.Fatalf("unqueried = %+v, want unresolved Python and unsupported CocoaPods", report.Unqueried)
	}
	for _, u := range report.Unqueried {
		checkOrigin(u.Component)
		c := u.Component
		switch {
		case c.Ecosystem == "pypi" && c.Name == "flask" && c.Version == "" && c.SourcePath == "python/requirements.txt" && u.Reason == "unresolved version":
		case c.Ecosystem == "CocoaPods" && c.Name == "Public/Core" && c.Version == "1.2.3" && c.SourcePath == "ios/Podfile.lock" && u.Reason == "unsupported ecosystem":
		default:
			t.Errorf("lost unqueried identity or reason: %+v", u)
		}
	}
	for id, c := range components {
		if seenOrigins[id] != 1 {
			t.Errorf("extracted component appears %d times in report, want once: %+v", seenOrigins[id], c)
		}
	}
	for _, warning := range profile.Warnings {
		if !slices.Contains(report.Warnings, warning) {
			t.Errorf("report lost profile warning %q", warning)
		}
	}

	wantRecords := map[string]reposcan.SourceRecord{
		"osv:GHSA-shared":       {Source: "osv", ID: "GHSA-shared", Aliases: []string{"CVE-2026-12345", "PYSEC-shared"}, Raw: json.RawMessage(advisories["GHSA-shared"])},
		"osv:PYSEC-shared":      {Source: "osv", ID: "PYSEC-shared", Aliases: []string{"CVE-2026-12345", "GHSA-shared"}, Raw: json.RawMessage(advisories["PYSEC-shared"])},
		"osv:RUSTSEC-2026-0001": {Source: "osv", ID: "RUSTSEC-2026-0001", Aliases: []string{}, Raw: json.RawMessage(advisories["RUSTSEC-2026-0001"])},
		"nvd:CVE-2026-12345":    {Source: "nvd", ID: "CVE-2026-12345", Aliases: []string{}, Raw: json.RawMessage(nvdRaw)},
	}
	assertProfileIntegrationJSON(t, "raw records, aliases and provider provenance", report.Records, wantRecords)
	wantGroups := []reposcan.AdvisoryGroup{
		{IDs: []string{"CVE-2026-12345", "GHSA-shared", "PYSEC-shared"}, RecordKeys: []string{"nvd:CVE-2026-12345", "osv:GHSA-shared", "osv:PYSEC-shared"}, RuntimeImpact: "unknown"},
		{IDs: []string{"RUSTSEC-2026-0001"}, RecordKeys: []string{"osv:RUSTSEC-2026-0001"}, RuntimeImpact: "unknown"},
	}
	if !reflect.DeepEqual(report.Groups, wantGroups) {
		t.Errorf("alias grouping lost source records or CVE-free advisory: %+v", report.Groups)
	}
	if !reflect.DeepEqual(report.Enrichment, []reposcan.EnrichmentResult{{Source: "nvd", ID: "CVE-2026-12345", Status: "found"}}) {
		t.Errorf("shared CVE enrichment = %+v", report.Enrichment)
	}

	state := reposcan.State{SchemaVersion: reposcan.SchemaVersion, Profile: profile, Report: report}
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := reposcan.Save(statePath, state); err != nil {
		t.Fatalf("save extracted snapshot: %v", err)
	}
	loaded, err := reposcan.Load(statePath)
	if err != nil {
		t.Fatalf("load extracted snapshot: %v", err)
	}
	if !reflect.DeepEqual(loaded.Profile, profile) || loaded.Profile.Repository.CommitSHA != identity.CommitSHA || loaded.Report.Repository != identity {
		t.Errorf("state round trip changed extracted profile or commit SHA: %+v", loaded.Profile)
	}
	assertProfileIntegrationJSON(t, "persisted raw provider records", loaded.Report.Records, wantRecords)
	assertProfileIntegrationJSON(t, "entire persisted snapshot", loaded, state)

	t.Run("failed HTTP refresh preserves extracted baseline", func(t *testing.T) {
		before, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		failBatch = true
		mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		failed := reposcan.Run(ctx, loaded.Profile, cfg)
		if failed.RefreshComplete || failed.Status != "incomplete" || len(failed.Queries) != len(wantQueries) {
			t.Fatalf("failed discovery reported as a completed refresh: %+v", failed)
		}
		for _, q := range failed.Queries {
			if q.Complete || q.Outcome != "unknown" || !strings.Contains(q.Error, "503") {
				t.Errorf("HTTP failure became negative evidence: %+v", q)
			}
		}
		if !reflect.DeepEqual(failed.Unqueried, report.Unqueried) {
			t.Errorf("failed refresh lost unqueried inventory: %+v", failed.Unqueried)
		}
		failedState := reposcan.State{SchemaVersion: reposcan.SchemaVersion, Profile: loaded.Profile, Report: failed}
		if err := reposcan.Save(statePath, failedState); err == nil || !strings.Contains(err.Error(), "incomplete refresh") {
			t.Fatalf("save failed refresh error = %v, want baseline protection", err)
		}
		after, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("failed refresh changed saved baseline")
		}
		unchanged, err := reposcan.Load(statePath)
		if err != nil {
			t.Fatal(err)
		}
		assertProfileIntegrationJSON(t, "baseline after failed refresh", unchanged, state)
	})
}

func assertProfileIntegrationJSON(t *testing.T, label string, got, want any) {
	t.Helper()
	// Marshal compacts RawMessage whitespace introduced by Save's indentation
	// without decoding through float64 and losing unknown large numeric values.
	actual, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal %s: %v", label, err)
	}
	expected, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal expected %s: %v", label, err)
	}
	if !bytes.Equal(actual, expected) {
		t.Errorf("%s:\ngot  %s\nwant %s", label, actual, expected)
	}
}
