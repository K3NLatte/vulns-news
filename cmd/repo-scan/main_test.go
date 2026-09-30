package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vulns-news/src/domain"
	"vulns-news/src/reposcan"
)

func fixtureProfile(t *testing.T) string {
	t.Helper()
	p := domain.RepositoryProfile{
		Repository: domain.RepositoryIdentity{ID: "example/mixed", CommitSHA: strings.Repeat("a", 40)},
		Components: []domain.Component{
			{ID: "one", Ecosystem: "npm", Name: "widget", Version: "1.0.0", SourcePath: "pnpm-lock.yaml"},
			{ID: "two", Ecosystem: "npm", Name: "widget", Version: "1.0.0", SourcePath: "tests/pnpm-lock.yaml"},
			{ID: "rust", Ecosystem: "crates.io", Name: "serde", Version: "1.0.0", SourcePath: "Cargo.lock"},
			{ID: "python", Ecosystem: "PyPI", Name: "requests", SourcePath: "pyproject.toml"},
		},
		Warnings: []string{"syntactic observations only"},
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	b, _ := json.Marshal(map[string]any{"repository_profile": p})
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPlanRequiresNoServiceAndPreservesOrigins(t *testing.T) {
	var out, logs bytes.Buffer
	err := run(context.Background(), []string{"-profile", fixtureProfile(t), "-plan-only", "-osv-base-url", ":invalid"}, &out, &logs)
	if err != nil {
		t.Fatal(err)
	}
	var got result
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Plan.Queries) != 2 || len(got.Plan.Unqueried) != 1 || got.StateUpdate != "" {
		t.Fatalf("%+v", got)
	}
	for _, q := range got.Plan.Queries {
		if q.Query.Ecosystem == "npm" && len(q.Origins) != 2 {
			t.Fatal("lost source paths")
		}
	}
}

func TestInitialAndMonitorHTTPIntegration(t *testing.T) {
	phase, batches := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/querybatch":
			batches++
			var req struct {
				Queries []struct {
					Package struct {
						Name string `json:"name"`
					} `json:"package"`
				} `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			results := make([]any, len(req.Queries))
			for i, q := range req.Queries {
				results[i] = map[string]any{}
				if q.Package.Name == "widget" {
					results[i] = map[string]any{"vulns": []any{map[string]string{"id": "GHSA-example"}}}
				}
				if q.Package.Name == "serde" && phase > 0 {
					results[i] = map[string]any{"vulns": []any{map[string]string{"id": "RUSTSEC-example"}}}
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case "/v1/vulns/GHSA-example":
			fmt.Fprintf(w, `{"id":"GHSA-example","aliases":["CVE-2026-1234"],"summary":"revision %d","affected":[{"package":{"ecosystem":"npm","name":"widget"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`, phase)
		case "/v1/vulns/RUSTSEC-example":
			fmt.Fprint(w, `{"id":"RUSTSEC-example","aliases":[],"affected":[{"package":{"ecosystem":"crates.io","name":"serde"}}]}`)
		case "/nvd":
			if r.URL.Query().Get("cveId") != "CVE-2026-1234" {
				t.Errorf("not exact lookup: %s", r.URL)
			}
			fmt.Fprint(w, `{"totalResults":1,"resultsPerPage":1,"startIndex":0,"vulnerabilities":[{"cve":{"id":"CVE-2026-1234","vulnStatus":"Received","descriptions":[],"configurations":[]}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	state := filepath.Join(t.TempDir(), "state.json")
	args := []string{"-state", state, "-osv-base-url", srv.URL, "-nvd-base-url", srv.URL + "/nvd", "-batch-size", "1"}
	var out, logs bytes.Buffer
	if err := run(context.Background(), append(append([]string{}, args...), "-profile", fixtureProfile(t)), &out, &logs); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	var initial result
	if err := json.Unmarshal(out.Bytes(), &initial); err != nil {
		t.Fatal(err)
	}
	if initial.Report.Status != "incomplete" || !initial.Report.RefreshComplete || initial.StateUpdate != "after_output" || len(initial.Report.Groups) != 1 || len(initial.Report.Records) != 2 || batches != 2 {
		t.Fatalf("%+v batches=%d", initial, batches)
	}
	previous, err := reposcan.Load(state)
	if err != nil {
		t.Fatal(err)
	}
	phase = 1
	out.Reset()
	if err := run(context.Background(), append(args, "-monitor"), &out, &logs); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	var monitored result
	if err := json.Unmarshal(out.Bytes(), &monitored); err != nil {
		t.Fatal(err)
	}
	if monitored.StateUpdate != "after_output" || len(monitored.Report.Groups) != 2 || len(monitored.Changes) == 0 || batches != 4 {
		t.Fatalf("%+v", monitored)
	}
	next, err := reposcan.Load(state)
	if err != nil {
		t.Fatal(err)
	}
	if next.Profile.Repository.CommitSHA != previous.Profile.Repository.CommitSHA {
		t.Fatal("monitor changed snapshot")
	}
	if _, ok := next.Report.Records["osv:RUSTSEC-example"]; !ok {
		t.Fatal("lost CVE-free advisory")
	}

	out.Reset()
	if err := run(context.Background(), append(append([]string{}, args...), "-monitor", "-nvd=false"), &out, &logs); err != nil {
		t.Fatal(err)
	}
	var unchecked result
	if err := json.Unmarshal(out.Bytes(), &unchecked); err != nil {
		t.Fatal(err)
	}
	if _, ok := unchecked.Report.RetainedRecords["nvd:CVE-2026-1234"]; !ok {
		t.Fatal("unchecked NVD evidence not retained in output")
	}
	out.Reset()
	if err := run(context.Background(), append(args, "-monitor"), &out, &logs); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &monitored); err != nil {
		t.Fatal(err)
	}
	if len(monitored.Changes) != 0 {
		t.Fatalf("re-enabling unchanged NVD caused changes: %+v", monitored.Changes)
	}
}

func TestIncompleteMonitorDoesNotReplaceBaseline(t *testing.T) {
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "upstream unavailable", 503)
			return
		}
		fmt.Fprint(w, `{"results":[{},{}]}`)
	}))
	defer srv.Close()
	state := filepath.Join(t.TempDir(), "snapshot.json")
	args := []string{"-state", state, "-osv-base-url", srv.URL, "-nvd=false"}
	var out, logs bytes.Buffer
	if err := run(context.Background(), append(append([]string{}, args...), "-profile", fixtureProfile(t)), &out, &logs); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(state)
	fail = true
	out.Reset()
	if err := run(context.Background(), append(args, "-monitor"), &out, &logs); err == nil {
		t.Fatal("incomplete refresh succeeded")
	}
	after, _ := os.ReadFile(state)
	if !bytes.Equal(before, after) {
		t.Fatal("failed refresh replaced state")
	}
	var got result
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.StateUpdate != "skipped_incomplete_refresh" || got.Report.RefreshComplete || got.Report.Queries[0].Outcome == "no_advisory_found" {
		t.Fatalf("%+v", got)
	}
}

type failedOutput struct{}

func (failedOutput) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

func TestOutputFailureLeavesMonitoringChangesRetryable(t *testing.T) {
	positive := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/vulns/GHSA-example" {
			fmt.Fprint(w, `{"id":"GHSA-example","affected":[{"package":{"ecosystem":"npm","name":"widget"}}]}`)
			return
		}
		if positive {
			fmt.Fprint(w, `{"results":[{},{"vulns":[{"id":"GHSA-example"}]}]}`)
		} else {
			fmt.Fprint(w, `{"results":[{},{}]}`)
		}
	}))
	defer srv.Close()
	state := filepath.Join(t.TempDir(), "snapshot.json")
	args := []string{"-state", state, "-osv-base-url", srv.URL, "-nvd=false"}
	var out, logs bytes.Buffer
	if err := run(context.Background(), append(append([]string{}, args...), "-profile", fixtureProfile(t)), &out, &logs); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	positive = true
	if err := run(context.Background(), append(args, "-monitor"), failedOutput{}, &logs); err == nil {
		t.Fatal("output failure accepted")
	}
	after, err := os.ReadFile(state)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed delivery advanced baseline: %v", err)
	}
	out.Reset()
	if err := run(context.Background(), append(args, "-monitor"), &out, &logs); err != nil {
		t.Fatal(err)
	}
	var got result
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, change := range got.Changes {
		if change.Kind == "added" && change.ID == "GHSA-example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("lost retryable change: %+v", got.Changes)
	}
}

func TestInvalidFlagsAndMissingImport(t *testing.T) {
	for _, args := range [][]string{nil, {"-monitor"}, {"-repository", "https://github.com/a/b", "-profile", "x"}, {"-profile", "x", "-plan-only", "-batch-size", "0"}, {"-profile", "x", "-plan-only", "-ref", "tag"}, {"-profile", "missing", "-plan-only"}} {
		var out, logs bytes.Buffer
		if err := run(context.Background(), args, &out, &logs); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
