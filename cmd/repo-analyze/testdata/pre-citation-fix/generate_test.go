package main

// Provenance: scan.json and analysis.json were generated with the unmodified
// production code and main_test.go from vulns-news-colab-deep-analysis-20260926.zip
// (SHA-256 ba294da01453ab9aad1188a42cacaefd29c225f2a8dbf7d4cbe4ee9baaa25020),
// before per-request citation schemas/retries and Generation.CitationRetries.
//
// Reproduce in a temporary directory, NOT in the current checkout:
//   1. Verify the ZIP checksum and extract it into a clean temporary directory.
//   2. Copy ONLY this file to the extracted vulns-news/cmd/repo-analyze/ directory.
//   3. Use the actual Go 1.25.0 binary (not a newer toolchain launcher). Create
//      a separate output directory and, from the extracted module, run:
//      GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off LEGACY_FIXTURE_OUTPUT=/absolute/output \
//        /path/to/go1.25.0/bin/go test ./cmd/repo-analyze -run TestGeneratePreCitationFixtures -count=1
//   4. Compare both output files byte-for-byte with the frozen fixtures.
// Dependencies/toolchain must already be cached; all HTTP is routed to httptest.
//
// The old reposcan.Run/Save/Load and CLI produce the material and ALL checksums.
// Scan timestamps are fixed BEFORE analysis computes the snapshot fingerprint.
// Only the unhashed report StartedAt/UpdatedAt are fixed after the old CLI run.
// No snapshot/input/output hash or Generation field is edited or recomputed here.
// This generator lives under testdata so normal current-code tests never run it.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vulns-news/src/llm"
	"vulns-news/src/osv"
	"vulns-news/src/processor"
	"vulns-news/src/reposcan"
)

var legacyFixtureIDs = []string{testAdvisoryID, "GHSA-3456-789c-fghj", "GHSA-4567-89cf-ghjm"}

type legacyFixtureOSV struct{}

func (legacyFixtureOSV) Query(_ context.Context, queries []osv.PackageVersion) []osv.QueryResult {
	results := make([]osv.QueryResult, len(queries))
	for i, query := range queries {
		results[i] = osv.QueryResult{Query: query, Complete: true, IDs: legacyFixtureIDs}
	}
	return results
}

func (legacyFixtureOSV) Advisory(_ context.Context, id string) (json.RawMessage, error) {
	for _, allowed := range legacyFixtureIDs {
		if id == allowed {
			return json.RawMessage(strings.ReplaceAll(testAdvisory, testAdvisoryID, id)), nil
		}
	}
	return nil, fmt.Errorf("unexpected advisory %q", id)
}

func TestGeneratePreCitationFixtures(t *testing.T) {
	output := os.Getenv("LEGACY_FIXTURE_OUTPUT")
	if output == "" {
		t.Skip("set LEGACY_FIXTURE_OUTPUT when running against the archived source")
	}
	if runtime.Version() != "go1.25.0" {
		t.Fatalf("fixture generator requires go1.25.0, got %s", runtime.Version())
	}
	if _, exists := reflect.TypeOf(processor.Generation{}).FieldByName("CitationRetries"); exists {
		t.Fatal("refusing to generate pre-fix fixtures with the citation-fix implementation")
	}
	for _, name := range []string{"scan.json", "analysis.json"} {
		if _, err := os.Stat(filepath.Join(output, name)); !os.IsNotExist(err) {
			t.Fatalf("fixture destination must not already exist: %s (%v)", name, err)
		}
	}

	scan := newSavedScan(t, true)
	state := scan.state
	state.Report = reposcan.Run(context.Background(), state.Profile, reposcan.Config{OSV: legacyFixtureOSV{}})
	fixed := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	state.Report.StartedAt, state.Report.FinishedAt = fixed, fixed.Add(time.Second)
	statePath := filepath.Join(output, "scan.json")
	if err := reposcan.Save(statePath, state); err != nil {
		t.Fatal(err)
	}
	if _, err := reposcan.Load(statePath); err != nil {
		t.Fatal(err)
	}
	original := readTestFile(t, statePath)

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index := int(calls.Add(1)) - 1
		if r.Method != http.MethodPost || r.URL.Path != "/api/chat" || index >= 4 {
			t.Errorf("unexpected request %d: %s %s", index+1, r.Method, r.URL)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		var request struct {
			Model    string          `json:"model"`
			Messages []llm.Message   `json:"messages"`
			Format   json.RawMessage `json:"format"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || len(request.Messages) != 2 {
			t.Errorf("invalid request: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var input processor.Input
		material := strings.TrimSuffix(strings.TrimPrefix(request.Messages[1].Content,
			"BEGIN_UNTRUSTED_ANALYSIS_MATERIAL\n"), "\nEND_UNTRUSTED_ANALYSIS_MATERIAL")
		if err := json.Unmarshal([]byte(material), &input); err != nil {
			t.Errorf("invalid material: %v", err)
			http.Error(w, "invalid material", http.StatusBadRequest)
			return
		}
		if request.Model != testModel || input.Vulnerability.ID != legacyFixtureIDs[index/2] {
			t.Errorf("unexpected request identity: model=%s advisory=%s", request.Model, input.Vulnerability.ID)
		}
		wantSchema := processor.ScreeningSchema()
		if index%2 == 1 {
			wantSchema = processor.DeepAnalysisSchema()
		}
		var got, want any
		if err := json.Unmarshal(request.Format, &got); err != nil {
			t.Error(err)
		}
		if err := json.Unmarshal(wantSchema, &want); err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Error("fixture must use the old, unmodified static response schema")
		}
		w.Header().Set("Content-Type", "application/json")
		if index == 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":"legacy fixture deep service unavailable"}`)
			return
		}
		ids := []string{}
		for _, evidence := range input.Evidence {
			ids = append(ids, evidence.ID)
		}
		var content any = processor.ScreeningResult{
			Relevance: processor.RelevanceRelated, Reason: "The saved package/version matches the advisory; runtime impact is unverified.", EvidenceIDs: ids,
		}
		if index%2 == 1 {
			content = processor.DeepAnalysis{
				Summary:            processor.SupportedClaim{Text: "The recorded dependency is listed by the advisory.", EvidenceIDs: ids},
				RepositoryImpact:   processor.SupportedClaim{Text: "Affected feature usage and exploitability remain unverified.", EvidenceIDs: ids},
				MissingInformation: []string{"Whether the affected feature is used"},
				RecommendedActions: []string{"Review dependency usage and the source advisory"},
			}
		}
		encoded, err := json.Marshal(content)
		if err != nil {
			t.Error(err)
			http.Error(w, "invalid fixture", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{
			"model": testModel, "done": true, "done_reason": "stop",
			"message":           llm.Message{Role: llm.RoleAssistant, Content: string(encoded)},
			"prompt_eval_count": 101 + index, "eval_count": 21 + index,
			"total_duration": 101000 + 1000*index, "load_duration": 10100 + 100*index,
		}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	local, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	const endpoint = "http://127.0.0.1:11434"
	previous := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host != endpoint {
			t.Errorf("external HTTP forbidden: %s", r.URL)
			return nil, fmt.Errorf("external HTTP forbidden: %s", r.URL)
		}
		forwarded := r.Clone(r.Context())
		forwarded.URL.Scheme, forwarded.URL.Host, forwarded.Host = local.Scheme, local.Host, local.Host
		return previous.RoundTrip(forwarded)
	})
	defer func() { http.DefaultTransport = previous }()

	reportPath := filepath.Join(output, "analysis.json")
	stdout, log, err := runCLI(t, []string{"-state", statePath, "-output", reportPath,
		"-model", testModel, "-base-url", endpoint, "-timeout", "5s", "-request-timeout", "2s"})
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("expected old deep failure, got %v\n%s", err, log)
	}
	report := decodeTestReport(t, stdout)
	if calls.Load() != 4 || len(report.Entries) != 3 || report.Analyzed != 1 || report.Screened != 2 || report.Errors != 1 || report.Pending != 1 {
		t.Fatalf("unexpected old report/call count: %d, %+v", calls.Load(), report)
	}
	report.StartedAt, report.UpdatedAt = fixed.Add(time.Minute), fixed.Add(time.Minute+time.Second)
	if err := saveReport(reportPath, report); err != nil {
		t.Fatal(err)
	}
	// The old resume validator must also accept the frozen timestamps/hashes
	// without making a model request.
	before := readTestFile(t, reportPath)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(cancelled, []string{"-state", statePath, "-output", reportPath,
		"-model", testModel, "-base-url", endpoint, "-resume"}, new(bytes.Buffer), new(bytes.Buffer)); err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("old resume rejected frozen fixture before context cancellation: %v", err)
	}
	// Run checkpoints once before observing cancellation; restore only the
	// unhashed fixed report timestamps with the old serializer, never checksums.
	if err := saveReport(reportPath, report); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 4 || !bytes.Equal(before, readTestFile(t, reportPath)) || !bytes.Equal(original, readTestFile(t, statePath)) {
		t.Fatal("old-code validation changed fixture contents or made another model call")
	}
}
