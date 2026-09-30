package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vulns-news/src/assessment"
	"vulns-news/src/domain"
	"vulns-news/src/feed"
	"vulns-news/src/llm"
	"vulns-news/src/osv"
	"vulns-news/src/processor"
	"vulns-news/src/reposcan"
	"vulns-news/src/scananalyze"
)

const testModel = "repo-analyze-test-model"
const testAdvisoryID = "GHSA-2345-6789-cfgh"
const testAdvisory = `{
  "id":"GHSA-2345-6789-cfgh",
  "published":"2026-09-01T00:00:00Z",
  "modified":"2026-09-25T00:00:00Z",
  "summary":"Archive extraction advisory",
  "details":"The affected package version is listed; repository exploitability is not established.",
  "affected":[{"package":{"ecosystem":"npm","name":"archive"},
    "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]
}`

type fakeOSV struct {
	hit                     bool
	queryCalls, detailCalls atomic.Int32
}

func (f *fakeOSV) Query(_ context.Context, queries []osv.PackageVersion) []osv.QueryResult {
	f.queryCalls.Add(1)
	results := make([]osv.QueryResult, len(queries))
	for i, query := range queries {
		results[i] = osv.QueryResult{Query: query, Complete: true}
		if f.hit && query.Ecosystem == "npm" && query.Name == "archive" && query.Version == "1.0.0" {
			results[i].IDs = []string{testAdvisoryID}
		}
	}
	return results
}

func (f *fakeOSV) Advisory(_ context.Context, id string) (json.RawMessage, error) {
	f.detailCalls.Add(1)
	if id != testAdvisoryID {
		return nil, fmt.Errorf("unexpected advisory %q", id)
	}
	return json.RawMessage(testAdvisory), nil
}

type savedScan struct {
	state         reposcan.State
	dir, path     string
	output        string
	originalBytes []byte
}

func newSavedScan(t *testing.T, hit bool) savedScan {
	t.Helper()
	profile := domain.RepositoryProfile{
		Repository: domain.RepositoryIdentity{
			ID: "github:example/archive-app", CanonicalURL: "https://github.com/example/archive-app",
			CommitSHA: strings.Repeat("a", 40), Ref: "main",
		},
		ProfiledAt: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC),
		Components: []domain.Component{{
			ID: "archive-lock-dependency", Ecosystem: "npm", Name: "archive", Version: "1.0.0",
			PURL: "pkg:npm/archive@1.0.0", SourcePath: "package-lock.json", Scope: "production", Direct: true,
		}},
	}
	provider := &fakeOSV{hit: hit}
	state := reposcan.State{SchemaVersion: reposcan.SchemaVersion, Profile: profile,
		Report: reposcan.Run(context.Background(), profile, reposcan.Config{OSV: provider})}
	if state.Report.Status != "complete" || !state.Report.RefreshComplete || len(state.Report.Queries) != 1 {
		t.Fatalf("invalid scan fixture: %+v", state.Report)
	}
	wantOutcome := "no_advisory_found"
	var wantDetails int32
	if hit {
		wantOutcome, wantDetails = "affected_version_match", 1
	}
	if state.Report.Queries[0].Outcome != wantOutcome {
		t.Fatalf("scan outcome = %q, want %q", state.Report.Queries[0].Outcome, wantOutcome)
	}
	dir := t.TempDir()
	fixture := savedScan{dir: dir, path: filepath.Join(dir, "scan.json"), output: filepath.Join(dir, "analysis.json")}
	if err := reposcan.Save(fixture.path, state); err != nil {
		t.Fatalf("save real scan: %v", err)
	}
	var err error
	fixture.state, err = reposcan.Load(fixture.path)
	if err != nil {
		t.Fatalf("load real scan: %v", err)
	}
	fixture.originalBytes = readTestFile(t, fixture.path)
	t.Cleanup(func() {
		if !bytes.Equal(readTestFile(t, fixture.path), fixture.originalBytes) {
			t.Error("CLI overwrote the source repo-scan state")
		}
		if provider.queryCalls.Load() != 1 || provider.detailCalls.Load() != wantDetails {
			t.Errorf("OSV calls = %d/%d; saved analysis must not rescan", provider.queryCalls.Load(), provider.detailCalls.Load())
		}
	})
	return fixture
}

func (s savedScan) args(baseURL string) []string {
	return []string{"-state", s.path, "-output", s.output, "-model", testModel,
		"-base-url", baseURL, "-timeout", "5s", "-request-timeout", "2s"}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func encodeTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decodeTestReport(t *testing.T, data []byte) scananalyze.Report {
	t.Helper()
	var report scananalyze.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, data)
	}
	return report
}

func runCLI(t *testing.T, args []string) ([]byte, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	err := run(ctx, args, &stdout, &stderr)
	return stdout.Bytes(), stderr.String(), err
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// These tests deliberately run serially: the CLI constructs its own HTTP client,
// so intercepting DefaultTransport is what proves no external APIs are contacted.
func restrictHTTP(t *testing.T, baseURL string) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if baseURL != "" && r.URL.Scheme+"://"+r.URL.Host == baseURL {
			return previous.RoundTrip(r)
		}
		t.Errorf("unexpected external HTTP request: %s", r.URL)
		return nil, fmt.Errorf("external HTTP disabled in CLI test: %s", r.URL)
	})
	t.Cleanup(func() { http.DefaultTransport = previous })
}

type ollamaReply struct {
	stage           string
	relevance       processor.Relevance
	status          int
	resumeScreening bool
}

type ollamaServer struct {
	url         string
	mu          sync.Mutex
	stages      []string
	checkpoints []scananalyze.Report
}

func newOllamaServer(t *testing.T, scan savedScan, replies ...ollamaReply) *ollamaServer {
	t.Helper()
	h := &ollamaServer{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/chat" {
			t.Errorf("unexpected Ollama request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected endpoint", http.StatusBadRequest)
			return
		}
		var request struct {
			Model    string          `json:"model"`
			Messages []llm.Message   `json:"messages"`
			Stream   bool            `json:"stream"`
			Think    bool            `json:"think"`
			Format   json.RawMessage `json:"format"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode Ollama request: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if request.Model != testModel || request.Stream || request.Think || len(request.Messages) != 2 {
			t.Errorf("unexpected structured request: %+v", request)
			http.Error(w, "invalid structured request", http.StatusBadRequest)
			return
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(request.Format, &schema); err != nil || len(schema.Properties) == 0 {
			t.Errorf("missing JSON schema: %s", request.Format)
			http.Error(w, "missing schema", http.StatusBadRequest)
			return
		}
		stage := "analysis"
		if _, ok := schema.Properties["relevance"]; ok {
			stage = "screening"
		}
		h.mu.Lock()
		index := len(h.stages)
		h.stages = append(h.stages, stage)
		h.mu.Unlock()
		if index >= len(replies) || replies[index].stage != stage {
			t.Errorf("unexpected model call %d: %s", index+1, stage)
			http.Error(w, "unexpected model call", http.StatusInternalServerError)
			return
		}
		if request.Messages[0].Role != llm.RoleSystem || request.Messages[1].Role != llm.RoleUser {
			t.Error("processor messages lost system/user trust boundary")
		}
		const prefix = "BEGIN_UNTRUSTED_ANALYSIS_MATERIAL\n"
		const suffix = "\nEND_UNTRUSTED_ANALYSIS_MATERIAL"
		material := request.Messages[1].Content
		if !strings.HasPrefix(material, prefix) || !strings.HasSuffix(material, suffix) {
			t.Error("processor input is not delimited untrusted material")
		}
		var input processor.Input
		if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(material, prefix), suffix)), &input); err != nil {
			t.Errorf("decode real processor material: %v", err)
			http.Error(w, "invalid material", http.StatusBadRequest)
			return
		}
		assertCitationSchema(t, citationRequest{Format: request.Format, Messages: request.Messages, stage: stage, input: input})
		if input.Repository.Repository != scan.state.Profile.Repository || input.Vulnerability.ID != testAdvisoryID || len(input.Candidate.Matches) != 1 {
			t.Errorf("saved repository facts lost in processor input: %+v", input)
		}
		ids := []string{}
		var advisory, dependency bool
		for _, evidence := range input.Evidence {
			switch evidence.Kind {
			case processor.EvidenceAdvisory:
				advisory = true
				ids = append(ids, evidence.ID)
			case processor.EvidenceRepositoryDependency:
				dependency = true
				ids = append(ids, evidence.ID)
			}
		}
		if !advisory || !dependency {
			t.Error("real input lacks advisory or dependency evidence")
		}
		// Observe the file while the model is executing, not just the final report.
		data, err := os.ReadFile(scan.output)
		var checkpoint scananalyze.Report
		if err == nil {
			err = json.Unmarshal(data, &checkpoint)
		}
		if err != nil || len(checkpoint.Entries) != 1 {
			t.Errorf("checkpoint missing before %s request: %v, %s", stage, err, data)
		} else {
			e := checkpoint.Entries[0]
			if stage == "screening" {
				wantStatus := "pending"
				if replies[index].resumeScreening {
					// A retry preserves the failed checkpoint until validated success.
					wantStatus = "screening_error"
				}
				if e.Status != wantStatus || e.Stage != "screening" || e.Screening != nil || e.ScreeningHash != "" || e.Analysis != nil || e.AnalysisHash != "" || e.Feed != nil {
					t.Errorf("screening checkpoint = %+v, want %s with no cached outputs", e, wantStatus)
				}
				if (!replies[index].resumeScreening && e.Error != "") || (replies[index].resumeScreening && strings.TrimSpace(e.Error) == "") {
					t.Errorf("screening checkpoint error = %q, resume=%t", e.Error, replies[index].resumeScreening)
				}
			}
			if stage == "analysis" && (e.Screening == nil || e.Screening.Result.Relevance != processor.RelevanceRelated || e.Analysis != nil || e.Stage != "analysis") {
				t.Errorf("screening not durably cached before deep request: %+v", e)
			}
		}
		h.mu.Lock()
		h.checkpoints = append(h.checkpoints, checkpoint)
		h.mu.Unlock()
		reply := replies[index]
		w.Header().Set("Content-Type", "application/json")
		if reply.status != 0 {
			w.WriteHeader(reply.status)
			fmt.Fprint(w, `{"error":"test deep service unavailable"}`)
			return
		}
		var content any
		if stage == "screening" {
			relevance := reply.relevance
			if relevance == "" {
				relevance = processor.RelevanceRelated
			}
			advisoryIDs, repositoryIDs := citationWireIDs(input)
			content = map[string]any{"relevance": relevance,
				"reason":                "The package/version query matches this advisory; runtime impact is unverified.",
				"advisory_evidence_ids": advisoryIDs, "repository_evidence_ids": repositoryIDs}
		} else {
			content = processor.DeepAnalysis{
				Summary:            processor.SupportedClaim{Text: "The recorded dependency is listed by the advisory.", EvidenceIDs: ids},
				RepositoryImpact:   processor.SupportedClaim{Text: "Affected feature usage and exploitability remain unverified.", EvidenceIDs: ids},
				MissingInformation: []string{"Whether the affected feature is used"},
				RecommendedActions: []string{"Review dependency usage and the source advisory"},
			}
		}
		encoded, err := json.Marshal(content)
		if err != nil {
			t.Errorf("encode model fixture: %v", err)
			http.Error(w, "invalid fixture", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{
			"model": testModel, "done": true, "done_reason": "stop",
			"message":           llm.Message{Role: llm.RoleAssistant, Content: string(encoded)},
			"prompt_eval_count": 20, "eval_count": 10,
		}); err != nil {
			t.Errorf("write Ollama response: %v", err)
		}
	}))
	h.url = server.URL
	t.Cleanup(server.Close)
	restrictHTTP(t, server.URL)
	return h
}

func (h *ollamaServer) calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string{}, h.stages...)
}

func assertCalls(t *testing.T, h *ollamaServer, want ...string) {
	t.Helper()
	if got := h.calls(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("model stages = %v, want %v", got, want)
	}
}

func assertLog(t *testing.T, log string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(log, fragment) {
			t.Errorf("stderr missing %q:\n%s", fragment, log)
		}
	}
}

func assertSavedReport(t *testing.T, scan savedScan, stdout []byte) scananalyze.Report {
	t.Helper()
	report := decodeTestReport(t, readTestFile(t, scan.output))
	if got := decodeTestReport(t, stdout); !reflect.DeepEqual(got, report) {
		t.Errorf("stdout and saved checkpoint differ:\nstdout=%+v\ncheckpoint=%+v", got, report)
	}
	if report.Repository != scan.state.Profile.Repository || report.Model != testModel || report.SnapshotHash == "" {
		t.Errorf("report lost snapshot identity: %+v", report)
	}
	if temps, err := filepath.Glob(filepath.Join(scan.dir, ".repo-analysis-*.tmp")); err != nil || len(temps) != 0 {
		t.Errorf("checkpoint temporary files leaked: %v, %v", temps, err)
	}
	return report
}

type fileSnapshot struct {
	Mode     fs.FileMode
	Modified time.Time
	Data     string
}

func snapshotFiles(t *testing.T, root string) map[string]fileSnapshot {
	t.Helper()
	result := map[string]fileSnapshot{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		snapshot := fileSnapshot{Mode: info.Mode(), Modified: info.ModTime()}
		if entry.Type()&os.ModeSymlink != 0 {
			snapshot.Data, err = os.Readlink(path)
		} else if info.Mode().IsRegular() {
			var data []byte
			data, err = os.ReadFile(path)
			snapshot.Data = string(data)
		}
		result[path] = snapshot
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertNoWrites(t *testing.T, root string, before map[string]fileSnapshot) {
	t.Helper()
	if after := snapshotFiles(t, root); !reflect.DeepEqual(after, before) {
		t.Error("files, links, permissions, or modification times changed on a read-only/rejected run")
	}
}

func TestRunSavedScanDeepAndResume(t *testing.T) {
	scan := newSavedScan(t, true)
	h := newOllamaServer(t, scan, ollamaReply{stage: "screening"}, ollamaReply{stage: "analysis"})
	args := append(scan.args(h.url), "-require-deep")
	stdout, log, err := runCLI(t, args)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, log)
	}
	report := assertSavedReport(t, scan, stdout)
	if !report.Complete || !report.SelectedComplete || report.TotalCandidates != 1 || report.SelectedCandidates != 1 || report.Screened != 1 || report.Analyzed != 1 || report.Errors != 0 || report.Pending != 0 || len(report.Entries) != 1 {
		t.Fatalf("unexpected completed report: %+v", report)
	}
	entry := report.Entries[0]
	if entry.Status != "analyzed" || entry.Stage != "complete" || entry.Screening == nil || entry.Analysis == nil || entry.Feed == nil || entry.Feed.Status != feed.StatusAnalyzed {
		t.Fatalf("deep pipeline incomplete: %+v", entry)
	}
	if entry.Feed.VulnerabilityID != testAdvisoryID || entry.Feed.VulnerabilityRevision.Format(time.RFC3339) != "2026-09-25T00:00:00Z" || entry.Feed.CVEID != "" || !entry.Feed.CVERevision.IsZero() {
		t.Errorf("generic advisory identity lost: %+v", entry.Feed)
	}
	var serialized struct {
		Entries []struct {
			Feed map[string]json.RawMessage `json:"feed"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(stdout, &serialized); err != nil {
		t.Fatal(err)
	}
	if _, exists := serialized.Entries[0].Feed["cve_id"]; exists {
		t.Error("GHSA feed JSON contains a fake cve_id")
	}
	if string(serialized.Entries[0].Feed["vulnerability_id"]) != `"`+testAdvisoryID+`"` {
		t.Error("feed JSON is missing generic vulnerability identity")
	}
	for _, check := range []assessment.Check{entry.Feed.Applicability.FeatureUsage, entry.Feed.Applicability.CodeReachability, entry.Feed.Applicability.AttackConditions} {
		if check.Status != assessment.Unknown {
			t.Errorf("exact query was promoted to runtime proof: %+v", check)
		}
	}
	if len(entry.Feed.Generation) != 2 || entry.Screening.Generation.Model != testModel || entry.Analysis.Generation.PromptTokens != 20 {
		t.Error("Ollama generation metadata lost")
	}
	assertCalls(t, h, "screening", "analysis")
	assertLog(t, log, "Using saved scan:", scan.state.Profile.Repository.ID, scan.state.Profile.Repository.CommitSHA,
		"No GitHub/OSV/NVD requests.", h.url, "Deep Analysis runs only for related", "candidate 1/1 "+testAdvisoryID+": screening",
		"candidate 1/1 "+testAdvisoryID+": analysis", "Candidates=1 Selected=1 Screened=1 Analyzed=1")

	stdout, log, err = runCLI(t, append(args, "-resume"))
	if err != nil {
		t.Fatalf("resume: %v\n%s", err, log)
	}
	resumed := assertSavedReport(t, scan, stdout)
	if !reflect.DeepEqual(resumed.Entries, report.Entries) || resumed.StartedAt != report.StartedAt || resumed.SnapshotHash != report.SnapshotHash {
		t.Error("completed resume changed cached results or snapshot identity")
	}
	assertCalls(t, h, "screening", "analysis")
	if strings.Contains(log, ": screening") || strings.Contains(log, ": analysis") {
		t.Errorf("completed resume logged new model stages:\n%s", log)
	}
}

func TestRunDeep503CheckpointsScreeningAndResumesOnlyDeep(t *testing.T) {
	scan := newSavedScan(t, true)
	h := newOllamaServer(t, scan, ollamaReply{stage: "screening"},
		ollamaReply{stage: "analysis", status: http.StatusServiceUnavailable}, ollamaReply{stage: "analysis"})
	args := append(scan.args(h.url), "-require-deep")
	stdout, log, err := runCLI(t, args)
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("run error = %v, want deep HTTP 503\n%s", err, log)
	}
	report := assertSavedReport(t, scan, stdout)
	if report.Complete || report.Errors != 1 || report.Screened != 1 || report.Analyzed != 0 || len(report.Entries) != 1 {
		t.Fatalf("failed deep report = %+v", report)
	}
	entry := report.Entries[0]
	if entry.Status != "analysis_error" || entry.Stage != "analysis" || entry.Screening == nil || entry.Analysis != nil || entry.Feed != nil || !strings.Contains(entry.Error, "503") {
		t.Fatalf("deep failure lost cached screening/error: %+v", entry)
	}
	cachedScreen := encodeTestJSON(t, entry.Screening)
	assertCalls(t, h, "screening", "analysis")
	assertLog(t, log, "Screened=1 Analyzed=0", "Errors=1")

	stdout, log, err = runCLI(t, append(args, "-resume"))
	if err != nil {
		t.Fatalf("resume deep: %v\n%s", err, log)
	}
	resumed := assertSavedReport(t, scan, stdout)
	if !resumed.Complete || resumed.Errors != 0 || resumed.Analyzed != 1 || resumed.Entries[0].Feed == nil || resumed.Entries[0].Feed.Status != feed.StatusAnalyzed {
		t.Fatalf("resumed report = %+v", resumed)
	}
	if !bytes.Equal(cachedScreen, encodeTestJSON(t, resumed.Entries[0].Screening)) {
		t.Error("resume replaced the successful screening output")
	}
	assertCalls(t, h, "screening", "analysis", "analysis")
	assertLog(t, log, "candidate 1/1 "+testAdvisoryID+": analysis", "Errors=0")
	if strings.Contains(log, ": screening") {
		t.Errorf("resume repeated screening:\n%s", log)
	}
}

func TestRunRequireDeepDoesNotOverrideUnknownOrNoHit(t *testing.T) {
	for _, hit := range []bool{true, false} {
		name := "no-hit"
		if hit {
			name = "all-unknown"
		}
		t.Run(name, func(t *testing.T) {
			scan := newSavedScan(t, hit)
			var replies []ollamaReply
			if hit {
				replies = append(replies, ollamaReply{stage: "screening", relevance: processor.RelevanceUnknown})
			}
			h := newOllamaServer(t, scan, replies...)
			stdout, log, err := runCLI(t, append(scan.args(h.url), "-require-deep"))
			if err == nil || !strings.Contains(err.Error(), "Deep Analysis E2E not covered") {
				t.Fatalf("error = %v, want require-deep failure\n%s", err, log)
			}
			report := assertSavedReport(t, scan, stdout)
			if !report.Complete || report.Analyzed != 0 || report.Errors != 0 {
				t.Fatalf("coverage check changed analysis outcome: %+v", report)
			}
			if hit {
				if report.ScreeningOnly != 1 || len(report.Entries) != 1 || report.Entries[0].Screening.Result.Relevance != processor.RelevanceUnknown || report.Entries[0].Analysis != nil || report.Entries[0].Feed.Status != feed.StatusScreened {
					t.Fatalf("unknown screening was overridden: %+v", report)
				}
				assertCalls(t, h, "screening")
			} else {
				if report.TotalCandidates != 0 || len(report.Entries) != 0 {
					t.Fatalf("no-hit scan invented candidates: %+v", report)
				}
				assertCalls(t, h)
			}
			if _, _, err := runCLI(t, append(scan.args(h.url), "-resume")); err != nil {
				t.Fatalf("same outcome without -require-deep must succeed: %v", err)
			}
			if len(h.calls()) != len(replies) {
				t.Error("resume regenerated a completed screening-only/no-hit result")
			}
		})
	}
}

func TestRunPlanOnlyMakesNoRequestsOrWrites(t *testing.T) {
	t.Setenv("OLLAMA_MODEL", "")
	for _, hit := range []bool{true, false} {
		t.Run(fmt.Sprintf("hit=%t", hit), func(t *testing.T) {
			scan := newSavedScan(t, hit)
			h := newOllamaServer(t, scan)
			before := snapshotFiles(t, scan.dir)
			// Even an output pointing at the source is inert in plan-only mode.
			stdout, log, err := runCLI(t, []string{"-state", scan.path, "-plan-only", "-base-url", h.url, "-output", scan.path})
			if err != nil {
				t.Fatalf("plan: %v\n%s", err, log)
			}
			var plan struct {
				Repository          domain.RepositoryIdentity `json:"repository"`
				TotalCandidates     int                       `json:"total_candidates"`
				PreparationErrors   int                       `json:"preparation_errors"`
				ScanRefreshComplete bool                      `json:"scan_refresh_complete"`
				Entries             []planEntry               `json:"entries"`
			}
			if err := json.Unmarshal(stdout, &plan); err != nil {
				t.Fatal(err)
			}
			want := 0
			if hit {
				want = 1
			}
			if plan.Repository != scan.state.Profile.Repository || plan.TotalCandidates != want || len(plan.Entries) != want || plan.PreparationErrors != 0 || !plan.ScanRefreshComplete {
				t.Fatalf("plan = %+v", plan)
			}
			if hit && (plan.Entries[0].ID != testAdvisoryID || plan.Entries[0].Origins != 1 || len(plan.Entries[0].RecordKeys) != 1) {
				t.Errorf("plan lost advisory origins: %+v", plan.Entries)
			}
			assertCalls(t, h)
			assertNoWrites(t, scan.dir, before)
		})
	}
}

func TestFlags(t *testing.T) {
	t.Setenv("OLLAMA_MODEL", "")
	t.Setenv("OLLAMA_BASE_URL", "")
	restrictHTTP(t, "")
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"missing state", nil, "-state is required"},
		{"positional", []string{"-state", "scan.json", "extra"}, "positional arguments"},
		{"missing output", []string{"-state", "scan.json", "-model", testModel}, "requires -output and -model"},
		{"missing model", []string{"-state", "scan.json", "-output", "analysis.json"}, "requires -output and -model"},
		{"blank model", []string{"-state", "scan.json", "-output", "analysis.json", "-model", "  "}, "requires -output and -model"},
		{"negative limit", []string{"-state", "scan.json", "-limit", "-1"}, "limit must be nonnegative"},

		{"negative timeout", []string{"-state", "scan.json", "-output", "analysis.json", "-model", testModel, "-timeout", "-1s", "-request-timeout", "0m"}, "timeout"},
		{"negative request timeout", []string{"-state", "scan.json", "-output", "analysis.json", "-model", testModel, "-request-timeout", "-1s"}, "timeout"},
		{"negative request timeout with no overall deadline", []string{"-state", "scan.json", "-output", "analysis.json", "-model", testModel, "-timeout", "0", "-request-timeout", "-1s"}, "timeout"},
		{"invalid duration", []string{"-state", "scan.json", "-timeout", "forever"}, "invalid value"},
		{"unknown flag", []string{"-unsupported"}, "flag provided but not defined"},
		{"plan resume", []string{"-state", "scan.json", "-plan-only", "-resume"}, "cannot be combined"},
		{"plan require deep", []string{"-state", "scan.json", "-plan-only", "-require-deep"}, "cannot be combined"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, err := runCLI(t, tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.want) || len(stdout) != 0 {
				t.Fatalf("error = %v, want %q; stdout = %s", err, tt.want, stdout)
			}
		})
	}
	if _, help, err := runCLI(t, []string{"-help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help error = %v", err)
	} else {
		for _, tt := range []struct {
			flag      string
			fragments []string
		}{
			{"-timeout", []string{"overall", "0", "disabl", "manual", "cancel", "default 2h"}},
			{"-request-timeout", []string{"0", "disabl", "overall", "applies", "enabled", "default 5m"}},
		} {
			start := strings.Index(help, "\n  "+tt.flag+" duration")
			if start < 0 {
				t.Fatalf("help omits %s:\n%s", tt.flag, help)
			}
			flagHelp := strings.SplitN(help[start+1:], "\n  -", 2)[0]
			for _, fragment := range tt.fragments {
				if !strings.Contains(flagHelp, fragment) {
					t.Errorf("%s help missing %q:\n%s", tt.flag, fragment, flagHelp)
				}
			}
		}
	}
	for _, duration := range []string{"0", "0s", "0m"} {
		t.Run("zero request timeout "+duration, func(t *testing.T) {
			o, err := parse([]string{"-state", "scan.json", "-output", "analysis.json", "-model", testModel,
				"-request-timeout", duration}, &bytes.Buffer{})
			if err != nil || o.requestTimeout != 0 || o.timeout != 2*time.Hour {
				t.Fatalf("zero request timeout options = %+v, %v", o, err)
			}
		})
	}
	for _, duration := range []string{"0", "0s", "0h"} {
		t.Run("zero overall timeout "+duration, func(t *testing.T) {
			args := []string{"-state", "scan.json", "-output", "analysis.json", "-model", testModel,
				"-timeout", duration}
			o, err := parse(args, &bytes.Buffer{})
			if err != nil || o.timeout != 0 || o.requestTimeout != 5*time.Minute {
				t.Fatalf("zero overall timeout options = %+v, %v", o, err)
			}
			o, err = parse(append(args, "-request-timeout", "0"), &bytes.Buffer{})
			if err != nil || o.timeout != 0 || o.requestTimeout != 0 {
				t.Fatalf("both timeouts disabled options = %+v, %v", o, err)
			}
		})
	}
	defaults, err := parse([]string{"-state", "scan.json", "-output", "analysis.json", "-model", testModel}, &bytes.Buffer{})
	if err != nil || defaults.baseURL != "http://127.0.0.1:11434" || defaults.timeout != 2*time.Hour || defaults.requestTimeout != 5*time.Minute || defaults.limit != 0 {
		t.Fatalf("defaults = %+v, %v", defaults, err)
	}
	t.Setenv("OLLAMA_MODEL", "  environment-model  ")
	t.Setenv("OLLAMA_BASE_URL", "  http://127.0.0.1:12345///  ")
	env, err := parse([]string{"-state", "scan.json", "-output", "analysis.json"}, &bytes.Buffer{})
	if err != nil || env.model != "environment-model" || env.baseURL != "http://127.0.0.1:12345" {
		t.Fatalf("environment options = %+v, %v", env, err)
	}
	explicit, err := parse([]string{"-state", "scan.json", "-output", "analysis.json", "-model", testModel, "-base-url", "http://localhost:12346/"}, &bytes.Buffer{})
	if err != nil || explicit.model != testModel || explicit.baseURL != "http://localhost:12346" {
		t.Fatalf("explicit options = %+v, %v", explicit, err)
	}
}

func TestRunRejectsInvalidInputWithoutWrites(t *testing.T) {
	scan := newSavedScan(t, true)
	h := newOllamaServer(t, scan)
	for name, data := range map[string][]byte{
		"missing":            nil,
		"matrix CSV":         []byte("repository,package,advisory\nrepo,archive," + testAdvisoryID + "\n"),
		"malformed JSON":     []byte(`{"schema_version":`),
		"trailing JSON":      append(append([]byte{}, scan.originalBytes...), []byte(` {}`)...),
		"unknown field":      append([]byte(`{"unexpected":true,`), scan.originalBytes[1:]...),
		"unsupported schema": bytes.Replace(scan.originalBytes, []byte(`"schema_version": 1`), []byte(`"schema_version": 99`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			input := filepath.Join(scan.dir, "bad-input.json")
			if data != nil {
				if err := os.WriteFile(input, data, 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(input); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			before := snapshotFiles(t, scan.dir)
			stdout, _, err := runCLI(t, append(scan.args(h.url), "-state", input))
			if err == nil || !strings.Contains(err.Error(), "load repo-scan state") || len(stdout) != 0 {
				t.Fatalf("invalid input error = %v; stdout = %s", err, stdout)
			}
			assertCalls(t, h)
			assertNoWrites(t, scan.dir, before)
		})
	}
}

func TestRunRejectsUnsafeOutputPathsWithoutWrites(t *testing.T) {
	for _, name := range []string{"state", "cleaned state", "existing output", "directory", "symlink", "dangling symlink", "hard link", "symlinked parent", "missing resume", "missing parent", "invalid endpoint"} {
		t.Run(name, func(t *testing.T) {
			scan := newSavedScan(t, true)
			h := newOllamaServer(t, scan)
			output := scan.output
			extra := []string{}
			want := ""
			switch name {
			case "state":
				output, want = scan.path, "must not overwrite the scan state"
			case "cleaned state":
				output, want = scan.dir+string(os.PathSeparator)+"."+string(os.PathSeparator)+"scan.json", "must not overwrite the scan state"
			case "existing output":
				if err := os.WriteFile(output, []byte("keep existing output"), 0600); err != nil {
					t.Fatal(err)
				}
				want = "output already exists"
			case "directory":
				if err := os.Mkdir(output, 0700); err != nil {
					t.Fatal(err)
				}
				want = "must be a regular file"
			case "symlink", "dangling symlink":
				target := scan.path
				if name == "dangling symlink" {
					target = filepath.Join(scan.dir, "absent.json")
				}
				if err := os.Symlink(target, output); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				want = "must be a regular file"
			case "hard link":
				if err := os.Link(scan.path, output); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
				want = "must not overwrite the scan state"
			case "symlinked parent":
				alias := filepath.Join(scan.dir, "alias")
				if err := os.Symlink(scan.dir, alias); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				output, want = filepath.Join(alias, "scan.json"), "must not overwrite the scan state"
			case "missing resume":
				extra, want = []string{"-resume"}, "requires an existing analysis output"
			case "missing parent":
				output, want = filepath.Join(scan.dir, "missing", "analysis.json"), "checkpoint analysis report"
			case "invalid endpoint":
				extra, want = []string{"-base-url", "file:///not-ollama"}, "absolute HTTP(S) URL"
			}
			before := snapshotFiles(t, scan.dir)
			args := append(scan.args(h.url), "-output", output)
			_, _, err := runCLI(t, append(args, extra...))
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %v, want %q", err, want)
			}
			assertCalls(t, h)
			assertNoWrites(t, scan.dir, before)
		})
	}
}

func TestRunResumeRejectsChangedOptionsAndInvalidCheckpointWithoutWrites(t *testing.T) {
	scan := newSavedScan(t, true)
	h := newOllamaServer(t, scan, ollamaReply{stage: "screening"}, ollamaReply{stage: "analysis"})
	if _, log, err := runCLI(t, scan.args(h.url)); err != nil {
		t.Fatalf("initial run: %v\n%s", err, log)
	}
	valid := readTestFile(t, scan.output)
	for _, tt := range []struct {
		name   string
		args   []string
		mutate func(*scananalyze.Report)
		raw    func([]byte) []byte
		want   string
	}{
		{name: "changed model", args: []string{"-model", "different-model"}, want: "analysis options differ"},
		{name: "changed endpoint", args: []string{"-base-url", h.url + "/different"}, want: "analysis options differ"},
		{name: "changed limit", args: []string{"-limit", "1"}, want: "analysis options differ"},
		{name: "schema", mutate: func(r *scananalyze.Report) { r.SchemaVersion++ }, want: "analysis options differ"},
		{name: "snapshot", mutate: func(r *scananalyze.Report) { r.SnapshotHash = "changed" }, want: "analysis options differ"},
		{name: "input fingerprint", mutate: func(r *scananalyze.Report) { r.Entries[0].InputHash = "changed" }, want: "input fingerprint differs"},
		{name: "counters", mutate: func(r *scananalyze.Report) { r.Analyzed++ }, want: "counters or completion flags"},
		{name: "invented screening citation", mutate: func(r *scananalyze.Report) { r.Entries[0].Screening.Result.EvidenceIDs = []string{"EVD-INVENTED"} }, want: "unknown evidence ID"},
		{name: "invented analysis citation", mutate: func(r *scananalyze.Report) {
			r.Entries[0].Analysis.Analysis.Summary.EvidenceIDs = []string{"EVD-INVENTED"}
		}, want: "unknown evidence ID"},
		{name: "null analysis array", mutate: func(r *scananalyze.Report) { r.Entries[0].Analysis.Analysis.MissingInformation = nil }, want: "JSON Schema validation failed"},
		{name: "analysis without screening", mutate: func(r *scananalyze.Report) { r.Entries[0].Screening = nil }, want: "requires related screening"},
		{name: "analysis with unknown screening", mutate: func(r *scananalyze.Report) { r.Entries[0].Screening.Result.Relevance = processor.RelevanceUnknown }, want: "requires related screening"},
		{name: "malformed JSON", raw: func([]byte) []byte { return []byte(`{"schema_version":`) }, want: "load analysis checkpoint"},
		{name: "trailing JSON", raw: func(b []byte) []byte { return append(b, []byte(` {}`)...) }, want: "trailing analysis checkpoint data"},
		{name: "unknown property", raw: func(b []byte) []byte { return append([]byte(`{"unexpected":true,`), b[1:]...) }, want: "unknown field"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := append([]byte{}, valid...)
			if tt.mutate != nil {
				report := decodeTestReport(t, data)
				tt.mutate(&report)
				data = encodeTestJSON(t, report)
			}
			if tt.raw != nil {
				data = tt.raw(data)
			}
			if err := os.WriteFile(scan.output, data, 0600); err != nil {
				t.Fatal(err)
			}
			before := snapshotFiles(t, scan.dir)
			args := append(scan.args(h.url), "-resume")
			stdout, _, err := runCLI(t, append(args, tt.args...))
			if err == nil || !strings.Contains(err.Error(), tt.want) || len(stdout) != 0 {
				t.Fatalf("resume error = %v, want %q; stdout = %s", err, tt.want, stdout)
			}
			assertCalls(t, h, "screening", "analysis")
			assertNoWrites(t, scan.dir, before)
		})
	}
}
