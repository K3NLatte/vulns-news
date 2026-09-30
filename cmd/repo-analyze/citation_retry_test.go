package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"vulns-news/src/feed"
	"vulns-news/src/llm"
	"vulns-news/src/osv"
	"vulns-news/src/processor"
	"vulns-news/src/reposcan"
	"vulns-news/src/scananalyze"
)

const rejectedCitationText = "REJECTED_MODEL_OUTPUT_MUST_NOT_BE_REPLAYED"
const secondCitationAdvisoryID = "GHSA-3456-789c-fghj"

type citationReply struct {
	stage  string
	defect string
}

type citationRequest struct {
	Model    string          `json:"model"`
	Messages []llm.Message   `json:"messages"`
	Stream   bool            `json:"stream"`
	Think    bool            `json:"think"`
	Format   json.RawMessage `json:"format"`

	stage      string
	input      processor.Input
	checkpoint scananalyze.Report
}

type citationServer struct {
	url      string
	mu       sync.Mutex
	requests []citationRequest
}

// Unlike a schema-enforcing model, this server deliberately returns invalid
// citations so the real CLI, transport, processor and checkpoint path handle them.
func newCitationServer(t *testing.T, scan savedScan, replies ...citationReply) *citationServer {
	t.Helper()
	h := &citationServer{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/chat" {
			t.Errorf("unexpected Ollama endpoint: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected endpoint", http.StatusBadRequest)
			return
		}
		var request citationRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || len(request.Messages) != 2 {
			t.Errorf("invalid Ollama request: %+v, %v", request, err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(request.Format, &schema); err != nil {
			t.Errorf("decode response schema: %v", err)
			http.Error(w, "invalid schema", http.StatusBadRequest)
			return
		}
		request.stage = "analysis"
		if _, ok := schema.Properties["relevance"]; ok {
			request.stage = "screening"
		}
		material := request.Messages[1].Content
		const prefix = "BEGIN_UNTRUSTED_ANALYSIS_MATERIAL\n"
		const suffix = "\nEND_UNTRUSTED_ANALYSIS_MATERIAL"
		if !strings.HasPrefix(material, prefix) || !strings.HasSuffix(material, suffix) {
			t.Error("processor lost the untrusted-material delimiters")
		}
		if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(material, prefix), suffix)), &request.input); err != nil {
			t.Errorf("decode processor material: %v", err)
			http.Error(w, "invalid material", http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(scan.output)
		if err == nil {
			err = json.Unmarshal(data, &request.checkpoint)
		}
		if err != nil {
			t.Errorf("read checkpoint during %s request: %v", request.stage, err)
		}
		h.mu.Lock()
		index := len(h.requests)
		h.requests = append(h.requests, request)
		h.mu.Unlock()
		if index >= len(replies) || replies[index].stage != request.stage {
			t.Errorf("unexpected model call %d: %s", index+1, request.stage)
			http.Error(w, "unexpected model call", http.StatusInternalServerError)
			return
		}
		reply := replies[index]
		w.Header().Set("Content-Type", "application/json")
		if reply.defect == "http" {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":"test model unavailable"}`)
			return
		}
		ids := []string{}
		for _, evidence := range request.input.Evidence {
			if reply.defect == "missing-advisory" && evidence.Kind != processor.EvidenceRepositoryDependency {
				continue
			}
			if reply.defect == "missing-repository" && evidence.Kind != processor.EvidenceAdvisory {
				continue
			}
			ids = append(ids, evidence.ID)
		}
		if reply.defect == "unknown" || reply.defect == "schema" {
			ids = []string{request.input.Vulnerability.ID}
		}
		text := "The recorded dependency matches the advisory; runtime impact remains unverified."
		if reply.defect != "" {
			text = rejectedCitationText
		}
		advisory, repository := citationWireIDs(request.input)
		switch reply.defect {
		case "missing-advisory":
			advisory = []string{}
		case "missing-repository":
			repository = []string{}
		case "unknown", "schema":
			advisory = ids
		}
		content := map[string]any{
			"relevance": "related", "reason": text,
			"advisory_evidence_ids": advisory, "repository_evidence_ids": repository,
		}
		if request.stage == "analysis" {
			validIDs := []string{}
			for _, evidence := range request.input.Evidence {
				validIDs = append(validIDs, evidence.ID)
			}
			content = map[string]any{
				"summary":             processor.SupportedClaim{Text: "The saved package version matches this advisory.", EvidenceIDs: validIDs},
				"repository_impact":   processor.SupportedClaim{Text: text, EvidenceIDs: ids},
				"missing_information": []string{"Whether the affected feature is used"},
				"recommended_actions": []string{"Review dependency usage and the source advisory"},
			}
		}
		if reply.defect == "schema" {
			// A static schema failure takes precedence even when citations are bad.
			content["unexpected_field"] = true
		}
		encoded, err := json.Marshal(content)
		if err != nil {
			t.Errorf("encode model output: %v", err)
			http.Error(w, "invalid fixture", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{
			"model": testModel, "done": true, "done_reason": "stop",
			"message":           llm.Message{Role: llm.RoleAssistant, Content: string(encoded)},
			"prompt_eval_count": 10 * (index + 1), "eval_count": 3 * (index + 1),
			"total_duration": 1000 * (index + 1), "load_duration": 100 * (index + 1),
		}); err != nil {
			t.Errorf("write Ollama response: %v", err)
		}
	}))
	h.url = server.URL
	t.Cleanup(server.Close)
	restrictHTTP(t, server.URL)
	return h
}

func (h *citationServer) captured() []citationRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]citationRequest(nil), h.requests...)
}

func assertCitationRequests(t *testing.T, h *citationServer, scan savedScan, stages ...string) []citationRequest {
	t.Helper()
	requests := h.captured()
	gotStages := []string{}
	for _, request := range requests {
		gotStages = append(gotStages, request.stage)
	}
	if !slices.Equal(gotStages, stages) {
		t.Fatalf("model stages = %v, want %v", gotStages, stages)
	}
	prepared := scananalyze.Prepare(scan.state)
	for i, request := range requests {
		if request.Model != testModel || request.Stream || request.Think || request.Messages[0].Role != llm.RoleSystem || request.Messages[1].Role != llm.RoleUser {
			t.Errorf("request %d lost structured generation or the system/user boundary: %+v", i+1, request)
		}
		candidateIndex := slices.IndexFunc(prepared, func(p scananalyze.Prepared) bool { return p.ID == request.input.Vulnerability.ID })
		if candidateIndex < 0 {
			t.Fatalf("request %d invented candidate %q", i+1, request.input.Vulnerability.ID)
		}
		candidate := prepared[candidateIndex]
		if !reflect.DeepEqual(request.input, candidate.Input) {
			t.Errorf("request %d changed saved scan material", i+1)
		}
		if len(request.checkpoint.Entries) != len(prepared) {
			t.Fatalf("request %d checkpoint has %d entries, want %d", i+1, len(request.checkpoint.Entries), len(prepared))
		}
		entry := request.checkpoint.Entries[candidateIndex]
		wantHash := fmt.Sprintf("%x", sha256.Sum256(encodeTestJSON(t, candidate)))
		if entry.InputHash != wantHash || entry.Stage != request.stage || entry.Analysis != nil || entry.Feed != nil {
			t.Errorf("request %d checkpoint lost input identity/stage: %+v", i+1, entry)
		}
		if request.stage == "screening" && entry.Screening != nil {
			t.Errorf("request %d cached an unvalidated screening: %+v", i+1, entry)
		}
		if request.stage == "analysis" && (entry.Screening == nil || entry.Screening.Result.Relevance != processor.RelevanceRelated || entry.ScreeningHash == "") {
			t.Errorf("request %d began deep analysis before screening was durably saved: %+v", i+1, entry)
		}
		assertCitationSchema(t, request)
	}
	return requests
}

func citationSchemaObject(t *testing.T, value map[string]any, path ...string) map[string]any {
	t.Helper()
	for _, key := range path {
		next, ok := value[key].(map[string]any)
		if !ok {
			t.Fatalf("schema object %q missing in %+v", key, value)
		}
		value = next
	}
	return value
}

func citationWireIDs(input processor.Input) (advisory, repository []string) {
	advisory, repository = []string{}, []string{}
	for _, evidence := range input.Evidence {
		switch evidence.Kind {
		case processor.EvidenceNVD, processor.EvidenceAdvisory:
			advisory = append(advisory, evidence.ID)
		case processor.EvidenceRepositoryDependency, processor.EvidenceRepositorySource, processor.EvidenceStaticAnalysis:
			repository = append(repository, evidence.ID)
		}
	}
	return advisory, repository
}

func assertCitationSchema(t *testing.T, request citationRequest) {
	t.Helper()
	want := []string{}
	for _, evidence := range request.input.Evidence {
		want = append(want, evidence.ID)
	}
	slices.Sort(want)
	var outbound, static map[string]any
	if err := json.Unmarshal(request.Format, &outbound); err != nil {
		t.Fatal(err)
	}
	advisory, repository := citationWireIDs(request.input)
	fields := map[string][]string{"advisory_evidence_ids": advisory, "repository_evidence_ids": repository}
	base := processor.ScreeningSchema()
	if request.stage == "analysis" {
		fields = map[string][]string{"evidence_ids": want}
		base = processor.DeepAnalysisSchema()
	}
	for field, ids := range fields {
		path := []string{"properties", field, "items"}
		if request.stage == "analysis" {
			path = []string{"$defs", "supported_claim", "properties", field, "items"}
		}
		items := citationSchemaObject(t, outbound, path...)
		var got []string
		if err := json.Unmarshal(encodeTestJSON(t, items["enum"]), &got); err != nil {
			t.Fatalf("decode evidence enum: %v", err)
		}
		slices.Sort(got)
		slices.Sort(ids)
		if !slices.Equal(got, ids) {
			t.Errorf("%s %s enum = %v, want exact IDs by kind %v", request.stage, field, got, ids)
		}
		delete(items, "enum")
	}
	if err := json.Unmarshal(base, &static); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(outbound, static) {
		t.Errorf("%s request changed static schema constraints beyond the evidence enum", request.stage)
	}
	catalog := regexp.MustCompile(`EVD-[A-Z0-9][A-Z0-9_-]{0,63}`).FindAllString(request.Messages[0].Content, -1)
	slices.Sort(catalog)
	catalog = slices.Compact(catalog)
	if !slices.Equal(catalog, want) {
		t.Errorf("%s system prompt ID catalog = %v, want %v", request.stage, catalog, want)
	}
	if strings.Contains(request.Messages[0].Content, request.input.Vulnerability.ID) {
		t.Error("system prompt includes the advisory ID instead of only backend-assigned evidence IDs")
	}
}

func assertCitationRetry(t *testing.T, first, retry citationRequest) {
	t.Helper()
	if first.stage != retry.stage || first.Messages[1] != retry.Messages[1] || !bytes.Equal(first.Format, retry.Format) {
		t.Error("citation retry changed stage, original material, or the response schema")
	}
	if first.Messages[0].Content == retry.Messages[0].Content {
		t.Error("citation retry lacks system correction guidance")
	}
	for _, message := range retry.Messages {
		if strings.Contains(message.Content, rejectedCitationText) {
			t.Error("citation retry replayed rejected model output")
		}
	}
	if !reflect.DeepEqual(first.checkpoint, retry.checkpoint) {
		t.Error("invalid citation attempt changed the durable checkpoint before correction succeeded")
	}
}

func assertCitationGeneration(t *testing.T, generation processor.Generation, attempts ...int) {
	t.Helper()
	sum := 0
	for _, attempt := range attempts {
		sum += attempt
	}
	if generation.Model != testModel || generation.DoneReason != "stop" || generation.PromptTokens != 10*sum || generation.CompletionTokens != 3*sum || generation.TotalDurationNS != int64(1000*sum) || generation.LoadDurationNS != int64(100*sum) {
		t.Errorf("generation did not aggregate attempts %v: %+v", attempts, generation)
	}
	var serialized map[string]json.RawMessage
	if err := json.Unmarshal(encodeTestJSON(t, generation), &serialized); err != nil {
		t.Fatal(err)
	}
	value, exists := serialized["citation_retries"]
	if len(attempts) == 1 {
		if exists {
			t.Errorf("zero citation_retries must remain absent for cached-output compatibility: %s", value)
		}
	} else if string(value) != "1" {
		t.Errorf("citation_retries = %s, want 1", value)
	}
}

func assertCitationCompletion(t *testing.T, report scananalyze.Report, count int) {
	t.Helper()
	if !report.Complete || !report.SelectedComplete || report.TotalCandidates != count || report.SelectedCandidates != count || report.Screened != count || report.Analyzed != count || report.Errors != 0 || report.Pending != 0 || len(report.Entries) != count {
		t.Fatalf("incomplete corrected report: %+v", report)
	}
	for _, entry := range report.Entries {
		if entry.Status != "analyzed" || entry.Stage != "complete" || entry.Error != "" || entry.Screening == nil || entry.Analysis == nil || entry.Feed == nil || entry.Feed.Status != feed.StatusAnalyzed || entry.ScreeningHash == "" || entry.AnalysisHash == "" {
			t.Fatalf("corrected pipeline did not reach Feed: %+v", entry)
		}
		if entry.Feed.VulnerabilityID != entry.ID || len(entry.Feed.Generation) != 2 || !reflect.DeepEqual(entry.Feed.Generation, []processor.Generation{entry.Screening.Generation, entry.Analysis.Generation}) {
			t.Errorf("Feed lost advisory identity or retry generation metadata: %+v", entry.Feed)
		}
		if bytes.Contains(encodeTestJSON(t, entry), []byte(rejectedCitationText)) {
			t.Error("rejected model content leaked into the saved output or Feed")
		}
	}
}

func assertCitationCachedResume(t *testing.T, scan savedScan, h *citationServer, args []string, report scananalyze.Report) {
	t.Helper()
	before := len(h.captured())
	stdout, log, err := runCLI(t, append(args, "-resume"))
	if err != nil {
		t.Fatalf("cached resume: %v\n%s", err, log)
	}
	resumed := assertSavedReport(t, scan, stdout)
	if !reflect.DeepEqual(resumed.Entries, report.Entries) || resumed.SnapshotHash != report.SnapshotHash || resumed.StartedAt != report.StartedAt {
		t.Error("cached resume changed outputs, checksums, or snapshot identity")
	}
	if len(h.captured()) != before || strings.Contains(log, ": screening") || strings.Contains(log, ": analysis") {
		t.Errorf("cached resume repeated model work:\n%s", log)
	}
	if !bytes.Equal(readTestFile(t, scan.path), scan.originalBytes) {
		t.Error("analysis/resume changed the original scan")
	}
}

func TestRunCitationRetryCorrectsSavedScanAndResumes(t *testing.T) {
	for _, defect := range []string{"unknown", "missing-advisory", "missing-repository"} {
		t.Run(defect, func(t *testing.T) {
			scan := newSavedScan(t, true)
			replies := []citationReply{{stage: "screening", defect: defect}, {stage: "screening"}}
			if defect == "unknown" {
				replies = append(replies, citationReply{stage: "analysis", defect: "unknown"})
			}
			replies = append(replies, citationReply{stage: "analysis"})
			h := newCitationServer(t, scan, replies...)
			args := append(scan.args(h.url), "-require-deep")
			stdout, log, err := runCLI(t, args)
			if err != nil {
				t.Fatalf("correctable citation failed: %v\n%s", err, log)
			}
			report := assertSavedReport(t, scan, stdout)
			assertCitationCompletion(t, report, 1)
			stages := []string{"screening", "screening", "analysis"}
			if defect == "unknown" {
				stages = append(stages, "analysis")
			}
			requests := assertCitationRequests(t, h, scan, stages...)
			assertCitationRetry(t, requests[0], requests[1])
			entry := report.Entries[0]
			assertCitationGeneration(t, entry.Screening.Generation, 1, 2)
			if defect == "unknown" {
				assertCitationRetry(t, requests[2], requests[3])
				assertCitationGeneration(t, entry.Analysis.Generation, 3, 4)
			} else {
				assertCitationGeneration(t, entry.Analysis.Generation, 3)
			}
			if !reflect.DeepEqual(requests[2].checkpoint.Entries[0].Screening, entry.Screening) {
				t.Error("corrected screening and its aggregated usage were not checkpointed before Deep")
			}
			assertCitationCachedResume(t, scan, h, args, report)
		})
	}
}

type twoCitationOSV struct{}

func (twoCitationOSV) Query(_ context.Context, queries []osv.PackageVersion) []osv.QueryResult {
	results := make([]osv.QueryResult, len(queries))
	for i, query := range queries {
		results[i] = osv.QueryResult{Query: query, Complete: true, IDs: []string{testAdvisoryID, secondCitationAdvisoryID}}
	}
	return results
}

func (twoCitationOSV) Advisory(_ context.Context, id string) (json.RawMessage, error) {
	if id != testAdvisoryID && id != secondCitationAdvisoryID {
		return nil, fmt.Errorf("unexpected advisory %q", id)
	}
	return json.RawMessage(strings.ReplaceAll(testAdvisory, testAdvisoryID, id)), nil
}

func newSavedTwoCitationScan(t *testing.T) savedScan {
	t.Helper()
	scan := newSavedScan(t, true)
	scan.path = filepath.Join(scan.dir, "two-advisories.json")
	scan.state.Report = reposcan.Run(context.Background(), scan.state.Profile, reposcan.Config{OSV: twoCitationOSV{}})
	if err := reposcan.Save(scan.path, scan.state); err != nil {
		t.Fatal(err)
	}
	var err error
	scan.state, err = reposcan.Load(scan.path)
	if err != nil {
		t.Fatal(err)
	}
	prepared := scananalyze.Prepare(scan.state)
	if len(prepared) != 2 || prepared[0].Error != "" || prepared[1].Error != "" {
		t.Fatalf("invalid two-candidate saved scan: %+v", prepared)
	}
	scan.originalBytes = readTestFile(t, scan.path)
	t.Cleanup(func() {
		if !bytes.Equal(readTestFile(t, scan.path), scan.originalBytes) {
			t.Error("CLI overwrote the two-candidate source scan")
		}
	})
	return scan
}

func TestRunCitationRetryExhaustionCheckpointsAndResumes(t *testing.T) {
	for _, stage := range []string{"screening", "analysis"} {
		t.Run(stage, func(t *testing.T) {
			scan := newSavedTwoCitationScan(t)
			replies := []citationReply{}
			stages := []string{}
			if stage == "analysis" {
				replies = append(replies, citationReply{stage: "screening"})
				stages = append(stages, "screening")
			}
			replies = append(replies, citationReply{stage: stage, defect: "unknown"}, citationReply{stage: stage, defect: "unknown"})
			stages = append(stages, stage, stage)
			failedCalls := len(replies)
			replies = append(replies, citationReply{stage: "screening"}, citationReply{stage: "analysis"})
			stages = append(stages, "screening", "analysis")
			if stage == "screening" {
				replies = append(replies, citationReply{stage: "screening"})
			}
			replies = append(replies, citationReply{stage: "analysis"})
			h := newCitationServer(t, scan, replies...)
			args := append(scan.args(h.url), "-require-deep")
			stdout, log, err := runCLI(t, args)
			if err == nil || !strings.Contains(err.Error(), "unknown evidence ID") {
				t.Fatalf("persistent citations error = %v, want unknown evidence ID\n%s", err, log)
			}
			report := assertSavedReport(t, scan, stdout)
			if report.Complete || report.SelectedComplete || report.Errors != 1 || report.Pending != 0 || report.Analyzed != 1 || len(report.Entries) != 2 {
				t.Fatalf("exhausted retry report = %+v", report)
			}
			failed, completed := report.Entries[0], report.Entries[1]
			if failed.Status != stage+"_error" || failed.Stage != stage || failed.Error == "" || failed.Analysis != nil || failed.AnalysisHash != "" || failed.Feed != nil {
				t.Fatalf("failed stage not checkpointed: %+v", failed)
			}
			if completed.Status != "analyzed" || completed.Stage != "complete" || completed.Screening == nil || completed.Analysis == nil || completed.Feed == nil || completed.Error != "" {
				t.Fatalf("later candidate was not completed: %+v", completed)
			}
			if stage == "screening" && (report.Screened != 1 || failed.Screening != nil || failed.ScreeningHash != "") {
				t.Error("invalid screening was cached")
			}
			if stage == "analysis" && (report.Screened != 2 || failed.Screening == nil || failed.ScreeningHash == "") {
				t.Fatal("successful screening was not cached before deep failure")
			}
			requests := assertCitationRequests(t, h, scan, stages...)
			assertCitationRetry(t, requests[failedCalls-2], requests[failedCalls-1])

			stdout, log, err = runCLI(t, append(args, "-resume"))
			if err != nil {
				t.Fatalf("resume after exhausted citation retry: %v\n%s", err, log)
			}
			resumed := assertSavedReport(t, scan, stdout)
			assertCitationCompletion(t, resumed, 2)
			if stage == "screening" {
				stages = append(stages, "screening")
				assertCitationGeneration(t, resumed.Entries[0].Screening.Generation, failedCalls+3)
			} else if !reflect.DeepEqual(failed.Screening, resumed.Entries[0].Screening) || failed.ScreeningHash != resumed.Entries[0].ScreeningHash {
				t.Error("resume replaced successful screening or its checksum")
			}
			stages = append(stages, "analysis")
			requests = assertCitationRequests(t, h, scan, stages...)
			assertCitationGeneration(t, resumed.Entries[0].Analysis.Generation, 6)
			assertCitationGeneration(t, resumed.Entries[1].Screening.Generation, failedCalls+1)
			assertCitationGeneration(t, resumed.Entries[1].Analysis.Generation, failedCalls+2)
			if !reflect.DeepEqual(completed, resumed.Entries[1]) {
				t.Error("resume changed the later candidate's cached success")
			}
			for _, request := range requests[failedCalls+2:] {
				if request.input.Vulnerability.ID != failed.ID {
					t.Error("resume requested a successful candidate again")
				}
			}
			if resumed.SnapshotHash != report.SnapshotHash || resumed.StartedAt != report.StartedAt {
				t.Error("resume changed snapshot identity")
			}
			for i := range report.Entries {
				if resumed.Entries[i].InputHash != report.Entries[i].InputHash {
					t.Errorf("resume changed candidate %d input hash", i)
				}
			}
			assertCitationCachedResume(t, scan, h, args, resumed)
		})
	}
}

func TestRunCitationRetryDoesNotRetrySchemaOrHTTPFailures(t *testing.T) {
	for _, stage := range []string{"screening", "analysis"} {
		for _, defect := range []string{"schema", "http"} {
			t.Run(stage+"/"+defect, func(t *testing.T) {
				scan := newSavedScan(t, true)
				replies := []citationReply{}
				stages := []string{}
				if stage == "analysis" {
					replies = append(replies, citationReply{stage: "screening"})
					stages = append(stages, "screening")
				}
				replies = append(replies, citationReply{stage: stage, defect: defect})
				stages = append(stages, stage)
				h := newCitationServer(t, scan, replies...)
				stdout, log, err := runCLI(t, scan.args(h.url))
				wantError := "JSON"
				if defect == "http" {
					wantError = "503"
				}
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("run error = %v, want %s failure\n%s", err, wantError, log)
				}
				report := assertSavedReport(t, scan, stdout)
				if report.Complete || report.Errors != 1 || report.Analyzed != 0 || len(report.Entries) != 1 {
					t.Fatalf("failed report = %+v", report)
				}
				entry := report.Entries[0]
				if entry.Status != stage+"_error" || entry.Stage != stage || entry.Error == "" || entry.Analysis != nil || entry.Feed != nil {
					t.Errorf("failed-stage checkpoint = %+v", entry)
				}
				assertCitationRequests(t, h, scan, stages...)
			})
		}
	}
}
