package scananalyze_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"vulns-news/src/feed"
	"vulns-news/src/llm"
	"vulns-news/src/osv"
	"vulns-news/src/processor"
	"vulns-news/src/reposcan"
	"vulns-news/src/scananalyze"
)

func runScreen(input processor.Input, relevance processor.Relevance) processor.ScreeningOutput {
	ids := []string{}
	for _, e := range input.Evidence {
		if e.Kind == processor.EvidenceAdvisory || e.Kind == processor.EvidenceRepositoryDependency {
			ids = append(ids, e.ID)
		}
	}
	return processor.ScreeningOutput{
		Result:     processor.ScreeningResult{Relevance: relevance, Reason: "Exact dependency query evidence; runtime impact remains unknown", EvidenceIDs: ids},
		Generation: processor.Generation{Model: "runner-model", DoneReason: "stop"},
	}
}

func runScreenWire(input processor.Input, relevance processor.Relevance) map[string]any {
	advisory, repository := []string{}, []string{}
	for _, e := range input.Evidence {
		switch e.Kind {
		case processor.EvidenceNVD, processor.EvidenceAdvisory:
			advisory = append(advisory, e.ID)
		case processor.EvidenceRepositoryDependency, processor.EvidenceRepositorySource, processor.EvidenceStaticAnalysis:
			repository = append(repository, e.ID)
		}
	}
	return map[string]any{"relevance": relevance, "reason": "Recorded dependency matches; runtime impact remains unknown",
		"advisory_evidence_ids": advisory, "repository_evidence_ids": repository}
}

func runAnalysis(input processor.Input) processor.AnalysisOutput {
	claim := processor.SupportedClaim{Text: "Dependency evidence only; runtime impact remains unknown", EvidenceIDs: runScreen(input, processor.RelevanceRelated).Result.EvidenceIDs}
	return processor.AnalysisOutput{
		Analysis:   processor.DeepAnalysis{Summary: claim, RepositoryImpact: claim, MissingInformation: []string{"Runtime reachability"}, RecommendedActions: []string{"Review the source advisory"}},
		Generation: processor.Generation{Model: "runner-model", DoneReason: "stop"},
	}
}

type runAnalyzer struct {
	screens, analyses int
	relevance         processor.Relevance
	screen            func(processor.Input) (processor.ScreeningOutput, error)
	analyze           func(processor.Input) (processor.AnalysisOutput, error)
}

func (a *runAnalyzer) Screen(_ context.Context, input processor.Input) (processor.ScreeningOutput, error) {
	a.screens++
	if a.screen != nil {
		return a.screen(input)
	}
	relevance := a.relevance
	if relevance == "" {
		relevance = processor.RelevanceRelated
	}
	return runScreen(input, relevance), nil
}

func (a *runAnalyzer) Analyze(_ context.Context, input processor.Input) (processor.AnalysisOutput, error) {
	a.analyses++
	if a.analyze != nil {
		return a.analyze(input)
	}
	return runAnalysis(input), nil
}

func runOutputHash(t *testing.T, inputHash, stage string, output any) string {
	t.Helper()
	data := prepareJSON(t, struct {
		InputHash string `json:"input_hash"`
		Stage     string `json:"stage"`
		Output    any    `json:"output"`
	}{InputHash: inputHash, Stage: stage, Output: output})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func assertRunOutputHashes(t *testing.T, r scananalyze.Report) {
	t.Helper()
	for _, e := range r.Entries {
		var encoded map[string]json.RawMessage
		if err := json.Unmarshal(prepareJSON(t, e), &encoded); err != nil {
			t.Fatal(err)
		}
		for _, output := range []struct {
			stage, hash string
			value       any
			present     bool
		}{
			{"screening", e.ScreeningHash, e.Screening, e.Screening != nil},
			{"analysis", e.AnalysisHash, e.Analysis, e.Analysis != nil},
		} {
			want := ""
			if output.present {
				want = runOutputHash(t, e.InputHash, output.stage, output.value)
			}
			_, serialized := encoded[output.stage+"_hash"]
			if output.hash != want || serialized != output.present {
				t.Fatalf("%s %s checksum = %q, want %q; serialized=%t", e.ID, output.stage, output.hash, want, serialized)
			}
		}
	}
}

func assertRunChecksumRejected(t *testing.T, state reposcan.State, cfg scananalyze.Config, r scananalyze.Report, stage string) {
	t.Helper()
	checkpoints := 0
	cfg.Checkpoint = func(scananalyze.Report) error { checkpoints++; return nil }
	a := &runAnalyzer{}
	_, err := scananalyze.Run(context.Background(), state, a, cfg, &r)
	if err == nil || !strings.Contains(err.Error(), "cached "+stage+" checksum mismatch") || checkpoints != 0 || a.screens != 0 || a.analyses != 0 {
		t.Fatalf("invalid %s checksum reached side effects: %v, checkpoints=%d, analyzer=%+v", stage, err, checkpoints, a)
	}
}

func runConfig() scananalyze.Config {
	return scananalyze.Config{Model: "runner-model", BaseURL: "http://llm.example.test"}
}

func runClone[T any](t *testing.T, value T) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(prepareJSON(t, value), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func runGroups(t *testing.T, count int) reposcan.State {
	t.Helper()
	records := map[string]json.RawMessage{}
	ids := []string{}
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("GHSA-group-%03d", i)
		ids = append(ids, id)
		records[id] = prepareRaw(t, id, "crates.io", "widget", nil, nil)
	}
	return prepareScan(t, prepareProfile(), prepareOSV{records: records, ids: func(osv.PackageVersion) []string { return ids }})
}

type runReply struct {
	stage   string
	content string
	status  int
	cancel  context.CancelFunc
}

type runHTTP struct {
	processor *processor.Processor
	config    scananalyze.Config
	mu        sync.Mutex
	stages    []string
}

// No fake analyzer/generator is used here: requests travel through Run's
// pipeline.Process, processor schema/evidence validation and llm's HTTP client.
func newRunHTTP(t *testing.T, replies ...runReply) *runHTTP {
	t.Helper()
	h := &runHTTP{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/chat" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var request struct {
			Model    string        `json:"model"`
			Messages []llm.Message `json:"messages"`
			Stream   bool          `json:"stream"`
			Think    bool          `json:"think"`
			Format   struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"format"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode chat request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if request.Model != "runner-model" || request.Stream || request.Think || len(request.Messages) != 2 || len(request.Format.Properties) == 0 {
			t.Errorf("invalid structured request: %+v", request)
		}
		stage := "analysis"
		if _, ok := request.Format.Properties["relevance"]; ok {
			stage = "screening"
			var input processor.Input
			material := strings.TrimSuffix(strings.TrimPrefix(request.Messages[1].Content, "BEGIN_UNTRUSTED_ANALYSIS_MATERIAL\n"), "\nEND_UNTRUSTED_ANALYSIS_MATERIAL")
			if err := json.Unmarshal([]byte(material), &input); err != nil {
				t.Errorf("decode input: %v", err)
			}
			wire := runScreenWire(input, processor.RelevanceRelated)
			if _, exists := request.Format.Properties["evidence_ids"]; exists {
				t.Error("screening schema still accepts generic evidence_ids")
			}
			for _, field := range []string{"advisory_evidence_ids", "repository_evidence_ids"} {
				var property struct {
					Items struct {
						Enum []string `json:"enum"`
					} `json:"items"`
				}
				if err := json.Unmarshal(request.Format.Properties[field], &property); err != nil {
					t.Errorf("decode %s schema: %v", field, err)
				}
				got, want := property.Items.Enum, wire[field].([]string)
				slices.Sort(got)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Errorf("%s enum = %v, want IDs by kind %v", field, got, want)
				}
			}
		}
		h.mu.Lock()
		index := len(h.stages)
		h.stages = append(h.stages, stage)
		h.mu.Unlock()
		if index >= len(replies) {
			t.Errorf("unexpected extra %s request", stage)
			http.Error(w, "unexpected extra request", http.StatusInternalServerError)
			return
		}
		reply := replies[index]
		if stage != reply.stage {
			t.Errorf("request %d stage = %s, want %s", index, stage, reply.stage)
		}
		if reply.cancel != nil {
			reply.cancel()
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if reply.status != 0 {
			w.WriteHeader(reply.status)
			_, _ = w.Write([]byte(`{"error":"model service unavailable"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": "runner-model", "done": true, "done_reason": "stop",
			"message":           map[string]string{"role": "assistant", "content": reply.content},
			"prompt_eval_count": 20, "eval_count": 10,
		})
	}))
	t.Cleanup(server.Close)
	client, err := llm.NewClient(llm.Config{Model: "runner-model", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	h.processor, err = processor.New(client)
	if err != nil {
		t.Fatal(err)
	}
	h.config = scananalyze.Config{Model: "runner-model", BaseURL: server.URL}
	return h
}

func (h *runHTTP) calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.stages...)
}

func TestRunHTTPPipeline(t *testing.T) {
	for _, tc := range []struct {
		name      string
		relevance processor.Relevance
		kind      any
		cve       bool
		status    string
	}{
		{"related-cve", processor.RelevanceRelated, nil, true, "analyzed"},
		{"maintenance-non-cve", processor.RelevanceRelated, "unmaintained", false, "analyzed"},
		{"unknown", processor.RelevanceUnknown, "unmaintained", false, "screening_only"},
		{"possibly-related", processor.RelevancePossiblyRelated, "unsound", false, "screening_only"},
		{"unrelated", processor.RelevanceUnrelated, nil, false, "excluded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extra := map[string]any{}
			if tc.cve {
				extra["aliases"] = []string{"CVE-2026-1000"}
			}
			state := prepareBasicState(t, tc.kind, extra)
			before := string(prepareJSON(t, state))
			p := prepareOne(t, state)
			replies := []runReply{{stage: "screening", content: string(prepareJSON(t, runScreenWire(p.Input, tc.relevance)))}}
			deep := tc.relevance == processor.RelevanceRelated
			if deep {
				replies = append(replies, runReply{stage: "analysis", content: string(prepareJSON(t, runAnalysis(p.Input).Analysis))})
			}
			h := newRunHTTP(t, replies...)
			var checkpoints []scananalyze.Report
			h.config.Checkpoint = func(r scananalyze.Report) error {
				assertRunOutputHashes(t, r)
				checkpoints = append(checkpoints, r)
				return nil
			}
			var progress []string
			h.config.Progress = func(message string) {
				stage := "screening"
				if len(progress) == 1 {
					stage = "analysis"
				}
				if len(h.calls()) != len(progress) || !strings.Contains(message, p.ID) || !strings.Contains(message, stage) {
					t.Fatalf("progress not before candidate/stage request: %s; calls=%v", message, h.calls())
				}
				progress = append(progress, message)
			}
			r, err := scananalyze.Run(context.Background(), state, h.processor, h.config, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !r.Complete || !r.SelectedComplete || r.TotalCandidates != 1 || r.SelectedCandidates != 1 || r.Errors != 0 || r.Pending != 0 || r.Screened != 1 || r.Entries[0].Status != tc.status {
				t.Fatalf("unexpected report: %+v", r)
			}
			if r.Repository != state.Profile.Repository || r.ScanStatus != state.Report.Status || r.ScanRefreshComplete != state.Report.RefreshComplete || r.Model != h.config.Model || r.BaseURL != h.config.BaseURL {
				t.Fatal("report lost snapshot/options")
			}
			sum := sha256.Sum256([]byte(before))
			if r.SnapshotHash != hex.EncodeToString(sum[:]) || len(r.Entries[0].InputHash) != 64 || r.StartedAt.IsZero() || r.UpdatedAt.Before(r.StartedAt) {
				t.Fatal("missing fingerprint or timestamps")
			}
			wantCheckpoints := 3
			if deep {
				wantCheckpoints = 4
				if r.Analyzed != 1 || checkpoints[2].Analyzed != 1 || checkpoints[2].Pending != 1 || checkpoints[2].Entries[0].Feed != nil {
					t.Fatal("deep output was not checkpointed before feed")
				}
			} else if r.Analyzed != 0 {
				t.Fatal("screening-only/excluded run falsely claims deep analysis")
			}
			if len(checkpoints) != wantCheckpoints || len(progress) != len(replies) || len(h.calls()) != len(replies) {
				t.Fatalf("checkpoints=%d progress=%v requests=%v", len(checkpoints), progress, h.calls())
			}
			if checkpoints[0].Pending != 1 || checkpoints[0].Screened != 0 || checkpoints[0].Complete || checkpoints[1].Screened != 1 || checkpoints[1].Entries[0].Analysis != nil || checkpoints[1].Entries[0].Feed != nil || checkpoints[1].Complete {
				t.Fatal("initial/screening checkpoints changed or were not incremental")
			}
			e := r.Entries[0]
			if tc.status == "excluded" {
				if e.Feed != nil || e.Analysis != nil || r.Excluded != 1 {
					t.Fatal("unrelated candidate produced feed/deep output")
				}
			} else {
				if e.Feed == nil || e.Feed.VulnerabilityID != p.ID || e.Feed.RepositoryID != state.Profile.Repository.ID || (e.Feed.CVEID != "") != tc.cve {
					t.Fatalf("bad generic feed identity: %+v", e.Feed)
				}
				if tc.kind != nil && !reflect.DeepEqual(e.AdvisoryKinds, []string{tc.kind.(string)}) {
					t.Fatal("advisory kind lost", e.AdvisoryKinds)
				}
				if !deep && (e.Feed.Status != feed.StatusScreened || e.Feed.Summary != nil || r.ScreeningOnly != 1) {
					t.Fatal("unknown/possible relevance was forced through deep analysis")
				}
				// Serialized feed facts and prose are ignored and regenerated.
				r.Entries[0].Feed.VulnerabilityID = "forged"
				r.Entries[0].Feed.RepositoryCommit = "forged"
				r.Entries[0].Feed.ScreeningReason = "forged"
			}
			previousBytes := string(prepareJSON(t, r))
			resumed, err := scananalyze.Run(context.Background(), state, h.processor, h.config, &r)
			if err != nil || len(h.calls()) != len(replies) || !resumed.Complete || !resumed.StartedAt.Equal(r.StartedAt) {
				t.Fatalf("completed resume: %+v, %v, calls=%v", resumed, err, h.calls())
			}
			if tc.status != "excluded" {
				want, err := feed.Build(p.Input, *resumed.Entries[0].Screening, resumed.Entries[0].Analysis)
				if err != nil || !reflect.DeepEqual(*resumed.Entries[0].Feed, want) {
					t.Fatal("resume trusted serialized feed", err)
				}
			}
			if before != string(prepareJSON(t, state)) || previousBytes != string(prepareJSON(t, r)) {
				t.Fatal("Run mutated state or previous report")
			}
		})
	}
}

func TestRunHTTPAliasDedup(t *testing.T) {
	records := map[string]json.RawMessage{
		"GHSA-alias":        prepareRaw(t, "GHSA-alias", "crates.io", "widget", nil, map[string]any{"aliases": []string{"RUSTSEC-2026-0001", "CVE-2026-1000"}}),
		"RUSTSEC-2026-0001": prepareRaw(t, "RUSTSEC-2026-0001", "crates.io", "widget", "unmaintained", map[string]any{"aliases": []string{"GHSA-alias", "CVE-2026-1000"}}),
	}
	state := prepareScan(t, prepareProfile(), prepareOSV{records: records, ids: func(osv.PackageVersion) []string { return []string{"GHSA-alias", "RUSTSEC-2026-0001", "GHSA-alias"} }})
	p := prepareOne(t, state)
	h := newRunHTTP(t,
		runReply{stage: "screening", content: string(prepareJSON(t, runScreenWire(p.Input, processor.RelevanceRelated)))},
		runReply{stage: "analysis", content: string(prepareJSON(t, runAnalysis(p.Input).Analysis))},
	)
	r, err := scananalyze.Run(context.Background(), state, h.processor, h.config, nil)
	if err != nil || r.TotalCandidates != 1 || r.Analyzed != 1 || len(h.calls()) != 2 || len(r.Entries[0].RecordKeys) != 2 || len(r.Entries[0].IDs) != 3 || r.Entries[0].ID != "CVE-2026-1000" {
		t.Fatalf("aliases were not processed as one group: %+v, %v, %v", r, err, h.calls())
	}
}

func TestRunHTTPFailuresAndResume(t *testing.T) {
	for _, tc := range []struct {
		name, stage, content string
		status               int
	}{
		{"screening-http", "screening", "", http.StatusServiceUnavailable},
		{"screening-json", "screening", `{"relevance":"invented"}`, 0},
		{"analysis-http", "analysis", "", http.StatusInternalServerError},
		{"analysis-json", "analysis", `{"summary":{"text":"invented","evidence_ids":["EVD-FORGED"]}}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := runGroups(t, 2)
			prepared := scananalyze.Prepare(state)
			p := prepared[0]
			screen := runReply{stage: "screening", content: string(prepareJSON(t, runScreenWire(p.Input, processor.RelevanceRelated)))}
			deep := runReply{stage: "analysis", content: string(prepareJSON(t, runAnalysis(p.Input).Analysis))}
			replies := []runReply{}
			if tc.stage == "analysis" {
				replies = append(replies, screen)
			}
			replies = append(replies, runReply{stage: tc.stage, content: tc.content, status: tc.status},
				runReply{stage: "screening", content: string(prepareJSON(t, runScreenWire(prepared[1].Input, processor.RelevanceRelated)))},
				runReply{stage: "analysis", content: string(prepareJSON(t, runAnalysis(prepared[1].Input).Analysis))})
			firstCalls := len(replies)
			if tc.stage == "screening" {
				replies = append(replies, screen)
			}
			replies = append(replies, deep)
			h := newRunHTTP(t, replies...)
			var saved []scananalyze.Report
			h.config.Checkpoint = func(r scananalyze.Report) error { saved = append(saved, r); return nil }
			r, err := scananalyze.Run(context.Background(), state, h.processor, h.config, nil)
			if err == nil || r.Errors != 1 || r.Complete || r.SelectedComplete || r.Pending != 0 || r.Analyzed != 1 || r.Entries[1].Status != "analyzed" || r.Entries[0].Feed != nil || r.Entries[0].Status != tc.stage+"_error" || len(h.calls()) != firstCalls {
				t.Fatalf("failure turned into success: %+v, %v", r, err)
			}
			if tc.status != 0 {
				var httpErr *llm.HTTPError
				if !errors.As(err, &httpErr) || httpErr.StatusCode != tc.status {
					t.Fatalf("HTTP error identity lost: %v", err)
				}
			}
			if (r.Entries[0].Screening != nil) != (tc.stage == "analysis") || saved[len(saved)-1].Errors != 1 {
				t.Fatal("completed screening lost or error not checkpointed")
			}
			resumed, err := scananalyze.Run(context.Background(), state, h.processor, h.config, &r)
			if err != nil || !resumed.Complete || resumed.Errors != 0 || resumed.Screened != 2 || resumed.Analyzed != 2 || len(h.calls()) != len(replies) {
				t.Fatalf("failed-stage retry: %+v, %v, calls=%v", resumed, err, h.calls())
			}
			if !reflect.DeepEqual(r.Entries[1], resumed.Entries[1]) || (r.Entries[0].Screening != nil && !reflect.DeepEqual(r.Entries[0].Screening, resumed.Entries[0].Screening)) {
				t.Error("resume replaced cached successes")
			}
			if _, err := scananalyze.Run(context.Background(), state, h.processor, h.config, &resumed); err != nil || len(h.calls()) != len(replies) {
				t.Fatal("complete entry requested again", err, h.calls())
			}
		})
	}
}

func TestRunServiceFailuresContinueAndResume(t *testing.T) {
	state := runGroups(t, 3)
	prepared := scananalyze.Prepare(state)
	replies := []runReply{
		{stage: "screening", status: http.StatusServiceUnavailable},
		{stage: "screening", status: http.StatusBadGateway},
	}
	for _, i := range []int{2, 0, 1} {
		replies = append(replies,
			runReply{stage: "screening", content: string(prepareJSON(t, runScreenWire(prepared[i].Input, processor.RelevanceRelated)))},
			runReply{stage: "analysis", content: string(prepareJSON(t, runAnalysis(prepared[i].Input).Analysis))})
	}
	h := newRunHTTP(t, replies...)
	var checkpoints []scananalyze.Report
	h.config.Checkpoint = func(r scananalyze.Report) error { checkpoints = append(checkpoints, r); return nil }
	r, err := scananalyze.Run(context.Background(), state, h.processor, h.config, nil)
	if err == nil || len(h.calls()) != 4 || r.Errors != 2 || r.Pending != 0 || r.Analyzed != 1 || r.Complete || r.SelectedComplete {
		t.Fatalf("service failures prevented independent work: %+v, %v, calls=%v", r, err, h.calls())
	}
	for i := 0; i < 2; i++ {
		if !strings.Contains(err.Error(), prepared[i].ID) || r.Entries[i].Status != "screening_error" || checkpoints[i+1].Entries[i].Error == "" {
			t.Fatalf("candidate failure missing from aggregate/checkpoint: %v, %+v", err, checkpoints)
		}
	}
	resumed, err := scananalyze.Run(context.Background(), state, h.processor, h.config, &r)
	if err != nil || !resumed.Complete || resumed.Analyzed != 3 || len(h.calls()) != len(replies) || !reflect.DeepEqual(r.Entries[2], resumed.Entries[2]) {
		t.Fatalf("resume did not retain later success: %+v, %v, calls=%v", resumed, err, h.calls())
	}
}

func TestRunCheckpointBoundariesAndResume(t *testing.T) {
	state := runGroups(t, 2)
	stop := errors.New("checkpoint disk failure")
	for failAt := 1; failAt <= 4; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			cfg := runConfig()
			calls := 0
			cfg.Checkpoint = func(r scananalyze.Report) error {
				calls++
				assertRunOutputHashes(t, r)
				if calls == failAt {
					return stop
				}
				return nil
			}
			a := &runAnalyzer{}
			r, err := scananalyze.Run(context.Background(), state, a, cfg, nil)
			wantScreens, wantDeep := 0, 0
			if failAt >= 2 {
				wantScreens = 1
			}
			if failAt >= 3 {
				wantDeep = 1
			}
			if !errors.Is(err, stop) || calls != failAt || a.screens != wantScreens || a.analyses != wantDeep || r.Screened != wantScreens || r.Analyzed != wantDeep || r.Errors != 0 {
				t.Fatalf("checkpoint failure did not abort immediately: %+v %v calls=%d analyzer=%+v", r, err, calls, a)
			}
			if r.Entries[1].Status != "pending" || r.Entries[1].Screening != nil {
				t.Fatal("checkpoint failure started the next candidate")
			}
			cfg.Checkpoint = nil
			next := &runAnalyzer{}
			resumed, err := scananalyze.Run(context.Background(), state, next, cfg, &r)
			if err != nil || !resumed.Complete || next.screens != 2-wantScreens || next.analyses != 2-wantDeep {
				t.Fatalf("checkpoint outputs not reusable: %+v, %v, %+v", resumed, err, next)
			}
		})
	}
}

func TestRunCheckpointIsolation(t *testing.T) {
	state := prepareBasicState(t, nil, nil)
	before := string(prepareJSON(t, state))
	cfg := runConfig()
	var snapshots []scananalyze.Report
	cfg.Checkpoint = func(r scananalyze.Report) error {
		snapshots = append(snapshots, runClone(t, r))
		r.Entries[0].IDs[0] = "forged"
		if r.Entries[0].Screening != nil {
			r.Entries[0].Screening.Result.EvidenceIDs[0] = "EVD-FORGED"
		}
		if r.Entries[0].Analysis != nil {
			r.Entries[0].Analysis.Analysis.Summary.Text = "forged"
		}
		return nil
	}
	r, err := scananalyze.Run(context.Background(), state, &runAnalyzer{}, cfg, nil)
	if err != nil || !r.Complete || r.Entries[0].IDs[0] == "forged" || r.Entries[0].Analysis.Analysis.Summary.Text == "forged" || before != string(prepareJSON(t, state)) {
		t.Fatalf("callback mutated live run: %+v, %v", r, err)
	}
	if snapshots[0].Entries[0].Screening != nil || snapshots[1].Entries[0].Analysis != nil || snapshots[2].Entries[0].Feed != nil {
		t.Fatal("retained checkpoints changed after later stages")
	}
}

func TestRunResumeRejectsOutputChecksumCorruption(t *testing.T) {
	state := runGroups(t, 2)
	prepared := scananalyze.Prepare(state)
	cfg := runConfig()
	a := &runAnalyzer{
		screen: func(in processor.Input) (processor.ScreeningOutput, error) {
			out := runScreen(in, processor.RelevanceRelated)
			out.Result.Reason += " for " + in.Vulnerability.ID
			return out, nil
		},
		analyze: func(in processor.Input) (processor.AnalysisOutput, error) {
			out := runAnalysis(in)
			out.Analysis.Summary.Text += " for " + in.Vulnerability.ID
			return out, nil
		},
	}
	base, err := scananalyze.Run(context.Background(), state, a, cfg, nil)
	if err != nil || len(base.Entries) != 2 || base.Entries[0].InputHash == base.Entries[1].InputHash {
		t.Fatalf("invalid two-candidate fixture: %+v %v", base, err)
	}
	for _, stage := range []string{"screening", "analysis"} {
		for _, mutation := range []string{"swapped-payload", "swapped-payload-and-hash", "changed-text", "changed-metadata", "missing-hash", "wrong-input", "wrong-stage"} {
			t.Run(stage+"/"+mutation, func(t *testing.T) {
				r := runClone(t, base)
				first, second := &r.Entries[0], &r.Entries[1]
				if stage == "screening" {
					switch mutation {
					case "swapped-payload", "swapped-payload-and-hash":
						first.Screening, second.Screening = second.Screening, first.Screening
						if mutation == "swapped-payload-and-hash" {
							first.ScreeningHash, second.ScreeningHash = second.ScreeningHash, first.ScreeningHash
						}
					case "changed-text":
						first.Screening.Result.Reason += " changed"
					case "changed-metadata":
						first.Screening.Generation.CompletionTokens++
					case "missing-hash":
						first.ScreeningHash = ""
					case "wrong-input":
						first.ScreeningHash = runOutputHash(t, second.InputHash, stage, first.Screening)
					case "wrong-stage":
						first.ScreeningHash = runOutputHash(t, first.InputHash, "analysis", first.Screening)
					}
				} else {
					switch mutation {
					case "swapped-payload", "swapped-payload-and-hash":
						first.Analysis, second.Analysis = second.Analysis, first.Analysis
						if mutation == "swapped-payload-and-hash" {
							first.AnalysisHash, second.AnalysisHash = second.AnalysisHash, first.AnalysisHash
						}
					case "changed-text":
						first.Analysis.Analysis.Summary.Text += " changed"
					case "changed-metadata":
						first.Analysis.Generation.CompletionTokens++
					case "missing-hash":
						first.AnalysisHash = ""
					case "wrong-input":
						first.AnalysisHash = runOutputHash(t, second.InputHash, stage, first.Analysis)
					case "wrong-stage":
						first.AnalysisHash = runOutputHash(t, first.InputHash, "screening", first.Analysis)
					}
				}
				if strings.HasPrefix(mutation, "swapped-") {
					// Reject an actual whole-output swap at the checksum boundary,
					// independently of any candidate-namespaced evidence checks.
					assertRunChecksumRejected(t, state, cfg, r, stage)
					// Also keep citations valid in the receiving input, so schema
					// validation alone cannot detect the transferred interpretation.
					for i := range r.Entries {
						ids := runScreen(prepared[i].Input, processor.RelevanceRelated).Result.EvidenceIDs
						if stage == "screening" {
							r.Entries[i].Screening.Result.EvidenceIDs = ids
						} else {
							r.Entries[i].Analysis.Analysis.Summary.EvidenceIDs = ids
							r.Entries[i].Analysis.Analysis.RepositoryImpact.EvidenceIDs = ids
						}
					}
				}
				for i, e := range r.Entries {
					if e.InputHash != base.Entries[i].InputHash {
						t.Fatal("test changed original candidate binding")
					}
					if err := processor.ValidateOutputs(prepared[i].Input, e.Screening, e.Analysis); err != nil {
						t.Fatalf("fixture must remain otherwise valid: %v", err)
					}
				}
				assertRunChecksumRejected(t, state, cfg, r, stage)
			})
		}
	}
	resumed, err := scananalyze.Run(context.Background(), state, a, cfg, &base)
	if err != nil || !resumed.Complete || a.screens != 2 || a.analyses != 2 {
		t.Fatalf("valid checksummed resume repeated calls: %+v %v %+v", resumed, err, a)
	}
	assertRunOutputHashes(t, resumed)
}

func TestRunResumeRejectsChecksumsWithoutOutputs(t *testing.T) {
	for _, preparationError := range []bool{false, true} {
		t.Run(fmt.Sprintf("preparation-error=%t", preparationError), func(t *testing.T) {
			state := runGroups(t, 2)
			if preparationError {
				record := state.Report.Records["osv:GHSA-group-000"]
				record.Raw = prepareRaw(t, record.ID, "crates.io", "widget", nil, map[string]any{"summary": 42})
				state.Report.Records["osv:GHSA-group-000"] = record
			}
			cfg := runConfig()
			cfg.Limit = 1
			stop := errors.New("stop at initial checkpoint")
			cfg.Checkpoint = func(r scananalyze.Report) error {
				assertRunOutputHashes(t, r)
				return stop
			}
			base, err := scananalyze.Run(context.Background(), state, &runAnalyzer{}, cfg, nil)
			if !errors.Is(err, stop) {
				t.Fatal(err)
			}
			for i, e := range base.Entries {
				for _, stage := range []string{"screening", "analysis"} {
					t.Run(e.Status+"/"+stage, func(t *testing.T) {
						r := runClone(t, base)
						if stage == "screening" {
							r.Entries[i].ScreeningHash = strings.Repeat("a", 64)
						} else {
							r.Entries[i].AnalysisHash = strings.Repeat("b", 64)
						}
						assertRunChecksumRejected(t, state, cfg, r, stage)
					})
				}
			}
		})
	}
}

func TestRunResumeRejectsFingerprintsAndTampering(t *testing.T) {
	state := prepareBasicState(t, nil, nil)
	cfg := runConfig()
	base, err := scananalyze.Run(context.Background(), state, &runAnalyzer{}, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*reposcan.State, *scananalyze.Config, *scananalyze.Report){
		"whole-state-time": func(s *reposcan.State, _ *scananalyze.Config, _ *scananalyze.Report) {
			s.Report.FinishedAt = s.Report.FinishedAt.Add(time.Second)
		},
		"whole-state-warning": func(s *reposcan.State, _ *scananalyze.Config, _ *scananalyze.Report) {
			s.Report.Warnings = append(s.Report.Warnings, "new warning")
		},
		"raw-source-revision": func(s *reposcan.State, _ *scananalyze.Config, _ *scananalyze.Report) {
			r := s.Report.Records["osv:RUSTSEC-2026-0001"]
			r.Raw = prepareRaw(t, r.ID, "crates.io", "widget", nil, map[string]any{"modified": "2026-09-01T00:00:00Z"})
			s.Report.Records["osv:RUSTSEC-2026-0001"] = r
		},
		"model-option": func(_ *reposcan.State, c *scananalyze.Config, _ *scananalyze.Report) { c.Model = "different" },
		"url-option":   func(_ *reposcan.State, c *scananalyze.Config, _ *scananalyze.Report) { c.BaseURL += "/different" },
		"limit-option": func(_ *reposcan.State, c *scananalyze.Config, _ *scananalyze.Report) { c.Limit = 1 },
		"schema":       func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.SchemaVersion++ },
		"repository": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) {
			r.Repository.CommitSHA = "forged"
		},
		"snapshot-hash": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.SnapshotHash = "forged" },
		"input-hash": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) {
			r.Entries[0].InputHash = "forged"
		},
		"id":          func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.Entries[0].ID = "forged" },
		"aliases":     func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.Entries[0].IDs = nil },
		"record-keys": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.Entries[0].RecordKeys = nil },
		"advisory-kinds": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) {
			r.Entries[0].AdvisoryKinds = []string{"forged"}
		},
		"missing-entry": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.Entries = nil },
		"duplicate-entry": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) {
			r.Entries = append(r.Entries, r.Entries[0])
		},
		"timestamps": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) {
			r.UpdatedAt = r.StartedAt.Add(-time.Second)
		},
		"zero-start":    func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.StartedAt = time.Time{} },
		"counts":        func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.Screened++ },
		"complete-flag": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.Complete = false },
		"selected-flag": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.SelectedComplete = false },
		"scan-status":   func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.ScanStatus = "forged" },
		"scan-refresh": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) {
			r.ScanRefreshComplete = !r.ScanRefreshComplete
		},
		"unknown-status": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) {
			r.Entries[0].Status = "finished"
		},
		"stage": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) {
			r.Entries[0].Stage = "screening"
		},
		"status-error":               func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.Entries[0].Error = "failed" },
		"analysis-without-screening": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.Entries[0].Screening = nil },
		"completed-without-analysis": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) { r.Entries[0].Analysis = nil },
		"screening-schema": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) {
			r.Entries[0].Screening.Result.Relevance = "invented"
		},
		"screening-evidence": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) {
			r.Entries[0].Screening.Result.EvidenceIDs = []string{"EVD-FORGED"}
		},
		"analysis-evidence": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) {
			r.Entries[0].Analysis.Analysis.Summary.EvidenceIDs = []string{"EVD-FORGED"}
		},
		"analysis-schema": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) {
			r.Entries[0].Analysis.Analysis.Summary.Text = ""
		},
		"deep-after-unknown": func(_ *reposcan.State, _ *scananalyze.Config, r *scananalyze.Report) {
			r.Entries[0].Screening.Result.Relevance = processor.RelevanceUnknown
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			s, c, r := runClone(t, state), cfg, runClone(t, base)
			change(&s, &c, &r)
			checkpoints := 0
			c.Checkpoint = func(scananalyze.Report) error { checkpoints++; return nil }
			a := &runAnalyzer{}
			if _, err := scananalyze.Run(context.Background(), s, a, c, &r); err == nil || !strings.Contains(err.Error(), "resume") || checkpoints != 0 || a.screens != 0 || a.analyses != 0 {
				t.Fatalf("invalid resume reached side effects: %v, checkpoints=%d, %+v", err, checkpoints, a)
			}
		})
	}
}

func TestRunResumeValidatesAllEntriesBeforeSideEffects(t *testing.T) {
	state := runGroups(t, 2)
	cfg := runConfig()
	r, err := scananalyze.Run(context.Background(), state, &runAnalyzer{}, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Entries[0].Status, r.Entries[0].Stage = "pending", "screening"
	r.Entries[0].Screening, r.Entries[0].Analysis, r.Entries[0].Feed = nil, nil, nil
	r.Entries[0].ScreeningHash, r.Entries[0].AnalysisHash = "", ""
	r.Screened, r.Analyzed, r.Pending, r.Complete, r.SelectedComplete = 1, 1, 1, false, false
	r.Entries[1].Analysis.Analysis.Summary.EvidenceIDs = []string{"EVD-FORGED"}
	cfg.Checkpoint = func(scananalyze.Report) error { t.Fatal("checkpoint before full validation"); return nil }
	a := &runAnalyzer{}
	if _, err := scananalyze.Run(context.Background(), state, a, cfg, &r); err == nil || a.screens != 0 || a.analyses != 0 {
		t.Fatalf("late tamper allowed earlier requests: %v %+v", err, a)
	}
}

func TestRunLimitsZeroMatchesAndScanCompleteness(t *testing.T) {
	for _, tc := range []struct{ groups, limit, selected int }{{3, 0, 3}, {3, 1, 1}, {3, 9, 3}, {0, 0, 0}, {0, 2, 0}} {
		t.Run(fmt.Sprintf("groups=%d/limit=%d", tc.groups, tc.limit), func(t *testing.T) {
			state := runGroups(t, tc.groups)
			cfg := runConfig()
			cfg.Limit = tc.limit
			a := &runAnalyzer{relevance: processor.RelevanceUnknown}
			r, err := scananalyze.Run(context.Background(), state, a, cfg, nil)
			if err != nil || r.TotalCandidates != tc.groups || len(r.Entries) != tc.groups || r.SelectedCandidates != tc.selected || r.NotSelected != tc.groups-tc.selected || !r.SelectedComplete || r.Complete != (tc.selected == tc.groups) || r.Analyzed != 0 || r.ScreeningOnly != tc.selected || a.screens != tc.selected || a.analyses != 0 {
				t.Fatalf("incorrect limit/empty accounting: %+v, %v, %+v", r, err, a)
			}
			for _, e := range r.Entries[tc.selected:] {
				if e.Status != "not_selected" || e.Screening != nil || e.Analysis != nil || e.Feed != nil {
					t.Fatal("unselected group hidden or processed", e)
				}
			}
			if _, err := scananalyze.Run(context.Background(), state, a, cfg, &r); err != nil || a.screens != tc.selected {
				t.Fatal("limited/empty report not resumable", err)
			}
		})
	}
	t.Run("scan-incomplete-is-independent", func(t *testing.T) {
		state := prepareBasicState(t, nil, nil)
		state.Report.Status, state.Report.RefreshComplete = "incomplete", false
		r, err := scananalyze.Run(context.Background(), state, &runAnalyzer{relevance: processor.RelevanceUnknown}, runConfig(), nil)
		if err != nil || !r.Complete || r.ScanRefreshComplete || r.ScanStatus != "incomplete" || r.Analyzed != 0 {
			t.Fatalf("analysis completion confused with scan/deep coverage: %+v %v", r, err)
		}
	})
}

func TestRunPreparationErrorContinuesValidGroups(t *testing.T) {
	state := runGroups(t, 2)
	record := state.Report.Records["osv:GHSA-group-000"]
	record.Raw = prepareRaw(t, record.ID, "crates.io", "widget", nil, map[string]any{"summary": 42})
	state.Report.Records["osv:GHSA-group-000"] = record
	a := &runAnalyzer{}
	r, err := scananalyze.Run(context.Background(), state, a, runConfig(), nil)
	if err == nil || r.Errors != 1 || r.Pending != 0 || r.Screened != 1 || r.Analyzed != 1 || r.Complete || r.Entries[0].Status != "preparation_error" || r.Entries[1].Status != "analyzed" || a.screens != 1 || a.analyses != 1 {
		t.Fatalf("preparation accounting: %+v %v %+v", r, err, a)
	}
	if resumed, err := scananalyze.Run(context.Background(), state, a, runConfig(), &r); err == nil || resumed.Errors != 1 || a.screens != 1 || a.analyses != 1 {
		t.Fatal("preparation failure not retained on resume", err)
	}
}

func TestRunFeedRetryUsesCachedOutputs(t *testing.T) {
	state := runGroups(t, 2)
	cfg := runConfig()
	saved, err := scananalyze.Run(context.Background(), state, &runAnalyzer{}, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Feed errors retain both completed calls and retry only feed assembly.
	// Current feed.Build cannot fail for these validated, consistent facts.
	saved.Entries[0].Status, saved.Entries[0].Error = "feed_error", "previous feed assembly failed"
	saved.Entries[0].Stage, saved.Entries[0].Feed = "feed", nil
	saved.Errors, saved.Complete, saved.SelectedComplete = 1, false, false
	a := &runAnalyzer{}
	r, err := scananalyze.Run(context.Background(), state, a, cfg, &saved)
	if err != nil || !r.Complete || r.Entries[0].Feed == nil || a.screens != 0 || a.analyses != 0 {
		t.Fatalf("feed retry repeated model calls: %+v %v %+v", r, err, a)
	}
	if !reflect.DeepEqual(saved.Entries[1], r.Entries[1]) || !reflect.DeepEqual(saved.Entries[0].Screening, r.Entries[0].Screening) || !reflect.DeepEqual(saved.Entries[0].Analysis, r.Entries[0].Analysis) || saved.Entries[0].ScreeningHash != r.Entries[0].ScreeningHash || saved.Entries[0].AnalysisHash != r.Entries[0].AnalysisHash {
		t.Error("feed retry replaced cached model outputs or a successful candidate")
	}
}

func TestRunRejectsInvalidAnalyzerOutputs(t *testing.T) {
	for _, stage := range []string{"screening", "analysis"} {
		t.Run(stage, func(t *testing.T) {
			a := &runAnalyzer{}
			if stage == "screening" {
				a.screen = func(in processor.Input) (processor.ScreeningOutput, error) {
					out := runScreen(in, processor.RelevanceRelated)
					out.Result.EvidenceIDs = []string{"EVD-FORGED"}
					return out, nil
				}
			} else {
				a.analyze = func(in processor.Input) (processor.AnalysisOutput, error) {
					out := runAnalysis(in)
					out.Analysis.Summary.EvidenceIDs = []string{"EVD-FORGED"}
					return out, nil
				}
			}
			r, err := scananalyze.Run(context.Background(), prepareBasicState(t, nil, nil), a, runConfig(), nil)
			if err == nil || r.Errors != 1 || r.Entries[0].Status != stage+"_error" || r.Entries[0].Feed != nil || r.Entries[0].Analysis != nil || (stage == "screening" && r.Entries[0].Screening != nil) {
				t.Fatalf("unvalidated analyzer result cached: %+v %v", r, err)
			}
		})
	}
}

func TestRunFatalErrorsAfterCandidateFailure(t *testing.T) {
	for _, mode := range []string{"checkpoint", "cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			state := runGroups(t, 3)
			candidateErr := errors.New("candidate screening failed")
			checkpointErr := errors.New("cannot persist candidate failure")
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
			}
			defer cancel()
			cfg := runConfig()
			checkpoints := 0
			cfg.Checkpoint = func(r scananalyze.Report) error {
				checkpoints++
				if r.Errors == 1 {
					switch mode {
					case "checkpoint":
						return checkpointErr
					case "cancel":
						cancel()
					case "deadline":
						<-ctx.Done()
					}
				}
				return nil
			}
			a := &runAnalyzer{screen: func(processor.Input) (processor.ScreeningOutput, error) {
				return processor.ScreeningOutput{}, candidateErr
			}}
			r, err := scananalyze.Run(ctx, state, a, cfg, nil)
			want := ctx.Err()
			if mode == "checkpoint" {
				want = checkpointErr
			}
			if !errors.Is(err, candidateErr) || !errors.Is(err, want) || a.screens != 1 || a.analyses != 0 || checkpoints != 2 || r.Errors != 1 || r.Pending != 2 {
				t.Fatalf("fatal error did not stop after saved candidate failure: %+v, %v, calls=%+v, checkpoints=%d", r, err, a, checkpoints)
			}
		})
	}
}

func TestRunCancellation(t *testing.T) {
	for _, when := range []string{"before-run", "progress", "after-screening", "after-first-candidate"} {
		t.Run(when, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cfg := runConfig()
			if when == "before-run" {
				cancel()
			}
			if when == "progress" {
				cfg.Progress = func(string) { cancel() }
			}
			cfg.Checkpoint = func(r scananalyze.Report) error {
				if (when == "after-screening" && r.Screened == 1) || (when == "after-first-candidate" && r.Entries[0].Status == "analyzed") {
					cancel()
				}
				return nil
			}
			a := &runAnalyzer{}
			state := runGroups(t, 2)
			r, err := scananalyze.Run(ctx, state, a, cfg, nil)
			if !errors.Is(err, context.Canceled) || r.Complete || r.Pending == 0 || a.screens > 1 || a.analyses > 1 {
				t.Fatalf("cancellation lost: %+v, %v, %+v", r, err, a)
			}
			if when == "after-screening" && (r.Screened != 1 || a.analyses != 0 || r.Entries[0].Stage != "analysis") {
				t.Fatal("screening checkpoint was lost or deep request started after cancellation")
			}
			cfg.Checkpoint, cfg.Progress = nil, nil
			next := &runAnalyzer{}
			resumed, err := scananalyze.Run(context.Background(), state, next, cfg, &r)
			if err != nil || !resumed.Complete || next.screens+a.screens != 2 || next.analyses+a.analyses != 2 {
				t.Fatalf("canceled report not resumable: %+v, %v, %+v", resumed, err, next)
			}
		})
	}
}

func TestRunHTTPCancellationAndResume(t *testing.T) {
	for _, stage := range []string{"screening", "analysis"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			state := prepareBasicState(t, nil, nil)
			p := prepareOne(t, state)
			screen := runReply{stage: "screening", content: string(prepareJSON(t, runScreenWire(p.Input, processor.RelevanceRelated)))}
			deep := runReply{stage: "analysis", content: string(prepareJSON(t, runAnalysis(p.Input).Analysis))}
			replies := []runReply{}
			if stage == "analysis" {
				replies = append(replies, screen)
			}
			replies = append(replies, runReply{stage: stage, cancel: cancel})
			if stage == "screening" {
				replies = append(replies, screen)
			}
			replies = append(replies, deep)
			h := newRunHTTP(t, replies...)
			r, err := scananalyze.Run(ctx, state, h.processor, h.config, nil)
			if !errors.Is(err, context.Canceled) || r.Errors != 1 || r.Entries[0].Status != stage+"_error" || (r.Screened == 1) != (stage == "analysis") {
				t.Fatalf("HTTP cancellation report: %+v, %v", r, err)
			}
			resumed, err := scananalyze.Run(context.Background(), state, h.processor, h.config, &r)
			if err != nil || !resumed.Complete || len(h.calls()) != len(replies) {
				t.Fatalf("HTTP cancellation resume: %+v, %v, %v", resumed, err, h.calls())
			}
		})
	}
}

func TestRunHTTPResumeBindsEverySourceRevision(t *testing.T) {
	records := map[string]json.RawMessage{
		"GHSA-older": prepareRaw(t, "GHSA-older", "crates.io", "widget", nil, map[string]any{"aliases": []string{"GHSA-newer"}, "modified": "2026-01-01T00:00:00Z"}),
		"GHSA-newer": prepareRaw(t, "GHSA-newer", "crates.io", "widget", nil, map[string]any{"modified": "2026-03-01T00:00:00Z"}),
	}
	state := prepareScan(t, prepareProfile(), prepareOSV{records: records, ids: func(osv.PackageVersion) []string { return []string{"GHSA-older", "GHSA-newer"} }})
	p := prepareOne(t, state)
	changed := runClone(t, state)
	record := changed.Report.Records["osv:GHSA-older"]
	record.Raw = prepareRaw(t, record.ID, "crates.io", "widget", nil, map[string]any{"aliases": []string{"GHSA-newer"}, "modified": "2026-02-01T00:00:00Z"})
	changed.Report.Records["osv:GHSA-older"] = record
	next := prepareOne(t, changed)
	if p.Input.Vulnerability.ModifiedAt != next.Input.Vulnerability.ModifiedAt {
		t.Fatal("fixture must preserve the alias group's maximum revision")
	}
	h := newRunHTTP(t,
		runReply{stage: "screening", content: string(prepareJSON(t, runScreenWire(p.Input, processor.RelevanceUnknown)))},
		runReply{stage: "screening", content: string(prepareJSON(t, runScreenWire(next.Input, processor.RelevanceUnknown)))},
	)
	base, err := scananalyze.Run(context.Background(), state, h.processor, h.config, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := 0
	h.config.Checkpoint = func(scananalyze.Report) error { checkpoints++; return nil }
	if _, err := scananalyze.Run(context.Background(), changed, h.processor, h.config, &base); err == nil || checkpoints != 0 || len(h.calls()) != 1 {
		t.Fatalf("non-maximum source revision reused cache: %v, checkpoints=%d, calls=%v", err, checkpoints, h.calls())
	}
	tampered := runClone(t, base)
	tampered.Entries[0].Screening.Result.EvidenceIDs = []string{"EVD-FORGED"}
	if _, err := scananalyze.Run(context.Background(), state, h.processor, h.config, &tampered); err == nil || checkpoints != 0 || len(h.calls()) != 1 {
		t.Fatalf("invalid HTTP cache reached side effects: %v, checkpoints=%d, calls=%v", err, checkpoints, h.calls())
	}
	fresh, err := scananalyze.Run(context.Background(), changed, h.processor, h.config, nil)
	if err != nil || fresh.SnapshotHash == base.SnapshotHash || fresh.Entries[0].InputHash == base.Entries[0].InputHash || !fresh.Complete || fresh.Analyzed != 0 || len(h.calls()) != 2 {
		t.Fatalf("source revision missing from fingerprints: %+v %v", fresh, err)
	}
}

func TestRunInvalidOptionsBeforeCheckpoint(t *testing.T) {
	for _, name := range []string{"negative-limit", "missing-model", "missing-analyzer", "invalid-snapshot-json"} {
		t.Run(name, func(t *testing.T) {
			state, cfg := prepareBasicState(t, nil, nil), runConfig()
			cfg.Checkpoint = func(scananalyze.Report) error { t.Fatal("invalid options reached checkpoint"); return nil }
			a := &runAnalyzer{}
			switch name {
			case "negative-limit":
				cfg.Limit = -1
			case "missing-model":
				cfg.Model = " "
			case "missing-analyzer":
				if _, err := scananalyze.Run(context.Background(), state, nil, cfg, nil); err == nil {
					t.Fatal("nil analyzer accepted")
				}
				return
			case "invalid-snapshot-json":
				record := state.Report.Records["osv:RUSTSEC-2026-0001"]
				record.Raw = json.RawMessage(`{`)
				state.Report.Records["osv:RUSTSEC-2026-0001"] = record
			}
			if _, err := scananalyze.Run(context.Background(), state, a, cfg, nil); err == nil || a.screens != 0 || a.analyses != 0 {
				t.Fatal("invalid run reached analyzer", err)
			}
		})
	}
}
