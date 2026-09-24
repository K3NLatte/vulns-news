package processor

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/llm"
)

const validDeepResponse = `{
	"summary":{"text":"対象Packageの影響バージョンを使用しています。","evidence_ids":["EVD-NVD-001","EVD-REPO-DEP-001"]},
	"repository_impact":{"text":"影響バージョンへの直接依存は確認できましたが、対象機能の使用状況は未確認です。","evidence_ids":["EVD-NVD-001","EVD-REPO-DEP-001"]},
	"missing_information":["対象機能を実際に使用しているか","本番環境で使用中のVersion"],
	"recommended_actions":["修正版へ更新する","対象機能の使用箇所を確認する"]
}`

type fakeGenerator struct {
	response llm.ChatResponse
	err      error
	request  llm.ChatRequest
	calls    int
}

func (f *fakeGenerator) Chat(_ context.Context, request llm.ChatRequest) (llm.ChatResponse, error) {
	f.calls++
	f.request = request
	return f.response, f.err
}

func TestProcessorScreen(t *testing.T) {
	t.Parallel()

	generator := &fakeGenerator{response: llm.ChatResponse{
		Model:            "qwen3:8b",
		Content:          `{"relevance":"related","reason":"NVDの対象Packageとlockfileの依存関係が一致します。","evidence_ids":["EVD-NVD-001","EVD-REPO-DEP-001"]}`,
		DoneReason:       "stop",
		PromptTokens:     120,
		CompletionTokens: 30,
		TotalDuration:    5 * time.Second,
	}}
	processor, err := New(generator)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	output, err := processor.Screen(context.Background(), sampleInput())
	if err != nil {
		t.Fatalf("Screen: %v", err)
	}

	if output.Result.Relevance != RelevanceRelated {
		t.Errorf("relevance = %q", output.Result.Relevance)
	}
	if output.Generation.Model != "qwen3:8b" || output.Generation.TotalDurationNS != int64(5*time.Second) {
		t.Errorf("generation = %+v", output.Generation)
	}
	if generator.calls != 1 {
		t.Errorf("calls = %d, want 1", generator.calls)
	}
	if len(generator.request.Messages) != 2 {
		t.Fatalf("messages = %d, want 2", len(generator.request.Messages))
	}
	if !strings.Contains(generator.request.Messages[0].Content, "未信頼") || !strings.Contains(generator.request.Messages[0].Content, "軽量判定") {
		t.Error("system prompt does not contain trust boundary and stage instructions")
	}
	if !strings.HasPrefix(generator.request.Messages[1].Content, "BEGIN_UNTRUSTED_ANALYSIS_MATERIAL\n{") {
		t.Error("user prompt is not a delimited JSON data block")
	}
	if !strings.Contains(generator.request.Messages[1].Content, "EVD-REPO-DEP-001") {
		t.Error("user prompt does not contain evidence")
	}
	if !json.Valid(generator.request.ResponseSchema) {
		t.Error("screening schema is invalid")
	}
}

func TestProcessorAnalyze(t *testing.T) {
	t.Parallel()

	generator := &fakeGenerator{response: llm.ChatResponse{
		Model:      "qwen3:8b",
		DoneReason: "stop",
		Content:    validDeepResponse,
	}}
	processor, err := New(generator)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	output, err := processor.Analyze(context.Background(), sampleInput())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if output.Analysis.Summary.Text == "" {
		t.Error("summary is empty")
	}
	if output.Analysis.RepositoryImpact.Text == "" {
		t.Error("repository impact is empty")
	}
	if len(output.Analysis.RecommendedActions) != 2 {
		t.Errorf("recommended actions = %+v", output.Analysis.RecommendedActions)
	}
	if !json.Valid(generator.request.ResponseSchema) {
		t.Error("deep-analysis schema is invalid")
	}
}

func TestProcessorRejectsUnknownEvidenceID(t *testing.T) {
	t.Parallel()

	generator := &fakeGenerator{response: llm.ChatResponse{
		Content: `{"relevance":"related","reason":"一致します。","evidence_ids":["EVD-NVD-001","EVD-MADE-UP"]}`,
	}}
	processor, err := New(generator)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = processor.Screen(context.Background(), sampleInput())
	if err == nil || !strings.Contains(err.Error(), "unknown evidence ID") {
		t.Fatalf("error = %v, want unknown evidence error", err)
	}
}

func TestProcessorEnforcesJSONSchema(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing required field": `{"relevance":"related","reason":"一致します。"}`,
		"wrong property case":    `{"relevance":"related","Reason":"一致します。","evidence_ids":["EVD-NVD-001","EVD-REPO-DEP-001"]}`,
		"null array":             `{"relevance":"related","reason":"一致します。","evidence_ids":null}`,
		"additional property":    `{"relevance":"related","reason":"一致します。","evidence_ids":["EVD-NVD-001","EVD-REPO-DEP-001"],"unexpected":true}`,
	}
	for name, response := range tests {
		name, response := name, response
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			processor, err := New(&fakeGenerator{response: llm.ChatResponse{Content: response}})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			_, err = processor.Screen(context.Background(), sampleInput())
			if err == nil || !strings.Contains(err.Error(), "JSON Schema validation failed") {
				t.Fatalf("error = %v, want schema validation error", err)
			}
		})
	}
}

func TestProcessorRejectsDuplicateJSONKeys(t *testing.T) {
	t.Parallel()

	generator := &fakeGenerator{response: llm.ChatResponse{
		Content: `{"relevance":"related","reason":"一致します。","reason":"重複しています。","evidence_ids":["EVD-NVD-001","EVD-REPO-DEP-001"]}`,
	}}
	processor, err := New(generator)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = processor.Screen(context.Background(), sampleInput())
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("error = %v, want duplicate key error", err)
	}
}

func TestProcessorRequiresBothScreeningEvidenceDomains(t *testing.T) {
	t.Parallel()

	processor, err := New(&fakeGenerator{response: llm.ChatResponse{
		Content: `{"relevance":"related","reason":"一致します。","evidence_ids":["EVD-NVD-001"]}`,
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = processor.Screen(context.Background(), sampleInput())
	if err == nil || !strings.Contains(err.Error(), "requires repository evidence") {
		t.Fatalf("error = %v, want repository evidence error", err)
	}
}

func TestProcessorRejectsNonCanonicalEvidenceID(t *testing.T) {
	t.Parallel()

	processor, err := New(&fakeGenerator{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	input := sampleInput()
	input.Evidence[0].ID = " EVD-NVD-001 "

	_, err = processor.Screen(context.Background(), input)
	if err == nil || !strings.Contains(err.Error(), "invalid ID") {
		t.Fatalf("error = %v, want canonical ID error", err)
	}
}

func TestProcessorRejectsRemovedDeepAnalysisFields(t *testing.T) {
	t.Parallel()

	response := strings.Replace(validDeepResponse, `"repository_impact":{"text":`, `"repository_impact":{"reachability":"reachable","text":`, 1)
	processor, err := New(&fakeGenerator{response: llm.ChatResponse{Content: response}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = processor.Analyze(context.Background(), sampleInput())
	if err == nil || !strings.Contains(err.Error(), "JSON Schema validation failed") {
		t.Fatalf("error = %v, want removed-field schema error", err)
	}
}

func TestProcessorValidatesInputBeforeGeneration(t *testing.T) {
	t.Parallel()

	generator := &fakeGenerator{}
	processor, err := New(generator)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	input := sampleInput()
	input.Vulnerability.ID = ""
	_, err = processor.Screen(context.Background(), input)
	if err == nil || !strings.Contains(err.Error(), "vulnerability ID") {
		t.Fatalf("error = %v, want vulnerability validation error", err)
	}
	if generator.calls != 0 {
		t.Errorf("calls = %d, want 0", generator.calls)
	}
}

func TestProcessorPropagatesGeneratorError(t *testing.T) {
	t.Parallel()

	generator := &fakeGenerator{err: errors.New("ollama unavailable")}
	processor, err := New(generator)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = processor.Screen(context.Background(), sampleInput())
	if err == nil || !strings.Contains(err.Error(), "ollama unavailable") {
		t.Fatalf("error = %v", err)
	}
}

func sampleInput() Input {
	modifiedAt := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	return Input{
		Vulnerability: domain.NormalizedVulnerability{
			ID:          "CVE-2026-1234",
			ModifiedAt:  modifiedAt,
			Description: "@example/archive versions before 1.4.0 are affected.",
			Affected: []domain.AffectedTarget{
				{
					ID:          "target-001",
					Kind:        domain.AffectedPackage,
					PURL:        "pkg:npm/%40example/archive",
					Ecosystem:   "npm",
					PackageName: "@example/archive",
					Constraints: []domain.VersionConstraint{{Scheme: "semver", VersionEndExcluding: "1.4.0"}},
				},
			},
		},
		Repository: domain.RepositoryProfile{
			Repository: domain.RepositoryIdentity{
				ID:           "repo-001",
				CanonicalURL: "https://github.com/example/project",
				Ref:          "main",
				CommitSHA:    "abc123",
			},
			Components: []domain.Component{
				{
					ID:         "component-001",
					PURL:       "pkg:npm/%40example/archive",
					Ecosystem:  "npm",
					Name:       "@example/archive",
					Version:    "1.3.0",
					Direct:     true,
					SourcePath: "pnpm-lock.yaml",
				},
			},
		},
		Candidate: domain.MatchCandidate{
			RepositoryID:     "repo-001",
			RepositoryCommit: "abc123",
			VulnerabilityID:  "CVE-2026-1234",
			VulnerabilityRev: modifiedAt,
			Matches: []domain.TargetMatch{
				{
					RepositoryItemID: "component-001",
					AffectedTargetID: "target-001",
					Reason:           domain.MatchPURLExact,
					VersionStatus:    domain.VersionAffected,
					InstalledVersion: "1.3.0",
				},
			},
		},
		Evidence: []Evidence{
			{
				ID:      "EVD-NVD-001",
				Kind:    EvidenceNVD,
				Source:  "NVD",
				URI:     "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
				Content: "@example/archive versions before 1.4.0 are affected.",
			},
			{
				ID:      "EVD-REPO-DEP-001",
				Kind:    EvidenceRepositoryDependency,
				Source:  "pnpm-lock.yaml",
				Content: "@example/archive 1.3.0",
			},
		},
	}
}
