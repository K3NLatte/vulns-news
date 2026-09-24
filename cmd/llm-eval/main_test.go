package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vulns-news/src/domain"
	"vulns-news/src/feed"
	"vulns-news/src/llm"
	"vulns-news/src/matcher"
	"vulns-news/src/pipeline"
	"vulns-news/src/processor"
)

type scriptedGenerator struct {
	responses []llm.ChatResponse
	calls     int
}

func (g *scriptedGenerator) Chat(context.Context, llm.ChatRequest) (llm.ChatResponse, error) {
	if g.calls >= len(g.responses) {
		return llm.ChatResponse{}, context.Canceled
	}
	response := g.responses[g.calls]
	g.calls++
	return response, nil
}

func TestPrepareInputCreatesCandidateFromFixture(t *testing.T) {
	fixture := readTestFixture(t)

	input, matched, err := prepareInput(matcher.New(nil), fixture)
	if err != nil {
		t.Fatalf("prepareInput: %v", err)
	}
	if !matched {
		t.Fatal("prepareInput returned no deterministic candidate")
	}
	if input.Candidate.RepositoryID != fixture.Repository.Repository.ID ||
		input.Candidate.RepositoryCommit != fixture.Repository.Repository.CommitSHA {
		t.Errorf("candidate repository = %q/%q", input.Candidate.RepositoryID, input.Candidate.RepositoryCommit)
	}
	if input.Candidate.VulnerabilityID != fixture.Vulnerability.ID ||
		!input.Candidate.VulnerabilityRev.Equal(fixture.Vulnerability.ModifiedAt) {
		t.Errorf("candidate vulnerability = %q/%s", input.Candidate.VulnerabilityID, input.Candidate.VulnerabilityRev)
	}
	if len(input.Candidate.Matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(input.Candidate.Matches))
	}
	match := input.Candidate.Matches[0]
	if match.Reason != domain.MatchPURLExact {
		t.Errorf("reason = %q, want %q", match.Reason, domain.MatchPURLExact)
	}
	if match.VersionStatus != domain.VersionUnknown {
		t.Errorf("version status = %q, want %q", match.VersionStatus, domain.VersionUnknown)
	}
	if match.InstalledVersion != "1.3.0" {
		t.Errorf("installed version = %q, want 1.3.0", match.InstalledVersion)
	}
	if len(input.Evidence) != len(fixture.Evidence) {
		t.Errorf("evidence count = %d, want %d", len(input.Evidence), len(fixture.Evidence))
	}
}

func TestMockPipelineRunsMatcherScreeningAnalysisAndFeed(t *testing.T) {
	fixture := readTestFixture(t)
	input, matched, err := prepareInput(matcher.New(nil), fixture)
	if err != nil {
		t.Fatalf("prepareInput: %v", err)
	}
	if !matched {
		t.Fatal("prepareInput returned no deterministic candidate")
	}

	generator := &scriptedGenerator{responses: []llm.ChatResponse{
		{
			Model:   "test-screening",
			Content: `{"relevance":"related","reason":"CVEの対象PackageとRepositoryの依存関係が一致します。","evidence_ids":["EVD-NVD-001","EVD-REPO-DEP-001"]}`,
		},
		{
			Model: "test-analysis",
			Content: `{
				"summary":{"text":"対象PackageがRepositoryに含まれています。","evidence_ids":["EVD-NVD-001","EVD-REPO-DEP-001"]},
				"repository_impact":{"text":"対象機能の利用状況は未確認です。","evidence_ids":["EVD-REPO-DEP-001"]},
				"missing_information":["対象機能を実際に使用しているか"],
				"recommended_actions":["Version比較を確認し、必要なら修正版へ更新する"]
			}`,
		},
	}}
	analyzer, err := processor.New(generator)
	if err != nil {
		t.Fatalf("processor.New: %v", err)
	}

	result, err := pipeline.Process(context.Background(), analyzer, input)
	if err != nil {
		t.Fatalf("pipeline.Process: %v", err)
	}
	if generator.calls != 2 {
		t.Fatalf("LLM calls = %d, want 2", generator.calls)
	}
	if result.Excluded || result.Analysis == nil || result.Feed == nil {
		t.Fatalf("result = %+v", result)
	}
	if result.Feed.Status != feed.StatusAnalyzed {
		t.Errorf("feed status = %q, want %q", result.Feed.Status, feed.StatusAnalyzed)
	}
	if result.Feed.RepositoryID != "repo-mock-001" || result.Feed.CVEID != "CVE-2026-1234" {
		t.Errorf("feed identity = %q/%q", result.Feed.RepositoryID, result.Feed.CVEID)
	}
	if len(result.Feed.Matches) != 1 || result.Feed.Matches[0].VersionStatus != domain.VersionUnknown {
		t.Errorf("feed matches = %+v", result.Feed.Matches)
	}
}

func TestPrepareInputSkipsUnmatchedFacts(t *testing.T) {
	fixture := readTestFixture(t)
	fixture.Vulnerability.Affected[0].PURL = ""
	fixture.Vulnerability.Affected[0].PackageName = "different-package"

	input, matched, err := prepareInput(matcher.New(nil), fixture)
	if err != nil {
		t.Fatalf("prepareInput: %v", err)
	}
	if matched {
		t.Fatalf("prepareInput unexpectedly matched: %+v", input.Candidate)
	}
	if len(input.Candidate.Matches) != 0 {
		t.Fatalf("unmatched input contains candidate matches: %+v", input.Candidate.Matches)
	}
}

func TestReadInputRejectsPrecomputedCandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	content := `{"vulnerability":{},"repository":{},"evidence":[],"candidate":{}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	_, err := readInput(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field \"candidate\"") {
		t.Fatalf("error = %v, want unknown candidate field error", err)
	}
}

func readTestFixture(t *testing.T) evalInput {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "scenarios", "npm-affected-dependency", "input.json")
	fixture, err := readInput(path)
	if err != nil {
		t.Fatalf("readInput(%q): %v", path, err)
	}
	return fixture
}
