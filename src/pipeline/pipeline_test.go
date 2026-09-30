package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/processor"
)

type fakeAnalyzer struct {
	screening   processor.ScreeningOutput
	analysis    processor.AnalysisOutput
	screenErr   error
	analysisErr error
	screenCalls int
	deepCalls   int
}

func (f *fakeAnalyzer) Screen(context.Context, processor.Input) (processor.ScreeningOutput, error) {
	f.screenCalls++
	return f.screening, f.screenErr
}

func (f *fakeAnalyzer) Analyze(context.Context, processor.Input) (processor.AnalysisOutput, error) {
	f.deepCalls++
	return f.analysis, f.analysisErr
}

func TestProcessRunsDeepAnalysisForRelatedCandidate(t *testing.T) {
	analyzer := &fakeAnalyzer{
		screening: screening(processor.RelevanceRelated),
		analysis: processor.AnalysisOutput{Analysis: processor.DeepAnalysis{
			Summary:            processor.SupportedClaim{Text: "summary", EvidenceIDs: []string{"EVD-NVD-001"}},
			RepositoryImpact:   processor.SupportedClaim{Text: "impact", EvidenceIDs: []string{"EVD-REPO-DEP-001"}},
			RecommendedActions: []string{"upgrade"},
		}},
	}

	result, err := Process(context.Background(), analyzer, sampleInput())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if analyzer.screenCalls != 1 || analyzer.deepCalls != 1 {
		t.Fatalf("calls = screen %d, deep %d", analyzer.screenCalls, analyzer.deepCalls)
	}
	if result.Excluded || result.Analysis == nil || result.Feed == nil {
		t.Fatalf("result = %+v", result)
	}
	if result.Feed.Status != "analyzed" {
		t.Errorf("feed status = %q", result.Feed.Status)
	}
}

func TestProcessBuildsScreeningOnlyFeedForUnknownCandidate(t *testing.T) {
	analyzer := &fakeAnalyzer{screening: screening(processor.RelevanceUnknown)}

	result, err := Process(context.Background(), analyzer, sampleInput())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if analyzer.deepCalls != 0 {
		t.Fatalf("deep calls = %d, want 0", analyzer.deepCalls)
	}
	if result.Analysis != nil || result.Feed == nil || result.Feed.Status != "screened" {
		t.Fatalf("result = %+v", result)
	}
}

func TestProcessExcludesUnrelatedCandidate(t *testing.T) {
	analyzer := &fakeAnalyzer{screening: screening(processor.RelevanceUnrelated)}

	result, err := Process(context.Background(), analyzer, sampleInput())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !result.Excluded || result.Feed != nil || analyzer.deepCalls != 0 {
		t.Fatalf("result = %+v, deep calls = %d", result, analyzer.deepCalls)
	}
}

func TestProcessPropagatesAnalysisError(t *testing.T) {
	analyzer := &fakeAnalyzer{
		screening:   screening(processor.RelevanceRelated),
		analysisErr: errors.New("ollama unavailable"),
	}

	_, err := Process(context.Background(), analyzer, sampleInput())
	if err == nil {
		t.Fatal("Process accepted a Deep Analysis error")
	}
}

func screening(relevance processor.Relevance) processor.ScreeningOutput {
	return processor.ScreeningOutput{Result: processor.ScreeningResult{
		Relevance:   relevance,
		Reason:      "test decision",
		EvidenceIDs: []string{"EVD-NVD-001", "EVD-REPO-DEP-001"},
	}}
}

func sampleInput() processor.Input {
	modifiedAt := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	return processor.Input{
		Vulnerability: domain.NormalizedVulnerability{ID: "CVE-2026-1234", ModifiedAt: modifiedAt},
		Repository: domain.RepositoryProfile{Repository: domain.RepositoryIdentity{
			ID: "repo-001", CommitSHA: "abc123",
		}},
		Candidate: domain.MatchCandidate{
			RepositoryID:     "repo-001",
			RepositoryCommit: "abc123",
			VulnerabilityID:  "CVE-2026-1234",
			VulnerabilityRev: modifiedAt,
			Matches: []domain.TargetMatch{{
				RepositoryItemID: "component-001",
				AffectedTargetID: "target-001",
				Reason:           domain.MatchPURLExact,
				VersionStatus:    domain.VersionAffected,
			}},
		},
	}
}
