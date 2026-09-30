package feed

import (
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/processor"
)

func TestBuildKeepsBackendFactsSeparateFromAnalysis(t *testing.T) {
	modifiedAt := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	cvss := 8.1
	input := processor.Input{
		Vulnerability: domain.NormalizedVulnerability{
			ID:          "CVE-2026-1234",
			ModifiedAt:  modifiedAt,
			Description: "test vulnerability",
			Severity:    "HIGH",
			CVSS:        &cvss,
		},
		Repository: domain.RepositoryProfile{
			Repository: domain.RepositoryIdentity{ID: "repo-001", CommitSHA: "abc123"},
		},
		Candidate: domain.MatchCandidate{
			RepositoryID:     "repo-001",
			RepositoryCommit: "abc123",
			VulnerabilityID:  "CVE-2026-1234",
			VulnerabilityRev: modifiedAt,
			Matches: []domain.TargetMatch{
				{RepositoryItemID: "component-001", AffectedTargetID: "target-001", Reason: domain.MatchPURLExact, VersionStatus: domain.VersionAffected},
			},
		},
	}
	screening := processor.ScreeningOutput{
		Result: processor.ScreeningResult{
			Relevance: processor.RelevanceRelated,
			Reason:    "The matched runtime dependency is affected.",
		},
	}
	analysis := &processor.AnalysisOutput{
		Analysis: processor.DeepAnalysis{
			Summary:            processor.SupportedClaim{Text: "Repository impact is possible."},
			RepositoryImpact:   processor.SupportedClaim{Text: "The affected component is present."},
			MissingInformation: []string{"affected feature usage"},
			RecommendedActions: []string{"upgrade the dependency"},
		},
	}

	item, err := Build(input, screening, analysis)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if item.CVEID != "CVE-2026-1234" || item.RepositoryCommit != "abc123" {
		t.Errorf("fact identity = %q/%q", item.CVEID, item.RepositoryCommit)
	}
	if item.Status != StatusAnalyzed || item.Summary == nil {
		t.Errorf("analysis status = %q, summary = %#v", item.Status, item.Summary)
	}
	if item.CVSS == nil || *item.CVSS != 8.1 {
		t.Errorf("CVSS = %#v", item.CVSS)
	}
}

func TestBuildRejectsUnrelatedResult(t *testing.T) {
	_, err := Build(processor.Input{}, processor.ScreeningOutput{
		Result: processor.ScreeningResult{Relevance: processor.RelevanceUnrelated},
	}, nil)
	if err == nil {
		t.Fatal("Build accepted an unrelated result")
	}
}
