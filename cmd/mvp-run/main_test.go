package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"testing"
	"time"

	"vulns-news/src/domain"
	npmprofile "vulns-news/src/ecosystem/npm"
	"vulns-news/src/matcher"
	"vulns-news/src/nvd"
	"vulns-news/src/processor"
)

type fakeAnalyzer struct {
	relevance processor.Relevance
	screenErr error
	deepCalls int
}

func (f *fakeAnalyzer) Screen(context.Context, processor.Input) (processor.ScreeningOutput, error) {
	if f.screenErr != nil {
		return processor.ScreeningOutput{}, f.screenErr
	}
	return processor.ScreeningOutput{Result: processor.ScreeningResult{
		Relevance:   f.relevance,
		Reason:      "test screening",
		EvidenceIDs: []string{"EVD-NVD-001", "EVD-REPO-001"},
	}}, nil
}

func (f *fakeAnalyzer) Analyze(context.Context, processor.Input) (processor.AnalysisOutput, error) {
	f.deepCalls++
	return processor.AnalysisOutput{Analysis: processor.DeepAnalysis{
		Summary: processor.SupportedClaim{
			Text:        "summary",
			EvidenceIDs: []string{"EVD-NVD-001", "EVD-REPO-001"},
		},
		RepositoryImpact: processor.SupportedClaim{
			Text:        "impact",
			EvidenceIDs: []string{"EVD-NVD-001", "EVD-REPO-001"},
		},
		MissingInformation: []string{"usage is unknown"},
		RecommendedActions: []string{"upgrade"},
	}}, nil
}

func TestProcessPageExcludesUnrelatedAndDeduplicates(t *testing.T) {
	modified := "2026-09-25T00:30:00.000Z"
	cve := nvd.CVE{
		ID:           "CVE-2026-1234",
		Published:    "2026-09-25T00:00:00.000Z",
		LastModified: modified,
		Descriptions: []nvd.LanguageValue{{Lang: "en", Value: "archive vulnerability"}},
		Configurations: []nvd.Configuration{{Nodes: []nvd.Node{{CPEMatch: []nvd.CPEMatch{{
			Vulnerable:          true,
			Criteria:            "cpe:2.3:a:example:archive:*:*:*:*:*:*:*:*",
			VersionEndExcluding: "1.4.0",
		}}}}}},
	}
	profile := domain.RepositoryProfile{
		Repository: domain.RepositoryIdentity{
			ID:        "example/project",
			CommitSHA: "0123456789012345678901234567890123456789",
		},
		Components: []domain.Component{{
			ID: "component-1", Ecosystem: "npm", Name: "@example/archive", Version: "1.3.0", SourcePath: "package-lock.json",
		}},
		Products: []domain.ProductCandidate{{
			ID: "product-1", Ecosystem: "npm", Vendor: "example", Name: "archive", Version: "1.3.0", Aliases: []string{"@example/archive", "archive"}, SourcePath: "package-lock.json",
		}},
	}
	analyzer := &fakeAnalyzer{relevance: processor.RelevanceUnrelated}
	page := nvd.Page{TotalResults: 2, Vulnerabilities: []nvd.Vulnerability{{CVE: cve}, {CVE: cve}}}

	got := processPage(context.Background(), profile, page, matcher.New(npmprofile.VersionEvaluator{}), analyzer)
	if got.NVD.Fetched != 2 || got.NVD.Normalized != 1 || got.NVD.Duplicates != 1 {
		t.Fatalf("NVD counts = %#v", got.NVD)
	}
	if got.Matched != 1 || got.Excluded != 1 || len(got.FeedItems) != 0 {
		t.Fatalf("result = %#v", got)
	}
	if analyzer.deepCalls != 0 {
		t.Fatalf("Deep Analysis calls = %d, want 0", analyzer.deepCalls)
	}
}

func TestProcessPageRecordsPerCVEErrors(t *testing.T) {
	profile := domain.RepositoryProfile{
		Repository: domain.RepositoryIdentity{ID: "example/project", CommitSHA: "0123456789012345678901234567890123456789"},
		Products:   []domain.ProductCandidate{{ID: "product-1", Ecosystem: "npm", Vendor: "example", Name: "archive", Version: "1.3.0", SourcePath: "package-lock.json"}},
	}
	page := nvd.Page{Vulnerabilities: []nvd.Vulnerability{
		{CVE: nvd.CVE{ID: "broken"}},
		{CVE: nvd.CVE{
			ID: "CVE-2026-1234", Published: "2026-09-25T00:00:00Z", LastModified: "2026-09-25T00:30:00Z",
			Descriptions:   []nvd.LanguageValue{{Lang: "en", Value: "archive vulnerability"}},
			Configurations: []nvd.Configuration{{Nodes: []nvd.Node{{CPEMatch: []nvd.CPEMatch{{Vulnerable: true, Criteria: "cpe:2.3:a:example:archive:*:*:*:*:*:*:*:*"}}}}}},
		}},
	}}
	analyzer := &fakeAnalyzer{relevance: processor.RelevanceRelated, screenErr: errors.New("LLM unavailable")}

	got := processPage(context.Background(), profile, page, matcher.New(npmprofile.VersionEvaluator{}), analyzer)
	if got.NVD.NormalizationErrors != 1 || got.Matched != 1 || len(got.Errors) != 2 {
		t.Fatalf("result = %#v", got)
	}
	if got.Errors[0].Stage != "normalize" || got.Errors[1].Stage != "analysis" {
		t.Fatalf("errors = %#v", got.Errors)
	}
}

func TestParseConfigFreezesCommandStart(t *testing.T) {
	oldFlags, oldArgs := flag.CommandLine, os.Args
	t.Cleanup(func() { flag.CommandLine, os.Args = oldFlags, oldArgs })
	flag.CommandLine = flag.NewFlagSet("mvp-run", flag.ContinueOnError)
	os.Args = []string{"mvp-run", "-repository", "https://github.com/example/project", "-model", "test-model"}
	started := time.Date(2026, 9, 25, 12, 0, 0, 0, time.FixedZone("JST", 9*60*60))
	cfg, err := parseConfig(started)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.asOf.Equal(started) || cfg.asOf.Location() != time.UTC || !cfg.publishedFrom.IsZero() || !cfg.publishedTo.IsZero() {
		t.Fatalf("config did not preserve latest-search cutoff: %#v", cfg)
	}
}

func TestPublicationWindowDefaultsToLatestSearch(t *testing.T) {
	now := time.Date(2026, time.September, 25, 12, 0, 0, 0, time.FixedZone("JST", 9*60*60))
	start, end, err := publicationWindow("", "", now)
	if err != nil {
		t.Fatalf("publicationWindow() error = %v", err)
	}
	if !end.IsZero() || !start.IsZero() {
		t.Fatalf("window = %v to %v", start, end)
	}
}

func TestPublicationWindowExplicitRanges(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, start, end   string
		wantStart, wantEnd time.Time
	}{
		{"end only", "", "2026-09-24T12:00:00Z", now.Add(-48 * time.Hour), now.Add(-24 * time.Hour)},
		{"start only", "2026-09-20T12:00:00Z", "", now.Add(-5 * 24 * time.Hour), now},
		{"both", "2026-09-20T12:00:00Z", "2026-09-24T12:00:00Z", now.Add(-5 * 24 * time.Hour), now.Add(-24 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start, end, err := publicationWindow(tc.start, tc.end, now)
			if err != nil || !start.Equal(tc.wantStart) || !end.Equal(tc.wantEnd) {
				t.Fatalf("window = %v to %v, error = %v", start, end, err)
			}
		})
	}
	if _, _, err := publicationWindow("", "2026-09-26T12:00:00Z", now); err == nil {
		t.Fatal("accepted publication end after command start")
	}
}

func TestPublicationWindowRejectsReverseRange(t *testing.T) {
	_, _, err := publicationWindow("2026-09-26T00:00:00Z", "2026-09-25T00:00:00Z", time.Now())
	if err == nil {
		t.Fatal("publicationWindow() error = nil, want error")
	}
}
