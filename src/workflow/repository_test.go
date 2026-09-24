package workflow

import (
	"context"
	"fmt"
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/nvd"
	"vulns-news/src/processor"
)

type fakePageFetcher struct {
	published []nvd.CVE
	modified  []nvd.CVE
	queries   []nvd.Query
}

func (f *fakePageFetcher) FetchPage(_ context.Context, query nvd.Query) (nvd.Page, error) {
	f.queries = append(f.queries, query)
	items := f.modified
	if !query.PublishedStart.IsZero() {
		items = f.published
	}
	start := query.StartIndex
	if start >= len(items) {
		return nvd.Page{StartIndex: start, TotalResults: len(items)}, nil
	}
	end := start + query.ResultsPerPage
	if end > len(items) {
		end = len(items)
	}
	return nvd.Page{
		StartIndex:      start,
		ResultsPerPage:  query.ResultsPerPage,
		TotalResults:    len(items),
		Vulnerabilities: wrapCVEs(items[start:end]),
	}, nil
}

type fakeAnalyzer struct {
	calls int
}

func (f *fakeAnalyzer) Screen(_ context.Context, input processor.Input) (processor.ScreeningOutput, error) {
	f.calls++
	return processor.ScreeningOutput{Result: processor.ScreeningResult{
		Relevance:   processor.RelevanceUnknown,
		Reason:      "insufficient semantic information",
		EvidenceIDs: []string{"EVD-NVD-001", "EVD-REPO-001"},
	}}, nil
}

func (*fakeAnalyzer) Analyze(context.Context, processor.Input) (processor.AnalysisOutput, error) {
	return processor.AnalysisOutput{}, fmt.Errorf("unexpected deep analysis")
}

func TestProcessRepositoryFetchesAllPagesAndDeduplicatesWindows(t *testing.T) {
	registeredAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	until := registeredAt.Add(time.Hour)
	cves := make([]nvd.CVE, 201)
	for index := range cves {
		cves[index] = sampleCVE(fmt.Sprintf("CVE-2026-%04d", index+1), registeredAt, registeredAt)
	}
	fetcher := &fakePageFetcher{
		published: cves,
		modified:  []nvd.CVE{cves[0]},
	}
	profile := sampleProfile()

	result, err := ProcessRepository(context.Background(), fetcher, profile, Config{
		RegisteredAt: registeredAt,
		Until:        until,
	})
	if err != nil {
		t.Fatalf("ProcessRepository: %v", err)
	}
	if result.Fetched != 201 || len(result.Results) != 201 {
		t.Fatalf("fetched/results = %d/%d, want 201/201", result.Fetched, len(result.Results))
	}
	if len(fetcher.queries) != 3 {
		t.Fatalf("fetch calls = %d, want 3", len(fetcher.queries))
	}
	if fetcher.queries[0].PublishedStart.IsZero() || fetcher.queries[0].PublishedStart != registeredAt {
		t.Errorf("publication window = %+v", fetcher.queries[0])
	}
	if fetcher.queries[1].StartIndex != 200 || fetcher.queries[1].ResultsPerPage != 200 {
		t.Errorf("second publication page = %+v", fetcher.queries[1])
	}
	if fetcher.queries[2].ModifiedStart.IsZero() || fetcher.queries[2].ModifiedStart != registeredAt {
		t.Errorf("modification window = %+v", fetcher.queries[2])
	}
}

func TestProcessRepositoryBuildsEvidenceAndScreensMatchedCVE(t *testing.T) {
	registeredAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	until := registeredAt.Add(time.Hour)
	cve := sampleCVE("CVE-2026-1234", registeredAt, registeredAt)
	cve.Configurations = []nvd.Configuration{{Nodes: []nvd.Node{{CPEMatch: []nvd.CPEMatch{{
		Vulnerable: true,
		Criteria:   "cpe:2.3:a:example:archive:*:*:*:*:*:*:*:*",
	}}}}}}
	fetcher := &fakePageFetcher{published: []nvd.CVE{cve}}
	analyzer := &fakeAnalyzer{}

	result, err := ProcessRepository(context.Background(), fetcher, sampleProfile(), Config{
		RegisteredAt: registeredAt,
		Until:        until,
		Analyzer:     analyzer,
	})
	if err != nil {
		t.Fatalf("ProcessRepository: %v", err)
	}
	if len(result.Results) != 1 || !result.Results[0].Matched {
		t.Fatalf("results = %+v", result.Results)
	}
	entry := result.Results[0]
	if entry.Pipeline == nil || entry.Pipeline.Feed == nil || entry.Pipeline.Feed.Status != "screened" {
		t.Fatalf("pipeline result = %+v", entry.Pipeline)
	}
	if analyzer.calls != 1 {
		t.Errorf("screen calls = %d, want 1", analyzer.calls)
	}
}

func wrapCVEs(items []nvd.CVE) []nvd.Vulnerability {
	result := make([]nvd.Vulnerability, len(items))
	for index, item := range items {
		result[index] = nvd.Vulnerability{CVE: item}
	}
	return result
}

func sampleCVE(id string, publishedAt, modifiedAt time.Time) nvd.CVE {
	return nvd.CVE{
		ID:           id,
		Published:    publishedAt.Format(time.RFC3339),
		LastModified: modifiedAt.Format(time.RFC3339),
		Descriptions: []nvd.LanguageValue{{Lang: "en", Value: "An example vulnerability."}},
		References:   []nvd.Reference{{URL: "https://nvd.nist.gov/vuln/detail/" + id}},
	}
}

func sampleProfile() domain.RepositoryProfile {
	return domain.RepositoryProfile{
		Repository: domain.RepositoryIdentity{
			ID:           "example/project",
			CanonicalURL: "https://github.com/example/project",
			Ref:          "main",
			CommitSHA:    "0123456789012345678901234567890123456789",
		},
		Products: []domain.ProductCandidate{{
			ID:         "product-001",
			Vendor:     "example",
			Name:       "archive",
			CPEs:       []string{"cpe:2.3:a:example:archive:*:*:*:*:*:*:*:*"},
			Aliases:    []string{},
			SourcePath: "Dockerfile",
		}},
	}
}
