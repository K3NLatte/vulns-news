package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/versions"
	"vulns-news/src/matcher"
	"vulns-news/src/nvd"
	"vulns-news/src/processor"
)

type recordingFetcher struct {
	count   int
	options *nvd.LatestOptions
	err     error
}

func (f *recordingFetcher) Fetch(_ context.Context, count int) ([]nvd.NormalizedVulnerability, error) {
	f.count = count
	return nil, f.err
}

func (f *recordingFetcher) FetchNormalizedLatest(_ context.Context, options nvd.LatestOptions) ([]nvd.NormalizedVulnerability, error) {
	f.options = &options
	return nil, f.err
}

func TestFetchVulnerabilitiesSelectsCrawlerOrExplicitWindow(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	for _, explicit := range []bool{false, true} {
		cfg := config{asOf: now}
		if explicit {
			cfg.publishedFrom, cfg.publishedTo = now.Add(-time.Hour), now
		}
		failure := errors.New("crawler incomplete")
		client := &recordingFetcher{err: failure}
		if _, err := fetchVulnerabilities(context.Background(), client, cfg); !errors.Is(err, failure) {
			t.Fatalf("crawler error was lost: %v", err)
		}
		if explicit {
			if client.count != 0 || client.options == nil || client.options.Limit != 200 || !client.options.PublishedStart.Equal(cfg.publishedFrom) || !client.options.PublishedEnd.Equal(cfg.publishedTo) || !client.options.AsOf.Equal(now) {
				t.Fatalf("explicit window was not preserved: %+v", client)
			}
		} else if client.count != 200 || client.options != nil {
			t.Fatalf("default did not select global crawler: %+v", client)
		}
	}
}

type crawlerAnalyzer struct {
	fakeAnalyzer
	inputs []processor.Input
}

func (a *crawlerAnalyzer) Screen(ctx context.Context, input processor.Input) (processor.ScreeningOutput, error) {
	a.inputs = append(a.inputs, input)
	return a.fakeAnalyzer.Screen(ctx, input)
}

func (a *crawlerAnalyzer) Analyze(ctx context.Context, input processor.Input) (processor.AnalysisOutput, error) {
	a.inputs = append(a.inputs, input)
	return a.fakeAnalyzer.Analyze(ctx, input)
}

func TestNormalizedCrawlerToScreeningDeepAnalysisAndFeed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != "" {
			t.Error("default crawler sent an API key")
		}
		if r.URL.Query().Get("pubStartDate") != "" {
			t.Error("global crawler sent a publication window")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"totalResults":1,"resultsPerPage":1,"startIndex":0,
			"vulnerabilities":[{"cve":{
				"id":"CVE-2026-1234","published":"2026-09-24T00:00:00.000","lastModified":"2026-09-25T00:00:00.000",
				"descriptions":[{"lang":"en","value":"Archive path validation issue."}],
				"metrics":{"cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":8.1,"baseSeverity":"HIGH"}}]},
				"weaknesses":[{"description":[{"lang":"en","value":"CWE-22"}]}],
				"affected":[{"affectedData":[{"vendor":"example","product":"archive","packageName":"@example/archive","versions":[{"version":"1.0.0","lessThan":"1.4.0","status":"affected"}]}]}],
				"references":[{"url":"https://example.com/advisory","source":"publisher","tags":["Vendor Advisory"]}]
			}}]
		}`))
	}))
	defer server.Close()
	client, err := nvd.NewAnalysisClient(nvd.Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	items, err := client.Fetch(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	profile := domain.RepositoryProfile{
		Repository: domain.RepositoryIdentity{ID: "example/project", CommitSHA: "0123456789012345678901234567890123456789"},
		Products:   []domain.ProductCandidate{{ID: "product-1", Ecosystem: "npm", Vendor: "example", Name: "archive", Version: "1.3.0", SourcePath: "package-lock.json"}},
	}
	for _, relevance := range []processor.Relevance{processor.RelevanceRelated, processor.RelevancePossiblyRelated, processor.RelevanceUnknown, processor.RelevanceUnrelated} {
		t.Run(string(relevance), func(t *testing.T) {
			analyzer := &crawlerAnalyzer{fakeAnalyzer: fakeAnalyzer{relevance: relevance}}
			result := processNormalizedWithEnricher(context.Background(), profile, items, matcher.New(versions.New()), analyzer, nil)
			if len(result.Errors) != 0 || result.NVD.Normalized != 1 || result.Matched != 1 {
				t.Fatalf("crawler output did not reach pipeline: %+v", result)
			}
			for _, input := range analyzer.inputs {
				v := input.Vulnerability
				if !v.PublishedAt.Equal(time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)) || !v.ModifiedAt.Equal(time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)) || len(v.Weaknesses) != 1 || v.Weaknesses[0] != "CWE-22" || len(v.References) != 1 || v.References[0].Source != "publisher" {
					t.Fatalf("crawler metadata lost at LLM boundary: %+v", v)
				}
			}
			if relevance == processor.RelevanceUnrelated {
				if result.Excluded != 1 || len(result.FeedItems) != 0 || analyzer.deepCalls != 0 {
					t.Fatalf("unrelated result: %+v", result)
				}
				return
			}
			if len(result.FeedItems) != 1 {
				t.Fatalf("feed count: %d", len(result.FeedItems))
			}
			item := result.FeedItems[0]
			if item.CVEID != "CVE-2026-1234" || item.Severity != "HIGH" || item.CVSS == nil || *item.CVSS != 8.1 {
				t.Fatalf("normalized facts lost: %+v", item)
			}
			if len(item.Matches) != 1 || item.Matches[0].VersionStatus != domain.VersionUnknown {
				t.Fatalf("unknown source version scheme was upgraded: %+v", item.Matches)
			}
			if relevance == processor.RelevanceRelated {
				if analyzer.deepCalls != 1 || result.Analyzed != 1 {
					t.Fatalf("missing deep analysis: %+v", result)
				}
			} else if analyzer.deepCalls != 0 || result.ScreeningOnly != 1 {
				t.Fatalf("unexpected deep analysis: %+v", result)
			}
		})
	}
}
