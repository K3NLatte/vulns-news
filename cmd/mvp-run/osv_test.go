package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"vulns-news/src/domain"
	npmprofile "vulns-news/src/ecosystem/npm"
	"vulns-news/src/matcher"
	"vulns-news/src/nvd"
	"vulns-news/src/processor"
)

type fakeEnricher func(context.Context, domain.RepositoryProfile, domain.NormalizedVulnerability) (domain.NormalizedVulnerability, error)

func (f fakeEnricher) Enrich(ctx context.Context, p domain.RepositoryProfile, v domain.NormalizedVulnerability) (domain.NormalizedVulnerability, error) {
	return f(ctx, p, v)
}

type inspectingAnalyzer struct {
	fakeAnalyzer
	inputs []processor.Input
}

func (a *inspectingAnalyzer) Screen(ctx context.Context, input processor.Input) (processor.ScreeningOutput, error) {
	a.inputs = append(a.inputs, input)
	return a.fakeAnalyzer.Screen(ctx, input)
}

func osvPage() nvd.Page {
	return nvd.Page{TotalResults: 1, Vulnerabilities: []nvd.Vulnerability{{CVE: nvd.CVE{
		ID: "CVE-2026-1234", Published: "2026-09-25T00:00:00Z", LastModified: "2026-09-25T00:30:00Z",
		Descriptions: []nvd.LanguageValue{{Lang: "en", Value: "NVD description without package ranges"}},
	}}}}
}
func osvProfile() domain.RepositoryProfile {
	return domain.RepositoryProfile{
		Repository: domain.RepositoryIdentity{ID: "example/project", CommitSHA: "0123456789012345678901234567890123456789"},
		Components: []domain.Component{{ID: "component-1", Ecosystem: "npm", Name: "example", Version: "1.2.3", SourcePath: "package-lock.json"}},
	}
}
func addOSVMatch(v domain.NormalizedVulnerability) domain.NormalizedVulnerability {
	v.Affected = append(v.Affected, domain.AffectedTarget{ID: "osv:GHSA-example:exact-version", Kind: domain.AffectedPackage, Ecosystem: "npm", PackageName: "example", Constraints: []domain.VersionConstraint{{Scheme: "npm", Expression: "1.2.3"}}})
	v.References = append(v.References, domain.Reference{URL: "https://osv.dev/vulnerability/GHSA-example", Tags: []string{"osv_match"}})
	return v
}

func TestProcessPageWithEnricherBeforeMatchAndAfterDeduplication(t *testing.T) {
	p, page := osvProfile(), osvPage()
	page.Vulnerabilities = append(page.Vulnerabilities, page.Vulnerabilities[0], nvd.Vulnerability{CVE: nvd.CVE{ID: "broken"}})
	expected, err := nvd.Normalize(page.Vulnerabilities[0].CVE)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	ctx := context.Background()
	enricher := fakeEnricher(func(gotCtx context.Context, gotProfile domain.RepositoryProfile, v domain.NormalizedVulnerability) (domain.NormalizedVulnerability, error) {
		calls++
		if gotCtx != ctx || !reflect.DeepEqual(gotProfile, p) || !reflect.DeepEqual(v, expected) {
			t.Errorf("enricher did not receive normalized inputs: %+v", v)
		}
		return addOSVMatch(v), nil
	})
	analyzer := &inspectingAnalyzer{fakeAnalyzer: fakeAnalyzer{relevance: processor.RelevancePossiblyRelated}}
	got := processPageWithEnricher(ctx, p, page, matcher.New(npmprofile.VersionEvaluator{}), analyzer, enricher)
	if calls != 1 || got.NVD.Normalized != 1 || got.NVD.Duplicates != 1 || got.NVD.NormalizationErrors != 1 || got.Matched != 1 || got.ScreeningOnly != 1 {
		t.Fatalf("calls=%d result=%+v", calls, got)
	}
	if len(got.Errors) != 1 || got.Errors[0].Stage != "normalize" {
		t.Fatal(got.Errors)
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "not NVD") {
		t.Fatalf("missing provenance warning: %+v", got.Warnings)
	}
	if len(analyzer.inputs) != 1 || len(got.FeedItems) != 1 {
		t.Fatal("missing enriched candidate")
	}
	input := analyzer.inputs[0]
	if len(input.Vulnerability.References) != 1 || input.Vulnerability.References[0].Tags[0] != "osv_match" || input.Candidate.Matches[0].VersionStatus != domain.VersionAffected {
		t.Fatalf("input=%+v", input)
	}
	citations := got.FeedItems[0].Evidence
	var nvdCount, osvCount int
	for _, citation := range citations {
		switch citation.Source {
		case "NVD":
			nvdCount++
			if citation.Kind != processor.EvidenceNVD || citation.URI != "https://nvd.nist.gov/vuln/detail/CVE-2026-1234" || strings.Contains(citation.Content, "1.2.3") || strings.Contains(citation.Content, "OSV") {
				t.Errorf("OSV evidence mislabeled as NVD: %+v", citation)
			}
		case "OSV":
			osvCount++
			if citation.Kind != processor.EvidenceAdvisory || citation.URI != input.Vulnerability.References[0].URL || !strings.Contains(citation.Content, "not NVD") {
				t.Errorf("OSV citation=%+v", citation)
			}
		}
	}
	if nvdCount != 1 || osvCount != 1 {
		t.Fatalf("NVD=%d OSV=%d", nvdCount, osvCount)
	}
}

func TestProcessPageEnrichmentIsOptional(t *testing.T) {
	for _, wrapper := range []bool{false, true} {
		analyzer := &inspectingAnalyzer{}
		var got output
		if wrapper {
			got = processPage(context.Background(), osvProfile(), osvPage(), matcher.New(npmprofile.VersionEvaluator{}), analyzer)
		} else {
			got = processPageWithEnricher(context.Background(), osvProfile(), osvPage(), matcher.New(npmprofile.VersionEvaluator{}), analyzer, nil)
		}
		if got.NVD.Normalized != 1 || got.Matched != 0 || len(got.Errors) != 0 || len(got.Warnings) != 0 || len(analyzer.inputs) != 0 {
			t.Fatalf("disabled result=%+v", got)
		}
	}
}

func TestProcessPageEnrichmentErrorIsExplicitAndSkipsCVE(t *testing.T) {
	page := osvPage()
	second := page.Vulnerabilities[0]
	second.CVE.ID = "CVE-2026-5678"
	page.Vulnerabilities = append(page.Vulnerabilities, second)
	calls := 0
	enricher := fakeEnricher(func(ctx context.Context, p domain.RepositoryProfile, v domain.NormalizedVulnerability) (domain.NormalizedVulnerability, error) {
		calls++
		if calls == 1 {
			return addOSVMatch(v), errors.New("OSV unavailable")
		}
		return addOSVMatch(v), nil
	})
	analyzer := &inspectingAnalyzer{fakeAnalyzer: fakeAnalyzer{relevance: processor.RelevanceUnrelated}}
	got := processPageWithEnricher(context.Background(), osvProfile(), page, matcher.New(npmprofile.VersionEvaluator{}), analyzer, enricher)
	if calls != 2 || got.NVD.Normalized != 2 || got.Matched != 1 || got.Excluded != 1 || len(got.Errors) != 1 {
		t.Fatalf("calls=%d result=%+v", calls, got)
	}
	failure := got.Errors[0]
	if failure.Stage != "osv" || failure.CVEID != "CVE-2026-1234" || failure.Error != "OSV unavailable" {
		t.Fatal(failure)
	}
	if len(analyzer.inputs) != 1 || analyzer.inputs[0].Vulnerability.ID != "CVE-2026-5678" {
		t.Fatal("failed CVE reached analyzer")
	}
}

func TestProcessPageEnricherCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	page := osvPage()
	page.Vulnerabilities = append(page.Vulnerabilities, page.Vulnerabilities[0])
	calls := 0
	enricher := fakeEnricher(func(ctx context.Context, p domain.RepositoryProfile, v domain.NormalizedVulnerability) (domain.NormalizedVulnerability, error) {
		calls++
		cancel()
		return v, ctx.Err()
	})
	got := processPageWithEnricher(ctx, osvProfile(), page, matcher.New(npmprofile.VersionEvaluator{}), &fakeAnalyzer{}, enricher)
	if calls != 1 || got.Matched != 0 || len(got.Errors) != 2 || got.Errors[0].Stage != "osv" || got.Errors[1].Stage != "context" {
		t.Fatalf("calls=%d result=%+v", calls, got)
	}
}

func TestParseConfigOSVOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "default off", true: "explicit opt in"}[enabled], func(t *testing.T) {
			oldFlags, oldArgs := flag.CommandLine, os.Args
			t.Cleanup(func() { flag.CommandLine, os.Args = oldFlags, oldArgs })
			flag.CommandLine = flag.NewFlagSet("mvp-run", flag.ContinueOnError)
			os.Args = []string{"mvp-run", "-repository", "https://github.com/example/project", "-model", "test-model"}
			if enabled {
				os.Args = append(os.Args, "-osv")
			}
			cfg, err := parseConfig(time.Now())
			if err != nil || cfg.osvEnabled != enabled {
				t.Fatalf("config=%+v error=%v", cfg, err)
			}
			help := flag.CommandLine.Lookup("osv").Usage
			for _, text := range []string{"names", "versions", "externally", "api.osv.dev"} {
				if !strings.Contains(help, text) || !strings.Contains(osvDisclosure, text) {
					t.Errorf("missing disclosure %q in help/stderr notice", text)
				}
			}
		})
	}
}
