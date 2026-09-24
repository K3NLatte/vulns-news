// Package workflow connects NVD ingestion, deterministic repository matching,
// evidence construction, and per-candidate analysis for one repository run.
package workflow

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/evidence"
	"vulns-news/src/matcher"
	"vulns-news/src/nvd"
	"vulns-news/src/pipeline"
	"vulns-news/src/processor"
)

const pageSize = 200

// PageFetcher is implemented by nvd.Client.
type PageFetcher interface {
	FetchPage(context.Context, nvd.Query) (nvd.Page, error)
}

// VersionEvaluator compares installed versions using ecosystem-specific rules.
type VersionEvaluator interface {
	Evaluate(string, string, []domain.VersionConstraint) (domain.VersionStatus, error)
}

// Config defines one registration-triggered processing run. RegisteredAt is the
// lower bound; Until defaults to the current time when it is zero.
type Config struct {
	RegisteredAt time.Time
	Until        time.Time
	Versions     VersionEvaluator
	Analyzer     pipeline.Analyzer
}

// VulnerabilityResult records whether a normalized NVD vulnerability matched
// the repository and, if so, the screening/analysis/feed outcome.
type VulnerabilityResult struct {
	Vulnerability domain.NormalizedVulnerability `json:"vulnerability"`
	Matched       bool                           `json:"matched"`
	Pipeline      *pipeline.Result               `json:"pipeline,omitempty"`
}

// RepositoryResult contains all distinct CVEs discovered in the configured
// registration window. Unmatched CVEs are included with Matched=false.
type RepositoryResult struct {
	RepositoryID string                `json:"repository_id"`
	From         time.Time             `json:"from"`
	Until        time.Time             `json:"until"`
	Fetched      int                   `json:"fetched"`
	Results      []VulnerabilityResult `json:"results"`
}

// ProcessRepository fetches CVEs published or modified since repository
// registration, following every NVD page (at most 200 results per request).
// NVD exposes publication and modification windows independently, so both
// queries are made and duplicate CVE IDs are collapsed before analysis.
func ProcessRepository(
	ctx context.Context,
	fetcher PageFetcher,
	profile domain.RepositoryProfile,
	config Config,
) (RepositoryResult, error) {
	if ctx == nil {
		return RepositoryResult{}, errors.New("context is required")
	}
	if fetcher == nil {
		return RepositoryResult{}, errors.New("NVD page fetcher is required")
	}
	if profile.Repository.ID == "" || profile.Repository.CommitSHA == "" {
		return RepositoryResult{}, errors.New("repository ID and commit SHA are required")
	}
	if config.RegisteredAt.IsZero() {
		return RepositoryResult{}, errors.New("repository registration time is required")
	}
	from := config.RegisteredAt.UTC()
	until := config.Until
	if until.IsZero() {
		until = time.Now().UTC()
	} else {
		until = until.UTC()
	}
	if until.Before(from) {
		return RepositoryResult{}, errors.New("processing end time precedes repository registration")
	}

	rawByID := make(map[string]nvd.CVE)
	for _, window := range []struct {
		name  string
		query func(time.Time, time.Time) nvd.Query
	}{
		{name: "published", query: func(start, end time.Time) nvd.Query {
			return nvd.Query{PublishedStart: start, PublishedEnd: end, ResultsPerPage: pageSize}
		}},
		{name: "modified", query: func(start, end time.Time) nvd.Query {
			return nvd.Query{ModifiedStart: start, ModifiedEnd: end, ResultsPerPage: pageSize}
		}},
	} {
		if err := fetchWindow(ctx, fetcher, window.name, window.query(from, until), rawByID); err != nil {
			return RepositoryResult{}, err
		}
	}

	normalizedByID := make(map[string]domain.NormalizedVulnerability, len(rawByID))
	for id, raw := range rawByID {
		vulnerability, err := nvd.Normalize(raw)
		if err != nil {
			return RepositoryResult{}, fmt.Errorf("normalize NVD vulnerability %q: %w", id, err)
		}
		normalizedByID[vulnerability.ID] = vulnerability
	}
	vulnerabilities := make([]domain.NormalizedVulnerability, 0, len(normalizedByID))
	for _, vulnerability := range normalizedByID {
		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	sort.Slice(vulnerabilities, func(i, j int) bool {
		if vulnerabilities[i].PublishedAt.Equal(vulnerabilities[j].PublishedAt) {
			return vulnerabilities[i].ID < vulnerabilities[j].ID
		}
		return vulnerabilities[i].PublishedAt.Before(vulnerabilities[j].PublishedAt)
	})

	result := RepositoryResult{
		RepositoryID: profile.Repository.ID,
		From:         from,
		Until:        until,
		Fetched:      len(vulnerabilities),
		Results:      make([]VulnerabilityResult, 0, len(vulnerabilities)),
	}
	candidateMatcher := matcher.New(config.Versions)
	for _, vulnerability := range vulnerabilities {
		candidate, matched, err := candidateMatcher.Match(profile, vulnerability)
		if err != nil {
			return RepositoryResult{}, fmt.Errorf("match %s: %w", vulnerability.ID, err)
		}
		entry := VulnerabilityResult{Vulnerability: vulnerability, Matched: matched}
		if matched {
			evidenceItems, err := evidence.Build(profile, vulnerability, candidate)
			if err != nil {
				return RepositoryResult{}, fmt.Errorf("build evidence for %s: %w", vulnerability.ID, err)
			}
			input := processor.Input{
				Vulnerability: vulnerability,
				Repository:    profile,
				Candidate:     candidate,
				Evidence:      evidenceItems,
			}
			pipelineResult, err := pipeline.Process(ctx, config.Analyzer, input)
			if err != nil {
				return RepositoryResult{}, fmt.Errorf("process %s: %w", vulnerability.ID, err)
			}
			entry.Pipeline = &pipelineResult
		}
		result.Results = append(result.Results, entry)
	}
	return result, nil
}

func fetchWindow(
	ctx context.Context,
	fetcher PageFetcher,
	name string,
	query nvd.Query,
	byID map[string]nvd.CVE,
) error {
	for {
		page, err := fetcher.FetchPage(ctx, query)
		if err != nil {
			return fmt.Errorf("fetch NVD %s window at index %d: %w", name, query.StartIndex, err)
		}
		if len(page.Vulnerabilities) > pageSize {
			return fmt.Errorf("NVD %s page at index %d exceeds %d CVEs", name, query.StartIndex, pageSize)
		}
		for _, item := range page.Vulnerabilities {
			id := item.CVE.ID
			if id == "" {
				return fmt.Errorf("NVD %s page at index %d contains a CVE without an ID", name, query.StartIndex)
			}
			previous, exists := byID[id]
			if !exists || item.CVE.LastModified > previous.LastModified {
				byID[id] = item.CVE
			}
		}
		if len(page.Vulnerabilities) == 0 || query.StartIndex+len(page.Vulnerabilities) >= page.TotalResults {
			return nil
		}
		nextIndex := query.StartIndex + len(page.Vulnerabilities)
		if nextIndex <= query.StartIndex {
			return fmt.Errorf("NVD %s pagination did not advance from index %d", name, query.StartIndex)
		}
		query.StartIndex = nextIndex
	}
}
