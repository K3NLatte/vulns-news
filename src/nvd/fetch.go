package nvd

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"vulns-news/src/domain"
)

// NormalizedVulnerability is the shared crawler/domain representation.
type NormalizedVulnerability = domain.NormalizedVulnerability

// Fetch retrieves exactly count unique global latest publications, newest first.
// Count must be between 1 and 200. No publication or modification filter is sent.
// Requests use a one-record count probe, exact tail offsets, and a 128-request
// budget (including the probe), paced per call
// at six seconds without an API key or 650 ms with one. Errors return no records.
// NVD has no snapshot token: unchanged-count concurrent edits cannot be detected.
// Equal-publication cutoff ties follow NVD ordering; selected ties sort by ID.
func (c *AnalysisClient) Fetch(ctx context.Context, count int) ([]NormalizedVulnerability, error) {
	return c.fetch(ctx, count, waitLatest)
}

func (c *AnalysisClient) fetch(ctx context.Context, count int, wait func(context.Context, time.Duration) error) ([]NormalizedVulnerability, error) {
	if count < 1 || count > maxPageSize {
		return nil, fmt.Errorf("NVD fetch count must be between 1 and %d", maxPageSize)
	}
	requests := 0
	fail := func(err error) ([]NormalizedVulnerability, error) {
		return nil, &IncompleteError{Requests: requests, Cause: err}
	}
	interval := 6 * time.Second
	if c.apiKey != "" {
		interval = 650 * time.Millisecond
	}
	total := -1
	fetch := func(start, size int) ([]NormalizedVulnerability, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if requests >= 128 {
			return nil, errors.New("NVD request budget exhausted")
		}
		if requests > 0 {
			if err := wait(ctx, interval); err != nil {
				return nil, err
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		requests++
		page, err := c.FetchPage(ctx, Query{StartIndex: start, ResultsPerPage: size})
		if err != nil {
			return nil, err
		}
		// The first request is a count-only probe, not a data page. Its CVE
		// payload is neither validated nor used, matching the PR #18 crawler.
		if requests == 1 {
			if page.TotalResults < 0 {
				return nil, fmt.Errorf("invalid NVD probe totalResults=%d", page.TotalResults)
			}
			total = page.TotalResults
			return nil, nil
		}
		if total >= 0 && page.TotalResults != total {
			return nil, fmt.Errorf("NVD result count changed during pagination: before totalResults=%d; after totalResults=%d; requested startIndex=%d resultsPerPage=%d; got startIndex=%d resultsPerPage=%d vulnerability_count=%d", total, page.TotalResults, start, size, page.StartIndex, page.ResultsPerPage, len(page.Vulnerabilities))
		}
		expected := size
		if remaining := page.TotalResults - start; remaining < expected {
			expected = remaining
		}
		if page.TotalResults < 0 || expected < 0 || page.StartIndex != start || page.ResultsPerPage != expected || len(page.Vulnerabilities) != expected {
			return nil, fmt.Errorf(
				"inconsistent NVD pagination metadata: requested startIndex=%d resultsPerPage=%d; expected response startIndex=%d resultsPerPage=%d vulnerability_count=%d; got startIndex=%d resultsPerPage=%d totalResults=%d vulnerability_count=%d",
				start, size, start, expected, expected,
				page.StartIndex, page.ResultsPerPage, page.TotalResults, len(page.Vulnerabilities),
			)
		}
		total = page.TotalResults
		items, err := normalizeFetched(ctx, page)
		if err != nil {
			return nil, err
		}
		for i, item := range items {
			if item.PublishedAt.IsZero() || item.ModifiedAt.IsZero() || (i > 0 && item.PublishedAt.Before(items[i-1].PublishedAt)) {
				return nil, errors.New("invalid NVD timestamps or ascending publication order")
			}
		}
		return items, nil
	}
	// Always fetch the actual data separately, even for a singleton database.
	_, err := fetch(0, 1)
	if err != nil {
		return fail(err)
	}
	if total < count {
		return fail(fmt.Errorf("NVD contains %d records; requested %d", total, count))
	}
	selected := make(map[string]NormalizedVulnerability)
	var newerBoundary time.Time
	upper := total
	for {
		size := count - len(selected)
		if size > maxPageSize {
			size = maxPageSize
		}
		if size > upper {
			size = upper
		}
		start := upper - size
		items, err := fetch(start, size)
		if err != nil {
			return fail(err)
		}
		if !newerBoundary.IsZero() && items[len(items)-1].PublishedAt.After(newerBoundary) {
			return fail(errors.New("NVD publications violate ascending order across pages"))
		}
		for _, item := range items {
			id := strings.ToUpper(strings.TrimSpace(item.ID))
			if existing, ok := selected[id]; !ok || item.PublishedAt.After(existing.PublishedAt) {
				selected[id] = item
			}
		}
		if len(selected) >= count {
			result := make([]NormalizedVulnerability, 0, len(selected))
			for _, item := range selected {
				result = append(result, item)
			}
			sort.Slice(result, func(i, j int) bool {
				if result[i].PublishedAt.Equal(result[j].PublishedAt) {
					return result[i].ID < result[j].ID
				}
				return result[i].PublishedAt.After(result[j].PublishedAt)
			})
			if err := ctx.Err(); err != nil {
				return fail(err)
			}
			return result[:count], nil
		}
		upper = start
		if upper == 0 {
			return fail(fmt.Errorf("NVD contains only %d unique records; requested %d", len(selected), count))
		}
		newerBoundary = items[0].PublishedAt
	}
}

// FetchNormalizedLatest normalizes the existing date-window FetchLatest path.
// It preserves LatestOptions semantics, including shorter exhausted explicit
// ranges, but discards all partial results on retrieval or normalization errors.
func (c *AnalysisClient) FetchNormalizedLatest(ctx context.Context, options LatestOptions) ([]NormalizedVulnerability, error) {
	return c.fetchNormalizedLatest(ctx, options, waitLatest)
}

func (c *AnalysisClient) fetchNormalizedLatest(ctx context.Context, options LatestOptions, wait func(context.Context, time.Duration) error) ([]NormalizedVulnerability, error) {
	page, err := c.fetchLatest(ctx, options, wait)
	if err != nil {
		return nil, err
	}
	return normalizeFetched(ctx, page)
}

func normalizeFetched(ctx context.Context, page Page) ([]NormalizedVulnerability, error) {
	result := make([]NormalizedVulnerability, 0, len(page.Vulnerabilities))
	for _, item := range page.Vulnerabilities {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		normalized, err := Normalize(item.CVE)
		if err != nil {
			return nil, err
		}
		result = append(result, normalized)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
