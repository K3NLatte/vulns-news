package nvd

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const maxPublicationWindow = 120 * 24 * time.Hour

// LatestOptions selects the newest publications at or before AsOf (required).
// An omitted publication range searches backwards from AsOf. An explicit range
// must supply both endpoints; its end is capped at AsOf. Limit defaults to 200
// and cannot exceed 200. MaxRequests defaults to 128, including count probes.
// Window defaults to seven days and cannot exceed NVD's 120-day maximum.
type LatestOptions struct {
	AsOf           time.Time
	PublishedStart time.Time
	PublishedEnd   time.Time
	Limit          int
	MaxRequests    int
	Window         time.Duration
}

// IncompleteError means the returned partial results must not be treated as the
// latest requested set. Unwrap preserves cancellation and underlying HTTP errors.
type IncompleteError struct {
	Requests int
	Cause    error
}

func (e *IncompleteError) Error() string {
	return fmt.Sprintf("NVD latest retrieval incomplete after %d requests: %v", e.Requests, e.Cause)
}

func (e *IncompleteError) Unwrap() error { return e.Cause }

// FetchLatest retrieves at most Limit unique CVEs, newest publication first.
// It relies on NVD's ascending publication order and seeks to each window's
// tail rather than treating its first page as the newest results. Adjacent
// windows overlap at their inclusive boundary; CVE IDs are deduplicated.
// Page.TotalResults is the selected unique count, not a database-wide count.
//
// NVD has no snapshot token or descending-order query. AsOf freezes publication
// time, not database state: concurrent edits/backfills with unchanged counts
// cannot be detected. Changed counts or invalid pages cause IncompleteError.
// Equal-publication cutoff ties follow NVD's ordering; selected ties are sorted
// by ID. Explicit exhausted ranges may successfully return fewer than Limit;
// default searches that exhaust their request budget return IncompleteError.
// Requests are paced (6 seconds without a key, 650 ms with one), with cancellable
// waits. HTTP errors, including throttling, are surfaced rather than retried.
// Pacing applies to this call only, not other clients sharing an IP or API key.
func (c *Client) FetchLatest(ctx context.Context, options LatestOptions) (Page, error) {
	return c.fetchLatest(ctx, options, waitLatest)
}

func waitLatest(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) fetchLatest(ctx context.Context, options LatestOptions, wait func(context.Context, time.Duration) error) (Page, error) {
	if options.AsOf.IsZero() {
		return Page{}, errors.New("NVD latest retrieval requires AsOf")
	}
	if err := validateWindow("published", options.PublishedStart, options.PublishedEnd); err != nil {
		return Page{}, err
	}
	if options.Limit == 0 {
		options.Limit = maxPageSize
	}
	if options.MaxRequests == 0 {
		options.MaxRequests = 128
	}
	if options.Window == 0 {
		options.Window = 7 * 24 * time.Hour
	}
	if options.Limit < 1 || options.Limit > maxPageSize || options.MaxRequests < 1 || options.Window <= 0 || options.Window > maxPublicationWindow {
		return Page{}, errors.New("invalid NVD latest limit, request budget, or window (maximum 120 days)")
	}
	end := options.AsOf.UTC()
	explicit := !options.PublishedStart.IsZero()
	if explicit && options.PublishedEnd.Before(end) {
		end = options.PublishedEnd.UTC()
	}
	if explicit && options.PublishedStart.After(end) {
		return Page{}, errors.New("NVD publication start is after AsOf")
	}

	type entry struct {
		item      Vulnerability
		published time.Time
	}
	selected := make(map[string]entry)
	requests := 0
	result := func(cause error) (Page, error) {
		entries := make([]entry, 0, len(selected))
		for _, value := range selected {
			entries = append(entries, value)
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].published.Equal(entries[j].published) {
				return entries[i].item.CVE.ID < entries[j].item.CVE.ID
			}
			return entries[i].published.After(entries[j].published)
		})
		if len(entries) > options.Limit {
			entries = entries[:options.Limit]
		}
		page := Page{TotalResults: len(entries), ResultsPerPage: len(entries), Vulnerabilities: make([]Vulnerability, 0, len(entries))}
		for _, value := range entries {
			page.Vulnerabilities = append(page.Vulnerabilities, value.item)
		}
		if cause != nil {
			return page, &IncompleteError{Requests: requests, Cause: cause}
		}
		return page, nil
	}
	interval := 6 * time.Second
	if c.apiKey != "" {
		interval = 650 * time.Millisecond
	}
	fetch := func(query Query) (Page, error) {
		if err := ctx.Err(); err != nil {
			return Page{}, err
		}
		if requests >= options.MaxRequests {
			return Page{}, errors.New("request budget exhausted")
		}
		if requests > 0 {
			if err := wait(ctx, interval); err != nil {
				return Page{}, err
			}
		}
		requests++
		page, err := c.FetchPage(ctx, query)
		if err != nil {
			return Page{}, err
		}
		expected := query.ResultsPerPage
		if remaining := page.TotalResults - query.StartIndex; remaining < expected {
			expected = remaining
		}
		if page.TotalResults < 0 || page.StartIndex != query.StartIndex || expected < 0 || len(page.Vulnerabilities) != expected || page.ResultsPerPage != expected {
			return Page{}, errors.New("inconsistent NVD pagination metadata or short page")
		}
		return page, nil
	}
	for {
		start := end.Add(-options.Window)
		if explicit && start.Before(options.PublishedStart) {
			start = options.PublishedStart.UTC()
		}
		query := Query{PublishedStart: start, PublishedEnd: end, ResultsPerPage: 1}
		probe, err := fetch(query)
		if err != nil {
			return result(err)
		}
		// Seek from the ascending result set's tail. Read earlier chunks only
		// when duplicates leave fewer unique CVEs than requested.
		upper := probe.TotalResults
		var newerBoundary time.Time
		for upper > 0 {
			size := min(maxPageSize, upper)
			query.StartIndex = upper - size
			query.ResultsPerPage = size
			page := probe
			if probe.TotalResults != 1 {
				page, err = fetch(query)
				if err != nil {
					return result(err)
				}
			}
			if page.TotalResults != probe.TotalResults {
				return result(errors.New("NVD result count changed during pagination"))
			}
			var previous time.Time
			for _, item := range page.Vulnerabilities {
				published, err := latestPublicationTime(item.CVE.Published)
				if err != nil || strings.TrimSpace(item.CVE.ID) == "" {
					return result(fmt.Errorf("invalid NVD identity or publication time for %q", item.CVE.ID))
				}
				if published.Before(start) || published.After(end) || (!previous.IsZero() && published.Before(previous)) || (!newerBoundary.IsZero() && published.After(newerBoundary)) {
					return result(errors.New("NVD publications outside window or ascending order"))
				}
				previous = published
				id := strings.ToUpper(strings.TrimSpace(item.CVE.ID))
				if existing, ok := selected[id]; !ok || published.After(existing.published) {
					selected[id] = entry{item: item, published: published}
				}
			}
			if len(selected) >= options.Limit {
				return result(nil)
			}
			newerBoundary, _ = latestPublicationTime(page.Vulnerabilities[0].CVE.Published)
			upper = query.StartIndex
		}
		if explicit && start.Equal(options.PublishedStart) {
			return result(nil)
		}
		end = start
	}
}

func latestPublicationTime(value string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	// NVD also emits UTC timestamps without a zone suffix.
	return time.Parse("2006-01-02T15:04:05.999999999", value)
}
