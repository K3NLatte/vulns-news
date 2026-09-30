// Package osv provides optional, CVE-linked package matching through OSV.
// Nothing runs automatically: invoking Enrich opts in to disclosing supported
// package names, ecosystems and pinned versions to BaseURL (api.osv.dev by
// default). Repository identity, paths, source and credentials are never sent.
//
// OSV query matches are retained as exact installed-version targets, not as
// inferred ranges. All ecosystems use scheme "osv"; ecosystem/versions confirms
// only the exact queried version and leaves other versions unknown. Target IDs
// and references tagged osv_match record the provider provenance.
// This evidence applies only to the queried version, not to unresolved packages
// or to exploitability. Callers choose whether to enable enrichment.
package osv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/versions"
)

const (
	maxQueries        = 100
	maxResults        = 1000
	maxBodyBytes      = 2 << 20
	maxComponents     = 10000
	maxCacheEntries   = 100
	maxCacheBytes     = 8 << 20
	enrichmentTimeout = 30 * time.Second
)

// Config selects an OSV API root and optional HTTP transport. NewClient does
// not perform I/O. Enrich is the caller's explicit network/disclosure opt-in.
type Config struct {
	BaseURL    string
	HTTPClient *http.Client
}

// Client owns a per-run cache. Reuse it across CVEs for one run; create a new
// client to refresh OSV data. Do not copy a Client after first use. The cache
// holds at most 100 distinct ecosystem/name/version queries (including failures
// and in-flight queries) and 8 MiB of response bodies. Ecosystem aliases share
// entries, but installed versions never do. Capacity exhaustion returns ErrLimit,
// not eviction or silently skipped packages. Non-context failures are cached to
// avoid repeatedly querying a failing service. Cancellation is never cached.
type Client struct {
	endpoint   string
	httpClient *http.Client
	mu         sync.Mutex
	cache      map[query]*cachedQuery
	cacheBytes int
}

// Closing ready publishes immutable data/err to all concurrent waiters.
type cachedQuery struct {
	ready chan struct{}
	data  []byte
	err   error
}

// ErrLimit indicates a budget was exceeded; no partial enrichment is returned.
var ErrLimit = errors.New("OSV enrichment limit exceeded")

// HTTPError reports an unsuccessful OSV response without reflecting its body.
type HTTPError struct{ StatusCode int }

func (e *HTTPError) Error() string { return fmt.Sprintf("OSV returned HTTP %d", e.StatusCode) }

func NewClient(config Config) (*Client, error) {
	base := config.BaseURL
	if base == "" {
		base = "https://api.osv.dev"
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse OSV base URL: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("OSV base URL must be an absolute HTTP(S) URL without credentials, query or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/query"
	u.RawPath = ""
	hc := http.Client{}
	if config.HTTPClient != nil {
		hc = *config.HTTPClient
	}
	// Never forward dependency data to a redirect destination.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{endpoint: u.String(), httpClient: &hc, cache: make(map[query]*cachedQuery)}, nil
}

var (
	cvePattern    = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	mavenName     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*:[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	packagistName = regexp.MustCompile(`^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9]([_.-]?[a-z0-9]+)*$`)
)

type packageKey struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}
type query struct {
	Package packageKey `json:"package"`
	Version string     `json:"version"`
}
type entry struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Withdrawn string   `json:"withdrawn"`
}
type response struct {
	Vulns         []entry `json:"vulns"`
	NextPageToken string  `json:"next_page_token"`
}

func componentQuery(c domain.Component) (query, bool) {
	pkg, ok := componentPackage(c)
	q := query{Package: pkg, Version: c.Version}
	return q, ok && versions.IsPinned(c.Ecosystem, c.Version)
}

// componentPackage accepts both profiler split names and coordinator-qualified
// names. A retained Namespace must agree with an already-qualified name.
func componentPackage(c domain.Component) (packageKey, bool) {
	eco, ok := versions.OSVEcosystem(c.Ecosystem)
	pkg := packageKey{Ecosystem: eco, Name: c.Name}
	if !ok || c.Name == "" {
		return pkg, false
	}
	separator := ""
	switch eco {
	case "Maven":
		separator = ":"
	case "Packagist":
		separator = "/"
	}
	if separator != "" && c.Namespace != "" {
		if strings.Contains(c.Name, separator) {
			if !strings.HasPrefix(c.Name, c.Namespace+separator) {
				return pkg, false
			}
		} else {
			pkg.Name = c.Namespace + separator + c.Name
		}
	}
	if len(pkg.Name) > 512 || strings.ContainsAny(pkg.Name, " \t\r\n\x00") {
		return pkg, false
	}
	if eco == "Maven" && !mavenName.MatchString(pkg.Name) || eco == "Packagist" && !packagistName.MatchString(pkg.Name) {
		return pkg, false
	}
	return pkg, true
}

// The matcher falls back to ecosystem/name even when PURLs differ. Until the
// coordinator qualifies split names, do not emit targets whose fallback identity
// also identifies a different namespace (including unresolved components).
func ambiguousIdentities(components []domain.Component) map[packageKey]bool {
	seen := make(map[packageKey]packageKey)
	ambiguous := make(map[packageKey]bool)
	for _, component := range components {
		identity := packageKey{Ecosystem: component.Ecosystem, Name: component.Name}
		pkg, ok := componentPackage(component)
		if !ok {
			// Invalid identities must not inherit evidence from a valid namesake.
			ambiguous[identity] = true
			continue
		}
		if previous, exists := seen[identity]; exists && previous != pkg {
			ambiguous[identity] = true
		}
		seen[identity] = pkg
	}
	return ambiguous
}

// Enrich queries at most 100 unique pinned ecosystem/name/version tuples,
// consuming at most 1,000 result entries overall and 2 MiB per response,
// within 30 seconds (or the caller's earlier deadline). Only exact CVE ID/alias
// linkage is accepted. Ambiguous unqualified package identities are not emitted;
// callers should qualify Maven and Packagist names before matching.
// Unsupported or unresolved versions are skipped, never resolved or guessed.
// Overflow, pagination, HTTP, decoding and context errors return the original
// vulnerability unchanged; callers may deliberately continue without OSV.
func (c *Client) Enrich(ctx context.Context, profile domain.RepositoryProfile, vulnerability domain.NormalizedVulnerability) (domain.NormalizedVulnerability, error) {
	if c == nil || c.httpClient == nil {
		return vulnerability, errors.New("nil OSV client")
	}
	ctx, cancel := context.WithTimeout(ctx, enrichmentTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return vulnerability, err
	}
	if !cvePattern.MatchString(vulnerability.ID) {
		return vulnerability, nil
	}
	if len(profile.Components) > maxComponents {
		return vulnerability, ErrLimit
	}
	queries := make(map[query]response)
	ordered := make([]query, 0)
	for _, component := range profile.Components {
		q, ok := componentQuery(component)
		if !ok {
			continue
		}
		if _, exists := queries[q]; exists {
			continue
		}
		if len(ordered) == maxQueries {
			return vulnerability, ErrLimit
		}
		queries[q] = response{}
		ordered = append(ordered, q)
	}
	results := 0
	for _, q := range ordered {
		r, err := c.query(ctx, q)
		if err != nil {
			return vulnerability, err
		}
		results += len(r.Vulns)
		if results > maxResults || r.NextPageToken != "" {
			return vulnerability, ErrLimit
		}
		queries[q] = r
	}
	out := vulnerability
	out.Affected = append([]domain.AffectedTarget(nil), vulnerability.Affected...)
	out.References = append([]domain.Reference(nil), vulnerability.References...)
	targets := make(map[string]bool)
	refs := make(map[string]bool)
	for _, t := range out.Affected {
		targets[t.ID] = true
	}
	for _, r := range out.References {
		if contains(r.Tags, "osv_match") {
			refs[r.URL] = true
		}
	}
	ambiguous := ambiguousIdentities(profile.Components)
	for _, component := range profile.Components {
		q, ok := componentQuery(component)
		if !ok || ambiguous[packageKey{Ecosystem: component.Ecosystem, Name: component.Name}] {
			continue
		}
		for _, e := range queries[q].Vulns {
			if e.ID == "" || e.Withdrawn != "" || (e.ID != vulnerability.ID && !contains(e.Aliases, vulnerability.ID)) {
				continue
			}
			id := fmt.Sprintf("osv:%s:%x", e.ID, sha256.Sum256([]byte(component.Ecosystem+"\x00"+component.Namespace+"\x00"+component.Name+"\x00"+component.Version+"\x00"+component.PURL)))
			if !targets[id] {
				out.Affected = append(out.Affected, domain.AffectedTarget{ID: id, Kind: domain.AffectedPackage, PURL: component.PURL, Ecosystem: component.Ecosystem, PackageName: component.Name, Constraints: []domain.VersionConstraint{{Scheme: "osv", Expression: component.Version}}})
				targets[id] = true
			}
			link := "https://osv.dev/vulnerability/" + url.PathEscape(e.ID)
			if !refs[link] {
				out.References = append(out.References, domain.Reference{URL: link, Tags: []string{"osv_match"}})
				refs[link] = true
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return vulnerability, err
	}
	return out, nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func (c *Client) query(ctx context.Context, q query) (response, error) {
	data, err := c.cachedResponse(ctx, q)
	if err != nil {
		return response{}, err
	}
	var r response
	// Decode separately for each caller so cached results cannot be mutated.
	if err := json.Unmarshal(data, &r); err != nil {
		return r, fmt.Errorf("decode OSV response: %w", err)
	}
	return r, nil
}

func (c *Client) cachedResponse(ctx context.Context, q query) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if cached, ok := c.cache[q]; ok {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-cached.ready:
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return cached.data, cached.err
		}
	}
	if len(c.cache) >= maxCacheEntries {
		c.mu.Unlock()
		return nil, ErrLimit
	}
	cached := &cachedQuery{ready: make(chan struct{})}
	c.cache[q] = cached
	c.mu.Unlock()

	data, err := c.fetch(ctx, q)
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err == nil && len(data) > maxCacheBytes-c.cacheBytes {
		err = ErrLimit
	}
	if err == nil {
		cached.data = data
		c.cacheBytes += len(data)
	}
	cached.err = err
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		delete(c.cache, q)
	}
	close(cached.ready)
	return cached.data, cached.err
}

func (c *Client) fetch(ctx context.Context, q query) ([]byte, error) {
	body, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSV query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{StatusCode: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read OSV response: %w", err)
	}
	if len(data) > maxBodyBytes {
		return nil, ErrLimit
	}
	var r response
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("decode OSV response: %w", err)
	}
	if len(r.Vulns) > maxResults || r.NextPageToken != "" {
		return nil, ErrLimit
	}
	return data, nil
}
