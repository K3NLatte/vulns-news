package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// PackageVersion identifies an exact installed package version.
type PackageVersion struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// QueryResult retains discovered IDs even when discovery is incomplete.
type QueryResult struct {
	Query    PackageVersion `json:"query"`
	IDs      []string       `json:"ids"`
	Complete bool           `json:"complete"`
	Error    string         `json:"error,omitempty"`
}

// DiscoveryConfig configures opt-in dependency disclosure to an OSV endpoint.
// Zero limits select defaults: 100 queries, 100 pages per query, and 8 MiB.
// HTTPClient is copied; redirects are disabled and a zero timeout becomes 30s.
type DiscoveryConfig struct {
	BaseURL          string
	HTTPClient       *http.Client
	BatchSize        int
	MaxPages         int
	MaxResponseBytes int64
}

type DiscoveryClient struct {
	baseURL          string
	httpClient       *http.Client
	batchSize        int
	maxPages         int
	maxResponseBytes int64
}

func NewDiscoveryClient(config DiscoveryConfig) (*DiscoveryClient, error) {
	if config.BaseURL == "" {
		config.BaseURL = "https://api.osv.dev"
	}
	u, err := url.Parse(config.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse OSV endpoint: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(config.BaseURL, "#") || u.RawPath != "" || strings.ContainsAny(u.Path, "\\") || strings.IndexFunc(config.BaseURL, unicode.IsControl) >= 0 {
		return nil, errors.New("OSV endpoint must be an absolute HTTP(S) URL without credentials, query, fragment or escaped path")
	}
	prefix := strings.TrimRight(u.Path, "/")
	if prefix != "" && path.Clean(prefix) != prefix {
		return nil, errors.New("OSV endpoint path must be canonical")
	}
	if config.BatchSize < 0 || config.MaxPages < 0 || config.MaxResponseBytes < 0 {
		return nil, errors.New("OSV limits must not be negative")
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.MaxPages == 0 {
		config.MaxPages = 100
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = 8 << 20
	}
	hc := http.Client{}
	if config.HTTPClient != nil {
		hc = *config.HTTPClient
	}
	if hc.Timeout < 0 {
		return nil, errors.New("OSV timeout must not be negative")
	}
	if hc.Timeout == 0 {
		hc.Timeout = 30 * time.Second
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	u.Path = prefix
	return &DiscoveryClient{u.String(), &hc, config.BatchSize, config.MaxPages, config.MaxResponseBytes}, nil
}

func discoveryValidText(s string) bool {
	return strings.TrimSpace(s) != "" && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}

type discoveryQuery struct {
	Package   packageKey `json:"package"`
	Version   string     `json:"version"`
	PageToken string     `json:"page_token,omitempty"`
}

type discoveryPage struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}

// Query returns one result per input, in input order. OSV querybatch responses
// have no echoed identity: their length and positional correspondence are checked
// before any page is applied. There is no aggregate input limit or cache.
func (c *DiscoveryClient) Query(ctx context.Context, queries []PackageVersion) []QueryResult {
	results := make([]QueryResult, len(queries))
	pending := make([]int, 0, len(queries))
	for i, q := range queries {
		results[i] = QueryResult{Query: q, IDs: []string{}}
		if !discoveryValidText(q.Ecosystem) || !discoveryValidText(q.Name) || !discoveryValidText(q.Version) {
			results[i].Error = "invalid ecosystem, name or version"
		} else {
			pending = append(pending, i)
		}
	}
	for len(pending) > 0 {
		n := min(c.batchSize, len(pending))
		active := pending[:n]
		pending = pending[n:]
		tokens := make(map[int]string)
		seen := make(map[int]map[string]bool)
		for page := 1; len(active) > 0; page++ {
			if err := ctx.Err(); err != nil {
				for _, i := range active {
					results[i].Error = err.Error()
				}
				for _, i := range pending {
					results[i].Error = "query skipped: " + err.Error()
				}
				pending = nil
				break
			}
			batch := make([]discoveryQuery, len(active))
			for j, i := range active {
				q := queries[i]
				batch[j] = discoveryQuery{packageKey{Ecosystem: q.Ecosystem, Name: q.Name}, q.Version, tokens[i]}
			}
			payload, _ := json.Marshal(struct {
				Queries []discoveryQuery `json:"queries"`
			}{batch})
			data, err := c.request(ctx, http.MethodPost, "/v1/querybatch", payload)
			var response struct {
				Results []*discoveryPage `json:"results"`
			}
			if err == nil {
				err = json.Unmarshal(data, &response)
			}
			if err == nil && len(response.Results) != len(active) {
				err = errors.New("OSV batch response count mismatch")
			}
			if err == nil {
				for _, p := range response.Results {
					if p == nil {
						err = errors.New("OSV batch response contains null result")
						break
					}
				}
			}
			if err != nil {
				for _, i := range active {
					results[i].Error = err.Error()
				}
				break
			}
			next := make([]int, 0, len(active))
			for j, i := range active {
				p := response.Results[j]
				for _, v := range p.Vulns {
					if !discoveryValidText(v.ID) {
						results[i].Error = "OSV response contains invalid vulnerability ID"
						continue
					}
					results[i].IDs = append(results[i].IDs, v.ID)
				}
				if results[i].Error != "" {
					continue
				}
				token := p.NextPageToken
				if token == "" {
					results[i].Complete = true
					continue
				}
				if seen[i] == nil {
					seen[i] = make(map[string]bool)
				}
				if seen[i][token] {
					results[i].Error = "OSV repeated page token"
					continue
				}
				if page >= c.maxPages {
					results[i].Error = "OSV maximum pages exceeded"
					continue
				}
				seen[i][token] = true
				tokens[i] = token
				next = append(next, i)
			}
			active = next
		}
	}
	for i := range results {
		ids := results[i].IDs
		sort.Strings(ids)
		unique := ids[:0]
		for _, id := range ids {
			if len(unique) == 0 || unique[len(unique)-1] != id {
				unique = append(unique, id)
			}
		}
		results[i].IDs = unique
	}
	return results
}

// Advisory returns the original JSON object, including unknown OSV fields.
func (c *DiscoveryClient) Advisory(ctx context.Context, id string) (json.RawMessage, error) {
	if !discoveryValidText(id) {
		return nil, errors.New("invalid OSV advisory ID")
	}
	data, err := c.request(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, fmt.Errorf("decode OSV advisory: %w", err)
	}
	if object == nil {
		return nil, errors.New("OSV advisory must be a JSON object")
	}
	var actual string
	if err := json.Unmarshal(object["id"], &actual); err != nil || actual != id {
		return nil, errors.New("OSV advisory ID mismatch")
	}
	return json.RawMessage(data), nil
}

func (c *DiscoveryClient) request(ctx context.Context, method, suffix string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.httpClient.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+suffix, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{StatusCode: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes))
	if err != nil {
		return nil, err
	}
	// Probe separately to avoid overflowing a caller-supplied int64 limit.
	var extra [1]byte
	n, err := resp.Body.Read(extra[:])
	if n > 0 {
		return nil, errors.New("OSV response exceeds maximum bytes")
	}
	if err != nil && err != io.EOF {
		return nil, err
	}
	return data, nil
}
