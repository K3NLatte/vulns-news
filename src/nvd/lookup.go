package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// ErrCVENotFound means NVD returned an empty result for the requested CVE.
var ErrCVENotFound = errors.New("NVD CVE not found")

var lookupCVEID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// LookupCVE retrieves the complete, unmodified CVE object for an uppercase ID.
// It performs one request without retries or pacing; callers manage rate limits.
func (c *AnalysisClient) LookupCVE(ctx context.Context, id string) (json.RawMessage, error) {
	if !lookupCVEID.MatchString(id) {
		return nil, fmt.Errorf("invalid CVE ID %q: expected CVE-[0-9]{4}-[0-9]{4,}", id)
	}
	requestURL := *c.endpoint
	requestURL.RawQuery = url.Values{"cveId": {id}}.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create NVD lookup request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		request.Header.Set("apiKey", c.apiKey)
	}
	// Do not mutate the shared client or forward credentials to redirect targets.
	httpClient := *c.httpClient
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("call NVD lookup: %w", err)
	}
	defer response.Body.Close()

	// Probe separately so even a MaxInt64 limit cannot overflow maximum+1.
	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read NVD lookup response: %w", err)
	}
	var probe [1]byte
	n, err := io.ReadFull(response.Body, probe[:])
	if n != 0 {
		return nil, fmt.Errorf("NVD response body exceeds %d bytes", c.maxResponseBytes)
	}
	if err != io.EOF {
		return nil, fmt.Errorf("read NVD lookup response: %w", err)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		message := strings.TrimSpace(response.Header.Get("message"))
		if message == "" {
			message = responseMessage(body)
		}
		return nil, &HTTPError{StatusCode: response.StatusCode, Message: message}
	}

	var page struct {
		TotalResults    *int `json:"totalResults"`
		StartIndex      *int `json:"startIndex"`
		ResultsPerPage  *int `json:"resultsPerPage"`
		Vulnerabilities *[]struct {
			CVE json.RawMessage `json:"cve"`
		} `json:"vulnerabilities"`
	}
	// Unmarshal rejects truncated JSON and trailing values without discarding
	// unknown provider fields inside the raw CVE object.
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("decode NVD lookup response: %w", err)
	}
	if page.TotalResults == nil || page.Vulnerabilities == nil {
		return nil, errors.New("NVD lookup response missing totalResults or vulnerabilities")
	}
	items := *page.Vulnerabilities
	total := *page.TotalResults
	if total < 0 || total > 1 || len(items) != total ||
		(page.StartIndex != nil && *page.StartIndex != 0) ||
		(page.ResultsPerPage != nil && *page.ResultsPerPage != len(items)) {
		return nil, errors.New("inconsistent NVD lookup result cardinality or pagination")
	}
	if total == 0 {
		return nil, fmt.Errorf("%w: %s", ErrCVENotFound, id)
	}
	var identity struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(items[0].CVE, &identity); err != nil {
		return nil, fmt.Errorf("decode NVD lookup CVE: %w", err)
	}
	if identity.ID != id {
		return nil, fmt.Errorf("NVD lookup returned CVE ID %q; requested %q", identity.ID, id)
	}
	return items[0].CVE, nil
}
