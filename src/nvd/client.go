package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	apiURL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	pageSize = 2000
)

// CVE contains a CVE identifier and its description.
type CVE struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// Client retrieves CVEs from the NVD API without an API key.
type Client struct {
	httpClient *http.Client
	endpoint   string
	interval   time.Duration
}

// NewClient returns a client with a 30-second request timeout.
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		endpoint:   apiURL,
		interval:   6 * time.Second,
	}
}

type apiResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// Fetch returns count CVEs in newest-first published order. It prefers English
// descriptions and returns an error if count exceeds NVD's total results.
func (c *Client) Fetch(ctx context.Context, count int) ([]CVE, error) {
	if count <= 0 {
		return nil, errors.New("件数は1以上を指定してください")
	}
	// The API returns the oldest published CVE first. Read its total before
	// requesting pages from the end of the collection.
	first, err := c.getPage(ctx, 0, 1)
	if err != nil {
		return nil, err
	}
	if count > first.TotalResults {
		return nil, fmt.Errorf("指定件数 %d は取得可能なCVE %d 件を超えています", count, first.TotalResults)
	}

	records := make([]CVE, 0, min(count, pageSize))
	for len(records) < count {
		if c.interval > 0 {
			timer := time.NewTimer(c.interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		size := min(count-len(records), pageSize)
		start := first.TotalResults - len(records) - size
		page, err := c.getPage(ctx, start, size)
		if err != nil {
			return nil, err
		}
		if page.TotalResults != first.TotalResults {
			return nil, errors.New("取得中にNVDの総件数が変わりました。再実行してください")
		}
		if len(page.Vulnerabilities) != size {
			return nil, fmt.Errorf("NVD APIの取得件数が要求件数と異なります: %d/%d", len(page.Vulnerabilities), size)
		}
		for i := len(page.Vulnerabilities) - 1; i >= 0; i-- {
			item := page.Vulnerabilities[i]
			entry := CVE{ID: item.CVE.ID}
			if len(item.CVE.Descriptions) > 0 {
				entry.Description = item.CVE.Descriptions[0].Value
			}
			for _, description := range item.CVE.Descriptions {
				if description.Lang == "en" {
					entry.Description = description.Value
					break
				}
			}
			records = append(records, entry)
		}
	}
	return records, nil
}

func (c *Client) getPage(ctx context.Context, start, size int) (apiResponse, error) {
	var page apiResponse
	u, err := url.Parse(c.endpoint)
	if err != nil {
		return page, err
	}
	query := u.Query()
	query.Set("startIndex", fmt.Sprint(start))
	query.Set("resultsPerPage", fmt.Sprint(size))
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return page, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return page, fmt.Errorf("NVD APIへの接続: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return page, fmt.Errorf("NVD APIがHTTP %dを返しました", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return page, fmt.Errorf("NVD APIの応答を解析できません: %w", err)
	}
	return page, nil
}
