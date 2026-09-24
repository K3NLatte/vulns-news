// Package nvd fetches and normalizes CVE records from the NVD CVE 2.0 API.
package nvd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultBaseURL          = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultTimeout          = 30 * time.Second
	defaultMaxResponseBytes = int64(16 << 20)
	maxPageSize             = 200
)

// Config controls access to the NVD CVE 2.0 endpoint. BaseURL may point at a
// compatible endpoint for testing. APIKey, when set, is sent in the apiKey
// header. HTTPClient defaults to a client with a 30-second timeout.
type Config struct {
	BaseURL          string
	APIKey           string
	HTTPClient       *http.Client
	MaxResponseBytes int64
}

// Query selects a publication and/or modification window and one result page.
// Every non-zero start must have a matching end and vice versa. ResultsPerPage
// defaults to 200 and cannot exceed 200.
type Query struct {
	PublishedStart time.Time
	PublishedEnd   time.Time
	ModifiedStart  time.Time
	ModifiedEnd    time.Time
	StartIndex     int
	ResultsPerPage int
}

// Client fetches pages from the NVD CVE 2.0 API.
type Client struct {
	endpoint         *url.URL
	apiKey           string
	httpClient       *http.Client
	maxResponseBytes int64
}

// HTTPError represents a non-2xx response from NVD.
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("NVD returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("NVD returned HTTP %d: %s", e.StatusCode, e.Message)
}

// NewClient constructs an NVD CVE 2.0 client.
func NewClient(config Config) (*Client, error) {
	baseURL := strings.TrimSpace(config.BaseURL)
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	endpoint, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse NVD base URL: %w", err)
	}
	if (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" {
		return nil, errors.New("NVD base URL must be an absolute HTTP(S) URL")
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("NVD base URL must not contain user info, a query, or a fragment")
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}
	maxBytes := config.MaxResponseBytes
	if maxBytes == 0 {
		maxBytes = defaultMaxResponseBytes
	}
	if maxBytes < 0 {
		return nil, errors.New("NVD maximum response size must be positive")
	}

	return &Client{
		endpoint:         endpoint,
		apiKey:           strings.TrimSpace(config.APIKey),
		httpClient:       httpClient,
		maxResponseBytes: maxBytes,
	}, nil
}

// FetchPage fetches one page for a publication and/or modification window.
func (c *Client) FetchPage(ctx context.Context, query Query) (Page, error) {
	values, err := queryValues(query)
	if err != nil {
		return Page{}, err
	}

	requestURL := *c.endpoint
	requestURL.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return Page{}, fmt.Errorf("create NVD request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		request.Header.Set("apiKey", c.apiKey)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return Page{}, fmt.Errorf("call NVD: %w", err)
	}
	defer response.Body.Close()

	body, err := readLimited(response.Body, c.maxResponseBytes)
	if err != nil {
		return Page{}, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		message := strings.TrimSpace(response.Header.Get("message"))
		if message == "" {
			message = responseMessage(body)
		}
		return Page{}, &HTTPError{StatusCode: response.StatusCode, Message: message}
	}

	var page Page
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&page); err != nil {
		return Page{}, fmt.Errorf("decode NVD response: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return Page{}, err
	}
	if len(page.Vulnerabilities) > maxPageSize {
		return Page{}, fmt.Errorf("NVD response contains %d vulnerabilities; maximum page size is %d", len(page.Vulnerabilities), maxPageSize)
	}
	return page, nil
}

func queryValues(query Query) (url.Values, error) {
	if query.StartIndex < 0 {
		return nil, errors.New("NVD start index must not be negative")
	}
	pageSize := query.ResultsPerPage
	if pageSize == 0 {
		pageSize = maxPageSize
	}
	if pageSize < 1 || pageSize > maxPageSize {
		return nil, fmt.Errorf("NVD results per page must be between 1 and %d", maxPageSize)
	}
	if err := validateWindow("published", query.PublishedStart, query.PublishedEnd); err != nil {
		return nil, err
	}
	if err := validateWindow("modified", query.ModifiedStart, query.ModifiedEnd); err != nil {
		return nil, err
	}
	if query.PublishedStart.IsZero() && query.ModifiedStart.IsZero() {
		return nil, errors.New("NVD published or modified window is required")
	}

	values := make(url.Values)
	values.Set("startIndex", fmt.Sprint(query.StartIndex))
	values.Set("resultsPerPage", fmt.Sprint(pageSize))
	if !query.PublishedStart.IsZero() {
		values.Set("pubStartDate", formatQueryTime(query.PublishedStart))
		values.Set("pubEndDate", formatQueryTime(query.PublishedEnd))
	}
	if !query.ModifiedStart.IsZero() {
		values.Set("lastModStartDate", formatQueryTime(query.ModifiedStart))
		values.Set("lastModEndDate", formatQueryTime(query.ModifiedEnd))
	}
	return values, nil
}

func validateWindow(name string, start, end time.Time) error {
	if start.IsZero() != end.IsZero() {
		return fmt.Errorf("NVD %s window requires both start and end", name)
	}
	if !start.IsZero() && end.Before(start) {
		return fmt.Errorf("NVD %s window end precedes start", name)
	}
	return nil
}

func formatQueryTime(value time.Time) string {
	return value.Format(time.RFC3339Nano)
}

func readLimited(reader io.Reader, maximum int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read NVD response: %w", err)
	}
	if int64(len(body)) > maximum {
		return nil, fmt.Errorf("NVD response body exceeds %d bytes", maximum)
	}
	return body, nil
}

func responseMessage(body []byte) string {
	var decoded struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &decoded) == nil && strings.TrimSpace(decoded.Message) != "" {
		return strings.TrimSpace(decoded.Message)
	}
	const maximum = 512
	message := strings.TrimSpace(string(body))
	if len(message) > maximum {
		message = message[:maximum] + "..."
	}
	return message
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("decode NVD response: unexpected trailing JSON value")
		}
		return fmt.Errorf("decode NVD response trailer: %w", err)
	}
	return nil
}
