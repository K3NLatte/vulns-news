package llm

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
	defaultBaseURL      = "http://127.0.0.1:11434"
	defaultTimeout      = 2 * time.Minute
	maxResponseBodySize = 4 << 20
)

// Role identifies the author of a chat message.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Message is one message sent to the local model.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
}

// ChatRequest describes a non-streaming generation. ResponseSchema is sent to
// Ollama as its structured-output format.
type ChatRequest struct {
	Messages       []Message
	ResponseSchema json.RawMessage
}

// ChatResponse contains the generated JSON text and metadata that can be saved
// in the LLM execution history.
type ChatResponse struct {
	Model            string
	Content          string
	DoneReason       string
	CreatedAt        time.Time
	TotalDuration    time.Duration
	LoadDuration     time.Duration
	PromptTokens     int
	CompletionTokens int
}

// Config configures an Ollama client. Model is required. BaseURL defaults to
// Ollama's loopback address. A custom HTTPClient can be supplied by callers and
// tests; otherwise a client with a two-minute timeout is used.
type Config struct {
	BaseURL    string
	Model      string
	HTTPClient *http.Client
}

// Client calls Ollama's local chat API.
type Client struct {
	endpoint   string
	model      string
	httpClient *http.Client
}

// HTTPError represents a non-successful response from Ollama.
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("ollama returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("ollama returned HTTP %d: %s", e.StatusCode, e.Message)
}

// NewClient creates a client for Ollama's /api/chat endpoint.
func NewClient(config Config) (*Client, error) {
	model := strings.TrimSpace(config.Model)
	if model == "" {
		return nil, errors.New("LLM model is required")
	}

	baseURL := strings.TrimSpace(config.BaseURL)
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse Ollama base URL: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("Ollama base URL must be an absolute HTTP(S) URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Ollama base URL must not contain user info, a query, or a fragment")
	}

	endpoint, err := url.JoinPath(parsed.String(), "api", "chat")
	if err != nil {
		return nil, fmt.Errorf("build Ollama chat URL: %w", err)
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}

	return &Client{
		endpoint:   endpoint,
		model:      model,
		httpClient: httpClient,
	}, nil
}

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []Message       `json:"messages"`
	Stream   bool            `json:"stream"`
	Think    bool            `json:"think"`
	Format   json.RawMessage `json:"format,omitempty"`
	Options  ollamaOptions   `json:"options"`
}

type ollamaOptions struct {
	Temperature float64 `json:"temperature"`
}

type ollamaChatResponse struct {
	Model      string    `json:"model"`
	CreatedAt  time.Time `json:"created_at"`
	Done       bool      `json:"done"`
	DoneReason string    `json:"done_reason"`
	Message    Message   `json:"message"`
	Error      string    `json:"error"`

	TotalDuration int64 `json:"total_duration"`
	LoadDuration  int64 `json:"load_duration"`
	PromptTokens  int   `json:"prompt_eval_count"`
	EvalTokens    int   `json:"eval_count"`
}

// Chat performs one low-temperature, non-streaming generation with model
// thinking disabled so the response contains only the requested structured output.
func (c *Client) Chat(ctx context.Context, request ChatRequest) (ChatResponse, error) {
	if err := validateRequest(request); err != nil {
		return ChatResponse{}, err
	}

	payload, err := json.Marshal(ollamaChatRequest{
		Model:    c.model,
		Messages: request.Messages,
		Stream:   false,
		Think:    false,
		Format:   request.ResponseSchema,
		Options: ollamaOptions{
			Temperature: 0,
		},
	})
	if err != nil {
		return ChatResponse{}, fmt.Errorf("encode Ollama request: %w", err)
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return ChatResponse{}, fmt.Errorf("create Ollama request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")

	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("call Ollama: %w", err)
	}
	defer response.Body.Close()

	body, err := readResponseBody(response.Body)
	if err != nil {
		return ChatResponse{}, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return ChatResponse{}, &HTTPError{
			StatusCode: response.StatusCode,
			Message:    responseErrorMessage(body),
		}
	}

	var decoded ollamaChatResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return ChatResponse{}, fmt.Errorf("decode Ollama response: %w", err)
	}
	if decoded.Error != "" {
		return ChatResponse{}, fmt.Errorf("Ollama generation failed: %s", decoded.Error)
	}
	if !decoded.Done {
		return ChatResponse{}, errors.New("Ollama returned an incomplete non-streaming response")
	}
	if strings.TrimSpace(decoded.Message.Content) == "" {
		return ChatResponse{}, errors.New("Ollama returned empty content")
	}

	return ChatResponse{
		Model:            decoded.Model,
		Content:          decoded.Message.Content,
		DoneReason:       decoded.DoneReason,
		CreatedAt:        decoded.CreatedAt,
		TotalDuration:    time.Duration(decoded.TotalDuration),
		LoadDuration:     time.Duration(decoded.LoadDuration),
		PromptTokens:     decoded.PromptTokens,
		CompletionTokens: decoded.EvalTokens,
	}, nil
}

func validateRequest(request ChatRequest) error {
	if len(request.Messages) == 0 {
		return errors.New("at least one LLM message is required")
	}
	for index, message := range request.Messages {
		switch message.Role {
		case RoleSystem, RoleUser, RoleAssistant:
		default:
			return fmt.Errorf("message %d has unsupported role %q", index, message.Role)
		}
		if strings.TrimSpace(message.Content) == "" {
			return fmt.Errorf("message %d has empty content", index)
		}
	}
	if len(request.ResponseSchema) > 0 && !json.Valid(request.ResponseSchema) {
		return errors.New("response schema is not valid JSON")
	}
	return nil
}

func readResponseBody(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxResponseBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("read Ollama response: %w", err)
	}
	if len(body) > maxResponseBodySize {
		return nil, fmt.Errorf("Ollama response exceeds %d bytes", maxResponseBodySize)
	}
	return body, nil
}

func responseErrorMessage(body []byte) string {
	var decoded struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &decoded) == nil && strings.TrimSpace(decoded.Error) != "" {
		return strings.TrimSpace(decoded.Error)
	}

	message := strings.TrimSpace(string(body))
	if len(message) > 512 {
		message = message[:512] + "..."
	}
	return message
}
