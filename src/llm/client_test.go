package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientChatSendsStructuredNonStreamingRequest(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/chat" {
			t.Errorf("path = %s, want /api/chat", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}

		var request ollamaChatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if request.Model != "qwen3:8b" {
			t.Errorf("model = %q, want qwen3:8b", request.Model)
		}
		if request.Stream {
			t.Error("stream = true, want false")
		}
		if request.Think {
			t.Error("think = true, want false")
		}
		if request.Options.Temperature != 0 {
			t.Errorf("temperature = %v, want 0", request.Options.Temperature)
		}
		if len(request.Messages) != 2 {
			t.Errorf("messages = %d, want 2", len(request.Messages))
		}
		if !json.Valid(request.Format) {
			t.Errorf("format is not valid JSON: %s", request.Format)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"model":"qwen3:8b",
			"created_at":"2026-09-24T12:00:00Z",
			"message":{"role":"assistant","content":"{\"relevance\":\"related\"}"},
			"done":true,
			"done_reason":"stop",
			"total_duration":1200,
			"load_duration":200,
			"prompt_eval_count":42,
			"eval_count":12
		}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{BaseURL: server.URL, Model: "qwen3:8b"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	response, err := client.Chat(context.Background(), ChatRequest{
		Messages: []Message{
			{Role: RoleSystem, Content: "system"},
			{Role: RoleUser, Content: "user"},
		},
		ResponseSchema: json.RawMessage(`{"type":"object"}`),
	})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}

	if response.Model != "qwen3:8b" {
		t.Errorf("model = %q, want qwen3:8b", response.Model)
	}
	if response.Content != `{"relevance":"related"}` {
		t.Errorf("content = %q", response.Content)
	}
	if response.DoneReason != "stop" {
		t.Errorf("done reason = %q, want stop", response.DoneReason)
	}
	if !response.CreatedAt.Equal(time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("created at = %s", response.CreatedAt)
	}
	if response.TotalDuration != 1200*time.Nanosecond {
		t.Errorf("total duration = %s", response.TotalDuration)
	}
	if response.PromptTokens != 42 || response.CompletionTokens != 12 {
		t.Errorf("tokens = %d/%d, want 42/12", response.PromptTokens, response.CompletionTokens)
	}
}

func TestClientChatReturnsHTTPError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"model is not loaded"}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{BaseURL: server.URL, Model: "qwen3:8b"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.Chat(context.Background(), ChatRequest{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})
	var httpError *HTTPError
	if !errors.As(err, &httpError) {
		t.Fatalf("error = %v, want *HTTPError", err)
	}
	if httpError.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d", httpError.StatusCode)
	}
	if httpError.Message != "model is not loaded" {
		t.Errorf("message = %q", httpError.Message)
	}
}

func TestClientChatRejectsIncompleteResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"message":{"role":"assistant","content":"{}"},"done":false}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{BaseURL: server.URL, Model: "qwen3:8b"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.Chat(context.Background(), ChatRequest{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("error = %v, want incomplete response error", err)
	}
}

func TestNewClientAndChatValidateInput(t *testing.T) {
	t.Parallel()

	if _, err := NewClient(Config{}); err == nil {
		t.Fatal("NewClient accepted an empty model")
	}
	if _, err := NewClient(Config{Model: "test", BaseURL: "file:///tmp/ollama"}); err == nil {
		t.Fatal("NewClient accepted a non-HTTP URL")
	}

	client, err := NewClient(Config{Model: "test"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Chat(context.Background(), ChatRequest{})
	if err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("error = %v, want message validation error", err)
	}
	_, err = client.Chat(context.Background(), ChatRequest{
		Messages:       []Message{{Role: RoleUser, Content: "test"}},
		ResponseSchema: json.RawMessage(`{"type":`),
	})
	if err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("error = %v, want schema validation error", err)
	}
}
