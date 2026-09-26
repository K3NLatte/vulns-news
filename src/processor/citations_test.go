package processor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"vulns-news/src/llm"
)

type citationGeneratorFunc func(context.Context, llm.ChatRequest) (llm.ChatResponse, error)

func (f citationGeneratorFunc) Chat(ctx context.Context, request llm.ChatRequest) (llm.ChatResponse, error) {
	return f(ctx, request)
}

func assertEvidenceSchema(t *testing.T, actual, base json.RawMessage, evidence []Evidence) {
	t.Helper()
	var got, want map[string]any
	if err := json.Unmarshal(actual, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(base, &want); err != nil {
		t.Fatal(err)
	}
	fields := []string{"advisory_evidence_ids", "repository_evidence_ids"}
	_, deep := want["$defs"]
	if deep {
		fields = []string{"evidence_ids"}
	}
	for _, field := range fields {
		path := []string{"properties", field, "items"}
		if deep {
			path = append([]string{"$defs", "supported_claim"}, path...)
		}
		items := got
		for _, key := range path {
			var ok bool
			items, ok = items[key].(map[string]any)
			if !ok {
				t.Fatalf("missing schema object %q", key)
			}
		}
		ids := []any{}
		for _, item := range evidence {
			advisory := item.Kind == EvidenceNVD || item.Kind == EvidenceAdvisory
			repository := item.Kind == EvidenceRepositoryDependency || item.Kind == EvidenceRepositorySource || item.Kind == EvidenceStaticAnalysis
			if deep || field == "advisory_evidence_ids" && advisory || field == "repository_evidence_ids" && repository {
				ids = append(ids, item.ID)
			}
		}
		if len(ids) == 0 {
			if !reflect.DeepEqual(items["not"], map[string]any{}) {
				t.Errorf("empty domain must reject all items: %v", items)
			}
			delete(items, "not")
		} else {
			if !reflect.DeepEqual(items["enum"], ids) {
				t.Errorf("%s enum = %v, want %v", field, items["enum"], ids)
			}
			delete(items, "enum")
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Error("base schema constraints changed beyond evidence enum")
	}
}

func citationStage(t *testing.T, p *Processor, input Input, deep bool, ctx context.Context) (Generation, error) {
	t.Helper()
	if deep {
		out, err := p.Analyze(ctx, input)
		return out.Generation, err
	}
	out, err := p.Screen(ctx, input)
	return out.Generation, err
}

func citationResponse(deep bool) string {
	if deep {
		return validDeepResponse
	}
	return `{"relevance":"related","reason":"Recorded dependency matches; runtime use remains unverified.","advisory_evidence_ids":["EVD-NVD-001"],"repository_evidence_ids":["EVD-REPO-DEP-001"]}`
}

func TestCitationCorrectionBothStages(t *testing.T) {
	t.Parallel()
	for _, deep := range []bool{false, true} {
		t.Run(fmt.Sprintf("deep=%t", deep), func(t *testing.T) {
			input := sampleInput()
			good := citationResponse(deep)
			bad := strings.ReplaceAll(good, "EVD-NVD-001", "GHSA-c9f4-xj24-8jqx")
			var requests []llm.ChatRequest
			p, err := New(citationGeneratorFunc(func(_ context.Context, request llm.ChatRequest) (llm.ChatResponse, error) {
				requests = append(requests, request)
				content := bad
				if len(requests) == 2 {
					content = good
				}
				return llm.ChatResponse{Content: content, Model: "test", DoneReason: "stop", PromptTokens: 20, CompletionTokens: 10, TotalDuration: time.Second, LoadDuration: time.Millisecond}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			generation, err := citationStage(t, p, input, deep, context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(requests) != 2 || generation.CitationRetries != 1 || generation.PromptTokens != 40 || generation.CompletionTokens != 20 || generation.TotalDurationNS != int64(2*time.Second) || generation.LoadDurationNS != int64(2*time.Millisecond) {
				t.Fatalf("calls = %d, generation = %+v", len(requests), generation)
			}
			if requests[0].Messages[0].Content == requests[1].Messages[0].Content || requests[0].Messages[1] != requests[1].Messages[1] || string(requests[0].ResponseSchema) != string(requests[1].ResponseSchema) {
				t.Error("retry must change instructions but preserve material and schema")
			}
			for _, request := range requests {
				if len(request.Messages) != 2 {
					t.Fatalf("retry replayed rejected output: %+v", request.Messages)
				}
				for _, message := range request.Messages {
					if strings.Contains(message.Content, "GHSA-c9f4-xj24-8jqx") {
						t.Error("untrusted bad response/error was replayed")
					}
				}
			}
			base := ScreeningSchema()
			if deep {
				base = DeepAnalysisSchema()
			}
			assertEvidenceSchema(t, requests[0].ResponseSchema, base, input.Evidence)
			validator, err := compileSchema("citation-test.json", requests[0].ResponseSchema)
			if err != nil {
				t.Fatal(err)
			}
			var out any
			if err := validateAndDecode(good, validator, &out); err != nil {
				t.Fatalf("request schema rejected known IDs: %v", err)
			}
			if err := validateAndDecode(bad, validator, &out); err == nil {
				t.Error("request schema allowed unknown IDs")
			}
		})
	}
}

func TestCitationCorrectionBoundedAndFailFast(t *testing.T) {
	t.Parallel()
	for _, deep := range []bool{false, true} {
		for _, defect := range []string{"unknown", "schema", "json", "semantic", "transport", "canceled-before", "canceled-during", "transport-on-retry", "schema-on-retry", "canceled-on-retry"} {
			t.Run(fmt.Sprintf("deep=%t/%s", deep, defect), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if defect == "canceled-before" {
					cancel()
				}
				calls := 0
				p, err := New(citationGeneratorFunc(func(_ context.Context, _ llm.ChatRequest) (llm.ChatResponse, error) {
					calls++
					content := strings.ReplaceAll(citationResponse(deep), "EVD-NVD-001", "GHSA-c9f4-xj24-8jqx")
					switch defect {
					case "schema":
						content = strings.Replace(content, "{", `{"unexpected":true,`, 1)
					case "json":
						content = "not JSON"
					case "semantic":
						if deep {
							content = strings.Replace(validDeepResponse, "対象Packageの影響バージョンを使用しています。", " ", 1)
						} else {
							content = `{"relevance":"related","reason":" ","advisory_evidence_ids":["EVD-NVD-001"],"repository_evidence_ids":["EVD-REPO-DEP-001"]}`
						}
					case "transport":
						return llm.ChatResponse{}, errors.New("unknown evidence ID in transport error must not trigger retry")
					case "canceled-during":
						cancel()
					case "transport-on-retry":
						if calls == 2 {
							return llm.ChatResponse{}, context.DeadlineExceeded
						}
					case "schema-on-retry":
						if calls == 2 {
							content = strings.Replace(content, "{", `{"unexpected":true,`, 1)
						}
					case "canceled-on-retry":
						if calls == 2 {
							cancel()
						}
					}
					return llm.ChatResponse{Content: content}, nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				_, err = citationStage(t, p, sampleInput(), deep, ctx)
				if err == nil {
					t.Fatal("invalid result was accepted")
				}
				wantCalls := 1
				switch defect {
				case "unknown":
					wantCalls = 2
					if !strings.Contains(err.Error(), "after one citation correction retry") || !strings.Contains(err.Error(), "unknown evidence ID") {
						t.Errorf("lost final retry error: %v", err)
					}
				case "transport-on-retry":
					wantCalls = 2
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Errorf("lost deadline error: %v", err)
					}
				case "schema-on-retry":
					wantCalls = 2
					if !strings.Contains(err.Error(), "JSON Schema validation failed") {
						t.Errorf("lost schema error: %v", err)
					}
				case "canceled-on-retry":
					wantCalls = 2
					if !errors.Is(err, context.Canceled) {
						t.Errorf("lost cancellation: %v", err)
					}
				case "canceled-before", "canceled-during":
					if defect == "canceled-before" {
						wantCalls = 0
					}
					if !errors.Is(err, context.Canceled) {
						t.Errorf("lost cancellation: %v", err)
					}
				}
				if calls != wantCalls {
					t.Errorf("calls = %d, want %d", calls, wantCalls)
				}
				if strings.Contains(err.Error(), "after one citation correction retry") != (wantCalls == 2) {
					t.Errorf("incorrect retry context for %d calls: %v", calls, err)
				}
			})
		}
	}
}

func TestCitationSchemasAreIsolatedAcrossConcurrentCandidates(t *testing.T) {
	baseScreen, baseDeep := string(ScreeningSchema()), string(DeepAnalysisSchema())
	p, err := New(citationGeneratorFunc(func(_ context.Context, request llm.ChatRequest) (llm.ChatResponse, error) {
		var input Input
		material := strings.TrimSuffix(strings.TrimPrefix(request.Messages[1].Content, "BEGIN_UNTRUSTED_ANALYSIS_MATERIAL\n"), "\nEND_UNTRUSTED_ANALYSIS_MATERIAL")
		if err := json.Unmarshal([]byte(material), &input); err != nil {
			return llm.ChatResponse{}, err
		}
		deep := !strings.Contains(string(request.ResponseSchema), `"relevance"`)
		base := ScreeningSchema()
		if deep {
			base = DeepAnalysisSchema()
		}
		assertEvidenceSchema(t, request.ResponseSchema, base, input.Evidence)
		content := citationResponse(deep)
		for i, original := range sampleInput().Evidence {
			content = strings.ReplaceAll(content, original.ID, input.Evidence[i].ID)
		}
		return llm.ChatResponse{Content: content}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("concurrent", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				t.Parallel()
				input := sampleInput()
				for j := range input.Evidence {
					input.Evidence[j].ID = fmt.Sprintf("EVD-CANDIDATE-%03d-%03d", i, j)
				}
				if _, err := citationStage(t, p, input, i%2 == 0, context.Background()); err != nil {
					t.Fatal(err)
				}
			})
		}
	})
	if string(ScreeningSchema()) != baseScreen || string(DeepAnalysisSchema()) != baseDeep {
		t.Error("request-specific enums mutated global schemas")
	}
}

func TestGenerationKeepsLegacyJSONWhenNotRetried(t *testing.T) {
	got, err := json.Marshal(Generation{})
	if err != nil {
		t.Fatal(err)
	}
	const legacy = `{"model":"","done_reason":"","prompt_tokens":0,"completion_tokens":0,"total_duration_ns":0,"load_duration_ns":0}`
	if string(got) != legacy {
		t.Fatalf("zero retry changed saved JSON/checksums: %s", got)
	}
}
