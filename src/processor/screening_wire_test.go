package processor

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"vulns-news/src/llm"
)

func TestScreeningTypedCitations(t *testing.T) {
	t.Parallel()
	for _, relevance := range []Relevance{RelevanceRelated, RelevancePossiblyRelated, RelevanceUnrelated, RelevanceUnknown} {
		for _, tc := range []struct {
			name                 string
			advisory, repository []string
			wantError            string
		}{
			{"both", []string{"EVD-NVD-001"}, []string{"EVD-REPO-DEP-001"}, ""},
			{"advisory only", []string{"EVD-NVD-001"}, []string{}, "requires repository evidence"},
			{"repository only", []string{}, []string{"EVD-REPO-DEP-001"}, "requires NVD or advisory evidence"},
			{"neither", []string{}, []string{}, "requires at least one evidence ID"},
			{"swapped", []string{"EVD-REPO-DEP-001"}, []string{"EVD-NVD-001"}, "incompatible evidence kind"},
			{"repository mixed", []string{"EVD-NVD-001"}, []string{"EVD-REPO-DEP-001", "EVD-NVD-001"}, "incompatible evidence kind"},
			{"advisory mixed", []string{"EVD-NVD-001", "EVD-REPO-DEP-001"}, []string{"EVD-REPO-DEP-001"}, "incompatible evidence kind"},
			{"unknown advisory", []string{"EVD-UNKNOWN"}, []string{"EVD-REPO-DEP-001"}, "unknown evidence ID"},
			{"unknown repository", []string{"EVD-NVD-001"}, []string{"EVD-UNKNOWN"}, "unknown evidence ID"},
		} {
			t.Run(string(relevance)+"/"+tc.name, func(t *testing.T) {
				wire := screeningWireResult{Relevance: relevance, Reason: "Evidence is limited.", AdvisoryEvidenceIDs: tc.advisory, RepositoryEvidenceIDs: tc.repository}
				content, err := json.Marshal(wire)
				if err != nil {
					t.Fatal(err)
				}
				generator := &fakeGenerator{response: llm.ChatResponse{Content: string(content)}}
				p, err := New(generator)
				if err != nil {
					t.Fatal(err)
				}
				out, err := p.Screen(context.Background(), sampleInput())
				wantError := tc.wantError
				if relevance == RelevanceUnknown && (tc.name == "advisory only" || tc.name == "repository only") {
					wantError = ""
				}
				if wantError != "" {
					if err == nil || !strings.Contains(err.Error(), wantError) {
						t.Fatalf("error = %v, want %q", err, wantError)
					}
					if generator.calls != 2 || !reflect.DeepEqual(out, ScreeningOutput{}) {
						t.Fatalf("failed citation produced output or escaped retry bound: %+v, calls=%d", out, generator.calls)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if out.Result.Relevance != relevance || generator.calls != 1 {
					t.Fatalf("changed decision or retried valid result: %+v", out)
				}
				if err := ValidateOutputs(sampleInput(), &out, nil); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestScreeningCitationKindsAndSchemas(t *testing.T) {
	t.Parallel()
	for _, kind := range []EvidenceKind{EvidenceNVD, EvidenceAdvisory, EvidenceRepositoryDependency, EvidenceRepositorySource, EvidenceStaticAnalysis, EvidencePoCCandidate, EvidencePoCVerified, EvidenceExploit, EvidenceCISAKEV, EvidenceExploitation, EvidencePatch, EvidenceCommit, EvidenceRelease} {
		t.Run(string(kind), func(t *testing.T) {
			input := sampleInput()
			input.Evidence = []Evidence{{ID: "EVD-ONLY-001", Kind: kind, Source: "test", Content: "Recorded evidence."}}
			schema, err := screeningSchemaWithEvidenceIDs(input.Evidence)
			if err != nil {
				t.Fatal(err)
			}
			assertEvidenceSchema(t, schema, ScreeningSchema(), input.Evidence)
			validator, err := compileSchema("typed-test.json", schema)
			if err != nil {
				t.Fatal(err)
			}
			for _, advisory := range []bool{true, false} {
				wire := screeningWireResult{Relevance: RelevanceUnknown, Reason: "Only one domain is available.", AdvisoryEvidenceIDs: []string{}, RepositoryEvidenceIDs: []string{}}
				if advisory {
					wire.AdvisoryEvidenceIDs = []string{"EVD-ONLY-001"}
				} else {
					wire.RepositoryEvidenceIDs = []string{"EVD-ONLY-001"}
				}
				content, err := json.Marshal(wire)
				if err != nil {
					t.Fatal(err)
				}
				allowed := advisory && (kind == EvidenceNVD || kind == EvidenceAdvisory) || !advisory && (kind == EvidenceRepositoryDependency || kind == EvidenceRepositorySource || kind == EvidenceStaticAnalysis)
				var decoded screeningWireResult
				if err := validateAndDecode(string(content), validator, &decoded); (err == nil) != allowed {
					t.Fatalf("schema: kind=%s advisory=%t error=%v", kind, advisory, err)
				}
				generator := &fakeGenerator{response: llm.ChatResponse{Content: string(content)}}
				p, err := New(generator)
				if err != nil {
					t.Fatal(err)
				}
				_, err = p.Screen(context.Background(), input)
				if (err == nil) != allowed {
					t.Fatalf("backend: kind=%s advisory=%t error=%v", kind, advisory, err)
				}
			}
		})
	}
}

func TestScreeningWirePreservesSavedFormat(t *testing.T) {
	p, err := New(&fakeGenerator{response: llm.ChatResponse{Content: citationResponse(false)}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Screen(context.Background(), sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(out.Result)
	if err != nil {
		t.Fatal(err)
	}
	const legacy = `{"relevance":"related","reason":"Recorded dependency matches; runtime use remains unverified.","evidence_ids":["EVD-NVD-001","EVD-REPO-DEP-001"]}`
	if string(got) != legacy {
		t.Fatalf("saved result changed: %s", got)
	}
	// Legacy checkpoints may contain other valid evidence kinds and a different
	// citation order. Loading them must not apply the new wire restrictions.
	input := sampleInput()
	input.Evidence = append(input.Evidence, Evidence{ID: "EVD-PATCH-001", Kind: EvidencePatch, Source: "test", Content: "Patch recorded."})
	out.Result.EvidenceIDs = []string{"EVD-REPO-DEP-001", "EVD-PATCH-001", "EVD-NVD-001"}
	before, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOutputs(input, &out, nil); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("validation changed checkpoint bytes")
	}
}

func TestSwappedCitationsCanBeCorrectedWithoutChangingDecision(t *testing.T) {
	calls := 0
	p, err := New(citationGeneratorFunc(func(_ context.Context, request llm.ChatRequest) (llm.ChatResponse, error) {
		calls++
		content := strings.Replace(citationResponse(false), `"related"`, `"unrelated"`, 1)
		if calls == 1 {
			content = strings.NewReplacer("EVD-NVD-001", "EVD-REPO-DEP-001", "EVD-REPO-DEP-001", "EVD-NVD-001").Replace(content)
		} else {
			for _, field := range []string{"advisory_evidence_ids", "repository_evidence_ids"} {
				if !strings.Contains(request.Messages[0].Content, field) {
					t.Errorf("correction lacks %s", field)
				}
			}
		}
		return llm.ChatResponse{Content: content}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Screen(context.Background(), sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Relevance != RelevanceUnrelated || out.Generation.CitationRetries != 1 || calls != 2 {
		t.Fatalf("unexpected corrected output: %+v, calls=%d", out, calls)
	}
}
