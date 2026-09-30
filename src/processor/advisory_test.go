package processor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"vulns-news/src/llm"
)

func advisoryInput(id string) Input {
	input := sampleInput()
	input.Vulnerability.ID = id
	input.Candidate.VulnerabilityID = id
	input.Evidence[0] = Evidence{
		ID: "EVD-ADVISORY-001", Kind: EvidenceAdvisory, Source: "OSV",
		URI:     "https://osv.dev/vulnerability/" + id,
		Content: "The advisory was returned for the exact package/version query. Exploitability is unverified.",
	}
	return input
}

func savedAdvisoryOutputs() (*ScreeningOutput, *AnalysisOutput) {
	return &ScreeningOutput{Result: ScreeningResult{
		Relevance:   RelevanceRelated,
		Reason:      "The advisory lists the recorded dependency version; exploitability is unverified.",
		EvidenceIDs: []string{"EVD-ADVISORY-001", "EVD-REPO-DEP-001"},
	}}, &AnalysisOutput{Analysis: DeepAnalysis{
		Summary: SupportedClaim{
			Text: "The advisory lists the queried package/version.", EvidenceIDs: []string{"EVD-ADVISORY-001"},
		},
		RepositoryImpact: SupportedClaim{
			Text:        "The dependency is recorded; feature usage and exploitability are unverified.",
			EvidenceIDs: []string{"EVD-ADVISORY-001", "EVD-REPO-DEP-001"},
		},
		MissingInformation: []string{"Usage of the affected feature"},
		RecommendedActions: []string{"Review dependency usage and the advisory"},
	}}
}

func TestProcessorAdvisoryPromptsAndSavedOutputs(t *testing.T) {
	t.Parallel()

	for _, id := range []string{"CVE-2026-1234", "GHSA-2345-6789-cfgh", "RUSTSEC-2026-0001"} {
		t.Run(id, func(t *testing.T) {
			input := advisoryInput(id)
			screening, analysis := savedAdvisoryOutputs()
			generator := &fakeGenerator{}
			processor, err := New(generator)
			if err != nil {
				t.Fatal(err)
			}
			checkRequest := func(schema json.RawMessage) {
				t.Helper()
				if len(generator.request.Messages) != 2 {
					t.Fatalf("messages = %d, want 2", len(generator.request.Messages))
				}
				prompt := generator.request.Messages[0].Content
				for _, want := range []string{
					"CVE/advisory", "GHSA", "RUSTSEC", "exact-query", "exploitability",
					"relatedも悪用可能を意味しません",
					"informational=unmaintained", "それ自体は脆弱性を意味しません",
					"unsound", "correctness/safety", "一律にセキュリティ脆弱性がある・ないと断定しない",
					"入力に存在するEvidence IDだけ", "CVE IDやadvisory種別を創作しない",
				} {
					if !strings.Contains(prompt, want) {
						t.Errorf("system prompt missing %q", want)
					}
				}
				if !strings.Contains(generator.request.Messages[1].Content, id) {
					t.Error("user material lost advisory identity")
				}
				assertEvidenceSchema(t, generator.request.ResponseSchema, schema, input.Evidence)
			}
			content, err := json.Marshal(screeningWireResult{
				Relevance: screening.Result.Relevance, Reason: screening.Result.Reason,
				AdvisoryEvidenceIDs:   []string{"EVD-ADVISORY-001"},
				RepositoryEvidenceIDs: []string{"EVD-REPO-DEP-001"},
			})
			if err != nil {
				t.Fatal(err)
			}
			generator.response = llm.ChatResponse{Content: string(content)}
			gotScreening, err := processor.Screen(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			checkRequest(ScreeningSchema())
			content, err = json.Marshal(analysis.Analysis)
			if err != nil {
				t.Fatal(err)
			}
			generator.response.Content = string(content)
			gotAnalysis, err := processor.Analyze(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			checkRequest(DeepAnalysisSchema())
			if err := ValidateOutputs(input, &gotScreening, &gotAnalysis); err != nil {
				t.Fatalf("ValidateOutputs rejected generated results: %v", err)
			}
			if generator.calls != 2 {
				t.Errorf("model calls = %d, want only Screen and Analyze", generator.calls)
			}
		})
	}
}

func TestValidateOutputsAllowsPartialProgress(t *testing.T) {
	t.Parallel()
	input := advisoryInput("RUSTSEC-2026-0001")
	if err := ValidateOutputs(input, nil, nil); err != nil {
		t.Fatalf("no saved outputs: %v", err)
	}
	for _, relevance := range []Relevance{RelevanceRelated, RelevancePossiblyRelated, RelevanceUnrelated, RelevanceUnknown} {
		t.Run(string(relevance), func(t *testing.T) {
			screening, _ := savedAdvisoryOutputs()
			screening.Result.Relevance = relevance
			if err := ValidateOutputs(input, screening, nil); err != nil {
				t.Fatalf("screening without analysis: %v", err)
			}
		})
	}
	screening, analysis := savedAdvisoryOutputs()
	analysis.Analysis.MissingInformation = []string{}
	if err := ValidateOutputs(input, screening, analysis); err != nil {
		t.Fatalf("empty (not null) missing_information: %v", err)
	}
}

func TestValidateOutputsRejectsAnalysisWithoutRelatedScreening(t *testing.T) {
	t.Parallel()
	input := advisoryInput("GHSA-2345-6789-cfgh")
	_, analysis := savedAdvisoryOutputs()
	if err := ValidateOutputs(input, nil, analysis); err == nil || !strings.Contains(err.Error(), "requires related screening") {
		t.Fatalf("analysis without screening: %v", err)
	}
	for _, relevance := range []Relevance{RelevancePossiblyRelated, RelevanceUnrelated, RelevanceUnknown} {
		t.Run(string(relevance), func(t *testing.T) {
			screening, _ := savedAdvisoryOutputs()
			screening.Result.Relevance = relevance
			if err := ValidateOutputs(input, screening, analysis); err == nil || !strings.Contains(err.Error(), "requires related screening") {
				t.Fatalf("analysis with %s screening: %v", relevance, err)
			}
		})
	}
}

func TestValidateOutputsRevalidatesInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Input)
		want   string
	}{
		{"missing vulnerability ID", func(in *Input) { in.Vulnerability.ID = " " }, "vulnerability ID is required"},
		{"malformed evidence ID", func(in *Input) { in.Evidence[0].ID = "EVD-invalid" }, "invalid ID"},
		{"padded evidence ID", func(in *Input) { in.Evidence[0].ID = " EVD-ADVISORY-001 " }, "invalid ID"},
		{"duplicate evidence ID", func(in *Input) { in.Evidence[1].ID = in.Evidence[0].ID }, "duplicate evidence ID"},
		{"unsupported evidence", func(in *Input) { in.Evidence[0].Kind = "model_claim" }, "unsupported kind"},
		{"missing evidence", func(in *Input) { in.Evidence = nil }, "at least one evidence"},
		{"oversized evidence", func(in *Input) { in.Evidence[0].Content = strings.Repeat("x", maxEvidenceContentSize+1) }, "exceeds"},
		{"oversized facts", func(in *Input) { in.Vulnerability.Description = strings.Repeat("x", maxMaterialSize+1) }, "analysis facts exceed"},
		{"vulnerability mismatch", func(in *Input) { in.Candidate.VulnerabilityID = "RUSTSEC-2026-0002" }, "vulnerability revision"},
		{"revision mismatch", func(in *Input) { in.Candidate.VulnerabilityRev = in.Candidate.VulnerabilityRev.Add(time.Second) }, "vulnerability revision"},
		{"repository mismatch", func(in *Input) { in.Candidate.RepositoryID = "other-repository" }, "repository profile"},
		{"commit mismatch", func(in *Input) { in.Candidate.RepositoryCommit = "other-commit" }, "repository profile"},
		{"unknown target", func(in *Input) { in.Candidate.Matches[0].AffectedTargetID = "made-up" }, "unknown affected target"},
		{"unknown repository item", func(in *Input) { in.Candidate.Matches[0].RepositoryItemID = "made-up" }, "unknown repository item"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := advisoryInput("RUSTSEC-2026-0001")
			tt.mutate(&input)
			screening, analysis := savedAdvisoryOutputs()
			if err := ValidateOutputs(input, screening, analysis); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateOutputsRejectsInvalidScreening(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*ScreeningResult)
		want   string
	}{
		{"invalid relevance", func(r *ScreeningResult) { r.Relevance = "exploitable" }, "JSON Schema validation failed"},
		{"empty reason", func(r *ScreeningResult) { r.Reason = "" }, "JSON Schema validation failed"},
		{"blank reason", func(r *ScreeningResult) { r.Reason = " \n\t" }, "reason is required"},
		{"null citations", func(r *ScreeningResult) { r.EvidenceIDs = nil }, "JSON Schema validation failed"},
		{"empty citations", func(r *ScreeningResult) { r.EvidenceIDs = []string{} }, "JSON Schema validation failed"},
		{"duplicate citations", func(r *ScreeningResult) { r.EvidenceIDs = append(r.EvidenceIDs, r.EvidenceIDs[0]) }, "JSON Schema validation failed"},
		{"invented citation", func(r *ScreeningResult) { r.EvidenceIDs = append(r.EvidenceIDs, "EVD-INVENTED") }, "unknown evidence ID"},
		{"malformed citation", func(r *ScreeningResult) { r.EvidenceIDs[0] = " EVD-ADVISORY-001 " }, "unknown evidence ID"},
		{"no repository support", func(r *ScreeningResult) { r.EvidenceIDs = []string{"EVD-ADVISORY-001"} }, "requires repository evidence"},
		{"no advisory support", func(r *ScreeningResult) { r.EvidenceIDs = []string{"EVD-REPO-DEP-001"} }, "requires NVD or advisory evidence"},
		{"oversized reason", func(r *ScreeningResult) { r.Reason = strings.Repeat("x", maxGeneratedJSONSize+1) }, "generated JSON exceeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			screening, _ := savedAdvisoryOutputs()
			tt.mutate(&screening.Result)
			err := ValidateOutputs(advisoryInput("GHSA-2345-6789-cfgh"), screening, nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateOutputsRejectsUnsupportedAnalysis(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*DeepAnalysis)
		want   string
	}{
		{"empty summary", func(a *DeepAnalysis) { a.Summary.Text = "" }, "JSON Schema validation failed"},
		{"blank summary", func(a *DeepAnalysis) { a.Summary.Text = " \n\t" }, "summary.text is required"},
		{"unsupported summary", func(a *DeepAnalysis) { a.Summary.EvidenceIDs = nil }, "JSON Schema validation failed"},
		{"invented summary citation", func(a *DeepAnalysis) { a.Summary.EvidenceIDs = []string{"EVD-INVENTED"} }, "summary.evidence_ids references unknown evidence ID"},
		{"duplicate summary citations", func(a *DeepAnalysis) { a.Summary.EvidenceIDs = append(a.Summary.EvidenceIDs, a.Summary.EvidenceIDs[0]) }, "JSON Schema validation failed"},
		{"blank impact", func(a *DeepAnalysis) { a.RepositoryImpact.Text = " \t" }, "repository_impact.text is required"},
		{"unsupported impact", func(a *DeepAnalysis) { a.RepositoryImpact.EvidenceIDs = []string{} }, "JSON Schema validation failed"},
		{"invented impact citation", func(a *DeepAnalysis) { a.RepositoryImpact.EvidenceIDs = []string{"EVD-INVENTED"} }, "repository_impact.evidence_ids references unknown evidence ID"},
		{"null missing information", func(a *DeepAnalysis) { a.MissingInformation = nil }, "JSON Schema validation failed"},
		{"empty missing information", func(a *DeepAnalysis) { a.MissingInformation = []string{""} }, "JSON Schema validation failed"},
		{"blank missing information", func(a *DeepAnalysis) { a.MissingInformation = []string{" "} }, "missing_information[0] must not be empty"},
		{"null actions", func(a *DeepAnalysis) { a.RecommendedActions = nil }, "JSON Schema validation failed"},
		{"empty actions", func(a *DeepAnalysis) { a.RecommendedActions = []string{} }, "JSON Schema validation failed"},
		{"empty action text", func(a *DeepAnalysis) { a.RecommendedActions = []string{""} }, "JSON Schema validation failed"},
		{"blank action text", func(a *DeepAnalysis) { a.RecommendedActions = []string{" "} }, "recommended_actions[0] must not be empty"},
		{"oversized summary", func(a *DeepAnalysis) { a.Summary.Text = strings.Repeat("x", maxGeneratedJSONSize+1) }, "generated JSON exceeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			screening, analysis := savedAdvisoryOutputs()
			tt.mutate(&analysis.Analysis)
			err := ValidateOutputs(advisoryInput("RUSTSEC-2026-0001"), screening, analysis)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}
