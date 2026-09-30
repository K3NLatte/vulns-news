package processor

import (
	"encoding/json"
	"reflect"
	"testing"

	"vulns-news/src/assessment"
	"vulns-news/src/domain"
)

func TestPrepareInputSerializesAssessmentAndSourceObservations(t *testing.T) {
	input := sampleInput()
	input.Repository.SourceObservations = []domain.SourceObservation{
		{Kind: "imported_selector_call", File: "api/main.go", Line: 12, EndLine: 14, Package: "example.org/archive", Symbol: "Extract"},
		{Kind: "http_route_registration", File: "api/main.go", Line: 20, EndLine: 20, Package: "net/http", Symbol: "HandleFunc", Route: "POST /archive"},
	}
	input.Repository.Warnings = []string{"Source observations are syntactic, not reachability proof."}
	material, evidence, err := prepareInput(input)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Applicability *assessment.Report `json:"applicability"`
		Repository    struct {
			SourceObservations []domain.SourceObservation `json:"source_observations"`
			Warnings           []string                   `json:"warnings"`
		} `json:"repository"`
		Evidence []Evidence `json:"evidence"`
	}
	if err := json.Unmarshal(material, &decoded); err != nil {
		t.Fatalf("invalid prompt JSON: %v", err)
	}
	if !reflect.DeepEqual(decoded.Repository.SourceObservations, input.Repository.SourceObservations) {
		t.Errorf("serialized source observations = %+v", decoded.Repository.SourceObservations)
	}
	if !reflect.DeepEqual(decoded.Repository.Warnings, input.Repository.Warnings) {
		t.Errorf("serialized warnings = %+v", decoded.Repository.Warnings)
	}
	if !reflect.DeepEqual(decoded.Evidence, input.Evidence) {
		t.Errorf("serialized evidence = %+v", decoded.Evidence)
	}
	if len(evidence) != len(input.Evidence) {
		t.Errorf("evidence index size = %d", len(evidence))
	}
	for _, want := range input.Evidence {
		if got, ok := evidence[want.ID]; !ok || got != want {
			t.Errorf("evidence index lost %q", want.ID)
		}
	}
	if decoded.Applicability == nil {
		t.Fatal("serialized prompt material is missing backend-owned applicability assessment")
	}
	want := assessment.Assess(input.Repository, input.Vulnerability, input.Candidate)
	if !reflect.DeepEqual(*decoded.Applicability, want) {
		t.Errorf("serialized assessment = %+v, want %+v", *decoded.Applicability, want)
	}
	for _, check := range []assessment.Check{decoded.Applicability.FeatureUsage, decoded.Applicability.CodeReachability, decoded.Applicability.AttackConditions} {
		if check.Status != assessment.Unknown || len(check.MissingReasons) == 0 {
			t.Errorf("source observations must not establish level %d: %+v", check.Level, check)
		}
	}
}
