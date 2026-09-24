package feed

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"vulns-news/src/assessment"
	"vulns-news/src/domain"
	"vulns-news/src/processor"
)

func TestBuildApplicabilityRemainsConservativeWithSourceAndAnalysis(t *testing.T) {
	revision := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	input := processor.Input{
		Repository: domain.RepositoryProfile{
			Repository:         domain.RepositoryIdentity{ID: "repo", CommitSHA: "abc123"},
			Components:         []domain.Component{{ID: "dep", Ecosystem: "npm", Name: "archive", PURL: "pkg:npm/archive", Version: "1.0.0", SourcePath: "package-lock.json"}},
			SourceObservations: []domain.SourceObservation{{Kind: "http_route_registration", File: "main.go", Line: 4, EndLine: 4, Package: "net/http", Symbol: "HandleFunc", Route: "/archive"}},
		},
		Vulnerability: domain.NormalizedVulnerability{ID: "CVE-2026-1234", ModifiedAt: revision, Affected: []domain.AffectedTarget{{ID: "target", Kind: domain.AffectedPackage, PURL: "pkg:npm/archive", Constraints: []domain.VersionConstraint{{Scheme: "semver", VersionEndExcluding: "2.0.0"}}}}},
		Candidate:     domain.MatchCandidate{RepositoryID: "repo", RepositoryCommit: "abc123", VulnerabilityID: "CVE-2026-1234", VulnerabilityRev: revision, Matches: []domain.TargetMatch{{RepositoryItemID: "dep", AffectedTargetID: "target", Reason: domain.MatchPURLExact, InstalledVersion: "1.0.0", VersionStatus: domain.VersionAffected}}},
	}
	for _, relevance := range []processor.Relevance{processor.RelevanceUnknown, processor.RelevancePossiblyRelated, processor.RelevanceRelated} {
		t.Run(string(relevance), func(t *testing.T) {
			var analysis *processor.AnalysisOutput
			if relevance == processor.RelevanceRelated {
				analysis = &processor.AnalysisOutput{Analysis: processor.DeepAnalysis{Summary: processor.SupportedClaim{Text: "The vulnerable feature is used and remotely exploitable."}, RepositoryImpact: processor.SupportedClaim{Text: "An attacker can reach the vulnerable code."}}}
			}
			item, err := Build(input, processor.ScreeningOutput{Result: processor.ScreeningResult{Relevance: relevance, Reason: "The route exposes the vulnerable feature."}}, analysis)
			if err != nil {
				t.Fatal(err)
			}
			want := assessment.Assess(input.Repository, input.Vulnerability, input.Candidate)
			if !reflect.DeepEqual(item.Applicability, want) {
				t.Errorf("applicability = %+v, want %+v", item.Applicability, want)
			}
			if item.Applicability.PackagePresence.Status != assessment.Confirmed || item.Applicability.AffectedVersion.Status != assessment.Confirmed {
				t.Errorf("levels 1–2 lost deterministic facts: %+v", item.Applicability)
			}
			for i, check := range []assessment.Check{item.Applicability.FeatureUsage, item.Applicability.CodeReachability, item.Applicability.AttackConditions} {
				if check.Level != i+3 || check.Status != assessment.Unknown || len(check.MissingReasons) == 0 || len(check.EvidenceIDs) != 0 {
					t.Errorf("level %d must remain unknown without invented proof: %+v", i+3, check)
				}
			}
			encoded, err := json.Marshal(item)
			if err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				Applicability *assessment.Report `json:"applicability"`
			}
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.Applicability == nil || !reflect.DeepEqual(*decoded.Applicability, want) {
				t.Errorf("serialized feed lost applicability: %s", encoded)
			}
		})
	}
}
