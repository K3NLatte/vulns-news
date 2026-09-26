package feed

import (
	"encoding/json"
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/processor"
)

func TestBuildAdvisoryIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id  string
		cve bool
	}{
		{id: "CVE-2026-1234", cve: true},
		{id: "CVE-2026-1234567", cve: true},
		{id: "GHSA-2345-6789-cfgh"},
		{id: "RUSTSEC-2026-0001"},
		{id: "CVE-2026-123"},
		{id: "CVE-26-1234"},
		{id: "CVE-2026-1234-extra"},
		{id: "not-CVE-2026-1234"},
		{id: "cve-2026-1234"},
		{id: "CVE-2026-1234\n"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			for _, analyzed := range []bool{false, true} {
				status := StatusScreened
				if analyzed {
					status = StatusAnalyzed
				}
				t.Run(string(status), func(t *testing.T) {
					revision := time.Date(2026, 9, 25, 1, 2, 3, 0, time.UTC)
					published := revision.Add(-24 * time.Hour)
					input := processor.Input{
						Vulnerability: domain.NormalizedVulnerability{ID: tt.id, ModifiedAt: revision, PublishedAt: published},
						Repository: domain.RepositoryProfile{
							Repository: domain.RepositoryIdentity{ID: "repo-001", CommitSHA: "abc123"},
						},
						Candidate: domain.MatchCandidate{
							RepositoryID: "repo-001", RepositoryCommit: "abc123",
							VulnerabilityID: tt.id, VulnerabilityRev: revision,
						},
					}
					screening := processor.ScreeningOutput{Result: processor.ScreeningResult{
						Relevance: processor.RelevancePossiblyRelated, Reason: "Advisory applicability needs review.",
					}}
					var analysis *processor.AnalysisOutput
					if analyzed {
						screening.Result.Relevance = processor.RelevanceRelated
						analysis = &processor.AnalysisOutput{Analysis: processor.DeepAnalysis{
							Summary:          processor.SupportedClaim{Text: "The dependency is listed by the advisory."},
							RepositoryImpact: processor.SupportedClaim{Text: "Exploitability remains unverified."},
						}}
					}
					item, err := Build(input, screening, analysis)
					if err != nil {
						t.Fatal(err)
					}
					if item.VulnerabilityID != tt.id || !item.VulnerabilityRevision.Equal(revision) {
						t.Errorf("generic identity = %q/%v", item.VulnerabilityID, item.VulnerabilityRevision)
					}
					if item.Status != status || item.RepositoryID != "repo-001" || item.RepositoryCommit != "abc123" || !item.PublishedAt.Equal(published) {
						t.Errorf("existing feed facts changed: %+v", item)
					}
					encoded, err := json.Marshal(item)
					if err != nil {
						t.Fatal(err)
					}
					var fields map[string]json.RawMessage
					if err := json.Unmarshal(encoded, &fields); err != nil {
						t.Fatal(err)
					}
					assertJSON := func(key string, want any) {
						t.Helper()
						expected, err := json.Marshal(want)
						if err != nil {
							t.Fatal(err)
						}
						if string(fields[key]) != string(expected) {
							t.Errorf("JSON %s = %s, want %s", key, fields[key], expected)
						}
					}
					assertJSON("vulnerability_id", tt.id)
					assertJSON("vulnerability_revision", revision)
					assertJSON("published_at", published)
					if tt.cve {
						if item.CVEID != tt.id || !item.CVERevision.Equal(revision) {
							t.Errorf("legacy CVE identity changed: %q/%v", item.CVEID, item.CVERevision)
						}
						assertJSON("cve_id", tt.id)
						assertJSON("cve_revision", revision)
					} else {
						if item.CVEID != "" || !item.CVERevision.IsZero() {
							t.Errorf("non-CVE was assigned CVE identity: %q/%v", item.CVEID, item.CVERevision)
						}
						if _, exists := fields["cve_id"]; exists {
							t.Errorf("non-CVE JSON contains cve_id: %s", encoded)
						}
						assertJSON("cve_revision", time.Time{})
					}
				})
			}
		})
	}
}
