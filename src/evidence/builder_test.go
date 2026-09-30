package evidence

import (
	"strings"
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/processor"
)

func TestBuildCreatesNVDAndRepositoryEvidence(t *testing.T) {
	modifiedAt := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	cvss := 8.1
	profile := domain.RepositoryProfile{
		Repository: domain.RepositoryIdentity{ID: "repo-001", CommitSHA: "abc123"},
		Components: []domain.Component{{
			ID: "component-001", Ecosystem: "npm", Name: "@example/archive",
			Version: "1.3.0", Direct: true, Scope: "runtime", SourcePath: "package-lock.json",
		}},
	}
	vulnerability := domain.NormalizedVulnerability{
		ID: "CVE-2026-1234", ModifiedAt: modifiedAt,
		Description: "Archive paths are not sufficiently validated.", Severity: "HIGH", CVSS: &cvss,
		Affected:   []domain.AffectedTarget{{ID: "target-001", Kind: domain.AffectedPackage}},
		References: []domain.Reference{{URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"}},
	}
	candidate := domain.MatchCandidate{
		RepositoryID: "repo-001", RepositoryCommit: "abc123",
		VulnerabilityID: "CVE-2026-1234", VulnerabilityRev: modifiedAt,
		Matches: []domain.TargetMatch{{
			RepositoryItemID: "component-001", AffectedTargetID: "target-001",
			Reason: domain.MatchPURLExact, VersionStatus: domain.VersionAffected, InstalledVersion: "1.3.0",
		}},
	}

	items, err := Build(profile, vulnerability, candidate)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("evidence count = %d, want 2", len(items))
	}
	if items[0].Kind != processor.EvidenceNVD || items[0].ID != "EVD-NVD-001" {
		t.Errorf("NVD evidence = %+v", items[0])
	}
	if items[1].Kind != processor.EvidenceRepositoryDependency || items[1].Source != "package-lock.json" {
		t.Errorf("repository evidence = %+v", items[1])
	}
	if !strings.Contains(items[1].Content, "version status=affected") {
		t.Errorf("repository content = %q", items[1].Content)
	}
}

func TestBuildRejectsMismatchedCandidate(t *testing.T) {
	_, err := Build(
		domain.RepositoryProfile{Repository: domain.RepositoryIdentity{ID: "repo-001", CommitSHA: "abc123"}},
		domain.NormalizedVulnerability{ID: "CVE-2026-1234", Description: "description"},
		domain.MatchCandidate{RepositoryID: "other"},
	)
	if err == nil {
		t.Fatal("Build accepted a mismatched candidate")
	}
}
