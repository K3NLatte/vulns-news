package matcher

import (
	"testing"

	"vulns-news/src/domain"
)

type fixedVersionEvaluator struct {
	status domain.VersionStatus
}

func (f fixedVersionEvaluator) Evaluate(string, string, []domain.VersionConstraint) (domain.VersionStatus, error) {
	return f.status, nil
}

func TestMatchCreatesCandidateForExactPackage(t *testing.T) {
	profile := sampleProfile()
	vulnerability := sampleVulnerability()

	candidate, matched, err := New(fixedVersionEvaluator{status: domain.VersionAffected}).Match(profile, vulnerability)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if !matched {
		t.Fatal("Match returned no candidate")
	}
	if len(candidate.Matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(candidate.Matches))
	}
	if candidate.Matches[0].Reason != domain.MatchPURLExact {
		t.Errorf("reason = %q, want %q", candidate.Matches[0].Reason, domain.MatchPURLExact)
	}
	if candidate.Matches[0].VersionStatus != domain.VersionAffected {
		t.Errorf("version status = %q", candidate.Matches[0].VersionStatus)
	}
}

func TestMatchKeepsExactIdentityWithUnknownVersion(t *testing.T) {
	candidate, matched, err := New(nil).Match(sampleProfile(), sampleVulnerability())
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if !matched || len(candidate.Matches) != 1 {
		t.Fatalf("matched = %t, matches = %d", matched, len(candidate.Matches))
	}
	if candidate.Matches[0].VersionStatus != domain.VersionUnknown {
		t.Errorf("version status = %q, want %q", candidate.Matches[0].VersionStatus, domain.VersionUnknown)
	}
}

func TestMatchExcludesKnownUnaffectedVersion(t *testing.T) {
	_, matched, err := New(fixedVersionEvaluator{status: domain.VersionNotAffected}).Match(sampleProfile(), sampleVulnerability())
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if matched {
		t.Fatal("Match returned a candidate for an unaffected version")
	}
}

func TestMatchDoesNotUseFuzzyPackageNames(t *testing.T) {
	vulnerability := sampleVulnerability()
	vulnerability.Affected[0].PURL = ""
	vulnerability.Affected[0].PackageName = "archive-js"

	_, matched, err := New(nil).Match(sampleProfile(), vulnerability)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if matched {
		t.Fatal("Match used fuzzy package-name similarity")
	}
}

func sampleProfile() domain.RepositoryProfile {
	return domain.RepositoryProfile{
		Repository: domain.RepositoryIdentity{
			ID:           "repo-001",
			CanonicalURL: "https://github.com/example/payment-api",
			Ref:          "main",
			CommitSHA:    "abc123",
		},
		Components: []domain.Component{
			{
				ID:         "component-001",
				PURL:       "pkg:npm/%40example/archive",
				Ecosystem:  "npm",
				Name:       "@example/archive",
				Version:    "1.3.0",
				Direct:     true,
				SourcePath: "pnpm-lock.yaml",
			},
		},
	}
}

func sampleVulnerability() domain.NormalizedVulnerability {
	return domain.NormalizedVulnerability{
		ID:          "CVE-2026-1234",
		Description: "Archive extraction can write outside the destination directory.",
		Affected: []domain.AffectedTarget{
			{
				ID:          "target-001",
				Kind:        domain.AffectedPackage,
				PURL:        "pkg:npm/%40example/archive",
				Ecosystem:   "npm",
				PackageName: "@example/archive",
				Constraints: []domain.VersionConstraint{{Scheme: "semver", VersionEndExcluding: "1.4.0"}},
			},
		},
	}
}
