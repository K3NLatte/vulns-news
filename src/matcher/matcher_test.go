package matcher

import (
	"encoding/json"
	"reflect"
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

func TestMatchWithTrace(t *testing.T) {
	packageTarget := sampleVulnerability().Affected[0]
	productTarget := domain.AffectedTarget{ID: "product-001", Kind: domain.AffectedProduct, Vendor: "example", Product: "server", CPEs: []string{"cpe:2.3:a:example:server:*"}, Constraints: packageTarget.Constraints}
	product := domain.ProductCandidate{ID: "product-item", Vendor: "example", Name: "server", Version: "1.3.0", CPEs: productTarget.CPEs}
	packageMatch := domain.TargetMatch{RepositoryItemID: "component-001", AffectedTargetID: packageTarget.ID, Reason: domain.MatchPURLExact, VersionStatus: domain.VersionAffected, InstalledVersion: "1.3.0"}
	productMatch := domain.TargetMatch{RepositoryItemID: product.ID, AffectedTargetID: productTarget.ID, Reason: domain.MatchCPEExact, VersionStatus: domain.VersionAffected, InstalledVersion: product.Version}

	tests := []struct {
		name     string
		profile  domain.RepositoryProfile
		affected []domain.AffectedTarget
		status   domain.VersionStatus
		decision string
		targets  []TargetDecision
		matches  []domain.TargetMatch
	}{
		{name: "no affected targets", profile: sampleProfile(), decision: "no_affected_targets", targets: []TargetDecision{}},
		{name: "identity mismatch", profile: sampleProfile(), affected: []domain.AffectedTarget{{ID: "other", Kind: domain.AffectedPackage, PURL: "pkg:npm/other"}}, decision: "no_identity_match", targets: []TargetDecision{{Target: domain.AffectedTarget{ID: "other", Kind: domain.AffectedPackage, PURL: "pkg:npm/other"}, RepositoryItemsCompared: 1, Matches: []domain.TargetMatch{}, Decision: "no_identity_match"}}},
		{name: "unaffected version", profile: sampleProfile(), affected: []domain.AffectedTarget{packageTarget}, status: domain.VersionNotAffected, decision: "version_excluded", targets: []TargetDecision{{Target: packageTarget, RepositoryItemsCompared: 1, IdentityMatches: 1, VersionExcluded: 1, Matches: []domain.TargetMatch{}, Decision: "version_excluded"}}},
		{name: "matched package", profile: sampleProfile(), affected: []domain.AffectedTarget{packageTarget}, status: domain.VersionAffected, decision: "matched", targets: []TargetDecision{{Target: packageTarget, RepositoryItemsCompared: 1, IdentityMatches: 1, Matches: []domain.TargetMatch{packageMatch}, Decision: "matched"}}, matches: []domain.TargetMatch{packageMatch}},
		{name: "matched product", profile: domain.RepositoryProfile{Repository: sampleProfile().Repository, Components: sampleProfile().Components, Products: []domain.ProductCandidate{product}}, affected: []domain.AffectedTarget{productTarget}, status: domain.VersionAffected, decision: "matched", targets: []TargetDecision{{Target: productTarget, RepositoryItemsCompared: 1, IdentityMatches: 1, Matches: []domain.TargetMatch{productMatch}, Decision: "matched"}}, matches: []domain.TargetMatch{productMatch}},
		{name: "mixed targets", profile: sampleProfile(), affected: []domain.AffectedTarget{{ID: "missing", Kind: domain.AffectedProduct}, packageTarget}, status: domain.VersionNotAffected, decision: "version_excluded", targets: []TargetDecision{{Target: domain.AffectedTarget{ID: "missing", Kind: domain.AffectedProduct}, Matches: []domain.TargetMatch{}, Decision: "no_identity_match"}, {Target: packageTarget, RepositoryItemsCompared: 1, IdentityMatches: 1, VersionExcluded: 1, Matches: []domain.TargetMatch{}, Decision: "version_excluded"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulnerability := sampleVulnerability()
			vulnerability.Affected = tt.affected
			matcher := New(fixedVersionEvaluator{status: tt.status})
			candidate, trace, matched, err := matcher.MatchWithTrace(tt.profile, vulnerability)
			if err != nil {
				t.Fatalf("MatchWithTrace: %v", err)
			}
			if trace.Decision != tt.decision || !reflect.DeepEqual(trace.Targets, tt.targets) {
				t.Errorf("trace = %+v, want decision %q and targets %+v", trace, tt.decision, tt.targets)
			}
			if matched != (len(tt.matches) > 0) || !reflect.DeepEqual(candidate.Matches, tt.matches) {
				t.Errorf("matched = %t, matches = %+v; want %+v", matched, candidate.Matches, tt.matches)
			}
			plain, plainMatched, plainErr := matcher.Match(tt.profile, vulnerability)
			if plainErr != nil || plainMatched != matched || !reflect.DeepEqual(plain, candidate) {
				t.Errorf("Match differs: candidate = %+v, matched = %t, err = %v", plain, plainMatched, plainErr)
			}
			encoded, err := json.Marshal(trace)
			if err != nil {
				t.Fatalf("marshal trace: %v", err)
			}
			var decoded struct {
				Targets json.RawMessage `json:"targets"`
			}
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("unmarshal trace: %v", err)
			}
			if string(decoded.Targets) == "null" {
				t.Errorf("targets array is null: %s", encoded)
			}
			for _, target := range trace.Targets {
				if target.Matches == nil {
					t.Errorf("matches array is null: %s", encoded)
				}
			}
		})
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
