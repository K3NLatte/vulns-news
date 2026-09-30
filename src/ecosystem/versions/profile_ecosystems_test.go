package versions_test

import (
	"testing"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/versions"
)

func TestPubAndCocoaPodsPins(t *testing.T) {
	for _, eco := range []string{"Pub", "CocoaPods"} {
		t.Run(eco, func(t *testing.T) {
			if got, ok := versions.OSVEcosystem(eco); !ok || got != eco {
				t.Fatalf("mapping = %q, %v", got, ok)
			}
			valid := []string{"1.2.3", "0.0.0", "1.2.3-beta.1", "1.2.3+build.01"}
			invalid := []string{"", "v1.2.3", "01.2.3", "1.2.3-01", "1.2.3-", "1.2.3+", "1..2", "1.2.", "^1.2.3", "~> 1.2", ">=1.2.3", "1.2.x", "latest", "git+https://example.org/pkg", "file:../pkg", "1.2.3\n"}
			numeric := []string{"1", "1.0", "1.2.3.4", "1.2.3.4.5"}
			if eco == "CocoaPods" {
				valid = append(valid, numeric...)
			} else {
				invalid = append(invalid, numeric...)
			}
			for _, version := range valid {
				if !versions.IsPinned(eco, version) {
					t.Errorf("rejected pin %q", version)
				}
				for _, tc := range []struct {
					constraint domain.VersionConstraint
					want       domain.VersionStatus
				}{
					{domain.VersionConstraint{Scheme: "osv", Expression: version}, domain.VersionAffected},
					{domain.VersionConstraint{Scheme: "osv", Expression: version + "+other"}, domain.VersionUnknown},
					{domain.VersionConstraint{Scheme: "osv", Expression: version, VersionEndExcluding: "9.0.0"}, domain.VersionUnknown},
					{domain.VersionConstraint{Scheme: "semver", Expression: version}, domain.VersionUnknown},
				} {
					got, err := versions.New().Evaluate(eco, version, []domain.VersionConstraint{tc.constraint})
					if err != nil || got != tc.want {
						t.Errorf("%q / %+v: %s, %v; want %s", version, tc.constraint, got, err, tc.want)
					}
				}
			}
			for _, version := range invalid {
				if versions.IsPinned(eco, version) {
					t.Errorf("accepted unresolved/malformed pin %q", version)
				}
				got, err := versions.New().Evaluate(eco, version, []domain.VersionConstraint{{Scheme: "osv", Expression: version}})
				if err != nil || got != domain.VersionUnknown {
					t.Errorf("invalid %q: %s, %v", version, got, err)
				}
			}
		})
	}
}

func TestInventoryOnlyEcosystemsHaveNoOSVMapping(t *testing.T) {
	for _, eco := range []string{"JSR", "CRAN", "Conan", "Julia", "vcpkg"} {
		if got, ok := versions.OSVEcosystem(eco); ok || got != "" {
			t.Errorf("invented mapping %s -> %q, %v", eco, got, ok)
		}
		if versions.IsPinned(eco, "1.2.3") {
			t.Errorf("accepted OSV pin for %s", eco)
		}
		got, err := versions.New().Evaluate(eco, "1.2.3", []domain.VersionConstraint{{Scheme: "osv", Expression: "1.2.3"}})
		if err != nil || got != domain.VersionUnknown {
			t.Errorf("%s: %s, %v", eco, got, err)
		}
	}
}
