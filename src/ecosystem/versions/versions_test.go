package versions_test

import (
	"strings"
	"testing"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/versions"
	"vulns-news/src/matcher"
)

var _ matcher.VersionEvaluator = versions.Versions{}

func TestPinnedVersions(t *testing.T) {
	for _, tc := range []struct {
		eco            string
		valid, invalid []string
	}{
		{"npm", []string{"1.2.3", "v1.2.3", "1.2.3-beta.1+build.2"}, []string{"1.2", "01.2.3", "1.2.3-01", "1.2.3+", "1.2.3-"}},
		{"Go", []string{"v1.2.3", "v0.0.0-20240101120000-abcdef123456", "v2.0.0+incompatible"}, []string{"1.2.3", "v1.2", "v1.2.3-01"}},
		{"crates.io", []string{"1.2.3", "1.2.3-alpha.1+build"}, []string{"v1.2.3", "1.2", "1.2.3-01"}},
		{"PyPI", []string{"1", "1.2.3rc1", "1!2.0.post1.dev2+linux.1", "1.0-1", "1.0rc"}, []string{"1.2.3foo", "1.2..3", "1.0+", "1.0rc1rc2"}},
		{"Maven", []string{"1", "1.2.3", "1.0.Final", "2.0-rc-1", "1.0-SNAPSHOT"}, []string{"1..2", "1.2.", "1.2+", "[1.0]", "[1.0,2.0)", "RELEASE", "LATEST"}},
		{"Packagist", []string{"1.2.3", "v1.2.3", "1.2.3.4", "1.2.3-RC1"}, []string{"1.2", "dev-main", "1.2.x-dev", "1.2.3 as 2.0.0", "1.2.3-"}},
		{"NuGet", []string{"1.2", "1.2.3.4", "1.2.3-beta.1+build"}, []string{"1.2.3.4.5", "[1.2.3]", "(1.0,2.0]", "1.2.3-", "1.2.3+"}},
		{"RubyGems", []string{"1", "1.2.3", "1.2.3.pre.1", "1.2.3-rc.1"}, []string{"v1.2.3", "1..2", "1.2.", "1.2.3-", "1.2.3+build"}},
	} {
		t.Run(tc.eco, func(t *testing.T) {
			for _, v := range tc.valid {
				if !versions.IsPinned(tc.eco, v) {
					t.Errorf("rejected %q", v)
				}
			}
			invalid := append(tc.invalid, "", "^1.2.3", "~1.2.3", "~>1.2.3", ">=1.2.3", "=1.2.3", "*", "1.x", "1.2.x", "latest", "git+https://example.org/repo", "https://example.org/repo", "file:../pkg", "../pkg", "/tmp/pkg", "workspace:1.2.3", "1.2.3 || 2.0.0", " 1.2.3", "1.2.3\n", "1.2.3\x00", strings.Repeat("1", 257))
			for _, v := range invalid {
				if versions.IsPinned(tc.eco, v) {
					t.Errorf("accepted %q", v)
				}
				status, err := versions.New().Evaluate(tc.eco, v, []domain.VersionConstraint{{Scheme: "osv", Expression: v}})
				if err != nil || status != domain.VersionUnknown {
					t.Errorf("malformed %q: %s, %v", v, status, err)
				}
			}
		})
	}
}

func TestExactOSVEvidence(t *testing.T) {
	for _, eco := range []string{"npm", "Go", "go", "PyPI", "pypi", "Maven", "maven", "Packagist", "packagist", "NuGet", "nuget", "RubyGems", "gem", "crates.io"} {
		t.Run(eco, func(t *testing.T) {
			installed := "1.2.3"
			if eco == "Go" || eco == "go" {
				installed = "v1.2.3"
			}
			exact := domain.VersionConstraint{Scheme: "osv", Expression: installed}
			for _, tc := range []struct {
				name        string
				constraints []domain.VersionConstraint
				want        domain.VersionStatus
			}{
				{"exact", []domain.VersionConstraint{exact}, domain.VersionAffected},
				{"none", nil, domain.VersionUnknown},
				{"empty", []domain.VersionConstraint{{Scheme: "osv"}}, domain.VersionUnknown},
				{"mismatch", []domain.VersionConstraint{{Scheme: "osv", Expression: "9.9.9"}}, domain.VersionUnknown},
				{"range expression", []domain.VersionConstraint{{Scheme: "osv", Expression: ">=" + installed}}, domain.VersionUnknown},
				{"unknown scheme", []domain.VersionConstraint{{Scheme: "other", Expression: installed}}, domain.VersionUnknown},
				{"positive wins", []domain.VersionConstraint{{Scheme: "osv", Expression: "9.9.9"}, exact}, domain.VersionAffected},
			} {
				status, err := versions.New().Evaluate(eco, installed, tc.constraints)
				if err != nil || status != tc.want {
					t.Errorf("%s: %s, %v", tc.name, status, err)
				}
			}
			for i := 0; i < 4; i++ {
				bounded := exact
				bounds := []*string{&bounded.VersionStartIncluding, &bounded.VersionStartExcluding, &bounded.VersionEndIncluding, &bounded.VersionEndExcluding}
				*bounds[i] = installed
				status, _ := versions.New().Evaluate(eco, installed, []domain.VersionConstraint{bounded})
				if status != domain.VersionUnknown {
					t.Errorf("bound %d: %s", i, status)
				}
			}
		})
	}
	for _, eco := range []string{"Swift", "unsupported", "", "NPM"} {
		if _, ok := versions.OSVEcosystem(eco); ok {
			t.Errorf("mapped %q", eco)
		}
		status, _ := versions.New().Evaluate(eco, "1.2.3", []domain.VersionConstraint{{Scheme: "osv", Expression: "1.2.3"}})
		if status != domain.VersionUnknown {
			t.Errorf("%s: %s", eco, status)
		}
	}
	// Even semver-equivalent spellings are not the same provider query.
	for _, expression := range []string{"v1.2.3", "1.2.3+build"} {
		status, _ := versions.New().Evaluate("npm", "1.2.3", []domain.VersionConstraint{{Scheme: "osv", Expression: expression}})
		if status != domain.VersionUnknown {
			t.Fatal(status)
		}
	}
}

func TestNPMDelegation(t *testing.T) {
	for _, tc := range []struct {
		constraints []domain.VersionConstraint
		want        domain.VersionStatus
	}{
		{[]domain.VersionConstraint{{Scheme: "npm", VersionStartIncluding: "1.0.0", VersionEndExcluding: "2.0.0"}}, domain.VersionAffected},
		{[]domain.VersionConstraint{{Scheme: "semver", Expression: "2.0.0"}}, domain.VersionNotAffected},
		{[]domain.VersionConstraint{{Scheme: "cpe", VersionEndExcluding: "1.0.0"}}, domain.VersionNotAffected},
		{[]domain.VersionConstraint{{Scheme: "npm", Expression: "2.0.0"}, {Scheme: "osv", Expression: "2.0.0"}}, domain.VersionUnknown},
		{[]domain.VersionConstraint{{Scheme: "npm", Expression: "2.0.0"}, {Scheme: "osv", Expression: "1.2.3"}}, domain.VersionAffected},
		{[]domain.VersionConstraint{{Scheme: "osv", Expression: "2.0.0"}, {Scheme: "npm", Expression: "1.2.3"}}, domain.VersionAffected},
	} {
		status, err := versions.New().Evaluate("npm", "1.2.3", tc.constraints)
		if err != nil || status != tc.want {
			t.Errorf("%+v: %s, %v", tc.constraints, status, err)
		}
	}
	for _, eco := range []string{"Maven", "maven", "Packagist", "packagist", "NuGet", "nuget", "RubyGems", "gem", "crates.io", "PyPI", "Go"} {
		for _, scheme := range []string{"npm", "semver", "cpe"} {
			status, _ := versions.New().Evaluate(eco, "1.2.3", []domain.VersionConstraint{{Scheme: scheme, Expression: "1.2.3"}})
			if status != domain.VersionUnknown {
				t.Errorf("%s/%s: %s", eco, scheme, status)
			}
		}
	}
}
