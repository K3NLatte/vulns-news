package versions_test

import (
	"testing"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/versions"
)

func TestProfilerAliases(t *testing.T) {
	for _, tc := range []struct{ alias, canonical, pinned, malformed string }{
		{"maven", "Maven", "1.2.3.Final", "1..2"},
		{"packagist", "Packagist", "v1.2.3-RC1", "dev-main"},
		{"nuget", "NuGet", "1.2.3.4", "1.2.3.4.5"},
		{"gem", "RubyGems", "1.2.3.pre.1", "1.2."},
	} {
		t.Run(tc.alias, func(t *testing.T) {
			if got, ok := versions.OSVEcosystem(tc.alias); !ok || got != tc.canonical {
				t.Fatalf("mapping = %q, %v", got, ok)
			}
			for _, version := range []string{tc.pinned, tc.malformed, "", "^1.2.3", "~>1.2.3", "1.x", "git+https://example.org/repo", "../path"} {
				wantPinned := version == tc.pinned
				if versions.IsPinned(tc.alias, version) != wantPinned {
					t.Errorf("pinned %q: want %v", version, wantPinned)
				}
				want := domain.VersionUnknown
				if wantPinned {
					want = domain.VersionAffected
				}
				status, err := versions.New().Evaluate(tc.alias, version, []domain.VersionConstraint{{Scheme: "osv", Expression: version}})
				if err != nil || status != want {
					t.Errorf("evaluate %q: %s, %v", version, status, err)
				}
			}
		})
	}
}
