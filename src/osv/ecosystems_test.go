package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/versions"
	"vulns-news/src/matcher"
)

var ecosystemCases = []struct{ eco, canonical, name, version string }{
	{"Maven", "Maven", "org.example:artifact", "1.2.3.Final"},
	{"maven", "Maven", "org.example:artifact", "1.2.3.Final"},
	{"packagist", "Packagist", "vendor/package", "1.2.3"},
	{"nuget", "NuGet", "Example.Package", "1.2.3.4"},
	{"gem", "RubyGems", "example", "1.2.3.pre.1"},
	{"Packagist", "Packagist", "vendor/package", "1.2.3"},
	{"NuGet", "NuGet", "Example.Package", "1.2.3.4"},
	{"RubyGems", "RubyGems", "example", "1.2.3.pre.1"},
	{"crates.io", "crates.io", "example", "1.2.3"},
	{"PyPI", "PyPI", "example", "1.2.3rc1"},
	{"pypi", "PyPI", "example", "1.2.3"},
	{"npm", "npm", "@example/package", "1.2.3+build"},
	{"Go", "Go", "example.org/module", "v1.2.3"},
	{"go", "Go", "example.org/module", "v1.2.3"},
}

func TestEcosystemQueries(t *testing.T) {
	for _, tc := range ecosystemCases {
		t.Run(tc.eco, func(t *testing.T) {
			calls := 0
			c := client(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				var q query
				if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
					t.Error(err)
				}
				if q != (query{Package: packageKey{Ecosystem: tc.canonical, Name: tc.name}, Version: tc.version}) {
					t.Errorf("query: %+v", q)
				}
				io.WriteString(w, `{"vulns":[{"id":"CVE-2025-12345"}]}`)
			})
			p := domain.RepositoryProfile{Components: []domain.Component{{Ecosystem: tc.eco, Name: tc.name, Version: tc.version}}}
			got, err := c.Enrich(context.Background(), p, vulnerability())
			if err != nil || calls != 1 || len(got.Affected) != 1 {
				t.Fatalf("%+v, %v, calls=%d", got, err, calls)
			}
			target := got.Affected[0]
			if target.Ecosystem != tc.eco || target.PackageName != tc.name || len(target.Constraints) != 1 || target.Constraints[0] != (domain.VersionConstraint{Scheme: "osv", Expression: tc.version}) {
				t.Fatalf("target: %+v", target)
			}
		})
	}
}

func TestRejectUnresolvedAcrossEcosystems(t *testing.T) {
	c := client(t, func(http.ResponseWriter, *http.Request) { t.Error("unexpected query") })
	for _, tc := range ecosystemCases {
		for _, version := range []string{"", "^1.2.3", "~1.2.3", "~>1.2.3", ">=1.2.3", "[1.2.3,2.0.0)", "*", "1.2.x", "latest", "dev-main", "git+https://example.org/repo", "file:../pkg", "../pkg", "1..2", "1.2.3\n"} {
			p := domain.RepositoryProfile{Components: []domain.Component{{Ecosystem: tc.eco, Name: tc.name, Version: version}}}
			got, err := c.Enrich(context.Background(), p, vulnerability())
			if err != nil || len(got.Affected) != 0 {
				t.Errorf("%s/%s: %+v, %v", tc.eco, version, got, err)
			}
		}
	}
	for _, component := range []domain.Component{
		{Ecosystem: "Swift", Name: "example", Version: "1.2.3"},
		{Ecosystem: "Maven", Name: "artifact", Version: "1.2.3"},
		{Ecosystem: "Maven", Name: "group:", Version: "1.2.3"},
		{Ecosystem: "Maven", Name: "group:artifact:extra", Version: "1.2.3"},
		{Ecosystem: "Packagist", Name: "package", Version: "1.2.3"},
		{Ecosystem: "Packagist", Name: "vendor/", Version: "1.2.3"},
		{Ecosystem: "Packagist", Name: "vendor/package/extra", Version: "1.2.3"},
	} {
		if _, ok := componentQuery(component); ok {
			t.Errorf("accepted %+v", component)
		}
	}
}

func TestMultipleInstalledVersionsDoNotSharePositiveEvidence(t *testing.T) {
	for _, tc := range ecosystemCases {
		t.Run(tc.eco, func(t *testing.T) {
			other := "2.0.0"
			if tc.canonical == "Go" {
				other = "v2.0.0"
			}
			calls := 0
			c := client(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				var q query
				if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
					t.Error(err)
				}
				id := "CVE-2025-12345"
				if q.Version == other {
					id = "CVE-2025-99999"
				}
				fmt.Fprintf(w, `{"vulns":[{"id":%q}]}`, id)
			})
			p := domain.RepositoryProfile{}
			p.Repository.ID, p.Repository.CommitSHA = "repo", "commit"
			p.Components = []domain.Component{
				{ID: "first", Ecosystem: tc.eco, Name: tc.name, Version: tc.version},
				{ID: "second", Ecosystem: tc.eco, Name: tc.name, Version: other},
				{ID: "unresolved", Ecosystem: tc.eco, Name: tc.name},
			}
			ids := make(map[string]bool)
			for i, id := range []string{"CVE-2025-12345", "CVE-2025-99999"} {
				got, err := c.Enrich(context.Background(), p, domain.NormalizedVulnerability{ID: id})
				if err != nil || len(got.Affected) != 1 {
					t.Fatalf("%+v, %v", got, err)
				}
				if ids[got.Affected[0].ID] {
					t.Fatal("target ID collision")
				}
				ids[got.Affected[0].ID] = true
				candidate, ok, err := matcher.New(versions.New()).Match(p, got)
				if err != nil || !ok || len(candidate.Matches) != 3 {
					t.Fatalf("%+v, %v", candidate, err)
				}
				for _, match := range candidate.Matches {
					want := domain.VersionUnknown
					if match.RepositoryItemID == p.Components[i].ID {
						want = domain.VersionAffected
					}
					if match.VersionStatus != want {
						t.Errorf("cross-attribution for %s: %+v", id, match)
					}
				}
			}
			if calls != 2 {
				t.Fatalf("queries=%d, want two version-specific cached queries", calls)
			}
		})
	}
}
