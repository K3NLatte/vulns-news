package osv

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/extralock"
	"vulns-news/src/ecosystem/nativeprofile"
	"vulns-news/src/ecosystem/versions"
)

func TestLockProfilesPreserveOSVIdentity(t *testing.T) {
	root := t.TempDir()
	for name, data := range map[string]string{
		"pubspec.lock": `packages:
  http:
    dependency: direct main
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "1.2.3+build"
`,
		"Podfile.lock": `PODS:
  - Public/Core (1.0)
  - Other (1.2.3.4)
SPEC REPOS:
  trunk:
    - Public
    - Other
`,
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	extra, err := extralock.Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	native, err := nativeprofile.Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	components := append(extra.Components, native.Components...)
	expected := map[string]struct{ ecosystem, version, purl string }{
		"http":        {"Pub", "1.2.3+build", "pkg:pub/http"},
		"Public/Core": {"CocoaPods", "1.0", "pkg:cocoapods/Public/Core"},
		"Other":       {"CocoaPods", "1.2.3.4", "pkg:cocoapods/Other"},
	}
	if len(components) != len(expected) {
		t.Fatalf("components: %+v", components)
	}
	calls := make(map[string]int)
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		var q query
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Error(err)
		}
		want, ok := expected[q.Package.Name]
		if !ok || q.Package.Ecosystem != want.ecosystem || q.Version != want.version {
			t.Errorf("query: %+v", q)
		}
		calls[q.Package.Name]++
		io.WriteString(w, `{"vulns":[{"id":"PROFILE-ADVISORY","aliases":["CVE-2025-12345"]}]}`)
	})
	got, err := c.Enrich(context.Background(), domain.RepositoryProfile{Components: components}, vulnerability())
	if err != nil || len(got.Affected) != len(expected) {
		t.Fatalf("enrich: %+v, %v", got, err)
	}
	seen := make(map[string]bool)
	for _, target := range got.Affected {
		want, ok := expected[target.PackageName]
		if !ok || seen[target.PackageName] || calls[target.PackageName] != 1 || target.Kind != domain.AffectedPackage || target.Ecosystem != want.ecosystem || target.PURL != want.purl || len(target.Constraints) != 1 || target.Constraints[0] != (domain.VersionConstraint{Scheme: "osv", Expression: want.version}) {
			t.Fatalf("changed identity or evidence: %+v; calls=%v", target, calls)
		}
		seen[target.PackageName] = true
		for _, installed := range []string{want.version, "9.0.0", ""} {
			wantStatus := domain.VersionUnknown
			if installed == want.version {
				wantStatus = domain.VersionAffected
			}
			status, err := versions.New().Evaluate(target.Ecosystem, installed, target.Constraints)
			if err != nil || status != wantStatus {
				t.Errorf("%s/%q: %s, %v", target.PackageName, installed, status, err)
			}
		}
	}
}

func TestInventoryOnlyProfilesNeverQueryOSV(t *testing.T) {
	c := client(t, func(http.ResponseWriter, *http.Request) { t.Error("inventory-only package disclosed to OSV") })
	var components []domain.Component
	for _, eco := range []string{"JSR", "CRAN", "Conan", "Julia", "vcpkg"} {
		components = append(components, domain.Component{Ecosystem: eco, Name: "example", Version: "1.2.3"})
	}
	got, err := c.Enrich(context.Background(), domain.RepositoryProfile{Components: components}, vulnerability())
	if err != nil || len(got.Affected) != 0 || len(got.References) != 0 {
		t.Fatalf("invented enrichment: %+v, %v", got, err)
	}
}
