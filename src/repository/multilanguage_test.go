package repository

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"vulns-news/src/domain"
)

func TestMultilanguageProfileMixedLockfiles(t *testing.T) {
	fixtures := []struct {
		path, body, ecosystem, name, version, purl string
		manifest                                   bool
	}{
		{"node/package-lock.json", `{"name":"web","lockfileVersion":3,"packages":{"node_modules/express":{"version":"4.21.0"}}}`, "npm", "express", "4.21.0", "pkg:npm/express", false},
		{"go/go.mod", "module example.org/app\ngo 1.25\nrequire golang.org/x/text v0.14.0\n", "Go", "golang.org/x/text", "v0.14.0", "pkg:golang/golang.org/x/text", true},
		{"python/requirements.txt", "urllib3==2.2.1\n", "pypi", "urllib3", "2.2.1", "pkg:pypi/urllib3", true},
		{"pipenv/Pipfile.lock", `{"_meta":{"pipfile-spec":6,"sources":[{"name":"pypi","url":"https://pypi.org/simple","verify_ssl":true}]},"default":{"Requests":{"version":"==2.31.0","index":"pypi"}},"develop":{}}`, "pypi", "requests", "2.31.0", "pkg:pypi/requests", false},
		{"php/composer.lock", `{"packages":[{"name":"symfony/http-foundation","version":"v6.4.0"}],"packages-dev":[]}`, "packagist", "symfony/http-foundation", "v6.4.0", "pkg:packagist/symfony/http-foundation", false},
		{"dotnet/packages.lock.json", `{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.3, )","resolved":"13.0.3"}}}}`, "nuget", "newtonsoft.json", "13.0.3", "pkg:nuget/newtonsoft.json", false},
		{"swift/Package.resolved", `{"version":3,"pins":[{"identity":"apple.swift-log","kind":"registry","state":{"version":"1.5.4"}}]}`, "swift", "swift-log", "1.5.4", "pkg:swift/apple/swift-log", false},
		{"gradle/gradle.lockfile", "# Generated dependency lock state\norg.apache.commons:commons-lang3:3.12.0=runtimeClasspath\nempty=\n", "maven", "org.apache.commons:commons-lang3", "3.12.0", "pkg:maven/org.apache.commons/commons-lang3", false},
		{"maven/pom.xml", `<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>app</artifactId><version>1.0</version><dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.9</version></dependency></dependencies></project>`, "maven", "org.slf4j:slf4j-api", "2.0.9", "pkg:maven/org.slf4j/slf4j-api", true},
		{"ruby/Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.0)\n\nDEPENDENCIES\n  rack (~> 3.1)\n\nBUNDLED WITH\n   2.5.0\n", "gem", "rack", "3.1.0", "pkg:gem/rack", false},
		{"rust/Cargo.lock", "version = 3\n[[package]]\nname = 'serde'\nversion = '1.0.200'\nsource = 'registry+https://github.com/rust-lang/crates.io-index'\n", "crates.io", "serde", "1.0.200", "pkg:cargo/serde@1.0.200", false},
		{"poetry/poetry.lock", "[[package]]\nname = 'Django'\nversion = '4.2.0'\n[metadata]\nlock-version = '2.0'\npython-versions = '^3.11'\n", "pypi", "django", "4.2.0", "pkg:pypi/django@4.2.0", false},
		{"uv/uv.lock", "version = 1\nrequires-python = '>=3.11'\n[[package]]\nname = 'Flask'\nversion = '3.0.0'\nsource = {registry = 'https://pypi.org/simple'}\n", "pypi", "flask", "3.0.0", "pkg:pypi/flask@3.0.0", false},
		{"pnpm/pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  '@babel/core@7.24.0':\n    resolution: {integrity: sha512-example}\n", "npm", "@babel/core", "7.24.0", "pkg:npm/%40babel/core@7.24.0", false},
		{"yarn/yarn.lock", "# yarn lockfile v1\n\n\"lodash@^4.17.21\":\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n", "npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", false},
	}
	root := t.TempDir()
	for _, f := range fixtures {
		writeProfileFile(t, root, f.path, f.body)
	}
	acquired := &AcquiredRepository{Path: root, Identity: domain.RepositoryIdentity{ID: "example/polyglot", CommitSHA: "abc123"}}
	at := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	got, err := Profile(acquired, at)
	if err != nil {
		t.Fatal(err)
	}
	if got.Repository != acquired.Identity || got.ProfiledAt != at {
		t.Errorf("snapshot identity lost: %+v", got)
	}
	if len(got.Components) != len(fixtures) {
		t.Errorf("got %d components, want %d: %+v", len(got.Components), len(fixtures), got.Components)
	}
	usages := map[string]domain.EcosystemUsage{}
	for _, usage := range got.Ecosystems {
		if _, exists := usages[usage.Name]; exists {
			t.Errorf("duplicate ecosystem: %s", usage.Name)
		}
		usages[usage.Name] = usage
	}
	ids := map[string]bool{}
	byPath := map[string][]domain.Component{}
	for _, c := range got.Components {
		if c.ID == "" || ids[c.ID] {
			t.Errorf("empty or duplicate component ID: %+v", c)
		}
		ids[c.ID] = true
		byPath[c.SourcePath] = append(byPath[c.SourcePath], c)
	}
	expectedEcosystems := map[string]bool{}
	for _, f := range fixtures {
		t.Run(f.path, func(t *testing.T) {
			components := byPath[f.path]
			if len(components) != 1 {
				t.Fatalf("components = %+v, want one", components)
			}
			c := components[0]
			if c.Ecosystem != f.ecosystem || c.Name != f.name || c.Version != f.version || c.PURL != f.purl {
				t.Errorf("identity = %+v; want %s / %s / %s / %s", c, f.ecosystem, f.name, f.version, f.purl)
			}
			paths := usages[f.ecosystem].Lockfiles
			if f.manifest {
				paths = usages[f.ecosystem].Manifests
			}
			found := false
			for _, path := range paths {
				if path == f.path {
					found = true
				}
			}
			if !found {
				t.Errorf("missing provenance %s in %+v", f.path, usages[f.ecosystem])
			}
		})
		expectedEcosystems[f.ecosystem] = true
	}
	if len(usages) != len(expectedEcosystems) {
		t.Errorf("ecosystems = %+v", got.Ecosystems)
	}
	for _, warning := range got.Warnings {
		lower := strings.ToLower(warning)
		if (strings.Contains(lower, "poetry.lock") || strings.Contains(lower, "uv.lock")) && strings.Contains(lower, "unsupported") {
			t.Errorf("stale unsupported warning: %s", warning)
		}
	}
	if len(got.Products) != 3 {
		t.Errorf("npm product candidates = %+v, want three", got.Products)
	}
	for _, product := range got.Products {
		if product.Ecosystem != "npm" {
			t.Errorf("invented non-npm CPE alias: %+v", product)
		}
	}
	again, err := Profile(acquired, at)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, again) {
		t.Error("mixed profile is not deterministic")
	}
}
