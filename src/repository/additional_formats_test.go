package repository

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"vulns-news/src/domain"
)

func TestAdditionalFormatsProfile(t *testing.T) {
	// Reduced fixtures from the extralock, manifestextra, and nativeprofile tests.
	fixtures := []struct {
		path, body, ecosystem, name, version, purl string
		manifest                                   bool
	}{
		{"dart/pubspec.lock", `packages:
  collection:
    dependency: "direct main"
    description: {name: collection, url: "https://pub.dev/"}
    source: hosted
    version: "1.18.0"
`, "Pub", "collection", "1.18.0", "pkg:pub/collection", false},
		{"deno/deno.lock", `{"version":"4","npm":{"@scope/tool@2.1.0":{"integrity":"sha512-abcdef=="}}}`, "npm", "@scope/tool", "2.1.0", "pkg:npm/%40scope/tool", false},
		{"r/renv.lock", `{"R":{"Version":"4.3.2","Repositories":[{"Name":"CRAN","URL":"https://cloud.r-project.org"}]},"Packages":{"MASS":{"Package":"MASS","Version":"7.3-60","Source":"Repository","Repository":"CRAN"}}}`, "CRAN", "MASS", "7.3-60", "pkg:cran/MASS", false},
		{"native/conan.lock", `{"version":"0.5","requires":["zlib/1.3.1#abcdef%1710000000.1","zlib/1.3.1#abcdef%1710000000.1"]}`, "Conan", "zlib", "1.3.1", "pkg:conan/zlib", false},
		{"ios/Podfile.lock", `PODS:
  - Public/Core (1.2.3)
SPEC REPOS:
  trunk:
    - Public
`, "CocoaPods", "Public/Core", "1.2.3", "pkg:cocoapods/Public/Core", false},
		{"julia/Manifest.toml", `julia_version = "1.10.0"
manifest_format = "2.0"
[[deps.Example]]
uuid = "7876AF07-990D-54B4-AB0E-23690620F79A"
version = "0.5.4"
git-tree-sha1 = "abcdef"
`, "Julia", "Example", "0.5.4", "pkg:generic/julia/Example?uuid=7876af07-990d-54b4-ab0e-23690620f79a", false},
		{"rust/Cargo.toml", `[package]
name = "not-a-dependency"
version = "0.1.0"
[dependencies]
serde = {version = "=1.0.210", features = ["derive"]}
local = {path = "../local"}
`, "crates.io", "serde", "1.0.210", "pkg:cargo/serde@1.0.210", true},
		{"python/pyproject.toml", `[project]
name = "not-a-dependency"
dependencies = ["Requests[security]==2.32.3; python_version >= '3.9'", "local @ file:///tmp/local"]
`, "pypi", "requests", "2.32.3", "pkg:pypi/requests@2.32.3", true},
		{"dotnet/obj/project.assets.json", `{"version":3,"targets":{"net8.0":{"Newtonsoft.Json/13.0.3":{"type":"package"}},"net9.0":{"Newtonsoft.Json/13.0.3":{"type":"package"}}},"libraries":{"Newtonsoft.Json/13.0.3":{"type":"package","path":"newtonsoft.json/13.0.3"},"Local.Library/1.0.0":{"type":"project","path":"../Local.Library/Local.Library.csproj"}},"project":{"restore":{"sources":{"https://api.nuget.org/v3/index.json":{}}}}}`, "NuGet", "newtonsoft.json", "13.0.3", "pkg:nuget/newtonsoft.json", false},
	}
	root := t.TempDir()
	for _, f := range fixtures {
		writeProfileFile(t, root, f.path, f.body)
	}
	acquired := &AcquiredRepository{Path: root, Identity: domain.RepositoryIdentity{ID: "example/additional", CommitSHA: "abc123"}}
	at := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	got, err := ProfileWithTraversal(acquired, at, nil)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := Profile(acquired, at)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, cached) {
		t.Fatalf("cached profile differs: legacy=%#v cached=%#v", got, cached)
	}
	if got.Repository != acquired.Identity || got.ProfiledAt != at {
		t.Errorf("snapshot metadata lost: %+v", got)
	}
	if len(got.Components) != len(fixtures) {
		t.Errorf("components = %+v, want %d unique identities", got.Components, len(fixtures))
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
	usages := map[string]domain.EcosystemUsage{}
	for _, usage := range got.Ecosystems {
		if _, exists := usages[usage.Name]; exists {
			t.Errorf("duplicate ecosystem: %s", usage.Name)
		}
		usages[usage.Name] = usage
	}
	if len(usages) != len(fixtures) {
		t.Errorf("ecosystems = %+v, want %d", got.Ecosystems, len(fixtures))
	}
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
			if c.Direct != (f.manifest || f.ecosystem == "Pub") {
				t.Errorf("unexpected directness: %+v", c)
			}
			if f.ecosystem == "Conan" && c.Scope != "zlib/1.3.1#abcdef%1710000000.1" {
				t.Errorf("Conan source reference lost: %+v", c)
			}
			if f.ecosystem == "Julia" && c.Scope != "7876af07-990d-54b4-ab0e-23690620f79a" {
				t.Errorf("Julia UUID lost: %+v", c)
			}
			usage := usages[f.ecosystem]
			paths, other := usage.Lockfiles, usage.Manifests
			if f.manifest {
				paths, other = usage.Manifests, usage.Lockfiles
			}
			if !reflect.DeepEqual(paths, []string{f.path}) || len(other) != 0 {
				t.Errorf("incorrect provenance: %+v", usage)
			}
			for _, warning := range got.Warnings {
				if strings.HasPrefix(warning, f.path+":") && strings.Contains(warning, "unsupported dependency format") {
					t.Errorf("stale coverage warning: %s", warning)
				}
			}
		})
	}
	for _, want := range []struct{ path, text string }{
		{"r/renv.lock", "no OSV"},
		{"native/conan.lock", "source identities"},
		{"julia/Manifest.toml", "OSV mapping are not established"},
		{"rust/Cargo.toml", "local"},
		{"python/pyproject.toml", "local"},
	} {
		found := false
		for _, warning := range got.Warnings {
			if strings.HasPrefix(warning, want.path+":") && strings.Contains(warning, want.text) {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %s warning containing %q: %v", want.path, want.text, got.Warnings)
		}
	}
	if len(got.Products) != 1 || got.Products[0].Ecosystem != "npm" || got.Products[0].SourcePath != "deno/deno.lock" {
		t.Errorf("product aliases must remain npm-only: %+v", got.Products)
	}
	again, err := Profile(acquired, at)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, again) {
		t.Error("additional-format profile is not deterministic")
	}
}

func TestAdditionalFormatsUnsupportedNeverMeansSafe(t *testing.T) {
	for _, supported := range []bool{false, true} {
		name := "unsupported-only"
		if supported {
			name = "with-supported-companion"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			paths := []string{"web/bun.lock", "elixir/mix.lock"}
			for _, path := range paths {
				writeProfileFile(t, root, path, "not parsed\x00")
			}
			wantComponents := 0
			if supported {
				writeProfileFile(t, root, "web/package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/express":{"version":"4.21.0"}}}`)
				wantComponents = 1
			}
			got, err := Profile(&AcquiredRepository{Path: root}, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Components) != wantComponents {
				t.Errorf("unsupported files invented components: %+v", got.Components)
			}
			for _, path := range paths {
				count := 0
				for _, warning := range got.Warnings {
					if !strings.HasPrefix(warning, path+":") {
						continue
					}
					count++
					for _, text := range []string{"unsupported dependency format", "not parsed", "supported companion files are assessed separately"} {
						if !strings.Contains(warning, text) {
							t.Errorf("missing limitation %q: %s", text, warning)
						}
					}
					for _, claim := range []string{"safe", "no dependencies", "no vulnerabilities"} {
						if strings.Contains(strings.ToLower(warning), claim) {
							t.Errorf("unsupported format presented as safe: %s", warning)
						}
					}
				}
				if count != 1 {
					t.Errorf("got %d warnings for %s, want one: %v", count, path, got.Warnings)
				}
			}
		})
	}
}

func TestAdditionalFormatsDetectedLanguages(t *testing.T) {
	root := t.TempDir()
	want := map[string][]string{
		"Dart":   {"lib/main.dart"},
		"Elixir": {"lib/app.ex", "test/app_test.exs"},
		"R":      {"analysis/model.R", "analysis/util.r"},
		"Julia":  {"science/main.jl"},
	}
	for _, paths := range want {
		for _, path := range paths {
			writeProfileFile(t, root, path, "")
		}
	}
	writeProfileFile(t, root, "README.md", "not source")
	got, err := Profile(&AcquiredRepository{Path: root}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Languages) != len(want) {
		t.Fatalf("languages = %+v, want %d", got.Languages, len(want))
	}
	seen := map[string]bool{}
	for _, language := range got.Languages {
		paths, exists := want[language.Name]
		if !exists || seen[language.Name] {
			t.Errorf("unexpected or duplicate language: %+v", language)
		}
		seen[language.Name] = true
		if !reflect.DeepEqual(language.SourcePaths, paths) {
			t.Errorf("%s paths = %v, want %v", language.Name, language.SourcePaths, paths)
		}
		percentage := float64(len(paths)) * 100 / 6
		if language.Percentage == nil || *language.Percentage != percentage {
			t.Errorf("%s percentage = %v, want %v", language.Name, language.Percentage, percentage)
		}
	}
}
