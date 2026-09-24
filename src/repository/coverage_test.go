package repository

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func writeCoverageFile(t *testing.T, root, name string) {
	t.Helper()
	file := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	// Invalid content is intentional: coverage discovery must not parse files.
	if err := os.WriteFile(file, []byte("not a valid manifest\x00"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDependencyCoverageWarningsUnsupportedFormats(t *testing.T) {
	names := []string{
		"bun.lock", "bun.lockb", "conanfile.py", "conanfile.txt", "conanfile.custom",
		"rebar.lock", "rebar.config", "mix.lock", "mix.exs", "build.sbt", "deps.edn", "project.clj",
		"stack.yaml", "stack.yaml.lock", "cabal.project", "cabal.project.freeze", "example.cabal",
		"opam", "opam.locked", "example.opam", "example.opam.locked", "cpanfile", "cpanfile.snapshot",
		"rockspec", "example-1.0.rockspec", "environment.yml", "environment.yaml", "conda-lock.yml", "conda-lock.yaml",
		"Cartfile", "Cartfile.resolved", "go.work", "go.work.sum", "Directory.Packages.props",
		"Directory.Build.props", "packages.props", "example.csproj", "example.fsproj", "example.vbproj", "example.vcxproj",
		"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "libs.versions.toml",
		"composer.json", "Gemfile", "Package.swift", "pubspec.yaml", "deno.json", "deno.jsonc",
		"Podfile", "Project.toml", "REQUIRE", "vcpkg-configuration.json",
	}
	root := t.TempDir()
	for _, name := range names {
		writeCoverageFile(t, root, "nested/"+name)
	}
	warnings, err := dependencyCoverageWarnings(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != len(names) {
		t.Fatalf("got %d warnings, want %d: %v", len(warnings), len(names), warnings)
	}
	for i := range names {
		names[i] = "nested/" + names[i] + ": "
	}
	sort.Strings(names)
	for i, warning := range warnings {
		if !strings.HasPrefix(warning, names[i]) {
			t.Errorf("warning is not source-relative or sorted: %q", warning)
		}
		if !strings.Contains(warning, "declarations") || !strings.Contains(warning, "not parsed") ||
			!strings.Contains(warning, "supported companion files are assessed separately") {
			t.Errorf("missing file-specific limitation: %q", warning)
		}
		for _, claim := range []string{root, "no inventory", "no dependencies", "all formats"} {
			if strings.Contains(warning, claim) {
				t.Errorf("misleading or non-relative warning: %q", warning)
			}
		}
	}
}

func TestDependencyCoverageWarningsSupportedAndUnrecognizedFiles(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{
		"package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
		"go.mod", "go.sum", "requirements.txt", "requirements-dev.txt", "requirements/base.in",
		"pyproject.toml", "pdm.lock", "poetry.lock", "uv.lock", "Pipfile.lock",
		"Cargo.lock", "Cargo.toml", "composer.lock", "Gemfile.lock", "packages.lock.json",
		"packages.config", "project.assets.json", "pom.xml", "gradle.lockfile", "Package.resolved",
		"package.resolved", "pubspec.lock", "deno.lock", "renv.lock", "conan.lock", "vcpkg.json",
		"Podfile.lock", "Manifest.toml", "README.md", "unknown.lock", "example.csproj.bak",
		"bun.lock.example", "notconanfile.py", "ordinary.toml",
	} {
		writeCoverageFile(t, root, name)
	}
	warnings, err := dependencyCoverageWarnings(root)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("warnings = %v, error = %v", warnings, err)
	}
}

func TestDependencyCoverageWarningsSupportedCompanionsDoNotSuppress(t *testing.T) {
	for _, pair := range [][2]string{
		{"conanfile.py", "conan.lock"}, {"build.gradle", "gradle.lockfile"},
		{"build.gradle.kts", "gradle.lockfile"}, {"app.csproj", "packages.lock.json"},
		{"Directory.Packages.props", "project.assets.json"}, {"go.work", "go.mod"},
		{"bun.lock", "package-lock.json"}, {"Podfile", "Podfile.lock"},
		{"Project.toml", "Manifest.toml"}, {"Package.swift", "Package.resolved"},
		{"composer.json", "composer.lock"}, {"Gemfile", "Gemfile.lock"},
	} {
		t.Run(pair[0], func(t *testing.T) {
			root := t.TempDir()
			writeCoverageFile(t, root, pair[0])
			before, err := dependencyCoverageWarnings(root)
			if err != nil || len(before) != 1 {
				t.Fatalf("before = %v, %v", before, err)
			}
			writeCoverageFile(t, root, pair[1])
			after, err := dependencyCoverageWarnings(root)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("companion changed warning: before %v, after %v, error %v", before, after, err)
			}
		})
	}
}

func TestDependencyCoverageWarningsDeterministic(t *testing.T) {
	names := []string{"z/bun.lock", "a/mix.lock", "build.sbt", "a/bun.lock", "a-foo/go.work"}
	var expected []string
	for order := 0; order < 2; order++ {
		root := t.TempDir()
		for i := range names {
			index := i
			if order == 1 {
				index = len(names) - 1 - i
			}
			writeCoverageFile(t, root, names[index])
		}
		for repeat := 0; repeat < 3; repeat++ {
			got, err := dependencyCoverageWarnings(root)
			if err != nil {
				t.Fatal(err)
			}
			if expected == nil {
				expected = got
			}
			if len(got) != len(names) || !sort.StringsAreSorted(got) || !reflect.DeepEqual(got, expected) {
				t.Fatalf("non-deterministic warnings: %v, want %v", got, expected)
			}
		}
	}
}

func TestDependencyCoverageWarningsSkips(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{
		".git", ".hg", ".svn", "node_modules", ".pnpm", ".yarn", "vendor", ".venv",
		"venv", "__pycache__", ".gradle", ".build", "target",
	} {
		writeCoverageFile(t, root, dir+"/deep/bun.lock")
	}
	// Hidden source directories are not categorically excluded; a directory
	// named like a manifest is not itself a dependency file.
	writeCoverageFile(t, root, ".source/bun.lock")
	if err := os.Mkdir(filepath.Join(root, "mix.lock"), 0755); err != nil {
		t.Fatal(err)
	}
	got, err := dependencyCoverageWarnings(root)
	if err != nil || len(got) != 1 || !strings.HasPrefix(got[0], ".source/bun.lock:") {
		t.Fatalf("warnings = %v, error = %v", got, err)
	}
}

func TestDependencyCoverageWarningsSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeCoverageFile(t, outside, "bun.lock")
	writeCoverageFile(t, root, "real/mix.lock")
	for name, target := range map[string]string{
		"external": outside, "bun.lock": filepath.Join(outside, "bun.lock"),
		"internal": filepath.Join(root, "real"), "cycle": root,
		"conanfile.py": filepath.Join(outside, "missing"),
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	got, err := dependencyCoverageWarnings(root)
	if err != nil || len(got) != 1 || !strings.HasPrefix(got[0], "real/mix.lock:") {
		t.Fatalf("warnings = %v, error = %v", got, err)
	}
	if _, err := dependencyCoverageWarnings(filepath.Join(root, "external")); err == nil {
		t.Fatal("accepted symlink root")
	}
}

func TestDependencyCoverageWarningsSpecialFile(t *testing.T) {
	root := t.TempDir()
	listener, err := net.Listen("unix", filepath.Join(root, "bun.lock"))
	if err != nil {
		t.Skipf("Unix socket unavailable: %v", err)
	}
	defer listener.Close()
	got, err := dependencyCoverageWarnings(root)
	if err != nil || len(got) != 0 {
		t.Fatalf("warnings = %v, error = %v", got, err)
	}
}

func TestDependencyCoverageWarningsLimits(t *testing.T) {
	t.Run("entries include unrecognized files and directories", func(t *testing.T) {
		root := t.TempDir()
		writeCoverageFile(t, root, "bun.lock")
		writeCoverageFile(t, root, "ordinary.txt")
		writeCoverageFile(t, root, "node_modules/ignored/mix.lock")
		if got, err := dependencyCoverageWarningsWithLimits(root, 3, 0); err != nil || len(got) != 1 {
			t.Fatalf("exact entry limit: %v, %v", got, err)
		}
		got, err := dependencyCoverageWarningsWithLimits(root, 2, 0)
		if err == nil || !strings.Contains(err.Error(), "entry limit") || got != nil {
			t.Fatalf("exceeded entry limit: %v, %v", got, err)
		}
	})
	t.Run("multiple directory read batches", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i < 260; i++ {
			writeCoverageFile(t, root, fmt.Sprintf("file-%03d.cabal", i))
		}
		if got, err := dependencyCoverageWarningsWithLimits(root, 260, 0); err != nil || len(got) != 260 {
			t.Fatalf("exact batch limit: %v, %v", got, err)
		}
		if got, err := dependencyCoverageWarningsWithLimits(root, 259, 0); err == nil || got != nil {
			t.Fatalf("exceeded batch limit: %v, %v", got, err)
		}
	})
	t.Run("default depth", func(t *testing.T) {
		root := t.TempDir()
		deep := strings.Repeat("d/", maxCoverageDepth)
		writeCoverageFile(t, root, deep+"bun.lock")
		if got, err := dependencyCoverageWarnings(root); err != nil || len(got) != 1 {
			t.Fatalf("exact depth limit: %v, %v", got, err)
		}
		writeCoverageFile(t, root, deep+"deeper/mix.lock")
		got, err := dependencyCoverageWarnings(root)
		if err == nil || !strings.Contains(err.Error(), "depth limit") || got != nil {
			t.Fatalf("exceeded depth limit: %v, %v", got, err)
		}
	})
}

func TestDependencyCoverageWarningsInvalidAndEmptyRoots(t *testing.T) {
	root := t.TempDir()
	if got, err := dependencyCoverageWarnings(root); err != nil || len(got) != 0 {
		t.Fatalf("empty root: %v, %v", got, err)
	}
	writeCoverageFile(t, root, "file")
	for _, invalid := range []string{"", "   ", filepath.Join(root, "missing"), filepath.Join(root, "file")} {
		if got, err := dependencyCoverageWarnings(invalid); err == nil || got != nil {
			t.Errorf("invalid root %q: %v, %v", invalid, got, err)
		}
	}
}
