package repository

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxCoverageEntries = 100_000
	maxCoverageDepth   = 64
)

// dependencyCoverageWarnings recognizes selected unsupported dependency formats.
// It does not read files, execute manifests, or claim exhaustive format coverage.
func dependencyCoverageWarnings(root string) ([]string, error) {
	return dependencyCoverageWarningsWithLimits(root, maxCoverageEntries, maxCoverageDepth)
}

func dependencyCoverageWarningsWithLimits(root string, maxEntries, maxDepth int) ([]string, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("dependency coverage root is required")
	}
	root = filepath.Clean(root)
	before, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("dependency coverage root: %w", err)
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("dependency coverage root must be a non-symlink directory")
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("open dependency coverage root: %w", err)
	}
	defer r.Close()
	after, err := r.Stat(".")
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, errors.New("dependency coverage root changed during traversal")
	}

	var warnings []string
	entries := 0
	var walk func(*os.Root, string, int) error
	walk = func(dir *os.Root, relative string, depth int) error {
		if depth > maxDepth {
			return fmt.Errorf("%s: dependency coverage depth limit exceeded", relative)
		}
		d, err := dir.Open(".")
		if err != nil {
			return err
		}
		defer d.Close()
		for {
			// Batch reads bound allocations even for an extremely wide directory.
			batch, readErr := d.ReadDir(128)
			for _, entry := range batch {
				entries++
				if entries > maxEntries {
					return errors.New("dependency coverage entry limit exceeded")
				}
				name := entry.Name()
				source := path.Join(relative, name)
				info, err := dir.Lstat(name)
				if err != nil {
					return fmt.Errorf("%s: %w", source, err)
				}
				if info.Mode()&os.ModeSymlink != 0 {
					continue
				}
				if info.IsDir() {
					if coverageSkippedDirectory(name) {
						continue
					}
					// Each child gets its own confined handle. Check identity so a
					// directory replaced between Lstat and OpenRoot is not scanned.
					child, err := dir.OpenRoot(name)
					if err != nil {
						return fmt.Errorf("%s: %w", source, err)
					}
					opened, statErr := child.Stat(".")
					if statErr != nil || !os.SameFile(info, opened) {
						child.Close()
						return fmt.Errorf("%s: directory changed during dependency coverage traversal", source)
					}
					err = walk(child, source, depth+1)
					child.Close()
					if err != nil {
						return err
					}
					continue
				}
				if info.Mode().IsRegular() && coverageUnsupportedFormat(name) {
					warnings = append(warnings, source+": unsupported dependency format; declarations or resolutions in this file are not parsed; supported companion files are assessed separately")
				}
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if readErr != nil {
				return fmt.Errorf("%s: read dependency coverage directory: %w", relative, readErr)
			}
		}
	}
	if err := walk(r, ".", 0); err != nil {
		// Never return partial results as a successful coverage scan.
		return nil, err
	}
	sort.Strings(warnings)
	return warnings, nil
}

func coverageSkippedDirectory(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules", ".pnpm", ".yarn", "vendor",
		".venv", "venv", "__pycache__", ".gradle", ".build", "target":
		return true
	}
	return false
}

func coverageUnsupportedFormat(name string) bool {
	// Deliberately enumerate names rather than treating every manifest/lock
	// extension as unsupported: supported parsers evolve independently.
	switch name {
	case "bun.lock", "bun.lockb", "rebar.lock", "rebar.config", "mix.lock", "mix.exs",
		"build.sbt", "deps.edn", "project.clj", "stack.yaml", "stack.yaml.lock", "cabal.project", "cabal.project.freeze",
		"opam", "opam.locked", "cpanfile", "cpanfile.snapshot", "rockspec",
		"environment.yml", "environment.yaml", "conda-lock.yml", "conda-lock.yaml",
		"Cartfile", "Cartfile.resolved", "go.work", "go.work.sum",
		"Directory.Packages.props", "Directory.Build.props", "packages.props",
		"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "libs.versions.toml",
		"composer.json", "Gemfile", "Package.swift", "pubspec.yaml", "deno.json", "deno.jsonc",
		"Podfile", "Project.toml", "REQUIRE", "vcpkg-configuration.json":
		return true
	}
	if strings.HasPrefix(name, "conanfile.") {
		return true
	}
	for _, suffix := range []string{".cabal", ".opam", ".opam.locked", ".rockspec", ".csproj", ".fsproj", ".vbproj", ".vcxproj"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
