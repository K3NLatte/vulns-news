package repository

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"vulns-news/src/assessment"
	"vulns-news/src/domain"
	"vulns-news/src/evidence"
	"vulns-news/src/feed"
	"vulns-news/src/matcher"
	"vulns-news/src/processor"
	"vulns-news/src/sourceinspect"
)

var traversalProfileTime = time.Date(2026, 9, 25, 12, 0, 0, 0, time.FixedZone("fixture", 3600))

func compareTraversalProfile(t *testing.T, acquired *AcquiredRepository) (domain.RepositoryProfile, domain.RepositoryProfile, error) {
	t.Helper()
	legacy, legacyErr := ProfileWithTraversal(acquired, traversalProfileTime, nil)
	cached, cachedErr := Profile(acquired, traversalProfileTime)
	if !reflect.DeepEqual(legacy, cached) {
		t.Fatalf("full profile differs:\nlegacy: %#v\ncached: %#v", legacy, cached)
	}
	// Missing roots differ only in the filesystem operation: legacy Stat vs
	// cached Open. Require PathError, the same path, and ErrNotExist there;
	// all other fixtures require exact error strings, including wrappers.
	var legacyPath, cachedPath *os.PathError
	missingPath := errors.Is(legacyErr, os.ErrNotExist) && errors.Is(cachedErr, os.ErrNotExist) &&
		errors.As(legacyErr, &legacyPath) && errors.As(cachedErr, &cachedPath) && legacyPath.Path == cachedPath.Path
	if !missingPath && (fmt.Sprint(legacyErr) != fmt.Sprint(cachedErr) || (legacyErr == nil) != (cachedErr == nil)) {
		t.Fatalf("errors differ: legacy=%v; cached=%v", legacyErr, cachedErr)
	}
	if errors.Is(legacyErr, sourceinspect.ErrLimit) != errors.Is(cachedErr, sourceinspect.ErrLimit) {
		t.Fatalf("source limit classification differs: %v / %v", legacyErr, cachedErr)
	}
	return legacy, cached, legacyErr
}

func TestProfileTraversalEmptyAndInvalidRoots(t *testing.T) {
	for _, tc := range []struct {
		name      string
		acquired  *AcquiredRepository
		wantError bool
	}{
		{"empty directory", &AcquiredRepository{Path: t.TempDir()}, false},
		{"nil", nil, true},
		{"blank path", &AcquiredRepository{}, true},
		{"missing", &AcquiredRepository{Path: filepath.Join(t.TempDir(), "missing")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := compareTraversalProfile(t, tc.acquired)
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, wantError=%t", err, tc.wantError)
			}
		})
	}
}

func TestProfileTraversalMalformedSupportedFiles(t *testing.T) {
	for _, tc := range []struct{ name, path, body string }{
		{"JSON", "package-lock.json", `{"lockfileVersion":`},
		{"TOML", "Cargo.lock", "[[package]\nname = \"unterminated"},
		{"YAML", "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: ["},
		{"XML", "pom.xml", "<project><dependencies></project>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeProfileFile(t, root, tc.path, tc.body)
			_, _, err := compareTraversalProfile(t, &AcquiredRepository{Path: root})
			if err == nil {
				t.Fatal("malformed supported file unexpectedly accepted")
			}
		})
	}
}

func TestProfileTraversalNPMScope(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"package.json":              `{"name":"root","workspaces":["packages/*"],"dependencies":{"express":"^4.0.0"}}`,
		"package-lock.json":         `{"lockfileVersion":3,"packages":{"node_modules/express":{"version":"4.21.0"},"packages/app":{"dependencies":{"express":"^4.0.0"}}}}`,
		"packages/app/package.json": `{"name":"workspace","dependencies":{"express":"^4.0.0"}}`,
		"nested/package.json":       `{"name":"nested","dependencies":{"express":"^5.0.0"}}`,
		"nested/package-lock.json":  `{"lockfileVersion":3,"packages":{"node_modules/express":{"version":"5.0.0"}}}`,
		"nested/child/package.json": `{"name":"child","dependencies":{"express":"^5.0.0"}}`,
	} {
		writeProfileFile(t, root, name, body)
	}
	legacy, cached, err := compareTraversalProfile(t, &AcquiredRepository{Path: root, Identity: domain.RepositoryIdentity{ID: "fixture/npm", CommitSHA: "abc123"}})
	if err != nil {
		t.Fatal(err)
	}
	for path, version := range map[string]string{"package-lock.json": "4.21.0", "nested/package-lock.json": "5.0.0"} {
		found := false
		for _, c := range legacy.Components {
			if c.SourcePath == path && c.Name == "express" && c.Version == version && c.Direct && c.Scope == "runtime" {
				found = true
			}
		}
		if !found {
			t.Errorf("missing nearest-lock resolution %s=%s: %+v", path, version, legacy.Components)
		}
	}
	if len(legacy.Components) != 2 {
		t.Fatalf("nearest locks should resolve declarations without duplicate manifest components: %+v", legacy.Components)
	}
	compareTraversalDownstream(t, legacy, cached)
}

func TestProfileTraversalExclusionsAndWarnings(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"vendor", "target", ".git"} {
		writeProfileFile(t, root, dir+"/observe.go", "package sample\nimport \"fmt\"\nfunc f() { fmt.Println(\"observation\") }\n")
	}
	writeProfileFile(t, root, "unknown/bun.lock", "not parsed")
	writeProfileFile(t, root, "unknown/mix.lock", "not parsed")
	got, _, err := compareTraversalProfile(t, &AcquiredRepository{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"vendor", "target", ".git"} {
		found := false
		for _, o := range got.SourceObservations {
			if o.File == dir+"/observe.go" {
				found = true
			}
		}
		if !found {
			t.Errorf("source inspection lost %s observation", dir)
		}
	}
	for _, path := range []string{"unknown/bun.lock", "unknown/mix.lock"} {
		if !strings.Contains(strings.Join(got.Warnings, "\n"), path+":") {
			t.Errorf("missing unsupported warning for %s", path)
		}
	}
	for _, language := range got.Languages {
		for _, path := range language.SourcePaths {
			if strings.HasPrefix(path, ".git/") {
				t.Errorf("language detection included %s", path)
			}
		}
	}
}

func TestProfileTraversalSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeProfileFile(t, outside, "package.json", "malformed external JSON")
	writeProfileFile(t, outside, "outside.go", "invalid external Go")
	for name, target := range map[string]string{"package.json": filepath.Join(outside, "package.json"), "outside.go": filepath.Join(outside, "outside.go"), "external": outside, "cycle": root, "dangling": filepath.Join(outside, "missing")} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	got, _, err := compareTraversalProfile(t, &AcquiredRepository{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Components) != 0 || len(got.SourceObservations) != 0 {
		t.Fatalf("followed a symlink: %+v", got)
	}
	if !strings.Contains(strings.Join(got.Warnings, "\n"), "symlink skipped") {
		t.Fatal("missing symlink warning")
	}
}

func TestProfileTraversalSourceLimits(t *testing.T) {
	for _, scenario := range []string{"depth", "file bytes", "file count", "entry count"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			switch scenario {
			case "depth":
				// Dependency profilers skip .git; source inspection deliberately does not.
				writeProfileFile(t, root, ".git/"+strings.Repeat("d/", sourceinspect.MaxDepth)+"source.go", "package sample\n")
			case "file bytes":
				writeProfileFile(t, root, "source.go", strings.Repeat(" ", sourceinspect.MaxFileBytes+1))
			case "file count":
				for i := 0; i <= sourceinspect.MaxFiles; i++ {
					writeProfileFile(t, root, fmt.Sprintf("f%04d.go", i), "package sample\n")
				}
			case "entry count":
				for i := 0; i <= sourceinspect.MaxEntries; i++ {
					writeProfileFile(t, root, fmt.Sprintf("f%05d.txt", i), "")
				}
			}
			_, _, err := compareTraversalProfile(t, &AcquiredRepository{Path: root})
			if !errors.Is(err, sourceinspect.ErrLimit) {
				t.Fatalf("want source inspection limit, got %v", err)
			}
		})
	}
}

func TestProfileDoesNotReuseTraversalAcrossCalls(t *testing.T) {
	root := t.TempDir()
	acquired := &AcquiredRepository{Path: root}
	first, _, err := compareTraversalProfile(t, acquired)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Components) != 0 {
		t.Fatalf("unexpected initial components: %+v", first.Components)
	}

	// Directory additions between calls must not be hidden by an earlier cache.
	writeProfileFile(t, root, "nested/package.json", `{"dependencies":{"express":"4.21.0"}}`)
	second, _, err := compareTraversalProfile(t, acquired)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Components) != 1 || second.Components[0].Name != "express" {
		t.Fatalf("new dependency was not discovered: %+v", second.Components)
	}
	if err := os.RemoveAll(filepath.Join(root, "nested")); err != nil {
		t.Fatal(err)
	}
	third, _, err := compareTraversalProfile(t, acquired)
	if err != nil {
		t.Fatal(err)
	}
	if len(third.Components) != 0 {
		t.Fatalf("removed dependency retained: %+v", third.Components)
	}
}

func TestProfileTraversalActualProject(t *testing.T) {
	// The checkout must remain stable during these sequential profiles. Symlink
	// fixtures elsewhere in the suite live only in temporary directories.
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(err)
	}
	got, _, err := compareTraversalProfile(t, &AcquiredRepository{Path: root, Identity: domain.RepositoryIdentity{ID: "fixture/actual-project", CommitSHA: "stable-checkout"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Components) == 0 || len(got.SourceObservations) == 0 {
		t.Fatal("actual project profile lacks dependencies or source observations")
	}
}

func compareTraversalDownstream(t *testing.T, legacy, cached domain.RepositoryProfile) {
	t.Helper()
	vulnerability := domain.NormalizedVulnerability{ID: "CVE-2026-1234", Description: "Synthetic express vulnerability for deterministic equivalence testing.", ModifiedAt: traversalProfileTime.UTC(), Affected: []domain.AffectedTarget{{ID: "express", Kind: domain.AffectedPackage, Ecosystem: "npm", PackageName: "express", PURL: "pkg:npm/express"}}}
	// Fixed fake screening isolates deterministic backend behavior, not LLM
	// reproducibility or real-world applicability of this synthetic CVE.
	screening := processor.ScreeningOutput{Result: processor.ScreeningResult{Relevance: processor.RelevancePossiblyRelated, Reason: "Fixed differential-test screening"}}
	var previousCandidate domain.MatchCandidate
	var previousEvidence []processor.Evidence
	var previousAssessment assessment.Report
	var previousFeed feed.Item
	for i, profile := range []domain.RepositoryProfile{legacy, cached} {
		candidate, matched, err := matcher.New(nil).Match(profile, vulnerability)
		if err != nil || !matched || len(candidate.Matches) == 0 {
			t.Fatalf("matcher: matched=%t, err=%v", matched, err)
		}
		citations, err := evidence.Build(profile, vulnerability, candidate)
		if err != nil {
			t.Fatal(err)
		}
		if len(citations) < 2 {
			t.Fatal("missing deterministic citations")
		}
		report := assessment.Assess(profile, vulnerability, candidate)
		item, err := feed.Build(processor.Input{Repository: profile, Vulnerability: vulnerability, Candidate: candidate, Evidence: citations}, screening, nil)
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			for _, pair := range []struct {
				name      string
				want, got any
			}{{"matcher", previousCandidate, candidate}, {"evidence", previousEvidence, citations}, {"assessment", previousAssessment, report}, {"feed", previousFeed, item}} {
				if !reflect.DeepEqual(pair.want, pair.got) {
					t.Errorf("%s differs: legacy=%#v cached=%#v", pair.name, pair.want, pair.got)
				}
			}
		}
		previousCandidate, previousEvidence, previousAssessment, previousFeed = candidate, citations, report, item
	}
}
