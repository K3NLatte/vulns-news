package repository

import (
	"fmt"
	"reflect"
	"testing"

	"vulns-news/src/sourceinspect"
	"vulns-news/src/traversal"
)

func TestCoverageTraversalDifferential(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"bun.lock", "a/mix.lock", "a/deep/go.work", "b/build.sbt", "vendor/bun.lock", ".git/mix.lock", "node_modules/go.work", "package-lock.json"} {
		writeCoverageFile(t, root, name)
	}
	for n := 0; n < 260; n++ {
		writeCoverageFile(t, root, fmt.Sprintf("a/ignored-%03d.txt", n))
	}
	want, err := dependencyCoverageWarnings(root)
	if err != nil || len(want) != 4 {
		t.Fatalf("baseline warnings = %v, error = %v", want, err)
	}
	for _, prewarm := range []bool{false, true} {
		t.Run(fmt.Sprintf("source-prewarm-%t", prewarm), func(t *testing.T) {
			cache := traversal.New()
			if prewarm {
				if _, err := sourceinspect.InspectWithTraversal(root, cache); err != nil {
					t.Fatal(err)
				}
			}
			for pass, candidate := range []*traversal.Cache{nil, cache, cache} {
				before := cache.Stats()
				got, err := dependencyCoverageWarningsWithTraversal(root, candidate)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("pass %d: warnings = %v, error = %v; want %v", pass, got, err, want)
				}
				if pass == 2 || (prewarm && pass == 1) {
					after := cache.Stats()
					if after.DirectoryReads != before.DirectoryReads || after.CacheHits <= before.CacheHits {
						t.Fatalf("nested directory cache reuse failed: before %+v, after %+v", before, after)
					}
				}
			}
		})
	}
}

func TestCoverageTraversalLimitsDifferential(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"bun.lock", "a/mix.lock", "a/deep/go.work", "b/build.sbt"} {
		writeCoverageFile(t, root, name)
	}
	cache := traversal.New()
	if _, err := dependencyCoverageWarningsWithTraversal(root, cache); err != nil {
		t.Fatal(err)
	}
	for _, limits := range [][2]int{{0, 64}, {3, 64}, {100, 0}, {100, 1}, {100, 64}} {
		want, wantErr := dependencyCoverageWarningsWithLimits(root, limits[0], limits[1])
		for _, candidate := range []*traversal.Cache{nil, traversal.New(), cache} {
			got, err := dependencyCoverageWarningsCore(root, limits[0], limits[1], candidate)
			if !reflect.DeepEqual(got, want) || fmt.Sprint(err) != fmt.Sprint(wantErr) {
				t.Fatalf("limits %v: got %v, %v; want %v, %v", limits, got, err, want, wantErr)
			}
		}
	}
}
