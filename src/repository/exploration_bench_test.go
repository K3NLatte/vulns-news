package repository

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
	"vulns-news/src/traversal"
)

// This isolates enumeration overhead on identical synthetic directory trees.
// The single-pass index is NOT a replacement profiler: it does not reproduce
// each existing consumer's exclusions, security checks or resource budgets.
var explorationNames = []string{"package.json", "go.mod", "pom.xml", "Cargo.lock", "pubspec.lock", "pyproject.toml", "conan.lock", "bun.lock", "main.go", "script.m"}
var explorationSink int

func explorationFixture(b *testing.B, files int) string {
	b.Helper()
	root := b.TempDir()
	for i := 0; i < files; i++ {
		dir := filepath.Join(root, fmt.Sprintf("d%03d", i/100))
		if i%100 == 0 {
			if err := os.MkdirAll(dir, 0700); err != nil {
				b.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("data%05d.txt", i)), []byte("fixture\n"), 0600); err != nil {
			b.Fatal(err)
		}
	}
	// A minimal valid input for the real profiler; no external dependency loads.
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"example":"1.2.3"}}`), 0600); err != nil {
		b.Fatal(err)
	}
	return root
}

func explorationDiscover(root string, shared bool) ([][]string, error) {
	result := make([][]string, len(explorationNames))
	index := map[string]int{}
	for i, name := range explorationNames {
		index[name] = i
	}
	if shared {
		err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.Type().IsRegular() {
				if i, ok := index[e.Name()]; ok {
					result[i] = append(result[i], path)
				}
			}
			return nil
		})
		return result, err
	}
	for i, name := range explorationNames {
		err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.Type().IsRegular() && e.Name() == name {
				result[i] = append(result[i], path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func TestExplorationPrototypeEquivalentDiscovery(t *testing.T) {
	root := t.TempDir()
	for _, name := range explorationNames {
		writeProfileFile(t, root, name, "fixture")
		writeProfileFile(t, root, "nested/"+name, "fixture")
	}
	writeProfileFile(t, root, "ignored.txt", "")
	repeated, err := explorationDiscover(root, false)
	if err != nil {
		t.Fatal(err)
	}
	indexed, err := explorationDiscover(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(repeated, indexed) {
		t.Fatalf("discovery differs: %#v vs %#v", repeated, indexed)
	}
	for _, files := range indexed {
		if len(files) != 2 {
			t.Fatalf("missing fixture: %v", files)
		}
	}
}

func BenchmarkRepositoryExploration(b *testing.B) {
	for _, files := range []int{1000, 5000} {
		b.Run(fmt.Sprintf("files_%d", files), func(b *testing.B) {
			root := explorationFixture(b, files)
			for _, shared := range []bool{false, true} {
				name := "ten_walks"
				if shared {
					name = "one_walk_dispatch"
				}
				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						result, err := explorationDiscover(root, shared)
						if err != nil {
							b.Fatal(err)
						}
						explorationSink = len(result)
					}
				})
			}
			b.Run("shared_full_profile", func(b *testing.B) {
				b.ReportAllocs()
				acquired := &AcquiredRepository{Path: root}
				at := time.Unix(0, 0)
				var reads, hits uint64
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					cache := traversal.New()
					profile, err := ProfileWithTraversal(acquired, at, cache)
					if err != nil {
						b.Fatal(err)
					}
					explorationSink = len(profile.Components)
					reads += cache.Stats().DirectoryReads
					hits += cache.Stats().CacheHits
				}
				b.ReportMetric(float64(reads)/float64(b.N), "readdir/op")
				b.ReportMetric(float64(hits)/float64(b.N), "cachehits/op")
			})
			b.Run("legacy_full_profile", func(b *testing.B) {
				b.ReportAllocs()
				acquired := &AcquiredRepository{Path: root}
				at := time.Unix(0, 0)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					profile, err := ProfileWithTraversal(acquired, at, nil)
					if err != nil {
						b.Fatal(err)
					}
					explorationSink = len(profile.Components)
				}
			})
		})
	}
}
