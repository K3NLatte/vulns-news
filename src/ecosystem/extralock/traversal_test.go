package extralock

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vulns-news/src/traversal"
)

func TestTraversalDifferential(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint(invalid), func(t *testing.T) {
			root := t.TempDir()
			put(t, root, "nested/pubspec.lock", pubFixture)
			put(t, root, ".git/deno.lock", "invalid")
			for i := 0; i < 260; i++ {
				put(t, root, fmt.Sprintf("ignored-%03d", i), "")
			}
			if err := os.Symlink("nested", filepath.Join(root, "linked")); err != nil {
				t.Fatal(err)
			}
			if invalid {
				put(t, root, "nested/deno.lock", "invalid")
			}
			want, wantErr := Profile(root)
			if (wantErr != nil) != invalid {
				t.Fatalf("unexpected baseline error: %v", wantErr)
			}
			cache := traversal.New()
			for i, c := range []*traversal.Cache{nil, cache, cache} {
				before := cache.Stats()
				got, err := ProfileWithTraversal(root, c)
				if fmt.Sprint(err) != fmt.Sprint(wantErr) || !reflect.DeepEqual(got, want) {
					t.Fatalf("run %d: got %+v, %v; want %+v, %v", i, got, err, want, wantErr)
				}
				if i == 2 && (cache.Stats().CacheHits <= before.CacheHits || cache.Stats().DirectoryReads != before.DirectoryReads) {
					t.Fatalf("warm cache not reused: before %+v, after %+v", before, cache.Stats())
				}
			}
		})
	}
}

func TestDefaultTraversalBeyondBatches(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 260; i++ {
		put(t, root, fmt.Sprintf("ignored-%03d", i), "")
	}
	put(t, root, "zz/pubspec.lock", pubFixture)
	got, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Components) == 0 || len(got.Ecosystems) == 0 || !reflect.DeepEqual(got.Ecosystems[0].Lockfiles, []string{"zz/pubspec.lock"}) {
		t.Fatalf("missing recognized file after ignored entries: %+v", got)
	}
}

func TestTraversalCustomLimits(t *testing.T) {
	root := t.TempDir()
	put(t, root, "nested/pubspec.lock", pubFixture)
	cache := traversal.New()
	if _, err := ProfileWithTraversal(root, cache); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"entries", "depth", "fileBytes", "totalBytes", "components"} {
		t.Run(field, func(t *testing.T) {
			lim := defaultLimits
			switch field {
			case "entries":
				lim.entries = 1
			case "depth":
				lim.depth = 0
			case "fileBytes":
				lim.fileBytes = 1
			case "totalBytes":
				lim.totalBytes = 1
			case "components":
				lim.components = 0
			}
			want, wantErr := profile(root, lim)
			got, err := profileWithTraversal(root, lim, cache)
			if wantErr == nil || fmt.Sprint(err) != fmt.Sprint(wantErr) || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, %v; want %+v, %v", got, err, want, wantErr)
			}
		})
	}
}
