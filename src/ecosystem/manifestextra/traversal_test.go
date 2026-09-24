package manifestextra

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
			fixture(t, root, "nested/Cargo.toml", "[dependencies]\nserde = \"=1.0.210\"\n")
			fixture(t, root, ".git/Cargo.toml", "invalid [")
			fixture(t, root, "target/Cargo.toml", "invalid [")
			fixture(t, root, ".cargo/config.toml", "")
			for i := 0; i < 260; i++ {
				fixture(t, root, fmt.Sprintf("ignored-%03d", i), "")
			}
			if err := os.Symlink("nested", filepath.Join(root, "linked")); err != nil {
				t.Fatal(err)
			}
			if invalid {
				fixture(t, root, "nested/pyproject.toml", "invalid [")
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
				if i == 2 && (cache.Stats().CacheHits <= before.CacheHits || (!invalid && cache.Stats().DirectoryReads != before.DirectoryReads)) {
					t.Fatalf("warm cache not reused: before %+v, after %+v", before, cache.Stats())
				}
			}
		})
	}
}
