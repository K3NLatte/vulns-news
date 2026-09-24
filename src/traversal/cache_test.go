package traversal

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"testing/fstest"
)

func fixture(t *testing.T, count int) string {
	t.Helper()
	root := t.TempDir()
	for i := 0; i < count; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("entry-%04d", count-i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func openDir(t *testing.T, root string) *os.File {
	t.Helper()
	f, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func names(entries []fs.DirEntry) []string {
	result := make([]string, len(entries))
	for i, entry := range entries {
		result[i] = entry.Name()
	}
	return result
}

func checkRead(t *testing.T, c *Cache, key string, actual, expected *os.File, n int) {
	t.Helper()
	got, gotErr := c.ReadDir(key, actual, n)
	want, wantErr := expected.ReadDir(n)
	if !reflect.DeepEqual(names(got), names(want)) || !errors.Is(gotErr, wantErr) {
		t.Fatalf("n=%d: got %v, %v; want %v, %v", n, names(got), gotErr, names(want), wantErr)
	}
}

func TestBatchContracts(t *testing.T) {
	for _, size := range []int{0, 1, 7} {
		root := fixture(t, size)
		for _, batch := range []int{-7, -1, 0, 1, 2, 3, 7, 8, 100} {
			t.Run(fmt.Sprintf("size=%d/batch=%d", size, batch), func(t *testing.T) {
				c := New()
				for run := 0; run < 2; run++ {
					actual, expected := openDir(t, root), openDir(t, root)
					for i := 0; i < size+3; i++ {
						checkRead(t, c, ".", actual, expected, batch)
					}
				}
				if c.Stats().EntriesCached != uint64(size) {
					t.Fatal(c.Stats())
				}
				if c.Stats().CacheHits == 0 {
					t.Fatal("no cache hits")
				}
			})
		}
	}
}

func TestPartialInterleavedCursors(t *testing.T) {
	root := fixture(t, 13)
	c := New()
	a, ar := openDir(t, root), openDir(t, root)
	b, br := openDir(t, root), openDir(t, root)
	d, dr := openDir(t, root), openDir(t, root)
	checkRead(t, c, "dir/sub", a, ar, 3)
	checkRead(t, c, "dir\\sub", b, br, 1)
	checkRead(t, c, "./dir/sub/", d, dr, 5)
	checkRead(t, c, "dir/sub", a, ar, 4)
	checkRead(t, c, "dir/sub", b, br, 8)
	checkRead(t, c, "dir/sub", d, dr, -1)
	checkRead(t, c, "dir/sub", a, ar, 100)
	checkRead(t, c, "dir/sub", b, br, 0)
	checkRead(t, c, "dir/sub", a, ar, 1)
	if len(c.directories) != 1 {
		t.Fatal("keys were not normalized")
	}
	if c.Stats().EntriesCached != 13 {
		t.Fatal(c.Stats())
	}
}

func TestLargePrefixCatchUp(t *testing.T) {
	root := fixture(t, skipBatch+5)
	c := New()
	a := openDir(t, root)
	if _, err := c.ReadDir(".", a, skipBatch+2); err != nil {
		t.Fatal(err)
	}
	checkRead(t, c, ".", openDir(t, root), openDir(t, root), -1)
	if c.Stats().DirectoryReads != 4 {
		t.Fatalf("expected initial, two catch-up and final reads: %+v", c.Stats())
	}
}

func TestStorageLimits(t *testing.T) {
	for _, entryLimit := range []int{0, 1, 4, 10} {
		for _, cursorLimit := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("entries=%d/cursors=%d", entryLimit, cursorLimit), func(t *testing.T) {
				root := fixture(t, 10)
				c := New()
				c.init()
				c.entryLimit, c.cursorLimit = entryLimit, cursorLimit
				for run := 0; run < 4; run++ {
					a, ar := openDir(t, root), openDir(t, root)
					for _, n := range []int{2, 1, 4, 1, -1, 1, 0} {
						checkRead(t, c, ".", a, ar, n)
					}
				}
				if c.Stats().EntriesCached > uint64(entryLimit) || len(c.cursors) > cursorLimit {
					t.Fatal("limit exceeded")
				}
			})
		}
	}
}

func TestCopiesAndDistinctKeys(t *testing.T) {
	root := fixture(t, 5)
	c := New()
	entries, err := c.ReadDir("one", openDir(t, root), -1)
	if err != nil {
		t.Fatal(err)
	}
	entries[0] = nil
	checkRead(t, c, "one", openDir(t, root), openDir(t, root), -1)
	before := c.Stats()
	checkRead(t, c, "two", openDir(t, root), openDir(t, root), -1)
	if c.Stats().DirectoryReads != before.DirectoryReads+1 || c.Stats().EntriesCached != 10 {
		t.Fatal(c.Stats())
	}
}

func TestIdentityReplacement(t *testing.T) {
	first, second := fixture(t, 3), fixture(t, 8)
	c := New()
	checkRead(t, c, ".", openDir(t, first), openDir(t, first), -1)
	// Different identities under the same key model a directory replaced between runs.
	a, ar := openDir(t, second), openDir(t, second)
	for _, n := range []int{2, 3, -1, 1} {
		checkRead(t, c, ".", a, ar, n)
	}
	if c.Stats().CacheHits != 0 || c.Stats().EntriesCached != 3 {
		t.Fatal(c.Stats())
	}
	closed := openDir(t, first)
	closed.Close()
	if _, err := c.ReadDir(".", closed, -1); err == nil {
		t.Fatal("closed new descriptor reused cached entries")
	}
}

func TestNilCache(t *testing.T) {
	var c *Cache
	root := fixture(t, 4)
	a, ar := openDir(t, root), openDir(t, root)
	for _, n := range []int{1, 2, -1, 1} {
		checkRead(t, c, ".", a, ar, n)
	}
	base := os.DirFS(root)
	if c.WrapFS(base) != base || c.Stats() != (Stats{}) {
		t.Fatal("nil receiver contract")
	}
}

func walk(t *testing.T, base fs.FS) []string {
	t.Helper()
	var result []string
	err := fs.WalkDir(base, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		result = append(result, name)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestWrapFS(t *testing.T) {
	root := fixture(t, 6)
	if err := os.Mkdir(filepath.Join(root, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "child", "nested"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	base := os.DirFS(root)
	c := New()
	wrapped := c.WrapFS(base)
	if _, ok := wrapped.(fs.ReadDirFS); !ok {
		t.Fatal("missing ReadDirFS")
	}
	want := walk(t, base)
	for i := 0; i < 2; i++ {
		if got := walk(t, wrapped); !reflect.DeepEqual(got, want) {
			t.Fatalf("%v != %v", got, want)
		}
	}
	entries, err := fs.ReadDir(wrapped, ".")
	if err != nil {
		t.Fatal(err)
	}
	if !sort.StringsAreSorted(names(entries)) {
		t.Fatal("not sorted")
	}
	entries[0] = nil
	checkRead(t, c, ".", openDir(t, root), openDir(t, root), -1)
	if c.Stats().DirectoryReads != 2 {
		t.Fatal(c.Stats())
	}
	if _, err := fs.ReadDir(wrapped, "../outside"); err == nil {
		t.Fatal("invalid FS path accepted")
	}
}

func TestWrapFSFallback(t *testing.T) {
	base := fstest.MapFS{"z": &fstest.MapFile{}, "a/b": &fstest.MapFile{}}
	c := New()
	if got, want := walk(t, c.WrapFS(base)), walk(t, base); !reflect.DeepEqual(got, want) {
		t.Fatalf("%v != %v", got, want)
	}
	if c.Stats() != (Stats{}) {
		t.Fatal("fallback should not cache non-os files")
	}
}

func TestWrapFSSymlinkBehavior(t *testing.T) {
	root := fixture(t, 1)
	outside := fixture(t, 2)
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	base := os.DirFS(root)
	if got, want := walk(t, New().WrapFS(base)), walk(t, base); !reflect.DeepEqual(got, want) {
		t.Fatalf("%v != %v", got, want)
	}
}

func TestCacheDoesNotOwnFiles(t *testing.T) {
	root := fixture(t, 2)
	c := New()
	f := openDir(t, root)
	if _, err := c.ReadDir(".", f, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stat(); err != nil {
		t.Fatal("cache closed caller file:", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	checkRead(t, c, ".", openDir(t, root), openDir(t, root), -1)
	// Full-directory reads suppress EOF; a subsequent positive read reports it.
	f = openDir(t, root)
	if _, err := c.ReadDir(".", f, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadDir(".", f, 1); err != io.EOF {
		t.Fatalf("got %v", err)
	}
}
