// Package traversal provides an experimental, opt-in directory enumeration cache.
// A Cache is for sequential repository profile runs; it is not safe for concurrent
// use. It caches raw DirEntry values, not authorization decisions or Info results.
// Callers must still perform their own checks and close every file they open.
// Directory contents are assumed stable during the lifetime of a Cache. SameFile
// protects against replacement, not in-place additions or removals.
package traversal

import (
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
)

const (
	maxEntries = 100_000
	maxCursors = 100_000
	skipBatch  = 1024
)

// Stats describes work performed through a Cache. DirectoryReads counts physical
// os.File.ReadDir calls, including catch-up and uncached reads. CacheHits counts
// calls served at least partly from cached entries (or a cached end of directory).
// EntriesCached is the number of retained entries. WrapFS fallback work is not counted.
type Stats struct {
	DirectoryReads uint64
	CacheHits      uint64
	EntriesCached  uint64
}

type directory struct {
	identity fs.FileInfo
	entries  []fs.DirEntry
	complete bool
}

type cursor struct {
	directory *directory
	logical   int
	physical  int
}

// Cache retains at most 100,000 entries and 100,000 file cursors/directories.
// On reaching a limit it falls back to physical enumeration, possibly rereading
// cached prefixes to synchronize file offsets. It never truncates a stream.
// Retained file pointers identify cursors only: Cache never closes files or keeps
// them open on the caller's behalf. Do not read or seek a file independently after
// passing it to ReadDir. Use a fresh, unread file for each traversal, and discard
// the Cache after the related profile runs to release its retained state.
// The zero value is usable.
type Cache struct {
	directories map[string]*directory
	cursors     map[*os.File]*cursor
	stats       Stats
	entryLimit  int
	cursorLimit int
	initialized bool
}

// New creates a cache with bounded storage. No global state is used.
func New() *Cache { return &Cache{} }

// Stats returns a snapshot of instrumentation. A nil Cache returns zero stats.
func (c *Cache) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	return c.stats
}

func (c *Cache) init() {
	if c.initialized {
		return
	}
	c.directories = make(map[string]*directory)
	c.cursors = make(map[*os.File]*cursor)
	c.entryLimit = maxEntries
	c.cursorLimit = maxCursors
	c.initialized = true
}

func normalize(key string) string {
	return path.Clean("/" + strings.ReplaceAll(key, "\\", "/"))[1:]
}

func (c *Cache) read(file *os.File, n int) ([]fs.DirEntry, error) {
	c.stats.DirectoryReads++
	return file.ReadDir(n)
}

// ReadDir implements os.File.ReadDir's batch and EOF contracts while preserving
// native enumeration order. Returned slices are independent of cache storage.
// Keys are normalized slash-separated root-relative names; use a consistent root
// per Cache. Distinct keys are independent even when they identify the same file.
// Each new file is validated with Stat and SameFile before reusing a directory.
// A replacement bypasses the old cache rather than receiving stale entries.
// A nil receiver delegates directly to file.ReadDir(n).
func (c *Cache) ReadDir(key string, file *os.File, n int) ([]fs.DirEntry, error) {
	if c == nil {
		return file.ReadDir(n)
	}
	c.init()
	cur := c.cursors[file]
	if cur == nil {
		if len(c.cursors) >= c.cursorLimit {
			return c.read(file, n)
		}
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		key = normalize(key)
		dir := c.directories[key]
		if dir != nil && !os.SameFile(dir.identity, info) {
			return c.read(file, n)
		}
		if dir == nil {
			dir = &directory{identity: info}
			c.directories[key] = dir
		}
		cur = &cursor{directory: dir}
		c.cursors[file] = cur
	}
	dir := cur.directory
	result := make([]fs.DirEntry, 0)
	available := len(dir.entries) - cur.logical
	if available > 0 {
		if n > 0 && available > n {
			available = n
		}
		result = append(result, dir.entries[cur.logical:cur.logical+available]...)
		cur.logical += available
		c.stats.CacheHits++
	} else if dir.complete && cur.logical == len(dir.entries) {
		c.stats.CacheHits++
	}
	if n > 0 && len(result) == n {
		return result, nil
	}
	if dir.complete && cur.logical == len(dir.entries) {
		if n > 0 && len(result) == 0 {
			return result, io.EOF
		}
		return result, nil
	}
	// A reused prefix advances the logical cursor only. Catch the real descriptor
	// up before fetching any new entries, including when the storage cap was hit.
	for cur.physical < cur.logical {
		count := cur.logical - cur.physical
		if count > skipBatch {
			count = skipBatch
		}
		skipped, err := c.read(file, count)
		cur.physical += len(skipped)
		if err != nil {
			return finish(result, err, n)
		}
	}
	count := n
	if n > 0 {
		count -= len(result)
	}
	entries, err := c.read(file, count)
	start := cur.logical
	cur.physical += len(entries)
	cur.logical += len(entries)
	result = append(result, entries...)
	if start == len(dir.entries) {
		room := c.entryLimit - int(c.stats.EntriesCached)
		keep := len(entries)
		if keep > room {
			keep = room
		}
		dir.entries = append(dir.entries, entries[:keep]...)
		c.stats.EntriesCached += uint64(keep)
		if keep == len(entries) && (err == io.EOF || (n <= 0 && err == nil)) {
			dir.complete = true
		}
	}
	return finish(result, err, n)
}

func finish(entries []fs.DirEntry, err error, n int) ([]fs.DirEntry, error) {
	if err == io.EOF && (n <= 0 || len(entries) > 0) {
		err = nil
	}
	return entries, err
}

type cachedFS struct {
	base  fs.FS
	cache *Cache
}

// WrapFS supplies fs.ReadDirFS with sorted, copied listings suitable for fs.WalkDir.
// Open delegates unchanged to base; no additional symlinks are followed. Only
// files returned by base.Open as *os.File (such as os.DirFS) use the cache. Other
// implementations fall back to fs.ReadDir. A nil receiver returns base unchanged.
func (c *Cache) WrapFS(base fs.FS) fs.FS {
	if c == nil {
		return base
	}
	return &cachedFS{base: base, cache: c}
}

func (f *cachedFS) Open(name string) (fs.File, error) { return f.base.Open(name) }

func (f *cachedFS) ReadDir(name string) ([]fs.DirEntry, error) {
	opened, err := f.base.Open(name)
	if err != nil {
		return nil, err
	}
	file, ok := opened.(*os.File)
	if !ok {
		opened.Close()
		return fs.ReadDir(f.base, name)
	}
	defer file.Close()
	entries, err := f.cache.ReadDir(name, file, -1)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, err
}
