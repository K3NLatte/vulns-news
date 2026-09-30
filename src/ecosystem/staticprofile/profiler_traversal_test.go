package staticprofile

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vulns-news/src/traversal"
)

func TestProfileWithTraversal(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"nested", "vendor"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string]string{
		"go.mod":                  "module example.com/app\n\ngo 1.24\nrequire example.com/lib v1.2.3\n",
		"nested/requirements.txt": "requests==2.32.0\n",
		"vendor/requirements.txt": "ignored==1.0\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	cache := traversal.New()
	for _, c := range []*traversal.Cache{nil, cache, cache} {
		got, err := ProfileWithTraversal(root, c)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, %v; want %#v", got, err, want)
		}
	}
	if cache.Stats().CacheHits == 0 {
		t.Fatal("warm traversal did not reuse cache")
	}
	limits := DefaultLimits()
	limits.MaxFiles = 1
	p, err := NewProfiler(limits)
	if err != nil {
		t.Fatal(err)
	}
	want, wantErr := p.Profile(root)
	got, gotErr := p.profile(root, cache)
	if wantErr == nil || gotErr == nil || wantErr.Error() != gotErr.Error() || !reflect.DeepEqual(got, want) {
		t.Fatalf("custom limits: got %#v, %v; want %#v, %v", got, gotErr, want, wantErr)
	}
}
