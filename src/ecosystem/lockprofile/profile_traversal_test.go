package lockprofile

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
		"composer.lock":        `{"packages":[{"name":"example/lib","version":"1.2.3"}]}`,
		"nested/composer.lock": `{"packages":[{"name":"example/other","version":"2.0.0"}]}`,
		"vendor/composer.lock": "invalid ignored input",
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
	// Directory caching must not cache file contents or hide parse errors.
	if err := os.WriteFile(filepath.Join(root, "composer.lock"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	want, wantErr := Profile(root)
	got, gotErr := ProfileWithTraversal(root, cache)
	if wantErr == nil || gotErr == nil || wantErr.Error() != gotErr.Error() || !reflect.DeepEqual(got, want) {
		t.Fatalf("parse error: got %#v, %v; want %#v, %v", got, gotErr, want, wantErr)
	}
}
