package sourceinspect

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"vulns-news/src/traversal"
)

func TestInspectTraversalDifferential(t *testing.T) {
	for _, scenario := range []string{"nested", "parse error", "file limit", "byte limit", "depth limit"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"main.go", "a/a.go", "a/deep/b.go", "b/c.go", "vendor/d.go"} {
				put(t, root, name, "package sample\nimport \"fmt\"\nfunc f() { fmt.Println(\"hello\") }\n")
			}
			// Cross the enumeration batch boundary without consuming the file budget.
			for n := 0; n < 130; n++ {
				put(t, root, fmt.Sprintf("ignored-%03d.txt", n), "ignored")
			}
			switch scenario {
			case "parse error":
				put(t, root, "a/bad.go", "package invalid\nfunc")
			case "file limit":
				for n := 0; n < MaxFiles; n++ {
					put(t, root, fmt.Sprintf("files/f%03d.go", n), "package sample\n")
				}
			case "byte limit":
				put(t, root, "large.go", strings.Repeat(" ", MaxFileBytes+1))
			case "depth limit":
				put(t, root, strings.Repeat("deep/", MaxDepth+1)+"f.go", "package sample\n")
			}
			want, wantErr := Inspect(root)
			cache := traversal.New()
			for pass, candidate := range []*traversal.Cache{nil, cache, cache} {
				got, err := InspectWithTraversal(root, candidate)
				if !reflect.DeepEqual(got, want) || fmt.Sprint(err) != fmt.Sprint(wantErr) || errors.Is(err, ErrLimit) != errors.Is(wantErr, ErrLimit) {
					t.Fatalf("pass %d: got %+v, %v; want %+v, %v", pass, got, err, want, wantErr)
				}
			}
			if cache.Stats().CacheHits == 0 {
				t.Fatal("repeated inspection did not reuse enumeration")
			}
			if scenario == "nested" {
				before := cache.Stats()
				if _, err := InspectWithTraversal(root, cache); err != nil {
					t.Fatal(err)
				}
				if cache.Stats().DirectoryReads != before.DirectoryReads {
					t.Fatal("warm inspection reread a directory")
				}
			}
		})
	}
}
