package sourceinspect

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func put(t *testing.T, root, name, data string) {
	t.Helper()
	name = filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func inspectOK(t *testing.T, root string) Report {
	t.Helper()
	r, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Complete || len(r.Limitations) == 0 {
		t.Fatalf("missing completeness/limitations: %+v", r)
	}
	return r
}

func ofKind(r Report, kind Kind) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

func TestAliasesCommentsAndPhysicalLocations(t *testing.T) {
	root := t.TempDir()
	put(t, root, "sub/main.go", `package sample
import h "net/http"
import dep "example.org/library/v2"
import _ "example.org/sideeffect"
// h.HandleFunc("/fake", nil); dep.Fake()
var text = "h.HandleFunc('/fake', nil)"
//line invented.go:900
func unused() {
 h.HandleFunc("GET /real", nil)
 dep.Run[int]()
 h.HandleFunc(text, nil)
}
`)
	r := inspectOK(t, root)
	if r.FilesInspected != 1 || len(ofKind(r, Import)) != 3 {
		t.Fatalf("unexpected report: %+v", r)
	}
	want := []Finding{
		{Kind: ImportedSelectorCall, File: "sub/main.go", Line: 9, EndLine: 9, Package: "net/http", Symbol: "HandleFunc"},
		{Kind: ImportedSelectorCall, File: "sub/main.go", Line: 10, EndLine: 10, Package: "example.org/library/v2", Symbol: "Run"},
		{Kind: ImportedSelectorCall, File: "sub/main.go", Line: 11, EndLine: 11, Package: "net/http", Symbol: "HandleFunc"},
	}
	if got := ofKind(r, ImportedSelectorCall); !reflect.DeepEqual(got, want) {
		t.Fatalf("calls = %+v; want %+v", got, want)
	}
	routes := ofKind(r, HTTPRouteRegistration)
	if len(routes) != 1 || routes[0].Route != "GET /real" || routes[0].Line != 9 {
		t.Fatalf("routes = %+v", routes)
	}
	if again := inspectOK(t, root); !reflect.DeepEqual(r, again) {
		t.Fatal("unstable report")
	}
}

func TestLexicalShadowing(t *testing.T) {
	cases := []struct {
		name, code string
		calls      int
	}{
		{"parameter", `func f(http T) { http.Get() }`, 0},
		{"named result", `func f() (http T) { http.Get(); return }`, 0},
		{"receiver", `type T int; func (http T) f() { http.Get() }`, 0},
		{"local", `func f() { http := value; http.Get() }`, 0},
		{"var", `func f() { var http T; http.Get() }`, 0},
		{"const", `func f() { const http = 1; http.Get() }`, 0},
		{"type", `func f() { type http int; http.Get() }`, 0},
		{"range", `func f() { for _, http := range values { http.Get() }; http.Get() }`, 1},
		{"if", `func f() { if http := value; true { http.Get() } else { http.Get() }; http.Get() }`, 1},
		{"for", `func f() { for http := value; true; http.Next() { http.Get() }; http.Get() }`, 1},
		{"switch", `func f() { switch http := value; http { default: http.Get() }; http.Get() }`, 1},
		{"type switch", `func f() { switch http := value.(type) { case T: http.Get() }; http.Get() }`, 1},
		{"select", `func f() { select { case http := <-ch: http.Get(); default: http.Get() } }`, 1},
		{"closure", `func f() { http := value; _ = func() { http.Get() } }`, 0},
		{"closure parameter", `func f() { _ = func(http T) { http.Get() }; http.Get() }`, 1},
		{"type parameter", `func f[http any]() { http.Get() }`, 0},
		{"before declaration and after block", `func f() { http.Get(); { http := value; http.Get() }; http.Get() }`, 2},
		{"short declaration RHS", `func f() { http := http.Get(); http.Get() }`, 1},
		{"var declaration RHS", `func f() { var http = http.Get(); http.Get() }`, 1},
		{"package declaration", `var http T; func f() { http.Get() }`, 0},
		{"function alias", `func f() { get := http.Get; get() }`, 0},
		{"method", `func f() { mux.HandleFunc("/", nil) }`, 0},
		{"parenthesized", `func f() { (http.Get)() }`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			put(t, root, "main.go", "package p\nimport \"net/http\"\n"+tc.code)
			r := inspectOK(t, root)
			if got := ofKind(r, ImportedSelectorCall); len(got) != tc.calls {
				t.Fatalf("calls = %+v; want %d", got, tc.calls)
			}
		})
	}
}

func TestConservativeResolution(t *testing.T) {
	for _, tc := range []struct {
		name, imports, extra string
		calls                int
	}{
		{"unknown default name", `import "example.org/http"`, "", 0},
		{"known default name", `import "net/http"`, "", 1},
		{"explicit dependency alias", `import http "example.org/other/v2"`, "", 1},
		{"dot import", "import \"net/http\"\nimport . \"example.org/other\"", "", 0},
		{"duplicate alias", "import http \"net/http\"\nimport http \"example.org/other\"", "", 0},
		{"cross file shadow", `import "net/http"`, "package p\nvar http T", 0},
		{"different package", `import "net/http"`, "package p_test\nvar http T", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			put(t, root, "main.go", "package p\n"+tc.imports+"\nfunc f() { http.Get() }")
			if tc.extra != "" {
				put(t, root, "extra.go", tc.extra)
			}
			r := inspectOK(t, root)
			if got := ofKind(r, ImportedSelectorCall); len(got) != tc.calls {
				t.Fatalf("calls = %+v; want %d", got, tc.calls)
			}
		})
	}
}

func TestSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	put(t, root, "real.go", "package p\nimport \"net/http\"\nfunc f() { http.Get() }")
	put(t, outside, "bad.go", "not valid Go")
	for name, target := range map[string]string{
		"outside.go":  filepath.Join(outside, "bad.go"),
		"outside":     outside,
		"inside.go":   filepath.Join(root, "real.go"),
		"loop":        root,
		"dangling.go": filepath.Join(outside, "missing.go"),
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	r := inspectOK(t, root)
	if r.FilesInspected != 1 || r.SymlinksSkipped != 5 {
		t.Fatalf("report = %+v", r)
	}
	link := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{link, link + string(os.PathSeparator)} {
		if r, err := Inspect(name); err == nil || r.Complete {
			t.Fatal("accepted symlink root")
		}
	}
}

func TestRouteSyntax(t *testing.T) {
	root := t.TempDir()
	put(t, root, "routes.go", `package p
import h "net/http"
import other "example.org/http"
func f() {
 h.HandleFunc(
  "/multi",
  nil,
 )
 h.HandleFunc("", nil)
 h.HandleFunc("/" + "computed", nil)
 h.HandleFunc(pattern, nil)
 h.HandleFunc(args...)
 h.HandleFunc("/wrong-arity")
 other.HandleFunc("/not-net-http", nil)
 mux.HandleFunc("/method", nil)
 { h := mux; h.HandleFunc("/shadow", nil) }
}
`)
	routes := ofKind(inspectOK(t, root), HTTPRouteRegistration)
	if len(routes) != 2 || routes[0].Route != "/multi" || routes[0].Line != 5 || routes[0].EndLine != 8 || routes[1].Route != "" {
		t.Fatalf("routes = %+v", routes)
	}
}

func TestErrors(t *testing.T) {
	root := t.TempDir()
	put(t, root, "bad.go", "package p\nfunc {")
	for _, name := range []string{root, filepath.Join(root, "missing"), filepath.Join(root, "bad.go")} {
		r, err := Inspect(name)
		if err == nil || r.Complete {
			t.Fatalf("Inspect(%q) = %+v, %v", name, r, err)
		}
		if len(r.Limitations) == 0 {
			t.Fatal("error report lacks limitations")
		}
	}
}

func TestResourceBounds(t *testing.T) {
	for _, name := range []string{"file bytes", "total bytes", "files", "entries", "depth", "findings"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			switch name {
			case "file bytes":
				put(t, root, "big.go", strings.Repeat(" ", MaxFileBytes+1))
			case "total bytes":
				data := "package p\n" + strings.Repeat(" ", MaxFileBytes-len("package p\n"))
				for n := 0; n <= MaxTotalBytes/MaxFileBytes; n++ {
					put(t, root, fmt.Sprintf("%03d.go", n), data)
				}
			case "files":
				for n := 0; n <= MaxFiles; n++ {
					put(t, root, fmt.Sprintf("%03d.go", n), "package p")
				}
			case "entries":
				for n := 0; n <= MaxEntries; n++ {
					put(t, root, fmt.Sprintf("%05d.txt", n), "")
				}
			case "depth":
				put(t, root, strings.Repeat("d/", MaxDepth+1)+"a.go", "package p")
			case "findings":
				put(t, root, "many.go", "package p\nimport \"net/http\"\nfunc f() {\n"+strings.Repeat("http.Get()\n", MaxFindings)+"}")
			}
			r, err := Inspect(root)
			if !errors.Is(err, ErrLimit) || r.Complete {
				t.Fatalf("report = %+v; error = %v", r, err)
			}
			if len(r.Findings) > MaxFindings || r.FilesInspected > MaxFiles || r.BytesRead > MaxTotalBytes+1 {
				t.Fatal("budget overrun")
			}
		})
	}
}

func TestExactFileByteBudgetAndEmptyRoot(t *testing.T) {
	root := t.TempDir()
	if r := inspectOK(t, root); r.FilesInspected != 0 || len(r.Findings) != 0 {
		t.Fatalf("empty report = %+v", r)
	}
	data := "package p\n" + strings.Repeat(" ", MaxFileBytes-len("package p\n"))
	put(t, root, "exact.go", data)
	put(t, root, "ignored.txt", "not Go")
	if r := inspectOK(t, root); r.BytesRead != MaxFileBytes || r.FilesInspected != 1 {
		t.Fatalf("report = %+v", r)
	}
}
