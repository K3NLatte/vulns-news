package manifestextra

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T, root, name, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestManifests(t *testing.T) {
	root := t.TempDir()
	fixture(t, root, "python/pyproject.toml", `[project]
name = "not-a-dependency"
dependencies = ["Requests[security]==2.32.3; python_version >= '3.9'", "urllib3>=2,<3", "typing_extensions", "local @ file:///tmp/local"]
[project.optional-dependencies]
test = ["pytest==8.3.2"]
[tool.poetry.dependencies]
python = "^3.11"
Rich = "13.9.4"
httpx = {version = "^0.27", extras = ["http2"]}
internal = {path = "../internal"}
[tool.poetry.group.dev.dependencies]
ruff = "==0.6.9"
`)
	fixture(t, root, "rust/Cargo.toml", `[package]
name = "app"
version = "0.1.0"
[dependencies]
serde = {version = "=1.0.210", features = ["derive"]}
json = {package = "serde_json", version = "1.0"}
local = {path = "../local"}
shared = {workspace = true}
remote = {git = "https://example.com/repo"}
secret = {version = "=1.0.0", registry = "internal"}
[build-dependencies]
cc = "=1.1.20"
[target.'cfg(unix)'.dev-dependencies]
libc = "0.2"
`)
	fixture(t, root, "requirements.txt", "ignored==1.0\n-r other.txt")
	a, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("nondeterministic output")
	}
	want := map[string]string{"requests": "2.32.3", "urllib3": "", "typing-extensions": "", "pytest": "8.3.2", "rich": "13.9.4", "httpx": "", "ruff": "0.6.9", "serde": "1.0.210", "serde_json": "", "cc": "1.1.20", "libc": ""}
	if len(a.Components) != len(want) {
		t.Fatalf("components: %+v", a.Components)
	}
	ids := map[string]bool{}
	for _, c := range a.Components {
		v, ok := want[c.Name]
		if !ok || c.Version != v {
			t.Fatalf("unexpected component %+v", c)
		}
		if !c.Direct || c.SourcePath == "" || len(c.ID) != 64 || ids[c.ID] {
			t.Fatalf("invalid metadata %+v", c)
		}
		ids[c.ID] = true
		if v == "" && strings.Contains(c.PURL, "@") {
			t.Fatalf("range has versioned PURL: %s", c.PURL)
		}
	}
	if len(a.Ecosystems) != 2 || len(a.Warnings) < 5 {
		t.Fatalf("missing evidence: %+v", a)
	}
}
func TestPDMPublicProvenance(t *testing.T) {
	root := t.TempDir()
	fixture(t, root, "pdm.lock", `[metadata]
lock_version = "4.5"
[[package]]
name = "Requests"
version = "2.32.3"
files = [{url = "https://files.pythonhosted.org/packages/ab/cd/requests-2.32.3-py3-none-any.whl", hash = "sha256:abc"}]
[[package]]
name = "unknown"
version = "1.0"
files = [{file = "unknown-1.0.whl", hash = "sha256:abc"}]
[[package]]
name = "private"
version = "1.0"
index = "https://private.example/simple"
[[package]]
name = "conflict"
version = "1.0"
source = {url = "https://private.example/simple"}
files = [{url = "https://files.pythonhosted.org/packages/a/b.whl"}]
[[package]]
name = "idna"
version = "3.10"
index = "https://pypi.org/simple"
[[package]]
name = "conflicting-artifact"
version = "1.0"
index = "https://pypi.org/simple"
files = [{url = "https://private.example/package.whl"}]
`)
	f, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Components) != 2 || len(f.Warnings) != 4 {
		t.Fatalf("unexpected inventory: %+v", f)
	}
	for _, c := range f.Components {
		if c.Direct || c.Version == "" || c.Ecosystem != "PyPI" {
			t.Fatalf("invalid lock component %+v", c)
		}
	}
	if len(f.Ecosystems) != 1 || !reflect.DeepEqual(f.Ecosystems[0].Lockfiles, []string{"pdm.lock"}) {
		t.Fatal(f.Ecosystems)
	}
}
func TestSourceConfiguration(t *testing.T) {
	root := t.TempDir()
	fixture(t, root, "pyproject.toml", `[project]
dependencies = ["internal==1.0"]
[[tool.pdm.source]]
name = "private"
url = "https://internal.example/simple"
`)
	fixture(t, root, "Cargo.toml", "[dependencies]\ninternal = \"=1.0.0\"\n")
	fixture(t, root, ".cargo/config.toml", "[source.crates-io]\nreplace-with = \"private\"\n")
	f, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Components) != 0 || len(f.Warnings) < 2 {
		t.Fatalf("private packages leaked: %+v", f)
	}
}
func TestErrorsAreAtomic(t *testing.T) {
	cases := []struct{ name, body string }{
		{"pyproject.toml", "[project\n"},
		{"pyproject.toml", "[project]\ndependencies = 42"},
		{"pyproject.toml", "[project]\ndependencies = [42]"},
		{"pyproject.toml", "project = 42"},
		{"Cargo.toml", "[dependencies]\nserde = false"},
		{"Cargo.toml", "dependencies = []"},
		{"Cargo.toml", "[patch.crates-io]\nserde = {path = '../serde'}"},
		{"pdm.lock", "[metadata]\nlock_version = '99.0'"},
		{"pdm.lock", "package = 42\n[metadata]\nlock_version = '4.5'"},
		{"pdm.lock", "[[package]]\nname = 'bad'\nversion = '*'\n[metadata]\nlock_version = '4.5'"},
	}
	for _, tc := range cases {
		t.Run(tc.name+tc.body, func(t *testing.T) {
			root := t.TempDir()
			fixture(t, root, "a/Cargo.toml", "[dependencies]\nserde = '=1.0.0'")
			fixture(t, root, tc.name, tc.body)
			f, err := Profile(root)
			if err == nil || !reflect.DeepEqual(f, Fragment{}) {
				t.Fatalf("expected atomic error, got %+v, %v", f, err)
			}
		})
	}
	for _, root := range []string{"", filepath.Join(t.TempDir(), "missing")} {
		if _, err := Profile(root); err == nil {
			t.Fatal("expected root error")
		}
	}
	root := t.TempDir()
	fixture(t, root, "file", "")
	if _, err := Profile(filepath.Join(root, "file")); err == nil {
		t.Fatal("accepted file root")
	}
}
func TestBounds(t *testing.T) {
	t.Run("bytes", func(t *testing.T) {
		root := t.TempDir()
		fixture(t, root, "pyproject.toml", strings.Repeat(" ", maxFileBytes+1))
		if _, err := Profile(root); err == nil {
			t.Fatal("expected byte limit")
		}
	})
	t.Run("depth", func(t *testing.T) {
		root := t.TempDir()
		fixture(t, root, strings.Repeat("d/", maxDepth+1)+"Cargo.toml", "")
		if _, err := Profile(root); err == nil {
			t.Fatal("expected depth limit")
		}
	})
	t.Run("total bytes", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i < 9; i++ {
			fixture(t, root, strings.Repeat("d/", i)+"Cargo.toml", strings.Repeat(" ", maxFileBytes))
		}
		if _, err := Profile(root); err == nil {
			t.Fatal("expected total byte limit")
		}
	})
}
func TestSymlinksAndIgnoredDirectories(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	fixture(t, outside, "Cargo.toml", "invalid toml [")
	if err := os.Symlink(filepath.Join(outside, "Cargo.toml"), filepath.Join(root, "Cargo.toml")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	fixture(t, root, "target/Cargo.toml", "invalid toml [")
	f, err := Profile(root)
	if err != nil || len(f.Components) != 0 || len(f.Warnings) != 2 {
		t.Fatalf("unexpected result %+v %v", f, err)
	}
	if _, err := Profile(filepath.Join(root, "linked")); err == nil {
		t.Fatal("accepted symlink root")
	}
}
func TestIdentityAndPins(t *testing.T) {
	root := t.TempDir()
	fixture(t, root, "pyproject.toml", `[project]
dependencies = ["Foo_Bar==1.2", "foo.bar==1.2", "wild==1.*", "compatible~=1.2", "multi==1.2,!=1.2.1"]
`)
	f, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Components) != 4 {
		t.Fatalf("normalization/dedup failed: %+v", f)
	}
	for _, c := range f.Components {
		if c.Name == "foo-bar" {
			if c.PURL != "pkg:pypi/foo-bar@1.2" {
				t.Fatal(c)
			}
		} else if c.Version != "" {
			t.Fatal(c)
		}
	}
	for _, v := range []string{"1.0", "01.0.0", "1.0.0-01", "^1.0.0"} {
		if exactCargo(v) {
			t.Fatalf("accepted %s", v)
		}
	}
}
