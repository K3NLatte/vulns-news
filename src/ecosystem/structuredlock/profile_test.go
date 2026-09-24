package structuredlock

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func put(t *testing.T, root, name, body string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestRegistrySources(t *testing.T) {
	cases := []struct {
		name, body, purl string
		warnings         int
	}{
		{"pnpm-lock.yaml", `lockfileVersion: '9.0'
packages:
  '@scope/pkg@1.2.3(peer@4.5.6)':
    resolution: {integrity: sha512-example}
  'local@file:../local':
    resolution: {directory: ../local, type: directory}
  'remote@git+https://example.org/repo':
    resolution: {repo: https://example.org/repo, type: git}
`, "pkg:npm/%40scope/pkg@1.2.3", 2},
		{"pnpm-lock.yaml", `lockfileVersion: 6.0
packages:
  /@scope/pkg@1.2.3(peer@4.5.6):
    resolution: {integrity: sha512-example}
`, "pkg:npm/%40scope/pkg@1.2.3", 0},
		{"Cargo.lock", `version = 3
[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "local"
version = "1.0.0"
[[package]]
name = "git"
version = "1.0.0"
source = "git+https://example.org/repo"
`, "pkg:cargo/serde@1.0.200", 2},
		{"poetry.lock", `[metadata]
lock-version = "2.0"
[[package]]
name = "Requests_Test.pkg"
version = "2.31.0"
[[package]]
name = "local"
version = "1.0"
source = {type = "directory", url = "../local"}
[[package]]
name = "git"
version = "1.0"
source = {type = "git", url = "https://example.org/repo"}
`, "pkg:pypi/requests-test-pkg@2.31.0", 2},
		{"uv.lock", `version = 1
[[package]]
name = "Requests_Test.pkg"
version = "2.31.0"
source = {registry = "https://pypi.org/simple"}
[[package]]
name = "local"
version = "1.0"
source = {editable = "."}
[[package]]
name = "git"
version = "1.0"
source = {git = "https://example.org/repo"}
`, "pkg:pypi/requests-test-pkg@2.31.0", 2},
		{"yarn.lock", `__metadata:
  version: 8
"@scope/pkg@npm:^1.0.0":
  version: 1.2.3
  resolution: "@scope/pkg@npm:1.2.3"
"local@workspace:.":
  version: 0.0.0-use.local
  resolution: "local@workspace:."
"git@https://example.org/repo":
  version: 1.0.0
  resolution: "git@https://example.org/repo#commit=123"
`, "pkg:npm/%40scope/pkg@1.2.3", 2},
		{"yarn.lock", `# yarn lockfile v1
"@scope/pkg@^1.0.0", "@scope/pkg@~1.2.0":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.2.3.tgz#abc"
  integrity sha512-example
  dependencies:
    other "^2.0.0"
"local@file:../local":
  version "1.0.0"
"git@git+https://example.org/repo":
  version "1.0.0"
  resolved "https://example.org/repo#123"
`, "pkg:npm/%40scope/pkg@1.2.3", 2},
	}
	for _, tt := range cases {
		t.Run(tt.name+tt.purl, func(t *testing.T) {
			root := t.TempDir()
			put(t, root, tt.name, tt.body)
			got, err := Profile(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Components) != 1 || got.Components[0].PURL != tt.purl {
				t.Fatalf("components: %+v", got.Components)
			}
			if len(got.Warnings) != tt.warnings {
				t.Fatalf("warnings: %v", got.Warnings)
			}
			if len(got.Ecosystems) != 1 || got.Ecosystems[0].Lockfiles[0] != tt.name {
				t.Fatalf("ecosystems: %+v", got.Ecosystems)
			}
			again, err := Profile(root)
			if err != nil || !reflect.DeepEqual(got, again) {
				t.Fatal("non-deterministic profile", err)
			}
		})
	}
}
func TestMalformed(t *testing.T) {
	for _, tt := range []struct{ name, body string }{
		{"Cargo.lock", "version = ["}, {"uv.lock", "version = 1\n[[package]]\nname = 12"}, {"poetry.lock", "not a lock"},
		{"pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: ["},
		{"pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: {}\n---\npackages: {}"},
		{"pnpm-lock.yaml", "lockfileVersion: '5.4'"},
		{"pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: {}\npackages: {}"},
		{"yarn.lock", "__metadata: ["}, {"yarn.lock", "garbage"},
		{"yarn.lock", "# yarn lockfile v1\n\"\":\n  version \"1.0.0\""},
		{"yarn.lock", "# yarn lockfile v1\npkg@^1:\n  version \"unterminated"},
	} {
		t.Run(tt.name+tt.body, func(t *testing.T) {
			root := t.TempDir()
			put(t, root, "a/Cargo.lock", "version = 3\n[[package]]\nname = 'ok'\nversion = '1.0.0'\nsource = 'registry+https://github.com/rust-lang/crates.io-index'")
			put(t, root, tt.name, tt.body)
			got, err := Profile(root)
			if err == nil {
				t.Fatalf("accepted malformed input: %+v", got)
			}
			if !reflect.DeepEqual(got, Fragment{}) {
				t.Fatalf("partial results: %+v", got)
			}
		})
	}
}
func TestLimits(t *testing.T) {
	if _, err := NewProfiler(Limits{}); err == nil {
		t.Fatal("zero limits accepted")
	}
	for _, kind := range []string{"size", "files", "depth", "components"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			l := DefaultLimits()
			switch kind {
			case "size":
				l.MaxFileSize = 10
				put(t, root, "Cargo.lock", strings.Repeat("x", 11))
			case "files":
				l.MaxFiles = 1
				put(t, root, "a", "")
				put(t, root, "b", "")
			case "depth":
				l.MaxDepth = 1
				put(t, root, "a/b/Cargo.lock", "version = 3")
			case "components":
				l.MaxComponents = 1
				put(t, root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n  b@1.0.0:\n    resolution: {integrity: sha512-y}")
			}
			p, err := NewProfiler(l)
			if err != nil {
				t.Fatal(err)
			}
			got, err := p.Profile(root)
			if err == nil || !reflect.DeepEqual(got, Fragment{}) {
				t.Fatalf("limit not enforced: %+v, %v", got, err)
			}
		})
	}
}
func TestSymlinksAndPruning(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	put(t, outside, "Cargo.lock", "broken")
	if err := os.Symlink(filepath.Join(outside, "Cargo.lock"), filepath.Join(root, "Cargo.lock")); err != nil {
		t.Skip(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	put(t, root, "node_modules/pkg/yarn.lock", "broken")
	got, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Components) != 0 || len(got.Warnings) != 2 {
		t.Fatalf("%+v", got)
	}
	if _, err := Profile(filepath.Join(root, "linked")); err == nil {
		t.Fatal("symlink root accepted")
	}
}
func TestUnknownSourcesAndVersions(t *testing.T) {
	root := t.TempDir()
	put(t, root, "pnpm-lock.yaml", `lockfileVersion: '9.0'
packages:
  a@1.2.3:
    resolution: {tarball: 'https://evil.test/a.tgz'}
  b@workspace:1.0.0:
    resolution: {integrity: sha512-x}
  c@^1.0.0:
    resolution: {integrity: sha512-x}
  d@1.0.0:
    resolution: {}
`)
	got, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Components) != 0 || len(got.Warnings) != 4 {
		t.Fatalf("%+v", got)
	}
}
