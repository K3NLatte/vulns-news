package nativeprofile

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func put(t *testing.T, root, file, data string) {
	t.Helper()
	name := filepath.Join(root, filepath.FromSlash(file))
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

const conanFixture = `{"version":"0.5","requires":["zlib/1.3.1#abcdef%1710000000.1","fmt/10.2.1@user/stable#123abc","zlib/1.3.1#abcdef%1710000000.1"],"build_requires":["cmake/3.29.0#1234"],"python_requires":["helpers/1.0#5678"]}`
const vcpkgFixture = `{"name":"application","version-string":"9.0","dependencies":["zlib",{"name":"fmt","version>=":"10.0","host":true},{"name":"zlib","features":["tools"]}],"features":{"optional":{"description":"Optional","dependencies":[{"name":"openssl","version>=":"3.0"}]}},"overrides":[{"name":"fmt","version":"10.1"}]}`
const podsFixture = `PODS:
  - Public/Core (1.2.3):
    - Other (~> 2.0)
  - Other (2.1.0)
  - GitPod/Sub (3.0)
  - CheckedOut (4.0)
  - Private (5.0)
  - Unknown (6.0)
SPEC REPOS:
  trunk:
    - Public
    - GitPod
    - CheckedOut
  https://github.com/CocoaPods/Specs.git:
    - Other
  https://private.example/specs:
    - Private
EXTERNAL SOURCES:
  GitPod:
    :git: https://example.com/gitpod
CHECKOUT OPTIONS:
  CheckedOut:
    :commit: abcdef
`
const juliaFixture = `julia_version = "1.10.0"
manifest_format = "2.0"
[[deps.Example]]
uuid = "7876AF07-990D-54B4-AB0E-23690620F79A"
version = "0.5.4"
git-tree-sha1 = "abcdef"
[[deps.Local]]
uuid = "7876af07-990d-54b4-ab0e-23690620f79a"
version = "1.0.0"
path = "../../outside"
[[deps.Remote]]
uuid = "7876af07-990d-54b4-ab0e-23690620f79a"
version = "1.0.0"
repo-url = "https://example.com/package.git"
[[deps.Stdlib]]
uuid = "7876af07-990d-54b4-ab0e-23690620f79a"
`

func TestInventory(t *testing.T) {
	root := t.TempDir()
	fixtures := map[string]string{"native/conan.lock": conanFixture, "native/vcpkg.json": vcpkgFixture, "ios/Podfile.lock": podsFixture, "science/Manifest.toml": juliaFixture}
	for file, data := range fixtures {
		put(t, root, file, data)
	}
	f, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Components) != 10 {
		t.Fatalf("components: %+v", f.Components)
	}
	seen := map[string]bool{}
	for _, c := range f.Components {
		if c.ID == "" || seen[c.ID] {
			t.Fatalf("missing/duplicate ID: %+v", c)
		}
		seen[c.ID] = true
		if _, ok := fixtures[c.SourcePath]; !ok {
			t.Fatalf("wrong source: %+v", c)
		}
		if strings.Contains(c.PURL, "@") {
			t.Fatalf("PURL must be versionless: %+v", c)
		}
		switch c.Ecosystem {
		case "Conan":
			if c.Version == "" || !strings.Contains(c.Scope, "#") {
				t.Fatalf("lost pinned reference: %+v", c)
			}
		case "vcpkg":
			if c.Version != "" || !strings.HasPrefix(c.PURL, "pkg:generic/vcpkg/") {
				t.Fatalf("invented vcpkg pin: %+v", c)
			}
		case "CocoaPods":
			if c.Name != "Public/Core" && c.Name != "Other" {
				t.Fatalf("nonpublic pod: %+v", c)
			}
		case "Julia":
			if c.Name != "Example" || c.Version != "0.5.4" || c.PURL != "pkg:generic/julia/Example?uuid=7876af07-990d-54b4-ab0e-23690620f79a" {
				t.Fatalf("Julia identity: %+v", c)
			}
		default:
			t.Fatalf("unexpected ecosystem: %+v", c)
		}
	}
	if len(f.Ecosystems) != 4 {
		t.Fatalf("usages: %+v", f.Ecosystems)
	}
	for _, e := range f.Ecosystems {
		if e.Name == "vcpkg" {
			if !reflect.DeepEqual(e.Manifests, []string{"native/vcpkg.json"}) || len(e.Lockfiles) != 0 {
				t.Fatal(e)
			}
		} else if len(e.Lockfiles) != 1 || len(e.Manifests) != 0 {
			t.Fatal(e)
		}
	}
	warnings := strings.Join(f.Warnings, "\n")
	for _, text := range []string{"source identities", "OSV", "unknown resolved version", "GitPod/Sub", "CheckedOut", "Private", "Unknown", "Local", "Remote", "Stdlib"} {
		if !strings.Contains(warnings, text) {
			t.Errorf("missing warning %q in %s", text, warnings)
		}
	}
	again, err := Profile(root)
	if err != nil || !reflect.DeepEqual(f, again) {
		t.Fatalf("nondeterminism: %v", err)
	}
}

func TestConanLegacyAndDistinctReferences(t *testing.T) {
	root := t.TempDir()
	put(t, root, "conan.lock", `{"version":"0.4","graph_lock":{"nodes":{"0":{"path":"."},"1":{"ref":"zlib/1.2.3@one/stable#abc"},"2":{"ref":"zlib/1.2.3@two/stable#def"},"3":{"ref":"zlib/[>=1.0]"},"4":{"ref":"bare"}}}}`)
	f, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Components) != 2 || f.Components[0].ID == f.Components[1].ID {
		t.Fatalf("references collapsed: %+v", f)
	}
	for _, c := range f.Components {
		if c.Version != "1.2.3" || c.Name != "zlib" {
			t.Fatal(c)
		}
	}
	if len(f.Warnings) != 4 {
		t.Fatalf("warnings: %v", f.Warnings)
	}
}
func TestJuliaLegacyUUIDIdentity(t *testing.T) {
	root := t.TempDir()
	put(t, root, "Manifest.toml", `[[Example]]
uuid = "7876af07-990d-54b4-ab0e-23690620f79a"
version = "0.5.4"
[[Example]]
uuid = "7876af07-990d-54b4-ab0e-23690620f79b"
version = "0.5.4"
`)
	f, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Components) != 2 || f.Components[0].PURL == f.Components[1].PURL {
		t.Fatalf("UUIDs collapsed: %+v", f)
	}
}
func TestUnknownSchemasWarn(t *testing.T) {
	for file, data := range map[string]string{"conan.lock": `{"version":"99","requires":["zlib/1.0#abc"]}`, "vcpkg.json": `{"unrecognized":[]}`, "Podfile.lock": "UNKNOWN: []\n", "Manifest.toml": "manifest_format = \"99.0\"\n"} {
		t.Run(file, func(t *testing.T) {
			root := t.TempDir()
			put(t, root, file, data)
			f, err := Profile(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(f.Components) != 0 || len(f.Warnings) == 0 {
				t.Fatalf("unknown schema: %+v", f)
			}
		})
	}
}
func TestMalformedIsAtomic(t *testing.T) {
	cases := []struct{ file, data string }{
		{"conan.lock", `{"version":`},
		{"conan.lock", `{"version":"0.5","requires":[42]}`},
		{"conan.lock", `{"version":"0.5","requires":{}}`},
		{"vcpkg.json", `[]`},
		{"vcpkg.json", `null`},
		{"vcpkg.json", `{"dependencies":[{"name":42}]}`},
		{"vcpkg.json", `{"dependencies":["../escape"]}`},
		{"vcpkg.json", `{"dependencies":[]} {}`},
		{"Podfile.lock", "PODS: [\n"},
		{"Podfile.lock", "PODS: []\n---\nPODS: []\n"},
		{"Podfile.lock", "PODS: []\nPODS: []\n"},
		{"Podfile.lock", "PODS: [Pod (~> 1.0)]\n"},
		{"Podfile.lock", "PODS: [42]\n"},
		{"Manifest.toml", "[[deps.Bad]\n"},
		{"Manifest.toml", "[[Bad]]\nuuid='invalid'\nversion='1.0'\n"},
	}
	for i, c := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			root := t.TempDir()
			put(t, root, "good/vcpkg.json", vcpkgFixture)
			put(t, root, c.file, c.data)
			f, err := Profile(root)
			if err == nil || !reflect.DeepEqual(f, Fragment{}) {
				t.Fatalf("want atomic error, got %+v, %v", f, err)
			}
			if !strings.Contains(err.Error(), c.file) {
				t.Fatalf("missing error path: %v", err)
			}
		})
	}
}
func TestPodProvenanceIsConservative(t *testing.T) {
	for _, repo := range []string{"", "https://cdn.cocoapods.org.evil/", "https://user@cdn.cocoapods.org/", "https://private.example/specs"} {
		t.Run(repo, func(t *testing.T) {
			root := t.TempDir()
			data := "PODS:\n  - Foo/Core (1.0)\n"
			if repo != "" {
				data += "SPEC REPOS:\n  " + repo + ":\n    - Foo\n"
			}
			put(t, root, "Podfile.lock", data)
			f, err := Profile(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(f.Components) != 0 || len(f.Warnings) == 0 {
				t.Fatalf("unproven source: %+v", f)
			}
		})
	}
	root := t.TempDir()
	put(t, root, "Podfile.lock", "PODS:\n  - Foo (1.0)\nSPEC REPOS:\n  trunk: [Foo]\n  https://private.example/specs: [Foo]\n")
	f, err := Profile(root)
	if err != nil || len(f.Components) != 0 {
		t.Fatalf("conflicting provenance: %+v %v", f, err)
	}
}
func TestPathsParticipateInIdentity(t *testing.T) {
	root := t.TempDir()
	put(t, root, "a/vcpkg.json", `{"dependencies":["zlib"]}`)
	put(t, root, "b/vcpkg.json", `{"dependencies":["zlib"]}`)
	f, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Components) != 2 || f.Components[0].ID == f.Components[1].ID {
		t.Fatal(f)
	}
	if !reflect.DeepEqual(f.Ecosystems[0].Manifests, []string{"a/vcpkg.json", "b/vcpkg.json"}) {
		t.Fatal(f.Ecosystems)
	}
}
func TestSymlinksAndIgnoredSources(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	put(t, outside, "vcpkg.json", `malformed`)
	if err := os.Symlink(filepath.Join(outside, "vcpkg.json"), filepath.Join(root, "vcpkg.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	put(t, root, ".git/conan.lock", "malformed")
	put(t, root, "conanfile.py", "raise Exception('must not execute')")
	put(t, root, "Podfile", "raise 'must not execute'")
	f, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Components) != 0 || len(f.Warnings) != 2 {
		t.Fatal(f)
	}
	if _, err := Profile(filepath.Join(root, "linked")); err == nil {
		t.Fatal("symlink root accepted")
	}
}
func TestRootsAndLimits(t *testing.T) {
	if _, err := Profile(""); err == nil {
		t.Fatal("empty root accepted")
	}
	root := t.TempDir()
	put(t, root, "plain", "x")
	if _, err := Profile(filepath.Join(root, "plain")); err == nil {
		t.Fatal("file root accepted")
	}
	if _, err := Profile(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing root accepted")
	}
	f, err := Profile(root)
	if err != nil || len(f.Components) != 0 || len(f.Ecosystems) != 0 {
		t.Fatalf("empty: %+v %v", f, err)
	}
	t.Run("file bytes", func(t *testing.T) {
		root := t.TempDir()
		put(t, root, "vcpkg.json", strings.Repeat(" ", maxFileBytes+1))
		if _, err := Profile(root); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("limit: %v", err)
		}
	})
	t.Run("total bytes", func(t *testing.T) {
		root := t.TempDir()
		data := `{"dependencies":[]}`
		data += strings.Repeat(" ", maxFileBytes-len(data))
		for i := 0; i < 9; i++ {
			put(t, root, fmt.Sprintf("%d/vcpkg.json", i), data)
		}
		if _, err := Profile(root); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("limit: %v", err)
		}
	})
	t.Run("depth", func(t *testing.T) {
		root := t.TempDir()
		put(t, root, strings.Repeat("d/", maxDepth+1)+"vcpkg.json", `{}`)
		if _, err := Profile(root); err == nil || !strings.Contains(err.Error(), "depth limit") {
			t.Fatalf("limit: %v", err)
		}
	})
	t.Run("components", func(t *testing.T) {
		s := &state{seen: map[string]bool{}}
		for i := 0; i <= maxComponents; i++ {
			err := s.add("vcpkg.json", "vcpkg", fmt.Sprint("p", i), "", "")
			if (i == maxComponents) != (err != nil) {
				t.Fatalf("component %d: %v", i, err)
			}
		}
	})
}
