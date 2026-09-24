package staticprofile

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"vulns-news/src/domain"
)

func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, text := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func byName(t *testing.T, f ProfileFragment) map[string]domain.Component {
	t.Helper()
	result := map[string]domain.Component{}
	for _, c := range f.Components {
		if _, ok := result[c.Name]; ok {
			t.Fatalf("duplicate name %q", c.Name)
		}
		result[c.Name] = c
	}
	return result
}

func TestGoRequirementsOnly(t *testing.T) {
	root := fixture(t, map[string]string{
		"nested/go.mod": "module example.org/app\ngo 1.25\nrequire example.org/direct v1.2.3\nrequire (\n example.org/indirect v0.0.0-20250101000000-abcdef123456 // indirect\n \"example.org/quoted\" \"v2.0.0+incompatible\"\n example.org/unknown\n example.org/range >=v1.0.0\n)\n",
		"nested/go.sum": "example.org/stale v9.0.0 h1:unused\n",
	})
	f, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	got := byName(t, f)
	if len(got) != 5 {
		t.Fatalf("components: %#v", got)
	}
	for name, version := range map[string]string{"example.org/direct": "v1.2.3", "example.org/indirect": "v0.0.0-20250101000000-abcdef123456", "example.org/quoted": "v2.0.0+incompatible", "example.org/unknown": "", "example.org/range": ""} {
		c := got[name]
		if c.Version != version || c.SourcePath != "nested/go.mod" || c.Ecosystem != "Go" || c.PURL != "pkg:golang/"+name || c.Scope != "runtime" {
			t.Errorf("%s: %#v", name, c)
		}
		if c.Direct != (name != "example.org/indirect") {
			t.Errorf("direct: %#v", c)
		}
	}
	if len(f.Warnings) != 2 {
		t.Fatalf("warnings: %#v", f.Warnings)
	}
	want := []domain.EcosystemUsage{{Name: "Go", Manifests: []string{"nested/go.mod"}}}
	if !reflect.DeepEqual(f.Ecosystems, want) {
		t.Fatalf("ecosystems: %#v", f.Ecosystems)
	}
}

func TestGoOverridesNeverClaimResolvedVersions(t *testing.T) {
	for _, directive := range []string{"replace example.org/a => ../local", "replace (\n example.org/a v1.0.0 => example.org/fork v2.0.0\n)", "exclude example.org/a v1.0.0"} {
		t.Run(directive, func(t *testing.T) {
			root := fixture(t, map[string]string{"go.mod": "require example.org/a v1.0.0\n" + directive + "\nrequire example.org/b v1.0.0 // indirect\n"})
			f, err := Profile(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(f.Components) != 2 || len(f.Warnings) != 1 {
				t.Fatalf("fragment: %#v", f)
			}
			for _, c := range f.Components {
				if c.Version != "" {
					t.Fatalf("false resolved version: %#v", c)
				}
			}
		})
	}
}

func TestPythonRequirements(t *testing.T) {
	cases := []struct {
		line, name, version string
		warning             bool
	}{
		{"Requests==2.32.3", "requests", "2.32.3", false},
		{"My_Package.Name[extra,other] == 1!2.0rc1.post2.dev3+linux.1 # comment", "my-package-name", "1!2.0rc1.post2.dev3+linux.1", false},
		{"bare", "bare", "", true},
		{"range>=1.0,<2", "range", "", true},
		{"wild==1.2.*", "wild", "", true},
		{"arbitrary===custom", "arbitrary", "", true},
		{"conditional==1.0; python_version < '3.12'", "conditional", "", true},
		{"remote @ https://example.org/a.whl", "remote", "", true},
		{"hashed==1.0 --hash=sha256:abc", "hashed", "", true},
		{"continued==1.0 \\\n --hash=sha256:abc", "continued", "", true},
		{"-r ../outside.txt", "", "", true},
		{"--requirement=https://example.org/r.txt", "", "", true},
		{"-c constraints.txt", "", "", true},
		{"-e git+https://example.org/repo#egg=x", "", "", true},
		{"https://example.org/a.whl", "", "", true},
		{"../local", "", "", true},
		{"# comment", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			f, err := Profile(fixture(t, map[string]string{"requirements.txt": tc.line + "\r\n"}))
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "" {
				if len(f.Components) != 0 {
					t.Fatalf("components: %#v", f.Components)
				}
			} else {
				if len(f.Components) != 1 {
					t.Fatalf("components: %#v", f.Components)
				}
				c := f.Components[0]
				if c.Name != tc.name || c.Version != tc.version || c.PURL != "pkg:pypi/"+tc.name || !c.Direct || c.SourcePath != "requirements.txt" {
					t.Fatalf("component: %#v", c)
				}
			}
			if (len(f.Warnings) != 0) != tc.warning {
				t.Fatalf("warnings: %#v", f.Warnings)
			}
			for _, w := range f.Warnings {
				if w.SourcePath != "requirements.txt" || w.Line != 1 {
					t.Fatalf("warning: %#v", w)
				}
			}
		})
	}
}

func TestDeterminismAndSourceIdentity(t *testing.T) {
	files := map[string]string{"z/requirements.txt": "A==1.0\nA==1.0\n", "a/requirements.txt": "A==1.0\n", "go.mod": "require example.org/a v1.0.0\n", "poetry.lock": "not parsed", "uv.lock": "not parsed"}
	root := fixture(t, files)
	first, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Profile(fixture(t, files))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("not reproducible:\n%#v\n%#v", first, second)
	}
	if len(first.Components) != 3 || len(first.Warnings) != 2 || len(first.Ecosystems) != 2 {
		t.Fatalf("fragment: %#v", first)
	}
	if !reflect.DeepEqual(first.Ecosystems[1].Lockfiles, []string{"poetry.lock", "uv.lock"}) {
		t.Fatal(first.Ecosystems)
	}
	seen := map[string]bool{}
	for _, c := range first.Components {
		if c.ID == "" || seen[c.ID] {
			t.Fatalf("invalid identity: %#v", c)
		}
		seen[c.ID] = true
		if strings.Contains(c.SourcePath, "\\") || filepath.IsAbs(c.SourcePath) {
			t.Fatal(c.SourcePath)
		}
	}
}

func TestSkippedDirectoriesAndSymlinks(t *testing.T) {
	root := fixture(t, map[string]string{".git/go.mod": "bad", "node_modules/requirements.txt": "bad", "vendor/go.mod": "bad", "requirements.txt": "safe==1.0"})
	outside := fixture(t, map[string]string{"requirements.txt": "outside==9.0"})
	for _, link := range []struct{ target, name string }{{outside, "linked"}, {filepath.Join(outside, "requirements.txt"), "go.mod"}} {
		if err := os.Symlink(link.target, filepath.Join(root, link.name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	f, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Components) != 1 || f.Components[0].Name != "safe" || len(f.Warnings) != 0 {
		t.Fatalf("fragment: %#v", f)
	}
	linkRoot := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(root, linkRoot); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{linkRoot, linkRoot + string(os.PathSeparator)} {
		if _, err := Profile(name); err == nil {
			t.Fatal("accepted symlink root")
		}
	}
}

func TestLimits(t *testing.T) {
	cases := []struct {
		name   string
		limits Limits
		files  map[string]string
		want   error
	}{
		{"file", Limits{4, 100, 100, 10}, map[string]string{"requirements.txt": "a==10"}, ErrFileTooLarge},
		{"total", Limits{10, 9, 100, 10}, map[string]string{"a/requirements.txt": "a==10", "b/requirements.txt": "b==10"}, ErrTotalSize},
		{"entries", Limits{100, 100, 2, 10}, map[string]string{"a": "", "b": "", "c": ""}, ErrTooManyFiles},
		{"directories", Limits{100, 100, 2, 10}, map[string]string{"a/b/c": ""}, ErrTooManyFiles},
		{"depth", Limits{100, 100, 100, 1}, map[string]string{"a/requirements.txt": "a==1"}, ErrMaxDepth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProfiler(tc.limits)
			if err != nil {
				t.Fatal(err)
			}
			f, err := p.Profile(fixture(t, tc.files))
			if !errors.Is(err, tc.want) {
				t.Fatalf("error %v; want %v", err, tc.want)
			}
			if !reflect.DeepEqual(f, ProfileFragment{}) {
				t.Fatalf("partial result on failure: %#v", f)
			}
		})
	}
	p, _ := NewProfiler(Limits{4, 4, 1, 1})
	if _, err := p.Profile(fixture(t, map[string]string{"requirements.txt": "a==1"})); err != nil {
		t.Fatalf("exact boundary: %v", err)
	}
	for _, limits := range []Limits{{}, {0, 1, 1, 1}, {1, 0, 1, 1}, {1, 1, 0, 1}, {1, 1, 1, 0}, {-1, 1, 1, 1}} {
		if _, err := NewProfiler(limits); err == nil {
			t.Fatalf("accepted limits: %#v", limits)
		}
	}
}

func TestInvalidRootsAndEmptyInventory(t *testing.T) {
	for _, root := range []string{"", filepath.Join(t.TempDir(), "missing")} {
		if _, err := Profile(root); err == nil {
			t.Fatalf("accepted %q", root)
		}
	}
	root := fixture(t, map[string]string{"go.sum": "example.org/unused v1.0.0 h1:x"})
	f, err := Profile(root)
	if err != nil || len(f.Components) != 0 || len(f.Ecosystems) != 0 {
		t.Fatalf("fragment: %#v; %v", f, err)
	}
	if _, err := Profile(filepath.Join(root, "go.sum")); err == nil {
		t.Fatal("accepted regular-file root")
	}
	var p *Profiler
	if _, err := p.Profile(root); err == nil {
		t.Fatal("accepted nil profiler")
	}
	if _, err := new(Profiler).Profile(root); err == nil {
		t.Fatal("accepted zero profiler")
	}
}

func TestMalformedGoWarnings(t *testing.T) {
	f, err := Profile(fixture(t, map[string]string{"go.mod": "require (\n example.org/a v1.0.0 extra\n /bad v1.0.0\n example.org/b latest\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Warnings) != 4 || len(f.Components) != 1 || f.Components[0].Version != "" {
		t.Fatalf("fragment: %#v", f)
	}
}
