package lockprofile

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T, root, name, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
func TestProfileFormats(t *testing.T) {
	cases := []struct {
		name, data, eco, purl, version, scope string
		direct                                bool
	}{
		{"Pipfile.lock", `{"_meta":{"sources":[{"name":"pypi","url":"https://pypi.org/simple","verify_ssl":true}]},"default":{"Foo_Bar":{"version":"==1.2.3","markers":"python_version >= '3.9'"}},"develop":{}}`, "pypi", "pkg:pypi/foo-bar", "1.2.3", "runtime", false},
		{"composer.lock", `{"packages":[],"packages-dev":[{"name":"vendor/library","version":"v2.0.1","source":{"type":"git","url":"https://example.test/repo.git"}}]}`, "packagist", "pkg:packagist/vendor/library", "v2.0.1", "development", false},
		{"packages.lock.json", `{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.3, )","resolved":"13.0.3"}}}}`, "nuget", "pkg:nuget/newtonsoft.json", "13.0.3", "net8.0", true},
		{"Package.resolved", `{"version":3,"originHash":"x","pins":[{"identity":"Example.Library","kind":"registry","state":{"version":"1.0.0"}}]}`, "swift", "pkg:swift/example/library", "1.0.0", "runtime", false},
		{"package.resolved", `{"version":2,"pins":[{"identity":"example.library","kind":"registry","state":{"version":"1.0.0"}}]}`, "swift", "pkg:swift/example/library", "1.0.0", "runtime", false},
		{"gradle.lockfile", "# generated\r\norg.example:library:2.1=runtimeClasspath\r\nempty=test\r\n", "maven", "pkg:maven/org.example/library", "2.1", "runtimeClasspath", false},
		{"Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.0)\n\nDEPENDENCIES\n  rack (~> 3.0)\n\nBUNDLED WITH\n   2.5.0\n", "gem", "pkg:gem/rack", "3.1.0", "runtime", true},
		{"pom.xml", `<project xmlns="http://maven.apache.org/POM/4.0.0"><properties><release>1.2</release><lib.version>${release}.3</lib.version></properties><dependencies><dependency><groupId>org.example</groupId><artifactId>library</artifactId><version>${lib.version}</version></dependency></dependencies></project>`, "maven", "pkg:maven/org.example/library", "1.2.3", "compile", true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			fixture(t, root, "sub/"+tt.name, tt.data)
			got, err := Profile(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Components) != 1 {
				t.Fatalf("components: %+v; warnings: %v", got.Components, got.Warnings)
			}
			c := got.Components[0]
			if c.PURL != tt.purl || c.Version != tt.version || c.Scope != tt.scope || c.Direct != tt.direct || c.Ecosystem != tt.eco || c.SourcePath != "sub/"+tt.name || c.ID == "" {
				t.Fatalf("component: %+v", c)
			}
			if strings.Contains(c.PURL, "@") {
				t.Fatalf("versioned PURL: %s", c.PURL)
			}
			if len(got.Ecosystems) != 1 || got.Ecosystems[0].Name != tt.eco {
				t.Fatalf("usage: %+v", got.Ecosystems)
			}
			paths := got.Ecosystems[0].Lockfiles
			if tt.name == "pom.xml" {
				paths = got.Ecosystems[0].Manifests
			}
			if !reflect.DeepEqual(paths, []string{"sub/" + tt.name}) {
				t.Fatalf("paths: %v", paths)
			}
			again, err := Profile(root)
			if err != nil || !reflect.DeepEqual(got, again) {
				t.Fatalf("not deterministic: %v", err)
			}
		})
	}
}
func TestMalformed(t *testing.T) {
	cases := []struct{ name, data string }{
		{"Pipfile.lock", `{"default":`}, {"Pipfile.lock", `null`}, {"Pipfile.lock", `{}`},
		{"Pipfile.lock", `{"default":{},"default":{}}`}, {"Pipfile.lock", `{"default":{}} {}`},
		{"Pipfile.lock", `{"default":{"a":null}}`}, {"Pipfile.lock", `{"default":{"a":{"version":3}}}`},
		{"composer.lock", `{"packages":{}}`}, {"composer.lock", `{"packages":[{"name":"bad","version":"1"}]}`},
		{"composer.lock", `{"packages":[{"name":"a/b"}]}`},
		{"packages.lock.json", `{"version":"1","dependencies":{}}`},
		{"packages.lock.json", `{"version":1,"dependencies":{"net8.0":{"a":{"type":"Direct"}}}}`},
		{"Package.resolved", `{"version":2,"pins":null}`},
		{"Package.resolved", `{"version":1,"object":{"pins":[{"package":"x","state":[]}]}}`},
		{"gradle.lockfile", "bad"}, {"gradle.lockfile", "a:b=runtime"}, {"gradle.lockfile", "a:b:1=runtime,"},
		{"Gemfile.lock", "  specs:\n"}, {"Gemfile.lock", "GEM\n  specs:\n    rack 1.2\n"},
		{"Gemfile.lock", "GEM\n  specs:\n      rack (~> 1)\n"},
		{"pom.xml", "<project>"}, {"pom.xml", "<wrong/>"}, {"pom.xml", "<project/><project/>"},
		{"pom.xml", `<!DOCTYPE project [<!ENTITY external SYSTEM "file:///etc/passwd">]><project/>`},
		{"pom.xml", "<project><dependencies/><dependencies/></project>"},
		{"pom.xml", "<project><properties><v>1</v><v>2</v></properties></project>"},
	}
	for _, tt := range cases {
		t.Run(tt.name+"/"+tt.data, func(t *testing.T) {
			root := t.TempDir()
			fixture(t, root, tt.name, tt.data)
			got, err := Profile(root)
			if err == nil {
				t.Fatalf("expected error, got %+v", got)
			}
			if !reflect.DeepEqual(got, Fragment{}) {
				t.Fatalf("partial result on error: %+v", got)
			}
			if !strings.Contains(err.Error(), tt.name) {
				t.Fatalf("missing source: %v", err)
			}
		})
	}
}
func TestUnsupported(t *testing.T) {
	root := t.TempDir()
	fixture(t, root, "Pipfile.lock", `{"default":{"gitdep":{"git":"https://example.test/x","version":"==1"},"pathdep":{"path":"../x"},"ranged":{"version":">=1"},"wildcard":{"version":"==1.*"}}}`)
	fixture(t, root, "composer.lock", `{"packages":[{"name":"a/b","version":"dev-main"},{"name":"a/c","version":"1.0","dist":{"type":"path"}}]}`)
	fixture(t, root, "packages.lock.json", `{"version":2,"dependencies":{"net8.0":{"Local.Project":{"type":"Project"}}}}`)
	fixture(t, root, "Package.resolved", `{"version":1,"object":{"pins":[{"package":"Repo","repositoryURL":"https://example.test/repo","state":{"revision":"abc","version":"1.2.3","branch":null}}]}}`)
	fixture(t, root, "gradle.lockfile", "a:b:1.+=runtime\n")
	fixture(t, root, "Gemfile.lock", "GIT\n  remote: https://example.test/repo\n  specs:\n    gitgem (1.0)\nPATH\n  remote: ../local\n  specs:\n    localgem (1.0)\nGEM\n  remote: https://rubygems.org/\n  specs:\n    native (1.0-x86_64-linux)\nDEPENDENCIES\n  gitgem!\n  localgem!\n")
	got, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Components) != 0 || len(got.Warnings) < 10 {
		t.Fatalf("unsupported entries: %+v", got)
	}
	for _, name := range []string{"Package.resolved", "packages.lock.json"} {
		t.Run(name, func(t *testing.T) {
			r := t.TempDir()
			fixture(t, r, name, `{"version":999}`)
			g, e := Profile(r)
			if e != nil || len(g.Components) != 0 || len(g.Warnings) != 1 {
				t.Fatalf("future schema: %+v %v", g, e)
			}
		})
	}
}
func TestPOMUnknownAndIgnored(t *testing.T) {
	root := t.TempDir()
	fixture(t, root, "pom.xml", `<project><parent><groupId>org.parent</groupId><artifactId>parent</artifactId><version>2.0</version></parent><properties><a>${b}</a><b>${a}</b></properties><dependencyManagement><dependencies><dependency><groupId>x</groupId><artifactId>managed</artifactId><version>9</version></dependency></dependencies></dependencyManagement><profiles><profile><dependencies><dependency><groupId>x</groupId><artifactId>profile-only</artifactId><version>9</version></dependency></dependencies></profile></profiles><dependencies><dependency><groupId>${project.groupId}</groupId><artifactId>inherited-literal</artifactId><version>${project.parent.version}</version><scope>test</scope></dependency><dependency><groupId>x</groupId><artifactId>cycle</artifactId><version>${a}</version></dependency><dependency><groupId>x</groupId><artifactId>missing</artifactId></dependency><dependency><groupId>x</groupId><artifactId>unknown</artifactId><version>${env.SECRET}</version></dependency><dependency><groupId>x</groupId><artifactId>range</artifactId><version>[1,2)</version></dependency><dependency><groupId>${unknown}</groupId><artifactId>omitted</artifactId><version>1</version></dependency></dependencies></project>`)
	got, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Components) != 5 {
		t.Fatalf("components: %+v", got)
	}
	for _, c := range got.Components {
		if c.Name == "inherited-literal" {
			if c.Version != "2.0" || c.Namespace != "org.parent" || c.Scope != "test" {
				t.Fatal(c)
			}
		} else if c.Version != "" {
			t.Fatalf("guessed version: %+v", c)
		}
	}
	if len(got.Warnings) < 8 {
		t.Fatalf("warnings: %v", got.Warnings)
	}
}
func TestExpansionBounds(t *testing.T) {
	for _, tt := range []struct {
		s     string
		props map[string]string
	}{
		{"${x}", map[string]string{"x": "${x}"}}, {"${missing}", nil}, {"${x", nil},
		{"${x}", map[string]string{"x": strings.Repeat("z", 65537)}},
		{strings.Repeat("${x}", 300), map[string]string{"x": "1"}},
	} {
		if _, ok := expand(tt.s, tt.props); ok {
			t.Fatalf("expected unresolved expansion")
		}
	}
}
func TestMultipleFrameworksScopesAndIDs(t *testing.T) {
	root := t.TempDir()
	fixture(t, root, "packages.lock.json", `{"version":1,"dependencies":{"net8.0":{"A":{"type":"Direct","resolved":"1"}},"net9.0":{"A":{"type":"Transitive","resolved":"2"}}}}`)
	fixture(t, root, "gradle.lockfile", "g:a:1=compile,runtime\ng:a:1=compile\n")
	fixture(t, root, "nested/gradle.lockfile", "g:a:1=compile\n")
	fixture(t, root, "Pipfile.lock", `{"_meta":{"sources":[{"name":"pypi","url":"https://pypi.org/simple","verify_ssl":true}]},"default":{"a":{"version":"==1"}},"develop":{"a":{"version":"==1"}}}`)
	g, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Components) != 7 {
		t.Fatalf("components: %+v", g.Components)
	}
	ids := map[string]bool{}
	for _, c := range g.Components {
		if ids[c.ID] {
			t.Fatalf("duplicate ID %s", c.ID)
		}
		ids[c.ID] = true
	}
}
func TestGemRegistryOnly(t *testing.T) {
	r := t.TempDir()
	fixture(t, r, "Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.0)\n      base (~> 1.0)\n    base (1.0)\nGIT\n  specs:\n    gitgem (4.0)\nDEPENDENCIES\n  rack\n  gitgem!\n")
	g, e := Profile(r)
	if e != nil {
		t.Fatal(e)
	}
	if len(g.Components) != 2 {
		t.Fatal(g)
	}
	for _, c := range g.Components {
		if c.Direct != (c.Name == "rack") {
			t.Fatal(c)
		}
	}
}
func TestRootAndTraversal(t *testing.T) {
	if _, err := Profile(""); err == nil {
		t.Fatal("empty root accepted")
	}
	r := t.TempDir()
	fixture(t, r, "plain", "x")
	if _, err := Profile(filepath.Join(r, "plain")); err == nil {
		t.Fatal("file root accepted")
	}
	for _, dir := range []string{".git", "vendor", "node_modules", ".gradle", ".build"} {
		fixture(t, r, dir+"/Pipfile.lock", "malformed")
	}
	fixture(t, r, "unrelated.json", "malformed")
	g, e := Profile(r)
	if e != nil || len(g.Ecosystems) != 0 {
		t.Fatalf("excluded files parsed: %+v %v", g, e)
	}
	outside := t.TempDir()
	fixture(t, outside, "Pipfile.lock", "malformed")
	if err := os.Symlink(filepath.Join(outside, "Pipfile.lock"), filepath.Join(r, "Pipfile.lock")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(r, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := Profile(r); err != nil {
		t.Fatalf("followed symlink: %v", err)
	}
	if _, err := Profile(filepath.Join(r, "linked")); err == nil {
		t.Fatal("symlink root accepted")
	}
	if err := os.Symlink(".", filepath.Join(r, "cycle")); err != nil {
		t.Fatal(err)
	}
	if _, err := Profile(r); err != nil {
		t.Fatal(err)
	}
}
func TestResourceBounds(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		r := t.TempDir()
		fixture(t, r, "Pipfile.lock", strings.Repeat(" ", maxFileBytes+1))
		if _, e := Profile(r); e == nil || !strings.Contains(e.Error(), "byte limit") {
			t.Fatalf("limit: %v", e)
		}
	})
	t.Run("total", func(t *testing.T) {
		r := t.TempDir()
		data := `{"default":{}}` + strings.Repeat(" ", maxFileBytes-len(`{"default":{}}`))
		for i := 0; i < 9; i++ {
			fixture(t, r, strings.Repeat("x", i+1)+"/Pipfile.lock", data)
		}
		if _, e := Profile(r); e == nil || !strings.Contains(e.Error(), "byte limit") {
			t.Fatalf("limit: %v", e)
		}
	})
	t.Run("depth", func(t *testing.T) {
		r := t.TempDir()
		if e := os.MkdirAll(filepath.Join(r, strings.Repeat("d/", maxDepth+1)), 0755); e != nil {
			t.Fatal(e)
		}
		if _, e := Profile(r); e == nil || !strings.Contains(e.Error(), "depth limit") {
			t.Fatalf("limit: %v", e)
		}
	})
	t.Run("JSON", func(t *testing.T) {
		r := t.TempDir()
		fixture(t, r, "Pipfile.lock", `{"default":`+strings.Repeat("[", 66)+strings.Repeat("]", 66)+`}`)
		if _, e := Profile(r); e == nil {
			t.Fatal("unbounded JSON")
		}
	})
	t.Run("XML", func(t *testing.T) {
		r := t.TempDir()
		fixture(t, r, "pom.xml", "<project>"+strings.Repeat("<x>", 65)+strings.Repeat("</x>", 65)+"</project>")
		if _, e := Profile(r); e == nil {
			t.Fatal("unbounded XML")
		}
	})
}
func FuzzParsers(f *testing.F) {
	f.Add(uint8(0), []byte(`{"default":{}}`))
	f.Add(uint8(1), []byte("<project/>"))
	f.Add(uint8(2), []byte("GEM\n  specs:\n"))
	parsers := []func(*Fragment, string, []byte) error{parsePip, parsePOM, parseGem, parseGradle, parseComposer, parseNuget, parseSwift}
	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		if len(data) > maxFileBytes {
			t.Skip()
		}
		var result Fragment
		_ = parsers[int(kind)%len(parsers)](&result, "input", data)
	})
}
