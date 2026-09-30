package lockprofile

import (
	"reflect"
	"strings"
	"testing"
)

func TestFailureDoesNotReturnEarlierFiles(t *testing.T) {
	r := t.TempDir()
	fixture(t, r, "a/gradle.lockfile", "g:a:1=runtime\n")
	fixture(t, r, "z/Pipfile.lock", "{")
	result, err := Profile(r)
	if err == nil || !reflect.DeepEqual(result, Fragment{}) {
		t.Fatalf("partial result: %+v %v", result, err)
	}
}

func TestExactVersionHandling(t *testing.T) {
	t.Run("pip", func(t *testing.T) {
		r := t.TempDir()
		fixture(t, r, "Pipfile.lock", `{"_meta":{"sources":[{"name":"pypi","url":"https://pypi.org/simple","verify_ssl":true}]},"default":{"epoch":{"version":"==1!2.0rc1.post2.dev3+local.1"},"bad":{"version":"==not-a-version"},"url":{"version":"==https://example.test/pkg"}}}`)
		g, e := Profile(r)
		if e != nil || len(g.Components) != 1 || g.Components[0].Name != "epoch" {
			t.Fatalf("versions: %+v %v", g, e)
		}
	})
	t.Run("nuget", func(t *testing.T) {
		r := t.TempDir()
		fixture(t, r, "packages.lock.json", `{"version":2,"dependencies":{"net8.0":{"Central":{"type":"CentralTransitive","resolved":"1.2.3-beta.1+build"}}}}`)
		g, e := Profile(r)
		if e != nil || len(g.Components) != 1 || g.Components[0].Direct {
			t.Fatalf("central: %+v %v", g, e)
		}
		fixture(t, r, "packages.lock.json", `{"version":2,"dependencies":{"net8.0":{"Bad":{"type":"Direct","resolved":"garbage"}}}}`)
		if _, e := Profile(r); e == nil {
			t.Fatal("invalid version accepted")
		}
	})
	t.Run("pom", func(t *testing.T) {
		r := t.TempDir()
		fixture(t, r, "pom.xml", `<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>LATEST</version></dependency><dependency><groupId>g</groupId><artifactId>b</artifactId><version>RELEASE</version></dependency></dependencies></project>`)
		g, e := Profile(r)
		if e != nil || len(g.Components) != 2 {
			t.Fatalf("POM: %+v %v", g, e)
		}
		for _, c := range g.Components {
			if c.Version != "" {
				t.Fatal(c)
			}
		}
	})
}

func TestGemSectionStructure(t *testing.T) {
	for _, data := range []string{"GEM\n", "GEM\nDEPENDENCIES\n", "GEM\n  specs:\n  specs:\n"} {
		r := t.TempDir()
		fixture(t, r, "Gemfile.lock", data)
		if _, e := Profile(r); e == nil {
			t.Fatalf("malformed GEM accepted: %q", data)
		}
	}
}

func TestStableAcrossJSONKeyOrder(t *testing.T) {
	r := t.TempDir()
	fixture(t, r, "Pipfile.lock", `{"_meta":{"sources":[{"name":"pypi","url":"https://pypi.org/simple","verify_ssl":true}]},"default":{"b":{"version":"==2"},"a":{"version":"==1"}},"develop":{}}`)
	first, e := Profile(r)
	if e != nil {
		t.Fatal(e)
	}
	fixture(t, r, "Pipfile.lock", `{"_meta":{"sources":[{"name":"pypi","url":"https://pypi.org/simple","verify_ssl":true}]},"develop":{},"default":{"a":{"version":"==1"},"b":{"version":"==2"}}}`)
	second, e := Profile(r)
	if e != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("unstable inventory: %v", e)
	}
	fixture(t, r, "Pipfile.lock", `{"_meta":{"sources":[{"name":"pypi","url":"https://pypi.org/simple","verify_ssl":true}]},"default":{"b":{"version":"==3"},"a":{"version":"==1"}},"develop":{}}`)
	third, e := Profile(r)
	if e != nil {
		t.Fatal(e)
	}
	for _, before := range first.Components {
		for _, after := range third.Components {
			if before.Name == after.Name {
				if before.PURL != after.PURL {
					t.Fatal("version changed PURL")
				}
				if before.Name == "b" && before.ID == after.ID {
					t.Fatal("version did not change ID")
				}
			}
		}
	}
}

func TestExactRejectsNonLiteralTokens(t *testing.T) {
	for _, s := range []string{"", "1\x00", "1\u00a0", "https://host/version", "[1,2)", "${version}"} {
		if exact(s) {
			t.Fatalf("accepted %q", s)
		}
	}
	if !exact("1.2.3-SNAPSHOT") {
		t.Fatal("literal Maven snapshot rejected")
	}
}

func TestPOMExpansionWorkBound(t *testing.T) {
	props := map[string]string{"a": "value"}
	for _, s := range []string{strings.Repeat("${a}", 257), strings.Repeat("x", 65537)} {
		if _, ok := expand(s, props); ok {
			t.Fatal("expansion limit ignored")
		}
	}
}
