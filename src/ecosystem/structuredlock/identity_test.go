package structuredlock

import (
	"reflect"
	"testing"
)

func TestIdentityAndDeduplication(t *testing.T) {
	s := &state{seen: map[string]bool{}, limit: 10}
	for _, v := range []struct{ eco, name, version string }{
		{"npm", "@scope/pkg", "1.2.3+build.1"},
		{"npm", "@scope/pkg", "1.2.3+build.1"},
		{"PyPI", "Foo__Bar.baz", "1!2.0RC1"},
		{"npm", "bad", "1.0.0-01"},
		{"npm", "UPPER", "1.0.0"},
	} {
		if err := s.add("lock", v.eco, v.name, v.version); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.fragment.Components) != 2 || len(s.fragment.Warnings) != 2 {
		t.Fatalf("%+v", s.fragment)
	}
	if got := s.fragment.Components[0]; got.PURL != "pkg:npm/%40scope/pkg@1.2.3%2Bbuild.1" || got.Namespace != "@scope" {
		t.Fatalf("%+v", got)
	}
	if got := s.fragment.Components[1]; got.PURL != "pkg:pypi/foo-bar-baz@1%212.0rc1" {
		t.Fatalf("%+v", got)
	}
}
func TestOrderingAcrossLockfiles(t *testing.T) {
	root := t.TempDir()
	a := "version = 1\n[[package]]\nname = 'Foo'\nversion = '1.0'\nsource = {registry = 'https://pypi.org/simple'}"
	put(t, root, "z/uv.lock", a)
	put(t, root, "a/uv.lock", a)
	got, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Components) != 2 || got.Components[0].SourcePath != "a/uv.lock" || got.Components[0].ID == got.Components[1].ID {
		t.Fatalf("%+v", got)
	}
	if len(got.Ecosystems) != 1 || !reflect.DeepEqual(got.Ecosystems[0].Lockfiles, []string{"a/uv.lock", "z/uv.lock"}) {
		t.Fatalf("%+v", got.Ecosystems)
	}
}
func TestUnsupportedResolutionAndPeerSyntax(t *testing.T) {
	root := t.TempDir()
	put(t, root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-x, unknownProtocol: foo}\n  b@1.0.0(patch_hash=abc):\n    resolution: {integrity: sha512-y}")
	got, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Components) != 0 || len(got.Warnings) != 2 {
		t.Fatalf("%+v", got)
	}
	put(t, root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  a@1.0.0(peer@2.0.0:\n    resolution: {integrity: sha512-x}")
	if _, err := Profile(root); err == nil {
		t.Fatal("malformed peer suffix accepted")
	}
}
