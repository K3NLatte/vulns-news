package repository

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLanguageCatalog(t *testing.T) {
	extensions, filenames := map[string]string{}, map[string]string{}
	for _, spec := range languageCatalog {
		if spec.name == "" {
			t.Fatal("empty language")
		}
		for _, ext := range strings.Fields(spec.extensions) {
			if prior, exists := extensions[ext]; exists {
				t.Fatalf("duplicate %s: %s / %s", ext, prior, spec.name)
			}
			extensions[ext] = spec.name
			if !strings.HasPrefix(ext, ".") {
				t.Fatalf("bad extension %s", ext)
			}
			if ambiguousLanguageFilename("source" + ext) {
				continue
			}
			if got := languageForFilename("source" + ext); got != spec.name {
				t.Errorf("%s = %s want %s", ext, got, spec.name)
			}
		}
		for _, name := range strings.Fields(spec.filenames) {
			if _, exists := filenames[name]; exists {
				t.Fatalf("duplicate filename %s", name)
			}
			filenames[name] = spec.name
			if got := languageForFilename(name); got != spec.name {
				t.Errorf("%s = %s want %s", name, got, spec.name)
			}
		}
	}
}

func TestFilenamePrecedenceAndUnknown(t *testing.T) {
	cases := map[string]string{
		"CMakeLists.txt": "CMake", "MODULE.bazel": "Starlark", "Makefile": "Makefile",
		"build.gradle.kts": "Kotlin", "Dockerfile.dev": "Dockerfile", "Containerfile.prod": "Dockerfile",
		"foo.C": "C++", "foo.c": "C", "MAIN.PY": "Python", "script.pl": "Perl",
		"movie.mp4": "", "readme.md": "", "file.xyz": "", "file.m": "", "file.v": "",
		"file.as": "", "file.cl": "", "go.mod": "", "build.pro": "",
	}
	for name, want := range cases {
		if got := languageForFilename(name); got != want {
			t.Errorf("%s = %q want %q", name, got, want)
		}
	}
}

func TestDetectLanguagesLogicAndBuildFiles(t *testing.T) {
	root := t.TempDir()
	cases := map[string]string{
		"rules.prolog": "Prolog", "rules.dl": "Datalog", "model.mzn": "MiniZinc",
		"problem.smt2": "SMT-LIB", "model.als": "Alloy", "Spec.tla": "TLA+",
		"flake.nix": "Nix", "BUILD.bazel": "Starlark", "CMakeLists.txt": "CMake",
		"Makefile": "Makefile", "infra/main.tf": "HCL", "Dockerfile": "Dockerfile",
		"meson.build": "Meson", "justfile": "Just", "src/component.vue": "Vue", "src/ui.svelte": "Svelte",
	}
	for name := range cases {
		writeProfileFile(t, root, name, "")
	}
	writeProfileFile(t, root, ".git/ignored.go", "")
	writeProfileFile(t, root, "node_modules/ignored.js", "")
	writeProfileFile(t, root, "unknown.zzz", "")
	got, err := detectLanguages(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(cases) {
		t.Fatalf("languages: %#v", got)
	}
	languages := languageMap(got)
	for source, name := range cases {
		language, ok := languages[name]
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if len(language.SourcePaths) != 1 || language.SourcePaths[0] != source {
			t.Errorf("%s sources: %v", name, language.SourcePaths)
		}
		assertPercentage(t, language, 100/float64(len(cases)))
	}
	again, err := detectLanguages(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, again) {
		t.Fatal("nondeterministic detection")
	}
}

func TestDetectLanguagesContentAndSymlinks(t *testing.T) {
	root := t.TempDir()
	writeProfileFile(t, root, "objc.m", "@implementation App\n@end\n")
	writeProfileFile(t, root, "hardware.v", "module adder(input a);\nendmodule\n")
	writeProfileFile(t, root, "rules.pro", ":- module(rules, []).\n")
	writeProfileFile(t, root, "unknown.m", "% no distinguishing syntax\n")
	outside := t.TempDir()
	writeProfileFile(t, outside, "outside.v", "fn main() {}\n")
	if err := os.Symlink(filepath.Join(outside, "outside.v"), filepath.Join(root, "linked.v")); err != nil {
		t.Logf("symlink unavailable: %v", err)
	}
	got, err := detectLanguages(root)
	if err != nil {
		t.Fatal(err)
	}
	languages := languageMap(got)
	if len(languages) != 3 {
		t.Fatalf("unexpected languages: %#v", got)
	}
	for _, name := range []string{"Objective-C", "Verilog", "Prolog"} {
		if _, ok := languages[name]; !ok {
			t.Errorf("missing %s", name)
		}
	}
}

func TestDetectLanguagesCapsSourceExamples(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 15; i++ {
		writeProfileFile(t, root, string(rune('a'+i))+".nix", "")
	}
	got, err := detectLanguages(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].SourcePaths) != maxLanguageSourcePaths {
		t.Fatalf("got %#v", got)
	}
	assertPercentage(t, got[0], 100)
}
