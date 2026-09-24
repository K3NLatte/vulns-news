package npm

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

func TestProfileFSParsesV3LockfileAndClassifiesDependencies(t *testing.T) {
	filesystem := fstest.MapFS{
		"package.json": &fstest.MapFile{Data: []byte(`{
			"dependencies":{"prod":"^1.0.0"},
			"devDependencies":{"tool":"~2.0.0"}
		}`)},
		"package-lock.json": &fstest.MapFile{Data: []byte(`{
			"name":"application",
			"lockfileVersion":3,
			"packages":{
				"":{"dependencies":{"prod":"^1.0.0"},"devDependencies":{"tool":"~2.0.0"}},
				"node_modules/prod":{"version":"1.4.2"},
				"node_modules/tool":{"version":"2.1.0","dev":true},
				"node_modules/prod/node_modules/@scope/transitive":{"version":"3.0.1"}
			}
		}`)},
	}

	fragment, err := ProfileFS(filesystem)
	if err != nil {
		t.Fatalf("ProfileFS: %v", err)
	}
	if len(fragment.Ecosystems) != 1 {
		t.Fatalf("ecosystems = %#v", fragment.Ecosystems)
	}
	usage := fragment.Ecosystems[0]
	if usage.Name != "npm" || len(usage.Manifests) != 1 || usage.Manifests[0] != "package.json" || len(usage.Lockfiles) != 1 || usage.Lockfiles[0] != "package-lock.json" {
		t.Errorf("ecosystem usage = %#v", usage)
	}
	if len(fragment.Components) != 3 {
		t.Fatalf("components = %#v", fragment.Components)
	}

	byName := make(map[string]int)
	for index, component := range fragment.Components {
		byName[component.Name] = index
		if component.ID == "" || !strings.HasPrefix(component.ID, "npm-") {
			t.Errorf("component ID = %q", component.ID)
		}
		if component.SourcePath != "package-lock.json" {
			t.Errorf("source path = %q", component.SourcePath)
		}
		if strings.Contains(component.PURL, "@"+component.Version) {
			t.Errorf("PURL contains a version: %q", component.PURL)
		}
	}

	prod := fragment.Components[byName["prod"]]
	if !prod.Direct || prod.Scope != "runtime" || prod.Version != "1.4.2" || prod.PURL != "pkg:npm/prod" {
		t.Errorf("prod component = %#v", prod)
	}
	tool := fragment.Components[byName["tool"]]
	if !tool.Direct || tool.Scope != "dev" || tool.Version != "2.1.0" {
		t.Errorf("tool component = %#v", tool)
	}
	transitive := fragment.Components[byName["@scope/transitive"]]
	if transitive.Direct || transitive.Scope != "runtime" || transitive.Namespace != "@scope" || transitive.PURL != "pkg:npm/%40scope/transitive" {
		t.Errorf("scoped transitive component = %#v", transitive)
	}

	again, err := ProfileFS(filesystem)
	if err != nil {
		t.Fatalf("second ProfileFS: %v", err)
	}
	for index := range fragment.Components {
		if fragment.Components[index].ID != again.Components[index].ID {
			t.Fatalf("unstable IDs: %q != %q", fragment.Components[index].ID, again.Components[index].ID)
		}
	}
}

func TestProfileFSParsesV2LegacyDependencyTree(t *testing.T) {
	filesystem := fstest.MapFS{
		"package.json": &fstest.MapFile{Data: []byte(`{"dependencies":{"parent":"1.0.0"}}`)},
		"package-lock.json": &fstest.MapFile{Data: []byte(`{
			"lockfileVersion":2,
			"dependencies":{
				"parent":{"version":"1.0.0","dependencies":{"child":{"version":"2.0.0"}}},
				"dev-only":{"version":"3.0.0","dev":true}
			}
		}`)},
	}

	fragment, err := ProfileFS(filesystem)
	if err != nil {
		t.Fatalf("ProfileFS: %v", err)
	}
	if len(fragment.Components) != 3 {
		t.Fatalf("components = %#v", fragment.Components)
	}
	components := map[string]struct {
		direct bool
		scope  string
	}{}
	for _, component := range fragment.Components {
		components[component.Name] = struct {
			direct bool
			scope  string
		}{component.Direct, component.Scope}
	}
	if !components["parent"].direct || components["parent"].scope != "runtime" {
		t.Errorf("parent classification = %#v", components["parent"])
	}
	if components["child"].direct {
		t.Errorf("child classification = %#v", components["child"])
	}
	if components["dev-only"].scope != "dev" {
		t.Errorf("dev-only classification = %#v", components["dev-only"])
	}
}

func TestProfileFSUsesManifestWhenNoLockEntryExists(t *testing.T) {
	filesystem := fstest.MapFS{
		"web/package.json": &fstest.MapFile{Data: []byte(`{
			"dependencies":{"exact":"1.2.3-beta.1","ranged":"^4.0.0"},
			"devDependencies":{"dev":"2.0.0"}
		}`)},
	}

	fragment, err := ProfileFS(filesystem)
	if err != nil {
		t.Fatalf("ProfileFS: %v", err)
	}
	if len(fragment.Components) != 3 {
		t.Fatalf("components = %#v", fragment.Components)
	}
	for _, component := range fragment.Components {
		if !component.Direct || component.SourcePath != "web/package.json" {
			t.Errorf("manifest component = %#v", component)
		}
		switch component.Name {
		case "exact":
			if component.Version != "1.2.3-beta.1" {
				t.Errorf("exact version = %q", component.Version)
			}
		case "ranged":
			if component.Version != "" {
				t.Errorf("range reported as installed version: %q", component.Version)
			}
		case "dev":
			if component.Scope != "dev" {
				t.Errorf("dev scope = %q", component.Scope)
			}
		}
	}
}

func TestProfileFSKeepsIndependentPackageRootsSeparate(t *testing.T) {
	filesystem := fstest.MapFS{
		"a/package.json":      &fstest.MapFile{Data: []byte(`{"dependencies":{"shared":"1.0.0"}}`)},
		"a/package-lock.json": &fstest.MapFile{Data: []byte(`{"lockfileVersion":3,"packages":{"":{"dependencies":{"shared":"1.0.0"}},"node_modules/shared":{"version":"1.0.0"}}}`)},
		"b/package.json":      &fstest.MapFile{Data: []byte(`{"dependencies":{"shared":"2.0.0"}}`)},
	}

	fragment, err := ProfileFS(filesystem)
	if err != nil {
		t.Fatalf("ProfileFS: %v", err)
	}
	if len(fragment.Components) != 2 {
		t.Fatalf("components = %#v", fragment.Components)
	}
	if fragment.Components[0].SourcePath != "a/package-lock.json" || fragment.Components[0].Version != "1.0.0" {
		t.Errorf("locked component = %#v", fragment.Components[0])
	}
	if fragment.Components[1].SourcePath != "b/package.json" || fragment.Components[1].Version != "2.0.0" {
		t.Errorf("manifest component = %#v", fragment.Components[1])
	}
}

func TestProfileFSRejectsMalformedUnsupportedAndOversizedFiles(t *testing.T) {
	t.Run("malformed manifest", func(t *testing.T) {
		_, err := ProfileFS(fstest.MapFS{"package.json": &fstest.MapFile{Data: []byte(`{"dependencies":`)}})
		if err == nil || !strings.Contains(err.Error(), "package.json") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("unsupported lockfile", func(t *testing.T) {
		_, err := ProfileFS(fstest.MapFS{"package-lock.json": &fstest.MapFile{Data: []byte(`{"lockfileVersion":1}`)}})
		if !errors.Is(err, ErrUnsupportedLockfile) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("oversized manifest", func(t *testing.T) {
		profiler, err := NewProfiler(Limits{MaxFileSize: 8, MaxFiles: 10, MaxDepth: 4})
		if err != nil {
			t.Fatalf("NewProfiler: %v", err)
		}
		_, err = profiler.ProfileFS(fstest.MapFS{"package.json": &fstest.MapFile{Data: []byte(`{"name":"too-large"}`)}})
		if !errors.Is(err, ErrFileTooLarge) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestProfileFSLimitsTraversal(t *testing.T) {
	filesystem := fstest.MapFS{
		"a/package.json": &fstest.MapFile{Data: []byte(`{}`)},
		"b/package.json": &fstest.MapFile{Data: []byte(`{}`)},
	}

	fileLimited, err := NewProfiler(Limits{MaxFileSize: 100, MaxFiles: 1, MaxDepth: 10})
	if err != nil {
		t.Fatalf("NewProfiler: %v", err)
	}
	if _, err := fileLimited.ProfileFS(filesystem); !errors.Is(err, ErrTooManyFiles) {
		t.Fatalf("file limit error = %v", err)
	}

	depthLimited, err := NewProfiler(Limits{MaxFileSize: 100, MaxFiles: 10, MaxDepth: 1})
	if err != nil {
		t.Fatalf("NewProfiler: %v", err)
	}
	if _, err := depthLimited.ProfileFS(filesystem); !errors.Is(err, ErrMaxDepth) {
		t.Fatalf("depth limit error = %v", err)
	}
}

func TestProfileFSSkipsDependencyAndUnsupportedManagerDirectories(t *testing.T) {
	filesystem := fstest.MapFS{
		"node_modules/ignored/package.json": &fstest.MapFile{Data: []byte(`not JSON`)},
		".pnpm/ignored/package.json":        &fstest.MapFile{Data: []byte(`not JSON`)},
		".yarn/ignored/package.json":        &fstest.MapFile{Data: []byte(`not JSON`)},
		"package.json":                      &fstest.MapFile{Data: []byte(`{"dependencies":{"kept":"1.0.0"}}`)},
		"pnpm-lock.yaml":                    &fstest.MapFile{Data: []byte(`unsupported`)},
		"yarn.lock":                         &fstest.MapFile{Data: []byte(`unsupported`)},
	}

	fragment, err := ProfileFS(filesystem)
	if err != nil {
		t.Fatalf("ProfileFS: %v", err)
	}
	if len(fragment.Components) != 1 || fragment.Components[0].Name != "kept" {
		t.Fatalf("components = %#v", fragment.Components)
	}
	if len(fragment.Ecosystems) != 1 || len(fragment.Ecosystems[0].Lockfiles) != 0 {
		t.Fatalf("ecosystems = %#v", fragment.Ecosystems)
	}
}
