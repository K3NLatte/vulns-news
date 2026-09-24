package repository

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/sourceinspect"
)

func TestProfileCombinesMixedRepositoryDeclarationsAndObservations(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		"package.json":     `{"dependencies":{"express":"4.21.0"}}`,
		"go.mod":           "module example.org/app\ngo 1.25\nrequire example.org/library v1.2.3\n",
		"requirements.txt": "Requests==2.32.3\nflask>=3\n",
		"web/index.js":     "export const ready = true;\n",
		"worker/main.py":   "import requests\n",
		"api/main.go":      "package api\nimport h \"net/http\"\nimport dep \"example.org/library\"\nfunc register() {\n h.HandleFunc(\"GET /archive\", nil)\n dep.Run()\n}\n",
	} {
		writeProfileFile(t, root, name, content)
	}
	acquired := &AcquiredRepository{Path: root, Identity: domain.RepositoryIdentity{ID: "example/mixed", CommitSHA: "abc123"}}
	at := time.Date(2026, 9, 25, 12, 0, 0, 0, time.FixedZone("JST", 9*60*60))
	profile, err := Profile(acquired, at)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Repository != acquired.Identity || profile.ProfiledAt != at.UTC() {
		t.Errorf("snapshot = %+v / %v", profile.Repository, profile.ProfiledAt)
	}
	if len(profile.Components) != 4 {
		t.Fatalf("components = %+v, want four declarations", profile.Components)
	}
	for _, want := range []struct{ name, ecosystem, version, path string }{
		{"express", "npm", "4.21.0", "package.json"},
		{"example.org/library", "Go", "v1.2.3", "go.mod"},
		{"requests", "pypi", "2.32.3", "requirements.txt"},
		{"flask", "pypi", "", "requirements.txt"},
	} {
		found := false
		for _, got := range profile.Components {
			if got.Name == want.name {
				found = true
				if got.Ecosystem != want.ecosystem || got.Version != want.version || got.SourcePath != want.path {
					t.Errorf("component %s = %+v", want.name, got)
				}
			}
		}
		if !found {
			t.Errorf("missing component %s", want.name)
		}
	}
	ecosystems := map[string]bool{}
	for _, e := range profile.Ecosystems {
		ecosystems[e.Name] = true
	}
	if !reflect.DeepEqual(ecosystems, map[string]bool{"npm": true, "Go": true, "pypi": true}) {
		t.Errorf("ecosystems = %+v", profile.Ecosystems)
	}
	languages := languageMap(profile.Languages)
	for _, name := range []string{"Go", "Python", "JavaScript"} {
		if _, ok := languages[name]; !ok {
			t.Errorf("missing language %s", name)
		}
	}
	if len(profile.Products) != 1 || profile.Products[0].Name != "express" {
		t.Errorf("product aliases must remain npm-only: %+v", profile.Products)
	}
	for _, want := range []domain.SourceObservation{
		{Kind: "import", File: "api/main.go", Line: 3, EndLine: 3, Package: "example.org/library"},
		{Kind: "imported_selector_call", File: "api/main.go", Line: 6, EndLine: 6, Package: "example.org/library", Symbol: "Run"},
		{Kind: "http_route_registration", File: "api/main.go", Line: 5, EndLine: 5, Package: "net/http", Symbol: "HandleFunc", Route: "GET /archive"},
	} {
		found := false
		for _, got := range profile.SourceObservations {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing observation %+v in %+v", want, profile.SourceObservations)
		}
	}
	warnings := strings.Join(profile.Warnings, "\n")
	for _, want := range []string{"requirements.txt:2:", "Dependency declarations are not a deployed inventory"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("warnings missing %q: %s", want, warnings)
		}
	}
	inspected, err := sourceinspect.Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(inspected.Limitations) == 0 {
		t.Fatal("source inspection lacks limitations")
	}
	for _, limitation := range inspected.Limitations {
		if !strings.Contains(warnings, limitation) {
			t.Errorf("dropped source limitation %q", limitation)
		}
	}
	again, err := Profile(acquired, at)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(profile, again) {
		t.Error("profile is not deterministic")
	}
}
