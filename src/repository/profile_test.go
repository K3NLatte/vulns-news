package repository

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"vulns-news/src/domain"
)

func TestProfileNPMComposesRepositoryProfile(t *testing.T) {
	root := t.TempDir()
	writeProfileFile(t, root, "package.json", `{
		"dependencies": {"@example/archive": "1.3.0", "express": "4.21.0"}
	}`)
	writeProfileFile(t, root, "src/index.ts", "export const answer: number = 42\n")
	writeProfileFile(t, root, "src/helper.js", "module.exports = 42\n")

	profiledAt := time.Date(2026, time.September, 25, 1, 2, 3, 0, time.FixedZone("JST", 9*60*60))
	acquired := &AcquiredRepository{
		Identity: domain.RepositoryIdentity{
			ID:           "example/project",
			CanonicalURL: "https://github.com/example/project",
			Ref:          "main",
			CommitSHA:    "0123456789012345678901234567890123456789",
		},
		Path: root,
	}

	profile, err := ProfileNPM(acquired, profiledAt)
	if err != nil {
		t.Fatalf("ProfileNPM() error = %v", err)
	}
	if profile.Repository != acquired.Identity {
		t.Fatalf("Repository = %#v, want %#v", profile.Repository, acquired.Identity)
	}
	if !profile.ProfiledAt.Equal(profiledAt.UTC()) {
		t.Fatalf("ProfiledAt = %v, want %v", profile.ProfiledAt, profiledAt.UTC())
	}
	if len(profile.Ecosystems) != 1 || profile.Ecosystems[0].Name != "npm" {
		t.Fatalf("Ecosystems = %#v, want npm", profile.Ecosystems)
	}
	if len(profile.Components) != 2 {
		t.Fatalf("Components length = %d, want 2", len(profile.Components))
	}

	languages := languageMap(profile.Languages)
	if len(languages) != 2 {
		t.Fatalf("Languages = %#v, want JavaScript and TypeScript", profile.Languages)
	}
	assertPercentage(t, languages["JavaScript"], 50)
	assertPercentage(t, languages["TypeScript"], 50)

	products := productMap(profile.Products)
	scoped, ok := products["archive"]
	if !ok {
		t.Fatalf("Products = %#v, missing scoped package product", profile.Products)
	}
	if scoped.Vendor != "example" || scoped.Ecosystem != "npm" || scoped.Version != "1.3.0" {
		t.Fatalf("scoped product = %#v", scoped)
	}
	if len(scoped.Aliases) != 2 || scoped.Aliases[0] != "@example/archive" || scoped.Aliases[1] != "archive" {
		t.Fatalf("scoped aliases = %#v", scoped.Aliases)
	}

	unscoped, ok := products["express"]
	if !ok {
		t.Fatalf("Products = %#v, missing unscoped package product", profile.Products)
	}
	if unscoped.Vendor != "" || unscoped.Ecosystem != "npm" || len(unscoped.Aliases) != 1 || unscoped.Aliases[0] != "express" {
		t.Fatalf("unscoped product = %#v", unscoped)
	}
}

func TestProfileNPMEmptyRepository(t *testing.T) {
	root := t.TempDir()
	acquired := &AcquiredRepository{
		Identity: domain.RepositoryIdentity{ID: "example/empty", CommitSHA: "0123456789012345678901234567890123456789"},
		Path:     root,
	}

	profile, err := ProfileNPM(acquired, time.Time{})
	if err != nil {
		t.Fatalf("ProfileNPM() error = %v", err)
	}
	if len(profile.Languages) != 0 || len(profile.Ecosystems) != 0 || len(profile.Components) != 0 || len(profile.Products) != 0 {
		t.Fatalf("empty profile contains detected data: %#v", profile)
	}
}

func TestProfileNPMRequiresAcquiredRepository(t *testing.T) {
	if _, err := ProfileNPM(nil, time.Now()); err == nil {
		t.Fatal("ProfileNPM(nil) error = nil, want error")
	}
	if _, err := ProfileNPM(&AcquiredRepository{}, time.Now()); err == nil {
		t.Fatal("ProfileNPM(empty path) error = nil, want error")
	}
}

func writeProfileFile(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func languageMap(languages []domain.LanguageUsage) map[string]domain.LanguageUsage {
	result := make(map[string]domain.LanguageUsage, len(languages))
	for _, language := range languages {
		result[language.Name] = language
	}
	return result
}

func productMap(products []domain.ProductCandidate) map[string]domain.ProductCandidate {
	result := make(map[string]domain.ProductCandidate, len(products))
	for _, product := range products {
		result[product.Name] = product
	}
	return result
}

func assertPercentage(t *testing.T, language domain.LanguageUsage, want float64) {
	t.Helper()
	if language.Percentage == nil || *language.Percentage != want {
		t.Fatalf("language percentage = %#v, want %.1f", language.Percentage, want)
	}
}
