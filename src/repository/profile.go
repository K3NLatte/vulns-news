package repository

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"fmt"
	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/extralock"
	"vulns-news/src/ecosystem/lockprofile"
	"vulns-news/src/ecosystem/manifestextra"
	"vulns-news/src/ecosystem/nativeprofile"
	npmprofile "vulns-news/src/ecosystem/npm"
	"vulns-news/src/ecosystem/staticprofile"
	"vulns-news/src/ecosystem/structuredlock"
	"vulns-news/src/sourceinspect"
	"vulns-news/src/traversal"
)

const (
	maxLanguageFiles       = 100_000
	maxLanguageSourcePaths = 10
)

// ProfileNPM builds the first MVP repository profile. It parses npm metadata,
// detects common source languages by extension, and derives explicit product
// aliases from npm package identities for later NVD CPE candidate matching.
func ProfileNPM(acquired *AcquiredRepository, profiledAt time.Time) (domain.RepositoryProfile, error) {
	return profileNPMWithTraversal(acquired, profiledAt, nil)
}

func profileNPMWithTraversal(acquired *AcquiredRepository, profiledAt time.Time, cache *traversal.Cache) (domain.RepositoryProfile, error) {
	if acquired == nil {
		return domain.RepositoryProfile{}, errors.New("acquired repository is required")
	}
	if strings.TrimSpace(acquired.Path) == "" {
		return domain.RepositoryProfile{}, errors.New("acquired repository path is required")
	}
	fragment, err := npmprofile.ProfileFS(cache.WrapFS(os.DirFS(acquired.Path)))
	if err != nil {
		return domain.RepositoryProfile{}, err
	}
	languages, err := detectLanguagesWithTraversal(acquired.Path, cache)
	if err != nil {
		return domain.RepositoryProfile{}, err
	}
	return domain.RepositoryProfile{
		Repository: acquired.Identity,
		ProfiledAt: profiledAt.UTC(),
		Languages:  languages,
		Ecosystems: fragment.Ecosystems,
		Components: fragment.Components,
		Products:   npmProductCandidates(fragment.Components),
	}, nil
}

// Profile combines static declaration inventories and bounded Go source observations.
// Unsupported constructs are reported rather than interpreted as absence.
// Directory entries are shared only within this call; the checkout must remain
// unchanged until profiling completes.
func Profile(acquired *AcquiredRepository, profiledAt time.Time) (domain.RepositoryProfile, error) {
	return ProfileWithTraversal(acquired, profiledAt, traversal.New())
}

// ProfileWithTraversal allows explicit control of directory enumeration caching.
// A nil cache uses uncached traversal for compatibility checks. Otherwise, use a
// fresh cache for one stable checkout and do not share it between concurrent calls.
func ProfileWithTraversal(acquired *AcquiredRepository, profiledAt time.Time, cache *traversal.Cache) (domain.RepositoryProfile, error) {
	profile, err := profileNPMWithTraversal(acquired, profiledAt, cache)
	if err != nil {
		return domain.RepositoryProfile{}, err
	}
	extra, err := staticprofile.ProfileWithTraversal(acquired.Path, cache)
	if err != nil {
		return domain.RepositoryProfile{}, err
	}
	profile.Components = append(profile.Components, extra.Components...)
	profile.Ecosystems = append(profile.Ecosystems, extra.Ecosystems...)
	for _, warning := range extra.Warnings {
		if strings.HasSuffix(warning.SourcePath, "poetry.lock") || strings.HasSuffix(warning.SourcePath, "uv.lock") {
			continue
		}
		profile.Warnings = append(profile.Warnings, fmt.Sprintf("%s:%d: %s", warning.SourcePath, warning.Line, warning.Message))
	}
	locks, err := lockprofile.ProfileWithTraversal(acquired.Path, cache)
	if err != nil {
		return domain.RepositoryProfile{}, fmt.Errorf("profile lockfiles: %w", err)
	}
	structured, err := structuredlock.ProfileWithTraversal(acquired.Path, cache)
	if err != nil {
		return domain.RepositoryProfile{}, fmt.Errorf("profile structured lockfiles: %w", err)
	}
	profile.Components = append(profile.Components, locks.Components...)
	profile.Components = append(profile.Components, structured.Components...)
	profile.Ecosystems = append(profile.Ecosystems, locks.Ecosystems...)
	profile.Ecosystems = append(profile.Ecosystems, structured.Ecosystems...)
	profile.Warnings = append(profile.Warnings, locks.Warnings...)
	profile.Warnings = append(profile.Warnings, structured.Warnings...)
	additional, err := extralock.ProfileWithTraversal(acquired.Path, cache)
	if err != nil {
		return domain.RepositoryProfile{}, fmt.Errorf("profile additional lockfiles: %w", err)
	}
	manifests, err := manifestextra.ProfileWithTraversal(acquired.Path, cache)
	if err != nil {
		return domain.RepositoryProfile{}, fmt.Errorf("profile additional manifests: %w", err)
	}
	native, err := nativeprofile.ProfileWithTraversal(acquired.Path, cache)
	if err != nil {
		return domain.RepositoryProfile{}, fmt.Errorf("profile native dependencies: %w", err)
	}
	profile.Components = append(profile.Components, additional.Components...)
	profile.Components = append(profile.Components, manifests.Components...)
	profile.Components = append(profile.Components, native.Components...)
	profile.Ecosystems = append(profile.Ecosystems, additional.Ecosystems...)
	profile.Ecosystems = append(profile.Ecosystems, manifests.Ecosystems...)
	profile.Ecosystems = append(profile.Ecosystems, native.Ecosystems...)
	profile.Warnings = append(profile.Warnings, additional.Warnings...)
	profile.Warnings = append(profile.Warnings, manifests.Warnings...)
	profile.Warnings = append(profile.Warnings, native.Warnings...)
	coverageWarnings, err := dependencyCoverageWarningsWithTraversal(acquired.Path, cache)
	if err != nil {
		return domain.RepositoryProfile{}, fmt.Errorf("detect unsupported dependency formats: %w", err)
	}
	profile.Warnings = append(profile.Warnings, coverageWarnings...)
	normalizeProfile(&profile)
	// Product aliases remain npm-only, candidate-generating heuristics.
	profile.Products = nil
	for _, component := range profile.Components {
		if component.Ecosystem == "npm" {
			profile.Products = append(profile.Products, npmProductCandidates([]domain.Component{component})...)
		}
	}
	observations, err := sourceinspect.InspectWithTraversal(acquired.Path, cache)
	if err != nil {
		return domain.RepositoryProfile{}, fmt.Errorf("inspect source: %w", err)
	}
	profile.Warnings = append(profile.Warnings, observations.Limitations...)
	profile.Warnings = append(profile.Warnings, "Dependency declarations are not a deployed inventory. Non-npm range comparison and package-to-CPE identity mapping are not implemented; optional OSV exact-version queries provide separate provider evidence.")
	for _, observation := range observations.Findings {
		profile.SourceObservations = append(profile.SourceObservations, domain.SourceObservation{
			Kind: string(observation.Kind), File: observation.File, Line: observation.Line, EndLine: observation.EndLine,
			Package: observation.Package, Symbol: observation.Symbol, Route: observation.Route,
		})
	}
	return profile, nil
}

func npmProductCandidates(components []domain.Component) []domain.ProductCandidate {
	result := make([]domain.ProductCandidate, 0, len(components))
	for _, component := range components {
		name := component.Name
		vendor := ""
		product := name
		if strings.HasPrefix(name, "@") {
			parts := strings.SplitN(name, "/", 2)
			if len(parts) == 2 {
				vendor = strings.TrimPrefix(parts[0], "@")
				product = parts[1]
			}
		}
		if product == "" {
			continue
		}
		aliases := []string{name}
		if product != name {
			aliases = append(aliases, product)
		}
		result = append(result, domain.ProductCandidate{
			ID:         "product-" + component.ID,
			Ecosystem:  "npm",
			Vendor:     vendor,
			Name:       product,
			Version:    component.Version,
			Aliases:    aliases,
			CPEs:       []string{},
			SourcePath: component.SourcePath,
		})
	}
	return result
}

func detectLanguages(root string) ([]domain.LanguageUsage, error) {
	return detectLanguagesWithTraversal(root, nil)
}

func detectLanguagesWithTraversal(root string, cache *traversal.Cache) ([]domain.LanguageUsage, error) {
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("language detection requires a non-symlink directory")
	}
	confined, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer confined.Close()
	contentBytes := int64(0)
	const maxLanguageContentBytes = int64(8 << 20)
	counts := make(map[string]int)
	sources := make(map[string][]string)
	total := 0
	seen := 0
	visit := func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path != root {
			seen++
			if seen > maxLanguageFiles {
				return errors.New("repository exceeds language-detection file limit")
			}
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", ".pnpm", ".yarn":
				if path != root {
					return fs.SkipDir
				}
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		language := languageForFilename(entry.Name())
		if language == "" && ambiguousLanguageFilename(entry.Name()) {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			const prefixLimit = int64(16 << 10)
			if contentBytes >= maxLanguageContentBytes {
				return errors.New("language detection exceeds content-read limit")
			}
			file, err := confined.Open(relative)
			if err != nil {
				return err
			}
			stat, err := file.Stat()
			if err != nil {
				file.Close()
				return err
			}
			if !stat.Mode().IsRegular() {
				file.Close()
				return nil
			}
			prefix, readErr := io.ReadAll(io.LimitReader(file, min(prefixLimit+1, maxLanguageContentBytes-contentBytes)))
			closeErr := file.Close()
			if readErr != nil {
				return readErr
			}
			if closeErr != nil {
				return closeErr
			}
			contentBytes += int64(len(prefix))
			language = languageFromContent(entry.Name(), prefix)
		}
		if language == "" {
			return nil
		}
		counts[language]++
		total++
		if len(sources[language]) < maxLanguageSourcePaths {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			sources[language] = append(sources[language], filepath.ToSlash(relative))
		}
		return nil
	}
	if cache == nil {
		err = filepath.WalkDir(root, visit)
	} else {
		err = fs.WalkDir(cache.WrapFS(os.DirFS(root)), ".", func(relative string, entry fs.DirEntry, walkErr error) error {
			return visit(filepath.Join(root, filepath.FromSlash(relative)), entry, walkErr)
		})
	}
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]domain.LanguageUsage, 0, len(names))
	for _, name := range names {
		percentage := float64(counts[name]) * 100 / float64(total)
		result = append(result, domain.LanguageUsage{
			Name: name, Percentage: &percentage, SourcePaths: sources[name],
		})
	}
	return result, nil
}
