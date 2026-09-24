// Package manifestextra statically inventories additional Python and Rust manifests.
package manifestextra

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"vulns-news/src/domain"
	"vulns-news/src/traversal"
)

type Fragment struct {
	Components []domain.Component      `json:"components"`
	Ecosystems []domain.EcosystemUsage `json:"ecosystems"`
	Warnings   []string                `json:"warnings"`
}

const (
	maxDepth      = 32
	maxEntries    = 20000
	maxFileBytes  = 2 << 20
	maxTotalBytes = 16 << 20
	maxComponents = 50000
)

type state struct {
	fragment      Fragment
	seen          map[string]bool
	pythonSources bool
	cargoConfig   bool
}

// Profile returns no partial inventory on traversal, decoding, or limit errors.
func Profile(root string) (Fragment, error) { return profileWithTraversal(root, nil) }

// ProfileWithTraversal optionally reuses directory listings from cache.
// Use one stable root per cache and call profiles sequentially; nil disables caching.
func ProfileWithTraversal(root string, cache *traversal.Cache) (Fragment, error) {
	return profileWithTraversal(root, cache)
}

func profileWithTraversal(root string, cache *traversal.Cache) (Fragment, error) {
	if strings.TrimSpace(root) == "" {
		return Fragment{}, errors.New("empty profile root")
	}
	info, err := os.Lstat(filepath.Clean(root))
	if err != nil {
		return Fragment{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Fragment{}, errors.New("root must be a non-symlink directory")
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return Fragment{}, err
	}
	defer r.Close()
	s := &state{seen: map[string]bool{}}
	documents := map[string]map[string]any{}
	entries, total := 0, 0
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		if depth > maxDepth {
			return errors.New("manifestextra depth limit exceeded")
		}
		before, err := r.Lstat(dir)
		if err != nil {
			return err
		}
		if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: directory changed", dir)
		}
		d, err := r.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		after, err := d.Stat()
		if err != nil {
			return err
		}
		if !os.SameFile(before, after) {
			return fmt.Errorf("%s: directory changed", dir)
		}
		for {
			batch, readErr := cache.ReadDir(dir, d, 128)
			for _, e := range batch {
				entries++
				if entries > maxEntries {
					return errors.New("manifestextra entry limit exceeded")
				}
				file := path.Join(dir, e.Name())
				if e.Type()&os.ModeSymlink != 0 {
					if e.Name() == ".cargo" || (path.Base(dir) == ".cargo" && (e.Name() == "config" || e.Name() == "config.toml")) {
						s.cargoConfig = true
					}
					if e.Name() == "pyproject.toml" {
						s.pythonSources = true
					}
					s.warn(file, "symlink skipped")
					continue
				}
				if e.IsDir() {
					switch e.Name() {
					case ".git", "node_modules", ".venv", "venv", "target", "__pycache__":
						continue
					}
					if err := walk(file, depth+1); err != nil {
						return err
					}
					continue
				}
				if path.Base(dir) == ".cargo" && (e.Name() == "config" || e.Name() == "config.toml") {
					s.cargoConfig = true
					s.warn(file, "Cargo configuration present; registry provenance unresolved")
				}
				if e.Name() != "pyproject.toml" && e.Name() != "pdm.lock" && e.Name() != "Cargo.toml" {
					continue
				}
				st, err := r.Lstat(file)
				if err != nil {
					return err
				}
				if !st.Mode().IsRegular() {
					s.warn(file, "non-regular file skipped")
					continue
				}
				if st.Size() > maxFileBytes {
					return fmt.Errorf("%s: file byte limit exceeded", file)
				}
				f, err := r.Open(file)
				if err != nil {
					return err
				}
				opened, err := f.Stat()
				if err != nil {
					f.Close()
					return err
				}
				if !opened.Mode().IsRegular() || !os.SameFile(st, opened) {
					f.Close()
					return fmt.Errorf("%s: file changed", file)
				}
				b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
				f.Close()
				if err != nil {
					return err
				}
				total += len(b)
				if len(b) > maxFileBytes || total > maxTotalBytes {
					return errors.New("manifestextra byte limit exceeded")
				}
				var doc map[string]any
				if err := toml.Unmarshal(b, &doc); err != nil {
					return fmt.Errorf("%s: %w", file, err)
				}
				documents[file] = doc
				if e.Name() == "pyproject.toml" && hasPythonSources(doc) {
					s.pythonSources = true
				}
			}
			if readErr == io.EOF {
				return nil
			}
			if readErr != nil {
				return readErr
			}
		}
	}
	if err := walk(".", 0); err != nil {
		return Fragment{}, err
	}
	usages := map[string]*domain.EcosystemUsage{}
	for _, file := range keys(documents) {
		eco := "PyPI"
		if path.Base(file) == "Cargo.toml" {
			eco = "crates.io"
		}
		if usages[eco] == nil {
			usages[eco] = &domain.EcosystemUsage{Name: eco}
		}
		if path.Base(file) == "pdm.lock" {
			usages[eco].Lockfiles = append(usages[eco].Lockfiles, file)
		} else {
			usages[eco].Manifests = append(usages[eco].Manifests, file)
		}
		if err := s.parse(file, documents[file]); err != nil {
			return Fragment{}, fmt.Errorf("%s: %w", file, err)
		}
	}
	for _, eco := range keys(usages) {
		s.fragment.Ecosystems = append(s.fragment.Ecosystems, *usages[eco])
	}
	sort.Slice(s.fragment.Components, func(i, j int) bool { return s.fragment.Components[i].ID < s.fragment.Components[j].ID })
	sort.Strings(s.fragment.Warnings)
	return s.fragment, nil
}
func keys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func (s *state) warn(file, msg string) {
	s.fragment.Warnings = append(s.fragment.Warnings, file+": "+msg)
}
func (s *state) add(file, eco, name, version, scope string, direct bool) error {
	typ := "cargo"
	if eco == "PyPI" {
		if !pythonName.MatchString(name) {
			return fmt.Errorf("invalid Python package name %q", name)
		}
		typ = "pypi"
		name = separators.ReplaceAllString(strings.ToLower(name), "-")
	} else if !cargoName.MatchString(name) {
		return fmt.Errorf("invalid Cargo package name %q", name)
	}
	purl := "pkg:" + typ + "/" + url.PathEscape(name)
	if version != "" {
		purl += "@" + url.PathEscape(version)
	}
	key := strings.Join([]string{file, purl, scope}, "\x00")
	if s.seen[key] {
		return nil
	}
	s.seen[key] = true
	if len(s.seen) > maxComponents {
		return errors.New("manifestextra component limit exceeded")
	}
	s.fragment.Components = append(s.fragment.Components, domain.Component{ID: fmt.Sprintf("%x", sha256.Sum256([]byte(key))), PURL: purl, Ecosystem: eco, Name: name, Version: version, Scope: scope, Direct: direct, SourcePath: file})
	return nil
}
