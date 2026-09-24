// Package lockprofile inventories static dependency facts without running builds
// or resolving dependencies. See README.md for format and safety limitations.
package lockprofile

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"vulns-news/src/domain"
	"vulns-news/src/traversal"
)

// Fragment contains declarations, not a fully resolved dependency graph.
type Fragment struct {
	Ecosystems []domain.EcosystemUsage
	Components []domain.Component
	Warnings   []string
}

const (
	maxFileBytes  = 4 << 20
	maxTotalBytes = 32 << 20
	maxEntries    = 100000
	maxDepth      = 64
)

type format struct {
	ecosystem string
	manifest  bool
	parse     func(*Fragment, string, []byte) error
}

var formats = map[string]format{
	"Pipfile.lock":       {"pypi", false, parsePip},
	"composer.lock":      {"packagist", false, parseComposer},
	"packages.lock.json": {"nuget", false, parseNuget},
	"Package.resolved":   {"swift", false, parseSwift},
	"package.resolved":   {"swift", false, parseSwift},
	"gradle.lockfile":    {"maven", false, parseGradle},
	"Gemfile.lock":       {"gem", false, parseGem},
	"pom.xml":            {"maven", true, parsePOM},
}

// Profile scans a non-symlink directory using confined os.Root operations. It
// returns an empty fragment on error. Use an immutable checkout: os.Root prevents
// escape, but cannot provide a snapshot or eliminate in-root replacement races.
func Profile(root string) (Fragment, error) {
	return ProfileWithTraversal(root, nil)
}

// ProfileWithTraversal profiles root with an optional directory enumeration cache.
func ProfileWithTraversal(root string, cache *traversal.Cache) (Fragment, error) {
	if strings.TrimSpace(root) == "" {
		return Fragment{}, errors.New("empty profile root")
	}
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil {
		return Fragment{}, err
	}
	if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return Fragment{}, errors.New("profile root must be a non-symlink directory")
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return Fragment{}, err
	}
	defer r.Close()
	var files []string
	entries := 0
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		if depth > maxDepth {
			return fmt.Errorf("%s: traversal depth limit exceeded", dir)
		}
		info, err := r.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%s: directory changed during traversal", dir)
		}
		d, err := r.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		for {
			batch, readErr := cache.ReadDir(dir, d, 1)
			for _, e := range batch {
				entries++
				if entries > maxEntries {
					return errors.New("traversal entry limit exceeded")
				}
				name := path.Join(dir, e.Name())
				if e.Type()&fs.ModeSymlink != 0 {
					continue
				}
				if e.IsDir() {
					switch e.Name() {
					case ".git", "node_modules", "vendor", ".gradle", ".build":
						continue
					}
					if err := walk(name, depth+1); err != nil {
						return err
					}
				} else if e.Type().IsRegular() {
					if _, ok := formats[e.Name()]; ok {
						files = append(files, name)
					}
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
	sort.Strings(files)
	var result Fragment
	usages := map[string]*domain.EcosystemUsage{}
	total := 0
	for _, file := range files {
		data, err := readFile(r, file, min(maxFileBytes, maxTotalBytes-total))
		if err != nil {
			return Fragment{}, fmt.Errorf("%s: %w", file, err)
		}
		total += len(data)
		spec := formats[path.Base(file)]
		if err := spec.parse(&result, file, data); err != nil {
			return Fragment{}, fmt.Errorf("%s: %w", file, err)
		}
		u := usages[spec.ecosystem]
		if u == nil {
			u = &domain.EcosystemUsage{Name: spec.ecosystem}
			usages[spec.ecosystem] = u
		}
		if spec.manifest {
			u.Manifests = append(u.Manifests, file)
		} else {
			u.Lockfiles = append(u.Lockfiles, file)
		}
	}
	for _, u := range usages {
		result.Ecosystems = append(result.Ecosystems, *u)
	}
	sort.Slice(result.Ecosystems, func(i, j int) bool { return result.Ecosystems[i].Name < result.Ecosystems[j].Name })
	sort.Slice(result.Components, func(i, j int) bool { return result.Components[i].ID < result.Components[j].ID })
	unique := result.Components[:0]
	for _, c := range result.Components {
		if len(unique) == 0 || unique[len(unique)-1].ID != c.ID {
			unique = append(unique, c)
		}
	}
	result.Components = unique
	sort.Strings(result.Warnings)
	return result, nil
}

func readFile(r *os.Root, name string, budget int) ([]byte, error) {
	info, err := r.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input is no longer a regular file")
	}
	if info.Size() > int64(budget) {
		return nil, errors.New("input byte limit exceeded")
	}
	f, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("input changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(budget)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > budget {
		return nil, errors.New("input byte limit exceeded")
	}
	return data, nil
}
func (f *Fragment) warn(file, message string) { f.Warnings = append(f.Warnings, file+": "+message) }
func (f *Fragment) add(file, eco, namespace, name, version, scope string, direct bool) {
	purl := "pkg:" + eco + "/"
	if namespace != "" {
		purl += url.PathEscape(namespace) + "/"
	}
	purl += url.PathEscape(name)
	key := strings.Join([]string{file, purl, version, scope, fmt.Sprint(direct)}, "\x00")
	f.Components = append(f.Components, domain.Component{ID: fmt.Sprintf("%s-%x", eco, sha256.Sum256([]byte(key))), PURL: purl, Ecosystem: eco, Namespace: namespace, Name: name, Version: version, Scope: scope, Direct: direct, SourcePath: file})
}
func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func exact(v string) bool {
	if v == "" || strings.ContainsAny(v, "<>=~^*[],(){}$|/\\:@?#") {
		return false
	}
	for _, c := range v {
		if unicode.IsSpace(c) || unicode.IsControl(c) {
			return false
		}
	}
	return true
}
