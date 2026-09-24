// Package extralock inventories pinned dependencies without executing package managers.
package extralock

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"vulns-news/src/domain"
)

type Fragment struct {
	Components []domain.Component
	Ecosystems []domain.EcosystemUsage
	Warnings   []string
}

type limits struct{ fileBytes, totalBytes, entries, depth, components int }

var defaultLimits = limits{4 << 20, 32 << 20, 100000, 64, 100000}

type state struct {
	Fragment
	usages  map[string]map[string]bool
	seen    map[string]bool
	limits  limits
	records int
}

// Profile reads a non-symlink directory. Errors return an empty fragment.
// Use a stable checkout: os.Root confines access but does not provide a snapshot.
func Profile(root string) (Fragment, error) { return profile(root, defaultLimits) }

func profile(root string, lim limits) (Fragment, error) {
	if strings.TrimSpace(root) == "" {
		return Fragment{}, errors.New("empty profile root")
	}
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
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
	s := &state{usages: map[string]map[string]bool{}, seen: map[string]bool{}, limits: lim}
	var files []string
	entries := 0
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		if depth > lim.depth {
			return errors.New("traversal depth limit exceeded")
		}
		before, err := r.Lstat(dir)
		if err != nil {
			return err
		}
		if !before.IsDir() {
			return fmt.Errorf("%s: directory changed during traversal", dir)
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
		if !after.IsDir() || !os.SameFile(before, after) {
			return fmt.Errorf("%s: directory changed during open", dir)
		}
		for {
			batch, readErr := d.ReadDir(128)
			for _, entry := range batch {
				entries++
				if entries > lim.entries {
					return errors.New("traversal entry limit exceeded")
				}
				name := path.Join(dir, entry.Name())
				st, err := r.Lstat(name)
				if err != nil {
					return err
				}
				if st.Mode()&os.ModeSymlink != 0 {
					s.warn(name, "symlink skipped")
					continue
				}
				if st.IsDir() {
					switch entry.Name() {
					case ".git", "node_modules", ".venv":
						continue
					}
					if err := walk(name, depth+1); err != nil {
						return err
					}
				} else if supported(entry.Name()) {
					if !st.Mode().IsRegular() {
						s.warn(name, "special file skipped")
						continue
					}
					files = append(files, name)
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
	total := 0
	for _, file := range files {
		b, err := readBounded(r, file, min(lim.fileBytes, lim.totalBytes-total))
		if err != nil {
			return Fragment{}, fmt.Errorf("%s: %w", file, err)
		}
		total += len(b)
		if err := s.parse(file, b); err != nil {
			return Fragment{}, fmt.Errorf("%s: %w", file, err)
		}
	}
	for eco, paths := range s.usages {
		usage := domain.EcosystemUsage{Name: eco}
		for file := range paths {
			if path.Base(file) == "packages.config" {
				usage.Manifests = append(usage.Manifests, file)
			} else {
				usage.Lockfiles = append(usage.Lockfiles, file)
			}
		}
		sort.Strings(usage.Manifests)
		sort.Strings(usage.Lockfiles)
		s.Ecosystems = append(s.Ecosystems, usage)
	}
	sort.Slice(s.Ecosystems, func(i, j int) bool { return s.Ecosystems[i].Name < s.Ecosystems[j].Name })
	sort.Slice(s.Components, func(i, j int) bool { return s.Components[i].ID < s.Components[j].ID })
	sort.Strings(s.Warnings)
	return s.Fragment, nil
}

func supported(name string) bool {
	switch name {
	case "pubspec.lock", "deno.lock", "packages.config", "project.assets.json", "renv.lock":
		return true
	}
	return false
}
func readBounded(r *os.Root, file string, budget int) ([]byte, error) {
	info, err := r.Lstat(file)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input is no longer a regular file")
	}
	if info.Size() > int64(budget) {
		return nil, errors.New("input byte limit exceeded")
	}
	f, err := r.Open(file)
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
	b, err := io.ReadAll(io.LimitReader(f, int64(budget)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > budget {
		return nil, errors.New("input byte limit exceeded")
	}
	return b, nil
}
func (s *state) warn(file, msg string) { s.Warnings = append(s.Warnings, file+": "+msg) }
func (s *state) usage(file, eco string) {
	if s.usages[eco] == nil {
		s.usages[eco] = map[string]bool{}
	}
	s.usages[eco][file] = true
}
func (s *state) record() error {
	s.records++
	if s.records > s.limits.components {
		return errors.New("component record limit exceeded")
	}
	return nil
}

var semver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
var npmName = regexp.MustCompile(`^(?:@[a-z0-9._-]+/)?[a-z0-9._-]+$`)
var jsrName = regexp.MustCompile(`^@[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9_-]*$`)
var pubName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
var nugetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var nugetVersion = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
var cranName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.]*$`)
var cranVersion = regexp.MustCompile(`^[0-9]+(?:[.-][0-9]+)+$`)

func exactSemver(v string) bool {
	if !semver.MatchString(v) {
		return false
	}
	base := strings.SplitN(v, "+", 2)[0]
	if i := strings.IndexByte(base, '-'); i >= 0 {
		for _, p := range strings.Split(base[i+1:], ".") {
			if len(p) > 1 && p[0] == '0' && strings.Trim(p, "0123456789") == "" {
				return false
			}
		}
	}
	return true
}
func (s *state) add(file, eco, name, version, scope string, direct bool) error {
	valid := false
	switch eco {
	case "npm":
		valid = npmName.MatchString(name) && exactSemver(version)
	case "JSR":
		valid = jsrName.MatchString(name) && exactSemver(version)
	case "Pub":
		valid = pubName.MatchString(name) && exactSemver(version)
	case "NuGet":
		valid = nugetName.MatchString(name) && nugetVersion.MatchString(version)
		name = strings.ToLower(name)
	case "CRAN":
		valid = cranName.MatchString(name) && !strings.HasSuffix(name, ".") && cranVersion.MatchString(version)
	}
	if !valid {
		return fmt.Errorf("invalid pinned %s identity %q@%q", eco, name, version)
	}
	parts := strings.Split(name, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
		parts[i] = strings.ReplaceAll(parts[i], "@", "%40")
	}
	purl := "pkg:" + strings.ToLower(eco) + "/" + strings.Join(parts, "/")
	key := strings.Join([]string{file, purl, version, scope, fmt.Sprint(direct)}, "\x00")
	if s.seen[key] {
		return nil
	}
	s.seen[key] = true
	c := domain.Component{ID: fmt.Sprintf("%x", sha256.Sum256([]byte(key))), PURL: purl, Ecosystem: eco, Name: name, Version: version, SourcePath: file, Scope: scope, Direct: direct}
	if strings.HasPrefix(name, "@") {
		c.Namespace = strings.SplitN(name, "/", 2)[0]
	}
	s.Components = append(s.Components, c)
	s.usage(file, eco)
	return nil
}
func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
