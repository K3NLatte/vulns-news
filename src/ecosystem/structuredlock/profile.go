// Package structuredlock reads resolved registry dependencies without running package managers.
package structuredlock

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
	Components []domain.Component      `json:"components"`
	Ecosystems []domain.EcosystemUsage `json:"ecosystems"`
	Warnings   []string                `json:"warnings"`
}

type Limits struct {
	MaxFileSize   int64
	MaxFiles      int
	MaxDepth      int
	MaxComponents int
}

func DefaultLimits() Limits { return Limits{10 << 20, 100000, 64, 100000} }

type Profiler struct{ limits Limits }

func New() *Profiler { return &Profiler{DefaultLimits()} }
func NewProfiler(l Limits) (*Profiler, error) {
	if l.MaxFileSize <= 0 || l.MaxFiles <= 0 || l.MaxDepth <= 0 || l.MaxComponents <= 0 {
		return nil, errors.New("structuredlock limits must be positive")
	}
	return &Profiler{l}, nil
}
func Profile(root string) (Fragment, error) { return New().Profile(root) }

// Profile returns no partial inventory on parse, traversal, or resource-limit errors.
// os.Root confines reads; symlinks and special files are never intentionally opened.
func (p *Profiler) Profile(root string) (Fragment, error) {
	if p == nil {
		return Fragment{}, errors.New("nil structuredlock profiler")
	}
	if _, err := NewProfiler(p.limits); err != nil {
		return Fragment{}, err
	}
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
	s := &state{limit: p.limits.MaxComponents, seen: map[string]bool{}}
	files := 0
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		if depth > p.limits.MaxDepth {
			return errors.New("structuredlock depth limit exceeded")
		}
		d, err := r.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		for {
			entries, readErr := d.ReadDir(128)
			for _, e := range entries {
				files++
				if files > p.limits.MaxFiles {
					return errors.New("structuredlock file limit exceeded")
				}
				name := path.Join(dir, e.Name())
				if e.Type()&os.ModeSymlink != 0 {
					s.warn(name, "symlink skipped")
					continue
				}
				if e.IsDir() {
					switch e.Name() {
					case ".git", "node_modules", ".yarn", ".pnpm-store", ".venv", "venv", "target":
						continue
					}
					if err := walk(name, depth+1); err != nil {
						return err
					}
					continue
				}
				eco := ecosystem(e.Name())
				if eco == "" {
					continue
				}
				info, err := r.Lstat(name)
				if err != nil {
					return err
				}
				if !info.Mode().IsRegular() {
					s.warn(name, "special file skipped")
					continue
				}
				if info.Size() > p.limits.MaxFileSize {
					return fmt.Errorf("%s: file size limit exceeded", name)
				}
				f, err := r.Open(name)
				if err != nil {
					return err
				}
				opened, err := f.Stat()
				if err != nil {
					f.Close()
					return err
				}
				if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
					f.Close()
					return fmt.Errorf("%s: file changed during traversal", name)
				}
				b, err := io.ReadAll(io.LimitReader(f, p.limits.MaxFileSize+1))
				f.Close()
				if err != nil {
					return err
				}
				if int64(len(b)) > p.limits.MaxFileSize {
					return fmt.Errorf("%s: file size limit exceeded", name)
				}
				if err := s.parse(name, b); err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				s.fragment.Ecosystems = append(s.fragment.Ecosystems, domain.EcosystemUsage{Name: eco, Lockfiles: []string{name}})
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
		return nil
	}
	if err := walk(".", 0); err != nil {
		return Fragment{}, err
	}
	sort.Slice(s.fragment.Components, func(i, j int) bool {
		a, b := s.fragment.Components[i], s.fragment.Components[j]
		return a.SourcePath+"\x00"+a.PURL < b.SourcePath+"\x00"+b.PURL
	})
	usages := map[string][]string{}
	for _, e := range s.fragment.Ecosystems {
		usages[e.Name] = append(usages[e.Name], e.Lockfiles...)
	}
	s.fragment.Ecosystems = nil
	for eco, locks := range usages {
		sort.Strings(locks)
		s.fragment.Ecosystems = append(s.fragment.Ecosystems, domain.EcosystemUsage{Name: eco, Lockfiles: locks})
	}
	sort.Slice(s.fragment.Ecosystems, func(i, j int) bool { return s.fragment.Ecosystems[i].Name < s.fragment.Ecosystems[j].Name })
	sort.Strings(s.fragment.Warnings)
	return s.fragment, nil
}
func ecosystem(name string) string {
	switch name {
	case "pnpm-lock.yaml", "yarn.lock":
		return "npm"
	case "Cargo.lock":
		return "crates.io"
	case "poetry.lock", "uv.lock":
		return "PyPI"
	}
	return ""
}
func exactSemver(version string) bool {
	if !semver.MatchString(version) {
		return false
	}
	base := strings.SplitN(version, "+", 2)[0]
	if i := strings.IndexByte(base, '-'); i >= 0 {
		for _, part := range strings.Split(base[i+1:], ".") {
			numeric := true
			for _, c := range part {
				if c < '0' || c > '9' {
					numeric = false
					break
				}
			}
			if numeric && len(part) > 1 && part[0] == '0' {
				return false
			}
		}
	}
	return true
}

type state struct {
	fragment Fragment
	seen     map[string]bool
	limit    int
	count    int
}

func (s *state) warn(file, msg string) {
	s.fragment.Warnings = append(s.fragment.Warnings, file+": "+msg)
}

var npmName = regexp.MustCompile(`^(?:@[a-z0-9._-]+/)?[a-z0-9._-]+$`)
var rustName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var pythonName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)
var pythonSeparators = regexp.MustCompile(`[-_.]+`)
var semver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
var pythonVersion = regexp.MustCompile(`(?i)^(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$`)

func (s *state) add(file, eco, name, version string) error {
	if name == "" || version == "" {
		return errors.New("registry package is missing name or version")
	}
	s.count++
	if s.count > s.limit {
		return errors.New("structuredlock component limit exceeded")
	}
	typ := ""
	valid := false
	switch eco {
	case "npm":
		typ = "npm"
		valid = npmName.MatchString(name) && exactSemver(version)
	case "crates.io":
		typ = "cargo"
		valid = rustName.MatchString(name) && exactSemver(version)
	case "PyPI":
		typ = "pypi"
		valid = pythonName.MatchString(name) && pythonVersion.MatchString(version)
		name = pythonSeparators.ReplaceAllString(strings.ToLower(name), "-")
		version = strings.ToLower(version)
	}
	if !valid {
		s.warn(file, fmt.Sprintf("invalid or unsupported exact identity %q@%q skipped", name, version))
		return nil
	}
	parts := strings.Split(name, "/")
	for i := range parts {
		parts[i] = url.QueryEscape(parts[i])
		parts[i] = strings.ReplaceAll(parts[i], "@", "%40")
	}
	purl := "pkg:" + typ + "/" + strings.Join(parts, "/") + "@" + url.QueryEscape(version)
	key := file + "\x00" + purl
	if s.seen[key] {
		return nil
	}
	s.seen[key] = true
	c := domain.Component{ID: fmt.Sprintf("%x", sha256.Sum256([]byte(key))), PURL: purl, Ecosystem: eco, Name: name, Version: version, SourcePath: file}
	if strings.HasPrefix(name, "@") {
		c.Namespace = strings.SplitN(name, "/", 2)[0]
	}
	s.fragment.Components = append(s.fragment.Components, c)
	return nil
}
