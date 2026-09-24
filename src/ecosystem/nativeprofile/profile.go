// Package nativeprofile inventories native dependency metadata without executing sources.
package nativeprofile

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

	"vulns-news/src/domain"
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
	fragment Fragment
	seen     map[string]bool
}

// Profile returns no partial inventory on decoding, traversal, or limit errors.
func Profile(root string) (Fragment, error) {
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
	usages := map[string]*domain.EcosystemUsage{}
	entries, total := 0, 0
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		if depth > maxDepth {
			return errors.New("nativeprofile depth limit exceeded")
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
			batch, readErr := d.ReadDir(128)
			for _, e := range batch {
				entries++
				if entries > maxEntries {
					return errors.New("nativeprofile entry limit exceeded")
				}
				file := path.Join(dir, e.Name())
				if e.Type()&os.ModeSymlink != 0 {
					s.warn(file, "symlink skipped")
					continue
				}
				if e.IsDir() {
					if e.Name() == ".git" {
						continue
					}
					if err := walk(file, depth+1); err != nil {
						return err
					}
					continue
				}
				eco := ecosystem(e.Name())
				if eco == "" {
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
					return fmt.Errorf("%s: byte limit exceeded", file)
				}
				if err := s.parse(file, b); err != nil {
					return fmt.Errorf("%s: %w", file, err)
				}
				if usages[eco] == nil {
					usages[eco] = &domain.EcosystemUsage{Name: eco}
				}
				if e.Name() == "vcpkg.json" {
					usages[eco].Manifests = append(usages[eco].Manifests, file)
				} else {
					usages[eco].Lockfiles = append(usages[eco].Lockfiles, file)
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
	for _, eco := range keys(usages) {
		u := usages[eco]
		sort.Strings(u.Manifests)
		sort.Strings(u.Lockfiles)
		s.fragment.Ecosystems = append(s.fragment.Ecosystems, *u)
	}
	sort.Slice(s.fragment.Components, func(i, j int) bool { return s.fragment.Components[i].ID < s.fragment.Components[j].ID })
	sort.Strings(s.fragment.Warnings)
	return s.fragment, nil
}
func ecosystem(name string) string {
	switch name {
	case "conan.lock":
		return "Conan"
	case "vcpkg.json":
		return "vcpkg"
	case "Podfile.lock":
		return "CocoaPods"
	case "Manifest.toml":
		return "Julia"
	}
	return ""
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
func (s *state) add(file, eco, name, version, identity string) error {
	typ, namespace := "generic", strings.ToLower(eco)
	switch eco {
	case "Conan":
		typ = "conan"
		namespace = ""
	case "CocoaPods":
		typ = "cocoapods"
		namespace = ""
	}
	purl := "pkg:" + typ + "/"
	if namespace != "" {
		purl += namespace + "/"
	}
	parts := strings.Split(name, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	purl += strings.Join(parts, "/")
	if eco == "Julia" {
		purl += "?uuid=" + url.QueryEscape(identity)
	}
	key := strings.Join([]string{file, purl, version, identity}, "\x00")
	if s.seen[key] {
		return nil
	}
	s.seen[key] = true
	if len(s.seen) > maxComponents {
		return errors.New("nativeprofile component limit exceeded")
	}
	s.fragment.Components = append(s.fragment.Components, domain.Component{ID: fmt.Sprintf("%x", sha256.Sum256([]byte(key))), PURL: purl, Ecosystem: eco, Name: name, Version: version, Scope: identity, SourcePath: file})
	return nil
}
