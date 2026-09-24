// Package staticprofile inventories Go and Python dependency declarations without
// executing repository code, resolving dependencies, or accessing the network.
package staticprofile

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

	"vulns-news/src/domain"
)

var (
	ErrFileTooLarge = errors.New("static profile file exceeds size limit")
	ErrTooManyFiles = errors.New("static profile repository exceeds entry limit")
	ErrMaxDepth     = errors.New("static profile repository exceeds depth limit")
	ErrTotalSize    = errors.New("static profile exceeds total read limit")
)

// Limits bounds traversal (including directories), individual reads, and total
// manifest bytes. Excluded directories count as entries but are not traversed.
type Limits struct {
	MaxFileSize  int64
	MaxTotalSize int64
	MaxFiles     int
	MaxDepth     int
}

func DefaultLimits() Limits {
	return Limits{MaxFileSize: 2 << 20, MaxTotalSize: 32 << 20, MaxFiles: 100_000, MaxDepth: 64}
}

// Warning describes omitted or unresolved syntax. Line is one-based, or zero
// for a whole-file warning. Paths are relative, slash-separated repository paths.
type Warning struct {
	SourcePath string `json:"source_path"`
	Line       int    `json:"line,omitempty"`
	Message    string `json:"message"`
}

type ProfileFragment struct {
	Ecosystems []domain.EcosystemUsage `json:"ecosystems"`
	Components []domain.Component      `json:"components"`
	Warnings   []Warning               `json:"warnings,omitempty"`
}

type Profiler struct{ limits Limits }

func New() *Profiler { return &Profiler{limits: DefaultLimits()} }

func NewProfiler(limits Limits) (*Profiler, error) {
	if limits.MaxFileSize <= 0 || limits.MaxTotalSize <= 0 || limits.MaxFiles <= 0 || limits.MaxDepth <= 0 {
		return nil, errors.New("static profiler limits must be positive")
	}
	return &Profiler{limits: limits}, nil
}

// Profile returns declarations, not a resolved build graph. Failures (including
// resource limits) return an empty fragment, never a silently truncated inventory.
func Profile(root string) (ProfileFragment, error) { return New().Profile(root) }

// Profile rejects a symlink root and skips descendant symlinks and special files.
// os.Root confines all opens to the root, including during concurrent renames.
// Profile an immutable checkout: concurrent modifications can change its contents.
func (p *Profiler) Profile(root string) (ProfileFragment, error) {
	if p == nil {
		return ProfileFragment{}, errors.New("nil static profiler")
	}
	if _, err := NewProfiler(p.limits); err != nil {
		return ProfileFragment{}, err
	}
	if strings.TrimSpace(root) == "" {
		return ProfileFragment{}, errors.New("empty profile root")
	}
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil {
		return ProfileFragment{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ProfileFragment{}, errors.New("profile root must be a non-symlink directory")
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return ProfileFragment{}, err
	}
	defer r.Close()
	var files []string
	seen := 0
	// Read one entry at a time: unlike WalkDir, a huge directory cannot force
	// an unbounded allocation before the entry budget is checked.
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		f, err := r.Open(dir)
		if err != nil {
			return err
		}
		defer f.Close()
		for {
			entries, readErr := f.ReadDir(1)
			for _, entry := range entries {
				seen++
				if seen > p.limits.MaxFiles {
					return ErrTooManyFiles
				}
				name := path.Join(dir, entry.Name())
				if entry.Type()&fs.ModeSymlink != 0 {
					continue
				}
				if entry.IsDir() && skipped(entry.Name()) {
					continue
				}
				if depth+1 > p.limits.MaxDepth {
					return fmt.Errorf("%s: %w", name, ErrMaxDepth)
				}
				if entry.IsDir() {
					if err := walk(name, depth+1); err != nil {
						return err
					}
				} else if entry.Type().IsRegular() && recognized(entry.Name()) {
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
		return ProfileFragment{}, err
	}
	sort.Strings(files)
	var result ProfileFragment
	usages := map[string]*domain.EcosystemUsage{}
	total := int64(0)
	for _, file := range files {
		eco := "pypi"
		if path.Base(file) == "go.mod" {
			eco = "Go"
		}
		usage := usages[eco]
		if usage == nil {
			usage = &domain.EcosystemUsage{Name: eco}
			usages[eco] = usage
		}
		if strings.HasSuffix(file, ".lock") {
			usage.Lockfiles = append(usage.Lockfiles, file)
			result.warn(file, 0, "unsupported lockfile; dependencies were not parsed")
			continue
		}
		usage.Manifests = append(usage.Manifests, file)
		data, err := readBounded(r, file, p.limits.MaxFileSize, p.limits.MaxTotalSize-total)
		if err != nil {
			return ProfileFragment{}, fmt.Errorf("%s: %w", file, err)
		}
		total += int64(len(data))
		if eco == "Go" {
			result.parseGo(file, string(data))
		} else {
			result.parseRequirements(file, string(data))
		}
	}
	for _, eco := range []string{"Go", "pypi"} {
		if u := usages[eco]; u != nil {
			result.Ecosystems = append(result.Ecosystems, *u)
		}
	}
	sort.Slice(result.Components, func(i, j int) bool { return result.Components[i].ID < result.Components[j].ID })
	// Repeated declarations in one source should have one stable identity.
	unique := result.Components[:0]
	for _, c := range result.Components {
		if len(unique) == 0 || unique[len(unique)-1].ID != c.ID {
			unique = append(unique, c)
		}
	}
	result.Components = unique
	return result, nil
}

func readBounded(root *os.Root, name string, max, remaining int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("manifest is no longer a regular file")
	}
	if info.Size() > max {
		return nil, ErrFileTooLarge
	}
	if info.Size() > remaining {
		return nil, ErrTotalSize
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Read at most the budget, then probe one byte without overflowing max+1.
	limit := min(max, remaining)
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, err
	}
	var probe [1]byte
	n, err := f.Read(probe[:])
	if n > 0 {
		if remaining < max {
			return nil, ErrTotalSize
		}
		return nil, ErrFileTooLarge
	}
	if err != nil && err != io.EOF {
		return nil, err
	}
	return data, nil
}

func skipped(name string) bool { return name == ".git" || name == "node_modules" || name == "vendor" }
func recognized(name string) bool {
	return name == "go.mod" || name == "requirements.txt" || name == "poetry.lock" || name == "uv.lock"
}
func (f *ProfileFragment) warn(source string, line int, message string) {
	f.Warnings = append(f.Warnings, Warning{SourcePath: source, Line: line, Message: message})
}
func (f *ProfileFragment) add(source, eco, name, version string, direct bool) {
	kind := eco
	if eco == "Go" {
		kind = "golang"
	}
	parts := strings.Split(name, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	purl := "pkg:" + kind + "/" + strings.Join(parts, "/")
	id := fmt.Sprintf("%s-%x", kind, sha256.Sum256([]byte(strings.Join([]string{source, name, version, fmt.Sprint(direct)}, "\x00"))))
	f.Components = append(f.Components, domain.Component{ID: id, PURL: purl, Ecosystem: eco, Name: name, Version: version, Direct: direct, Scope: "runtime", SourcePath: source})
}
