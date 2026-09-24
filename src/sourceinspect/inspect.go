// Package sourceinspect produces bounded, syntactic source observations without
// executing code, loading dependencies, or making vulnerability claims.
package sourceinspect

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"vulns-news/src/traversal"
)

// Fixed budgets apply to one Inspect invocation. They bound work and retained
// input, not wall-clock time (filesystem operations may block).
const (
	MaxEntries    = 10000
	MaxFiles      = 512
	MaxFileBytes  = 1 << 20
	MaxTotalBytes = 16 << 20
	MaxDepth      = 32
	MaxFindings   = 20000
)

// ErrLimit indicates that inspection stopped at a fixed resource budget.
var ErrLimit = errors.New("source inspection resource limit exceeded")

// Never guess a dependency's declared package name from its path. This small
// allowlist supports common standard packages without loading any source.
var standardImportNames = map[string]string{
	"bytes": "bytes", "context": "context", "crypto/tls": "tls",
	"encoding/json": "json", "encoding/xml": "xml", "errors": "errors",
	"fmt": "fmt", "io": "io", "io/fs": "fs", "log": "log",
	"log/slog": "slog", "math": "math", "net": "net", "net/http": "http",
	"net/url": "url", "os": "os", "os/exec": "exec", "path": "path",
	"path/filepath": "filepath", "reflect": "reflect", "regexp": "regexp",
	"runtime": "runtime", "slices": "slices", "sort": "sort",
	"strconv": "strconv", "strings": "strings", "sync": "sync",
	"sync/atomic": "atomic", "testing": "testing", "time": "time",
	"unicode": "unicode", "unsafe": "unsafe",
}

// Kind describes syntax, never runtime behavior.
type Kind string

const (
	Import                Kind = "import"
	ImportedSelectorCall  Kind = "imported_selector_call"
	HTTPRouteRegistration Kind = "http_route_registration"
)

// Finding identifies a source observation. File is slash-separated and relative
// to the inspected root; Line and EndLine are one-based, physical source lines.
// Package is the imported path, not the enclosing Go package. Symbol is empty
// for imports. Route is populated only for literal net/http.HandleFunc patterns.
type Finding struct {
	Kind    Kind   `json:"kind"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	EndLine int    `json:"end_line"`
	Package string `json:"package"`
	Symbol  string `json:"symbol,omitempty"`
	Route   string `json:"route,omitempty"`
}

// Report is candidate evidence for a supplemental source-inspection profile.
// Complete means traversal and parsing completed within budgets, not that the
// program is understood or that all relevant calls have been identified.
type Report struct {
	Findings        []Finding `json:"findings"`
	Limitations     []string  `json:"limitations"`
	Complete        bool      `json:"complete"`
	FilesInspected  int       `json:"files_inspected"`
	BytesRead       int       `json:"bytes_read"`
	SymlinksSkipped int       `json:"symlinks_skipped"`
}

type source struct {
	name string
	file *ast.File
}

type inspector struct {
	cache   *traversal.Cache
	root    *os.Root
	fset    *token.FileSet
	report  Report
	entries int
	sources []source
}

// Inspect inspects regular .go files beneath root using only the standard
// library. It does not invoke Go tools, import dependencies, or execute code.
// Errors (including ErrLimit) return an incomplete report; callers must not
// treat an incomplete report or an empty result as negative security evidence.
func Inspect(root string) (Report, error) {
	return inspect(root, nil)
}

// InspectWithTraversal is Inspect with optional directory enumeration reuse.
// The cache must be used sequentially for one root with stable directory contents.
// A nil cache preserves uncached inspection.
func InspectWithTraversal(root string, cache *traversal.Cache) (Report, error) {
	return inspect(root, cache)
}

func inspect(root string, cache *traversal.Cache) (Report, error) {
	i := inspector{cache: cache, fset: token.NewFileSet(), report: Report{
		Findings: []Finding{},
		Limitations: []string{
			"Syntax observations only: no proof of execution, reachability, vulnerability, or CVE usage; no CVE rules are applied.",
			"No type checking or dependency loading; unaliased imports resolve only through a fixed standard-library name allowlist. Other packages require explicit aliases.",
			"A selector in call position may denote a function, function-valued variable, or type conversion; this inspection does not distinguish them.",
			"Only direct imported-package selector calls are observed; dot imports, function aliases, methods, interfaces, reflection, and dynamic dispatch are not resolved.",
			"All regular .go files are considered, including tests, generated files, vendor trees, and files excluded by build constraints; no build configuration is selected.",
			"Symlinks and non-regular files are skipped. Inspection is not an atomic filesystem snapshot; concurrent changes can make evidence inconsistent.",
			"Fixed entry, file, byte, depth, and finding budgets apply; filesystem blocking and parser wall-clock time are not bounded.",
		},
	}}
	// Clean trailing separators so Lstat cannot dereference a symlink root
	// merely because the caller supplied a trailing slash.
	if root != "" {
		root = filepath.Clean(root)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return i.report, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return i.report, fmt.Errorf("inspection root must be a non-symlink directory")
	}
	i.root, err = os.OpenRoot(root)
	if err != nil {
		return i.report, err
	}
	defer i.root.Close()
	opened, err := i.root.Stat(".")
	if err != nil {
		return i.report, err
	}
	if !os.SameFile(info, opened) {
		return i.report, fmt.Errorf("inspection root changed during open")
	}
	if err := i.walk(".", 0); err != nil {
		return i.report, err
	}
	// Parse all files first so package-level declarations in other files can
	// conservatively veto a putative imported-package reference.
	if err := i.collect(); err != nil {
		return i.report, err
	}
	i.report.Complete = true
	return i.report, nil
}

func (i *inspector) walk(dir string, depth int) error {
	if depth > MaxDepth {
		return fmt.Errorf("%w: directory depth", ErrLimit)
	}
	f, err := i.openChecked(dir, true)
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		entries, readErr := i.cache.ReadDir(dir, f, 64)
		for _, entry := range entries {
			i.entries++
			if i.entries > MaxEntries {
				return fmt.Errorf("%w: directory entries", ErrLimit)
			}
			name := filepath.Join(dir, entry.Name())
			info, err := i.root.Lstat(name)
			if err != nil {
				return fmt.Errorf("stat %s: %w", name, err)
			}
			switch {
			case info.Mode()&os.ModeSymlink != 0:
				i.report.SymlinksSkipped++
			case info.IsDir():
				if err := i.walk(name, depth+1); err != nil {
					return err
				}
			case info.Mode().IsRegular() && strings.HasSuffix(name, ".go"):
				if err := i.parse(name); err != nil {
					return err
				}
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("read directory %s: %w", dir, readErr)
		}
	}
}

// OpenRoot confines resolution to the root even during rename/symlink races.
// Identity checks reject replacements detectable between stat and open; this
// is deliberately not advertised as an atomic no-follow filesystem snapshot.
func (i *inspector) openChecked(name string, directory bool) (*os.File, error) {
	before, err := i.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || (directory && !before.IsDir()) || (!directory && !before.Mode().IsRegular()) {
		return nil, fmt.Errorf("unsupported or changed source path: %s", name)
	}
	f, err := i.root.Open(name)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		f.Close()
		return nil, fmt.Errorf("source path changed during inspection: %s", name)
	}
	return f, nil
}

func (i *inspector) parse(name string) error {
	if len(i.sources) >= MaxFiles {
		return fmt.Errorf("%w: Go files", ErrLimit)
	}
	f, err := i.openChecked(name, false)
	if err != nil {
		return err
	}
	defer f.Close()
	remaining := MaxTotalBytes - i.report.BytesRead
	budget := min(MaxFileBytes, remaining)
	data, err := io.ReadAll(io.LimitReader(f, int64(budget)+1))
	i.report.BytesRead += len(data)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	if len(data) > budget {
		return fmt.Errorf("%w: source bytes in %s", ErrLimit, name)
	}
	// Do not use SkipObjectResolution: Ident.Obj supplies lexical shadowing
	// information for parameters, receivers, locals, and type parameters.
	file, err := parser.ParseFile(i.fset, name, data, parser.AllErrors)
	if err != nil {
		return fmt.Errorf("parse %s: %w", name, err)
	}
	i.sources = append(i.sources, source{filepath.ToSlash(name), file})
	i.report.FilesInspected++
	return nil
}

func (i *inspector) collect() error {
	sort.Slice(i.sources, func(a, b int) bool { return i.sources[a].name < i.sources[b].name })
	packageNames := map[string]map[string]bool{}
	key := func(s source) string { return path.Dir(s.name) + "/" + s.file.Name.Name }
	for _, s := range i.sources {
		names := packageNames[key(s)]
		if names == nil {
			names = map[string]bool{}
			packageNames[key(s)] = names
		}
		for name := range s.file.Scope.Objects {
			names[name] = true
		}
	}
	for _, s := range i.sources {
		imports := map[string]string{}
		ambiguous := map[string]bool{}
		dotImport := false
		for _, spec := range s.file.Imports {
			pkg, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			if err := i.add(s, spec, Import, pkg, "", ""); err != nil {
				return err
			}
			name := standardImportNames[pkg]
			if spec.Name != nil {
				name = spec.Name.Name
			}
			if name == "." {
				dotImport = true
			}
			if name == "." || name == "_" || !token.IsIdentifier(name) {
				continue
			}
			if _, exists := imports[name]; exists {
				ambiguous[name] = true
			}
			imports[name] = pkg
		}
		var collectErr error
		ast.Inspect(s.file, func(node ast.Node) bool {
			if collectErr != nil || dotImport {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			fun := call.Fun
			for {
				switch expr := fun.(type) {
				case *ast.ParenExpr:
					fun = expr.X
				case *ast.IndexExpr:
					fun = expr.X
				case *ast.IndexListExpr:
					fun = expr.X
				default:
					goto unwrapped
				}
			}
		unwrapped:
			selector, ok := fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok || ident.Obj != nil || ambiguous[ident.Name] || packageNames[key(s)][ident.Name] {
				return true
			}
			pkg, ok := imports[ident.Name]
			if !ok {
				return true
			}
			collectErr = i.add(s, call, ImportedSelectorCall, pkg, selector.Sel.Name, "")
			if collectErr == nil && pkg == "net/http" && selector.Sel.Name == "HandleFunc" && len(call.Args) == 2 && !call.Ellipsis.IsValid() && call.Fun == fun {
				if literal, ok := call.Args[0].(*ast.BasicLit); ok && literal.Kind == token.STRING {
					if route, err := strconv.Unquote(literal.Value); err == nil {
						collectErr = i.add(s, call, HTTPRouteRegistration, pkg, "HandleFunc", route)
					}
				}
			}
			return true
		})
		if collectErr != nil {
			return collectErr
		}
	}
	sort.SliceStable(i.report.Findings, func(a, b int) bool {
		x, y := i.report.Findings[a], i.report.Findings[b]
		if x.File != y.File {
			return x.File < y.File
		}
		if x.Line != y.Line {
			return x.Line < y.Line
		}
		return x.Kind < y.Kind
	})
	return nil
}

func (i *inspector) add(s source, node ast.Node, kind Kind, pkg, symbol, route string) error {
	if len(i.report.Findings) >= MaxFindings {
		return fmt.Errorf("%w: findings", ErrLimit)
	}
	// Ignore //line directives: evidence must point at the inspected file.
	start := i.fset.PositionFor(node.Pos(), false)
	end := i.fset.PositionFor(node.End()-1, false)
	i.report.Findings = append(i.report.Findings, Finding{
		Kind: kind, File: s.name, Line: start.Line, EndLine: end.Line,
		Package: pkg, Symbol: symbol, Route: route,
	})
	return nil
}
