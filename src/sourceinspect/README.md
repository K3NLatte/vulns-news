# sourceinspect

Standalone, standard-library-only Go source inspection for a supplemental
Level 3 **candidate-evidence** profile. This package does not assign assessment
levels, integrate with the coordinator/domain, or make security conclusions.
It never runs inspected code, invokes commands, loads dependencies, downloads
modules, or evaluates build scripts.

## API

```go
func Inspect(root string) (Report, error)
```

```go
report, err := sourceinspect.Inspect("/path/to/source")
if err != nil {
    // report is incomplete. Do not interpret missing findings as absence.
    return err
}
for _, finding := range report.Findings {
    // Persist/display candidate evidence, not a vulnerability verdict.
    fmt.Printf("%s:%d %s %s.%s\n",
        finding.File, finding.Line, finding.Kind,
        finding.Package, finding.Symbol)
}
```

`Report` contains JSON-ready `Findings`, `Limitations`, `Complete`,
`FilesInspected`, `BytesRead`, and `SymlinksSkipped`. A `Finding` contains:

- `Kind`: `import`, `imported_selector_call`, or `http_route_registration`.
- `File`: slash-separated path relative to the root.
- `Line`, `EndLine`: physical, one-based source lines, ignoring `//line` remapping.
- `Package`: imported package path.
- `Symbol`: selector name (empty for imports).
- `Route`: unquoted literal pattern for route observations, when applicable.

Successful results are sorted by file, line, then kind. Distinct occurrences
on the same line are retained. Errors return `Complete == false`; collection
may have produced partial findings, or none if traversal/parsing failed.
Use `errors.Is(err, sourceinspect.ErrLimit)` to identify budget exhaustion.

## Evidence semantics

**Imports** are AST import declarations, including blank and dot imports.
Text inside comments or string literals is not source evidence.

**Imported selector calls** are selectors in AST call position whose base
identifier resolves to an import binding. The parser's lexical object resolver
is enabled: locals, parameters, receivers, range variables, short declarations,
block scopes, closures, and type parameters can shadow imports. Package-level
names across files in the same directory and package conservatively veto
resolution. Duplicate aliases are not resolved. Files with dot imports emit
imports only because their introduced names cannot be determined locally.

Explicit aliases work for any import path. For unaliased imports, only the
fixed standard-library name allowlist in `inspect.go` is supported. Unknown
package names are **not guessed from path basenames** (notably versioned or
renamed dependencies). Those imports still produce import observations.
Dependencies are never opened to discover names. This deliberately favors
missed candidates over speculative resolution.

Parenthesized and generic selector call syntax is supported. No type checker
runs: a call-position selector can represent a function, function-valued
variable, or type conversion. A resolved binding is not proof of symbol
existence, valid Go code, or invocation at runtime. Function aliases, object
methods, chained selectors, reflection, and dynamic dispatch are not traced.

**HTTP route observations** supplement the call observation only for direct
`net/http.HandleFunc` syntax (including import aliases), with exactly two
non-variadic arguments and a string-literal first argument. Dynamic patterns,
`ServeMux` methods, wrapper calls, and handler identities are not resolved.
The pattern is not validated against any Go version. A registration in an
unused function is still a syntax observation: it does not establish that a
route is registered at runtime or reachable over a network.

There are **no CVE rules** in this package. Import/call/route observations do not
prove function execution, CVE usage, exploitability, vulnerability, exposure,
or reachability. A consumer would need a separate explicit rule and additional
evidence to tie a package/symbol observation to a CVE. An empty report is not
proof of safety.

## Filesystem and resource limits

Go 1.25+ is required, matching the repository. `os.Root` confines traversal and
opens to the root. The root must be a directory, not a symlink. Symlinks inside
the tree (including internal links, external links, broken links, and loops)
are skipped, as are non-regular files. Checked opens compare file identities
to reject detectable replacements. This is not an atomic snapshot or an
absolute no-follow guarantee against concurrent filesystem changes; inspect
an immutable checkout for reproducible evidence. Parent components used to
locate the initial root may themselves be symlinks.

All regular `.go` files are parsed, including tests, generated code, vendor
files, hidden directories, and files excluded by platform/build constraints.
There is no build selection, dependency graph, or module/workspace resolution.
Parse and I/O failures stop inspection rather than silently omitting files.

| Budget | Maximum |
| --- | ---: |
| Directory entries examined (all file kinds) | 10,000 |
| Go files parsed | 512 |
| Bytes per Go file | 1 MiB |
| Total source bytes | 16 MiB |
| Directory depth below root | 32 |
| Findings | 20,000 |

Directory reads use fixed-size batches, and file reads use bounded readers,
not file-size metadata alone. A read may consume one extra byte to detect a
byte-limit violation; `BytesRead` includes that byte. ASTs are retained only
within the file and byte budgets. These are input/work budgets, **not hard
wall-clock or process-memory limits**. Filesystem operations can block and
parser/AST allocations expand input size. There are no timeout goroutines
that leave parsing running in the background. Use an externally constrained
worker if hostile inputs require a strict time or memory isolation boundary.

## Tests

```sh
go test ./src/sourceinspect
go test -race ./src/sourceinspect
```

Tests cover aliases, conservative import-name handling, lexical shadowing,
comments/strings, physical locations, cross-file declarations, route syntax,
symlinks, parse/root errors, deterministic output, and each resource budget.
Symlink tests skip on platforms where symlink creation is unavailable.
