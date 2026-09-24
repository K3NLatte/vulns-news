# Static dependency profiling

```go
fragment, err := staticprofile.Profile(root)
```

`Profile(root string) (ProfileFragment, error)` returns `Ecosystems`,
`Components` (domain types), and `Warnings`. It does not invoke scripts, package
managers, or network operations. No coordinator integration is included.
`New().Profile(root)` is equivalent; `NewProfiler(Limits)` allows explicit
positive resource budgets.

## Coverage and semantics

- **Go (`Go`, PURL type `golang`):** single-line and multiline `require`
  declarations in `go.mod`, including quoted tokens, pseudo-versions,
  `+incompatible`, and `// indirect`. `go.sum` is never used as an inventory.
  This is a conservative line-oriented parser, not the complete Go module
  grammar or a module resolver. Missing/unsupported versions remain empty.
  `replace` or `exclude` triggers a warning and clears **all** requirement
  versions in that manifest rather than claiming they are resolved versions.
  It does not apply minimum version selection, workspaces, replacements,
  exclusions, toolchain dependencies, or graph pruning.
- **Python (`pypi`):** `requirements.txt` at any traversed depth, normalized
  package names, optional extras, comments, and exact `==` pins from a
  conservative PEP 440 subset (numeric releases, epochs, a/b/rc prereleases,
  post/dev releases, and local versions). Ranges and wildcard pins are never
  emitted as versions. Named unpinned, conditional, URL, hashed, continued,
  and unsupported-version requirements retain identity with an empty version
  and a warning. Environment markers are not evaluated; such components are
  possible declarations, not proof of an installed dependency. Includes,
  constraints, editable installs, bare URLs/paths, and pip options are warned
  about and never followed. Continuation tails are skipped. Other requirements
  filenames and `pyproject.toml` are not parsed.
- **`poetry.lock` / `uv.lock`:** recorded as lockfile evidence with an explicit
  unsupported warning; no components are inferred from their contents. There
  is no TOML library among the existing dependencies.

Components represent declarations, not an installed or fully resolved graph.
`Direct` means explicitly listed (except Go `// indirect`); Python requirements
may themselves have been generated from a transitive lock. `Scope` is `runtime`
and is not inferred from directory names or Python extras. Go module paths are
kept whole in `Name`; `Namespace` is empty. PURLs are versionless, following the
npm adapter convention. Versions live in `Component.Version`. IDs hash the
relative source path, package name, version, and directness. Repeated identical
declarations within a file are deduplicated; declarations in different files
remain distinct. All source paths are slash-separated and root-relative.

## Safety boundaries

Defaults: 2 MiB per parsed file, 32 MiB total parsed bytes, 100,000 filesystem
entries, and depth 64 (root is depth zero). Traversal reads directory entries
incrementally, avoiding whole-directory allocation before checking budgets.
Skipped directories count toward the entry budget but are not traversed.
`.git`, `node_modules`, `vendor`, descendant symlinks, and special files are
skipped. A symlink root is rejected. Reads are bounded even if files grow.
Unparsed lockfiles are not read. I/O and limit failures return an error and an
empty fragment, not a partial inventory. Unsupported syntax returns warnings.

`os.Root` confines opens to the repository. Use an **immutable checkout**:
filesystem confinement is not snapshot isolation, and concurrent modification
can still change content or file types between inspection and opening. The
caller-provided root's ancestor directories are trusted.

## Validation

Run offline with a locally installed Go toolchain:

```
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test ./src/ecosystem/staticprofile -race -cover
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go vet ./src/ecosystem/staticprofile
```
