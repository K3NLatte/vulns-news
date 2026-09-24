# structuredlock

```go
fragment, err := structuredlock.Profile(root)
```

`Fragment` contains `Components []domain.Component`,
`Ecosystems []domain.EcosystemUsage`, and `Warnings []string`. The coordinator
owns merging these records into a repository profile. This package performs no
network requests, subprocess execution, or script execution.

Supported inputs:

- `pnpm-lock.yaml`: v6/v9 package records, including scoped names and parenthesized
  peer contexts. Snapshot/importer ranges are not treated as installed versions.
- `yarn.lock`: classic v1's explicit format marker and scalar/dependency-map
  grammar; Berry metadata versions 4/5/6/8 with exact `npm:` resolutions.
  Classic requires an HTTPS public npm/Yarn registry tarball matching both the
  name and exact version.
- `Cargo.lock`: versions 1–4 with an explicit crates.io registry/index source.
  Unversioned legacy Cargo files are not supported.
- `poetry.lock`: metadata lock versions 1.1/2.0/2.1. No source denotes Poetry's
  default PyPI registry; explicit sources must identify the public PyPI index.
- `uv.lock`: version 1, explicit public PyPI registry sources only.

Git, local paths, workspaces, patches, alternate registries, unknown protocols,
and unsupported exact identities are skipped with source-qualified warnings.
Syntax/schema decoding failures, unsupported lockfile formats, and resource
limit failures return an error and an empty fragment, never a partial inventory.
Yarn classic is not YAML and has a separate strict grammar; TOML and YAML parsing
use `github.com/pelletier/go-toml/v2` v2.2.4 and `gopkg.in/yaml.v3` v3.0.1.

Explicit pnpm tarball URLs and Yarn classic resolved URLs must have the standard
npm path `/<name>/-/<unscoped-name>-<version>.tgz`, matching the locked identity.
Scoped names may use percent-encoded `@` and `/`; paths are decoded once, not
cleaned or repeatedly decoded. Unrecognized paths and name/version conflicts
are skipped with warnings, even when an integrity field is present.

## Identity

Ecosystem names are `npm`, `crates.io`, and `PyPI`. PURL types are `npm`, `cargo`,
and `pypi`. PURLs include exact versions and percent-encode identity segments.
Scoped npm components retain the full `@scope/name` in `Name` and `@scope` in
`Namespace`. npm names must be lowercase; npm/Cargo versions must be exact
SemVer (no ranges, tags, or `v` prefixes). Cargo spelling is preserved. Python
names are lowercased and runs of `-_.` become `-`; versions accept a conservative
PEP 440 subset (numeric releases, epochs, a/b/rc, post/dev, local identifiers),
are lowercased, and otherwise retain lockfile spelling. Unsupported version
spellings warn rather than being guessed. Directness is not inferred.

Components are deduplicated per lockfile and identity, sorted deterministically,
and assigned SHA-256 IDs from source path and versioned PURL. Ecosystem records
are merged by name with sorted lockfile paths; warnings are sorted.

## Bounds and filesystem policy

`NewProfiler(Limits)` allows explicit positive bounds. Defaults: 10 MiB per
lockfile, 100,000 visited directory entries, depth 64, and 100,000 registry
component candidates (before deduplication). Directory entries are read in
batches. Dependency stores, virtual environments, `.git`, and Cargo `target`
are not traversed. Root symlinks are rejected; descendant symlinks and selected
special files are skipped with warnings. All traversal and reads use `os.Root`;
regular-file metadata is checked before and after opening and reads are bounded.
As with other filesystem profilers, use a stable acquired tree: `os.Root` confines
access but does not provide a snapshot against concurrent repository mutation.

Run `go test ./src/ecosystem/structuredlock`.
