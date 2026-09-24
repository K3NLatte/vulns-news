# Additional static manifests

`manifestextra` is standalone: it does not register with the coordinator or change
any existing parser. It never executes scripts/package managers or uses a network.

## API

```go
func Profile(root string) (Fragment, error)

type Fragment struct {
    Components []domain.Component
    Ecosystems []domain.EcosystemUsage
    Warnings   []string
}
```

Components use the existing `PyPI` and `crates.io` ecosystem names and `pypi` and
`cargo` PURL types. An unknown version has an empty `Version` and a versionless
PURL, not a wildcard or a fabricated resolved version. SHA-256 IDs incorporate
relative source path, PURL, and scope. Python names are lowercased and runs of
`-`, `_`, and `.` normalize to `-`. Components, ecosystem evidence, and warnings
are deterministic. Repeated identical declarations within a scope are deduplicated.

## Supported inputs

- `pyproject.toml`: PEP 621 dependencies and optional dependencies; named PEP 508
  requirements with extras and markers. Only single exact `==` pins in the
  supported PEP 440 subset retain versions. Ranges, wildcards, and compound
  constraints have unknown versions. Markers/extras are not evaluated: this is
  an inventory of declarations, not an environment-specific installation plan.
  Direct URL/file/VCS requirements are skipped with warnings.
- Poetry: `tool.poetry.dependencies`, legacy `dev-dependencies`, and named group
  dependencies. Bare exact versions and `==` pins retain versions. The `python`
  interpreter constraint is excluded. Source/git/path/URL declarations are skipped.
- `pdm.lock`: lock format versions 4.0–4.5; exact package records only. Public
  provenance requires an explicit `index = "https://pypi.org/simple"`, a source
  table containing only that URL, or a nonempty files list whose URLs all use
  `https://files.pythonhosted.org/packages/`. Explicit private/local/VCS source
  evidence overrides positive evidence. Ordinary filename/hash-only lock records
  are deliberately **not** treated as proof of PyPI origin. Hashes are not verified.
- `Cargo.toml`: regular, dev, build, and target-specific dependencies, including
  package aliases. Only explicit `=1.2.3`-style complete SemVer pins retain versions;
  bare versions are Cargo ranges. Workspace-inherited, git, path, and custom
  registry dependencies are skipped with warnings. Workspace templates are not
  resolved. Patch/replace tables cause an error, since they can change identities
  throughout a workspace.

Manifest dependencies are direct; PDM records are not asserted direct. Optional,
development, build, and target/group declarations carry distinct scopes. Project
metadata is not itself a dependency.

## Conservative source policy and limitations

Detected Poetry/PDM/uv source configuration anywhere in the scanned tree disables
Python public-package attribution throughout that scan. A detected `.cargo/config`
or `.cargo/config.toml` similarly disables default Cargo registry attribution.
This intentionally over-skips rather than guessing config inheritance. In the
absence of such configuration, manifest registry dependencies use their standard
public registry default. No ambient user, ancestor, environment, or package-manager
configuration outside the root is consulted; callers must not interpret this as
proof of the registry an external installation would actually use.

No requirements files (including `-r`/`-c` includes), lock reconciliation,
transitive resolution, workspace inheritance, dynamic dependency computation,
PEP 735/PDM development groups, or build-system requirements are processed.
Python version syntax is a conservative subset of PEP 440; unsupported spellings
are not guessed. TOML syntax/type errors on supported dependency structures and
invalid lock identities fail the entire profile. Unsupported sources are warnings.

## Traversal and errors

Reads are confined with `os.Root`. Symlinks and special input files are skipped
with warnings; a symlink root is rejected. Opened files/directories are checked
against their pre-open identity. Use a stable checkout: these checks are not an
atomic snapshot and cannot guarantee safety against all concurrent in-root file
replacement races (including replacement with a blocking special file).

Fixed limits: depth 32, 20,000 directory entries, 2 MiB per input, 16 MiB total
input bytes, and 50,000 unique components. Directories are enumerated in bounded
batches. `.git`, `node_modules`, `.venv`, `venv`, `target`, and `__pycache__` are
pruned. Only the three supported filenames are read; Cargo config presence is
observed but its contents are not read. Parse, I/O, and resource-limit errors
return an empty fragment, never a partial inventory.

Run tests with `go test ./src/ecosystem/manifestextra`.
