# extralock

Static, additive dependency inventory. This package has no integration side effects
and never executes package managers, builds, scripts, network requests, or tools.

```go
fragment, err := extralock.Profile(root)
```

The exported contract is `Profile(root string) (Fragment, error)`, where `Fragment`
contains `Components []domain.Component`, `Ecosystems []domain.EcosystemUsage`, and
`Warnings []string`. Errors return an empty fragment, not a partial inventory.

## Supported inputs

| File | Supported inventory | Exclusions / provenance |
| --- | --- | --- |
| `pubspec.lock` | YAML `packages` mapping; exact hosted Pub versions | Requires a description mapping with matching name and an explicit `https://pub.dev` URL (optional trailing slash). Private hosts, legacy string descriptions, SDK, path, and Git dependencies are skipped with warnings. Does not assume `pub.dartlang.org` is `pub.dev`. |
| `deno.lock` | JSON versions `"2"`, `"3"`, `"4"`, `"5"`; pinned npm records and, in v3–v5, JSR records | v2: `npm.packages`; v3: `packages.npm` / `packages.jsr`; v4/v5: top-level `npm` / `jsr`. Requires registry records with nonempty integrity. Specifiers, workspace declarations, and remote URL hashes do not create components. Explicit alternate source metadata is skipped. |
| `packages.config` | XML `packages/package` elements with exact NuGet `id` and `version` | This installed-package inventory includes transitive packages; it does not establish directness or public nuget.org provenance. Recorded as a manifest in ecosystem usage. |
| `project.assets.json` | JSON schema version 3, resolved `libraries` of type `package` | Project libraries are excluded. Target/framework duplicates are avoided by reading the resolved library table, not target declarations. Individual feed provenance and directness are not inferred. |
| `renv.lock` | JSON `Packages`; exact CRAN versions with `Source: Repository`, `Repository: CRAN`, and matching `Package` identity | GitHub, Git, local, Bioconductor, other repositories, and records with conflicting `Remote*` metadata are skipped. Repository labels are declarations, not authentication of the download host. **CRAN inventory does not imply an OSV ecosystem or advisory coverage.** |

Unsupported versions, missing recognized schema sections, and unsupported sources
produce path-qualified warnings. Invalid syntax, duplicate JSON/YAML keys,
conflicting identities, wrong recognized field types, and non-pinned versions in
otherwise supported records produce path-qualified errors. Unknown metadata fields
are tolerated. YAML aliases/anchors and XML DTD/directives are rejected. XML external
entities are never fetched. Integrity fields are not cryptographically verified.
Empty recognized package maps are valid.

Deno registry sections provide the lockfile's declared npm/JSR provenance; this
package does not inspect external Deno configuration, registry mirrors, or caches.
Peer-context suffixes are removed from versions and repeated peer contexts of the
same package/version are deduplicated. No dependency edges or directness are inferred
from Deno specifiers. Pub's `direct main`, `direct dev`, and `transitive` declarations
are preserved; an empty scope or false direct flag elsewhere means not established.

## Identity and determinism

Ecosystem names are exactly `NuGet`, `npm`, `Pub`, `CRAN`, and `JSR`. PURLs use their
lowercase types and are **versionless**. `Version` holds the exact recorded pin.
NuGet names are canonicalized to lowercase; CRAN case is preserved. Scoped npm/JSR
names retain the complete canonical name (for example, `@std/path`) in `Name`, with
`@std` also in `Namespace`, and `pkg:jsr/%40std/path` as the PURL.

SHA-256 IDs include the root-relative source path, PURL, version, scope, and
directness. Thus different versions or lockfiles remain distinct while relocating
the checkout does not change IDs. Components, usages, paths, and warnings are sorted.
NuGet versions retain their recorded spelling rather than attempting package-manager
normalization. No OSV mappings or source-host guarantees are fabricated.

## Safety and limits

Traversal and reads use `os.Root`, require a non-symlink directory root, and skip
symlinks (including internal links) and special files with warnings. `.git`,
`node_modules`, and `.venv` directories are pruned; `obj` is deliberately scanned for
.NET assets. Limits are fixed per call:

- 4 MiB per recognized file; 32 MiB total recognized-file contents
- 100,000 visited directory entries; 64 levels of directory nesting
- 100,000 examined package records, including skipped records
- 64 levels of JSON/YAML/XML nesting

Reads are bounded independently of reported file sizes. File/directory identities
are checked around opens. Use a stable, trusted snapshot: `os.Root` confines access
but cannot eliminate all in-root replacement races or prevent a malicious concurrent
replacement with a blocking special file between the check and open. Parsing is
bounded by input sizes; warnings and record handling are likewise bounded by these
limits. No filesystem writes are performed.

## Validation

Tests include realistic fixtures for every format, Deno schema layouts, exported API
compilation, deterministic and versionless identities, provenance filtering,
unsupported schemas, malformed data, duplicate keys, byte/entry/depth/record limits,
symlink roots/files/directories, and a Linux FIFO.

From the Windows editor environment:

```sh
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu --cd /home/sabakn0123/vulns-news/vulns-news --exec /snap/bin/go test ./src/ecosystem/extralock
```
