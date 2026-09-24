# Static lockfile profiling

`lockprofile` is an independent, standard-library-only inventory package (Go
1.25+). It does not execute builds, run package managers, read environment
properties, download parents, or access the network. It is intentionally **not a
complete dependency resolver**. No coordinator integration is included.

## API

```go
import "vulns-news/src/ecosystem/lockprofile"

fragment, err := lockprofile.Profile(checkoutDirectory)
```

```go
func Profile(root string) (Fragment, error)

type Fragment struct {
    Ecosystems []domain.EcosystemUsage
    Components []domain.Component
    Warnings   []string
}
```

Malformed supported input, I/O failures, and exceeded limits return an error
with an **empty fragment**, not partial results. Unsupported declarations or
schema versions produce source-prefixed warnings. Unknown filenames are ignored;
this package does not claim to detect every dependency format. JSON shape checks
cover fields used by the parser, not the entire upstream schema. Unknown metadata
fields are ignored. Duplicate JSON keys and trailing documents are errors.

Paths are relative and slash-separated. Ecosystems, components, and warnings
are sorted deterministically. Component IDs are SHA-256 hashes of source path,
versionless PURL, version, scope, and directness. Identical facts are deduplicated;
different source files, versions, or scopes retain separate IDs. PURLs contain no
version; versions are stored in `Component.Version`. PyPI names normalize runs of
`-_.` to `-`; NuGet and Swift identities are lowercase. Maven/Composer namespaces
are stored separately from component names.

`Direct: false` means **not established as direct**, not necessarily proven
transitive. The domain boolean has no unknown state.

## Coverage and limits by format

| Filename | Ecosystem | Facts retained | Deliberate limitations |
| --- | --- | --- | --- |
| `Pipfile.lock` | `pypi` | `default` / `develop` entries with exact `==` PEP 440 versions; runtime/development scope | Requires public PyPI source metadata (see below). Private, unknown, ambiguous or missing sources, Git/path/file/editable entries, wildcards, and non-exact versions are omitted with warnings. Markers/extras are not evaluated; directness is unknown. |
| `composer.lock` | `packagist` | `packages` / `packages-dev`, vendor/name, numeric release versions, runtime/development scope | Path distributions and dev branches omitted. Source Git metadata is normal for Composer releases and does not alone cause omission. Custom repository provenance and directness are unknown. |
| `packages.lock.json` | `nuget` | Schemas 1/2; Direct, Transitive, CentralTransitive; resolved versions; framework/runtime target retained as scope | Project and unknown dependency types omitted. Requested ranges are never used as resolved versions. No framework selection or graph evaluation. |
| `Package.resolved`, `package.resolved` | `swift` | Schemas 1/2/3 recognized; registry pins in 2/3 with scope.name identity and release version | Source-control pins (including schema 1), revisions, and branch-only pins are omitted with warnings rather than inventing registry identities from URLs. Most existing Swift lockfiles therefore yield warnings, not components. |
| `gradle.lockfile` | `maven` | `group:artifact:version=config1,config2`; one component per configuration | Comments and `empty=` records ignored. Dynamic versions omitted. No directness, variant, plugin, buildscript, or legacy per-configuration lockfile resolution. |
| `Gemfile.lock` | `gem` | Only four-space specs inside verified public RubyGems `GEM` sections; `DEPENDENCIES` establishes directness | GIT/PATH specs and GEM blocks with private, mixed or missing remotes are omitted. Platform-qualified specs are omitted instead of guessing the version/platform split. Nested requirements are not installed versions. Groups/platform selection are unknown. |
| `pom.xml` | `maven` | Top-level direct dependencies, explicit literal/local-property versions, declared scopes (default compile) | Not an effective POM. No dependencyManagement/BOM, plugin, profile, module, parent download, or transitive resolution. Missing, cyclic, unknown, range, LATEST, and RELEASE versions remain empty with warnings. Unresolved coordinates and system-scoped local JAR dependencies are omitted with warnings. |

POM properties support nested local `${key}` substitutions and literal
`project.*`, `pom.*`, `project.parent.*`, and `pom.parent.*` groupId/artifactId/version
aliases. Group/version may use the explicitly declared parent coordinates; this
does **not** load a parent POM. Expansion is bounded to 32 recursive levels, 256
calls and 64 KiB per result. Type, classifier and optional metadata are warned
about but cannot be represented by this domain type. XML DTDs/directives are
rejected; external entities are never fetched. Only the standard Maven namespace
or no namespace is interpreted.

### Public-source provenance and fixture migration

Pipenv and RubyGems now fail closed when public provenance is missing or
ambiguous. An exact name/version alone must not turn a private or local package
into a public vulnerability-match candidate.

- **Pipenv:** an explicit dependency `index` must name a unique `_meta.sources`
  entry whose URL is `https://pypi.org/simple` (optional trailing slash).
  Arbitrary source names are allowed; a source named `pypi` is not itself proof.
  Unknown/empty indexes, duplicate source names, private URLs, missing metadata,
  and explicitly disabled `verify_ssl` are not accepted. Without an `index`, an
  entry is accepted only when the nonempty source list is entirely verified
  public PyPI; mixed public/private sources do not establish its origin.
- **RubyGems:** each GEM block must declare at least one `remote`, and every
  remote in that block must be `https://rubygems.org` (optional trailing slash).
  Mixed-source blocks are omitted wholesale because individual specs have no
  source attribution. Source state never carries over between GEM blocks.
- Public endpoints allow case-insensitive hostnames and an explicit HTTPS port
  `443`. HTTP, credentials, nonstandard ports, query strings, fragments, custom
  paths, mirrors, legacy aliases, and lookalike hosts are not accepted. No URL
  is fetched or redirected, and source URLs are not included in warnings.
- **Maven:** scope `system`, including a locally expanded property with that
  value, identifies a local JAR, not a public registry dependency. It is omitted
  regardless of an exact version or `systemPath`; local JARs are never opened.

Accepted sources are static declarations, not verified download provenance;
external package-manager configuration and actual artifact contents remain
outside this profiler. Other ecosystems retain their existing limitations:
for example a private Composer repository can reuse a Packagist-style name.
This change does not establish public provenance for those formats.

Tests expecting public Pipenv components must include explicit public metadata,
for example:

```json
{"_meta":{"sources":[{"name":"pypi","url":"https://pypi.org/simple","verify_ssl":true}]},"default":{"urllib3":{"index":"pypi","version":"==2.2.1"}},"develop":{}}
```

The existing Pipenv fixtures in `src/repository/multilanguage_test.go` and
`cmd/mvp-run/multilanguage_test.go` omit sources and need this metadata to retain
their positive-match expectations. They are outside this package's change scope
and are intentionally not modified here. Existing public RubyGems integration
fixtures already declare the required remote.

## Traversal and resource safety

- Every traversal/read operation after opening the root uses `os.Root` confinement.
- The root must be a directory and not itself a symlink. Descendant symlinks and
  special files are skipped. Files are rechecked before reading.
- `.git`, `node_modules`, `vendor`, `.gradle`, and `.build` directories are skipped.
- Limits: 100,000 entries (including directories/skipped entries), 64 directory
  levels below the root, 4 MiB per recognized input, and 32 MiB total input.
- Directories are read one entry at a time, not allocated wholesale. Reads are
  bounded even if a file grows. JSON/XML nesting is limited to 64 levels; XML
  additionally permits at most 50,000 elements.

Profile an **immutable checkout**. Confinement prevents escaping the open root,
but is not a filesystem snapshot. Concurrent replacements may change results;
`os.Root` does not promise no-follow semantics for every in-root path component,
nor protection against hostile device replacement or mount changes. Skipped
symlinks are intentionally not inventoried and do not produce warnings.

## Validation

```sh
go test ./src/ecosystem/lockprofile -cover
go test -race ./src/ecosystem/lockprofile
go vet ./src/ecosystem/lockprofile
go test ./src/ecosystem/lockprofile -run '^$' -fuzz FuzzParsers -fuzztime 10s
```

Public-API tests exercise every recognized filename, normalized components,
usage paths, malformed formats, unsupported entries, source-only Swift pins,
public-only Ruby specs, private/missing/mixed provenance, endpoint spoofing,
system-scoped local JAR exclusion, unknown/cyclic POM properties, deterministic IDs,
multiple scopes/frameworks, deduplication, exclusions, symlinks, and byte/depth
limits. Parser fuzz seeds run as part of ordinary tests; the last command runs
additional generated cases.
