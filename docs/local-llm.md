# Local LLM vulnerability-feed MVP

## Scope

The MVP turns a public GitHub repository and the latest NVD publications (or an
explicit publication window) into vulnerability feed results. It combines bounded
dependency inventories with Go syntax observations, not full multi-language
vulnerability or exploitability analysis:

```text
public GitHub HTTPS URL
  -> anonymous, shallow repository acquisition
  -> immutable commit SHA
  -> language detection, bounded multi-ecosystem declaration/lockfile profiling
  -> bounded Go AST source observations and warnings
  -> RepositoryProfile

NVD CVE 2.0 publications at or before command start
  -> FetchLatest (bounded multi-request retrieval, at most 200 unique CVEs)
  -> NVD normalization
  -> NormalizedVulnerability

RepositoryProfile + each NormalizedVulnerability
  -> optional OSV pinned-package enrichment (external disclosure)
  -> deterministic identity, local npm ranges, exact OSV version evidence
  -> backend-built Evidence
  -> local-LLM Screening
  -> Deep Analysis only when Screening says related
  -> Feed item/result with backend-owned applicability assessment
  -> JSON on standard output
```

The backend, not the LLM, owns repository acquisition, parsing, identities,
versions, candidate selection, evidence, control flow, and feed facts. Repository
files and NVD text are treated as untrusted input.

## Current architecture

### Public GitHub acquisition

`src/repository` accepts canonical public repository URLs of the form
`https://github.com/owner/repository`. Acquisition is anonymous and HTTPS-only.
It shallow-clones one branch without tags or submodules, disables credentials and
Git hooks, does not execute repository code, and resolves the checkout to an
immutable commit SHA. An optional branch or tag can be supplied as the ref; an
empty ref uses the repository's default branch.

Private repositories, credentials, SSH URLs, non-GitHub hosts, submodules, and
repository build/install commands are not supported.

### Repository profiling

`src/repository.Profile`, used by `cmd/mvp-run`, starts with `ProfileNPM`:

- source-language detection by file extension;
- npm `package.json` parsing;
- npm `package-lock.json` v2 and v3 parsing, including locked direct and
  transitive versions; and
- a bounded npm-to-CPE product-candidate heuristic.

The heuristic derives explicit product candidates from npm component names so
NVD CPE product records can participate in deterministic matching. For an
unscoped package, the package name is the product alias. For a scoped package
such as `@vendor/product`, the scope is used as a vendor candidate and both the
full package name and unscoped product name are aliases. This is candidate
generation, not proof that every similarly named CPE describes the npm package.
The later deterministic match and LLM Screening stages preserve that distinction.

The coordinator then merges `src/ecosystem/staticprofile`,
`src/ecosystem/lockprofile`, and `src/ecosystem/structuredlock` inventories.
These are **supported parser subsets, not complete dependency resolvers**:
profiling does not run package managers, builds, or repository scripts, fetch
parents, or resolve a complete dependency graph.

| Ecosystem / input | Supported subset | Important limits |
| --- | --- | --- |
| npm: `package.json`, `package-lock.json` | Manifest declarations and v2/v3 locked direct/transitive versions. | Declarations are not proof of installed or deployed versions. |
| pnpm: `pnpm-lock.yaml` | v6/v9 package records, scoped names and parenthesized peer contexts. | Importer/snapshot ranges are not installed versions; directness is not inferred. |
| Yarn: `yarn.lock` | Classic v1 with explicit format marker; Berry metadata versions 4/5/6/8 with exact `npm:` resolutions. | Classic requires a public HTTPS npm/Yarn registry tarball matching name/version; not every Yarn protocol is supported. |
| Go: `go.mod` | `require` declarations and direct/indirect markers. | `go.sum` is ignored; `replace`/`exclude` leave requirement versions unknown. No workspace, module graph, or build resolution. |
| Python: `requirements.txt` | Names and a conservative subset of exact `==` pins. | No range, marker, URL, option, include, or dependency resolution. |
| Python/Pipenv: `Pipfile.lock` | Exact `==` PEP 440 pins in `default`/`develop`, with runtime/development scope. | Requires unambiguous public PyPI source metadata; Git/path/editable and non-exact entries are omitted. Markers/extras and directness are not resolved. |
| Python/Poetry: `poetry.lock` | Metadata lock versions 1.1/2.0/2.1; default PyPI when no source is declared, or explicit public PyPI source. | Conservative exact PEP 440 subset; no `pyproject.toml` dependency inventory or resolver. |
| Python/uv: `uv.lock` | Version 1 with explicit public PyPI registry sources. | Conservative exact PEP 440 subset; non-registry sources are omitted. |
| Java/Kotlin/Maven: `pom.xml` | Top-level direct dependencies with literal or bounded local-property versions and declared scopes. | Not an effective POM: no parent fetching, dependencyManagement/BOM, profile, plugin, module, or transitive resolution. Unresolved versions remain empty with warnings; unresolved coordinates and system-scoped local JARs are omitted. |
| Java/Kotlin/Gradle: `gradle.lockfile` | Locked `group:artifact:version=configurations` records, one component per configuration. | Locked dependencies only: no build-script evaluation, dynamic versions, variants, plugins, or legacy per-configuration lockfile resolution. |
| Rust: `Cargo.lock` | Versions 1–4 with explicit crates.io registry/index sources and exact SemVer. | No unversioned legacy format, Git/path dependencies, alternate registries, or resolver. |
| PHP: `composer.lock` | `packages`/`packages-dev`, vendor/name and numeric release versions, with scope. | Path distributions and dev branches omitted; custom repository provenance and directness unknown. Normal release source Git metadata alone does not exclude a package. |
| Ruby: `Gemfile.lock` | Specs in verified public RubyGems `GEM` sections; `DEPENDENCIES` establishes directness. | GIT/PATH, private/mixed/missing remotes, and platform-qualified specs omitted. Nested requirements are not installed versions; groups/platform selection unknown. |
| .NET: `packages.lock.json` | NuGet schemas 1/2, resolved Direct/Transitive/CentralTransitive entries, framework/runtime scope. | No project dependencies, requested-range resolution, framework selection, or graph evaluation. |
| Swift: `Package.resolved` / `package.resolved` | Schemas 1/2/3 recognized; registry pins in 2/3 with scope.name identity and release version. | **Inventory-only, no OSV mapping.** Source-control pins (including schema 1), revisions, and branch-only pins are omitted with warnings. |

Structured locks reject unsupported Git/path/workspace/patch/alternate-registry
identities with source-qualified warnings. Explicit pnpm tarball and Yarn classic
resolved URLs must match the locked npm name and version. Pipenv requires a
uniquely selected public PyPI source (or an entirely public source list when no
index is selected); RubyGems requires every remote in a GEM block to be public
RubyGems. These are static source declarations, not verified artifact provenance.
Malformed supported inputs and resource-limit failures fail profiling rather than
return a successful partial inventory. See the
[lockprofile README](../src/ecosystem/lockprofile/README.md) and
[structuredlock README](../src/ecosystem/structuredlock/README.md) for exact
format, provenance, traversal, and resource boundaries.

`src/repository/normalize.go` preserves per-file component provenance, normalizes
`PyPI` to `pypi`, and forms Maven `group:artifact` and Packagist `vendor/name`
component names from namespaces. Python names normalize case and runs of `-_.`;
NuGet and Swift identities are lowercase. Ecosystem usage paths are merged,
sorted, and deduplicated. Parser PURLs may be versionless (`lockprofile`) or
versioned (`structuredlock`); `Component.Version` carries the exact version.
Unknown directness is not proof of transitivity. npm product candidates are
rebuilt from all normalized npm components, including pnpm/Yarn locks; non-npm
package-to-CPE mapping is not implemented.

`src/sourceinspect` adds bounded Go AST observations: imports, direct imported
selector calls, and literal `net/http.HandleFunc` route registrations, with
relative file paths and line spans. There is no type checking or dependency
loading. Unaliased imports resolve only through a fixed standard-library
allowlist; other packages require explicit aliases. Function aliases, methods,
interfaces, reflection, and dynamic dispatch are not resolved. Inspection does
not select a build configuration and includes tests, generated code, and files
excluded by build constraints.

`RepositoryProfile.source_observations` carries these syntax findings;
`warnings` carries parser warnings and inspection limitations. Resource limits
and inspection errors fail profiling rather than establish absence. Declarations
are not a deployed inventory, and source observations are not proof of CVE
feature usage, execution, reachability, or attack conditions. Non-npm local range
comparison is not implemented; exact OSV provider evidence is separate (below).
Language detection by extension does not imply source analysis for that language.

### NVD client and normalization

`src/nvd` is a real client for the NVD CVE 2.0 HTTPS API. It supports publication
and/or modification time windows, an optional NVD API key, bounded responses,
and a configurable endpoint for testing. A request defaults to 200 results and
cannot request or accept more than 200 vulnerabilities.

`cmd/mvp-run` uses `FetchLatest` to select up to 200 unique CVEs, newest
publication first, at a cutoff captured at command start (before cloning).
Without publication flags, it searches backward in seven-day windows and seeks
to the tail of NVD's ascending publication pages; it is neither a single-page
request nor a fixed previous-24-hours query. Boundary CVEs are deduplicated.
The default request budget is 128, including count probes. Exhausting that
budget or encountering inconsistent pages returns an incomplete-retrieval error;
the CLI does not analyze that partial set as a successful latest result. An
exhausted explicit range may successfully yield fewer than 200 records.

Requests are paced at six seconds without an API key or 650 ms with one. HTTP
errors, including throttling, are surfaced rather than retried. The cutoff
freezes publication time, not NVD database state: concurrent edits/backfills
cannot all be detected because NVD supplies no snapshot token.

Separately, `src/workflow.ProcessRepository` provides the registration-triggered
ingestion core: given a repository registration timestamp, it queries both publication
and modification windows from that timestamp through the run time, requests
pages of at most 200 records until each window is exhausted, and deduplicates
CVE IDs before analysis. NVD records are normalized into CVE metadata, English
description, preferred CVSS data, weaknesses, references, CPE product targets,
and CPE version constraints. The normalizer does not invent package-manager
PURLs from CPE data.

The workflow is not yet wired to repository registration HTTP handlers and does
not persist results or a cursor. A caller must invoke it again to fetch later
updates; no recurring scheduler is implemented.

### Deterministic matching and version evidence

`src/matcher` creates a candidate only from exact normalized identities: exact
PURL, ecosystem/package, CPE, vendor/product, explicit product alias, container,
or infrastructure identity. Fuzzy names do not create candidates.

`cmd/mvp-run` uses `src/ecosystem/versions.New()`. For local constraints it
delegates to `src/ecosystem/npm.VersionEvaluator`, which compares npm semantic
versions with normalized constraints. Non-npm local range comparison remains
unsupported. Proven-unaffected matches are removed before any LLM call.

For provider constraints with scheme `osv`, a supported pinned installed version
that is byte-identical to the queried version, with no range bounds, is
`affected`—including supported non-npm ecosystems. A different version remains
`unknown`, not `not_affected`: provider query results are positive exact-version
evidence, not exhaustive ranges. Missing, unsupported, or unparseable version
information remains `unknown`; the LLM cannot promote it to an affected fact.

### Evidence, local LLM, pipeline, and feed

`src/evidence` builds immutable Evidence from backend facts: one NVD citation and
one repository citation per deterministic match. The LLM cannot create Evidence
IDs or add unmatched repository items.

`src/processor` sends a typed candidate and its Evidence to Ollama. Screening
runs first. `src/pipeline` then applies the result:

- `unrelated`: exclude it and do not create a feed item;
- `possibly_related` or `unknown`: create a screening-only feed item for review;
- `related`: run Deep Analysis, then create the analyzed feed item.

Deep Analysis supplies a supported summary, repository-impact explanation,
missing information, and recommended actions. It does not determine package
identity, version status, reachability, or a backend risk score. `src/feed` keeps
these generated interpretations separate from backend-owned CVE, repository,
match, version, severity, and CVSS facts.

### Backend applicability assessment (Levels 1–5)

`src/assessment.Assess` builds a deterministic, candidate-scoped report.
`src/feed` includes it as `applicability` in both screening-only and analyzed
items. `src/processor` also includes it in prompt material alongside repository
warnings and source observations; LLM prose cannot promote its statuses.

| Level | Current implementation | Boundary |
| --- | --- | --- |
| 1: Package presence | Checks exact component package/PURL identity and validates snapshot/match references. | Product aliases and CPE candidates do not prove package identity; this is not a deployed inventory. |
| 2: Affected version | Preserves local npm evaluation and exact OSV queried-version evidence, including supported non-npm ecosystems, with per-match sources and identity conditions. | Non-npm local range comparison remains unsupported. A version result conditional on package identity does not confirm the same product. |
| 3: Vulnerable feature usage | Reports `unknown` with missing reasons. | Go syntax observations do not establish use of a CVE-specific vulnerable feature. |
| 4: Code reachability | Reports `unknown` with missing reasons. | No call graph or entry-point-to-vulnerable-code path analysis. |
| 5: Attack conditions | Reports `unknown` with missing reasons. | No proof of runtime configuration, exposure, or attacker prerequisites. |

The report preserves individual matches and does not invent Evidence IDs or an
overall risk/exploitability score. `unknown` and `not_found` do not mean safe;
`not_affected` is a bounded version result, not an exploitability verdict.
Prior conceptual Level examples were design illustrations, not descriptions of
implemented feature-use, call-graph, or attack-condition analysis. Adding these
report fields and prompt guidance does not complete Levels 3–5.

### Optional OSV enrichment

`cmd/mvp-run -osv` opts in to `src/osv` package queries to
`https://api.osv.dev`. It is disabled by default. Supported dependency ecosystems,
names, and pinned versions are sent externally; repository identity, file paths,
source, and credentials are not sent to OSV. The CLI prints the disclosure to
standard error. This is an explicit disclosure of dependency metadata to a
third-party service, not part of offline profiling.

| Profile ecosystem | OSV ecosystem / package identity |
| --- | --- |
| `npm` (npm/pnpm/Yarn) | `npm`, including full scoped names |
| `Go` / `go` | `Go`, module path |
| `pypi` / `PyPI` | `PyPI`, normalized package name |
| `maven` / `Maven` | `Maven`, `group:artifact` |
| `crates.io` | `crates.io`, crate name |
| `packagist` / `Packagist` | `Packagist`, `vendor/name` |
| `gem` / `RubyGems` | `RubyGems`, gem name |
| `nuget` / `NuGet` | `NuGet`, package name (lowercase in the profile) |

Swift has no OSV mapping and remains inventory-only. Mapping an ecosystem does
not make every declaration queryable: `versions.IsPinned` accepts conservative
concrete-version subsets, never resolves ranges, and retains version spelling
for queries and exact evidence matching.

One client/cache is shared across CVEs for the run: at most 100 unique pinned
package queries and 8 MiB of cached response bodies. Unsupported/unresolved
versions are skipped, not guessed. Exceeding limits is an error, not silent
truncation to the first 100 packages. Non-context failures are cached for the
run; cancellation is not. There is no persistent cache. Each enrichment also has
a 30-second deadline, a 2 MiB response limit, and a 1,000-result-entry limit;
paginated OSV responses are rejected rather than partially accepted.

Only exact CVE ID/alias links add package targets. `osv:` target IDs,
`osv_match` references, and OSV advisory citations keep provenance separate from
NVD. Matches apply only to the queried version: they are not inferred NVD version
ranges or exploitability proof. Exact supported queried versions can now be
`affected` for non-npm packages too; other versions and non-npm local ranges
remain `unknown`.
On OSV failure the CLI records an `osv` error, skips analysis of that CVE,
continues processing, writes the result JSON, and exits unsuccessfully rather
than silently falling back to unenriched analysis.

## Run mock input with `cmd/llm-eval`

`cmd/llm-eval` reads an already normalized mock `RepositoryProfile`,
`NormalizedVulnerability`, and Evidence fixture. It performs deterministic
matching, calls a real Ollama instance for Screening and conditional Deep
Analysis, builds the pipeline/feed result, and emits indented JSON to standard
output. It does not access GitHub or NVD and does not use SQLite.

Prepare Ollama:

```sh
ollama pull qwen3:8b
ollama serve
```

Run the default fixture from the repository root:

```sh
OLLAMA_MODEL=qwen3:8b \
OLLAMA_BASE_URL=http://127.0.0.1:11434 \
go run ./cmd/llm-eval
```

Or pass all options explicitly:

```sh
go run ./cmd/llm-eval \
  -input testdata/scenarios/npm-affected-dependency/input.json \
  -model qwen3:8b \
  -base-url http://127.0.0.1:11434 \
  -timeout 10m
```

Flags:

- `-input`: normalized mock input JSON; defaults to
  `testdata/scenarios/npm-affected-dependency/input.json`.
- `-model`: Ollama model; required unless `OLLAMA_MODEL` is set.
- `-base-url`: Ollama URL; may also be set with `OLLAMA_BASE_URL` and otherwise
  uses the client default `http://127.0.0.1:11434`.
- `-timeout`: maximum duration for one Ollama generation; defaults to `10m`.

This mock command constructs its matcher without an ecosystem version evaluator,
so fixture matches retain an `unknown` version status. `cmd/mvp-run`, by contrast,
registers the combined local-npm/exact-OSV version evaluator. Progress and errors go to standard error;
successful standard output contains JSON only.

## GitHub-to-NVD MVP with `cmd/mvp-run`

`cmd/mvp-run` wires the implemented components into one real
GitHub -> NVD -> Feed run. With no publication flags, it retrieves up to 200
latest unique CVEs published at or before command start, searching backward as
needed within the request budget:

```sh
OLLAMA_MODEL=qwen3:8b \
NVD_API_KEY=optional-api-key \
go run ./cmd/mvp-run \
  -repository https://github.com/owner/repository
```

An explicit publication window and the remaining options can be supplied as
follows:

```sh
go run ./cmd/mvp-run \
  -repository https://github.com/owner/repository \
  -ref main \
  -published-start 2026-09-24T00:00:00Z \
  -published-end 2026-09-25T00:00:00Z \
  -model qwen3:8b \
  -base-url http://127.0.0.1:11434 \
  -timeout 10m
```

Flags:

- `-repository` (required): public GitHub repository URL.
- `-ref`: optional branch or tag; defaults to the repository default branch.
- `-published-start`: RFC 3339 NVD publication-window start. With neither
  publication flag, search backward for the latest 200; with only an end,
  default to 24 hours before that end.
- `-published-end`: RFC 3339 NVD publication-window end; defaults to command
  start and must not be later than command start.
- `-osv`: optional external OSV pinned-package enrichment; defaults to `false`.
  See the disclosure, cache, and failure boundaries above.
- `-nvd-api-key`: optional NVD key; defaults to `NVD_API_KEY`.
- `-nvd-base-url`: optional NVD-compatible CVE API URL; the real NVD CVE 2.0
  endpoint is used by default.
- `-model`: Ollama model; required unless `OLLAMA_MODEL` is set.
- `-base-url`: Ollama URL; defaults from `OLLAMA_BASE_URL`, then to the Ollama
  client default.
- `-timeout`: positive maximum duration for each Ollama generation; defaults to
  `10m`.

The start and end flags are independently optional. For example, specifying only
`-published-end` selects the 24 hours ending at that value, while specifying only
`-published-start` selects from that value through command start. The end must
not precede the start. There are no modification-window flags.

The command creates a temporary workspace, acquires and profiles the repository
once, and calls `FetchLatest` for a result set capped at 200 unique CVEs, potentially
using multiple requests/windows. It normalizes and deduplicates the fetched CVEs,
optionally enriches them through OSV, deterministically matches each one with the
combined local-npm/exact-OSV version evaluator, builds Evidence for every
candidate, and runs Screening
plus conditional Deep Analysis. Normalization, matching, evidence, and analysis
failures for individual CVEs are recorded in the output while processing
continues. Unlike `src/workflow.ProcessRepository`, this CLI selects a bounded
latest set rather than ingesting every record since registration; it does not
query modification windows.

Successful standard output is one indented JSON object containing the repository
profile (including warnings/source observations), NVD
available/fetched/normalized/duplicate/error counts, matched, excluded,
screening-only, and analyzed counts, feed items with `applicability`, per-CVE
errors, and optional OSV warnings. For `FetchLatest`, `nvd.available` is the
selected unique count, not the total number of CVEs in NVD. Operational progress
and fatal errors are written to standard error.

## Offline validation

From the repository root:

```sh
go test ./src/ecosystem/lockprofile ./src/ecosystem/structuredlock ./src/ecosystem/versions ./src/repository ./src/osv
go test ./cmd/mvp-run -run '^TestMultilanguage' -count=1
go test ./cmd/mvp-run
```

`TestMultilanguageOSVToFeed` covers 13 integration cases: Maven Gradle, Maven
POM, Packagist, NuGet, RubyGems, Cargo, Poetry, uv, Pipenv, Go, npm, pnpm, and
Yarn. It exercises profiling, OSV request identities, CVE alias filtering,
matching, Evidence, assessment, and feed output. Positive cases confirm Levels
1–2 while Levels 3–5 remain `unknown`; negative alias cases do not create feed
items. A separate private-Pipenv case checks that no OSV query is made.
These tests use temporary fixtures, injected HTTP transports/local test servers,
and fake analyzers—not live GitHub, NVD, OSV, or Ollama endpoints. They validate
the documented subsets, not complete ecosystem resolution or exploitability.

## MVP support boundary

| Area | Implemented | Missing / not established |
| --- | --- | --- |
| Acquisition | Anonymous public GitHub HTTPS checkout and immutable commit SHA. | Private/authenticated repositories, submodules, build/install execution. |
| npm | `package.json`, `package-lock.json` v2/v3 direct/transitive locked versions, npm version evaluation, CPE product candidates. | Proof that a product alias identifies the same vulnerable package; deployed inventory. |
| pnpm / Yarn | Supported pnpm v6/v9 and Yarn classic/Berry lock subsets feed normalized npm identities and version matching. | Unsupported protocols/formats, full resolution, complete dependency graphs. |
| Go dependencies | Static `go.mod` require declarations and warnings. | Module/workspace/build resolution, `go.sum` inventory, local Go vulnerability-version evaluation, package-to-CPE mapping. |
| Python | Conservative requirements declarations and exact pins; Pipenv, Poetry, and uv lock subsets. | Dependency/marker/include resolution, `pyproject.toml` inventory, local range comparison, package-to-CPE mapping. |
| Java / Kotlin | Static direct POM dependencies and Gradle locked dependencies. | Effective POM/BOM/parent resolution, Gradle build-script evaluation, full graphs. |
| Rust / PHP / Ruby / .NET | Cargo, Composer, public RubyGems GEM sections, and NuGet lock subsets. | Full package-manager resolution, unsupported sources/formats, non-npm local range comparison. |
| Swift | Supported registry pins in resolved files, inventory-only. | Source-control pin identities, OSV mapping, full Swift resolution. |
| Other inventory | Language detection where recognized. | Container/infrastructure profilers and full multi-language analysis. |
| Source inspection | Bounded Go AST imports, direct imported selector calls, literal `net/http.HandleFunc` routes, locations and limitations. | Type-aware/CVE-specific feature usage, other-language source analysis, complete symbol resolution. |
| Reachability / taint | Levels 3–5 explicitly report `unknown`. | Call graphs, entry-point paths, interprocedural data flow, taint analysis, sanitization or attacker-input tracking. |
| Production environment | Explicit missing-information reporting. | Deployed versions, production build/configuration, feature flags, authentication/exposure, runtime reachability, attacker prerequisites, exploitability proof. |
| NVD | CLI latest-at-command-start retrieval, at most 200 unique CVEs via multiple bounded requests; separate registration-window all-page workflow. | Snapshot consistency guarantees, CLI modification-window ingestion, persistent cursors. |
| OSV | Opt-in CVE-linked queries across eight mapped ecosystems, exact queried-version affected evidence, bounded per-run cache, external disclosure and provenance. | Swift mapping, unresolved-package matching, inferred NVD ranges, non-npm local range comparison, persistent cache, exploitability proof. |
| Assessment / LLM / feed | Backend-owned Evidence and applicability report, Screening, conditional Deep Analysis, JSON feed output. | LLM authority to change backend facts, completed Levels 3–5, overall exploitability/risk scoring. |
| Orchestration / storage | Bounded command-line run and callable registration-window workflow core. | Registration HTTP-handler integration, application-service orchestration, SQLite/other result persistence, recurring scheduler. |

The MVP is a bounded command-line analysis with optional in-memory OSV caching.
It does not register repositories, remember previous runs, or claim that a
matched package is reachable or exploitable. Empty observations, unsupported
input, and unknown assessment levels must not be interpreted as evidence of
safety.
