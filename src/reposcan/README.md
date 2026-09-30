# reposcan

CPU-only advisory discovery for a `domain.RepositoryProfile`. All package files
and tests live here; no CLI, repository acquisition, scheduler, or model runtime
is included.

## API

- `Plan(profile) PlanReport`: deterministic, deduplicated, sorted OSV queries.
  Each `PlannedQuery` includes the complete original `domain.Component` origins.
  Unsupported ecosystems, unresolved versions, and invalid/ambiguous identities
  remain visible as `UnqueriedComponent` entries. Different versions are separate
  queries, ordered by ecosystem/name/version. Workspace and dependency path
    are explicitly `unavailable`. CocoaPods is excluded as an unsupported OSV
    ecosystem. NuGet inventory is retained but unqueried with reason
    `OSV canonical package identity unavailable`: profiler-lowercased names cannot
    safely supply OSV's case-sensitive canonical identity. No network name
    resolver or guessed casing is used.
- `Run(ctx, profile, Config) Report`: query the complete planned package batch,
  fetch each OSV advisory once per run, and optionally enrich explicit CVE IDs
  using NVD. `Config.OSV` accepts `*osv.DiscoveryClient`; `Config.NVD` accepts
  `*nvd.Client`. Both are narrow interfaces suitable for testing. Clients must
  honor the context. `NVDInterval` waits between lookups and is cancellable;
  zero disables pacing. Configure an interval appropriate to the endpoint's
  rate limits. Requests disclose package names/versions to OSV and CVE IDs to
  NVD; planning and state operations do not access the network.
- `RetainEvidence(previous, current Report) Report`: carry last-observed NVD
  evidence forward in `current.RetainedRecords`, separate from current records.
  Disabled NVD, failed lookups, and disappearing OSV aliases do not erase history.
  A fresh current observation supersedes its retained record; authoritative
  `not_found` removes it. Call this helper before diffing and emitting a monitor
  report. It performs no I/O and does not change current groups, query matches,
  enrichment, or completeness. See the monitoring contract below.
- `State{SchemaVersion, Profile, Report}`, `SchemaVersion = 1`:
  retain the entire original profile and report. `Load(path)` validates the
  schema, raw current/retained evidence, and snapshot consistency, refusing
  corrupt state. Enrichment must account exactly once for every distinct CVE
  ID/alias in current OSV records, even when NVD is disabled (`not_checked`).
  Historical records do not create expected enrichment entries. Current NVD
  records must correspond exactly to `found` entries; other outcomes cannot
  have current NVD records. Duplicates, missing/extra results, current/retained
  overlap, and retained evidence contradicting authoritative absence are rejected.
  `Save(path, state)` writes a synced `0600` temporary JSON file in the same
  directory and atomically renames it. The directory must exist. It refuses
  symlinks, corrupt existing state, changed profiles, and replacing an existing
  baseline with `RefreshComplete=false`. The **entire serialized Profile** is
  immutable, including inventory, origins, warnings, observations, and profiling
  time—not merely repository ID/SHA. Go-only time internals and empty omitted
  fields are compared as they survive JSON persistence. Use a new state path for
  re-profiling, even at the same commit.
  Operationally complete refreshes can advance an unchanged-profile baseline
  even when `Status=incomplete` because of persistent coverage warnings or
  unqueried inventory. Save applies `RetainEvidence` against the stored baseline
  automatically and revalidates the merged report, without mutating the caller's
  report. An initial failed refresh can be saved for inspection. Serialize
  concurrent writers to the same path.
- `Changes(previous, current) []Change`: deterministic `added` and `modified`
  changes keyed by `source:id`, plus `query_changed` for query evidence or
  origins. Current observations are compared against both previous current and
  retained evidence: re-enabling NVD reports an unchanged CVE as unchanged, and
  changed provider JSON as `modified`, not `added`. Retained records themselves
  never generate additions or modifications. Removals require
  `RefreshComplete=true` for the same snapshot, not
  complete coverage. A source with `not_checked` enrichment cannot produce
  removals. NVD removal additionally requires an explicit `not_found` lookup
  for that CVE; disabling NVD or dropping an OSV alias is not NVD disappearance.
  `no_longer_observed` does **not** mean fixed. Provider JSON whitespace/key
  order and scan timestamps alone do not cause record changes.

Supporting exported types are `PackageResult`, `Match`, `SourceRecord`,
`AdvisoryGroup`, `EnrichmentResult`, and `EcosystemSummary`.

## Evidence and completeness

`Acquisition` is `complete` only with a repository ID and commit SHA, consistent
with existing repository workflows. Invalid input produces `unknown` acquisition
and an incomplete report; the scan itself does not clone or validate remote Git.

`Status=complete` describes the requested inventory discovery, not whole-system
security or runtime reachability. Unqueried components, profile warnings, OSV
pagination/detail failures, and NVD HTTP failures make it `incomplete`. Positive
query evidence is retained even when another page or source fails. OS/deployment
environment coverage is always warned as unevaluated; every runtime impact is
`unknown`. Missing optional NVD configuration is metadata `not_checked`, not a
package scan failure. NVD's explicit empty result is `not_found`, never safety.

`Report.RefreshComplete` (`refresh_complete` in JSON) tracks operational
query, pagination, detail, and configured NVD completion independently of
coverage. Persistent profile warnings and unqueried components do not make it
false; request failures, cancellation, invalid configuration, invalid profiles,
and detail/package discrepancies do. Optional NVD `not_checked` and explicit
`not_found` are not operational failures. The flag controls baseline advancement
and removal diffs, never a safety claim. State validation rejects a true flag
when queries or enrichment have failed. Existing otherwise-valid schema-1 states
without the new field load conservatively with `RefreshComplete=false`; a fresh
successful run is required before advancing a baseline or reporting removals.

An empty complete OSV query is `no_advisory_found`, not `safe` or `not_affected`.
A query-linked, nonwithdrawn advisory with the matching ecosystem/package can
supply `affected_version_match`. A nonwithdrawn detail record without that
package is an explicit `unknown` discrepancy: `Match.Reason`, the query error,
and report warnings describe it; query/refresh completion are false and raw
provenance remains available. It is not `no_advisory_found`.
Withdrawn advisories remain in the raw source
records but do not supply positive evidence. `Match.FixedVersions` includes
only fixed boundaries from that advisory's matching package; these are not
verified upgrade recommendations. Ranges, aliases, unknown fields, configurations,
and source IDs remain in full raw provider JSON. JSON serialization may change
insignificant whitespace, but does not drop or normalize provider fields.

`Report.Records` contains only this run's observations, keyed by `osv:<id>` or
`nvd:<id>`. `Report.Groups` connects these current records only through explicit
IDs and aliases, transitively, without discarding source records or inventing a
CVE for a GHSA-only advisory. Query matches remain attached to exact
package/version identities and all original component origins.

`Report.RetainedRecords` (`retained_records`, omitted when empty) contains only
historical `nvd:<id>` records, with their complete raw JSON intact. These are
**not current observations**, do not enter groups or matches, and supply no
current completeness or safety claim. Report start/finish times describe the
current run, not when retained records were fetched. History survives repeated
unchecked refreshes and removed OSV aliases. No lookup of a historical-only CVE
is implied; `Run` still enriches only CVEs present in current OSV records.
Schema version remains 1; the new optional map needs no published-state migration.

## Saved-profile monitoring

The core integration sequence is:

```go
previous, err := reposcan.Load(statePath)
// Handle err before proceeding.
current := reposcan.Run(ctx, previous.Profile, cfg)
current = reposcan.RetainEvidence(previous.Report, current)
changes := reposcan.Changes(previous.Report, current)
// Emit current and changes; handle delivery errors before advancing the baseline.
// When current.RefreshComplete is true, save:
// reposcan.Save(statePath, reposcan.State{
//     SchemaVersion: reposcan.SchemaVersion,
//     Profile: previous.Profile,
//     Report: current,
// })
```

`RetainEvidence` expects valid reports and compares their full `Repository`
identities; different identities leave `current` unchanged. It cannot check full
profile equality because reports do not contain full profiles; Save enforces
that invariant. The helper is idempotent and mutates neither input. Its returned
retention map and retained records are copied; other current fields are shared
unchanged, so continue treating reports as immutable. Previously observed data
takes precedence over a caller-supplied retained copy of the same record.

An authoritative NVD absence requires a same-snapshot, acquisition-complete,
`RefreshComplete=true` refresh with an explicit `not_found` for that CVE and no
NVD `not_checked` source opt-out. Failed/partial runs cannot remove history or
advance an existing baseline. A confirmed absence produces
`no_longer_observed`, **not fixed**; a subsequent fresh observation is `added`.
Save performs retention even when an API caller omits the helper, but does not
update that caller's in-memory report. Call the helper explicitly before CLI
output so emitted evidence matches what Save will persist.
Every run rechecks the entire package batch, including previous empty results;
there is no permanent negative cache. New advisories affecting the saved
inventory can therefore appear on later runs. This is **not** an upstream delta
feed, does not re-clone or execute the repository, and does not track dependency
changes after the saved commit. Failed runs should be surfaced to the caller
without advancing an existing baseline.

## Tests

`go test ./src/reposcan` uses only in-process fakes, local HTTP mock servers, and
temporary files. No live provider requests, repository execution, or model
runtime is required. `state_retention_test.go` covers repeated NVD opt-out and
re-enablement, dropped aliases, authoritative absence, malformed enrichment and
retained records, and immutable full-profile baseline protection.
