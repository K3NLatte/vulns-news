# Conservative Level 1–5 assessment

Public entry point:

```go
func Assess(
    profile domain.RepositoryProfile,
    vulnerability domain.NormalizedVulnerability,
    candidate domain.MatchCandidate,
) Report
```

Integration:

```go
report := assessment.Assess(profile, vulnerability, candidate)
```

`Report` exposes `PackagePresence` (Level 1), `AffectedVersion` (Level 2),
`FeatureUsage` (Level 3), `CodeReachability` (Level 4), `AttackConditions`
(Level 5), and per-match `Matches`. Each `Check` includes `Status`,
`ConditionalOnPackageIdentity`, `Sources`, `EvidenceIDs`, and `MissingReasons`.
All public report fields have JSON tags. There is no confidence or risk score.

## Meaning and boundaries

- `confirmed`: the specific check is supported, not that exploitation is possible.
- `unknown`: required proof is unavailable or input is inconsistent.
- `not_found`: no exact package identity was found among the supplied candidate
  matches. Profiling completeness is not established; this is not package absence.
- `not_affected`: the supplied deterministic version evaluator ruled out the
  referenced installed version. This is not an exploitability verdict.

Level 1 requires a referenced real `domain.Component`, a package target, and
exact package identity (ecosystem plus fully qualified name) or identical PURL.
Identity comparisons are case-sensitive. Bare basenames do not prove namespaced
package identity. Conflicting PURLs prevent package-name fallback. No fuzzy
matching, product aliases, CPE aliases, container references, or infrastructure
references establish package presence.

Level 2 consumes `domain.TargetMatch.VersionStatus`; it does not implement or
second-guess ecosystem version comparison. A nonempty installed version must
match its referenced repository item, and the target must carry constraints.
Unknown, missing, or unsupported statuses stay unknown. Per-match version
results without confirmed package identity are explicitly conditional, including
`not_affected` results. They cannot promote the aggregate Level 2 check.

The aggregate version check is confirmed if any identity-confirmed match is
affected, and not affected only if every supplied match has confirmed package
identity and is not affected. Otherwise it is unknown. This aggregation covers
only the supplied candidate, not omitted components or targets. In particular,
the current matcher filters out unaffected matches; an empty candidate must not
be used to infer that all packages are unaffected.

Levels 3–5 remain unknown: the current API has no structured feature-use,
call-graph, entry-point, deployment, or attacker-prerequisite evidence. Dependency
scope, vulnerability descriptions, CVSS, references, and previous levels do not
prove those facts. No scanner is simulated and repository code is not executed.

## Trust and provenance

Supply backend-owned normalized profiles and deterministic matcher results, not
LLM-authored candidates. `Assess` validates the repository/commit and
vulnerability/revision binding. Missing or ambiguous match references and
repeated item/target pairs fail closed, including conflicting duplicate results.
It does not authenticate the caller or recompute supplied version statuses.

`Sources` retains the supplied repository item ID, affected target ID, source
path where available, and zero-based candidate match index. The report carries
snapshot IDs. `EvidenceIDs` is empty because these inputs do not carry immutable
processor evidence IDs. Integration may associate real collected evidence later;
the assessment does not manufacture IDs or treat source paths as evidence IDs.

This package imports domain types only in production and does not alter the
processor, matcher, pipeline, or any existing package. `processor.Input` and
processor schemas are unchanged; integration must explicitly decide where to
store or expose the report.
