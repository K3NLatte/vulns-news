# nativeprofile

Standalone, static dependency inventory. This package does not register with or
change existing profilers, collectors, or vulnerability matching.

```go
fragment, err := nativeprofile.Profile(root)
```

`Fragment` contains `Components []domain.Component`,
`Ecosystems []domain.EcosystemUsage`, and `Warnings []string`.
Errors return an empty fragment, never a partial inventory. Source paths are exact
root-relative file paths using `/`, including nested project directories.
`vcpkg.json` is recorded under `Manifests`; the other files under `Lockfiles`.

## Formats and identity

| File | Accepted inventory | Deliberate exclusions / limitations |
| --- | --- | --- |
| `conan.lock` | Conan 0.5 requirement lists (`requires`, `build_requires`, `python_requires`, `config_requires`); 0.4 `graph_lock.nodes[].ref` | Only full `name/version` references, optionally `@user/channel`, `#revision`, and `%timestamp`. Ranges, bare names, and local path nodes are skipped with warnings. No binary package resolution. |
| `vcpkg.json` | Named string/object dependencies, including feature dependencies | Versions remain unknown, even with minimum constraints or overrides. No baseline/registry/overlay resolution or platform/feature evaluation. The application itself is not a dependency. |
| `Podfile.lock` | Resolved `PODS` scalar and mapping specs with explicit public `SPEC REPOS` membership | Only `trunk`, `https://cdn.cocoapods.org/`, and `https://github.com/CocoaPods/Specs.git` are accepted. Private/conflicting/absent provenance is excluded. `EXTERNAL SOURCES` and `CHECKOUT OPTIONS` exclude the whole root pod, including all subspecs, regardless of the public listing. |
| `Manifest.toml` | Julia legacy top-level package arrays and format `2.0` `deps` package arrays with UUID and version | Any `path`, `repo-url`, `repo-rev`, or `repo-subdir` field excludes that entry. Entries without UUID/version (including unversioned stdlibs) are skipped. UUIDs are normalized to lowercase; registry provenance is not verified. |

PURLs are **versionless**: `pkg:conan/name`, `pkg:cocoapods/Name[/Subspec]`,
`pkg:generic/vcpkg/name`, and `pkg:generic/julia/Name?uuid=...`. The generic types
avoid inventing package-url ecosystem standards for vcpkg and Julia.
Known versions are stored separately in `Component.Version`.

Because the shared component model has no source-reference field,
`Component.Scope` preserves the complete Conan reference (including user/channel,
revision hash, and timestamp), or the Julia UUID. It is empty for the other two
formats. In particular, a Conan revision does **not** turn the dependency into an
unknown version. Distinct source references are not merged, even when their
versionless PURLs match. IDs are SHA-256 over NUL-delimited source path, PURL,
version, and preserved source identity. Exact duplicates within a file collapse;
identical packages from different files retain separate IDs. Directness is not
inferred (`Direct` remains false).

Conan references and Julia UUID/version entries are **inventory/source identities,
not asserted OSV identities**; each such file produces an explicit warning. No
registry provenance, checksum integrity, reachability, or vulnerability lookup is
verified for any ecosystem. CocoaPods subspec names are retained, not collapsed
into their root pod.

Unknown schema versions and unrecognized shapes produce warnings rather than
invented components. Invalid syntax, invalid recognized field types, malformed
resolved pod specs, invalid Julia UUID/version strings, and filesystem/limit
failures return errors with the source path where applicable. Unsupported Conan
reference syntax is warned and skipped. This is not a complete schema validator;
unrelated metadata fields are ignored.

## Filesystem and resource boundaries

- Uses `os.Root` for confined reads. Never invokes interpreters, package managers,
  subprocesses, hooks, source files, or network APIs.
- Rejects empty roots and roots that are files or symlinks. Skips symlink entries
  (files and directories) with warnings and skips recognized non-regular files,
  including FIFOs, before opening them.
- Checks file/directory identity around opening and bounds reads independently of
  reported file sizes. Like the neighboring portable profilers, this is intended
  for a stable source tree, **not a race-proof snapshot** of a tree being modified
  by an adversarial writer; pre-open checks cannot eliminate every replacement
  race (including replacement with a special file).
- Recurses through nested directories, excluding `.git`. Does not resolve include
  paths, source URLs, Julia paths, or Conan paths found in metadata.
- Limits: depth 32, 20,000 directory entries, 2 MiB per recognized file, 16 MiB
  total recognized input, and 50,000 distinct components. Limit failures are
  errors, not silently truncated output. YAML uses the existing decoder's alias
  protections; all parsers are additionally bounded by the input byte limits.
- Sorts components by ID, ecosystem usages by name, paths and warnings
  lexicographically. Results do not depend on directory iteration order.

## Validation

From the repository root with Go 1.25 and the existing dependencies available:

```sh
gofmt -w src/ecosystem/nativeprofile/*.go
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test ./src/ecosystem/nativeprofile
```

Tests cover combined inventories, Conan revisions and legacy graphs, Julia UUID
identity and legacy manifests, public/private/external CocoaPods provenance,
versionless vcpkg dependencies, malformed/unknown schemas, deterministic IDs and
paths, symlinks, root validation, file/total byte limits, depth/component limits,
and Linux FIFOs. Only synthetic temporary metadata is profiled by tests; no
package source is executed.
