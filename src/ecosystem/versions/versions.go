// Package versions evaluates local npm constraints and exact OSV query evidence.
// It does not infer affected ranges from provider query samples.
package versions

import (
	"regexp"
	"strings"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/npm"
)

// Versions implements matcher.VersionEvaluator. Its zero value is ready to use.
type Versions struct{}

// New returns an evaluator suitable for matcher.New without performing I/O.
func New() Versions { return Versions{} }

// Evaluate treats constraints as alternatives. OSV expressions are positive
// samples, not exhaustive ranges: a mismatch is unknown, never not_affected.
// Only byte-identical pinned versions without any range bounds are confirmed.
// Non-OSV constraints retain npm.VersionEvaluator's existing semantics.
func (Versions) Evaluate(ecosystem, installed string, constraints []domain.VersionConstraint) (domain.VersionStatus, error) {
	if len(constraints) == 0 {
		return domain.VersionUnknown, nil
	}
	unknown := false
	for _, c := range constraints {
		status := domain.VersionUnknown
		if c.Scheme == "osv" {
			if IsPinned(ecosystem, installed) && c.Expression == installed &&
				c.VersionStartIncluding == "" && c.VersionStartExcluding == "" &&
				c.VersionEndIncluding == "" && c.VersionEndExcluding == "" {
				status = domain.VersionAffected
			}
		} else {
			var err error
			status, err = (npm.VersionEvaluator{}).Evaluate(ecosystem, installed, []domain.VersionConstraint{c})
			if err != nil {
				return domain.VersionUnknown, err
			}
		}
		if status == domain.VersionAffected {
			return status, nil
		}
		unknown = unknown || status == domain.VersionUnknown
	}
	if unknown {
		return domain.VersionUnknown, nil
	}
	return domain.VersionNotAffected, nil
}

// OSVEcosystem maps supported profiler names to OSV ecosystem identifiers.
// Inventory-only ecosystems are intentionally unsupported; no mapping is assumed.
func OSVEcosystem(ecosystem string) (string, bool) {
	switch ecosystem {
	case "npm", "Maven", "Packagist", "NuGet", "RubyGems", "crates.io", "Pub", "CocoaPods":
		return ecosystem, true
	case "maven":
		return "Maven", true
	case "packagist":
		return "Packagist", true
	case "nuget":
		return "NuGet", true
	case "gem":
		return "RubyGems", true
	case "Go", "go":
		return "Go", true
	case "PyPI", "pypi":
		return "PyPI", true
	default:
		return "", false
	}
}

var (
	semver = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
	python = regexp.MustCompile(`(?i)^v?([0-9]+!)?[0-9]+(\.[0-9]+)*([-_.]?(a|b|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?((-[0-9]+)|([-_.]?(post|rev|r)[-_.]?[0-9]*))?([-_.]?dev[-_.]?[0-9]*)?(\+[a-z0-9]+([._-][a-z0-9]+)*)?$`)
	// Maven has no universal version grammar. Accept a conservative, numeric-
	// leading literal subset, not arbitrary labels, property expressions or ranges.
	maven     = regexp.MustCompile(`^[0-9]+([.][0-9]+)*([.-][A-Za-z0-9]+)*$`)
	packagist = regexp.MustCompile(`(?i)^v?[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?(-(alpha|a|beta|b|RC|patch|p)[.-]?[0-9]*)?$`)
	nuget     = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
	ruby      = regexp.MustCompile(`^[0-9]+(\.[0-9A-Za-z]+)*(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)
	// CocoaPods also uses concrete numeric versions with other segment counts.
	podNumeric = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*$`)
	wildcard   = regexp.MustCompile(`(?i)(^|[.-])x($|[.-])`)
)

// IsPinned recognizes a conservative subset of concrete registry versions.
// It never resolves ranges, tags, branches, git references or local paths. The
// original spelling is retained for both the query and exact evidence matching.
func IsPinned(ecosystem, version string) bool {
	eco, ok := OSVEcosystem(ecosystem)
	if !ok || version == "" || len(version) > 256 || wildcard.MatchString(version) {
		return false
	}
	switch eco {
	case "CocoaPods":
		if podNumeric.MatchString(version) {
			return true
		}
		fallthrough
	case "npm", "Go", "crates.io", "Pub":
		if eco == "Go" && !strings.HasPrefix(version, "v") || (eco == "crates.io" || eco == "Pub" || eco == "CocoaPods") && strings.HasPrefix(version, "v") {
			return false
		}
		if !semver.MatchString(version) {
			return false
		}
		// The npm parser additionally rejects leading zeroes in numeric
		// prerelease identifiers, which a simple semver regex would allow.
		status, _ := (npm.VersionEvaluator{}).Evaluate("npm", version, []domain.VersionConstraint{{Scheme: "npm", Expression: version}})
		return status == domain.VersionAffected
	case "PyPI":
		return python.MatchString(version)
	case "Maven":
		return maven.MatchString(version)
	case "Packagist":
		return packagist.MatchString(version)
	case "NuGet":
		return nuget.MatchString(version)
	case "RubyGems":
		return ruby.MatchString(version)
	default:
		return false
	}
}
