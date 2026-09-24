package npm

import (
	"strings"

	"vulns-news/src/domain"
)

// VersionEvaluator applies npm semantic-version precedence to normalized
// vulnerability constraints. Its zero value is ready for use.
type VersionEvaluator struct{}

var _ interface {
	Evaluate(string, string, []domain.VersionConstraint) (domain.VersionStatus, error)
} = VersionEvaluator{}

// Evaluator is a concise alias for VersionEvaluator.
type Evaluator = VersionEvaluator

// NewVersionEvaluator returns an npm version evaluator.
func NewVersionEvaluator() VersionEvaluator {
	return VersionEvaluator{}
}

// Evaluate implements the version-evaluator contract used by matcher.Matcher.
// Unsupported ecosystems, schemes, ranges, and malformed versions are unknown,
// rather than being guessed at or compared lexically.
func (VersionEvaluator) Evaluate(ecosystem, installedVersion string, constraints []domain.VersionConstraint) (domain.VersionStatus, error) {
	if strings.ToLower(strings.TrimSpace(ecosystem)) != ecosystemName || len(constraints) == 0 {
		return domain.VersionUnknown, nil
	}

	installed, ok := parseSemanticVersion(installedVersion)
	if !ok {
		return domain.VersionUnknown, nil
	}

	hasUnknown := false
	hasApplicable := false
	for _, constraint := range constraints {
		matches, applicable := evaluateConstraint(installed, constraint)
		if !applicable {
			hasUnknown = true
			continue
		}
		hasApplicable = true
		if matches {
			return domain.VersionAffected, nil
		}
	}
	if hasUnknown || !hasApplicable {
		return domain.VersionUnknown, nil
	}
	return domain.VersionNotAffected, nil
}

func evaluateConstraint(installed semanticVersion, constraint domain.VersionConstraint) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(constraint.Scheme)) {
	case "npm", "semver", "cpe":
	default:
		return false, false
	}

	expression := strings.TrimSpace(constraint.Expression)
	startIncluding := strings.TrimSpace(constraint.VersionStartIncluding)
	startExcluding := strings.TrimSpace(constraint.VersionStartExcluding)
	endIncluding := strings.TrimSpace(constraint.VersionEndIncluding)
	endExcluding := strings.TrimSpace(constraint.VersionEndExcluding)
	if expression == "" && startIncluding == "" && startExcluding == "" && endIncluding == "" && endExcluding == "" {
		return false, false
	}
	if startIncluding != "" && startExcluding != "" {
		return false, false
	}
	if endIncluding != "" && endExcluding != "" {
		return false, false
	}

	exact, exactOK := parseOptionalSemanticVersion(expression)
	startInclusiveBoundary, startIncludingOK := parseOptionalSemanticVersion(startIncluding)
	startExclusiveBoundary, startExcludingOK := parseOptionalSemanticVersion(startExcluding)
	endInclusiveBoundary, endIncludingOK := parseOptionalSemanticVersion(endIncluding)
	endExclusiveBoundary, endExcludingOK := parseOptionalSemanticVersion(endExcluding)
	if !exactOK || !startIncludingOK || !startExcludingOK || !endIncludingOK || !endExcludingOK {
		return false, false
	}

	if expression != "" && compareSemanticVersions(installed, exact) != 0 {
		return false, true
	}
	if startIncluding != "" && compareSemanticVersions(installed, startInclusiveBoundary) < 0 {
		return false, true
	}
	if startExcluding != "" && compareSemanticVersions(installed, startExclusiveBoundary) <= 0 {
		return false, true
	}
	if endIncluding != "" && compareSemanticVersions(installed, endInclusiveBoundary) > 0 {
		return false, true
	}
	if endExcluding != "" && compareSemanticVersions(installed, endExclusiveBoundary) >= 0 {
		return false, true
	}
	return true, true
}

func parseOptionalSemanticVersion(value string) (semanticVersion, bool) {
	if value == "" {
		return semanticVersion{}, true
	}
	return parseSemanticVersion(value)
}

type semanticVersion struct {
	major      string
	minor      string
	patch      string
	prerelease []versionIdentifier
}

type versionIdentifier struct {
	value   string
	numeric bool
}

func parseSemanticVersion(value string) (semanticVersion, bool) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "v") {
		value = strings.TrimPrefix(value, "v")
	}
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return semanticVersion{}, false
	}

	precedence := value
	if plus := strings.IndexByte(precedence, '+'); plus >= 0 {
		if strings.IndexByte(precedence[plus+1:], '+') >= 0 || !validDotIdentifiers(precedence[plus+1:]) {
			return semanticVersion{}, false
		}
		precedence = precedence[:plus]
	}

	core := precedence
	var prerelease []versionIdentifier
	if hyphen := strings.IndexByte(precedence, '-'); hyphen >= 0 {
		core = precedence[:hyphen]
		parsed, ok := parsePrerelease(precedence[hyphen+1:])
		if !ok {
			return semanticVersion{}, false
		}
		prerelease = parsed
	}

	parts := strings.Split(core, ".")
	if len(parts) != 3 || !validCoreNumber(parts[0]) || !validCoreNumber(parts[1]) || !validCoreNumber(parts[2]) {
		return semanticVersion{}, false
	}
	return semanticVersion{
		major:      parts[0],
		minor:      parts[1],
		patch:      parts[2],
		prerelease: prerelease,
	}, true
}

func validCoreNumber(value string) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func parsePrerelease(value string) ([]versionIdentifier, bool) {
	if !validDotIdentifiers(value) {
		return nil, false
	}
	parts := strings.Split(value, ".")
	result := make([]versionIdentifier, 0, len(parts))
	for _, part := range parts {
		numeric := true
		for _, character := range part {
			if character < '0' || character > '9' {
				numeric = false
				break
			}
		}
		if numeric && len(part) > 1 && part[0] == '0' {
			return nil, false
		}
		result = append(result, versionIdentifier{value: part, numeric: numeric})
	}
	return result, true
}

func validDotIdentifiers(value string) bool {
	if value == "" {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" {
			return false
		}
		for _, character := range part {
			if (character >= '0' && character <= '9') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= 'a' && character <= 'z') || character == '-' {
				continue
			}
			return false
		}

	}
	return true
}

func compareSemanticVersions(left, right semanticVersion) int {
	if comparison := compareNumericIdentifier(left.major, right.major); comparison != 0 {
		return comparison
	}
	if comparison := compareNumericIdentifier(left.minor, right.minor); comparison != 0 {
		return comparison
	}
	if comparison := compareNumericIdentifier(left.patch, right.patch); comparison != 0 {
		return comparison
	}
	return comparePrerelease(left.prerelease, right.prerelease)
}

func comparePrerelease(left, right []versionIdentifier) int {
	if len(left) == 0 && len(right) == 0 {
		return 0
	}
	if len(left) == 0 {
		return 1
	}
	if len(right) == 0 {
		return -1
	}

	length := len(left)
	if len(right) < length {
		length = len(right)
	}
	for index := 0; index < length; index++ {
		leftIdentifier := left[index]
		rightIdentifier := right[index]
		if leftIdentifier.numeric && rightIdentifier.numeric {
			if comparison := compareNumericIdentifier(leftIdentifier.value, rightIdentifier.value); comparison != 0 {
				return comparison
			}
			continue
		}
		if leftIdentifier.numeric != rightIdentifier.numeric {
			if leftIdentifier.numeric {
				return -1
			}
			return 1
		}
		if leftIdentifier.value < rightIdentifier.value {
			return -1
		}
		if leftIdentifier.value > rightIdentifier.value {
			return 1
		}
	}
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return 0
}

func compareNumericIdentifier(left, right string) int {
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
