package nvd

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"vulns-news/src/domain"
)

// Normalize converts the NVD fields retained by this package into the backend
// domain model. CPE data remains product data: this function does not infer a
// package ecosystem or manufacture a PURL.
func Normalize(cve CVERecord) (domain.NormalizedVulnerability, error) {
	id := strings.TrimSpace(cve.ID)
	if id == "" {
		return domain.NormalizedVulnerability{}, errors.New("normalize NVD CVE: ID is required")
	}
	published, err := parseNVDTime(cve.Published)
	if err != nil {
		return domain.NormalizedVulnerability{}, fmt.Errorf("normalize NVD CVE %s published time: %w", id, err)
	}
	modified, err := parseNVDTime(cve.LastModified)
	if err != nil {
		return domain.NormalizedVulnerability{}, fmt.Errorf("normalize NVD CVE %s modified time: %w", id, err)
	}

	severity, score := preferredCVSS(cve.Metrics)
	return domain.NormalizedVulnerability{
		ID:          id,
		PublishedAt: published,
		ModifiedAt:  modified,
		Description: englishValue(cve.Descriptions),
		Severity:    severity,
		CVSS:        score,
		Weaknesses:  normalizeWeaknesses(cve.Weaknesses),
		Affected:    affectedTargets(id, cve),
		References:  normalizeReferences(cve.References),
	}, nil
}

func parseNVDTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, errors.New("value is required")
	}
	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999999",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp %q", value)
}

func englishValue(values []LanguageValue) string {
	fallback := ""
	for _, value := range values {
		text := strings.TrimSpace(value.Value)
		if text == "" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(value.Lang), "en") {
			return text
		}
		if fallback == "" {
			fallback = text
		}
	}
	return fallback
}

func preferredCVSS(metrics Metrics) (string, *float64) {
	for _, generation := range [][]CVSSMetric{metrics.CVSSMetricV40, metrics.CVSSMetricV31, metrics.CVSSMetricV30, metrics.CVSSMetricV2} {
		if metric, ok := preferredMetric(generation); ok {
			severity := strings.TrimSpace(metric.CVSSData.BaseSeverity)
			if severity == "" {
				severity = strings.TrimSpace(metric.BaseSeverity)
			}
			score := metric.CVSSData.BaseScore
			return severity, &score
		}
	}
	return "", nil
}

func preferredMetric(metrics []CVSSMetric) (CVSSMetric, bool) {
	for _, metric := range metrics {
		if metric.CVSSData.hasScore() && strings.EqualFold(strings.TrimSpace(metric.Type), "Primary") {
			return metric, true
		}
	}
	for _, metric := range metrics {
		if metric.CVSSData.hasScore() {
			return metric, true
		}
	}
	return CVSSMetric{}, false
}

func normalizeWeaknesses(weaknesses []Weakness) []string {
	result := make([]string, 0, len(weaknesses))
	seen := make(map[string]struct{})
	for _, weakness := range weaknesses {
		value := englishValue(weakness.Description)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func normalizeReferences(references []Reference) []domain.Reference {
	result := make([]domain.Reference, 0, len(references))
	seen := make(map[string]struct{})
	for _, reference := range references {
		address := strings.TrimSpace(reference.URL)
		if address == "" {
			continue
		}
		// Deduplicate only identical metadata; a URL can have several sources.
		keyBytes, _ := json.Marshal(Reference{URL: address, Source: reference.Source, Tags: reference.Tags})
		key := string(keyBytes)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, domain.Reference{
			URL:    address,
			Source: reference.Source,
			Tags:   append([]string(nil), reference.Tags...),
		})
	}
	return result
}

// affectedTargets retains source status rules, including default-affected
// exceptions. packageName alone proves neither ecosystem nor PURL, so these
// remain product candidates. Unknown schemes deliberately prevent existing
// version evaluators from turning source boundaries into applicability claims.
func affectedTargets(cveID string, cve CVERecord) []domain.AffectedTarget {
	result := make([]domain.AffectedTarget, 0)
	hasUsableAffectedData := false
	for _, group := range cve.Affected {
		for _, data := range group.AffectedData {
			target := domain.AffectedTarget{
				Kind:   domain.AffectedProduct,
				Vendor: strings.TrimSpace(data.Vendor), Product: strings.TrimSpace(data.Product),
				PackageName:   strings.TrimSpace(data.PackageName),
				DefaultStatus: strings.TrimSpace(data.DefaultStatus),
				CPEs:          []string{}, Aliases: []string{}, Constraints: []domain.VersionConstraint{},
			}
			for _, cpe := range data.CPEs {
				if strings.TrimSpace(cpe) != "" {
					target.CPEs = append(target.CPEs, cpe)
				}
			}
			// Vendor alone is not a usable product identity.
			if target.Product == "" && target.PackageName == "" && len(target.CPEs) == 0 {
				continue
			}
			hasUsableAffectedData = true
			candidate := target.DefaultStatus != "unaffected"
			for _, version := range data.Versions {
				status := strings.TrimSpace(version.Status)
				if status != "unaffected" {
					candidate = true
				}
				constraint := domain.VersionConstraint{Scheme: "unknown", Status: status,
					VersionEndExcluding: strings.TrimSpace(version.LessThan),
					VersionEndIncluding: strings.TrimSpace(version.LessThanOrEqual)}
				if constraint.VersionEndExcluding != "" || constraint.VersionEndIncluding != "" {
					constraint.VersionStartIncluding = strings.TrimSpace(version.Version)
				} else {
					constraint.Expression = strings.TrimSpace(version.Version)
				}
				target.Constraints = append(target.Constraints, constraint)
			}
			if candidate {
				target.ID = targetID(cveID, target)
				result = append(result, target)
			}
		}
	}
	// An identified entry can explicitly exclude every version. Do not promote
	// contradictory configuration evidence just because it emitted no candidate.
	if !hasUsableAffectedData {
		result = normalizeAffected(cveID, cve.Configurations)
	}
	return result
}

// targetID is bounded even for arbitrarily long source identities, and includes
// version/status facts so distinct ranges do not share an ID. Identical facts
// intentionally have identical IDs; source ordering does not affect the hash.
func targetID(cveID string, target domain.AffectedTarget) string {
	target.ID = ""
	data, _ := json.Marshal(struct {
		CVE    string
		Target domain.AffectedTarget
	}{cveID, target})
	return fmt.Sprintf("nvd:%x", sha256.Sum256(data))
}

// Plain OR leaves retain CPE version comparisons for ecosystem-aware evaluators.
// AND, negation, unknown operators, and nested node expressions remain candidate
// facts only: flattening cannot establish their environmental applicability.
// An omitted operator retains compatibility with simple legacy configurations.
func normalizeAffected(cveID string, configurations []Configuration) []domain.AffectedTarget {
	var result []domain.AffectedTarget
	for _, configuration := range configurations {
		for _, node := range configuration.Nodes {
			appendNodeTargets(cveID, node, complexOperator(configuration.Operator, configuration.Negate), &result)
		}
	}
	return result
}

func complexOperator(operator string, negate bool) bool {
	operator = strings.ToUpper(strings.TrimSpace(operator))
	return negate || (operator != "" && operator != "OR")
}

func appendNodeTargets(cveID string, node Node, complexContext bool, result *[]domain.AffectedTarget) {
	// Keep complexity sticky through descendants; a simple child cannot erase
	// an ancestor's prerequisites. Nested expressions are conservatively unknown.
	complexContext = complexContext || complexOperator(node.Operator, node.Negate) || len(node.Children) > 0
	scheme := "cpe"
	if complexContext {
		scheme = "unknown"
	}
	for _, match := range node.CPEMatch {
		if !match.Vulnerable || strings.TrimSpace(match.Criteria) == "" {
			continue
		}
		criteria := strings.TrimSpace(match.Criteria)
		vendor, product, version, _ := parseCPE23(criteria)
		target := domain.AffectedTarget{
			Kind:    domain.AffectedProduct,
			Vendor:  vendor,
			Product: product,
			CPEs:    []string{match.Criteria},
			Aliases: []string{},
		}
		constraint := domain.VersionConstraint{
			Scheme:                scheme,
			VersionStartIncluding: strings.TrimSpace(match.VersionStartIncluding),
			VersionStartExcluding: strings.TrimSpace(match.VersionStartExcluding),
			VersionEndIncluding:   strings.TrimSpace(match.VersionEndIncluding),
			VersionEndExcluding:   strings.TrimSpace(match.VersionEndExcluding),
		}
		if version != "" && version != "*" && version != "-" {
			constraint.Expression = version
		}
		if hasConstraint(constraint) {
			target.Constraints = []domain.VersionConstraint{constraint}
		} else {
			target.Constraints = []domain.VersionConstraint{}
		}
		target.ID = targetID(cveID, target)
		*result = append(*result, target)
	}
	for _, child := range node.Children {
		appendNodeTargets(cveID, child, complexContext, result)
	}
}

func hasConstraint(value domain.VersionConstraint) bool {
	return value.Expression != "" || value.VersionStartIncluding != "" ||
		value.VersionStartExcluding != "" || value.VersionEndIncluding != "" ||
		value.VersionEndExcluding != ""
}

func parseCPE23(value string) (vendor, product, version string, ok bool) {
	const prefix = "cpe:2.3:"
	if !strings.HasPrefix(value, prefix) {
		return "", "", "", false
	}
	parts, valid := splitCPEComponents(strings.TrimPrefix(value, prefix))
	if !valid || len(parts) != 11 {
		return "", "", "", false
	}
	vendor = decodeCPEComponent(parts[1])
	product = decodeCPEComponent(parts[2])
	version = decodeCPEComponent(parts[3])
	if vendor == "" || product == "" || vendor == "*" || vendor == "-" || product == "*" || product == "-" {
		return "", "", version, false
	}
	return vendor, product, version, true
}

func splitCPEComponents(value string) ([]string, bool) {
	var parts []string
	var current strings.Builder
	escaped := false
	for _, character := range value {
		if escaped {
			current.WriteRune(character)
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == ':' {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(character)
	}
	if escaped {
		return nil, false
	}
	parts = append(parts, current.String())
	return parts, true
}

func decodeCPEComponent(value string) string {
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}
