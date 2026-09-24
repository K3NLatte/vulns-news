package nvd

import (
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
func Normalize(cve CVE) (domain.NormalizedVulnerability, error) {
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
		Affected:    normalizeAffected(id, cve.Configurations),
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
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value.Lang), "en") {
			return strings.TrimSpace(value.Value)
		}
	}
	return ""
}

func preferredCVSS(metrics Metrics) (string, *float64) {
	for _, generation := range [][]CVSSMetric{metrics.CVSSMetricV31, metrics.CVSSMetricV30, metrics.CVSSMetricV2} {
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
		if strings.EqualFold(strings.TrimSpace(metric.Type), "Primary") {
			return metric, true
		}
	}
	if len(metrics) == 0 {
		return CVSSMetric{}, false
	}
	return metrics[0], true
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
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, domain.Reference{
			URL:  address,
			Tags: append([]string(nil), reference.Tags...),
		})
	}
	return result
}

func normalizeAffected(cveID string, configurations []Configuration) []domain.AffectedTarget {
	var result []domain.AffectedTarget
	for _, configuration := range configurations {
		for _, node := range configuration.Nodes {
			appendNodeTargets(cveID, node, &result)
		}
	}
	return result
}

func appendNodeTargets(cveID string, node Node, result *[]domain.AffectedTarget) {
	for _, match := range node.CPEMatch {
		if !match.Vulnerable || strings.TrimSpace(match.Criteria) == "" {
			continue
		}
		criteria := strings.TrimSpace(match.Criteria)
		id := strings.TrimSpace(match.MatchCriteriaID)
		if id == "" {
			id = cveID + ":" + criteria
		}
		vendor, product, version, _ := parseCPE23(criteria)
		target := domain.AffectedTarget{
			ID:      id,
			Kind:    domain.AffectedProduct,
			Vendor:  vendor,
			Product: product,
			CPEs:    []string{criteria},
			Aliases: []string{},
		}
		constraint := domain.VersionConstraint{
			Scheme:                "cpe",
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
		*result = append(*result, target)
	}
	for _, child := range node.Children {
		appendNodeTargets(cveID, child, result)
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
