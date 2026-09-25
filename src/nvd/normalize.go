package nvd

import (
	"fmt"
	"strings"
	"time"
)

type localizedText struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type apiMetric struct {
	Source       string `json:"source"`
	Type         string `json:"type"`
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		BaseScore    *float64 `json:"baseScore"`
		BaseSeverity string   `json:"baseSeverity"`
	} `json:"cvssData"`
}

type apiCVE struct {
	ID           string          `json:"id"`
	Published    string          `json:"published"`
	LastModified string          `json:"lastModified"`
	Descriptions []localizedText `json:"descriptions"`
	Metrics      struct {
		V40 []apiMetric `json:"cvssMetricV40"`
		V31 []apiMetric `json:"cvssMetricV31"`
		V30 []apiMetric `json:"cvssMetricV30"`
		V2  []apiMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []localizedText `json:"description"`
	} `json:"weaknesses"`
	Affected []struct {
		AffectedData []struct {
			Vendor        string   `json:"vendor"`
			Product       string   `json:"product"`
			PackageName   string   `json:"packageName"`
			DefaultStatus string   `json:"defaultStatus"`
			CPEs          []string `json:"cpes"`
			Versions      []struct {
				Version         string `json:"version"`
				Status          string `json:"status"`
				LessThan        string `json:"lessThan"`
				LessThanOrEqual string `json:"lessThanOrEqual"`
			} `json:"versions"`
		} `json:"affectedData"`
	} `json:"affected"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Criteria              string `json:"criteria"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []Reference `json:"references"`
}

func normalize(raw apiCVE) (NormalizedVulnerability, error) {
	published, err := parseNVDTime(raw.Published)
	if err != nil {
		return NormalizedVulnerability{}, fmt.Errorf("%sの公開日時: %w", raw.ID, err)
	}
	modified, err := parseNVDTime(raw.LastModified)
	if err != nil {
		return NormalizedVulnerability{}, fmt.Errorf("%sの更新日時: %w", raw.ID, err)
	}
	v := NormalizedVulnerability{
		ID:          raw.ID,
		PublishedAt: published,
		ModifiedAt:  modified,
		Description: selectText(raw.Descriptions),
		Weaknesses:  make([]string, 0),
		Affected:    make([]AffectedTarget, 0),
		References:  make([]Reference, 0, len(raw.References)),
	}
	for _, group := range [][]apiMetric{raw.Metrics.V40, raw.Metrics.V31, raw.Metrics.V30, raw.Metrics.V2} {
		if metric := preferredMetric(group); metric != nil {
			v.CVSS = metric.CVSSData.BaseScore
			v.Severity = metric.CVSSData.BaseSeverity
			if v.Severity == "" {
				v.Severity = metric.BaseSeverity // CVSS v2 stores it outside cvssData.
			}
			break
		}
	}
	seenWeaknesses := make(map[string]bool)
	for _, weakness := range raw.Weaknesses {
		value := selectText(weakness.Description)
		if value != "" && !seenWeaknesses[value] {
			v.Weaknesses = append(v.Weaknesses, value)
			seenWeaknesses[value] = true
		}
	}
	v.Affected = affectedTargets(raw)
	v.References = append(v.References, raw.References...)
	return v, nil
}

func parseNVDTime(value string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t, nil
	}
	// NVD currently emits timestamps without a timezone; its API uses UTC.
	return time.ParseInLocation("2006-01-02T15:04:05", value, time.UTC)
}

func selectText(texts []localizedText) string {
	for _, text := range texts {
		if text.Lang == "en" {
			return text.Value
		}
	}
	if len(texts) > 0 {
		return texts[0].Value
	}
	return ""
}

func preferredMetric(metrics []apiMetric) *apiMetric {
	for i := range metrics {
		if metrics[i].Type == "Primary" && metrics[i].CVSSData.BaseScore != nil {
			return &metrics[i]
		}
	}
	for i := range metrics {
		if metrics[i].CVSSData.BaseScore != nil {
			return &metrics[i]
		}
	}
	return nil
}

func affectedTargets(raw apiCVE) []AffectedTarget {
	targets := make([]AffectedTarget, 0)
	for _, group := range raw.Affected {
		for _, product := range group.AffectedData {
			base := AffectedTarget{Vendor: product.Vendor, Product: product.Product, PackageName: product.PackageName}
			for _, version := range product.Versions {
				if version.Status != "affected" {
					continue
				}
				target := base
				if version.LessThan != "" || version.LessThanOrEqual != "" {
					target.VersionStartIncluding = version.Version
					target.VersionEndExcluding = version.LessThan
					target.VersionEndIncluding = version.LessThanOrEqual
				} else {
					target.Version = version.Version
				}
				targets = append(targets, target)
			}
			if product.DefaultStatus == "affected" && len(product.Versions) == 0 {
				if len(product.CPEs) == 0 {
					targets = append(targets, base)
				} else {
					for _, cpe := range product.CPEs {
						target := base
						target.CPE = cpe
						targets = append(targets, target)
					}
				}
			}
		}
	}
	if len(targets) > 0 {
		return targets
	}
	// Older records lack affectedData. Preserve their vulnerable CPE matches.
	for _, configuration := range raw.Configurations {
		for _, node := range configuration.Nodes {
			for _, match := range node.CPEMatch {
				if !match.Vulnerable || strings.TrimSpace(match.Criteria) == "" {
					continue
				}
				targets = append(targets, AffectedTarget{
					CPE:                   match.Criteria,
					VersionStartIncluding: match.VersionStartIncluding,
					VersionStartExcluding: match.VersionStartExcluding,
					VersionEndIncluding:   match.VersionEndIncluding,
					VersionEndExcluding:   match.VersionEndExcluding,
				})
			}
		}
	}
	return targets
}
