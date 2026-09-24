package nvd

import (
	"testing"
	"time"

	"vulns-news/src/domain"
)

func TestNormalizeUsesPreferredFieldsAndPreservesCPE(t *testing.T) {
	cve := CVE{
		ID:           "CVE-2026-1234",
		Published:    "2026-01-02T03:04:05.123Z",
		LastModified: "2026-02-03T04:05:06.456",
		Descriptions: []LanguageValue{
			{Lang: "es", Value: "descripción"},
			{Lang: "en", Value: " English description. "},
		},
		Metrics: Metrics{
			CVSSMetricV31: []CVSSMetric{
				{Type: "Secondary", CVSSData: CVSSData{BaseScore: 5.0, BaseSeverity: "MEDIUM"}},
				{Type: "Primary", CVSSData: CVSSData{BaseScore: 9.8, BaseSeverity: "CRITICAL"}},
			},
			CVSSMetricV30: []CVSSMetric{{Type: "Primary", CVSSData: CVSSData{BaseScore: 8.8, BaseSeverity: "HIGH"}}},
		},
		Weaknesses: []Weakness{
			{Description: []LanguageValue{{Lang: "en", Value: "CWE-79"}}},
			{Description: []LanguageValue{{Lang: "en", Value: "CWE-79"}}},
			{Description: []LanguageValue{{Lang: "en", Value: "CWE-20"}}},
		},
		References: []Reference{{URL: "https://example.test/advisory", Tags: []string{"Vendor Advisory"}}},
		Configurations: []Configuration{{Nodes: []Node{{CPEMatch: []CPEMatch{
			{
				Vulnerable:            true,
				Criteria:              `cpe:2.3:a:acme:widget\:server:*:*:*:*:*:*:*:*`,
				MatchCriteriaID:       "match-001",
				VersionStartIncluding: "1.0",
				VersionEndExcluding:   "2.0",
			},
			{Vulnerable: false, Criteria: `cpe:2.3:o:acme:platform:*:*:*:*:*:*:*:*`},
		}}}}},
	}

	got, err := Normalize(cve)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got.ID != cve.ID || got.Description != "English description." {
		t.Errorf("identity/description = %q/%q", got.ID, got.Description)
	}
	if !got.PublishedAt.Equal(time.Date(2026, 1, 2, 3, 4, 5, 123000000, time.UTC)) {
		t.Errorf("published = %v", got.PublishedAt)
	}
	if got.ModifiedAt.Location() != time.UTC || got.ModifiedAt.Hour() != 4 {
		t.Errorf("modified = %v", got.ModifiedAt)
	}
	if got.Severity != "CRITICAL" || got.CVSS == nil || *got.CVSS != 9.8 {
		t.Errorf("CVSS = %q/%v", got.Severity, got.CVSS)
	}
	if len(got.Weaknesses) != 2 || got.Weaknesses[0] != "CWE-79" || got.Weaknesses[1] != "CWE-20" {
		t.Errorf("weaknesses = %#v", got.Weaknesses)
	}
	if len(got.References) != 1 || got.References[0].URL != "https://example.test/advisory" {
		t.Errorf("references = %#v", got.References)
	}
	if len(got.Affected) != 1 {
		t.Fatalf("affected = %#v", got.Affected)
	}
	target := got.Affected[0]
	if target.ID != "match-001" || target.Kind != domain.AffectedProduct || target.Vendor != "acme" || target.Product != "widget:server" {
		t.Errorf("target identity = %#v", target)
	}
	if target.PURL != "" || target.Ecosystem != "" || target.PackageName != "" {
		t.Errorf("inferred package identity = %#v", target)
	}
	if len(target.CPEs) != 1 || target.CPEs[0] != cve.Configurations[0].Nodes[0].CPEMatch[0].Criteria {
		t.Errorf("CPEs = %#v", target.CPEs)
	}
	if len(target.Constraints) != 1 || target.Constraints[0].Scheme != "cpe" || target.Constraints[0].VersionStartIncluding != "1.0" || target.Constraints[0].VersionEndExcluding != "2.0" {
		t.Errorf("constraints = %#v", target.Constraints)
	}
}

func TestNormalizeFallsBackAcrossCVSSVersions(t *testing.T) {
	tests := []struct {
		name         string
		metrics      Metrics
		wantScore    float64
		wantSeverity string
	}{
		{
			name:         "v3.0",
			metrics:      Metrics{CVSSMetricV30: []CVSSMetric{{CVSSData: CVSSData{BaseScore: 7.5, BaseSeverity: "HIGH"}}}},
			wantScore:    7.5,
			wantSeverity: "HIGH",
		},
		{
			name:         "v2",
			metrics:      Metrics{CVSSMetricV2: []CVSSMetric{{BaseSeverity: "MEDIUM", CVSSData: CVSSData{BaseScore: 5.0}}}},
			wantScore:    5.0,
			wantSeverity: "MEDIUM",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Normalize(CVE{
				ID: "CVE-2026-0001", Published: "2026-01-01T00:00:00Z", LastModified: "2026-01-02T00:00:00Z", Metrics: test.metrics,
			})
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if got.CVSS == nil || *got.CVSS != test.wantScore || got.Severity != test.wantSeverity {
				t.Errorf("CVSS = %q/%v", got.Severity, got.CVSS)
			}
		})
	}
}

func TestNormalizeRetainsUnparseableCPEWithoutInventingIdentity(t *testing.T) {
	got, err := Normalize(CVE{
		ID: "CVE-2026-0002", Published: "2026-01-01T00:00:00Z", LastModified: "2026-01-02T00:00:00Z",
		Configurations: []Configuration{{Nodes: []Node{{CPEMatch: []CPEMatch{{Vulnerable: true, Criteria: "not-a-cpe"}}}}}},
	})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got.Affected) != 1 || got.Affected[0].CPEs[0] != "not-a-cpe" {
		t.Fatalf("affected = %#v", got.Affected)
	}
	if got.Affected[0].Vendor != "" || got.Affected[0].Product != "" || got.Affected[0].PURL != "" {
		t.Errorf("invented identity = %#v", got.Affected[0])
	}
}
