package nvd

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/npm"
)

func TestNormalizeUsesPreferredFieldsAndPreservesCPE(t *testing.T) {
	cve := CVERecord{
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
	if !strings.HasPrefix(target.ID, "nvd:") || target.Kind != domain.AffectedProduct || target.Vendor != "acme" || target.Product != "widget:server" {
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

func normalizeJSON(t *testing.T, fields string) domain.NormalizedVulnerability {
	t.Helper()
	var cve CVERecord
	if err := json.Unmarshal([]byte(`{"id":"CVE-2026-0001","published":"2026-01-01T00:00:00Z","lastModified":"2026-01-02T00:00:00Z",`+fields+`}`), &cve); err != nil {
		t.Fatal(err)
	}
	got, err := Normalize(cve)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestNormalizeScorePresenceAndPriority(t *testing.T) {
	for _, tt := range []struct {
		name, metrics string
		want          *float64
	}{
		{"absent data", `{"cvssMetricV40":[{"type":"Primary"}]}`, nil},
		{"absent score", `{"cvssMetricV40":[{"cvssData":{"baseSeverity":"HIGH"}}]}`, nil},
		{"null score", `{"cvssMetricV40":[{"cvssData":{"baseScore":null}}]}`, nil},
		{"zero", `{"cvssMetricV40":[{"cvssData":{"baseScore":0}}]}`, scorePointer(0)},
		{"v40 primary", `{"cvssMetricV40":[{"cvssData":{"baseScore":5}},{"type":"Primary","cvssData":{"baseScore":8}}],"cvssMetricV31":[{"cvssData":{"baseScore":9}}]}`, scorePointer(8)},
		{"unscored primary", `{"cvssMetricV40":[{"type":"Primary","cvssData":{}},{"cvssData":{"baseScore":4}}]}`, scorePointer(4)},
		{"fallback generation", `{"cvssMetricV40":[{}],"cvssMetricV31":[{"cvssData":{"baseScore":7}}]}`, scorePointer(7)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeJSON(t, `"metrics":`+tt.metrics)
			if !reflect.DeepEqual(got.CVSS, tt.want) {
				t.Fatalf("score = %v, want %v", got.CVSS, tt.want)
			}
		})
	}
	for _, input := range []string{`{}`, `{"baseScore":null}`, `{"baseScore":0}`, `{"baseScore":9}`} {
		var data CVSSData
		if err := json.Unmarshal([]byte(input), &data); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip CVSSData
		if err := json.Unmarshal(encoded, &roundtrip); err != nil {
			t.Fatal(err)
		}
		if data != roundtrip {
			t.Fatalf("presence lost: %s => %s", input, encoded)
		}
	}
	data := CVSSData{BaseScore: 9}
	if err := json.Unmarshal([]byte(`{}`), &data); err != nil {
		t.Fatal(err)
	}
	if data.hasScore() {
		t.Fatal("reused decoder retained score")
	}
}

func scorePointer(value float64) *float64 { return &value }

func TestNormalizeFallbackTextAndReferenceSources(t *testing.T) {
	got := normalizeJSON(t, `"descriptions":[{"lang":"en","value":" "},{"lang":"ja","value":"説明"}],"weaknesses":[{"description":[{"lang":"ja","value":"CWE-79"}]}],"references":[{"url":"https://example.test","source":"one","tags":["Patch"]},{"url":"https://example.test","source":"two"}]`)
	if got.Description != "説明" || !reflect.DeepEqual(got.Weaknesses, []string{"CWE-79"}) {
		t.Fatalf("text = %#v", got)
	}
	if len(got.References) != 2 || got.References[0].Source != "one" || got.References[1].Source != "two" {
		t.Fatalf("references = %#v", got.References)
	}
}

func TestNormalizeAffectedVersionsAndDefaults(t *testing.T) {
	got := normalizeJSON(t, `"affected":[{"affectedData":[{"vendor":"acme","product":"widget","packageName":"@acme/widget","defaultStatus":"affected","cpes":["source-cpe"],"versions":[{"version":"1.0","status":"unaffected"},{"version":"2.0","lessThan":"3.0","status":"affected"},{"version":"4.0","lessThanOrEqual":"5.0","status":"affected"}]}]}]`)
	if len(got.Affected) != 1 {
		t.Fatalf("targets = %#v", got.Affected)
	}
	target := got.Affected[0]
	if target.Kind != domain.AffectedProduct || target.PackageName != "@acme/widget" || target.Ecosystem != "" || target.PURL != "" || target.DefaultStatus != "affected" || !reflect.DeepEqual(target.CPEs, []string{"source-cpe"}) {
		t.Fatalf("identity = %#v", target)
	}
	want := []domain.VersionConstraint{
		{Scheme: "unknown", Status: "unaffected", Expression: "1.0"},
		{Scheme: "unknown", Status: "affected", VersionStartIncluding: "2.0", VersionEndExcluding: "3.0"},
		{Scheme: "unknown", Status: "affected", VersionStartIncluding: "4.0", VersionEndIncluding: "5.0"},
	}
	if !reflect.DeepEqual(target.Constraints, want) {
		t.Fatalf("constraints = %#v", target.Constraints)
	}
	for _, tt := range []struct {
		name, data string
		count      int
	}{
		{"default affected", `{"product":"p","defaultStatus":"affected"}`, 1},
		{"default unaffected", `{"product":"p","defaultStatus":"unaffected"}`, 0},
		{"missing identity", `{"vendor":"v","defaultStatus":"affected"}`, 0},
		{"blank identity", `{"product":" ","cpes":[" "],"defaultStatus":"affected"}`, 0},
		{"package only", `{"packageName":"npm:widget","versions":[{"version":"1","status":"affected"}]}`, 1},
		{"cpe only", `{"cpes":["source-cpe"],"defaultStatus":"affected"}`, 1},
		{"affected exception", `{"product":"p","defaultStatus":"unaffected","versions":[{"version":"1","status":"affected"}]}`, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := normalizeJSON(t, `"affected":[{"affectedData":[`+tt.data+`]}]`)
			if len(v.Affected) != tt.count {
				t.Fatalf("targets = %#v", v.Affected)
			}
			for _, target := range v.Affected {
				if target.PURL != "" || target.Ecosystem != "" || target.Kind != domain.AffectedProduct {
					t.Fatalf("invented identity: %#v", target)
				}
			}
		})
	}
}

func TestNormalizeConfigurationFallbackRequiresNoUsableAffectedData(t *testing.T) {
	const cpe = "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"
	const configurations = `"configurations":[{"operator":"OR","nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"` + cpe + `","versionStartIncluding":"1.0.0","versionEndExcluding":"2.0.0"}]}]}]`
	for _, tt := range []struct {
		name         string
		affected     string
		wantFallback bool
	}{
		{"explicit unaffected rules", `[{"affectedData":[{"vendor":"acme","product":"widget","cpes":["` + cpe + `"],"defaultStatus":"unaffected","versions":[{"version":"1.0.0","lessThan":"2.0.0","status":"unaffected"}]}]}]`, false},
		{"unaffected default without versions", `[{"affectedData":[{"product":"widget","defaultStatus":"unaffected"}]}]`, false},
		{"unaffected package identity", `[{"affectedData":[{"packageName":"widget","defaultStatus":"unaffected"}]}]`, false},
		{"unaffected CPE identity", `[{"affectedData":[{"cpes":["` + cpe + `"],"defaultStatus":"unaffected"}]}]`, false},
		{"unusable entries do not override usable exclusion", `[{"affectedData":[{"vendor":"acme"}]},{"affectedData":[{"product":"widget","defaultStatus":"unaffected"},{}]}]`, false},
		{"missing affected", "", true},
		{"empty affected", `[]`, true},
		{"empty group", `[{"affectedData":[]}]`, true},
		{"missing identity", `[{"affectedData":[{"defaultStatus":"unaffected","versions":[{"version":"1.0.0","status":"unaffected"}]}]}]`, true},
		{"vendor only", `[{"affectedData":[{"vendor":"acme","defaultStatus":"unaffected"}]}]`, true},
		{"blank identities", `[{"affectedData":[{"product":" ","packageName":" ","cpes":[" "],"defaultStatus":"unaffected"}]}]`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fields := configurations
			if tt.affected != "" {
				fields += `,"affected":` + tt.affected
			}
			got := normalizeJSON(t, fields)
			if !tt.wantFallback {
				if len(got.Affected) != 0 {
					t.Fatalf("configuration promoted despite explicit unaffected data: %#v", got.Affected)
				}
				return
			}
			if len(got.Affected) != 1 || !reflect.DeepEqual(got.Affected[0].CPEs, []string{cpe}) {
				t.Fatalf("missing fallback candidate: %#v", got.Affected)
			}
			status, err := (npm.VersionEvaluator{}).Evaluate("npm", "1.5.0", got.Affected[0].Constraints)
			if err != nil || status != domain.VersionAffected {
				t.Fatalf("simple OR fallback evaluation = %s, %v", status, err)
			}
		})
	}
}

func TestNormalizeConfigurationCandidatesAndIDs(t *testing.T) {
	fields := `"affected":[{"affectedData":[{"defaultStatus":"affected"}]}],"configurations":[{"operator":"AND","negate":true,"nodes":[{"operator":"OR","negate":true,"cpeMatch":[{"vulnerable":false,"criteria":"environment"}],"children":[{"cpeMatch":[{"vulnerable":true,"criteria":"source-cpe","versionEndExcluding":"2"},{"vulnerable":true,"criteria":"source-cpe","versionEndExcluding":"3"}]}]}]}]`
	got := normalizeJSON(t, fields)
	if len(got.Affected) != 2 {
		t.Fatalf("targets = %#v", got.Affected)
	}
	if !reflect.DeepEqual(got, normalizeJSON(t, fields)) {
		t.Fatal("normalization is nondeterministic")
	}
	if got.Affected[0].ID == got.Affected[1].ID {
		t.Fatal("different ranges share ID")
	}
	for _, target := range got.Affected {
		if len(target.ID) != 68 || target.Kind != domain.AffectedProduct || target.Constraints[0].Scheme != "unknown" {
			t.Fatalf("unsafe target: %#v", target)
		}
	}
	long := normalizeJSON(t, `"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"`+strings.Repeat("x", 10000)+`","matchCriteriaId":"`+strings.Repeat("y", 10000)+`"}]}]}]`)
	if len(long.Affected[0].ID) != 68 {
		t.Fatal("unbounded ID")
	}
	preferred := normalizeJSON(t, `"affected":[{"affectedData":[{"product":"preferred","defaultStatus":"affected"}]}],"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"fallback"}]}]}]`)
	if len(preferred.Affected) != 1 || preferred.Affected[0].Product != "preferred" {
		t.Fatalf("fallback replaced affectedData: %#v", preferred.Affected)
	}
}

func TestNormalizeConfigurationSchemes(t *testing.T) {
	match := CPEMatch{
		Vulnerable:            true,
		Criteria:              "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
		VersionStartIncluding: "1.0.0",
		VersionEndExcluding:   "2.0.0",
	}
	leaf := Node{Operator: "OR", CPEMatch: []CPEMatch{match}}
	for _, tt := range []struct {
		name          string
		configuration Configuration
		wantScheme    string
	}{
		{"plain OR", Configuration{Operator: "OR", Nodes: []Node{leaf}}, "cpe"},
		{"omitted operators", Configuration{Nodes: []Node{{CPEMatch: []CPEMatch{match}}}}, "cpe"},
		{"normalized operator", Configuration{Operator: " or ", Nodes: []Node{leaf}}, "cpe"},
		{"configuration AND", Configuration{Operator: "AND", Nodes: []Node{leaf}}, "unknown"},
		{"configuration negation", Configuration{Negate: true, Nodes: []Node{leaf}}, "unknown"},
		{"configuration unknown operator", Configuration{Operator: "XOR", Nodes: []Node{leaf}}, "unknown"},
		{"node AND", Configuration{Nodes: []Node{{Operator: "AND", CPEMatch: []CPEMatch{match}}}}, "unknown"},
		{"node negation", Configuration{Nodes: []Node{{Operator: "OR", Negate: true, CPEMatch: []CPEMatch{match}}}}, "unknown"},
		{"node unknown operator", Configuration{Nodes: []Node{{Operator: "XOR", CPEMatch: []CPEMatch{match}}}}, "unknown"},
		{"nested OR", Configuration{Nodes: []Node{{Operator: "OR", CPEMatch: []CPEMatch{match}, Children: []Node{leaf}}}}, "unknown"},
		{"ancestor AND", Configuration{Nodes: []Node{{Operator: "AND", Children: []Node{leaf}}}}, "unknown"},
		{"ancestor negation", Configuration{Nodes: []Node{{Negate: true, Children: []Node{leaf}}}}, "unknown"},
		{"ancestor unknown operator", Configuration{Nodes: []Node{{Operator: "XOR", Children: []Node{leaf}}}}, "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			targets := normalizeAffected("CVE-test", []Configuration{tt.configuration})
			if len(targets) == 0 {
				t.Fatal("lost product candidates")
			}
			for _, target := range targets {
				if len(target.Constraints) != 1 || target.Constraints[0].Scheme != tt.wantScheme {
					t.Fatalf("constraints = %#v, want %s", target.Constraints, tt.wantScheme)
				}
				for _, version := range []string{"1.5.0", "2.0.0"} {
					want := domain.VersionUnknown
					if tt.wantScheme == "cpe" {
						want = domain.VersionAffected
						if version == "2.0.0" {
							want = domain.VersionNotAffected
						}
					}
					got, err := (npm.VersionEvaluator{}).Evaluate("npm", version, target.Constraints)
					if err != nil || got != want {
						t.Fatalf("evaluate %s = %s, %v; want %s", version, got, err, want)
					}
				}
			}
		})
	}
	// Complexity in one branch or configuration must not taint its siblings.
	targets := normalizeAffected("CVE-test", []Configuration{
		{Nodes: []Node{{Operator: "AND", CPEMatch: []CPEMatch{match}}, leaf}},
		{Nodes: []Node{leaf}},
	})
	if len(targets) != 3 || targets[0].Constraints[0].Scheme != "unknown" || targets[1].Constraints[0].Scheme != "cpe" || targets[2].Constraints[0].Scheme != "cpe" {
		t.Fatalf("context leaked: %#v", targets)
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
			got, err := Normalize(CVERecord{
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
	got, err := Normalize(CVERecord{
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
