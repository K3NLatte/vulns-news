package nvd

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	const fixture = `{
		"id":"CVE-2026-12345",
		"published":"2026-09-24T08:17:03.280",
		"lastModified":"2026-09-25T01:02:03.000",
		"descriptions":[{"lang":"ja","value":"日本語"},{"lang":"en","value":"English"}],
		"metrics":{
			"cvssMetricV40":[
				{"source":"vendor","type":"Secondary","cvssData":{"baseScore":8.1,"baseSeverity":"HIGH"}},
				{"source":"nvd@nist.gov","type":"Primary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}
			],
			"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM"}}]
		},
		"weaknesses":[
			{"description":[{"lang":"en","value":"CWE-79"}]},
			{"description":[{"lang":"en","value":"CWE-79"}]},
			{"description":[{"lang":"en","value":"CWE-89"}]}
		],
		"affected":[{"affectedData":[
			{"vendor":"Example","product":"App","versions":[
				{"version":"1.0","status":"affected"},
				{"version":"1.1","status":"unaffected"},
				{"version":"2.0","status":"affected","lessThan":"3.0"}
			]}
		]}],
		"references":[{"url":"https://example.com/advisory","source":"vendor","tags":["Vendor Advisory"]}]
	}`
	var raw apiCVE
	if err := json.Unmarshal([]byte(fixture), &raw); err != nil {
		t.Fatal(err)
	}
	got, err := normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "CVE-2026-12345" || got.Description != "English" || got.Severity != "CRITICAL" || got.CVSS == nil || *got.CVSS != 9.8 {
		t.Fatalf("基本項目またはCVSSが不正です: %+v", got)
	}
	if got.PublishedAt.Location() != time.UTC || got.PublishedAt.Format(time.RFC3339Nano) != "2026-09-24T08:17:03.28Z" {
		t.Fatalf("公開日時が不正です: %v", got.PublishedAt)
	}
	if !reflect.DeepEqual(got.Weaknesses, []string{"CWE-79", "CWE-89"}) {
		t.Fatalf("弱点分類が不正です: %+v", got.Weaknesses)
	}
	if len(got.Affected) != 2 || got.Affected[0].Vendor != "Example" || got.Affected[0].Version != "1.0" || got.Affected[1].VersionStartIncluding != "2.0" || got.Affected[1].VersionEndExcluding != "3.0" {
		t.Fatalf("影響製品が不正です: %+v", got.Affected)
	}
	if len(got.References) != 1 || got.References[0].URL != "https://example.com/advisory" || got.References[0].Tags[0] != "Vendor Advisory" {
		t.Fatalf("参照情報が不正です: %+v", got.References)
	}
}

func TestNormalizeCPEFallbackAndMissingMetrics(t *testing.T) {
	const fixture = `{
		"id":"CVE-2020-1234",
		"published":"2020-01-01T00:00:00Z",
		"lastModified":"2020-01-02T00:00:00Z",
		"configurations":[{"nodes":[{"cpeMatch":[
			{"vulnerable":false,"criteria":"cpe:2.3:o:other:os:*:*:*:*:*:*:*:*"},
			{"vulnerable":true,"criteria":"cpe:2.3:a:example:app:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0","versionEndExcluding":"2.0"}
		]}]}]
	}`
	var raw apiCVE
	if err := json.Unmarshal([]byte(fixture), &raw); err != nil {
		t.Fatal(err)
	}
	got, err := normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.CVSS != nil || got.Severity != "" || len(got.Affected) != 1 || got.Affected[0].VersionEndExcluding != "2.0" {
		t.Fatalf("任意項目またはCPEが不正です: %+v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["cvss"] != nil || fields["severity"] != nil || fields["weaknesses"] == nil || fields["references"] == nil {
		t.Fatalf("JSONの任意項目または配列が不正です: %s", encoded)
	}
}

func TestNormalizeInvalidDate(t *testing.T) {
	_, err := normalize(apiCVE{ID: "CVE-2026-12345", Published: "invalid"})
	if err == nil {
		t.Fatal("不正な公開日時が受け入れられました")
	}
}
