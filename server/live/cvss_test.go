package live

import (
	"encoding/json"
	"testing"

	"vulns-news/src/reposcan"
)

func TestCVSSBaseVectors(t *testing.T) {
	const v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
	for _, tt := range []struct {
		name, kind, vector string
		want               float64
		valid              bool
	}{
		{"saved uglify-js", "CVSS_V3", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, true},
		{"saved devalue", "CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3, true},
		{"v31 critical", "CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"zero is scored", "CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, true},
		{"v4", "CVSS_V4", v4, 10, true},
		{"v4 base not threat score", "CVSS_V4", v4 + "/E:U", 10, true},
		{"v3 base not temporal score", "CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U", 9.8, true},
		{"missing metrics", "CVSS_V3", "CVSS:3.1/AV:N", 0, false},
		{"v4 missing metrics", "CVSS_V4", "CVSS:4.0/AV:N", 0, false},
		{"mismatched type", "CVSS_V3", v4, 0, false},
		{"untyped numeric", "CVSS_V3", "7.5", 0, false},
		{"prose", "CVSS_V3", "CVE-2015-8858 has score 7.5", 0, false},
		{"invalid optional", "CVSS_V4", v4 + "/E:INVALID", 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := vectorScore(tt.kind, tt.vector)
			if ok != tt.valid || (ok && got.score != tt.want) {
				t.Fatalf("got %+v valid=%v want=%v valid=%v", got, ok, tt.want, tt.valid)
			}
		})
	}
	if cvssSeverity(0) != "none" || cvssSeverity(7.5) != "high" || cvssSeverity(5.3) != "medium" {
		t.Fatal("incorrect severity bands")
	}
}
func scoreRecord(t *testing.T, id, kind, vector string) reposcan.SourceRecord {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"id": id, "severity": []map[string]string{{"type": kind, "score": vector}}})
	if err != nil {
		t.Fatal(err)
	}
	return reposcan.SourceRecord{Source: "osv", ID: id, Raw: raw}
}
func TestCVSSSourcesAndSelection(t *testing.T) {
	low := scoreRecord(t, "GHSA-one", "CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L")
	high := scoreRecord(t, "GHSA-two", "CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	newer := scoreRecord(t, "GHSA-three", "CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
	records := map[string]reposcan.SourceRecord{"osv:GHSA-one": low, "osv:GHSA-two": high, "osv:GHSA-three": newer}
	score := osvCVSS([]string{"osv:GHSA-one", "osv:GHSA-two"}, records)
	if score == nil || score.score != 9.8 {
		t.Fatal("same-version maximum not chosen")
	}
	score = osvCVSS([]string{"osv:GHSA-one", "osv:GHSA-two", "osv:GHSA-three"}, records)
	if score == nil || score.score != 0 || score.version != "4.0" {
		t.Fatal("newest version or zero lost")
	}
	newer.Withdrawn = true
	records["osv:GHSA-three"] = newer
	score = osvCVSS([]string{"osv:GHSA-three"}, records)
	if score != nil {
		t.Fatal("withdrawn record contributes")
	}
	records["osv:GHSA-one"] = reposcan.SourceRecord{Source: "osv", ID: "GHSA-one", Raw: json.RawMessage(`{"id":"GHSA-one","details":"CVSS 9.8","database_specific":{"severity":"CRITICAL"}}`)}
	if osvCVSS([]string{"osv:GHSA-one", "absent"}, records) != nil {
		t.Fatal("invented CVSS from prose/label")
	}
}
