package live

import (
	"encoding/json"
	"math"
	"sort"
	"strings"

	cvss30 "github.com/pandatix/go-cvss/30"
	cvss31 "github.com/pandatix/go-cvss/31"
	cvss40 "github.com/pandatix/go-cvss/40"
	"vulns-news/src/reposcan"
)

type sourceCVSS struct {
	score                   float64
	rank                    int
	source, vector, version string
}

// Only structured severity vectors from current, non-withdrawn OSV records are
// eligible. Description text, LLM prose and provider severity labels are not scores.
// Prefer v4.0 > v3.1 > v3.0, then the highest base score within that version.
func osvCVSS(keys []string, records map[string]reposcan.SourceRecord) *sourceCVSS {
	keys = append([]string(nil), keys...)
	sort.Strings(keys)
	var best *sourceCVSS
	for _, key := range keys {
		record, ok := records[key]
		if !ok || record.Source != "osv" || record.Withdrawn || key != "osv:"+record.ID {
			continue
		}
		var raw struct {
			ID        string `json:"id"`
			Withdrawn string `json:"withdrawn"`
			Severity  []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
		}
		if json.Unmarshal(record.Raw, &raw) != nil || raw.ID != record.ID || raw.Withdrawn != "" {
			continue
		}
		for _, severity := range raw.Severity {
			value, ok := vectorScore(severity.Type, severity.Score)
			if !ok {
				continue
			}
			value.source = "OSV " + record.ID + " / CVSS " + value.version + " 基本値"
			if best == nil || value.rank > best.rank || (value.rank == best.rank && value.score > best.score) {
				best = &value
			}
		}
	}
	return best
}

func vectorScore(kind, vector string) (sourceCVSS, bool) {
	value := sourceCVSS{vector: vector}
	switch {
	case kind == "CVSS_V3" && strings.HasPrefix(vector, "CVSS:3.0/"):
		v, err := cvss30.ParseVector(vector)
		if err != nil {
			return value, false
		}
		value.score, value.rank, value.version = v.BaseScore(), 30, "3.0"
	case kind == "CVSS_V3" && strings.HasPrefix(vector, "CVSS:3.1/"):
		v, err := cvss31.ParseVector(vector)
		if err != nil {
			return value, false
		}
		value.score, value.rank, value.version = v.BaseScore(), 31, "3.1"
	case kind == "CVSS_V4" && strings.HasPrefix(vector, "CVSS:4.0/"):
		v, err := cvss40.ParseVector(vector)
		if err != nil {
			return value, false
		}
		// v4 Score includes threat/environment metrics. Rebuild base-only metrics
		// after validating the entire vector, so this field always means CVSS-B.
		base := "CVSS:4.0"
		for _, metric := range []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"} {
			text, err := v.Get(metric)
			if err != nil {
				return value, false
			}
			base += "/" + metric + ":" + text
		}
		b, err := cvss40.ParseVector(base)
		if err != nil {
			return value, false
		}
		value.score, value.rank, value.version = b.Score(), 40, "4.0"
	default:
		return value, false
	}
	return value, !math.IsNaN(value.score) && !math.IsInf(value.score, 0) && value.score >= 0 && value.score <= 10
}
func cvssSeverity(score float64) string {
	switch {
	case score == 0:
		return "none"
	case score < 4:
		return "low"
	case score < 7:
		return "medium"
	case score < 9:
		return "high"
	default:
		return "critical"
	}
}
