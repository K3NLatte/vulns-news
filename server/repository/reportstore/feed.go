package reportstore

import (
	"encoding/json"
	"reflect"
	"time"
)

var feedColumns = map[string]bool{
	"repository_id": true, "repository_commit": true,
	"vulnerability_id": true, "vulnerability_revision": true,
	"cve_id": true, "cve_revision": true, "published_at": true,
	"severity": true, "cvss": true, "status": true, "relevance": true,
}

// FromFeedJSON は、フィードのJSONを各カラムとレポート本文に分ける。
// generationは保存しない。最上位に未知の項目があればエラーにし、
// フィードの仕様変更によってデータが黙って失われることを防ぐ。
// 日時の欠損、null、バックエンドのゼロ日時は、不明を表す空文字列へ変換する。
func FromFeedJSON(data []byte, screening *Screening) (Input, error) {
	feed, err := readObject(data)
	if err != nil {
		return Input{}, err
	}
	for key := range feed {
		if !bodyFields[key] && !feedColumns[key] && key != "generation" {
			return Input{}, invalid("unsupported feed field %q", key)
		}
	}
	var input Input
	if err := json.Unmarshal(data, &input); err != nil {
		return Input{}, invalid("feed columns: %v", err)
	}
	input.PublishedAt = normalizeFeedTime(input.PublishedAt)
	input.VulnerabilityRevision = normalizeFeedTime(input.VulnerabilityRevision)
	input.CVERevision = normalizeFeedTime(input.CVERevision)
	input, err = canonicalizeInputTimes(input)
	if err != nil {
		return Input{}, err
	}
	if app, ok := feed["applicability"].(map[string]any); ok {
		for key, want := range contextValues(input.ContextKey) {
			value, ok := app[key].(string)
			if key == "vulnerability_revision" {
				// revisionの欠損やnullも、ゼロ日時と同じく不明として扱う。
				ok = ok || app[key] == nil
				value, err = canonicalTimestamp(normalizeFeedTime(value))
				if err != nil {
					return Input{}, invalid("applicability vulnerability_revision: %v", err)
				}
			}
			if !ok || value != want {
				return Input{}, invalid("applicability identity does not match %s", key)
			}
			delete(app, key)
		}
	}
	for key := range feed {
		if !bodyFields[key] {
			delete(feed, key)
		}
	}
	if screening != nil {
		if screening.Relevance != input.Relevance || screening.Reason != feed["screening_reason"] {
			return Input{}, invalid("screening decision does not match feed")
		}
		if len(screening.EvidenceIDs) == 0 {
			return Input{}, invalid("screening evidence IDs are required")
		}
		ids := make([]any, len(screening.EvidenceIDs))
		for i, id := range screening.EvidenceIDs {
			if !nonempty(id) {
				return Input{}, invalid("screening evidence IDs must be nonempty UTF-8 text")
			}
			ids[i] = id
		}
		if old, exists := feed["screening_evidence_ids"]; exists && !reflect.DeepEqual(old, ids) {
			return Input{}, invalid("screening evidence IDs conflict with feed")
		}
		feed["screening_evidence_ids"] = ids
	}
	input.Body, err = json.Marshal(feed)
	if err != nil {
		return Input{}, invalid("report body: %v", err)
	}
	if err := validateInput(input); err != nil {
		return Input{}, err
	}
	return input, nil
}

// ToFeedJSON は、DBのカラムからフィードの識別情報を復元する。
// generationやDB内のIDは出力せず、不明な日時を補完しない。
// 不明な日時のキーを省略することで、time.Timeを含むフィード型へ読み込めるようにする。
func ToFeedJSON(report Report) ([]byte, error) {
	input, err := canonicalizeInputTimes(report.Input)
	if err != nil {
		return nil, err
	}
	report.Input = input
	if err := validateInput(report.Input); err != nil {
		return nil, err
	}
	feed, err := readObject(report.Body)
	if err != nil {
		return nil, err
	}
	for key, value := range contextValues(report.ContextKey) {
		if value != "" {
			feed[key] = value
		}
	}
	if report.PublishedAt != "" {
		feed["published_at"] = report.PublishedAt
	}
	feed["status"] = report.Status
	feed["relevance"] = report.Relevance
	if report.CVEID != "" {
		feed["cve_id"] = report.CVEID
	}
	if report.CVERevision != "" {
		feed["cve_revision"] = report.CVERevision
	}
	if report.Severity != "" {
		feed["severity"] = report.Severity
	}
	if report.CVSS != nil {
		feed["cvss"] = *report.CVSS
	}
	if app, ok := feed["applicability"].(map[string]any); ok {
		for key, value := range contextValues(report.ContextKey) {
			if value != "" {
				app[key] = value
			}
		}
	}
	data, err := json.Marshal(feed)
	if err != nil {
		return nil, invalid("feed: %v", err)
	}
	return data, nil
}

func normalizeFeedTime(value string) string {
	if utcTimestamp.MatchString(value) {
		if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil && parsed.IsZero() {
			return ""
		}
	}
	return value
}

func contextValues(key ContextKey) map[string]string {
	return map[string]string{
		"repository_id": key.RepositoryID, "repository_commit": key.RepositoryCommit,
		"vulnerability_id": key.VulnerabilityID, "vulnerability_revision": key.VulnerabilityRevision,
	}
}
