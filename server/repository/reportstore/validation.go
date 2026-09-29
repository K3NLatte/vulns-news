package reportstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var utcTimestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)

var bodyFields = map[string]bool{
	"matches": true, "screening_reason": true, "screening_evidence_ids": true,
	"summary": true, "repository_impact": true, "missing_information": true,
	"recommended_actions": true, "applicability": true, "evidence": true,
}

var contextFields = []string{"repository_id", "repository_commit", "vulnerability_id", "vulnerability_revision"}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func nonempty(value string) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) != ""
}

// canonicalTimestamp は、時刻とナノ秒精度を保ち、小数部末尾の不要な0を除く。
// 不明な日時は補完せず、不明のまま返す。
func canonicalTimestamp(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if !utcTimestamp.MatchString(value) {
		return "", invalid("timestamp must be a nonzero UTC RFC3339 timestamp or absent")
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || t.Year() <= 1 {
		return "", invalid("timestamp must be a nonzero UTC RFC3339 timestamp or absent")
	}
	return t.Format(time.RFC3339Nano), nil
}

func canonicalizeContextKey(key ContextKey) (ContextKey, error) {
	value, err := canonicalTimestamp(key.VulnerabilityRevision)
	if err != nil {
		return ContextKey{}, fmt.Errorf("vulnerability_revision: %w", err)
	}
	key.VulnerabilityRevision = value
	return key, nil
}

// canonicalizeInputTimes は日時の3カラムだけを正規化する。
// ほかの項目とレポート本文の検証はvalidateInputで行う。
func canonicalizeInputTimes(input Input) (Input, error) {
	key, err := canonicalizeContextKey(input.ContextKey)
	if err != nil {
		return Input{}, err
	}
	input.ContextKey = key
	input.PublishedAt, err = canonicalTimestamp(input.PublishedAt)
	if err != nil {
		return Input{}, fmt.Errorf("published_at: %w", err)
	}
	input.CVERevision, err = canonicalTimestamp(input.CVERevision)
	if err != nil {
		return Input{}, fmt.Errorf("cve_revision: %w", err)
	}
	return input, nil
}

func validTime(value string) bool {
	_, err := canonicalTimestamp(value)
	return value != "" && err == nil
}

func validateKey(key ContextKey) error {
	if !nonempty(key.RepositoryID) || !nonempty(key.RepositoryCommit) || !nonempty(key.VulnerabilityID) {
		return invalid("repository ID, commit and vulnerability ID are required")
	}
	if key.VulnerabilityRevision != "" && !validTime(key.VulnerabilityRevision) {
		return invalid("vulnerability_revision must be a nonzero UTC RFC3339 timestamp or absent")
	}
	return nil
}

func validateInput(input Input) error {
	if err := validateKey(input.ContextKey); err != nil {
		return err
	}
	if input.PublishedAt != "" && !validTime(input.PublishedAt) {
		return invalid("published_at must be a nonzero UTC RFC3339 timestamp or absent")
	}
	if input.CVEID != "" && !nonempty(input.CVEID) {
		return invalid("CVE ID must be nonempty text or absent")
	}
	if input.CVERevision != "" && (input.CVEID == "" || !validTime(input.CVERevision)) {
		return invalid("CVE revision requires a CVE ID and must be a nonzero UTC RFC3339 timestamp or absent")
	}
	if input.Severity != "" && !nonempty(input.Severity) {
		return invalid("severity must be nonempty text or absent")
	}
	if input.CVSS != nil && (math.IsNaN(*input.CVSS) || math.IsInf(*input.CVSS, 0) || *input.CVSS < 0 || *input.CVSS > 10) {
		return invalid("cvss must be a finite number between 0 and 10")
	}
	if !((input.Status == Analyzed && input.Relevance == Related) || (input.Status == Screened && (input.Relevance == PossiblyRelated || input.Relevance == Unrelated || input.Relevance == Unknown))) {
		return invalid("unsupported status/relevance combination")
	}
	body, err := readObject(input.Body)
	if err != nil {
		return err
	}
	for key := range body {
		if !bodyFields[key] {
			return invalid("unsupported report body field %q", key)
		}
	}
	if !textValue(body["screening_reason"]) {
		return invalid("screening_reason must be nonempty text")
	}
	if err := objectArray(body["matches"], "matches"); err != nil {
		return err
	}
	for _, match := range body["matches"].([]any) {
		if err := validateMatch(match.(map[string]any)); err != nil {
			return err
		}
	}
	applicability, ok := body["applicability"].(map[string]any)
	if !ok && !(input.Relevance == Unrelated && body["applicability"] == nil) {
		return invalid("applicability must be an object")
	}
	if ok {
		for _, key := range contextFields {
			if _, exists := applicability[key]; exists {
				return invalid("applicability duplicates %s", key)
			}
		}
		if err := validateApplicability(applicability); err != nil {
			return err
		}
	}
	for _, key := range []string{"summary", "repository_impact"} {
		if input.Status == Screened {
			if body[key] != nil {
				return invalid("screened report cannot contain %s", key)
			}
		} else {
			claim, ok := body[key].(map[string]any)
			if !ok || !textValue(claim["text"]) {
				return invalid("%s must be a supported nonempty claim", key)
			}
			if ids, ok := claim["evidence_ids"].([]any); !ok || len(ids) == 0 {
				return invalid("%s requires evidence_ids", key)
			}
		}
	}
	for _, key := range []string{"missing_information", "recommended_actions"} {
		if body[key] != nil {
			if err := stringArray(body[key], key); err != nil {
				return err
			}
		}
	}
	if err := objectArray(body["evidence"], "evidence"); err != nil {
		return err
	}
	evidence := body["evidence"].([]any)
	if len(evidence) == 0 {
		return invalid("evidence cannot be empty")
	}
	known := make(map[string]bool, len(evidence))
	for _, entry := range evidence {
		item := entry.(map[string]any)
		for _, field := range []string{"id", "kind", "source", "content"} {
			if !textValue(item[field]) {
				return invalid("evidence %s must be nonempty text", field)
			}
		}
		if uri, exists := item["uri"]; exists {
			if _, ok := uri.(string); !ok {
				return invalid("evidence uri must be text when present")
			}
		}
		id := item["id"].(string)
		if known[id] {
			return invalid("duplicate evidence ID %q", id)
		}
		known[id] = true
	}
	if ids, exists := body["screening_evidence_ids"]; exists || input.Relevance == Unrelated {
		if values, ok := ids.([]any); !ok || len(values) == 0 {
			return invalid("screening_evidence_ids must be a nonempty array")
		}
	}
	return validateReferences(body, known)
}

func textValue(value any) bool {
	text, ok := value.(string)
	return ok && nonempty(text)
}

func objectArray(value any, name string) error {
	items, ok := value.([]any)
	if !ok {
		return invalid("%s must be an array of objects", name)
	}
	for _, item := range items {
		if _, ok := item.(map[string]any); !ok {
			return invalid("%s must contain only objects", name)
		}
	}
	return nil
}

func stringArray(value any, name string) error {
	items, ok := value.([]any)
	if !ok {
		return invalid("%s must be an array of text", name)
	}
	for _, item := range items {
		if !textValue(item) {
			return invalid("%s must contain nonempty text", name)
		}
	}
	return nil
}

func validateMatch(match map[string]any) error {
	for _, field := range []string{"repository_item_id", "affected_target_id", "reason", "version_status", "installed_version"} {
		if value, exists := match[field]; exists {
			if _, ok := value.(string); !ok {
				return invalid("match %s must be text", field)
			}
		}
	}
	return nil
}

// 解析モデルの全項目を定義し直さず、既知の項目の構造を検証する。
// 入れ子内の未知の項目は保持し、その中にある根拠IDの参照も検証する。
func validateApplicability(app map[string]any) error {
	for _, field := range []string{"package_presence", "affected_version", "feature_usage", "code_reachability", "attack_conditions"} {
		if value, exists := app[field]; exists {
			stage, ok := value.(map[string]any)
			if !ok {
				return invalid("applicability %s must be an object", field)
			}
			if value, exists := stage["level"]; exists {
				number, ok := value.(json.Number)
				if !ok {
					return invalid("applicability level must be an integer")
				}
				level, err := number.Int64()
				if err != nil || level < 1 || level > 5 {
					return invalid("applicability level must be between 1 and 5")
				}
			}
			if value, exists := stage["status"]; exists && !textValue(value) {
				return invalid("applicability status must be nonempty text")
			}
			if value, exists := stage["conditional_on_package_identity"]; exists {
				if _, ok := value.(bool); !ok {
					return invalid("conditional_on_package_identity must be boolean")
				}
			}
			if value, exists := stage["sources"]; exists {
				if err := objectArray(value, "applicability sources"); err != nil {
					return err
				}
			}
			if value, exists := stage["missing_reasons"]; exists {
				if err := stringArray(value, "missing_reasons"); err != nil {
					return err
				}
			}
		}
	}
	if value, exists := app["matches"]; exists {
		if err := objectArray(value, "applicability matches"); err != nil {
			return err
		}
		for _, value := range value.([]any) {
			item := value.(map[string]any)
			if value, exists := item["match"]; exists {
				match, ok := value.(map[string]any)
				if !ok {
					return invalid("applicability match must be an object")
				}
				if err := validateMatch(match); err != nil {
					return err
				}
			}
			if err := validateApplicability(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateReferences(value any, known map[string]bool) error {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if key == "evidence_ids" || key == "screening_evidence_ids" {
				if err := stringArray(child, key); err != nil {
					return err
				}
				seen := make(map[string]bool)
				for _, value := range child.([]any) {
					id := value.(string)
					if !known[id] || seen[id] {
						return invalid("unknown or duplicate evidence reference %q", id)
					}
					seen[id] = true
				}
			} else if err := validateReferences(child, known); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := validateReferences(child, known); err != nil {
				return err
			}
		}
	}
	return nil
}

// mapへの変換で重複キーが失われる前に、Decoder.Tokenで検出して拒否する。
// 入れ子の拡張項目に含まれる大きな数値も、json.Numberで精度を保つ。
func readObject(data []byte) (map[string]any, error) {
	if len(data) > MaxBodyBytes {
		return nil, invalid("JSON exceeds %d bytes", MaxBodyBytes)
	}
	if !utf8.Valid(data) {
		return nil, invalid("JSON must be UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readValue(decoder, 0)
	if err != nil {
		return nil, invalid("JSON: %v", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, invalid("JSON has trailing data")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, invalid("JSON must be an object")
	}
	return object, nil
}

func readValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("nesting exceeds 64 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("object key is not text")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate key %q", key)
			}
			value, err := readValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		_, err := decoder.Token()
		return object, err
	case json.Delim('['):
		array := make([]any, 0)
		for decoder.More() {
			value, err := readValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		_, err := decoder.Token()
		return array, err
	default:
		return token, nil
	}
}
