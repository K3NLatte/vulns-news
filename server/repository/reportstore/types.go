// Package reportstore は、リポジトリの脆弱性レポートをSQLiteに保存する。
// HTTPハンドラー、認可、LLMの実行は扱わない。
package reportstore

import (
	"encoding/json"
	"errors"
)

var (
	ErrNotFound = errors.New("report not found")
	ErrInvalid  = errors.New("invalid report input")
)

type Status string

const (
	Screened Status = "screened"
	Analyzed Status = "analyzed"
)

type Relevance string

const (
	Related         Relevance = "related"
	PossiblyRelated Relevance = "possibly_related"
	Unrelated       Relevance = "unrelated"
	Unknown         Relevance = "unknown"
)

// ContextKey は、解析対象リポジトリと入力データの版を識別する。解析の実行ごとのIDではない。
// 日時はUTCのRFC3339文字列で受け取り、保存・フィード変換時にRFC3339Nanoへ正規化する。
// ナノ秒まで保持し、同じ時刻を表す文字列は表記が異なっても同じ対象として扱う。
// 空のrevisionは更新日時が不明な状態であり、日時が分かっている版とは区別する。
type ContextKey struct {
	RepositoryID          string `json:"repository_id"`
	RepositoryCommit      string `json:"repository_commit"`
	VulnerabilityID       string `json:"vulnerability_id"`
	VulnerabilityRevision string `json:"vulnerability_revision,omitempty"`
}

// Input は、DBの各カラムと保存対象のレポート本文を持つ。
// 任意項目の空文字列はSQLのNULLになる。日時の空文字列は不明を表し、
// CVE番号があっても更新日時が不明な場合は受け付ける。
// CVSSのnilは未評価であり、0点とは区別する。
type Input struct {
	ContextKey
	CVEID       string          `json:"cve_id,omitempty"`
	CVERevision string          `json:"cve_revision,omitempty"`
	PublishedAt string          `json:"published_at,omitempty"`
	Severity    string          `json:"severity,omitempty"`
	CVSS        *float64        `json:"cvss,omitempty"`
	Status      Status          `json:"status"`
	Relevance   Relevance       `json:"relevance"`
	Body        json.RawMessage `json:"report_json"`
}

type Report struct {
	ID int64 `json:"report_id"`
	Input
	StoredAt string `json:"stored_at"`
}

// ListOptions は、ContextKeyごとの最新結果を取得する条件。
// 異なるコミットの結果を混在させないため、リポジトリIDとコミットの両方を必須とする。
// 最新結果を選んでからunrelatedを除外する。IncludeUnrelatedで除外せずに取得できる。
type ListOptions struct {
	RepositoryID     string
	RepositoryCommit string
	Limit            int   // 0なら既定の50件。最大200件。
	BeforeID         int64 // 前ページ末尾のReport.ID。0なら最新から取得する。
	IncludeUnrelated bool
}

// Screening はフィード変換時に任意で渡す一次判定結果。フィード自体には一次判定の根拠ID一覧がない。
type Screening struct {
	Relevance   Relevance `json:"relevance"`
	Reason      string    `json:"reason"`
	EvidenceIDs []string  `json:"evidence_ids"`
}

const MaxBodyBytes = 8 << 20
