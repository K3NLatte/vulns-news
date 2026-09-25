package main

// API のレスポンスと mockdata の JSON に対応する型。
// 日時はフロントが受け取るミリ秒付き UTC 形式を保つため、文字列で扱う。
// 例: 2026-09-24T03:00:00.000Z

// FeedResult は全体・リポジトリ別の CVE 一覧を表す。
type FeedResult struct {
	Items        []FeedItem `json:"items"`        // 0件の場合も null ではなく空の配列を使う。
	Total        int        `json:"total"`        // 絞り込み前の件数。
	MatchedTotal int        `json:"matchedTotal"` // 絞り込み後の件数。
	GeneratedAt  string     `json:"generatedAt"`
}

// FeedItem は CVE 1件を表し、一覧の要素と詳細レスポンスで共用する。
type FeedItem struct {
	ID                 string              `json:"id"`
	AdvisoryID         string              `json:"advisoryId"`
	Title              string              `json:"title"`
	Product            string              `json:"product"`
	AffectedVersions   string              `json:"affectedVersions"`
	FixedVersion       string              `json:"fixedVersion"`
	Severity           string              `json:"severity"`             // critical / high / medium / low。
	CVSS               *float64            `json:"cvss"`                 // 未評価は null。0点と区別する。
	Assessment         string              `json:"assessment,omitempty"` // unverified。指定がなければ省略。
	PublishedAt        string              `json:"publishedAt"`
	UpdatedAt          string              `json:"updatedAt"`
	Summary            string              `json:"summary"`
	Exploitation       string              `json:"exploitation"` // observed / poc / not-observed。
	AffectedComponent  string              `json:"affectedComponent"`
	Remediation        []string            `json:"remediation"`
	ProofOfConcept     *FeedProofOfConcept `json:"proofOfConcept,omitempty"`
	RepositoryAnalysis string              `json:"repositoryAnalysis,omitempty"` // analyzed / pending。
	Analysis           FeedAnalysis        `json:"analysis"`
	Relevance          *FeedRelevance      `json:"relevance,omitempty"`
	Sources            []FeedSource        `json:"sources"`
}

// FeedAnalysis は記事の分析内容と根拠を表す。
type FeedAnalysis struct {
	Summary    string `json:"summary"`
	Evidence   string `json:"evidence"`
	Confidence string `json:"confidence"` // high / medium / low。
}

// FeedRelevance は対象リポジトリとの関連性を表す。
type FeedRelevance struct {
	Kind             string   `json:"kind"`            // direct / transitive / review。
	Priority         string   `json:"priority"`        // urgent / high / medium / low / review。
	Score            *float64 `json:"score,omitempty"` // 0〜100。未評価なら省略し、0点と区別する。
	Reason           string   `json:"reason"`
	PackageName      string   `json:"packageName"`
	InstalledVersion string   `json:"installedVersion"`
}

// FeedProofOfConcept は検証例と成立条件を表す。
type FeedProofOfConcept struct {
	Language   string   `json:"language"`
	Code       string   `json:"code"`
	Conditions []string `json:"conditions"`
}

// FeedSource は記事の参照先を表す。
type FeedSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Kind string `json:"kind"` // vendor / reference。
}

// CreateRepositoryResponse はリポジトリ登録時に返す識別子を表す。
type CreateRepositoryResponse struct {
	RepositoryID string `json:"repository_id"`
	JobID        string `json:"job_id"`
}

// JobResponse はリポジトリの解析処理の状態を表す。
// 任意の数値・真偽値はポインタにし、未指定と 0・false を区別する。
type JobResponse struct {
	JobID               string `json:"job_id"`
	RepositoryID        string `json:"repository_id"`
	Stage               string `json:"stage"` // queued / profiling / matching / screening / analyzing / completed / failed。
	Processed           *int   `json:"processed,omitempty"`
	Total               *int   `json:"total,omitempty"`
	ConfirmedCount      *int   `json:"confirmedCount,omitempty"` // 分析済みの記事数。
	PendingCount        *int   `json:"pendingCount,omitempty"`   // 関連性が未確定の記事数。
	HasAvailableResults *bool  `json:"hasAvailableResults,omitempty"`
	ErrorMessage        string `json:"errorMessage,omitempty"`
}
