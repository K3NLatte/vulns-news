package nvd

// Page is one page returned by the NVD CVE 2.0 API.
type Page struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability wraps an NVD CVE item.
type Vulnerability struct {
	CVE CVE `json:"cve"`
}

// CVE contains only the NVD fields used by normalization.
type CVE struct {
	ID             string          `json:"id"`
	Published      string          `json:"published"`
	LastModified   string          `json:"lastModified"`
	Descriptions   []LanguageValue `json:"descriptions"`
	Metrics        Metrics         `json:"metrics"`
	Weaknesses     []Weakness      `json:"weaknesses"`
	Configurations []Configuration `json:"configurations"`
	References     []Reference     `json:"references"`
}

// LanguageValue is localized NVD text.
type LanguageValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Metrics contains supported CVSS generations in preference order.
type Metrics struct {
	CVSSMetricV31 []CVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []CVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []CVSSMetric `json:"cvssMetricV2"`
}

// CVSSMetric contains the score and severity fields needed from an NVD metric.
type CVSSMetric struct {
	Type         string   `json:"type"`
	BaseSeverity string   `json:"baseSeverity"`
	CVSSData     CVSSData `json:"cvssData"`
}

// CVSSData contains normalized fields shared by supported CVSS generations.
type CVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// Weakness contains localized CWE descriptions.
type Weakness struct {
	Description []LanguageValue `json:"description"`
}

// Reference is an NVD source URL and its NVD tags.
type Reference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// Configuration is an NVD applicability configuration. Logical applicability
// cannot be represented by the domain model, so normalization retains its
// vulnerable CPE matches rather than attempting to evaluate the expression.
type Configuration struct {
	Nodes []Node `json:"nodes"`
}

// Node contains CPE matches and, for compatibility with nested NVD documents,
// child nodes.
type Node struct {
	CPEMatch []CPEMatch `json:"cpeMatch"`
	Children []Node     `json:"children"`
}

// CPEMatch identifies an affected CPE and NVD's optional version boundaries.
type CPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}
