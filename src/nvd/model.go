package nvd

import "time"

// NormalizedVulnerability is the NVD data exposed to the rest of the project.
type NormalizedVulnerability struct {
	ID          string           `json:"id"`
	PublishedAt time.Time        `json:"published_at"`
	ModifiedAt  time.Time        `json:"modified_at"`
	Description string           `json:"description"`
	Severity    string           `json:"severity,omitempty"`
	CVSS        *float64         `json:"cvss,omitempty"`
	Weaknesses  []string         `json:"weaknesses"`
	Affected    []AffectedTarget `json:"affected"`
	References  []Reference      `json:"references"`
}

// CVE is an alias kept for callers of the earlier crawler API.
type CVE = NormalizedVulnerability

// AffectedTarget identifies an affected product or CPE version range.
type AffectedTarget struct {
	Vendor                string `json:"vendor,omitempty"`
	Product               string `json:"product,omitempty"`
	PackageName           string `json:"package_name,omitempty"`
	CPE                   string `json:"cpe,omitempty"`
	Version               string `json:"version,omitempty"`
	VersionStartIncluding string `json:"version_start_including,omitempty"`
	VersionStartExcluding string `json:"version_start_excluding,omitempty"`
	VersionEndIncluding   string `json:"version_end_including,omitempty"`
	VersionEndExcluding   string `json:"version_end_excluding,omitempty"`
}

// Reference is a source URL and its NVD metadata.
type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}
