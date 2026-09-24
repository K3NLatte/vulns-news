// Package domain defines language- and ecosystem-independent facts shared by
// repository profiling, vulnerability ingestion, matching, analysis, and feeds.
package domain

import "time"

// RepositoryProfile is a normalized snapshot of one repository commit.
// Ecosystem-specific profilers populate this type without executing repository code.
type RepositoryProfile struct {
	Repository         RepositoryIdentity    `json:"repository"`
	ProfiledAt         time.Time             `json:"profiled_at"`
	Languages          []LanguageUsage       `json:"languages"`
	Ecosystems         []EcosystemUsage      `json:"ecosystems"`
	Components         []Component           `json:"components"`
	Products           []ProductCandidate    `json:"products"`
	Containers         []ContainerReference  `json:"containers"`
	Infrastructure     []InfrastructureAsset `json:"infrastructure"`
	Warnings           []string              `json:"warnings,omitempty"`
	SourceObservations []SourceObservation   `json:"source_observations,omitempty"`
}

// SourceObservation records syntax, not runtime execution or exploitability.
type SourceObservation struct {
	Kind    string `json:"kind"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	EndLine int    `json:"end_line"`
	Package string `json:"package"`
	Symbol  string `json:"symbol,omitempty"`
	Route   string `json:"route,omitempty"`
}

// RepositoryIdentity pins analysis to an immutable commit rather than a moving branch.
type RepositoryIdentity struct {
	ID           string `json:"id"`
	CanonicalURL string `json:"canonical_url"`
	Ref          string `json:"ref"`
	CommitSHA    string `json:"commit_sha"`
}

// LanguageUsage records a detected source language and how it was detected.
type LanguageUsage struct {
	Name        string   `json:"name"`
	Percentage  *float64 `json:"percentage,omitempty"`
	SourcePaths []string `json:"source_paths"`
}

// EcosystemUsage identifies a package ecosystem and its source files. Name is
// intentionally open so adding an ecosystem does not require changing domain code.
type EcosystemUsage struct {
	Name      string   `json:"name"`
	Manifests []string `json:"manifests"`
	Lockfiles []string `json:"lockfiles"`
}

// Component is a dependency discovered by an ecosystem-specific profiler.
// PURL is the preferred cross-tool identity when it is available.
type Component struct {
	ID         string `json:"id"`
	PURL       string `json:"purl,omitempty"`
	Ecosystem  string `json:"ecosystem"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Direct     bool   `json:"direct"`
	Scope      string `json:"scope,omitempty"`
	SourcePath string `json:"source_path"`
}

// ProductCandidate represents software visible outside a language package
// manager, such as PostgreSQL, nginx, Kubernetes, or an operating-system package.
type ProductCandidate struct {
	ID         string   `json:"id"`
	Ecosystem  string   `json:"ecosystem,omitempty"`
	Vendor     string   `json:"vendor,omitempty"`
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	CPEs       []string `json:"cpes"`
	Aliases    []string `json:"aliases"`
	SourcePath string   `json:"source_path"`
}

// ContainerReference is a container image reference found in a Dockerfile,
// Compose file, or deployment manifest. Profiling does not inspect image layers.
type ContainerReference struct {
	ID         string `json:"id"`
	Image      string `json:"image"`
	Tag        string `json:"tag,omitempty"`
	Digest     string `json:"digest,omitempty"`
	SourcePath string `json:"source_path"`
}

// InfrastructureAsset is a product inferred from deployment or infrastructure
// configuration, for example a Terraform-managed database service.
type InfrastructureAsset struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Provider   string `json:"provider,omitempty"`
	Product    string `json:"product"`
	Version    string `json:"version,omitempty"`
	SourcePath string `json:"source_path"`
}

// NormalizedVulnerability is the backend-owned representation of an NVD record.
// Raw NVD documents should be retained separately for audit and re-normalization.
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

// AffectedTargetKind identifies what kind of repository fact may match an NVD target.
type AffectedTargetKind string

const (
	AffectedPackage        AffectedTargetKind = "package"
	AffectedProduct        AffectedTargetKind = "product"
	AffectedContainer      AffectedTargetKind = "container"
	AffectedInfrastructure AffectedTargetKind = "infrastructure"
)

// AffectedTarget is a normalized package, product, container, or infrastructure target.
type AffectedTarget struct {
	ID          string              `json:"id"`
	Kind        AffectedTargetKind  `json:"kind"`
	PURL        string              `json:"purl,omitempty"`
	Ecosystem   string              `json:"ecosystem,omitempty"`
	PackageName string              `json:"package_name,omitempty"`
	Vendor      string              `json:"vendor,omitempty"`
	Product     string              `json:"product,omitempty"`
	CPEs        []string            `json:"cpes"`
	Aliases     []string            `json:"aliases"`
	Constraints []VersionConstraint `json:"constraints"`
}

// VersionConstraint retains source version boundaries and the comparison scheme
// required to interpret them. Different ecosystems must use their own evaluator.
type VersionConstraint struct {
	Scheme                string `json:"scheme"`
	Expression            string `json:"expression,omitempty"`
	VersionStartIncluding string `json:"version_start_including,omitempty"`
	VersionStartExcluding string `json:"version_start_excluding,omitempty"`
	VersionEndIncluding   string `json:"version_end_including,omitempty"`
	VersionEndExcluding   string `json:"version_end_excluding,omitempty"`
}

// Reference is a normalized source URL attached to a vulnerability.
type Reference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// MatchReason is a deterministic identity-match reason.
type MatchReason string

const (
	MatchPURLExact           MatchReason = "purl_exact"
	MatchCPEExact            MatchReason = "cpe_exact"
	MatchPackageExact        MatchReason = "ecosystem_package_exact"
	MatchProductExact        MatchReason = "vendor_product_exact"
	MatchProductAliasExact   MatchReason = "product_alias_exact"
	MatchContainerExact      MatchReason = "container_image_exact"
	MatchInfrastructureExact MatchReason = "infrastructure_product_exact"
)

// VersionStatus is produced only by an ecosystem-aware version evaluator.
type VersionStatus string

const (
	VersionAffected    VersionStatus = "affected"
	VersionNotAffected VersionStatus = "not_affected"
	VersionUnknown     VersionStatus = "unknown"
)

// TargetMatch links one repository fact to one affected target.
type TargetMatch struct {
	RepositoryItemID string        `json:"repository_item_id"`
	AffectedTargetID string        `json:"affected_target_id"`
	Reason           MatchReason   `json:"reason"`
	VersionStatus    VersionStatus `json:"version_status"`
	InstalledVersion string        `json:"installed_version,omitempty"`
}

// MatchCandidate is created deterministically before the LLM is called.
type MatchCandidate struct {
	RepositoryID     string        `json:"repository_id"`
	RepositoryCommit string        `json:"repository_commit"`
	VulnerabilityID  string        `json:"vulnerability_id"`
	VulnerabilityRev time.Time     `json:"vulnerability_revision"`
	Matches          []TargetMatch `json:"matches"`
}
