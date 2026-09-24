// Package assessment reports conservative, deterministic Level 1–5 checks.
// It does not scan source, compare versions, or infer exploitability from prose.
package assessment

import (
	"strings"
	"time"

	"vulns-news/src/domain"
)

// Status distinguishes missing proof from a bounded search with no result.
type Status string

const (
	Unknown Status = "unknown"
	// NotFound means no exact package identity was found in the supplied candidate;
	// it does not mean the repository is free of the package or vulnerability.
	NotFound  Status = "not_found"
	Confirmed Status = "confirmed"
	// NotAffected is only a version evaluator's result, not an exploitability verdict.
	NotAffected Status = "not_affected"
)

// Source identifies supplied facts, not newly generated evidence. MatchIndex is
// zero-based within Candidate.Matches. IDs are scoped by Report's snapshot IDs.
type Source struct {
	RepositoryItemID string `json:"repository_item_id"`
	AffectedTargetID string `json:"affected_target_id"`
	SourcePath       string `json:"source_path,omitempty"`
	MatchIndex       int    `json:"match_index"`
}

// Check is one bounded question. ConditionalOnPackageIdentity marks a version
// result that must not be interpreted as proof of an affected installed package.
// EvidenceIDs remains empty: Assess's inputs contain no processor evidence IDs.
type Check struct {
	Level                        int      `json:"level"`
	Status                       Status   `json:"status"`
	ConditionalOnPackageIdentity bool     `json:"conditional_on_package_identity"`
	Sources                      []Source `json:"sources"`
	EvidenceIDs                  []string `json:"evidence_ids"`
	MissingReasons               []string `json:"missing_reasons"`
}

// MatchAssessment preserves each deterministic result independently. Invalid
// references and conflicting duplicate matches are unknown, never proof.
type MatchAssessment struct {
	Match           domain.TargetMatch `json:"match"`
	PackagePresence Check              `json:"package_presence"`
	AffectedVersion Check              `json:"affected_version"`
}

// Report is scoped to the supplied candidate, not a complete repository audit.
// There is deliberately no overall risk, confidence, or exploitability score.
// AffectedVersion is confirmed if any identity-confirmed match is affected; it
// is not_affected only if every supplied match has confirmed package identity
// and a not_affected result. Empty or unresolved candidates cannot prove safety.
type Report struct {
	RepositoryID          string            `json:"repository_id"`
	RepositoryCommit      string            `json:"repository_commit"`
	VulnerabilityID       string            `json:"vulnerability_id"`
	VulnerabilityRevision time.Time         `json:"vulnerability_revision"`
	PackagePresence       Check             `json:"package_presence"`
	AffectedVersion       Check             `json:"affected_version"`
	FeatureUsage          Check             `json:"feature_usage"`
	CodeReachability      Check             `json:"code_reachability"`
	AttackConditions      Check             `json:"attack_conditions"`
	Matches               []MatchAssessment `json:"matches"`
}

func check(level int, reason string) Check {
	c := Check{Level: level, Status: Unknown, Sources: []Source{}, EvidenceIDs: []string{}, MissingReasons: []string{}}
	if reason != "" {
		c.MissingReasons = append(c.MissingReasons, reason)
	}
	return c
}

// Assess consumes backend-owned deterministic match statuses, without redoing
// ecosystem-specific version comparisons. Callers must not supply LLM-authored
// candidates. Snapshot and reference checks fail closed. Levels 3–5 remain unknown
// because these domain types carry no feature, call-graph, or deployment proof.
func Assess(profile domain.RepositoryProfile, vulnerability domain.NormalizedVulnerability, candidate domain.MatchCandidate) Report {
	r := Report{
		RepositoryID: profile.Repository.ID, RepositoryCommit: profile.Repository.CommitSHA,
		VulnerabilityID: vulnerability.ID, VulnerabilityRevision: vulnerability.ModifiedAt,
		PackagePresence: check(1, ""), AffectedVersion: check(2, ""),
		FeatureUsage:     check(3, "inputs contain no structured evidence of vulnerable feature usage"),
		CodeReachability: check(4, "inputs contain no call-path or entry-point reachability evidence"),
		AttackConditions: check(5, "inputs contain no proof of required runtime configuration or attacker prerequisites"),
		Matches:          []MatchAssessment{},
	}
	if strings.TrimSpace(profile.Repository.ID) == "" || strings.TrimSpace(profile.Repository.CommitSHA) == "" || strings.TrimSpace(vulnerability.ID) == "" ||
		candidate.RepositoryID != profile.Repository.ID || candidate.RepositoryCommit != profile.Repository.CommitSHA ||
		candidate.VulnerabilityID != vulnerability.ID || !candidate.VulnerabilityRev.Equal(vulnerability.ModifiedAt) {
		r.PackagePresence.MissingReasons = []string{"candidate snapshot identity is missing or does not match the supplied inputs"}
		r.AffectedVersion.MissingReasons = append([]string{}, r.PackagePresence.MissingReasons...)
		return r
	}
	if len(candidate.Matches) == 0 {
		r.PackagePresence.Status = NotFound
		r.PackagePresence.MissingReasons = []string{"no candidate matches supplied; profile completeness is not established"}
		r.AffectedVersion.MissingReasons = []string{"no deterministic version results supplied"}
		return r
	}
	itemCounts := map[string]int{}
	for _, c := range profile.Components {
		itemCounts[c.ID]++
	}
	for _, p := range profile.Products {
		itemCounts[p.ID]++
	}
	for _, c := range profile.Containers {
		itemCounts[c.ID]++
	}
	for _, a := range profile.Infrastructure {
		itemCounts[a.ID]++
	}
	targets := map[string]domain.AffectedTarget{}
	targetCounts := map[string]int{}
	for _, t := range vulnerability.Affected {
		targets[t.ID] = t
		targetCounts[t.ID]++
	}
	type pair struct{ item, target string }
	pairs := map[pair]int{}
	for _, m := range candidate.Matches {
		pairs[pair{m.RepositoryItemID, m.AffectedTargetID}]++
	}
	allAbsent, allUnaffected := true, true
	for i, m := range candidate.Matches {
		a := MatchAssessment{Match: m, PackagePresence: check(1, ""), AffectedVersion: check(2, "")}
		a.AffectedVersion.ConditionalOnPackageIdentity = true
		t := targets[m.AffectedTargetID]
		if strings.TrimSpace(m.RepositoryItemID) == "" || strings.TrimSpace(m.AffectedTargetID) == "" || itemCounts[m.RepositoryItemID] != 1 || targetCounts[m.AffectedTargetID] != 1 || pairs[pair{m.RepositoryItemID, m.AffectedTargetID}] != 1 {
			a.PackagePresence.MissingReasons = []string{"match references are missing, ambiguous, or duplicated"}
			a.AffectedVersion.MissingReasons = append([]string{}, a.PackagePresence.MissingReasons...)
		} else {
			version, path := itemDetails(profile, m.RepositoryItemID)
			source := Source{RepositoryItemID: m.RepositoryItemID, AffectedTargetID: m.AffectedTargetID, SourcePath: path, MatchIndex: i}
			a.PackagePresence.Sources = append(a.PackagePresence.Sources, source)
			a.AffectedVersion.Sources = append(a.AffectedVersion.Sources, source)
			a.PackagePresence.Status = NotFound
			a.PackagePresence.MissingReasons = []string{"no real component with exact package/PURL identity; product, CPE, and derived aliases are not package proof"}
			for _, c := range profile.Components {
				if c.ID == m.RepositoryItemID && exactComponent(c, t, m.Reason) {
					a.PackagePresence.Status = Confirmed
					a.PackagePresence.MissingReasons = []string{}
					a.AffectedVersion.ConditionalOnPackageIdentity = false
				}
			}
			switch {
			case !knownReason(m.Reason):
				a.PackagePresence.Status = Unknown
				a.PackagePresence.MissingReasons = []string{"unsupported identity match reason"}
				a.AffectedVersion.MissingReasons = []string{"unsupported identity match reason"}
			case strings.TrimSpace(version) == "" || m.InstalledVersion != version:
				a.AffectedVersion.MissingReasons = []string{"installed version is missing or does not match the referenced repository item"}
			case len(t.Constraints) == 0:
				a.AffectedVersion.MissingReasons = []string{"affected target has no version constraints"}
			default:
				switch m.VersionStatus {
				case domain.VersionAffected:
					a.AffectedVersion.Status = Confirmed
				case domain.VersionNotAffected:
					a.AffectedVersion.Status = NotAffected
				default:
					a.AffectedVersion.MissingReasons = []string{"deterministic version result is unknown, missing, or unsupported"}
				}
			}
			if a.AffectedVersion.ConditionalOnPackageIdentity {
				a.AffectedVersion.MissingReasons = append(a.AffectedVersion.MissingReasons, "version result is conditional on unproven package identity")
			}
		}
		r.Matches = append(r.Matches, a)
		r.PackagePresence.Sources = append(r.PackagePresence.Sources, a.PackagePresence.Sources...)
		r.AffectedVersion.Sources = append(r.AffectedVersion.Sources, a.AffectedVersion.Sources...)
		if a.PackagePresence.Status != NotFound {
			allAbsent = false
		}
		if a.PackagePresence.Status == Confirmed {
			r.PackagePresence.Status = Confirmed
			if a.AffectedVersion.Status == Confirmed {
				r.AffectedVersion.Status = Confirmed
			}
		}
		if a.PackagePresence.Status != Confirmed || a.AffectedVersion.Status != NotAffected {
			allUnaffected = false
		}
	}
	if allAbsent {
		r.PackagePresence.Status = NotFound
	}
	if r.PackagePresence.Status != Confirmed {
		r.PackagePresence.MissingReasons = []string{"exact package presence is not established; see per-match checks"}
	}
	if allUnaffected {
		r.AffectedVersion.Status = NotAffected
	}
	if r.AffectedVersion.Status == Unknown {
		r.AffectedVersion.MissingReasons = []string{"no identity-confirmed affected match and not all candidate matches are proven unaffected; see per-match checks"}
	}
	return r
}

func exactComponent(c domain.Component, t domain.AffectedTarget, reason domain.MatchReason) bool {
	if t.Kind != domain.AffectedPackage {
		return false
	}
	switch reason {
	case domain.MatchPURLExact:
		return strings.HasPrefix(c.PURL, "pkg:") && len(c.PURL) > 4 && c.PURL == t.PURL
	case domain.MatchPackageExact:
		// A bare basename cannot resolve a namespaced component. Do not normalize
		// case, punctuation, aliases, or version-bearing PURLs into identity proof.
		name := c.Name
		if c.Namespace != "" && !strings.HasPrefix(name, c.Namespace+"/") {
			name = c.Namespace + "/" + name
		}
		return strings.TrimSpace(c.Name) != "" && strings.TrimSpace(c.Ecosystem) != "" && c.Ecosystem == t.Ecosystem && name == t.PackageName &&
			!(c.PURL != "" && t.PURL != "" && c.PURL != t.PURL)
	}
	return false
}

func knownReason(r domain.MatchReason) bool {
	switch r {
	case domain.MatchPURLExact, domain.MatchPackageExact, domain.MatchCPEExact, domain.MatchProductExact, domain.MatchProductAliasExact, domain.MatchContainerExact, domain.MatchInfrastructureExact:
		return true
	}
	return false
}

func itemDetails(p domain.RepositoryProfile, id string) (version, path string) {
	for _, c := range p.Components {
		if c.ID == id {
			return c.Version, c.SourcePath
		}
	}
	for _, v := range p.Products {
		if v.ID == id {
			return v.Version, v.SourcePath
		}
	}
	for _, c := range p.Containers {
		if c.ID == id {
			return c.Tag, c.SourcePath
		}
	}
	for _, a := range p.Infrastructure {
		if a.ID == id {
			return a.Version, a.SourcePath
		}
	}
	return "", ""
}
