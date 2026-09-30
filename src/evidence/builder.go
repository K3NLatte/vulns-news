// Package evidence builds immutable, deterministic citations from normalized
// backend facts. It never asks the LLM to create evidence.
package evidence

import (
	"errors"
	"fmt"
	"strings"

	"vulns-news/src/domain"
	"vulns-news/src/processor"
)

// Build creates one NVD citation and one repository citation per deterministic
// match. Input consistency is checked again so evidence cannot cite unrelated facts.
func Build(
	profile domain.RepositoryProfile,
	vulnerability domain.NormalizedVulnerability,
	candidate domain.MatchCandidate,
) ([]processor.Evidence, error) {
	if candidate.RepositoryID != profile.Repository.ID || candidate.RepositoryCommit != profile.Repository.CommitSHA {
		return nil, errors.New("candidate does not match repository profile")
	}
	if candidate.VulnerabilityID != vulnerability.ID || !candidate.VulnerabilityRev.Equal(vulnerability.ModifiedAt) {
		return nil, errors.New("candidate does not match vulnerability revision")
	}
	if strings.TrimSpace(vulnerability.Description) == "" {
		return nil, errors.New("vulnerability description is required")
	}
	if len(candidate.Matches) == 0 {
		return nil, errors.New("candidate requires at least one match")
	}

	targets := make(map[string]domain.AffectedTarget, len(vulnerability.Affected))
	for _, target := range vulnerability.Affected {
		targets[target.ID] = target
	}
	items := repositoryItems(profile)

	result := []processor.Evidence{{
		ID:      "EVD-NVD-001",
		Kind:    processor.EvidenceNVD,
		Source:  "NVD",
		URI:     preferredNVDReference(vulnerability),
		Content: vulnerabilityContent(vulnerability),
	}}
	for index, match := range candidate.Matches {
		item, exists := items[match.RepositoryItemID]
		if !exists {
			return nil, fmt.Errorf("match %d references unknown repository item %q", index, match.RepositoryItemID)
		}
		target, exists := targets[match.AffectedTargetID]
		if !exists {
			return nil, fmt.Errorf("match %d references unknown affected target %q", index, match.AffectedTargetID)
		}
		if strings.TrimSpace(item.source) == "" || strings.TrimSpace(item.identity) == "" {
			return nil, fmt.Errorf("match %d repository item lacks source or identity", index)
		}
		result = append(result, processor.Evidence{
			ID:      fmt.Sprintf("EVD-REPO-%03d", index+1),
			Kind:    item.kind,
			Source:  item.source,
			Content: repositoryContent(item, target, match),
		})
	}
	return result, nil
}

type repositoryItem struct {
	kind       processor.EvidenceKind
	source     string
	identity   string
	version    string
	attributes string
}

func repositoryItems(profile domain.RepositoryProfile) map[string]repositoryItem {
	items := make(map[string]repositoryItem)
	for _, component := range profile.Components {
		attributes := fmt.Sprintf("ecosystem=%s, direct=%t", component.Ecosystem, component.Direct)
		if component.Scope != "" {
			attributes += ", scope=" + component.Scope
		}
		items[component.ID] = repositoryItem{
			kind:       processor.EvidenceRepositoryDependency,
			source:     component.SourcePath,
			identity:   component.Name,
			version:    component.Version,
			attributes: attributes,
		}
	}
	for _, product := range profile.Products {
		identity := strings.TrimSpace(strings.TrimSpace(product.Vendor + " " + product.Name))
		items[product.ID] = repositoryItem{
			kind:     processor.EvidenceRepositorySource,
			source:   product.SourcePath,
			identity: identity,
			version:  product.Version,
		}
	}
	for _, container := range profile.Containers {
		version := container.Tag
		if container.Digest != "" {
			version = container.Digest
		}
		items[container.ID] = repositoryItem{
			kind:       processor.EvidenceRepositorySource,
			source:     container.SourcePath,
			identity:   container.Image,
			version:    version,
			attributes: "container image",
		}
	}
	for _, asset := range profile.Infrastructure {
		items[asset.ID] = repositoryItem{
			kind:       processor.EvidenceRepositorySource,
			source:     asset.SourcePath,
			identity:   asset.Product,
			version:    asset.Version,
			attributes: "infrastructure provider=" + asset.Provider,
		}
	}
	return items
}

func preferredNVDReference(vulnerability domain.NormalizedVulnerability) string {
	for _, reference := range vulnerability.References {
		if strings.Contains(strings.ToLower(reference.URL), "nvd.nist.gov") {
			return reference.URL
		}
	}
	if len(vulnerability.References) > 0 {
		return vulnerability.References[0].URL
	}
	return ""
}

func vulnerabilityContent(vulnerability domain.NormalizedVulnerability) string {
	parts := []string{vulnerability.ID + ": " + strings.TrimSpace(vulnerability.Description)}
	if vulnerability.Severity != "" {
		parts = append(parts, "severity="+vulnerability.Severity)
	}
	if vulnerability.CVSS != nil {
		parts = append(parts, fmt.Sprintf("CVSS=%.1f", *vulnerability.CVSS))
	}
	return strings.Join(parts, "; ")
}

func repositoryContent(item repositoryItem, target domain.AffectedTarget, match domain.TargetMatch) string {
	parts := []string{"repository item " + item.identity}
	if item.version != "" {
		parts = append(parts, "installed version="+item.version)
	}
	if item.attributes != "" {
		parts = append(parts, item.attributes)
	}
	parts = append(parts,
		"affected target="+target.ID,
		"match reason="+string(match.Reason),
		"version status="+string(match.VersionStatus),
	)
	return strings.Join(parts, "; ")
}
