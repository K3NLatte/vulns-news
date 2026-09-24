// Package matcher creates CVE candidates from normalized repository and
// vulnerability facts without asking an LLM to identify packages or compare versions.
package matcher

import (
	"errors"
	"fmt"

	"vulns-news/src/domain"
)

// VersionEvaluator applies ecosystem- or scheme-specific version semantics.
// Implementations must return VersionUnknown when a value cannot be interpreted.
type VersionEvaluator interface {
	Evaluate(ecosystem, installedVersion string, constraints []domain.VersionConstraint) (domain.VersionStatus, error)
}

// Matcher performs strict identity matching and delegates version comparison.
type Matcher struct {
	versions VersionEvaluator
}

// New creates a deterministic matcher. A nil evaluator is valid and leaves all
// matched versions unknown until an ecosystem adapter is registered.
func New(versions VersionEvaluator) *Matcher {
	return &Matcher{versions: versions}
}

// Match returns a candidate only when at least one normalized identity matches
// and no version evaluator has established that every match is unaffected.
func (m *Matcher) Match(profile domain.RepositoryProfile, vulnerability domain.NormalizedVulnerability) (domain.MatchCandidate, bool, error) {
	if profile.Repository.ID == "" || profile.Repository.CommitSHA == "" {
		return domain.MatchCandidate{}, false, errors.New("repository ID and commit SHA are required")
	}
	if vulnerability.ID == "" {
		return domain.MatchCandidate{}, false, errors.New("vulnerability ID is required")
	}

	candidate := domain.MatchCandidate{
		RepositoryID:     profile.Repository.ID,
		RepositoryCommit: profile.Repository.CommitSHA,
		VulnerabilityID:  vulnerability.ID,
		VulnerabilityRev: vulnerability.ModifiedAt,
	}

	for _, target := range vulnerability.Affected {
		switch target.Kind {
		case domain.AffectedPackage:
			for _, component := range profile.Components {
				reason, matched := matchComponent(component, target)
				if !matched {
					continue
				}
				versionStatus, err := m.evaluateVersion(component.Ecosystem, component.Version, target.Constraints)
				if err != nil {
					return domain.MatchCandidate{}, false, fmt.Errorf("evaluate component %q against target %q: %w", component.ID, target.ID, err)
				}
				if versionStatus == domain.VersionNotAffected {
					continue
				}
				candidate.Matches = append(candidate.Matches, domain.TargetMatch{
					RepositoryItemID: component.ID,
					AffectedTargetID: target.ID,
					Reason:           reason,
					VersionStatus:    versionStatus,
					InstalledVersion: component.Version,
				})
			}
		case domain.AffectedProduct:
			for _, product := range profile.Products {
				reason, matched := matchProduct(product, target)
				if !matched {
					continue
				}
				versionStatus, err := m.evaluateVersion(product.Ecosystem, product.Version, target.Constraints)
				if err != nil {
					return domain.MatchCandidate{}, false, fmt.Errorf("evaluate product %q against target %q: %w", product.ID, target.ID, err)
				}
				if versionStatus == domain.VersionNotAffected {
					continue
				}
				candidate.Matches = append(candidate.Matches, domain.TargetMatch{
					RepositoryItemID: product.ID,
					AffectedTargetID: target.ID,
					Reason:           reason,
					VersionStatus:    versionStatus,
					InstalledVersion: product.Version,
				})
			}
		case domain.AffectedContainer:
			for _, container := range profile.Containers {
				if container.Image == "" || container.Image != target.Product {
					continue
				}
				versionStatus, err := m.evaluateVersion("container", container.Tag, target.Constraints)
				if err != nil {
					return domain.MatchCandidate{}, false, fmt.Errorf("evaluate container %q against target %q: %w", container.ID, target.ID, err)
				}
				if versionStatus == domain.VersionNotAffected {
					continue
				}
				candidate.Matches = append(candidate.Matches, domain.TargetMatch{
					RepositoryItemID: container.ID,
					AffectedTargetID: target.ID,
					Reason:           domain.MatchContainerExact,
					VersionStatus:    versionStatus,
					InstalledVersion: container.Tag,
				})
			}
		case domain.AffectedInfrastructure:
			for _, asset := range profile.Infrastructure {
				if asset.Product == "" || asset.Product != target.Product {
					continue
				}
				versionStatus, err := m.evaluateVersion(asset.Provider, asset.Version, target.Constraints)
				if err != nil {
					return domain.MatchCandidate{}, false, fmt.Errorf("evaluate infrastructure asset %q against target %q: %w", asset.ID, target.ID, err)
				}
				if versionStatus == domain.VersionNotAffected {
					continue
				}
				candidate.Matches = append(candidate.Matches, domain.TargetMatch{
					RepositoryItemID: asset.ID,
					AffectedTargetID: target.ID,
					Reason:           domain.MatchInfrastructureExact,
					VersionStatus:    versionStatus,
					InstalledVersion: asset.Version,
				})
			}
		default:
			return domain.MatchCandidate{}, false, fmt.Errorf("affected target %q has unsupported kind %q", target.ID, target.Kind)
		}
	}

	return candidate, len(candidate.Matches) > 0, nil
}

func (m *Matcher) evaluateVersion(ecosystem, installed string, constraints []domain.VersionConstraint) (domain.VersionStatus, error) {
	if installed == "" || len(constraints) == 0 || m.versions == nil {
		return domain.VersionUnknown, nil
	}
	status, err := m.versions.Evaluate(ecosystem, installed, constraints)
	if err != nil {
		return domain.VersionUnknown, err
	}
	switch status {
	case domain.VersionAffected, domain.VersionNotAffected, domain.VersionUnknown:
		return status, nil
	default:
		return domain.VersionUnknown, fmt.Errorf("unsupported version status %q", status)
	}
}

func matchComponent(component domain.Component, target domain.AffectedTarget) (domain.MatchReason, bool) {
	if component.PURL != "" && target.PURL != "" && component.PURL == target.PURL {
		return domain.MatchPURLExact, true
	}
	if component.Ecosystem != "" && component.Ecosystem == target.Ecosystem && component.Name != "" && component.Name == target.PackageName {
		return domain.MatchPackageExact, true
	}
	return "", false
}

func matchProduct(product domain.ProductCandidate, target domain.AffectedTarget) (domain.MatchReason, bool) {
	if intersects(product.CPEs, target.CPEs) {
		return domain.MatchCPEExact, true
	}
	if product.Name != "" && product.Name == target.Product && product.Vendor == target.Vendor {
		return domain.MatchProductExact, true
	}
	if intersects(product.Aliases, append([]string{target.Product}, target.Aliases...)) {
		return domain.MatchProductAliasExact, true
	}
	return "", false
}

func intersects(left, right []string) bool {
	values := make(map[string]struct{}, len(left))
	for _, value := range left {
		if value != "" {
			values[value] = struct{}{}
		}
	}
	for _, value := range right {
		if _, exists := values[value]; exists {
			return true
		}
	}
	return false
}
