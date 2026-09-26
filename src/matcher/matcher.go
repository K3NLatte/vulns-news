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

// Trace explains the overall match decision and each affected target's result.
type Trace struct {
	Decision string           `json:"decision"`
	Targets  []TargetDecision `json:"targets"`
}

// TargetDecision records the comparisons and retained matches for one target.
type TargetDecision struct {
	Target                  domain.AffectedTarget `json:"target"`
	RepositoryItemsCompared int                   `json:"repository_items_compared"`
	IdentityMatches         int                   `json:"identity_matches"`
	VersionExcluded         int                   `json:"version_excluded"`
	Matches                 []domain.TargetMatch  `json:"matches"`
	Decision                string                `json:"decision"`
}

// Match returns a candidate only when at least one normalized identity matches
// and no version evaluator has established that every match is unaffected.
func (m *Matcher) Match(profile domain.RepositoryProfile, vulnerability domain.NormalizedVulnerability) (domain.MatchCandidate, bool, error) {
	candidate, _, matched, err := m.MatchWithTrace(profile, vulnerability)
	return candidate, matched, err
}

// MatchWithTrace returns the same candidate as Match plus per-target decisions.
func (m *Matcher) MatchWithTrace(profile domain.RepositoryProfile, vulnerability domain.NormalizedVulnerability) (domain.MatchCandidate, Trace, bool, error) {
	if profile.Repository.ID == "" || profile.Repository.CommitSHA == "" {
		return domain.MatchCandidate{}, Trace{}, false, errors.New("repository ID and commit SHA are required")
	}
	if vulnerability.ID == "" {
		return domain.MatchCandidate{}, Trace{}, false, errors.New("vulnerability ID is required")
	}

	candidate := domain.MatchCandidate{
		RepositoryID:     profile.Repository.ID,
		RepositoryCommit: profile.Repository.CommitSHA,
		VulnerabilityID:  vulnerability.ID,
		VulnerabilityRev: vulnerability.ModifiedAt,
	}
	trace := Trace{Targets: make([]TargetDecision, 0, len(vulnerability.Affected))}
	anyIdentityMatch := false

	for _, target := range vulnerability.Affected {
		decision := TargetDecision{Target: target, Matches: []domain.TargetMatch{}}
		addMatch := func(kind, id, ecosystem, version string, reason domain.MatchReason) error {
			decision.IdentityMatches++
			status, err := m.evaluateVersion(ecosystem, version, target.Constraints)
			if err != nil {
				return fmt.Errorf("evaluate %s %q against target %q: %w", kind, id, target.ID, err)
			}
			if status == domain.VersionNotAffected {
				decision.VersionExcluded++
				return nil
			}
			match := domain.TargetMatch{
				RepositoryItemID: id,
				AffectedTargetID: target.ID,
				Reason:           reason,
				VersionStatus:    status,
				InstalledVersion: version,
			}
			candidate.Matches = append(candidate.Matches, match)
			decision.Matches = append(decision.Matches, match)
			return nil
		}

		switch target.Kind {
		case domain.AffectedPackage:
			decision.RepositoryItemsCompared = len(profile.Components)
			for _, component := range profile.Components {
				reason, matched := matchComponent(component, target)
				if matched {
					if err := addMatch("component", component.ID, component.Ecosystem, component.Version, reason); err != nil {
						return domain.MatchCandidate{}, Trace{}, false, err
					}
				}
			}
		case domain.AffectedProduct:
			decision.RepositoryItemsCompared = len(profile.Products)
			for _, product := range profile.Products {
				reason, matched := matchProduct(product, target)
				if matched {
					if err := addMatch("product", product.ID, product.Ecosystem, product.Version, reason); err != nil {
						return domain.MatchCandidate{}, Trace{}, false, err
					}
				}
			}
		case domain.AffectedContainer:
			decision.RepositoryItemsCompared = len(profile.Containers)
			for _, container := range profile.Containers {
				if container.Image != "" && container.Image == target.Product {
					if err := addMatch("container", container.ID, "container", container.Tag, domain.MatchContainerExact); err != nil {
						return domain.MatchCandidate{}, Trace{}, false, err
					}
				}
			}
		case domain.AffectedInfrastructure:
			decision.RepositoryItemsCompared = len(profile.Infrastructure)
			for _, asset := range profile.Infrastructure {
				if asset.Product != "" && asset.Product == target.Product {
					if err := addMatch("infrastructure asset", asset.ID, asset.Provider, asset.Version, domain.MatchInfrastructureExact); err != nil {
						return domain.MatchCandidate{}, Trace{}, false, err
					}
				}
			}
		default:
			return domain.MatchCandidate{}, Trace{}, false, fmt.Errorf("affected target %q has unsupported kind %q", target.ID, target.Kind)
		}

		switch {
		case len(decision.Matches) > 0:
			decision.Decision = "matched"
		case decision.IdentityMatches > 0:
			decision.Decision = "version_excluded"
		default:
			decision.Decision = "no_identity_match"
		}
		anyIdentityMatch = anyIdentityMatch || decision.IdentityMatches > 0
		trace.Targets = append(trace.Targets, decision)
	}

	switch {
	case len(vulnerability.Affected) == 0:
		trace.Decision = "no_affected_targets"
	case len(candidate.Matches) > 0:
		trace.Decision = "matched"
	case anyIdentityMatch:
		trace.Decision = "version_excluded"
	default:
		trace.Decision = "no_identity_match"
	}
	return candidate, trace, len(candidate.Matches) > 0, nil
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
