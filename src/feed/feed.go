// Package feed assembles backend-owned facts and validated LLM interpretations
// into stable data for a repository vulnerability feed.
package feed

import (
	"errors"
	"fmt"
	"time"

	"vulns-news/src/assessment"
	"vulns-news/src/domain"
	"vulns-news/src/processor"
)

// AnalysisStatus identifies how far a feed item progressed through the pipeline.
type AnalysisStatus string

const (
	StatusScreened AnalysisStatus = "screened"
	StatusAnalyzed AnalysisStatus = "analyzed"
)

// Item is API-ready feed data. Identity, severity, affected components, and
// versions come from backend-owned facts; generated prose remains separated.
type Item struct {
	Applicability    assessment.Report         `json:"applicability"`
	RepositoryID     string                    `json:"repository_id"`
	RepositoryCommit string                    `json:"repository_commit"`
	CVEID            string                    `json:"cve_id"`
	CVERevision      time.Time                 `json:"cve_revision"`
	PublishedAt      time.Time                 `json:"published_at"`
	Severity         string                    `json:"severity,omitempty"`
	CVSS             *float64                  `json:"cvss,omitempty"`
	Matches          []domain.TargetMatch      `json:"matches"`
	Relevance        processor.Relevance       `json:"relevance"`
	Status           AnalysisStatus            `json:"status"`
	ScreeningReason  string                    `json:"screening_reason"`
	Summary          *processor.SupportedClaim `json:"summary,omitempty"`
	RepositoryImpact *processor.SupportedClaim `json:"repository_impact,omitempty"`
	MissingInfo      []string                  `json:"missing_information"`
	Actions          []string                  `json:"recommended_actions"`
	Evidence         []processor.Evidence      `json:"evidence"`
	Generation       []processor.Generation    `json:"generation"`
}

// Build creates one feed item. Unrelated results are intentionally excluded,
// and a related result must have completed deep analysis first.
func Build(
	input processor.Input,
	screening processor.ScreeningOutput,
	analysis *processor.AnalysisOutput,
) (Item, error) {
	switch screening.Result.Relevance {
	case processor.RelevanceUnrelated:
		return Item{}, errors.New("unrelated screening results do not produce feed items")
	case processor.RelevanceRelated:
		if analysis == nil {
			return Item{}, errors.New("related screening result requires deep analysis")
		}
	case processor.RelevancePossiblyRelated, processor.RelevanceUnknown:
		if analysis != nil {
			return Item{}, errors.New("only related screening results may include deep analysis")
		}
	default:
		return Item{}, fmt.Errorf("unsupported screening relevance %q", screening.Result.Relevance)
	}
	if input.Candidate.RepositoryID != input.Repository.Repository.ID || input.Candidate.VulnerabilityID != input.Vulnerability.ID {
		return Item{}, fmt.Errorf("candidate does not match feed facts")
	}

	var cvss *float64
	if input.Vulnerability.CVSS != nil {
		value := *input.Vulnerability.CVSS
		cvss = &value
	}
	item := Item{
		Applicability:    assessment.Assess(input.Repository, input.Vulnerability, input.Candidate),
		RepositoryID:     input.Candidate.RepositoryID,
		RepositoryCommit: input.Candidate.RepositoryCommit,
		CVEID:            input.Vulnerability.ID,
		CVERevision:      input.Vulnerability.ModifiedAt,
		PublishedAt:      input.Vulnerability.PublishedAt,
		Severity:         input.Vulnerability.Severity,
		CVSS:             cvss,
		Matches:          append([]domain.TargetMatch(nil), input.Candidate.Matches...),
		Relevance:        screening.Result.Relevance,
		Status:           StatusScreened,
		ScreeningReason:  screening.Result.Reason,
		Evidence:         append([]processor.Evidence(nil), input.Evidence...),
		Generation:       []processor.Generation{screening.Generation},
	}
	if analysis == nil {
		return item, nil
	}

	item.Status = StatusAnalyzed
	item.Summary = &analysis.Analysis.Summary
	item.RepositoryImpact = &analysis.Analysis.RepositoryImpact
	item.MissingInfo = append([]string(nil), analysis.Analysis.MissingInformation...)
	item.Actions = append([]string(nil), analysis.Analysis.RecommendedActions...)
	item.Generation = append(item.Generation, analysis.Generation)
	return item, nil
}
