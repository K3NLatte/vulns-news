// Package pipeline connects validated candidates to LLM screening, conditional
// Deep Analysis, and feed construction.
package pipeline

import (
	"context"
	"fmt"

	"vulns-news/src/feed"
	"vulns-news/src/processor"
)

// Analyzer is implemented by processor.Processor and can be replaced by a fake
// in orchestration tests.
type Analyzer interface {
	Screen(context.Context, processor.Input) (processor.ScreeningOutput, error)
	Analyze(context.Context, processor.Input) (processor.AnalysisOutput, error)
}

// Result records every completed stage. Unrelated candidates are marked as
// excluded and intentionally have no analysis or feed item.
type Result struct {
	Screening processor.ScreeningOutput `json:"screening"`
	Analysis  *processor.AnalysisOutput `json:"analysis,omitempty"`
	Feed      *feed.Item                `json:"feed,omitempty"`
	Excluded  bool                      `json:"excluded"`
}

// Process screens one deterministic candidate, runs Deep Analysis only for a
// related result, and assembles an API-ready feed item when applicable.
func Process(ctx context.Context, analyzer Analyzer, input processor.Input) (Result, error) {
	if analyzer == nil {
		return Result{}, fmt.Errorf("analysis processor is required")
	}

	screening, err := analyzer.Screen(ctx, input)
	if err != nil {
		return Result{}, fmt.Errorf("screen candidate: %w", err)
	}
	result := Result{Screening: screening}

	switch screening.Result.Relevance {
	case processor.RelevanceUnrelated:
		result.Excluded = true
		return result, nil
	case processor.RelevancePossiblyRelated, processor.RelevanceUnknown:
		item, err := feed.Build(input, screening, nil)
		if err != nil {
			return Result{}, fmt.Errorf("build screening-only feed item: %w", err)
		}
		result.Feed = &item
		return result, nil
	case processor.RelevanceRelated:
		analysis, err := analyzer.Analyze(ctx, input)
		if err != nil {
			return Result{}, fmt.Errorf("analyze related candidate: %w", err)
		}
		item, err := feed.Build(input, screening, &analysis)
		if err != nil {
			return Result{}, fmt.Errorf("build analyzed feed item: %w", err)
		}
		result.Analysis = &analysis
		result.Feed = &item
		return result, nil
	default:
		return Result{}, fmt.Errorf("unsupported screening relevance %q", screening.Result.Relevance)
	}
}
