// Package live connects repository discovery, validated analysis and the feed API.
package live

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"vulns-news/src/llm"
	"vulns-news/src/osv"
	"vulns-news/src/pipeline"
	"vulns-news/src/processor"
	"vulns-news/src/reposcan"
	"vulns-news/src/repository"
	"vulns-news/src/scananalyze"
	"vulns-news/src/scanjob"
)

type Discover func(context.Context, scanjob.Request) (reposcan.State, error)

// DiscoverRepository limits only acquisition/discovery, never model execution.
func DiscoverRepository(ctx context.Context, request scanjob.Request) (reposcan.State, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	workspace, err := os.MkdirTemp("", "news-scan-")
	if err != nil {
		return reposcan.State{}, err
	}
	defer os.RemoveAll(workspace)
	acquirer, err := repository.NewAcquirer(repository.Config{})
	if err != nil {
		return reposcan.State{}, err
	}
	acquired, err := acquirer.Acquire(ctx, workspace, repository.RepositorySpec{URL: request.URL, Ref: request.Ref})
	if err != nil {
		return reposcan.State{}, err
	}
	defer acquired.Cleanup()
	profile, err := repository.Profile(acquired, time.Now().UTC())
	if err != nil {
		return reposcan.State{}, err
	}
	client, err := osv.NewDiscoveryClient(osv.DiscoveryConfig{HTTPClient: &http.Client{Timeout: 30 * time.Second}})
	if err != nil {
		return reposcan.State{}, err
	}
	report := reposcan.Run(ctx, profile, reposcan.Config{OSV: client})
	state := reposcan.State{SchemaVersion: reposcan.SchemaVersion, Profile: profile, Report: report}
	if !report.RefreshComplete {
		return state, errors.New("scan refresh incomplete")
	}
	return state, nil
}

func NewAnalyzer(model, baseURL string) (pipeline.Analyzer, error) {
	client, err := llm.NewClient(llm.Config{Model: model, BaseURL: baseURL, HTTPClient: &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}})
	if err != nil {
		return nil, err
	}
	return processor.New(client)
}

type offlineAnalyzer struct{}

func (offlineAnalyzer) Screen(context.Context, processor.Input) (processor.ScreeningOutput, error) {
	return processor.ScreeningOutput{}, errors.New("offline import cannot call a model")
}
func (offlineAnalyzer) Analyze(context.Context, processor.Input) (processor.AnalysisOutput, error) {
	return processor.AnalysisOutput{}, errors.New("offline import cannot call a model")
}

// Restore uses the existing resume checks (snapshot, entry and output hashes,
// citations), and rebuilds feed facts instead of trusting serialized feed data.
// Run validates/rebuilds before observing cancellation in its processing loop.
func Restore(state reposcan.State, saved scananalyze.Report) (scananalyze.Report, error) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := scananalyze.Run(ctx, state, offlineAnalyzer{}, scananalyze.Config{
		Model: saved.Model, BaseURL: saved.BaseURL, Limit: saved.Limit,
	}, &saved)
	if report.SchemaVersion == 0 || (err != nil && !errors.Is(err, context.Canceled)) {
		return scananalyze.Report{}, fmt.Errorf("validate saved analysis: %w", err)
	}
	return report, nil
}
