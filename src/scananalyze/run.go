package scananalyze

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/feed"
	"vulns-news/src/pipeline"
	"vulns-news/src/processor"
	"vulns-news/src/reposcan"
)

const SchemaVersion = 1

type Config struct {
	Model      string
	BaseURL    string
	Limit      int // Zero selects all matching alias groups.
	Checkpoint func(Report) error
	Progress   func(string)
}

// Report describes analysis of the matching groups in one immutable scan.
// Complete does not assert scan coverage or deep-analysis execution; consult
// ScanRefreshComplete, ScanStatus and Analyzed separately.
// Screened and Analyzed count validated outputs, even before feed completion.
type Report struct {
	SchemaVersion       int                       `json:"schema_version"`
	Repository          domain.RepositoryIdentity `json:"repository"`
	Model               string                    `json:"model"`
	BaseURL             string                    `json:"base_url"`
	SnapshotHash        string                    `json:"snapshot_hash"`
	Limit               int                       `json:"limit"`
	StartedAt           time.Time                 `json:"started_at"`
	UpdatedAt           time.Time                 `json:"updated_at"`
	TotalCandidates     int                       `json:"total_candidates"`
	SelectedCandidates  int                       `json:"selected_candidates"`
	NotSelected         int                       `json:"not_selected"`
	Screened            int                       `json:"screened"`
	Analyzed            int                       `json:"analyzed"`
	ScreeningOnly       int                       `json:"screening_only"`
	Excluded            int                       `json:"excluded"`
	Errors              int                       `json:"errors"`
	Pending             int                       `json:"pending"`
	SelectedComplete    bool                      `json:"selected_complete"`
	Complete            bool                      `json:"complete"`
	ScanRefreshComplete bool                      `json:"scan_refresh_complete"`
	ScanStatus          string                    `json:"scan_status"`
	Entries             []Entry                   `json:"entries"`
}

// Entry's output checksums bind cached payloads to their input and stage. They
// detect corruption and accidental swaps, not deliberate edits with recomputed
// checksums; they are not signatures or proof of authenticity.
type Entry struct {
	ID            string                     `json:"id"`
	IDs           []string                   `json:"ids"`
	RecordKeys    []string                   `json:"record_keys"`
	AdvisoryKinds []string                   `json:"advisory_kinds"`
	InputHash     string                     `json:"input_hash"`
	ScreeningHash string                     `json:"screening_hash,omitempty"`
	AnalysisHash  string                     `json:"analysis_hash,omitempty"`
	Status        string                     `json:"status"`
	Stage         string                     `json:"stage"`
	Error         string                     `json:"error,omitempty"`
	Screening     *processor.ScreeningOutput `json:"screening,omitempty"`
	Analysis      *processor.AnalysisOutput  `json:"analysis,omitempty"`
	Feed          *feed.Item                 `json:"feed,omitempty"`
}

// Run uses pipeline.Process without changing its relevance routing. Successful
// model calls are checkpointed before the next stage. Request/validation/feed
// failures are recorded while independent candidates continue. Parent context
// cancellation and checkpoint failures stop the run immediately.
// Resume validates the entire report before any checkpoint or analyzer call.
func Run(ctx context.Context, state reposcan.State, analyzer pipeline.Analyzer, cfg Config, previous *Report) (Report, error) {
	if cfg.Limit < 0 {
		return Report{}, errors.New("analysis limit must not be negative")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return Report{}, errors.New("analysis model is required")
	}
	if analyzer == nil {
		return Report{}, errors.New("analysis processor is required")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return Report{}, fmt.Errorf("encode scan snapshot: %w", err)
	}
	// Isolate nested slices/maps from analyzers and checkpoint callbacks as well
	// as from our own preparation. The caller's saved scan remains untouched.
	var snapshot reposcan.State
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Report{}, fmt.Errorf("copy scan snapshot: %w", err)
	}
	prepared := Prepare(snapshot)
	now := time.Now().UTC()
	r := Report{
		SchemaVersion: SchemaVersion, Repository: snapshot.Profile.Repository,
		Model: cfg.Model, BaseURL: cfg.BaseURL, Limit: cfg.Limit,
		SnapshotHash: digest(data), StartedAt: now, UpdatedAt: now,
		ScanRefreshComplete: snapshot.Report.RefreshComplete, ScanStatus: snapshot.Report.Status,
		Entries: make([]Entry, len(prepared)),
	}
	for i, p := range prepared {
		// Prepared includes each source's revision in its evidence, not just the
		// alias group's maximum revision. Identity and preparation errors bind too.
		data, err := json.Marshal(p)
		if err != nil {
			return Report{}, fmt.Errorf("encode candidate %q: %w", p.ID, err)
		}
		e := Entry{ID: p.ID, IDs: p.IDs, RecordKeys: p.RecordKeys, AdvisoryKinds: p.AdvisoryKinds,
			InputHash: digest(data), Status: "pending", Stage: "screening"}
		if cfg.Limit > 0 && i >= cfg.Limit {
			e.Status, e.Stage = "not_selected", "selection"
		} else if p.Error != "" {
			e.Status, e.Stage, e.Error = "preparation_error", "preparation", p.Error
		}
		r.Entries[i] = e
	}
	r.recount()
	if previous != nil {
		if err := validateResume(*previous, r, prepared); err != nil {
			return Report{}, fmt.Errorf("resume analysis: %w", err)
		}
		r, err = copyReport(*previous)
		if err != nil {
			return Report{}, fmt.Errorf("copy previous analysis: %w", err)
		}
		// Serialized feed facts are never authoritative, including on entries
		// that will not make another model call.
		for i := range r.Entries {
			e := &r.Entries[i]
			e.Feed = nil
			if e.Status == "analyzed" || e.Status == "screening_only" {
				item, err := feed.Build(prepared[i].Input, *e.Screening, e.Analysis)
				if err != nil {
					return Report{}, fmt.Errorf("resume candidate %q feed: %w", e.ID, err)
				}
				e.Feed = &item
			}
		}
	}

	checkpoint := func() error {
		r.recount()
		r.UpdatedAt = time.Now().UTC()
		if cfg.Checkpoint == nil {
			return nil
		}
		// A callback may retain or mutate its argument. Never share cache pointers.
		saved, err := copyReport(r)
		if err == nil {
			err = cfg.Checkpoint(saved)
		}
		if err != nil {
			return fmt.Errorf("checkpoint analysis report: %w", err)
		}
		return nil
	}
	if err := checkpoint(); err != nil {
		return r, err
	}
	var failures []error
	for _, e := range r.Entries {
		if e.Status == "preparation_error" {
			failures = append(failures, fmt.Errorf("candidate %q preparation: %s", e.ID, e.Error))
		}
	}
	for i := range r.Entries {
		if err := ctx.Err(); err != nil {
			return r, errors.Join(append(failures, err)...)
		}
		e := &r.Entries[i]
		if finished(e.Status) || e.Status == "not_selected" || e.Status == "preparation_error" {
			continue
		}
		e.Status, e.Error, e.Feed = "pending", "", nil
		e.Stage = nextStage(*e)
		cached := &cachingAnalyzer{analyzer: analyzer, entry: e, checkpoint: checkpoint,
			progress: cfg.Progress, index: i + 1, total: r.SelectedCandidates}
		result, err := pipeline.Process(ctx, cached, prepared[i].Input)
		if cached.stopErr != nil {
			// Checkpoint failures must not cause another checkpoint or turn a
			// completed model output into an apparent model failure.
			r.recount()
			return r, errors.Join(append(failures, cached.stopErr)...)
		}
		if err != nil {
			e.Status, e.Error = e.Stage+"_error", err.Error()
			failures = append(failures, fmt.Errorf("candidate %q: %w", e.ID, err))
		} else {
			e.Stage, e.Feed = "complete", result.Feed
			switch {
			case result.Excluded:
				e.Status = "excluded"
			case result.Analysis != nil:
				e.Status = "analyzed"
			default:
				e.Status = "screening_only"
			}
		}
		if saveErr := checkpoint(); saveErr != nil {
			return r, errors.Join(append(failures, saveErr)...)
		}
		if err := ctx.Err(); err != nil {
			return r, errors.Join(append(failures, err)...)
		}
	}
	return r, errors.Join(append(failures, ctx.Err())...)
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func outputHash[T any](inputHash, stage string, output *T) (string, error) {
	if output == nil {
		return "", nil
	}
	data, err := json.Marshal(struct {
		InputHash string `json:"input_hash"`
		Stage     string `json:"stage"`
		Output    *T     `json:"output"`
	}{InputHash: inputHash, Stage: stage, Output: output})
	if err != nil {
		return "", fmt.Errorf("encode %s output checksum: %w", stage, err)
	}
	return digest(data), nil
}

func copyReport(r Report) (Report, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return Report{}, err
	}
	var copied Report
	err = json.Unmarshal(data, &copied)
	return copied, err
}

func finished(status string) bool {
	return status == "analyzed" || status == "screening_only" || status == "excluded"
}

func nextStage(e Entry) string {
	if e.Screening == nil {
		return "screening"
	}
	if e.Screening.Result.Relevance == processor.RelevanceRelated && e.Analysis == nil {
		return "analysis"
	}
	return "feed"
}

func (r *Report) recount() {
	r.TotalCandidates = len(r.Entries)
	r.NotSelected, r.Screened, r.Analyzed, r.ScreeningOnly, r.Excluded, r.Errors, r.Pending = 0, 0, 0, 0, 0, 0, 0
	for _, e := range r.Entries {
		if e.Screening != nil {
			r.Screened++
		}
		if e.Analysis != nil {
			r.Analyzed++
		}
		switch e.Status {
		case "not_selected":
			r.NotSelected++
		case "screening_only":
			r.ScreeningOnly++
		case "excluded":
			r.Excluded++
		case "preparation_error", "screening_error", "analysis_error", "feed_error":
			r.Errors++
		case "pending":
			r.Pending++
		}
	}
	r.SelectedCandidates = r.TotalCandidates - r.NotSelected
	r.SelectedComplete = r.Errors == 0 && r.Pending == 0
	r.Complete = r.SelectedComplete && r.NotSelected == 0
}

func validateResume(saved, expected Report, prepared []Prepared) error {
	if saved.SchemaVersion != expected.SchemaVersion || saved.Repository != expected.Repository ||
		saved.SnapshotHash != expected.SnapshotHash || saved.Model != expected.Model ||
		saved.BaseURL != expected.BaseURL || saved.Limit != expected.Limit ||
		saved.ScanStatus != expected.ScanStatus || saved.ScanRefreshComplete != expected.ScanRefreshComplete {
		return errors.New("snapshot or analysis options differ from saved report")
	}
	if saved.StartedAt.IsZero() || saved.UpdatedAt.IsZero() || saved.UpdatedAt.Before(saved.StartedAt) {
		return errors.New("invalid saved report timestamps")
	}
	if len(saved.Entries) != len(expected.Entries) {
		return errors.New("saved candidate count differs from prepared groups")
	}
	for i, e := range saved.Entries {
		want := expected.Entries[i]
		if e.ID != want.ID || e.InputHash != want.InputHash || !slices.Equal(e.IDs, want.IDs) ||
			!slices.Equal(e.RecordKeys, want.RecordKeys) || !slices.Equal(e.AdvisoryKinds, want.AdvisoryKinds) {
			return fmt.Errorf("candidate %d identity or input fingerprint differs", i+1)
		}
		if err := validateEntry(e, want, prepared[i].Input); err != nil {
			return fmt.Errorf("candidate %d (%s): %w", i+1, e.ID, err)
		}
	}
	counts := saved
	counts.recount()
	if saved.TotalCandidates != counts.TotalCandidates || saved.SelectedCandidates != counts.SelectedCandidates ||
		saved.NotSelected != counts.NotSelected || saved.Screened != counts.Screened || saved.Analyzed != counts.Analyzed ||
		saved.ScreeningOnly != counts.ScreeningOnly || saved.Excluded != counts.Excluded ||
		saved.Errors != counts.Errors || saved.Pending != counts.Pending ||
		saved.SelectedComplete != counts.SelectedComplete || saved.Complete != counts.Complete {
		return errors.New("saved counters or completion flags contradict entries")
	}
	return nil
}

func validateEntry(e, expected Entry, input processor.Input) error {
	screeningHash, err := outputHash(e.InputHash, "screening", e.Screening)
	if err != nil {
		return err
	}
	var checksumErr error
	if e.ScreeningHash != screeningHash {
		checksumErr = errors.New("cached screening checksum mismatch")
	}
	analysisHash, err := outputHash(e.InputHash, "analysis", e.Analysis)
	if err != nil {
		return err
	}
	if e.AnalysisHash != analysisHash {
		checksumErr = errors.Join(checksumErr, errors.New("cached analysis checksum mismatch"))
	}
	if expected.Status == "not_selected" || expected.Status == "preparation_error" {
		if e.Status != expected.Status || e.Stage != expected.Stage || e.Error != expected.Error || e.Screening != nil || e.Analysis != nil {
			return errors.Join(checksumErr, errors.New("saved selection or preparation result is inconsistent"))
		}
		return checksumErr
	}
	// Preserve actionable schema/evidence diagnostics alongside checksum errors.
	if err := processor.ValidateOutputs(input, e.Screening, e.Analysis); err != nil {
		return errors.Join(checksumErr, fmt.Errorf("invalid cached output: %w", err))
	}
	if checksumErr != nil {
		return checksumErr
	}
	stage := nextStage(e)
	valid := false
	switch e.Status {
	case "pending":
		valid = e.Stage == stage && e.Error == ""
	case "screening_error", "analysis_error", "feed_error":
		valid = e.Stage == stage && e.Status == stage+"_error" && strings.TrimSpace(e.Error) != ""
		if stage == "feed" && e.Screening.Result.Relevance == processor.RelevanceUnrelated {
			valid = false
		}
	case "analyzed":
		valid = e.Analysis != nil
	case "screening_only":
		valid = e.Screening != nil && (e.Screening.Result.Relevance == processor.RelevanceUnknown || e.Screening.Result.Relevance == processor.RelevancePossiblyRelated)
	case "excluded":
		valid = e.Screening != nil && e.Screening.Result.Relevance == processor.RelevanceUnrelated
	}
	if finished(e.Status) {
		valid = valid && e.Stage == "complete" && e.Error == ""
	}
	if !valid {
		return errors.New("saved status/stage contradict cached outputs")
	}
	return nil
}

type cachingAnalyzer struct {
	analyzer   pipeline.Analyzer
	entry      *Entry
	checkpoint func() error
	progress   func(string)
	index      int
	total      int
	stopErr    error
}

func (a *cachingAnalyzer) before(ctx context.Context, stage string) error {
	a.entry.Stage = stage
	if ctx.Err() == nil && a.progress != nil {
		a.progress(fmt.Sprintf("candidate %d/%d %s: %s", a.index, a.total, a.entry.ID, stage))
	}
	a.stopErr = ctx.Err()
	return a.stopErr
}

func (a *cachingAnalyzer) Screen(ctx context.Context, input processor.Input) (processor.ScreeningOutput, error) {
	if a.entry.Screening != nil {
		return *a.entry.Screening, nil
	}
	if err := a.before(ctx, "screening"); err != nil {
		return processor.ScreeningOutput{}, err
	}
	out, err := a.analyzer.Screen(ctx, input)
	if err != nil {
		return processor.ScreeningOutput{}, err
	}
	if err := processor.ValidateOutputs(input, &out, nil); err != nil {
		return processor.ScreeningOutput{}, fmt.Errorf("validate screening output: %w", err)
	}
	hash, err := outputHash(a.entry.InputHash, "screening", &out)
	if err != nil {
		return processor.ScreeningOutput{}, err
	}
	a.entry.Screening, a.entry.ScreeningHash = &out, hash
	a.entry.Stage = nextStage(*a.entry)
	a.stopErr = a.checkpoint()
	return out, a.stopErr
}

func (a *cachingAnalyzer) Analyze(ctx context.Context, input processor.Input) (processor.AnalysisOutput, error) {
	if a.entry.Analysis != nil {
		return *a.entry.Analysis, nil
	}
	if err := a.before(ctx, "analysis"); err != nil {
		return processor.AnalysisOutput{}, err
	}
	out, err := a.analyzer.Analyze(ctx, input)
	if err != nil {
		return processor.AnalysisOutput{}, err
	}
	if err := processor.ValidateOutputs(input, a.entry.Screening, &out); err != nil {
		return processor.AnalysisOutput{}, fmt.Errorf("validate analysis output: %w", err)
	}
	hash, err := outputHash(a.entry.InputHash, "analysis", &out)
	if err != nil {
		return processor.AnalysisOutput{}, err
	}
	a.entry.Analysis, a.entry.AnalysisHash = &out, hash
	a.entry.Stage = "feed"
	a.stopErr = a.checkpoint()
	return out, a.stopErr
}
