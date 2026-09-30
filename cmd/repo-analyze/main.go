// Command repo-analyze resumes a saved repository scan through the LLM pipeline.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/feed"
	"vulns-news/src/llm"
	"vulns-news/src/processor"
	"vulns-news/src/reposcan"
	"vulns-news/src/scananalyze"
)

type options struct {
	state, output, model, baseURL string
	resume, plan, requireDeep     bool
	limit                         int
	timeout, requestTimeout       time.Duration
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "repo-analyze:", err)
		os.Exit(1)
	}
}

func parse(args []string, stderr io.Writer) (options, error) {
	var o options
	f := flag.NewFlagSet("repo-analyze", flag.ContinueOnError)
	f.SetOutput(stderr)
	f.StringVar(&o.state, "state", "", "immutable JSON state saved by repo-scan (not matrix CSV)")
	f.StringVar(&o.output, "output", "", "analysis JSON checkpoint; saved after each model stage")
	f.StringVar(&o.model, "model", os.Getenv("OLLAMA_MODEL"), "Ollama model (or OLLAMA_MODEL)")
	f.StringVar(&o.baseURL, "base-url", os.Getenv("OLLAMA_BASE_URL"), "Ollama base URL; default http://127.0.0.1:11434")
	f.BoolVar(&o.resume, "resume", false, "resume output checkpoint with identical state, model, endpoint and limit")
	f.BoolVar(&o.plan, "plan-only", false, "show matching alias groups and preparation errors without LLM requests")
	f.BoolVar(&o.requireDeep, "require-deep", false, "fail if no analyzed feed item was produced; E2E coverage check, not forced relevance")
	f.IntVar(&o.limit, "limit", 0, "explicit maximum candidate groups to analyze; 0 selects all")
	f.DurationVar(&o.timeout, "timeout", 2*time.Hour, "overall analysis deadline; 0 disables this limit (manual cancellation still applies)")
	f.DurationVar(&o.requestTimeout, "request-timeout", 5*time.Minute, "timeout per LLM request; 0 disables this limit (overall deadline applies when enabled)")
	if err := f.Parse(args); err != nil {
		return o, err
	}
	if o.state == "" || f.NArg() > 0 {
		return o, errors.New("-state is required; positional arguments are not supported")
	}
	if o.limit < 0 || o.timeout < 0 || o.requestTimeout < 0 {
		return o, errors.New("limit must be nonnegative; timeouts must be nonnegative (0 disables the corresponding limit)")
	}
	if o.plan && (o.resume || o.requireDeep) {
		return o, errors.New("-plan-only cannot be combined with -resume or -require-deep")
	}
	o.model = strings.TrimSpace(o.model)
	o.baseURL = strings.TrimRight(strings.TrimSpace(o.baseURL), "/")
	if o.baseURL == "" {
		o.baseURL = "http://127.0.0.1:11434"
	}
	if !o.plan && (o.output == "" || o.model == "") {
		return o, errors.New("analysis requires -output and -model (or OLLAMA_MODEL)")
	}
	return o, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	o, err := parse(args, stderr)
	if err != nil {
		return err
	}
	state, err := reposcan.Load(o.state)
	if err != nil {
		return fmt.Errorf("load repo-scan state: %w", err)
	}
	if o.plan {
		return printPlan(stdout, state)
	}
	if err := checkOutput(o.state, o.output, o.resume); err != nil {
		return err
	}
	var previous *scananalyze.Report
	if o.resume {
		previous, err = loadReport(o.output)
		if err != nil {
			return fmt.Errorf("load analysis checkpoint: %w", err)
		}
	}
	client, err := llm.NewClient(llm.Config{BaseURL: o.baseURL, Model: o.model, HTTPClient: &http.Client{
		Timeout:       o.requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}})
	if err != nil {
		return err
	}
	analyzer, err := processor.New(client)
	if err != nil {
		return err
	}
	if o.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.timeout)
		defer cancel()
	}
	fmt.Fprintln(stderr, "Using saved scan:", state.Profile.Repository.ID, "commit", state.Profile.Repository.CommitSHA)
	fmt.Fprintln(stderr, "No GitHub/OSV/NVD requests. Matched package facts, source paths and advisory text will be sent to", o.baseURL)
	requestTimeout, overallTimeout := "disabled", "disabled"
	if o.requestTimeout > 0 {
		requestTimeout = o.requestTimeout.String()
	}
	if o.timeout > 0 {
		overallTimeout = o.timeout.String()
	}
	fmt.Fprintf(stderr, "Per-request timeout: %s; overall analysis deadline: %s\n", requestTimeout, overallTimeout)
	fmt.Fprintln(stderr, "Preparing matching alias groups; Deep Analysis runs only for related screening results.")
	report, runErr := scananalyze.Run(ctx, state, analyzer, scananalyze.Config{
		Model: o.model, BaseURL: o.baseURL, Limit: o.limit,
		Checkpoint: func(r scananalyze.Report) error { return saveReport(o.output, r) },
		Progress:   func(message string) { fmt.Fprintln(stderr, time.Now().UTC().Format(time.RFC3339), message) },
	}, previous)
	if report.SchemaVersion != 0 {
		fmt.Fprintf(stderr, "Candidates=%d Selected=%d Screened=%d Analyzed=%d ScreeningOnly=%d Excluded=%d Errors=%d Pending=%d NotSelected=%d\n",
			report.TotalCandidates, report.SelectedCandidates, report.Screened, report.Analyzed, report.ScreeningOnly, report.Excluded, report.Errors, report.Pending, report.NotSelected)
		e := json.NewEncoder(stdout)
		e.SetIndent("", "  ")
		if err := e.Encode(report); err != nil {
			return errors.Join(runErr, err)
		}
	}
	if runErr != nil {
		return runErr
	}
	if o.requireDeep {
		for _, entry := range report.Entries {
			if entry.Analysis != nil && entry.Feed != nil && entry.Feed.Status == feed.StatusAnalyzed {
				return nil
			}
		}
		return errors.New("Deep Analysis E2E not covered: no analyzed feed item (screening outcomes were not overridden)")
	}
	return nil
}

type planEntry struct {
	ID            string   `json:"id"`
	IDs           []string `json:"ids"`
	RecordKeys    []string `json:"record_keys"`
	AdvisoryKinds []string `json:"advisory_kinds"`
	Origins       int      `json:"origins"`
	Error         string   `json:"error,omitempty"`
}

func printPlan(w io.Writer, state reposcan.State) error {
	p := struct {
		Repository          domain.RepositoryIdentity `json:"repository"`
		ScanStatus          string                    `json:"scan_status"`
		ScanRefreshComplete bool                      `json:"scan_refresh_complete"`
		TotalCandidates     int                       `json:"total_candidates"`
		PreparationErrors   int                       `json:"preparation_errors"`
		Entries             []planEntry               `json:"entries"`
	}{Repository: state.Profile.Repository, ScanStatus: state.Report.Status, ScanRefreshComplete: state.Report.RefreshComplete, Entries: []planEntry{}}
	for _, candidate := range scananalyze.Prepare(state) {
		p.Entries = append(p.Entries, planEntry{candidate.ID, candidate.IDs, candidate.RecordKeys, candidate.AdvisoryKinds, len(candidate.Input.Repository.Components), candidate.Error})
		if candidate.Error != "" {
			p.PreparationErrors++
		}
	}
	p.TotalCandidates = len(p.Entries)
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	if err := e.Encode(p); err != nil {
		return err
	}
	if p.PreparationErrors > 0 {
		return fmt.Errorf("%d candidate groups could not be prepared; see entries[].error", p.PreparationErrors)
	}
	return nil
}

func checkOutput(state, output string, resume bool) error {
	s, err := filepath.Abs(state)
	if err != nil {
		return err
	}
	o, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if s == o {
		return errors.New("analysis output must not overwrite the scan state")
	}
	info, err := os.Lstat(output)
	if errors.Is(err, os.ErrNotExist) {
		if resume {
			return errors.New("-resume requires an existing analysis output")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("analysis output must be a regular file, not a symlink")
	}
	stateInfo, err := os.Stat(state)
	if err != nil {
		return err
	}
	if os.SameFile(stateInfo, info) {
		return errors.New("analysis output must not overwrite the scan state")
	}
	if !resume {
		return errors.New("output already exists; use -resume or choose a new output path")
	}
	return nil
}

func loadReport(path string) (*scananalyze.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var report scananalyze.Report
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err := d.Decode(&report); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing analysis checkpoint data")
	}
	return &report, nil
}

// Callers must serialize writers to an output path. Scan state is never updated.
func saveReport(path string, report scananalyze.Report) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("checkpoint destination is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".repo-analysis-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(data, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
