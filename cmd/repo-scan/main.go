// Command repo-scan discovers package advisories without an LLM or GPU.
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
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/nvd"
	"vulns-news/src/osv"
	"vulns-news/src/reposcan"
	"vulns-news/src/repository"
)

type options struct {
	repository, ref, profile, state, osvURL, nvdURL, key string
	monitor, plan, nvd                                   bool
	batchSize, maxPages                                  int
	timeout, requestTimeout                              time.Duration
}

type result struct {
	Mode            string                    `json:"mode"`
	ProfileSource   string                    `json:"profile_source"`
	Repository      domain.RepositoryIdentity `json:"repository"`
	Plan            *reposcan.PlanReport      `json:"plan,omitempty"`
	Report          *reposcan.Report          `json:"report,omitempty"`
	Changes         []reposcan.Change         `json:"changes"`
	StatePath       string                    `json:"state_path,omitempty"`
	StateUpdate     string                    `json:"state_update,omitempty"`
	Acquisition     string                    `json:"acquisition"`
	ProfileWarnings []string                  `json:"profile_warnings,omitempty"`
	Error           string                    `json:"error,omitempty"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "repo-scan:", err)
		os.Exit(1)
	}
}

func parse(args []string, stderr io.Writer) (options, error) {
	var o options
	f := flag.NewFlagSet("repo-scan", flag.ContinueOnError)
	f.SetOutput(stderr)
	f.StringVar(&o.repository, "repository", "", "public GitHub URL for a new snapshot")
	f.StringVar(&o.ref, "ref", "", "branch or tag to acquire")
	f.StringVar(&o.profile, "profile", "", "import a RepositoryProfile JSON or mvp-run result; no clone")
	f.StringVar(&o.state, "state", "", "snapshot JSON path (required except -plan-only)")
	f.BoolVar(&o.monitor, "monitor", false, "recheck saved packages once without cloning; schedule this externally")
	f.BoolVar(&o.plan, "plan-only", false, "show deduplicated queries and unqueried components without calling OSV/NVD")
	f.BoolVar(&o.nvd, "nvd", true, "enrich explicit CVE IDs with NVD metadata")
	f.StringVar(&o.osvURL, "osv-base-url", "", "OSV API base URL")
	f.StringVar(&o.nvdURL, "nvd-base-url", "", "NVD CVE API URL")
	f.StringVar(&o.key, "nvd-api-key", os.Getenv("NVD_API_KEY"), "optional NVD key (prefer NVD_API_KEY environment variable)")
	f.IntVar(&o.batchSize, "batch-size", 100, "maximum OSV queries per HTTP batch")
	f.IntVar(&o.maxPages, "max-pages", 100, "page budget per OSV query; exceeded queries are incomplete")
	f.DurationVar(&o.timeout, "timeout", 15*time.Minute, "network/clone run deadline")
	f.DurationVar(&o.requestTimeout, "request-timeout", 30*time.Second, "HTTP request timeout")
	if err := f.Parse(args); err != nil {
		return o, err
	}
	if f.NArg() != 0 {
		return o, errors.New("unexpected positional arguments")
	}
	if o.timeout <= 0 || o.requestTimeout <= 0 || o.batchSize <= 0 || o.maxPages <= 0 {
		return o, errors.New("timeouts and batch/page limits must be positive")
	}
	if o.monitor {
		if o.state == "" || o.repository != "" || o.profile != "" || o.ref != "" {
			return o, errors.New("-monitor requires only a saved -state, not a new repository/profile/ref")
		}
	} else if (o.repository == "") == (o.profile == "") {
		return o, errors.New("provide exactly one of -repository or -profile")
	}
	if o.profile != "" && o.ref != "" {
		return o, errors.New("-ref applies only to -repository")
	}
	if !o.plan && o.state == "" {
		return o, errors.New("-state is required to bind results to a saved commit")
	}
	return o, nil
}

func importProfile(path string) (domain.RepositoryProfile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return domain.RepositoryProfile{}, err
	}
	var wrapper struct {
		Profile json.RawMessage `json:"repository_profile"`
	}
	if err := json.Unmarshal(b, &wrapper); err != nil {
		return domain.RepositoryProfile{}, err
	}
	if wrapper.Profile != nil {
		b = wrapper.Profile
	}
	var p domain.RepositoryProfile
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	if p.Repository.ID == "" || p.Repository.CommitSHA == "" {
		return p, errors.New("imported profile requires repository ID and commit SHA")
	}
	return p, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	o, err := parse(args, stderr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	out := result{Mode: "initial", Acquisition: "not_started", Changes: []reposcan.Change{}}
	write := func() error { e := json.NewEncoder(stdout); e.SetIndent("", "  "); return e.Encode(out) }
	fail := func(cause error) error {
		out.Error = cause.Error()
		if err := write(); err != nil {
			return err
		}
		return cause
	}
	var p domain.RepositoryProfile
	var previous reposcan.State
	if o.monitor {
		out.Mode, out.ProfileSource = "monitor", "saved_snapshot"
		previous, err = reposcan.Load(o.state)
		if err != nil {
			return fail(err)
		}
		p = previous.Profile
	} else {
		if !o.plan {
			if _, err := os.Lstat(o.state); err == nil {
				return fail(errors.New("state already exists; use -monitor or a new path for a new commit"))
			} else if !errors.Is(err, os.ErrNotExist) {
				return fail(err)
			}
		}
		if o.profile != "" {
			out.ProfileSource = "imported_snapshot"
			p, err = importProfile(o.profile)
		} else {
			out.ProfileSource = "github"
			var workspace string
			workspace, err = os.MkdirTemp("", "repo-scan-")
			if err == nil {
				defer os.RemoveAll(workspace)
				var acquirer *repository.Acquirer
				acquirer, err = repository.NewAcquirer(repository.Config{})
				if err == nil {
					fmt.Fprintln(stderr, "Cloning", o.repository)
					var acquired *repository.AcquiredRepository
					acquired, err = acquirer.Acquire(ctx, workspace, repository.RepositorySpec{URL: o.repository, Ref: o.ref})
					if err == nil {
						defer acquired.Cleanup()
						out.Acquisition = "complete"
						p, err = repository.Profile(acquired, time.Now().UTC())
					}
				}
			}
		}
		if err != nil {
			if out.Acquisition != "complete" {
				out.Acquisition = "failed"
			}
			return fail(err)
		}
	}
	out.Repository, out.Acquisition, out.ProfileWarnings = p.Repository, "complete", p.Warnings
	if o.plan {
		out.Mode = "plan"
		plan := reposcan.Plan(p)
		out.Plan = &plan
		return write()
	}
	fmt.Fprintln(stderr, "OSV: sending package names, ecosystems and pinned versions; not source code or repository paths")
	osvClient, err := osv.NewDiscoveryClient(osv.DiscoveryConfig{BaseURL: o.osvURL, BatchSize: o.batchSize, MaxPages: o.maxPages, HTTPClient: &http.Client{Timeout: o.requestTimeout}})
	if err != nil {
		return fail(err)
	}
	cfg := reposcan.Config{OSV: osvClient}
	if o.nvd {
		cfg.NVD, err = nvd.NewAnalysisClient(nvd.Config{BaseURL: o.nvdURL, APIKey: o.key, HTTPClient: &http.Client{Timeout: o.requestTimeout}})
		if err != nil {
			return fail(err)
		}
		cfg.NVDInterval = 6 * time.Second
		if o.key != "" {
			cfg.NVDInterval = 650 * time.Millisecond
		}
	}
	report := reposcan.Run(ctx, p, cfg)
	if o.monitor {
		report = reposcan.RetainEvidence(previous.Report, report)
		out.Changes = reposcan.Changes(previous.Report, report)
	}
	out.Report, out.StatePath = &report, o.state
	out.StateUpdate = "after_output"
	if !report.RefreshComplete {
		out.Error = "scan refresh incomplete; inspect report and retry (not a clean result)"
		if o.monitor {
			out.StateUpdate = "skipped_incomplete_refresh"
		}
	}
	// Deliver changes before acknowledging them in the baseline. An output error
	// must leave the previous state retryable. A save error is signaled on stderr
	// and by the exit status; emitted JSON deliberately makes no saved-state claim.
	if err := write(); err != nil {
		return err
	}
	if out.StateUpdate == "after_output" {
		state := reposcan.State{SchemaVersion: reposcan.SchemaVersion, Profile: p, Report: report}
		if err := reposcan.Save(o.state, state); err != nil {
			return fmt.Errorf("snapshot not updated: %w", err)
		}
		fmt.Fprintln(stderr, "Snapshot saved:", o.state)
	}
	if out.Error != "" {
		return errors.New(out.Error)
	}
	return nil
}
