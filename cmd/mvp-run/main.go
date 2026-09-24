// Command mvp-run clones one public GitHub repository, profiles its
// components, retrieves the latest NVD CVEs, and writes analyzed feed data to stdout.
// Optional -osv enrichment discloses dependency names and pinned versions to
// api.osv.dev. OSV package matches are advisory facts, not NVD version ranges.
// It does not persist data or execute repository code.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/versions"
	"vulns-news/src/evidence"
	"vulns-news/src/feed"
	"vulns-news/src/llm"
	"vulns-news/src/matcher"
	"vulns-news/src/nvd"
	"vulns-news/src/osv"
	"vulns-news/src/pipeline"
	"vulns-news/src/processor"
	"vulns-news/src/repository"
)

const nvdPageLimit = 200

const osvDisclosure = "OSV enabled: dependency ecosystems, names and pinned versions will be sent externally to https://api.osv.dev."
const osvProvenanceWarning = "Optional OSV package-match evidence is identified by osv: target IDs, osv_match references and OSV advisory citations; it is not NVD version-range evidence or proof of exploitability. OSV confirms only the exact queried version; other versions and non-npm ranges remain unknown."

// Enricher adds optional external package-match facts before deterministic matching.
type Enricher interface {
	Enrich(context.Context, domain.RepositoryProfile, domain.NormalizedVulnerability) (domain.NormalizedVulnerability, error)
}

type config struct {
	repositoryURL string
	ref           string
	model         string
	ollamaBaseURL string
	llmTimeout    time.Duration
	nvdBaseURL    string
	nvdAPIKey     string
	osvEnabled    bool
	asOf          time.Time
	publishedFrom time.Time
	publishedTo   time.Time
}

type nvdCounts struct {
	Available           int `json:"available"`
	Fetched             int `json:"fetched"`
	Normalized          int `json:"normalized"`
	Duplicates          int `json:"duplicates"`
	NormalizationErrors int `json:"normalization_errors"`
}

type runError struct {
	CVEID string `json:"cve_id,omitempty"`
	Stage string `json:"stage"`
	Error string `json:"error"`
}

type output struct {
	Repository    domain.RepositoryProfile `json:"repository_profile"`
	NVD           nvdCounts                `json:"nvd"`
	Matched       int                      `json:"matched"`
	Excluded      int                      `json:"excluded"`
	ScreeningOnly int                      `json:"screening_only"`
	Analyzed      int                      `json:"analyzed"`
	FeedItems     []feed.Item              `json:"feed_items"`
	Errors        []runError               `json:"errors"`
	Warnings      []string                 `json:"warnings,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "mvp-run: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := parseConfig(time.Now())
	if err != nil {
		return err
	}

	ollamaClient, err := llm.NewClient(llm.Config{
		BaseURL: cfg.ollamaBaseURL,
		Model:   cfg.model,
		HTTPClient: &http.Client{
			Timeout: cfg.llmTimeout,
		},
	})
	if err != nil {
		return fmt.Errorf("create Ollama client: %w", err)
	}
	analysisProcessor, err := processor.New(ollamaClient)
	if err != nil {
		return fmt.Errorf("create analysis processor: %w", err)
	}
	nvdClient, err := nvd.NewClient(nvd.Config{
		BaseURL: cfg.nvdBaseURL,
		APIKey:  cfg.nvdAPIKey,
	})
	if err != nil {
		return fmt.Errorf("create NVD client: %w", err)
	}
	var enricher Enricher
	if cfg.osvEnabled {
		client, err := osv.NewClient(osv.Config{})
		if err != nil {
			return fmt.Errorf("create OSV client: %w", err)
		}
		enricher = client // One cache shared by all CVEs in this run.
		fmt.Fprintln(os.Stderr, osvDisclosure)
		fmt.Fprintln(os.Stderr, "Warning:", osvProvenanceWarning)
	}
	acquirer, err := repository.NewAcquirer(repository.Config{})
	if err != nil {
		return fmt.Errorf("create repository acquirer: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	workspace, err := os.MkdirTemp("", "vulns-news-")
	if err != nil {
		return fmt.Errorf("create temporary workspace: %w", err)
	}
	defer os.RemoveAll(workspace)

	fmt.Fprintf(os.Stderr, "Cloning %s...\n", cfg.repositoryURL)
	acquired, err := acquirer.Acquire(ctx, workspace, repository.RepositorySpec{URL: cfg.repositoryURL, Ref: cfg.ref})
	if err != nil {
		return fmt.Errorf("acquire repository: %w", err)
	}
	defer acquired.Cleanup()

	profile, err := repository.Profile(acquired, time.Now())
	if err != nil {
		return fmt.Errorf("profile repository: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Profiled %d components; fetching up to %d latest NVD CVEs...\n", len(profile.Components), nvdPageLimit)

	page, err := nvdClient.FetchLatest(ctx, nvd.LatestOptions{
		AsOf:           cfg.asOf,
		PublishedStart: cfg.publishedFrom,
		PublishedEnd:   cfg.publishedTo,
		Limit:          nvdPageLimit,
	})
	if err != nil {
		return fmt.Errorf("fetch NVD CVEs: %w", err)
	}

	result := processPageWithEnricher(ctx, profile, page, matcher.New(versions.New()), analysisProcessor, enricher)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("write result JSON: %w", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	for _, runErr := range result.Errors {
		if runErr.Stage == "osv" {
			return errors.New("OSV enrichment failed; affected CVEs were skipped (see JSON errors)")
		}
	}
	return nil
}

func parseConfig(now time.Time) (config, error) {
	repositoryURL := flag.String("repository", "", "public GitHub repository URL")
	ref := flag.String("ref", "", "optional branch or tag (default: repository default branch)")
	model := flag.String("model", os.Getenv("OLLAMA_MODEL"), "Ollama model name (or set OLLAMA_MODEL)")
	ollamaBaseURL := flag.String("base-url", os.Getenv("OLLAMA_BASE_URL"), "Ollama base URL (or set OLLAMA_BASE_URL)")
	llmTimeout := flag.Duration("timeout", 10*time.Minute, "maximum time for each Ollama generation")
	osvEnabled := flag.Bool("osv", false, "opt in to OSV package matching; discloses dependency names, ecosystems and pinned versions externally to api.osv.dev")
	nvdBaseURL := flag.String("nvd-base-url", "", "optional NVD-compatible CVE API URL")
	nvdAPIKey := flag.String("nvd-api-key", os.Getenv("NVD_API_KEY"), "NVD API key (or set NVD_API_KEY)")
	publishedStart := flag.String("published-start", "", "NVD publication start in RFC3339 (default: search backwards until 200; with end only: previous 24 hours)")
	publishedEnd := flag.String("published-end", "", "NVD publication end in RFC3339 (default and maximum: command start)")
	flag.Parse()

	if strings.TrimSpace(*repositoryURL) == "" {
		return config{}, errors.New("-repository is required")
	}
	if strings.TrimSpace(*model) == "" {
		return config{}, errors.New("Ollama model is required; set OLLAMA_MODEL or pass -model")
	}
	if *llmTimeout <= 0 {
		return config{}, errors.New("-timeout must be positive")
	}
	from, to, err := publicationWindow(*publishedStart, *publishedEnd, now)
	if err != nil {
		return config{}, err
	}
	return config{
		repositoryURL: *repositoryURL,
		ref:           *ref,
		model:         *model,
		ollamaBaseURL: *ollamaBaseURL,
		llmTimeout:    *llmTimeout,
		nvdBaseURL:    *nvdBaseURL,
		nvdAPIKey:     *nvdAPIKey,
		osvEnabled:    *osvEnabled,
		asOf:          now.UTC(),
		publishedFrom: from,
		publishedTo:   to,
	}, nil
}

func publicationWindow(startText, endText string, now time.Time) (time.Time, time.Time, error) {
	if strings.TrimSpace(startText) == "" && strings.TrimSpace(endText) == "" {
		return time.Time{}, time.Time{}, nil
	}
	end := now.UTC()
	if strings.TrimSpace(endText) != "" {
		parsed, err := time.Parse(time.RFC3339, endText)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("parse -published-end: %w", err)
		}
		end = parsed.UTC()
	}
	if end.After(now) {
		return time.Time{}, time.Time{}, errors.New("-published-end must not be after command start")
	}
	start := end.Add(-24 * time.Hour)
	if strings.TrimSpace(startText) != "" {
		parsed, err := time.Parse(time.RFC3339, startText)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("parse -published-start: %w", err)
		}
		start = parsed.UTC()
	}
	if end.Before(start) {
		return time.Time{}, time.Time{}, errors.New("-published-end must not precede -published-start")
	}
	return start, end, nil
}

func processPage(ctx context.Context, profile domain.RepositoryProfile, page nvd.Page, candidateMatcher *matcher.Matcher, analyzer pipeline.Analyzer) output {
	return processPageWithEnricher(ctx, profile, page, candidateMatcher, analyzer, nil)
}

func processPageWithEnricher(ctx context.Context, profile domain.RepositoryProfile, page nvd.Page, candidateMatcher *matcher.Matcher, analyzer pipeline.Analyzer, enricher Enricher) output {
	result := output{
		Repository: profile,
		NVD: nvdCounts{
			Available: page.TotalResults,
			Fetched:   len(page.Vulnerabilities),
		},
		FeedItems: []feed.Item{},
		Errors:    []runError{},
	}
	if enricher != nil {
		result.Warnings = []string{osvProvenanceWarning}
	}
	seen := make(map[string]struct{}, len(page.Vulnerabilities))
	for index, item := range page.Vulnerabilities {
		if ctx.Err() != nil {
			result.Errors = append(result.Errors, runError{Stage: "context", Error: ctx.Err().Error()})
			break
		}
		vulnerability, err := nvd.Normalize(item.CVE)
		if err != nil {
			result.NVD.NormalizationErrors++
			result.Errors = append(result.Errors, runError{CVEID: strings.TrimSpace(item.CVE.ID), Stage: "normalize", Error: err.Error()})
			continue
		}
		if _, exists := seen[vulnerability.ID]; exists {
			result.NVD.Duplicates++
			continue
		}
		seen[vulnerability.ID] = struct{}{}
		result.NVD.Normalized++

		if enricher != nil {
			enriched, err := enricher.Enrich(ctx, profile, vulnerability)
			if err != nil {
				result.Errors = append(result.Errors, runError{CVEID: vulnerability.ID, Stage: "osv", Error: err.Error()})
				continue
			}
			vulnerability = enriched
		}

		candidate, matched, err := candidateMatcher.Match(profile, vulnerability)
		if err != nil {
			result.Errors = append(result.Errors, runError{CVEID: vulnerability.ID, Stage: "match", Error: err.Error()})
			continue
		}
		if !matched {
			continue
		}
		result.Matched++
		citations, err := evidence.Build(profile, vulnerability, candidate)
		if err != nil {
			result.Errors = append(result.Errors, runError{CVEID: vulnerability.ID, Stage: "evidence", Error: err.Error()})
			continue
		}
		if enricher != nil {
			// Build's first citation describes the NVD record, not OSV targets.
			// Do not let its reference fallback label an OSV URL as NVD.
			citations[0].URI = "https://nvd.nist.gov/vuln/detail/" + vulnerability.ID
			osvCitationCount := 0
			for _, reference := range vulnerability.References {
				for _, tag := range reference.Tags {
					if tag != "osv_match" {
						continue
					}
					osvCitationCount++
					citations = append(citations, processor.Evidence{
						ID:      fmt.Sprintf("EVD-OSV-%03d", osvCitationCount),
						Kind:    processor.EvidenceAdvisory,
						Source:  "OSV",
						URI:     reference.URL,
						Content: "This OSV advisory was returned by a pinned-package query and linked by ID/alias to " + vulnerability.ID + ". Exact queried package versions are recorded in osv: targets. These are OSV matches, not NVD version ranges or proof of exploitability. Other versions remain unknown.",
					})
					break
				}
			}
		}
		fmt.Fprintf(os.Stderr, "Analyzing candidate %s (%d/%d)...\n", vulnerability.ID, index+1, len(page.Vulnerabilities))
		processed, err := pipeline.Process(ctx, analyzer, processor.Input{
			Vulnerability: vulnerability,
			Repository:    profile,
			Candidate:     candidate,
			Evidence:      citations,
		})
		if err != nil {
			result.Errors = append(result.Errors, runError{CVEID: vulnerability.ID, Stage: "analysis", Error: err.Error()})
			continue
		}
		if processed.Excluded {
			result.Excluded++
			continue
		}
		if processed.Feed == nil {
			result.Errors = append(result.Errors, runError{CVEID: vulnerability.ID, Stage: "feed", Error: "pipeline returned no feed item"})
			continue
		}
		result.FeedItems = append(result.FeedItems, *processed.Feed)
		if processed.Analysis == nil {
			result.ScreeningOnly++
		} else {
			result.Analyzed++
		}
	}
	return result
}
