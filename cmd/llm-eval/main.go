// Command llm-eval runs deterministic matching, Screening, conditional Deep
// Analysis, and feed construction against normalized mock input and a real
// Ollama instance. It does not clone repositories, call NVD, or persist data.
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
	"vulns-news/src/llm"
	"vulns-news/src/matcher"
	"vulns-news/src/pipeline"
	"vulns-news/src/processor"
)

const defaultInputPath = "testdata/scenarios/npm-affected-dependency/input.json"

type evalInput struct {
	Vulnerability domain.NormalizedVulnerability `json:"vulnerability"`
	Repository    domain.RepositoryProfile       `json:"repository"`
	Evidence      []processor.Evidence           `json:"evidence"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "llm-eval: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	inputPath := flag.String("input", defaultInputPath, "path to normalized repository, vulnerability, and evidence JSON")
	model := flag.String("model", os.Getenv("OLLAMA_MODEL"), "Ollama model name (or set OLLAMA_MODEL)")
	baseURL := flag.String("base-url", os.Getenv("OLLAMA_BASE_URL"), "Ollama base URL (or set OLLAMA_BASE_URL)")
	timeout := flag.Duration("timeout", 10*time.Minute, "maximum time to wait for one Ollama generation")
	flag.Parse()

	if *model == "" {
		return errors.New("Ollama model is required; set OLLAMA_MODEL or pass -model")
	}

	fixture, err := readInput(*inputPath)
	if err != nil {
		return err
	}
	input, matched, err := prepareInput(matcher.New(nil), fixture)
	if err != nil {
		return fmt.Errorf("match repository and vulnerability: %w", err)
	}
	if !matched {
		return errors.New("input produced no deterministic match candidate")
	}

	client, err := llm.NewClient(llm.Config{
		BaseURL: *baseURL,
		Model:   *model,
		HTTPClient: &http.Client{
			Timeout: *timeout,
		},
	})
	if err != nil {
		return fmt.Errorf("create Ollama client: %w", err)
	}
	analysisProcessor, err := processor.New(client)
	if err != nil {
		return fmt.Errorf("create analysis processor: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Fprintf(os.Stderr, "Running Screening and conditional Deep Analysis with %s (timeout per generation: %s)...\n", *model, timeout.String())
	output, err := pipeline.Process(ctx, analysisProcessor, input)
	if err != nil {
		return fmt.Errorf("run analysis pipeline: %w", err)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("write analysis JSON: %w", err)
	}
	return nil
}

func readInput(path string) (evalInput, error) {
	file, err := os.Open(path)
	if err != nil {
		return evalInput{}, fmt.Errorf("open input fixture %q: %w", path, err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()

	var input evalInput
	if err := decoder.Decode(&input); err != nil {
		return evalInput{}, fmt.Errorf("decode input fixture %q: %w", path, err)
	}
	if err := requireEOF(decoder); err != nil {
		return evalInput{}, fmt.Errorf("decode input fixture %q: %w", path, err)
	}
	return input, nil
}

func prepareInput(candidateMatcher *matcher.Matcher, fixture evalInput) (processor.Input, bool, error) {
	if candidateMatcher == nil {
		return processor.Input{}, false, errors.New("matcher is required")
	}
	candidate, matched, err := candidateMatcher.Match(fixture.Repository, fixture.Vulnerability)
	if err != nil {
		return processor.Input{}, false, err
	}
	if !matched {
		return processor.Input{}, false, nil
	}
	return processor.Input{
		Vulnerability: fixture.Vulnerability,
		Repository:    fixture.Repository,
		Candidate:     candidate,
		Evidence:      fixture.Evidence,
	}, true, nil
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return fmt.Errorf("trailing data: %w", err)
}
