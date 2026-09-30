package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vulns-news/src/processor"
	"vulns-news/src/reposcan"
	"vulns-news/src/scananalyze"
)

// These fixtures are actual old CLI output, not checkpoints synthesized with
// today's hashing/serialization code. See testdata/pre-citation-fix/generate_test.go
// for the release ZIP checksum and reproducible, offline Go 1.25.0 procedure.
func TestRunResumePreCitationFixCheckpoint(t *testing.T) {
	fixtureDir := filepath.Join("testdata", "pre-citation-fix")
	before := snapshotFiles(t, fixtureDir)
	t.Cleanup(func() { assertNoWrites(t, fixtureDir, before) })
	scanBytes := readTestFile(t, filepath.Join(fixtureDir, "scan.json"))
	reportBytes := readTestFile(t, filepath.Join(fixtureDir, "analysis.json"))
	// Pin the old files themselves so accidental regeneration with current code
	// cannot silently weaken the compatibility regression test.
	for _, fixture := range []struct {
		name string
		data []byte
		hash string
	}{
		{"scan.json", scanBytes, "b60b7865a6ed94f5deebf530d1fe698e0b2fa72b1cac4f93cf2f0fd2030ef8a7"},
		{"analysis.json", reportBytes, "2c254ccda45c0b8e7d74f315d6cac63a659395bf396014a463f34422d5618144"},
	} {
		if got := fmt.Sprintf("%x", sha256.Sum256(fixture.data)); got != fixture.hash {
			t.Fatalf("frozen pre-fix %s changed: SHA-256 = %s, want %s", fixture.name, got, fixture.hash)
		}
	}

	dir := t.TempDir()
	scan := savedScan{dir: dir, path: filepath.Join(dir, "scan.json"),
		output: filepath.Join(dir, "analysis.json"), originalBytes: scanBytes}
	if err := os.WriteFile(scan.path, scanBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scan.output, reportBytes, 0600); err != nil {
		t.Fatal(err)
	}
	var err error
	scan.state, err = reposcan.Load(scan.path)
	if err != nil {
		t.Fatalf("load old scan: %v", err)
	}
	previous, err := loadReport(scan.output)
	if err != nil {
		t.Fatalf("load old checkpoint: %v", err)
	}
	if len(previous.Entries) != 3 || previous.Screened != 2 || previous.Analyzed != 1 || previous.Errors != 1 || previous.Pending != 1 || previous.Complete || previous.SelectedComplete {
		t.Fatalf("legacy fixture no longer covers completed, failed and pending work: %+v", previous)
	}
	completed, failed, pending := previous.Entries[0], previous.Entries[1], previous.Entries[2]
	if completed.Status != "analyzed" || completed.Screening == nil || completed.Analysis == nil || completed.Feed == nil ||
		failed.Status != "analysis_error" || failed.Screening == nil || failed.Analysis != nil || failed.Feed != nil ||
		pending.Status != "pending" || pending.Screening != nil || pending.Analysis != nil || pending.Feed != nil {
		t.Fatalf("unexpected old stage outputs: %+v", previous.Entries)
	}
	for _, generation := range []processor.Generation{completed.Screening.Generation, completed.Analysis.Generation, failed.Screening.Generation} {
		if generation.Model != testModel || generation.DoneReason != "stop" || generation.PromptTokens <= 0 || generation.CompletionTokens <= 0 || generation.TotalDurationNS <= 0 || generation.LoadDurationNS <= 0 {
			t.Fatalf("old generation metadata must be populated, not synthesized zero values: %+v", generation)
		}
	}
	if bytes.Contains(reportBytes, []byte(`"citation_retries"`)) {
		t.Fatal("pre-fix fixture unexpectedly contains the new generation field")
	}

	var rawPrevious struct {
		Entries []map[string]json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(reportBytes, &rawPrevious); err != nil {
		t.Fatal(err)
	}
	assertPreserved := func(report scananalyze.Report) {
		t.Helper()
		if report.SnapshotHash != previous.SnapshotHash || report.StartedAt != previous.StartedAt || report.Model != previous.Model || report.BaseURL != previous.BaseURL || report.Limit != previous.Limit {
			t.Error("resume changed the old snapshot identity or analysis options")
		}
		if len(report.Entries) != len(previous.Entries) {
			t.Fatalf("resume changed candidate count: %d", len(report.Entries))
		}
		for i, old := range previous.Entries {
			entry := report.Entries[i]
			if entry.ID != old.ID || entry.InputHash != old.InputHash ||
				(old.ScreeningHash != "" && entry.ScreeningHash != old.ScreeningHash) ||
				(old.AnalysisHash != "" && entry.AnalysisHash != old.AnalysisHash) {
				t.Errorf("candidate %d lost an old input/output hash: %+v", i, entry)
			}
			for stage, output := range map[string]any{"screening": entry.Screening, "analysis": entry.Analysis} {
				if raw, exists := rawPrevious.Entries[i][stage]; exists {
					var compact bytes.Buffer
					if err := json.Compact(&compact, raw); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(compact.Bytes(), encodeTestJSON(t, output)) {
						t.Errorf("candidate %d %s changed old serialized output/Generation (including absent citation_retries)", i, stage)
					}
				}
			}
		}
		if !reflect.DeepEqual(report.Entries[0], completed) {
			t.Error("resume changed the fully cached candidate or its rebuilt Feed")
		}
	}

	h := newCitationServer(t, scan, citationReply{stage: "analysis"},
		citationReply{stage: "screening"}, citationReply{stage: "analysis"})
	local, err := url.Parse(h.url)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the frozen base_url unchanged. Only the test transport redirects it
	// to httptest; the CLI still validates the actual old options and hashes.
	transport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host != previous.BaseURL {
			t.Errorf("unexpected HTTP request: %s", r.URL)
			return nil, fmt.Errorf("external HTTP disabled in legacy resume test: %s", r.URL)
		}
		forwarded := r.Clone(r.Context())
		forwarded.URL.Scheme, forwarded.URL.Host, forwarded.Host = local.Scheme, local.Host, local.Host
		return transport.RoundTrip(forwarded)
	})
	t.Cleanup(func() { http.DefaultTransport = transport })

	args := append(scan.args(previous.BaseURL), "-require-deep")
	stdout, log, err := runCLI(t, append(args, "-resume"))
	if err != nil {
		t.Fatalf("resume genuinely pre-fix checkpoint: %v\n%s", err, log)
	}
	report := assertSavedReport(t, scan, stdout)
	assertCitationCompletion(t, report, 3)
	assertPreserved(report)
	requests := assertCitationRequests(t, h, scan, "analysis", "screening", "analysis")
	for i, candidate := range []string{failed.ID, pending.ID, pending.ID} {
		if requests[i].input.Vulnerability.ID != candidate {
			t.Errorf("request %d ran for %s, want unfinished candidate %s", i+1, requests[i].input.Vulnerability.ID, candidate)
		}
		assertPreserved(requests[i].checkpoint)
	}
	assertLog(t, log, "candidate 2/3 "+failed.ID+": analysis", "candidate 3/3 "+pending.ID+": screening",
		"candidate 3/3 "+pending.ID+": analysis", "Candidates=3 Selected=3 Screened=3 Analyzed=3", "Errors=0 Pending=0")
	assertCitationCachedResume(t, scan, h, args, report)
	assertPreserved(decodeTestReport(t, readTestFile(t, scan.output)))
}
