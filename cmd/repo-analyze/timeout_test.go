package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"vulns-news/src/feed"
	"vulns-news/src/processor"
	"vulns-news/src/scananalyze"
)

// A watchdog cancels stuck tests without adding a parent deadline that would
// hide an accidentally injected overall deadline or HTTP client timeout.
func timeoutTestContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	watchdogErr := errors.New("timeout test exceeded its five-second watchdog")
	watchdog := time.AfterFunc(5*time.Second, func() { cancel(watchdogErr) })
	t.Cleanup(func() {
		watchdog.Stop()
		if errors.Is(context.Cause(ctx), watchdogErr) {
			t.Error(watchdogErr)
		}
		cancel(context.Canceled)
	})
	return ctx, func() { cancel(context.Canceled) }
}

func runTimeoutCLI(t *testing.T, args []string) ([]byte, string, error) {
	t.Helper()
	ctx, cancel := timeoutTestContext(t)
	defer cancel()
	var stdout, stderr bytes.Buffer
	err := run(ctx, args, &stdout, &stderr)
	return stdout.Bytes(), stderr.String(), err
}

func assertTimeoutCompletion(t *testing.T, report scananalyze.Report) {
	t.Helper()
	if !report.Complete || !report.SelectedComplete || report.TotalCandidates != 1 || report.SelectedCandidates != 1 || report.Screened != 1 || report.Analyzed != 1 || report.Errors != 0 || report.Pending != 0 || len(report.Entries) != 1 {
		t.Fatalf("timeout/resume pipeline incomplete: %+v", report)
	}
	entry := report.Entries[0]
	if entry.Status != "analyzed" || entry.Stage != "complete" || entry.Error != "" || entry.Screening == nil || entry.Analysis == nil || entry.Feed == nil || entry.Feed.Status != feed.StatusAnalyzed || entry.ScreeningHash == "" || entry.AnalysisHash == "" {
		t.Fatalf("timeout/resume did not reach Feed: %+v", entry)
	}
	if entry.Feed.VulnerabilityID != testAdvisoryID || !reflect.DeepEqual(entry.Feed.Generation, []processor.Generation{entry.Screening.Generation, entry.Analysis.Generation}) {
		t.Error("Feed lost advisory identity or generation metadata")
	}
}

func assertTimeoutCachedResume(t *testing.T, scan savedScan, h *ollamaServer, args []string, report scananalyze.Report) {
	t.Helper()
	calls := h.calls()
	stdout, log, err := runTimeoutCLI(t, append(args, "-resume"))
	if err != nil {
		t.Fatalf("cached resume: %v\n%s", err, log)
	}
	resumed := assertSavedReport(t, scan, stdout)
	assertTimeoutCompletion(t, resumed)
	if !reflect.DeepEqual(resumed.Entries, report.Entries) || resumed.SnapshotHash != report.SnapshotHash || resumed.StartedAt != report.StartedAt {
		t.Error("cached resume changed outputs, checksums, or snapshot identity")
	}
	assertCalls(t, h, calls...)
	if strings.Contains(log, ": screening") || strings.Contains(log, ": analysis") {
		t.Errorf("cached resume repeated model work:\n%s", log)
	}
}

func TestRunZeroRequestTimeoutDelayedResponsesAndCachedResume(t *testing.T) {
	for _, overall := range []time.Duration{10 * time.Minute, 0} {
		t.Run("overall="+overall.String(), func(t *testing.T) {
			scan := newSavedScan(t, true)
			h := newOllamaServer(t, scan, ollamaReply{stage: "screening"}, ollamaReply{stage: "analysis"})
			ctx, cancel := timeoutTestContext(t)
			defer cancel()

			started := time.Now()
			var firstDeadline time.Time
			calls := 0
			previous := http.DefaultTransport
			http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				deadline, ok := r.Context().Deadline()
				if overall == 0 {
					if ok {
						t.Errorf("request %d has deadline %v with both timeouts disabled", calls, deadline)
					}
					if r.Context() != ctx {
						t.Errorf("request %d did not inherit the supplied parent context directly", calls)
					}
				} else if !ok || deadline.Before(started.Add(overall)) || deadline.After(time.Now().Add(overall)) {
					t.Errorf("request %d deadline = %v, present=%t; want only the %s overall deadline, not a default client timer", calls, deadline, ok, overall)
				}
				if calls == 1 {
					firstDeadline = deadline
				} else if !deadline.Equal(firstDeadline) {
					t.Error("Screen and Deep requests did not share the overall deadline")
				}
				response, err := previous.RoundTrip(r)
				if err != nil {
					return nil, err
				}
				// Delay each valid Ollama response without waiting minutes. Inspecting
				// the request deadline above detects fallback overall or client timers.
				delay := time.NewTimer(20 * time.Millisecond)
				defer delay.Stop()
				select {
				case <-delay.C:
					return response, nil
				case <-r.Context().Done():
					response.Body.Close()
					return nil, r.Context().Err()
				}
			})
			t.Cleanup(func() { http.DefaultTransport = previous })

			args := append(scan.args(h.url), "-request-timeout", "0m", "-timeout", overall.String(), "-require-deep")
			var stdout, stderr bytes.Buffer
			if err := run(ctx, args, &stdout, &stderr); err != nil {
				t.Fatalf("unlimited requests: %v\n%s", err, &stderr)
			}
			report := assertSavedReport(t, scan, stdout.Bytes())
			assertTimeoutCompletion(t, report)
			assertCalls(t, h, "screening", "analysis")
			wantOverall := overall.String()
			if overall == 0 {
				wantOverall = "disabled"
			}
			assertLog(t, stderr.String(), "Per-request timeout: disabled", "overall analysis deadline: "+wantOverall)
			if calls != 2 || ctx.Err() != nil {
				t.Fatalf("transport calls = %d, parent error = %v", calls, ctx.Err())
			}

			// Timeout settings are not model inputs: changing them must not invalidate
			// a completed checkpoint or regenerate cached model output.
			assertTimeoutCachedResume(t, scan, h, append(args, "-request-timeout", "250ms", "-timeout", "5s"), report)
			assertTimeoutCachedResume(t, scan, h, append(args, "-request-timeout", "0", "-timeout", "0"), report)
			if calls != 2 {
				t.Errorf("cached resume made another HTTP request: %d calls", calls)
			}
		})
	}
}

func TestRunRequestTimeoutContinuesIndependentCandidate(t *testing.T) {
	for _, stage := range []string{"screening", "analysis"} {
		for _, overall := range []string{"0", "10m"} {
			t.Run(stage+"/overall="+overall, func(t *testing.T) {
				scan := newSavedTwoCitationScan(t)
				replies := []citationReply{{stage: "screening"}}
				stages := []string{"screening"}
				blockedCall := 1
				if stage == "analysis" {
					replies = append(replies, citationReply{stage: "analysis"})
					stages = append(stages, "analysis")
					blockedCall = 2
				}
				replies = append(replies, citationReply{stage: "screening"}, citationReply{stage: "analysis"})
				stages = append(stages, "screening", "analysis")
				if stage == "screening" {
					replies = append(replies, citationReply{stage: "screening"})
				}
				replies = append(replies, citationReply{stage: "analysis"})
				h := newCitationServer(t, scan, replies...)
				previous := http.DefaultTransport
				calls := 0
				http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					response, err := previous.RoundTrip(r)
					if err != nil || calls != blockedCall {
						return response, err
					}
					defer response.Body.Close()
					<-r.Context().Done()
					return nil, r.Context().Err()
				})
				t.Cleanup(func() { http.DefaultTransport = previous })
				args := append(scan.args(h.url), "-request-timeout", "250ms", "-timeout", overall)
				stdout, log, err := runTimeoutCLI(t, args)
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("request timeout = %v\n%s", err, log)
				}
				report := assertSavedReport(t, scan, stdout)
				if report.Errors != 1 || report.Pending != 0 || report.Analyzed != 1 || report.Complete || report.Entries[0].Status != stage+"_error" || report.Entries[1].Status != "analyzed" {
					t.Fatalf("request timeout prevented later candidate: %+v", report)
				}
				requests := assertCitationRequests(t, h, scan, stages...)
				if requests[blockedCall].checkpoint.Entries[0].Status != stage+"_error" {
					t.Error("timeout was not checkpointed before the next candidate")
				}
				resumeArgs := append(args, "-request-timeout", "0", "-timeout", "0")
				stdout, log, err = runTimeoutCLI(t, append(resumeArgs, "-resume"))
				if err != nil {
					t.Fatalf("resume: %v\n%s", err, log)
				}
				resumed := assertSavedReport(t, scan, stdout)
				assertCitationCompletion(t, resumed, 2)
				if !reflect.DeepEqual(report.Entries[1], resumed.Entries[1]) || (stage == "analysis" && !reflect.DeepEqual(report.Entries[0].Screening, resumed.Entries[0].Screening)) {
					t.Error("resume replaced a cached success")
				}
				if stage == "screening" {
					stages = append(stages, "screening")
				}
				stages = append(stages, "analysis")
				assertCitationRequests(t, h, scan, stages...)
				assertCitationCachedResume(t, scan, h, resumeArgs, resumed)
			})
		}
	}
}

func TestRunRequestTimeoutAndCancellationCheckpointAndResume(t *testing.T) {
	for _, stage := range []string{"screening", "analysis"} {
		for _, mode := range []string{"per-request", "overall", "explicit cancellation", "per-request without overall timeout", "explicit cancellation without timeouts", "parent deadline without timeouts"} {
			t.Run(stage+"/"+mode, func(t *testing.T) {
				scan := newSavedScan(t, true)
				blockedCall := 1
				replies := []ollamaReply{{stage: "screening"}}
				if stage == "analysis" {
					blockedCall = 2
					replies = append(replies, ollamaReply{stage: "analysis"})
				} else {
					replies = append(replies, ollamaReply{stage: "screening", resumeScreening: true})
				}
				replies = append(replies, ollamaReply{stage: "analysis"})
				h := newOllamaServer(t, scan, replies...)
				watchdogCtx, cancel := timeoutTestContext(t)
				defer cancel()
				ctx := watchdogCtx

				requestTimeout, overall := time.Duration(0), 10*time.Minute
				wantErr := context.DeadlineExceeded
				switch mode {
				case "per-request", "per-request without overall timeout":
					requestTimeout = 250 * time.Millisecond
					if mode == "per-request without overall timeout" {
						overall = 0
					}
				case "overall":
					overall = time.Second
				case "explicit cancellation":
					wantErr = context.Canceled
				case "explicit cancellation without timeouts":
					overall = 0
					wantErr = context.Canceled
				case "parent deadline without timeouts":
					overall = 0
					var cancelDeadline context.CancelFunc
					ctx, cancelDeadline = context.WithTimeout(ctx, time.Second)
					defer cancelDeadline()
				}
				args := append(scan.args(h.url), "-request-timeout", requestTimeout.String(), "-timeout", overall.String(), "-require-deep")
				calls := 0
				var requestErr error
				previous := http.DefaultTransport
				http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					deadline, ok := r.Context().Deadline()
					if calls <= blockedCall && overall == 0 && requestTimeout == 0 {
						parentDeadline, parentOK := ctx.Deadline()
						if ok != parentOK || !deadline.Equal(parentDeadline) || r.Context() != ctx {
							t.Errorf("request %d did not inherit parent context/deadline directly: deadline=%v, present=%t; parent=%v, present=%t", calls, deadline, ok, parentDeadline, parentOK)
						}
					} else if calls > blockedCall && ok {
						t.Errorf("retry request %d has deadline %v with both timeouts disabled", calls, deadline)
					}
					response, err := previous.RoundTrip(r)
					if err != nil || calls != blockedCall {
						return response, err
					}
					defer response.Body.Close()
					if wantErr == context.Canceled {
						cancel()
					}
					// Withhold a valid response until the actual request context
					// ends; no synthetic timeout error or retry is injected.
					select {
					case <-r.Context().Done():
					case <-ctx.Done():
					}
					requestErr = r.Context().Err()
					if requestErr == nil {
						t.Error("HTTP request did not observe parent cancellation")
						return nil, ctx.Err()
					}
					return nil, requestErr
				})
				t.Cleanup(func() { http.DefaultTransport = previous })

				var stdout, stderr bytes.Buffer
				err := run(ctx, args, &stdout, &stderr)
				if !errors.Is(err, wantErr) || !errors.Is(requestErr, wantErr) || calls != blockedCall {
					t.Fatalf("run error = %v, request error = %v, calls = %d; want %v at call %d\n%s", err, requestErr, calls, wantErr, blockedCall, &stderr)
				}
				if wantErr == context.Canceled {
					if !errors.Is(context.Cause(ctx), context.Canceled) {
						t.Fatalf("parent cancellation cause = %v", context.Cause(ctx))
					}
				} else if mode == "parent deadline without timeouts" {
					if !errors.Is(ctx.Err(), context.DeadlineExceeded) || watchdogCtx.Err() != nil {
						t.Fatalf("parent deadline error = %v, watchdog error = %v", ctx.Err(), context.Cause(watchdogCtx))
					}
				} else if ctx.Err() != nil {
					t.Fatalf("CLI timeout canceled parent context: %v", context.Cause(ctx))
				}
				report := assertSavedReport(t, scan, stdout.Bytes())
				if report.Complete || report.SelectedComplete || report.Errors != 1 || report.Screened != blockedCall-1 || report.Analyzed != 0 || report.Pending != 0 || len(report.Entries) != 1 {
					t.Fatalf("interrupted report = %+v", report)
				}
				entry := report.Entries[0]
				if entry.Status != stage+"_error" || entry.Stage != stage || entry.Analysis != nil || entry.AnalysisHash != "" || entry.Feed != nil || !strings.Contains(entry.Error, wantErr.Error()) {
					t.Fatalf("interruption lost stage/error or saved incomplete output: %+v", entry)
				}
				if (stage == "analysis") != (entry.Screening != nil && entry.ScreeningHash != "") || (stage == "screening" && (entry.Screening != nil || entry.ScreeningHash != "")) {
					t.Fatalf("interruption lost or fabricated cached screening: %+v", entry)
				}
				cachedScreen := encodeTestJSON(t, entry.Screening)
				wantCalls := []string{"screening"}
				if stage == "analysis" {
					wantCalls = append(wantCalls, "analysis")
				}
				assertCalls(t, h, wantCalls...)
				assertLog(t, stderr.String(), "Errors=1")
				if overall == 0 {
					wantRequest := requestTimeout.String()
					if requestTimeout == 0 {
						wantRequest = "disabled"
					}
					assertLog(t, stderr.String(), "Per-request timeout: "+wantRequest, "overall analysis deadline: disabled")
				}

				resumeArgs := append(args, "-request-timeout", "0m", "-timeout", "0h")
				resumedOut, log, err := runTimeoutCLI(t, append(resumeArgs, "-resume"))
				if err != nil {
					t.Fatalf("retry resume: %v\n%s", err, log)
				}
				resumed := assertSavedReport(t, scan, resumedOut)
				assertTimeoutCompletion(t, resumed)
				h.mu.Lock()
				checkpoints := append([]scananalyze.Report{}, h.checkpoints...)
				h.mu.Unlock()
				if len(checkpoints) <= blockedCall || len(checkpoints[blockedCall].Entries) != 1 || !reflect.DeepEqual(checkpoints[blockedCall].Entries[0], entry) {
					t.Error("retry did not preserve the failed entry and its original error until validated success")
				}
				if resumed.SnapshotHash != report.SnapshotHash || resumed.StartedAt != report.StartedAt {
					t.Error("retry resume changed snapshot identity")
				}
				if stage == "analysis" {
					if !bytes.Equal(cachedScreen, encodeTestJSON(t, resumed.Entries[0].Screening)) || resumed.Entries[0].ScreeningHash != entry.ScreeningHash || strings.Contains(log, ": screening") {
						t.Errorf("retry resume replaced successful screening output:\n%s", log)
					}
				} else {
					wantCalls = append(wantCalls, "screening")
				}
				wantCalls = append(wantCalls, "analysis")
				assertCalls(t, h, wantCalls...)
				assertLog(t, log, "Errors=0", "Per-request timeout: disabled", "overall analysis deadline: disabled")
				assertTimeoutCachedResume(t, scan, h, resumeArgs, resumed)
				if calls != len(wantCalls) {
					t.Errorf("resume made unexpected HTTP requests: %d, want %d", calls, len(wantCalls))
				}
			})
		}
	}
}
