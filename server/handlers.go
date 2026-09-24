package main

import "net/http"

// Each handler is an API boundary placeholder and returns 501 until its
// application service and persistence implementation are connected.

// handleCreateRepository validates a public GitHub URL and queues profiling.
func handleCreateRepository(w http.ResponseWriter, r *http.Request) {
	// Input: {"url":"https://github.com/owner/repository","ref":"main"}.
	// Output: repository_id, profiling job_id, and queued status.
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleGetRepository returns a repository's pinned profile and current status.
func handleGetRepository(w http.ResponseWriter, r *http.Request) {
	// The profile is backend-owned data: languages, ecosystems, components,
	// products, containers, infrastructure, ref, and commit SHA.
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleRefreshRepository queues profiling when the configured ref has changed.
func handleRefreshRepository(w http.ResponseWriter, r *http.Request) {
	// A refresh resolves the ref to a commit and never executes repository code.
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleGetRepositoryFeed returns related and unresolved CVEs for one repository.
func handleGetRepositoryFeed(w http.ResponseWriter, r *http.Request) {
	// CVE identity, severity, matched components, and versions are backend facts;
	// generated summaries and risk explanations remain explicitly separated.
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleGetJob returns progress for profiling and daily CVE processing jobs.
func handleGetJob(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
