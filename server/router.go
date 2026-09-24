package main

import "net/http"

// newRouter registers the repository-first API surface. CVEs are fetched by
// scheduled backend jobs and are never selected by an API user.
func newRouter() *http.ServeMux {
	mux := http.NewServeMux()

	// Register a GitHub URL and start profiling its pinned commit.
	mux.HandleFunc("POST /api/repositories", handleCreateRepository)

	// Return repository identity, profile revision, and profiling status.
	mux.HandleFunc("GET /api/repositories/{repository_id}", handleGetRepository)

	// Resolve the configured ref again and rebuild the profile when it changed.
	mux.HandleFunc("POST /api/repositories/{repository_id}/refresh", handleRefreshRepository)

	// Return related and unresolved CVEs assembled as backend feed data.
	mux.HandleFunc("GET /api/repositories/{repository_id}/feed", handleGetRepositoryFeed)

	// Return progress for repository profiling or daily NVD processing.
	mux.HandleFunc("GET /api/jobs/{job_id}", handleGetJob)

	return mux
}
