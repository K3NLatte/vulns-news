package main

import (
	"net/http"
	"vulns-news/src/scanjob"
)

func newRouter(jobs *scanjob.Manager) *http.ServeMux {
	a := &api{jobs: jobs}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/repositories", a.handleCreateRepository)
	mux.HandleFunc("GET /api/jobs/{job_id}", a.handleGetJob)
	mux.HandleFunc("GET /api/repositories/{repository_id}", notImplemented)
	mux.HandleFunc("POST /api/repositories/{repository_id}/refresh", notImplemented)
	mux.HandleFunc("GET /api/repositories/{repository_id}/feed", notImplemented)
	return mux
}
