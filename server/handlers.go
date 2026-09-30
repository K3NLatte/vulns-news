package main

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"vulns-news/src/scanjob"
)

type api struct{ jobs *scanjob.Manager }

func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func apiError(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}

func (a *api) handleCreateRepository(w http.ResponseWriter, r *http.Request) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		apiError(w, 415, "Content-Type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()
	// Decode explicitly to reject duplicate keys, null values and case-insensitive aliases.
	d := json.NewDecoder(r.Body)
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		apiError(w, 400, "invalid request body")
		return
	}
	var request scanjob.Request
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			apiError(w, 400, "invalid request body")
			return
		}
		name, ok := key.(string)
		if !ok || seen[name] || (name != "url" && name != "ref") {
			apiError(w, 400, "unknown or duplicate field")
			return
		}
		seen[name] = true
		value, err := d.Token()
		text, ok := value.(string)
		if err != nil || !ok {
			apiError(w, 400, "fields must be strings")
			return
		}
		if name == "url" {
			request.URL = text
		} else {
			request.Ref = text
		}
	}
	token, err = d.Token()
	var extra any
	if err != nil || token != json.Delim('}') || d.Decode(&extra) != io.EOF {
		apiError(w, 400, "invalid request body")
		return
	}
	request, err = scanjob.Validate(request)
	if err != nil {
		apiError(w, 400, "invalid public GitHub URL or ref")
		return
	}
	job, err := a.jobs.Submit(request)
	if err != nil {
		if errors.Is(err, scanjob.ErrFull) || errors.Is(err, scanjob.ErrClosed) {
			w.Header().Set("Retry-After", "5")
			apiError(w, 503, "scan service unavailable")
			return
		}
		apiError(w, 500, "unable to start scan")
		return
	}
	w.Header().Set("Location", "/api/jobs/"+job.JobID)
	respond(w, http.StatusAccepted, job)
}
func (a *api) handleGetJob(w http.ResponseWriter, r *http.Request) {
	job, ok := a.jobs.Get(r.PathValue("job_id"))
	if !ok {
		apiError(w, 404, "job not found")
		return
	}
	respond(w, 200, job)
}
func notImplemented(w http.ResponseWriter, r *http.Request) { apiError(w, 501, "not implemented") }
