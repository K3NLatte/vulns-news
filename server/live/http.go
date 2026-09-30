package live

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"vulns-news/server/model"
	"vulns-news/src/scanjob"
)

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func apiError(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/analyses", s.analyses)
	mux.HandleFunc("POST /api/repositories", s.register)
	mux.HandleFunc("GET /api/jobs/{job}", s.job)
	mux.HandleFunc("GET /api/repositories/{repository}", s.repository)
	mux.HandleFunc("POST /api/repositories/{repository}/refresh", s.refresh)
	mux.HandleFunc("GET /api/repositories/{repository}/feed", s.feed)
	mux.HandleFunc("GET /api/repositories/{repository}/feed/{item}", s.feed)
	mux.HandleFunc("GET /api/cves", s.feed)
	mux.HandleFunc("GET /api/cves/{item}", s.feed)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { apiError(w, 404, "not found") })
	return mux
}

// analyses lists the latest saved snapshot per repository/ref without scheduling work.
func (s *Service) analyses(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	type summary struct {
		URL        string            `json:"url"`
		Ref        string            `json:"ref"`
		Job        model.JobResponse `json:"job"`
		Commit     string            `json:"commit"`
		ScanStatus string            `json:"scanStatus"`
		UpdatedAt  string            `json:"updatedAt"`
		ItemCount  int               `json:"itemCount"`
	}
	items := []summary{}
	for _, rec := range s.repositories {
		if rec.Report == nil {
			continue
		}
		items = append(items, summary{rec.Request.URL, rec.Request.Ref, rec.Job, rec.Report.Repository.CommitSHA, rec.Report.ScanStatus, stamp(rec.Report.UpdatedAt), len(rec.items)})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].UpdatedAt == items[j].UpdatedAt {
			return items[i].Job.RepositoryID < items[j].Job.RepositoryID
		}
		return items[i].UpdatedAt > items[j].UpdatedAt
	})
	respond(w, 200, struct {
		ReadOnly bool      `json:"readOnly"`
		Items    []summary `json:"items"`
	}{s.cfg.Analyzer == nil, items})
}
func (s *Service) register(w http.ResponseWriter, r *http.Request) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		apiError(w, 415, "Content-Type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()
	// Token decoding also rejects duplicate keys and case-insensitive aliases.
	d := json.NewDecoder(r.Body)
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		apiError(w, 400, "invalid request body")
		return
	}
	request := scanjob.Request{}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] || (name != "url" && name != "ref") {
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
	job, err := s.Submit(request, false)
	if err != nil {
		w.Header().Set("Retry-After", "5")
		apiError(w, 503, "scan service unavailable")
		return
	}
	w.Header().Set("Location", "/api/jobs/"+job.JobID)
	respond(w, 202, model.CreateRepositoryResponse{RepositoryID: job.RepositoryID, JobID: job.JobID})
}
func (s *Service) job(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.jobs[r.PathValue("job")]
	if rec == nil {
		apiError(w, 404, "job not found")
		return
	}
	respond(w, 200, rec.Job)
}
func (s *Service) repository(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.repositories[r.PathValue("repository")]
	if rec == nil {
		apiError(w, 404, "repository not found")
		return
	}
	result := map[string]any{"repository_id": rec.Job.RepositoryID, "url": rec.Request.URL, "ref": rec.Request.Ref, "job_id": rec.Job.JobID}
	if rec.Report != nil {
		result["commit_sha"] = rec.Report.Repository.CommitSHA
		result["scan_status"] = rec.Report.ScanStatus
		result["scan_refresh_complete"] = rec.Report.ScanRefreshComplete
	}
	respond(w, 200, result)
}
func (s *Service) refresh(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	rec := s.repositories[r.PathValue("repository")]
	var request scanjob.Request
	if rec != nil {
		request = rec.Request
	}
	s.mu.Unlock()
	if rec == nil {
		apiError(w, 404, "repository not found")
		return
	}
	job, err := s.Submit(request, true)
	if err != nil {
		apiError(w, 503, "scan service unavailable")
		return
	}
	respond(w, 202, model.CreateRepositoryResponse{RepositoryID: job.RepositoryID, JobID: job.JobID})
}
func (s *Service) feed(w http.ResponseWriter, r *http.Request) {
	limit, offset := 1000, 0
	for key, target := range map[string]*int{"limit": &limit, "offset": &offset} {
		if raw := r.URL.Query().Get(key); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 0 || (key == "limit" && (n < 1 || n > 1000)) {
				apiError(w, 400, "invalid pagination")
				return
			}
			*target = n
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	items := []model.FeedItem{}
	generated := time.Now().UTC()
	if id := r.PathValue("repository"); id != "" {
		rec := s.repositories[id]
		if rec == nil {
			apiError(w, 404, "repository not found")
			return
		}
		items = append(items, rec.items...)
		if rec.Report != nil {
			generated = rec.Report.UpdatedAt
		}
	} else {
		items = s.allItems()
	}
	if id := r.PathValue("item"); id != "" {
		for _, item := range items {
			if item.ID == id {
				respond(w, 200, item)
				return
			}
		}
		apiError(w, 404, "article not found")
		return
	}
	total := len(items)
	query := strings.ToLower(r.URL.Query().Get("search"))
	severity := r.URL.Query().Get("severity")
	filtered := []model.FeedItem{}
	for _, item := range items {
		if severity != "" && severity != "all" && item.Severity != severity {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(item.ID+" "+item.Title+" "+item.Summary+" "+item.Product), query) {
			continue
		}
		filtered = append(filtered, item)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].PublishedAt == filtered[j].PublishedAt {
			return filtered[i].ID < filtered[j].ID
		}
		return filtered[i].PublishedAt > filtered[j].PublishedAt
	})
	if offset > len(filtered) {
		offset = len(filtered)
	}
	end := offset + min(limit, len(filtered)-offset)
	page := filtered[offset:end]
	result := model.FeedResult{Items: page, Total: total, MatchedTotal: len(page), GeneratedAt: stamp(generated)}
	if rec := s.repositories[r.PathValue("repository")]; rec != nil && rec.Report != nil {
		result.ScanStatus = rec.Report.ScanStatus
		result.RepositoryCommit = rec.Report.Repository.CommitSHA
	}
	if end < len(filtered) {
		result.NextOffset = &end
	}
	respond(w, 200, result)
}
