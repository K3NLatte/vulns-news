package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vulns-news/src/scanjob"
)

type scanFunc func(context.Context, scanjob.Request) (scanjob.Summary, error)

func (f scanFunc) Scan(c context.Context, r scanjob.Request) (scanjob.Summary, error) { return f(c, r) }
func TestAsyncAPI(t *testing.T) {
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	m, _ := scanjob.New(context.Background(), scanFunc(func(c context.Context, r scanjob.Request) (scanjob.Summary, error) {
		started <- c
		select {
		case <-release:
			return scanjob.Summary{CommitSHA: "abc", RefreshComplete: true}, nil
		case <-c.Done():
			return scanjob.Summary{}, c.Err()
		}
	}), 1, 1, time.Second)
	defer m.Close()
	router := newRouter(m)
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("POST", "/api/repositories", strings.NewReader(`{"url":"https://github.com/a/b.git","ref":"main"}`)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var job scanjob.Job
	if err := json.Unmarshal(w.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	if job.JobID == "" || job.RepositoryID == "" || w.Header().Get("Location") != "/api/jobs/"+job.JobID {
		t.Fatal(w.Header(), job)
	}
	scanCtx := <-started
	cancel()
	if scanCtx.Err() != nil {
		t.Fatal("request canceled job")
	}
	req = httptest.NewRequest("POST", "/api/repositories", strings.NewReader(`{"url":"https://github.com/a/b"}`))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		w = httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/api/jobs/"+job.JobID, nil))
		_ = json.Unmarshal(w.Body.Bytes(), &job)
		if job.State == "succeeded" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(job)
		}
		time.Sleep(time.Millisecond)
	}
	if job.Summary.CommitSHA != "abc" {
		t.Fatal(job)
	}
	for path, status := range map[string]int{"/api/jobs/missing": 404, "/api/repositories/id": 501, "/api/repositories/id/feed": 501} {
		w = httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != status {
			t.Fatal(path, w.Code)
		}
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/api/repositories/id/refresh", nil))
	if w.Code != 501 {
		t.Fatal(w.Code)
	}
}
func TestInvalidRequestsNeverScan(t *testing.T) {
	var calls atomic.Int32
	m, _ := scanjob.New(context.Background(), scanFunc(func(context.Context, scanjob.Request) (scanjob.Summary, error) {
		calls.Add(1)
		return scanjob.Summary{}, nil
	}), 1, 10, time.Second)
	defer m.Close()
	router := newRouter(m)
	for _, body := range []string{`{}`, `null`, `[]`, `{"url":null}`, `{"url":1}`, `{"URL":"https://github.com/a/b"}`, `{"url":"https://github.com/a/b","extra":1}`, `{"url":"https://github.com/a/b","url":"https://github.com/a/b"}`, `{"url":"https://github.com/a/b"} {}`, `{"url":"http://github.com/a/b"}`, `{"url":"https://github.com/a/b","ref":"--help"}`, `{"url":"https://github.com/a/b","ref":null}`, `{"url":"https://github.com/a/b","ref":"` + strings.Repeat("a", 5000) + `"}`} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/repositories", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Errorf("body %q: %d", body, w.Code)
		}
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/api/repositories", strings.NewReader(`{}`)))
	if w.Code != 415 {
		t.Fatal(w.Code)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request scanned")
	}
}
