// Package scanjob runs bounded, ephemeral repository scans independently of HTTP requests.
package scanjob

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"time"

	"vulns-news/src/repository"
)

var (
	ErrFull   = errors.New("job capacity reached")
	ErrClosed = errors.New("job manager stopped")
)

type Request struct {
	URL string `json:"url"`
	Ref string `json:"ref"`
}
type Summary struct {
	CommitSHA       string `json:"commit_sha,omitempty"`
	RefreshComplete bool   `json:"refresh_complete"`
}
type Job struct {
	JobID        string   `json:"job_id"`
	RepositoryID string   `json:"repository_id"`
	State        string   `json:"state"`
	Error        string   `json:"error,omitempty"`
	Summary      *Summary `json:"summary,omitempty"`
}

// Scanner must honor ctx cancellation and return promptly. CLI enforces this for subprocesses.
type Scanner interface {
	Scan(context.Context, Request) (Summary, error)
}

// Validate reuses acquisition URL rules and accepts a conservative subset of git refs.
// URL syntax validation cannot establish whether the repository exists or is public.
func Validate(r Request) (Request, error) {
	u, err := repository.CanonicalizeGitHubURL(r.URL)
	if err != nil {
		return r, err
	}
	if len(r.URL) > 2048 || len(r.Ref) > 255 {
		return r, errors.New("URL or ref too long")
	}
	if r.Ref != "" {
		if r.Ref == "@" || strings.HasPrefix(r.Ref, "-") || strings.Contains(r.Ref, "..") || strings.Contains(r.Ref, "@{") {
			return r, errors.New("invalid ref")
		}
		for _, c := range r.Ref {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._/", c)) {
				return r, errors.New("invalid ref")
			}
		}
		for _, p := range strings.Split(r.Ref, "/") {
			if p == "" || strings.HasPrefix(p, ".") || strings.HasSuffix(p, ".") || strings.HasSuffix(p, ".lock") {
				return r, errors.New("invalid ref")
			}
		}
	}
	r.URL = u
	return r, nil
}

type entry struct {
	job      Job
	request  Request
	ctx      context.Context
	cancel   context.CancelFunc
	finished uint64
}
type Manager struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	scanner  Scanner
	timeout  time.Duration
	capacity int
	jobs     map[string]*entry
	queue    chan *entry
	wg       sync.WaitGroup
	sequence uint64
}

func New(ctx context.Context, scanner Scanner, workers, capacity int, timeout time.Duration) (*Manager, error) {
	if ctx == nil || scanner == nil || workers < 1 || capacity < workers || timeout <= 0 {
		return nil, errors.New("invalid job manager configuration")
	}
	ctx, cancel := context.WithCancel(ctx)
	m := &Manager{ctx: ctx, cancel: cancel, scanner: scanner, timeout: timeout, capacity: capacity, jobs: make(map[string]*entry), queue: make(chan *entry, capacity)}
	for i := 0; i < workers; i++ {
		m.wg.Add(1)
		go m.worker()
	}
	return m, nil
}

func (m *Manager) Submit(r Request) (Job, error) {
	r, err := Validate(r)
	if err != nil {
		return Job{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return Job{}, ErrClosed
	}
	if len(m.jobs) >= m.capacity {
		var oldest *entry
		for _, e := range m.jobs {
			if e.finished != 0 && (oldest == nil || e.finished < oldest.finished) {
				oldest = e
			}
		}
		if oldest == nil {
			return Job{}, ErrFull
		}
		delete(m.jobs, oldest.job.JobID)
	}
	ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
	e := &entry{job: Job{JobID: rand.Text(), RepositoryID: rand.Text(), State: "queued"}, request: r, ctx: ctx, cancel: cancel}
	m.jobs[e.job.JobID] = e
	m.queue <- e
	return e.job, nil
}

func (m *Manager) Get(id string) (Job, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.jobs[id]
	if !ok {
		return Job{}, false
	}
	j := e.job
	if j.Summary != nil {
		s := *j.Summary
		j.Summary = &s
	}
	return j, true
}

func (m *Manager) worker() {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			return
		case e := <-m.queue:
			m.mu.Lock()
			e.job.State = "running"
			m.mu.Unlock()
			var summary Summary
			var err error
			if e.ctx.Err() == nil {
				summary, err = m.scanner.Scan(e.ctx, e.request)
			}
			m.mu.Lock()
			switch {
			case errors.Is(e.ctx.Err(), context.DeadlineExceeded):
				e.job.State = "failed"
				e.job.Error = "scan timed out"
			case e.ctx.Err() != nil:
				e.job.State = "canceled"
				e.job.Error = "scan canceled"
			case err != nil:
				e.job.State = "failed"
				e.job.Error = "scan failed"
			default:
				e.job.State = "succeeded"
				e.job.Summary = &summary
			}
			m.sequence++
			e.finished = m.sequence
			e.cancel()
			m.mu.Unlock()
		}
	}
}

// Close cancels active/queued jobs and waits for scanners to release resources.
func (m *Manager) Close() {
	m.cancel()
	m.wg.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.jobs {
		e.cancel()
		if e.finished == 0 {
			e.job.State = "canceled"
			e.job.Error = "scan canceled"
			m.sequence++
			e.finished = m.sequence
		}
	}
}
