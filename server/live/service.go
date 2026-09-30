package live

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"vulns-news/server/model"
	"vulns-news/src/pipeline"
	"vulns-news/src/reposcan"
	"vulns-news/src/scananalyze"
	"vulns-news/src/scanjob"
)

type Config struct {
	DataDir  string
	Model    string
	BaseURL  string
	Workers  int
	Capacity int
	Discover Discover
	Analyzer pipeline.Analyzer
}
type record struct {
	Version   int                 `json:"version"`
	Request   scanjob.Request     `json:"request"`
	Job       model.JobResponse   `json:"job"`
	CreatedAt time.Time           `json:"created_at"`
	Report    *scananalyze.Report `json:"report,omitempty"`
	items     []model.FeedItem
}
type Service struct {
	mu           sync.Mutex
	cfg          Config
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	queue        chan *record
	jobs         map[string]*record
	repositories map[string]*record
	closed       bool
}

var ErrUnavailable = errors.New("scan service unavailable")

func repositoryID(r scanjob.Request) string {
	// An unspecified ref and HEAD both refer to the default branch snapshot.
	ref := r.Ref
	if ref == "HEAD" {
		ref = ""
	}
	sum := sha256.Sum256([]byte(r.URL + "\x00" + ref))
	return hex.EncodeToString(sum[:16])
}
func Open(ctx context.Context, cfg Config) (*Service, error) {
	if ctx == nil || cfg.DataDir == "" || cfg.Workers < 1 || cfg.Capacity < cfg.Workers || (cfg.Analyzer != nil && cfg.Model == "") {
		return nil, errors.New("invalid live service configuration")
	}
	if cfg.Discover == nil {
		cfg.Discover = DiscoverRepository
	}
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Service{cfg: cfg, ctx: ctx, cancel: cancel, queue: make(chan *record, cfg.Capacity), jobs: map[string]*record{}, repositories: map[string]*record{}}
	paths, err := filepath.Glob(filepath.Join(cfg.DataDir, "*", "record.json"))
	if err != nil {
		cancel()
		return nil, err
	}
	for _, path := range paths {
		var rec record
		data, err := os.ReadFile(path)
		if err != nil {
			cancel()
			return nil, err
		}
		if err = json.Unmarshal(data, &rec); err != nil {
			cancel()
			return nil, err
		}
		request, err := scanjob.Validate(rec.Request)
		if err != nil || rec.Version != 1 || rec.Job.RepositoryID != repositoryID(request) || filepath.Base(filepath.Dir(path)) != rec.Job.JobID {
			cancel()
			return nil, fmt.Errorf("invalid persisted record: %s", path)
		}
		if rec.Report != nil {
			state, err := reposcan.Load(filepath.Join(filepath.Dir(path), "scan.json"))
			if err != nil {
				cancel()
				return nil, err
			}
			report, err := Restore(state, *rec.Report)
			if err != nil {
				cancel()
				return nil, err
			}
			if state.Profile.Repository.CanonicalURL != request.URL {
				cancel()
				return nil, errors.New("stored repository URL mismatch")
			}
			rec.Report = &report
			rec.items = Items(report, scananalyze.Prepare(state), state.Report.Records)
			updateCounts(&rec)
		}
		if rec.Job.Stage != "completed" && rec.Job.Stage != "failed" {
			rec.Job.Stage = "failed"
			rec.Job.ErrorMessage = "サーバーの再起動により処理が中断されました。再スキャンしてください。"
			if err := s.save(&rec); err != nil {
				cancel()
				return nil, err
			}
		}
		s.jobs[rec.Job.JobID] = &rec
		old := s.repositories[rec.Job.RepositoryID]
		if old == nil || old.CreatedAt.Before(rec.CreatedAt) {
			s.repositories[rec.Job.RepositoryID] = &rec
		}
	}
	for i := 0; i < cfg.Workers; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	return s, nil
}
func (s *Service) path(rec *record, name string) string {
	return filepath.Join(s.cfg.DataDir, rec.Job.JobID, name)
}
func (s *Service) save(rec *record) error {
	dir := filepath.Dir(s.path(rec, "record.json"))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".record-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path(rec, "record.json"))
}
func (s *Service) Submit(request scanjob.Request, refresh bool) (model.JobResponse, error) {
	request, err := scanjob.Validate(request)
	if err != nil {
		return model.JobResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := repositoryID(request)
	if rec := s.repositories[id]; rec != nil && (!refresh || (rec.Job.Stage != "completed" && rec.Job.Stage != "failed")) {
		return rec.Job, nil
	}
	if s.closed || s.ctx.Err() != nil || s.cfg.Analyzer == nil || len(s.queue) == cap(s.queue) {
		return model.JobResponse{}, ErrUnavailable
	}
	rec := &record{Version: 1, Request: request, CreatedAt: time.Now().UTC(), Job: model.JobResponse{RepositoryID: id, JobID: rand.Text(), Stage: "queued"}}
	if err := s.save(rec); err != nil {
		return model.JobResponse{}, err
	}
	s.jobs[rec.Job.JobID] = rec
	s.repositories[id] = rec
	s.queue <- rec
	return rec.Job, nil
}
func (s *Service) worker() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case rec := <-s.queue:
			s.run(rec)
		}
	}
}
func (s *Service) stage(rec *record, stage string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec.Job.Stage = stage
	return s.save(rec)
}
func (s *Service) run(rec *record) {
	err := s.stage(rec, "profiling")
	var state reposcan.State
	if err == nil {
		state, err = s.cfg.Discover(s.ctx, rec.Request)
	}
	if state.SchemaVersion != 0 {
		if saveErr := reposcan.Save(s.path(rec, "scan.json"), state); saveErr != nil {
			err = errors.Join(err, saveErr)
		}
	}
	if err == nil && state.Profile.Repository.CanonicalURL != rec.Request.URL {
		err = errors.New("discovery repository mismatch")
	}
	if err == nil {
		prepared := scananalyze.Prepare(state)
		_, err = scananalyze.Run(s.ctx, state, s.cfg.Analyzer, scananalyze.Config{Model: s.cfg.Model, BaseURL: s.cfg.BaseURL, Checkpoint: func(report scananalyze.Report) error {
			items := Items(report, prepared, state.Report.Records)
			s.mu.Lock()
			defer s.mu.Unlock()
			rec.Report = &report
			rec.items = items
			rec.Job.Stage = "analyzing"
			updateCounts(rec)
			return s.save(rec)
		}}, nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec.Job.Stage = "completed"
	if err != nil {
		log.Printf("job %s: %v", rec.Job.JobID, err)
		rec.Job.Stage = "failed"
		rec.Job.ErrorMessage = "スキャンまたは解析に失敗しました。取得済み結果を確認してください。"
	}
	if saveErr := s.save(rec); saveErr != nil {
		rec.Job.Stage = "failed"
		rec.Job.ErrorMessage = "結果の保存に失敗しました。"
		log.Printf("persist job %s: %v", rec.Job.JobID, saveErr)
	}
}
func updateCounts(rec *record) {
	confirmed, pending := 0, 0
	for _, item := range rec.items {
		if item.RepositoryAnalysis == "analyzed" {
			confirmed++
		} else {
			pending++
		}
	}
	available := len(rec.items) > 0
	rec.Job.HasAvailableResults = &available
	rec.Job.ConfirmedCount = &confirmed
	rec.Job.PendingCount = &pending
	if rec.Report != nil {
		processed := rec.Report.Screened
		total := rec.Report.TotalCandidates
		rec.Job.Processed = &processed
		rec.Job.Total = &total
	}
}

// Import never sends a network request or invokes a model. Both files must belong
// to the same immutable scan; Restore validates every cached output before use.
func (s *Service) Import(scanPath, analysisPath string) (model.JobResponse, error) {
	state, err := reposcan.Load(scanPath)
	if err != nil {
		return model.JobResponse{}, err
	}
	data, err := os.ReadFile(analysisPath)
	if err != nil {
		return model.JobResponse{}, err
	}
	var saved scananalyze.Report
	if err = json.Unmarshal(data, &saved); err != nil {
		return model.JobResponse{}, err
	}
	report, err := Restore(state, saved)
	if err != nil {
		return model.JobResponse{}, err
	}
	request, err := scanjob.Validate(scanjob.Request{URL: report.Repository.CanonicalURL, Ref: report.Repository.Ref})
	if err != nil {
		return model.JobResponse{}, err
	}
	rec := &record{Version: 1, Request: request, CreatedAt: time.Now().UTC(), Report: &report, items: Items(report, scananalyze.Prepare(state), state.Report.Records), Job: model.JobResponse{RepositoryID: repositoryID(request), JobID: rand.Text(), Stage: "completed"}}
	if !report.Complete {
		rec.Job.Stage = "failed"
		rec.Job.ErrorMessage = "未完了の解析結果です。取得済み結果のみ表示しています。"
	}
	updateCounts(rec)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return model.JobResponse{}, ErrUnavailable
	}
	if old := s.repositories[rec.Job.RepositoryID]; old != nil && old.Job.Stage != "completed" && old.Job.Stage != "failed" {
		return model.JobResponse{}, ErrUnavailable
	}
	if err = os.MkdirAll(filepath.Dir(s.path(rec, "scan.json")), 0700); err != nil {
		return model.JobResponse{}, err
	}
	if err = reposcan.Save(s.path(rec, "scan.json"), state); err != nil {
		return model.JobResponse{}, err
	}
	if err = s.save(rec); err != nil {
		return model.JobResponse{}, err
	}
	s.jobs[rec.Job.JobID] = rec
	s.repositories[rec.Job.RepositoryID] = rec
	return rec.Job, nil
}
func (s *Service) Close() { s.mu.Lock(); s.closed = true; s.cancel(); s.mu.Unlock(); s.wg.Wait() }
func (s *Service) allItems() []model.FeedItem {
	// Global articles are deterministic but must not imply a repository assessment.
	records := make([]*record, 0, len(s.repositories))
	for _, rec := range s.repositories {
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].CreatedAt.After(records[j].CreatedAt) })
	seen := map[string]bool{}
	items := []model.FeedItem{}
	for _, rec := range records {
		for _, item := range rec.items {
			if !seen[item.ID] {
				seen[item.ID] = true
				item.Relevance = nil
				item.RepositoryAnalysis = ""
				items = append(items, item)
			}
		}
	}
	return items
}
