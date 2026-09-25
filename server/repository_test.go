package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMockRepositoryFeedDetails(t *testing.T) {
	repository := NewMockRepository("mockdata")
	feed, err := repository.ListCVEs()
	if err != nil {
		t.Fatal(err)
	}
	if len(feed.Items) != 12 || feed.Total != 12 || feed.MatchedTotal != 12 {
		t.Fatalf("全体の一覧件数が不正です: %+v", feed)
	}
	for _, item := range feed.Items {
		detail, err := repository.GetCVE(item.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(detail, item) {
			t.Errorf("%s の詳細が一覧と一致しません", item.ID)
		}
	}
	if feed.Items[len(feed.Items)-1].CVSS != nil {
		t.Error("未評価の CVSS は nil である必要があります")
	}

	registration, err := repository.GetRepositoryRegistration()
	if err != nil {
		t.Fatal(err)
	}
	if registration.RepositoryID != "repo-001" || registration.JobID != "job-001" {
		t.Fatalf("登録結果が不正です: %+v", registration)
	}
	related, err := repository.GetRepositoryFeed(registration.RepositoryID)
	if err != nil {
		t.Fatal(err)
	}
	if len(related.Items) != 6 || related.Total != 6 || related.MatchedTotal != 6 {
		t.Fatalf("リポジトリ別の一覧件数が不正です: %+v", related)
	}
	analyzed, pending := 0, 0
	for _, item := range related.Items {
		detail, err := repository.GetRepositoryCVE(registration.RepositoryID, item.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(detail, item) {
			t.Errorf("%s の詳細がリポジトリ別の一覧と一致しません", item.ID)
		}
		switch item.RepositoryAnalysis {
		case "analyzed":
			analyzed++
		case "pending":
			pending++
		default:
			t.Errorf("%s の分析状態が不正です: %q", item.ID, item.RepositoryAnalysis)
		}
	}
	job, err := repository.GetJob(registration.JobID)
	if err != nil {
		t.Fatal(err)
	}
	if job.RepositoryID != registration.RepositoryID || job.Stage != "completed" ||
		job.HasAvailableResults == nil || !*job.HasAvailableResults ||
		job.Processed == nil || *job.Processed != len(related.Items) ||
		job.Total == nil || *job.Total != len(related.Items) ||
		job.ConfirmedCount == nil || *job.ConfirmedCount != analyzed ||
		job.PendingCount == nil || *job.PendingCount != pending {
		t.Fatalf("完了状態とリポジトリ別の一覧が一致しません: %+v", job)
	}
}

func TestMockRepositoryNotFound(t *testing.T) {
	repository := NewMockRepository("mockdata")
	cases := []struct {
		name string
		call func() error
	}{
		{"unknown CVE", func() error { _, err := repository.GetCVE("missing"); return err }},
		{"unknown job", func() error { _, err := repository.GetJob("missing"); return err }},
		{"unknown repository", func() error { _, err := repository.GetRepositoryFeed("missing"); return err }},
		{"detail in unknown repository", func() error { _, err := repository.GetRepositoryCVE("missing", "demo-001"); return err }},
		{"CVE outside repository", func() error { _, err := repository.GetRepositoryCVE("repo-001", "demo-012"); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, ErrNotFound) {
				t.Fatalf("error = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestMockRepositoryReadErrors(t *testing.T) {
	directory := t.TempDir()
	repository := NewMockRepository(directory)
	if _, err := repository.ListCVEs(); !errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrNotFound) {
		t.Fatalf("ファイル欠損と ID 不在を区別できません: %v", err)
	}
	path := filepath.Join(directory, "cves.json")
	if err := os.WriteFile(path, []byte(`{"items":`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := repository.ListCVEs()
	var syntaxError *json.SyntaxError
	if !errors.As(err, &syntaxError) {
		t.Fatalf("error = %v, want JSON syntax error", err)
	}
	if err := os.WriteFile(path, []byte(`{"items": [], "total": "invalid"}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = repository.ListCVEs()
	var typeError *json.UnmarshalTypeError
	if !errors.As(err, &typeError) {
		t.Fatalf("error = %v, want JSON type error", err)
	}
}
