package repository

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"vulns-news/server/model"
)

// ErrNotFound は指定された ID のデータが存在しないことを表す。
// handler では errors.Is(err, ErrNotFound) で判定できる。
var ErrNotFound = errors.New("対象のデータが見つかりません")

// MockRepository は JSON ファイルから API 用のデータを取得する。
type MockRepository struct {
	dataDir string
}

// NewMockRepository はモックの保存先を指定して作成する。
// dataDir は絶対パス、またはサーバー起動時の作業ディレクトリからの相対パス。
func NewMockRepository(dataDir string) *MockRepository {
	return &MockRepository{dataDir: dataDir}
}

// ListCVEs は全体の CVE 一覧を返す。
func (r *MockRepository) ListCVEs() (model.FeedResult, error) {
	var result model.FeedResult
	if err := r.readJSON("cves.json", &result); err != nil {
		return model.FeedResult{}, err
	}
	return result, nil
}

// GetCVE は一覧から指定された ID の詳細を返す。
// 詳細サンプルの1件だけでなく、一覧にあるすべての記事を取得できる。
func (r *MockRepository) GetCVE(cveID string) (model.FeedItem, error) {
	feed, err := r.ListCVEs()
	if err != nil {
		return model.FeedItem{}, err
	}
	return findCVE(feed.Items, cveID)
}

// GetRepositoryRegistration は登録結果の固定モックを返す。
// この関数ではリポジトリの保存や解析ジョブの作成は行わない。
func (r *MockRepository) GetRepositoryRegistration() (model.CreateRepositoryResponse, error) {
	var result model.CreateRepositoryResponse
	if err := r.readJSON("repository-created.json", &result); err != nil {
		return model.CreateRepositoryResponse{}, err
	}
	return result, nil
}

// GetJob は指定されたジョブの完了状態を返す。
// 現段階では待機・処理中からの時間による状態遷移は行わない。
func (r *MockRepository) GetJob(jobID string) (model.JobResponse, error) {
	var result model.JobResponse
	if err := r.readJSON("job-completed.json", &result); err != nil {
		return model.JobResponse{}, err
	}
	if result.JobID != jobID {
		return model.JobResponse{}, fmt.Errorf("ジョブ %q: %w", jobID, ErrNotFound)
	}
	return result, nil
}

// GetRepositoryFeed は登録済みのリポジトリに関連する CVE 一覧を返す。
func (r *MockRepository) GetRepositoryFeed(repositoryID string) (model.FeedResult, error) {
	registration, err := r.GetRepositoryRegistration()
	if err != nil {
		return model.FeedResult{}, err
	}
	if registration.RepositoryID != repositoryID {
		return model.FeedResult{}, fmt.Errorf("リポジトリ %q: %w", repositoryID, ErrNotFound)
	}

	var result model.FeedResult
	if err := r.readJSON("repository-feed.json", &result); err != nil {
		return model.FeedResult{}, err
	}
	return result, nil
}

// GetRepositoryCVE は対象リポジトリの一覧から CVE の詳細・関連性を返す。
func (r *MockRepository) GetRepositoryCVE(repositoryID, cveID string) (model.FeedItem, error) {
	feed, err := r.GetRepositoryFeed(repositoryID)
	if err != nil {
		return model.FeedItem{}, err
	}
	return findCVE(feed.Items, cveID)
}

func findCVE(items []model.FeedItem, cveID string) (model.FeedItem, error) {
	for _, item := range items {
		if item.ID == cveID {
			return item, nil
		}
	}
	return model.FeedItem{}, fmt.Errorf("CVE %q: %w", cveID, ErrNotFound)
}

// readJSON はファイルを読み、呼び出し元が渡した構造体に変換する。
// filename にはこのファイル内の固定名だけを渡し、リクエストの ID は使わない。
func (r *MockRepository) readJSON(filename string, result any) error {
	data, err := os.ReadFile(filepath.Join(r.dataDir, filename))
	if err != nil {
		return fmt.Errorf("モック %s の読み込み: %w", filename, err)
	}
	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("モック %s のJSON解析: %w", filename, err)
	}
	return nil
}
