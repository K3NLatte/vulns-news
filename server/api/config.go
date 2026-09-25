package api

import (
	"net/http"
	"os"
	"path/filepath"

	"vulns-news/server/repository"
)

// NewMockRouter は起動時の設定からモックの取得先を決め、HTTP API を作る。
func NewMockRouter() *http.ServeMux {
	dataDir := os.Getenv("MOCK_DATA_DIR")
	if dataDir == "" {
		dataDir = filepath.Join("server", "mockdata")
		// server ディレクトリから起動する場合にも対応する。
		if _, err := os.Stat(dataDir); os.IsNotExist(err) {
			dataDir = "mockdata"
		}
	}
	return NewRouter(repository.NewMockRepository(dataDir))
}
