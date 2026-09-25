package api

import (
	"net/http"
	"path/filepath"
	"testing"

	"vulns-news/server/model"
)

func TestMockAPIDefaultDataDirectory(t *testing.T) {
	serverDirectory, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MOCK_DATA_DIR", "")
	for _, directory := range []string{serverDirectory, filepath.Dir(serverDirectory)} {
		t.Run(directory, func(t *testing.T) {
			t.Chdir(directory)
			feed := requestJSON[model.FeedResult](t, NewMockRouter(), "GET", "/api/cves?limit=1", "", http.StatusOK)
			if len(feed.Items) != 1 {
				t.Fatal("起動ディレクトリに対応するモックを読み込めません")
			}
		})
	}
}

func TestMockAPIConfiguredDataDirectory(t *testing.T) {
	directory, err := filepath.Abs("../mockdata")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MOCK_DATA_DIR", directory)
	t.Chdir(t.TempDir())
	requestJSON[model.FeedResult](t, NewMockRouter(), "GET", "/api/cves", "", http.StatusOK)
}
