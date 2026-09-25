package api

import (
	"net/http"

	"vulns-news/server/repository"
)

// NewRouter は取得先を各 handler に渡し、リクエストの振り分け先を登録する。
// 登録順は処理の実行順ではなく、調査全体の流れは Orchestrator が制御する。
func NewRouter(repo *repository.MockRepository) *http.ServeMux {
	handler := &apiHandler{repository: repo}
	mux := http.NewServeMux()

	// 初期画面に表示する、モックの CVE 一覧を取得する。
	mux.HandleFunc("GET /api/cves", handler.handleListCVEs)

	// 指定された CVE の詳細を取得する。
	mux.HandleFunc("GET /api/cves/{cve_id}", handler.handleGetCVE)

	// リポジトリを登録し、repository_id と job_id を返す。
	mux.HandleFunc("POST /api/repositories", handler.handleCreateRepository)

	// リポジトリの解析処理の進捗を取得する。
	mux.HandleFunc("GET /api/jobs/{job_id}", handler.handleGetJob)

	// リポジトリに関連する CVE 一覧を取得する。
	mux.HandleFunc("GET /api/repositories/{repository_id}/feed", handler.handleGetRepositoryFeed)

	// リポジトリにおける CVE の詳細・関連性を取得する。
	mux.HandleFunc("GET /api/repositories/{repository_id}/feed/{cve_id}", handler.handleGetRepositoryCVE)

	// CVE・Repository・ref を指定して調査を開始し、analysis_id を返す。
	mux.HandleFunc("POST /api/analyses", handleCreateAnalysis)

	// analysis_id に対応する調査の進捗・レポートを取得する。
	mux.HandleFunc("GET /api/analyses/{analysis_id}", handleGetAnalysis)

	// Processor を別サービスに分ける場合の、Orchestrator 向けの内部 API。
	// 収集・解析済みの材料を検証・照合して、最終レポートを作る。
	// 同じバックエンド内で処理する場合は、このルートを内部関数の呼び出しに置き換えられる。
	mux.HandleFunc("POST /api/internal/analyses/{analysis_id}/process", handleProcessAnalysis)

	return mux
}
