package main

import "net/http"

// newRouter はリクエストの振り分け先を登録する。
// 登録順は処理の実行順ではなく、調査全体の流れは Orchestrator が制御する。
func newRouter() *http.ServeMux {
	mux := http.NewServeMux()

	// 初期画面に表示する、収集済みの CVE 一覧を取得する。
	mux.HandleFunc("GET /api/cves", handleListCVEs)

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
