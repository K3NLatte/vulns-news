package main

import "net/http"

// 各ハンドラーはたたき台。処理を実装するまでは 501 Not Implemented を返す。

// handleListCVEs は収集済みの CVE 一覧を返す。
func handleListCVEs(w http.ResponseWriter, r *http.Request) {
	// 入力: ListCVEsQuery（クエリ） / 出力: ListCVEsResponse。
	// TODO: 保存済みの CVE 情報を取得し、一覧の JSON を返す。
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleCreateAnalysis は新しい調査を作成し、Orchestrator に実行を依頼する。
func handleCreateAnalysis(w http.ResponseWriter, r *http.Request) {
	// 入力: CreateAnalysisRequest / 出力: CreateAnalysisResponse。
	// TODO: cve_id・repository_id・ref を検証し、調査を登録する。
	// TODO: analysis_id と status: queued を JSON で返す。
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleGetAnalysis は指定された調査の進捗・レポートを返す。
func handleGetAnalysis(w http.ResponseWriter, r *http.Request) {
	// 入力: URL の analysis_id / 出力: AnalysisResponse。
	// TODO: r.PathValue("analysis_id") に対応する調査を取得する。
	// TODO: analysis_id・status・report・errors を JSON で返す。
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleProcessAnalysis は収集・解析済みの材料を Processor に渡す。
func handleProcessAnalysis(w http.ResponseWriter, r *http.Request) {
	// 入力: URL の analysis_id と ProcessAnalysisRequest / 出力: AnalysisResponse。
	// TODO: r.PathValue("analysis_id") で対象の調査を特定する。
	// TODO: cve_analysis・repository_scan・evidence を受け取り、Processor に渡す。
	// TODO: 最終レポートと調査の状態を保存する。
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
