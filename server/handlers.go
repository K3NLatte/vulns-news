package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"vulns-news/src/nvd"
)

/*
handleListCVEs は NVD から最新の CVE 一覧を取得して返す。
*/
const (
	minCVEListLimit     = 1
	defaultCVEListLimit = 10
	maxCVEListLimit     = 200
)

func handleListCVEs(w http.ResponseWriter, r *http.Request) {
	limit := defaultCVEListLimit
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < minCVEListLimit || parsed > maxCVEListLimit {
			http.Error(w, "limit は1以上100以下の整数を指定してください", http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	cves, err := nvd.NewClient().Fetch(r.Context(), limit)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		http.Error(w, err.Error(), status)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(cves); err != nil {
		log.Printf("CVE一覧のレスポンス書き込みに失敗しました: %v", err)
	}
}

// handleGetCVE は指定された CVE の詳細を返す。
func handleGetCVE(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleCreateRepository はリポジトリを登録し、リポジトリ ID とジョブ ID を返す。
func handleCreateRepository(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleGetJob は指定されたジョブの処理状態を返す。
func handleGetJob(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleGetRepositoryFeed はリポジトリに関連する CVE 一覧を返す。
func handleGetRepositoryFeed(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleGetRepositoryCVE はリポジトリにおける CVE の詳細・関連性を返す。
func handleGetRepositoryCVE(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleCreateAnalysis は新しい調査を作成し、Orchestrator に実行を依頼する。
func handleCreateAnalysis(w http.ResponseWriter, r *http.Request) {

	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleGetAnalysis は指定された調査の進捗・レポートを返す。
func handleGetAnalysis(w http.ResponseWriter, r *http.Request) {

	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleProcessAnalysis は収集・解析済みの材料を Processor に渡す。
func handleProcessAnalysis(w http.ResponseWriter, r *http.Request) {

	http.Error(w, "not implemented", http.StatusNotImplemented)
}
