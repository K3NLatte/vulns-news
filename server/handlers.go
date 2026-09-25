package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

const (
	minCVEListLimit     = 1
	defaultCVEListLimit = 10
	maxCVEListLimit     = 200
)

// apiHandler は各ルートから利用するデータ取得先を保持する。
type apiHandler struct {
	repository *MockRepository
}

// handleListCVEs はモックの CVE 一覧を指定件数まで返す。
func (h *apiHandler) handleListCVEs(w http.ResponseWriter, r *http.Request) {
	limit := defaultCVEListLimit
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < minCVEListLimit || parsed > maxCVEListLimit {
			http.Error(w, fmt.Sprintf("limit は%d以上%d以下の整数を指定してください", minCVEListLimit, maxCVEListLimit), http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	feed, err := h.repository.ListCVEs()
	if err != nil {
		writeRepositoryError(w, err)
		return
	}
	if len(feed.Items) > limit {
		feed.Items = feed.Items[:limit]
	}
	// フロントの契約に合わせ、matchedTotal は返す items の件数にする。
	feed.MatchedTotal = len(feed.Items)
	writeJSON(w, http.StatusOK, feed)
}

// handleGetCVE は指定された CVE の詳細を返す。
func (h *apiHandler) handleGetCVE(w http.ResponseWriter, r *http.Request) {
	cve, err := h.repository.GetCVE(r.PathValue("cve_id"))
	if err != nil {
		writeRepositoryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cve)
}

// handleCreateRepository は登録受付を模したリポジトリ ID とジョブ ID を返す。
// モック接続の段階では本文を利用せず、保存や解析も行わない。
func (h *apiHandler) handleCreateRepository(w http.ResponseWriter, r *http.Request) {
	registration, err := h.repository.GetRepositoryRegistration()
	if err != nil {
		writeRepositoryError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, registration)
}

// handleGetJob は指定されたジョブの処理状態を返す。
func (h *apiHandler) handleGetJob(w http.ResponseWriter, r *http.Request) {
	job, err := h.repository.GetJob(r.PathValue("job_id"))
	if err != nil {
		writeRepositoryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// handleGetRepositoryFeed はリポジトリに関連する CVE 一覧を返す。
func (h *apiHandler) handleGetRepositoryFeed(w http.ResponseWriter, r *http.Request) {
	feed, err := h.repository.GetRepositoryFeed(r.PathValue("repository_id"))
	if err != nil {
		writeRepositoryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, feed)
}

// handleGetRepositoryCVE はリポジトリにおける CVE の詳細・関連性を返す。
func (h *apiHandler) handleGetRepositoryCVE(w http.ResponseWriter, r *http.Request) {
	cve, err := h.repository.GetRepositoryCVE(r.PathValue("repository_id"), r.PathValue("cve_id"))
	if err != nil {
		writeRepositoryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cve)
}

// writeRepositoryError は取得時のエラーを HTTP の状態コードに変換する。
func writeRepositoryError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		http.Error(w, ErrNotFound.Error(), http.StatusNotFound)
		return
	}
	log.Printf("データの取得に失敗しました: %v", err)
	http.Error(w, "データの取得に失敗しました", http.StatusInternalServerError)
}

// writeJSON は JSON への変換が成功してからレスポンスを書き込む。
func writeJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		log.Printf("レスポンスのJSON変換に失敗しました: %v", err)
		http.Error(w, "レスポンスの作成に失敗しました", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write(data); err != nil {
		log.Printf("レスポンス書き込みに失敗しました: %v", err)
	}
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
