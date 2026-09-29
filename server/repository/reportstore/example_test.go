package reportstore_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"vulns-news/server/repository/reportstore"
)

func ExampleStore() {
	ctx := context.Background()
	store, err := reportstore.Open(ctx, ":memory:")
	if err != nil {
		panic(err)
	}
	defer store.Close()

	// 除外されたスクリーニング結果は、正規化された入力の事実をもとに保存する。
	// 表示用のフィード項目は不要で、存在しない分析結果を補うこともしない。
	input := reportstore.Input{
		ContextKey: reportstore.ContextKey{
			RepositoryID:          "example/service",
			RepositoryCommit:      "abc123",
			VulnerabilityID:       "GHSA-example",
			VulnerabilityRevision: "2026-09-24T12:00:00Z",
		},
		PublishedAt: "2026-09-24T10:00:00Z",
		Status:      reportstore.Screened,
		Relevance:   reportstore.Unrelated,
		Body: json.RawMessage(`{
			"matches": [],
			"screening_reason": "The sample dependency is not installed.",
			"screening_evidence_ids": ["dependency-list"],
			"evidence": [{
				"id": "dependency-list", "kind": "repository_dependency",
				"source": "go.mod", "content": "Dependencies from the example repository."
			}]
		}`),
	}
	created, err := store.Create(ctx, input)
	if err != nil {
		panic(err)
	}
	latest, err := store.GetLatest(ctx, input.ContextKey)
	if err != nil {
		panic(err)
	}
	fmt.Println(latest.Status, latest.Relevance)
	if err := store.Delete(ctx, created.ID); err != nil {
		panic(err)
	}
	_, err = store.Get(ctx, created.ID)
	fmt.Println(errors.Is(err, reportstore.ErrNotFound))
	// Output:
	// screened unrelated
	// true
}
