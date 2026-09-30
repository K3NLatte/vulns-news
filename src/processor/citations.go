package processor

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"vulns-news/src/llm"
)

// Only semantic citation errors can trigger another model call. JSON/schema,
// input-validation and transport errors must not become retry loops.
type citationError struct {
	message string
}

func (e *citationError) Error() string { return e.message }

const citationCorrection = `前回の応答は根拠の引用検証に失敗し、採用されませんでした。元の分析材料からJSON全体を再生成してください。
引用配列には許可一覧のEVD-で始まるIDだけを完全一致で引用し、CVE/GHSA/RUSTSEC番号やURLを使用しないでください。
Screeningではadvisory_evidence_idsにnvd/advisoryだけ、repository_evidence_idsにrepository_dependency/repository_source/static_analysisだけを引用してください。unknown以外は両側が必要で、unknownでも全体で最低1件の実在する引用が必要です。
詳細分析では引き続き各主張のevidence_idsを使用してください。
引用を通すために判定をrelatedやunknownへ変えたり、根拠を創作したりしないでください。`

// IDs and kinds have already passed prepareInput's allowlists. Do not include
// arbitrary source strings, advisory content or generated text in this catalog.
func evidenceCatalog(evidence []Evidence) string {
	var catalog strings.Builder
	catalog.WriteString("\n\n許可されたEvidence ID一覧（ID / kind）:\n")
	for _, item := range evidence {
		fmt.Fprintf(&catalog, "- %s / %s\n", item.ID, item.Kind)
	}
	return catalog.String()
}

func (p *Processor) generateWithCitationRetry(ctx context.Context, request llm.ChatRequest, stage string, validate func(string) error) (response llm.ChatResponse, retries int, err error) {
	defer func() {
		if err != nil && retries > 0 {
			err = fmt.Errorf("after one citation correction retry: %w", err)
		}
	}()
	var usage llm.ChatResponse
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return llm.ChatResponse{}, attempt, fmt.Errorf("run LLM %s: %w", stage, err)
		}
		response, err := p.generator.Chat(ctx, request)
		if err != nil {
			return llm.ChatResponse{}, attempt, fmt.Errorf("run LLM %s: %w", stage, err)
		}
		if err := ctx.Err(); err != nil {
			return llm.ChatResponse{}, attempt, fmt.Errorf("run LLM %s: %w", stage, err)
		}
		usage.PromptTokens += response.PromptTokens
		usage.CompletionTokens += response.CompletionTokens
		usage.TotalDuration += response.TotalDuration
		usage.LoadDuration += response.LoadDuration
		err = validate(response.Content)
		if err == nil {
			response.PromptTokens = usage.PromptTokens
			response.CompletionTokens = usage.CompletionTokens
			response.TotalDuration = usage.TotalDuration
			response.LoadDuration = usage.LoadDuration
			return response, attempt, nil
		}
		var citation *citationError
		if attempt == 1 || !errors.As(err, &citation) {
			return llm.ChatResponse{}, attempt, err
		}
		// A fresh attempt uses the same evidence, not a guessed ID substitution.
		// Never promote the rejected model response/error into system instructions.
		request.Messages = append([]llm.Message(nil), request.Messages...)
		request.Messages[0].Content += "\n\n" + citationCorrection
	}
}
