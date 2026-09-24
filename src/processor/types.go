package processor

import "vulns-news/src/domain"

// Relevance is the first-stage relationship between a repository and a CVE.
type Relevance string

const (
	RelevanceRelated         Relevance = "related"
	RelevancePossiblyRelated Relevance = "possibly_related"
	RelevanceUnrelated       Relevance = "unrelated"
	RelevanceUnknown         Relevance = "unknown"
)

// EvidenceKind describes how Go obtained a piece of evidence. Restricting this
// value allows the processor to reject semantically incompatible citations.
type EvidenceKind string

const (
	EvidenceNVD                  EvidenceKind = "nvd"
	EvidenceAdvisory             EvidenceKind = "advisory"
	EvidenceRepositoryDependency EvidenceKind = "repository_dependency"
	EvidenceRepositorySource     EvidenceKind = "repository_source"
	EvidenceStaticAnalysis       EvidenceKind = "static_analysis"
	EvidencePoCCandidate         EvidenceKind = "poc_candidate"
	EvidencePoCVerified          EvidenceKind = "poc_verified"
	EvidenceExploit              EvidenceKind = "exploit"
	EvidenceCISAKEV              EvidenceKind = "cisa_kev"
	EvidenceExploitation         EvidenceKind = "exploitation"
	EvidencePatch                EvidenceKind = "patch"
	EvidenceCommit               EvidenceKind = "commit"
	EvidenceRelease              EvidenceKind = "release"
)

// Evidence is factual material collected and assigned an immutable ID by Go.
// The model may cite an ID but cannot create new evidence.
type Evidence struct {
	ID      string       `json:"id"`
	Kind    EvidenceKind `json:"kind"`
	Source  string       `json:"source"`
	URI     string       `json:"uri,omitempty"`
	Content string       `json:"content"`
}

// Input contains only typed, backend-owned facts. Candidate must have been
// created by the deterministic matcher before the LLM processor is called.
type Input struct {
	Vulnerability domain.NormalizedVulnerability `json:"vulnerability"`
	Repository    domain.RepositoryProfile       `json:"repository"`
	Candidate     domain.MatchCandidate          `json:"candidate"`
	Evidence      []Evidence                     `json:"evidence"`
}

// ScreeningResult is the lightweight result saved for every candidate CVE.
// It is an LLM proposal and must not replace Go-owned facts.
type ScreeningResult struct {
	Relevance   Relevance `json:"relevance"`
	Reason      string    `json:"reason"`
	EvidenceIDs []string  `json:"evidence_ids"`
}

// SupportedClaim is generated interpretation linked to Go-owned evidence.
type SupportedClaim struct {
	Text        string   `json:"text"`
	EvidenceIDs []string `json:"evidence_ids"`
}

// DeepAnalysis explains confirmed backend facts in repository context, then
// states what remains unknown and what a human should do next. It does not
// assign model-generated confidence, reachability, or risk scores.
type DeepAnalysis struct {
	Summary            SupportedClaim `json:"summary"`
	RepositoryImpact   SupportedClaim `json:"repository_impact"`
	MissingInformation []string       `json:"missing_information"`
	RecommendedActions []string       `json:"recommended_actions"`
}

// Generation records model metadata needed for observability and LLM history.
type Generation struct {
	Model            string `json:"model"`
	DoneReason       string `json:"done_reason"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	TotalDurationNS  int64  `json:"total_duration_ns"`
	LoadDurationNS   int64  `json:"load_duration_ns"`
}

// ScreeningOutput combines a validated screening result with generation data.
type ScreeningOutput struct {
	Result     ScreeningResult `json:"result"`
	Generation Generation      `json:"generation"`
}

// AnalysisOutput combines a validated deep analysis with generation data.
type AnalysisOutput struct {
	Analysis   DeepAnalysis `json:"analysis"`
	Generation Generation   `json:"generation"`
}
