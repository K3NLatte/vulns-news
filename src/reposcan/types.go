// Package reposcan discovers advisories for an immutable repository profile.
// It never clones repositories, executes repository code, or evaluates runtime
// exploitability. Monitoring calls Run again with State.Profile: every package
// batch is rechecked, including previous empty results. This is not an upstream
// delta feed and does not discover dependency changes after the saved commit.
package reposcan

import (
	"context"
	"encoding/json"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/osv"
)

const SchemaVersion = 1

type Config struct {
	OSV interface {
		Query(context.Context, []osv.PackageVersion) []osv.QueryResult
		Advisory(context.Context, string) (json.RawMessage, error)
	}
	NVD interface {
		LookupCVE(context.Context, string) (json.RawMessage, error)
	}
	NVDInterval time.Duration
}

type PlannedQuery struct {
	Query          osv.PackageVersion `json:"query"`
	Origins        []domain.Component `json:"origins"`
	Workspace      string             `json:"workspace"`
	DependencyPath string             `json:"dependency_path"`
}

type UnqueriedComponent struct {
	Component domain.Component `json:"component"`
	Reason    string           `json:"reason"`
}

type PlanReport struct {
	Queries   []PlannedQuery       `json:"queries"`
	Unqueried []UnqueriedComponent `json:"unqueried"`
}

// Match is evidence from an exact OSV query, not a local range evaluation.
// FixedVersions are provider-reported boundaries, not upgrade recommendations.
type Match struct {
	RecordKey     string   `json:"record_key"`
	Outcome       string   `json:"outcome"`
	Reason        string   `json:"reason,omitempty"`
	FixedVersions []string `json:"fixed_versions"`
}

type PackageResult struct {
	Query          osv.PackageVersion `json:"query"`
	Origins        []domain.Component `json:"origins"`
	Workspace      string             `json:"workspace"`
	DependencyPath string             `json:"dependency_path"`
	Complete       bool               `json:"complete"`
	Error          string             `json:"error,omitempty"`
	Outcome        string             `json:"outcome"`
	IDs            []string           `json:"ids"`
	Matches        []Match            `json:"matches"`
	RuntimeImpact  string             `json:"runtime_impact"`
}

type SourceRecord struct {
	Source    string          `json:"source"`
	ID        string          `json:"id"`
	Aliases   []string        `json:"aliases"`
	Withdrawn bool            `json:"withdrawn"`
	Raw       json.RawMessage `json:"raw"`
}

type AdvisoryGroup struct {
	IDs           []string `json:"ids"`
	RecordKeys    []string `json:"record_keys"`
	RuntimeImpact string   `json:"runtime_impact"`
}

type EnrichmentResult struct {
	Source string `json:"source"`
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type EcosystemSummary struct {
	Ecosystem  string `json:"ecosystem"`
	Components int    `json:"components"`
	Queries    int    `json:"queries"`
	Unqueried  int    `json:"unqueried"`
	Complete   bool   `json:"complete"`
}

type Report struct {
	Repository  domain.RepositoryIdentity `json:"repository"`
	StartedAt   time.Time                 `json:"started_at"`
	FinishedAt  time.Time                 `json:"finished_at"`
	Acquisition string                    `json:"acquisition"`
	Status      string                    `json:"status"`
	// RefreshComplete tracks operational success, independently of inventory
	// coverage warnings and unqueried components. Unchecked optional sources
	// do not fail a refresh, but cannot supply evidence of record removal.
	RefreshComplete bool                    `json:"refresh_complete"`
	Queries         []PackageResult         `json:"queries"`
	Unqueried       []UnqueriedComponent    `json:"unqueried"`
	Records         map[string]SourceRecord `json:"records"`
	// RetainedRecords holds historical NVD evidence not observed in this run.
	// It is disjoint from Records and never contributes to current groups,
	// matches, enrichment accounting, or completeness.
	RetainedRecords map[string]SourceRecord `json:"retained_records,omitempty"`
	Groups          []AdvisoryGroup         `json:"groups"`
	Warnings        []string                `json:"warnings"`
	Ecosystems      []EcosystemSummary      `json:"ecosystems"`
	Enrichment      []EnrichmentResult      `json:"enrichment"`
	RuntimeImpact   string                  `json:"runtime_impact"`
}

type State struct {
	SchemaVersion int                      `json:"schema_version"`
	Profile       domain.RepositoryProfile `json:"profile"`
	Report        Report                   `json:"report"`
}

type Change struct {
	Kind   string              `json:"kind"`
	Key    string              `json:"key"`
	Source string              `json:"source,omitempty"`
	ID     string              `json:"id,omitempty"`
	Query  *osv.PackageVersion `json:"query,omitempty"`
}
