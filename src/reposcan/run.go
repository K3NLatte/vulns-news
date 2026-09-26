package reposcan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/versions"
	"vulns-news/src/nvd"
	"vulns-news/src/osv"
)

var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

type advisory struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Withdrawn string   `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// Run always reissues the package batch. Its caches exist only for this run.
// Configured clients may disclose package identities to their endpoints; no
// network calls are made by Plan, Load, Save or Changes.
func Run(ctx context.Context, profile domain.RepositoryProfile, cfg Config) (r Report) {
	r = Report{Repository: profile.Repository, StartedAt: time.Now().UTC(), Acquisition: "unknown", Status: "incomplete",
		Queries: []PackageResult{}, Unqueried: []UnqueriedComponent{}, Records: map[string]SourceRecord{}, Groups: []AdvisoryGroup{},
		Warnings: append([]string{}, profile.Warnings...), Ecosystems: []EcosystemSummary{}, Enrichment: []EnrichmentResult{}, RuntimeImpact: "unknown"}
	defer func() { r.FinishedAt = time.Now().UTC(); r.Ecosystems = summarize(profile, r) }()
	r.Warnings = append(r.Warnings, "OS and deployment environment unevaluated; runtime impact unknown", "Workspace and dependency path unavailable in repository profile")
	if cfg.NVD == nil {
		r.Warnings = append(r.Warnings, "NVD metadata not checked")
	}
	if !validProfile(profile) {
		r.Warnings = append(r.Warnings, "Invalid profile: repository ID and commit SHA are required")
		for _, c := range profile.Components {
			r.Unqueried = append(r.Unqueried, UnqueriedComponent{Component: c, Reason: "invalid repository profile"})
		}
		return r
	}
	r.Acquisition = "complete"
	r.RefreshComplete = true
	p := Plan(profile)
	r.Unqueried = p.Unqueried
	r.Status = "complete"
	if len(p.Unqueried) > 0 || len(profile.Warnings) > 0 {
		r.Status = "incomplete"
	}
	if ctx == nil {
		ctx = context.Background()
		r.Warnings = append(r.Warnings, "Missing context")
		r.Status = "incomplete"
		r.RefreshComplete = false
	}
	if cfg.NVDInterval < 0 {
		r.Warnings = append(r.Warnings, "NVD interval must not be negative")
		r.Status = "incomplete"
		r.RefreshComplete = false
	}
	input := make([]osv.PackageVersion, len(p.Queries))
	for i, q := range p.Queries {
		input[i] = q.Query
	}
	var results []osv.QueryResult
	if cfg.OSV != nil && len(input) > 0 && ctx.Err() == nil {
		results = cfg.OSV.Query(ctx, input)
	}
	details := map[string]advisory{}
	detailErrors := map[string]error{}
	for i, planned := range p.Queries {
		q := PackageResult{Query: planned.Query, Origins: planned.Origins, Workspace: planned.Workspace, DependencyPath: planned.DependencyPath,
			IDs: []string{}, Matches: []Match{}, Outcome: "unknown", RuntimeImpact: "unknown"}
		switch {
		case cfg.OSV == nil:
			q.Error = "OSV discovery client not configured"
		case len(results) == 0 && ctx.Err() != nil:
			q.Error = ctx.Err().Error()
		case len(results) != len(input):
			q.Error = "OSV query result count mismatch"
		case results[i].Query != planned.Query:
			q.Error = "OSV query identity mismatch"
		default:
			result := results[i]
			q.Complete, q.Error, q.IDs = result.Complete && result.Error == "", result.Error, unique(result.IDs)
			for _, id := range result.IDs {
				if !validText(id) {
					q.Complete = false
					q.Error = joinError(q.Error, "OSV returned invalid advisory ID")
				}
			}
			if !q.Complete && q.Error == "" {
				q.Error = "OSV discovery incomplete"
			}
			for _, id := range q.IDs {
				if !validText(id) {
					continue
				}
				a, loaded := details[id]
				err, failed := detailErrors[id]
				if !loaded && !failed {
					var raw json.RawMessage
					if err = ctx.Err(); err == nil {
						raw, err = cfg.OSV.Advisory(ctx, id)
					}
					if err == nil {
						err = json.Unmarshal(raw, &a)
					}
					if err == nil && (a.ID != id || !validText(id)) {
						err = errors.New("OSV advisory identity mismatch")
					}
					if err != nil {
						detailErrors[id] = err
					} else {
						details[id] = a
						r.Records["osv:"+id] = SourceRecord{Source: "osv", ID: id, Aliases: unique(a.Aliases), Withdrawn: a.Withdrawn != "", Raw: append(json.RawMessage(nil), raw...)}
					}
				}
				if err != nil {
					q.Complete = false
					q.Error = joinError(q.Error, fmt.Sprintf("OSV %s: %v", id, err))
					continue
				}
				m := matchAdvisory(q.Query, a)
				if m.Reason != "" {
					q.Complete = false
					discrepancy := fmt.Sprintf("OSV %s for %s %s@%s: %s", id, q.Query.Ecosystem, q.Query.Name, q.Query.Version, m.Reason)
					q.Error = joinError(q.Error, discrepancy)
					r.Warnings = append(r.Warnings, discrepancy)
				}
				q.Matches = append(q.Matches, m)
				if m.Outcome == "affected_version_match" {
					q.Outcome = m.Outcome
				}
			}
			if len(q.IDs) == 0 && q.Complete {
				q.Outcome = "no_advisory_found"
			}
		}
		if !q.Complete {
			r.Status = "incomplete"
			r.RefreshComplete = false
		}
		r.Queries = append(r.Queries, q)
	}
	enrich(ctx, cfg, &r)
	r.Groups = groupRecords(r.Records)
	if ctx.Err() != nil {
		r.Status = "incomplete"
		r.RefreshComplete = false
		r.Warnings = append(r.Warnings, ctx.Err().Error())
	}
	return r
}

func matchAdvisory(q osv.PackageVersion, a advisory) Match {
	m := Match{RecordKey: "osv:" + a.ID, Outcome: "unknown", FixedVersions: []string{}}
	if a.Withdrawn != "" {
		m.Outcome = "withdrawn"
		return m
	}
	for _, affected := range a.Affected {
		// The exact query supplies version evidence. Details must additionally
		// identify this package; ranges for other packages never supply fixes.
		if affected.Package.Ecosystem != q.Ecosystem || affected.Package.Name != q.Name {
			continue
		}
		m.Outcome = "affected_version_match"
		for _, rg := range affected.Ranges {
			for _, event := range rg.Events {
				if event.Fixed != "" {
					m.FixedVersions = append(m.FixedVersions, event.Fixed)
				}
			}
		}
	}
	m.FixedVersions = unique(m.FixedVersions)
	if m.Outcome == "unknown" {
		m.Reason = "advisory affected packages do not match queried ecosystem/name"
	}
	return m
}

func joinError(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func enrich(ctx context.Context, cfg Config, r *Report) {
	ids := []string{}
	for _, record := range r.Records {
		for _, id := range append([]string{record.ID}, record.Aliases...) {
			if cveID.MatchString(id) {
				ids = append(ids, id)
			}
		}
	}
	for i, id := range unique(ids) {
		result := EnrichmentResult{Source: "nvd", ID: id, Status: "not_checked"}
		if cfg.NVD == nil {
			r.Enrichment = append(r.Enrichment, result)
			continue
		}
		err := ctx.Err()
		if cfg.NVDInterval < 0 {
			err = errors.New("NVD interval must not be negative")
		}
		if err == nil && i > 0 && cfg.NVDInterval > 0 {
			timer := time.NewTimer(cfg.NVDInterval)
			select {
			case <-ctx.Done():
				err = ctx.Err()
			case <-timer.C:
			}
			timer.Stop()
		}
		var raw json.RawMessage
		if err == nil {
			raw, err = cfg.NVD.LookupCVE(ctx, id)
		}
		switch {
		case errors.Is(err, nvd.ErrCVENotFound):
			result.Status = "not_found"
		case err != nil:
			result.Status, result.Error = "error", err.Error()
			r.Status = "incomplete"
			r.RefreshComplete = false
		default:
			var identity struct {
				ID string `json:"id"`
			}
			if err = json.Unmarshal(raw, &identity); err == nil && identity.ID != id {
				err = errors.New("NVD identity mismatch")
			}
			if err != nil {
				result.Status, result.Error = "error", err.Error()
				r.Status = "incomplete"
				r.RefreshComplete = false
			} else {
				result.Status = "found"
				r.Records["nvd:"+id] = SourceRecord{Source: "nvd", ID: id, Aliases: []string{}, Raw: append(json.RawMessage(nil), raw...)}
			}
		}
		r.Enrichment = append(r.Enrichment, result)
	}
}

func groupRecords(records map[string]SourceRecord) []AdvisoryGroup {
	parent := map[string]string{}
	var root func(string) string
	root = func(s string) string {
		p, ok := parent[s]
		if !ok {
			parent[s] = s
			return s
		}
		if p != s {
			parent[s] = root(p)
		}
		return parent[s]
	}
	keys := make([]string, 0, len(records))
	for k := range records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		rec := records[k]
		root(rec.ID)
		for _, alias := range rec.Aliases {
			if validText(alias) {
				a, b := root(rec.ID), root(alias)
				if a != b {
					parent[b] = a
				}
			}
		}
	}
	groups := map[string]*AdvisoryGroup{}
	for _, k := range keys {
		rec := records[k]
		rt := root(rec.ID)
		if groups[rt] == nil {
			groups[rt] = &AdvisoryGroup{RuntimeImpact: "unknown"}
		}
		groups[rt].RecordKeys = append(groups[rt].RecordKeys, k)
	}
	for id := range parent {
		rt := root(id)
		if g := groups[rt]; g != nil {
			g.IDs = append(g.IDs, id)
		}
	}
	out := make([]AdvisoryGroup, 0, len(groups))
	for _, g := range groups {
		sort.Strings(g.IDs)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return strings.Join(out[i].IDs, "\x00") < strings.Join(out[j].IDs, "\x00") })
	return out
}

func summarize(p domain.RepositoryProfile, r Report) []EcosystemSummary {
	sums := map[string]*EcosystemSummary{}
	canonical := func(eco string) string {
		if mapped, ok := versions.OSVEcosystem(eco); ok {
			return mapped
		}
		return eco
	}
	get := func(eco string) *EcosystemSummary {
		eco = canonical(eco)
		if sums[eco] == nil {
			sums[eco] = &EcosystemSummary{Ecosystem: eco, Complete: r.Acquisition == "complete" && len(p.Warnings) == 0}
		}
		return sums[eco]
	}
	for _, e := range p.Ecosystems {
		get(e.Name)
	}
	for _, c := range p.Components {
		get(c.Ecosystem).Components++
	}
	for _, q := range r.Queries {
		s := get(q.Query.Ecosystem)
		s.Queries++
		s.Complete = s.Complete && q.Complete
	}
	for _, u := range r.Unqueried {
		s := get(u.Component.Ecosystem)
		s.Unqueried++
		s.Complete = false
	}
	out := make([]EcosystemSummary, 0, len(sums))
	for _, s := range sums {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ecosystem < out[j].Ecosystem })
	return out
}
