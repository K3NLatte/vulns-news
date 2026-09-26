package reposcan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/nvd"
	"vulns-news/src/osv"
)

const retentionKey = "nvd:CVE-2026-12345"

func retentionNVD() fakeNVD {
	return func(_ context.Context, id string) (json.RawMessage, error) {
		return json.RawMessage(`{"id":"` + id + `","unknown":{"large":9007199254740993}}`), nil
	}
}

func retentionWithoutAlias() fakeOSV {
	f := positiveOSV()
	f.detail = func(context.Context, string) (json.RawMessage, error) {
		return json.RawMessage(strings.Replace(rawAdvisory, `"aliases":["CVE-2026-12345"]`, `"aliases":[]`, 1)), nil
	}
	return f
}

func retentionState(p domain.RepositoryProfile, r Report) State {
	return State{SchemaVersion: SchemaVersion, Profile: p, Report: r}
}

func assertRetentionChange(t *testing.T, changes []Change, want string) {
	t.Helper()
	var kinds []string
	for _, change := range changes {
		if change.Key == retentionKey {
			kinds = append(kinds, change.Kind)
		}
	}
	if want == "" && len(kinds) != 0 || want != "" && !reflect.DeepEqual(kinds, []string{want}) {
		t.Fatalf("NVD changes = %v, want %q; all changes: %+v", kinds, want, changes)
	}
}

func TestStateRetentionUncheckedTransitions(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"disabled", Config{OSV: positiveOSV()}},
		{"alias_removed", Config{OSV: retentionWithoutAlias(), NVD: retentionNVD()}},
		{"osv_absent", Config{OSV: emptyOSV(), NVD: retentionNVD()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profile()
			initial := Run(context.Background(), p, Config{OSV: positiveOSV(), NVD: retentionNVD()})
			path := filepath.Join(t.TempDir(), "state.json")
			if err := Save(path, retentionState(p, initial)); err != nil {
				t.Fatal(err)
			}
			previous := initial
			for i := 0; i < 2; i++ {
				current := Run(context.Background(), p, tc.cfg)
				prepared := RetainEvidence(previous, current)
				if !prepared.RefreshComplete || len(prepared.RetainedRecords) != 1 || !sameJSON(prepared.RetainedRecords[retentionKey].Raw, initial.Records[retentionKey].Raw) {
					t.Fatalf("lost historical evidence: %+v", prepared)
				}
				if _, ok := prepared.Records[retentionKey]; ok {
					t.Fatal("historical NVD evidence became a current observation")
				}
				withoutHistory := prepared
				withoutHistory.RetainedRecords = nil
				if !reflect.DeepEqual(withoutHistory, current) {
					t.Fatal("retention changed current observations, groups or completeness")
				}
				if !reflect.DeepEqual(prepared, RetainEvidence(previous, prepared)) {
					t.Fatal("retention is not idempotent")
				}
				assertRetentionChange(t, Changes(previous, prepared), "")
				// API users need not prepare retention themselves before saving.
				if err := Save(path, retentionState(p, current)); err != nil {
					t.Fatal(err)
				}
				if len(current.RetainedRecords) != 0 {
					t.Fatal("Save mutated the caller's report")
				}
				saved, err := Load(path)
				if err != nil {
					t.Fatal(err)
				}
				want, _ := json.Marshal(prepared)
				got, _ := json.Marshal(saved.Report)
				if !sameJSON(want, got) {
					t.Fatal("Save retention differs from the public helper")
				}
				previous = saved.Report
			}

			reenabled := Run(context.Background(), p, Config{OSV: positiveOSV(), NVD: retentionNVD()})
			assertRetentionChange(t, Changes(previous, reenabled), "")
			reenabled = RetainEvidence(previous, reenabled)
			if len(reenabled.RetainedRecords) != 0 || len(reenabled.Records) != 2 {
				t.Fatal("fresh observation did not supersede retained evidence")
			}
			assertRetentionChange(t, Changes(previous, reenabled), "")
			modified := reenabled
			modified.Records = recordHistory(reenabled)
			record := modified.Records[retentionKey]
			record.Raw = json.RawMessage(strings.Replace(string(record.Raw), "9007199254740993", "9007199254740992", 1))
			modified.Records[retentionKey] = record
			assertRetentionChange(t, Changes(previous, modified), "modified")
			if err := Save(path, retentionState(p, reenabled)); err != nil {
				t.Fatal(err)
			}
			saved, err := Load(path)
			if err != nil || len(saved.Report.RetainedRecords) != 0 {
				t.Fatalf("superseded history survived Save: %+v, %v", saved.Report, err)
			}
		})
	}
}

func TestStateRetentionAuthoritativeAbsence(t *testing.T) {
	p := profile()
	initial := Run(context.Background(), p, Config{OSV: positiveOSV(), NVD: retentionNVD()})
	previous := RetainEvidence(initial, Run(context.Background(), p, Config{OSV: positiveOSV()}))
	missing := fakeNVD(func(context.Context, string) (json.RawMessage, error) { return nil, nvd.ErrCVENotFound })
	current := Run(context.Background(), p, Config{OSV: positiveOSV(), NVD: missing})

	incomplete := current
	incomplete.RefreshComplete, incomplete.Status = false, "incomplete"
	incomplete = RetainEvidence(previous, incomplete)
	if len(incomplete.RetainedRecords) != 1 {
		t.Fatal("incomplete refresh discarded history")
	}
	assertRetentionChange(t, Changes(previous, incomplete), "")
	if err := validateState(retentionState(p, incomplete)); err != nil {
		t.Fatal("incomplete report with history must remain inspectable:", err)
	}

	failed := Run(context.Background(), p, Config{OSV: positiveOSV(), NVD: fakeNVD(func(context.Context, string) (json.RawMessage, error) {
		return nil, errors.New("HTTP 503")
	})})
	failed = RetainEvidence(previous, failed)
	if len(failed.RetainedRecords) != 1 || failed.Enrichment[0].Status != "error" {
		t.Fatal("failed lookup lost history or failure evidence")
	}
	if err := validateState(retentionState(p, failed)); err != nil {
		t.Fatal(err)
	}
	assertRetentionChange(t, Changes(previous, failed), "")

	prepared := RetainEvidence(previous, current)
	if len(prepared.RetainedRecords) != 0 {
		t.Fatal("authoritative not_found did not remove history")
	}
	assertRetentionChange(t, Changes(previous, prepared), "no_longer_observed")
	assertRetentionChange(t, Changes(initial, prepared), "no_longer_observed")
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, retentionState(p, previous)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	for _, r := range []Report{incomplete, failed} {
		if err := Save(path, retentionState(p, r)); err == nil {
			t.Fatal("failed refresh replaced baseline")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("failed refresh changed baseline bytes")
		}
	}
	if err := Save(path, retentionState(p, current)); err != nil {
		t.Fatal(err)
	}
	saved, err := Load(path)
	if err != nil || len(saved.Report.RetainedRecords) != 0 {
		t.Fatalf("Save did not honor authoritative absence: %+v, %v", saved.Report, err)
	}
	assertRetentionChange(t, Changes(saved.Report, current), "")
	assertRetentionChange(t, Changes(saved.Report, initial), "added")
}

func TestRetainEvidenceOwnershipAndSnapshot(t *testing.T) {
	p := profile()
	previous := Run(context.Background(), p, Config{OSV: positiveOSV(), NVD: retentionNVD()})
	current := Run(context.Background(), p, Config{OSV: positiveOSV()})
	prepared := RetainEvidence(previous, current)
	copied := RetainEvidence(previous, prepared)
	copied.RetainedRecords[retentionKey].Raw[0] = '!'
	delete(copied.RetainedRecords, retentionKey)
	if !json.Valid(previous.Records[retentionKey].Raw) || !json.Valid(prepared.RetainedRecords[retentionKey].Raw) || len(current.RetainedRecords) != 0 {
		t.Fatal("helper mutated an input's map or raw JSON")
	}
	previous.Repository.CommitSHA = "another-commit"
	if got := RetainEvidence(previous, current); !reflect.DeepEqual(got, current) {
		t.Fatal("history crossed repository snapshots")
	}
}

func TestStateRetentionRejectsMalformedEvidenceAndEnrichment(t *testing.T) {
	p := profile()
	initial := Run(context.Background(), p, Config{OSV: positiveOSV(), NVD: retentionNVD()})
	for _, tc := range []struct {
		name   string
		mutate func(*Report)
	}{
		{"missing_enrichment", func(r *Report) { r.Enrichment = nil }},
		{"duplicate_enrichment", func(r *Report) { r.Enrichment = append(r.Enrichment, r.Enrichment[0]) }},
		{"contradictory_duplicate", func(r *Report) {
			r.Enrichment = append(r.Enrichment, EnrichmentResult{Source: "nvd", ID: "CVE-2026-12345", Status: "not_found"})
		}},
		{"unexpected_enrichment", func(r *Report) {
			r.Enrichment = append(r.Enrichment, EnrichmentResult{Source: "nvd", ID: "CVE-2026-99999", Status: "not_checked"})
		}},
		{"wrong_enrichment_source", func(r *Report) { r.Enrichment[0].Source = "osv" }},
		{"unknown_enrichment_status", func(r *Report) { r.Enrichment[0].Status = "safe" }},
		{"found_with_error", func(r *Report) { r.Enrichment[0].Error = "HTTP 503" }},
		{"found_without_record", func(r *Report) { delete(r.Records, retentionKey) }},
		{"not_found_with_record", func(r *Report) { r.Enrichment[0].Status = "not_found" }},
		{"not_checked_with_record", func(r *Report) { r.Enrichment[0].Status = "not_checked" }},
		{"error_with_record", func(r *Report) {
			r.Enrichment[0].Status, r.Enrichment[0].Error = "error", "HTTP 503"
			r.RefreshComplete, r.Status = false, "incomplete"
		}},
		{"orphan_current_nvd", func(r *Report) {
			*r = Run(context.Background(), p, Config{OSV: retentionWithoutAlias()})
			r.Records[retentionKey] = initial.Records[retentionKey]
		}},
		{"retained_and_current", func(r *Report) { r.RetainedRecords = map[string]SourceRecord{retentionKey: r.Records[retentionKey]} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Run(context.Background(), p, Config{OSV: positiveOSV(), NVD: retentionNVD()})
			tc.mutate(&r)
			r.Groups = groupRecords(r.Records)
			assertRetentionInvalidState(t, retentionState(p, r))
		})
	}

	for _, tc := range []struct {
		name   string
		mutate func(*Report)
	}{
		{"null_raw", func(r *Report) {
			rec := r.RetainedRecords[retentionKey]
			rec.Raw = json.RawMessage(`null`)
			r.RetainedRecords[retentionKey] = rec
		}},
		{"wrong_raw_identity", func(r *Report) {
			rec := r.RetainedRecords[retentionKey]
			rec.Raw = json.RawMessage(`{"id":"CVE-2026-99999"}`)
			r.RetainedRecords[retentionKey] = rec
		}},
		{"wrong_key", func(r *Report) {
			r.RetainedRecords["nvd:wrong"] = r.RetainedRecords[retentionKey]
			delete(r.RetainedRecords, retentionKey)
		}},
		{"wrong_id", func(r *Report) {
			rec := r.RetainedRecords[retentionKey]
			rec.ID = "not-a-CVE"
			r.RetainedRecords = map[string]SourceRecord{"nvd:not-a-CVE": rec}
		}},
		{"aliases", func(r *Report) {
			rec := r.RetainedRecords[retentionKey]
			rec.Aliases = []string{"GHSA-example"}
			r.RetainedRecords[retentionKey] = rec
		}},
		{"withdrawn", func(r *Report) {
			rec := r.RetainedRecords[retentionKey]
			rec.Withdrawn = true
			r.RetainedRecords[retentionKey] = rec
		}},
		{"osv_history", func(r *Report) { r.RetainedRecords["osv:GHSA-example"] = initial.Records["osv:GHSA-example"] }},
		{"authoritative_absence", func(r *Report) { r.Enrichment[0].Status = "not_found" }},
		{"historical_only_enrichment", func(r *Report) {
			*r = RetainEvidence(initial, Run(context.Background(), p, Config{OSV: retentionWithoutAlias()}))
			r.Enrichment = []EnrichmentResult{{Source: "nvd", ID: "CVE-2026-12345", Status: "not_checked"}}
		}},
	} {
		t.Run("retained_"+tc.name, func(t *testing.T) {
			r := RetainEvidence(initial, Run(context.Background(), p, Config{OSV: positiveOSV()}))
			tc.mutate(&r)
			assertRetentionInvalidState(t, retentionState(p, r))
		})
	}
}

func assertRetentionInvalidState(t *testing.T, s State) {
	t.Helper()
	if err := validateState(s); err == nil {
		t.Fatal("accepted inconsistent evidence")
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, s); err == nil {
		t.Fatal("Save accepted inconsistent evidence")
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted inconsistent evidence")
	}
}

func TestStateEnrichmentAccountsForCurrentOSVIDsAndAliases(t *testing.T) {
	p := profile()
	f := positiveOSV()
	f.query = func(_ context.Context, qs []osv.PackageVersion) []osv.QueryResult {
		return []osv.QueryResult{{Query: qs[0], Complete: true, IDs: []string{"CVE-2026-12345"}}}
	}
	f.detail = func(context.Context, string) (json.RawMessage, error) {
		return json.RawMessage(`{"id":"CVE-2026-12345","aliases":["CVE-2026-12345","CVE-2026-99999","GHSA-example"],"affected":[{"package":{"ecosystem":"npm","name":"pkg"}}]}`), nil
	}
	r := Run(context.Background(), p, Config{OSV: f})
	if len(r.Enrichment) != 2 {
		t.Fatalf("expected unique CVE accounting for record ID and aliases: %+v", r.Enrichment)
	}
	if err := validateState(retentionState(p, r)); err != nil {
		t.Fatal(err)
	}
	f.detail = func(context.Context, string) (json.RawMessage, error) { return nil, errors.New("detail failed") }
	r = Run(context.Background(), p, Config{OSV: f})
	if r.RefreshComplete || len(r.Enrichment) != 0 {
		t.Fatal("unfetched OSV detail invented enrichment")
	}
	if err := validateState(retentionState(p, r)); err != nil {
		t.Fatal("failed detail without current OSV record must remain inspectable:", err)
	}
}

func TestStateRetentionRequiresImmutableFullProfile(t *testing.T) {
	p := profile()
	p.ProfiledAt = time.Now().UTC()
	p.Languages = []domain.LanguageUsage{{Name: "JavaScript", SourcePaths: []string{"index.js"}}}
	p.Ecosystems = []domain.EcosystemUsage{{Name: "npm", Lockfiles: []string{"package-lock.json"}}}
	p.Products = []domain.ProductCandidate{{ID: "product", Name: "nginx"}}
	p.Containers = []domain.ContainerReference{{ID: "container", Image: "app", Tag: "1"}}
	p.Infrastructure = []domain.InfrastructureAsset{{ID: "infra", Kind: "database", Product: "postgres"}}
	p.SourceObservations = []domain.SourceObservation{{Kind: "import", File: "index.js", Line: 1, Package: "pkg"}}
	p.Warnings = []string{"partial inventory"}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, retentionState(p, Run(context.Background(), p, Config{OSV: emptyOSV()}))); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	for _, tc := range []struct {
		name   string
		mutate func(*domain.RepositoryProfile)
	}{
		{"inventory_removed", func(p *domain.RepositoryProfile) { p.Components = nil }},
		{"version", func(p *domain.RepositoryProfile) { p.Components[0].Version = "2.0.0" }},
		{"origin", func(p *domain.RepositoryProfile) { p.Components[0].SourcePath = "other/package-lock.json" }},
		{"scope", func(p *domain.RepositoryProfile) { p.Components[0].Scope = "development" }},
		{"repository", func(p *domain.RepositoryProfile) { p.Repository.ID = "another" }},
		{"timestamp", func(p *domain.RepositoryProfile) { p.ProfiledAt = p.ProfiledAt.Add(time.Second) }},
		{"languages", func(p *domain.RepositoryProfile) { p.Languages[0].SourcePaths = []string{"other.js"} }},
		{"ecosystems", func(p *domain.RepositoryProfile) { p.Ecosystems[0].Lockfiles = nil }},
		{"products", func(p *domain.RepositoryProfile) { p.Products[0].Name = "apache" }},
		{"containers", func(p *domain.RepositoryProfile) { p.Containers[0].Tag = "2" }},
		{"infrastructure", func(p *domain.RepositoryProfile) { p.Infrastructure[0].Product = "mysql" }},
		{"source_observations", func(p *domain.RepositoryProfile) { p.SourceObservations[0].Line = 2 }},
		{"warnings", func(p *domain.RepositoryProfile) { p.Warnings = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&saved.Profile)
			saved.Report = Run(context.Background(), saved.Profile, Config{OSV: emptyOSV()})
			if err := validateState(saved); err != nil {
				t.Fatal("test must use an otherwise-valid new profile/report:", err)
			}
			if err := Save(path, saved); err == nil || !strings.Contains(err.Error(), "different saved profile") {
				t.Fatalf("changed profile replacement error = %v", err)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("refused replacement modified baseline")
			}
		})
	}
}

func TestStateProfileEqualityUsesPersistedFacts(t *testing.T) {
	p := profile()
	p.ProfiledAt = time.Now()
	p.Warnings = []string{}
	p.SourceObservations = []domain.SourceObservation{}
	s := retentionState(p, Run(context.Background(), p, Config{OSV: emptyOSV()}))
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, s); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, s); err != nil {
		t.Fatal("JSON round trip changed profile equality:", err)
	}
}
