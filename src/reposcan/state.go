package reposcan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
)

func validateState(s State) error {
	if s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported reposcan schema version %d", s.SchemaVersion)
	}
	if !validProfile(s.Profile) {
		return errors.New("invalid saved profile")
	}
	r := s.Report
	if r.Repository != s.Profile.Repository {
		return errors.New("report and profile snapshot mismatch")
	}
	if r.Acquisition != "complete" || (r.Status != "complete" && r.Status != "incomplete") || r.RuntimeImpact != "unknown" {
		return errors.New("invalid report status")
	}
	if r.StartedAt.IsZero() || r.FinishedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) {
		return errors.New("invalid report timestamps")
	}
	p := Plan(s.Profile)
	if len(p.Queries) != len(r.Queries) || !reflect.DeepEqual(p.Unqueried, r.Unqueried) {
		return errors.New("report does not cover saved profile")
	}
	for i, q := range r.Queries {
		if q.Query != p.Queries[i].Query || !reflect.DeepEqual(q.Origins, p.Queries[i].Origins) || q.RuntimeImpact != "unknown" || q.Workspace != "unavailable" || q.DependencyPath != "unavailable" {
			return errors.New("invalid saved query identity or origins")
		}
		if q.Complete && q.Error != "" {
			return errors.New("complete query has an error")
		}
		if (r.Status == "complete" || r.RefreshComplete) && !q.Complete {
			return errors.New("complete report or refresh contains incomplete query")
		}
		expectedOutcome := "unknown"
		if q.Complete && len(q.IDs) == 0 {
			expectedOutcome = "no_advisory_found"
		}
		expectedMatches := []Match{}
		for _, id := range q.IDs {
			rec, ok := r.Records["osv:"+id]
			if !ok {
				if q.Complete {
					return errors.New("complete query missing source record")
				}
				continue
			}
			var a advisory
			if err := json.Unmarshal(rec.Raw, &a); err != nil {
				return errors.New("invalid OSV raw record")
			}
			expectedMatches = append(expectedMatches, matchAdvisory(q.Query, a))
		}
		if !reflect.DeepEqual(expectedMatches, q.Matches) {
			return errors.New("query evidence differs from raw records")
		}
		for _, m := range q.Matches {
			if m.Reason != "" && (q.Complete || q.Error == "") {
				return errors.New("unreported advisory package discrepancy")
			}
			if m.Outcome == "affected_version_match" {
				expectedOutcome = m.Outcome
			}
		}
		if q.Outcome != expectedOutcome {
			return errors.New("invalid query outcome")
		}
	}
	if r.Status == "complete" && (len(p.Unqueried) > 0 || len(s.Profile.Warnings) > 0) {
		return errors.New("complete report omits profile uncertainty")
	}
	if r.Records == nil {
		return errors.New("missing source records")
	}
	expectedCVEs := map[string]bool{}
	for key, rec := range r.Records {
		if err := validateSourceRecord(key, rec); err != nil {
			return err
		}
		if rec.Source == "osv" {
			if cveID.MatchString(rec.ID) {
				expectedCVEs[rec.ID] = true
			}
			for _, id := range rec.Aliases {
				if cveID.MatchString(id) {
					expectedCVEs[id] = true
				}
			}
		}
	}
	if !reflect.DeepEqual(groupRecords(r.Records), r.Groups) {
		return errors.New("invalid advisory groups")
	}
	enrichment := map[string]string{}
	for _, e := range r.Enrichment {
		if e.Source != "nvd" || !expectedCVEs[e.ID] {
			return errors.New("invalid or unexpected enrichment identity")
		}
		if _, exists := enrichment[e.ID]; exists {
			return errors.New("duplicate enrichment identity")
		}
		enrichment[e.ID] = e.Status
		_, observed := r.Records["nvd:"+e.ID]
		if observed != (e.Status == "found") {
			return errors.New("enrichment status differs from current NVD records")
		}
		switch e.Status {
		case "error":
			if e.Error == "" || r.Status == "complete" || r.RefreshComplete {
				return errors.New("invalid enrichment failure")
			}
		case "found":
			if e.Error != "" {
				return errors.New("invalid enrichment success")
			}
		case "not_found", "not_checked":
			if e.Error != "" {
				return errors.New("invalid enrichment status")
			}
		default:
			return errors.New("invalid enrichment status")
		}
	}
	if len(enrichment) != len(expectedCVEs) {
		return errors.New("missing enrichment results for current OSV CVEs")
	}
	for _, rec := range r.Records {
		if rec.Source == "nvd" && enrichment[rec.ID] != "found" {
			return errors.New("current NVD record without found enrichment")
		}
	}
	absent := nvdAbsences(r)
	for key, rec := range r.RetainedRecords {
		if rec.Source != "nvd" {
			return errors.New("only NVD records may be retained")
		}
		if err := validateSourceRecord(key, rec); err != nil {
			return fmt.Errorf("invalid retained evidence: %w", err)
		}
		if _, observed := r.Records[key]; observed {
			return errors.New("retained evidence duplicates a current record")
		}
		if absent[rec.ID] {
			return errors.New("retained NVD evidence contradicts authoritative absence")
		}
	}
	if !reflect.DeepEqual(summarize(s.Profile, r), r.Ecosystems) {
		return errors.New("invalid ecosystem summaries")
	}
	for _, warning := range s.Profile.Warnings {
		found := false
		for _, w := range r.Warnings {
			if w == warning {
				found = true
				break
			}
		}
		if !found {
			return errors.New("missing profile warning")
		}
	}
	return nil
}

func validateSourceRecord(key string, rec SourceRecord) error {
	if (rec.Source != "osv" && rec.Source != "nvd") || !validText(rec.ID) || key != rec.Source+":"+rec.ID {
		return errors.New("invalid source record key")
	}
	var identity struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Raw, &identity); err != nil || identity.ID != rec.ID {
		return errors.New("invalid raw source record")
	}
	if rec.Source == "osv" {
		var a advisory
		if err := json.Unmarshal(rec.Raw, &a); err != nil || !reflect.DeepEqual(unique(a.Aliases), rec.Aliases) || (a.Withdrawn != "") != rec.Withdrawn {
			return errors.New("source metadata differs from raw record")
		}
	} else if !cveID.MatchString(rec.ID) || len(rec.Aliases) != 0 || rec.Withdrawn {
		return errors.New("invalid NVD record metadata")
	}
	return nil
}

// Load refuses unknown schema versions, malformed/trailing JSON and inconsistent
// snapshots. Unknown fields are refused to avoid silently discarding state data.
func Load(path string) (State, error) {
	var s State
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&s); err != nil {
		return State{}, fmt.Errorf("decode reposcan state: %w", err)
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return State{}, errors.New("trailing state data")
	}
	if err = validateState(s); err != nil {
		return State{}, err
	}
	return s, nil
}

// Save writes a synced 0600 temporary file in the destination directory, then
// renames it atomically. A failed scan may be saved initially, but cannot replace
// an existing baseline. RefreshComplete permits advancement despite persistent
// coverage warnings/unqueried inventory and an incomplete Status. Corrupt or
// different-profile baselines are never replaced. The entire serialized Profile
// must be unchanged, not just its repository identity. Save applies RetainEvidence
// against the existing baseline without mutating the caller's report; callers
// should apply the helper themselves before emitting a report or computing diffs.
// Callers must serialize concurrent writers to the same path.
func Save(path string, s State) error {
	if err := validateState(s); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("state destination is not a regular file")
		}
		old, err := Load(path)
		if err != nil {
			return fmt.Errorf("refuse replacing invalid baseline: %w", err)
		}
		// Compare persisted facts rather than Go-only time internals or empty
		// omitempty slices that do not survive a JSON round trip.
		oldProfile, err := json.Marshal(old.Profile)
		if err != nil {
			return err
		}
		profile, err := json.Marshal(s.Profile)
		if err != nil {
			return err
		}
		if !sameJSON(oldProfile, profile) {
			return errors.New("refuse replacing a different saved profile")
		}
		if !s.Report.RefreshComplete {
			return errors.New("refuse replacing baseline with incomplete refresh")
		}
		s.Report = RetainEvidence(old.Report, s.Report)
		if err := validateState(s); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".reposcan-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(data, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
