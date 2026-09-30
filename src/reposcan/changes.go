package reposcan

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
)

// RetainEvidence carries last-observed NVD evidence into current.RetainedRecords
// for the same repository snapshot. Current observations supersede history; only
// an operationally complete, explicit NVD not_found permits forgetting an absent
// record. Disabled NVD, failed lookups and dropped OSV aliases retain history.
//
// Inputs must be valid reports. Different repository identities leave current
// unchanged. The helper is idempotent, performs no I/O, and mutates neither input:
// retained records are copied, while other current fields are shared unchanged.
// Call it before Changes and emitting a monitor report. Save also applies it when
// advancing an existing baseline, without changing the caller's report.
func RetainEvidence(previous, current Report) Report {
	if previous.Repository != current.Repository {
		return current
	}
	history := recordHistory(previous)
	for key, record := range current.RetainedRecords {
		if _, ok := history[key]; !ok {
			history[key] = record
		}
	}
	absent := nvdAbsences(current)
	current.RetainedRecords = nil
	for key, record := range history {
		if record.Source != "nvd" || absent[record.ID] {
			continue
		}
		if _, observed := current.Records[key]; observed {
			continue
		}
		if current.RetainedRecords == nil {
			current.RetainedRecords = make(map[string]SourceRecord)
		}
		record.Raw = append(json.RawMessage(nil), record.Raw...)
		record.Aliases = append([]string(nil), record.Aliases...)
		current.RetainedRecords[key] = record
	}
	return current
}

func recordHistory(r Report) map[string]SourceRecord {
	records := make(map[string]SourceRecord, len(r.Records)+len(r.RetainedRecords))
	for key, record := range r.RetainedRecords {
		records[key] = record
	}
	for key, record := range r.Records {
		records[key] = record
	}
	return records
}

func nvdAbsences(r Report) map[string]bool {
	if !r.RefreshComplete || r.Acquisition != "complete" {
		return nil
	}
	absent := map[string]bool{}
	for _, e := range r.Enrichment {
		if e.Source != "nvd" {
			continue
		}
		// Preserve the conservative source-wide opt-out rule for mixed results.
		if e.Status == "not_checked" {
			return nil
		}
		if e.Status == "not_found" && e.Error == "" {
			absent[e.ID] = true
		}
	}
	return absent
}

// Changes compares observations, not remediation. Previous retained NVD evidence
// participates in comparisons but is never itself a new current observation.
// Absence is reported only for
// an operationally complete refresh of the same snapshot, never for unchecked
// sources. NVD removal additionally requires an explicit not_found lookup for
// that ID. Query changes ignore scan timestamps.
func Changes(previous, current Report) []Change {
	out := []Change{}
	sameSnapshot := previous.Repository == current.Repository
	canRemove := current.RefreshComplete && current.Acquisition == "complete" && sameSnapshot
	unchecked := map[string]bool{}
	nvdNotFound := nvdAbsences(current)
	for _, e := range current.Enrichment {
		if e.Status == "not_checked" {
			unchecked[e.Source] = true
		}
	}
	previousRecords := recordHistory(previous)
	for key, record := range current.Records {
		old, ok := previousRecords[key]
		kind := ""
		if !ok {
			kind = "added"
		} else if !sameJSON(old.Raw, record.Raw) {
			kind = "modified"
		}
		if kind != "" {
			out = append(out, Change{Kind: kind, Key: key, Source: record.Source, ID: record.ID})
		}
	}
	if canRemove {
		for key, record := range previousRecords {
			if unchecked[record.Source] || (record.Source == "nvd" && !nvdNotFound[record.ID]) {
				continue
			}
			if _, ok := current.Records[key]; !ok {
				out = append(out, Change{Kind: "no_longer_observed", Key: key, Source: record.Source, ID: record.ID})
			}
		}
	}
	oldQueries := map[string]PackageResult{}
	for _, q := range previous.Queries {
		oldQueries[queryKey(q.Query)] = q
	}
	for _, q := range current.Queries {
		k := queryKey(q.Query)
		old, ok := oldQueries[k]
		if !ok || !reflect.DeepEqual(old, q) {
			query := q.Query
			out = append(out, Change{Kind: "query_changed", Key: "query:" + k, Query: &query})
		}
		delete(oldQueries, k)
	}
	if canRemove && !unchecked["osv"] {
		for k, q := range oldQueries {
			query := q.Query
			out = append(out, Change{Kind: "query_changed", Key: "query:" + k, Query: &query})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key == out[j].Key {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func sameJSON(a, b json.RawMessage) bool {
	// Decoding with UseNumber avoids rounding large provider numeric fields.
	if !json.Valid(a) || !json.Valid(b) {
		return false
	}
	var x, y any
	decode := func(raw json.RawMessage, dst *any) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		return d.Decode(dst)
	}
	return decode(a, &x) == nil && decode(b, &y) == nil && reflect.DeepEqual(x, y)
}
