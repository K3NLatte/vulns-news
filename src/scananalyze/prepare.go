// Package scananalyze bridges saved repository discovery evidence to analysis.
package scananalyze

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/versions"
	"vulns-news/src/osv"
	"vulns-news/src/processor"
	"vulns-news/src/reposcan"
)

// Prepared is one alias group with positive, exact-version OSV query evidence.
// An entry with Error must not be submitted to the processor.
type Prepared struct {
	ID            string          `json:"id"`
	IDs           []string        `json:"ids"`
	RecordKeys    []string        `json:"record_keys"`
	AdvisoryKinds []string        `json:"advisory_kinds"`
	Input         processor.Input `json:"input"`
	Error         string          `json:"error,omitempty"`
}

var realCVE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

const dependencyContext = "Only matched dependency evidence is submitted, not a complete repository profile. No feature usage, code reachability, runtime configuration, or exploitability is proven. Unrelated components, products, containers, infrastructure, languages, ecosystems, and source observations are omitted; the original profile and full raw records remain in the saved state."
const advisoryKindContext = "OSV advisory kinds are source-provided informational classifications, including maintenance notices. An unknown kind does not mean vulnerability. An affected_version_match establishes only an exact query hit, not that the advisory describes an exploitable vulnerability."
const versionContext = "OSV constraints represent only exact queried versions, not inferred affected ranges. Fixed versions are provider-reported boundaries, not verified upgrade recommendations."
const sourceApplicabilityContext = "OSV affected entries are untrusted source applicability restrictions, not observed repository usage, reachability, or runtime facts. Entries are limited to this alias group's queried ecosystem/name identities; source ranges do not expand exact-version query evidence. Full raw records remain in saved state."

// Prepare consumes a snapshot loaded through reposcan.Load. It performs no I/O,
// requery, CPE inference, or local range expansion. Additional preparation checks
// fail closed per group; malformed orphan hits are returned as error entries.
// Full scan warning lists remain in state and are summarized by count. The
// processor's existing material and evidence limits still apply; matched origins
// and query evidence are never truncated to fit those limits.
func Prepare(state reposcan.State) []Prepared {
	hits := map[string][]int{}
	var inconsistentQueries []int
	for i, q := range state.Report.Queries {
		positive := false
		for _, m := range q.Matches {
			if m.Outcome == "affected_version_match" {
				hits[m.RecordKey] = append(hits[m.RecordKey], i)
				positive = true
			}
		}
		if q.Outcome == "affected_version_match" && !positive {
			inconsistentQueries = append(inconsistentQueries, i)
		}
	}

	membership := map[string]int{}
	for _, group := range state.Report.Groups {
		for _, key := range group.RecordKeys {
			membership[key]++
		}
	}
	planned := map[osv.PackageVersion]reposcan.PlannedQuery{}
	if len(hits) > 0 {
		for _, q := range reposcan.Plan(state.Profile).Queries {
			planned[q.Query] = q
		}
	}
	componentCounts := map[string]int{}
	for _, c := range state.Profile.Components {
		componentCounts[c.ID]++
	}

	out := []Prepared{}
	for _, group := range state.Report.Groups {
		indices := map[int]bool{}
		matchingIDs := []string{}
		for _, key := range group.RecordKeys {
			for _, i := range hits[key] {
				indices[i] = true
			}
			if len(hits[key]) > 0 && state.Report.Records[key].Source == "osv" {
				matchingIDs = append(matchingIDs, state.Report.Records[key].ID)
			}
		}
		if len(indices) == 0 {
			continue
		}
		p := Prepared{IDs: sortedUnique(group.IDs), RecordKeys: sortedUnique(group.RecordKeys), AdvisoryKinds: []string{}}
		for _, id := range p.IDs {
			if realCVE.MatchString(id) {
				p.ID = id
				break
			}
		}
		if p.ID == "" {
			if ids := sortedUnique(matchingIDs); len(ids) > 0 {
				p.ID = ids[0]
			}
		}
		input, kinds, err := prepareGroup(state, p, indices, planned, componentCounts, membership)
		if err == nil {
			// Reuse the processor's input checks and limits without a model call.
			err = processor.ValidateOutputs(input, nil, nil)
		}
		if err != nil {
			p.Error = err.Error()
		} else {
			p.Input, p.AdvisoryKinds = input, kinds
		}
		out = append(out, p)
	}
	for _, key := range sortedMapKeys(hits) {
		if membership[key] == 0 {
			out = append(out, Prepared{RecordKeys: []string{key}, Error: fmt.Sprintf("affected query record %q has no current advisory group", key)})
		}
	}
	for _, i := range inconsistentQueries {
		out = append(out, Prepared{Error: fmt.Sprintf("query %d claims an affected version without matching evidence", i)})
	}
	if err := preparationSnapshotError(state); err != nil {
		if len(out) == 0 {
			out = append(out, Prepared{})
		}
		for i := range out {
			out[i].Error = err.Error()
			out[i].Input = processor.Input{}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return strings.Join(out[i].RecordKeys, "\x00") < strings.Join(out[j].RecordKeys, "\x00")
	})
	return out
}

func preparationSnapshotError(s reposcan.State) error {
	r := s.Profile.Repository
	if s.SchemaVersion != reposcan.SchemaVersion || s.Report.Repository != r {
		return fmt.Errorf("invalid schema or report/profile snapshot mismatch; load a validated reposcan state")
	}
	if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.CommitSHA) == "" || strings.TrimSpace(r.CanonicalURL) == "" {
		return fmt.Errorf("analysis requires repository ID, canonical URL, and commit SHA")
	}
	if s.Report.Acquisition != "complete" || (s.Report.Status != "complete" && s.Report.Status != "incomplete") || s.Report.RuntimeImpact != "unknown" {
		return fmt.Errorf("invalid repository scan status")
	}
	return nil
}

type savedOSV struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Withdrawn string   `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		DatabaseSpecific struct {
			Informational json.RawMessage `json:"informational"`
		} `json:"database_specific"`
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

func prepareGroup(s reposcan.State, p Prepared, indices map[int]bool, planned map[osv.PackageVersion]reposcan.PlannedQuery, counts, membership map[string]int) (processor.Input, []string, error) {
	in := processor.Input{
		Repository: domain.RepositoryProfile{
			Repository: s.Profile.Repository, ProfiledAt: s.Profile.ProfiledAt,
			Components: []domain.Component{},
			Warnings:   []string{dependencyContext, advisoryKindContext, versionContext},
		},
		Vulnerability: domain.NormalizedVulnerability{ID: p.ID, Affected: []domain.AffectedTarget{}, References: []domain.Reference{}, Weaknesses: []string{}},
		Evidence:      []processor.Evidence{},
	}
	fail := func(err error) (processor.Input, []string, error) { return processor.Input{}, nil, err }
	if p.ID == "" {
		return fail(fmt.Errorf("alias group has no matching OSV identity"))
	}
	in.Repository.Warnings = append(in.Repository.Warnings, fmt.Sprintf("Repository scan status=%s; refresh_complete=%t; unqueried components=%d; omitted warning entries=%d (profile=%d, report=%d; lists may overlap). Full profile/report warnings remain in saved state. Missing or incomplete results do not establish absence of advisories.", s.Report.Status, s.Report.RefreshComplete, len(s.Report.Unqueried), len(s.Profile.Warnings)+len(s.Report.Warnings), len(s.Profile.Warnings), len(s.Report.Warnings)))
	queriedPackages := map[[2]string]bool{}
	for i := range indices {
		q := s.Report.Queries[i].Query
		queriedPackages[[2]string{q.Ecosystem, q.Name}] = true
	}
	documents := map[string]savedOSV{}
	allIDs, kinds, descriptions := []string{}, []string{}, []string{}
	for _, key := range p.RecordKeys {
		rec, exists := s.Report.Records[key]
		if !exists || membership[key] != 1 || key != rec.Source+":"+rec.ID || strings.TrimSpace(rec.ID) == "" {
			return fail(fmt.Errorf("missing, ambiguous, or invalid current source record %q", key))
		}
		var raw map[string]json.RawMessage
		var identity struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rec.Raw, &raw); err != nil {
			return fail(fmt.Errorf("%s: invalid raw source record: %w", key, err))
		}
		if err := json.Unmarshal(rec.Raw, &identity); err != nil || identity.ID != rec.ID {
			return fail(fmt.Errorf("%s: raw source identity mismatch", key))
		}
		allIDs = append(allIDs, rec.ID)
		allIDs = append(allIDs, rec.Aliases...)
		fields := map[string]json.RawMessage{}
		content := map[string]any{"record_key": key, "source": rec.Source, "source_text_untrusted": true, "source_fields": fields}
		e := processor.Evidence{ID: fmt.Sprintf("EVD-SOURCE-%03d", len(in.Evidence)+1)}
		switch rec.Source {
		case "osv":
			var a savedOSV
			if err := json.Unmarshal(rec.Raw, &a); err != nil {
				return fail(fmt.Errorf("%s: decode OSV advisory: %w", key, err))
			}
			if !reflect.DeepEqual(sortedUnique(a.Aliases), sortedUnique(rec.Aliases)) || (a.Withdrawn != "") != rec.Withdrawn {
				return fail(fmt.Errorf("%s: OSV metadata contradicts raw record", key))
			}
			documents[key] = a
			published, err := sourceTimestamp(a.Published)
			if err != nil {
				return fail(fmt.Errorf("%s: invalid published timestamp: %w", key, err))
			}
			modified, err := sourceTimestamp(a.Modified)
			if err != nil {
				return fail(fmt.Errorf("%s: invalid modified timestamp: %w", key, err))
			}
			if !published.IsZero() && !modified.IsZero() && modified.Before(published) {
				in.Repository.Warnings = append(in.Repository.Warnings, fmt.Sprintf("%s: source modified timestamp %s precedes published timestamp %s; both source-provided values are preserved", key, a.Modified, a.Published))
			}
			missing := []string{}
			if published.IsZero() {
				missing = append(missing, "published")
			}
			if modified.IsZero() {
				missing = append(missing, "modified")
			}
			if strings.TrimSpace(a.Summary) == "" && strings.TrimSpace(a.Details) == "" {
				missing = append(missing, "summary/details")
			}
			if len(missing) > 0 {
				in.Repository.Warnings = append(in.Repository.Warnings, key+": source fields unavailable: "+strings.Join(missing, ", ")+"; missing timestamps remain zero, not scan time")
			}
			content["missing_fields"] = missing
			// Keep complete raw entries so provider-specific applicability and
			// range qualifiers survive without becoming backend runtime facts.
			var rawAffected []json.RawMessage
			if value, exists := raw["affected"]; exists {
				if err := json.Unmarshal(value, &rawAffected); err != nil {
					return fail(fmt.Errorf("%s: decode OSV affected entries: %w", key, err))
				}
			}
			if len(rawAffected) != len(a.Affected) {
				return fail(fmt.Errorf("%s: affected entries differ from raw affected field", key))
			}
			selectedAffected := []json.RawMessage{}
			sourceKinds, affectedKinds := []string{}, []any{}
			for i, affected := range a.Affected {
				if len(queriedPackages) > 0 && !queriedPackages[[2]string{affected.Package.Ecosystem, affected.Package.Name}] {
					continue
				}
				selectedAffected = append(selectedAffected, rawAffected[i])
				ks, err := informationalKinds(affected.DatabaseSpecific.Informational)
				if err != nil {
					return fail(fmt.Errorf("%s: %w", key, err))
				}
				sourceKinds = append(sourceKinds, ks...)
				affectedKinds = append(affectedKinds, map[string]any{"package": affected.Package, "advisory_kinds": ks})
			}
			if len(sourceKinds) == 0 {
				sourceKinds = append(sourceKinds, "unknown")
			}
			if _, exists := raw["affected"]; exists {
				fields["affected"], err = json.Marshal(selectedAffected)
				if err != nil {
					return fail(fmt.Errorf("%s: encode OSV affected entries: %w", key, err))
				}
			}
			content["affected_entries_omitted"] = len(rawAffected) - len(selectedAffected)
			content["advisory_kinds"], content["affected_kinds"] = sortedUnique(sourceKinds), affectedKinds
			content["caveat"] = advisoryKindContext + " " + sourceApplicabilityContext
			if !rec.Withdrawn {
				kinds = append(kinds, sourceKinds...)
				text := strings.TrimSpace(a.Summary + "\n\n" + a.Details)
				if text == "" {
					text = "Source summary and details unavailable."
				}
				descriptions = append(descriptions, key+":\n"+text)
				// Group dates aggregate source dates only: earliest publication,
				// latest modification. Per-source values/missingness stay in evidence.
				if !published.IsZero() && (in.Vulnerability.PublishedAt.IsZero() || published.Before(in.Vulnerability.PublishedAt)) {
					in.Vulnerability.PublishedAt = published
				}
				if modified.After(in.Vulnerability.ModifiedAt) {
					in.Vulnerability.ModifiedAt = modified
				}
			}
			for _, ref := range a.References {
				if ref.URL != "" {
					in.Vulnerability.References = append(in.Vulnerability.References, domain.Reference{Source: key, URL: ref.URL, Tags: []string{ref.Type}})
				}
			}
			selectSourceFields(fields, raw, "id", "aliases", "summary", "details", "published", "modified", "withdrawn", "references")
			e.Kind, e.Source, e.URI = processor.EvidenceAdvisory, "OSV", "https://osv.dev/vulnerability/"+url.PathEscape(rec.ID)
		case "nvd":
			if !realCVE.MatchString(rec.ID) || rec.Withdrawn || len(rec.Aliases) != 0 {
				return fail(fmt.Errorf("%s: invalid NVD metadata", key))
			}
			selectSourceFields(fields, raw, "id", "published", "lastModified", "vulnStatus", "descriptions", "metrics", "weaknesses", "references")
			content["caveat"] = "Current NVD supplementary metadata only; it supplies no repository identity, exact-version, CPE, or runtime applicability proof."
			e.Kind, e.Source, e.URI = processor.EvidenceNVD, "NVD", "https://nvd.nist.gov/vuln/detail/"+rec.ID
		default:
			return fail(fmt.Errorf("%s: unsupported source %q", key, rec.Source))
		}
		if err := appendEvidence(&in, e, content); err != nil {
			return fail(err)
		}
	}
	if !reflect.DeepEqual(sortedUnique(allIDs), p.IDs) {
		return fail(fmt.Errorf("alias group IDs differ from current source records"))
	}
	in.Vulnerability.Description = strings.Join(descriptions, "\n\n")
	in.Candidate = domain.MatchCandidate{RepositoryID: s.Profile.Repository.ID, RepositoryCommit: s.Profile.Repository.CommitSHA, VulnerabilityID: p.ID, VulnerabilityRev: in.Vulnerability.ModifiedAt, Matches: []domain.TargetMatch{}}

	queryIndices := make([]int, 0, len(indices))
	for i := range indices {
		queryIndices = append(queryIndices, i)
	}
	sort.Ints(queryIndices)
	type targetIdentity struct{ purl, ecosystem, name, version string }
	targets := map[targetIdentity]string{}
	components := map[string]domain.Component{}
	pairs := map[[2]string]bool{}
	for _, i := range queryIndices {
		q := s.Report.Queries[i]
		plan, exists := planned[q.Query]
		if !exists || len(q.Origins) == 0 || !reflect.DeepEqual(q.Origins, plan.Origins) {
			return fail(fmt.Errorf("query %d identity or full origins differ from saved profile", i))
		}
		if q.Outcome != "affected_version_match" || q.RuntimeImpact != "unknown" || (q.Complete && q.Error != "") || (!q.Complete && (s.Report.Status == "complete" || s.Report.RefreshComplete)) {
			return fail(fmt.Errorf("query %d has contradictory outcome or completeness", i))
		}
		selected := map[string]reposcan.Match{}
		seen := map[string]reposcan.Match{}
		for _, m := range q.Matches {
			if !contains(p.RecordKeys, m.RecordKey) {
				continue
			}
			m.FixedVersions = sortedUnique(m.FixedVersions)
			if prior, ok := seen[m.RecordKey]; ok && !reflect.DeepEqual(prior, m) {
				return fail(fmt.Errorf("query %d has conflicting duplicate matches for %q", i, m.RecordKey))
			}
			seen[m.RecordKey] = m
			if m.Outcome != "affected_version_match" {
				continue
			}
			a, ok := documents[m.RecordKey]
			if !ok || a.Withdrawn != "" || m.Reason != "" || !contains(q.IDs, a.ID) {
				return fail(fmt.Errorf("query %d has invalid or withdrawn OSV match %q", i, m.RecordKey))
			}
			matched, fixed := false, []string{}
			for _, affected := range a.Affected {
				if affected.Package.Ecosystem == q.Query.Ecosystem && affected.Package.Name == q.Query.Name {
					matched = true
					for _, r := range affected.Ranges {
						for _, event := range r.Events {
							fixed = append(fixed, event.Fixed)
						}
					}
				}
			}
			if !matched || !reflect.DeepEqual(sortedUnique(fixed), sortedUnique(m.FixedVersions)) {
				return fail(fmt.Errorf("query %d match %q contradicts OSV affected packages or fixed boundaries", i, m.RecordKey))
			}
			selected[m.RecordKey] = m
		}
		if len(selected) == 0 {
			return fail(fmt.Errorf("query %d has no usable OSV match for alias group", i))
		}
		matches := []reposcan.Match{}
		for _, key := range sortedMapKeys(selected) {
			matches = append(matches, selected[key])
		}
		for _, c := range q.Origins {
			if counts[c.ID] != 1 || strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.SourcePath) == "" || c.Version != q.Query.Version {
				return fail(fmt.Errorf("query %d has ambiguous or invalid origin %q", i, c.ID))
			}
			name := c.Name
			if c.Namespace != "" && !strings.HasPrefix(name, c.Namespace+"/") {
				name = c.Namespace + "/" + name
			}
			reason := domain.MatchPackageExact
			if c.PURL != "" {
				if !strings.HasPrefix(c.PURL, "pkg:") || len(c.PURL) <= 4 {
					return fail(fmt.Errorf("origin %q has invalid PURL", c.ID))
				}
				reason = domain.MatchPURLExact
			}
			// These are original profile identities, not OSV-normalized names.
			// assessment.exactComponent uses a slash even for Maven namespaces.
			identity := targetIdentity{c.PURL, c.Ecosystem, name, q.Query.Version}
			targetID, exists := targets[identity]
			constraints := []domain.VersionConstraint{{Scheme: "osv", Expression: q.Query.Version}}
			status, err := versions.New().Evaluate(c.Ecosystem, c.Version, constraints)
			if err != nil || status != domain.VersionAffected {
				return fail(fmt.Errorf("origin %q lacks exact pinned OSV version evidence", c.ID))
			}
			if !exists {
				targetID = fmt.Sprintf("OSV-TARGET-%03d", len(targets)+1)
				targets[identity] = targetID
				in.Vulnerability.Affected = append(in.Vulnerability.Affected, domain.AffectedTarget{ID: targetID, Kind: domain.AffectedPackage, PURL: c.PURL, Ecosystem: c.Ecosystem, PackageName: name, Constraints: constraints})
			}
			components[c.ID] = c
			pair := [2]string{c.ID, targetID}
			if !pairs[pair] {
				pairs[pair] = true
				in.Candidate.Matches = append(in.Candidate.Matches, domain.TargetMatch{RepositoryItemID: c.ID, AffectedTargetID: targetID, Reason: reason, VersionStatus: status, InstalledVersion: c.Version})
			}
		}
		// Keep every original path/scope/namespace, not a representative origin.
		q.Matches = matches
		content := map[string]any{"query_result": q, "caveat": versionContext + " Matches are limited to this alias group's positive evidence; discovered IDs may include other groups."}
		e := processor.Evidence{ID: fmt.Sprintf("EVD-QUERY-%03d", len(in.Evidence)+1), Kind: processor.EvidenceRepositoryDependency, Source: "reposcan report.queries"}
		if err := appendEvidence(&in, e, content); err != nil {
			return fail(err)
		}
		if !q.Complete || q.Error != "" {
			in.Repository.Warnings = append(in.Repository.Warnings, fmt.Sprintf("Related OSV query %s %s@%s incomplete: %s", q.Query.Ecosystem, q.Query.Name, q.Query.Version, q.Error))
		}
	}
	for _, e := range s.Report.Enrichment {
		if contains(p.IDs, e.ID) && e.Status != "found" {
			in.Repository.Warnings = append(in.Repository.Warnings, fmt.Sprintf("Related enrichment %s:%s status=%s: %s", e.Source, e.ID, e.Status, e.Error))
		}
	}
	for _, id := range sortedMapKeys(components) {
		in.Repository.Components = append(in.Repository.Components, components[id])
	}
	in.Repository.Warnings = sortedUnique(in.Repository.Warnings)
	return in, sortedUnique(kinds), nil
}

func sourceTimestamp(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return parsed.UTC(), err
}

func informationalKinds(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return []string{"unknown"}, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		if strings.TrimSpace(value) == "" {
			value = "unknown"
		}
		return []string{value}, nil
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("invalid affected.database_specific.informational: expected string or strings")
	}
	values = sortedUnique(values)
	if len(values) == 0 {
		values = []string{"unknown"}
	}
	return values, nil
}

func selectSourceFields(dst, src map[string]json.RawMessage, names ...string) {
	for _, name := range names {
		if value, ok := src[name]; ok {
			dst[name] = value
		}
	}
}

func appendEvidence(in *processor.Input, e processor.Evidence, content any) error {
	data, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("encode %s evidence: %w", e.Source, err)
	}
	e.Content = string(data)
	identity, err := json.Marshal(struct {
		Repository  domain.RepositoryIdentity `json:"repository"`
		CandidateID string                    `json:"candidate_id"`
		Evidence    processor.Evidence        `json:"evidence"`
	}{in.Repository.Repository, in.Vulnerability.ID, e})
	if err != nil {
		return fmt.Errorf("encode %s evidence identity: %w", e.Source, err)
	}
	// Keep the readable kind/index and bind citations to immutable context.
	// A 96-bit suffix fits the processor's 64-character evidence-ID payload.
	digest := sha256.Sum256(identity)
	e.ID = fmt.Sprintf("%s-%X", e.ID, digest[:12])
	in.Evidence = append(in.Evidence, e)
	return nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func sortedUnique(values []string) []string {
	set := map[string]bool{}
	for _, value := range values {
		if value != "" {
			set[value] = true
		}
	}
	return sortedMapKeys(set)
}

func sortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
