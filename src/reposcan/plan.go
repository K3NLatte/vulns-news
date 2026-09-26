package reposcan

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/versions"
	"vulns-news/src/osv"
)

var mavenName = regexp.MustCompile(`^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$`)
var packagistName = regexp.MustCompile(`^[a-z0-9_.-]+/[a-z0-9_.-]+$`)

func validText(s string) bool {
	return s != "" && strings.TrimSpace(s) == s && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}

func packageIdentity(c domain.Component) (osv.PackageVersion, bool) {
	eco, supported := versions.OSVEcosystem(c.Ecosystem)
	q := osv.PackageVersion{Ecosystem: eco, Name: c.Name, Version: c.Version}
	if !validText(c.Name) {
		return q, false
	}
	sep := ""
	switch eco {
	case "Maven":
		sep = ":"
	case "Packagist":
		sep = "/"
	}
	if sep != "" && c.Namespace != "" {
		if strings.Contains(c.Name, sep) {
			if !strings.HasPrefix(c.Name, c.Namespace+sep) {
				return q, false
			}
		} else {
			q.Name = c.Namespace + sep + c.Name
		}
	}
	// npm split scopes can be represented without guessing a namespace.
	if eco == "npm" && c.Namespace != "" {
		if !strings.HasPrefix(c.Namespace, "@") {
			return q, false
		}
		if strings.Contains(c.Name, "/") {
			if !strings.HasPrefix(c.Name, c.Namespace+"/") {
				return q, false
			}
		} else {
			q.Name = c.Namespace + "/" + c.Name
		}
	}
	if !supported || !validText(q.Name) || len(q.Name) > 512 || strings.IndexFunc(q.Name, unicode.IsSpace) >= 0 {
		return q, false
	}
	if eco == "Maven" && !mavenName.MatchString(q.Name) || eco == "Packagist" && !packagistName.MatchString(q.Name) {
		return q, false
	}
	return q, true
}

func queryKey(q osv.PackageVersion) string {
	b, _ := json.Marshal(q)
	return string(b)
}

// Plan is deterministic and performs no I/O. Origins retain original identities,
// namespaces, scopes and paths; workspace and dependency-path data is unavailable.
// Invalid identities are rejected per component, not per unqualified name.
func Plan(profile domain.RepositoryProfile) PlanReport {
	out := PlanReport{Queries: []PlannedQuery{}, Unqueried: []UnqueriedComponent{}}

	queries := map[osv.PackageVersion][]domain.Component{}
	for _, c := range profile.Components {
		reason := ""
		q, valid := packageIdentity(c)
		// Endpoint support and canonical identity availability are stricter
		// than the shared version grammar's ecosystem mapping.
		if eco, supported := versions.OSVEcosystem(c.Ecosystem); !supported || eco == "CocoaPods" {
			reason = "unsupported ecosystem"
		} else if eco == "NuGet" {
			reason = "OSV canonical package identity unavailable"
		} else if !valid {
			reason = "invalid/ambiguous identity"
		} else if !versions.IsPinned(c.Ecosystem, c.Version) {
			reason = "unresolved version"
		}
		if reason != "" {
			out.Unqueried = append(out.Unqueried, UnqueriedComponent{c, reason})
			continue
		}
		queries[q] = append(queries[q], c)
	}
	for q, origins := range queries {
		sort.SliceStable(origins, func(i, j int) bool {
			a, _ := json.Marshal(origins[i])
			b, _ := json.Marshal(origins[j])
			return string(a) < string(b)
		})
		out.Queries = append(out.Queries, PlannedQuery{q, origins, "unavailable", "unavailable"})
	}
	sort.Slice(out.Queries, func(i, j int) bool { return queryKey(out.Queries[i].Query) < queryKey(out.Queries[j].Query) })
	return out
}

func validProfile(p domain.RepositoryProfile) bool {
	return validText(p.Repository.ID) && validText(p.Repository.CommitSHA)
}

func unique(values []string) []string {
	set := map[string]bool{}
	for _, v := range values {
		if v != "" {
			set[v] = true
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
