package repository

import (
	"sort"
	"strings"
	"vulns-news/src/domain"
)

// Normalize ecosystem identities before matching, preserving per-file provenance.
func normalizeProfile(profile *domain.RepositoryProfile) {
	for i := range profile.Components {
		c := &profile.Components[i]
		if c.Ecosystem == "PyPI" {
			c.Ecosystem = "pypi"
		}
		if c.Namespace != "" {
			switch c.Ecosystem {
			case "maven":
				if !strings.Contains(c.Name, ":") {
					c.Name = c.Namespace + ":" + c.Name
				}
			case "packagist":
				if !strings.Contains(c.Name, "/") {
					c.Name = c.Namespace + "/" + c.Name
				}
			}
		}
	}
	sort.Slice(profile.Components, func(i, j int) bool { return profile.Components[i].ID < profile.Components[j].ID })
	usages := map[string]*domain.EcosystemUsage{}
	for _, u := range profile.Ecosystems {
		if u.Name == "PyPI" {
			u.Name = "pypi"
		}
		existing := usages[u.Name]
		if existing == nil {
			existing = &domain.EcosystemUsage{Name: u.Name}
			usages[u.Name] = existing
		}
		existing.Manifests = append(existing.Manifests, u.Manifests...)
		existing.Lockfiles = append(existing.Lockfiles, u.Lockfiles...)
	}
	profile.Ecosystems = nil
	for _, u := range usages {
		u.Manifests = uniquePaths(u.Manifests)
		u.Lockfiles = uniquePaths(u.Lockfiles)
		profile.Ecosystems = append(profile.Ecosystems, *u)
	}
	sort.Slice(profile.Ecosystems, func(i, j int) bool { return profile.Ecosystems[i].Name < profile.Ecosystems[j].Name })
	profile.Warnings = uniquePaths(profile.Warnings)
}

func uniquePaths(paths []string) []string {
	sort.Strings(paths)
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		if len(result) == 0 || result[len(result)-1] != p {
			result = append(result, p)
		}
	}
	return result
}
