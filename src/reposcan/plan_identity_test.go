package reposcan_test

import (
	"reflect"
	"slices"
	"testing"

	"vulns-news/src/domain"
	"vulns-news/src/osv"
	"vulns-news/src/reposcan"
)

func TestPlanNamespaceIdentity(t *testing.T) {
	for _, tc := range []struct {
		ecosystem, alias, first, second, separator, source string
	}{
		{"Maven", "maven", "org.one", "org.two", ":", "pom.xml"},
		{"Packagist", "packagist", "vendor-one", "vendor-two", "/", "composer.lock"},
	} {
		t.Run(tc.ecosystem, func(t *testing.T) {
			firstName := tc.first + tc.separator + "core"
			secondName := tc.second + tc.separator + "core"
			components := []domain.Component{
				{ID: "a-split", Ecosystem: tc.alias, Namespace: tc.first, Name: "core", Version: "1.0.0", SourcePath: tc.source, Scope: "runtime", Direct: true},
				{ID: "b-full", Ecosystem: tc.ecosystem, Name: firstName, Version: "1.0.0", SourcePath: "nested/" + tc.source, Scope: "development"},
				{ID: "c-full-with-namespace", Ecosystem: tc.alias, Namespace: tc.first, Name: firstName, Version: "1.0.0", SourcePath: "tests/" + tc.source},
				{ID: "d-other-namespace", Ecosystem: tc.alias, Namespace: tc.second, Name: "core", Version: "1.0.0", SourcePath: tc.source},
				{ID: "e-other-full", Ecosystem: tc.ecosystem, Name: secondName, Version: "1.0.0", SourcePath: "nested/" + tc.source},
				{ID: "f-other-version", Ecosystem: tc.ecosystem, Namespace: tc.first, Name: "core", Version: "2.0.0", SourcePath: tc.source},
				{ID: "g-other-name", Ecosystem: tc.alias, Namespace: tc.first, Name: "extra", Version: "1.0.0", SourcePath: tc.source},
			}
			want := map[osv.PackageVersion][]domain.Component{
				{Ecosystem: tc.ecosystem, Name: firstName, Version: "1.0.0"}:                         {components[0], components[1], components[2]},
				{Ecosystem: tc.ecosystem, Name: secondName, Version: "1.0.0"}:                        {components[3], components[4]},
				{Ecosystem: tc.ecosystem, Name: firstName, Version: "2.0.0"}:                         {components[5]},
				{Ecosystem: tc.ecosystem, Name: tc.first + tc.separator + "extra", Version: "1.0.0"}: {components[6]},
			}
			t.Run("distinct namespaces and equivalent forms", func(t *testing.T) {
				assertNamespaceIdentityPlan(t, components, want, []reposcan.UnqueriedComponent{})
			})

			for _, invalid := range []struct {
				name, namespace, packageName, version, reason string
			}{
				{"contradictory first namespace", tc.second, firstName, "1.0.0", "invalid/ambiguous identity"},
				{"contradictory second namespace", tc.first, secondName, "1.0.0", "invalid/ambiguous identity"},
				{"unqualified name", "", "core", "1.0.0", "invalid/ambiguous identity"},
				{"malformed namespace", "bad namespace", "core", "1.0.0", "invalid/ambiguous identity"},
				{"unresolved version", tc.first, "core", "", "unresolved version"},
			} {
				t.Run(invalid.name+" does not poison valid origins", func(t *testing.T) {
					bad := domain.Component{
						ID: "invalid", Ecosystem: tc.ecosystem, Namespace: invalid.namespace,
						Name: invalid.packageName, Version: invalid.version,
						SourcePath: "invalid/" + tc.source, Scope: "development", Direct: true,
					}
					input := append(slices.Clone(components), bad)
					assertNamespaceIdentityPlan(t, input, want, []reposcan.UnqueriedComponent{{Component: bad, Reason: invalid.reason}})
				})
			}
		})
	}
}

func TestPlanIdentityKeepsEcosystemsDistinct(t *testing.T) {
	components := []domain.Component{
		{ID: "a-npm", Ecosystem: "npm", Name: "core", Version: "1.0.0", SourcePath: "package-lock.json"},
		{ID: "b-python", Ecosystem: "pypi", Name: "core", Version: "1.0.0", SourcePath: "requirements.txt"},
		{ID: "c-python-alias", Ecosystem: "PyPI", Name: "core", Version: "1.0.0", SourcePath: "nested/requirements.txt"},
	}
	want := map[osv.PackageVersion][]domain.Component{
		{Ecosystem: "npm", Name: "core", Version: "1.0.0"}:  {components[0]},
		{Ecosystem: "PyPI", Name: "core", Version: "1.0.0"}: {components[1], components[2]},
	}
	assertNamespaceIdentityPlan(t, components, want, []reposcan.UnqueriedComponent{})
}

func assertNamespaceIdentityPlan(t *testing.T, components []domain.Component, want map[osv.PackageVersion][]domain.Component, unqueried []reposcan.UnqueriedComponent) {
	t.Helper()
	original := slices.Clone(components)
	got := reposcan.Plan(domain.RepositoryProfile{Components: components})
	if !reflect.DeepEqual(components, original) {
		t.Error("planning mutated the original component identities")
	}
	if !reflect.DeepEqual(got.Unqueried, unqueried) {
		t.Errorf("unqueried components = %+v, want %+v", got.Unqueried, unqueried)
	}
	if len(got.Queries) != len(want) {
		t.Errorf("got %d queries, want %d fully-qualified identities: %+v", len(got.Queries), len(want), got.Queries)
	}
	seen := make(map[osv.PackageVersion]bool)
	for _, q := range got.Queries {
		origins, ok := want[q.Query]
		if !ok || seen[q.Query] {
			t.Errorf("unexpected or duplicate query: %+v", q)
			continue
		}
		seen[q.Query] = true
		if !reflect.DeepEqual(q.Origins, origins) {
			t.Errorf("origins for %+v = %+v, want %+v", q.Query, q.Origins, origins)
		}
		if q.Workspace != "unavailable" || q.DependencyPath != "unavailable" {
			t.Errorf("invented workspace/dependency path: %+v", q)
		}
	}
	for q := range want {
		if !seen[q] {
			t.Errorf("missing fully-qualified query: %+v", q)
		}
	}
	reversed := slices.Clone(original)
	slices.Reverse(reversed)
	// Each case has at most one unqueried origin, so the whole plan can be
	// compared while verifying bad-first and bad-last inventory orders.
	if again := reposcan.Plan(domain.RepositoryProfile{Components: reversed}); !reflect.DeepEqual(got, again) {
		t.Errorf("plan depends on component order:\nforward: %+v\nreverse: %+v", got, again)
	}
}
