package osv

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/versions"
	"vulns-news/src/matcher"
)

func TestSplitAndQualifiedNames(t *testing.T) {
	for _, tc := range []struct{ eco, canonical, namespace, name, separator, purl string }{
		{"maven", "Maven", "org.example", "artifact", ":", "pkg:maven/org.example/artifact@1.2.3"},
		{"Maven", "Maven", "org.example", "artifact", ":", "pkg:maven/org.example/artifact@1.2.3"},
		{"packagist", "Packagist", "vendor", "package", "/", "pkg:composer/vendor/package@1.2.3"},
		{"Packagist", "Packagist", "vendor", "package", "/", "pkg:composer/vendor/package@1.2.3"},
	} {
		t.Run(tc.eco, func(t *testing.T) {
			calls := 0
			qualified := tc.namespace + tc.separator + tc.name
			c := client(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				var q query
				if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
					t.Error(err)
				}
				if q.Package != (packageKey{Ecosystem: tc.canonical, Name: qualified}) || q.Version != "1.2.3" {
					t.Errorf("query: %+v", q)
				}
				io.WriteString(w, `{"vulns":[{"id":"CVE-2025-12345"}]}`)
			})
			for _, usePURL := range []bool{false, true} {
				for _, form := range []struct{ name, namespace string }{
					{tc.name, tc.namespace}, {qualified, tc.namespace}, {qualified, ""},
				} {
					component := domain.Component{ID: "component", Ecosystem: tc.eco, Namespace: form.namespace, Name: form.name, Version: "1.2.3"}
					if usePURL {
						component.PURL = tc.purl
					}
					p := domain.RepositoryProfile{Components: []domain.Component{component}}
					p.Repository.ID, p.Repository.CommitSHA = "repo", "commit"
					got, err := c.Enrich(context.Background(), p, vulnerability())
					if err != nil || len(got.Affected) != 1 {
						t.Fatalf("%+v, %v", got, err)
					}
					target := got.Affected[0]
					if target.PackageName != component.Name || target.Ecosystem != component.Ecosystem || target.PURL != component.PURL {
						t.Fatalf("changed identity: %+v -> %+v", component, target)
					}
					candidate, ok, err := matcher.New(versions.New()).Match(p, got)
					if err != nil || !ok || len(candidate.Matches) != 1 || candidate.Matches[0].VersionStatus != domain.VersionAffected {
						t.Fatalf("%+v, %v", candidate, err)
					}
				}
			}
			if calls != 1 {
				t.Fatalf("split and qualified forms must share the query cache: %d", calls)
			}
		})
	}
}

func TestInvalidNamespaceNames(t *testing.T) {
	for _, tc := range []struct{ eco, separator string }{{"maven", ":"}, {"packagist", "/"}} {
		for _, form := range []struct{ name, namespace string }{
			{"group" + tc.separator + "artifact", "other"},
			{"artifact", "bad namespace"},
			{"artifact", "bad\x00namespace"},
			{"artifact", "group" + tc.separator + "extra"},
			{"artifact", strings.Repeat("a", 512)},
			{"artifact", ""},
		} {
			component := domain.Component{Ecosystem: tc.eco, Name: form.name, Namespace: form.namespace, Version: "1.2.3"}
			if q, ok := componentQuery(component); ok {
				t.Errorf("accepted %+v as %+v", component, q)
			}
		}
	}
}

func TestNamespaceCollisions(t *testing.T) {
	for _, tc := range []struct{ eco, separator, purlType string }{{"maven", ":", "maven"}, {"packagist", "/", "composer"}} {
		t.Run(tc.eco, func(t *testing.T) {
			c := client(t, func(w http.ResponseWriter, r *http.Request) {
				var q query
				if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
					t.Error(err)
				}
				if strings.HasPrefix(q.Package.Name, "first"+tc.separator) {
					io.WriteString(w, `{"vulns":[{"id":"CVE-2025-12345"}]}`)
				} else {
					io.WriteString(w, `{}`)
				}
			})
			for _, usePURL := range []bool{false, true} {
				for _, otherVersion := range []string{"1.2.3", ""} {
					p := domain.RepositoryProfile{Components: []domain.Component{
						{ID: "first", Ecosystem: tc.eco, Namespace: "first", Name: "artifact", Version: "1.2.3"},
						{ID: "second", Ecosystem: tc.eco, Namespace: "second", Name: "artifact", Version: otherVersion},
					}}
					p.Repository.ID, p.Repository.CommitSHA = "repo", "commit"
					if usePURL {
						for i := range p.Components {
							component := &p.Components[i]
							component.PURL = "pkg:" + tc.purlType + "/" + component.Namespace + "/artifact@" + component.Version
						}
					}
					got, err := c.Enrich(context.Background(), p, vulnerability())
					if err != nil || len(got.Affected) != 0 {
						t.Fatalf("unsafe bare-name target: %+v, %v", got, err)
					}
					// Apply the coordinator's normalization without changing Namespace.
					for i := range p.Components {
						p.Components[i].Name = p.Components[i].Namespace + tc.separator + p.Components[i].Name
					}
					got, err = c.Enrich(context.Background(), p, vulnerability())
					if err != nil || len(got.Affected) != 1 {
						t.Fatalf("normalized target: %+v, %v", got, err)
					}
					candidate, ok, err := matcher.New(versions.New()).Match(p, got)
					if err != nil || !ok || len(candidate.Matches) != 1 || candidate.Matches[0].RepositoryItemID != "first" || candidate.Matches[0].VersionStatus != domain.VersionAffected {
						t.Fatalf("namespace cross-attribution: %+v, %v", candidate, err)
					}
				}
			}
		})
	}
}

func TestTargetIDsIncludeNamespace(t *testing.T) {
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"vulns":[{"id":"CVE-2025-12345"}]}`)
	})
	ids := make(map[string]bool)
	for _, namespace := range []string{"first", "second"} {
		p := domain.RepositoryProfile{Components: []domain.Component{{Ecosystem: "maven", Namespace: namespace, Name: "artifact", Version: "1.2.3"}}}
		got, err := c.Enrich(context.Background(), p, vulnerability())
		if err != nil || len(got.Affected) != 1 {
			t.Fatalf("%+v, %v", got, err)
		}
		id := got.Affected[0].ID
		if ids[id] {
			t.Fatal("namespace target ID collision")
		}
		ids[id] = true
	}
}
