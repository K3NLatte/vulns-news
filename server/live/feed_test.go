package live

import (
	"fmt"
	"reflect"
	"testing"

	"vulns-news/server/model"
	"vulns-news/src/domain"
	"vulns-news/src/feed"
	"vulns-news/src/scananalyze"
)

func referenceItems(refs []domain.Reference) []model.FeedItem {
	prepared := []scananalyze.Prepared{{ID: "CVE-2026-1000"}, {ID: "CVE-2026-1001"}}
	report := scananalyze.Report{}
	for i := range prepared {
		prepared[i].Input.Vulnerability.References = refs
		report.Entries = append(report.Entries, scananalyze.Entry{ID: prepared[i].ID, Feed: &feed.Item{}})
	}
	return Items(report, prepared, nil)
}

func TestItemsDeduplicateReferenceURLs(t *testing.T) {
	const base = "https://example.test/advisory"
	refs := []domain.Reference{
		{Source: "osv:GHSA-first", URL: base},
		{Source: "osv:GHSA-first", URL: base},
		{Source: "osv:CVE-2026-1000", URL: base},
	}
	want := []model.FeedSource{{Name: "example.test/advisory", URL: base, Kind: "reference"}}
	// These can identify different resources; do not normalize them together.
	for _, suffix := range []string{"/", "?a=1&b=2", "?b=2&a=1", "#one", "#two", "/%61", "/a"} {
		refs = append(refs, domain.Reference{URL: base + suffix})
		want = append(want, model.FeedSource{Name: "example.test/advisory" + suffix, URL: base + suffix, Kind: "reference"})
	}
	for _, invalid := range []string{"", "http://example.test/advisory", "javascript:alert(1)", "https:///missing-host", "https://user@example.test/advisory", "https://example.test/%zz"} {
		refs = append(refs, domain.Reference{URL: invalid})
	}
	original := append([]domain.Reference(nil), refs...)
	items := referenceItems(refs)
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	for _, item := range items {
		if !reflect.DeepEqual(item.Sources, want) {
			t.Fatalf("%s sources = %+v, want %+v", item.ID, item.Sources, want)
		}
	}
	if !reflect.DeepEqual(refs, original) {
		t.Fatal("display deduplication mutated source references")
	}
}

func TestItemsReferenceLimitCountsUniqueURLs(t *testing.T) {
	refs := []domain.Reference{}
	for i := 0; i < 105; i++ {
		ref := domain.Reference{URL: fmt.Sprintf("https://example.test/%03d", i)}
		refs = append(refs, ref, ref, ref)
	}
	for _, item := range referenceItems(refs) {
		if len(item.Sources) != 100 {
			t.Fatalf("sources = %d, want 100", len(item.Sources))
		}
		for i, source := range item.Sources {
			if want := refs[i*3].URL; source.URL != want {
				t.Fatalf("source %d = %q, want %q", i, source.URL, want)
			}
		}
	}
}

func TestItemsReferenceLabelsIdentifyLinkedResources(t *testing.T) {
	for _, label := range []string{
		"github.com/advisories/GHSA-fg7r-2g4j-5cgr",
		"nvd.nist.gov/vuln/detail/CVE-2021-45710",
		"github.com/example/project/issues/123",
		"github.com/example/project/commit/abcdef123456",
		"example.test",
		"example.test:8443/docs/%E6%BC%8F%E6%B4%A9?version=2#details",
	} {
		t.Run(label, func(t *testing.T) {
			url := "https://" + label
			refs := []domain.Reference{{Source: "osv:GHSA-same-provider", URL: url}}
			for _, item := range referenceItems(refs) {
				want := []model.FeedSource{{Name: label, URL: url, Kind: "reference"}}
				if !reflect.DeepEqual(item.Sources, want) {
					t.Fatalf("sources = %+v, want %+v", item.Sources, want)
				}
			}
		})
	}
}

func TestItemsEmptyReferences(t *testing.T) {
	for _, item := range referenceItems(nil) {
		if item.Sources == nil || len(item.Sources) != 0 {
			t.Fatalf("sources = %+v, want non-nil empty slice", item.Sources)
		}
	}
}
