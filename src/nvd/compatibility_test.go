package nvd_test

import (
	"context"
	"encoding/json"
	"testing"

	"vulns-news/src/nvd"
)

// Both contracts must coexist without changing main's return type or JSON shape.
var _ interface {
	Fetch(context.Context, int) ([]nvd.CVE, error)
} = (*nvd.Client)(nil)

var _ interface {
	FetchPage(context.Context, nvd.Query) (nvd.Page, error)
	Fetch(context.Context, int) ([]nvd.NormalizedVulnerability, error)
	LookupCVE(context.Context, string) (json.RawMessage, error)
} = (*nvd.AnalysisClient)(nil)

func TestPublicAndAnalysisClientsCoexist(t *testing.T) {
	if nvd.NewClient() == nil {
		t.Fatal("public client is nil")
	}
	if client, err := nvd.NewAnalysisClient(nvd.Config{}); err != nil || client == nil {
		t.Fatalf("analysis client: %v", err)
	}
	// Positional literals are also part of main's public CVE compatibility.
	body, err := json.Marshal(nvd.CVE{"CVE-2026-1234", "description"})
	if err != nil || string(body) != `{"id":"CVE-2026-1234","description":"description"}` {
		t.Fatalf("public CVE JSON changed: %s, %v", body, err)
	}
	var page nvd.Page
	if err := json.Unmarshal([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2026-1234","published":"2026-09-30T00:00:00Z"}}]}`), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Vulnerabilities) != 1 || page.Vulnerabilities[0].CVE.Published != "2026-09-30T00:00:00Z" {
		t.Fatalf("analysis CVE record changed: %+v", page)
	}
}
