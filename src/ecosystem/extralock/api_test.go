package extralock_test

import (
	"testing"

	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/extralock"
)

// Compile-time checks keep the exported contract independent of parser internals.
var _ func(string) (extralock.Fragment, error) = extralock.Profile
var _ = extralock.Fragment{
	Components: []domain.Component{},
	Ecosystems: []domain.EcosystemUsage{},
	Warnings:   []string{},
}

func TestPublicAPI(t *testing.T) {
	f, err := extralock.Profile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Components) != 0 || len(f.Ecosystems) != 0 || len(f.Warnings) != 0 {
		t.Fatalf("nonempty directory inventory: %+v", f)
	}
}
