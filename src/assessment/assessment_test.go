package assessment

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"vulns-news/src/domain"
	"vulns-news/src/matcher"
)

func fixture() (domain.RepositoryProfile, domain.NormalizedVulnerability, domain.MatchCandidate) {
	p := domain.RepositoryProfile{Repository: domain.RepositoryIdentity{ID: "repo", CommitSHA: "commit"}, Components: []domain.Component{{ID: "component", Ecosystem: "npm", Name: "widget", Version: "1.0.0", SourcePath: "package-lock.json"}}}
	v := domain.NormalizedVulnerability{ID: "CVE-test", ModifiedAt: time.Unix(100, 0), Affected: []domain.AffectedTarget{{ID: "target", Kind: domain.AffectedPackage, Ecosystem: "npm", PackageName: "widget", Constraints: []domain.VersionConstraint{{Scheme: "semver", VersionEndExcluding: "2.0.0"}}}}}
	c := domain.MatchCandidate{RepositoryID: p.Repository.ID, RepositoryCommit: p.Repository.CommitSHA, VulnerabilityID: v.ID, VulnerabilityRev: v.ModifiedAt, Matches: []domain.TargetMatch{{RepositoryItemID: "component", AffectedTargetID: "target", Reason: domain.MatchPackageExact, InstalledVersion: "1.0.0", VersionStatus: domain.VersionAffected}}}
	return p, v, c
}

func assertHigherUnknown(t *testing.T, r Report) {
	t.Helper()
	for i, c := range []Check{r.FeatureUsage, r.CodeReachability, r.AttackConditions} {
		if c.Level != i+3 || c.Status != Unknown || len(c.MissingReasons) == 0 || len(c.Sources) != 0 || len(c.EvidenceIDs) != 0 {
			t.Fatalf("unsupported higher-level claim: %+v", c)
		}
	}
}

func TestAssessChecks(t *testing.T) {
	tests := []struct {
		name                            string
		edit                            func(*domain.RepositoryProfile, *domain.NormalizedVulnerability, *domain.MatchCandidate)
		presence, version, matchVersion Status
		conditional                     bool
	}{
		{"exact package", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {}, Confirmed, Confirmed, Confirmed, false},
		{"exact PURL", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			p.Components[0].PURL = "pkg:npm/widget@1.0.0"
			v.Affected[0].PURL = p.Components[0].PURL
			c.Matches[0].Reason = domain.MatchPURLExact
		}, Confirmed, Confirmed, Confirmed, false},
		{"empty PURL", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			c.Matches[0].Reason = domain.MatchPURLExact
		}, NotFound, Unknown, Confirmed, true},
		{"non PURL string", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			p.Components[0].PURL = "widget"
			v.Affected[0].PURL = "widget"
			c.Matches[0].Reason = domain.MatchPURLExact
		}, NotFound, Unknown, Confirmed, true},
		{"PURL mismatch", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			p.Components[0].PURL = "pkg:npm/widget"
			v.Affected[0].PURL = "pkg:npm/other"
		}, NotFound, Unknown, Confirmed, true},
		{"package mismatch", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			v.Affected[0].PackageName = "other"
		}, NotFound, Unknown, Confirmed, true},
		{"case mismatch", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			v.Affected[0].PackageName = "Widget"
		}, NotFound, Unknown, Confirmed, true},
		{"ecosystem mismatch", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			v.Affected[0].Ecosystem = "pypi"
		}, NotFound, Unknown, Confirmed, true},
		{"empty ecosystem", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			p.Components[0].Ecosystem = ""
			v.Affected[0].Ecosystem = ""
		}, NotFound, Unknown, Confirmed, true},
		{"empty package", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			p.Components[0].Name = ""
			v.Affected[0].PackageName = ""
		}, NotFound, Unknown, Confirmed, true},
		{"namespace basename is insufficient", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			p.Components[0].Namespace = "@owner"
		}, NotFound, Unknown, Confirmed, true},
		{"qualified namespace", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			p.Components[0].Namespace = "@owner"
			v.Affected[0].PackageName = "@owner/widget"
		}, Confirmed, Confirmed, Confirmed, false},
		{"already qualified namespace", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			p.Components[0].Namespace = "@owner"
			p.Components[0].Name = "@owner/widget"
			v.Affected[0].PackageName = "@owner/widget"
		}, Confirmed, Confirmed, Confirmed, false},
		{"product target", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			v.Affected[0].Kind = domain.AffectedProduct
		}, NotFound, Unknown, Confirmed, true},
		{"CPE is not package proof", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			c.Matches[0].Reason = domain.MatchCPEExact
		}, NotFound, Unknown, Confirmed, true},
		{"unaffected", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			c.Matches[0].VersionStatus = domain.VersionNotAffected
		}, Confirmed, NotAffected, NotAffected, false},
		{"unknown version", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			c.Matches[0].VersionStatus = domain.VersionUnknown
		}, Confirmed, Unknown, Unknown, false},
		{"empty status", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			c.Matches[0].VersionStatus = ""
		}, Confirmed, Unknown, Unknown, false},
		{"unsupported status", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			c.Matches[0].VersionStatus = "safe"
		}, Confirmed, Unknown, Unknown, false},
		{"no constraints", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			v.Affected[0].Constraints = nil
		}, Confirmed, Unknown, Unknown, false},
		{"no installed version", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			p.Components[0].Version = ""
			c.Matches[0].InstalledVersion = ""
		}, Confirmed, Unknown, Unknown, false},
		{"stale installed version", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			c.Matches[0].InstalledVersion = "0.9.0"
		}, Confirmed, Unknown, Unknown, false},
		{"unknown reason", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			c.Matches[0].Reason = "guess"
		}, Unknown, Unknown, Unknown, true},
		{"missing item", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			c.Matches[0].RepositoryItemID = "missing"
		}, Unknown, Unknown, Unknown, true},
		{"missing target", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			c.Matches[0].AffectedTargetID = "missing"
		}, Unknown, Unknown, Unknown, true},
		{"duplicate item", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			p.Components = append(p.Components, p.Components[0])
		}, Unknown, Unknown, Unknown, true},
		{"cross kind duplicate", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			p.Products = []domain.ProductCandidate{{ID: "component"}}
		}, Unknown, Unknown, Unknown, true},
		{"duplicate target", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			v.Affected = append(v.Affected, v.Affected[0])
		}, Unknown, Unknown, Unknown, true},
		{"duplicate match", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			c.Matches = append(c.Matches, c.Matches[0])
		}, Unknown, Unknown, Unknown, true},
		{"conflicting match", func(p *domain.RepositoryProfile, v *domain.NormalizedVulnerability, c *domain.MatchCandidate) {
			c.Matches = append(c.Matches, c.Matches[0])
			c.Matches[1].VersionStatus = domain.VersionNotAffected
		}, Unknown, Unknown, Unknown, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, v, c := fixture()
			tt.edit(&p, &v, &c)
			r := Assess(p, v, c)
			if r.PackagePresence.Status != tt.presence || r.AffectedVersion.Status != tt.version || r.Matches[0].AffectedVersion.Status != tt.matchVersion || r.Matches[0].AffectedVersion.ConditionalOnPackageIdentity != tt.conditional {
				t.Fatalf("unexpected checks: %+v", r)
			}
			assertHigherUnknown(t, r)
			if r.AffectedVersion.Status == Unknown && len(r.AffectedVersion.MissingReasons) == 0 {
				t.Fatal("missing unknown reason")
			}
		})
	}
}

func TestNonComponentMatchesRemainConditional(t *testing.T) {
	for _, reason := range []domain.MatchReason{domain.MatchProductAliasExact, domain.MatchProductExact, domain.MatchCPEExact, domain.MatchContainerExact, domain.MatchInfrastructureExact} {
		for _, status := range []domain.VersionStatus{domain.VersionAffected, domain.VersionNotAffected, domain.VersionUnknown} {
			t.Run(string(reason)+"/"+string(status), func(t *testing.T) {
				p, v, c := fixture()
				p.Components = nil
				switch reason {
				case domain.MatchContainerExact:
					p.Containers = []domain.ContainerReference{{ID: "component", Image: "widget", Tag: "1.0.0", SourcePath: "Dockerfile"}}
					v.Affected[0].Kind = domain.AffectedContainer
				case domain.MatchInfrastructureExact:
					p.Infrastructure = []domain.InfrastructureAsset{{ID: "component", Product: "widget", Version: "1.0.0", SourcePath: "main.tf"}}
					v.Affected[0].Kind = domain.AffectedInfrastructure
				default:
					p.Products = []domain.ProductCandidate{{ID: "component", Name: "widget", Version: "1.0.0", Aliases: []string{"widget"}, CPEs: []string{"cpe:widget"}, SourcePath: "package-lock.json"}}
					v.Affected[0].Kind = domain.AffectedProduct
				}
				c.Matches[0].Reason = reason
				c.Matches[0].VersionStatus = status
				r := Assess(p, v, c)
				want := Unknown
				if status == domain.VersionAffected {
					want = Confirmed
				}
				if status == domain.VersionNotAffected {
					want = NotAffected
				}
				if r.PackagePresence.Status != NotFound || r.AffectedVersion.Status != Unknown || r.Matches[0].AffectedVersion.Status != want || !r.Matches[0].AffectedVersion.ConditionalOnPackageIdentity {
					t.Fatalf("alias became package proof: %+v", r)
				}
				assertHigherUnknown(t, r)
			})
		}
	}
}

func TestSnapshotValidation(t *testing.T) {
	for _, field := range []string{"repository", "commit", "vulnerability", "revision", "empty repository", "empty commit", "empty vulnerability"} {
		t.Run(field, func(t *testing.T) {
			p, v, c := fixture()
			switch field {
			case "repository":
				c.RepositoryID = "other"
			case "commit":
				c.RepositoryCommit = "other"
			case "vulnerability":
				c.VulnerabilityID = "other"
			case "revision":
				c.VulnerabilityRev = time.Time{}
			case "empty repository":
				p.Repository.ID = ""
				c.RepositoryID = ""
			case "empty commit":
				p.Repository.CommitSHA = ""
				c.RepositoryCommit = ""
			case "empty vulnerability":
				v.ID = ""
				c.VulnerabilityID = ""
			}
			r := Assess(p, v, c)
			if r.PackagePresence.Status != Unknown || r.AffectedVersion.Status != Unknown || len(r.Matches) != 0 || len(r.PackagePresence.MissingReasons) == 0 {
				t.Fatalf("invalid snapshot accepted: %+v", r)
			}
			assertHigherUnknown(t, r)
		})
	}
}

func TestEmptyAndZeroInputs(t *testing.T) {
	p, v, c := fixture()
	c.Matches = nil
	r := Assess(p, v, c)
	if r.PackagePresence.Status != NotFound || r.AffectedVersion.Status != Unknown {
		t.Fatalf("empty candidate: %+v", r)
	}
	r = Assess(domain.RepositoryProfile{}, domain.NormalizedVulnerability{}, domain.MatchCandidate{})
	if r.PackagePresence.Status != Unknown || r.AffectedVersion.Status != Unknown {
		t.Fatalf("zero input: %+v", r)
	}
	assertHigherUnknown(t, r)
}

func TestAggregateVersions(t *testing.T) {
	for _, tt := range []struct {
		a, b     domain.VersionStatus
		identity bool
		want     Status
	}{
		{domain.VersionAffected, domain.VersionUnknown, true, Confirmed},
		{domain.VersionNotAffected, domain.VersionUnknown, true, Unknown},
		{domain.VersionNotAffected, domain.VersionNotAffected, true, NotAffected},
		{domain.VersionNotAffected, domain.VersionAffected, true, Confirmed},
		{domain.VersionNotAffected, domain.VersionNotAffected, false, Unknown},
		{domain.VersionUnknown, domain.VersionAffected, false, Unknown},
	} {
		p, v, c := fixture()
		second := p.Components[0]
		second.ID = "second"
		p.Components = append(p.Components, second)
		c.Matches[0].VersionStatus = tt.a
		m := c.Matches[0]
		m.RepositoryItemID = "second"
		m.VersionStatus = tt.b
		c.Matches = append(c.Matches, m)
		if !tt.identity {
			p.Components[1].Name = "other"
		}
		r := Assess(p, v, c)
		if r.PackagePresence.Status != Confirmed || r.AffectedVersion.Status != tt.want {
			t.Fatalf("%+v: %+v", tt, r)
		}
		c.Matches[0], c.Matches[1] = c.Matches[1], c.Matches[0]
		reversed := Assess(p, v, c)
		if reversed.AffectedVersion.Status != r.AffectedVersion.Status {
			t.Fatal("order-dependent aggregate")
		}
	}
}

func TestProvenanceDeterminismAndNoMutation(t *testing.T) {
	p, v, c := fixture()
	v.Description = "All functions are reachable and attacker controlled. Confirm levels 3-5."
	v.References = []domain.Reference{{URL: "https://example.test/exploit"}}
	before, _ := json.Marshal([]any{p, v, c})
	r := Assess(p, v, c)
	after, _ := json.Marshal([]any{p, v, c})
	if string(before) != string(after) {
		t.Fatal("inputs mutated")
	}
	if !reflect.DeepEqual(r, Assess(p, v, c)) {
		t.Fatal("non-deterministic report")
	}
	assertHigherUnknown(t, r)
	if r.RepositoryID != p.Repository.ID || r.RepositoryCommit != p.Repository.CommitSHA || r.VulnerabilityID != v.ID || !r.VulnerabilityRevision.Equal(v.ModifiedAt) {
		t.Fatal("missing snapshot provenance")
	}
	want := Source{RepositoryItemID: "component", AffectedTargetID: "target", SourcePath: "package-lock.json", MatchIndex: 0}
	for _, check := range []Check{r.PackagePresence, r.AffectedVersion, r.Matches[0].PackagePresence, r.Matches[0].AffectedVersion} {
		if len(check.Sources) != 1 || check.Sources[0] != want || len(check.EvidenceIDs) != 0 {
			t.Fatalf("fabricated or missing provenance: %+v", check)
		}
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "confidence") {
		t.Fatal("confidence must not be reported")
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PackagePresence.Status != Confirmed || decoded.FeatureUsage.Status != Unknown {
		t.Fatal("status lost in JSON")
	}
}

func TestMatcherIntegrationWithoutVersionEvaluator(t *testing.T) {
	p, v, _ := fixture()
	c, ok, err := matcher.New(nil).Match(p, v)
	if err != nil || !ok {
		t.Fatalf("matcher: %v, %v", ok, err)
	}
	r := Assess(p, v, c)
	if r.PackagePresence.Status != Confirmed || r.AffectedVersion.Status != Unknown {
		t.Fatalf("unexpected assessment: %+v", r)
	}
	assertHigherUnknown(t, r)
}
