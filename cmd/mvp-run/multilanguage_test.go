package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vulns-news/src/assessment"
	"vulns-news/src/domain"
	"vulns-news/src/ecosystem/versions"
	"vulns-news/src/feed"
	"vulns-news/src/matcher"
	"vulns-news/src/osv"
	"vulns-news/src/processor"
	"vulns-news/src/repository"
)

// An injected transport exercises the OSV HTTP contract without opening sockets
// or allowing a mistaken endpoint to reach an external service.
type multilanguageTransport func(*http.Request) (*http.Response, error)

func (f multilanguageTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMultilanguagePrivatePipenvDoesNotQueryOSV(t *testing.T) {
	root := t.TempDir()
	// Even a public package name/version must not imply a public identity when
	// its selected index is private, regardless of other configured sources.
	body := `{"_meta":{"pipfile-spec":6,"sources":[{"name":"pypi","url":"https://pypi.org/simple","verify_ssl":true},{"name":"private","url":"https://packages.example.invalid/simple","verify_ssl":true}]},"default":{"urllib3":{"version":"==2.2.1","index":"private"}},"develop":{}}`
	if err := os.WriteFile(filepath.Join(root, "Pipfile.lock"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	profile, err := repository.Profile(&repository.AcquiredRepository{Path: root, Identity: domain.RepositoryIdentity{ID: "example/private", CommitSHA: "abc123"}}, time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.Components) != 0 {
		t.Errorf("private registry yielded public components: %+v", profile.Components)
	}
	if !strings.Contains(strings.Join(profile.Warnings, "\n"), "public PyPI identity not established") {
		t.Errorf("missing provenance warning: %v", profile.Warnings)
	}
	calls := 0
	client, err := osv.NewClient(osv.Config{BaseURL: "https://osv.invalid", HTTPClient: &http.Client{Transport: multilanguageTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("private dependency must not be queried against OSV")
	})}})
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &inspectingAnalyzer{fakeAnalyzer: fakeAnalyzer{relevance: processor.RelevanceRelated}}
	got := processPageWithEnricher(context.Background(), profile, osvPage(), matcher.New(versions.New()), analyzer, client)
	if calls != 0 || got.NVD.Normalized != 1 || got.Matched != 0 || len(got.FeedItems) != 0 || len(got.Errors) != 0 || len(analyzer.inputs) != 0 || analyzer.deepCalls != 0 {
		t.Fatalf("private dependency reached OSV or analysis: requests=%d result=%+v", calls, got)
	}
}

func TestMultilanguageOSVToFeed(t *testing.T) {
	cases := []struct{ label, path, body, ecosystem, osvEcosystem, name, version, purl string }{
		{"Maven Gradle", "gradle.lockfile", "# Generated dependency lock state\norg.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath\n", "maven", "Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core"},
		{"Maven POM", "pom.xml", `<project><modelVersion>4.0.0</modelVersion><dependencies><dependency><groupId>org.hibernate</groupId><artifactId>hibernate-core</artifactId><version>5.6.15.Final</version></dependency></dependencies></project>`, "maven", "Maven", "org.hibernate:hibernate-core", "5.6.15.Final", "pkg:maven/org.hibernate/hibernate-core"},
		{"Packagist", "composer.lock", `{"packages":[{"name":"symfony/http-foundation","version":"v6.4.0"}],"packages-dev":[]}`, "packagist", "Packagist", "symfony/http-foundation", "v6.4.0", "pkg:packagist/symfony/http-foundation"},
		{"NuGet", "packages.lock.json", `{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.3, )","resolved":"13.0.3"}}}}`, "nuget", "NuGet", "newtonsoft.json", "13.0.3", "pkg:nuget/newtonsoft.json"},
		{"RubyGems", "Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.0)\n\nDEPENDENCIES\n  rack\n", "gem", "RubyGems", "rack", "3.1.0", "pkg:gem/rack"},
		{"Cargo", "Cargo.lock", "version = 3\n[[package]]\nname = 'serde'\nversion = '1.0.200'\nsource = 'registry+https://github.com/rust-lang/crates.io-index'\n", "crates.io", "crates.io", "serde", "1.0.200", "pkg:cargo/serde@1.0.200"},
		{"Poetry", "poetry.lock", "[[package]]\nname = 'Django'\nversion = '4.2.0'\n[metadata]\nlock-version = '2.0'\n", "pypi", "PyPI", "django", "4.2.0", "pkg:pypi/django@4.2.0"},
		{"uv", "uv.lock", "version = 1\n[[package]]\nname = 'Requests'\nversion = '2.31.0'\nsource = {registry = 'https://pypi.org/simple'}\n", "pypi", "PyPI", "requests", "2.31.0", "pkg:pypi/requests@2.31.0"},
		{"Pipenv", "Pipfile.lock", `{"_meta":{"pipfile-spec":6,"sources":[{"name":"pypi","url":"https://pypi.org/simple","verify_ssl":true}]},"default":{"urllib3":{"version":"==2.2.1","index":"pypi"}},"develop":{}}`, "pypi", "PyPI", "urllib3", "2.2.1", "pkg:pypi/urllib3"},
		{"Go", "go.mod", "module example.org/app\ngo 1.25\nrequire golang.org/x/text v0.14.0\n", "Go", "Go", "golang.org/x/text", "v0.14.0", "pkg:golang/golang.org/x/text"},
		{"npm", "package-lock.json", `{"name":"web","lockfileVersion":3,"packages":{"node_modules/express":{"version":"4.21.0"}}}`, "npm", "npm", "express", "4.21.0", "pkg:npm/express"},
		{"pnpm", "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  '@babel/core@7.24.0':\n    resolution: {integrity: sha512-example}\n", "npm", "npm", "@babel/core", "7.24.0", "pkg:npm/%40babel/core@7.24.0"},
		{"Yarn", "yarn.lock", "# yarn lockfile v1\n\"lodash@^4.17.21\":\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n", "npm", "npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, tc.path), []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			profile, err := repository.Profile(&repository.AcquiredRepository{Path: root, Identity: domain.RepositoryIdentity{ID: "example/polyglot", CommitSHA: "0123456789012345678901234567890123456789"}}, time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC))
			if err != nil {
				t.Fatal(err)
			}
			if len(profile.Components) != 1 {
				t.Fatalf("components = %+v", profile.Components)
			}
			component := profile.Components[0]
			if component.Ecosystem != tc.ecosystem || component.Name != tc.name || component.Version != tc.version || component.PURL != tc.purl {
				t.Fatalf("profile identity = %+v", component)
			}
			page := osvPage()
			if len(page.Vulnerabilities[0].CVE.Configurations) != 0 {
				t.Fatal("fixture must not supply CPE matches")
			}
			baseline := processPageWithEnricher(context.Background(), profile, page, matcher.New(versions.New()), &fakeAnalyzer{}, nil)
			if baseline.Matched != 0 || len(baseline.FeedItems) != 0 || len(baseline.Errors) != 0 {
				t.Fatalf("unexpected match without OSV: %+v", baseline)
			}

			for _, positive := range []bool{true, false} {
				t.Run(fmt.Sprintf("CVE_alias_matches=%t", positive), func(t *testing.T) {
					calls := 0
					client, err := osv.NewClient(osv.Config{BaseURL: "https://osv.invalid", HTTPClient: &http.Client{Transport: multilanguageTransport(func(r *http.Request) (*http.Response, error) {
						calls++
						if r.Method != http.MethodPost || r.URL.String() != "https://osv.invalid/v1/query" {
							t.Errorf("unexpected request: %s %s", r.Method, r.URL)
						}
						var query struct {
							Package struct {
								Ecosystem string `json:"ecosystem"`
								Name      string `json:"name"`
							} `json:"package"`
							Version string `json:"version"`
						}
						if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
							return nil, err
						}
						if query.Package.Ecosystem != tc.osvEcosystem || query.Package.Name != tc.name || query.Version != tc.version {
							t.Errorf("OSV identity = %+v, want %s / %s / %s", query, tc.osvEcosystem, tc.name, tc.version)
						}
						alias := "CVE-2026-9999"
						if positive {
							alias = page.Vulnerabilities[0].CVE.ID
						}
						body := fmt.Sprintf(`{"vulns":[{"id":"GHSA-2345-6789-cfgh","aliases":[%q]}]}`, alias)
						return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
					})}})
					if err != nil {
						t.Fatal(err)
					}
					analyzer := &inspectingAnalyzer{fakeAnalyzer: fakeAnalyzer{relevance: processor.RelevanceRelated}}
					got := processPageWithEnricher(context.Background(), profile, page, matcher.New(versions.New()), analyzer, client)
					if calls != 1 || got.NVD.Normalized != 1 || len(got.Errors) != 0 {
						t.Fatalf("requests=%d result=%+v", calls, got)
					}
					if !positive {
						if got.Matched != 0 || len(got.FeedItems) != 0 || len(analyzer.inputs) != 0 || analyzer.deepCalls != 0 {
							t.Fatalf("unrelated OSV CVE generated a match: %+v", got)
						}
						return
					}
					if got.Matched != 1 || len(got.FeedItems) != 1 || len(analyzer.inputs) != 1 || analyzer.deepCalls != 1 {
						t.Fatalf("enrichment did not reach analysis/feed: %+v", got)
					}
					input := analyzer.inputs[0]
					if len(input.Vulnerability.Affected) != 1 {
						t.Fatalf("targets = %+v", input.Vulnerability.Affected)
					}
					target := input.Vulnerability.Affected[0]
					if target.Ecosystem != tc.ecosystem || target.PackageName != tc.name || len(target.Constraints) != 1 || target.Constraints[0] != (domain.VersionConstraint{Scheme: "osv", Expression: tc.version}) {
						t.Errorf("OSV exact-version target = %+v", target)
					}
					item := got.FeedItems[0]
					if item.CVEID != page.Vulnerabilities[0].CVE.ID || item.RepositoryID != profile.Repository.ID || item.RepositoryCommit != profile.Repository.CommitSHA || item.Status != feed.StatusAnalyzed {
						t.Errorf("feed identity/status = %+v", item)
					}
					if len(item.Matches) != 1 {
						t.Fatalf("feed matches = %+v", item.Matches)
					}
					match := item.Matches[0]
					if match.RepositoryItemID != component.ID || match.AffectedTargetID != target.ID || match.InstalledVersion != tc.version || match.VersionStatus != domain.VersionAffected {
						t.Errorf("OSV match lost in feed: %+v", match)
					}
					report := item.Applicability
					if report.PackagePresence.Status != assessment.Confirmed || report.AffectedVersion.Status != assessment.Confirmed {
						t.Errorf("L1/L2 = %+v", report)
					}
					for i, check := range []assessment.Check{report.FeatureUsage, report.CodeReachability, report.AttackConditions} {
						if check.Level != i+3 || check.Status != assessment.Unknown || len(check.MissingReasons) == 0 || len(check.EvidenceIDs) != 0 {
							t.Errorf("L%d must remain unknown: %+v", i+3, check)
						}
					}
					osvEvidence := 0
					for _, evidence := range item.Evidence {
						if evidence.Source == "OSV" {
							osvEvidence++
							if evidence.Kind != processor.EvidenceAdvisory || !strings.Contains(evidence.Content, "not NVD") {
								t.Errorf("OSV provenance lost: %+v", evidence)
							}
						}
					}
					if osvEvidence != 1 {
						t.Errorf("OSV evidence count = %d, want one", osvEvidence)
					}
				})
			}
		})
	}
}
