package lockprofile

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPipenvPublicProvenance(t *testing.T) {
	const public = `{"name":"public","url":"https://pypi.org/simple","verify_ssl":true}`
	const private = `{"name":"private","url":"https://user:secret@private.test/simple"}`
	cases := []struct {
		name, meta, index string
		want              bool
	}{
		{"explicit public", `{"sources":[` + public + `]}`, `,"index":"public"`, true},
		{"public only unindexed", `{"sources":[` + public + `]}`, "", true},
		{"public selected among private", `{"sources":[` + private + `,` + public + `]}`, `,"index":"public"`, true},
		{"private selected among public", `{"sources":[` + public + `,` + private + `]}`, `,"index":"private"`, false},
		{"mixed unindexed", `{"sources":[` + public + `,` + private + `]}`, "", false},
		{"unknown index", `{"sources":[` + public + `]}`, `,"index":"unknown"`, false},
		{"empty index", `{"sources":[` + public + `]}`, `,"index":""`, false},
		{"missing metadata", "", "", false},
		{"missing metadata explicit public name", "", `,"index":"pypi"`, false},
		{"missing sources", `{"pipfile-spec":6}`, "", false},
		{"empty sources", `{"sources":[]}`, "", false},
		{"private only unindexed", `{"sources":[` + private + `]}`, "", false},
		{"public name private URL", `{"sources":[{"name":"pypi","url":"https://private.test/simple"}]}`, `,"index":"pypi"`, false},
		{"duplicate name", `{"sources":[` + public + `,{"name":"public","url":"https://private.test/simple"}]}`, `,"index":"public"`, false},
		{"duplicate name reverse", `{"sources":[{"name":"public","url":"https://private.test/simple"},` + public + `]}`, `,"index":"public"`, false},
		{"missing URL", `{"sources":[{"name":"public"}]}`, `,"index":"public"`, false},
		{"missing name", `{"sources":[{"url":"https://pypi.org/simple"}]}`, "", false},
		{"disabled TLS validation", `{"sources":[{"name":"public","url":"https://pypi.org/simple","verify_ssl":false}]}`, `,"index":"public"`, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			prefix := ""
			if tt.meta != "" {
				prefix = `"_meta":` + tt.meta + `,`
			}
			// Check both dependency sections, with the same public package name/version
			// that would otherwise be a candidate for public vulnerability matching.
			entry := `{"urllib3":{"version":"==2.2.1"` + tt.index + `}}`
			root := t.TempDir()
			fixture(t, root, "Pipfile.lock", "{"+prefix+`"default":`+entry+`,"develop":`+entry+"}")
			got, err := Profile(root)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			if tt.want {
				count = 2
			}
			if len(got.Components) != count {
				t.Fatalf("components: %+v; warnings: %v", got.Components, got.Warnings)
			}
			if !tt.want && !strings.Contains(strings.Join(got.Warnings, "\n"), "public PyPI identity not established") {
				t.Fatalf("missing provenance warning: %v", got.Warnings)
			}
			if strings.Contains(strings.Join(got.Warnings, "\n"), "secret") {
				t.Fatal("warning leaked credentials")
			}
			if len(got.Ecosystems) != 1 {
				t.Fatal("omitted components should still record ecosystem usage")
			}
		})
	}
}

func TestPublicRegistryEndpointValidation(t *testing.T) {
	for _, host := range []string{"pypi.org", "rubygems.org"} {
		endpoint := ""
		if host == "pypi.org" {
			endpoint = "/simple"
		}
		for _, address := range []string{"https://" + host + endpoint, "https://" + host + endpoint + "/", "https://" + strings.ToUpper(host) + ":443" + endpoint} {
			if !publicRegistry(address, host, endpoint) {
				t.Errorf("public endpoint rejected: %s", address)
			}
		}
		for _, address := range []string{
			"http://" + host + endpoint, "https://" + host + ".evil.test" + endpoint,
			"https://" + host + "@evil.test" + endpoint, "https://user:secret@" + host + endpoint,
			"https://" + host + ":8443" + endpoint, "https://" + host + endpoint + "?secret=x",
			"https://" + host + endpoint + "?", "https://" + host + endpoint + "#fragment",
			"https://" + host + endpoint + "#", "https://" + host + endpoint + "/private",
			"https://" + host + "/../" + strings.TrimPrefix(endpoint, "/"),
			"https://" + host + "/%73imple", "https://${REGISTRY}" + endpoint, "not a URL",
		} {
			if publicRegistry(address, host, endpoint) {
				t.Errorf("untrusted endpoint accepted: %s", address)
			}
			root := t.TempDir()
			name := "Gemfile.lock"
			data := "GEM\n  remote: " + address + "\n  specs:\n    rack (3.1.0)\n"
			if host == "pypi.org" {
				name = "Pipfile.lock"
				encoded, _ := json.Marshal(address)
				data = `{"_meta":{"sources":[{"name":"pypi","url":` + string(encoded) + `}]},"default":{"urllib3":{"index":"pypi","version":"==2.2.1"}}}`
			}
			fixture(t, root, name, data)
			got, err := Profile(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Components) != 0 || len(got.Warnings) == 0 {
				t.Fatalf("untrusted endpoint yielded component: %s %+v", address, got)
			}
		}
	}
}

func TestGemPublicProvenance(t *testing.T) {
	cases := []struct {
		name, remotes string
		want          bool
	}{
		{"public", "  remote: https://rubygems.org/\n", true},
		{"missing", "", false},
		{"empty", "  remote: \n", false},
		{"private", "  remote: https://private.test/\n", false},
		{"mixed public first", "  remote: https://rubygems.org/\n  remote: https://private.test/\n", false},
		{"mixed public last", "  remote: https://private.test/\n  remote: https://rubygems.org/\n", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			fixture(t, root, "Gemfile.lock", "GEM\n"+tt.remotes+"  specs:\n    rack (3.1.0)\n      base (~> 1)\nDEPENDENCIES\n  rack\n")
			got, err := Profile(root)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			if tt.want {
				count = 1
			}
			if len(got.Components) != count {
				t.Fatalf("components: %+v", got)
			}
			if !tt.want && !strings.Contains(strings.Join(got.Warnings, "\n"), "public RubyGems identity not established") {
				t.Fatalf("missing warning: %v", got.Warnings)
			}
		})
	}
	t.Run("block isolation", func(t *testing.T) {
		root := t.TempDir()
		fixture(t, root, "Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    public-first (1.0)\nGEM\n  remote: https://private.test/\n  specs:\n    rack (3.1.0)\nGEM\n  specs:\n    missing (1.0)\nGEM\n  remote: https://rubygems.org/\n  specs:\n    public-last (2.0)\nDEPENDENCIES\n  rack\n  missing\n  public-first\n  public-last\n")
		got, err := Profile(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Components) != 2 {
			t.Fatal(got)
		}
		for _, c := range got.Components {
			if !strings.HasPrefix(c.Name, "public-") || !c.Direct {
				t.Fatal(c)
			}
		}
	})
}

func TestPOMSystemScopeOmitted(t *testing.T) {
	for _, scope := range []string{"system", "${local.scope}"} {
		t.Run(scope, func(t *testing.T) {
			root := t.TempDir()
			fixture(t, root, "pom.xml", fmt.Sprintf(`<project><properties><local.scope>system</local.scope></properties><dependencies><dependency><groupId>org.example</groupId><artifactId>local</artifactId><version>1.2.3</version><scope>%s</scope><systemPath>${project.basedir}/lib/local.jar</systemPath></dependency><dependency><groupId>org.example</groupId><artifactId>ordinary</artifactId><version>1.2.3</version></dependency></dependencies></project>`, scope))
			got, err := Profile(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Components) != 1 || got.Components[0].Name != "ordinary" {
				t.Fatal(got)
			}
			if !strings.Contains(strings.Join(got.Warnings, "\n"), "system-scoped local JAR omitted") {
				t.Fatal(got.Warnings)
			}
		})
	}
}

func TestMalformedPipProvenance(t *testing.T) {
	for _, data := range []string{
		`{"_meta":null,"default":{}}`, `{"_meta":{"sources":{}},"default":{}}`,
		`{"_meta":{"sources":[null]},"default":{}}`,
		`{"_meta":{"sources":[{"name":4}]},"default":{}}`,
		`{"_meta":{"sources":[{"name":"x","url":4}]},"default":{}}`,
		`{"_meta":{"sources":[{"name":"x","verify_ssl":"true"}]},"default":{}}`,
		`{"default":{"a":{"version":"==1","index":4}}}`,
	} {
		root := t.TempDir()
		fixture(t, root, "Pipfile.lock", data)
		got, err := Profile(root)
		if err == nil || !reflect.DeepEqual(got, Fragment{}) {
			t.Fatalf("malformed provenance accepted: %+v %v", got, err)
		}
	}
}
