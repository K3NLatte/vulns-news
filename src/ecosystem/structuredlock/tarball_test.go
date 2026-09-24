package structuredlock

import (
	"fmt"
	"strings"
	"testing"
)

func TestTarballIdentity(t *testing.T) {
	cases := []struct {
		label, name, version, path string
		accept                     bool
	}{
		{"unscoped", "foo", "1.0.0", "/foo/-/foo-1.0.0.tgz", true},
		{"hyphenated", "foo-bar", "1.0.0", "/foo-bar/-/foo-bar-1.0.0.tgz", true},
		{"scoped", "@scope/foo", "1.0.0", "/@scope/foo/-/foo-1.0.0.tgz", true},
		{"encoded scope marker", "@scope/foo", "1.0.0", "/%40scope/foo/-/foo-1.0.0.tgz", true},
		{"encoded scoped separator", "@scope/foo", "1.0.0", "/@scope%2ffoo/-/foo-1.0.0.tgz", true},
		{"encoded scoped name", "@scope/foo", "1.0.0", "/%40scope%2Ffoo/-/foo-1.0.0.tgz", true},
		{"prerelease", "foo", "1.0.0-beta.2", "/foo/-/foo-1.0.0-beta.2.tgz", true},
		{"build metadata", "foo", "1.0.0+build.1", "/foo/-/foo-1.0.0%2Bbuild.1.tgz", true},
		{"different name and version", "foo", "1.0.0", "/bar/-/bar-2.0.0.tgz", false},
		{"different directory", "foo", "1.0.0", "/bar/-/foo-1.0.0.tgz", false},
		{"different filename name", "foo", "1.0.0", "/foo/-/bar-1.0.0.tgz", false},
		{"different version", "foo", "1.0.0", "/foo/-/foo-2.0.0.tgz", false},
		{"version prefix", "foo", "1.0.0", "/foo/-/foo-1.0.0-beta.2.tgz", false},
		{"version prefix digits", "foo", "1.0.0", "/foo/-/foo-1.0.01.tgz", false},
		{"different scope", "@scope/foo", "1.0.0", "/@other/foo/-/foo-1.0.0.tgz", false},
		{"encoded conflicting scope", "@scope/foo", "1.0.0", "/%40other%2Ffoo/-/foo-1.0.0.tgz", false},
		{"scoped wrong version", "@scope/foo", "1.0.0", "/@scope%2Ffoo/-/foo-2.0.0.tgz", false},
		{"scope in filename", "@scope/foo", "1.0.0", "/@scope/foo/-/@scope/foo-1.0.0.tgz", false},
		{"double encoding", "@scope/foo", "1.0.0", "/%2540scope%252Ffoo/-/foo-1.0.0.tgz", false},
		{"unrecognized path", "foo", "1.0.0", "/download/foo-1.0.0.tgz", false},
		{"missing filename", "foo", "1.0.0", "/foo/-/", false},
		{"extra suffix", "foo", "1.0.0", "/foo/-/foo-1.0.0.tgz/extra", false},
		{"different extension", "foo", "1.0.0", "/foo/-/foo-1.0.0.zip", false},
		{"path traversal", "foo", "1.0.0", "/foo/-/../-/foo-1.0.0.tgz", false},
		{"query override", "foo", "1.0.0", "/foo/-/foo-1.0.0.tgz?other=2.0.0", false},
	}
	for _, format := range []string{"pnpm6", "pnpm9", "classic npm", "classic yarn"} {
		t.Run(format, func(t *testing.T) {
			for _, tt := range cases {
				t.Run(tt.label, func(t *testing.T) {
					host := "registry.npmjs.org"
					if format == "classic yarn" {
						host = "registry.yarnpkg.com"
					}
					tarball := "https://" + host + tt.path
					var file, body string
					if strings.HasPrefix(format, "pnpm") {
						version, prefix := "9.0", ""
						if format == "pnpm6" {
							version, prefix = "6.0", "/"
						}
						file = "pnpm-lock.yaml"
						// Integrity must not override a conflicting explicit tarball identity.
						body = fmt.Sprintf("lockfileVersion: %q\npackages:\n  %q:\n    resolution: {integrity: sha512-example, tarball: %q}\n", version, prefix+tt.name+"@"+tt.version+"(peer@2.0.0)", tarball)
					} else {
						file = "yarn.lock"
						body = fmt.Sprintf("# yarn lockfile v1\n%q:\n  version %q\n  resolved %q\n", tt.name+"@^1.0.0", tt.version, tarball+"#abc123")
					}
					root := t.TempDir()
					put(t, root, file, body)
					got, err := Profile(root)
					if err != nil {
						t.Fatal(err)
					}
					if tt.accept {
						if len(got.Components) != 1 || len(got.Warnings) != 0 {
							t.Fatalf("valid tarball rejected: %+v", got)
						}
						if c := got.Components[0]; c.Name != tt.name || c.Version != tt.version {
							t.Fatalf("incorrect identity: %+v", c)
						}
					} else {
						if len(got.Components) != 0 || len(got.Warnings) != 1 {
							t.Fatalf("conflicting or unrecognized tarball not skipped: %+v", got)
						}
						if !strings.HasPrefix(got.Warnings[0], file+": ") || !strings.Contains(got.Warnings[0], "skipped") {
							t.Fatalf("missing source-qualified skip warning: %v", got.Warnings)
						}
					}
				})
			}
		})
	}
}
