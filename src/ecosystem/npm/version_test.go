package npm

import (
	"testing"

	"vulns-news/src/domain"
)

func TestVersionEvaluatorEvaluate(t *testing.T) {
	tests := []struct {
		name        string
		ecosystem   string
		installed   string
		constraints []domain.VersionConstraint
		want        domain.VersionStatus
	}{
		{
			name:      "exact expression",
			ecosystem: "npm",
			installed: "v1.2.3",
			constraints: []domain.VersionConstraint{{
				Scheme: "semver", Expression: "1.2.3",
			}},
			want: domain.VersionAffected,
		},
		{
			name:      "exact expression excludes another version",
			ecosystem: "npm",
			installed: "1.2.4",
			constraints: []domain.VersionConstraint{{
				Scheme: "npm", Expression: "1.2.3",
			}},
			want: domain.VersionNotAffected,
		},
		{
			name:      "build metadata does not change precedence",
			ecosystem: "npm",
			installed: "1.2.3+installed.7",
			constraints: []domain.VersionConstraint{{
				Scheme: "semver", Expression: "1.2.3+advisory.9",
			}},
			want: domain.VersionAffected,
		},
		{
			name:      "inclusive NVD boundaries",
			ecosystem: "npm",
			installed: "1.4.0",
			constraints: []domain.VersionConstraint{{
				Scheme: "cpe", VersionStartIncluding: "1.0.0", VersionEndIncluding: "1.4.0",
			}},
			want: domain.VersionAffected,
		},
		{
			name:      "exclusive lower boundary",
			ecosystem: "npm",
			installed: "1.0.0",
			constraints: []domain.VersionConstraint{{
				Scheme: "cpe", VersionStartExcluding: "1.0.0", VersionEndExcluding: "2.0.0",
			}},
			want: domain.VersionNotAffected,
		},
		{
			name:      "exclusive upper boundary",
			ecosystem: "npm",
			installed: "2.0.0",
			constraints: []domain.VersionConstraint{{
				Scheme: "cpe", VersionStartIncluding: "1.0.0", VersionEndExcluding: "2.0.0",
			}},
			want: domain.VersionNotAffected,
		},
		{
			name:      "numeric prerelease identifiers use numeric order",
			ecosystem: "npm",
			installed: "1.0.0-beta.2",
			constraints: []domain.VersionConstraint{{
				Scheme: "semver", VersionStartIncluding: "1.0.0-beta.1", VersionEndExcluding: "1.0.0-beta.11",
			}},
			want: domain.VersionAffected,
		},
		{
			name:      "prerelease sorts before release",
			ecosystem: "npm",
			installed: "1.0.0-rc.1",
			constraints: []domain.VersionConstraint{{
				Scheme: "semver", VersionEndExcluding: "1.0.0",
			}},
			want: domain.VersionAffected,
		},
		{
			name:      "release sorts after prerelease",
			ecosystem: "npm",
			installed: "1.0.0",
			constraints: []domain.VersionConstraint{{
				Scheme: "semver", VersionEndIncluding: "1.0.0-rc.9",
			}},
			want: domain.VersionNotAffected,
		},
		{
			name:      "any matching constraint is affected",
			ecosystem: "npm",
			installed: "3.1.4",
			constraints: []domain.VersionConstraint{
				{Scheme: "semver", Expression: "2.0.0"},
				{Scheme: "semver", VersionStartIncluding: "3.0.0", VersionEndExcluding: "4.0.0"},
			},
			want: domain.VersionAffected,
		},
		{
			name:      "affected match wins over unsupported constraint",
			ecosystem: "npm",
			installed: "1.2.3",
			constraints: []domain.VersionConstraint{
				{Scheme: "pep440", Expression: "1.2.3"},
				{Scheme: "semver", Expression: "1.2.3"},
			},
			want: domain.VersionAffected,
		},
		{
			name:      "all applicable constraints exclude",
			ecosystem: "npm",
			installed: "5.0.0",
			constraints: []domain.VersionConstraint{
				{Scheme: "semver", VersionEndExcluding: "2.0.0"},
				{Scheme: "cpe", VersionStartIncluding: "6.0.0"},
			},
			want: domain.VersionNotAffected,
		},
		{
			name:      "unsupported ecosystem",
			ecosystem: "pypi",
			installed: "1.2.3",
			constraints: []domain.VersionConstraint{{
				Scheme: "semver", Expression: "1.2.3",
			}},
			want: domain.VersionUnknown,
		},
		{
			name:      "unsupported scheme",
			ecosystem: "npm",
			installed: "1.2.3",
			constraints: []domain.VersionConstraint{{
				Scheme: "pep440", Expression: "1.2.3",
			}},
			want: domain.VersionUnknown,
		},
		{
			name:      "range expression is unsupported",
			ecosystem: "npm",
			installed: "1.2.3",
			constraints: []domain.VersionConstraint{{
				Scheme: "semver", Expression: "^1.0.0",
			}},
			want: domain.VersionUnknown,
		},
		{
			name:      "partial version is unsupported",
			ecosystem: "npm",
			installed: "1.2",
			constraints: []domain.VersionConstraint{{
				Scheme: "semver", VersionEndExcluding: "2.0.0",
			}},
			want: domain.VersionUnknown,
		},
		{
			name:      "leading zero is invalid",
			ecosystem: "npm",
			installed: "01.2.3",
			constraints: []domain.VersionConstraint{{
				Scheme: "semver", Expression: "1.2.3",
			}},
			want: domain.VersionUnknown,
		},
		{
			name:      "malformed boundary is unknown",
			ecosystem: "npm",
			installed: "1.2.3",
			constraints: []domain.VersionConstraint{{
				Scheme: "semver", VersionStartIncluding: "2.0.0", VersionEndExcluding: "not-a-version",
			}},
			want: domain.VersionUnknown,
		},
		{
			name:      "unsupported constraint prevents exclusion conclusion",
			ecosystem: "npm",
			installed: "3.0.0",
			constraints: []domain.VersionConstraint{
				{Scheme: "semver", VersionEndExcluding: "2.0.0"},
				{Scheme: "semver", Expression: ">=3.0.0"},
			},
			want: domain.VersionUnknown,
		},
		{
			name:      "conflicting boundaries are unknown",
			ecosystem: "npm",
			installed: "1.2.3",
			constraints: []domain.VersionConstraint{{
				Scheme: "semver", VersionStartIncluding: "1.0.0", VersionStartExcluding: "1.0.0",
			}},
			want: domain.VersionUnknown,
		},
		{
			name:        "no constraints",
			ecosystem:   "npm",
			installed:   "1.2.3",
			constraints: nil,
			want:        domain.VersionUnknown,
		},
	}

	evaluator := NewVersionEvaluator()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := evaluator.Evaluate(test.ecosystem, test.installed, test.constraints)
			if err != nil {
				t.Fatalf("Evaluate returned error: %v", err)
			}
			if got != test.want {
				t.Errorf("Evaluate(%q, %q, %#v) = %q, want %q", test.ecosystem, test.installed, test.constraints, got, test.want)
			}
		})
	}
}
