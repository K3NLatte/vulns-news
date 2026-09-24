package staticprofile

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	goModule        = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+$`)
	goVersion       = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+incompatible)?$`)
	pythonName      = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(\[[A-Za-z0-9_,. -]+\])?(.*)$`)
	normalizePython = regexp.MustCompile(`[-_.]+`)
	// A conservative subset of PEP 440: arbitrary === equality and wildcards
	// are intentionally not treated as exact versions.
	pythonVersion = regexp.MustCompile(`(?i)^v?([0-9]+!)?[0-9]+(\.[0-9]+)*((a|b|rc)[0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?(\+[a-z0-9]+([._-][a-z0-9]+)*)?$`)
)

// parseGo only inventories require directives; go.sum is deliberately ignored.
// Replacement/exclusion directives invalidate resolved-version claims, so all
// requirements in such a file retain their names but have unknown versions.
func (f *ProfileFragment) parseGo(source, text string) {
	start := len(f.Components)
	block := ""
	unresolved := false
	for i, raw := range strings.Split(text, "\n") {
		code, comment, _ := strings.Cut(raw, "//")
		fields := strings.Fields(code)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == ")" {
			if block == "" || len(fields) != 1 {
				f.warn(source, i+1, "malformed Go directive block")
			}
			block = ""
			continue
		}
		directive := block
		if directive == "" {
			directive = fields[0]
			fields = fields[1:]
			if directive == "replace" || directive == "exclude" {
				unresolved = true
				f.warn(source, i+1, "Go replace/exclude is not resolved; requirement versions are unknown")
			}
			if len(fields) == 1 && fields[0] == "(" {
				block = directive
				continue
			}
		}
		if directive != "require" {
			continue
		}
		if len(fields) == 0 || len(fields) > 2 {
			f.warn(source, i+1, "unsupported or malformed Go require directive")
			continue
		}
		name := goToken(fields[0])
		if !goModule.MatchString(name) || strings.Contains(name, "//") || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
			f.warn(source, i+1, "invalid Go module path")
			continue
		}
		version := ""
		if len(fields) == 2 {
			version = goToken(fields[1])
		}
		if !goVersion.MatchString(version) {
			version = ""
			f.warn(source, i+1, "missing or unsupported Go requirement version")
		}
		f.add(source, "Go", name, version, strings.TrimSpace(comment) != "indirect")
	}
	if block != "" {
		f.warn(source, 0, "unterminated Go directive block")
	}
	if unresolved {
		var old []struct {
			name   string
			direct bool
		}
		for _, c := range f.Components[start:] {
			old = append(old, struct {
				name   string
				direct bool
			}{c.Name, c.Direct})
		}
		f.Components = f.Components[:start]
		for _, c := range old {
			f.add(source, "Go", c.name, "", c.direct)
		}
	}
}

func goToken(token string) string {
	if strings.HasPrefix(token, `"`) || strings.HasPrefix(token, "`") {
		value, err := strconv.Unquote(token)
		if err != nil {
			return ""
		}
		return value
	}
	return token
}

func (f *ProfileFragment) parseRequirements(source, text string) {
	continuing := false
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		wasContinuing := continuing
		continuing = strings.HasSuffix(line, "\\")
		if wasContinuing {
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// pip treats a hash preceded by whitespace as a comment, not a URL fragment.
		for j := 1; j < len(line); j++ {
			if line[j] == '#' && (line[j-1] == ' ' || line[j-1] == '\t') {
				line = strings.TrimSpace(line[:j])
				break
			}
		}
		if strings.HasPrefix(line, "-") {
			f.warn(source, i+1, "unsupported requirements option/include; not followed")
			continue
		}
		match := pythonName.FindStringSubmatch(line)
		if match == nil {
			f.warn(source, i+1, "unsupported requirement; no package identity inferred")
			continue
		}
		rest := strings.TrimSpace(match[3])
		// Do not mistake URLs or local paths for package names.
		if rest != "" && !strings.ContainsAny(rest[:1], "=<>!~@;\\") {
			f.warn(source, i+1, "unsupported requirement; no package identity inferred")
			continue
		}
		name := normalizePython.ReplaceAllString(strings.ToLower(match[1]), "-")
		version := ""
		if strings.HasPrefix(rest, "==") && !strings.HasPrefix(rest, "===") && !continuing {
			candidate := strings.TrimSpace(rest[2:])
			if pythonVersion.MatchString(candidate) {
				version = candidate
			}
		}
		if version == "" {
			f.warn(source, i+1, "unresolved requirement: unpinned, range, marker, URL, option, or unsupported version")
		}
		f.add(source, "pypi", name, version, true)
	}
}
