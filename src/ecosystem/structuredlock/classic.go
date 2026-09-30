package structuredlock

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Classic's indentation-based grammar predates YAML. Only its scalar fields and
// one-level dependency maps are accepted; unfamiliar syntax fails closed.
func classicScalar(raw string) (string, error) {
	if strings.HasPrefix(raw, "\"") {
		return strconv.Unquote(raw)
	}
	if raw == "" || strings.ContainsAny(raw, "\"\t\r\n") {
		return "", fmt.Errorf("invalid classic scalar %q", raw)
	}
	return raw, nil
}
func classicSelectors(raw string) ([]string, error) {
	var result []string
	for len(raw) > 0 {
		end := 0
		if raw[0] == '"' {
			end = 1
			for end < len(raw) {
				if raw[end] == '\\' {
					end += 2
					continue
				}
				if raw[end] == '"' {
					end++
					break
				}
				end++
			}
			if end > len(raw) {
				return nil, fmt.Errorf("invalid selector")
			}
		} else {
			end = strings.IndexByte(raw, ',')
			if end < 0 {
				end = len(raw)
			}
		}
		value, err := classicScalar(strings.TrimSpace(raw[:end]))
		if err != nil {
			return nil, err
		}
		result = append(result, value)
		raw = strings.TrimSpace(raw[end:])
		if raw == "" {
			break
		}
		if raw[0] != ',' {
			return nil, fmt.Errorf("invalid selector separator")
		}
		raw = strings.TrimSpace(raw[1:])
		if raw == "" {
			return nil, fmt.Errorf("empty selector")
		}
	}
	return result, nil
}
func (s *state) parseClassic(file string, b []byte) error {
	var selectors []string
	fields := map[string]string{}
	nested := false
	seenNested := map[string]bool{}
	flush := func() error {
		if len(selectors) == 0 {
			return nil
		}
		name := ""
		valid := true
		for _, selector := range selectors {
			if len(selector) < 2 {
				return fmt.Errorf("invalid classic selector %q", selector)
			}
			i := strings.IndexByte(selector[1:], '@') + 1
			if i <= 0 {
				return fmt.Errorf("invalid classic selector %q", selector)
			}
			n, spec := selector[:i], selector[i+1:]
			if name == "" {
				name = n
			}
			if n != name || spec == "" || strings.ContainsAny(spec, ":/\\") {
				valid = false
			}
		}
		resolved := fields["resolved"]
		u, err := url.Parse(resolved)
		if err != nil || u == nil || u.Scheme != "https" || (u.Host != "registry.yarnpkg.com" && u.Host != "registry.npmjs.org") || u.User != nil || u.RawQuery != "" {
			valid = false
		}
		if !valid {
			s.warn(file, fmt.Sprintf("%q: non-registry or unknown classic resolution skipped", strings.Join(selectors, ", ")))
			return nil
		}
		if !npmTarballMatches(u, name, fields["version"]) {
			s.warn(file, fmt.Sprintf("%q: unrecognized or conflicting classic tarball identity skipped", name))
			return nil
		}
		return s.add(file, "npm", name, fields["version"])
	}
	for number, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		text := strings.TrimSpace(line)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fail := func() error { return fmt.Errorf("line %d: unsupported or malformed classic syntax", number+1) }
		if strings.ContainsRune(line, '\t') {
			return fail()
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			if !strings.HasSuffix(text, ":") {
				return fail()
			}
			if err := flush(); err != nil {
				return err
			}
			var err error
			selectors, err = classicSelectors(strings.TrimSuffix(text, ":"))
			if err != nil {
				return err
			}
			if len(selectors) == 0 {
				return fail()
			}
			fields = map[string]string{}
			seenNested = map[string]bool{}
			nested = false
			continue
		}
		if len(selectors) == 0 {
			return fail()
		}
		if indent == 2 && strings.HasSuffix(text, ":") {
			key := strings.TrimSuffix(text, ":")
			if key != "dependencies" && key != "optionalDependencies" && key != "peerDependencies" {
				return fail()
			}
			if seenNested[key] {
				return fail()
			}
			seenNested[key] = true
			nested = true
			continue
		}
		if indent != 2 && !(indent == 4 && nested) {
			return fail()
		}
		// Find the separator after a possibly quoted key.
		split := strings.IndexByte(text, ' ')
		if strings.HasPrefix(text, "\"") {
			split = -1
			for i := 1; i < len(text); i++ {
				if text[i] == '\\' {
					i++
					continue
				}
				if text[i] == '"' {
					if i+1 < len(text) && text[i+1] == ' ' {
						split = i + 1
					}
					break
				}
			}
		}
		if split <= 0 {
			return fail()
		}
		key, err := classicScalar(text[:split])
		if err != nil {
			return err
		}
		value, err := classicScalar(strings.TrimSpace(text[split+1:]))
		if err != nil {
			return err
		}
		if indent == 2 {
			nested = false
			switch key {
			case "version", "resolved", "integrity", "uid":
			default:
				return fail()
			}
			if _, ok := fields[key]; ok {
				return fail()
			}
			fields[key] = value
		}
	}
	return flush()
}
