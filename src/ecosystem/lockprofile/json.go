package lockprofile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Token validation rejects duplicate keys (otherwise encoding/json silently uses
// the last value) and bounds nesting before any format-specific interpretation.
func jsonObject(data []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		if depth > 64 {
			return nil, fmt.Errorf("JSON nesting limit exceeded")
		}
		t, err := d.Token()
		if err != nil {
			return nil, err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return t, nil
		}
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				t, err := d.Token()
				if err != nil {
					return nil, err
				}
				k, ok := t.(string)
				if !ok {
					return nil, fmt.Errorf("expected object key")
				}
				if _, ok := m[k]; ok {
					return nil, fmt.Errorf("duplicate JSON key %q", k)
				}
				v, err := value(depth + 1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			if _, err := d.Token(); err != nil {
				return nil, err
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, err := value(depth + 1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := d.Token(); err != nil {
				return nil, err
			}
			return a, nil
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter")
		}
	}
	v, err := value(0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return object(v, "document")
}
func object(v any, label string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	return m, nil
}
func array(v any, label string) ([]any, error) {
	a, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", label)
	}
	return a, nil
}
func text(m map[string]any, key string, required bool) (string, error) {
	v, ok := m[key]
	if !ok && !required {
		return "", nil
	}
	s, ok := v.(string)
	if !ok || (required && strings.TrimSpace(s) == "") {
		return "", fmt.Errorf("%s must be a nonempty string", key)
	}
	return s, nil
}

var pythonName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var pythonSeparators = regexp.MustCompile(`[-_.]+`)
var composerName = regexp.MustCompile(`^[a-z0-9_.-]+/[a-z0-9_.-]+$`)
var pythonVersion = regexp.MustCompile(`(?i)^v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?(?:-[0-9]+|[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?(?:[-_.]?dev[-_.]?[0-9]*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)
var releaseVersion = regexp.MustCompile(`^v?[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?(?:\+[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$`)
var swiftVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?(?:\+[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$`)

func parsePip(f *Fragment, file string, data []byte) error {
	m, err := jsonObject(data)
	if err != nil {
		return err
	}
	sources, allPublic, err := pipSources(m)
	if err != nil {
		return err
	}
	found := false
	for _, section := range []string{"default", "develop"} {
		v, ok := m[section]
		if !ok {
			continue
		}
		found = true
		deps, err := object(v, section)
		if err != nil {
			return err
		}
		for _, name := range keys(deps) {
			p, err := object(deps[name], name)
			if err != nil {
				return err
			}
			if !pythonName.MatchString(name) {
				return fmt.Errorf("invalid PyPI name %q", name)
			}
			unsupported := false
			for _, key := range []string{"git", "hg", "svn", "bzr", "path", "file", "editable"} {
				if _, ok := p[key]; ok {
					unsupported = true
				}
			}
			if unsupported {
				f.warn(file, name+": non-registry/editable Pipenv dependency omitted")
				continue
			}
			v, err := text(p, "version", false)
			if err != nil {
				return err
			}
			if !strings.HasPrefix(v, "==") || !pythonVersion.MatchString(strings.TrimPrefix(v, "==")) {
				f.warn(file, name+": missing or non-exact Pipenv version omitted")
				continue
			}
			public := allPublic
			if _, exists := p["index"]; exists {
				index, err := text(p, "index", false)
				if err != nil {
					return err
				}
				public = index != "" && sources[index]
			}
			if !public {
				f.warn(file, name+": missing, private or ambiguous Pipenv source; public PyPI identity not established, dependency omitted")
				continue
			}
			scope := "runtime"
			if section == "develop" {
				scope = "development"
			}
			name = pythonSeparators.ReplaceAllString(strings.ToLower(name), "-")
			f.add(file, "pypi", "", name, v[2:], scope, false)
		}
	}
	if !found {
		return fmt.Errorf("missing default/develop dependency sections")
	}
	f.warn(file, "Pipenv lock entries do not establish directness; markers and extras are not evaluated")
	return nil
}
func parseComposer(f *Fragment, file string, data []byte) error {
	m, err := jsonObject(data)
	if err != nil {
		return err
	}
	found := false
	for _, section := range []string{"packages", "packages-dev"} {
		v, ok := m[section]
		if !ok {
			continue
		}
		found = true
		deps, err := array(v, section)
		if err != nil {
			return err
		}
		for _, v := range deps {
			p, err := object(v, "package")
			if err != nil {
				return err
			}
			name, err := text(p, "name", true)
			if err != nil {
				return err
			}
			version, err := text(p, "version", true)
			if err != nil {
				return err
			}
			if !composerName.MatchString(name) {
				return fmt.Errorf("invalid Composer package name %q", name)
			}
			distType := ""
			if v, ok := p["dist"]; ok && v != nil {
				dist, err := object(v, "dist")
				if err != nil {
					return err
				}
				distType, err = text(dist, "type", false)
				if err != nil {
					return err
				}
			}
			if distType == "path" {
				f.warn(file, name+": path package omitted")
				continue
			}
			if !releaseVersion.MatchString(version) || strings.HasPrefix(version, "dev-") || strings.HasSuffix(version, "-dev") {
				f.warn(file, name+": non-release Composer version omitted")
				continue
			}
			parts := strings.SplitN(name, "/", 2)
			scope := "runtime"
			if section == "packages-dev" {
				scope = "development"
			}
			f.add(file, "packagist", parts[0], parts[1], version, scope, false)
		}
	}
	if !found {
		return fmt.Errorf("missing packages/packages-dev sections")
	}
	f.warn(file, "Composer package names use Packagist identity; custom repository provenance and directness cannot be established from this lockfile")
	return nil
}
func parseNuget(f *Fragment, file string, data []byte) error {
	m, err := jsonObject(data)
	if err != nil {
		return err
	}
	version, ok := m["version"].(json.Number)
	if !ok {
		return fmt.Errorf("NuGet version must be a number")
	}
	if version != "1" && version != "2" {
		f.warn(file, "unsupported NuGet lockfile version "+string(version))
		return nil
	}
	frameworks, err := object(m["dependencies"], "dependencies")
	if err != nil {
		return err
	}
	for _, framework := range keys(frameworks) {
		deps, err := object(frameworks[framework], framework)
		if err != nil {
			return err
		}
		for _, name := range keys(deps) {
			if !pythonName.MatchString(name) {
				return fmt.Errorf("invalid NuGet package name %q", name)
			}
			p, err := object(deps[name], name)
			if err != nil {
				return err
			}
			kind, err := text(p, "type", true)
			if err != nil {
				return err
			}
			if kind != "Direct" && kind != "Transitive" && kind != "CentralTransitive" {
				f.warn(file, name+": unsupported NuGet dependency type "+kind)
				continue
			}
			version, err := text(p, "resolved", true)
			if err != nil {
				return err
			}
			if !releaseVersion.MatchString(version) || strings.HasPrefix(version, "v") {
				return fmt.Errorf("%s: invalid resolved NuGet version", name)
			}
			f.add(file, "nuget", "", strings.ToLower(name), version, framework, kind == "Direct")
		}
	}
	return nil
}
func parseSwift(f *Fragment, file string, data []byte) error {
	m, err := jsonObject(data)
	if err != nil {
		return err
	}
	version, ok := m["version"].(json.Number)
	if !ok {
		return fmt.Errorf("Swift version must be a number")
	}
	var pins any
	switch version {
	case "1":
		o, err := object(m["object"], "object")
		if err != nil {
			return err
		}
		pins = o["pins"]
	case "2", "3":
		pins = m["pins"]
	default:
		f.warn(file, "unsupported Swift resolved-file version "+string(version))
		return nil
	}
	a, err := array(pins, "pins")
	if err != nil {
		return err
	}
	for _, v := range a {
		p, err := object(v, "pin")
		if err != nil {
			return err
		}
		nameKey := "identity"
		if version == "1" {
			nameKey = "package"
		}
		name, err := text(p, nameKey, true)
		if err != nil {
			return err
		}
		state, err := object(p["state"], "state")
		if err != nil {
			return err
		}
		// Source-control pins are not registry coordinates. Even a semantic version
		// does not justify inventing a Swift registry namespace from a repository URL.
		kind := "sourceControl"
		if version != "1" {
			kind, err = text(p, "kind", true)
			if err != nil {
				return err
			}
		}
		release, err := textNullable(state, "version")
		if err != nil {
			return err
		}
		if kind != "registry" {
			f.warn(file, name+": Swift source-control/unsupported pin omitted (no registry identity)")
			continue
		}
		parts := strings.Split(name, ".")
		if len(parts) != 2 || !swiftPart(parts[0]) || !swiftPart(parts[1]) {
			return fmt.Errorf("invalid Swift registry identity %q", name)
		}
		if !swiftVersion.MatchString(release) {
			f.warn(file, name+": Swift pin without exact release omitted")
			continue
		}
		f.add(file, "swift", strings.ToLower(parts[0]), strings.ToLower(parts[1]), release, "runtime", false)
	}
	return nil
}
func textNullable(m map[string]any, key string) (string, error) {
	if m[key] == nil {
		return "", nil
	}
	return text(m, key, false)
}
func swiftPart(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
