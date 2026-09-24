package manifestextra

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var pythonName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)
var cargoName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var separators = regexp.MustCompile(`[-_.]+`)
var pythonVersion = regexp.MustCompile(`(?i)^(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$`)
var cargoVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
var requirement = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_, .-]+\])?\s*(.*)$`)

func table(v any) map[string]any { m, _ := v.(map[string]any); return m }
func text(v any) string          { s, _ := v.(string); return s }
func hasPythonSources(d map[string]any) bool {
	tool := table(d["tool"])
	for _, name := range []string{"poetry", "pdm", "uv"} {
		t := table(tool[name])
		for _, key := range []string{"source", "sources", "index", "index-url", "extra-index-url"} {
			if _, ok := t[key]; ok {
				return true
			}
		}
	}
	return false
}
func (s *state) parse(file string, d map[string]any) error {
	switch path.Base(file) {
	case "pyproject.toml":
		return s.python(file, d)
	case "Cargo.toml":
		return s.cargo(file, d)
	default:
		return s.pdm(file, d)
	}
}
func (s *state) python(file string, d map[string]any) error {
	if v, ok := d["project"]; ok && table(v) == nil {
		return fmt.Errorf("project must be a table")
	}
	project := table(d["project"])
	if v, ok := project["dynamic"]; ok {
		s.warn(file, fmt.Sprintf("dynamic project fields not resolved: %v", v))
	}
	parseList := func(v any, scope string) error {
		if v == nil {
			return nil
		}
		list, ok := v.([]any)
		if !ok {
			return fmt.Errorf("%s dependencies must be an array", scope)
		}
		for _, item := range list {
			raw, ok := item.(string)
			if !ok {
				return fmt.Errorf("dependency must be a string")
			}
			m := requirement.FindStringSubmatch(strings.TrimSpace(raw))
			if m == nil {
				s.warn(file, "unsupported requirement skipped: "+raw)
				continue
			}
			spec := strings.TrimSpace(strings.SplitN(m[2], ";", 2)[0])
			spec = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(spec, "("), ")"))
			if strings.Contains(spec, "@") {
				s.warn(file, m[1]+": direct reference unresolved")
				continue
			}
			if s.pythonSources {
				s.warn(file, m[1]+": configured Python sources unresolved")
				continue
			}
			version := ""
			if strings.HasPrefix(spec, "==") && pythonVersion.MatchString(strings.TrimSpace(spec[2:])) {
				version = strings.TrimSpace(spec[2:])
			}
			if version == "" && spec != "" {
				s.warn(file, m[1]+": version constraint unresolved")
			}
			if err := s.add(file, "PyPI", m[1], version, scope, true); err != nil {
				return err
			}
		}
		return nil
	}
	if err := parseList(project["dependencies"], "runtime"); err != nil {
		return err
	}
	if v, ok := project["optional-dependencies"]; ok && table(v) == nil {
		return fmt.Errorf("optional-dependencies must be a table")
	}
	for _, group := range keys(table(project["optional-dependencies"])) {
		if err := parseList(table(project["optional-dependencies"])[group], "optional:"+group); err != nil {
			return err
		}
	}
	tool := table(d["tool"])
	poetry := table(tool["poetry"])
	parsePoetry := func(v any, scope string) error {
		if v == nil {
			return nil
		}
		deps, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("Poetry dependencies must be a table")
		}
		for _, name := range keys(deps) {
			if strings.EqualFold(name, "python") {
				continue
			}
			value := deps[name]
			spec, ok := value.(string)
			if !ok {
				t := table(value)
				if t == nil {
					s.warn(file, name+": unsupported Poetry declaration")
					continue
				}
				blocked := false
				for _, key := range []string{"source", "git", "path", "url"} {
					if _, exists := t[key]; exists {
						blocked = true
					}
				}
				if blocked {
					s.warn(file, name+": non-public or unresolved Poetry source")
					continue
				}
				spec = text(t["version"])
			}
			if s.pythonSources {
				s.warn(file, name+": configured Python sources unresolved")
				continue
			}
			version := strings.TrimSpace(strings.TrimPrefix(spec, "=="))
			if !pythonVersion.MatchString(version) {
				version = ""
				s.warn(file, name+": version constraint unresolved")
			}
			if err := s.add(file, "PyPI", name, version, scope, true); err != nil {
				return err
			}
		}
		return nil
	}
	if err := parsePoetry(poetry["dependencies"], "runtime"); err != nil {
		return err
	}
	if err := parsePoetry(poetry["dev-dependencies"], "dev"); err != nil {
		return err
	}
	for _, group := range keys(table(poetry["group"])) {
		if err := parsePoetry(table(table(poetry["group"])[group])["dependencies"], "group:"+group); err != nil {
			return err
		}
	}
	return nil
}
func (s *state) cargo(file string, d map[string]any) error {
	var parseDeps func(any, string) error
	parseDeps = func(v any, scope string) error {
		if v == nil {
			return nil
		}
		deps, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("Cargo dependencies must be a table")
		}
		for _, alias := range keys(deps) {
			name := alias
			spec, ok := deps[alias].(string)
			if !ok {
				t := table(deps[alias])
				if t == nil {
					return fmt.Errorf("invalid Cargo dependency %q", alias)
				}
				blocked := false
				for _, key := range []string{"workspace", "git", "path", "registry", "registry-index"} {
					if _, exists := t[key]; exists {
						blocked = true
					}
				}
				if blocked {
					s.warn(file, alias+": workspace/git/path/custom registry dependency unresolved")
					continue
				}
				if p, exists := t["package"]; exists {
					name = text(p)
					if name == "" {
						return fmt.Errorf("invalid Cargo package alias")
					}
				}
				spec = text(t["version"])
			}
			if s.cargoConfig {
				s.warn(file, name+": configured Cargo registry unresolved")
				continue
			}
			version := ""
			trim := strings.TrimSpace(spec)
			if strings.HasPrefix(trim, "=") {
				candidate := strings.TrimSpace(trim[1:])
				if exactCargo(candidate) {
					version = candidate
				}
			}
			if version == "" {
				s.warn(file, name+": version constraint unresolved")
			}
			if err := s.add(file, "crates.io", name, version, scope, true); err != nil {
				return err
			}
		}
		return nil
	}
	parseSections := func(t map[string]any, prefix string) error {
		for _, section := range []string{"dependencies", "dev-dependencies", "build-dependencies"} {
			if err := parseDeps(t[section], prefix+section); err != nil {
				return err
			}
		}
		return nil
	}
	if err := parseSections(d, ""); err != nil {
		return err
	}
	for _, target := range keys(table(d["target"])) {
		if err := parseSections(table(table(d["target"])[target]), "target:"+target+":"); err != nil {
			return err
		}
	}
	if table(d["workspace"])["dependencies"] != nil {
		s.warn(file, "workspace dependency templates not resolved")
	}
	if d["patch"] != nil || d["replace"] != nil {
		// Overrides can also affect dependencies in other workspace members.
		return fmt.Errorf("Cargo patch/replace overrides require resolution")
	}
	return nil
}
func exactCargo(v string) bool {
	if !cargoVersion.MatchString(v) {
		return false
	}
	pre := strings.SplitN(v, "+", 2)[0]
	if i := strings.IndexByte(pre, '-'); i >= 0 {
		for _, part := range strings.Split(pre[i+1:], ".") {
			if len(part) > 1 && part[0] == '0' && strings.Trim(part, "0123456789") == "" {
				return false
			}
		}
	}
	return true
}
func publicIndex(v string) bool {
	return v == "https://pypi.org/simple" || v == "https://pypi.org/simple/"
}
func publicArtifact(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host == "files.pythonhosted.org" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && strings.HasPrefix(u.Path, "/packages/")
}
func (s *state) pdm(file string, d map[string]any) error {
	version := text(table(d["metadata"])["lock_version"])
	if version != "4.0" && version != "4.1" && version != "4.2" && version != "4.3" && version != "4.4" && version != "4.5" {
		return fmt.Errorf("unsupported PDM lock_version %q", version)
	}
	raw, exists := d["package"]
	if !exists {
		return nil
	}
	packages, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("PDM package must be an array")
	}
	for _, raw := range packages {
		p := table(raw)
		if p == nil {
			return fmt.Errorf("PDM package must be a table")
		}
		name, ver := text(p["name"]), text(p["version"])
		if !pythonName.MatchString(name) || !pythonVersion.MatchString(ver) {
			return fmt.Errorf("invalid PDM exact package identity %q@%q", name, ver)
		}
		blocked := s.pythonSources
		for _, key := range []string{"git", "path", "url", "editable", "vcs", "directory"} {
			if _, ok := p[key]; ok {
				blocked = true
			}
		}
		public := false
		if source, ok := p["source"]; ok {
			t := table(source)
			public = len(t) == 1 && publicIndex(text(t["url"]))
			if !public {
				blocked = true
			}
		}
		if index, ok := p["index"]; ok {
			if publicIndex(text(index)) {
				public = true
			} else {
				blocked = true
			}
		}
		if files, ok := p["files"].([]any); ok && len(files) > 0 {
			all := true
			for _, f := range files {
				u, explicit := table(f)["url"]
				if !publicArtifact(text(u)) {
					all = false
					if explicit {
						blocked = true
					}
				}
			}
			if all {
				public = true
			}
		}
		if blocked || !public {
			s.warn(file, name+": public PyPI provenance not established; skipped")
			continue
		}
		if err := s.add(file, "PyPI", name, ver, "locked", false); err != nil {
			return err
		}
	}
	return nil
}
