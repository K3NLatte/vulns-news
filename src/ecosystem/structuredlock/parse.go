package structuredlock

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

func (s *state) parse(file string, b []byte) error {
	switch path.Base(file) {
	case "Cargo.lock", "poetry.lock", "uv.lock":
		return s.parseTOML(file, b)
	case "pnpm-lock.yaml":
		return s.parsePNPM(file, b)
	case "yarn.lock":
		return s.parseYarn(file, b)
	}
	return errors.New("unknown lockfile")
}
func decodeYAML(b []byte, out any) error {
	d := yaml.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("multiple YAML documents are unsupported")
	}
	return nil
}
func keys[T any](m map[string]T) []string {
	k := make([]string, 0, len(m))
	for v := range m {
		k = append(k, v)
	}
	sort.Strings(k)
	return k
}
func publicRegistry(raw, host string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == host && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// npmTarballMatches binds the standard registry tarball path to the lockfile
// identity. URL.Path is decoded exactly once by net/url, including scoped name
// separators. Do not clean paths or infer identities from nonstandard filenames.
// Callers separately enforce the permitted registry authority and URL options.
func npmTarballMatches(u *url.URL, name, version string) bool {
	if u == nil {
		return false
	}
	basename := name[strings.LastIndexByte(name, '/')+1:]
	return u.Path == "/"+name+"/-/"+basename+"-"+version+".tgz"
}

func (s *state) parseTOML(file string, b []byte) error {
	var lock struct {
		Version  any            `toml:"version"`
		Metadata map[string]any `toml:"metadata"`
		Package  []struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
			Source  any    `toml:"source"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(b, &lock); err != nil {
		return err
	}
	base := path.Base(file)
	if base == "poetry.lock" {
		v, _ := lock.Metadata["lock-version"].(string)
		if v != "1.1" && v != "2.0" && v != "2.1" {
			return fmt.Errorf("unsupported poetry lock version %q", v)
		}
	} else {
		v, ok := lock.Version.(int64)
		if !ok || (base == "uv.lock" && v != 1) || (base == "Cargo.lock" && (v < 1 || v > 4)) {
			return fmt.Errorf("unsupported %s version %v", base, lock.Version)
		}
	}
	for _, p := range lock.Package {
		registry := false
		switch base {
		case "Cargo.lock":
			source, _ := p.Source.(string)
			registry = source == "registry+https://github.com/rust-lang/crates.io-index" || source == "sparse+https://index.crates.io/"
		case "poetry.lock":
			if p.Source == nil {
				registry = true
			} else if source, ok := p.Source.(map[string]any); ok {
				typ, _ := source["type"].(string)
				u, _ := source["url"].(string)
				registry = (typ == "legacy" || typ == "registry") && publicRegistry(u, "pypi.org") && (strings.TrimSuffix(u, "/") == "https://pypi.org/simple")
			}
		case "uv.lock":
			if source, ok := p.Source.(map[string]any); ok && len(source) == 1 {
				u, _ := source["registry"].(string)
				registry = strings.TrimSuffix(u, "/") == "https://pypi.org/simple"
			}
		}
		if !registry {
			s.warn(file, fmt.Sprintf("%q: non-public-registry or unknown source skipped", p.Name))
			continue
		}
		if err := s.add(file, ecosystem(base), p.Name, p.Version); err != nil {
			return err
		}
	}
	return nil
}
func (s *state) parsePNPM(file string, b []byte) error {
	var lock struct {
		Version  string `yaml:"lockfileVersion"`
		Packages map[string]struct {
			Name       string `yaml:"name"`
			Version    string `yaml:"version"`
			Resolution struct {
				Integrity string         `yaml:"integrity"`
				Tarball   string         `yaml:"tarball"`
				Type      string         `yaml:"type"`
				Repo      string         `yaml:"repo"`
				Directory string         `yaml:"directory"`
				Unknown   map[string]any `yaml:",inline"`
			} `yaml:"resolution"`
		} `yaml:"packages"`
	}
	if err := decodeYAML(b, &lock); err != nil {
		return err
	}
	if lock.Version != "6.0" && lock.Version != "9.0" && lock.Version != "6" && lock.Version != "9" {
		return fmt.Errorf("unsupported pnpm lockfile version %q", lock.Version)
	}
	for _, key := range keys(lock.Packages) {
		p := lock.Packages[key]
		identity := strings.TrimPrefix(key, "/")
		if i := strings.IndexByte(identity, '('); i >= 0 {
			suffix := identity[i:]
			depth := 0
			valid := true
			if strings.Contains(suffix, "patch_hash=") {
				s.warn(file, fmt.Sprintf("%q: patched package skipped", key))
				continue
			}
			for _, c := range suffix {
				if c == '(' {
					depth++
				} else if c == ')' {
					depth--
					if depth < 0 {
						valid = false
						break
					}
				} else if depth == 0 {
					valid = false
					break
				}
			}
			if depth != 0 || !valid {
				return fmt.Errorf("malformed peer suffix in %q", key)
			}
			identity = identity[:i]
		}
		at := strings.LastIndexByte(identity, '@')
		if at <= 0 {
			s.warn(file, fmt.Sprintf("%q: unsupported package locator skipped", key))
			continue
		}
		name, version := identity[:at], identity[at+1:]
		r := p.Resolution
		if len(r.Unknown) > 0 || r.Type != "" || r.Repo != "" || r.Directory != "" || (r.Tarball != "" && !publicRegistry(r.Tarball, "registry.npmjs.org")) || (r.Integrity == "" && r.Tarball == "") {
			s.warn(file, fmt.Sprintf("%q: non-registry or unknown resolution skipped", key))
			continue
		}
		if r.Tarball != "" {
			u, _ := url.Parse(r.Tarball) // The public-registry check above already validates the URL.
			if !npmTarballMatches(u, name, version) {
				s.warn(file, fmt.Sprintf("%q: unrecognized or conflicting tarball identity skipped", key))
				continue
			}
		}
		if p.Name != "" && p.Name != name || p.Version != "" && p.Version != version {
			s.warn(file, fmt.Sprintf("%q: conflicting identity skipped", key))
			continue
		}
		if err := s.add(file, "npm", name, version); err != nil {
			return err
		}
	}
	return nil
}

func (s *state) parseYarn(file string, b []byte) error {
	// Classic is not YAML. Its explicit format marker prevents guessing a dialect.
	if bytes.Contains(b, []byte("# yarn lockfile v1")) {
		return s.parseClassic(file, b)
	}
	var entries map[string]yaml.Node
	if err := decodeYAML(b, &entries); err != nil {
		return err
	}
	metadata, ok := entries["__metadata"]
	if !ok {
		return errors.New("unrecognized yarn lock dialect (missing Berry metadata or classic marker)")
	}
	var meta struct {
		Version int `yaml:"version"`
	}
	if err := metadata.Decode(&meta); err != nil {
		return err
	}
	if meta.Version != 4 && meta.Version != 5 && meta.Version != 6 && meta.Version != 8 {
		return fmt.Errorf("unsupported Berry metadata version %d", meta.Version)
	}
	for _, key := range keys(entries) {
		if key == "__metadata" {
			continue
		}
		var p struct {
			Version    string `yaml:"version"`
			Resolution string `yaml:"resolution"`
		}
		node := entries[key]
		if err := node.Decode(&p); err != nil {
			return err
		}
		i := strings.Index(p.Resolution, "@npm:")
		if i <= 0 {
			s.warn(file, fmt.Sprintf("%q: unsupported Yarn resolution skipped", key))
			continue
		}
		name, version := p.Resolution[:i], p.Resolution[i+5:]
		if version != p.Version {
			s.warn(file, fmt.Sprintf("%q: conflicting Yarn identity skipped", key))
			continue
		}
		if err := s.add(file, "npm", name, version); err != nil {
			return err
		}
	}
	return nil
}
