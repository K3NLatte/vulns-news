package extralock

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

func (s *state) parse(file string, b []byte) error {
	switch path.Base(file) {
	case "pubspec.lock":
		return s.pub(file, b)
	case "packages.config":
		return s.packages(file, b)
	}
	if err := validateJSON(b); err != nil {
		return err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	if doc == nil {
		return errors.New("expected JSON object")
	}
	switch path.Base(file) {
	case "deno.lock":
		return s.deno(file, doc)
	case "project.assets.json":
		return s.assets(file, doc)
	case "renv.lock":
		return s.renv(file, doc)
	}
	return nil
}

// Reject duplicate keys rather than silently accepting the last conflicting fact.
func validateJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting limit exceeded")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok {
					return errors.New("invalid JSON key")
				}
				if seen[key] {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("multiple JSON values")
	}
	return nil
}
func object(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("expected object, got null")
	}
	return m, nil
}
func text(m map[string]json.RawMessage, key string) (string, error) {
	raw, ok := m[key]
	if !ok {
		return "", nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", fmt.Errorf("%s must be a string", key)
	}
	var v string
	err := json.Unmarshal(raw, &v)
	return v, err
}
func publicURL(raw, host string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == host && u.User == nil && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery
}

func validateYAML(n *yaml.Node, depth int) error {
	if depth > 64 {
		return errors.New("YAML nesting limit exceeded")
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return errors.New("YAML anchors and aliases are unsupported")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
				return errors.New("YAML mapping keys must be strings")
			}
			if seen[k.Value] {
				return fmt.Errorf("duplicate YAML key %q", k.Value)
			}
			seen[k.Value] = true
		}
	}
	for _, c := range n.Content {
		if err := validateYAML(c, depth+1); err != nil {
			return err
		}
	}
	return nil
}
func (s *state) pub(file string, b []byte) error {
	s.usage(file, "Pub")
	d := yaml.NewDecoder(bytes.NewReader(b))
	var node yaml.Node
	if err := d.Decode(&node); err != nil {
		return err
	}
	if err := validateYAML(&node, 0); err != nil {
		return err
	}
	var extra yaml.Node
	if err := d.Decode(&extra); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("multiple YAML documents")
	}
	if len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
		return errors.New("expected YAML mapping")
	}
	var doc struct {
		Packages map[string]struct {
			Dependency  string    `yaml:"dependency"`
			Description yaml.Node `yaml:"description"`
			Source      string    `yaml:"source"`
			Version     string    `yaml:"version"`
		} `yaml:"packages"`
	}
	if err := node.Decode(&doc); err != nil {
		return err
	}
	if doc.Packages == nil {
		s.warn(file, "unsupported pubspec.lock schema: missing packages mapping")
		return nil
	}
	for _, name := range keys(doc.Packages) {
		if err := s.record(); err != nil {
			return err
		}
		p := doc.Packages[name]
		if p.Source == "" {
			return fmt.Errorf("%s: missing source", name)
		}
		if p.Source != "hosted" {
			s.warn(file, name+": non-hosted source skipped ("+p.Source+")")
			continue
		}
		if p.Description.Kind != yaml.MappingNode {
			s.warn(file, name+": unsupported hosted description; explicit pub.dev provenance required")
			continue
		}
		var desc struct {
			Name string `yaml:"name"`
			URL  string `yaml:"url"`
		}
		if err := p.Description.Decode(&desc); err != nil {
			return err
		}
		if desc.Name == "" || desc.URL == "" {
			return fmt.Errorf("%s: hosted description requires name and URL", name)
		}
		if desc.Name != name {
			return fmt.Errorf("%s: hosted name mismatch %q", name, desc.Name)
		}
		if !publicURL(desc.URL, "pub.dev") {
			s.warn(file, name+": non-public pub.dev host skipped")
			continue
		}
		scope := ""
		direct := false
		switch p.Dependency {
		case "direct main":
			direct = true
			scope = "runtime"
		case "direct dev":
			direct = true
			scope = "development"
		case "transitive":
		case "":
			return fmt.Errorf("%s: missing dependency kind", name)
		default:
			s.warn(file, name+": unsupported dependency kind skipped")
			continue
		}
		if err := s.add(file, "Pub", name, p.Version, scope, direct); err != nil {
			return err
		}
	}
	return nil
}

func (s *state) deno(file string, doc map[string]json.RawMessage) error {
	version, err := text(doc, "version")
	if err != nil {
		return err
	}
	var sections map[string]json.RawMessage
	switch version {
	case "2":
		sections = map[string]json.RawMessage{}
		if raw, ok := doc["npm"]; ok {
			npm, err := object(raw)
			if err != nil {
				return err
			}
			if p, ok := npm["packages"]; ok {
				sections["npm"] = p
			} else {
				s.warn(file, "unsupported Deno v2 npm schema: missing packages")
			}
		}
	case "3":
		if raw, ok := doc["packages"]; ok {
			sections, err = object(raw)
			if err != nil {
				return err
			}
		} else {
			s.warn(file, "unsupported Deno v3 schema: missing packages")
		}
	case "4", "5":
		sections = doc
	default:
		s.warn(file, fmt.Sprintf("unsupported deno.lock version %q", version))
		return nil
	}
	if _, npm := sections["npm"]; !npm {
		if _, jsr := sections["jsr"]; !jsr {
			s.warn(file, "no supported pinned npm/JSR records; specifiers and remote URLs are not resolved registry inventory")
		}
	}
	for _, eco := range []string{"npm", "JSR"} {
		raw, ok := sections[strings.ToLower(eco)]
		if !ok {
			continue
		}
		s.usage(file, eco)
		records, err := object(raw)
		if err != nil {
			return err
		}
		for _, key := range keys(records) {
			if err := s.record(); err != nil {
				return err
			}
			record, err := object(records[key])
			if err != nil {
				return err
			}
			// Find the separator after the name, not an @ in a peer context.
			if len(key) < 2 {
				return fmt.Errorf("invalid Deno package key %q", key)
			}
			at := strings.IndexByte(key[1:], '@') + 1
			if at <= 0 {
				return fmt.Errorf("invalid Deno package key %q", key)
			}
			name := key[:at]
			version := key[at+1:]
			if i := strings.IndexAny(version, "_("); i >= 0 {
				if i == len(version)-1 || (version[i] == '(' && !strings.HasSuffix(version, ")")) {
					return fmt.Errorf("invalid Deno peer context %q", key)
				}
				version = version[:i]
			}
			integrity, err := text(record, "integrity")
			if err != nil {
				return err
			}
			if strings.TrimSpace(integrity) == "" {
				s.warn(file, key+": unsupported registry record without integrity")
				continue
			}
			foreign := false
			for _, field := range []string{"resolved", "tarball", "registry", "source", "url"} {
				if _, ok := record[field]; ok {
					foreign = true
				}
			}
			if foreign {
				s.warn(file, key+": explicit alternate source metadata skipped")
				continue
			}
			if err := s.add(file, eco, name, version, "", false); err != nil {
				return err
			}
		}
	}
	if raw, ok := doc["remote"]; ok {
		m, err := object(raw)
		if err != nil {
			return err
		}
		if len(m) > 0 {
			s.warn(file, "remote URL dependencies are not registry identities and were skipped")
		}
	}
	return nil
}

func (s *state) packages(file string, b []byte) error {
	s.usage(file, "NuGet")
	d := xml.NewDecoder(bytes.NewReader(b))
	depth := 0
	root := ""
	supportedRoot := false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.Directive:
			return errors.New("XML directives/DTD are unsupported")
		case xml.StartElement:
			depth++
			if depth > 64 {
				return errors.New("XML nesting limit exceeded")
			}
			if depth == 1 {
				if root != "" {
					return errors.New("multiple XML roots")
				}
				root = t.Name.Local
				supportedRoot = t.Name.Local == "packages" && t.Name.Space == ""
				if !supportedRoot {
					s.warn(file, "unsupported packages.config root")
				}
				continue
			}
			if !supportedRoot {
				continue
			}
			if depth != 2 || t.Name.Local != "package" || t.Name.Space != "" {
				s.warn(file, "unsupported packages.config element "+t.Name.Local)
				continue
			}
			if err := s.record(); err != nil {
				return err
			}
			attrs := map[string]string{}
			for _, a := range t.Attr {
				key := a.Name.Space + "|" + a.Name.Local
				if _, ok := attrs[key]; ok {
					return errors.New("duplicate XML attribute")
				}
				attrs[key] = a.Value
			}
			name, version := attrs["|id"], attrs["|version"]
			if err := s.add(file, "NuGet", name, version, "", false); err != nil {
				return err
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return errors.New("unexpected XML text")
			}
		}
	}
	if root == "" || depth != 0 {
		return errors.New("missing or incomplete XML root")
	}
	if supportedRoot {
		s.warn(file, "NuGet package sources are not recorded by packages.config; public nuget.org provenance is not asserted")
	}
	return nil
}
func (s *state) assets(file string, doc map[string]json.RawMessage) error {
	s.usage(file, "NuGet")
	raw, ok := doc["version"]
	if !ok {
		s.warn(file, "unsupported project.assets.json schema: missing version")
		return nil
	}
	var version int
	if err := json.Unmarshal(raw, &version); err != nil {
		return err
	}
	if version != 3 {
		s.warn(file, fmt.Sprintf("unsupported project.assets.json version %d", version))
		return nil
	}
	raw, ok = doc["libraries"]
	if !ok {
		s.warn(file, "unsupported project.assets.json schema: missing libraries")
		return nil
	}
	libraries, err := object(raw)
	if err != nil {
		return err
	}
	for _, key := range keys(libraries) {
		if err := s.record(); err != nil {
			return err
		}
		lib, err := object(libraries[key])
		if err != nil {
			return err
		}
		typ, err := text(lib, "type")
		if err != nil {
			return err
		}
		if typ == "project" {
			continue
		}
		if typ == "" {
			return fmt.Errorf("%s: missing library type", key)
		}
		if typ != "package" {
			s.warn(file, key+": unsupported library type "+typ)
			continue
		}
		parts := strings.Split(key, "/")
		if len(parts) != 2 {
			return fmt.Errorf("invalid resolved NuGet identity %q", key)
		}
		if err := s.add(file, "NuGet", parts[0], parts[1], "", false); err != nil {
			return err
		}
	}
	s.warn(file, "NuGet libraries do not identify their individual feeds; public nuget.org provenance is not asserted")
	return nil
}
func (s *state) renv(file string, doc map[string]json.RawMessage) error {
	s.usage(file, "CRAN")
	raw, ok := doc["Packages"]
	if !ok {
		s.warn(file, "unsupported renv.lock schema: missing Packages")
		return nil
	}
	packages, err := object(raw)
	if err != nil {
		return err
	}
	for _, key := range keys(packages) {
		if err := s.record(); err != nil {
			return err
		}
		p, err := object(packages[key])
		if err != nil {
			return err
		}
		source, err := text(p, "Source")
		if err != nil {
			return err
		}
		repo, err := text(p, "Repository")
		if err != nil {
			return err
		}
		if source == "" {
			return fmt.Errorf("%s: missing renv source", key)
		}
		if source != "Repository" || repo != "CRAN" {
			s.warn(file, key+": non-CRAN source skipped")
			continue
		}
		remote := false
		for field := range p {
			if strings.HasPrefix(field, "Remote") {
				remote = true
			}
		}
		if remote {
			s.warn(file, key+": conflicting remote provenance skipped")
			continue
		}
		name, err := text(p, "Package")
		if err != nil {
			return err
		}
		version, err := text(p, "Version")
		if err != nil {
			return err
		}
		if name != key {
			return fmt.Errorf("%s: renv Package identity mismatch %q", key, name)
		}
		if err := s.add(file, "CRAN", name, version, "", false); err != nil {
			return err
		}
	}
	s.warn(file, "CRAN inventory uses declared repository provenance only; no OSV ecosystem or advisory coverage is assumed")
	return nil
}
