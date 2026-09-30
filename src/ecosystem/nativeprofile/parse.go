package nativeprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

var packageName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.+-]*$`)
var exactVersion = regexp.MustCompile(`^[0-9][A-Za-z0-9_.+-]*$`)
var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var conanRef = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9_.+-]*)/([A-Za-z0-9_][A-Za-z0-9_.+-]*)(?:@([A-Za-z0-9_.+-]+)/([A-Za-z0-9_.+-]+))?(?:#[A-Za-z0-9]+(?:%[0-9.]+)?)?$`)
var podSpec = regexp.MustCompile(`^([A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*) \(([0-9][A-Za-z0-9_.+-]*)\)$`)

func (s *state) parse(file string, b []byte) error {
	switch path.Base(file) {
	case "conan.lock":
		return s.conan(file, b)
	case "vcpkg.json":
		return s.vcpkg(file, b)
	case "Podfile.lock":
		return s.pods(file, b)
	case "Manifest.toml":
		return s.julia(file, b)
	}
	return errors.New("unsupported file")
}
func jsonObject(b []byte) (map[string]json.RawMessage, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, errors.New("expected JSON object")
	}
	return doc, nil
}
func (s *state) conan(file string, b []byte) error {
	doc, err := jsonObject(b)
	if err != nil {
		return err
	}
	var version string
	if err := json.Unmarshal(doc["version"], &version); err != nil {
		if doc["version"] != nil {
			return err
		}
	}
	s.warn(file, "Conan references are source identities, not verified public-registry or OSV identities")
	refs := []string{}
	switch version {
	case "0.5":
		for _, field := range []string{"requires", "build_requires", "python_requires", "config_requires"} {
			if raw, ok := doc[field]; ok {
				var list []string
				if err := json.Unmarshal(raw, &list); err != nil {
					return err
				}
				if list == nil {
					return fmt.Errorf("%s must be an array", field)
				}
				refs = append(refs, list...)
			}
		}
	case "0.4":
		var graph struct {
			Nodes map[string]struct {
				Ref  string `json:"ref"`
				Path string `json:"path"`
			} `json:"nodes"`
		}
		raw, ok := doc["graph_lock"]
		if !ok {
			s.warn(file, "unknown Conan graph schema skipped")
			return nil
		}
		if err := json.Unmarshal(raw, &graph); err != nil {
			return err
		}
		if graph.Nodes == nil {
			s.warn(file, "unknown Conan nodes schema skipped")
			return nil
		}
		for _, id := range keys(graph.Nodes) {
			n := graph.Nodes[id]
			if n.Path != "" {
				s.warn(file, "local Conan node skipped")
				continue
			}
			if n.Ref != "" {
				refs = append(refs, n.Ref)
			}
		}
	default:
		s.warn(file, fmt.Sprintf("unknown Conan lock version %q skipped", version))
		return nil
	}
	for _, ref := range refs {
		m := conanRef.FindStringSubmatch(ref)
		if m == nil {
			s.warn(file, fmt.Sprintf("unsupported Conan reference %q skipped", ref))
			continue
		}
		if err := s.add(file, "Conan", m[1], m[2], ref); err != nil {
			return err
		}
	}
	return nil
}
func (s *state) vcpkg(file string, b []byte) error {
	doc, err := jsonObject(b)
	if err != nil {
		return err
	}
	found := false
	var deps func(json.RawMessage) error
	deps = func(raw json.RawMessage) error {
		var list []json.RawMessage
		if err := json.Unmarshal(raw, &list); err != nil {
			return err
		}
		if list == nil {
			return errors.New("dependencies must be an array")
		}
		for _, entry := range list {
			var name string
			if len(entry) > 0 && entry[0] == '"' {
				if err := json.Unmarshal(entry, &name); err != nil {
					return err
				}
			} else {
				obj, err := jsonObject(entry)
				if err != nil {
					return err
				}
				if raw, ok := obj["name"]; ok {
					if err := json.Unmarshal(raw, &name); err != nil {
						return err
					}
				} else {
					s.warn(file, "unknown vcpkg dependency schema skipped")
					continue
				}
			}
			if !packageName.MatchString(name) {
				return fmt.Errorf("invalid vcpkg dependency name %q", name)
			}
			s.warn(file, fmt.Sprintf("%s: vcpkg manifest dependency has unknown resolved version (constraints are not pins)", name))
			if err := s.add(file, "vcpkg", name, "", ""); err != nil {
				return err
			}
		}
		return nil
	}
	if raw, ok := doc["dependencies"]; ok {
		found = true
		if err := deps(raw); err != nil {
			return err
		}
	}
	if raw, ok := doc["features"]; ok {
		var features map[string]struct {
			Dependencies json.RawMessage `json:"dependencies"`
		}
		if err := json.Unmarshal(raw, &features); err != nil {
			return err
		}
		for _, key := range keys(features) {
			if raw := features[key].Dependencies; raw != nil {
				found = true
				if err := deps(raw); err != nil {
					return err
				}
			}
		}
	}
	if !found {
		s.warn(file, "no recognized vcpkg dependencies")
	}
	return nil
}
func (s *state) pods(file string, b []byte) error {
	var doc struct {
		Pods     []yaml.Node          `yaml:"PODS"`
		Repos    map[string][]string  `yaml:"SPEC REPOS"`
		External map[string]yaml.Node `yaml:"EXTERNAL SOURCES"`
		Checkout map[string]yaml.Node `yaml:"CHECKOUT OPTIONS"`
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&doc); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("multiple YAML documents unsupported")
	}
	if doc.Pods == nil {
		s.warn(file, "unknown CocoaPods lock schema skipped")
		return nil
	}
	rootName := func(n string) string { return strings.SplitN(n, "/", 2)[0] }
	public, excluded := map[string]bool{}, map[string]bool{}
	for repo, names := range doc.Repos {
		trusted := repo == "trunk" || repo == "https://cdn.cocoapods.org/" || repo == "https://github.com/CocoaPods/Specs.git"
		for _, n := range names {
			if trusted {
				public[rootName(n)] = true
			} else {
				excluded[rootName(n)] = true
			}
		}
	}
	for n := range doc.External {
		excluded[rootName(n)] = true
	}
	for n := range doc.Checkout {
		excluded[rootName(n)] = true
	}
	for _, node := range doc.Pods {
		var spec string
		switch node.Kind {
		case yaml.ScalarNode:
			if node.Tag != "!!str" {
				return errors.New("PODS entry must be a string")
			}
			spec = node.Value
		case yaml.MappingNode:
			if len(node.Content) != 2 || node.Content[0].Tag != "!!str" || node.Content[1].Kind != yaml.SequenceNode {
				return errors.New("invalid PODS dependency mapping")
			}
			spec = node.Content[0].Value
		default:
			return errors.New("invalid PODS entry")
		}
		m := podSpec.FindStringSubmatch(spec)
		if m == nil {
			return fmt.Errorf("invalid resolved pod spec %q", spec)
		}
		name := m[1]
		root := rootName(name)
		if excluded[root] || !public[root] {
			s.warn(file, fmt.Sprintf("%s: external, private, or unknown CocoaPods source skipped", name))
			continue
		}
		if err := s.add(file, "CocoaPods", name, m[2], ""); err != nil {
			return err
		}
	}
	return nil
}
func (s *state) julia(file string, b []byte) error {
	var doc map[string]any
	if err := toml.Unmarshal(b, &doc); err != nil {
		return err
	}
	s.warn(file, "Julia UUID/version entries are inventory identities; registry provenance and OSV mapping are not established")
	packages := doc
	if format, ok := doc["manifest_format"]; ok {
		if format != "2.0" {
			s.warn(file, fmt.Sprintf("unknown Julia manifest format %v skipped", format))
			return nil
		}
		var ok bool
		packages, ok = doc["deps"].(map[string]any)
		if !ok {
			s.warn(file, "unknown Julia deps schema skipped")
			return nil
		}
	}
	recognized := false
	for _, name := range keys(packages) {
		records, ok := packages[name].([]any)
		if !ok {
			if name != "julia_version" && name != "manifest_format" && name != "project_hash" {
				s.warn(file, name+": unknown Julia package schema skipped")
			}
			continue
		}
		recognized = true
		if !packageName.MatchString(name) {
			return fmt.Errorf("invalid Julia package name %q", name)
		}
		for _, record := range records {
			p, ok := record.(map[string]any)
			if !ok {
				return errors.New("invalid Julia package record")
			}
			source := false
			for _, key := range []string{"path", "repo-url", "repo-rev", "repo-subdir"} {
				if _, ok := p[key]; ok {
					source = true
				}
			}
			if source {
				s.warn(file, name+": Julia path/repository source skipped")
				continue
			}
			uuid, uok := p["uuid"].(string)
			version, vok := p["version"].(string)
			if p["uuid"] != nil && !uok || p["version"] != nil && !vok {
				return fmt.Errorf("Julia UUID/version for %s must be strings", name)
			}
			if !uok || !vok {
				s.warn(file, name+": missing UUID/version (including stdlib) skipped")
				continue
			}
			if !uuidPattern.MatchString(uuid) || !exactVersion.MatchString(version) {
				return fmt.Errorf("invalid Julia UUID/version for %s", name)
			}
			if err := s.add(file, "Julia", name, version, strings.ToLower(uuid)); err != nil {
				return err
			}
		}
	}
	if !recognized {
		s.warn(file, "no recognized Julia package tables")
	}
	return nil
}
