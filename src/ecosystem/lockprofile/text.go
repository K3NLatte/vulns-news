package lockprofile

import (
	"fmt"
	"regexp"
	"strings"
)

var coordinatePart = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var gemSpec = regexp.MustCompile(`^    ([A-Za-z0-9_.-]+) \(([^()]+)\)$`)
var gemDependency = regexp.MustCompile(`^  ([A-Za-z0-9_.-]+)(?: \([^()]+\))?(!)?$`)
var gemVersion = regexp.MustCompile(`^[0-9]+(?:\.[A-Za-z0-9]+)*$`)

func parseGradle(f *Fragment, file string, data []byte) error {
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		left, right, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("line %d: expected coordinates=configurations", i+1)
		}
		if left == "empty" {
			continue
		}
		parts := strings.Split(left, ":")
		if len(parts) != 3 {
			return fmt.Errorf("line %d: expected group:artifact:version", i+1)
		}
		if !coordinatePart.MatchString(parts[0]) || !coordinatePart.MatchString(parts[1]) || parts[2] == "" {
			return fmt.Errorf("line %d: invalid Maven coordinates", i+1)
		}
		configs := strings.Split(right, ",")
		for _, c := range configs {
			if strings.TrimSpace(c) == "" || c != strings.TrimSpace(c) {
				return fmt.Errorf("line %d: invalid configuration list", i+1)
			}
		}
		if !exact(parts[2]) || strings.Contains(parts[2], "+") || strings.HasPrefix(parts[2], "latest.") {
			f.warn(file, fmt.Sprintf("line %d: dynamic Gradle version omitted", i+1))
			continue
		}
		for _, c := range configs {
			f.add(file, "maven", parts[0], parts[1], parts[2], c, false)
		}
	}
	f.warn(file, "Gradle lock configurations are retained as scope; dependency directness and build variants are not resolved")
	return nil
}
func parseGem(f *Fragment, file string, data []byte) error {
	type spec struct{ name, version string }
	var specs []spec
	direct := map[string]bool{}
	section := ""
	inSpecs := false
	seenSpecs := false
	hasSpec := false
	remoteCount := 0
	publicRemotes := true
	publicBlock := false
	known := map[string]bool{"GEM": true, "GIT": true, "PATH": true, "DEPENDENCIES": true, "PLATFORMS": true, "BUNDLED WITH": true, "RUBY VERSION": true, "CHECKSUMS": true}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.ContainsRune(line, '\t') {
			return fmt.Errorf("line %d: tabs in Gemfile.lock", i+1)
		}
		if line[0] != ' ' {
			if section == "GEM" && !inSpecs {
				return fmt.Errorf("line %d: GEM section missing specs", i+1)
			}
			section = line
			inSpecs = false
			hasSpec = false
			remoteCount = 0
			publicRemotes = true
			publicBlock = false
			if !known[section] {
				f.warn(file, "unsupported Gemfile.lock section "+section)
			}
			if section == "GIT" || section == "PATH" {
				f.warn(file, section+" gems omitted; no RubyGems identity inferred")
			}
			continue
		}
		if section == "" {
			return fmt.Errorf("line %d: missing Gemfile.lock section", i+1)
		}
		if section == "GEM" {
			if line == "  specs:" {
				if inSpecs {
					return fmt.Errorf("line %d: duplicate GEM specs", i+1)
				}
				inSpecs = true
				seenSpecs = true
				hasSpec = false
				publicBlock = remoteCount > 0 && publicRemotes
				if !publicBlock {
					f.warn(file, fmt.Sprintf("line %d: GEM block omitted: missing, private or ambiguous remote; public RubyGems identity not established", i+1))
				}
				continue
			}
			if !inSpecs {
				if strings.HasPrefix(line, "  remote:") {
					remoteCount++
					publicRemotes = publicRemotes && publicRegistry(strings.TrimSpace(strings.TrimPrefix(line, "  remote:")), "rubygems.org", "")
					continue
				}
				return fmt.Errorf("line %d: invalid GEM header", i+1)
			}
			if strings.HasPrefix(line, "      ") {
				if !hasSpec {
					return fmt.Errorf("line %d: dependency without gem spec", i+1)
				}
				if !gemDependency.MatchString(strings.TrimPrefix(line, "    ")) {
					return fmt.Errorf("line %d: invalid gem dependency", i+1)
				}
				continue
			}
			match := gemSpec.FindStringSubmatch(line)
			if match == nil {
				return fmt.Errorf("line %d: malformed gem spec", i+1)
			}
			hasSpec = true
			if !gemVersion.MatchString(match[2]) {
				f.warn(file, match[1]+": platform-qualified or unsupported gem version omitted")
				continue
			}
			if publicBlock {
				specs = append(specs, spec{match[1], match[2]})
			}
		} else if section == "DEPENDENCIES" {
			match := gemDependency.FindStringSubmatch(line)
			if match == nil {
				return fmt.Errorf("line %d: malformed gem dependency", i+1)
			}
			if match[2] != "!" {
				direct[match[1]] = true
			}
		}
	}
	if section == "" {
		return fmt.Errorf("empty Gemfile.lock")
	}
	if section == "GEM" && !inSpecs {
		return fmt.Errorf("GEM section missing specs")
	}
	if !seenSpecs && section != "" {
		f.warn(file, "no registry GEM specs found")
	}
	for _, s := range specs {
		f.add(file, "gem", "", s.name, s.version, "runtime", direct[s.name])
	}
	f.warn(file, "Gem groups and platform selection are not resolved; only GEM blocks with public RubyGems remotes are inventoried")
	return nil
}
