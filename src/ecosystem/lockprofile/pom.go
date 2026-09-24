package lockprofile

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

type xmlNode struct {
	name     xml.Name
	text     strings.Builder
	children []*xmlNode
}

func parseXML(data []byte) (*xmlNode, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	var root *xmlNode
	var stack []*xmlNode
	nodes := 0
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch v := t.(type) {
		case xml.StartElement:
			nodes++
			if nodes > 50000 || len(stack) >= 64 {
				return nil, fmt.Errorf("XML structure limit exceeded")
			}
			n := &xmlNode{name: v.Name}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("multiple XML roots")
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				p.children = append(p.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(v)) != "" {
					return nil, fmt.Errorf("text outside XML root")
				}
			} else {
				stack[len(stack)-1].text.Write(v)
			}
		case xml.Directive:
			return nil, fmt.Errorf("XML directives/DOCTYPE are unsupported")
		case xml.ProcInst:
			if v.Target != "xml" {
				return nil, fmt.Errorf("XML processing instructions are unsupported")
			}
		}
	}
	if root == nil {
		return nil, fmt.Errorf("empty XML document")
	}
	return root, nil
}
func (n *xmlNode) one(name string) (*xmlNode, error) {
	var found *xmlNode
	for _, c := range n.children {
		if c.name.Local == name && c.name.Space == n.name.Space {
			if found != nil {
				return nil, fmt.Errorf("duplicate POM element %s", name)
			}
			found = c
		}
	}
	return found, nil
}
func (n *xmlNode) scalar(name string) (string, error) {
	c, err := n.one(name)
	if err != nil || c == nil {
		return "", err
	}
	if len(c.children) > 0 {
		return "", fmt.Errorf("nested content in POM %s", name)
	}
	return strings.TrimSpace(c.text.String()), nil
}
func parsePOM(f *Fragment, file string, data []byte) error {
	root, err := parseXML(data)
	if err != nil {
		return err
	}
	if root.name.Local != "project" {
		return fmt.Errorf("expected POM project root")
	}
	if root.name.Space != "" && root.name.Space != "http://maven.apache.org/POM/4.0.0" {
		f.warn(file, "unsupported POM namespace")
		return nil
	}
	props := map[string]string{}
	p, err := root.one("properties")
	if err != nil {
		return err
	}
	if p != nil {
		for _, c := range p.children {
			if c.name.Space != root.name.Space {
				f.warn(file, "foreign-namespace POM property omitted")
				continue
			}
			if len(c.children) > 0 {
				return fmt.Errorf("nested POM property %s", c.name.Local)
			}
			if _, ok := props[c.name.Local]; ok {
				return fmt.Errorf("duplicate POM property %s", c.name.Local)
			}
			props[c.name.Local] = strings.TrimSpace(c.text.String())
		}
	}
	parent, err := root.one("parent")
	if err != nil {
		return err
	}
	for _, key := range []string{"groupId", "artifactId", "version"} {
		own, err := root.scalar(key)
		if err != nil {
			return err
		}
		inherited := ""
		if parent != nil {
			inherited, err = parent.scalar(key)
			if err != nil {
				return err
			}
			props["project.parent."+key] = inherited
			props["pom.parent."+key] = inherited
		}
		if own == "" && key != "artifactId" {
			own = inherited
		}
		props["project."+key] = own
		props["pom."+key] = own
	}
	for _, section := range []string{"parent", "dependencyManagement", "profiles", "build", "modules", "repositories"} {
		n, err := root.one(section)
		if err != nil {
			return err
		}
		if n != nil {
			f.warn(file, "POM "+section+" is not resolved (only explicit top-level dependencies are inventoried)")
		}
	}
	deps, err := root.one("dependencies")
	if err != nil {
		return err
	}
	if deps == nil {
		return nil
	}
	for _, dep := range deps.children {
		if dep.name.Local != "dependency" || dep.name.Space != root.name.Space {
			f.warn(file, "unsupported element in POM dependencies omitted")
			continue
		}
		fields := map[string]string{}
		for _, key := range []string{"groupId", "artifactId", "version", "scope", "type", "classifier", "optional"} {
			v, err := dep.scalar(key)
			if err != nil {
				return err
			}
			fields[key] = v
		}
		group, gok := expand(fields["groupId"], props)
		name, nok := expand(fields["artifactId"], props)
		if !gok || !nok || !coordinatePart.MatchString(group) || !coordinatePart.MatchString(name) {
			f.warn(file, "POM dependency with missing/unresolved coordinates omitted")
			continue
		}
		version, vok := expand(fields["version"], props)
		if !vok || !exact(version) || version == "LATEST" || version == "RELEASE" {
			version = ""
			f.warn(file, group+":"+name+": missing, non-exact or unresolved POM version retained as unknown")
		}
		scope, sok := expand(fields["scope"], props)
		if !sok {
			scope = "unknown"
			f.warn(file, group+":"+name+": unresolved POM scope")
		}
		if scope == "" {
			scope = "compile"
		}
		if scope == "system" {
			f.warn(file, group+":"+name+": system-scoped local JAR omitted; public Maven identity not established")
			continue
		}
		switch scope {
		case "compile", "provided", "runtime", "test", "unknown":
		default:
			f.warn(file, group+":"+name+": unsupported POM scope "+scope+" omitted")
			continue
		}
		if fields["type"] != "" && fields["type"] != "jar" || fields["classifier"] != "" || fields["optional"] != "" {
			f.warn(file, group+":"+name+": POM type/classifier/optional metadata is not represented")
		}
		f.add(file, "maven", group, name, version, scope, true)
	}
	return nil
}

// Expansion is local only: no environment, filesystem, parent downloads or Maven
// evaluation. Both recursion and work/output are bounded, including fan-out.
func expand(s string, props map[string]string) (string, bool) {
	active := map[string]bool{}
	steps := 0
	var resolve func(string, int) (string, bool)
	resolve = func(s string, depth int) (string, bool) {
		steps++
		if depth > 32 || steps > 256 || len(s) > 65536 {
			return "", false
		}
		var out strings.Builder
		for {
			start := strings.Index(s, "${")
			if start < 0 {
				out.WriteString(s)
				break
			}
			out.WriteString(s[:start])
			end := strings.IndexByte(s[start+2:], '}')
			if end < 0 {
				return "", false
			}
			end += start + 2
			key := s[start+2 : end]
			value, ok := props[key]
			if !ok || active[key] || value == "" {
				return "", false
			}
			active[key] = true
			v, ok := resolve(value, depth+1)
			delete(active, key)
			if !ok {
				return "", false
			}
			out.WriteString(v)
			if out.Len() > 65536 {
				return "", false
			}
			s = s[end+1:]
		}
		if out.Len() > 65536 {
			return "", false
		}
		return out.String(), true
	}
	return resolve(s, 0)
}
