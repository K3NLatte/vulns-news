package lockprofile

import (
	"fmt"
	"net/url"
	"strings"
)

// Match a canonical HTTPS registry endpoint, not a substring or a redirect.
// Do not log URLs: source URLs may contain credentials or secret query values.
func publicRegistry(raw, host, endpoint string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}
	if !strings.EqualFold(u.Host, host) && !strings.EqualFold(u.Host, host+":443") {
		return false
	}
	return u.EscapedPath() == endpoint || u.EscapedPath() == endpoint+"/"
}

// Explicit indexes must select a unique public source. Unindexed entries have
// no per-package origin, so they are public only if every source is public.
func pipSources(m map[string]any) (map[string]bool, bool, error) {
	sources := map[string]bool{}
	raw, exists := m["_meta"]
	if !exists {
		return sources, false, nil
	}
	meta, err := object(raw, "_meta")
	if err != nil {
		return nil, false, err
	}
	raw, exists = meta["sources"]
	if !exists {
		return sources, false, nil
	}
	list, err := array(raw, "_meta.sources")
	if err != nil {
		return nil, false, err
	}
	allPublic := len(list) > 0
	for _, raw := range list {
		source, err := object(raw, "Pipenv source")
		if err != nil {
			return nil, false, err
		}
		name, err := text(source, "name", false)
		if err != nil {
			return nil, false, err
		}
		address, err := text(source, "url", false)
		if err != nil {
			return nil, false, err
		}
		public := name != "" && publicRegistry(address, "pypi.org", "/simple")
		if v, exists := source["verify_ssl"]; exists {
			verify, ok := v.(bool)
			if !ok {
				return nil, false, fmt.Errorf("Pipenv source verify_ssl must be a boolean")
			}
			public = public && verify
		}
		if _, duplicate := sources[name]; duplicate {
			public = false
		}
		sources[name] = public
		allPublic = allPublic && public
	}
	return sources, allPublic, nil
}
