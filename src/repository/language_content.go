package repository

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
)

const languageContentLimit = 16 * 1024

// ambiguousLanguageFilename identifies suffixes eligible for content inspection.
// In particular, .pl retains its legacy filename-based Perl classification.
func ambiguousLanguageFilename(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".m", ".v", ".as", ".cl", ".cls", ".pro", ".mod":
		return true
	}
	return false
}

type contentLanguageSignature struct {
	language string
	patterns []*regexp.Regexp
}

func contentSignature(language string, patterns ...string) contentLanguageSignature {
	s := contentLanguageSignature{language: language}
	for _, pattern := range patterns {
		s.patterns = append(s.patterns, regexp.MustCompile(`(?m)^[\t ]*(?:`+pattern+`)`))
	}
	return s
}

// Every pattern in a signature must match. Alternatives are kept within a
// pattern; independent declarations provide corroboration for shared syntax.
var contentLanguageSignatures = map[string][]contentLanguageSignature{
	".m": {
		contentSignature("Objective-C", `@(?:interface|implementation|protocol)[\t ]+[A-Za-z_]\w*`),
		contentSignature("MATLAB", `function[\t ]+(?:\[[^\]\n]+\]|[A-Za-z_]\w*)[\t ]*=[\t ]*[A-Za-z_]\w*\b`),
		contentSignature("MATLAB", `function[\t ]+[A-Za-z_]\w*[\t ]*\([^\n]*\)`, `end[\t ]*;?[\t ]*$`),
		contentSignature("MATLAB", `classdef[\t ]+(?:\([^\n]*\)[\t ]+)?[A-Za-z_]\w*`, `end[\t ]*;?[\t ]*$`),
		contentSignature("Octave", `function[\t ]+`, `endfunction\b`),
		contentSignature("Octave", `unwind_protect[\t ]*$`, `end_unwind_protect\b`),
		contentSignature("Mercury", `:-[\t ]*module[\t ]+[a-z][\w.]*[\t ]*\.`, `:-[\t ]*(?:interface|implementation)[\t ]*\.`),
	},
	".v": {
		contentSignature("Verilog", `module[\t ]+[A-Za-z_]\w*[\t ]*(?:#?[\t ]*\(|;)`),
		contentSignature("Coq / Rocq", `(?:From[\t ]+[\w.]+[\t ]+)?Require[\t ]+(?:(?:Import|Export)[\t ]+)?[A-Za-z_][\w.]*(?:[\t ]+[A-Za-z_][\w.]*)*[\t ]*\.[\t ]*$`),
		contentSignature("Coq / Rocq", `(?:Lemma|Theorem|Example|Definition|Fixpoint|Inductive)[\t ]+[A-Za-z_]\w*\b`, `(?:Proof[\t ]*\.|.*:=[\t ]*\S)`),
		contentSignature("V", `(?:pub[\t ]+)?fn[\t ]+(?:\([^\n]+\)[\t ]+)?[A-Za-z_]\w*[\t ]*\([^\n]*\)[^\n{]*\{`),
	},
	".as": {
		contentSignature("ActionScript", `package(?:[\t ]+[A-Za-z_][\w.]*)?[\t ]*\{`, `(?:public[\t ]+|internal[\t ]+)?(?:final[\t ]+|dynamic[\t ]+)?class[\t ]+[A-Za-z_]\w*`),
		contentSignature("ActionScript", `(?:public[\t ]+|private[\t ]+|protected[\t ]+)?(?:static[\t ]+)?function[\t ]+[A-Za-z_]\w*[\t ]*\([^\n]*\)[\t ]*:[\t ]*[A-Za-z_]\w*`),
		contentSignature("AngelScript", `(?:[A-Za-z_]\w*(?:<[^\n>]+>)?)[\t ]*@\+?[\t ]*[A-Za-z_]\w*[\t ]*(?:[=;,)]|$)`),
		contentSignature("AngelScript", `(?:void|bool|int|uint|float|double|string)[\t ]+[A-Za-z_]\w*[\t ]*\([^\n]*&[\t ]*(?:in|out|inout)\b[^\n]*\)`),
	},
	".cl": {
		contentSignature("Common Lisp", `(?i)\((?:defun|defmacro|defpackage|in-package|defclass|defmethod|defparameter|defvar)[\t ]+[^\s()]+`),
		contentSignature("OpenCL", `(?:(?:__kernel|kernel)[\t ]+void|void[\t ]+(?:__kernel|kernel))[\t ]+[A-Za-z_]\w*[\t ]*\(`),
	},
	".cls": {
		contentSignature("Apex", `(?:public|global)[\t ]+(?:(?:with|without|inherited)[\t ]+sharing[\t ]+)(?:abstract[\t ]+|virtual[\t ]+)?class[\t ]+[A-Za-z_]\w*`),
		contentSignature("Apex", `@(?:isTest|RestResource)\b`, `(?:public[\t ]+|private[\t ]+|global[\t ]+)?(?:(?:with|without|inherited)[\t ]+sharing[\t ]+)?class[\t ]+[A-Za-z_]\w*`),
	},
	".pro": {
		contentSignature("Prolog", `:-[\t ]*(?:module|use_module|dynamic|multifile|discontiguous|initialization)\b[^\n]*\.[\t ]*$`),
		contentSignature("Prolog", `[a-z]\w*[\t ]*\([^\n]*\)[\t ]*:-[\t \n]*[a-z][\w]*(?:\([^.]*)?\.[\t ]*$`),
		contentSignature("QMake", `TEMPLATE[\t ]*=[\t ]*(?:app|lib|subdirs|aux)[\t ]*$`),
		contentSignature("QMake", `(?:QT|CONFIG)[\t ]*\+?=[\t ]*\S`, `(?:SOURCES|HEADERS|FORMS|RESOURCES)[\t ]*\+?=[\t ]*\S`),
	},
	".mod": {
		contentSignature("Modula-2", `(?:IMPLEMENTATION[\t ]+|DEFINITION[\t ]+)?MODULE[\t ]+[A-Za-z_]\w*[\t ]*;`, `(?:FROM[\t ]+[A-Za-z_]\w*[\t ]+IMPORT\b|IMPORT[\t ]+[A-Za-z_]|BEGIN\b|END[\t ]+[A-Za-z_]\w*[\t ]*\.)`),
	},
}

// languageFromContent inspects only a bounded text prefix, never executing it.
// Empty means unsupported, weak, or conflicting evidence, not a default label.
// MATLAB is the conventional label for shared MATLAB/Octave function syntax;
// distinctive Octave syntax takes precedence over that shared evidence.
func languageFromContent(name string, prefix []byte) string {
	if !ambiguousLanguageFilename(name) || strings.EqualFold(filepath.Base(name), "go.mod") {
		return ""
	}
	if len(prefix) > languageContentLimit {
		prefix = prefix[:languageContentLimit]
		// Do not turn a partially read line into a complete signature.
		if end := bytes.LastIndexByte(prefix, '\n'); end >= 0 {
			prefix = prefix[:end+1]
		} else {
			return ""
		}
	}
	if bytes.IndexByte(prefix, 0) >= 0 {
		return ""
	}
	ext := strings.ToLower(filepath.Ext(name))
	text := maskLanguageContent(strings.TrimPrefix(string(prefix), "\xef\xbb\xbf"), ext)
	matches := make(map[string]bool)
	for _, signature := range contentLanguageSignatures[ext] {
		matched := true
		for _, pattern := range signature.patterns {
			if !pattern.MatchString(text) {
				matched = false
				break
			}
		}
		if matched {
			matches[signature.language] = true
		}
	}
	if matches["Octave"] {
		delete(matches, "MATLAB")
	}
	if len(matches) == 1 {
		for language := range matches {
			return language
		}
	}
	return ""
}

// Mask comments and quoted text while preserving line boundaries. This is a
// deliberately conservative lexer, not a parser: comment syntaxes from all
// candidates for a suffix are recognized, including nested Coq/Lisp comments.
func maskLanguageContent(text, ext string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	out := []byte(text)
	mask := func(start, end int, replacement byte) {
		for i := start; i < end; i++ {
			if out[i] != '\n' {
				out[i] = replacement
			}
		}
	}
	for i := 0; i < len(text); {
		rest := text[i:]
		open, close := "", ""
		switch {
		case strings.HasPrefix(rest, "/*"):
			open, close = "/*", "*/"
		case (ext == ".v" || ext == ".mod") && strings.HasPrefix(rest, "(*"):
			open, close = "(*", "*)"
		case ext == ".cl" && strings.HasPrefix(rest, "#|"):
			open, close = "#|", "|#"
		case ext == ".m" && (strings.HasPrefix(rest, "%{") || strings.HasPrefix(rest, "#{")):
			open, close = rest[:2], rest[:1]+"}"
		}
		if open != "" {
			start, depth := i, 1
			i += len(open)
			for i < len(text) && depth > 0 {
				switch {
				case strings.HasPrefix(text[i:], close):
					depth--
					i += len(close)
				case strings.HasPrefix(text[i:], open):
					depth++
					i += len(open)
				default:
					i++
				}
			}
			mask(start, i, ' ')
			continue
		}
		lineComment := strings.HasPrefix(rest, "//") ||
			((ext == ".m" || ext == ".pro") && text[i] == '%') ||
			((ext == ".m" || ext == ".pro") && text[i] == '#') ||
			(ext == ".cl" && text[i] == ';')
		if lineComment {
			end := strings.IndexByte(rest, '\n')
			if end < 0 {
				end = len(rest)
			}
			mask(i, i+end, ' ')
			i += end
			continue
		}
		// Apostrophes are identifier characters in Coq and transpose operators
		// in MATLAB; only treat them as quotes at a token boundary there.
		quote := text[i]
		isQuote := quote == '"' || quote == '\'' || (ext == ".v" && quote == '`')
		if quote == '\'' && (ext == ".m" || ext == ".v") && i > 0 {
			prev := text[i-1]
			if prev >= 'a' && prev <= 'z' || prev >= 'A' && prev <= 'Z' || prev >= '0' && prev <= '9' || strings.ContainsRune("_)]}'", rune(prev)) {
				isQuote = false
			}
		}
		if isQuote {
			start := i
			i++
			for i < len(text) {
				if text[i] == '\\' && i+1 < len(text) {
					i += 2
				} else if text[i] == quote {
					i++
					if i < len(text) && text[i] == quote {
						i++
						continue
					}
					break
				} else {
					i++
				}
			}
			// Non-whitespace prevents text following a literal from becoming
			// an artificial start-of-line declaration.
			mask(start, i, '~')
			continue
		}
		i++
	}
	return string(out)
}
