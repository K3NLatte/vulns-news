package repository

import (
	"path/filepath"
	"strings"
)

// Filename-based inventory, not a parser or a claim of vulnerability coverage.
// Ambiguous suffixes with no reliable filename-only interpretation are omitted.
// Existing .h/.pl defaults remain C/Perl for backwards compatibility.
type languageSpec struct {
	name       string
	extensions string
	filenames  string
}

var languageCatalog = []languageSpec{
	{"C", ".c .h", ""},
	{"C++", ".cc .cpp .cxx .c++ .hh .hpp .hxx .h++ .ipp .tpp .ixx .cppm", ""},
	{"C#", ".cs .csx", ""},
	{"Go", ".go", ""},
	{"Java", ".java", ""},
	{"JavaScript", ".js .jsx .mjs .cjs", ""},
	{"TypeScript", ".ts .tsx .mts .cts", ""},
	{"Kotlin", ".kt .kts", ""},
	{"PHP", ".php .php3 .php4 .php5 .php7 .php8 .phtml", ""},
	{"Python", ".py .pyi .pyw .pyx .pxd .pxi", ""},
	{"Ruby", ".rb .rake .gemspec", "Gemfile Rakefile Guardfile Vagrantfile Podfile"},
	{"Rust", ".rs", ""},
	{"Swift", ".swift", ""},
	{"Dart", ".dart", ""},
	{"Elixir", ".ex .exs", "mix.lock"},
	{"Erlang", ".erl .hrl .escript", "rebar.config rebar.lock"},
	{"Scala", ".scala .sc .sbt", ""},
	{"Clojure", ".clj .cljc", ""},
	{"ClojureScript", ".cljs", ""},
	{"Haskell", ".hs .lhs", ""},
	{"OCaml", ".ml .mli .mll .mly", ""},
	{"R", ".r .rmd", "Rprofile .Rprofile"},
	{"Julia", ".jl", ""},
	{"Perl", ".pl .pm .t .pod", "cpanfile"},
	{"Lua", ".lua .rockspec", ""},
	{"Shell", ".sh .bash .zsh .ksh .csh .tcsh", ".bashrc .bash_profile .zshrc .zprofile .profile"},
	{"Fish", ".fish", ""},
	{"PowerShell", ".ps1 .psm1 .psd1", ""},
	{"Batch", ".bat .cmd", ""},
	{"SQL", ".sql", ""},
	{"HTML", ".html .htm .xhtml", ""},
	{"CSS", ".css", ""},
	{"SCSS", ".scss", ""},
	{"Sass", ".sass", ""},
	{"Less", ".less", ""},
	{"Vue", ".vue", ""},
	{"Svelte", ".svelte", ""},
	{"Astro", ".astro", ""},
	{"Objective-C++", ".mm", ""},
	{"F#", ".fs .fsi .fsx", ""},
	{"Visual Basic .NET", ".vb", ""},
	{"Groovy", ".groovy .gvy .gy .gsh .gradle", "Jenkinsfile"},
	{"Zig", ".zig .zon", ""},
	{"Nim", ".nim .nims .nimble", ""},
	{"Crystal", ".cr", ""},
	{"D", ".d .di", ""},
	{"Fortran", ".f .for .f77 .f90 .f95 .f03 .f08", ""},
	{"COBOL", ".cob .cbl .cpy", ""},
	{"Assembly", ".asm .s", ""},
	{"Racket", ".rkt .rktl", ""},
	{"Scheme", ".scm .ss .sld", ""},
	{"Common Lisp", ".lisp .lsp .cl .asd", ""},
	{"Elm", ".elm", ""},
	{"PureScript", ".purs", ""},
	{"ReasonML", ".re .rei", ""},
	{"ReScript", ".res .resi", ""},
	{"Solidity", ".sol", ""},
	{"Vyper", ".vy", ""},
	{"WebAssembly", ".wat .wast", ""},
	{"MATLAB", ".matlab", ""},
	{"Octave", ".octave", ""},
	{"Ada", ".adb .ads .ada", ""},
	{"Pascal", ".pas .pp .dpr .dpk", ""},
	{"Odin", ".odin", ""},
	{"Hare", ".ha", ""},
	{"Vale", ".vale", ""},
	{"Modula-2", "", ""},
	{"Ceylon", ".ceylon", ""},
	{"Gosu", ".gs .gsx .gst .gsp", ""},
	{"Boo", ".boo", ""},
	{"F*", ".fst .fsti", ""},
	{"Idris", ".idr .lidr .ipkg", ""},
	{"Agda", ".agda .lagda", ""},
	{"Lean", ".lean", ""},
	{"Coq / Rocq", ".coq", ""},
	{"Standard ML", ".sml .sig .fun", ""},
	{"Futhark", ".fut", ""},
	{"Tcl", ".tcl .tk", ""},
	{"AWK", ".awk", ""},
	{"Sed", ".sed", ""},
	{"Raku", ".raku .rakumod .rakutest .p6 .pm6", ""},
	{"AppleScript", ".applescript", ""},
	{"AutoHotkey", ".ahk", ""},
	{"AutoIt", ".au3", ""},
	{"CoffeeScript", ".coffee .litcoffee", "Cakefile"},
	{"LiveScript", ".ls", ""},
	{"Haxe", ".hx .hxml", ""},
	{"ActionScript", ".as", ""},
	{"PureBasic", ".pb .pbi", ""},
	{"GDScript", ".gd", ""},
	{"GML", ".gml", ""},
	{"UnrealScript", ".uc", ""},
	{"Wren", ".wren", ""},
	{"Squirrel", ".nut", ""},
	{"SAS", ".sas", ""},
	{"Stata", ".do .ado .mata", ""},
	{"SPSS", ".sps", ""},
	{"Wolfram Language", ".wl .wls", ""},
	{"Maple", ".mpl .maple", ""},
	{"Scilab", ".sci .sce", ""},
	{"SystemVerilog", ".sv .svh", ""},
	{"Verilog", ".vh .verilog", ""},
	{"VHDL", ".vhd .vhdl", ""},
	{"GLSL", ".glsl .vert .frag .geom .tesc .tese .comp", ""},
	{"HLSL", ".hlsl .hlsli .fx", ""},
	{"WGSL", ".wgsl", ""},
	{"CUDA", ".cu .cuh", ""},
	{"OpenCL", ".opencl", ""},
	{"Metal", ".metal", ""},
	{"ABAP", ".abap", ""},
	{"Apex", ".apex .trigger", ""},
	{"RPG", ".rpg .rpgle .sqlrpgle", ""},
	{"PL/I", ".pli .pl1", ""},
	{"Prolog", ".prolog .yap", ""},
	{"Mercury", "", ""},
	{"Datalog", ".dl .datalog", ""},
	{"MiniZinc", ".mzn .dzn", ""},
	{"SMT-LIB", ".smt .smt2", ""},
	{"Alloy", ".als", ""},
	{"TLA+", ".tla", ""},
	{"Promela", ".pml", ""},
	{"Nix", ".nix", ""},
	{"Starlark", ".bzl .star", "BUILD BUILD.bazel WORKSPACE WORKSPACE.bazel MODULE.bazel"},
	{"CMake", ".cmake", "CMakeLists.txt"},
	{"Makefile", ".mk .mak", "Makefile makefile GNUmakefile BSDmakefile"},
	{"HCL", ".hcl .tf .tfvars", ""},
	{"Dockerfile", "", "Dockerfile Containerfile"},
	{"Meson", ".meson", "meson.build meson_options.txt"},
	{"Ninja", ".ninja", ""},
	{"Just", ".just", "justfile Justfile .justfile"},
	{"Dune", "", "dune dune-project dune-workspace"},
	{"Dhall", ".dhall", ""},
	{"CUE", ".cue", ""},
	{"Jsonnet", ".jsonnet .libsonnet", ""},
	{"Smalltalk", ".st", ""},
	{"Eiffel", ".e", ""},
	{"Io", ".io", ""},
	{"Red", ".red .reds", ""},
	{"REBOL", ".reb .rebol", ""},
	{"Factor", ".factor", ""},
	{"Forth", ".forth .fth .4th", ""},
	{"APL", ".apl .dyalog", ""},
	{"J", ".ijs", ""},
	{"BQN", ".bqn", ""},
	{"Pony", ".pony", ""},
	{"Chapel", ".chpl", ""},
	{"X10", ".x10", ""},
	{"Ballerina", ".bal", ""},
	{"V", "", ""},
	{"AngelScript", "", ""},
	{"Objective-C", "", ""},
	{"Protocol Buffers", ".proto", ""},
	{"GraphQL", ".graphql .gql", ""},
	{"Thrift", ".thrift", ""},
	{"Cap'n Proto", ".capnp", ""},
}

var languageExtensions, languageFilenames = buildLanguageIndex()

func buildLanguageIndex() (map[string]string, map[string]string) {
	extensions, filenames := map[string]string{}, map[string]string{}
	for _, spec := range languageCatalog {
		for _, ext := range strings.Fields(spec.extensions) {
			extensions[ext] = spec.name
		}
		for _, filename := range strings.Fields(spec.filenames) {
			filenames[filename] = spec.name
		}
	}
	return extensions, filenames
}

func languageForFilename(filename string) string {
	if language := languageFilenames[filename]; language != "" {
		return language
	}
	if strings.HasPrefix(filename, "Dockerfile.") || strings.HasPrefix(filename, "Containerfile.") {
		return "Dockerfile"
	}
	// These conventional suffixes are case-sensitive; lowering .C would mean C.
	if filepath.Ext(filename) == ".C" {
		return "C++"
	}
	if ambiguousLanguageFilename(filename) {
		return ""
	}
	return languageExtensions[strings.ToLower(filepath.Ext(filename))]
}
