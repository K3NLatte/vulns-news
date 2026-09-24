# Repository language detection

`src/repository/languages.go` is the source of truth for recognized filenames and
extensions. `language_content.go` contains bounded heuristics for shared suffixes.
This is a language inventory, **not** an added package-manager parser, compiler,
call graph, or vulnerability scanner. Unknown files are omitted, not classified
as safe. This catalogue is broad but is not an exhaustive list of world languages.

## Added families

- Logic/constraints: Prolog, Mercury, Datalog, MiniZinc, SMT-LIB, Alloy, TLA+,
  Promela. Prolog `.prolog`/`.yap` are filename rules; `.pro` and Mercury `.m`
  require distinctive content.
- Build/configuration DSLs: Nix, Starlark/Bazel, CMake, Makefile, HCL/Terraform,
  Dockerfile/Containerfile, Meson, Ninja, Just, Dune, Dhall, CUE, Jsonnet and
  content-qualified QMake. Recognizes names such as `BUILD`, `MODULE.bazel`,
  `CMakeLists.txt`, `GNUmakefile`, `meson.build`, and `justfile`.
- Shell/web: shell scripts, Fish, PowerShell, Batch, SQL, HTML, CSS, SCSS, Sass,
  Less, Vue, Svelte, Astro, CoffeeScript, LiveScript, Elm, PureScript, ReScript,
  ReasonML, Solidity, Vyper and WebAssembly text.
- Systems/JVM/.NET: Objective-C/C++, F#, VB.NET, Groovy, Zig, Nim, Crystal, D,
  V, Fortran, COBOL, Assembly, Ada, Pascal/Delphi, Odin, Hare, Vale, Modula-2,
  Ceylon, Gosu and Boo.
- Functional/proofs: Racket, Scheme, Common Lisp, F*, Idris, Agda, Lean,
  Coq/Rocq, Standard ML and Futhark.
- Scripting/game: Tcl, AWK, Sed, Raku, AppleScript, AutoHotkey, AutoIt, Haxe,
  ActionScript, PureBasic, GDScript, GML, AngelScript, UnrealScript, Wren, Squirrel.
- Scientific/business: MATLAB, Octave, SAS, Stata, SPSS, Wolfram Language,
  Maple, Scilab, ABAP, Apex, RPG and PL/I.
- Hardware/GPU: Verilog, SystemVerilog, VHDL, GLSL, HLSL, WGSL, CUDA, OpenCL,
  Metal Shading Language.
- Other: Smalltalk, Eiffel, Io, Red, REBOL, Factor, Forth, APL, J, BQN, Pony,
  Chapel, X10, Ballerina, Protocol Buffers, GraphQL, Thrift and Cap'n Proto.
- Existing Go, Java, JavaScript/TypeScript, Python, Ruby, Rust, Swift, Kotlin,
  PHP, Dart, Elixir, Erlang, Scala, Clojure, Haskell, OCaml, R, Julia, Perl,
  Lua, C and C# remain recognized.

## Selection and ambiguity

1. Exact special filename rules take priority.
2. `Dockerfile.*` and `Containerfile.*` are recognized as build files.
3. `.C` remains C++; `.c` is C. Other extension rules are case-insensitive.
4. Shared `.m`, `.v`, `.as`, `.cl`, `.cls`, `.pro`, `.mod` suffixes need
   distinctive content. Only the first 16 KiB is interpreted, with a total
   read budget of 8 MiB per repository. Obvious comments and quoted strings
   are masked. Conflicting or insufficient evidence returns no language.
5. Unambiguous configured suffixes use the catalogue.

Examples: `.m` can be Objective-C, MATLAB/Octave or Mercury; `.v` can be Verilog,
Coq/Rocq or V; `.cl` can be Common Lisp or OpenCL. Shared MATLAB/Octave syntax is
conventionally labeled MATLAB, while distinctive Octave syntax takes priority.
A language can still be missed when its identifying syntax is beyond the prefix,
when only shared syntax appears, or when another extension is used. These rules
are heuristics, not full parsers.

Some conventional defaults remain intentionally lossy: `.h` is C, `.pl` is Perl,
`.fs` is F#, and `.ts` is TypeScript. File names alone cannot reliably distinguish
all languages, dialects, data and generated artifacts. No language is executed.
Extensionless shebang scripts are not classified unless a special filename rule
matches. Vue/Svelte/Astro count as component formats; embedded languages are not
individually extracted.

## Output and bounds

The existing `RepositoryProfile.languages` schema is unchanged. Percentages are
**recognized file counts**, not bytes, lines of code or GitHub Linguist statistics.
DSL and component files count toward that denominator. Unknown files do not.
Language entries and source examples are deterministic; at most ten source paths
are retained per language. `.git`, `node_modules`, `.pnpm`, and `.yarn` are skipped.
Symlink entries and non-regular files are skipped; root symlinks are rejected.
Content opens are confined with `os.Root`. The existing 100,000-entry traversal
limit remains. Use an immutable checkout; this is not a hostile-mutation sandbox.

## Verification

```sh
go test ./src/repository -run 'TestLanguage|TestFilename|TestDetectLanguages'
go test ./...
go vet ./...
```
