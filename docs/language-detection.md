# リポジトリの言語検出

認識対象のファイル名・拡張子の定義は `src/repository/languages.go` にあります。
`language_content.go` には、複数の言語で共有される拡張子を、読み取り範囲を制限して判別するルールがあります。
これは使用言語の一覧を作る機能であり、**Package Managerの解析器・コンパイラ・呼び出しグラフ・脆弱性スキャナーの追加ではありません**。
判別できないファイルは一覧から除外しますが、安全と判定するわけではありません。
幅広い言語を対象にしていますが、世界中のすべての言語を網羅する一覧ではありません。

## 追加した言語・形式の分類

- **論理・制約系**：Prolog、Mercury、Datalog、MiniZinc、SMT-LIB、Alloy、TLA+、Promela。
  Prologの `.prolog`／`.yap` はファイル名から判定します。
  `.pro` とMercuryの `.m` は、内容に識別可能な構文が必要です。
- **ビルド・設定用DSL**：Nix、Starlark／Bazel、CMake、Makefile、HCL／Terraform、
  Dockerfile／Containerfile、Meson、Ninja、Just、Dune、Dhall、CUE、Jsonnet、内容から判別できるQMake。
  `BUILD`、`MODULE.bazel`、`CMakeLists.txt`、`GNUmakefile`、`meson.build`、`justfile` などのファイル名も認識します。
- **シェル・Web系**：シェルスクリプト、Fish、PowerShell、Batch、SQL、HTML、CSS、SCSS、Sass、
  Less、Vue、Svelte、Astro、CoffeeScript、LiveScript、Elm、PureScript、ReScript、ReasonML、
  Solidity、Vyper、WebAssemblyのテキスト形式。
- **システム・JVM・.NET系**：Objective-C／C++、F#、VB.NET、Groovy、Zig、Nim、Crystal、D、V、
  Fortran、COBOL、アセンブリ言語、Ada、Pascal／Delphi、Odin、Hare、Vale、Modula-2、Ceylon、Gosu、Boo。
- **関数型・定理証明系**：Racket、Scheme、Common Lisp、F*、Idris、Agda、Lean、Coq／Rocq、
  Standard ML、Futhark。
- **スクリプト・ゲーム系**：Tcl、AWK、Sed、Raku、AppleScript、AutoHotkey、AutoIt、Haxe、
  ActionScript、PureBasic、GDScript、GML、AngelScript、UnrealScript、Wren、Squirrel。
- **科学技術・業務系**：MATLAB、Octave、SAS、Stata、SPSS、Wolfram Language、Maple、Scilab、
  ABAP、Apex、RPG、PL/I。
- **ハードウェア・GPU系**：Verilog、SystemVerilog、VHDL、GLSL、HLSL、WGSL、CUDA、OpenCL、
  Metal Shading Language。
- **その他**：Smalltalk、Eiffel、Io、Red、REBOL、Factor、Forth、APL、J、BQN、Pony、Chapel、
  X10、Ballerina、Protocol Buffers、GraphQL、Thrift、Cap'n Proto。
- **既存の対応**：Go、Java、JavaScript／TypeScript、Python、Ruby、Rust、Swift、Kotlin、PHP、
  Dart、Elixir、Erlang、Scala、Clojure、Haskell、OCaml、R、Julia、Perl、Lua、C、C#の検出も維持しています。

## 判定の優先順位と曖昧な拡張子

1. 特殊ファイル名の完全一致ルールを優先します。
2. `Dockerfile.*` と `Containerfile.*` はビルド用ファイルとして認識します。
3. `.C` はC++、`.c` はCとして区別します。それ以外の拡張子ルールは大文字・小文字を区別しません。
4. 複数言語で共有される `.m`、`.v`、`.as`、`.cl`、`.cls`、`.pro`、`.mod` は、内容に識別可能な構文が必要です。
   判別対象は先頭16 KiBまでで、リポジトリ全体の読み取り上限は8 MiBです。
   明らかなコメントや引用符内の文字列は判定対象から隠します。
   根拠が矛盾する場合や不足する場合は、言語を確定しません。
5. 曖昧さのない登録済み拡張子は、定義一覧に従って判定します。

例えば `.m` はObjective-C・MATLAB／Octave・Mercury、`.v` はVerilog・Coq／Rocq・V、
`.cl` はCommon Lisp・OpenCLの可能性があります。
MATLABとOctaveで共通する構文は、慣例上MATLABと表示します。
Octave固有の構文が見つかった場合は、そちらを優先します。
識別可能な構文が読み取り範囲より後にある場合、共通の構文しかない場合、別の拡張子が使われている場合には、
言語を検出できないことがあります。これらは推定ルールであり、完全な構文解析器ではありません。

一部の既定の判定には、意図的に曖昧さを残しています。
`.h` はC、`.pl` はPerl、`.fs` はF#、`.ts` はTypeScriptとして扱います。
ファイル名だけでは、すべての言語・方言・データ・生成物を正確に区別できません。
対象言語のコードを実行することはありません。
拡張子のないシバン付きスクリプトは、特殊ファイル名のルールに一致しない限り分類しません。
Vue／Svelte／Astroはコンポーネント形式として数え、内部に埋め込まれた言語を個別に抽出することはしません。

## 出力と処理上限

既存の `RepositoryProfile.languages` のスキーマは変更していません。
割合は**認識したファイルの数**を基準に算出します。
バイト数・コード行数・GitHub Linguistの統計ではありません。
DSLやコンポーネントのファイルも分母に含みます。言語を判別できないファイルは含みません。

言語の並びとソースパスの例は決定的に出力し、各言語について最大10件のソースパスを保持します。
`.git`、`node_modules`、`.pnpm`、`.yarn` は探索しません。
シンボリックリンクと通常ファイル以外の項目は読み飛ばし、解析対象のルート自体がシンボリックリンクの場合は拒否します。
内容の読み取りには `os.Root` を使い、ルート外へのアクセスを制限します。
探索する項目数には固定上限を設けていません。内容の読み取りは合計8 MiBに制限しています。
解析中に変更されないチェックアウトを使用してください。
この処理は、攻撃者による同時変更から保護するサンドボックスではありません。

## 検証方法

```sh
go test ./src/repository -run 'TestLanguage|TestFilename|TestDetectLanguages'
go test ./...
go vet ./...
```
