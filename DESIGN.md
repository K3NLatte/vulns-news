---
name: "vulns-news"
description: "脆弱性情報を比較し、影響範囲と対応の根拠を確認する日本語UI"
colors:
  accent: "#146b5c"
  accent-hover: "#0f574a"
  selected: "#edf6f3"
  focus: "#0b7767"
  ink: "#20363f"
  muted: "#5f7078"
  subtle: "#687a82"
  line: "#dce4e7"
  surface: "#fff"
  workspace: "#f3f6f7"
  header-bg: "#182d36"
  header-ink: "#f3f8f8"
  header-mark: "#a2d9c9"
  input-border: "#bdcdd3"
  button-border: "#aabec5"
  secondary-hover: "#edf3f4"
  row-hover: "#f4f8f8"
  analysis-bg: "#f2f5f8"
  demo-bg: "#e8eef0"
  demo-ink: "#4c616b"
  critical-bg: "#f9e7e8"
  critical-ink: "#a32637"
  high-bg: "#fff0e5"
  high-ink: "#a14b12"
  medium-bg: "#f5f0d9"
  medium-ink: "#796015"
  low-bg: "#e8eff9"
  low-ink: "#3a6191"
typography:
  headline:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "27px"
    fontWeight: 700
    lineHeight: 1.45
    letterSpacing: "-.035em"
  title:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "21px"
    fontWeight: 700
    lineHeight: 1.65
    letterSpacing: "-.025em"
  title-list:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "15px"
    fontWeight: 650
    lineHeight: 1.75
    letterSpacing: "-.015em"
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.95
  body-list:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.85
  section-title:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "14px"
    fontWeight: 650
    lineHeight: 1.6
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "12px"
    fontWeight: 600
  identifier:
    fontFamily: "ui-monospace, \"Cascadia Code\", Consolas, monospace"
    fontSize: "11px"
    fontWeight: 400
rounded:
  badge: "3px"
  small: "4px"
  control: "6px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
  wide: "36px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.surface}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "9px 14px"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "9px 14px"
  button-secondary-hover:
    backgroundColor: "{colors.secondary-hover}"
  button-text:
    textColor: "{colors.accent}"
    padding: "6px 0"
  button-icon:
    textColor: "{colors.muted}"
    rounded: "{rounded.small}"
    width: "30px"
  input-search:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "9px 36px 9px 39px"
  feed-navigation:
    textColor: "{colors.muted}"
    padding: "13px 0 14px"
  feed-navigation-active:
    textColor: "{colors.accent}"
  severity-badge:
    rounded: "{rounded.badge}"
    padding: "3px 6px"
  feed-row:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    padding: "20px 22px 17px"
  feed-row-selected:
    backgroundColor: "{colors.selected}"
  analysis-card:
    backgroundColor: "{colors.analysis-bg}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "17px 18px"
  input-repository:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "10px 12px"
---

# Design System: vulns-news

## Overview

**Creative North Star: "根拠を確認できる情報面"**

セキュリティ従事者が、脆弱性情報の重要度・悪用状況・依存関係との関連性を読み分けるための日本語UI。識別子や数値は比較しやすく、説明文は読み進めやすく配置する。落ち着いた背景と白い情報面に、操作と選択を示す緑を絞って使う。

日本語UI、読みやすさ、単純な保守性、架空データと実データの区別はPRODUCT.mdの確定要件である。色、書体構成、余白、一覧と詳細の構成は、任されたローカル実装で採用した暫定判断であり、ユーザーが個別に指定・承認したブランド仕様ではない。本書は2026-09-24時点のfrontend/src/styles.cssとVueコンポーネントから抽出した実装記録とする。

数値とトークンは現行実装の基準であり、本文は使い分けを説明する。更新時はCSSとコンポーネントの変更を同時に反映する。最初のフィード画面の構成理由は、ローカルのsurface briefに置く。

**Key Characteristics:**

- 比較と読解を支える、罫線と余白による情報整理。
- 操作の緑と重要度の色を区別し、文字ラベルを併記。
- 一覧の要約と詳細本文で密度を変え、狭い画面では読む面を切り替える。

## Colors

冷たい明るい背景に、濃い文字と抑えた緑のアクセントを組み合わせる。以下の名称は実装上の用途を表し、ブランドカラー名として承認されたものではない。値はfrontmatterを参照する。

### Primary

- **操作の緑（accent / accent-hover）**：主要ボタン、リンク、選択された表示対象。hoverは同系色を暗くする。
- **選択の淡い緑（selected）**：選択中の一覧行とリポジトリ関連性の説明面。
- **フォーカスの緑（focus）**：キーボード操作の位置を示す輪郭。

### Neutral

- **本文と補助文字（ink / muted / subtle）**：本文、要約や補助情報、小さな注記の順に使い分ける。
- **白い情報面と作業背景（surface / workspace）**：記事の面とその外側を分ける。
- **区切りと入力枠（line / input-border / button-border）**：記事の境界、入力欄、補助ボタンを整理する。
- **濃いヘッダー（header-bg / header-ink / header-mark）**：短い製品名とモックの説明への入口。
- **補助面（analysis-bg / demo-bg / demo-ink）**：AI分析サンプルと画面全体のデモ説明を読み分ける。
- **操作前後の中間色（secondary-hover / row-hover）**：補助ボタンや未選択行へのhover。

### 重要度の意味色

critical、high、medium、lowは、各々の淡い背景と濃い文字色を組み合わせる。バッジには文字ラベルと、ある場合はCVSS値を添える。悪用観測はcritical-inkと文字・アイコンで示すが、重要度とは別の項目である。

**意味を混ぜない** 選択・操作にはaccent系、重要度には四段階のラベル付き配色を使う。赤い重要度を、リポジトリとの関連性やAIの確度の代わりに使わない。

sidecarの8段階tonalRampは、抽出色から生成したプレビュー用の補助情報である。現在のCSSに8段階の色階調が実装されているという意味ではない。

## Typography

UIと日本語本文はシステムのサンセリフを使い、外部フォント配信には依存しない。等幅書体は識別子、パッケージ名、バージョン、リポジトリURLに限定する。日付、CVSS、件数には等幅数字を使う。

| 役割 | トークン | 使い方 |
| --- | --- | --- |
| ページ見出し | headline | 画面の目的を短く示す。 |
| 記事詳細見出し | title | 長文は自然に折り返す。 |
| 一覧タイトル | title-list | 要約より強く、重要度バッジより読みやすくする。 |
| 詳細本文 | body | 要約の基準。行送りを広く取る。 |
| 一覧要約 | body-list | 最大2行で省略し、全文は詳細に置く。 |
| 詳細内の区切り | section-title | 対応、関連性、推定、参考情報を分ける。 |
| 操作ラベル | label | 主・補助ボタンの基準。 |
| 識別子 | identifier | UI本文から区別する。 |

一覧要約は13px、詳細要約は14pxを採用している。対応手順とAI分析本文も14pxで、行高は手順・分析要約が1.9、分析の根拠・関連性の説明が1.85。これらは最終CSSから確認した値である。注記やメタデータには10〜12pxを使用するが、説明本文の代わりにはしない。

狭い画面ではページ見出しを23px、詳細見出しを20pxにする。一覧要約13px・詳細本文14pxは維持する。一覧タイトルの行高は1.8になる。これらはresponsive layerの差分であり、frontmatterの基本値を置き換えない。

**本文の可読性** 一覧要約にはbody-list、詳細の要約にはbodyを使う。対応手順・関連性の説明・AI分析の本文も詳細と同じ文字サイズを保ち、情報量を理由に注記サイズへ縮めない。

## Layout

内容領域は中央寄せで、最大幅は1600px。通常の左右余白は36px、1100px以下で24px、599px以下で16pxになる。画面全体の見出し・操作域と、記事を読む領域を分ける。

現在のフィードは一覧と詳細の2列で、比率は1:1.05。1100px以下では1:1.08。左右の面は独立してスクロールする。高さは画面高から上部を引き、最低565pxを確保する。記事行は密度を抑え、詳細は横方向に広めの余白を取る。この比率や高さは現行フィードの実装値であり、将来の全画面に強制する基準ではない。

899px以下では1面表示に切り替え、一覧で選択すると詳細を表示する。「一覧に戻る」で選択行へフォーカスを戻す。読込中・0件・エラー・リポジトリ未指定は一覧領域を1面で使う。599px以下ではリポジトリ入力と実行ボタンを縦に並べる。最小対応幅は320px。

余白トークンはCSSで繰り返し使われる値を抽出したもので、CSS変数による統一スケールが既にあるわけではない。新しい要素は既存の近い役割に合わせ、独立した余白体系を増やさない。

## Elevation & Depth

情報面はフラット。内容の所属は背景の差、細い境界線、余白で示す。状態を試すポップオーバーも境界線付きの白い面で、影は付けていない。強い奥行きや装飾画像は、現在のUIでは使っていない。

**影に頼らない区切り** 通常面、選択面、推定を示す面は、背景色・罫線・余白で区別する。現行実装にbox-shadowはない。

操作の色と枠色の変化は150ms ease-out。読込中のスケルトンのみ1.5秒の緩やかな明暗変化がある。prefers-reduced-motionではtransitionとanimationを停止する。面の選択に移動や拡大のアニメーションは使わない。

## Shapes

入力欄、主要なボタン、記事領域、説明面にはcontrolの小さな角丸を使う。アイコンボタンはsmall、重要度バッジはbadge。記事行そのものは四角く、行間の1px罫線で連続した一覧として見せる。丸い形はバッジの点など、小さな状態記号に限る。

フォーカスは通常2pxの輪郭と3pxの外側余白で示す。一覧行では輪郭を内側へ入れ、ヘッダーでは明るいheader-markを使う。詳細見出しへのプログラムによるフォーカスは、操作を中断しないため輪郭を表示しない。

## Components

### ボタン

主要ボタンは緑の面と白文字、補助ボタンは白い面と輪郭。最小高は40px。hoverで背景を変え、focus-visibleで輪郭を出す。テキストボタンは緑の文字とhover時の下線、アイコンボタンは透明な面とhover時の淡い背景を使う。アイコン単独には読み上げ用ラベルを付ける。無効状態はカーソルと不透明度で表す。

### 入力とフィルター

検索欄は左に検索アイコン、入力後は右にクリア操作を置く。重要度と並び順はラベル付きのネイティブselect。通常の最小高は39px、狭い画面の検索欄は42px。リポジトリURLは等幅書体とし、無効値には赤い枠と具体的なエラーテキストを併記する。URLを外部送信しないモックであることを入力欄の近くにも書く。

### 表示対象ナビゲーション

一般とリポジトリ向けの表示は、下線・緑文字・太さ・aria-pressedで選択を示す。ルート間移動ではなく、同じフィードの表示対象を切り替えるボタンである。

### 重要度バッジ

淡い面、濃い文字、小さな点を組み合わせる。CVSS値を併記する場合は細い区切り線を入れる。スコアのないデータを架空の数値で埋めない。

### 記事行と詳細

記事行は行全体がボタンで、重要度・識別子・公開日、タイトル、最大2行の要約、製品と悪用状況または関連性を縦に並べる。選択は淡い緑の面とaria-currentで示す。選択時は詳細見出しへフォーカスを移し、モバイルでは読む面を表示する。

詳細は要約、対象・影響・修正・公開日の定義リスト、対応、推定、参考資料の順に整理する。識別子のコピーには成功・失敗のフィードバックを出す。外部資料には新しいタブで開くことを知らせる。

### 推定・関連性・デモ表示

AI分析のサンプルはanalysis-bgの面にまとめ、想定の確度と折りたたみ可能な根拠を添える。関連性の面には淡い緑を使い、依存構成がサンプルであることを記す。全体のデモ帯に加えて、記事・AI分析・依存構成の表示箇所にもサンプルであることを明示する。

### 読込中・0件・エラー・未指定

読込中は5行のスケルトンと読み上げ用の状態。0件は条件解除、エラーは再読込、未指定はサンプルURLを試す操作へつなぐ。結果件数はaria-liveで通知する。常時表示する成功メトリクスなど、未実装の状態を推測させる要素は追加しない。

## Do's and Don'ts

### Do:

- **Do** 重要度、悪用状況、関連性、AIの確度を別の情報として表示し、色と文字ラベルを併用する。
- **Do** 一覧要約と詳細本文の役割を保ち、長い識別子・バージョン・日本語タイトルが折り返せるようにする。
- **Do** 架空の記事、AI分析のサンプル、サンプル依存構成をそれぞれの表示箇所でも明示する。
- **Do** キーボードフォーカス、読込中・0件・エラー・未指定状態、一覧に戻る操作を新しい画面でも確認する。

### Don't:

- **Don't** 暫定パレットやレイアウトを、ユーザー承認済みのブランド仕様として扱わない。
- **Don't** 本文を識別子用の等幅書体に置き換えたり、注記と同じサイズに縮めたりしない。
- **Don't** 重要度の色だけで状態を伝えたり、選択状態に警告色を流用したりしない。
- **Don't** 未接続のLLMや未実装の保存・認証・解析を、動作中の機能として見せない。
