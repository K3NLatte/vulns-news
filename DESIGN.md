---
name: "vulns-news"
description: "脆弱性の影響・根拠・対応を確認する日本語フィード"
colors:
  accent: "#174bd1"
  accent-hover: "#103aa8"
  selected: "#f0f4ff"
  focus: "#174bd1"
  ink: "#171717"
  muted: "#575757"
  line: "#d8d8d8"
  surface: "#fff"
  workspace: "#fafafa"
  neutral-soft: "#f0f0f0"
  critical: "#a51d32"
  high-ink: "#933c0a"
  high-bg: "#fff0e5"
  medium-ink: "#725500"
  medium-bg: "#fff5cd"
  low-ink: "#246349"
  low-bg: "#e7f3ed"
  severity-ink: "#383838"
  error: "#a32020"
typography:
  headline:
    fontFamily: "\"Yu Mincho\", \"Hiragino Mincho ProN\", \"Noto Serif JP\", Georgia, serif"
    fontSize: "2rem"
    fontWeight: 700
    lineHeight: 1.45
    letterSpacing: ".02em"
  headline-feed:
    fontFamily: "\"Yu Mincho\", \"Hiragino Mincho ProN\", \"Noto Serif JP\", Georgia, serif"
    fontSize: "1.625rem"
    fontWeight: 700
    lineHeight: 1.45
    letterSpacing: ".02em"
  title-expanded:
    fontFamily: "\"Yu Mincho\", \"Hiragino Mincho ProN\", \"Noto Serif JP\", Georgia, serif"
    fontSize: "2rem"
    fontWeight: 700
    lineHeight: 1.6
    letterSpacing: "-.015em"
  title:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 700
    lineHeight: 1.65
    letterSpacing: "-.015em"
  title-list:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 650
    lineHeight: 1.7
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.9
  body-list:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.8
  body-expanded:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 400
    lineHeight: 1.9
  section-title:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 700
    lineHeight: 1.6
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: ".875rem"
    fontWeight: 400
  control:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Noto Sans JP\", \"Yu Gothic UI\", \"Hiragino Kaku Gothic ProN\", Meiryo, sans-serif"
    fontSize: "1rem"
    fontWeight: 600
    lineHeight: 1.4
  identifier:
    fontFamily: "ui-monospace, \"Cascadia Code\", Consolas, monospace"
    fontSize: ".875rem"
    fontWeight: 400
rounded:
  control: "3px"
spacing:
  small: "8px"
  compact: "12px"
  medium: "16px"
  section: "24px"
  content: "28px"
  column: "28px"
  large: "48px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.surface}"
    typography: "{typography.control}"
    rounded: "{rounded.control}"
    padding: "10px 18px"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.control}"
    rounded: "{rounded.control}"
    padding: "10px 18px"
  button-secondary-hover:
    backgroundColor: "{colors.neutral-soft}"
  button-text:
    textColor: "{colors.accent}"
    typography: "{typography.label}"
    padding: "6px 2px"
  button-icon:
    textColor: "{colors.muted}"
    rounded: "{rounded.control}"
    width: "44px"
  input-search:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "11px 44px"
  select-control:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "10px 42px 10px 13px"
  feed-navigation:
    textColor: "{colors.muted}"
    padding: "14px 0"
  feed-navigation-active:
    textColor: "{colors.ink}"
  severity-badge:
    backgroundColor: "{colors.neutral-soft}"
    textColor: "{colors.severity-ink}"
    padding: "4px 7px"
  severity-critical:
    backgroundColor: "{colors.critical}"
    textColor: "{colors.surface}"
  severity-high:
    backgroundColor: "{colors.high-bg}"
    textColor: "{colors.high-ink}"
  severity-medium:
    backgroundColor: "{colors.medium-bg}"
    textColor: "{colors.medium-ink}"
  severity-low:
    backgroundColor: "{colors.low-bg}"
    textColor: "{colors.low-ink}"
  analysis-status:
    textColor: "{colors.ink}"
    padding: "12px 0"
  analysis-pending:
    backgroundColor: "{colors.medium-bg}"
    textColor: "{colors.medium-ink}"
    padding: "3px 6px"
  feed-row:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    padding: "24px 24px 10px"
  feed-row-selected:
    backgroundColor: "{colors.selected}"
  impact-panel:
    backgroundColor: "{colors.selected}"
    textColor: "{colors.ink}"
    padding: "20px"
  account-dialog:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    padding: "28px"
    width: "min(480px, calc(100% - 32px))"
---

# Design System: vulns-news

## Overview

**Creative North Star: "余白と文字で読み分ける"**

白・黒・グレーを土台に、青を操作・選択へ使う。重要度と対応優先度には赤・橙・黄・緑の意味色を使い、文字ラベルを併記する。日本語本文はサンセリフ、ページ見出しと独立記事の見出しは明朝系。罫線と文字の強弱で情報を整理し、内容を読み比べられる画面にする。

この配色と、カンザキイオリ／amazarashiのモチーフを余白・文字へ抽象化する方針はユーザー指定。歌詞、ロゴ、写真、既存レイアウトは使わない。具体的な値は2026-09-25時点のfrontend/src/styles.css、useFeedPanes.tsとVueコンポーネントから記録したもので、今後も実装と一緒に更新する。

方向選定の記録はローカルのsurface briefに置く（候補キーc9431a34、候補5）。探索候補よりユーザー指定を優先する。機能範囲とモックの実装境界はPRODUCT.md、README、統合文書で扱う。

**Key Characteristics:**

- 左の一覧はページ全体でスクロールし、右の詳細だけが画面に追従する。
- 本文・タイトル・補助情報を役割別の大きさで区別。
- CVSS、関連度、対応優先度、分析の確度を別々に示す。

## Colors

値はfrontmatterを基準とする。通常の本文はink、補助情報はmuted、記事面はsurface、ページ背景はworkspace、区切りはlineを使う。

- **Primary**：accentは主要操作・リンク・選択の下線。hoverはaccent-hover、選択行と関連性の説明面はselected。focusはキーボード位置を示す。
- **Neutral**：本文・補助文字・記事面・罫線の階層は白・黒・グレーで作る。意味を持たない装飾色は増やさない。
- **意味色**：CVSSの緊急と対応優先度の最優先はcritical、高はhigh、中はmedium、低はlow。緊急は赤い面と白文字、それ以外は淡い背景と濃い文字を組み合わせる。要確認はグレー、分析の未確定は黄。入力・保存エラーと削除操作にはerrorを使う。

**意味を分ける** CVSS、対応優先度、分析の未確定は、それぞれ明示的なラベルで示す。同じ意味色を使っていても、同じ尺度として扱わない。青い選択面は重要度の代わりにしない。

sidecarのtonalRampは抽出色から作るプレビュー用階調で、製品CSSに追加する色トークンではない。

## Typography

基準は16px。本文・操作はOSの日本語サンセリフ、紙面の見出しは明朝系、識別子・バージョン・コードは等幅書体。外部フォント配信は使わない。

| 役割 | 実装上の大きさ | 行高・用途 |
| --- | --- | --- |
| 一般ページ見出し | 32px、599px以下は28px | 1.45、明朝系 |
| PCのフィード見出し | 26px | 幅1000px以上で操作域をコンパクトにする |
| 一覧タイトル | 18px | 1.7、太さ650 |
| 詳細列の見出し | 24px | 1.65 |
| 独立記事の見出し | 32px、599px以下は26px | 1.6、狭い画面は1.7 |
| 一覧要約 | 16px | 1.8、最大2行 |
| 詳細本文・対応・分析 | 16px | 主に1.9 |
| 独立記事の冒頭要約 | 18px、599px以下は16px | 1.9 |
| 入力・主要ボタン | 16px | 入力を補助文字サイズへ縮めない |
| 日付・ラベル・識別子 | 14px | 内容の主従を示す |
| 事実欄の値 | 16px、599px以下は15px | 1.7 |

詳細要約の行長は最大70ch。日付、CVSS、件数は等幅数字。文字サイズはCSSでrem、レイアウトは主にpxで指定する。

**役割から文字を選ぶ** 本文と入力は16px、一覧タイトルは18px、補助情報は14pxを基本とする。全文の読解に必要な情報を補助ラベルの密度へ落とさない。

比較資料として、[GOV.UKのType scale](https://design-system.service.gov.uk/styles/type-scale/)は本文19px・小さい本文16pxと画面幅別の見出しを定義し、[CarbonのType sets](https://carbondesignsystem.com/elements/typography/type-sets/)は用途に応じた14pxと16pxの基準を用意している。本画面の16/18/14pxは日本語の読解と操作密度に合わせた採用値であり、全UIに共通する「最低16px」という規則ではない。

## Layout

内容の最大幅は1600px。PCのフィードは左右余白32px・上下16px、一覧と詳細は1:1.08の2列で列間28px。記事ページは最大960px、設定ページは最大1000px。

左の一覧は高さ制限も内部スクロールも持たず、ページ全体と一緒に流れる。ヘッダーと検索・フィルターなどの上部操作域も固定しない。右の詳細だけが上端16pxで追従する。操作行と記事ヘッダー（ID・タイトル・CVSS）は表示したままにし、その下の本文だけを縦にスクロールする。詳細全体はflexの縦積みでoverflow:hidden、本文はflex:1とoverflow-y:autoを持つ。

右の高さはuseFeedPanesで画面内に残る高さから測る。最小280pxを確保し、上部操作域が画面外へ流れるにつれて伸び、追従位置では画面高から上下16pxを引いた高さになる。左のリスト長をこの高さへ揃えない。

| 条件 | 変更 |
| --- | --- |
| 幅1000px以上かつ高さ500px × 文字拡大率以上 | 一覧と、本文だけが独立スクロールする詳細を並べる。 |
| 1199px以下 | 検索を全幅にし、フィルターを次の行へ。 |
| 幅1000px未満、または必要な画面高に満たない場合 | 一覧を1列にし、記事選択で記事ページへ移る。 |
| 999px以下 | 記事ページの最大幅800px。 |
| 599px以下 | 左右余白16px。設定・入力・操作群は折り返す。事実欄や関連性の配置を簡略化。 |

最小幅は320px。余白の抽出値はfrontmatterのspacingにまとめる。CSSに余白変数が既にあるという意味ではない。

**一覧と詳細のスクロールを分ける** 左は自然な文書スクロール、右は操作と記事ヘッダーを残して本文だけをスクロールする。両方を同じ高さの箱に入れない。並列表示に必要な画面高は標準16pxで500pxとし、ルート文字サイズの拡大率に応じて増やす。

## Elevation & Depth

影は使わない。情報の区切りには通常1pxの罫線、一覧・詳細・設定セクションの起点には2pxの濃い線を使う。淡い青の面は関連性と選択を示す。アカウントダイアログだけ、黒45%のbackdropで背後の操作を一時停止する。

操作の色・背景・枠色は120ms ease。読込中のスケルトンは1.5秒の明暗変化。prefers-reduced-motionではいずれも停止する。

## Shapes

ボタンと入力欄は小さな角丸（control）。記事行、意味ラベル、関連性の面は四角く保つ。主要・補助・アイコンボタンは最小44px、入力とselectは最小46px。フォーカスは2pxの青い輪郭と3pxの外側余白で示し、一覧行では輪郭を内側へ置く。

## Components

- **ヘッダーとナビゲーション**：製品名はGeorgia、newsの下線に青。フィード対象はリンクとaria-currentで表示し、保存・設定・アカウントへ移動できる。faviconは白地に黒のセリフ付きVと青い下線を描いた独自SVG。
- **検索・select**：検索はラベルとクリア操作を持つ。selectはネイティブの意味とキーボード操作を保ち、装飾の矢印だけ別要素にする。
- **記事行**：CVSS、識別子、日付、タイトル、2行要約、製品を整理。リポジトリ表示では「分析済み／未確定」、関連度、対応優先度を分ける。記事選択、保存、ページ表示は別の操作。
- **詳細・記事ページ**：対象・影響版・修正版を定義リストで示し、関連性、対応状況、手順、分析、参照情報を分ける。独立記事ではコメントを表示する。
- **設定とアカウント**：設定は通常ページ。複数リポジトリを追加・選択・削除し、削除は行内で確認する。アカウントにはnative dialogを使い、Escと閉じた後のフォーカス復帰に対応する。
- **コメントとPoC**：本文は文字列で描画。コメントは改行と長文の折り返しを保ち、投稿・削除・エラーを示す。PoCは折りたたみ可能な静的テキストで、実行操作を置かない。
- **解析状態**：待ち、構成確認、照合、関連性確認、記事分析、完了、失敗を段階表示する。結果は「すべて／分析済み／未確定」で絞り込む。未確定には黄色い説明を置き、関連度を未確定と表示し、対応手順・分析本文を隠す。既に得られた記事は処理中・失敗時も読める。件数は判明している値だけを表示し、状態欄とフィルターで重複させない。
- **状態**：読込中、0件、取得エラー、リポジトリ未指定、保存0件を区別し、再試行・条件解除・設定への導線を用意する。入力・保存エラーには文字で理由を示す。
- **MVP**：同じ部品で閲覧、検索、重要度・関連度順、単一リポジトリ入力、記事詳細を提供する。保存・設定・ログイン・コメントなどを非表示にし、別のデザイン体系は作らない。

モックの範囲や保存方式の説明はレビュー文書に集約する。製品画面では利用者の判断に必要な説明とエラーだけを表示する。

## Do's and Don'ts

### Do:

- **Do** 白・黒・グレーと青を基調とし、余白と見出しの強弱で読む順序を作る。
- **Do** 狭い画面でも本文16pxと入力16pxを維持し、長いタイトル・URL・コードを折り返す。
- **Do** 0件・読込中・エラー・保存失敗を、具体的な操作へつながる状態として表示する。

### Don't:

- **Don't** 左の一覧を固定高の箱に入れたり、一覧に独立スクロールを設けたりしない。右の閲覧面の高さを左へ適用しない。
- **Don't** モック注意書き、キャッチコピー、開発者向け操作を製品画面に散在させない。
- **Don't** 指定された作品の歌詞・ロゴ・写真・画面構成を流用しない。
- **Don't** CVSS、関連度、対応優先度、分析の確度を同じ尺度として扱わない。
