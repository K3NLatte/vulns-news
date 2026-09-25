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
  control-border: "#767676"
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

脆弱性の根拠と影響を読み比べるための画面。白・黒・グレーを土台に、青を操作と選択へ使う。罫線、余白、文字の大きさで情報の順序を示し、本文を読む面積を確保する。

配色と「カンザキイオリ／amazarashi」のモチーフを文字と余白へ抽象化する方針は、採用済みのデザイン方針。歌詞、ロゴ、写真、既存の画面構成は流用しない。操作性と読みやすさを優先し、モチーフを理由に文字を小さくしたり、装飾文を増やしたりしない。

この文書は開発を続けるフロントエンドの共通仕様。値は [styles.css](frontend/src/styles.css)、[useFeedPanes.ts](frontend/src/composables/useFeedPanes.ts)、各Vueコンポーネントの実装に合わせている。画面を追加するときもこの体系を使い、機能要件と接続状況は [PRODUCT.md](PRODUCT.md) と [連携メモ](docs/frontend-integration.md) で管理する。

- 一覧は自然なページスクロール、右の詳細は画面内へ追従する。
- 本文、見出し、補助情報を役割別の大きさで区別する。
- CVSS、リポジトリとの関連度、対応優先度、分析の確度を別々に示す。

## Colors

冒頭のYAMLに記載した値を使う。通常の本文はink、補助情報はmuted、記事面はsurface、ページ背景はworkspace、区切りはline。

| 役割 | 使用する色 | 適用先 |
| --- | --- | --- |
| 操作 | accent / accent-hover | 主要ボタン、リンク、選択の下線 |
| 選択・関連性 | selected | 選択記事、リポジトリとの関連性を示す面 |
| フォーカス | focus | キーボード操作中の輪郭 |
| 緊急・最優先 | criticalと白文字 | CVSS緊急、対応優先度の最優先 |
| 高・中・低 | high / medium / lowの背景と文字の組 | 各重要度と対応優先度 |
| 未確定 | mediumの背景と文字 | 分析の未確定ラベルと説明 |
| 要確認 | グレー | 対応優先度の要確認 |
| エラー・削除 | error | 入力・保存エラー、削除操作 |

意味色には文字ラベルを併記する。色が同じでも、CVSSと対応優先度を同じ尺度として扱わない。青い選択面は重要度を意味しない。

## Typography

ルートの文字サイズは `100%` とし、ブラウザーの標準文字サイズ設定に従う。本文1remは標準設定で16px。入力枠にはcontrol-borderを使い、淡い区切り線と区別する。

基準は16px。本文と操作にはOSの日本語サンセリフ、ページ見出しと独立記事の見出しには明朝系、識別子・バージョン・コードには等幅書体を使う。フォントの具体的なフォールバック順は冒頭のYAMLに記載する。外部フォント配信は使わない。

| 役割 | 大きさ | 行高・用途 |
| --- | --- | --- |
| 一般ページ見出し | 32px、幅599px以下は28px | 1.45、明朝系 |
| PCのフィード見出し | 26px | 幅1000px以上で適用 |
| 一覧タイトル | 18px | 1.7、太さ650 |
| 詳細列の見出し | 24px | 1.65 |
| 独立記事の見出し | 32px、幅599px以下は26px | 1.6、狭い画面では1.7 |
| ページ内セクション見出し | 22px | 1.6 |
| 小見出し | 18px | 1.6 |
| 一覧要約 | 16px | 1.8、最大2行 |
| 詳細本文・対応・分析 | 16px | 主に1.9 |
| 独立記事の冒頭要約 | 18px、幅599px以下は16px | 1.9 |
| 入力・主要ボタン | 16px | 入力を補助文字サイズへ縮めない |
| 日付・ラベル・識別子 | 14px | 補助情報 |
| 事実欄の値 | 16px、幅599px以下は15px | 1.7 |

詳細要約の行長は最大70ch。日付、CVSS、件数は等幅数字にする。文字サイズはremで指定し、文字拡大時にも操作を維持する。一覧の要約を省略した場合、全文は詳細で読めるようにする。

16/18/14pxはこの画面の読解と操作密度に合わせた採用値。すべてのUIへ一律に適用する最低サイズの規則ではない。

## Layout

内容の最大幅は1600px。PCのフィードは左右余白32px・上下16px、一覧と詳細は1:1.08の2列、列間28px。独立記事は最大960px、設定は最大1000px、解析画面は最大1100px。

左の一覧に高さ制限や内部スクロールを設けない。ヘッダーと検索・フィルターなどの操作域も、文書と一緒に画面外へ流れる。右の詳細だけが上端16pxで追従する。操作行と記事ヘッダー（ID・タイトル・CVSS）を残し、その下の本文だけを縦にスクロールする。

右の高さは、画面高から詳細の画面内上端（最小16px）と下余白16pxを引いて測り、最小280pxとする。上部操作域が画面外へ流れるにつれて伸び、追従位置では画面高から上下16pxを引いた高さになる。この値を左の一覧へ適用しない。別の記事を選んでも一覧の閲覧位置は保ち、右の詳細を先頭へ戻す。記事ページから戻った場合も一覧の位置を復元する。

長いタイトルなどで、操作行と記事ヘッダーを差し引いた本文の高さが160px × 文字拡大率に満たない場合は、右の詳細全体をスクロール可能にする。見出しを省略して本文を隠すことはしない。標準の長さの記事に戻り本文の高さを確保できれば、本文だけのスクロールへ戻す。

| 条件 | 変更 |
| --- | --- |
| 幅1000px以上、かつ高さ500px × 文字拡大率以上 | 一覧と追従する詳細を並べる |
| 幅1199px以下 | 検索を全幅へ、フィルターを次の行へ。列間24px |
| 幅1000px未満、または必要な画面高に満たない場合 | 一覧を1列にし、選択した記事を記事ページで開く |
| 幅999px以下 | 記事ページの最大幅800px |
| 幅699px以下 | ヘッダーと解析画面の入力・操作群を折り返す |
| 幅599px以下 | 左右余白16px。設定・操作群を折り返し、事実欄と関連性の配置を簡略化 |

文字拡大率はルートの文字サイズを16pxで割った値。並列表示に必要な画面高は、標準16pxで500px、文字サイズ200%で1000pxとする。画面高がこの条件を満たしていても、個々の長い記事見出しで本文の余地が不足する場合は、上記の詳細全体スクロールを使う。対応する最小画面幅は320px。冒頭のspacingは実装から整理した余白であり、同名のCSS変数が存在するという意味ではない。

## Elevation & Depth

影は使わない。情報の区切りには通常1pxの罫線、一覧・詳細・設定セクションの起点には2pxの濃い線を使う。選択と関連性は淡い青の面で示す。アカウントダイアログは黒45%のbackdropで背後の操作を停止する。

共有URLの手動コピーパネルは共有ボタンの近くの通常フローに置く。本文や操作を覆う固定配置を使わない。Escはこのパネル内でのみ処理し、閉じたら共有ボタンへフォーカスを戻す。

操作の色・背景・枠色の変化は120ms ease。読込中のスケルトンは1.5秒の明暗変化。prefers-reduced-motionではアニメーションとトランジションを停止する。

## Shapes

ボタンと入力欄は3pxの角丸。記事行、意味ラベル、関連性の面は四角く保つ。主要・補助・アイコンボタンは最小44px、入力とselectは最小46px。フォーカスは2pxの青い輪郭と3pxの外側余白で示し、一覧行では輪郭を内側へ置く。

## Components

- **ヘッダーとナビゲーション**：製品名はGeorgia、newsの下線に青。現在のページをaria-currentで示す。faviconは白地に黒のセリフ付きVと青い下線を描いた独自SVG。
- **検索・select**：入力ラベルと検索のクリア操作を持つ。selectはネイティブの意味とキーボード操作を保ち、装飾の矢印だけ別要素にする。矢印は垂直中央、右13px。幅599px以下は右11px。
- **記事行**：CVSS、識別子、日付、タイトル、2行要約、製品を表示。リポジトリ表示では分析済み／未確定、関連度、対応優先度を分ける。記事選択、保存、ページ表示は別の操作にする。
- **詳細・記事ページ**：対象・影響版・修正版を定義リストで示す。関連性、利用者の対応状況、対策、分析、参照情報を分ける。独立記事ではタイトルをh1、詳細列ではh2とし、独立記事にコメントを表示する。
- **設定とアカウント**：設定は通常ページ。リポジトリを追加・選択・削除し、削除は行内で確認する。アカウントにはnative dialogを使い、Escと閉じた後のフォーカス復帰に対応する。
- **コメントとPoC**：文字列として描画する。コメントは改行と長文の折り返しを保ち、投稿・削除・エラーを示す。PoCは折りたたみ可能な静的テキストとし、実行操作を置かない。
- **解析状態**：処理段階と分析結果を別に示す。未確定の記事には黄色い説明を置き、確定していない分析本文・対応手順を表示しない。途中結果と既存記事は処理中・失敗時も残す。件数は判明している値だけを表示する。
- **解析の依頼**：入力、依頼一覧、追跡レポートを罫線で分ける。受付中は青、完了は緑、失敗は赤、中止はグレーを文字ラベルと併用する。再試行・中止・レポート表示は対象の依頼に配置する。
- **更新と追跡**：最終分析・版・追跡期限・次回確認を並べ、履歴は開閉できる。手動の再分析と追跡の再開を別操作にする。新着の追加候補は通知し、利用者が反映するまで閲覧中の一覧を動かさない。追跡欄は脆弱性の事実・対策の後へ置く。分析結果がない場合は版数・最終分析日時・確度を作らず、未確認と表示する。
- **見出しと選択**：記事ページの題名はh1、本文の節はh2。サイド表示では題名h2、本文の節h3。選択は色だけに依存せず輪郭を併用し、単列一覧にはサイド選択表示を付けない。
- **共有**：端末の共有操作、リンクコピー、手動コピーの順で利用可能な手段を使う。処理中・成功・失敗を文字で伝え、手動コピーを閉じたら起点へフォーカスを戻す。
- **状態表示**：読込中、0件、取得エラー、リポジトリ未指定、保存0件を区別する。再試行、条件解除、設定への導線を用意し、入力・保存エラーには理由を添える。
- **MVP表示**：同じ部品から閲覧、検索、重要度・関連度順、単一リポジトリ入力、詳細を提供する。機能を非表示にしても別のデザイン体系を作らない。

モックの範囲、データ取得、保存方式の説明は開発・レビュー文書へ集約する。製品画面には利用者の判断と操作に必要な説明を置く。

## Do's and Don'ts

### Do:

- **Do** 白・黒・グレーと青を基調に、文字と余白で読む順序を示す。
- **Do** 長いタイトル・URL・コード、キーボード操作、文字拡大、狭い画面を確認する。
- **Do** 0件・読み込み・エラー・保存失敗を区別し、利用者が次の操作を選べるようにする。

### Don't:

- **Don't** 左の一覧を固定高の箱や独立スクロール領域にする。
- **Don't** キャッチコピー、モック注意書き、開発者向け操作を製品画面に散在させる。
- **Don't** 指定作品の歌詞・ロゴ・写真・画面構成を流用する。
- **Don't** CVSS、関連度、対応優先度、分析の確度を同じ尺度として扱う。
