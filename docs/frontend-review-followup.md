# 外部レビューの対応表

対象は `codex/frontend-review-completion`、比較先は #16 取り込み後の `codex/frontend-review-suite`（`943babc`）。H-1〜H-3の初期修正は #16 に含まれ、今回のPRにはその後の追加修正が出ます。H/M/L は後のレビュー、A〜I は先行レビューの指摘IDです。重複した指摘は同じ修正にまとめています。

前回の差分はHighと周辺だけでした。この差分では、未評価表示、保存と復旧、非同期処理、画面遷移、入力、キーボード操作まで対象を広げています。「実装」は修正コードがあるという意味です。実バックエンド接続や実機・支援技術での確認とは区別します。

## High / Medium

| 指摘 | 対応 | 実装・回帰の入口 |
| --- | --- | --- |
| H-1 / A2 | 現在のリポジトリに評価が無い記事を未確定にする。評価・優先度・依存情報・対応状況編集を出さない | [repositoryAssessment.ts](../frontend/src/services/repositoryAssessment.ts)、[review-regressions.spec.ts](../frontend/e2e/review-regressions.spec.ts) |
| H-2 / B2 | 解析履歴・追加記事・追跡状態を利用者別に切替。旧所有者の監視・タイマー・受付中コマンドを中止 | [解析ライブラリ](../frontend/src/composables/useReportLibrary.ts)、[単体テスト](../frontend/src/composables/useReportLibrary.test.ts) |
| H-3 | `analysis` / `scenario` / `view` のURLスイッチをDEV限定にする | [previewOptions.ts](../frontend/src/utils/previewOptions.ts)、[本番E2E](../frontend/e2e/preview.production.spec.ts) |
| M-1・M-2 / A7・C3 | 記事を開くだけではジョブを作らない。明示操作の未開始・受付拒否・実行・失敗・中止・完了を分ける | [App.vue](../frontend/src/App.vue)、[操作E2E](../frontend/e2e/report-actions.spec.ts) |
| M-3 / B8・B12 | 受付結果を返し、エラーは依頼・記事・ジョブごとに表示。重複にも受付済みと通知する | [解析ライブラリ](../frontend/src/composables/useReportLibrary.ts)、同単体テスト |
| M-4・M-5 / A3・A4 | CVSS未評価を `unknown`、0点を `none` に分ける。製品・バージョン・日時・分析文の未提供をnullで表す。スコアと帯、不明な分析と確定評価の矛盾を拒否 | [feed.tsの型](../frontend/src/types/feed.ts)、[feedContract.test.ts](../frontend/src/services/feedContract.test.ts) |
| M-6・M-7 / A1 | 不明な評価を未確定にする。分類をソートより前に行い、未確定からスコアを除いて関連度順の末尾へ | [mocks/feed.ts](../frontend/src/mocks/feed.ts)、[feed.test.ts](../frontend/src/services/feed.test.ts) |
| M-8 / A3・B9・B11 | ローカルの受付完了を分析完了にしない。未評価の版は0のまま。初回分析はinitial、再利用は再分析扱いにしない。閉じている間に完了した処理は保存済み履歴の復元後に一度だけ反映 | [reports.ts](../frontend/src/services/reports.ts)、[解析ライブラリの回帰](../frontend/src/composables/useReportLibrary.test.ts)、[ReportTracking.vue](../frontend/src/components/ReportTracking.vue) |
| M-9 / A5 | 年付き日付と日本時間の日時を共通関数へ集約。依頼日時と公開日時を分ける | [presentation.ts](../frontend/src/utils/presentation.ts)、同単体テスト |
| M-10・M-11 / B1 | 再ログイン時に最新の保存内容を読む。閲覧中のリポジトリをタブ内状態に分離。競合時は最新読込、失敗した更新は巻戻し、別タブ更新を通知 | [workspace.ts](../frontend/src/services/workspace.ts)、[workspace.test.ts](../frontend/src/services/workspace.test.ts)、[useWorkspace.ts](../frontend/src/composables/useWorkspace.ts) |
| M-12・M-13 | 表示名の正規化を冪等にする。プロフィール・ログイン状態・ゲスト移行の部分失敗を扱い、失敗を成功表示にしない | [workspace.test.ts](../frontend/src/services/workspace.test.ts) |
| M-14 / B5 | 不正な保存行を隔離し、有効な行を復元。元データの出力と明示的な復旧を用意。未知バージョンは上書きしない | [workspace.ts](../frontend/src/services/workspace.ts)、[AccountDialog.vue](../frontend/src/components/AccountDialog.vue) |
| M-15 / B4 | 利用者オブジェクトの複製でコメントエラーを消さない。保存失敗時は投稿成功にせず下書きを残す | [App.vue](../frontend/src/App.vue)、[CommentThread.vue](../frontend/src/components/CommentThread.vue)、レビュー回帰E2E |
| M-16・M-17 / C6・C7・F1 | 正規化後のURL長を検証。C1・Bidi・不可視制御文字を拒否。名前とコメントの上限はコードポイント単位。CVE/GHSAの全角正規化と形式別エラー | [publicUrl.ts](../frontend/src/utils/publicUrl.ts)、[inputText.ts](../frontend/src/utils/inputText.ts)、[reports.test.ts](../frontend/src/services/reports.test.ts) |
| M-18 | 参照リンクにホスト名を併記。未検証の提供元ラベルを使わず、vendor分類にはアダプターの許可ホストを要求 | [FeedDetail.vue](../frontend/src/components/FeedDetail.vue)、[feedContract.ts](../frontend/src/services/feedContract.ts) |
| M-19 / A6・B10 | 再利用は識別子または個別の脆弱性情報URLだけに限定し、共通のCWE参照は一致条件から除外。完了済みの再利用を重複排除。終了した依頼を削除できる。初期値のままの追跡情報を保存せず、変更分だけ保存 | [解析ライブラリの回帰](../frontend/src/composables/useReportLibrary.test.ts)、[AnalysisDesk.vue](../frontend/src/components/AnalysisDesk.vue) |
| M-20 | 時計が戻っても履歴を捨てない。依頼日時を保持し、再試行開始時刻を分離。復元時の実行開始は現在時刻へ補正 | [reportSession.ts](../frontend/src/services/reportSession.ts)、解析ライブラリの時計変更テスト |
| M-21 | 保存していない追加記事のコメント・対応状況にも復元用参照を保持。復元不能な旧孤立データを隔離 | [workspace.test.ts](../frontend/src/services/workspace.test.ts) |
| M-22 / C1 | 再取得中は成功した結果を残す。同一クエリの不要な取得を避け、取得無効時も選択を保持 | [useFeed.ts](../frontend/src/composables/useFeed.ts)、同単体テスト |
| M-23 / C10 | エラーを公開用分類から表示し、生の例外文を表示しない。取得とコマンドにタイムアウト・中止処理 | [requestError.ts](../frontend/src/utils/requestError.ts)、useFeed・解析ライブラリの単体テスト |
| M-24 | workspaceと解析受付に非同期アダプター、Promiseの結果、pending・失敗・競合を用意。利用者切替後の遅い応答を破棄。入力検証はアダプター呼出し前 | [useWorkspace.ts](../frontend/src/composables/useWorkspace.ts)、[ReportCommandAdapter](../frontend/src/types/reports.ts)、[非同期受付テスト](../frontend/src/composables/useReportLibrary.test.ts) |
| M-25 / G1 | ローカル記事の結合と検索をアダプター内へ移す。画面は検証済み応答を使う。未合意の追加解析はビルド設定で外せる | [localFeedLoader.ts](../frontend/src/services/localFeedLoader.ts)、App.vue |
| M-26 / B5 | 不正な行だけを除外し件数を返す。総量制限を保持したままカーソル・総件数・追加読込を表現 | [feedContract.test.ts](../frontend/src/services/feedContract.test.ts)、[useFeed.test.ts](../frontend/src/composables/useFeed.test.ts) |
| M-27〜M-29 / B6・B7・C4 | 履歴エントリーごとに一覧・記事・詳細の読書位置を記録。選択を取得から分離。戻る操作で履歴を余分に積まない | [useReadingPosition.ts](../frontend/src/composables/useReadingPosition.ts)、[useNavigation.ts](../frontend/src/composables/useNavigation.ts)、レビュー回帰E2E |
| M-30 / D1 | 処理中はフォーカスを保ち、消える操作は見出し・入力・次の項目へ移す。二重送信はガードする | 各コンポーネント、App.vue、操作・レビュー回帰E2E |
| M-31 / C8 | 手動共有パネルを操作の直後に置く。Escapeはパネル内だけで処理し、背面やIMEへ干渉しない | [ShareArticle.vue](../frontend/src/components/ShareArticle.vue)、レビュー回帰E2E |
| M-32・M-33 / D2・D3 | ライブリージョンを常設。保存ボタンの名前を固定し、表示ラベルを含める。コメント削除の名前を区別 | App.vue、FeedList・FeedDetail・CommentThread・AnalysisDesk |
| M-34〜M-36 / D9 | 選択を罫線でも表示。強制カラー対応。入力枠を濃くし、ルート文字サイズを100%へ | [styles.css](../frontend/src/styles.css)、文字サイズ・強制カラーE2E |
| M-37 / C2 | 短い画面の詳細スクロール、隠れるフォーカス、ヘッダーや長文の折返し、一覧から詳細へ移る操作を修正。コメント削除に確認、IME確定後に検索 | [useFeedPanes.ts](../frontend/src/composables/useFeedPanes.ts)、コンポーネント・表示回帰E2E。実IME・支援技術は下記の未確認範囲 |

キーボードの回帰は [review-accessibility.spec.ts](../frontend/e2e/review-accessibility.spec.ts)、履歴・通知・例外復旧は [review-navigation.spec.ts](../frontend/e2e/review-navigation.spec.ts)、復旧・ログアウト失敗は [review-storage.spec.ts](../frontend/e2e/review-storage.spec.ts) を参照してください。

## Lowの照合

| 指摘 | 対応・判断 |
| --- | --- |
| L-1〜L-4 | 履歴の戻る、記事間遷移のフォーカス、不明ルートの404、設定の遷移元復帰を扱う。`useNavigation` / `useReadingPosition` / App.vue |
| L-5 | コメント・解析・リポジトリ入力の下書きを画面外で保持し、利用者間では分離。App.vueと各フォーム |
| L-6 | 「ページで開く」をリンクにする。FeedDetail.vue |
| L-7〜L-10 / C5 | 入力時・画面変更時のエラー解消、原因別文言、`novalidate`、入力の大文字表記の維持。各フォームとApp.vue |
| L-11 / C9 | 非セキュアオリジンでは安全な乱数からUUIDを生成する。`localId.ts`。実機LAN環境は未確認 |
| L-12 | GitHub予約パス・名前長、URL正規化後の長さと特殊用途ホスト、認証情報と思われるクエリ、厳密な保存日時を検証。CVE番号には根拠のない桁数上限を設けず、入力全体2,048文字で制限 |
| L-13 | 検索のNFKC・ダッシュ類・大小文字を正規化し、ID・タイトル・製品・要約・コンポーネント・依存名・参照名を対象にする。長音は日本語の意味を変えるため一律置換しない |
| L-14 | 同じCVSS帯ではスコア、公開日時、IDの順に並べる。未評価は末尾 |
| L-15 | 未確定を確定優先度と区別。記事共通の分析文から「直接依存が一致」等の特定リポジトリの断定を除く |
| L-16 | URLのホストとパスを識別表示に使う。URL由来のローカル記事IDは短い固定IDのまま |
| L-17 | 検証用の分析状態はDEV限定。再試行で終わらない固定状態を解消。実リポジトリのジョブ状態はURL単位 |
| L-18〜L-20 | 依頼は操作時刻、再試行は別の開始時刻。成功した保存でエラー解消。定期追加する架空記事の日付を固定し、画面を開くたびに新しい公開日にしない |
| L-21・L-22 | 保存容量制限と失敗時巻戻し。復元時は許可したフィールドだけを採用。workspace.test.ts |
| L-23 | リポジトリ削除時に対応状況も削除されることを確認文へ含める |
| L-24〜L-27 / D4・D6 | 記事の取得中も戻る導線、解析結果から開く際のリポジトリ文脈、見出し階層、一覧ボタンの短い名前を整える |
| L-28・L-29 / D5 | 開閉操作44px、アカウントのダイアログ起動を明示 |
| L-30〜L-33 / D7・D8 | 一列化時のフォーカス移動、印刷、通知領域、詳細ペインだけの高さ更新。一覧を独立した狭いスクロール枠にはしない |
| L-34・L-35 | 非表示タブ・追加解析無効時に時計更新を停止。取得・workspaceはshallowRef。保存アダプターの防御的複製は残し、容量上限で制約する |
| L-36・L-37 | 繰返し要素のkeyを重複させない。空IDでフォーカス先を検索しない |
| L-38 / B3 | ゲストのタブ内保持・既存プロフィールへの切替で内容を自動統合しないことを通知。移行方針のチーム合意は別途必要 |
| L-39 | 条件未指定の0件では「条件を解除」を出さない |
| L-40〜L-42 / E3 | CVSSと対応優先度、未評価と未確定の表記を整理。追跡欄を主要事実の下へ移す。等幅フォントに日本語フォールバック |

## 先行レビューと保守性の補足

- A1〜A7、B1〜B12、C1〜C10、D1〜D9、F1は上の表へ対応付けています。B9は復元順序の回帰テスト、B10は重複と履歴削除、B11は再利用中の表示、B12は操作の場所での通知が確認箇所です。
- E1はメディアクエリの上書き順を整理。E2のモバイル上部を折りたたむ案は任意のデザイン案です。合意済みの画面構成は維持し、折返し・文字拡大での欠けを修正しました。E3は追跡欄の移動で対応。
- G1はアダプターと追加解析フラグ、G2はESLint・Vue・a11yルールとファイル指定の整形コマンド、G3は既報不具合の単体・操作E2E、G5は確認範囲の書き直しで対応。テスト数やaxe違反0だけで全画面の利用可能性を保証する記述にはしません。
- G4 / 後のレビュー§7はNode・pnpmの指定、CIのlint・audit、本番成果物へのE2E、ポーリングのオプトインを確認箇所とします。OSはUbuntu 24.04へ固定し、checkout・setup-node・pnpm設定・artifact保存は確認した公式安定版のコミットSHAへ更新しました。実行結果はpush後のCIで確認します。
- コンポーネント専用テストランナーやカバレッジ率100%を導入目的にはせず、Vueの操作連鎖は実ブラウザーで検証します。新しい回帰は異常応答、競合、容量上限、時計変更、複数回の履歴移動、操作後フォーカスを対象にしています。

## 仕様・外部環境として残る範囲

以下を「修正済みの不具合」に数えていません。

- **APIとサーバー**: Goの実応答から画面モデルへのマッピング、認証・認可、CSRF、取得先のSSRF制御、ジョブ所有者・永続化、実ページング。フロントの非同期・エラー・未提供値の境界は用意していますが、接続試験は未実施です。本文の言語フィールドとHTMLのlang属性への対応も、API契約の合意と接続時に残っています。
- **M-37の画面上のモック注記**: ユーザーから削除の明示指示があるため、注意書きの再追加は採用していません。データと処理の制約はREADME・PRに記載します。
- **仕様の合意**: CVSSのバージョン・ベクター・出典、レポート追跡期限、共有コメントの文脈、ゲスト移行、未合意解析機能の採否。ローカルの生成記事は他端末で解決できないため、共有URLを作らずその場で伝えます。
- **I1 / 配信**: CSPなど本番ヘッダーは配信基盤で設定・検証が必要です。静的アプリの変更だけで配信設定済みとはしません。
- **I2**: 追加解析のナビを保存・設定の後へ移し、機能フラグで除外可能にしました。
- **I3・I4 / 実機確認**: スクリーンリーダーでの通知量、フォーカスの読み上げ、実IME、実ズーム、実際のWindows強制カラー、iOS/Safariは未確認。合成イベント・ブラウザーのエミュレーションと区別します。
- **任意の拡張**: KEV/EPSS、VEX、SBOM、通知配信等の提案は今回の不具合修正の対象ではありません。

## 検証の読み方

2026-09-25のローカル最終実行: 単体323件成功、Chromium・FirefoxのE2Eは93件成功・1件対象外（Chromium CDP専用の標準フォント設定検査をFirefoxでskip）。Lint・型チェック・本番ビルド成功、依存パッケージ監査で既知の脆弱性なし。新しい回帰には読書位置の複数回復帰、通知挿入の位置、破損保存の復旧、ログアウト失敗、利用者別の下書きを含みます。

本番成果物のE2EもChromium・Firefoxで2件成功。追加解析を無効にした別ビルドでも、両ブラウザーでフィード・保存・設定が動き、解析ナビ・直接遷移・タイマーを無効にできることを確認しました。

最新の統合実行結果はPR本文とCIを参照してください。この文書内で過去の255件・58件を今回の結果として再利用しません。単体は入力・契約・保存・状態遷移、E2Eは画面操作と描画、本番E2EはDEV用URLスイッチの無効化を確認します。

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm test:e2e
pnpm test:e2e:production
```

ブラウザーエンジン限定のAPIを使う検査のskipは成功数に含めません。修正のため変更したテストは、不正な旧挙動を期待していないかも確認してください。
