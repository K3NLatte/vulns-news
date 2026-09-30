# 実スキャン → 解析 → 保存 → Feed → 画面

## 構成

- `cmd/news-server`: 統合用の起動コマンド。既存のスキャン専用 `server/*.go` / `src/scanjob` は変更せず保持。
- `server/live`: GitHub取得・Profile・OSV照合を既存ライブラリで実行し、`scananalyze.Run` → `pipeline.Process` → Screening／条件付きDeep Analysisに接続。
- `server/live/feed.go`: 検証済みの解析とGo側の事実をフロントの契約へ変換。未知の重要度・悪用状況・確度は `unknown`。関連度スコアや直接／間接依存を推測しない。
- `server/model` と `frontend`: `origin/codex/frontend-api-integration` の `2c985f6` から取り込んだ既存の統合作業を保持。main起点への組み直しで `server/api`・`server/cmd/api`・SQLite reportstoreも保持し、依存を統合した。`server/mockdata` はフロント単体テストとmain由来のモックAPIが使用し、実解析APIは使用しない。
- フロントは通常・本番とも実APIを使用。`VITE_FEED_SOURCE=local` は開発時だけのデザインプレビュー。

mainのNVD公開API (`NewClient()` / `Client.Fetch` / `CVE`) と解析APIは分離して共存する。解析側は `NewAnalysisClient(Config)` / `AnalysisClient` / `CVERecord` を使用する。JSONの保存形式・解析ハッシュは変更しない。

## 起動（WSL内、リポジトリ直下）

```sh
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend build
go run ./cmd/news-server -model=""
```

http://127.0.0.1:8080/ を開く。モデル未指定の場合は保存済みデータの閲覧・登録IDの取得だけが可能。未登録リポジトリの新規スキャンは503。環境変数 `OLLAMA_MODEL` がある場合も無効にしたいときは `-model=""` を明示する。

新規実スキャンを有効にする場合（Ollamaの起動・モデル取得は別途必要）：

```sh
go run ./cmd/news-server -model qwen3.5:9b -base-url http://127.0.0.1:11434
```

画面の「リポジトリに関連」で公開GitHub URLを入力して「読み込む」。既存登録は保存結果を再利用し、POSTの重複で再スキャンしない。バックグラウンドジョブはブラウザーの切断でキャンセルしない。

- GitHubへの取得とOSVへのパッケージ名・ecosystem・バージョン送信が発生する。統合経路のNVD補完は無効。
- 照合した依存・ソースパス・アドバイザリの材料を設定したOllamaへ送信する。リモート接続先の料金・機密性は利用者が確認する。
- LLMの実行期限・リクエスト期限は追加していない。手動終了のcontextキャンセルは伝播する。取得・OSV照合のみ15分の既存相当の上限を使用。
- 既存フロントのポーリングは約60回で一旦止まり、再試行案内を出す。サーバーの解析は継続し、取得済みの部分結果も表示する。画面の再試行は読み取りであって新規ジョブ開始ではない。

Viteを使う開発時は、別ターミナルで `pnpm --dir frontend dev`。`/api` は8080へプロキシする。Go、Node、pnpmは同じWSL環境で動かす。

## 既存解析のオフライン取り込み

対応するrepo-scan状態JSONとrepo-analyze結果JSONを指定する。同じ名前でも異なるスキャンのファイルを混ぜない。

```sh
go run ./cmd/news-server -data .local/news \
  -import-scan .local/imported-nextjs/analysis-scan-state.json \
  -import-analysis .local/imported-nextjs/analysis-results.json \
  -import-only
```

ネットワーク・LLM呼び出しはない。`reposcan.Load` と既存のresume検証を再利用し、スナップショット・入力／出力ハッシュ・引用根拠を検証してからFeedを再構築する。JSON内のserialized feedを権威ある事実として扱わない。検証失敗時は取り込みを拒否する。未完了の解析は成功扱いにせず、利用可能な部分結果のみ残す。

### この環境で見つかった実データ

`analysis-results.zip` の次の2ファイルを `.local/imported-nextjs/` に展開した（元ZIPは変更していない）：

- `analysis-scan-state.json`
- `analysis-results.json`

ZIP外の同名JSONは過去の失敗途中の結果なので使用していない。

取り込み済みデータ：

- URL: `https://github.com/vercel/next.js`
- commit: `0423222b7eb3a1373b5bff4c939fd69858928993`
- model: `qwen3.5:9b`
- 候補591件、深掘り355件、スクリーニングのみ227件、除外9件
- Feed582件、解析エラー0件
- 解析自体は完了、スキャン範囲は `incomplete`。画面に警告と対象SHAを表示する。実行時の到達可能性・攻撃成立を証明したものではない。

`.local/news` に保存済みなので、この作業環境では閲覧専用の起動コマンドだけで確認できる。実データ・生成物は `.gitignore` の対象で、リポジトリには含めない。

## 保存と再起動

`.local/news/<job_id>/scan.json` と `record.json` に保存する。recordはモデルステージごとに一時ファイル→sync→renameで置換し、成功済み解析とジョブ進捗を残す。refreshは新しいjobディレクトリを使い、以前のスキャンを上書きしない。

起動時に保存済み解析を再検証してFeedを復元する。中断されたジョブは失敗として復元し、自動的にLLMを再実行しない。旧ジョブはAPIで取得でき、リポジトリ表示は最新登録を参照する。

## API

| API | 動作 |
| --- | --- |
| `GET /api/analyses` | 保存済み解析の一覧（repository/refごとの最新結果）、サーバーのreadOnly状態。選択・閲覧に登録POSTは不要 |
| `POST /api/repositories` | `{ "url": "https://github.com/owner/repo", "ref": "optional" }`。202でrepository_idとjob_id。既存登録は再利用 |
| `GET /api/jobs/{job_id}` | queued / profiling / analyzing / completed / failed、処理数、分析済み／未確定数、部分結果の有無 |
| `GET /api/repositories/{repository_id}` | URL、ref、job_id、解析があればcommit SHA・scan_status |
| `POST /api/repositories/{repository_id}/refresh` | 明示的に新規スキャン。実行中の同一リポジトリは重複させない |
| `GET /api/repositories/{repository_id}/feed` | リポジトリ別結果、scanStatus、repositoryCommit |
| `GET /api/repositories/{repository_id}/feed/{id}` | CVEまたはGHSA等の記事詳細 |
| `GET /api/cves` / `GET /api/cves/{id}` | 保存済みリポジトリ群の結果をIDで重複排除。全脆弱性のクローラー一覧ではない |

一覧は `limit`（1–1000）、`offset`、`search`、`severity` を受け付ける。`total` は絞り込み前、`matchedTotal` は返したページの件数、`nextOffset` があれば後続あり。フロントは全ページを取得後に検索・並べ替えを適用する（画面の安全上限は10,000件）。日時はミリ秒付きUTCに統一。0件は `items: []`、未知IDは404、不正入力は400、容量超過／閲覧専用での新規スキャンは503。

## CVSSの表示

OSVスキャン由来の解析では、旧 `scananalyze.Prepare` はCVSSを正規化していなかったため、保存Feedの582件すべてでスコアが未設定だった。元のscan stateにはCVSSベクトルが残っている。GUIのAPI変換で、検証済みスキャンの現在の非撤回OSVレコードからベクトルを計算する（`server/live/cvss.go`、`github.com/pandatix/go-cvss v0.6.4`）。既存解析の入力・出力ハッシュや本文は変更しない。

- CVSS 3.0 / 3.1 / 4.0の基本値を表示する。v4のThreat／Environmental値と混同しない。
- 複数ベクトルは4.0 > 3.1 > 3.0を優先し、同一版では最大値を採用する。出典・版は記事上部、元ベクトルと選択方針は根拠欄で確認できる。
- OSVのseverity.scoreは数値ではなくベクトル。本文・LLM生成文・CVE識別番号・HIGH等のラベルから数値を推測しない。構造不正・未対応・欠落・撤回済みの値は採用しない。
- CVSS 0.0は未評価と異なり「なし 0.0」。これは出典の基本値であり、リポジトリの安全性を保証しない。
- 保存済みNext.jsでは548件が数値表示、34件は出典にseverityベクトルがなく未評価。`CVE-2015-8858` は3.0基本値7.5（高）、`CVE-2026-81176` は3.1基本値5.3（中）。`RUSTSEC-2026-0258` は未評価。
- このスキャンのレコードはOSVのみでNVDレコードはない。表示値をNVDの評価値と呼ばない。「分析の確度」「悪用状況」「リポジトリの関連度」は別項目で、CVSSから補完しない。

ビルド済みのフロントと新しいサーバーで表示するため、既存サーバーをCtrl+Cで終了して `go run ./cmd/news-server -model=""` で再起動する。再取り込み・LLM再実行は不要。

## 非LLM検証

```sh
go test ./...
go test -race ./server/live ./server ./src/scanjob
pnpm --dir frontend typecheck
pnpm --dir frontend test
pnpm --dir frontend build
```

Goの結合テストは固定のスキャン状態とテスト用Analyzerでジョブ→既存パイプライン→保存→再起動→HTTP一覧／詳細を確認する。壊れた出力の拒否、部分結果、入力検証、重複登録、ページ分割も対象。

手元の実解析をGo APIとフロント契約の両側で検証する場合、以下の環境変数には絶対パスを指定する：

```sh
NEWS_TEST_SCAN=/path/to/vulns-news/.local/imported-nextjs/analysis-scan-state.json \
NEWS_TEST_ANALYSIS=/path/to/vulns-news/.local/imported-nextjs/analysis-results.json \
NEWS_TEST_FEED=/path/to/vulns-news/.local/validated-feed.json \
go test ./server/live -run TestSavedAnalysisIntegration -v

NEWS_TEST_FEED=/path/to/vulns-news/.local/validated-feed.json \
pnpm --dir frontend test
```

Next.js実データのブラウザーE2E（上記の取り込みとフロントビルド後）：

```sh
pnpm --dir frontend exec playwright install chromium
pnpm --dir frontend test:e2e:live
```

Playwrightが閲覧専用の実サーバーを8180で起動・終了する。APIをモックせず、582件の一覧、検索、記事詳細、再読み込み、保存済み解析の選択（POSTなし）、355/227件の分類、カバレッジ警告を確認する。このE2Eは上記Next.jsスナップショット専用。別の実データを使う場合はGo／Vitestのオプトイン契約テストを使う。スクリーンショットは `frontend/test-results/live-nextjs.png`。

## スライド用の実GUI撮影

この環境で確認したZIP内のファイル名は `analysis-results.json`（`results.json` ではない）。対応する `analysis-scan-state.json` とセットで取り込み済み。元ZIPおよび解析本文は変更しない。

```sh
pnpm --dir frontend build
NEWS_CAPTURE_SLIDES=1 pnpm --dir frontend test:e2e:live
```

有限のPlaywright処理が閲覧専用サーバーを起動・終了し、APIをモックせず実GUIを撮影する。出力はGit対象外の `.local/slides/`。通常のテスト結果フォルダーと別なので、通常のE2E再実行で削除されない。

- `00-saved-analyses.png`: 初期画面の保存済み解析一覧と「結果を開く」ボタン。URL入力不要。
- `01-repository-overview.png`: 一覧、591候補の処理完了、Feed582件、分析済み355／未確定227、対象SHAとカバレッジ警告。
- `02-article-detail.png`: `CVE-2015-8858` の記事上部。保存済み日本語解析、`uglify-js@2.4.24` のOSV照合結果。
- `03-analysis-evidence.png`: 対応の確認ポイントと分析・根拠の表示。
- `04-article-full.png`: 根拠を展開した記事全文（縦長、拡大・切り出し用）。
- `capture.json`: 撮影対象・件数・記事APIレスポンス。

00〜03の4枚は1600×900（16:9）。解析例はテスト用lockfile由来の依存であり、Next.js本番環境での攻撃成立を証明するものではない。本文の更新案は保存済みLLM出力で、GUIの修正バージョン欄は未確認のまま。『解析完了』と『スキャン範囲が完全／安全』を区別して説明する。

手元で操作する場合は、現在のサーバーをCtrl+Cで終了し、WSLの `/path/to/vulns-news` で `go run ./cmd/news-server -model=""` を実行する。http://127.0.0.1:8080/ を開き、「保存済み解析結果」の「vercel/next.js — 結果を開く」を押すだけで閲覧できる。URL入力・登録POST・新規スキャン・LLM呼び出しは不要。古い画面が残る場合はCtrl+F5。終了はCtrl+C。

一覧は実APIから取得し、0件時は取り込み案内、通信失敗時は再取得操作を表示する。保存済みの未完了解析も部分結果として開ける。新しい結果の追加は既存import CLIを使用し、サーバー再起動後に一覧から選ぶ。JSON単独アップロードは実装しない（対応するscan stateが必要）。URL登録フォームはスキャン有効モードだけの折りたたみ導線として残す。

## 制限

- ローカル単一プロセス向けのJSON保存。SQLite reportstoreとの統合、複数プロセスの排他、認証／認可、定期監視、削除・保持期限は未実装。インターネットへ公開しないこと。
- 完了ジョブ・履歴は自動削除しない。登録済みデータは起動時にメモリーへ読み込み、checkpoint保存もJSON全体を更新するため、大規模運用には向かない。
- サーバー終了後の自動再開はしない。再スキャンはrefresh API、保存済み解析からの再開は既存 `repo-analyze -resume` を使う。フロントにrefresh操作はまだない。
- CVSS未評価や修正バージョン未確認を低リスクと解釈しない。直接／間接依存・ランタイム到達性・悪用状況を推測で生成しない。
- 今回は長時間の実LLM処理および新しい外部GitHub/OSVのライブスキャンを再実行していない。実データの再利用と非LLMテストで結合を検証した。
- 既存のデザイン／モックAPI用Playwrightスイートは保持。モックAPI専用スイートは別途元のモックサーバーが必要。
