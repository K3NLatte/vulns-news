# vulns-news

## 実スキャン・解析・保存・Feed・画面の結合

`cmd/news-server` が公開GitHubの取得 → OSV照合 → 既存Screening／Deep Analysis → JSON保存 → Feed API → Vue画面を接続します。既存の `server` / `src/scanjob` のスキャン専用実装は保持しています。

```sh
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend build
go run ./cmd/news-server -model=""
```

http://127.0.0.1:8080/ を開きます。上記は保存結果の閲覧専用で、初回は空です。既存解析の取り込み、新規スキャンを有効にする方法、非LLM検証は [全体結合ガイド](docs/e2e-integration.md) を参照してください。

## main由来のAPI・保存機能とローカルプレビュー

mainのモックAPI・SQLite reportstoreは、実解析用の `cmd/news-server` と独立して保持しています。

- モックAPI: `go run ./server/cmd/api`（[APIガイド](server/README.md)）
- SQLiteのレポート保存CRUD: [reportstoreガイド](server/repository/reportstore/README.md)。HTTPルートへの接続は未実装です。
- 架空データでの画面確認: `VITE_FEED_SOURCE=local pnpm --dir frontend dev`（開発時のみ）。通常・本番は実APIを使用します。
- [フロント起動・画面の確認方法](frontend/README.md)、[既存の連携メモ](docs/frontend-integration.md)、[製品の範囲](PRODUCT.md)

各サーバーは既定で8080番を使用するため、同時に起動しないでください。JSON保存の実解析とSQLite保存は別経路で、保存済みデータを自動移行しません。

NVDの公開API `nvd.NewClient()` / `Client.Fetch` / `CVE` はmainのままです。解析用の設定付きクライアントは `nvd.NewAnalysisClient(nvd.Config)` / `AnalysisClient`、正規化前の詳細レコード型は `CVERecord` として分離しています。

## Google Colabで試す（ソース同梱）

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/K3NLatte/vulns-news/blob/feature/local-llm/docs/colab-standalone.ipynb)

共有用ファイル：[`docs/colab-standalone.ipynb`](docs/colab-standalone.ipynb)。新しいColabランタイムでセル1から順に実行できます。Goソースを同梱しているため、ローカル環境・ソースZIP・以前のPython変数は不要です。

1. 上のリンクから開き、必要なら自分のGoogle Driveにコピーします。
2. ランタイムをGPUに設定します。CPUを使う場合はセル3で `REQUIRE_GPU=False` を明示します。
3. セル2の `REPOSITORY_URL` を対象の公開GitHubリポジトリに設定します。初期値はNext.jsです。初回は `SOURCE_MODE="github"`、保存済みstateと分析結果から再開する場合は `"resume"` を選びます。
4. セル3でOllamaとモデルを準備し、セル4で分析します。初期値 `LIMIT=0` は全候補です。動作確認だけなら新規分析時に `LIMIT=5` などを指定できますが、全候補のE2E確認にはなりません。途中結果に対してlimitやモデルを変更する場合は別の分析出力が必要です。
5. セル5で成功・エラー・未処理・Deep Analysisへの到達を確認し、セル6でstateと結果を保存します。候補エラーがあっても後続を処理しますが、失敗を安全／成功に置き換えません。

**注意:** モデル等のダウンロードと外部API通信が必要です。初期設定はローカルOllama・NVD補完なしで、外部LLMのAPIキーは不要です。GPUの利用可否・料金・実行時間はColabの契約と制限に従います。本分析の待ち時間上限は初期値で無効です。一部候補が約34分かかった実行例があり、この性能問題は未解決です。短時間での全件完了を保証しません。手動停止後、成功済みの段階を再利用して再開できます。

同梱コードは配布時のスナップショットです。ノートブックには実スキャン結果や秘密情報を保存していませんが、実行後のstate・結果には依存情報や出典本文が含まれるため、共有前に内容を確認してください。リモートOllamaを指定すると分析材料がその接続先へ送られます。ライブColab E2Eの成功は未確認です。

## 開発環境

[Nix](https://nixos.org/) の開発シェルに Go、Node.js、pnpm、SQLite のコマンドを用意します。Vueアプリは `frontend` にあります。

```sh
nix develop path:.
```

開発シェル内で各コマンドを確認できます。

```sh
go version
node --version
pnpm --version
sqlite3 --version
```

フロントエンドの開発時は、開発シェル内で次を実行します。

```sh
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend dev
```

Nix の設定で `nix-command` と `flakes` が無効の場合は、`nix --extra-experimental-features 'nix-command flakes' develop path:.` を使用してください。

## OSVによる初回スキャン・保存構成の監視（GPU不要）

公開GitHubリポジトリから多言語の依存を抽出し、エコシステム＋名前＋確定バージョンでOSVに一括照会します。CVE IDがあればNVDで補完し、出典の原文・未照会理由・commit SHAをJSONに残します。

```sh
go run ./cmd/repo-scan \
  -repository https://github.com/juice-shop/juice-shop \
  -state juice-shop-state.json > juice-shop-scan.json

go run ./cmd/repo-scan \
  -monitor -state juice-shop-state.json > juice-shop-monitor.json
```

0件は「該当情報なし」であり、安全を意味しません。監視は保存したSHAの構成を1回再照会する方式です。自動スケジュール、全OSV/NVDの更新フィード取り込みは含みません。既存のNVD新着経路とは分離しています。

**Colab用セル・結果matrixの表示・未対応範囲・終了コード**は [`docs/repository-scan.md`](docs/repository-scan.md) を参照してください。

## 保存したOSV結果をDeep Analysisまで検証

`repo-analyze` は保存stateから一致候補を作り、既存のScreening → 関連ありの場合のDeep Analysis → Feedに接続します。GitHub／OSVの再取得は不要です。各LLMステージの完了を保存し、中断後は `-resume` で続行できます。

```sh
go run ./cmd/repo-analyze -state juice-shop-state.json \
  -output analysis-results.json -model qwen3:8b -require-deep
```

デフォルトは全候補。`-require-deep` は分析済みFeedが0件なら終了1にし、E2E到達を区別します。関連性を強制する機能ではありません。GPUが有効なのはOllamaの推論です。

**ソース同梱の共有用ノートブック：** [`docs/colab-standalone.ipynb`](docs/colab-standalone.ipynb)

開発用（ソースZIPを別途アップロード）：[`docs/colab-deep-analysis.ipynb`](docs/colab-deep-analysis.ipynb)

ノートブック内で `scan-state.json` を生成し、そのまま分析へ渡します。stateの事前アップロードは不要です。既存stateを使うモードも残しています。NVD補完は明示的にオン／オフできます。

**セルごとの説明：** [`docs/colab-deep-analysis.md`](docs/colab-deep-analysis.md)

## NVD クローラーと LLM 分析

PR #18（`9ab2de0`）を基に、NVD クローラーが正規化済みの CVE を返し、既存の照合 → Screening → 条件付き Deep Analysis → Feed へ渡す構成です。NVD API キーは任意です。

```sh
go run ./cmd/mvp-run \
  -repository https://github.com/juice-shop/juice-shop \
  -model qwen3:8b \
  -base-url http://127.0.0.1:11434
```

Ollama の起動とモデル取得が必要です。通常は NVD 全体の最新 200 件を取得し、`-published-start` / `-published-end` 指定時は既存の期間検索を使います。全既知脆弱性を調べるスキャナーではなく、Feed が空でも安全を意味しません。

結果 JSON の `match_matrix` は正規化に成功した重複なしの CVE ごとに、`cve_id`、最終 `decision`、NVD/OSV の対象ごとの `target`・`repository_items_compared`・`identity_matches`・`version_excluded`・`matches` を出力します。`no_affected_targets` は照合対象なし、`no_identity_match` は識別子の完全一致なし、`version_excluded` は一致した識別子のバージョンが除外、`matched` は候補ありを示します。正規化エラーは `errors` に記録され、行は作りません。`matched` は脆弱性や到達可能性の証明ではありません。

キーなしの NVD 取得だけを確認する場合（外部通信あり）:

```sh
NVD_LIVE_TEST=1 NVD_LIVE_COUNT=200 go test -v -count=1 ./src/nvd -run '^TestFetchLive$'
```

NVD の件数不整合や取得・正規化エラーは正常結果として扱わず停止します。詳細と対応範囲は [`docs/local-llm.md`](docs/local-llm.md) を参照してください。

## Repository vulnerability analysis

GitHub RepositoryをProfile化し、登録時刻以降に公開または更新されたCVEをNVDから200件ずつ全ページ取得して照合・分析するWorkflowを実装中です。Workflowは登録処理から未接続で、永続化・定期実行もありません。詳細は[`docs/local-llm.md`](docs/local-llm.md)を参照してください。
