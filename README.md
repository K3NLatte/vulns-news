# vulns-news

## 実スキャン・解析・保存・Feed・画面の結合

`cmd/news-server` が公開GitHubの取得 → OSV照合 → 既存Screening／Deep Analysis → JSON保存 → Feed API → Vue画面を接続します。既存の `server` / `src/scanjob` のスキャン専用実装は保持しています。

```sh
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend build
go run ./cmd/news-server -model=""
```

http://127.0.0.1:8080/ を開きます。上記は保存結果の閲覧専用で、初回は空です。既存解析の取り込み、新規スキャンを有効にする方法、非LLM検証は [全体結合ガイド](docs/e2e-integration.md) を参照してください。

現行フロントの正式な接続先は `cmd/news-server` です。旧 `server/cmd/api` のモックAPIとSQLite実装は互換性維持のため保持していますが、現行画面に必要な `GET /api/analyses` に対応せず、接続先としては使用しません。保存データの自動移行も行いません。

標準GUI検証は `pnpm --dir frontend test:e2e`。本番ビルドと現行サーバーを使い、リポジトリ内fixtureを一時領域に取り込むため、外部LLM・スキャン・手元の実解析データは不要です。初回のブラウザー導入などは [フロントガイド](frontend/README.md#検証) を参照してください。


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

フロントエンドの開発時は、上記の `cmd/news-server` を起動したまま、別の開発シェル内で次を実行します。`/api` は8080番の現行サーバーへ転送されます。

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

**結果matrixの表示・未対応範囲・終了コード**は [`docs/repository-scan.md`](docs/repository-scan.md) を参照してください。

## 保存したOSV結果をDeep Analysisまで検証

`repo-analyze` は保存stateから一致候補を作り、既存のScreening → 関連ありの場合のDeep Analysis → Feedに接続します。GitHub／OSVの再取得は不要です。各LLMステージの完了を保存し、中断後は `-resume` で続行できます。

```sh
go run ./cmd/repo-analyze -state juice-shop-state.json \
  -output analysis-results.json -model qwen3:8b -require-deep
```

デフォルトは全候補。`-require-deep` は分析済みFeedが0件なら終了1にし、E2E到達を区別します。関連性を強制する機能ではありません。GPUが有効なのはOllamaの推論です。


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
