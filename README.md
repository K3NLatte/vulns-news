# vulns-news

## 開発環境

[Nix](https://nixos.org/) の開発シェルに Go、Node.js、pnpm、SQLite のコマンドを用意します。Vue は JavaScript のライブラリなので、プロジェクトを作成するときに pnpm で追加します。

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

## フロントエンドのローカルモック

Nix開発シェルに入った後、次を実行します。

```sh
cd frontend
pnpm install --frozen-lockfile
pnpm dev
```

ブラウザで <http://localhost:5173> を開いてください。WindowsではWSL側のターミナルで実行します。

一般フィード、リポジトリ向け表示、検索、重要度フィルター、並び替え、記事詳細を確認できます。記事・依存関係・AI分析はすべて架空サンプルで、APIや実際の解析には接続していません。

- [起動手順・画面の確認方法](frontend/README.md)
- [バックエンド接続に向けた境界と未決定事項](docs/frontend-integration.md)
- [製品の範囲](PRODUCT.md)

Nix の設定で `nix-command` と `flakes` が無効の場合は、`nix --extra-experimental-features 'nix-command flakes' develop path:.` を使用してください。

## NVDのCVE取得ライブラリ

`src/nvd` は、NIST（米国国立標準技術研究所）のNVD（脆弱性データベース）からCVE（脆弱性識別子）を取得するGoパッケージです。`Fetch` は公開日時が新しい順に `[]nvd.NormalizedVulnerability` を返します。

```go
import (
    "context"
    "vulns-news/src/nvd"
)

client := nvd.NewClient()
items, err := client.Fetch(context.Background(), 10)
```

`NormalizedVulnerability` にはCVE ID、公開日時、更新日時、説明文、深刻度、CVSSスコア、弱点分類、影響製品、参照情報を含めます。NVDの日時にタイムゾーンがない場合はUTCとして解釈します。説明文は英語を優先します。

CVSS（共通脆弱性評価システム）は、4.0、3.1、3.0、2.0の順に選びます。同じ版に複数の評価がある場合は `Primary` を優先します。評価がない場合、`cvss` は省略され、`severity` は空文字列になります。

影響製品には、NVDの `affected` にある `affected` 状態のバージョンを使用します。該当する情報がない場合は、`configurations` にある `vulnerable: true` のCPE（製品識別子）条件を使用します。NVDの適用条件に含まれるAND・ORや除外条件は、この一覧には反映されません。そのため、この一覧だけで個別環境が脆弱かどうかは判定できません。
