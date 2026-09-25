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
