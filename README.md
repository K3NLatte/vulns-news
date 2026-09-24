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

Vue のアプリを作成する場合は、開発シェル内で次を実行します。

```sh
pnpm create vue@latest
```

Nix の設定で `nix-command` と `flakes` が無効の場合は、`nix --extra-experimental-features 'nix-command flakes' develop path:.` を使用してください。

## Repository vulnerability analysis

GitHub RepositoryをProfile化し、登録時刻以降に公開または更新されたCVEをNVDから200件ずつ全ページ取得して照合・分析するWorkflowを実装中です。Workflowは登録処理から未接続で、永続化・定期実行もありません。詳細は[`docs/local-llm.md`](docs/local-llm.md)を参照してください。
