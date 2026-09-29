# レポートの保存・取得

SQLiteのテーブル作成と、Goから呼べるCRUD処理です。HTTPルート・既存モックAPI・フロントエンドは変更していません。

## 呼び出す処理

| 処理 | 用途 |
| --- | --- |
| `Open(ctx, path)` | DBを開き、初回だけテーブルを作る。サーバー起動時に1回呼ぶ |
| `Create(ctx, input)` | 解析結果を1件追加。採番したレポートを返す |
| `Get(ctx, reportID)` | IDで1件取得 |
| `GetLatest(ctx, key)` | リポジトリ・コミット・脆弱性ID・更新日時が一致する最新の保存結果を取得 |
| `ListLatest(ctx, options)` | 指定リポジトリ・コミットの最新結果をページ単位で取得 |
| `Update(ctx, reportID, input)` | 既存レポート1件の内容を置き換える |
| `Delete(ctx, reportID)` | 指定レポート1件を物理削除 |
| `Close()` | DB接続を閉じる。サーバー終了時に呼ぶ |

`Input`、戻り値の `Report`、`ContextKey` は [types.go](types.go) にあります。本文は `Body`（JSON名は `report_json`）。入力にレポートIDや保存日時を指定する必要はありません。

```go
store, err := reportstore.Open(ctx, "reports.sqlite")
if err != nil {
    return err
}
defer store.Close()

// feedJSONは解析側のfeed.ItemをJSONにしたもの。
// screeningは一次判定結果。feed単体しかなければnil。
input, err := reportstore.FromFeedJSON(feedJSON, screening)
if err != nil {
    return err
}
saved, err := store.Create(ctx, input)
if err != nil {
    return err
}
loaded, err := store.Get(ctx, saved.ID)
if err != nil {
    return err
}
```

完全な使用例は [example_test.go](example_test.go) にあります。`Open` のパスはサーバー設定で指定するローカルファイルです。親フォルダーは先に用意してください。リクエスト値をDBのパスに使わないでください。

## API担当への受け渡し

API側でこのパッケージを呼び、HTTPレスポンスへの変換とエラー処理を実装してください。

- `errors.Is(err, reportstore.ErrInvalid)`：入力や状態の不整合。
- `errors.Is(err, reportstore.ErrNotFound)`：指定したレポートなし。更新・削除でも返す。
- `context.Canceled` / `context.DeadlineExceeded`：呼び出し元の中止・タイムアウト。
- その他：DBの読み書き等の失敗。内部エラー本文をそのままHTTPで公開しない。

一覧が0件なら空配列を返します。`Limit` は既定50件、最大200件。次ページは最後のレポートのIDを `BeforeID` に渡します。認証・認可はここでは行わないため、特に更新・削除を公開する場合の利用者確認はAPI側の責務です。

mainの `server/model.FeedItem` は画面用モック型で、今回の保存型とは異なります。解析側の `src/feed` はまだ別PRなのでimportしていません。解析のJSONを `FromFeedJSON` で変換するか、同じ項目の `Input` をGo側で作成してください。

`ToFeedJSON(report)` は本文とカラム、applicability内の識別情報を再結合します。保存対象外の `generation` と不明な日時は出力しません。画面用のタイトルや関連度スコアなどを作る処理は含みません。

## 更新・再解析・削除

再解析結果は `Create` で新しい行にします。`Update` は既存行の訂正用で、レポートID、最初の保存日時、4項目の `ContextKey` を変更できません。古い行を訂正しても最新の順番は変わりません。

更新のトランザクションは、対象行を読む前に書き込みロックを取得します。複数のStoreから同時に更新した場合もロック解放を待ち、最後に成功した更新が残ります。ユーザー同士の編集競合を通知する仕組みはありません。

`Delete` は履歴を含む指定1行だけの削除です。最新行を削除すると、残っている過去の行が最新になります。フィードから恒久的に非表示にする操作ではありません。削除済みレポートのIDは再利用しません。

`ListLatest` は各ContextKeyの最新行を選んだ後で `unrelated` を除外します。`IncludeUnrelated: true` で無関係の判定も取得できます。異なる脆弱性revisionを1つにまとめる選択や、どのコミットを利用者に表示するかは呼び出し側で決めてください。ページ取得中の更新・削除を固定するスナップショットは提供しません。

## 保存するデータ

スキーマは [schema.sql](schema.sql) にあります。`reports` と初期化用の `reportstore_schema` を作ります。リポジトリID・コミット・脆弱性IDは必須です。公開日時・更新日時・CVE番号・深刻度・CVSSは任意で、不明な値はNULLとして保存します。NULLのCVSSを0点に変えません。

解析側が日時の欠損を表す `0001-01-01T00:00:00Z` は、取り込み時に不明へ変換します。現在時刻や他の日付で補完しません。更新日時不明の結果は既知の版と分けて保持します。同じ版と確認できた結果としてキャッシュを再利用しないでください。

JSON本文はmatches、一次判定理由・根拠ID、要約、影響説明、不足情報、推奨対応、applicability、evidenceを保存します。カラムの重複やgenerationは保存しません。日時はUTC RFC3339で小数秒9桁まで保持し、末尾の不要な0を除いた共通の表記へ正規化します。`12:00:00Z` と `12:00:00.000Z` は同じ版として保存・検索します。

`FromFeedJSON` はapplicability内の対象IDを照合してから重複を除きます。一次判定を別途渡した場合は、関連性・理由の一致と根拠IDを検証します。構造が変わって項目が増えた場合はエラーにし、保存すべきか確認して変換処理を更新します。

本文のJSON構造、サイズ、対象ID、状態、CVSS、根拠ID参照を検証します。SQLへは値をパラメーターで渡します。解析文章の正しさや、参照先の安全性を保証するものではありません。取得後も未信頼の文章・URLとして扱ってください。

無関係の結果は `screened + unrelated` のInputとして保存できます。ただし、除外前の正規化済み対象情報・matches・evidence本文が必要です。共有されたZIPの除外9件にはこれらが不足しているため、アーカイブ検証では保存できた件数に含めません。欠損を空データで埋めません。

## 初期化と運用

SQLiteドライバーは `modernc.org/sqlite v1.59.0`。Go 1.25に対応する版へ固定しています。既存のNix設定は変更していません。

初期化と移行はトランザクションで行います。スキーマv1・v2のDBは、日時欠損と日時表記の統一に対応するv3へ移行します。既存レポート・ID・保存日時・削除済みIDの採番履歴を維持し、同じ版の履歴も削除しません。未知のスキーマ版や、版管理のない古い試作reportsテーブルには自動適用しません。版管理のない試作DBを使う場合は別途移行が必要です。

1つのStore内のDBアクセスは1接続で直列化します。WAL・busy timeout・外部キー制約・同期設定は接続ごとに適用し、処理中断による再接続後も維持します。呼び出しには期限付きcontextを渡してください。DB接続を毎リクエスト開き直す必要はありません。

レポートの自動再利用、有効期限、重複リクエストの排除、ジョブ管理、バックアップ運用は含みません。

## テスト

リポジトリの開発シェルで実行します。テストは一時DBを使います。

```sh
go test ./...
go test -race ./server/repository/reportstore
go vet ./...
go mod verify
```

共有された実データも検証する場合:

```sh
VULNS_ANALYSIS_ARCHIVE=/path/to/analysis-results.zip go test ./server/repository/reportstore -run Archive -v
```

ZIPはテスト用のローカル入力で、リポジトリへ同梱していません。JSONだけを読み、LLM・クロール・外部APIは呼びません。候補処理の完了と情報収集の網羅性は別で、添付結果のscanはincompleteです。

参照した実装はmain `bc2466d`（モックAPI #19）と解析PR #15の `1183eb6`、実データは `analysis-results.zip` です。Issue #11の広い構想よりも、直近に合意したレポートCRUDを実装範囲にしています。
