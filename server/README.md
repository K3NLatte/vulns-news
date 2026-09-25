# モックAPIサーバー

フロントエンドとの接続確認用に、`mockdata/` のJSONをHTTPで返します。

## フォルダ構成

```text
server/
├── cmd/api/main.go       # サーバーの起動
├── api/
│   ├── config.go         # モックの場所を設定
│   ├── router.go         # URLとhandlerの対応
│   └── handlers.go       # 入力の確認とHTTPレスポンス
├── repository/mock.go   # JSONの読み込みとIDによる検索
├── model/types.go       # JSONに対応するGoの構造体
└── mockdata/            # 固定のJSONデータ
```

リクエストは `router → handler → repository` の順に処理します。
`model` の構造体はAPIとrepositoryで共用し、テストは対象のコードと同じフォルダに置きます。

## 起動と確認

Go 1.25以上を使用し、リポジトリのルートで実行します。

```sh
go run ./server/cmd/api
```

`http://127.0.0.1:8080` で起動します。別のターミナルから確認できます。

```sh
curl -i "http://127.0.0.1:8080/api/cves?limit=5"
go test ./server/...
```

`server` ディレクトリ内から起動する場合は `go run ./cmd/api` を使います。
モックの保存先を変更する場合は、環境変数 `MOCK_DATA_DIR` にディレクトリのパスを指定します。

## 実装済みのルート

| メソッド | パス | 応答 |
| --- | --- | --- |
| GET | `/api/cves?limit=5` | CVE一覧（200）。limitは1〜200、省略時10 |
| GET | `/api/cves/{cve_id}` | CVE詳細（200） |
| POST | `/api/repositories` | 登録受付の固定ID（202） |
| GET | `/api/jobs/{job_id}` | ジョブの完了状態（200） |
| GET | `/api/repositories/{repository_id}/feed` | 関連CVE一覧（200） |
| GET | `/api/repositories/{repository_id}/feed/{cve_id}` | 関連CVE詳細（200） |

一般一覧は12件、関連一覧は6件です。登録は本文を利用せず、常に `repo-001` と `job-001` を返します。
リポジトリの保存、実際の解析、ジョブの時間による状態遷移は行いません。
不正なlimitは400、存在しないIDは404、モックの読み込み失敗は500を返します。
解析作成・取得と内部処理の3ルートは、引き続き501を返す未実装の窓口です。
