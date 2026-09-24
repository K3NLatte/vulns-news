# vulns-news

## NVDのCVE取得ライブラリ

`nvd` パッケージは、NIST（米国国立標準技術研究所）のNVD（脆弱性データベース）から、公開日時が新しいCVE（脆弱性識別子）と説明文を取得します。APIキーは不要です。

```go
import (
    "context"
    "vulns-news/nvd"
)

client := nvd.NewClient()
items, err := client.Fetch(context.Background(), 10)
```

同じGoモジュール内では `vulns-news/nvd` をインポートして使用します。`Fetch` は指定した件数を新しい順に返します。英語の説明文があれば優先します。複数回の取得が必要な場合は、リクエスト間に6秒の間隔を置きます。
