# リポジトリ起点のOSVスキャン（CPUのみ）

`cmd/repo-scan` は、既存の「NVD全体の最新200件 → LLM」経路とは別の初回スキャン・保存構成の再照会コマンドです。Ollama、モデル、GPUは不要です。対象はNext.jsに限定しません。

## 処理

1. 公開GitHubリポジトリを取得し、既存プロファイラーでlockfile／manifestなどから構成要素を抽出。解析したcommit SHAを保存します。対象コードやパッケージのインストールスクリプトは実行しません。
2. **エコシステム＋完全なパッケージ名＋確定バージョン**でOSV照会を重複排除します。異なるバージョンは別照会です。各照会に元コンポーネント、ファイル、scopeをすべて残します。
3. OSV `/v1/querybatch` を分割して照会し、各照会のページを最後までたどります。返されたIDの詳細を `/v1/vulns/{id}` から取得します。同じ詳細の取得は1実行につき1回です。
4. OSVレコードのID／aliasに明示されたCVEのみ、NVDに `cveId` で照会します。パッケージ名からCPEを推測せず、NVDの原文も保存します。
5. 明示的なID／aliasでグループ化しつつ、各情報源の原文とパッケージ単位の照合根拠を別々に保存します。CVEのないGHSA等も残します。
6. `-monitor` で保存済み構成を1回再照会し、新規／更新／観測されなくなったレコードを比較します。

**これは全OSV/NVDの更新フィード取り込みや常駐スケジューラーではありません。** 定期実行は外部から `-monitor` を呼びます。毎回、前回0件だった照会も含めて再照会し、新しく登録された該当アドバイザリを検出します。保存SHA以降の依存変更は追跡しません。別commitは新しいstateに初回スキャンしてください。従来のNVD新着監視／LLM経路はそのまま残しています。

## 実行

プロジェクトルートで実行します。Go 1.25.0以上とGitが必要です。対応するGoでは `GOTOOLCHAIN=auto` によるツールチェーン取得も利用できます。

```sh
# 初回：依存抽出 → OSV → NVD補完 → JSON出力 → state保存
# stateの親ディレクトリは事前に作成し、既存のstateとは別の名前を使います。
go run ./cmd/repo-scan \
  -repository https://github.com/juice-shop/juice-shop \
  -state juice-shop-state.json > juice-shop-scan.json

# 同じ構成・SHAを再照会。cloneやLLM呼び出しはしません。
go run ./cmd/repo-scan \
  -monitor -state juice-shop-state.json > juice-shop-monitor.json

# 以前のmvp-run結果のrepository_profileも入力できます。
go run ./cmd/repo-scan \
  -profile previous-mvp-result.json -plan-only > query-plan.json

# 抽出済みプロフィールを使う初回スキャン。
go run ./cmd/repo-scan \
  -profile previous-mvp-result.json -state imported-state.json > imported-scan.json
```

- `-ref`：初回GitHub取得のブランチ／タグ。省略はデフォルトブランチです。「前のバージョン」を試す場合は対象タグを明示してください。
- `-plan-only`：OSV/NVDには通信せず、照会予定と未照会理由を出力。`-repository` 指定時のGitHub取得は行います。`-profile` なら取得も不要です。
- `-nvd=false`：OSVだけを照会。NVD補完は `not_checked`。旧NVDの根拠は監視結果の `retained_records` に残します。
- `NVD_API_KEY`：任意。キーなしはNVD照会間隔6秒、キーありは650ミリ秒。複数プロセスのレート共有はありません。
- `-batch-size 100`：1回のOSV HTTPリクエストに含める照会数。**総パッケージ数100件という制限ではありません。** 旧`Enrich`の100種類／10,000構成要素制限は新経路に適用しません。
- `-max-pages 100`：1照会あたりのページ予算。超過は打ち切り成功ではなく `complete:false`。
- `-request-timeout 30s`：1HTTPリクエストの時間制限。
- `-timeout 15m`：取得・API処理の期限。既存の同期プロファイラー処理を途中停止する保証はありません。
- `-osv-base-url` / `-nvd-base-url`：テスト用エンドポイントの指定。

OSVにはパッケージ名・エコシステム・バージョン、NVDにはCVE IDを送信します。ソース本文・検出元パスはこれらのAPIに送りません。state／結果JSONには依存情報・出典パスが含まれるため、共有範囲に注意してください。

重複排除とバッチ化で通信量を減らしますが、処理時間一定の保証はありません。NVDの補完対象が多いと、キーなしの場合は待機だけでも概ね `6秒 × (CVE数 − 1)` 必要です。必要に応じて期限を長くするか、まず `-nvd=false` でOSV部分を確認してください。HTTP失敗は不完全な結果として返し、無制限の自動リトライはしません。

## JSONの読み方

| フィールド | 意味 |
| --- | --- |
| `repository.commit_sha` | 今回の構成要素が属するcommit |
| `acquisition` / `profile_source` | 取得状態とGitHub／インポート／保存スナップショットの区別 |
| `report.refresh_complete` | 照会・ページング・詳細取得・指定されたNVD補完が完了したか |
| `report.status` | `complete` または `incomplete`。未照会やプロファイル警告も含む網羅性の状態 |
| `report.queries` | パッケージ＋バージョン別の結果matrix。`origins`が元ファイルなどの一覧 |
| `report.queries[].complete` / `error` | その照会の完了状態と失敗理由。部分的な一致とエラーは併存できます |
| `report.queries[].matches` | 出典レコードへのキーと、出典が提示した修正版の境界 |
| `report.unqueried` | バージョン不明・未対応・識別子不明などの未照会構成要素 |
| `report.records` | 今回取得した `osv:<ID>` / `nvd:<ID>` 別の原文 |
| `report.retained_records` | 以前取得したが今回は再確認できていないNVD原文。今回の一致根拠には混ぜません |
| `report.groups` | 明示ID／aliasに基づく今回の複数出典の関連付け |
| `report.enrichment` | CVEごとのNVD補完：`found` / `not_found` / `not_checked` / `error` |
| `report.ecosystems` / `warnings` | エコシステム別の件数、検査できなかった範囲と理由 |
| `changes` | 監視時の `added` / `modified` / `query_changed` / `no_longer_observed` |
| `state_update` | `after_output`＝出力後に保存を試行、`skipped_incomplete_refresh`＝既存state更新を見送り |

判定は次の意味です。

- `affected_version_match`：OSVの正確なバージョン照会がアドバイザリを返し、詳細のエコシステム・パッケージが一致。**コード上の到達可能性／実被害の確定ではありません。**
- `no_advisory_found`：完了した照会で該当情報が見つからなかった。「安全」「影響範囲外」ではありません。
- `unknown`：不完全・詳細不整合などにより判断できない。未照会構成要素は別の `unqueried` に残します。
- `withdrawn`：取り下げられたアドバイザリ。原文は残しますが肯定的な一致根拠にしません。

この経路では「該当なし」から `not_affected` を作りません。`fixed_versions` は出典の修正境界一覧であり、全てのブランチに適用可能なアップグレード推奨ではありません。影響範囲原文は `records` で確認できます。`runtime_impact` は常に `unknown` とし、その後のコード・設定の確認と分離します。

既存プロファイラーは注意事項を持つため、**正常な通信でも `status:incomplete` になる場合があります。** `refresh_complete` と `unqueried`・`warnings` を合わせて確認してください。

### 終了コードと保存

- 終了0：要求された照会処理とstate保存が成功（`-plan-only` は照会・保存なし）。全範囲の検査や安全を意味しません。
- 終了1：取得／照会／出力／保存などの失敗。結果JSONがあればその詳細と標準エラーを確認してください。
- 初回の不完全な結果は再試行のためstateに保存できますが、既存stateを不完全な監視結果で置き換えません。
- 監視結果の出力に失敗した場合、基準stateを進めません。出力成功後に保存し、保存成功は標準エラーの `Snapshot saved:` と終了状態で確認します。JSONの `state_update:after_output` 自体は保存成功の宣言ではありません。
- 保存失敗や出力後のプロセス停止では、次回に同じ変更が再通知され得ます。exactly-once配送を保証する通知システムではありません。
- stateは同じディレクトリの0600一時ファイル経由で置換。異なるプロフィール、壊れたstate、symlinkへの上書きを拒否します。同じstateへの同時書き込みは外部で直列化してください。
- `no_longer_observed` は今回観測しなくなったという意味で、修正完了ではありません。NVDを無効化しただけでは削除通知しません。

## 未対応・不明の扱い

- OS・配備環境は、このリポジトリ構成だけでは網羅的に評価しません。
- workspace／依存経路は既存profileにないため `unavailable`。ファイルパスから推測で埋めません。
- 解決済みバージョンがないmanifest宣言は原文の構成要素を残し、`unresolved version` とします。
- CocoaPodsは新OSV照会経路では未対応。NuGetは既存抽出の小文字化からOSV向けの正規パッケージ名を確実に復元できないため、`OSV canonical package identity unavailable` として未照会にします。
- 他の形式も既存プロファイラーの対応範囲に依存します。プロフィールの警告は削除せず出力に引き継ぎます。未対応を「検査完了」にしません。
- テスト／examples／開発用の依存も抽出対象に含まれ得ます。構成要素の総数を本番の固有依存数と解釈しないでください。

## Google ColabでのE2E手順

**CPUランタイムで実行できます。** 実API・実リポジトリを使うこの手順は手元での確認用です。自動テストはHTTPモックを使っています。

### 1. 新しいZIPを展開・ビルド

アップロード名が `(1).zip` になっても、保存されたパスに依存しない方法です。古い展開先と混ぜません。

```python
from google.colab import files
from pathlib import Path
from zipfile import ZipFile
from io import BytesIO
import tempfile, subprocess, shutil, os, json, tarfile, hashlib, platform
from urllib.request import urlopen

uploaded = files.upload()
assert len(uploaded) == 1, "今回の実装ZIPを1つアップロードしてください"
work = Path(tempfile.mkdtemp(prefix="vulns-news-osv-", dir="/content"))
with ZipFile(BytesIO(next(iter(uploaded.values())))) as z:
    z.extractall(work)  # 自分が信頼するソースZIPだけを展開してください
repo = work / "vulns-news"
assert (repo / "cmd/repo-scan/main.go").is_file(), repo

if not shutil.which("git"):
    subprocess.run(["apt-get", "update", "-qq"], check=True, timeout=300)
    subprocess.run(["apt-get", "install", "-y", "git"], check=True, timeout=300)

# aptの古いGoに依存せず、公式Go 1.25.0を作業用フォルダに取得します。
assert platform.system() == "Linux" and platform.machine() == "x86_64"
with urlopen("https://go.dev/dl/?mode=json&include=all", timeout=60) as response:
    releases = json.load(response)
release = next(r for r in releases if r["version"] == "go1.25.0")
archive = next(f for f in release["files"]
               if f["os"] == "linux" and f["arch"] == "amd64" and f["kind"] == "archive")
with urlopen("https://go.dev/dl/" + archive["filename"], timeout=180) as response:
    payload = response.read()
assert hashlib.sha256(payload).hexdigest() == archive["sha256"], "Goのチェックサム不一致"
toolchain = work / "toolchain"
toolchain.mkdir()
with tarfile.open(fileobj=BytesIO(payload), mode="r:gz") as tar:
    tar.extractall(toolchain, filter="data")
go = toolchain / "go/bin/go"
env = dict(os.environ, GOTOOLCHAIN="auto")
env["PATH"] = str(go.parent) + os.pathsep + env.get("PATH", "")
binary = work / "repo-scan"
subprocess.run([str(go), "version"], cwd=repo, env=env, check=True, timeout=300)
subprocess.run([str(go), "build", "-o", str(binary), "./cmd/repo-scan"],
               cwd=repo, env=env, check=True, timeout=600)
print("使用コード:", repo)
```

### 2. 初回スキャン

NVDキーは任意です。Next.jsで特定バージョンを検証する場合は実在するタグを `ref` に指定してください。空ならデフォルトブランチです。

```python
repository_url = "https://github.com/vercel/next.js"
ref = ""  # 特定バージョンのテストでは対象のタグを指定
state = work / "scan-state.json"
assert not state.exists(), "初回スキャン済みです。監視セルを実行するか新しいstate名を指定してください"
args = [str(binary), "-repository", repository_url,
        "-state", str(state), "-timeout", "30m"]
if ref:
    args += ["-ref", ref]
# NVDを含めずまずOSVを検証する場合のみ: args += ["-nvd=false"]
result = subprocess.run(args, cwd=repo, env=env, capture_output=True,
                        text=True, timeout=2100)
print(result.stderr)
print("終了コード:", result.returncode)
(work / "scan-result.json").write_text(result.stdout, encoding="utf-8")
data = json.loads(result.stdout) if result.stdout.strip() else {}
report = data.get("report")
if report:
    print("SHA:", data["repository"]["commit_sha"])
    print("網羅性:", report["status"], "照会完了:", report["refresh_complete"])
    print("照会数:", len(report["queries"]), "未照会:", len(report["unqueried"]))
    print("出典レコード:", len(report["records"]), "統合グループ:", len(report["groups"]))
else:
    print(data)
```

### 3. 結果をmatrix／CSVにする

1行は1照会と1アドバイザリの組です。複数のアドバイザリがあれば行数はパッケージ数より増えます。出典詳細は `record_key` を使って `report.records` を参照します。未照会も一覧に含めます。

```python
import pandas as pd
assert report is not None, "取得エラーを解消して初回スキャンを再実行してください"
rows = []
for q in report["queries"]:
    for match in q["matches"] or [{}]:
        rows.append({
            **q["query"], "outcome": match.get("outcome", q["outcome"]),
            "complete": q["complete"], "error": q.get("error", ""),
            "record_key": match.get("record_key", ""),
            "fixed_versions": ", ".join(match.get("fixed_versions", [])),
            "origins": len(q["origins"]),
            "source_paths": ", ".join(sorted({c["source_path"] for c in q["origins"]})),
            "runtime_impact": q["runtime_impact"],
        })
for item in report["unqueried"]:
    c = item["component"]
    rows.append({"ecosystem": c["ecosystem"], "name": c["name"],
                 "version": c.get("version", ""), "outcome": "unqueried",
                 "complete": False, "error": item["reason"],
                 "source_paths": c.get("source_path", ""), "runtime_impact": "unknown"})
df = pd.DataFrame(rows)
with pd.option_context("display.max_rows", None):
    display(df)
csv = work / "scan-matrix.csv"
df.to_csv(csv, index=False)
print("CSV:", csv)
print("警告:", report["warnings"])
```

### 4. 同じ構成を再照会

```python
assert state.is_file(), "先に初回stateを保存してください"
result = subprocess.run(
    [str(binary), "-monitor", "-state", str(state), "-timeout", "30m"],
    cwd=repo, env=env, capture_output=True, text=True, timeout=2100)
print(result.stderr)
print("終了コード:", result.returncode)
(work / "monitor-result.json").write_text(result.stdout, encoding="utf-8")
monitor = json.loads(result.stdout) if result.stdout.strip() else {}
print("変更:", monitor.get("changes", []))
```

初回に `-nvd=false` を使った場合、監視でも同じフラグならOSVのみです。フラグを外せばNVD補完を追加します。Colabのランタイム終了でstateが消えるので、継続監視にはDriveなどへバックアップしてください。モデルを使ったDeep Analysis／Feed出力は `repo-scan` 自体には含まれません。保存stateを入力とする `repo-analyze` で続行できます。実行セルは [Colab Deep Analysis手順](colab-deep-analysis.md) と [ノートブック](colab-deep-analysis.ipynb) を参照してください。

## 単体・結合テスト

```sh
go test ./...
go vet ./...
go test -race ./cmd/repo-scan ./src/reposcan ./src/osv ./src/nvd -count=1
```

実ファイルからの多言語抽出、バッチ／ページング、異なるバージョンと出典の保持、CVEなしアドバイザリ、NVD補完、原文保持、状態の往復、再照会差分、部分失敗、出力失敗、未確認の過去根拠の保持を検証します。実APIの応答内容・実行時間や巨大リポジトリのE2E完了は、このテストでは保証しません。

API仕様：[OSV querybatch](https://google.github.io/osv.dev/post-v1-querybatch/)、[OSV詳細取得](https://google.github.io/osv.dev/get-v1-vulns/)、[NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities)。
