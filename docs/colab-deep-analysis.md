# Colab: GitHub → OSVスキャン → Screening → Deep Analysis → Feed

**このノートブックだけで、リポジトリ取得から `scan-state.json` の生成、LLM分析まで実行できます。stateを事前に用意する必要はありません。** セル2で `repo-scan` がstateを生成し、そのstateを `repo-analyze` に渡します。分析段階ではGitHub／OSV／NVDを再取得しません。

**新しいノートブック／ランタイムでも、セル1から順番に実行できます。以前のPython変数や更新セルは不要です。** 配布版 `colab-github-to-feed-typed-citations-20260926.ipynb` は型別引用ID対応版のソースを同梱しており、ソースZIPの別アップロードも不要です。

セル2の `SOURCE_MODE` で処理を選びます。

| モード | 処理 | 必要なファイル |
|---|---|---|
| `github`（初期値） | GitHub取得 → OSVスキャン → 分析 | なし |
| `saved` | 保存済みスキャンから分析を開始 | `analysis-scan-state.json` または元の `scan-state.json` |
| `resume` | 保存済みの成功結果を再利用し、失敗／未処理から再開 | 上記stateと、それに対応する `analysis-results.json` |

保存ファイルはアップロード、または残っているファイルのパス指定で読み込めます。CSVやmatrixはstateの代わりにはなりません。ランタイム切断前にセル6でバックアップしてください。

- CPU：GitHub取得、依存抽出、OSV／任意のNVD照会、state検証、分析候補・根拠の組み立て、JSON検証、Feed生成。
- GPUが有効：OllamaによるScreening／Deep Analysisの推論。今回の配布版はセル3で短い推論とモデルのGPU配置を確認してから進みます。CPUでも動きますが、遅いCPU推論を許容する場合は明示的に `REQUIRE_GPU=False` にしてください。
- 最初にGPUランタイムを選べば同じランタイムで一連の処理を進められます。途中でランタイムを変更するとファイルが消える場合があるため、その前にstateをダウンロード／Driveに保存してください。
- ソースZIPとOllama・Go・モデルのダウンロードは通信が発生します。`qwen3:8b` は約5GBのモデルです。
- 一致した依存の名前・バージョン・出典パスとアドバイザリ本文をモデルに渡します。全ソースコードや13,000件の全構成要素を候補ごとに送信する方式ではありません。リモートOllamaを指定する場合はその情報の外部開示になります。

以下のセルは同梱の `colab-deep-analysis.ipynb` にもあります。実OllamaでのE2Eは手元で実行してください。自動テストではHTTPモックを使用しています。

## 1. 初期設定・修正版コードのビルド（CPU）

**ソース同梱版は、そのままこのセルを実行してください。** 同梱ソースのSHA-256を確認してから展開します。ソースを同梱しない開発用ノートブック／このMarkdownから実行する場合のみ、`vulns-news-colab-typed-citations-20260926.zip` をアップロードします。旧ZIPには型別引用IDや候補失敗後の継続に未対応のものがあるため、この配布版を使用してください。ソースのハッシュ照合は破損検出であり、配布元の認証ではありません。信頼するノートブックだけを実行してください。

セル1は必要な変数を初期化し、別の一時フォルダを作ります。以前のファイルは削除・上書きしません。**新しいランタイムではセル1から実行し、復元するならセル2で `resume` を選んでください。** 同じランタイムで単に分析を再試行する場合は、セル1をやり直さずセル4だけを再実行します。

```python
#@title 1. 初期設定・修正版コードのビルド
from google.colab import files
from pathlib import Path
from io import BytesIO
from zipfile import ZipFile
from urllib.request import urlopen
import os, json, subprocess, shutil, tempfile, tarfile, hashlib, platform, re, signal, base64, stat

analysis_setup_ready = False
analysis_ready = False
model_ready = False
model_ready_for = None
analysis_returncode = None
resume_settings = {}
if globals().get("_BUNDLED_SOURCE_B64"):
    source_payload = base64.b64decode(_BUNDLED_SOURCE_B64, validate=True)
    assert hashlib.sha256(source_payload).hexdigest() == _BUNDLED_SOURCE_SHA256, "同梱ソースのハッシュが一致しません"
    print("同梱の引用ID修正版コードを使用します。ソースZIPのアップロードは不要です。")
else:
    uploaded_source = files.upload()
    assert len(uploaded_source) == 1, "引用ID修正版のソースZIPを1つ選択してください"
    source_payload = next(iter(uploaded_source.values()))
print("ソースSHA-256:", hashlib.sha256(source_payload).hexdigest())
analysis_work = Path(tempfile.mkdtemp(prefix="vulns-news-analysis-", dir="/content"))
with ZipFile(BytesIO(source_payload)) as z:
    assert z.testzip() is None, "ソースZIPが破損しています"
    for member in z.infolist():
        target = (analysis_work / member.filename).resolve()
        assert target.is_relative_to(analysis_work.resolve()) and not stat.S_ISLNK(member.external_attr >> 16), "安全に展開できないZIPエントリです"
    z.extractall(analysis_work)
analysis_repo = analysis_work / "vulns-news"
for relative in ("cmd/repo-analyze/main.go", "cmd/repo-scan/main.go", "go.mod", "src/processor/citations.go"):
    assert (analysis_repo / relative).is_file(), f"引用ID修正版のソースが必要です: {relative} がありません"
analysis_output = analysis_work / "analysis-results.json"
if not shutil.which("git"):
    subprocess.run(["apt-get", "update", "-qq"], check=True, timeout=300)
    subprocess.run(["apt-get", "install", "-y", "git"], check=True, timeout=300)

analysis_env = dict(os.environ, GOTOOLCHAIN="auto")
existing_go = shutil.which("go")
bootstrap = str(existing_go) if existing_go else None
version = subprocess.run([bootstrap, "version"], capture_output=True, text=True, timeout=120) if bootstrap and Path(bootstrap).is_file() else None
match = re.search(r"go(\d+)\.(\d+)", version.stdout) if version and version.returncode == 0 else None
if not match or tuple(map(int, match.groups())) < (1, 21):
    assert platform.system() == "Linux" and platform.machine() == "x86_64"
    with urlopen("https://go.dev/dl/?mode=json&include=all", timeout=60) as response:
        releases = json.load(response)
    release = next(r for r in releases if r["version"] == "go1.25.0")
    archive = next(f for f in release["files"]
                   if f["os"] == "linux" and f["arch"] == "amd64" and f["kind"] == "archive")
    with urlopen("https://go.dev/dl/" + archive["filename"], timeout=180) as response:
        payload = response.read()
    assert hashlib.sha256(payload).hexdigest() == archive["sha256"]
    toolchain = analysis_work / "toolchain"
    toolchain.mkdir()
    with tarfile.open(fileobj=BytesIO(payload), mode="r:gz") as tar:
        tar.extractall(toolchain, filter="data")
    bootstrap = str(toolchain / "go/bin/go")
analysis_env["PATH"] = str(Path(bootstrap).parent) + os.pathsep + analysis_env.get("PATH", "")
scan_binary = analysis_work / "repo-scan"
analysis_binary = analysis_work / "repo-analyze"
for binary, package in [(scan_binary, "./cmd/repo-scan"), (analysis_binary, "./cmd/repo-analyze")]:
    subprocess.run([bootstrap, "build", "-o", str(binary), package],
                   cwd=analysis_repo, env=analysis_env, check=True, timeout=600)

def run_with_progress(command, output_path=None):
    # JSONはファイルへ、進行ログはその場で表示します。
    with open(output_path if output_path is not None else os.devnull, "w", encoding="utf-8") as output:
        process = subprocess.Popen(command, cwd=analysis_repo, env=analysis_env,
                                   stdout=output, stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            for line in process.stderr:
                print(line, end="", flush=True)
            return process.wait()
        except KeyboardInterrupt:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            raise
        finally:
            process.stderr.close()

analysis_setup_ready = True
print("使用コード:", analysis_repo)
print("作業フォルダ:", analysis_work)
print("初期設定完了。セル2のモードを選んで進めてください。")
```

## 2. 新規スキャン／保存データの復元・分析候補の確認（CPU）

初期設定は **Next.jsのデフォルトブランチ → OSVスキャン**です。特定バージョンを試す場合は実在するタグを `REF` に指定してください。空欄は「前バージョン」ではありません。

`USE_NVD=False` はNVD補完を省略する明示的な設定です。GitHub→OSV→LLM→FeedのE2Eを先に確認し、NVD補完も含める場合は最初から `True` にしてください。NVDキーなしではCVE照会間に6秒待つため、件数により大幅に時間が増えます。必要なら `SCAN_TIMEOUT` を延長し、任意の `NVD_API_KEY` を環境変数で設定してください。

`github` では、同じセルを再実行すると照会完了済みstateを再利用し、不完全なstateは保存済みの構成・SHAで再照会します。取得・照会を中断してstateがまだない場合は、次回に取得からやり直します。

**前回の591候補などを途中から再開するなら `resume` を選んでください。** `SAVED_STATE_PATH`・`SAVED_ANALYSIS_PATH` が空なら、state → 分析途中結果の順にアップロードを求めます。ファイルが残っている場合はその絶対パスを指定できます。`saved` はstateだけから分析を始めるモードで、前回の推論結果は引き継ぎません。同じ作業フォルダに途中結果がある場合は停止します。再開には `resume`、新規分析にはセル1から別の作業フォルダを使ってください。`saved`／`resume` ではGitHub・OSV・NVDを再照会しません。

```python
#@title 2. 新規スキャン／保存データからの復元
analysis_ready = False
model_ready = False
model_ready_for = None
analysis_returncode = None
resume_settings = {}
assert globals().get("analysis_setup_ready", False), "新しいランタイムでは、先にセル1を実行してください"
SOURCE_MODE = "github" #@param ["github", "saved", "resume"]
REPOSITORY_URL = "https://github.com/vercel/next.js" #@param {type:"string"}
REF = "" #@param {type:"string"}
USE_NVD = False #@param {type:"boolean"}
SCAN_TIMEOUT = "30m" #@param {type:"string"}
SAVED_STATE_PATH = "" #@param {type:"string"}
SAVED_ANALYSIS_PATH = "" #@param {type:"string"}
assert SOURCE_MODE in ("github", "saved", "resume")
analysis_output = analysis_work / "analysis-results.json"
assert SOURCE_MODE != "saved" or not analysis_output.exists(), "途中結果が既にあります。再開するならresume、新規分析ならセル1から別の作業フォルダを作ってください"

if SOURCE_MODE == "github":
    input_state = analysis_work / "scan-state.json"
    request_file = analysis_work / "scan-request.json"
    request_settings = {"repository": REPOSITORY_URL, "ref": REF, "nvd": USE_NVD}
    if request_file.exists():
        assert json.loads(request_file.read_text()) == request_settings, "対象・ref・NVD設定が変わりました。別スキャンはセル1から新しい作業フォルダで実行してください"
    else:
        assert not input_state.exists(), "取得設定がない既存stateです。SOURCE_MODE=savedで明示的に読み込んでください"
        request_file.write_text(json.dumps(request_settings), encoding="utf-8")
    existing_scan = json.loads(input_state.read_text(encoding="utf-8")) if input_state.exists() else None
    if existing_scan is None or not existing_scan["report"]["refresh_complete"]:
        scan_args = [str(scan_binary), "-state", str(input_state),
                     "-nvd=" + str(USE_NVD).lower(), "-timeout", SCAN_TIMEOUT]
        if existing_scan is None:
            scan_args += ["-repository", REPOSITORY_URL]
            if REF:
                scan_args += ["-ref", REF]
        else:
            scan_args += ["-monitor"]
        print("スキャン開始:", REPOSITORY_URL, "ref:", REF or "default branch", "NVD補完:", USE_NVD)
        scan_returncode = run_with_progress(scan_args, analysis_work / "scan-result.json")
        print("スキャン終了コード:", scan_returncode)
        assert scan_returncode == 0, "スキャン未完了です。直前のログとscan-result.jsonを確認し、復旧後に同じセルを再実行してください"
    else:
        print("照会完了済みのscan-state.jsonを再利用します。API再照会はしません。")
else:
    input_state = Path(SAVED_STATE_PATH) if SAVED_STATE_PATH else analysis_work / "uploaded-scan-state.json"
    if SAVED_STATE_PATH:
        assert input_state.is_file(), f"stateがありません: {input_state}"
    elif not input_state.exists():
        print("保存済みのanalysis-scan-state.jsonまたはscan-state.jsonを1つ選択してください。")
        uploaded_state = files.upload()
        assert len(uploaded_state) == 1, "元のscan-state.jsonを1つ選んでください（CSVやscan-result.jsonではありません）"
        input_state.write_bytes(next(iter(uploaded_state.values())))

saved_scan = json.loads(input_state.read_text(encoding="utf-8"))
assert all(k in saved_scan for k in ("schema_version", "profile", "report")), "repo-scanのstate形式ではありません"
assert saved_scan["report"]["refresh_complete"], "元スキャンの照会が未完了です。repo-scan -monitorで完了させてから分析してください"
analysis_state = analysis_work / "analysis-scan-state.json"
if analysis_state.exists():
    assert analysis_state.read_bytes() == input_state.read_bytes(), "解析用stateは固定です。別スキャンは新しい作業フォルダで実施してください"
else:
    shutil.copyfile(input_state, analysis_state)
plan_result = subprocess.run(
    [str(analysis_binary), "-state", str(analysis_state), "-plan-only"],
    cwd=analysis_repo, env=analysis_env, capture_output=True, text=True, timeout=300)
print(plan_result.stderr)
analysis_plan = json.loads(plan_result.stdout) if plan_result.stdout.strip() else {}
print("state:", input_state)
print("SHA:", saved_scan["profile"]["repository"]["commit_sha"])
print("抽出した構成要素:", len(saved_scan["profile"]["components"]))
print("OSV照会:", len(saved_scan["report"]["queries"]), "未照会:", len(saved_scan["report"]["unqueried"]))
print("スキャン網羅性:", saved_scan["report"]["status"])
print("照会完了:", saved_scan["report"]["refresh_complete"])
print("分析候補グループ:", analysis_plan.get("total_candidates"))
print("準備エラー:", analysis_plan.get("preparation_errors"))
for item in analysis_plan.get("entries", []):
    if item.get("error"):
        print(item["id"], item["error"])
assert plan_result.returncode == 0, "先に候補準備エラーを確認してください"
assert analysis_plan["total_candidates"] > 0, "一致候補が0件のためDeep Analysisを通すE2Eは実施できません"

# 復元対象は複製し、元ファイルとGoが管理するハッシュを書き換えません。
checkpoint_bytes = analysis_output.read_bytes() if analysis_output.exists() else None
if SOURCE_MODE == "resume":
    if SAVED_ANALYSIS_PATH:
        checkpoint_source = Path(SAVED_ANALYSIS_PATH)
        assert checkpoint_source.is_file(), f"途中結果がありません: {checkpoint_source}"
        checkpoint_bytes = checkpoint_source.read_bytes()
    elif checkpoint_bytes is None:
        print("このstateに対応するanalysis-results.jsonを1つ選択してください。")
        uploaded_analysis = files.upload()
        assert len(uploaded_analysis) == 1, "analysis-results.jsonを1つ選択してください"
        checkpoint_bytes = next(iter(uploaded_analysis.values()))
if checkpoint_bytes is not None:
    checkpoint = json.loads(checkpoint_bytes)
    assert isinstance(checkpoint, dict) and all(k in checkpoint for k in ("schema_version", "repository", "model", "base_url", "limit", "snapshot_hash", "entries")), "repo-analyzeの途中結果形式ではありません"
    assert isinstance(checkpoint["entries"], list), "途中結果のentriesが不正です"
    assert all(isinstance(checkpoint[k], str) and checkpoint[k].strip() for k in ("model", "base_url", "snapshot_hash")), "途中結果のモデル・接続先・ハッシュが不正です"
    assert type(checkpoint["limit"]) is int and checkpoint["limit"] >= 0, "途中結果のlimitが不正です"
    assert checkpoint["repository"] == saved_scan["profile"]["repository"], "stateと途中結果のリポジトリ／SHAが一致しません"
    if analysis_output.exists():
        assert analysis_output.read_bytes() == checkpoint_bytes, "別の途中結果を上書きできません。セル1から別の作業フォルダを作ってください"
    else:
        analysis_output.write_bytes(checkpoint_bytes)
    resume_settings = {k: checkpoint[k] for k in ("model", "base_url", "limit")}
    print("復元する分析設定:", resume_settings)
    print("state・入力・出力のハッシュは、セル4でGoがモデル呼び出し前に再検証します。")
analysis_ready = True
```

1候補はパッケージ1個やmatrix1行ではなく、明示的なID／aliasで関連づいたアドバイザリグループです。同じ問題のGHSAとRUSTSECを重複分析しません。複数バージョン・出典パスは根拠として残します。`status:incomplete` は未対応・バージョン不明などの網羅性の警告を含み、通信完了の `refresh_complete` とは区別します。

## 3. Ollamaを起動してモデルを準備（推論にGPUが有効）

既に `http://127.0.0.1:11434` で利用できればそのまま使います。未導入なら公式インストーラーを実行し、バックグラウンド起動します。再開時は保存済みのモデル名を使います。**外部Ollamaの接続先は自動適用しません。** `BASE_URL` を自分で確認・指定し、モデルはそのサーバー側で用意してください。再開する場合、前回と異なる接続先は拒否します。

**モデル一覧の取得成功だけでは準備完了にしません。** 本分析と同じ非ストリーミング・thinking無効の `/api/chat` で小さなJSON応答を1回生成し、モデルをロードします。このテストではリポジトリ情報を送りません。初期設定では接続待ち10秒・応答待ち180秒で打ち切り、自動再試行しません。失敗時は分析を開始せず、`ollama-preflight.json` に診断を保存します。

- `/api/ps` の対象モデルの `size_vram > 0`：`gpu_or_mixed`。GPUに配置された部分がありますが、全レイヤーのGPU実行を保証しません。
- `size_vram = 0`：`cpu`。初期設定の `REQUIRE_GPU=True` では停止します。
- モデル不在・取得失敗・情報欠落：`unknown`。CPUと断定せず、初期設定では停止します。

`nvidia-smi` にGPUが表示されても、OllamaがそのGPUを使っているとは限りません。CPU実行を明示的に許容する、または配置確認なしで進める場合のみ `REQUIRE_GPU=False` にして再実行してください。**短い推論テストの成功は、大きな候補入力や全591件の完了を保証しません。**

```python
#@title 3. Ollama準備・短い推論テスト・GPU配置の確認
import time, requests
model_ready = False
model_ready_for = None
analysis_returncode = None
assert globals().get("analysis_ready", False), "先にセル2を正常終了させてください"
MODEL = "qwen3:8b" #@param {type:"string"}
BASE_URL = "http://127.0.0.1:11434" #@param {type:"string"}
PREFLIGHT_TIMEOUT_SECONDS = 180 #@param {type:"integer"}
REQUIRE_GPU = True #@param {type:"boolean"}
assert type(PREFLIGHT_TIMEOUT_SECONDS) is int and PREFLIGHT_TIMEOUT_SECONDS > 0
assert type(REQUIRE_GPU) is bool
if resume_settings:
    MODEL = resume_settings["model"]
    assert BASE_URL == resume_settings["base_url"], f"再開には前回の接続先が必要です。確認してBASE_URLを指定してください: {resume_settings['base_url']}"

def ollama_ready():
    try:
        response = requests.get(BASE_URL + "/api/tags", timeout=5)
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError):
        return None

local_ollama = BASE_URL in ("http://127.0.0.1:11434", "http://localhost:11434")
if ollama_ready() is None:
    assert local_ollama, "指定したOllamaサーバーに接続できません"
    if not shutil.which("ollama"):
        subprocess.run(["apt-get", "update", "-qq"], check=True, timeout=300)
        subprocess.run(["apt-get", "install", "-y", "zstd"], check=True, timeout=300)
        installer = analysis_work / "ollama-install.sh"
        with urlopen("https://ollama.com/install.sh", timeout=60) as response:
            installer.write_bytes(response.read())
        subprocess.run(["sh", str(installer)], check=True, timeout=900)
    ollama_log = analysis_work / "ollama.log"
    with ollama_log.open("ab") as log:
        ollama_process = subprocess.Popen(
            [shutil.which("ollama"), "serve"],
            env=dict(os.environ, OLLAMA_HOST="127.0.0.1:11434"),
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    for _ in range(60):
        if ollama_ready() is not None:
            break
        if ollama_process.poll() is not None:
            raise RuntimeError(ollama_log.read_text(errors="replace"))
        time.sleep(1)
    assert ollama_ready() is not None, f"Ollama起動未完了。ログ: {ollama_log}"

# 一覧照合だけで省略タグを補い、チェックポイントに使うMODEL自体は変えません。
def ollama_model_key(name):
    if not isinstance(name, str) or not name:
        return None
    return name if ":" in name.rsplit("/", 1)[-1] else name + ":latest"

tags = ollama_ready()
assert tags is not None
if not any(ollama_model_key(m.get("name")) == ollama_model_key(MODEL) for m in tags["models"]):
    assert local_ollama and shutil.which("ollama"), "指定サーバー側でモデルを取得してください"
    subprocess.run([shutil.which("ollama"), "pull", MODEL],
                   env=dict(os.environ, OLLAMA_HOST="127.0.0.1:11434"), check=True, timeout=1800)
print("使用モデル:", MODEL, "接続先:", BASE_URL)
print("利用可能:", [m["name"] for m in ollama_ready()["models"]])
if local_ollama and shutil.which("nvidia-smi"):
    subprocess.run(["nvidia-smi"], check=False, timeout=30)

# /api/tags はダウンロード済みモデル一覧で、推論成功やGPU利用の証明ではありません。
def inspect_ollama_runtime():
    info = {"placement": "unknown"}
    try:
        response = requests.get(BASE_URL.rstrip("/") + "/api/ps", timeout=10, allow_redirects=False)
        if response.status_code != 200:
            raise ValueError(f"/api/ps HTTP {response.status_code}")
        models = response.json().get("models", [])
        item = next((m for m in models if ollama_model_key(MODEL) in (ollama_model_key(m.get("name")), ollama_model_key(m.get("model")))), None)
        if item is None:
            info["detail"] = "対象モデルのロード状態が見つかりません"
        else:
            info.update({k: item.get(k) for k in ("name", "model", "size", "size_vram", "context_length")})
            vram = item.get("size_vram")
            if type(vram) is int and vram >= 0:
                info["placement"] = "gpu_or_mixed" if vram > 0 else "cpu"
    except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
        info["detail"] = str(exc)
    return info

preflight = {"model": MODEL, "base_url": BASE_URL, "status": "running"}
preflight_error = None
started = time.monotonic()
print(f"短い推論テストを開始します（応答待ち上限 {PREFLIGHT_TIMEOUT_SECONDS}秒）。リポジトリ情報は送りません。", flush=True)
try:
    response = requests.post(
        BASE_URL.rstrip("/") + "/api/chat",
        json={"model": MODEL, "messages": [{"role": "user", "content": 'Return only {"ok":true}.'}],
              "stream": False, "think": False, "keep_alive": "15m",
              "format": {"type": "object", "properties": {"ok": {"type": "boolean", "enum": [True]}},
                         "required": ["ok"], "additionalProperties": False},
              "options": {"temperature": 0, "num_predict": 32}},
        timeout=(10, PREFLIGHT_TIMEOUT_SECONDS), allow_redirects=False)
    if response.status_code != 200:
        raise ValueError(f"/api/chat HTTP {response.status_code}: {response.text[:500]}")
    result = response.json()
    if result.get("error") or result.get("done") is not True or result.get("done_reason") == "length":
        raise ValueError("短い推論が完了しませんでした: " + str(result.get("error") or result.get("done_reason")))
    content = json.loads(result.get("message", {}).get("content", ""))
    if not isinstance(content, dict) or set(content) != {"ok"} or content["ok"] is not True:
        raise ValueError("推論テストのJSON応答が不正です")
    preflight["metrics"] = {k: result.get(k) for k in (
        "load_duration", "prompt_eval_count", "prompt_eval_duration", "eval_count", "eval_duration", "total_duration")}
    preflight["status"] = "passed"
except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
    preflight_error = exc
    preflight["status"] = "failed"
    preflight["error"] = str(exc)
except KeyboardInterrupt:
    preflight["status"] = "interrupted"
    raise
finally:
    preflight["elapsed_seconds"] = round(time.monotonic() - started, 2)
    try:
        preflight["runtime"] = inspect_ollama_runtime()
    except KeyboardInterrupt:
        preflight["status"] = "interrupted"
        preflight["runtime"] = {"placement": "unknown", "detail": "実行状態の確認中に中断されました"}
        raise
    finally:
        if preflight["status"] == "passed" and REQUIRE_GPU and preflight["runtime"]["placement"] != "gpu_or_mixed":
            preflight["status"] = "gpu_unverified"
        (analysis_work / "ollama-preflight.json").write_text(json.dumps(preflight, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(preflight, ensure_ascii=False, indent=2))

if preflight_error is not None:
    log_path = analysis_work / "ollama.log"
    if local_ollama and log_path.is_file():
        with log_path.open("rb") as log:
            log.seek(max(0, log_path.stat().st_size - 8000))
            print("Ollamaログ末尾:\n", log.read(8000).decode("utf-8", errors="replace"))
    raise RuntimeError("短い推論テストが失敗したため分析を開始しません。ollama-preflight.jsonとOllamaログを確認してください。タイムアウトだけではCPU/GPU・読み込み・待ち行列のどれが原因かは確定できません。") from preflight_error
if preflight["status"] == "gpu_unverified":
    raise RuntimeError("GPUへのモデル配置を確認できません。placement=cpuならCPU配置、unknownなら確認不能です。GPU環境を確認するか、遅いCPU推論を許容する場合だけREQUIRE_GPU=Falseでセル3を再実行してください。ランタイム変更前にセル6でバックアップしてください。")
metrics = preflight["metrics"]
count, duration = metrics.get("eval_count"), metrics.get("eval_duration")
if type(count) is int and type(duration) is int and duration > 0:
    print("短い応答の生成速度:", round(count / (duration / 1e9), 2), "tokens/s（本分析の所要時間の保証ではありません）")
print("推論テスト成功。GPU配置:", preflight["runtime"]["placement"], "。gpu_or_mixedは全レイヤーのGPU実行を保証しません。")
model_ready_for = (MODEL, BASE_URL)
model_ready = True
```

## 4. 全候補を分析・逐次保存（LLM使用）

**新規分析は `LIMIT=0` が全候補です。** まず少数だけ試す場合は明示的に変更できますが、残りは `not_selected` となり全件E2Eではありません。再開時は保存済みの件数上限を自動復元し、フォームの指定より優先します。モデル・件数上限を変える場合は別の `analysis_output` を使ってください。

同じセルの再実行で自動的に `-resume` が付き、保存済みScreening／Deep Analysisを再利用します。実行中のステージは、停止時点によって再試行されます。

**`REQUEST_TIMEOUT_MINUTES=0`（初期値）は、本分析の1リクエストごとのタイムアウトを無効にします。** 5分・15分で個別に打ち切ることはありません。正の整数を指定すると、その分数での制限を有効にできます。

**`ANALYSIS_TIMEOUT_HOURS=0`（初期値）は、本分析全体の時間制限も無効にします。** 正の整数に変更した場合だけ、その時間数での制限が有効になります。個別・全体とも0なら、時間経過を理由に本分析を自動停止しません。ただし手動停止、呼び出し元からのキャンセル、Colab自体のランタイム終了・利用時間制限、サーバー側の制限は残ります。応答が返らなければ手動停止するまで待つ可能性があります。

上限をなくしても処理自体が速くなるわけではありません。制限時間の変更だけなら保存済み結果の破棄や再スキャンは不要です。

セル3の短い推論テストには別の `PREFLIGHT_TIMEOUT_SECONDS`（初期値180秒）が残ります。本分析の個別・全体上限とは別です。旧ノートブックのGoコードは `-timeout 0` を拒否するので、この配布版に同梱した更新済みコードを使用してください。

```python
#@title 4. 分析開始／途中から再開
import signal
analysis_returncode = None
assert globals().get("analysis_ready", False), "先にセル2を正常終了させてください"
assert globals().get("model_ready", False), "先にセル3でモデルの準備を完了させてください"
assert globals().get("model_ready_for") == (globals().get("MODEL"), globals().get("BASE_URL")), "モデル・接続先が変わりました。先にセル3の推論テストをやり直してください"
LIMIT = 0 #@param {type:"integer"}
REQUEST_TIMEOUT_MINUTES = 0 #@param {type:"integer"}
ANALYSIS_TIMEOUT_HOURS = 0 #@param {type:"integer"}
assert type(REQUEST_TIMEOUT_MINUTES) is int and REQUEST_TIMEOUT_MINUTES >= 0
assert type(ANALYSIS_TIMEOUT_HOURS) is int and ANALYSIS_TIMEOUT_HOURS >= 0
if resume_settings:
    LIMIT = resume_settings["limit"]
assert type(LIMIT) is int and LIMIT >= 0
analysis_output = analysis_work / "analysis-results.json"
analysis_args = [str(analysis_binary), "-state", str(analysis_state),
                 "-output", str(analysis_output), "-model", MODEL,
                 "-base-url", BASE_URL, "-limit", str(LIMIT),
                 "-request-timeout", f"{REQUEST_TIMEOUT_MINUTES}m",
                 "-timeout", f"{ANALYSIS_TIMEOUT_HOURS}h", "-require-deep"]
if analysis_output.exists():
    analysis_args += ["-resume"]

analysis_returncode = None
request_timeout_label = "なし" if REQUEST_TIMEOUT_MINUTES == 0 else f"{REQUEST_TIMEOUT_MINUTES}分"
analysis_timeout_label = "なし" if ANALYSIS_TIMEOUT_HOURS == 0 else f"{ANALYSIS_TIMEOUT_HOURS}時間"
print(f"分析開始: 1リクエスト上限={request_timeout_label}、今回の実行上限={analysis_timeout_label}。手動停止可能で、完了済みの段階は保存されます。", flush=True)
try:
    analysis_returncode = run_with_progress(analysis_args)
except KeyboardInterrupt:
    print("\n中断しました。完了済みの処理は保存されています。同じセルで再開できます。")
print("終了コード:", analysis_returncode)
print("途中結果／最終結果:", analysis_output)
```

進捗は例えば `candidate 1/120 CVE-...: screening` → `...: analysis` と表示されます。候補単位のScreening／Deep Analysis失敗はエラーとして保存し、後続候補の処理を続けます。最後に候補エラーを集約し、1件でもあれば終了コード1になります。後続候補の成功結果も保存されます。ただしキャンセルとチェックポイント保存失敗は即座に停止します。未処理は `pending`、失敗済みは `errors` として区別します。APIやモデルを復旧して再実行してください。

Screeningのモデル通信（MODEL WIRE）では `advisory_evidence_ids` と `repository_evidence_ids` を分離し、それぞれ出典側／リポジトリ側の `EVD-...` 根拠IDだけを応答スキーマで許可します。Deep Analysisの各主張は従来どおり `evidence_ids` を使います。内部・保存済みScreening結果も従来の `evidence_ids` を維持し、旧チェックポイントと互換です。保存形式の手動変換やスナップショットの再スキャンは不要です。同じstate・モデル・接続先・limitで再開すると、保存済み成功ステージは再利用され、失敗／未処理だけが再試行されます。未知のID引用やScreeningの必要な根拠種別の不足は、同じ材料から**各ステージ最大1回だけ再生成**します。訂正成功時は `generation.citation_retries=1` が保存され、トークン数・処理時間は両試行の合計です。通信・JSON構造のエラーを無制限に再試行したり、GHSA番号を適当な根拠IDへ置換したりはしません。訂正後も検証できなければ候補エラーとして保存し、後続候補へ進みます。

`-require-deep` は **分析済みFeedが1件もなければ終了1** にします。Screeningを強制的に `related` に書き換える機能ではありません。`unknown`／`possibly_related` はScreeningのみのFeed、`unrelated` は除外となります。

### `Client.Timeout exceeded while awaiting headers` が出た場合

非ストリーミングの推論は、モデル読み込み・入力処理・生成中に応答ヘッダーを返さないことがあります。これはOSV照会や引用ID検証のエラーではなく、モデル呼び出しの期限切れです。CPU／GPU、メモリ不足、長い入力、Ollamaの待ち行列のどれが原因かは、この文字列だけでは特定できません。

1. 同じランタイムならセル3の推論テストと `runtime`・読み込み時間を確認します。失敗時はOllamaログを確認し、むやみに全候補を再実行しないでください。
2. GPU配置を確認でき、短い推論が成功するなら、必要に応じてセル4の待ち時間を調整し、同じモデル・出力へ再開します。モデルを小さく変更する場合は、同じ途中結果へ混ぜず別の分析出力を使ってください。
3. ランタイムをGPUへ変更する、または新しいノートブックへ移る前には、セル6でstateと途中結果を保存します。新しいランタイムではセル2の `resume` で復元してください。

確認した公式API仕様: [Chat API](https://docs.ollama.com/api/chat)、[実行中モデルとVRAM使用量](https://docs.ollama.com/api/ps)。

## 5. E2E到達点・Feed・エラーを確認（CPU）

初期値 `STRICT_E2E=False` は診断用です。候補エラーや中断でも表示・CSV出力を行い、それだけではassertしません。Deep Feedが存在しても、終了コードが非0／未確認、未完了、エラー、未選択があれば全候補E2E成功とは表示しません。`STRICT_E2E=True` は全診断の出力後に全候補E2E条件をassertします。元スキャンの網羅性は別途確認してください。

```python
#@title 5. 結果・エラー・Deep Analysisへの到達確認
STRICT_E2E = False #@param {type:"boolean"}
import pandas as pd
assert globals().get("analysis_setup_ready", False), "先にセル1から実行してください"
assert analysis_output.is_file(), "解析結果がまだ保存されていません。直前のエラーを確認してください"
analysis_data = json.loads(analysis_output.read_text(encoding="utf-8"))
print({k: analysis_data[k] for k in (
    "total_candidates", "selected_candidates", "screened", "analyzed",
    "screening_only", "excluded", "errors", "pending", "not_selected",
    "selected_complete", "complete", "scan_refresh_complete", "scan_status")})
analysis_rows = [{
    "id": e["id"], "advisory_kinds": ", ".join(e["advisory_kinds"]),
    "status": e["status"], "stage": e["stage"], "error": e.get("error", ""),
    "relevance": (e.get("screening") or {}).get("result", {}).get("relevance"),
    "deep_completed": e.get("analysis") is not None,
    "feed_status": (e.get("feed") or {}).get("status"),
} for e in analysis_data["entries"]]
analysis_df = pd.DataFrame(analysis_rows)
display(analysis_df)
analysis_df.to_csv(analysis_work / "analysis-matrix.csv", index=False)
feeds = [e["feed"] for e in analysis_data["entries"] if e.get("feed")]
deep_feeds = [f for f in feeds if f["status"] == "analyzed"]
print("Feed件数:", len(feeds), "Deep Analysis済みFeed:", len(deep_feeds))
failed_entries = [{k: e.get(k) for k in ("id", "status", "stage", "error")} for e in analysis_data["entries"] if e.get("error")]
if failed_entries:
    print("エラー先頭3件:", json.dumps(failed_entries[:3], ensure_ascii=False, indent=2))
    if any("deadline exceeded" in str(e.get("error", "")) or "Client.Timeout" in str(e.get("error", "")) for e in failed_entries):
        print("期限切れが記録されています。REQUEST_TIMEOUT_MINUTES=0、ANALYSIS_TIMEOUT_HOURS=0なら本分析の個別・全体タイマーは無効です。過去の保存エラー、呼び出し元の期限やサーバー側の制限もあり得るので実行ログを確認してください。GPU配置・短い推論テストと本分析の入力処理は別です。繰り返す場合はOllamaログの確認が必要です。")
        preflight_path = analysis_work / "ollama-preflight.json"
        if preflight_path.is_file():
            print("直近の推論テスト:", preflight_path.read_text(encoding="utf-8"))
if deep_feeds:
    print(json.dumps(deep_feeds[0], ensure_ascii=False, indent=2))
exitcode = globals().get("analysis_returncode")
print("終了コード:", exitcode, "（Noneは中断／未実行などで終了コード未確認）")
print(f"処理状況: pending={analysis_data['pending']} errors={analysis_data['errors']} selected_complete={analysis_data['selected_complete']} complete={analysis_data['complete']}")
if analysis_data["pending"]:
    print("未処理候補があります。保存済み結果から再開してください。")
if analysis_data["errors"] or failed_entries:
    print("候補エラーがあります。後続候補の成功とは別に、失敗した段階の再試行が必要です。")
print("Deep Analysis→Feedの到達:", "あり" if deep_feeds else "未確認（Screeningのみ／除外は正常な分岐です）")
if analysis_data["not_selected"] > 0:
    print("注意: 件数制限による未選択候補があります。全候補完了ではありません。")
e2e_success = (exitcode == 0 and analysis_data["selected_complete"]
               and analysis_data["complete"] and analysis_data["pending"] == 0
               and analysis_data["errors"] == 0 and not failed_entries
               and analysis_data["not_selected"] == 0 and bool(deep_feeds))
if e2e_success:
    print("全候補の処理が完了し、Deep Analysis→FeedまでのE2E成功を確認しました。")
else:
    print("全候補のE2E成功は未確認です。終了コード・未処理・エラー・未選択・Deep Feedを個別に確認してください。")
if not analysis_data["scan_refresh_complete"] or analysis_data["scan_status"] != "complete":
    print("注意: 元スキャンに未照会・警告等があります。リポジトリ全体の網羅性は別途確認してください。")
if STRICT_E2E:
    assert e2e_success, "全候補のE2E条件を満たしていません。上の診断を確認してください"
```

`advisory_kinds: unmaintained` は保守停止の通知であり、悪用可能な脆弱性の確定ではありません。出典側が種別を示していないものは `unknown`。関数・OS・アーキテクチャの条件は出典の情報としてLLMに渡しますが、対象リポジトリがそれらを使用・実行していることの証明にはしません。

このDeep Analysisは**根拠付きのLLM説明**です。全言語のソース解析、呼出グラフ、PoC実行、悪用可能性の実証ではありません。影響度の確定に必要な情報は `missing_information` と `applicability` に残します。

## 6. 結果をダウンロード（任意）

stateには依存情報・出典の原文、分析結果にはそれらの一部とモデル出力が含まれます。共有範囲に注意してください。Colabランタイム終了前にバックアップしておくと、別ランタイムでも再開できます。

```python
#@title 6. state・途中結果のバックアップ（中断・エラー後も実行可能）
assert globals().get("analysis_setup_ready", False), "先にセル1から実行してください"
backup_paths = [analysis_work / "analysis-scan-state.json", analysis_work / "analysis-results.json", analysis_work / "ollama-preflight.json"]
if not backup_paths[0].is_file():
    backup_paths[0] = analysis_work / "scan-state.json"
for path in backup_paths:
    if path.is_file():
        files.download(str(path))
    else:
        print("まだ作成されていません:", path.name)
```

別ランタイムからの再開では、セル1を実行し、セル2で `SOURCE_MODE="resume"` を選び、保存したstateと `analysis-results.json` を順番にアップロードしてください。モデル名・件数上限は途中結果から復元します。接続先はセル3で確認・指定し、セル4で `-resume` により未完了の段階だけを再開します。モデル名が同じでもモデル自体が更新された場合まで自動検知するものではありません。stateや入力・出力のチェックサムは取り違え／破損の検出用であり、署名や生成内容の真実性の証明ではありません。

## コマンドラインで使う場合

```sh
# API呼び出しなしで準備を確認
go run ./cmd/repo-analyze -state scan-state.json -plan-only

# 全候補、Deep Analysisに到達したかまで検査
go run ./cmd/repo-analyze -state scan-state.json \
  -output analysis-results.json -model qwen3:8b -require-deep

# 同じ出力へ再開（個別リクエスト・全体とも時間制限なし）
go run ./cmd/repo-analyze -state scan-state.json \
  -output analysis-results.json -model qwen3:8b -require-deep -resume \
  -request-timeout 0 -timeout 0
```

- `-output` はstateとは別ファイル。各ステージの完了時に0600一時ファイルから置換します。同じ出力への同時実行はしないでください。
- `-resume` はstate／モデル名／接続先／limit／入力の一致と保存済み出力の検証後に実行。完了済みの推論は再呼び出しません。Feedの事実情報は元入力から再構築します。
- `-request-timeout 0` はHTTPクライアントの個別タイマー、`-timeout 0` はコマンド全体のタイマーを無効にします。CLIで省略した場合の既定値は互換性のため個別5分・全体2時間のままです。ノートブックは両方0を明示します。負の値は拒否し、手動停止・呼び出し元のキャンセルは維持します。
- 元stateは更新しません。監視でstateを更新した場合は別の解析出力を使ってください。
- 原文や出典が大きすぎて既存LLM入力制限を超える候補は `preparation_error` で明示。根拠を黙って削ったり制限を無効化したりしません。
- 終了0でも全候補がDeep Analysisされたとは限りません。`screening_only`／`excluded` は通常の分岐です。終了1の具体的理由は標準エラーと `entries[].error` を確認してください。

## 開発時の検証

Markdownからノートブックを再生成できます。通常版はソース非同梱、配布版は検証済みソースZIPを同梱します。

```sh
python3 -B docs/build_colab_notebook.py --output docs/colab-deep-analysis.ipynb
python3 -B docs/build_colab_notebook.py --source-zip ../vulns-news-colab-typed-citations-20260926.zip --output ../colab-github-to-feed-typed-citations-20260926.ipynb
```

```sh
go test ./...
go vet ./...
go test -race ./cmd/repo-analyze ./src/scananalyze ./src/processor ./src/pipeline ./src/feed -count=1
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s docs -p 'test_colab*.py'
```

HTTPモック経由で、保存済みOSV結果 → 実LLMクライアント → Screening → Deep Analysis → Feedの接続、CVEなしのID、重複候補の統合、モデル応答の検証、失敗・中断・再開・入力の取り違え拒否をテストします。実モデルの回答品質・速度・実GPUでのE2EはColab側で検証してください。
