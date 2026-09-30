# Colab: 引用IDエラーからの再開

`unknown evidence ID GHSA-c9f4-xj24-8jqx` は、モデルが根拠用の `EVD-...` IDの代わりにアドバイザリIDを引用したScreening検証エラーです。**失敗は1件、残り590件は未処理の `pending`** で、591件すべてが失敗したわけではありません。このエラーはGPU不足やOSV取得失敗を示すものではありません。

修正版はリクエストごとの根拠IDをenumで制約し、Screening／Deep Analysisの引用不備について各ステージ最大1回だけ訂正を試みます。厳格な検証は維持し、state形式・Prepared入力ハッシュ・既存チェックサムは変更しません。実モデルの応答や全件成功を保証するものではありません。

訂正後に成功した結果の `generation` には `citation_retries=1` が記録され、トークン数・処理時間は初回と訂正試行の合計になります。訂正なしではこのフィールドは省略されます。

## 更新セル（既存ランタイムで実行）

- 実行中の分析を停止してから、下のセルを追加して実行してください。**セル1・2・3の再実行、ランタイム変更、リポジトリ再スキャンは不要です。**
- **新しいフルソースZIP `vulns-news-colab-citation-fix-20260926.zip`** を1つ選択します。旧ZIPの再アップロード／改名では修正されません。信頼できる配布元のものだけを使ってください。ZIP内は `vulns-news/go.mod`、`vulns-news/cmd/...` の構成です。再アップロード時にColabが付ける ` (1)`、` (2)` などの数値接尾辞は許容します。
- ソースは別の一時ディレクトリへ展開します。既存の作業フォルダ・scan state・分析用state・結果・`MODEL`・`BASE_URL`・`LIMIT` は保持します。`repo-scan` は更新・実行しません。Goの依存／ツールチェーン取得には通信が発生する場合がありますが、このセルはLLMを呼びません。
- 変数／ファイル不足やビルド失敗時は停止します。旧作業データは削除せず、ビルド失敗時は旧バイナリも残します。エラーを解消してこの更新セルを再実行するまで、セル4へ進まないでください。

```python
from google.colab import files
from pathlib import Path
from io import BytesIO
from zipfile import ZipFile
import os, re, stat, subprocess, tempfile

# 更新失敗後に、旧バイナリで分析を再開させない。
analysis_ready = False
analysis_returncode = None

def _install_citation_fix():
    required = (
        "bootstrap", "analysis_env", "analysis_work", "analysis_repo",
        "analysis_binary", "analysis_state", "analysis_output", "input_state",
        "MODEL", "BASE_URL", "LIMIT", "run_with_progress",
    )
    missing = [name for name in required if name not in globals() or globals()[name] is None]
    if missing:
        raise RuntimeError("既存ランタイムの変数が不足しています: " + ", ".join(missing))
    for name in ("analysis_work", "analysis_repo"):
        value = globals()[name]
        if not isinstance(value, (str, Path)) or not Path(value).is_dir():
            raise RuntimeError(f"既存ディレクトリがありません: {name}={value!r}")
    for name in ("bootstrap", "analysis_binary", "analysis_state", "analysis_output", "input_state"):
        value = globals()[name]
        if not isinstance(value, (str, Path)) or not Path(value).is_file():
            raise RuntimeError(f"既存ファイルがありません: {name}={value!r}")
    if not os.access(bootstrap, os.X_OK):
        raise RuntimeError("既存bootstrapを実行できません")
    if not isinstance(analysis_env, dict) or not analysis_env or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in analysis_env.items()
    ):
        raise RuntimeError("既存analysis_envが不正です")
    if not callable(run_with_progress):
        raise RuntimeError("既存run_with_progressがありません")
    if not all(isinstance(value, str) and value.strip() for value in (MODEL, BASE_URL)):
        raise RuntimeError("既存MODEL／BASE_URLが不正です")
    if type(LIMIT) is not int or LIMIT < 0:
        raise RuntimeError("既存LIMITが不正です")

    expected = "vulns-news-colab-citation-fix-20260926.zip"
    uploaded = files.upload()
    uploaded_name = next(iter(uploaded), "")
    # Colabの同名アップロードによる数値接尾辞だけを許可する。
    allowed_name = re.escape(expected[:-4]) + r"(?: \([1-9][0-9]*\))?\.zip"
    if len(uploaded) != 1 or not re.fullmatch(allowed_name, uploaded_name):
        raise RuntimeError(f"新しいフルソースZIP {expected} を1つ選んでください")
    source_dir = Path(tempfile.mkdtemp(
        prefix="vulns-news-citation-source-", dir=Path(analysis_work).parent,
    ))
    with ZipFile(BytesIO(uploaded[uploaded_name])) as archive:
        # 展開前に全エントリを検査し、別の場所への書き込みを防ぐ。
        for member in archive.infolist():
            target = (source_dir / member.filename).resolve()
            if not target.is_relative_to(source_dir.resolve()) or stat.S_ISLNK(member.external_attr >> 16):
                raise RuntimeError(f"安全に展開できないZIPエントリ: {member.filename}")
        archive.extractall(source_dir)
    new_repo = source_dir / "vulns-news"
    for relative in ("go.mod", "go.sum", "cmd/repo-analyze/main.go", "cmd/repo-scan/main.go"):
        if not (new_repo / relative).is_file():
            raise RuntimeError(f"フルソースZIPではありません: {relative} が不足")
    if not (new_repo / "src").is_dir():
        raise RuntimeError("フルソースZIPではありません: src が不足")

    # 同じファイルシステム上でビルドし、成功後にだけ原子的に置換する。
    with tempfile.TemporaryDirectory(prefix=".citation-build-", dir=Path(analysis_binary).parent) as build_dir:
        staged_binary = Path(build_dir) / "repo-analyze"
        subprocess.run(
            [str(bootstrap), "build", "-o", str(staged_binary), "./cmd/repo-analyze"],
            cwd=new_repo, env=analysis_env, check=True, timeout=600,
        )
        if not staged_binary.is_file() or staged_binary.stat().st_size == 0 or not os.access(staged_binary, os.X_OK):
            raise RuntimeError("実行可能なバイナリが生成されませんでした。旧バイナリを保持します")
        os.replace(staged_binary, analysis_binary)
    return new_repo

analysis_repo = _install_citation_fix()
analysis_ready = True
print("更新済みソース:", analysis_repo)
print("保持したstate:", analysis_state, "結果:", analysis_output)
print("MODEL:", MODEL, "BASE_URL:", BASE_URL, "LIMIT:", LIMIT)
print("更新完了。既存セル4 → セル5の順に再実行してください（分析はまだ開始していません）。")
```

## 再開と確認

**既存セル4 → セル5** の順に再実行してください。セル4内の `LIMIT` と `analysis_output` の代入が現在の設定と同じことを確認してください（独自の件数上限・出力先を既定値に戻さない）。既存結果があるためセル4は自動で `-resume` を付け、保存済みの成功結果を再利用して失敗／未処理候補を再試行します。stateや結果JSONのID・ハッシュ・チェックサムを手で書き換える必要はありません。

セル5でエラー・`pending`・Deep Analysis済みFeedを確認します。再度止まった場合は直前のログと候補のエラーを確認してください。厳格な検証は残るため、更新成功だけではLLM分析の成功やE2E到達を意味しません。

オフライン検証: `python3 -B -m unittest discover -s docs -p 'test_colab_citation_recovery.py' -v`（アップロードとビルドをモック。実Goビルド／実モデルの検証ではありません）。
