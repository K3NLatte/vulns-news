r"""Build the six-cell Colab notebook using only the Python standard library.

Examples (from the project root)::

    python3 docs/build_colab_notebook.py --output docs/colab-deep-analysis.ipynb
    python3 docs/build_colab_notebook.py --output ../standalone.ipynb \
        --source-zip ../vulns-news-colab-citation-fix-20260926.zip

Markdown is the runtime source of truth. The builder never executes its cells or
rewrites their setup/mode logic. Bundled exports only prepend the two assignments
consumed by the Markdown's globals().get("_BUNDLED_SOURCE_B64") setup hook, which
must verify _BUNDLED_SOURCE_SHA256 before extraction. Archive checks establish
safe structure and integrity, not authenticity or correctness of the Go code:
only bundle source you trust. Building is offline; running Colab can use network.
"""

import argparse
import ast
import base64
import hashlib
import json
import re
import stat
import zlib
from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZipFile

DEFAULT_MARKDOWN = Path(__file__).resolve().with_name("colab-deep-analysis.md")
EXPECTED_CODE_CELLS = 6
REQUIRED_SOURCE_FILES = frozenset({
    "vulns-news/go.mod",
    "vulns-news/cmd/repo-analyze/main.go",
    "vulns-news/cmd/repo-scan/main.go",
    "vulns-news/src/processor/citations.go",
    "vulns-news/src/processor/schema.go",
    "vulns-news/src/processor/types.go",
})
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})([^\r\n]*)(?:\r?\n)?$")

BUNDLED_NOTICE = """**修正版コード同梱：ソースZIPの別アップロードは不要です。**
新しいColabランタイムでセル1から順番に実行してください。以前の変数や更新セルは不要です。
セル1で同梱ソースのSHA-256を照合してビルドします。以下のソースZIPアップロード手順は
コード非同梱版だけの代替手順です。Go・依存パッケージ・モデルの取得やAPI照会には
通信が必要です。オフライン実行ではありません。共有時は同梱コードも共有されます。

途中から再開する場合は、セル2で `SOURCE_MODE = 'resume'` を選び、保存済みの
stateと分析途中結果をアップロードしてください。詳しくはセル2の説明に従ってください。
SHA-256は破損検出用で、配布元の署名ではありません。信頼するノートブックだけを実行してください。
"""
UPLOAD_NOTICE = """**開発用・コード非同梱版：ソースZIPのアップロードが必要です。**
セル1で信頼できる引用ID修正版のソースZIPを選択してください。新しいランタイムでも実行できます。
セル2で新規スキャン／保存済みデータからの復元を選びます。`--source-zip` で生成した
配布用のソース同梱版では、ソースZIPの別アップロードは不要です。
"""


def validate_python(source, index):
    """Reject empty/comment-only or invalid cells without executing them."""
    filename = f"<markdown>:cell{index}"
    try:
        tree = ast.parse(source, filename=filename)
        if not tree.body:
            raise ValueError(f"Python cell {index} is empty")
        compile(tree, filename, "exec")
    except (SyntaxError, TypeError) as exc:
        raise ValueError(f"Invalid Python cell {index}: {exc}") from exc


def markdown_cells(markdown):
    """Split fenced Python into cells, retaining other fenced blocks as prose.

    A fence state machine avoids treating examples inside non-Python fences as
    executable cells. Python source, including its final newline, is untouched.
    """
    cells = []
    prose = []
    code = []
    fence = None
    is_python = False
    code_count = 0
    for line in markdown.splitlines(keepends=True):
        match = FENCE.fullmatch(line)
        if fence is None:
            if match:
                fence = match[1]
                is_python = match[2].strip() == "python"
                if is_python:
                    if "".join(prose).strip():
                        cells.append(("markdown", "".join(prose)))
                    prose = []
                    code = []
                    continue
            prose.append(line)
            continue

        closes = (match is not None and not match[2].strip()
                  and match[1][0] == fence[0] and len(match[1]) >= len(fence))
        if is_python:
            if closes:
                code_count += 1
                source = "".join(code)
                validate_python(source, code_count)
                cells.append(("code", source))
            else:
                code.append(line)
        else:
            prose.append(line)
        if closes:
            fence = None
            is_python = False

    if fence is not None:
        raise ValueError("Unclosed Markdown fence (Python or prose)")
    if "".join(prose).strip():
        cells.append(("markdown", "".join(prose)))
    if code_count != EXPECTED_CODE_CELLS:
        raise ValueError(f"Expected {EXPECTED_CODE_CELLS} Python cells, found {code_count}")
    return cells


def validate_source_zip(payload):
    """Check all members and CRCs in memory; never extract or execute source."""
    try:
        with ZipFile(BytesIO(payload)) as archive:
            entries = {}
            for info in archive.infolist():
                # orig_filename retains NULs that ZipInfo.filename truncates.
                name = info.orig_filename
                path = name[:-1] if info.is_dir() else name
                parts = path.split("/")
                if (not path or "\x00" in name or "\\" in name or ":" in name
                        or any(part in ("", ".", "..") for part in parts)):
                    raise ValueError(f"Unsafe source ZIP path: {name!r}")
                if parts[0] != "vulns-news" or (len(parts) == 1 and not info.is_dir()):
                    raise ValueError(f"Source ZIP must have one vulns-news/ root: {name!r}")
                if path in entries:
                    raise ValueError(f"Duplicate source ZIP path: {path!r}")
                mode = stat.S_IFMT(info.external_attr >> 16)
                if mode == stat.S_IFLNK:
                    raise ValueError(f"Source ZIP symlink is not allowed: {name!r}")
                if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError(f"Source ZIP special file is not allowed: {name!r}")
                if ((mode == stat.S_IFDIR and not info.is_dir())
                        or (mode == stat.S_IFREG and info.is_dir())
                        or (info.external_attr & 0x10 and not info.is_dir())
                        or (info.is_dir() and info.file_size != 0)):
                    raise ValueError(f"Inconsistent source ZIP directory: {name!r}")
                if info.flag_bits & 1:
                    raise ValueError(f"Encrypted source ZIP member is not allowed: {name!r}")
                entries[path] = info

            for path in entries:
                parts = path.split("/")
                for length in range(1, len(parts)):
                    parent = entries.get("/".join(parts[:length]))
                    if parent is not None and not parent.is_dir():
                        raise ValueError(f"Source ZIP file/directory conflict: {path!r}")
            missing = sorted(name for name in REQUIRED_SOURCE_FILES
                             if name not in entries or entries[name].is_dir()
                             or entries[name].file_size == 0)
            if missing:
                raise ValueError("Source ZIP missing nonempty required files: " + ", ".join(missing))
            corrupt = archive.testzip()
            if corrupt is not None:
                raise ValueError(f"Source ZIP CRC/header check failed: {corrupt!r}")
    except (BadZipFile, RuntimeError, NotImplementedError, EOFError, OSError, zlib.error) as exc:
        raise ValueError(f"Invalid source ZIP: {exc}") from exc


def build_notebook(markdown, *, output_name, source_zip=None):
    """Return an nbformat 4.5 dictionary, optionally embedding validated ZIP bytes."""
    cells = markdown_cells(markdown)
    if source_zip is not None:
        validate_source_zip(source_zip)
        prefix = (
            f'_BUNDLED_SOURCE_B64 = "{base64.b64encode(source_zip).decode("ascii")}"\n'
            f'_BUNDLED_SOURCE_SHA256 = "{hashlib.sha256(source_zip).hexdigest()}"\n'
        )
        first_code = next(index for index, (kind, _) in enumerate(cells) if kind == "code")
        source = prefix + cells[first_code][1]
        validate_python(source, 1)
        cells[first_code] = ("code", source)
        notice = BUNDLED_NOTICE
    else:
        notice = UPLOAD_NOTICE
    if cells[0][0] == "markdown":
        cells[0] = ("markdown", notice + "\n" + cells[0][1])
    else:
        cells.insert(0, ("markdown", notice))

    notebook_cells = []
    for index, (kind, source) in enumerate(cells):
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:16]
        cell_id = f"{kind}-{index}-{digest}"
        cell = {
            "cell_type": kind,
            "id": cell_id,
            "metadata": {"id": cell_id},
            "source": source.splitlines(keepends=True),
        }
        if kind == "code":
            cell["metadata"]["cellView"] = "form"
            cell["execution_count"] = None
            cell["outputs"] = []
        notebook_cells.append(cell)
    return {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {
            "colab": {"name": Path(output_name).name, "provenance": []},
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python"},
        },
        "cells": notebook_cells,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MARKDOWN,
                        help="Markdown input (default: colab-deep-analysis.md beside this script)")
    parser.add_argument("--output", type=Path, required=True, help="Destination .ipynb path (required)")
    parser.add_argument("--source-zip", type=Path, help="Trusted citation-fix source ZIP to embed (optional)")
    args = parser.parse_args(argv)
    try:
        inputs = [args.markdown] + ([args.source_zip] if args.source_zip is not None else [])
        if any(args.output.resolve() == path.resolve() for path in inputs):
            raise ValueError("Output must not overwrite the Markdown or source ZIP input")
        markdown = args.markdown.read_text(encoding="utf-8")
        source_zip = args.source_zip.read_bytes() if args.source_zip is not None else None
        notebook = build_notebook(markdown, output_name=args.output.name, source_zip=source_zip)
        # Validate everything before touching the destination. Explicit LF keeps
        # identical inputs byte-for-byte reproducible across host platforms.
        args.output.write_bytes((json.dumps(notebook, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
