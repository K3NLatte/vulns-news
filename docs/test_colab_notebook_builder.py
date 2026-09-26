"""Offline stdlib tests; no notebook runtime, Go build, or network is executed.

CLI tests write only disposable fixture notebooks in temporary directories.
The checked-in notebook and source Markdown are never modified.
"""

import ast
import base64
import hashlib
import importlib.util
import json
import re
import stat
import struct
import tempfile
import unittest
import warnings
from contextlib import redirect_stderr
from io import BytesIO, StringIO
from pathlib import Path
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

DOCS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("build_colab_notebook", DOCS / "build_colab_notebook.py")
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)

SOURCE_FILES = {
    "vulns-news/go.mod": b"module vulns-news\n",
    "vulns-news/cmd/repo-analyze/main.go": b"package main\n",
    "vulns-news/cmd/repo-scan/main.go": b"package main\n",
    "vulns-news/src/processor/citations.go": b"package processor\n",
    "vulns-news/src/processor/schema.go": b"package processor\n",
    "vulns-news/src/processor/types.go": b"package processor\n",
}
FIXTURE_CELLS = [
    (
        "import base64, hashlib\n"
        "source = globals().get('_BUNDLED_SOURCE_B64')\n"
        "if source is not None:\n"
        "    payload = base64.b64decode(source, validate=True)\n"
        "    assert hashlib.sha256(payload).hexdigest() == globals().get('_BUNDLED_SOURCE_SHA256')\n"
    ),
    'SOURCE_MODE = "fresh"\n',
    'model = "fixture"\n',
    "result = 42\n",
    "print(result)\n",
    "print('done')\n",
]


def markdown_fixture(cells=None):
    cells = FIXTURE_CELLS if cells is None else cells
    return "# Fixture 日本語\n\n" + "".join(
        f"## Step {index}\n\n```python\n{source}```\n\n"
        for index, source in enumerate(cells, 1)
    ) + "## Shell reference\n\n```sh\necho not-a-code-cell\n```\n"


def zip_info(name, mode):
    info = ZipInfo(name, date_time=(2026, 9, 26, 0, 0, 0))
    info.create_system = 3
    info.external_attr = mode << 16
    return info


def source_zip(entries=None, compression=ZIP_STORED):
    stream = BytesIO()
    with ZipFile(stream, "w") as archive:
        for name, content in (SOURCE_FILES.items() if entries is None else entries):
            info = name if isinstance(name, ZipInfo) else zip_info(
                name, (stat.S_IFDIR | 0o755) if name.endswith("/") else (stat.S_IFREG | 0o644)
            )
            archive.writestr(info, content, compress_type=compression)
    return stream.getvalue()


def code_sources(notebook):
    return ["".join(cell["source"]) for cell in notebook["cells"] if cell["cell_type"] == "code"]


def build(markdown=None, payload=None, name="fixture.ipynb"):
    return builder.build_notebook(
        markdown_fixture() if markdown is None else markdown,
        output_name=name, source_zip=payload,
    )


class NotebookBuilderTests(unittest.TestCase):
    def test_real_markdown_has_six_compilable_cells_and_exact_unbundled_parity(self):
        markdown = (DOCS / "colab-deep-analysis.md").read_text(encoding="utf-8")
        # Deliberately match the existing parity test, not the builder's parser.
        expected = re.findall(r"^```python[ \t]*\n(.*?)^```[ \t]*$", markdown, re.MULTILINE | re.DOTALL)
        self.assertEqual(len(expected), 6)
        notebook = build(markdown)
        self.assertEqual(code_sources(notebook), expected)
        for index, source in enumerate(code_sources(notebook), 1):
            compile(source, f"markdown:cell{index}", "exec")
        bundled = code_sources(build(markdown, source_zip()))
        self.assertEqual(len(bundled), 6)
        self.assertEqual("".join(bundled[0].splitlines(keepends=True)[2:]), expected[0])
        self.assertEqual(bundled[1:], expected[1:])
        for source in bundled:
            compile(source, "bundled-cell", "exec")

    def test_only_first_code_cell_gets_exact_roundtrip_assignments(self):
        payload = source_zip()
        notebook = build(payload=payload)
        sources = code_sources(notebook)
        self.assertEqual(len(sources), 6)
        expected_prefix = (
            f'_BUNDLED_SOURCE_B64 = "{base64.b64encode(payload).decode("ascii")}"\n'
            f'_BUNDLED_SOURCE_SHA256 = "{hashlib.sha256(payload).hexdigest()}"\n'
        )
        self.assertEqual(sources[0], expected_prefix + FIXTURE_CELLS[0])
        self.assertEqual(sources[1:], FIXTURE_CELLS[1:])
        assignments = {}
        for node in ast.parse(sources[0]).body[:2]:
            assert isinstance(node, ast.Assign)
            self.assertEqual(len(node.targets), 1)
            target = node.targets[0]
            assert isinstance(target, ast.Name)
            assignments[target.id] = ast.literal_eval(node.value)
        self.assertEqual(list(assignments), ["_BUNDLED_SOURCE_B64", "_BUNDLED_SOURCE_SHA256"])
        encoded, digest = assignments.values()
        self.assertEqual(base64.b64decode(encoded, validate=True), payload)
        self.assertEqual(hashlib.sha256(base64.b64decode(encoded)).hexdigest(), digest)
        for source in sources:
            compile(source, "fixture-cell", "exec")

    def test_top_notice_distinguishes_bundled_source_from_upload_fallback(self):
        bundled = "".join(build(payload=source_zip())["cells"][0]["source"])
        unbundled = "".join(build()["cells"][0]["source"])
        self.assertIn("ソースZIPの別アップロードは不要", bundled)
        self.assertIn("新しいColabランタイム", bundled)
        self.assertIn("SOURCE_MODE = 'resume'", bundled)
        self.assertIn("stateと分析途中結果", bundled)
        self.assertIn("セル2の説明", bundled)
        self.assertIn("オフライン実行ではありません", bundled)
        self.assertIn("開発用", unbundled)
        self.assertIn("コード非同梱版", unbundled)
        self.assertIn("引用ID修正版", unbundled)
        self.assertTrue(bundled.endswith("# Fixture 日本語\n\n## Step 1\n\n"))

    def test_nbformat_metadata_ids_and_clean_execution_state(self):
        for payload in (None, source_zip()):
            with self.subTest(bundled=payload is not None):
                notebook = build(payload=payload, name="exports/Named notebook.ipynb")
                self.assertEqual((notebook["nbformat"], notebook["nbformat_minor"]), (4, 5))
                self.assertEqual(notebook["metadata"]["colab"]["name"], "Named notebook.ipynb")
                self.assertEqual(notebook["metadata"]["kernelspec"], {
                    "name": "python3", "display_name": "Python 3", "language": "python",
                })
                self.assertEqual(notebook["metadata"]["language_info"]["name"], "python")
                self.assertNotIn("accelerator", notebook["metadata"])
                ids = [cell["id"] for cell in notebook["cells"]]
                self.assertEqual(len(ids), len(set(ids)))
                for cell in notebook["cells"]:
                    self.assertRegex(cell["id"], r"^[A-Za-z0-9_-]{1,64}$")
                    self.assertEqual(cell["metadata"]["id"], cell["id"])
                    self.assertIsInstance(cell["source"], list)
                    if cell["cell_type"] == "code":
                        self.assertEqual(cell["metadata"]["cellView"], "form")
                        self.assertIsNone(cell["execution_count"])
                        self.assertEqual(cell["outputs"], [])
                    else:
                        self.assertNotIn("outputs", cell)
                        self.assertNotIn("execution_count", cell)
                self.assertEqual(notebook, json.loads(json.dumps(notebook)))
                self.assertEqual(notebook, build(payload=payload, name="exports/Named notebook.ipynb"))

    def test_identical_sources_still_have_unique_deterministic_ids(self):
        markdown = markdown_fixture(["pass\n"] * 6)
        first = build(markdown)
        second = build(markdown)
        ids = [cell["id"] for cell in first["cells"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(first, second)

    def test_preserves_other_fences_prose_and_source_whitespace(self):
        reference = "# Literal example\n\n````text\n```python\nnot executable!\n```\n````\n\n"
        cells = ["# leading comment\n\npass  # trailing spaces  \n\n"] * 6
        notebook = build(reference + markdown_fixture(cells))
        self.assertEqual(code_sources(notebook), cells)
        prose = "".join("".join(cell["source"]) for cell in notebook["cells"] if cell["cell_type"] == "markdown")
        self.assertIn(reference, prose)
        self.assertIn("```sh\necho not-a-code-cell\n```", prose)
        self.assertIn("## Step 6", prose)

    def test_tilde_fences_crlf_and_markdown_starting_with_code(self):
        markdown = "".join(f"~~~python\n{source}~~~\n" for source in FIXTURE_CELLS)
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=newline):
                notebook = build(markdown.replace("\n", newline))
                self.assertEqual(notebook["cells"][0]["cell_type"], "markdown")
                self.assertEqual(code_sources(notebook), [source.replace("\n", newline) for source in FIXTURE_CELLS])

    def test_builder_does_not_execute_cells(self):
        cells = ["raise RuntimeError('must not run during generation')\n"] * 6
        self.assertEqual(code_sources(build(markdown_fixture(cells))), cells)

    def test_rejects_missing_or_extra_python_cells(self):
        for cells in ([], FIXTURE_CELLS[:5], FIXTURE_CELLS + ["pass\n"]):
            with self.subTest(count=len(cells)), self.assertRaisesRegex(ValueError, "Expected 6 Python cells"):
                build(markdown_fixture(cells))
        with self.assertRaisesRegex(ValueError, "Expected 6 Python cells"):
            build("")

    def test_rejects_empty_and_malformed_python_without_dropping_the_cell(self):
        for bad in ("", " \n\n", "# only comments\n", "if True print('bad')\n", "return 1\n", "x = (\n", "\x00\n"):
            cells = FIXTURE_CELLS.copy()
            cells[2] = bad
            with self.subTest(source=bad), self.assertRaisesRegex(ValueError, "[Cc]ell 3"):
                build(markdown_fixture(cells))

    def test_rejects_unclosed_python_and_nonpython_fences(self):
        for suffix in ("```python\npass\n", "```sh\necho test\n"):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(ValueError, "Unclosed Markdown fence"):
                build(markdown_fixture() + suffix)

    def test_validates_syntax_after_prefix_injection_too(self):
        cells = FIXTURE_CELLS.copy()
        cells[0] = "from __future__ import annotations\n"
        build(markdown_fixture(cells))
        with self.assertRaisesRegex(ValueError, "Invalid Python cell 1"):
            build(markdown_fixture(cells), source_zip())


class SourceZipTests(unittest.TestCase):
    def test_accepts_stored_and_compressed_archives_with_optional_directories(self):
        entries = list(SOURCE_FILES.items()) + [
            ("vulns-news/", b""), ("vulns-news/src/", b""),
            ("vulns-news/README.md", b"trusted fixture\n"),
        ]
        for compression in (ZIP_STORED, ZIP_DEFLATED):
            with self.subTest(compression=compression):
                builder.validate_source_zip(source_zip(entries, compression))

    def test_every_required_file_must_be_present_nonempty_and_regular(self):
        for missing in SOURCE_FILES:
            for replacement in ([], [(missing, b"")], [(missing + "/", b"")]):
                entries = [(name, data) for name, data in SOURCE_FILES.items() if name != missing] + replacement
                with (
                    self.subTest(missing=missing, replacement=replacement),
                    self.assertRaisesRegex(ValueError, "missing nonempty required files"),
                ):
                    builder.validate_source_zip(source_zip(entries))

    def test_rejects_unsafe_paths_and_unexpected_roots(self):
        for path in ("../escape", "/absolute", "vulns-news/../escape", "vulns-news/./file",
                     "vulns-news//file", "vulns-news\\file", "C:/vulns-news/file",
                     "vulns-news/C:/file", "other/file", "vulns-news"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "Unsafe.*path|one vulns-news/ root"):
                builder.validate_source_zip(source_zip(list(SOURCE_FILES.items()) + [(path, b"bad")]))

    def test_rejects_nul_names_even_when_zipinfo_truncates_them(self):
        for original, corrupt in ((b"vulns-news/badXname", b"vulns-news/bad\x00name"),
                                  (b"Xulns-news/file", b"\x00ulns-news/file")):
            payload = source_zip(list(SOURCE_FILES.items()) + [(original.decode("ascii"), b"bad")])
            payload = payload.replace(original, corrupt)
            with self.subTest(name=corrupt), self.assertRaisesRegex(ValueError, "Unsafe source ZIP path"):
                builder.validate_source_zip(payload)

    def test_rejects_duplicate_files_directories_and_file_directory_aliases(self):
        extras = [
            [("vulns-news/go.mod", b"duplicate")],
            [("vulns-news/extra/", b""), ("vulns-news/extra/", b"")],
            [("vulns-news/extra", b"file"), ("vulns-news/extra/", b"")],
        ]
        for extra in extras:
            with self.subTest(extra=extra), warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with self.assertRaisesRegex(ValueError, "Duplicate source ZIP path"):
                    builder.validate_source_zip(source_zip(list(SOURCE_FILES.items()) + extra))

    def test_rejects_file_parent_conflicts_in_either_archive_order(self):
        extra = [("vulns-news/extra", b"file"), ("vulns-news/extra/child", b"child")]
        for ordered in (extra, list(reversed(extra))):
            with self.subTest(order=ordered), self.assertRaisesRegex(ValueError, "file/directory conflict"):
                builder.validate_source_zip(source_zip(list(SOURCE_FILES.items()) + ordered))

    def test_rejects_symlinks_and_special_files(self):
        for kind in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFSOCK):
            info = zip_info("vulns-news/link", kind | 0o777)
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "symlink|special file"):
                builder.validate_source_zip(source_zip(list(SOURCE_FILES.items()) + [(info, b"../outside")]))

    def test_rejects_inconsistent_directory_markers_and_directory_payloads(self):
        for info, data in ((zip_info("vulns-news/extra", stat.S_IFDIR | 0o755), b""),
                           (zip_info("vulns-news/extra/", stat.S_IFREG | 0o644), b""),
                           (zip_info("vulns-news/extra/", stat.S_IFDIR | 0o755), b"unexpected")):
            with self.subTest(name=info.filename, mode=info.external_attr), self.assertRaisesRegex(ValueError, "Inconsistent"):
                builder.validate_source_zip(source_zip(list(SOURCE_FILES.items()) + [(info, data)]))

    def test_rejects_empty_nonzip_and_truncated_archives(self):
        for payload in (b"", b"not a ZIP", source_zip([]), source_zip()[:-12]):
            with self.subTest(length=len(payload)), self.assertRaises(ValueError):
                build(payload=payload)

    def test_crc_checks_include_nonrequired_files(self):
        for target in ("vulns-news/go.mod", "vulns-news/extra.bin"):
            payload = source_zip(list(SOURCE_FILES.items()) + [("vulns-news/extra.bin", b"unique-payload")])
            with ZipFile(BytesIO(payload)) as archive:
                info = archive.getinfo(target)
            offset = info.header_offset
            name_size, extra_size = struct.unpack_from("<HH", payload, offset + 26)
            start = offset + 30 + name_size + extra_size
            corrupted = bytearray(payload)
            corrupted[start] ^= 1
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "CRC/header check failed"):
                builder.validate_source_zip(bytes(corrupted))

    def test_rejects_encrypted_members(self):
        payload = bytearray(source_zip())
        # Set the encryption bit in the first central directory entry; no
        # password prompt or attempted decryption should occur.
        offset = payload.index(b"PK\x01\x02")
        flags = struct.unpack_from("<H", payload, offset + 8)[0]
        struct.pack_into("<H", payload, offset + 8, flags | 1)
        with self.assertRaisesRegex(ValueError, "Encrypted source ZIP member"):
            builder.validate_source_zip(bytes(payload))


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="colab-builder-test-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.markdown = self.root / "fixture.md"
        self.markdown.write_text(markdown_fixture(), encoding="utf-8")
        self.output = self.root / "Export 日本語.ipynb"
        self.archive = self.root / "source.zip"
        self.archive.write_bytes(source_zip())

    def assert_cli_error(self, arguments, message):
        stderr = StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
            builder.main(arguments)
        self.assertEqual(error.exception.code, 2)
        self.assertIn(message, stderr.getvalue())

    def test_default_markdown_is_script_sibling_and_output_is_required(self):
        self.assertEqual(builder.DEFAULT_MARKDOWN, DOCS / "colab-deep-analysis.md")
        self.assert_cli_error([], "--output")
        with patch.object(builder, "DEFAULT_MARKDOWN", self.markdown):
            self.assertEqual(builder.main(["--output", str(self.output)]), 0)
        self.assertEqual(code_sources(json.loads(self.output.read_bytes())), FIXTURE_CELLS)

    def test_explicit_inputs_and_bundled_export_are_deterministic_utf8(self):
        arguments = ["--markdown", str(self.markdown), "--output", str(self.output),
                     "--source-zip", str(self.archive)]
        original_markdown = self.markdown.read_bytes()
        original_archive = self.archive.read_bytes()
        self.assertEqual(builder.main(arguments), 0)
        first = self.output.read_bytes()
        self.assertEqual(builder.main(arguments), 0)
        self.assertEqual(first, self.output.read_bytes())
        self.assertNotIn(b"\r\n", first)
        self.assertIn("日本語".encode(), first)
        notebook = json.loads(first)
        self.assertEqual(notebook, build(payload=original_archive, name=self.output.name))
        self.assertEqual(notebook["metadata"]["colab"]["name"], self.output.name)
        self.assertEqual(self.markdown.read_bytes(), original_markdown)
        self.assertEqual(self.archive.read_bytes(), original_archive)

    def test_invalid_markdown_leaves_existing_output_untouched(self):
        self.output.write_bytes(b"keep existing output")
        self.markdown.write_text("```python\ninvalid =\n```\n", encoding="utf-8")
        self.assert_cli_error(["--markdown", str(self.markdown), "--output", str(self.output)],
                              "Invalid Python cell 1")
        self.assertEqual(self.output.read_bytes(), b"keep existing output")

    def test_invalid_zip_does_not_create_output(self):
        self.archive.write_bytes(b"not a ZIP")
        self.assert_cli_error(["--markdown", str(self.markdown), "--output", str(self.output),
                               "--source-zip", str(self.archive)], "Invalid source ZIP")
        self.assertFalse(self.output.exists())

    def test_missing_input_has_clean_cli_error(self):
        missing = self.root / "missing.md"
        self.assert_cli_error(["--markdown", str(missing), "--output", str(self.output)], "missing.md")
        self.assertFalse(self.output.exists())

    def test_output_cannot_overwrite_either_input(self):
        for destination in (self.markdown, self.archive):
            original = destination.read_bytes()
            with self.subTest(destination=destination):
                self.assert_cli_error(["--markdown", str(self.markdown), "--output", str(destination),
                                       "--source-zip", str(self.archive)], "Output must not overwrite")
                self.assertEqual(destination.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
