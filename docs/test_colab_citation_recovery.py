"""Offline stdlib tests for the citation recovery cell.

Uploads and Go builds are mocked; no Go, Colab, network, scan, or LLM is run.
Real temporary files exercise extraction, preservation, and atomic installation.
"""

import ast
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch
from zipfile import ZipFile, ZipInfo

DOCS = Path(__file__).resolve().parent
MARKDOWN = DOCS / "colab-citation-recovery.md"
EXPECTED_ZIP = "vulns-news-colab-citation-fix-20260926.zip"
REQUIRED = (
    "bootstrap", "analysis_env", "analysis_work", "analysis_repo",
    "analysis_binary", "analysis_state", "analysis_output", "input_state",
    "MODEL", "BASE_URL", "LIMIT", "run_with_progress",
)
SOURCE_FILES = {
    "vulns-news/go.mod": "module fixture\n",
    "vulns-news/go.sum": "fixture dependencies\n",
    "vulns-news/cmd/repo-analyze/main.go": "package main\n",
    "vulns-news/cmd/repo-scan/main.go": "package main\n",
    "vulns-news/src/processor/fixture.go": "package processor\n",
}


def python_cells(path=MARKDOWN):
    return re.findall(
        r"^```python[ \t]*\n(.*?)^```[ \t]*$",
        path.read_text(encoding="utf-8"),
        flags=re.MULTILINE | re.DOTALL,
    )


def source_zip(entries=None):
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        for name, content in (SOURCE_FILES if entries is None else entries).items():
            archive.writestr(name, content)
    return output.getvalue()


class RecoveryHarness:
    def __init__(self, root):
        self.root = root
        self.work = root / "existing-analysis"
        self.repo = self.work / "vulns-news"
        self.repo.mkdir(parents=True)
        (self.repo / "old-source.txt").write_bytes(b"Keep the old source\n")
        self.binary = self.work / "repo-analyze"
        self.binary.write_bytes(b"old executable\n")
        self.binary.chmod(0o755)
        self.bootstrap = self.work / "toolchain" / "bin" / "go"
        self.bootstrap.parent.mkdir(parents=True)
        self.bootstrap.write_bytes(b"mock go bootstrap\n")
        self.bootstrap.chmod(0o755)
        self.env = {"GOTOOLCHAIN": "auto", "PATH": str(self.bootstrap.parent),
                    "PRESERVE_ENV": "custom value"}
        self.input_state = self.work / "scan-state.json"
        self.snapshot = self.work / "analysis-scan-state.json"
        self.output = self.work / "custom-results.json"
        # Opaque fixtures: Python must not migrate or rewrite Go-owned state.
        self.input_state.write_bytes(b'{"fixture_scan": true}\n')
        self.snapshot.write_bytes(self.input_state.read_bytes())
        self.output.write_bytes(
            b'{"errors": 1, "pending": 590, "checksum": "old-checksum", '
            b'"input_hash": "old-prepared-hash"}\n'
        )
        self.scan_binary = self.work / "repo-scan"
        self.scan_binary.write_bytes(b"old scan executable\n")
        (self.work / "scan-request.json").write_bytes(b'{"ref": "keep"}\n')
        (self.work / "scan-result.json").write_bytes(b'{"keep": true}\n')
        self.forbidden_io = Mock(side_effect=AssertionError("Unexpected network, scan, or LLM"))
        self.upload = Mock(return_value={EXPECTED_ZIP: source_zip()})
        self.build = Mock(side_effect=self._build)
        self.build_error: BaseException | None = None
        self.artifact = "executable"
        self.real_replace = os.replace
        self.replace = Mock(side_effect=self._replace)
        self.events = []
        self.stdout = StringIO()
        self.namespace = {
            "bootstrap": str(self.bootstrap), "analysis_env": self.env,
            "analysis_work": self.work, "analysis_repo": self.repo,
            "analysis_binary": self.binary, "analysis_state": self.snapshot,
            "analysis_output": self.output, "input_state": self.input_state,
            "scan_binary": self.scan_binary, "MODEL": "fixture-model:custom",
            "BASE_URL": "http://fixture.invalid:11434", "LIMIT": 7,
            "run_with_progress": self.forbidden_io, "analysis_ready": True,
            "analysis_returncode": 1, "analysis_plan": {"total_candidates": 591},
            "SOURCE_MODE": "github", "REF": "keep", "USE_NVD": False,
        }
        self.original_names = set(self.namespace)

    def snapshot_work(self):
        return {p.relative_to(self.work): p.read_bytes()
                for p in self.work.rglob("*") if p.is_file()}

    def _build(self, command, **kwargs):
        if len(command) != 5 or command[:3] != [str(self.bootstrap), "build", "-o"] or command[4] != "./cmd/repo-analyze":
            raise AssertionError(f"Only repo-analyze go build is allowed: {command!r}")
        staged = Path(command[3])
        if staged == self.binary or staged.parent.parent != self.binary.parent:
            raise AssertionError("Build must target a separate path on the same filesystem")
        new_repo = kwargs.get("cwd")
        if not isinstance(new_repo, Path) or new_repo == self.repo or new_repo.parent.parent != self.work.parent:
            raise AssertionError("Build must use separately extracted source")
        if kwargs != {"cwd": new_repo, "env": self.env, "check": True, "timeout": 600}:
            raise AssertionError(f"Unexpected build settings: {kwargs!r}")
        if self.binary.read_bytes() != self.work_before[Path("repo-analyze")]:
            raise AssertionError("Old binary changed before build completed")
        if self.namespace["analysis_repo"] is not self.before["analysis_repo"]:
            raise AssertionError("Source switched before build completed")
        self.events.append("build")
        if self.artifact != "missing":
            staged.write_bytes(b"" if self.artifact == "empty" else b"new executable\n")
            staged.chmod(0o644 if self.artifact == "not_executable" else 0o755)
        if self.build_error is not None:
            raise self.build_error
        return subprocess.CompletedProcess(command, 0)

    def _replace(self, source, destination):
        if Path(destination) != self.binary:
            raise AssertionError("Only the analysis binary may be replaced")
        if self.binary.read_bytes() != self.work_before[Path("repo-analyze")]:
            raise AssertionError("Old binary changed before atomic installation")
        self.events.append("replace")
        self.real_replace(source, destination)

    def execute(self):
        self.before = self.namespace.copy()
        self.env_before = self.env.copy()
        self.work_before = self.snapshot_work()
        self.cwd_before = Path.cwd()
        google = ModuleType("google")
        colab = ModuleType("google.colab")
        colab.__dict__["files"] = SimpleNamespace(upload=self.upload)
        google.__dict__["colab"] = colab
        code = compile(python_cells()[0], str(MARKDOWN) + ":cell1", "exec", optimize=2)
        with (
            redirect_stdout(self.stdout),
            patch.dict(sys.modules, {"google": google, "google.colab": colab}),
            patch("subprocess.run", self.build),
            patch("subprocess.Popen", self.forbidden_io),
            patch("os.replace", self.replace),
            patch("os.system", self.forbidden_io),
            patch("os.chdir", self.forbidden_io),
            patch("urllib.request.urlopen", self.forbidden_io),
            patch("socket.create_connection", self.forbidden_io),
            patch("socket.socket", self.forbidden_io),
        ):
            exec(code, self.namespace)  # noqa: S102


class RecoverySourceTests(unittest.TestCase):
    def test_single_python_cell_compiles(self):
        cells = python_cells()
        self.assertEqual(len(cells), 1)
        for index, cell in enumerate(cells, 1):
            compile(cell, f"{MARKDOWN}:cell{index}", "exec")


class RecoveryTests(unittest.TestCase):
    def harness(self):
        directory = tempfile.TemporaryDirectory(prefix="colab-citation-test-")
        self.addCleanup(directory.cleanup)
        harness = RecoveryHarness(Path(directory.name))
        self.addCleanup(harness.forbidden_io.assert_not_called)
        return harness

    def assert_preserved(self, h, *, installed=False):
        expected_files = h.work_before.copy()
        if installed:
            expected_files[Path("repo-analyze")] = b"new executable\n"
        self.assertEqual(h.snapshot_work(), expected_files)
        self.assertEqual(h.env, h.env_before)
        self.assertEqual(Path.cwd(), h.cwd_before)
        for name in h.original_names & h.before.keys():
            value = h.before[name]
            if name in ("analysis_ready", "analysis_returncode") or (installed and name == "analysis_repo"):
                continue
            with self.subTest(variable=name):
                self.assertIs(h.namespace[name], value)
        self.assertIs(h.namespace["analysis_ready"], installed)
        self.assertIsNone(h.namespace["analysis_returncode"])
        self.assertFalse(list(h.work.glob(".citation-build-*")))
        self.assertTrue((h.repo / "old-source.txt").is_file())

    def assert_rejected_before_upload(self, h):
        h.upload.assert_not_called()
        h.build.assert_not_called()
        h.replace.assert_not_called()
        self.assert_preserved(h)
        self.assertFalse(list(h.root.glob("vulns-news-citation-source-*")))

    def test_success_preserves_settings_files_and_atomically_installs(self):
        h = self.harness()
        h.execute()
        self.assert_preserved(h, installed=True)
        h.upload.assert_called_once_with()
        self.assertEqual(h.events, ["build", "replace"])
        h.build.assert_called_once()
        h.replace.assert_called_once()
        new_repo = h.namespace["analysis_repo"]
        self.assertNotEqual(new_repo, h.repo)
        self.assertEqual(new_repo.parent.parent, h.work.parent)
        self.assertFalse(new_repo.is_relative_to(h.work))
        for relative, content in SOURCE_FILES.items():
            self.assertEqual((new_repo.parent / relative).read_text(), content)
        staged = Path(h.build.call_args.args[0][3])
        h.build.assert_called_once_with(
            [str(h.bootstrap), "build", "-o", str(staged), "./cmd/repo-analyze"],
            cwd=new_repo, env=h.env, check=True, timeout=600,
        )
        self.assertIs(h.build.call_args.kwargs["env"], h.env)
        h.replace.assert_called_once_with(staged, h.binary)
        self.assertFalse(staged.exists())
        self.assertTrue(os.access(h.binary, os.X_OK))
        self.assertIn("既存セル4 → セル5", h.stdout.getvalue())

    def test_missing_or_none_variables_fail_before_upload_even_with_optimization(self):
        for name in REQUIRED:
            for missing in (True, False):
                with self.subTest(name=name, missing=missing):
                    h = self.harness()
                    if missing:
                        del h.namespace[name]
                    else:
                        h.namespace[name] = None
                    with self.assertRaisesRegex(RuntimeError, name):
                        h.execute()
                    self.assert_rejected_before_upload(h)

    def test_missing_files_fail_before_upload(self):
        for name in ("bootstrap", "analysis_binary", "analysis_state", "analysis_output", "input_state"):
            with self.subTest(name=name):
                h = self.harness()
                Path(h.namespace[name]).unlink()
                with self.assertRaisesRegex(RuntimeError, name):
                    h.execute()
                self.assert_rejected_before_upload(h)

    def test_invalid_paths_and_configuration_fail_before_upload(self):
        cases = [
            ("analysis_work", "missing-directory"), ("analysis_repo", "missing-directory"),
            ("analysis_state", 42), ("analysis_output", ""),
            ("analysis_env", {}), ("analysis_env", {"PATH": 42}),
            ("analysis_env", []), ("MODEL", ""), ("BASE_URL", " "),
            ("LIMIT", -1), ("LIMIT", "0"), ("LIMIT", True), ("run_with_progress", 42),
        ]
        for name, value in cases:
            with self.subTest(name=name, value=value):
                h = self.harness()
                h.namespace[name] = value
                with self.assertRaisesRegex(RuntimeError, name):
                    h.execute()
                self.assert_rejected_before_upload(h)

    def test_nonexecutable_bootstrap_is_rejected(self):
        h = self.harness()
        h.bootstrap.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "bootstrap"):
            h.execute()
        self.assert_rejected_before_upload(h)

    def test_wrong_empty_or_multiple_uploads_are_rejected(self):
        for uploaded in ({}, {"vulns-news-colab-deep-analysis-20260926.zip": source_zip()},
                         {EXPECTED_ZIP: source_zip(), "extra.zip": source_zip()}):
            with self.subTest(names=list(uploaded)):
                h = self.harness()
                h.upload.return_value = uploaded
                with self.assertRaisesRegex(RuntimeError, EXPECTED_ZIP):
                    h.execute()
                h.build.assert_not_called()
                h.replace.assert_not_called()
                self.assert_preserved(h)

    def test_colab_numeric_collision_suffix_uses_actual_returned_payload(self):
        for suffix in (1, 2, 10):
            with self.subTest(suffix=suffix):
                h = self.harness()
                name = f"{Path(EXPECTED_ZIP).stem} ({suffix}).zip"
                entries = dict(SOURCE_FILES, **{"vulns-news/upload-marker.txt": name})
                h.upload.return_value = {name: source_zip(entries)}
                h.execute()
                self.assert_preserved(h, installed=True)
                self.assertEqual((h.namespace["analysis_repo"] / "upload-marker.txt").read_text(), name)
                h.upload.assert_called_once_with()
                self.assertEqual(h.events, ["build", "replace"])

    def test_unrelated_or_malformed_collision_names_are_rejected(self):
        stem = Path(EXPECTED_ZIP).stem
        names = [
            "unrelated (1).zip", "vulns-news-colab-deep-analysis-20260926 (1).zip",
            f"{stem} (0).zip", f"{stem} (01).zip", f"{stem} (-1).zip",
            f"{stem} (one).zip", f"{stem} (１).zip", f"{stem}(1).zip",
            f"{stem}  (1).zip", f"{stem} (1) (2).zip", f"{stem} (1).ZIP",
            f"{stem} (1).zip.bak", f"{stem} (1).zip\n", f"prefix-{stem} (1).zip",
            f"../{stem} (1).zip", f"folder/{stem} (1).zip",
        ]
        for name in names:
            with self.subTest(name=name):
                h = self.harness()
                h.upload.return_value = {name: source_zip()}
                with self.assertRaisesRegex(RuntimeError, re.escape(EXPECTED_ZIP)):
                    h.execute()
                h.build.assert_not_called()
                h.replace.assert_not_called()
                self.assert_preserved(h)
                self.assertFalse(list(h.root.glob("vulns-news-citation-source-*")))

    def test_collision_name_still_requires_full_source_zip(self):
        h = self.harness()
        name = f"{Path(EXPECTED_ZIP).stem} (1).zip"
        h.upload.return_value = {name: source_zip({"vulns-news/go.mod": "module fixture\n"})}
        with self.assertRaisesRegex(RuntimeError, r"go\.sum が不足"):
            h.execute()
        h.build.assert_not_called()
        h.replace.assert_not_called()
        self.assert_preserved(h)

    def test_incomplete_source_zip_is_rejected(self):
        for missing in SOURCE_FILES:
            with self.subTest(missing=missing):
                h = self.harness()
                h.upload.return_value = {EXPECTED_ZIP: source_zip({
                    key: value for key, value in SOURCE_FILES.items() if key != missing
                })}
                with self.assertRaisesRegex(RuntimeError, "フルソースZIP"):
                    h.execute()
                h.build.assert_not_called()
                h.replace.assert_not_called()
                self.assert_preserved(h)

    def test_traversal_absolute_paths_and_symlinks_are_rejected_before_extraction(self):
        for attack in ("traversal", "absolute", "symlink"):
            with self.subTest(attack=attack):
                h = self.harness()
                entries: dict[str | ZipInfo, str] = {
                    name: content for name, content in SOURCE_FILES.items()
                }
                if attack == "symlink":
                    link = ZipInfo("vulns-news/link")
                    link.create_system = 3
                    link.external_attr = (stat.S_IFLNK | 0o777) << 16
                    entries[link] = str(h.work)
                else:
                    name = ("../existing-analysis/repo-analyze" if attack == "traversal"
                            else h.binary.as_posix())
                    entries[name] = "overwrite old executable"
                h.upload.return_value = {EXPECTED_ZIP: source_zip(entries)}
                with self.assertRaisesRegex(RuntimeError, "ZIPエントリ"):
                    h.execute()
                h.build.assert_not_called()
                h.replace.assert_not_called()
                self.assert_preserved(h)
                extracted = list(h.root.glob("vulns-news-citation-source-*"))
                self.assertEqual(len(extracted), 1)
                self.assertEqual(list(extracted[0].iterdir()), [])

    def test_failed_build_timeout_and_interrupt_keep_old_binary_and_repo(self):
        for error in (subprocess.CalledProcessError(1, ["go", "build"]),
                      subprocess.TimeoutExpired(["go", "build"], 600), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                h = self.harness()
                h.build_error = error
                with self.assertRaises(type(error)) as caught:
                    h.execute()
                self.assertIs(caught.exception, error)
                self.assertEqual(h.events, ["build"])
                h.replace.assert_not_called()
                self.assert_preserved(h)
                self.assertTrue((h.build.call_args.kwargs["cwd"] / "go.mod").is_file())

    def test_missing_empty_or_nonexecutable_build_output_keeps_old_binary(self):
        for artifact in ("missing", "empty", "not_executable"):
            with self.subTest(artifact=artifact):
                h = self.harness()
                h.artifact = artifact
                with self.assertRaisesRegex(RuntimeError, "旧バイナリ"):
                    h.execute()
                h.replace.assert_not_called()
                self.assert_preserved(h)

    def test_atomic_install_failure_keeps_old_binary_and_repo(self):
        h = self.harness()
        h.replace.side_effect = PermissionError("fixture install denied")
        with self.assertRaisesRegex(PermissionError, "fixture install denied"):
            h.execute()
        h.replace.assert_called_once()
        self.assert_preserved(h)

    def test_failed_update_blocks_existing_cell4_and_collision_upload_can_retry(self):
        h = self.harness()
        retry_name = f"{Path(EXPECTED_ZIP).stem} (1).zip"
        retry_source = dict(SOURCE_FILES, **{"vulns-news/upload-marker.txt": "retry payload"})
        h.upload.side_effect = [
            {EXPECTED_ZIP: source_zip()}, {retry_name: source_zip(retry_source)},
        ]
        h.build_error = subprocess.CalledProcessError(1, ["go", "build"])
        with self.assertRaises(subprocess.CalledProcessError):
            h.execute()
        self.assert_preserved(h)
        h.replace.assert_not_called()
        tree = ast.parse(python_cells(DOCS / "colab-deep-analysis.md")[3])
        guard = next(node for node in tree.body if isinstance(node, ast.Assert))
        code = compile(ast.Module(body=[guard], type_ignores=[]), "cell4-readiness", "exec")
        with self.assertRaises(AssertionError):
            exec(code, h.namespace)  # noqa: S102
        h.build_error = None
        h.execute()
        self.assert_preserved(h, installed=True)
        self.assertEqual((h.namespace["analysis_repo"] / "upload-marker.txt").read_text(), "retry payload")
        self.assertEqual(h.upload.call_count, 2)
        self.assertEqual(h.events, ["build", "build", "replace"])
        exec(code, h.namespace)  # noqa: S102

    def test_repeated_update_with_collision_keeps_previous_source_and_saved_work(self):
        h = self.harness()
        second_name = f"{Path(EXPECTED_ZIP).stem} (1).zip"
        second_source = dict(SOURCE_FILES, **{"vulns-news/upload-marker.txt": "second payload"})
        h.upload.side_effect = [
            {EXPECTED_ZIP: source_zip()}, {second_name: source_zip(second_source)},
        ]
        h.execute()
        previous_repo = h.namespace["analysis_repo"]
        h.execute()
        self.assert_preserved(h, installed=True)
        self.assertNotEqual(h.namespace["analysis_repo"], previous_repo)
        self.assertTrue((previous_repo / "go.mod").is_file())
        self.assertFalse((previous_repo / "upload-marker.txt").exists())
        self.assertEqual((h.namespace["analysis_repo"] / "upload-marker.txt").read_text(), "second payload")
        self.assertEqual(h.upload.call_count, 2)
        self.assertEqual(h.events, ["build", "replace", "build", "replace"])


if __name__ == "__main__":
    unittest.main()
