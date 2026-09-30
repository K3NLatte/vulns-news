"""Offline regression tests for the Python cells in colab-deep-analysis.md.

Only cell 2 and the isolated run_with_progress definition are executed. Scanning,
planning, uploads, and child processes are mocked; these are not live GitHub or
Ollama E2E tests and do not install anything or validate model output.
"""

import ast
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, Mock, call, patch

DOCS = Path(__file__).resolve().parent
MARKDOWN = DOCS / "colab-deep-analysis.md"
NOTEBOOK = DOCS / "colab-deep-analysis.ipynb"
CONFIG_NAMES = {
    "SOURCE_MODE", "REPOSITORY_URL", "REF", "USE_NVD", "SCAN_TIMEOUT",
    "SAVED_STATE_PATH", "SAVED_ANALYSIS_PATH",
}
DEFAULT_REQUEST = {
    "repository": "https://github.com/vercel/next.js", "ref": "", "nvd": False,
}


def python_cells():
    return re.findall(
        r"^```python[ \t]*\n(.*?)^```[ \t]*$",
        MARKDOWN.read_text(encoding="utf-8"),
        flags=re.MULTILINE | re.DOTALL,
    )


def configured_cell(source, **overrides):
    """Replace only named, top-level assignment values, never source strings."""
    unknown = overrides.keys() - CONFIG_NAMES
    if unknown:
        raise ValueError(f"Unknown cell configuration: {sorted(unknown)}")
    tree = ast.parse(source, filename=str(MARKDOWN) + ":cell2")
    for name, value in overrides.items():
        assignments = [
            node for node in tree.body
            if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ]
        if len(assignments) != 1:
            raise ValueError(f"Expected one top-level assignment for {name}")
        assignment = assignments[0]
        if type(value) is not type(ast.literal_eval(assignment.value)):
            raise ValueError(f"Wrong configuration type for {name}")
        assignment.value = ast.copy_location(ast.Constant(value=value), assignment.value)
    return compile(ast.fix_missing_locations(tree), str(MARKDOWN) + ":cell2", "exec")


def scan_state(*, complete=True, status="complete", sha="a" * 40):
    # Only the state fields consumed by this Python cell are needed: the Go
    # state validator and candidate builder are outside this mocked boundary.
    return {
        "schema_version": 1,
        "profile": {
            "repository": {
                "canonical_url": DEFAULT_REQUEST["repository"], "commit_sha": sha,
            },
            "components": [
                {"ecosystem": "npm", "name": "fixture", "version": "1.0.0",
                 "source_path": "package-lock.json"},
            ],
        },
        "report": {
            "refresh_complete": complete,
            "status": status,
            "queries": [{"query": {"ecosystem": "npm", "name": "fixture",
                                   "version": "1.0.0"}, "complete": complete}],
            "unqueried": [],
        },
    }


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class Cell2Harness:
    def __init__(self, work):
        self.work = work
        self.repo = work / "vulns-news"
        self.repo.mkdir()
        self.env = {"GOTOOLCHAIN": "auto"}
        self.scan_binary = work / "repo-scan"
        self.analysis_binary = work / "repo-analyze"
        self.input_state = work / "scan-state.json"
        self.request_file = work / "scan-request.json"
        self.snapshot = work / "analysis-scan-state.json"
        self.scan_result = work / "scan-result.json"
        self.uploaded_state = work / "uploaded-scan-state.json"
        self.next_scan_state: dict | None = scan_state()
        self.scan_returncode = 0
        self.scan_error: BaseException | None = None
        self.plan_report = {
            "total_candidates": 1, "preparation_errors": 0,
            "entries": [{"id": "GHSA-fixture"}],
        }
        self.plan_returncode = 0
        self.plan_stderr = "fixture plan-only diagnostics\n"
        self.events = []
        self.states_before_scan = []
        self.planned_snapshots = []
        self.scan = Mock(name="run_with_progress", side_effect=self._scan)
        self.plan = Mock(name="subprocess.run", side_effect=self._plan)
        self.upload = Mock(name="files.upload", side_effect=AssertionError("Unexpected upload"))
        self.forbidden_io = Mock(side_effect=AssertionError("Unexpected network or child process"))
        self.continuation = Mock(name="model_continuation")
        self.stdout = StringIO()
        self.namespace = {
            "Path": Path, "json": json, "shutil": shutil, "subprocess": subprocess,
            "analysis_work": work, "analysis_repo": self.repo, "analysis_env": self.env,
            "scan_binary": self.scan_binary, "analysis_binary": self.analysis_binary,
            "files": SimpleNamespace(upload=self.upload), "run_with_progress": self.scan,
            "urlopen": self.forbidden_io, "analysis_setup_ready": True,
        }

    def seed_github(self, state=None, settings=None):
        write_json(self.input_state, scan_state() if state is None else state)
        write_json(self.request_file, DEFAULT_REQUEST if settings is None else settings)

    def _scan(self, command, output_path):
        if command[0] != str(self.scan_binary):
            raise AssertionError(f"Only repo-scan is allowed here: {command!r}")
        state_path = Path(command[command.index("-state") + 1])
        if state_path != self.input_state or output_path != self.scan_result:
            raise AssertionError("Scan must use the working scan-state and separate result file")
        self.events.append("scan")
        self.states_before_scan.append(
            json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else None
        )
        if self.next_scan_state is not None:
            write_json(state_path, self.next_scan_state)
            write_json(output_path, self.next_scan_state["report"])
        if self.scan_error is not None:
            raise self.scan_error
        return self.scan_returncode

    def _plan(self, command, **kwargs):
        expected = [str(self.analysis_binary), "-state", str(self.snapshot), "-plan-only"]
        if command != expected or kwargs != {
            "cwd": self.repo, "env": self.env,
            "capture_output": True, "text": True, "timeout": 300,
        }:
            raise AssertionError(f"Only the offline plan-only invocation is allowed: {command!r}")
        self.events.append("plan")
        self.planned_snapshots.append(self.snapshot.read_bytes())
        return subprocess.CompletedProcess(
            command, self.plan_returncode, json.dumps(self.plan_report), self.plan_stderr,
        )

    def execute(self, **overrides):
        code = configured_cell(python_cells()[1], **overrides)
        with (
            redirect_stdout(self.stdout),
            patch("subprocess.run", self.plan),
            patch("subprocess.Popen", self.forbidden_io),
            patch("urllib.request.urlopen", self.forbidden_io),
            patch("socket.create_connection", self.forbidden_io),
            patch("socket.socket", self.forbidden_io),
        ):
            exec(code, self.namespace)  # noqa: S102
            # A sequential caller must not reach this marker on a cell error.
            # This does not execute model cells or guard manual Colab execution.
            self.continuation()


class NotebookSourceTests(unittest.TestCase):
    def test_all_python_cells_compile(self):
        cells = python_cells()
        self.assertEqual(len(cells), 6)
        for index, source in enumerate(cells, 1):
            with self.subTest(cell=index):
                compile(source, f"{MARKDOWN}:cell{index}", "exec")

    def test_generated_notebook_code_equals_markdown_cells(self):
        notebook = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
        sources = [
            "".join(cell["source"]) for cell in notebook["cells"]
            if cell["cell_type"] == "code"
        ]
        self.assertEqual(sources, python_cells(), "Regenerate the notebook from Markdown")

    def test_configuration_overrides_are_literal_and_reject_unknown_names(self):
        value = "a 'quoted' path\n; raise RuntimeError('not code')"
        namespace = {}
        exec(configured_cell('SAVED_STATE_PATH = ""', SAVED_STATE_PATH=value), namespace)  # noqa: S102
        self.assertEqual(namespace["SAVED_STATE_PATH"], value)
        with self.assertRaisesRegex(ValueError, "Unknown cell configuration"):
            configured_cell(python_cells()[1], SOURCE_MOD="saved")
        with self.assertRaisesRegex(ValueError, "Expected one top-level assignment"):
            configured_cell("pass", REF="fixture")
        with self.assertRaisesRegex(ValueError, "Wrong configuration type"):
            configured_cell(python_cells()[1], USE_NVD="False")


class Cell2Tests(unittest.TestCase):
    def harness(self):
        directory = tempfile.TemporaryDirectory(prefix="colab-cell2-")
        self.addCleanup(directory.cleanup)
        harness = Cell2Harness(Path(directory.name))
        self.addCleanup(harness.forbidden_io.assert_not_called)
        return harness

    def assert_stopped_before_plan(self, harness):
        harness.plan.assert_not_called()
        harness.continuation.assert_not_called()
        harness.upload.assert_not_called()
        self.assertFalse(harness.snapshot.exists())
        self.assertFalse(harness.namespace["analysis_ready"])

    def test_failed_rerun_invalidates_previous_ready_state(self):
        h = self.harness()
        h.execute()
        self.assertTrue(h.namespace["analysis_ready"])
        h.namespace["analysis_returncode"] = 0
        with self.assertRaises(AssertionError):
            h.execute(REF="another-tag")
        self.assertFalse(h.namespace["analysis_ready"])
        self.assertIsNone(h.namespace["analysis_returncode"])
        for cell_index in (2, 3):
            tree = ast.parse(python_cells()[cell_index])
            guard = next(node for node in tree.body if isinstance(node, ast.Assert))
            code = compile(ast.Module(body=[guard], type_ignores=[]), "readiness-guard", "exec")
            with self.assertRaises(AssertionError):
                exec(code, h.namespace)  # noqa: S102

    def test_default_fresh_github_scan_copies_state_then_plans(self):
        h = self.harness()
        h.execute()
        self.assertTrue(h.namespace["analysis_ready"])
        self.assertEqual(h.namespace["SOURCE_MODE"], "github")
        self.assertEqual(h.namespace["SAVED_STATE_PATH"], "")
        h.scan.assert_called_once_with([
            str(h.scan_binary), "-state", str(h.input_state), "-nvd=false",
            "-timeout", "30m", "-repository", DEFAULT_REQUEST["repository"],
        ], h.scan_result)
        self.assertEqual(json.loads(h.request_file.read_text()), DEFAULT_REQUEST)
        self.assertEqual(h.states_before_scan, [None])
        self.assertEqual(h.events, ["scan", "plan"])
        original = h.input_state.read_bytes()
        self.assertEqual(json.loads(original), h.next_scan_state)
        self.assertEqual(h.snapshot.read_bytes(), original)
        self.assertEqual(h.planned_snapshots, [original])
        self.assertFalse(h.snapshot.samefile(h.input_state))
        self.assertNotEqual(h.scan_result.read_bytes(), original)
        self.assertEqual(h.namespace["analysis_state"], h.snapshot)
        self.assertEqual(h.namespace["analysis_plan"], h.plan_report)
        h.plan.assert_called_once()
        h.upload.assert_not_called()
        h.continuation.assert_called_once_with()
        output = h.stdout.getvalue()
        for text in ("SHA: " + "a" * 40, "抽出した構成要素: 1", "OSV照会: 1 未照会: 0",
                     "照会完了: True", "分析候補グループ: 1", "準備エラー: 0"):
            self.assertIn(text, output)

    def test_ref_nvd_and_timeout_flags(self):
        for ref in ("", "v-fixture"):
            for use_nvd in (False, True):
                with self.subTest(ref=ref, nvd=use_nvd):
                    h = self.harness()
                    h.execute(REF=ref, USE_NVD=use_nvd, SCAN_TIMEOUT="90m")
                    expected = [
                        str(h.scan_binary), "-state", str(h.input_state),
                        "-nvd=" + str(use_nvd).lower(), "-timeout", "90m",
                        "-repository", DEFAULT_REQUEST["repository"],
                    ]
                    if ref:
                        expected += ["-ref", ref]
                    h.scan.assert_called_once_with(expected, h.scan_result)
                    self.assertEqual(json.loads(h.request_file.read_text()), {
                        **DEFAULT_REQUEST, "ref": ref, "nvd": use_nvd,
                    })
                    h.continuation.assert_called_once_with()

    def test_complete_refresh_reuses_state_without_requests(self):
        for status in ("complete", "incomplete"):
            with self.subTest(coverage=status):
                h = self.harness()
                state = scan_state(status=status)
                if status == "incomplete":
                    state["report"]["unqueried"] = [{"reason": "unsupported fixture"}]
                h.seed_github(state)
                original = h.input_state.read_bytes()
                request = h.request_file.read_bytes()
                h.execute()
                h.execute()
                h.scan.assert_not_called()
                h.upload.assert_not_called()
                self.assertEqual(h.events, ["plan", "plan"])
                self.assertEqual(h.planned_snapshots, [original, original])
                self.assertEqual(h.input_state.read_bytes(), original)
                self.assertEqual(h.snapshot.read_bytes(), original)
                self.assertEqual(h.request_file.read_bytes(), request)
                self.assertIn("API再照会はしません", h.stdout.getvalue())
                self.assertEqual(h.continuation.call_count, 2)

    def test_incomplete_refresh_monitors_same_state_without_cloning(self):
        h = self.harness()
        pending = scan_state(complete=False, status="incomplete", sha="b" * 40)
        settings = {**DEFAULT_REQUEST, "ref": "v-fixture", "nvd": True}
        h.seed_github(pending, settings)
        h.next_scan_state = scan_state(sha="b" * 40)
        h.execute(REF="v-fixture", USE_NVD=True)
        h.scan.assert_called_once_with([
            str(h.scan_binary), "-state", str(h.input_state), "-nvd=true",
            "-timeout", "30m", "-monitor",
        ], h.scan_result)
        self.assertEqual(h.states_before_scan, [pending])
        self.assertEqual(h.events, ["scan", "plan"])
        self.assertEqual(h.namespace["saved_scan"]["profile"], pending["profile"])
        self.assertTrue(h.namespace["saved_scan"]["report"]["refresh_complete"])
        self.assertEqual(h.snapshot.read_bytes(), h.input_state.read_bytes())
        h.continuation.assert_called_once_with()

    def test_scan_failure_stops_before_snapshot_or_plan(self):
        for complete in (False, True):
            with self.subTest(state_looks_complete=complete):
                h = self.harness()
                h.next_scan_state = scan_state(complete=complete)
                h.scan_returncode = 1
                with self.assertRaisesRegex(AssertionError, "スキャン未完了"):
                    h.execute()
                h.scan.assert_called_once()
                self.assertEqual(h.events, ["scan"])
                self.assertTrue(h.input_state.exists())
                self.assertTrue(h.scan_result.exists())
                self.assertIn("スキャン終了コード: 1", h.stdout.getvalue())
                self.assert_stopped_before_plan(h)

    def test_cancellation_propagates_without_promoting_snapshot(self):
        for writes_checkpoint in (False, True):
            with self.subTest(writes_checkpoint=writes_checkpoint):
                h = self.harness()
                h.next_scan_state = scan_state(complete=False) if writes_checkpoint else None
                interrupt = KeyboardInterrupt("fixture cancellation")
                h.scan_error = interrupt
                with self.assertRaises(KeyboardInterrupt) as caught:
                    h.execute()
                self.assertIs(caught.exception, interrupt)
                self.assertEqual(h.input_state.exists(), writes_checkpoint)
                self.assertTrue(h.request_file.exists())
                self.assert_stopped_before_plan(h)

    def test_config_mismatch_refuses_complete_or_incomplete_state(self):
        for complete in (False, True):
            for override in ({"REPOSITORY_URL": "https://github.com/example/fixture"},
                             {"REF": "v-other"}, {"USE_NVD": True}):
                with self.subTest(complete=complete, override=override):
                    h = self.harness()
                    h.seed_github(scan_state(complete=complete))
                    original = h.input_state.read_bytes()
                    request = h.request_file.read_bytes()
                    with self.assertRaisesRegex(AssertionError, "対象・ref・NVD設定が変わりました"):
                        h.execute(**override)
                    h.scan.assert_not_called()
                    self.assertEqual(h.input_state.read_bytes(), original)
                    self.assertEqual(h.request_file.read_bytes(), request)
                    self.assert_stopped_before_plan(h)

    def test_state_without_request_settings_requires_explicit_saved_mode(self):
        h = self.harness()
        write_json(h.input_state, scan_state())
        original = h.input_state.read_bytes()
        with self.assertRaisesRegex(AssertionError, "取得設定がない既存state"):
            h.execute()
        h.scan.assert_not_called()
        self.assertFalse(h.request_file.exists())
        self.assertEqual(h.input_state.read_bytes(), original)
        self.assert_stopped_before_plan(h)

    def test_saved_path_bypasses_github_settings_scan_and_upload(self):
        h = self.harness()
        h.seed_github(scan_state(complete=False), {**DEFAULT_REQUEST, "ref": "unrelated"})
        request = h.request_file.read_bytes()
        github_state = h.input_state.read_bytes()
        saved = h.work / "saved 'scan state'.json"
        write_json(saved, scan_state(sha="c" * 40))
        original = saved.read_bytes()
        h.execute(SOURCE_MODE="saved", SAVED_STATE_PATH=str(saved))
        h.scan.assert_not_called()
        h.upload.assert_not_called()
        self.assertEqual(h.namespace["input_state"], saved)
        self.assertEqual(h.snapshot.read_bytes(), original)
        self.assertEqual(saved.read_bytes(), original)
        self.assertEqual(h.planned_snapshots, [original])
        self.assertEqual(h.request_file.read_bytes(), request)
        self.assertEqual(h.input_state.read_bytes(), github_state)
        h.continuation.assert_called_once_with()

    def test_saved_upload_bypasses_scan_and_is_reused_on_rerun(self):
        h = self.harness()
        original = json.dumps(scan_state()).encode("utf-8")
        h.upload.side_effect = None
        h.upload.return_value = {"original-scan-state.json": original}
        h.execute(SOURCE_MODE="saved")
        h.execute(SOURCE_MODE="saved")
        h.upload.assert_called_once_with()
        h.scan.assert_not_called()
        self.assertEqual(h.uploaded_state.read_bytes(), original)
        self.assertEqual(h.snapshot.read_bytes(), original)
        self.assertEqual(h.planned_snapshots, [original, original])
        self.assertFalse(h.input_state.exists())
        self.assertFalse(h.request_file.exists())
        self.assertEqual(h.continuation.call_count, 2)

    def test_saved_missing_invalid_or_incomplete_state_stops_before_plan(self):
        cases = [
            (None, "stateがありません"),
            ({"total_candidates": 1}, "repo-scanのstate形式ではありません"),
            (scan_state(complete=False), "元スキャンの照会が未完了"),
        ]
        for state, message in cases:
            with self.subTest(message=message):
                h = self.harness()
                saved = h.work / "saved.json"
                if state is not None:
                    write_json(saved, state)
                with self.assertRaisesRegex(AssertionError, message):
                    h.execute(SOURCE_MODE="saved", SAVED_STATE_PATH=str(saved))
                h.scan.assert_not_called()
                self.assert_stopped_before_plan(h)

    def test_successful_scan_with_incomplete_state_is_not_promoted(self):
        h = self.harness()
        h.next_scan_state = scan_state(complete=False)
        with self.assertRaisesRegex(AssertionError, "元スキャンの照会が未完了"):
            h.execute()
        self.assert_stopped_before_plan(h)

    def test_zero_candidates_stops_model_continuation(self):
        h = self.harness()
        h.plan_report.update(total_candidates=0, entries=[])
        with self.assertRaisesRegex(AssertionError, "一致候補が0件"):
            h.execute()
        self.assertEqual(h.events, ["scan", "plan"])
        h.plan.assert_called_once()
        h.continuation.assert_not_called()
        self.assertIn("分析候補グループ: 0", h.stdout.getvalue())
        self.assertEqual(h.snapshot.read_bytes(), h.input_state.read_bytes())

    def test_preparation_error_prints_details_and_stops_model_continuation(self):
        h = self.harness()
        h.plan_report.update(
            preparation_errors=1,
            entries=[{"id": "GHSA-fixture", "error": "fixture exceeds input budget"}],
        )
        # repo-analyze printPlan returns nonzero when any preparation fails.
        h.plan_returncode = 1
        with self.assertRaisesRegex(AssertionError, "先に候補準備エラーを確認"):
            h.execute()
        h.plan.assert_called_once()
        h.continuation.assert_not_called()
        output = h.stdout.getvalue()
        self.assertIn("準備エラー: 1", output)
        self.assertIn("GHSA-fixture fixture exceeds input budget", output)
        self.assertIn(h.plan_stderr, output)
        self.assertEqual(h.snapshot.read_bytes(), h.input_state.read_bytes())

    def test_changed_input_cannot_replace_immutable_analysis_copy(self):
        for mode in ("github", "saved"):
            with self.subTest(mode=mode):
                h = self.harness()
                h.seed_github()
                settings = {"SOURCE_MODE": mode}
                if mode == "saved":
                    settings["SAVED_STATE_PATH"] = str(h.input_state)
                h.execute(**settings)
                original = h.snapshot.read_bytes()
                write_json(h.input_state, scan_state(sha="d" * 40))
                changed = h.input_state.read_bytes()
                self.assertNotEqual(changed, original)
                self.assertEqual(h.snapshot.read_bytes(), original)
                h.plan.reset_mock()
                h.continuation.reset_mock()
                with self.assertRaisesRegex(AssertionError, "解析用stateは固定"):
                    h.execute(**settings)
                h.scan.assert_not_called()
                h.upload.assert_not_called()
                h.plan.assert_not_called()
                h.continuation.assert_not_called()
                self.assertEqual(h.snapshot.read_bytes(), original)
                self.assertEqual(h.input_state.read_bytes(), changed)


class RunWithProgressTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="colab-progress-")
        self.addCleanup(directory.cleanup)
        self.work = Path(directory.name)
        self.env = {"GOTOOLCHAIN": "auto"}
        self.process = Mock()
        self.process.stderr = StringIO("fixture scan progress\n")
        self.process.wait.return_value = 7
        self.popen = Mock(side_effect=self.start_process)
        tree = ast.parse(python_cells()[0])
        functions: list[ast.stmt] = [
            node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name == "run_with_progress"
        ]
        self.assertEqual(len(functions), 1)
        namespace = {
            "os": os, "signal": signal, "analysis_repo": self.work,
            "analysis_env": self.env,
            "subprocess": SimpleNamespace(Popen=self.popen, PIPE=subprocess.PIPE,
                                          TimeoutExpired=subprocess.TimeoutExpired),
        }
        # Do not execute uploads, downloads, installs, or builds from cell 1.
        code = compile(ast.Module(body=functions, type_ignores=[]), str(MARKDOWN), "exec")
        exec(code, namespace)  # noqa: S102
        self.run_progress = cast(Callable[..., int], namespace["run_with_progress"])

    def start_process(self, command, **kwargs):
        kwargs["stdout"].write('{"fixture": true}\n')
        return self.process

    def test_streams_progress_separately_and_returns_child_exit_code(self):
        output = self.work / "result.json"
        progress = StringIO()
        with redirect_stdout(progress):
            result = self.run_progress(["fixture-repo-scan"], output)
        self.assertEqual(result, 7)
        self.assertEqual(output.read_text(encoding="utf-8"), '{"fixture": true}\n')
        self.assertEqual(progress.getvalue(), "fixture scan progress\n")
        handle = self.popen.call_args.kwargs["stdout"]
        self.popen.assert_called_once_with(
            ["fixture-repo-scan"], cwd=self.work, env=self.env, stdout=handle,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        self.assertTrue(handle.closed)
        self.assertTrue(self.process.stderr.closed)
        self.process.wait.assert_called_once_with()
        self.process.send_signal.assert_not_called()
        self.process.kill.assert_not_called()

    def test_interrupt_signals_waits_and_only_kills_after_timeout(self):
        for times_out in (False, True):
            with self.subTest(times_out=times_out):
                self.process.reset_mock()
                self.popen.reset_mock()
                interrupt = KeyboardInterrupt("fixture cancellation")
                stderr = MagicMock()
                stderr.__iter__.side_effect = interrupt
                self.process.stderr = stderr
                self.process.poll.return_value = None
                self.process.wait.side_effect = (
                    [subprocess.TimeoutExpired("fixture-repo-scan", 15), -9]
                    if times_out else [130]
                )
                with self.assertRaises(KeyboardInterrupt) as caught:
                    self.run_progress(["fixture-repo-scan"], self.work / "interrupted.json")
                self.assertIs(caught.exception, interrupt)
                self.process.send_signal.assert_called_once_with(signal.SIGINT)
                waits = [call(timeout=15), call()] if times_out else [call(timeout=15)]
                self.assertEqual(self.process.wait.call_args_list, waits)
                if times_out:
                    self.process.kill.assert_called_once_with()
                else:
                    self.process.kill.assert_not_called()
                stderr.close.assert_called_once_with()
                self.assertTrue(self.popen.call_args.kwargs["stdout"].closed)


if __name__ == "__main__":
    unittest.main()
