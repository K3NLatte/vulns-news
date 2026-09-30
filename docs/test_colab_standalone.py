"""Offline regression tests for fresh Colab setup and saved-checkpoint resume.

Execute the Markdown cells, not a rewritten implementation. All installs, Go
commands, HTTP, uploads, Ollama, and pandas are mocked. Only temporary files and
checked-in source fixtures are read/written; no notebook is regenerated here.
Go's state/prepared-input/output hash validation remains a backend concern.
"""

import ast
import base64
import copy
import hashlib
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, call, patch
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import build_colab_notebook as builder
from test_colab_deep_analysis import (
    MARKDOWN,
    Cell2Harness,
    configured_cell,
    python_cells,
    scan_state,
    write_json,
)

ROOT = MARKDOWN.parent.parent
LOCAL_URL = "http://127.0.0.1:11434"
REMOTE_URL = "https://ollama.fixture.invalid"


def source_files():
    # Real citation-fix source, but not a compilable project: builds are mocked.
    return {name: (ROOT / name.removeprefix("vulns-news/")).read_bytes()
            for name in sorted(builder.REQUIRED_SOURCE_FILES)}


def source_zip(entries=None):
    stream = BytesIO()
    with ZipFile(stream, "w", compression=ZIP_DEFLATED) as archive:
        for name, data in (source_files().items() if entries is None else entries):
            archive.writestr(name, data)
    return stream.getvalue()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def saved_state():
    state = scan_state()
    repository = state["profile"]["repository"]
    repository.update(id="github:vercel/next.js", ref="refs/heads/canary")
    state["report"].update(repository=copy.deepcopy(repository),
                           acquisition="complete", runtime_impact="unknown")
    return state


def saved_results(state, *, base_url=LOCAL_URL, limit=7):
    # Report/Entry-shaped metadata, not Go-validated prepared inputs or outputs.
    # Python must preserve these opaque hashes, never repair/recompute them.
    return {
        "schema_version": 1,
        "repository": copy.deepcopy(state["profile"]["repository"]),
        "model": "fixture-resume:8b", "base_url": base_url, "limit": limit,
        "snapshot_hash": hashlib.sha256(json_bytes(state)).hexdigest(),
        "started_at": "2026-09-26T00:00:00Z", "updated_at": "2026-09-26T00:01:00Z",
        "total_candidates": 2, "selected_candidates": 2, "not_selected": 0,
        "screened": 0, "analyzed": 0, "screening_only": 0, "excluded": 0,
        "errors": 1, "pending": 1, "selected_complete": False, "complete": False,
        "scan_refresh_complete": True, "scan_status": "complete",
        "entries": [
            {"id": "GHSA-2345-6789-cfgh", "ids": ["GHSA-2345-6789-cfgh"],
             "record_keys": ["osv:GHSA-2345-6789-cfgh"],
             "advisory_kinds": ["vulnerability"], "input_hash": "b" * 64,
             "status": "error", "stage": "screening",
             "error": "fixture citation validation failed"},
            {"id": "GHSA-jmpq-rvwx-2345", "ids": ["GHSA-jmpq-rvwx-2345"],
             "record_keys": ["osv:GHSA-jmpq-rvwx-2345"],
             "advisory_kinds": ["vulnerability"], "input_hash": "c" * 64,
             "status": "pending", "stage": "pending"},
        ],
    }


def preflight_payload(model):
    return {
        "model": model,
        "messages": [{"role": "user", "content": 'Return only {"ok":true}.'}],
        "stream": False, "think": False, "keep_alive": "15m",
        "format": {"type": "object", "properties": {"ok": {"type": "boolean", "enum": [True]}},
                   "required": ["ok"], "additionalProperties": False},
        "options": {"temperature": 0, "num_predict": 32},
    }


class MockRequestException(Exception):
    pass


class MockTimeout(MockRequestException):
    pass


def form_cell(index, **overrides):
    source = python_cells()[index - 1]
    if index == 2:
        return configured_cell(source, **overrides)
    tree = ast.parse(source)
    if overrides.keys() - {"MODEL", "BASE_URL", "LIMIT", "PREFLIGHT_TIMEOUT_SECONDS",
                           "REQUIRE_GPU", "REQUEST_TIMEOUT_MINUTES", "ANALYSIS_TIMEOUT_HOURS", "STRICT_E2E"}:
        raise ValueError("Only model/analysis form values may be overridden")
    for name, value in overrides.items():
        assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                       and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                       and node.targets[0].id == name]
        if len(assignments) != 1 or type(value) is not type(ast.literal_eval(assignments[0].value)):
            raise ValueError(f"Invalid form override: {name}")
        assignments[0].value = ast.copy_location(ast.Constant(value), assignments[0].value)
    return compile(ast.fix_missing_locations(tree), f"{MARKDOWN}:cell{index}", "exec")


def module(name, **members):
    result = ModuleType(name)
    result.__dict__.update(members)
    return result


class ResumeHarness(Cell2Harness):
    def __init__(self, work):
        super().__init__(work)
        self.output = work / "analysis-results.json"
        self.saved_state = work.parent / f"{work.name}-saved-state.json"
        self.saved_results = work.parent / f"{work.name}-saved-results.json"
        self.state = saved_state()
        self.results = saved_results(self.state)
        write_json(self.saved_state, self.state)
        write_json(self.saved_results, self.results)
        self.plan_report = {
            "total_candidates": len(self.results["entries"]), "preparation_errors": 0,
            "entries": [{"id": entry["id"]} for entry in self.results["entries"]],
        }


class OfflineCellTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="colab-standalone-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.stdout = StringIO()
        self.forbidden_io = Mock(side_effect=AssertionError("Unexpected process/network I/O"))
        self.addCleanup(self.forbidden_io.assert_not_called)
        self.upload = Mock(side_effect=AssertionError("Unexpected upload"))
        self.download = Mock()
        self.files = SimpleNamespace(upload=self.upload, download=self.download)
        self.http = Mock(side_effect=self.forbidden_io)
        self.http_post = Mock(side_effect=self.forbidden_io)
        self.requests = module("requests", get=self.http, post=self.http_post,
                               RequestException=MockRequestException, Timeout=MockTimeout)
        self.dataframe = Mock(name="DataFrame")
        colab = module("google.colab", files=self.files)
        self.patch("sys.modules", {
            "google": module("google", colab=colab), "google.colab": colab,
            "requests": self.requests,
            "pandas": module("pandas", DataFrame=self.dataframe),
        }, dictionary=True)
        for target in ("subprocess.run", "subprocess.Popen", "os.system", "os.chdir",
                       "urllib.request.urlopen", "socket.create_connection", "socket.socket",
                       "time.sleep"):
            self.patch(target, self.forbidden_io)

    def patch(self, target, value, *, dictionary=False):
        patcher = patch.dict(target, value) if dictionary else patch(target, value)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def execute(self, index, namespace, **overrides):
        with redirect_stdout(self.stdout):
            exec(form_cell(index, **overrides), namespace)  # noqa: S102

    def mock_ollama(self, model, *, base_url=LOCAL_URL, preflight_timeout=180):
        self.tags_response = Mock(status_code=200)
        self.tags_response.json.return_value = {"models": [{"name": model}]}
        self.chat_response = Mock(status_code=200)
        self.chat_response.json.return_value = {
            "done": True, "done_reason": "stop", "message": {"content": '{"ok":true}'},
        }
        self.runtime_response = Mock(status_code=200)
        self.runtime_response.json.return_value = {
            "models": [{"name": model, "size": 4096, "size_vram": 2048, "context_length": 4096}],
        }
        self.chat = Mock(return_value=self.chat_response)
        self.runtime = Mock(return_value=self.runtime_response)

        def get(url, **kwargs):
            if url == base_url + "/api/tags":
                self.assertEqual(kwargs, {"timeout": 5})
                return self.tags_response
            self.assertEqual(url, base_url.rstrip("/") + "/api/ps")
            self.assertEqual(kwargs, {"timeout": 10, "allow_redirects": False})
            return self.runtime()

        def post(url, **kwargs):
            self.assertEqual(url, base_url.rstrip("/") + "/api/chat")
            self.assertEqual(kwargs, {"json": preflight_payload(model),
                                      "timeout": (10, preflight_timeout), "allow_redirects": False})
            return self.chat()

        self.http.reset_mock()
        self.http_post.reset_mock()
        self.http.side_effect = get
        self.http_post.side_effect = post

    def harness(self):
        work = self.root / f"work-{len(list(self.root.iterdir()))}"
        work.mkdir()
        h = ResumeHarness(work)
        self.addCleanup(h.forbidden_io.assert_not_called)
        return h

    def resume(self, h):
        h.execute(SOURCE_MODE="resume", SAVED_STATE_PATH=str(h.saved_state),
                  SAVED_ANALYSIS_PATH=str(h.saved_results))


class SetupTests(OfflineCellTests):
    def setUp(self):
        super().setUp()
        self.namespace = {}
        self.go = self.root / "installed-go"
        self.go.write_bytes(b"mock executable; never run\n")
        self.go_version = "go version go1.25.0 linux/amd64\n"
        self.go_returncode = 0
        self.have_go = True
        self.have_git = True
        self.failed_package = None
        self.builds = []
        self.flags_during_commands = []
        self.commands = Mock(side_effect=self.run_command)
        self.patch("subprocess.run", self.commands)
        self.patch("shutil.which", self.which)
        real_mkdtemp = tempfile.mkdtemp

        def mkdtemp(*, prefix, dir):
            self.assertEqual(dir, "/content")
            self.assertEqual(prefix, "vulns-news-analysis-")
            return real_mkdtemp(prefix=prefix, dir=self.root)

        self.mkdtemp = Mock(side_effect=mkdtemp)
        self.patch("tempfile.mkdtemp", self.mkdtemp)
        self.patch("platform.system", lambda: "Linux")
        self.patch("platform.machine", lambda: "x86_64")

    def which(self, name):
        if name == "go":
            return str(self.go) if self.have_go else None
        if name == "git":
            return "/fixture/bin/git" if self.have_git else None
        raise AssertionError(f"Unexpected executable lookup: {name}")

    def run_command(self, command, **kwargs):
        flags = tuple(self.namespace[name] for name in
                      ("analysis_setup_ready", "analysis_ready", "model_ready"))
        self.flags_during_commands.append(flags)
        self.assertEqual(flags, (False, False, False))
        self.assertIsNone(self.namespace["model_ready_for"])
        if command == [str(self.go), "version"]:
            self.assertEqual(kwargs, {"capture_output": True, "text": True, "timeout": 120})
            return subprocess.CompletedProcess(command, self.go_returncode, self.go_version, "")
        if command in (["apt-get", "update", "-qq"], ["apt-get", "install", "-y", "git"]):
            self.assertEqual(kwargs, {"check": True, "timeout": 300})
            return subprocess.CompletedProcess(command, 0)
        self.assertEqual(command[:3], [self.namespace["bootstrap"], "build", "-o"])
        self.assertEqual(len(command), 5)
        self.assertIn(command[4], ("./cmd/repo-scan", "./cmd/repo-analyze"))
        self.assertEqual(kwargs, {"cwd": self.namespace["analysis_repo"],
                                 "env": self.namespace["analysis_env"], "check": True, "timeout": 600})
        self.builds.append(command[4])
        if command[4] == self.failed_package:
            raise subprocess.CalledProcessError(1, command, stderr="fixture build failure")
        Path(command[3]).write_bytes(b"mock built executable\n")
        return subprocess.CompletedProcess(command, 0)

    def setup(self, payload=None, *, bundled=True):
        payload = source_zip() if payload is None else payload
        if bundled:
            self.namespace.update(_BUNDLED_SOURCE_B64=base64.b64encode(payload).decode("ascii"),
                                  _BUNDLED_SOURCE_SHA256=hashlib.sha256(payload).hexdigest())
        else:
            self.upload.side_effect = None
            self.upload.return_value = {"citation-fix.zip": payload}
        self.execute(1, self.namespace)

    def mock_go_download(self, *, corrupt=False):
        archive = BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            data = b"fake downloaded Go; never executed\n"
            info = tarfile.TarInfo("go/bin/go")
            info.size, info.mode = len(data), 0o755
            tar.addfile(info, BytesIO(data))
        payload = archive.getvalue()
        release = [{"version": "go1.25.0", "files": [{
            "os": "linux", "arch": "amd64", "kind": "archive",
            "filename": "go1.25.0.linux-amd64.tar.gz",
            "sha256": "0" * 64 if corrupt else hashlib.sha256(payload).hexdigest(),
        }]}]

        def urlopen(url, *, timeout):
            if url == "https://go.dev/dl/?mode=json&include=all":
                self.assertEqual(timeout, 60)
                return BytesIO(json_bytes(release))
            self.assertEqual(url, "https://go.dev/dl/go1.25.0.linux-amd64.tar.gz")
            self.assertEqual(timeout, 180)
            return BytesIO(payload)

        return self.patch("urllib.request.urlopen", Mock(side_effect=urlopen))

    def test_builder_bundle_bootstraps_empty_namespace_without_upload_or_old_go(self):
        self.assertEqual(self.namespace, {})
        payload = source_zip()
        notebook = builder.build_notebook(MARKDOWN.read_text(encoding="utf-8"),
                                          output_name="fixture.ipynb", source_zip=payload)
        cells = ["".join(c["source"]) for c in notebook["cells"] if c["cell_type"] == "code"]
        self.assertEqual(len(cells), 6)
        with redirect_stdout(self.stdout):
            exec(compile(cells[0], "bundled-cell1", "exec"), self.namespace)  # noqa: S102
        self.upload.assert_not_called()
        self.assertNotIn("go", self.namespace)
        self.assertIs(self.namespace["analysis_setup_ready"], True)
        self.assertIs(self.namespace["analysis_ready"], False)
        self.assertIs(self.namespace["model_ready"], False)
        self.assertIsNone(self.namespace["model_ready_for"])
        self.assertIsNone(self.namespace["analysis_returncode"])
        self.assertEqual(self.namespace["resume_settings"], {})
        self.assertEqual(self.builds, ["./cmd/repo-scan", "./cmd/repo-analyze"])
        self.assertEqual(self.flags_during_commands, [(False, False, False)] * 3)
        work = self.namespace["analysis_work"]
        self.assertEqual(work.parent, self.root)
        self.assertEqual(self.namespace["analysis_output"], work / "analysis-results.json")
        self.assertFalse(self.namespace["analysis_output"].exists())
        self.assertTrue(callable(self.namespace["run_with_progress"]))
        self.assertEqual(self.namespace["analysis_env"]["GOTOOLCHAIN"], "auto")
        self.assertEqual(self.namespace["analysis_env"]["PATH"].split(os.pathsep)[0], str(self.go.parent))
        for name, content in source_files().items():
            self.assertEqual((work / name).read_bytes(), content)
        self.assertIn("generateWithCitationRetry", (work / "vulns-news/src/processor/citations.go").read_text())
        self.assertIn(hashlib.sha256(payload).hexdigest(), self.stdout.getvalue())

    def test_fresh_setup_namespace_can_resume_through_model_analysis_and_backup(self):
        self.setup()
        work = self.namespace["analysis_work"]
        state = saved_state()
        results = saved_results(state, base_url=REMOTE_URL)
        self.upload.side_effect = [
            {"scan-state.json": json_bytes(state)},
            {"analysis-results.json": json_bytes(results)},
        ]
        plan = Mock(return_value=subprocess.CompletedProcess(
            [], 0, json.dumps({"total_candidates": 2, "preparation_errors": 0}), "",
        ))
        self.patch("subprocess.run", plan)
        self.execute(2, self.namespace, SOURCE_MODE="resume")
        plan.assert_called_once_with(
            [str(self.namespace["analysis_binary"]), "-state",
             str(work / "analysis-scan-state.json"), "-plan-only"],
            cwd=self.namespace["analysis_repo"], env=self.namespace["analysis_env"],
            capture_output=True, text=True, timeout=300,
        )
        self.assertFalse(self.namespace["model_ready"])
        self.assertIsNone(self.namespace["model_ready_for"])
        self.mock_ollama(results["model"], base_url=REMOTE_URL)
        self.patch("shutil.which", Mock(return_value=None))
        self.execute(3, self.namespace, BASE_URL=REMOTE_URL)
        self.assertTrue(self.namespace["model_ready"])
        self.assertEqual(self.namespace["model_ready_for"], (results["model"], REMOTE_URL))
        self.assertEqual(self.namespace["MODEL"], results["model"])
        runner = Mock(return_value=1)
        self.namespace["run_with_progress"] = runner
        self.execute(4, self.namespace)
        command = runner.call_args.args[0]
        self.assertIn("-resume", command)
        self.assertEqual(command[command.index("-limit") + 1], str(results["limit"]))
        self.assertEqual(command[command.index("-base-url") + 1], REMOTE_URL)
        self.execute(6, self.namespace)
        self.assertEqual(self.download.call_args_list, [
            call(str(work / "analysis-scan-state.json")),
            call(str(work / "analysis-results.json")),
            call(str(work / "ollama-preflight.json")),
        ])
        self.assertEqual((work / "analysis-scan-state.json").read_bytes(), json_bytes(state))
        self.assertEqual((work / "analysis-results.json").read_bytes(), json_bytes(results))
        self.assertEqual(self.upload.call_count, 2)

    def test_unbundled_upload_and_setup_rerun_preserve_all_previous_files(self):
        original_env = dict(os.environ)
        self.setup(bundled=False)
        old_work = self.namespace["analysis_work"]
        for name in ("scan-state.json", "analysis-scan-state.json", "analysis-results.json"):
            (old_work / name).write_bytes(b"saved input/checkpoint must survive\n")
        before = {p: p.read_bytes() for p in old_work.rglob("*") if p.is_file()}
        self.namespace.update(go="obsolete-go-variable", analysis_ready=True,
                              model_ready=True, model_ready_for=("stale:8b", LOCAL_URL),
                              analysis_returncode=0, resume_settings={"limit": 3})
        self.setup()
        self.assertNotEqual(self.namespace["analysis_work"], old_work)
        self.assertEqual({p: p.read_bytes() for p in before}, before)
        self.assertEqual(dict(os.environ), original_env)
        self.upload.assert_called_once_with()
        self.assertEqual(self.namespace["bootstrap"], str(self.go))
        self.assertEqual(self.namespace["resume_settings"], {})
        self.assertIsNone(self.namespace["model_ready_for"])
        self.assertIsNone(self.namespace["analysis_returncode"])

    def test_build_failure_never_promotes_setup_or_retains_stale_readiness(self):
        for package in ("./cmd/repo-scan", "./cmd/repo-analyze"):
            with self.subTest(package=package):
                self.namespace.update(analysis_setup_ready=True, analysis_ready=True,
                                      model_ready=True, model_ready_for=("stale:8b", LOCAL_URL),
                                      analysis_returncode=0)
                self.failed_package = package
                with self.assertRaises(subprocess.CalledProcessError):
                    self.setup()
                for name in ("analysis_setup_ready", "analysis_ready", "model_ready"):
                    self.assertIs(self.namespace[name], False)
                self.assertIsNone(self.namespace["model_ready_for"])
                self.assertIsNone(self.namespace["analysis_returncode"])

    def test_bad_bundle_digest_rejected_before_extraction_or_commands(self):
        self.namespace.update(_BUNDLED_SOURCE_B64=base64.b64encode(source_zip()).decode("ascii"),
                              _BUNDLED_SOURCE_SHA256="0" * 64)
        with self.assertRaisesRegex(AssertionError, "ハッシュが一致しません"):
            self.execute(1, self.namespace)
        self.mkdtemp.assert_not_called()
        self.upload.assert_not_called()
        self.commands.assert_not_called()
        self.assertIs(self.namespace["analysis_setup_ready"], False)

    def test_missing_citation_fix_rejected_before_installs_or_builds(self):
        entries = source_files()
        del entries["vulns-news/src/processor/citations.go"]
        with self.assertRaisesRegex(AssertionError, "引用ID修正版.*citations.go"):
            self.setup(source_zip(entries.items()))
        self.commands.assert_not_called()
        self.upload.assert_not_called()
        self.assertIs(self.namespace["analysis_setup_ready"], False)

    def test_unsafe_zip_rejected_before_extracting_any_member(self):
        link = ZipInfo("vulns-news/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        for name in ("../escaped", "vulns-news/../../escaped", str(self.root / "escaped"), link):
            with self.subTest(name=name):
                entries = [*source_files().items(), (name, b"outside target")]
                with self.assertRaisesRegex(AssertionError, "安全に展開できないZIP"):
                    self.setup(source_zip(entries))
                self.assertEqual(list(self.namespace["analysis_work"].iterdir()), [])
                self.assertFalse((self.root / "escaped").exists())
                self.assertIs(self.namespace["analysis_setup_ready"], False)
        self.commands.assert_not_called()

    def test_missing_git_and_go_are_bootstrapped_only_through_mocks(self):
        self.have_git = self.have_go = False
        download = self.mock_go_download()
        self.setup()
        self.assertEqual(self.commands.call_args_list[:2], [
            call(["apt-get", "update", "-qq"], check=True, timeout=300),
            call(["apt-get", "install", "-y", "git"], check=True, timeout=300),
        ])
        self.assertEqual(download.call_count, 2)
        self.assertEqual(self.namespace["bootstrap"], str(self.namespace["analysis_work"] / "toolchain/go/bin/go"))
        self.assertTrue(Path(self.namespace["bootstrap"]).is_file())
        self.assertTrue(self.namespace["analysis_setup_ready"])

    def test_old_or_unreadable_go_version_uses_mock_download(self):
        download = self.mock_go_download()
        for stdout, returncode in (("go version go1.20.14 linux/amd64", 0), ("unknown", 0), ("", 1)):
            with self.subTest(stdout=stdout, returncode=returncode):
                self.go_version, self.go_returncode = stdout, returncode
                self.setup()
                self.assertNotEqual(self.namespace["bootstrap"], str(self.go))
                self.assertTrue(self.namespace["analysis_setup_ready"])
        self.assertEqual(download.call_count, 6)

    def test_corrupt_toolchain_download_rejected_before_build(self):
        self.have_go = False
        self.mock_go_download(corrupt=True)
        with self.assertRaises(AssertionError):
            self.setup()
        self.commands.assert_not_called()
        self.assertFalse(self.namespace["analysis_setup_ready"])


class ResumeTests(OfflineCellTests):
    def assert_not_ready(self, h):
        self.assertFalse(h.namespace["analysis_ready"])
        self.assertFalse(h.namespace["model_ready"])
        self.assertIsNone(h.namespace["model_ready_for"])
        self.assertIsNone(h.namespace["analysis_returncode"])
        self.assertEqual(h.namespace["resume_settings"], {})
        h.scan.assert_not_called()
        h.continuation.assert_not_called()

    def test_resume_uploads_two_files_once_and_reuses_them_on_rerun(self):
        h = self.harness()
        state, results = json_bytes(h.state), json_bytes(h.results)
        h.upload.side_effect = [{"analysis-scan-state.json": state}, {"analysis-results.json": results}]
        h.execute(SOURCE_MODE="resume")
        h.execute(SOURCE_MODE="resume")
        self.assertEqual(h.upload.call_args_list, [call(), call()])
        h.scan.assert_not_called()
        self.assertEqual(h.uploaded_state.read_bytes(), state)
        self.assertEqual(h.snapshot.read_bytes(), state)
        self.assertFalse(h.snapshot.samefile(h.uploaded_state))
        self.assertEqual(h.output.read_bytes(), results)
        self.assertEqual(h.planned_snapshots, [state, state])
        self.assertEqual(h.namespace["resume_settings"], {
            "model": h.results["model"], "base_url": LOCAL_URL, "limit": 7,
        })
        self.assertTrue(h.namespace["analysis_ready"])
        self.assertFalse(h.namespace["model_ready"])
        self.assertFalse(h.input_state.exists())
        self.assertFalse(h.request_file.exists())
        self.assertFalse(h.scan_result.exists())

    def test_resume_paths_ignore_github_settings_and_preserve_original_bytes(self):
        h = self.harness()
        h.seed_github(scan_state(complete=False))
        paths = [h.saved_state, h.saved_results, h.input_state, h.request_file]
        before = {p: p.read_bytes() for p in paths}
        h.execute(SOURCE_MODE="resume", SAVED_STATE_PATH=str(h.saved_state),
                  SAVED_ANALYSIS_PATH=str(h.saved_results), REPOSITORY_URL="not a repository", REF="ignored")
        self.resume(h)
        h.scan.assert_not_called()
        h.upload.assert_not_called()
        self.assertEqual({p: p.read_bytes() for p in paths}, before)
        self.assertEqual(h.snapshot.read_bytes(), before[h.saved_state])
        self.assertEqual(h.output.read_bytes(), before[h.saved_results])
        self.assertFalse(h.snapshot.samefile(h.saved_state))
        self.assertFalse(h.output.samefile(h.saved_results))

    def test_resume_rejects_repository_identity_or_sha_mismatch(self):
        for key, value in (("canonical_url", "https://github.com/other/repo"),
                           ("commit_sha", "f" * 40), ("id", "github:other/repo"), ("ref", "v-other")):
            with self.subTest(key=key):
                h = self.harness()
                h.results["repository"][key] = value
                write_json(h.saved_results, h.results)
                original = h.saved_results.read_bytes()
                with self.assertRaisesRegex(AssertionError, "リポジトリ／SHAが一致しません"):
                    self.resume(h)
                self.assert_not_ready(h)
                self.assertFalse(h.output.exists())
                self.assertEqual(h.saved_results.read_bytes(), original)
                self.assertEqual(h.snapshot.read_bytes(), h.saved_state.read_bytes())

    def test_resume_rejects_missing_checkpoint_and_invalid_upload_selection(self):
        h = self.harness()
        h.saved_results.unlink()
        with self.assertRaisesRegex(AssertionError, "途中結果がありません"):
            self.resume(h)
        h.upload.assert_not_called()
        self.assert_not_ready(h)
        for uploads in ({}, {"one.json": b"{}", "two.json": b"{}"}):
            with self.subTest(uploads=uploads):
                h = self.harness()
                h.upload.side_effect = None
                h.upload.return_value = uploads
                with self.assertRaisesRegex(AssertionError, "analysis-results.jsonを1つ"):
                    h.execute(SOURCE_MODE="resume", SAVED_STATE_PATH=str(h.saved_state))
                self.assertFalse(h.output.exists())
                self.assert_not_ready(h)

    def test_resume_rejects_missing_metadata_and_wrong_types_without_copying(self):
        template = saved_results(saved_state())
        cases = [(f"missing {key}", {k: v for k, v in template.items() if k != key})
                 for key in ("schema_version", "repository", "model", "base_url", "limit", "snapshot_hash", "entries")]
        cases += [(f"{key}={value!r}", {**template, key: value}) for key, values in (
            ("entries", (None, {}, "entries")), ("model", (None, "", "  ", 3)),
            ("base_url", (None, "", "  ", 3)), ("snapshot_hash", (None, "", "  ", 3)),
            ("limit", (-1, True, False, "7", 1.5, None)),
        ) for value in values]
        cases += [("not an object", []), ("null", None)]
        for name, value in cases:
            with self.subTest(name=name):
                h = self.harness()
                write_json(h.saved_results, value)
                original = h.saved_results.read_bytes()
                with self.assertRaisesRegex(AssertionError, "途中結果"):
                    self.resume(h)
                self.assert_not_ready(h)
                self.assertFalse(h.output.exists())
                self.assertEqual(h.saved_results.read_bytes(), original)
        h = self.harness()
        h.saved_results.write_bytes(b"{broken json")
        with self.assertRaises(json.JSONDecodeError):
            self.resume(h)
        self.assert_not_ready(h)
        self.assertFalse(h.output.exists())

    def test_resume_cannot_overwrite_different_output_or_immutable_snapshot(self):
        for changed in ("results", "state"):
            with self.subTest(changed=changed):
                h = self.harness()
                self.resume(h)
                before = {p: p.read_bytes() for p in (h.snapshot, h.output)}
                h.namespace.update(model_ready=True, model_ready_for=("stale:8b", LOCAL_URL),
                                   analysis_returncode=0)
                h.plan.reset_mock()
                h.continuation.reset_mock()
                if changed == "results":
                    h.results["updated_at"] = "2026-09-26T00:02:00Z"
                    write_json(h.saved_results, h.results)
                    message = "別の途中結果を上書きできません"
                else:
                    h.state["profile"]["repository"]["commit_sha"] = "d" * 40
                    write_json(h.saved_state, h.state)
                    message = "解析用stateは固定"
                with self.assertRaisesRegex(AssertionError, message):
                    self.resume(h)
                self.assert_not_ready(h)
                self.assertEqual({p: p.read_bytes() for p in before}, before)
                if changed == "state":
                    h.plan.assert_not_called()

    def test_saved_mode_rejects_existing_checkpoint_before_scan_upload_or_overwrite(self):
        h = self.harness()
        self.resume(h)
        paths = (h.saved_state, h.saved_results, h.snapshot, h.output)
        before = {p: p.read_bytes() for p in paths}
        h.plan.reset_mock()
        h.continuation.reset_mock()
        for state_path in ("", str(h.saved_state)):
            with self.subTest(state_path=state_path):
                h.namespace.update(analysis_ready=True, model_ready=True,
                                   model_ready_for=("stale:8b", LOCAL_URL), analysis_returncode=0)
                with self.assertRaisesRegex(AssertionError, "途中結果が既にあります。再開するならresume"):
                    h.execute(SOURCE_MODE="saved", SAVED_STATE_PATH=state_path)
                self.assert_not_ready(h)
                h.plan.assert_not_called()
                h.upload.assert_not_called()
                self.assertFalse(h.uploaded_state.exists())
                self.assertEqual({p: p.read_bytes() for p in paths}, before)

    def test_saved_mode_needs_only_state_and_leaves_no_resume_settings(self):
        h = self.harness()
        h.saved_results.unlink()
        h.execute(SOURCE_MODE="saved", SAVED_STATE_PATH=str(h.saved_state))
        h.upload.assert_not_called()
        h.scan.assert_not_called()
        self.assertTrue(h.namespace["analysis_ready"])
        self.assertEqual(h.namespace["resume_settings"], {})
        self.assertFalse(h.output.exists())

    def test_cell2_missing_setup_gives_descriptive_guard_not_name_error(self):
        for mode in ("github", "saved", "resume"):
            with self.subTest(mode=mode):
                namespace = {}
                with self.assertRaisesRegex(AssertionError, "先にセル1"):
                    self.execute(2, namespace, SOURCE_MODE=mode)
                self.assertFalse(namespace["analysis_ready"])
                self.assertFalse(namespace["model_ready"])
                self.assertIsNone(namespace["model_ready_for"])
                self.assertIsNone(namespace["analysis_returncode"])
        self.upload.assert_not_called()


class ContinuationTests(OfflineCellTests):
    def ready_namespace(self, *, base_url=LOCAL_URL):
        h = self.harness()
        h.results["base_url"] = base_url
        write_json(h.saved_results, h.results)
        self.resume(h)
        h.namespace.update(MODEL=h.results["model"], BASE_URL=base_url, model_ready=True,
                           model_ready_for=(h.results["model"], base_url))
        return h


    def test_cell3_restores_model_and_only_contacts_explicit_matching_base_url(self):
        for base_url in (LOCAL_URL, REMOTE_URL):
            with self.subTest(base_url=base_url):
                h = self.ready_namespace(base_url=base_url)
                self.mock_ollama(h.results["model"], base_url=base_url)
                self.patch("shutil.which", Mock(return_value=None))
                self.execute(3, h.namespace, BASE_URL=base_url)
                self.assertEqual(h.namespace["MODEL"], h.results["model"])
                self.assertEqual(h.namespace["BASE_URL"], base_url)
                self.assertTrue(h.namespace["model_ready"])
                self.assertEqual(h.namespace["model_ready_for"], (h.results["model"], base_url))
                self.assertGreater(self.http.call_count, 1)
                self.assertEqual(self.http.call_args_list[-1],
                                 call(base_url + "/api/ps", timeout=10, allow_redirects=False))
                for request in self.http.call_args_list[:-1]:
                    self.assertEqual(request, call(base_url + "/api/tags", timeout=5))
                self.http_post.assert_called_once_with(
                    base_url + "/api/chat", json=preflight_payload(h.results["model"]),
                    timeout=(10, 180), allow_redirects=False,
                )

    def test_cell3_localhost_checkpoint_boots_mock_local_server_without_changing_data(self):
        localhost_url = "http://localhost:11434"
        h = self.ready_namespace(base_url=localhost_url)
        h.namespace.update(os=os, model_ready=False)
        paths = (h.saved_state, h.saved_results, h.snapshot, h.output)
        before = {p: p.read_bytes() for p in paths}
        settings_before = dict(h.namespace["resume_settings"])
        ollama = str(h.work / "installed-ollama")
        self.patch("shutil.which", Mock(side_effect={"ollama": ollama, "nvidia-smi": None}.__getitem__))
        process = Mock(name="ollama_process")
        popen = self.patch("subprocess.Popen", Mock(return_value=process))
        self.mock_ollama(h.results["model"], base_url=localhost_url)
        ready_get = self.http.side_effect

        def get(url, **kwargs):
            self.assertFalse(h.namespace["model_ready"])
            self.assertIsNone(h.namespace["model_ready_for"])
            if not popen.called:
                self.assertEqual(url, localhost_url + "/api/tags")
                self.assertEqual(kwargs, {"timeout": 5})
                raise self.requests.RequestException("fixture Ollama server is not running yet")
            return ready_get(url, **kwargs)

        self.http.side_effect = get
        self.execute(3, h.namespace, BASE_URL=localhost_url)
        log = popen.call_args.kwargs["stdout"]
        popen.assert_called_once_with(
            [ollama, "serve"], env=dict(os.environ, OLLAMA_HOST="127.0.0.1:11434"),
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
        )
        self.assertEqual(Path(log.name), h.work / "ollama.log")
        self.assertTrue(log.closed)
        self.assertIs(h.namespace["ollama_process"], process)
        self.assertGreaterEqual(self.http.call_count, 2)
        self.assertTrue(h.namespace["local_ollama"])
        self.assertTrue(h.namespace["model_ready"])
        self.assertEqual(h.namespace["MODEL"], h.results["model"])
        self.assertEqual(h.namespace["BASE_URL"], localhost_url)
        self.assertEqual(h.namespace["resume_settings"], settings_before)
        self.assertEqual({p: p.read_bytes() for p in paths}, before)
        self.forbidden_io.assert_not_called()

    def test_cell3_rejects_unconfirmed_checkpoint_url_before_any_request(self):
        h = self.ready_namespace(base_url=REMOTE_URL)
        for overrides in ({}, {"BASE_URL": "https://other.fixture.invalid"}):
            with self.subTest(overrides=overrides):
                h.namespace["model_ready"] = True
                with self.assertRaisesRegex(AssertionError, "確認してBASE_URLを指定"):
                    self.execute(3, h.namespace, **overrides)
                self.assertFalse(h.namespace["model_ready"])
                self.assertIsNone(h.namespace["model_ready_for"])
                self.assertEqual(h.namespace["MODEL"], h.results["model"])
                self.http.assert_not_called()
                self.http_post.assert_not_called()
        self.assertEqual(h.output.read_bytes(), h.saved_results.read_bytes())

    def test_cell3_remote_missing_model_does_not_install_or_pull(self):
        h = self.ready_namespace(base_url=REMOTE_URL)
        self.mock_ollama("a-different-model:latest", base_url=REMOTE_URL)
        with self.assertRaisesRegex(AssertionError, "指定サーバー側でモデルを取得"):
            self.execute(3, h.namespace, BASE_URL=REMOTE_URL)
        self.assertFalse(h.namespace["model_ready"])
        self.assertIsNone(h.namespace["model_ready_for"])
        self.http_post.assert_not_called()
        self.runtime.assert_not_called()

    def test_cells3_and4_missing_preparation_give_descriptive_guards(self):
        for index in (3, 4):
            with self.subTest(cell=index), self.assertRaisesRegex(AssertionError, "先にセル2"):
                self.execute(index, {})
        for settings in ({"analysis_ready": True}, {"analysis_ready": True, "model_ready": False}):
            with self.subTest(settings=settings):
                namespace = {**settings, "analysis_returncode": 0}
                with self.assertRaisesRegex(AssertionError, "先にセル3"):
                    self.execute(4, namespace)
                self.assertIsNone(namespace["analysis_returncode"])
        self.http.assert_not_called()

    def test_cell4_restores_limit_auto_resumes_and_preserves_state_and_results(self):
        h = self.ready_namespace()
        paths = (h.saved_state, h.saved_results, h.snapshot, h.output)
        before = {p: p.read_bytes() for p in paths}
        runner = Mock(return_value=0)
        h.namespace["run_with_progress"] = runner
        for _ in range(2):
            self.execute(4, h.namespace, LIMIT=1)
        expected = [str(h.analysis_binary), "-state", str(h.snapshot), "-output", str(h.output),
                    "-model", h.results["model"], "-base-url", LOCAL_URL, "-limit", "7",
                    "-request-timeout", "0m", "-timeout", "0h", "-require-deep", "-resume"]
        self.assertEqual(runner.call_args_list, [call(expected), call(expected)])
        self.assertEqual(h.namespace["REQUEST_TIMEOUT_MINUTES"], 0)
        self.assertEqual(h.namespace["ANALYSIS_TIMEOUT_HOURS"], 0)
        self.assertIn("1リクエスト上限=なし、今回の実行上限=なし", self.stdout.getvalue())
        self.assertIn("手動停止可能", self.stdout.getvalue())
        self.assertEqual(h.namespace["LIMIT"], 7)
        self.assertEqual(h.namespace["analysis_returncode"], 0)
        self.assertEqual({p: p.read_bytes() for p in paths}, before)
        h.scan.assert_not_called()
        h.upload.assert_not_called()

    def test_cell4_first_analysis_omits_resume_then_rerun_adds_it(self):
        h = self.harness()
        h.execute(SOURCE_MODE="saved", SAVED_STATE_PATH=str(h.saved_state))
        h.namespace.update(MODEL="fixture:8b", BASE_URL=LOCAL_URL, model_ready=True,
                           model_ready_for=("fixture:8b", LOCAL_URL))
        snapshot = h.snapshot.read_bytes()

        def checkpoint(command):
            self.assertEqual(h.snapshot.read_bytes(), snapshot)
            h.output.write_bytes(json_bytes(h.results))
            return 1

        runner = Mock(side_effect=checkpoint)
        h.namespace["run_with_progress"] = runner
        self.execute(4, h.namespace)
        self.assertNotIn("-resume", runner.call_args.args[0])
        self.assertEqual(h.namespace["LIMIT"], 0)
        self.assertEqual(h.namespace["analysis_returncode"], 1)
        self.execute(4, h.namespace)
        self.assertIn("-resume", runner.call_args.args[0])
        self.assertEqual(h.snapshot.read_bytes(), snapshot)

    def test_cell4_interrupt_or_failure_preserves_checkpoint_and_reports_status(self):
        for result in (1, KeyboardInterrupt()):
            with self.subTest(result=result):
                h = self.ready_namespace()
                before = {p: p.read_bytes() for p in (h.snapshot, h.output)}
                runner = Mock(return_value=result) if isinstance(result, int) else Mock(side_effect=result)
                h.namespace.update(run_with_progress=runner, analysis_returncode=0)
                self.execute(4, h.namespace)
                self.assertEqual(h.namespace["analysis_returncode"], result if isinstance(result, int) else None)
                self.assertEqual({p: p.read_bytes() for p in before}, before)
                self.assertIn("終了コード:", self.stdout.getvalue())
                if isinstance(result, KeyboardInterrupt):
                    self.assertIn("同じセルで再開できます", self.stdout.getvalue())

    def test_cell5_guards_missing_setup_or_results_without_name_error(self):
        with self.assertRaisesRegex(AssertionError, "先にセル1"):
            self.execute(5, {})
        with self.assertRaisesRegex(AssertionError, "解析結果がまだ保存されていません"):
            self.execute(5, {"analysis_setup_ready": True, "analysis_output": self.root / "missing.json"})
        self.dataframe.assert_not_called()

    def test_cell5_prints_saved_errors_without_rejecting_failed_analysis(self):
        h = self.ready_namespace()
        display = Mock()
        h.namespace.update(display=display, analysis_returncode=1)
        before = h.output.read_bytes()
        self.execute(5, h.namespace)
        text = self.stdout.getvalue()
        self.assertIn("fixture citation validation failed", text)
        self.assertIn("GHSA-2345-6789-cfgh", text)
        self.assertIn("Deep Analysis済みFeed: 0", text)
        self.assertNotIn("到達を確認しました", text)
        rows = self.dataframe.call_args.args[0]
        self.assertEqual(rows[0]["error"], h.results["entries"][0]["error"])
        self.assertFalse(rows[0]["deep_completed"])
        display.assert_called_once_with(self.dataframe.return_value)
        self.dataframe.return_value.to_csv.assert_called_once_with(h.work / "analysis-matrix.csv", index=False)
        self.assertEqual(h.output.read_bytes(), before)

    def test_cell5_diagnostic_outcomes_and_opt_in_strict_assertions(self):
        # Backend-shaped reports: the Python diagnostic must not confuse a later
        # successful candidate with successful completion of the whole run.
        cases = [
            ("candidate_error_then_success", 1, 1, 0, 0, True, False),
            ("pending", 0, 0, 1, 0, True, False),
            ("interrupted", None, 0, 1, 0, True, False),
            ("unknown_exit", None, 0, 0, 0, True, False),
            ("checkpoint_failure", 1, 0, 0, 0, True, False),
            ("all_unknown", 1, 0, 0, 0, False, False),
            ("no_deep_even_exit_zero", 0, 0, 0, 0, False, False),
            ("limited", 0, 0, 0, 1, True, False),
            ("complete", 0, 0, 0, 0, True, True),
        ]
        for name, code, errors, pending, not_selected, deep, success in cases:
            for strict in (False, True):
                with self.subTest(case=name, strict=strict):
                    h = self.ready_namespace()
                    entries = []
                    if errors:
                        entries.append({"id": "failed-first", "advisory_kinds": ["unknown"],
                                        "status": "screening_error", "stage": "screening",
                                        "error": "fixture citation validation failed"})
                    entries.append({"id": "later-success", "advisory_kinds": ["unknown"],
                                    "status": "analyzed" if deep else "screening_only",
                                    "stage": "complete", "analysis": {} if deep else None,
                                    "feed": {"status": "analyzed" if deep else "screening_only"},
                                    "screening": {"result": {"relevance": "related" if deep else "unknown",
                                                              "evidence_ids": ["EVD-legacy"]}}})
                    for status, count in (("pending", pending), ("not_selected", not_selected)):
                        entries.extend({"id": status, "advisory_kinds": ["unknown"],
                                        "status": status, "stage": status} for _ in range(count))
                    report = dict(h.results, errors=errors, pending=pending,
                                  not_selected=not_selected, entries=entries,
                                  total_candidates=len(entries), selected_candidates=len(entries) - not_selected,
                                  screened=1, analyzed=int(deep), screening_only=int(not deep),
                                  selected_complete=not (errors or pending),
                                  complete=not (errors or pending or not_selected))
                    h.output.write_bytes(json_bytes(report))
                    before = h.output.read_bytes()
                    h.namespace.update(display=Mock(), analysis_returncode=code)
                    self.stdout.seek(0)
                    self.stdout.truncate()
                    self.dataframe.reset_mock()
                    if strict and not success:
                        with self.assertRaisesRegex(AssertionError, "全候補のE2E条件"):
                            self.execute(5, h.namespace, STRICT_E2E=True)
                    else:
                        self.execute(5, h.namespace, STRICT_E2E=strict)
                    text = self.stdout.getvalue()
                    self.assertIn(f"終了コード: {code}", text)
                    self.assertIn(f"pending={pending} errors={errors}", text)
                    self.assertIn(f"Deep Analysis済みFeed: {int(deep)}", text)
                    self.assertEqual("E2E成功を確認しました" in text, success)
                    self.assertEqual("件数制限による未選択" in text, bool(not_selected))
                    self.assertEqual(h.namespace["e2e_success"], success)
                    self.dataframe.return_value.to_csv.assert_called_once_with(
                        h.work / "analysis-matrix.csv", index=False)
                    h.namespace["display"].assert_called_once()
                    self.assertEqual(h.output.read_bytes(), before)
                    if errors:
                        self.assertIn("fixture citation validation failed", text)
                        self.assertEqual(self.dataframe.call_args.args[0][1]["feed_status"], "analyzed")

    def test_cell6_guard_and_backup_before_any_results_exist(self):
        with self.assertRaisesRegex(AssertionError, "先にセル1"):
            self.execute(6, {})
        namespace = {"analysis_setup_ready": True, "analysis_work": self.root, "files": self.files}
        self.execute(6, namespace)
        self.download.assert_not_called()
        self.assertIn("まだ作成されていません: scan-state.json", self.stdout.getvalue())
        self.assertIn("まだ作成されていません: analysis-results.json", self.stdout.getvalue())
        self.assertIn("まだ作成されていません: ollama-preflight.json", self.stdout.getvalue())
        scan = self.root / "scan-state.json"
        scan.write_bytes(b"original scan")
        self.execute(6, namespace)
        self.download.assert_called_once_with(str(scan))
        self.assertEqual(scan.read_bytes(), b"original scan")

    def test_cell6_prefers_immutable_snapshot_and_includes_saved_results(self):
        h = self.ready_namespace()
        h.namespace["files"] = self.files
        h.input_state.write_bytes(b"new monitor state, not the analysis snapshot")
        before = {p: p.read_bytes() for p in (h.input_state, h.snapshot, h.output)}
        self.execute(6, h.namespace)
        self.assertEqual(self.download.call_args_list, [call(str(h.snapshot)), call(str(h.output))])
        self.assertEqual({p: p.read_bytes() for p in before}, before)


if __name__ == "__main__":
    unittest.main()
