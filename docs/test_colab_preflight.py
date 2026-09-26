"""Offline preflight regressions executing the actual Markdown cells 3–6.

Only the fixed warmup POST, tags GETs and runtime GET are allowed. No model,
network, installer or analysis binary is run; checkpoint bytes stay opaque.
"""

import ast
import copy
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, call

from test_colab_deep_analysis import MARKDOWN, python_cells, write_json
from test_colab_standalone import (
    LOCAL_URL,
    REMOTE_URL,
    OfflineCellTests,
    form_cell,
    preflight_payload,
)

METRICS = {
    "load_duration": 2_000_000_000,
    "prompt_eval_count": 12,
    "prompt_eval_duration": 1_000_000_000,
    "eval_count": 8,
    "eval_duration": 500_000_000,
    "total_duration": 3_500_000_000,
}


def invalid_form_cell(index, name, value):
    # Deliberately bypass the fixture's type check to exercise the cell's guard.
    tree = ast.parse(python_cells()[index - 1])
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                   and node.targets[0].id == name]
    assert len(assignments) == 1
    assignments[0].value = ast.copy_location(ast.Constant(value), assignments[0].value)
    return compile(ast.fix_missing_locations(tree), f"{MARKDOWN}:cell{index}", "exec")


class PreflightTests(OfflineCellTests):
    def setUp(self):
        super().setUp()
        self.patch("shutil.which", Mock(return_value=None))

    def prepared(self, *, base_url=LOCAL_URL, preflight_timeout=180, model=None):
        h = self.harness()
        if model is not None:
            h.results["model"] = model
        h.results["base_url"] = base_url
        write_json(h.saved_results, h.results)
        self.resume(h)
        h.namespace.update(MODEL=h.results["model"], BASE_URL=base_url,
                           run_with_progress=Mock(return_value=0))
        self.mock_ollama(h.results["model"], base_url=base_url,
                         preflight_timeout=preflight_timeout)
        self.preserved = {p: p.read_bytes() for p in
                          (h.saved_state, h.saved_results, h.snapshot, h.output)}
        return h

    def marker(self, h):
        return json.loads((h.work / "ollama-preflight.json").read_text(encoding="utf-8"))

    def assert_preserved(self, h):
        self.assertEqual({p: p.read_bytes() for p in self.preserved}, self.preserved)
        h.scan.assert_not_called()
        h.upload.assert_not_called()

    def assert_blocked(self, h, status):
        self.assertFalse(h.namespace["model_ready"])
        self.assertIsNone(h.namespace["model_ready_for"])
        self.assertIsNone(h.namespace["analysis_returncode"])
        marker = self.marker(h)
        self.assertEqual(marker["status"], status)
        self.assertEqual(marker["model"], h.results["model"])
        self.assertEqual(marker["base_url"], h.results["base_url"])
        self.assertGreaterEqual(marker["elapsed_seconds"], 0)
        self.assertIn("placement", marker["runtime"])
        self.http_post.assert_called_once()
        self.runtime.assert_called_once_with()
        with self.assertRaisesRegex(AssertionError, "先にセル3"):
            self.execute(4, h.namespace)
        h.namespace["run_with_progress"].assert_not_called()
        self.assert_preserved(h)
        return marker

    def test_successful_warmup_schema_transport_runtime_and_metrics(self):
        h = self.prepared(base_url=REMOTE_URL + "/")
        self.chat_response.json.return_value.update(METRICS)
        self.patch("time.monotonic", Mock(side_effect=[100.0, 112.25]))

        def chat():
            self.assertFalse(h.namespace["model_ready"])
            self.assertIsNone(h.namespace["model_ready_for"])
            self.runtime.assert_not_called()
            return self.chat_response

        def runtime():
            self.chat.assert_called_once_with()
            self.assertFalse(h.namespace["model_ready"])
            return self.runtime_response

        self.chat.side_effect = chat
        self.runtime.side_effect = runtime
        self.execute(3, h.namespace, BASE_URL=REMOTE_URL + "/")
        self.http_post.assert_called_once_with(
            REMOTE_URL + "/api/chat", json=preflight_payload(h.results["model"]),
            timeout=(10, 180), allow_redirects=False,
        )
        self.assertEqual(self.http.call_args_list[-1],
                         call(REMOTE_URL + "/api/ps", timeout=10, allow_redirects=False))
        self.assertGreater(len(self.http.call_args_list), 1)
        self.tags_response.raise_for_status.assert_called()
        marker = self.marker(h)
        self.assertEqual(marker, {
            "model": h.results["model"], "base_url": REMOTE_URL + "/", "status": "passed",
            "metrics": METRICS, "elapsed_seconds": 12.25,
            "runtime": {"placement": "gpu_or_mixed", "name": h.results["model"],
                        "model": None, "size": 4096, "size_vram": 2048, "context_length": 4096},
        })
        self.assertTrue(h.namespace["REQUIRE_GPU"])
        self.assertTrue(h.namespace["model_ready"])
        self.assertEqual(h.namespace["model_ready_for"], (h.results["model"], REMOTE_URL + "/"))
        text = self.stdout.getvalue()
        self.assertIn("16.0 tokens/s", text)
        self.assertIn("本分析の所要時間の保証ではありません", text)
        self.assertIn("全レイヤーのGPU実行を保証しません", text)
        self.assertIn("リポジトリ情報は送りません", text)
        h.namespace["run_with_progress"].assert_not_called()
        self.assert_preserved(h)

    def test_tagless_models_match_canonical_tags_and_gpu_without_changing_checkpoint(self):
        for model in ("qwen3", "registry.fixture.invalid:5000/team/qwen3"):
            for runtime_field in ("name", "model"):
                with self.subTest(model=model, runtime_field=runtime_field):
                    h = self.prepared(model=model)
                    canonical = model + ":latest"
                    settings = copy.deepcopy(h.namespace["resume_settings"])
                    self.tags_response.json.return_value = {"models": [{"name": canonical}]}
                    self.runtime_response.json.return_value = {
                        "models": [{runtime_field: canonical, "size_vram": 2048}],
                    }
                    self.execute(3, h.namespace)
                    self.http_post.assert_called_once_with(
                        LOCAL_URL + "/api/chat", json=preflight_payload(model),
                        timeout=(10, 180), allow_redirects=False,
                    )
                    self.runtime.assert_called_once_with()
                    marker = self.marker(h)
                    self.assertEqual(marker["status"], "passed")
                    self.assertEqual(marker["model"], model)
                    self.assertEqual(marker["runtime"]["placement"], "gpu_or_mixed")
                    self.assertEqual(marker["runtime"][runtime_field], canonical)
                    self.assertTrue(h.namespace["model_ready"])
                    self.assertEqual(h.namespace["MODEL"], model)
                    self.assertEqual(h.namespace["model_ready_for"], (model, LOCAL_URL))
                    self.assertEqual(h.namespace["resume_settings"], settings)
                    self.execute(4, h.namespace)
                    h.namespace["run_with_progress"].assert_called_once_with([
                        str(h.analysis_binary), "-state", str(h.snapshot), "-output", str(h.output),
                        "-model", model, "-base-url", LOCAL_URL, "-limit", "7",
                        "-request-timeout", "0m", "-timeout", "0h", "-require-deep", "-resume",
                    ])
                    self.assertEqual(json.loads(h.output.read_text(encoding="utf-8"))["model"], model)
                    self.assert_preserved(h)
                    self.forbidden_io.assert_not_called()  # No pull, install or server process.

    def test_differing_explicit_tags_are_not_merged_in_tags_or_runtime(self):
        for model, other in (("qwen3:8b", "qwen3:latest"), ("qwen3:8b", "qwen3:4b"),
                             ("registry.fixture.invalid:5000/team/qwen3:8b",
                              "registry.fixture.invalid:5000/team/qwen3:latest")):
            for endpoint in ("tags", "ps"):
                with self.subTest(model=model, other=other, endpoint=endpoint):
                    h = self.prepared(model=model, base_url=REMOTE_URL)
                    if endpoint == "tags":
                        self.tags_response.json.return_value = {"models": [{"name": other}]}
                        with self.assertRaisesRegex(AssertionError, "指定サーバー側でモデルを取得"):
                            self.execute(3, h.namespace, BASE_URL=REMOTE_URL)
                        self.http_post.assert_not_called()
                        self.runtime.assert_not_called()
                        self.assertFalse((h.work / "ollama-preflight.json").exists())
                        with self.assertRaisesRegex(AssertionError, "先にセル3"):
                            self.execute(4, h.namespace)
                    else:
                        self.runtime_response.json.return_value = {
                            "models": [{"name": other, "model": other, "size_vram": 2048}],
                        }
                        with self.assertRaisesRegex(RuntimeError, "unknownなら確認不能"):
                            self.execute(3, h.namespace, BASE_URL=REMOTE_URL)
                        marker = self.assert_blocked(h, "gpu_unverified")
                        self.assertEqual(marker["runtime"]["placement"], "unknown")
                        self.assertIn("対象モデルのロード状態が見つかりません", marker["runtime"]["detail"])
                    self.assertFalse(h.namespace["model_ready"])
                    self.assertIsNone(h.namespace["model_ready_for"])
                    self.assertEqual(h.namespace["MODEL"], model)
                    h.namespace["run_with_progress"].assert_not_called()
                    self.assert_preserved(h)

    def test_inference_timeout_after_successful_tags_blocks_analysis_and_bounds_logs(self):
        h = self.prepared()
        # A failed rerun must invalidate both readiness markers, not retain an old pass.
        self.execute(3, h.namespace)
        self.assertEqual(self.marker(h)["status"], "passed")
        h.namespace["analysis_returncode"] = 0
        self.mock_ollama(h.results["model"])
        timeout = self.requests.Timeout("fixture read timed out while awaiting headers")
        self.chat.side_effect = timeout
        log = h.work / "ollama.log"
        log.write_bytes(b"MUST-NOT-PRINT" + b"x" * 9000 + b"LAST-LOG-LINE\n")
        original_log = log.read_bytes()
        self.stdout.seek(0)
        self.stdout.truncate()
        with self.assertRaisesRegex(RuntimeError, "分析を開始しません") as error:
            self.execute(3, h.namespace)
        self.assertIs(error.exception.__cause__, timeout)
        self.tags_response.raise_for_status.assert_called()
        marker = self.assert_blocked(h, "failed")
        self.assertEqual(marker["error"], str(timeout))
        self.assertEqual(marker["runtime"]["placement"], "gpu_or_mixed")
        self.assertNotIn("metrics", marker)
        text = self.stdout.getvalue()
        self.assertNotIn("MUST-NOT-PRINT", text)
        self.assertEqual(text.split("Ollamaログ末尾:\n ", 1)[1],
                         original_log[-8000:].decode("utf-8") + "\n")
        self.assertEqual(log.read_bytes(), original_log)
        self.assertIn("タイムアウトだけではCPU/GPU", str(error.exception))
        self.assertIn("原因かは確定できません", str(error.exception))

    def test_malformed_incomplete_or_misformatted_reply_is_not_readiness(self):
        valid = {"done": True, "message": {"content": '{"ok":true}'}}
        cases = [
            ("invalid response JSON", ValueError("fixture malformed response JSON")),
            ("null response", None), ("array response", []), ("string response", "ok"),
            ("missing done", {"message": valid["message"]}),
            ("unfinished", {**valid, "done": False}),
            ("nonboolean done", {**valid, "done": 1}),
            ("truncated", {**valid, "done_reason": "length"}),
            ("server error", {**valid, "error": "fixture model failed"}),
            ("missing message", {"done": True}),
            ("null message", {"done": True, "message": None}),
            ("array message", {"done": True, "message": []}),
            ("missing content", {"done": True, "message": {}}),
        ]
        cases += [(f"content {content!r}", {"done": True, "message": {"content": content}})
                  for content in ("", "not JSON", '```json\n{"ok":true}\n```',
                                  '{"ok":true} extra', "null", "[]", "true", '{}',
                                  '{"ok":false}', '{"ok":1}', '{"ok":"true"}',
                                  '{"ok":true,"extra":1}', None, {"ok": True})]
        for label, result in cases:
            with self.subTest(label=label):
                h = self.prepared()
                if isinstance(result, Exception):
                    self.chat_response.json.side_effect = result
                else:
                    self.chat_response.json.return_value = result
                with self.assertRaisesRegex(RuntimeError, "分析を開始しません") as error:
                    self.execute(3, h.namespace)
                self.assertIsInstance(error.exception.__cause__, (ValueError, TypeError, AttributeError))
                marker = self.assert_blocked(h, "failed")
                self.assertIn("error", marker)
                self.assertNotIn("metrics", marker)

    def test_http_errors_and_redirects_are_not_parsed_or_followed(self):
        for status in (201, 301, 302, 307, 400, 500, 503):
            with self.subTest(status=status):
                h = self.prepared(base_url=REMOTE_URL)
                self.chat_response.status_code = status
                self.chat_response.text = "x" * 500 + "MUST-NOT-PRINT"
                with self.assertRaisesRegex(RuntimeError, "分析を開始しません"):
                    self.execute(3, h.namespace, BASE_URL=REMOTE_URL)
                marker = self.assert_blocked(h, "failed")
                self.assertEqual(marker["error"], f"/api/chat HTTP {status}: " + "x" * 500)
                self.chat_response.json.assert_not_called()
                self.assertNotIn("MUST-NOT-PRINT", self.stdout.getvalue())

    def test_cpu_and_unknown_are_distinct_and_require_explicit_opt_out(self):
        cases = [
            ("cpu", {"size_vram": 0}, "cpu"),
            ("missing VRAM", {}, "unknown"),
            ("null VRAM", {"size_vram": None}, "unknown"),
            ("negative VRAM", {"size_vram": -1}, "unknown"),
            ("string VRAM", {"size_vram": "2048"}, "unknown"),
            ("float VRAM", {"size_vram": 2048.0}, "unknown"),
            ("boolean VRAM", {"size_vram": True}, "unknown"),
            ("false VRAM", {"size_vram": False}, "unknown"),
        ]
        for label, fields, placement in cases:
            for require_gpu in (True, False):
                with self.subTest(label=label, require_gpu=require_gpu):
                    h = self.prepared()
                    self.runtime_response.json.return_value = {
                        "models": [{"name": h.results["model"], **fields}],
                    }
                    if require_gpu:
                        with self.assertRaisesRegex(RuntimeError, "REQUIRE_GPU=False"):
                            self.execute(3, h.namespace)
                        marker = self.assert_blocked(h, "gpu_unverified")
                    else:
                        self.execute(3, h.namespace, REQUIRE_GPU=False)
                        marker = self.marker(h)
                        self.assertEqual(marker["status"], "passed")
                        self.assertTrue(h.namespace["model_ready"])
                        self.assertEqual(h.namespace["model_ready_for"], (h.results["model"], LOCAL_URL))
                        self.assert_preserved(h)
                    self.assertEqual(marker["runtime"]["placement"], placement)
                    self.assertIn("metrics", marker)  # Warmup succeeded even when GPU verification did not.
                    self.assertNotIn("error", marker)

    def test_unavailable_or_malformed_runtime_stays_unknown_not_cpu(self):
        cases = [
            ("timeout", self.requests.Timeout("fixture runtime timeout")),
            ("HTTP", 500), ("redirect", 302),
            ("invalid JSON", ValueError("fixture runtime JSON")),
            ("missing models", {}), ("empty models", {"models": []}),
            ("null models", {"models": None}), ("wrong models", {"models": [None]}),
            ("null document", None), ("array document", []),
            ("other model", {"models": [{"name": "other:8b", "size_vram": 8192}]}),
        ]
        for label, result in cases:
            for require_gpu in (True, False):
                with self.subTest(label=label, require_gpu=require_gpu):
                    h = self.prepared(base_url=REMOTE_URL)
                    if isinstance(result, self.requests.RequestException):
                        self.runtime.side_effect = result
                    elif isinstance(result, ValueError):
                        self.runtime_response.json.side_effect = result
                    elif type(result) is int:
                        self.runtime_response.status_code = result
                    else:
                        self.runtime_response.json.return_value = result
                    if require_gpu:
                        with self.assertRaisesRegex(RuntimeError, "unknownなら確認不能"):
                            self.execute(3, h.namespace, BASE_URL=REMOTE_URL)
                        marker = self.assert_blocked(h, "gpu_unverified")
                    else:
                        self.execute(3, h.namespace, BASE_URL=REMOTE_URL, REQUIRE_GPU=False)
                        marker = self.marker(h)
                        self.assertEqual(marker["status"], "passed")
                        self.assertTrue(h.namespace["model_ready"])
                        self.assertEqual(h.namespace["model_ready_for"], (h.results["model"], REMOTE_URL))
                        self.assert_preserved(h)
                    self.assertEqual(marker["runtime"]["placement"], "unknown")
                    self.assertIn("detail", marker["runtime"])
                    if type(result) is int:
                        self.runtime_response.json.assert_not_called()

    def test_runtime_matches_model_field_and_positive_vram_not_total_size(self):
        h = self.prepared()
        self.runtime_response.json.return_value = {"models": [
            {"name": "unrelated:8b", "size": 100, "size_vram": 0},
            {"model": h.results["model"], "size": 8192, "size_vram": 1},
        ]}
        self.execute(3, h.namespace)
        marker = self.marker(h)
        self.assertEqual(marker["status"], "passed")
        self.assertEqual(marker["runtime"]["placement"], "gpu_or_mixed")
        self.assertEqual(marker["runtime"]["size_vram"], 1)

    def test_missing_or_unusable_metrics_do_not_crash_or_claim_throughput(self):
        for metrics in ({}, {"eval_count": 8}, {"eval_duration": 500_000_000},
                        {"eval_count": 8, "eval_duration": 0},
                        {"eval_count": 8, "eval_duration": -1},
                        {"eval_count": True, "eval_duration": 1},
                        {"eval_count": 8, "eval_duration": True},
                        {"eval_count": "8", "eval_duration": "500000000"}):
            with self.subTest(metrics=metrics):
                h = self.prepared()
                self.chat_response.json.return_value.update(metrics)
                self.stdout.seek(0)
                self.stdout.truncate()
                self.execute(3, h.namespace)
                marker = self.marker(h)
                self.assertEqual(marker["status"], "passed")
                self.assertEqual(marker["metrics"], {key: metrics.get(key) for key in METRICS})
                self.assertGreaterEqual(marker["elapsed_seconds"], 0)
                self.assertTrue(h.namespace["model_ready"])
                self.assertNotIn("tokens/s", self.stdout.getvalue())
                self.assert_preserved(h)

    def test_keyboard_interrupt_saves_marker_and_propagates_without_readiness(self):
        h = self.prepared()
        h.namespace.update(model_ready=True, model_ready_for=(h.results["model"], LOCAL_URL))
        self.chat.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.execute(3, h.namespace)
        marker = self.assert_blocked(h, "interrupted")
        self.assertNotIn("metrics", marker)
        self.assertNotIn("推論テスト成功", self.stdout.getvalue())

    def test_runtime_interrupt_replaces_stale_passed_diagnostic_before_rethrow(self):
        h = self.prepared()
        self.execute(3, h.namespace)
        self.assertEqual(self.marker(h)["status"], "passed")
        self.assertEqual(self.marker(h)["runtime"]["placement"], "gpu_or_mixed")
        self.assertTrue(h.namespace["model_ready"])
        marker_path = h.work / "ollama-preflight.json"
        previous_marker = marker_path.read_bytes()
        h.namespace["analysis_returncode"] = 0
        self.mock_ollama(h.results["model"])
        self.chat_response.json.return_value.update(METRICS)
        interrupt = KeyboardInterrupt("fixture interrupt during /api/ps")
        self.runtime.side_effect = interrupt
        self.patch("time.monotonic", Mock(side_effect=[300.0, 301.25]))
        self.stdout.seek(0)
        self.stdout.truncate()
        with self.assertRaises(KeyboardInterrupt) as error:
            self.execute(3, h.namespace)
        self.assertIs(error.exception, interrupt)
        self.chat_response.json.assert_called_once_with()
        self.assertEqual(self.http.call_args_list[-1],
                         call(LOCAL_URL + "/api/ps", timeout=10, allow_redirects=False))
        marker = self.assert_blocked(h, "interrupted")
        self.assertEqual(marker["runtime"], {
            "placement": "unknown", "detail": "実行状態の確認中に中断されました",
        })
        self.assertEqual(marker["metrics"], METRICS)
        self.assertEqual(marker["elapsed_seconds"], 1.25)
        self.assertNotEqual(marker_path.read_bytes(), previous_marker)
        text = self.stdout.getvalue()
        self.assertIn('"status": "interrupted"', text)
        self.assertIn("実行状態の確認中に中断されました", text)
        self.assertNotIn("推論テスト成功", text)

    def test_preflight_timeout_override_changes_only_transport_deadline(self):
        h = self.prepared(preflight_timeout=240)
        settings = copy.deepcopy(h.namespace["resume_settings"])
        self.execute(3, h.namespace, PREFLIGHT_TIMEOUT_SECONDS=240)
        self.http_post.assert_called_once_with(
            LOCAL_URL + "/api/chat", json=preflight_payload(h.results["model"]),
            timeout=(10, 240), allow_redirects=False,
        )
        self.assertEqual(h.namespace["resume_settings"], settings)
        self.assertEqual(self.marker(h)["status"], "passed")
        self.assert_preserved(h)

    def test_changed_model_or_url_requires_new_preflight_even_with_ready_boolean(self):
        for name, value in (("MODEL", "changed:8b"), ("BASE_URL", REMOTE_URL),
                            ("model_ready_for", None)):
            with self.subTest(name=name):
                h = self.prepared()
                self.execute(3, h.namespace)
                h.namespace[name] = value
                h.namespace["analysis_returncode"] = 0
                with self.assertRaisesRegex(AssertionError, "推論テストをやり直して"):
                    self.execute(4, h.namespace)
                self.assertIsNone(h.namespace["analysis_returncode"])
                h.namespace["run_with_progress"].assert_not_called()
                self.assert_preserved(h)

    def test_timeout_overrides_preserve_resume_arguments_and_checkpoint_bytes(self):
        h = self.prepared()
        self.execute(3, h.namespace)
        settings = copy.deepcopy(h.namespace["resume_settings"])
        marker_before = (h.work / "ollama-preflight.json").read_bytes()
        expected_calls = []
        for minutes, hours in ((0, 0), (0, 2), (15, 0), (15, 2), (30, 4), (0, 4), (1, 1)):
            self.execute(4, h.namespace, REQUEST_TIMEOUT_MINUTES=minutes,
                         ANALYSIS_TIMEOUT_HOURS=hours, LIMIT=1)
            expected_calls.append(call([
                str(h.analysis_binary), "-state", str(h.snapshot), "-output", str(h.output),
                "-model", h.results["model"], "-base-url", LOCAL_URL, "-limit", "7",
                "-request-timeout", f"{minutes}m", "-timeout", f"{hours}h", "-require-deep", "-resume",
            ]))
        self.assertEqual(h.namespace["run_with_progress"].call_args_list, expected_calls)
        self.assertEqual(h.namespace["resume_settings"], settings)
        self.assertEqual((h.work / "ollama-preflight.json").read_bytes(), marker_before)
        self.assertEqual(h.namespace["analysis_returncode"], 0)
        self.http_post.assert_called_once()
        self.assert_preserved(h)

    def test_timeout_overrides_do_not_add_resume_until_checkpoint_exists(self):
        h = self.harness()
        h.results.update(model="qwen3:8b", limit=0)
        write_json(h.saved_results, h.results)
        h.execute(SOURCE_MODE="saved", SAVED_STATE_PATH=str(h.saved_state))
        self.mock_ollama("qwen3:8b")
        self.execute(3, h.namespace)
        snapshot = h.snapshot.read_bytes()

        def checkpoint(command):
            self.assertEqual(h.snapshot.read_bytes(), snapshot)
            if not h.output.exists():
                self.assertNotIn("-resume", command)
                h.output.write_bytes(h.saved_results.read_bytes())
            return 1

        runner = Mock(side_effect=checkpoint)
        h.namespace["run_with_progress"] = runner
        self.execute(4, h.namespace, REQUEST_TIMEOUT_MINUTES=20, ANALYSIS_TIMEOUT_HOURS=3)
        checkpoint_bytes = h.output.read_bytes()
        self.execute(4, h.namespace, REQUEST_TIMEOUT_MINUTES=0, ANALYSIS_TIMEOUT_HOURS=0)
        prefix = [str(h.analysis_binary), "-state", str(h.snapshot), "-output", str(h.output),
                  "-model", "qwen3:8b", "-base-url", LOCAL_URL, "-limit", "0"]
        self.assertEqual(runner.call_args_list, [
            call(prefix + ["-request-timeout", "20m", "-timeout", "3h", "-require-deep"]),
            call(prefix + ["-request-timeout", "0m", "-timeout", "0h", "-require-deep", "-resume"]),
        ])
        self.assertEqual(h.output.read_bytes(), checkpoint_bytes)
        self.assertEqual(h.snapshot.read_bytes(), snapshot)
        self.assertEqual(h.namespace["resume_settings"], {})
        self.http_post.assert_called_once()

    def test_form_guards_reject_invalid_timeouts_before_io(self):
        for index, name in ((3, "PREFLIGHT_TIMEOUT_SECONDS"),
                            (4, "REQUEST_TIMEOUT_MINUTES"), (4, "ANALYSIS_TIMEOUT_HOURS")):
            invalid_values = (-1, True, False, 1.5, "15", None)
            if name == "PREFLIGHT_TIMEOUT_SECONDS":
                invalid_values = (0,) + invalid_values
            for value in invalid_values:
                with self.subTest(cell=index, name=name, value=value):
                    h = self.prepared()
                    h.namespace.update(model_ready=True, model_ready_for=(h.results["model"], LOCAL_URL))
                    with redirect_stdout(self.stdout), self.assertRaises(AssertionError):
                        exec(invalid_form_cell(index, name, value), h.namespace)  # noqa: S102
                    self.http.assert_not_called()
                    self.http_post.assert_not_called()
                    h.namespace["run_with_progress"].assert_not_called()
                    self.assertFalse((h.work / "ollama-preflight.json").exists())
                    self.assert_preserved(h)
                    if index == 3:
                        self.assertFalse(h.namespace["model_ready"])
                        self.assertIsNone(h.namespace["model_ready_for"])

    def test_require_gpu_must_be_an_explicit_boolean(self):
        for value in (0, 1, "False", None):
            with self.subTest(value=value):
                h = self.prepared()
                with redirect_stdout(self.stdout), self.assertRaises(AssertionError):
                    exec(invalid_form_cell(3, "REQUIRE_GPU", value), h.namespace)  # noqa: S102
                self.http.assert_not_called()
                self.http_post.assert_not_called()
                self.assertFalse(h.namespace["model_ready"])
                self.assertIsNone(h.namespace["model_ready_for"])

    def test_timeout_diagnostics_print_saved_preflight_without_asserting(self):
        for message in ("context deadline exceeded (Client.Timeout exceeded while awaiting headers)",
                        "context deadline exceeded", "Client.Timeout exceeded while awaiting headers"):
            for have_preflight in (True, False):
                with self.subTest(message=message, have_preflight=have_preflight):
                    h = self.prepared()
                    if have_preflight:
                        self.execute(3, h.namespace)
                    h.results["entries"][0]["error"] = message
                    write_json(h.output, h.results)
                    before = h.output.read_bytes()
                    h.namespace.update(display=Mock(), analysis_returncode=1)
                    self.stdout.seek(0)
                    self.stdout.truncate()
                    self.execute(5, h.namespace)
                    self.assertFalse(h.namespace["e2e_success"])
                    text = self.stdout.getvalue()
                    self.assertIn(message, text)
                    self.assertIn("REQUEST_TIMEOUT_MINUTES", text)
                    self.assertIn("短い推論テストと本分析の入力処理は別", text)
                    self.assertIn("Ollamaログ", text)
                    self.assertEqual("直近の推論テスト:" in text, have_preflight)
                    if have_preflight:
                        self.assertIn((h.work / "ollama-preflight.json").read_text(encoding="utf-8"), text)
                    self.assertNotIn("E2E成功を確認しました", text)
                    self.assertEqual(h.output.read_bytes(), before)
                    h.namespace["display"].assert_called_once()
                    h.namespace["run_with_progress"].assert_not_called()

    def test_backup_includes_preflight_after_failed_warmup_without_modifying_inputs(self):
        h = self.prepared()
        self.chat.side_effect = self.requests.Timeout("fixture timeout")
        with self.assertRaises(RuntimeError):
            self.execute(3, h.namespace)
        marker_path = h.work / "ollama-preflight.json"
        marker_before = marker_path.read_bytes()
        h.namespace["files"] = self.files
        self.execute(6, h.namespace)
        self.assertEqual(self.download.call_args_list, [
            call(str(h.snapshot)), call(str(h.output)), call(str(marker_path)),
        ])
        self.assertEqual(marker_path.read_bytes(), marker_before)
        self.assert_preserved(h)

    def test_form_fixture_keeps_unknown_and_mistyped_overrides_rejected(self):
        with self.assertRaisesRegex(ValueError, "Only model/analysis form"):
            form_cell(3, REQUEST_TIMEOUT_SECOND=5)
        with self.assertRaisesRegex(ValueError, "Invalid form override"):
            form_cell(3, REQUIRE_GPU="False")
        with self.assertRaisesRegex(ValueError, "Invalid form override"):
            form_cell(4, REQUEST_TIMEOUT_MINUTES=True)


if __name__ == "__main__":
    unittest.main()
