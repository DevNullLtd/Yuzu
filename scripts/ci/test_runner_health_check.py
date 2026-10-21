#!/usr/bin/env python3
"""Regression tests for runner-health-check.py.

Run directly; no runner access or GitHub credentials are used.
"""

from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("runner-health-check.py")
ROOT = SCRIPT.parents[2]
SPEC = importlib.util.spec_from_file_location("runner_health_check", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner_health = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner_health
SPEC.loader.exec_module(runner_health)


def runner(name: str, labels: list[str], status: str = "online") -> dict[str, object]:
    return {
        "name": name,
        "status": status,
        "busy": False,
        "labels": [{"name": label} for label in labels],
    }


class QueryRunnersTests(unittest.TestCase):
    def query(self, *, returncode: int = 0, stdout: str = "", stderr: str = ""):
        completed = subprocess.CompletedProcess([], returncode, stdout, stderr)
        with mock.patch.object(runner_health.subprocess, "run", return_value=completed):
            with redirect_stdout(io.StringIO()):
                return runner_health.query_runners()

    def test_auth_failure_is_distinct_from_api_failure(self) -> None:
        auth = self.query(returncode=1, stderr="HTTP 403: Resource not accessible")
        api = self.query(returncode=1, stderr="dial tcp: network unreachable")

        self.assertEqual(auth.state, runner_health.QueryState.AUTH_ERROR)
        self.assertEqual(api.state, runner_health.QueryState.API_ERROR)

    def test_live_actions_admin_403_is_an_authentication_failure(self) -> None:
        result = self.query(
            returncode=1,
            stderr="gh: Resource not accessible by integration (HTTP 403)",
        )
        self.assertEqual(result.state, runner_health.QueryState.AUTH_ERROR)

    def test_rate_limit_is_distinct_from_authentication_failure(self) -> None:
        result = self.query(returncode=1, stderr="HTTP 403: API rate limit exceeded")
        self.assertEqual(result.state, runner_health.QueryState.RATE_LIMIT)
        self.assertIn("rate limit", result.report.lower())

    def test_transient_api_failure_retries_three_times(self) -> None:
        payload = {"runners": [runner("linux-0", ["self-hosted", "Linux", "X64"])]}
        responses = [
            subprocess.CompletedProcess([], 1, "", "network unreachable"),
            subprocess.CompletedProcess([], 1, "", "temporary gateway error"),
            subprocess.CompletedProcess([], 0, json.dumps(payload), ""),
        ]
        with (
            mock.patch.object(runner_health.subprocess, "run", side_effect=responses) as run,
            mock.patch.object(runner_health.time, "sleep") as sleep,
        ):
            result = runner_health.query_runners()

        self.assertEqual(result.state, runner_health.QueryState.OK)
        self.assertEqual(run.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])

    def test_invalid_json_is_malformed_response(self) -> None:
        result = self.query(stdout="not-json")
        self.assertEqual(result.state, runner_health.QueryState.MALFORMED_RESPONSE)

    def test_transport_timeout_is_api_error(self) -> None:
        timeout = subprocess.TimeoutExpired(["gh", "api"], 30)
        with mock.patch.object(runner_health.subprocess, "run", side_effect=timeout):
            result = runner_health.query_runners()
        self.assertEqual(result.state, runner_health.QueryState.API_ERROR)
        self.assertIn("timed out", result.report)

    def test_missing_gh_executable_is_api_error(self) -> None:
        with mock.patch.object(
            runner_health.subprocess,
            "run",
            side_effect=FileNotFoundError("gh not found"),
        ):
            result = runner_health.query_runners()
        self.assertEqual(result.state, runner_health.QueryState.API_ERROR)
        self.assertIn("could not start", result.report)

    def test_missing_runner_schema_is_malformed_response(self) -> None:
        result = self.query(stdout=json.dumps({"total_count": 1}))
        self.assertEqual(result.state, runner_health.QueryState.MALFORMED_RESPONSE)

    def test_valid_response_is_ok(self) -> None:
        payload = {"runners": [runner("linux-0", ["self-hosted", "Linux", "X64"])]}
        result = self.query(stdout=json.dumps(payload))
        self.assertEqual(result.state, runner_health.QueryState.OK)
        self.assertEqual(result.payload, payload)

    def test_invalid_field_types_and_duplicate_names_are_rejected(self) -> None:
        malformed = {"runners": [runner("linux-0", []), runner("linux-0", [])]}
        duplicate = self.query(stdout=json.dumps(malformed))
        self.assertEqual(duplicate.state, runner_health.QueryState.MALFORMED_RESPONSE)
        malformed["runners"][0]["busy"] = "false"
        malformed["runners"].pop()
        wrong_type = self.query(stdout=json.dumps(malformed))
        self.assertEqual(wrong_type.state, runner_health.QueryState.MALFORMED_RESPONSE)


class MainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        root = Path(self.tempdir.name)
        self.inventory = root / "inventory.json"
        self.output = root / "github-output"
        self.expected = [
            {
                "name": "linux-0",
                "labels": ["self-hosted", "Linux", "X64", "yuzu-bigtam-linux"],
            },
            {
                "name": "windows-0",
                "labels": ["self-hosted", "Windows", "X64", "yuzu-weetam-windows"],
            },
            {
                "name": "bigmags-0",
                "labels": ["self-hosted", "macOS", "ARM64", "yuzu-bigmags-macos"],
            },
        ]
        self.inventory.write_text(
            json.dumps({"strict_unknown_runners": True, "expected_runners": self.expected}),
            encoding="utf-8",
        )

    def run_main(self, result, *args: str) -> tuple[int, str]:
        self.output.write_text("", encoding="utf-8")
        env = {"GITHUB_OUTPUT": str(self.output)}
        with (
            mock.patch.object(runner_health, "INVENTORY_PATH", str(self.inventory)),
            mock.patch.object(runner_health, "query_runners", return_value=result),
            mock.patch.dict(os.environ, env, clear=True),
            redirect_stdout(io.StringIO()),
        ):
            code = runner_health.main(list(args))
        return code, self.output.read_text(encoding="utf-8")

    def test_control_failure_is_red_and_emits_typed_false_outputs(self) -> None:
        result = runner_health.QueryResult(
            runner_health.QueryState.AUTH_ERROR,
            report="token rejected",
        )
        code, output = self.run_main(result, "--mode", "preflight", "--require-pool", "bigtam")

        self.assertEqual(code, 1)
        self.assertIn("bigtam_pool_healthy=false\n", output)
        self.assertIn("control_state=auth_error\n", output)
        self.assertIn("failure_kind=runner_control_error\n", output)
        self.assertIn("failure_report=token rejected\n", output)

    def test_unavailable_required_pool_is_red(self) -> None:
        payload = {
            "runners": [
                runner("linux-0", self.expected[0]["labels"], status="offline"),
                runner("windows-0", self.expected[1]["labels"]),
                runner("bigmags-0", self.expected[2]["labels"]),
            ]
        }
        result = runner_health.QueryResult(runner_health.QueryState.OK, payload=payload)
        code, output = self.run_main(
            result, "--mode", "preflight", "--require-pool", "bigtam"
        )

        self.assertEqual(code, 1)
        self.assertIn("failure_kind=required_pool_unavailable\n", output)
        self.assertIn("bigtam_pool_healthy=false\n", output)

    def test_automatic_fork_preflight_is_red_and_never_queries(self) -> None:
        with (
            mock.patch.object(runner_health, "INVENTORY_PATH", str(self.inventory)),
            mock.patch.object(runner_health, "query_runners") as query,
            mock.patch.dict(
                os.environ,
                {
                    "GITHUB_OUTPUT": str(self.output),
                    "GITHUB_EVENT_NAME": "pull_request",
                    "GITHUB_REPOSITORY": "DevNullLtd/Yuzu",
                    "GITHUB_HEAD_REPOSITORY": "contributor/Yuzu",
                },
                clear=True,
            ),
            redirect_stdout(io.StringIO()),
        ):
            code = runner_health.main(["--mode", "preflight"])

        query.assert_not_called()
        self.assertEqual(code, 1)
        output = self.output.read_text(encoding="utf-8")
        self.assertIn("control_state=auth_error\n", output)
        self.assertIn("bigtam_pool_healthy=false\n", output)
        self.assertIn("weetam_pool_healthy=false\n", output)

    def test_healthy_required_pools_pass(self) -> None:
        payload = {
            "runners": [
                runner("linux-0", self.expected[0]["labels"]),
                runner("windows-0", self.expected[1]["labels"]),
                runner("bigmags-0", self.expected[2]["labels"]),
            ]
        }
        result = runner_health.QueryResult(runner_health.QueryState.OK, payload=payload)
        code, output = self.run_main(
            result,
            "--mode", "preflight",
            "--require-pool", "bigtam",
            "--require-pool", "weetam",
            "--require-pool", "bigmags",
        )

        self.assertEqual(code, 0)
        self.assertIn("bigtam_pool_healthy=true\n", output)
        self.assertIn("weetam_pool_healthy=true\n", output)
        self.assertIn("bigmags_pool_healthy=true\n", output)
        self.assertIn("control_state=ok\n", output)

    def test_sentinel_drift_emits_issue_ready_report(self) -> None:
        payload = {
            "runners": [
                runner("linux-0", self.expected[0]["labels"], status="offline"),
                runner("windows-0", self.expected[1]["labels"]),
                runner("bigmags-0", self.expected[2]["labels"]),
            ]
        }
        result = runner_health.QueryResult(runner_health.QueryState.OK, payload=payload)
        code, output = self.run_main(result, "--mode", "sentinel")

        self.assertEqual(code, 1)
        self.assertIn("failure_kind=inventory_drift\n", output)
        self.assertIn("failure_count=1\n", output)
        self.assertIn("OFFLINE", output)

    def test_malformed_inventory_is_red_with_typed_report(self) -> None:
        self.inventory.write_text('{"expected_runners": "not-a-list"}', encoding="utf-8")

        code, output = self.run_main(
            runner_health.QueryResult(runner_health.QueryState.OK, payload={"runners": []}),
            "--mode",
            "sentinel",
        )

        self.assertEqual(code, 1)
        self.assertIn("control_state=config_error\n", output)
        self.assertIn("failure_kind=runner_control_error\n", output)
        self.assertIn("failure_report=Runner inventory cannot be trusted:", output)

    def test_non_boolean_strict_mode_is_a_config_error(self) -> None:
        self.inventory.write_text(
            json.dumps({"strict_unknown_runners": [], "expected_runners": self.expected}),
            encoding="utf-8",
        )

        code, output = self.run_main(
            runner_health.QueryResult(runner_health.QueryState.OK, payload={"runners": []}),
            "--mode",
            "sentinel",
        )

        self.assertEqual(code, 1)
        self.assertIn("control_state=config_error\n", output)

    def test_shulgi_does_not_satisfy_the_weetam_pool(self) -> None:
        self.expected[1]["labels"] = ["self-hosted", "Windows", "X64"]
        self.inventory.write_text(
            json.dumps({"strict_unknown_runners": True, "expected_runners": self.expected}),
            encoding="utf-8",
        )
        payload = {
            "runners": [
                runner("linux-0", self.expected[0]["labels"]),
                runner("windows-0", self.expected[1]["labels"]),
            ]
        }

        code, output = self.run_main(
            runner_health.QueryResult(runner_health.QueryState.OK, payload=payload),
            "--mode",
            "preflight",
            "--require-pool",
            "weetam",
        )

        self.assertEqual(code, 1)
        self.assertIn("weetam_pool_healthy=false\n", output)


class WorkflowWiringTests(unittest.TestCase):
    @staticmethod
    def job(workflow: str, name: str) -> str:
        text = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
        match = re.search(
            rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            text,
        )
        if not match:
            raise AssertionError(f"job {name!r} not found in {workflow}")
        return match.group(1)

    @staticmethod
    def meson_test_chunks() -> list[str]:
        """tests/meson.build split at every test( call; each chunk starts after it."""
        text = (ROOT / "tests" / "meson.build").read_text(encoding="utf-8")
        return re.split(r"(?m)^[ \t]*test\(", text)[1:]

    @staticmethod
    def meson_test_name(chunk: str) -> str:
        return re.match(r"\s*('[^']*')", chunk).group(1)

    def test_weetam_gate_matches_every_windows_consumer(self) -> None:
        # ci.yml's pool probe lives in the fast `preflight-gate` job (the required
        # `preflight` check carries only the source gates); nightly.yml still has
        # the one `preflight` job.
        for workflow, job_name, gate in (
            ("ci.yml", "windows", "preflight-gate"),
            ("nightly.yml", "windows-asan", "preflight"),
        ):
            with self.subTest(workflow=workflow, job=job_name):
                job = self.job(workflow, job_name)
                self.assertRegex(
                    job,
                    r"(?m)^    runs-on: \[self-hosted, Windows, X64, yuzu-weetam-windows\]$",
                )
                self.assertIn(f"needs.{gate}.outputs.weetam_pool_healthy == 'true'", job)

        for workflow, gate in (("ci.yml", "preflight-gate"), ("nightly.yml", "preflight")):
            with self.subTest(workflow=workflow):
                preflight = self.job(workflow, gate)
                self.assertIn("--require-pool weetam", preflight)
                self.assertIn("weetam_pool_healthy", preflight)

    def test_bigmags_gate_matches_every_macos_consumer(self) -> None:
        for workflow, job_name in (("ci.yml", "macos"),):
            with self.subTest(workflow=workflow, job=job_name):
                job = self.job(workflow, job_name)
                self.assertRegex(
                    job,
                    r"(?m)^    runs-on: \[self-hosted, macOS, ARM64, yuzu-bigmags-macos\]$",
                )
                self.assertIn("needs.preflight-gate.outputs.bigmags_pool_healthy == 'true'", job)

        for workflow in ("ci.yml",):
            with self.subTest(workflow=workflow):
                preflight = self.job(workflow, "preflight-gate")
                self.assertIn("--require-pool bigmags", preflight)
                self.assertIn("bigmags_pool_healthy", preflight)

    def test_preflight_context_names_are_unique(self) -> None:
        expected = {
            "ci.yml": 'name: "Preflight (runner health)"',
            "nightly.yml": 'name: "Nightly preflight (runner health)"',
            "sanitizer-tests.yml": 'name: "Sanitizer preflight (runner health)"',
        }
        for workflow, name_line in expected.items():
            with self.subTest(workflow=workflow):
                self.assertIn(name_line, self.job(workflow, "preflight"))

    def test_automatic_fork_detection_comes_from_the_event_payload(self) -> None:
        preflight = self.job("ci.yml", "preflight-gate")
        self.assertIn(
            "GITHUB_HEAD_REPOSITORY: ${{ github.event.pull_request.head.repo.full_name }}",
            preflight,
        )
        self.assertIn(
            "github.event.pull_request.head.repo.full_name != github.repository",
            preflight,
        )
        self.assertIn("steps.codegate.outputs.code_changed == 'true'", preflight)

    def test_trusted_call_uses_its_input_and_always_verifies_checkout(self) -> None:
        trusted_inputs = self.job("ci.yml", "trusted_inputs")
        gate = self.job("ci.yml", "preflight-gate")
        preflight = self.job("ci.yml", "preflight")
        self.assertIn('if [[ -z "$APPROVED_SHA" ]]', trusted_inputs)
        self.assertNotIn("EVENT_NAME", trusted_inputs)
        self.assertIn("checkout_sha=$head_sha", trusted_inputs)
        self.assertIn("trusted_execution=true", trusted_inputs)
        self.assertIn("ref: ${{ github.workflow_sha }}", gate)
        self.assertIn("- name: Verify resolved checkout", preflight)
        self.assertNotIn("if: github.event_name == 'workflow_call'", preflight)
        self.assertNotIn("if: github.event_name == 'workflow_call'", gate)

    def test_ci_preflight_split_wiring(self) -> None:
        """The required check name stays on `preflight`; the fast `preflight-gate`
        job feeds every consumer, and `preflight` fails closed on it."""
        gate = self.job("ci.yml", "preflight-gate")
        for pool in ("bigtam", "weetam", "bigmags"):
            self.assertIn(f"--require-pool {pool}", gate)
        self.assertIn("id: codegate", gate)
        self.assertIn("id: health", gate)
        self.assertIn("secrets.RUNNER_INVENTORY_TOKEN", gate)
        self.assertIn('name: "Preflight (gate)"', gate)

        preflight = self.job("ci.yml", "preflight")
        self.assertIn('name: "Preflight (runner health)"', preflight)
        self.assertIn("needs: [trusted_inputs, preflight-gate]", preflight)
        self.assertIn("if: ${{ !cancelled() }}", preflight)
        self.assertIn("needs.preflight-gate.result", preflight)
        # The only step that sees the administration-scoped token is in the gate.
        self.assertNotIn("secrets.RUNNER_INVENTORY_TOKEN", preflight)

        for job_name, pool in (
            ("proto-compat", "linux"),
            ("linux", "bigtam"),
            ("windows", "weetam"),
            ("macos", "bigmags"),
        ):
            with self.subTest(job=job_name):
                job = self.job("ci.yml", job_name)
                self.assertIn("needs: [preflight-gate]", job)
                self.assertIn(
                    f"needs.preflight-gate.outputs.{pool}_pool_healthy == 'true'", job
                )
                self.assertIn("needs.preflight-gate.outputs.code_changed == 'true'", job)
        stub = self.job("ci.yml", "docs-required-checks")
        self.assertIn("needs: [preflight-gate]", stub)
        self.assertIn("needs.preflight-gate.outputs.code_changed == 'false'", stub)
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertNotRegex(text, r"needs\.preflight\.outputs\.")

    def test_windows_suite_cover_guards_match_their_selections(self) -> None:
        """Both Windows Test steps run assert-suite-cover.py over the suites they
        really select. The pg step must exclude `platform`, or its guard fails the
        job on every debug/full run (#4884)."""
        windows = self.job("ci.yml", "windows")
        steps = [
            step
            for step in re.split(r"(?m)^      - ", windows)
            if "python scripts/ci/assert-suite-cover.py" in step
        ]
        expected = (
            (
                {"agent", "platform", "proto", "tar", "gateway", "server-nonpg", "server-checks"},
                {"server-pg", "server-pg-smoke", "docs"},
            ),
            (
                {"server-pg"},
                {"agent", "docs", "proto", "tar", "gateway", "server-nonpg", "server-checks",
                 "server-pg-smoke", "platform"},
            ),
        )
        self.assertEqual(len(expected), len(steps))
        for step, (selected, excluded) in zip(steps, expected):
            with self.subTest(selected=sorted(selected)):
                suites = re.search(r"suites=\(([^)]*)\)", step)
                self.assertIsNotNone(suites)
                self.assertEqual(selected, set(re.findall(r"--suite (\S+)", suites.group(1))))
                guard = re.search(
                    r"python scripts/ci/assert-suite-cover\.py(?:[^\n]*\\\n)*[^\n]*", step
                )
                self.assertIsNotNone(guard)
                self.assertEqual(excluded, set(re.findall(r"--exclude-suite (\S+)", guard.group(0))))
                # The guard and flake-retry share one list, so neither can drift.
                self.assertEqual(2, step.count('"${suites[@]}"'))

    def test_per_leg_suite_selectors_and_platform_entries(self) -> None:
        """docs runs on the Linux leg only; the OS-contract entries live in suite
        `platform` and run on every leg (#4884)."""
        self.assertIn(
            "--suite agent --suite docs --suite proto --suite tar --suite gateway --suite platform",
            self.job("ci.yml", "linux"),
        )
        self.assertIn("--no-suite docs", self.job("ci.yml", "macos"))
        # A dual label ('healthcheck CLI contract' is ['server', 'platform']) counts too.
        platform = {
            self.meson_test_name(chunk)
            for chunk in self.meson_test_chunks()
            if re.search(r"suite:\s*(?:'platform'|\[[^\]]*'platform'[^\]]*\])", chunk)
        }
        self.assertEqual(
            {
                "'Windows toolchain contract'",
                "'gateway build wrapper'",
                "'gateway OTP pin resolution'",
                "'instructions runner hardening'",
                "'windows sdk contract'",
                "'build_examples=false gating smoke test'",
                "'start-UAT.sh kill_stale scoping (#5333)'",
                "'capability matrix gate shell tests (#2204 F10)'",
                "'healthcheck CLI contract (#5906)'",
            },
            platform,
        )

    def test_duration_summary_follows_every_flake_retry_test_step(self) -> None:
        """meson overwrites testlog.json on each invocation, so the summary runs
        once per flake-retry Test step, against that step's own build dir."""
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertEqual(6, len(re.findall(r"scripts/ci/test-durations-summary\.py --builddir", ci)))
        for job_name, labels in (
            ("linux", ["Linux non-pg (cheap suites)", "Linux non-pg (server shards)", "Linux pg shards"]),
            ("windows", ["Windows non-pg", "Windows pg shards"]),
            ("macos", ["macOS"]),
        ):
            with self.subTest(job=job_name):
                job = self.job("ci.yml", job_name)
                summaries = list(
                    re.finditer(
                        r'scripts/ci/test-durations-summary\.py --builddir (.+?) --label "([^"]+)"', job
                    )
                )
                self.assertEqual(labels, [m.group(2) for m in summaries])
                for m in summaries:
                    runs = re.findall(r"flake-retry\.py --builddir (.+?) --", job[: m.start()])
                    self.assertTrue(runs)
                    self.assertEqual(runs[-1], m.group(1))

    def test_catch2_server_and_agent_entries_carry_durations(self) -> None:
        """The per-case summary reads Catch2's `--durations=yes` (the `=` form is
        required, see docs/ci-architecture.md). The two exemptions are deliberate:
        a ~3 s push-only smoke entry and the [tsan-heavy] checkpoints entry."""
        exempt = {"'server pg smoke'", "'agent tsan-heavy checkpoints'"}
        seen = set()
        for chunk in self.meson_test_chunks():
            m = re.match(r"\s*('[^']*'(?:\s*\+\s*\w+)?)\s*,\s*(server_test_exe|agent_test_exe)\b", chunk)
            if not m:
                continue
            seen.add(m.group(1))
            if m.group(1) not in exempt:
                with self.subTest(entry=m.group(1)):
                    self.assertIn("'--durations=yes'", chunk)
        self.assertLessEqual(exempt, seen)
        self.assertGreater(len(seen - exempt), 1)

    def test_trusted_fork_secret_and_cache_boundaries_are_explicit(self) -> None:
        wrapper = (ROOT / ".github" / "workflows" / "trusted-fork-ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("secrets: inherit", wrapper)
        self.assertIn("TRUSTED_FORK_CI_GATE: ${{ secrets.TRUSTED_FORK_CI_GATE }}", wrapper)
        self.assertIn("RUNNER_INVENTORY_TOKEN: ${{ secrets.RUNNER_INVENTORY_TOKEN }}", wrapper)

        # #4471 quarantine-ref contract. ci.yml's trusted_inputs step is covered
        # behaviourally by tests/shell/test_trusted_inputs_validate.sh, and
        # fork-dynamic-review.yml's own quarantine guard by
        # tests/shell/test_fork_dynamic_review_validate.sh (both extraction
        # harnesses) -- this string pin is a cheap structural backstop, not
        # the only net. The wrapper's purge job is the sole actions:write
        # holder, checks nothing out, and must never hand that grant to the
        # reusable gate.
        quarantine = "^refs/heads/trusted-fork/pr-${PR_NUMBER}(-[0-9a-fA-F]{7,40})?$"
        review = (ROOT / ".github" / "workflows" / "fork-dynamic-review.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(quarantine, review)
        self.assertIn(quarantine, self.job("ci.yml", "trusted_inputs"))
        purge = self.job("trusted-fork-ci.yml", "purge-quarantine-cache")
        self.assertIn("actions: write", purge)
        self.assertEqual(wrapper.count("actions: write"), 1)
        self.assertNotIn("actions/checkout", purge)
        self.assertIn("if: always()", purge)
        self.assertIn("needs: [trusted-gate]", purge)
        # The purge job's own scope guard is a separate spelling (no PR number
        # in scope there); pin it so it cannot drift or vanish unnoticed.
        self.assertIn("^refs/heads/trusted-fork/pr-[1-9][0-9]*(-[0-9a-fA-F]{7,40})?$", purge)

    def test_codeql_query_filters_are_exactly_the_documented_two(self) -> None:
        """#4471: the poisonable-step exclusion is the trade-off that stops
        alert #5177 re-firing on every preflight step; a query-id rename or an
        accidental broadening would silently reopen or over-suppress it."""
        config = (ROOT / ".github" / "codeql" / "codeql-config.yml").read_text(encoding="utf-8")
        ids = re.findall(r"(?m)^\s*-\s*exclude:\n\s*id:\s*(\S+)\s*$", config)
        self.assertEqual(
            ids,
            ["cpp/poorly-documented-function", "actions/cache-poisoning/poisonable-step"],
        )

        # linux + windows carry the full boundary: conditional clean:false
        # (safe only with their branch-switch wipe step + vcpkg sentinel) plus
        # the trusted-fork cache-isolation trio.
        for job_name in ("linux", "windows"):
            with self.subTest(job=job_name):
                job = self.job("ci.yml", job_name)
                self.assertIn(
                    "clean: ${{ needs.preflight-gate.outputs.trusted_execution == 'true' }}",
                    job,
                )
                self.assertIn("VCPKG_BINARY_SOURCES=clear", job)
                self.assertIn("CCACHE_DIR=$cache_root/ccache", job)
                self.assertIn("Purge trusted-fork workspace", job)

    def test_pr_derived_checkout_refs_stay_in_the_quarantined_workflows(self) -> None:
        """#4471: CodeQL's actions/cache-poisoning/poisonable-step is excluded in
        .github/codeql/codeql-config.yml because its model cannot see the
        trusted-fork/pr-<N> quarantine. This sweep is the in-repo replacement:
        a workflow that checks out a PR-derived ref must be one of the two that
        carry the quarantine assertion. Extending the allowlist is a security
        decision, not a routine edit. Any dispatch input or job output used as a
        checkout ref counts (deliberately broad). Only `with:` blocks written
        after the `uses:` line are inspected — every checkout in this repo is
        written that way."""
        allowed = {"ci.yml", "fork-dynamic-review.yml"}
        pr_derived = re.compile(
            r"refs/pull/|github\.event\.pull_request\.head|inputs\.|needs\.[A-Za-z0-9_-]+\.outputs\."
        )
        offenders = []
        # GitHub loads BOTH extensions ("must have either a .yml or .yaml file
        # extension" — Workflow syntax docs); adversarial-review (CDX-4471-02 /
        # kimi P2) mutation-proved that globbing only *.yml lets an offending
        # *.yaml workflow pass unseen. zizmor.yml's own grep already covers
        # both (`--include='*.yml' --include='*.yaml'`) — match that pattern.
        for path in sorted(
            p for ext in ("*.yml", "*.yaml") for p in (ROOT / ".github" / "workflows").glob(ext)
        ):
            text = path.read_text(encoding="utf-8")
            # A checkout step's `with:` block: the indented lines after the
            # `uses:` line (either `- uses:` or `- name:` + `uses:` form) up to
            # the next `- ` step.
            for step in re.finditer(
                r"(?m)^[ \t]*(?:- )?uses: actions/checkout@[^\n]*\n((?:(?![ \t]*- )[ \t]+[^\n]*\n)*)",
                text,
            ):
                ref = re.search(r"(?m)^[ \t]*ref:[ \t]*(.+)$", step.group(1))
                if ref and pr_derived.search(ref.group(1)) and path.name not in allowed:
                    offenders.append(f"{path.name}: ref: {ref.group(1).strip()}")
        self.assertEqual(offenders, [])

    def test_fork_review_guard_precedes_checkout(self) -> None:
        """#4471 (adversarial-review CDX-4471-03 / kimi K3): the extraction
        test keys on step NAME only, so a future reorder that moves the
        checkout above the quarantine-ref guard would keep every existing
        assertion green while checking out unreviewed fork code first. Pin
        the ORDER, not just the presence, of the two steps."""
        review = self.job("fork-dynamic-review.yml", "linux")
        validate_at = review.find("- name: Validate immutable inputs")
        checkout_at = review.find("- name: Check out exact PR revision")
        self.assertNotEqual(validate_at, -1)
        self.assertNotEqual(checkout_at, -1)
        self.assertLess(validate_at, checkout_at)

        # macOS deliberately keeps actions/checkout's default clean:true (a
        # fresh workspace every run is a *stronger* fork-isolation boundary; the
        # conditional clean:false form is not adopted here because its
        # branch-switch wipe step + vcpkg sentinel companions are not ported to
        # macOS — cross-run incrementality is deferred). So macOS is asserted
        # for the SAME cache-isolation trio but NOT the conditional clean
        # expression — asserting that would force clean:false with no wipe
        # companion, shipping cross-run staleness.
        with self.subTest(job="macos"):
            job = self.job("ci.yml", "macos")
            self.assertNotIn(
                "clean: ${{ needs.preflight-gate.outputs.trusted_execution == 'true' }}",
                job,
            )
            self.assertIn("VCPKG_BINARY_SOURCES=clear", job)
            self.assertIn("CCACHE_DIR=$cache_root/ccache", job)
            self.assertIn("Purge trusted-fork workspace", job)

    def test_nightly_alert_does_not_open_a_merge_block_after_cancellation(self) -> None:
        nightly = (ROOT / ".github" / "workflows" / "nightly.yml").read_text(encoding="utf-8")
        # #4018 added an `inputs.jobs != 'windows-asan'` clause so a windows-asan-only
        # dispatch doesn't comment on the shared nightly-broken issue; !cancelled()
        # (the property this test guards) is still the leading status-check function,
        # unaffected by the AND'd clause after it.
        # #4019 added `contains(needs.*.result, 'cancelled')` so a leg that hits its
        # timeout-minutes (reported `cancelled`, not `failure`) still opens the issue.
        # It must sit INSIDE the leading !cancelled(): a whole-run cancel by an operator
        # must still open nothing. Pin both the exact guard and that property.
        guard = (
            "if: ${{ !cancelled() && inputs.jobs != 'windows-asan' && "
            "(failure() || contains(needs.*.result, 'cancelled') || "
            "needs.preflight.result == 'failure') }}"
        )
        self.assertIn(guard, nightly)
        # The property, read from the ALERT job's own if: (not from `guard` above), so a
        # future edit that keeps the text elsewhere but reorders this guard still fails.
        alert = nightly[nightly.index("\n  alert:\n") :]
        alert = alert[: alert.index("\n  close-on-green:\n")]
        alert_if = next(l.strip() for l in alert.splitlines() if l.strip().startswith("if:"))
        self.assertTrue(alert_if.startswith("if: ${{ !cancelled() && "), alert_if)
        self.assertIn("contains(needs.*.result, 'cancelled')", alert_if)

    def test_sentinel_opens_an_issue_for_untyped_failures(self) -> None:
        sentinel = (ROOT / ".github" / "workflows" / "runner-inventory-sentinel.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "if: ${{ always() && steps.check.outcome == 'failure' }}",
            sentinel,
        )
        self.assertIn("runner_control_crash", sentinel)
        self.assertIn("failed before it could emit typed evidence", sentinel)


    def test_self_hosted_runner_label_lists_are_pinned_to_a_declared_pool(self) -> None:
        """A bare [self-hosted, Linux, X64] list matches every runner carrying
        those default labels, including runners outside the inventory (a retired
        runner stayed registered and took proto-compat and cache-prune jobs).
        Every self-hosted `runs-on:` / matrix `runner:` label list must carry a
        yuzu-* pool label and be a subset of some declared runner's labels.

        Covers: inline flow lists (single or multi-line), block lists, and a
        bare `runs-on: self-hosted` string, in *.yml and *.yaml workflows.
        Skips any list containing a `${{ }}` expression. Does not cover
        `runs-on: ${{ matrix.runner }}` itself (its matrix `runner:` lists are
        scanned instead), the `runs-on: {group:, labels:}` mapping form, or
        matrix keys other than `runner:`. Labels are compared case-insensitively
        and trailing `# comments` are ignored."""
        inventory = json.loads(
            (ROOT / ".github" / "runner-inventory.json").read_text(encoding="utf-8")
        )
        declared = [set(r["labels"]) for r in inventory["expected_runners"]]
        flow = re.compile(r"^[ \t-]*(?:runs-on|runner):[ \t]*\[([^\]]*)\]", re.MULTILINE)
        block = re.compile(
            r"^[ \t]*runs-on:[ \t]*\n((?:[ \t]+-[ \t]*[^\n]+\n?)+)", re.MULTILINE
        )
        string = re.compile(
            r"^[ \t]*runs-on:[ \t]*['\"]?(self-hosted)['\"]?[ \t]*(?:#.*)?$",
            re.MULTILINE | re.IGNORECASE,
        )
        offenders: list[str] = []

        def norm(raw: str) -> str:
            return raw.split("#", 1)[0].strip().strip("'\"").lower()

        declared = [{x.lower() for x in d} for d in declared]

        def check(name: str, labels: set[str], shown: str) -> None:
            if "self-hosted" not in labels or any("${{" in x for x in labels):
                return
            pooled = any(label.startswith("yuzu-") for label in labels)
            if not pooled or not any(labels <= d for d in declared):
                offenders.append(f"{name}: {shown}")

        workflows = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
        self.assertTrue(workflows)
        for path in workflows:
            text = path.read_text(encoding="utf-8")
            for m in flow.finditer(text):
                labels = {norm(p) for p in m.group(1).split(",") if norm(p)}
                check(path.name, labels, f"[{m.group(1).strip()}]")
            for m in block.finditer(text):
                labels = {
                    norm(ln.strip()[1:])
                    for ln in m.group(1).splitlines()
                    if ln.strip().startswith("-") and norm(ln.strip()[1:])
                }
                check(path.name, labels, f"block {sorted(labels)}")
            for m in string.finditer(text):
                offenders.append(f"{path.name}: runs-on: {m.group(1)} (bare string)")
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
