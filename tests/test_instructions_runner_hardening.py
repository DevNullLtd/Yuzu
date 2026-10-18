#!/usr/bin/env python3
"""test_instructions_runner_hardening.py - the destructive/forensic path of the /test
--instructions runner against a fake Yuzu server (#5261, governance round).

A targeted run changes or reads a real device, so these tests drive ir.main() end to end against
an in-process HTTP server on an ephemeral 127.0.0.1 port and assert what the server SAW: which
POSTs arrived, with which body, and whether the manifest line existed when each one did. Covers
the override gate, the override file, the proxy bypass, abort and error handling, the strict
grading of those two classes, the target pre-flight and its confirmation, and attribution.

Runnable standalone: `python3 tests/test_instructions_runner_hardening.py`. Hermetic: loopback
sockets on ephemeral ports and temp dirs only; the test-runs DB writers are replaced.
"""
import contextlib
import http.server
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "test"))
import instructions_runner as ir  # noqa: E402

AGENT = "agent-under-test"
HOSTNAME = "Box-1"
RUN_ID = "run-5261"
GOOD = [{"output": "x", "status": "ok", "rc": 0}]


class FakeYuzu:
    """Just enough of the dashboard: /login, /api/agents, the execute route and /api/responses."""

    def __init__(self):
        self.posts = []        # {"id", "body", "ua", "manifest": text of the manifest at receipt}
        self.requests = []     # (method, path, user-agent) for every request
        self.logins = 0
        self.inflight = 0
        self.max_inflight = 0
        self.manifest_path = None
        self.agents = [{"agent_id": AGENT, "hostname": HOSTNAME, "os": "linux", "arch": "x86_64",
                        "agent_version": "9.9.9"}]
        self.agents_code = 200
        self.responses = GOOD
        self.responses_raw = None      # bytes: replaces the /api/responses body
        self.execute = None            # callable(post) -> (code, bytes, delay_s) or None
        self._lock = threading.Lock()
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, delay=0.0):
                if delay:
                    time.sleep(delay)
                try:
                    self.send_response(code)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass

            def do_GET(self):
                fake.requests.append(("GET", self.path, self.headers.get("User-Agent")))
                if self.path == "/api/agents":
                    self._send(fake.agents_code, json.dumps(fake.agents).encode())
                elif self.path.startswith("/api/responses/"):
                    body = fake.responses_raw if fake.responses_raw is not None else \
                        json.dumps({"responses": fake.responses}).encode()
                    self._send(200, body)
                else:
                    self._send(404, b"{}")

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                ua = self.headers.get("User-Agent")
                fake.requests.append(("POST", self.path, ua))
                if self.path == "/login":
                    fake.logins += 1
                    self._send(200, b"{}")
                    return
                text = ""
                if fake.manifest_path and Path(fake.manifest_path).exists():
                    text = Path(fake.manifest_path).read_text(encoding="utf-8")
                post = {"id": self.path.split("/")[3], "body": json.loads(raw), "ua": ua,
                        "manifest": text}
                with fake._lock:
                    fake.posts.append(post)
                    fake.inflight += 1
                    fake.max_inflight = max(fake.max_inflight, fake.inflight)
                try:
                    code, body, delay = fake.execute(post) if fake.execute else \
                        (200, json.dumps({"command_id": "c-" + post["id"]}).encode(), 0.0)
                    self._send(code, body, delay)
                finally:
                    with fake._lock:
                        fake.inflight -= 1

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def posted_ids(self):
        return [p["id"] for p in self.posts]


def definition(def_id, risk, *, plugin="p", required=(), properties=(), platforms=()):
    return {"id": def_id, "risk": risk, "plugin": plugin, "required": list(required),
            "properties": list(properties), "platforms": list(platforms)}


def write_content(tmp, defs):
    content = Path(tempfile.mkdtemp(prefix="yuzu_test_defs_", dir=tmp))
    for d in defs:
        props = "".join(f"      {p}: {{type: string}}\n" for p in d["properties"] or d["required"])
        lines = [
            "apiVersion: yuzu.io/v1alpha1", "kind: InstructionDefinition",
            "metadata:", f"  id: {d['id']}", "spec:", "  type: action",
            f"  platforms: {json.dumps(d['platforms'])}", "  execution:",
            f"    plugin: {d['plugin']}", "    action: a",
        ]
        if props:
            lines += ["  parameters:", f"    required: {json.dumps(d['required'])}",
                      "    properties:"] + props.rstrip("\n").split("\n")
        (content / f"{d['id']}.yaml").write_text("\n".join(lines) + "\n")
    table = Path(tmp) / "risk.json"
    table.write_text(json.dumps({"_overrides": {d["id"]: d["risk"] for d in defs}}))
    return content, table


class Result:
    def __init__(self, rc, out, err, summary, manifest):
        self.rc, self.out, self.err, self.summary, self.manifest = rc, out, err, summary, manifest

    def outcome(self, def_id):
        return next(o for o in self.summary["outcomes"] if o["id"] == def_id)


class RunnerCase(unittest.TestCase):
    """Per-test fake server, temp dir and stubbed test-runs DB writers."""

    def setUp(self):
        self.fake = FakeYuzu()
        self.addCleanup(self.fake.close)
        self._tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_runner_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.metrics = []
        for name, sink in (("db_record_timing", []), ("db_record_metric", self.metrics)):
            p = mock.patch.object(ir, name, lambda *a, _s=sink, **k: _s.append(a))
            p.start()
            self.addCleanup(p.stop)
        self.fake.manifest_path = str(self.tmp / "manifest.jsonl")

    def run_runner(self, defs, *, overrides=None, raw_overrides=None, risks=("destructive",),
                   targeted=True, extra=(), dashboard=None, patch_as_completed=None):
        content, table = write_content(self.tmp, defs)
        argv = ["--dashboard", dashboard or self.fake.url, "--password", "p",
                "--content-dir", str(content), "--risk-table", str(table),
                "--risks", *risks, "--poll-timeout", "5",
                "--output", str(self.tmp / "out.json"),
                "--manifest", self.fake.manifest_path]
        if targeted:
            argv += ["--target-agent-id", AGENT, "--confirm-target", HOSTNAME, "--run-id", RUN_ID]
        if overrides is not None or raw_overrides is not None:
            path = self.tmp / "overrides.json"
            path.write_text(raw_overrides if raw_overrides is not None else json.dumps(overrides))
            argv += ["--params-override", str(path)]
        argv += list(extra)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
            if patch_as_completed:
                stack.enter_context(mock.patch.object(ir.concurrent.futures, "as_completed",
                                                      patch_as_completed))
            rc = ir.main(argv)
        outfile = self.tmp / "out.json"
        summary = json.loads(outfile.read_text()) if outfile.exists() else None
        mf = Path(self.fake.manifest_path)
        manifest = [json.loads(line) for line in mf.read_text().splitlines()] if mf.exists() else []
        return Result(rc, out.getvalue(), err.getvalue(), summary, manifest)


class OverrideGate(RunnerCase):
    DEFS = [definition("t.clear", "destructive", properties=["opt"]),
            definition("t.path", "destructive", required=["path", "mode"]),
            definition("t.other", "destructive", required=["a"], properties=["a", "b"])]

    def test_typod_id_dispatches_nothing_and_exits_2_before_login(self):
        r = self.run_runner(self.DEFS, overrides={"t.clea": {}})
        self.assertEqual(r.rc, 2)
        self.assertIn("covered by --params-override", r.err)
        self.assertEqual((self.fake.posts, self.fake.logins), ([], 0))

    def test_no_override_file_at_all_dispatches_nothing(self):
        r = self.run_runner(self.DEFS)
        self.assertEqual((r.rc, self.fake.posts, self.fake.logins), (2, [], 0))

    def test_bad_override_file_exits_2_before_login(self):
        for label, raw in (("malformed", "{nope"), ("list", "[]"), ("string entry", '{"t.clear": 1}')):
            with self.subTest(label):
                r = self.run_runner(self.DEFS, raw_overrides=raw)
                self.assertEqual((r.rc, self.fake.posts, self.fake.logins), (2, [], 0))
                self.assertIn("--params-override", r.err)

    def test_missing_override_file_exits_2_before_login(self):
        r = self.run_runner(self.DEFS, extra=["--params-override", str(self.tmp / "absent.json")])
        self.assertEqual((r.rc, self.fake.posts, self.fake.logins), (2, [], 0))
        self.assertIn("--params-override", r.err)

    def test_gate_matrix_in_one_run(self):
        r = self.run_runner(self.DEFS, overrides={
            "t.clear": {},                  # parameterless: {} is a real entry
            "t.path": {"path": "/x"},       # lacks 'mode'
            "t.other": {"a": "1"},          # covers the required 'a' only
            "t.safe_entry_for_another_class": {"zz": "1"},
        })
        self.assertEqual(r.rc, 0, r.err)
        by_id = {p["id"]: p for p in self.fake.posts}
        self.assertEqual(sorted(by_id), ["t.clear", "t.other"])
        # {} is the whole params object even though the definition declares an optional 'opt'
        self.assertEqual(by_id["t.clear"]["body"], {"params": {}, "agent_ids": [AGENT]})
        # replaced, never merged: no synthesised value for the optional sibling 'b'
        self.assertEqual(by_id["t.other"]["body"], {"params": {"a": "1"}, "agent_ids": [AGENT]})
        skipped = r.outcome("t.path")
        self.assertEqual(skipped["status"], "skip")
        self.assertIn("lacks required", skipped["note"])
        self.assertFalse(skipped["dispatched"])

    def test_empty_entry_for_a_definition_with_required_params_is_skipped(self):
        r = self.run_runner(self.DEFS, overrides={"t.clear": {}, "t.path": {}})
        self.assertEqual(self.fake.posted_ids(), ["t.clear"])
        self.assertEqual(r.outcome("t.path")["status"], "skip")

    def test_no_entry_is_skipped_with_a_note(self):
        r = self.run_runner(self.DEFS, overrides={"t.clear": {}})
        self.assertEqual(self.fake.posted_ids(), ["t.clear"])
        self.assertIn("no --params-override entry", r.outcome("t.other")["note"])

    def test_safe_definitions_keep_synthesised_params_and_get_no_target(self):
        defs = [definition("t.safe", "safe", required=["host"]), definition("t.clear", "destructive")]
        r = self.run_runner(defs, risks=("safe", "destructive"), overrides={"t.clear": {}})
        self.assertEqual(r.rc, 0, r.err)
        safe = next(p for p in self.fake.posts if p["id"] == "t.safe")
        self.assertEqual(safe["body"], {"params": {"host": "127.0.0.1"}})

    def test_server_rows_are_skipped_even_with_an_override(self):
        defs = [definition("server.x", "destructive", plugin="server_internal"),
                definition("t.clear", "destructive")]
        r = self.run_runner(defs, overrides={"server.x": {}, "t.clear": {}})
        self.assertEqual(self.fake.posted_ids(), ["t.clear"])
        self.assertIn("server-internal: never dispatched with a target",
                      r.outcome("server.x")["note"])


class Attribution(RunnerCase):
    def test_manifest_line_exists_before_each_post_and_requests_are_attributed(self):
        defs = [definition(f"t.d{i}", "destructive") for i in range(3)]
        r = self.run_runner(defs, overrides={d["id"]: {} for d in defs}, extra=["--parallelism", "4"])
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(len(self.fake.posts), 3)
        for post in self.fake.posts:
            seen = [json.loads(line) for line in post["manifest"].splitlines()]
            self.assertIn(post["id"], [m["id"] for m in seen], "manifest line must precede the POST")
        for m in r.manifest:
            self.assertEqual((m["run_id"], m["target_agent_id"], m["risk"], m["params"]),
                             (RUN_ID, AGENT, "destructive", {}))
            self.assertRegex(m["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual({ua for _, _, ua in self.fake.requests}, {f"yuzu-instructions-runner/{RUN_ID}"})

    def test_targeted_definitions_run_one_at_a_time(self):
        defs = [definition(f"t.d{i}", "destructive") for i in range(4)]
        self.fake.execute = lambda post: (200, json.dumps({"command_id": "c"}).encode(), 0.1)
        r = self.run_runner(defs, overrides={d["id"]: {} for d in defs}, extra=["--parallelism", "4"])
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(self.fake.max_inflight, 1)
        self.assertIn("one at a time", r.out)

    def test_summary_banner_and_metric(self):
        defs = [definition("t.clear", "destructive"), definition("t.path", "destructive", required=["p"])]
        r = self.run_runner(defs, overrides={"t.clear": {}})
        self.assertIn("TARGETED RUN target=agent-under-test host=Box-1 os=linux version=9.9.9", r.out)
        self.assertIn("covered=1 skipped=1", r.out)
        self.assertIn("1 of 2 definitions dispatched; 0 pending_approval, 1 skipped", r.out)
        s = r.summary
        self.assertEqual((s["target_agent_id"], s["dashboard"], s["user"], s["skipped"], s["manifest"],
                          s["risks"]),
                         (AGENT, self.fake.url, "admin", 1, self.fake.manifest_path, ["destructive"]))
        self.assertIn(("instructions_targeted_dispatched", 1),
                      [(a[2], a[3]) for a in self.metrics if a[2] == "instructions_targeted_dispatched"])

    def test_a_target_with_padding_is_sent_stripped(self):
        r = self.run_runner([definition("t.clear", "destructive")], overrides={"t.clear": {}},
                            targeted=False, extra=["--target-agent-id", f"  {AGENT} ",
                                                   "--confirm-target", HOSTNAME, "--run-id", RUN_ID])
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(self.fake.posts[0]["body"]["agent_ids"], [AGENT])

    def test_a_targeted_run_without_run_id_exits_2(self):
        r = self.run_runner([definition("t.clear", "destructive")], overrides={"t.clear": {}},
                            targeted=False, extra=["--target-agent-id", AGENT,
                                                   "--confirm-target", HOSTNAME])
        self.assertEqual((r.rc, self.fake.posts, self.fake.logins), (2, [], 0))
        self.assertIn("--run-id", r.err)


class Preflight(RunnerCase):
    DEFS = [definition("t.clear", "destructive")]
    OV = {"t.clear": {}}

    def refused(self, r):
        self.assertEqual(r.rc, 2, r.err)
        self.assertEqual(self.fake.posts, [])

    def test_unknown_id(self):
        self.fake.agents = [dict(self.fake.agents[0], agent_id="someone-else")]
        self.refused(self.run_runner(self.DEFS, overrides=self.OV))

    def test_offline_id(self):
        self.fake.agents = [dict(self.fake.agents[0], online=False)]
        r = self.run_runner(self.DEFS, overrides=self.OV)
        self.refused(r)
        self.assertIn("offline", r.err)

    def test_hostname_mismatch(self):
        r = self.run_runner(self.DEFS, overrides=self.OV, targeted=False,
                            extra=["--target-agent-id", AGENT, "--confirm-target", "Other-Box",
                                   "--run-id", RUN_ID])
        self.refused(r)
        self.assertIn("does not match", r.err)

    def test_missing_confirm_target(self):
        r = self.run_runner(self.DEFS, overrides=self.OV, targeted=False,
                            extra=["--target-agent-id", AGENT, "--run-id", RUN_ID])
        self.refused(r)
        self.assertEqual(self.fake.logins, 0)

    def test_unreadable_endpoint(self):
        self.fake.agents_code = 500
        r = self.run_runner(self.DEFS, overrides=self.OV)
        self.refused(r)
        self.assertIn("cannot read the agent list", r.err)

    def test_confirmation_is_case_insensitive_and_posts(self):
        r = self.run_runner(self.DEFS, overrides=self.OV, targeted=False,
                            extra=["--target-agent-id", AGENT, "--confirm-target", HOSTNAME.upper(),
                                   "--run-id", RUN_ID])
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(self.fake.posted_ids(), ["t.clear"])

    def test_platform_skip_uses_the_targets_os(self):
        self.fake.agents = [dict(self.fake.agents[0], os="windows")]
        defs = [definition("t.win", "destructive", platforms=["windows"]),
                definition("t.nix", "destructive", platforms=["linux"])]
        r = self.run_runner(defs, overrides={"t.win": {}, "t.nix": {}})
        self.assertEqual(self.fake.posted_ids(), ["t.win"])
        self.assertIn("target os=windows", r.outcome("t.nix")["note"])


class ProxyBypass(RunnerCase):
    def test_opener_has_no_proxy_handler_even_with_a_proxy_environment(self):
        # ProxyHandler({}) registers no protocol methods, so it is not kept in `handlers`; what
        # it does is stop build_opener adding the default one, which would read these variables.
        with mock.patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:9", "HTTP_PROXY":
                                          "http://127.0.0.1:9"}):
            opener = ir.YuzuClient("http://127.0.0.1:1").opener
        self.assertEqual([h for h in opener.handlers
                          if isinstance(h, ir.urllib.request.ProxyHandler)], [])

    def test_proxy_environment_is_never_used(self):
        proxy = socket.socket()
        proxy.bind(("127.0.0.1", 0))
        proxy.listen(5)
        proxy.settimeout(0.2)
        self.addCleanup(proxy.close)
        url = f"http://127.0.0.1:{proxy.getsockname()[1]}"
        env = {k: url for k in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY")}
        env.update({"no_proxy": "", "NO_PROXY": ""})
        with mock.patch.dict(os.environ, env):
            r = self.run_runner([definition("t.safe", "safe")], risks=("safe",), targeted=False)
        self.assertEqual(r.rc, 0, r.err)
        self.assertGreater(len(self.fake.requests), 0)
        with self.assertRaises(socket.timeout):
            proxy.accept()


class ErrorsAndAbort(RunnerCase):
    DEFS = [definition(f"t.d{i}", "destructive") for i in range(3)]
    OV = {f"t.d{i}": {} for i in range(3)}

    def test_failures_become_error_outcomes_and_the_summary_is_written(self):
        modes = {"t.d0": (200, b"<html>proxy</html>", 0.0),
                 "t.d1": (200, b"[1, 2]", 0.0)}
        self.fake.execute = lambda post: modes.get(
            post["id"], (200, json.dumps({"command_id": "c"}).encode(), 0.0))
        r = self.run_runner(self.DEFS, overrides=self.OV)
        self.assertEqual(r.rc, 1)
        self.assertEqual([r.outcome(f"t.d{i}")["status"] for i in range(3)], ["error", "error", "pass"])
        self.assertIn("JSONDecodeError", r.outcome("t.d0")["note"])
        self.assertIn("not a JSON object", r.outcome("t.d1")["note"])
        self.assertEqual(len(self.fake.posts), 3)

    def test_a_stalled_dispatch_times_out_into_an_error_outcome(self):
        self.fake.execute = lambda post: (200, b"{}", 2.0 if post["id"] == "t.d0" else 0.0)
        with mock.patch.object(ir, "DEFAULT_DISPATCH_TIMEOUT_S", 1):
            r = self.run_runner(self.DEFS, overrides=self.OV)
        self.assertEqual(r.rc, 1)
        self.assertEqual(r.outcome("t.d0")["status"], "error")
        self.assertEqual(len(r.summary["outcomes"]), 3)

    def test_a_poll_that_returns_html_is_reported_not_raised(self):
        self.fake.responses_raw = b"<html>"
        r = self.run_runner([self.DEFS[0]], overrides=self.OV, extra=["--poll-timeout", "1"])
        self.assertEqual(r.rc, 1)
        out = r.outcome("t.d0")
        self.assertEqual(out["status"], "fail")  # an answer-less dispatch, not a runner crash
        self.assertIn("no response within", out["note"])
        self.assertIn("JSONDecodeError", out["note"])

    def test_a_future_that_raises_is_an_error_outcome_and_the_rest_still_run(self):
        real = ir._exercise

        def boom(client, defn, *a, **k):
            if defn.id == "t.d1":
                raise RuntimeError("kaput")
            return real(client, defn, *a, **k)

        with mock.patch.object(ir, "_exercise", boom):
            r = self.run_runner(self.DEFS, overrides=self.OV)
        self.assertEqual(r.rc, 1)
        self.assertEqual(r.outcome("t.d1")["status"], "error")
        self.assertIn("RuntimeError", r.outcome("t.d1")["note"])
        self.assertEqual(self.fake.posted_ids(), ["t.d0", "t.d2"])

    def test_interrupt_stops_dispatch_and_keeps_the_record(self):
        defs = [definition(f"t.q{i}", "destructive") for i in range(12)]
        self.fake.execute = lambda post: (200, json.dumps({"command_id": "c"}).encode(), 0.4)

        def interrupt_after_two(futures, *a, **k):
            deadline = time.monotonic() + 10
            while len(self.fake.posts) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            raise KeyboardInterrupt
            yield  # pragma: no cover

        r = self.run_runner(defs, overrides={d["id"]: {} for d in defs},
                            patch_as_completed=interrupt_after_two)
        time.sleep(1.0)  # the in-flight POST finishes; nothing queued behind it may start
        self.assertEqual(r.rc, 130)
        self.assertEqual(len(self.fake.posts), 2)
        self.assertEqual(r.summary["aborted"], "KeyboardInterrupt")
        self.assertEqual(len(r.manifest), 2)


class Grading(unittest.TestCase):
    class Client:
        def __init__(self, responses):
            self.responses = responses

        def execute_instruction(self, def_id, params, agent_ids=None):
            return 200, {"command_id": "c"}

        def get_responses(self, command_id):
            return {"responses": self.responses}

    def grade(self, risk, responses):
        d = ir.Definition(id="g", plugin="p", action="a", type="action", platforms=[], parameters={},
                          result_columns=[], approval_mode="auto", risk=risk, file="g.yaml")
        return ir.exercise(self.Client(responses), d, {"g": {}}, 30, AGENT).status

    def test_targeted_rows_fail_on_an_errored_or_unfinished_answer(self):
        for label, resp in (("error, no output", [{"status": "error", "rc": 1, "output": ""}]),
                            ("rc only", [{"status": "ok", "rc": 2, "output": ""}]),
                            ("running", [{"status": "running", "output": ""}]),
                            ("one bad of two", GOOD + [{"status": "error", "output": "x"}])):
            for risk in ("destructive", "forensic"):
                with self.subTest(label=label, risk=risk):
                    self.assertEqual(self.grade(risk, resp), "fail")

    def test_targeted_rows_still_pass_a_clean_empty_answer(self):
        self.assertEqual(self.grade("destructive", [{"status": "ok", "rc": 0, "output": ""}]), "pass")

    def test_safe_and_mutating_grading_is_unchanged(self):
        for risk in ("safe", "mutating"):
            for resp in ([{"status": "error", "rc": 1, "output": ""}], [{"status": "running", "output": ""}]):
                with self.subTest(risk=risk, resp=resp):
                    self.assertEqual(self.grade(risk, resp), "pass")
            self.assertEqual(self.grade(risk, [{"status": "error", "rc": 1, "output": "boom"}]), "fail")


class RunWiring(unittest.TestCase):
    """qe's F3: run() must thread the target to exercise() (a mutant dropping it survives
    every test that calls exercise() directly)."""

    class FakeClient:
        calls = []

        def __init__(self, *a, **k):
            pass

        def login(self, user, password):
            pass

        def list_agents(self):
            return [{"agent_id": AGENT, "hostname": HOSTNAME, "os": "linux", "agent_version": "1"}]

        def execute_instruction(self, def_id, params, agent_ids=None):
            RunWiring.FakeClient.calls.append((def_id, agent_ids))
            return 200, {"command_id": "c-" + def_id}

        def get_responses(self, command_id):
            return {"responses": GOOD}

    def test_run_threads_the_target_to_opt_in_classes_only(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_runner_") as tmp:
            defs = [definition("t.safe", "safe"), definition("t.destructive", "destructive"),
                    definition("t.forensic", "forensic")]
            content, table = write_content(tmp, defs)
            ov = Path(tmp) / "ov.json"
            ov.write_text(json.dumps({"t.destructive": {}, "t.forensic": {}}))
            RunWiring.FakeClient.calls = []
            argv = ["--dashboard", "http://127.0.0.1:8080", "--password", "p",
                    "--content-dir", str(content), "--risk-table", str(table),
                    "--risks", "safe", "destructive", "forensic", "--params-override", str(ov),
                    "--target-agent-id", AGENT, "--confirm-target", HOSTNAME, "--run-id", "r",
                    "--manifest", str(Path(tmp) / "m.jsonl"), "--parallelism", "1"]
            with mock.patch.object(ir, "YuzuClient", RunWiring.FakeClient), \
                    mock.patch.object(ir, "db_record_timing"), mock.patch.object(ir, "db_record_metric"), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ir.main(argv), 0)
            self.assertEqual(sorted(RunWiring.FakeClient.calls),
                             [("t.destructive", [AGENT]), ("t.forensic", [AGENT]), ("t.safe", None)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
