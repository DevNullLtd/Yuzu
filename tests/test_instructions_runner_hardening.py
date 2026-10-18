#!/usr/bin/env python3
"""test_instructions_runner_hardening.py - the destructive/forensic path of the /test
--instructions runner against a fake Yuzu server (#5261, governance rounds).

A targeted run changes or reads a real device, so these tests drive ir.main() end to end against
an in-process HTTP server on an ephemeral 127.0.0.1 port and assert what the server SAW: which
POSTs arrived, with which body, and whether the manifest line existed when each one did. The
fake's /api/responses emits the REAL row shape (integer `status`, `error_detail`, no `rc`),
because a fake that emits shapes the server never produces proves nothing about grading.

Runnable standalone: `python3 tests/test_instructions_runner_hardening.py`. Hermetic: loopback
sockets on ephemeral ports and temp dirs only; the test-runs DB writers are replaced.
"""
import contextlib
import errno
import http.server
import io
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
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
RUNNING, SUCCESS, FAILURE, TIMEOUT, REJECTED = 0, 1, 2, 3, 4


def row(status=SUCCESS, output="x", error_detail="", agent_id=AGENT):
    """A /api/responses row exactly as response_routes.cpp serialises it."""
    return {"id": 1, "instruction_id": "c", "agent_id": agent_id, "timestamp": 1,
            "status": status, "output": output, "error_detail": error_detail}


GOOD = [row()]


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
        self.agents_raw = None         # bytes: replaces the /api/agents body
        self.polls = lambda command_id, n: GOOD      # -> rows for poll number n of a command
        self.responses_raw = None      # bytes: replaces the /api/responses body
        self.responses_code = 200
        self.poll_script = None        # callable(command_id, n) -> (http code, body bytes)
        self.execute_headers = {}      # headers on the execute answer (e.g. a Location)
        self.redirect_hits = 0
        self.execute = None            # callable(post) -> (code, bytes, delay_s) or None
        self._polled = {}
        self._lock = threading.Lock()
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, delay=0.0, headers=None):
                if delay:
                    time.sleep(delay)
                try:
                    self.send_response(code)
                    for k, v in (headers or {}).items():
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass

            def do_GET(self):
                fake.requests.append(("GET", self.path, self.headers.get("User-Agent")))
                if self.path == "/api/redirected":
                    fake.redirect_hits += 1
                    self._send(200, b'{"command_id": "c-redirected"}')
                elif self.path == "/api/agents":
                    body = fake.agents_raw if fake.agents_raw is not None else \
                        json.dumps(fake.agents).encode()
                    self._send(fake.agents_code, body)
                elif self.path.startswith("/api/responses/"):
                    cid = self.path.rsplit("/", 1)[1]
                    with fake._lock:
                        n = fake._polled[cid] = fake._polled.get(cid, 0) + 1
                    if fake.poll_script:
                        code, body = fake.poll_script(cid, n)
                        self._send(code, body)
                        return
                    body = fake.responses_raw if fake.responses_raw is not None else \
                        json.dumps({"responses": fake.polls(cid, n)}).encode()
                    self._send(fake.responses_code, body)
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
                    self._send(code, body, delay, fake.execute_headers)
                finally:
                    with fake._lock:
                        fake.inflight -= 1

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()

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
            "metadata:", f"  id: {json.dumps(d['id'])}", "spec:", "  type: action",
            f"  platforms: {json.dumps(d['platforms'])}", "  execution:",
            f"    plugin: {d['plugin']}", "    action: a",
        ]
        if props:
            lines += ["  parameters:", f"    required: {json.dumps(d['required'])}",
                      "    properties:"] + props.rstrip("\n").split("\n")
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in d["id"])
        (content / f"{safe_name}.yaml").write_text("\n".join(lines) + "\n")
    table = Path(tmp) / "risk.json"
    table.write_text(json.dumps({"_overrides": {d["id"]: d["risk"] for d in defs}}))
    return content, table


class Result:
    def __init__(self, rc, out, err, summary, manifest):
        self.rc, self.out, self.err, self.summary, self.manifest = rc, out, err, summary, manifest

    def outcome(self, def_id):
        return next(o for o in self.summary["outcomes"] if o["id"] == def_id)

    def dispatch_lines(self):
        return [m for m in self.manifest if m.get("event") == "dispatch"]


class RunnerCase(unittest.TestCase):
    """Per-test fake server, temp dir, fast polling and stubbed test-runs DB writers."""

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
        for name, value in (("POLL_INTERVAL_S", 0.02), ("TARGETED_POLL_TIMEOUT_S", 3)):
            p = mock.patch.object(ir, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.fake.manifest_path = str(self.tmp / "manifest.jsonl")

    def run_runner(self, defs, *, overrides=None, raw_overrides=None, risks=("destructive",),
                   targeted=True, extra=(), dashboard=None, poll_timeout="5", stdout=None):
        content, table = write_content(self.tmp, defs)
        argv = ["--dashboard", dashboard or self.fake.url, "--password", "p",
                "--content-dir", str(content), "--risk-table", str(table),
                "--risks", *risks,
                "--output", str(self.tmp / "out.json"),
                "--manifest", self.fake.manifest_path]
        if poll_timeout:
            argv += ["--poll-timeout", poll_timeout]
        if targeted:
            argv += ["--target-agent-id", AGENT, "--confirm-target", HOSTNAME, "--run-id", RUN_ID]
        if overrides is not None or raw_overrides is not None:
            path = self.tmp / "overrides.json"
            path.write_text(raw_overrides if raw_overrides is not None else json.dumps(overrides))
            argv += ["--params-override", str(path)]
        argv += list(extra)
        outfile = self.tmp / "out.json"
        if outfile.exists() and "--output" not in extra:
            outfile.unlink()   # a targeted run refuses an existing --output: one run per file
        out, err = stdout or io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = ir.main(argv)
        summary = json.loads(outfile.read_text()) if outfile.exists() else None
        mf = Path(self.fake.manifest_path)
        manifest = [json.loads(line) for line in mf.read_text().splitlines()] if mf.exists() else []
        return Result(rc, out.getvalue() if hasattr(out, "getvalue") else "", err.getvalue(),
                      summary, manifest)

    def settle(self, grace=0.3):
        """Wait for every request the fake is serving to finish, then give a wrongly started
        one `grace` seconds to show up."""
        deadline = time.monotonic() + 10
        while self.fake.inflight and time.monotonic() < deadline:
            time.sleep(0.02)
        time.sleep(grace)

    def interrupt_after_posts(self, count):
        """A stand-in for concurrent.futures.wait that raises KeyboardInterrupt (Ctrl-C) once,
        after `count` execute POSTs have reached the server, then behaves normally."""
        real, state = ir.concurrent.futures.wait, {"raised": False}

        def wait(fs, timeout=None, return_when=ir.concurrent.futures.FIRST_COMPLETED):
            if not state["raised"]:
                deadline = time.monotonic() + 10
                while len(self.fake.posts) < count and time.monotonic() < deadline:
                    time.sleep(0.01)
                state["raised"] = True
                raise KeyboardInterrupt
            return real(fs, timeout=timeout, return_when=return_when)

        return mock.patch.object(ir.concurrent.futures, "wait", wait)


class OverrideGate(RunnerCase):
    DEFS = [definition("t.clear", "destructive", properties=["opt"]),
            definition("t.path", "destructive", required=["path", "mode"]),
            definition("t.other", "destructive", required=["a"], properties=["a", "b"])]

    def test_typod_id_dispatches_nothing_and_exits_2_before_login(self):
        r = self.run_runner(self.DEFS, overrides={"t.clea": {}})
        self.assertEqual(r.rc, 2)
        self.assertIn("covers its required parameters", r.err)
        self.assertEqual((self.fake.posts, self.fake.logins), ([], 0))

    def test_no_override_file_at_all_says_to_pass_one(self):
        r = self.run_runner(self.DEFS)
        self.assertEqual((r.rc, self.fake.posts, self.fake.logins), (2, [], 0))
        self.assertIn("pass --params-override FILE", r.err)

    def test_bad_override_file_exits_2_before_login(self):
        for label, raw in (("malformed", "{nope"), ("list", "[]"), ("string entry", '{"t.clear": 1}'),
                           ("duplicate top", '{"t.clear": {}, "t.clear": {}}'),
                           ("duplicate nested", '{"t.clear": {"a": "1", "a": "2"}}')):
            with self.subTest(label):
                r = self.run_runner(self.DEFS, raw_overrides=raw)
                self.assertEqual((r.rc, self.fake.posts, self.fake.logins), (2, [], 0))
                self.assertIn("--params-override", r.err)

    def test_bad_override_on_an_untargeted_run_also_exits_2(self):
        r = self.run_runner([definition("t.safe", "safe")], risks=("safe",), targeted=False,
                            raw_overrides="{nope")
        self.assertEqual((r.rc, self.fake.posts, self.fake.logins), (2, [], 0))

    def test_only_strings_and_integers_are_accepted_as_values(self):
        for label, value in (("null", None), ("bool", True), ("false", False), ("list", ["a"]),
                             ("dict", {"a": 1}), ("float", 1.5)):
            with self.subTest(label):
                r = self.run_runner(self.DEFS, overrides={"t.clear": {"opt": value}})
                self.assertEqual((r.rc, self.fake.posts, self.fake.logins), (2, [], 0))
                self.assertIn("'t.clear'", r.err)
                self.assertIn("'opt'", r.err)
        r = self.run_runner(self.DEFS, overrides={"t.other": {"a": 7}, "t.clear": {"opt": "true"}})
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(next(p for p in self.fake.posts if p["id"] == "t.other")["body"]["params"],
                         {"a": "7"})

    def test_underscore_keys_are_ignored(self):
        r = self.run_runner(self.DEFS, overrides={"_comment": 5, "t.clear": {}})
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(self.fake.posted_ids(), ["t.clear"])

    def test_missing_override_file_exits_2_before_login(self):
        r = self.run_runner(self.DEFS, extra=["--params-override", str(self.tmp / "absent.json")])
        self.assertEqual((r.rc, self.fake.posts, self.fake.logins), (2, [], 0))
        self.assertIn("--params-override", r.err)

    def test_gate_matrix_in_one_run(self):
        r = self.run_runner(self.DEFS, overrides={
            "t.clear": {},                  # parameterless: {} is a real entry
            "t.path": {"path": "/x"},       # lacks 'mode'
            "t.other": {"a": "1"},          # covers the required 'a' only
            "t.not_a_definition": {"zz": "1"},
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
        self.assertIn("warning: override for t.path skipped", r.err)  # not only under --verbose

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
        self.assertIn("mixed run: safe/mutating definitions are still sent to EVERY agent", r.out)

    def test_server_rows_are_skipped_even_with_an_override(self):
        defs = [definition("server.x", "destructive", plugin="server_internal"),
                definition("t.clear", "destructive")]
        r = self.run_runner(defs, overrides={"server.x": {}, "t.clear": {}})
        self.assertEqual(self.fake.posted_ids(), ["t.clear"])
        self.assertIn("server-internal: never dispatched with a target",
                      r.outcome("server.x")["note"])

    def test_run_id_is_validated_before_login(self):
        for bad in ("../x", "-lead", "a b", "x" * 65, "a/b"):
            with self.subTest(bad):
                r = self.run_runner([definition("t.safe", "safe")], risks=("safe",), targeted=False,
                                    extra=[f"--run-id={bad}"])
                self.assertEqual((r.rc, self.fake.logins), (2, 0))
                self.assertIn("--run-id must match", r.err)


class Attribution(RunnerCase):
    def test_manifest_line_exists_before_each_post_and_requests_are_attributed(self):
        defs = [definition(f"t.d{i}", "destructive") for i in range(3)]
        r = self.run_runner(defs, overrides={d["id"]: {} for d in defs}, extra=["--parallelism", "4"])
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(len(self.fake.posts), 3)
        for post in self.fake.posts:
            seen = [json.loads(line) for line in post["manifest"].splitlines()]
            self.assertIn(post["id"], [m.get("id") for m in seen], "manifest line must precede the POST")
        for m in r.dispatch_lines():
            self.assertEqual((m["run_id"], m["target_agent_id"], m["risk"], m["params"]),
                             (RUN_ID, AGENT, "destructive", {}))
            self.assertRegex(m["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual({ua for _, _, ua in self.fake.requests}, {f"yuzu-instructions-runner/{RUN_ID}"})

    def test_manifest_starts_with_a_run_start_line_without_credentials(self):
        self.assertEqual(ir.redact_url("http://admin:s3cret@127.0.0.1:8080/x?y=1"),
                         "http://127.0.0.1:8080/x")
        r = self.run_runner([definition("t.clear", "destructive")], overrides={"t.clear": {}})
        first = r.manifest[0]
        self.assertEqual((first["event"], first["hostname"], first["os"], first["agent_version"],
                          first["target_agent_id"], first["run_id"]),
                         ("run-start", HOSTNAME, "linux", "9.9.9", AGENT, RUN_ID))
        self.assertEqual(first["dashboard"], self.fake.url)
        self.assertNotIn("--password", Path(self.fake.manifest_path).read_text())

    @unittest.skipIf(sys.platform == "win32", "POSIX file modes")
    def test_manifest_is_owner_only(self):
        self.run_runner([definition("t.clear", "destructive")], overrides={"t.clear": {}})
        self.assertEqual(stat.S_IMODE(os.stat(self.fake.manifest_path).st_mode), 0o600)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "symlink"), "needs O_NOFOLLOW")
    def test_manifest_refuses_a_symlink(self):
        target = self.tmp / "elsewhere.txt"
        target.write_text("")
        os.symlink(target, self.fake.manifest_path)
        r = self.run_runner([definition("t.clear", "destructive")], overrides={"t.clear": {}})
        self.assertEqual((r.rc, self.fake.posts), (2, []))
        self.assertIn("cannot open the manifest", r.err)
        self.assertEqual(target.read_text(), "")

    def test_a_manifest_write_failure_means_no_post(self):
        with mock.patch.object(ir.Manifest, "record", side_effect=OSError("disk full")):
            r = self.run_runner([definition("t.clear", "destructive")], overrides={"t.clear": {}})
        self.assertEqual(self.fake.posts, [])
        self.assertEqual(r.rc, 1)
        self.assertIn("manifest:", r.outcome("t.clear")["note"])

    def test_closing_the_manifest_never_raises(self):
        m = ir.Manifest(self.tmp / "m.jsonl", "r")

        class Broken:
            def close(self):
                raise OSError("EIO")

        m._fh.close()
        m._fh = Broken()
        m.close()

    def test_targeted_definitions_run_one_at_a_time(self):
        defs = [definition(f"t.d{i}", "destructive") for i in range(4)]
        self.fake.execute = lambda post: (200, json.dumps({"command_id": "c"}).encode(), 0.1)
        r = self.run_runner(defs, overrides={d["id"]: {} for d in defs}, extra=["--parallelism", "4"])
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(self.fake.max_inflight, 1)
        self.assertIn("one at a time", r.out)

    def test_banner_summary_tally_and_metric(self):
        defs = [definition("t.clear", "destructive"), definition("t.path", "destructive", required=["p"]),
                definition("t.appr", "destructive")]
        self.fake.execute = lambda post: (202, b'{"status": "pending_approval", "approval_id": "a1"}', 0) \
            if post["id"] == "t.appr" else (200, json.dumps({"command_id": "c"}).encode(), 0)
        r = self.run_runner(defs, overrides={"t.clear": {}, "t.appr": {}})
        self.assertIn("TARGETED RUN target=agent-under-test host=Box-1 os=linux version=9.9.9", r.out)
        self.assertIn("covered=2 skipped=1", r.out)
        # a 202 is not a dispatch: nothing ran
        self.assertIn("1 dispatched, 0 dispatch_unknown, 1 pending_approval (not executed), "
                      "1 skipped, 0 failed", r.out)
        s = r.summary
        self.assertEqual((s["target_agent_id"], s["dashboard"], s["user"], s["skipped"], s["manifest"],
                          s["risks"], s["dispatched"]),
                         (AGENT, self.fake.url, "admin", 1, self.fake.manifest_path, ["destructive"], 1))
        self.assertEqual([a[3] for a in self.metrics if a[2] == "instructions_targeted_dispatched"], [1])
        self.assertFalse(r.outcome("t.appr")["dispatched"])

    def test_agent_reported_strings_are_escaped(self):
        evil = "Box\x1b[31m\n-1"
        self.fake.agents = [dict(self.fake.agents[0], hostname=evil, agent_version="1\x07")]
        r = self.run_runner([definition("t.clear", "destructive")], overrides={"t.clear": {}},
                            targeted=False, extra=["--target-agent-id", AGENT, "--confirm-target", evil,
                                                   "--run-id", RUN_ID])
        self.assertEqual(r.rc, 0, r.err)
        self.assertNotIn("\x1b", r.out + r.err)
        self.assertNotIn("\x07", r.out + r.err)
        self.assertIn("Box\\x1b[31m\\x0a-1", r.out)

    def test_error_text_from_the_server_is_escaped(self):
        self.assertEqual(ir.error_message({"error": {"message": "a\x1bb\nc"}}), "a\\x1bb\\x0ac")
        self.fake.execute = lambda post: (400, json.dumps(
            {"error": {"code": 400, "message": "bad\x1b[2Jthing\r\nFORGED"}}).encode(), 0)
        r = self.run_runner([definition("t.clear", "destructive")], overrides={"t.clear": {}})
        self.assertNotIn("\x1b", r.out + r.err)
        self.assertEqual(r.rc, 1)
        self.assertNotIn("\r", r.out + r.err)

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

    def test_three_consecutive_auth_failures_stop_the_run(self):
        defs = [definition(f"t.d{i}", "destructive") for i in range(6)]
        self.fake.execute = lambda post: (401, b'{"error": {"code": 401, "message": "no session"}}', 0)
        r = self.run_runner(defs, overrides={d["id"]: {} for d in defs})
        self.assertEqual(r.rc, 1)
        self.assertEqual(len(self.fake.posts), 3)
        self.assertIn("consecutive HTTP 401/403", r.err)
        self.assertEqual(sum(1 for o in r.summary["outcomes"] if o["status"] == "skip"), 3)
        self.assertEqual(r.summary["dispatched"], 0)  # the server accepted none of them


class Preflight(RunnerCase):
    DEFS = [definition("t.clear", "destructive")]
    OV = {"t.clear": {}}

    def refused(self, r):
        self.assertEqual(r.rc, 2, r.err)
        self.assertEqual(self.fake.posts, [])
        self.assertFalse(Path(self.fake.manifest_path).exists(), "no manifest for a refused run")

    def run_confirm(self, confirm, target=AGENT):
        return self.run_runner(self.DEFS, overrides=self.OV, targeted=False,
                               extra=["--target-agent-id", target, "--confirm-target", confirm,
                                      "--run-id", RUN_ID])

    def test_unknown_id(self):
        self.fake.agents = [dict(self.fake.agents[0], agent_id="someone-else")]
        self.refused(self.run_runner(self.DEFS, overrides=self.OV))

    def test_hostname_mismatch_including_substrings_in_both_directions(self):
        for confirm in ("Other-Box", "Box", "Box-1-extra", "-1"):
            with self.subTest(confirm):
                self.refused(self.run_confirm(confirm))
                self.assertIn("does not match", self.run_confirm(confirm).err)

    def test_agent_id_is_matched_exactly(self):
        self.fake.agents = [
            {"agent_id": "a10", "hostname": "Host-A10", "os": "linux", "agent_version": "1"},
            {"agent_id": "a1", "hostname": "Host-A1", "os": "linux", "agent_version": "1"}]
        self.fake.polls = lambda cid, n: [row(agent_id="a1")]
        r = self.run_confirm("Host-A1", target="a1")
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(self.fake.posts[0]["body"]["agent_ids"], ["a1"])
        self.fake.posts.clear()
        self.refused_substring = self.run_confirm("Host-A10", target="a1")
        self.assertEqual(self.refused_substring.rc, 2)
        self.assertEqual(self.fake.posts, [])

    def test_missing_confirm_target(self):
        r = self.run_runner(self.DEFS, overrides=self.OV, targeted=False,
                            extra=["--target-agent-id", AGENT, "--run-id", RUN_ID])
        self.refused(r)
        self.assertEqual(self.fake.logins, 0)

    def test_unreadable_endpoint_surfaces_the_a4_message_and_permission(self):
        self.fake.agents_code = 403
        self.fake.agents_raw = json.dumps({"error": {"code": 403, "message": "denied",
                                                     "permission": "Zed:Read"}}).encode()
        r = self.run_runner(self.DEFS, overrides=self.OV)
        self.refused(r)
        self.assertIn("HTTP 403", r.err)
        self.assertIn("denied", r.err)
        self.assertIn("(needs Zed:Read)", r.err)
        self.assertIn("Infrastructure:Read", r.err)

    def test_non_list_agent_body_is_refused(self):
        self.fake.agents_raw = b'{"agents": "nope"}'
        self.refused(self.run_runner(self.DEFS, overrides=self.OV))

    def test_confirmation_is_case_insensitive_and_posts(self):
        r = self.run_confirm(HOSTNAME.upper())
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(self.fake.posted_ids(), ["t.clear"])

    def test_platform_skip_uses_the_targets_os(self):
        self.fake.agents = [dict(self.fake.agents[0], os="windows")]
        defs = [definition("t.win", "destructive", platforms=["windows"]),
                definition("t.nix", "destructive", platforms=["linux"])]
        r = self.run_runner(defs, overrides={"t.win": {}, "t.nix": {}})
        self.assertEqual(self.fake.posted_ids(), ["t.win"])
        self.assertIn("target os=windows", r.outcome("t.nix")["note"])
        self.assertIn("warning: override for t.nix skipped", r.err)

    def test_nothing_eligible_on_the_targets_os_exits_2_without_a_manifest(self):
        defs = [definition("t.win", "destructive", platforms=["windows"]),
                definition("t.win2", "forensic", platforms=["windows"])]
        r = self.run_runner(defs, risks=("destructive", "forensic"),
                            overrides={"t.win": {}, "t.win2": {}})
        self.refused(r)
        self.assertIn("eligible on the target", r.err)
        self.assertIn("os=linux", r.err)


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

    def test_an_unreadable_200_body_is_dispatch_unknown_and_stops_the_run(self):
        for label, body in (("html", b"<html>proxy</html>"), ("non-object", b"[1, 2]")):
            with self.subTest(label):
                self.fake.posts.clear()
                self.fake.execute = lambda post, body=body: (200, body, 0.0)
                r = self.run_runner(self.DEFS, overrides=self.OV)
                self.assertEqual(r.rc, 1)
                first = r.outcome("t.d0")
                self.assertEqual((first["status"], first["dispatch_unknown"]), ("error", True))
                self.assertTrue(first["note"].startswith("dispatch_unknown: the request may have "
                                                         "reached the server"))
                self.assertEqual([r.outcome(f"t.d{i}")["status"] for i in (1, 2)], ["skip", "skip"])
                self.assertIn("stopped: previous dispatch outcome unknown", r.outcome("t.d1")["note"])
                self.assertEqual(len(self.fake.posts), 1)

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
        self.assertIn("poll failed", out["note"])
        self.assertIn("JSONDecodeError", out["note"])
        self.assertNotIn("still running", out["note"])

    def test_a_poll_that_returns_html_on_a_safe_row_is_reported_not_raised(self):
        self.fake.responses_raw = b"<html>"
        r = self.run_runner([definition("t.safe", "safe")], risks=("safe",), targeted=False,
                            extra=["--poll-timeout", "1"])
        out = r.outcome("t.safe")
        self.assertEqual(out["status"], "fail")
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

    def slow_posts(self, delay=0.4):
        self.fake.execute = lambda post: (200, json.dumps({"command_id": "c"}).encode(), delay)

    def test_interrupt_stops_dispatch_and_keeps_the_record(self):
        defs = [definition(f"t.q{i}", "destructive") for i in range(12)]
        self.slow_posts()
        with self.interrupt_after_posts(2):
            r = self.run_runner(defs, overrides={d["id"]: {} for d in defs})
        self.settle()  # an in-flight POST finishes; nothing queued behind it may start
        self.assertEqual(r.rc, 130)
        self.assertEqual(len(self.fake.posts), 2)
        self.assertEqual(r.summary["aborted"], "SIGINT")
        self.assertEqual(len(r.summary["outcomes"]), 12)   # the tally reconciles with the 12 selected
        self.assertTrue(all(o["note"].startswith("not started: SIGINT")
                            for o in r.summary["outcomes"] if o["status"] == "skip"))
        self.assertIn("records attempts, not outcomes", r.err)
        self.assertIn(self.fake.manifest_path, r.err)
        self.assertEqual(len(r.dispatch_lines()), 2)

    def test_untargeted_interrupt_is_stopped_by_cancel_futures_alone(self):
        defs = [definition(f"t.s{i}", "safe") for i in range(12)]
        self.slow_posts()
        with self.interrupt_after_posts(2), mock.patch.object(ir.RunControl, "request_stop"):
            r = self.run_runner(defs, risks=("safe",), targeted=False, extra=["--parallelism", "1"])
        self.settle()
        self.assertEqual((r.rc, len(self.fake.posts)), (130, 2))

    def test_the_stop_flag_alone_stops_new_dispatch(self):
        defs = [definition(f"t.s{i}", "safe") for i in range(12)]
        self.slow_posts()
        real = ir.concurrent.futures.ThreadPoolExecutor.shutdown

        def no_cancel(self_, wait=True, *, cancel_futures=False):
            return real(self_, wait=False)

        with self.interrupt_after_posts(2), \
                mock.patch.object(ir.concurrent.futures.ThreadPoolExecutor, "shutdown", no_cancel):
            r = self.run_runner(defs, risks=("safe",), targeted=False, extra=["--parallelism", "1"])
        self.settle()
        self.assertEqual((r.rc, len(self.fake.posts)), (130, 2))

    def test_exercise_starts_nothing_once_stop_is_set(self):
        class Never:
            def execute_instruction(self, *a, **k):
                raise AssertionError("POST after stop")

        control = ir.RunControl()
        control.request_stop()
        for risk in ("safe", "destructive"):
            d = ir.Definition(id="g", plugin="p", action="a", type="action", platforms=[],
                              parameters={}, result_columns=[], approval_mode="auto", risk=risk,
                              file="g.yaml")
            out = ir.exercise(Never(), d, {"g": {}}, 5, AGENT, "linux", NullManifest(), control)
            self.assertEqual(out.status, "skip")
            self.assertEqual(out.note, "aborted before dispatch")

    def test_the_main_wait_is_timed_so_an_interrupt_can_land_on_windows(self):
        calls, real = [], ir.concurrent.futures.wait

        def spy(fs, timeout=None, return_when=ir.concurrent.futures.ALL_COMPLETED):
            calls.append(timeout)
            return real(fs, timeout=timeout, return_when=return_when)

        with mock.patch.object(ir.concurrent.futures, "wait", spy):
            self.run_runner(self.DEFS, overrides=self.OV)
        self.assertTrue(calls)
        self.assertTrue(all(t is not None and t <= 1 for t in calls), calls)

    def test_a_stop_during_polling_reports_the_dispatch_as_in_flight(self):
        control = ir.RunControl()

        class Client:
            def execute_instruction(self, *a, **k):
                return 200, {"command_id": "c"}

            def get_responses(self, command_id):
                control.request_stop()
                return {"responses": [row(status=RUNNING)]}

        d = ir.Definition(id="g", plugin="p", action="a", type="action", platforms=[], parameters={},
                          result_columns=[], approval_mode="auto", risk="destructive", file="g.yaml")
        with mock.patch.object(ir, "POLL_INTERVAL_S", 0.01):
            out = ir.exercise(Client(), d, {"g": {}}, 5, AGENT, "linux", NullManifest(), control)
        self.assertEqual((out.status, out.dispatched), ("error", True))
        self.assertIn("in_flight_unknown", out.note)

    def test_an_interrupt_during_a_stalled_dispatch_reports_it_as_in_flight(self):
        defs = [definition(f"t.q{i}", "destructive") for i in range(3)]
        self.fake.execute = lambda post: (200, json.dumps({"command_id": "c"}).encode(), 1.6)
        with self.interrupt_after_posts(1):
            r = self.run_runner(defs, overrides={d["id"]: {} for d in defs})
        self.assertEqual(r.rc, 130)
        out = r.outcome("t.q0")
        self.assertEqual((out["status"], out["dispatched"]), ("error", True))
        self.assertIn("in_flight_unknown", out["note"])
        self.assertIn("in_flight_unknown", r.out)
        self.assertEqual(r.summary["dispatched"], 1)
        self.assertEqual([a[3] for a in self.metrics if a[2] == "instructions_targeted_dispatched"], [1])
        self.assertEqual(len(self.fake.posts), 1)
        self.settle()  # let the stalled handler finish before the fake closes

    @unittest.skipIf(sys.platform == "win32", "os.kill(SIGTERM) terminates a Windows process")
    @unittest.skipUnless(threading.current_thread() is threading.main_thread(), "signals need the main thread")
    def test_sigterm_takes_the_same_path_as_ctrl_c(self):
        self.fake.execute = lambda post: (200, json.dumps({"command_id": "c"}).encode(), 1.6)
        # A no-op baseline: if main() installed nothing, the SIGTERM below is swallowed and the
        # assertions fail, instead of the signal killing the test process.
        self.addCleanup(signal.signal, signal.SIGTERM, signal.getsignal(signal.SIGTERM))
        signal.signal(signal.SIGTERM, lambda signum, frame: None)
        before = signal.getsignal(signal.SIGTERM)
        timer = threading.Timer(0.4, os.kill, (os.getpid(), signal.SIGTERM))
        timer.start()
        self.addCleanup(timer.cancel)
        r = self.run_runner(self.DEFS, overrides=self.OV)
        self.assertEqual(r.rc, 130)
        self.assertEqual(r.summary["aborted"], "SIGTERM")
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)
        self.settle()


class NullManifest:
    path = "null.manifest"

    def record(self, *a, **k):
        pass


class PollAndTransport(RunnerCase):
    DEFS = [definition(f"t.d{i}", "destructive") for i in range(4)]
    OV = {f"t.d{i}": {} for i in range(4)}

    def test_refused_polls_are_reported_as_poll_failed_and_stop_the_run(self):
        self.fake.responses_code = 403
        self.fake.responses_raw = b'{"error": {"code": 403, "message": "no"}}'
        r = self.run_runner(self.DEFS, overrides=self.OV)
        out = r.outcome("t.d0")
        self.assertEqual(out["status"], "fail")
        self.assertIn("poll failed", out["note"])
        self.assertIn("403", out["note"])
        self.assertIn("the action may or may not have run", out["note"])
        self.assertNotIn("still running", out["note"])
        self.assertEqual((r.rc, len(self.fake.posts)), (1, 1))
        self.assertIn("targeted polls refused", r.err)
        self.assertIn("stopped: responses cannot be read", r.outcome("t.d1")["note"])

    def test_no_rows_ever_is_its_own_note(self):
        self.fake.polls = lambda cid, n: []
        r = self.run_runner(self.DEFS[:1], overrides=self.OV, extra=["--poll-timeout", "1"])
        note = r.outcome("t.d0")["note"]
        self.assertIn("no response rows within 1s (--poll-timeout)", note)
        self.assertNotIn("still running", note)
        self.assertNotIn("poll failed", note)

    def test_a_row_still_running_stops_the_run_and_skips_the_rest(self):
        self.fake.polls = lambda cid, n: [row(status=RUNNING, output="part")]
        r = self.run_runner(self.DEFS, overrides=self.OV, extra=["--poll-timeout", "1"])
        self.assertEqual(r.rc, 1)
        self.assertEqual(self.fake.posted_ids(), ["t.d0"])
        self.assertIn("still running after 1s (--poll-timeout)", r.outcome("t.d0")["note"])
        for i in (1, 2, 3):
            out = r.outcome(f"t.d{i}")
            self.assertEqual(out["status"], "skip")
            self.assertEqual(out["note"], "stopped: previous row still running")
        self.assertIn("3 skipped", r.out)

    def test_poll_refusal_counter_resets_and_ignores_transport_failures(self):
        c = ir.RunControl()
        for refused in (True, True, False, True, True, None):
            self.assertFalse(c.note_poll(refused))
        self.assertFalse(c.stop.is_set())
        self.assertTrue(c.note_poll(True))
        self.assertTrue(c.stop.is_set())
        self.assertEqual(c.skip_note, "stopped: responses cannot be read")

    def test_the_targeted_poll_timeout_default_is_longer_and_an_explicit_value_wins(self):
        seen = []
        real = ir.exercise

        def spy(*a, **k):
            seen.append((a[3], a[8]))
            return real(*a, **k)

        for poll, want in ((None, (30, ir.TARGETED_POLL_TIMEOUT_S)), ("7", (7, 7))):
            seen.clear()
            with mock.patch.object(ir, "exercise", spy):
                self.run_runner(self.DEFS[:1], overrides=self.OV, poll_timeout=poll)
            self.assertEqual(seen[0], want)

    def sends(self, exc, defn_risk="destructive"):
        class Client:
            def execute_instruction(self, *a, **k):
                raise exc

        d = ir.Definition(id="g", plugin="p", action="a", type="action", platforms=[], parameters={},
                          result_columns=[], approval_mode="auto", risk=defn_risk, file="g.yaml")
        control = ir.RunControl()
        out = ir.exercise(Client(), d, {"g": {}}, 5, AGENT, "linux", NullManifest(), control)
        return out, control

    def test_transport_failure_after_send_is_dispatch_unknown(self):
        for exc in (socket.timeout("timed out"), ConnectionResetError("reset"),
                    ir.urllib.error.URLError(socket.timeout("t")), ir.http.client.RemoteDisconnected("x"),
                    ir.http.client.IncompleteRead(b""), ir.http.client.HTTPException("x"),
                    ValueError("bad body"), TypeError("bug"), RuntimeError("x"),
                    RecursionError("deep"), MemoryError("oom"), KeyError("k")):
            with self.subTest(exc=repr(exc)):
                out, control = self.sends(exc)
                self.assertEqual((out.status, out.dispatch_unknown), ("error", True))
                self.assertTrue(control.stop.is_set())
                self.assertIn("do not re-run blindly", out.note)

    def test_failure_before_send_stays_a_plain_error(self):
        for exc in (ir.urllib.error.URLError(ConnectionRefusedError(111, "refused")),
                    ConnectionRefusedError(111, "refused"),
                    ir.urllib.error.URLError(socket.gaierror(-2, "nodename")),
                    OSError(errno_unreachable(), "unreachable"),
                    OSError(errno.EHOSTUNREACH, "no route"), OSError(errno.EADDRNOTAVAIL, "no addr")):
            with self.subTest(exc=repr(exc)):
                out, control = self.sends(exc)
                self.assertEqual((out.status, out.dispatch_unknown), ("error", False))
                self.assertFalse(control.stop.is_set())
                self.assertTrue(out.note.startswith("dispatch: "))

    def test_a_non_object_200_body_is_a_plain_error_untargeted_and_for_a_202(self):
        for risk, code in (("safe", 200), ("destructive", 202)):
            class Client:
                def execute_instruction(self, *a, **k):
                    return code, [1, 2]

            d = ir.Definition(id="g", plugin="p", action="a", type="action", platforms=[],
                              parameters={}, result_columns=[], approval_mode="auto", risk=risk,
                              file="g.yaml")
            control = ir.RunControl()
            out = ir.exercise(Client(), d, {"g": {}}, 5, AGENT, "linux", NullManifest(), control)
            with self.subTest(risk=risk, code=code):
                self.assertEqual((out.status, out.dispatch_unknown, control.stop.is_set()),
                                 ("error", False, False))
                self.assertIn("not a JSON object", out.note)

    def test_an_untargeted_transport_failure_is_unchanged(self):
        out, control = self.sends(socket.timeout("t"), defn_risk="safe")
        self.assertEqual((out.dispatch_unknown, control.stop.is_set()), (False, False))
        self.assertTrue(out.note.startswith("dispatch: "))

    def test_a_stalled_dispatch_is_counted_conservatively(self):
        self.fake.execute = lambda post: (200, b"{}", 1.3)
        with mock.patch.object(ir, "DEFAULT_DISPATCH_TIMEOUT_S", 1):
            r = self.run_runner(self.DEFS, overrides=self.OV)
        self.assertEqual(r.rc, 1)
        self.assertIn("0 dispatched, 1 dispatch_unknown", r.out)
        self.assertEqual([a[3] for a in self.metrics if a[2] == "instructions_targeted_dispatched"], [1])
        self.assertEqual(len(self.fake.posts), 1)
        self.settle()

    def test_all_pending_approval_means_nothing_executed(self):
        self.fake.execute = lambda post: (202, b'{"status": "pending_approval", "approval_id": "a"}', 0)
        r = self.run_runner(self.DEFS[:2], overrides=self.OV)
        self.assertEqual(r.rc, 1)
        self.assertIn("no destructive/forensic row was executed (2 pending_approval, 0 skipped)", r.err)

    def test_a_dispatched_run_is_not_nothing_executed(self):
        r = self.run_runner(self.DEFS[:1], overrides=self.OV)
        self.assertEqual(r.rc, 0, r.err)
        self.assertNotIn("was executed", r.err)

    def test_chargen_start_is_unsupported_even_with_an_override(self):
        defs = [definition("testing.chargen.start", "destructive"), definition("t.clear", "destructive")]
        r = self.run_runner(defs, overrides={"testing.chargen.start": {}, "t.clear": {}})
        self.assertEqual(self.fake.posted_ids(), ["t.clear"])
        self.assertIn("unsupported in targeted runs: streams until stopped", r.outcome("testing.chargen.start")["note"])
        self.assertIn("start and stop it by hand through the dashboard or REST with agent_ids",
                      r.outcome("testing.chargen.start")["note"])
        self.assertIn("warning: override for testing.chargen.start skipped", r.err)

    def test_only_chargen_covered_exits_2_before_login(self):
        r = self.run_runner([definition("testing.chargen.start", "destructive")],
                            overrides={"testing.chargen.start": {}})
        self.assertEqual((r.rc, self.fake.logins, self.fake.posts), (2, 0, []))


def errno_unreachable():
    import errno
    return errno.ENETUNREACH


class OutputAndEscape(RunnerCase):
    def test_an_unwritable_output_path_exits_2_before_login(self):
        missing = str(self.tmp / "no_such_dir" / "out.json")
        r = self.run_runner([definition("t.clear", "destructive")], overrides={"t.clear": {}},
                            extra=["--output", missing])
        self.assertEqual((r.rc, self.fake.logins, self.fake.posts), (2, 0, []))
        self.assertIn("--output", r.err)

    def test_the_output_probe_leaves_nothing_behind_and_keeps_an_existing_file(self):
        fresh = self.tmp / "fresh.json"
        self.assertEqual(ir.check_output_writable(str(fresh)), "")
        self.assertFalse(fresh.exists())
        kept = self.tmp / "kept.json"
        kept.write_text("keep")
        self.assertEqual(ir.check_output_writable(str(kept)), "")
        self.assertEqual(kept.read_text(), "keep")

    def test_a_failed_final_write_warns_and_never_raises(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            ir.write_output(str(self.tmp / "no_such_dir" / "out.json"), {"a": 1})
        self.assertIn("warning: could not write --output", err.getvalue())

    def test_esc_covers_controls_c1_separators_bidi_and_all_non_ascii(self):
        for ch, want in (("\x1b", "\\x1b"), ("\x7f", "\\x7f"), ("\x9b", "\\u009b"),
                         ("\u2028", "\\u2028"), ("\u2029", "\\u2029"), ("\u202e", "\\u202e"),
                         ("\u2066", "\\u2066"), ("\ufeff", "\\ufeff"), ("\u0416", "\\u0416"),
                         ("\U0001f600", "\\U0001f600")):
            with self.subTest(ch=want):
                self.assertEqual(ir.esc("a" + ch + "b"), "a" + want + "b")
        self.assertEqual(ir.esc("plain text 123"), "plain text 123")
        self.assertTrue(ir.esc("".join(chr(i) for i in range(0x20, 0x300))).isascii())

    def test_a_cyrillic_hostname_with_a_c1_control_prints_without_raising(self):
        evil = "\u0425\u043e\u0441\u0442\x9b-1"
        self.fake.agents = [dict(self.fake.agents[0], hostname=evil)]
        r = self.run_runner([definition("t.clear", "destructive")], overrides={"t.clear": {}},
                            targeted=False, extra=["--target-agent-id", AGENT, "--confirm-target", evil,
                                                   "--run-id", RUN_ID])
        self.assertEqual(r.rc, 0, r.err)
        self.assertTrue((r.out + r.err).isascii())
        self.assertIn("\\u0425\\u043e\\u0441\\u0442\\u009b-1", r.out)

    def test_a_control_character_in_an_agent_id_is_escaped_in_the_note(self):
        self.fake.polls = lambda cid, n: [row(status=FAILURE, agent_id="a\x1b[2Jb\x7f")]
        r = self.run_runner([definition("t.clear", "destructive")], overrides={"t.clear": {}})
        blob = json.dumps(r.summary) + r.out + r.err
        self.assertNotIn("\x1b", blob)
        self.assertNotIn("\x7f", blob)

    def test_a_run_id_with_a_trailing_newline_is_refused(self):
        for bad in ("ok\n", "ok\r", ""):
            if not bad:
                continue
            with self.subTest(repr(bad)):
                r = self.run_runner([definition("t.safe", "safe")], risks=("safe",), targeted=False,
                                    extra=[f"--run-id={bad}"])
                self.assertEqual((r.rc, self.fake.logins), (2, 0))
        r = self.run_runner([definition("t.safe", "safe")], risks=("safe",), targeted=False,
                            extra=["--run-id=" + "a" * 64])
        self.assertEqual(r.rc, 0, r.err)
        r = self.run_runner([definition("t.safe", "safe")], risks=("safe",), targeted=False,
                            extra=["--run-id=a.b_c-d"])
        self.assertEqual(r.rc, 0, r.err)


class Supplemental(RunnerCase):
    DEFS = [definition(f"t.d{i}", "destructive") for i in range(6)]
    OV = {f"t.d{i}": {} for i in range(6)}

    def test_403_on_execute_counts_as_an_auth_failure(self):
        self.fake.execute = lambda post: (403, b'{"error": {"code": 403, "message": "no"}}', 0)
        r = self.run_runner(self.DEFS, overrides=self.OV)
        self.assertEqual((r.rc, len(self.fake.posts)), (1, 3))

    def test_the_auth_counter_resets_on_a_non_auth_answer(self):
        codes = iter([401, 200, 401, 401, 200, 200])

        def execute(post):
            c = next(codes)
            body = b'{"error": {"code": 401, "message": "no"}}' if c == 401 else \
                json.dumps({"command_id": "c"}).encode()
            return c, body, 0

        self.fake.execute = execute
        r = self.run_runner(self.DEFS, overrides=self.OV)
        self.assertEqual(len(self.fake.posts), 6)
        self.assertNotIn("consecutive", r.err)

    def test_a_400_is_not_dispatched(self):
        self.fake.execute = lambda post: (400, b'{"error":{"code":400,"message":"m"}}', 0)
        r = self.run_runner(self.DEFS[:1], overrides=self.OV)
        self.assertFalse(r.outcome("t.d0")["dispatched"])
        self.assertIn("0 dispatched", r.out)

    def test_the_failed_tally_counts_errors_and_failures(self):
        self.fake.polls = lambda cid, n: [row(status=FAILURE)]
        r = self.run_runner(self.DEFS[:2], overrides=self.OV)
        self.assertIn("2 failed", r.out)

    def test_an_exception_in_the_pool_loop_exits_1(self):
        with mock.patch.object(ir.concurrent.futures, "wait", side_effect=RuntimeError("bug")):
            r = self.run_runner(self.DEFS[:1], overrides=self.OV)
        self.assertEqual(r.rc, 1)

    def test_an_agent_reporting_no_os_is_refused(self):
        self.fake.agents = [dict(self.fake.agents[0], os="")]
        r = self.run_runner(self.DEFS[:1], overrides=self.OV)
        self.assertEqual((r.rc, self.fake.posts), (2, []))

    def test_no_override_warning_for_a_definition_without_an_entry(self):
        r = self.run_runner(self.DEFS[:2], overrides={"t.d0": {}})
        self.assertNotIn("warning: override for t.d1", r.err)


class SafeGradingUnchanged(unittest.TestCase):
    """Safe/mutating grading is deliberately the original one (a separate follow-up)."""

    def grade(self, rows, timeout=2):
        d = ir.Definition(id="g", plugin="p", action="a", type="action", platforms=[], parameters={},
                          result_columns=[], approval_mode="auto", risk="safe", file="g.yaml")

        class C:
            def execute_instruction(self, *a, **k):
                return 200, {"command_id": "c"}

            def get_responses(self, command_id):
                return {"responses": rows}

        return ir.exercise(C(), d, {}, timeout)

    def test_mixed_rows_pass_as_on_origin_dev(self):
        rows = [{"status": "error", "rc": 1, "output": "b"}, {"status": "ok", "rc": 0, "output": "a"}]
        self.assertEqual(self.grade(rows).status, "pass")

    def test_an_integer_running_status_with_output_passes(self):
        self.assertEqual(self.grade([row(status=RUNNING, output="x")]).status, "pass")

    def test_a_safe_row_does_not_wait_for_running_rows_to_finish(self):
        polls = []

        class C:
            def execute_instruction(self, *a, **k):
                return 200, {"command_id": "c"}

            def get_responses(self, command_id):
                polls.append(1)
                return {"responses": [row(status=RUNNING)]}

        d = ir.Definition(id="g", plugin="p", action="a", type="action", platforms=[], parameters={},
                          result_columns=[], approval_mode="auto", risk="safe", file="g.yaml")
        self.assertEqual(ir.exercise(C(), d, {}, 5).status, "pass")
        self.assertEqual(len(polls), 1)


class VerdictlessRowsStopTheRun(RunnerCase):
    """A targeted row that ends without a verdict from terminal rows stops the run (round 3)."""

    DEFS = [definition(f"t.d{i}", "destructive") for i in range(3)]
    OV = {f"t.d{i}": {} for i in range(3)}

    def assert_stopped(self, r, reason_fragment):
        self.assertEqual(r.rc, 1)
        self.assertEqual(self.fake.posted_ids(), ["t.d0"])
        self.assertEqual(r.outcome("t.d0")["status"], "fail")
        for i in (1, 2):
            out = r.outcome(f"t.d{i}")
            self.assertEqual(out["status"], "skip")
            self.assertIn(reason_fragment, out["note"])

    def test_a_quiet_long_running_action_stops_the_run_at_the_deadline(self):
        # The server stores no row for a quiet action until its terminal frame arrives.
        self.fake.polls = lambda cid, n: [] if n < 400 else [row()]
        r = self.run_runner(self.DEFS, overrides=self.OV, extra=["--poll-timeout", "1"])
        self.assert_stopped(r, "stopped: previous row returned no response rows")
        self.assertIn("a quiet long-running action shows no rows", r.outcome("t.d0")["note"])

    def test_a_quiet_action_that_finishes_in_time_passes(self):
        self.fake.polls = lambda cid, n: [] if n < 5 else [row()]
        r = self.run_runner(self.DEFS, overrides=self.OV)
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(len(self.fake.posts), 3)

    def test_polls_failing_for_any_reason_stop_the_run(self):
        cases = {
            "404": lambda cid, n: (404, b'{"error": {"code": 404, "message": "gone"}}'),
            "500": lambda cid, n: (500, b'{"error": {"code": 500, "message": "boom"}}'),
            "html": lambda cid, n: (200, b"<html>proxy</html>"),
        }
        for label, script in cases.items():
            with self.subTest(label):
                self.fake.posts.clear()
                self.fake.poll_script = script
                r = self.run_runner(self.DEFS, overrides=self.OV, extra=["--poll-timeout", "1"])
                self.assert_stopped(r, "stopped: previous row's responses could not be read")
                self.assertIn("poll failed", r.outcome("t.d0")["note"])

    def test_running_rows_then_failing_polls_stop_at_the_deadline(self):
        def script(cid, n):
            if n == 1:
                return 200, json.dumps({"responses": [row(status=RUNNING, output="part")]}).encode()
            return 500, b'{"error": {"code": 500, "message": "boom"}}'

        self.fake.poll_script = script
        r = self.run_runner(self.DEFS, overrides=self.OV, extra=["--poll-timeout", "1"])
        self.assertEqual((r.rc, self.fake.posted_ids()), (1, ["t.d0"]))
        note = r.outcome("t.d0")["note"]
        self.assertIn("still running", note)
        self.assertIn("poll failed", note)
        # with several reasons at once the most informative one is the stop reason
        self.assertEqual(r.outcome("t.d1")["note"], "stopped: previous row still running")

    def test_a_terminal_failure_row_is_a_known_outcome_and_does_not_stop(self):
        self.fake.polls = lambda cid, n: [row(status=FAILURE, error_detail="no")]
        r = self.run_runner(self.DEFS, overrides=self.OV)
        self.assertEqual(r.rc, 1)
        self.assertEqual(len(self.fake.posts), 3)
        self.assertEqual([r.outcome(f"t.d{i}")["status"] for i in range(3)], ["fail"] * 3)

    def test_responses_null_after_an_accepted_post_is_dispatch_unknown_and_stops(self):
        for label, raw in (("null", b'{"responses": null}'), ("string", b'{"responses": "x"}')):
            with self.subTest(label):
                self.fake.posts.clear()
                self.fake.responses_raw = raw
                r = self.run_runner(self.DEFS, overrides=self.OV)
                first = r.outcome("t.d0")
                self.assertEqual((first["status"], first["dispatch_unknown"]), ("error", True))
                self.assertEqual(self.fake.posted_ids(), ["t.d0"])
                self.assertEqual(r.rc, 1)
                self.assertEqual(r.outcome("t.d1")["status"], "skip")

    def test_an_unusable_command_id_is_dispatch_unknown_and_stops(self):
        for label, body in (("int", b'{"command_id": 5}'), ("missing", b"{}"), ("empty", b'{"command_id": ""}')):
            with self.subTest(label):
                self.fake.posts.clear()
                self.fake.execute = lambda post, body=body: (200, body, 0)
                r = self.run_runner(self.DEFS, overrides=self.OV)
                self.assertTrue(r.outcome("t.d0")["dispatch_unknown"])
                self.assertEqual(self.fake.posted_ids(), ["t.d0"])
                self.assertEqual(r.rc, 1)

    def test_a_dispatch_unknown_row_counts_in_the_tally_once(self):
        self.fake.responses_raw = b'{"responses": null}'
        r = self.run_runner(self.DEFS[:1], overrides=self.OV)
        self.assertIn("0 dispatched, 1 dispatch_unknown", r.out)
        self.assertEqual(r.summary["dispatch_unknown"], 1)
        self.assertIn(self.fake.manifest_path, r.outcome("t.d0")["note"])
        self.assertEqual([a[3] for a in self.metrics if a[2] == "instructions_targeted_dispatched"], [1])

    def test_post_answers_that_may_have_started_the_action_are_dispatch_unknown(self):
        for code, body in ((500, b'{"error": {"code": 500, "message": "dispatch failed"}}'),
                           (502, b"<html>bad gateway</html>"), (504, b"<html>timeout</html>"),
                           (503, b'{"error": {"code": 503, "message": "store busy"}}')):
            with self.subTest(code=code):
                self.fake.posts.clear()
                self.fake.execute = lambda post, code=code, body=body: (code, body, 0)
                r = self.run_runner(self.DEFS, overrides=self.OV)
                self.assertTrue(r.outcome("t.d0")["dispatch_unknown"])
                self.assertEqual((r.rc, len(self.fake.posts)), (1, 1))

    def test_pre_dispatch_refusals_stay_plain_failures(self):
        refusals = [(503, {"error": {"code": 503, "message": "m", "reason": reason}})
                    for reason in ir.PRE_DISPATCH_503_REASONS]
        refusals += [(503, {"error": {"code": 503, "message": "no agents reached for t.d0"}}),
                     (400, {"error": {"code": 400, "message": "bad"}}),
                     (403, {"error": {"code": 403, "message": "no"}}),
                     (404, {"error": {"code": 404, "message": "nope"}})]
        for code, body in refusals:
            with self.subTest(code=code, body=body["error"].get("reason", body["error"]["message"])):
                self.fake.posts.clear()
                self.fake.execute = lambda post, code=code, body=body: (code, json.dumps(body).encode(), 0)
                r = self.run_runner(self.DEFS[:1], overrides=self.OV)
                out = r.outcome("t.d0")
                self.assertEqual((out["status"], out["dispatch_unknown"]), ("fail", False))
                reason = body["error"].get("reason")
                if reason:
                    self.assertIn(f"HTTP {code} {reason}:", out["note"])

    def test_poll_timeout_below_one_is_refused_for_a_targeted_run_only(self):
        r = self.run_runner(self.DEFS[:1], overrides=self.OV, poll_timeout="0")
        self.assertEqual((r.rc, self.fake.logins, self.fake.posts), (2, 0, []))
        self.assertIn("--poll-timeout of at least 1", r.err)

    def test_the_stop_message_names_the_manifest_and_how_to_resume(self):
        self.fake.polls = lambda cid, n: []
        r = self.run_runner(self.DEFS, overrides=self.OV, extra=["--poll-timeout", "1"])
        self.assertIn(f"manifest: {self.fake.manifest_path}", r.err)
        self.assertIn("records attempts, not outcomes", r.err)
        self.assertIn("--only-id (one id) or an anchored --match regex", r.err)
        self.assertIn("raise --poll-timeout if it needs longer", r.err)
        self.assertIn("not started: t.d1, t.d2", r.err)
        self.assertEqual(r.summary["stop_reason"][:20], "a targeted row ended")


class PollRefusalIntegration(RunnerCase):
    """Refused polls through the real poll loop, with the real A4 body shape."""

    DEFS = [definition(f"t.d{i}", "destructive") for i in range(3)]
    OV = {f"t.d{i}": {} for i in range(3)}

    @staticmethod
    def a4(code, message, permission=None):
        err = {"code": code, "message": message, "correlation_id": "cid-1", "retry_after_ms": 5000}
        if permission:
            err["permission"] = permission
        return json.dumps({"error": err, "meta": {"api_version": "v1"}}).encode()

    @staticmethod
    def rows(*r):
        return 200, json.dumps({"responses": list(r)}).encode()

    def test_the_a4_message_and_permission_reach_the_note(self):
        self.fake.poll_script = lambda cid, n: (403, self.a4(403, "permission denied: Response:Read",
                                                             "Response:Read"))
        r = self.run_runner(self.DEFS, overrides=self.OV)
        note = r.outcome("t.d0")["note"]
        self.assertIn("poll failed: HTTP 403 permission denied: Response:Read (needs Response:Read); "
                      "could not read", note)

    def test_codes_that_count_as_refusals_each_stop_after_three(self):
        for code in (401, 403, 503):
            with self.subTest(code=code):
                self.fake.posts.clear()
                self.fake.poll_script = lambda cid, n, code=code: (code, self.a4(code, "refused"))
                r = self.run_runner(self.DEFS, overrides=self.OV)
                self.assertEqual((r.rc, len(self.fake.posts)), (1, 1))
                self.assertIn("targeted polls refused", r.summary["stop_reason"])

    def test_the_refusal_counter_resets_on_an_answered_poll(self):
        def script(cid, n):
            if n in (1, 2, 4, 5):
                return 403, self.a4(403, "no")
            if n == 3:
                return self.rows(row(status=RUNNING, output="part"))
            return self.rows(row())

        self.fake.poll_script = script
        r = self.run_runner(self.DEFS[:1], overrides=self.OV)
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(r.summary["stop_reason"], "")

    def test_a_garbage_answer_is_neutral_so_refusals_around_it_still_add_up(self):
        def script(cid, n):
            if n == 3:
                return 200, b"<html>garbage</html>"
            if n in (1, 2, 4):
                return 403, self.a4(403, "no")
            return self.rows(row())   # only reached if the garbage answer reset the count

        self.fake.poll_script = script
        r = self.run_runner(self.DEFS, overrides=self.OV)
        self.assertEqual((r.rc, len(self.fake.posts)), (1, 1))
        self.assertIn("targeted polls refused", r.summary["stop_reason"])


class RunLevelAccounting(RunnerCase):
    DEFS = [definition("t.safe", "safe"), definition("t.d0", "destructive"),
            definition("t.d1", "destructive")]
    OV = {"t.d0": {}, "t.d1": {}}

    def pending(self, post):
        if post["id"].startswith("t.d"):
            return 202, b'{"status": "pending_approval", "approval_id": "a"}', 0
        return 200, json.dumps({"command_id": "c"}).encode(), 0

    def test_a_safe_row_that_ran_does_not_hide_that_no_destructive_row_did(self):
        self.fake.execute = self.pending
        r = self.run_runner(self.DEFS, risks=("safe", "destructive"), overrides=self.OV)
        self.assertEqual(r.rc, 1)
        self.assertIn("no destructive/forensic row was executed (2 pending_approval, 0 skipped)", r.err)

    def test_an_untargeted_run_whose_rows_are_all_pending_still_exits_0(self):
        self.fake.execute = lambda post: (202, b'{"status": "pending_approval", "approval_id": "a"}', 0)
        r = self.run_runner([definition("t.safe", "safe")], risks=("safe",), targeted=False)
        self.assertEqual(r.rc, 0, r.err)
        self.assertNotIn("was executed", r.err)

    def test_dispatch_unknown_rows_count_as_executed_for_the_nothing_executed_check(self):
        self.fake.responses_raw = b'{"responses": null}'
        r = self.run_runner(self.DEFS[1:2], overrides=self.OV)
        self.assertNotIn("was executed", r.err)

    def test_an_unwritable_final_output_only_warns(self):
        bad = str(self.tmp / "no_such_dir" / "out.json")
        with mock.patch.object(ir, "check_output_writable", return_value=""):
            r = self.run_runner(self.DEFS[1:2], overrides=self.OV, extra=["--output", bad])
        self.assertEqual(r.rc, 0, r.err)
        self.assertIn("warning: could not write --output", r.err)

    @unittest.skipUnless(hasattr(os, "symlink") and sys.platform != "win32", "needs symlinks")
    def test_output_through_a_symlink_is_refused(self):
        target = self.tmp / "real.json"
        target.write_text("keep")
        link = self.tmp / "link.json"
        os.symlink(target, link)
        for path in (link, self.tmp / "dangling_link.json"):
            if path.name.startswith("dangling"):
                os.symlink(self.tmp / "nowhere.json", path)
            with self.subTest(path=path.name):
                r = self.run_runner(self.DEFS[1:2], overrides=self.OV, extra=["--output", str(path)])
                self.assertEqual((r.rc, self.fake.logins, self.fake.posts), (2, 0, []))
                self.assertIn("refusing to write through a symlink", r.err)
        self.assertEqual(target.read_text(), "keep")

    def test_the_summary_records_stop_reason_and_unknown_count(self):
        self.fake.polls = lambda cid, n: []
        r = self.run_runner(self.DEFS[1:], overrides=self.OV, extra=["--poll-timeout", "1"])
        self.assertEqual(r.summary["aborted"], "")
        self.assertIn("no response rows", r.summary["stop_reason"] + r.outcome("t.d0")["note"])
        self.assertEqual(r.summary["dispatch_unknown"], 0)
        self.assertEqual(len(r.summary["outcomes"]), 2)


class ConsoleSafety(RunnerCase):
    def test_outcome_short_is_ascii_and_escapes_the_id(self):
        line = ir.Outcome("a\x1bbЖ", "safe", "pass", 1, note="n").short()
        self.assertTrue(line.isascii())
        self.assertIn(" - ", line)
        self.assertNotIn("\x1b", line)

    def test_help_is_ascii(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            ir.parse_args(["--help"])
        self.assertTrue(out.getvalue().isascii())

    @unittest.skipIf(sys.platform == "win32", "control characters in a file name")
    def test_the_manifest_path_is_escaped_in_the_banner(self):
        odd = self.tmp / "m\x1bdir"
        odd.mkdir()
        self.fake.manifest_path = str(odd / "m.jsonl")
        r = self.run_runner([definition("t.clear", "destructive")], overrides={"t.clear": {}})
        self.assertEqual(r.rc, 0, r.err)
        self.assertNotIn("\x1b", r.out + r.err)
        self.assertIn("m\\x1bdir", r.out)

    def test_main_makes_stdout_line_buffered(self):
        raw = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", write_through=False)
        self.assertFalse(raw.line_buffering)
        with contextlib.redirect_stdout(raw), contextlib.redirect_stderr(io.StringIO()):
            ir.main(["--dashboard", "http://127.0.0.1:9", "--password", "p", "--risks", "destructive"])
        self.assertTrue(raw.line_buffering)


@unittest.skipIf(sys.platform == "win32" or not shutil.which("bash"), "needs bash and a POSIX shell shim")
class BashEntry(unittest.TestCase):
    """scripts/test/instructions-tests.sh against a python3 shim that records its argv."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_bash_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        shim = self.tmp / "python3"
        shim.write_text('#!/bin/sh\n[ "$1" = "-c" ] && exit 0\nprintf \'%s\\0\' "$@" > "$REC"\nexit 0\n')
        shim.chmod(0o755)
        self.rec = self.tmp / "argv.rec"

    def run_bash(self, *args):
        env = dict(os.environ, PATH=f"{self.tmp}{os.pathsep}{os.environ['PATH']}", REC=str(self.rec))
        r = subprocess.run(["bash", str(ROOT / "scripts" / "test" / "instructions-tests.sh"),
                            "--dashboard", "http://127.0.0.1:1", "--password", "p", *args],
                           env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return self.rec.read_bytes().decode().split("\0")[:-1]

    def test_poll_timeout_is_passed_only_when_given(self):
        self.assertNotIn("--poll-timeout", self.run_bash())
        argv = self.run_bash("--poll-timeout", "45")
        self.assertEqual(argv[argv.index("--poll-timeout") + 1], "45")

    def test_a_comma_risks_list_becomes_space_separated_values(self):
        argv = self.run_bash("--risks", "destructive,forensic")
        i = argv.index("--risks")
        self.assertEqual(argv[i + 1:i + 3], ["destructive", "forensic"])
        self.assertTrue(argv[i + 3].startswith("--"))

    def test_values_with_spaces_arrive_as_single_arguments(self):
        argv = self.run_bash("--confirm-target", "Host name 1", "--manifest", "/tmp/a b/m.jsonl",
                             "--params-override", "/tmp/o v/x.json", "--target-agent-id", "id 1")
        for flag, value in (("--confirm-target", "Host name 1"), ("--manifest", "/tmp/a b/m.jsonl"),
                            ("--params-override", "/tmp/o v/x.json"), ("--target-agent-id", "id 1")):
            self.assertEqual(argv[argv.index(flag) + 1], value)


class ShippedDefaults(unittest.TestCase):
    def test_the_targeted_default_poll_timeout_is_exactly_120_seconds(self):
        # RunnerCase patches the constant to keep the suite fast, so read the shipped value.
        import ast
        tree = ast.parse((ROOT / "scripts" / "test" / "instructions_runner.py").read_text(encoding="utf-8"))
        values = [n.value.value for n in tree.body if isinstance(n, ast.Assign)
                  and any(getattr(t, "id", "") == "TARGETED_POLL_TIMEOUT_S" for t in n.targets)]
        self.assertEqual(values, [120])
        self.assertEqual(ir.DEFAULT_POLL_TIMEOUT_S, 30)


class FailClosedPost(RunnerCase):
    DEFS = [definition(f"t.d{i}", "destructive") for i in range(3)]
    OV = {f"t.d{i}": {} for i in range(3)}

    def assert_unknown_and_stopped(self, r):
        out = r.outcome("t.d0")
        self.assertEqual((out["status"], out["dispatch_unknown"]), ("error", True))
        self.assertEqual((r.rc, self.fake.posted_ids()), (1, ["t.d0"]))
        self.assertEqual(r.outcome("t.d1")["status"], "skip")

    def test_a_body_that_overflows_the_json_decoder_is_dispatch_unknown(self):
        self.fake.execute = lambda post: (200, b"[" * 200000, 0)
        self.assert_unknown_and_stopped(self.run_runner(self.DEFS, overrides=self.OV))

    def test_a_memory_error_while_sending_is_dispatch_unknown(self):
        class Client:
            def execute_instruction(self, *a, **k):
                raise MemoryError("oom")

        d = ir.Definition(id="g", plugin="p", action="a", type="action", platforms=[], parameters={},
                          result_columns=[], approval_mode="auto", risk="destructive", file="g.yaml")
        control = ir.RunControl()
        out = ir.exercise(Client(), d, {"g": {}}, 5, AGENT, "linux", NullManifest(), control)
        self.assertEqual((out.dispatch_unknown, control.stop.is_set()), (True, True))

    def test_a_redirect_is_not_followed_and_is_a_plain_failure(self):
        self.fake.execute = lambda post: (302, b"", 0)
        self.fake.execute_headers = {"Location": self.fake.url + "/api/redirected"}
        r = self.run_runner(self.DEFS[:1], overrides=self.OV)
        out = r.outcome("t.d0")
        self.assertEqual((out["status"], out["dispatch_unknown"]), ("fail", False))
        self.assertIn("HTTP 302", out["note"])
        self.assertEqual(self.fake.redirect_hits, 0)

    def test_a_redirect_is_not_followed_for_an_untargeted_row_either(self):
        self.fake.execute = lambda post: (302, b"", 0)
        self.fake.execute_headers = {"Location": self.fake.url + "/api/redirected"}
        r = self.run_runner([definition("t.safe", "safe")], risks=("safe",), targeted=False)
        self.assertEqual(r.outcome("t.safe")["status"], "fail")
        self.assertEqual(self.fake.redirect_hits, 0)

    def test_any_2xx_other_than_200_and_202_is_dispatch_unknown(self):
        for code in (201, 204, 206):
            with self.subTest(code=code):
                self.fake.posts.clear()
                self.fake.execute = lambda post, code=code: (code, b"" if code == 204 else b"{}", 0)
                self.assert_unknown_and_stopped(self.run_runner(self.DEFS, overrides=self.OV))

    def test_a_202_without_pending_approval_is_a_plain_failure(self):
        self.fake.execute = lambda post: (202, b"{}", 0)
        r = self.run_runner(self.DEFS[:1], overrides=self.OV)
        out = r.outcome("t.d0")
        self.assertEqual((out["status"], out["dispatch_unknown"]), ("fail", False))

    def test_dispatch_unknown_after_an_accepted_post_keeps_the_ids(self):
        self.fake.execute = lambda post: (200, b'{"command_id": "c1", "execution_id": "e1"}', 0)
        self.fake.responses_raw = b'{"responses": null}'
        r = self.run_runner(self.DEFS, overrides=self.OV)
        out = r.outcome("t.d0")
        self.assertEqual((out["dispatch_unknown"], out["command_id"], out["execution_id"]),
                         (True, "c1", "e1"))

    def test_the_manifest_records_what_the_server_answered(self):
        codes = {"t.d0": (200, {"command_id": "c0", "execution_id": "e0"}),
                 "t.d1": (202, {"status": "pending_approval", "approval_id": "ap1"}),
                 "t.d2": (400, {"error": {"code": 400, "message": "bad"}})}
        self.fake.execute = lambda post: (codes[post["id"]][0], json.dumps(codes[post["id"]][1]).encode(), 0)
        r = self.run_runner(self.DEFS, overrides=self.OV)
        events = [(m["event"], m.get("id")) for m in r.manifest]
        self.assertEqual(events[0][0], "run-start")
        for i in range(3):   # a dispatch line is always followed by its accepted line
            self.assertLess(events.index(("dispatch", f"t.d{i}")), events.index(("accepted", f"t.d{i}")))
        acc = {m["id"]: m for m in r.manifest if m["event"] == "accepted"}
        self.assertEqual((acc["t.d0"]["http"], acc["t.d0"]["command_id"], acc["t.d0"]["execution_id"]),
                         (200, "c0", "e0"))
        self.assertEqual((acc["t.d1"]["http"], acc["t.d1"]["approval_id"]), (202, "ap1"))
        self.assertEqual(acc["t.d2"]["http"], 400)
        self.assertRegex(acc["t.d0"]["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_each_dispatch_is_announced_before_the_post(self):
        r = self.run_runner(self.DEFS, overrides=self.OV)
        for i in range(3):
            self.assertIn(f"dispatching t.d{i} ({i + 1}/3)", r.out)

    def test_skip_unknown_and_stopped_metrics_are_recorded(self):
        self.fake.responses_raw = b'{"responses": null}'
        self.run_runner(self.DEFS, overrides={"t.d0": {}, "t.d1": {}})
        got = {a[2]: a[3] for a in self.metrics}
        self.assertEqual((got["instructions_dispatch_unknown"], got["instructions_stopped"]), (1, 1))
        self.assertIn("instructions_skipped", got)


class UnrecognisedRows(RunnerCase):
    DEFS = [definition(f"t.d{i}", "destructive") for i in range(3)]
    OV = {f"t.d{i}": {} for i in range(3)}

    def test_odd_rows_fail_the_row_and_stop_the_run(self):
        cases = {"not an object": ["x"], "status 9": [row(status=9)], "status string": [dict(row(), status="ok")],
                 "bool status": [dict(row(), status=True)], "other agent": [row(agent_id="someone-else")],
                 "negative status": [row(status=-1)]}
        for label, rows in cases.items():
            with self.subTest(label):
                self.fake.posts.clear()
                self.fake.polls = lambda cid, n, rows=rows: rows
                r = self.run_runner(self.DEFS, overrides=self.OV)
                self.assertEqual((r.rc, self.fake.posted_ids()), (1, ["t.d0"]))
                self.assertEqual(r.outcome("t.d0")["status"], "fail")
                self.assertIn("unrecognised response row", r.outcome("t.d0")["note"])
                self.assertEqual(r.outcome("t.d1")["note"], "stopped: unrecognised response row")

    def test_a_row_without_an_agent_id_is_tolerated(self):
        no_agent = row()
        del no_agent["agent_id"]
        self.fake.polls = lambda cid, n: [no_agent]
        r = self.run_runner(self.DEFS, overrides=self.OV)
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(len(self.fake.posts), 3)


class OutputHardening(RunnerCase):
    DEFS = [definition("t.d0", "destructive")]
    OV = {"t.d0": {}}

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "symlink"), "needs O_NOFOLLOW")
    def test_a_symlink_planted_after_the_preflight_is_not_followed(self):
        victim = self.tmp / "victim.txt"
        victim.write_text("keep")
        link = self.tmp / "out_link.json"
        os.symlink(victim, link)
        with mock.patch.object(ir, "check_output_writable", return_value=""):
            r = self.run_runner(self.DEFS, overrides=self.OV, extra=["--output", str(link)])
        self.assertEqual(victim.read_text(), "keep")
        self.assertIn("warning: could not write --output", r.err)
        self.assertEqual(r.rc, 0, r.err)

    @unittest.skipIf(sys.platform == "win32", "POSIX file modes")
    def test_the_output_is_created_owner_only(self):
        self.run_runner(self.DEFS, overrides=self.OV)
        self.assertEqual(stat.S_IMODE(os.stat(self.tmp / "out.json").st_mode), 0o600)

    def test_a_targeted_run_refuses_an_existing_output(self):
        existing = self.tmp / "earlier.json"
        existing.write_text('{"earlier": "run"}')
        r = self.run_runner(self.DEFS, overrides=self.OV, extra=["--output", str(existing)])
        self.assertEqual((r.rc, self.fake.logins, self.fake.posts), (2, 0, []))
        self.assertIn("rename it first", r.err)
        self.assertEqual(existing.read_text(), '{"earlier": "run"}')

    def test_an_untargeted_run_may_overwrite_its_output(self):
        existing = self.tmp / "earlier.json"
        existing.write_text("old")
        r = self.run_runner([definition("t.safe", "safe")], risks=("safe",), targeted=False,
                            extra=["--output", str(existing)])
        self.assertEqual(r.rc, 0, r.err)
        self.assertIn('"outcomes"', existing.read_text())

    def test_output_may_not_be_the_manifest(self):
        r = self.run_runner(self.DEFS, overrides=self.OV, extra=["--output", self.fake.manifest_path])
        self.assertEqual((r.rc, self.fake.logins, self.fake.posts), (2, 0, []))
        self.assertIn("--output and --manifest are the same file", r.err)

    def test_a_dead_stdout_costs_nothing(self):
        class Dead(io.StringIO):
            def write(self, text):
                raise BrokenPipeError("closed")

        r = self.run_runner(self.DEFS, overrides=self.OV, stdout=Dead())
        self.assertEqual(r.rc, 0, r.err)
        self.assertEqual(r.summary["outcomes"][0]["status"], "pass")
        self.assertIn("instructions_pass", [a[2] for a in self.metrics])

    @unittest.skipIf(sys.platform == "win32", "os.kill(SIGINT) semantics")
    @unittest.skipUnless(threading.current_thread() is threading.main_thread(), "signals need the main thread")
    def test_a_second_interrupt_while_the_summary_is_written_is_ignored(self):
        before = signal.getsignal(signal.SIGINT)
        with ir._ignore_second_interrupt():
            os.kill(os.getpid(), signal.SIGINT)     # would raise KeyboardInterrupt otherwise
            time.sleep(0.05)
            ir._raise_interrupt(signal.SIGTERM, None)  # and so is a SIGTERM
        self.assertEqual(signal.getsignal(signal.SIGINT), before)
        with self.assertRaises(KeyboardInterrupt):
            ir._raise_interrupt(signal.SIGTERM, None)

    def test_outcomes_are_recorded_in_submission_order(self):
        defs = [definition(f"t.s{i}", "safe") for i in range(6)]
        self.fake.execute = lambda post: (200, json.dumps({"command_id": "c"}).encode(),
                                          (5 - int(post["id"][-1])) * 0.05)
        r = self.run_runner(defs, risks=("safe",), targeted=False, extra=["--parallelism", "4"])
        self.assertEqual([o["id"] for o in r.summary["outcomes"]], [d["id"] for d in defs])


class EscapingAndFinalPoll(RunnerCase):
    def test_the_agent_os_in_a_skip_warning_is_escaped(self):
        self.fake.agents = [dict(self.fake.agents[0], os="li\x1bnux")]
        defs = [definition("t.clear", "destructive", platforms=["windows"]),
                definition("t.ok", "destructive", platforms=["li\x1bnux"])]
        r = self.run_runner(defs, overrides={"t.clear": {}, "t.ok": {}})
        self.assertNotIn("\x1b", r.out + r.err)
        self.assertIn("warning: override for t.clear skipped: target os=li\\x1bnux", r.err)

    def test_a_definition_id_with_a_control_character_is_escaped_in_the_warning(self):
        evil = "t.\x1bclear"
        defs = [definition(evil, "destructive", platforms=["windows"]), definition("t.ok", "destructive")]
        r = self.run_runner(defs, overrides={evil: {}, "t.ok": {}})
        self.assertNotIn("\x1b", r.out + r.err)
        self.assertIn("override for t.\\x1bclear skipped", r.err)

    def test_the_banner_dashboard_is_escaped(self):
        # urllib refuses a control character in the part of the URL it sends, and redact_url drops
        # userinfo, query and fragment; whatever is left still goes through esc() in the banner.
        url = "http://u:pw@127.0.0.1:8080/p\x1bq?x=\x1b#\x1b"
        self.assertEqual(ir.redact_url(url), "http://127.0.0.1:8080/p\x1bq")
        self.assertEqual(ir.esc(ir.redact_url(url)), "http://127.0.0.1:8080/p\\x1bq")
        r = self.run_runner([definition("t.clear", "destructive")], overrides={"t.clear": {}})
        self.assertIn(f"dashboard={self.fake.url} ", r.out)

    def test_one_final_poll_after_the_deadline_catches_a_late_result(self):
        now = [0.0]
        calls = []

        class Client:
            def execute_instruction(self, *a, **k):
                return 200, {"command_id": "c"}

            def get_responses(self, command_id):
                calls.append(now[0])
                return {"responses": [row()] if now[0] >= 1.0 else []}

        def sleep(seconds):
            now[0] += 0.3

        d = ir.Definition(id="g", plugin="p", action="a", type="action", platforms=[], parameters={},
                          result_columns=[], approval_mode="auto", risk="destructive", file="g.yaml")
        with mock.patch.object(ir.time, "monotonic", lambda: now[0]), mock.patch.object(ir.time, "sleep", sleep):
            out = ir.exercise(Client(), d, {"g": {}}, 1.0, AGENT, "linux", NullManifest(),
                              ir.RunControl(poll_explicit=True))
        self.assertEqual(out.status, "pass")
        self.assertGreaterEqual(calls[-1], 1.0)   # the last look was after the deadline


class QESurvivors(RunnerCase):
    def test_the_http_error_body_is_closed_after_a_poll(self):
        closed = []

        class Err(ir.urllib.error.HTTPError):
            def close(self):
                closed.append(1)
                super().close()

        def boom(req, timeout=None):
            raise Err("u", 403, "forbidden", {}, io.BytesIO(
                b'{"error": {"code": 403, "message": "denied", "permission": "Response:Read"}}'))

        c = ir.YuzuClient("http://127.0.0.1:1")
        c.opener = mock.Mock(open=boom)
        out = c.get_responses("c1")
        self.assertEqual((out["code"], out["permission"], closed), (403, "Response:Read", [1]))
        self.assertEqual(out["error"], "HTTP 403 denied")

    def test_a_mixed_run_whose_safe_row_is_skipped_by_platform_counts_only_targeted_skips(self):
        other = "windows" if ir.HOST != "windows" else "linux"
        defs = [definition("t.safe", "safe", platforms=[other]),
                definition("t.d0", "destructive"), definition("t.d1", "destructive")]
        self.fake.execute = lambda post: (202, b'{"status": "pending_approval", "approval_id": "a"}', 0)
        r = self.run_runner(defs, risks=("safe", "destructive"), overrides={"t.d0": {}, "t.d1": {}})
        self.assertEqual(r.rc, 1)
        self.assertIn("no destructive/forensic row was executed (2 pending_approval, 0 skipped)", r.err)

    def test_a_refusal_sequence_with_a_coded_non_refusal_in_it_does_not_stop(self):
        def script(cid, n):
            if n in (1, 2, 4):
                return 403, b'{"error": {"code": 403, "message": "no"}}'
            if n == 3:
                return 500, b'{"error": {"code": 500, "message": "boom"}}'
            return 200, json.dumps({"responses": [row()]}).encode()

        self.fake.poll_script = script
        r = self.run_runner([definition("t.d0", "destructive")], overrides={"t.d0": {}})
        self.assertEqual((r.rc, r.summary["stop_reason"]), (0, ""))


class Grading(unittest.TestCase):
    """exercise() against the REAL response row shape."""

    class Client:
        def __init__(self, polls):
            self.polls, self.n = polls, 0

        def execute_instruction(self, def_id, params, agent_ids=None):
            return 200, {"command_id": "c"}

        def get_responses(self, command_id):
            rows = self.polls[min(self.n, len(self.polls) - 1)]
            self.n += 1
            return {"responses": rows}

    def setUp(self):
        p = mock.patch.object(ir, "POLL_INTERVAL_S", 0.01)
        p.start()
        self.addCleanup(p.stop)

    def grade(self, risk, *polls, timeout=30):
        d = ir.Definition(id="g", plugin="p", action="a", type="action", platforms=[], parameters={},
                          result_columns=[], approval_mode="auto", risk=risk, file="g.yaml")
        return ir.exercise(self.Client(list(polls)), d, {"g": {}}, timeout, AGENT, "linux", NullManifest(),
                           ir.RunControl(poll_explicit=True))

    def test_success_with_no_error_detail_passes(self):
        for risk in ("destructive", "forensic"):
            for output in ("x", ""):
                with self.subTest(risk=risk, output=output):
                    self.assertEqual(self.grade(risk, [row(output=output)]).status, "pass")

    def test_failure_timeout_and_rejected_fail_with_or_without_output(self):
        for status, name in ((FAILURE, "FAILURE"), (TIMEOUT, "TIMEOUT"), (REJECTED, "REJECTED")):
            for output in ("", "some output"):
                for risk in ("destructive", "forensic"):
                    with self.subTest(status=name, output=output, risk=risk):
                        out = self.grade(risk, [row(status=status, output=output)])
                        self.assertEqual(out.status, "fail")
                        self.assertIn(name, out.note)

    def test_success_with_an_error_detail_fails_and_names_it(self):
        out = self.grade("destructive", [row(error_detail="plugin said no\x1b[2J")])
        self.assertEqual(out.status, "fail")
        self.assertIn("plugin said no", out.note)
        self.assertNotIn("\x1b", out.note)

    def test_running_then_success_passes_after_waiting(self):
        out = self.grade("destructive", [row(status=RUNNING, output="part")], [row(status=RUNNING)],
                         [row(status=SUCCESS)])
        self.assertEqual(out.status, "pass")

    def test_a_targeted_row_gets_the_longer_poll_timeout_but_a_safe_row_does_not(self):
        slow = [[row(status=RUNNING)]] * 60 + [[row(status=SUCCESS)]]  # ~0.6 s at 0.01 s per poll
        d = ir.Definition(id="g", plugin="p", action="a", type="action", platforms=[], parameters={},
                          result_columns=[], approval_mode="auto", risk="destructive", file="g.yaml")
        out = ir.exercise(self.Client(list(slow)), d, {"g": {}}, 0.3, AGENT, "linux", NullManifest(),
                          None, 5)
        self.assertEqual(out.status, "pass")
        out = ir.exercise(self.Client(list(slow)), d, {"g": {}}, 0.3, AGENT, "linux", NullManifest())
        self.assertEqual(out.status, "fail")

    def test_a_safe_row_never_gets_the_targeted_timeout(self):
        class Quiet:
            n = 0

            def execute_instruction(self, *a, **k):
                return 200, {"command_id": "c"}

            def get_responses(self, command_id):
                Quiet.n += 1
                return {"responses": [] if Quiet.n < 60 else [row()]}

        d = ir.Definition(id="g", plugin="p", action="a", type="action", platforms=[], parameters={},
                          result_columns=[], approval_mode="auto", risk="safe", file="g.yaml")
        out = ir.exercise(Quiet(), d, {}, 0.3, AGENT, "linux", None, None, 5)
        self.assertEqual(out.status, "fail")
        self.assertIn("no response within 0.3s", out.note)

    def test_the_poll_timeout_is_always_named_in_a_deadline_note(self):
        d = ir.Definition(id="g", plugin="p", action="a", type="action", platforms=[], parameters={},
                          result_columns=[], approval_mode="auto", risk="destructive", file="g.yaml")
        for explicit, want in ((True, "(--poll-timeout)"), (False, "raise --poll-timeout")):
            out = ir.exercise(self.Client([[]]), d, {"g": {}}, 0.3, AGENT, "linux", NullManifest(),
                              ir.RunControl(poll_explicit=explicit))
            self.assertIn(want, out.note)

    def test_running_forever_fails_when_the_deadline_passes(self):
        out = self.grade("destructive", [row(status=RUNNING, output="part")], timeout=0.3)
        self.assertEqual(out.status, "fail")
        self.assertIn("still running after 0.3s", out.note)
        self.assertIn("may still be executing", out.note)

    def test_one_agent_still_running_or_failed_among_successes_fails(self):
        done, running = row(), row(status=RUNNING)
        self.assertEqual(self.grade("destructive", [done, running], timeout=0.3).status, "fail")
        self.assertEqual(self.grade("destructive", [done, row(status=FAILURE)]).status, "fail")

    def test_no_rows_at_all_fails(self):
        out = self.grade("forensic", [], timeout=0.3)
        self.assertEqual(out.status, "fail")
        self.assertIn("no response rows within 0.3s (--poll-timeout)", out.note)

    def test_a_status_that_is_not_the_wire_integer_never_passes(self):
        for resp in ({"status": "ok", "output": "x"}, {"status": None}, {"status": True},
                     {"status": "error", "output": ""}, {"status": 1, "rc": 3}, "not-an-object"):
            with self.subTest(resp=resp):
                self.assertEqual(self.grade("destructive", [resp]).status, "fail")

    def test_the_real_shape_probe_each_non_success_status_with_empty_output_fails(self):
        for status in (FAILURE, TIMEOUT, REJECTED):
            self.assertEqual(self.grade("destructive", [row(status=status, output="")]).status, "fail")
        self.assertEqual(self.grade("destructive", [row(status=RUNNING, output="part")], timeout=0.3).status, "fail")

    def test_safe_and_mutating_grading_is_the_original_one(self):
        # Unchanged on purpose (a separate follow-up): it reads a string status and an `rc`.
        for risk in ("safe", "mutating"):
            with self.subTest(risk=risk):
                self.assertEqual(self.grade(risk, [row(status=RUNNING, output="part")]).status, "pass")
                self.assertEqual(self.grade(
                    risk, [{"status": "error", "rc": 1, "output": "boom"}]).status, "fail")
                self.assertEqual(self.grade(
                    risk, [{"status": "error", "rc": 1, "output": ""}]).status, "pass")


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
