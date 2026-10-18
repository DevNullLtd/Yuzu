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
import http.server
import io
import json
import os
import signal
import socket
import stat
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
        self.execute = None            # callable(post) -> (code, bytes, delay_s) or None
        self._polled = {}
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
                    body = fake.agents_raw if fake.agents_raw is not None else \
                        json.dumps(fake.agents).encode()
                    self._send(fake.agents_code, body)
                elif self.path.startswith("/api/responses/"):
                    cid = self.path.rsplit("/", 1)[1]
                    with fake._lock:
                        n = fake._polled[cid] = fake._polled.get(cid, 0) + 1
                    body = fake.responses_raw if fake.responses_raw is not None else \
                        json.dumps({"responses": fake.polls(cid, n)}).encode()
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
        p = mock.patch.object(ir, "POLL_INTERVAL_S", 0.02)
        p.start()
        self.addCleanup(p.stop)
        self.fake.manifest_path = str(self.tmp / "manifest.jsonl")

    def run_runner(self, defs, *, overrides=None, raw_overrides=None, risks=("destructive",),
                   targeted=True, extra=(), dashboard=None):
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
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = ir.main(argv)
        outfile = self.tmp / "out.json"
        summary = json.loads(outfile.read_text()) if outfile.exists() else None
        mf = Path(self.fake.manifest_path)
        manifest = [json.loads(line) for line in mf.read_text().splitlines()] if mf.exists() else []
        return Result(rc, out.getvalue(), err.getvalue(), summary, manifest)

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
                self.assertIn("--run-id", r.err)


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
        self.assertIn("1 dispatched, 1 pending_approval (not executed), 1 skipped, 0 failed", r.out)
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
        self.assertIn("still running after 1s", out["note"])

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
        time.sleep(1.0)  # an in-flight POST finishes; nothing queued behind it may start
        self.assertEqual(r.rc, 130)
        self.assertEqual(len(self.fake.posts), 2)
        self.assertEqual(r.summary["aborted"], "KeyboardInterrupt")
        self.assertEqual(len(r.dispatch_lines()), 2)

    def test_untargeted_interrupt_is_stopped_by_cancel_futures_alone(self):
        defs = [definition(f"t.s{i}", "safe") for i in range(12)]
        self.slow_posts()
        with self.interrupt_after_posts(2), mock.patch.object(ir.RunControl, "request_stop"):
            r = self.run_runner(defs, risks=("safe",), targeted=False, extra=["--parallelism", "1"])
        time.sleep(1.0)
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
        time.sleep(1.5)
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
            self.assertIn("aborted", out.note)

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
        self.fake.execute = lambda post: (200, json.dumps({"command_id": "c"}).encode(), 3.0)
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
        time.sleep(3.2)  # let the stalled handler finish before the fake closes

    @unittest.skipIf(sys.platform == "win32", "os.kill(SIGTERM) terminates a Windows process")
    @unittest.skipUnless(threading.current_thread() is threading.main_thread(), "signals need the main thread")
    def test_sigterm_takes_the_same_path_as_ctrl_c(self):
        self.fake.execute = lambda post: (200, json.dumps({"command_id": "c"}).encode(), 3.0)
        before = signal.getsignal(signal.SIGTERM)
        timer = threading.Timer(0.8, os.kill, (os.getpid(), signal.SIGTERM))
        timer.start()
        self.addCleanup(timer.cancel)
        r = self.run_runner(self.DEFS, overrides=self.OV)
        self.assertEqual(r.rc, 130)
        self.assertEqual(r.summary["aborted"], "KeyboardInterrupt")
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)
        time.sleep(3.2)


class NullManifest:
    def record(self, *a, **k):
        pass


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
        return ir.exercise(self.Client(list(polls)), d, {"g": {}}, timeout, AGENT, "linux", NullManifest())

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
        out = self.grade("destructive", [row(status=RUNNING, output="")], [row(status=RUNNING)],
                         [row(status=SUCCESS)])
        self.assertEqual(out.status, "pass")

    def test_running_forever_fails_when_the_deadline_passes(self):
        out = self.grade("destructive", [row(status=RUNNING, output="")], timeout=1)
        self.assertEqual(out.status, "fail")
        self.assertIn("still running after 1s", out.note)
        self.assertIn("may still be executing", out.note)

    def test_one_agent_still_running_or_failed_among_successes_fails(self):
        done, running = row(agent_id="a1"), row(status=RUNNING, agent_id="a2")
        self.assertEqual(self.grade("destructive", [done, running], timeout=1).status, "fail")
        self.assertEqual(self.grade("destructive", [done, row(status=FAILURE, agent_id="a2")]).status, "fail")

    def test_no_rows_at_all_fails(self):
        out = self.grade("forensic", [], timeout=1)
        self.assertEqual(out.status, "fail")
        self.assertIn("still running after 1s", out.note)

    def test_a_status_that_is_not_the_wire_integer_never_passes(self):
        for resp in ({"status": "ok", "output": "x"}, {"status": None}, {"status": True},
                     {"status": "error", "output": ""}, {"status": 1, "rc": 3}, "not-an-object"):
            with self.subTest(resp=resp):
                self.assertEqual(self.grade("destructive", [resp]).status, "fail")

    def test_the_real_shape_probe_each_non_success_status_with_empty_output_fails(self):
        for status in (FAILURE, TIMEOUT, REJECTED):
            self.assertEqual(self.grade("destructive", [row(status=status, output="")]).status, "fail")
        self.assertEqual(self.grade("destructive", [row(status=RUNNING, output="")], timeout=1).status, "fail")

    def test_safe_and_mutating_grading_is_the_original_one(self):
        # Unchanged on purpose (a separate follow-up): it reads a string status and an `rc`.
        for risk in ("safe", "mutating"):
            with self.subTest(risk=risk):
                self.assertEqual(self.grade(risk, [row(status=RUNNING, output="")]).status, "pass")
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
