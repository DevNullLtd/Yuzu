#!/usr/bin/env python3
"""test_instructions_runner_target.py - the /test --instructions runner sends an explicit target
for the destructive and forensic classes, and for nothing else (#5261).

The server refuses a broadcast for a Destructive or Forensics capability row (HTTP 400) and wants
an explicit, in-scope `agent_ids` list (any non-empty list for Destructive, exactly one entry for
Forensics), so the runner takes --target-agent-id, sends it
with those two classes only, and refuses to select them without it or (off loopback) without
--allow-remote. Also pins the error-body handling that used to raise on a string `error`.

Runnable standalone: `python3 tests/test_instructions_runner_target.py`. Hermetic: a fake client,
no network and no server (the refusals return before the runner would log in).
"""
import io
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "test"))
import instructions_runner as ir  # noqa: E402

AGENT = "agent-under-test"
HOSTNAME = "Box-1"
ANSWERED = [{"output": "x", "status": 1, "error_detail": ""}]  # the wire row shape


def make_def(risk, plugin="p"):
    return ir.Definition(id=f"x.{risk}", plugin=plugin, action="a", type="action", platforms=[],
                         parameters={}, result_columns=[], approval_mode="auto", risk=risk,
                         file="x.yaml")


class NullManifest:
    def record(self, *a, **k):
        pass


class RecordingClient:
    """Stands in for YuzuClient: mirrors its signature, so an agent_ids argument is recorded."""

    def __init__(self, code=200, payload=None):
        self.calls = []
        self.code = code
        self.payload = {"command_id": "c1"} if payload is None else payload

    def execute_instruction(self, def_id, params, agent_ids=None):
        self.calls.append((def_id, params, agent_ids))
        return self.code, self.payload

    def get_responses(self, command_id):
        return {"responses": ANSWERED}


class OldSignatureClient(RecordingClient):
    """The pre-#5261 signature: a safe/mutating dispatch must not need the new argument."""

    def execute_instruction(self, def_id, params):
        self.calls.append((def_id, params, None))
        return self.code, self.payload


def parse(*argv, dashboard="http://127.0.0.1:8080"):
    return ir.parse_args(["--dashboard", dashboard, "--password", "p", *argv])


def targeted(*argv, dashboard="http://127.0.0.1:8080", risk="destructive"):
    """A fully specified targeted run, so a test names only the one thing it takes away."""
    base = ["--risks", risk, "--target-agent-id", AGENT, "--confirm-target", HOSTNAME,
            "--run-id", "r1"]
    return parse(*base, *argv, dashboard=dashboard)


class TargetIsSent(unittest.TestCase):
    def test_opt_in_classes_send_exactly_the_one_agent(self):
        for risk in ("destructive", "forensic"):
            with self.subTest(risk=risk):
                client = RecordingClient()
                out = ir.exercise(client, make_def(risk), {f"x.{risk}": {}}, 30, AGENT, "", NullManifest())
                self.assertEqual(out.status, "pass")
                self.assertTrue(out.dispatched)
                self.assertEqual([c[2] for c in client.calls], [[AGENT]])
                self.assertEqual([c[1] for c in client.calls], [{}])

    def test_a_targeted_definition_is_never_dispatched_unrecorded(self):
        client = RecordingClient()
        out = ir.exercise(client, make_def("destructive"), {"x.destructive": {}}, 30, AGENT)
        self.assertEqual((out.status, client.calls), ("error", []))
        self.assertIn("no manifest", out.note)

    def test_safe_and_mutating_send_nothing_extra(self):
        for risk in ("safe", "mutating", "server-internal"):
            with self.subTest(risk=risk):
                # OldSignatureClient raises TypeError if the call carries agent_ids at all.
                client = OldSignatureClient()
                self.assertEqual(ir.exercise(client, make_def(risk), {}, 30, AGENT).status, "pass")
                self.assertEqual([c[2] for c in client.calls], [None])

    def test_default_run_is_unchanged(self):
        client = OldSignatureClient()
        self.assertEqual(ir.exercise(client, make_def("mutating"), {}, 30).status, "pass")
        self.assertEqual([c[2] for c in client.calls], [None])

    def test_request_body_gains_agent_ids_only_when_given(self):
        sent = []

        class Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b"{}"

        c = ir.YuzuClient("http://127.0.0.1:8080")
        c.post_opener = mock.Mock(open=lambda req, timeout=None: sent.append(req.data) or Resp())
        c.execute_instruction("a.b", {"k": 1})
        c.execute_instruction("a.b", {"k": 1}, [AGENT])
        self.assertEqual(sent[0], b'{"params": {"k": "1"}}')
        self.assertEqual(sent[1], b'{"params": {"k": "1"}, "agent_ids": ["agent-under-test"]}')


class Refusals(unittest.TestCase):
    def test_opt_in_class_without_a_target_is_refused(self):
        want = ("needs --target-agent-id ID (the id of one connected agent) "
                "and --confirm-target HOSTNAME")
        for risk in ("destructive", "forensic"):
            with self.subTest(risk=risk):
                self.assertIn(want, ir.targeting_error(parse("--risks", risk)))
        for missing in ("--target-agent-id", "--confirm-target"):
            with self.subTest(missing=missing):
                argv = ["--risks", "destructive", "--target-agent-id", AGENT,
                        "--confirm-target", HOSTNAME, "--run-id", "r1"]
                i = argv.index(missing)
                self.assertIn(want, ir.targeting_error(parse(*argv[:i], *argv[i + 2:])))

    def test_a_blank_target_counts_as_not_given_and_a_padded_one_is_stripped(self):
        self.assertIn("--target-agent-id", ir.targeting_error(parse(
            "--risks", "forensic", "--target-agent-id", "  ", "--confirm-target", HOSTNAME,
            "--run-id", "r1")))
        self.assertEqual(targeted("--target-agent-id", f" {AGENT}\t").target_agent_id, AGENT)

    def test_a_targeted_run_needs_a_run_id(self):
        a = parse("--risks", "destructive", "--target-agent-id", AGENT, "--confirm-target", HOSTNAME)
        self.assertIn("--run-id", ir.targeting_error(a))

    def test_main_exits_2_before_login_or_dispatch(self):
        cases = ((["--risks", "destructive"], "http://127.0.0.1:8080", "--target-agent-id"),
                 (["--risks", "safe", "forensic", "--target-agent-id", AGENT, "--confirm-target",
                   HOSTNAME, "--run-id", "r1"], "http://yuzu.example.com:8080", "--allow-remote"))
        with mock.patch.object(ir, "YuzuClient", side_effect=AssertionError("must not connect")):
            for extra, dashboard, text in cases:
                with self.subTest(extra=extra), redirect_stderr(io.StringIO()) as err:
                    argv = ["--dashboard", dashboard, "--password", "p", *extra]
                    self.assertEqual(ir.main(argv), 2)
                    self.assertIn("instructions_runner:", err.getvalue())
                    self.assertIn(text, err.getvalue())

    def test_remote_dashboard_needs_allow_remote(self):
        remote = "http://yuzu.example.com:8080"
        self.assertIn("--allow-remote", ir.targeting_error(targeted(dashboard=remote)))
        self.assertEqual(ir.targeting_error(targeted("--allow-remote", dashboard=remote)), "")

    def test_loopback_spellings_are_allowed_without_allow_remote(self):
        for url in ("http://127.0.0.1:8080", "https://localhost:8443", "http://[::1]:8080"):
            with self.subTest(url=url):
                self.assertEqual(ir.targeting_error(targeted(dashboard=url, risk="forensic")), "")

    def test_lookalike_hosts_are_not_loopback(self):
        for url in ("http://evillocalhost:8080", "http://127.0.0.1.evil.example:8080",
                    "http://localhost.evil.example:8080", "http://localhost@evil.example/",
                    "http://[bad", "http://\u2100.example"):
            with self.subTest(url=url):
                self.assertIn("--allow-remote", ir.targeting_error(targeted(dashboard=url)))

    def test_default_and_other_classes_need_none_of_it(self):
        remote = "http://yuzu.example.com"
        for risks in ([], ["server-internal"], ["interactive", "network-disrupt"]):
            with self.subTest(risks=risks):
                a = parse(*(["--risks", *risks] if risks else []), dashboard=remote)
                self.assertEqual(ir.targeting_error(a), "")


class ErrorBodyHandling(unittest.TestCase):
    def note(self, payload):
        out = ir.exercise(RecordingClient(code=500, payload=payload), make_def("safe"), {}, 0)
        self.assertEqual(out.status, "fail")
        return out.note

    def test_dict_error_keeps_its_message(self):
        self.assertEqual(self.note({"error": {"message": "boom"}}), "HTTP 500 boom")

    def test_string_error_is_the_message(self):
        self.assertEqual(self.note({"error": "boom"}), "HTTP 500 boom")

    def test_reason_or_string_code_is_prefixed_to_the_message(self):
        self.assertEqual(self.note({"error": {"code": 400, "message": "m", "reason": "r_x"}}),
                         "HTTP 500 r_x: m")
        self.assertEqual(self.note({"error": {"code": "destructive_untargeted", "message": "m"}}),
                         "HTTP 500 destructive_untargeted: m")
        self.assertEqual(self.note({"error": {"code": 400, "message": "m"}, "reason": "top"}),
                         "HTTP 500 top: m")

    def test_missing_malformed_or_non_dict_bodies_never_raise(self):
        for payload in ({}, {"error": None}, {"error": {}}, {"error": {"message": 7}},
                        {"error": 7}, ["boom"], "boom"):
            with self.subTest(payload=payload):
                self.assertEqual(self.note(payload), "HTTP 500")


if __name__ == "__main__":
    unittest.main(verbosity=2)
