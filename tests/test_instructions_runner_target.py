#!/usr/bin/env python3
"""test_instructions_runner_target.py - the /test --instructions runner sends an explicit target
for the destructive and forensic classes, and for nothing else (#5261).

The server refuses a broadcast for a Destructive or Forensics capability row (HTTP 400) and wants
exactly one explicit, in-scope `agent_ids` entry, so the runner takes --target-agent-id, sends it
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
ANSWERED = [{"output": "x", "status": "ok", "rc": 0}]


def make_def(risk, plugin="p"):
    return ir.Definition(id=f"x.{risk}", plugin=plugin, action="a", type="action", platforms=[],
                         parameters={}, result_columns=[], approval_mode="auto", risk=risk,
                         file="x.yaml")


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


class TargetIsSent(unittest.TestCase):
    def test_opt_in_classes_send_exactly_the_one_agent(self):
        for risk in ("destructive", "forensic"):
            with self.subTest(risk=risk):
                client = RecordingClient()
                out = ir.exercise(client, make_def(risk), {}, 30, AGENT)
                self.assertEqual(out.status, "pass")
                self.assertEqual([c[2] for c in client.calls], [[AGENT]])

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
        c.opener = mock.Mock(open=lambda req, timeout=None: sent.append(req.data) or Resp())
        c.execute_instruction("a.b", {"k": 1})
        c.execute_instruction("a.b", {"k": 1}, [AGENT])
        self.assertEqual(sent[0], b'{"params": {"k": "1"}}')
        self.assertEqual(sent[1], b'{"params": {"k": "1"}, "agent_ids": ["agent-under-test"]}')


class Refusals(unittest.TestCase):
    def test_opt_in_class_without_a_target_is_refused(self):
        for risk in ("destructive", "forensic"):
            with self.subTest(risk=risk):
                self.assertIn("--target-agent-id", ir.targeting_error(parse("--risks", risk)))

    def test_main_exits_2_before_login_or_dispatch(self):
        cases = (["--risks", "destructive"],
                 ["--risks", "safe", "forensic", "--target-agent-id", AGENT,
                  "--dashboard", "http://yuzu.example.com:8080"])
        with mock.patch.object(ir, "YuzuClient", side_effect=AssertionError("must not connect")):
            for extra in cases:
                with self.subTest(extra=extra), redirect_stderr(io.StringIO()) as err:
                    argv = ["--dashboard", "http://127.0.0.1:8080", "--password", "p", *extra]
                    self.assertEqual(ir.main(argv), 2)
                    self.assertIn("instructions_runner:", err.getvalue())

    def test_remote_dashboard_needs_allow_remote(self):
        remote = "http://yuzu.example.com:8080"
        base = ("--risks", "destructive", "--target-agent-id", AGENT)
        self.assertIn("--allow-remote", ir.targeting_error(parse(*base, dashboard=remote)))
        self.assertEqual(ir.targeting_error(parse(*base, "--allow-remote", dashboard=remote)), "")

    def test_loopback_spellings_are_allowed_without_allow_remote(self):
        for url in ("http://127.0.0.1:8080", "https://localhost:8443", "http://[::1]:8080"):
            with self.subTest(url=url):
                a = parse("--risks", "forensic", "--target-agent-id", AGENT, dashboard=url)
                self.assertEqual(ir.targeting_error(a), "")

    def test_a_lookalike_host_is_not_loopback(self):
        a = parse("--risks", "destructive", "--target-agent-id", AGENT,
                  dashboard="http://localhost.evil.example:8080")
        self.assertIn("--allow-remote", ir.targeting_error(a))

    def test_default_and_other_classes_need_neither(self):
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

    def test_missing_malformed_or_non_dict_bodies_never_raise(self):
        for payload in ({}, {"error": None}, {"error": {}}, {"error": {"message": 7}},
                        {"error": 7}, ["boom"], "boom"):
            with self.subTest(payload=payload):
                self.assertEqual(self.note(payload), "HTTP 500")


if __name__ == "__main__":
    unittest.main(verbosity=2)
