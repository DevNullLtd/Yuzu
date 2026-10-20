#!/usr/bin/env python3
"""Self-test for tests/test_same_site_wiring_lexical.py.

Feeds in-memory mutated copies of server/core/src/server.cpp to the gate's `problems()` and
asserts each mutation is reported (so a pattern gone stale, or a check that can no longer fail,
is a loud failure here), plus positive cases that must stay clean: a second handler
registration, braces and quotes inside literals, comment text containing pinned tokens, and the
optional step-up allowance. The real file is never written.

Usage: python3 -I tests/test_same_site_wiring_lexical_selftest.py
"""
import importlib.util
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"

# `python3 -I` drops the script directory from sys.path, so load the gate by path.
_spec = importlib.util.spec_from_file_location("same_site_gate",
                                               HERE / "test_same_site_wiring_lexical.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

GATE_STMT = re.compile(
    r"[ \t]*if \(detail::apply_same_site_write_gate\(.*?\)\) \{\s*"
    r"return httplib::Server::HandlerResponse::Handled;\s*\}\n", re.DOTALL)
RESOLVE_LINE = "auto session = auth_routes_->resolve_session(req);\n"
STASH_LINE = "detail::tls_engine_principal() = session->is_engine();\n"
TOP_RESET = "detail::tls_engine_principal() = false;\n"
PRE_ROUTING = "web_server_->set_pre_routing_handler("
PRE_REQUEST = "web_server_->set_pre_request_handler("


def once(src, anchor):
    assert src.count(anchor) == 1, f"anchor not unique/present (stale mutation): {anchor!r}"
    return src.index(anchor)


def gate_stmt(src):
    m = GATE_STMT.search(src)
    assert m, "gate statement not found (stale mutation)"
    return m


def remove_gate(src):
    m = gate_stmt(src)
    return src[:m.start()] + src[m.end():], m.group(0)


def insert_before(src, anchor, text):
    at = once(src, anchor)
    return src[:at] + text + src[at:]


def insert_after(src, anchor, text):
    at = once(src, anchor) + len(anchor)
    return src[:at] + text + src[at:]


def lambda_open_brace(src, opener):
    """Index of the `{` that opens the lambda body passed to `opener`."""
    at = once(src, opener)
    depth, i = 0, src.index("(", at)
    while True:
        c = src[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "{" and depth == 1:
            return i
        i += 1


def last_unhandled_of_pre_routing(src):
    start = lambda_open_brace(src, PRE_ROUTING)
    end = gate.find_close(src, start)
    ret = "return httplib::Server::HandlerResponse::Unhandled;"
    at = src.rfind(ret, start, end)
    assert at > 0
    return at


# --- mutations: name -> (function(raw) -> mutated, substring expected in some problem) -------

def m_delete_call(s):
    return remove_gate(s)[0]


def m_move_above_resolve(s):
    s, stmt = remove_gate(s)
    return insert_before(s, RESOLVE_LINE, stmt)


def m_move_below_stash(s):
    s, stmt = remove_gate(s)
    return insert_after(s, STASH_LINE, stmt)


def m_fifth_early_unhandled(s):
    return insert_before(s, RESOLVE_LINE,
                         'if (req.path == "/other") { '
                         'return httplib::Server::HandlerResponse::Unhandled; }\n')


def m_widen_exempt(s):
    old = "if (is_login_exempt_path(req.path)) {"
    once(s, old)
    return s.replace(old, 'if (is_login_exempt_path(req.path) || '
                          'req.path.starts_with("/canary/")) {')


def m_metrics_prefix(s):
    old = 'if (req.path == "/metrics") {'
    once(s, old)
    return s.replace(old, 'if (req.path.starts_with("/metrics")) {')


def m_unhandled_between_401_and_gate(s):
    m = gate_stmt(s)
    return (s[:m.start()] + "return httplib::Server::HandlerResponse::Unhandled;\n" +
            s[m.start():])


def m_session_replaced_by_req(s):
    m = gate_stmt(s)
    return s[:m.start()] + m.group(0).replace("*session", "req", 1) + s[m.end():]


def m_duplicate_call(s):
    m = gate_stmt(s)
    return s[:m.end()] + m.group(0) + s[m.end():]


def m_remove_include(s):
    old = '#include "same_site_write_gate.hpp"'
    once(s, old)
    return s.replace(old, "")


def m_stage_before_gate(s):
    m = gate_stmt(s)
    return s[:m.start()] + "run_pre_request_stage(req, res, {});\n" + s[m.start():]


def m_consume_pass_after_resolve(s):
    return insert_after(s, RESOLVE_LINE, 'consume_step_up_pass(req, "x");\n')


def m_extra_argument(s):
    m = gate_stmt(s)
    return s[:m.start()] + m.group(0).replace("same_site_audit_fn_)", "same_site_audit_fn_, hook)",
                                              1) + s[m.end():]


def m_audit_sink_not_wired(s):
    old = "return auth_routes_->audit_log_for_principal(r, action"
    once(s, old)
    return s.replace(old, "return auth_routes_->some_other_sink(r, action")


def m_probe_condition_widened(s):
    old = "if (yuzu::server::health::is_probe_path(req.path)) {"
    once(s, old)
    return s.replace(old, 'if (yuzu::server::health::is_probe_path(req.path) || '
                          'req.method == "GET") {')


def m_local_metrics_widened(s):
    old = 'if (req.remote_addr == "127.0.0.1" || req.remote_addr == "::1") {'
    once(s, old)
    return s.replace(old, 'if (req.remote_addr == "127.0.0.1" || req.remote_addr == "::1" || '
                          'true) {')


def m_refusal_returns_unhandled(s):
    m = gate_stmt(s)
    mutated = m.group(0).replace("HandlerResponse::Handled", "HandlerResponse::Unhandled")
    return s[:m.start()] + mutated + s[m.end():]


def m_gate_after_last_return(s):
    s, stmt = remove_gate(s)
    at = last_unhandled_of_pre_routing(s)
    ret = "return httplib::Server::HandlerResponse::Unhandled;"
    return s[:at + len(ret)] + "\n" + stmt + s[at + len(ret):]


def m_call_only_in_comment(s):
    s, stmt = remove_gate(s)
    return insert_before(s, RESOLVE_LINE,
                         "// if (detail::apply_same_site_write_gate(req, res, *session, "
                         "cfg_.csrf_trusted_origins, metrics_, same_site_audit_fn_)) {}\n")


def m_camel_case_step_up(s):
    return insert_after(s, RESOLVE_LINE, "if (stepUpPending(req)) { res.status = 401; }\n")


def m_step_up_allowance_too_late(s):
    return insert_before(s, RESOLVE_LINE, "clear_step_up_pass();\n")


def m_stage_twice(s):
    at = lambda_open_brace(s, PRE_REQUEST)
    s = s[:at + 1] + "\nrun_pre_request_stage(req, res, kNone);\n" + s[at + 1:]
    return s + "\nvoid f() { run_pre_request_stage(req, res, kNone); }\n"


def m_second_pre_routing_registration(s):
    return s + "\nvoid g() { svr.set_pre_routing_handler([](const auto&, auto&) { " \
               "return httplib::Server::HandlerResponse::Unhandled; }); }\n"


MUTATIONS = [
    ("delete the gate call", m_delete_call, "exactly one apply_same_site_write_gate("),
    ("gate above resolve_session", m_move_above_resolve, "must come after"),
    ("gate below the engine stash", m_move_below_stash, "before the engine-principal stash"),
    ("fifth early Unhandled", m_fifth_early_unhandled, "Unhandled returns before"),
    ("widened exempt condition", m_widen_exempt, "early Unhandled return #2"),
    ("metrics branch becomes a prefix match", m_metrics_prefix, "early Unhandled return #3"),
    ("Unhandled between the 401 block and the gate", m_unhandled_between_401_and_gate,
     "between resolve_session and the gate call"),
    ("*session replaced by req", m_session_replaced_by_req, "arguments are not exactly"),
    ("duplicated gate call", m_duplicate_call, "exactly one apply_same_site_write_gate("),
    ("include removed", m_remove_include, "no longer has #include"),
    ("step-up stage before the gate", m_stage_before_gate, "run_pre_request_stage( must not"),
    ("step-up pass consumed after resolve", m_consume_pass_after_resolve, "step-up token"),
    ("extra gate argument", m_extra_argument, "arguments are not exactly"),
    ("audit sink not wired to the audit log", m_audit_sink_not_wired,
     "not initialised from auth_routes_->audit_log_for_principal("),
    ("probe condition widened", m_probe_condition_widened, "early Unhandled return #1"),
    ("local-address metrics condition widened", m_local_metrics_widened,
     "early Unhandled return #3"),
    ("refusal returns Unhandled", m_refusal_returns_unhandled, "inside its `if`"),
    ("gate after the last Unhandled return", m_gate_after_last_return, "must come after"),
    ("call survives only in a comment", m_call_only_in_comment,
     "exactly one apply_same_site_write_gate("),
    ("camel-case step-up token", m_camel_case_step_up, "step-up token"),
    ("step-up allowance after the first early return", m_step_up_allowance_too_late,
     "must sit before the first early Unhandled"),
    ("step-up stage called twice", m_stage_twice, "must occur exactly once"),
    ("second pre-routing registration", m_second_pre_routing_registration,
     "exactly one set_pre_routing_handler("),
]


# --- positive cases: must stay clean -----------------------------------------------------------

def p_second_pre_request_handler_registration(s):
    return insert_before(s, PRE_ROUTING,
                         "web_server_->set_pre_request_handler([](const httplib::Request&, "
                         "httplib::Response&) { return httplib::Server::HandlerResponse::"
                         "Unhandled; });\n")


def p_literals_and_comments_with_tokens(s):
    return insert_after(
        s, TOP_RESET,
        'const char* k = "}{\'";\n'
        "char c = '{';\n"
        "// return httplib::Server::HandlerResponse::Unhandled; apply_same_site_write_gate(\n"
        "/* run_pre_request_stage( stepUp { */\n")


def p_optional_clear_step_up_pass_at_top(s):
    return insert_after(s, TOP_RESET, "clear_step_up_pass();\n")


def p_qualified_clear_step_up_pass_at_top(s):
    return insert_after(s, TOP_RESET, "detail::clear_step_up_pass();\n")


def p_stage_inside_pre_request_handler(s):
    at = lambda_open_brace(s, PRE_REQUEST)
    return s[:at + 1] + "\nrun_pre_request_stage(req, res, kNone);\n" + s[at + 1:]


def p_unqualified_gate_spelling(s):
    return s.replace("if (detail::apply_same_site_write_gate(", "if (apply_same_site_write_gate(", 1)


def p_reflowed_call(s):
    m = gate_stmt(s)
    flat = re.sub(r"\s+", " ", m.group(0))
    return s[:m.start()] + flat.replace("(req,", "(\n  req,") + "\n" + s[m.end():]


POSITIVES = [
    ("second pre_request handler registration", p_second_pre_request_handler_registration),
    ("literals and comments carrying pinned tokens", p_literals_and_comments_with_tokens),
    ("optional clear_step_up_pass at the top", p_optional_clear_step_up_pass_at_top),
    ("qualified clear_step_up_pass at the top", p_qualified_clear_step_up_pass_at_top),
    ("run_pre_request_stage only in the pre_request lambda", p_stage_inside_pre_request_handler),
    ("unqualified gate spelling", p_unqualified_gate_spelling),
    ("reflowed call", p_reflowed_call),
]


class SameSiteWiringSelftest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = SERVER_CPP.read_text(encoding="utf-8")

    def test_unmutated_source_is_clean(self):
        self.assertEqual(gate.problems(self.raw), [])

    def test_mutations_are_caught(self):
        for name, fn, expected in MUTATIONS:
            with self.subTest(mutation=name):
                mutated = fn(self.raw)
                self.assertNotEqual(mutated, self.raw, "mutation changed nothing (stale)")
                p = gate.problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertTrue(any(expected in m for m in p),
                                f"expected a problem containing {expected!r}, got {p}")

    def test_positive_cases_stay_clean(self):
        for name, fn in POSITIVES:
            with self.subTest(case=name):
                mutated = fn(self.raw)
                self.assertNotEqual(mutated, self.raw, "case changed nothing (stale)")
                self.assertEqual(gate.problems(mutated), [])

    def test_lexer_helpers(self):
        t = gate.normalise('a /* x { */ "b//c" // tail\n R"x(}{ // )x" \'}\' z')
        self.assertIn('"b//c"', t)
        self.assertNotIn("tail", t)
        text = "{ \"}\" '}' R\"x(})x\" }"
        self.assertEqual(gate.find_close(text, 0), len(text) - 1)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
