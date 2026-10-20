#!/usr/bin/env python3
"""Self-test for tests/test_same_site_wiring_lexical.py.

Feeds in-memory mutated copies of server/core/src/server.cpp to the gate's `problems()` and
asserts each mutation is reported (so a pattern gone stale, or a check that can no longer fail,
is a loud failure here), plus positive cases that must stay clean: a second handler
registration, braces and quotes inside literals, comment text containing pinned tokens, prefixed
and plain char literals holding a quote, digit separators, a macro that names nothing the lambda
uses, and the optional step-up allowance. A backslash-newline is NOT a positive any more: the gate
rejects every line splice (ANY backslash then blanks then end of line) wherever it appears, so each
splice shape is a mutation row. The registration inventory over the other source files is covered
with synthetic temp trees (the repo is never touched). The real file is never written.

Every row runs against a TRIMMED copy of server.cpp (the include line, the two handler
registrations and the audit-sink declaration, verbatim): lexing the 1.5 MB file ~70 times made the
selftest take 10 s. The rows in FULL_FILE_ROWS (the file-level counts and the ones that touch text
far from the pre-routing lambda) ALSO run against the complete file, and the unmutated complete file
is checked, so nothing that needs the whole file is skipped.

Usage: python3 -I tests/test_same_site_wiring_lexical_selftest.py
"""
import importlib.util
import re
import sys
import tempfile
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
    r"^[ \t]*if \(detail::apply_same_site_write_gate\(.*?\)\) \{\s*"
    r"return httplib::Server::HandlerResponse::Handled;\s*\}\n", re.DOTALL | re.MULTILINE)
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


def masked(src):
    """`src` with every comment replaced by spaces (same length), so a scan that walks the raw
    text is not derailed by an apostrophe inside a comment."""
    return gate._TOKEN_RE.sub(
        lambda m: m.group(0) if m.group(0)[0] != "/" else " " * len(m.group(0)), src)


def lambda_open_brace(src, opener):
    """Index of the `{` that opens the lambda body passed to `opener`."""
    at = once(src, opener)
    depth, i = 0, src.index("(", at)
    src = masked(src)
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
    end = gate.find_close(masked(src), start)
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


def _flat(stmt):
    return re.sub(r"\s+", " ", stmt).strip()


def _wrap_gate(s, before, after):
    m = gate_stmt(s)
    return s[:m.start()] + before + m.group(0) + after + s[m.end():]


def m_gate_in_string_literal(s):
    s, stmt = remove_gate(s)
    return insert_before(s, STASH_LINE, 'const char* k = "' + _flat(stmt) + '";\n')


def m_gate_in_raw_string_literal(s):
    s, stmt = remove_gate(s)
    return insert_before(s, STASH_LINE, 'const char* k = R"x(' + _flat(stmt) + ')x";\n')


def m_gate_in_hash_if_0(s):
    return _wrap_gate(s, "#if 0\n", "#endif\n")


def m_gate_in_hash_ifdef(s):
    return _wrap_gate(s, "#ifdef YUZU_NEVER_DEFINED\n", "#endif\n")


def m_registration_in_hash_if_0(s):
    at = once(s, PRE_ROUTING)
    return s[:at] + "#if 0\n" + s[at:] + "\n#endif\n"


def m_unbraced_if_on_path(s):
    return _wrap_gate(s, 'if (req.path != "/api/v1/canary") ', "")


def m_unbraced_if_on_method(s):
    return _wrap_gate(s, 'if (req.method != "DELETE") ', "")


def m_if_false_wrap(s):
    return _wrap_gate(s, "if (false) {\n", "}\n")


def m_else_wrap(s):
    m = gate_stmt(s)
    return (s[:m.start()] + 'if (req.path == "/api/v1/canary") { }\nelse ' + m.group(0).lstrip() +
            s[m.end():])


def m_try_wrap(s):
    return _wrap_gate(s, "try {\n", "} catch (...) { }\n")


def m_while_false_wrap(s):
    return _wrap_gate(s, "while (false) {\n", "}\n")


def m_never_invoked_lambda_wrap(s):
    return _wrap_gate(s, "auto unused_gate = [&]() -> httplib::Server::HandlerResponse {\n",
                      "return httplib::Server::HandlerResponse::Unhandled;\n};\n")


def m_bare_return_before_call(s):
    m = gate_stmt(s)
    return (s[:m.start()] +
            "return static_cast<httplib::Server::HandlerResponse>(1);\n" + s[m.start():])


def m_bare_return_before_resolve(s):
    return insert_before(s, RESOLVE_LINE,
                         'if (req.path == "/api/v1/canary") { '
                         "return static_cast<httplib::Server::HandlerResponse>(1); }\n")


def m_second_handled_return_before_call(s):
    m = gate_stmt(s)
    return (s[:m.start()] + 'if (req.method == "POST") { '
            "return httplib::Server::HandlerResponse::Handled; }\n" + s[m.start():])


def m_loop_before_call(s):
    m = gate_stmt(s)
    return s[:m.start()] + "for (;;) { }\n" + s[m.start():]


def m_throw_before_call(s):
    m = gate_stmt(s)
    return s[:m.start()] + "throw std::runtime_error(\"x\");\n" + s[m.start():]


def m_local_cfg_shadow(s):
    m = gate_stmt(s)
    return s[:m.start()] + "auto cfg_ = ServerConfig{};\n" + s[m.start():]


def m_local_metrics_shadow(s):
    m = gate_stmt(s)
    return s[:m.start()] + "MetricsRegistry metrics_;\n" + s[m.start():]


def m_session_reassigned(s):
    m = gate_stmt(s)
    return s[:m.start()] + "session = other_session;\n" + s[m.start():]


def m_lambda_capture_changed(s):
    old = PRE_ROUTING + "[this]("
    once(s, old)
    return s.replace(old, PRE_ROUTING + "[this, cfg_ = ServerConfig{}](")


def m_gate_conjunct_before(s):
    old = "if (detail::apply_same_site_write_gate("
    once(s, old)
    return s.replace(old, 'if (req.path != "/api/v1/canary" && detail::apply_same_site_write_gate(')


def m_comment_line_splice(s):
    m = gate_stmt(s)
    return s[:m.start()] + "// note \\\n" + _flat(m.group(0)) + "\n" + s[m.end():]


def m_spliced_comment_opener(s):
    m = gate_stmt(s)
    return s[:m.start()] + "/\\\n* " + _flat(m.group(0)) + " */\n" + s[m.end():]


def m_digraph_block(s):
    return _wrap_gate(s, "if (false) <%\n", "%>\n")


def m_digraph_hash_directive(s):
    at = once(s, PRE_ROUTING)
    return s[:at] + "%:if 0\n" + s[at:] + "\n%:endif\n"


def m_trigraph_splice_comment(s):
    m = gate_stmt(s)
    return s[:m.start()] + "// note ??/\n" + _flat(m.group(0)) + "\n" + s[m.end():]


def _before_gate(text):
    def mutate(s):
        m = gate_stmt(s)
        return s[:m.start()] + text + "\n" + s[m.start():]
    return mutate


def m_noreturn_before_resolve(s):
    return insert_before(s, RESOLVE_LINE, "std::abort();\n")


def m_second_registration_spaced(s):
    return s + "\nvoid g() { svr.set_pre_routing_handler (nullptr); }\n"


def m_second_registration_newline(s):
    return s + "\nvoid g() { svr.set_pre_routing_handler\n(nullptr); }\n"


def m_registration_name_mentioned(s):
    return s + "\nauto g = &httplib::Server::set_pre_routing_handler;\n"


def m_gate_conjunct_after(s):
    m = gate_stmt(s)
    flat = m.group(0).replace("same_site_audit_fn_)) {", "same_site_audit_fn_) && false) {")
    assert flat != m.group(0), "stale mutation"
    return s[:m.start()] + flat + s[m.end():]


# --- round 3: splices, prefixed char literals, rebinding, macros, audit sink -----------------

UNH = "return httplib::Server::HandlerResponse::Unhandled;"
PREFIXES = ("u8", "u", "U", "L")


def _splice_before_flat_gate(tail):
    """A `//` comment whose line ends in a backslash + `tail`, followed by the flattened gate call
    on the next line: the compiler joins the call into the comment."""
    def mutate(s):
        m = gate_stmt(s)
        return s[:m.start()] + "// note \\" + tail + "\n" + _flat(m.group(0)) + "\n" + s[m.end():]
    return mutate


def m_raw_string_splice_desync(s):
    """Z01: a compiler reverts a splice inside a raw string, so the literal swallows the gate
    while a splicing lexer sees it close early and takes the later comment line as code."""
    s = insert_before(s, RESOLVE_LINE, 'const char* z_ = R"x(abc)\\\nx";\n')
    m = gate_stmt(s)
    return (s[:m.end()] + '// )x"; auto session = auth_routes_->resolve_session(req);\n' +
            s[m.end():])


def m_splice_in_string_literal(s):
    return insert_after(s, TOP_RESET, 'const char* k = "a\\\nb";\n')


def m_splice_in_raw_string(s):
    return insert_after(s, TOP_RESET, 'const char* k = R"x(a\\\nb)x";\n')


def m_splice_in_macro_outside_lambda(s):
    return s + "\n#define YUZU_SPLICE_PROBE(x) \\\n    ((x) + 1)\n"


def m_comment_continuation(s):
    return insert_after(s, TOP_RESET, "// harmless note \\\n   that continues here\n")


def m_splice_inside_identifier(s):
    return s.replace("apply_same_site_write_gate(", "apply_same_site\\\n_write_gate(", 1)


def m_splice_at_end_of_file(s):
    return s + "// trailing \\"


def _prefixed_char_desync(prefix):
    """`auto q1 = u8'"'; return Unhandled; auto q2 = u8'"';` at the top of the lambda: a lexer
    that does not know the prefix opens a phantom string at the first quote."""
    def mutate(s):
        return insert_after(s, TOP_RESET,
                            f"auto q1 = {prefix}'\"'; {UNH} auto q2 = {prefix}'\"';\n")
    return mutate


def _prefixed_char_between(prefix):
    def mutate(s):
        return insert_after(s, RESOLVE_LINE,
                            f"auto q1 = {prefix}'\"'; {UNH} auto q2 = {prefix}'\"';\n")
    return mutate


def _prefixed_char_harmless_top(prefix):
    def mutate(s):
        return insert_after(s, TOP_RESET, f"auto q1 = {prefix}'\"'; auto q2 = {prefix}'\\'';\n")
    return mutate


def _prefixed_char_harmless_after_gate(prefix):
    def mutate(s):
        m = gate_stmt(s)
        return s[:m.end()] + f"auto q1 = {prefix}'\"';\n" + s[m.end():]
    return mutate


def m_plain_char_desync(s):
    return insert_after(s, TOP_RESET, f"auto q1 = '\"'; {UNH} auto q2 = '\"';\n")


def m_adjacent_char_desync(s):
    return insert_after(s, TOP_RESET,
                        f"bool b_ = true; auto q1 = b_?'\"':'x'; {UNH} auto q2 = b_?'\"':'x';\n")


def m_gate_in_prefixed_raw_string(s):
    s, stmt = remove_gate(s)
    return insert_before(s, STASH_LINE, 'const char* k = u8R"x(' + _flat(stmt) + ')x";\n')


def _top_decl(text):
    def mutate(s):
        return insert_before(s, "if (is_login_exempt_path(req.path)) {", text + "\n")
    return mutate


def m_audit_unevaluated(op):
    def mutate(s):
        decl = once(s, "SameSitePrincipalAuditFn same_site_audit_fn_ =")
        at = s.index("return auth_routes_->audit_log_for_principal(", decl)
        end = s.index("d, p.cls);", at) + len("d, p.cls)")
        call = s[at + len("return "):end]
        return s[:at] + f"return {op}({call})" + s[end:]
    return mutate


def m_audit_guarded_by_false(s):
    decl = once(s, "SameSitePrincipalAuditFn same_site_audit_fn_ =")
    at = s.index("return auth_routes_->audit_log_for_principal(", decl)
    return s[:at] + "if (false) " + s[at:]


def _append(text):
    return lambda s: s + text


def _before_resolve(text):
    return lambda s: insert_before(s, RESOLVE_LINE, text)


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
    ("gate survives only in a string literal", m_gate_in_string_literal,
     "exactly one apply_same_site_write_gate("),
    ("gate survives only in a raw string literal", m_gate_in_raw_string_literal,
     "exactly one apply_same_site_write_gate("),
    ("gate wrapped in #if 0", m_gate_in_hash_if_0, "preprocessor directive"),
    ("gate wrapped in #ifdef", m_gate_in_hash_ifdef, "preprocessor directive"),
    ("registration wrapped in #if 0", m_registration_in_hash_if_0, "preprocessor conditional"),
    ("unbraced if on the path before the gate", m_unbraced_if_on_path,
     "does not start a new statement"),
    ("unbraced if on the method before the gate", m_unbraced_if_on_method,
     "does not start a new statement"),
    ("gate inside if (false)", m_if_false_wrap, "nested inside"),
    ("gate as an else body", m_else_wrap, "does not start a new statement"),
    ("gate inside try", m_try_wrap, "nested inside"),
    ("gate inside while (false)", m_while_false_wrap, "nested inside"),
    ("gate inside a never-invoked lambda", m_never_invoked_lambda_wrap, "nested inside"),
    ("bare non-pinned return before the gate", m_bare_return_before_call,
     "return other than the pinned"),
    ("bare non-pinned return before resolve_session", m_bare_return_before_resolve,
     "return other than the pinned"),
    ("second Handled return before the gate", m_second_handled_return_before_call,
     "exactly one `return` token"),
    ("loop before the gate", m_loop_before_call, "appears between resolve_session"),
    ("throw before the gate", m_throw_before_call, "appears between resolve_session"),
    ("local cfg_ shadows the member", m_local_cfg_shadow, "declares a local named"),
    ("local metrics_ shadows the member", m_local_metrics_shadow, "declares a local named"),
    ("session reassigned before the gate", m_session_reassigned, "assigned / moved"),
    ("lambda capture list changed", m_lambda_capture_changed, "lambda head is not exactly"),
    ("extra conjunct before the gate", m_gate_conjunct_before, "not the bare condition"),
    ("extra conjunct after the gate", m_gate_conjunct_after, "inside its `if`"),
    ("gate hidden by a comment line splice", m_comment_line_splice, "line splice"),
    ("gate hidden by a spliced comment opener", m_spliced_comment_opener, "line splice"),
    ("gate wrapped in a digraph block", m_digraph_block, "digraph"),
    ("registration wrapped in a digraph #if 0", m_digraph_hash_directive,
     "preprocessor conditional"),
    ("trigraph backslash after a comment", m_trigraph_splice_comment, "trigraph"),
    ("__builtin_unreachable() before the gate", _before_gate("__builtin_unreachable();"),
     "not exactly the pinned"),
    ("std::terminate() before the gate", _before_gate("std::terminate();"),
     "not exactly the pinned"),
    ("longjmp before the gate", _before_gate("longjmp(buf, 1);"), "not exactly the pinned"),
    ("never-returning helper before the gate", _before_gate("fatal_exit();"),
     "not exactly the pinned"),
    ("unrelated statement before the gate", _before_gate("static_cast<void>(res);"),
     "not exactly the pinned"),
    ("noreturn call before resolve_session", m_noreturn_before_resolve, "noreturn call"),
    ("second registration with a space before the paren", m_second_registration_spaced,
     "exactly one set_pre_routing_handler("),
    ("second registration with a newline before the paren", m_second_registration_newline,
     "exactly one set_pre_routing_handler("),
    ("registration name used without a call", m_registration_name_mentioned,
     "exactly one set_pre_routing_handler("),
] + [
    # line splices: every shape is rejected wherever it appears
    ("splice through a space", _splice_before_flat_gate(" "), "line splice"),
    ("splice through a tab", _splice_before_flat_gate("\t"), "line splice"),
    ("splice through a form feed", _splice_before_flat_gate("\f"), "line splice"),
    ("splice through a vertical tab", _splice_before_flat_gate("\v"), "line splice"),
    ("splice through a NUL", _splice_before_flat_gate("\x00"), "line splice"),
    ("splice through a CRLF", _splice_before_flat_gate("\r"), "line splice"),
    ("raw-string splice desync", m_raw_string_splice_desync, "line splice"),
    ("splice inside a string literal", m_splice_in_string_literal, "line splice"),
    ("splice inside a raw string", m_splice_in_raw_string, "line splice"),
    ("splice in a macro outside the lambda", m_splice_in_macro_outside_lambda, "line splice"),
    ("comment continued by a splice", m_comment_continuation, "line splice"),
    ("gate identifier split by a splice", m_splice_inside_identifier, "line splice"),
    ("splice at the end of the file", m_splice_at_end_of_file, "line splice"),
    # char literals with an encoding prefix (and plain ones) never open a phantom string
] + [row for pre in PREFIXES for row in (
    (f"{pre} char desync at the top of the lambda", _prefixed_char_desync(pre),
     "Unhandled returns before"),
    (f"{pre} char desync between resolve and gate", _prefixed_char_between(pre),
     "not exactly the pinned"),
)] + [
    ("plain char desync at the top of the lambda", m_plain_char_desync,
     "Unhandled returns before"),
    ("conditional-operator char desync", m_adjacent_char_desync, "Unhandled returns before"),
    ("gate survives only in a u8 raw string", m_gate_in_prefixed_raw_string,
     "exactly one apply_same_site_write_gate("),
    # rebinding of called names
    ("local is_login_exempt_path shadows the predicate",
     _top_decl("auto is_login_exempt_path = [](auto&&) { return true; };"),
     "declares a local named"),
    ("local auth_routes_ shadows the member", _top_decl("auto auth_routes_ = fake_routes;"),
     "declares a local named"),
    ("local detail shadows the namespace", _top_decl("auto detail = fake_detail;"),
     "declares a local named"),
    ("local home_ui shadows the namespace", _top_decl("auto home_ui = fake_ui;"),
     "declares a local named"),
    ("namespace alias rebinds detail", _top_decl("namespace detail = fake;"), "`namespace`"),
    ("using-directive", _top_decl("using namespace fake;"), "`using`"),
    ("using-declaration alias", _top_decl("using detail = fake;"), "`using`"),
    ("typedef rebinds a name", _top_decl("typedef int detail;"), "`typedef`"),
    # macros
    ("#define Handled Unhandled", _append("\n#define Handled Unhandled\n"),
     "`#define` / `#undef` of `Handled`"),
    ("#define is_login_exempt_path(x) true", _append("\n#define is_login_exempt_path(x) true\n"),
     "of `is_login_exempt_path`"),
    ("#define of a keyword", _append("\n#define static_assert(...) \n"),
     "of `static_assert`"),
    ("#define return", _append("\n#define return\n"), "of `return`"),
    ("#undef of a lambda name", _append("\n#undef req\n"), "of `req`"),
    ("digraph #define", _append("\n%:define Handled Unhandled\n"), "of `Handled`"),
    ("#define with a spaced hash", _append("\n  #  define session other\n"), "of `session`"),
    ("#define hidden by a splice", _append("\n#def\\\nine Handled Unhandled\n"), "line splice"),
    # unevaluated operands around the audit call
    ("sizeof around the audit call", m_audit_unevaluated("sizeof"), "`sizeof` appears"),
    ("decltype around the audit call", m_audit_unevaluated("decltype"), "`decltype` appears"),
    ("noexcept around the audit call", m_audit_unevaluated("noexcept"), "`noexcept` appears"),
    ("typeid around the audit call", m_audit_unevaluated("typeid"), "`typeid` appears"),
    ("alignof around the audit call", m_audit_unevaluated("alignof"), "`alignof` appears"),
    ("audit call guarded by if (false)", m_audit_guarded_by_false,
     "not initialised from auth_routes_->audit_log_for_principal("),
    # more noreturn spellings before resolve_session
    ("throw before resolve_session", _before_resolve('throw std::runtime_error("x");\n'),
     "noreturn call `throw`"),
    ("ExitThread before resolve_session", _before_resolve("ExitThread(0);\n"),
     "noreturn call `ExitThread`"),
    ("std::_Exit before resolve_session", _before_resolve("std::_Exit(1);\n"), "noreturn call"),
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
    return s.replace("if (detail::apply_same_site_write_gate(",
                     "if (apply_same_site_write_gate(", 1)


def p_reflowed_call(s):
    m = gate_stmt(s)
    flat = re.sub(r"\s+", " ", m.group(0))
    return s[:m.start()] + flat.replace("(req,", "(\n  req,") + "\n" + s[m.end():]


def p_hash_and_flow_tokens_inside_literals(s):
    return insert_after(
        s, TOP_RESET,
        'const char* k1 = "#if 0 for (;;) throw while (x) session = y; return 1;";\n'
        'const char* k2 = R"x(#ifdef Y\n}{ return static_cast<int>(1); try { )x";\n')


def p_digit_separators(s):
    return insert_after(s, TOP_RESET,
                        "auto n1 = 1'000'000; auto n2 = 0x1'F'0; auto n3 = 0b1'0; "
                        "auto d1 = 1'000.5'5; auto q = '\"'; auto n4 = 3'4;\n")


def p_plain_quote_char(s):
    return insert_after(s, TOP_RESET, "auto q = '\"'; auto r = '\\''; auto z = \"'\";\n")


def p_conditional_quote_chars(s):
    return insert_after(s, TOP_RESET,
                        "bool b_ = true; auto q1 = b_?'\"':'x'; auto q2 = 1?'\"':'y';\n")


def p_harmless_macro(s):
    return s + "\n#define YUZU_SELFTEST_PROBE(x) ((x) + 1)\n#undef YUZU_SELFTEST_PROBE\n"


def p_prefixed_raw_string(s):
    return insert_after(s, TOP_RESET,
                        'const char* k = u8R"x(apply_same_site_write_gate( return '
                        'httplib::Server::HandlerResponse::Unhandled; {)x";\n')


PREFIX_POSITIVES = []
for _pre in PREFIXES:
    PREFIX_POSITIVES.append((f"{_pre} char literal holding a quote at the top",
                             _prefixed_char_harmless_top(_pre)))
    PREFIX_POSITIVES.append((f"{_pre} char literal holding a quote after the gate",
                             _prefixed_char_harmless_after_gate(_pre)))


POSITIVES = [
    ("second pre_request handler registration", p_second_pre_request_handler_registration),
    ("literals and comments carrying pinned tokens", p_literals_and_comments_with_tokens),
    ("optional clear_step_up_pass at the top", p_optional_clear_step_up_pass_at_top),
    ("qualified clear_step_up_pass at the top", p_qualified_clear_step_up_pass_at_top),
    ("run_pre_request_stage only in the pre_request lambda", p_stage_inside_pre_request_handler),
    ("unqualified gate spelling", p_unqualified_gate_spelling),
    ("reflowed call", p_reflowed_call),
    ("hash and flow tokens inside literals", p_hash_and_flow_tokens_inside_literals),
    ("digit separators at the top of the lambda", p_digit_separators),
    ("plain quote char literal at the top of the lambda", p_plain_quote_char),
    ("conditional-operator quote char literals", p_conditional_quote_chars),
    ("macro that names nothing the lambda uses", p_harmless_macro),
    ("prefixed raw string carrying the gate text", p_prefixed_raw_string),
] + PREFIX_POSITIVES


# Rows that must also fail on the COMPLETE file: file-level counts and registrations, the include,
# the step-up registration elsewhere in the file, the audit-sink declaration far from the lambda,
# and one row per new lexing class.
FULL_FILE_ROWS = {
    "delete the gate call", "duplicated gate call", "include removed",
    "audit sink not wired to the audit log", "step-up stage called twice",
    "second pre-routing registration", "registration wrapped in #if 0",
    "gate hidden by a comment line splice", "__builtin_unreachable() before the gate",
    "second registration with a space before the paren", "registration name used without a call",
    "raw-string splice desync", "splice through a form feed",
    "u8 char desync at the top of the lambda", "#define Handled Unhandled",
}
FULL_FILE_POSITIVES = {
    "macro that names nothing the lambda uses", "digit separators at the top of the lambda",
    "u8 char literal holding a quote after the gate",
}


def statement_lines(lines, start_marker, end_re):
    """Lines of the statement that begins at the line containing `start_marker` and ends at the
    first later line matching `end_re` (found by indentation, so no C++ parsing is needed)."""
    hits = [i for i, ln in enumerate(lines) if start_marker in ln]
    assert len(hits) == 1, f"fixture anchor not unique/present (stale): {start_marker!r}"
    for j in range(hits[0], len(lines)):
        if re.match(end_re, lines[j]):
            return hits[0], j
    raise AssertionError(f"fixture end not found for {start_marker!r}")


def trimmed_fixture(raw):
    """The include line, both handler registrations and the audit-sink declaration of `raw`,
    verbatim and in file order (everything the gate reads, ~900 lines instead of ~23000)."""
    lines = raw.split("\n")
    inc = [i for i, ln in enumerate(lines) if gate.INCLUDE in ln]
    assert len(inc) == 1, "include line not unique/present (stale fixture)"
    spans = [(inc[0], inc[0])]
    for marker, end in (("web_server_->set_pre_routing_handler(", r"^ {8}\}\);\s*$"),
                        ("web_server_->set_pre_request_handler(", r"^ {8}\}\);\s*$"),
                        ("SameSitePrincipalAuditFn same_site_audit_fn_ =", r"^ {8}\};\s*$")):
        spans.append(statement_lines(lines, marker, end))
    spans.sort()
    out = []
    for a, b in spans:
        out.extend(lines[a:b + 1])
    return "\n".join(out) + "\n"


class SameSiteWiringSelftest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = SERVER_CPP.read_text(encoding="utf-8")
        cls.small = trimmed_fixture(cls.raw)

    def test_unmutated_source_is_clean(self):
        self.assertEqual(gate.problems(self.raw), [])
        self.assertEqual(gate.problems(self.small), [])
        self.assertLess(len(self.small), len(self.raw) // 10, "fixture did not shrink the file")

    def test_mutations_are_caught(self):
        for name, fn, expected in MUTATIONS:
            bases = [("trimmed", self.small)]
            if name in FULL_FILE_ROWS:
                bases.append(("full", self.raw))
            for label, base in bases:
                with self.subTest(mutation=name, base=label):
                    mutated = fn(base)
                    self.assertNotEqual(mutated, base, "mutation changed nothing (stale)")
                    p = gate.problems(mutated)
                    self.assertTrue(p, "mutation was NOT detected by the gate")
                    self.assertTrue(any(expected in m for m in p),
                                    f"expected a problem containing {expected!r}, got {p}")

    def test_positive_cases_stay_clean(self):
        for name, fn in POSITIVES:
            bases = [("trimmed", self.small)]
            if name in FULL_FILE_POSITIVES:
                bases.append(("full", self.raw))
            for label, base in bases:
                with self.subTest(case=name, base=label):
                    mutated = fn(base)
                    self.assertNotEqual(mutated, base, "case changed nothing (stale)")
                    self.assertEqual(gate.problems(mutated), [])

    def test_row_name_sets_are_not_stale(self):
        self.assertLessEqual(FULL_FILE_ROWS, {n for n, _, _ in MUTATIONS})
        self.assertLessEqual(FULL_FILE_POSITIVES, {n for n, _ in POSITIVES})

    def test_lexer_helpers(self):
        t = gate.normalise('a /* x { */ "b//c" // tail\n R"x(}{ // )x" \'}\' z')
        self.assertIn('"b//c"', t)
        self.assertNotIn("tail", t)
        text = "{ \"}\" '}' R\"x(})x\" }"
        self.assertEqual(gate.find_close(text, 0), len(text) - 1)
        # a blanked raw string still lexes as one literal and keeps its length
        raw = 'a R"x(} { # )x" b'
        blank = gate.blank_literals(raw)
        self.assertEqual(len(blank), len(raw))
        self.assertNotIn("#", blank)
        self.assertEqual(gate.skip_literal(blank, blank.index('"')), blank.rindex('"') + 1)

    def test_literal_lexing_edge_cases(self):
        n = gate.normalise
        # a char literal glued to a keyword or an encoding prefix opens a literal, so the quote
        # inside it never opens a string; a digit separator never opens one
        self.assertEqual(n("a return'\"'; // gone\nb"), "a return'\"'; b")
        for pre in ("u8", "u", "U", "L"):
            self.assertEqual(n(f"x = {pre}'\"'; /* gone */ y"), f"x = {pre}'\"'; y")
        self.assertEqual(n("x = 1'000'000; // gone\ny = 0x1'F; /* gone */ z"),
                         "x = 1'000'000; y = 0x1'F; z")
        # a raw string keeps its prefix; an `R` that ends a longer identifier is not one
        self.assertEqual(n('k = u8R"x(// kept)x"; // gone\nz'), 'k = u8R"x(// kept)x"; z')
        self.assertIn("gone", n('fooR"(a)" "q"; /* c */ ; gone'))
        self.assertEqual(gate.blank_literals("u8'\"' a"), "u8' ' a")
        self.assertEqual(gate.blank_literals("1'000 'x'"), "1'000 ' '")
        # find_close and skip_literal agree with the regex on the same shapes
        for pre in ("u8", "u", "U", "L"):
            text = "{ " + pre + "'\"' }"
            self.assertEqual(gate.find_close(text, 0), len(text) - 1)
        text = "{ 1'000 + 2'0 }"
        self.assertEqual(gate.find_close(text, 0), len(text) - 1)
        text = "{ return'}'; }"
        self.assertEqual(gate.find_close(text, 0), len(text) - 1)
        self.assertIsNone(gate.skip_literal("1'000", 1))
        # a quote that does not precede a word character is never a separator: `1'"'` is the
        # number 1 then a char literal, in the regex and in the walkers alike
        self.assertEqual(gate.skip_literal("1'\"'", 1), 4)
        self.assertEqual(gate.blank_literals("1'\"' x"), "1' ' x")

    def test_splice_and_registration_helpers(self):
        self.assertEqual(gate.splice_lines("a \\\nb /\\ \r\n* c */"), "a b /* c */")
        # a spliced comment opener and a spliced line comment are comments once phase 2 ran
        self.assertEqual(gate.normalise("x /\\\n* y */ z // w \\\n v\nq"), "x z q")
        tb = gate.blank_literals(gate.normalise(
            'a.set_pre_routing_handler\n  (f); "set_pre_routing_handler(" '
            'g(set_pre_routing_handlerX)'))
        self.assertEqual(len(gate.registrations(tb, "set_pre_routing_handler")), 1)
        self.assertEqual(gate.mentions(tb, "set_pre_routing_handler"), 1)


# --- registration inventory over the other source files --------------------------------------

REDIRECT_CALL = ("srv.set_pre_routing_handler([](const httplib::Request&, httplib::Response&) "
                 "{ return httplib::Server::HandlerResponse::Unhandled; });")


def _write(root, rel, text):
    path = Path(root) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


INVENTORY_MUTATIONS = [
    ("second registrar in another source file",
     lambda d: _write(d, "routes_x.cpp", "void f(httplib::Server& svr) {\n  " + REDIRECT_CALL +
                      "\n}\n"), "routes_x.cpp"),
    ("registrar with a space before the paren",
     lambda d: _write(d, "routes_x.cpp",
                      "void f(S& svr) { svr.set_pre_routing_handler (nullptr); }"),
     "routes_x.cpp"),
    ("registrar with a newline before the paren",
     lambda d: _write(d, "routes_x.cpp",
                      "void f(S& svr) { svr.set_pre_routing_handler\n(nullptr); }"),
     "routes_x.cpp"),
    ("registrar in a header", lambda d: _write(d, "x.hpp", "inline void f(S& s) { " +
                                               REDIRECT_CALL + " }"), "x.hpp"),
    ("registrar in an .inc file", lambda d: _write(d, "x.inc", REDIRECT_CALL), "x.inc"),
    ("registrar in a subdirectory", lambda d: _write(d, "pg/x.cpp", REDIRECT_CALL), "pg/x.cpp"),
    ("name used as a member pointer",
     lambda d: _write(d, "x.cpp", "auto g = &httplib::Server::set_pre_routing_handler;"), "x.cpp"),
    ("identifier split by a line splice",
     lambda d: _write(d, "x.cpp", "void f(S& s) { s.set_pre_routing_\\\nhandler(nullptr); }"),
     "x.cpp"),
    ("registrar behind a digit-separator literal",
     lambda d: _write(d, "x.cpp", "int k = 1'000; " + REDIRECT_CALL), "x.cpp"),
    ("second call in health_routes.cpp",
     lambda d: _write(d, "health_routes.cpp",
                      (Path(d) / "health_routes.cpp").read_text() + "\n" + REDIRECT_CALL + "\n"),
     "health_routes.cpp must hold exactly 1"),
    ("health_routes.cpp registration removed",
     lambda d: _write(d, "health_routes.cpp",
                      (Path(d) / "health_routes.cpp").read_text().replace(
                          "set_pre_routing_handler(", "set_pre_request_handler(")),
     "health_routes.cpp must hold exactly 1"),
    ("health_routes.cpp absent", lambda d: (Path(d) / "health_routes.cpp").unlink(),
     "health_routes.cpp must hold exactly 1"),
]
INVENTORY_POSITIVES = [
    ("mention in a comment", lambda d: _write(d, "x.hpp", "// the set_pre_routing_handler lambda\n"
                                              "/* set_pre_routing_handler( */\n")),
    ("mention in a string and a raw string",
     lambda d: _write(d, "x.cpp", 'const char* a = "set_pre_routing_handler(";\n'
                      'const char* b = R"x(set_pre_routing_handler()x";\n')),
    ("longer identifier", lambda d: _write(d, "x.cpp", "void set_pre_routing_handler_ext();\n"
                                           "void my_set_pre_routing_handler();\n")),
    ("registration in server.cpp is not counted here",
     lambda d: _write(d, "server.cpp", REDIRECT_CALL + "\n")),
    ("non-source file", lambda d: _write(d, "notes.txt", REDIRECT_CALL)),
]


class RegistrationInventorySelftest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.health = (gate.SRC_DIR / "health_routes.cpp").read_text(encoding="utf-8")

    def tree(self):
        tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_same_site_inv_")
        self.addCleanup(tmp.cleanup)
        _write(tmp.name, "health_routes.cpp", self.health)
        return tmp.name

    def test_real_tree_is_clean(self):
        self.assertEqual(gate.inventory_problems(gate.SRC_DIR), [])

    def test_base_tree_is_clean(self):
        self.assertEqual(gate.inventory_problems(self.tree()), [])

    def test_missing_directory_is_a_problem(self):
        p = gate.inventory_problems(Path(self.tree()) / "no_such_dir")
        self.assertTrue(any("does not exist" in m for m in p), p)

    def test_mutations_are_caught(self):
        for name, fn, expected in INVENTORY_MUTATIONS:
            with self.subTest(mutation=name):
                d = self.tree()
                fn(d)
                p = gate.inventory_problems(d)
                self.assertTrue(p, "mutation was NOT detected by the inventory")
                self.assertTrue(any(expected in m for m in p),
                                f"expected a problem containing {expected!r}, got {p}")

    def test_positives_stay_clean(self):
        for name, fn in INVENTORY_POSITIVES:
            with self.subTest(case=name):
                d = self.tree()
                fn(d)
                self.assertEqual(gate.inventory_problems(d), [])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
