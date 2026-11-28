#!/usr/bin/env python3
"""Static lexical gate over the Echo security wiring no unit binary on a Mac can reach.

Five properties of the #7075 / #3864 / #7290 / #2532 batch live in files the unit suites do not
build or run here, so they are pinned by text:

  1. echo_plugin.cpp (not part of yuzu_echo_tests) writes the `process` baseline only through
     yuzu::echo::encode_process_baseline, never an inline JSON dump that would carry a command
     line back into echo_state: no processes_to_json / json_to_processes, no "cmdline" string
     literal, every set_state(proc_key, ...) is handed the codec's output, and init scrubs a
     legacy row with scrub_process_baseline(*db_).
  2. The capture-sources push handler (echo_tree_routes.cpp) writes every audit row through the
     session-bound writer (audit_as_session_fn_), never through the request-resolving audit_fn_,
     which stamps an empty principal once the session is gone.
  3. server.cpp wires that writer: echo_tree_routes_->set_audit_as_session_fn(
     auth_routes_->audit_as_session_fn()).
  4. (#7290) The dispatch gate publishes in the one safe order, because start_collection runs on the
     open-retry thread while the plugin takes commands and writes db_ and every collector member
     without collect_mu_. EchoPlugin has no seam (TU-local), so the order is pinned here:
     exactly one `online_.store(true, std::memory_order_release);`, directly followed by
     `return {}; }` (start_collection's last statement); execute_dispatch opens with
     `if (!online_.load(std::memory_order_acquire))`; fail_internal rolls back only behind
     `online_.load(std::memory_order_acquire) && db_`; shutdown opens with `open_retry_.stop();
     online_.store(false, std::memory_order_release);` (join the retry thread, then close the gate).
  5. (#2532) The per-device scoped gate has ONE body and two typed consumers wired in order.
     auth_routes.cpp's Boolean `require_scoped_permission` is exactly the `== Admitted` wrapper over
     `require_scoped_permission_outcome`, so it admits only on the single admitting class and a
     second body cannot appear unseen. server.cpp builds one `scoped_gate_fn` that returns that
     typed outcome and wires it into BOTH Echo purge surfaces (`dashboard_routes_->set_scoped_perm_fn`
     and `rest_api_v1_->set_scoped_gate_fn`). REST copies the function by value when its routes
     register, so the REST setter must come BEFORE `rest_api_v1_->register_routes(`: a setter after it
     leaves the purge route on its fail-closed 500 for good and no unit binary notices (the harnesses
     wire their own fake). The dashboard reads its member per request, so only its presence is pinned.

Lexical only: comments (`//` and `/* */`) are stripped and whitespace is collapsed before matching,
and a check that a token is PRESENT also ignores string and character literals, so a token kept
only in a comment or a literal does not satisfy it. It cannot see a relocation that keeps the
tokens but changes control flow (review-enforced). The self-test applies in-memory mutations and
requires problems() to be non-empty on each; a mutation whose pattern no longer matches the source
fails loudly (stale pattern) rather than passing vacuously.

Usage: python3 -I tests/test_echo_security_wiring_lexical.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "agents" / "plugins" / "echo" / "src" / "echo_plugin.cpp"
ROUTES = ROOT / "server" / "core" / "src" / "echo_tree_routes.cpp"
SERVER = ROOT / "server" / "core" / "src" / "server.cpp"
AUTH = ROOT / "server" / "core" / "src" / "auth_routes.cpp"
PUSH_ROUTE = 'sink.Post("/fragments/echo/capture-sources/push"'
WIRING = "echo_tree_routes_->set_audit_as_session_fn(auth_routes_->audit_as_session_fn())"
WIRING_STATUS = "echo_tree_routes_->set_denial_status_fn("
GATE_LAMBDA = "return auth_routes_->require_scoped_permission_outcome(req, res, type, op, agent_id);"
DASHBOARD_GATE = "dashboard_routes_->set_scoped_perm_fn(scoped_gate_fn);"
REST_GATE = "rest_api_v1_->set_scoped_gate_fn(scoped_gate_fn);"
# The Boolean gate: exactly the `== Admitted` wrapper over the one body.
GATE_WRAPPER = re.compile(
    r"bool AuthRoutes::require_scoped_permission\([^)]*\) \{ return "
    r"require_scoped_permission_outcome\(req, res, securable_type, operation, agent_id\) == "
    r"ScopedGateOutcome::Admitted; \}")
# The REST setter statement, followed LATER by the registration that copies it by value.
REST_GATE_BEFORE_REGISTER = re.compile(
    r"rest_api_v1_->set_scoped_gate_fn\(scoped_gate_fn\);.*?rest_api_v1_->register_routes\(")
HINT = (" (this gate pins the #7075/#3864 wiring, the #7290 online_ publish order and the #2532 scoped"
        " gate's one body and wiring order; if the code was"
        " legitimately restructured,"
        " update tests/test_echo_security_wiring_lexical.py)")


# Comments and literals are found in ONE pass, so a quote inside a comment, or a comment marker
# inside a literal ("/api/*"), cannot hide code or pass a comment off as code.
LEX = re.compile(r'//[^\n]*|/\*.*?\*/|R"([^\s()\\]{0,16})\(.*?\)\1"|"(?:\\.|[^"\\\n])*"'
                 r"|'(?:\\.|[^'\\\n])'", re.S)


def normalise(src, literals=True):
    """Strip comments, collapse whitespace; literals=False also blanks string and char literals."""
    def tok(m):
        if m.group(0)[0] == "/":
            return " "
        return m.group(0) if literals else '""'
    return re.sub(r"\s+", " ", LEX.sub(tok, src))


def push_body(routes):
    """The push handler's text: from its registration to the next route registration."""
    start = routes.find(PUSH_ROUTE)
    if start < 0:
        return None
    ends = [i for i in (routes.find("sink.Get(", start + 1), routes.find("sink.Post(", start + 1))
            if i >= 0]
    return routes[start:min(ends)] if ends else routes[start:]


def problems(plugin_src, routes_src, server_src, auth_src=""):
    out = []
    p = normalise(plugin_src)
    p_code = normalise(plugin_src, literals=False)
    r = normalise(routes_src)
    s_code = normalise(server_src, literals=False)

    for tok in ("processes_to_json", "json_to_processes"):
        if tok in p:
            out.append(f"echo_plugin.cpp again uses the retired {tok} baseline codec")
    if re.search(r'"[^"]*cmdline[^"]*"', p):
        out.append('echo_plugin.cpp holds a "cmdline" string literal: the process baseline carries '
                   "no command line (#3864)")
    sites = re.findall(r"set_state\(\s*proc_key,\s*(\S+)", p)
    if not sites:
        out.append("echo_plugin.cpp no longer writes the process baseline through set_state(proc_key, ...)")
    for arg in sites:
        if not (arg.startswith("yuzu::echo::encode_process_baseline(") or arg.startswith("state_json")):
            out.append(f"set_state(proc_key, {arg}...) is not the process baseline codec's output")
    if "state_json = yuzu::echo::encode_process_baseline(" not in p_code:
        out.append("the process poll's state_json is no longer built by encode_process_baseline")
    if "scrub_process_baseline(*db_)" not in p_code:
        out.append("init no longer scrubs a legacy process baseline (scrub_process_baseline(*db_))")

    body = push_body(r)
    if body is None:
        out.append("the capture-sources push route is missing from echo_tree_routes.cpp")
    else:
        if re.search(r"\baudit_fn_\b", body):
            out.append("the push handler writes through audit_fn_, which re-resolves the principal "
                       "at write time (empty once the session is gone): use the session-bound writer")
        if "audit_as_session_fn_" not in normalise(body, literals=False):
            out.append("the push handler no longer writes through audit_as_session_fn_")

    stores = re.findall(r"online_\.store\(true, std::memory_order_release\);( return \{\}; \})?", p_code)
    if len(stores) != 1:
        out.append(f"echo_plugin.cpp stores online_ = true {len(stores)} times; the dispatch gate must be "
                   "published exactly once (#7290)")
    elif not stores[0]:
        out.append("echo_plugin.cpp's online_.store(true, release) is no longer directly followed by "
                   "`return {}; }`: the gate must be start_collection's last statement (#7290)")
    if not re.search(r"int execute_dispatch\([^)]*\) \{ if \(!online_\.load\(std::memory_order_acquire\)\)",
                     p_code):
        out.append("execute_dispatch no longer opens with `if (!online_.load(std::memory_order_acquire))` "
                   "(#7290)")
    if "if (online_.load(std::memory_order_acquire) && db_) db_->rollback_open_transaction();" not in p_code:
        out.append("fail_internal's rollback is no longer guarded by "
                   "`online_.load(std::memory_order_acquire) && db_` (#7290)")
    if not re.search(r"void shutdown\(yuzu::PluginContext& ctx\) noexcept override \{ open_retry_\.stop\(\); "
                     r"online_\.store\(false, std::memory_order_release\);", p_code):
        out.append("shutdown no longer opens with open_retry_.stop(); online_.store(false, release) (#7290)")

    if WIRING + ";" not in s_code:  # as a statement, outside comments and literals
        out.append("server.cpp no longer wires the push's session-bound audit writer")
    if WIRING_STATUS not in s_code:  # outside comments and literals
        out.append("server.cpp no longer injects the push's denial status mapping (set_denial_status_fn): "
                   "a refused dispatch would answer 500 instead of 403")

    # Property 5 (#2532): the scoped gate's one body, and the typed gate wired into both surfaces.
    if not GATE_WRAPPER.search(normalise(auth_src, literals=False)):
        out.append("auth_routes.cpp's require_scoped_permission is no longer exactly "
                   "`return require_scoped_permission_outcome(...) == ScopedGateOutcome::Admitted;`: the "
                   "Boolean gate must admit only on the one admitting class (#2532)")
    if GATE_LAMBDA not in s_code:
        out.append("server.cpp's scoped_gate_fn no longer returns "
                   "auth_routes_->require_scoped_permission_outcome(...) (#2532)")
    if DASHBOARD_GATE not in s_code:
        out.append("server.cpp no longer wires the typed scoped gate into the dashboard's Echo purge "
                   "and re-enable (dashboard_routes_->set_scoped_perm_fn(scoped_gate_fn)) (#2532)")
    if REST_GATE not in s_code:
        out.append("server.cpp no longer wires the typed scoped gate into the REST Echo purge "
                   "(rest_api_v1_->set_scoped_gate_fn(scoped_gate_fn)) (#2532)")
    elif not REST_GATE_BEFORE_REGISTER.search(s_code):
        out.append("server.cpp calls rest_api_v1_->set_scoped_gate_fn AFTER "
                   "rest_api_v1_->register_routes: the purge route copies the function at "
                   "registration, so it would answer its fail-closed 500 for good (#2532)")
    return out


def mutate(src, old, new):
    assert old in src, f"stale mutation pattern: {old!r}"
    return src.replace(old, new, 1)


def mutate_re(src, pattern, new):
    """Like mutate, for a statement whose line breaks and indentation the formatter may move."""
    assert re.search(pattern, src), f"stale mutation pattern: {pattern!r}"
    return re.sub(pattern, lambda _m: new, src, count=1)


class EchoSecurityWiringLexical(unittest.TestCase):
    def setUp(self):
        self.plugin = PLUGIN.read_text(encoding="utf-8")
        self.routes = ROUTES.read_text(encoding="utf-8")
        self.server = SERVER.read_text(encoding="utf-8")
        self.auth = AUTH.read_text(encoding="utf-8")

    def probe(self, **over):
        return problems(over.get("p", self.plugin), over.get("r", self.routes),
                        over.get("s", self.server), over.get("a", self.auth))

    def test_source_is_clean(self):
        self.assertEqual(self.probe(), [], HINT)

    def test_mutations_are_caught(self):
        p, r, s, a = self.plugin, self.routes, self.server, self.auth
        wrapper = (r"return require_scoped_permission_outcome\(req, res, securable_type, operation, "
                   r"agent_id\)\s*==\s*ScopedGateOutcome::Admitted;")
        cases = {
            "a poll write reverts to an inline dump": dict(p=mutate(
                p, "db_->set_state(proc_key, yuzu::echo::encode_process_baseline(current))",
                   "db_->set_state(proc_key, nlohmann::json(current).dump())")),
            "the retired codec returns": dict(p=p + "\nstatic std::string processes_to_json();\n"),
            "a cmdline literal returns": dict(p=p + '\nstatic const char* k = "cmdline";\n'),
            "the poll's state_json stops using the codec": dict(p=mutate(
                p, "state_json = yuzu::echo::encode_process_baseline(", "state_json = inline_dump(")),
            "init stops scrubbing": dict(p=mutate(p, "scrub_process_baseline(*db_)", "(void)0")),
            "the push writes through audit_fn_ again": dict(r=mutate(
                r, "auth::Session actor = *session;",
                   'audit_fn_(req, "x", "y", "z", "w", "v");\n        auth::Session actor = *session;')),
            "the push loses the session-bound writer": dict(r=mutate(
                r, "if (audit_as_session_fn_)", "if (audit_fn_)")),
            "server.cpp stops wiring the writer": dict(s=mutate(s, WIRING + ";", "")),
            "server.cpp stops injecting the denial status": dict(s=mutate(
                s, WIRING_STATUS, "echo_tree_routes_->unrelated_setter(")),
            "the wiring survives only in a block comment": dict(s=mutate(
                s, WIRING + ";", "/* " + WIRING + "; */")),
            "the wiring survives only in a string literal": dict(s=mutate(
                s, WIRING + ";", 'spdlog::info("' + WIRING + ';");')),
            "the gate is published early as well": dict(p=mutate(
                p, "reconcile_db_health_publish(ctx); // #1567",
                   "online_.store(true, std::memory_order_release);\n        reconcile_db_health_publish(ctx); // #1567")),
            "a statement follows the gate's publish": dict(p=mutate(
                p, "online_.store(true, std::memory_order_release);\n        return {};",
                   "online_.store(true, std::memory_order_release);\n        spdlog::info(\"online\");\n        return {};")),
            "execute_dispatch stops loading the gate": dict(p=mutate(
                p, "if (!online_.load(std::memory_order_acquire)) {\n            OfflineState offline;",
                   "if (false) {\n            OfflineState offline;")),
            "fail_internal rolls back without the gate": dict(p=mutate(
                p, "if (online_.load(std::memory_order_acquire) && db_)", "if (db_)")),
            "shutdown stops joining the retry thread first": dict(p=mutate(
                p, "open_retry_.stop();\n        // Close the dispatch gate", "(void)0;\n        // Close the dispatch gate")),
            "the Boolean gate admits everything": dict(a=mutate_re(a, wrapper, "return true;")),
            "the Boolean gate admits anything but a plain denial": dict(a=mutate_re(
                a, wrapper,
                "return require_scoped_permission_outcome(req, res, securable_type, operation, "
                "agent_id) != ScopedGateOutcome::Denied;")),
            "the typed lambda stops returning the gate's class": dict(s=mutate(
                s, GATE_LAMBDA, "return yuzu::server::ScopedGateOutcome::Admitted;")),
            "the dashboard setter is removed": dict(s=mutate(s, DASHBOARD_GATE, "")),
            "the dashboard setter is rebound to the Boolean gate": dict(s=mutate(
                s, DASHBOARD_GATE, "dashboard_routes_->set_scoped_perm_fn(scoped_perm_fn);")),
            "the REST setter is removed": dict(s=mutate(s, REST_GATE, "")),
            # Still present, but after the registration that copies it: only the ORDER check sees it.
            "the REST setter moves after register_routes": dict(s=mutate(s, REST_GATE, "") + "\n" + REST_GATE + "\n"),
        }
        for name, over in cases.items():
            with self.subTest(mutation=name):
                self.assertNotEqual(self.probe(**over), [], f"mutation not caught: {name}")


if __name__ == "__main__":
    unittest.main()
