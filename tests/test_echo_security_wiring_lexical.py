#!/usr/bin/env python3
"""Static lexical gate over the Echo security wiring no unit binary on a Mac can reach.

Three properties of the #7075 / #3864 batch live in files the unit suites do not build or run
here, so they are pinned by text:

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

Lexical only: `//` comments are stripped and whitespace is collapsed before matching (`/* */`
comments are deliberately NOT stripped), so it cannot see a relocation that keeps the tokens but
changes control flow (review-enforced). The self-test applies in-memory mutations and requires
problems() to be non-empty on each; a mutation whose pattern no longer matches the source fails
loudly (stale pattern) rather than passing vacuously.

Usage: python3 -I tests/test_echo_security_wiring_lexical.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "agents" / "plugins" / "echo" / "src" / "echo_plugin.cpp"
ROUTES = ROOT / "server" / "core" / "src" / "echo_tree_routes.cpp"
SERVER = ROOT / "server" / "core" / "src" / "server.cpp"
PUSH_ROUTE = 'sink.Post("/fragments/echo/capture-sources/push"'
WIRING = "echo_tree_routes_->set_audit_as_session_fn(auth_routes_->audit_as_session_fn())"
HINT = (" (this gate pins the #7075/#3864 wiring; if the code was legitimately restructured,"
        " update tests/test_echo_security_wiring_lexical.py)")


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    lines = [re.sub(r"//.*$", "", ln) for ln in src.splitlines()]
    return re.sub(r"\s+", " ", " ".join(lines))


def push_body(routes):
    """The push handler's text: from its registration to the next route registration."""
    start = routes.find(PUSH_ROUTE)
    if start < 0:
        return None
    ends = [i for i in (routes.find("sink.Get(", start + 1), routes.find("sink.Post(", start + 1))
            if i >= 0]
    return routes[start:min(ends)] if ends else routes[start:]


def problems(plugin_src, routes_src, server_src):
    out = []
    p = normalise(plugin_src)
    r = normalise(routes_src)
    s = normalise(server_src)

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
    if "state_json = yuzu::echo::encode_process_baseline(" not in p:
        out.append("the process poll's state_json is no longer built by encode_process_baseline")
    if "scrub_process_baseline(*db_)" not in p:
        out.append("init no longer scrubs a legacy process baseline (scrub_process_baseline(*db_))")

    body = push_body(r)
    if body is None:
        out.append("the capture-sources push route is missing from echo_tree_routes.cpp")
    else:
        if re.search(r"\baudit_fn_\b", body):
            out.append("the push handler writes through audit_fn_, which re-resolves the principal "
                       "at write time (empty once the session is gone): use the session-bound writer")
        if "audit_as_session_fn_" not in body:
            out.append("the push handler no longer writes through audit_as_session_fn_")

    if WIRING not in s:
        out.append("server.cpp no longer wires the push's session-bound audit writer")
    return out


def mutate(src, old, new):
    assert old in src, f"stale mutation pattern: {old!r}"
    return src.replace(old, new, 1)


class EchoSecurityWiringLexical(unittest.TestCase):
    def setUp(self):
        self.plugin = PLUGIN.read_text(encoding="utf-8")
        self.routes = ROUTES.read_text(encoding="utf-8")
        self.server = SERVER.read_text(encoding="utf-8")

    def probe(self, **over):
        return problems(over.get("p", self.plugin), over.get("r", self.routes),
                        over.get("s", self.server))

    def test_source_is_clean(self):
        self.assertEqual(self.probe(), [], HINT)

    def test_mutations_are_caught(self):
        p, r, s = self.plugin, self.routes, self.server
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
        }
        for name, over in cases.items():
            with self.subTest(mutation=name):
                self.assertNotEqual(self.probe(**over), [], f"mutation not caught: {name}")


if __name__ == "__main__":
    unittest.main()
