#!/usr/bin/env python3
"""Static lexical gate over server.cpp's wiring of the echo.db corruption-audit gate signals.

ServerImpl is never constructed by a unit test, and server code cannot be built on every dev host,
so nothing else notices if the wiring around the gate (echo_corruption_audit.hpp, unit-tested in
isolation) is dropped with every unit case green. Four sites, anchored on tokens (never line
numbers):

  1. Pre-seeds. `yuzu_server_echo_db_quarantines_total`,
     `yuzu_server_health_upsert_exceptions_total`,
     `yuzu_server_echo_corruption_audit_store_closed_total` and every
     `yuzu_server_echo_corruption_audit_degraded_total{reason}` series are touched to 0 at
     boot, unconditionally, in the block that describes them. The YuzuEchoDbCorruptionDetected alert
     is an increase() over the counter, and increase() of a series first seen at 1 is 0 (promtool
     CORRUPTION CASE 5). The reason list is written twice, once in the pre-seed and once as the
     `DegradedCause` enumerators plus `echo_corruption_degraded_cause_token`: the two sets must match.
     The closed-store increment sits in the sink's closed-store branch, before the gate call.
  2. The quarantine increment is `if (wrote) ...increment();`, the only increment of the counter,
     in the corruption sink after `const bool wrote = detail::log_echo_corruption_once(`, so a
     refused, failed, duplicate or durable-lookup-hit audit row never counts.
  3. The degraded observer counts under the reason it is handed (the token of its argument), and
     is passed to the gate as its third constructor argument (the argument is optional, so a
     dropped one still compiles).
  4. The fleet sweep sets `yuzu_fleet_retired_tar_plugin_agents` from
     `registry_.retired_tar_only_count()`, 0 included, unconditionally in the sweep block after
     the health recompute.

Lexical only: comments are stripped before matching (a token kept in a comment does not count) and
whitespace is free. It cannot see a relocation that keeps the tokens in one block but changes
control flow (review-enforced). The self-test applies in-memory mutations and requires problems()
to name each one; a mutation whose pattern no longer matches the source fails loudly (stale
pattern) rather than passing vacuously.

Usage: python3 -I tests/test_corruption_audit_gate_wiring_lexical.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "server" / "core" / "src" / "server.cpp"
HEADER = ROOT / "server" / "core" / "src" / "echo_corruption_audit.hpp"
HINT = (" (this gate pins the corruption-audit gate signal wiring; if server.cpp was legitimately"
        " restructured, update tests/test_corruption_audit_gate_wiring_lexical.py)")

QUARANTINES = "yuzu_server_echo_db_quarantines_total"
DEGRADED = "yuzu_server_echo_corruption_audit_degraded_total"
UPSERTS = "yuzu_server_health_upsert_exceptions_total"
STORE_CLOSED = "yuzu_server_echo_corruption_audit_store_closed_total"
TAR_ONLY = "yuzu_fleet_retired_tar_plugin_agents"

# Comments and literals are found in ONE pass, so a quote inside a comment, or a comment marker
# inside a literal, cannot hide code or pass a comment off as code.
LEX = re.compile(r'//[^\n]*|/\*.*?\*/|R"([^\s()\\]{0,16})\(.*?\)\1"|"(?:\\.|[^"\\\n])*"'
                 r"|'(?:\\.|[^'\\\n])'", re.S)
BRACE = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])\'|[{}]')


def strip_comments(src):
    return LEX.sub(lambda m: " " if m.group(0)[0] == "/" else m.group(0), src)


TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\w+|\S')


def rx(template):
    """Regex for a C++ snippet: whitespace is free between its tokens, and required only between
    two words (so `constchar` never matches `const char`)."""
    toks = TOKEN.findall(template)
    out = re.escape(toks[0])
    for prev, tok in zip(toks, toks[1:]):
        words = re.match(r"\w", prev[-1]) and re.match(r"\w", tok[0])
        out += (r"\s+" if words else r"\s*") + re.escape(tok)
    return out


def same_block(code, a, b):
    """True when code[a:b] closes every brace it opens and none it did not: one block holds both."""
    depth = 0
    for m in BRACE.finditer(code, min(a, b), max(a, b)):
        if m.group() in "{}":
            depth += 1 if m.group() == "{" else -1
            if depth < 0:
                return False
    return depth == 0


def header_tokens(header):
    """(enumerators, {enumerator: token}) of DegradedCause as the header spells them."""
    enum = re.search(r"enum class DegradedCause\b[^{]*\{([^}]*)\}", header)
    names = [e.split("=")[0].strip() for e in enum.group(1).split(",") if e.strip()] if enum else []
    return names, dict(re.findall(r'case DegradedCause::(\w+):\s*return "([^"]*)";', header))


def problems(server_src, header_src):
    s, h = strip_comments(server_src), strip_comments(header_src)
    out = []

    def find(template, what):
        hits = [m.start() for m in re.finditer(rx(template), s)]
        if len(hits) != 1:
            out.append(f"server.cpp must contain exactly one {what}; found {len(hits)}")
            return None
        return hits[0]

    # 1. Pre-seeds: each sits in the same block as the describe of its own family.
    seeds = {
        QUARANTINES: f'metrics_.counter("{QUARANTINES}");',
        UPSERTS: f'metrics_.counter("{UPSERTS}");',
        STORE_CLOSED: f'metrics_.counter("{STORE_CLOSED}");',
    }
    seed_at = {name: find(stmt, f"pre-seed `{stmt}` (the first increase() needs a 0 sample)")
               for name, stmt in seeds.items()}
    loop = re.search(rx("for (const char* reason : {") + r"(?P<list>[^}]*)"
                     + rx(f'}}) metrics_.counter("{DEGRADED}", {{{{"reason", reason}}}});'), s)
    if loop is None:
        out.append(f"server.cpp no longer pre-seeds every {DEGRADED}{{reason}} series")
    seed_at[DEGRADED] = loop.start() if loop else None
    for name, at in seed_at.items():
        desc = find(f'metrics_.describe("{name}",', f"describe of {name}")
        if at is not None and desc is not None and not same_block(s, desc, at):
            out.append(f"the {name} pre-seed is not in the block that describes it "
                       "(conditional or moved): it would not run at every boot")

    enumerators, tokens = header_tokens(h)
    if not enumerators:
        out.append("echo_corruption_audit.hpp no longer declares `enum class DegradedCause`")
    for e in enumerators:
        if e not in tokens:
            out.append(f"DegradedCause::{e} has no token in echo_corruption_degraded_cause_token")
    if loop:
        seeded = set(re.findall(r'"([^"]*)"', loop.group("list")))
        for tok in sorted(set(tokens.values()) - seeded):
            out.append(f"the {DEGRADED} pre-seed lacks reason {tok!r}, a DegradedCause token")
        for tok in sorted(seeded - set(tokens.values())):
            out.append(f"the {DEGRADED} pre-seed names reason {tok!r}, which no DegradedCause token spells")

    # 2. The quarantine increment: once, behind `wrote`, in the sink, after the audit call.
    call = find("const bool wrote = detail::log_echo_corruption_once(", "`wrote` bound from log_echo_corruption_once")
    guard = find(f'if (wrote) metrics_.counter("{QUARANTINES}").increment();',
                 f"`if (wrote)` guarded increment of {QUARANTINES}")
    incs = len(re.findall(rx(f'metrics_.counter("{QUARANTINES}").increment()'), s))
    if incs != 1:
        out.append(f"{QUARANTINES} is incremented {incs} times; only the one behind `wrote` may be")
    if call is not None and guard is not None and not (call < guard and same_block(s, call, guard)):
        out.append("the `if (wrote)` increment is not in the sink, after the log_echo_corruption_once call")

    # 2b. A closed audit store is counted, once, in the sink before the audit call: the quarantine
    # counter cannot move then, so without this the signal is silent exactly when the store is down.
    closed_guard = find("if (!audit_store_ || !audit_store_->is_open()) { "
                        f'metrics_.counter("{STORE_CLOSED}").increment(); return; }}',
                        f"closed-store branch that counts {STORE_CLOSED} before it returns")
    if closed_guard is not None and call is not None and not closed_guard < call:
        out.append(f"the {STORE_CLOSED} closed-store branch must come before the log_echo_corruption_once call")

    # 3. The observer counts under its argument's token and is the gate's third argument.
    find('auto on_degraded = [this](detail::DegradedCause cause) { '
         'const char* reason = detail::echo_corruption_degraded_cause_token(cause); '
         f'metrics_.counter("{DEGRADED}", {{{{"reason", reason}}}}).increment();',
         f"degraded observer counting {DEGRADED} under the token of its argument")
    find("std::make_shared<detail::EchoCorruptionAuditGate>(std::move(latest), "
         "&detail::EchoCorruptionAuditGate::steady_seconds, std::move(on_degraded))",
         "gate construction handing the observer in as its third argument")

    # 4. The sweep gauge: after the health recompute, same block, so every sweep sets it.
    recompute = find("health_store_.recompute_metrics(metrics_, detail::kAgentHealthStaleness);",
                     "fleet sweep health recompute")
    gauge = find(f'metrics_.gauge("{TAR_ONLY}").set(static_cast<double>(registry_.retired_tar_only_count()));',
                 f"sweep that sets {TAR_ONLY} from registry_.retired_tar_only_count()")
    if recompute is not None and gauge is not None and not (recompute < gauge and same_block(s, recompute, gauge)):
        out.append(f"the {TAR_ONLY} set is not an unconditional statement after the sweep's health recompute")
    return out


def mutate(src, template, new):
    out, n = re.subn(rx(template), lambda _m: new, src, count=1)
    assert n == 1, f"stale mutation pattern: {template!r}"
    return out


QUARANTINE_SEED = f'metrics_.counter("{QUARANTINES}");'
UPSERT_SEED = f'metrics_.counter("{UPSERTS}");'
SEED_LOOP = ('for (const char* reason : {"lookup_degraded", "lookup_threw", "write_failed"}) '
             f'metrics_.counter("{DEGRADED}", {{{{"reason", reason}}}});')
GUARDED = f'if (wrote) metrics_.counter("{QUARANTINES}").increment();'
OBSERVER_COUNT = f'metrics_.counter("{DEGRADED}", {{{{"reason", reason}}}}).increment();'
GAUGE = f'metrics_.gauge("{TAR_ONLY}").set(static_cast<double>(registry_.retired_tar_only_count()));'
RECOMPUTE = "health_store_.recompute_metrics(metrics_, detail::kAgentHealthStaleness);"

# (name, target, template, replacement, expected substring of the problems)
MUTATIONS = [
    ("quarantines pre-seed removed", "s", QUARANTINE_SEED, "", "pre-seed `metrics_.counter(\"" + QUARANTINES),
    ("quarantines pre-seed made conditional", "s", QUARANTINE_SEED, "if (audit_store_) { " + QUARANTINE_SEED + " }",
     f"the {QUARANTINES} pre-seed is not in the block"),
    ("upsert pre-seed removed", "s", UPSERT_SEED, "", "pre-seed `metrics_.counter(\"" + UPSERTS),
    ("degraded pre-seed removed", "s", SEED_LOOP, "", "no longer pre-seeds every"),
    ("degraded pre-seed loses a reason", "s", '{"lookup_degraded", "lookup_threw", "write_failed"}',
     '{"lookup_degraded", "write_failed"}', "lacks reason 'lookup_threw'"),
    ("degraded pre-seed gains a reason no cause spells", "s", '"write_failed"})',
     '"write_failed", "unknown"})', "names reason 'unknown'"),
    ("degraded pre-seed made conditional", "s", SEED_LOOP, "if (audit_store_) { " + SEED_LOOP + " }",
     f"the {DEGRADED} pre-seed is not in the block"),
    ("an enumerator is added without a token or a pre-seed", "h", "lookup_threw, write_failed };",
     "lookup_threw, write_failed, brand_new };", "DegradedCause::brand_new has no token"),
    ("a token is respelled so the pre-seed is stale", "h", 'return "write_failed";',
     'return "write_fail";', "lacks reason 'write_fail'"),
    ("the increment loses its wrote guard", "s", GUARDED, GUARDED[len("if (wrote) "):],
     "`if (wrote)` guarded increment"),
    ("the increment guard is inverted", "s", GUARDED, GUARDED.replace("(wrote)", "(!wrote)"),
     "`if (wrote)` guarded increment"),
    ("the increment is duplicated unguarded", "s", GUARDED, GUARDED + " " + GUARDED[len("if (wrote) "):],
     "is incremented 2 times"),
    ("wrote is no longer the audit call's result", "s", "const bool wrote = detail::log_echo_corruption_once(",
     "const bool wrote = detail::log_echo_something_else(", "`wrote` bound from log_echo_corruption_once"),
    ("the observer stops counting", "s", OBSERVER_COUNT, "", "degraded observer counting"),
    ("the observer counts under a fixed reason", "s", OBSERVER_COUNT, OBSERVER_COUNT.replace("reason}", '"x"}'),
    "degraded observer counting"),
    ("the observer reason is not the token", "s", "const char* reason = detail::echo_corruption_degraded_cause_token(cause);",
     'const char* reason = "lookup_degraded";', "degraded observer counting"),
    ("the observer is not handed to the gate", "s", ", std::move(on_degraded))", ")",
     "gate construction handing the observer"),
    ("closed-store pre-seed removed", "s", f'metrics_.counter("{STORE_CLOSED}");', "",
     "pre-seed `metrics_.counter(\"" + STORE_CLOSED),
    ("closed-store increment removed", "s", f'metrics_.counter("{STORE_CLOSED}").increment();', "",
     f"closed-store branch that counts {STORE_CLOSED}"),
    ("the sweep gauge removed", "s", GAUGE, "", "sweep that sets"),
    ("the sweep gauge kept only in a comment", "s", GAUGE, "/* " + GAUGE + " */", "sweep that sets"),
    ("the sweep gauge made conditional", "s", GAUGE, "if (stream_budget_) { " + GAUGE + " }",
     "not an unconditional statement"),
    ("the sweep gauge reads a constant", "s", "registry_.retired_tar_only_count()", "0", "sweep that sets"),
]


class CorruptionAuditGateWiringLexical(unittest.TestCase):
    def setUp(self):
        self.server = SERVER.read_text(encoding="utf-8")
        self.header = HEADER.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        self.assertEqual(problems(self.server, self.header), [], HINT)

    def test_mutations_are_caught(self):
        for name, target, template, new, expected in MUTATIONS:
            with self.subTest(mutation=name):
                srv, hdr = self.server, self.header
                if target == "s":
                    srv = mutate(srv, template, new)
                else:
                    hdr = mutate(hdr, template, new)
                found = problems(srv, hdr)
                self.assertTrue(any(expected in p for p in found),
                                f"mutation not caught as {expected!r}: {found}")

    def test_gauge_reordered_before_recompute_is_caught(self):
        moved = mutate(mutate(self.server, GAUGE, ""), RECOMPUTE, GAUGE + " " + RECOMPUTE)
        self.assertTrue(any("not an unconditional statement" in p for p in problems(moved, self.header)))

    def test_increment_before_the_audit_call_is_caught(self):
        moved = mutate(mutate(self.server, GUARDED, ""), "const bool wrote = detail::log_echo_corruption_once(",
                       GUARDED + " const bool wrote = detail::log_echo_corruption_once(")
        self.assertTrue(any("not in the sink, after" in p for p in problems(moved, self.header)))


if __name__ == "__main__":
    unittest.main()
