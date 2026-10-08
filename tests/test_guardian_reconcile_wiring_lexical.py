#!/usr/bin/env python3
"""#5513 static lexical gate over the Guardian heartbeat-reconcile lambda in server.cpp.

ServerImpl is never constructed by a unit test, so nothing else would notice if the wiring that
makes the reconcile path safe at fleet scale were reverted: the building blocks
(guardian_reconcile_gate.hpp, guardian_reconcile_budget.hpp, guardian_generation_cache.hpp,
guardian_rule_bundle.hpp, AgentRegistry::evaluate_scope_for_agent) are unit-tested in isolation,
and every one of them could be silently bypassed with all those tests green. This gate pins the
call sites. Invariants, over the argument of `set_guardian_reconcile_fn(` in server.cpp (comments
removed, string-literal contents reduced to [A-Za-z0-9_], whitespace collapsed):

  a. The lambda decides through `guardian_reconcile_gate_.decide(` and handles all four
     `GuardianReconcileGate::Decision` values (Converged, RateLimited, Shed, Admit).
  b. The Shed case increments `yuzu_server_guardian_reconciles_total{result="shed"}` and writes
     NO audit row (no `audit_store_`, `AuditEvent` or `->log(` in that case).
  c. Right after the Admit case, `begin_admitted()` is taken into a NAMED local (a discarded
     temporary would debit immediately instead of at every exit).
  d. The rule bundle comes from `guardian_rule_bundle_cache_.get(` and its `.rules` feed
     `build_agent_push(`.
  e. Scope membership uses `evaluate_scope_for_agent(` and the lambda never calls
     `evaluate_scope_local(` (that builds the fleet's matching-id vector under the registry lock).
  f. A StoreDegraded scope error sets `scope_degraded`, and `if (scope_degraded)` leads to
     `abort_degraded(` and a `return` (send nothing; never a narrowed full_sync).
  g. The generation is read through `guardian_generation_cache_.get()`; the lambda never calls
     `current_policy_generation(` itself.
  h. Order inside the lambda: decide < begin_admitted < bundle get < evaluate_scope_for_agent.
  i. Whole file: `guardian_last_reconcile_` and `guardian_reconcile_mu_` no longer exist; the
     claim-map sweep (`guardian_reconcile_gate_.sweep(`) is called; and the pre-seed loop for
     `yuzu_server_guardian_reconciles_total` includes "shed".
  j. Control flow: the Converged, RateLimited and Shed cases each `return;` (a case that falls
     through would run the push for an agent that must not get one); the RateLimited case counts
     result="rate_limited".
  k. decide() is called with its real argument order, `decide(agent_id, agent_gen, current)`.
  l. The push is labelled with the FRESH generation: `fresh_generation` is read through
     `guardian_generation_cache_.get_fresh()` AFTER decide and BEFORE the bundle get, and the
     bundle get and `build_agent_push(` are keyed by it, never by `agent_gen` or the cached
     `current`; an unreadable fresh read aborts through `abort_degraded("policy generation
     unreadable"`.
  m. `abort_degraded` increments the `degraded` counter AND writes the audit event; the rule,
     baseline and bundle-load degrade branches each reach it.
  n. A session-less Admit releases its claim (`guardian_reconcile_gate_.release(`) and the
     single-flight waits are excluded from the debit (`.exclude(`).
  o. The bundle load goes through `guardian::load_reconcile_bundle(` (unit-tested for its
     evaluation order), and no statement anywhere in server.cpp or guardian_push_builder.cpp
     combines `filter_deployed_members(` with `std::move(`: `make_bundle` takes both arguments
     by value and the order of evaluation is unspecified, so a move of the deployed set can run
     before the filter reads it (GCC and MSVC do exactly that) and empty the bundle.
  p. Outside the lambda, `guardian_push_fn_` invalidates both reconcile caches.

LEXICAL ONLY. It cannot see a relocation that keeps the tokens but changes control flow (that
stays review-enforced), and the behavioural guarantees are the building blocks' own unit tests.
The self-test applies in-memory mutations to a COPY of the source and requires problems() to name
the expected invariant on each; a mutation that changes nothing fails loudly (stale pattern).
BENIGN controls prove a comment or string that merely mentions a token cannot trip or satisfy it.

Modelled on tests/test_gateway_peer_registration_lexical.py and
tests/test_guardian_heartbeat_wiring_lexical.py. Sources are read as UTF-8. Python, not bash, like
the other no-build lexical gates (#5428).

Usage: python3 tests/test_guardian_reconcile_wiring_lexical.py
       SERVER_CPP=<path> PUSH_BUILDER_CPP=<path> python3 -I tests/test_guardian_reconcile_wiring_lexical.py
                                                                    (point at copies)
"""
import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_CPP = Path(os.environ.get("SERVER_CPP", ROOT / "server" / "core" / "src" / "server.cpp"))
PUSH_BUILDER_CPP = Path(os.environ.get(
    "PUSH_BUILDER_CPP", ROOT / "server" / "core" / "src" / "guardian_push_builder.cpp"))
TAG = "test_guardian_reconcile_wiring_lexical"
HINT = (" (this gate pins the #5513 Guardian reconcile wiring; if server.cpp was legitimately "
        "restructured, update tests/test_guardian_reconcile_wiring_lexical.py)")

# Comments -> one space; string literal contents sanitised; char literals blanked. Alternation
# order matters: the scan is left to right, so a `//` inside a string literal is consumed by the
# string first. A raw string literal is recognised only at an identifier boundary.
_LEX = re.compile(
    r'//[^\n]*'
    r'|/\*.*?\*/'
    r'|(?<![A-Za-z0-9_])(?:u8|u|U|L)?R"([^()\\\s]{0,16})\(.*?\)\1"'
    r'|"(?:\\.|[^"\\\n])*"'
    r"|'(?:\\.|[^'\\\n])*'",
    re.S,
)
_HEX = frozenset("0123456789abcdefABCDEF")
_WORD = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def preprocess(src):
    """Undo line splices and C++14 digit separators (`1'000`), which would otherwise open a
    bogus character literal that swallows code up to the next apostrophe."""
    if src.startswith("﻿"):
        src = src[1:]
    src = src.replace("\\\r\n", "").replace("\\\n", "")
    out, last = [], 0
    for m in re.finditer("'", src):
        i = m.start()
        if i == 0 or i + 1 >= len(src) or src[i - 1] not in _HEX or src[i + 1] not in _HEX:
            continue
        if src[i - 2:i] == "u8" and (i < 3 or src[i - 3] not in _WORD):
            continue
        out.append(src[last:i])
        last = i + 1
    out.append(src[last:])
    return "".join(out)


def lex(src):
    """Comments -> one space; string literal -> its content reduced to [A-Za-z0-9_] (so a brace,
    paren or `//` inside a literal can never disturb structure while a metric name or a result
    label stays matchable); raw strings and char literals blanked; whitespace collapsed."""
    pre = preprocess(src)
    parts, last = [], 0
    for m in _LEX.finditer(pre):
        t = m.group(0)
        parts.append(pre[last:m.start()])
        last = m.end()
        if t.startswith("//") or t.startswith("/*"):
            parts.append(" ")
        elif t[0] == "'":
            parts.append("''")
        elif t[0] == '"':
            parts.append('"' + re.sub(r"[^A-Za-z0-9_]", "_", t[1:-1]) + '"')
        else:
            parts.append('""')  # raw string literal
    parts.append(pre[last:])
    return re.sub(r"\s+", " ", "".join(parts))


def match_close(t, open_idx, open_ch, close_ch):
    """Index of the bracket closing t[open_idx] (strings are already sanitised), or -1."""
    depth = 0
    for i in range(open_idx, len(t)):
        c = t[i]
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return -1


def lambda_body(t):
    """The text of the set_guardian_reconcile_fn( ... ) argument, or None."""
    starts = [m.end() - 1 for m in re.finditer(r"\bset_guardian_reconcile_fn\(", t)]
    if len(starts) != 1:
        return None
    end = match_close(t, starts[0], "(", ")")
    return None if end < 0 else t[starts[0] + 1:end]


DECISIONS = ("Converged", "RateLimited", "Shed", "Admit")
D = "GuardianReconcileGate::Decision::"
SHED_COUNTER = (r'\.counter\( ?"yuzu_server_guardian_reconciles_total", ?\{ ?\{ ?"result", ?"shed" ?\} ?\} ?\)'
                r' ?\.increment\(\)')


def case_body(b, name, next_name):
    """Text of `case Decision::<name>:` up to `case Decision::<next_name>:`, or None."""
    m = re.search(r"\bcase " + re.escape(D + name) + r" ?:(.*?)\bcase " + re.escape(D + next_name) + r" ?:", b)
    return m.group(1) if m else None


def block_after(t, marker):
    """Text of the first `{ ... }` block that follows `marker` in t, or None."""
    i = t.find(marker)
    if i < 0:
        return None
    o = t.find("{", i)
    if o < 0:
        return None
    c = match_close(t, o, "{", "}")
    return None if c < 0 else t[o:c + 1]


def statements(t):
    """t split on ; { } so each chunk is (at most) one statement or one block header."""
    return re.split(r"[;{}]", t)


def move_filter_problems(t, where):
    """(o) no statement combines filter_deployed_members( with std::move(."""
    return [f"{where}: a statement combines filter_deployed_members( with std::move( - the evaluation "
            f"order of two arguments is unspecified, so the deployed set can be moved before the "
            f"filter reads it and the bundle comes out empty (o)"
            for st in statements(t)
            if re.search(r"\bfilter_deployed_members\(", st) and re.search(r"\bstd::move\(", st)]


def problems(src):
    """One message per violated invariant, lettered a..i; [] when clean."""
    t, out = lex(src), []
    b = lambda_body(t)
    if b is None:
        return ["server.cpp no longer has exactly one parseable set_guardian_reconcile_fn( call (a)"]

    decide = re.search(r"guardian_reconcile_gate_\.decide\(", b)
    if not decide:
        out.append("the reconcile lambda no longer calls guardian_reconcile_gate_.decide( (a)")
    for d in DECISIONS:
        if not re.search(r"\bcase " + re.escape(D + d) + r" ?:", b):
            out.append(f"the reconcile lambda no longer handles case {D}{d} (a)")

    shed = re.search(r"\bcase " + re.escape(D + "Shed") + r" ?:(.*?)\bcase " + re.escape(D + "Admit") + r" ?:", b)
    if not shed:
        out.append("could not isolate the Shed case (it must precede the Admit case) (b)")
    else:
        if not re.search(SHED_COUNTER, shed.group(1)):
            out.append('the Shed case no longer increments yuzu_server_guardian_reconciles_total{result="shed"} (b)')
        if re.search(r"audit_store_|\bAuditEvent\b|->log\(|\.log\(", shed.group(1)):
            out.append("the Shed case writes an audit row (it must be counter plus throttled log only) (b)")

    admitted = re.search(r"\bcase " + re.escape(D + "Admit") + r" ?: ?break; ?\} ?(?:const )?auto \w+ = "
                         r"guardian_reconcile_gate_\.begin_admitted\(\) ?;", b)
    if not admitted:
        out.append("begin_admitted() is no longer taken into a named local right after the Admit case (c)")

    bundle_get = re.search(r"guardian_rule_bundle_cache_\.get\(", b)
    if not bundle_get:
        out.append("the reconcile lambda no longer gets its rules from guardian_rule_bundle_cache_.get( (d)")
    if not re.search(r"build_agent_push\( ?\w+\.rules\b", b):
        out.append("build_agent_push( is no longer fed the cached bundle's .rules (d)")

    scope_for_agent = re.search(r"\bevaluate_scope_for_agent\(", b)
    if not scope_for_agent:
        out.append("scope membership no longer uses evaluate_scope_for_agent( (e)")
    if re.search(r"\bevaluate_scope_local\(", b):
        out.append("the reconcile lambda calls evaluate_scope_local( again (fleet-wide vector under the "
                   "registry lock) (e)")

    if not re.search(r"Kind::StoreDegraded\b[^;]*?\) ?\{ ?scope_degraded = true ?;", b):
        out.append("a StoreDegraded scope error no longer sets scope_degraded (f)")
    if not re.search(r"\bif \( ?scope_degraded ?\) ?\{[^{}]*?\babort_degraded\([^;]*;[^{}]*?\breturn ?;", b):
        out.append("if (scope_degraded) no longer leads to abort_degraded( and a return (f)")

    if not re.search(r"guardian_generation_cache_\.get\(\)", b):
        out.append("the generation is no longer read through guardian_generation_cache_.get() (g)")
    if re.search(r"\bcurrent_policy_generation\(", b):
        out.append("the reconcile lambda calls current_policy_generation( directly, bypassing the cache (g)")

    begin = re.search(r"guardian_reconcile_gate_\.begin_admitted\(", b)
    if decide and begin and bundle_get and scope_for_agent:
        if not (decide.start() < begin.start() < bundle_get.start() < scope_for_agent.start()):
            out.append("order is no longer decide < begin_admitted < bundle get < evaluate_scope_for_agent (h)")

    # (?<![\w"])/(?![\w"]): a string literal that is exactly the name is data, not a member.
    if re.search(r'(?<![\w"])(?:guardian_last_reconcile_|guardian_reconcile_mu_)(?![\w"])', t):
        out.append("guardian_last_reconcile_ / guardian_reconcile_mu_ exist again in server.cpp (i)")
    if not re.search(r"guardian_reconcile_gate_\.sweep\(", t.replace(b, "")):
        out.append("the claim-map sweep guardian_reconcile_gate_.sweep( is no longer called outside the "
                   "reconcile lambda (i)")
    if not re.search(r'for \( ?auto \w+ : \{[^{}]*"shed"[^{}]*\} ?\) ?metrics_\.counter\( ?'
                     r'"yuzu_server_guardian_reconciles_total"', t):
        out.append('the yuzu_server_guardian_reconciles_total pre-seed loop no longer includes "shed" (i)')

    # (j) control flow of the three non-push decisions, and the rate_limited label.
    for name, nxt in (("Converged", "RateLimited"), ("RateLimited", "Shed"), ("Shed", "Admit")):
        body = case_body(b, name, nxt)
        if body is None:
            out.append(f"could not isolate the {name} case (j)")
        elif not re.search(r"\breturn ?;", body):
            out.append(f"the {name} case no longer returns (it would fall through and push) (j)")
    rl = case_body(b, "RateLimited", "Shed")
    if rl is not None and not re.search(
            r'\.counter\( ?"yuzu_server_guardian_reconciles_total", ?\{ ?\{ ?"result", ?"rate_limited" ?\} ?\} ?\)'
            r' ?\.increment\(\)', rl):
        out.append('the RateLimited case no longer increments result="rate_limited" (j)')

    # (k) the real argument order.
    if decide and not re.search(r"guardian_reconcile_gate_\.decide\( ?agent_id, ?agent_gen, ?current ?\)", b):
        out.append("decide( is no longer called as decide(agent_id, agent_gen, current) (k)")

    # (l) the push is labelled with the FRESH generation.
    fresh_read = re.search(r"guardian_generation_cache_\.get_fresh\(\)", b)
    if not fresh_read:
        out.append("the push generation is no longer read through guardian_generation_cache_.get_fresh() (l)")
    if not re.search(r"const std::uint64_t fresh_generation = \*\w+ ?;", b):
        out.append("fresh_generation is no longer taken from the fresh read (l)")
    if not re.search(r"guardian_rule_bundle_cache_\.get\( ?fresh_generation ?,", b):
        out.append("the rule bundle is no longer keyed by fresh_generation (l)")
    if re.search(r"guardian_rule_bundle_cache_\.get\( ?(?:agent_gen|current)\b", b):
        out.append("the rule bundle is keyed by the agent's or the cached generation (l)")
    if not re.search(r"build_agent_push\(.*?, ?fresh_generation, ?&metrics_ ?\)", b):
        out.append("build_agent_push( is no longer labelled with fresh_generation (l)")
    if not re.search(r'abort_degraded\( ?"policy_generation_unreadable"', b):
        out.append("an unreadable fresh generation no longer aborts through abort_degraded (l)")
    if decide and fresh_read and bundle_get and not (decide.start() < fresh_read.start() < bundle_get.start()):
        out.append("order is no longer decide < get_fresh < bundle get (l)")

    # (m) abort_degraded body, and the degrade branches that reach it.
    ab = block_after(b, "auto abort_degraded = [")
    if ab is None:
        out.append("could not isolate the abort_degraded lambda body (m)")
    else:
        if not re.search(r'\.counter\( ?"yuzu_server_guardian_reconciles_total", ?\{ ?\{ ?"result", ?"degraded" ?\} ?\} ?\)'
                         r' ?\.increment\(\)', ab):
            out.append('abort_degraded no longer increments result="degraded" (m)')
        if not (re.search(r"\bAuditEvent\b", ab) and re.search(r"audit_store_ ?->log\(", ab)):
            out.append("abort_degraded no longer writes the audit event (m)")
    for site in ("rule_store_degraded", "baseline_store_degraded", "rule_bundle_load_failed"):
        if not re.search(r'abort_degraded\( ?"' + site + '"', b):
            out.append(f'the "{site}" branch no longer reaches abort_degraded (m)')

    # (n) release on no_session, exclusion of single-flight waits.
    if not re.search(r"guardian_reconcile_gate_\.release\( ?agent_id ?\)", b):
        out.append("a session-less Admit no longer releases its claim (n)")
    if not re.search(r"\.exclude\(", b):
        out.append("single-flight waits are no longer excluded from the budget debit (n)")

    # (o) the bundle load goes through the unit-tested loader.
    if not re.search(r"guardian::load_reconcile_bundle\(", b):
        out.append("the bundle loader is no longer guardian::load_reconcile_bundle( (o)")
    out.extend(move_filter_problems(t, "server.cpp"))

    # (p) the bump fan-out drops both reconcile caches.
    outside = t.replace(b, "")
    for cache in ("guardian_generation_cache_", "guardian_rule_bundle_cache_"):
        if not re.search(cache + r"\.invalidate\(\)", outside):
            out.append(f"guardian_push_fn_ no longer calls {cache}.invalidate() (p)")
    return out


def push_builder_problems(src):
    """(o) over guardian_push_builder.cpp: the loader sequences the filter before the move."""
    t = lex(src)
    out = move_filter_problems(t, "guardian_push_builder.cpp")
    if not re.search(r"\bauto filtered = filter_deployed_members\(", t):
        out.append("load_reconcile_bundle no longer computes the filtered rules in their own statement (o)")
    if not re.search(r"\bmake_bundle\( ?std::move\(filtered\) ?,", t):
        out.append("load_reconcile_bundle no longer passes std::move(filtered) to make_bundle (o)")
    return out


def _sub(old, new):
    """Literal one-shot replacement; `old` must be present (a stale pattern fails the self-test)."""
    return lambda s: s.replace(old, new, 1)


def _resub(pattern, repl):
    """Regex one-shot replacement for edits that span source whitespace."""
    return lambda s: re.sub(pattern, repl, s, count=1, flags=re.S)


def _after(marker, old, new):
    """Replace the first `old` that follows `marker` (for tokens that also occur earlier)."""
    def mut(s):
        i = s.index(marker)
        j = s.index(old, i)
        return s[:j] + new + s[j + len(old):]
    return mut


DECIDE_SWITCH = "switch (guardian_reconcile_gate_.decide(agent_id, agent_gen, current))"
BEGIN = "auto admitted = guardian_reconcile_gate_.begin_admitted();"
SHED_OPEN = "case GuardianReconcileGate::Decision::Shed: {"
EVAL = "const auto eval = registry_.evaluate_scope_for_agent("
ABORT = 'abort_degraded("scope store degraded", scope_degraded_detail);'

# (name, mutator, expected letter-tagged substring of the joined problems)
MUTATIONS = [
    ("delete the decide call", _sub(DECIDE_SWITCH, "switch (GuardianReconcileGate::Decision::Admit)"), "(a)"),
    ("comment the decide call out", _sub(DECIDE_SWITCH, "/* " + DECIDE_SWITCH + " */ switch (GuardianReconcileGate::Decision::Admit)"), "(a)"),
    ("drop the Shed case", _sub(SHED_OPEN, "case GuardianReconcileGate::Decision::RateLimited: {"), "(a)"),
    ("shed metric label changed", _sub('{{"result", "shed"}})', '{{"result", "rate_limited"}})'), "(b)"),
    ("Shed branch writes an audit row", _sub(SHED_OPEN, SHED_OPEN + " if (audit_store_) (void)audit_store_->log(AuditEvent{});"), "(b)"),
    ("drop begin_admitted", _sub(BEGIN, "(void)0;"), "(c)"),
    ("begin_admitted discarded temporary", _sub(BEGIN, "(void)guardian_reconcile_gate_.begin_admitted();"), "(c)"),
    ("bypass the rule bundle cache", _sub("guardian_rule_bundle_cache_.get(", "load_rules_directly("), "(d)"),
    ("build_agent_push fed the wrong rules", _sub("bundle.rules, sess->os,", "rules_result_rules, sess->os,"), "(d)"),
    ("call evaluate_scope_local again", _sub(EVAL, "const auto eval = registry_.evaluate_scope_local("), "(e)"),
    ("skip setting scope_degraded", _sub("scope_degraded = true;", "(void)0;"), "(f)"),
    ("skip the degraded abort", _sub(ABORT, "(void)0;"), "(f)"),
    ("read the generation around the cache", _sub("guardian_generation_cache_.get()", "guaranteed_state_store_->current_policy_generation()"), "(g)"),
    ("reintroduce guardian_last_reconcile_", lambda s: s + "\nstd::unordered_map<std::string, int> guardian_last_reconcile_;\n", "(i)"),
    ("drop the claim-map sweep", _sub("(void)guardian_reconcile_gate_.sweep();", "(void)0;"), "(i)"),
    ("drop shed from the pre-seed loop", _sub('"rate_limited", "shed", "degraded"', '"rate_limited", "degraded"'), "(i)"),
]

# Mutations that move code so the ORDER invariant (h) must fire: the begin_admitted statement is
# hoisted above the decide switch, keeping every token present.
def _hoist_begin(s):
    assert BEGIN in s and DECIDE_SWITCH in s
    s = s.replace(BEGIN, "(void)0;", 1)
    return s.replace(DECIDE_SWITCH, BEGIN + " " + DECIDE_SWITCH, 1)


MUTATIONS.append(("begin_admitted hoisted above decide", _hoist_begin, "(h)"))

NEXT = "case GuardianReconcileGate::Decision::"
MUTATIONS += [
    ("Converged case loses its return",
     _resub(r"(Decision::Converged:\s*)return;", r"\1(void)0;"), "(j)"),
    ("RateLimited case loses its return",
     _resub(r"return;(\s*" + NEXT + r"Shed: \{)", r"\1"), "(j)"),
    ("Shed case loses its return",
     _resub(r"return;(\s*\}\s*" + NEXT + r"Admit:)", r"\1"), "(j)"),
    ("rate_limited counter label changed", _sub('{{"result", "rate_limited"}})', '{{"result", "ratelimited"}})'), "(j)"),
    ("decide called with swapped generations",
     _sub(DECIDE_SWITCH, "switch (guardian_reconcile_gate_.decide(agent_id, current, agent_gen))"), "(k)"),
    ("push labelled from the cached read (get_fresh -> get)",
     _sub("guardian_generation_cache_.get_fresh()", "guardian_generation_cache_.get()"), "(l)"),
    ("bundle keyed by the agent's generation",
     _resub(r"guardian_rule_bundle_cache_\.get\(\s*fresh_generation,", "guardian_rule_bundle_cache_.get(agent_gen,"), "(l)"),
    ("bundle keyed by the cached generation",
     _resub(r"guardian_rule_bundle_cache_\.get\(\s*fresh_generation,", "guardian_rule_bundle_cache_.get(current,"), "(l)"),
    ("build_agent_push labelled with the cached generation",
     _sub("/*full_sync=*/true, fresh_generation, &metrics_", "/*full_sync=*/true, current, &metrics_"), "(l)"),
    ("unreadable fresh generation no longer aborts",
     _sub('abort_degraded("policy generation unreadable", fresh_res.error());', "(void)0;"), "(l)"),
    ("abort_degraded stops counting",
     _after("auto abort_degraded = [", '{{"result", "degraded"}}', '{{"result", "degradedx"}}'), "(m)"),
    ("abort_degraded stops auditing",
     _after("auto abort_degraded = [", "(void)audit_store_->log(ev);", "(void)0;"), "(m)"),
    ("rule store degrade no longer aborts",
     _sub('abort_degraded("rule store degraded", err.detail);', "(void)0;"), "(m)"),
    ("baseline store degrade no longer aborts",
     _sub('abort_degraded("baseline store degraded", err.detail);', "(void)0;"), "(m)"),
    ("session-less Admit keeps its claim",
     _sub("guardian_reconcile_gate_.release(agent_id);", "(void)0;"), "(n)"),
    ("single-flight waits charged to the budget",
     _sub("admitted.exclude(std::chrono::steady_clock::now() - t0);", "(void)t0;"), "(n)"),
    ("bundle loader no longer load_reconcile_bundle",
     _sub("guardian::load_reconcile_bundle(", "guardian::make_bundle("), "(o)"),
    ("filter and std::move combined in one statement",
     (lambda s: s + "\nauto b = guardian::make_bundle(guardian::filter_deployed_members(r, d), std::move(*deployed_result));\n"), "(o)"),
    ("bump fan-out stops dropping the generation cache",
     _sub("guardian_generation_cache_.invalidate();", "(void)0;"), "(p)"),
    ("bump fan-out stops dropping the bundle cache",
     _sub("guardian_rule_bundle_cache_.invalidate();", "(void)0;"), "(p)"),
]

# Mutations over guardian_push_builder.cpp (the bundle loader's evaluation order).
LOADER_SEQ = ("auto filtered = filter_deployed_members(*rules_result, *deployed_result);\n"
              "    return make_bundle(std::move(filtered), std::move(*deployed_result));")
PUSH_MUTATIONS = [
    ("loader reverts to the single-expression form",
     _sub(LOADER_SEQ, "return make_bundle(filter_deployed_members(*rules_result, *deployed_result), "
                      "std::move(*deployed_result));"), "(o)"),
    ("loader moves the deployed set into the filter statement",
     _sub(LOADER_SEQ, "auto filtered = filter_deployed_members(*rules_result, std::move(*deployed_result));\n"
                      "    return make_bundle(std::move(filtered), {});"), "(o)"),
]

# BENIGN controls: text that merely MENTIONS tokens must neither satisfy nor trip a rule.
BENIGN = [
    ("comment mentions evaluate_scope_local(",
     _sub("bool scope_degraded = false;", "bool scope_degraded = false; // not evaluate_scope_local( any more")),
    ("string literal mentions guardian_last_reconcile_",
     _sub("bool scope_degraded = false;", 'bool scope_degraded = false; const char* old_name = "guardian_last_reconcile_";')),
    ("block comment mentions current_policy_generation(",
     _sub("bool scope_degraded = false;", "bool scope_degraded = false; /* current_policy_generation( */")),
]


class GuardianReconcileWiringLexical(unittest.TestCase):
    def setUp(self):
        self.src = SERVER_CPP.read_text(encoding="utf-8")
        self.push_src = PUSH_BUILDER_CPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.src)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for name, mutate, expected in MUTATIONS:
            with self.subTest(mutation=name):
                mutated = mutate(self.src)
                self.assertNotEqual(mutated, self.src, "mutation changed nothing (stale pattern)")
                p = problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertIn(expected, "\n".join(p))

    def test_push_builder_is_clean(self):
        p = push_builder_problems(self.push_src)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_push_builder_mutations_are_caught(self):
        for name, mutate, expected in PUSH_MUTATIONS:
            with self.subTest(mutation=name):
                mutated = mutate(self.push_src)
                self.assertNotEqual(mutated, self.push_src, "mutation changed nothing (stale pattern)")
                p = push_builder_problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertIn(expected, "\n".join(p))

    def test_benign_text_is_not_flagged(self):
        for name, mutate in BENIGN:
            with self.subTest(benign=name):
                mutated = mutate(self.src)
                self.assertNotEqual(mutated, self.src, "benign edit changed nothing (stale pattern)")
                self.assertEqual(problems(mutated), [])

    def test_a_commented_out_decide_does_not_satisfy_the_gate(self):
        # Comment stripping must remove the call entirely, not merely hide it from one regex.
        mutated = self.src.replace(DECIDE_SWITCH, "// " + DECIDE_SWITCH + "\n switch (GuardianReconcileGate::Decision::Admit)", 1)
        self.assertNotEqual(mutated, self.src)
        self.assertIn("(a)", "\n".join(problems(mutated)))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
