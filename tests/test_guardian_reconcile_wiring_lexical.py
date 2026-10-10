#!/usr/bin/env python3
"""#5513 static lexical gate over the Guardian heartbeat-reconcile control flow and its wiring.

ServerImpl is never constructed by a unit test, so nothing else would notice if the wiring that
makes the reconcile path safe at fleet scale were reverted: the building blocks
(guardian_reconcile_gate.hpp, guardian_reconcile_budget.hpp, guardian_generation_cache.hpp,
guardian_rule_bundle.hpp, AgentRegistry::evaluate_scope_for_agent) are unit-tested in isolation,
and every one of them could be silently bypassed with all those tests green. This gate pins the
call sites.

TWO TARGETS (the control flow moved out of server.cpp into guardian_reconcile_flow.hpp so that
it is unit tested; tests/unit/server/test_guardian_reconcile_flow.cpp is now the behavioural
guard and this gate is the cheap tripwire that stays beside it):

  FLOW = the body of `void run(` in server/core/src/guardian_reconcile_flow.hpp (comments
  removed, string-literal contents reduced to [A-Za-z0-9_], whitespace collapsed): invariants
  a-h, j-o, r, s below.
  WIRING = server.cpp: the `set_guardian_reconcile_fn(` call, the `GuardianReconcileFlowDeps`
  construction feeding it, the maintenance tick, and the store's rule-mutation hook: invariants
  i, o (second half), p, q, t, u, v.

Invariants over the FLOW:

  a. The flow decides through `guardian_reconcile_gate_.decide(` and handles all four
     `GuardianReconcileGate::Decision` values (Converged, RateLimited, Shed, Admit).
  b. The Shed case increments `yuzu_server_guardian_reconciles_total{result="shed"}` and writes
     NO audit row (no `audit_(`, `AuditEvent` or `->log(` in that case).
  c. Right after the Admit case, `begin_admitted()` is taken into a NAMED local (a discarded
     temporary would debit immediately instead of at every exit).
  d. The rule bundle comes from `guardian_rule_bundle_cache_.get(` and its `.rules` feed
     `build_agent_push(`.
  e. Scope membership uses the injected `eval_scope_(` and the flow never calls
     `evaluate_scope_local(` (that builds the fleet's matching-id vector under the registry lock).
  f. A StoreDegraded scope error sets `scope_degraded`, and `if (scope_degraded)` leads to
     `abort_degraded(` and a `return` (send nothing; never a narrowed full_sync).
  g. The generation is read through `guardian_generation_cache_.get()`; the flow never calls
     `current_policy_generation(` itself.
  h. Order inside run(): decide < begin_admitted < bundle get < eval_scope_(.
  j. Control flow: the Converged, RateLimited and Shed cases each `return;` (a case that falls
     through would run the push for an agent that must not get one); the RateLimited case counts
     result="rate_limited".
  k. decide() is the direct operand of the `switch` and is called with its real argument order
     INCLUDING the `&shed_cause` out-parameter, `decide(agent_id, agent_gen, current, &shed_cause)`
     (the out-parameter is mandatory: the Shed log is worded by it; a `true ||` bypass in front
     of the call is also red).
  l. The push is labelled with the FRESH generation: `fresh_generation` is read through
     `guardian_generation_cache_.get_fresh()` AFTER decide and BEFORE the bundle get, and the
     bundle get and `build_agent_push(` are keyed by it, never by `agent_gen` or the cached
     `current`; an unreadable fresh read aborts through `abort_degraded("policy generation
     unreadable"`.
  m. `abort_degraded` increments the `degraded` counter AND writes the audit event; the rule,
     baseline and bundle-load degrade branches each reach it.
  n. A session-less Admit KEEPS its claim: the flow never calls `release(` (an agent
     heartbeating generation 0 in a loop would, with the claim released, turn each heartbeat into a
     fresh admission and let one credential drain the shared budget), and the `no_session` branch
     counts then returns. Only the time spent BLOCKED on another thread's rule-set load is excluded
     from the debit: there is EXACTLY ONE `admitted.exclude(` in run(), `exclude(bundle_waited)`
     fed by the cache's `waited` out-parameter (a second would double-subtract); the generic
     `excluding(` wrapper that also excluded the owner's own load must not return.
  o. The bundle load goes through `guardian::load_reconcile_bundle(` (unit-tested for its
     evaluation order), and no statement anywhere in the flow, server.cpp or
     guardian_push_builder.cpp combines `filter_deployed_members(` with `std::move(`:
     `make_bundle` takes both arguments by value and the order of evaluation is unspecified, so a
     move of the deployed set can run before the filter reads it (GCC and MSVC do exactly that)
     and empty the bundle.
  r. After the fresh-generation read: an unreadable result aborts through `abort_degraded(` AND
     returns (else `*fresh_res` is dereferenced), `if (fresh_generation <= agent_gen)` returns
     BEFORE the bundle get (a reconcile whose fresh value is not ahead sends nothing and must not
     pay for a load), no policy-generation gauge `.set(` anywhere in run() takes the cached
     `current` (only `fresh_generation`), and `admitted.exclude(` comes after the bundle get whose
     waited value it takes.
  s. The push is counted `sent`, and audited `success`, ONLY inside `if (send_push_(`: a failed
     send must not count, gauge or audit a reconcile that did not happen.

Invariants over the WIRING (server.cpp):

  i. `guardian_last_reconcile_` and `guardian_reconcile_mu_` no longer exist; the claim-map sweep
     (`guardian_reconcile_gate_.sweep(`) is called; and the pre-seed loop for
     `yuzu_server_guardian_reconciles_total` includes "shed".
  p. The body of the `guardian_push_fn_` lambda (not merely anywhere else) invalidates both
     reconcile caches.
  q. The 15 s maintenance tick publishes the three saturation gauges
     (`yuzu_server_guardian_reconcile_in_flight`, `..._budget_balance_ms`, `..._claims`) from the
     gate and budget in their OWN try block with both catch arms (`std::exception`, named or not,
     and `...`, parsed from the try body's closing brace), placed after
     `publish_cohort_perf_gauges();` and before `registry_.reap_stale_sessions(` and the
     `guardian_reconcile_gate_.sweep(` call, so a throwing reap or sweep cannot freeze them. The
     try must follow a complete statement (`;` or `}`, not `{`, `)` or `else`), publish_cohort_perf_gauges();,
     the gauge try, the reap and the sweep try must all be statements of ONE block (an `if (false) {`
     or a lambda body is a deeper block), and no return, continue, break, goto, throw, if, switch,
     for or while may sit between publish_cohort_perf_gauges(); and the gauge try or between the
     gauge try and the sweep. The sweep sits in a try with both catch arms; what else the sweep try
     contains (consuming the result, further statements) is not pinned. Accepted limit: a
     construct that keeps all of the above yet stops the block running is review-only; the
     shapes named here are known not to be caught: a dead `if (false)` wrapping the whole gauge
     span, a preprocessor `#if` around it, a lambda that is defined but never invoked, a `throw`
     inside a catch arm, a constant-folded `.set(0 ? x : 0.0)`, a macro, and a throwing statement
     the lexer does not recognise.
  t. `set_guardian_reconcile_fn(` is called exactly once, its lambda does nothing but call
     `reconcile_flow->run(agent_id_sv, agent_gen)` (no inline `decide(`: a second, unreviewed copy
     of the control flow would be the drift this extraction removed), and the lambda captures the
     flow it runs. `GuardianReconcileFlowDeps{...}` is constructed exactly once and feeds the
     gate, both caches, the budget, the metrics registry and the duration histogram from the
     ServerImpl members of those names.
  u. The dependency callables in that construction keep their security-relevant bodies:
     `eval_scope` uses `registry_.evaluate_scope_for_agent(` and never `evaluate_scope_local(`;
     `send_push` builds a `DispatchCaller{.system = true}` for `__guard__`/`push_rules`, sends
     through `send_system_reserved(... guardian_push_rules)` and calls `forward_gateway_pending()`
     exactly once, only on the success branch; `audit` keeps the `audit_store_->is_open()` check;
     `list_rules`, `deployed_ids`, `session_os` and `random_suffix` keep their sources. The
     callables are also pinned to their exact reviewed BODIES (whitespace, wrapping and comments
     are free; values are not), because the flow's tests stub them: `store_wired` is exactly
     `static_cast<bool>(guaranteed_state_store_)`; `list_rules` is exactly
     `guaranteed_state_store_->list_rules()`; `session_os` looks up `registry_.get_session(agent_id)`
     and returns `sess->os`; `random_suffix` is `bytes_to_hex(random_bytes(8))`; `eval_scope`
     passes its own `agent_id` and `expr` and the real `tag_store_.get()` /
     `custom_properties_store_.get()`; `send_push` builds the command from its own `command_id`
     and `push_bytes` and sends to its own `agent_id`. `audit` is exactly
     `if (audit_store_ && audit_store_->is_open()) (void)audit_store_->log(ev);` (a `log(` of
     anything but its own parameter, or an `is_open() || true`, is red), and `send_push`'s result
     arms are pinned whole: `return true;` only inside the `forward_gateway_pending()` success
     branch, a final `return false;`, and `classified && send_system_reserved(...)` (not `||`).
     (u) pins SPELLING, not only values: it is a lexical match against the reviewed text, so a
     semantically equivalent rewrite in a form the patterns do not list (for example a
     `std::optional` unwrapped through `value_or`) is red until the gate is updated. It
     tolerates the spellings that do not change meaning: a `this->` member prefix,
     `!= nullptr` against an implicit bool test, `const auto` against `auto`, optional braces
     around a single statement, and any names for the callable's own parameters (the pins follow
     the names the lambda declares).
  v. `GuaranteedStateStore::set_on_rule_mutation(` is called with a lambda whose body invalidates
     BOTH reconcile caches (`guardian_generation_cache_` and `guardian_rule_bundle_cache_`) and
     does nothing else: a rule create/update/delete whose best-effort generation bump failed
     leaves the generation unchanged, so without this hook a held rule bundle is served to a new
     agent for up to its max_age (chaos-F1). The store-side half (the hook fires after the commit
     and after the bump attempt on all three mutation paths, never throws, holds no lease) is
     pinned by the [rule_hook] cases in tests/unit/server/test_guaranteed_state_store.cpp, which
     need a Postgres.

LEXICAL ONLY. It cannot see a relocation that keeps the tokens but changes control flow (that
stays review-enforced), and the behavioural guarantees are the building blocks' own unit tests.
The self-test applies in-memory mutations to a COPY of each source and requires problems() (server.cpp)
or flow_problems() (the flow header) to name the expected invariant on each; a mutation that changes nothing fails loudly (stale pattern).
BENIGN controls prove a comment or string that merely mentions a token cannot trip or satisfy it.

Modelled on tests/test_gateway_peer_registration_lexical.py and
tests/test_guardian_heartbeat_wiring_lexical.py. Sources are read as UTF-8. Python, not bash, like
the other no-build lexical gates (#5428).

Usage: python3 tests/test_guardian_reconcile_wiring_lexical.py
       SERVER_CPP=<path> FLOW_HPP=<path> PUSH_BUILDER_CPP=<path> \\
           python3 -I tests/test_guardian_reconcile_wiring_lexical.py        (point at copies)
"""
import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_CPP = Path(os.environ.get("SERVER_CPP", ROOT / "server" / "core" / "src" / "server.cpp"))
FLOW_HPP = Path(os.environ.get("FLOW_HPP", ROOT / "server" / "core" / "src" / "guardian_reconcile_flow.hpp"))
PUSH_BUILDER_CPP = Path(os.environ.get(
    "PUSH_BUILDER_CPP", ROOT / "server" / "core" / "src" / "guardian_push_builder.cpp"))
TAG = "test_guardian_reconcile_wiring_lexical"
HINT = (" (this gate pins the #5513 Guardian reconcile flow and wiring; if server.cpp or "
        "guardian_reconcile_flow.hpp was legitimately restructured, update "
        "tests/test_guardian_reconcile_wiring_lexical.py)")

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


def run_body(t):
    """The text of the `void run(...) { ... }` body in the flow header, or None."""
    starts = [m.end() - 1 for m in re.finditer(r"\bvoid run\([^()]*\) ?\{", t)]
    if len(starts) != 1:
        return None
    end = match_close(t, starts[0], "{", "}")
    return None if end < 0 else t[starts[0]:end + 1]


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


def flow_problems(src):
    """One message per violated FLOW invariant (guardian_reconcile_flow.hpp), lettered; [] when clean."""
    t, out = lex(src), []
    b = run_body(t)
    if b is None:
        return ["guardian_reconcile_flow.hpp no longer has exactly one parseable `void run(` body (a)"]

    decide = re.search(r"guardian_reconcile_gate_\.decide\(", b)
    if not decide:
        out.append("the reconcile flow no longer calls guardian_reconcile_gate_.decide( (a)")
    for d in DECISIONS:
        if not re.search(r"\bcase " + re.escape(D + d) + r" ?:", b):
            out.append(f"the reconcile flow no longer handles case {D}{d} (a)")

    shed = re.search(r"\bcase " + re.escape(D + "Shed") + r" ?:(.*?)\bcase " + re.escape(D + "Admit") + r" ?:", b)
    if not shed:
        out.append("could not isolate the Shed case (it must precede the Admit case) (b)")
    else:
        if not re.search(SHED_COUNTER, shed.group(1)):
            out.append('the Shed case no longer increments yuzu_server_guardian_reconciles_total{result="shed"} (b)')
        if re.search(r"audit_store_|\baudit_ ?\(|\bAuditEvent\b|->log\(|\.log\(", shed.group(1)):
            out.append("the Shed case writes an audit row (it must be counter plus throttled log only) (b)")

    admitted = re.search(r"\bcase " + re.escape(D + "Admit") + r" ?: ?break; ?\} ?(?:const )?auto \w+ = "
                         r"guardian_reconcile_gate_\.begin_admitted\(\) ?;", b)
    if not admitted:
        out.append("begin_admitted() is no longer taken into a named local right after the Admit case (c)")

    bundle_get = re.search(r"guardian_rule_bundle_cache_\.get\(", b)
    if not bundle_get:
        out.append("the reconcile flow no longer gets its rules from guardian_rule_bundle_cache_.get( (d)")
    if not re.search(r"build_agent_push\( ?\w+\.rules\b", b):
        out.append("build_agent_push( is no longer fed the cached bundle's .rules (d)")

    scope_for_agent = re.search(r"\beval_scope_\(", b)
    if not scope_for_agent:
        out.append("scope membership no longer uses the injected eval_scope_( (e)")
    if re.search(r"\bevaluate_scope_local\(", t):
        out.append("the reconcile flow calls evaluate_scope_local( (fleet-wide vector under the "
                   "registry lock) (e)")

    if not re.search(r"Kind::StoreDegraded\b[^;]*?\) ?\{ ?scope_degraded = true ?;", b):
        out.append("a StoreDegraded scope error no longer sets scope_degraded (f)")
    if not re.search(r"\bif \( ?scope_degraded ?\) ?\{[^{}]*?\babort_degraded\([^;]*;[^{}]*?\breturn ?;", b):
        out.append("if (scope_degraded) no longer leads to abort_degraded( and a return (f)")

    if not re.search(r"guardian_generation_cache_\.get\(\)", b):
        out.append("the generation is no longer read through guardian_generation_cache_.get() (g)")
    if re.search(r"\bcurrent_policy_generation\(", b):
        out.append("the reconcile flow calls current_policy_generation( directly, bypassing the cache (g)")

    begin = re.search(r"guardian_reconcile_gate_\.begin_admitted\(", b)
    if decide and begin and bundle_get and scope_for_agent:
        if not (decide.start() < begin.start() < bundle_get.start() < scope_for_agent.start()):
            out.append("order is no longer decide < begin_admitted < bundle get < eval_scope_ (h)")

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

    # (k) the real argument order, the mandatory &shed_cause out-parameter, and decide() as the
    # direct switch operand (so a `true ||` bypass in front of it is red).
    if decide and not re.search(
            r"\bswitch \( ?guardian_reconcile_gate_\.decide\( ?agent_id, ?agent_gen, ?current, ?&shed_cause ?\) ?\) ?\{", b):
        out.append("decide( is no longer the direct switch operand called as "
                   "decide(agent_id, agent_gen, current, &shed_cause) (k)")
    # (k2) the shed log is worded by cause: both causes are distinguished.
    shed_body = case_body(b, "Shed", "Admit")
    if decide and shed_body is not None and not (
            re.search(r"\bShedCause::InFlightCap\b", shed_body) and re.search(r"\bshed_cause\b", shed_body)):
        out.append("the Shed case no longer words its log by shed_cause (k)")

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

    # (r) control flow after the fresh read, the generation gauge, and exclude-after-get.
    if not re.search(r'abort_degraded\( ?"policy_generation_unreadable", ?\w+\.error\(\) ?\) ?; ?return ?;', b):
        out.append("an unreadable fresh generation no longer aborts AND returns (the next line would "
                   "dereference the error result) (r)")
    if not re.search(r"\bif \( ?fresh_generation <= agent_gen ?\) ?return ?;", b):
        out.append("the `if (fresh_generation <= agent_gen) return;` early exit is gone: a reconcile "
                   "whose fresh generation is not ahead of the agent would still push (r)")
    if not re.search(r'\.gauge\( ?"yuzu_server_guardian_policy_generation" ?\) ?\.set\( ?static_cast<double>\( ?fresh_generation ?\) ?\)', b):
        out.append("the policy-generation gauge is no longer set from fresh_generation (r)")
    for gm in re.finditer(r'\.gauge\( ?"yuzu_server_guardian_policy_generation"[^;]*;', b):
        if re.search(r"\bcurrent\b", gm.group(0)):
            out.append("a policy-generation gauge .set( takes the cached `current` in the reconcile flow (r)")
    early = re.search(r"\bif \( ?fresh_generation <= agent_gen ?\) ?return ?;", b)
    if early and bundle_get and not early.start() < bundle_get.start():
        out.append("the `fresh_generation <= agent_gen` return is no longer BEFORE the bundle get: a "
                   "reconcile that sends nothing would still pay for a rule-set load (r)")
    ex = re.search(r"\badmitted\.exclude\(", b)
    if bundle_get and ex and not bundle_get.start() < ex.start():
        out.append("admitted.exclude( is no longer after the bundle get that produces its argument (r)")

    # (m) abort_degraded body, and the degrade branches that reach it.
    ab = block_after(b, "auto abort_degraded = [")
    if ab is None:
        out.append("could not isolate the abort_degraded lambda body (m)")
    else:
        if not re.search(r'\.counter\( ?"yuzu_server_guardian_reconciles_total", ?\{ ?\{ ?"result", ?"degraded" ?\} ?\} ?\)'
                         r' ?\.increment\(\)', ab):
            out.append('abort_degraded no longer increments result="degraded" (m)')
        if not (re.search(r"\bAuditEvent\b", ab) and re.search(r"\baudit_ ?\( ?ev ?\) ?;", ab)):
            out.append("abort_degraded no longer writes the audit event (m)")
    for site in ("rule_store_degraded", "baseline_store_degraded", "rule_bundle_load_failed"):
        if not re.search(r'abort_degraded\( ?"' + site + '"', b):
            out.append(f'the "{site}" branch no longer reaches abort_degraded (m)')

    # (n) no_session keeps its claim; only a BLOCKED wait is excluded from the debit.
    if re.search(r"\brelease\(", b):
        out.append("the reconcile flow calls release( again: a session-less Admit must KEEP its claim, "
                   "or an unsubscribed agent's heartbeats become unbounded admissions (n)")
    if not re.search(r'\{ ?\{ ?"result", ?"no_session" ?\} ?\} ?\) ?\.increment\(\) ?; ?return ?;', b):
        out.append("the no_session branch is no longer counter-then-return (n)")
    if len(re.findall(r"\badmitted\.exclude\(", b)) != 1:
        out.append("the reconcile flow no longer has exactly one admitted.exclude( (a second would "
                   "subtract the same wait twice) (n)")
    if not re.search(r"\badmitted\.exclude\( ?bundle_waited ?\)", b):
        out.append("the time blocked on another thread's rule-bundle load is no longer excluded from "
                   "the budget debit (n)")
    if not re.search(r"guardian_rule_bundle_cache_\.get\(.*?, ?&bundle_waited ?\)", b):
        out.append("the bundle get no longer reports how long it was blocked (&bundle_waited) (n)")
    if re.search(r"\bexcluding\(", b):
        out.append("a generic excluding( wrapper is back: it would also exclude the owner's own load "
                   "from the debit (n)")

    # (o) the bundle load goes through the unit-tested loader.
    if not re.search(r"guardian::load_reconcile_bundle\(", b):
        out.append("the bundle loader is no longer guardian::load_reconcile_bundle( (o)")
    out.extend(move_filter_problems(t, "guardian_reconcile_flow.hpp"))

    # (s) sent / success audit only on a delivered push.
    sent_if = re.search(r"\bif \( ?send_push_\([^;{}]*\) ?\) ?\{(.*)", b)
    if not sent_if:
        out.append("the push is no longer gated by `if (send_push_(...))` (s)")
    else:
        tail = sent_if.group(1)
        if not re.search(r'^ ?metrics_ ?\.counter\( ?"yuzu_server_guardian_reconciles_total", ?\{ ?\{ ?"result", ?"sent" ?\} ?\} ?\)'
                         r' ?\.increment\(\)', tail):
            out.append('the `sent` counter is no longer the first statement of the delivered-push branch (s)')
        if not re.search(r'\bev\.result = "success" ?; ?audit_\( ?ev ?\) ?;', tail):
            out.append("the success audit row is no longer written inside the delivered-push branch (s)")
    return out


def problems(src):
    """One message per violated WIRING invariant (server.cpp), lettered; [] when clean."""
    t, out = lex(src), []
    b = lambda_body(t)
    if b is None:
        return ["server.cpp no longer has exactly one parseable set_guardian_reconcile_fn( call (t)"]

    # (t) the lambda is a thin call into the flow; the flow is built once, from the ServerImpl members.
    if not re.search(r"^\[ ?reconcile_flow ?\]\( ?std::string_view agent_id_sv, ?std::uint64_t agent_gen ?\) ?\{ ?"
                     r"reconcile_flow ?-> ?run\( ?agent_id_sv, ?agent_gen ?\) ?; ?\}$", b.strip()):
        out.append("the set_guardian_reconcile_fn lambda is no longer exactly "
                   "`[reconcile_flow](agent_id_sv, agent_gen) { reconcile_flow->run(agent_id_sv, agent_gen); }` (t)")
    if re.search(r"guardian_reconcile_gate_\.decide\(", t):
        out.append("server.cpp calls guardian_reconcile_gate_.decide( again: the control flow belongs in "
                   "GuardianReconcileFlow::run, a second copy is the drift the extraction removed (t)")
    ctor = [m.end() - 1 for m in re.finditer(r"\bstd::make_shared<GuardianReconcileFlow> ?\( ?GuardianReconcileFlowDeps ?\{", t)]
    c = None
    if len(ctor) != 1:
        out.append("server.cpp no longer constructs exactly one GuardianReconcileFlow from "
                   "GuardianReconcileFlowDeps{...} (t)")
    else:
        close = match_close(t, ctor[0], "{", "}")
        c = None if close < 0 else t[ctor[0]:close + 1]
        if c is None:
            out.append("the GuardianReconcileFlowDeps{...} initializer is unbalanced (t)")
    if c is not None:
        # A `this->` member prefix is spelling, not meaning: drop it so every pin below sees the
        # bare member name.
        c = re.sub(r"(?<![\w:])this ?-> ?", "", c)
        for field, member in ((".gate", "guardian_reconcile_gate_"), (".generation_cache", "guardian_generation_cache_"),
                              (".rule_bundle_cache", "guardian_rule_bundle_cache_"),
                              (".budget", "guardian_reconcile_budget_"), (".metrics", "metrics_"),
                              (".duration", "reconcile_duration")):
            if not re.search(re.escape(field) + r" ?= ?" + member + r" ?,", c):
                out.append(f"the flow is no longer constructed with {field} = {member} (t)")
        if re.search(r"\bevaluate_scope_local\(", c):
            out.append("the flow's dependencies call evaluate_scope_local( (fleet-wide vector under the "
                       "registry lock) (u)")

        def field_block(name):
            return block_after(c, "." + name + " =")

        for name, needs in (
                ("eval_scope", (r"registry_ ?\.evaluate_scope_for_agent\(",)),
                ("list_rules", (r"guaranteed_state_store_ ?-> ?list_rules\(\)",)),
                ("deployed_ids", (r"\bdeployed_member_rule_ids\(\)",)),
                ("session_os", (r"registry_ ?\. ?get_session\(", r"->os\b")),
                ("random_suffix", (r"AuthManager::bytes_to_hex\( ?(?:auth::)?AuthManager::random_bytes\(8\) ?\)",)),
                ("audit", (r"\baudit_store_(?: ?!= ?nullptr)? ?&& ?audit_store_ ?-> ?is_open\(\)", r"\baudit_store_ ?-> ?log\(")),
                ("send_push", (r"yuzu::server::DispatchCaller ?\{ ?\.system = true ?\}", r'"__guard__"', r'"push_rules"',
                               r"SystemReservedPush::guardian_push_rules"))):
            blk = field_block(name)
            if blk is None:
                out.append(f"could not isolate the .{name} dependency in the flow construction (u)")
                continue
            for pat in needs:
                if not re.search(pat, blk):
                    out.append(f"the .{name} dependency no longer matches `{pat}` (u)")
        # Exact bodies (whitespace and line wrapping tolerant: the text is lexed, comments gone,
        # runs of whitespace collapsed). A callable that keeps the right TOKENS but feeds them the
        # wrong values (a constant command id, an empty push, another agent's id, null stores) is
        # exactly the wiring defect the flow's unit tests cannot see, because they stub these.
        def params(name):
            """The names the lambda declares for its own parameters, in order. The pins below are
            about STRUCTURE (which parameter feeds which call), not about what it is called."""
            m = re.search(r"\." + name + r" ?= ?\[[^\]]*\] ?\(([^()]*)\)", c)
            if not m or not m.group(1).strip():
                return []
            return [re.findall(r"\w+", part)[-1] for part in m.group(1).split(",")]

        def esc(ident):
            return re.escape(ident)

        store = r"guaranteed_state_store_"
        sess_p = params("session_os")
        eval_p = params("eval_scope")
        audit_p = params("audit")
        send_p = params("send_push")
        exact = [
            ("store_wired", r"^\{ ?return (?:static_cast<bool>\( ?" + store + r" ?\)|" + store +
             r" ?!= ?nullptr|nullptr ?!= ?" + store + r") ?; ?\}$"),
            ("list_rules", r"^\{ ?return " + store + r" ?-> ?list_rules\( ?\) ?; ?\}$"),
            ("deployed_ids", r"^\{ ?return deployed_member_rule_ids\( ?\) ?; ?\}$"),
            ("random_suffix", r"^\{ ?return (?:auth::)?AuthManager::bytes_to_hex\( ?(?:auth::)?AuthManager::"
                              r"random_bytes\(8\) ?\) ?; ?\}$"),
        ]
        if len(sess_p) == 1:
            sp_ = esc(sess_p[0])
            exact.append(("session_os", r"^\{ ?(?:const )?auto (?P<s>\w+) ?= ?registry_ ?\. ?get_session\( ?" + sp_ +
                          r" ?\) ?; ?if ?\( ?! ?(?P=s) ?\) ?(?:\{ ?)?return std::nullopt ?; ?(?:\} ?)?"
                          r"return (?P=s) ?-> ?os ?; ?\}$"))
        else:
            out.append("could not read the .session_os lambda's parameter (u)")
        if len(eval_p) == 2:
            exact.append(("eval_scope", r"^\{ ?return registry_ ?\. ?evaluate_scope_for_agent\( ?" + esc(eval_p[0]) +
                          r", ?" + esc(eval_p[1]) + r", ?tag_store_ ?\. ?get\( ?\), ?custom_properties_store_ ?\. ?"
                          r"get\( ?\) ?\) ?; ?\}$"))
        else:
            out.append("could not read the .eval_scope lambda's parameters (u)")
        if len(audit_p) == 1:
            exact.append(("audit", r"^\{ ?if ?\( ?audit_store_(?: ?!= ?nullptr)? ?&& ?audit_store_ ?-> ?is_open\( ?\) ?\) ?"
                          r"(?:\{ ?)?\(void\) ?audit_store_ ?-> ?log\( ?" + esc(audit_p[0]) + r" ?\) ?; ?(?:\} ?)?\}$"))
        else:
            out.append("could not read the .audit lambda's parameter (u)")
        if len(send_p) == 3:
            agent_p, cmd_p, bytes_p = (esc(x) for x in send_p)
            exact.append(("send_push",
                          r"^\{ ?(?:const )?auto classified = build_classified_command\( ?yuzu::server::DispatchCaller ?\{ ?"
                          r"\.system = true ?\} ?, ?\"__guard__\", ?\"push_rules\", ?" + cmd_p + r", ?\{ ?\} ?, ?" + bytes_p +
                          r" ?\) ?; ?if ?\( ?(?:classified|classified ?\. ?has_value\( ?\)|classified ?!= ?std::nullopt) ?&& ?"
                          r"send_system_reserved\( ?" + agent_p + r", ?\* ?classified, ?"
                          r"yuzu::server::SystemReservedPush::guardian_push_rules ?\) ?\) ?\{ ?forward_gateway_pending\( ?\) ?; ?"
                          r"return true ?; ?\} ?return false ?; ?\}$"))
        else:
            out.append("could not read the .send_push lambda's parameters (u)")
        for name, pat in exact:
            blk = field_block(name)
            if blk is not None and not re.search(pat, blk.strip()):
                out.append(f"the .{name} dependency body is no longer exactly its reviewed form `{pat}` (u)")
        sp = field_block("send_push")
        if sp is not None:
            # (The command id, the push bytes and the target being the lambda's OWN parameters is
            # pinned by the whole-body match above, under whatever names the lambda declares.)
            if len(re.findall(r"\bforward_gateway_pending\(\)", sp)) != 1 or not re.search(
                    r"\bsend_system_reserved\([^{}]*?\) ?\) ?\{ ?forward_gateway_pending\(\) ?; ?return true ?;", sp):
                out.append("the .send_push dependency must call forward_gateway_pending() exactly once, and only "
                           "inside the send_system_reserved success branch (u)")

    # (i) whole-file items.
    # (?<![\w"])/(?![\w"]): a string literal that is exactly the name is data, not a member.
    if re.search(r'(?<![\w"])(?:guardian_last_reconcile_|guardian_reconcile_mu_)(?![\w"])', t):
        out.append("guardian_last_reconcile_ / guardian_reconcile_mu_ exist again in server.cpp (i)")
    if not re.search(r"guardian_reconcile_gate_\.sweep\(", t):
        out.append("the claim-map sweep guardian_reconcile_gate_.sweep( is no longer called (i)")
    if not re.search(r'for \( ?auto \w+ : \{[^{}]*"shed"[^{}]*\} ?\) ?metrics_\.counter\( ?'
                     r'"yuzu_server_guardian_reconciles_total"', t):
        out.append('the yuzu_server_guardian_reconciles_total pre-seed loop no longer includes "shed" (i)')

    out.extend(move_filter_problems(t, "server.cpp"))

    # (p) the bump fan-out drops both reconcile caches, INSIDE the guardian_push_fn_ body.
    push_fn = re.search(r"\bguardian_push_fn_ = \[this\]\([^)]*\) -> int ?\{", t)
    push_body = None
    if push_fn:
        close = match_close(t, push_fn.end() - 1, "{", "}")
        push_body = None if close < 0 else t[push_fn.end() - 1:close + 1]
    if push_body is None:
        out.append("could not isolate the guardian_push_fn_ lambda body (p)")
    else:
        for cache in ("guardian_generation_cache_", "guardian_rule_bundle_cache_"):
            if not re.search(cache + r"\.invalidate\(\)", push_body):
                out.append(f"guardian_push_fn_ no longer calls {cache}.invalidate() (p)")

    # (v) a rule create/update/delete on this replica drops both reconcile caches (chaos-F1).
    hooks = [m.end() - 1 for m in re.finditer(r"\bset_on_rule_mutation\((?= ?\[)", t)]
    if len(hooks) != 1:
        out.append("server.cpp no longer wires exactly one GuaranteedStateStore::set_on_rule_mutation( lambda (v)")
    else:
        end = match_close(t, hooks[0], "(", ")")
        arg = "" if end < 0 else t[hooks[0] + 1:end]
        body = block_after(arg, "]") or ""
        inv = r"(?:this ?-> ?)?%s ?\. ?invalidate\( ?\) ?;"
        gen, bun = inv % "guardian_generation_cache_", inv % "guardian_rule_bundle_cache_"
        if not (re.search(r"^\{ ?" + gen + " ?" + bun + r" ?\}$", body.strip()) or
                re.search(r"^\{ ?" + bun + " ?" + gen + r" ?\}$", body.strip())):
            out.append("the set_on_rule_mutation lambda no longer does exactly "
                       "{ guardian_generation_cache_.invalidate(); guardian_rule_bundle_cache_.invalidate(); } (v)")

    # (q) the saturation gauges and the claim sweep (see q_problems).
    out.extend(q_problems(t))
    return out


_CATCH_STD = re.compile(r" ?catch ?\( ?(?:const )?std::exception(?: const)? ?&(?: ?\w+)? ?\) ?\{")
_CATCH_ALL = re.compile(r" ?catch ?\( ?\.\.\. ?\) ?\{")
_CONTROL_FLOW = re.compile(r"\b(?:return|continue|break|goto|throw)\b|\bif ?\(|\bswitch ?\(|\b(?:for|while) ?\(")


def _catch_arms(t, close):
    """Parse the catch arms that must directly follow the try whose body closes at t[close].
    Returns (None, index just past the last arm) or (what is wrong, -1)."""
    m = _CATCH_STD.match(t, close + 1)
    if not m:
        return "no catch (const std::exception&) arm directly after the try", -1
    c = match_close(t, m.end() - 1, "{", "}")
    if c < 0:
        return "the catch (const std::exception&) arm is unbalanced", -1
    m = _CATCH_ALL.match(t, c + 1)
    if not m:
        return "no catch (...) arm directly after the catch (const std::exception&) arm", -1
    c = match_close(t, m.end() - 1, "{", "}")
    if c < 0:
        return "the catch (...) arm is unbalanced", -1
    return None, c + 1


def _enclosing_block(t, pos):
    """Index of the innermost `{` still open at t[pos], or -1 at namespace scope."""
    stack = []
    for m in re.finditer(r"[{}]", t[:pos]):
        if m.group(0) == "{":
            stack.append(m.start())
        elif stack:
            stack.pop()
    return stack[-1] if stack else -1


def q_problems(t2):
    """(q) over the lexed source with the reconcile lambda removed. Each message names the
    condition that failed. Accepted limit: a rewrite that keeps all of this and still stops the
    block running (a macro, or a throwing statement the check does not recognise) is review-only."""
    out = []
    tries = []  # (open, close, keyword start) of every `try {`
    for m in re.finditer(r"\btry ?\{", t2):
        c = match_close(t2, m.end() - 1, "{", "}")
        if c > 0:
            tries.append((m.end() - 1, c, m.start()))

    sweeps = [m.start() for m in re.finditer(r"guardian_reconcile_gate_\.sweep\(\)", t2)]
    if len(sweeps) != 1:
        out.append(f"expected exactly one guardian_reconcile_gate_.sweep() call outside the reconcile lambda, "
                   f"found {len(sweeps)} (q)")
        return out
    sweep_pos = sweeps[0]
    around = [x for x in tries if x[0] < sweep_pos < x[1]]
    sweep_try = max(around) if around else None
    if sweep_try is None:
        out.append("the claim sweep is not inside a try block (q)")
    else:
        why, _ = _catch_arms(t2, sweep_try[1])
        if why:
            out.append(f"the claim sweep try: {why} (q)")

    holding = [x for x in tries if "yuzu_server_guardian_reconcile_in_flight" in t2[x[0]:x[1]]]
    gauge_try = max(holding) if holding else None
    if gauge_try is None:
        out.append("the saturation gauges are no longer published inside a try block (q)")
        return out
    why, gauge_end = _catch_arms(t2, gauge_try[1])
    if why:
        out.append(f"the gauge try: {why} (q)")
        gauge_end = gauge_try[1] + 1
    tick = t2[gauge_try[0]:gauge_try[1]]
    for name, src in (("yuzu_server_guardian_reconcile_in_flight", r"guardian_reconcile_gate_\.in_flight\(\)"),
                      ("yuzu_server_guardian_reconcile_budget_balance_ms",
                       r"guardian_reconcile_budget_\.balance_ms\(\)"),
                      ("yuzu_server_guardian_reconcile_claims", r"guardian_reconcile_gate_\.claims_size\(\)")):
        if not re.search(r'metrics_ ?\.gauge\( ?"' + name + r'" ?\) ?\.set\([^;]*' + src, tick):
            out.append(f"{name} is no longer set from {src.replace(chr(92), '')} in the gauge block (q)")

    # Placement: after publish_cohort_perf_gauges(); before the reap; in the SAME block as the
    # sweep, with nothing that can skip the block on either side.
    pcpg = [m for m in re.finditer(r"\bpublish_cohort_perf_gauges\(\) ?;", t2) if m.end() <= gauge_try[0]]
    if not pcpg:
        out.append("the gauge block no longer follows a publish_cohort_perf_gauges(); call (q)")
        return out
    pcpg_end = pcpg[-1].end()
    reaps = [m for m in re.finditer(r"\bregistry_\.reap_stale_sessions\(", t2) if m.start() >= pcpg_end]
    if not reaps:
        out.append("could not find registry_.reap_stale_sessions( after publish_cohort_perf_gauges(); (q)")
        return out
    reap_pos = reaps[0].start()
    if reap_pos < gauge_try[1]:
        out.append("the saturation gauges are published AFTER registry_.reap_stale_sessions(: a throwing reap "
                   "would freeze them (q)")
    if sweep_pos < gauge_try[1]:
        out.append("the saturation gauges are published AFTER the claim sweep: a throwing sweep would "
                   "freeze them (q)")
    if _CONTROL_FLOW.search(t2[pcpg_end:gauge_try[2]]):
        out.append("a return, continue, branch or loop sits between publish_cohort_perf_gauges(); and the "
                   "gauge try and can skip the gauges (q)")
    if not re.search(r"[;}] ?$", t2[:gauge_try[2]]):
        out.append("the gauge try is not preceded by a complete statement (a `{`, `)` or `else` before it makes "
                   "it conditional or part of a lambda) (q)")
    if gauge_try[1] < sweep_pos:
        between = t2[gauge_end:sweep_pos]
        if _CONTROL_FLOW.search(between):
            out.append("a return, continue, branch or loop sits between the gauge block and the claim sweep, "
                       "so the block no longer runs unconditionally ahead of the sweep (q)")
    if sweep_try is not None:
        blocks = {_enclosing_block(t2, pcpg[-1].start()), _enclosing_block(t2, gauge_try[0]),
                  _enclosing_block(t2, reap_pos), _enclosing_block(t2, sweep_try[0])}
        if len(blocks) != 1:
            out.append("publish_cohort_perf_gauges();, the gauge block, the reap and the claim sweep are no "
                       "longer statements of one block (the gauge block is inside an `if`, a lambda or another "
                       "function) (q)")
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


def _wsub(old, new):
    """Like _sub but whitespace-tolerant: `old` is matched with any run of whitespace between its
    tokens, so a mutation survives a source line wrap (the decide( call is wrapped by clang-format)."""
    pattern = r"\s*".join(re.escape(tok) for tok in re.split(r"\s+", old.strip()))
    return lambda s: re.sub(pattern, lambda _m: new, s, count=1)


def _after(marker, old, new):
    """Replace the first `old` that follows `marker` (for tokens that also occur earlier)."""
    def mut(s):
        i = s.index(marker)
        j = s.index(old, i)
        return s[:j] + new + s[j + len(old):]
    return mut


def _wafter(marker, old, new):
    """Like _after but `old` is matched whitespace-tolerantly (tokens split on whitespace in `old`,
    joined by \\s* in the pattern), so a mutation survives clang-format's wrapping of the wiring."""
    pattern = r"\s*".join(re.escape(tok) for tok in re.split(r"\s+", old.strip()))

    def mut(s):
        i = s.index(marker)
        m = re.compile(pattern).search(s, i)
        assert m, "wafter: pattern not found after marker (stale pattern): " + old[:50]
        return s[:m.start()] + new + s[m.end():]
    return mut


DECIDE_SWITCH = "switch (guardian_reconcile_gate_.decide(agent_id, agent_gen, current, &shed_cause))"
BEGIN = "auto admitted = guardian_reconcile_gate_.begin_admitted();"
SHED_OPEN = "case GuardianReconcileGate::Decision::Shed: {"
EVAL = "const auto eval = eval_scope_("
ABORT = 'abort_degraded("scope store degraded", scope_degraded_detail);'

_GAUGE_BLOCK = re.compile(r"[ \t]*try \{\s*metrics_\s*\.gauge\(\"yuzu_server_guardian_reconcile_in_flight\"\).*?"
                          r"Guardian reconcile gauge publish failed: unknown exception\"\);\s*\}\n", re.S)


def _cut_gauges(s):
    """(source without the gauge try block, the block, where it was). Tokens all stay present."""
    m = _GAUGE_BLOCK.search(s)
    assert m, "gauge block not found (stale pattern)"
    return s[:m.start()] + s[m.end():], m.group(0), m.start()


def _move_gauges_after_sweep(s):
    """Cut the gauge try block out and paste it after the sweep's catch arms."""
    s, block, _ = _cut_gauges(s)
    n = re.search(r"Guardian reconcile claim sweep failed: unknown exception\"\);\s*\}\n", s)
    assert n, "sweep block not found (stale pattern)"
    return s[:n.end()] + block + s[n.end():]


def _gauges_wrapped(head, tail="}\n"):
    """Keep the gauge block where it is but wrap it: head + block + tail."""
    def mut(s):
        _, block, at = _cut_gauges(s)
        return s[:at] + head + block + tail + s[at + len(block):]
    return mut


def _gauges_moved_after(marker):
    """Cut the gauge block and paste it right after `marker` (first occurrence)."""
    def mut(s):
        s, block, _ = _cut_gauges(s)
        i = s.index(marker) + len(marker)
        return s[:i] + "\n" + block + s[i:]
    return mut


def _insert_before_gauges(text):
    return lambda s: (lambda m: s[:m.start()] + text + s[m.start():])(_GAUGE_BLOCK.search(s))


def _insert_after_gauges(text):
    return lambda s: (lambda m: s[:m.end()] + text + s[m.end():])(_GAUGE_BLOCK.search(s))


# (name, mutator, expected letter-tagged substring of the joined problems). One combined list;
# FLOW_MUTATIONS / SERVER_MUTATIONS below route each entry to the source it mutates.
MUTATIONS = [
    ("delete the decide call", _wsub(DECIDE_SWITCH, "switch (GuardianReconcileGate::Decision::Admit)"), "(a)"),
    ("comment the decide call out", _wsub(DECIDE_SWITCH, "/* " + DECIDE_SWITCH + " */ switch (GuardianReconcileGate::Decision::Admit)"), "(a)"),
    ("drop the Shed case", _sub(SHED_OPEN, "case GuardianReconcileGate::Decision::RateLimited: {"), "(a)"),
    ("shed metric label changed", _sub('{{"result", "shed"}})', '{{"result", "rate_limited"}})'), "(b)"),
    ("Shed branch writes an audit row", _sub(SHED_OPEN, SHED_OPEN + " audit_(AuditEvent{});"), "(b)"),
    ("drop begin_admitted", _sub(BEGIN, "(void)0;"), "(c)"),
    ("begin_admitted discarded temporary", _sub(BEGIN, "(void)guardian_reconcile_gate_.begin_admitted();"), "(c)"),
    ("bypass the rule bundle cache", _sub("guardian_rule_bundle_cache_.get(", "load_rules_directly("), "(d)"),
    ("build_agent_push fed the wrong rules", _sub("bundle.rules, *sess,", "rules_result_rules, *sess,"), "(d)"),
    ("call evaluate_scope_local again", _sub(EVAL, "const auto eval = registry_.evaluate_scope_local("), "(e)"),
    ("skip setting scope_degraded", _sub("scope_degraded = true;", "(void)0;"), "(f)"),
    ("skip the degraded abort", _sub(ABORT, "(void)0;"), "(f)"),
    ("read the generation around the cache", _sub("guardian_generation_cache_.get()", "store.current_policy_generation()"), "(g)"),
    ("reintroduce guardian_last_reconcile_", lambda s: s + "\nstd::unordered_map<std::string, int> guardian_last_reconcile_;\n", "(i)"),
    ("drop the claim-map sweep", _sub("(void)guardian_reconcile_gate_.sweep();", "(void)0;"), "(i)"),
    ("drop shed from the pre-seed loop", _sub('"rate_limited", "shed", "degraded"', '"rate_limited", "degraded"'), "(i)"),
]

# Mutations that move code so the ORDER invariant (h) must fire: the begin_admitted statement is
# hoisted above the decide switch, keeping every token present.
def _hoist_begin(s):
    assert BEGIN in s
    s = s.replace(BEGIN, "(void)0;", 1)
    return _wsub(DECIDE_SWITCH, BEGIN + " " + DECIDE_SWITCH)(s)


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
     _wsub(DECIDE_SWITCH, "switch (guardian_reconcile_gate_.decide(agent_id, current, agent_gen, &shed_cause))"), "(k)"),
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
     _after("auto abort_degraded = [", "audit_(ev);", "(void)0;"), "(m)"),
    ("rule store degrade no longer aborts",
     _sub('abort_degraded("rule store degraded", err.detail);', "(void)0;"), "(m)"),
    ("baseline store degrade no longer aborts",
     _sub('abort_degraded("baseline store degraded", err.detail);', "(void)0;"), "(m)"),
    ("session-less Admit releases its claim again",
     _resub(r'(\{\{"result", "no_session"\}\}\)\s*\.increment\(\);)', r"\1 guardian_reconcile_gate_.release(agent_id);"), "(n)"),
    ("a second admitted.exclude( is added",
     _sub("admitted.exclude(bundle_waited);", "admitted.exclude(bundle_waited); admitted.exclude(bundle_waited);"), "(n)"),
    ("no_session branch no longer returns right after counting",
     _resub(r'(\{\{"result", "no_session"\}\}\)\s*\.increment\(\);)', r"\1 (void)0;"), "(n)"),
    ("time blocked on another thread's load charged to the budget",
     _sub("admitted.exclude(bundle_waited);", "(void)bundle_waited;"), "(n)"),
    ("bundle get stops reporting its wait",
     _sub("&bundle_waited);", "nullptr);"), "(n)"),
    ("a generic excluding wrapper returns",
     _sub("std::chrono::nanoseconds bundle_waited{0};",
          "std::chrono::nanoseconds bundle_waited{0}; const auto wrapped = excluding([&] { return 0; });"), "(n)"),
    ("unreadable fresh generation aborts but no longer returns",
     _resub(r'(abort_degraded\("policy generation unreadable", fresh_res\.error\(\)\);)\s*return;', r"\1"), "(r)"),
    ("converged-against-fresh early return removed",
     _resub(r"if \(fresh_generation <= agent_gen\)\s*return;", "(void)0;"), "(r)"),
    ("generation gauge set from the cached generation",
     _sub("set(static_cast<double>(fresh_generation))", "set(static_cast<double>(current))"), "(r)"),
    ("exclude hoisted above the bundle get",
     _resub(r"(const auto bundle_result = guardian_rule_bundle_cache_\.get\()", r"admitted.exclude(bundle_waited); \1"), "(r)"),
    ("Shed log no longer worded by cause",
     _sub("shed_cause == GuardianReconcileGate::ShedCause::InFlightCap", "false"), "(k)"),
    ("bundle loader no longer load_reconcile_bundle",
     _sub("guardian::load_reconcile_bundle(", "guardian::make_bundle("), "(o)"),
    ("filter and std::move combined in one statement",
     (lambda s: s + "\nauto b = guardian::make_bundle(guardian::filter_deployed_members(r, d), std::move(*deployed_result));\n"), "(o)"),
    ("bump fan-out stops dropping the generation cache",
     _after("guardian_push_fn_ = [this]", "guardian_generation_cache_.invalidate();", "(void)0;"), "(p)"),
    ("bump fan-out stops dropping the bundle cache",
     _after("guardian_push_fn_ = [this]", "guardian_rule_bundle_cache_.invalidate();", "(void)0;"), "(p)"),
    ("invalidate moved out of the push fn into unrelated code",
     lambda s: _after("guardian_push_fn_ = [this]", "guardian_generation_cache_.invalidate();", "(void)0;")(s)
     + "\nvoid elsewhere() { guardian_generation_cache_.invalidate(); }\n", "(p)"),
    ("in-flight gauge no longer published in the gauge block",
     _resub(r'metrics_\s*\.gauge\("yuzu_server_guardian_reconcile_in_flight"\)\s*\.set\(static_cast<double>\(guardian_reconcile_gate_\.in_flight\(\)\)\);',
            "(void)0;"), "(q)"),
    ("budget balance gauge no longer published in the gauge block",
     _sub('.set(guardian_reconcile_budget_.balance_ms());', ".set(0.0);"), "(q)"),
    ("claims gauge no longer published in the gauge block",
     _resub(r'metrics_\s*\.gauge\("yuzu_server_guardian_reconcile_claims"\)\s*\.set\(static_cast<double>\(guardian_reconcile_gate_\.claims_size\(\)\)\);',
            "(void)0;"), "(q)"),
    ("gauge block loses its catch (...) arm",
     _resub(r'(Guardian reconcile gauge publish failed: \{\}", e\.what\(\)\);\s*\})\s*catch \(\.\.\.\) \{\s*spdlog::warn\("Guardian reconcile gauge publish failed: unknown exception"\);\s*\}',
            r"\1"), "(q)"),
    ("claim sweep loses its catch (...) arm",
     _resub(r'(Guardian reconcile claim sweep failed: \{\}", e\.what\(\)\);\s*\})\s*catch \(\.\.\.\) \{\s*spdlog::warn\("Guardian reconcile claim sweep failed: unknown exception"\);\s*\}',
            r"\1"), "(q)"),
    ("claim sweep loses its catch (const std::exception&) arm",
     _resub(r'\}\s*catch \(const std::exception& e\) \{\s*spdlog::warn\("Guardian reconcile claim sweep failed: \{\}", e\.what\(\)\);\s*\}(\s*catch \(\.\.\.\) \{\s*spdlog::warn\("Guardian reconcile claim sweep failed)',
            r"}\1"), "(q)"),
    ("gauges moved after the claim sweep",
     lambda s: _move_gauges_after_sweep(s), "(q)"),
    ("gauge block inside if (false) { }", _gauges_wrapped("if (false) {\n"), "(q)"),
    ("gauge block in an else arm", _gauges_wrapped("if (true) {} else\n", ""), "(q)"),
    ("a conditional continue before the gauge block",
     _insert_before_gauges("if (guardian_reconcile_budget_.balance_ms() < 0) continue;\n"), "(q)"),
    ("a conditional return before the gauge block",
     _insert_before_gauges("if (guardian_reconcile_budget_.balance_ms() < 0) return;\n"), "(q)"),
    ("a conditional continue between the gauge block and the sweep",
     _insert_after_gauges("if (guardian_reconcile_budget_.balance_ms() < 0) continue;\n"), "(q)"),
    ("a bare return between the gauge block and the sweep", _insert_after_gauges("return;\n"), "(q)"),
    ("gauge block between the reap and the sweep",
     _gauges_moved_after("registry_.reap_stale_sessions(cfg_.session_timeout);"), "(q)"),
    ("gauge block moved into an earlier unrelated function",
     _gauges_moved_after("void bootstrap_default_certs() {"), "(q)"),
    ("gauge block in a never-invoked lambda",
     _gauges_wrapped("auto unused_publish = [&] {\n", "};\n"), "(q)"),
    ("gauge block in a never-invoked lambda after another statement",
     _gauges_wrapped("auto unused_publish = [&] { int pad = 0; (void)pad;\n", "};\n"), "(q)"),
    ("claim sweep outside any try",
     _resub(r'try \{\s*YUZU_ASSERT_BACKGROUND_JOB\("guardian_reconcile_gate\.sweep"\);.*?'
            r'claim sweep failed: unknown exception"\);\s*\}',
            "(void)guardian_reconcile_gate_.sweep();"), "(q)"),
    ("a policy-generation gauge takes the cached current as well",
     _sub("set(static_cast<double>(fresh_generation));",
          "set(static_cast<double>(fresh_generation)); metrics_.gauge(\"yuzu_server_guardian_policy_generation\").set(static_cast<double>(current));"), "(r)"),
    ("fresh-not-ahead return moved after the bundle get",
     lambda s: _resub(r"if \(fresh_generation <= agent_gen\)\s*return;[^\n]*", "(void)0;")(s).replace(
         "admitted.exclude(bundle_waited);", "admitted.exclude(bundle_waited); if (fresh_generation <= agent_gen) return;", 1), "(r)"),
    ("decide( loses its &shed_cause out-parameter",
     _wsub(DECIDE_SWITCH, "switch (guardian_reconcile_gate_.decide(agent_id, agent_gen, current))"), "(k)"),
    ("decide( bypassed by a leading true ||",
     _wsub(DECIDE_SWITCH, "switch (true || guardian_reconcile_gate_.decide(agent_id, agent_gen, current, &shed_cause))"), "(k)"),
]

# Invariants that live in server.cpp; every other lettered entry above mutates the flow header.
SERVER_LETTERS = ("(i)", "(p)", "(q)")

# (s) the delivered-push branch.
SEND = "if (send_push_(agent_id, command_id, push.SerializeAsString())) {"
MUTATIONS += [
    ("sent counted without the send succeeding",
     _sub(SEND, "if (true) { (void)send_push_(agent_id, command_id, push.SerializeAsString());"), "(s)"),
    ("success audit dropped from the delivered-push branch",
     _after('ev.result = "success";', "audit_(ev);", "(void)0;"), "(s)"),
    ("sent counter label changed",
     _sub('{{"result", "sent"}})', '{{"result", "sent_"}})'), "(s)"),
]

FLOW_MUTATIONS = [m for m in MUTATIONS if m[2] not in SERVER_LETTERS]

# (t)/(u): the wiring in server.cpp.
LAMBDA_CALL = "reconcile_flow->run(agent_id_sv, agent_gen);"
FLOW_CTOR = "std::make_shared<GuardianReconcileFlow>("
SERVER_MUTATIONS = [m for m in MUTATIONS if m[2] in SERVER_LETTERS] + [
    ("lambda stops calling the flow", _sub(LAMBDA_CALL, "(void)0;"), "(t)"),
    ("lambda runs the flow and then more",
     _sub(LAMBDA_CALL, LAMBDA_CALL + " (void)guardian_reconcile_gate_.sweep();"), "(t)"),
    ("inline decide( reappears in server.cpp",
     lambda s: s + "\nvoid copy() { (void)guardian_reconcile_gate_.decide(a, b, c); }\n", "(t)"),
    ("flow constructed with a different gate",
     _sub(".gate = guardian_reconcile_gate_,", ".gate = other_gate_,"), "(t)"),
    ("flow constructed with a different budget",
     _sub(".budget = guardian_reconcile_budget_,", ".budget = other_budget_,"), "(t)"),
    ("flow constructed with a different rule bundle cache",
     _sub(".rule_bundle_cache = guardian_rule_bundle_cache_,", ".rule_bundle_cache = other_cache_,"), "(t)"),
    ("flow constructed without the duration histogram",
     _sub(".duration = reconcile_duration,", ".duration = nullptr,"), "(t)"),
    ("scope dependency evaluates the fleet vector",
     _after(FLOW_CTOR, "registry_.evaluate_scope_for_agent(agent_id, expr,", "registry_.evaluate_scope_local(agent_id, expr,"), "(u)"),
    ("push dependency loses the system caller",
     _after(FLOW_CTOR, "yuzu::server::DispatchCaller{.system = true}", "yuzu::server::DispatchCaller{}"), "(u)"),
    ("push dependency forwards the gateway queue before knowing the send worked",
     _sub("auto classified = build_classified_command(\n                        yuzu::server::DispatchCaller{.system = true}",
          "forward_gateway_pending();\n                    auto classified = build_classified_command(\n                        yuzu::server::DispatchCaller{.system = true}"), "(u)"),
    ("push dependency never forwards the gateway queue",
     _after(FLOW_CTOR, "forward_gateway_pending();\n                        return true;", "return true;"), "(u)"),
    ("audit dependency loses the is_open check",
     _after(FLOW_CTOR, "if (audit_store_ && audit_store_->is_open())", "if (audit_store_)"), "(u)"),
    ("rule source reads something else",
     _after(FLOW_CTOR, "guaranteed_state_store_->list_rules()", "guaranteed_state_store_->list_rules_unfiltered()"), "(u)"),
    ("deployed set source dropped",
     _after(FLOW_CTOR, "return deployed_member_rule_ids();", "return DeployedSet{};"), "(u)"),
    ("session lookup dropped",
     _after(FLOW_CTOR, "auto sess = registry_.get_session(agent_id);", "auto sess = std::shared_ptr<AgentSession>{};"), "(u)"),
    ("command id suffix no longer random",
     _after(FLOW_CTOR, "auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8))", "std::string(\"0\")"), "(u)"),
    # (u) exact wiring bodies: the right tokens fed the wrong values.
    ("push dependency sends an EMPTY push (ignores its push_bytes parameter)",
     _wafter(FLOW_CTOR, "command_id, /*parameters=*/{}, push_bytes);", "command_id, /*parameters=*/{}, std::string{});"), "(u)"),
    ("push dependency uses a CONSTANT command id (ignores its command_id parameter)",
     _wafter(FLOW_CTOR, '"push_rules", command_id,', '"push_rules", std::string("fixed-id"),'), "(u)"),
    ("push dependency sends to the wrong agent_id",
     _wafter(FLOW_CTOR, "send_system_reserved( agent_id, *classified,", "send_system_reserved( other_agent_id_, *classified,"), "(u)"),
    ("scope dependency passes null tag and property stores",
     _wafter(FLOW_CTOR, "evaluate_scope_for_agent(agent_id, expr, tag_store_.get(), custom_properties_store_.get())",
             "evaluate_scope_for_agent(agent_id, expr, nullptr, nullptr)"), "(u)"),
    ("scope dependency passes only the tag store",
     _wafter(FLOW_CTOR, "tag_store_.get(), custom_properties_store_.get())", "tag_store_.get(), nullptr)"), "(u)"),
    ("scope dependency evaluates the wrong agent_id",
     _wafter(FLOW_CTOR, "evaluate_scope_for_agent(agent_id, expr,", "evaluate_scope_for_agent(other_agent_id_, expr,"), "(u)"),
    ("store_wired is constant true",
     _wafter(FLOW_CTOR, "return static_cast<bool>(guaranteed_state_store_);", "return true;"), "(u)"),
    ("store_wired inverted",
     _wafter(FLOW_CTOR, "return static_cast<bool>(guaranteed_state_store_);", "return !static_cast<bool>(guaranteed_state_store_);"), "(u)"),
    ("list_rules gains a side effect before the read",
     _wafter(FLOW_CTOR, "return guaranteed_state_store_->list_rules();", "(void)deployed_member_rule_ids(); return guaranteed_state_store_->list_rules();"), "(u)"),
    ("session lookup targets the wrong agent",
     _wafter(FLOW_CTOR, "registry_.get_session(agent_id)", "registry_.get_session(other_agent_id_)"), "(u)"),
    ("session os is a constant",
     _wafter(FLOW_CTOR, "return sess->os;", 'return std::string("linux");'), "(u)"),
    ("command id suffix uses fewer random bytes",
     _wafter(FLOW_CTOR, "random_bytes(8)", "random_bytes(1)"), "(u)"),
    ("command id suffix is random bytes without the hex encoding",
     _wafter(FLOW_CTOR, "return auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));",
             "return std::string(auth::AuthManager::random_bytes(8).begin(), auth::AuthManager::random_bytes(8).end());"), "(u)"),
    ("filter and std::move combined in one statement (server.cpp)",
     (lambda s: s + "\nauto b = guardian::make_bundle(guardian::filter_deployed_members(r, d), std::move(*deployed_result));\n"), "(o)"),
    # (u) the audit callable and the send_push result arms, pinned whole.
    ("audit dependency logs an empty event instead of its parameter",
     _after(FLOW_CTOR, "(void)audit_store_->log(ev);", "(void)audit_store_->log(AuditEvent{});"), "(u)"),
    ("audit dependency's is_open check is made vacuous",
     _after(FLOW_CTOR, "if (audit_store_ && audit_store_->is_open())",
            "if (audit_store_ && (audit_store_->is_open() || true))"), "(u)"),
    ("audit dependency logs unconditionally",
     _after(FLOW_CTOR, "if (audit_store_ && audit_store_->is_open())\n", "if (true)\n"), "(u)"),
    ("push dependency admits an unclassified command (classified ||)",
     _wafter(FLOW_CTOR, "if (classified &&", "if (classified ||"), "(u)"),
    ("push dependency reports success on its final fall-through",
     _after(FLOW_CTOR, "return false;", "return true;"), "(u)"),
    ("push dependency reports success without waiting for the send",
     _wafter(FLOW_CTOR, "forward_gateway_pending(); return true; } return false;",
             "forward_gateway_pending(); } return true;"), "(u)"),
    # (v) the rule-mutation hook.
    ("rule-mutation hook is never wired",
     _wafter("set_on_rule_mutation([this] {",
             "guardian_generation_cache_.invalidate(); guardian_rule_bundle_cache_.invalidate(); });",
             "});"), "(v)"),
    ("rule-mutation hook forgets the rule bundle cache",
     _wafter("set_on_rule_mutation([this] {", "guardian_rule_bundle_cache_.invalidate();", "(void)0;"), "(v)"),
    ("rule-mutation hook forgets the generation cache",
     _wafter("set_on_rule_mutation([this] {", "guardian_generation_cache_.invalidate();", "(void)0;"), "(v)"),
    ("rule-mutation hook invalidates only when something else holds",
     _wafter("set_on_rule_mutation([this] {", "guardian_generation_cache_.invalidate();",
             "if (cfg_.guardian_reconcile_max_per_s > 0) guardian_generation_cache_.invalidate();"), "(v)"),
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
BENIGN_FLOW = [
    ("comment mentions evaluate_scope_local(",
     _sub("bool scope_degraded = false;", "bool scope_degraded = false; // not evaluate_scope_local( any more")),
    ("string literal mentions guardian_last_reconcile_",
     _sub("bool scope_degraded = false;", 'bool scope_degraded = false; const char* old_name = "guardian_last_reconcile_";')),
    ("block comment mentions current_policy_generation(",
     _sub("bool scope_degraded = false;", "bool scope_degraded = false; /* current_policy_generation( */")),
]

BENIGN_SERVER = [
    # (u) exact bodies must accept reflow and comments, only values matter.
    ("scope dependency call re-wrapped, one argument per line",
     _wafter(FLOW_CTOR, "evaluate_scope_for_agent(agent_id, expr, tag_store_.get(), custom_properties_store_.get());",
             "evaluate_scope_for_agent(\n agent_id,\n expr,\n tag_store_.get(),\n custom_properties_store_.get());")),
    ("push command built on one line with a comment on each argument",
     _wafter(FLOW_CTOR, 'build_classified_command( yuzu::server::DispatchCaller{.system = true}, "__guard__", "push_rules", command_id, /*parameters=*/{}, push_bytes);',
             'build_classified_command(yuzu::server::DispatchCaller{.system = true}, /*caller*/ "__guard__", "push_rules", /*id*/ command_id, {}, /*bytes*/ push_bytes);')),
    ("send_system_reserved call re-wrapped",
     _wafter(FLOW_CTOR, "send_system_reserved( agent_id, *classified,", "send_system_reserved(\n agent_id,\n *classified,")),
    ("store_wired body split across lines with a comment",
     _wafter(FLOW_CTOR, "[this] { return static_cast<bool>(guaranteed_state_store_); }",
             "[this] {\n // the store pointer is reset by stop()\n return static_cast<bool>(guaranteed_state_store_);\n }")),
    # (u) tolerated spellings: they do not change what the callable does.
    ("this-> member prefixes on the dependency bodies",
     _wafter(FLOW_CTOR, "return registry_.evaluate_scope_for_agent(agent_id, expr, tag_store_.get(), custom_properties_store_.get());",
             "return this->registry_.evaluate_scope_for_agent(agent_id, expr, this->tag_store_.get(), this->custom_properties_store_.get());")),
    ("store_wired compared against nullptr",
     _wafter(FLOW_CTOR, "return static_cast<bool>(guaranteed_state_store_);", "return guaranteed_state_store_ != nullptr;")),
    ("audit store tested against nullptr, with braces and a this-> prefix",
     _wafter(FLOW_CTOR, "if (audit_store_ && audit_store_->is_open()) (void)audit_store_->log(ev);",
             "if (this->audit_store_ != nullptr && this->audit_store_->is_open()) { (void)this->audit_store_->log(ev); }")),
    ("const auto for the session local",
     _wafter(FLOW_CTOR, "auto sess = registry_.get_session(agent_id);", "const auto sess = registry_.get_session(agent_id);")),
    ("lambda parameters renamed",
     _wafter(FLOW_CTOR, "[this](const AuditEvent& ev) { if (audit_store_ && audit_store_->is_open()) (void)audit_store_->log(ev); }",
             "[this](const AuditEvent& event) { if (audit_store_ && audit_store_->is_open()) (void)audit_store_->log(event); }")),
    ("send_push parameters renamed",
     _wafter(FLOW_CTOR, "[this](const std::string& agent_id, const std::string& command_id, const std::string& push_bytes) -> bool { auto classified = build_classified_command( yuzu::server::DispatchCaller{.system = true}, \"__guard__\", \"push_rules\", command_id, /*parameters=*/{}, push_bytes); if (classified && send_system_reserved( agent_id, *classified,",
             "[this](const std::string& target, const std::string& cid, const std::string& bytes) -> bool { auto classified = build_classified_command( yuzu::server::DispatchCaller{.system = true}, \"__guard__\", \"push_rules\", cid, /*parameters=*/{}, bytes); if (classified && send_system_reserved( target, *classified,")),
    ("rule-mutation hook with the invalidations in the other order and a this-> prefix",
     _wafter("set_on_rule_mutation([this] {",
             "guardian_generation_cache_.invalidate(); guardian_rule_bundle_cache_.invalidate();",
             "this->guardian_rule_bundle_cache_.invalidate(); this->guardian_generation_cache_.invalidate();")),
    ("session lookup with braces around the early return",
     _wafter(FLOW_CTOR, "if (!sess) return std::nullopt;", "if (!sess) { return std::nullopt; }")),
    # (q) must accept restructurings that keep the invariant: the gate is about order and
    # placement, not about the exact text of the sweep try.
    ("the sweep result is consumed",
     _sub("(void)guardian_reconcile_gate_.sweep();",
          "const auto swept = guardian_reconcile_gate_.sweep(); (void)swept;")),
    ("an extra statement follows the sweep in its try",
     _sub("(void)guardian_reconcile_gate_.sweep();",
          'const auto swept = guardian_reconcile_gate_.sweep(); spdlog::debug("swept {}", swept);')),
    ("unnamed catch variables",
     _resub(r"catch \(const std::exception& e\) \{(\s*)spdlog::warn\(\"Guardian reconcile claim sweep failed: \{\}\", e\.what\(\)\);",
            r'catch (const std::exception&) {\1spdlog::warn("Guardian reconcile claim sweep failed");')),
    ("unnamed catch variable on the gauge try",
     _resub(r"catch \(const std::exception& e\) \{(\s*)spdlog::warn\(\"Guardian reconcile gauge publish failed: \{\}\", e\.what\(\)\);",
            r'catch (const std::exception&) {\1spdlog::warn("Guardian reconcile gauge publish failed");')),
    ("a brace initializer inside a catch body",
     _sub('spdlog::warn("Guardian reconcile claim sweep failed: unknown exception");',
          'spdlog::warn("Guardian reconcile claim sweep failed: unknown exception"); '
          'const std::string tag{"x"}; (void)tag;')),
    ("a nested block inside the gauge try",
     _resub(r'(try \{)(\s*metrics_\s*\.gauge\("yuzu_server_guardian_reconcile_in_flight"\))',
            r"\1 { int probe{0}; (void)probe; } \2")),
    ("clang-format style reflow of the catch arms",
     lambda s: re.sub(r"\} catch \(const std::exception& e\) \{", "}\n      catch (const std::exception &e)\n      {", s)),
    ("an unrelated statement between the reap and the sweep",
     _sub("registry_.reap_stale_sessions(cfg_.session_timeout);",
          "registry_.reap_stale_sessions(cfg_.session_timeout); spdlog::debug(\"reaped\");")),
]


class GuardianReconcileWiringLexical(unittest.TestCase):
    def setUp(self):
        self.src = SERVER_CPP.read_text(encoding="utf-8")
        self.flow_src = FLOW_HPP.read_text(encoding="utf-8")
        self.push_src = PUSH_BUILDER_CPP.read_text(encoding="utf-8")

    def _check_clean(self, found):
        for m in found:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(found, [])

    def _check_caught(self, mutations, source, check):
        for name, mutate, expected in mutations:
            with self.subTest(mutation=name):
                mutated = mutate(source)
                self.assertNotEqual(mutated, source, "mutation changed nothing (stale pattern)")
                p = check(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertIn(expected, "\n".join(p))

    def test_flow_is_clean(self):
        self._check_clean(flow_problems(self.flow_src))

    def test_flow_mutations_are_caught(self):
        self._check_caught(FLOW_MUTATIONS, self.flow_src, flow_problems)

    def test_wiring_is_clean(self):
        self._check_clean(problems(self.src))

    def test_wiring_mutations_are_caught(self):
        self._check_caught(SERVER_MUTATIONS, self.src, problems)

    def test_every_mutation_is_routed_to_a_source(self):
        # A mutation list entry whose letter belongs to neither source would silently never run.
        self.assertEqual(len(FLOW_MUTATIONS) + len([m for m in MUTATIONS if m[2] in SERVER_LETTERS]),
                         len(MUTATIONS))

    def test_push_builder_is_clean(self):
        self._check_clean(push_builder_problems(self.push_src))

    def test_push_builder_mutations_are_caught(self):
        self._check_caught(PUSH_MUTATIONS, self.push_src, push_builder_problems)

    def test_benign_text_is_not_flagged(self):
        for name, mutate in BENIGN_FLOW:
            with self.subTest(benign=name):
                mutated = mutate(self.flow_src)
                self.assertNotEqual(mutated, self.flow_src, "benign edit changed nothing (stale pattern)")
                self.assertEqual(flow_problems(mutated), [])
        for name, mutate in BENIGN_SERVER:
            with self.subTest(benign=name):
                mutated = mutate(self.src)
                self.assertNotEqual(mutated, self.src, "benign edit changed nothing (stale pattern)")
                self.assertEqual(problems(mutated), [])

    def test_a_commented_out_decide_does_not_satisfy_the_gate(self):
        # Comment stripping must remove the call entirely, not merely hide it from one regex.
        mutated = _wsub(DECIDE_SWITCH, "// " + DECIDE_SWITCH + "\n switch (GuardianReconcileGate::Decision::Admit)")(self.flow_src)
        self.assertNotEqual(mutated, self.flow_src)
        self.assertIn("(a)", "\n".join(flow_problems(mutated)))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
