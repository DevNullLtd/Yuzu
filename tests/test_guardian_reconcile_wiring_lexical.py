#!/usr/bin/env python3
"""#5513 static lexical gate over the Guardian heartbeat-reconcile control flow and its wiring.

ServerImpl is never constructed by a unit test, so nothing else would notice if the wiring that
makes the reconcile path safe at fleet scale were reverted: the building blocks
(guardian_reconcile_gate.hpp, guardian_reconcile_budget.hpp, guardian_generation_cache.hpp,
guardian_rule_bundle.hpp, AgentRegistry::evaluate_scope_for_agent) are unit-tested in isolation,
and every one of them could be silently bypassed with all those tests green. This gate pins the
call sites.

TWO TARGETS (the control flow lives in guardian_reconcile_flow.hpp, extracted from the ServerImpl
heartbeat lambda so that it is unit tested; tests/unit/server/test_guardian_reconcile_flow.cpp is
the behavioural guard and this gate is the cheap tripwire that stays beside it):

  FLOW = the body of `void run(` in server/core/src/guardian_reconcile_flow.hpp (comments
  removed, string-literal contents reduced to [A-Za-z0-9_], whitespace collapsed): invariants
  a-h, j-o, r, s, w below.
  WIRING = server.cpp: the `set_guardian_reconcile_fn(` call, the `GuardianReconcileFlowDeps`
  construction feeding it, the maintenance tick, the cache-invalidation wrapper, the two stores'
  post-mutation hooks, the push fan-out and the member declaration order: invariants i, o
  (second half), p, q, t, u, v, x, y, z, aa.
  WRITERS = server/core/src/baseline_store.cpp: the BaselineStore writer guard, "bw" below.

LETTERS. "p" names two invariants over server.cpp, "p (invalidation)" (the fan-out invalidates) and
"p (placement)" (where it does so); both report as "(p)". The BaselineStore writer guard is "bw", not "b", because "b" is the Shed
invariant of the FLOW.

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
  f. A scope-evaluation error of EVERY kind except `Unresolvable` sets `scope_degraded`
     (`kind != ScopeEvalError::Kind::Unresolvable`; `Unresolvable` alone is "not a member"), and
     `if (scope_degraded)` leads to `abort_degraded(` and a `return` (send nothing; never a
     narrowed full_sync). The abort's detail (audit row and log) is the kind name alone, with the
     error's own detail appended only for `StoreDegraded` (another kind's detail can be a
     caller-supplied identifier: `OwnerCheckFailed` carries a result-set id).
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

  w. A rule bundle that an invalidation overtook is never sent (the epoch check): the flow reads
     `const auto bundle_epoch = guardian_rule_bundle_cache_.epoch();` BEFORE the fresh generation
     read (so every invalidation after that point is seen), and compares
     `guardian_rule_bundle_cache_.epoch() != bundle_epoch` AFTER the bundle get and BEFORE the
     send, where a changed epoch aborts through `abort_invalidated("rule bundle invalidated
     during load", ...)` AND returns. `abort_invalidated` counts
     `yuzu_server_guardian_reconcile_invalidated_total` and NOT result="degraded" (no store
     failed; the degraded series is the pool-pressure signal), and writes the same ABORTED audit
     row through the shared `audit_abort` helper that `abort_degraded` also uses (m).
     GuardianRuleBundleCache::get() hands a load that invalidate() detached to its own caller and
     to its waiters, so without this check a rule edit whose best-effort generation bump failed
     lets an in-flight reconcile send the pre-edit rows under the unchanged generation, and the
     agent stays converged on them until the next bump. Tolerated spellings: a `this->` prefix,
     `auto` or `std::uint64_t` for `bundle_epoch`, `const` or not, either operand order of the
     `!=`. NOT pinnable lexically (review-enforced): a conditional `return` or an `if (false)`
     wrapped around the abort inside the check block, and a dead or unreachable check.

Invariants over the WIRING (server.cpp):

  i. `guardian_last_reconcile_` and `guardian_reconcile_mu_` no longer exist; the claim-map sweep
     (`guardian_reconcile_gate_.sweep(`) is called; and the pre-seed loop for
     `yuzu_server_guardian_reconciles_total` includes "shed".
  p (invalidation). The body of the `guardian_push_fn_` lambda (not merely anywhere else) invalidates the
     reconcile caches, through the wrapper of (z) (see `p (placement)` below).
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
     of the control flow would drift from the unit-tested one), and the lambda captures the
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
  aa. DECLARATION ORDER of the `ServerImpl` members the flow's lifetime depends on. C++ destroys
     members in reverse declaration order, and the flow (held by the lambda that
     `heartbeat_ingestion_` owns) holds references to the budget, gate and both caches, and its
     callables read the two stores. So in server.cpp: `guardian_reconcile_budget_` is declared
     before `guardian_reconcile_gate_` (the gate holds a reference to it); each of the four
     guardian members (budget, gate, `guardian_generation_cache_`,
     `guardian_rule_bundle_cache_`) is declared before `heartbeat_ingestion_` (so the flow dies
     first); and each of the two stores (`guaranteed_state_store_`, `baseline_store_`) is declared
     before each of the two caches. That last pair of rules is a conservative second line, not the
     cover for the hook direction: the invalidation hooks are installed ON the stores and call INTO
     the caches, and stop() clears both hooks before it resets the stores. What the order covers
     is a call still running inside a cache while it is destroyed: the generation cache's fetch
     lambda and the loader the flow builds for the bundle cache capture `this` and read the stores
     through it, so the stores must still be alive. The caches have no destructor that touches a
     store. Each declaration must appear exactly once. Tolerated: any whitespace, comments,
     `guardian::` qualification, a `{...}` initializer or a bare `;`. Limits: it pins the
     relative order of these seven declarations only; a member declared elsewhere that the flow
     also borrows (for example `metrics_`, `registry_`) is not covered. Checked by
     `declaration_order_problems()` on its own, not inside `problems()`, so that its self-test
     stays in the light half.
  z. ONE owner for "drop the reconcile caches": `ServerImpl::invalidate_guardian_reconcile_caches()` is
     defined once and its body calls BOTH `guardian_generation_cache_.invalidate()` and
     `guardian_rule_bundle_cache_.invalidate()`; those two direct calls appear nowhere else in
     server.cpp, so a writer that repeats the pair, or forgets one cache, is red.
  v. `GuaranteedStateStore::set_on_rule_mutation(` is wired exactly once, with a lambda whose body is
     exactly one call to that wrapper, not under a constant-false `if`, and cleared again with
     `set_on_rule_mutation({})` exactly once at stop() time: a rule create/update/delete whose
     best-effort generation bump failed leaves the generation unchanged, so without this hook a held
     rule bundle is served to a new agent for up to its max_age (chaos-F1). The store-side half (the
     hook fires after the commit and after the bump attempt on all three mutation paths, never
     throws, holds no lease) is pinned by the [rule_hook] cases in
     tests/unit/server/test_guaranteed_state_store.cpp, which need a Postgres.
  x. `GuardianRoutes` baseline deploy/delete reach the reconcile caches BEFORE their own policy
     bump: `BaselineStore::set_on_baseline_mutation(` is wired exactly once with the same
     one-wrapper-call lambda, not under a constant-false `if`, and cleared at stop() time (a
     deploy writes the new deployed snapshot, then takes a second lease for the bump; a
     reconcile in that gap would send the old deployed set under the unchanged label). The
     pre-seed of `yuzu_server_guardian_reconcile_invalidated_total` is present exactly once and
     not under a constant-false `if`.
  p (placement). Inside the `guardian_push_fn_` body the wrapper is called exactly once, at the lambda's own
     brace depth and not as the body of an `if`/`else`/loop, so every path that reaches the
     reads has invalidated first.
  y. In the same body the explicit scope is parsed first, under exactly
     `if (!scope.empty() && !(scope.starts_with("group:") && mgmt_group_store_))`, and an
     unparseable scope is refused with `return -1` (tolerated spellings: `if (!parsed)`,
     `.has_value()`, `== false`, braced or split over lines), BEFORE the wrapper call, which
     comes BEFORE the generation read (`current_policy_generation(`): an invalid-scope push must
     not withhold in-flight reconciles, and the fan-out order stays safe.

Invariants over the WRITERS (baseline_store.cpp):

  bw. BaselineStore writer drift guard (baseline_store.cpp, `baseline_writer_problems`): every
     function that writes `baseline_store.baselines` (UPDATE, DELETE FROM, INSERT INTO) calls
     `notify_baseline_mutation()` or is on BASELINE_WRITER_ALLOWLIST with a reason (set_members
     and set_assignment stamp updated_at only, and are red the moment they name lifecycle or
     deployed_snapshot). Where it calls it, the call comes AFTER `lease.reset()` (the hook must
     not run with the pool lease held), is not under a constant-false `if`, and is not the body
     of a conditional: update_baseline and delete_baseline fire unconditionally (brace depth 1),
     and create_baseline fires only inside `if (lifecycle == kBaselineDeployed) { ... }` (a
     draft create, which is all the routes ever do, stays silent). A write outside every
     BaselineStore method is red too. The runtime half (the hook fires once per committed
     update, delete and deployed create, never on a failed one, holds no lease, cannot break the
     mutation) is pinned by the [baseline_hook] cases in tests/unit/server/test_baseline_store.cpp.
     Accepted limits of (bw), lexical only, no code for them: it can be falsely RED on
     `if (auto it = f(); cond) return x;` and on `for (;;) return ...` (the statement head is cut
     at the last `;`, so the conditional is not seen). It can be falsely GREEN on a bare
     `{ return; }` block, a `throw`, a `goto`, `if (true) return`, a conditional return after
     the commit that skips the notify, and a notify placed before an explicit COMMIT after a
     future PgTxn refactor. It also only sees what it can match: a raw string literal
     `R"sql(UPDATE baseline_store.baselines ...)sql"` (lex() blanks raw strings), lowercase
     `update ...`, `delete from ...` or `insert into ...` (the write pattern is case-sensitive)
     and a literal split in two (`"UPDATE " "baseline_store.baselines"`) are not recognised as
     writes; neither are doubled spaces inside the statement, `UPDATE ONLY`, `TRUNCATE`, `MERGE`
     or quoted identifiers (`"baseline_store"."baselines"`), none of which the write pattern
     lists. baseline_store.cpp is the only source that names the table today. The
     [baseline_hook] runtime cases are the backstop for all of these.

LEXICAL ONLY. It cannot see a relocation that keeps the tokens but changes control flow (that
stays review-enforced), and the behavioural guarantees are the building blocks' own unit tests.
The self-test applies in-memory mutations to a COPY of each source and requires problems() (server.cpp)
or flow_problems() (the flow header) to name the expected invariant on each; a mutation that changes nothing fails loudly (stale pattern).
BENIGN controls prove a comment or string that merely mentions a token cannot trip or satisfy it.

Modelled on tests/test_gateway_peer_registration_lexical.py and
tests/test_guardian_heartbeat_wiring_lexical.py. Sources are read as UTF-8. Python, not bash, like
the other no-build lexical gates (#5428).

Usage: python3 tests/test_guardian_reconcile_wiring_lexical.py
       LEXICAL_GATE_PART=light|heavy python3 -I tests/test_guardian_reconcile_wiring_lexical.py   (CI halves)
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
BASELINE_STORE_CPP = Path(os.environ.get(
    "BASELINE_STORE_CPP", ROOT / "server" / "core" / "src" / "baseline_store.cpp"))
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

    if not re.search(r"\} else if \( ?\w+\.error\(\)\.kind ?!= ?ScopeEvalError::Kind::Unresolvable ?\) ?\{ ?"
                     r"scope_degraded = true ?;", b):
        out.append("a scope error of a kind other than Unresolvable no longer sets scope_degraded: "
                   "only Unresolvable may mean 'not a member' (f)")
    if not re.search(r"\bif \( ?scope_degraded ?\) ?\{[^{}]*?\babort_degraded\([^;]*;[^{}]*?\breturn ?;", b):
        out.append("if (scope_degraded) no longer leads to abort_degraded( and a return (f)")
    if not re.search(r"scope_degraded_detail = to_string\( ?\w+\.error\(\)\.kind ?\) ?; ?"
                     r"if \( ?\w+\.error\(\)\.kind ?== ?ScopeEvalError::Kind::StoreDegraded ?&& ?"
                     r"!\w+\.error\(\)\.detail\.empty\(\) ?\) ?scope_degraded_detail \+= ", b):
        out.append("the scope-degraded detail is no longer the kind name alone for every kind except "
                   "StoreDegraded: another kind's detail (OwnerCheckFailed carries a result-set id) "
                   "would reach the audit row and the log (f)")

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
    aa = block_after(b, "auto audit_abort = [")
    if ab is None:
        out.append("could not isolate the abort_degraded lambda body (m)")
    else:
        if not re.search(r'\.counter\( ?"yuzu_server_guardian_reconciles_total", ?\{ ?\{ ?"result", ?"degraded" ?\} ?\} ?\)'
                         r' ?\.increment\(\)', ab):
            out.append('abort_degraded no longer increments result="degraded" (m)')
        if not re.search(r"\baudit_abort\( ?what, ?err ?\) ?;", ab):
            out.append("abort_degraded no longer writes the audit event through audit_abort (m)")
    if aa is None:
        out.append("could not isolate the audit_abort lambda body (m)")
    elif not (re.search(r"\bAuditEvent\b", aa) and re.search(r"\baudit_ ?\( ?ev ?\) ?;", aa)):
        out.append("audit_abort no longer writes the audit event (m)")
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

    # (w) an invalidated bundle is never sent.
    epoch_read = re.search(r"\b(?:const )?(?:auto|std::uint64_t) bundle_epoch = (?:this ?-> ?)?"
                           r"guardian_rule_bundle_cache_\.epoch\(\) ?;", b)
    if not epoch_read:
        out.append("the flow no longer reads guardian_rule_bundle_cache_.epoch() into bundle_epoch (w)")
    elif fresh_read and not epoch_read.start() < fresh_read.start():
        out.append("bundle_epoch is no longer read BEFORE the fresh generation read: an invalidation "
                   "that lands between the two would go unseen (w)")
    send_at = re.search(r"\bsend_push_\(", b)
    ep = r"(?:this ?-> ?)?guardian_rule_bundle_cache_\.epoch\(\)"
    check = re.search(r"\bif \( ?(?:" + ep + r" ?!= ?bundle_epoch|bundle_epoch ?!= ?" + ep + r") ?\) ?\{([^{}]*)\}", b)
    if not check:
        out.append("the `if (guardian_rule_bundle_cache_.epoch() != bundle_epoch)` check is gone: a rule "
                   "bundle an invalidation overtook would be sent under the unchanged generation (w)")
    else:
        if not re.search(r'\babort_invalidated\( ?"rule_bundle_invalidated_during_load"[^;]*;[^{}]*?\breturn ?;', check.group(1)):
            out.append("a changed bundle epoch no longer aborts through abort_invalidated and returns (w)")
        if bundle_get and not bundle_get.start() < check.start():
            out.append("the bundle epoch check is no longer AFTER the bundle get (w)")
        if send_at and not check.start() < send_at.start():
            out.append("the bundle epoch check is no longer BEFORE the send (w)")
    ai = block_after(b, "auto abort_invalidated = [")
    if ai is None:
        out.append("could not isolate the abort_invalidated lambda body (w)")
    else:
        if not re.search(r'\.counter\( ?"yuzu_server_guardian_reconcile_invalidated_total" ?\) ?\.increment\(\)', ai):
            out.append("abort_invalidated no longer increments yuzu_server_guardian_reconcile_invalidated_total (w)")
        if re.search(r'"yuzu_server_guardian_reconciles_total"|"degraded"', ai):
            out.append('abort_invalidated counts result="degraded": no store failed, and that series is the '
                       'pool-pressure signal (w)')
        if not re.search(r"\baudit_abort\( ?what, ?err ?\) ?;", ai):
            out.append("abort_invalidated no longer writes the ABORTED audit row through audit_abort (w)")
    return out


# Writers of baseline_store.baselines that may skip the post-mutation hook, each with the reason.
# set_members and set_assignment only stamp `updated_at`: neither touches `lifecycle` or
# `deployed_snapshot`. create_baseline is not allowlisted: it must fire the hook when it commits
# a DEPLOYED baseline (a route-created one is always a draft, guardian_routes.cpp
# create_baseline_from_form, and a draft create stays silent), and the sweep pins that shape.
BASELINE_WRITER_ALLOWLIST = {
    "set_members": "stamps updated_at only, never lifecycle or deployed_snapshot",
    "set_assignment": "stamps updated_at only, never lifecycle or deployed_snapshot",
}
_BASELINE_WRITE = re.compile(r"(?<![A-Za-z0-9])(?:UPDATE|DELETE_FROM|INSERT_INTO)_baseline_store_baselines(?![A-Za-z0-9])")
_STAMP_ONLY = ("set_members", "set_assignment")


def baseline_writer_problems(src):
    """(bw) Drift guard for BaselineStore (#5513): every function that writes the baselines table
    (UPDATE, DELETE FROM or INSERT INTO baseline_store.baselines) must call
    notify_baseline_mutation(), or sit on BASELINE_WRITER_ALLOWLIST with a reason. A new writer
    that forgets the hook would let a reconcile send the old deployed set under the unchanged
    generation label, the exact defect the hook exists to close."""
    t, out = lex(src), []
    braces = [(m.start(), m.group()) for m in re.finditer(r"[{}]", t)]
    spans = []  # (name, body_start, body_end)
    for m in re.finditer(r"\bBaselineStore::(~?\w+) ?\(", t):
        close = match_close(t, m.end() - 1, "(", ")")
        if close < 0:
            continue
        rest = re.match(r" ?(?:const)? ?(?:noexcept)? ?(?::[^{;]*)?\{", t[close + 1:])
        if not rest:
            continue  # a call, not a definition
        open_idx = close + 1 + rest.end() - 1
        end = match_close(t, open_idx, "{", "}")
        if end >= 0:
            spans.append((m.group(1), open_idx, end))
    if not spans:
        return ["baseline_store.cpp no longer has any parseable BaselineStore:: method definitions (bw)"]
    writers = {}
    for w in _BASELINE_WRITE.finditer(t):
        owner = [sp for sp in spans if sp[1] < w.start() < sp[2]]
        if not owner:
            out.append("a write to baseline_store.baselines sits outside every BaselineStore method (bw)")
            continue
        writers.setdefault(owner[0][0], owner[0])
    for name, (_n, lo, hi) in writers.items():
        body = t[lo:hi + 1]
        notifies = re.search(r"\bnotify_baseline_mutation\( ?\) ?;", body) is not None
        if name in BASELINE_WRITER_ALLOWLIST:
            if name in _STAMP_ONLY and re.search(r'"[^"]*(?<![A-Za-z0-9])(?:lifecycle|deployed_snapshot)(?![A-Za-z0-9])[^"]*"', body):
                out.append(f"BaselineStore::{name} is allowlisted as an updated_at-only writer but now names "
                           f"lifecycle or deployed_snapshot: it must fire notify_baseline_mutation() (bw)")
            continue
        if not notifies:
            out.append(f"BaselineStore::{name} writes baseline_store.baselines but never calls "
                       f"notify_baseline_mutation(), and is not on the allowlist (bw)")
            continue
        last_write = max(w2.start() for w2 in _BASELINE_WRITE.finditer(body))
        for nm in re.finditer(r"\bnotify_baseline_mutation\( ?\) ?;", body):
            before = body[:nm.start()]
            if nm.start() < last_write:
                out.append(f"BaselineStore::{name} calls notify_baseline_mutation() before its write to "
                           f"baseline_store.baselines: it would announce a change that has not committed (bw)")
            # An unconditional `return` between the write and the notify makes the notify unreachable.
            running = 0
            depth_at = []
            for ch in body[:nm.start()]:
                if ch == "{":
                    running += 1
                elif ch == "}":
                    running -= 1
                depth_at.append(running)
            for rt in re.finditer(r"\breturn\b", body[last_write:nm.start()]):
                r_pos = last_write + rt.start()
                rhead = body[:r_pos]
                rhead = rhead[max(rhead.rfind(";"), rhead.rfind("{"), rhead.rfind("}")) + 1:]
                if re.search(r"\b(?:if|else|for|while|switch)\b|\?", rhead):
                    continue  # a conditional return does not dominate the notify
                d_r = depth_at[r_pos - 1] if r_pos else 0
                if min(depth_at[r_pos:], default=d_r) >= d_r:
                    out.append(f"BaselineStore::{name} has an unconditional `return` between its write and "
                               f"notify_baseline_mutation(): the notify is unreachable (bw)")
                    break
            if not re.search(r"\blease ?\. ?reset\( ?\) ?;", before):
                out.append(f"BaselineStore::{name} calls notify_baseline_mutation() before lease.reset(): the hook "
                           f"would run with the pool lease held (bw)")
            if under_dead_condition(t, braces, lo + nm.start()):
                out.append(f"BaselineStore::{name} calls notify_baseline_mutation() under a dead condition (bw)")
            depth = before.count("{") - before.count("}")
            head = before[max(before.rfind(";"), before.rfind("{"), before.rfind("}")) + 1:]
            if re.search(r"\b(?:if|else|for|while|switch)\b|\?", head):
                out.append(f"BaselineStore::{name} calls notify_baseline_mutation() as the body of a conditional "
                           f"statement (bw)")
            if name == "create_baseline":
                if depth != 2 or not re.search(r"\bif ?\( ?lifecycle ?== ?kBaselineDeployed ?\) ?\{ ?(?:[^{}]*;)? ?$", before):
                    out.append("BaselineStore::create_baseline must fire the hook only inside "
                               "`if (lifecycle == kBaselineDeployed) { ... }` (a draft create stays silent, a "
                               "deployed one changes the deployed set) (bw)")
            elif depth != 1:
                out.append(f"BaselineStore::{name} calls notify_baseline_mutation() inside a branch: it must fire on "
                           f"every committed {name} (bw)")
    for name in ("create_baseline", "update_baseline", "delete_baseline"):
        if name not in writers:
            out.append(f"BaselineStore::{name} no longer writes baseline_store.baselines where expected (bw)")
    return out


_DEAD_COND = re.compile(r"\b(?:if|while) ?\( ?(?:false|0|nullptr) ?\) ?$|\bif constexpr ?\( ?false ?\) ?$")
_DEAD_ANY = re.compile(r"\bif ?\( ?(?:false|0|nullptr) ?\)")


def under_dead_condition(t, braces, idx):
    """True when t[idx] is dominated by a constant-false `if`/`while`: inside a block opened right
    after one, or an unbraced statement that follows one. `braces` is [(pos, '{' or '}')]."""
    import bisect
    k = bisect.bisect_left(braces, (idx, "")) - 1
    depth = 0
    while k >= 0:
        pos, ch = braces[k]
        if ch == "}":
            depth += 1
        elif depth:
            depth -= 1
        else:
            if _DEAD_COND.search(t[max(0, pos - 40):pos].rstrip()):
                return True
        k -= 1
    start = max(t.rfind(";", 0, idx), t.rfind("{", 0, idx), t.rfind("}", 0, idx))
    return bool(_DEAD_ANY.search(t[start + 1:idx]))


# (aa) The seven ServerImpl member declarations whose relative order the flow's lifetime depends on,
# as patterns over lexed text (comments gone, whitespace collapsed). A namespace qualifier on the
# type is tolerated (the pattern starts at the type name); the declarator ends at `;`, `{` (a brace
# initializer) or `=`. Kept free of a leading `(?:\w+::)*`, which makes the scan quadratic.
_DECL = {
    "guaranteed_state_store_": r"std::unique_ptr<(?:\w+::)*GuaranteedStateStore> guaranteed_state_store_ ?[;{=]",
    "baseline_store_": r"std::unique_ptr<(?:\w+::)*BaselineStore> baseline_store_ ?[;{=]",
    "guardian_reconcile_budget_": r"(?<!\w)GuardianReconcileBudget guardian_reconcile_budget_ ?[;{=]",
    "guardian_reconcile_gate_": r"(?<!\w)GuardianReconcileGate guardian_reconcile_gate_ ?[;{=]",
    "guardian_generation_cache_": r"(?<!\w)GuardianGenerationCache guardian_generation_cache_ ?[;{=]",
    "guardian_rule_bundle_cache_": r"(?<!\w)GuardianRuleBundleCache guardian_rule_bundle_cache_ ?[;{=]",
    "heartbeat_ingestion_": r"std::unique_ptr<(?:\w+::)*HeartbeatIngestion> heartbeat_ingestion_ ?[;{=]",
}
_GUARDIAN_MEMBERS = ("guardian_reconcile_budget_", "guardian_reconcile_gate_",
                     "guardian_generation_cache_", "guardian_rule_bundle_cache_")
# (earlier, later): every pair must be declared in this order.
_DECL_ORDER = ([("guardian_reconcile_budget_", "guardian_reconcile_gate_")] +
               [(m, "heartbeat_ingestion_") for m in _GUARDIAN_MEMBERS] +
               [(st, c) for st in ("guaranteed_state_store_", "baseline_store_")
                for c in ("guardian_generation_cache_", "guardian_rule_bundle_cache_")])


def declaration_order_problems(t):
    """(aa) the member declaration order the flow's lifetime depends on."""
    out, at = [], {}
    for name, pat in _DECL.items():
        hits = [m.start() for m in re.finditer(pat, t)]
        if len(hits) != 1:
            out.append(f"server.cpp no longer declares {name} exactly once (found {len(hits)}): the "
                       f"declaration order of the reconcile members cannot be checked (aa)")
        else:
            at[name] = hits[0]
    for first, second in _DECL_ORDER:
        if first in at and second in at and not at[first] < at[second]:
            out.append(f"{first} is declared AFTER {second}: members are destroyed in reverse "
                       f"declaration order, so {first} would be destroyed while {second} can still "
                       f"reach it (aa)")
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
                   "GuardianReconcileFlow::run, a second copy would drift from the unit-tested flow (t)")
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

    # (z) ONE owner for "drop the reconcile caches": the wrapper member holds BOTH direct calls and
    # nothing else in server.cpp makes a direct call, so a hook or the fan-out that forgets one cache,
    # or repeats the pair instead of calling the wrapper, is red.
    wrap_calls = r"(?:this ?-> ?)?invalidate_guardian_reconcile_caches\( ?\) ?;"
    wrappers = [m.end() - 1 for m in re.finditer(r"\bvoid invalidate_guardian_reconcile_caches\( ?\) ?\{", t)]
    if len(wrappers) != 1:
        out.append("server.cpp no longer defines exactly one invalidate_guardian_reconcile_caches() member (z)")
    else:
        wend = match_close(t, wrappers[0], "{", "}")
        wbody = "" if wend < 0 else t[wrappers[0]:wend + 1]
        for cache in ("guardian_generation_cache_", "guardian_rule_bundle_cache_"):
            if not re.search(r"\b" + cache + r" ?\. ?invalidate\( ?\) ?;", wbody):
                out.append(f"invalidate_guardian_reconcile_caches() no longer calls {cache}.invalidate() (z)")
    for cache in ("guardian_generation_cache_", "guardian_rule_bundle_cache_"):
        n = len(re.findall(r"\b" + cache + r" ?\. ?invalidate\( ?\)", t))
        if n != 1:
            out.append(f"{cache}.invalidate() is called {n} times in server.cpp: only the wrapper may call it, "
                       f"every writer calls invalidate_guardian_reconcile_caches() (z)")
    braces = [(m.start(), m.group()) for m in re.finditer(r"[{}]", t)]

    # (p)/(y) the fan-out: ONE wrapper call at the lambda's own depth, scope parsed first, wrapper before the
    # generation read.
    push_fn = re.search(r"\bguardian_push_fn_ = \[this\]\([^)]*\) -> int ?\{", t)
    push_body = None
    if push_fn:
        close = match_close(t, push_fn.end() - 1, "{", "}")
        push_body = None if close < 0 else t[push_fn.end() - 1:close + 1]
    if push_body is None:
        out.append("could not isolate the guardian_push_fn_ lambda body (p)")
    else:
        calls = list(re.finditer(wrap_calls, push_body))
        parses = list(re.finditer(r"\bscope::parse\( ?scope ?\)", push_body))
        gen_read = re.search(r"\bcurrent_policy_generation\(", push_body)
        if len(calls) != 1:
            out.append("guardian_push_fn_ no longer calls invalidate_guardian_reconcile_caches() exactly once (p)")
        else:
            depth = push_body[:calls[0].start()].count("{") - push_body[:calls[0].start()].count("}")
            if depth != 1:
                out.append("the guardian_push_fn_ cache invalidation is nested inside a branch or lambda (depth "
                           f"{depth}, want 1): it must run on every path that reaches the reads (p)")
            head = push_body[:calls[0].start()]
            stmt_start = max(head.rfind(";"), head.rfind("{"), head.rfind("}"))
            if re.search(r"\b(?:if|else|for|while|switch)\b|\?", head[stmt_start + 1:]):
                out.append("the guardian_push_fn_ cache invalidation is the body of a conditional statement: it must "
                           "run on every path that reaches the reads (p)")
        cond = re.search(r"\bstd::optional<yuzu::scope::Expression> parsed_scope ?; ?if ?\( ?! ?scope\. ?empty\( ?\) ?&& ?"
                         r"! ?\( ?scope\. ?starts_with\( ?\"group_\" ?\) ?&& ?mgmt_group_store_ ?\) ?\) ?\{", push_body)
        if not cond:
            out.append("the hoisted explicit-scope parse is no longer guarded by exactly "
                       "`if (!scope.empty() && !(scope.starts_with(\"group:\") && mgmt_group_store_))` (y)")
        if len(parses) != 1:
            out.append("guardian_push_fn_ no longer parses the explicit scope exactly once up front "
                       "(scope::parse(scope)) (y)")
        else:
            refuse = (r"scope::parse\( ?scope ?\) ?; ?if ?\( ?(?:! ?\w+(?: ?\. ?has_value\( ?\))?|\w+ ?\. ?has_value\( ?\) ?== ?false) ?\) ?"
                      r"(?:\{ ?)?return -1 ?; ?(?:\} ?)?\w+ ?= ?std::move\( ?\* ?\w+ ?\) ?;")
            if not re.search(refuse, push_body[parses[0].start():]):
                out.append("guardian_push_fn_ no longer refuses an unparseable scope with `return -1` right "
                           "after parsing it (y)")
            if cond and not cond.start() < parses[0].start():
                out.append("the scope parse is not inside its guarding condition (y)")
        if calls and parses and not parses[0].start() < calls[0].start():
            out.append("the guardian_push_fn_ cache invalidation runs BEFORE the scope parse: an invalid-scope "
                       "push would withhold every in-flight reconcile for nothing (y)")
        if calls and gen_read and not calls[-1].start() < gen_read.start():
            out.append("the guardian_push_fn_ cache invalidation no longer comes BEFORE the generation read (y)")

    # (v)/(x) the two post-mutation hooks: each wired exactly once, with a lambda that does nothing but call the
    # wrapper, not under a dead condition; and cleared again at stop() time.
    for setter, what, letter in (("set_on_rule_mutation", "GuaranteedStateStore::set_on_rule_mutation", "(v)"),
                                 ("set_on_baseline_mutation", "BaselineStore::set_on_baseline_mutation", "(x)")):
        hooks = [m.end() - 1 for m in re.finditer(r"\b" + setter + r"\((?= ?\[)", t)]
        if len(hooks) != 1:
            out.append(f"server.cpp no longer wires exactly one {what}( lambda {letter}")
        else:
            end = match_close(t, hooks[0], "(", ")")
            arg = "" if end < 0 else t[hooks[0] + 1:end]
            body = block_after(arg, "]") or ""
            if not re.search(r"^\{ ?" + wrap_calls + r" ?\}$", body.strip()):
                out.append(f"the {setter} lambda no longer does exactly "
                           f"{{ invalidate_guardian_reconcile_caches(); }} {letter}")
            if under_dead_condition(t, braces, hooks[0]):
                out.append(f"the {setter} wiring sits under a dead condition {letter}")
        clears = [m.start() for m in re.finditer(r"\b" + setter + r"\( ?\{ ?\} ?\) ?;", t)]
        if len(clears) != 1:
            out.append(f"server.cpp no longer clears the {setter} hook exactly once at stop() time (it captures "
                       f"`this`) {letter}")
        elif under_dead_condition(t, braces, clears[0]):
            out.append(f"the {setter}({{}}) clear sits under a dead condition {letter}")
    preseed = [m.start() for m in re.finditer(r'metrics_\.counter\( ?"yuzu_server_guardian_reconcile_invalidated_total" ?\) ?;', t)]
    if len(preseed) != 1:
        out.append("yuzu_server_guardian_reconcile_invalidated_total is no longer pre-seeded exactly once (x)")
    elif under_dead_condition(t, braces, preseed[0]):
        out.append("the yuzu_server_guardian_reconcile_invalidated_total pre-seed sits under a dead condition (x)")

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
    ("every kind's detail reaches the audit row and the log",
     _wsub("eval.error().kind == ScopeEvalError::Kind::StoreDegraded && !eval.error().detail.empty()",
           "!eval.error().detail.empty()"), "(f)"),
    ("only StoreDegraded aborts again (every other kind is a member decision)",
     _sub("eval.error().kind != ScopeEvalError::Kind::Unresolvable",
          "eval.error().kind == ScopeEvalError::Kind::StoreDegraded"), "(f)"),
    ("every error kind is not-a-member (Unresolvable test inverted)",
     _sub("eval.error().kind != ScopeEvalError::Kind::Unresolvable",
          "eval.error().kind == ScopeEvalError::Kind::Unresolvable"), "(f)"),
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
     _resub(r"(Decision::Converged:(?:(?!\bcase\b).)*?)\breturn;", r"\1(void)0;"), "(j)"),
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
     _after("auto abort_degraded = [", "audit_abort(what, err);", "(void)0;"), "(m)"),
    ("the shared audit helper stops auditing",
     _after("auto audit_abort = [", "audit_(ev);", "(void)0;"), "(m)"),
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
SERVER_LETTERS = ("(i)", "(p)", "(q)", "(v)", "(x)", "(y)", "(z)")
# (aa) is over server.cpp too, but it is checked by declaration_order_problems alone (not part of
# problems()), in the light half, so its mutations (ORDER_MUTATIONS, below) stay out of this
# lettered list and out of the heavy full-problems() sweep.

# (w) the bundle epoch check.
EPOCH_READ = "const auto bundle_epoch = guardian_rule_bundle_cache_.epoch();"
ABORT_INV = r'abort_invalidated\("rule bundle invalidated during load",.*?retried on a later heartbeat"\);'
MUTATIONS += [
    ("bundle epoch no longer read", _sub(EPOCH_READ, "const std::uint64_t bundle_epoch = 0;"), "(w)"),
    ("bundle epoch read after the fresh generation read",
     lambda s: _sub(EPOCH_READ, "")(s).replace(
         "const std::uint64_t fresh_generation = *fresh_res;",
         "const std::uint64_t fresh_generation = *fresh_res; " + EPOCH_READ, 1), "(w)"),
    ("bundle epoch comparison dropped",
     _sub("guardian_rule_bundle_cache_.epoch() != bundle_epoch", "false"), "(w)"),
    ("bundle epoch comparison inverted",
     _sub("guardian_rule_bundle_cache_.epoch() != bundle_epoch", "guardian_rule_bundle_cache_.epoch() == bundle_epoch"), "(w)"),
    ("changed bundle epoch no longer aborts",
     _resub(ABORT_INV, "(void)0;"), "(w)"),
    ("changed bundle epoch aborts but no longer returns",
     _resub("(" + ABORT_INV + r")\s*return;", r"\1"), "(w)"),
    ("changed bundle epoch aborts through abort_degraded (counts as a store failure)",
     _resub(r'abort_invalidated\("rule bundle invalidated during load"', 'abort_degraded("rule bundle invalidated during load"'), "(w)"),
    ("abort_invalidated counts result=degraded instead of its own counter",
     _after("auto abort_invalidated = [", '"yuzu_server_guardian_reconcile_invalidated_total"',
            '"yuzu_server_guardian_reconciles_total", {{"result", "degraded"}}'), "(w)"),
    ("abort_invalidated also counts result=degraded",
     _after("auto abort_invalidated = [", "audit_abort(what, err);",
            'metrics_.counter("yuzu_server_guardian_reconciles_total", {{"result", "degraded"}}).increment(); audit_abort(what, err);'), "(w)"),
    ("abort_invalidated stops auditing",
     _after("auto abort_invalidated = [", "audit_abort(what, err);", "(void)0;"), "(w)"),
    ("bundle epoch check moved after the send",
     lambda s: (lambda m: s[:m.start()] + s[m.end():])(
         re.search(r"if \(guardian_rule_bundle_cache_\.epoch\(\) != bundle_epoch\) \{.*?return;  // send NOTHING[^\n]*\n\s*\}",
                   s, re.S)).replace(
         "if (send_push_(agent_id, command_id, push.SerializeAsString())) {",
         "if (send_push_(agent_id, command_id, push.SerializeAsString())) { if (guardian_rule_bundle_cache_.epoch() != bundle_epoch) { abort_invalidated(\"rule bundle invalidated during load\", \"x\"); return; }", 1), "(w)"),
]

# (v)/(x)/(y)/(z): the cache-invalidation owner, both hooks and the push fan-out ordering (server.cpp).
WRAPPER_CALL = "invalidate_guardian_reconcile_caches();"
RULE_HOOK = "set_on_rule_mutation( [this] { invalidate_guardian_reconcile_caches(); });"
BASE_HOOK = "set_on_baseline_mutation( [this] { invalidate_guardian_reconcile_caches(); });"
GEN_DIRECT = "guardian_generation_cache_.invalidate();"
BUN_DIRECT = "guardian_rule_bundle_cache_.invalidate();"
PUSH_ANCHOR = "                invalidate_guardian_reconcile_caches();\n                const auto now_s"
def _scope_parse_block(s):
    m = re.search(r"[ \t]*std::optional<yuzu::scope::Expression> parsed_scope;.*?parsed_scope = std::move\(\*parsed\);\n\s*\}\n", s, re.S)
    assert m, "scope parse block not found (stale pattern)"
    return s[:m.start()] + s[m.end():], m.group(0)
def _invalidate_before_parse(s):
    s, blk = _scope_parse_block(s)
    anchor = "                invalidate_guardian_reconcile_caches();\n"
    i = s.index(anchor, s.index("guardian_push_fn_ = [this]"))
    return s[:i + len(anchor)] + blk + s[i + len(anchor):]
def _invalidate_after_generation_read(s):
    anchor = "                invalidate_guardian_reconcile_caches();\n"
    i = s.index(anchor, s.index("guardian_push_fn_ = [this]"))
    s = s[:i] + s[i + len(anchor):]
    j = s.index("const std::uint64_t generation = *generation_opt;", i)
    return s[:j] + anchor + s[j:]
def _wrapper_body_sub(old, new):
    def mut(s):
        i = s.index("void invalidate_guardian_reconcile_caches() {")
        j = s.index(old, i)
        return s[:j] + new + s[j + len(old):]
    return mut
MUTATIONS += [
    # (z) the wrapper
    ("wrapper forgets the generation cache", _wrapper_body_sub(GEN_DIRECT, "(void)0;"), "(z)"),
    ("wrapper forgets the rule bundle cache", _wrapper_body_sub(BUN_DIRECT, "(void)0;"), "(z)"),
    ("wrapper is split in two (a second direct call appears elsewhere)",
     lambda s: s + "\nvoid again() { guardian_generation_cache_.invalidate(); }\n", "(z)"),
    # (v) rule hook
    ("rule-mutation hook is never wired", _wsub(RULE_HOOK, "(void)0;"), "(v)"),
    ("rule-mutation hook repeats the pair instead of calling the wrapper",
     _wsub(RULE_HOOK, "set_on_rule_mutation( [this] { " + GEN_DIRECT + " " + BUN_DIRECT + " });"), "(v)"),
    ("rule-mutation hook calls only one cache directly",
     _wsub(RULE_HOOK, "set_on_rule_mutation( [this] { " + GEN_DIRECT + " });"), "(v)"),
    ("rule-mutation hook calls the wrapper only conditionally",
     _wsub(RULE_HOOK, "set_on_rule_mutation( [this] { if (cfg_.guardian_reconcile_max_per_s > 0) invalidate_guardian_reconcile_caches(); });"), "(v)"),
    ("rule-mutation hook is no longer cleared at stop()",
     _sub("guaranteed_state_store_->set_on_rule_mutation({}); // hook captures `this` (#5513)", "(void)0;"), "(v)"),
    ("rule-mutation hook wiring under if (false)", _wsub("guaranteed_state_store_->" + RULE_HOOK, "if (false) guaranteed_state_store_->" + RULE_HOOK), "(v)"),
    # (x) baseline hook, counter pre-seed
    ("baseline-mutation hook is never wired", _wsub(BASE_HOOK, "(void)0;"), "(x)"),
    ("baseline-mutation hook repeats the pair instead of calling the wrapper",
     _wsub(BASE_HOOK, "set_on_baseline_mutation( [this] { " + GEN_DIRECT + " " + BUN_DIRECT + " });"), "(x)"),
    ("baseline-mutation hook calls only the rule bundle cache directly",
     _wsub(BASE_HOOK, "set_on_baseline_mutation( [this] { " + BUN_DIRECT + " });"), "(x)"),
    ("baseline-mutation hook is no longer cleared at stop()",
     _sub("baseline_store_->set_on_baseline_mutation({}); // hook captures `this` (#5513)", "(void)0;"), "(x)"),
    ("baseline-mutation hook wiring under if (false)", _wsub("baseline_store_->" + BASE_HOOK, "if (false) baseline_store_->" + BASE_HOOK), "(x)"),
    ("invalidated counter no longer pre-seeded",
     _sub('metrics_.counter("yuzu_server_guardian_reconcile_invalidated_total");', "(void)0;"), "(x)"),
    ("invalidated counter pre-seed under if (false)",
     _sub('metrics_.counter("yuzu_server_guardian_reconcile_invalidated_total");',
          'if (false) metrics_.counter("yuzu_server_guardian_reconcile_invalidated_total");'), "(x)"),
    # (p)/(y) the fan-out
    ("push fan-out stops dropping the caches", _sub(PUSH_ANCHOR, "                const auto now_s"), "(p)"),
    ("push fan-out repeats the pair instead of calling the wrapper",
     _sub(PUSH_ANCHOR, "                " + GEN_DIRECT + " " + BUN_DIRECT + "\n                const auto now_s"), "(p)"),
    ("push fan-out calls the wrapper only conditionally",
     _sub(PUSH_ANCHOR, "                if (full_sync) " + WRAPPER_CALL + "\n                const auto now_s"), "(p)"),
    ("push fan-out calls the wrapper inside a nested block",
     _sub(PUSH_ANCHOR, "                { " + WRAPPER_CALL + " }\n                const auto now_s"), "(p)"),
    ("push fan-out calls the wrapper twice",
     _sub(PUSH_ANCHOR, "                " + WRAPPER_CALL + " " + WRAPPER_CALL + "\n                const auto now_s"), "(p)"),
    ("push fan-out invalidates before parsing the scope", _invalidate_before_parse, "(y)"),
    ("push fan-out invalidates after the generation read", _invalidate_after_generation_read, "(y)"),
    ("push fan-out no longer refuses an unparseable scope up front",
     _resub(r"(auto parsed = yuzu::scope::parse\(scope\);\s*)if \(!parsed\)\s*return -1;", r"\1"), "(y)"),
    ("hoisted scope parse is dead (if (false))",
     _sub("if (!scope.empty() && !(scope.starts_with(\"group:\") && mgmt_group_store_)) {", "if (false) {"), "(y)"),
    ("hoisted scope parse runs only for non-empty scopes (group: scopes parsed too)",
     _sub("if (!scope.empty() && !(scope.starts_with(\"group:\") && mgmt_group_store_)) {", "if (!scope.empty()) {"), "(y)"),
    ("hoisted scope parse always runs (an empty scope would be refused)",
     _sub("if (!scope.empty() && !(scope.starts_with(\"group:\") && mgmt_group_store_)) {", "if (true) {"), "(y)"),
]

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

# (aa) member declaration order. Each declaration as a pattern over the RAW source (so a mutation
# can cut it out whole, initializer included) and a mutation that moves one declaration to just
# after another, which must be a later one in the reviewed order.
_SRC_DECL = {
    "guaranteed_state_store_": r"[ \t]*std::unique_ptr<GuaranteedStateStore> guaranteed_state_store_;[^\n]*\n",
    "baseline_store_": r"[ \t]*std::unique_ptr<BaselineStore> baseline_store_;[^\n]*\n",
    "guardian_reconcile_budget_": r"[ \t]*GuardianReconcileBudget guardian_reconcile_budget_\{.*?\}\};\n",
    "guardian_reconcile_gate_": r"[ \t]*GuardianReconcileGate guardian_reconcile_gate_\{[^\n]*\};\n",
    "guardian_generation_cache_": r"[ \t]*GuardianGenerationCache guardian_generation_cache_\{.*?\n    \}\};\n",
    "guardian_rule_bundle_cache_": r"[ \t]*guardian::GuardianRuleBundleCache guardian_rule_bundle_cache_;\n",
    "heartbeat_ingestion_": r"[ \t]*std::unique_ptr<HeartbeatIngestion> heartbeat_ingestion_;\n",
}


def _decl_after(moved, anchor):
    """Cut the `moved` member declaration out and paste it right after `anchor`'s (which must come
    later in the source). Every token stays present, only the order changes."""
    def mut(s):
        m = re.search(_SRC_DECL[moved], s, re.S)
        a = re.search(_SRC_DECL[anchor], s, re.S)
        assert m and a and m.end() <= a.start(), "declaration pattern stale or already out of order"
        s = s[:a.end()] + m.group(0) + s[a.end():]
        return s[:m.start()] + s[m.end():]
    return mut


def _decl_before(moved, anchor):
    """Cut the `moved` member declaration out and paste it right BEFORE `anchor`'s (which must come
    earlier in the source). Every token stays present, only the order changes."""
    def mut(s):
        m = re.search(_SRC_DECL[moved], s, re.S)
        a = re.search(_SRC_DECL[anchor], s, re.S)
        assert m and a and a.start() <= m.start(), "declaration pattern stale or already out of order"
        s = s[:m.start()] + s[m.end():]
        return s[:a.start()] + m.group(0) + s[a.start():]
    return mut


def _pair(first, second):
    """The text declaration_order_problems() emits for one violated (first, second) pair."""
    return f"{first} is declared AFTER {second}:"


_GS, _BS = "guaranteed_state_store_", "baseline_store_"
_BUD, _GATE = "guardian_reconcile_budget_", "guardian_reconcile_gate_"
_GEN, _BUN, _HB = "guardian_generation_cache_", "guardian_rule_bundle_cache_", "heartbeat_ingestion_"

# (name, mutate, the EXACT set of findings it must produce). The check compares the whole set, so a
# pair dropped from _DECL_ORDER turns the mutation that exercises it red, whichever other pairs the
# same move also violates. Source order: gs, bs, budget, gate, generation cache, bundle cache, hb.
ORDER_MUTATIONS = [
    ("budget declared after the gate that references it",
     _decl_after(_BUD, _GATE), [_pair(_BUD, _GATE)]),
    ("budget declared after heartbeat_ingestion_",
     _decl_after(_BUD, _HB), [_pair(_BUD, _HB), _pair(_BUD, _GATE)]),
    ("gate declared after heartbeat_ingestion_",
     _decl_after(_GATE, _HB), [_pair(_GATE, _HB)]),
    ("generation cache declared after heartbeat_ingestion_",
     _decl_after(_GEN, _HB), [_pair(_GEN, _HB)]),
    ("rule bundle cache declared after heartbeat_ingestion_",
     _decl_after(_BUN, _HB), [_pair(_BUN, _HB)]),
    ("guaranteed-state store declared after the generation cache",
     _decl_after(_GS, _GEN), [_pair(_GS, _GEN)]),
    ("guaranteed-state store declared after the rule bundle cache",
     _decl_after(_GS, _BUN), [_pair(_GS, _GEN), _pair(_GS, _BUN)]),
    ("baseline store declared after the generation cache",
     _decl_after(_BS, _GEN), [_pair(_BS, _GEN)]),
    ("baseline store declared after the rule bundle cache",
     _decl_after(_BS, _BUN), [_pair(_BS, _GEN), _pair(_BS, _BUN)]),
    # The bundle cache moves ABOVE the stores while the generation cache stays put, so only the
    # (store, bundle cache) pairs fire; moving a store below the bundle cache also moves it below
    # the generation cache, which is why these two have their own mutations.
    ("rule bundle cache declared above both stores (generation cache unmoved)",
     _decl_before(_BUN, _GS), [_pair(_GS, _BUN), _pair(_BS, _BUN)]),
    ("rule bundle cache declared between the stores (generation cache unmoved)",
     _decl_before(_BUN, _BS), [_pair(_BS, _BUN)]),
    ("heartbeat_ingestion_ declaration renamed away (order cannot be checked)",
     _sub("std::unique_ptr<HeartbeatIngestion> heartbeat_ingestion_;",
          "std::unique_ptr<HeartbeatIngestion> heartbeat_ingestion_x_;"),
     ["no longer declares heartbeat_ingestion_ exactly once (found 0)"]),
    ("heartbeat_ingestion_ declared twice",
     _sub("std::unique_ptr<HeartbeatIngestion> heartbeat_ingestion_;",
          "std::unique_ptr<HeartbeatIngestion> heartbeat_ingestion_;\n    std::unique_ptr<HeartbeatIngestion> heartbeat_ingestion_;"),
     ["no longer declares heartbeat_ingestion_ exactly once (found 2)"]),
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
    ("flow constructed with a different generation cache",
     _sub(".generation_cache = guardian_generation_cache_,", ".generation_cache = other_cache_,"), "(t)"),
    ("flow constructed with a different metrics registry",
     _sub(".metrics = metrics_,", ".metrics = other_metrics_,"), "(t)"),
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

BENIGN_FLOW += [
    # (w) tolerated spellings of the epoch pin: they do not change what it does.
    ("(w) bundle_epoch spelled with std::uint64_t and a this-> prefix",
     _sub(EPOCH_READ, "const std::uint64_t bundle_epoch = this->guardian_rule_bundle_cache_.epoch();")),
    ("(w) epoch comparison with swapped operands",
     _sub("guardian_rule_bundle_cache_.epoch() != bundle_epoch", "bundle_epoch != guardian_rule_bundle_cache_.epoch()")),
    ("(w) a comment and a string that merely mention the abort and the epoch",
     _sub("bool scope_degraded = false;",
          'bool scope_degraded = false; // abort_degraded("rule bundle invalidated during load") if epoch() != bundle_epoch\n'
          ' const char* note = "guardian_rule_bundle_cache_.epoch() != bundle_epoch";')),
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
    ("rule-mutation hook calling the wrapper through this->",
     _wafter("set_on_rule_mutation(",
             "invalidate_guardian_reconcile_caches();", "this->invalidate_guardian_reconcile_caches();")),
    ("baseline-mutation hook calling the wrapper through this->",
     _wafter("set_on_baseline_mutation(",
             "invalidate_guardian_reconcile_caches();", "this->invalidate_guardian_reconcile_caches();")),
    # (y) tolerated spellings of the scope refusal.
    ("scope refusal braced",
     _resub(r"if \(!parsed\)\s*return -1;", "if (!parsed) { return -1; }")),
    ("scope refusal braced and split over lines",
     _resub(r"if \(!parsed\)\s*return -1;", "if (!parsed)\n {\n return -1;\n }")),
    ("scope refusal through has_value()",
     _resub(r"if \(!parsed\)\s*return -1;", "if (!parsed.has_value()) return -1;")),
    ("scope refusal through has_value() == false",
     _resub(r"if \(!parsed\)\s*return -1;", "if (parsed.has_value() == false) return -1;")),
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


# (aa) must accept a declaration that is reflowed or only mentioned in a comment or string. Checked
# through declaration_order_problems alone, like ORDER_MUTATIONS.
BENIGN_ORDER = [
    ("heartbeat_ingestion_ declaration split over two lines",
     _sub("std::unique_ptr<HeartbeatIngestion> heartbeat_ingestion_;",
          "std::unique_ptr<HeartbeatIngestion>\n        heartbeat_ingestion_;")),
    ("a comment and a string mention a heartbeat_ingestion_ declaration before the guardian members",
     _sub("GuardianReconcileBudget guardian_reconcile_budget_{",
          "// std::unique_ptr<HeartbeatIngestion> heartbeat_ingestion_;\n"
          "    const char* kNote = \"std::unique_ptr<HeartbeatIngestion> heartbeat_ingestion_;\";\n"
          "    GuardianReconcileBudget guardian_reconcile_budget_{")),
]


def _upd_without_notify(s):
    i = s.index("std::expected<void, std::string> BaselineStore::update_baseline")
    j = s.index("notify_baseline_mutation();", i)
    return s[:j] + "(void)0;" + s[j + len("notify_baseline_mutation();"):]


def _delete_without_notify(s):
    i = s.index("std::expected<void, std::string> BaselineStore::delete_baseline")
    j = s.index("notify_baseline_mutation();", i)
    return s[:j] + "(void)0;" + s[j + len("notify_baseline_mutation();"):]


def _in_fn(fn_marker, old, new):
    def mut(s):
        i = s.index(fn_marker)
        j = s.index(old, i)
        return s[:j] + new + s[j + len(old):]
    return mut


UPD = "std::expected<void, std::string> BaselineStore::update_baseline"
CRE = "std::expected<std::string, std::string> BaselineStore::create_baseline"
LEASE_NOTIFY = "lease.reset(); // no pool lease held while the hook runs\n    notify_baseline_mutation();"
BASELINE_WRITER_MUTATIONS = [
    ("a return before the deployed block makes create_baseline's notify unreachable",
     _in_fn(CRE, "    if (lifecycle == kBaselineDeployed) {\n        lease.reset();", "    return id;\n    if (lifecycle == kBaselineDeployed) {\n        lease.reset();"), "(bw)"),
    ("a return before the notify makes update_baseline's notify unreachable",
     _in_fn(UPD, LEASE_NOTIFY, "lease.reset();\n    return {};\n    notify_baseline_mutation();"), "(bw)"),
    ("update_baseline announces the change before the write",
     _in_fn(UPD, "    if (!open_)", "    notify_baseline_mutation();\n    if (!open_)"), "(bw)"),
    ("update_baseline fires the hook before releasing the lease",
     _in_fn(UPD, LEASE_NOTIFY, "notify_baseline_mutation();\n    lease.reset();"), "(bw)"),
    ("update_baseline fires the hook under if (false)",
     _in_fn(UPD, LEASE_NOTIFY, "lease.reset();\n    if (false) notify_baseline_mutation();"), "(bw)"),
    ("update_baseline fires the hook only for some updates",
     _in_fn(UPD, LEASE_NOTIFY, "lease.reset();\n    if (b.lifecycle == kBaselineDeployed) notify_baseline_mutation();"), "(bw)"),
    ("update_baseline fires the hook inside a nested block",
     _in_fn(UPD, LEASE_NOTIFY, "lease.reset();\n    { notify_baseline_mutation(); }"), "(bw)"),
    ("a deployed create_baseline no longer fires the hook",
     _in_fn(CRE, "    if (lifecycle == kBaselineDeployed) {\n        lease.reset(); // no pool lease held while the hook runs\n        notify_baseline_mutation();\n    }\n", ""), "(bw)"),
    ("create_baseline fires the hook for every create (drafts too)",
     _in_fn(CRE, "    if (lifecycle == kBaselineDeployed) {\n        lease.reset(); // no pool lease held while the hook runs\n        notify_baseline_mutation();\n    }\n",
            "    lease.reset();\n    notify_baseline_mutation();\n"), "(bw)"),
    ("create_baseline fires the hook before releasing the lease",
     _in_fn(CRE, "        lease.reset(); // no pool lease held while the hook runs\n        notify_baseline_mutation();", "        notify_baseline_mutation();"), "(bw)"),
    ("create_baseline fires on the wrong condition",
     _in_fn(CRE, "if (lifecycle == kBaselineDeployed) {\n        lease.reset();", "if (lifecycle == kBaselineDraft) {\n        lease.reset();"), "(bw)"),
    ("update_baseline stops firing the hook", _upd_without_notify, "(bw)"),
    ("delete_baseline stops firing the hook", _delete_without_notify, "(bw)"),
    ("a new writer function that is not allowlisted",
     lambda s: s + """
std::expected<void, std::string> BaselineStore::undeploy_baseline(const std::string& baseline_id) {
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    pg::exec_params(lease.get(), "UPDATE baseline_store.baselines SET lifecycle = 'draft' WHERE baseline_id = $1",
                    std::vector<std::string>{baseline_id});
    return {};
}
""", "(bw)"),
    ("a writer outside every BaselineStore method",
     lambda s: s + """
static void raw_write(PGconn* c) {
    pg::exec_params(c, "DELETE FROM baseline_store.baselines", std::vector<std::string>{});
}
""", "(bw)"),
    ("set_members starts rewriting the deployed snapshot",
     _sub("UPDATE baseline_store.baselines SET updated_at = $1::bigint ",
          "UPDATE baseline_store.baselines SET deployed_snapshot = '[]', updated_at = $1::bigint "), "(bw)"),
    ("update_baseline no longer writes the table",
     _sub("UPDATE baseline_store.baselines SET name = $1", "UPDATE baseline_store.baseline_x SET name = $1"), "(bw)"),
]

BENIGN_BASELINE = [
    ("a conditional early return before the notify",
     _in_fn(UPD, LEASE_NOTIFY, "lease.reset();\n    if (b.name.empty()) return {};\n    notify_baseline_mutation();")),
    ("an early return inside a closed error block before the notify",
     _in_fn(UPD, LEASE_NOTIFY, "lease.reset();\n    if (b.name.empty()) {\n        return {};\n    }\n    notify_baseline_mutation();")),
    ("create_baseline hook condition on one line with a comment",
     _in_fn(CRE, "if (lifecycle == kBaselineDeployed) {", "if (lifecycle == kBaselineDeployed) { // deployed only\n")),
    ("a comment mentions a write and the hook",
     _sub("std::expected<void, std::string> BaselineStore::delete_baseline",
          "// UPDATE baseline_store.baselines is not issued here; notify_baseline_mutation() is.\n"
          "std::expected<void, std::string> BaselineStore::delete_baseline")),
    ("the notify call is re-wrapped and commented",
     _resub(r"notify_baseline_mutation\(\);", "notify_baseline_mutation( /* hook */ );")),
    ("a write to the member table of another name is not flagged",
     lambda s: s + """
std::size_t BaselineStore::drop_stray_members() {
    pg::exec_params(nullptr, "DELETE FROM baseline_store.baseline_rules", std::vector<std::string>{});
    return 0;
}
"""),
    ("the delete statement is reflowed over two literals",
     _sub('lease.get(), "DELETE FROM baseline_store.baselines WHERE baseline_id = $1 RETURNING baseline_id",',
          'lease.get(), "DELETE FROM baseline_store.baselines "\n "WHERE baseline_id = $1 RETURNING baseline_id",')),
]


# The sweep over every server.cpp wiring mutation costs most of the run (about 10 s of 13), so CI runs
# this file as two meson tests, LEXICAL_GATE_PART=light (everything else) and LEXICAL_GATE_PART=heavy
# (that sweep), each under the 30 s budget. Unset runs everything. A new test method
# lands in "light" by default, so nothing can silently fall out of both.
_HEAVY_TESTS = frozenset({"test_wiring_mutations_are_caught"})
_PART = os.environ.get("LEXICAL_GATE_PART", "all")


def heavy_names_missing(cls, names=_HEAVY_TESTS):
    """The names in `names` that are not test methods of `cls`. A renamed heavy test would otherwise
    leave the `heavy` half running zero tests and exiting 0."""
    return sorted(n for n in names if not callable(getattr(cls, n, None)))


class GuardianReconcileWiringLexical(unittest.TestCase):
    def setUp(self):
        if _PART not in ("all", "light", "heavy"):
            self.fail(f"LEXICAL_GATE_PART must be all, light or heavy, not {_PART!r}")
        missing = heavy_names_missing(type(self))
        if missing:
            self.fail(f"_HEAVY_TESTS names no such test method(s): {missing} (a rename would make the heavy "
                      f"half run nothing)")
        heavy = self._testMethodName in _HEAVY_TESTS
        if (_PART == "light" and heavy) or (_PART == "heavy" and not heavy):
            self.skipTest(f"runs in the other LEXICAL_GATE_PART (this one is {_PART})")
        self.src = SERVER_CPP.read_text(encoding="utf-8")
        self.flow_src = FLOW_HPP.read_text(encoding="utf-8")
        self.push_src = PUSH_BUILDER_CPP.read_text(encoding="utf-8")
        self.baseline_src = BASELINE_STORE_CPP.read_text(encoding="utf-8")

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

    def test_every_lettered_mutation_is_routed_to_exactly_one_source(self):
        # FLOW_MUTATIONS is defined as the complement of SERVER_LETTERS, so the routing cannot be
        # checked against it. These three sets are written out independently: a NEW letter must be
        # added to exactly one of them by hand (this test is red until it is), which is what stops a
        # mutation being run against the wrong file or silently skipped.
        flow_set = {"(a)", "(b)", "(c)", "(d)", "(e)", "(f)", "(g)", "(h)", "(j)", "(k)", "(l)", "(m)",
                    "(n)", "(o)", "(r)", "(s)", "(w)"}
        server_set = {"(i)", "(p)", "(q)", "(v)", "(x)", "(y)", "(z)"}
        self.assertEqual(flow_set & server_set, set())
        self.assertEqual({m[2] for m in MUTATIONS}, flow_set | server_set)
        self.assertEqual({m[2] for m in FLOW_MUTATIONS}, flow_set)
        self.assertEqual(set(SERVER_LETTERS), server_set)
        # The (aa) order mutations are a separate list, not lettered; each is asserted to produce exactly the findings it lists.
        self.assertTrue(ORDER_MUTATIONS)
        flow_letters = {m[2] for m in FLOW_MUTATIONS}
        direct = {m[2] for m in SERVER_MUTATIONS} - set(SERVER_LETTERS)  # appended to SERVER_MUTATIONS directly
        self.assertTrue(direct)
        self.assertEqual(direct & (flow_letters - {"(o)"}), set())  # (o) has a mutation in each source

    def test_declaration_order_is_clean(self):
        self._check_clean(declaration_order_problems(lex(self.src)))

    def test_benign_declaration_text_is_not_flagged(self):
        for name, mutate in BENIGN_ORDER:
            with self.subTest(benign=name):
                mutated = mutate(self.src)
                self.assertNotEqual(mutated, self.src, "benign edit changed nothing (stale pattern)")
                self.assertEqual(declaration_order_problems(lex(mutated)), [])

    def test_declaration_order_mutations_are_caught(self):
        # Each mutation must produce EXACTLY the findings it lists (one per violated pair, each naming
        # the pair), so removing a pair from _DECL_ORDER cannot hide behind another pair that the same
        # move also violates.
        for name, mutate, expected in ORDER_MUTATIONS:
            with self.subTest(mutation=name):
                mutated = mutate(self.src)
                self.assertNotEqual(mutated, self.src, "mutation changed nothing (stale pattern)")
                got = declaration_order_problems(lex(mutated))
                self.assertEqual(len(got), len(expected), got)
                for fragment in expected:
                    self.assertEqual(sum(fragment in g for g in got), 1, (fragment, got))

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

    def test_the_heavy_half_names_real_tests(self):
        self.assertTrue(_HEAVY_TESTS)  # emptying it must not pass vacuously
        self.assertEqual(heavy_names_missing(type(self)), [])
        # The check itself: a name that is not a test method is reported.
        self.assertEqual(heavy_names_missing(type(self), {"test_wiring_mutations_are_caught", "test_renamed"}),
                         ["test_renamed"])

    def test_baseline_writers_are_clean(self):
        self._check_clean(baseline_writer_problems(self.baseline_src))

    def test_baseline_writer_mutations_are_caught(self):
        self._check_caught(BASELINE_WRITER_MUTATIONS, self.baseline_src, baseline_writer_problems)

    def test_benign_baseline_text_is_not_flagged(self):
        for name, mutate in BENIGN_BASELINE:
            with self.subTest(benign=name):
                mutated = mutate(self.baseline_src)
                self.assertNotEqual(mutated, self.baseline_src, "benign edit changed nothing (stale pattern)")
                self.assertEqual(baseline_writer_problems(mutated), [])

    def test_a_commented_out_decide_does_not_satisfy_the_gate(self):
        # Comment stripping must remove the call entirely, not merely hide it from one regex.
        mutated = _wsub(DECIDE_SWITCH, "// " + DECIDE_SWITCH + "\n switch (GuardianReconcileGate::Decision::Admit)")(self.flow_src)
        self.assertNotEqual(mutated, self.flow_src)
        self.assertIn("(a)", "\n".join(flow_problems(mutated)))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
