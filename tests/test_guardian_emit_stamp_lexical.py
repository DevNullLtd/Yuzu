#!/usr/bin/env python3
"""UP-14 static lexical gate pinning where the Guardian wire emit pair is stamped.

Every GuaranteedStateEvent the agent daemon sends carries (boot_epoch, emit_seq), both-or-neither
(proto fields 24/25), so the server can order events by a per-boot monotonic ordinal instead of a
wall-clock timestamp. The stamp primitives are unit-tested in isolation, but nothing unit-tests
that EVERY producer calls them: a future enqueue that forgets the stamp compiles and passes, and
simply degrades that event to unordered. This gate pins the call sites lexically.

Invariants (the four numbered rules below; each failure message starts with its rule tag):

  R1  agents/core/src/guardian_spark_runtime.cpp: every production enqueue into the Spark outbox
      (`outbox_.enqueue(`, `outbox_.enqueue_all(`, `lifecycle_log_.enqueue(`,
      `lifecycle_log_.enqueue_all(`) has a `stamp_seq_locked(` token between the nearest preceding
      `outbox_mu_` lock token and the enqueue token (anchored on the lock token, never on a line
      distance). Exactly one `stamp_seq_locked(` call passes `wire_ordered=false` (the page-time
      stamp, whose seq is a hold key only and must NOT put a pair on the wire) and it sits inside
      `try_page_batch`; every other call keeps the default (live, wire-ordered).
  R2  `stamp_emit_pair(` is called only inside `offer(` in guardian_legacy_sink_executor.hpp and
      inside `set_common` in guardian_spark_send.cpp (its definition lives in
      guardian_emit_seq.hpp); the raw `set_emit_seq(` / `set_boot_epoch(` setters appear only in
      guardian_emit_seq.hpp across agents/core; `set_common` never mentions `journal_batch_key`
      (the replay discriminator is the page-time stamp, never the batch key:
      backfill_batch_provenance sets the key on LIVE entries); guardian_engine.cpp never calls
      `stamp_emit_pair(` (the legacy stamp is at executor admission only).
  R3  agents/core/src/agent.cpp: the identifier assigned from `claim_guardian_boot_epoch(` is the
      FOURTH argument of `std::make_unique<GuardianEngine>(` (third is the literal `false`) and
      the claim precedes the construction. TRIPWIRE ON KNOWN WRITERS (not a proof that no other
      serializer exists): `emit_guardian_event(` is called from exactly two places, the
      `set_event_sink` lambda and the DEX observer; a third caller is a new wire writer that
      must be reviewed for the stamp.
  R4  agents/core/src/guardian_engine.cpp: every legacy executor is built through
      `make_legacy_sink_executor(` (no direct `make_unique<GuardianLegacySinkExecutor>` outside
      that helper, every `legacy_sink_executor_` init/assign goes through it), the helper copies
      the engine's `emit_seq_source_` into the Config, and `wire_spark_engine` assigns
      `emit_seq_source` into the runtime Config before the runtime is constructed.

Robustness: comments (`//`, `/* */`), string literals, raw strings and char literals are removed
and whitespace is collapsed before matching, so line wrapping, re-indentation and a comment or
string mentioning a token can neither satisfy nor trip a rule. Function-body scoping uses
balanced brackets on the stripped text. Patterns anchor on distinctive tokens, never line numbers.

Lexical only: it cannot see a relocation that keeps the tokens but changes control flow
(review-enforced), and it does not prove stamp CORRECTNESS (the Catch2 suites do that). The
self-test applies in-memory mutations of the committed sources, one or more per rule, plus
comment/string-stripping proofs, and requires problems() to report each; a mutation whose
pattern no longer matches fails loudly (stale pattern) rather than passing vacuously.

Python, not bash: a source-text gate is one process (docs/testing/unit-test-conventions.md).

Usage: python3 tests/test_guardian_emit_stamp_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "agents" / "core"
TAG = "test_guardian_emit_stamp_lexical"
HINT = (
    " (this gate pins the UP-14 emit-pair stamp sites; if the sources were legitimately"
    " restructured, update tests/test_guardian_emit_stamp_lexical.py)"
)

# Keys are paths relative to agents/core, posix style.
RUNTIME = "src/guardian_spark_runtime.cpp"
EXECUTOR = "src/guardian_legacy_sink_executor.hpp"
SEND = "src/guardian_spark_send.cpp"
EMIT_SEQ = "src/guardian_emit_seq.hpp"
ENGINE = "src/guardian_engine.cpp"
AGENT = "src/agent.cpp"
REQUIRED = (RUNTIME, EXECUTOR, SEND, EMIT_SEQ, ENGINE, AGENT)

_SCAN_SUFFIXES = {".cpp", ".hpp", ".h", ".cc", ".mm", ".m"}

# Longest-first alternation; the leftmost match wins, so a quote inside a comment or a comment
# marker inside a string is consumed by whichever construct starts first.
_STRIP = re.compile(
    r"""
      //[^\n]*(?:\\\n[^\n]*)*                              # line comment (with continuations)
    | /\*.*?\*/                                            # block comment
    | (?<![A-Za-z0-9_])(?:u8|u|U|L)?R"(?P<d>[^()\\\s]{0,16})\(.*?\)(?P=d)"   # raw string
    | "(?:\\.|[^"\\\n])*"                                  # string literal
    | (?<![0-9A-Fa-f_])'(?:\\.|[^'\\\n])+'                 # char literal (not a digit separator)
    """,
    re.S | re.X,
)


def _blank(m):
    s = m.group(0)
    if s.startswith("/"):
        return " "
    if s.endswith("'"):
        return "''"
    return '""'


def normalise(src):
    """Strip comments and string/char literals, collapse whitespace, trim spaces at punctuation."""
    t = _STRIP.sub(_blank, src)
    t = re.sub(r"[ \t\n\r\f\v]+", " ", t)
    return re.sub(r" ?([(){};,]) ?", r"\1", t)


def match_close(t, i):
    """Index of the bracket closing t[i] ('(' or '{'), or -1."""
    op = t[i]
    cl = {"(": ")", "{": "}"}[op]
    depth = 0
    for j in range(i, len(t)):
        c = t[j]
        if c == op:
            depth += 1
        elif c == cl:
            depth -= 1
            if depth == 0:
                return j
    return -1


def split_args(s):
    """Split a call's argument text on top-level commas."""
    out, depth, cur = [], 0, []
    for c in s:
        if c in "({[":
            depth += 1
        elif c in ")}]":
            depth -= 1
        if c == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    if cur or out:
        out.append("".join(cur))
    return out


def call_sites(t, pattern):
    """(start, args_start, args_end) for every `pattern(` occurrence; args exclude the parens."""
    out = []
    for m in re.finditer(pattern + r"\(", t):
        op = m.end() - 1
        cp = match_close(t, op)
        if cp >= 0:
            out.append((m.start(), op + 1, cp))
    return out


_DEF_TAIL = re.compile(r"(?: ?(?:const|noexcept|override|final|&&|&))*(?: ?->[^{;]*)? ?\{")


def function_bodies(t, name):
    """(body_start, body_end) of every DEFINITION of a function called `name` (qualified or not).

    A call such as `name(x);` or `if (name(x)) {` is not a definition: only a parameter list
    followed (after optional qualifiers) directly by `{` counts.
    """
    out = []
    for (start, a0, a1) in call_sites(t, r"(?<![A-Za-z0-9_])" + re.escape(name)):
        m = _DEF_TAIL.match(t, a1 + 1)
        if not m:
            continue
        ob = m.end() - 1
        cb = match_close(t, ob)
        if cb >= 0:
            out.append((ob + 1, cb))
    return out


def _inside(pos, ranges):
    return any(a <= pos < b for (a, b) in ranges)


# A guard on the outbox mutex, or an explicit lock() on it.
_LOCK = re.compile(
    r"(?:lock_guard|unique_lock|scoped_lock)(?:<[^>]*>)? \w+[{(]outbox_mu_[})]"
    r"|(?<![A-Za-z0-9_])outbox_mu_\.lock\(\)"
)
_ENQ = re.compile(r"(?<![A-Za-z0-9_])(?:outbox_|lifecycle_log_)\.enqueue(?:_all)?\(")
_STAMP_SEQ = r"(?<![A-Za-z0-9_])stamp_seq_locked"


def _rule1(t, out):
    locks = [m.end() for m in _LOCK.finditer(t)]
    enqs = list(_ENQ.finditer(t))
    if len(enqs) < 5:
        out.append(f"R1: found only {len(enqs)} outbox/lifecycle_log enqueue sites in {RUNTIME}"
                   " (expected the five known stamp sites; the gate pattern is stale)")
    for m in enqs:
        prior = [e for e in locks if e <= m.start()]
        what = m.group(0)
        if not prior:
            out.append(f"R1: {what} in {RUNTIME} has no preceding outbox_mu_ lock token")
            continue
        if "stamp_seq_locked(" not in t[prior[-1]:m.start()]:
            out.append(f"R1: {what} in {RUNTIME} is not preceded by stamp_seq_locked( between the "
                       "outbox_mu_ lock and the enqueue (an unstamped event is unordered on the wire)")

    page = function_bodies(t, "try_page_batch")
    calls = call_sites(t, _STAMP_SEQ)
    if len(calls) < 5:
        out.append(f"R1: found only {len(calls)} stamp_seq_locked( calls in {RUNTIME} (expected >= 5)")
    false_calls = []
    for (start, a0, a1) in calls:
        args = split_args(t[a0:a1])
        if len(args) == 2 and args[1] == "false":
            false_calls.append(start)
        elif len(args) != 1:
            out.append(f"R1: stamp_seq_locked({t[a0:a1]}) in {RUNTIME} must use the default "
                       "wire_ordered (live, one argument) or pass the literal false at the page-time site")
    if len(false_calls) != 1:
        out.append(f"R1: expected exactly one stamp_seq_locked(..., false) (the page-time stamp) in "
                   f"{RUNTIME}, found {len(false_calls)}")
    elif not _inside(false_calls[0], page):
        out.append("R1: the stamp_seq_locked(..., false) call is not inside try_page_batch "
                   f"in {RUNTIME}")


def _rule2(srcs, norm, out):
    ex = norm(EXECUTOR)
    offer = function_bodies(ex, "offer")
    sites = call_sites(ex, r"(?<![A-Za-z0-9_])stamp_emit_pair")
    for (s, _, _) in sites:
        if not _inside(s, offer):
            out.append(f"R2: stamp_emit_pair( in {EXECUTOR} outside offer()")
    if not any(_inside(s, offer) for (s, _, _) in sites):
        out.append(f"R2: offer() in {EXECUTOR} no longer calls stamp_emit_pair( (executor admission stamp)")

    sd = norm(SEND)
    common = function_bodies(sd, "set_common")
    sites = call_sites(sd, r"(?<![A-Za-z0-9_])stamp_emit_pair")
    for (s, _, _) in sites:
        if not _inside(s, common):
            out.append(f"R2: stamp_emit_pair( in {SEND} outside set_common")
    if not any(_inside(s, common) for (s, _, _) in sites):
        out.append(f"R2: set_common in {SEND} no longer calls stamp_emit_pair(")
    for (a, b) in common:
        if re.search(r"(?<![A-Za-z0-9_])journal_batch_key", sd[a:b]):
            out.append(f"R2: set_common in {SEND} mentions journal_batch_key (the replay "
                       "discriminator is the page-time stamp; backfill_batch_provenance sets the "
                       "key on LIVE entries)")

    if re.search(r"(?<![A-Za-z0-9_])stamp_emit_pair\(", norm(ENGINE)):
        out.append(f"R2: {ENGINE} calls stamp_emit_pair( (the legacy stamp is at executor admission only)")

    # Sweep: the whole agent-core tree. The three files with a scoped rule above are skipped for
    # stamp_emit_pair( (their own checks are stricter); the raw setters are checked everywhere.
    scoped = (EXECUTOR, SEND, ENGINE)
    for key in srcs:
        if key == EMIT_SEQ:
            continue
        raw = srcs[key]
        if "stamp_emit_pair" not in raw and "set_emit_seq" not in raw and "set_boot_epoch" not in raw:
            continue
        t = norm(key)
        if key not in scoped and re.search(r"(?<![A-Za-z0-9_])stamp_emit_pair\(", t):
            out.append(f"R2: stamp_emit_pair( in {key} (allowed only in {EXECUTOR} offer() and "
                       f"{SEND} set_common)")
        if re.search(r"(?<![A-Za-z0-9_])(?:set_emit_seq|set_boot_epoch)\(", t):
            out.append(f"R2: raw set_emit_seq(/set_boot_epoch( in {key} (allowed only in {EMIT_SEQ})")


def _rule3(t, out):
    claims = list(re.finditer(r"(\w+) ?= ?claim_guardian_boot_epoch\(", t))
    if len(claims) != 1:
        out.append(f"R3: expected exactly one `<id> = claim_guardian_boot_epoch(` in {AGENT}, "
                   f"found {len(claims)}")
    sites = call_sites(t, r"make_(?:unique|shared)<GuardianEngine>")
    if not sites:
        out.append(f"R3: no make_unique<GuardianEngine>( call in {AGENT}")
    for (start, a0, a1) in sites:
        args = split_args(t[a0:a1])
        if len(args) != 4:
            out.append(f"R3: make_unique<GuardianEngine> in {AGENT} has {len(args)} arguments, "
                       "expected 4 (kv, agent_id, prefer_spark=false, claimed boot_epoch)")
            continue
        if args[2] != "false":
            out.append(f"R3: the third GuardianEngine argument in {AGENT} is `{args[2]}`, "
                       "expected the literal false (prefer_spark_ is never true in production)")
        if len(claims) == 1:
            var = claims[0].group(1)
            if args[3] not in (var, var + ".boot_epoch"):
                out.append(f"R3: the fourth GuardianEngine argument in {AGENT} is `{args[3]}`, "
                           f"expected the claim result `{var}.boot_epoch`")
            if claims[0].start() > start:
                out.append(f"R3: claim_guardian_boot_epoch( does not precede make_unique<GuardianEngine> in {AGENT}")

    # TRIPWIRE ON KNOWN WRITERS, not a proof that no other serializer exists.
    sink = [(a0, a1) for (_, a0, a1) in call_sites(t, r"set_event_sink")]
    sink_n = dex_n = other = 0
    for (start, a0, a1) in call_sites(t, r"(?<![A-Za-z0-9_])emit_guardian_event"):
        if re.search(r"LegacySendOutcome $", t[:start]):
            continue  # the definition
        args = t[a0:a1]
        if _inside(start, sink) and args == "ev":
            sink_n += 1
        elif args.startswith("signal_observation_to_event("):
            dex_n += 1
        else:
            other += 1
    if (sink_n, dex_n, other) != (1, 1, 0):
        out.append(f"R3 (tripwire on KNOWN WRITERS, not a proof that no other serializer exists): "
                   f"emit_guardian_event( callers in {AGENT} are expected to be exactly the "
                   f"set_event_sink lambda and the DEX observer; found sink={sink_n}, dex={dex_n}, "
                   f"unrecognised={other}. A new wire writer must be reviewed for the emit-pair stamp")


def _rule4(t, out):
    helper = function_bodies(t, "make_legacy_sink_executor")
    direct = [m.start() for m in re.finditer(
        r"make_(?:unique|shared)<GuardianLegacySinkExecutor>\(|(?<![A-Za-z0-9_:])GuardianLegacySinkExecutor[({]", t)]
    for p in direct:
        if not _inside(p, helper):
            out.append(f"R4: a GuardianLegacySinkExecutor is constructed in {ENGINE} outside "
                       "make_legacy_sink_executor( (a bare Config drops the shared emit source)")
    if not helper:
        out.append(f"R4: no make_legacy_sink_executor definition in {ENGINE}")
    for (a, b) in helper:
        if not re.search(r"\.emit_seq_source ?= ?emit_seq_source_;", t[a:b]):
            out.append("R4: make_legacy_sink_executor no longer assigns emit_seq_source_ into the "
                       "executor Config")
    inits = list(re.finditer(r"(?<![A-Za-z0-9_])legacy_sink_executor_(?: ?= ?(?!=)|\{|\.reset\()", t))
    if len(inits) < 2:
        out.append(f"R4: expected the constructor init and the test-seam rebuild of "
                   f"legacy_sink_executor_ in {ENGINE}, found {len(inits)}")
    for m in inits:
        if not t.startswith("make_legacy_sink_executor(", m.end()):
            out.append(f"R4: legacy_sink_executor_ is initialised/assigned in {ENGINE} without "
                       "make_legacy_sink_executor(")

    wire = function_bodies(t, "wire_spark_engine")
    if not wire:
        out.append(f"R4: no wire_spark_engine definition in {ENGINE}")
    for (a, b) in wire:
        body = t[a:b]
        m = re.search(r"\.emit_seq_source ?= ?emit_seq_source_;", body)
        rt = re.search(r"make_shared<GuardianSparkRuntime>\(", body)
        if not m:
            out.append("R4: wire_spark_engine no longer assigns emit_seq_source into the Spark "
                       "runtime Config")
        elif rt and m.start() > rt.start():
            out.append("R4: wire_spark_engine assigns emit_seq_source after constructing the runtime")


def problems(srcs):
    """One message per violated invariant; [] when clean. `srcs` maps agents/core-relative paths
    to raw source text and must contain every file in REQUIRED."""
    cache = {}

    def norm(key):
        if key not in cache:
            cache[key] = normalise(srcs[key])
        return cache[key]

    out = []
    for k in REQUIRED:
        if k not in srcs:
            return [f"missing source {k}"]
    _rule1(norm(RUNTIME), out)
    _rule2(srcs, norm, out)
    _rule3(norm(AGENT), out)
    _rule4(norm(ENGINE), out)
    return out


def load_sources():
    srcs = {}
    for sub in ("src", "include"):
        for p in sorted((CORE / sub).rglob("*")):
            if p.is_file() and p.suffix in _SCAN_SUFFIXES:
                srcs[p.relative_to(CORE).as_posix()] = p.read_text(encoding="utf-8", errors="replace")
    return srcs


def mutate(srcs, key, pattern, repl, count=1, flags=0):
    """Copy of srcs with one regex substitution applied to srcs[key]; fails on a stale pattern."""
    new, n = re.subn(pattern, repl, srcs[key], count=count, flags=flags)
    if n < 1:
        raise AssertionError(f"mutation changed nothing in {key} (stale pattern: {pattern})")
    out = dict(srcs)
    out[key] = new
    return out


# (id, key, pattern, repl, count, flags, expected substring of some problem)
MUTATIONS = [
    # R1: an enqueue with its stamp removed (each of the four live shapes) ...
    ("R1 unstamped enqueue_all (health/transition)", RUNTIME,
     r"(for \(auto& e : entries\)\s*)stamp_seq_locked\(e\);(\s*outbox_\.enqueue_all\(std::move\(entries\)\); // best-effort)",
     r"\1(void)e;\2", 1, 0, "R1: outbox_.enqueue_all("),
    ("R1 unstamped enqueue_all (evaluate_key)", RUNTIME,
     r"(for \(auto& e : entries\)\s*)stamp_seq_locked\(e\);(\s*accepted = outbox_\.enqueue_all)",
     r"\1(void)e;\2", 1, 0, "R1: outbox_.enqueue_all("),
    ("R1 unstamped lifecycle arm enqueue", RUNTIME,
     r"stamp_seq_locked\(entry\);(\s*const bool accepted = lifecycle_log_\.enqueue\(std::move\(entry\)\); // throwing)",
     r"\1", 1, 0, "R1: lifecycle_log_.enqueue("),
    ("R1 unstamped lifecycle disarm enqueue", RUNTIME,
     r"stamp_seq_locked\(entry\);(\s*const bool accepted = lifecycle_log_\.enqueue\(std::move\(entry\)\); // best-effort)",
     r"\1", 1, 0, "R1: lifecycle_log_.enqueue("),
    ("R1 unstamped page-time enqueue", RUNTIME,
     r"stamp_seq_locked\(e, /\*wire_ordered=\*/false\);", "", 1, 0, "R1: lifecycle_log_.enqueue("),
    # ... a brand-new unstamped enqueue added behind a fresh lock.
    ("R1 new unstamped enqueue behind its own lock", RUNTIME,
     r"(void GuardianSparkRuntime::set_outbox_enqueue_waker\()",
     "void GuardianSparkRuntime::extra_unstamped_for_gate(OutboxEntry e) {\n"
     "    std::lock_guard<std::mutex> ob{outbox_mu_};\n"
     "    outbox_.enqueue(std::move(e));\n}\n\n\\1", 1, 0, "R1: outbox_.enqueue("),
    # R1: the page-time call passing true / the live default passing false.
    ("R1 page-time call passing true", RUNTIME,
     r"stamp_seq_locked\(e, /\*wire_ordered=\*/false\)", "stamp_seq_locked(e, /*wire_ordered=*/true)",
     1, 0, "expected exactly one stamp_seq_locked(..., false)"),
    ("R1 live call passing false", RUNTIME,
     r"stamp_seq_locked\(entry\);(\s*const bool accepted = lifecycle_log_\.enqueue\(std::move\(entry\)\); // throwing)",
     r"stamp_seq_locked(entry, false);\1", 1, 0, "expected exactly one stamp_seq_locked(..., false)"),
    # R2
    ("R2 stamp_emit_pair in the engine", ENGINE,
     r"(GuardianEngine::emit_seq_source_for_test\(\) const \{)", r"\1\n    stamp_emit_pair(*(gpb::GuaranteedStateEvent*)nullptr, 1, 1);",
     1, 0, "R2: src/guardian_engine.cpp calls stamp_emit_pair("),
    ("R2 stamp_emit_pair in an unrelated file", "src/guardian_boot_epoch.cpp",
     r"\Z", "\nvoid gate_probe() { stamp_emit_pair(ev, 1, 2); }\n", 1, 0, "R2: stamp_emit_pair( in src/guardian_boot_epoch.cpp"),
    ("R2 stamp_emit_pair outside offer() in the executor", EXECUTOR,
     r"(void set_pre_launch_race_hook_for_test\(std::function<void\(\)> hook\) \{)",
     r"\1\n        stamp_emit_pair(*static_cast<::yuzu::guardian::v1::GuaranteedStateEvent*>(nullptr), 1, 1);",
     1, 0, "R2: stamp_emit_pair( in " + EXECUTOR + " outside offer()"),
    ("R2 offer() stops stamping", EXECUTOR,
     r"stamp_emit_pair\(ev, state_->emit_seq_source->boot_epoch,\s*state_->emit_seq_source->draw\(\)\);", "",
     1, 0, "R2: offer() in " + EXECUTOR),
    ("R2 set_common stops stamping", SEND,
     r"stamp_emit_pair\(ev, e\.boot_epoch, e\.seq\);", "", 1, 0, "R2: set_common in " + SEND),
    ("R2 stamp_emit_pair outside set_common in send", SEND,
     r"(gpb::GuaranteedStateEvent guardian_outbox_entry_to_event\(const OutboxEntry& e,\s*std::string_view platform\) \{\n\s*gpb::GuaranteedStateEvent ev;)",
     r"\1\n    stamp_emit_pair(ev, e.boot_epoch, e.seq);", 1, 0, "R2: stamp_emit_pair( in " + SEND + " outside set_common"),
    ("R2 raw setter outside guardian_emit_seq.hpp", SEND,
     r"stamp_emit_pair\(ev, e\.boot_epoch, e\.seq\);", "ev.set_emit_seq(e.seq);", 1, 0,
     "R2: raw set_emit_seq("),
    ("R2 journal_batch_key inside set_common", SEND,
     r"stamp_emit_pair\(ev, e\.boot_epoch, e\.seq\);",
     "if (!e.journal_batch_key.empty()) stamp_emit_pair(ev, e.boot_epoch, e.seq);", 1, 0,
     "mentions journal_batch_key"),
    # R3
    ("R3 third emit_guardian_event writer", AGENT,
     r"(LegacySendOutcome emit_guardian_event\(const gpb::GuaranteedStateEvent& ev\) \{)",
     "void rogue_writer(const gpb::GuaranteedStateEvent& ev) { emit_guardian_event(ev); }\n    \\1",
     1, 0, "R3 (tripwire on KNOWN WRITERS"),
    ("R3 DEX observer writer removed", AGENT,
     r"emit_guardian_event\(signal_observation_to_event\(obs, event_id\)\);", "(void)obs;", 1, 0,
     "R3 (tripwire on KNOWN WRITERS"),
    ("R3 3-arg make_unique", AGENT,
     r"(std::make_unique<GuardianEngine>\(kv_store_\.get\(\), cfg_\.agent_id,\s*/\*prefer_spark=\*/false),\s*boot_epoch_claim\.boot_epoch\)",
     r"\1)", 1, 0, "has 3 arguments, expected 4"),
    ("R3 claim result not passed", AGENT,
     r"/\*prefer_spark=\*/false, boot_epoch_claim\.boot_epoch\)", "/*prefer_spark=*/false, 0)", 1, 0,
     "the fourth GuardianEngine argument"),
    ("R3 prefer_spark flipped", AGENT,
     r"/\*prefer_spark=\*/false, boot_epoch_claim", "/*prefer_spark=*/true, boot_epoch_claim", 1, 0,
     "the third GuardianEngine argument"),
    ("R3 claim moved after the construction", AGENT,
     r"(const auto boot_epoch_claim = claim_guardian_boot_epoch\([^;]*\);)(\s*guardian_ =\s*std::make_unique<GuardianEngine>\([^;]*\);)",
     r"\2\n        \1", 1, 0, "does not precede make_unique<GuardianEngine>"),
    ("R3 claim call removed", AGENT,
     r"const auto boot_epoch_claim = claim_guardian_boot_epoch\(kv_store_\.get\(\), now_unix_s\);", "",
     1, 0, "expected exactly one `<id> = claim_guardian_boot_epoch(`"),
    # R4
    ("R4 bare-Config executor construction (test seam)", ENGINE,
     r"legacy_sink_executor_ = make_legacy_sink_executor\(max_events\);",
     "legacy_sink_executor_ = std::make_unique<GuardianLegacySinkExecutor>(GuardianLegacySinkExecutor::Config{});",
     1, 0, "R4: a GuardianLegacySinkExecutor is constructed"),
    ("R4 assignment skips the helper", ENGINE,
     r"legacy_sink_executor_ = make_legacy_sink_executor\(max_events\);",
     "legacy_sink_executor_ = nullptr;", 1, 0, "without make_legacy_sink_executor("),
    ("R4 helper drops the source", ENGINE,
     r"cfg\.emit_seq_source = emit_seq_source_;", "", 1, 0, "make_legacy_sink_executor no longer assigns"),
    ("R4 wire_spark_engine forgets the field", ENGINE,
     r"spark_runtime_cfg\.emit_seq_source = emit_seq_source_;", "", 1, 0,
     "wire_spark_engine no longer assigns emit_seq_source"),
]


class GuardianEmitStampLexical(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srcs = load_sources()

    def test_source_is_clean(self):
        p = problems(self.srcs)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for (mid, key, pat, repl, cnt, flags, expected) in MUTATIONS:
            with self.subTest(mutation=mid):
                p = problems(mutate(self.srcs, key, pat, repl, cnt, flags | re.S))
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertTrue(any(expected in m for m in p),
                                f"expected a problem containing {expected!r}, got {p}")

    def test_rules_are_not_vacuous(self):
        # Each rule must have found real sites in the clean tree, else a stale pattern passes.
        rt = normalise(self.srcs[RUNTIME])
        self.assertGreaterEqual(len(_ENQ.findall(rt)), 5)
        self.assertGreaterEqual(len(call_sites(rt, _STAMP_SEQ)), 5)
        self.assertTrue(function_bodies(rt, "try_page_batch"))
        self.assertTrue(function_bodies(normalise(self.srcs[EXECUTOR]), "offer"))
        self.assertTrue(function_bodies(normalise(self.srcs[SEND]), "set_common"))
        self.assertTrue(function_bodies(normalise(self.srcs[ENGINE]), "make_legacy_sink_executor"))
        self.assertTrue(function_bodies(normalise(self.srcs[ENGINE]), "wire_spark_engine"))

    def test_comment_and_string_tokens_cannot_satisfy_a_rule(self):
        base = self.srcs
        cases = [
            ("R1 line comment", RUNTIME,
             r"stamp_seq_locked\(entry\);(\s*const bool accepted = lifecycle_log_\.enqueue\(std::move\(entry\)\); // throwing)",
             r"// stamp_seq_locked(entry);\1", "R1: lifecycle_log_.enqueue("),
            ("R1 block comment", RUNTIME,
             r"stamp_seq_locked\(entry\);(\s*const bool accepted = lifecycle_log_\.enqueue\(std::move\(entry\)\); // throwing)",
             r"/* stamp_seq_locked(entry); */\1", "R1: lifecycle_log_.enqueue("),
            ("R1 string literal", RUNTIME,
             r"stamp_seq_locked\(entry\);(\s*const bool accepted = lifecycle_log_\.enqueue\(std::move\(entry\)\); // throwing)",
             r'(void)"stamp_seq_locked(entry);";\1', "R1: lifecycle_log_.enqueue("),
            ("R1 page-time false only in a comment", RUNTIME,
             r"stamp_seq_locked\(e, /\*wire_ordered=\*/false\)",
             "stamp_seq_locked(e, true /* false */)", "expected exactly one stamp_seq_locked(..., false)"),
            ("R2 offer stamp only in a comment", EXECUTOR,
             r"stamp_emit_pair\(ev, state_->emit_seq_source->boot_epoch,\s*state_->emit_seq_source->draw\(\)\);",
             "// stamp_emit_pair(ev, boot_epoch, draw());", "R2: offer() in " + EXECUTOR),
            ("R3 claim only in a comment", AGENT,
             r"const auto boot_epoch_claim = claim_guardian_boot_epoch\(kv_store_\.get\(\), now_unix_s\);",
             "// const auto boot_epoch_claim = claim_guardian_boot_epoch(kv_store_.get(), now_unix_s);",
             "expected exactly one `<id> = claim_guardian_boot_epoch(`"),
            ("R4 emit_seq_source only in a comment", ENGINE,
             r"spark_runtime_cfg\.emit_seq_source = emit_seq_source_;",
             "// spark_runtime_cfg.emit_seq_source = emit_seq_source_;",
             "wire_spark_engine no longer assigns emit_seq_source"),
        ]
        for (cid, key, pat, repl, expected) in cases:
            with self.subTest(case=cid):
                p = problems(mutate(base, key, pat, repl, 1, re.S))
                self.assertTrue(any(expected in m for m in p), f"{expected!r} not in {p}")

    def test_comment_and_string_tokens_cannot_trip_a_rule(self):
        noise = ("// stamp_emit_pair( set_emit_seq( set_boot_epoch( journal_batch_key\n"
                 '/* stamp_emit_pair(ev, 1, 2); journal_batch_key */\n'
                 'static const char* kGateNoise = "stamp_emit_pair( set_boot_epoch( journal_batch_key";\n')
        srcs = dict(self.srcs)
        for key in (ENGINE, SEND, AGENT, EXECUTOR, RUNTIME, "src/guardian_boot_epoch.cpp"):
            srcs[key] = srcs[key] + "\n" + noise
        # Inside set_common too: append noise right after its opening brace.
        srcs = mutate(srcs, SEND, r"(void set_common\([^)]*\) \{)", r"\1\n" + noise.replace("\\", "\\\\"), 1, re.S)
        self.assertEqual(problems(srcs), [])

    def test_normaliser_basics(self):
        t = normalise('a // x\nb /* y\nz */ c "s//t" \'q\' 1\'000 R"d(\n)" )d" e')
        self.assertEqual(t, 'a b c "" \'\' 1\'000 "" e')
        self.assertEqual(split_args("a,f(b,c),{d,e},g"), ["a", "f(b,c)", "{d,e}", "g"])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
