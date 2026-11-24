#!/usr/bin/env python3
"""Static lexical gate over server/core/src/server.cpp: the PostgreSQL collation version check
stays wired in at BOTH ends: the constructor-time call in the ServerImpl constructor's substrate
block, and the recheck's construction, start and stop in run() and stop().

Why: the check (server/core/src/pg/pg_collation_check.{hpp,cpp}) never stops the server and is exercised by
unit tests, but nothing exercises ServerImpl's wiring in a unit test. A refactor could drop the
call and every unit test would stay green, while the gauge `yuzu_pg_collation_version_mismatch`
and its shipped alert would silently never move: a database whose text indexes disagree with the
operating system's collation would go unreported: its ordered reads of a text key could skip or
repeat rows without any signal.

The same gate pins the recheck (`PgCollationRecheck`, pg_collation_recheck.hpp): a thread
that borrows the PostgreSQL pool, so a dropped start is a silent loss of the repeated signal and a
dropped join is a use-after-free at shutdown that no unit test exercises, and a request_stop that
slips behind the join (or behind the web server stop) silently puts the check's wait back on the
critical path of every shutdown.

Invariants:

  1. `pg::report_collation_check(` appears exactly once in server.cpp, and its first argument is
     `pg::check_collation_version(` (the report is fed by the check, not by a constant).
  2. The call is guarded by exactly `if (pg_probe_ok)`, so it runs only on a pool whose probe
     checkout succeeded (the check needs a working pool).
  3. It is textually after the probe block, which is the statement `pg_probe_ok = true;`, so the
     probe lease is already released when the check takes its own lease (a pool of size 1 would
     otherwise deadlock itself).
  4. It is NOT tied to `startup_failed_`: neither its guard nor its statement mentions it. The
     check never stops the server and must run (and report) whatever else is wrong with the boot.
  5. The call passes `collation_state_`, the state the recheck is seeded from.
  6. `pg_collation_recheck_ = std::make_unique<PgCollationRecheck>(` appears exactly once, inside
     the brace-matched body of `void run() override`, textually after the constructor-time call
     (the recheck never runs before the start-time check has finished), and is seeded with
     `collation_state_`. `pg_collation_recheck_->start();` follows it, in run().
  7. `pg_collation_recheck_->stop();` appears exactly once, inside the body of
     `void stop() noexcept override`, textually before `pg_pool_.reset();` in that body: the
     thread is joined before the pool its check borrows is destroyed.
  8. The member `std::unique_ptr<PgCollationRecheck> pg_collation_recheck_;` is declared after
     `std::unique_ptr<pg::PgPool> pg_pool_;`, so reverse destruction cannot reach a dead pool even
     if stop() was skipped.
  9. The construction is preceded, within a short window, by `lifecycle_mu_` and a
     `stop_requested_` check: it is made and started under the mutex stop() holds, so a SIGTERM
     during boot cannot race the pointer assignment against stop().

  10. `pg_collation_recheck_->request_stop();` appears exactly once, inside the body of
     `void stop() noexcept override`, null-guarded by `if (pg_collation_recheck_)`, textually
     after `std::lock_guard<std::mutex> life(lifecycle_mu_);` (inside the lifecycle window, so the
     pointer read cannot race run()'s assignment), textually before `web_server_->stop();` and
     before the join `pg_collation_recheck_->stop();`: the check in flight is told to stop at the
     start of teardown, so it overlaps the rest of it instead of being added after it.

  11. The recheck construction is guarded by exactly
     `if (!teardown_complete_ && !stop_requested_.load(std::memory_order_acquire)) {` (both
     conditions present and negated): an inverted or half-dropped guard compiles, passes every
     unit test and either never starts the recheck or starts one stop() will not join.
  12. The three series' HELP text and the counter's closed result set are wired: `pg::seed_collation_metrics(metrics_);`
     appears exactly once, before the constructor-time report, and `metrics_.describe(` is called
     once for each of the mismatch gauge, the check counter and the last-completed gauge. A dropped
     seed makes the first failure after a restart invisible to `increase()`.

  13. The join `pg_collation_recheck_->stop();` comes AFTER `leader_elector_->resign();`,
     `audit_store_->stop_cleanup();` and `offload_target_store_->flush_all();` in stop(): the join
     can wait out a check stuck against a frozen backend, and a kill during that wait must not skip
     the lease release or the flushes (it is the last step before the pool is reset).
     Those three steps belong to other subsystems: if one is renamed or removed the gate says
     "stale anchor" and names the step, rather than reporting a collation-wiring defect.

  14. The recheck `start()` is wrapped in try/catch(const std::exception&) that resets the unstarted
     recheck: a refused thread creation (a task or thread limit) must degrade a best-effort check,
     not abort the boot (found by an external review; one mutant).

  14b. The catch logs at ERROR (`spdlog::error(`), never warn: a recheck that never starts leaves
     a Mismatch or Unproven gate in place until a restart (writes paused, CI reads refused), which
     is an operator-actionable fault, not a degradation to note in passing.

  15a. The `collation_gate_` initialiser is exactly `{pg::kInitialCollationGate}` (Unproven, pinned
     by a static_assert in test_pg_collation_check.cpp), never Trusted; and every member that
     borrows a pointer to it (the recheck, the store, the hardware routes, the MCP server) is
     declared after it.

  15. The collation GATE (the lock-free atomic the check publishes, which pauses device_ci writes)
     is wired at all three ends: both report sites (the constructor-time `report_collation_check(`
     and the `PgCollationRecheck` construction) pass `&collation_gate_`, and
     `device_inventory_store_->set_write_gate(&collation_gate_);` appears exactly once. A dropped
     argument leaves the gate Unproven for the life of the process (writes never pause); a dropped
     `set_write_gate` leaves the store with no gate (the default), so a mismatch pauses nothing.
     Both compile and pass every unit test.
  16. The `collation_gate_` member is declared before the `device_inventory_store_` member that
     borrows a pointer to it, so it outlives the store.
  17. The bulk device-CI read's concurrency cap (#7949/#7951, `bulk_read_slots.hpp`) is wired at
     both consumers and constructed on every boot path: `.ci_read_slots = hardware_ci_read_slots_.get(),`
     (the hardware routes) and `tool_deps.ci_read_slots = hardware_ci_read_slots_.get();` (the MCP
     tools) each appear exactly once and nothing assigns `ci_read_slots` to null (a null pointer
     means "no cap" and serves, so a dropped wire leaves the pool unbounded with every unit test
     green); the `hardware_ci_read_slots_` member is declared before `hardware_routes_` and
     `mcp_server_`, which borrow it; the boot resolution (`resolve_bulk_read_cap(`) is called once
     and its refusal arm sets `startup_failed_` and still constructs the slots object.
  18. The busy counter is wired at both consumers: `.ci_read_busy_fn = hw_ci_read_busy_fn` (the
     hardware routes' Deps) and `tool_deps.ci_read_busy_fn = hw_ci_read_busy_fn` (the MCP tools)
     each appear exactly once, and the closed two-value surface label
     `surface == hardware_ci_page::Surface::kMcp ? "mcp" : "rest"` is present (a dropped wire
     leaves `yuzu_hardware_ci_read_busy_total` flat while the 503s still flow). The lambda body
     of `hw_ci_read_busy_fn` must also name the counter `yuzu_hardware_ci_read_busy_total` and
     call `.increment()` (a lambda that is wired but never moves the counter is the same flat
     gauge). The label and counter-name checks read the RAW source, because normalisation blanks
     string literals; they strip comments from the lambda body first and are otherwise best
     effort, while the structural half (blanked literals) still guards the wires and the
     `.increment()` call.

`//` and block comments are stripped and whitespace collapsed before matching; string and
character literals are blanked first so a token in a literal cannot satisfy or break a check, and
the preprocessor-dead branches of `#if 0` / `#if 1 ... #else` (nested, with `#elif`) are removed,
so wiring parked behind `#if 0` does not count as wiring. `#ifdef`, `#ifndef` and any other
condition are unknown: every branch is kept.

REMAINING LIMIT (review-enforced). It is lexical only: it cannot see a start() or call that
keeps its tokens but never runs, such as one under `if (false)`, in an uncalled lambda or helper,
or in a branch the control flow never reaches, nor a macro that expands to a dead branch. The
self-tests below delete, move or disable each required statement in memory and assert that the
gate names it, so a stale pattern fails loudly instead of passing vacuously.

Usage: python3 -I tests/test_pg_collation_check_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"

REPORT = "pg::report_collation_check("
CHECK = "pg::check_collation_version("
GUARD = "if (pg_probe_ok)"
PROBE_OK = "pg_probe_ok = true;"

MSG_COUNT = "expected exactly one `pg::report_collation_check(` call in server.cpp, found {n}"
MSG_NOT_FED = "the report_collation_check call is not fed by `pg::check_collation_version(`"
MSG_GUARD = "the report_collation_check call is not guarded by exactly `if (pg_probe_ok)`"
MSG_BEFORE_PROBE = ("the report_collation_check call is before the probe block "
                    "(`pg_probe_ok = true;`); the probe lease must be released first")
MSG_STARTUP_FAILED = "the report_collation_check call or its guard mentions startup_failed_"
MSG_NO_STATE = "the report_collation_check call does not pass collation_state_"

MAKE = "pg_collation_recheck_ = std::make_unique<PgCollationRecheck>("
START = "pg_collation_recheck_->start();"
STOP = "pg_collation_recheck_->stop();"
POOL_DECL = "std::unique_ptr<pg::PgPool> pg_pool_;"
RECHECK_DECL = "std::unique_ptr<PgCollationRecheck> pg_collation_recheck_;"
POOL_RESET = "pg_pool_.reset();"
REQUEST_STOP = "pg_collation_recheck_->request_stop();"
REQUEST_GUARD = "if (pg_collation_recheck_)"
LIFECYCLE_LOCK = "std::lock_guard<std::mutex> life(lifecycle_mu_);"
WEB_STOP = "web_server_->stop();"

MSG_MAKE_COUNT = "expected exactly one `{}` in server.cpp, found {{n}}".format(MAKE)
MSG_MAKE_NOT_IN_RUN = "the PgCollationRecheck is not constructed inside run()'s own body"
MSG_MAKE_BEFORE_CHECK = ("the PgCollationRecheck is constructed before the constructor-time "
                         "report_collation_check call")
MSG_MAKE_NO_STATE = "the PgCollationRecheck is not seeded with collation_state_"
MSG_NO_START = "run() no longer starts the PgCollationRecheck after constructing it"
START_GUARD = "if (!teardown_complete_ && !stop_requested_.load(std::memory_order_acquire)) {"
MSG_UNLOCKED = ("the PgCollationRecheck is not constructed under lifecycle_mu_ with exactly the "
                "guard `" + START_GUARD + "` (both conditions, both negated)")
SEED = "pg::seed_collation_metrics(metrics_);"
DESCRIBED = ("pg::kCollationMismatchGauge", "pg::kCollationCheckCounter",
             "pg::kCollationLastCompletedGauge")
MSG_SEED = ("server.cpp must call `" + SEED + "` exactly once, before the constructor-time "
            "report_collation_check call")
MSG_DESCRIBE = "server.cpp must call metrics_.describe(...) once for each of the three collation series"
MSG_STOP_COUNT = "expected exactly one `{}` in server.cpp, found {{n}}".format(STOP)
MSG_STOP_NOT_IN_STOP = "the PgCollationRecheck is not stopped inside stop()'s own body"
MSG_STOP_AFTER_POOL = "stop() resets pg_pool_ before it stops the PgCollationRecheck"
MSG_REQ_COUNT = "expected exactly one `{}` in server.cpp, found {{n}}".format(REQUEST_STOP)
MSG_REQ_NOT_IN_STOP = "the early request_stop is not inside stop()'s own body"
MSG_REQ_UNGUARDED = "the early request_stop is not guarded by exactly `if (pg_collation_recheck_)`"
MSG_REQ_NOT_LOCKED = ("the early request_stop is not after stop()'s `lifecycle_mu_` lock_guard "
                      "(it must run inside the lifecycle window)")
MSG_REQ_AFTER_JOIN = ("the early request_stop is after the join `pg_collation_recheck_->stop();` "
                      "(then it is not early)")
MSG_REQ_AFTER_WEB = "the early request_stop is after `web_server_->stop();` (then it is not early)"
BEFORE_JOIN = ("leader_elector_->resign();", "audit_store_->stop_cleanup();",
               "offload_target_store_->flush_all();")
MSG_STALE_ANCHOR = ("`{}` is not found in stop() (stale anchor): it names ANOTHER subsystem's step, "
                    "which was renamed or removed. This is not a collation-wiring defect; update "
                    "BEFORE_JOIN in this test to the step's new spelling and re-check that the "
                    "join still comes after it")
MSG_JOIN_LATE = ("the PgCollationRecheck join must come after the leader resign, the audit cleanup "
                 "and the offload flush in stop(): a join that waits on a wedged check must not be "
                 "able to skip them")
START_CATCH = "} catch (const std::exception& e) {"
RESET_ARM = "pg_collation_recheck_.reset();"
MSG_START_NOT_ERROR = ("the PgCollationRecheck start() catch does not log with spdlog::error (or logs "
                       "with spdlog::warn): a failed start leaves a Mismatch or Unproven gate in place "
                       "until a restart, so it must be an ERROR")
MSG_START_UNGUARDED = ("the PgCollationRecheck start() is not wrapped in try/catch(const std::exception&) "
                       "that resets the unstarted recheck: a refused thread creation would abort the "
                       "boot of a best-effort check")
GATE_ARG = "&collation_gate_"
WRITE_GATE = "device_inventory_store_->set_write_gate(&collation_gate_);"
GATE_DECL = "std::atomic<pg::CollationGate> collation_gate_"
GATE_INIT_DECL = "std::atomic<pg::CollationGate> collation_gate_{pg::kInitialCollationGate};"
STORE_DECL = "std::unique_ptr<DeviceInventoryStore> device_inventory_store_;"
# Every member that borrows a pointer to the gate (qe-3 / cpp-safety-2): the store (set_write_gate),
# the recheck (publishes), the hardware routes and the MCP server (`ci_collation_gate`). Each must
# be declared AFTER the gate so it is destroyed BEFORE it. STORE_DECL is checked by its own message.
BORROWER_DECLS = (
    ("pg_collation_recheck_", RECHECK_DECL),
    ("hardware_routes_", "std::unique_ptr<HardwareRoutes> hardware_routes_;"),
    ("mcp_server_", "std::unique_ptr<mcp::McpServer> mcp_server_;"),
)
MSG_REPORT_NO_GATE = "the report_collation_check call does not pass &collation_gate_"
MSG_MAKE_NO_GATE = "the PgCollationRecheck is not given &collation_gate_"
MSG_WRITE_GATE = ("server.cpp must call `" + WRITE_GATE + "` exactly once: without it the "
                  "device_ci store has no gate and a collation mismatch pauses nothing")
MSG_GATE_DECL_ORDER = ("the collation_gate_ member is not declared before the "
                       "device_inventory_store_ member that borrows a pointer to it")
MSG_GATE_INIT = ("the collation_gate_ member is not initialised with `{pg::kInitialCollationGate}`: "
                 "any other initial value (a fail-open Trusted) would let every device_ci write and "
                 "read through before the first check concludes")
MSG_GATE_BORROWER_ORDER = ("the {name} member that borrows a pointer to the collation gate is not "
                           "declared after the collation_gate_ member (it would outlive the gate it "
                           "reads)")
MSG_DECL_ORDER = ("the pg_collation_recheck_ member is not declared after the pg_pool_ member it "
                  "borrows")


_RAW_OPEN = re.compile(r'R"([^()\\\s]{0,16})\(')


def normalise(src):
    """Strip comments and blank literals, then collapse whitespace.

    One left-to-right scan, so a `//` inside a string literal is not a comment and a quote inside
    a comment is not a literal. Raw strings are blanked whole, and a quote that follows an
    alphanumeric character is a C++14 digit separator (`10'000`), not a character literal. Line
    structure survives the scan (a block comment or raw string keeps its newlines) so that the
    preprocessor pass can drop dead `#if 0` branches before whitespace is collapsed.
    """
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif two == "/*":
            j = src.find("*/", i + 2)
            span = src[i:n if j < 0 else j + 2]
            i = n if j < 0 else j + 2
            out.append(" " + "\n" * span.count("\n"))
        elif c == "R" and src[i + 1:i + 2] == '"' and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            m = _RAW_OPEN.match(src, i)
            if m:
                end = src.find(")" + m.group(1) + '"', m.end())
                stop = n if end < 0 else end + len(m.group(1)) + 2
                out.append('""' + "\n" * src[i:stop].count("\n"))
                i = stop
            else:
                out.append(c)
                i += 1
        elif c == "'" and i > 0 and src[i - 1].isalnum():
            out.append(c)  # a digit separator
            i += 1
        elif c == '"' or c == "'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            out.append(c + c)
            i = j + 1
        else:
            out.append(c)
            i += 1
    return re.sub(r"\s+", " ", strip_dead_branches("".join(out)))


_DIRECTIVE = re.compile(r"^\s*#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)$")
_TRUE = {"1", "(1)", "true"}
_FALSE = {"0", "(0)", "false"}


def _const(cond):
    """True / False for a literal-constant `#if` condition, None when it is anything else."""
    cond = cond.strip()
    if cond in _TRUE:
        return True
    if cond in _FALSE:
        return False
    return None


def strip_dead_branches(text):
    """Drop the preprocessor directive lines and every line in a branch known to be dead.

    A branch is dead after `#if 0` (until `#else`/`#elif`), after the taken branch of `#if 1`, and
    anywhere inside a dead region. Conditions other than the literals 0 and 1 are unknown, so all
    their branches are kept (the previous behaviour for `#ifdef _WIN32` and the like).
    """
    out = []
    stack = []  # [active, taken]: this branch is live; an earlier branch is known to be taken

    def live():
        return all(frame[0] for frame in stack)

    for line in text.split("\n"):
        m = _DIRECTIVE.match(line)
        if not m:
            if live():
                out.append(line)
            continue
        word, arg = m.group(1), m.group(2)
        if word in ("if", "ifdef", "ifndef"):
            val = _const(arg) if word == "if" else None
            stack.append([val is not False, val is True])
        elif word == "elif" and stack:
            frame, val = stack[-1], _const(arg)
            if frame[1]:
                frame[0] = False
            else:
                frame[0] = val is not False
                frame[1] = val is True
        elif word == "else" and stack:
            frame = stack[-1]
            frame[0] = not frame[1]
            frame[1] = True
        elif word == "endif" and stack:
            stack.pop()
    return "\n".join(out)


def call_span(t, start):
    """Index just past the `)` that closes the call whose `(` ends the token at `start`."""
    depth = 0
    for k in range(t.index("(", start), len(t)):
        if t[k] == "(":
            depth += 1
        elif t[k] == ")":
            depth -= 1
            if depth == 0:
                return k + 1
    return len(t)


def body_span(t, head):
    """(start, end) of the brace-matched body whose opening `{` ends `head`; None if absent."""
    i = t.find(head)
    if i < 0:
        return None
    j = t.index("{", i)
    depth = 0
    for k in range(j, len(t)):
        if t[k] == "{":
            depth += 1
        elif t[k] == "}":
            depth -= 1
            if depth == 0:
                return (j, k)
    return None


def request_stop_problems(t, stop, joins):
    """The early, null-guarded, lock-held request_stop in stop()'s body (invariant 10)."""
    reqs = [m.start() for m in re.finditer(re.escape(REQUEST_STOP), t)]
    if len(reqs) != 1:
        return [MSG_REQ_COUNT.format(n=len(reqs))]
    pos = reqs[0]
    if not (stop[0] < pos < stop[1]):
        return [MSG_REQ_NOT_IN_STOP]
    out = []
    if not t[:pos].rstrip().endswith(REQUEST_GUARD):
        out.append(MSG_REQ_UNGUARDED)
    lock = t.find(LIFECYCLE_LOCK, stop[0])
    if not (0 <= lock < pos):
        out.append(MSG_REQ_NOT_LOCKED)
    # A join elsewhere (the destructor) is invariant 7's business, not an ordering fact here.
    if joins and stop[0] < joins[0] < stop[1] and joins[0] < pos:
        out.append(MSG_REQ_AFTER_JOIN)
    web = t.find(WEB_STOP, stop[0])
    if not (0 <= web < stop[1]):
        out.append("`web_server_->stop();` not found in stop() (stale pattern)")
    elif web < pos:
        out.append(MSG_REQ_AFTER_WEB)
    return out


def recheck_problems(t, report_pos):
    out = []
    makes = [m.start() for m in re.finditer(re.escape(MAKE), t)]
    run = body_span(t, "void run() override {")
    stop = body_span(t, "void stop() noexcept override {")
    if run is None or stop is None:
        return ["`void run() override {` or `void stop() noexcept override {` not found "
                "(stale pattern)"]
    if len(makes) != 1:
        out.append(MSG_MAKE_COUNT.format(n=len(makes)))
    else:
        pos = makes[0]
        end = call_span(t, pos)
        if not (run[0] < pos < run[1]):
            out.append(MSG_MAKE_NOT_IN_RUN)
        if report_pos is not None and pos < report_pos:
            out.append(MSG_MAKE_BEFORE_CHECK)
        if "collation_state_" not in t[pos:end]:
            out.append(MSG_MAKE_NO_STATE)
        if GATE_ARG not in t[pos:end]:
            out.append(MSG_MAKE_NO_GATE)
        window = t[max(0, pos - 300):pos]
        if "lifecycle_mu_" not in window or START_GUARD not in window:
            out.append(MSG_UNLOCKED)
        start = t.find(START, pos)
        if start < 0 or not (run[0] < start < run[1]):
            out.append(MSG_NO_START)
        elif not (0 <= t.find(START_CATCH, start) < start + 120) or t.find(RESET_ARM, start, run[1]) < 0:
            out.append(MSG_START_UNGUARDED)
        else:
            c0 = t.find(START_CATCH, start)
            c1 = t.find(RESET_ARM, start, run[1])
            if "spdlog::error(" not in t[c0:c1] or "spdlog::warn(" in t[c0:c1]:
                out.append(MSG_START_NOT_ERROR)
    stops = [m.start() for m in re.finditer(re.escape(STOP), t)]
    if len(stops) != 1:
        out.append(MSG_STOP_COUNT.format(n=len(stops)))
    else:
        if not (stop[0] < stops[0] < stop[1]):
            out.append(MSG_STOP_NOT_IN_STOP)
        else:
            reset = t.find(POOL_RESET, stop[0])
            if 0 <= reset < stop[1] and reset < stops[0]:
                out.append(MSG_STOP_AFTER_POOL)
    out += request_stop_problems(t, stop, stops)
    if len(stops) == 1 and stop[0] < stops[0] < stop[1]:
        for step in BEFORE_JOIN:
            at = t.find(step, stop[0], stop[1])
            if at < 0:
                out.append(MSG_STALE_ANCHOR.format(step))
            elif at > stops[0]:
                out.append(MSG_JOIN_LATE)
                break
    pool = t.find(POOL_DECL)
    decl = t.find(RECHECK_DECL)
    if pool < 0 or decl < 0 or decl < pool:
        out.append(MSG_DECL_ORDER)
    return out


def problems(src):
    t = normalise(src)
    starts = [m.start() for m in re.finditer(re.escape(REPORT), t)]
    if len(starts) != 1:
        return [MSG_COUNT.format(n=len(starts))]
    pos = starts[0]
    end = call_span(t, pos)
    out = []
    if not t[pos + len(REPORT):end].lstrip().startswith(CHECK):
        out.append(MSG_NOT_FED)
    if not t[:pos].rstrip().endswith(GUARD):
        out.append(MSG_GUARD)
    probe = t.rfind(PROBE_OK, 0, pos)
    if probe < 0:
        out.append(MSG_BEFORE_PROBE)
    guard_text = t[max(0, pos - 80):pos]
    if "startup_failed_" in t[pos:end] or "startup_failed_" in guard_text.split(";")[-1]:
        out.append(MSG_STARTUP_FAILED)
    if "collation_state_" not in t[pos:end]:
        out.append(MSG_NO_STATE)
    if GATE_ARG not in t[pos:end]:
        out.append(MSG_REPORT_NO_GATE)
    if len(re.findall(re.escape(WRITE_GATE), t)) != 1:
        out.append(MSG_WRITE_GATE)
    gate_decl = t.find(GATE_DECL)
    store_decl = t.find(STORE_DECL)
    if gate_decl < 0 or store_decl < 0 or gate_decl > store_decl:
        out.append(MSG_GATE_DECL_ORDER)
    if GATE_INIT_DECL not in t:
        out.append(MSG_GATE_INIT)
    for name, decl in BORROWER_DECLS:
        pos_b = t.find(decl)
        if gate_decl < 0 or pos_b < 0 or gate_decl > pos_b:
            out.append(MSG_GATE_BORROWER_ORDER.format(name=name))
    seeds = [m.start() for m in re.finditer(re.escape(SEED), t)]
    if len(seeds) != 1 or seeds[0] > pos:
        out.append(MSG_SEED)
    for name in DESCRIBED:
        if len(re.findall(r"metrics_\.describe\(\s*" + re.escape(name) + r"\s*,", t)) != 1:
            out.append(MSG_DESCRIBE)
            break
    return out + recheck_problems(t, pos)


SLOTS_RESOLVE = "resolve_bulk_read_cap("
SLOTS_REST_WIRE = ".ci_read_slots = hardware_ci_read_slots_.get(),"
SLOTS_MCP_WIRE = "tool_deps.ci_read_slots = hardware_ci_read_slots_.get();"
SLOTS_DECL = "std::unique_ptr<yuzu::server::BulkReadSlots> hardware_ci_read_slots_;"
SLOTS_MAKE = "hardware_ci_read_slots_ = std::make_unique<yuzu::server::BulkReadSlots>("
SLOTS_REFUSE_ARM = "if (!cap) {"
MSG_SLOTS_REST_WIRE = ("the hardware routes' Deps is not handed `hardware_ci_read_slots_.get()` exactly "
                       "once as `.ci_read_slots` (a null slots pointer means no cap and serves)")
MSG_SLOTS_MCP_WIRE = ("the MCP ToolDeps is not handed `hardware_ci_read_slots_.get()` exactly once as "
                      "`tool_deps.ci_read_slots` (a null slots pointer means no cap and serves)")
MSG_SLOTS_NULL = "`ci_read_slots` is assigned null somewhere in server.cpp"
MSG_SLOTS_DECL_ORDER = ("the hardware_ci_read_slots_ member is missing or is not declared before the "
                        "{name} member that borrows a pointer to it")
MSG_SLOTS_RESOLVE = ("server.cpp must call `resolve_bulk_read_cap(` exactly once, with "
                     "`cfg_.hardware_ci_read_concurrency`: the boot arithmetic and its refusal")
MSG_SLOTS_MAKE = ("`hardware_ci_read_slots_` must be constructed in exactly two places, the refusal "
                  "arm and the accepted arm of the boot resolution, so it is never null")
MSG_SLOTS_REFUSE = ("the refusal arm of the bulk read cap resolution does not set `startup_failed_` "
                    "(an invalid explicit --hardware-ci-read-concurrency must refuse boot)")
SLOTS_BORROWER_DECLS = (
    ("hardware_routes_", "std::unique_ptr<HardwareRoutes> hardware_routes_;"),
    ("mcp_server_", "std::unique_ptr<mcp::McpServer> mcp_server_;"),
)


def slots_problems(src):
    """Wiring of the bulk read concurrency cap (invariant 17)."""
    t = normalise(src)
    out = []
    if len(re.findall(re.escape(SLOTS_REST_WIRE), t)) != 1:
        out.append(MSG_SLOTS_REST_WIRE)
    if len(re.findall(re.escape(SLOTS_MCP_WIRE), t)) != 1:
        out.append(MSG_SLOTS_MCP_WIRE)
    if re.search(r"ci_read_slots\s*=\s*(nullptr|\{\}|NULL)", t) or len(re.findall(r"ci_read_slots =", t)) != 2:
        out.append(MSG_SLOTS_NULL)
    decl = t.find(SLOTS_DECL)
    for name, borrower in SLOTS_BORROWER_DECLS:
        pos = t.find(borrower)
        if decl < 0 or pos < 0 or decl > pos:
            out.append(MSG_SLOTS_DECL_ORDER.format(name=name))
    resolves = [m.start() for m in re.finditer(re.escape(SLOTS_RESOLVE), t)]
    if len(resolves) != 1 or "cfg_.hardware_ci_read_concurrency" not in t[resolves[0]:resolves[0] + 120]:
        out.append(MSG_SLOTS_RESOLVE)
    if len(re.findall(re.escape(SLOTS_MAKE), t)) != 2:
        out.append(MSG_SLOTS_MAKE)
    arm = t.find(SLOTS_REFUSE_ARM, resolves[0]) if resolves else -1
    arm_end = t.find("} else {", arm) if arm >= 0 else -1
    if arm < 0 or arm_end < 0 or "startup_failed_ = true;" not in t[arm:arm_end]:
        out.append(MSG_SLOTS_REFUSE)
    return out


class HardwareCiReadSlotsWiring(unittest.TestCase):
    def setUp(self):
        self.src = SERVER_CPP.read_text(encoding="utf-8")

    def test_clean(self):
        self.assertEqual(slots_problems(self.src), [])

    def test_rest_wire_dropped_or_nulled(self):
        m = self.src.replace(SLOTS_REST_WIRE, ".ci_read_slots = nullptr,", 1)
        self.assertNotEqual(m, self.src)
        got = slots_problems(m)
        self.assertIn(MSG_SLOTS_REST_WIRE, got)
        self.assertIn(MSG_SLOTS_NULL, got)

    def test_mcp_wire_dropped_or_nulled(self):
        m = self.src.replace(SLOTS_MCP_WIRE, "tool_deps.ci_read_slots = nullptr;", 1)
        self.assertNotEqual(m, self.src)
        got = slots_problems(m)
        self.assertIn(MSG_SLOTS_MCP_WIRE, got)
        self.assertIn(MSG_SLOTS_NULL, got)
        m = self.src.replace(SLOTS_MCP_WIRE, "(void)0;", 1)
        self.assertIn(MSG_SLOTS_MCP_WIRE, slots_problems(m))

    def test_wire_inside_if_0_does_not_count(self):
        m = self.src.replace(SLOTS_REST_WIRE, "\n#if 0\n" + SLOTS_REST_WIRE + "\n#endif\n", 1)
        self.assertIn(MSG_SLOTS_REST_WIRE, slots_problems(m))

    def test_wired_twice(self):
        m = self.src.replace(SLOTS_MCP_WIRE, SLOTS_MCP_WIRE + "\n" + SLOTS_MCP_WIRE, 1)
        self.assertIn(MSG_SLOTS_MCP_WIRE, slots_problems(m))

    def test_member_declared_after_each_borrower(self):
        for name, borrower in SLOTS_BORROWER_DECLS:
            with self.subTest(borrower=name):
                i = self.src.index(SLOTS_DECL)
                rest = self.src[:i] + self.src[i + len(SLOTS_DECL):]
                k = rest.index(borrower) + len(borrower)
                m = rest[:k] + "\n    " + SLOTS_DECL + rest[k:]
                self.assertIn(MSG_SLOTS_DECL_ORDER.format(name=name), slots_problems(m))

    def test_member_deleted(self):
        m = self.src.replace(SLOTS_DECL, "", 1)
        got = slots_problems(m)
        for name, _ in SLOTS_BORROWER_DECLS:
            self.assertIn(MSG_SLOTS_DECL_ORDER.format(name=name), got)

    def test_resolution_deleted_or_not_fed_the_flag(self):
        m = self.src.replace(SLOTS_RESOLVE, "resolve_bulk_read_cap_renamed(", 1)
        self.assertIn(MSG_SLOTS_RESOLVE, slots_problems(m))
        m = self.src.replace("resolve_bulk_read_cap(cfg_.hardware_ci_read_concurrency",
                             "resolve_bulk_read_cap(2", 1)
        self.assertNotEqual(m, self.src)
        self.assertIn(MSG_SLOTS_RESOLVE, slots_problems(m))

    def test_a_construction_arm_deleted(self):
        i = self.src.index(SLOTS_MAKE)
        j = self.src.index(";", i) + 1
        m = self.src[:i] + "(void)0;" + self.src[j:]
        self.assertIn(MSG_SLOTS_MAKE, slots_problems(m))

    def test_refusal_arm_no_longer_refuses_boot(self):
        i = self.src.index(SLOTS_REFUSE_ARM, self.src.index(SLOTS_RESOLVE))
        j = self.src.index("startup_failed_ = true;", i)
        m = self.src[:j] + "(void)0;" + self.src[j + len("startup_failed_ = true;"):]
        self.assertIn(MSG_SLOTS_REFUSE, slots_problems(m))


BUSY_REST_WIRE = ".ci_read_busy_fn = hw_ci_read_busy_fn,"
BUSY_MCP_WIRE = "tool_deps.ci_read_busy_fn = hw_ci_read_busy_fn;"
BUSY_LABEL_NORM = 'surface == hardware_ci_page::Surface::kMcp ? "" : ""'
BUSY_LABEL_RAW = 'surface == hardware_ci_page::Surface::kMcp ? "mcp" : "rest"'
MSG_BUSY_REST_WIRE = ("the hardware routes' Deps is not handed `hw_ci_read_busy_fn` exactly once as "
                      "`.ci_read_busy_fn` (the busy counter would never move)")
MSG_BUSY_MCP_WIRE = ("the MCP ToolDeps is not handed `hw_ci_read_busy_fn` exactly once as "
                     "`tool_deps.ci_read_busy_fn` (the busy counter would never move)")
MSG_BUSY_LABEL = ("the busy counter's closed surface label ternary "
                  "`surface == hardware_ci_page::Surface::kMcp ? \"mcp\" : \"rest\"` is missing")
BUSY_LAMBDA = re.compile(r"auto\s+hw_ci_read_busy_fn\s*=\s*\[[^\]]*\]\s*\([^)]*\)\s*\{")
BUSY_COUNTER = "yuzu_hardware_ci_read_busy_total"
MSG_BUSY_COUNTER_NAME = ("the `hw_ci_read_busy_fn` lambda body does not name the counter "
                         "`yuzu_hardware_ci_read_busy_total` (the alerted series would never move)")
MSG_BUSY_INCREMENT = ("the `hw_ci_read_busy_fn` lambda body does not call `.increment()` "
                      "(a refusal would not move the busy counter)")


def busy_lambda_body(text):
    """The brace-balanced body of the `hw_ci_read_busy_fn` lambda in `text`, or None."""
    m = BUSY_LAMBDA.search(text)
    if not m:
        return None
    depth, i = 1, m.end()
    while i < len(text) and depth:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    return text[m.end():i - 1] if depth == 0 else None


def busy_problems(src):
    """Wiring of the bulk read busy counter (invariant 18)."""
    t = normalise(src)
    out = []
    if len(re.findall(re.escape(BUSY_REST_WIRE), t)) != 1:
        out.append(MSG_BUSY_REST_WIRE)
    if len(re.findall(re.escape(BUSY_MCP_WIRE), t)) != 1:
        out.append(MSG_BUSY_MCP_WIRE)
    if len(re.findall(re.escape(BUSY_LABEL_NORM), t)) != 1 or BUSY_LABEL_RAW not in src:
        out.append(MSG_BUSY_LABEL)
    body = busy_lambda_body(t)
    if body is None or ".increment()" not in body:
        out.append(MSG_BUSY_INCREMENT)
    raw = busy_lambda_body(src)
    if raw is not None:
        raw = re.sub(r"/\*.*?\*/", "", raw, flags=re.S)
        raw = re.sub(r"//[^\n]*", "", raw)
    if raw is None or BUSY_COUNTER not in raw:
        out.append(MSG_BUSY_COUNTER_NAME)
    return out


class HardwareCiReadBusyWiring(unittest.TestCase):
    def setUp(self):
        self.src = SERVER_CPP.read_text(encoding="utf-8")

    def test_clean(self):
        self.assertEqual(busy_problems(self.src), [])

    def test_rest_wire_dropped(self):
        m = self.src.replace(BUSY_REST_WIRE, ".ci_read_busy_fn = nullptr,", 1)
        self.assertNotEqual(m, self.src)
        self.assertIn(MSG_BUSY_REST_WIRE, busy_problems(m))

    def test_mcp_wire_dropped_or_doubled(self):
        m = self.src.replace(BUSY_MCP_WIRE, "(void)0;", 1)
        self.assertNotEqual(m, self.src)
        self.assertIn(MSG_BUSY_MCP_WIRE, busy_problems(m))
        m = self.src.replace(BUSY_MCP_WIRE, BUSY_MCP_WIRE + "\n" + BUSY_MCP_WIRE, 1)
        self.assertIn(MSG_BUSY_MCP_WIRE, busy_problems(m))

    def test_wire_inside_if_0_does_not_count(self):
        m = self.src.replace(BUSY_MCP_WIRE, "\n#if 0\n" + BUSY_MCP_WIRE + "\n#endif\n", 1)
        self.assertIn(MSG_BUSY_MCP_WIRE, busy_problems(m))

    def test_label_ternary_changed(self):
        m = self.src.replace(BUSY_LABEL_RAW, 'surface == hardware_ci_page::Surface::kMcp ? "mcp" : "other"', 1)
        self.assertNotEqual(m, self.src)
        self.assertIn(MSG_BUSY_LABEL, busy_problems(m))
        m = self.src.replace(BUSY_LABEL_RAW, "std::string{}", 1)
        self.assertIn(MSG_BUSY_LABEL, busy_problems(m))

    def _mutate_in_lambda(self, old, new):
        """Replace the first `old` after the lambda header only (the name occurs elsewhere)."""
        h = BUSY_LAMBDA.search(self.src)
        self.assertIsNotNone(h)
        i = self.src.index(old, h.end())
        return self.src[:i] + new + self.src[i + len(old):]

    def test_counter_name_removed_or_commented_out(self):
        m = self._mutate_in_lambda(BUSY_COUNTER, "yuzu_some_other_total")
        self.assertNotEqual(m, self.src)
        got = busy_problems(m)
        self.assertIn(MSG_BUSY_COUNTER_NAME, got)
        self.assertNotIn(MSG_BUSY_INCREMENT, got)
        m = self._mutate_in_lambda(BUSY_COUNTER, "yuzu_some_other_total /* " + BUSY_COUNTER + " */")
        self.assertIn(MSG_BUSY_COUNTER_NAME, busy_problems(m))

    def test_increment_removed_or_commented_out(self):
        m = self._mutate_in_lambda(".increment();", ";")
        self.assertNotEqual(m, self.src)
        got = busy_problems(m)
        self.assertIn(MSG_BUSY_INCREMENT, got)
        self.assertNotIn(MSG_BUSY_COUNTER_NAME, got)
        m = self._mutate_in_lambda(".increment();", "; // .increment();")
        self.assertIn(MSG_BUSY_INCREMENT, busy_problems(m))

    def test_lambda_deleted_or_renamed(self):
        m = self.src.replace("auto hw_ci_read_busy_fn = [this]",
                             "auto hw_ci_read_busy_fn_x = [this]", 1)
        self.assertNotEqual(m, self.src)
        got = busy_problems(m)
        self.assertIn(MSG_BUSY_INCREMENT, got)
        self.assertIn(MSG_BUSY_COUNTER_NAME, got)


class PgCollationCheckWiring(unittest.TestCase):
    def setUp(self):
        self.src = SERVER_CPP.read_text(encoding="utf-8")

    def test_clean(self):
        self.assertEqual(problems(self.src), [])

    def test_call_deleted(self):
        m = self.src.replace(REPORT, "pg::report_collation_check_renamed(", 1)
        self.assertEqual(problems(m), [MSG_COUNT.format(n=0)])

    def test_call_duplicated(self):
        i = self.src.index(REPORT)
        j = self.src.index(";", i) + 1
        m = self.src[:j] + "\n" + self.src[i:j] + self.src[j:]
        self.assertEqual(problems(m), [MSG_COUNT.format(n=2)])

    def test_not_fed_by_the_check(self):
        m = self.src.replace(CHECK + "*pg_pool_)", "pg::CollationReport{}", 1)
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_NOT_FED])

    def test_guard_removed(self):
        m = self.src.replace(GUARD + "\n                    " + REPORT, REPORT, 1)
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_GUARD])

    def test_guard_tied_to_startup_failed(self):
        m = self.src.replace(GUARD + "\n                    " + REPORT,
                             "if (pg_probe_ok && !startup_failed_)\n                    " + REPORT, 1)
        self.assertNotEqual(m, self.src)
        got = problems(m)
        self.assertIn(MSG_STARTUP_FAILED, got)

    def test_moved_before_the_probe_block(self):
        i = self.src.index(REPORT)
        j = self.src.index(";", i) + 1
        stmt = self.src[i:j]
        rest = self.src[:i] + self.src[j:]
        k = rest.index("bool pg_probe_ok = false;")
        m = rest[:k] + GUARD + " " + stmt + "\n" + rest[k:]
        self.assertIn(MSG_BEFORE_PROBE, problems(m))

    def test_recheck_construction_deleted(self):
        m = self.src.replace(MAKE, "pg_collation_recheck_ = std::make_unique<PgOther>(", 1)
        self.assertEqual(problems(m), [MSG_MAKE_COUNT.format(n=0)])

    def test_recheck_not_seeded(self):
        i = self.src.index(MAKE)
        j = self.src.index("collation_state_,", i)
        m = self.src[:j] + "pg::CollationState{}," + self.src[j + len("collation_state_,"):]
        self.assertEqual(problems(m), [MSG_MAKE_NO_STATE])

    def test_report_call_not_passed_the_gate(self):
        i = self.src.index(REPORT)
        j = self.src.index(GATE_ARG, i)
        m = self.src[:j] + "nullptr" + self.src[j + len(GATE_ARG):]
        self.assertEqual(problems(m), [MSG_REPORT_NO_GATE])

    def test_recheck_not_given_the_gate(self):
        i = self.src.index(MAKE)
        j = self.src.index(GATE_ARG, i)
        m = self.src[:j] + "nullptr" + self.src[j + len(GATE_ARG):]
        self.assertEqual(problems(m), [MSG_MAKE_NO_GATE])

    def test_store_write_gate_not_wired(self):
        m = self.src.replace(WRITE_GATE, "(void)0;", 1)
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_WRITE_GATE])

    def test_store_write_gate_wired_twice(self):
        m = self.src.replace(WRITE_GATE, WRITE_GATE + "\n" + WRITE_GATE, 1)
        self.assertEqual(problems(m), [MSG_WRITE_GATE])

    def test_store_write_gate_in_if_0_fails(self):
        m = self.src.replace(WRITE_GATE, "\n#if 0\n" + WRITE_GATE + "\n#endif\n", 1)
        self.assertEqual(problems(m), [MSG_WRITE_GATE])

    def test_gate_declared_after_the_store(self):
        i = self.src.index(GATE_DECL)
        j = self.src.index(";", i) + 1
        decl = self.src[i:j]
        rest = self.src[:i] + self.src[j:]
        k = rest.index(STORE_DECL) + len(STORE_DECL)
        m = rest[:k] + "\n    " + decl + rest[k:]
        # The store is declared after the hardware routes and the MCP server, so moving the gate
        # past the store moves it past those two borrowers as well.
        self.assertEqual(problems(m), [
            MSG_GATE_DECL_ORDER,
            MSG_GATE_BORROWER_ORDER.format(name="hardware_routes_"),
            MSG_GATE_BORROWER_ORDER.format(name="mcp_server_"),
        ])

    def test_gate_declared_after_each_other_borrower(self):
        for name, decl in BORROWER_DECLS:
            with self.subTest(borrower=name):
                i = self.src.index(GATE_DECL)
                j = self.src.index(";", i) + 1
                gate = self.src[i:j]
                rest = self.src[:i] + self.src[j:]
                k = rest.index(decl) + len(decl)
                m = rest[:k] + "\n    " + gate + rest[k:]
                self.assertIn(MSG_GATE_BORROWER_ORDER.format(name=name), problems(m))

    def test_gate_initialised_to_trusted(self):
        for bad in ("{pg::CollationGate::Trusted}", "{}", "{pg::CollationGate::Mismatch}"):
            with self.subTest(init=bad):
                m = self.src.replace(GATE_INIT_DECL,
                                     "std::atomic<pg::CollationGate> collation_gate_" + bad + ";", 1)
                self.assertNotEqual(m, self.src)
                self.assertEqual(problems(m), [MSG_GATE_INIT])

    def test_recheck_start_deleted(self):
        m = self.src.replace(START, "(void)0;", 1)
        self.assertEqual(problems(m), [MSG_NO_START])

    def test_recheck_moved_into_the_constructor(self):
        i = self.src.index(MAKE)
        j = self.src.index(START, i) + len(START)
        stmt = self.src[i:j]
        rest = self.src[:i] + self.src[j:]
        k = rest.index(REPORT)
        k = rest.index(";", k) + 1
        m = rest[:k] + "\n" + stmt + "\n" + rest[k:]
        got = problems(m)
        self.assertIn(MSG_MAKE_NOT_IN_RUN, got)

    def test_stop_join_deleted(self):
        m = self.src.replace(STOP, "(void)0;", 1)
        self.assertEqual(problems(m), [MSG_STOP_COUNT.format(n=0)])

    def test_stop_moved_after_the_pool_reset(self):
        i = self.src.index(STOP)
        j = i + len(STOP)
        rest = self.src[:i] + self.src[j:]
        k = rest.index(POOL_RESET, rest.index("void stop() noexcept override {"))
        k += len(POOL_RESET)
        m = rest[:k] + "\n" + STOP + "\n" + rest[k:]
        self.assertEqual(problems(m), [MSG_STOP_AFTER_POOL])

    def test_stop_moved_into_the_destructor(self):
        i = self.src.index(STOP)
        j = i + len(STOP)
        rest = self.src[:i] + self.src[j:]
        k = rest.index("~ServerImpl() override {") + len("~ServerImpl() override {")
        m = rest[:k] + "\n" + STOP + "\n" + rest[k:]
        self.assertEqual(problems(m), [MSG_STOP_NOT_IN_STOP])

    def test_early_request_stop_deleted(self):
        m = self.src.replace(REQUEST_STOP, "(void)0;", 1)
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_REQ_COUNT.format(n=0)])

    def test_early_request_stop_duplicated(self):
        m = self.src.replace(REQUEST_STOP, REQUEST_STOP + "\n" + REQUEST_STOP, 1)
        self.assertEqual(problems(m), [MSG_REQ_COUNT.format(n=2)])

    def test_early_request_stop_moved_after_the_join(self):
        i = self.src.index(REQUEST_STOP)
        rest = self.src[:i] + self.src[i + len(REQUEST_STOP):]
        k = rest.index(STOP) + len(STOP)
        m = rest[:k] + "\n" + REQUEST_STOP + "\n" + rest[k:]
        got = problems(m)
        self.assertIn(MSG_REQ_AFTER_JOIN, got)
        self.assertIn(MSG_REQ_AFTER_WEB, got)

    def test_early_request_stop_moved_after_the_web_server_stop(self):
        i = self.src.index(REQUEST_STOP)
        rest = self.src[:i] + self.src[i + len(REQUEST_STOP):]
        start = rest.index("void stop() noexcept override {")
        k = rest.index(WEB_STOP, start) + len(WEB_STOP)
        # Guarded and still before the join, so only the web-stop ordering is wrong.
        m = rest[:k] + "\n" + REQUEST_GUARD + " " + REQUEST_STOP + "\n" + rest[k:]
        self.assertEqual(problems(m), [MSG_REQ_AFTER_WEB])

    def test_early_request_stop_before_the_lifecycle_lock(self):
        i = self.src.index(REQUEST_STOP)
        rest = self.src[:i] + self.src[i + len(REQUEST_STOP):]
        k = rest.index("void stop() noexcept override {") + len("void stop() noexcept override {")
        m = rest[:k] + "\n" + REQUEST_GUARD + " " + REQUEST_STOP + "\n" + rest[k:]
        self.assertEqual(problems(m), [MSG_REQ_NOT_LOCKED])

    def test_early_request_stop_without_the_null_guard(self):
        i = self.src.index(REQUEST_GUARD + "\n                " + REQUEST_STOP)
        m = self.src[:i] + "(void)0;\n                " + self.src[i + len(REQUEST_GUARD) + 1 + 16:]
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_REQ_UNGUARDED])

    def test_early_request_stop_moved_into_the_destructor(self):
        i = self.src.index(REQUEST_STOP)
        rest = self.src[:i] + self.src[i + len(REQUEST_STOP):]
        k = rest.index("~ServerImpl() override {") + len("~ServerImpl() override {")
        m = rest[:k] + "\n" + REQUEST_STOP + "\n" + rest[k:]
        self.assertEqual(problems(m), [MSG_REQ_NOT_IN_STOP])

    def test_early_request_stop_inside_if_0_fails(self):
        m = self.src.replace(REQUEST_STOP, "\n#if 0\n" + REQUEST_STOP + "\n#endif\n", 1)
        self.assertEqual(problems(m), [MSG_REQ_COUNT.format(n=0)])

    def test_member_declared_before_the_pool(self):
        i = self.src.index(RECHECK_DECL)
        rest = self.src[:i] + self.src[i + len(RECHECK_DECL):]
        k = rest.index(POOL_DECL)
        m = rest[:k] + RECHECK_DECL + "\n    " + rest[k:]
        # Moved above the pool, the recheck is also above the gate declared right after the pool.
        self.assertEqual(problems(m), [MSG_GATE_BORROWER_ORDER.format(name="pg_collation_recheck_"),
                                       MSG_DECL_ORDER])

    def test_join_moved_before_the_leader_resign(self):
        i = self.src.index(STOP)
        j = i + len(STOP)
        rest = self.src[:i] + "(void)0;" + self.src[j:]
        k = rest.index("leader_elector_->resign();")
        m = rest[:k] + STOP + "\n            " + rest[k:]
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_JOIN_LATE])

    def test_join_moved_before_the_audit_cleanup(self):
        i = self.src.index(STOP)
        j = i + len(STOP)
        rest = self.src[:i] + "(void)0;" + self.src[j:]
        k = rest.index("audit_store_->stop_cleanup();")
        m = rest[:k] + STOP + "\n            " + rest[k:]
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_JOIN_LATE])

    def test_join_moved_before_the_offload_flush(self):
        i = self.src.index(STOP)
        j = i + len(STOP)
        rest = self.src[:i] + "(void)0;" + self.src[j:]
        k = rest.index("offload_target_store_->flush_all();")
        m = rest[:k] + STOP + "\n            " + rest[k:]
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_JOIN_LATE])

    def test_a_renamed_borrowed_step_reports_a_stale_anchor_not_a_wiring_defect(self):
        for step in BEFORE_JOIN:
            with self.subTest(step=step):
                m = self.src.replace(step, step.replace("_", "X", 1), 1)
                self.assertNotEqual(m, self.src)
                self.assertEqual(problems(m), [MSG_STALE_ANCHOR.format(step)])

    def test_start_not_guarded_against_a_refused_thread(self):
        m, n = re.subn(r"try \{\s*pg_collation_recheck_->start\(\);\s*\} catch \(const std::exception& e\) \{.*?pg_collation_recheck_\.reset\(\);\s*\}",
                       "pg_collation_recheck_->start();", self.src, count=1, flags=re.S)
        self.assertEqual(n, 1)
        self.assertEqual(problems(m), [MSG_START_UNGUARDED])

    def test_start_catch_logging_at_warn_not_error(self):
        i = self.src.index(START)
        j = self.src.index("spdlog::error(", i)
        m = self.src[:j] + "spdlog::warn(" + self.src[j + len("spdlog::error("):]
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_START_NOT_ERROR])

    def test_start_catch_without_a_log(self):
        i = self.src.index(START)
        j = self.src.index("spdlog::error(", i)
        m = self.src[:j] + "(void)(" + self.src[j + len("spdlog::error("):]
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_START_NOT_ERROR])

    def test_start_guard_with_the_stop_condition_not_negated(self):
        m = self.src.replace("!stop_requested_.load(std::memory_order_acquire)) {\n                    pg_collation_recheck_",
                             "stop_requested_.load(std::memory_order_acquire)) {\n                    pg_collation_recheck_", 1)
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_UNLOCKED])

    def test_start_guard_without_the_teardown_condition(self):
        m = self.src.replace("if (!teardown_complete_ && !stop_requested_.load(", "if (!stop_requested_.load(", 1)
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_UNLOCKED])

    def test_metrics_seed_deleted(self):
        m = self.src.replace(SEED, "(void)0;", 1)
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_SEED])

    def test_a_collation_series_not_described(self):
        # A regex, not a literal: clang-format may break the call after "(".
        m = re.sub(r"metrics_\.describe\(\s*pg::kCollationLastCompletedGauge,",
                   'metrics_.describe("yuzu_other",', self.src, count=1)
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_DESCRIBE])

    def test_recheck_not_under_the_lifecycle_lock(self):
        i = self.src.index(MAKE)
        window = self.src[max(0, i - 600):i]
        j = window.index("std::lock_guard<std::mutex> life(lifecycle_mu_);")
        m = (self.src[:i - len(window) + j] + "(void)0;" +
             self.src[i - len(window) + j + len("std::lock_guard<std::mutex> life(lifecycle_mu_);"):])
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_UNLOCKED])

    def test_recheck_constructed_before_the_constructor_time_call(self):
        # Move the whole guarded constructor-time call to just after the recheck's start(): the
        # recheck is then constructed before the check it is seeded from.
        i = self.src.index(GUARD + "\n                    " + REPORT)
        j = self.src.index(";", i) + 1
        stmt = self.src[i:j]
        rest = self.src[:i] + self.src[j:]
        k = rest.index(START) + len(START)
        m = rest[:k] + "\n" + stmt + "\n" + rest[k:]
        self.assertIn(MSG_MAKE_BEFORE_CHECK, problems(m))

    def test_start_wrapped_in_if_0_fails(self):
        m = self.src.replace(START, "\n#if 0\n" + START + "\n#endif\n", 1)
        self.assertNotEqual(m, self.src)
        self.assertEqual(problems(m), [MSG_NO_START])

    def test_report_call_inside_if_0_fails(self):
        i = self.src.index(REPORT)
        j = self.src.index(";", i) + 1
        m = self.src[:i] + "\n#if 0\n" + self.src[i:j] + "\n#endif\n" + self.src[j:]
        self.assertEqual(problems(m), [MSG_COUNT.format(n=0)])

    def test_stop_inside_if_0_fails(self):
        m = self.src.replace(STOP, "\n#if 0\n" + STOP + "\n#endif\n", 1)
        self.assertEqual(problems(m), [MSG_STOP_COUNT.format(n=0)])

    def test_if_1_else_keeps_the_live_branch(self):
        live = self.src.replace(START, "\n#if 1\n" + START + "\n#else\n(void)0;\n#endif\n", 1)
        self.assertEqual(problems(live), [])
        # A second copy in the dead `#else` of `#if 1` is not counted.
        dup = self.src.replace(STOP, "\n#if 1\n" + STOP + "\n#else\n" + STOP + "\n#endif\n", 1)
        self.assertEqual(problems(dup), [])
        # `#if 0 ... #else <live> #endif` keeps the else branch.
        els = self.src.replace(START, "\n#if 0\n(void)0;\n#else\n" + START + "\n#endif\n", 1)
        self.assertEqual(problems(els), [])

    def test_nested_and_elif_dead_branches(self):
        nested = self.src.replace(START, "\n#if 0\n#if 1\n" + START + "\n#endif\n#endif\n", 1)
        self.assertEqual(problems(nested), [MSG_NO_START])
        elif0 = self.src.replace(
            START, "\n#if 0\n(void)0;\n#elif 0\n" + START + "\n#endif\n", 1)
        self.assertEqual(problems(elif0), [MSG_NO_START])
        elif_after_1 = self.src.replace(
            START, "\n#if 1\n(void)0;\n#elif 1\n" + START + "\n#endif\n", 1)
        self.assertEqual(problems(elif_after_1), [MSG_NO_START])
        # An unknown condition keeps both branches.
        unknown = self.src.replace(
            START, "\n#ifdef SOME_MACRO\n" + START + "\n#else\n(void)0;\n#endif\n", 1)
        self.assertEqual(problems(unknown), [])

    def test_normalise_ignores_comments_and_literals(self):
        src = '// pg::report_collation_check(\nauto s = "pg::report_collation_check(";\n'
        self.assertEqual(problems(src), [MSG_COUNT.format(n=0)])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
