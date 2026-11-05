#!/usr/bin/env python3
"""#5047 static lexical gate over server/core/src/server.cpp's three TierPolicyFn wiring sites, plus
(clause 5, #6065 PR-Q) the one-definition-two-uses wiring of the dispatch authorizer closure.

AuthRoutes::gateless_tier_policy_fn() (auth_routes.hpp) is the SOLE production factory for a
gate-less-route TierPolicyFn -- the result-set sites' own comments say so explicitly: "never
re-inline this as a local lambda; a second copy is exactly how the original clause-5 violation
this belt exists to prevent could recur unreviewed at a 9th call site."

The unit test in test_auth_routes.cpp ("gateless_tier_policy_fn -- the REAL production
TierPolicyFn...") drives the factory directly and proves its OUTPUT is correct, but it cannot
observe whether server.cpp actually calls the factory -- a reverted call site (back to a
hand-rolled lambda naming .permission, reopening the clause-5 gap) or a new undocumented
call site would pass every existing test. This gate closes that:

  1. `result_set::Deps`'s designated-init field (the dashboard-fragment wiring,
     /fragments/result-sets/*) reads `.tier_policy_fn = auth_routes_->gateless_tier_policy_fn(),`
     -- exactly once, as an ACTIVE line (anchored start-of-line, not merely a substring -- a
     commented-out copy of this exact text does not count; #5047 governance re-review finding,
     independently converged by two reviewers).
  2. `rest_api_v1_->register_routes(...)`'s positional tier-policy argument (the REST
     /api/v1/result-sets JSON wiring) is `auth_routes_->gateless_tier_policy_fn(),` -- exactly
     once, same anchored-active-line requirement. It is no longer the FINAL argument: #6065 PR-Q
     appends `authorize_dispatch` after it, so the line ends in a comma, not `);`. The only other
     active line of this shape is clause 1's, which carries the `.tier_policy_fn = ` prefix and
     so cannot satisfy this anchored pattern.
  3. `CryptoRoutes::Deps`'s LAST designated-init field (the /crypto dashboard layout routes,
     GET/PUT /api/v1/crypto/dashboard/layout -- the caller's OWN layout, keyed by the session
     username, so there is no securable grant to admit against: a gate-less route like the
     result-set family, ADR-0070 widget dashboard) reads
     `.tier_policy_fn = auth_routes_->gateless_tier_policy_fn()});` -- exactly once, same
     anchored-active-line requirement. The `});` close distinguishes it from clause 1's `,`.
  4. The literal substring `auth_routes_->gateless_tier_policy_fn()` appears in server.cpp
     EXACTLY THREE TIMES, total -- DELIBERATELY a broad, unanchored substring count (not just the
     sum of clauses 1-3): it exists to catch a brand-new fourth call site written in some OTHER
     shape none of clauses 1-3 would recognise. The trade-off: an unrelated comment that happens to
     quote the literal string would also trip this clause -- a false RED, never a false GREEN.

  5. (#6065 PR-Q) The dispatch-chokepoint pre-check closure is defined ONCE in server.cpp
     (`const mcp::McpServer::AuthorizeDispatchFn authorize_dispatch =`) and used EXACTLY twice,
     both as ACTIVE lines: as REST's trailing `register_routes` argument (`authorize_dispatch);`)
     and in `set_authorize_dispatch_fn(authorize_dispatch)`. The REST parameter is defaulted so
     that unrelated callers still compile, which means dropping the trailing argument compiles
     cleanly and every POST and DELETE /api/v1/quarantine then answers 500 -- and no unit test, whose rig
     wires its own closure, can see it. A second definition (a route-local copy) is the drift the
     closure exists to prevent. Same anchored-active-line requirement as clauses 1 and 2.

  6. (#6065 PR-Q, rest-audit-principal-reresolution)
     `rest_api_v1_->set_audit_as_session_fn(auth_routes_->audit_as_session_fn());` is called
     EXACTLY ONCE in server.cpp as an ACTIVE line: the production writer is the AuthRoutes
     factory (whose closure a test drives through a real AuditStore), never a hand-rolled lambda
     whose eight same-typed parameters could be transposed unseen. The setter's parameter is optional by
     construction (every other `RestApiV1` rig leaves it unwired), so dropping the call compiles
     cleanly and every POST and DELETE /api/v1/quarantine then answers 500 -- and no unit test,
     whose rig wires its own writer, can see it. Same anchored-active-line requirement as above.
     The call must also PRECEDE `rest_api_v1_->register_routes(`: the writer is captured by value
     there, so a call placed after it keeps the count at one and every unit rig green while
     production answers 500 on both routes.

  7. (#2146 D2a, per-step workflow credential check) The workflow-execute REST route's credential
     liveness seam is wired: `wf_deps.revalidate = ` is assigned EXACTLY ONCE as an active line, and
     the line `return auth_routes_->revalidate_stream(req, principal);` appears EXACTLY TWICE as
     active lines (that assignment's body, and the MCP `StreamRevalidateFn` lambda beside
     `build_handler`'s arguments, which `execute_workflow` also reads). Both seams are OPTIONAL by
     construction (an empty one is "no check", so every unit rig leaves it unwired), which means
     dropping either compiles cleanly, passes every unit test, and leaves a revoked credential able
     to finish a workflow run it started; only production wiring can be pinned, here.

  8. (#2146 sec-3/I1/I6, workflow run cap, shutdown drain and audit) The seams of the workflow-execute
     twins are OPTIONAL by construction (a null `StreamBudget` is "unmetered", an empty `draining`
     is "never draining", an empty audit sink is "audit off", a `{}` control disables the deadline,
     the idempotency claim, the stop level and the safety hooks), so dropping or rewriting any of
     them compiles and passes every unit rig, which wires its own. Pinned as active lines in
     server.cpp, each EXACTLY ONCE: `wf_deps.stream_budget = stream_budget_.get();` (the one
     ADR-0034 budget the held-open cap leases from); `wf_deps.draining` and
     `mcp_server_->set_draining_fn` with the body `draining_ || stop_requested_` (REST and MCP
     admission refuse a new run once shutdown begins); the run adapter's
     `return engine->execute(..., control);` (the whole control reaches the
     engine, never `{}`; `on_admitted` travels inside it, the engine has no positional parameter); `wf_deps.audit_fn` and `wf_deps.persist_audit_fn` (the REST route's audit
     sinks; an unwired sink passes vacuously as "audit off"); and `workflow_engine_->set_should_stop`
     with its body (stop wins over draining); and the idempotency pre-check beside the run port
     (`WorkflowIdempotencyLookupFn`, workflow_run_port.hpp, NOT a `WorkflowApi` method):
     `return engine->find_execution_by_key(caller.principal, idempotency_key);` (the principal is the
     authenticated caller's own, never a parameter), `wf_deps.workflow_idempotency_lookup = ...;`
     and `mcp_server_->set_workflow_idempotency_lookup_fn(...);` with the SAME function the run
     port's neighbours get (unwired, a keyed call is refused as "engine not available", so a
     dropped line fails every execute rather than losing replay protection, but only production
     wiring can show it). The drain loop's own feed is pinned in
     tests/unit/server/test_shutdown_join_order.cpp.

Static/text-only, no build required -- a lexical gate, not a semantic one: it cannot see a
relocation that keeps the same tokens but changes the surrounding control flow, nor a `#if 0` /
`/* */` block that comments out an entire real site while preserving its exact leading
whitespace and text -- both stay review-enforced concerns clauses 1-3's anchoring cannot reach.

Known limitation (NICE, not fixed): clause 4 only catches a new call that reuses the
gateless_tier_policy_fn() literal. A wholly new gate-less route wired with its OWN fresh inline
lambda -- one that never references gateless_tier_policy_fn() at all -- is invisible to this
gate; that class of regression stays a plain-review concern.

Lines are counted per line: split on "\\n", one count per line, never str.count. The file
is read with universal newlines, so a CRLF checkout is matched the same as LF (all sources are
LF today). A missing source now raises in setUp instead of a `::error::` line.

Usage: python3 tests/test_tier_policy_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"
TAG = "test_tier_policy_wiring_lexical"
CALL = "auth_routes_->gateless_tier_policy_fn()"
DESIGNATED = r"[ \t\r\f\v]*\.tier_policy_fn = auth_routes_->gateless_tier_policy_fn\(\),"
POSITIONAL = r"[ \t\r\f\v]*auth_routes_->gateless_tier_policy_fn\(\),"
CRYPTO = r"[ \t\r\f\v]*\.tier_policy_fn = auth_routes_->gateless_tier_policy_fn\(\)\}\);"
EXPECTED_TOTAL = 3
CLOSURE_DEF = r"[ \t\r\f\v]*const mcp::McpServer::AuthorizeDispatchFn authorize_dispatch =.*"
CLOSURE_REST = r"[ \t\r\f\v]*authorize_dispatch\);"
CLOSURE_MCP = r"[ \t\r\f\v]*mcp_server_->set_authorize_dispatch_fn\(authorize_dispatch\);"
AUDIT_SESSION = r"[ \t\r\f\v]*rest_api_v1_->set_audit_as_session_fn\(auth_routes_->audit_as_session_fn\(\)\);"
REGISTER_ROUTES = r"[ \t\r\f\v]*rest_api_v1_->register_routes\("
REVALIDATE_ASSIGN = r"[ \t\r\f\v]*wf_deps\.revalidate = .*"
REVALIDATE_BODY = r"[ \t\r\f\v]*return auth_routes_->revalidate_stream\(req, principal\);"
# Clause 8: multi-line, matched over the whole source with re.M; `^[ \t]*` keeps a `//` copy out.
_STOP_OR_DRAIN = (r"\{\s*return draining_\.load\(std::memory_order_acquire\) \|\|\s*"
                  r"stop_requested_\.load\(std::memory_order_acquire\);\s*\}")
WF_STREAM_BUDGET = r"^[ \t]*wf_deps\.stream_budget = stream_budget_\.get\(\);.*$"
WF_DRAINING = r"^[ \t]*wf_deps\.draining = \[this\] " + _STOP_OR_DRAIN + r";"
MCP_DRAINING = r"^[ \t]*mcp_server_->set_draining_fn\(\[this\] " + _STOP_OR_DRAIN + r"\);"
RUN_ADAPTER = (r"^[ \t]*return engine->execute\(workflow_id, agent_ids, std::move\(dispatch_fn\),\s*"
               r"std::move\(condition_fn\), control\);")
IDEMP_LOOKUP = (r"^[ \t]*workflow_idempotency_lookup_fn = \[engine = workflow_engine_\.get\(\)\]\(\s*"
                r"const yuzu::server::DispatchCaller& caller,\s*"
                r"const std::string& idempotency_key\) \{\s*"
                r"return engine->find_execution_by_key\(caller\.principal, idempotency_key\);")
WF_IDEMP = r"^[ \t]*wf_deps\.workflow_idempotency_lookup = workflow_idempotency_lookup_fn;.*$"
MCP_IDEMP = (r"^[ \t]*mcp_server_->set_workflow_idempotency_lookup_fn\("
             r"workflow_idempotency_lookup_fn\);")
WF_AUDIT_FN = r"^[ \t]*wf_deps\.audit_fn = audit_fn;.*$"
WF_PERSIST_AUDIT_FN = r"^[ \t]*wf_deps\.persist_audit_fn = audit_fn;.*$"
SHOULD_STOP = (r"^[ \t]*workflow_engine_->set_should_stop\(\[this\] \{\s*"
               r"if \(stop_requested_\.load\(std::memory_order_acquire\)\)\s*"
               r"return yuzu::server::WorkflowStopLevel::kStop;\s*"
               r"if \(draining_\.load\(std::memory_order_acquire\)\)\s*"
               r"return yuzu::server::WorkflowStopLevel::kDraining;\s*"
               r"return yuzu::server::WorkflowStopLevel::kNone;\s*\}\);")


def count_rx(pattern, src):
    return len(re.findall(pattern, src, re.M))


WORKFLOW_PINS = (
    ("wf_deps.stream_budget", WF_STREAM_BUDGET),
    ("wf_deps.draining", WF_DRAINING),
    ("mcp_server_->set_draining_fn", MCP_DRAINING),
    ("engine->execute", RUN_ADAPTER),
    ("workflow_idempotency_lookup_fn", IDEMP_LOOKUP),
    ("wf_deps.workflow_idempotency_lookup", WF_IDEMP),
    ("set_workflow_idempotency_lookup_fn", MCP_IDEMP),
    ("wf_deps.audit_fn", WF_AUDIT_FN),
    ("wf_deps.persist_audit_fn", WF_PERSIST_AUDIT_FN),
    ("set_should_stop", SHOULD_STOP),
)
WORKFLOW_PIN_ADVICE = {
    "wf_deps.stream_budget": "'wf_deps.stream_budget = stream_budget_.get();' -- a null budget is unmetered, so the "
                             "workflow run cap and the held-open lease count nothing",
    "wf_deps.draining": "'wf_deps.draining = [this] { return draining_ || stop_requested_; };' -- an empty one is "
                        "'never draining', so REST admits runs during shutdown",
    "mcp_server_->set_draining_fn": "'mcp_server_->set_draining_fn([this] { return draining_ || stop_requested_; });' "
                                    "-- an unset one is 'never draining', so MCP admits runs during shutdown",
    "engine->execute": "the run adapter's 'return engine->execute(workflow_id, agent_ids, std::move(dispatch_fn), "
                       "std::move(condition_fn), control);' -- a '{}' control disables the "
                       "deadline, the idempotency claim, the stop level and the safety hooks",
    "workflow_idempotency_lookup_fn": "the idempotency lookup 'return engine->find_execution_by_key(caller.principal, "
                                      "idempotency_key);' -- the principal must be the authenticated caller's own, "
                                      "never a supplied parameter",
    "wf_deps.workflow_idempotency_lookup": "'wf_deps.workflow_idempotency_lookup = workflow_idempotency_lookup_fn;' -- "
                                           "unwired, the REST execute route refuses every keyed call as 'engine not "
                                           "available'",
    "set_workflow_idempotency_lookup_fn": "'mcp_server_->set_workflow_idempotency_lookup_fn("
                                          "workflow_idempotency_lookup_fn);' -- unwired, every MCP execute_workflow "
                                          "call (all keyed) is refused as 'engine not available'",
    "wf_deps.audit_fn": "'wf_deps.audit_fn = audit_fn;' -- an unwired sink is 'audit off' to the workflow route",
    "wf_deps.persist_audit_fn": "'wf_deps.persist_audit_fn = audit_fn;' -- the persisted sink the route prefers; "
                                "unwired it falls back to the best-effort one",
    "set_should_stop": "'workflow_engine_->set_should_stop([this] {...});' with stop_requested_ -> kStop checked "
                       "before draining_ -> kDraining -- an unset one means no run ever learns of a shutdown",
}


def problems(src):
    """One message per violated clause, in clause order (1 to 8); [] when clean."""
    lines = src.split("\n")
    total = sum(1 for ln in lines if CALL in ln)
    designated = sum(1 for ln in lines if re.fullmatch(DESIGNATED, ln))
    positional = sum(1 for ln in lines if re.fullmatch(POSITIONAL, ln))
    crypto = sum(1 for ln in lines if re.fullmatch(CRYPTO, ln))
    closure_def = sum(1 for ln in lines if re.fullmatch(CLOSURE_DEF, ln))
    closure_rest = sum(1 for ln in lines if re.fullmatch(CLOSURE_REST, ln))
    closure_mcp = sum(1 for ln in lines if re.fullmatch(CLOSURE_MCP, ln))
    audit_session = sum(1 for ln in lines if re.fullmatch(AUDIT_SESSION, ln))
    setter_at = [i for i, ln in enumerate(lines) if re.fullmatch(AUDIT_SESSION, ln)]
    register_at = [i for i, ln in enumerate(lines) if re.match(REGISTER_ROUTES, ln)]
    revalidate_assign = sum(1 for ln in lines if re.fullmatch(REVALIDATE_ASSIGN, ln))
    revalidate_body = sum(1 for ln in lines if re.fullmatch(REVALIDATE_BODY, ln))
    wf_counts = {name: count_rx(pat, src) for name, pat in WORKFLOW_PINS}
    out = []
    if designated != 1:
        out.append("expected exactly 1 designated-init site ('.tier_policy_fn = auth_routes_->gateless_tier_policy_fn(),' "
                   f"-- the dashboard-fragment result_set::Deps wiring), found {designated}. A reversion to a "
                   "hand-rolled lambda here reopens the #5047 clause-5 gap on /fragments/result-sets/*.")
    if positional != 1:
        out.append("expected exactly 1 positional-arg site ('auth_routes_->gateless_tier_policy_fn(),' -- the REST "
                   f"rest_api_v1_->register_routes(...) wiring), found {positional}. A reversion to a hand-rolled "
                   "lambda here reopens the #5047 clause-5 gap on /api/v1/result-sets.")
    if crypto != 1:
        out.append("expected exactly 1 crypto-layout site ('.tier_policy_fn = auth_routes_->gateless_tier_policy_fn()});' "
                   f"-- the CryptoRoutes::Deps wiring), found {crypto}. A reversion to a hand-rolled lambda here "
                   "reopens the #5047 clause-5 gap on /api/v1/crypto/dashboard/layout.")
    if total != EXPECTED_TOTAL:
        out.append("expected the literal 'auth_routes_->gateless_tier_policy_fn()' to appear EXACTLY THREE TIMES in "
                   f"server.cpp (the three known call sites), found {total}. A count above 3 means an undocumented "
                   "new call site was added outside this gate's knowledge -- extend this script in the same change, "
                   "per gateless_tier_policy_fn()'s own doc comment (auth_routes.hpp: 'every server.cpp wiring "
                   "site calls this SAME function').")
    if (closure_def, closure_rest, closure_mcp) != (1, 1, 1):
        out.append("expected the dispatch authorizer closure to be defined exactly once "
                   "('const mcp::McpServer::AuthorizeDispatchFn authorize_dispatch =') and used exactly once as "
                   "REST's trailing register_routes argument ('authorize_dispatch);') and once as "
                   "'mcp_server_->set_authorize_dispatch_fn(authorize_dispatch);'; found "
                   f"definition={closure_def}, rest-arg={closure_rest}, mcp-wiring={closure_mcp}. A dropped "
                   "REST argument compiles (the parameter is defaulted) and makes POST and DELETE /api/v1/quarantine "
                   "answer 500; a second definition is a route-local copy that can drift from MCP's.")
    if audit_session != 1:
        out.append("expected 'rest_api_v1_->set_audit_as_session_fn(auth_routes_->audit_as_session_fn());' exactly once "
                   "in server.cpp as an active line (the AuthRoutes factory, not a lambda); "
                   f"found {audit_session}. A dropped call compiles (the setter is optional) and makes "
                   "POST and DELETE /api/v1/quarantine answer 500; a second call is a second writer that can drift.")
    if len(register_at) != 1:
        out.append("expected exactly 1 active 'rest_api_v1_->register_routes(' line in server.cpp, found "
                   f"{len(register_at)}; the setter-order check below cannot run without it, so a reformatted "
                   "or renamed call must update this gate in the same change.")
    if audit_session == 1 and len(register_at) == 1 and setter_at[0] > register_at[0]:
        out.append("'rest_api_v1_->set_audit_as_session_fn(' must be called BEFORE 'rest_api_v1_->register_routes(': "
                   "the writer is captured by value at registration, so a later call leaves it empty and POST and "
                   "DELETE /api/v1/quarantine answer 500.")
    if (revalidate_assign, revalidate_body) != (1, 2):
        out.append("expected 'wf_deps.revalidate = ' assigned exactly once and "
                   "'return auth_routes_->revalidate_stream(req, principal);' exactly twice (the REST workflow "
                   "assignment's body and the MCP StreamRevalidateFn lambda) as active lines in server.cpp; found "
                   f"assignment={revalidate_assign}, body={revalidate_body}. Either seam is optional and an "
                   "empty one is 'no check', so a dropped line compiles and passes every unit rig while a "
                   "revoked credential finishes the workflow run it started.")
    for name, _ in WORKFLOW_PINS:
        if wf_counts[name] != 1:
            out.append(f"expected {WORKFLOW_PIN_ADVICE[name]} exactly once as an active line in server.cpp; found "
                       f"{wf_counts[name]}. The seam is optional by construction, so a dropped or rewritten line "
                       "compiles and passes every unit rig (each wires its own) while production loses the control.")
    return out


DESIGNATED_LINE = "                            .tier_policy_fn = auth_routes_->gateless_tier_policy_fn(),\n"
POSITIONAL_LINE = "            auth_routes_->gateless_tier_policy_fn(),\n"
CRYPTO_LINE = "                               .tier_policy_fn = auth_routes_->gateless_tier_policy_fn()});\n"
CLOSURE_REST_LINE = "            authorize_dispatch);\n"
CLOSURE_MCP_LINE = "            mcp_server_->set_authorize_dispatch_fn(authorize_dispatch);\n"
AUDIT_SESSION_LINE = "        rest_api_v1_->set_audit_as_session_fn(auth_routes_->audit_as_session_fn());\n"
REVALIDATE_ASSIGN_LINE = "        wf_deps.revalidate = [this](const httplib::Request& req, const std::string& principal) {\n"
REVALIDATE_BODY_LINE = "\n            return auth_routes_->revalidate_stream(req, principal);\n"  # leading newline: the MCP site is indented deeper
LAMBDA = "[](const auto&) { return TierPolicy{}; }"
STREAM_BUDGET_LINE = "        wf_deps.stream_budget = stream_budget_.get(); // ADR-0034: one budget, every surface\n"
WF_DRAINING_HEAD = "        wf_deps.draining = [this] {\n"
MCP_DRAINING_HEAD = "            mcp_server_->set_draining_fn([this] {\n"
RUN_ADAPTER_TAIL = "                                       std::move(condition_fn), control);\n"
IDEMP_LOOKUP_BODY = "                return engine->find_execution_by_key(caller.principal, idempotency_key);\n"
WF_IDEMP_LINE = ("        wf_deps.workflow_idempotency_lookup = workflow_idempotency_lookup_fn; "
                 "// and the same lookup\n")
MCP_IDEMP_LINE = "            mcp_server_->set_workflow_idempotency_lookup_fn(workflow_idempotency_lookup_fn);\n"
AUDIT_FN_LINE = "        wf_deps.audit_fn = audit_fn;\n"
PERSIST_AUDIT_FN_LINE = "        wf_deps.persist_audit_fn = audit_fn; // #4990: the drawer's response.forensics.read row\n"
SHOULD_STOP_HEAD = "                workflow_engine_->set_should_stop([this] {\n"
SHOULD_STOP_STOP = ("                    if (stop_requested_.load(std::memory_order_acquire))\n"
                    "                        return yuzu::server::WorkflowStopLevel::kStop;\n")
SHOULD_STOP_DRAIN = ("                    if (draining_.load(std::memory_order_acquire))\n"
                     "                        return yuzu::server::WorkflowStopLevel::kDraining;\n")


class TierPolicyWiringLexical(unittest.TestCase):
    def setUp(self):
        self.src = SERVER_CPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.src)
        for m in p:
            print(f"\n::error::{TAG}: {m}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        src = self.src
        for a in (DESIGNATED_LINE, POSITIONAL_LINE, CRYPTO_LINE, CLOSURE_REST_LINE, CLOSURE_MCP_LINE, AUDIT_SESSION_LINE,
                  REVALIDATE_ASSIGN_LINE, REVALIDATE_BODY_LINE, STREAM_BUDGET_LINE, WF_DRAINING_HEAD, MCP_DRAINING_HEAD,
                  RUN_ADAPTER_TAIL, AUDIT_FN_LINE, PERSIST_AUDIT_FN_LINE, SHOULD_STOP_HEAD, SHOULD_STOP_STOP,
                  SHOULD_STOP_DRAIN):
            n = src.count(a)
            self.assertEqual(n, 1, f"mutation anchor must match exactly once, found {n}; update the constant: {a!r}")
        # (name, mutated source, the clause fragments that must appear; len(p) pins that no other clause fires)
        cases = [
            ("T1 designated reverted to a lambda",
             src.replace(DESIGNATED_LINE, DESIGNATED_LINE.replace(CALL, LAMBDA), 1),
             ["designated-init", "EXACTLY THREE"]),
            ("T2 designated line commented out (anchoring proof: clause 1 only)",
             src.replace(DESIGNATED_LINE, "// " + DESIGNATED_LINE, 1),
             ["designated-init"]),
            ("T3 positional reverted to a lambda",
             src.replace(POSITIONAL_LINE, POSITIONAL_LINE.replace(CALL, LAMBDA), 1),
             ["positional-arg", "EXACTLY THREE"]),
            ("T4 fourth call appended (clause 4 only)",
             src + "    auth_routes_->gateless_tier_policy_fn();\n",
             ["EXACTLY THREE"]),
            ("T14 crypto layout site reverted to a lambda",
             src.replace(CRYPTO_LINE, CRYPTO_LINE.replace(CALL, LAMBDA), 1),
             ["crypto-layout", "EXACTLY THREE"]),
            ("T15 crypto layout site commented out (anchoring proof: clause 3 only)",
             src.replace(CRYPTO_LINE, "// " + CRYPTO_LINE, 1),
             ["crypto-layout"]),
            ("T5 REST trailing authorize_dispatch argument dropped (compiles: the param is defaulted)",
             src.replace(CLOSURE_REST_LINE, "            );\n", 1),
             ["authorizer closure"]),
            ("T6 MCP wiring dropped",
             src.replace(CLOSURE_MCP_LINE, "", 1),
             ["authorizer closure"]),
            ("T7 a route-local second definition appended",
             src + "    const mcp::McpServer::AuthorizeDispatchFn authorize_dispatch = {};\n",
             ["authorizer closure"]),
            ("T8 session audit writer wiring dropped (compiles: the setter is optional)",
             src.replace(AUDIT_SESSION_LINE, "        rest_api_v1_->unrelated(\n", 1),
             ["set_audit_as_session_fn"]),
            ("T9 session audit writer wiring commented out (anchoring proof)",
             src.replace(AUDIT_SESSION_LINE, "// " + AUDIT_SESSION_LINE, 1),
             ["set_audit_as_session_fn"]),
            ("T10 a second session audit writer appended",
             src + AUDIT_SESSION_LINE,
             ["set_audit_as_session_fn"]),
            ("T12 register_routes call reformatted so the order check cannot find it",
             src.replace("        rest_api_v1_->register_routes(", "        rest_api_v1_\n            ->register_routes(", 1),
             ["register_routes"]),
            ("T13 the writer wired with a hand-rolled lambda instead of the AuthRoutes factory",
             src.replace(AUDIT_SESSION_LINE, "        rest_api_v1_->set_audit_as_session_fn([](const auto&...) { return true; });\n", 1),
             ["set_audit_as_session_fn"]),
            ("T16 the REST workflow revalidate assignment dropped (compiles: the seam is optional)",
             src.replace(REVALIDATE_ASSIGN_LINE, "        wf_deps.unrelated = [this](const httplib::Request& req, const std::string& principal) {\n", 1),
             ["wf_deps.revalidate"]),
            ("T17 the REST workflow revalidate assignment commented out (anchoring proof)",
             src.replace(REVALIDATE_ASSIGN_LINE, "// " + REVALIDATE_ASSIGN_LINE, 1),
             ["wf_deps.revalidate"]),
            ("T18 the REST workflow revalidate body replaced by a constant answer",
             src.replace(REVALIDATE_BODY_LINE, "\n            return auth::CredentialCheck::kValid;\n", 1),
             ["wf_deps.revalidate"]),
            ("T19 a third revalidate_stream body appended",
             src + REVALIDATE_BODY_LINE.lstrip("\n"),
             ["wf_deps.revalidate"]),
            ("T20 the workflow stream budget wiring dropped (compiles: a null budget is unmetered)",
             src.replace(STREAM_BUDGET_LINE, STREAM_BUDGET_LINE.replace("wf_deps.stream_budget", "wf_deps.unrelated"), 1),
             ["wf_deps.stream_budget"]),
            ("T21 the workflow stream budget wiring commented out (anchoring proof)",
             src.replace(STREAM_BUDGET_LINE, "// " + STREAM_BUDGET_LINE, 1),
             ["wf_deps.stream_budget"]),
            ("T22 the workflow stream budget wired to nullptr",
             src.replace(STREAM_BUDGET_LINE, STREAM_BUDGET_LINE.replace("stream_budget_.get()", "nullptr"), 1),
             ["wf_deps.stream_budget"]),
            ("T23 a second stream budget assignment appended",
             src + STREAM_BUDGET_LINE,
             ["wf_deps.stream_budget"]),
            ("T24 wf_deps.draining dropped (compiles: an empty one is never draining)",
             src.replace(WF_DRAINING_HEAD, WF_DRAINING_HEAD.replace("wf_deps.draining", "wf_deps.unrelated"), 1),
             ["wf_deps.draining"]),
            ("T25 wf_deps.draining answers only draining_ (stop_requested_ dropped)",
             src.replace(WF_DRAINING_HEAD + "            return draining_.load(std::memory_order_acquire) ||\n"
                         "                   stop_requested_.load(std::memory_order_acquire);\n",
                         WF_DRAINING_HEAD + "            return draining_.load(std::memory_order_acquire);\n", 1),
             ["wf_deps.draining"]),
            ("T26 wf_deps.draining always false",
             src.replace(WF_DRAINING_HEAD, WF_DRAINING_HEAD + "            return false;\n", 1),
             ["wf_deps.draining"]),
            ("T27 mcp set_draining_fn dropped (compiles: an unset one is never draining)",
             src.replace(MCP_DRAINING_HEAD, MCP_DRAINING_HEAD.replace("set_draining_fn", "set_unrelated_fn"), 1),
             ["set_draining_fn"]),
            ("T28 mcp set_draining_fn commented out (anchoring proof)",
             src.replace(MCP_DRAINING_HEAD, "// " + MCP_DRAINING_HEAD, 1),
             ["set_draining_fn"]),
            ("T29 mcp set_draining_fn always false",
             src.replace(MCP_DRAINING_HEAD, MCP_DRAINING_HEAD + "                return false;\n", 1),
             ["set_draining_fn"]),
            ("T30 the run adapter passes an empty control instead of `control`",
             src.replace(RUN_ADAPTER_TAIL, RUN_ADAPTER_TAIL.replace("condition_fn), control", "condition_fn), {}"), 1),
             ["engine->execute"]),
            ("T31 the run adapter drops the control argument",
             src.replace(RUN_ADAPTER_TAIL, RUN_ADAPTER_TAIL.replace(", control);", ");"), 1),
             ["engine->execute"]),
            ("T32 the run adapter passes a default-constructed control",
             src.replace(RUN_ADAPTER_TAIL,
                         RUN_ADAPTER_TAIL.replace("condition_fn), control", "condition_fn), "
                                                  "yuzu::server::WorkflowRunControl{}"), 1),
             ["engine->execute"]),
            ("T33 the workflow route audit sink dropped (compiles: unwired is audit off)",
             src.replace(AUDIT_FN_LINE, AUDIT_FN_LINE.replace("wf_deps.audit_fn", "wf_deps.unrelated"), 1),
             ["wf_deps.audit_fn"]),
            ("T34 the workflow route persisted audit sink dropped",
             src.replace(PERSIST_AUDIT_FN_LINE,
                         PERSIST_AUDIT_FN_LINE.replace("wf_deps.persist_audit_fn", "wf_deps.unrelated"), 1),
             ["wf_deps.persist_audit_fn"]),
            ("T35 the workflow route persisted audit sink commented out (anchoring proof)",
             src.replace(PERSIST_AUDIT_FN_LINE, "// " + PERSIST_AUDIT_FN_LINE, 1),
             ["wf_deps.persist_audit_fn"]),
            ("T36 the workflow route audit sink wired to an empty function",
             src.replace(AUDIT_FN_LINE, AUDIT_FN_LINE.replace("= audit_fn", "= {}"), 1),
             ["wf_deps.audit_fn"]),
            ("T37 set_should_stop wiring dropped (compiles: an unset one never learns of a shutdown)",
             src.replace(SHOULD_STOP_HEAD, SHOULD_STOP_HEAD.replace("set_should_stop", "set_unrelated"), 1),
             ["set_should_stop"]),
            ("T38 set_should_stop wiring commented out (anchoring proof)",
             src.replace(SHOULD_STOP_HEAD, "// " + SHOULD_STOP_HEAD, 1),
             ["set_should_stop"]),
            ("T39 set_should_stop checks draining_ before stop_requested_ (stop must win)",
             src.replace(SHOULD_STOP_STOP + SHOULD_STOP_DRAIN, SHOULD_STOP_DRAIN + SHOULD_STOP_STOP, 1),
             ["set_should_stop"]),
            ("T40 set_should_stop maps stop_requested_ to kDraining",
             src.replace(SHOULD_STOP_STOP, SHOULD_STOP_STOP.replace("kStop", "kDraining"), 1),
             ["set_should_stop"]),
            ("T41 the idempotency lookup answers a supplied principal instead of the caller's",
             src.replace(IDEMP_LOOKUP_BODY, IDEMP_LOOKUP_BODY.replace("caller.principal", "idempotency_key"), 1),
             ["find_execution_by_key"]),
            ("T42 the idempotency lookup always answers no run bound (a repeat would dispatch again)",
             src.replace(IDEMP_LOOKUP_BODY,
                         "                return std::expected<std::optional<yuzu::server::WorkflowIdempotentRun>, "
                         "std::string>{std::nullopt};\n", 1),
             ["find_execution_by_key"]),
            ("T43 wf_deps.workflow_idempotency_lookup dropped (compiles: unwired is engine not available)",
             src.replace(WF_IDEMP_LINE, WF_IDEMP_LINE.replace("wf_deps.workflow_idempotency_lookup", "wf_deps.unrelated"), 1),
             ["wf_deps.workflow_idempotency_lookup"]),
            ("T44 wf_deps.workflow_idempotency_lookup commented out (anchoring proof)",
             src.replace(WF_IDEMP_LINE, "// " + WF_IDEMP_LINE, 1),
             ["wf_deps.workflow_idempotency_lookup"]),
            ("T45 mcp set_workflow_idempotency_lookup_fn dropped",
             src.replace(MCP_IDEMP_LINE, MCP_IDEMP_LINE.replace("set_workflow_idempotency_lookup_fn", "set_unrelated_fn"), 1),
             ["set_workflow_idempotency_lookup_fn"]),
            ("T46 mcp set_workflow_idempotency_lookup_fn wired to an empty function",
             src.replace(MCP_IDEMP_LINE, MCP_IDEMP_LINE.replace("(workflow_idempotency_lookup_fn)", "({})"), 1),
             ["set_workflow_idempotency_lookup_fn"]),
            ("T11 the writer wired after register_routes (count stays one)",
             src.replace(AUDIT_SESSION_LINE, "        rest_api_v1_->unrelated(\n", 1) + AUDIT_SESSION_LINE,
             ["BEFORE"]),
        ]
        for name, mutated, present in cases:
            with self.subTest(mutation=name):
                p = problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                joined = "\n".join(p)
                for frag in present:
                    self.assertIn(frag, joined)
                self.assertEqual(len(p), len(present))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
