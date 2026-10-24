#!/usr/bin/env python3
"""#4990 static lexical gate over server/core/src/server.cpp: the Forensics response tier stays wired.

The tier is enforced in the stored-response read seam, but every route class, the live event bus,
the execution tracker, the policy evaluator and the result-set materialiser receive the Forensics
plugin set (and, for the operator-facing surfaces, the visibility resolver) from ONE place:
ServerImpl in server.cpp. Each of those is a setter call or a designated-initialiser field, and
nothing exercises ServerImpl's wiring in a unit test. A refactor could drop one of them and every
unit test would stay green, because a route class built without its plugin set fails CLOSED
(present-empty visibility, an unwired live bus publishes nothing): the surface would quietly lose
Forensics rows for every caller and nobody would be told. This gate pins the statements lexically.

Required statements (each is one requirement id below):
  * the catalogue-derived plugin set is built from the composed capability registry, an empty or
    unsound derivation sets startup_failed_ (boot refusal), the member is declared after the
    registry it is derived from, and forensics_plugins() hands out nullptr only for a failed boot;
  * the plugin set reaches the agent service (live output bus), the execution tracker, the policy
    evaluator, the response routes, the hardware routes, the dashboard routes, the workflow routes
    (executions drawer and bundle paths), REST v1 and MCP; the result-set materialiser reads
    through result_set_members(...) with it; every fixed-plugin poll uses
    for_fixed_plugin_poll(forensics_plugins());
  * the visibility resolver is wired into the response routes, hardware routes, dashboard routes,
    workflow routes, REST v1 and MCP, and is built with every dependency it needs
    (auth routes, RBAC store, management-group store, metrics);
  * the withheld-read counter family is pre-seeded (seed_forensics_tier_metrics);
  * the drawer's Response:Read probe is the QUIET draw-time fleet-read probe, and the drawer's
    audit row is persisted through a real audit sink;
  * the dashboard results fragment's audit sink (set_persist_audit_fn) is wired before its
    registration: an unwired sink reads as "audit off", so a dropped setter silently loses the
    response.forensics.read rows;
  * setters that take effect only at registration run BEFORE the matching register_routes call;
  * lifetime orderings (ORDER_ANCHORS): the plugin-set member is declared before every member that
    borrows it, the agent service gets the set before its listener starts, and MCP gets the set and
    the resolver before the web thread starts;
  * no wiring spells the unwired hatches (a null plugin set passed to a setter or a Deps field,
    for_fixed_plugin_poll(nullptr));
  * the raw failure text of a command response (`resp.error().message()`) is read at EXACTLY the
    sites it is read today in agent_service_impl.cpp (a second file, checked by
    agent_service_problems): the two that feed the stored response row, and the one inside
    failure_text_for_sinks that reduces it for every other sink. A new read is a new sink of text
    the tier does not cover, and it fails here until it is reviewed and counted.

Robustness: comments are stripped with a literal-aware scanner (a string such as "/api/*" must not
open a comment), whitespace is collapsed and removed around punctuation, so line wrapping,
re-indentation and comment text mentioning a token cannot satisfy or break a check. Patterns anchor
on distinctive tokens, never line numbers.

The raw-failure-text pins are lexical too: they count the spellings `X.error().message()`,
`X->error().message()`, any `.message()` / `->message()`, `resp.error()` / `resp->error()` and forbid
the whole-message dumps (`DebugString`, the `Serialize*` and `AppendToString` family, JSON and text
format printers, `GetReflection()`) and the submessage hand-outs (`mutable_error()`,
`release_error()`). A response
renamed to something other than `resp` and then read only through a dump helper outside this file
is not seen (review-enforced), and neither is a read through a dump spelling not listed here.

Lexical only: it cannot see a relocation that keeps the tokens but changes control flow, or a
statement that is present but sits in a branch that never runs (review-enforced). The companion
tests/test_forensics_tier_wiring_lexical_selftest.py deletes each required statement in memory and
requires the gate to name it, so a stale pattern fails loudly instead of passing vacuously.

Usage: python3 -I tests/test_forensics_tier_wiring_lexical.py
"""
from __future__ import annotations

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_CPP = os.path.join("server", "core", "src", "server.cpp")
AGENT_SERVICE_CPP = os.path.join("server", "core", "src", "agent_service_impl.cpp")
TAG = "test_forensics_tier_wiring_lexical"
HINT = (" (this gate pins the #4990 Forensics-tier wiring; if server.cpp was legitimately restructured "
        "or renamed, update tests/test_forensics_tier_wiring_lexical.py and its selftest)")


def strip_comments(text: str) -> str:
    """Drop // and /* */ comments, leaving string, character and raw-string literals intact."""
    out, i, n = [], 0, len(text)
    raw_open = re.compile(r'R"([^()\\\s]{0,16})\(')
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif two == "/*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        elif c == "R" and text[i + 1:i + 2] == '"' and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            m = raw_open.match(text, i)
            if m:
                end = text.find(")" + m.group(1) + '"', m.end())
                j = n if end < 0 else end + len(m.group(1)) + 2
                out.append(text[i:j])
                i = j
            else:
                out.append(c)
                i += 1
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":  # a C++14 digit separator is not a quote
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


_PUNCT = re.compile(r" ?([(){},;=:.&<>*\[\]!?|]|->) ?")


def canonical(src: str) -> str:
    """Comment-free, whitespace-collapsed text with spaces removed around punctuation."""
    t = re.sub(r"\s+", " ", strip_comments(src))
    return _PUNCT.sub(r"\1", t)


# Each row: (id, pattern over canonical(), why). The pattern carries a named group `k`: the key
# statement the selftest deletes. DOTALL is on; gaps are bounded so a deleted statement cannot be
# satisfied by a copy of the same field in a different construction further away.
_FP = r"forensics_plugins\(\)"
_VF = r"forensics_visibility_fn"
REQUIRED: list[tuple[str, str, str]] = [
    ("derive-set",
     r"(?P<k>forensics_plugin_set_=yuzu::server::derive_forensics_plugin_set\(capability_registry_\);)",
     "the Forensics plugin set must be derived from the composed capability registry, once"),
    ("boot-refusal",
     r"if\(!forensics_plugin_set_\)\{const auto defect=yuzu::server::forensics_catalogue_defect\(capability_registry_\);"
     r"spdlog::error\([^;]*\);(?P<k>startup_failed_=true;)\}",
     "an empty or unsound Forensics plugin set must refuse to start (startup_failed_)"),
    ("member-order",
     r"capability_registry_\{YUZU_ALL_CAPABILITY_FRAGMENTS\};.{0,600}?"
     r"(?P<k>std::optional<yuzu::server::ForensicsPluginSet>forensics_plugin_set_;)",
     "the plugin-set member must be declared after the registry it is derived from"),
    ("borrow-accessor",
     r"(?P<k>const yuzu::server::ForensicsPluginSet\*forensics_plugins\(\)const noexcept\{"
     r"return forensics_plugin_set_\?&\*forensics_plugin_set_:nullptr;\})",
     "forensics_plugins() must hand out the derived set, nullptr only for a failed boot"),
    ("metrics-seed",
     r"(?P<k>yuzu::server::seed_forensics_tier_metrics\(metrics_\);)",
     "the withheld-read counter family must be pre-seeded so absent-vs-zero is meaningful"),
    ("agent-service-set",
     r"(?P<k>agent_service_\.set_forensics_plugin_set\(" + _FP + r"\);)",
     "the live output bus must receive the plugin set (unset publishes no output row)"),
    ("tracker-set",
     r"(?P<k>execution_tracker_->set_forensics_plugin_set\(" + _FP + r"\);)",
     "the execution tracker must receive the plugin set (error text sanitisation)"),
    ("policy-evaluator-set",
     r"PolicyEvaluator::Deps\{[^;]{0,1500}?(?P<k>\.forensics_plugins=" + _FP + r")",
     "the policy evaluator must receive the plugin set (a Forensics check scores unknown)"),
    ("response-routes-set",
     r"response::Deps\{[^;]{0,700}?(?P<k>\.forensics_plugins=" + _FP + r")",
     "the response routes must receive the plugin set"),
    ("response-routes-fn",
     r"response::Deps\{[^;]{0,700}?(?P<k>\." + _VF + r"=" + _VF + r")",
     "the response routes must receive the visibility resolver"),
    # NOTE (hardware-routes-fn / -set): these two anchor on the field ORDER at the tail of the
    # HardwareRoutes::Deps initialiser (`.write_gate`, then the visibility fn, then the plugin set,
    # then `});`). Reordering those designated fields breaks THIS gate, not the wiring: update the
    # pattern rather than "fixing" the server.
    ("hardware-routes-fn",
     r"\.write_gate=WriteGate\{resolve_session_fn,cfg_\.csrf_trusted_origins\},(?P<k>\." + _VF + r"=" + _VF + r"),",
     "the hardware routes must receive the visibility resolver"),
    ("hardware-routes-set",
     r"\." + _VF + r"=" + _VF + r",(?P<k>\.forensics_plugins=" + _FP + r"),\}\);",
     "the hardware routes must receive the plugin set"),
    ("hardware-known-plugin",
     r"(?P<k>\.known_plugin_fn=\[this\]\(const std::string&plugin\)\{return capability_registry_\.knows_plugin\(plugin\);\})",
     "the hardware result poll must validate its plugin against the composed catalogue"),
    ("dashboard-set",
     r"(?P<k>dashboard_routes_->set_forensics_plugin_set\(" + _FP + r"\);).*?dashboard_routes_->register_routes\(",
     "the dashboard routes must receive the plugin set before registration"),
    ("dashboard-fn",
     r"(?P<k>dashboard_routes_->set_forensics_visibility_fn\(" + _VF + r"\);).*?dashboard_routes_->register_routes\(",
     "the dashboard routes must receive the visibility resolver before registration"),
    ("dashboard-persist-audit",
     r"(?P<k>dashboard_routes_->set_persist_audit_fn\(audit_fn\);).*?dashboard_routes_->register_routes\(",
     "the dashboard results fragment's response.forensics.read row must be persisted through a real "
     "audit sink (an unwired sink reads as audit-off, not as a failure)"),
    ("workflow-set",
     r"(?P<k>wf_deps\.forensics_plugins=" + _FP + r";).*?workflow_routes_->register_routes\(",
     "the workflow routes (executions drawer, bundle paths) must receive the plugin set"),
    ("workflow-fn",
     r"(?P<k>wf_deps\.forensics_visibility_fn=" + _VF + r";).*?workflow_routes_->register_routes\(",
     "the workflow routes must receive the visibility resolver"),
    ("workflow-quiet-probe",
     r"(?P<k>wf_deps\.response_probe_fn=draw_fleet_read_fn;).*?workflow_routes_->register_routes\(",
     "the drawer's Response:Read probe must be the quiet draw-time fleet-read probe"),
    ("workflow-persist-audit",
     r"(?P<k>wf_deps\.persist_audit_fn=audit_fn;).*?workflow_routes_->register_routes\(",
     "the drawer's response.forensics.read row must be persisted through a real audit sink"),
    ("rest-set",
     r"(?P<k>rest_api_v1_->set_forensics_plugin_set\(" + _FP + r"\);).*?rest_api_v1_->register_routes\(",
     "REST v1 must receive the plugin set BEFORE register_routes (captured by value there)"),
    ("rest-fn",
     r"(?P<k>rest_api_v1_->set_forensics_visibility_fn\(" + _VF + r"\);).*?rest_api_v1_->register_routes\(",
     "REST v1 must receive the visibility resolver BEFORE register_routes"),
    ("mcp-set",
     r"(?P<k>mcp_server_->set_forensics_plugin_set\(" + _FP + r"\);)",
     "MCP must receive the plugin set"),
    ("mcp-fn",
     r"(?P<k>mcp_server_->set_forensics_visibility_fn\(" + _VF + r"\);)",
     "MCP must receive the visibility resolver"),
    ("resolver-auth-routes",
     r"resolve_forensics_visible\(\{[^}]*?(?P<k>\.auth_routes=auth_routes_\.get\(\))",
     "the resolver needs the auth routes (the global Forensics:Read proof)"),
    ("resolver-rbac-store",
     r"resolve_forensics_visible\(\{[^}]*?(?P<k>\.rbac_store=rbac_store_\.get\(\))",
     "the resolver needs the RBAC store (the scoped grant)"),
    ("resolver-mgmt-store",
     r"resolve_forensics_visible\(\{[^}]*?(?P<k>\.mgmt_store=mgmt_group_store_\.get\(\))",
     "the resolver needs the management-group store (the scoped grant)"),
    ("resolver-metrics",
     r"resolve_forensics_visible\(\{[^}]*?(?P<k>\.metrics=&metrics_)\}",
     "the resolver needs the metrics registry (the withheld-read counter)"),
    ("materialiser",
     r"(?P<k>result_set_members\(\*response_store_," + _FP + r",p\))",
     "the result-set materialiser must read through result_set_members with the plugin set"),
]

# Lifetime orderings. Each row's key statement must appear BEFORE its anchor in the file; the
# selftest moves the key statement after the anchor and requires the row to be named.
#   * the plugin-set member is declared before every member that borrows `forensics_plugins()`, so
#     reverse-order destruction keeps the borrowed pointer valid until the borrowers are gone;
#   * the agent service receives the set before its gRPC listener starts (the first ingest runs on
#     a listener thread), and MCP receives it before the web thread starts.
# Anchors are the canonical (comment-free, punctuation-tight) spelling of the declaration or call.
_SET_MEMBER = r"(?P<k>std::optional<yuzu::server::ForensicsPluginSet>forensics_plugin_set_;)"
ORDER_ANCHORS: dict[str, str] = {
    "member-before-agent-service": "detail::AgentServiceImpl agent_service_;",
    "member-before-response-store": "std::unique_ptr<ResponseStore>response_store_;",
    "member-before-execution-tracker": "std::unique_ptr<ExecutionTracker>execution_tracker_;",
    "member-before-policy-evaluator": "std::unique_ptr<PolicyEvaluator>policy_evaluator_;",
    "member-before-rest-api": "std::unique_ptr<RestApiV1>rest_api_v1_;",
    "member-before-mcp-server": "std::unique_ptr<mcp::McpServer>mcp_server_;",
    "member-before-hardware-routes": "std::unique_ptr<HardwareRoutes>hardware_routes_;",
    "member-before-dashboard-routes": "std::unique_ptr<DashboardRoutes>dashboard_routes_;",
    "member-before-workflow-routes": "std::unique_ptr<WorkflowRoutes>workflow_routes_;",
    "agent-service-set-before-listener": "agent_server_=builder.BuildAndStart();",
    "mcp-set-before-web-thread": "web_thread_=std::thread(",
    "mcp-fn-before-web-thread": "web_thread_=std::thread(",
}
for _rid, _anchor in ORDER_ANCHORS.items():
    if _rid.startswith("member-before-"):
        _pat = _SET_MEMBER + r".*?" + re.escape(_anchor)
        _why = ("the plugin-set member must be declared before the member that borrows it, so it is "
                "destroyed after it")
    elif _rid == "agent-service-set-before-listener":
        _pat = (r"(?P<k>agent_service_\.set_forensics_plugin_set\(" + _FP + r"\);).*?" + re.escape(_anchor))
        _why = "the agent service must receive the plugin set before its gRPC listener starts"
    elif _rid == "mcp-set-before-web-thread":
        _pat = (r"(?P<k>mcp_server_->set_forensics_plugin_set\(" + _FP + r"\);).*?" + re.escape(_anchor))
        _why = "MCP must receive the plugin set before the web thread starts serving"
    else:
        _pat = (r"(?P<k>mcp_server_->set_forensics_visibility_fn\(" + _VF + r"\);).*?" + re.escape(_anchor))
        _why = "MCP must receive the visibility resolver before the web thread starts serving"
    REQUIRED.append((_rid, _pat, _why))

# Patterns whose occurrence COUNT is pinned (a deleted site must not hide behind the others).
COUNTED: list[tuple[str, str, int, str]] = [
    ("fixed-plugin-polls",
     r"(?P<k>ResponseTierFilter::for_fixed_plugin_poll\(" + _FP + r"\))", 3,
     "the DEX, TAR and device fixed-plugin polls must each build their tier with the plugin set"),
]

# Spellings that open an unwired hatch. Each must NOT occur.
FORBIDDEN: list[tuple[str, str, str]] = [
    ("null-set-setter", r"set_forensics_plugin_set\((nullptr|NULL|0)\)",
     "a setter handed a null plugin set"),
    ("null-set-field", r"\.forensics_plugins=(nullptr|NULL|0)\b",
     "a Deps field handed a null plugin set"),
    ("null-fixed-poll", r"for_fixed_plugin_poll\((nullptr|NULL|0)\)",
     "for_fixed_plugin_poll handed a null plugin set"),
]


# Patterns over agent_service_impl.cpp whose occurrence count is pinned EXACTLY (a new read is as
# much a defect as a deleted one). Every count is over canonical text, so wrapping and comments
# cannot move it. The first row is the catch-all: ANY `.error().message()` read, whatever it is
# assigned to; the other two say where today's reads are.
EXACT_AGENT_SERVICE: list[tuple[str, str, int, str]] = [
    ("raw-failure-text-reads", r"(?:\.|->)error\(\)(?:\.|->)message\(\)", 3,
     "the raw failure text of a command response is read at exactly three sites; a new read is a "
     "new sink the Forensics tier does not cover (route it through failure_text_for_sinks)"),
    # The same text reached another way: through a pointer or a held reference (`const auto& e =
    # resp.error(); e.message()`), so BOTH halves are pinned separately. Every `.message()` read in
    # this file is today one of the three above, and so is every `resp.error()` accessor.
    ("raw-failure-text-any-message-read", r"(?:\.|->)message\(\)", 3,
     "a `.message()` read anywhere in this file (through a pointer, a held reference, any variable) "
     "is a possible new sink of the raw failure text; there are exactly three today"),
    ("raw-failure-text-error-accessor", r"\bresp(?:\.|->)error\(\)", 3,
     "the response's error submessage is taken at exactly three sites; holding it in a reference "
     "or passing it on is a new way to reach the raw failure text"),
    ("raw-failure-text-stored-row", r"err_detail=resp\.error\(\)\.message\(\);", 2,
     "the stored response row (Subscribe and gateway ingest) keeps the raw text; it is read only "
     "through the tier-filtered stored-response reads"),
    ("raw-failure-text-helper", r"std::string text=resp\.error\(\)\.message\(\);", 1,
     "failure_text_for_sinks is the one place the raw text is reduced for the other sinks"),
    # The tracker write path skips its Forensics lookup when the persisted text equals the incoming
    # one, because the incoming text was already reduced here. Dropping this call would let a raw
    # Forensics failure text through the status upsert unreduced.
    ("tracker-status-text-reduced", r"\bs\.error_detail=failure_text_for_sinks\(", 1,
     "notify_exec_tracker must reduce the status text with failure_text_for_sinks: the tracker "
     "write path relies on the incoming text already being reduced (it skips the lookup when the "
     "persisted text equals it)"),
    # The pinned assignment above is only meaningful if nothing rewrites the field afterwards in
    # the same function. Every write to `s.error_detail` in this file (assignment, compound
    # assignment, or a mutating string call) is counted; the one allowed is the reduction itself.
    ("tracker-status-text-not-rewritten",
     r"\bs\.error_detail(?:=(?!=)| ?\+=|\.(?:append|assign|clear|swap|push_back|insert|replace|resize|erase)\()",
     1,
     "the status text must not be written again after the failure_text_for_sinks reduction: the "
     "tracker write path trusts it as already reduced"),
]


# Spellings that serialise or dump a whole message, including the error text, without ever calling
# `.message()`. None occurs in agent_service_impl.cpp today; each must NOT occur.
FORBIDDEN_AGENT_SERVICE: list[tuple[str, str, str]] = [
    ("raw-failure-text-dump",
     r"(?:Short|Utf8)?DebugString\(|SerializeAsString\(|SerializeToString\(|SerializeToArray\(|"
     r"SerializeToOstream\(|SerializeToCodedStream\(|SerializePartial\w*\(|AppendToString\(|"
     r"AppendPartialToString\(|\bMessageToJson|\bTextFormat\b|GetReflection\(",
     "a whole-message dump of a command response would carry the raw failure text; reduce it with "
     "failure_text_for_sinks and log or store only that"),
    ("raw-failure-text-mutable-error", r"(?:\.|->)(?:mutable_error|release_error|unsafe_arena_release_error)\(\)",
     "mutable_error(), release_error() and unsafe_arena_release_error() hand out the error "
     "submessage; no ingest path needs them"),
]


# ExecutionTracker::update_agent_status trusts its caller to have reduced the failure text at
# ingest (see the precondition on its declaration). Exactly one production caller exists, in
# agent_service_impl.cpp; a second caller, in any file under server/core/src, is a new writer of
# that text and fails here until it is reviewed and counted. Receivers that are the policy or
# deployment stores (unrelated classes with a same-named method) are not tracker calls.
SRC_DIR = os.path.join("server", "core", "src")
TRACKER_CALLER_FILE = "agent_service_impl.cpp"
_TRACKER_CALL = re.compile(r"(?:->|\.)update_agent_status\(")
_TRACKER_PMF = re.compile(r"&ExecutionTracker::update_agent_status\b")
_OTHER_RECEIVERS = ("policy_store", "deployment_store")


def tracker_caller_problems(sources: dict[str, str]) -> list[tuple[str, str]]:
    """(id, message) when ExecutionTracker::update_agent_status is not called from exactly one site.

    `sources` maps a file name (base name) to its text. Comments are stripped first.
    """
    sites: list[str] = []
    for name in sorted(sources):
        t = canonical(sources[name])
        for m in _TRACKER_CALL.finditer(t):
            if any(r in t[max(0, m.start() - 40):m.start()] for r in _OTHER_RECEIVERS):
                continue
            sites.append(name)
        # A pointer to member (`&ExecutionTracker::update_agent_status`) also reaches it.
        sites.extend(name for _ in _TRACKER_PMF.finditer(t))
    out: list[tuple[str, str]] = []
    if sites != [TRACKER_CALLER_FILE]:
        out.append(("tracker-update-agent-status-callers",
                    f"tracker-update-agent-status-callers: ExecutionTracker::update_agent_status must have "
                    f"exactly one call site, in {TRACKER_CALLER_FILE} (the ingest that reduces the failure "
                    f"text); found {len(sites)}: {sites}. A new caller must reduce the text with "
                    f"failure_text_for_sinks first and be reviewed, then be counted here"))
    return out


def read_src_tree() -> dict[str, str]:
    root = os.path.join(REPO_ROOT, SRC_DIR)
    out: dict[str, str] = {}
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            if f.endswith((".cpp", ".hpp", ".h", ".cc")):
                with open(os.path.join(dirpath, f), encoding="utf-8", errors="replace") as fh:
                    out[os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/")] = fh.read()
    return out


def agent_service_problems(src: str) -> list[tuple[str, str]]:
    """(id, message) per violated exact count in agent_service_impl.cpp; [] when clean."""
    t = canonical(src)
    out: list[tuple[str, str]] = []
    for rid, pat, want, why in EXACT_AGENT_SERVICE:
        got = len(re.findall(pat, t, re.S))
        if got != want:
            out.append((rid, f"{rid}: expected exactly {want} occurrences, found {got}: {why}"))
    for rid, pat, why in FORBIDDEN_AGENT_SERVICE:
        if re.search(pat, t, re.S):
            out.append((rid, f"{rid}: {why}"))
    return out


def problems_canonical(t: str) -> list[tuple[str, str]]:
    """(id, message) per violated requirement over already-canonical text; [] when clean."""
    out: list[tuple[str, str]] = []
    for rid, pat, why in REQUIRED:
        if not re.search(pat, t, re.S):
            out.append((rid, f"{rid}: {why}"))
    for rid, pat, want, why in COUNTED:
        got = len(re.findall(pat, t, re.S))
        if got < want:
            out.append((rid, f"{rid}: expected {want} occurrences, found {got}: {why}"))
    for rid, pat, why in FORBIDDEN:
        if re.search(pat, t, re.S):
            out.append((rid, f"{rid}: {why}"))
    return out


def problems(src: str) -> list[tuple[str, str]]:
    return problems_canonical(canonical(src))


def main() -> int:
    path = os.path.join(REPO_ROOT, SERVER_CPP)
    try:
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
    except OSError as e:
        print(f"::error::{TAG}: cannot read {SERVER_CPP}: {e}", file=sys.stderr)
        return 1
    found = problems(src)
    for _rid, msg in found:
        print(f"::error::{TAG}: {SERVER_CPP}: {msg}{HINT}", file=sys.stderr)
    try:
        with open(os.path.join(REPO_ROOT, AGENT_SERVICE_CPP), encoding="utf-8") as fh:
            asrc = fh.read()
    except OSError as e:
        print(f"::error::{TAG}: cannot read {AGENT_SERVICE_CPP}: {e}", file=sys.stderr)
        return 1
    afound = agent_service_problems(asrc)
    for _rid, msg in afound:
        print(f"::error::{TAG}: {AGENT_SERVICE_CPP}: {msg}{HINT}", file=sys.stderr)
    tfound = tracker_caller_problems(read_src_tree())
    for _rid, msg in tfound:
        print(f"::error::{TAG}: {SRC_DIR}: {msg}{HINT}", file=sys.stderr)
    if found or afound or tfound:
        return 1
    print(f"OK: {len(REQUIRED)} wiring statements, {len(COUNTED)} counted sites, "
          f"{len(FORBIDDEN)} forbidden hatches, {len(EXACT_AGENT_SERVICE)} exact counts, "
          f"1 tracker-caller pin, "
          f"{len(FORBIDDEN_AGENT_SERVICE)} forbidden dumps checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
