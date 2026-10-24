#!/usr/bin/env python3
"""Self-test for tests/test_forensics_tier_wiring_lexical.py (#4990).

A gate that has never been seen to fail proves nothing. This runs the gate against in-memory
mutations of the real server/core/src/server.cpp (nothing on disk is touched):

  * for EVERY required wiring statement, delete its key text and require the gate to name exactly
    that requirement (so a stale or over-broad pattern fails loudly instead of passing vacuously);
  * for each counted site, delete the first occurrence and require the count check to fire;
  * for each forbidden hatch, append a spelling of it and require the gate to flag it;
  * move a registration-order setter after its register_routes call and require the gate to flag
    the order for REST v1, the dashboard and the workflow routes;
  * the raw failure-text reads in agent_service_impl.cpp are pinned EXACTLY: appending one more
    read, or deleting one of the stored-row reads or the helper's read, is named;
  * a comment that merely mentions a required token must not satisfy a requirement, and a string
    literal containing a comment opener must not hide a real statement.

Stdlib only.
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "forensics_tier_wiring_lexical", os.path.join(HERE, "test_forensics_tier_wiring_lexical.py"))
g = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = g
spec.loader.exec_module(g)

FAILURES: list[str] = []


def expect(cond: bool, what: str) -> None:
    if not cond:
        FAILURES.append(what)
        print(f"FAIL: {what}", file=sys.stderr)


def ids(found: list[tuple[str, str]]) -> set[str]:
    return {rid for rid, _ in found}


def main() -> int:
    with open(os.path.join(g.REPO_ROOT, g.SERVER_CPP), encoding="utf-8") as fh:
        raw = fh.read()
    t = g.canonical(raw)

    expect(g.problems_canonical(t) == [], "the real server.cpp must pass the gate")
    expect(len(g.REQUIRED) >= 41, "the required-statement list must not shrink silently")

    # Delete each required statement's key text.
    for rid, pat, _why in g.REQUIRED:
        m = re.search(pat, t, re.S)
        if not m:
            expect(False, f"{rid}: pattern no longer matches the real source (stale pattern)")
            continue
        a, b = m.span("k")
        mutated = t[:a] + t[b:]
        found = ids(g.problems_canonical(mutated))
        expect(rid in found, f"{rid}: deleting its statement was NOT detected")

    # Counted sites: delete the first occurrence.
    for rid, pat, want, _why in g.COUNTED:
        ms = list(re.finditer(pat, t, re.S))
        expect(len(ms) >= want, f"{rid}: real source has fewer than {want} sites")
        if ms:
            a, b = ms[0].span("k")
            mutated = t[:a] + "(void)0" + t[b:]
            expect(rid in ids(g.problems_canonical(mutated)),
                   f"{rid}: deleting one counted site was NOT detected")

    # Forbidden hatches.
    hatches = {
        "null-set-setter": "rest_api_v1_->set_forensics_plugin_set(nullptr);",
        "null-set-field": "wf_deps.forensics_plugins = nullptr;; .forensics_plugins = nullptr,",
        "null-fixed-poll": "auto tier = ResponseTierFilter::for_fixed_plugin_poll(nullptr);",
    }
    for rid, spelling in hatches.items():
        mutated = g.canonical(raw + "\n" + spelling + "\n")
        expect(rid in ids(g.problems_canonical(mutated)), f"{rid}: hatch spelling was NOT detected")
    expect({r for r, _, _ in g.FORBIDDEN} == set(hatches), "every forbidden hatch has a selftest spelling")

    # Registration-order: move the setter text after its register_routes call.
    orders = [("rest-set", "rest_api_v1_->register_routes("),
              ("rest-fn", "rest_api_v1_->register_routes("),
              ("dashboard-set", "dashboard_routes_->register_routes("),
              ("dashboard-fn", "dashboard_routes_->register_routes("),
              ("dashboard-persist-audit", "dashboard_routes_->register_routes("),
              ("workflow-set", "workflow_routes_->register_routes("),
              ("workflow-fn", "workflow_routes_->register_routes(")]
    # Lifetime orderings: the key statement moved after its anchor (a declaration or a call).
    orders += list(g.ORDER_ANCHORS.items())
    for rid, reg in orders:
        pat = next(p for r, p, _ in g.REQUIRED if r == rid)
        m = re.search(pat, t, re.S)
        a, b = m.span("k")
        stmt = t[a:b]
        without = t[:a] + t[b:]
        # Put the statement after the LAST occurrence of the register call so none follows it.
        last = without.rfind(reg)
        expect(last >= 0, f"{rid}: register call not found in the real source")
        # Everything after the last register call must not contain another one, so the moved
        # statement has no register call after it.
        moved = without[:last] + without[last:] + stmt
        expect(rid in ids(g.problems_canonical(moved)),
               f"{rid}: a setter placed after the matching register_routes was NOT detected")

    # A comment that mentions a required token must not satisfy a requirement.
    needle = "agent_service_.set_forensics_plugin_set(forensics_plugins());"
    expect(needle in raw, "selftest anchor moved: update the selftest")
    commented = raw.replace(needle, "// " + needle, 1)
    expect("agent-service-set" in ids(g.problems(commented)),
           "a commented-out statement must not satisfy its requirement")

    # A string literal holding a comment opener must not hide a real statement after it.
    hidden = raw.replace(needle, 'static const char* kUrl = "http://x/*"; ' + needle, 1)
    expect("agent-service-set" not in ids(g.problems(hidden)),
           "a string literal containing a comment opener must not hide a real statement")

    # The raw failure-text reads in agent_service_impl.cpp: an EXACT count, so an addition is
    # caught as well as a deletion.
    with open(os.path.join(g.REPO_ROOT, g.AGENT_SERVICE_CPP), encoding="utf-8") as fh:
        asrc = fh.read()
    expect(g.agent_service_problems(asrc) == [], "the real agent_service_impl.cpp must pass the exact counts")
    for extra in ("std::string leak = resp.error().message();",
                  "notify(resp.error().message());",
                  "auto m =\n   resp.error()\n      .message();",
                  "const auto& e = other.error().message();",
                  "auto m = p->error().message();",
                  "auto m = (&resp)->error().message();"):
        expect("raw-failure-text-reads" in ids(g.agent_service_problems(asrc + "\n" + extra + "\n")),
               f"a new raw failure-text read was NOT detected: {extra!r}")
    # The same text reached through a held reference, a pointer, or a dump.
    for extra, want in (("const auto& e = resp.error();\n auto m = e.message();",
                         "raw-failure-text-error-accessor"),
                        ("const auto& e = resp.error();\n auto m = e.message();",
                         "raw-failure-text-any-message-read"),
                        ("const auto* e = &resp.error();\n auto m = e->message();",
                         "raw-failure-text-any-message-read"),
                        ("auto m = holder->message();", "raw-failure-text-any-message-read"),
                        ("auto m = resp.error().message();", "raw-failure-text-error-accessor"),
                        ("auto m = resp.ShortDebugString();", "raw-failure-text-dump"),
                        ("auto m = resp.DebugString();", "raw-failure-text-dump"),
                        ("auto m = resp.Utf8DebugString();", "raw-failure-text-dump"),
                        ("auto m = resp.SerializeAsString();", "raw-failure-text-dump"),
                        ("resp.SerializeToString(&out);", "raw-failure-text-dump"),
                        ("auto m = resp.error().ShortDebugString();", "raw-failure-text-dump"),
                        ("resp.mutable_error()->set_message(x);", "raw-failure-text-mutable-error"),
                        ("resp->mutable_error()->set_message(x);", "raw-failure-text-mutable-error"),
                        ("auto* e = resp.release_error();", "raw-failure-text-mutable-error"),
                        ("auto* e = resp->unsafe_arena_release_error();", "raw-failure-text-mutable-error"),
                        # The accessor row must see the pointer spelling too: only this row fires.
                        ("auto e = resp->error();", "raw-failure-text-error-accessor"),
                        # Whole-message dumps that never call .message(): one case per alternative,
                        # so dropping an alternative from the dump pattern turns this red.
                        ("resp.SerializeToArray(buf, n);", "raw-failure-text-dump"),
                        ("resp.SerializeToOstream(&os);", "raw-failure-text-dump"),
                        ("resp.SerializeToCodedStream(&cs);", "raw-failure-text-dump"),
                        ("resp.SerializePartialToString(&s);", "raw-failure-text-dump"),
                        ("resp.AppendToString(&s);", "raw-failure-text-dump"),
                        ("resp.AppendPartialToString(&s);", "raw-failure-text-dump"),
                        ("google::protobuf::util::MessageToJsonString(resp, &s);", "raw-failure-text-dump"),
                        ("google::protobuf::TextFormat::PrintToString(resp, &s);", "raw-failure-text-dump"),
                        ("const auto* r = resp.GetReflection();", "raw-failure-text-dump")):
        expect(want in ids(g.agent_service_problems(asrc + "\n" + extra + "\n")),
               f"{want} was NOT raised for: {extra!r}")
    # The accessor-only spelling must raise ONLY the accessor row (not another row that would
    # mask a loosened accessor pattern).
    expect(ids(g.agent_service_problems(asrc + "\nauto e = resp->error();\n")) ==
           {"raw-failure-text-error-accessor"},
           "resp->error() alone must be named by the accessor row and no other")
    expect(g.agent_service_problems(asrc + "\n// auto m = resp.DebugString(); e->message();\n") == [],
           "a comment mentioning a dump or a message read is not one")
    stored = "err_detail = resp.error().message();"
    expect(asrc.count(stored) == 2, "selftest anchor moved: the two stored-row reads")
    expect("raw-failure-text-stored-row" in ids(g.agent_service_problems(asrc.replace(stored, "err_detail = {};", 1))),
           "deleting a stored-row raw read was NOT detected")
    helper = "std::string text = resp.error().message();"
    expect(asrc.count(helper) == 1, "selftest anchor moved: the helper's read")
    expect("raw-failure-text-helper" in ids(g.agent_service_problems(asrc.replace(helper, "std::string text;", 1))),
           "deleting the helper's raw read was NOT detected")
    sinks = "s.error_detail = failure_text_for_sinks(command_id, resp);"
    expect(asrc.count(sinks) == 1, "selftest anchor moved: the tracker status text reduction")
    expect("tracker-status-text-reduced" in ids(g.agent_service_problems(
               asrc.replace(sinks, "s.error_detail = resp.error().message();", 1))),
           "replacing the tracker status text reduction was NOT detected")
    expect("tracker-status-text-reduced" in ids(g.agent_service_problems(asrc.replace(sinks, "// " + sinks, 1))),
           "a commented-out tracker status text reduction must not count")
    # The reduced status text is not rewritten afterwards, and update_agent_status has one caller.
    for rewrite in ("s.error_detail = resp.error().message();", "s.error_detail += extra;",
                    "s.error_detail.clear();", "s.error_detail.append(extra);",
                    "s.error_detail=\n  other;"):
        expect("tracker-status-text-not-rewritten" in ids(g.agent_service_problems(asrc + "\n" + rewrite + "\n")),
               f"a rewrite of the reduced status text was NOT detected: {rewrite!r}")
    expect("tracker-status-text-not-rewritten" not in ids(g.agent_service_problems(
               asrc + "\n// s.error_detail = x;\n if (s.error_detail == y) {}\n sr.error_detail = z;\n")),
           "a comment, a comparison or another variable is not a rewrite of the status text")
    tree = g.read_src_tree()
    expect(g.tracker_caller_problems(tree) == [], "the real tree must have exactly one tracker caller")
    expect(g.TRACKER_CALLER_FILE in tree, "selftest anchor moved: the tracker caller file")
    for fname, extra in (("other_routes.cpp", "tracker->update_agent_status(id, s);"),
                         ("other_routes.cpp", "execution_tracker_.update_agent_status(id, s);"),
                         ("other_routes.cpp", "tracker_ptr_\n   ->update_agent_status(id, s);"),
                         ("other_routes.cpp", "auto f = &ExecutionTracker::update_agent_status;"),
                         (g.TRACKER_CALLER_FILE, "tracker->update_agent_status(id, s);")):
        crafted = dict(tree)
        crafted[fname] = crafted.get(fname, "") + "\n" + extra + "\n"
        expect("tracker-update-agent-status-callers" in ids(g.tracker_caller_problems(crafted)),
               f"a second tracker caller was NOT detected: {extra!r} in {fname}")
    crafted = dict(tree)
    crafted["other_routes.cpp"] = ("// tracker->update_agent_status(id, s);\n"
                                   "d_.policy_store->update_agent_status(p, a, st, r, gen);\n"
                                   "deployment_store_->update_agent_status(d, s);\n")
    expect(g.tracker_caller_problems(crafted) == [],
           "a comment, a PolicyStore call or a deployment-store call is not a tracker caller")
    crafted = dict(tree)
    crafted[g.TRACKER_CALLER_FILE] = crafted[g.TRACKER_CALLER_FILE].replace("tracker->update_agent_status(", "tracker->noop(", 1)
    expect("tracker-update-agent-status-callers" in ids(g.tracker_caller_problems(crafted)),
           "removing the only tracker caller was NOT detected")
    expect(g.agent_service_problems(asrc.replace(stored, "// " + stored, 1)) != [],
           "a commented-out stored-row read must not count")
    expect(g.agent_service_problems(asrc + "\n// resp.error().message() is only mentioned here\n") == [],
           "a comment mentioning the accessor is not a read")

    if FAILURES:
        print(f"{len(FAILURES)} selftest failure(s)", file=sys.stderr)
        return 1
    print(f"OK: {len(g.REQUIRED)} deletions, {len(g.COUNTED)} counted, {len(g.FORBIDDEN)} hatches, "
          f"{len(orders)} order, 2 comment/literal and the exact raw-read mutations all caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
