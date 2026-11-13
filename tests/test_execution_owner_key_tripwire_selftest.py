#!/usr/bin/env python3
"""Self-test for tests/test_execution_owner_key_tripwire.py (#5557).

A tripwire that has never been seen to fail proves nothing. This runs the tripwire's checks against
mutated copies of the real server tree (held in memory, nothing on disk is touched) and asserts each
mutation is caught by the check meant to catch it: a bare `dispatched_by` compare in a handler (also
reversed, `!=`, `.compare(`, split across lines), the Astra bypass `ExecutionScope s{std::in_place};
s->owner = session->username;`, a dropped or literal scope argument on the checked tracker reads, a
string-typed `execution_visible(...)`, a string overload, a mutation request that lost `.owner`, a
raw-username guard replaced by a check on the key, a public string constructor on the key, the entry
refusal deleted from each list gate, a second caller of `require_list_read_unchecked`, a second
definition of the shared predicate, responder or key factory, and a second `ListAuthority`
construction. It also requires the unmutated tree to pass, a comment or string literal holding the
same text NOT to trip, and every frozen entry to be load-bearing (a stale entry fails). Stdlib only.
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "execution_owner_key_tripwire", os.path.join(HERE, "test_execution_owner_key_tripwire.py"))
t = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = t
spec.loader.exec_module(t)

S = t._SRC
FAILURES: list[str] = []


def expect(cond: bool, what: str) -> None:
    if not cond:
        FAILURES.append(what)
        print(f"FAIL: {what}", file=sys.stderr)


def mutate(files, rel, old, new, count=1, regex=False):
    """A copy of `files` with `old` replaced in `rel`; the anchor MUST exist (the selftest fails
    loudly when the source moves, rather than silently testing nothing)."""
    text = files[S + rel]
    if regex:
        out, n = re.subn(old, new, text, count=count, flags=re.DOTALL)
        assert n, f"selftest anchor moved in {rel}: /{old}/"
    else:
        assert old in text, f"selftest anchor moved in {rel}: {old!r}"
        out = text.replace(old, new, count)
    return {**files, S + rel: out}


def fires(check, mutated, prefix) -> bool:
    return any(e.startswith(prefix) for e in check(mutated))


def must_fail(what, check, mutated, prefix):
    expect(fires(check, mutated, prefix), f"{what}: {prefix} must fail")


def main() -> int:
    files = t.read_tree(t.REPO_ROOT, "server")

    # The unmutated tree is clean (the tripwire itself is green), every check individually.
    for label, fn in t.CHECKS:
        expect(fn(files) == [], f"the real tree must pass {label}: {fn(files)[:2]}")
    expect(len(t.BOUND_OWNER_KEYS) == 12 and sum(t.BOUND_OWNER_KEYS.values()) == 12,
           "twelve guarded owner-key handlers are frozen")

    # ---- CHECK 1: dispatched_by compares and uses --------------------------------------------
    anchor_rt = "            scope_arg = confined_list_scope(owner, gate.scope);\n"
    for what, line in (
            ("a bare compare", "const bool mine = e.dispatched_by == session->username;"),
            ("a reversed compare", "const bool mine = session->username == e.dispatched_by;"),
            ("a != compare", "const bool other = e.dispatched_by != session->username;"),
            ("a .compare() call", "const bool mine = e.dispatched_by.compare(session->username) == 0;"),
            ("a split-line compare", "const bool mine = e.dispatched_by\n    ==\n    session->username;"),
            ("a compare on a second receiver", "const bool mine = exec_opt->dispatched_by == username;"),
            ("a restored string filter", "eq.dispatched_by = session->username;"),
            ("a new attribution-style write", "row.dispatched_by = session->username;"),
            ("a JSON-key compare", "const bool mine = j[\"dispatched_by\"] == session->username;")):
        must_fail(what + " in a route", t.check_dispatched_by,
                  mutate(files, "execution_routes.cpp", anchor_rt, anchor_rt + "            " + line + "\n"),
                  "CHECK 1")
    must_fail("the owner-only filter restored to the raw username", t.check_dispatched_by,
              mutate(files, "mcp_server.cpp", "eq.dispatched_by = owner_only_filter(owner);",
                     "eq.dispatched_by = session->username;"), "CHECK 1")
    must_fail("a SQL comparison in a non-tracker file", t.check_dispatched_by,
              mutate(files, "execution_routes.cpp", anchor_rt,
                     anchor_rt + '            auto q2 = "SELECT 1 WHERE dispatched_by = $1";\n'), "CHECK 1")
    must_fail("a second ownership compare spelled like owns()", t.check_dispatched_by,
              mutate(files, "execution_scope_rules.hpp",
                     "[[nodiscard]] bool owns(const Execution& e) const {",
                     "[[nodiscard]] bool owns2(const Execution& e) const { return e.dispatched_by == key_; }\n"
                     "    [[nodiscard]] bool owns(const Execution& e) const {"), "CHECK 1")
    must_fail("the bundle exception edited", t.check_dispatched_by,
              mutate(files, "bundle_orchestrator.cpp", "it->second.dispatched_by != principal",
                     "it->second.dispatched_by == principal"), "CHECK 1")
    # The same text inside a comment, or prose in a string literal, is NOT a compare. (A literal that
    # spells an SQL comparison on the column is flagged on purpose: see the SQL case above.)
    for what, line in (("a line comment", "// if (e.dispatched_by == session->username) {}"),
                       ("a block comment", "/* e.dispatched_by == session->username */"),
                       ("a prose string literal", 'const char* k = "the dispatched_by of the row";')):
        expect(t.check_dispatched_by(mutate(files, "execution_routes.cpp", anchor_rt,
                                            anchor_rt + "            " + line + "\n")) == [],
               f"{what} holding a dispatched_by compare must NOT trip CHECK 1")

    # ---- CHECK 2: scope construction ---------------------------------------------------------
    anchor_rest = "                scope_arg = confined_list_scope(owner, gate.scope);\n"
    for what, snippet in (
            ("Astra's in_place bypass (declaration and owner write)",
             "yuzu::server::ExecutionScope s{std::in_place}; s->owner = session->username;"),
            ("a hand-initialised scope", "yuzu::server::ExecutionScope s{std::in_place};"),
            ("an owner write from the session", "scope_arg->owner = session->username;"),
            ("an owner write through a dot", "scope_arg.value().owner = session->username;"),
            ("a scope emplaced in place", "scope_arg.emplace();"),
            ("an owner assign() call", "scope_arg->owner.assign(session->username);"),
            ("an owner append", "scope_arg->owner += session->username;"),
            ("an owner exchange", "std::exchange(scope_arg->owner, session->username);"),
            ("an owner alias reference", "auto& o = scope_arg->owner; o = session->username;"),
            ("an owner read into a local", "const std::string who = scope_arg->owner;"),
            ("a scope reassigned to nullopt", "scope_arg = std::nullopt;"),
            ("a scope reassigned to a hand-built value", "scope_arg = yuzu::server::ExecutionListScope{};"),
            ("a named ExecutionListScope", "yuzu::server::ExecutionListScope raw; raw.owner = session->username;"),
            ("an optional of the list scope", "auto s = std::optional<yuzu::server::ExecutionListScope>{};"),
            ("make_optional of the scope", "yuzu::server::ExecutionScope s = std::make_optional(x);")):
        must_fail(what, t.check_scope_construction,
                  mutate(files, "rest_api_v1.cpp", anchor_rest, anchor_rest + "                " + snippet + "\n"),
                  "CHECK 2")
    # The pre-fix shape in one compound mutation: an in-place scope filled from the session, a
    # default scope on the tracker declaration and a one-argument call. Each half is caught by its
    # own check; none of the three would have failed the first draft of this tripwire.
    prefix = mutate(mutate(files, "rest_api_v1.cpp", anchor_rest,
                           anchor_rest + "                scope_arg.emplace(); scope_arg->owner = session->username;\n"),
                    "mcp_server.cpp", "query_executions_checked(eq, query_scope)", "query_executions_checked(eq)")
    prefix = mutate(prefix, "execution_tracker.hpp",
                    "query_executions_checked(const ExecutionQuery& q, const ExecutionScope& scope) const;",
                    "query_executions_checked(const ExecutionQuery& q = {}, const ExecutionScope& scope = std::nullopt) const;")
    must_fail("the compound pre-fix shape", t.check_scope_construction, prefix, "CHECK 2")
    must_fail("the compound pre-fix shape", t.check_scope_args, prefix, "CHECK 3")
    must_fail("a new owner read by the tracker", t.check_scope_construction,
              mutate(files, "execution_tracker.cpp", "binds.push_back(scope->owner);",
                     "binds.push_back(scope->owner); binds.push_back(scope->owner);"), "CHECK 2")
    must_fail("the owner field written from a string inside the factory", t.check_scope_construction,
              mutate(files, "execution_scope_rules.hpp", "out.owner = owner.key_;",
                     "out.owner = owner.key_; out.owner = std::string{};"), "CHECK 2")
    must_fail("a designated initialiser owner", t.check_scope_construction,
              mutate(files, "mcp_server.cpp", "ExecutionMutationRequest mreq;",
                     "ExecutionMutationRequest mreq; auto x = Foo{.owner = session->username};"), "CHECK 2")
    expect(t.check_scope_construction(
        mutate(files, "rest_api_v1.cpp", anchor_rest,
               anchor_rest + "                // scope_arg->owner = session->username;\n"
                             '                const char* k = "s->owner = session->username";\n')) == [],
        "a comment or string holding `s->owner = session->username` must NOT trip CHECK 2")

    # ---- CHECK 3: the scope argument ---------------------------------------------------------
    for what, rel, old, new in (
            ("the scope dropped from a route list", "rest_api_v1.cpp",
             "query_executions_checked(q, scope_arg)", "query_executions_checked(q)"),
            ("the scope dropped from a children call", "execution_routes.cpp",
             "get_children_checked(id, scope_arg)", "get_children_checked(id)"),
            ("the scope dropped from MCP list_executions", "mcp_server.cpp",
             "query_executions_checked(eq, query_scope)", "query_executions_checked(eq)"),
            ("a literal nullopt in a route", "workflow_routes.cpp",
             "query_executions_checked(q, scope_arg)", "query_executions_checked(q, std::nullopt)"),
            ("a literal nullopt in MCP children", "mcp_server.cpp",
             "get_children_checked(exec_id, scope_arg)", "get_children_checked(exec_id, std::nullopt)"),
            ("a braced empty scope", "execution_routes.cpp",
             "query_executions_checked(q, scope_arg)", "query_executions_checked(q, {})"),
            ("MCP list_executions moved off its sanctioned scope form", "mcp_server.cpp",
             "const auto query_scope =\n                    confined_list_scope(owner, service_scoped ? gate.scope : unrestricted);",
             "const auto query_scope = confined_list_scope(owner, authz::VisibleSet{});"),
            ("the default scope restored on the declaration", "execution_tracker.hpp",
             "query_executions_checked(const ExecutionQuery& q, const ExecutionScope& scope) const;",
             "query_executions_checked(const ExecutionQuery& q = {}, const ExecutionScope& scope = std::nullopt) const;"),
            ("a default on get_children_checked", "execution_tracker.hpp",
             "get_children_checked(const std::string& parent_id, const ExecutionScope& scope) const;",
             "get_children_checked(const std::string& parent_id, const ExecutionScope& scope = std::nullopt) const;"),
            ("a new unchecked read of the tracker", "health_routes.cpp",
             "deps.execution_tracker->query_executions({.limit = 1000})",
             "deps.execution_tracker->query_executions({.limit = 99999})")):
        must_fail(what, t.check_scope_args, mutate(files, rel, old, new), "CHECK 3")
    # a scope variable whose source is not confined_list_scope(, and a wrapped argument
    must_fail("a scope variable assigned from a hand value before the call", t.check_scope_args,
              mutate(files, "rest_api_v1.cpp", "scope_arg = confined_list_scope(owner, gate.scope);",
                     "scope_arg = yuzu::server::ExecutionScope{};", count=1), "CHECK 3")
    must_fail("a wrapped scope argument", t.check_scope_args,
              mutate(files, "rest_api_v1.cpp", "query_executions_checked(q, scope_arg)",
                     "query_executions_checked(q, [&] { return scope_arg; }())"), "CHECK 3")
    # a new, unfrozen call site (with an intact scope) is a reviewed act
    must_fail("a new checked-read call site", t.check_scope_args,
              mutate(files, "execution_routes.cpp", "auto execs_opt = deps.execution_tracker->query_executions_checked(q, scope_arg);",
                     "auto execs_opt = deps.execution_tracker->query_executions_checked(q, scope_arg);\n"
                     "        auto more = deps.execution_tracker->query_executions_checked(q, scope_arg);"),
              "CHECK 3")

    # ---- CHECK 4: the visibility predicates --------------------------------------------------
    must_fail("a string-typed execution_visible call", t.check_predicate_calls,
              mutate(files, "execution_routes.cpp", "execution_visible(e, statuses, gate.scope, owner)",
                     "execution_visible(e, statuses, gate.scope, session->username)"), "CHECK 4")
    must_fail("a string variable passed as the owner", t.check_predicate_calls,
              mutate(files, "execution_routes.cpp",
                     "        yuzu::server::ExecutionOwnerKey owner; // empty unless a confined, resolved session\n"
                     "        if (gate.scope) {\n            auto session = deps.resolve_session_fn(req);\n"
                     "            username = session ? session->username : std::string{};",
                     "        std::string owner;\n"
                     "        if (gate.scope) {\n            auto session = deps.resolve_session_fn(req);\n"
                     "            username = session ? session->username : std::string{};"), "CHECK 4")
    must_fail("a string-typed admit_confined_mutation call", t.check_predicate_calls,
              mutate(files, "execution_routes.cpp", "gate.scope,\n                                                        owner_key)",
                     "gate.scope,\n                                                        username)"), "CHECK 4")
    must_fail("a three-argument execution_visible call", t.check_predicate_calls,
              mutate(files, "execution_routes.cpp", "execution_visible(e, statuses, gate.scope, owner)",
                     "execution_visible(e, statuses, gate.scope)"), "CHECK 4")
    must_fail("a string overload of execution_visible", t.check_predicate_calls,
              mutate(files, "execution_scope_rules.hpp", "/// Recomputed execution counters, projected to only the in-scope agent",
                     "[[nodiscard]] inline bool execution_visible(const Execution& exec,\n"
                     "                                            const std::vector<AgentExecStatus>& statuses,\n"
                     "                                            const authz::VisibleSet& scope,\n"
                     "                                            const std::string& owner) { return true; }\n"
                     "/// Recomputed execution counters, projected to only the in-scope agent"), "CHECK 4")
    must_fail("a string owner parameter on admit_confined_mutation", t.check_predicate_calls,
              mutate(files, "execution_scope_rules.hpp",
                     "                                                  const ExecutionOwnerKey& owner) {\n    if (statuses.empty())",
                     "                                                  const std::string& owner) {\n    if (statuses.empty())"),
              "CHECK 4")

    # ---- CHECK 5: the mutation request -------------------------------------------------------
    must_fail("a mutation request that lost .owner", t.check_mutation_requests,
              mutate(files, "mcp_server.cpp", "mreq.owner = execution_owner_key(*session);", ""), "CHECK 5")
    must_fail("a mutation owner taken from the raw username", t.check_mutation_requests,
              mutate(files, "rest_api_v1.cpp", "mreq.owner = execution_owner_key(*session);",
                     "mreq.owner = session->username;"), "CHECK 5")
    must_fail("a mutation username taken from the owner key", t.check_mutation_requests,
              mutate(files, "rest_api_v1.cpp", "mreq.username = session->username;",
                     "mreq.username = owner;"), "CHECK 5")
    must_fail("a brace-initialised mutation request", t.check_mutation_requests,
              mutate(files, "mcp_server.cpp", "ExecutionMutationRequest mreq;",
                     "ExecutionMutationRequest mreq{};"), "CHECK 5")
    must_fail("an unlisted mutation request construction", t.check_mutation_requests,
              mutate(files, "workflow_routes.cpp", anchor_rt.strip() + "\n",
                     anchor_rt.strip() + "\n            ExecutionMutationRequest extra;\n"), "CHECK 5")
    must_fail("the mutation request owner retyped to a string", t.check_mutation_requests,
              mutate(files, "execution_mutation.hpp", "ExecutionOwnerKey owner;", "std::string owner;"),
              "CHECK 5")

    # ---- CHECK 6: the raw-username guards ----------------------------------------------------
    must_fail("a raw-username guard replaced by a check on the key", t.check_guards,
              mutate(files, "execution_routes.cpp", "            if (username.empty()) {",
                     "            if (owner.empty()) {"), "CHECK 6")
    must_fail("an MCP guard replaced by a check on the key", t.check_guards,
              mutate(files, "mcp_server.cpp", "if (gate.scope && session->username.empty()) {",
                     "if (gate.scope && owner.empty()) {"), "CHECK 6")
    must_fail("a new unguarded owner-key binding", t.check_guards,
              mutate(files, "workflow_routes.cpp", anchor_rt.strip() + "\n",
                     anchor_rt.strip() + "\n            const ExecutionOwnerKey extra = execution_owner_key(*session);\n"),
              "CHECK 6")
    must_fail("an owner-key binding in a new handler name", t.check_guards,
              mutate(files, "mcp_server.cpp", 'if (tool_name == "get_execution_children") {',
                     'if (tool_name == "get_execution_children_v2") {'), "CHECK 6")

    must_fail("an inert owner-key use in a renamed (new) handler", t.check_guards,
              mutate(files, "mcp_server.cpp", 'if (tool_name == "get_execution_status") {',
                     'if (tool_name == "get_execution_status_v2") {'), "CHECK 6")
    must_fail("a second inert owner-key use in a frozen handler", t.check_guards,
              mutate(files, "mcp_server.cpp",
                     "const bool owns_execution = exec && execution_owner_key(*session).owns(*exec);",
                     "const bool owns_execution = exec && (execution_owner_key(*session).owns(*exec) ||"
                     " execution_owner_key(*session).owns(*exec));"), "CHECK 6")

    # ---- CHECK 7: the key type ---------------------------------------------------------------
    must_fail("a second execution_owner_key definition", t.check_owner_key_type,
              {**files, S + "dashboard_routes.cpp": files[S + "dashboard_routes.cpp"] +
               "\nnamespace yuzu::server { inline ExecutionOwnerKey execution_owner_key(const auth::Session& s, int) { return {}; } }\n"},
              "CHECK 7")
    must_fail("a public string constructor on the key", t.check_owner_key_type,
              mutate(files, "execution_scope_rules.hpp", "    ExecutionOwnerKey() = default;",
                     "    ExecutionOwnerKey() = default;\n    ExecutionOwnerKey(std::string s) : key_(std::move(s)) {}"),
              "CHECK 7")
    must_fail("a public explicit string constructor on the key", t.check_owner_key_type,
              mutate(files, "execution_scope_rules.hpp", "    ExecutionOwnerKey() = default;",
                     "    ExecutionOwnerKey() = default;\n    explicit ExecutionOwnerKey(const char* s) : key_(s) {}"),
              "CHECK 7")
    must_fail("the key class turned into a struct", t.check_owner_key_type,
              mutate(files, "execution_scope_rules.hpp", "class ExecutionOwnerKey {", "struct ExecutionOwnerKey {"),
              "CHECK 7")
    must_fail("a new friend of the key", t.check_owner_key_type,
              mutate(files, "execution_scope_rules.hpp", "    friend std::string owner_only_filter(const ExecutionOwnerKey&);",
                     "    friend std::string owner_only_filter(const ExecutionOwnerKey&);\n"
                     "    friend std::string leak_key(const ExecutionOwnerKey&);"), "CHECK 7")
    must_fail("the key built from an argument outside its header", t.check_owner_key_type,
              mutate(files, "rest_api_v1.cpp", anchor_rest,
                     anchor_rest + "                auto k = ExecutionOwnerKey{session->username};\n"), "CHECK 7")
    must_fail("the service-scope test removed from the factory", t.check_owner_key_type,
              mutate(files, "execution_scope_rules.hpp",
                     "if (!s.token_scope_service.empty() || s.username.empty())", "if (s.username.empty())"),
              "CHECK 7")

    # ---- CHECK 8: the gates ------------------------------------------------------------------
    refusal = (r"        if \(!session->token_scope_service\.empty\(\)\) \{\s*"
               r"refuse_service_scoped_unrestricted\([^;]*?kListRead,[^;]*?kEngineEntry\);\s*return gate;\s*\}\n")
    must_fail("the entry refusal deleted from require_list_read", t.check_gates,
              mutate(files, "auth_routes.cpp", refusal, "", regex=True), "CHECK 8")
    refusal_fleet = (r"        if \(!session->token_scope_service\.empty\(\)\) \{\s*"
                     r"refuse_service_scoped_unrestricted\([^;]*?kFleetRead,[^;]*?kEngineEntry\);\s*"
                     r"return std::unexpected\(authz::GateFailure::Forbidden\);\s*\}\n")
    must_fail("the entry refusal deleted from require_fleet_read", t.check_gates,
              mutate(files, "authz_gates.cpp", refusal_fleet, "", regex=True), "CHECK 8")
    must_fail("the entry refusal no longer first in the fleet-read engine branch", t.check_gates,
              mutate(files, "authz_gates.cpp", "    if (session->is_engine()) {\n        if (!session->token_scope_service.empty()) {",
                     "    if (session->is_engine()) {\n        audit_log(req, \"x\", \"y\", \"\", \"\", \"z\");\n"
                     "        if (!session->token_scope_service.empty()) {"), "CHECK 8")
    must_fail("the entry refusal wrong gate label in list read", t.check_gates,
              mutate(files, "auth_routes.cpp", "authz::UnrestrictedRefusalGate::kListRead,\n"
                     "                                               authz::UnrestrictedRefusalSite::kEngineEntry",
                     "authz::UnrestrictedRefusalGate::kListRead,\n"
                     "                                               authz::UnrestrictedRefusalSite::kPostcondition"),
              "CHECK 8")
    must_fail("require_list_read_unchecked called from a second site", t.check_gates,
              mutate(files, "mcp_server.cpp", "ExecutionMutationRequest mreq;",
                     "ExecutionMutationRequest mreq;\n                auto g2 = auth_->require_list_read_unchecked(req, res, \"X\", \"Read\");"),
              "CHECK 8")
    must_fail("the postcondition removed from the require_list_read wrapper", t.check_gates,
              mutate(files, "auth_routes.cpp",
                     r"!\(gate\.session && authz::service_scope_authority_ok\(\*gate\.session, gate\.scope\)\)",
                     "false", regex=True), "CHECK 8")
    # The postconditions are pinned FAIL CLOSED: each of these keeps the predicate and the responder
    # textually present and still has to fail.
    must_fail("the wrapper backstop reverted to fail OPEN on an admit with no session", t.check_gates,
              mutate(files, "auth_routes.cpp",
                     r"!\(gate\.session && authz::service_scope_authority_ok\(\*gate\.session, gate\.scope\)\)",
                     "gate.session && !authz::service_scope_authority_ok(*gate.session, gate.scope)",
                     regex=True), "CHECK 8")
    must_fail("the wrapper postcondition made dead with `false &&`", t.check_gates,
              mutate(files, "auth_routes.cpp", "if (gate.admitted &&\n        !(gate.session",
                     "if (false && gate.admitted &&\n        !(gate.session"), "CHECK 8")
    must_fail("the wrapper refusal no longer un-admits the gate", t.check_gates,
              mutate(files, "auth_routes.cpp", "        gate.admitted = false;\n        gate.scope.reset();\n"
                     "        const auth::Session no_session{};",
                     "        gate.scope.reset();\n        const auth::Session no_session{};"), "CHECK 8")
    must_fail("the wrapper refusal no longer drops the scope", t.check_gates,
              mutate(files, "auth_routes.cpp", "        gate.admitted = false;\n        gate.scope.reset();\n"
                     "        const auth::Session no_session{};",
                     "        gate.admitted = false;\n        const auth::Session no_session{};"), "CHECK 8")
    must_fail("admit_fleet_read refuses but falls through to mint the authority", t.check_gates,
              mutate(files, "authz_gates.cpp", "        return std::unexpected(authz::GateFailure::InvariantViolated);\n", ""),
              "CHECK 8")
    must_fail("admit_fleet_read refusal returns the wrong failure", t.check_gates,
              mutate(files, "authz_gates.cpp", "return std::unexpected(authz::GateFailure::InvariantViolated);",
                     "return std::unexpected(authz::GateFailure::Forbidden);"), "CHECK 8")
    must_fail("admit_fleet_read postcondition made dead with `false &&`", t.check_gates,
              mutate(files, "authz_gates.cpp", "if (!authz::service_scope_authority_ok(session, scope)) {",
                     "if (false && !authz::service_scope_authority_ok(session, scope)) {"), "CHECK 8")
    must_fail("a second definition of service_scope_authority_ok", t.check_gates,
              {**files, S + "dashboard_routes.cpp": files[S + "dashboard_routes.cpp"] +
               "\nnamespace yuzu::server::authz { inline bool service_scope_authority_ok(const auth::Session&, int) { return true; } }\n"},
              "CHECK 8")
    must_fail("a lambda copy of service_scope_authority_ok", t.check_gates,
              {**files, S + "dashboard_routes.cpp": files[S + "dashboard_routes.cpp"] +
               "\nstatic auto service_scope_authority_ok = [](const auth::Session&, int) { return true; };\n"},
              "CHECK 8")
    must_fail("a second definition of refuse_service_scoped_unrestricted", t.check_gates,
              {**files, S + "dashboard_routes.cpp": files[S + "dashboard_routes.cpp"] +
               "\nvoid AuthRoutes::refuse_service_scoped_unrestricted(const httplib::Request&, httplib::Response&,"
               " const auth::Session&, const std::string&, authz::UnrestrictedRefusalGate,"
               " authz::UnrestrictedRefusalSite) {}\n"},
              "CHECK 8")
    must_fail("a second ListAuthority construction", t.check_gates,
              mutate(files, "authz_gates.cpp", "return admit_fleet_read(req, res, *session, perm, std::nullopt); // TOP: unfiltered",
                     "return authz::ListAuthority(std::nullopt); // TOP: unfiltered"), "CHECK 8")
    must_fail("a ListAuthority built outside authz_gates.cpp", t.check_gates,
              {**files, S + "dashboard_routes.cpp": files[S + "dashboard_routes.cpp"] +
               "\nstatic auto la = authz::ListAuthority(std::nullopt);\n"}, "CHECK 8")
    must_fail("the funnel without its postcondition", t.check_gates,
              mutate(files, "authz_gates.cpp", r"if \(!authz::service_scope_authority_ok\(session, scope\)\) \{",
                     "if (false) {", regex=True), "CHECK 8")

    # ---- the frozen lists are load-bearing: a stale entry fails ------------------------------
    for name, table, key, value in (
            ("DISPATCHED_BY", t.DISPATCHED_BY, (S + "mcp_server.cpp", "; ghost.dispatched_by = nobody ;"), (1, "x")),
            ("OWNER_ACCESS", t.OWNER_ACCESS, (S + "mcp_server.cpp", "^ ghost.owner = x"), (1, "x")),
            ("SCOPE_CALLS", t.SCOPE_CALLS, (S + "mcp_server.cpp", "query_executions_checked", "ghost", ()), (1, "x")),
            ("UNCHECKED_CALLS", t.UNCHECKED_CALLS, (S + "server.cpp", "query_executions", "ghost"), (1, "x"))):
        table[key] = value
        try:
            check = {"DISPATCHED_BY": t.check_dispatched_by, "OWNER_ACCESS": t.check_scope_construction,
                     "SCOPE_CALLS": t.check_scope_args, "UNCHECKED_CALLS": t.check_scope_args}[name]
            expect(any("stale" in e for e in check(files)), f"a stale {name} entry must fail")
        finally:
            del table[key]
    saved = dict(t.BOUND_OWNER_KEYS)
    try:
        t.BOUND_OWNER_KEYS[(S + "mcp_server.cpp", "ghost_tool")] = 1
        expect(any("stale" in e for e in t.check_guards(files)), "a stale BOUND_OWNER_KEYS handler must fail")
    finally:
        t.BOUND_OWNER_KEYS.clear()
        t.BOUND_OWNER_KEYS.update(saved)
    expect(t.check_dispatched_by(files) == [], "the frozen tables were restored after the stale-entry probes")

    # ---- a pure reformat of a frozen spelling must NOT trip -------------------------------------
    for what, rel, old, new in (
            ("a re-wrapped confined_list_scope initialiser", "mcp_server.cpp",
             "const auto query_scope =\n                    confined_list_scope(owner, service_scoped ? gate.scope : unrestricted);",
             "const auto query_scope = confined_list_scope(owner, service_scoped ?\n  gate.scope\n : unrestricted);"),
            ("an unbraced-to-braced attribution write", "mcp_server.cpp",
             "if (gate.scope && !service_scoped)\n                    // Non-empty: the raw username was guarded above.\n"
             "                    eq.dispatched_by = owner_only_filter(owner);",
             "if (gate.scope && !service_scoped) {\n                    eq.dispatched_by = owner_only_filter(owner);\n                }"),
            ("a re-wrapped scope call", "execution_routes.cpp",
             "query_executions_checked(q, scope_arg)", "query_executions_checked(\n    q,\n    scope_arg)")):
        mutated = mutate(files, rel, old, new)
        expect(t.run_all(mutated) == [], f"{what} must NOT trip any check: {t.run_all(mutated)[:2]}")

    # ---- the scanner itself ------------------------------------------------------------------
    sneaky = {**files, S + "sneaky.cpp": 'const char* k = "/api/*";\nbool b = e.dispatched_by == u;\n/* c */\n'}
    must_fail("a compare after a string containing /*", t.check_dispatched_by, sneaky, "CHECK 1")
    spliced = {**files, S + "spliced.cpp": "bool b = e.dispatched_by \\\n == u;\n"}
    must_fail("a compare split by a line splice", t.check_dispatched_by, spliced, "CHECK 1")
    raw = {**files, S + "raw.cpp": 'const char* k = R"x(the e.dispatched_by of "a" // b)x";\nint z = 1;\n'}
    expect(t.check_dispatched_by(raw) == [], "a raw string literal holding the identifier is not code")

    if FAILURES:
        return 1
    print("OK: the #5557 owner-key tripwire fails on every mutation it is meant to catch")
    return 0


if __name__ == "__main__":
    sys.exit(main())
