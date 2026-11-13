#!/usr/bin/env python3
"""#5557 tripwire: ownership-based execution admission is keyed on the owner key, and neither list
gate hands a service-scoped session unrestricted authority.

BEST-EFFORT LEXICAL, NOT A CONTROL-FLOW PROOF. This reads the non-test C++ under server/ after
comments, preprocessor lines and the CONTENT of string literals have been blanked (line splices
joined first), and pins the shapes the fix introduced. It is the structural backstop for the typed
compile-time controls (`ExecutionOwnerKey` has no public string constructor, `execution_visible()`
and `admit_confined_mutation()` take the key, `query_executions_checked()` has no default scope),
catching what a type system cannot: a new ownership compare that never names the key, a scope built
by hand, a dropped scope argument, a gate branch that lost its refusal. See the routed row in
`.claude/routed-concerns-access-control.md` ("Service-scoped API token confinement", clause 7).

CHECK 1 (dispatched_by). Every code occurrence of the identifier `dispatched_by`, and every string
  literal that is exactly `"dispatched_by"` (a JSON key) or spells an SQL comparison on it, is keyed
  by (file, a local token window: the left token, the receiver chain, and up to three tokens to the
  right, stopping at `;`, `{` or `}`) and must equal a FROZEN multiset. The ownership COMPARE exists in
  exactly two entries: `ExecutionOwnerKey::owns` and the documented read-side bundle-manifest
  exception in `bundle_orchestrator.cpp`. Everything else is an attribution WRITE at dispatch/create
  time, a response-row projection, a declaration, or the tracker's own SQL, each with its reason. A
  new use, a changed window or a second copy fails until reviewed.
CHECK 2 (scope construction). Every `.owner` / `->owner` member access under server/ is a frozen
  window: `ExecutionListScope::owner` is written once (in `confined_list_scope()`) and read by the
  tracker's SQL, the mutation request's `owner` takes `execution_owner_key(...)`, and the rest is the
  schedule display flag; so `s->owner = session->username`, `.assign(`, `+=`, `std::exchange` and an
  alias reference all fail. `ExecutionListScope` is named only in `execution_tracker.{hpp,cpp}` and
  `execution_scope_rules.hpp`; an `ExecutionScope` variable outside those files is declared
  uninitialised and assigned only from `confined_list_scope(`, never from `std::in_place`,
  `emplace`, a literal or a member write.
CHECK 3 (scope argument). Every call of `query_executions_checked(` / `get_children_checked(`
  passes the scope argument explicitly. The (file, callee, scope-argument spelling, what that
  variable was initialised from) tuples are FROZEN, so MCP `list_executions` keeps its two sanctioned
  forms (`confined_list_scope(owner, ...)` plus the owner-only filter assignment pinned by CHECK 1),
  and a literal `std::nullopt` is allowed at three frozen sites only (the tracker's own unchecked
  wrappers and the home failed-execution read). The unchecked `query_executions(` callers are frozen
  too, and the declarations carry no `= ...` default.
CHECK 4 (visibility predicates). `execution_visible(` and `admit_confined_mutation(` are called with
  four arguments whose last is an owner key (a variable typed `ExecutionOwnerKey`, `req.owner`, or
  `execution_owner_key(...)`), and each is DECLARED exactly once with an `ExecutionOwnerKey`
  parameter and no `std::string` one (no string overload).
CHECK 5 (mutation request). Every `ExecutionMutationRequest` constructed under server/ sets `.owner`
  from `execution_owner_key(` in the same handler, and a `.username` is never assigned from an owner.
CHECK 6 (raw-username guards). Every handler (the innermost lambda, or an MCP `if (tool_name == ...)`
  block) that BINDS an owner key to a variable or ternary also carries a `username.empty()` guard on
  the RAW username, never replaced by a check on the key. The twelve such handlers are frozen by route
  path or tool name. The ten handlers that only use the key inertly (`.owns(`, a predicate argument,
  `.owner =`) need no guard by design (an empty key owns nothing) and are frozen as a second set.
CHECK 7 (the key type). `execution_owner_key` is DEFINED exactly once under server/, its body tests
  the service scope before returning a key, `ExecutionOwnerKey` is a class whose only public
  constructors are the defaulted ones, its friends are the frozen three, and nothing outside the
  header brace-constructs it from an argument.
CHECK 8 (gates). In `AuthRoutes::require_fleet_read` and `AuthRoutes::require_list_read_unchecked`
  the FIRST statement inside the `is_engine()` branch tests `token_scope_service` and its first
  statement calls `refuse_service_scoped_unrestricted(... kEngineEntry)`; `require_list_read` is the
  wrapper and the ONLY caller of `require_list_read_unchecked`, running the postcondition;
  `service_scope_authority_ok` and `refuse_service_scoped_unrestricted` are each DEFINED once under
  server/; `admit_fleet_read` is the only place a `ListAuthority` is constructed, and it runs the
  postcondition first.

Every frozen entry must still match something (a stale entry fails), so the lists cannot rot.

LIMITS, stated plainly. A `.owner` reached through a pointer-to-member, a structured binding or a
differently named field, a `dispatched_by` copied into a differently named field and compared there,
an alias of a type or function (`using S = ...`, a function pointer, a macro,
`decltype`), a scope or key built in one function and passed through another, a compare on a JSON value
read by another spelling of the key, `execution_owner_key` called through an alias, and any
control-flow path that reaches a pinned call with a wrong value are NOT detected. A frozen window also
includes adjacent string literals and the first tokens of the neighbouring expression, so a reworded
neighbour is a reviewed re-freeze. Handler boundaries are approximated (innermost
lambda, or the `tool_name ==` block). The compensating controls are the typed signatures, the
exact-set behaviour tests, and the routed-concern review.

Stdlib only, like the other tests/test_*.py gates. Exit 0 = pass; non-zero prints each failure.
tests/test_execution_owner_key_tripwire_selftest.py mutates the sources in memory and requires every
mutation to fail the matching check.

Usage: python3 -I tests/test_execution_owner_key_tripwire.py
"""
from __future__ import annotations

import bisect
import collections
import functools
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = "server/core/src/"
RULES = _SRC + "execution_scope_rules.hpp"
TRACKER_HPP = _SRC + "execution_tracker.hpp"
TRACKER_CPP = _SRC + "execution_tracker.cpp"
MUTATION_HPP = _SRC + "execution_mutation.hpp"
MUTATION_CPP = _SRC + "execution_mutation.cpp"
GATES_CPP = _SRC + "authz_gates.cpp"
AUTH_ROUTES_CPP = _SRC + "auth_routes.cpp"

_SRC_EXTS = (".cpp", ".hpp", ".h", ".cc")

# --- FROZEN LISTS (the lock). Editing any is a reviewed act; see the module docstring. -----------

# CHECK 1: (file, local window) -> (count, reason). The window is `<left token> <receiver chain>
# <next three tokens>` around each occurrence (see `_window`), so these strings are mechanical, not
# prose; the reason says why that occurrence is not a visibility decision.
_OWNS = "THE ownership compare: ExecutionOwnerKey::owns (an empty key owns nothing)"
_BUNDLE = ("read-side bundle-manifest ownership behind a Response:Read gate: a DOCUMENTED exception, "
           "not converted by #5557 (the manifest is keyed by the dispatching principal)")
_DECL = "member or parameter declaration (a new one is a new copy of the attribution)"
_PROJ = "output only: a response-row / JSON / HTML projection or log argument of the stored value"
_ATTRIB = "attribution WRITE at dispatch/create time (records who dispatched; not a visibility decision)"
_LADDER = ("dispatch TARGETING identity for a from_result_set rerun (downstream visibility "
           "intersection still applies), not the read-owner predicate")
_SQL = "the tracker's own SQL: the exact-match LIST filter and its bind"
_HYDRATE = "tracker row hydration from the stored column"
_INSERT = "INSERT parameter for the stored column (attribution write)"
_RERUN = "rerun attribution WRITE (the acting principal)"
_OWNER_ONLY = ("the sanctioned owner-only LIST filter for a confined, non-service session (a non-empty "
               "key, raw-username guarded); a service-scoped session takes confined_list_scope instead")
DISPATCHED_BY: dict[tuple[str, str], tuple[int, str]] = {}


def _db(file: str, key: str, reason: str, count: int = 1) -> None:
    DISPATCHED_BY[(_SRC + file, key)] = (count, reason)


_db('bundle_orchestrator.cpp', ', oldest->second.dispatched_by , correlation )', _PROJ)
_db('bundle_orchestrator.cpp', '|| it->second.dispatched_by != principal )', _BUNDLE)
_db('bundle_orchestrator.hpp', 'string dispatched_by ;', _DECL)
_db('command_v1_routes.hpp', '& dispatched_by , const std', _DECL)
_db('dispatch_scope_ladder.hpp', '= ex->dispatched_by ;', _LADDER)
_db('execution_model.cpp', ', row.dispatched_by }', _PROJ)
_db('execution_model.cpp', '^ "dispatched_by" , row .', _PROJ)
_db('execution_model.hpp', 'string dispatched_by ;', _DECL)
_db('execution_routes.cpp', ', e.dispatched_by }', _PROJ, 2)
_db('execution_routes.cpp', ', exec.dispatched_by }', _PROJ)
_db('execution_routes.cpp', '^ "dispatched_by" , e .', _PROJ, 2)
_db('execution_routes.cpp', '^ "dispatched_by" , exec .', _PROJ)
_db('execution_scope_rules.hpp', '&& e.dispatched_by == key_ ;', _OWNS)
_db('execution_tracker.cpp', '! q.dispatched_by . empty (', _SQL)
_db('execution_tracker.cpp', '( "dispatched_by = $" + std ::', _SQL)
_db('execution_tracker.cpp', '( q.dispatched_by ) ;', _SQL)
_db('execution_tracker.cpp', '+= " AND dispatched_by = $" + std ::', _SQL)
_db('execution_tracker.cpp', ', exec.dispatched_by , std ::', _INSERT)
_db('execution_tracker.cpp', '^ e.dispatched_by = col_str (', _HYDRATE)
_db('execution_tracker.cpp', '^ rerun.dispatched_by = user ;', _RERUN, 2)
_db('execution_tracker.hpp', 'string dispatched_by ;', _DECL, 2)
_db('executions_page_render.cpp', '( e.dispatched_by ) + "</span>"', _PROJ)
_db('executions_page_render.cpp', '( e.dispatched_by ) + "</span></td>"', _PROJ)
_db('executions_page_render.cpp', '( e.dispatched_by ) + "\\" data-responded=\\""', _PROJ)
_db('executions_page_render.cpp', '( e.dispatched_by ) + "\\">"', _PROJ, 2)
_db('executions_page_render.hpp', 'string dispatched_by ;', _DECL)
_db('instruction_execute.cpp', '^ row.dispatched_by = rq .', _ATTRIB)
_db('instruction_execute.hpp', 'string dispatched_by ;', _DECL)
_db('instruction_execute_ports.cpp', '= row.dispatched_by ;', _PROJ)
_db('instruction_execute_ports.cpp', '^ exec.dispatched_by = row .', _ATTRIB)
_db('mcp_server.cpp', '( "dispatched_by" , exec ->', _PROJ)
_db('mcp_server.cpp', ', exec->dispatched_by ) . add', _PROJ)
_db('mcp_server.cpp', '= e.dispatched_by ;', _PROJ)
_db('mcp_server.cpp', '^ eq.dispatched_by = owner_only_filter (', _OWNER_ONLY)
_db('mcp_server.cpp', '^ exec.dispatched_by = session ->', _ATTRIB, 2)
_db('mcp_server.cpp', '^ row.dispatched_by = e .', _PROJ)
_db('rest_api_v1.cpp', '( "dispatched_by" , e .', _PROJ)
_db('rest_api_v1.cpp', ', e.dispatched_by ) . add', _PROJ)
_db('rest_api_v1.cpp', '= e.dispatched_by ;', _PROJ, 2)
_db('rest_api_v1.cpp', '^ exec.dispatched_by = owner ;', _ATTRIB)
_db('rest_api_v1.cpp', '^ row.dispatched_by = e .', _PROJ, 2)
_db('schedule_runner.cpp', '^ exec.dispatched_by = s .', _ATTRIB)
_db('server.cpp', '^ exec.dispatched_by = by ;', _ATTRIB)
_db('workflow_routes.cpp', '( e.dispatched_by ) + "</td>"', _PROJ)
_db('workflow_routes.cpp', '( exec.dispatched_by ) + "</div>"', _PROJ)
_db('workflow_routes.cpp', '= e.dispatched_by ;', _PROJ)
_db('workflow_routes.cpp', '= exec.dispatched_by ;', _PROJ)
_db('workflow_routes.cpp', '^ exec.dispatched_by = session ->', _ATTRIB)
_db('workflow_routes.cpp', '^ row.dispatched_by = e .', _PROJ)
_db('workflow_routes.cpp', '^ row.dispatched_by = exec .', _PROJ)

# CHECK 2: every `.owner` / `->owner` member access: (file, window) -> (count, reason). The `owner` field
# of an ExecutionListScope is written once (the factory) and read by the tracker's SQL; the mutation
# request's `owner` takes the key and is read by the predicate; the rest is a schedule display flag.
_OWN_REQ = "ExecutionMutationRequest::owner takes the key at construction"
OWNER_ACCESS: dict[tuple[str, str], tuple[int, str]] = {
    (RULES, "^ out.owner = owner ."):
        (1, "the ONE write of ExecutionListScope::owner, inside confined_list_scope()"),
    (TRACKER_CPP, "! scope->owner . empty ("): (1, "the tracker's SQL reads the engaged scope's owner"),
    (TRACKER_CPP, "( scope->owner ) ;"): (1, "the tracker's SQL binds the engaged scope's owner"),
    (MUTATION_CPP, ", req.owner ) ;"): (1, "the mutation admission hands the request's key to the predicate"),
    (_SRC + "mcp_server.cpp", "^ mreq.owner = execution_owner_key ("): (2, _OWN_REQ),
    (_SRC + "rest_api_v1.cpp", "^ mreq.owner = execution_owner_key ("): (2, _OWN_REQ),
    (_SRC + "workflow_routes.cpp", "^ row.owner = ! sc"):
        (1, "a schedule-list DISPLAY flag on a different row type (schedules gate before this flag)"),
    (_SRC + "workflow_routes.cpp", "( row.owner ) {"):
        (1, "reads that schedule display flag"),
}
# `workflows_page_render.cpp` renders the schedule rows: its `s.owner` is that same bool display flag,
# in a file with no tracker, scope or session access.
OWNER_ACCESS_EXEMPT_FILES = frozenset({_SRC + "workflows_page_render.cpp"})
SCOPE_TYPE_FILES = frozenset({TRACKER_HPP, TRACKER_CPP, RULES})

# CHECK 3: (file, callee, scope-argument spelling, initialisers of that variable) -> (count, reason).
_CONF = "confined_list_scope(owner,gate.scope)"
SCOPE_CALLS: dict[tuple[str, str, str, tuple[str, ...]], tuple[int, str]] = {
    (_SRC + "execution_routes.cpp", "query_executions_checked", "scope_arg", (_CONF,)):
        (1, "legacy GET /api/executions list"),
    (_SRC + "execution_routes.cpp", "get_children_checked", "scope_arg", (_CONF,)):
        (1, "legacy GET /api/executions/{id}/children"),
    (_SRC + "rest_api_v1.cpp", "query_executions_checked", "scope_arg", (_CONF,)):
        (1, "REST v1 execution list"),
    (_SRC + "rest_api_v1.cpp", "get_children_checked", "scope_arg", (_CONF,)):
        (1, "REST v1 execution children"),
    (_SRC + "workflow_routes.cpp", "query_executions_checked", "scope_arg", (_CONF,)):
        (1, "dashboard execution list fragment"),
    (_SRC + "mcp_server.cpp", "get_children_checked", "scope_arg",
     (_CONF,)):
        (1, "MCP get_execution_children"),
    (_SRC + "mcp_server.cpp", "query_executions_checked", "query_scope",
     ("confined_list_scope(owner,service_scoped?gate.scope:authz::VisibleSet{})",)):
        (1, "MCP list_executions: the sanctioned scope form (service-scoped sessions engage the "
            "scope with an empty key; others pass the unrestricted default and use the owner-only "
            "filter pinned by CHECK 1)"),
    (TRACKER_CPP, "query_executions_checked", "std::nullopt", ()):
        (1, "the tracker's own unchecked query_executions(q) wrapper (its callers are frozen below)"),
    (TRACKER_CPP, "get_children_checked", "std::nullopt", ()):
        (1, "the tracker's own unchecked get_children(id) wrapper (no production caller)"),
    (_SRC + "server.cpp", "query_executions_checked", "std::nullopt", ()):
        (1, "home failed-execution figure: an unfiltered list that home_routes.cpp reads only for an "
            "unconfined caller (an engaged scope is reported Limited and the list is not read); the one "
            "literal unrestricted scope outside the tracker"),
}
# The unchecked reads: (file, callee, normalised first argument) -> (count, reason).
UNCHECKED_CALLS: dict[tuple[str, str, str], tuple[int, str]] = {
    (_SRC + "health_routes.cpp", "query_executions", "{.status=\"running\"}"):
        (2, "internal health/metrics count, no caller scope by design"),
    (_SRC + "health_routes.cpp", "query_executions", "{.limit=1000}"):
        (1, "internal health/metrics count, no caller scope by design"),
    (_SRC + "server.cpp", "query_executions", "{.status=\"running\"}"):
        (2, "internal running-execution gauge, no caller scope by design"),
}

# CHECK 4: the sanctioned spelling of the owner argument of the two predicates.
OWNER_ARG_VARS = ("owner", "owner_key")
OWNER_ARG_EXPRS = ("req.owner",)

# CHECK 6: the handlers that BIND an owner key to a variable or ternary, (file, handler id) -> count.
# The id is the route path or MCP tool name. Each needs a raw `username.empty()` guard in its body.
BOUND_OWNER_KEYS = {
    (_SRC + "execution_routes.cpp", route): 1 for route in (
        "/api/executions", "/api/executions/([^/]+)", "/api/executions/([^/]+)/agents",
        "/api/executions/([^/]+)/cancel", "/api/executions/([^/]+)/children",
        "/api/executions/([^/]+)/rerun", "/api/executions/([^/]+)/summary")
}
BOUND_OWNER_KEYS.update({
    (_SRC + "rest_api_v1.cpp", "/api/v1/executions"): 1,
    (_SRC + "rest_api_v1.cpp", "/api/v1/executions/([A-Za-z0-9_-]{1,128})/children"): 1,
    (_SRC + "mcp_server.cpp", "get_execution_children"): 1,
    (_SRC + "mcp_server.cpp", "list_executions"): 1,
    (_SRC + "workflow_routes.cpp", "/fragments/executions"): 1,
})
# The handlers that call execution_owner_key only INERTLY (`.owns(`, a direct argument of the two
# predicates, or `.owner =` on a mutation request): an empty key owns nothing, so no raw-username
# guard is required by design (the mutation path refuses an empty `req.username` itself). Frozen so a
# new caller is a reviewed act; the ids are the route path or MCP tool name.
_RA = "/api/v1/executions/([A-Za-z0-9_-]{1,128})"
INERT_OWNER_KEY_HANDLERS = {
    (_SRC + "mcp_server.cpp", "cancel_execution"): 1,
    (_SRC + "mcp_server.cpp", "get_execution_status"): 1,
    (_SRC + "mcp_server.cpp", "record_execution_rerun"): 1,
    (_SRC + "mcp_server.cpp", "summarize_working_set"): 1,
    (_SRC + "rest_api_v1.cpp", "/api/v1/events"): 1,
    (_SRC + "rest_api_v1.cpp", _RA): 1,
    (_SRC + "rest_api_v1.cpp", _RA + "/cancel"): 1,
    (_SRC + "rest_api_v1.cpp", _RA + "/rerun"): 1,
    (_SRC + "workflow_routes.cpp", "/fragments/executions/([A-Za-z0-9_-]{1,128})/detail"): 1,
    (_SRC + "workflow_routes.cpp", "/sse/executions/([A-Za-z0-9_-]{1,128})"): 1,
}
KEY_FRIENDS = frozenset({"execution_owner_key", "confined_list_scope", "owner_only_filter"})

_PRED_NAMES = ("execution_visible", "admit_confined_mutation")


# --- the scanner --------------------------------------------------------------------------------

_RAW_OPEN = re.compile(r'R"([^()\\\s]{0,16})\(')
_FILL = "\x01"


class Scanned:
    __slots__ = ("code", "masked", "strings")

    def __init__(self, code: str, masked: str, strings: tuple[tuple[int, str], ...]):
        self.code, self.masked, self.strings = code, masked, strings


_SCAN = re.compile(
    r"(?P<pp>^[ \t]*\#[^\n]*)"
    r"|(?P<lc>//[^\n]*)"
    r"|(?P<bc>/\*.*?(?:\*/|\Z))"
    r"|(?P<raw>(?<![\w])R\"(?P<d>[^()\\\s\"]{0,16})\()"
    r"|(?P<str>\"(?:\\.|[^\"\\\n])*\"?)"
    r"|(?P<chr>(?<![0-9A-Za-z_])'(?:\\.|[^'\\\n])*'?)",
    re.MULTILINE | re.DOTALL)
_NOT_NL = re.compile(r"[^\n]")


@functools.lru_cache(maxsize=None)
def scan(text: str) -> Scanned:
    """Comments and preprocessor lines blanked to spaces; `masked` also blanks string contents.

    `code` keeps string literals (so a normalised window still shows its JSON key or SQL text);
    `masked` replaces every character between a literal's quotes with a filler so an identifier scan
    never sees inside a string. Both have the same length and newlines, so indices align. Memoised
    per file text: the selftest re-scans the tree once per mutation and a mutation changes one file.
    A regex strip of comments alone would be wrong: a literal such as "/api/*" would open a block
    comment, so the alternation below consumes literals and comments in source order.
    """
    text = text.replace("\\\r\n", "").replace("\\\n", "")
    n = len(text)
    code: list[str] = []
    masked: list[str] = []
    strings: list[tuple[int, str]] = []
    pos = 0
    while pos < n:
        m = _SCAN.search(text, pos)
        if not m:
            code.append(text[pos:])
            masked.append(text[pos:])
            break
        gap = text[pos:m.start()]
        code.append(gap)
        masked.append(gap)
        kind = m.lastgroup
        if kind in ("pp", "lc"):
            seg = " " * (m.end() - m.start())
            code.append(seg)
            masked.append(seg)
            pos = m.end()
        elif kind == "bc":
            seg = _NOT_NL.sub(" ", m.group())
            code.append(seg)
            masked.append(seg)
            pos = m.end()
        elif kind == "raw" or m.group("d") is not None and m.group("raw"):
            delim = m.group("d")
            end_tok = ")" + delim + '"'
            end = text.find(end_tok, m.end())
            j = n if end < 0 else end + len(end_tok)
            body_end = n if end < 0 else end
            code.append(text[m.start():j])
            masked.append(text[m.start():m.end()] + _NOT_NL.sub(_FILL, text[m.end():body_end])
                          + text[body_end:j])
            strings.append((m.end(), text[m.end():body_end]))
            pos = j
        elif kind == "str":
            seg = m.group()
            body = seg[1:-1] if len(seg) > 1 and seg.endswith('"') else seg[1:]
            code.append(seg)
            masked.append('"' + _FILL * len(body) + seg[1 + len(body):])
            strings.append((m.start() + 1, body))
            pos = m.end()
        else:  # a character literal (or a C++14 digit separator, harmlessly masked)
            seg = m.group()
            body = seg[1:-1] if len(seg) > 1 and seg.endswith("'") else seg[1:]
            code.append(seg)
            masked.append("'" + _FILL * len(body) + seg[1 + len(body):])
            pos = m.end()
    return Scanned("".join(code), "".join(masked), tuple(strings))


@functools.lru_cache(maxsize=None)
def _braces(masked: str):
    opens: list[int] = []
    close_of: dict[int, int] = {}
    parent: dict[int, int] = {}
    stack: list[int] = []
    for m in re.finditer(r"[{}]", masked):
        if m.group() == "{":
            parent[m.start()] = stack[-1] if stack else -1
            stack.append(m.start())
            opens.append(m.start())
        elif stack:
            close_of[stack.pop()] = m.start()
    for o in stack:
        close_of[o] = len(masked)
    return opens, close_of, parent


def _enclosing(masked: str, idx: int) -> list[int]:
    """Opening-brace indices of the blocks enclosing idx, innermost first."""
    opens, close_of, parent = _braces(masked)
    k = bisect.bisect_left(opens, idx) - 1
    o = opens[k] if k >= 0 else -1
    chain: list[int] = []
    while o != -1:
        if close_of[o] > idx:
            chain.append(o)
        o = parent[o]
    return chain


def _header_start(masked: str, open_idx: int) -> int:
    return max(masked.rfind(";", 0, open_idx), masked.rfind("{", 0, open_idx),
               masked.rfind("}", 0, open_idx)) + 1


def _header(masked: str, open_idx: int) -> str:
    return masked[_header_start(masked, open_idx):open_idx]


def _handler_id(sc: Scanned, open_idx: int) -> str:
    """A stable name for the handler whose body opens at open_idx: the first string literal in its
    header (the route path, or the MCP tool name in `tool_name == "..."`)."""
    a = _header_start(sc.masked, open_idx)
    for start, content in sc.strings:
        if a <= start <= open_idx:
            return content
    return "<anonymous>"


_LAMBDA_HDR = re.compile(r"\]\s*\([^;{}]*\)\s*(?:mutable\b|noexcept\b|const\b|->[^{};]*|\s)*$")
_TOOL_HDR = re.compile(r'\btool_name\s*==\s*"[^"]*"\s*\)\s*$')
_NOT_FUNC = re.compile(r"\b(namespace|class|struct|enum|union|extern)\b")


def _handler_span(masked: str, idx: int) -> tuple[int, int]:
    """(open, close) of the handler enclosing idx: the innermost lambda or MCP tool block, else the
    outermost function-like block."""
    chain = _enclosing(masked, idx)
    _opens, close_of, _parent = _braces(masked)
    for o in chain:
        h = _header(masked, o)
        if _LAMBDA_HDR.search(h) or _TOOL_HDR.search(h):
            return o, close_of[o]
    for o in reversed(chain):
        if not _NOT_FUNC.search(_header(masked, o)):
            return o, close_of[o]
    return 0, len(masked)


def _norm(s: str) -> str:
    return " ".join(s.split())


def _canon(s: str) -> str:
    """`_norm` with the spaces around punctuation removed, so a clang-format re-wrap of a frozen
    spelling does not change its key."""
    return re.sub(r"\s*([^\w\s])\s*", r"\1", _norm(s))


def _stmt_span(masked: str, idx: int) -> tuple[int, int]:
    a = max(masked.rfind(";", 0, idx), masked.rfind("{", 0, idx), masked.rfind("}", 0, idx)) + 1
    ends = [e for e in (masked.find(";", idx), masked.find("{", idx), masked.find("}", idx)) if e >= 0]
    return a, (min(ends) if ends else len(masked))


def _expr_end(masked: str, idx: int) -> int:
    """End of the expression starting at idx: the first `;` or `,` or unmatched closer at depth 0."""
    depth = 0
    for k in range(idx, len(masked)):
        ch = masked[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return k
            depth -= 1
        elif ch in ";," and depth == 0:
            return k
    return len(masked)


def _balanced(masked: str, open_idx: int, oc: str = "(", cc: str = ")") -> int:
    """Index of the bracket closing masked[open_idx]; len(masked) if unbalanced."""
    depth = 0
    for k in range(open_idx, len(masked)):
        ch = masked[k]
        if ch == oc:
            depth += 1
        elif ch == cc:
            depth -= 1
            if depth == 0:
                return k
    return len(masked)


def _split_args(masked: str, code: str, open_idx: int, close_idx: int) -> list[str]:
    """Top-level comma split of the argument text (taken from `code`, so strings survive)."""
    parts, depth, cur_start = [], 0, open_idx + 1
    for k in range(open_idx + 1, close_idx):
        ch = masked[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(_norm(code[cur_start:k]))
            cur_start = k + 1
    tail = _norm(code[cur_start:close_idx])
    if tail or parts:
        parts.append(tail)
    return parts


_TAIL_TOKEN = re.compile(r"(\w+|>>|&&|\|\||->|::|==|!=|<=|>=|\S)\s*$")


def _prev_token(masked: str, idx: int) -> str:
    """The token ending just before idx (looked up in a short window, never a whole-file scan)."""
    m = _TAIL_TOKEN.search(masked, max(0, idx - 80), idx)
    return m.group(1) if m else ""


_CALL_KEYWORDS = frozenset({"return", "co_return", "else", "throw", "case", "and", "or", "not", "new",
                            "delete", "sizeof", "co_await", "co_yield"})
_QUALIFIER = re.compile(r"[A-Za-z_]\w*\s*::\s*$")


def _is_declaration_site(masked: str, name_idx: int) -> bool:
    """True when the name at name_idx is a declarator (preceded by a type), not a call.

    `Type name(`, `Type Cls::name(` and `Type& name(` are declarators; `x.name(`, `p->name(`,
    `= name(`, `(name(`, `return name(`, `!name(`, `&& name(` and `ns::name(` are calls.
    """
    end = name_idx
    while True:  # skip a `Qualifier::` chain
        m = _QUALIFIER.search(masked, max(0, end - 80), end)
        if not m:
            break
        end = m.start()
    tok = _prev_token(masked, end)
    if tok == "":
        return False
    if tok in ("&", "*", ">", ">>"):
        return True
    return (tok[0].isalpha() or tok[0] == "_") and tok not in _CALL_KEYWORDS


# --- tree access --------------------------------------------------------------------------------

def read_tree(root: str, subdir: str) -> dict[str, str]:
    out = {}
    for dirpath, dirnames, filenames in os.walk(os.path.join(root, subdir)):
        dirnames[:] = [d for d in dirnames if not d.startswith("build") and d != "vcpkg_installed"]
        for f in filenames:
            if f.endswith(_SRC_EXTS):
                p = os.path.join(dirpath, f)
                with open(p, encoding="utf-8", errors="replace") as fh:
                    out[os.path.relpath(p, root).replace(os.sep, "/")] = fh.read()
    return out


def _each(files: dict[str, str], *needles: str):
    """(rel, Scanned) for each file whose masked text contains any needle (all files if none)."""
    for rel in sorted(files):
        sc = scan(files[rel])
        if needles and not any(n in sc.masked for n in needles):
            continue
        yield rel, sc


def _stale_and_extra(found: collections.Counter, frozen: dict, label: str, fmt) -> list[str]:
    errs: list[str] = []
    for key, n in sorted(found.items(), key=lambda kv: str(kv[0])):
        want = frozen.get(key, (0, ""))[0]
        if n > want:
            errs.append(f"{label}: unreviewed {fmt(key)}" + (f" (x{n}, frozen x{want})" if want else ""))
    for key, (want, _reason) in sorted(frozen.items(), key=lambda kv: str(kv[0])):
        if found.get(key, 0) < want:
            errs.append(f"{label}: stale frozen entry (no longer matches the tree, x{found.get(key, 0)} "
                        f"of x{want}) {fmt(key)}")
    return errs


# --- CHECK 1 ------------------------------------------------------------------------------------

_DB_IDENT = re.compile(r"\bdispatched_by\b")
_SQL_CMP = re.compile(r"\bdispatched_by\b\s*(?:=|!=|<>|<|>|\bIN\b|\bLIKE\b)", re.IGNORECASE)


_TOKEN = re.compile(
    r'R"[^()\\\s"]{0,16}\([\x01\n]*\)[^()\\\s"]{0,16}"|"[^"\n]*"|\'[^\'\n]*\'|[A-Za-z_]\w*|\d[\w.\']*'
    r"|->\*?|::|==|!=|<=>|<=|>=|&&|\|\||<<|>>|\+\+|--|[+\-*/%&|^]=|\S")


def _local_tokens(sc: Scanned, lo: int, hi: int) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in _TOKEN.finditer(sc.masked, lo, hi)]


def _window(sc: Scanned, pos: int, end: int, is_ident: bool) -> str:
    """A local key for the occurrence spanning [pos, end): `<left> <receiver chain> <next 3 tokens>`.

    A window, not the whole statement (it ends at the first `;`, `{` or `}` and a statement start is `^`, so a
    reformat does not change it): a `dispatched_by` buried in a long `.add(...)` or HTML chain
    must not make the key depend on every unrelated field in that chain, and a compare spliced into
    such a chain must still change its own key. Tokens come from `masked` (so a string is one token)
    and their text from `code` (so a JSON key or SQL text survives).
    """
    def text(tk: tuple[int, int]) -> str:
        return sc.code[tk[0]:tk[1]]
    back = 160
    left_toks = _local_tokens(sc, max(0, pos - back), pos)
    while len(left_toks) < 4 and back < pos and back < 8000:  # blanked comments can leave a window empty
        back *= 4
        left_toks = _local_tokens(sc, max(0, pos - back), pos)
    first = pos
    if is_ident:  # extend over a receiver chain: a.b->c.dispatched_by
        while len(left_toks) >= 2 and text(left_toks[-1]) in (".", "->", "::") and \
                re.fullmatch(r"[A-Za-z_]\w*", text(left_toks[-2])):
            first = left_toks[-2][0]
            left_toks = left_toks[:-2]
    left = text(left_toks[-1]) if left_toks else ""
    chain = _norm(sc.code[first:end])
    right: list[str] = []
    for tk in _local_tokens(sc, end, min(len(sc.masked), end + 120)):
        right.append(text(tk))
        if right[-1] in (";", "{", "}") or len(right) == 3:  # never read into the next statement
            break
    if left in (";", "{", "}") or (left == ")" and right[:1] == ["="]):
        left = "^"  # a statement start, however the braces and line breaks fall
    return " ".join(x for x in (left, chain, *right) if x)


def dispatched_by_occurrences(files: dict[str, str]) -> collections.Counter:
    found: collections.Counter = collections.Counter()
    for rel, sc in _each(files):
        if "dispatched_by" not in sc.code:  # the JSON-key spelling lives only in a string
            continue
        for m in _DB_IDENT.finditer(sc.masked):
            found[(rel, _window(sc, m.start(), m.end(), True))] += 1
        for start, content in sc.strings:
            # an exact JSON key, or SQL spelling a comparison on the column
            if "dispatched_by" in content and (content == "dispatched_by" or _SQL_CMP.search(content)):
                found[(rel, _window(sc, start - 1, start + len(content) + 1, False))] += 1
    return found


def check_dispatched_by(files: dict[str, str]) -> list[str]:
    found = dispatched_by_occurrences(files)
    errs = []
    for (rel, key), n in sorted(found.items()):
        want = DISPATCHED_BY.get((rel, key), (0, ""))[0]
        if n > want:
            cmp_ = bool(re.search(r"(?:^| )(?:==|!=|<|>|<=|>=|<=>|\. compare \()(?: |$)", key))
            kind = ("an ownership-style COMPARE of dispatched_by outside ExecutionOwnerKey::owns"
                    if cmp_ else "a use of dispatched_by")
            errs.append(f"CHECK 1: unreviewed {kind} in {rel}: `{key}`"
                        + (f" (x{n}, frozen x{want})" if want else ""))
    for key, (want, _r) in sorted(DISPATCHED_BY.items()):
        if found.get(key, 0) < want:
            errs.append(f"CHECK 1: stale frozen dispatched_by entry (x{found.get(key, 0)} of x{want}) "
                        f"in {key[0]}: `{key[1]}`")
    return errs


# --- CHECK 2 ------------------------------------------------------------------------------------

_OWNER_MEMBER = re.compile(r"(?:\.|->)\s*(owner)\b")
_SCOPE_DECL = re.compile(r"\b(?:const\s+)?(?:(?:yuzu::server::|server::)?ExecutionScope)\s+(\w+)\s*([;{(=])")


def owner_accesses(files: dict[str, str]) -> collections.Counter:
    """Every `.owner` / `->owner` member access, as a window (a read, a write, `.assign(`, `+=`,
    `std::exchange(s->owner, ...)` and `auto& o = s->owner;` all change the window or add one)."""
    found: collections.Counter = collections.Counter()
    for rel, sc in _each(files, "owner"):
        if rel in OWNER_ACCESS_EXEMPT_FILES:
            continue
        for m in _OWNER_MEMBER.finditer(sc.masked):
            found[(rel, _window(sc, m.start(1), m.end(1), True))] += 1
    return found


def check_scope_construction(files: dict[str, str]) -> list[str]:
    errs = _stale_and_extra(owner_accesses(files), OWNER_ACCESS, "CHECK 2 (owner member access)",
                            lambda k: f"in {k[0]}: `{k[1]}`")
    for rel, sc in _each(files, "ExecutionScope", "ExecutionListScope"):
        if rel in SCOPE_TYPE_FILES:
            continue
        for m in re.finditer(r"\bExecutionListScope\b", sc.masked):
            errs.append(f"CHECK 2: ExecutionListScope named outside execution_tracker/"
                        f"execution_scope_rules in {rel}: `{_norm(sc.code[slice(*_stmt_span(sc.masked, m.start()))])}`")
        for m in _SCOPE_DECL.finditer(sc.masked):
            name, term = m.group(1), m.group(2)
            if term != ";":
                rhs = _norm(sc.code[m.end():_stmt_span(sc.masked, m.end())[1]]) if term == "=" else ""
                if not (term == "=" and rhs.startswith("confined_list_scope(")):
                    errs.append(f"CHECK 2: ExecutionScope `{name}` in {rel} is initialised by hand "
                                f"(only `= confined_list_scope(...)` or an uninitialised declaration "
                                f"is allowed)")
                continue
            lo, hi = _handler_span(sc.masked, m.start())
            for w in re.finditer(r"\b" + re.escape(name) + r"\b\s*(?:(=)(?!=)|\.\s*(?:emplace|reset|swap)\s*\(|->\s*\w+\s*=(?!=)|\.\s*\w+\s*=(?!=))",
                                 sc.masked[m.end():hi]):
                at = m.end() + w.start()
                if w.group(1) == "=":
                    rhs = _norm(sc.code[at + w.end() - w.start():_stmt_span(sc.masked, at)[1]])
                    if rhs.startswith("confined_list_scope("):
                        continue
                    errs.append(f"CHECK 2: ExecutionScope `{name}` in {rel} is assigned `{rhs}`; only "
                                f"confined_list_scope(...) may build an engaged scope")
                else:
                    errs.append(f"CHECK 2: ExecutionScope `{name}` in {rel} is modified in place "
                                f"(`{_norm(sc.code[at:_stmt_span(sc.masked, at)[1]])}`)")
        for m in re.finditer(r"\bstd::in_place\b|\bmake_optional\b", sc.masked) \
                if ("in_place" in sc.masked or "make_optional" in sc.masked) else ():
            a, b = _stmt_span(sc.masked, m.start())
            if re.search(r"ExecutionScope|ExecutionListScope", sc.masked[a:b]):
                errs.append(f"CHECK 2: in_place/make_optional beside an execution scope type in {rel}: "
                            f"`{_norm(sc.code[a:b])}`")
    return errs


# --- CHECK 3 ------------------------------------------------------------------------------------

_CHECKED = ("query_executions_checked", "get_children_checked")


def _resolve_scope_inits(sc: Scanned, call_idx: int, name: str) -> tuple[str, ...] | str:
    """How the scope variable `name` was initialised before the call: a tuple of initialiser
    expressions, or an error string."""
    lo, _hi = _handler_span(sc.masked, call_idx)
    region = sc.masked[lo:call_idx]
    decls = list(re.finditer(r"\b(?:const\s+)?([\w:]+)\s+" + re.escape(name) + r"\b\s*([;={(])", region))
    if not decls:
        return f"no declaration of `{name}` found in its handler"
    d = decls[-1]
    ty = d.group(1).split("::")[-1]
    if ty not in ("ExecutionScope", "auto"):
        return f"`{name}` resolves to a `{d.group(1)}`, not an ExecutionScope"
    base = lo + d.end()
    inits: list[str] = []
    if d.group(2) == "=":
        inits.append(_canon(sc.code[base:_expr_end(sc.masked, base)]))
    elif d.group(2) != ";":
        return f"`{name}` is brace/paren initialised by hand"
    elif ty == "auto":
        return f"`{name}` is a bare `auto` declaration"
    for w in re.finditer(r"\b" + re.escape(name) + r"\b\s*=(?!=)", sc.masked[base:call_idx]):
        at = base + w.end()
        inits.append(_canon(sc.code[at:_expr_end(sc.masked, at)]))
    return tuple(inits)


def scope_calls(files: dict[str, str]):
    """([(file, callee, arg2, inits)], [problems], [(file, callee, arg1)])"""
    calls, problems, unchecked = [], [], []
    for rel, sc in _each(files, "_checked", "query_executions", "get_children"):
        for callee in _CHECKED:
            if callee not in sc.masked:
                continue
            for m in re.finditer(r"\b" + callee + r"\s*\(", sc.masked):
                if _is_declaration_site(sc.masked, m.start()):
                    continue  # declaration/definition; the signature is pinned in check_scope_args
                op = m.end() - 1
                args = _split_args(sc.masked, sc.code, op, _balanced(sc.masked, op))
                if len(args) != 2:
                    problems.append(f"CHECK 3: {callee}( in {rel} passes {len(args)} argument(s); the "
                                    f"scope argument must be explicit: `{_norm(sc.code[m.start():_stmt_span(sc.masked, m.start())[1]])}`")
                    continue
                a2 = _canon(args[1])
                if re.fullmatch(r"[A-Za-z_]\w*", a2):
                    inits = _resolve_scope_inits(sc, m.start(), a2)
                    if isinstance(inits, str):
                        problems.append(f"CHECK 3: {callee}( in {rel}: {inits}")
                        continue
                    bad = [i for i in inits if not i.startswith("confined_list_scope(")]
                    if bad or not inits:
                        problems.append(f"CHECK 3: {callee}( in {rel}: scope `{a2}` is not built from "
                                        f"confined_list_scope( (initialisers: {list(inits)})")
                        continue
                    calls.append((rel, callee, a2, inits))
                else:
                    calls.append((rel, callee, a2, ()))
        for m in re.finditer(r"\bquery_executions\s*\(", sc.masked) if "query_executions(" in sc.masked else ():
            if _is_declaration_site(sc.masked, m.start()):
                continue
            op = m.end() - 1
            args = _split_args(sc.masked, sc.code, op, _balanced(sc.masked, op))
            unchecked.append((rel, "query_executions", _canon(args[0]) if args else ""))
        for m in re.finditer(r"tracker\w*\s*(?:->|\.)\s*get_children\s*\(", sc.masked) \
                if "get_children" in sc.masked else ():
            unchecked.append((rel, "get_children", _norm(sc.code[m.start():m.end()])))
    return calls, problems, unchecked


def _decl_params(files: dict[str, str], name: str):
    """[(file, [param text])] for every declaration/definition (not a call) of `name`."""
    out = []
    for rel, sc in _each(files, name):
        for m in re.finditer(r"\b" + name + r"\s*\(", sc.masked):
            if not _is_declaration_site(sc.masked, m.start()):
                continue
            op = m.end() - 1
            out.append((rel, _split_args(sc.masked, sc.code, op, _balanced(sc.masked, op))))
    return out


def check_scope_args(files: dict[str, str]) -> list[str]:
    calls, errs, unchecked = scope_calls(files)
    canon = collections.Counter((r, c, a, tuple(i)) for r, c, a, i in calls)
    errs = list(errs)
    errs += _stale_and_extra(canon, SCOPE_CALLS, "CHECK 3 (scope argument)",
                             lambda k: f"{k[1]}(..., {k[2]}) in {k[0]} initialised from {list(k[3])}")
    errs += _stale_and_extra(collections.Counter(unchecked), UNCHECKED_CALLS, "CHECK 3 (unchecked read)",
                             lambda k: f"{k[1]}({k[2]}) in {k[0]}")
    for name in _CHECKED:
        decls = _decl_params(files, name)
        if not decls:
            errs.append(f"CHECK 3: no declaration of {name} found (renamed? update the tripwire)")
        for rel, params in decls:
            if len(params) != 2 or any("=" in p for p in params):
                errs.append(f"CHECK 3: declaration of {name} in {rel} must take exactly two parameters "
                            f"with no default value: {params}")
    return errs


# --- CHECK 4 ------------------------------------------------------------------------------------

def _typed_as_owner_key(sc: Scanned, idx: int, name: str) -> bool:
    lo, _hi = _handler_span(sc.masked, idx)
    decls = list(re.finditer(r"\b((?:const\s+)?[\w:]+)\s*&?\s+" + re.escape(name) + r"\b\s*(?=[;={(,)])",
                             sc.masked[lo:idx]))
    if not decls:
        return False
    last = decls[-1].group(1).split()[-1].split("::")[-1]
    return last == "ExecutionOwnerKey"


def check_predicate_calls(files: dict[str, str]) -> list[str]:
    errs: list[str] = []
    for pred in _PRED_NAMES:
        decls = _decl_params(files, pred)
        if len(decls) != 1:
            errs.append(f"CHECK 4: {pred} must be declared exactly once (no string overload); found "
                        f"{len(decls)}: {[d[0] for d in decls]}")
        for rel, params in decls:
            if len(params) != 4 or "ExecutionOwnerKey" not in params[-1] or any("string" in p for p in params):
                errs.append(f"CHECK 4: {pred} in {rel} must end in an ExecutionOwnerKey parameter and "
                            f"take no string-typed one: {params}")
    for rel, sc in _each(files, *_PRED_NAMES):
        for pred in _PRED_NAMES:
            for m in re.finditer(r"\b" + pred + r"\s*\(", sc.masked):
                if _is_declaration_site(sc.masked, m.start()):
                    continue
                op = m.end() - 1
                args = _split_args(sc.masked, sc.code, op, _balanced(sc.masked, op))
                if len(args) != 4:
                    errs.append(f"CHECK 4: {pred}( in {rel} takes {len(args)} arguments, not 4")
                    continue
                last = args[3]
                if last in OWNER_ARG_VARS:
                    if not _typed_as_owner_key(sc, m.start(), last):
                        errs.append(f"CHECK 4: {pred}( in {rel}: `{last}` is not declared as an "
                                    f"ExecutionOwnerKey")
                elif last in OWNER_ARG_EXPRS or re.fullmatch(r"execution_owner_key\([^()]*\)", last):
                    pass
                else:
                    errs.append(f"CHECK 4: {pred}( in {rel} is called with `{last}` as its owner "
                                f"argument; it must be an owner key (execution_owner_key(...))")
    return errs


# --- CHECK 5 ------------------------------------------------------------------------------------

MUTATION_REQUEST_SITES = {_SRC + "mcp_server.cpp": 2, _SRC + "rest_api_v1.cpp": 2}


def check_mutation_requests(files: dict[str, str]) -> list[str]:
    errs: list[str] = []
    sites: collections.Counter = collections.Counter()
    for rel, sc in _each(files, "ExecutionMutationRequest"):
        if rel in (MUTATION_HPP, MUTATION_CPP):
            continue
        for m in re.finditer(r"\bExecutionMutationRequest\b\s*([{(])", sc.masked):
            errs.append(f"CHECK 5: ExecutionMutationRequest in {rel} is built as a temporary / with "
                        f"arguments (`{_norm(sc.code[m.start():_stmt_span(sc.masked, m.start())[1]])}`); "
                        f"declare a variable and set `.owner = execution_owner_key(...)`")
        for m in re.finditer(r"\bExecutionMutationRequest\s+(\w+)\s*([;={(])", sc.masked):
            var = m.group(1)
            sites[rel] += 1
            _lo, hi = _handler_span(sc.masked, m.start())
            body = sc.masked[m.end():hi]
            if m.group(2) in "{(":
                errs.append(f"CHECK 5: ExecutionMutationRequest `{var}` in {rel} is brace/paren "
                            f"initialised; assign `.owner` explicitly after declaring it")
            if not re.search(r"\b" + re.escape(var) + r"\.owner\s*=\s*execution_owner_key\s*\(", body):
                errs.append(f"CHECK 5: ExecutionMutationRequest `{var}` in {rel} never gets "
                            f"`{var}.owner = execution_owner_key(...)` in its handler")
    for rel, sc in _each(files, "execution_owner_key", "ExecutionOwnerKey", "owner_key"):
        for m in re.finditer(r"(?:\.|->)\s*username\s*=(?!=)", sc.masked):
            a, b = _stmt_span(sc.masked, m.end())
            rhs = sc.masked[m.end():b]
            if re.search(r"\bowner\b|owner_key|execution_owner_key", rhs):
                errs.append(f"CHECK 5: a `.username` is assigned from an owner key in {rel}: "
                            f"`{_norm(sc.code[a:b])}` (username stays the real principal)")
    errs += _stale_and_extra(sites, {k: (v, "") for k, v in MUTATION_REQUEST_SITES.items()},
                             "CHECK 5 (ExecutionMutationRequest construction sites)",
                             lambda k: f"in {k}")
    hdr = files.get(MUTATION_HPP)
    if hdr is None:
        errs.append(f"CHECK 5: {MUTATION_HPP} not found")
    else:
        body = scan(hdr).masked
        m = re.search(r"\bstruct\s+ExecutionMutationRequest\b[^;{]*\{", body)
        if not m:
            errs.append("CHECK 5: struct ExecutionMutationRequest not found")
        else:
            struct_body = body[m.end():_balanced(body, m.end() - 1, "{", "}")]
            if not re.search(r"\bExecutionOwnerKey\s+owner\s*[;={]", struct_body):
                errs.append("CHECK 5: ExecutionMutationRequest::owner must be an ExecutionOwnerKey")
    return errs


# --- CHECK 6 ------------------------------------------------------------------------------------

_OWNER_KEY_CALL = re.compile(r"\bexecution_owner_key\s*\(")


def _inert_owner_key_use(sc: Scanned, idx: int) -> bool:
    close = _balanced(sc.masked, sc.masked.index("(", idx))
    if re.match(r"\s*\.\s*owns\s*\(", sc.masked[close + 1:close + 24]):
        return True
    if re.search(r"(?:\.|->)\s*owner\s*=\s*$", sc.masked[max(0, idx - 40):idx]):
        return True
    depth, k = 0, idx - 1
    while k >= 0 and idx - k < 400:
        ch = sc.masked[k]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                m = re.search(r"(\w+)\s*$", sc.masked[max(0, k - 40):k])
                return bool(m and m.group(1) in _PRED_NAMES)
            depth -= 1
        elif ch in ";{}":
            break
        k -= 1
    return False


def check_guards(files: dict[str, str]) -> list[str]:
    errs: list[str] = []
    bound: collections.Counter = collections.Counter()
    inert: collections.Counter = collections.Counter()
    for rel, sc in _each(files, "execution_owner_key"):
        for m in _OWNER_KEY_CALL.finditer(sc.masked):
            if _is_declaration_site(sc.masked, m.start()) and _prev_token(sc.masked, m.start()) == "ExecutionOwnerKey":
                continue  # the definition / friend declaration
            if _inert_owner_key_use(sc, m.start()):
                inert[(rel, _handler_id(sc, _handler_span(sc.masked, m.start())[0]))] += 1
                continue
            lo, hi = _handler_span(sc.masked, m.start())
            bound[(rel, _handler_id(sc, lo))] += 1
            if not re.search(r"\busername\s*\.\s*empty\s*\(\s*\)", sc.masked[lo:hi]):
                errs.append(f"CHECK 6: execution_owner_key( is bound in {rel} handler "
                            f"`{_handler_id(sc, lo)}` with no raw `username.empty()` guard: "
                            f"`{_norm(sc.code[slice(*_stmt_span(sc.masked, m.start()))])}`")
    errs += _stale_and_extra(bound, {k: (v, "") for k, v in BOUND_OWNER_KEYS.items()},
                             "CHECK 6 (owner-key binding per handler)",
                             lambda k: f"in {k[0]} handler `{k[1]}`")
    errs += _stale_and_extra(inert, {k: (v, "") for k, v in INERT_OWNER_KEY_HANDLERS.items()},
                             "CHECK 6 (inert owner-key use per handler)",
                             lambda k: f"in {k[0]} handler `{k[1]}`")
    return errs


# --- CHECK 7 ------------------------------------------------------------------------------------

def _definitions(files: dict[str, str], name: str, qualified: str | None = None):
    """[(file, name_idx, open_brace_idx)] for each definition (a declarator followed by a body)."""
    out = []
    pat = (re.escape(qualified) if qualified else r"(?<![\w:.>])" + re.escape(name)) + r"\s*\("
    for rel, sc in _each(files, name):
        for m in re.finditer(pat, sc.masked):
            op = m.end() - 1
            close = _balanced(sc.masked, op)
            tail = re.match(r"\s*(?:const\b|noexcept\b|override\b|final\b|\s)*(?:->[^{;]*)?\s*(\{)", sc.masked[close + 1:close + 200])
            if not tail:
                continue
            if not qualified and not _is_declaration_site(sc.masked, m.start()):
                continue
            out.append((rel, m.start(), close + 1 + tail.start(1)))
        # a lambda or alias bound to the name is a second definition
        if qualified is None:
            for m in re.finditer(r"\b" + re.escape(name) + r"\s*=\s*(?:\[|std::function|&)", sc.masked):
                out.append((rel, m.start(), -1))
    return out


def _public_text(body: str) -> str:
    out, depth, access, cur, i = [], 0, "private", [], 0
    acc = re.compile(r"(public|private|protected)\s*:(?!:)")
    while i < len(body):
        m = acc.match(body, i) if depth == 0 else None
        if m and (i == 0 or not (body[i - 1].isalnum() or body[i - 1] == "_")):
            if access == "public":
                out.append("".join(cur))
            access, cur, i = m.group(1), [], m.end()
            continue
        depth += {"{": 1, "}": -1}.get(body[i], 0)
        cur.append(body[i])
        i += 1
    if access == "public":
        out.append("".join(cur))
    return "\n".join(out)


def check_owner_key_type(files: dict[str, str]) -> list[str]:
    errs: list[str] = []
    defs = _definitions(files, "execution_owner_key")
    if len(defs) != 1:
        errs.append(f"CHECK 7: execution_owner_key must be DEFINED exactly once under server/; found "
                    f"{len(defs)}: {[d[0] for d in defs]}")
    for rel, _n, ob in defs:
        sc = scan(files[rel])
        if ob >= 0:
            body = sc.masked[ob:_balanced(sc.masked, ob, "{", "}")]
            first = _norm(body[1:])
            if not first.startswith("if (!s.token_scope_service.empty()"):
                errs.append(f"CHECK 7: the body of execution_owner_key in {rel} must test "
                            f"`token_scope_service` first (a service-scoped session's username is its "
                            f"minter's); starts `{first[:60]}`")
    sc = scan(files[RULES]) if RULES in files else None
    if sc is None:
        return errs + [f"CHECK 7: {RULES} not found"]
    m = re.search(r"\bclass\s+ExecutionOwnerKey\b[^;{]*\{", sc.masked)
    if not m:
        errs.append("CHECK 7: `class ExecutionOwnerKey` not found (a struct would make every member public)")
        return errs
    body = sc.masked[m.end():_balanced(sc.masked, m.end() - 1, "{", "}")]
    pub = _public_text(body)
    for stmt in re.split(r";", pub):
        s = _norm(stmt)
        if "ExecutionOwnerKey(" in s and not re.fullmatch(
                r"ExecutionOwnerKey\(\) = default|ExecutionOwnerKey\(const ExecutionOwnerKey&\) = default|"
                r"ExecutionOwnerKey\(ExecutionOwnerKey&&\)(?: noexcept)? = default", s):
            errs.append(f"CHECK 7: ExecutionOwnerKey has a public constructor other than the defaulted "
                        f"ones: `{s}`")
        if re.search(r"\boperator\b", s) and "operator=" not in s.replace(" ", ""):
            errs.append(f"CHECK 7: ExecutionOwnerKey has a public conversion/operator: `{s}`")
        if re.match(r"template\b", s) and "ExecutionOwnerKey" in s:
            errs.append(f"CHECK 7: ExecutionOwnerKey has a public template member: `{s}`")
    friends = {x for x in re.findall(r"\bfriend\b[^;]*?(\w+)\s*\(", body)}
    if friends != KEY_FRIENDS:
        errs.append(f"CHECK 7: the friends of ExecutionOwnerKey must be exactly {sorted(KEY_FRIENDS)}; "
                    f"found {sorted(friends)}")
    for rel, scx in _each(files, "ExecutionOwnerKey"):
        if rel == RULES:
            continue
        for m2 in re.finditer(r"\bExecutionOwnerKey\s*(?:\{\s*[^}\s]|\(\s*[^)\s])", scx.masked):
            if _prev_token(scx.masked, m2.start()) in ("class", "struct", "friend"):
                continue
            errs.append(f"CHECK 7: ExecutionOwnerKey is constructed from an argument in {rel}: "
                        f"`{_norm(scx.code[slice(*_stmt_span(scx.masked, m2.start()))])}`")
    # inside the header: the only argument construction is the factory's own
    inner = [m2 for m2 in re.finditer(r"\bExecutionOwnerKey\s*\{\s*[^}\s]", sc.masked)
             if _prev_token(sc.masked, m2.start()) not in ("class", "struct")]
    if len(inner) != 1:
        errs.append(f"CHECK 7: execution_scope_rules.hpp brace-constructs an ExecutionOwnerKey from an "
                    f"argument {len(inner)} times; only execution_owner_key() may (once)")
    return errs


# --- CHECK 8 ------------------------------------------------------------------------------------

def _function_body(files: dict[str, str], rel: str, qualified: str):
    if rel not in files:
        return None, f"{rel} not found"
    sc = scan(files[rel])
    defs = _definitions({rel: files[rel]}, qualified.split("::")[-1], qualified)
    if len(defs) != 1:
        return None, f"{qualified} must be defined exactly once in {rel}; found {len(defs)}"
    ob = defs[0][2]
    return (sc, ob, _balanced(sc.masked, ob, "{", "}")), None


_ENGINE_IF = re.compile(r"\bif\s*\(\s*session\s*->\s*is_engine\s*\(\s*\)\s*\)\s*\{")


def _check_engine_entry(files, rel, qualified, gate_enum):
    body, err = _function_body(files, rel, qualified)
    if err:
        return [f"CHECK 8: {err}"]
    sc, lo, hi = body
    engines = list(_ENGINE_IF.finditer(sc.masked, lo, hi))
    if len(engines) != 1:
        return [f"CHECK 8: {qualified} must have exactly one `if (session->is_engine())` branch; "
                f"found {len(engines)}"]
    ob = engines[0].end() - 1
    inner = sc.masked[ob + 1:_balanced(sc.masked, ob, "{", "}")]
    m = re.match(r"\s*if\s*\(\s*!\s*session\s*->\s*token_scope_service\s*\.\s*empty\s*\(\s*\)\s*\)\s*\{", inner)
    if not m:
        return [f"CHECK 8: the FIRST statement inside the is_engine() branch of {qualified} must test "
                f"`!session->token_scope_service.empty()`; it starts `{_norm(inner[:70])}`"]
    inner2 = inner[m.end():]
    call = re.match(r"\s*refuse_service_scoped_unrestricted\s*\(", inner2)
    if not call:
        return [f"CHECK 8: the refusal block in {qualified} must START with "
                f"refuse_service_scoped_unrestricted(...); it starts `{_norm(inner2[:70])}`"]
    close = _balanced(inner2, call.end() - 1)
    args = inner2[call.end() - 1:close + 1]
    errs = []
    if "kEngineEntry" not in args or gate_enum not in args:
        errs.append(f"CHECK 8: the entry refusal in {qualified} must pass {gate_enum} and kEngineEntry")
    if not re.match(r"\s*;\s*return\b", inner2[close + 1:close + 40]):
        errs.append(f"CHECK 8: the entry refusal in {qualified} must be followed by a return")
    return errs


def check_gates(files: dict[str, str]) -> list[str]:
    errs: list[str] = []
    errs += _check_engine_entry(files, GATES_CPP, "AuthRoutes::require_fleet_read", "kFleetRead")
    errs += _check_engine_entry(files, AUTH_ROUTES_CPP, "AuthRoutes::require_list_read_unchecked", "kListRead")

    # require_list_read is the wrapper and the ONLY caller of require_list_read_unchecked.
    callers = []
    for rel, sc in _each(files, "require_list_read_unchecked"):
        for m in re.finditer(r"\brequire_list_read_unchecked\s*\(", sc.masked):
            op = m.end() - 1
            close = _balanced(sc.masked, op)
            if re.match(r"\s*(?:const\b|noexcept\b|\s)*[{;]", sc.masked[close + 1:close + 40]) and \
                    _is_declaration_site(sc.masked, m.start()) and _prev_token(sc.masked, m.start()) != "=":
                continue  # declaration / definition
            callers.append((rel, m.start()))
    wrapper, err = _function_body(files, AUTH_ROUTES_CPP, "AuthRoutes::require_list_read")
    if err:
        errs.append(f"CHECK 8: {err}")
    else:
        sc, lo, hi = wrapper
        inside = [c for c in callers if c[0] == AUTH_ROUTES_CPP and lo < c[1] < hi]
        if len(callers) != 1 or len(inside) != 1:
            errs.append(f"CHECK 8: require_list_read_unchecked must be called exactly once, from inside "
                        f"AuthRoutes::require_list_read; found callers {[(c[0]) for c in callers]}")
        body = sc.masked[lo:hi]
        if not re.search(r"service_scope_authority_ok\s*\(", body) or \
                not re.search(r"refuse_service_scoped_unrestricted\s*\([^;]*kListRead[^;]*kPostcondition", body):
            errs.append("CHECK 8: AuthRoutes::require_list_read must run the postcondition "
                        "(service_scope_authority_ok then refuse_service_scoped_unrestricted(... "
                        "kListRead, kPostcondition))")

    # ONE definition each of the predicate and the responder under server/.
    for name, qual in (("service_scope_authority_ok", None),
                       ("refuse_service_scoped_unrestricted", "AuthRoutes::refuse_service_scoped_unrestricted")):
        defs = _definitions(files, name, qual)
        if len(defs) != 1:
            errs.append(f"CHECK 8: {name} must be DEFINED exactly once under server/ (a second copy is a "
                        f"defect); found {len(defs)}: {[d[0] for d in defs]}")
    other = [rel for rel, sc in _each(files, "refuse_service_scoped_unrestricted")
             for _m in re.finditer(r"(?<![\w:])refuse_service_scoped_unrestricted\s*\([^;{)]*\)\s*(?:const\s*)?\{", sc.masked)]
    if other:
        errs.append(f"CHECK 8: an unqualified definition of refuse_service_scoped_unrestricted in {other}")

    # admit_fleet_read is the only ListAuthority construction, and it runs the postcondition first.
    cons = []
    for rel, sc in _each(files, "ListAuthority"):
        if rel == _SRC + "authz_gates.hpp":
            continue  # the class's own constructors
        for m in re.finditer(r"\bListAuthority\s*[({]", sc.masked):
            if _is_declaration_site(sc.masked, m.start()) and _prev_token(sc.masked, m.start()) not in ("::",):
                pass
            cons.append((rel, m.start()))
    admit, err = _function_body(files, GATES_CPP, "AuthRoutes::admit_fleet_read")
    if err:
        errs.append(f"CHECK 8: {err}")
    else:
        sc, lo, hi = admit
        inside = [c for c in cons if c[0] == GATES_CPP and lo < c[1] < hi]
        if len(cons) != 1 or len(inside) != 1:
            errs.append(f"CHECK 8: a ListAuthority must be constructed exactly once under server/, inside "
                        f"AuthRoutes::admit_fleet_read; found {[c[0] for c in cons]}")
        body = sc.masked[lo:hi]
        gate_at = re.search(r"service_scope_authority_ok\s*\(", body)
        build_at = re.search(r"\bListAuthority\s*\(", body)
        if not gate_at or not build_at or gate_at.start() > build_at.start() or \
                not re.search(r"refuse_service_scoped_unrestricted\s*\([^;]*kFleetRead[^;]*kPostcondition", body):
            errs.append("CHECK 8: AuthRoutes::admit_fleet_read must run the postcondition "
                        "(service_scope_authority_ok, refuse_service_scoped_unrestricted(... kFleetRead, "
                        "kPostcondition)) BEFORE it constructs the ListAuthority")
    return errs


# --- driver -------------------------------------------------------------------------------------

CHECKS = (
    ("CHECK 1 dispatched_by", check_dispatched_by),
    ("CHECK 2 scope construction", check_scope_construction),
    ("CHECK 3 scope argument", check_scope_args),
    ("CHECK 4 visibility predicates", check_predicate_calls),
    ("CHECK 5 mutation request", check_mutation_requests),
    ("CHECK 6 raw-username guards", check_guards),
    ("CHECK 7 owner key type", check_owner_key_type),
    ("CHECK 8 gates", check_gates),
)


def run_all(files: dict[str, str]) -> list[str]:
    errs: list[str] = []
    for _label, fn in CHECKS:
        errs += fn(files)
    return errs


def main() -> int:
    files = read_tree(REPO_ROOT, "server")
    if RULES not in files:
        print(f"FAIL: {RULES} not found", file=sys.stderr)
        return 1
    errors = run_all(files)
    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"OK: {len(DISPATCHED_BY)} dispatched_by windows, {len(SCOPE_CALLS)} scope-argument call "
          f"sites, {len(BOUND_OWNER_KEYS)} guarded owner-key handlers, gate refusals pinned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
