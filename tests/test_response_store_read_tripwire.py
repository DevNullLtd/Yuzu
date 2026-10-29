#!/usr/bin/env python3
"""#4990 tripwire: no stored-response read can ship without deciding its Forensics tier.

Two lexical checks over the server tree, plus a marker guard. They are the structural backstop for
the compile-time one (`ResponseStore`'s reads take a `const ResponseTierFilter&` with no default
value, pinned by static_asserts in tests/unit/server/test_response_tier_filter.cpp): a lexical gate
catches what a type system cannot, namely a read method that never took the parameter at all, and a
call site that quietly picked the "internal consumer" escape hatch.

CHECK 1 (exact set of reads). The public section of server/core/src/response_store.hpp is parsed
  into declarations. Every public method must be classified in exactly one of two FROZEN lists:
  READS (the fourteen read methods) or NOT_READS (constructor, store(), finalize_terminal_status(),
  the allow-list accessors, ...). A method in neither list fails: a NEW method must be added to a
  list, which is a reviewed act, and a new read cannot be filed under NOT_READS without a reviewer
  noticing. Every READS method must take a `ResponseTierFilter` parameter, with no default value,
  and no NOT_READS method may take one (that would be an unlisted read). A name in a frozen list
  that no longer exists also fails, so the lists cannot rot.

CHECK 2 (internal-consumer allowlist). `ResponseTierFilter::unrestricted_internal_consumer()` is the
  one call that reads every row regardless of the Forensics tier. Its call sites under server/
  (outside response_tier_filter.hpp, where it is defined) must equal a FROZEN list of four sites,
  each keyed by file + the ResponseStore method called + that call's first argument, so the key
  survives reformatting and a comment edit but not a new site. A fifth site fails until it is
  reviewed and added here. The frozen list below carries the human label of each site and WHY it
  passes the principled definition of "internal": the read-back of a command the server dispatches
  itself from a FIXED server-side plugin set none of which is Forensics-tier (a unit test pins that
  set against the catalogue), or a read whose bytes reach no principal lacking the dispatcher's
  authority. The policy evaluator, bundle collate and result-set materializer were three more sites
  that failed that definition and now read through a real tier filter.

CHECK 2b (the other unrestricted spellings). The factory is not the only way to build a filter that
  excludes nothing: `ResponseTierFilter::exclude(<set>, std::nullopt)` is the same thing spelled
  as "a global Forensics:Read", and `for_fixed_plugin_poll(nullptr)` was once the same thing for an
  unwired surface. Neither may appear in non-test code under server/: a caller that really holds a
  global grant gets `nullopt` from the resolver at run time and passes a variable (see
  `tier_filter_for`), never a literal. Tests live outside server/ and may spell either.

CHECK 3 (markers). `operator_surface_pending_wiring` (the removed transitional factory) and
  `TODO(#4990)` must not reappear anywhere under server/ or tests/unit/.

GREP LIMIT: this is lexical. A same-file alias of the filter type (and an alias of an alias) is
  followed in CHECK 2b, line splices are joined, whitespace around `::` is closed, a bare `nullopt`
  or `optional<...>` is read as `std::` when the same file has a `using std::nullopt;`,
  `using std::optional;` or `using namespace std;`, and the literal spellings are matched through
  casts and parentheses. A renamed alias of the factory, an alias of the filter type declared in
  another file, a call through a function pointer, a parenthesised `(ResponseTierFilter::exclude)(...)`,
  a macro, or a nullopt produced by `std::exchange`, a ternary or comma expression, a lambda or
  `std::decay_t<decltype(v)>{}`, or a read added to a class other than ResponseStore evades it; the
  type-level static_asserts and the routed-concern review (Executions-history ladder row) are the
  compensating controls.

Stdlib only, like the other tests/test_*.py gates. Exit 0 = pass; non-zero prints each failure.
"""
from __future__ import annotations

import functools
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE_HEADER = os.path.join("server", "core", "src", "response_store.hpp")
FILTER_HEADER = os.path.join("server", "core", "src", "response_tier_filter.hpp")

# --- FROZEN LISTS (the lock). Editing either is a reviewed act; see the module docstring. ---------

READS = frozenset({
    "query",
    "query_bounded",
    "query_by_execution",
    "get_by_instruction",
    "aggregate",
    "distinct_agent_ids",
    "distinct_agent_ids_by_execution",
    "total_count",
    "facet_values",
    "facet_agent_ids",
    "facet_agent_count",
    "facet_line_count",
    "query_by_ids",
    "facet_response_ids",
})

NOT_READS = frozenset({
    "ResponseStore",         # constructor, copy-constructor (deleted)
    "operator=",             # deleted copy assignment
    "responses_reaped_total",     # metrics counters: no stored data
    "facets_predrained_total",
    "is_open",
    "retention_days",
    "set_metrics",
    "store",                 # ingest
    "finalize_terminal_status",
    "allowed_group_by",      # static allow-list accessors: constants, no stored data
    "allowed_op_column",
    "reap_expired",          # retention sweep
})

# The internal-consumer call sites: "file:method(first-arg)" -> human label (file:function) and the
# reason it is internal. Each plugin set below is fixed in server code; test_forensics_ingest_leaks.cpp
# asserts none of those plugins is in the Forensics set.
INTERNAL_CONSUMER_SITES = {
    "server/core/src/preflight_eval.cpp:query_by_execution(check_execution_id(run_id, key))":
        "preflight_eval.cpp: pre-flight check collation (kPreflightChecks: a fixed non-Forensics "
        "plugin list; the grid is scored server-side, never returned as rows)",
    "server/core/src/quarantine_containment_reconciler.cpp:query(pending_command_id)":
        "quarantine_containment_reconciler.cpp: in-flight quarantine command poll (the closed "
        "protective set, plugin `quarantine`; polls its own dispatch)",
    "server/core/src/server.cpp:query(command_id)":
        "server.cpp: tar.fleet_snapshot topology poll (fixed plugin `tar`; parsed into the "
        "topology graph, never returned as rows)",
    "server/core/src/server.cpp:query_by_execution(execution_id)":
        "server.cpp: deployment collect (fixed plugin `content_dist`; scored, cohort "
        "re-authorized every tick)",
}

FORBIDDEN_MARKERS = ("operator_surface_pending_wiring", "TODO(#4990)")

_SRC_EXTS = (".cpp", ".hpp", ".h", ".cc")


# --- CHECK 1: the public section of ResponseStore ---------------------------------------------

_RAW_OPEN = re.compile(r'R"([^()\\\s]{0,16})\(')


@functools.lru_cache(maxsize=None)
def _strip_comments(text: str) -> str:
    """Drop // and /* */ comments, leaving string and character literals (and raw strings) intact.

    Memoised per file text: the scans re-strip the whole tree once per check (and the selftest once
    per mutation), and a mutation changes one file, so every other file is a cache hit.

    A regex strip is wrong here: a literal such as "/api/*" would open a block comment that eats
    real code up to some later `*/`, silently hiding call sites from the scan.
    """
    out, i, n = [], 0, len(text)
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
            m = _RAW_OPEN.match(text, i)
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


def _class_body(header: str, cls: str) -> str | None:
    m = re.search(r"\bclass\s+" + re.escape(cls) + r"\b[^;{]*\{", header)
    if not m:
        return None
    depth, i = 1, m.end()
    while i < len(header) and depth:
        depth += {"{": 1, "}": -1}.get(header[i], 0)
        i += 1
    return header[m.end():i - 1]


_ACCESS_RE = re.compile(r"(public|private|protected)\s*:(?!:)")


def _public_sections(body: str) -> str:
    """The text of every `public:` segment, nesting-aware (specifiers inside nested types ignored)."""
    out, depth, access, cur = [], 0, "private", []
    i = 0
    while i < len(body):
        m = _ACCESS_RE.match(body, i) if depth == 0 else None
        if m and (i == 0 or not (body[i - 1].isalnum() or body[i - 1] == "_")):
            if access == "public":
                out.append("".join(cur))
            access, cur, i = m.group(1), [], m.end()
            continue
        ch = body[i]
        depth += {"{": 1, "}": -1}.get(ch, 0)
        cur.append(ch)
        i += 1
    if access == "public":
        out.append("".join(cur))
    return "\n".join(out)


def _statements(text: str) -> list[str]:
    stmts, depth, cur = [], 0, []
    for ch in text:
        cur.append(ch)
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
            if ch == "}" and depth == 0:
                stmts.append("".join(cur))
                cur = []
        elif ch == ";" and depth == 0:
            stmts.append("".join(cur))
            cur = []
    return [" ".join(s.split()) for s in stmts if s.strip() and s.strip() != ";"]


def _split_params(params: str) -> list[str]:
    parts, depth, cur = [], 0, []
    for ch in params:
        if ch in "(<[{":
            depth += 1
        elif ch in ")>]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def parse_public_methods(header_text: str, cls: str = "ResponseStore"):
    """[(name, [param text, ...])] for every public member function of `cls`."""
    body = _class_body(_strip_comments(header_text), cls)
    if body is None:
        raise ValueError(f"class {cls} not found")
    methods = []
    for stmt in _statements(_public_sections(body)):
        if re.match(r"(enum|struct|class|using|typedef|friend|static_assert)\b", stmt):
            continue
        # Two inline accessors can share one statement when the first has a `{ ... }` body.
        for piece in re.split(r"(?<=\})\s+(?=\[\[|\w)", stmt):
            paren = piece.find("(")
            if paren < 0:
                continue  # a data member
            m = re.search(r"(~?\w+|operator\s*[^\s(]+)\s*$", piece[:paren])
            if not m:
                continue
            depth, j = 0, paren
            while j < len(piece):
                depth += {"(": 1, ")": -1}.get(piece[j], 0)
                j += 1
                if depth == 0:
                    break
            methods.append((re.sub(r"\s+", "", m.group(1)), _split_params(piece[paren + 1:j - 1])))
    return methods


_TIER_PARAM_RE = re.compile(r"^const\s+(?:\w+::)*ResponseTierFilter\s*&\s*\w*$")


def _is_tier_filter_param(param: str) -> bool:
    """True iff `param` is a `const ResponseTierFilter&` parameter (a default value ignored here).

    A substring test (`"ResponseTierFilter" in p`) also accepted `int ResponseTierFilterCount` or a
    by-value filter; the type must be exactly a const lvalue reference to it.
    """
    return bool(_TIER_PARAM_RE.match(param.split("=", 1)[0].strip()))


def check_store_reads(header_text: str) -> list[str]:
    errors = []
    try:
        methods = parse_public_methods(header_text)
    except ValueError as e:
        return [f"{STORE_HEADER}: {e}"]
    names = {n for n, _ in methods}
    overlap = READS & NOT_READS
    if overlap:
        errors.append(f"frozen lists overlap: {sorted(overlap)}")
    for name, params in methods:
        takes = [p for p in params if _is_tier_filter_param(p)]
        if name in READS:
            if not takes:
                errors.append(f"read method {name}() does not take a ResponseTierFilter")
            elif any("=" in p for p in takes):
                errors.append(f"read method {name}() gives its ResponseTierFilter a default value")
        elif name in NOT_READS:
            if takes:
                errors.append(f"{name}() takes a ResponseTierFilter but is classified NOT_READS "
                              f"(an unlisted read?)")
        else:
            errors.append(f"public method {name}() is in neither READS nor NOT_READS: classify it in "
                          f"tests/test_response_store_read_tripwire.py (a read must take a "
                          f"ResponseTierFilter, #4990)")
    for missing in sorted((READS | NOT_READS) - names):
        errors.append(f"frozen-list entry {missing}() is no longer a public ResponseStore method: "
                      f"update the list")
    return errors


# --- CHECK 2: the internal-consumer call sites ----------------------------------------------

_CALL_RE = re.compile(
    r"(?:->|\.)\s*(query\w*|get_by_instruction|aggregate|distinct\w*|facet\w*|total_count)\s*\(")


def _first_arg(text: str, open_paren: int) -> str:
    depth, cur = 0, []
    for ch in text[open_paren:]:
        if ch in "([{<":
            depth += 1
            if depth == 1:
                continue
        elif ch in ")]}>":
            if ch == ">" and cur and cur[-1] == "-":
                cur.append(ch)  # the `->` of a member access, not a closing bracket
                continue
            depth -= 1
            if depth == 0:
                break
        if ch == "," and depth == 1:
            break
        cur.append(ch)
    return " ".join("".join(cur).split())


@functools.lru_cache(maxsize=None)
def _internal_sites_in_file(rel: str, text: str) -> tuple[str, ...]:
    """Site keys in one file (memoised, like _unrestricted_in_file)."""
    keys: list[str] = []
    code = _strip_comments(text)
    for m in re.finditer(r"unrestricted_internal_consumer\s*\(", code):
        calls = [c for c in _CALL_RE.finditer(code, 0, m.start())]
        if calls:
            c = calls[-1]
            key = f"{c.group(1)}({_first_arg(code, c.end() - 1)})"
        else:
            key = "<no preceding ResponseStore call>"
        keys.append(f"{rel}:{key}")
    return tuple(keys)


def find_internal_consumer_sites(files: dict[str, str]) -> list[str]:
    """Site keys for every `unrestricted_internal_consumer()` call outside its definition header."""
    keys: list[str] = []
    for rel, text in files.items():
        rel = rel.replace(os.sep, "/")
        if rel == FILTER_HEADER.replace(os.sep, "/"):
            continue
        keys.extend(_internal_sites_in_file(rel, text))
    return keys


def check_internal_sites(files: dict[str, str]) -> list[str]:
    found = sorted(find_internal_consumer_sites(files))
    expected = sorted(INTERNAL_CONSUMER_SITES)
    errors = []
    for k in found:
        if k not in INTERNAL_CONSUMER_SITES:
            errors.append(f"unreviewed unrestricted_internal_consumer() call site: {k} "
                          f"(an operator-reachable read must pass ResponseTierFilter::exclude; a "
                          f"genuinely internal one is reviewed and added to INTERNAL_CONSUMER_SITES)")
    for k in expected:
        if k not in found:
            errors.append(f"frozen internal-consumer site no longer present: {k} "
                          f"({INTERNAL_CONSUMER_SITES[k]}): update the list")
    if len(found) != len(set(found)):
        errors.append("an internal-consumer site key occurs more than once: a second call of the "
                      "same shape is a new site, give it a distinguishing first argument or list it")
    return errors


# The literal spellings of "no restriction" for the second argument of exclude(): `std::nullopt`,
# a value-initialized nullopt_t, a bare `{}` or `{std::nullopt}` (a trailing comma allowed), a
# value-initialized VisibleSet or `std::optional<...>` built from nothing or from `std::nullopt`
# (braces or parentheses), `auto{std::nullopt}` / `auto(std::nullopt)`, `decltype(x){}`, each with an
# optional leading `::`, and each optionally wrapped in a `static_cast<...>(...)`, a C-style cast,
# `std::move(...)` or redundant parentheses. A VARIABLE holding a nullopt cannot be seen lexically
# (review-enforced, and `tier_filter_for` is the sanctioned shape that derives it from the
# resolver), nor can a spelling through a user-defined alias of the VisibleSet type or a macro.
_GLOBAL = r"(?:::)?"
_NULLOPT = _GLOBAL + r"std::nullopt"
_EMPTY_INIT = r"(?:\{\s*\}|\(\s*\))"
_NULLOPT_INIT = r"(?:\{\s*" + _NULLOPT + r"\s*,?\s*\}|\(\s*" + _NULLOPT + r"\s*\))"
_UNRESTRICTED_VISIBLE = re.compile(
    r"^(?:" + _NULLOPT + r"(?:_t\s*" + _EMPTY_INIT + r")?"
    r"|\{\s*\}"
    r"|\{\s*" + _NULLOPT + r"\s*,?\s*\}"
    r"|" + _GLOBAL + r"(?:\w+::)*VisibleSet\s*(?:" + _EMPTY_INIT + r"|" + _NULLOPT_INIT + r")"
    r"|" + _GLOBAL + r"std::optional\s*<.*>\s*(?:" + _EMPTY_INIT + r"|" + _NULLOPT_INIT + r")"
    r"|auto\s*" + _NULLOPT_INIT +
    r"|decltype\s*\([^()]*\)\s*" + _EMPTY_INIT + r")$")
_NULL_PLUGIN_SET = re.compile(r"^(?:nullptr|NULL|0|\{\s*\})$")
_C_CAST = re.compile(r"^\(\s*[\w:<>,\s*&]+\)\s*(?=[\w{(:])")


def _balanced_end(s: str, i: int, open_c: str, close_c: str) -> int:
    """Index just past the bracket matching s[i] == open_c, or -1."""
    depth = 0
    for j in range(i, len(s)):
        if s[j] == open_c:
            depth += 1
        elif s[j] == close_c:
            depth -= 1
            if depth == 0:
                return j + 1
    return -1


def _close_scope_ws(a: str) -> str:
    """`std :: nullopt` and `std:: nullopt` are the same token sequence as `std::nullopt` to the
    compiler; close the whitespace around every `::` so the literal matcher sees one spelling."""
    return re.sub(r"\s*::\s*", "::", a)


def _peel(arg: str) -> str:
    """The argument text with redundant wrappers removed: outer parentheses, `static_cast<T>(x)`,
    `std::move(x)` and a C-style `(T)x`. What is left is matched against the literal spellings above, so peeling
    can only reveal a literal, never invent one."""
    a = _close_scope_ws(" ".join(arg.split()))
    while True:
        if a.startswith("(") and _balanced_end(a, 0, "(", ")") == len(a):
            a = a[1:-1].strip()
            continue
        m = re.match(r"static_cast\s*<", a)
        if m:
            j = _balanced_end(a, m.end() - 1, "<", ">")
            rest = a[j:].lstrip() if j > 0 else ""
            if rest.startswith("(") and _balanced_end(rest, 0, "(", ")") == len(rest):
                a = rest[1:-1].strip()
                continue
        m = re.match(r"(?:::)?std::move\s*(?=\()", a)
        if m:
            rest = a[m.end():]
            if _balanced_end(rest, 0, "(", ")") == len(rest):
                a = rest[1:-1].strip()
                continue
        m = _C_CAST.match(a)
        if m:
            a = a[m.end():].strip()
            continue
        return a


def _is_unrestricted_visible(arg: str) -> bool:
    return bool(_UNRESTRICTED_VISIBLE.match(_peel(arg)))


def _is_null_plugin_set(arg: str) -> bool:
    return bool(_NULL_PLUGIN_SET.match(_peel(arg)))


# `using RTF = ResponseTierFilter;` / `typedef ResponseTierFilter RTF;` in the SAME file (and an
# alias of such an alias): the alias is searched for as well. An alias declared in one file and
# used in another, or `using ResponseTierFilter::exclude;` followed by a bare `exclude(...)`, is
# not seen (GREP LIMIT).
_FILTER_TYPE = r"(?:\w+\s*::\s*)*ResponseTierFilter"
_ALIAS_USING = re.compile(r"\busing\s+(\w+)\s*=\s*(?:const\s+)?" + _FILTER_TYPE + r"\s*;")
_ALIAS_TYPEDEF = re.compile(r"\btypedef\s+" + _FILTER_TYPE + r"\s+(\w+)\s*;")


def _filter_names(code: str) -> list[str]:
    """The filter type's name and every same-file alias of it, including an alias of an alias
    (`using B = A;` where `A` itself aliases the type): iterated to a fixed point."""
    names = {"ResponseTierFilter"}
    while True:
        before = len(names)
        alt = "|".join(re.escape(n) for n in sorted(names))
        ty = r"(?:\w+\s*::\s*)*(?:" + alt + r")"
        for m in re.finditer(r"\busing\s+(\w+)\s*=\s*(?:const\s+)?" + ty + r"\s*;", code):
            names.add(m.group(1))
        for m in re.finditer(r"\btypedef\s+" + ty + r"\s+(\w+)\s*;", code):
            names.add(m.group(1))
        if len(names) == before:
            return sorted(names)


# `using std::nullopt;` / `using std::optional;` / `using namespace std;` in a file lets the same
# file spell the literal without the `std::` qualifier. When one is present the argument text is
# re-qualified before it is matched.
_USING_NULLOPT = re.compile(r"\busing\s+(?:(?:::)?std\s*::\s*(?:nullopt(?:_t)?|optional)|namespace\s+(?:::)?std)\s*;")


def _requalify_std(arg: str) -> str:
    arg = re.sub(r"(?<![\w:])nullopt_t\b", "std::nullopt_t", arg)
    arg = re.sub(r"(?<![\w:])nullopt\b", "std::nullopt", arg)
    return re.sub(r"(?<![\w:])optional\s*<", "std::optional<", arg)


def _call_args(code: str, open_paren: int) -> list[str]:
    depth = 0
    for j in range(open_paren, len(code)):
        depth += {"(": 1, ")": -1}.get(code[j], 0)
        if depth == 0:
            return _split_params(code[open_paren + 1:j])
    return []


@functools.lru_cache(maxsize=None)
def _unrestricted_in_file(rel: str, text: str) -> tuple[str, ...]:
    """The literal-unrestricted constructions in one file. Memoised: the selftest re-runs the scan
    once per mutation over a tree in which only one file changed."""
    found: list[str] = []
    # Translation phase 2 first: a backslash-newline splice joins a token split across lines.
    code = _strip_comments(re.sub(r"\\\r?\n", "", text))
    bare_std = bool(_USING_NULLOPT.search(code))
    for name in _filter_names(code):
        for m in re.finditer(r"\b" + re.escape(name) + r"\s*::\s*exclude\s*\(", code):
            args = _call_args(code, m.end() - 1)
            if len(args) < 2:
                continue
            # Close the whitespace around every `::` BEFORE re-qualifying: `std :: nullopt` has a
            # space before the bare name, so the re-qualifier would otherwise turn it into
            # `std :: std::nullopt`, which no literal spelling matches.
            arg = _requalify_std(_close_scope_ws(args[1])) if bare_std else args[1]
            if _is_unrestricted_visible(arg):
                found.append(f"{rel}: {name}::exclude(..., {' '.join(args[1].split())})")
    for m in re.finditer(r"for_fixed_plugin_poll\s*\(", code):
        args = _call_args(code, m.end() - 1)
        if len(args) == 1 and _is_null_plugin_set(args[0]):
            found.append(f"{rel}: for_fixed_plugin_poll({' '.join(args[0].split())})")
    return tuple(found)


def find_unrestricted_idioms(files: dict[str, str]) -> list[str]:
    """`file: <description>` for each literal-unrestricted filter construction in the given files."""
    found: list[str] = []
    for rel, text in files.items():
        rel = rel.replace(os.sep, "/")
        if rel == FILTER_HEADER.replace(os.sep, "/"):
            continue
        found.extend(_unrestricted_in_file(rel, text))
    return found


def check_unrestricted_idioms(files: dict[str, str]) -> list[str]:
    return [f"{f}: spells an unrestricted tier filter as a literal; resolve the caller's visibility "
            f"and pass it (tier_filter_for), or use a reviewed internal-consumer site"
            for f in find_unrestricted_idioms(files)]


def check_forbidden_markers(files: dict[str, str]) -> list[str]:
    errors = []
    for rel, text in files.items():
        for marker in FORBIDDEN_MARKERS:
            if marker in text:
                errors.append(f"{rel.replace(os.sep, '/')}: forbidden marker {marker!r} (#4990)")
    return errors


# --- driver -------------------------------------------------------------------------------

def _read_tree(root: str, subdir: str) -> dict[str, str]:
    out = {}
    for dirpath, dirnames, filenames in os.walk(os.path.join(root, subdir)):
        dirnames[:] = [d for d in dirnames if not d.startswith("build") and d != "vcpkg_installed"]
        for f in filenames:
            if f.endswith(_SRC_EXTS):
                p = os.path.join(dirpath, f)
                with open(p, encoding="utf-8", errors="replace") as fh:
                    out[os.path.relpath(p, root)] = fh.read()
    return out


def main() -> int:
    server = _read_tree(REPO_ROOT, "server")
    tests = _read_tree(REPO_ROOT, os.path.join("tests", "unit"))
    header = server.get(STORE_HEADER)
    if header is None:
        print(f"FAIL: {STORE_HEADER} not found", file=sys.stderr)
        return 1
    errors = check_store_reads(header)
    errors += check_internal_sites(server)
    errors += check_unrestricted_idioms(server)
    errors += check_forbidden_markers({**server, **tests})
    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"OK: {len(READS)} reads classified, {len(INTERNAL_CONSUMER_SITES)} internal-consumer "
          f"sites, no forbidden markers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
