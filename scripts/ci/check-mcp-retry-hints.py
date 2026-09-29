#!/usr/bin/env python3
"""check-mcp-retry-hints.py — lexical tripwire for the A5 "honest retry_after_ms"
standard (docs/agentic-first-principle.md / ADR-1005 exec-plan Decision 16,
routed-concerns.md's A5 row: "every new/materially-changed MCP tool ships...
honest retry_after_ms").

SCOPE: NEW OR MATERIALLY-CHANGED TOOLS ONLY, not a repo-wide retrofit. This
mirrors A5's own wording. A blanket scan of every store/query-fault error
branch across mcp_server.cpp + every REST route file produces >100 hits, the
overwhelming majority of which are existence checks, business-rule 409s, and
input-parse failures that are correctly non-retryable -- distinguishing those
from a genuine transient store/query fault is a semantic question a lexical
regex cannot answer at repo scope without an unmaintainable hand-curated
allowlist. Scoping to the tools a CHANGE actually adds or touches keeps the
diff small enough that a human reviewer (governance / colleague review) can
verify each flagged branch by hand, which is the same reason F1
(check-api-parity.py) is a RATCHET on a measured baseline rather than a
type-aware analysis of the whole tree.

WHAT THIS CATCHES, within a new/changed tool's own handler block: a variable
assigned from a function CALL (`auto x = some_call(...);`) then guarded by
`if (!x) { ... }` with an error_response()/a4_error() call inside and no
retry_after_ms. That shape is how this codebase's own review history (see the
#4030/#4036 "review finding (blocking)" comments, and
governance.d/*-mcp-retry-hardening*.jsonl) already distinguishes a genuine
"the query itself failed" branch from a "this pointer was never wired"
misconfiguration guard (`if (!store_ptr)`, which correctly carries NO retry
hint everywhere this was checked by hand during this script's own authoring).

WHAT THIS IS NOT: a proof. Same disclaimer as check-api-parity.py -- a lexical
tripwire, not a type-aware parse. A flagged branch that is legitimately
terminal (a "not found" lookup, an invalid-parameter parse) gets an inline
`// retry-hint-exempt: <reason>` comment on the SAME line as the
error_response/a4_error call, not a separate allowlist file -- keeping the
exemption next to the code it exempts is more auditable than a parallel list
that silently drifts.

USAGE:
    check-mcp-retry-hints.py <BASE> <HEAD> [--summary]

<BASE>/<HEAD> are git refs (matches check-plugin-readme-touch.sh's own
convention). The tool-name set is the symmetric difference of kTools[] entries
between BASE and HEAD, i.e. every NEW tool this change adds. (Tools this
change edits without adding are not in scope for THIS script by construction
--- kTools[] additions are grep-diffable; in-place edits to an existing
handler are not, and re-litigating every historical tool on every unrelated
touch is exactly the repo-wide-retrofit problem this script avoids. A
materially-changed EXISTING tool's retry-hint correctness is a governance
Gate-3/Gate-8 review question, not this script's job.)
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SERVER_CPP = "server/core/src/mcp_server.cpp"

KTOOLS_NAME = re.compile(r'^\s*\{"([a-z_][a-z0-9_]*)",', re.MULTILINE)

# Matches only the PREFIX up to and including the guard's opening brace --
# deliberately does NOT try to capture the body itself. A naive
# `\{([^{}]*)\}` body capture cannot cross any brace, and this codebase's own
# canonical call shape (`a4_error(code, message, {}, retry_after_ms)`, with
# `{}` as the empty options/remediation argument) contains exactly one nested
# brace pair -- so that naive form silently produces ZERO matches on every
# converted site in this PR, the precise shape this gate exists to police
# (found by colleague review on PR #4261, both an external adversarial pass
# and direct human reproduction of the regex against this file's own code).
# find_balanced_block() below does real depth-counted extraction instead,
# the same algorithm find_tool_block() already uses for the outer scan.
CALL_ASSIGNED_GUARD_PREFIX = re.compile(
    r"auto\s+(\w+)\s*=\s*[\w:>*.&()_,\s\-]*?\([^;]*\);"
    r"\s*(?:if\s*\(!\1(?:_or)?\)|if\s*\(!\1\.has_value\(\)\))"
    r"\s*\{",
    re.DOTALL,
)

ERROR_CALL = re.compile(r"(error_response|a4_error|error_response_a4)\s*\(")
EXEMPT_COMMENT = re.compile(r"//\s*retry-hint-exempt:\s*\S")
LINE_COMMENT = re.compile(r"//[^\n]*")
TOOL_BLOCK_START = "if (tool_name == \"{name}\") {{"


def git_show(ref: str, path: str) -> str | None:
    try:
        return subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError:
        return None


def tool_names(text: str) -> set[str]:
    return set(KTOOLS_NAME.findall(text))


def find_balanced_block(text: str, open_brace_pos: int) -> str:
    """Given the index of an opening '{' (already consumed -- open_brace_pos
    is the position RIGHT AFTER it), return everything up to its matching
    '}', honoring nesting. Same depth-counting algorithm as find_tool_block,
    factored out so both callers get real brace-balanced extraction instead
    of a bounded-lookahead regex that breaks on the first nested '{'."""
    depth = 1
    i = open_brace_pos
    while depth > 0 and i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[open_brace_pos:i - 1]


def find_tool_block(text: str, name: str) -> str | None:
    m = re.search(r'if \(tool_name == "' + re.escape(name) + r'"\) \{', text)
    if not m:
        return None
    return find_balanced_block(text, m.end())


def scan_block(name: str, block: str) -> list[tuple[str, str]]:
    """Return (varname, status) for every call-assigned error guard in one
    tool's handler block."""
    out = []
    for m in CALL_ASSIGNED_GUARD_PREFIX.finditer(block):
        varname = m.group(1)
        body = find_balanced_block(block, m.end())
        if not ERROR_CALL.search(body):
            continue
        # Strip line comments before the retry_after_ms substring check so a
        # stray `// TODO: retry_after_ms` note can't spoof an "ok" verdict --
        # real code only. EXEMPT_COMMENT below deliberately checks the
        # UNSTRIPPED body, since that marker is itself a comment.
        code_only = LINE_COMMENT.sub("", body)
        if "retry_after_ms" in code_only:
            status = "ok"
        elif EXEMPT_COMMENT.search(body):
            status = "exempt"
        else:
            status = "gap"
        out.append((varname, status))
    return out


def selftest() -> int:
    """Regression guard for the exact defect a colleague review found on PR
    #4261: the prior body-capture regex (`\\{([^{}]*)\\}`) could not cross any
    brace, so it silently produced ZERO matches -- not even a flagged gap --
    on this codebase's own canonical call shape, which nests an empty `{}`
    options/remediation argument inside the guard body. Run standalone:
    `python3 check-mcp-retry-hints.py --selftest`."""
    cases: list[tuple[str, str, str]] = [
        (
            "canonical shape, hint present -> ok",
            'if (tool_name == "fake_tool") {\n'
            "    auto rows = store->call();\n"
            "    if (!rows) {\n"
            '        res.set_content(a4_error(kInternalError, "down", {},\n'
            "                                 /*retry_after_ms=*/mcp::kMcpStoreFaultRetryMs),\n"
            '                        "application/json");\n'
            "        return;\n"
            "    }\n"
            "}",
            "ok",
        ),
        (
            "canonical shape, hint MISSING -> gap (the bug: this used to match nothing at all)",
            'if (tool_name == "fake_tool") {\n'
            "    auto rows = store->call();\n"
            "    if (!rows) {\n"
            '        res.set_content(a4_error(kInternalError, "down", {}),\n'
            '                        "application/json");\n'
            "        return;\n"
            "    }\n"
            "}",
            "gap",
        ),
        (
            "canonical shape, exempt comment -> exempt",
            'if (tool_name == "fake_tool") {\n'
            "    auto rows = store->call();\n"
            "    if (!rows) {\n"
            "        // retry-hint-exempt: not found, terminal\n"
            '        res.set_content(a4_error(kInternalError, "down", {}),\n'
            '                        "application/json");\n'
            "        return;\n"
            "    }\n"
            "}",
            "exempt",
        ),
        (
            "stray comment mentioning retry_after_ms must NOT spoof ok",
            'if (tool_name == "fake_tool") {\n'
            "    auto rows = store->call();\n"
            "    if (!rows) {\n"
            "        // TODO: retry_after_ms\n"
            '        res.set_content(a4_error(kInternalError, "down", {}),\n'
            '                        "application/json");\n'
            "        return;\n"
            "    }\n"
            "}",
            "gap",
        ),
    ]
    failures = 0
    for label, src, expected in cases:
        block = find_tool_block(src, "fake_tool")
        if block is None:
            print(f"selftest FAIL [{label}]: find_tool_block returned None")
            failures += 1
            continue
        results = scan_block("fake_tool", block)
        if len(results) != 1:
            print(f"selftest FAIL [{label}]: expected exactly 1 finding, got {len(results)}: {results}")
            failures += 1
            continue
        _, status = results[0]
        if status != expected:
            print(f"selftest FAIL [{label}]: expected status={expected!r}, got {status!r}")
            failures += 1
    if failures:
        print(f"\ncheck-mcp-retry-hints selftest: FAIL ({failures}/{len(cases)} case(s))")
        return 1
    print(f"check-mcp-retry-hints selftest: OK ({len(cases)}/{len(cases)} case(s))")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base", nargs="?", default="origin/dev")
    ap.add_argument("head", nargs="?", default="HEAD")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--selftest", action="store_true",
                    help="run the regex/extractor regression suite and exit, ignoring base/head")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    base_src = git_show(args.base, MCP_SERVER_CPP)
    head_src = git_show(args.head, MCP_SERVER_CPP)
    if head_src is None:
        print(f"check-mcp-retry-hints: {MCP_SERVER_CPP} not found at {args.head}")
        print("check-mcp-retry-hints: FAIL (cannot verify the A5 retry-hint gate -- fail closed;")
        print("if the file genuinely moved, update MCP_SERVER_CPP in this script)")
        return 1  # fail CLOSED: an unreadable target must never look like a clean gate

    base_tools = tool_names(base_src) if base_src is not None else set()
    head_tools = tool_names(head_src)
    new_tools = sorted(head_tools - base_tools)

    if not new_tools:
        print(f"check-mcp-retry-hints: OK (no new MCP tools between {args.base} and {args.head})")
        return 0

    total_gaps = 0
    findings = []
    for name in new_tools:
        block = find_tool_block(head_src, name)
        if block is None:
            continue  # inline-builder tool with no dispatch-switch block; not this shape
        for varname, status in scan_block(name, block):
            findings.append((name, varname, status))
            if status == "gap":
                total_gaps += 1

    if args.summary:
        print(f"New tools in range ({len(new_tools)}): {', '.join(new_tools)}")
        for name, varname, status in findings:
            print(f"  {name}: var={varname} [{status}]")
        print()

    gaps = [f for f in findings if f[2] == "gap"]
    if gaps:
        print("check-mcp-retry-hints: new tool(s) have a store/query-fault error branch with")
        print("no retry_after_ms and no inline `// retry-hint-exempt: <reason>` comment:")
        for name, varname, _ in gaps:
            print(f"  {name} (guard variable: {varname})")
        print()
        print("Fix: pass retry_after_ms on the error_response/a4_error call (match the REST or")
        print("MCP twin's own value if one exists -- never invent a number). If this guard is")
        print("genuinely non-retryable (a \"not found\" lookup, an input-parse failure), add")
        print("`// retry-hint-exempt: <why>` on the error_response/a4_error line itself.")
        print(f"\ncheck-mcp-retry-hints: FAIL ({len(gaps)} new-tool gap(s))")
        return 1

    print(f"check-mcp-retry-hints: OK ({len(new_tools)} new tool(s), 0 unexempted gaps)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
