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
convention). The tool-name set is the symmetric difference of the tool entries
between BASE and HEAD, i.e. every NEW tool this change adds: kTools[] in
mcp_server.cpp UNIONED with the kToolRecords[] slice of every
server/core/src/mcp_tools_*.cpp registry file present at that ref (a tool served
from the registry seam has no kTools[] row, and its handler is a
`void handle_<name>(const ToolCallContext& ctx)` function, not an
`if (tool_name == ...)` block; both shapes are scanned). (Tools this
change edits without adding are not in scope for THIS script by construction
--- kTools[] additions are grep-diffable; in-place edits to an existing
handler are not, and re-litigating every historical tool on every unrelated
touch is exactly the repo-wide-retrofit problem this script avoids. A
materially-changed EXISTING tool's retry-hint correctness is a governance
Gate-3/Gate-8 review question, not this script's job.)

HEADERS: the registry seam's shared helpers live in server/core/src/mcp_tool*.hpp
(mcp_tool_helpers.hpp's answer_unwired, the registry and deps headers). A header holds
no per-tool handler, so the per-tool scan above cannot reach it. Instead every
mcp_tool*.hpp that is NEW or whose text DIFFERS between BASE and HEAD is scanned
whole, with the same guard shape and the same `// retry-hint-exempt: <reason>`
mechanism. The header scan recognises ONLY the `auto x = call(); if (!x) { ... }` shape
with an error_response()/a4_error() call in the guard body, so it is a tripwire, not a
proof: a retryable error returned from a helper written any other way (a ternary, a
`switch`, a bare `if (!ptr)`, an error built in a callee) is not seen. Findings are
reported under the header's file name. A header that git lists but cannot show is a
GateError (fail closed), exactly like a registry file. answer_unwired has no such guard
and no retry hint by design, so it yields no finding and needs no marker; the marker
only has an effect INSIDE a guard body.

The OK line names what was scanned: the new tools and the new-or-changed headers (and
how many headers exist at HEAD), so an empty tool set is never reported as "nothing
scanned" while headers were read. The BASE/HEAD wiring lives in run(), which the
selftest drives end to end against a temporary git repository.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SERVER_CPP = "server/core/src/mcp_server.cpp"
MCP_REGISTRY_DIR = "server/core/src/"
# The registry file-name rule and the record-name grammar are SHARED with
# scripts/ci/check-api-parity.py (keep the two in step) and with build_catalogue's boot check in
# mcp_server.cpp: a registry file is `mcp_tools_[a-z0-9_]+\.cpp`, a record name `^[a-z][a-z0-9_]*$`.
# A file matching the glob `mcp_tools_*.cpp` but not this regex is an error, never a silent skip.
MCP_REGISTRY_FILE = re.compile(r"mcp_tools_[a-z0-9_]+\.cpp")
# Registry-seam helper headers: `mcp_tool` + any [a-z0-9_]* stem + `.hpp` (mcp_tool_helpers.hpp,
# mcp_tool_registry.hpp, mcp_tool_deps.hpp, and a future mcp_tools_<x>.hpp). Scanned whole when
# new or changed (see HEADERS in the module docstring); a glob match outside the regex is an error.
MCP_HEADER_FILE = re.compile(r"mcp_tool[a-z0-9_]*\.hpp")
REGISTRY_ANCHOR = "constexpr ToolRecord kToolRecords[] = {"
REGISTRY_OPENER = re.compile(r"^ {4}\{", re.MULTILINE)
REGISTRY_ENTRY = re.compile(r'^ {4}\{"([a-z][a-z0-9_]*)",', re.MULTILINE)


class GateError(RuntimeError):
    """The gate cannot establish what it scans: reported as a named FAIL (exit 1), never a
    traceback and never a silent skip."""


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


def git_ls_files(ref: str, directory: str) -> list[str]:
    """Paths directly under `directory` at `ref` (empty when the ref or directory is absent)."""
    try:
        out = subprocess.run(
            ["git", "ls-tree", "--name-only", ref, directory],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError:
        return []
    return [line for line in out.splitlines() if line]


def registry_sources(ref: str) -> dict[str, str]:
    """{path: text} of every mcp_tools_*.cpp registry file present at `ref`. A file that matches
    the glob but not MCP_REGISTRY_FILE, or one `git ls-tree` lists but `git show` cannot read, is
    a GateError: the registry set must never shrink silently."""
    files = {}
    for path in git_ls_files(ref, MCP_REGISTRY_DIR):
        base = path.rsplit("/", 1)[-1]
        if not (base.startswith("mcp_tools_") and base.endswith(".cpp")):
            continue
        if not MCP_REGISTRY_FILE.fullmatch(base):
            raise GateError(f"{path} at {ref} matches mcp_tools_*.cpp but not "
                            f"{MCP_REGISTRY_FILE.pattern}: its tools would be skipped silently")
        text = git_show(ref, path)
        if text is None:
            raise GateError(f"{path} at {ref} is listed by git ls-tree but git show failed: "
                            f"its tools cannot be scanned (fail closed)")
        files[path] = text
    return files


def header_sources(ref: str) -> dict[str, str]:
    """{path: text} of every mcp_tool*.hpp helper header present at `ref`. A file that matches the
    glob but not MCP_HEADER_FILE, or one `git ls-tree` lists but `git show` cannot read, is a
    GateError: the scanned header set must never shrink silently."""
    files = {}
    for path in git_ls_files(ref, MCP_REGISTRY_DIR):
        base = path.rsplit("/", 1)[-1]
        if not (base.startswith("mcp_tool") and base.endswith(".hpp")):
            continue
        if not MCP_HEADER_FILE.fullmatch(base):
            raise GateError(f"{path} at {ref} matches mcp_tool*.hpp but not "
                            f"{MCP_HEADER_FILE.pattern}: it would be skipped silently")
        text = git_show(ref, path)
        if text is None:
            raise GateError(f"{path} at {ref} is listed by git ls-tree but git show failed: "
                            f"it cannot be scanned (fail closed)")
        files[path] = text
    return files


def changed_headers(base_headers: dict[str, str], head_headers: dict[str, str]) -> list[str]:
    """Paths of the headers that are new at HEAD or whose text differs from BASE's (the scanned set)."""
    return [p for p in sorted(head_headers) if base_headers.get(p) != head_headers[p]]


def header_findings(base_headers: dict[str, str], head_headers: dict[str, str]) -> list[tuple[str, str, str]]:
    """(header basename, guard variable, status) for every guarded error branch in each header that
    is new at HEAD or whose text differs from BASE's. An unchanged header is not re-litigated (the
    same new-or-changed scope as the tool scan)."""
    out = []
    for path in changed_headers(base_headers, head_headers):
        text = head_headers[path]
        name = path.rsplit("/", 1)[-1]
        for varname, status in scan_block(name, text):
            out.append((name, varname, status))
    return out


def registry_slice(text: str) -> str:
    """The kToolRecords[] array body of one registry file ('' when it has no anchor)."""
    start = text.find(REGISTRY_ANCHOR)
    if start < 0:
        return ""
    end = text.find("\n};", start)
    return text[start:end if end >= 0 else len(text)]


def validate_registry_file(path: str, text: str) -> list[str]:
    """The record names of one registry file at HEAD, or a GateError: no anchor, an unterminated
    or empty slice, or a 4-space `{` record opener that is not `    {"<name>",` with a grammar
    name (a partial miss would drop a served tool from the scan)."""
    start = text.find(REGISTRY_ANCHOR)
    if start < 0:
        raise GateError(f"{path} has no `{REGISTRY_ANCHOR}` anchor: a registry file whose records "
                        f"cannot be located is not scanned (fail closed)")
    end = text.find("\n};", start)
    if end < 0:
        raise GateError(f"{path}: kToolRecords[] is unterminated (no `}};` at column 0)")
    first_line = text.count("\n", 0, start) + 1
    names = []
    for off, line in enumerate(text[start:end].split("\n")):
        if not REGISTRY_OPENER.match(line):
            continue
        m = REGISTRY_ENTRY.match(line)
        if not m:
            raise GateError(f"{path}:{first_line + off}: record opener {line.strip()[:48]!r} is not "
                            f"`    {{\"<name>\",` with a name matching [a-z][a-z0-9_]*: the scan "
                            f"would skip a record that is still served")
        names.append(m.group(1))
    if not names:
        raise GateError(f"{path}: kToolRecords[] yielded zero records (empty slice): the entry "
                        f"layout this script reads changed")
    return names


def validate_registry(files: dict[str, str]) -> dict[str, str]:
    """{tool name: registry path} over the HEAD registry files, each validated (see
    validate_registry_file); a name declared in two files is a GateError."""
    owners: dict[str, str] = {}
    for path, text in files.items():
        for name in validate_registry_file(path, text):
            if name in owners:
                raise GateError(f"registry tool {name!r} is declared in both {owners[name]} and {path}")
            owners[name] = path
    return owners


def tool_names(text: str, registry_texts: tuple[str, ...] = ()) -> set[str]:
    """kTools[] entries of mcp_server.cpp unioned with the kToolRecords[] entries of the
    registry files (only inside the array, so a nested brace-init elsewhere in a registry
    file is not mistaken for a tool). Lenient: HEAD's registry files are validated separately."""
    names = set(KTOOLS_NAME.findall(text))
    for reg in registry_texts:
        names |= set(REGISTRY_ENTRY.findall(registry_slice(reg)))
    return names


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


def _registry_handler_re(name: str) -> "re.Pattern[str]":
    return re.compile(r'void\s+handle_' + re.escape(name)
                      + r'\s*\(\s*const\s+ToolCallContext\s*&\s*ctx\s*\)\s*\{')


def find_registry_block(text: str, name: str) -> str | None:
    """The body of a registry file's `void handle_<name>(const ToolCallContext& ctx) {` (the
    parameter must be named `ctx`); None when the file has no such function."""
    m = _registry_handler_re(name).search(text)
    return find_balanced_block(text, m.end()) if m else None


def find_tool_block(text: str, name: str) -> str | None:
    """The handler body of `name` in `text`: the legacy `if (tool_name == "name") {` dispatch
    branch of mcp_server.cpp, or a registry file's `void handle_<name>(const ToolCallContext&
    ctx) {` function. None when `text` holds neither (an inline-builder tool)."""
    m = re.search(r'if \(tool_name == "' + re.escape(name) + r'"\) \{', text)
    if m:
        return find_balanced_block(text, m.end())
    return find_registry_block(text, name)


def registry_block_or_fail(files: dict[str, str], owners: dict[str, str], name: str) -> str:
    """The handler block of a HEAD registry tool. Unlike a legacy inline-builder tool, a registry
    tool has no exemption: a missing or mis-spelled `void handle_<name>(const ToolCallContext&
    ctx)` is a GateError, because its retry hints would otherwise never be scanned."""
    block = find_registry_block(files[owners[name]], name)
    if block is None:
        raise GateError(f"registry tool {name!r} ({owners[name]}) has no "
                        f"`void handle_{name}(const ToolCallContext& ctx)` definition: the handler "
                        f"convention (exact tool name, parameter named `ctx`) is what lets this gate "
                        f"scan it; rename the handler or its parameter")
    return block


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


def gap_report(gaps: list[tuple[str, str, str]], registry_tools: set[str]) -> list[str]:
    """The failure text for the unexempted gaps. A registry handler gets the H1 convention
    spelled out: the gate matches the token `retry_after_ms` in the code of the guard body, so a
    bare `-1`/number in the 4th argument of ctx.a4_error(...) is not seen."""
    lines = ["check-mcp-retry-hints: new tool(s) or changed helper header(s) have a store/query-fault error branch with",
             "no retry_after_ms and no inline `// retry-hint-exempt: <reason>` comment:"]
    for name, varname, _ in gaps:
        lines.append(f"  {name} (guard variable: {varname})")
    lines.append("")
    lines.append("Fix: pass retry_after_ms on the error_response/a4_error call (match the REST or")
    lines.append("MCP twin's own value if one exists -- never invent a number). If this guard is")
    lines.append("genuinely non-retryable (a \"not found\" lookup, an input-parse failure), add")
    lines.append("`// retry-hint-exempt: <why>` on the error_response/a4_error line itself.")
    reg = sorted({name for name, _, _ in gaps if name in registry_tools})
    if reg:
        lines.append("")
        lines.append(f"Registry handler(s) {', '.join(reg)}: write the hint as the 4th argument of")
        lines.append("`ctx.a4_error(code, message, remediation, retry_after_ms)` AND put a")
        lines.append("`/*retry_after_ms=*/` comment next to it whenever the value is not -1, e.g.")
        lines.append("`ctx.a4_error(kInternalError, \"down\", {}, /*retry_after_ms=*/mcp::kMcpStoreFaultRetryMs)`.")
        lines.append("The gate matches the token `retry_after_ms` in the code of the guard body.")
        lines.append("Line comments (`//`) are stripped first (except `// retry-hint-exempt:`), but a")
        lines.append("block comment such as `/*retry_after_ms=*/` is seen by the gate; a bare number")
        lines.append("with no token is reported as a gap even when the value is right.")
    return lines


def end_to_end_checks() -> list[tuple[str, object, object]]:
    """Drive run() against a throwaway git repository, so the BASE/HEAD wiring itself (which ref
    feeds which scan, the header scan, the pass/fail result) is under test and not only the pure
    helpers. Kills the mutants base=head, base={}, header scan dropped and header gaps ignored."""
    tool_src = 'static const ToolDef kTools[] = {\n    {"old_tool", "d"},\n};\n'
    bad = ("inline void helper(const ToolCallContext& ctx) {\n    auto rows = store->call();\n"
           "    if (!rows) {\n        ctx.res.set_content(ctx.a4_error(kInternalError, \"x\", {}, -1), \"j\");\n"
           "        return;\n    }\n}\n")
    exempt = bad.replace("        ctx.res", "        // retry-hint-exempt: terminal\n        ctx.res")
    clean = "inline void answer(const ToolCallContext& ctx, std::string b) { ctx.res.set_content(b, \"j\"); }\n"
    new_tool = ('static const ToolDef kTools[] = {\n    {"old_tool", "d"},\n    {"new_tool", "d"},\n};\n'
                'void f() {\n    if (tool_name == "new_tool") {\n        auto rows = store->call();\n'
                '        if (!rows) {\n            return a4_error(kInternalError, "x", {}, -1);\n        }\n    }\n}\n')
    src_dir = "server/core/src"
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
               GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")

    def git(root: Path, *args: str) -> str:
        return subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull, *args],
                              cwd=root, env=env, capture_output=True, text=True, check=True).stdout.strip()

    def commit(root: Path, parent: str | None, files: dict[str, str]) -> str:
        """Check out `parent`'s tree, write `files`, commit, return the new commit id."""
        if parent is not None:
            git(root, "reset", "--hard", "-q", parent)
        for rel, text in files.items():
            f = root / src_dir / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text)
        git(root, "add", "-A")
        git(root, "commit", "-q", "--allow-empty", "-m", "c")
        return git(root, "rev-parse", "HEAD")

    def go(base: str, head: str) -> tuple[int, str]:
        lines: list[str] = []
        return run(base, head, emit=lines.append), "\n".join(lines)

    saved_root = globals()["REPO_ROOT"]
    with tempfile.TemporaryDirectory(prefix="yuzu_test_retryhints_") as tmp:
        root = Path(tmp)
        git(root, "init", "-q")
        globals()["REPO_ROOT"] = root
        try:
            b0 = commit(root, None, {"mcp_server.cpp": tool_src})
            h_bad = commit(root, b0, {"mcp_tool_x.hpp": bad})
            h_clean = commit(root, b0, {"mcp_tool_x.hpp": clean})
            h_exempt = commit(root, b0, {"mcp_tool_x.hpp": exempt})
            h_touch = commit(root, h_bad, {"mcp_server.cpp": tool_src + "// unrelated edit\n"})
            h_tool = commit(root, b0, {"mcp_server.cpp": new_tool})
            rc_bad, out_bad = go(b0, h_bad)
            rc_clean, out_clean = go(b0, h_clean)
            rc_exempt, out_exempt = go(b0, h_exempt)
            rc_same, out_same = go(h_bad, h_touch)
            rc_tool, out_tool = go(b0, h_tool)
            rc_nofile, _ = go(b0, "0" * 40)
        finally:
            globals()["REPO_ROOT"] = saved_root
    # The real tree's helper headers (comments included, because the scan reads them) must come up
    # clean; a header comment that spells out a flagged guard would otherwise only fail in CI.
    real_findings = []
    for hdr in sorted((saved_root / src_dir).glob("mcp_tool*.hpp")):
        real_findings += [(hdr.name, v, st) for v, st in scan_block(hdr.name, hdr.read_text(encoding="utf-8"))]
    return [
        ("e2e: the checked-in mcp_tool*.hpp headers scan clean", real_findings, []),
        ("e2e: a new header with an unhinted guarded error fails", rc_bad, 1),
        ("e2e: the failure names the header", "mcp_tool_x.hpp" in out_bad, True),
        ("e2e: a new clean header passes", rc_clean, 0),
        ("e2e: the OK line says the header was scanned", "1 new or changed header(s)" in out_clean, True),
        ("e2e: the OK line does not claim no tools were looked at", "no new MCP tools" in out_clean, False),
        ("e2e: an exempt-marked guard in a new header passes", rc_exempt, 0),
        ("e2e: an unchanged bad header is not re-litigated", rc_same, 0),
        ("e2e: the unchanged header is not counted as scanned", "0 new or changed header(s)" in out_same, True),
        ("e2e: a new tool with an unhinted guarded error fails", rc_tool, 1),
        ("e2e: the failure names the tool", "new_tool" in out_tool, True),
        ("e2e: an unreadable HEAD fails closed", rc_nofile, 1),
    ]


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
        (
            "registry handler, ctx.a4_error with the hint -> ok",
            "void handle_fake_tool(const ToolCallContext& ctx) {\n"
            "    auto rows = store->call();\n"
            "    if (!rows) {\n"
            '        ctx.res.set_content(ctx.a4_error(kInternalError, "down", {},\n'
            "                                         /*retry_after_ms=*/mcp::kMcpStoreFaultRetryMs),\n"
            '                            "application/json");\n'
            "        return;\n"
            "    }\n"
            "}",
            "ok",
        ),
        (
            "registry handler, ctx.a4_error without the hint -> gap",
            "void handle_fake_tool(const ToolCallContext& ctx) {\n"
            "    auto rows = store->call();\n"
            "    if (!rows) {\n"
            '        ctx.res.set_content(ctx.a4_error(kInternalError, "down", {}, -1),\n'
            '                            "application/json");\n'
            "        return;\n"
            "    }\n"
            "}",
            "gap",
        ),
        (
            "registry handler, exempt comment -> exempt",
            "static void handle_fake_tool( const ToolCallContext &ctx )\n{\n"
            "    auto rows = store->call();\n"
            "    if (!rows) {\n"
            "        // retry-hint-exempt: not found, terminal\n"
            '        ctx.res.set_content(ctx.a4_error(kInternalError, "down", {}, -1),\n'
            '                            "application/json");\n'
            "        return;\n"
            "    }\n"
            "}",
            "exempt",
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
    # The tool-name set unions kTools[] with the registry's kToolRecords[] (and only that array),
    # and a handler for another tool is never mistaken for this one's.
    legacy = 'static const ToolDef kTools[] = {\n    {"old_tool", "d"},\n};\n'
    registry = (
        "namespace {\nvoid handle_new_tool(const ToolCallContext& ctx) {}\n"
        'constexpr ToolRecord kToolRecords[] = {\n    {"new_tool",\n        "d", "{}"},\n};\n'
        '}  // namespace\nstatic const X kOther[] = {\n    {"not_a_tool", 1},\n};\n'
    )
    shape_checks = (
        ("legacy names alone", tool_names(legacy), {"old_tool"}),
        ("legacy plus registry", tool_names(legacy, (registry,)), {"old_tool", "new_tool"}),
        ("registry file with no anchor adds nothing", tool_names(legacy, ("int x;\n",)), {"old_tool"}),
        ("handler lookup is by exact name", find_tool_block(registry, "new_tool") is not None, True),
        ("a prefix of the name does not match", find_tool_block(registry, "new") is None, True),
        ("a kTools row alone has no handler block", find_tool_block(legacy, "old_tool") is None, True),
    )
    for label, got, want in shape_checks:
        if got != want:
            print(f"selftest FAIL [{label}]: expected {want!r}, got {got!r}")
            failures += 1
    # B2: the gate fails closed on a registry file it cannot scan.
    def raises(fn, *needles):
        try:
            fn()
        except GateError as e:
            return all(n in str(e) for n in needles)
        return False

    def rec(*names, extra=""):
        rows = "".join(f'    {{"{n}",\n        "d", "{{}}"}},\n' for n in names)
        return f"namespace {{\n{REGISTRY_ANCHOR}\n{rows}{extra}}};\n}}  // namespace\n"

    def handler(name, param="ctx", hint=True):
        arg = "/*retry_after_ms=*/mcp::kMcpStoreFaultRetryMs" if hint else "-1"
        return (f"void handle_{name}(const ToolCallContext& {param}) {{\n    auto rows = store->call();\n"
                f"    if (!rows) {{\n        {param}.res.set_content({param}.a4_error(kInternalError, \"x\", {{}}, {arg}), \"j\");\n"
                f"        return;\n    }}\n}}\n")

    good = rec("reg_a", "reg_b")
    saved = (globals()["git_ls_files"], globals()["git_show"])
    try:
        globals()["git_ls_files"] = lambda ref, d: ["server/core/src/mcp_tools_ok.cpp", "server/core/src/mcp_tools_gone.cpp",
                                                    "server/core/src/mcp_server.cpp"]
        globals()["git_show"] = lambda ref, path: good if path.endswith("mcp_tools_ok.cpp") else None
        b_unreadable = raises(lambda: registry_sources("HEAD"), "mcp_tools_gone.cpp", "git show failed")
        globals()["git_ls_files"] = lambda ref, d: ["server/core/src/mcp_tools_Bad.cpp"]
        b_badname = raises(lambda: registry_sources("HEAD"), "mcp_tools_Bad.cpp", "mcp_tools_[a-z0-9_]+")
        globals()["git_ls_files"] = lambda ref, d: ["server/core/src/mcp_tools_.cpp"]
        b_emptystem = raises(lambda: registry_sources("HEAD"), "mcp_tools_.cpp")
        globals()["git_ls_files"] = lambda ref, d: ["server/core/src/mcp_tools_ok.cpp", "server/core/src/mcp_tools_x.hpp",
                                                    "server/core/src/mcp_tools_other.txt"]
        b_ignores = list(registry_sources("HEAD")) == ["server/core/src/mcp_tools_ok.cpp"]
    finally:
        globals()["git_ls_files"], globals()["git_show"] = saved
    one = {"p.cpp": good}
    owners = validate_registry(one)
    gap_cases = [("reg_a", "rows", "gap")]
    robust_checks = (
        ("(a) no anchor at HEAD is an error", raises(lambda: validate_registry({"p.cpp": "int x;\n"}), "p.cpp", "anchor"), True),
        ("(a) an empty slice is an error",
         raises(lambda: validate_registry({"p.cpp": f"{REGISTRY_ANCHOR}\n    // nothing\n}};\n"}), "p.cpp", "zero records"), True),
        ("(a) an unterminated slice is an error", raises(lambda: validate_registry({"p.cpp": f"{REGISTRY_ANCHOR}\n    {{\"a\", 1}},\n"}), "unterminated"), True),
        ("(a) a valid file yields its names", sorted(owners), ["reg_a", "reg_b"]),
        ("(a) a name in two files is an error", raises(lambda: validate_registry({"p.cpp": good, "q.cpp": rec("reg_a")}), "reg_a", "both"), True),
        ("grammar: an upper-case record is an error naming file and line",
         raises(lambda: validate_registry({"p.cpp": rec("reg_a", extra='    {"Reg_B", "d"},\n')}), "p.cpp:5:", "[a-z][a-z0-9_]*"), True),
        ("grammar: a hyphenated record is an error", raises(lambda: validate_registry({"p.cpp": rec("reg_a", extra='    {"reg-b", "d"},\n')}), "record opener"), True),
        ("grammar: a record opener with no comma is an error", raises(lambda: validate_registry({"p.cpp": rec("reg_a", extra='    {"reg_b"},\n')}), "record opener"), True),
        ("grammar: a lone brace opener is an error", raises(lambda: validate_registry({"p.cpp": rec("reg_a", extra="    {\n")}), "record opener"), True),
        ("grammar: tool_names does not return a non-grammar name", tool_names(legacy, (rec("reg_a", extra='    {"Reg_B", "d"},\n'),)), {"old_tool", "reg_a"}),
        ("(b) git show failure for a listed registry file is an error", b_unreadable, True),
        ("file rule: a glob match outside the regex is an error", b_badname, True),
        ("file rule: an empty stem is an error", b_emptystem, True),
        ("file rule: non-.cpp registry-looking files are ignored", b_ignores, True),
        ("(c) a HEAD registry tool with a handler is found",
         registry_block_or_fail({"p.cpp": good + handler("reg_a")}, {"reg_a": "p.cpp"}, "reg_a") is not None, True),
        ("(c) a HEAD registry tool with no handler is an error",
         raises(lambda: registry_block_or_fail({"p.cpp": good}, {"reg_a": "p.cpp"}, "reg_a"), "reg_a", "handle_reg_a"), True),
        ("(c) a handler whose parameter is not named ctx is an error",
         raises(lambda: registry_block_or_fail({"p.cpp": good + handler("reg_a", param="c")}, {"reg_a": "p.cpp"}, "reg_a"), "ctx"), True),
        ("(c) a handler for a different tool does not satisfy it",
         raises(lambda: registry_block_or_fail({"p.cpp": good + handler("reg_ab")}, {"reg_a": "p.cpp"}, "reg_a"), "reg_a"), True),
        ("(c) a legacy tool with no block is still the inline-builder exemption", find_tool_block(legacy, "old_tool") is None, True),
        ("(d) a registry gap explains the /*retry_after_ms=*/ convention",
         all(tok in " ".join(gap_report(gap_cases, {"reg_a"})) for tok in ("/*retry_after_ms=*/", "4th argument", "ctx.a4_error")), True),
        ("(d) a legacy-only gap does not carry the registry paragraph",
         any("Registry handler" in line for line in gap_report([("old_tool", "rows", "gap")], {"reg_a"})), False),
        ("scan: a registry handler carrying the /*retry_after_ms=*/ hint is ok",
         scan_block("reg_a", registry_block_or_fail({"p.cpp": good + handler("reg_a")}, {"reg_a": "p.cpp"}, "reg_a")),
         [("rows", "ok")]),
        ("scan: a registry handler gap with a bare -1 is reported",
         scan_block("reg_a", registry_block_or_fail({"p.cpp": good + handler("reg_a", hint=False)}, {"reg_a": "p.cpp"}, "reg_a")),
         [("rows", "gap")]),
    )
    for label, got, want in robust_checks:
        if got != want:
            print(f"selftest FAIL [{label}]: expected {want!r}, got {got!r}")
            failures += 1
    # Headers: the helper headers are scanned whole when new or changed, with the same gap/exempt
    # semantics, and a violation placed in a header must be seen (non-vacuity).
    hdr_gap = ("inline void helper(const ToolCallContext& ctx) {\n    auto rows = store->call();\n"
               "    if (!rows) {\n        ctx.res.set_content(ctx.a4_error(kInternalError, \"x\", {}, -1), \"j\");\n"
               "        return;\n    }\n}\n")
    hdr_exempt = hdr_gap.replace("        ctx.res", "        // retry-hint-exempt: terminal\n        ctx.res")
    hdr_hint = hdr_gap.replace("{}, -1)", "{}, /*retry_after_ms=*/mcp::kMcpStoreFaultRetryMs)")
    hdr_path = "server/core/src/mcp_tool_helpers.hpp"
    hdr_clean = "inline void answer(const ToolCallContext& ctx, std::string b) { ctx.res.set_content(b, \"j\"); }\n"
    saved_h = (globals()["git_ls_files"], globals()["git_show"])
    try:
        globals()["git_ls_files"] = lambda ref, d: ["server/core/src/mcp_tool_helpers.hpp", "server/core/src/mcp_tool_gone.hpp",
                                                    "server/core/src/mcp_server.hpp", "server/core/src/mcp_tools_ok.cpp"]
        globals()["git_show"] = lambda ref, path: hdr_gap if path.endswith("mcp_tool_helpers.hpp") else None
        h_unreadable = raises(lambda: header_sources("HEAD"), "mcp_tool_gone.hpp", "git show failed")
        globals()["git_ls_files"] = lambda ref, d: ["server/core/src/mcp_tool_Bad.hpp"]
        h_badname = raises(lambda: header_sources("HEAD"), "mcp_tool_Bad.hpp", "mcp_tool[a-z0-9_]*")
        globals()["git_ls_files"] = lambda ref, d: ["server/core/src/mcp_tool_helpers.hpp", "server/core/src/mcp_server.hpp",
                                                    "server/core/src/mcp_tools_ok.cpp", "server/core/src/mcp_tool_x.cpp"]
        globals()["git_show"] = lambda ref, path: hdr_gap
        h_only_hpp = list(header_sources("HEAD")) == [hdr_path]
    finally:
        globals()["git_ls_files"], globals()["git_show"] = saved_h
    header_checks = (
        ("header: a new header carrying an unhinted guarded error is a gap",
         header_findings({}, {hdr_path: hdr_gap}), [("mcp_tool_helpers.hpp", "rows", "gap")]),
        ("header: a changed header is scanned (base text differs)",
         header_findings({hdr_path: hdr_clean}, {hdr_path: hdr_gap}), [("mcp_tool_helpers.hpp", "rows", "gap")]),
        ("header: an unchanged header is not re-litigated",
         header_findings({hdr_path: hdr_gap}, {hdr_path: hdr_gap}), []),
        ("header: the exempt marker is honoured",
         header_findings({}, {hdr_path: hdr_exempt}), [("mcp_tool_helpers.hpp", "rows", "exempt")]),
        ("header: a retry_after_ms hint is ok",
         header_findings({}, {hdr_path: hdr_hint}), [("mcp_tool_helpers.hpp", "rows", "ok")]),
        ("header: a clean header yields nothing", header_findings({}, {hdr_path: hdr_clean}), []),
        ("header: a stray comment mentioning retry_after_ms does not spoof ok",
         header_findings({}, {hdr_path: hdr_gap.replace("        ctx.res", "        // retry_after_ms\n        ctx.res")}),
         [("mcp_tool_helpers.hpp", "rows", "gap")]),
        ("header: git show failure for a listed header is an error", h_unreadable, True),
        ("header: a glob match outside the regex is an error", h_badname, True),
        ("header: only mcp_tool*.hpp files are collected", h_only_hpp, True),
    )
    for label, got, want in header_checks:
        if got != want:
            print(f"selftest FAIL [{label}]: expected {want!r}, got {got!r}")
            failures += 1
    e2e = end_to_end_checks()
    for label, got, want in e2e:
        if got != want:
            print(f"selftest FAIL [{label}]: expected {want!r}, got {got!r}")
            failures += 1
    total = len(cases) + len(shape_checks) + len(robust_checks) + len(header_checks) + len(e2e)
    if failures:
        print(f"\ncheck-mcp-retry-hints selftest: FAIL ({failures}/{total} case(s))")
        return 1
    print(f"check-mcp-retry-hints selftest: OK ({total}/{total} case(s))")
    return 0


def run(base: str, head: str, summary: bool = False, emit=print) -> int:
    """The BASE..HEAD gate: returns the process exit code and reports every line through `emit`.
    Factored out of main() so the selftest can drive the real ref/header wiring."""
    base_src = git_show(base, MCP_SERVER_CPP)
    head_src = git_show(head, MCP_SERVER_CPP)
    if head_src is None:
        emit(f"check-mcp-retry-hints: {MCP_SERVER_CPP} not found at {head}")
        emit("check-mcp-retry-hints: FAIL (cannot verify the A5 retry-hint gate -- fail closed;")
        emit("if the file genuinely moved, update MCP_SERVER_CPP in this script)")
        return 1  # fail CLOSED: an unreadable target must never look like a clean gate

    try:
        base_registry = registry_sources(base)
        head_registry = registry_sources(head)
        head_owners = validate_registry(head_registry)
        base_headers = header_sources(base)
        head_headers = header_sources(head)
    except GateError as e:
        emit(f"check-mcp-retry-hints: {e}")
        emit("check-mcp-retry-hints: FAIL (cannot establish the registry tool set -- fail closed)")
        return 1
    base_tools = tool_names(base_src, tuple(base_registry.values())) if base_src is not None else set()
    head_tools = tool_names(head_src, tuple(head_registry.values()))
    new_tools = sorted(head_tools - base_tools)

    scanned_headers = changed_headers(base_headers, head_headers)
    header_gaps = header_findings(base_headers, head_headers)

    total_gaps = 0
    findings = list(header_gaps)
    total_gaps += sum(1 for f in header_gaps if f[2] == "gap")
    try:
        for name in new_tools:
            if name in head_owners:
                block = registry_block_or_fail(head_registry, head_owners, name)
            else:
                block = find_tool_block(head_src, name)
                if block is None:
                    continue  # inline-builder tool with no dispatch-switch block; not this shape
            for varname, status in scan_block(name, block):
                findings.append((name, varname, status))
                if status == "gap":
                    total_gaps += 1
    except GateError as e:
        emit(f"check-mcp-retry-hints: {e}")
        emit("check-mcp-retry-hints: FAIL (a registry tool's handler cannot be scanned -- fail closed)")
        return 1

    if summary:
        emit(f"New tools in range ({len(new_tools)}): {', '.join(new_tools)}")
        emit(f"New or changed headers ({len(scanned_headers)}): "
             f"{', '.join(p.rsplit('/', 1)[-1] for p in scanned_headers)}")
        for name, varname, status in findings:
            emit(f"  {name}: var={varname} [{status}]")
        emit("")

    gaps = [f for f in findings if f[2] == "gap"]
    if gaps:
        for line in gap_report(gaps, set(head_owners)):
            emit(line)
        emit(f"\ncheck-mcp-retry-hints: FAIL ({len(gaps)} new-tool/header gap(s))")
        return 1

    emit(f"check-mcp-retry-hints: OK (scanned {len(new_tools)} new tool(s) and "
         f"{len(scanned_headers)} new or changed header(s) of {len(head_headers)} at {head}; "
         f"{len(findings)} guarded finding(s), 0 unexempted gaps; between {base} and {head})")
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
    return run(args.base, args.head, args.summary)


if __name__ == "__main__":
    sys.exit(main())
