#!/usr/bin/env python3
"""#2146 lexical gate: the workflow-execute docs say what the code says about zero-reach and about an
absent command_id.

Two facts each live in more than one place, and nothing else notices when one copy drifts:
  * the closed list of zero-reach statuses (kWorkflowZeroReachStatuses in workflow_execute.hpp) must
    be named in the REST manual's "Nothing reached 503" block and in the MCP manual's
    execute_workflow row (`definition_changed` is MCP-only: REST carries no ticket-bound effects);
  * a step with no command_id is NOT proof a step was never sent (the id is stored by a write that
    can be dropped), so no source or manual may say it was.
The selftest removes a status and re-inserts the old claim in memory and proves the gate names both.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
HPP = ROOT / "server/core/src/workflow_execute.hpp"
REST = ROOT / "docs/user-manual/rest-api.md"
MCP = ROOT / "docs/user-manual/mcp.md"
NEVER_SENT = re.compile(r"no\s+`?command_id`?\s+was\s+never\s+sent", re.I)
KEYED_PHRASE = "use a new idempotency key (MCP: a new approval)"
REST_ONLY_EXEMPT = {"definition_changed"}


def statuses(hpp_text):
    m = re.search(r"kWorkflowZeroReachStatuses\{(.*?)\};", hpp_text, re.S)
    return re.findall(r'"([a-z_]+)"', m.group(1)) if m else []


def rest_block(text):
    i = text.find("**Nothing reached `503`:**")
    j = text.find("A missing `Workflow:Execute` permission is a `403`", i)
    return text[i:j] if i >= 0 and j > i else ""


def mcp_row(text):
    m = re.search(r"^\| \d+ \| `execute_workflow`.*$", text, re.M)
    return m.group(0) if m else ""


def problems(hpp_text, rest_text, mcp_text, swept):
    out = []
    toks = statuses(hpp_text)
    if len(toks) < 12:
        out.append("kWorkflowZeroReachStatuses not parsed or shorter than the 12 known statuses")
    block, row = rest_block(rest_text), mcp_row(mcp_text)
    if not block:
        out.append("rest-api.md: the 'Nothing reached `503`' block is missing")
    if not row:
        out.append("mcp.md: the execute_workflow row is missing")
    for t in toks:
        if block and t not in REST_ONLY_EXEMPT and f"`{t}`" not in block:
            out.append(f"rest-api.md: zero-reach status `{t}` is not named")
        if row and f"`{t}`" not in row:
            out.append(f"mcp.md: zero-reach status `{t}` is not named")
    if block and KEYED_PHRASE not in block.replace("\n", " ") and "use a new idempotency key" not in block:
        out.append("rest-api.md: the keyed zero-reach rule is not stated")
    if row and KEYED_PHRASE not in row:
        out.append("mcp.md: the keyed zero-reach rule is not stated")
    for name, text in swept.items():
        for m in NEVER_SENT.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            out.append(f"{name}:{line}: claims an absent command_id proves a step was never sent")
    return out


def sweep():
    files = {}
    for p in [ROOT / "docs/mcp-server.md", *(ROOT / "docs/user-manual").glob("*.md"),
              *(ROOT / "server/core/src").glob("*.cpp"), *(ROOT / "server/core/src").glob("*.hpp")]:
        files[str(p.relative_to(ROOT))] = p.read_text(encoding="utf-8", errors="replace")
    return files


def main():
    hpp, rest, mcp = (p.read_text(encoding="utf-8") for p in (HPP, REST, MCP))
    swept = sweep()
    found = problems(hpp, rest, mcp, swept)

    # selftest: the gate must name a dropped status and a reintroduced claim.
    drop = problems(hpp, rest.replace("`run_failed`", "`x`"), mcp, swept)
    claim = problems(hpp, rest, mcp, {**swept, "x.md": "a step with no `command_id` was never sent"})
    if not any("run_failed" in p for p in drop) or not any("x.md" in p for p in claim):
        found.append("selftest: the gate did not detect an in-memory mutation")
    # The row is found by its text, not its table number: a renumber must stay green, a dropped
    # status in that row must not.
    row = mcp_row(mcp)
    renum = problems(hpp, rest, mcp.replace(row, re.sub(r"^\| \d+ ", "| 9999 ", row), 1), swept)
    mdrop = problems(hpp, rest, mcp.replace(row, row.replace("`run_failed`", "`x`")), swept)
    if renum != found or not any("run_failed" in p for p in mdrop):
        found.append("selftest: the mcp.md row anchor is tied to its number or misses a dropped status")

    for p in found:
        print("FAIL:", p)
    if found:
        return 1
    print(f"ok: {len(statuses(hpp))} statuses pinned, {len(swept)} files swept")
    return 0


if __name__ == "__main__":
    sys.exit(main())
