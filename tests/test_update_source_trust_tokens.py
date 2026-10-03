#!/usr/bin/env python3
"""test_update_source_trust_tokens.py -- the failure-token vocabulary the plugin can emit
must equal the one its README documents.

Source side: every string literal passed as the detail of `note_failure(acc, <prefix>, "<lit>")`
or `fail("<lit>")` (read_file's failure helper) in update_source_trust_linux_parsers.hpp and
update_source_trust_parsers.hpp, plus every literal `errno_detail` returns.
README side, two vocabularies: the `### Result status` table's CONSTRAINED rows (the `<detail>`
list, plus the detail of any backticked `linux:<source>:<tok>` literal: `planned` lives on its own
`linux:rpm_repo:planned` row, not in the list) and the first column of the 'Token detail' gloss table.
Checked, for EACH table separately (a token deleted from one table must not be masked by the
other): source is a subset of the table (an undocumented token), and the table is a subset of source
plus {planned, unparsed_entry} (a documented token nothing produces). The exception-category rows
carry `<os>:`-style literals, not detail tokens, and are not compared.

Runnable standalone: `python3 tests/test_update_source_trust_tokens.py [README]` (a script, not
pytest: pytest would collect zero tests). Exit 1 prints the difference.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "agents" / "plugins" / "update_source_trust" / "src"
HEADERS = [SRC / "update_source_trust_linux_parsers.hpp", SRC / "update_source_trust_parsers.hpp"]
README = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "agents" / "plugins" / "update_source_trust" / "README.md"
EXTRA_OK = {"planned", "unparsed_entry"}  # produced by name outside the two regexes' reach


def source_tokens() -> set[str]:
    toks: set[str] = set()
    for h in HEADERS:
        text = h.read_text(encoding="utf-8")
        toks |= set(re.findall(r'note_failure\(\s*acc\s*,\s*[^,]+,\s*"(\w+)"\s*\)', text))
        toks |= set(re.findall(r'\bfail\(\s*"(\w+)"\s*\)', text))
        m = re.search(r"errno_detail\(int err, IoStage stage\).*?\n\}\n", text, re.S)
        if m:
            toks |= set(re.findall(r'return\s+"(\w+)"\s*;', m.group(0)))
    return toks


def readme_tokens() -> tuple[set[str], set[str]]:
    """(status-row tokens, gloss tokens), each from its own table."""
    text = README.read_text(encoding="utf-8")
    status = text[text.index("### Result status"):text.index("### Reading a constrained result")]
    status_toks: set[str] = set()
    for line in status.splitlines():
        if not line.startswith("| `CONSTRAINED`"):
            continue
        if "with `<detail>` one of" in line:
            listed = line.split("with `<detail>` one of", 1)[1].split("(apt only)", 1)[0]
            status_toks |= set(re.findall(r"`(\w+)`", listed))
        status_toks |= set(re.findall(r"`linux:\w+:(\w+)`", line))
    gloss_toks: set[str] = set()
    gloss = text[text.index("### Reading a constrained result"):]
    for line in gloss.splitlines():
        if line.startswith("| Token detail") or line.startswith("|---"):
            continue
        if line.startswith("| `"):
            gloss_toks |= set(re.findall(r"`([a-z_]+)`", line.split("|")[1]))
        elif line.startswith("###") and "Reading" not in line:
            break
    return status_toks, gloss_toks


def main() -> int:
    src = source_tokens()
    if not src:
        print("no tokens extracted from the headers: the regexes drifted")
        return 1
    status_toks, gloss_toks = readme_tokens()
    bad = False
    for name, table in (("Result status row", status_toks), ("Token detail gloss", gloss_toks)):
        undocumented = sorted(src - table)
        unproduced = sorted(table - src - EXTRA_OK)
        if undocumented or unproduced:
            bad = True
            print(f"{name}: emitted but not documented: {undocumented}")
            print(f"{name}: documented but never emitted: {unproduced}")
    if bad:
        return 1
    print(f"ok: {len(src)} source tokens, {len(status_toks)} status-row, {len(gloss_toks)} gloss")
    return 0


if __name__ == "__main__":
    sys.exit(main())
