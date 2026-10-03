#!/usr/bin/env python3
"""test_update_source_trust_tokens.py -- the failure-token vocabulary the plugin can emit
must equal the one its README documents.

Source side: every string literal passed as the detail of `note_failure(acc, <prefix>, "<lit>")`
or `fail("<lit>")` (read_file's failure helper) in update_source_trust_linux_parsers.hpp and
update_source_trust_parsers.hpp, plus every literal `errno_detail` returns.
README side: the `<detail>` list in the `### Result status` CONSTRAINED row and the first column
of the 'Token detail' gloss table.
Checked: source is a subset of README (an undocumented token), and README is a subset of source
plus {planned, unparsed_entry} (a documented token nothing produces). The exception-category
and `planned` rows carry `<os>:`-style literals, not detail tokens, and are not compared.

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


def readme_tokens() -> set[str]:
    text = README.read_text(encoding="utf-8")
    status = text[text.index("### Result status"):]
    row = next(l for l in status.splitlines() if "`CONSTRAINED` | partial | `linux:apt_sources:<detail>`" in l)
    listed = row.split("with `<detail>` one of", 1)[1].split("(apt only)", 1)[0]
    toks = set(re.findall(r"`(\w+)`", listed))
    gloss = text[text.index("### Reading a constrained result"):]
    for line in gloss.splitlines():
        if line.startswith("| Token detail") or line.startswith("|---"):
            continue
        if line.startswith("| `"):
            toks |= set(re.findall(r"`([a-z_]+)`", line.split("|")[1]))
        elif line.startswith("###") and "Reading" not in line:
            break
    return toks


def main() -> int:
    src, doc = source_tokens(), readme_tokens()
    undocumented = sorted(src - doc)
    unproduced = sorted(doc - src - EXTRA_OK)
    if not src:
        print("no tokens extracted from the headers: the regexes drifted")
        return 1
    if undocumented or unproduced:
        print(f"emitted but not in the README: {undocumented}")
        print(f"in the README but never emitted: {unproduced}")
        return 1
    print(f"ok: {len(src)} source tokens, {len(doc)} README tokens")
    return 0


if __name__ == "__main__":
    sys.exit(main())
