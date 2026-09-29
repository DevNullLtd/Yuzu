#!/usr/bin/env bash
# check-metrics-help-ascii.sh -- Prometheus HELP-text ASCII gate (#2128)
#
# A zero-cost, no-build text scan (the check-plugin-spawn-lexical.sh /
# check-compose-versions.sh pattern) that fails a PR reintroducing a
# non-ASCII byte into a Prometheus metric's HELP text. Grafana/Prometheus
# render HELP strings verbatim; a stray em dash or curly quote copy-pasted
# from prose has repeatedly slipped into a `describe(...)` call and shown up
# mangled wherever the exposition text is not read back as UTF-8. This is
# scoped to HELP text ONLY -- it must never scan whole .cpp files, because
# server.cpp alone carries ~1,400 lines of non-ASCII COMMENT prose (box-
# drawing, em dashes) that #2128 explicitly says to leave alone.
#
# Two scan surfaces, kept in one constant (SCAN_TARGETS below) so adding a
# future HELP table is a one-line change:
#
#   (a) DESCRIBE_GLOB -- every paren-balanced `describe(` call's double-quoted
#       string-literal arguments, across server/core/src/*.cpp AND
#       agents/core/src/*.cpp (the agent registers its own metrics at
#       agents/core/src/agent.cpp, e.g. around the AgentImpl constructor, and
#       would otherwise be uncovered).
#
#   (b) HELP_TABLE_FILES -- every double-quoted string literal in the two
#       Guardian HELP-table headers (guardian_journal_fleet_tags.hpp,
#       guardian_health_fleet_tags.hpp), scanned WHOLE. Their table entries
#       (`m.help`) and `kGuardian*Help` constants reach `describe()`
#       INDIRECTLY, through a loop variable or a named constant, never as a
#       literal argument to `describe(` itself -- so rule (a)'s per-call
#       literal scan cannot see them; a name-based / call-site-based match
#       would silently miss these aggregate initializers. Scanning the two
#       files whole is safe only because they are pure metric-name/HELP
#       tables with no other prose to false-positive on.
#
# Usage:
#   scripts/ci/check-metrics-help-ascii.sh              # scan the real tree
#   scripts/ci/check-metrics-help-ascii.sh --selftest    # fixture self-test
#
# Exit status: 0 = clean (or selftest passed), 1 = a non-ASCII byte was found
# in a scanned HELP string (or selftest failed), 2 = usage error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SELFTEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --selftest) SELFTEST=1 ;;
    *)
      echo "usage: $0 [--selftest]" >&2
      exit 2
      ;;
  esac
  shift
done

# Resolve a WORKING interpreter, not merely one whose name is on PATH (the
# Windows python3.exe App Execution Alias stub reports success on
# `command -v` but is not a real interpreter).
PYTHON_BIN=""
for _candidate in python3 python; do
  if command -v "$_candidate" >/dev/null 2>&1 && "$_candidate" -c "" >/dev/null 2>&1; then
    PYTHON_BIN="$_candidate"
    break
  fi
done
if [ -z "$PYTHON_BIN" ]; then
  echo "check-metrics-help-ascii: no working python interpreter found (tried python3, python)." >&2
  exit 2
fi

"$PYTHON_BIN" - "$REPO_ROOT" "$SELFTEST" <<'PYEOF'
import glob
import os
import re
import shutil
import sys
import tempfile

repo_root = sys.argv[1]
selftest_flag = sys.argv[2] == "1"

# ---- scan surfaces (see the module header for why both are needed) ------
# (a) directories whose *.cpp files are scanned for describe(...) calls only.
# (b) HELP-table headers scanned WHOLE (every string literal in the file).
# Kept in one constant so adding a future HELP table is a one-line change.
SCAN_TARGETS = {
    "describe_dirs": ["server/core/src", "agents/core/src"],
    "help_tables": [
        "server/core/src/guardian_journal_fleet_tags.hpp",
        "server/core/src/guardian_health_fleet_tags.hpp",
    ],
}


def cpp_code_mask(text):
    """Blank out `//` and `/* */` comments and quoted-literal contents,
    preserving length and newlines, so a paren inside a comment or a
    character/string literal can never be mistaken for call-boundary syntax.
    describe(...) call-detection and paren-balancing run against this mask;
    the actual string-literal scan for non-ASCII bytes still reads the
    original (unmasked) source slice."""
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            end = n if close < 0 else close + 2
        elif text[i] in ('"', "'"):
            quote = text[i]
            end = i + 1
            escaped = False
            while end < n:
                c = text[end]
                end += 1
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == quote:
                    break
        else:
            i += 1
            continue
        for j in range(i, end):
            if out[j] != "\n":
                out[j] = " "
        i = end
    return "".join(out)


def find_describe_calls(text):
    """Every `describe(...)` call in `text`, paren-balanced (a call routinely
    spans several lines, so this must not be line-based). Call boundaries are
    located against a comment/string-masked view of `text` so a paren inside
    a comment or a character literal can't desync the balance count; the
    returned call_text slice is taken from the ORIGINAL text so its string
    literals are scanned for real. Returns a list of
    (line_number_of_call_start, byte_offset_of_call_start, call_text)."""
    calls = []
    mask = cpp_code_mask(text)
    for m in re.finditer(r"\bdescribe\s*\(", mask):
        start = m.end() - 1  # index of the opening '('
        depth = 0
        i = start
        n = len(mask)
        while i < n:
            c = mask[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        end = i + 1
        line = text.count("\n", 0, m.start()) + 1
        byte_offset = len(text[:start].encode("utf-8"))
        calls.append((line, byte_offset, text[start:end]))
    return calls


def string_literals(segment):
    """Every double-quoted string literal in `segment`, as (offset, text)."""
    return [(m.start(), m.group(0)) for m in re.finditer(r'"(?:[^"\\]|\\.)*"', segment, re.S)]


def non_ascii_findings(rel, base_line, base_offset, segment):
    """Findings for every byte > 0x7F inside a double-quoted literal within
    `segment`, whose first character sits at `base_offset` in the file and
    whose first line is `base_line`."""
    out = []
    for lit_off, lit in string_literals(segment):
        abs_off = base_offset + lit_off
        for k, ch in enumerate(lit):
            if ord(ch) > 0x7F:
                # Line number: count newlines from the start of the call/file
                # segment up to this character.
                line = base_line + segment[:lit_off + k].count("\n")
                # Byte offset within the (UTF-8 encoded) file, for precision
                # when several non-ASCII characters share a line.
                byte_off = len(segment[:lit_off + k].encode("utf-8"))
                out.append((rel, line, byte_off, ch))
    return out


def scan_describe_surface(root):
    findings = []
    for scan_dir in SCAN_TARGETS["describe_dirs"]:
        base = os.path.join(root, scan_dir)
        if not os.path.isdir(base):
            continue
        for full in sorted(glob.glob(os.path.join(base, "*.cpp"))):
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                with open(full, "r", encoding="utf-8") as f:
                    text = f.read()
            except OSError as e:
                findings.append((rel, 0, 0, f"<unreadable: {type(e).__name__}>"))
                continue
            for line, byte_offset, call_text in find_describe_calls(text):
                findings.extend(non_ascii_findings(rel, line, byte_offset, call_text))
    return findings


def scan_help_table_files(root):
    findings = []
    for rel in SCAN_TARGETS["help_tables"]:
        full = os.path.join(root, rel)
        if not os.path.isfile(full):
            # A listed HELP table that vanished is a config error, not a
            # silent pass -- surface it rather than shrinking the surface.
            findings.append((rel, 0, 0, "<missing scan target>"))
            continue
        try:
            with open(full, "r", encoding="utf-8") as f:
                text = f.read()
        except OSError as e:
            findings.append((rel, 0, 0, f"<unreadable: {type(e).__name__}>"))
            continue
        findings.extend(non_ascii_findings(rel, 1, 0, text))
    return findings


def run_full_scan(root):
    findings = scan_describe_surface(root) + scan_help_table_files(root)
    if findings:
        for rel, line, byte_off, ch in findings:
            if isinstance(ch, str) and ch.startswith("<"):
                print(f"::error file={rel},line={line}::{ch}")
                continue
            cp = f"U+{ord(ch):04X}"
            print(
                f"::error file={rel},line={line}::non-ASCII byte at byte offset {byte_off} "
                f"in a HELP string literal: {cp} ({ch!r}). Prometheus HELP text must be ASCII "
                f"-- see #2128. Normalize this character (e.g. an em dash -> ' - ', an arrow "
                f"-> '->') rather than adding it to any allowlist; this gate has none by design."
            )
        print(f"\n{len(findings)} non-ASCII byte(s) found in scanned HELP text.", file=sys.stderr)
        return 1
    print("check-metrics-help-ascii: clean (no non-ASCII bytes in scanned HELP text).")
    return 0


def run_selftest():
    tmp = tempfile.mkdtemp(prefix="yuzu_test_help_ascii_")
    try:
        # Clean fixture: an ASCII-only describe() call, including one that
        # spans multiple lines, must not be flagged.
        clean_dir = os.path.join(tmp, "clean", "server", "core", "src")
        os.makedirs(clean_dir)
        with open(os.path.join(clean_dir, "server.cpp"), "w", encoding="utf-8") as f:
            f.write(
                'void f() {\n'
                '    metrics_.describe("yuzu_thing_total",\n'
                '                      "A perfectly ordinary ASCII HELP string - nothing to see",\n'
                '                      "counter");\n'
                '}\n'
            )
        clean_findings = scan_describe_surface(os.path.join(tmp, "clean"))
        if clean_findings:
            print(f"SELFTEST FAILED: clean fixture unexpectedly flagged: {clean_findings}")
            return 1

        # Seeded fixture (a): an em dash inside a describe() HELP literal in
        # server/core/src must be flagged.
        seeded_dir = os.path.join(tmp, "seeded", "server", "core", "src")
        os.makedirs(seeded_dir)
        with open(os.path.join(seeded_dir, "server.cpp"), "w", encoding="utf-8") as f:
            f.write(
                'void f() {\n'
                '    metrics_.describe("yuzu_thing_total",\n'
                '                      "Reintroduced em dash — right here", "counter");\n'
                '}\n'
            )
        seeded_findings = scan_describe_surface(os.path.join(tmp, "seeded"))
        if not any(ch == "—" for _r, _l, _b, ch in seeded_findings):
            print(f"SELFTEST FAILED: seeded em-dash fixture was NOT flagged: {seeded_findings}")
            return 1

        # Comment false-positive guard: non-ASCII prose OUTSIDE any
        # describe() call (a comment) must never be flagged -- #2128's whole
        # point is that comments are left alone.
        comment_dir = os.path.join(tmp, "comment_only", "server", "core", "src")
        os.makedirs(comment_dir)
        with open(os.path.join(comment_dir, "server.cpp"), "w", encoding="utf-8") as f:
            f.write(
                '// A comment with an em dash — and a section sign § in prose.\n'
                'void f() {\n'
                '    metrics_.describe("yuzu_thing_total", "clean", "counter");\n'
                '}\n'
            )
        comment_findings = scan_describe_surface(os.path.join(tmp, "comment_only"))
        if comment_findings:
            print(f"SELFTEST FAILED: comment prose false-positived: {comment_findings}")
            return 1

        # Seeded fixture (a, agent side): agents/core/src is scanned too --
        # the agent registers its own metrics and would otherwise be
        # uncovered.
        agent_dir = os.path.join(tmp, "agent_seeded", "agents", "core", "src")
        os.makedirs(agent_dir)
        with open(os.path.join(agent_dir, "agent.cpp"), "w", encoding="utf-8") as f:
            f.write(
                'void f() {\n'
                '    metrics_.describe("yuzu_agent_thing_total",\n'
                '                      "Reintroduced em dash — here too", "gauge");\n'
                '}\n'
            )
        agent_findings = scan_describe_surface(os.path.join(tmp, "agent_seeded"))
        if not any(ch == "—" for _r, _l, _b, ch in agent_findings):
            print(f"SELFTEST FAILED: agents/core/src em-dash fixture was NOT flagged: {agent_findings}")
            return 1

        # Seeded fixture (b): a non-ASCII byte in one of the HELP-table
        # headers must be flagged even though it never appears as a literal
        # argument to describe( ) itself -- the whole reason surface (b)
        # exists.
        table_dir = os.path.join(tmp, "table_seeded", "server", "core", "src")
        os.makedirs(table_dir)
        with open(
            os.path.join(table_dir, "guardian_journal_fleet_tags.hpp"), "w", encoding="utf-8"
        ) as f:
            f.write(
                'namespace detail {\n'
                'struct Entry { const char* gauge; const char* help; };\n'
                'inline constexpr Entry kGuardianJournalMetrics[] = {\n'
                '    {"yuzu_x", "Reintroduced em dash — in a table entry"},\n'
                '};\n'
                '} // namespace detail\n'
            )
        saved_files = list(SCAN_TARGETS["help_tables"])
        SCAN_TARGETS["help_tables"] = ["server/core/src/guardian_journal_fleet_tags.hpp"]
        try:
            table_findings = scan_help_table_files(os.path.join(tmp, "table_seeded"))
        finally:
            SCAN_TARGETS["help_tables"] = saved_files
        if not any(ch == "—" for _r, _l, _b, ch in table_findings):
            print(f"SELFTEST FAILED: HELP-table fixture was NOT flagged: {table_findings}")
            return 1

        # Metric NAME / TYPE arguments are never edited by the fix this gate
        # guards, and this gate scans EVERY literal in the call -- a
        # non-ASCII byte accidentally placed in the metric name would also
        # be caught, which is correct: it proves the gate is not silently
        # ASCII-blind on that argument position either.
        name_dir = os.path.join(tmp, "name_seeded", "server", "core", "src")
        os.makedirs(name_dir)
        with open(os.path.join(name_dir, "server.cpp"), "w", encoding="utf-8") as f:
            f.write(
                'void f() {\n'
                '    metrics_.describe("yuzu_th—ing_total", "clean help", "counter");\n'
                '}\n'
            )
        name_findings = scan_describe_surface(os.path.join(tmp, "name_seeded"))
        if not any(ch == "—" for _r, _l, _b, ch in name_findings):
            print(f"SELFTEST FAILED: non-ASCII metric-name fixture was NOT flagged: {name_findings}")
            return 1

        print("check-metrics-help-ascii --selftest: all fixtures behaved as expected.")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if selftest_flag:
    sys.exit(run_selftest())
else:
    sys.exit(run_full_scan(repo_root))
PYEOF
