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
# Three scan surfaces, kept in one constant (SCAN_TARGETS below) so adding a
# future HELP table is a one-line change:
#
#   (a) DESCRIBE_GLOB -- every paren-balanced `describe(` call's double-quoted
#       string-literal arguments, across every *.cpp under server/core/src AND
#       agents/core/src (the agent registers its own metrics at
#       agents/core/src/agent.cpp, e.g. around the AgentImpl constructor, and
#       would otherwise be uncovered), plus every *.hpp under those same
#       directories. Both trees are walked recursively (a file in a
#       subdirectory such as server/core/src/pg/ is scanned too), and headers
#       are found by that walk rather than listed so a new header
#       that carries an inline `describe(` call is covered with no edit here;
#       a header with no `describe(` call contributes nothing, and a
#       `describe(` mentioned in a comment or a string literal is masked out
#       exactly as it is in the .cpp files.
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
#   (c) ERL_HELP_DIRS -- every `{help, ...}` tuple's double-quoted literals
#       (binaries `<<"...">>` included) in the Erlang gateway's production
#       code (#4845): *.erl / *.hrl under each gateway/apps/<app>/src and
#       /include, walked recursively. test/, integration_test/ and _build are
#       NOT walked -- test metrics are never served on :9568, and a render
#       test may one day need a deliberately non-ASCII HELP fixture. Here a
#       non-ASCII HELP literal is FATAL, not cosmetic: in a string, a code
#       point above 255 makes prometheus_text_format raise badarg, so every
#       scrape of :9568/metrics answers HTTP 500 for the whole registry
#       (#4707, #5177). A non-ASCII binary behaves differently: one whose
#       bytes include 0x80-0x9F (an em dash's UTF-8 does) is rejected when
#       the metric is declared, at gateway start, and any other renders its
#       raw bytes. This lint flags every binary whose non-ASCII character is
#       written inside the quotes (an escape such as `<<"\351">>` is not --
#       see the residual list). Scanning it here means the PR
#       fast path catches it without Erlang. Only the tuple's real string
#       literals are scanned: a `"` in a comment, a quoted atom or a `$"`
#       literal inside the tuple is never paired with one. The key may be
#       quoted (`{'help', ...}`) or split from the `{` by a comment.
#       OTP 27+ triple-quoted strings and sigils (`~"..."`, `~b(...)`, ...)
#       are NOT parsed: their delimiter/escape rules are where a lexer this
#       small would mis-parse silently. Nor is an unterminated `$\x{...}`
#       character literal (erlc rejects it). Any file that contains the
#       WORD `help` anywhere -- a comment counts -- is lexed, and if it holds
#       any of these constructs it fails LOUDLY instead; extend erl_code_mask
#       first. The gate is the bare word, not `{help`, so that no spelling of
#       the key can make a file skip the scan.
#       Residual: this lint checks only the characters written inside the
#       string literals of a `{help, ...}` tuple. It does not see:
#         - an escape inside a string (`\x{2014}`, octal `\351`), which is
#           ASCII in the source;
#         - a non-ASCII value written outside a string literal: a `$` char
#           literal, an integer code point (`[8212]`) or a byte binary
#           (`<<226,128,148>>`);
#         - a HELP that is not a literal at the site: a `?MACRO`, a variable,
#           a helper's argument, the map form `#{help => ...}`, or a key
#           spelled with an escape (`{'\x68elp', ...}`).
#       All of these pass this lint;
#       yuzu_gw_telemetry_tests:metrics_scrape_renders_test_ renders the real
#       registry and remains the backstop for them.
#
# Usage:
#   scripts/ci/check-metrics-help-ascii.sh              # scan the real tree
#   scripts/ci/check-metrics-help-ascii.sh --selftest    # fixture self-test
#
# Exit status: 0 = clean (or selftest passed); 1 = at least one finding -- a
# non-ASCII character in a scanned HELP literal, or a scan error (a missing or
# unreadable scan target, an unsupported Erlang construct, no gateway
# {help, ...} tuple found) -- or the selftest failed; 2 = usage error, or no
# working python interpreter.

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
import contextlib
import io
import os
import re
import shutil
import sys
import tempfile
import time

repo_root = sys.argv[1]
selftest_flag = sys.argv[2] == "1"

# ---- scan surfaces (see the module header for why all three are needed) --
# (a) directories whose *.cpp files are scanned for describe(...) calls only.
# (b) HELP-table headers scanned WHOLE (every string literal in the file).
# (c) gateway Erlang roots whose {help, ...} tuples are scanned.
# Kept in one constant so adding a future HELP table is a one-line change.
SCAN_TARGETS = {
    "describe_dirs": ["server/core/src", "agents/core/src"],
    # Every *.hpp in "describe_dirs" is scanned like the .cpp files (see scan_describe_surface).
    "help_tables": [
        "server/core/src/guardian_journal_fleet_tags.hpp",
        "server/core/src/guardian_health_fleet_tags.hpp",
    ],
    # (c) roots whose apps' src/ and include/ *.erl/*.hrl are scanned for {help, ...} tuples.
    "erl_help_dirs": ["gateway/apps"],
}
# Only these per-app subdirectories are walked under an erl_help_dirs root (see the header).
ERL_CODE_SUBDIRS = ("src", "include")


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


def string_literals(segment, erlang=False):
    """Every double-quoted string literal in `segment`, as (offset, text).
    With `erlang`, an Erlang `\\^X` escape is three characters and X may be
    `\\` (as in "\\^\\"), matching erl_code_mask's string reader."""
    # The escape alternatives are mutually exclusive (\^X, or \ plus any non-^),
    # so an unterminated literal cannot backtrack exponentially.
    pattern = r'"(?:[^"\\]|\\(?:\^.|[^^]))*"' if erlang else r'"(?:[^"\\]|\\.)*"'
    return [(m.start(), m.group(0)) for m in re.finditer(pattern, segment, re.S)]


def non_ascii_findings(rel, base_line, base_offset, segment, erlang=False):
    """Findings for every byte > 0x7F inside a double-quoted literal within
    `segment`, whose first character sits at `base_offset` in the file and
    whose first line is `base_line`."""
    out = []
    for lit_off, lit in string_literals(segment, erlang):
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
    paths = []
    for scan_dir in SCAN_TARGETS["describe_dirs"]:
        base = os.path.join(root, scan_dir)
        if not os.path.isdir(base):
            if root == repo_root:
                # A listed directory that vanished from the real tree is a config error, not a
                # silent pass (selftest fixture trees hold only the directories they seed).
                findings.append((scan_dir, 0, 0, "<missing scan target>"))
            continue
        # Recursive walk (no `**` glob, no bash-only construct): every .cpp and .hpp at any depth.
        found = []
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames.sort()
            for name in sorted(filenames):
                if name.endswith((".cpp", ".hpp")):
                    found.append(os.path.join(dirpath, name))
        if not found and root == repo_root:
            findings.append((scan_dir, 0, 0, "<missing scan target>"))
        paths.extend(found)
    for full in paths:
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


def erl_code_mask(text):
    """Erlang counterpart of cpp_code_mask: blank out `%` comments, "..."
    strings, '...' quoted atoms and $c / $\\c / $\\^c / $\\x{H+} character
    literals (so `$"`, `$}`, `$\\^]` or `$%` can't desync the scan),
    preserving length and newlines. The quoted atom 'help' alone is masked
    to ` help `, so a `{'help', ...}` key is found like `{help, ...}`.
    Also returns the code-level constructs this lexer does NOT parse, as
    (offset, kind): a triple-quoted string (a `"` followed by `""`), a
    sigil (any code-level `~` -- Erlang has no `~` operator, and a format
    directive like "~s" sits inside a string, which is masked first) and a
    `$\\x{` with no closing hex-digits-then-`}` (erlc rejects it; masking to
    the next `}` anywhere would swallow real code).
    The third return value keeps ONLY the code-level "..." strings (quotes
    included) and blanks everything else, so a `"` inside a comment, a
    quoted atom or a `$"` literal can never be paired with a real string
    when a tuple's literals are extracted."""
    out = list(text)
    strings_only = [ch if ch == "\n" else " " for ch in text]
    unsupported = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "%":
            end = text.find("\n", i)
            end = n if end < 0 else end
        elif c == "$":
            if text.startswith("$\\x{", i):
                hexm = re.compile(r"\$\\x\{[0-9A-Fa-f]+\}").match(text, i)
                if hexm:
                    end = hexm.end()
                else:
                    unsupported.append((i, "unterminated $\\x{...} character literal"))
                    end = i + 3
            elif text.startswith("$\\^", i):
                end = min(n, i + 4)  # $\^X: the control character X is the 4th
            else:
                end = min(n, i + (3 if text.startswith("$\\", i) else 2))
        elif c == "~":
            unsupported.append((i, "OTP 27+ sigil"))
            i += 1
            continue
        elif c in ('"', "'"):
            if text.startswith('"""', i):
                unsupported.append((i, "OTP 27+ triple-quoted string"))
            end = i + 1
            escaped = False
            while end < n:
                ch = text[end]
                end += 1
                if escaped:
                    escaped = False
                    if ch == "^" and end < n:
                        # \^X is three characters. X may be \ but never the
                        # quote (erlc rejects that), so X is skipped unchecked.
                        end += 1
                elif ch == "\\":
                    escaped = True
                elif ch == c:
                    break
            if c == '"':
                strings_only[i:end] = text[i:end]
        else:
            i += 1
            continue
        for j in range(i, end):
            if out[j] != "\n":
                out[j] = " "
        if text[i:end] == "'help'":
            out[i + 1:end - 1] = "help"
        i = end
    return "".join(out), unsupported, "".join(strings_only)


def find_erl_help_tuples(text, mask):
    """Every `{help, ...}` tuple in `text`, bracket-balanced against `mask`
    (a HELP routinely spans several lines as adjacent literals). Returns
    (line_number_of_tuple_start, tuple_text), the slice taken from `text`. The caller passes erl_code_mask's
    strings-only view as `text`, so the slice holds the tuple's real string
    literals and nothing a quote in a comment or atom could mis-pair with."""
    tuples = []
    for m in re.finditer(r"\{\s*help\s*,", mask):
        start = m.start()
        depth = 0
        i = start
        n = len(mask)
        while i < n:
            c = mask[i]
            if c in "{([":
                depth += 1
            elif c in "})]":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        end = i + 1
        line = text.count("\n", 0, start) + 1
        tuples.append((line, text[start:end]))
    return tuples


def scan_erl_help_surface(root):
    findings = []
    paths = []
    for scan_dir in SCAN_TARGETS["erl_help_dirs"]:
        base = os.path.join(root, scan_dir)
        if not os.path.isdir(base):
            if root == repo_root:
                findings.append((scan_dir, 0, 0, "<missing scan target>"))
            continue
        # Each app's src/ and include/ only; test/, integration_test/ and _build are skipped.
        for app in sorted(os.listdir(base)):
            for sub in ERL_CODE_SUBDIRS:
                code_dir = os.path.join(base, app, sub)
                if not os.path.isdir(code_dir):
                    continue
                for dirpath, dirnames, filenames in os.walk(code_dir):
                    dirnames[:] = sorted(d for d in dirnames if d != "_build")
                    for name in sorted(filenames):
                        if name.endswith((".erl", ".hrl")):
                            paths.append(os.path.join(dirpath, name))
    tuple_count = 0
    for full in paths:
        rel = os.path.relpath(full, root).replace(os.sep, "/")
        try:
            with open(full, "r", encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError) as e:
            findings.append((rel, 0, 0, f"<unreadable: {type(e).__name__}>"))
            continue
        # The bare word, not `{help`: a comment between `{` and `help`, or the
        # quoted key 'help', must still reach the comment-aware tuple finder.
        if not re.search(r"\bhelp\b", text):
            continue
        mask, unsupported, strings_only = erl_code_mask(text)
        if unsupported:
            # A mis-mask anywhere in the file can shift a tuple's boundaries,
            # so any unparsed construct in a file mentioning `help` fails it.
            for off, kind in unsupported:
                line = text.count("\n", 0, off) + 1
                findings.append((rel, line, 0,
                                 f"<unsupported {kind}; "
                                 f"scripts/ci/check-metrics-help-ascii.sh cannot verify HELP "
                                 f"text in this file - extend its erl_code_mask>"))
            continue
        for line, tuple_text in find_erl_help_tuples(strings_only, mask):
            tuple_count += 1
            # No byte offset: non_ascii_findings measures it from the start of
            # tuple_text (base_offset never reaches the reported byte offset),
            # and tuple_text is a slice of the strings-only view, where each
            # blanked multi-byte character is one space, so it is neither
            # file- nor tuple-accurate in bytes.
            # The line number is exact.
            findings.extend((r, l, None, ch)
                            for r, l, _b, ch in non_ascii_findings(rel, line, 0, tuple_text, erlang=True))
    if root == repo_root and tuple_count == 0 and not findings:
        # The gateway declares its metrics as {help, ...} proplists; finding none
        # means the declaration shape changed under this lint, not a clean tree.
        findings.append((SCAN_TARGETS["erl_help_dirs"][0], 0, 0,
                         "<no {help, ...} tuple found; the gateway's metric declarations changed "
                         "shape under scripts/ci/check-metrics-help-ascii.sh - update its surface (c)>"))
    return findings


def run_full_scan(root):
    findings = (scan_describe_surface(root) + scan_help_table_files(root)
                + scan_erl_help_surface(root))
    if findings:
        for rel, line, byte_off, ch in findings:
            if isinstance(ch, str) and ch.startswith("<"):
                print(f"::error file={rel},line={line}::{ch}")
                continue
            cp = f"U+{ord(ch):04X}"
            where = "" if byte_off is None else f" at byte offset {byte_off}"
            print(
                f"::error file={rel},line={line}::non-ASCII byte{where} "
                f"in a HELP string literal: {cp} ({ch!r}). Prometheus HELP text must be ASCII "
                f"-- see #2128; in a gateway .erl it fails every scrape (#4845). Normalize this character (e.g. an em dash -> ' - ', an arrow "
                f"-> '->') rather than adding it to any allowlist; this gate has none by design."
            )
        print(f"\n{len(findings)} finding(s) in scanned HELP text (non-ASCII bytes or scan errors).",
              file=sys.stderr)
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

        # Seeded fixture (a, header): a describe() call inline in ANY header under a scanned
        # directory is scanned too. The file name is deliberately one no list could name.
        hdr_dir = os.path.join(tmp, "header_seeded", "server", "core", "src")
        os.makedirs(hdr_dir)
        with open(os.path.join(hdr_dir, "some_new_metrics.hpp"), "w", encoding="utf-8") as f:
            f.write(
                'inline void seed(Metrics& m) {\n'
                '    m.describe("yuzu_x_total", "Reintroduced em dash — in a header", "counter");\n'
                '}\n'
            )
        hdr_findings = scan_describe_surface(os.path.join(tmp, "header_seeded"))
        if not any(ch == "—" and r.endswith("some_new_metrics.hpp") for r, _l, _b, ch in hdr_findings):
            print(f"SELFTEST FAILED: header describe() fixture was NOT flagged: {hdr_findings}")
            return 1

        # A header that only MENTIONS describe( in a comment, or holds non-ASCII prose outside
        # any describe() call, must not be flagged (same masking as the .cpp files).
        hdr_clean_dir = os.path.join(tmp, "header_clean", "server", "core", "src")
        os.makedirs(hdr_clean_dir)
        with open(os.path.join(hdr_clean_dir, "prose.hpp"), "w", encoding="utf-8") as f:
            f.write(
                '// See describe("x — y") in the registry; an em dash — here is prose.\n'
                'inline int g() { return 1; } // section sign §\n'
            )
        hdr_clean_findings = scan_describe_surface(os.path.join(tmp, "header_clean"))
        if hdr_clean_findings:
            print(f"SELFTEST FAILED: header comment prose false-positived: {hdr_clean_findings}")
            return 1

        # Seeded fixture (a, subdirectory): a describe() call in a header AND in a .cpp placed in
        # a subdirectory of a scanned directory (as under server/core/src/pg/) is scanned too.
        sub_dir = os.path.join(tmp, "subdir_seeded", "server", "core", "src", "pg")
        os.makedirs(sub_dir)
        with open(os.path.join(sub_dir, "pool_metrics.hpp"), "w", encoding="utf-8") as f:
            f.write(
                'inline void seed(Metrics& m) {\n'
                '    m.describe("yuzu_pg_x_total", "Reintroduced em dash \u2014 in a subdir header", "counter");\n'
                '}\n'
            )
        with open(os.path.join(sub_dir, "pool_metrics.cpp"), "w", encoding="utf-8") as f:
            f.write(
                'void f(Metrics& m) {\n'
                '    m.describe("yuzu_pg_y_total", "Reintroduced em dash \u2014 in a subdir source", "counter");\n'
                '}\n'
            )
        sub_findings = scan_describe_surface(os.path.join(tmp, "subdir_seeded"))
        for suffix in ("pg/pool_metrics.hpp", "pg/pool_metrics.cpp"):
            if not any(ord(ch) == 0x2014 and r.endswith(suffix) for r, _l, _b, ch in sub_findings):
                print(f"SELFTEST FAILED: subdirectory fixture {suffix} was NOT flagged: {sub_findings}")
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

        # ---- (c) gateway .erl {help, ...} fixtures (#4845) -----------------
        # Every fixture is a virtual path inside `tmp`; nothing touches the
        # real gateway/apps.
        def erl_case(case, sub, body):
            d = os.path.join(tmp, case, "gateway", "apps", "yuzu_gw", sub)
            os.makedirs(d)
            with open(os.path.join(d, "yuzu_gw_telemetry.erl"), "w", encoding="utf-8") as f:
                f.write(body)
            return scan_erl_help_surface(os.path.join(tmp, case))

        def flagged_em_dash(findings):
            return any(ch == "—" for _r, _l, _b, ch in findings)

        def unsupported(findings):
            return any(isinstance(ch, str) and ch.startswith("<unsupported") for _r, _l, _b, ch in findings)

        # Clean: a multi-line HELP made of adjacent literals, and an ASCII binary HELP.
        f = erl_case("erl_clean", "src",
                     'declare() ->\n'
                     '    prometheus_counter:declare([\n'
                     '        {name, yuzu_gw_x_total},\n'
                     '        {help, "Total things accepted "\n'
                     '               "across every node"}]),\n'
                     '    prometheus_gauge:declare([{name, yuzu_gw_y}, {help, <<"A binary HELP">>}]).\n')
        if f:
            print(f"SELFTEST FAILED: clean .erl fixture unexpectedly flagged: {f}")
            return 1

        # Seeded: an em dash in a {help, ...} literal must fail -- the #4707 regression.
        f = erl_case("erl_seeded", "src",
                     'declare() ->\n'
                     '    prometheus_counter:declare([\n'
                     '        {name, yuzu_gw_x_total},\n'
                     '        {help, "Total things accepted — "\n'
                     '               "across every node"}]).\n')
        if not flagged_em_dash(f):
            print(f"SELFTEST FAILED: seeded .erl em-dash HELP was NOT flagged: {f}")
            return 1

        # Comment and non-HELP string prose must never be flagged.
        f = erl_case("erl_prose", "src",
                     '%% An em dash — in a comment, and a section sign §.\n'
                     'log() -> io_lib:format("x — y ~s", ["z"]).\n'
                     'declare() -> prometheus_counter:declare([{name, a}, {help, "clean"}]).\n')
        if f:
            print(f"SELFTEST FAILED: .erl comment/non-HELP prose false-positived: {f}")
            return 1

        # Char literals and a quoted atom holding brackets/quotes ahead of the
        # tuple must not desync the mask; the seeded HELP is still found.
        f = erl_case("erl_mask", "src",
                     'p($}) -> 1; p($") -> 2; p($\\x{7D}) -> 3; p(\'}\') -> 4.\n'
                     'declare() -> prometheus_counter:declare([{name, a}, {help, "bad — here"}]).\n')
        if not flagged_em_dash(f):
            print(f"SELFTEST FAILED: .erl mask-guard fixture was NOT flagged: {f}")
            return 1

        # A binary HELP is scanned too.
        f = erl_case("erl_binary", "src",
                     'declare() -> prometheus_gauge:declare([{name, a}, {help, <<"bad — here">>}]).\n')
        if not flagged_em_dash(f):
            print(f"SELFTEST FAILED: .erl binary HELP fixture was NOT flagged: {f}")
            return 1

        # test/ is deliberately not walked (test metrics are never served).
        f = erl_case("erl_testdir", "test",
                     'declare() -> prometheus_counter:declare([{name, a}, {help, "bad — here"}]).\n')
        if f:
            print(f"SELFTEST FAILED: .erl fixture under test/ was scanned: {f}")
            return 1

        # OTP 27+ sigil and triple-quoted string in a file holding {help: fail loudly.
        f = erl_case("erl_sigil", "src",
                     'declare() -> prometheus_counter:declare([{name, a}, {help, ~"x"}]).\n')
        if not unsupported(f):
            print(f"SELFTEST FAILED: .erl sigil HELP did not fail loudly: {f}")
            return 1
        f = erl_case("erl_triple", "src",
                     'declare() -> prometheus_counter:declare([{name, a}, {help, """\n'
                     '    x\n'
                     '    """}]).\n')
        if not unsupported(f):
            print(f"SELFTEST FAILED: .erl triple-quoted HELP did not fail loudly: {f}")
            return 1

        # Narrowness: a sigil in a file with no {help is not this lint's business.
        f = erl_case("erl_sigil_nohelp", "src", 'greet() -> ~"hello".\n')
        if f:
            print(f"SELFTEST FAILED: .erl sigil in a file not mentioning help flagged: {f}")
            return 1

        # A bad character only in the SECOND adjacent literal, in a tuple that
        # follows a clean one, is flagged on its own line.
        f = erl_case("erl_later_literal", "src",
                     'declare() ->\n'
                     '    prometheus_counter:declare([{name, a}, {help, "clean"}]),\n'
                     '    prometheus_counter:declare([\n'
                     '        {name, b},\n'
                     '        {help, "first part is fine "\n'
                     '               "second — is not"}]).\n')
        if not any(ord(ch) == 0x2014 and line == 6 for _r, line, _b, ch in f if len(ch) == 1):
            print(f"SELFTEST FAILED: .erl second-literal em dash not flagged at line 6: {f}")
            return 1

        # A `"` inside a comment or a quoted atom within the tuple must not
        # pair with a real literal and hide the HELP after it.
        f = erl_case("erl_comment_quote", "src",
                     'declare() -> prometheus_counter:declare([{name, a},\n'
                     '    {help, "ok " % it"s fine\n'
                     '           "bad — x"}]),\n'
                     '    prometheus_counter:declare([{name, b}, {help, [\'a"b\', "bad — y"]}]).\n')
        if sum(1 for _r, _l, _b, ch in f if ch == "—") != 2:
            print(f"SELFTEST FAILED: .erl comment/atom quote hid a HELP literal: {f}")
            return 1

        # The next fixtures each hold exactly one HELP tuple, so a sibling
        # tuple can never stand in for the one the lint failed to see.
        # A comment between `{` and `help` (valid Erlang) must not hide the tuple.
        f = erl_case("erl_comment_split", "src",
                     'declare() -> prometheus_counter:declare([{name, a}, { % key below\n'
                     '      help, "bad — x"}]).\n')
        if not flagged_em_dash(f):
            print(f"SELFTEST FAILED: .erl comment-split {{help key was NOT scanned: {f}")
            return 1

        # The quoted-atom key 'help' is the same atom as help.
        f = erl_case("erl_quoted_key", "src",
                     "declare() -> prometheus_counter:declare([{name, a}, {'help', \"bad — x\"}]).\n")
        if not flagged_em_dash(f):
            print(f"SELFTEST FAILED: .erl {{'help', ...}} key was NOT scanned: {f}")
            return 1

        # $\^X is four characters: a bracket as the X must not leak into the
        # tuple balancer, either ending the tuple early (a miss) ...
        f = erl_case("erl_ctrl_escape_fn", "src",
                     'declare() -> prometheus_counter:declare([{name, a},\n'
                     '    {help, [$\\^], $\\^], "bad — x"]}]).\n')
        if not flagged_em_dash(f):
            print(f"SELFTEST FAILED: .erl $\\^] char literal hid a HELP literal: {f}")
            return 1
        # ... or running it on past its end into a non-HELP string (a false positive).
        # The em dash inside the tuple must be flagged (the tuple was scanned);
        # the one in the prose string after it must not be.
        f = erl_case("erl_ctrl_escape_fp", "src",
                     'f() -> _ = {help, [$\\^[, "in tuple — x"]}, "nonhelp — y".\n')
        if sum(1 for _r, _l, _b, ch in f if ch == "—") != 1:
            print(f"SELFTEST FAILED: .erl $\\^[ char literal mis-bounded a tuple: {f}")
            return 1

        # Inside a string or a quoted atom, \^X is three characters and X may
        # be \ : "\^\" is the one-character string [28], so the reader must
        # not take its closing quote as escaped and hide the tuple after it.
        f = erl_case("erl_string_ctrl_escape", "src",
                     'c() -> "\\^\\".\n'
                     'declare() -> prometheus_counter:declare([{name, a}, {help, "bad – x"}]).\n')
        if not any(ch == "–" for _r, _l, _b, ch in f):
            print(f"SELFTEST FAILED: .erl \"\\^\\\" string hid a later HELP literal: {f}")
            return 1
        f = erl_case("erl_atom_ctrl_escape", "src",
                     "c() -> '\\^\\'.\n"
                     'declare() -> prometheus_counter:declare([{name, a}, {help, "bad – x"}]).\n')
        if not any(ch == "–" for _r, _l, _b, ch in f):
            print(f"SELFTEST FAILED: .erl '\\^\\' quoted atom hid a later HELP literal: {f}")
            return 1
        # ... and the same rule when the literals are read back out of the tuple.
        f = erl_case("erl_tuple_ctrl_escape", "src",
                     'declare() -> prometheus_counter:declare([{name, a}, {help, ["\\^\\", "bad – x"]}]).\n')
        if not any(ch == "–" for _r, _l, _b, ch in f):
            print(f"SELFTEST FAILED: .erl \"\\^\\\" inside a HELP tuple hid its other literal: {f}")
            return 1
        # An escaped backslash followed by a plain ^ is not a \^X escape: "a\\^"
        # ends at its own quote, so the literal after it must still be scanned.
        f = erl_case("erl_escaped_backslash_caret", "src",
                     'declare() -> prometheus_counter:declare([{name, a}, {help, ["a\\\\^", "bad – x"]}]).\n')
        if not any(ch == "\u2013" for _r, _l, _b, ch in f):
            print(f"SELFTEST FAILED: .erl \"a\\\\^\" over-ate its closing quote: {f}")
            return 1

        # Regression for exponential backtracking: an unterminated string made
        # of a long run of \^ (not valid Erlang; erlc rejects it). With
        # overlapping escape alternatives 42 repeats take tens of seconds; the
        # mutually exclusive ones take milliseconds. The elapsed time is
        # checked after the scan returns, so a regression still runs to
        # completion before failing; 5 s is far above the healthy time.
        started = time.monotonic()
        erl_case("erl_caret_backtrack", "src",
                 'declare() -> prometheus_counter:declare([{name, a}, {help, "' + '\\^' * 42 + '\n')
        elapsed = time.monotonic() - started
        if elapsed > 5.0:
            print(f"SELFTEST FAILED: .erl unterminated run of \\^ took {elapsed:.1f}s (regex backtracking)")
            return 1

        # An unterminated $\x{ must fail loudly, not mask to the next `}`.
        f = erl_case("erl_unterminated_hex", "src",
                     'p($\\x{7D) -> 1.\n'
                     'declare() -> prometheus_counter:declare([{name, a}, {help, "x"}]).\n')
        if not any(isinstance(ch, str) and ch.startswith("<unsupported unterminated $\\x{")
                   for _r, _l, _b, ch in f):
            print(f"SELFTEST FAILED: .erl unterminated $\\x{{ did not fail loudly: {f}")
            return 1

        # Deliberate: the gate is the bare word `help`, so a file that only
        # mentions it in a comment is lexed, and an unparsed construct in it
        # fails loudly (erl_sigil_nohelp above is the no-mention counterpart).
        f = erl_case("erl_sigil_help_word", "src",
                     '%% the help text lives elsewhere\n'
                     'greet() -> ~"hello".\n')
        if not any(isinstance(ch, str) and ch.startswith("<unsupported OTP 27+ sigil")
                   for _r, _l, _b, ch in f):
            print(f"SELFTEST FAILED: .erl sigil in a file mentioning help did not fail loudly: {f}")
            return 1

        # The full scan includes surface (c). Assert on the .erl annotation
        # itself, not on the exit code: in a fixture root surface (b) always
        # reports its two HELP tables missing, so rc is 1 either way.
        full_root = os.path.join(tmp, "erl_full_scan")
        erl_case("erl_full_scan", "src",
                 'declare() -> prometheus_counter:declare([{name, a}, {help, "bad — z"}]).\n')
        full_out = io.StringIO()
        with contextlib.redirect_stdout(full_out), contextlib.redirect_stderr(io.StringIO()):
            run_full_scan(full_root)
        if ("file=gateway/apps/yuzu_gw/src/yuzu_gw_telemetry.erl,line=1::non-ASCII"
                not in full_out.getvalue()):
            print(f"SELFTEST FAILED: run_full_scan did not report the seeded .erl: {full_out.getvalue()!r}")
            return 1
        # The gateway annotation carries no byte offset (it would be one into the masked view).
        erl_lines = [ln for ln in full_out.getvalue().splitlines() if ".erl,line=" in ln]
        if not erl_lines or any("byte offset" in ln for ln in erl_lines):
            print(f"SELFTEST FAILED: gateway annotation reported a byte offset: {erl_lines!r}")
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
