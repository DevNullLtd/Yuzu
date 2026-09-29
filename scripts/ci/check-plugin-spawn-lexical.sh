#!/usr/bin/env bash
# check-plugin-spawn-lexical.sh -- Decision-10a per-PR lexical spawn gate
# (docs/adr/3002-acquisition-ladder.md:459-488).
#
# A zero-cost, no-build text scan (the check-compose-versions.sh pattern)
# that fails a PR introducing a raw process-spawn token in agents/plugins/*
# or agents/core -- outside the registered allowlist below -- rather than
# going through the shared, sanctioned runner
# (yuzu::agent::run_bounded_subprocess, agents/core/src/subprocess_runner.cpp).
# This is tier (a) of the ADR's two-tier enforcement; CodeQL (tier b,
# scheduled, call-identity-aware) is the deep net this cannot be -- see the
# ADR for why neither tier alone is sufficient.
#
# Token semantics are pinned exactly as the ADR specifies:
#   * word-boundary matching, so a raw token never matches as a substring of
#     a longer identifier (`subsystem(` must never trip on `system`);
#   * the exec family is enumerated BY NAME, never a glob -- a bare `exec*`
#     would match every plugin's own `execute(` method. `execve`, `fexecve`,
#     and `execveat` are ALSO enumerated here, beyond the ADR's original
#     literal list -- this PR's own runner work (A5's explicit envp, B6's
#     TOCTOU-safe exec) introduces real calls to them, and leaving them out
#     would let a plugin call raw execve() and never trip the gate;
#   * `system`/`fork`/`posix_spawn`/`popen`/`_popen` as bounded whole words;
#   * the Windows family spelled out (`CreateProcess*`, `ShellExecute*`,
#     `_spawn*`/`_wspawn*`);
#   * a token only counts as a hit when it looks like a CALL (`token(`),
#     narrowing (not eliminating -- see the comment/string stripper below)
#     prose false positives.
#
# Two allowlist tiers, both by FILE (see the ADR's "exceptions by call
# identity, never by file" -- the per-call-identity mechanism is the sink
# manifest, docs/agent-spawn-sink-manifest.md, population tracked separately
# in #2380 and out of this PR's scope; a coarser file-level allowlist is the
# honest state this lexical-only gate can enforce today without that
# manifest):
#   1. RUNNER_ALLOWLIST -- the ONE canonical, permanent, ADR-sanctioned
#      allowlist entry: the runner's own implementation. A second file
#      forking/exec'ing/CreateProcess'ing directly is exactly the "scattered
#      copies" this ADR exists to prevent -- route through the runner
#      instead of adding a second entry here.
#   2. GRANDFATHERED -- pre-existing, NOT-YET-MIGRATED call sites (migration
#      sequencing is a separate roadmap concern, not this ADR's or this
#      script's job -- see fork_lock.hpp's own residual ledger). Frozen as of
#      this PR so a full-tree run is green against the CURRENT codebase
#      instead of failing on ~40 known, already-accepted sites the migration
#      hasn't reached yet; a NEW site in a file not already on this list
#      still fails the gate. Removing an entry as a site migrates onto the
#      runner is expected and welcome.
#
# KNOWN tier-(a) LIMIT -- context/relocation blindness (GF-loc, CDX-R5-01):
# the grandfathered base-vs-head diff compares CALL IDENTITY (token + argument
# bytes, see find_calls). It CANNOT see a change that leaves a call's text
# identical but alters its CONTEXT -- relocating an unchanged spawn into a
# reachable path, removing a guarding `if`, or activating a dormant `#if 0`
# call. ADR-3002 Decision 1 (3002-acquisition-ladder.md:368-372) states the
# Decision-10 lexical gate "cannot see" routed-data/context attacks and that
# the REVIEW-ENFORCED freeze rule closes that window; Decision 10 scopes this
# gate as tier (a) "plain-text", with scheduled CodeQL as the tier (b) deep
# net. The function-granular stable-site-ID mechanism (`<plugin>/<function>#<n>`)
# that would catch relocation is the sink manifest (#2380), out of this PR's
# scope. So a reviewer of a GRANDFATHERED-file diff must not treat a green gate
# as proof a legacy spawn's reachability is unchanged -- read the diff.
#
# A second tier-(a) residual (K-R6-02): the call signature normalizes
# inter-token whitespace and emits punctuators as single-char tokens, so a
# whitespace-sensitive maximal-munch REGROUPING inside a frozen call's arguments
# -- `argv[a+++b]` -> `argv[a+ ++b]`, or `x && y` -> `x & &y` -- changes the
# runtime value while reading as a pure reflow. No grandfathered call currently
# contains such an adjacency (verified), so this is a theoretical residual of
# the same tier-(a) lexical class delegated to review + CodeQL.
#
# Usage:
#   scripts/ci/check-plugin-spawn-lexical.sh              # scan the real tree
#   scripts/ci/check-plugin-spawn-lexical.sh --selftest    # fixture self-test
#
# Exit status: 0 = clean (or selftest passed), 1 = a raw spawn token was
# found outside the allowlist (or selftest failed), 2 = usage error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SELFTEST=0
# Base ref for the grandfathered base-vs-head call-identity diff (BR-011). A
# grandfathered file is no longer skipped wholesale: its calls are diffed vs
# this base, so a NEW raw spawn beside a legacy one still fails. Default
# origin/dev; the CI workflow fetches it. K-08/CDX-R4-10: if a REQUESTED base
# cannot be resolved (shallow fetch / unfetched ref) the run HARD-FAILS with
# exit 2 -- a config error never reads as a passing gate.
BASE_REF="${LEXICAL_GATE_BASE:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --selftest) SELFTEST=1 ;;
    --base) shift; BASE_REF="${1:-}" ;;
    --base=*) BASE_REF="${1#--base=}" ;;
    *)
      echo "usage: $0 [--selftest] [--base <ref>]" >&2
      exit 2
      ;;
  esac
  shift
done
if [ -z "$BASE_REF" ]; then BASE_REF="origin/dev"; fi

# Resolve a WORKING interpreter, not merely one whose name is on PATH:
# `command -v python3` reports success on Windows even when the only thing
# answering to that name is the default python3.exe App Execution Alias
# stub, which prints a Microsoft-Store-redirect message and exits non-zero
# instead of running any code. The Windows CI runner's provisioned, self-
# tested toolchain guarantees `python` (deploy/windows/README.md's
# toolchain-manifest.json, docs/windows-build.md's toolchain table) --
# `python3` was never part of that contract, so prefer it where it genuinely
# works but fall back rather than hard-requiring it.
PYTHON_BIN=""
for _candidate in python3 python; do
  if command -v "$_candidate" >/dev/null 2>&1 && "$_candidate" -c "" >/dev/null 2>&1; then
    PYTHON_BIN="$_candidate"
    break
  fi
done
if [ -z "$PYTHON_BIN" ]; then
  echo "check-plugin-spawn-lexical: no working python interpreter found (tried python3, python --" >&2
  echo "python3 already a hard build dependency, see CLAUDE.md's PyYAML note)." >&2
  exit 2
fi

"$PYTHON_BIN" - "$REPO_ROOT" "$SELFTEST" "$BASE_REF" <<'PYEOF'
import bisect
import collections
import os
import re
import shutil
import subprocess
import sys
import tempfile

repo_root = sys.argv[1]
selftest_flag = sys.argv[2] == "1"
base_ref = sys.argv[3] if len(sys.argv) > 3 else ""

# ---- pinned token family (ADR-3002:459-488) ----------------------------
# Literal spellings (exec family + POSIX bounded words). `posix_spawn`/`vfork`
# and the whole Windows family are covered by FAMILY_PATTERNS below so their
# real suffixed entry points (CreateProcessAsUserW, ShellExecuteExA,
# posix_spawnp, …) also match — CDX-P2-001/K-21/K-03.
LITERAL_TOKENS = [
    "execl", "execlp", "execle", "execv", "execvp", "execvpe",
    "execve", "fexecve", "execveat",
    "system", "fork", "vfork", "popen", "_popen",
    # K-04/CDX-R2-008: the MSVCRT wide + <tchar.h> twins of system/popen are the
    # SAME shell-interpreter injection surface the ADR bans; forkpty is a pty
    # fork+exec. The wide/tchar exec/spawn twins are covered by FAMILY_PATTERNS.
    "_wsystem", "_tsystem", "_wpopen", "_tpopen", "forkpty",
]
# Regex fragments (NOT escaped) matching the suffixed/variant real entry points.
FAMILY_PATTERNS = [
    r"posix_spawnp?",
    r"CreateProcess(?:AsUser|WithLogonW|WithTokenW)?[AW]?",
    r"ShellExecute(?:Ex)?[AW]?",
    r"_[wt]?spawn(?:l|le|lp|lpe|v|ve|vp|vpe)",   # spawn*/_wspawn*/_tspawn*
    # K-02/CDX-R4-06: the canonical MSVCRT <process.h> exec family is the
    # plain-underscore _exec* (the non-underscore names are the deprecated POSIX
    # aliases on Windows); the w/t infix is OPTIONAL so _execvpe AND _wexec*/
    # _texec* all match.
    r"_[wt]?exec(?:l|le|lp|lpe|v|ve|vp|vpe)",
]
# Longest literal first so e.g. `execvpe` precedes `execv` in the alternation
# (Python `re` picks the first alternative that matches at a position). The
# trailing `\s*\(` also rejects a shorter partial that can't reach the call paren.
LITERAL_SET = frozenset(LITERAL_TOKENS)
# A banned identifier is an exact literal spelling OR a FULL match of one of the
# suffixed/variant family patterns. Because the tokenizer below matches WHOLE
# identifier tokens (not `\b`-bounded substrings), `subsystem`/`execute` can
# never match `system`/`exec*` -- the false-positive class the ADR warns about.
FAMILY_RE = re.compile("|".join(FAMILY_PATTERNS))


class UnterminatedLiteral(Exception):
    """A string/char literal ran to EOF. The lexer is now desynchronised from
    the compiler's view, so anything it reports about the rest of the file is
    unreliable -- callers must FAIL, never treat a clean result as clean."""

    def __init__(self, line):
        super().__init__(f"unterminated literal starting at line {line}")
        self.line = line


def is_banned(name):
    return name in LITERAL_SET or FAMILY_RE.fullmatch(name) is not None


# Raw-string encoding prefixes (C++ [lex.string]): `R`, plus the u8/u/U/L
# encoding-prefixed forms. An identifier equal to one of these immediately
# followed by `"` opens a raw string literal `R"delim( ... )delim"`.
RAW_PREFIXES = frozenset({"R", "u8R", "uR", "UR", "LR"})


def _raw_string_end(s, body_start, n):
    """Given ``body_start`` = the index just past a raw-string opening quote
    (`R"`/`u8R"`/...), return the index just past the closing `)delim"`, ``n`` if
    unterminated, or ``None`` if there is no `(` (not a well-formed raw string,
    caller falls through).

    MUST be called over the ORIGINAL (unspliced) text, never the spliced text.
    C++ translation phase 2 does NOT splice inside a raw body, so a `\\`+newline
    there is literal data; deleting it first can manufacture a `)delim"` that
    does not exist in the source (CDX-R8-03 / K-R8-03). See tokenize()."""
    close_paren = s.find("(", body_start)
    if close_paren == -1:
        return None
    delim = s[body_start:close_paren]
    term = ")" + delim + '"'
    end = s.find(term, close_paren + 1)
    return (end + len(term)) if end != -1 else n


def splice_phase2(text):
    """C++ translation phase 2: delete every backslash-newline (`\\`+`\\n` or
    `\\`+`\\r\\n`), returning ``(spliced, line_map, orig_offsets)`` where
    ``line_map[i]`` is the 1-based ORIGINAL source line of ``spliced[i]`` and
    ``orig_offsets[i]`` is the ORIGINAL byte index of ``spliced[i]``.

    Splicing is UNCONDITIONAL (a complete first pass with NO string/comment/raw
    awareness) -- that is exactly what closes the split-token evasion: a split
    token (`sys\\`+nl+`tem`) always becomes contiguous, and a split block-comment
    terminator becomes adjacent, regardless of any `"R"` literal or `R"` comment
    that precedes it (K-R7-01/CDX-R7-01: a context-aware splice mis-detected a
    raw opener inside an ordinary string and disabled splicing for the file tail).

    The RAW-STRING EXEMPTION (a `\\`+newline INSIDE `R"(...)"` is literal data,
    not a splice -- CDX-R6-01) is handled DOWNSTREAM in tokenize(), which
    recognizes raw strings correctly in CODE state and RESTORES each raw `lit`
    token's bytes from the ORIGINAL source via ``orig_offsets``. So the exemption
    never depends on this context-free pass guessing where raw strings are.
    """
    out = []
    line_map = []
    orig_offsets = []
    i, n = 0, len(text)
    line = 1
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n and (
            text[i + 1] == "\n"
            or (text[i + 1] == "\r" and i + 2 < n and text[i + 2] == "\n")
        ):
            i += 3 if text[i + 1] == "\r" else 2
            line += 1
            continue
        out.append(c)
        line_map.append(line)
        orig_offsets.append(i)
        if c == "\n":
            line += 1
        i += 1
    return "".join(out), line_map, orig_offsets


def _is_id_start(ch):
    return ch.isalpha() or ch == "_"


def _is_id(ch):
    return ch.isalnum() or ch == "_"


def tokenize(spliced, line_map, orig_offsets, original_text):
    """A real C++ phase-3 tokenizer over already-spliced text. Emits the tokens
    the spawn check needs -- identifiers (`id`), a left paren (`lparen`), string/
    char/raw-string literals (`lit`, carrying their EXACT raw text), and any
    other single significant character (`other`) -- while CONSUMING (emitting
    nothing for) whitespace and `//` / `/* */` comments. A literal is ONE token,
    so an identifier or `(` inside it is never emitted (cannot look like a call,
    B2/CDX-01) yet its bytes are preserved for the call signature (CDX-R5-01: a
    change inside a literal must be detectable). Each token carries its ORIGINAL
    source line via line_map and its start offset.

    This is where raw strings are recognized correctly (in CODE state, never
    inside an ordinary string or comment -- so the K-R7-01/CDX-R7-01 evasion,
    where a `"R"` literal or `R"` comment mis-triggered a context-free splice,
    cannot recur). ``orig_offsets`` maps each spliced index back to its ORIGINAL
    source index; a raw literal's `lit` token text is RESTORED from
    ``original_text`` so a `\\`+newline inside `R"(...)"` -- which unconditional
    splicing removed from ``spliced`` but which C++ keeps as literal bytes
    (CDX-R6-01) -- is preserved for the signature.
    """
    tokens = []
    i, n = 0, len(spliced)
    while i < n:
        c = spliced[i]
        # whitespace
        if c in " \t\r\n\f\v":
            i += 1
            continue
        # line comment
        if c == "/" and i + 1 < n and spliced[i + 1] == "/":
            i += 2
            while i < n and spliced[i] != "\n":
                i += 1
            continue
        # block comment
        if c == "/" and i + 1 < n and spliced[i + 1] == "*":
            i += 2
            while i + 1 < n and not (spliced[i] == "*" and spliced[i + 1] == "/"):
                i += 1
            i += 2  # past the closing */ (over-steps EOF harmlessly if unterminated)
            continue
        # identifier -- OR a raw-string encoding prefix
        if _is_id_start(c):
            start = i
            while i < n and _is_id(spliced[i]):
                i += 1
            name = spliced[start:i]
            if name in RAW_PREFIXES and i < n and spliced[i] == '"':
                # raw string R"delim( ... )delim" -- emit as ONE `lit` token
                # carrying its EXACT raw text (prefix included), so a change to
                # its content (e.g. a command-separating space -> newline) is a
                # signature change (CDX-R5-01/K-R5-03), while a `(` inside it is
                # never a separate token and cannot look like a call.
                # Locate the terminator in the ORIGINAL text, not the spliced
                # text. C++ exempts raw bodies from phase 2, so a `\`+newline
                # inside the body is literal data; searching the spliced text
                # deletes it first and can INVENT a `)delim"` that the compiler
                # never sees (CDX-R8-03 / K-R8-03). That desync cut both ways:
                # it false-positived on benign literal text, and -- the reason
                # this is fail-open, not just noisy -- it ended the literal
                # early so the real `)"` re-opened an ordinary string that
                # swallowed a later LIVE spawn call, which the gate then missed
                # (a compiling probe the pre-rework gate caught).
                orig_quote = orig_offsets[i]
                stop_orig = _raw_string_end(original_text, orig_quote + 1, len(original_text))
                if stop_orig is not None:
                    # The token's bytes are the ORIGINAL span [id start, terminator).
                    lit_text = original_text[orig_offsets[start]:stop_orig]
                    tokens.append(("lit", lit_text, line_map[start], start))
                    # Resume at the first spliced index at/after the original
                    # end (orig_offsets is strictly increasing). An unterminated
                    # literal yields len(orig_offsets) -> i = n, ending the loop.
                    i = bisect.bisect_left(orig_offsets, stop_orig)
                    continue
                # No '(' -> not a well-formed raw string: fall through and emit
                # `name` as an identifier; the `"` becomes a normal string below.
            tokens.append(("id", name, line_map[start], start))
            continue
        # preprocessing-number (so an identifier is never split out of a number)
        if c.isdigit():
            start = i
            i += 1
            while i < n:
                d = spliced[i]
                if d in "eEpP" and i + 1 < n and spliced[i + 1] in "+-":
                    i += 2
                    continue
                if d.isalnum() or d in "._'":
                    i += 1
                    continue
                break
            tokens.append(("other", spliced[start:i], line_map[start], start))
            continue
        # string literal -- emitted as one `lit` token with its exact raw text
        # (so its bytes participate in the call signature; a `(` inside it is
        # never a token).
        #
        # K-R8-01/CDX-R8-04: an UNTERMINATED literal desynchronises this lexer
        # from the compiler's. The classic shape is a dead `#if 0` branch
        # holding an unclosed quote: the preprocessor never tokenizes it, so the
        # file still COMPILES, while this scanner runs to EOF and swallows the
        # entire tail -- including any live spawn call below it -- into one
        # `lit`. There is no safe way to guess where the literal "should" have
        # ended, so this FAILS CLOSED: the file is reported rather than silently
        # scanned wrong. (Full preprocessing-state handling is the durable fix
        # and belongs with the tier-(b) CodeQL leg; a false alarm here costs one
        # rewritten literal, a miss costs the gate's entire purpose.)
        if c == '"':
            start = i
            i += 1
            while i < n and spliced[i] != '"':
                i += 2 if (spliced[i] == "\\" and i + 1 < n) else 1
            if i >= n:
                raise UnterminatedLiteral(line_map[start])
            i += 1
            tokens.append(("lit", spliced[start:i], line_map[start], start))
            continue
        # character literal -- likewise a `lit` token, same fail-closed rule.
        if c == "'":
            start = i
            i += 1
            while i < n and spliced[i] != "'":
                i += 2 if (spliced[i] == "\\" and i + 1 < n) else 1
            if i >= n:
                raise UnterminatedLiteral(line_map[start])
            i += 1
            tokens.append(("lit", spliced[start:i], line_map[start], start))
            continue
        if c == "(":
            tokens.append(("lparen", "(", line_map[i], i))
            i += 1
            continue
        tokens.append(("other", c, line_map[i], i))
        i += 1
    return tokens


def find_calls(text):
    """Every banned raw-spawn CALL in `text` as [(token_name, orig_line,
    signature)]: a banned identifier token immediately followed (in the
    significant-token stream) by `(`. `system + (x)` is NOT a call (an `other`
    token sits between them); `system(x)`, `system (x)`, and `sys\\`+nl+`tem(x)`
    all are.

    The `signature` is composed from the TOKEN STREAM -- the identifier plus the
    text of every token from its `(` through the matching `)`, single-space
    joined. This normalizes only INTER-token whitespace (so a pure code reflow of
    a frozen call is NOT a change, K-R5-02) while preserving the exact bytes
    INSIDE literals (so `system(R\"(a b)\")` and `system(R\"(a<newline>b)\")`
    differ -- the newline turns one shell command into two, CDX-R5-01/K-R5-03).
    It lets the grandfather check compare CALL IDENTITY (token + arguments)
    instead of token counts or drift-prone line numbers (CDX-R4-01): a one-for-
    one swap or any argument change (Decision 1: frozen sites may not gain
    interpolated input) yields a signature absent from base and is caught, while
    a pure deletion (migration to the runner) is not. It remains blind to
    context/relocation (see the module header) -- ADR-3002 delegates that to
    review + the #2380 sink manifest."""
    spliced, line_map, orig_offsets = splice_phase2(text)
    tokens = tokenize(spliced, line_map, orig_offsets, text)
    calls = []
    for idx in range(len(tokens)):
        kind, name, line, _off = tokens[idx]
        if kind != "id" or not is_banned(name):
            continue
        # The invoking `(` is not always ADJACENT to the identifier: C++
        # function-pointer DECAY lets a call place `)` in between, and all of
        # `(system)("x")`, `(*system)("x")` and `(0, system)("x")` invoke
        # `system` while a strict-adjacency test sees `)` and moves on (K-FN-01
        # -- every one compiled and every one was missed). Skip a run of closing
        # parens before deciding. This stays a LEXICAL test: it does not track a
        # pointer stored in a variable and called later (`auto p = &system;
        # p("x");`), which needs dataflow -- see the residual ledger in the
        # module header and ADR-3002's tier-(b) CodeQL leg.
        lp = idx + 1
        while lp < len(tokens) and tokens[lp][0] == "other" and tokens[lp][1] == ")":
            lp += 1
        if lp >= len(tokens) or tokens[lp][0] != "lparen":
            continue
        # Walk to the matching ')' over the TOKEN stream (a ')' inside a literal
        # is part of that literal's single token, never a closer), collecting the
        # token texts for the signature.
        depth = 0
        sig_tokens = []
        closed = False
        for j in range(lp, len(tokens)):
            tk, tt, _tl, _toff = tokens[j]
            sig_tokens.append(tt)
            if tk == "lparen":
                depth += 1
            elif tt == ")":
                depth -= 1
                if depth == 0:
                    closed = True
                    break
        sig = name + " " + " ".join(sig_tokens) if closed else name + " ("
        calls.append((name, line, sig))
    return calls



# ---- allowlist tier 1: the canonical registered allowlist entry --------
RUNNER_ALLOWLIST = {
    "agents/core/src/subprocess_runner.cpp",
}

# ---- allowlist tier 2: pre-existing, not-yet-migrated sites -------------
# Grounded in the actual tree as of this PR (verified by running this
# script's --selftest-adjacent full scan against a bare allowlist and
# reading every hit -- not copied from a doc comment that could have
# drifted). A meson.build hit (Meson's own `host_machine.system()`) is not a
# C/C++ source file and is excluded by SCAN_EXT below, not by this list.
GRANDFATHERED = {
    "agents/plugins/firewall/src/firewall_plugin.cpp",
    # installed_apps AND msi_packages both removed here (#3405): this PR
    # argv-ised the last shell hop in each, so both files now have zero raw
    # spawn primitives and their entries grandfathered nothing while masking any
    # regression that re-introduced one. Removing an entry moves the file from
    # the base-diff path onto the FULL scan, so it is strictly stricter.
    # script_exec's own entry is removed here: it argv-ised its last raw spawn
    # primitives onto the shared subprocess runner, so its entry grandfathered
    # nothing while masking any regression that re-introduced one.
    # software_actions AND license_scan (Linux leg) removed here too (Wave 4
    # PR4.3b): same reasoning -- software_actions_plugin.cpp and
    # licensing_linux.cpp are now clean of raw spawn tokens outside the runner.
    # network_config stays -- it is still rung 3 and remains a separate PR's to
    # remove, the remaining half of #3405.
    "agents/plugins/network_config/src/network_config_plugin.cpp",
    "agents/plugins/tar/src/tar_mapdrive_collector.cpp",
    "agents/plugins/tar/src/tar_service_collector.cpp",
    "agents/plugins/software_actions/src/software_actions_plugin.cpp",
    "agents/plugins/vuln_scan/src/config_checks.hpp",
    "agents/plugins/vuln_scan/src/vuln_scan_plugin.cpp",
    "agents/plugins/windows_updates/src/windows_updates_plugin.cpp",
    "agents/core/src/dex_linux_collector.cpp",
    "agents/core/src/dex_linux_journal.hpp",
    "agents/core/src/dex_macos_collector.cpp",
    "agents/core/src/trigger_engine.cpp",
}

ALLOWLIST = RUNNER_ALLOWLIST | GRANDFATHERED

# CDX-P2-012/K-09: agents/shared holds header-only helpers that compile into
# BOTH agent-core and the plugins, so a raw spawn introduced there is reachable
# by governed code — scan it too.
SCAN_DIRS = ["agents/plugins", "agents/core/src", "agents/core/include", "agents/shared"]
# CDX-005: Objective-C++/Objective-C (.mm/.m) are C++ for this control boundary
# and CAN call popen/fork/exec/CreateProcess — this PR globally enables .mm and
# ships agents/plugins/wifi/src/wifi_corewlan.mm, so the gate must scan them or a
# macOS acquisition path could add a raw spawn undetected.
# Every extension a C/C++ TU can ship as. `.cxx`/`.c++`/`.C` and the
# `.inl`/`.ipp`/`.tcc` inline-include forms were absent, and a spawn call
# in any of them evaded the gate entirely (verified empirically).
SCAN_EXT = (".c", ".cc", ".cpp", ".cxx", ".c++", ".C", ".h", ".hpp", ".hh",
            ".hxx", ".inl", ".ipp", ".tcc", ".mm", ".m")


def iter_scanned_files(root):
    for scan_dir in SCAN_DIRS:
        base = os.path.join(root, scan_dir)
        if not os.path.isdir(base):
            continue
        # followlinks=True: a symlinked plugin directory was silently
        # unscanned under os.walk's default (verified empirically). The
        # tree is a source checkout, not attacker-controlled, so the
        # usual cycle concern does not apply.
        for dirpath, _dirnames, filenames in os.walk(base, followlinks=True):
            for fn in filenames:
                if fn.endswith(SCAN_EXT):
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, root).replace(os.sep, "/")
                    yield rel, full


def scan(root, allowlist):
    findings = []
    for rel, full in iter_scanned_files(root):
        if rel in allowlist:
            continue
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as e:
            # FAIL CLOSED. Skipping an unreadable file made the gate report
            # `clean` and exit 0 for a file it never looked at — a scannable
            # source that happens to be unreadable (permissions, a transient
            # I/O error on the runner, a broken symlink) silently left the
            # scan incomplete while the run still passed. That is the same
            # failure shape as the desynchronised-lexer skip below: a gate
            # that cannot see a file must not vouch for it.
            findings.append((rel, 0, f"<unreadable: {type(e).__name__}>"))
            continue
        try:
            for tok, lineno, _sig in find_calls(text):
                findings.append((rel, lineno, tok))
        except UnterminatedLiteral as e:
            # FAIL CLOSED (K-R8-01/CDX-R8-04): a desynchronised lexer cannot
            # vouch for the rest of this file, so report it rather than let a
            # swallowed tail read as clean.
            findings.append((rel, e.line, "<unterminated-literal>"))
    return findings


def resolve_base(root, base):
    """Return the resolved commit for `base`, or None if it cannot be found
    (no git, unfetched ref) -- callers then disable added-line enforcement
    with a warning rather than silently passing."""
    if not base:
        return None
    try:
        r = subprocess.run(
            ["git", "-C", root, "rev-parse", "--verify", "--quiet", base + "^{commit}"],
            capture_output=True, text=True)
    except OSError:
        return None
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def base_file_content(root, base, rel):
    """Content of `rel` at commit `base`; "" if the file did not exist there
    (or on a git error -- `base` is already validated by resolve_base, so a
    non-zero `git show` here means the path is absent at base, i.e. added since,
    whose spawn calls are legitimately new)."""
    try:
        r = subprocess.run(["git", "-C", root, "show", f"{base}:{rel}"],
                           capture_output=True, text=True)
    except OSError:
        return ""
    return r.stdout if r.returncode == 0 else ""


def scan_added(rel, full, base_text):
    """Report the NEW raw-spawn CALLS a grandfathered file gained vs `base`, by
    diffing the per-token CALL MULTISET between base and head -- NOT by
    added-line membership.

    CDX-02: an added-line filter keyed on the call's token-start line can be
    bypassed by adding ONLY a later `(` line, turning a dormant legacy `system`
    identifier into a live call whose match still lands on the unchanged
    identifier line.

    The identity is the (token, signature) pair, where signature is the call's
    whitespace-normalized raw text (see find_calls). A head call is NEW when its
    (token, signature) count exceeds base's. This catches a newly-formed call, a
    one-for-one same-token swap with different arguments (CDX-R4-01/K-01), and a
    frozen-site argument change (ADR-3002 Decision 1), while grandfathering exact
    pre-existing calls and pure deletions (migration to the runner). Line numbers
    are never used, so unrelated edits above a retained call don't false-positive."""
    try:
        with open(full, "r", encoding="utf-8", errors="replace") as f:
            head_text = f.read()
    except OSError:
        return []
    # FAIL CLOSED on either side (K-R8-01/CDX-R8-04): if BASE is desynchronised
    # its signature census is wrong, which would silently grandfather a new
    # call; if HEAD is, its tail was swallowed. Neither can be treated as clean.
    try:
        base_sigs = collections.Counter((tok, sig) for tok, _ln, sig in find_calls(base_text))
        head_calls = find_calls(head_text)
    except UnterminatedLiteral as e:
        return [(rel, e.line, "<unterminated-literal>")]
    seen = collections.Counter()
    findings = []
    for tok, lineno, sig in head_calls:
        key = (tok, sig)
        seen[key] += 1
        if seen[key] > base_sigs.get(key, 0):
            findings.append((rel, lineno, tok))
    return findings


def run_full_scan(root):
    # Non-grandfathered, non-runner files: any raw spawn is a new site (full scan).
    findings = scan(root, ALLOWLIST)
    # BR-011: grandfathered files are NOT skipped wholesale anymore -- a NEW raw
    # spawn a PR introduces beside a legacy one in one of these high-risk files
    # must still fail. Diff each grandfathered file's per-token call multiset
    # against the base ref (CDX-02).
    base = resolve_base(root, base_ref)
    if base is None:
        if base_ref:
            # K-08/CDX-R4-10: a base WAS requested (CI always sets one) but could
            # not be resolved -- a real misconfiguration (shallow fetch, unfetched
            # ref). Fail HARD (exit 2) rather than silently dropping the
            # grandfathered base-diff and still printing "clean"; a config error
            # must never read as a passing gate.
            print(
                f"::error::base ref '{base_ref}' could not be resolved (shallow fetch / unfetched "
                f"ref). Grandfathered base-diff enforcement would be SKIPPED. Fetch it (CI uses "
                f"fetch-depth: 0) or correct --base / LEXICAL_GATE_BASE.",
                file=sys.stderr)
            return 2
        # No base requested at all: warn, keep the whole-file-new-site check,
        # skip the grandfathered base-diff. NOTE (K-R5-05): the bash wrapper
        # always defaults BASE_REF=origin/dev, so this branch is reachable only
        # by invoking this Python directly with an empty base arg -- it is
        # defensive, never hit through the normal `check-plugin-spawn-lexical.sh`
        # entrypoint (which is why an unresolvable CI base hits the exit-2 path
        # above, not this warning).
        print(
            f"check-plugin-spawn-lexical: WARNING -- no base ref set; base-diff enforcement on the "
            f"{len(GRANDFATHERED)} grandfathered files is DISABLED for this run. Whole-file-new "
            f"spawn sites are still checked. Set --base / LEXICAL_GATE_BASE to a fetched ref "
            f"(the CI workflow fetches origin/dev) to enable it.",
            file=sys.stderr)
    else:
        for rel in sorted(GRANDFATHERED):
            base_text = base_file_content(root, base, rel)
            findings.extend(scan_added(rel, os.path.join(root, rel), base_text))
    if findings:
        for rel, lineno, tok in findings:
            print(
                f"::error file={rel},line={lineno}::raw spawn token `{tok}(` outside the "
                f"registered allowlist (Decision-10a, ADR-3002:459-488) -- route through "
                f"yuzu::agent::run_bounded_subprocess (agents/core/src/subprocess_runner.cpp), "
                f"or if this is a genuinely pre-existing site awaiting migration, add it to "
                f"GRANDFATHERED in scripts/ci/check-plugin-spawn-lexical.sh with a tracking issue."
            )
        print(f"\n{len(findings)} raw spawn token(s) found outside the allowlist.", file=sys.stderr)
        return 1
    print("check-plugin-spawn-lexical: clean (no raw spawn tokens outside the registered allowlist).")
    return 0


def run_selftest():
    tmp = tempfile.mkdtemp(prefix="yuzu_test_spawn_gate_")
    try:
        # Clean fixture: a plugin that routes through the runner; a comment
        # mentioning every banned token in prose must not trip the gate.
        clean_dir = os.path.join(tmp, "clean", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(clean_dir)
        with open(os.path.join(clean_dir, "fixture_plugin.cpp"), "w") as f:
            f.write(
                "#include <yuzu/agent/subprocess_runner.hpp>\n"
                "// This comment mentions fork() and popen() and system() and execve() in\n"
                "// prose only -- must NOT trip the gate once comments are stripped.\n"
                "void run() {\n"
                "    auto r = yuzu::agent::run_bounded_subprocess({\"/bin/echo\"}, {});\n"
                "    (void)r;\n"
                "}\n"
            )
        clean_findings = scan(os.path.join(tmp, "clean"), set())
        if clean_findings:
            print(f"SELFTEST FAILED: clean fixture unexpectedly flagged: {clean_findings}")
            return 1

        # Seeded fixture: a raw popen() call outside any allowlist must fail.
        seeded_dir = os.path.join(tmp, "seeded", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(seeded_dir)
        with open(os.path.join(seeded_dir, "fixture_plugin.cpp"), "w") as f:
            f.write(
                "#include <cstdio>\n"
                "void run() {\n"
                "    FILE* p = popen(\"echo hi\", \"r\");\n"
                "    (void)p;\n"
                "}\n"
            )
        seeded_findings = scan(os.path.join(tmp, "seeded"), set())
        if not seeded_findings:
            print("SELFTEST FAILED: seeded raw-spawn fixture was NOT flagged")
            return 1
        if not any(tok == "popen" for _rel, _lineno, tok in seeded_findings):
            print(f"SELFTEST FAILED: seeded fixture flagged for the wrong token: {seeded_findings}")
            return 1

        # Allowlisted fixture: a raw call inside a file ON the allowlist
        # (standing in for the runner's own implementation) must NOT be
        # flagged -- the sanctioned spawner never trips its own gate.
        allow_dir = os.path.join(tmp, "allow", "agents", "core", "src")
        os.makedirs(allow_dir)
        with open(os.path.join(allow_dir, "subprocess_runner.cpp"), "w") as f:
            f.write("void run() { system(\"echo hi\"); }\n")
        allow_findings = scan(os.path.join(tmp, "allow"), ALLOWLIST)
        if allow_findings:
            print(f"SELFTEST FAILED: the runner's own allowlisted file was flagged: {allow_findings}")
            return 1

        # False-positive guard: `execute(` (a real plugin method name) must
        # never match the exec family (the ADR's own "a bare exec* glob
        # would match every plugin's execute(" concern).
        exe_dir = os.path.join(tmp, "execute_guard", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(exe_dir)
        with open(os.path.join(exe_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("int execute(int argc, char** argv) { return 0; }\n")
        exe_findings = scan(os.path.join(tmp, "execute_guard"), set())
        if exe_findings:
            print(f"SELFTEST FAILED: execute( false-positived: {exe_findings}")
            return 1

        # `subsystem(` false-positive guard (the ADR's own example for the
        # bounded word `system`).
        sub_dir = os.path.join(tmp, "subsystem_guard", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(sub_dir)
        with open(os.path.join(sub_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("void subsystem(int x) { (void)x; }\n")
        sub_findings = scan(os.path.join(tmp, "subsystem_guard"), set())
        if sub_findings:
            print(f"SELFTEST FAILED: subsystem( false-positived: {sub_findings}")
            return 1

        # CDX-005: a raw spawn in an Objective-C++ (.mm) plugin source must be
        # flagged just like a .cpp one — .mm is C++ for this control boundary.
        mm_dir = os.path.join(tmp, "objcpp_guard", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(mm_dir)
        with open(os.path.join(mm_dir, "fixture_plugin.mm"), "w") as f:
            f.write("void run() { FILE* p = popen(\"echo hi\", \"r\"); (void)p; }\n")
        mm_findings = scan(os.path.join(tmp, "objcpp_guard"), set())
        if not any(tok == "popen" for _rel, _lineno, tok in mm_findings):
            print(f"SELFTEST FAILED: a raw popen in a .mm plugin source was NOT flagged: {mm_findings}")
            return 1

        # CDX-P2-001 multiline half: a call whose `(` is on the NEXT line must be
        # flagged — the per-line matcher missed it.
        ml_dir = os.path.join(tmp, "multiline_guard", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(ml_dir)
        with open(os.path.join(ml_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("void run() {\n    FILE* p = popen\n        (\"echo hi\", \"r\");\n    (void)p;\n}\n")
        ml_findings = scan(os.path.join(tmp, "multiline_guard"), set())
        if not any(tok == "popen" for _rel, _lineno, tok in ml_findings):
            print(f"SELFTEST FAILED: a multiline popen(newline)( was NOT flagged: {ml_findings}")
            return 1

        # CDX-P2-001 suffix half: the real suffixed Win32 entry points and
        # posix_spawnp must be flagged (K-03).
        suf_dir = os.path.join(tmp, "suffix_guard", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(suf_dir)
        with open(os.path.join(suf_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("void a() { CreateProcessAsUserW(0,0,0,0,0,0,0,0,0,0); }\n"
                    "void b() { ShellExecuteExW(0); }\n"
                    "void c() { posix_spawnp(0,0,0,0,0,0); }\n")
        suf_findings = {tok for _r, _l, tok in scan(os.path.join(tmp, "suffix_guard"), set())}
        for expected in ("CreateProcessAsUserW", "ShellExecuteExW", "posix_spawnp"):
            if expected not in suf_findings:
                print(f"SELFTEST FAILED: {expected}( was NOT flagged: {sorted(suf_findings)}")
                return 1

        # K-01/CDX-R2-006 line-continuation: `sys\`+newline+`tem(` splices into a
        # compiling system( call and MUST be flagged (translation phase 2). The
        # reported line must be the token-start line (where `sys` sits).
        lc_dir = os.path.join(tmp, "linecont_guard", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(lc_dir)
        with open(os.path.join(lc_dir, "fixture_plugin.cpp"), "w") as f:
            # line 1: void run() {   line 2: sys\  line 3: tem("id");  line 4: }
            f.write("void run() {\n    sys\\\ntem(\"id\");\n}\n")
        lc_findings = scan(os.path.join(tmp, "linecont_guard"), set())
        if not any(tok == "system" for _r, _l, tok in lc_findings):
            print(f"SELFTEST FAILED: continuation-split system( was NOT flagged: {lc_findings}")
            return 1

        # K-02/CDX-R2-002 raw-string blindness: a raw string with an embedded `"`
        # must NOT invert quote state and hide a following real spawn call.
        rs_dir = os.path.join(tmp, "rawstr_guard", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(rs_dir)
        with open(os.path.join(rs_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("#include <cstdlib>\n"
                    "const char* metadata = R\"(one embedded \" quote)\";\n"
                    "void launch() { system(\"raw spawn\"); }\n")
        rs_findings = scan(os.path.join(tmp, "rawstr_guard"), set())
        if not any(tok == "system" for _r, _l, tok in rs_findings):
            print(f"SELFTEST FAILED: system( after a raw string was NOT flagged: {rs_findings}")
            return 1

        # Raw-string false-positive guard: a banned token that lives INSIDE a raw
        # string (with a custom delimiter) is not code and must NOT be flagged.
        rsc_dir = os.path.join(tmp, "rawstr_clean", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(rsc_dir)
        with open(os.path.join(rsc_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("const char* doc = R\"delim(usage: run system(\"x\") or popen(\"y\"))delim\";\n")
        rsc_findings = scan(os.path.join(tmp, "rawstr_clean"), set())
        if rsc_findings:
            print(f"SELFTEST FAILED: tokens inside a raw string false-positived: {rsc_findings}")
            return 1

        # CDX-R8-03 raw-body splice, FALSE-POSITIVE half: a `)` + `\`+newline +
        # `"` sequence INSIDE a raw body is literal data (C++ exempts raw bodies
        # from phase 2). Locating the terminator in spliced text invented a
        # `)"` here and reported the literal's contents as a live call.
        rsfp_dir = os.path.join(tmp, "rawstr_splice_fp", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(rsfp_dir)
        with open(os.path.join(rsfp_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("const char* doc = R\"(payload)\\\n\" system(\"not a call\")\ntail)\";\n")
        rsfp_findings = scan(os.path.join(tmp, "rawstr_splice_fp"), set())
        if rsfp_findings:
            print(f"SELFTEST FAILED: raw-body `)`+splice+`\"` false-positived: {rsfp_findings}")
            return 1

        # CDX-R8-03/K-R8-03 raw-body splice, FALSE-NEGATIVE half -- the reason
        # the above is fail-OPEN, not merely noisy. The invented terminator ends
        # the literal early, so the real `)"` re-opens an ordinary string that
        # swallows the LIVE `system(` below it. This exact source compiles and
        # RUNS the call; the gate must flag it.
        rsfn_dir = os.path.join(tmp, "rawstr_splice_fn", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(rsfn_dir)
        with open(os.path.join(rsfn_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("#include <cstdlib>\n"
                    "const char* doc = R\"(payload)\\\n\" tail)\";\n"
                    "void live() { std::system(\"pwned\"); }\n")
        rsfn_findings = {tok for _r, _l, tok in scan(os.path.join(tmp, "rawstr_splice_fn"), set())}
        if "system" not in rsfn_findings:
            print("SELFTEST FAILED: a live system( hidden by a raw-body splice was NOT flagged")
            return 1

        # K-FN-01 function-pointer DECAY: the invoking `(` need not be adjacent
        # to the identifier. All three of these compile and call `system`; a
        # strict-adjacency call test saw the `)` and missed every one.
        decay_dir = os.path.join(tmp, "decay_guard", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(decay_dir)
        with open(os.path.join(decay_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("#include <cstdlib>\n"
                    "void a() { (system)(\"echo A\"); }\n"
                    "void b() { (*system)(\"echo B\"); }\n"
                    "void c() { (0, system)(\"echo C\"); }\n")
        decay_findings = scan(os.path.join(tmp, "decay_guard"), set())
        if len([1 for _r, _l, tok in decay_findings if tok == "system"]) != 3:
            print(f"SELFTEST FAILED: function-pointer-decay calls not all flagged: {decay_findings}")
            return 1

        # Decay guard's false-positive twin: a banned identifier in a
        # NON-call parenthesised position must still not be flagged.
        decay_fp = os.path.join(tmp, "decay_fp", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(decay_fp)
        with open(os.path.join(decay_fp, "fixture_plugin.cpp"), "w") as f:
            f.write("extern int system;\n"
                    "int probe() { if (system) { return 1; } return (system) + 1; }\n")
        decay_fp_findings = scan(os.path.join(tmp, "decay_fp"), set())
        if decay_fp_findings:
            print(f"SELFTEST FAILED: non-call parenthesised identifier flagged: {decay_fp_findings}")
            return 1

        # K-R8-01/CDX-R8-04: an unterminated ordinary string inside a DEAD
        # `#if 0` branch still COMPILES (the preprocessor never tokenizes it),
        # but desynchronises this lexer so the file tail — including the live
        # spawn call below — was swallowed into one literal and missed. The scan
        # must now FAIL CLOSED on the file rather than report it clean.
        unterm_dir = os.path.join(tmp, "unterminated", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(unterm_dir)
        with open(os.path.join(unterm_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("#include <cstdio>\n"
                    "#if 0\n"
                    "const char* dead = \"never terminated\n"
                    "#endif\n"
                    "void live() { ::popen(\"true\", \"r\"); }\n")
        unterm = {tok for _r, _l, tok in scan(os.path.join(tmp, "unterminated"), set())}
        if "<unterminated-literal>" not in unterm and "popen" not in unterm:
            print("SELFTEST FAILED: an unterminated literal hiding a live spawn call was NOT "
                  f"reported: {sorted(unterm)}")
            return 1

        # K-04/CDX-R2-008 wide/tchar/forkpty twins: the MSVCRT wide + tchar
        # spellings of system/popen/exec/spawn and forkpty are the same surface.
        wt_dir = os.path.join(tmp, "widetchar_guard", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(wt_dir)
        with open(os.path.join(wt_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("void a() { _wsystem(L\"id\"); }\n"
                    "void b() { _wpopen(L\"id\", L\"r\"); }\n"
                    "void c() { _tsystem(_T(\"id\")); }\n"
                    "void d() { _wspawnl(0, L\"x\", L\"x\", 0); }\n"
                    "void e() { _texecvp(0, 0); }\n"
                    "void g() { _execvpe(\"t\", 0, 0); }\n"   # K-02: plain-underscore MSVCRT exec
                    "void f() { forkpty(0, 0, 0, 0); }\n")
        wt_findings = {tok for _r, _l, tok in scan(os.path.join(tmp, "widetchar_guard"), set())}
        for expected in ("_wsystem", "_wpopen", "_tsystem", "_wspawnl", "_texecvp", "_execvpe", "forkpty"):
            if expected not in wt_findings:
                print(f"SELFTEST FAILED: {expected}( was NOT flagged: {sorted(wt_findings)}")
                return 1

        # CDX-01: a block-comment terminator split by a line-continuation
        # (`*\`+newline+`/`) closes the comment in real C++ (phase 2 splices the
        # pair BEFORE lexing), so a following system( is LIVE code and must be
        # flagged. The old single-pass stripper stayed in comment state and
        # masked it; the splice-first tokenizer closes the comment correctly.
        sc_dir = os.path.join(tmp, "splitcomment_guard", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(sc_dir)
        with open(os.path.join(sc_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("/* comment ending in a spliced terminator *\\\n/\nvoid run() { system(\"true\"); }\n")
        sc_findings = scan(os.path.join(tmp, "splitcomment_guard"), set())
        if not any(tok == "system" for _r, _l, tok in sc_findings):
            print(f"SELFTEST FAILED: system( after a spliced block-comment terminator was NOT flagged: {sc_findings}")
            return 1

        # K-R7-01/CDX-R7-01 (regression): an ordinary string literal whose
        # CONTENT is `R` (i.e. `"R"`) must NOT be mis-read as a raw-string opener
        # that suppresses phase-2 splicing for the file tail. A split spawn token
        # AFTER such a literal must still splice into `system(` and flag. (The
        # round-6 context-free raw-aware splice regressed exactly this: it saw the
        # `R"` byte pair inside the ordinary literal, treated it as an
        # unterminated raw opener, and copied the rest of the file verbatim so the
        # split `sys\`+nl+`tem` was never rejoined. The fix makes splicing
        # UNCONDITIONAL and recognizes raw strings only in the tokenizer's CODE
        # state, where `"R"` is an ordinary literal.)
        p1_dir = os.path.join(tmp, "strR_then_split", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(p1_dir)
        with open(os.path.join(p1_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("const char* marker = \"R\";\n"
                    "void run() { sys\\\ntem(\"x\"); }\n")
        p1_findings = scan(os.path.join(tmp, "strR_then_split"), set())
        if not any(tok == "system" for _r, _l, tok in p1_findings):
            print(f"SELFTEST FAILED: K-R7-01 -- split system( after an ordinary \"R\" literal was NOT flagged: {p1_findings}")
            return 1

        # K-R7-01 (regression, comment variant): a `R"` appearing INSIDE a
        # comment must likewise not disable splicing of a later split spawn token.
        p2_dir = os.path.join(tmp, "cmtR_then_split", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(p2_dir)
        with open(os.path.join(p2_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("// example: R\"(payload)\" appears here in prose\n"
                    "void run() { sys\\\ntem(\"x\"); }\n")
        p2_findings = scan(os.path.join(tmp, "cmtR_then_split"), set())
        if not any(tok == "system" for _r, _l, tok in p2_findings):
            print(f"SELFTEST FAILED: K-R7-01 -- split system( after a `R\"` inside a comment was NOT flagged: {p2_findings}")
            return 1

        # Grandfathered base-vs-head CALL-MULTISET diff (replaces the old
        # added-line filter). base KEEPS a legacy popen call (grandfathered) and
        # has a DORMANT `system` reference (no call). head keeps the legacy popen
        # unchanged (must NOT re-flag) and turns the dormant reference into a LIVE
        # call by adding only the `(` line -- CDX-02: must flag despite the
        # token-start line being unchanged. An in-comment popen must NOT flag.
        gf_dir = os.path.join(tmp, "gf_added", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(gf_dir)
        gf_full = os.path.join(gf_dir, "fixture_plugin.cpp")
        gf_rel = "agents/plugins/fixture_plugin/src/fixture_plugin.cpp"
        gf_base = ("void legacy() { popen(\"old\", \"r\"); }\n"       # legacy popen CALL (grandfathered)
                   "auto handle = system\n"                             # dormant: `system` with NO `(`
                   ";\n"
                   "/* a pre-existing comment mentioning popen(\"x\") */\n")
        gf_head = ("void legacy() { popen(\"old\", \"r\"); }\n"       # unchanged legacy popen call
                   "auto handle = system\n"                             # unchanged identifier line
                   "(\"activated\");\n"                                 # CDX-02: ONLY the `(` line added -> live call
                   "/* a pre-existing comment mentioning popen(\"x\") */\n")
        with open(gf_full, "w") as f:
            f.write(gf_head)
        gf_new = scan_added(gf_rel, gf_full, gf_base)
        gf_toks = {tok for _r, _ln, tok in gf_new}
        if "system" not in gf_toks:
            print(f"SELFTEST FAILED: CDX-02 -- a dormant `system` activated by an added `(` line was NOT flagged: {gf_new}")
            return 1
        if "popen" in gf_toks:
            print(f"SELFTEST FAILED: a grandfathered pre-existing popen call was re-flagged: {gf_new}")
            return 1

        # CDX-R4-01/K-01: an equal-COUNT one-for-one swap -- delete one legacy
        # system("fixed") call and add a NEW system(attacker) call elsewhere in
        # the same file -- must flag (call IDENTITY changed, not just count). A
        # pure deletion (migration) must NOT flag.
        sw_base = "void old() { system(\"fixed\"); }\n"
        sw_head_swap = "void neu() { system(\"attacker-influenced\"); }\n"   # deleted old, added new
        sw_head_del = "void old() { /* migrated to run_bounded_subprocess */ }\n"  # pure deletion
        sw_full = os.path.join(gf_dir, "swap.cpp")
        with open(sw_full, "w") as f:
            f.write(sw_head_swap)
        sw_new = scan_added(gf_rel, sw_full, sw_base)
        if not any(tok == "system" for _r, _l, tok in sw_new):
            print(f"SELFTEST FAILED: CDX-R4-01 -- an equal-count system() swap was NOT flagged: {sw_new}")
            return 1
        with open(sw_full, "w") as f:
            f.write(sw_head_del)
        sw_del = scan_added(gf_rel, sw_full, sw_base)
        if sw_del:
            print(f"SELFTEST FAILED: a pure deletion (migration) of a grandfathered call was flagged: {sw_del}")
            return 1

        # CDX-R5-01/K-R5-03: a change INSIDE a literal must be caught even when
        # it collapses under naive whitespace normalization. base has a
        # space-separated raw-string command; head inserts a NEWLINE (turning one
        # shell command into two) -- the token-stream signature preserves literal
        # bytes, so this differs from base and must flag.
        lit_base = 'void old() { system(R"(true /tmp/x)"); }\n'
        lit_head = 'void old() { system(R"(true\n/tmp/x)"); }\n'  # space -> newline INSIDE the raw string
        with open(sw_full, "w") as f:
            f.write(lit_head)
        lit_new = scan_added(gf_rel, sw_full, lit_base)
        if not any(tok == "system" for _r, _l, tok in lit_new):
            print(f"SELFTEST FAILED: CDX-R5-01 -- a command-separating newline inside a frozen raw string was NOT flagged: {lit_new}")
            return 1
        # A double-space -> single-space change inside a string literal likewise
        # alters the frozen argument and must flag.
        lit2_base = 'void old() { system("a  b"); }\n'
        lit2_head = 'void old() { system("a b"); }\n'
        with open(sw_full, "w") as f:
            f.write(lit2_head)
        if not scan_added(gf_rel, sw_full, lit2_base):
            print("SELFTEST FAILED: CDX-R5-01 -- a whitespace change inside a frozen string literal was NOT flagged")
            return 1

        # CDX-R6-01: a backslash-newline INSIDE a raw string is LITERAL data
        # (C++ exempts raw bodies from phase-2 splicing); the gate must NOT
        # splice it away, so `R"(ab)"` and `R"(a\<newline>b)"` differ and the
        # frozen-literal change is flagged.
        litr_base = 'void old() { system(R"(ab)"); }\n'
        litr_head = 'void old() { system(R"(a\\\nb)"); }\n'  # a, backslash, newline, b inside the raw body
        with open(sw_full, "w") as f:
            f.write(litr_head)
        if not scan_added(gf_rel, sw_full, litr_base):
            print("SELFTEST FAILED: CDX-R6-01 -- a backslash-newline inside a frozen raw string was NOT flagged")
            return 1

        # K-R5-02: a PURE CODE REFLOW of a frozen call (only inter-token
        # whitespace changes, literal bytes identical) must NOT false-positive.
        rf_base = 'void old() { system("fixed"); }\n'
        rf_head = 'void old() {\n    system(\n        "fixed"\n    );\n}\n'
        with open(sw_full, "w") as f:
            f.write(rf_head)
        rf_new = scan_added(gf_rel, sw_full, rf_base)
        if rf_new:
            print(f"SELFTEST FAILED: K-R5-02 -- a pure reflow of a frozen call false-positived: {rf_new}")
            return 1

        print("check-plugin-spawn-lexical --selftest: all fixtures behaved as expected.")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if selftest_flag:
    sys.exit(run_selftest())
else:
    sys.exit(run_full_scan(repo_root))
PYEOF
