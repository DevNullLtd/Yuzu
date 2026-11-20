#!/usr/bin/env python3
"""Lexical tripwire: the vuln_scan plugin must never execute Homebrew's brew.

The macOS agent runs as root and a Homebrew prefix is owned by the installing (non-root) user,
so running `brew` executes a user-controlled script as root (installed_apps has the same
defect, tracked in #8184). The macOS enumeration is `#elif defined(__APPLE__)`, so a behavioural test cannot
run on Linux; pin the source text instead (best-effort lexical backstop, not a proof).

Method: backslash-newline splices are removed first; a small C++ tokenizer strips comments WITHOUT
being fooled by `//` or `/*` inside string literals (`"https://x"; run("brew list")`), treats the
L/u8/u/U prefixes as part of a literal, decodes simple, \\x, octal, \\u and \\U escapes, and joins
adjacent string literals (`"br" "ew"`, `"br" L"ew"`) before the search. The search also runs over a
view with shell-quoting characters removed (`b''rew`). Every C/C++/Objective-C++ source under
agents/plugins/vuln_scan/src/ is scanned recursively.

Three structural pins (the "commands are absolute / coverage is wired" claims have no off-Mac
behavioural test, so they are pinned lexically):
  (a) no string literal in the plugin sources starts with a bare macOS tool name (spctl, fdesetup,
      csrutil, socketfilterfw, systemsetup, system_profiler, defaults);
  (b) every kMacos*Cmd constant defined in macos_software.hpp is USED in another source file;
  (d) the CVE-input guard is wired (the pure decisions live in macos_software.hpp and are
      unit-tested; this pins the plugin CALLS them: update_cve_inputs, skip_unusable_for_compare,
      want_clean_placeholder, the unrecognised-line plumbing, a by-reference coverage argument);
  (c) in vuln_scan_plugin.cpp each of the five action branches calls declare_coverage(ctx, cov)
      exactly once (five calls in all), every do_*_impl / get_installed_apps call is passed &cov,
      scan/cve_scan/config_scan call emit_coverage_row, summary calls emit_coverage_summary_row,
      and inventory calls neither row emitter (its rows feed NVD matching).

Two more groups cover the Apple-only glue in vuln_scan_plugin.cpp, which no off-Mac build
compiles:
  (e) the lines that copy the parser's results into the coverage state and decide the status are
      pinned verbatim (`cov->macos_software = true`, `cov->sp_readable = parsed.readable`, the
      parser called with the run's `ok`, the runner's `ok` including the exit code, the config
      scan given `macos_run`, `config_unreadable` set under `any_config_unreadable`, the status
      declared only for a non-empty token and from `coverage_token(cov)`, both
      `fold_backslashes` calls);
  (f) no `popen`, `system`, `exec*`, `posix_spawn` or `fork` call appears on any line a macOS build
      compiles (a conditional block whose directive names `__APPLE__`, or one that does not
      exclude it; a `#else` after an `__APPLE__` branch is outside it).

Not caught (disclosed): a name built at run time, split across preprocessor macros, or reached by
indirection. Self-test: test_vuln_scan_no_brew_lexical_selftest.py.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "agents/plugins/vuln_scan/src"
SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".m", ".mm"}

# `brew` as a whole word (also matches /bin/brew and /opt/homebrew/bin/brew; does NOT match the
# status token `homebrew_not_scanned` or prose "Homebrew") or a Homebrew prefix path.
BREW = re.compile(r"\bbrew\b|/(?:opt|usr/local)/homebrew", re.I)

_SIMPLE_ESC = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'", "0": "\0"}


def _decode_escape(src: str, i: int):
    """src[i] is the char after a backslash. Returns (decoded, next_index)."""
    c = src[i]
    if c in "uU":
        n = 4 if c == "u" else 8
        m = re.match(r"[0-9a-fA-F]{%d}" % n, src[i + 1:])
        if m:
            try:
                return chr(int(m.group(0), 16)), i + 1 + n
            except (ValueError, OverflowError):
                return "\ufffd", i + 1 + n
    if c == "x":
        m = re.match(r"[0-9a-fA-F]+", src[i + 1:])
        if m:
            return chr(int(m.group(0)[-2:], 16) & 0xFF), i + 1 + len(m.group(0))
    if c in "01234567":
        m = re.match(r"[0-7]{1,3}", src[i:])
        return chr(int(m.group(0), 8) & 0xFF), i + len(m.group(0))
    return _SIMPLE_ESC.get(c, c), i + 1


_LIT_START = re.compile(r'(?:u8|u|U|L)?(R)?"')
_RAW_OPEN = re.compile(r'([^()\\\s]{0,16})\(')
_IDENT = re.compile(r"[A-Za-z0-9_]")


def _splice(src: str) -> str:
    """Translation phase 2: remove backslash-newline (also CRLF) before anything is lexed."""
    return re.sub(r"\\[ \t\f\v]*\r?\n", "", src)


def lex_all(src: str):
    """Return (code, literals): the code with comments removed and adjacent string literals
    joined (each joined run emitted as one `"..."` token), and the list of joined literal values.

    String contents are kept in the code (a brew call lives in a string).
    """
    src = _splice(src)
    out: list[str] = []
    lits: list[str] = []
    last_is_str = False  # only whitespace/comments since the previous string literal
    last_idx = -1
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j  # newline itself handled as whitespace
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c.isspace():
            out.append(c)
            i += 1
            continue
        m = _LIT_START.match(src, i) if (i == 0 or not _IDENT.match(src[i - 1])) else None
        if m:
            i = m.end()
            if m.group(1):  # raw string: R"delim( ... )delim"
                ro = _RAW_OPEN.match(src, i)
                if ro:
                    end = src.find(")" + ro.group(1) + '"', ro.end())
                    content = src[ro.end():] if end < 0 else src[ro.end():end]
                    i = n if end < 0 else end + len(ro.group(1)) + 2
                else:
                    content = ""
            else:
                buf = []
                while i < n and src[i] != '"' and src[i] != "\n":
                    if src[i] == "\\" and i + 1 < n:
                        d, i = _decode_escape(src, i + 1)
                        buf.append(d)
                    else:
                        buf.append(src[i])
                        i += 1
                i += 1  # closing quote
                content = "".join(buf)
            if last_is_str:
                out[last_idx] = out[last_idx][:-1] + content + '"'
                lits[-1] += content
            else:
                out.append('"' + content + '"')
                lits.append(content)
                last_idx = len(out) - 1
            last_is_str = True
            continue
        prefixed_char = re.search(r"(?:^|[^A-Za-z0-9_])(?:u8|u|U|L)$", src[max(0, i - 3):i]) is not None
        if c == "'" and (prefixed_char or not (i > 0 and _IDENT.match(src[i - 1]))):
            # character literal (a digit separator 1'000 is excluded by the check above)
            i += 1
            while i < n and src[i] != "'" and src[i] != "\n":
                i += 2 if src[i] == "\\" else 1
            i += 1
            out.append("' '")
            last_is_str = False
            continue
        out.append(c)
        last_is_str = False
        i += 1
    return "".join(out), lits


def lex(src: str) -> str:
    return lex_all(src)[0]


def scan_source(text: str) -> list[str]:
    code = lex(text)
    # second view: shell quoting removed, so b''rew / b""rew / b\rew read as brew
    dequoted = re.sub(r"""['"\\]""", "", code)
    return sorted({m.group(0) for v in (code, dequoted) for m in BREW.finditer(v)})


# A literal that STARTS a command with a bare tool name, optionally behind `env`, `/usr/bin/env` or
# VAR=value assignments (`PATH=/x spctl`).
BARE_TOOL = re.compile(
    r"\s*(?:(?:/usr/bin/env|env)\s+|[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
    r"(?:spctl|fdesetup|csrutil|socketfilterfw|systemsetup|system_profiler|defaults)\b")
ACTIONS = ("scan", "cve_scan", "config_scan", "inventory", "summary")


def source_files(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SUFFIXES)


def action_blocks(code: str) -> dict:
    """Map each `if (action == "x")` branch of execute() to its text (to the next branch)."""
    marks = [(m.start(), m.group(1)) for m in re.finditer(r'if\s*\(\s*action\s*==\s*"(\w+)"\s*\)', code)]
    end_all = code.find('unknown action')
    blocks = {}
    for k, (pos, name) in enumerate(marks):
        stop = marks[k + 1][0] if k + 1 < len(marks) else (end_all if end_all > pos else len(code))
        blocks[name] = code[pos:stop]
    return blocks


def pin_errors(root: pathlib.Path) -> list[str]:
    errs = []
    files = source_files(root)
    lexed = {f.relative_to(root).as_posix(): lex_all(f.read_text(errors="replace")) for f in files}
    # (a) no bare macOS tool literal
    for name, (_code, lits) in lexed.items():
        for lit in lits:
            if BARE_TOOL.match(lit):
                errs.append(f"{name}: string literal starts with a bare tool name {lit[:40]!r} "
                            "(macOS commands must be absolute paths, defined in macos_software.hpp)")
    # (b) every kMacos*Cmd constant is used outside macos_software.hpp
    hdr = lexed.get("macos_software.hpp")
    if hdr is None:
        errs.append("macos_software.hpp is missing")
    else:
        consts = sorted(set(re.findall(r"\b(kMacos\w*Cmd)\b", hdr[0])))
        if not consts:
            errs.append("macos_software.hpp defines no kMacos*Cmd constants")
        others = "\n".join(c for n, (c, _l) in lexed.items() if n != "macos_software.hpp")
        for c in consts:
            if not re.search(r"\b%s\b" % c, others):
                errs.append(f"{c} is defined in macos_software.hpp but used by no other source")
    # (c) coverage wiring in vuln_scan_plugin.cpp
    plug = lexed.get("vuln_scan_plugin.cpp")
    if plug is None:
        errs.append("vuln_scan_plugin.cpp is missing")
    else:
        blocks = action_blocks(plug[0])
        for a in ACTIONS:
            b = blocks.get(a)
            if b is None:
                errs.append(f"vuln_scan_plugin.cpp: no `action == \"{a}\"` branch found")
                continue
            if len(re.findall(r"\bdeclare_coverage\s*\(\s*ctx\b", b)) != 1:
                errs.append(f"{a}: must call declare_coverage(ctx, ...) exactly once")
            row = len(re.findall(r"\bemit_coverage_row\s*\(", b))
            srow = len(re.findall(r"\bemit_coverage_summary_row\s*\(", b))
            want_row, want_srow = (1, 0) if a in ("scan", "cve_scan", "config_scan") else (0, 1) if a == "summary" else (0, 0)
            if (row, srow) != (want_row, want_srow):
                errs.append(f"{a}: coverage row emitters are ({row}, {srow}), expected ({want_row}, {want_srow})"
                            + (" (inventory rows feed NVD matching; no in-band rows)" if a == "inventory" else ""))
        # every do_*_impl / get_installed_apps call must receive the run's state (&cov), and
        # declare_coverage must be handed that same `cov`, never a fresh CoverageState{}
        for a, b in blocks.items():
            for m in re.finditer(r"\b(do_cve_scan_impl|do_config_scan_impl|get_installed_apps)\s*\(([^)]*)\)", b):
                want = "cov" if m.group(1) == "do_cve_scan_impl" else "&cov"
                if m.group(2).strip() != want:
                    errs.append(f"{a}: {m.group(1)}({m.group(2).strip()}) must be passed {want}")
            for m in re.finditer(r"\bdeclare_coverage\s*\(([^)]*)\)", b):
                if re.sub(r"\s+", "", m.group(1)) != "ctx,cov":
                    errs.append(f"{a}: declare_coverage({m.group(1).strip()}) must be (ctx, cov)")
        # the CVE-input guard: unusable-version apps are counted from the apps list, unusable
        # versions are never string-compared on macOS, and the clean placeholder is suppressed
        for needle, why in (
            (r"yuzu::vuln::update_cve_inputs\(\s*cov\s*,\s*apps\s*,\s*yuzu::vuln::kCveRules\s*\)", "the unusable CVE-input count is not set"),
            (r"yuzu::vuln::skip_unusable_for_compare\(\s*cov\.macos_software\s*,\s*app\.version\s*\)", "an unusable version is not skipped on macOS"),
            (r"if\s*\(\s*yuzu::vuln::want_clean_placeholder\(\s*cov\s*\)\s*\)", "the clean placeholder is not gated by want_clean_placeholder(cov)"),
            (r"cov->software_unrecognised\s*=\s*parsed\.readable\s*\?\s*parsed\.suspect_lines\s*:\s*0", "the unrecognised-line count is not plumbed from the parser"),
            (r"std::vector<Finding>\s+do_cve_scan_impl\(\s*yuzu::vuln::CoverageState&\s+cov\s*\)", "do_cve_scan_impl must take the coverage by reference (no silent default)"),
        ):
            if not re.search(needle, plug[0]):
                errs.append(f"vuln_scan_plugin.cpp: {why}")
        for needle, why in APPLE_GLUE:
            if not re.search(needle, plug[0]):
                errs.append(f"vuln_scan_plugin.cpp: {why}")
        if len(re.findall(r"\bdeclare_coverage\s*\(\s*ctx\b", plug[0])) != len(ACTIONS):
            errs.append(f"declare_coverage(ctx, ...) must appear exactly {len(ACTIONS)} times in vuln_scan_plugin.cpp")
    # (f) no process-spawning call on a line a macOS build compiles
    for name, (code, _lits) in lexed.items():
        lines, struct_errs = apple_compiled_lines(code)
        errs.extend(f"{name}: preprocessor structure: {e}" for e in struct_errs)
        for ln in lines:
            m = SPAWN_CALL.search(re.sub(r'"[^"\n]*"', '""', ln))  # string contents are not calls
            if m:
                errs.append(f"{name}: `{m.group(0)}` on a line a macOS build compiles "
                            "(macOS reads go through the bounded argv runner)")
    return errs


# Calls that start a shell or a child process. A match is `name(` as a whole word.
SPAWN_CALL = re.compile(r"\b(?:popen|system|fork|vfork|forkpty|wordexp|execl|execlp|execle|execv|execvp|execve"
                        r"|execvpe|fexecve|execveat|posix_spawn|posix_spawnp)\s*\(")
_DIRECTIVE = re.compile(r"^[ \t]*(?:#|%:)[ \t]*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")
_NON_APPLE_TEST = re.compile(r"^\s*(?:defined\s*\(\s*(?:__linux__|_WIN32)\s*\)|defined\s+(?:__linux__|_WIN32))\s*$")
_APPLE_TEST = re.compile(r"^\s*(?:defined\s*\(\s*__APPLE__\s*\)|defined\s+__APPLE__)\s*$")


def _is_non_apple_test(kind: str, cond: str) -> bool:
    """True only for an EXACT `__linux__` / `_WIN32` test (an `&&` chain with one such conjunct
    also excludes macOS). Anything else (`||`, `!`, an unknown macro, `1`) may compile there."""
    if kind == "ifdef":
        return cond.strip() in ("__linux__", "_WIN32")
    if kind not in ("if", "elif") or "||" in cond:
        return False
    return any(_NON_APPLE_TEST.match(part) for part in cond.split("&&"))


def _is_apple_test(kind: str, cond: str) -> bool:
    """True only for an EXACT `__APPLE__` test: the sole shape whose `#else` is off for macOS."""
    if kind == "ifdef":
        return cond.strip() == "__APPLE__"
    return kind in ("if", "elif") and bool(_APPLE_TEST.match(cond))


def apple_compiled_lines(code: str):
    """(lines, errors): the lines of (lexed) source that a macOS build compiles, and structural
    errors (an `#endif`/`#else`/`#elif` with no `#if`, an `#if` never closed). A stack of
    conditional frames tracks whether every enclosing branch can compile there; `#else` after an
    exact `__APPLE__` test is off, `#else` after anything else is on."""
    out: list[str] = []
    errors: list[str] = []
    stack: list[list] = []  # [branch_on, exact_apple_branch_seen_in_chain]
    for line in code.split("\n"):
        m = _DIRECTIVE.match(line)
        if m:
            kind, cond = m.group(1), m.group(2)
            apple = _is_apple_test(kind, cond)
            on = not _is_non_apple_test(kind, cond)
            if kind in ("if", "ifdef", "ifndef"):
                stack.append([on if kind != "ifndef" else True, apple])
            elif not stack:
                errors.append(f"`#{kind}` with no open `#if`")
            elif kind == "elif":
                stack[-1][0] = on and not stack[-1][1]
                stack[-1][1] = stack[-1][1] or apple
            elif kind == "else":
                stack[-1][0] = not stack[-1][1]
            else:  # endif
                stack.pop()
            continue
        if all(f[0] for f in stack):
            out.append(line)
    if stack:
        errors.append("an `#if` is never closed")
    return out, errors


# Lines the Apple glue must keep, pinned verbatim (whitespace-insensitive): (pattern, what breaks).
APPLE_GLUE = (
    (r"cov->macos_software\s*=\s*true\s*;", "the software leg is not marked as macOS"),
    (r"cov->sp_readable\s*=\s*parsed\.readable\s*;", "sp_readable is not taken from the parser"),
    (r"parse_system_profiler_apps\(\s*r\.out\s*,\s*r\.ok\s*\)", "the parser is not given the run's ok"),
    (r"out\.ok\s*=\s*out\.ran\s*&&\s*r\.exit_code\s*==\s*0\s*;", "the runner's ok ignores the exit code"),
    (r"run_all_config_checks\(\s*macos_run\s*\)", "the config scan is not given the bounded macOS runner"),
    (r"if\s*\(\s*cov\s*&&\s*yuzu::vuln::any_config_unreadable\(\s*checks\s*\)\s*\)\s*"
     r"cov->config_unreadable\s*=\s*true\s*;", "config_unreadable is not raised from the checks"),
    (r"const\s+auto\s+token\s*=\s*yuzu::vuln::coverage_token\(\s*cov\s*\)\s*;",
     "the status token is not derived from the coverage state"),
    (r"if\s*\(\s*!\s*token\.empty\(\)\s*\)\s*ctx\.set_result_status\(\s*YUZU_RESULT_STATUS_CONSTRAINED\s*,"
     r"\s*YUZU_RESULT_COMPLETENESS_PARTIAL\s*,\s*token\s*\)",
     "the status is not declared exactly when the token is non-empty"),
    (r"fold_backslashes\(\s*a\.name\s*\)", "a backslash in an application name is not folded"),
    (r"fold_backslashes\(\s*a\.version\s*\)", "a backslash in an application version is not folded"),
)


def scan_tree(root: pathlib.Path) -> list[str]:
    errs = []
    files = source_files(root)
    if not files:
        errs.append(f"no vuln_scan sources found under {root}")
    for f in files:
        hits = scan_source(f.read_text(errors="replace"))
        if hits:
            errs.append(f"{f.relative_to(root)}: executes or names brew {hits} "
                        "(root agent must not run a user-owned script)")
    if files:
        errs.extend(pin_errors(root))
    return errs


def main() -> int:
    errs = scan_tree(PLUGIN)
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
