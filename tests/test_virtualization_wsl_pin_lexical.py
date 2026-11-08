#!/usr/bin/env python3
"""Static lexical gate over the virtualization `wsl` Windows shell (virtualization_win.cpp).

The Windows body cannot run in the unit suites (it walks the machine's real profile list and may
mount logged-off hives), and every decision it relies on is unit-tested through fakes in
test_virtualization_wsl_parsers.cpp, so the few wiring facts the fakes cannot see are pinned here,
on source text readable from every host. Invariants:

  1. The offline arm is entered in exactly one place: ONE `with_user_hive(` call, with exactly four
     arguments, the last being `&report`. That is the shared ladder's DEFAULT-ON hive-file guard:
     no `check` argument, so neither `OfflineHiveFileCheck` nor `kOfflineHiveFileUnguarded` is
     ever named.
  2. HKEY_USERS is never enumerated (`enumerate_hku_subkeys` does not appear): the loaded-versus-
     offline choice belongs to with_user_hive alone.
  3. Every `RegOpenKeyExW(` passes `REG_OPTION_OPEN_LINK` as its third argument (the Lxss subtree
     sits in a hive its owning user can write; a planted registry link must read as no WSL, never
     as a read of another key). The flag is pinned on the call, not on the file: the explanatory
     comment above it names the flag too, and a comment must not satisfy the pin.
  4. `mount_name` (it embeds the SID) appears only inside `spdlog::error(` calls, so it can reach
     the agent log and never a row; and it does still reach the log.

Robustness: `//` and `/* */` comments are blanked (string and character literals are kept intact)
and whitespace is collapsed before matching, so a commented-out call cannot satisfy a check. The
checks read call ARGUMENT LISTS (balanced, split at top-level commas), not substrings of the file.
Limits: a template argument list containing a comma would split early (none appears in the pinned
calls), and the gate cannot see a relocation that keeps the tokens but changes control flow
(review-enforced). The self-test applies in-memory mutations and requires problems() to be
non-empty on each; a mutation whose pattern no longer matches the source fails loudly (stale
pattern) rather than passing vacuously.

Usage: python3 tests/test_virtualization_wsl_pin_lexical.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WIN = ROOT / "agents" / "plugins" / "virtualization" / "src" / "virtualization_win.cpp"
HINT = (" (this gate pins the virtualization `wsl` Windows wiring; if virtualization_win.cpp was"
        " legitimately restructured, update tests/test_virtualization_wsl_pin_lexical.py)")

_STRING = r'"(?:\\.|[^"\\])*"'
_CHAR = r"'(?:\\.|[^'\\])'"
_BLANK = re.compile(f"{_STRING}|{_CHAR}|//[^\\n]*|/\\*.*?\\*/", re.S)
_TOKEN = re.compile(f"{_STRING}|{_CHAR}|[()\\[\\]{{}},]")


def normalise(src):
    """Blank // and /* */ comments (literals kept), then collapse whitespace."""
    kept = _BLANK.sub(lambda m: m.group(0) if m.group(0)[0] in "\"'" else " ", src)
    return re.sub(r"\s+", " ", kept)


def call_span(text, open_idx):
    """For the '(' at open_idx: (top-level argument texts, index just past the ')'), else (None, -1)."""
    depth, start, args = 0, open_idx + 1, []
    for m in _TOKEN.finditer(text, open_idx):
        t = m.group(0)
        if len(t) != 1:
            continue  # a string or character literal
        if t in "([{":
            depth += 1
        elif t in ")]}":
            depth -= 1
            if depth == 0:
                args.append(text[start:m.start()].strip())
                return args, m.end()
        elif t == "," and depth == 1:
            args.append(text[start:m.start()].strip())
            start = m.end()
    return None, -1


def call_opens(text, name):
    """Index of the '(' of every `name(` call."""
    return [m.end() - 1 for m in re.finditer(r"(?<![\w])" + re.escape(name) + r"\s*\(", text)]


def without_calls(text, name):
    """text with every balanced `name(...)` call removed."""
    out, pos = [], 0
    for open_idx in call_opens(text, name):
        if open_idx < pos:
            continue
        _, end = call_span(text, open_idx)
        if end < 0:
            continue
        out.append(text[pos:open_idx])
        pos = end
    out.append(text[pos:])
    return "".join(out)


def problems(win_src):
    out = []
    t = normalise(win_src)

    hive_calls = call_opens(t, "with_user_hive")
    if len(hive_calls) != 1:
        out.append(f"expected exactly one with_user_hive( call, found {len(hive_calls)}")
    else:
        args, _ = call_span(t, hive_calls[0])
        if args is None or len(args) != 4 or args[-1] != "&report":
            out.append("with_user_hive must take exactly four arguments, the last `&report` "
                       "(the default-on hive-file guard: no check argument)")
    for tok in ("OfflineHiveFileCheck", "kOfflineHiveFileUnguarded"):
        if tok in t:
            out.append(f"{tok} is named: the offline arm must use the default-on guard only")
    if "enumerate_hku_subkeys" in t:
        out.append("enumerate_hku_subkeys appears: HKEY_USERS must not be enumerated")

    opens = call_opens(t, "RegOpenKeyExW")
    if not opens:
        out.append("no RegOpenKeyExW( call: the Lxss walk's open is missing")
    for open_idx in opens:
        args, _ = call_span(t, open_idx)
        if args is None or len(args) != 5 or args[2] != "REG_OPTION_OPEN_LINK":
            out.append("every RegOpenKeyExW( call must pass REG_OPTION_OPEN_LINK as its third "
                       "argument")

    if "mount_name" not in t:
        out.append("mount_name no longer reaches the log (an unload_failed mount must stay "
                   "actionable from the agent log)")
    if "mount_name" in without_calls(t, "spdlog::error"):
        out.append("mount_name appears outside an spdlog::error( call (it embeds the SID: the "
                   "agent log only)")
    return out


def mutate(src, old, new):
    assert src.count(old) == 1, f"stale mutation pattern: {old!r}"
    return src.replace(old, new, 1)


class VirtualizationWslPinLexical(unittest.TestCase):
    def setUp(self):
        self.win = WIN.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        self.assertEqual(problems(self.win), [], HINT)

    def test_normalise_blanks_comments_and_keeps_literals(self):
        self.assertNotIn("with_user_hive", normalise("a /* with_user_hive( */ b"))
        self.assertNotIn("with_user_hive", normalise("a // with_user_hive(\nb"))
        self.assertIn('"// kept"', normalise('x = "// kept"; // dropped'))
        self.assertIn("'\"'", normalise("c = '\"'; // dropped"))

    def test_mutations_are_caught(self):
        w = self.win
        flag_off = mutate(w, "name, REG_OPTION_OPEN_LINK, KEY_READ", "name, 0, KEY_READ")
        # The explanatory comment still names the flag: only the call-site check can catch this.
        self.assertIn("REG_OPTION_OPEN_LINK", flag_off)
        cases = {
            "open-link flag replaced by 0, comment kept": flag_off,
            "RegOpenKeyExW call commented out": mutate(
                w, "RegOpenKeyExW(static_cast<HKEY>(parent), name",
                "// RegOpenKeyExW(static_cast<HKEY>(parent), name"),
            "a fifth check argument": mutate(
                w, "[&](HKEY root) { fn(root); }, &report);",
                "[&](HKEY root) { fn(root); }, &report, check);"),
            "the unguarded opt-out named": mutate(
                w, "[&](HKEY root) { fn(root); }, &report);",
                "[&](HKEY root) { fn(root); }, &report, kOfflineHiveFileUnguarded);"),
            "report argument dropped": mutate(
                w, "[&](HKEY root) { fn(root); }, &report);", "[&](HKEY root) { fn(root); });"),
            "with_user_hive call commented out": mutate(
                w, "out.status = yuzu::win::with_user_hive(",
                "// out.status = yuzu::win::with_user_hive("),
            "with_user_hive called a second time": mutate(
                w, "out.refusal = std::move(report.refusal);",
                "out.refusal = std::move(report.refusal); yuzu::win::with_user_hive("
                "profile.sid, profile.profile_path, [&](HKEY r) { fn(r); }, &report);"),
            "HKEY_USERS enumerated": mutate(
                w, "const auto profiles = yuzu::profiles::build_profile_list(",
                "const auto hku = yuzu::win::enumerate_hku_subkeys();\n"
                "    const auto profiles = yuzu::profiles::build_profile_list("),
            "mount_name copied into the result": mutate(
                w, "out.unload_failed = report.unload_failed;",
                "out.unload_failed = report.unload_failed; out.refusal = report.mount_name;"),
            "mount_name logged below error level": mutate(
                w, 'spdlog::error("virtualization wsl: hive unload failed',
                'spdlog::warn("virtualization wsl: hive unload failed'),
        }
        for name, mutated in cases.items():
            with self.subTest(mutation=name):
                self.assertNotEqual(problems(mutated), [], f"mutation not caught: {name}")


if __name__ == "__main__":
    unittest.main()
