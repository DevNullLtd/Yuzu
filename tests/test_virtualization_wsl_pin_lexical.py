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
     The call is found in its template-argument form too (`with_user_hive<T>(`).
  2. HKEY_USERS is never named in code (the plugin has no reason to: the loaded-versus-offline
     choice belongs to with_user_hive alone) and `enumerate_hku_subkeys` does not appear.
  3. Every `RegOpenKeyExW(` passes `REG_OPTION_OPEN_LINK` as its third argument (the Lxss subtree
     sits in a hive its owning user can write; a planted registry link must open as the link
     object, which the walk then detects, never as a read of another key). The flag is pinned on
     the call, not on the file: the explanatory comment above it names the flag too, and a
     comment must not satisfy the pin. No other `RegOpenKey*` API is called (none of them takes
     the flag through the same argument).
  4. `mount_name` (it embeds the SID) appears only inside `spdlog::error(` calls, so it can reach
     the agent log and never a row; and it does still reach the log.
  5. The ProfileList end classification is called as `profile_list_token(list.root_rc,
     list.last_rc, list.probe_rc)`: three longs of one type, so a swap compiles and misreads
     every enumeration outcome.
  6. The `record_failures` loop keeps both its system-SID filter (a system account's record
     failure concerns a profile this action never walks) and the `profile_unreadable` token.
  7. The `catch (...)` arm logs the unload failure (`log_unload_failed()`) BEFORE it rethrows,
     so the ABI catch never loses the one place the mount name is recorded.

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
    """Index of the '(' of every `name(` or `name<template args>(` call."""
    pattern = r"(?<![\w])" + re.escape(name) + r"\s*(?:<[^;(){}]*?>)?\s*\("
    return [m.end() - 1 for m in re.finditer(pattern, text)]


def block_body(text, open_idx):
    """Body of the balanced {...} whose '{' is at open_idx, else None."""
    depth = 0
    for m in _TOKEN.finditer(text, open_idx):
        t = m.group(0)
        if len(t) != 1:
            continue  # a string or character literal
        if t in "([{":
            depth += 1
        elif t in ")]}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:m.start()]
    return None


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
    if "HKEY_USERS" in t:
        out.append("HKEY_USERS is named in code: the shell never touches it (with_user_hive tries "
                   "the loaded hive itself)")

    for m in re.finditer(r"(?<![\w])(RegOpenKey\w*)\s*\(", t):
        if m.group(1) != "RegOpenKeyExW":
            out.append(f"{m.group(1)}( is called: only RegOpenKeyExW( with REG_OPTION_OPEN_LINK "
                       "may open a key")

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

    list_calls = call_opens(t, "profile_list_token")
    list_args = [call_span(t, i)[0] for i in list_calls]
    if len(list_calls) != 1 or list_args[0] != ["list.root_rc", "list.last_rc", "list.probe_rc"]:
        out.append("profile_list_token must be called exactly once as (list.root_rc, "
                   "list.last_rc, list.probe_rc)")

    loops = list(re.finditer(r"for\s*\([^)]*:\s*list\.record_failures\s*\)\s*\{", t))
    body = block_body(t, loops[0].end() - 1) if len(loops) == 1 else None
    if body is None:
        out.append("expected exactly one `for (... : list.record_failures) {` loop")
    elif "is_system_sid" not in body or '"profile_unreadable"' not in body:
        out.append("the record_failures loop must keep both its is_system_sid filter and the "
                   "\"profile_unreadable\" token")

    catches = list(re.finditer(r"catch\s*\(\s*\.\.\.\s*\)\s*\{", t))
    arm = block_body(t, catches[0].end() - 1) if len(catches) == 1 else None
    if arm is None:
        out.append("expected exactly one catch (...) arm in the Windows shell")
    else:
        logged, rethrown = arm.find("log_unload_failed()"), arm.find("throw;")
        if logged < 0 or rethrown < 0 or logged > rethrown:
            out.append("the catch (...) arm must call log_unload_failed() before `throw;` (the "
                       "ABI catch carries no mount name)")
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
        call = "[&](HKEY root) { fn(root); }, &report);"
        # name -> (mutated source, a fragment of the problem the mutation must reach ALONE-ish:
        # asserting the fragment proves the intended branch fired, not just that something did).
        cases = {
            "open-link flag replaced by 0, comment kept": (flag_off, "REG_OPTION_OPEN_LINK as its"),
            "RegOpenKeyExW call commented out": (mutate(
                w, "RegOpenKeyExW(static_cast<HKEY>(parent), name",
                "// RegOpenKeyExW(static_cast<HKEY>(parent), name"), "no RegOpenKeyExW("),
            "another RegOpenKey API called": (mutate(
                w, "out.refusal = std::move(report.refusal);",
                "out.refusal = std::move(report.refusal); RegOpenKeyExA(nullptr, nullptr, 0, "
                "KEY_READ, nullptr);"), "RegOpenKeyExA( is called"),
            "a fifth check argument": (mutate(w, call, call[:-2] + ", check);"),
                                       "exactly four arguments"),
            "the unguarded opt-out named, arity changed": (mutate(
                w, call, call[:-2] + ", kOfflineHiveFileUnguarded);"), "kOfflineHiveFileUnguarded"),
            # Each token branch ALONE: the arity is untouched, only the name appears.
            "OfflineHiveFileCheck named, arity unchanged": (mutate(
                w, "out.refusal = std::move(report.refusal);",
                "out.refusal = std::move(report.refusal); using Chk = "
                "yuzu::win::OfflineHiveFileCheck;"), "OfflineHiveFileCheck is named"),
            "kOfflineHiveFileUnguarded named, arity unchanged": (mutate(
                w, "out.refusal = std::move(report.refusal);",
                "out.refusal = std::move(report.refusal); auto g = "
                "yuzu::win::kOfflineHiveFileUnguarded;"), "kOfflineHiveFileUnguarded is named"),
            "report argument dropped": (mutate(w, call, "[&](HKEY root) { fn(root); });"),
                                        "exactly four arguments"),
            "with_user_hive call commented out": (mutate(
                w, "out.status = yuzu::win::with_user_hive(",
                "// out.status = yuzu::win::with_user_hive("), "exactly one with_user_hive("),
            "with_user_hive called a second time": (mutate(
                w, "out.refusal = std::move(report.refusal);",
                "out.refusal = std::move(report.refusal); yuzu::win::with_user_hive("
                "profile.sid, profile.profile_path, [&](HKEY r) { fn(r); }, &report);"),
                "exactly one with_user_hive("),
            # The template-argument form is a second call that `name(` alone would not see.
            "with_user_hive called a second time with template arguments and a check": (mutate(
                w, "out.refusal = std::move(report.refusal);",
                "out.refusal = std::move(report.refusal); yuzu::win::with_user_hive<"
                "yuzu::profiles::HiveAccessStatus>(profile.sid, profile.profile_path, "
                "[&](HKEY r) { fn(r); }, &report, check);"), "exactly one with_user_hive("),
            "HKEY_USERS enumerated through the helper": (mutate(
                w, "const auto profiles = yuzu::profiles::build_profile_list(",
                "const auto hku = yuzu::win::enumerate_hku_subkeys();\n"
                "    const auto profiles = yuzu::profiles::build_profile_list("),
                "enumerate_hku_subkeys"),
            "HKEY_USERS enumerated directly": (mutate(
                w, "out.refusal = std::move(report.refusal);",
                "out.refusal = std::move(report.refusal); RegEnumKeyExW(HKEY_USERS, 0, nullptr, "
                "nullptr, nullptr, nullptr, nullptr, nullptr);"), "HKEY_USERS is named"),
            "mount_name copied into the result": (mutate(
                w, "out.unload_failed = report.unload_failed;",
                "out.unload_failed = report.unload_failed; out.refusal = report.mount_name;"),
                "outside an spdlog::error("),
            "mount_name logged below error level": (mutate(
                w, 'spdlog::error("virtualization wsl: hive unload failed',
                'spdlog::warn("virtualization wsl: hive unload failed'),
                "outside an spdlog::error("),
            # The other branch ALONE: the log call is kept, only the mount name leaves it.
            "mount_name no longer reaches the log": (mutate(
                w, "pname, report.mount_name, report.mount_name);", "pname, pname, pname);"),
                "mount_name no longer reaches the log"),
            "profile_list_token arguments swapped": (mutate(
                w, "profile_list_token(list.root_rc, list.last_rc, list.probe_rc)",
                "profile_list_token(list.root_rc, list.probe_rc, list.last_rc)"),
                "profile_list_token must be called exactly once"),
            "profile_list_token called a second time": (mutate(
                w, "wsl::detail::add_token(reads.tokens, *t);",
                "wsl::detail::add_token(reads.tokens, *t); "
                "wsl::profile_list_token(list.root_rc, list.last_rc, list.probe_rc);"),
                "profile_list_token must be called exactly once"),
            "record_failures loop loses the system-SID filter": (mutate(
                w, "if (!yuzu::profiles::is_system_sid(rf.sid)) {", "if (true) {"),
                "record_failures loop must keep both"),
            "record_failures loop loses the token": (mutate(
                w, 'wsl::detail::add_token(reads.tokens, "profile_unreadable");',
                'wsl::detail::add_token(reads.tokens, "profile_cap");'),
                "record_failures loop must keep both"),
            "unload log dropped from the catch arm": (mutate(
                w, "if (report.unload_failed)\n                log_unload_failed();\n            throw;",
                "throw;"), "before `throw;`"),
            "unload log moved after the rethrow": (mutate(
                w, "if (report.unload_failed)\n                log_unload_failed();\n            throw;",
                "throw;\n            if (report.unload_failed)\n                log_unload_failed();"),
                "before `throw;`"),
        }
        for name, (mutated, fragment) in cases.items():
            with self.subTest(mutation=name):
                found = problems(mutated)
                self.assertNotEqual(found, [], f"mutation not caught: {name}")
                self.assertTrue(any(fragment in f for f in found),
                                f"mutation {name!r} did not reach the {fragment!r} branch: {found}")


if __name__ == "__main__":
    unittest.main()
