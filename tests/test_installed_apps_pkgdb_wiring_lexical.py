#!/usr/bin/env python3
"""Static lexical gate over the installed_apps package-database wiring (SAM-45).

The dpkg and rpm readers are pure and tested (tests/unit/test_installed_apps_pkgdb.cpp), but two
facts about the REAL plugin are invisible to every portable test, because the Linux block of
agents/plugins/installed_apps/src/installed_apps_plugin.cpp is `#ifdef __linux__` and a unit test
never spawns a process or depends on host privilege:

  1. The Linux actions no longer run `dpkg-query` or `rpm`. Parity is the design, so no output
     assertion can tell the old and new acquisition apart: restoring the old call sites (and keeping
     every helper and test) leaves the whole suite green. This gate pins that no string literal in the
     plugin or the shell names such an executable, that `get_installed_apps_linux` and
     `get_inventory_linux` each call the bounded database read exactly once, and that every
     `probe_tool_path` literal left in them names pacman or apk.
  2. The lifecycle of the bounded read: the tracked-call guard is held across the call (the WAIT is
     counted on the calling thread, never inside the detached worker), the stop flag is the one
     handed to the reader, `shutdown()` quiesces, `init()` re-arms, and the quiesce waits the bounded
     five seconds. The behaviour of the wall bound, the `pkgdb:timeout|busy|unreadable` tokens and the
     stop predicate is tested in the unit suite (read_host_packages_bounded is in the shell header);
     a behavioural quiesce test belongs with the shared tracked-call primitive (#8364).

Lexical only: it cannot see an acquisition built another way (a literal assembled at run time, an
executable named by a variable), nor control flow that keeps these tokens. Beyond the tokens it is
review-enforced. The sources contain non-ASCII text, so they are read as UTF-8.
Usage: python3 tests/test_installed_apps_pkgdb_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "agents" / "plugins" / "installed_apps" / "src"
PLUGIN_CPP = SRC / "installed_apps_plugin.cpp"
SHELL_HPP = SRC / "installed_apps_pkgdb_read.hpp"
TAG = "test_installed_apps_pkgdb_wiring_lexical"
HINT = (
    " (this gate pins that the installed_apps Linux actions read the dpkg and rpm databases"
    " in-process and the lifecycle of that read; if the plugin was legitimately restructured, update"
    " the patterns AND the MUTATIONS in tests/test_installed_apps_pkgdb_wiring_lexical.py)"
)

# Comments first (so a // inside nothing else is read as one), then raw strings, strings and character
# literals taken whole so a brace or a quote inside one never moves anything. A digit separator
# (30'000) has no closing quote on its line, so it matches no character literal.
TOKEN = (r"//[^\n]*|/\*.*?\*/|R\"([^()\\\s]{0,16})\(.*?\)\1\"|\"(?:\\.|[^\"\\\n])*\""
         r"|'(?:\\.|[^'\\\n])*'")
TOKEN_RE = re.compile(TOKEN, re.S)
BRACE_RE = re.compile(TOKEN + r"|[{}]", re.S)


def code_of(src):
    """The source with every comment replaced by one space (literals untouched)."""
    return TOKEN_RE.sub(lambda m: " " if m.group(0).startswith(("//", "/*")) else m.group(0), src)


def literals(code):
    """The contents of every ordinary string literal in comment-free `code`."""
    return [m.group(0)[1:-1] for m in TOKEN_RE.finditer(code) if m.group(0).startswith('"')]


def norm(text):
    return re.sub(r"\s+", " ", text)


def body_of(code, head):
    """The text between the braces of the construct whose opening is matched by `head` (a regex ending
    at its `{`), or None. Brace-matched on comment-free code, literals skipped whole."""
    m = re.search(head, code)
    if not m:
        return None
    depth = 1
    for t in BRACE_RE.finditer(code, m.end()):
        g = t.group(0)
        depth += (g == "{") - (g == "}")
        if depth == 0:
            return code[m.end():t.start()]
    return None


# An executable that the OLD acquisition ran: dpkg-query anywhere in a literal, or rpm named as an
# argv[0] or by an absolute path. (The rpm DATABASE directories "var/lib/rpm" are not executables.)
OLD_TOOL = re.compile(r"dpkg-query|^rpm$|^/.*bin/rpm$")

HEAD_APPS = r"AppCollection\s+get_installed_apps_linux\(\s*\)\s*\{"
HEAD_INV = r"InvCollection\s+get_inventory_linux\(\s*\)\s*\{"
HEAD_WRAP = r"pkgdb::HostPackages\s+read_host_packages_bounded\(\s*\)\s*\{"
HEAD_QUIESCE = r"void\s+quiesce_pkgdb_calls\(\s*\)\s*noexcept\s*\{"
HEAD_GUARD = r"class\s+PkgDbCallGuard\s*\{"
HEAD_INIT = r"yuzu::Result<void>\s+init\(\s*yuzu::PluginContext&[^)]*\)\s*override\s*\{"
HEAD_SHUTDOWN = r"void\s+shutdown\(\s*yuzu::PluginContext&[^)]*\)\s*noexcept\s*override\s*\{"


def problems(plugin_src, shell_src):
    """One message per violated invariant, in invariant order; [] when clean."""
    plugin = code_of(plugin_src)
    shell = code_of(shell_src)
    out = []

    # 1. No literal names the old executables, in the plugin or in the shell header.
    for name, code in (("installed_apps_plugin.cpp", plugin), ("installed_apps_pkgdb_read.hpp", shell)):
        for lit in literals(code):
            if OLD_TOOL.search(lit):
                out.append(f'{name}: the string literal "{lit}" names a dpkg-query or rpm executable')

    # 2. Each Linux collector reads the database once and keeps only the pacman and apk legs.
    for fn, head in (("get_installed_apps_linux", HEAD_APPS), ("get_inventory_linux", HEAD_INV)):
        body = body_of(plugin, head)
        if body is None:
            out.append(f"{fn}() is not defined")
            continue
        body = norm(body)
        calls = len(re.findall(r"(?<![:\w])read_host_packages_bounded\( ?\)", body))
        if calls != 1:
            out.append(f"{fn}() calls read_host_packages_bounded() {calls} times, expected exactly once")
        probes = re.findall(r"probe_tool_path\( ?\{(.*?)\} ?\)", body)
        if not probes:
            out.append(f"{fn}() has no probe_tool_path leg left (the pacman leg was expected)")
        for lst in probes:
            lits = re.findall(r'"([^"]*)"', lst)
            if not lits or not all(("pacman" in x or "apk" in x) for x in lits):
                out.append(f"{fn}() has a probe_tool_path list that names something other than "
                           f"pacman or apk: {lst.strip()}")

    # 3. Lifecycle of the bounded read.
    guard = body_of(plugin, HEAD_GUARD)
    if guard is None:
        out.append("class PkgDbCallGuard is not defined")
    else:
        g = norm(guard)
        if not (re.search(r"PkgDbCallGuard\( ?\) noexcept \{ \+\+g_outstanding_pkgdb_calls; \}", g) and
                re.search(r"~PkgDbCallGuard\( ?\) noexcept \{ --g_outstanding_pkgdb_calls; \}", g)):
            out.append("PkgDbCallGuard no longer increments g_outstanding_pkgdb_calls in its constructor "
                       "and decrements it in its destructor")

    wrap = body_of(plugin, HEAD_WRAP)
    if wrap is None:
        out.append("pkgdb::HostPackages read_host_packages_bounded() is not defined")
    else:
        w = norm(wrap)
        if len(re.findall(r"\bPkgDbCallGuard\b", w)) != 1:
            out.append("read_host_packages_bounded() does not declare exactly one PkgDbCallGuard "
                       "(the wait must be counted on the calling thread)")
        if not re.search(r'^ ?PkgDbCallGuard guard; return pkgdb::read_host_packages_bounded\( ?"/", ?'
                         r"pkgdb::Limits\{\}, ?\[\] \{ return g_pkgdb_stop\.load\(", w):
            out.append('read_host_packages_bounded() no longer takes the PkgDbCallGuard first and then '
                       'calls pkgdb::read_host_packages_bounded("/", pkgdb::Limits{}, <g_pkgdb_stop '
                       'predicate>)')

    quiesce = body_of(plugin, HEAD_QUIESCE)
    if quiesce is None:
        out.append("void quiesce_pkgdb_calls() noexcept is not defined")
    else:
        q = norm(quiesce)
        if not re.search(r"g_pkgdb_stop\.store\( ?true", q):
            out.append("quiesce_pkgdb_calls() no longer raises g_pkgdb_stop")
        if not re.search(r"steady_clock::now\( ?\) \+ kPkgDbShutdownQuiesce", q) or \
                "g_outstanding_pkgdb_calls.load" not in q:
            out.append("quiesce_pkgdb_calls() no longer waits on g_outstanding_pkgdb_calls until "
                       "kPkgDbShutdownQuiesce")
    if not re.search(r"constexpr std::chrono::seconds kPkgDbShutdownQuiesce\{ ?5 ?\};", norm(plugin)):
        out.append("kPkgDbShutdownQuiesce is no longer five seconds")

    shutdown = body_of(plugin, HEAD_SHUTDOWN)
    if shutdown is None:
        out.append("the plugin's shutdown() is not defined")
    elif len(re.findall(r"\bquiesce_pkgdb_calls\( ?\);", shutdown)) != 1:
        out.append("shutdown() does not call quiesce_pkgdb_calls() exactly once")

    init = body_of(plugin, HEAD_INIT)
    if init is None:
        out.append("the plugin's init() is not defined")
    elif not re.search(r"g_pkgdb_stop\.store\( ?false", init):
        out.append("init() no longer clears g_pkgdb_stop (a re-initialised instance would never read again)")
    return out


# Each row damages one invariant: (target, pattern, repl, flags, [expected substrings, ALL must
# appear in some problem]). The patterns match the raw sources.
MUTATIONS = [
    # 1. the old acquisition restored in the list collector (helpers and tests untouched)
    ("plugin", r"auto host = read_host_packages_bounded\(\);",
     'auto old = yuzu::agent::probe_tool_path({"/usr/bin/dpkg-query"}); pkgdb::HostPackages host;', 0,
     ["dpkg-query", "get_installed_apps_linux() calls read_host_packages_bounded() 0 times"]),
    # 2. the old rpm leg restored in the inventory collector
    ("plugin", r"(InvCollection get_inventory_linux\(\) \{.*?)auto host = read_host_packages_bounded\(\);",
     r'\g<1>auto old = yuzu::agent::probe_tool_path({"/usr/bin/rpm", "/bin/rpm"}); '
     r"pkgdb::HostPackages host;", re.S,
     ["/usr/bin/rpm", "get_inventory_linux() calls read_host_packages_bounded() 0 times"]),
    # 3. the database read called twice in one collector
    ("plugin", r"(InvCollection get_inventory_linux\(\) \{.*?)(auto host = read_host_packages_bounded\(\);)",
     r"\g<1>\g<2> (void)read_host_packages_bounded();", re.S,
     ["get_inventory_linux() calls read_host_packages_bounded() 2 times"]),
    # 4. a probe_tool_path leg for a tool that is neither pacman nor apk
    ("plugin", r'(probe_tool_path\(\{)("/usr/bin/pacman")', r'\g<1>"/usr/bin/yum", \g<2>', 0,
     ["other than pacman or apk"]),
    # 5. an rpm executable literal in the shell header
    ("shell", r"(constexpr std::string_view kSource = \"dpkg_status\";)",
     r'\g<1> constexpr const char* kOld = "/usr/bin/rpm";', 0, ["installed_apps_pkgdb_read.hpp", "/usr/bin/rpm"]),
    # 6. argv[0] "rpm" as a bare literal
    ("plugin", r"auto host = read_host_packages_bounded\(\);",
     'auto host = read_host_packages_bounded(); const char* argv0 = "rpm";', 0,
     ['the string literal "rpm"']),
    # 7. the guard removed from the wrapper
    ("plugin", r"    PkgDbCallGuard guard; // counts the wait", "    // counts the wait", 0,
     ["exactly one PkgDbCallGuard"]),
    # 8. the guard moved into the worker's predicate (counted from inside the detached worker)
    ("plugin", r"    PkgDbCallGuard guard;[^\n]*\n(    return pkgdb::read_host_packages_bounded\(\n"
     r"        \"/\", pkgdb::Limits\{\}, \[\] \{ )(return g_pkgdb_stop)",
     r"\g<1>PkgDbCallGuard guard; \g<2>", 0, ["no longer takes the PkgDbCallGuard first"]),
    # 9. the stop predicate no longer the plugin's flag
    ("plugin", r"\[\] \{ return g_pkgdb_stop\.load\(std::memory_order_relaxed\); \}\);\n\}",
     "[] { return false; });\n}", 0, ["no longer takes the PkgDbCallGuard first"]),
    # 10. shutdown() no longer quiesces
    ("plugin", r"        quiesce_pkgdb_calls\(\);", "", 0, ["shutdown() does not call quiesce_pkgdb_calls()"]),
    # 11. init() no longer clears the stop flag
    ("plugin", r"g_pkgdb_stop\.store\(false, std::memory_order_relaxed\);", "(void)0;", 0,
     ["init() no longer clears g_pkgdb_stop"]),
    # 12. the quiesce no longer raises the stop flag
    ("plugin", r"g_pkgdb_stop\.store\(true, std::memory_order_relaxed\);", "(void)0;", 0,
     ["quiesce_pkgdb_calls() no longer raises g_pkgdb_stop"]),
    # 13. the quiesce bound changed
    ("plugin", r"kPkgDbShutdownQuiesce\{5\}", "kPkgDbShutdownQuiesce{0}", 0,
     ["kPkgDbShutdownQuiesce is no longer five seconds"]),
    # 14. the guard's destructor no longer releases the count
    ("plugin", r"~PkgDbCallGuard\(\) noexcept \{ --g_outstanding_pkgdb_calls; \}",
     "~PkgDbCallGuard() noexcept {}", 0, ["PkgDbCallGuard no longer increments"]),
]


class InstalledAppsPkgdbWiringLexical(unittest.TestCase):
    def setUp(self):
        self.plugin = PLUGIN_CPP.read_text(encoding="utf-8")
        self.shell = SHELL_HPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.plugin, self.shell)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (target, pat, repl, flags, expected) in enumerate(MUTATIONS, 1):
            with self.subTest(mutation=i, pattern=pat):
                src = self.plugin if target == "plugin" else self.shell
                mutated, n = re.subn(pat, repl, src, count=1, flags=flags)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = (problems(mutated, self.shell) if target == "plugin"
                     else problems(self.plugin, mutated))
                self.assertTrue(p, "mutation was NOT detected by the gate")
                for want in expected:
                    self.assertTrue(any(want in m for m in p),
                                    f"expected a problem containing {want!r}, got {p}")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
