#!/usr/bin/env python3
"""Static lexical gate over Echo's bounded hive-mount call site (related issue #5291, PR #6311).

enum_registry_outbound_history (agents/plugins/echo/src/echo_mapdrive_collector.cpp, Windows only)
abandons a mount thread that outlives its bound; that thread keeps running Echo code and nothing
joins it, and so does a worker that COMPLETES (it destroys its plugin-resident closure after
publishing the result). The only thing between them and an unmapped module is the pin taken before
the first mount, and the Windows bodies cannot run in the unit suites (the decision policy itself is unit-tested in
test_echo_mapdrive.cpp), so this pins the wiring lexically. Invariants:

  1. pin_plugin_module pins by address: GET_MODULE_HANDLE_EX_FLAG_PIN | ..._FROM_ADDRESS, with
     its own address as the module hint.
  2. The walk pins the module and asks decide_walk_gate (pin + abandoned workers still running,
     counted by MountWorkerGuard) BEFORE the first bounded mount; a closed gate means no mount is
     tried. The non-Completed branch asks decide_mount_call, records `outcome.attempted =
     decision.attempted` and stops the walk (`mounts_halted = decision.halt_walk`). The pin is taken
     up front, not on a timeout, because a worker that COMPLETES is detached too and destroys its
     plugin-resident closure after publishing the result.
  3. A halted walk records each remaining profile as not attempted (`attempted = false`, the cause
     token, appended) and `continue`s, BEFORE the next bounded_call_ex.
  4. A MountPoints2 child-open failure reaches note_failure(sk_rc) and skips the row; a clean
     cap-cut read is labelled "row_cap".
  5. echo_plugin.cpp's first-pass insert passes skip_known_historical=true, and a vanished
     pending SID is logged.
  6. The banner no longer cites dism_bounded_call.hpp as the pattern it follows (that header
     keeps its work in agent-core, which is never unloaded: the opposite stance).
  7. The in-flight counter, MountWorkerGuard and the mount bound live in echo_hive_mount_gate.hpp,
     shared with the registry source (one counter per plugin DLL); the registry source's offline
     reader (echo_registry_source.cpp, read_offline_hive_bounded) follows the same wiring: it asks
     decide_walk_gate(pin_plugin_module(), ...) before its first bounded_call_ex, refuses without
     mounting when the gate is closed or an earlier mount this tick halted the rest, counts its
     worker in flight before with_user_hive, bounds the wait with kHiveMountBoundMs and halts the
     tick on a timeout/rejection, and opens each root with REG_OPTION_OPEN_LINK. It mounts
     through the DEFAULT-ON hive-file guard only (its with_user_hive call ends `&report)` and
     never names kOfflineHiveFileUnguarded), logs a closed gate once per transition
     (note_mount_gate, between the gate decision and the refusal), and its catch(...) handler
     only moves in a fallback result built before the try (it must not allocate). Its profile
     discovery (discover_offline_profiles) routes through the unit-tested pure
     classify_offline_discovery.
  8. The registry source's start-up sweep of leftover YUZU_HIVE_* mounts (UP-6) goes through the
     same gate and worker: run_pending_hive_sweep asks decide_walk_gate(pin_plugin_module(), ...)
     before its bounded_call_ex(kHiveMountBoundMs, ...), counts its worker in flight, clears
     sweep_pending only when the worker completed and otherwise halts the tick through
     decide_mount_call; it runs from the reader's start() before the ETW session and from
     read_offline_hive_bounded before that function's own halted check. The shell
     (sweep_leftover_hive_mounts) takes the process-wide offline-hive lock BEFORE it lists
     HKEY_USERS (that lock is what keeps it off this process's own live mounts), lists through
     the shared enumerate_hku_subkeys, offers only select_stale_hive_mounts' names to
     RegUnLoadKeyW only when SeRestorePrivilege is held, and never forces an unload; the
     worker sweeps the whole default prefix (no argument).

Robustness: `//` comments are stripped and whitespace is collapsed before matching, so a
`//`-commented call cannot satisfy a check (`/* */` comments are deliberately NOT stripped). Lexical only: it cannot see a relocation that keeps
the tokens but changes control flow (review-enforced). The self-test applies in-memory
mutations and requires problems() to be non-empty on each; a mutation whose pattern no longer
matches the source fails loudly (stale pattern) rather than passing vacuously.

Usage: python3 tests/test_echo_mapdrive_pin_lexical.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COLLECTOR = ROOT / "agents" / "plugins" / "echo" / "src" / "echo_mapdrive_collector.cpp"
PLUGIN = ROOT / "agents" / "plugins" / "echo" / "src" / "echo_plugin.cpp"
GATE = ROOT / "agents" / "plugins" / "echo" / "src" / "echo_hive_mount_gate.hpp"
REGISTRY = ROOT / "agents" / "plugins" / "echo" / "src" / "echo_registry_source.cpp"
OFFLINE_READER = "OfflineHiveRead read_offline_hive_bounded("  # anchor: the mount reader, not the sweep
HINT = (" (this gate pins the #5291 hive-mount wiring; if the collector was legitimately"
        " restructured, update tests/test_echo_mapdrive_pin_lexical.py)")


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    lines = [re.sub(r"//.*$", "", ln) for ln in src.splitlines()]
    return re.sub(r"\s+", " ", " ".join(lines))


def body_of(text, signature):
    start = text.find(signature)
    if start < 0:
        return None
    brace = text.index("{", start)
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace:i + 1]
    return None


def problems(collector_src, plugin_src, gate_src, registry_src):
    out = []
    c = normalise(collector_src)
    p = normalise(plugin_src)
    g = normalise(gate_src)
    r = normalise(registry_src)

    pin = body_of(c, "bool pin_plugin_module() noexcept")
    if pin is None:
        out.append("pin_plugin_module() is missing")
    else:
        if "return true;" not in pin or "return false;" not in pin:
            out.append("pin_plugin_module() must return true on success and false on failure")
        for tok in ("GET_MODULE_HANDLE_EX_FLAG_PIN", "GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS",
                    "&pin_plugin_module)"):
            if tok not in pin:
                out.append(f"pin_plugin_module() no longer contains {tok}")

    if not re.search(r"MountWorkerGuard\(\) noexcept \{ g_mount_workers_in_flight\.fetch_add\(1\);"
                     r" \} ~MountWorkerGuard\(\) \{ g_mount_workers_in_flight\.fetch_sub\(1\); \}",
                     g):
        out.append("MountWorkerGuard (echo_hive_mount_gate.hpp) no longer counts the worker in and out")
    if "inline std::atomic<int> g_mount_workers_in_flight{0};" not in g:
        out.append("echo_hive_mount_gate.hpp no longer owns the in-flight counter")
    if "kHiveMountBoundMs{30000}" not in g:
        out.append("echo_hive_mount_gate.hpp no longer owns the mount bound")
    if "bool pin_plugin_module() noexcept;" not in g:
        out.append("echo_hive_mount_gate.hpp no longer declares pin_plugin_module")
    if "echo_hive_mount_gate.hpp" not in c or "echo_hive_mount_gate.hpp" not in r:
        out.append("the mapdrive collector and the registry source must both include the shared gate")

    offline = body_of(r, "OfflineHiveRead read_offline_hive_bounded(")
    if offline is None:
        out.append("read_offline_hive_bounded() is missing")
    else:
        gate_at = offline.find("decide_walk_gate(pin_plugin_module(), g_mount_workers_in_flight.load())")
        mount_at = offline.find("bounded_call_ex(")
        if gate_at < 0 or mount_at < 0 or gate_at > mount_at:
            out.append("the offline reader must pin the module and ask decide_walk_gate (pin + in-flight "
                       "workers) before its first bounded_call_ex")
        if not re.search(r"if \(gate != yuzu::echo::WalkGate::open\) return unreadable_hive\(roots, false,",
                         offline):
            out.append("a closed gate must answer not-attempted without mounting")
        if not re.search(r"if \(tick\.halted\) return unreadable_hive\(roots, false,", offline):
            out.append("a halted tick must answer not-attempted without mounting")
        if not re.search(r"bounded_call_ex\(\s*kHiveMountBoundMs\b", offline):
            out.append("the offline mount is no longer bounded by kHiveMountBoundMs")
        if not re.search(r"const MountWorkerGuard \w+;[^}]*?with_user_hive\(", offline):
            out.append("the offline mount worker no longer counts itself in flight before with_user_hive")
        if not re.search(r"tick\.halted = decision\.halt_walk;", offline):
            out.append("a timed-out or rejected offline mount no longer halts the tick")
        # The default-on hive-file guard (#5291) is the whole point of sharing the ladder: the
        # offline reader must never pass the opt-out, whatever name it goes by.
        if "kOfflineHiveFileUnguarded" in offline:
            out.append("the offline reader opts out of the default hive-file guard "
                       "(kOfflineHiveFileUnguarded)")
        if not re.search(r"with_user_hive\( sid, path, \[&\]\(HKEY root\) \{.*?\}, &report\);", offline):
            out.append("the offline reader's with_user_hive call must end `&report)`: the default "
                       "guard, no fifth argument")
        decide_at = offline.find("decide_walk_gate(")
        note_at = offline.find("note_mount_gate(tick, gate);")
        refuse_at = offline.find("if (gate != yuzu::echo::WalkGate::open)")
        if not (0 <= decide_at < note_at < refuse_at):
            out.append("a closed mount gate must be logged (note_mount_gate) between the gate "
                       "decision and the refusal")
        fallback_at = offline.find("OfflineHiveRead failed = unreadable_hive(")
        try_at = offline.find("try {")
        handler = re.search(r"catch \(\.\.\.\) \{([^{}]*)\}", offline)
        if not (0 <= fallback_at < try_at) or handler is None or "unreadable_hive(" in handler.group(1):
            out.append("the worker's catch(...) handler must only move in a fallback result built "
                       "before the try (a bad_alloc inside the handler would leave the closure)")
        if "decide_mount_call(" not in offline:
            out.append("the offline reader no longer asks decide_mount_call")
        # A root that is itself a symbolic-link key is read as the link, never followed: the
        # same flags open_root passes on the live path (security-relevant, kept in step here).
        if not re.search(r"RegOpenKeyExW\([^;]*?REG_OPTION_OPEN_LINK, KEY_READ \| KEY_WOW64_64KEY, "
                         r"key\.put\(\)\)", offline):
            out.append("the offline reader's root open no longer passes REG_OPTION_OPEN_LINK with "
                       "KEY_READ | KEY_WOW64_64KEY")
    if not re.search(r"r\.read_offline_hive = .*?read_offline_hive_bounded\(", r):
        out.append("the Windows reader no longer wires read_offline_hive to read_offline_hive_bounded")
    # The start-up sweep of leftover YUZU_HIVE_* mounts (UP-6): same gate, same bounded worker.
    if "bool sweep_pending{true};" not in r:
        out.append("OfflineMountTick no longer starts with the start-up sweep pending")
    sweep = body_of(r, "void run_pending_hive_sweep(OfflineMountTick& tick)")
    if sweep is None:
        out.append("run_pending_hive_sweep() is missing")
    else:
        gate_at = sweep.find("decide_walk_gate(pin_plugin_module(), g_mount_workers_in_flight.load())")
        call_at = sweep.find("bounded_call_ex(")
        if gate_at < 0 or call_at < 0 or gate_at > call_at:
            out.append("the sweep must pin the module and ask decide_walk_gate (pin + in-flight "
                       "workers) before its bounded_call_ex")
        if not re.search(r"decide_walk_gate\(pin_plugin_module\(\), g_mount_workers_in_flight\.load\(\)\) "
                         r"!= yuzu::echo::WalkGate::open\) return;", sweep):
            out.append("a closed gate must leave the sweep pending without running it")
        if not re.search(r"bounded_call_ex\(\s*kHiveMountBoundMs\b", sweep):
            out.append("the sweep is no longer bounded by kHiveMountBoundMs")
        if not re.search(r"const MountWorkerGuard \w+;[^}]*?sweep_leftover_hive_mounts\(\)", sweep):
            out.append("the sweep worker no longer counts itself in flight before it sweeps, or "
                       "no longer sweeps the whole default prefix (no argument)")
        if not re.search(r"BoundedCallStatus::Completed\) \{ tick\.sweep_pending = false; return; \}", sweep):
            out.append("the sweep must clear sweep_pending when, and only when, its worker completed")
        if sweep.count("sweep_pending = false") != 1:
            out.append("sweep_pending is cleared on a path other than a completed worker")
        if "decide_mount_call(" not in sweep or "tick.halted = decision.halt_walk;" not in sweep:
            out.append("a timed-out or rejected sweep no longer halts the tick through decide_mount_call")
        if not sweep.lstrip("{ ").startswith("if (!tick.sweep_pending || tick.halted) return;"):
            out.append("the sweep must return at once when nothing is pending or the tick is halted")
    if offline is not None:
        sweep_at = offline.find("run_pending_hive_sweep(tick);")
        halted_at = offline.find("if (tick.halted)")
        if not (0 <= sweep_at < halted_at):
            out.append("the offline reader must run the pending sweep before it checks whether the "
                       "tick is halted (a sweep that halts the tick answers not-attempted)")
    start = body_of(r, "r.start = [etw, tick] {")
    if start is None or "run_pending_hive_sweep(*tick);" not in start:
        out.append("the Windows reader's start() no longer runs the pending sweep")
    elif start.find("run_pending_hive_sweep(*tick);") > start.find("etw->start()"):
        out.append("the sweep must run before the ETW session opens")
    if not re.search(r"r\.read_offline_hive = \[tick\]", r):
        out.append("the offline-read hook and start() no longer share one OfflineMountTick")
    shell = body_of(r, "HiveSweepResult sweep_leftover_hive_mounts(std::string_view prefix)")
    if shell is None:
        out.append("sweep_leftover_hive_mounts() is missing")
    else:
        lock_at = shell.find('ScopedOfflineHiveLock offline_lock("echo_registry_sweep")')
        list_at = shell.find("enumerate_hku_subkeys()")
        if not (0 <= lock_at < list_at):
            out.append("the sweep must take the process-wide offline-hive lock BEFORE it lists "
                       "HKEY_USERS: the lock is what keeps it off this process's live mounts")
        if "select_stale_hive_mounts(yuzu::win::enumerate_hku_subkeys(), prefix)" not in shell:
            out.append("the sweep must list through the shared enumerate_hku_subkeys and select "
                       "through the unit-tested select_stale_hive_mounts")
        if "enumerate_hku()" in shell:
            out.append("the sweep must not list through Echo's own enumerate_hku")
        if ('PrivilegeScope restore_priv(L"SeRestorePrivilege")' not in shell
                or "if (restore_priv.ok())" not in shell):
            out.append("the sweep no longer enables SeRestorePrivilege, or no longer gates the "
                       "unload on holding it")
        if not re.search(r"sweep_hive_mounts\( ?stale, \[\]\(const std::string& name\) \{ return "
                         r"RegUnLoadKeyW\(HKEY_USERS, yuzu::win::to_wide\(name\)\.c_str\(\)\) "
                         r"== ERROR_SUCCESS; \}\);", shell):
            out.append("the sweep must unload only the selected names, through a plain RegUnLoadKeyW")
        if "NtUnloadKey" in shell or "REG_FORCE_UNLOAD" in shell:
            out.append("the sweep forces an unload: a holder with an open handle is a live user of the hive")
    # The profile-list classification is unit-tested (classify_offline_discovery); the Windows
    # shell must feed it, or an empty-but-complete discovery would leave every test green.
    discovery = body_of(
        r, "OfflineDiscovery discover_offline_profiles(const std::vector<std::string>& loaded) noexcept")
    if discovery is None:
        out.append("discover_offline_profiles(loaded) is missing")
    else:
        if "classify_offline_discovery(" not in discovery:
            out.append("discover_offline_profiles() no longer classifies through "
                       "classify_offline_discovery")
        # One HKU snapshot per tick: the shell classifies against collect()'s own list, never a
        # second enumeration (a logon between the two would drop a baselined offline profile).
        if "build_profile_list(disc.records, loaded)" not in discovery:
            out.append("discover_offline_profiles() no longer classifies against collect()'s loaded list")
        if "enumerate_hku" in discovery:
            out.append("discover_offline_profiles() enumerates HKU a second time")
    if not re.search(r"r\.offline_profiles = \[\]\(const std::vector<std::string>& loaded\) \{ "
                     r"return discover_offline_profiles\(loaded\); \}", r):
        out.append("the Windows reader no longer wires offline_profiles to discover_offline_profiles")

    walk = body_of(c, "void enum_registry_outbound_history(")
    if walk is None:
        out.append("enum_registry_outbound_history() is missing")
    else:
        mount = walk.find("bounded_call_ex(")
        gate_at = walk.find("decide_walk_gate(pin_plugin_module(), g_mount_workers_in_flight.load())")
        if gate_at < 0 or mount < 0 or gate_at > mount:
            out.append("the walk must pin the module and ask decide_walk_gate (pin + in-flight "
                       "workers) before its first bounded_call_ex")
        if not re.search(r"mounts_halted = gate != yuzu::echo::WalkGate::open;", walk):
            out.append("a closed walk gate no longer halts the walk")
        if "decide_mount_call(" not in walk:
            out.append("the walk no longer asks decide_mount_call")
        if not re.search(r"mounts_halted = decision\.halt_walk;", walk):
            out.append("the timeout branch no longer halts the walk")
        if not re.search(r"outcome\.status = yuzu::win::HiveAccessStatus::mount_failed; "
                         r"outcome\.token = cause; outcome\.attempted = decision\.attempted; "
                         r"outcome\.complete = true; h\.profiles\.push_back\(std::move\(outcome\)\); "
                         r"mounts_halted = decision\.halt_walk; .*?continue; \}", walk):
            out.append("the timeout/rejection branch must record a mount_failed outcome carrying "
                       "decision.attempted, halt the walk and continue")
        if not re.search(r"const MountWorkerGuard \w+;[^}]*?with_user_hive\(", walk):
            out.append("the mount worker closure no longer counts itself in flight")
        halted = re.search(r"if \(mounts_halted\) \{ ProfileHiveOutcome skipped;([^{}]*?)"
                           r"h\.profiles\.push_back\(std::move\(skipped\)\); continue; \}", walk)
        if not halted or mount < 0 or halted.start() > mount:
            out.append("the halted-walk block must append its skipped outcome and continue, "
                       "before the next bounded_call_ex")
        else:
            blk = halted.group(1)
            if "attempted = false" not in blk:
                out.append("the halted-walk block must record the profile as attempted = false")
            if "skipped.token = halted_token;" not in blk:
                out.append("the halted-walk block must carry the cause token")
        if '"row_cap"' not in walk:
            out.append('a clean cap-cut read is no longer labelled "row_cap"')

    if not re.search(r"const LONG sk_rc = RegOpenKeyExW\(mp\.h, sub, 0, KEY_READ, &sk\.h\); "
                     r"if \(sk_rc != ERROR_SUCCESS\) \{.*?note_failure\(sk_rc\); idx\+\+; "
                     r"len = 256; continue; \}", c):
        out.append("a MountPoints2 child-open failure no longer skips the row and reaches "
                   "note_failure")

    if not re.search(r"typed\.empty\(\) \|\| db_->fold_mapdrive_events\( ?typed, std::nullopt, "
                     r"/\*skip_known_historical=\*/true\)", p):
        out.append("the first-pass insert no longer passes skip_known_historical=true")
    if "dropped from the pending set" not in p:
        out.append("a vanished pending SID is no longer logged")

    if re.search(r"see dism_bounded_call\.hpp/power_health_plugin\.cpp", collector_src):
        out.append("the banner again cites dism_bounded_call.hpp as the pattern followed")
    return out


def mutate(src, old, new):
    assert old in src, f"stale mutation pattern: {old!r}"
    return src.replace(old, new, 1)


def mutate_after(src, anchor, old, new):
    """Replace the first `old` after the first `anchor` (the retry path also passes the flag)."""
    at = src.index(anchor)
    i = src.index(old, at)
    return src[:i] + new + src[i + len(old):]


class EchoMapdrivePinLexical(unittest.TestCase):
    def setUp(self):
        self.collector = COLLECTOR.read_text(encoding="utf-8")
        self.plugin = PLUGIN.read_text(encoding="utf-8")
        self.gate = GATE.read_text(encoding="utf-8")
        self.registry = REGISTRY.read_text(encoding="utf-8")

    def probe(self, **over):
        return problems(over.get("c", self.collector), over.get("p", self.plugin),
                        over.get("g", self.gate), over.get("r", self.registry))

    def test_source_is_clean(self):
        self.assertEqual(self.probe(), [], HINT)

    def test_mutations_are_caught(self):
        c, p, g, r = self.collector, self.plugin, self.gate, self.registry
        cases = {
            "gate decision deleted": dict(c=mutate(
                c, "decide_walk_gate(pin_plugin_module(),\n"
                   "                                                   g_mount_workers_in_flight.load())",
                   "decide_walk_gate(true, 0)")),
            "gate decision commented out": dict(c=mutate(
                c, "const auto gate = yuzu::echo::decide_walk_gate(pin_plugin_module(),",
                   "const auto gate = yuzu::echo::WalkGate::open; // decide_walk_gate(pin_plugin_module(),")),
            "pin flag dropped": dict(c=mutate(c, "GET_MODULE_HANDLE_EX_FLAG_PIN", "0")),
            "closed gate no longer halts": dict(c=mutate(
                c, "bool mounts_halted = gate != yuzu::echo::WalkGate::open;",
                   "bool mounts_halted = false;")),
            "halt assignment dropped": dict(c=mutate(c, "mounts_halted = decision.halt_walk;",
                                                     "(void)decision;")),
            "outcome attempted flag dropped": dict(c=mutate(
                c, "outcome.attempted = decision.attempted;", "(void)decision;")),
            "worker no longer counted in flight": dict(c=mutate(
                c, "const MountWorkerGuard in_flight;", "(void)0;")),
            "in-flight guard stops counting": dict(g=mutate(
                g, "g_mount_workers_in_flight.fetch_sub(1);", "(void)0;")),
            "gate header loses the counter": dict(g=mutate(
                g, "inline std::atomic<int> g_mount_workers_in_flight{0};",
                   "inline std::atomic<int> g_other{0};")),
            "gate header loses the mount bound": dict(g=mutate(
                g, "kHiveMountBoundMs{30000}", "kHiveMountBoundMs{0}")),
            "collector stops including the shared gate": dict(c=mutate(
                c, '#include "echo_hive_mount_gate.hpp"', "#include <atomic>")),
            "halted block loses attempted=false": dict(
                c=mutate(c, "skipped.attempted = false;", "skipped.attempted = true;")),
            "halted block loses its append": dict(c=mutate(
                c, "h.profiles.push_back(std::move(skipped));", "(void)skipped;")),
            "halted block loses its cause token": dict(c=mutate(
                c, "skipped.token = halted_token;", 'skipped.token = "x";')),
            "halted block loses its continue": dict(c=mutate(
                mutate(c, "skipped.token = halted_token;", "skipped.token = halted_token;"),
                "h.profiles.push_back(std::move(skipped));\n            continue;",
                "h.profiles.push_back(std::move(skipped));")),
            "a mount is started before the halted block": dict(c=mutate(
                c, "if (mounts_halted) {\n            // Not tried",
                   "{ auto early = yuzu::shared::bounded_call_ex(kHiveMountBoundMs, [] { return 0; });"
                   " (void)early; }\n        if (mounts_halted) {\n            // Not tried")),
            "pin returns true on failure": dict(c=mutate(
                c, "        return false;\n    }();", "        return true;\n    }();")),
            "timeout outcome loses its halt": dict(c=mutate(
                c, "h.profiles.push_back(std::move(outcome));\n            mounts_halted =",
                   "h.profiles.push_back(std::move(outcome));\n            (void)")),
            "row_cap label dropped": dict(c=mutate(c, '"row_cap"', '"ok"')),
            "MountPoints2 failure no longer skips": dict(c=mutate(
                c, "note_failure(sk_rc);\n                        idx++;", "idx++;")),
            "dism reference restored": dict(c=(
                c + "\n// plugin's first consumer; see dism_bounded_call.hpp/power_health_plugin.cpp\n")),
            "first-pass dedupe dropped": dict(p=mutate_after(
                p, "typed.empty() ||", "/*skip_known_historical=*/true",
                "/*skip_known_historical=*/false")),
            "vanished-SID log dropped": dict(p=mutate(p, "dropped from the pending set", "dropped")),
            # the registry source's offline reader
            "registry gate decision deleted": dict(r=mutate_after(
                r, OFFLINE_READER, "decide_walk_gate(pin_plugin_module(), g_mount_workers_in_flight.load())",
                   "yuzu::echo::WalkGate::open")),
            "registry closed gate no longer refuses": dict(r=mutate(
                r, "if (gate != yuzu::echo::WalkGate::open)", "if (false)")),
            "registry halted tick still mounts": dict(r=mutate(
                r, "if (tick.halted)\n", "if (false)\n")),
            "registry mount unbounded": dict(r=mutate(
                r, "kHiveMountBoundMs, [sid, path, roots, deadline]",
                   "std::chrono::milliseconds{0}, [sid, path, roots, deadline]")),
            "registry worker not counted in flight": dict(r=mutate_after(
                r, OFFLINE_READER, "const MountWorkerGuard in_flight;", "(void)0;")),
            "registry timeout no longer halts the tick": dict(r=mutate_after(
                r, OFFLINE_READER, "tick.halted = decision.halt_walk;", "(void)decision;")),
            "registry hook no longer wired": dict(r=mutate(
                r, "return read_offline_hive_bounded(sid, path, roots, deadline, *tick);",
                   "return OfflineHiveRead{};")),
            "registry discovery stops classifying": dict(r=mutate(
                r, "return classify_offline_discovery(", "return classify_offline(")),
            "registry discovery hook no longer wired": dict(r=mutate(
                r, "return discover_offline_profiles(loaded);", "return OfflineDiscovery{};")),
            "registry discovery enumerates HKU a second time": dict(r=mutate(
                r, "build_profile_list(disc.records, loaded)",
                   "build_profile_list(disc.records, yuzu::win::enumerate_hku_subkeys())")),
            "registry discovery ignores collect's loaded list": dict(r=mutate(
                r, "build_profile_list(disc.records, loaded)", "build_profile_list(disc.records, {})")),
            "registry closed gate answers attempted": dict(r=mutate(
                r, "if (gate != yuzu::echo::WalkGate::open)\n        return unreadable_hive(roots, false,",
                   "if (gate != yuzu::echo::WalkGate::open)\n        return unreadable_hive(roots, true,")),
            "registry halted check inverted": dict(r=mutate(
                r, "if (tick.halted)\n", "if (!tick.halted)\n")),
            "registry reader stops asking decide_mount_call": dict(r=mutate_after(
                r, OFFLINE_READER, "decide_mount_call(", "decide_mount(")),
            "registry gate asked after the mount": dict(r=mutate(
                r, "const auto gate = yuzu::echo::decide_walk_gate(",
                   "(void)yuzu::shared::bounded_call_ex(kHiveMountBoundMs, [] { return 0; });\n"
                   "    const auto gate = yuzu::echo::decide_walk_gate(")),
            "registry opts out of the default hive-file guard": dict(r=mutate(
                r, "                  &report);\n               if (status",
                   "                  &report, &yuzu::win::kOfflineHiveFileUnguarded);\n"
                   "               if (status")),
            "registry gate closing is no longer logged": dict(r=mutate(
                r, "note_mount_gate(tick, gate);", "(void)gate;")),
            "registry catch handler allocates again": dict(r=mutate(
                r, "r = std::move(failed);", 'r = unreadable_hive(roots, true, "offline:exception");')),
            "registry fallback built inside the try": dict(r=mutate(
                r, 'OfflineHiveRead failed = unreadable_hive(roots, true, "offline:exception");',
                   "OfflineHiveRead failed;")),
            "registry root open drops the link flag": dict(r=mutate(
                r, "REG_OPTION_OPEN_LINK, KEY_READ | KEY_WOW64_64KEY, key.put()",
                   "0, KEY_READ | KEY_WOW64_64KEY, key.put()")),
            # the start-up sweep of leftover YUZU_HIVE_* mounts (UP-6)
            "sweep no longer starts pending": dict(r=mutate(
                r, "bool sweep_pending{true};", "bool sweep_pending{false};")),
            "sweep gate decision deleted": dict(r=mutate(
                r, "if (yuzu::echo::decide_walk_gate(pin_plugin_module(), g_mount_workers_in_flight.load()) !=\n"
                   "        yuzu::echo::WalkGate::open)\n        return;",
                   "if (false)\n        return;")),
            "sweep closed gate no longer leaves it pending": dict(r=mutate(
                r, "yuzu::echo::WalkGate::open)\n        return;\n    const auto bounded",
                   "yuzu::echo::WalkGate::open)\n        tick.sweep_pending = false;\n    const auto bounded")),
            "sweep unbounded": dict(r=mutate(
                r, "bounded_call_ex(kHiveMountBoundMs, [] {",
                   "bounded_call_ex(std::chrono::milliseconds{0}, [] {")),
            "sweep worker not counted in flight": dict(r=mutate(
                r, "const MountWorkerGuard in_flight; // counted until this closure really returns\n"
                   "        return yuzu::echo::sweep_leftover_hive_mounts();",
                   "return yuzu::echo::sweep_leftover_hive_mounts();")),
            "sweep cleared when it did not complete": dict(r=mutate(
                r, "if (bounded.status == yuzu::shared::BoundedCallStatus::Completed) {\n"
                   "        tick.sweep_pending = false;\n        return;\n    }",
                   "tick.sweep_pending = false;\n    if (bounded.status == yuzu::shared::BoundedCallStatus::Completed) {\n"
                   "        return;\n    }")),
            "sweep timeout no longer halts the tick": dict(r=mutate(
                r, "tick.halted = decision.halt_walk;\n    tick.halted_token = decision.attempted ? "
                   "\"skipped_after_timeout\"", "(void)decision;\n    tick.halted_token = decision.attempted ? "
                   "\"skipped_after_timeout\"")),
            "sweep reruns on a halted tick": dict(r=mutate(
                r, "if (!tick.sweep_pending || tick.halted)\n        return;",
                   "if (!tick.sweep_pending)\n        return;")),
            "offline reader runs the sweep after its halted check": dict(r=mutate(
                mutate(r, "    run_pending_hive_sweep(tick);\n    if (tick.halted)",
                          "    if (tick.halted)"),
                "    const auto gate = yuzu::echo::decide_walk_gate(",
                "    run_pending_hive_sweep(tick);\n    const auto gate = yuzu::echo::decide_walk_gate(")),
            "start no longer runs the sweep": dict(r=mutate(
                r, "run_pending_hive_sweep(*tick);", "(void)tick;")),
            "start runs the sweep after the session opens": dict(r=mutate_after(
                mutate(r, "        run_pending_hive_sweep(*tick);\n        if (const ULONG rc = etw->start();",
                          "        if (const ULONG rc = etw->start();"),
                "r.start = [etw, tick] {", "                         rc);\n    };",
                "                         rc);\n        run_pending_hive_sweep(*tick);\n    };")),
            "hook and start stop sharing one tick": dict(r=mutate(
                r, "r.read_offline_hive = [tick](", "r.read_offline_hive = [tick = std::make_shared<OfflineMountTick>()](")),
            "sweep lists HKU before it takes the lock": dict(r=mutate(
                r, '        const yuzu::agent::ScopedOfflineHiveLock offline_lock("echo_registry_sweep");\n'
                   "        stale = select_stale_hive_mounts(yuzu::win::enumerate_hku_subkeys(), prefix);\n",
                   "        stale = select_stale_hive_mounts(yuzu::win::enumerate_hku_subkeys(), prefix);\n"
                   '        const yuzu::agent::ScopedOfflineHiveLock offline_lock("echo_registry_sweep");\n')),
            "sweep unloads names it did not select": dict(r=mutate(
                r, "r = sweep_hive_mounts(stale, [](", "r = sweep_hive_mounts(yuzu::win::enumerate_hku_subkeys(), [](")),
            "sweep lists through Echo's own enumeration": dict(r=mutate(
                r, "select_stale_hive_mounts(yuzu::win::enumerate_hku_subkeys(), prefix)",
                   "select_stale_hive_mounts(enumerate_hku(), prefix)")),
            "sweep no longer enables SeRestorePrivilege": dict(r=mutate(
                r, 'const yuzu::win::PrivilegeScope restore_priv(L"SeRestorePrivilege");', "(void)0;")),
            "sweep worker narrows the prefix": dict(r=mutate(
                r, "return yuzu::echo::sweep_leftover_hive_mounts();",
                   'return yuzu::echo::sweep_leftover_hive_mounts("YUZU_HIVE_S-1-5-21-1");')),
            "sweep unloads without holding the privilege": dict(r=mutate(
                r, "if (restore_priv.ok()) {", "if (true) {")),
            "sweep forces the unload": dict(r=mutate(
                r, "return RegUnLoadKeyW(HKEY_USERS, yuzu::win::to_wide(name).c_str()) == ERROR_SUCCESS;",
                   "return NtUnloadKey2(name) == ERROR_SUCCESS;")),
        }
        for name, over in cases.items():
            with self.subTest(mutation=name):
                self.assertNotEqual(self.probe(**over), [], f"mutation not caught: {name}")


if __name__ == "__main__":
    unittest.main()
