#!/usr/bin/env python3
"""Static lexical gate over TAR's bounded hive-mount call site (related issue #5291, PR #6311).

enum_registry_outbound_history (agents/plugins/tar/src/tar_mapdrive_collector.cpp, Windows only)
abandons a mount thread that outlives its bound; that thread keeps running TAR code and nothing
joins it. The only thing between it and an unmapped module is the pin taken on the timeout, and
the Windows bodies cannot run in the unit suites (the decision policy itself is unit-tested in
test_tar_mapdrive.cpp), so this pins the wiring lexically. Invariants:

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
  5. tar_plugin.cpp's first-pass insert passes skip_known_historical=true, and a vanished
     pending SID is logged.
  6. The banner no longer cites dism_bounded_call.hpp as the pattern it follows (that header
     keeps its work in agent-core, which is never unloaded: the opposite stance).

Robustness: `//` comments are stripped and whitespace is collapsed before matching, so a
commented-out call cannot satisfy a check. Lexical only: it cannot see a relocation that keeps
the tokens but changes control flow (review-enforced). The self-test applies in-memory
mutations and requires problems() to be non-empty on each; a mutation whose pattern no longer
matches the source fails loudly (stale pattern) rather than passing vacuously.

Usage: python3 tests/test_tar_mapdrive_pin_lexical.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COLLECTOR = ROOT / "agents" / "plugins" / "tar" / "src" / "tar_mapdrive_collector.cpp"
PLUGIN = ROOT / "agents" / "plugins" / "tar" / "src" / "tar_plugin.cpp"
HINT = (" (this gate pins the #5291 hive-mount wiring; if the collector was legitimately"
        " restructured, update tests/test_tar_mapdrive_pin_lexical.py)")


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


def problems(collector_src, plugin_src):
    out = []
    c = normalise(collector_src)
    p = normalise(plugin_src)

    pin = body_of(c, "bool pin_plugin_module() noexcept")
    if pin is None:
        out.append("pin_plugin_module() is missing")
    else:
        for tok in ("GET_MODULE_HANDLE_EX_FLAG_PIN", "GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS",
                    "&pin_plugin_module)"):
            if tok not in pin:
                out.append(f"pin_plugin_module() no longer contains {tok}")

    if not re.search(r"MountWorkerGuard\(\) noexcept \{ g_mount_workers_in_flight\.fetch_add\(1\);"
                     r" \} ~MountWorkerGuard\(\) \{ g_mount_workers_in_flight\.fetch_sub\(1\); \}",
                     c):
        out.append("MountWorkerGuard no longer counts the worker in and out")

    walk = body_of(c, "void enum_registry_outbound_history(")
    if walk is None:
        out.append("enum_registry_outbound_history() is missing")
    else:
        mount = walk.find("bounded_call_ex(")
        gate_at = walk.find("decide_walk_gate(pin_plugin_module(), g_mount_workers_in_flight.load())")
        if gate_at < 0 or mount < 0 or gate_at > mount:
            out.append("the walk must pin the module and ask decide_walk_gate (pin + in-flight "
                       "workers) before its first bounded_call_ex")
        if not re.search(r"mounts_halted = gate != yuzu::tar::WalkGate::open;", walk):
            out.append("a closed walk gate no longer halts the walk")
        if "decide_mount_call(" not in walk:
            out.append("the walk no longer asks decide_mount_call")
        if not re.search(r"mounts_halted = decision\.halt_walk;", walk):
            out.append("the timeout branch no longer halts the walk")
        if not re.search(r"outcome\.attempted = decision\.attempted;", walk):
            out.append("the timeout/rejection outcome no longer carries decision.attempted")
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

    if not re.search(r"typed\.empty\(\) \|\| db_->insert_mapdrive_events\( ?typed, std::nullopt, "
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


class TarMapdrivePinLexical(unittest.TestCase):
    def setUp(self):
        self.collector = COLLECTOR.read_text(encoding="utf-8")
        self.plugin = PLUGIN.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        self.assertEqual(problems(self.collector, self.plugin), [], HINT)

    def test_mutations_are_caught(self):
        c, p = self.collector, self.plugin
        cases = {
            "gate decision deleted": (mutate(
                c, "decide_walk_gate(pin_plugin_module(),\n"
                   "                                                   g_mount_workers_in_flight.load())",
                   "decide_walk_gate(true, 0)"), p),
            "gate decision commented out": (mutate(
                c, "const auto gate = yuzu::tar::decide_walk_gate(pin_plugin_module(),",
                   "const auto gate = yuzu::tar::WalkGate::open; // decide_walk_gate(pin_plugin_module(),"), p),
            "pin flag dropped": (mutate(c, "GET_MODULE_HANDLE_EX_FLAG_PIN", "0"), p),
            "closed gate no longer halts": (mutate(
                c, "bool mounts_halted = gate != yuzu::tar::WalkGate::open;",
                   "bool mounts_halted = false;"), p),
            "halt assignment dropped": (mutate(c, "mounts_halted = decision.halt_walk;",
                                               "(void)decision;"), p),
            "outcome attempted flag dropped": (mutate(
                c, "outcome.attempted = decision.attempted;", "(void)decision;"), p),
            "worker no longer counted in flight": (mutate(
                c, "const MountWorkerGuard in_flight;", "(void)0;"), p),
            "in-flight guard stops counting": (mutate(
                c, "g_mount_workers_in_flight.fetch_sub(1);", "(void)0;"), p),
            "halted block loses attempted=false": (
                mutate(c, "skipped.attempted = false;", "skipped.attempted = true;"), p),
            "halted block loses its append": (mutate(
                c, "h.profiles.push_back(std::move(skipped));", "(void)skipped;"), p),
            "halted block loses its cause token": (mutate(
                c, "skipped.token = halted_token;", 'skipped.token = "x";'), p),
            "halted block loses its continue": (mutate(
                mutate(c, "skipped.token = halted_token;", "skipped.token = halted_token;"),
                "h.profiles.push_back(std::move(skipped));\n            continue;",
                "h.profiles.push_back(std::move(skipped));"), p),
            "halted check moved past the mount": (mutate(
                mutate(c, "if (mounts_halted) {\n            // Not tried",
                          "if (false) {\n            // Not tried"),
                "auto bounded = yuzu::shared::bounded_call_ex(",
                "if (mounts_halted) { h.profiles.push_back(ProfileHiveOutcome{}); continue; }\n"
                "        auto bounded = yuzu::shared::bounded_call_ex("), p),
            "row_cap label dropped": (mutate(c, '"row_cap"', '"ok"'), p),
            "MountPoints2 failure no longer skips": (mutate(
                c, "note_failure(sk_rc);\n                        idx++;", "idx++;"), p),
            "dism reference restored": (
                c + "\n// plugin's first consumer; see dism_bounded_call.hpp/power_health_plugin.cpp\n",
                p),
            "first-pass dedupe dropped": (c, mutate_after(
                p, "typed.empty() ||", "/*skip_known_historical=*/true",
                "/*skip_known_historical=*/false")),
            "vanished-SID log dropped": (c, mutate(p, "dropped from the pending set", "dropped")),
        }
        for name, (cs, ps) in cases.items():
            with self.subTest(mutation=name):
                self.assertNotEqual(problems(cs, ps), [], f"mutation not caught: {name}")


if __name__ == "__main__":
    unittest.main()
