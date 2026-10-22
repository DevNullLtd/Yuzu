#!/usr/bin/env python3
"""Static lexical gate over TAR's bounded hive-mount call site (related issue #5291, PR #6311).

enum_registry_outbound_history (agents/plugins/tar/src/tar_mapdrive_collector.cpp, Windows only)
abandons a mount thread that outlives its bound; that thread keeps running TAR code and nothing
joins it. The only thing between it and an unmapped module is the pin taken on the timeout, and
the Windows bodies cannot run in the unit suites (the decision policy itself is unit-tested in
test_tar_mapdrive.cpp), so this pins the wiring lexically. Invariants:

  1. pin_plugin_module pins by address: GET_MODULE_HANDLE_EX_FLAG_PIN | ..._FROM_ADDRESS, with
     its own address as the module hint.
  2. The non-Completed branch asks decide_mount_call, calls pin_plugin_module() when told to
     (`decision.pin_module`), and stops the walk (`mounts_halted = decision.halt_walk`).
  3. A halted walk records the remaining profiles as not attempted (`attempted = false`) and
     `continue`s, BEFORE the next bounded_call_ex.
  4. A MountPoints2 child-open failure reaches note_failure(sk_rc); a clean cap-cut read is
     labelled "row_cap".
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

    pin = body_of(c, "void pin_plugin_module() noexcept")
    if pin is None:
        out.append("pin_plugin_module() is missing")
    else:
        for tok in ("GET_MODULE_HANDLE_EX_FLAG_PIN", "GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS",
                    "&pin_plugin_module)"):
            if tok not in pin:
                out.append(f"pin_plugin_module() no longer contains {tok}")

    walk = body_of(c, "void enum_registry_outbound_history(")
    if walk is None:
        out.append("enum_registry_outbound_history() is missing")
    else:
        if "decide_mount_call(" not in walk:
            out.append("the walk no longer asks decide_mount_call")
        if not re.search(r"if \(decision\.pin_module\) pin_plugin_module\(\);", walk):
            out.append("the timeout branch no longer pins the module on decision.pin_module")
        if not re.search(r"mounts_halted = decision\.halt_walk;", walk):
            out.append("the timeout branch no longer halts the walk")
        halted = re.search(r"if \(mounts_halted\) \{(.*?)\bcontinue;", walk)
        mount = walk.find("bounded_call_ex(")
        if not halted or mount < 0 or halted.start() > mount:
            out.append("the halted-walk block must come, and continue, before the next "
                       "bounded_call_ex")
        elif "attempted = false" not in halted.group(1):
            out.append("the halted-walk block must record the profile as attempted = false")
        if '"row_cap"' not in walk:
            out.append('a clean cap-cut read is no longer labelled "row_cap"')

    if not re.search(r"const LONG sk_rc = RegOpenKeyExW\(mp\.h, sub, 0, KEY_READ, &sk\.h\);"
                     r".*?else note_failure\(sk_rc\);", c):
        out.append("a MountPoints2 child-open failure no longer reaches note_failure")

    if not re.search(r"typed\.empty\(\) \|\| db_->insert_mapdrive_events\( ?typed, std::nullopt, "
                     r"/\*skip_known_historical=\*/true\)", p):
        out.append("the first-pass insert no longer passes skip_known_historical=true")
    if "dropped from the pending set" not in p:
        out.append("a vanished pending SID is no longer logged")

    raw_banner = collector_src
    if re.search(r"see dism_bounded_call\.hpp/power_health_plugin\.cpp", raw_banner):
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
            "pin call deleted": (mutate(c, "pin_plugin_module();\n", "\n"), p),
            "pin call commented out": (
                mutate(c, "if (decision.pin_module)\n                pin_plugin_module();",
                       "// if (decision.pin_module) pin_plugin_module();"), p),
            "pin flag dropped": (mutate(c, "GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | "
                                           "GET_MODULE_HANDLE_EX_FLAG_PIN",
                                        "GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS"), p),
            "halt assignment dropped": (mutate(c, "mounts_halted = decision.halt_walk;",
                                               "(void)decision;"), p),
            "halted block loses attempted=false": (
                mutate(c, "skipped.attempted = false;", "skipped.attempted = true;"), p),
            "halted block moved after the mount": (
                mutate(mutate(c, "if (mounts_halted) {", "if (false) {"),
                       "auto bounded = yuzu::shared::bounded_call_ex(",
                       "if (mounts_halted) { continue; }\n        auto bounded = "
                       "yuzu::shared::bounded_call_ex("), p),
            "row_cap label dropped": (mutate(c, '"row_cap"', '"ok"'), p),
            "MountPoints2 note_failure dropped": (mutate(c, "note_failure(sk_rc);", ";"), p),
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
