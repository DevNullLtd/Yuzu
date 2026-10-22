#!/usr/bin/env python3
"""Lexical gate for TAR's bounded hive-mount call site (related issue #5291, PR #6311 review).

enum_registry_outbound_history (agents/plugins/tar/src/tar_mapdrive_collector.cpp, Windows only)
abandons a mount thread that outlives its bound; that thread keeps running TAR code, and nothing
joins it. The only thing standing between it and an unmapped module is the pin taken on the first
timeout, and the Windows body cannot run in the unit suites, so this pins the shape of the wiring:

  1. pin_plugin_module pins by address (GET_MODULE_HANDLE_EX_FLAG_PIN | ..._FROM_ADDRESS);
  2. the non-Completed branch asks decide_mount_call, pins when told to, and stops the walk;
  3. a halted walk records the remaining profiles as not attempted, before any further mount;
  4. the banner no longer cites dism_bounded_call.hpp as the pattern it follows (that header keeps
     its work in agent-core, which is the opposite stance).

Source text only; no build needed.
"""
import pathlib
import re
import sys
import unittest

SRC = pathlib.Path(__file__).resolve().parent.parent / "agents/plugins/tar/src/tar_mapdrive_collector.cpp"


def body_of(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace : i + 1]
    raise AssertionError("unbalanced braces after " + signature)


class MapdrivePinWiring(unittest.TestCase):
    text = SRC.read_text(encoding="utf-8")

    def test_pin_is_by_address(self):
        body = body_of(self.text, "void pin_plugin_module() noexcept")
        self.assertIn("GET_MODULE_HANDLE_EX_FLAG_PIN", body)
        self.assertIn("GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS", body)
        self.assertIn("&pin_plugin_module)", body)

    def test_timeout_branch_pins_and_halts(self):
        walk = body_of(self.text, "void enum_registry_outbound_history(")
        self.assertRegex(walk, r"decide_mount_call\(")
        self.assertRegex(walk, r"if \(decision\.pin_module\)\s*pin_plugin_module\(\);")
        self.assertRegex(walk, r"mounts_halted\s*=\s*decision\.halt_walk;")

    def test_halted_walk_records_not_attempted_before_mounting(self):
        walk = body_of(self.text, "void enum_registry_outbound_history(")
        halted = walk.index("if (mounts_halted)")
        mount = walk.index("bounded_call_ex(")
        self.assertLess(halted, mount, "the halted check must come before the next mount")
        block = walk[halted:mount]
        self.assertIn("attempted = false", block)

    def test_banner_states_the_unload_stance(self):
        self.assertNotRegex(
            self.text,
            r"see dism_bounded_call\.hpp/power_health_plugin\.cpp\s*//\s*for the established pattern",
        )
        self.assertIn("PINNED", self.text)


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=0).result.wasSuccessful() is not True)
