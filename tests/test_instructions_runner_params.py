#!/usr/bin/env python3
"""test_instructions_runner_params.py - the /test --instructions runner must synthesise
parameter values the server accepts.

The server rejects a string parameter that does not match its definition's
`validation.pattern` (HTTP 400; RE2 PartialMatch, i.e. an unanchored search, which is what
`re.search` does here). Before the runner honoured the pattern, the Instructions gate failed
on device.agent_actions.set_log_level, device.discovery.scan_subnet and
crossplatform.tar.configure. This sweeps EVERY pattern-constrained parameter of every
InstructionDefinition the gate dispatches, so a new pattern the runner cannot satisfy fails
here instead of in a 15-minute live-stack run, and pins the precedence rules around it.

Runnable standalone: `python3 tests/test_instructions_runner_params.py`. Hermetic: reads
content/definitions/ only (needs PyYAML, as the runner does). No subprocess, network or clock.
"""
import ipaddress
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "test"))
import instructions_runner as ir  # noqa: E402


def synth(schema):
    return ir.synthesise_params({"required": ["p"], "properties": {"p": schema}})["p"]


def string_schema(pattern, **extra):
    return {"type": "string", "validation": {"pattern": pattern}, **extra}


class PatternSynthesis(unittest.TestCase):
    def test_every_definition_pattern_is_satisfied(self):
        swept = 0
        for d in ir.load_definitions(ROOT / "content" / "definitions", {}):
            for name, schema in (d.parameters.get("properties") or {}).items():
                pattern = ((schema or {}).get("validation") or {}).get("pattern")
                if not pattern or schema.get("type", "string") != "string":
                    continue
                swept += 1
                with self.subTest(definition=d.id, parameter=name):
                    got = ir._value_for_property(name, schema)
                    self.assertIsNotNone(re.search(pattern, got), f"{got!r} does not match {pattern!r}")
        self.assertGreater(swept, 0, "no pattern-constrained parameters found: the sweep is vacuous")

    def test_scan_subnet_never_targets_a_routable_network(self):
        d = next(d for d in ir.load_definitions(ROOT / "content" / "definitions", {})
                 if d.id == "device.discovery.scan_subnet")
        got = ir._value_for_property("subnet", d.parameters["properties"]["subnet"])
        self.assertTrue(ipaddress.ip_network(got).subnet_of(ipaddress.ip_network("192.0.2.0/24")), got)

    def test_name_based_default_is_kept_when_it_matches(self):
        # "host" synthesises 127.0.0.1; the digit fallback "10" would also satisfy this pattern.
        self.assertEqual(ir._value_for_property("host", string_schema(r"^[a-zA-Z0-9.:\-]+$")), "127.0.0.1")

    def test_no_pattern_leaves_the_name_based_default(self):
        self.assertEqual(synth({"type": "string"}), ir._synth_string("p", {}))

    def test_explicit_default_and_enum_win_over_the_pattern(self):
        # "10" (a fallback) would satisfy this pattern, so fitting a default or enum would show.
        self.assertEqual(synth(string_schema("^[0-9]+$", default="keep")), "keep")
        self.assertEqual(synth(string_schema("^[0-9]+$", enum=["a", "b"])), "a")

    def test_unsatisfiable_or_invalid_pattern_leaves_the_value_for_the_server(self):
        self.assertEqual(synth(string_schema("^zzz$")), ir._synth_string("p", {}))
        self.assertEqual(synth(string_schema("[")), ir._synth_string("p", {}))


if __name__ == "__main__":
    unittest.main()
