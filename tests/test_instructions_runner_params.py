#!/usr/bin/env python3
"""Unit check for scripts/test/instructions_runner.py parameter synthesis.

The server rejects a string parameter that does not match its definition's
`validation.pattern` (HTTP 400), so the runner must synthesise a value that does.
The three patterns below are copied verbatim from content/definitions/ (the
guard at the bottom fails if a definition's pattern drifts from them), and they
are the ones the /test Instructions gate failed on before the runner honoured
`validation.pattern`. Hermetic: imports the runner, starts no server.

Run: python3 tests/test_instructions_runner_params.py
"""
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("instructions_runner", ROOT / "scripts/test/instructions_runner.py")
runner = importlib.util.module_from_spec(spec)
sys.modules["instructions_runner"] = runner
spec.loader.exec_module(runner)

# (definition file, parameter, verbatim pattern)
CASES = [
    ("agent_actions.yaml", "level", r"^(?i:trace|debug|info|warn|warning|err|error|critical|off)$"),
    ("discovery.yaml", "subnet", r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$"),
    ("tar.yaml", "retention_days", r"^[0-9]+$"),
]

failures = []


def check(ok, msg):
    if not ok:
        failures.append(msg)


for fname, param, pattern in CASES:
    src = (ROOT / "content/definitions" / fname).read_text()
    # YAML double-quoted scalars escape the backslash; compare the unescaped form.
    check(pattern in src.replace("\\\\", "\\"), f"{fname}: pattern for '{param}' drifted from the test fixture")
    got = runner.synthesise_params(
        {"required": [param], "properties": {param: {"type": "string", "validation": {"pattern": pattern}}}}
    )[param]
    check(re.search(pattern, got) is not None, f"{param}: synthesised {got!r} does not match {pattern!r}")

# Behaviour that must not change: no pattern -> the name-based default; an explicit
# default and an enum still win; an unsatisfiable pattern keeps the original value
# so the server, not the runner, reports the mismatch.
check(runner.synthesise_params({"required": ["path"], "properties": {"path": {"type": "string"}}})["path"]
      == runner._synth_string("path", {}), "no-pattern default changed")
check(runner.synthesise_params({"required": ["m"], "properties": {"m": {
    "type": "string", "default": "keep", "validation": {"pattern": "^zzz$"}}}})["m"] == "keep",
    "explicit default must win over pattern fitting")
check(runner.synthesise_params({"required": ["e"], "properties": {"e": {
    "type": "string", "enum": ["a", "b"], "validation": {"pattern": "^zzz$"}}}})["e"] == "a",
    "enum must win over pattern fitting")
check(runner.synthesise_params({"required": ["u"], "properties": {"u": {
    "type": "string", "validation": {"pattern": "^zzz$"}}}})["u"] == runner._synth_string("u", {}),
    "unsatisfiable pattern must leave the original value")
check(runner.synthesise_params({"required": ["b"], "properties": {"b": {
    "type": "string", "validation": {"pattern": "["}}}})["b"] == runner._synth_string("b", {}),
    "invalid pattern must leave the original value")

if failures:
    print("FAIL:\n  " + "\n  ".join(failures))
    sys.exit(1)
print("instructions_runner params: OK")
