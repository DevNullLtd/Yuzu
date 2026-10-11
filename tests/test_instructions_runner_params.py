#!/usr/bin/env python3
"""Unit check for scripts/test/instructions_runner.py parameter synthesis.

The server rejects a string parameter that does not match its definition's
`validation.pattern` (HTTP 400), so the runner must synthesise a value that does.
Before the runner honoured `validation.pattern`, the /test Instructions gate failed on
device.agent_actions.set_log_level, device.discovery.scan_subnet and
crossplatform.tar.configure. This sweeps EVERY pattern-constrained parameter in
content/definitions/, so a new pattern the runner cannot satisfy fails here rather
than in a 15-minute live-stack run. Hermetic: imports the runner, starts no server.

Run: python3 tests/test_instructions_runner_params.py
"""
import importlib.util
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("instructions_runner", ROOT / "scripts/test/instructions_runner.py")
runner = importlib.util.module_from_spec(spec)
sys.modules["instructions_runner"] = runner
spec.loader.exec_module(runner)

failures = []


def check(ok, msg):
    if not ok:
        failures.append(msg)


swept = 0
for f in sorted((ROOT / "content/definitions").glob("*.yaml")):
    for doc in yaml.safe_load_all(f.read_text()):
        if not doc:
            continue
        props = ((doc.get("spec") or doc).get("parameters") or {}).get("properties") or {}
        for name, schema in props.items():
            pattern = ((schema or {}).get("validation") or {}).get("pattern")
            if not pattern or (schema or {}).get("type", "string") != "string":
                continue
            swept += 1
            got = runner._value_for_property(name, schema)
            check(re.search(pattern, got) is not None, f"{f.name}: {name}: {got!r} does not match {pattern!r}")
check(swept > 0, "no pattern-constrained parameters found: the sweep is vacuous")


def synth(schema):
    return runner.synthesise_params({"required": ["p"], "properties": {"p": schema}})["p"]


# No pattern: the name-based default is unchanged. An unsatisfiable or invalid pattern keeps
# the original value, so the server (not the runner) reports the mismatch.
check(synth({"type": "string"}) == runner._synth_string("p", {}), "no-pattern default changed")
check(synth({"type": "string", "validation": {"pattern": "^zzz$"}}) == runner._synth_string("p", {}),
      "unsatisfiable pattern must leave the original value")
check(synth({"type": "string", "validation": {"pattern": "["}}) == runner._synth_string("p", {}),
      "invalid pattern must leave the original value")

if failures:
    print("FAIL:\n  " + "\n  ".join(failures))
    sys.exit(1)
print(f"instructions_runner params: OK ({swept} pattern-constrained parameters satisfied)")
