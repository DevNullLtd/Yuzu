#!/usr/bin/env python3
"""Self-test for test_reregistration_gate_wiring_lexical.py: delete each required statement from the
production text IN MEMORY and prove the gate names it (a gate that cannot fail proves nothing)."""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("gate", HERE / "test_reregistration_gate_wiring_lexical.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

texts = {k: gate.read(v) for k, v in gate.FILES.items()}
assert gate.run(texts) == [], "the unmutated sources must pass"

MUTATIONS = [
    ("server", "gateway_service_->set_agent_identity_hooks(hooks)", "wire hooks into the gateway service"),
    ("server", "agent_service_.set_agent_identity_hooks(hooks)", "wire hooks into the direct service"),
    ("server", "gateway_service_->set_reregistration_proof_mode(proof_mode)", "set the mode on the gateway"),
    ("server", "agent_service_.set_agent_identity_hooks(nullptr)", "clear the hooks at shutdown"),
    ("server", "rev.revocation_reason != kRevokeReasonReenrolled", "HIGH-2 reenrolled exemption"),
    ("direct", "apply_reregistration_gate(", "direct handler applies the gate"),
    ("gateway", "apply_reregistration_gate(", "gateway handler applies the gate"),
    ("direct", "if (!prior)", "direct absent-row gate"),
    ("gateway", "if (!prior)", "gateway absent-row gate"),
    ("gateway", "gateway_attested_peer_cert_pem(", "gateway reads the witnessed PEM"),
    ("main_cpp", "CLI::IsMember({\"off\", \"audit\", \"enforce\"})", "mode validated at parse time"),
    ("cfg", "agent_reregistration_proof{\"audit\"}", "default mode is audit"),
]
bad = 0
for key, needle, what in MUTATIONS:
    if needle not in texts[key]:
        print(f"SELFTEST SETUP ERROR: {needle!r} not found in {key}")
        bad += 1
        continue
    mutated = dict(texts)
    mutated[key] = texts[key].replace(needle, "/*deleted*/", 1)
    if not gate.run(mutated):
        print(f"SELFTEST FAIL: deleting `{what}` was not caught")
        bad += 1
# an extra direct-path jump (a handler-local bypass) must be caught too
mutated = dict(texts)
mutated["direct"] = texts["direct"].replace("goto enrolled;", "goto enrolled;\n goto enrolled;", 1)
if not gate.run(mutated):
    print("SELFTEST FAIL: a second `goto enrolled;` was not caught")
    bad += 1
if bad:
    sys.exit(1)
print("WP01 wiring tripwire self-test OK")
