#!/usr/bin/env python3
"""Self-test for tests/test_policy_dispatch_wiring_lexical.py.

Runs the gate on the real sources (it must pass), then mutates each required statement in memory
and requires the gate to name the matching requirement id, so a stale pattern fails loudly instead
of passing vacuously. Comment text that mentions a token must not satisfy a check either.

Usage: python3 -I tests/test_policy_dispatch_wiring_lexical_selftest.py
"""
from __future__ import annotations

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "gate", os.path.join(HERE, "test_policy_dispatch_wiring_lexical.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

S, E = gate.SERVER_CPP, gate.EVALUATOR_CPP
failures: list[str] = []


def mutate(sources, path, old, new, count=1):
    text = sources[path]
    if text.count(old) < 1:
        failures.append(f"mutation anchor not found in {path}: {old!r}")
        return None
    out = dict(sources)
    out[path] = text.replace(old, new, count)
    return out


def expect(name, mutated, req_id):
    if mutated is None:
        return
    found = gate.problems(mutated)
    if not any(p.startswith(req_id + ":") for p in found):
        failures.append(f"{name}: expected a '{req_id}' problem, got {found}")


real = gate.load()
base = gate.problems(real)
if base:
    failures.append(f"the gate does not pass on the real sources: {base}")

# Another engine's Deps in server.cpp also carries `.capability_registry`, so anchor on the
# comment that only the PolicyEvaluator's block has.
POLICY_ANCHOR = "outlives the evaluator.\n            .capability_registry = &capability_registry_,"
expect("drop the registry from Deps",
       mutate(real, S, POLICY_ANCHOR, "outlives the evaluator.\n"), "deps-registry")
expect("drop the audit store from Deps",
       mutate(real, S, ".audit_store = audit_store_.get(),\n        });\n        policy_eval_thread_",
              "\n        });\n        policy_eval_thread_"), "deps-audit")
expect("comment mentioning the registry does not satisfy it",
       mutate(real, S, POLICY_ANCHOR,
              "outlives the evaluator.\n            // .capability_registry = &capability_registry_,"),
       "deps-registry")
expect("registry declared after the evaluator",
       mutate(mutate(real, S,
                     "yuzu::server::CommandCapabilityRegistry capability_registry_{YUZU_ALL_CAPABILITY_FRAGMENTS};",
                     "int capability_registry_placeholder_;"),
              S, "std::unique_ptr<PolicyEvaluator> policy_evaluator_;",
              "std::unique_ptr<PolicyEvaluator> policy_evaluator_;\n"
              "    yuzu::server::CommandCapabilityRegistry capability_registry_{YUZU_ALL_CAPABILITY_FRAGMENTS};"),
       "registry-lifetime")
expect("tile figure without blocked",
       mutate(real, S, "fc->compliance_pct, fc->error, fc->blocked};", "fc->compliance_pct, fc->error};"),
       "tile-figure")
expect("a second dispatch site",
       mutate(real, E, "auto outcome = d_.dispatch_fn(",
              "auto extra = d_.dispatch_fn(def.plugin, def.action, targets, \"\", parameters, \"x\");\n"
              "    auto outcome = d_.dispatch_fn("), "single-dispatch")
expect("the seam call removed",
       mutate(real, E, "authorize_policy_dispatch(*d_.capability_registry,",
              "classify_only(*d_.capability_registry,"), "seam-first")
expect("the refusal no longer returns",
       mutate(real, E, "return refused;", "(void)refused;"), "seam-first")
expect("the unwired arm removed",
       mutate(real, E, "denial = PolicyDispatchDenial{PolicyDispatchDenialReason::Unwired};",
              "denial = std::nullopt;"), "unwired-closed")
expect("the verify caller no longer records",
       mutate(real, E, 'record_denial(f.policy_id, "verify",', 'forget_denial(f.policy_id, "verify",'),
       "denial-recorded")
expect("the fix caller no longer records",
       mutate(real, E, 'record_denial_status(policy_id, "fix",',
              'forget_denial(policy_id, "fix",'),
       "denial-recorded")
expect("the fix caller no longer writes its audit row",
       mutate(real, E, "emit_denial_audit(pending);", "(void)pending;"),
       "denial-audit-emitted")
expect("the check caller no longer records",
       mutate(real, E, 'record_denial(p.id, "check",', 'forget_denial(p.id, "check",'),
       "denial-recorded")

if failures:
    for f in failures:
        print(f"FAIL test_policy_dispatch_wiring_lexical_selftest: {f}")
    sys.exit(1)
print("OK test_policy_dispatch_wiring_lexical_selftest: every requirement is detected when removed")
