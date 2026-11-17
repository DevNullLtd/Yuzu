#!/usr/bin/env python3
"""G01 static lexical gate: policy evaluation keeps applying the execute gate before it dispatches.

Policy evaluation applies the action approval requirement before dispatch. The decision is made in
`PolicyEvaluator::dispatch_instruction` (policy_evaluator.cpp) through `authorize_policy_dispatch`
(policy_dispatch.hpp), with the capability registry handed in at ONE place: the
`PolicyEvaluator::Deps` construction in server.cpp. Nothing exercises ServerImpl's wiring in a unit
test, and an evaluator built without a registry fails CLOSED (every dispatch is refused as
`unwired`), so a dropped line would stop every policy from running without any test noticing.
This gate pins the statements lexically.

Required statements (each is one requirement id below):
  * deps-registry       server.cpp wires `.capability_registry = &capability_registry_` into the
                        `PolicyEvaluator::Deps` it constructs;
  * deps-audit          the same Deps carries `.audit_store = audit_store_.get()` (the
                        `policy.dispatch` / `denied` rows);
  * registry-lifetime   the `capability_registry_` member is declared BEFORE `policy_evaluator_`,
                        so the registry outlives the evaluator that borrows it;
  * tile-figure         the home tile's `home::ComplianceFigure` is built with the fleet's `error`
                        and `blocked` counts (they count as failing);
  * single-dispatch     `d_.dispatch_fn(` is called from exactly ONE place in policy_evaluator.cpp,
                        so one refusal covers the check, the fix and the verify;
  * seam-first          `authorize_policy_dispatch(*d_.capability_registry, ...)` is called before
                        that dispatch, and the refusal returns before it;
  * unwired-closed      an evaluator with no registry is refused (`Unwired`), never allowed;
  * denial-recorded     the check, fix and verify callers each record a refused dispatch.

Robustness: comments are stripped with a literal-aware scanner, and all whitespace is removed before
matching, so line wrapping, re-indentation and comment text that mentions a token cannot satisfy or
break a check. Patterns anchor on distinctive tokens, never on line numbers.

Lexical only: it cannot see a relocation that keeps the tokens but changes control flow, or a
statement that sits in a branch that never runs (review-enforced). The companion
tests/test_policy_dispatch_wiring_lexical_selftest.py mutates each statement in memory and requires
this gate to name it, so a stale pattern fails loudly instead of passing vacuously.

Usage: python3 -I tests/test_policy_dispatch_wiring_lexical.py
"""
from __future__ import annotations

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_CPP = os.path.join("server", "core", "src", "server.cpp")
EVALUATOR_CPP = os.path.join("server", "core", "src", "policy_evaluator.cpp")
TAG = "test_policy_dispatch_wiring_lexical"
HINT = (" (this gate pins the G01 policy dispatch wiring; if the file was legitimately restructured "
        "or renamed, update tests/test_policy_dispatch_wiring_lexical.py and its selftest)")


def strip_comments(text: str) -> str:
    """Drop // and /* */ comments, leaving string, character and raw-string literals intact."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif two == "/*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        elif c == 'R' and text[i:i + 2] == 'R"':
            m = re.match(r'R"([^()\\ ]{0,16})\(', text[i:])
            if m:
                end = ")" + m.group(1) + '"'
                j = text.find(end, i + len(m.group(0)))
                j = n if j < 0 else j + len(end)
                out.append(text[i:j])
                i = j
            else:
                out.append(c)
                i += 1
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def squash(text: str) -> str:
    """Comments gone, every whitespace character removed."""
    return re.sub(r"\s+", "", strip_comments(text))


def deps_block(server: str) -> str | None:
    """The text of the `PolicyEvaluator::Deps{ ... }` initializer, or None."""
    k = server.find("PolicyEvaluator::Deps{")
    if k < 0:
        return None
    depth = 0
    start = server.find("{", k)
    for i in range(start, len(server)):
        if server[i] == "{":
            depth += 1
        elif server[i] == "}":
            depth -= 1
            if depth == 0:
                return server[start:i + 1]
    return None


def problems(sources: dict[str, str]) -> list[str]:
    """Return one message per requirement that is not met. Each starts with its requirement id."""
    out: list[str] = []
    server = squash(sources[SERVER_CPP])
    evaluator = squash(sources[EVALUATOR_CPP])

    block = deps_block(server)
    if block is None:
        out.append("deps-registry: no PolicyEvaluator::Deps{...} construction found in server.cpp")
        block = ""
    if ".capability_registry=&capability_registry_" not in block:
        out.append("deps-registry: the PolicyEvaluator::Deps in server.cpp does not carry "
                   ".capability_registry = &capability_registry_ (an unwired evaluator refuses "
                   "every dispatch)")
    if ".audit_store=audit_store_.get()" not in block:
        out.append("deps-audit: the PolicyEvaluator::Deps in server.cpp does not carry "
                   ".audit_store = audit_store_.get()")

    reg = server.find("CommandCapabilityRegistrycapability_registry_")
    ev = server.find("std::unique_ptr<PolicyEvaluator>policy_evaluator_;")
    if reg < 0 or ev < 0 or reg > ev:
        out.append("registry-lifetime: the capability_registry_ member must be declared before "
                   "policy_evaluator_ (it is borrowed by the evaluator)")

    fig = server.find("home::ComplianceFigure{")
    fig_end = server.find("}", fig) if fig >= 0 else -1
    figure = server[fig:fig_end] if fig >= 0 and fig_end > fig else ""
    if "fc->error" not in figure or "fc->blocked" not in figure:
        out.append("tile-figure: the home tile's ComplianceFigure is not built with fc->error and "
                   "fc->blocked (they count as failing)")

    calls = [m.start() for m in re.finditer(re.escape("d_.dispatch_fn("), evaluator)]
    if len(calls) != 1:
        out.append(f"single-dispatch: d_.dispatch_fn( is called {len(calls)} times in "
                   "policy_evaluator.cpp, expected exactly 1")
    seam = evaluator.find("authorize_policy_dispatch(*d_.capability_registry,")
    refused_return = evaluator.find("returnrefused;")
    if calls:
        if seam < 0 or seam > calls[0]:
            out.append("seam-first: authorize_policy_dispatch(*d_.capability_registry, ...) is not "
                       "called before d_.dispatch_fn(")
        if refused_return < 0 or refused_return > calls[0]:
            out.append("seam-first: a refused dispatch does not return before d_.dispatch_fn(")

    if "if(!d_.capability_registry){denial=PolicyDispatchDenial{PolicyDispatchDenialReason::Unwired}" \
            not in evaluator:
        out.append("unwired-closed: an evaluator with no capability_registry is not refused as Unwired")

    for phase in ("check", "fix", "verify"):
        if not re.search(r'record_denial\([A-Za-z_.>-]*policy_id,"%s"|record_denial\(p\.id,"%s"'
                         % (phase, phase), evaluator):
            out.append(f"denial-recorded: no record_denial(..., \"{phase}\", ...) call in "
                       "policy_evaluator.cpp")
    return out


def load() -> dict[str, str]:
    sources = {}
    for rel in (SERVER_CPP, EVALUATOR_CPP):
        with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
            sources[rel] = f.read()
    return sources


def main() -> int:
    found = problems(load())
    if found:
        for p in found:
            print(f"FAIL {TAG}: {p}{HINT}")
        return 1
    print(f"OK {TAG}: policy dispatch wiring is in place")
    return 0


if __name__ == "__main__":
    sys.exit(main())
