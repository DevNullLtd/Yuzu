#!/usr/bin/env python3
"""WP01 drift guard: the server's uniform re-registration refusal message is copied byte for byte into
the gateway (yuzu_gw_upstream.erl treats it as neutral for the circuit breaker), its eunit and the
gateway manual. If one copy drifts, the refusal counts as a breaker failure again and five refusals
open the breaker for every agent behind the gateway while every other test stays green.
Usage: python3 -I tests/test_reregistration_refusal_literal_lexical.py"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CPP = ROOT / "server/core/src/agent_reregistration_gate.hpp"
ERL = ROOT / "gateway/apps/yuzu_gw/src/yuzu_gw_upstream.erl"
EUNIT = ROOT / "gateway/apps/yuzu_gw/test/yuzu_gw_circuit_breaker_tests.erl"
DOC = ROOT / "docs/user-manual/gateway.md"


def main():
    cpp = re.search(r'kReregistrationRefusalPublicMessage\s*=\s*"([^"]+)"', CPP.read_text(encoding="utf-8"))
    erl = re.search(r'-define\(REREGISTRATION_REFUSAL_MESSAGE,\s*<<"([^"]+)">>\)', ERL.read_text(encoding="utf-8"))
    eu = re.search(r'-define\(REFUSAL,\s*<<"([^"]+)">>\)', EUNIT.read_text(encoding="utf-8"))
    problems = []
    if not (cpp and erl and eu):
        problems.append("a literal was not found (C++: %s, erlang: %s, eunit: %s)" % (bool(cpp), bool(erl), bool(eu)))
    else:
        want = cpp.group(1)
        for name, m in (("yuzu_gw_upstream.erl", erl), ("yuzu_gw_circuit_breaker_tests.erl", eu)):
            if m.group(1) != want:
                problems.append("%s differs from the C++ constant: %r != %r" % (name, m.group(1), want))
        if want not in DOC.read_text(encoding="utf-8"):
            problems.append("docs/user-manual/gateway.md does not quote the C++ message %r" % want)
    for p in problems:
        print("::error::" + p)
    if problems:
        return 1
    print("WP01 refusal-literal drift guard OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
