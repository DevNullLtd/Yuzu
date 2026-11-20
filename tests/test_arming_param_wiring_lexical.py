#!/usr/bin/env python3
"""Best-effort lexical tripwire: both production `arming_check` lambdas in
server/core/src/server.cpp (ScheduleRunner and CommandOutboxDelivery) must FORWARD their
`parameters` argument to `schedule_arming_permitted` (sg10). A lambda that drops it (or passes
`{}`) judges the row's default securable and silently re-opens the parameter-escalation bypass
(windows_updates.patch_connectivity + `targets` needs Infrastructure:Read). The behavioural proof is
tests/unit/server/test_arming_param_escalation.cpp; this pins the wiring the unit tests cannot see.

Usage: python3 -I tests/test_arming_param_wiring_lexical.py
"""
import pathlib
import re
import sys

SERVER = pathlib.Path(__file__).resolve().parent.parent / "server/core/src/server.cpp"

LAMBDA = re.compile(r"\.arming_check\s*=\s*\[this\]\s*\(([^)]*)\)\s*->\s*bool\s*\{(.*?)\n\s*\}[,;]", re.S)
CALL = re.compile(r"schedule_arming_permitted\s*\(([^;]*?)\)\s*;", re.S)


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def check(source):
    """Return a list of defects in `source` (empty = pinned)."""
    src = strip_comments(source)
    defects = []
    lambdas = LAMBDA.findall(src)
    if len(lambdas) != 2:
        defects.append(f"expected exactly 2 `.arming_check = [this](...) -> bool` lambdas, found {len(lambdas)}")
    for sig, body in lambdas:
        sig_n = " ".join(sig.split())
        if "const std::unordered_map<std::string, std::string>& parameters" not in sig_n:
            defects.append("an arming_check lambda does not take `parameters`")
        m = CALL.search(body)
        if not m:
            defects.append("an arming_check lambda does not call schedule_arming_permitted")
            continue
        args = [a.strip() for a in " ".join(m.group(1).split()).split(",")]
        if args[-1] != "parameters" or len(args) != 6:
            defects.append(f"schedule_arming_permitted is not called with the lambda's `parameters` last: {args}")
    n_calls = len(re.findall(r"schedule_arming_permitted\s*\(", src))
    if n_calls != 2:
        defects.append(f"expected exactly 2 production calls of schedule_arming_permitted, found {n_calls}")
    return defects


SCHEDULE_DEPS = re.compile(r"register_schedule_routes\(\s*inline_sink,\s*yuzu::server::schedule::Deps\{(.*?)\}\s*\);", re.S)
PRESEED = re.compile(
    r'for \(const char\* route : \{([^}]*)\}\)\s*metrics_\.counter\("yuzu_server_dispatch_target_rejected_total",\s*'
    r'\{\{"route", route\},\s*\{"reason", std::string\(yuzu::server::kReasonParamKeyInvalid\)\}\}\);', re.S)
ROUTES = {"command", "command_v1", "instruction_execute", "mcp", "schedule", "bundle", "policy_fragment"}


def check_param_key_wiring(source):
    """The `param_key_invalid` counter wiring: the schedule routes get the metrics registry and the
    seven counted route labels are pre-seeded (absent() alerting needs the series at zero). Searched in
    the raw text (the one-pass comment stripper above is not trustworthy across a whole file with
    string literals that hold comment markers); the patterns span no comment."""
    src = source
    defects = []
    m = SCHEDULE_DEPS.search(src)
    if not m:
        defects.append("the register_schedule_routes Deps block was not found")
    elif ".metrics = &metrics_" not in " ".join(m.group(1).split()):
        defects.append("the schedule routes Deps does not carry `.metrics = &metrics_` (param_key_invalid is never counted)")
    p = PRESEED.search(src)
    if not p:
        defects.append("the param_key_invalid pre-seed loop was not found")
    else:
        got = {r.strip().strip('"') for r in p.group(1).split(",") if r.strip()}
        if got != ROUTES:
            defects.append(f"the param_key_invalid pre-seed routes are {sorted(got)}, expected {sorted(ROUTES)}")
    return defects


def selftest(source):
    mutants = {
        "drops the forwarded argument": source.replace("plugin, action, parameters)", "plugin, action, {})", 1),
        "passes the argument from a first lambda only": source.replace("plugin, action, parameters);", "plugin, action);", 1),
    }
    mutants["schedule Deps without metrics"] = source.replace("                             .metrics = &metrics_,\n                         });\n\n        // #2542 PR-11: the 3-route legacy pre-v1 Responses API","                         });\n\n        // #2542 PR-11: the 3-route legacy pre-v1 Responses API",1)
    mutants["pre-seed drops a route"] = source.replace('"mcp", "schedule", "bundle",\n                                  "policy_fragment"}','"mcp", "bundle",\n                                  "policy_fragment"}',1)
    mutants["pre-seed drops mcp"] = source.replace('"instruction_execute", "mcp", "schedule"','"instruction_execute", "schedule"',1)
    for name, mutated in mutants.items():
        if mutated == source:
            print(f"SELFTEST SETUP FAILED: mutation '{name}' did not change the source")
            return 1
        if not (check(mutated) or check_param_key_wiring(mutated)):
            print(f"SELFTEST FAILED: mutation '{name}' was not caught")
            return 1
    return 0


def main():
    source = SERVER.read_text(encoding="utf-8")
    defects = check(source) + check_param_key_wiring(source)
    for d in defects:
        print("FAIL:", d)
    if defects:
        return 1
    if selftest(source):
        return 1
    print("arming parameter wiring lexical gate OK (2 lambdas forward `parameters`)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
