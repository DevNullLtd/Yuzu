#!/usr/bin/env python3
"""#2146 static lexical gate pinning the `processes` live-read retry hint to the processes plugin's action budget.

`kLiveReadProcessesTimeoutRetryMs` (server/core/src/mcp_retry.hpp) is the `retry_after_ms` a live
read of kind `processes` answers when it times out. It must equal the plugin's own action budget
(`kActionBudget` in agents/plugins/processes/src/processes_plugin.cpp): a retry sooner than that
can land inside the first run's hashing and start a second one on the same device. The plugin is a
separate DSO, so no static_assert can link the two numbers; this gate reads both sources.

A pattern that stops matching fails loudly, so a rename or reformat cannot pass vacuously.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "agents/plugins/processes/src/processes_plugin.cpp"
HINT = ROOT / "server/core/src/mcp_retry.hpp"


def problems(plugin_text: str, hint_text: str) -> list[str]:
    out = []
    budget = re.search(r"kActionBudget\s*=\s*std::chrono::seconds\(\s*(\d+)\s*\)", plugin_text)
    hint = re.search(
        r"kLiveReadProcessesTimeoutRetryMs\s*=\s*(\d+)\s*;", hint_text)
    if not budget:
        out.append("kActionBudget = std::chrono::seconds(N) no longer matches in processes_plugin.cpp")
    if not hint:
        out.append("kLiveReadProcessesTimeoutRetryMs = N no longer matches in mcp_retry.hpp")
    if budget and hint and int(budget.group(1)) * 1000 != int(hint.group(1)):
        out.append(
            f"kLiveReadProcessesTimeoutRetryMs ({hint.group(1)} ms) != kActionBudget "
            f"({budget.group(1)} s)")
    return out


def self_test() -> list[str]:
    good_p = "constexpr auto kActionBudget = std::chrono::seconds(120);"
    good_h = "inline constexpr std::int64_t kLiveReadProcessesTimeoutRetryMs = 120000;"
    errs = []
    if problems(good_p, good_h):
        errs.append("self-test: a matching pair was reported")
    if not problems(good_p, good_h.replace("120000", "3000")):
        errs.append("self-test: a mismatched hint was not reported")
    if not problems(good_p.replace("kActionBudget", "kBudget"), good_h):
        errs.append("self-test: a stale plugin pattern passed vacuously")
    if not problems(good_p, good_h.replace("kLiveReadProcessesTimeoutRetryMs", "kRenamed")):
        errs.append("self-test: a stale hint pattern passed vacuously")
    return errs


def main() -> int:
    errs = self_test() + problems(PLUGIN.read_text(encoding="utf-8"), HINT.read_text(encoding="utf-8"))
    for e in errs:
        print(f"FAIL: {e}", file=sys.stderr)
    if not errs:
        print("live retry budget lexical gate: OK")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
