#!/usr/bin/env python3
"""Best-effort lexical tripwire for the agent's stop/reconnect path (agents/core/src/agent.cpp):

  1. a command's stagger/delay sleep goes through `sleep_interruptible` (never a bare
     `std::this_thread::sleep_for(std::chrono::seconds(total_delay))`), so it ends within a slice of a
     reconnect or stop;
  2. the reconnect teardown sets `command_pool_closing_` BEFORE `thread_pool_.reset()` (an unset flag
     leaves queued staggered tasks sleeping through the pool destructor);
  3. `execute_command_task` checks `command_pool_closing()` before it starts a task, and a rejected,
     never-started command goes through `reject_unstarted_command` (claim released, REJECTED).

The behavioural proof of the slicing is tests/unit/test_interruptible_wait.cpp; this pins the wiring the
unit tests cannot see.

Usage: python3 -I tests/test_agent_stagger_stop_lexical.py
"""
import pathlib
import re
import sys

AGENT = pathlib.Path(__file__).resolve().parent.parent / "agents/core/src/agent.cpp"


def check(src):
    defects = []
    if re.search(r"std::this_thread::sleep_for\(\s*std::chrono::seconds\(\s*total_delay\s*\)\s*\)", src):
        defects.append("the stagger/delay sleep is a bare, uninterruptible sleep_for")
    if not re.search(r"sleep_interruptible\(\s*std::chrono::seconds\(\s*total_delay\s*\)\s*,\s*\[this\]\s*\{\s*return command_pool_closing\(\);", src):
        defects.append("the stagger/delay sleep does not use sleep_interruptible with command_pool_closing()")
    closing = [m.start() for m in re.finditer(r"command_pool_closing_\.store\(true", src)]
    resets = [m.start() for m in re.finditer(r"\n\s*thread_pool_\.reset\(\);", src)]
    # The reconnect teardown is the LAST reset in the connection loop (the stop path's own reset is
    # earlier in the file and is covered by stop_requested_ inside command_pool_closing()).
    if not closing:
        defects.append("command_pool_closing_ is never set before a pool reset")
    elif not any(0 < r - c < 400 for c in closing for r in resets):
        defects.append("command_pool_closing_.store(true) is not immediately before thread_pool_.reset()")
    body = re.search(r"void execute_command_task\([^)]*\)\s*\{(.*?)Stagger/delay", src, re.S)
    if not body or "command_pool_closing()" not in body.group(1) or "reject_unstarted_command" not in body.group(1):
        defects.append("execute_command_task does not reject an unstarted command when the pool is closing")
    rej = re.search(r"void reject_unstarted_command\(.*?\n    \}\n", src, re.S)
    if not rej or "release(cmd.command_id())" not in rej.group(0):
        defects.append("reject_unstarted_command does not release the dedup claim")
    return defects


def selftest(src):
    mutants = {
        "bare sleep": src.replace("if (!sleep_interruptible(std::chrono::seconds(total_delay),", "std::this_thread::sleep_for(std::chrono::seconds(total_delay)); if (!sleep_interruptible(std::chrono::seconds(0),", 1),
        "no closing flag set": src.replace("command_pool_closing_.store(true, std::memory_order_release);", "", 1),
        "no start check": src.replace("        if (command_pool_closing()) {\n            reject_unstarted_command(stream, cmd, claimed_here);\n            return;\n        }", "", 1),
    }
    for name, mutated in mutants.items():
        if mutated == src:
            print(f"SELFTEST SETUP FAILED: '{name}' did not change the source")
            return 1
        if not check(mutated):
            print(f"SELFTEST FAILED: mutation '{name}' was not caught")
            return 1
    return 0


def main():
    src = AGENT.read_text(encoding="utf-8")
    defects = check(src)
    for d in defects:
        print("FAIL:", d)
    if defects:
        return 1
    if selftest(src):
        return 1
    print("agent stagger/stop wiring lexical gate OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
