#!/usr/bin/env python3
"""#6086 tripwire: the DEX score policy has ONE store writer.

The policy is a single runtime-config document under the key `dex_score_policy`
(kDexScorePolicyKey, server/core/src/dex_score_policy_json.hpp). Every write must reach the
store through apply_dex_score_policy (dex_score_policy_writer.hpp), which validates, audits
first, and installs through the provider; the store-side binding of that path is
dex_score_policy_store_writer in server/core/src/dex_api.cpp. A second write path would
skip the If-Match precondition, the audit rows or the provider's commit-then-install order.

Two checks over server/core/src/*.{cpp,hpp}, comments removed:

  1. A store write call (compare_and_set, compare_and_remove, set, remove) whose argument text
     names kDexScorePolicyKey or the literal "dex_score_policy" is allowed only in dex_api.cpp,
     and dex_api.cpp must hold exactly one compare_and_set and one compare_and_remove of that
     key (so a rename or a removal fails this test instead of passing it vacuously).
  2. The literal "dex_score_policy" is spelled only in dex_score_policy_json.hpp (the constant),
     runtime_config_store.cpp (the allowed-key list) and body_cap_policy.hpp (a metric label for
     the route's body cap, not a store key). Any other file names the key through the constant.

LIMITS. A lexical scan, not a proof: it cannot see a key held in a variable and passed to a
write call, a write through a helper that takes the key as a parameter, or a spelling built at
run time. It is a tripwire for the ordinary way a second writer gets added.
"""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "server" / "core" / "src"

WRITER_FILE = "dex_api.cpp"
LITERAL_FILES = {"dex_score_policy_json.hpp", "runtime_config_store.cpp", "body_cap_policy.hpp"}

WRITE_CALL = re.compile(r"\b(compare_and_set|compare_and_remove|set|remove)\s*\(")
KEY_NAMED = re.compile(r'kDexScorePolicyKey|"dex_score_policy"')
LITERAL = re.compile(r'"dex_score_policy"')
# Strings are matched first so a `//` inside one is not a comment.
TOKEN = re.compile(r'"(?:\\.|[^"\\\n])*"|//[^\n]*|/\*.*?\*/', re.S)


def strip_comments(text):
    return TOKEN.sub(lambda m: m.group(0) if m.group(0).startswith('"') else " ", text)


def key_write_calls(text):
    """Names of the store write calls in `text` whose arguments name the policy key."""
    text = strip_comments(text)
    found = []
    for m in WRITE_CALL.finditer(text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            i += 1
        if KEY_NAMED.search(text[m.end():i]):
            found.append(m.group(1))
    return found


def literal_count(text):
    return len(LITERAL.findall(strip_comments(text)))


def self_test():
    bad = "auto r = store.compare_and_set(std::string(kDexScorePolicyKey), e, c, a);"
    assert key_write_calls(bad) == ["compare_and_set"], "a key write must be seen"
    assert key_write_calls('rt->set("dex_score_policy", v, who);') == ["set"]
    assert key_write_calls("// store.compare_and_set(kDexScorePolicyKey, e, c, a)") == []
    assert key_write_calls("store.compare_and_set(std::string(kOtherKey), e, c, a);") == []
    assert key_write_calls("store.get(std::string(kDexScorePolicyKey));") == []
    assert literal_count('x = "dex_score_policy"; // "dex_score_policy"') == 1
    assert literal_count("/* \"dex_score_policy\" */") == 0


def main():
    self_test()
    problems = []
    writer_calls = []
    for path in sorted(SRC.glob("*.[ch]pp")):
        text = path.read_text(encoding="utf-8", errors="replace")
        calls = key_write_calls(text)
        if path.name == WRITER_FILE:
            writer_calls = calls
        elif calls:
            problems.append(f"{path.name}: store write of the score policy key ({', '.join(calls)}); "
                            f"only {WRITER_FILE} may write it, via apply_dex_score_policy")
        if path.name not in LITERAL_FILES and literal_count(text):
            problems.append(f'{path.name}: spells "dex_score_policy"; use kDexScorePolicyKey')
    if sorted(writer_calls) != ["compare_and_remove", "compare_and_set"]:
        problems.append(f"{WRITER_FILE}: expected exactly one compare_and_set and one "
                        f"compare_and_remove of the policy key, found {writer_calls}")
    if problems:
        print("FAIL:")
        print("\n".join(problems))
        return 1
    print(f"OK: the score policy key is written only in {WRITER_FILE}: {', '.join(writer_calls)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
