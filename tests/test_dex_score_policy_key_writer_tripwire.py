#!/usr/bin/env python3
"""#6086 tripwire: the DEX score policy has ONE store writer.

The policy is a single runtime-config document under the key `dex_score_policy`
(kDexScorePolicyKey, server/core/src/dex_score_policy_json.hpp). Every write must reach the
store through apply_dex_score_policy (dex_score_policy_writer.hpp), which validates, audits
first, and installs through the provider; the store-side binding of that path is
dex_score_policy_store_writer in server/core/src/dex_api.cpp. A second write path would
skip the If-Match precondition, the audit rows or the provider's commit-then-install order.

Three checks over server/core/src/*.{cpp,hpp}, comments removed:

  1. A store write call (compare_and_set, compare_and_remove, set, remove) whose argument text
     names kDexScorePolicyKey or the literal "dex_score_policy" is allowed only in dex_api.cpp,
     and dex_api.cpp must hold exactly one compare_and_set and one compare_and_remove of that
     key (so a rename or a removal fails this test instead of passing it vacuously).
  2. The literal "dex_score_policy" is spelled only in dex_score_policy_json.hpp (the constant),
     runtime_config_store.cpp (the allowed-key list) and body_cap_policy.hpp (a metric label for
     the route's body cap, not a store key). Any other file names the key through the constant.
  3. The server.cpp assembly that no unit test reaches (every route test injects its own deps):
     (a) `rest_api_v1_->set_dex_score_policy_writer(` is one active line and comes BEFORE
     `rest_api_v1_->register_routes(` (the deps are captured by value there, so a later call
     compiles, keeps every injected-deps rig green and leaves the three routes answering 503);
     (b) the setter sits under exactly `if (dex_score_policy_provider_) {` (the nearest `if (`
     above it), so the routes answer 503 exactly where there is no provider, that is no open
     runtime config store, and not wherever some other store is absent;
     (c) the provider is constructed under `if (runtime_config_store_ && runtime_config_store_->is_open())`
     in the scope that declares `dex_api`, ahead of the `if (guaranteed_state_store_) {` block
     (it depends only on the runtime config store, so nested inside that block the routes answer
     503 wherever the signals store is absent).

LIMITS. A lexical scan, not a proof: it cannot see a key held in a variable and passed to a
write call, a write through a helper that takes the key as a parameter, or a spelling built at
run time. It is a tripwire for the ordinary way a second writer gets added. Check 3 pins the
order and the scope of the wiring lines, not that the deps they hand over are the right ones; it
is the same shape as tests/test_tier_policy_wiring_lexical.py clause 5.
"""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "server" / "core" / "src"

WRITER_FILE = "dex_api.cpp"
SERVER_FILE = "server.cpp"
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


def wiring_problems(text):
    """Check 3: the server.cpp wiring of the writer deps and the provider; [] when clean."""
    lines = [ln.strip() for ln in strip_comments(text).split("\n") if ln.strip()]

    def at(prefix):
        return [i for i, ln in enumerate(lines) if ln.startswith(prefix)]

    setter = at("rest_api_v1_->set_dex_score_policy_writer(")
    register = at("rest_api_v1_->register_routes(")
    provider = at("dex_score_policy_provider_ = std::make_shared<DexScorePolicyProvider>(")
    decl = at("std::shared_ptr<yuzu::server::DexApi> dex_api;")
    out = []
    for name, found in (("set_dex_score_policy_writer", setter), ("register_routes", register),
                        ("provider construction", provider), ("dex_api declaration", decl)):
        if len(found) != 1:
            out.append(f"{SERVER_FILE}: expected exactly one active {name} line, found {len(found)}")
    if out:
        return out
    if setter[0] > register[0]:
        out.append("set_dex_score_policy_writer must be called BEFORE register_routes: the deps are "
                   "captured by value there, so a later call leaves all three routes answering 503")
    guard = next((ln for ln in reversed(lines[:setter[0]]) if ln.startswith("if (")), "")
    if guard != "if (dex_score_policy_provider_) {":
        out.append("the writer deps must be set under exactly `if (dex_score_policy_provider_) {`; "
                   "any other guard changes where the three routes answer 503")
    if lines[provider[0] - 1] != "if (runtime_config_store_ && runtime_config_store_->is_open())":
        out.append("the provider must be guarded by exactly `if (runtime_config_store_ && "
                   "runtime_config_store_->is_open())`; any other guard changes when the routes are 503")
    body = "\n".join(lines[provider[0]:decl[0]])
    if provider[0] > decl[0] or body.count("{") != body.count("}"):
        out.append("the provider must be constructed in the scope that declares dex_api, before it "
                   "(it depends only on the runtime config store, not on the signals store)")
    return out


GOOD_WIRING = """\
if (runtime_config_store_ && runtime_config_store_->is_open())
    dex_score_policy_provider_ = std::make_shared<DexScorePolicyProvider>(
        reader, []() -> std::int64_t { return 0; });
std::shared_ptr<yuzu::server::DexApi> dex_api;
if (guaranteed_state_store_) {
    dex_api = make_local_dex_api();
}
if (dex_score_policy_provider_) {
    rest_api_v1_->set_dex_score_policy_writer({});
}
rest_api_v1_->register_routes(*web_server_);
"""


def self_test():
    bad = "auto r = store.compare_and_set(std::string(kDexScorePolicyKey), e, c, a);"
    assert key_write_calls(bad) == ["compare_and_set"], "a key write must be seen"
    assert key_write_calls('rt->set("dex_score_policy", v, who);') == ["set"]
    assert key_write_calls("// store.compare_and_set(kDexScorePolicyKey, e, c, a)") == []
    assert key_write_calls("store.compare_and_set(std::string(kOtherKey), e, c, a);") == []
    assert key_write_calls("store.get(std::string(kDexScorePolicyKey));") == []
    assert literal_count('x = "dex_score_policy"; // "dex_score_policy"') == 1
    assert literal_count("/* \"dex_score_policy\" */") == 0
    assert wiring_problems(GOOD_WIRING) == [], "the reference wiring must pass"
    setter = "if (dex_score_policy_provider_) {\n    rest_api_v1_->set_dex_score_policy_writer({});\n}\n"
    register = "rest_api_v1_->register_routes(*web_server_);\n"
    assert setter + register in GOOD_WIRING
    late = GOOD_WIRING.replace(setter + register, register + setter)
    assert any("BEFORE register_routes" in p for p in wiring_problems(late)), "late setter"
    assert wiring_problems(GOOD_WIRING.replace("rest_api_v1_->set_dex_score_policy_writer",
                                               "// rest_api_v1_->set_dex_score_policy_writer")), \
        "commented-out setter"
    swapped = GOOD_WIRING.replace("if (dex_score_policy_provider_) {", "if (guaranteed_state_store_) {")
    assert any("if (dex_score_policy_provider_) {" in p for p in wiring_problems(swapped)), \
        "swapped setter guard"
    nested = """\
std::shared_ptr<yuzu::server::DexApi> dex_api;
if (guaranteed_state_store_) {
    if (runtime_config_store_ && runtime_config_store_->is_open())
        dex_score_policy_provider_ = std::make_shared<DexScorePolicyProvider>(reader, clock);
    dex_api = make_local_dex_api();
}
""" + setter + register
    assert any("scope that declares dex_api" in p for p in wiring_problems(nested)), "nested provider"


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
    server = SRC / SERVER_FILE
    problems += wiring_problems(server.read_text(encoding="utf-8", errors="replace"))
    if sorted(writer_calls) != ["compare_and_remove", "compare_and_set"]:
        problems.append(f"{WRITER_FILE}: expected exactly one compare_and_set and one "
                        f"compare_and_remove of the policy key, found {writer_calls}")
    if problems:
        print("FAIL:")
        print("\n".join(problems))
        return 1
    print(f"OK: the score policy key is written only in {WRITER_FILE}: {', '.join(writer_calls)}; "
          f"{SERVER_FILE} wires the writer deps before register_routes and the provider outside the "
          "signals-store block")
    return 0


if __name__ == "__main__":
    sys.exit(main())
