#!/usr/bin/env python3
"""#5675 wiring pin for the agent-decommission cascade (lexical, no build required).

The cascade is assembled from live store pointers in ServerImpl::decommission_agent
(server/core/src/server.cpp). A store that is declared in AgentDecommissionStores and registered in
agent_decommission.cpp but never handed over there is silently `Skipped` for every operator
decommission: the route test injects its own `decommission_fn`, and the drift guard in
test_agent_decommission.cpp pins only the COUNT of registered stores, so every unit test stays green
while the Art.17 erasure quietly skips a store. Properties checked here:

  1. Every field of `AgentDecommissionStores` (agent_decommission.hpp) appears as a designated
     initializer `.<field> = <expr>.get()` inside ServerImpl::decommission_agent.
  2. `decommission_agent` does not initialise a field the struct no longer has.
  3. Every field is also read by the registration list in agent_decommission.cpp
     (`stores.<field>`), so a field added to the struct and forgotten there is reported too.

`//` and block comments are stripped before matching, so prose cannot satisfy a check.

WHAT THIS DOES NOT PROVE (a lexical gate is not a C++ parser): it does not see that the pointer
handed over belongs to the right store (it checks the `.get()` shape, not the member's type), a
conditional that nulls the pointer, or a second cascade built elsewhere; the runtime outcome per
store is pinned by the real-store fan-out in test_agent_decommission.cpp.

Usage: python3 tests/test_decommission_wiring_lexical.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "server" / "core" / "src"

# Opener of a C++ raw string, from the quote: "delim( with a delimiter of at most 16 characters.
_RAW_OPEN = re.compile(r'"([^ ()\\\t\v\f\n"]{0,16})\(')
# A struct member of the shape `Type* name{nullptr};`.
_FIELD = re.compile(r"\b\w+\s*\*\s*(\w+)\s*\{\s*nullptr\s*\}\s*;")
_MIN_FIELDS = 9  # the ninth store (guaranteed_state, #5675) joined an eight-store cascade


def strip_comments(text: str) -> str:
    """Remove // and /* */ comments, leaving string literals (ordinary and raw) untouched."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"' and i > 0 and text[i - 1] == "R":
            m = _RAW_OPEN.match(text, i)
            if m:
                close = ")" + m.group(1) + '"'
                k = text.find(close, m.end())
                end = n if k < 0 else k + len(close)
                out.append(text[i:end])
                i = end
                continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def balanced(text: str, open_idx: int):
    """Return the text from the brace at `open_idx` to its matching close, or None."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx : i + 1]
    return None


def struct_fields(hpp_code: str):
    k = hpp_code.find("struct AgentDecommissionStores")
    if k < 0:
        return None
    b = hpp_code.find("{", k)
    body = balanced(hpp_code, b) if b >= 0 else None
    if body is None:
        return None
    return _FIELD.findall(body)


def decommission_agent_body(server_code: str):
    k = server_code.find("DecommissionResult decommission_agent(std::string_view agent_id)")
    if k < 0:
        return None
    b = server_code.find("{", k)
    return balanced(server_code, b) if b >= 0 else None


def problems(files: dict) -> list:
    """`files` maps a basename under server/core/src to its raw text."""
    found = []
    hpp = strip_comments(files["agent_decommission.hpp"])
    cpp = strip_comments(files["agent_decommission.cpp"])
    server = strip_comments(files["server.cpp"])

    fields = struct_fields(hpp)
    if fields is None:
        return ["agent_decommission.hpp: struct AgentDecommissionStores not found (renamed? "
                "the pin must follow it)"]
    if len(fields) < _MIN_FIELDS:
        found.append(f"agent_decommission.hpp: parsed only {len(fields)} fields (expected at least "
                     f"{_MIN_FIELDS}): the field pattern no longer matches the struct")
    if len(set(fields)) != len(fields):
        found.append("agent_decommission.hpp: a duplicate field name in AgentDecommissionStores")

    body = decommission_agent_body(server)
    if body is None:
        return found + ["server.cpp: ServerImpl::decommission_agent not found (renamed? the pin "
                        "must follow it)"]
    init = re.search(r"AgentDecommissionStores\s*\{", body)
    if init is None:
        return found + ["server.cpp: decommission_agent builds no AgentDecommissionStores{...}"]
    block = balanced(body, init.end() - 1)
    if block is None:
        return found + ["server.cpp: unbalanced AgentDecommissionStores{...} initializer"]

    given = re.findall(r"\.(\w+)\s*=\s*([^,}]+)", block)
    given_names = [name for name, _ in given]
    for f in fields:
        hit = [expr for name, expr in given if name == f]
        if not hit:
            found.append(f"server.cpp: decommission_agent does not wire .{f} (the store would be "
                         "Skipped for every operator decommission)")
        elif not re.search(r"\w+_\s*\.get\s*\(\s*\)\s*$", hit[0].strip()):
            found.append(f"server.cpp: .{f} = {hit[0].strip()[:40]} is not a `<member>_.get()` "
                         "hand-over")
    for name in given_names:
        if name not in fields:
            found.append(f"server.cpp: decommission_agent initialises .{name}, which "
                         "AgentDecommissionStores does not declare")
    if len(given_names) != len(set(given_names)):
        found.append("server.cpp: decommission_agent initialises a field twice")

    for f in fields:
        if not re.search(rf"\bstores\s*\.\s*{re.escape(f)}\b", cpp):
            found.append(f"agent_decommission.cpp: no registration reads stores.{f}")
    return found


def load() -> dict:
    return {n: (SRC / n).read_text(encoding="utf-8")
            for n in ("agent_decommission.hpp", "agent_decommission.cpp", "server.cpp")}


class DecommissionWiring(unittest.TestCase):
    def test_tree_is_clean(self):
        self.assertEqual(problems(load()), [])

    def test_selftest_mutations_are_reported(self):
        base = load()

        def mutated(name, old, new, count=1):
            files = dict(base)
            self.assertGreaterEqual(files[name].count(old), 1, f"mutation anchor missing: {old!r}")
            files[name] = files[name].replace(old, new, count)
            return files

        cases = {
            "the ninth store is not wired": mutated(
                "server.cpp", ".guaranteed_state = guaranteed_state_store_.get(),", ""),
            "the first store is not wired": mutated(
                "server.cpp", ".inventory = inventory_store_.get(),", ""),
            "a store is wired from a literal null": mutated(
                "server.cpp", ".app_usage = app_usage_store_.get(),", ".app_usage = nullptr,"),
            "a field the struct lacks is initialised": mutated(
                "server.cpp", ".guaranteed_state = guaranteed_state_store_.get(),",
                ".guaranteed_state = guaranteed_state_store_.get(), "
                ".phantom = phantom_store_.get(),"),
            "a wiring line survives only in a comment": mutated(
                "server.cpp", ".guaranteed_state = guaranteed_state_store_.get(),",
                "// .guaranteed_state = guaranteed_state_store_.get(),"),
            "a struct field is not registered": mutated(
                "agent_decommission.cpp", "stores.guaranteed_state", "stores.inventory", count=-1),
            "a new struct field is never wired": mutated(
                "agent_decommission.hpp", "GuaranteedStateStore* guaranteed_state{nullptr};",
                "GuaranteedStateStore* guaranteed_state{nullptr}; "
                "OfflineEndpointStore* tenth{nullptr};"),
        }
        for label, files in cases.items():
            self.assertTrue(problems(files), f"mutation not reported: {label}")

        # Benign controls: whitespace and a reordered initializer must stay clean.
        reordered = mutated("server.cpp", ".inventory = inventory_store_.get(),",
                            ".inventory   =   inventory_store_.get(),")
        self.assertEqual(problems(reordered), [], "whitespace change reported as a problem")


if __name__ == "__main__":
    unittest.main()
