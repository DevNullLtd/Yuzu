#!/usr/bin/env python3
"""#2240 wiring pins for the guardian_backend reader (lexical, no build required).

Four properties the C++ unit tests cannot see, because each is a property of which source line
calls what, or of declaration order, not of behaviour:

  1. ONE STALENESS CONSTANT. The 15 s sweep, perf_snapshot, net_snapshot and both per-device
     accessors must all be called with `detail::kAgentHealthStaleness`, and none of those files
     may carry a literal 90 second window. Every unit test uses a 0 or 300 s window, so a site
     passing a different window (or a re-introduced `seconds{90}`) leaves the gauge and the
     device field applying different freshness tests with every test still green.
  2. HARD RULE. `guardian_backend` must not appear in the unauthenticated legacy `/api/agents`
     path: not in AgentRegistry::to_json_obj(), not in server.cpp (make_device_row / devices_fn,
     the dashboard's device model), not in dashboard_api_routes.cpp, and not in
     device_routes.cpp's dashboard row builder `to_device_row`. It is served only by the REST
     `device_agent_row_json` and the two MCP tools, behind the fleet-read gate.
  3. DESTRUCTION ORDER. `ServerImpl::health_store_` must be declared BEFORE each member listed in
     HOLDERS below (the DeviceApi holders and the other direct borrowers), because
     `LocalDeviceApi` keeps a `const AgentHealthStore&` and members are destroyed in reverse
     declaration order. Moving it back below a holder is a use-after-free that only a sanitizer
     run during shutdown would find.

  4. CHEAP READS. The callers that discard the per-device backend (the dashboard device fragment,
     the crypto hostname map, the two page-render connected counts) must call
     `list_devices_basic()` / `connected_count()` and never the full `list_devices()`, which pays the
     health-store lookup and the registry JSON walk. Every behavioural test passes with either call,
     so only this gate (and the dashboard call-count pin in test_device_routes.cpp) sees a revert.

`//` and block comments are stripped before matching, so prose cannot satisfy a check. The
self-test applies in-memory mutations and requires problems() to report each one.

WHAT THIS DOES NOT PROVE (a lexical gate is not a C++ lexer): it does not see a holder added
later that is not in HOLDERS; a new call of the accessors in another file; a derived window such
as `kAgentHealthStaleness / 2` (it checks the constant's NAME appears in the argument); the
constant's own value (agent_registry.hpp is not scanned); a leak through a helper called from
to_json_obj, or under a constant spelling; character-literal edge cases (a quote inside '...') in the comment
stripper; raw strings are handled. Runtime teardown order still needs a sanitizer run of start/stop.

Usage: python3 tests/test_guardian_backend_wiring_lexical.py
"""
import functools
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "server" / "core" / "src"

# The members this gate knows borrow health_store_ (directly or through LocalDeviceApi /
# LocalNetworkApi): agent_service_ holds &health_store_ (set_health_store), gateway_service_ is built
# with &health_store_, network_routes_ holds the LocalNetworkApi built from it, heartbeat_ingestion_
# calls upsert on it. All must be destroyed BEFORE it. A borrower added later is NOT covered until it
# is added here.
HOLDERS = ("rest_api_v1_", "mcp_server_", "device_routes_", "crypto_device_api_",
           "agent_service_", "gateway_service_", "network_routes_", "heartbeat_ingestion_")
STALENESS_CALLS = (
    # (file, call prefix that must be followed by an argument naming the constant)
    ("server.cpp", "recompute_metrics("),
    ("server.cpp", "perf_snapshot("),
    ("network_api.cpp", "net_snapshot("),
    ("device_api.cpp", "guardian_backend_for("),
    ("device_api.cpp", "guardian_backend_of("),
)
LITERAL_90 = re.compile(r"seconds\s*[{(]\s*90\s*[})]")
# Callers of the DeviceApi seam that discard the per-device backend must use a cheap read, so they
# do not pay the health-store lookup (and the registry JSON walk, for the counts): (file, token that
# MUST appear in code, token that must NOT). Only REST /api/v1/devices and MCP list_agents may call
# the full list_devices().
CHEAP_READS = (
    ("device_routes.cpp", "list_devices_basic()", "list_devices()"),
    ("crypto_api.cpp", "list_devices_basic()", "list_devices()"),
    ("server.cpp", "connected_count()", "list_devices()"),
    ("software_catalogue_model.cpp", "connected_count()", "list_devices()"),
)
# Opener of a C++ raw string, from the quote: "delim( with a delimiter of at most 16 characters.
_RAW_OPEN = re.compile(r'"([^ ()\\\t\v\f\n"]{0,16})\(')


@functools.lru_cache(maxsize=32)
def strip_comments(text: str) -> str:
    """Remove // and /* */ comments, leaving string literals (ordinary and raw) untouched."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"' and i > 0 and text[i - 1] == "R":
            # Raw string R"delim( ... )delim": no escapes, and a `//` or `/*` inside is payload,
            # not a comment. An unterminated or malformed opener is kept to the end of the text,
            # so a leak after it is still visible to the scan (fail toward reporting).
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


def function_body(text: str, signature: str):
    """Return the brace-balanced body following `signature`, or None."""
    k = text.find(signature)
    if k < 0:
        return None
    b = text.find("{", k)
    if b < 0:
        return None
    depth = 0
    for i in range(b, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[b : i + 1]
    return None


def call_args(text: str, prefix: str):
    """Yield the argument text of every call that begins with `prefix`."""
    start = 0
    while True:
        k = text.find(prefix, start)
        if k < 0:
            return
        i = k + len(prefix)
        depth = 1
        j = i
        while j < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[j], 0)
            j += 1
        yield text[i : j - 1]
        start = j


def problems(files: dict) -> list:
    """`files` maps a basename under server/core/src to its raw text."""
    found = []
    code = {name: strip_comments(text) for name, text in files.items()}

    # 1. one staleness constant
    for name, prefix in STALENESS_CALLS:
        args = list(call_args(code[name], prefix))
        if not args:
            found.append(f"{name}: no call to {prefix} found (renamed? the pin must follow it)")
        for a in args:
            if "kAgentHealthStaleness" not in a:
                found.append(f"{name}: {prefix}{a.strip()[:40]}...) does not pass kAgentHealthStaleness")
    for name in ("server.cpp", "network_api.cpp", "device_api.cpp"):
        if LITERAL_90.search(code[name]):
            found.append(f"{name}: a literal 90 second window is back; use detail::kAgentHealthStaleness")

    # 2. hard rule: the legacy /api/agents path and the dashboard row never carry the field
    body = function_body(code["agent_registry.cpp"], "AgentRegistry::to_json_obj() const")
    if body is None:
        found.append("agent_registry.cpp: AgentRegistry::to_json_obj() not found")
    elif "guardian_backend" in body:
        found.append("agent_registry.cpp: to_json_obj() carries guardian_backend (HARD RULE)")
    server_no_include = re.sub(r'#include\s+"[^"]*"', "", code["server.cpp"])
    if "guardian_backend" in server_no_include:
        found.append("server.cpp: guardian_backend appears outside the #include (make_device_row / "
                     "devices_fn / the legacy /api/agents provider must not carry it: HARD RULE)")
    if "guardian_backend" in code["dashboard_api_routes.cpp"]:
        found.append("dashboard_api_routes.cpp: guardian_backend appears (legacy /api/agents: HARD RULE)")
    # Anchor on the lambda DEFINITION: a bare "to_device_row(" first matches a call site, whose next
    # brace belongs to an unrelated lambda (the first version of this gate scanned `{ return
    # d.online; }` and could never fail).
    row = function_body(code["device_routes.cpp"], "auto to_device_row = [")
    if row is None:
        found.append("device_routes.cpp: `auto to_device_row = [` not found (renamed? the pin must follow it)")
    elif len(row) < 100 or "DeviceRow" not in row:
        found.append("device_routes.cpp: the to_device_row body the gate scanned is not the row builder "
                     "(too short or no DeviceRow): the anchor is wrong")
    elif "guardian_backend" in row:
        found.append("device_routes.cpp: to_device_row carries guardian_backend (dashboard row: HARD RULE)")

    # 3. destruction order
    decl = member_declarations(code["server.cpp"])
    if "health_store_" not in decl:
        found.append("server.cpp: no `health_store_;` member declaration found")
    else:
        for h in HOLDERS:
            if h not in decl:
                found.append(f"server.cpp: holder member {h} not found (renamed? the pin must follow it)")
            elif decl["health_store_"] > decl[h]:
                found.append(f"server.cpp: health_store_ is declared AFTER {h}: it would be destroyed "
                             "BEFORE a holder of the DeviceApi (use-after-free at shutdown)")
    return found


@functools.lru_cache(maxsize=32)
def member_declarations(text: str) -> dict:
    """Name -> offset of the first line shaped like a member declaration `<type> name_;`."""
    decl = {}
    for m in re.finditer(r"^[ \t]+[^\n;(){}=]+?[ \t]+(\w+_);[ \t]*$", text, re.M):
        decl.setdefault(m.group(1), m.start())
    return decl


def cheap_read_problems(files: dict) -> list:
    """The discarding callers must read through list_devices_basic()/connected_count() and must not
    call the full list_devices() (comments are stripped first, so prose cannot satisfy this)."""
    out = []
    for name, must, must_not in CHEAP_READS:
        code = strip_comments(files[name])
        if must not in code:
            out.append(f"{name}: expected a call to {must} (the caller discards the per-device backend)")
        if must_not in code:
            out.append(f"{name}: calls the full {must_not}, which pays the health-store lookup")
    return out


def load_cheap() -> dict:
    return {name: (SRC / name).read_text(encoding="utf-8") for name, _, _ in CHEAP_READS}


def load() -> dict:
    names = ("server.cpp", "network_api.cpp", "device_api.cpp", "agent_registry.cpp",
             "dashboard_api_routes.cpp", "device_routes.cpp")
    return {n: (SRC / n).read_text(encoding="utf-8") for n in names}


class GuardianBackendWiring(unittest.TestCase):
    def test_tree_is_clean(self):
        self.assertEqual(problems(load()), [])

    def test_selftest_mutations_are_reported(self):
        base = load()

        def mutated(name, old, new, count=1):
            files = dict(base)
            self.assertGreaterEqual(files[name].count(old), 1, f"mutation anchor missing: {old!r}")
            files[name] = files[name].replace(old, new, count)
            return files

        def inject_after_open_brace(name, signature):
            files = dict(base)
            text = files[name]
            k = text.find(signature)
            self.assertGreaterEqual(k, 0, f"mutation anchor missing: {signature!r}")
            brace = text.find("{", k)
            files[name] = text[: brace + 1] + '\n    auto leak = "guardian_backend";' + text[brace + 1:]
            return files

        leak_server = dict(base)
        leak_server["server.cpp"] = base["server.cpp"] + '\nstatic const char* leak = "guardian_backend";\n'
        leak_dashboard = dict(base)
        leak_dashboard["dashboard_api_routes.cpp"] = base["dashboard_api_routes.cpp"] + '\nconst char* leak = "guardian_backend";\n'
        cases = {
            "sweep window literal": mutated(
                "server.cpp", "recompute_metrics(metrics_, detail::kAgentHealthStaleness)",
                "recompute_metrics(metrics_, std::chrono::seconds{90})"),
            "accessor window literal": mutated(
                "device_api.cpp", "guardian_backend_for(ids, detail::kAgentHealthStaleness)",
                "guardian_backend_for(ids, std::chrono::seconds{60})"),
            "field leaks into to_json_obj": inject_after_open_brace(
                "agent_registry.cpp", "AgentRegistry::to_json_obj() const"),
            "field leaks into server.cpp": leak_server,
            "field leaks into the legacy dashboard routes": leak_dashboard,
            "field leaks into the dashboard row": inject_after_open_brace(
                "device_routes.cpp", "auto to_device_row = ["),
        }
        for label, files in cases.items():
            self.assertTrue(problems(files), f"mutation not reported: {label}")

        # destruction order: move the health_store_ declaration below EACH listed holder in turn, so
        # dropping a name from HOLDERS turns this red instead of going unnoticed.
        for holder in HOLDERS:
            files = dict(base)
            text = files["server.cpp"]
            m = re.search(r"^[ \t]+detail::AgentHealthStore health_store_;\s*$", text, re.M)
            self.assertIsNotNone(m)
            line = m.group(0)
            text = text.replace(line, "", 1)
            h = re.search(r"^[ \t]+[^\n;(){}=]+?[ \t]" + re.escape(holder) + r";[ \t]*$", text, re.M)
            self.assertIsNotNone(h, f"no declaration line for {holder}")
            text = text[: h.end()] + "\n" + line + text[h.end():]
            files["server.cpp"] = text
            self.assertTrue(any(f"AFTER {holder}" in p for p in problems(files)),
                            f"reorder below {holder} not reported")

    def test_discarding_callers_use_cheap_reads(self):
        self.assertEqual(cheap_read_problems(load_cheap()), [])

    def test_cheap_read_mutations_are_reported(self):
        base = load_cheap()
        for name, must, must_not in CHEAP_READS:
            files = dict(base)
            self.assertIn(must, strip_comments(files[name]), f"anchor missing in {name}")
            # point the caller back at the full list
            # (every occurrence, so a comment that happens to come first cannot absorb the mutation)
            files[name] = files[name].replace(must, must_not)
            self.assertTrue(cheap_read_problems(files), f"reverting {name} not reported")
            # a comment mentioning the cheap call must not satisfy the check
            files = dict(base)
            files[name] = files[name].replace(must, "list_devices_other()") + f"\n// {must}\n"
            self.assertTrue(cheap_read_problems(files), f"comment satisfied the check in {name}")

    def test_comment_stripper_understands_raw_strings(self):
        leak = 'auto leak = "guardian_backend";'
        # A `//` inside a raw string is payload: the leak after it on the same line must survive.
        same_line = 'auto s = R"({"url":"http://example.test"})"; ' + leak
        self.assertIn("guardian_backend", strip_comments(same_line))
        # Custom delimiter, and a `)"` inside the payload that does not close it.
        custom = 'auto s = R"x(a)" // b)x"; ' + leak
        self.assertIn("guardian_backend", strip_comments(custom))
        # Prefixed raw strings.
        for prefix in ("u8R", "LR", "uR", "UR"):
            self.assertIn("guardian_backend", strip_comments(f'auto s = {prefix}"(//)"; ' + leak))
        # A real comment after a raw string is still removed, and so is its content.
        after = 'auto s = R"(x)"; // guardian_backend in a comment\nint y;'
        self.assertNotIn("guardian_backend", strip_comments(after))
        # A comment that merely mentions R"( must not open a raw string.
        mention = '// see R"( for details\n' + leak
        self.assertIn("guardian_backend", strip_comments(mention))
        # An unterminated raw string fails toward reporting: the tail stays visible.
        self.assertIn("guardian_backend", strip_comments('auto s = R"(unterminated ' + leak))
        # End to end: the HARD RULE scan reports a leak that sits after a raw-string URL.
        files = load()
        files["dashboard_api_routes.cpp"] += '\nauto s = R"({"u":"http://x"})"; ' + leak + "\n"
        self.assertTrue(any("dashboard_api_routes.cpp" in p for p in problems(files)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
