#!/usr/bin/env python3
"""Static LEXICAL gate over server/core/src/server.cpp: the gateway-upstream service is
registered on the production gRPC builder ONLY through GatewayPeerGuardedService.

The guard unit tests exercise the guard directly and nothing constructs ServerImpl, so no unit
test can see the registration site. This gate pins it. Over server.cpp with comments removed,
string/char literal contents blanked and whitespace collapsed:

  1. Every identifier that looks like a service-registration API (`\\w*Register\\w*Service\\w*`:
     RegisterService, RegisterAsyncGenericService, RegisterCallbackGenericService, a
     pointer-to-member `&ServerBuilder::RegisterService`, a differently spelled wrapper) is
     either one of EXACTLY three `builder.RegisterService(<arg>)` calls, whose arguments are
     {&agent_service_, &mgmt_service_, gateway_peer_guard_.get()} once each, or a violation.
     Space before the paren, arrow/dot/pointer forms and line wrapping do not matter.
  2. No generic-service type or API is mentioned at all (`GenericService`): it routes by method
     name without naming a generated service, so it would bypass the lexical argument check.
  3. There is exactly ONE `ServerBuilder` and the identifier `builder` is only ever used as
     `builder.<known method>(` (or its declaration): passing the builder to a helper, taking a
     reference or pointer to it, or copying it is a violation, because the helper's registration
     would be invisible to rule 1.
  4. `gateway_service_` (the inner, unguarded handler) appears only in an allow-listed set of
     contexts: member calls (`->`), null checks, the assignment that creates it, its
     declaration, and the two `GatewayPeerGuardedService` constructions that take `*gateway_service_`.
     Any other use (`.get()`, `std::addressof`, `std::move`, a cast, an alias initialised from
     it) is a violation: an alias is how the unguarded handler would reach a registration the
     rule-1 argument check cannot name.

LEXICAL ONLY. It cannot see a registration in another translation unit that is handed a builder
from outside server.cpp (rule 3 forbids server.cpp handing it out), and it is not a data-flow
analysis. The behavioural guarantee is the guard's own tests
(tests/unit/server/test_gateway_peer_guard.cpp) and the descriptor sweep there.

The negative controls (MUTATIONS) run against in-memory mutated COPIES of the source, never the
file on disk; each must make the gate report a problem naming the expected control, and a
mutation whose pattern no longer matches fails loudly (stale pattern) instead of passing
vacuously. BENIGN controls prove the gate is not over-eager: comment text and string literals
that merely mention the tokens must NOT trip it.

Python, not bash, like the other no-build lexical gates (#5428): one process on every OS.

Usage: python3 tests/test_gateway_peer_registration_lexical.py
       SERVER_CPP=<path> python3 -I tests/test_gateway_peer_registration_lexical.py   (point at a copy)
"""
import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_CPP = Path(os.environ.get("SERVER_CPP", ROOT / "server" / "core" / "src" / "server.cpp"))
TAG = "test_gateway_peer_registration_lexical"
HINT = (" (this gate pins the gateway-upstream registration; if server.cpp was legitimately "
        "restructured, update tests/test_gateway_peer_registration_lexical.py)")

# Comments -> one space; string/char literal contents blanked (so a log message or a doc string
# that mentions a token can neither satisfy nor trip a rule). Alternation order matters: the
# scan is left to right, so a `//` inside a string literal is consumed by the string first.
_LEX = re.compile(
    r'//[^\n]*'                       # line comment
    r'|/\*.*?\*/'                     # block comment
    r'|R"([^()\\\s]{0,16})\(.*?\)\1"'  # raw string literal
    r'|"(?:\\.|[^"\\\n])*"'           # string literal
    r"|'(?:\\.|[^'\\\n])*'",          # char literal (a digit separator pair is harmless here)
    re.S,
)


def normalise(src):
    def sub(m):
        t = m.group(0)
        if t.startswith("//") or t.startswith("/*"):
            return " "
        return '""' if t[0] in "\"R" else "''"
    return re.sub(r"\s+", " ", _LEX.sub(sub, src))


ALLOWED_REGISTRATIONS = ("&agent_service_", "&mgmt_service_", "gateway_peer_guard_.get()")
# Methods server.cpp legitimately calls on the one builder. A new one is a deliberate edit here.
BUILDER_METHODS = ("AddChannelArgument", "SetResourceQuota", "AddListeningPort", "BuildAndStart",
                   "RegisterService", "experimental")

# Contexts in which `gateway_service_` may appear: (name, regex over BEFORE + "\x00" + AFTER),
# BEFORE being up to 70 normalised chars to the left, AFTER up to 90 to the right.
GW_ALLOWED = (
    ("member call", re.compile(r"\x00->")),
    ("null check in a condition", re.compile(r"(if \(|\(!|&& |\|\| )\x00 ?[)&|]")),
    ("null comparison", re.compile(r"\x00 (!=|==) nullptr")),
    ("ternary test", re.compile(r"\x00 \? ")),
    ("creation", re.compile(r"\x00 = std::make_unique<detail::GatewayUpstreamServiceImpl>")),
    ("declaration", re.compile(r"std::unique_ptr<detail::GatewayUpstreamServiceImpl> \x00;")),
    ("guard construction", re.compile(r"std::make_unique<detail::GatewayPeerGuardedService>\( ?\*\x00,")),
)


def problems(src):
    """One message per violated rule instance, tagged with the control name; [] when clean."""
    t = normalise(src)
    out = []

    # Rule 1 + 2: registration identifiers.
    regs = []
    for m in re.finditer(r"\b\w*Register\w*Service\w*\b|\b\w*GenericService\w*\b", t):
        name = m.group(0)
        if "GenericService" in name:
            out.append(f"[generic-service] `{name}`: generic services route by method name and "
                       "are not allowed on this builder")
            continue
        tail = t[m.end():m.end() + 200]
        head = t[max(0, m.start() - 20):m.start()]
        call = re.match(r" ?\( ?(&agent_service_|&mgmt_service_|gateway_peer_guard_\.get\(\)) ?\)", tail)
        if name != "RegisterService" or call is None or not re.search(r"\bbuilder ?\. ?$", head):
            ctx = (head + name + tail[:60]).strip()
            out.append(f"[registration-form] unrecognised service-registration form `{ctx}`: only "
                       "`builder.RegisterService(<one of the three allowed services>)` is permitted")
        else:
            regs.append(call.group(1))
    for want in ALLOWED_REGISTRATIONS:
        n = regs.count(want)
        if n != 1:
            out.append(f"[registration-set] RegisterService({want}) found {n} times, expected exactly 1"
                       + (" (the guard is the only gateway-upstream registration)"
                          if want.startswith("gateway_peer_guard_") else ""))

    # Rule 3: one builder, only ever used through known methods.
    nb = len(re.findall(r"\bServerBuilder\b", t))
    if nb != 1:
        out.append(f"[builder-count] expected exactly one `ServerBuilder` mention, found {nb}: a second "
                   "builder or a helper taking one hides registrations from this gate")
    for m in re.finditer(r"\bbuilder\b", t):
        tail = t[m.end():m.end() + 40]
        head = t[max(0, m.start() - 20):m.start()]
        if re.search(r"ServerBuilder ?$", head) and tail.startswith(";"):
            continue  # the one declaration
        mm = re.match(r" ?\. ?(\w+)", tail)
        if mm is None or mm.group(1) not in BUILDER_METHODS:
            ctx = (head + "builder" + tail[:30]).strip()
            out.append(f"[builder-escape] `builder` used other than as builder.<known method>(...): `{ctx}`")

    # Rule 4: the inner handler is never reachable except from allow-listed contexts.
    for m in re.finditer(r"\bgateway_service_\b", t):
        before = t[max(0, m.start() - 70):m.start()]
        after = t[m.end():m.end() + 90]
        probe = before + "\x00" + after
        if not any(rx.search(probe) for _, rx in GW_ALLOWED):
            out.append("[inner-handler-use] `gateway_service_` used in an unrecognised context "
                       f"(alias or direct registration risk): `{(before[-30:] + 'gateway_service_' + after[:30]).strip()}`")
    return out


# Negative controls: (name, pattern, replacement, flags, expected substring in the problems).
# count 1 = first match only. Each is applied to the raw source.
_GUARD_LINE = r"builder\.RegisterService\(gateway_peer_guard_\.get\(\)\);"
MUTATIONS = (
    ("guard replaced by the inner handler",
     r"RegisterService\(gateway_peer_guard_\.get\(\)\)", "RegisterService(gateway_service_.get())", 0,
     "registration-form"),
    ("inner handler registered in addition to the guard",
     r"(" + _GUARD_LINE + r")", r"\1 builder.RegisterService(gateway_service_.get());", 0,
     "registration-form"),
    ("guard registration deleted",
     _GUARD_LINE, "", 0, "registration-set"),
    ("a fourth, unreviewed service",
     r"(builder\.RegisterService\(&mgmt_service_\);)", r"\1 builder.RegisterService(&other_service_);", 0,
     "registration-form"),
    ("space before the paren (guard replaced by the inner handler)",
     r"builder\.RegisterService\(gateway_peer_guard_\.get\(\)\);",
     "builder.RegisterService (gateway_service_.get());", 0, "registration-form"),
    ("space before the paren (extra inner handler registration)",
     r"(" + _GUARD_LINE + r")", r"\1 builder . RegisterService  ( gateway_service_.get() );", 0,
     "registration-form"),
    ("alias of the inner handler registered",
     r"(" + _GUARD_LINE + r")",
     r"\1 auto* gw_alias = gateway_service_.get(); builder.RegisterService(gw_alias);", 0,
     "registration-form"),
    ("alias via std::addressof, no registration in this file",
     r"(" + _GUARD_LINE + r")", r"\1 auto* gw_alias = std::addressof(*gateway_service_);", 0,
     "inner-handler-use"),
    ("helper taking the builder and the inner handler",
     r"(" + _GUARD_LINE + r")", r"\1 register_gateway_service(builder, *gateway_service_);", 0,
     "builder-escape"),
    ("a reference alias of the builder",
     r"(grpc::ServerBuilder builder;)", r"\1 grpc::ServerBuilder& alias_b = builder;", 0,
     "builder-count"),
    ("callback generic-service registration",
     r"(" + _GUARD_LINE + r")",
     r"\1 builder.experimental().RegisterCallbackGenericService(&cb_generic_);", 0,
     "generic-service"),
    ("async generic-service registration",
     r"(" + _GUARD_LINE + r")", r"\1 builder.RegisterAsyncGenericService(&async_generic_);", 0,
     "generic-service"),
    ("pointer-to-member registration through a builder reference",
     r"(" + _GUARD_LINE + r")",
     r"\1 auto reg = &grpc::ServerBuilder::RegisterService;", 0, "registration-form"),
    ("a second builder registering the inner handler",
     r"(" + _GUARD_LINE + r")",
     r"\1 grpc::ServerBuilder b2; b2.RegisterService(gateway_service_.get());", 0, "builder-count"),
    ("inner handler moved out",
     r"(" + _GUARD_LINE + r")", r"\1 auto gw_moved = std::move(gateway_service_);", 0,
     "inner-handler-use"),
)

# Benign controls: edits that must NOT change the verdict (comments and literals mentioning the
# tokens). A gate that trips on these would train people to loosen it.
BENIGN = (
    ("commented-out registration of the inner handler",
     r"(" + _GUARD_LINE + r")", r"\1 // builder.RegisterService(gateway_service_.get());", 0),
    ("block-commented generic registration",
     r"(" + _GUARD_LINE + r")", r"\1 /* builder.RegisterAsyncGenericService(&g); */", 0),
    ("string literal naming the tokens",
     r"(" + _GUARD_LINE + r")",
     r'\1 spdlog::debug("builder.RegisterService(gateway_service_.get()) is forbidden; // x");', 0),
)


class GatewayPeerRegistrationLexical(unittest.TestCase):
    def setUp(self):
        self.raw = SERVER_CPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.raw)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_negative_controls_are_caught(self):
        for i, (name, pat, repl, cnt, expected) in enumerate(MUTATIONS, 1):
            with self.subTest(control=f"{i}: {name}"):
                mutated, n = re.subn(pat, repl, self.raw, count=cnt)
                self.assertGreaterEqual(n, 1, f"control '{name}' changed nothing (stale pattern)")
                p = problems(mutated)
                self.assertTrue(p, f"control '{name}' was NOT detected by the gate")
                self.assertTrue(any(expected in x for x in p),
                                f"control '{name}' was detected but not as [{expected}]: {p}")

    def test_benign_edits_are_not_flagged(self):
        for i, (name, pat, repl, cnt) in enumerate(BENIGN, 1):
            with self.subTest(control=f"{i}: {name}"):
                mutated, n = re.subn(pat, repl, self.raw, count=cnt)
                self.assertGreaterEqual(n, 1, f"benign control '{name}' changed nothing (stale pattern)")
                self.assertEqual(problems(mutated), [], f"benign control '{name}' tripped the gate")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
