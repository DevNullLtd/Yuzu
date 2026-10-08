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

  5. Member order: the declarations of `agent_service_`, `gateway_service_` and
     `gateway_peer_guard_` precede `agent_server_` in server.cpp, in that order (the guard must
     outlive the gRPC server that calls it, and the OTA row's agent_service_/agent_server_ order is
     untouched). Each is declared exactly once, and all four sit at the SAME brace depth, which is
     the depth of the body of `class ServerImpl` (a declaration moved into a nested struct would
     keep the textual order and change the destruction order). Exactly TWO
     `GatewayPeerGuardedService` constructions exist (the acknowledged-insecure arm and the
     enforcing arm of the one boot function); a third is a new, unreviewed way to build the guard.
  6. `#include` hygiene: server.cpp includes only headers (.h/.hpp), spelled `#include` or with
     the `%:` digraph, and imports (`import "x.cpp";`, `import <x.cpp>;`, a named module) are held to
     the same rule. An included .cpp/.inc file would be text the lexical rules never see; a
     macro-argument include is refused for the same reason. The only exemption is a bare
     `<name>` with no `/` and no extension (a standard-library header such as `<algorithm>`).
     A line beginning with `#include` inside a raw string literal is data, not a directive, and
     is not read as one.
  7. Tree rule: no other C/C++ file under server/ (extensions matched case-insensitively:
     .c .cc .cpp .cxx .c++ .h .hh .hpp .hxx .inc .ipp .tpp .tcc .inl .ixx .cppm .ino .mm .m) names
     `ServerBuilder` or any service-registration or listener API (comments stripped), so a
     registration cannot hide in a helper translation unit that server.cpp passes the builder to.
     No directory is exempt: there is no `test`/`tests` directory under server/ today, and a
     blanket exemption would be a place to hide one. Rule 3 already forbids server.cpp handing
     the builder out; this rule is the independent check from the other side.

Preprocessing the lexer undoes first: a leading UTF-8 byte-order mark (which would stop the first
line reading as a directive), backslash-newline splices (a token split across lines) and C++14
digit separators (`1'000`), which would otherwise open a bogus character literal that swallows a
registration up to the next apostrophe. A raw string literal is recognised only at an identifier
boundary (`XR"(` is the identifier `XR` followed by an ordinary string, not a raw string), with or
without an encoding prefix (`u8R"(`, `uR"(`, `UR"(`, `LR"(`).

LEXICAL ONLY. It is not a data-flow analysis. A registration reached through a macro, a generated
file or a header that is included but not under server/ is outside its reach. The behavioural guarantee is the guard's own tests
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
    r'|(?<![A-Za-z0-9_])(?:u8|u|U|L)?R"([^()\\\s]{0,16})\(.*?\)\1"'  # raw string literal (identifier boundary)
    r'|"(?:\\.|[^"\\\n])*"'           # string literal
    r"|'(?:\\.|[^'\\\n])*'",          # char literal (a digit separator pair is harmless here)
    re.S,
)


_HEX = frozenset("0123456789abcdefABCDEF")
_WORD = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def preprocess(src):
    """Undo line splices and C++14 digit separators so neither can hide a token from the lexer.

    A digit separator is an apostrophe between two hex digits. The one false positive that matters
    is the `u8'a'` character-literal prefix (a `8` before the quote, a hex letter after), so an
    apostrophe directly after a standalone `u8` is left alone. Done with a literal scan for the
    apostrophes and a per-apostrophe check, not a whole-file regex, to keep the gate fast."""
    if src.startswith("\ufeff"):
        src = src[1:]  # a byte-order mark would stop the first line reading as a directive
    src = src.replace("\\\r\n", "").replace("\\\n", "")
    out, last = [], 0
    for m in re.finditer("'", src):
        i = m.start()
        if i == 0 or i + 1 >= len(src) or src[i - 1] not in _HEX or src[i + 1] not in _HEX:
            continue
        if src[i - 2:i] == "u8" and (i < 3 or src[i - 3] not in _WORD):
            continue
        out.append(src[last:i])
        last = i + 1
    out.append(src[last:])
    return "".join(out)


def lex(src):
    """One lexer pass over `src`: (normalised, comments_stripped).

    normalised: comments -> one space, string/char literal contents blanked, whitespace collapsed
    (what rules 1-5 and 7 read). comments_stripped: comments -> one space, literals KEPT (what the
    `#include` scan of rule 6 reads, because an include target is a literal; raw strings are blanked)."""
    pre = preprocess(src)
    blank, keep, last = [], [], 0
    for m in _LEX.finditer(pre):
        t = m.group(0)
        gap = pre[last:m.start()]
        blank.append(gap)
        keep.append(gap)
        last = m.end()
        if t.startswith("//") or t.startswith("/*"):
            blank.append(" ")
            keep.append(" ")
        elif t[0] == "'":
            blank.append("''")
            keep.append(t)
        else:
            blank.append('""')
            # An ordinary string literal is kept (an include target is one); a raw string literal
            # is blanked here too, so a `#include` at the start of one of its lines is data and
            # cannot be read as a directive.
            keep.append(t if t[0] == '"' else '""')
    tail = pre[last:]
    blank.append(tail)
    keep.append(tail)
    return " ".join("".join(blank).split()), "".join(keep)


def normalise(src):
    return lex(src)[0]


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
    t, kept = lex(src)
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

    # Rule 5: member order inside ServerImpl (destruction order is the reverse of declaration).
    pos = {}
    for name, rx in MEMBER_DECLS:
        found = [m.start() for m in rx.finditer(t)]
        if len(found) != 1:
            out.append(f"[member-order] expected exactly one declaration of `{name}`, found {len(found)}")
        else:
            pos[name] = found[0]
    if len(pos) == len(MEMBER_DECLS):
        for early, late in zip(MEMBER_ORDER, MEMBER_ORDER[1:]):
            if not pos[early] < pos[late]:
                out.append(f"[member-order] `{early}` must be declared before `{late}` so the gRPC server "
                           "is destroyed before the objects it calls into")
        # Same brace depth, and that depth is the body of `class ServerImpl`: textual order across a
        # nested struct or function body says nothing about member destruction order.
        cls = CLASS_OPEN.search(t)
        if cls is None:
            out.append("[member-order] `class ServerImpl ... {` was not found, so the member depth cannot be checked")
        else:
            body_depth = brace_depth(t, cls.end() - 1) + 1
            for name in MEMBER_ORDER:
                d = brace_depth(t, pos[name])
                if d != body_depth:
                    out.append(f"[member-order] `{name}` is at brace depth {d}, not {body_depth} (the body of "
                               "`class ServerImpl`): a member in a nested scope does not fix the destruction order")

    # Exactly two constructions of the guard (the acknowledged-insecure arm and the enforcing arm).
    n_ctor = len(GUARD_CTOR.findall(t))
    if n_ctor != 2:
        out.append(f"[guard-construction-count] expected exactly 2 constructions of GatewayPeerGuardedService "
                   f"(acknowledged-insecure and enforcing), found {n_ctor}: a new construction is a new, "
                   "unreviewed way to build the guard")

    # Rule 6: only headers are included (`#include`, the `%:` digraph spelling, and C++20 `import`).
    for m in INCLUDE_RX.finditer(kept):
        kind = m.group("kind") or "import"
        arg = (m.group("arg") or m.group("modarg") or "").strip()
        inc = re.match(r'[<"]([^>"]+)[>"]', arg)
        if inc is None:
            out.append(f"[include-form] `{kind} {arg[:40]}`: only `#include <header>` / `\"header\"` is permitted")
        elif not (inc.group(1).endswith((".h", ".hpp"))
                  or (arg[0] == "<" and "." not in inc.group(1) and "/" not in inc.group(1))):
            # (a bare extensionless angle-bracket name is a standard-library header: <algorithm>)
            out.append(f"[include-nonheader] `{kind} {inc.group(1)}`: an included source file is text this "
                       "gate cannot lex as part of the registration site")
    return out


def brace_depth(t, pos):
    """Number of unmatched `{` before offset `pos` of the normalised text (literals are blanked)."""
    return t.count("{", 0, pos) - t.count("}", 0, pos)


CLASS_OPEN = re.compile(r"\bclass ServerImpl\b[^{;]*\{")
GUARD_CTOR = re.compile(r"\b(?:make_unique|make_shared) ?< ?(?:detail::)?GatewayPeerGuardedService ?>"
                        r"|\bnew (?:detail::)?GatewayPeerGuardedService\b")
# `#include` / `%:include` / `# include_next` / `import "x"` / `import <x>` / `import name;`
# at the start of a line (a C++20 `export import` too).
INCLUDE_RX = re.compile(
    r"^[ \t]*(?:(?P<kind>(?:#|%:)[ \t]*(?:include_next|include|import))\b(?P<arg>[^\n]*)"
    r"|(?:export[ \t]+)?import\b[ \t]*(?P<modarg>[<\"][^>\"]*[>\"]|[A-Za-z_][\w.:]*[ \t]*;|:[\w.]+[ \t]*;))",
    re.M)


# Rule 5 inputs: (name, declaration regex over normalised text) in REQUIRED declaration order.
MEMBER_DECLS = (
    ("agent_service_", re.compile(r"\bdetail::AgentServiceImpl agent_service_;")),
    ("gateway_service_", re.compile(r"\bstd::unique_ptr<detail::GatewayUpstreamServiceImpl> gateway_service_;")),
    ("gateway_peer_guard_", re.compile(r"\bstd::unique_ptr<detail::GatewayPeerGuardedService> gateway_peer_guard_;")),
    ("agent_server_", re.compile(r"\bstd::unique_ptr<grpc::Server> agent_server_;")),
)
MEMBER_ORDER = tuple(n for n, _ in MEMBER_DECLS)

# Rule 7: the whole-tree scan. Names a registration or listener can only be reached through.
TREE_TOKENS = re.compile(r"\b(?:ServerBuilder|\w*Register\w*Service\w*|\w*GenericService\w*|"
                         r"AddListeningPort|BuildAndStart)\b")
TREE_PREFILTER = ("ServerBuilder", "Register", "GenericService", "AddListeningPort", "BuildAndStart")
# Compared case-insensitively (`.C`, `.H` are C++ / C headers on a case-sensitive filesystem).
TREE_EXTS = frozenset((".cpp", ".cc", ".cxx", ".c++", ".c", ".hpp", ".h", ".hh", ".hxx", ".h++", ".inc",
                       ".ipp", ".tpp", ".tcc", ".inl", ".ixx", ".cppm", ".ino", ".mm", ".m"))
SERVER_TREE = ROOT / "server"
SERVER_REL = "server/core/src/server.cpp"


def tree_sources(tree=SERVER_TREE, base=ROOT):
    """{repo-relative posix path: text} for every C/C++ file under `tree` except server.cpp."""
    out = {}
    for f in sorted(tree.rglob("*")):
        if not f.is_file() or f.suffix.lower() not in TREE_EXTS:
            continue
        rel = f.relative_to(base).as_posix()
        if rel == SERVER_REL:
            continue
        out[rel] = f.read_text(encoding="utf-8", errors="replace")
    return out


def tree_problems(files):
    out = []
    for rel, src in files.items():
        spliced = src.replace("\\\r\n", "").replace("\\\n", "")
        if not any(w in spliced for w in TREE_PREFILTER):
            continue  # cannot match after comment stripping either: skip the lexer for speed
        for m in TREE_TOKENS.finditer(normalise(src)):
            out.append(f"[tree-registration] {rel}: `{m.group(0)}` outside server.cpp: the production gRPC "
                       "builder and its listeners are owned by server.cpp so the registration gate can see them")
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
    ("digit separators hide an inner-handler registration",
     r"(" + _GUARD_LINE + r")",
     r"\1 int a1 = 1'000; builder.RegisterService(gateway_service_.get()); int a2 = 2'000;", 0,
     "registration-form"),
    ("registration split by a line splice",
     r"(" + _GUARD_LINE + r")",
     "\\1 builder.Register\\\nService(gateway_service_.get());", 0, "registration-form"),
    ("guard declared after the gRPC server",
     r"(?s)(std::unique_ptr<detail::GatewayPeerGuardedService> gateway_peer_guard_;)(.*?)"
     r"(std::unique_ptr<grpc::Server> agent_server_;)", r"\2\3 \1", 0, "member-order"),
    ("gRPC server declared before the services",
     r"(?s)(detail::AgentServiceImpl agent_service_;)(.*?)(std::unique_ptr<grpc::Server> agent_server_;)",
     r"\3\2\1", 0, "member-order"),
    ("inner handler declared after the guard",
     r"(?s)(std::unique_ptr<detail::GatewayUpstreamServiceImpl> gateway_service_;)(.*?)"
     r"(std::unique_ptr<detail::GatewayPeerGuardedService> gateway_peer_guard_;)", r"\3\2\1", 0,
     "member-order"),
    ("member declaration duplicated",
     r"(std::unique_ptr<grpc::Server> agent_server_;)", r"\1 std::unique_ptr<grpc::Server> agent_server_;", 0,
     "member-order"),
    ("included .cpp file",
     r'(#include "bundled_content\.hpp")', r'\1\n#include "gateway_service_body.cpp"', 0,
     "include-nonheader"),
    ("included .inc file via angle brackets",
     r'(#include "bundled_content\.hpp")', r'\1\n#  include <gateway_registration.inc>', 0,
     "include-nonheader"),
    ("macro-argument include",
     r'(#include "bundled_content\.hpp")', r'\1\n#include GATEWAY_REGISTRATION_HEADER', 0,
     "include-form"),
    ("an XR\"( identifier-prefixed string is not a raw string (it would hide a registration)",
     r"(" + _GUARD_LINE + r")",
     r'\1 const char* xs = XR"(" ; builder.RegisterService(gateway_service_.get()); const char* xe = ")";', 0,
     "registration-form"),
    ("a leading byte-order mark does not hide the first line's directive",
     r"\A", '\ufeff#include "evil_body.cpp"\n', 1, "include-nonheader"),
    ("digraph include of a source file",
     r'(#include "bundled_content\.hpp")', r'\1\n%: include "gateway_service_body.cpp"', 0,
     "include-nonheader"),
    ("C++20 import of a source file",
     r'(#include "bundled_content\.hpp")', r'\1\nimport "gateway_service_body.cpp";', 0,
     "include-nonheader"),
    ("C++20 import of an angle-bracket source file",
     r'(#include "bundled_content\.hpp")', r'\1\nimport <gateway_service_body.cpp>;', 0,
     "include-nonheader"),
    ("exported import of a source file",
     r'(#include "bundled_content\.hpp")', r'\1\nexport import "gateway_service_body.cpp";', 0,
     "include-nonheader"),
    ("import of a named module",
     r'(#include "bundled_content\.hpp")', r'\1\nimport gateway.registration;', 0,
     "include-form"),
    ("angle include with a path separator is not the standard-library exemption",
     r'(#include "bundled_content\.hpp")', r'\1\n#include <detail/gateway_body>', 0,
     "include-nonheader"),
    ("guard member moved into a nested struct (text order kept, depth changed)",
     r"std::unique_ptr<detail::GatewayPeerGuardedService> gateway_peer_guard_;",
     "struct NestedHolder { std::unique_ptr<detail::GatewayPeerGuardedService> gateway_peer_guard_; };", 0,
     "member-order"),
    ("a third guard construction",
     r"(" + _GUARD_LINE + r")",
     r"\1 auto g3 = std::make_unique<detail::GatewayPeerGuardedService>(*gateway_service_, other_policy);", 0,
     "guard-construction-count"),
    ("a guard built with new",
     r"(" + _GUARD_LINE + r")",
     r"\1 auto* g3 = new detail::GatewayPeerGuardedService(*gateway_service_, other_policy);", 0,
     "guard-construction-count"),
)

# Benign controls: edits that must NOT change the verdict (comments and literals mentioning the
# tokens). A gate that trips on these would train people to loosen it.
BENIGN = (
    ("commented-out registration of the inner handler",
     r"(" + _GUARD_LINE + r")", r"\1 // builder.RegisterService(gateway_service_.get());", 0),
    ("block-commented generic registration",
     r"(" + _GUARD_LINE + r")", r"\1 /* builder.RegisterAsyncGenericService(&g); */", 0),
    ("digit separators in ordinary arithmetic",
     r"(" + _GUARD_LINE + r")", r"\1 constexpr int kBigStep = 3'600; constexpr auto kMask = 0xFF'FF;", 0),
    ("a char literal next to a number",
     r"(" + _GUARD_LINE + r")", r"\1 char sep = 'a'; int n = 5; char c2 = '7';", 0),
    ("header include spelled with extra whitespace",
     r'(#include "bundled_content\.hpp")', r'\1\n#  include   <yuzu/extra.hpp>', 0),
    ("commented-out source include",
     r'(#include "bundled_content\.hpp")', r'\1\n// #include "gateway_service_body.cpp"', 0),
    ("a raw string literal naming the tokens, with and without an encoding prefix",
     r"(" + _GUARD_LINE + r")",
     r'\1 const char* r1 = R"(builder.RegisterService(gateway_service_.get()))"; '
     r'const char* r2 = u8R"x(builder.RegisterAsyncGenericService(&g))x"; const wchar_t* r3 = LR"(ServerBuilder)";', 0),
    ("a raw string literal with a line-leading #include",
     r"(" + _GUARD_LINE + r")",
     '\\1 const char* r4 = R"(\n#include "evil_body.cpp"\n  import <evil_body.cpp>;\n)";', 0),
    ("a standard-library angle include and a header import",
     r'(#include "bundled_content\.hpp")', r'\1\n#include <algorithm>\nimport "extra.hpp";', 0),
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

    def test_no_registration_outside_server_cpp(self):
        files = tree_sources()
        self.assertGreater(len(files), 100, "the tree scan found almost nothing: ROOT or TREE_EXTS is wrong")
        self.assertIn("server/core/src/main.cpp", files)
        p = tree_problems(files)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_tree_rule_negative_controls(self):
        victim = "server/core/src/main.cpp"
        base = tree_sources()[victim]
        controls = (
            ("second builder in another file", base + "\ngrpc::ServerBuilder other;\n"),
            ("registration in another file", base + "\nvoid f(){ b.RegisterService(&svc); }\n"),
            ("generic registration in another file", base + "\nvoid f(){ b.RegisterCallbackGenericService(&g); }\n"),
            ("listener in another file", base + "\nvoid f(){ b.AddListeningPort(a, c); }\n"),
            ("build in another file", base + "\nauto s = b.BuildAndStart();\n"),
            ("digit separators hide it", base + "\nint a=1'000; b.RegisterService(&x); int c=2'000;\n"),
            ("line splice hides it", base + "\nvoid f(){ b.Register\\\nService(&svc); }\n"),
        )
        for name, mutated in controls:
            with self.subTest(control=name):
                p = tree_problems({victim: mutated})
                self.assertTrue(any("tree-registration" in x and victim in x for x in p),
                                f"control '{name}' was not caught: {p}")
        benign = base + "\n// grpc::ServerBuilder b; b.BuildAndStart();\nconst char* k = \"RegisterService\";\n"
        self.assertEqual(tree_problems({victim: benign}), [])
        # A raw string that merely mentions the tokens is data; one spelled XR"( is not a raw string.
        self.assertEqual(tree_problems({victim: base + '\nconst char* k = u8R"(b.RegisterService(&x))";\n'}), [])
        self.assertTrue(tree_problems({victim: base + '\nconst char* a = XR"(" ; b.RegisterService(&x); const char* z = ")";\n'}))
        self.assertTrue(tree_problems({victim: "\ufeff" + base + "\nvoid f(){ b.AddListeningPort(a, c); }\n"}))

    def test_tree_scan_extensions_and_directories(self):
        # Every C/C++ spelling is scanned (case-insensitively) and no directory name is exempt.
        import tempfile
        exts = (".C", ".c++", ".ixx", ".cppm", ".ino", ".tcc", ".inl", ".H", ".hh", ".hxx", ".cpp", ".hpp")
        with tempfile.TemporaryDirectory(prefix="yuzu_test_gwreg_") as d:
            base = Path(d)
            (base / "core" / "tests").mkdir(parents=True)
            (base / "core" / "test").mkdir()
            for i, ext in enumerate(exts):
                (base / "core" / ("tests" if i % 2 else "test") / f"hidden{i}{ext}").write_text("void f(){}\n")
            (base / "notes.txt").write_text("x\n")
            seen = tree_sources(base, base)
            self.assertEqual(len(seen), len(exts), sorted(seen))
            self.assertTrue(any("/tests/" in k for k in seen) and any("/test/" in k for k in seen))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
