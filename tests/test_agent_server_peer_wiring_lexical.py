#!/usr/bin/env python3
"""Static lexical gate over the live control peer published to plugins ("agent.server_peer").

The firewall plugin's containment must allow, and its verification must prove, the address the
agent's control channel really uses -- not only the address resolved once at agent start (a server
that moved since leaves a green verify over a dead path, UP-8). agents/core publishes that address:
at every successful Register it converts `ClientContext::peer()` with `grpc_peer_literal`, interns
the literal and stores the pointer into every plugin context, and `yuzu_ctx_get_config` answers the
key `agent.server_peer` from that atomic. The conversion is unit-tested
(test_server_address_parsers.cpp) and the plugin side has fake-leg tests, but the wiring lives in
`AgentImpl` and `PluginContextImpl`, translation-unit-local types in agent.cpp with no header and no
test seam, so no unit test can call it. This gate pins the four lines the trust rule depends on:

  1. `yuzu_ctx_get_config` answers `agent.server_peer` from `impl->server_peer.load(` -- never from
     the unsynchronised `config` map (a reconnect-time write there would race a plugin's read).
  2. `PluginContextImpl::server_peer` is a `std::atomic<const char*>`.
  3. `publish_server_peer` applies `grpc_peer_literal(` to its input BEFORE any `server_peer.store(`,
     and stores into every per-plugin context (a plugin only ever sees a value core produced, from
     the stream the server actually answered on; a plugin never resolves a name, #3429 round 4).
  4. The Register success point (right after `agent.connected_since` is written) calls
     `publish_server_peer(ctx.peer())` -- the Register stream's own peer, not a configured name.

Robustness: `//` comments are stripped and whitespace is collapsed before matching, so line wrapping,
re-indentation and comment text mentioning a token cannot satisfy or break a check. Patterns anchor on
distinctive tokens, never line numbers.

Lexical only: it cannot see a relocation that keeps the tokens but changes control flow
(review-enforced). The self-test applies in-memory mutations and requires problems() to be non-empty
on each; a mutation whose pattern no longer matches fails loudly (stale pattern) rather than passing
vacuously.

Usage: python3 tests/test_agent_server_peer_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_CPP = ROOT / "agents" / "core" / "src" / "agent.cpp"
PARSERS_HPP = ROOT / "agents" / "core" / "include" / "yuzu" / "agent" / "server_address_parsers.hpp"
TAG = "test_agent_server_peer_wiring_lexical"
HINT = (
    " (this gate pins the agent.server_peer publish path; if agent.cpp was legitimately restructured,"
    " update tests/test_agent_server_peer_wiring_lexical.py and re-read the trust rule in"
    " AgentImpl::publish_server_peer first)"
)


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def problems(agent_src, hpp_src):
    """One message per violated invariant, in invariant order; [] when clean."""
    out = []
    cpp = normalise(agent_src)

    get_config = re.search(
        r"const char\* yuzu_ctx_get_config\(.*?(?=YUZU_EXPORT const char\* yuzu_ctx_get_secret\()", cpp)
    if not get_config:
        out.append("agent.cpp no longer defines yuzu_ctx_get_config ahead of yuzu_ctx_get_secret")
    elif not re.search(
            r'if \( ?std::strcmp\( ?key, ?"agent\.server_peer" ?\) ?== ?0 ?\) ?'
            r"return impl->server_peer\.load\(", get_config.group(0)):
        out.append("yuzu_ctx_get_config no longer answers agent.server_peer from impl->server_peer.load( "
                   "(the key would read the unsynchronised config map, or nothing)")

    if not re.search(r"std::atomic<const char\*> server_peer\b", cpp):
        out.append("PluginContextImpl::server_peer is no longer a std::atomic<const char*> "
                   "(a plugin's read would race the Register thread's write)")

    publish = re.search(r"void publish_server_peer\(.*?(?=static constexpr std::size_t kMaxInternedPeers)", cpp)
    if not publish:
        out.append("agent.cpp no longer defines AgentImpl::publish_server_peer")
    else:
        body = publish.group(0)
        conv = body.find("grpc_peer_literal(")
        store = body.find("server_peer.store(")
        if conv < 0 or store < 0 or conv > store:
            out.append("publish_server_peer no longer applies grpc_peer_literal( before server_peer.store( "
                       "(a plugin could see a value the transport did not produce as a literal)")
        if not re.search(r"for \( ?auto& \[[^\]]*\] : per_plugin_ctx_ ?\) [^;]*->server_peer\.store\(", body):
            out.append("publish_server_peer no longer stores into every per-plugin context "
                       "(a plugin would keep reading the start-resolved set alone)")

    if not re.search(
            r'agent\.connected_since"\] = [^;]*; publish_server_peer\( ?ctx\.peer\( ?\) ?\);', cpp):
        out.append("the Register success point no longer calls publish_server_peer(ctx.peer()) right after "
                   "agent.connected_since (the control set would not follow the peer the server answered on)")

    if not re.search(r"inline std::string grpc_peer_literal\( ?std::string_view peer ?\)", normalise(hpp_src)):
        out.append("server_address_parsers.hpp no longer declares "
                   "`inline std::string grpc_peer_literal(std::string_view peer)`")
    return out


# Each row removes one invariant: (file, pattern, repl, expected substring of the FIRST problem).
# Applied once (count=1) to the named file's text.
MUTATIONS = [
    ("cpp", r'std::strcmp\(key, "agent\.server_peer"\) == 0', 'std::strcmp(key, "agent.server_peer_x") == 0',
     "no longer answers agent.server_peer"),
    ("cpp", r"return impl->server_peer\.load\(std::memory_order_acquire\);",
     'return impl->config["agent.server_peer"].c_str();', "no longer answers agent.server_peer"),
    ("cpp", r"std::atomic<const char\*> server_peer\{nullptr\};", "const char* server_peer{nullptr};",
     "no longer a std::atomic"),
    ("cpp", r"yuzu::agent::grpc_peer_literal\(grpc_peer\)", "grpc_peer",
     "no longer applies grpc_peer_literal("),
    ("cpp", r"for \(auto& \[name, pctx\] : per_plugin_ctx_\)\s*pctx->server_peer\.store\(interned, std::memory_order_release\);",
     "", "no longer stores into every per-plugin context"),
    ("cpp", r"publish_server_peer\(ctx\.peer\(\)\);", "(void)0;",
     "no longer calls publish_server_peer(ctx.peer())"),
    ("cpp", r"publish_server_peer\(ctx\.peer\(\)\);", 'publish_server_peer(cfg_.server_address);',
     "no longer calls publish_server_peer(ctx.peer())"),
    ("hpp", r"inline std::string grpc_peer_literal\(std::string_view peer\)",
     "inline std::string grpc_peer_literal_renamed(std::string_view peer)", "no longer declares"),
]


class AgentServerPeerWiringLexical(unittest.TestCase):
    def setUp(self):
        self.cpp = AGENT_CPP.read_text(encoding="utf-8")
        self.hpp = PARSERS_HPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.cpp, self.hpp)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (which, pat, repl, expected) in enumerate(MUTATIONS, 1):
            with self.subTest(mutation=i, pattern=pat):
                raw = self.cpp if which == "cpp" else self.hpp
                mutated, n = re.subn(pat, repl, raw, count=1)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = problems(mutated, self.hpp) if which == "cpp" else problems(self.cpp, mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertTrue(any(expected in m for m in p), f"expected {expected!r} in {p}")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
