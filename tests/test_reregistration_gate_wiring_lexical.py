#!/usr/bin/env python3
"""Best-effort lexical tripwire for WP01 (agent re-registration identity).

The decision lives in server/core/src/agent_reregistration_gate.hpp and is applied by
agent_reregistration_apply.hpp. The unit tests drive the handlers with fake hooks, so they stay
green if production wiring is deleted or if a handler grows a new `approved -> enrolled` jump that
skips the gate. This script pins the production wiring text. It is a TRIPWIRE, not proof.

Checks (all on comment-stripped source):
  1. server.cpp wires the identity hooks and proof mode into the direct AND the gateway service,
     inside the block that wires the signer, and clears both at shutdown.
  2. agent_service_impl.cpp and gateway_service_impl.cpp each call apply_reregistration_gate(
     exactly once, and each has exactly one jump to the enrolled label (`goto enrolled;` /
     `goto gw_enrolled;`) inside the `approved` fast path, AFTER that call.
  3. Neither handler reads the gateway-witnessed request fields except the gateway one:
     `gateway_attests_peer_cert(` / `gateway_attested_peer_cert_pem(` never appear in
     agent_service_impl.cpp.
  4. The refusal is a gRPC status: the gate apply header never calls set_accepted(.
  5. main.cpp registers --agent-reregistration-proof with CLI::IsMember (a typo must refuse boot)
     and the Config default is "audit".
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "server" / "core" / "src"
FILES = {
    "server": SRC / "server.cpp",
    "direct": SRC / "agent_service_impl.cpp",
    "gateway": SRC / "gateway_service_impl.cpp",
    "apply_hdr": SRC / "agent_reregistration_apply.hpp",
    "main_cpp": SRC / "main.cpp",
    "cfg": ROOT / "server" / "core" / "include" / "yuzu" / "server" / "server.hpp",
}


def strip_comments(text):
    # Whole-line comments only: a block-comment regex would swallow spans between a "/*" that sits
    # inside a string literal (a route glob) and the next "*/", hiding real code.
    keep = []
    for line in text.splitlines():
        t = line.lstrip()
        if t.startswith("//") or t.startswith("/*") or t.startswith("*"):
            continue
        keep.append(line)
    return "\n".join(keep)


def read(path):
    return strip_comments(path.read_text(encoding="utf-8"))




def run(texts):
    """Return the list of failures for the given {name: source text} mapping."""
    failures = []

    def check(cond, msg):
        if not cond:
            failures.append(msg)

    server, direct, gateway = texts["server"], texts["direct"], texts["gateway"]
    apply_hdr, main_cpp, cfg = texts["apply_hdr"], texts["main_cpp"], texts["cfg"]

    # 1. server.cpp wiring
    check(server.count("agent_service_.set_agent_identity_hooks(hooks)") == 1,
          "server.cpp must wire the hooks into agent_service_ exactly once")
    check(server.count("gateway_service_->set_agent_identity_hooks(hooks)") == 1,
          "server.cpp must wire the SAME hooks into gateway_service_ exactly once")
    check(server.count("agent_service_.set_reregistration_proof_mode(proof_mode)") == 1
          and server.count("gateway_service_->set_reregistration_proof_mode(proof_mode)") == 1,
          "server.cpp must set the proof mode on BOTH services")
    check(server.count("agent_service_.set_agent_identity_hooks(nullptr)") == 1
          and server.count("gateway_service_->set_agent_identity_hooks(nullptr)") == 1,
          "server.cpp must clear the hooks on both services at shutdown")
    a_sig = server.find("agent_service_.set_agent_cert_signer(cert_signer)")
    a_hook = server.find("agent_service_.set_agent_identity_hooks(hooks)")
    check(0 <= a_sig < a_hook,
          "the hooks are wired in the CA-active block, after the signer")
    check("rev.revocation_reason != kRevokeReasonReenrolled" in server,
          "sign_agent_csr's HIGH-2 guard must skip a leaf revoked as 'reenrolled'")

    # 2. both handlers apply the gate before the jump
    for name, text, label in (("agent_service_impl.cpp", direct, "enrolled"),
                              ("gateway_service_impl.cpp", gateway, "gw_enrolled")):
        check(text.count("apply_reregistration_gate(") == 1,
              f"{name}: exactly one apply_reregistration_gate( call")
        jumps = [m.start() for m in re.finditer(r"goto\s+" + label + r"\s*;", text)]
        check(len(jumps) == 1, f"{name}: exactly one `goto {label};` (found {len(jumps)})")
        if jumps and "apply_reregistration_gate(" in text:
            check(text.find("apply_reregistration_gate(") < jumps[0],
                  f"{name}: the gate must be applied BEFORE the jump to {label}")

    # 2b. UP-2: the gate also runs when the pending row is ABSENT (an id that still holds a live
    #     leaf must not enrol afresh without proof): each handler calls the gate lambda twice.
    for name, text in (("agent_service_impl.cpp", direct), ("gateway_service_impl.cpp", gateway)):
        check(text.count("run_reregistration_gate()") == 2,
              f"{name}: run_reregistration_gate() must be called for the approved row AND the absent row")
        check("if (!prior || *prior == auth::PendingStatus::pending)" in text,
              f"{name}: the absent-or-pending-row gate call is missing")

    # 3. the witnessed fields are a gateway-only input
    for field in ("gateway_attests_peer_cert(", "gateway_attested_peer_cert_pem("):
        check(field not in direct, f"agent_service_impl.cpp must not read {field} (direct path ignores it)")
        check(field in gateway, f"gateway_service_impl.cpp must read {field}")

    # 4. refusal is a status
    check("set_accepted(" not in apply_hdr, "agent_reregistration_apply.hpp must refuse by gRPC status only")
    check("UNAUTHENTICATED" in apply_hdr and "UNAVAILABLE" in apply_hdr,
          "the apply header answers UNAUTHENTICATED (refusal) and UNAVAILABLE (lookup failure)")

    # 5. option + default
    check('"--agent-reregistration-proof"' in main_cpp and
          re.search(r'--agent-reregistration-proof.*?CLI::IsMember\(\{"off", "audit", "enforce"\}\)',
                    main_cpp, re.S) is not None,
          "main.cpp must register --agent-reregistration-proof with CLI::IsMember(off|audit|enforce)")
    check('agent_reregistration_proof{"audit"}' in cfg,
          'Config::agent_reregistration_proof must default to "audit"')

    # 6. the test seam override_cert_proof_for_test is declared in agent_service_impl.hpp, used once
    #    in agent_service_impl.cpp, and called by NO other production translation unit.
    stray = [p.name for p in SRC.iterdir()
             if p.suffix in (".cpp", ".hpp", ".h", ".cc")
             and p.name not in ("agent_service_impl.hpp", "agent_service_impl.cpp")
             and "override_cert_proof_for_test" in p.read_text(encoding="utf-8", errors="replace")]
    check(not stray, "override_cert_proof_for_test (a test seam) must not appear in " + ", ".join(stray))

    # 7. the flush thread is spawned under lifecycle_mu_ with the teardown re-check (like the typed-source
    #    purge start), and stop() joins it BEFORE the forced flush.
    spawn = server.find("reregistration_flush_thread_ = std::thread(")
    check(server.count("reregistration_flush_thread_ = std::thread(") == 1 and spawn > 0,
          "server.cpp must spawn reregistration_flush_thread_ exactly once")
    if spawn > 0:
        head = server[max(0, spawn - 400):spawn]
        check("lifecycle_mu_" in head and "!teardown_complete_" in head and "stop_requested_" in head,
              "the reregistration_flush_thread_ spawn must hold lifecycle_mu_ and re-check "
              "teardown_complete_/stop_requested_")
    join = server.find("reregistration_flush_thread_.join()")
    forced = server.find("flush_reregistration_audit_summary(audit_store_.get(), &metrics_, /*force=*/true)")
    check(0 < join < forced, "stop() must join reregistration_flush_thread_ before the forced flush")
    return failures


def main():
    texts = {k: read(v) for k, v in FILES.items()}
    failures = run(texts)
    if failures:
        print("WP01 wiring tripwire FAILED:")
        for f in failures:
            print("  -", f)
        sys.exit(1)
    print("WP01 wiring tripwire OK")


if __name__ == "__main__":
    main()
