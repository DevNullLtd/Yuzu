# ADR-0066: gRPC is the permanent transport — the QUIC migration (#376) is withdrawn

- **Status:** Accepted
- **Date:** 2026-10-08
- **Authors:** Nathan Dornbrook
- **Withdraws:** issue #376 ("Strategic: migrate transport off gRPC to QUIC") and the never-merged
  `docs/adrs/0001-quic-transport-msquic-quicer.md` (msquic + quicer, "Accepted" 2026-05-07) and
  `docs/adrs/0002-gateway-scaling.md` ("Proposed"). Both lived only on `feat/quic-transport` and never
  reached `dev`; they are preserved, with the spike results, at the git tag `archive/quic-transport`
  (`436a95ed9`).
- **Related:** #4722 (gRPC transport state of play — the umbrella that now owns transport hardening),
  #375 / #518 (Windows grpc static-link), `docs/pki-architecture.md`, `docs/auth-architecture.md`,
  ADR-2002 (HA — built on the gRPC gateway).

## Context

Since April 2026 a migration from gRPC to QUIC (msquic on the C++ side, quicer on the Erlang gateway)
was recorded as the "strategic escape" from the grpc/abseil build cost (#375, #501, #518) and as the
future home for several security residuals. The work reached a branch with 71 commits — a transport
abstraction, an msquic backend, spike results — but it was never merged and has been dormant since
2026-05-16. Its PR 5 cutover was gated on a dual-stack pilot (#892), on shipping and patching an msquic
dynamic library and its quictls OpenSSL fork on every platform (#1027, #1028), and on a pre-cutover
blocker list (#1044).

Meanwhile everything built since assumes gRPC: the PKI programme (PR1–PR5d), the mTLS management
plane (#1422), the TLS-by-default work (#4722), and the HA architecture's gateway-fronted routing
(ADR-2002). The Windows static-link configuration the escape was meant to retire has been stable since
April. An October 2026 assessment of the ~50 open gateway issues by the project lead (not separately
published) classified nearly all of them as application-level or small grpcbox fixes, not transport limits.

Several docs and code comments nonetheless deferred real security work "to the QUIC era". With no
QUIC coming, those deferrals point at nothing.

## Decision

1. **gRPC (C++ grpc on server and agent, grpcbox on the Erlang gateway) is Yuzu's permanent transport.**
   Protobuf stays the wire format. No alternative transport is planned.
2. **#376 and every QUIC-only issue are to be closed as not planned when this ADR merges.** QUIC-ladder
   follow-ups that describe a defect also present on `dev` are re-parented to #4722; the rest are closed
   as obsolete.
3. **Every "QUIC-era" deferral gets a gRPC-native owner:**

| Capability QUIC was to provide | gRPC-native owner |
|---|---|
| Agent's real origin IP at the gateway (`gateway_observed_peer`; #1064, #1172; ADR-0013 residual) #1172. grpcbox already holds the agent's socket (chatterbox `sock:peername/1`) but does not pass the peer to service handlers; the fix is a small vendored accessor alongside the existing grpcbox patches, keeping the `x-forwarded-for` path for proxied deployments. #1172's written scope is XFF-only and must be widened to cover the accessor. The proto field is already transport-agnostic; no wire change. |
| Cryptographic agent identity and mutual auth across the agent↔gateway hop (PKI R-5/R-6, #1292; gateway half of #1677; the "issued-but-dormant" agent leaf) **#5578** (a separate design ADR), which becomes #1292's dependency in place of #376: TLS-level *optional* client-certificate verification on the gateway's agent listener (`verify_peer` + `fail_if_no_peer_cert=false`, already configurable in the patched grpcbox), plus gateway-forwarded, gateway-attested identity and revocation enforced at the gateway edge. It must not install a grpcbox `auth_fun` on `:50051`, because that rejects every certless peer and breaks agent bootstrap (see the PKI routed concern). It must also handle a *presented-but-invalid* certificate aborting the handshake under `verify_peer` (a stale-leaf agent must not be locked out of re-enrolment), and handlers having no access to the peer certificate today. |
| TLS 1.3, session resumption, mandatory TLS on every hop (#1293, #660) #4722's five-PR sequence (minimum stays TLS 1.2; #1293 adds 1.3 on the gateway hops). These were previously framed as stepping stones to QUIC; they are now the end state. |
| Retirement of the Windows grpc/abseil static-link workaround (#375, #518) | None. The `triplets/x64-windows.cmake` + `meson.build` hand-wiring is permanent and load-bearing. #518 is re-triaged on its own merits. |

## Consequences

- The transport-related residuals in the PKI, auth and attack-chain docs stay open, but they are owned and sequenced rather than waiting on a dependency that will never ship.
- The Windows build keeps its two-half static-link configuration indefinitely. `.claude/agents/build-ci.md`'s #375 history remains required reading.
- The Alpine/musl agent ambition loses the path the QUIC ADR gave it. That ADR's assessment was that grpc/abseil have no usable musl story in vcpkg (see `docs/per-target-agent-build-pipeline-scope.md` at the `archive/quic-transport` tag; it never reached `dev`). Any future musl agent needs its own decision.
- ECDSA P-256/P-384 for the internal CA (`x509_ca.hpp`) stays. It was chosen with QUIC in mind, but it is equally the right choice for gRPC over TLS 1.2 and 1.3.
- The account-lockout follow-up UP-2, also parked on "QUIC-era auth work", is re-homed to #5579.
- A proposal to rewrite the gateway transport (for example Cowboy + gun) is a separate decision. This ADR does not adopt one. The default path is the grpcbox fix backlog (#1172, #1293, #635, #3913, #5175) and grpcbox upgrades.
