#pragma once

/// @file agent_reregistration_gate.hpp
///
/// WP01 (agent re-registration identity): the ONE decision both agent ingest paths make before
/// re-admitting an agent id whose enrollment row is already `approved` - `AgentServiceImpl::Register`
/// (direct) and `GatewayUpstreamServiceImpl::ProxyRegister` (gateway-relayed). EXTEND it, never
/// fork a per-handler copy: the two fast paths used to be hand-copied `approved -> goto enrolled`
/// jumps keyed on the caller-supplied `info.agent_id` alone, and this header exists so they cannot
/// drift apart again.
///
/// Pure decision code: no I/O, no store or wire types. It lives in server/core, NOT
/// `common/include/` (CLAUDE.md firewall), because it is trust-boundary authority.
///
/// THE RULE. An already-enrolled id with a LIVE (unexpired, active) agent leaf in `ca_issued` is an
/// identity that has a credential in the field, so a certificate-less re-registration is a claim,
/// not a proof. It is admitted only when the caller
///   - presents the current leaf (direct: the mTLS peer certificate; gateway: the certificate the
///     gateway WITNESSED, `RegisterRequest.gateway_attested_peer_cert_pem`), or
///   - presents a fresh SINGLE-USE enrollment token (the lost-key recovery; the handler enforces the
///     single-use bound and supersedes the older leaf after issuing the new one).
/// A revoked, unexpired agent identity with no live leaf is refused outright, token or no token
/// (clearing a revocation is an operator action; `sign_agent_csr`'s HIGH-2 guard agrees). An id with
/// no live and no revoked leaf (first enrolment completing, an expired leaf, an operator-CA agent)
/// is unchanged: only a LIVE leaf triggers the gate.
///
/// WHAT THE GATE IS NOT. It is inert, by construction, where no proof can exist: `--no-tls`,
/// plain-TLS without a client CA, and agents carrying operator-CA certificates (no `ca_issued` agent
/// leaf for the id). Those get NO protection from it; `docs/pki-architecture.md` says so in writing.
///
/// ROLLOUT. `off | audit | enforce` (`--agent-reregistration-proof`). `audit` (the default) decides
/// and counts exactly as `enforce` would but admits as before; `enforce` refuses. The refusal is a
/// gRPC status (`UNAUTHENTICATED`, uniform message, no oracle for "this id has a leaf"), NEVER
/// `accepted=false` - that is a permanent rejection to the agent (`agent.cpp` returns from `run()`),
/// whereas a gRPC status keeps its retry loop alive so it self-heals once the operator issues a
/// token. The refusal happens BEFORE `registry_.register_agent` (which replaces the live session
/// and revokes device tokens), so a refused impostor cannot kick the real agent.

#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include "ca_store.hpp"

namespace yuzu::server {

enum class ReregistrationProofMode { Off, Audit, Enforce };

[[nodiscard]] constexpr std::string_view to_string(ReregistrationProofMode m) {
    switch (m) {
    case ReregistrationProofMode::Off:
        return "off";
    case ReregistrationProofMode::Audit:
        return "audit";
    case ReregistrationProofMode::Enforce:
        return "enforce";
    }
    return "audit";
}

/// Exact, lower-case spellings only. nullopt for anything else: a typo must fail boot, never fall
/// back to a weaker mode (the caller refuses to start).
[[nodiscard]] constexpr std::optional<ReregistrationProofMode>
parse_reregistration_proof_mode(std::string_view s) {
    if (s == "off")
        return ReregistrationProofMode::Off;
    if (s == "audit")
        return ReregistrationProofMode::Audit;
    if (s == "enforce")
        return ReregistrationProofMode::Enforce;
    return std::nullopt;
}

/// What the caller could show. Computed by the handler from its own transport; the gate trusts
/// nothing else the request carries.
struct ReregistrationEvidence {
    /// The presented/witnessed leaf is Yuzu-issued, unexpired, unrevoked and names THIS agent id.
    bool cert_proves_identity{false};
    /// The request carries a non-empty enrollment token (validity is decided by the token block).
    bool token_presented{false};
    /// Gateway path only: an upgraded gateway ran the witness overwrite for this request
    /// (`gateway_attests_peer_cert`). Always true on the direct path, where the server sees the
    /// transport itself.
    bool transport_can_prove{true};
};

enum class ReregistrationOutcome {
    NoLeafOnRecord,        ///< No live and no revoked leaf: not this gate's business (admit).
    ProvenByLeaf,          ///< The current leaf was shown (admit).
    ViaToken,              ///< No cert proof, a token was presented: route to the token block.
    RefuseNoProof,         ///< Live leaf, no cert proof, no token.
    RefuseUnattested,      ///< As above, and the gateway could not witness (not upgraded).
    RefuseRevokedIdentity, ///< Revoked unexpired identity, nothing live: refused, token or not.
    LookupFailed,          ///< ca_store could not answer: cannot tell, never "no leaf".
};

[[nodiscard]] constexpr std::string_view to_string(ReregistrationOutcome o) {
    switch (o) {
    case ReregistrationOutcome::NoLeafOnRecord:
        return "no_leaf_on_record";
    case ReregistrationOutcome::ProvenByLeaf:
        return "proven_by_leaf";
    case ReregistrationOutcome::ViaToken:
        return "via_token";
    case ReregistrationOutcome::RefuseNoProof:
        return "no_proof";
    case ReregistrationOutcome::RefuseUnattested:
        return "unattested_gateway";
    case ReregistrationOutcome::RefuseRevokedIdentity:
        return "revoked_identity";
    case ReregistrationOutcome::LookupFailed:
        return "lookup_failed";
    }
    return "lookup_failed";
}

/// The decision. `leaf` is the `ca_store` read for the claimed agent id; its error alternative is a
/// genuine read failure and is NEVER folded into "no leaf".
[[nodiscard]] constexpr ReregistrationOutcome
decide_reregistration(const std::expected<AgentLeafState, std::string>& leaf,
                      const ReregistrationEvidence& ev) {
    if (!leaf)
        return ReregistrationOutcome::LookupFailed;
    // A revoked, unexpired agent leaf that is not a `reenrolled` supersession means an operator
    // (or the revocation sweep) withdrew this identity and nothing has cleared it:
    // `sign_agent_csr`'s HIGH-2 guard will refuse any issuance for the id, so a token would be
    // consumed for a leaf that can never be issued (UP-5: a live leaf beside a stale revoked one
    // wedged the agent). Decided BEFORE the token block, whatever else the caller shows, except
    // the current leaf (a renewal's own CSR is then refused by that guard, as before).
    if (leaf->has_revoked_unexpired && !ev.cert_proves_identity)
        return ReregistrationOutcome::RefuseRevokedIdentity;
    if (leaf->has_live) {
        if (ev.cert_proves_identity)
            return ReregistrationOutcome::ProvenByLeaf;
        if (ev.token_presented)
            return ReregistrationOutcome::ViaToken;
        return ev.transport_can_prove ? ReregistrationOutcome::RefuseNoProof
                                      : ReregistrationOutcome::RefuseUnattested;
    }
    if (leaf->has_revoked_unexpired)
        return ReregistrationOutcome::RefuseRevokedIdentity;
    return ReregistrationOutcome::NoLeafOnRecord;
}

/// True for the outcomes `enforce` refuses (a status, before any session state is touched).
[[nodiscard]] constexpr bool is_refusal(ReregistrationOutcome o) {
    return o == ReregistrationOutcome::RefuseNoProof ||
           o == ReregistrationOutcome::RefuseUnattested ||
           o == ReregistrationOutcome::RefuseRevokedIdentity;
}

/// Server-side hooks both services receive from `server.cpp`, set once before the gRPC servers
/// start and cleared at shutdown (the lifetime contract of `set_agent_cert_signer`). All three are
/// wired only when this install has its OWN issuing CA; an unset bundle makes the gate inert.
struct AgentIdentityHooks {
    /// `CaStore::agent_leaf_state` (DB clock, one indexed read).
    std::function<std::expected<AgentLeafState, std::string>(const std::string& agent_id)>
        leaf_state;
    /// Gateway path: does the witnessed PEM prove `agent_id`? Yuzu-issued (chain to OUR CA),
    /// within its validity window, unrevoked, CN equal to `agent_id`, size-bounded.
    std::function<bool(const std::string& cert_pem, const std::string& agent_id)>
        attested_leaf_proves;
    /// After a token re-enrolment issued `new_cert_pem`: revoke the agent's OTHER live leaves
    /// (`kRevokeReasonReenrolled`). Best effort, logged and audited by the implementation.
    /// Returns false when the older leaves could NOT be revoked (the agent already holds a good new
    /// leaf; the caller audits the failure, it does not fail the registration: best effort).
    std::function<bool(const std::string& agent_id, const std::string& new_cert_pem)>
        supersede_older_leaves;
};

/// The wire answer for every refusal. ONE uniform message: it must not reveal whether the id
/// exists, has a leaf, or is revoked (the reason is in the counter label and the server log).
inline constexpr std::string_view kReregistrationRefusalPublicMessage =
    "re-registration requires proof of the agent identity";

} // namespace yuzu::server
