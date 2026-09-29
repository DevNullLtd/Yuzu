#pragma once

/// @file ota_audit_key.hpp
///
/// Composes the bucket key for the OTA identity-deny AUDIT rate limiter, as a
/// PURE function.
///
/// WHY THIS IS ITS OWN CHOKEPOINT, and it is the whole reason the file exists:
/// two separate blocking defects have now been found in this one string.
///
///  1. It was originally keyed on the caller's own `claimed_agent_id`. A caller
///     varying that per request minted a fresh bucket every time — and
///     `RateLimiter::allow` admits any NEW key unconditionally — so the bound
///     applied only to a caller obliging enough to reuse one value.
///
///  2. Re-keying on the peer fixed that but left a subtler hole: the admission
///     key reports `mode="cert"` for ANY certificate the listener accepted,
///     without consulting the recognizer. On a multi-CA trust bundle a peer
///     holding a certificate from some OTHER CA in that bundle could set
///     `CN=<victim agent id>` and land in the same bucket as the victim, then
///     spend the victim's allowance and suppress the victim's audit rows on
///     demand — a third party selecting off another principal's forensic
///     attribution.
///
/// `reason` is therefore part of the key, and that is what closes (2): a
/// foreign-CA peer can only ever provoke `foreign_ca`, while a recognised peer's
/// denials carry `agent_id_mismatch` or `agent_id_missing`. The two land in
/// disjoint namespaces, so neither can consume the other's tokens. It is also
/// right on its own terms — different denial reasons are different forensic
/// classes and should not suppress each other.
///
/// Being a pure function is not incidental either: while this lived inline, a
/// mutation reverting the key to `claimed_agent_id` left the ENTIRE server
/// suite green (42,326 assertions). See `test_ota_audit_key.cpp`.

#include <string>
#include <string_view>

namespace yuzu::server::detail {

/// Upper bound on the peer-identity portion of the key. A certificate CN or SAN
/// is peer-supplied text, and while a cert must be signed by a trusted CA to get
/// here at all, an operator's own CA can mint an arbitrarily long CN. The
/// limiter's map has no eviction that runs in production, so an unclamped key
/// makes every entry's cost caller-chosen as well as permanent.
inline constexpr std::size_t kMaxAuditKeyIdentity = 256;

/// Compose the rate-limit bucket key for one identity denial.
///
/// SEPARATOR SAFETY: only the LAST field is variable-length and peer-influenced.
/// `rpc` and `reason` are compile-time literals from closed sets and `key_mode`
/// is one of "cert"/"peer_ip"/"unknown", so no choice of separator inside the
/// peer identity can make two distinct triples collide — the prefix is
/// unambiguous before the identity begins.
[[nodiscard]] inline std::string ota_identity_audit_key(std::string_view rpc,
                                                        std::string_view reason,
                                                        std::string_view key_mode,
                                                        std::string_view peer_key) {
    std::string out;
    out.reserve(rpc.size() + reason.size() + key_mode.size() +
                std::min(peer_key.size(), kMaxAuditKeyIdentity) + 3);
    out.append(rpc).push_back('|');
    out.append(reason).push_back('|');
    out.append(key_mode).push_back('|');
    out.append(peer_key.substr(0, std::min(peer_key.size(), kMaxAuditKeyIdentity)));
    return out;
}

} // namespace yuzu::server::detail
