#pragma once

/// @file gateway_peer_policy.hpp
/// The pure admission decision for a gateway-upstream peer.
///
/// WHO DECIDES. `decide()` is the single place that answers "may this caller use
/// the gateway-upstream service". Nothing else reimplements the rule; the guard
/// (gateway_peer_guard.hpp) is the only production caller and applies it before
/// any request is processed.
///
/// WHAT IT REQUIRES. All of the following, in this order; a caller is admitted
/// only if every one holds:
///   1. a ServerContext exists (`NullContext`; there is NO test exemption),
///   2. the transport authenticated the peer (`NotAuthenticated`). A PEM present
///      on an unauthenticated peer is a deny, never a pass,
///   3. a client certificate was presented (`NoCert`),
///   4. the certificate parses (`BadCert`),
///   5. it lists serverAuth in its extendedKeyUsage (`NoServerAuthEku`); the pin
///      is the identity and this is a requirement on the pinned certificate too,
///   6. its SPKI SHA-256 is in the pin set (`NotPinned`): the KEY is pinned, never
///      an issuer, a subject name or CA membership,
///   7. `now` lies inside its validity window (`OutsideValidity`). The window opens
///      `kNotBeforeLeeway` BEFORE notBefore (this check's own allowance; a TLS
///      handshake applies none) and ends strictly at notAfter. Both bounds are
///      whole seconds and `now` is floored to a second before comparing.
///
/// FAIL CLOSED. A default-constructed `Decision` is a deny. An empty pin set is an
/// `InternalError` deny (boot refuses to start with zero pins, so reaching this is
/// a wiring defect, not an operator state). Any exception while deciding is an
/// `InternalError` deny.
///
/// REASONS are a CLOSED set of 8. `to_label()` is the stable snake_case string used
/// as the metric `reason` label; adding a value means adding a label, a test row
/// and a pre-seeded series in the guard.
///
/// The decision is pure: no I/O, no globals, no clock read (the caller passes
/// `now`). Nothing here depends on gRPC. There is no revocation check and no pin
/// reload: see `gateway_peer_pinset.hpp`.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "gateway_peer_cert.hpp"
#include "gateway_peer_pinset.hpp"

namespace yuzu::server::gateway_peer {

enum class DenyReason : std::uint8_t {
    NullContext,
    NotAuthenticated,
    NoCert,
    BadCert,
    NoServerAuthEku,
    NotPinned,
    OutsideValidity,
    InternalError,
};

inline constexpr std::array<DenyReason, 8> kAllDenyReasons{
    DenyReason::NullContext,      DenyReason::NotAuthenticated, DenyReason::NoCert,
    DenyReason::BadCert,          DenyReason::NoServerAuthEku,  DenyReason::NotPinned,
    DenyReason::OutsideValidity,  DenyReason::InternalError,
};
// A reason added to the enum without a row here would be missing from every pre-seeded
// metric series and from the label tests; the enum's last value is InternalError.
static_assert(kAllDenyReasons.size() == static_cast<std::size_t>(DenyReason::InternalError) + 1,
              "kAllDenyReasons must list every DenyReason");

[[nodiscard]] constexpr std::string_view to_label(DenyReason r) {
    switch (r) {
    case DenyReason::NullContext:
        return "null_context";
    case DenyReason::NotAuthenticated:
        return "not_authenticated";
    case DenyReason::NoCert:
        return "no_cert";
    case DenyReason::BadCert:
        return "bad_cert";
    case DenyReason::NoServerAuthEku:
        return "no_server_auth_eku";
    case DenyReason::NotPinned:
        return "not_pinned";
    case DenyReason::OutsideValidity:
        return "outside_validity";
    case DenyReason::InternalError:
        return "internal_error";
    }
    return "internal_error";
}

/// A certificate is treated as valid from `kNotBeforeLeeway` before its notBefore. Expiry has
/// no allowance.
inline constexpr std::chrono::minutes kNotBeforeLeeway{5};

/// What the transport told us about the caller. `cert_pem` is kept even when
/// `peer_authenticated` is false so the two are decided separately.
struct PeerEvidence {
    bool context_present{false};
    bool peer_authenticated{false};
    std::string cert_pem;
};

struct Decision {
    bool allowed{false};
    DenyReason reason{DenyReason::InternalError}; ///< meaningful only when !allowed
    /// SPKI SHA-256 (64 lowercase hex) of the presented certificate, set only when it parsed,
    /// so a denial's audit attribution does not parse the certificate a second time.
    std::string spki_sha256_hex;

    [[nodiscard]] static Decision allow() { return Decision{true, DenyReason::InternalError, {}}; }
    [[nodiscard]] static Decision deny(DenyReason r) { return Decision{false, r, {}}; }
};

/// See the file banner. Never throws.
[[nodiscard]] inline Decision decide(const PeerEvidence& ev, const PinSet& pins,
                                     std::chrono::system_clock::time_point now) noexcept {
    try {
        if (!ev.context_present)
            return Decision::deny(DenyReason::NullContext);
        if (!ev.peer_authenticated)
            return Decision::deny(DenyReason::NotAuthenticated);
        if (ev.cert_pem.empty())
            return Decision::deny(DenyReason::NoCert);
        if (pins.empty())
            return Decision::deny(DenyReason::InternalError);

        const auto facts = parse_cert_facts(ev.cert_pem);
        if (!facts || facts->spki_sha256_hex.empty())
            return Decision::deny(DenyReason::BadCert);
        const auto deny = [&facts](DenyReason r) {
            Decision d = Decision::deny(r);
            d.spki_sha256_hex = facts->spki_sha256_hex;
            return d;
        };
        if (!facts->has_server_auth_eku)
            return deny(DenyReason::NoServerAuthEku);
        if (!pins.contains(facts->spki_sha256_hex))
            return deny(DenyReason::NotPinned);
        const CertInstant now_s = std::chrono::floor<std::chrono::seconds>(now);
        if (now_s < facts->not_before - kNotBeforeLeeway || now_s > facts->not_after)
            return deny(DenyReason::OutsideValidity);

        Decision d = Decision::allow();
        d.spki_sha256_hex = facts->spki_sha256_hex;
        return d;
    } catch (...) {
        return Decision::deny(DenyReason::InternalError);
    }
}

using WallClockFn = std::function<std::chrono::system_clock::time_point()>;

/// `decide` bound to its two inputs: the boot pin set and the wall clock (validity checks).
/// A null pin set means "no pins" (an `InternalError` deny); a null clock means
/// `system_clock::now`. Immutable after construction.
class GatewayPeerPolicy {
public:
    explicit GatewayPeerPolicy(std::shared_ptr<const PinSet> pins, WallClockFn clock = {})
        : pins_(std::move(pins)), clock_(std::move(clock)) {}

    /// Never throws.
    [[nodiscard]] Decision decide(const PeerEvidence& ev) const noexcept {
        try {
            if (!pins_)
                return Decision::deny(DenyReason::InternalError);
            const auto now = clock_ ? clock_() : std::chrono::system_clock::now();
            return gateway_peer::decide(ev, *pins_, now);
        } catch (...) {
            return Decision::deny(DenyReason::InternalError);
        }
    }

private:
    std::shared_ptr<const PinSet> pins_;
    WallClockFn clock_;
};

} // namespace yuzu::server::gateway_peer
