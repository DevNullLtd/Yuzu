#pragma once

/// @file outbound_destination_guard.hpp
/// Destination-ADDRESS guard for the operator-supplied URLs the server delivers to (webhooks and
/// offload targets; #4816 / #3870, scan finding F43). The URL-text policy lives in
/// outbound_url_policy.hpp; this file adds the resolved-address half, built on the address
/// classifier the OIDC egress policy already owns (oidc_egress_policy.hpp) and the bounded
/// resolver (bounded_resolver.hpp). EXTEND those, never fork a second classifier.
///
/// SCOPE (owner ruling, WP10 first slice). Refused at delivery, on EVERY resolved address:
/// unspecified (0.0.0.0/8, ::), link-local (169.254.0.0/16 incl. the 169.254.169.254 cloud
/// metadata address, fe80::/10), the other cloud-metadata addresses, multicast and the reserved
/// 240.0.0.0/4 block, with IPv4-mapped / NAT64 / 6to4 forms judged by the embedded address. These
/// are `egress::decision(c, /*allow_private=*/true) == Refuse`: the tier no switch ever opens.
/// Loopback and RFC 1918 / unique-local / carrier-grade-NAT destinations are NOT refused here:
/// an on-prem receiver on a private address is routine, and the opt-in policy for them is the
/// separate `security.offload_url_policy` setting (#4816), which stays open. Do not widen this
/// guard to loopback or private ranges without that setting.
///
/// RESOLVE ONCE, CONNECT PINNED. The delivery path resolves a NAME exactly once, vets every
/// answer, and connects to the vetted address (httplib `set_hostname_addr_map`, which keeps the
/// Host header and TLS name verification on the name), so an answer that changes between check and
/// connect (DNS rebinding) cannot reach a refused address. A literal address needs no lookup. An
/// unresolvable name fails CLOSED (`unresolved`), never "connect and see".
///
/// Create time can only judge a LITERAL host (no blocking DNS in a request handler):
/// `url_literal_destination_refused`. Delivery-time vetting is the one that covers names and rows
/// that bypassed create.

#include "bounded_resolver.hpp"
#include "oidc_egress_policy.hpp"
#include "outbound_url_policy.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

enum class DestinationVerdict : std::uint8_t {
    Allow,
    Refused,    ///< a resolved address is in the never-allowed tier
    Unresolved, ///< the name did not resolve (or the resolver was busy / timed out): fail closed
};

struct VettedDestination {
    DestinationVerdict verdict{DestinationVerdict::Unresolved};
    /// Set only for an Allow on a resolved NAME: the numeric address to connect to. Empty for a
    /// literal host (nothing to pin).
    std::string pinned_ip;
    /// The host as httplib knows it (userinfo/port/brackets removed): the addr-map key.
    std::string host;
    /// Fixed class label of the refused address (egress::class_name), never the address itself.
    const char* refused_class{""};
};

namespace detail {

/// `host[:port]` or `[v6][:port]` -> bare host (brackets and port removed). Empty when malformed.
[[nodiscard]] inline std::string bare_host(std::string_view host_port) {
    if (host_port.empty())
        return {};
    if (host_port.front() == '[') {
        const auto close = host_port.find(']');
        if (close == std::string_view::npos || close == 1)
            return {};
        return std::string(host_port.substr(1, close - 1));
    }
    const auto colon = host_port.rfind(':');
    return std::string(host_port.substr(0, colon == std::string_view::npos ? host_port.size()
                                                                           : colon));
}

/// True when `c` is in the tier no operator switch opens (see the file banner).
[[nodiscard]] constexpr bool destination_class_never_allowed(oidc::egress::AddressClass c) noexcept {
    return oidc::egress::decision(c, /*allow_private=*/true) == oidc::egress::Verdict::Refuse;
}

} // namespace detail

/// Create-time check: true when the URL's host is a LITERAL address in the never-allowed tier
/// (`http://169.254.169.254/`, `http://[fe80::1]/`, `http://0.0.0.0/`). Names are not judged here.
[[nodiscard]] inline bool url_literal_destination_refused(std::string_view url) {
    const auto parts = url_delivery_parts(url);
    const auto host = detail::bare_host(parts.host_port);
    if (host.empty())
        return false;
    const auto cls = oidc::egress::classify_literal(host);
    return cls && detail::destination_class_never_allowed(*cls);
}

/// Judge every address of one resolver answer (pure). Any refused address refuses the whole
/// answer: the caller does not control which one a connect would pick.
[[nodiscard]] inline VettedDestination vet_resolved_addresses(const std::string& host,
                                                              const std::vector<std::string>& addrs) {
    VettedDestination out;
    out.host = host;
    if (addrs.empty())
        return out; // Unresolved
    for (const auto& a : addrs) {
        const auto cls = oidc::egress::classify_literal(a);
        if (!cls) { // the resolver returned text that is not a canonical address: fail closed
            out.verdict = DestinationVerdict::Unresolved;
            return out;
        }
        if (detail::destination_class_never_allowed(*cls)) {
            out.verdict = DestinationVerdict::Refused;
            out.refused_class = oidc::egress::class_name(*cls);
            return out;
        }
    }
    out.verdict = DestinationVerdict::Allow;
    out.pinned_ip = addrs.front();
    return out;
}

/// Delivery-time vetting of `url`'s destination: a literal is classified directly; a name is
/// resolved ONCE through the bounded resolver (`lookup` injectable for tests) and every answer
/// judged. The caller connects to `pinned_ip` when it is non-empty.
[[nodiscard]] inline VettedDestination
vet_delivery_destination(std::string_view url,
                         std::chrono::milliseconds resolve_timeout = std::chrono::seconds(3),
                         net::LookupFn lookup = {}) {
    const auto parts = url_delivery_parts(url);
    VettedDestination out;
    out.host = detail::bare_host(parts.host_port);
    if (out.host.empty())
        return out; // Unresolved: not a host we can judge
    if (const auto cls = oidc::egress::classify_literal(out.host)) {
        if (detail::destination_class_never_allowed(*cls)) {
            out.verdict = DestinationVerdict::Refused;
            out.refused_class = oidc::egress::class_name(*cls);
        } else {
            out.verdict = DestinationVerdict::Allow; // literal: nothing to pin
        }
        return out;
    }
    const auto resolved = net::bounded_resolve(out.host, resolve_timeout, std::move(lookup));
    if (resolved.status != net::ResolveStatus::kOk)
        return out; // Unresolved
    return vet_resolved_addresses(out.host, resolved.addresses);
}

} // namespace yuzu::server
