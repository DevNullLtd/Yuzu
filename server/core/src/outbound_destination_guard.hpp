#pragma once

/// @file outbound_destination_guard.hpp
/// Destination-ADDRESS guard for the operator-supplied URLs the server delivers to (webhooks and
/// offload targets; #4816 / #3870, from the 2026-11-17 security scan). The URL-text policy lives in
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
/// Create time can only judge a host that needs no DNS: a canonical literal, or a numeric spelling
/// the OS resolver would read as an address (`http://2852039166/`, `0xa9fea9fe`,
/// `0251.0376.0251.0376`, `http://0/`), which `url_literal_destination_refused` refuses (a
/// spelling that parses as an address but not as a canonical one fails closed). Delivery-time
/// vetting is the one that covers real names and rows that bypassed create.
///
/// DUAL-STACK. A host that answers both families keeps its connect fallback: the vetted answers are
/// returned in connect order (IPv4 first) and the delivery tries each in turn, every one of which
/// was judged; a delivery never connects to an address that was not vetted.
///
/// OWN RESOLVER POOL. Delivery resolves through a pool of its own (`delivery_resolver_pool()`), never
/// the process pool CRL source registration uses (bounded_resolver.hpp: a consumer that must not be
/// starved needs its own pool, the OIDC precedent), so slow DNS for a webhook host cannot make CRL
/// registration answer busy, and the reverse.

#include "bounded_resolver.hpp"
#include "oidc_egress_policy.hpp"
#include "outbound_url_policy.hpp"
#include "refusal_throttle.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#endif

namespace yuzu::server {

enum class DestinationVerdict : std::uint8_t {
    Allow,
    Refused,    ///< a resolved address is in the never-allowed tier
    Unresolved, ///< the name did not resolve (or the resolver was busy / timed out): fail closed
};

struct VettedDestination {
    DestinationVerdict verdict{DestinationVerdict::Unresolved};
    /// Set only for an Allow on a resolved NAME: the vetted numeric addresses in connect order
    /// (IPv4 first). Empty for a literal host (nothing to pin).
    std::vector<std::string> pinned_ips;
    /// The host as httplib knows it (userinfo/port/brackets removed): the addr-map key.
    std::string host;
    /// Fixed class label of the refused address (egress::class_name), never the address itself.
    const char* refused_class{""};
};

/// The resolver pool webhook and offload-target delivery use (see the file banner). A leaked
/// function-local static, like `detail::process_pool()`: a delivery worker can reach it while
/// statics are being destroyed at exit and the 15 s gauge read can run during shutdown.
[[nodiscard]] inline const std::shared_ptr<net::ResolverPool>& delivery_resolver_pool() {
    static const std::shared_ptr<net::ResolverPool>& p =
        *new std::shared_ptr<net::ResolverPool>(std::make_shared<net::ResolverPool>());
    return p;
}
[[nodiscard]] inline int delivery_resolver_in_flight() {
    return delivery_resolver_pool()->in_flight.load();
}
[[nodiscard]] inline int delivery_resolver_pool_capacity() { return delivery_resolver_pool()->cap; }
[[nodiscard]] inline std::array<std::uint64_t, net::kResolveStatusCount>
delivery_resolver_outcome_counts() {
    return delivery_resolver_pool()->outcome_counts();
}

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

namespace detail {

/// True when the OS resolver would read `host` as a NUMERIC address by itself (no DNS): dotted
/// forms with octal/hex/short parts, a bare decimal or hex integer, IPv6 text. Judged with the
/// resolver's own parser (AI_NUMERICHOST) so the create check and the delivery connect agree.
[[nodiscard]] inline bool resolver_reads_as_numeric_host(const std::string& host) {
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;
    struct addrinfo* raw = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), nullptr, &hints, &raw);
    if (raw != nullptr)
        ::freeaddrinfo(raw);
    return rc == 0;
}

} // namespace detail

/// The closed `cause` label set of the delivery-refused counter and the delivery-log error text.
[[nodiscard]] constexpr const char* destination_cause(DestinationVerdict v) noexcept {
    return v == DestinationVerdict::Refused ? "destination_refused" : "destination_unresolved";
}

/// Create-time check: true when the URL's host needs no DNS and is not acceptable: a CANONICAL
/// literal in the never-allowed tier (`http://169.254.169.254/`, `http://[fe80::1]/`,
/// `http://0.0.0.0/`), or a numeric SPELLING the resolver accepts but the canonical parser does not
/// (`2852039166`, `0xa9fea9fe`, `0251.0376.0251.0376`, `0`): such a spelling is refused outright,
/// because delivery would classify the address the resolver returns (a metadata address among
/// them) and decline it, so accepting it at create only stores a target that can never deliver.
/// Real names are not judged here.
[[nodiscard]] inline bool url_literal_destination_refused(std::string_view url) {
    const auto parts = url_delivery_parts(url);
    const auto host = detail::bare_host(parts.host_port);
    if (host.empty())
        return false;
    if (const auto cls = oidc::egress::classify_literal(host))
        return detail::destination_class_never_allowed(*cls);
    return detail::resolver_reads_as_numeric_host(host);
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
    // Connect order: IPv4 first, then IPv6, each in resolver order. Every entry was judged above.
    for (const auto& a : addrs)
        if (a.find(':') == std::string::npos)
            out.pinned_ips.push_back(a);
    for (const auto& a : addrs)
        if (a.find(':') != std::string::npos)
            out.pinned_ips.push_back(a);
    return out;
}

/// Delivery-time vetting of `url`'s destination: a literal is classified directly; a name is
/// resolved ONCE through the delivery pool of the bounded resolver (`lookup` and `pool` injectable
/// for tests) and every answer judged. The caller connects to `pinned_ips` in order when non-empty.
[[nodiscard]] inline VettedDestination
vet_delivery_destination(std::string_view url,
                         std::chrono::milliseconds resolve_timeout = std::chrono::seconds(3),
                         net::LookupFn lookup = {},
                         std::shared_ptr<net::ResolverPool> pool = {}) {
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
    const auto resolved =
        net::bounded_resolve(out.host, resolve_timeout, std::move(lookup),
                             pool ? std::move(pool) : delivery_resolver_pool());
    if (resolved.status != net::ResolveStatus::kOk)
        return out; // Unresolved
    return vet_resolved_addresses(out.host, resolved.addresses);
}

} // namespace yuzu::server
