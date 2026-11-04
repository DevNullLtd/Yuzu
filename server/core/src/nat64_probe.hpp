#pragma once

/// @file nat64_probe.hpp
/// The ONE mapping from a bounded-resolver result for `ipv4only.arpa` to the shared NAT64 discovery
/// outcome (nat64_discovery.hpp). Used by the OIDC egress probe and any later consumer,
/// so they cannot classify a resolver result differently, and both resolve through the
/// ONE resolver (bounded_resolver.hpp) whose error classifier is resolver_errors.hpp.
///
/// Mapping: kOk -> answered / answered-none by whether any AAAA came back; kNotFound (NXDOMAIN,
/// NODATA: a definitive "no such data") -> answered-none; kTemporary (EAI_AGAIN, EAI_FAIL,
/// EAI_SYSTEM, ...) and an UNCLAMPED kTimeout -> failed; kBusy, and a kTimeout under a budget the
/// caller CLAMPED below a full lookup -> inconclusive (recorded nowhere).

#include "bounded_resolver.hpp"
#include "nat64_discovery.hpp"
#include "oidc_egress_policy.hpp"

#include <vector>

namespace yuzu::server::net {

/// The resolver pool EVERY NAT64 discovery lookup runs in: capacity ONE, process-wide. The cache's
/// single-flight (nat64_discovery.hpp) only covers callers still waiting; a lookup whose caller
/// timed out keeps its worker (and its slot) until the resolver returns. A cap-1 pool makes the
/// bound hold for the WORKER too: while a hung discovery lookup is outstanding, every new one is
/// refused kBusy (inconclusive), so discovery can never hold more than one thread or take a slot
/// from any other pool. Shared by every discovery consumer; a future one must use it too.
[[nodiscard]] inline std::shared_ptr<ResolverPool> nat64_probe_pool() {
    static const std::shared_ptr<ResolverPool>& p = *new std::shared_ptr<ResolverPool>(
        std::make_shared<ResolverPool>(1));
    return p;
}

[[nodiscard]] inline Nat64LookupOutcome
nat64_outcome_from_resolve(const ResolveResult& r, bool budget_clamped,
                           std::vector<::yuzu::server::oidc::egress::Ipv6>& out) {
    switch (r.status) {
    case ResolveStatus::kBusy:
        return Nat64LookupOutcome::kInconclusive;
    case ResolveStatus::kTimeout:
        return budget_clamped ? Nat64LookupOutcome::kInconclusive : Nat64LookupOutcome::kFailed;
    case ResolveStatus::kTemporary:
        return Nat64LookupOutcome::kFailed;
    case ResolveStatus::kNotFound:
        return Nat64LookupOutcome::kAnsweredNone;
    case ResolveStatus::kOk:
        break;
    }
    for (const auto& text : r.addresses)
        if (text.find(':') != std::string::npos)
            if (const auto v6 = ::yuzu::server::oidc::egress::parse_ipv6(text))
                out.push_back(*v6);
    return out.empty() ? Nat64LookupOutcome::kAnsweredNone : Nat64LookupOutcome::kAnswered;
}

} // namespace yuzu::server::net
