#pragma once

/// @file resolver_errors.hpp
/// The ONE definition of "the resolver answered, and the answer is that there is no such data",
/// as opposed to "the lookup failed". `bounded_resolver.hpp` maps its platform error code here
/// (CRL source registration is its first consumer), so every later consumer shares ONE classifier
/// and none can disagree about NXDOMAIN.
///
/// The codes are the platform resolver's return codes. On the platform whose codes would need
/// socket includes, literals are used instead, so that branch needs none.

#ifndef _WIN32
#include <netdb.h>
#endif

namespace yuzu::server::net {

/// True for the resolver's definitive "no such name / no address of this kind" (NXDOMAIN, NODATA).
/// EVERY other nonzero code (EAI_AGAIN, EAI_FAIL, EAI_SYSTEM, EAI_MEMORY, WSATRY_AGAIN,
/// WSANO_RECOVERY, timeouts, ...) is a failure, never an answer.
[[nodiscard]] constexpr bool resolver_code_is_no_data(int rc) noexcept {
#ifdef _WIN32
    return rc == 11001 /* WSAHOST_NOT_FOUND */ || rc == 11004 /* WSANO_DATA */;
#else
    bool r = false;
#ifdef EAI_NONAME
    r = r || rc == EAI_NONAME;
#endif
#ifdef EAI_NODATA
    r = r || rc == EAI_NODATA;
#endif
    return r;
#endif
}

} // namespace yuzu::server::net
