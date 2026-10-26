#pragma once

/// @file bounded_resolver.hpp
/// A name lookup with a hard time bound whose state is OWNED BY THE LOOKUP, never by the caller's
/// stack. Shared by the revocation-source registration check (revocation_source_service.cpp) and,
/// later, the CRL fetcher (2b-1b), so the two resolve the same way.
///
/// WHY NOT httplib's `getaddrinfo_with_timeout`: on glibc it hands a request that lives on the
/// CALLER's stack to the async resolver, and on timeout it ignores `EAI_NOTCANCELED`, so the
/// resolver's helper thread later writes into a dead frame (a use-after-free, plus a leak). This
/// header never does that: the blocking lookup runs on a worker thread that owns a heap-allocated
/// `State` through a `shared_ptr`; the caller waits on a condition variable with a timeout and, on
/// timeout, simply stops waiting. The worker finishes whenever the resolver returns, converts and
/// frees the `addrinfo` list itself, and releases the state. Nothing the worker touches belongs to
/// a caller.
///
/// RESOURCE LEDGER (what this adds): one DETACHED worker thread per outstanding lookup, bounded
/// by the pool's cap (`kMaxInFlightLookups` for the process pool; a lookup beyond the cap is
/// refused `kBusy`, never queued). A worker stuck in a resolver that never answers pins one slot
/// and one thread until process exit; the cap bounds that. Nothing is joined at shutdown: a worker
/// holds no pointer into any object that is destroyed (the shared state, the host string, the
/// lookup function and the pool are all owned through the worker's own copies / shared_ptrs).
///
/// The lookup function is injectable (`LookupFn`) so a test can block it behind a latch and prove
/// the timeout, the cap and the not-found paths deterministically, with no DNS.
///
/// POOLS IN USE: the default process-wide pool (cap 16) serves CRL-source registration host lookups;
/// NAT64 discovery uses its OWN capacity-one pool (`nat64_probe_pool()` in nat64_probe.hpp) so a hung
/// discovery lookup can never take a registration slot.
///
/// CONTRACT FOR CONSUMERS (the registration check today, the CRL fetcher in 2b-1b):
///  - POOL OWNERSHIP. The default is ONE process-wide pool of `kMaxInFlightLookups`; every consumer
///    that passes no pool shares it, so a stuck resolver starves all of them together. A consumer
///    whose lookups must not be starved by another (the fetcher's refresh job vs an operator's
///    registration) passes its OWN `ResolverPool`, sized for its own concurrency.
///  - `kNotFound` IS NOT PROOF OF ABSENCE. It is the resolver's current answer (it may be a
///    split-horizon or a poisoned NXDOMAIN, or a transient server failure the OS reported as "no
///    name"). The registration check treats it as a caller error (400); the fetcher must treat it
///    as a FAILED FETCH of this cycle and KEEP THE LAST GOOD CRL, never as "the CA has no CRL" or as
///    a reason to drop revocation state.
///  - `kTemporary`, `kTimeout`, `kBusy` are retryable and mean "unknown".
///  - WINDOWS: the Winsock DLL must be initialised (WSAStartup) before the first call. httplib
///    initialises it once in a static initialiser, which every server TU links; a consumer in a
///    binary without httplib must call WSAStartup itself.
///  - The lookup function runs on a worker thread: it must not assert, throw to the caller, or
///    touch caller-owned state (an exception is caught and reported `kTemporary`).
///
/// Returned addresses are numeric text from `inet_ntop` (a scope zone is not included).

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
// clang-format on
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "resolver_errors.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace yuzu::server::net {

enum class ResolveStatus {
    kOk,        ///< at least one address
    kNotFound,  ///< the resolver answered definitively: no such name / no address
    kTemporary, ///< the resolver failed transiently (EAI_AGAIN / EAI_FAIL): retry, not a "no"
    kTimeout,   ///< no answer within the bound (the lookup may still be running)
    kBusy       ///< the pool's cap of lookups are already outstanding; nothing was started
};

struct ResolveResult {
    ResolveStatus status{ResolveStatus::kNotFound};
    std::vector<std::string> addresses;
};

using LookupFn = std::function<ResolveResult(const std::string& host)>;

inline constexpr int kMaxInFlightLookups = 16;

struct ResolverPool;

/// The in-flight counter and its cap. Held by shared_ptr so a worker that outlives the call (and a
/// test pool that outlives nothing) always has a live counter.
struct ResolverPool {
    std::atomic<int> in_flight{0};
    int cap{kMaxInFlightLookups};
    explicit ResolverPool(int c = kMaxInFlightLookups) : cap(c) {}
};

namespace detail {

struct ResolveState {
    std::mutex mu;
    std::condition_variable cv;
    bool done{false};
    ResolveResult result;
};

inline std::shared_ptr<ResolverPool> process_pool() {
    // Never destroyed: detached workers may still hold it at process exit.
    static const std::shared_ptr<ResolverPool>& p = *new std::shared_ptr<ResolverPool>(
        std::make_shared<ResolverPool>());
    return p;
}

/// The real lookup: blocking getaddrinfo, converted to numeric text before anything is returned.
inline ResolveResult system_lookup(const std::string& host) {
    ResolveResult out;
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* list = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), "0", &hints, &list);
    if (rc != 0 || list == nullptr) {
        // Only the resolver's definitive "no such name / no such data" is kNotFound (the rule lives
        // in resolver_errors.hpp, shared with every other consumer). EVERY other failure
        // (EAI_AGAIN, EAI_FAIL, EAI_SYSTEM, EAI_MEMORY, ...) is transient or ours. NOTE: do not
        // use httplib's getaddrinfo wrappers here: on macOS they report EAI_NODATA for every
        // CFHost error, which would read as a definitive answer.
        const bool not_found = rc == 0 || resolver_code_is_no_data(rc); // 0: success, empty list
        out.status = not_found ? ResolveStatus::kNotFound : ResolveStatus::kTemporary;
        return out;
    }
    for (const struct addrinfo* ai = list; ai != nullptr; ai = ai->ai_next) {
        // Copy the sockaddr into a local of the right type (length-checked) rather than casting
        // ai_addr, whose alignment is the resolver's business.
        char buf[INET6_ADDRSTRLEN] = {};
        if (ai->ai_family == AF_INET && ai->ai_addr != nullptr &&
            static_cast<std::size_t>(ai->ai_addrlen) >= sizeof(sockaddr_in)) {
            sockaddr_in sa{};
            std::memcpy(&sa, ai->ai_addr, sizeof(sa));
            if (::inet_ntop(AF_INET, &sa.sin_addr, buf, sizeof(buf)) != nullptr)
                out.addresses.emplace_back(buf);
        } else if (ai->ai_family == AF_INET6 && ai->ai_addr != nullptr &&
                   static_cast<std::size_t>(ai->ai_addrlen) >= sizeof(sockaddr_in6)) {
            sockaddr_in6 sa{};
            std::memcpy(&sa, ai->ai_addr, sizeof(sa));
            if (::inet_ntop(AF_INET6, &sa.sin6_addr, buf, sizeof(buf)) != nullptr)
                out.addresses.emplace_back(buf);
        }
    }
    ::freeaddrinfo(list);
    out.status = out.addresses.empty() ? ResolveStatus::kNotFound : ResolveStatus::kOk;
    return out;
}

} // namespace detail

/// Lookups currently outstanding in the process-wide pool (a stuck resolver pins its slots).
[[nodiscard]] inline int process_resolver_in_flight() {
    return detail::process_pool()->in_flight.load();
}

/// Resolve `host`, waiting at most `timeout`. Never blocks the caller past the bound, never
/// touches caller-owned memory from another thread. `lookup` (default: the system resolver) and
/// `pool` (default: the process pool) are injectable for tests.
[[nodiscard]] inline ResolveResult bounded_resolve(const std::string& host,
                                                   std::chrono::milliseconds timeout,
                                                   LookupFn lookup = {},
                                                   std::shared_ptr<ResolverPool> pool = {}) {
    if (!pool)
        pool = detail::process_pool();
    if (!lookup)
        lookup = &detail::system_lookup;
    if (pool->in_flight.fetch_add(1) >= pool->cap) {
        pool->in_flight.fetch_sub(1);
        return {ResolveStatus::kBusy, {}};
    }
    std::shared_ptr<detail::ResolveState> state;
    try {
        state = std::make_shared<detail::ResolveState>();
        std::thread([state, host, lookup = std::move(lookup), pool] {
            ResolveResult r;
            try {
                r = lookup(host);
            } catch (...) {
                r = {ResolveStatus::kTemporary, {}}; // never let an exception leave the thread
            }
            {
                std::lock_guard lk(state->mu);
                state->result = std::move(r);
                state->done = true;
            }
            state->cv.notify_all();
            pool->in_flight.fetch_sub(1);
        }).detach();
    } catch (...) {
        // make_shared or the thread could not be created: nothing was started.
        pool->in_flight.fetch_sub(1);
        return {ResolveStatus::kBusy, {}};
    }
    std::unique_lock lk(state->mu);
    if (!state->cv.wait_for(lk, timeout, [&] { return state->done; }))
        return {ResolveStatus::kTimeout, {}};
    return std::move(state->result);
}

} // namespace yuzu::server::net
