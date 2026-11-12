#pragma once

/// @file bounded_resolver.hpp
/// A name lookup with a hard time bound whose state is OWNED BY THE LOOKUP, never by the caller's
/// stack. CRL source registration (ADR-0070 R1) is the first consumer; the OIDC egress path is
/// the second, with a pool of its own, so both resolve the same way.
///
/// WHY NOT httplib's `getaddrinfo_with_timeout`: on Linux its wait is not bounded the way this
/// header's is. Here the blocking lookup runs on a worker thread that owns a heap-allocated
/// `State` through a `shared_ptr`; the caller waits on a condition variable with a timeout and, on
/// timeout, simply stops waiting. The worker finishes whenever the resolver returns, converts and
/// frees the `addrinfo` list itself, and releases the state. Nothing the worker touches belongs to
/// a caller.
///
/// RESOURCE LEDGER (what this adds): one DETACHED worker thread per outstanding lookup, bounded
/// by the pool's cap (`kMaxInFlightLookups` for the process pool; a lookup beyond the cap is
/// refused `kBusy`, never queued). A worker releases its slot and exits when its resolver call
/// returns; the cap bounds how many are outstanding at once. Nothing is joined
/// at shutdown: a worker holds no pointer into any object that is destroyed (the shared state,
/// the host string, the lookup function and the pool are all owned through the worker's own
/// copies / shared_ptrs).
///
/// The lookup function is injectable (`LookupFn`) so a test can block it behind a latch and prove
/// the timeout, the cap and the not-found paths deterministically, with no DNS.
///
/// POOLS IN USE: CRL source registration uses the default process-wide pool (cap
/// `kMaxInFlightLookups`), which any consumer that passes no pool also gets. OIDC name lookups
/// (`resolve_host_addresses_status` in `oidc_provider.cpp`) use their own pool of the same cap, so
/// sign-in and registration do not starve each other.
///
/// CONTRACT FOR CONSUMERS:
///  - POOL OWNERSHIP. Every consumer that passes no pool shares the process pool, so a slow
///    resolver call affects all of them together. A consumer whose lookups must not be starved by
///    another passes its OWN `ResolverPool`, sized for its own concurrency.
///  - `kNotFound` IS NOT PROOF OF ABSENCE. It is the resolver's current answer (it may be a
///    split-horizon or a poisoned NXDOMAIN, or a transient server failure the OS reported as "no
///    name"). A consumer that keeps last-good state must treat it as a failed cycle, never as a
///    reason to drop that state.
///  - `kTemporary`, `kTimeout`, `kBusy` are retryable and mean "unknown".
///  - The platform socket library must be initialised before the first call. httplib does this
///    once in a static initialiser, which every server TU links; a consumer in a binary without
///    httplib must initialise it itself.
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
    struct addrinfo* raw = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), "0", &hints, &raw);
    // Owned from here: a throwing emplace_back below must not leak the list.
    std::unique_ptr<struct addrinfo, decltype(&::freeaddrinfo)> list(raw, &::freeaddrinfo);
    if (rc != 0 || list == nullptr) {
        // Only the resolver's definitive "no such name / no such data" is kNotFound (the rule lives
        // in resolver_errors.hpp, shared with every other consumer). EVERY other failure
        // (EAI_AGAIN, EAI_FAIL, EAI_SYSTEM, EAI_MEMORY, ...) is transient or ours. NOTE: call
        // ::getaddrinfo directly here, so the return code is the resolver's own.
        const bool not_found = rc == 0 || resolver_code_is_no_data(rc); // 0: success, empty list
        out.status = not_found ? ResolveStatus::kNotFound : ResolveStatus::kTemporary;
        return out;
    }
    for (const struct addrinfo* ai = list.get(); ai != nullptr; ai = ai->ai_next) {
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
    out.status = out.addresses.empty() ? ResolveStatus::kNotFound : ResolveStatus::kOk;
    return out;
}

} // namespace detail

/// Lookups currently outstanding in the process-wide pool (a call that has not returned holds
/// its slot).
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
