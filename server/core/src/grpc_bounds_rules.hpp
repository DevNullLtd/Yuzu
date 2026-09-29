#pragma once

/// @file grpc_bounds_rules.hpp
///
/// Derives the server-wide gRPC resource bounds (#913's fleet-wide half) from
/// `Config`, as a PURE function.
///
/// WHY IT IS SEPARATE. The two values handed to `grpc::ServerBuilder` involve an
/// easy-to-get-wrong MiB-to-bytes conversion and a config-plumbing hop, and
/// neither was reachable by any test while it lived inline in `server.cpp` —
/// asserting on a built `ServerBuilder` is not something gRPC exposes. Splitting
/// the arithmetic out makes the part we own testable and leaves two thin lines
/// at the call site.
///
/// HONEST LIMIT: this proves the values we COMPUTE, not that gRPC honours them.
/// Verifying that `GRPC_ARG_MAX_CONCURRENT_STREAMS` and `SetResourceQuota`
/// actually bound the runtime would be testing the library, not this change.

#include <cstddef>
#include <cstdint> // SIZE_MAX

#include <yuzu/server/server.hpp>

namespace yuzu::server {

struct GrpcResourceBounds {
    int max_concurrent_streams{0};
    std::size_t resource_quota_bytes{0};
    int max_threads{0};
};

/// Clamp floor for both knobs. A zero or negative value would configure a server
/// that accepts nothing at all, which is a self-inflicted outage rather than a
/// bound; CLI11 already rejects non-positive input at parse time, so this is the
/// defence for any other construction path (a config struct built in code, or a
/// future config-file loader that does not go through CLI11).
inline constexpr int kMinConcurrentStreams = 1;
inline constexpr std::size_t kMinResourceQuotaBytes = 1024ULL * 1024ULL;
/// A server that cannot run at least this many handler threads cannot serve a
/// fleet at all; the floor exists for the same reason as the two above.
inline constexpr int kMinThreads = 8;

[[nodiscard]] inline GrpcResourceBounds grpc_bounds_from_config(const Config& cfg) {
    GrpcResourceBounds b;
    b.max_concurrent_streams =
        cfg.grpc_max_concurrent_streams < kMinConcurrentStreams ? kMinConcurrentStreams
                                                                : cfg.grpc_max_concurrent_streams;

    // Widen BEFORE multiplying. `grpc_max_resource_memory_mb` is an int, and
    // `mb * 1024 * 1024` evaluated in int overflows above ~2048 MiB — a
    // perfectly reasonable value for a large deployment to configure, which
    // would otherwise wrap to a negative and then convert to an enormous
    // size_t, silently disabling the very bound it was meant to raise.
    const std::int64_t mb =
        cfg.grpc_max_resource_memory_mb < 1 ? 1 : cfg.grpc_max_resource_memory_mb;
    const std::uint64_t bytes = static_cast<std::uint64_t>(mb) * 1024ULL * 1024ULL;
    // Clamp into size_t BEFORE narrowing — on a 32-bit target the multiply above
    // would otherwise wrap on assignment and the floor below would then hand back a
    // TINY quota, the inverse of what the operator asked for.
    b.resource_quota_bytes = static_cast<std::size_t>(
        bytes > static_cast<std::uint64_t>(SIZE_MAX) ? static_cast<std::uint64_t>(SIZE_MAX) : bytes);
    if (b.resource_quota_bytes < kMinResourceQuotaBytes)
        b.resource_quota_bytes = kMinResourceQuotaBytes;

    b.max_threads = cfg.grpc_max_threads < kMinThreads ? kMinThreads : cfg.grpc_max_threads;
    return b;
}

} // namespace yuzu::server
