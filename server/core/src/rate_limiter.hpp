#pragma once

#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>

namespace httplib {
struct Response;
}

namespace yuzu::server {

/**
 * Token bucket rate limiter keyed by client IP.
 *
 * Each IP gets a bucket that refills at `rate` tokens/second up to `rate` max.
 * Stale buckets (no request for 60s) are purged periodically.
 */
class RateLimiter {
public:
    explicit RateLimiter(int rate_per_second = 100);

    /// Try to consume a token for the given key. Returns true if allowed.
    bool allow(const std::string& key);

    /// Purge stale entries older than 60 seconds.
    void purge_stale();

    /// Number of tracked keys (for monitoring).
    size_t bucket_count() const;

private:
    struct Bucket {
        double tokens;
        std::chrono::steady_clock::time_point last_refill;
        std::chrono::steady_clock::time_point last_used;
    };

    int rate_;
    mutable std::mutex mu_;
    std::unordered_map<std::string, Bucket> buckets_;
};

/// The refusal every pre-routing rate-limit site sends: 429, `Retry-After: 1` and the
/// `rate limit exceeded` JSON body. One definition, so a limited probe path and the general
/// API path cannot drift apart.
void write_rate_limited_response(httplib::Response& res);

} // namespace yuzu::server
