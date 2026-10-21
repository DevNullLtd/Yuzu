#include "rate_limiter.hpp"

#include "rest_a4_envelope_http.hpp"

#include <httplib.h>

#include <algorithm>
#include <cstdint>

namespace yuzu::server {

RateLimiter::RateLimiter(int rate_per_second) : rate_(std::max(1, rate_per_second)) {}

bool RateLimiter::allow(const std::string& key) {
    std::lock_guard lock(mu_);
    auto now = std::chrono::steady_clock::now();

    auto [it, inserted] = buckets_.try_emplace(key, Bucket{});
    if (inserted) {
        it->second.tokens = static_cast<double>(rate_) - 1.0;
        it->second.last_refill = now;
        it->second.last_used = now;
        return true;
    }

    auto& b = it->second;
    // Refill tokens based on elapsed time
    auto elapsed =
        std::chrono::duration<double>(now - b.last_refill).count();
    b.tokens = std::min(static_cast<double>(rate_), b.tokens + elapsed * rate_);
    b.last_refill = now;
    b.last_used = now;

    if (b.tokens >= 1.0) {
        b.tokens -= 1.0;
        return true;
    }
    return false;
}

void RateLimiter::purge_stale() {
    std::lock_guard lock(mu_);
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(60);

    for (auto it = buckets_.begin(); it != buckets_.end();) {
        if (it->second.last_used < cutoff)
            it = buckets_.erase(it);
        else
            ++it;
    }
}

size_t RateLimiter::bucket_count() const {
    std::lock_guard lock(mu_);
    return buckets_.size();
}

void write_rate_limited_response(httplib::Response& res) {
    res.status = 429;
    res.set_header("Retry-After", "1");
    // The A4 envelope: `correlation_id` is the one carried in `X-Correlation-Id` (minted here
    // when no upstream gate set it), and `retry_after_ms` agrees with the `Retry-After` header.
    res.set_content(detail::error_json_a4(429, "rate limit exceeded",
                                          detail::ensure_correlation_id(res),
                                          std::int64_t{1000}, {}),
                    "application/json");
}

} // namespace yuzu::server
