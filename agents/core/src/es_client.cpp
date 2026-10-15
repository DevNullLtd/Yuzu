/**
 * es_client.cpp -- see yuzu/agent/es_client.hpp.
 */
#include <yuzu/agent/es_client.hpp>

namespace yuzu::agent {

std::uint64_t es_seq_gap(std::uint64_t last_seq, std::uint64_t seq) noexcept {
    // Only a strict forward jump is a kernel drop; equal/decreasing seq (a client
    // re-create resets the per-type counter) yields 0 rather than underflowing.
    return seq > last_seq + 1 ? seq - last_seq - 1 : 0;
}

bool es_stream_is_stalled(std::int64_t last_event_ts, std::int64_t started_ts,
                          std::int64_t now, std::int64_t threshold_seconds) noexcept {
    const std::int64_t since = (last_event_ts != 0) ? last_event_ts : started_ts;
    if (since <= 0)
        return false; // never started / clock uninitialised — don't fall back blindly
    return (now - since) > threshold_seconds;
}

} // namespace yuzu::agent
