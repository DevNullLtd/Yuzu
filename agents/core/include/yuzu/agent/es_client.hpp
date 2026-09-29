#pragma once

/**
 * es_client.hpp -- shared, pure Endpoint Security helpers.
 *
 * es_seq_gap() and es_stream_is_stalled() are lifted from TAR's
 * tar_proc_es.cpp (A0, macOS Spark/Reflex/DEX programme) into agent-core so
 * a future shared ES client (a later slice) and TAR's own process collector
 * both consume ONE copy. Pure integer arithmetic -- no ES headers, no
 * platform API -- so, like every other pure-decision-code header in this
 * tree, this compiles and is unit-tested on every host even though only a
 * macOS/YUZU_HAVE_ENDPOINT_SECURITY caller exists today.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>

namespace yuzu::agent {

/// Count kernel-side ES drops from a seq_num gap: only a strict forward jump
/// counts (a client re-create resets the per-type counter, which must never
/// underflow into a huge bogus count).
[[nodiscard]] YUZU_EXPORT std::uint64_t es_seq_gap(std::uint64_t last, std::uint64_t seq) noexcept;

/// Endpoint Security idle-fallback threshold (see es_stream_is_stalled). A
/// NOTIFY-only ES client exposes no liveness API, so prolonged TOTAL silence
/// is the only "presumed dead" signal available. Sized well beyond any
/// plausible quiet period so a healthy stream on a legitimately idle host is
/// not falsely dropped to an inferior poll fallback. Revisit once a real
/// liveness signal exists (#1455).
inline constexpr std::int64_t kEsIdleFallbackSeconds = 3600; // 1 hour with zero events

/// True once TOTAL silence (no event AND no stream start) has lasted longer
/// than `threshold_seconds`, measured from the later of `last_event_ts`/
/// `started_ts`. `since <= 0` (never started / clock uninitialised) never
/// reports stalled -- there is nothing yet to have gone quiet.
[[nodiscard]] YUZU_EXPORT bool es_stream_is_stalled(std::int64_t last_event_ts,
                                                    std::int64_t started_ts, std::int64_t now,
                                                    std::int64_t threshold_seconds) noexcept;

} // namespace yuzu::agent
