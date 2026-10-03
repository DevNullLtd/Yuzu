#pragma once

/**
 * Per-source collection health ledger (#1846). Pure: no I/O, no clock -- the
 * caller passes the epoch. Keyed by REGISTRY source name (capture_sources()),
 * never by tar_state key ("network" is a state key; the source is "tcp").
 *
 * Process memory only: an agent restart resets every source to never_ran / 0,
 * which must not be read as a recovery. `last_status_at` lets an operator spot a
 * source frozen behind an upstream fatal early return in the same tick.
 */

#include "tar_schema_registry.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::tar {

/// Tokens that count toward `consecutive_failures`. Everything else (including
/// source_disabled, unsupported_platform and baseline resets) resets the streak.
[[nodiscard]] constexpr bool collect_status_is_failure(std::string_view token) noexcept {
    return token == "capture_incomplete" || token == "counters_unavailable" ||
           token == "cursor_lost" || token == "state_unreadable" || token == "insert_failed" ||
           token == "state_save_failed";
}

/// The tcp source's single terminal per-tick health token, with failure
/// precedence: a failed nstat lifecycle insert earlier in the tick must not
/// be silently overwritten by a later successful poll-leg write in the same
/// tick (#1846 M2) -- an insert failure means events were lost even when the
/// poll's own baseline/diff commit succeeds.
[[nodiscard]] constexpr std::string_view tcp_tick_status(bool nstat_insert_failed,
                                                         std::string_view poll_status) noexcept {
    return nstat_insert_failed ? std::string_view{"insert_failed"} : poll_status;
}

struct SourceHealth {
    std::string last_status;
    int consecutive_failures{0};
    int64_t last_status_at{0};
};

class SourceHealthLedger {
public:
    void record(std::string_view source, std::string_view status, int64_t now_epoch) {
        const auto& srcs = capture_sources();
        bool known = false;
        for (const auto& d : srcs) {
            if (d.name == source) {
                known = true;
                break;
            }
        }
        if (!known)
            return; // not a registry name (e.g. a tar_state key): ignored
        auto& h = entries_[std::string{source}];
        h.last_status = std::string{status};
        h.consecutive_failures = collect_status_is_failure(status) ? h.consecutive_failures + 1 : 0;
        h.last_status_at = now_epoch;
    }

    [[nodiscard]] std::optional<SourceHealth> get(std::string_view source) const {
        auto it = entries_.find(std::string{source});
        if (it == entries_.end())
            return std::nullopt;
        return it->second;
    }

private:
    std::unordered_map<std::string, SourceHealth> entries_;
};

/// Three `config|` lines per registry source, in registry order.
[[nodiscard]] inline std::vector<std::string>
format_source_health_lines(const SourceHealthLedger& ledger,
                           const std::vector<CaptureSourceDef>& sources) {
    std::vector<std::string> out;
    out.reserve(sources.size() * 3);
    for (const auto& d : sources) {
        const auto h = ledger.get(d.name);
        const std::string name{d.name};
        out.push_back("config|" + name + "_last_status|" +
                      (h ? h->last_status : std::string{"never_ran"}));
        out.push_back("config|" + name + "_consecutive_failures|" +
                      std::to_string(h ? h->consecutive_failures : 0));
        out.push_back("config|" + name + "_last_status_at|" +
                      std::to_string(h ? h->last_status_at : int64_t{0}));
    }
    return out;
}

} // namespace yuzu::tar
