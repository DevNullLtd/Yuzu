/// @file hardware_section_integrity.cpp
/// See hardware_section_integrity.hpp.

#include "hardware_section_integrity.hpp"

#include "hardware_list_model.hpp" // served_section_verdict, SectionFault, section_fault_label

#include <yuzu/log_token.hpp> // log_token: ids and kinds in a log line
#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>

namespace yuzu::server {

namespace {

/// The faults that are counted: every non-None `SectionFault`. The one list the pre-seed, the
/// sampler lookup and the test reset all iterate.
constexpr std::array<SectionFault, 3> kCountedFaults{SectionFault::RowCount, SectionFault::Content,
                                                     SectionFault::Unverifiable};

/// Per-reason WARN state, mirroring DeviceInventoryStore's DegradeSampler: log the leading edge of
/// an episode, then every Nth occurrence, so a partial restore across a fleet cannot flood the
/// log - the counter is the continuous signal, the log a sampled breadcrumb.
struct IntegritySampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};
constexpr std::uint64_t kIntegrityLogSample = 100;
constexpr std::int64_t kIntegrityEpisodeGapSecs = 60;

/// nullptr for `SectionFault::None`: it has no sampler, so a caller passing it cannot pollute one.
IntegritySampler* integrity_sampler(SectionFault fault) {
    static IntegritySampler row_count, content, unverifiable;
    switch (fault) {
    case SectionFault::RowCount:
        return &row_count;
    case SectionFault::Content:
        return &content;
    case SectionFault::Unverifiable:
        return &unverifiable;
    case SectionFault::None:
        break;
    }
    return nullptr;
}

} // namespace

void register_section_integrity_metrics(yuzu::MetricsRegistry& metrics) {
    metrics.describe("yuzu_hardware_section_integrity_total",
                     "Hardware record sections composed downgraded to constrained because the "
                     "rows read back disagree with the row count or content digest the server "
                     "recorded when the section was written (row_count_mismatch, "
                     "content_digest_mismatch), or the server could not compute the digest to "
                     "compare (digest_unverifiable: a fault of this server, not of the "
                     "device). Counts reads composed with a faulted section, once per section per "
                     "read (including a read whose body is then withheld by an audit-write "
                     "failure), so a polled device inflates it; it is not a count of distinct "
                     "defects",
                     "counter");
    for (const auto fault : kCountedFaults)
        metrics.counter("yuzu_hardware_section_integrity_total",
                        {{"reason", std::string(section_fault_label(fault))}});
}

void reset_section_integrity_log_state_for_test() noexcept {
    for (const auto fault : kCountedFaults) {
        auto* s = integrity_sampler(fault);
        s->count.store(0, std::memory_order_relaxed);
        s->last_ts.store(0, std::memory_order_relaxed);
    }
}

void record_section_integrity(const std::vector<DeviceCiSection>& sections,
                              std::string_view agent_id, yuzu::MetricsRegistry* metrics,
                              DigestFn digest) {
    for (const auto& section : sections) {
        const SectionFault fault = served_section_verdict(section, digest).fault;
        auto* s = integrity_sampler(fault);
        if (s == nullptr)
            continue; // SectionFault::None: nothing to count
        const std::string_view label = section_fault_label(fault);
        if (metrics != nullptr)
            metrics
                ->counter("yuzu_hardware_section_integrity_total", {{"reason", std::string(label)}})
                .increment();
        const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count();
        const std::int64_t prev = s->last_ts.exchange(now, std::memory_order_relaxed);
        const std::uint64_t n = s->count.fetch_add(1, std::memory_order_relaxed) + 1;
        const bool new_episode = prev == 0 || (now - prev) > kIntegrityEpisodeGapSecs;
        if (new_episode || (n % kIntegrityLogSample) == 0) {
            // Device id and section kind only - never row contents (a section's rows are
            // agent-supplied bytes and may hold personal data).
            spdlog::warn("hardware record: section integrity fault agent={} kind={} reason={} "
                         "(served constrained; occurrence {})",
                         yuzu::log_token(agent_id), yuzu::log_token(section.kind), label, n);
        }
    }
}

} // namespace yuzu::server
