#include "guardian_boot_epoch.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <optional>
#include <string>
#include <system_error>

namespace yuzu::agent {

namespace {

using Outcome = GuardianBootEpochClaim::Outcome;

const char* outcome_name(Outcome o) noexcept {
    switch (o) {
    case Outcome::Claimed:
        return "claimed";
    case Outcome::Recovered:
        return "recovered";
    case Outcome::NoStore:
        return "no_store";
    case Outcome::ReadFailed:
        return "read_failed";
    case Outcome::WriteFailed:
        return "write_failed";
    case Outcome::OutOfRange:
        return "out_of_range";
    case Outcome::DurabilityBelowFull:
        return "durability_below_full";
    }
    return "unknown";
}

// What the stored row looked like. Kept for the log line only; never the raw bytes.
enum class Stored { Absent, Parsed, Unusable };

struct Detail {
    Stored stored = Stored::Absent;
    std::size_t stored_len = 0;
    std::uint64_t clock = 0;
    std::uint64_t candidate = 0;
    int synchronous = -2; // -2 = not read; -3 = the read threw
};

// Full-consume decimal parse. from_chars stops at the first non-digit, so a suffix or an
// embedded NUL leaves ptr short of end and is rejected; an empty string, a sign, leading
// whitespace and a value above uint64 max are rejected by the error code.
std::optional<std::uint64_t> parse_decimal(const std::string& s) noexcept {
    std::uint64_t v = 0;
    const char* const first = s.data();
    const char* const last = first + s.size();
    const auto [ptr, ec] = std::from_chars(first, last, v);
    if (ec != std::errc{} || ptr != last)
        return std::nullopt;
    return v;
}

GuardianBootEpochClaim claim_impl(IJournalStore* store, std::int64_t now_unix_s, Detail& d,
                                  Outcome& on_throw) {
    if (store == nullptr)
        return {0, Outcome::NoStore, 0};

    on_throw = Outcome::ReadFailed;
    auto entry = store->get_entry(kGuardianBootEpochNamespace, kGuardianBootEpochKey);
    if (!entry.has_value())
        return {0, Outcome::ReadFailed, 0};

    // Clock term: clamped to 0 when the clock reads at or before the epoch of time.
    d.clock = now_unix_s > 0 ? static_cast<std::uint64_t>(now_unix_s) : 0;

    std::uint64_t persisted = 0;
    bool recovered = false;
    if (entry->has_value()) {
        const std::string& raw = **entry;
        d.stored_len = raw.size();
        const auto parsed = parse_decimal(raw);
        // The ceiling check on the PERSISTED value precedes any "+ 1". A value whose
        // successor would reach the ceiling (2^62 - 1 and above, including uint64 max) is
        // unusable: it is re-claimed from the clock, never incremented, and never left to
        // fail the claim on every later boot.
        if (parsed.has_value() && *parsed < kGuardianBootEpochCeiling - 1) {
            persisted = *parsed;
            d.stored = Stored::Parsed;
        } else {
            recovered = true;
            d.stored = Stored::Unusable;
        }
    }

    // Safe: persisted < 2^62 - 1, so persisted + 1 is below the ceiling and cannot wrap. An
    // unusable row re-claims from the clock alone (floor 1, so the epoch is never 0 on a
    // successful claim). Only a clock term at or above the ceiling can still reach it.
    const std::uint64_t lower = recovered ? 1 : persisted + 1;
    d.candidate = std::max(lower, d.clock);

    if (d.candidate >= kGuardianBootEpochCeiling)
        return {0, Outcome::OutOfRange, persisted};

    // The epoch write must survive power loss, or the next boot can re-issue an equal or lower
    // epoch for events already emitted under this one. SQLite rolls back a committed but
    // unsynced transaction below FULL (OFF, or NORMAL in WAL), so the claim is refused unless
    // the store REPORTS FULL (2) or EXTRA (3). -1 (unreadable) is refused too: durability that
    // cannot be shown is not assumed. A throwing read is a failed read (ReadFailed, nothing
    // written), set below by on_throw before the call.
    on_throw = Outcome::ReadFailed;
    d.synchronous = -3;
    d.synchronous = store->pragma_synchronous();
    if (d.synchronous < 2)
        return {0, Outcome::DurabilityBelowFull, persisted};

    on_throw = Outcome::WriteFailed;
    char buf[24];
    const auto [end, ec] = std::to_chars(buf, buf + sizeof(buf), d.candidate);
    (void)ec; // 20 digits at most; the buffer cannot overflow
    if (!store->set(kGuardianBootEpochNamespace, kGuardianBootEpochKey,
                    std::string_view(buf, static_cast<std::size_t>(end - buf))))
        return {0, Outcome::WriteFailed, persisted};

    return {d.candidate, recovered ? Outcome::Recovered : Outcome::Claimed, persisted};
}

void log_claim(IJournalStore* store, const GuardianBootEpochClaim& c, Detail& d,
               std::int64_t now_unix_s) noexcept {
    try {
        if (store != nullptr && d.synchronous == -2)
            d.synchronous = store->pragma_synchronous();
        const char* stored = d.stored == Stored::Absent   ? "absent"
                             : d.stored == Stored::Parsed ? "parsed"
                                                          : "unusable";
        const auto level =
            (c.outcome == Outcome::Claimed) ? spdlog::level::info : spdlog::level::err;
        // No raw stored bytes: an unusable row is described by its byte length only.
        spdlog::log(level,
                    "Guardian boot_epoch claim: outcome={} boot_epoch={} stored={} persisted={} "
                    "stored_len={} clock_unix_s={} candidate={} synchronous={}",
                    outcome_name(c.outcome), c.boot_epoch, stored, c.persisted, d.stored_len,
                    now_unix_s, d.candidate, d.synchronous);
    } catch (...) {
        // Logging is best-effort and must never change the claim.
    }
}

} // namespace

GuardianBootEpochClaim claim_guardian_boot_epoch(IJournalStore* store,
                                                 std::int64_t now_unix_s) noexcept {
    Detail d;
    Outcome on_throw = Outcome::NoStore;
    GuardianBootEpochClaim claim;
    try {
        claim = claim_impl(store, now_unix_s, d, on_throw);
    } catch (...) {
        // A throwing store is a failed read or write: unordered, nothing invented.
        claim = {0, on_throw, 0};
    }
    log_claim(store, claim, d, now_unix_s);
    return claim;
}

} // namespace yuzu::agent
