#include "app_usage_ingestion.hpp"

#include "agent.pb.h"
#include "app_usage_store.hpp"
#include "utf8_sanitize.hpp" // shared yuzu::server::sanitize_utf8_strict (server side of the pair)

#include <yuzu/metrics.hpp>

#include <openssl/evp.h>
#include <spdlog/spdlog.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

namespace pb = ::yuzu::agent::v1;

constexpr const char* kSourceAppUsage = "app_usage";

// Caps — MUST match the agent source once it lands (agents/core/src/
// sync_source_app_usage.cpp — the producer for this ingest path ships in a
// follow-up PR, not this one; see this repo's server-half-only precedent for
// VulnFindingStore, docs/postgres-migration-ladder.md) — comment-coordinated
// (the repo has no shared agent/server constants, C-2). A one-sided cap
// reintroduces the agent-sends/server-drops tight loop (UP-7).
constexpr std::size_t kMaxBlobBytes = 512u * 1024; // 512 KiB
constexpr std::size_t kMaxRecords = 5000;
constexpr std::size_t kMaxFieldLen = 512;
// Positional fields in a `lu|` record AFTER the kind prefix.
constexpr std::size_t kLuFieldCount = 5;
// Report-level source-count cap — defense-in-depth, mirrors the sibling seams.
constexpr int kMaxSources = 64;

std::string clamp_field(std::string_view raw) {
    std::string f = sanitize_utf8_strict(raw);
    std::erase_if(f, [](char c) {
        return c == '|' || c == '\n' || c == '\r' || c == '\x1f' || c == '\x1e' || c == '\0';
    });
    if (f.size() > kMaxFieldLen) {
        std::size_t end = kMaxFieldLen;
        while (end > 0 && (static_cast<unsigned char>(f[end]) & 0xC0) == 0x80)
            --end;
        f.resize(end);
    }
    return f;
}

// Locale-independent numeric parse (std::from_chars), clamped non-negative. A
// malformed or negative token yields 0 rather than rejecting the whole row.
// The end pointer is checked against the full token so a trailing non-digit
// tail (e.g. "12junk") falls back to 0 instead of silently accepting the
// leading-digit prefix "12" — from_chars parses as much as it can and does
// not itself reject unconsumed trailing characters.
std::int64_t parse_nonneg_i64(std::string_view s) {
    std::int64_t v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || v < 0 || p != s.data() + s.size())
        return 0;
    return v;
}

} // namespace

std::string app_usage_raw_hash(const std::string& blob) {
    // SHA-256 hex of the RAW received bytes (OpenSSL EVP one-shot) — the same
    // local pattern as software_licensing_raw_hash, kept local so the seam
    // has no AuthManager dependency. This is the ONE hash this source ever
    // stores.
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(blob.data(), blob.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return {};
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

AppUsageParse parse_app_usage_blob(const std::string& blob) {
    AppUsageParse out;
    if (blob.size() > kMaxBlobBytes) {
        // Defence-in-depth; the ingest entry point caps + nacks before parsing.
        out.over_record_cap = true;
        return out;
    }
    // exe_key -> index in out.rows, so a repeated key within one blob
    // OVERWRITES (last-wins) rather than appending a second row: the DB
    // primary key is (agent_id, exe_key), so two rows for the same key would
    // otherwise violate it and nack the whole replace, permanently, for this
    // agent (a duplicate key can't ever heal — the raw-byte hash covers the
    // exact bytes that produced it, so an identical resend hash-skips
    // forever). Keyed by value (not a view into the loop-local `f` array
    // below, which is reassigned every iteration) — deliberately a real
    // std::string copy per unique key.
    std::unordered_map<std::string, std::size_t> index_by_exe_key;
    std::size_t records_seen = 0;
    std::size_t i = 0;
    while (i < blob.size()) {
        std::size_t rec_end = blob.find('\x1e', i);
        if (rec_end == std::string::npos)
            rec_end = blob.size();
        std::string_view rec(blob.data() + i, rec_end - i);
        if (!rec.empty()) {
            if (++records_seen > kMaxRecords) {
                // Record-count breach: flag for the caller to drop + nack the
                // WHOLE blob. Truncate-and-store is unsafe here: the raw-byte
                // hash covers the full blob, so every later identical blob
                // would hash-skip to "touched" and the missing rows would
                // never heal.
                out.over_record_cap = true;
                out.rows.clear();
                return out;
            }
            std::size_t kind_end = rec.find('\x1f');
            if (kind_end == std::string_view::npos)
                kind_end = rec.size();
            const std::string_view kind = rec.substr(0, kind_end);
            std::string_view rest =
                kind_end < rec.size() ? rec.substr(kind_end + 1) : std::string_view{};

            if (kind == "lu") {
                std::array<std::string, kLuFieldCount> f; // value-initialised to empty
                std::size_t fi = 0;
                std::size_t p = 0;
                while (fi < kLuFieldCount && !rest.empty()) {
                    std::size_t fe = rest.find('\x1f', p);
                    if (fe == std::string_view::npos)
                        fe = rest.size();
                    f[fi] = rest.substr(p, fe - p);
                    ++fi;
                    if (fe >= rest.size())
                        break;
                    p = fe + 1;
                }
                // Positional order: exe_key|first_seen|last_seen|
                // run_count_30d|total_seconds_30d. Tokens beyond the 5th are
                // dropped (forward-version tolerance); missing trailing
                // fields stayed empty above.
                AgentLastUsedRow r;
                r.exe_key = clamp_field(f[0]);
                if (r.exe_key.empty()) {
                    // No exe_key = no row identity — drop (mirrors the
                    // sibling seams' empty-name drop).
                } else {
                    r.first_seen = parse_nonneg_i64(f[1]);
                    r.last_seen = parse_nonneg_i64(f[2]);
                    r.run_count_30d = parse_nonneg_i64(f[3]);
                    r.total_seconds_30d = parse_nonneg_i64(f[4]);
                    if (auto it = index_by_exe_key.find(r.exe_key); it != index_by_exe_key.end()) {
                        out.rows[it->second] = std::move(r); // last-wins, same key
                    } else {
                        index_by_exe_key.emplace(r.exe_key, out.rows.size());
                        out.rows.push_back(std::move(r));
                    }
                }
            }
            // else: `cfg|` (machine-scope marker), or any newer kind — SKIP
            // without error (forward-compat; the raw-byte hash already
            // covered the bytes, so skipping cannot desynchronise hash-skip).
        }
        if (rec_end >= blob.size())
            break;
        i = rec_end + 1;
    }
    return out;
}

void ingest_app_usage_report(AppUsageStore& store, const std::string& agent_id,
                             const pb::InventoryReport& report, pb::InventoryAck& ack,
                             ::yuzu::MetricsRegistry* metrics) {
    const auto emit = [&](const char* outcome) {
        if (metrics)
            metrics->counter("yuzu_inventory_ingest_total",
                             {{"source", kSourceAppUsage}, {"outcome", outcome}})
                .increment();
    };
    const auto observe = [&](const char* phase, std::chrono::steady_clock::time_point t0) {
        if (metrics) {
            const double secs =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            metrics
                ->histogram("yuzu_inventory_ingest_duration_seconds",
                            {{"source", kSourceAppUsage}, {"phase", phase}},
                            yuzu::Histogram::seconds_buckets_60s())
                .observe(secs);
        }
    };
    if (agent_id.empty())
        return;
    if (report.content_hashes_size() > kMaxSources || report.plugin_data_size() > kMaxSources) {
        spdlog::warn("app_usage: report from agent={} carries too many sources (hashes={}, "
                     "blobs={}, cap={}) — skipping app_usage",
                     agent_id, report.content_hashes_size(), report.plugin_data_size(),
                     kMaxSources);
        emit("rejected");
        // Every other drop path in this function nacks so the agent resends
        // in full next cycle — this one skipped that call (review finding),
        // which would otherwise leave app_usage silently stuck until the next
        // cycle's report happens to fall back under the cap on its own.
        ack.add_need_full(kSourceAppUsage);
        return;
    }

    const auto hit = report.content_hashes().find(kSourceAppUsage);
    if (hit == report.content_hashes().end())
        return; // app_usage not due this cycle
    const std::string& claimed_hash = hit->second;

    const auto bit = report.plugin_data().find(kSourceAppUsage);
    if (bit == report.plugin_data().end()) {
        // ── Hash-only report: trichotomy legs 1–2 (stored_hash → touch) ─────
        const auto t0 = std::chrono::steady_clock::now();
        const auto stored = store.stored_hash(agent_id);
        if (!stored.has_value()) {
            observe("hash_only", t0);
            emit("error"); // store degrade — nack, the agent re-sends next cycle
            ack.add_need_full(kSourceAppUsage);
            return;
        }
        if (!stored->has_value() || **stored != claimed_hash) {
            // Cold cache or drift → full resend.
            observe("hash_only", t0);
            emit("need_full");
            ack.add_need_full(kSourceAppUsage);
            return;
        }
        const bool touched = store.touch(agent_id);
        observe("hash_only", t0);
        if (!touched) {
            emit("error");
            ack.add_need_full(kSourceAppUsage);
            return;
        }
        emit("touched");
        return;
    }

    // ── Full payload: trichotomy leg 3 (replace) ────────────────────────────
    const std::string& blob = bit->second;
    if (blob.size() > kMaxBlobBytes) {
        spdlog::warn("app_usage: oversized blob from agent={} ({} B > {} B) — dropping + nacking",
                     agent_id, blob.size(), kMaxBlobBytes);
        ack.add_need_full(kSourceAppUsage);
        emit("dropped");
        return;
    }

    // RAW-BYTE hash first: SHA-256 over exactly the received bytes, BEFORE
    // parsing/projection — never the agent's claim.
    const std::string raw_hash = app_usage_raw_hash(blob);
    if (raw_hash.empty()) {
        spdlog::warn("app_usage: SHA-256 digest failed for agent={} — nacking", agent_id);
        emit("error");
        ack.add_need_full(kSourceAppUsage);
        return;
    }

    AppUsageParse parsed = parse_app_usage_blob(blob);
    if (parsed.over_record_cap) {
        spdlog::warn("app_usage: blob from agent={} exceeds the record cap ({}) — dropping + "
                     "nacking",
                     agent_id, kMaxRecords);
        ack.add_need_full(kSourceAppUsage);
        emit("dropped");
        return;
    }
    std::int64_t collected_at = 0;
    if (report.has_collected_at())
        collected_at = report.collected_at().millis_epoch() / 1000;
    for (auto& r : parsed.rows)
        r.collected_at = collected_at;

    // An empty rows vector is a legitimate full replace-to-empty — collected_at
    // is passed as its own parameter (not derived from parsed.rows) precisely
    // so that case still persists a real batch collection time on the parent
    // usage_state row rather than losing it (#C2).
    const auto t0 = std::chrono::steady_clock::now();
    const bool ok =
        store.replace_agent_last_used(agent_id, parsed.rows, raw_hash, collected_at);
    observe("full", t0);
    if (!ok) {
        emit("error"); // fail-soft: nack, the agent re-sends next cycle
        ack.add_need_full(kSourceAppUsage);
        return;
    }
    emit("stored");
}

} // namespace yuzu::server
