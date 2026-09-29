#include "inventory_ingestion.hpp"

#include "agent.pb.h"
#include "software_inventory_store.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

namespace pb = ::yuzu::agent::v1;

constexpr const char* kSourceInstalledSoftware = "installed_software";

// Input caps — the report is untrusted (security-guardian). A blob over the cap
// is rejected (dropped + nacked); entries/fields beyond the cap are
// dropped/truncated.
// kMaxBlobBytes MUST equal the agent source's kMaxBlobBytes
// (agents/core/src/sync_source_installed_software.cpp) — comment-coordinated, a
// one-sided bump reintroduces the agent-sends/server-drops tight loop (UP-7).
// Set below the gRPC 4 MiB receive ceiling for the wire-framing reason
// documented agent-side (UP-6).
constexpr std::size_t kMaxBlobBytes = 3u * 1024 * 1024; // 3 MiB per source
constexpr std::size_t kMaxEntries = 20000;
constexpr std::size_t kMaxFieldLen = 1024;
// The sync framework wires a small fixed number of sources (1 today; a handful
// ever). A report carrying an implausibly large content_hashes / plugin_data map is
// malformed or abusive — reject it wholesale (defense-in-depth; already bounded by
// the 4 MiB gRPC receive ceiling, but an explicit cap is cheaper to reason about).
// gov fjarvis LOW.
constexpr int kMaxSources = 64;

// Parse the canonical wire blob into rows: entries are 0x1E-separated; each is
// 0x1F-separated in blob contract v2 field order (name, version, publisher,
// install_date, kind, ecosystem, epoch, release, arch, signature_status,
// distro_id, distro_version) — the same byte form the agent hashes (ADR-0016
// §4), so the server re-hash matches. A v1 4-field record parses fine: the
// token walk stops at the record's end, leaving fields 5–12 default-empty (the
// documented mixed-version behaviour — an old agent's rows store with empty v2
// columns). Tokens beyond the 12th are dropped. nullopt only when the blob
// exceeds the cap; an empty list is a legitimate "nothing here".
std::optional<std::vector<SoftwareEntry>> parse_software_blob(const std::string& blob) {
    if (blob.size() > kMaxBlobBytes)
        return std::nullopt;
    std::vector<SoftwareEntry> out;
    std::size_t i = 0;
    while (i < blob.size() && out.size() < kMaxEntries) {
        std::size_t rec_end = blob.find('\x1e', i);
        if (rec_end == std::string::npos)
            rec_end = blob.size();
        std::string_view rec(blob.data() + i, rec_end - i);
        if (!rec.empty()) {
            SoftwareEntry e;
            std::string* fields[12] = {&e.name,
                                       &e.version,
                                       &e.publisher,
                                       &e.install_date,
                                       &e.kind,
                                       &e.ecosystem,
                                       &e.epoch,
                                       &e.release,
                                       &e.arch,
                                       &e.signature_status,
                                       &e.distro_id,
                                       &e.distro_version};
            std::size_t fi = 0;
            std::size_t p = 0;
            while (fi < 12) {
                std::size_t f_end = rec.find('\x1f', p);
                if (f_end == std::string_view::npos)
                    f_end = rec.size();
                std::string_view raw = rec.substr(p, f_end - p);
                // Scrub to valid UTF-8 FIRST (governance UP-IN1), then truncate on a
                // codepoint boundary. Both steps MUST match the agent's clamp_field
                // (sync_source_installed_software.cpp) byte-for-byte — scrub before
                // clamp, U+FFFD for any invalid byte — or the server-recomputed hash
                // diverges from the agent's (governance UP-10 for the clamp half).
                std::string f = sanitize_utf8_strict(raw);
                if (f.size() > kMaxFieldLen) {
                    std::size_t end = kMaxFieldLen;
                    while (end > 0 && (static_cast<unsigned char>(f[end]) & 0xC0) == 0x80)
                        --end;
                    f.resize(end);
                }
                *fields[fi] = std::move(f);
                ++fi;
                if (f_end >= rec.size())
                    break;
                p = f_end + 1;
            }
            if (!e.name.empty())
                out.push_back(std::move(e));
        }
        if (rec_end >= blob.size())
            break;
        i = rec_end + 1;
    }
    return out;
}

} // namespace

bool validate_inventory_report_source_count(const std::string& agent_id,
                                            const pb::InventoryReport& report,
                                            ::yuzu::MetricsRegistry* metrics) {
    if (report.content_hashes_size() <= kMaxSources && report.plugin_data_size() <= kMaxSources)
        return true;
    spdlog::warn("inventory: report from agent={} carries too many sources "
                 "(hashes={}, blobs={}, cap={}) — rejecting whole report",
                 agent_id, report.content_hashes_size(), report.plugin_data_size(), kMaxSources);
    if (metrics)
        metrics->counter("yuzu_inventory_ingest_total",
                         {{"source", "__report__"}, {"outcome", "rejected"}})
            .increment();
    return false;
}

void ingest_inventory_report(SoftwareInventoryStore& store, const std::string& agent_id,
                             const pb::InventoryReport& report, pb::InventoryAck& ack,
                             ::yuzu::MetricsRegistry* metrics) {
    const auto emit = [&](const std::string& source, const char* outcome) {
        if (metrics)
            metrics->counter("yuzu_inventory_ingest_total",
                             {{"source", source}, {"outcome", outcome}})
                .increment();
    };
    if (agent_id.empty())
        return;
    if (!validate_inventory_report_source_count(agent_id, report, metrics)) {
        // Whole-report reject (malformed/abusive). Deliberately NO need_full nack — we do
        // not amplify resends to a misbehaving agent; the empty ack means the agent records
        // the cycle done until the weekly floor. Safety rests on the legit source count
        // (1 today) staying far below kMaxSources, so a legit report is never dropped here.
        // Emit a DISTINCT `rejected` outcome (NOT `dropped` — that label's alert/runbook is
        // oversized-blob-specific: nacked + never-self-heals; this reject is neither) so a
        // flooding agent is observable without misdirecting the dropped-blob runbook (gov
        // consistency). YuzuInventoryReportRejected alerts on it.
        return;
    }

    std::int64_t collected_at = 0;
    if (report.has_collected_at())
        collected_at = report.collected_at().millis_epoch() / 1000;

    // content_hashes is the source of truth for "which sources came due" — it is
    // always present per due source, whether or not the blob accompanies it.
    for (const auto& [source, claimed_hash] : report.content_hashes()) {
        if (source != kSourceInstalledSoftware)
            continue; // slice 1: only installed_software is wired

        std::optional<std::vector<SoftwareEntry>> rows;
        auto it = report.plugin_data().find(source);
        if (it != report.plugin_data().end()) {
            rows = parse_software_blob(it->second);
            if (!rows.has_value()) {
                // Oversized blob: don't store it, but DO nack so the agent
                // retries rather than recording a false success (UP-2). The
                // agent's own blob cap (UP-4) should prevent reaching here.
                spdlog::warn("inventory: oversized '{}' blob from agent={}, dropping + nacking",
                             source, agent_id);
                ack.add_need_full(source);
                emit(source, "dropped");
                continue;
            }
        }

        // #1664: time the apply — it holds a pooled connection for the whole
        // advisory-lock + DELETE + batched-INSERT transaction (and any
        // lease-acquire wait), the cost that saturates the pool under a
        // need_full herd and is otherwise invisible. Split by `phase`: a `full`
        // payload runs the expensive replace transaction; a `hash_only` report
        // is just a compare + last_seen bump. Without the split the cheap
        // hash_only samples (the steady-state majority) would bury the
        // full-replace tail that #1664 is about. `source` matches
        // yuzu_inventory_ingest_total{source,outcome}.
        const char* phase = rows.has_value() ? "full" : "hash_only";
        const auto ingest_t0 = std::chrono::steady_clock::now();
        // rows is not read after this call (phase is computed above), so move it
        // in — the store takes the optional by value and moves the entries out,
        // avoiding a copy of up to kMaxEntries rows on the ingest hot path (UP-8).
        InventoryIngestOutcome outcome = store.apply_installed_software(
            agent_id, claimed_hash, std::move(rows), collected_at);
        if (metrics) {
            const double secs =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - ingest_t0).count();
            // A creating site for yuzu_inventory_ingest_duration_seconds (the other is
            // device_ci_ingestion.cpp) — the bucket boundaries are fixed by whichever
            // call births a (source,phase) series first (unlike pg_acquire there is no
            // registration birth, because the {source,phase} label sets aren't known up
            // front). Any NEW call site for this metric MUST pass seconds_buckets_60s()
            // too, or it would silently birth a default-10s-ceiling series and collapse
            // the tail (governance #1686 UP-6 / consistency N2).
            metrics->histogram("yuzu_inventory_ingest_duration_seconds",
                               {{"source", source}, {"phase", phase}},
                               yuzu::Histogram::seconds_buckets_60s())
                .observe(secs);
        }
        emit(source, outcome == InventoryIngestOutcome::kStored    ? "stored"
                     : outcome == InventoryIngestOutcome::kTouched  ? "touched"
                     : outcome == InventoryIngestOutcome::kNeedFull ? "need_full"
                                                                    : "error");
        // need_full on cold-cache/drift (kNeedFull) AND on a transient store
        // failure (kError) — otherwise the agent sees an empty need_full, treats
        // the cycle as stored, and silently advances past un-stored data for up
        // to a week (UP-2). Nacking makes the agent resend a full payload.
        if (outcome == InventoryIngestOutcome::kNeedFull ||
            outcome == InventoryIngestOutcome::kError)
            ack.add_need_full(source);
    }
}

} // namespace yuzu::server
