#include "software_licensing_ingestion.hpp"

#include "agent.pb.h"
#include "software_licensing_store.hpp"
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
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

namespace pb = ::yuzu::agent::v1;

constexpr const char* kSourceSoftwareLicensing = "software_licensing";

// Caps — roadmap R5: ≤ 1 MiB blob, ≤ 10 000 records, 1024 B fields. MUST match
// the agent source (agents/core/src/sync_source_software_licensing.cpp) —
// comment-coordinated (the repo has NO shared agent/server constants, C-2); a
// one-sided cap reintroduces the agent-sends/server-drops tight loop (UP-7).
// Sized for per-user fan-out (products × profiles + PR2 `ent|` records), below
// the 4 MiB gRPC receive ceiling.
constexpr std::size_t kMaxBlobBytes = 1u * 1024 * 1024; // 1 MiB
constexpr std::size_t kMaxRecords = 10000;
constexpr std::size_t kMaxFieldLen = 1024;
// The number of positional fields in a `lic|` record AFTER the kind prefix
// (§3.1). Extra fields in a (forward-version) blob are ignored; missing
// trailing fields stay empty.
constexpr std::size_t kLicFieldCount = 13;
// Report-level source-count cap — defense-in-depth, mirrors the sibling seams
// (inventory_ingestion.cpp / device_ci_ingestion.cpp). This seam does keyed
// find()s only, so a huge map is not an amplification vector HERE, but every
// typed seam enforces the same cap to keep the contract uniform (gov L1).
constexpr int kMaxSources = 64;

// expires_at plausibility horizon: anything more than 100 years out is agent
// garbage/overflow, treated as "no expiry" (0) — like the sibling app_perf
// day-plausibility clamp, the value is normalised rather than the row dropped.
constexpr std::int64_t kMaxExpiryHorizonSecs = 100ll * 365 * 86400;

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// ── field scrub + clamp (§3.3, third defensive layer) ───────────────────────
// UTF-8 scrub via the shared server-side sanitize_utf8_strict, then strip the
// §3.3 byte set (`|` \n \r 0x1F 0x1E NUL — the plugin's record framing plus
// the wire framing), then clamp to 1024 B on a codepoint boundary. Scrub
// BEFORE clamp (U+FFFD is 3 bytes — the C-2 ordering contract). Unlike
// installed_software/device_ci this need NOT byte-match the agent's copy:
// the D-2 raw-byte hash removes the byte-equality burden for this source —
// the scrub protects PG and the §3.3 contract only.
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

// Locale-independent numeric parse (std::from_chars, the app_perf pattern). A
// malformed token yields 0 ("no expiry") rather than rejecting the whole row.
std::int64_t parse_i64(std::string_view s) {
    std::int64_t v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    (void)p;
    return ec == std::errc{} ? v : 0;
}

// ── closed-vocabulary whitelists (§3.2, C-7) ─────────────────────────────────
// Applied at store projection, AFTER the raw-byte hash by construction (the
// hash never sees parsed rows) — pinned in ADR-0024 Decision 5. Unrecognised
// values map to "unknown"; the agent-emit side promises the same closed sets.
template <std::size_t N>
std::string whitelist(std::string value, const std::array<std::string_view, N>& allowed) {
    for (std::string_view a : allowed)
        if (value == a)
            return value;
    return "unknown";
}

constexpr std::array<std::string_view, 9> kLicenseTypes = {
    "perpetual", "subscription", "trial",       "volume",  "oem",
    "retail",    "open_source",  "freeware",    "unknown"};
constexpr std::array<std::string_view, 7> kStatuses = {
    "licensed", "subscription_active", "trial", "grace", "expired", "unlicensed", "unknown"};
constexpr std::array<std::string_view, 7> kSources = {
    "os_licensing_api", "entitlement_cert", "registry_probe", "license_file",
    "package_metadata", "app_receipt",      "heuristic"};
constexpr std::array<std::string_view, 3> kConfidences = {"authoritative", "probable",
                                                          "heuristic"};
constexpr std::array<std::string_view, 3> kUserRefModes = {"collect", "hash", "omit"};

} // namespace

std::string software_licensing_raw_hash(const std::string& blob) {
    // SHA-256 hex of the RAW received bytes (OpenSSL EVP one-shot) — the same
    // local pattern as the sibling stores' sha256_hex (software_inventory_store
    // .cpp), kept local so the seam has no AuthManager dependency. This is the
    // ONE hash this source ever stores (ADR-0024 Decision 3 / roadmap D-2).
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

SoftwareLicensingParse parse_software_licensing_blob(const std::string& blob) {
    SoftwareLicensingParse out;
    if (blob.size() > kMaxBlobBytes) {
        // Defence-in-depth; the ingest entry point caps + nacks before parsing.
        out.over_record_cap = true;
        return out;
    }
    const std::int64_t max_expiry = now_secs() + kMaxExpiryHorizonSecs;
    std::size_t records_seen = 0;
    std::size_t i = 0;
    while (i < blob.size()) {
        std::size_t rec_end = blob.find('\x1e', i);
        if (rec_end == std::string::npos)
            rec_end = blob.size();
        std::string_view rec(blob.data() + i, rec_end - i);
        if (!rec.empty()) {
            if (++records_seen > kMaxRecords) {
                // R5 breach: flag for the caller to drop + nack the WHOLE blob.
                // Truncate-and-store (the legacy sources' posture) is unsafe
                // here: the raw-byte hash would cover the full blob, so every
                // later identical blob would hash-skip to "touched" and the
                // missing rows would never heal (D-2 corollary).
                out.over_record_cap = true;
                out.rows.clear();
                out.effective_user_ref_mode.clear();
                return out;
            }
            // Record kind = field 0 (raw compare — a real kind is short ASCII).
            std::size_t kind_end = rec.find('\x1f');
            if (kind_end == std::string_view::npos)
                kind_end = rec.size();
            const std::string_view kind = rec.substr(0, kind_end);
            std::string_view rest =
                kind_end < rec.size() ? rec.substr(kind_end + 1) : std::string_view{};

            if (kind == "lic") {
                std::array<std::string, kLicFieldCount> f; // value-initialised to empty
                std::size_t fi = 0;
                std::size_t p = 0;
                while (fi < kLicFieldCount && !rest.empty()) {
                    std::size_t fe = rest.find('\x1f', p);
                    if (fe == std::string_view::npos)
                        fe = rest.size();
                    f[fi] = clamp_field(rest.substr(p, fe - p));
                    ++fi;
                    if (fe >= rest.size())
                        break;
                    p = fe + 1;
                }
                // Positional §3.1 order: product|vendor|version|license_type|
                // channel|status|expires_at|source|confidence|key_hint|
                // exe_hints|user_scope|user_ref. Tokens beyond the 13th are
                // dropped (forward-version tolerance); missing trailing fields
                // stayed empty above.
                AgentLicenseRow r;
                r.product = std::move(f[0]);
                if (r.product.empty()) {
                    // No product = no row identity — drop (mirrors the sibling
                    // seams' empty-name drop).
                } else {
                    r.vendor = std::move(f[1]);
                    r.version = std::move(f[2]);
                    r.license_type = whitelist(std::move(f[3]), kLicenseTypes);
                    r.channel = std::move(f[4]);
                    r.state = whitelist(std::move(f[5]), kStatuses);
                    // expires_at: epoch seconds; plausibility clamp — negative
                    // or > now + 100 years → 0 ("no expiry"), value normalised
                    // rather than the row dropped (the app_perf clamp posture).
                    r.expiry_at = parse_i64(f[6]);
                    if (r.expiry_at < 0 || r.expiry_at > max_expiry)
                        r.expiry_at = 0;
                    r.detector = whitelist(std::move(f[7]), kSources);
                    // confidence: closed §3.2 set (authoritative|probable|
                    // heuristic), anything else → "unknown". Stored from
                    // migration v1 (ADR-0024 Decisions 1/2/7) — operators
                    // weight heuristic rows via it, and hash-skip would
                    // freeze a later-added column empty on stable estates.
                    r.confidence = whitelist(std::move(f[8]), kConfidences);
                    r.key_hint = std::move(f[9]);
                    r.exe_hints = std::move(f[10]);
                    // user_scope is its own closed pair — an unrecognised scope
                    // falls back to "machine" (the conservative scope: no
                    // per-user attribution invented).
                    if (f[11] == "machine" || f[11] == "user")
                        r.user_scope = std::move(f[11]);
                    else
                        r.user_scope = "machine";
                    r.user_ref = std::move(f[12]);
                    out.rows.push_back(std::move(r));
                }
            } else if (kind == "cfg") {
                // D-10 config-stable record: cfg|user_ref|<collect|hash|omit>.
                // One per blob (sorted+deduped agent-side) — first wins.
                // Unknown cfg subkeys are skipped like unknown record kinds.
                std::size_t sub_end = rest.find('\x1f');
                if (sub_end == std::string_view::npos)
                    sub_end = rest.size();
                if (rest.substr(0, sub_end) == "user_ref" && out.effective_user_ref_mode.empty()) {
                    std::string_view val =
                        sub_end < rest.size() ? rest.substr(sub_end + 1) : std::string_view{};
                    std::size_t val_end = val.find('\x1f');
                    if (val_end != std::string_view::npos)
                        val = val.substr(0, val_end);
                    out.effective_user_ref_mode =
                        whitelist(clamp_field(val), kUserRefModes);
                }
            }
            // else: unknown record kind (`ent|` until PR2, the live-only
            // `probe_status|`, anything newer) — SKIP without error (ADR-0024
            // Decision 3 forward-compat; the raw-byte hash already covered the
            // bytes, so skipping cannot desynchronise hash-skip).
        }
        if (rec_end >= blob.size())
            break;
        i = rec_end + 1;
    }
    return out;
}

void ingest_software_licensing_report(SoftwareLicensingStore& store, const std::string& agent_id,
                                      const pb::InventoryReport& report, pb::InventoryAck& ack,
                                      ::yuzu::MetricsRegistry* metrics) {
    const auto emit = [&](const char* outcome) {
        if (metrics)
            metrics->counter("yuzu_inventory_ingest_total",
                             {{"source", kSourceSoftwareLicensing}, {"outcome", outcome}})
                .increment();
    };
    const auto observe = [&](const char* phase, std::chrono::steady_clock::time_point t0) {
        if (metrics) {
            const double secs =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            // Shares yuzu_inventory_ingest_duration_seconds with the sibling
            // seams; MUST pass seconds_buckets_60s() (bucket-ceiling contract,
            // #1686 UP-6).
            metrics
                ->histogram("yuzu_inventory_ingest_duration_seconds",
                            {{"source", kSourceSoftwareLicensing}, {"phase", phase}},
                            yuzu::Histogram::seconds_buckets_60s())
                .observe(secs);
        }
    };
    if (agent_id.empty())
        return;
    if (report.content_hashes_size() > kMaxSources || report.plugin_data_size() > kMaxSources) {
        // Malformed/abusive report — skip software_licensing (no need_full
        // nack, mirrors the sibling seams' whole-report reject).
        spdlog::warn("software_licensing: report from agent={} carries too many sources "
                     "(hashes={}, blobs={}, cap={}) — skipping software_licensing",
                     agent_id, report.content_hashes_size(), report.plugin_data_size(),
                     kMaxSources);
        emit("rejected");
        return;
    }

    // Single keyed lookup — bounded regardless of how many sources the report
    // carries. content_hashes is the "due this cycle" signal (ADR-0016 §4).
    const auto hit = report.content_hashes().find(kSourceSoftwareLicensing);
    if (hit == report.content_hashes().end())
        return; // software_licensing not due this cycle
    const std::string& claimed_hash = hit->second;

    const auto bit = report.plugin_data().find(kSourceSoftwareLicensing);
    if (bit == report.plugin_data().end()) {
        // ── Hash-only report: trichotomy legs 1–2 (stored_hash → touch) ─────
        // The claimed hash is used HERE ONLY, for the framework's skip
        // decision — it is never stored (D-2; storage always carries the
        // seam-recomputed raw-byte hash).
        const auto t0 = std::chrono::steady_clock::now();
        const auto stored = store.stored_hash(agent_id);
        if (!stored.has_value()) {
            observe("hash_only", t0);
            emit("error"); // store degrade — nack, the agent re-sends next cycle
            ack.add_need_full(kSourceSoftwareLicensing);
            return;
        }
        if (!stored->has_value() || **stored != claimed_hash) {
            // Cold cache or drift → full resend. This leg is also the recorded
            // forced-reprojection lever (roadmap G-8): under the raw-byte hash
            // a projection fix does not self-apply on a stable estate, so
            // need_full must stay reachable.
            observe("hash_only", t0);
            emit("need_full");
            ack.add_need_full(kSourceSoftwareLicensing);
            return;
        }
        const bool touched = store.touch(agent_id);
        observe("hash_only", t0);
        if (!touched) {
            emit("error");
            ack.add_need_full(kSourceSoftwareLicensing);
            return;
        }
        emit("touched");
        return;
    }

    // ── Full payload: trichotomy leg 3 (replace) ────────────────────────────
    const std::string& blob = bit->second;
    if (blob.size() > kMaxBlobBytes) {
        // Oversized: don't store, but nack so the agent resends rather than
        // recording a false success. The agent's own R5 cap
        // (sync_source_software_licensing.cpp) should prevent this.
        spdlog::warn("software_licensing: oversized blob from agent={} ({} B > {} B) — dropping "
                     "+ nacking",
                     agent_id, blob.size(), kMaxBlobBytes);
        ack.add_need_full(kSourceSoftwareLicensing);
        emit("dropped");
        return;
    }

    // RAW-BYTE hash first (D-2): SHA-256 over exactly the received bytes,
    // BEFORE parsing/projection — never the agent's claim.
    const std::string raw_hash = software_licensing_raw_hash(blob);
    if (raw_hash.empty()) {
        spdlog::warn("software_licensing: SHA-256 digest failed for agent={} — nacking", agent_id);
        emit("error");
        ack.add_need_full(kSourceSoftwareLicensing);
        return;
    }

    SoftwareLicensingParse parsed = parse_software_licensing_blob(blob);
    if (parsed.over_record_cap) {
        // R5 record-count breach: reject whole (see parse_software_licensing_
        // blob — truncate-and-store would freeze a partial projection under
        // hash-skip). Same nacked-dropped posture as the oversized blob.
        spdlog::warn("software_licensing: blob from agent={} exceeds the record cap ({}) — "
                     "dropping + nacking",
                     agent_id, kMaxRecords);
        ack.add_need_full(kSourceSoftwareLicensing);
        emit("dropped");
        return;
    }
    std::int64_t collected_at = 0;
    if (report.has_collected_at())
        collected_at = report.collected_at().millis_epoch() / 1000;
    for (auto& r : parsed.rows)
        r.collected_at = collected_at;

    // An empty rows vector is a legitimate full replace-to-empty (zero
    // detected licences is a valid state — ADR-0024 Decision 3's empty-vs-
    // error guard lives agent-side; the server accepts).
    const auto t0 = std::chrono::steady_clock::now();
    const bool ok = store.replace_agent_licenses(agent_id, parsed.rows, raw_hash,
                                                 parsed.effective_user_ref_mode);
    observe("full", t0);
    if (!ok) {
        emit("error"); // fail-soft: nack, the agent re-sends next cycle
        ack.add_need_full(kSourceSoftwareLicensing);
        return;
    }
    emit("stored");
}

} // namespace yuzu::server
