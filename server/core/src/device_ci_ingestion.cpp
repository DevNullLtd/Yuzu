#include "device_ci_ingestion.hpp"

#include "agent.pb.h"
#include "device_ci_kinds.hpp"
#include "device_inventory_store.hpp"
#include "sha256_hex.hpp"
#include "utf8_sanitize.hpp" // shared yuzu::server::sanitize_utf8_strict (server side of the pair)

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

namespace pb = ::yuzu::agent::v1;

constexpr const char* kSourceDeviceCi = "device_ci";

// Caps. The field cap MUST match the agent source (sync_source_device_ci.cpp),
// comment-coordinated. The blob cap is the server-side bound and must stay >= the agent's:
// the server accepts everything an agent can send. A v1 agent's own 64 KiB cap sits inside
// it; the agent-side v2 writer adopts the same 1 MiB (ADR-0016 update "device_ci blob v2")
// so a host near every row cap is never dropped whole. 1 MiB is a fixed value, not derived
// from the registry caps: the clamp-bound worst case (1,520 rows x <=7 fields x 1024 B,
// ~10.9 MB) exceeds the 4 MiB gRPC receive ceiling, while a realistic near-cap host is
// ~160 KB, so 1 MiB leaves ~6x headroom and stays well under gRPC.
constexpr std::size_t kMaxBlobBytes = 1024u * 1024;
constexpr std::size_t kMaxFieldLen = 1024;
// The number of positional fields in the canonical record (see DeviceCiRecord /
// the agent's CiRecord). Extra fields in a (forward-version) blob are ignored;
// missing trailing fields stay empty.
constexpr std::size_t kFieldCount = 22;
// Report-level source-count cap — defense-in-depth, mirrors inventory_ingestion.cpp.
// device_ci does a single keyed find() (not a full-map iteration), so a huge map is
// not an amplification vector for THIS seam, but enforcing the same cap on every
// typed seam keeps the contract uniform (gov L1). (Shared-helper across seams is the
// documented follow-up.)
constexpr int kMaxSources = 64;

// ── field clamp ─────────────────────────────────────────────────────────────
// UTF-8 scrub via the shared server-side yuzu::server::sanitize_utf8_strict
// (utf8_sanitize.hpp) — the SAME impl installed_software's seam uses, byte-pinned
// against the agent's copy by the cross-pin test. clamp_field stays local because it
// strips only the framing separators (0x1F/0x1E) + NUL (NOT all control bytes — the
// agent keeps e.g. tabs), unlike app_perf's all-C0 variant. Scrub BEFORE clamp
// (U+FFFD is 3 bytes; clamping first would budget differently on each side).
std::string clamp_field(std::string_view raw) {
    std::string f = sanitize_utf8_strict(raw);
    if (f.size() > kMaxFieldLen) {
        std::size_t end = kMaxFieldLen;
        while (end > 0 && (static_cast<unsigned char>(f[end]) & 0xC0) == 0x80)
            --end;
        f.resize(end);
    }
    std::string out;
    out.reserve(f.size());
    for (char c : f) {
        if (c == '\x1f' || c == '\x1e' || c == '\0')
            continue;
        out.push_back(c);
    }
    return out;
}

// Split one record on 0x1F into at most `max_fields` clamped fields (the rest are
// ignored). An empty record yields one empty field, matching the v1 loop.
std::vector<std::string> split_fields(std::string_view record, std::size_t max_fields) {
    std::vector<std::string> out;
    std::size_t p = 0;
    while (out.size() < max_fields) {
        std::size_t fe = record.find('\x1f', p);
        if (fe == std::string_view::npos)
            fe = record.size();
        out.push_back(clamp_field(record.substr(p, fe - p)));
        if (fe >= record.size())
            break;
        p = fe + 1;
    }
    return out;
}

// Positions 0-21 — frozen across v1 and v2. MUST match the agent's CiRecord order.
void assign_base_fields(DeviceCiRecord& rec, std::string* f) {
    rec.manufacturer = std::move(f[0]);
    rec.model = std::move(f[1]);
    rec.serial = std::move(f[2]);
    rec.system_uuid = std::move(f[3]);
    rec.hostname = std::move(f[4]);
    rec.domain = std::move(f[5]);
    rec.ou = std::move(f[6]);
    rec.bios_vendor = std::move(f[7]);
    rec.bios_version = std::move(f[8]);
    rec.bios_date = std::move(f[9]);
    rec.cpu_model = std::move(f[10]);
    rec.cpu_cores = std::move(f[11]);
    rec.cpu_threads = std::move(f[12]);
    rec.ram_bytes = std::move(f[13]);
    rec.disks_summary = std::move(f[14]);
    rec.primary_mac = std::move(f[15]);
    rec.macs_summary = std::move(f[16]);
    rec.nic_count = std::move(f[17]);
    rec.os_name = std::move(f[18]);
    rec.os_version = std::move(f[19]);
    rec.os_build = std::move(f[20]);
    rec.arch = std::move(f[21]);
}

// The machine ID ships only as a hash (hex), or "-" when absent; the algorithm is open, so
// the server enforces the shape but no length. Honest limit: this rejects UUID/GUID shapes
// (dashes, braces, upper case) so a raw platform identifier is never stored under the hash
// column, but it cannot detect a raw hex id such as /etc/machine-id (32 hex is also a valid
// raw id, so a length floor would be theatre).
bool machine_id_hash_shape_ok(std::string_view h) {
    if (h.empty() || h == "-")
        return true;
    return std::ranges::all_of(
        h, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

constexpr const char* kMachineIdShapeNote = "server:machine_id_shape";

// v2: 0x02 scalar_record list_record* (see device_ci_kinds.hpp for the layout).
DeviceCiRecord parse_v2(const std::string& blob) {
    DeviceCiRecord rec;
    rec.blob_version = 2;
    // The agent's canonical bytes ARE the blob, so the server hashes what it received
    // (never a re-serialisation that a cap/clamp mismatch could silently drift). A digest
    // failure leaves the hash empty: canonical_hash returns "" and the store answers
    // kError (nack need_full) rather than storing under a v1-shaped default.
    if (auto h = sha256_hex(blob))
        rec.content_hash = std::move(*h);
    else
        spdlog::warn("device_ci: sha256 of a v2 blob failed — record will be nacked");

    std::string_view rest(blob.data() + 1, blob.size() - 1);
    const auto next_record = [&rest]() -> std::optional<std::string_view> {
        if (rest.empty())
            return std::nullopt;
        std::size_t e = rest.find('\x1e');
        std::string_view r = rest.substr(0, e == std::string_view::npos ? rest.size() : e);
        rest.remove_prefix(e == std::string_view::npos ? rest.size() : e + 1);
        return r;
    };

    // Record 0: the 33 scalar positions (missing trailing stay blank, extras ignored).
    // A blob that is only the version byte, or whose first record is empty, still yields
    // an (all-blank) v2 record.
    {
        std::string_view r0;
        if (auto r = next_record())
            r0 = *r;
        auto f = split_fields(r0, kDeviceCiScalarFields);
        f.resize(kDeviceCiScalarFields);
        assign_base_fields(rec, f.data());
        rec.chassis_type = std::move(f[22]);
        rec.chassis_serial = std::move(f[23]);
        rec.chassis_asset_tag = std::move(f[24]);
        rec.chassis_source = std::move(f[25]);
        rec.board_vendor = std::move(f[26]);
        rec.board_product = std::move(f[27]);
        rec.board_serial = std::move(f[28]);
        rec.board_source = std::move(f[29]);
        rec.machine_id_hash = std::move(f[30]);
        rec.machine_id_algorithm = std::move(f[31]);
        rec.machine_id_source = std::move(f[32]);
    }

    struct Acc {
        bool seen{false};
        std::string note; ///< server-side disclosure (cap or shape), appended to the reason
        DeviceCiSection sec;
    };
    std::array<Acc, kDeviceCiSectionCount> acc;
    // Widest record: the biggest list kind's columns plus the kind token.
    std::size_t max_rec_fields = 4; // "status" section level reason
    for (const auto& d : kDeviceCiSections)
        max_rec_fields = std::max(max_rec_fields, static_cast<std::size_t>(d.n_fields) + 1);

    // Trust boundary on the one hashed identifier: a machine ID that is not hex (or "-") is
    // blanked and disclosed on the machine_id section through the same note path the row
    // caps use, so a raw GUID/IOPlatformUUID is never stored as if it were a hash.
    if (!machine_id_hash_shape_ok(rec.machine_id_hash)) {
        rec.machine_id_hash.clear();
        if (const auto mi = device_ci_section_index("machine_id")) {
            acc[*mi].seen = true;
            acc[*mi].note = kMachineIdShapeNote;
        }
    }

    while (auto r = next_record()) {
        if (r->empty())
            continue;
        auto f = split_fields(*r, max_rec_fields);
        if (f[0] == "status") {
            if (f.size() < 2)
                continue;
            const auto i = device_ci_section_index(f[1]);
            if (!i)
                continue; // unregistered section
            auto& a = acc[*i];
            a.seen = true;
            a.sec.level = f.size() > 2 ? std::move(f[2]) : std::string{};
            a.sec.reason = f.size() > 3 ? std::move(f[3]) : std::string{};
            continue;
        }
        const auto i = device_ci_section_index(f[0]);
        if (!i || kDeviceCiSections[*i].table == nullptr)
            continue; // unknown kind, or a row for a status-only section
        const auto& def = kDeviceCiSections[*i];
        auto& a = acc[*i];
        a.seen = true;
        if (static_cast<int>(a.sec.rows.size()) >= def.row_cap) {
            if (a.note.empty())
                a.note = "server_cap:" + std::to_string(def.row_cap);
            continue;
        }
        std::vector<std::string> row(static_cast<std::size_t>(def.n_fields));
        for (std::size_t c = 0; c < row.size() && c + 1 < f.size(); ++c)
            row[c] = std::move(f[c + 1]);
        a.sec.rows.push_back(std::move(row));
    }

    for (std::size_t i = 0; i < kDeviceCiSectionCount; ++i) {
        auto& a = acc[i];
        if (!a.seen)
            continue;
        a.sec.kind = kDeviceCiSections[i].section;
        if (!a.note.empty()) {
            // Disclose the server-side truncation / blanking on the persisted section so a
            // hash-only ack of an unchanged blob never reads a bounded projection as complete.
            // Applied after every incoming status record, so a trailing `ok` cannot hide it.
            a.sec.level = "constrained";
            a.sec.reason = a.sec.reason.empty() ? a.note : a.sec.reason + ";" + a.note;
        }
        rec.sections.push_back(std::move(a.sec));
    }
    return rec;
}

} // namespace

DeviceCiRecord parse_device_ci_blob(const std::string& blob) {
    DeviceCiRecord rec;
    if (blob.size() > kMaxBlobBytes)
        return rec; // defence-in-depth; caller caps + nacks before reaching here
    if (!blob.empty() && blob[0] == kDeviceCiVersionByte)
        return parse_v2(blob);
    // v1: one record, terminated by the first 0x1E (the agent emits exactly one).
    std::size_t rec_end = blob.find('\x1e');
    if (rec_end == std::string::npos)
        rec_end = blob.size();
    auto f = split_fields(std::string_view(blob.data(), rec_end), kFieldCount);
    f.resize(kFieldCount); // missing trailing fields stay empty
    assign_base_fields(rec, f.data());
    return rec;
}

void ingest_device_ci_report(DeviceInventoryStore& store, const std::string& agent_id,
                             const pb::InventoryReport& report, pb::InventoryAck& ack,
                             ::yuzu::MetricsRegistry* metrics) {
    const auto emit = [&](const char* outcome) {
        if (metrics)
            metrics->counter("yuzu_inventory_ingest_total",
                             {{"source", kSourceDeviceCi}, {"outcome", outcome}})
                .increment();
    };
    if (agent_id.empty())
        return;
    if (report.content_hashes_size() > kMaxSources || report.plugin_data_size() > kMaxSources) {
        // Malformed/abusive report — skip device_ci (no need_full nack, mirrors the
        // installed_software seam's whole-report reject).
        spdlog::warn("device_ci: report from agent={} carries too many sources "
                     "(hashes={}, blobs={}, cap={}) — skipping device_ci",
                     agent_id, report.content_hashes_size(), report.plugin_data_size(), kMaxSources);
        emit("rejected");
        return;
    }

    // Single keyed lookup — bounded regardless of how many sources the report
    // carries (no full-map iteration; a huge map costs only this one find()).
    const auto hit = report.content_hashes().find(kSourceDeviceCi);
    if (hit == report.content_hashes().end())
        return; // device_ci not due this cycle
    const std::string& claimed_hash = hit->second;

    std::int64_t collected_at = 0;
    if (report.has_collected_at())
        collected_at = report.collected_at().millis_epoch() / 1000;

    const auto bit = report.plugin_data().find(kSourceDeviceCi);
    std::optional<DeviceCiRecord> rec;
    if (bit != report.plugin_data().end()) {
        if (bit->second.size() > kMaxBlobBytes) {
            // Oversized: don't store, but nack so the agent resends rather than
            // recording a false success. The agent's own cap should prevent this.
            spdlog::warn("device_ci: oversized blob from agent={} ({} B > {} B) — dropping + "
                         "nacking",
                         agent_id, bit->second.size(), kMaxBlobBytes);
            ack.add_need_full(kSourceDeviceCi);
            emit("dropped");
            return;
        }
        rec = parse_device_ci_blob(bit->second);
    }
    // rec == nullopt → hash-only report: the store compares claimed_hash against the
    // stored hash (kTouched on match, kNeedFull on cold/drift).
    // Time the apply (parity with the installed_software / app_perf seams), split by
    // phase: a `full` payload runs the upsert; a `hash_only` report is a compare +
    // last_seen bump. Computed BEFORE the move (rec is consumed by apply).
    const char* phase = rec.has_value() ? "full" : "hash_only";
    const auto ingest_t0 = std::chrono::steady_clock::now();
    const InventoryIngestOutcome outcome =
        store.apply_device_ci(agent_id, claimed_hash, std::move(rec), collected_at);
    if (metrics) {
        const double secs =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - ingest_t0).count();
        // Shares the yuzu_inventory_ingest_duration_seconds family with installed_software;
        // MUST pass seconds_buckets_60s() (the bucket-ceiling contract, #1686 UP-6).
        metrics
            ->histogram("yuzu_inventory_ingest_duration_seconds",
                        {{"source", kSourceDeviceCi}, {"phase", phase}},
                        yuzu::Histogram::seconds_buckets_60s())
            .observe(secs);
    }
    emit(outcome == InventoryIngestOutcome::kStored    ? "stored"
         : outcome == InventoryIngestOutcome::kTouched ? "touched"
         : outcome == InventoryIngestOutcome::kNeedFull ? "need_full"
                                                        : "error");
    if (outcome == InventoryIngestOutcome::kNeedFull || outcome == InventoryIngestOutcome::kError)
        ack.add_need_full(kSourceDeviceCi);
}

} // namespace yuzu::server
