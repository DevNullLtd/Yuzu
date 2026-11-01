#include "sync_source_device_ci.hpp"

#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // sanitize_utf8_strict / clamp_field / sha256_hex

#include <inventory_status_row.hpp> // parse_status_row: the plugins' own status-row grammar

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

namespace {

// Caps. The field cap MUST match the server seam (device_ci_ingestion.cpp) so the server's
// parse never truncates differently from what this source hashed. The blob cap
// (kDeviceCiMaxBlobBytes, sync_source_device_ci.hpp) must stay <= the server's (server >= agent):
// the server accepts everything this source can send; the two are equal by contract.
constexpr std::size_t kMaxFieldLen = detail::kCiClampField;

// ── UTF-8 scrub + field clamp ───────────────────────────────────────────────
// sanitize_utf8_strict / clamp_field live in sync_canonical.{hpp,cpp} — one
// agent-side implementation shared by every daily-sync source. The server's
// copy in device_ci_ingestion.cpp (parse) must stay byte-for-byte identical,
// or the agent- and server-recomputed canonical hashes diverge → permanent
// need_full. This source's field cap is kMaxFieldLen above
// (comment-coordinated with the server seam).

// ── plugin-output parsing ───────────────────────────────────────────────────
// Each plugin action writes pipe-delimited lines: `key|f1|f2|...`.

std::vector<std::string_view> split_lines(std::string_view out) {
    std::vector<std::string_view> lines;
    std::size_t pos = 0;
    while (pos < out.size()) {
        std::size_t eol = out.find('\n', pos);
        if (eol == std::string_view::npos)
            eol = out.size();
        std::string_view line = out.substr(pos, eol - pos);
        while (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (!line.empty())
            lines.push_back(line);
        pos = eol + 1;
    }
    return lines;
}

std::vector<std::string_view> split_pipe(std::string_view line) {
    std::vector<std::string_view> tok;
    std::size_t fp = 0;
    while (true) {
        std::size_t bar = line.find('|', fp);
        if (bar == std::string_view::npos) {
            tok.push_back(line.substr(fp));
            break;
        }
        tok.push_back(line.substr(fp, bar - fp));
        fp = bar + 1;
    }
    return tok;
}

// First `key|value` line's value column ("" if absent). For scalar actions.
std::string scalar(std::string_view out, std::string_view key) {
    for (auto line : split_lines(out)) {
        auto t = split_pipe(line);
        if (t.size() >= 2 && t[0] == key)
            return std::string(t[1]);
    }
    return {};
}

long long to_ll(std::string_view s) {
    long long v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    (void)p;
    return ec == std::errc{} ? v : 0;
}

// A MAC that carries no information (all-zero or empty) — excluded so it can't
// inflate nic_count or pin primary_mac.
bool meaningful_mac(std::string_view mac) {
    if (mac.empty())
        return false;
    for (char c : mac)
        if (c != '0' && c != ':' && c != '-')
            return true;
    return false;
}

// The clamp-join shared by the v1 blob and the v2 scalar record: each field scrubbed + clamped,
// 0x1F-joined, one 0x1E terminator. ONE loop, so the v2 scalar record's first 22 fields can never
// drift from the frozen v1 bytes.
std::string clamp_join_record(const std::string* fields, std::size_t n) {
    std::string canon;
    for (std::size_t i = 0; i < n; ++i) {
        if (i)
            canon += '\x1f';
        canon += clamp_field(fields[i], kMaxFieldLen);
    }
    canon += '\x1e';
    return canon;
}

constexpr std::size_t kV1Fields = 22;

// The frozen v1 positions, in wire order -- the ONE list behind both the v1 blob and the v2 scalar
// record's first 22 fields. POSITIONAL: field order is the contract (see CiRecord). The return type
// pins the count at compile time (CTAD deduces std::array<std::string, N> from the initialisers).
std::array<std::string, kV1Fields> v1_fields(const CiRecord& rec) {
    return std::array{
        rec.manufacturer, rec.model,       rec.serial,        rec.system_uuid,
        rec.hostname,     rec.domain,      rec.ou,            rec.bios_vendor,
        rec.bios_version, rec.bios_date,   rec.cpu_model,     rec.cpu_cores,
        rec.cpu_threads,  rec.ram_bytes,   rec.disks_summary, rec.primary_mac,
        rec.macs_summary, rec.nic_count,   rec.os_name,       rec.os_version,
        rec.os_build,     rec.arch,
    };
}

} // namespace

std::string device_ci_canonical_blob(const CiRecord& rec) {
    // Each field is scrub+clamp'd in the join; the server re-clamps on parse (idempotent) and
    // rejoins.
    const auto fields = v1_fields(rec);
    return clamp_join_record(fields.data(), fields.size());
}

// ── v2 writer ───────────────────────────────────────────────────────────────

namespace {

constexpr std::string_view kLevelOk = "ok";
constexpr std::string_view kLevelConstrained = "constrained";
constexpr std::string_view kLevelUnavailable = "unavailable";
constexpr std::string_view kLevelDenied = "permission_denied";

struct SectionStatus {
    std::string level;
    std::string reason; ///< base reason, already clamped to kMaxFieldLen - kCiAgentCapReserve
};

// The plugin's own `status|<action>|<level>|<tokens>` row token, "" when absent. parse_status_row
// returns field 4 verbatim, so a literal "-" (the grammar's "no tokens") is normalised here.
std::string status_row_token(std::string_view captured, std::string_view action) {
    for (auto line : split_lines(captured)) {
        auto t = split_pipe(line);
        if (auto row = yuzu::shared::parse_status_row(t, action))
            return row->tokens == "-" ? std::string{} : std::move(row->tokens);
    }
    return {};
}

// Per-action result -> section status. Failure (rc / truncation / plugin absent) outranks the
// typed result; reason is typed provenance, else the plugin's own status-row token, else "".
SectionStatus section_status_of(const CiActionResult& r, std::string_view action,
                                bool plugin_loaded) {
    constexpr std::size_t kBaseReasonMax = kMaxFieldLen - kCiAgentCapReserve;
    const auto make = [&](std::string_view level, std::string reason) {
        return SectionStatus{std::string(level), clamp_field(reason, kBaseReasonMax)};
    };
    if (!plugin_loaded)
        return make(kLevelUnavailable, "agent:plugin_not_loaded");
    if (r.rc != 0) {
        // A plugin that predates the action answers `unknown action: <name>` at rc 1. That prefix
        // is the convention of the hardware and disk_actions plugins, not the plugin ABI: a plugin
        // that answers differently maps to `agent:rc=<n>` -- the section is unavailable either way,
        // only the reason token is less specific.
        return make(kLevelUnavailable, std::string_view(r.captured).starts_with("unknown action")
                                           ? "agent:action_absent"
                                           : "agent:rc=" + std::to_string(r.rc));
    }
    if (r.truncated)
        return make(kLevelUnavailable, "agent:truncated");

    std::string_view level;
    switch (r.status) {
    case YUZU_RESULT_STATUS_CONSTRAINED:
        level = kLevelConstrained;
        break;
    case YUZU_RESULT_STATUS_UNAVAILABLE:
        level = kLevelUnavailable;
        break;
    case YUZU_RESULT_STATUS_PERMISSION_DENIED:
        level = kLevelDenied;
        break;
    default: // UNDECLARED / OK
        level = kLevelOk;
        break;
    }
    return make(level, !r.provenance.empty() ? r.provenance : status_row_token(r.captured, action));
}

bool rows_allowed(const SectionStatus& s) {
    return s.level == kLevelOk || s.level == kLevelConstrained;
}

// One wire row `kind 1F c1 .. 1F cn 1E` from a plugin data line, or nullopt when the line is not a
// row of this kind (a status line, another kind, or an empty-result placeholder). `plugin_kind` is
// the row token the plugin prints; swap drops used_mb (plugin column 3: volatile telemetry).
std::optional<std::string> project_row(const CiV2Section& sec, std::string_view plugin_kind,
                                       const std::vector<std::string_view>& t) {
    if (t.empty() || t[0] != plugin_kind)
        return std::nullopt;
    if (sec.token == std::string_view("disk") && t.size() >= 4 && t[2] == "unknown" &&
        t[3] == "0")
        return std::nullopt; // the hardware disk sentinel (same predicate as build_device_ci_record)
    if (sec.token == std::string_view("dimm") && t.size() >= 3 && t[1] == "unknown" &&
        t[2] == "0")
        return std::nullopt; // the hardware empty-result dimm sentinel (not a DIMM)
    if (sec.token == std::string_view("volume") && t.size() >= 2 && t[1] == "-")
        return std::nullopt; // the disk_actions empty-result placeholder (volume name "-")
    const bool swap = sec.token == std::string_view("swap");
    std::string row(sec.token);
    for (int c = 0; c < sec.n_fields; ++c) {
        const std::size_t src = swap && c == 2 ? 4 : static_cast<std::size_t>(c) + 1;
        row += '\x1f';
        if (src < t.size())
            row += clamp_field(t[src], kMaxFieldLen);
    }
    row += '\x1e';
    return row;
}

std::vector<std::string> project_rows(const CiV2Section& sec, std::string_view plugin_kind,
                                      std::string_view captured) {
    std::vector<std::string> rows;
    for (auto line : split_lines(captured)) {
        auto t = split_pipe(line);
        if (yuzu::shared::is_status_line(t))
            continue;
        if (auto row = project_row(sec, plugin_kind, t))
            rows.push_back(std::move(*row));
    }
    std::sort(rows.begin(), rows.end());
    return rows;
}

// First data row of a scalar section's capture, split on the raw pipe (empty when none).
std::vector<std::string_view> first_row(std::string_view captured, std::string_view kind) {
    for (auto line : split_lines(captured)) {
        auto t = split_pipe(line);
        if (!t.empty() && t[0] == kind)
            return t;
    }
    return {};
}

struct SectionBuild {
    SectionStatus st;
    std::vector<std::string> rows;
    std::size_t total{0}; ///< rows before any cap or trim
    std::string cap;      ///< "" or "agent_cap:<kept>/<total>" -- ONE slot, replaced never appended
    std::string status_record;

    void set_cap() {
        cap = "agent_cap:" + std::to_string(rows.size()) + "/" + std::to_string(total);
    }
    void render(std::string_view token) {
        std::string reason = st.reason;
        if (!cap.empty())
            reason += (reason.empty() ? "" : ";") + cap;
        const std::string_view level = cap.empty() ? std::string_view(st.level) : kLevelConstrained;
        status_record = "status\x1f" + std::string(token) + "\x1f" + std::string(level) + "\x1f" +
                        reason + "\x1e";
    }
};

} // namespace

std::string device_ci_canonical_blob_v2(const CiRecord& rec, const CiSectionInputs& in) {
    // Section inputs, POSITIONALLY parallel to kCiV2Sections: result, the status-row action name,
    // the section token (the plugin's data-row kind), and whether the owning plugin is loaded.
    // The per-section loop asserts each token against the registry entry it is paired with, so a
    // reordered registry fails every writer test rather than silently misrouting rows.
    struct Src {
        const CiActionResult* res;
        const char* action;
        const char* token;
        bool loaded;
    };
    const Src srcs[kCiV2SectionCount] = {
        {&in.chassis, "chassis", "chassis", true},
        {&in.baseboard, "baseboard", "baseboard", true},
        {&in.machine_id, "machine_id", "machine_id", true},
        {&in.processors, "processors", "cpu", true},
        {&in.memory, "memory", "dimm", true},
        {&in.disks, "disks", "disk", true},
        {&in.swap, "swap", "swap", true},
        {&in.volumes, "volumes", "volume", in.disk_actions_loaded},
        {&in.partitions, "partitions", "partition", in.disk_actions_loaded},
        {&in.topology, "topology", "topology", in.disk_actions_loaded},
    };

    std::vector<SectionBuild> sections(kCiV2SectionCount);
    for (std::size_t i = 0; i < kCiV2SectionCount; ++i) {
        const auto& def = kCiV2Sections[i];
        assert(std::string_view(srcs[i].token) == def.token);
        auto& b = sections[i];
        b.st = section_status_of(*srcs[i].res, srcs[i].action, srcs[i].loaded);
        // Failure provenance: a failed section projects nothing.
        if (def.row_cap > 0 && rows_allowed(b.st)) {
            b.rows = project_rows(def, def.token, srcs[i].res->captured);
            b.total = b.rows.size();
            if (b.rows.size() > static_cast<std::size_t>(def.row_cap)) {
                b.rows.resize(static_cast<std::size_t>(def.row_cap));
                b.set_cap();
            }
        }
        b.render(def.token);
    }

    // Scalar record: the 22 v1 fields, then positions 22-32 from the first chassis / baseboard /
    // machine_id row, only when that section is readable (blank = not reported).
    std::array<std::string, detail::kCiScalarFields> f;
    {
        auto v1 = v1_fields(rec);
        std::move(v1.begin(), v1.end(), f.begin());
    }
    constexpr std::size_t kChassisFirst = kV1Fields;
    constexpr std::size_t kBaseboardFirst = kChassisFirst + 4;
    constexpr std::size_t kMachineIdFirst = kBaseboardFirst + 4;
    static_assert(kMachineIdFirst + 3 == detail::kCiScalarFields,
                  "device_ci v2: the appended scalar groups must exactly fill the scalar record");
    const auto fill = [&](std::size_t sec, std::string_view kind, std::size_t first,
                          std::size_t n) {
        if (!rows_allowed(sections[sec].st))
            return;
        const auto t = first_row(srcs[sec].res->captured, kind);
        for (std::size_t c = 0; c < n; ++c)
            if (c + 1 < t.size())
                f[first + c] = std::string(t[c + 1]);
    };
    fill(0, "chassis", kChassisFirst, 4);     // type, serial, asset_tag, source
    fill(1, "baseboard", kBaseboardFirst, 4); // vendor, product, serial, source
    fill(2, "machine_id", kMachineIdFirst, 3); // hash, algorithm, source
    const std::string scalar_record = clamp_join_record(f.data(), f.size());

    std::size_t total = 1 + scalar_record.size();
    for (const auto& b : sections) {
        total += b.status_record.size();
        for (const auto& r : b.rows)
            total += r.size();
    }

    // Ceiling trim: pop tail rows kind by kind in kCiV2TrimOrder until the blob fits. Running
    // total, so a pop costs O(1) plus one status re-render. Scalar and status records are never
    // popped; the header static_assert is the termination proof.
    std::size_t trim_idx[std::size(kCiV2TrimOrder)]{};
    for (std::size_t t = 0; t < std::size(kCiV2TrimOrder); ++t)
        for (std::size_t i = 0; i < kCiV2SectionCount; ++i)
            if (std::string_view(kCiV2Sections[i].token) == kCiV2TrimOrder[t])
                trim_idx[t] = i; // present exactly once (header static_assert)
    while (total > kDeviceCiMaxBlobBytes) {
        bool popped = false;
        for (const std::size_t idx : trim_idx) {
            auto& b = sections[idx];
            if (b.rows.empty())
                continue;
            total -= b.rows.back().size();
            b.rows.pop_back();
            const std::size_t old_status = b.status_record.size();
            b.set_cap();
            b.render(kCiV2Sections[idx].token);
            total = total - old_status + b.status_record.size();
            popped = true;
            break;
        }
        if (!popped)
            break; // unreachable (static_assert); the caller's size guard is the backstop
    }

    std::string blob;
    blob.reserve(total);
    blob += '\x02';
    blob += scalar_record;
    for (const auto& b : sections) {
        blob += b.status_record;
        for (const auto& r : b.rows)
            blob += r;
    }
    return blob;
}

bool core_identity_unavailable(const CiRecord& rec) {
    // Both "unknown" ⇒ the identity subsystem was unavailable for this collection.
    // Windows: manufacturer + model BOTH come from one Win32_ComputerSystem query
    // behind one wmi.valid() gate, so a WMI outage drives both to "unknown" together.
    // Linux: they are TWO separate /sys/class/dmi/id files (sys_vendor, product_name)
    // — both "unknown" only if DMI itself is unreadable. macOS: manufacturer defaults
    // to "Apple Inc.", so the AND effectively keys on model there. AND (not OR) so a
    // host reporting a real manufacturer but an empty model is never skipped forever.
    return rec.manufacturer == "unknown" && rec.model == "unknown";
}

CiRecord build_device_ci_record(const CiPluginOutputs& out) {
    CiRecord rec;
    rec.manufacturer = scalar(out.manufacturer, "manufacturer");
    rec.model = scalar(out.model, "model");
    rec.serial = scalar(out.system, "serial");
    rec.system_uuid = scalar(out.system, "system_uuid");
    rec.hostname = scalar(out.device_name, "device_name");
    rec.domain = scalar(out.domain, "domain");
    rec.ou = scalar(out.ou, "ou");
    rec.bios_vendor = scalar(out.bios, "bios_vendor");
    rec.bios_version = scalar(out.bios, "bios_version");
    rec.bios_date = scalar(out.bios, "bios_date");
    rec.os_name = scalar(out.os_name, "os_name");
    rec.os_version = scalar(out.os_version, "os_version");
    rec.os_build = scalar(out.os_build, "os_build");
    rec.arch = scalar(out.os_arch, "os_arch");

    // processors: `cpu|<id>|<model>|<cores>|<threads>|<mhz>[|<socket_designation>|<stepping>]`
    // (trailing columns are placeholders and ignored here) — model from the first CPU,
    // cores/threads summed across sockets.
    long long cores = 0;
    long long threads = 0;
    for (auto line : split_lines(out.processors)) {
        auto t = split_pipe(line);
        if (t.size() >= 5 && t[0] == "cpu") {
            if (rec.cpu_model.empty() && !t[2].empty())
                rec.cpu_model = std::string(t[2]);
            cores += to_ll(t[3]);
            threads += to_ll(t[4]);
        }
    }
    rec.cpu_cores = std::to_string(cores);
    rec.cpu_threads = std::to_string(threads);

    // memory: `dimm|<slot>|<size_mb>|<type>|<speed_mhz>[|<manufacturer>|<part_number>|<serial>]`
    // (trailing columns are placeholders and ignored here) — sum size_mb → bytes.
    long long total_mb = 0;
    for (auto line : split_lines(out.memory)) {
        auto t = split_pipe(line);
        if (t.size() >= 3 && t[0] == "dimm")
            total_mb += to_ll(t[2]);
    }
    rec.ram_bytes = std::to_string(total_mb * 1024 * 1024);

    // disks: `disk|<idx>|<model>|<size>|<type>|<interface>` — sorted human summary
    // "<model> <size> <type>". (No numeric total: the size unit is not portable — GB
    // int on Windows, "476.9G" on Linux.) Skip the empty sentinel.
    std::vector<std::string> disk_strs;
    for (auto line : split_lines(out.disks)) {
        auto t = split_pipe(line);
        if (t.size() >= 5 && t[0] == "disk") {
            if (t[2] == "unknown" && t[3] == "0")
                continue;
            disk_strs.push_back(std::string(t[2]) + " " + std::string(t[3]) + " " +
                                std::string(t[4]));
        }
    }
    std::sort(disk_strs.begin(), disk_strs.end());
    for (std::size_t i = 0; i < disk_strs.size(); ++i) {
        if (i)
            rec.disks_summary += "; ";
        rec.disks_summary += disk_strs[i];
    }

    // adapters: `adapter|<name>|<mac>|<speed>|<status>` — collect meaningful MACs,
    // dedup + sort (deterministic). primary = first sorted.
    std::vector<std::string> macs;
    for (auto line : split_lines(out.adapters)) {
        auto t = split_pipe(line);
        if (t.size() >= 3 && t[0] == "adapter" && meaningful_mac(t[2]))
            macs.emplace_back(t[2]);
    }
    std::sort(macs.begin(), macs.end());
    macs.erase(std::unique(macs.begin(), macs.end()), macs.end());
    rec.nic_count = std::to_string(macs.size());
    if (!macs.empty())
        rec.primary_mac = macs.front();
    for (std::size_t i = 0; i < macs.size(); ++i) {
        if (i)
            rec.macs_summary += ",";
        rec.macs_summary += macs[i];
    }
    return rec;
}

SyncSource make_device_ci_source(const YuzuPluginDescriptor* hardware,
                                 const YuzuPluginDescriptor* device_identity,
                                 const YuzuPluginDescriptor* os_info,
                                 const YuzuPluginDescriptor* network_config,
                                 const YuzuPluginDescriptor* disk_actions) {
    SyncSource src;
    src.name = "device_ci";
    src.interval = std::chrono::hours{24};
    src.collect = [hardware, device_identity, os_info, network_config,
                   disk_actions]() -> std::optional<std::pair<std::string, std::string>> {
        if (hardware == nullptr || device_identity == nullptr || os_info == nullptr ||
            network_config == nullptr) {
            spdlog::debug("sync: a device_ci source plugin is not loaded — source idle "
                          "(hardware={}, device_identity={}, os_info={}, network_config={})",
                          static_cast<const void*>(hardware),
                          static_cast<const void*>(device_identity),
                          static_cast<const void*>(os_info),
                          static_cast<const void*>(network_config));
            return std::nullopt;
        }

        LocalDispatcher dispatcher;
        CiSectionInputs inputs;
        // Dispatcher result -> the section writer's input (typed metadata + captured stdout).
        auto to_action_result = [](LocalDispatcher::Result&& r) {
            CiActionResult a;
            a.rc = r.rc;
            a.truncated = r.truncated;
            a.status = r.result_status;
            a.provenance = std::move(r.result_provenance);
            a.captured = std::move(r.captured);
            return a;
        };
        // Run one REQUIRED action, returning its captured stdout. Any rc!=0 or a truncated
        // capture aborts the whole cycle (skip — never sync a partial CI record,
        // which would flap the hash). nullopt propagates the abort. `meta`, when given,
        // receives the action's typed result for its section status.
        auto run = [&](const YuzuPluginDescriptor* d, const char* action,
                       CiActionResult* meta) -> std::optional<std::string> {
            CiActionResult a = to_action_result(dispatcher.run(d, action));
            if (a.rc != 0) {
                spdlog::warn("sync: device_ci action '{}' rc={} — skipping this cycle", action,
                             a.rc);
                return std::nullopt;
            }
            if (a.truncated) {
                spdlog::warn("sync: device_ci action '{}' output truncated — skipping this cycle",
                             action);
                return std::nullopt;
            }
            if (meta) { // the three actions with a section keep both copies
                *meta = std::move(a);
                return meta->captured;
            }
            return std::move(a.captured);
        };

        CiPluginOutputs o;
        auto get = [&](const YuzuPluginDescriptor* d, const char* action, std::string& dst,
                       CiActionResult* meta = nullptr) -> bool {
            auto r = run(d, action, meta);
            if (!r)
                return false;
            dst = std::move(*r);
            return true;
        };
        // Any failed action aborts the cycle (|| short-circuits — a later action is
        // not dispatched once one fails). Never sync a partial CI record.
        if (!get(hardware, "manufacturer", o.manufacturer) || !get(hardware, "model", o.model) ||
            !get(hardware, "system", o.system) || !get(hardware, "bios", o.bios) ||
            !get(hardware, "processors", o.processors, &inputs.processors) ||
            !get(hardware, "memory", o.memory, &inputs.memory) ||
            !get(hardware, "disks", o.disks, &inputs.disks) ||
            !get(device_identity, "device_name", o.device_name) ||
            !get(device_identity, "domain", o.domain) || !get(device_identity, "ou", o.ou) ||
            !get(os_info, "os_name", o.os_name) || !get(os_info, "os_version", o.os_version) ||
            !get(os_info, "os_build", o.os_build) || !get(os_info, "os_arch", o.os_arch) ||
            !get(network_config, "adapters", o.adapters))
            return std::nullopt; // a required action failed → skip the cycle

        CiRecord rec = build_device_ci_record(o);

        // UP-1: a transient WMI/DMI outage makes the identity actions emit the
        // "unknown" sentinel at rc=0 (the per-action rc check above can't see it).
        // Persisting that record would overwrite the last-good CI row and flap the
        // content hash every blip; worse, every affected host stores the same
        // serial/uuid="unknown". Skip the cycle instead — the next cycle re-collects.
        // A genuinely serial-less VM (real manufacturer/model) is NOT caught here.
        if (core_identity_unavailable(rec)) {
            spdlog::warn("sync: device_ci core identity unavailable (manufacturer + model both "
                         "'unknown' — WMI/DMI down) — skipping this cycle");
            return std::nullopt;
        }

        // The section actions added with v2 never abort the cycle: a failure, truncation or an
        // absent plugin becomes a typed section status in the blob. A planned leg is the norm
        // until the legs land, so a degraded section is only a debug line.
        auto run_section = [&](const YuzuPluginDescriptor* d, const char* action,
                               CiActionResult& dst) {
            dst = to_action_result(dispatcher.run(d, action));
            if (dst.rc != 0 || dst.truncated || dst.status == YUZU_RESULT_STATUS_UNAVAILABLE ||
                dst.status == YUZU_RESULT_STATUS_PERMISSION_DENIED)
                spdlog::debug("sync: device_ci section action '{}' degraded (rc={}, truncated={})",
                              action, dst.rc, dst.truncated);
        };
        run_section(hardware, "chassis", inputs.chassis);
        run_section(hardware, "baseboard", inputs.baseboard);
        run_section(hardware, "swap", inputs.swap);
        run_section(hardware, "machine_id", inputs.machine_id);
        inputs.disk_actions_loaded = disk_actions != nullptr;
        if (disk_actions != nullptr) {
            run_section(disk_actions, "volumes", inputs.volumes);
            run_section(disk_actions, "partitions", inputs.partitions);
            run_section(disk_actions, "topology", inputs.topology);
        }

        std::string blob = device_ci_canonical_blob_v2(rec, inputs);
        if (blob.size() > kDeviceCiMaxBlobBytes) {
            spdlog::warn("sync: device_ci blob {} B exceeds {} B cap — skipping this cycle",
                         blob.size(), kDeviceCiMaxBlobBytes);
            return std::nullopt;
        }
        std::string hash = sha256_hex(blob);
        return std::make_pair(std::move(blob), std::move(hash));
    };
    return src;
}

} // namespace yuzu::agent
