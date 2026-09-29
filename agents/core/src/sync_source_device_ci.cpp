#include "sync_source_device_ci.hpp"

#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // sanitize_utf8_strict / clamp_field / sha256_hex

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

namespace {

// Caps — MUST match the server seam (device_ci_ingestion.cpp) so the server's
// parse never truncates/drops differently from what this source hashed.
constexpr std::size_t kMaxFieldLen = 1024;
// The device-CI canonical blob is a single small record (~22 short fields); 64 KiB
// is far above any real machine and well below the gRPC 4 MiB receive ceiling.
constexpr std::size_t kMaxBlobBytes = 64u * 1024;

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

} // namespace

std::string device_ci_canonical_blob(const CiRecord& rec) {
    // POSITIONAL — field order is the contract (see CiRecord). Each field is
    // scrub+clamp'd here; the server re-clamps on parse (idempotent) and rejoins.
    const std::string fields[] = {
        rec.manufacturer, rec.model,       rec.serial,        rec.system_uuid,
        rec.hostname,     rec.domain,      rec.ou,            rec.bios_vendor,
        rec.bios_version, rec.bios_date,   rec.cpu_model,     rec.cpu_cores,
        rec.cpu_threads,  rec.ram_bytes,   rec.disks_summary, rec.primary_mac,
        rec.macs_summary, rec.nic_count,   rec.os_name,       rec.os_version,
        rec.os_build,     rec.arch,
    };
    std::string canon;
    bool first = true;
    for (const auto& f : fields) {
        if (!first)
            canon += '\x1f';
        canon += clamp_field(f, kMaxFieldLen);
        first = false;
    }
    canon += '\x1e';
    return canon;
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

    // processors: `cpu|<id>|<model>|<cores>|<threads>|<mhz>` — model from the first
    // CPU, cores/threads summed across sockets.
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

    // memory: `dimm|<slot>|<size_mb>|<type>|<speed_mhz>` — sum size_mb → bytes.
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
                                 const YuzuPluginDescriptor* network_config) {
    SyncSource src;
    src.name = "device_ci";
    src.interval = std::chrono::hours{24};
    src.collect = [hardware, device_identity, os_info,
                   network_config]() -> std::optional<std::pair<std::string, std::string>> {
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
        // Run one action, returning its captured stdout. Any rc!=0 or a truncated
        // capture aborts the whole cycle (skip — never sync a partial CI record,
        // which would flap the hash). nullopt propagates the abort.
        auto run = [&](const YuzuPluginDescriptor* d,
                       const char* action) -> std::optional<std::string> {
            LocalDispatcher::Result r = dispatcher.run(d, action);
            if (r.rc != 0) {
                spdlog::warn("sync: device_ci action '{}' rc={} — skipping this cycle", action,
                             r.rc);
                return std::nullopt;
            }
            if (r.truncated) {
                spdlog::warn("sync: device_ci action '{}' output truncated — skipping this cycle",
                             action);
                return std::nullopt;
            }
            return std::move(r.captured);
        };

        CiPluginOutputs o;
        auto get = [&](const YuzuPluginDescriptor* d, const char* action,
                       std::string& dst) -> bool {
            auto r = run(d, action);
            if (!r)
                return false;
            dst = std::move(*r);
            return true;
        };
        // Any failed action aborts the cycle (|| short-circuits — a later action is
        // not dispatched once one fails). Never sync a partial CI record.
        if (!get(hardware, "manufacturer", o.manufacturer) || !get(hardware, "model", o.model) ||
            !get(hardware, "system", o.system) || !get(hardware, "bios", o.bios) ||
            !get(hardware, "processors", o.processors) || !get(hardware, "memory", o.memory) ||
            !get(hardware, "disks", o.disks) ||
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

        std::string blob = device_ci_canonical_blob(rec);
        if (blob.size() > kMaxBlobBytes) {
            spdlog::warn("sync: device_ci blob {} B exceeds {} B cap — skipping this cycle",
                         blob.size(), kMaxBlobBytes);
            return std::nullopt;
        }
        std::string hash = sha256_hex(blob);
        return std::make_pair(std::move(blob), std::move(hash));
    };
    return src;
}

} // namespace yuzu::agent
