#include "sync_source_installed_software.hpp"

#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // sanitize_utf8_strict / clamp_field / sha256_hex

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <optional>
#include <string_view>
#include <utility>

namespace yuzu::agent {

namespace {

// Must match the server seam's caps (inventory_ingestion.cpp) so the server's
// parse does not truncate/drop differently from what this source hashed.
constexpr std::size_t kMaxEntries = 20000;
constexpr std::size_t kMaxFieldLen = 1024;
// Total canonical-blob ceiling — MUST equal the server seam's kMaxBlobBytes
// (inventory_ingestion.cpp); the two are comment-coordinated. Deliberately set
// BELOW the gRPC default 4 MiB max-receive-message limit (no SetMaxReceiveMessageSize
// override exists on the agent channel, the server, or the gateway hop), with
// headroom for the InventoryReport's proto/map framing + content_hashes +
// collected_at on top of the blob. At 4 MiB the wire message would exceed the
// 4 MiB receive ceiling and the RPC would be rejected before the handler runs —
// a permanent tight retry loop (governance UP-6). A 3 MiB canonical blob is
// ~20k v2 entries (~150 B/record with the 12-field blob-v2 layout), which
// matches kMaxEntries as the binding limit; no real machine reaches it, and an
// over-cap host is dropped (governance UP-4) rather than looping. Lowering this
// trades "outlier host skips" for "outlier host loops" — the right call for
// installed software.
constexpr std::size_t kMaxBlobBytes = 3u * 1024 * 1024;

// The UTF-8 scrub + field clamp (sanitize_utf8_strict / clamp_field) live in
// sync_canonical.{hpp,cpp} — one agent-side implementation shared by every
// daily-sync source. The server's copy in inventory_ingestion.cpp
// (parse_software_blob) must stay byte-for-byte identical, or the agent's and
// server's canonical hashes diverge → permanent always-full. This source's
// field cap is kMaxFieldLen above (comment-coordinated with the server seam).

// Sort/dedup key walks ALL 12 v2 fields in blob order. MUST mirror the server's
// entry_less/entry_equal (software_inventory_store.cpp) or the two sides'
// canonical hashes diverge → permanent always-full.
bool entry_less(const SwEntry& a, const SwEntry& b) {
    if (a.name != b.name)
        return a.name < b.name;
    if (a.version != b.version)
        return a.version < b.version;
    if (a.publisher != b.publisher)
        return a.publisher < b.publisher;
    if (a.install_date != b.install_date)
        return a.install_date < b.install_date;
    if (a.kind != b.kind)
        return a.kind < b.kind;
    if (a.ecosystem != b.ecosystem)
        return a.ecosystem < b.ecosystem;
    if (a.epoch != b.epoch)
        return a.epoch < b.epoch;
    if (a.release != b.release)
        return a.release < b.release;
    if (a.arch != b.arch)
        return a.arch < b.arch;
    if (a.signature_status != b.signature_status)
        return a.signature_status < b.signature_status;
    if (a.distro_id != b.distro_id)
        return a.distro_id < b.distro_id;
    return a.distro_version < b.distro_version;
}

bool entry_equal(const SwEntry& a, const SwEntry& b) {
    return a.name == b.name && a.version == b.version && a.publisher == b.publisher &&
           a.install_date == b.install_date && a.kind == b.kind && a.ecosystem == b.ecosystem &&
           a.epoch == b.epoch && a.release == b.release && a.arch == b.arch &&
           a.signature_status == b.signature_status && a.distro_id == b.distro_id &&
           a.distro_version == b.distro_version;
}

} // namespace

std::vector<SwEntry> parse_installed_apps_output(const std::string& out) {
    std::vector<SwEntry> entries;
    std::size_t pos = 0;
    while (pos < out.size() && entries.size() < kMaxEntries) {
        std::size_t eol = out.find('\n', pos);
        if (eol == std::string::npos)
            eol = out.size();
        std::string_view line(out.data() + pos, eol - pos);
        while (!line.empty() && (line.back() == '\r'))
            line.remove_suffix(1);
        pos = eol + 1;
        if (line.empty())
            continue;

        // Split on '|' into up to 13 tokens (the `inv` prefix + 12 v2 fields).
        // Anything past the 13th token is dropped — the same truncation the
        // server's parse applies past field 12, so fields can never shift.
        std::vector<std::string_view> tok;
        std::size_t fp = 0;
        while (tok.size() < 13) {
            std::size_t bar = line.find('|', fp);
            if (bar == std::string_view::npos) {
                tok.push_back(line.substr(fp));
                break;
            }
            tok.push_back(line.substr(fp, bar - fp));
            fp = bar + 1;
        }
        if (tok.empty() || tok[0] != "inv")
            continue; // skip app|, user_app|, error|, found|, etc.
        if (tok.size() < 2 || tok[1].empty())
            continue; // malformed / empty name

        // Blob contract v2 field order; missing trailing tokens → empty fields.
        SwEntry e;
        const auto field = [&tok](std::size_t i) -> std::string {
            return tok.size() > i ? clamp_field(tok[i], kMaxFieldLen) : std::string{};
        };
        e.name = field(1);
        e.version = field(2);
        e.publisher = field(3);
        e.install_date = field(4);
        e.kind = field(5);
        e.ecosystem = field(6);
        e.epoch = field(7);
        e.release = field(8);
        e.arch = field(9);
        e.signature_status = field(10);
        e.distro_id = field(11);
        e.distro_version = field(12);
        // Drop a name that became empty AFTER clamping (e.g. a separator-only
        // name). The server's parse_software_blob drops empty-name rows, so the
        // agent must too or the two canonical hashes diverge → permanent
        // always-full (governance UP-1). Mirrors the server's `!e.name.empty()`.
        if (e.name.empty())
            continue;
        entries.push_back(std::move(e));
    }
    return entries;
}

std::string installed_software_canonical_blob(std::vector<SwEntry> entries) {
    std::sort(entries.begin(), entries.end(), entry_less);
    entries.erase(std::unique(entries.begin(), entries.end(), entry_equal), entries.end());
    // Blob contract v2: 12 fields, 0x1F-separated, in this exact order, record-
    // terminated 0x1E — byte-identical to the server's canonical_hash walk
    // (software_inventory_store.cpp). Append-only: never reorder.
    std::string canon;
    canon.reserve(entries.size() * 96);
    for (const auto& e : entries) {
        canon += e.name;
        canon += '\x1f';
        canon += e.version;
        canon += '\x1f';
        canon += e.publisher;
        canon += '\x1f';
        canon += e.install_date;
        canon += '\x1f';
        canon += e.kind;
        canon += '\x1f';
        canon += e.ecosystem;
        canon += '\x1f';
        canon += e.epoch;
        canon += '\x1f';
        canon += e.release;
        canon += '\x1f';
        canon += e.arch;
        canon += '\x1f';
        canon += e.signature_status;
        canon += '\x1f';
        canon += e.distro_id;
        canon += '\x1f';
        canon += e.distro_version;
        canon += '\x1e';
    }
    return canon;
}

SyncSource make_installed_software_source(const YuzuPluginDescriptor* descriptor) {
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::hours{24};
    src.collect = [descriptor]() -> std::optional<std::pair<std::string, std::string>> {
        if (descriptor == nullptr) {
            spdlog::debug("sync: installed_apps plugin not loaded — installed_software source idle");
            return std::nullopt;
        }
        LocalDispatcher dispatcher;
        // Per-call capture cap: v2's 12-field rows (~200 B each raw) would
        // saturate the shared 2 MiB default around ~14k packages, turning a
        // dense host into a permanent silent cycle-skip. 3.5 MiB re-aligns the
        // capture ceiling with kMaxEntries (20k) as the binding limit: a 20k-row
        // canonical blob is ~2.8 MB, still under kMaxBlobBytes (3 MiB) and the
        // 4 MiB gRPC receive ceiling. The shared default stays 2 MiB.
        constexpr std::size_t kInventoryCaptureCap = 3'670'016; // 3.5 MiB
        LocalDispatcher::Result r =
            dispatcher.run(descriptor, "list_inventory", {}, kInventoryCaptureCap);
        if (r.rc != 0) {
            spdlog::warn("sync: installed_apps 'list_inventory' rc={} — skipping this cycle", r.rc);
            return std::nullopt;
        }
        if (r.truncated) {
            // The capture hit the byte cap — parsing it would yield a partial
            // inventory and a hash that flip-flops. Drop this cycle rather than
            // sync wrong data (mirrors the snapshot pump).
            spdlog::warn("sync: installed_apps 'list_inventory' output truncated at the capture "
                         "cap — skipping this cycle");
            return std::nullopt;
        }
        auto entries = parse_installed_apps_output(r.captured);
        if (entries.empty()) {
            // A real endpoint always reports >= 1 application; an empty parse is a
            // transient plugin hiccup (or an old plugin without the action → rc!=0
            // above), NOT a genuine "everything uninstalled". Sending an empty full
            // payload would DELETE the agent's stored inventory and the server
            // would record the wipe as a successful store (governance UP-IN6). Skip
            // the cycle and keep the last good state; the next cycle re-collects.
            spdlog::debug("sync: installed_apps 'list_inventory' yielded no entries — skipping "
                          "this cycle (not wiping stored inventory)");
            return std::nullopt;
        }
        std::string blob = installed_software_canonical_blob(std::move(entries));
        if (blob.size() > kMaxBlobBytes) {
            spdlog::warn("sync: installed_software blob {} B exceeds {} B cap — skipping this "
                         "cycle (won't send an un-storable payload)",
                         blob.size(), kMaxBlobBytes);
            return std::nullopt;
        }
        std::string hash = sha256_hex(blob);
        return std::make_pair(std::move(blob), std::move(hash));
    };
    return src;
}

} // namespace yuzu::agent
