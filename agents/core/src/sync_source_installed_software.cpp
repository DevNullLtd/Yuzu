#include "sync_source_installed_software.hpp"

#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // sanitize_utf8_strict / clamp_field / sha256_hex

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>
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
// a permanent tight retry loop (governance UP-6). Real captures measure ~111-113 B
// per record including the 16-field tail (Mac: 460 records / 51,062 B; Windows:
// 378 / 42,556 B; tests/unit/test_inventory_sync.cpp); a dense host at ~150 B per
// 12-field record plus the ~35 B tail (~185 B) hits this byte cap near ~17k
// records, before kMaxEntries (20k). No real machine reaches either; an over-cap
// host is dropped (governance UP-4) rather than looping. Lowering this
// trades "outlier host skips" for "outlier host loops" — the right call for
// installed software.
constexpr std::size_t kMaxBlobBytes = 3u * 1024 * 1024;

// The UTF-8 scrub + field clamp (sanitize_utf8_strict / clamp_field) live in
// sync_canonical.{hpp,cpp} — one agent-side implementation shared by every
// daily-sync source. The server's copy in inventory_ingestion.cpp
// (parse_software_blob) must stay byte-for-byte identical, or the agent's and
// server's canonical hashes diverge → permanent always-full. This source's
// field cap is kMaxFieldLen above (comment-coordinated with the server seam).

// Sort/dedup key walks the 12 v2 fields then the package_id/source tail, in blob
// order. MUST mirror the server's entry_less/entry_equal
// (software_inventory_store.cpp) or the two sides' canonical hashes diverge →
// permanent always-full.
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
    if (a.distro_version != b.distro_version)
        return a.distro_version < b.distro_version;
    // Extended tail LAST, package_id then source — byte-for-byte the server's
    // comparator (software_inventory_store.cpp).
    if (a.package_id != b.package_id)
        return a.package_id < b.package_id;
    return a.source < b.source;
}

bool entry_equal(const SwEntry& a, const SwEntry& b) {
    return a.name == b.name && a.version == b.version && a.publisher == b.publisher &&
           a.install_date == b.install_date && a.kind == b.kind && a.ecosystem == b.ecosystem &&
           a.epoch == b.epoch && a.release == b.release && a.arch == b.arch &&
           a.signature_status == b.signature_status && a.distro_id == b.distro_id &&
           a.distro_version == b.distro_version && a.package_id == b.package_id &&
           a.source == b.source;
}

// The single sort + dedup in the server's comparator order, shared by the cap
// check and the canonical blob.
void normalize_installed_software(std::vector<SwEntry>& entries) {
    std::sort(entries.begin(), entries.end(), entry_less);
    entries.erase(std::unique(entries.begin(), entries.end(), entry_equal), entries.end());
}

// ── shared line/token splitters (installed_apps + the pkg/wof adapters) ──

// Calls `fn(line)` for every non-empty line (CRLF-tolerant) until it returns false.
template <class Fn> void for_each_line(const std::string& out, Fn&& fn) {
    std::size_t pos = 0;
    while (pos < out.size()) {
        std::size_t eol = out.find('\n', pos);
        if (eol == std::string::npos)
            eol = out.size();
        std::string_view line(out.data() + pos, eol - pos);
        while (!line.empty() && (line.back() == '\r'))
            line.remove_suffix(1);
        pos = eol + 1;
        if (line.empty())
            continue;
        if (!fn(line))
            return;
    }
}

// Split on '|' into at most `max` tokens; anything past the max-th token is dropped.
std::vector<std::string_view> split_tokens(std::string_view line, std::size_t max) {
    std::vector<std::string_view> tok;
    std::size_t fp = 0;
    while (tok.size() < max) {
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

AdaptedRows failed(std::string reason) {
    AdaptedRows r;
    r.status = AdaptedRows::Status::failed;
    r.reason = std::move(reason);
    return r;
}

// `pkg_inventory` grammar (pkg_inventory_parsers.hpp format_status_row /
// format_manager_row / format_package_row): exactly one
// `status|<action>|<supported|constrained|unsupported>|<tokens or ->` row, plus
// data rows. Status decides success; malformed DATA rows are dropped. A status
// row answering a different action is not counted (-> "bad status").
// `constrained_fails`: a `constrained` level fails the action (packages: a
// constrained listing is an incomplete package list). When false (managers) the
// constraint names facts the presence row does not carry, so the adapted rows
// are kept (status ok, reason = the status token) -- but ONLY if at least one
// present row survived: constrained with zero rows is indistinguishable from an
// absent/unreadable manager and still fails.
template <class OnRow>
AdaptedRows adapt_pkg_inventory(const std::string& out, std::string_view action, OnRow on_row,
                                bool constrained_fails) {
    AdaptedRows res;
    int status_rows = 0;
    std::string level;
    std::string reason;
    for_each_line(out, [&](std::string_view line) {
        const auto tok = split_tokens(line, 8);
        if (tok[0] == "status") {
            if (tok.size() >= 4 && tok[1] == action) {
                ++status_rows;
                level = std::string(tok[2]);
                reason = std::string(tok[3]);
            }
            return true;
        }
        on_row(tok, res.entries);
        return res.entries.size() <= kMaxEntries;
    });
    if (status_rows != 1 || (level != "supported" && level != "constrained" && level != "unsupported"))
        return failed("bad status");
    if (level == "constrained") {
        if (constrained_fails || res.entries.empty())
            return failed(reason);
        res.reason = reason; // ok + non-empty reason = constrained, rows kept
    }
    if (level == "unsupported") {
        res.entries.clear();
        res.status = AdaptedRows::Status::unsupported;
    }
    return res;
}

// One table row per inventory action. Adding an action = one row + one pure adapter.
struct InventoryAction {
    std::string_view plugin;
    std::string_view action;
    AdaptedRows (*adapt)(const std::string& captured);
    // A typed result_completeness of PARTIAL (sdk/include/yuzu/plugin.h:264-267)
    // skips the cycle unless the row opts in. managers opts in: it legitimately
    // reports CONSTRAINED/PARTIAL while still carrying a present row.
    bool accept_partial{false};
};

// UP-IN6 preserved per plugin: installed_apps always reports >= 1 application on a
// real endpoint, so an empty parse is a plugin hiccup, NOT "everything uninstalled".
// Sending the other plugins' rows alone would DELETE the stored apps.
AdaptedRows adapt_installed_apps(const std::string& captured) {
    AdaptedRows r;
    r.entries = parse_installed_apps_output(captured);
    if (r.entries.empty())
        return failed("no inv rows");
    return r;
}

const InventoryAction kInventoryActions[] = {
    {"installed_apps", "list_inventory", adapt_installed_apps},
    {"pkg_inventory", "managers", parse_pkg_inventory_managers_output, true},
    {"pkg_inventory", "packages", parse_pkg_inventory_packages_output},
    {"windows_optional_features", "list", parse_windows_optional_features_output},
};

} // namespace

std::vector<SwEntry> parse_installed_apps_output(const std::string& out) {
    std::vector<SwEntry> entries;
    // Reads ONE PAST kMaxEntries so the collector's per-action raw-count check can
    // see an over-cap host and skip the cycle rather than hash a silently truncated
    // list.
    for_each_line(out, [&entries](std::string_view line) {
        // Split on '|' into up to 13 tokens (the `inv` prefix + 12 v2 fields).
        // Anything past the 13th token is dropped — the same truncation the
        // server's parse applies past field 12, so fields can never shift.
        const auto tok = split_tokens(line, 13);
        if (tok.empty() || tok[0] != "inv")
            return true; // skip app|, user_app|, error|, found|, etc.
        if (tok.size() < 2 || tok[1].empty())
            return true; // malformed / empty name

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
        if (!e.name.empty())
            entries.push_back(std::move(e));
        return entries.size() <= kMaxEntries;
    });
    return entries;
}

AdaptedRows parse_pkg_inventory_packages_output(const std::string& out) {
    // package|homebrew|<id>|<version>|<formula|cask>
    return adapt_pkg_inventory(out, "packages",
                               [](const std::vector<std::string_view>& tok,
                                  std::vector<SwEntry>& entries) {
        if (tok[0] != "package" || tok.size() != 5 || tok[1] != "homebrew")
            return;
        SwEntry e;
        e.name = clamp_field(tok[2], kMaxFieldLen);
        if (e.name.empty())
            return;
        if (tok[4] == "formula")
            e.kind = "pkg";
        else if (tok[4] == "cask")
            e.kind = "app";
        else
            return;
        e.version = clamp_field(tok[3], kMaxFieldLen);
        e.ecosystem = "brew";
        entries.push_back(std::move(e));
    }, /*constrained_fails=*/true);
}

AdaptedRows parse_pkg_inventory_managers_output(const std::string& out) {
    // manager|<name>|<present|unavailable>|<version or ->|<root>|<facts>|<reason>
    // A PRESENCE row only (the v2 row has no field for the prefix, so two Homebrew
    // prefixes collapse to one row after dedup). Homebrew-only: any other manager
    // name (dpkg/apt/rpm/dnf/pacman/apk) is dropped — the Linux/Windows managers
    // legs must add a deliberate mapping, and manager facts belong to facet rows.
    return adapt_pkg_inventory(out, "managers",
                               [](const std::vector<std::string_view>& tok,
                                  std::vector<SwEntry>& entries) {
        if (tok[0] != "manager" || tok.size() != 7 || tok[2] != "present")
            return;
        if (tok[1] != "homebrew") {
            spdlog::debug("sync: pkg_inventory manager '{}' has no installed_software mapping — "
                          "dropped",
                          tok[1]);
            return;
        }
        SwEntry e;
        e.name = "homebrew";
        e.version = tok[3] == "-" ? std::string{} : clamp_field(tok[3], kMaxFieldLen);
        e.kind = "app";
        e.ecosystem = "brew";
        entries.push_back(std::move(e));
    }, /*constrained_fails=*/false);
}

AdaptedRows parse_windows_optional_features_output(const std::string& out) {
    // windows_optional_features_parsers.hpp: `feature|<name>|<state>|<0/1>` per
    // feature (no status row in this grammar); sentinels are 3-token
    // `feature|unsupported|<token>` / `feature|unavailable|<token>`. The restart
    // flag is dropped (transient, no slot); the state token rides in `version`.
    AdaptedRows res;
    AdaptedRows sentinel; // status != ok once an unsupported/unavailable sentinel row is seen
    for_each_line(out, [&](std::string_view line) {
        const auto tok = split_tokens(line, 5);
        if (tok[0] != "feature")
            return true;
        if (tok.size() == 3 && tok[1] == "unsupported") {
            sentinel.status = AdaptedRows::Status::unsupported;
            return false;
        }
        if (tok.size() == 3 && tok[1] == "unavailable") {
            sentinel = failed(std::string(tok[2]));
            return false;
        }
        if (tok.size() != 4)
            return true;
        SwEntry e;
        e.name = clamp_field(tok[1], kMaxFieldLen);
        if (e.name.empty())
            return true;
        e.version = clamp_field(tok[2], kMaxFieldLen);
        e.kind = "feat";
        e.ecosystem = "optional_feature";
        res.entries.push_back(std::move(e));
        return res.entries.size() <= kMaxEntries;
    });
    if (sentinel.status != AdaptedRows::Status::ok)
        return sentinel;
    if (res.entries.empty())
        return failed("no rows");
    return res;
}

std::vector<std::pair<std::string_view, std::string_view>> installed_software_actions() {
    std::vector<std::pair<std::string_view, std::string_view>> out;
    for (const auto& row : kInventoryActions)
        out.emplace_back(row.plugin, row.action);
    return out;
}

std::string installed_software_canonical_blob(std::vector<SwEntry> entries) {
    normalize_installed_software(entries);
    // Blob contract v2: 12 fields, 0x1F-separated, in this exact order, record-
    // terminated 0x1E — byte-identical to the server's canonical_hash walk
    // (software_inventory_store.cpp). Append-only: never reorder. The 4-field tail
    // (reserved install_location, reserved uninstall_string, package_id, source)
    // is appended whole only when package_id or source is non-empty, so a 12-field
    // entry hashes exactly as it always did.
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
        if (!e.package_id.empty() || !e.source.empty()) {
            canon += "\x1f\x1f"; // reserved slots 13-14: always empty
            canon += '\x1f';
            canon += e.package_id;
            canon += '\x1f';
            canon += e.source;
        }
        canon += '\x1e';
    }
    return canon;
}

SyncSource make_installed_software_source(SyncPluginMap plugins) {
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::hours{24};
    src.collect = [plugins = std::move(plugins)]() -> std::optional<std::pair<std::string, std::string>> {
        // installed_apps anchors the report (UP-IN6): without it the other
        // plugins' rows alone would replace the stored inventory.
        const auto anchor = plugins.find("installed_apps");
        if (anchor == plugins.end() || anchor->second == nullptr) {
            spdlog::warn("sync: installed_apps plugin not loaded — installed_software source idle");
            return std::nullopt;
        }
        LocalDispatcher dispatcher;
        // Per-call capture cap: v2's 12-field rows (~200 B each raw) would
        // saturate the shared 2 MiB default around ~14k packages, turning a
        // dense host into a permanent silent cycle-skip. 3.5 MiB re-aligns the
        // capture ceiling with the 3 MiB blob cap (a ~17k-row blob is ~3 MiB; raw rows
        // are larger than their canonical form). The shared default stays 2 MiB.
        constexpr std::size_t kInventoryCaptureCap = 3'670'016; // 3.5 MiB
        std::vector<SwEntry> all;
        for (const auto& row : kInventoryActions) {
            const auto it = plugins.find(row.plugin);
            if (it == plugins.end() || it->second == nullptr) {
                spdlog::warn("sync: {} plugin not loaded — {} rows will be absent from this report "
                             "(its stored rows are removed server-side)",
                             row.plugin, row.action);
                continue;
            }
            LocalDispatcher::Result r =
                dispatcher.run(it->second, row.action, {}, kInventoryCaptureCap);
            if (r.rc != 0 || r.truncated) {
                // A truncated capture would yield a partial inventory and a hash that
                // flip-flops (mirrors the snapshot pump) — drop the cycle.
                spdlog::warn("sync: {}.{} rc={}{} — skipping this cycle", row.plugin, row.action,
                             r.rc, r.truncated ? " (output truncated at the capture cap)" : "");
                return std::nullopt;
            }
            AdaptedRows rows = row.adapt(r.captured);
            if (rows.entries.size() > kMaxEntries) {
                // Every adapter stops reading at kMaxEntries + 1 RAW rows, so the post-
                // dedup merged check below cannot see the overflow once exact
                // duplicates pull the count back under the cap — a truncated inventory
                // would ship as complete. Same UP-4 posture as the byte cap.
                spdlog::warn("sync: {}.{} read more than {} rows — skipping this cycle",
                             row.plugin, row.action, kMaxEntries);
                return std::nullopt;
            }
            if (rows.status == AdaptedRows::Status::unsupported) {
                spdlog::debug("sync: {}.{} unsupported on this OS — skipped", row.plugin,
                              row.action);
                continue;
            }
            if (rows.status == AdaptedRows::Status::failed) {
                spdlog::warn("sync: {}.{} failed: {} — skipping this cycle", row.plugin, row.action,
                             rows.reason);
                return std::nullopt;
            }
            if (r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL && !row.accept_partial) {
                spdlog::warn("sync: {}.{} typed result completeness PARTIAL — skipping this cycle",
                             row.plugin, row.action);
                return std::nullopt;
            }
            if (!rows.reason.empty())
                spdlog::info("sync: {}.{} constrained ({}) — rows kept: the constraint names facts "
                             "this row does not carry",
                             row.plugin, row.action, rows.reason);
            std::string source = std::string(row.plugin) + '.' + std::string(row.action);
            for (auto& e : rows.entries) {
                e.source = source;
                all.push_back(std::move(e));
            }
        }
        if (all.empty()) {
            spdlog::debug("sync: installed_software collected no rows — skipping this cycle");
            return std::nullopt;
        }
        normalize_installed_software(all);
        if (all.size() > kMaxEntries) {
            // The server keeps the first kMaxEntries in blob order, so its hash would
            // diverge from ours → permanent need_full. Same UP-4 posture as the byte cap.
            spdlog::warn("sync: installed_software {} entries exceed {} cap — skipping this cycle",
                         all.size(), kMaxEntries);
            return std::nullopt;
        }
        std::string blob = installed_software_canonical_blob(std::move(all));
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
