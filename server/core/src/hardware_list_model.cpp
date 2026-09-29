/// @file hardware_list_model.cpp
/// See hardware_list_model.hpp.

#include "hardware_list_model.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <unordered_set>

namespace yuzu::server {

namespace {

std::string to_lower_ascii(std::string_view s) {
    std::string out(s);
    for (char& c : out)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    return out;
}

bool is_blank_sentinel(const std::string& s) { return s.empty() || s == "unknown"; }

// inventory_ui.cpp has its own os_label() (anonymous-namespace, internal linkage) —
// this file defines its own copy rather than exporting a shared one, since pulling
// in the whole UI translation unit just for this one mapping isn't worth it.
std::string os_label(const std::string& os) {
    const std::string lower = to_lower_ascii(os);
    if (lower == "windows" || lower == "win")
        return "Windows";
    if (lower == "linux" || lower == "lin")
        return "Linux";
    if (lower == "darwin" || lower == "macos" || lower == "mac")
        return "macOS";
    return os;
}

/// Numeric compare on a decimal-string field (e.g. ci_ram_bytes) that tolerates a
/// blank/non-numeric value by treating it as "smaller than any real value" — the
/// caller still applies the blanks-last-both-directions rule on top of this.
std::int64_t parse_i64_or_min(const std::string& s) {
    std::int64_t v = 0;
    auto res = std::from_chars(s.data(), s.data() + s.size(), v);
    if (res.ec != std::errc{} || res.ptr != s.data() + s.size())
        return std::numeric_limits<std::int64_t>::min();
    return v;
}

/// "major.minor.patch" -> {major, minor, patch}, ignoring a trailing "+build" suffix
/// (kFullVersionString = "@PROJECT_VERSION@+@YUZU_BUILD_NUMBER@"). At most 3 dotted
/// numeric components; missing trailing components read as 0. nullopt on anything
/// empty, non-numeric, or pre-release-tagged (e.g. "-rc1") — callers fail closed
/// (agent_supports_sync_now) or fall back to a lexicographic compare (the Version
/// sort column), never crash or silently misorder.
std::optional<std::array<int, 3>> parse_semver3(std::string_view agent_version) noexcept {
    const auto plus = agent_version.find('+');
    std::string_view v = plus == std::string_view::npos ? agent_version : agent_version.substr(0, plus);
    if (v.empty())
        return std::nullopt;
    std::array<int, 3> parts{0, 0, 0};
    std::size_t idx = 0;
    std::size_t start = 0;
    while (start <= v.size() && idx < 3) {
        const auto dot = v.find('.', start);
        const std::string_view comp = v.substr(start, dot == std::string_view::npos ? std::string_view::npos
                                                                                      : dot - start);
        if (comp.empty())
            return std::nullopt;
        int n = 0;
        const auto res = std::from_chars(comp.data(), comp.data() + comp.size(), n);
        if (res.ec != std::errc{} || res.ptr != comp.data() + comp.size() || n < 0)
            return std::nullopt; // non-numeric (incl. "-rc1") → fail closed
        parts[idx++] = n;
        if (dot == std::string_view::npos)
            break;
        start = dot + 1;
    }
    return parts;
}

int status_rank(const InventoryDeviceRow& row) {
    if (row.online)
        return 0;
    if (row.stale)
        return 2;
    return 1; // offline, not (yet) stale
}

std::string hw_search_haystack(const InventoryDeviceRow& row) {
    std::string h;
    h.reserve(128);
    auto add = [&h](const std::string& part) {
        if (is_blank_sentinel(part))
            return;
        h += to_lower_ascii(part);
        h += ' ';
    };
    add(row.hostname);
    add(row.agent_id);
    add(row.os);
    add(os_label(row.os));
    add(row.ci_serial);
    add(row.ci_model);
    add(row.ci_manufacturer);
    add(row.ci_cpu_model);
    add(row.ci_os_name);
    add(row.ci_os_version);
    add(row.ci_os_build);
    add(row.ci_domain);
    add(row.ci_arch);
    add(row.agent_version);
    add(row.arch);
    for (const auto& ip : row.ips) add(ip);
    for (const auto& [k, v] : row.tags) {
        add(k);
        if (!v.empty()) add(k + "=" + v);
    }
    return h;
}

// "key" or "key=value" -> {key, optional value}. Caller has already validated the
// key half (normalise_hardware_query); an empty key means "no filter".
std::pair<std::string_view, std::optional<std::string_view>> split_tag_filter(std::string_view tag) {
    if (tag.empty())
        return {{}, std::nullopt};
    const auto eq = tag.find('=');
    if (eq == std::string_view::npos)
        return {tag, std::nullopt};
    return {tag.substr(0, eq), tag.substr(eq + 1)};
}

bool tag_token_matches(const InventoryDeviceRow& row, std::string_view tag) {
    const auto [key, value] = split_tag_filter(tag);
    if (key.empty())
        return true;
    for (const auto& [k, v] : row.tags) {
        if (k != key)
            continue;
        if (!value || *value == v)
            return true;
    }
    return false;
}

bool os_token_matches(const InventoryDeviceRow& row, std::string_view os_token) {
    if (os_token == "all")
        return true;
    const std::string os = to_lower_ascii(row.os);
    if (os_token == "windows")
        return os == "windows" || os == "win";
    if (os_token == "linux")
        return os == "linux" || os == "lin";
    if (os_token == "macos")
        return os == "darwin" || os == "macos" || os == "mac";
    return false; // unreachable once normalise_hardware_query has validated os_token
}

bool status_token_matches(const InventoryDeviceRow& row, std::string_view status_token) {
    if (status_token == "all")
        return true;
    if (status_token == "online")
        return row.online;
    if (status_token == "offline")
        return !row.online; // offline includes stale — stale is a KPI facet, not a filter facet
    return false;
}

/// `nlohmann::json` null for a blank/"unknown" sentinel string field, else the value.
nlohmann::json ci_json(const std::string& s) {
    if (is_blank_sentinel(s))
        return nullptr;
    return s;
}

/// `ci_ram_bytes` etc. are decimal strings; render as a JSON integer when parseable,
/// else null — never a stringly-typed number for a well-formed row.
nlohmann::json ci_json_int(const std::string& s) {
    if (is_blank_sentinel(s))
        return nullptr;
    std::int64_t v = 0;
    auto res = std::from_chars(s.data(), s.data() + s.size(), v);
    if (res.ec != std::errc{} || res.ptr != s.data() + s.size())
        return nullptr;
    return v;
}

} // namespace

std::optional<HwSortKey> parse_hw_sort_key(std::string_view token) {
    if (token == "name") return HwSortKey::Name;
    if (token == "os") return HwSortKey::Os;
    if (token == "status") return HwSortKey::Status;
    if (token == "last_seen") return HwSortKey::LastSeen;
    if (token == "manufacturer") return HwSortKey::Manufacturer;
    if (token == "model") return HwSortKey::Model;
    if (token == "serial") return HwSortKey::Serial;
    if (token == "cpu") return HwSortKey::Cpu;
    if (token == "ram") return HwSortKey::Ram;
    if (token == "os_version") return HwSortKey::OsVersion;
    if (token == "version") return HwSortKey::Version;
    if (token == "ip") return HwSortKey::Ip;
    return std::nullopt;
}

std::string_view hw_sort_token(HwSortKey key) {
    switch (key) {
        case HwSortKey::Name: return "name";
        case HwSortKey::Os: return "os";
        case HwSortKey::Status: return "status";
        case HwSortKey::LastSeen: return "last_seen";
        case HwSortKey::Manufacturer: return "manufacturer";
        case HwSortKey::Model: return "model";
        case HwSortKey::Serial: return "serial";
        case HwSortKey::Cpu: return "cpu";
        case HwSortKey::Ram: return "ram";
        case HwSortKey::OsVersion: return "os_version";
        case HwSortKey::Version: return "version";
        case HwSortKey::Ip: return "ip";
    }
    return "name"; // unreachable; silences -Wreturn-type on some compilers
}

std::optional<HardwareListQuery> normalise_hardware_query(HardwareListQuery raw) {
    HardwareListQuery q = std::move(raw);
    if (q.os.empty()) q.os = "all";
    if (q.status.empty()) q.status = "all";
    if (q.sort.empty()) q.sort = "name";
    q.os = to_lower_ascii(q.os);
    q.status = to_lower_ascii(q.status);
    q.sort = to_lower_ascii(q.sort);

    if (q.os != "all" && q.os != "windows" && q.os != "linux" && q.os != "macos")
        return std::nullopt;
    if (q.status != "all" && q.status != "online" && q.status != "offline")
        return std::nullopt;
    if (!parse_hw_sort_key(q.sort))
        return std::nullopt;
    if (!q.tag.empty()) {
        const auto [key, value] = split_tag_filter(q.tag);
        (void)value;
        if (!TagStore::validate_key(std::string(key)))
            return std::nullopt;
    }

    q.limit = std::clamp<std::size_t>(q.limit == 0 ? 50 : q.limit, 1, 200);
    // offset is clamped against the actual result size later, in build_hardware_list_page.
    return q;
}

std::vector<std::string> hw_search_tokens(std::string_view q) {
    std::vector<std::string> tokens;
    std::string cur;
    auto flush = [&] {
        if (!cur.empty()) {
            tokens.push_back(to_lower_ascii(cur));
            cur.clear();
        }
    };
    for (char c : q) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            flush();
        } else {
            cur.push_back(c);
        }
    }
    flush();
    if (tokens.size() > 8)
        tokens.resize(8);
    return tokens;
}

bool hw_row_matches(const InventoryDeviceRow& row, const std::vector<std::string>& tokens,
                    std::string_view os, std::string_view status, std::string_view tag) {
    if (!os_token_matches(row, os) || !status_token_matches(row, status))
        return false;
    if (!tag_token_matches(row, tag))
        return false;
    if (tokens.empty())
        return true;
    const std::string haystack = hw_search_haystack(row);
    for (const auto& tok : tokens)
        if (haystack.find(tok) == std::string::npos)
            return false;
    return true;
}

HardwareKpis hardware_kpis(const std::vector<InventoryDeviceRow>& roster) {
    HardwareKpis k;
    k.total = roster.size();
    for (const auto& row : roster) {
        if (row.online)
            ++k.online;
        else
            ++k.offline;
        if (row.stale)
            ++k.stale;
        if (!is_blank_sentinel(row.ci_serial) || !is_blank_sentinel(row.ci_model))
            ++k.with_ci;
    }
    return k;
}

HardwareListPage build_hardware_list_page(std::vector<InventoryDeviceRow> roster,
                                          const HardwareListQuery& normalised) {
    HardwareListPage page;
    page.kpis = hardware_kpis(roster);

    const std::vector<std::string> tokens = hw_search_tokens(normalised.q);
    std::vector<InventoryDeviceRow> matched;
    matched.reserve(roster.size());
    for (auto& row : roster)
        if (hw_row_matches(row, tokens, normalised.os, normalised.status, normalised.tag))
            matched.push_back(std::move(row));
    page.total_matching = matched.size();

    const auto key = parse_hw_sort_key(normalised.sort);
    const HwSortKey sort_key = key ? *key : HwSortKey::Name; // normalise_hardware_query guarantees valid

    auto name_of = [](const InventoryDeviceRow& r) -> const std::string& {
        return r.hostname.empty() ? r.agent_id : r.hostname;
    };
    auto fold = [](const std::string& s) { return to_lower_ascii(s); };

    std::stable_sort(matched.begin(), matched.end(),
                     [&](const InventoryDeviceRow& a, const InventoryDeviceRow& b) {
        bool lt = false;
        bool gt = false;
        switch (sort_key) {
            case HwSortKey::Name: {
                const std::string an = fold(name_of(a)), bn = fold(name_of(b));
                lt = an < bn; gt = an > bn;
                break;
            }
            case HwSortKey::Os: {
                const std::string ao = fold(os_label(a.os)), bo = fold(os_label(b.os));
                lt = ao < bo; gt = ao > bo;
                break;
            }
            case HwSortKey::Status: {
                const int ar = status_rank(a), br = status_rank(b);
                lt = ar < br; gt = ar > br;
                break;
            }
            case HwSortKey::LastSeen: {
                lt = a.last_seen_ms < b.last_seen_ms; gt = a.last_seen_ms > b.last_seen_ms;
                break;
            }
            case HwSortKey::Manufacturer: {
                const bool ab = is_blank_sentinel(a.ci_manufacturer), bb = is_blank_sentinel(b.ci_manufacturer);
                if (ab != bb) return !ab; // blanks sort last both directions — independent of desc
                const std::string am = fold(a.ci_manufacturer), bm = fold(b.ci_manufacturer);
                lt = am < bm; gt = am > bm;
                break;
            }
            case HwSortKey::Model: {
                const bool ab = is_blank_sentinel(a.ci_model), bb = is_blank_sentinel(b.ci_model);
                if (ab != bb) return !ab; // blanks sort last both directions — independent of desc
                const std::string am = fold(a.ci_model), bm = fold(b.ci_model);
                lt = am < bm; gt = am > bm;
                break;
            }
            case HwSortKey::Serial: {
                const bool ab = is_blank_sentinel(a.ci_serial), bb = is_blank_sentinel(b.ci_serial);
                if (ab != bb) return !ab; // blanks sort last both directions — independent of desc
                const std::string am = fold(a.ci_serial), bm = fold(b.ci_serial);
                lt = am < bm; gt = am > bm;
                break;
            }
            case HwSortKey::Cpu: {
                const bool ab = is_blank_sentinel(a.ci_cpu_model), bb = is_blank_sentinel(b.ci_cpu_model);
                if (ab != bb) return !ab; // blanks sort last both directions — independent of desc
                const std::string am = fold(a.ci_cpu_model), bm = fold(b.ci_cpu_model);
                lt = am < bm; gt = am > bm;
                break;
            }
            case HwSortKey::Ram: {
                const bool ab = is_blank_sentinel(a.ci_ram_bytes), bb = is_blank_sentinel(b.ci_ram_bytes);
                if (ab != bb) return !ab; // blanks sort last both directions — independent of desc
                const std::int64_t av = parse_i64_or_min(a.ci_ram_bytes), bv = parse_i64_or_min(b.ci_ram_bytes);
                lt = av < bv; gt = av > bv;
                break;
            }
            case HwSortKey::OsVersion: {
                const bool ab = is_blank_sentinel(a.ci_os_version), bb = is_blank_sentinel(b.ci_os_version);
                if (ab != bb) return !ab; // blanks sort last both directions — independent of desc
                const std::string am = fold(a.ci_os_version), bm = fold(b.ci_os_version);
                lt = am < bm; gt = am > bm;
                break;
            }
            case HwSortKey::Version: {
                const bool ab = a.agent_version.empty(), bb = b.agent_version.empty();
                if (ab != bb) return !ab; // blanks (offline, no report) sort last — independent of desc
                const auto av = parse_semver3(a.agent_version), bv = parse_semver3(b.agent_version);
                if (av && bv) { lt = *av < *bv; gt = *av > *bv; break; }
                // Unparsable version strings fall back to a lexicographic compare so
                // the column never silently drops a row from the ordering.
                const std::string am = fold(a.agent_version), bm = fold(b.agent_version);
                lt = am < bm; gt = am > bm;
                break;
            }
            case HwSortKey::Ip: {
                const bool ab = a.ips.empty(), bb = b.ips.empty();
                // Unlike the string-valued blank checks above, an empty `ips` makes
                // `.front()` UB below — a both-offline pair (`ab && bb`) is everyday
                // fleet data, not a crafted input (governance Gate 3, CRITICAL: this
                // used to fall through to `.front()` on that pair).
                if (ab != bb) return !ab; // no live claim sorts last — independent of desc
                if (!ab) {
                    // Both non-blank: only case where .front() is safe.
                    const std::string am = fold(a.ips.front()), bm = fold(b.ips.front());
                    lt = am < bm; gt = am > bm;
                }
                // Both blank: lt/gt stay false (initialized above) — falls through to
                // the shared name/agent_id tie-break below instead of a bare tie with
                // unspecified relative order (governance Gate 8 cpp-safety: every
                // other sort key's both-blank case reaches that same tie-break; this
                // one used to short-circuit past it).
                break;
            }
        }
        if (lt != gt)
            return normalised.desc ? gt : lt;
        // Stable tie-break: name asc, then agent_id asc — deterministic across renders
        // regardless of the primary sort direction.
        const std::string an = fold(name_of(a)), bn = fold(name_of(b));
        if (an != bn)
            return an < bn;
        return a.agent_id < b.agent_id;
    });

    const std::size_t total = matched.size();
    std::size_t offset = std::min(normalised.offset, total);
    const std::size_t end = std::min(offset + normalised.limit, total);
    page.rows.assign(std::make_move_iterator(matched.begin() + static_cast<std::ptrdiff_t>(offset)),
                     std::make_move_iterator(matched.begin() + static_cast<std::ptrdiff_t>(end)));

    page.query = normalised;
    page.query.offset = offset;
    return page;
}

nlohmann::json hardware_row_json(const InventoryDeviceRow& row) {
    return nlohmann::json{
        {"agent_id", row.agent_id},
        {"hostname", row.hostname.empty() ? row.agent_id : row.hostname},
        {"os", row.os},
        {"os_label", os_label(row.os)},
        {"online", row.online},
        {"stale", row.stale},
        {"last_seen", row.last_seen},
        {"last_seen_ms", row.last_seen_ms},
        {"ci_present", !is_blank_sentinel(row.ci_serial) || !is_blank_sentinel(row.ci_model)},
        {"serial", ci_json(row.ci_serial)},
        {"model", ci_json(row.ci_model)},
        {"manufacturer", ci_json(row.ci_manufacturer)},
        {"cpu_model", ci_json(row.ci_cpu_model)},
        {"cpu_cores", ci_json_int(row.ci_cpu_cores)},
        {"cpu_threads", ci_json_int(row.ci_cpu_threads)},
        {"ram_bytes", ci_json_int(row.ci_ram_bytes)},
        {"os_name", ci_json(row.ci_os_name)},
        {"os_version", ci_json(row.ci_os_version)},
        {"os_build", ci_json(row.ci_os_build)},
        {"arch", row.arch.empty() ? ci_json(row.ci_arch) : nlohmann::json(row.arch)},
        {"domain", ci_json(row.ci_domain)},
        {"primary_mac", ci_json(row.ci_primary_mac)},
        {"agent_version", row.agent_version.empty() ? nlohmann::json(nullptr) : nlohmann::json(row.agent_version)},
        {"ips", row.ips.empty() ? nlohmann::json(nullptr) : nlohmann::json(row.ips)},
        {"tags", [&] {
             nlohmann::json t = nlohmann::json::array();
             for (const auto& [k, v] : row.tags) t.push_back({{"key", k}, {"value", v}});
             return t;
         }()},
        {"dex_score", row.dex_score < 0 ? nlohmann::json(nullptr) : nlohmann::json(row.dex_score)},
    };
}

nlohmann::json hardware_list_json(const HardwareListPage& page, bool ci_degraded,
                                  std::size_t devices_omitted, bool tags_degraded) {
    nlohmann::json rows = nlohmann::json::array();
    for (const auto& row : page.rows)
        rows.push_back(hardware_row_json(row));
    return nlohmann::json{
        {"devices", std::move(rows)},
        {"count", page.rows.size()},
        {"total_matching", page.total_matching},
        {"devices_omitted", devices_omitted},
        {"ci_degraded", ci_degraded},
        {"tags_degraded", tags_degraded},
        {"kpis",
         {{"total", page.kpis.total},
          {"online", page.kpis.online},
          {"offline", page.kpis.offline},
          {"stale", page.kpis.stale},
          {"with_ci", ci_degraded ? nlohmann::json(nullptr) : nlohmann::json(page.kpis.with_ci)}}},
        {"query",
         {{"q", page.query.q},
          {"os", page.query.os},
          {"status", page.query.status},
          {"sort", page.query.sort},
          {"dir", page.query.desc ? "desc" : "asc"},
          {"limit", page.query.limit},
          {"offset", page.query.offset},
          {"tag", page.query.tag}}},
    };
}

bool agent_supports_sync_now(std::string_view agent_version) noexcept {
    const auto parts = parse_semver3(agent_version);
    return parts && *parts >= kSyncNowMinAgentVersion; // lexicographic on {major, minor, patch}
}

nlohmann::json hardware_ci_json(const HardwareCiDetail& detail, std::int64_t /*now_secs*/) {
    nlohmann::json out;
    if (detail.identity) {
        out["agent_id"] = detail.identity->agent_id;
        out["hostname"] = detail.identity->hostname.empty() ? detail.identity->agent_id
                                                             : detail.identity->hostname;
        out["os"] = detail.identity->os;
        out["online"] = detail.identity->online;
        out["last_seen"] = detail.identity->last_seen;
    } else {
        out["agent_id"] = nullptr;
        out["hostname"] = nullptr;
        out["os"] = nullptr;
        out["online"] = false;
        out["last_seen"] = nullptr;
    }

    if (!detail.ci.has_value()) {
        out["ci"] = nullptr;
        out["ci_state"] = "degraded";
    } else if (!detail.ci->has_value()) {
        out["ci"] = nullptr;
        out["ci_state"] = "absent";
    } else {
        const DeviceCiRecord& ci = **detail.ci;
        out["ci"] = {
            {"manufacturer", ci_json(ci.manufacturer)}, {"model", ci_json(ci.model)},
            {"serial", ci_json(ci.serial)},             {"system_uuid", ci_json(ci.system_uuid)},
            {"domain", ci_json(ci.domain)},             {"ou", ci_json(ci.ou)},
            {"bios_vendor", ci_json(ci.bios_vendor)},   {"bios_version", ci_json(ci.bios_version)},
            {"bios_date", ci_json(ci.bios_date)},       {"cpu_model", ci_json(ci.cpu_model)},
            {"cpu_cores", ci_json_int(ci.cpu_cores)},   {"cpu_threads", ci_json_int(ci.cpu_threads)},
            {"ram_bytes", ci_json_int(ci.ram_bytes)},   {"disks_summary", ci_json(ci.disks_summary)},
            {"primary_mac", ci_json(ci.primary_mac)},   {"macs_summary", ci_json(ci.macs_summary)},
            {"nic_count", ci_json_int(ci.nic_count)},   {"os_name", ci_json(ci.os_name)},
            {"os_version", ci_json(ci.os_version)},     {"os_build", ci_json(ci.os_build)},
            {"arch", ci_json(ci.arch)},                 {"first_seen", ci.first_seen},
            {"last_seen", ci.last_seen},
        };
        out["ci_state"] = "found";
    }

    if (!detail.software) {
        out["software"] = nullptr;
    } else {
        nlohmann::json sw = nlohmann::json::array();
        for (const auto& e : *detail.software)
            sw.push_back({{"name", e.name}, {"version", e.version}, {"publisher", e.publisher},
                          {"install_date", e.install_date}});
        out["software"] = std::move(sw);
    }
    out["software_truncated"] = detail.software_truncated;

    if (!detail.tags) {
        out["tags"] = nullptr;
    } else {
        nlohmann::json tags = nlohmann::json::array();
        for (const auto& t : *detail.tags)
            tags.push_back({{"key", t.key}, {"value", t.value}, {"source", t.source},
                            {"updated_at", t.updated_at}});
        out["tags"] = std::move(tags);
    }
    out["agent_version"] = detail.agent_version ? nlohmann::json(*detail.agent_version) : nullptr;
    out["sync_supported"] = detail.agent_version && agent_supports_sync_now(*detail.agent_version);
    out["software_last_seen"] =
        detail.software_last_seen ? nlohmann::json(*detail.software_last_seen) : nullptr;
    return out;
}

} // namespace yuzu::server
