#include "software_catalogue_model.hpp"

#include "data_export.hpp"
#include "device_api.hpp"
#include "list_keyset.hpp"
#include "model_param_helpers.hpp" // shared param/cursor helpers (one copy, both models)
#include "software_catalog_rules.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/log_token.hpp>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <expected>
#include <format>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <unordered_set>
#include <utility>

namespace yuzu::server::software_catalogue {

namespace sc = software_catalog;

namespace {

// The parameter and cursor-payload helpers are shared with crypto_library_model.cpp.
using model_detail::find_param;
using model_detail::fnv1a_hex16;
using model_detail::is_lower_hex16;
using model_detail::kSep;
using model_detail::length_prefixed;
using model_detail::parse_i64;
using model_detail::parse_nonneg;
using model_detail::read_length_prefixed;
using model_detail::valid_text;

// ── Parameter helpers ────────────────────────────────────────────────────────

// The raw route's legacy rule: a repeated key keeps the FIRST value. lower_bound is the first equal
// element (multimap::find may return any of them).
const std::string* first_param(const Params& p, const std::string& key) {
    const auto it = p.lower_bound(key);
    return it != p.end() && it->first == key ? &it->second : nullptr;
}

using Fields = std::initializer_list<const std::string*>;

// The shared hygiene block of the three parsers: strict UTF-8 / no NUL over every text field, the
// short-field bound, then the name-length bound. nullopt = clean; else the 400 message.
std::optional<std::string> text_error(Fields text, Fields short_fields, Fields long_fields = {}) {
    for (const std::string* f : text)
        if (!valid_text(*f))
            return "invalid parameter encoding";
    for (const std::string* f : short_fields)
        if (f->size() > kSourceMaxBytes)
            return "parameter too long";
    for (const std::string* f : long_fields)
        if (f->size() > kNameMaxBytes)
            return "parameter too long";
    return std::nullopt;
}

// Shared by the two parsers: reads `limit` (empty == absent) into [1, max].
std::expected<std::int64_t, std::string> read_limit(const std::string& v, std::int64_t def,
                                                    std::int64_t max) {
    if (v.empty())
        return def;
    const auto n = parse_i64(v);
    if (!n)
        return std::unexpected("invalid limit (expected integer)");
    return std::clamp<std::int64_t>(*n, 1, max);
}

// ── base64url (RFC 4648 §5, no padding) ──────────────────────────────────────

// The strict codec is shared with every other cursor in the server (list_keyset.hpp).
using ::yuzu::server::keyset::b64url_decode;
using ::yuzu::server::keyset::b64url_encode;

// ── Fingerprints and tokens ──────────────────────────────────────────────────

std::vector<std::string_view> split(std::string_view s, char d) {
    std::vector<std::string_view> out;
    std::size_t start = 0;
    for (;;) {
        const auto pos = s.find(d, start);
        if (pos == std::string_view::npos) {
            out.push_back(s.substr(start));
            return out;
        }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
}

// ── JSON/CSV helpers ─────────────────────────────────────────────────────────

nlohmann::json split_list(const std::string& csv) {
    auto arr = nlohmann::json::array();
    if (csv.empty())
        return arr;
    for (const auto part : split(csv, ','))
        arr.push_back(std::string(part));
    return arr;
}

std::string join_semicolon(const std::string& csv) {
    std::string out = csv;
    std::ranges::replace(out, ',', ';');
    return out;
}

void append_row(std::string& out, std::initializer_list<std::string> cells) {
    bool first = true;
    for (const auto& c : cells) {
        if (!first)
            out += ',';
        first = false;
        out += data_export::csv_escape(c);
    }
    out += '\n';
}

int pct_of(std::int64_t part, std::int64_t whole) {
    return whole > 0 ? static_cast<int>(std::lround(100.0 * static_cast<double>(part) /
                                                     static_cast<double>(whole)))
                     : 0;
}

void tail(std::string& out, std::string_view key, const std::string& v) {
    if (!v.empty()) {
        out += ';';
        out += key;
        out += '=';
        out += ::yuzu::log_token(v);
    }
}

} // namespace

// ── Parsers ──────────────────────────────────────────────────────────────────

std::expected<CatalogueRequest, std::string> parse_catalogue_params(const Params& p) {
    std::optional<std::string> err;
    auto get = [&](const char* k) -> std::string {
        const auto* v = find_param(p, k, err);
        return v ? *v : std::string{};
    };
    CatalogueRequest r;
    std::string q = get("q");
    r.query.kind = get("kind");
    r.query.ecosystem = get("ecosystem");
    r.query.source = get("source");
    r.query.agent_id = get("agent_id");
    r.cursor = get("cursor");
    const std::string versions_min = get("versions_min");
    const std::string limit = get("limit");
    const std::string format = get("format");
    if (err)
        return std::unexpected(*err);
    if (const auto bad = text_error({&q, &r.query.kind, &r.query.ecosystem, &r.query.source,
                                     &r.query.agent_id, &r.cursor},
                                    {&r.query.kind, &r.query.ecosystem, &r.query.source,
                                     &r.query.agent_id}))
        return std::unexpected(*bad);
    // Clamp only validated text: clamp_utf8 over a run of stray continuation bytes returns "".
    r.query.q = sc::clamp_utf8(q, sc::kSearchMaxBytes);
    if (!versions_min.empty()) {
        const auto n = parse_i64(versions_min);
        if (!n || *n < 0)
            return std::unexpected("invalid versions_min (expected integer >= 0)");
        r.query.versions_min = static_cast<int>(std::min<std::int64_t>(*n, 100000));
    }
    if (!format.empty()) {
        if (format != "json" && format != "csv")
            return std::unexpected("invalid format (expected json or csv)");
        r.format = format;
    }
    if (r.cursor.size() > kCursorMaxBytes)
        return std::unexpected("invalid cursor");
    const bool csv = r.format == "csv";
    // An export is one whole walk: a continuation token has no meaning there, never a silent drop.
    if (csv && !r.cursor.empty())
        return std::unexpected("cursor is not accepted with format=csv");
    // For csv the limit is the TOTAL export cap (default and ceiling kExportCap).
    const auto lim = read_limit(limit, csv ? kExportCap : kCatalogueDefaultLimit,
                                csv ? kExportCap : kCataloguePageMax);
    if (!lim)
        return std::unexpected(lim.error());
    r.query.limit = static_cast<int>(*lim);
    return r;
}

std::expected<VersionsRequest, std::string> parse_versions_params(const Params& p) {
    std::optional<std::string> err;
    auto get = [&](const char* k) -> std::string {
        const auto* v = find_param(p, k, err);
        return v ? *v : std::string{};
    };
    VersionsRequest r;
    r.query.name = get("name");
    r.query.kind = get("kind");
    r.query.ecosystem = get("ecosystem");
    r.query.source = get("source");
    r.query.agent_id = get("agent_id");
    const std::string limit = get("limit");
    if (err)
        return std::unexpected(*err);
    if (r.query.name.empty())
        return std::unexpected("name is required");
    if (const auto bad = text_error({&r.query.name, &r.query.kind, &r.query.ecosystem,
                                     &r.query.source, &r.query.agent_id},
                                    {&r.query.kind, &r.query.ecosystem, &r.query.source,
                                     &r.query.agent_id},
                                    {&r.query.name}))
        return std::unexpected(*bad);
    const auto lim = read_limit(limit, kVersionsDefaultLimit, kVersionsMax);
    if (!lim)
        return std::unexpected(lim.error());
    r.query.limit = static_cast<int>(*lim);
    return r;
}

std::expected<DevicesRequest, std::string> parse_devices_params(const Params& p) {
    auto get = [&](const char* k) -> std::string {
        const auto* v = first_param(p, k);
        return v ? *v : std::string{};
    };
    DevicesRequest r;
    r.query.agent_id = get("agent_id");
    r.query.name = get("name");
    if (const auto* v = first_param(p, "version"))
        r.query.version = *v;
    std::string q = get("q");
    r.query.kind = get("kind");
    r.query.ecosystem = get("ecosystem");
    r.query.source = get("source");
    r.cursor = get("cursor");
    r.format = get("format");
    const std::string limit = get("limit");
    const std::string no_version; // an absent version passes every check below trivially
    const std::string* const version = r.query.version ? &*r.query.version : &no_version;
    if (const auto bad = text_error({&r.query.agent_id, &r.query.name, &q, &r.query.kind,
                                     &r.query.ecosystem, &r.query.source, &r.cursor, version},
                                    {&r.query.agent_id, &r.query.kind, &r.query.ecosystem,
                                     &r.query.source},
                                    {&r.query.name, version}))
        return std::unexpected(*bad);
    // Clamp only validated text: clamp_utf8 over a run of stray continuation bytes returns "".
    r.query.q = sc::clamp_utf8(q, sc::kSearchMaxBytes);
    if (!r.format.empty() && r.format != "json" && r.format != "csv")
        return std::unexpected("invalid format (expected json or csv)");
    if (r.cursor.size() > kCursorMaxBytes)
        return std::unexpected("invalid cursor");
    const bool export_mode = !r.format.empty();
    const auto lim = read_limit(limit, export_mode ? kExportCap : kCatalogueDefaultLimit,
                                export_mode ? kExportCap : kCataloguePageMax);
    if (!lim)
        return std::unexpected(lim.error());
    r.query.limit = static_cast<int>(*lim);
    return r;
}

std::optional<std::string> strict_args_error(const nlohmann::json& args) {
    constexpr std::string_view kKinds[] = {"package", "app", "pkg", "feat"};
    if (!args.is_object())
        return std::nullopt;
    struct StrKey {
        const char* key;
        std::size_t max;
    };
    for (const StrKey k : {StrKey{"q", sc::kSearchMaxBytes}, StrKey{"name", kNameMaxBytes},
                           StrKey{"source", kSourceMaxBytes}, StrKey{"agent_id", kSourceMaxBytes},
                           StrKey{"cursor", kCursorMaxBytes}, StrKey{"kind", 16},
                           StrKey{"ecosystem", 32}}) {
        if (!args.contains(k.key))
            continue;
        if (!args[k.key].is_string())
            return std::string(k.key) + " must be a JSON string";
        if (args[k.key].get_ref<const std::string&>().size() > k.max)
            return std::string(k.key) + " is too long";
    }
    if (args.contains("kind") &&
        std::ranges::find(kKinds, args["kind"].get<std::string>()) == std::end(kKinds))
        return "kind is not one of the published kinds";
    if (args.contains("ecosystem") &&
        std::ranges::none_of(sc::kEcosystemFamilies, [&](const auto& e) {
            return e.ecosystem == args["ecosystem"].get<std::string>();
        }))
        return "ecosystem is not one of the published ecosystems";
    struct IntKey {
        const char* key;
        std::int64_t min, max;
    };
    static_assert(kCataloguePageMax == kVersionsMax,
                  "one `limit` bound serves both MCP tools below");
    for (const IntKey k : {IntKey{"limit", 1, kCataloguePageMax}, IntKey{"versions_min", 0, 100000}}) {
        if (!args.contains(k.key))
            continue;
        if (!args[k.key].is_number_integer())
            return std::string(k.key) + " must be a JSON integer";
        const auto v = args[k.key].get<std::int64_t>();
        if (v < k.min || v > k.max)
            return std::string(k.key) + " must be between " + std::to_string(k.min) + " and " +
                   std::to_string(k.max);
    }
    return std::nullopt;
}

std::optional<std::string> installed_software_args_error(const nlohmann::json& args) {
    if (!args.is_object())
        return std::nullopt;
    for (const char* key : {"agent_id", "name", "version", "cursor"})
        if (args.contains(key) && !args[key].is_string())
            return std::string(key) + " must be a JSON string";
    if (args.contains("limit")) {
        const auto& l = args["limit"];
        // nlohmann stores every non-negative integer as unsigned: above INT64_MAX the later
        // get<int64_t>() would wrap, so it is refused here rather than clamped.
        if (!l.is_number_integer() ||
            (l.is_number_unsigned() &&
             l.get<std::uint64_t>() > static_cast<std::uint64_t>(INT64_MAX)))
            return "limit must be a JSON integer";
    }
    return std::nullopt;
}

// ── Audit targets ────────────────────────────────────────────────────────────

std::string audit_target(const SoftwareCatalogQuery& q) {
    std::string out = q.agent_id.empty() ? std::string("fleet")
                                         : "agent=" + ::yuzu::log_token(q.agent_id);
    tail(out, "kind", q.kind);
    tail(out, "ecosystem", q.ecosystem);
    tail(out, "source", q.source);
    tail(out, "q", q.q);
    if (q.versions_min > 0)
        out += ";versions_min=" + std::to_string(q.versions_min);
    return out;
}

std::string audit_target(const SoftwareVersionsQuery& q) {
    std::string out = "name=" + ::yuzu::log_token(q.name);
    tail(out, "agent", q.agent_id);
    tail(out, "kind", q.kind);
    tail(out, "ecosystem", q.ecosystem);
    tail(out, "source", q.source);
    return out;
}

std::string audit_target(const SoftwareFleetQuery& q) {
    std::string out = !q.name.empty()       ? "name=" + ::yuzu::log_token(q.name)
                      : !q.agent_id.empty() ? "agent=" + ::yuzu::log_token(q.agent_id)
                                            : std::string("fleet");
    if (!q.name.empty())
        tail(out, "agent", q.agent_id); // a name query narrowed to one device names both
    if (q.version)
        out += ";version=" + ::yuzu::log_token(*q.version);
    tail(out, "q", q.q);
    tail(out, "kind", q.kind);
    tail(out, "ecosystem", q.ecosystem);
    tail(out, "source", q.source);
    return out;
}

// ── Cursors ──────────────────────────────────────────────────────────────────

std::string_view cursor_error_message(CursorError e) {
    switch (e) {
    case CursorError::kMalformed:
        return "invalid cursor";
    case CursorError::kFilterMismatch:
        return "cursor was issued for a different filter set";
    case CursorError::kStale:
        break;
    }
    return "cursor predates the current catalogue refresh; restart from the first page";
}

std::string filter_fingerprint(const SoftwareCatalogQuery& q) {
    return fnv1a_hex16(length_prefixed({&q.kind, &q.ecosystem, &q.source, &q.q, &q.agent_id}) +
                       std::to_string(q.versions_min));
}

std::string devices_fingerprint(const SoftwareFleetQuery& q) {
    static const std::string kNoVersion;
    // A present-empty version (the exact empty-version bucket) is not an absent one.
    return fnv1a_hex16(
        std::string(1, q.version ? '1' : '0') +
        length_prefixed({&q.agent_id, &q.name, q.version ? &*q.version : &kNoVersion, &q.q, &q.kind,
                         &q.ecosystem, &q.source}));
}

std::string encode_catalogue_cursor(const SoftwareCatalogRow& last, std::string_view fp,
                                    std::int64_t refreshed_at) {
    std::string out = "c1:";
    out += fp;
    out += ':';
    out += std::to_string(refreshed_at);
    out += ':';
    out += b64url_encode(std::to_string(last.device_count) + kSep + last.name);
    return out;
}

std::expected<SoftwareCatalogCursor, CursorError>
decode_catalogue_cursor(std::string_view token, std::string_view fp, std::int64_t refreshed_at) {
    const auto parts = split(token, ':');
    if (parts.size() != 4 || parts[0] != "c1" || !is_lower_hex16(parts[1]))
        return std::unexpected(CursorError::kMalformed);
    const auto gen = parse_nonneg(parts[2]);
    const auto payload = b64url_decode(parts[3]);
    if (!gen || !payload)
        return std::unexpected(CursorError::kMalformed);
    // installs, then the name verbatim (the name may itself contain the separator).
    const auto sep = payload->find(kSep);
    if (sep == std::string::npos || !valid_text(std::string_view(*payload).substr(sep + 1)))
        return std::unexpected(CursorError::kMalformed);
    const auto installs = parse_nonneg(std::string_view(*payload).substr(0, sep));
    if (!installs)
        return std::unexpected(CursorError::kMalformed);
    if (parts[1] != fp)
        return std::unexpected(CursorError::kFilterMismatch);
    if (*gen != refreshed_at)
        return std::unexpected(CursorError::kStale);
    return SoftwareCatalogCursor{*installs, payload->substr(sep + 1)};
}

std::string encode_devices_cursor(const DevicesCursor& at, std::string_view fp) {
    const std::string id = std::to_string(at.after.install_id);
    const std::string skip = std::to_string(at.skip);
    std::string out = "d2:";
    out += fp;
    out += ':';
    out += b64url_encode(length_prefixed({&at.after.name, &at.after.agent_id, &id, &skip}));
    return out;
}

std::expected<DevicesCursor, CursorError> decode_devices_cursor(std::string_view token,
                                                                std::string_view fp) {
    const auto parts = split(token, ':');
    if (parts.size() != 3 || parts[0] != "d2" || !is_lower_hex16(parts[1]))
        return std::unexpected(CursorError::kMalformed);
    const auto payload = b64url_decode(parts[2]);
    if (!payload)
        return std::unexpected(CursorError::kMalformed);
    const auto fields = read_length_prefixed(*payload, 4);
    if (!fields)
        return std::unexpected(CursorError::kMalformed);
    const auto id = parse_nonneg((*fields)[2]);
    const auto skip = parse_nonneg((*fields)[3]);
    // The decoded text is bound as SQL parameters: strict UTF-8 and no NUL, like the parsers.
    if (!id || !skip || !valid_text((*fields)[0]) || !valid_text((*fields)[1]))
        return std::unexpected(CursorError::kMalformed);
    if (parts[1] != fp)
        return std::unexpected(CursorError::kFilterMismatch);
    return DevicesCursor{SoftwareCursor{std::string((*fields)[0]), std::string((*fields)[1]), *id},
                         *skip};
}

// ── KPIs ─────────────────────────────────────────────────────────────────────

KpiFigures derive_kpis(const CatalogRollupMeta& meta, const Coverage& coverage) {
    KpiFigures k;
    k.meta = meta;
    k.coverage = coverage;
    k.building = meta.refreshed_at == 0;
    k.windows_pct = pct_of(meta.installs_windows, meta.total_installs);
    k.macos_pct = pct_of(meta.installs_macos, meta.total_installs);
    k.linux_pct = pct_of(meta.installs_linux, meta.total_installs);
    k.other_pct = pct_of(meta.installs_other, meta.total_installs);
    if (meta.current_total > 0)
        k.stay_current_pct = pct_of(meta.current_installs, meta.current_total);
    if (meta.total_titles > 0)
        k.sprawl_pct = std::round(1000.0 * static_cast<double>(meta.sprawl_titles) /
                                  static_cast<double>(meta.total_titles)) /
                       10.0;
    if (meta.total_devices > 0)
        k.avg_installs_per_device = static_cast<std::int64_t>(std::llround(
            static_cast<double>(meta.total_installs) / static_cast<double>(meta.total_devices)));
    return k;
}

nlohmann::json kpis_json(const KpiFigures& k) {
    using nlohmann::json;
    const auto& m = k.meta;
    auto opt = [](const std::optional<std::int64_t>& v) { return v ? json(*v) : json(nullptr); };
    return json{
        {"titles", m.total_titles},
        {"publishers", m.total_publishers},
        {"installs", m.total_installs},
        {"installs_by_os",
         {{"windows", m.installs_windows},
          {"macos", m.installs_macos},
          {"linux", m.installs_linux},
          {"other", m.installs_other}}},
        {"os_pct",
         {{"windows", k.windows_pct},
          {"macos", k.macos_pct},
          {"linux", k.linux_pct},
          {"other", k.other_pct}}},
        {"stay_current",
         {{"current_installs", m.current_installs},
          {"total_installs", m.current_total},
          {"titles", m.current_titles},
          {"pct", k.stay_current_pct ? json(*k.stay_current_pct) : json(nullptr)}}},
        {"sprawl", {{"titles", m.sprawl_titles}, {"pct", k.sprawl_pct}}},
        {"rpm", {{"total", m.rpm_total}, {"unsigned", m.rpm_unsigned}}},
        {"coverage",
         {{"reporting", m.total_devices},
          {"connected", opt(k.coverage.connected)},
          {"stale", opt(k.coverage.stale)}}},
        {"avg_installs_per_device", k.avg_installs_per_device},
        {"refreshed_at", m.refreshed_at},
        {"building", k.building},
    };
}

// ── JSON ─────────────────────────────────────────────────────────────────────

nlohmann::json catalogue_row_json(const SoftwareCatalogRow& r, bool omit_newest) {
    return nlohmann::json{
        {"name", r.name},
        {"publisher", r.publisher},
        {"installs", r.device_count},
        {"versions", r.version_count},
        {"ecosystems", split_list(r.ecosystems)},
        {"kinds", split_list(r.kinds)},
        {"newest_version", omit_newest ? std::string() : r.newest_version},
    };
}

nlohmann::json catalogue_response_json(const std::vector<SoftwareCatalogRow>& rows,
                                       const SoftwareCatalogTotals& totals,
                                       const std::optional<KpiFigures>& kpis,
                                       std::string_view next_cursor, bool omit_newest,
                                       std::int64_t devices_omitted) {
    auto titles = nlohmann::json::array();
    for (const auto& r : rows)
        titles.push_back(catalogue_row_json(r, omit_newest));
    nlohmann::json out{
        {"titles", std::move(titles)},
        {"count", rows.size()},
        {"next_cursor", next_cursor.empty() ? nlohmann::json(nullptr)
                                            : nlohmann::json(std::string(next_cursor))},
        {"totals", {{"titles", totals.titles}, {"installs", totals.installs}}},
        {"kpis", kpis ? kpis_json(*kpis) : nlohmann::json(nullptr)},
        {"devices_omitted", devices_omitted},
    };
    if (omit_newest)
        out["newest_omitted"] = true;
    return out;
}

nlohmann::json version_row_json(const SoftwareVersionCount& v, bool omit_newest) {
    return nlohmann::json{
        {"version", v.version},
        {"installs", v.device_count},
        {"newest", omit_newest ? false : v.newest},
    };
}

nlohmann::json versions_response_json(std::string_view name,
                                      const std::vector<SoftwareVersionCount>& rows, bool truncated,
                                      bool omit_newest, std::int64_t devices_omitted) {
    auto versions = nlohmann::json::array();
    for (const auto& v : rows)
        versions.push_back(version_row_json(v, omit_newest));
    nlohmann::json out{
        {"name", std::string(name)},
        {"versions", std::move(versions)},
        {"count", rows.size()},
        {"truncated", truncated},
        {"devices_omitted", devices_omitted},
    };
    if (omit_newest)
        out["newest_omitted"] = true;
    return out;
}

nlohmann::json device_row_json(const SoftwareFleetRow& r) {
    const auto& e = r.entry;
    return nlohmann::json{
        {"agent_id", r.agent_id},
        {"name", e.name},
        {"version", e.version},
        {"publisher", e.publisher},
        {"install_date", e.install_date},
        {"kind", e.kind},
        {"ecosystem", e.ecosystem},
        {"epoch", e.epoch},
        {"release", e.release},
        {"arch", e.arch},
        {"signature_status", e.signature_status},
        {"distro_id", e.distro_id},
        {"distro_version", e.distro_version},
        {"source", e.source},
    };
}

nlohmann::json devices_response_json(const std::vector<SoftwareFleetRow>& rows,
                                     std::string_view next_cursor, std::int64_t devices_omitted,
                                     bool truncated_by_cap) {
    auto arr = nlohmann::json::array();
    for (const auto& r : rows)
        arr.push_back(device_row_json(r));
    nlohmann::json out{
        {"software", std::move(arr)},
        {"count", rows.size()},
        {"next_cursor", next_cursor.empty() ? nlohmann::json(nullptr)
                                            : nlohmann::json(std::string(next_cursor))},
        {"devices_omitted", devices_omitted},
    };
    if (truncated_by_cap)
        out["result_truncated_by_cap"] = true;
    return out;
}

std::string dump_safe(const nlohmann::json& j) {
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

// ── CSV ──────────────────────────────────────────────────────────────────────

std::string installs_csv(const std::vector<SoftwareFleetRow>& rows) {
    std::string out(kInstallsCsvHeader);
    out += '\n';
    for (const auto& r : rows) {
        const auto& e = r.entry;
        append_row(out, {r.agent_id, e.name, e.version, e.publisher, e.install_date, e.kind,
                         e.ecosystem, e.epoch, e.release, e.arch, e.signature_status, e.distro_id,
                         e.distro_version, e.source});
    }
    return out;
}

std::string titles_csv(const std::vector<SoftwareCatalogRow>& rows, bool omit_newest) {
    std::string out(kTitlesCsvHeader);
    out += '\n';
    for (const auto& r : rows)
        append_row(out, {r.name, r.publisher, std::to_string(r.device_count),
                         std::to_string(r.version_count), join_semicolon(r.ecosystems),
                         join_semicolon(r.kinds), omit_newest ? std::string() : r.newest_version});
    return out;
}

std::optional<TitlesExport> titles_export(const CatalogueReader& read, SoftwareCatalogQuery q,
                                          std::int64_t cap, bool omit_newest) {
    TitlesExport out;
    std::vector<SoftwareCatalogRow> all;
    q.after.reset();
    while (static_cast<std::int64_t>(all.size()) < cap) {
        const std::int64_t want =
            std::min<std::int64_t>(cap - static_cast<std::int64_t>(all.size()), kCatalogRowCap);
        q.limit = static_cast<int>(want);
        auto page = read(q);
        if (!page)
            return std::nullopt;
        const bool full = static_cast<std::int64_t>(page->size()) == want;
        for (auto& r : *page)
            all.push_back(std::move(r));
        if (!full)
            break;
        // A full read that reaches the cap may have left rows behind: report it, as the raw
        // route does whenever rows == the effective limit.
        if (static_cast<std::int64_t>(all.size()) >= cap) {
            out.truncated = true;
            break;
        }
        q.after = SoftwareCatalogCursor{all.back().device_count, all.back().name};
    }
    out.rows = static_cast<std::int64_t>(all.size());
    out.csv = titles_csv(all, omit_newest);
    return out;
}

std::expected<CataloguePage, std::optional<CursorError>>
read_catalogue_page(const CatalogueReads& io, const CatalogueRequest& rq, std::int64_t now_epoch) {
    const auto& q = rq.query;
    const bool host = !q.agent_id.empty();
    const bool continuation = !rq.cursor.empty();
    const std::string fp = filter_fingerprint(q);
    bool moved = false; // generation moved under a first page: re-read once
    auto attempt = [&]() -> std::expected<CataloguePage, std::optional<CursorError>> {
        CataloguePage out;
        std::int64_t gen = 0;
        if (!host) {
            out.meta = io.meta();
            if (!out.meta)
                return std::unexpected(std::nullopt);
            gen = out.meta->refreshed_at;
        }
        auto query = q;
        if (continuation) {
            auto cur = decode_catalogue_cursor(rq.cursor, fp, gen);
            if (!cur)
                return std::unexpected(cur.error());
            query.after = *cur;
        }
        auto rows = io.rows(query);
        if (!rows)
            return std::unexpected(std::nullopt);
        auto totals = io.totals(query);
        if (!totals)
            return std::unexpected(std::nullopt);
        out.rows = std::move(*rows);
        out.totals = *totals;
        if (!host) {
            const auto after = io.meta();
            if (!after)
                return std::unexpected(std::nullopt);
            if (after->refreshed_at != gen) {
                // A continuation never re-pages an old keyset over a new snapshot.
                if (continuation)
                    return std::unexpected(CursorError::kStale);
                moved = true;
                return std::unexpected(std::nullopt); // a second move: 503
            }
        }
        if (!out.rows.empty() && static_cast<int>(out.rows.size()) == q.limit)
            out.next_cursor = encode_catalogue_cursor(out.rows.back(), fp, gen);
        return out;
    };
    auto page = attempt();
    if (moved) {
        moved = false;
        page = attempt();
    }
    // Coverage + KPIs once, for the page actually returned (a first fleet page only): a re-read
    // above must not repeat the device-registry walk or the bounded stale count.
    if (page && page->meta && !continuation) {
        Coverage coverage;
        if (io.connected)
            coverage.connected = io.connected();
        coverage.stale = io.stale(now_epoch - kStaleWindowSecs);
        page->kpis = derive_kpis(*page->meta, coverage);
    }
    return page;
}

CatalogueReads catalogue_reads(SoftwareInventoryStore& store, const DeviceApi* device_api) {
    CatalogueReads io{[&store] { return store.catalog_rollup_meta(); },
                      [&store](const SoftwareCatalogQuery& c) { return store.software_catalog(c); },
                      [&store](const SoftwareCatalogQuery& c) {
                          return store.software_catalog_totals(c);
                      },
                      [&store](std::int64_t cutoff) { return store.count_stale_agents(cutoff); }};
    if (device_api)
        io.connected = [device_api] {
            return static_cast<std::int64_t>(device_api->list_devices().size());
        };
    return io;
}

VersionsReads versions_reads(SoftwareInventoryStore& store) {
    return {[&store] { return store.catalog_rollup_meta(); },
            [&store](const SoftwareVersionsQuery& v) { return store.software_versions(v); }};
}

DevicesReader devices_reader(SoftwareInventoryStore& store) {
    return [&store](const SoftwareFleetQuery& q) { return store.query_software(q); };
}

std::optional<TitlesExport> read_titles_export(const CatalogueReads& io,
                                               const CatalogueRequest& rq, bool omit_newest) {
    const bool host = !rq.query.agent_id.empty();
    for (int attempt = 0; attempt < 2; ++attempt) {
        std::int64_t gen = 0;
        if (!host) {
            const auto before = io.meta();
            if (!before)
                break;
            gen = before->refreshed_at;
            // Never computed: an empty file would read as "no titles". Say so, read nothing.
            if (gen == 0)
                return TitlesExport{.building = true};
        }
        auto body = titles_export(io.rows, rq.query, rq.query.limit, omit_newest);
        if (!body)
            break;
        if (!host) {
            const auto after = io.meta();
            if (!after)
                break;
            if (after->refreshed_at != gen)
                continue; // moved under the walk: restart once
        }
        return std::move(*body);
    }
    return std::nullopt;
}

std::expected<std::vector<SoftwareVersionCount>, VersionsError>
read_versions(const VersionsReads& io, const SoftwareVersionsQuery& q) {
    // Only the unfiltered fleet drill reads the precomputed version rollup.
    if (q.agent_id.empty() && q.kind.empty() && q.ecosystem.empty() && q.source.empty()) {
        const auto meta = io.meta();
        if (!meta)
            return std::unexpected(VersionsError::kDegraded);
        if (meta->refreshed_at == 0)
            return std::unexpected(VersionsError::kBuilding);
    }
    auto rows = io.versions(q);
    if (!rows)
        return std::unexpected(VersionsError::kDegraded);
    return std::move(*rows);
}

std::string denied_detail(const DevicesPage& page) {
    if (page.devices_omitted > 0)
        return "scope: filtered " + std::to_string(page.devices_omitted) +
               " out-of-scope device(s) (management-group and/or service-tag axis)";
    return page.target_denied ? "scope: agent_id outside the caller's scope" : std::string{};
}

std::expected<DevicesPage, std::optional<CursorError>>
read_devices_page(const DevicesReader& read, const DevicesRequest& rq,
                  const authz::VisibleSet& scope) {
    auto q = rq.query;
    // The cursor is bound to the filter set (never to the scope: the scope only narrows what the
    // same keyset position yields).
    const std::string fp = devices_fingerprint(q);
    DevicesCursor incoming; // the head: nothing served yet
    if (!rq.cursor.empty()) {
        auto cur = decode_devices_cursor(rq.cursor, fp);
        if (!cur)
            return std::unexpected(cur.error());
        incoming = std::move(*cur);
    }
    const auto key_of = [](const SoftwareFleetRow& r) {
        return SoftwareCursor{r.entry.name, r.agent_id, r.install_id};
    };
    // The head anchor is "from the start", whatever install_id the store hands out.
    const auto& a = incoming.after;
    if (!(a.name.empty() && a.agent_id.empty() && a.install_id == 0))
        q.after = a;
    DevicesPage out;
    out.target_denied = !q.agent_id.empty() && !authz::in_scope(scope, q.agent_id);
    // TOP leaves the query alone; engaged-empty is agent_ids = {} (the store returns empty without
    // SQL); a bounded set is pushed into SQL; a wider one is post-filtered below.
    const bool filter = scope && scope->size() > kScopePushdownMaxIds;
    if (scope && !filter)
        q.agent_ids.emplace(scope->begin(), scope->end());
    if (!filter) {
        // Every returned row is in scope, so the last one is a safe cursor. A skip is only ever
        // minted by the wide path below; it has no meaning here and is ignored.
        auto rows = read(q);
        if (!rows)
            return std::unexpected(std::nullopt);
        out.hit_cap = !rows->empty() && rows->size() == static_cast<std::size_t>(q.limit);
        if (out.hit_cap)
            out.next_cursor = encode_devices_cursor({key_of(rows->back()), 0}, fp);
        out.rows = std::move(*rows);
        return out;
    }

    // Wide scope: post-filter, refilling the page with at most kWideScopeMaxReads bounded reads.
    // The cursor must never carry a dropped row's key, so it is the last IN-SCOPE row served
    // (the incoming anchor if there is none) plus the number of rows scanned after it, which the
    // next request passes over in SQL. Each refill read continues after the last row SCANNED,
    // kept in-process only.
    const auto limit = static_cast<std::size_t>(q.limit);
    q.skip = incoming.skip;
    std::int64_t since_anchor = incoming.skip;
    std::unordered_set<std::string> dropped;
    bool more = false;
    out.rows.reserve(limit);
    for (int reads = 1;; ++reads) {
        auto rows = read(q);
        if (!rows)
            return std::unexpected(std::nullopt);
        const bool full = !rows->empty() && rows->size() == limit;
        SoftwareCursor last_scanned;
        if (full && reads < kWideScopeMaxReads)
            last_scanned = key_of(rows->back());
        std::size_t i = 0;
        for (; i < rows->size() && out.rows.size() < limit; ++i) {
            auto& r = (*rows)[i];
            if (authz::in_scope(scope, r.agent_id)) {
                out.rows.push_back(std::move(r));
                since_anchor = 0;
            } else {
                dropped.insert(r.agent_id); // each DISTINCT device counts once
                ++since_anchor;
            }
        }
        if (out.rows.size() >= limit) { // page filled: rows may remain here or beyond
            more = i < rows->size() || full;
            break;
        }
        if (!full) // a short read is the end of the data
            break;
        if (reads >= kWideScopeMaxReads) { // bound reached: say there may be more
            more = true;
            break;
        }
        q.after = std::move(last_scanned);
        q.skip = 0;
    }
    out.devices_omitted = static_cast<std::int64_t>(dropped.size());
    out.hit_cap = more;
    if (more)
        out.next_cursor = encode_devices_cursor(
            {out.rows.empty() ? incoming.after : key_of(out.rows.back()), since_anchor}, fp);
    return out;
}

} // namespace yuzu::server::software_catalogue
