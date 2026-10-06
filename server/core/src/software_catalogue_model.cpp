#include "software_catalogue_model.hpp"

#include <yuzu/log_token.hpp>

#include <algorithm>
#include <charconv>
#include <climits>
#include <cmath>

namespace yuzu::server::software_catalogue {

namespace sc = software_catalog;

namespace {

constexpr char kSep = '\x1f';

// ── Parameter helpers ────────────────────────────────────────────────────────

// Value of `key`, or nullptr when absent. `strict` (the two new routes) rejects a repeated key;
// otherwise the first value wins (the raw route's legacy behaviour).
const std::string* find_param(const Params& p, const std::string& key, bool strict,
                              std::optional<ParseError>& err) {
    const auto [lo, hi] = p.equal_range(key);
    if (lo == hi)
        return nullptr;
    if (strict && std::next(lo) != hi) {
        err = ParseError{400, "repeated query parameter " + key};
        return nullptr;
    }
    return &lo->second;
}

// Full-consume signed decimal; nullopt on any defect (empty, sign-only, trailing bytes, range).
std::optional<std::int64_t> parse_i64(std::string_view s) {
    std::int64_t v = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || ptr != s.data() + s.size())
        return std::nullopt;
    return v;
}

// Shared by the three parsers: reads `limit` (empty == absent) into [1, max].
std::expected<std::int64_t, ParseError> read_limit(const std::string* v, std::int64_t def,
                                                   std::int64_t max) {
    if (!v || v->empty())
        return def;
    const auto n = parse_i64(*v);
    if (!n)
        return std::unexpected(ParseError{400, "invalid limit (expected integer)"});
    return std::clamp<std::int64_t>(*n, 1, max);
}

// ── base64url (RFC 4648 §5, no padding) ──────────────────────────────────────

constexpr std::string_view kB64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string b64url_encode(std::string_view in) {
    std::string out;
    out.reserve((in.size() * 4 + 2) / 3);
    std::size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        const std::uint32_t n = (static_cast<std::uint8_t>(in[i]) << 16) |
                                (static_cast<std::uint8_t>(in[i + 1]) << 8) |
                                static_cast<std::uint8_t>(in[i + 2]);
        out += kB64[(n >> 18) & 63];
        out += kB64[(n >> 12) & 63];
        out += kB64[(n >> 6) & 63];
        out += kB64[n & 63];
    }
    if (const std::size_t rem = in.size() - i; rem == 1) {
        const std::uint32_t n = static_cast<std::uint8_t>(in[i]) << 16;
        out += kB64[(n >> 18) & 63];
        out += kB64[(n >> 12) & 63];
    } else if (rem == 2) {
        const std::uint32_t n = (static_cast<std::uint8_t>(in[i]) << 16) |
                                (static_cast<std::uint8_t>(in[i + 1]) << 8);
        out += kB64[(n >> 18) & 63];
        out += kB64[(n >> 12) & 63];
        out += kB64[(n >> 6) & 63];
    }
    return out;
}

// Strict: alphabet only (no '=' padding), tail length != 1 mod 4.
std::optional<std::string> b64url_decode(std::string_view in) {
    if (in.size() % 4 == 1)
        return std::nullopt;
    std::string out;
    out.reserve(in.size() * 3 / 4);
    std::uint32_t acc = 0;
    int bits = 0;
    for (const char c : in) {
        const auto pos = kB64.find(c);
        if (pos == std::string_view::npos)
            return std::nullopt;
        acc = (acc << 6) | static_cast<std::uint32_t>(pos);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((acc >> bits) & 0xFF);
        }
    }
    return out;
}

// ── Fingerprints and tokens ──────────────────────────────────────────────────

std::string fnv1a_hex16(std::string_view s) {
    std::uint64_t h = 1469598103934665603ULL;
    for (const char c : s) {
        h ^= static_cast<std::uint8_t>(c);
        h *= 1099511628211ULL;
    }
    static constexpr char hex[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i, h >>= 4)
        out[static_cast<std::size_t>(i)] = hex[h & 0xF];
    return out;
}

bool is_lower_hex16(std::string_view s) {
    return s.size() == 16 && std::ranges::all_of(s, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

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

std::optional<std::int64_t> parse_nonneg(std::string_view s) {
    if (s.empty() || !std::ranges::all_of(s, [](char c) { return c >= '0' && c <= '9'; }))
        return std::nullopt;
    return parse_i64(s);
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

std::expected<CatalogueRequest, ParseError> parse_catalogue_params(const Params& p) {
    std::optional<ParseError> err;
    auto get = [&](const char* k) -> std::string {
        const auto* v = find_param(p, k, true, err);
        return v ? *v : std::string{};
    };
    CatalogueRequest r;
    r.query.q = sc::clamp_utf8(get("q"), sc::kSearchMaxBytes);
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
    if (r.query.source.size() > kSourceMaxBytes || r.query.agent_id.size() > kSourceMaxBytes)
        return std::unexpected(ParseError{400, "parameter too long"});
    if (!versions_min.empty()) {
        const auto n = parse_i64(versions_min);
        if (!n || *n < 0)
            return std::unexpected(ParseError{400, "invalid versions_min (expected integer >= 0)"});
        r.query.versions_min = static_cast<int>(std::min<std::int64_t>(*n, 100000));
    }
    if (!format.empty()) {
        if (format != "json" && format != "csv")
            return std::unexpected(ParseError{400, "invalid format (expected json or csv)"});
        r.format = format;
    }
    if (r.cursor.size() > kCursorMaxBytes)
        return std::unexpected(ParseError{400, "invalid cursor"});
    const bool csv = r.format == "csv";
    const auto lim = read_limit(limit.empty() ? nullptr : &limit,
                                csv ? kExportCap : kCatalogueDefaultLimit,
                                csv ? kExportCap : kCataloguePageMax);
    if (!lim)
        return std::unexpected(lim.error());
    if (csv)
        r.export_cap = *lim;
    r.query.limit = static_cast<int>(*lim);
    return r;
}

std::expected<VersionsRequest, ParseError> parse_versions_params(const Params& p) {
    std::optional<ParseError> err;
    auto get = [&](const char* k) -> std::string {
        const auto* v = find_param(p, k, true, err);
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
        return std::unexpected(ParseError{400, "name is required"});
    if (r.query.source.size() > kSourceMaxBytes || r.query.agent_id.size() > kSourceMaxBytes)
        return std::unexpected(ParseError{400, "parameter too long"});
    const auto lim = read_limit(limit.empty() ? nullptr : &limit, kVersionsDefaultLimit, kVersionsMax);
    if (!lim)
        return std::unexpected(lim.error());
    r.query.limit = static_cast<int>(*lim);
    return r;
}

std::expected<DevicesRequest, ParseError> parse_devices_params(const Params& p) {
    std::optional<ParseError> err; // never set: strict=false
    auto get = [&](const char* k) -> std::string {
        const auto* v = find_param(p, k, false, err);
        return v ? *v : std::string{};
    };
    DevicesRequest r;
    r.query.agent_id = get("agent_id");
    r.query.name = get("name");
    if (const auto* v = find_param(p, "version", false, err))
        r.query.version = *v;
    r.query.q = sc::clamp_utf8(get("q"), sc::kSearchMaxBytes);
    r.query.kind = get("kind");
    r.query.ecosystem = get("ecosystem");
    r.query.source = get("source");
    r.cursor = get("cursor");
    r.format = get("format");
    const std::string limit = get("limit");
    if (!r.format.empty() && r.format != "json" && r.format != "csv")
        return std::unexpected(ParseError{400, "invalid format (expected json or csv)"});
    if (r.cursor.size() > kCursorMaxBytes)
        return std::unexpected(ParseError{400, "invalid cursor"});
    r.export_mode = !r.format.empty();
    const auto lim = read_limit(limit.empty() ? nullptr : &limit,
                                r.export_mode ? kExportCap : 100,
                                r.export_mode ? kExportCap : kDevicesPageMax);
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
    for (const StrKey k : {StrKey{"q", sc::kSearchMaxBytes}, StrKey{"name", 1024},
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

// ── Scope ────────────────────────────────────────────────────────────────────

ScopeApply apply_scope(SoftwareFleetQuery& q, const authz::VisibleSet& scope) {
    if (!scope)
        return ScopeApply::kUnfiltered;
    if (scope->empty()) {
        q.agent_ids = std::vector<std::string>{};
        return ScopeApply::kDenyAll;
    }
    if (scope->size() > kScopePushdownMaxIds)
        return ScopeApply::kPostFilter;
    q.agent_ids = std::vector<std::string>(scope->begin(), scope->end());
    return ScopeApply::kPushedDown;
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
    std::string s;
    for (const std::string* f : {&q.kind, &q.ecosystem, &q.source, &q.q, &q.agent_id}) {
        s += *f;
        s += kSep;
    }
    s += std::to_string(q.versions_min);
    return fnv1a_hex16(s);
}

std::string devices_fingerprint(const SoftwareFleetQuery& q) {
    std::string s = q.agent_id;
    s += kSep;
    s += q.name;
    s += kSep;
    s += q.version ? "1" + *q.version : std::string("0");
    for (const std::string* f : {&q.q, &q.kind, &q.ecosystem, &q.source}) {
        s += kSep;
        s += *f;
    }
    return fnv1a_hex16(s);
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
    if (sep == std::string::npos)
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

std::string encode_devices_cursor(const SoftwareFleetRow& last, std::string_view fp) {
    std::string out = "d1:";
    out += fp;
    out += ':';
    out += b64url_encode(last.entry.name + kSep + last.agent_id + kSep +
                         std::to_string(last.install_id));
    return out;
}

std::expected<SoftwareCursor, CursorError> decode_devices_cursor(std::string_view token,
                                                                 std::string_view fp) {
    const auto parts = split(token, ':');
    if (parts.size() != 3 || parts[0] != "d1" || !is_lower_hex16(parts[1]))
        return std::unexpected(CursorError::kMalformed);
    const auto payload = b64url_decode(parts[2]);
    if (!payload)
        return std::unexpected(CursorError::kMalformed);
    // name 0x1F agent_id 0x1F install_id: peel the two trailing fields from the right, so a
    // name containing the separator still round-trips.
    const auto last = payload->rfind(kSep);
    if (last == std::string::npos || last == 0)
        return std::unexpected(CursorError::kMalformed);
    const auto mid = payload->rfind(kSep, last - 1);
    if (mid == std::string::npos)
        return std::unexpected(CursorError::kMalformed);
    const auto id = parse_nonneg(std::string_view(*payload).substr(last + 1));
    if (!id)
        return std::unexpected(CursorError::kMalformed);
    if (parts[1] != fp)
        return std::unexpected(CursorError::kFilterMismatch);
    return SoftwareCursor{payload->substr(0, mid), payload->substr(mid + 1, last - mid - 1), *id};
}

SkewAction skew_action(bool cursor_present, std::int64_t gen_before, std::int64_t gen_after) {
    if (gen_before == gen_after)
        return SkewAction::kNone;
    return cursor_present ? SkewAction::kStale : SkewAction::kRetry;
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
                                      bool omit_newest) {
    auto versions = nlohmann::json::array();
    for (const auto& v : rows)
        versions.push_back(version_row_json(v, omit_newest));
    nlohmann::json out{
        {"name", std::string(name)},
        {"versions", std::move(versions)},
        {"count", rows.size()},
        {"truncated", truncated},
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

std::optional<std::string> titles_export(const CatalogueReader& read, SoftwareCatalogQuery q,
                                         std::int64_t cap, bool omit_newest, bool& truncated) {
    truncated = false;
    std::vector<SoftwareCatalogRow> all;
    q.after.reset();
    while (static_cast<std::int64_t>(all.size()) < cap) {
        const std::int64_t want =
            std::min<std::int64_t>(cap - static_cast<std::int64_t>(all.size()), kCatalogReadMax);
        q.limit = static_cast<int>(want);
        auto page = read(q);
        if (!page)
            return std::nullopt;
        if (page->empty())
            break;
        const bool full = static_cast<std::int64_t>(page->size()) == want;
        for (auto& r : *page)
            all.push_back(std::move(r));
        if (!full)
            break;
        // A full read that reaches the cap may have left rows behind: report it, as the raw
        // route does whenever rows == the effective limit.
        if (static_cast<std::int64_t>(all.size()) >= cap) {
            truncated = true;
            break;
        }
        q.after = SoftwareCatalogCursor{all.back().device_count, all.back().name};
    }
    return titles_csv(all, omit_newest);
}

PageStatus read_catalogue_page(const CatalogueReads& io, const CatalogueRequest& rq,
                               CataloguePage& out) {
    const auto& q = rq.query;
    const bool host = !q.agent_id.empty();
    const bool continuation = !rq.cursor.empty();
    const std::string fp = filter_fingerprint(q);
    enum class Step { kOk, kDegraded, kBadCursor, kStale, kMoved };
    auto attempt = [&]() -> Step {
        out = {};
        std::int64_t gen = 0;
        if (!host) {
            out.meta = io.meta();
            if (!out.meta)
                return Step::kDegraded;
            gen = out.meta->refreshed_at;
        }
        auto query = q;
        if (continuation) {
            auto cur = decode_catalogue_cursor(rq.cursor, fp, gen);
            if (!cur) {
                out.cursor_error = cur.error();
                return cur.error() == CursorError::kStale ? Step::kStale : Step::kBadCursor;
            }
            query.after = *cur;
        }
        auto rows = io.rows(query);
        if (!rows)
            return Step::kDegraded;
        auto totals = io.totals(query);
        if (!totals)
            return Step::kDegraded;
        out.rows = std::move(*rows);
        out.totals = *totals;
        if (!host) {
            const auto after = io.meta();
            if (!after)
                return Step::kDegraded;
            switch (skew_action(continuation, gen, after->refreshed_at)) {
            case SkewAction::kNone:
                break;
            case SkewAction::kStale:
                out.cursor_error = CursorError::kStale;
                return Step::kStale;
            case SkewAction::kRetry:
                return Step::kMoved;
            }
        }
        if (static_cast<int>(out.rows.size()) == q.limit)
            out.next_cursor = encode_catalogue_cursor(out.rows.back(), fp, gen);
        return Step::kOk;
    };
    Step st = attempt();
    if (st == Step::kMoved)
        st = attempt(); // first page only: one retry over the new snapshot
    switch (st) {
    case Step::kOk:
        return PageStatus::kOk;
    case Step::kBadCursor:
        return PageStatus::kBadCursor;
    case Step::kStale:
        return PageStatus::kStale;
    case Step::kDegraded:
    case Step::kMoved:
        break;
    }
    return PageStatus::kDegraded;
}

PageStatus read_titles_export(const CatalogueReads& io, const CatalogueRequest& rq,
                              bool omit_newest, std::string& csv, bool& truncated) {
    const bool host = !rq.query.agent_id.empty();
    for (int attempt = 0; attempt < 2; ++attempt) {
        std::int64_t gen = 0;
        if (!host) {
            const auto before = io.meta();
            if (!before)
                return PageStatus::kDegraded;
            gen = before->refreshed_at;
        }
        auto body = titles_export(io.rows, rq.query, rq.export_cap, omit_newest, truncated);
        if (!body)
            return PageStatus::kDegraded;
        if (!host) {
            const auto after = io.meta();
            if (!after)
                return PageStatus::kDegraded;
            if (after->refreshed_at != gen)
                continue; // moved under the walk: restart once
        }
        csv = std::move(*body);
        return PageStatus::kOk;
    }
    return PageStatus::kDegraded;
}

} // namespace yuzu::server::software_catalogue
