#include "software_catalogue_model.hpp"

#include <yuzu/log_token.hpp>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <format>

namespace yuzu::server::software_catalogue {

namespace sc = software_catalog;

namespace {

constexpr char kSep = '\x1f';

// ── Parameter helpers ────────────────────────────────────────────────────────

// Value of `key`, or nullptr when absent. A repeated key sets `err` (and yields nullptr).
const std::string* find_param(const Params& p, const std::string& key,
                              std::optional<std::string>& err) {
    const auto [lo, hi] = p.equal_range(key);
    if (lo == hi)
        return nullptr;
    if (std::next(lo) != hi) {
        err = "repeated query parameter " + key;
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

constexpr std::string_view kB64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string b64url_encode(std::string_view in) {
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    std::size_t i = 0;
    for (; i + 3 <= in.size(); i += 3) {
        const std::uint32_t v = static_cast<std::uint8_t>(in[i]) << 16 |
                                static_cast<std::uint8_t>(in[i + 1]) << 8 |
                                static_cast<std::uint8_t>(in[i + 2]);
        for (const int shift : {18, 12, 6, 0})
            out += kB64[(v >> shift) & 63];
    }
    if (const auto rest = in.size() - i; rest > 0) {
        std::uint32_t v = static_cast<std::uint8_t>(in[i]) << 16;
        if (rest == 2)
            v |= static_cast<std::uint8_t>(in[i + 1]) << 8;
        for (std::size_t k = 0; k <= rest; ++k)
            out += kB64[(v >> (18 - 6 * k)) & 63];
    }
    return out;
}

// Strict: alphabet only (no '=' padding, no skipped bytes), tail length != 1 mod 4.
std::optional<std::string> b64url_decode(std::string_view in) {
    if (in.size() % 4 == 1 || in.find_first_not_of(kB64) != std::string_view::npos)
        return std::nullopt;
    std::string out;
    out.reserve(in.size() / 4 * 3 + 2);
    std::uint32_t acc = 0;
    int bits = 0;
    for (const char c : in) {
        acc = acc << 6 | static_cast<std::uint32_t>(kB64.find(c));
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
    return std::format("{:016x}", h);
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

std::expected<CatalogueRequest, std::string> parse_catalogue_params(const Params& p) {
    std::optional<std::string> err;
    auto get = [&](const char* k) -> std::string {
        const auto* v = find_param(p, k, err);
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
        return std::unexpected("parameter too long");
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
    if (r.query.source.size() > kSourceMaxBytes || r.query.agent_id.size() > kSourceMaxBytes)
        return std::unexpected("parameter too long");
    const auto lim = read_limit(limit, kVersionsDefaultLimit, kVersionsMax);
    if (!lim)
        return std::unexpected(lim.error());
    r.query.limit = static_cast<int>(*lim);
    return r;
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

std::string dump_safe(const nlohmann::json& j) {
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

// ── CSV ──────────────────────────────────────────────────────────────────────

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
            std::min<std::int64_t>(cap - static_cast<std::int64_t>(all.size()), kCatalogReadMax);
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

std::expected<CataloguePage, PageError> read_catalogue_page(const CatalogueReads& io,
                                                            const CatalogueRequest& rq) {
    const auto& q = rq.query;
    const bool host = !q.agent_id.empty();
    const bool continuation = !rq.cursor.empty();
    const std::string fp = filter_fingerprint(q);
    bool moved = false; // generation moved under a first page: re-read once
    auto attempt = [&]() -> std::expected<CataloguePage, PageError> {
        CataloguePage out;
        std::int64_t gen = 0;
        if (!host) {
            out.meta = io.meta();
            if (!out.meta)
                return std::unexpected(PageError{PageStatus::kDegraded});
            gen = out.meta->refreshed_at;
        }
        auto query = q;
        if (continuation) {
            auto cur = decode_catalogue_cursor(rq.cursor, fp, gen);
            if (!cur)
                return std::unexpected(PageError{cur.error() == CursorError::kStale
                                                     ? PageStatus::kStale
                                                     : PageStatus::kBadCursor,
                                                 cur.error()});
            query.after = *cur;
        }
        auto rows = io.rows(query);
        if (!rows)
            return std::unexpected(PageError{PageStatus::kDegraded});
        auto totals = io.totals(query);
        if (!totals)
            return std::unexpected(PageError{PageStatus::kDegraded});
        out.rows = std::move(*rows);
        out.totals = *totals;
        if (!host) {
            const auto after = io.meta();
            if (!after)
                return std::unexpected(PageError{PageStatus::kDegraded});
            if (after->refreshed_at != gen) {
                // A continuation never re-pages an old keyset over a new snapshot.
                if (continuation)
                    return std::unexpected(PageError{PageStatus::kStale, CursorError::kStale});
                moved = true;
                return std::unexpected(PageError{PageStatus::kDegraded}); // a second move: 503
            }
        }
        if (static_cast<int>(out.rows.size()) == q.limit)
            out.next_cursor = encode_catalogue_cursor(out.rows.back(), fp, gen);
        return out;
    };
    auto page = attempt();
    if (moved) {
        moved = false;
        page = attempt();
    }
    return page;
}

std::expected<TitlesExport, PageError> read_titles_export(const CatalogueReads& io,
                                                          const CatalogueRequest& rq,
                                                          bool omit_newest) {
    const bool host = !rq.query.agent_id.empty();
    for (int attempt = 0; attempt < 2; ++attempt) {
        std::int64_t gen = 0;
        if (!host) {
            const auto before = io.meta();
            if (!before)
                break;
            gen = before->refreshed_at;
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
    return std::unexpected(PageError{PageStatus::kDegraded});
}

} // namespace yuzu::server::software_catalogue
