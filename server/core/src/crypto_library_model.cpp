#include "crypto_library_model.hpp"

#include "list_keyset.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/log_token.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <format>
#include <initializer_list>
#include <iterator>
#include <utility>

namespace yuzu::server::crypto_library {

namespace {

constexpr char kSep = '\x1f';

constexpr std::array<Family, 12> kFamilies{{
    {"openssl", "OpenSSL"},
    {"libressl", "LibreSSL"},
    {"boringssl", "BoringSSL"},
    {"gnutls", "GnuTLS"},
    {"nss", "NSS"},
    {"mbedtls", "Mbed TLS"},
    {"wolfssl", "wolfSSL"},
    {"libgcrypt", "Libgcrypt"},
    {"libsodium", "libsodium"},
    {"nettle", "Nettle"},
    {"botan", "Botan"},
    {"bouncycastle", "Bouncy Castle"},
}};

// Sorted by (family_id, kind, value) - kExact before kPrefix. Every value is lowercase. Editing
// this table bumps kCryptoTableVersion. `nss` is exact-only on purpose: nss-mdns and
// nss-pam-ldapd are name-service plugins, not cryptography. The `win32 openssl` / `win64
// openssl` prefixes cover the Shining Light installer display names.
constexpr auto E = MatchKind::kExact;
constexpr auto P = MatchKind::kPrefix;
constexpr std::array kRules = std::to_array<MatchRule>({
    {"boringssl", P, "boringssl"},
    {"botan", P, "botan"},
    {"botan", P, "libbotan"},
    {"bouncycastle", P, "bcprov"},
    {"bouncycastle", P, "bouncycastle"},
    {"bouncycastle", P, "libbcpkix"},
    {"bouncycastle", P, "libbcprov"},
    {"gnutls", E, "gnutls"},
    {"gnutls", P, "gnutls-"},
    {"gnutls", P, "libgnutls"},
    {"libgcrypt", P, "libgcrypt"},
    {"libressl", P, "libressl"},
    {"libsodium", P, "libsodium"},
    {"mbedtls", E, "mbedtls"},
    {"mbedtls", P, "libmbedcrypto"},
    {"mbedtls", P, "libmbedtls"},
    {"mbedtls", P, "libmbedx509"},
    {"nettle", E, "nettle"},
    {"nettle", P, "libhogweed"},
    {"nettle", P, "libnettle"},
    {"nss", E, "libnss3"},
    {"nss", E, "libnss3-tools"},
    {"nss", E, "mozilla-nss"},
    {"nss", E, "mozilla-nss-tools"},
    {"nss", E, "nss"},
    {"nss", E, "nss-softokn"},
    {"nss", E, "nss-softokn-freebl"},
    {"nss", E, "nss-sysinit"},
    {"nss", E, "nss-tools"},
    {"nss", E, "nss-util"},
    {"openssl", E, "compat-openssl10"},
    {"openssl", E, "compat-openssl11"},
    {"openssl", E, "libopenssl1_1"},
    {"openssl", E, "libopenssl3"},
    {"openssl", E, "libssl-dev"},
    {"openssl", E, "libssl-doc"},
    {"openssl", E, "openssl"},
    {"openssl", E, "openssl-1.1"},
    {"openssl", E, "openssl-1_1"},
    {"openssl", E, "openssl-3"},
    {"openssl", E, "openssl-libs"},
    {"openssl", E, "openssl1.1"},
    {"openssl", E, "openssl3"},
    {"openssl", E, "openssl3-libs"},
    {"openssl", P, "libcrypto0"},
    {"openssl", P, "libcrypto1"},
    {"openssl", P, "libcrypto3"},
    {"openssl", P, "libcrypto4"},
    {"openssl", P, "libssl0"},
    {"openssl", P, "libssl1"},
    {"openssl", P, "libssl3"},
    {"openssl", P, "libssl4"},
    {"openssl", P, "openssl@"},
    {"openssl", P, "win32 openssl"},
    {"openssl", P, "win64 openssl"},
    {"wolfssl", E, "wolfssl"},
    {"wolfssl", P, "libwolfssl"},
});

std::string ascii_lower(std::string_view s) {
    std::string out(s);
    for (char& c : out)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    return out;
}

bool rule_matches(const MatchRule& r, std::string_view lower_name) {
    return r.kind == MatchKind::kExact ? lower_name == r.value : lower_name.starts_with(r.value);
}

// True for text Postgres can bind: strict UTF-8 and no NUL (anything else would surface as a
// store error and be reported as a retryable 503 instead of a caller 400).
bool valid_text(std::string_view v) {
    return v.find('\0') == std::string_view::npos && ::yuzu::server::sanitize_utf8_strict(v) == v;
}

// Value of `key`, or nullptr when absent. A repeated key sets `err` (and yields nullptr).
const std::string* find_param(const Params& p, const std::string& key,
                              std::optional<std::string>& err) {
    const auto [lo, hi] = p.equal_range(key);
    if (lo == hi)
        return nullptr;
    if (std::next(lo) != hi) {
        err = "repeated query parameter " + key; // differing values; identical pairs collapse upstream
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

std::optional<std::int64_t> parse_nonneg(std::string_view s) {
    if (s.empty() || !std::ranges::all_of(s, [](char c) { return c >= '0' && c <= '9'; }))
        return std::nullopt;
    return parse_i64(s);
}

// Length-prefixed so no byte content (incl. the separator) can shift a field boundary.
std::string length_prefixed(std::initializer_list<const std::string*> fields) {
    std::string s;
    for (const std::string* f : fields) {
        s += std::to_string(f->size());
        s += ':';
        s += *f;
        s += kSep;
    }
    return s;
}

// Inverse of length_prefixed(): exactly `n` fields, nothing before or after.
std::optional<std::vector<std::string_view>> read_length_prefixed(std::string_view in,
                                                                  std::size_t n) {
    std::vector<std::string_view> out;
    std::size_t pos = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const auto colon = in.find(':', pos);
        if (colon == std::string_view::npos)
            return std::nullopt;
        const auto len = parse_nonneg(in.substr(pos, colon - pos));
        const std::size_t remaining = in.size() - (colon + 1);
        if (!len || static_cast<std::uint64_t>(*len) >= remaining)
            return std::nullopt;
        const auto end = colon + 1 + static_cast<std::size_t>(*len);
        if (in[end] != kSep)
            return std::nullopt;
        out.push_back(in.substr(colon + 1, static_cast<std::size_t>(*len)));
        pos = end + 1;
    }
    if (pos != in.size())
        return std::nullopt;
    return out;
}

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

// Shared text hygiene of the parsers; nullopt = clean, else the 400 message.
std::optional<std::string> text_error(const std::string* family, const std::string* version,
                                      const std::string* ecosystem, const std::string* cursor) {
    for (const std::string* f : {family, version, ecosystem, cursor})
        if (f && !valid_text(*f))
            return "invalid parameter encoding";
    if (family && family->size() > 64)
        return "parameter too long";
    if (version && version->size() > kVersionMaxBytes)
        return "parameter too long";
    if (ecosystem && ecosystem->size() > kEcosystemMaxBytes)
        return "parameter too long";
    if (cursor && cursor->size() > kCursorMaxBytes)
        return "invalid cursor";
    return std::nullopt;
}

void tail(std::string& out, std::string_view key, const std::optional<std::string>& v) {
    if (v) {
        out += ';';
        out += key;
        out += '=';
        out += ::yuzu::log_token(*v);
    }
}

// MCP strict check of one optional string argument.
std::optional<std::string> string_arg_error(const nlohmann::json& args, const char* key,
                                            std::size_t max) {
    if (!args.contains(key))
        return std::nullopt;
    if (!args[key].is_string())
        return std::string(key) + " must be a JSON string";
    if (args[key].get_ref<const std::string&>().size() > max)
        return std::string(key) + " is too long";
    return std::nullopt;
}

std::optional<std::string> family_arg_error(const nlohmann::json& args) {
    if (const auto e = string_arg_error(args, "family", 64))
        return e;
    if (args.contains("family") && !find_family(args["family"].get<std::string>()))
        return "family is not one of the published families";
    return std::nullopt;
}

} // namespace

std::span<const Family> families() { return kFamilies; }
std::span<const MatchRule> rules() { return kRules; }

const Family* find_family(std::string_view id) {
    const auto it = std::ranges::find(kFamilies, id, &Family::id);
    return it == kFamilies.end() ? nullptr : &*it;
}

std::optional<std::string_view> classify(std::string_view package_name) {
    const std::string lower = ascii_lower(package_name);
    for (const auto& r : kRules)
        if (rule_matches(r, lower))
            return r.family_id;
    return std::nullopt;
}

std::string like_pattern(const MatchRule& r) {
    std::string out;
    out.reserve(r.value.size() + 1);
    for (const char c : r.value) {
        if (c == '\\' || c == '%' || c == '_')
            out.push_back('\\');
        out.push_back(c);
    }
    if (r.kind == MatchKind::kPrefix)
        out.push_back('%');
    return out;
}

SqlPatterns sql_patterns(std::optional<std::string_view> family) {
    SqlPatterns out;
    for (const auto& r : kRules) {
        if (family && r.family_id != *family)
            continue;
        out.patterns.push_back(like_pattern(r));
        out.labels.emplace_back(r.family_id);
    }
    return out;
}

// ── Parsers ──────────────────────────────────────────────────────────────────

std::expected<CryptoSummaryQuery, std::string> parse_summary_params(const Params& p) {
    std::optional<std::string> err;
    const auto* family = find_param(p, "family", err);
    const auto* ecosystem = find_param(p, "ecosystem", err);
    if (err)
        return std::unexpected(*err);
    if (const auto bad = text_error(family, nullptr, ecosystem, nullptr))
        return std::unexpected(*bad);
    CryptoSummaryQuery q;
    if (family && !family->empty()) {
        if (!find_family(*family))
            return std::unexpected("unknown family");
        q.family = *family;
    }
    if (ecosystem)
        q.ecosystem = *ecosystem; // present (even empty) = the exact ecosystem; absent = any
    return q;
}

std::expected<CryptoDevicesQuery, std::string> parse_devices_params(const Params& p) {
    std::optional<std::string> err;
    const auto* family = find_param(p, "family", err);
    const auto* version = find_param(p, "version", err);
    const auto* ecosystem = find_param(p, "ecosystem", err);
    const auto* cursor = find_param(p, "cursor", err);
    const auto* limit = find_param(p, "limit", err);
    if (err)
        return std::unexpected(*err);
    if (!family || family->empty())
        return std::unexpected("family is required");
    if (const auto bad = text_error(family, version, ecosystem, cursor))
        return std::unexpected(*bad);
    if (!find_family(*family))
        return std::unexpected("unknown family");
    CryptoDevicesQuery q;
    q.family = *family;
    if (version)
        q.version = *version;
    if (ecosystem)
        q.ecosystem = *ecosystem;
    if (cursor)
        q.cursor = *cursor;
    q.limit = static_cast<int>(kDefaultLimit);
    if (limit && !limit->empty()) {
        const auto n = parse_i64(*limit);
        if (!n)
            return std::unexpected("invalid limit (expected integer)");
        q.limit = static_cast<int>(std::clamp<std::int64_t>(*n, 1, kPageMax));
    }
    return q;
}

std::optional<std::string> strict_summary_args_error(const nlohmann::json& args) {
    if (!args.is_object())
        return std::nullopt;
    if (const auto e = family_arg_error(args))
        return e;
    return string_arg_error(args, "ecosystem", kEcosystemMaxBytes);
}

std::optional<std::string> strict_devices_args_error(const nlohmann::json& args) {
    if (!args.is_object() || !args.contains("family"))
        return "family is required";
    if (const auto e = family_arg_error(args))
        return e;
    if (const auto e = string_arg_error(args, "version", kVersionMaxBytes))
        return e;
    if (const auto e = string_arg_error(args, "ecosystem", kEcosystemMaxBytes))
        return e;
    if (const auto e = string_arg_error(args, "cursor", kCursorMaxBytes))
        return e;
    if (args.contains("limit")) {
        const auto& l = args["limit"];
        if (!l.is_number_integer())
            return "limit must be a JSON integer";
        // nlohmann stores every non-negative integer as unsigned: refuse above INT64_MAX
        // rather than let get<int64_t>() wrap.
        if (l.is_number_unsigned() && l.get<std::uint64_t>() > static_cast<std::uint64_t>(kPageMax))
            return "limit must be between 1 and " + std::to_string(kPageMax);
        const auto v = l.get<std::int64_t>();
        if (v < 1 || v > kPageMax)
            return "limit must be between 1 and " + std::to_string(kPageMax);
    }
    return std::nullopt;
}

// ── Audit targets ────────────────────────────────────────────────────────────

std::string audit_target(const CryptoSummaryQuery& q) {
    std::string out = "fleet";
    tail(out, "family", q.family);
    tail(out, "ecosystem", q.ecosystem);
    return out;
}

std::string audit_target(const CryptoDevicesQuery& q) {
    std::string out = "family=" + ::yuzu::log_token(q.family);
    tail(out, "version", q.version);
    tail(out, "ecosystem", q.ecosystem);
    return out;
}

std::string audit_detail(std::string_view cid, std::string_view family, std::size_t rows,
                         bool continuation) {
    return std::format("{}tv={} family={} rows={}{}",
                       cid.empty() ? std::string() : std::format("cid={} ", cid), kCryptoTableVersion,
                       family, rows, continuation ? " page=continuation" : "");
}

std::string audit_detail_degraded(std::string_view cid) {
    return std::format("{}tv={} store degraded",
                       cid.empty() ? std::string() : std::format("cid={} ", cid), kCryptoTableVersion);
}

// ── Cursors ──────────────────────────────────────────────────────────────────

std::string_view cursor_error_message(CursorError e) {
    return e == CursorError::kMalformed
               ? "invalid cursor"
               : "cursor was issued for a different filter set or table version; restart the "
                 "walk without a cursor";
}

std::string devices_fingerprint(const CryptoDevicesQuery& q, int table_version) {
    static const std::string kNone;
    const std::string tv = std::to_string(table_version);
    // A present-empty version/ecosystem (the exact empty bucket) is not an absent one. The table
    // version is part of the binding: a walk straddling a table edit (a rolling upgrade) must
    // restart, never silently alternate between two memberships.
    return fnv1a_hex16(std::string(1, q.version ? '1' : '0') + (q.ecosystem ? '1' : '0') +
                       length_prefixed({&tv, &q.family, q.version ? &*q.version : &kNone,
                                        q.ecosystem ? &*q.ecosystem : &kNone}));
}

std::string encode_cursor(const CursorPos& at, std::string_view fp) {
    const std::string id = std::to_string(at.install_id);
    std::string out = "k1:";
    out += fp;
    out += ':';
    out += keyset::b64url_encode(length_prefixed({&at.agent_id, &at.name, &id}));
    return out;
}

std::expected<CursorPos, CursorError> decode_cursor(std::string_view token, std::string_view fp) {
    // k1:<fp16>:<payload> - the base64url alphabet has no ':'.
    if (!token.starts_with("k1:") || token.size() < 3 + 16 + 1 || token[3 + 16] != ':')
        return std::unexpected(CursorError::kMalformed);
    const auto got_fp = token.substr(3, 16);
    const auto payload = keyset::b64url_decode(token.substr(3 + 16 + 1));
    if (!is_lower_hex16(got_fp) || !payload)
        return std::unexpected(CursorError::kMalformed);
    const auto f = read_length_prefixed(*payload, 3);
    if (!f || !valid_text((*f)[0]) || !valid_text((*f)[1]))
        return std::unexpected(CursorError::kMalformed);
    const auto id = parse_nonneg((*f)[2]);
    if (!id)
        return std::unexpected(CursorError::kMalformed);
    if (got_fp != fp)
        return std::unexpected(CursorError::kFilterMismatch);
    return CursorPos{.agent_id = std::string((*f)[0]), .name = std::string((*f)[1]), .install_id = *id};
}

// ── Assembly + JSON ──────────────────────────────────────────────────────────

namespace {

nlohmann::json version_json(const CryptoVersionRow& v) {
    return nlohmann::json{{"version", v.version},
                          {"ecosystem", v.ecosystem},
                          {"device_count", v.device_count},
                          {"package_names", v.package_names}};
}

// A package name cut to kNameMaxBytes on a code-point boundary; a cut name ends in U+2026.
std::string clamp_name(std::string n) {
    if (n.size() <= kNameMaxBytes)
        return n;
    constexpr std::string_view kEllipsis = "\xE2\x80\xA6";
    std::size_t end = kNameMaxBytes - kEllipsis.size();
    while (end > 0 && (static_cast<unsigned char>(n[end]) & 0xC0) == 0x80)
        --end;
    n.resize(end);
    n += kEllipsis;
    return n;
}

// Serialised size of one bucket inside its array (the element plus a separator).
std::size_t bucket_bytes(const CryptoVersionRow& v) { return dump_safe(version_json(v)).size() + 1; }

} // namespace

void finish_summary(CryptoSummary& s) {
    std::erase_if(s.families, [](const CryptoFamilyRow& f) { return f.device_count <= 0; });
    for (auto& f : s.families) {
        if (const Family* fam = find_family(f.id))
            f.display = std::string(fam->display);
        std::ranges::sort(f.versions, [](const CryptoVersionRow& a, const CryptoVersionRow& b) {
            if (a.device_count != b.device_count)
                return a.device_count > b.device_count;
            if (a.version != b.version)
                return a.version < b.version;
            return a.ecosystem < b.ecosystem;
        });
        if (f.versions.size() > kMaxVersionsPerFamily) {
            f.versions.resize(kMaxVersionsPerFamily);
            f.versions_truncated = true;
        }
        for (auto& v : f.versions)
            for (auto& n : v.package_names)
                n = clamp_name(std::move(n));
    }
    std::ranges::sort(s.families, [](const CryptoFamilyRow& a, const CryptoFamilyRow& b) {
        if (a.device_count != b.device_count)
            return a.device_count > b.device_count;
        return a.id < b.id;
    });

    // Fit the serialised size into the byte budget. Every family keeps its first bucket (the
    // "reserved" floor, counted up front so the total can never exceed the budget); further
    // buckets are admitted in order until the allowance runs out, then the rest of that family
    // and every later family's extras are dropped - flagged, never silent.
    constexpr std::size_t kEnvelope = 512;       // table_version, coverage, flags, braces
    constexpr std::size_t kFamilyOverhead = 192; // the family object's own keys
    std::size_t used = kEnvelope;
    for (const auto& f : s.families) {
        used += kFamilyOverhead + f.id.size() + f.display.size();
        if (!f.versions.empty())
            used += bucket_bytes(f.versions.front());
    }
    std::size_t allowance = used >= kSummaryByteBudget ? 0 : kSummaryByteBudget - used;
    bool budget_cut = false;
    for (auto& f : s.families) {
        for (std::size_t i = 1; i < f.versions.size(); ++i) {
            const std::size_t sz = bucket_bytes(f.versions[i]);
            if (budget_cut || sz > allowance) {
                f.versions.resize(i);
                f.versions_truncated = true;
                budget_cut = true;
                break;
            }
            allowance -= sz;
        }
    }
    if (budget_cut)
        s.result_truncated = true;
    // The store's row cap may have dropped EVERY bucket of a family: still a cut list.
    if (s.result_truncated)
        for (auto& f : s.families)
            if (f.versions.empty())
                f.versions_truncated = true;
}

nlohmann::json summary_json(const CryptoSummary& s) {
    using nlohmann::json;
    auto fams = json::array();
    for (const auto& f : s.families) {
        auto vers = json::array();
        for (const auto& v : f.versions)
            vers.push_back(version_json(v));
        fams.push_back(json{{"id", f.id},
                            {"display", f.display},
                            {"device_count", f.device_count},
                            {"versions", std::move(vers)},
                            {"versions_truncated", f.versions_truncated}});
    }
    return json{{"table_version", kCryptoTableVersion},
                {"families", std::move(fams)},
                {"coverage",
                 {{"devices_reporting_inventory", s.coverage.devices_reporting_inventory},
                  {"devices_with_crypto_library", s.coverage.devices_with_crypto_library}}},
                {"result_truncated", s.result_truncated}};
}

nlohmann::json devices_json(const CryptoDevicesPage& p) {
    using nlohmann::json;
    auto rows = json::array();
    for (const auto& d : p.devices)
        rows.push_back(json{{"agent_id", d.agent_id},
                            {"hostname", d.hostname.empty() ? json(nullptr) : json(d.hostname)},
                            {"package_name", d.package_name},
                            {"version", d.version},
                            {"release", d.release},
                            {"ecosystem", d.ecosystem},
                            {"kind", d.kind}});
    return json{{"table_version", kCryptoTableVersion},
                {"family", p.family},
                {"version", p.version ? json(*p.version) : json(nullptr)},
                {"devices", std::move(rows)},
                {"next_cursor", p.next_cursor.empty() ? json(nullptr) : json(p.next_cursor)},
                {"count", p.devices.size()}};
}

std::string dump_safe(const nlohmann::json& j) {
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

} // namespace yuzu::server::crypto_library
