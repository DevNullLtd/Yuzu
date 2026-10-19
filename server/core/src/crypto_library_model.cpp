#include "crypto_library_model.hpp"

#include "list_keyset.hpp"
#include "model_param_helpers.hpp" // shared param/cursor helpers (one copy, both models)
#include "software_catalog_rules.hpp" // kEcosystemFamilies: MCP's closed ecosystem vocabulary
#include "utf8_sanitize.hpp"

#include <yuzu/log_token.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <format>
#include <initializer_list>
#include <utility>

namespace yuzu::server::crypto_library {

namespace {

// The parameter and cursor-payload helpers are shared with software_catalogue_model.cpp.
using model_detail::find_param;
using model_detail::fnv1a_hex16;
using model_detail::is_lower_hex16;
using model_detail::kSep;
using model_detail::length_prefixed;
using model_detail::parse_i64;
using model_detail::parse_nonneg;
using model_detail::read_length_prefixed;
using model_detail::valid_text;

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
// nss-pam-ldapd are name-service plugins, not cryptography. Windows installer builds of OpenSSL
// (Uninstall-key DisplayNames) are deliberately NOT matched: table version 3 removed the
// `win32 openssl` / `win64 openssl` prefixes, which rested on no recorded DisplayName capture.
// Add a Windows rule only together with a real capture cited in the test that pins it.
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

// MCP's closed ecosystem vocabulary: the software catalogue twins' published set
// (software_catalog::kEcosystemFamilies), plus the empty string - the real bucket of rows that
// carry no ecosystem (pre-v2 rows). REST stays free text, as the software catalogue's REST
// routes do: an unknown value there simply matches no rows.
std::optional<std::string> ecosystem_arg_error(const nlohmann::json& args) {
    if (const auto e = string_arg_error(args, "ecosystem", kEcosystemMaxBytes))
        return e;
    if (!args.contains("ecosystem"))
        return std::nullopt;
    const auto& v = args["ecosystem"].get_ref<const std::string&>();
    if (v.empty() || std::ranges::any_of(software_catalog::kEcosystemFamilies,
                                         [&](const auto& e) { return e.ecosystem == v; }))
        return std::nullopt;
    return "ecosystem is not one of the published ecosystems";
}

std::optional<std::string> family_arg_error(const nlohmann::json& args) {
    if (const auto e = string_arg_error(args, "family", 64))
        return e;
    if (args.contains("family") && !find_family(args["family"].get<std::string>()))
        return "family is not one of the published families";
    return std::nullopt;
}

} // namespace

// Every rule's literal must be at least kLeadChars long: the store's step 1 pre-filters names by
// the first kLeadChars characters of each rule, so a shorter rule would silently never match.
constexpr bool all_rules_long_enough() {
    for (const auto& r : kRules)
        if (r.value.size() < kLeadChars)
            return false;
    return true;
}
static_assert(all_rules_long_enough(),
              "every crypto match rule must be at least kLeadChars (3) characters long");

// ...and sql_patterns() emits `value.substr(0, kLeadChars)`, so every lead is EXACTLY kLeadChars
// long - the store matches a literal-length prefix and rejects any other length.
constexpr bool all_leads_exact_length() {
    for (const auto& r : kRules)
        if (r.value.substr(0, kLeadChars).size() != kLeadChars)
            return false;
    return true;
}
static_assert(all_leads_exact_length(), "every crypto lead must be exactly kLeadChars long");

// Every rule value must be lowercase ASCII: the SQL compares lower(name COLLATE "C") with the
// stored lead and LIKE pattern, so an uppercase or non-ASCII rule byte could never match.
// (LIKE metacharacters, `_` included, are fine: like_pattern escapes them and the lead is
// compared by equality.)
constexpr bool all_rules_lowercase_ascii() {
    for (const auto& r : kRules)
        for (const char c : r.value)
            if ((c >= 'A' && c <= 'Z') || static_cast<unsigned char>(c) >= 0x80)
                return false;
    return true;
}
static_assert(all_rules_lowercase_ascii(),
              "every crypto match rule value must be lowercase ASCII (the SQL folds ASCII only)");

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
        out.leads.emplace_back(r.value.substr(0, kLeadChars));
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
    // A non-object root (null, array, string, number) is refused, never read as "no filter":
    // `[{"family":"openssl"}]` must not silently answer the unfiltered summary. An ABSENT
    // `arguments` reaches here as {} (the dispatcher's default) and is the unfiltered call.
    if (!args.is_object())
        return std::string(kArgumentsNotObject);
    if (const auto e = family_arg_error(args))
        return e;
    return ecosystem_arg_error(args);
}

std::optional<std::string> strict_devices_args_error(const nlohmann::json& args) {
    if (!args.is_object())
        return std::string(kArgumentsNotObject);
    if (!args.contains("family"))
        return "family is required";
    if (const auto e = family_arg_error(args))
        return e;
    if (const auto e = string_arg_error(args, "version", kVersionMaxBytes))
        return e;
    if (const auto e = ecosystem_arg_error(args))
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

namespace {
// ADR-0017 INV-9: the audit row says whether the read was fleet-wide or filtered.
constexpr std::string_view scope_token(bool confined) { return confined ? "confined" : "fleet"; }
} // namespace

std::string audit_detail(std::string_view cid, std::string_view family, std::size_t rows,
                         bool names_from_catalogue, bool continuation, bool confined) {
    return std::format("{}tv={} family={} rows={} src={} scope={}{}",
                       cid.empty() ? std::string() : std::format("cid={} ", cid), kCryptoTableVersion,
                       family, rows, names_from_catalogue ? "catalogue" : "live",
                       scope_token(confined), continuation ? " page=continuation" : "");
}

std::string audit_detail_degraded(std::string_view cid, CryptoReadCause cause, bool confined) {
    // Exhaustive, no default: a new cause must choose its audit wording. kNone is not a failure
    // cause; it reads as the store-degraded wording.
    std::string_view what;
    switch (cause) {
    case CryptoReadCause::kCapacity:
        what = "capacity in use";
        break;
    case CryptoReadCause::kAccessCheck: // fragment-only; the gate writes its own audit row
        what = "access check unavailable";
        break;
    case CryptoReadCause::kNone:
    case CryptoReadCause::kStoreDegraded:
        what = "store degraded";
        break;
    }
    return std::format("{}tv={} scope={} {}",
                       cid.empty() ? std::string() : std::format("cid={} ", cid),
                       kCryptoTableVersion, scope_token(confined), what);
}

std::string_view degraded_message(CryptoReadCause cause) {
    switch (cause) {
    case CryptoReadCause::kCapacity:
        return "crypto read capacity in use; retry";
    case CryptoReadCause::kAccessCheck: // fragment-only; REST/MCP carry the gate's own envelope
        return "crypto access check unavailable";
    case CryptoReadCause::kNone:
    case CryptoReadCause::kStoreDegraded:
        return "crypto library read degraded";
    }
    return "crypto library read degraded"; // unreachable: every enumerator returns above
}

// ── Cursors ──────────────────────────────────────────────────────────────────

std::string_view cursor_error_message(CursorError e) {
    return e == CursorError::kMalformed
               ? "invalid cursor"
               : "cursor was issued for a different filter set or table version; restart the "
                 "walk without a cursor";
}

std::string_view names_source_changed_message() {
    return "the previous page was read on live package names and the shared catalogue "
           "(names_source / names_as_of) is now in use, so rows could be skipped; restart the "
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
    const std::string as_of = std::to_string(at.names_as_of);
    std::string out = "k1:";
    out += fp;
    out += ':';
    out += keyset::b64url_encode(length_prefixed({&at.agent_id, &at.name, &id, &as_of}));
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
    const auto f = read_length_prefixed(*payload, 4);
    if (!f || !valid_text((*f)[0]) || !valid_text((*f)[1]))
        return std::unexpected(CursorError::kMalformed);
    const auto id = parse_nonneg((*f)[2]);
    const auto as_of = parse_nonneg((*f)[3]);
    if (!id || !as_of)
        return std::unexpected(CursorError::kMalformed);
    if (got_fp != fp)
        return std::unexpected(CursorError::kFilterMismatch);
    return CursorPos{.agent_id = std::string((*f)[0]),
                     .name = std::string((*f)[1]),
                     .install_id = *id,
                     .names_as_of = *as_of};
}

// ── Assembly + JSON ──────────────────────────────────────────────────────────

namespace {

nlohmann::json version_json(const CryptoVersionRow& v) {
    return nlohmann::json{{"version", v.version},
                          {"ecosystem", v.ecosystem},
                          {"device_count", v.device_count},
                          {"package_names", v.package_names},
                          {"package_names_truncated", v.package_names_truncated}};
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
    // The store's row ceiling fired: which families lost buckets is unknowable here (the cut
    // falls wherever the ordering puts it), so every family is flagged - a truthful over-flag,
    // never a silent partial list.
    const bool store_cut = s.result_truncated;
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

    // Fit the serialised size into the byte budget (about 256 KiB). Every family keeps its
    // first bucket (the floor, counted up front and never dropped, so a worst case of hostile
    // long values in 12 first buckets lands near 300 KB, not at the budget); further buckets
    // are admitted in order until the allowance runs out, then the rest of that family and
    // every later family's extras are dropped - flagged, never silent.
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
    if (store_cut)
        for (auto& f : s.families)
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
                {"names_source", s.names_from_catalogue ? "catalogue" : "live"},
                {"names_as_of", s.names_from_catalogue ? json(s.names_as_of) : json(nullptr)},
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
                {"names_source", p.names_from_catalogue ? "catalogue" : "live"},
                {"names_as_of", p.names_from_catalogue ? json(p.names_as_of) : json(nullptr)},
                {"family", p.family},
                {"version", p.version ? json(*p.version) : json(nullptr)},
                {"ecosystem", p.ecosystem ? json(*p.ecosystem) : json(nullptr)},
                {"devices", std::move(rows)},
                {"next_cursor", p.next_cursor.empty() ? json(nullptr) : json(p.next_cursor)},
                {"count", p.devices.size()}};
}

std::string dump_safe(const nlohmann::json& j) {
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

} // namespace yuzu::server::crypto_library
