#include "certificate_read_model.hpp"

#include "list_keyset.hpp"
#include "model_param_helpers.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <initializer_list>
#include <utility>

namespace yuzu::server::cert_read {

namespace {

using model_detail::find_param;
using model_detail::fnv1a_hex16;
using model_detail::is_lower_hex16;
using model_detail::length_prefixed;
using model_detail::parse_i64;
using model_detail::read_length_prefixed;
using model_detail::valid_text;

constexpr std::size_t kTextMaxBytes = 1024;
constexpr std::size_t kAgentIdMaxBytes = 256;

constexpr std::array<std::string_view, 8> kNotRead = {
    "Java cacerts",
    "PKCS#12 files",
    ".p11-kit trust modules",
    "NSS databases",
    "application-private certificate stores",
    "per-user certificate stores",
    "chain validation (no chain result is built)",
    "revocation (not checked by this version)",
};

// The keys every certificate filter shares, in the order audit_detail names them.
constexpr std::array<std::string_view, 19> kFilterKeys = {
    "store",          "scope",         "key_alg_oid",        "sig_alg_oid",
    "ec_curve_oid",   "not_after_before", "not_after_after", "not_before_after",
    "rsa_modulus_bits_lt", "ec_order_bits_lt", "is_ca",      "self_signed",
    "agent_id",       "issuer_dn",     "issuer_dn_contains", "subject_dn_contains",
    "sha256",         "spki_sha256",   "aki_key_id"};

bool is_hex(std::string_view s) {
    return !s.empty() && std::ranges::all_of(s, [](unsigned char c) { return std::isxdigit(c) != 0; });
}

std::string lower(std::string_view s) {
    std::string o(s);
    for (auto& c : o)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return o;
}

std::string upper(std::string_view s) {
    std::string o(s);
    for (auto& c : o)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return o;
}

/// `^[0-2](\.[0-9]+){1,32}$`
bool is_oid(std::string_view s) {
    if (s.size() < 3 || s.size() > 1024 || s[0] < '0' || s[0] > '2')
        return false;
    std::size_t arcs = 0;
    std::size_t i = 1;
    while (i < s.size()) {
        if (s[i] != '.')
            return false;
        ++i;
        const std::size_t start = i;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9')
            ++i;
        if (i == start)
            return false;
        ++arcs;
    }
    return arcs >= 1 && arcs <= 32;
}

std::optional<std::string> validate_text(std::string_view name, std::string_view v,
                                         std::size_t max_bytes) {
    if (v.size() > max_bytes)
        return "parameter " + std::string(name) + " is too long (at most " +
               std::to_string(max_bytes) + " bytes)";
    if (!valid_text(v))
        return "parameter " + std::string(name) + " is not valid UTF-8 text";
    return std::nullopt;
}

struct Reader {
    const Params& p;
    std::optional<std::string> err;

    /// The value of `key`, nullptr when absent; a repeated key sets err.
    const std::string* get(const std::string& key) {
        if (err)
            return nullptr;
        return find_param(p, key, err);
    }
    void fail(std::string m) {
        if (!err)
            err = std::move(m);
    }
};

void read_filter(Reader& r, CertReadFilter& f) {
    const auto text = [&](const char* key, std::optional<std::string>& dst, std::size_t max,
                          bool allow_empty) {
        const auto* v = r.get(key);
        if (!v || r.err)
            return;
        if (const auto bad = validate_text(key, *v, max)) {
            r.fail(*bad);
            return;
        }
        if (v->empty() && !allow_empty) {
            r.fail(std::string("parameter ") + key + " must not be empty");
            return;
        }
        dst = *v;
    };
    const auto oid = [&](const char* key, std::optional<std::string>& dst) {
        const auto* v = r.get(key);
        if (!v || r.err)
            return;
        if (!is_oid(*v)) {
            r.fail(std::string("parameter ") + key +
                   " must be a dotted-decimal OID (for example 1.2.840.113549.1.1.1)");
            return;
        }
        dst = *v;
    };
    const auto instant = [&](const char* key, std::optional<std::string>& dst) {
        const auto* v = r.get(key);
        if (!v || r.err)
            return;
        const auto t = parse_instant(*v);
        if (!t) {
            r.fail(std::string("parameter ") + key +
                   " must be an RFC 3339 UTC instant to the second (YYYY-MM-DDTHH:MM:SSZ)");
            return;
        }
        dst = *t;
    };
    const auto bits = [&](const char* key, std::optional<int>& dst) {
        const auto* v = r.get(key);
        if (!v || r.err)
            return;
        const auto n = parse_i64(*v);
        if (!n || *n < 1 || *n > 65536 || (!v->empty() && ((*v)[0] == '+' || (*v)[0] == '-'))) {
            r.fail(std::string("parameter ") + key + " must be an integer from 1 to 65536");
            return;
        }
        dst = static_cast<int>(*n);
    };
    const auto flag = [&](const char* key, std::optional<bool>& dst) {
        const auto* v = r.get(key);
        if (!v || r.err)
            return;
        if (*v != "true" && *v != "false") {
            r.fail(std::string("parameter ") + key + " must be true or false");
            return;
        }
        dst = *v == "true";
    };
    const auto digest = [&](const char* key, std::optional<std::string>& dst) {
        const auto* v = r.get(key);
        if (!v || r.err)
            return;
        if (v->size() != 64 || !is_hex(*v)) {
            r.fail(std::string("parameter ") + key + " must be 64 hexadecimal characters");
            return;
        }
        dst = lower(*v); // digests are stored lowercase
    };

    text("store", f.store, kTextMaxBytes, false);
    if (const auto* v = r.get("scope"); v && !r.err) {
        if (*v != "machine")
            r.fail("parameter scope must be machine");
        else
            f.scope = *v;
    }
    oid("key_alg_oid", f.key_alg_oid);
    oid("sig_alg_oid", f.sig_alg_oid);
    oid("ec_curve_oid", f.ec_curve_oid);
    instant("not_after_before", f.not_after_before);
    instant("not_after_after", f.not_after_after);
    instant("not_before_after", f.not_before_after);
    bits("rsa_modulus_bits_lt", f.rsa_modulus_bits_lt);
    bits("ec_order_bits_lt", f.ec_order_bits_lt);
    flag("is_ca", f.is_ca);
    flag("self_signed", f.self_signed);
    text("agent_id", f.agent_id, kAgentIdMaxBytes, false);
    text("issuer_dn", f.issuer_dn, kTextMaxBytes, true); // an empty issuer is a real value
    for (const auto& [key, dst] :
         {std::pair<const char*, std::optional<std::string>*>{"issuer_dn_contains",
                                                              &f.issuer_dn_contains},
          std::pair<const char*, std::optional<std::string>*>{"subject_dn_contains",
                                                              &f.subject_dn_contains}}) {
        const auto* v = r.get(key);
        if (!v || r.err)
            continue;
        if (v->size() < kCertFilterContainsMin || v->size() > kCertFilterContainsMax) {
            r.fail(std::string("parameter ") + key + " must be " +
                   std::to_string(kCertFilterContainsMin) + " to " +
                   std::to_string(kCertFilterContainsMax) + " bytes");
            continue;
        }
        if (const auto bad = validate_text(key, *v, kCertFilterContainsMax)) {
            r.fail(*bad);
            continue;
        }
        *dst = *v;
    }
    digest("sha256", f.sha256);
    digest("spki_sha256", f.spki_sha256);
    if (const auto* v = r.get("aki_key_id"); v && !r.err) {
        if (v->size() < 2 || v->size() > 128 || v->size() % 2 != 0 || !is_hex(*v))
            r.fail("parameter aki_key_id must be 2 to 128 hexadecimal characters (whole bytes)");
        else
            f.aki_key_id = upper(*v); // key identifiers are stored uppercase
    }
    // The subject substring is only ever searched among CA certificates: an end-entity subject
    // can carry a person's name or e-mail address, and a fleet-wide substring search over those
    // would be a search for a person.
    if (!r.err && f.subject_dn_contains && !(f.is_ca && *f.is_ca))
        r.fail("parameter subject_dn_contains is accepted only together with is_ca=true");
}

/// Refuse any key not in `allowed` (a typo'd filter silently ignored would return the whole
/// fleet from an audited read).
void refuse_unknown(Reader& r, std::initializer_list<std::string_view> extra) {
    if (r.err)
        return;
    for (const auto& [k, v] : r.p) {
        (void)v;
        const bool known = std::ranges::find(kFilterKeys, k) != kFilterKeys.end() ||
                           std::ranges::find(extra, std::string_view(k)) != extra.end();
        if (!known) {
            r.fail("unknown parameter " + k);
            return;
        }
    }
}

} // namespace

std::span<const std::string_view> not_read() { return kNotRead; }

std::optional<std::string> parse_instant(std::string_view s) {
    // YYYY-MM-DDTHH:MM:SSZ
    if (s.size() != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s[19] != 'Z')
        return std::nullopt;
    const auto num = [&](std::size_t pos, std::size_t len) -> std::optional<int> {
        int v = 0;
        for (std::size_t i = pos; i < pos + len; ++i) {
            if (s[i] < '0' || s[i] > '9')
                return std::nullopt;
            v = v * 10 + (s[i] - '0');
        }
        return v;
    };
    const auto y = num(0, 4), mo = num(5, 2), d = num(8, 2), h = num(11, 2), mi = num(14, 2),
               se = num(17, 2);
    if (!y || !mo || !d || !h || !mi || !se || *y < 1 || *mo < 1 || *mo > 12 || *d < 1 || *h > 23 ||
        *mi > 59 || *se > 59)
        return std::nullopt;
    static constexpr int kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap = (*y % 4 == 0 && *y % 100 != 0) || *y % 400 == 0;
    const int dim = kDays[*mo - 1] + (*mo == 2 && leap ? 1 : 0);
    if (*d > dim)
        return std::nullopt;
    return std::string(s);
}

std::expected<CertQuery, std::string> parse_list_params(const Params& p) {
    Reader r{p, std::nullopt};
    refuse_unknown(r, {"cursor", "limit"});
    CertQuery q;
    read_filter(r, q.filter);
    if (const auto* v = r.get("cursor"); v && !r.err) {
        if (v->size() > kCertCursorMaxBytes)
            r.fail("parameter cursor is too long");
        else if (!valid_text(*v))
            r.fail("parameter cursor is not valid UTF-8 text");
        else
            q.cursor = *v;
    }
    if (const auto* v = r.get("limit"); v && !r.err) {
        const auto n = parse_i64(*v);
        if (!n || *n < 1 || *n > kCertPageMax || (!v->empty() && ((*v)[0] == '+' || (*v)[0] == '-')))
            r.fail("parameter limit must be an integer from 1 to " + std::to_string(kCertPageMax));
        else
            q.limit = static_cast<int>(*n);
    }
    if (r.err)
        return std::unexpected(*r.err);
    return q;
}

std::expected<CertSummaryQuery, std::string> parse_summary_params(const Params& p) {
    Reader r{p, std::nullopt};
    refuse_unknown(r, {"not_after_edges"});
    CertSummaryQuery q;
    read_filter(r, q.filter);
    if (const auto* v = r.get("not_after_edges"); v && !r.err) {
        std::string_view rest = *v;
        while (true) {
            const auto comma = rest.find(',');
            const auto piece = rest.substr(0, comma);
            const auto t = parse_instant(piece);
            if (!t) {
                r.fail("parameter not_after_edges must be a comma-separated list of RFC 3339 UTC "
                       "instants (YYYY-MM-DDTHH:MM:SSZ)");
                break;
            }
            if (!q.not_after_edges.empty() && !(q.not_after_edges.back() < *t)) {
                r.fail("parameter not_after_edges must be strictly ascending");
                break;
            }
            q.not_after_edges.push_back(*t);
            if (q.not_after_edges.size() > kCertEdgesMax) {
                r.fail("parameter not_after_edges takes at most " + std::to_string(kCertEdgesMax) +
                       " instants");
                break;
            }
            if (comma == std::string_view::npos)
                break;
            rest.remove_prefix(comma + 1);
        }
    }
    if (r.err)
        return std::unexpected(*r.err);
    return q;
}

namespace {

enum class Kind { kString, kInt, kBool, kStringArray };

std::optional<std::string> strict_args(const nlohmann::json& args,
                                       std::initializer_list<std::pair<std::string_view, Kind>> extra) {
    if (!args.is_object())
        return std::string(kArgumentsNotObject);
    const auto kind_of = [&](const std::string& k) -> std::optional<Kind> {
        if (k == "rsa_modulus_bits_lt" || k == "ec_order_bits_lt")
            return Kind::kInt;
        if (k == "is_ca" || k == "self_signed")
            return Kind::kBool;
        if (std::ranges::find(kFilterKeys, std::string_view(k)) != kFilterKeys.end())
            return Kind::kString;
        for (const auto& [name, kind] : extra)
            if (name == k)
                return kind;
        return std::nullopt;
    };
    for (const auto& [k, v] : args.items()) {
        const auto kind = kind_of(k);
        if (!kind)
            return "unknown parameter " + k;
        switch (*kind) {
        case Kind::kString:
            if (!v.is_string())
                return "parameter " + k + " must be a string";
            break;
        case Kind::kInt:
            if (!v.is_number_integer() || (v.is_number_unsigned() && v.get<std::uint64_t>() > 1000000))
                return "parameter " + k + " must be an integer";
            break;
        case Kind::kBool:
            if (!v.is_boolean())
                return "parameter " + k + " must be a boolean";
            break;
        case Kind::kStringArray:
            if (!v.is_array() ||
                !std::ranges::all_of(v, [](const nlohmann::json& e) { return e.is_string(); }))
                return "parameter " + k + " must be an array of strings";
            break;
        }
    }
    return std::nullopt;
}

} // namespace

std::optional<std::string> strict_list_args_error(const nlohmann::json& args) {
    return strict_args(args, {{"cursor", Kind::kString}, {"limit", Kind::kInt}});
}

std::optional<std::string> strict_summary_args_error(const nlohmann::json& args) {
    return strict_args(args, {{"not_after_edges", Kind::kStringArray}});
}

Params params_from_args(const nlohmann::json& args) {
    Params p;
    if (!args.is_object())
        return p;
    for (const auto& [k, v] : args.items()) {
        if (v.is_string())
            p.emplace(k, v.get<std::string>());
        else if (v.is_boolean())
            p.emplace(k, v.get<bool>() ? "true" : "false");
        else if (v.is_number_integer())
            p.emplace(k, std::to_string(v.get<std::int64_t>()));
        else if (v.is_array()) {
            std::string joined;
            for (const auto& e : v) {
                if (!joined.empty())
                    joined += ',';
                joined += e.get<std::string>();
            }
            // An empty array is a present-but-empty list, refused by the parser like "".
            p.emplace(k, joined);
        }
    }
    return p;
}

// ── Cursors ──────────────────────────────────────────────────────────────────

std::string_view cursor_error_message(CursorError e) {
    return e == CursorError::kMalformed
               ? "invalid cursor"
               : "cursor was issued for a different filter set; restart the walk without a "
                 "cursor";
}

std::string filter_fingerprint(const CertReadFilter& f) {
    static const std::string kNone;
    const auto b = [](const std::optional<bool>& v) {
        return std::string(v ? (*v ? "1" : "0") : "-");
    };
    const auto i = [](const std::optional<int>& v) {
        return v ? std::to_string(*v) : std::string("-");
    };
    const auto s = [](const std::optional<std::string>& v) {
        return std::string(v ? "1" : "0") + (v ? *v : kNone);
    };
    const std::string parts[] = {s(f.store),
                                 s(f.scope),
                                 s(f.key_alg_oid),
                                 s(f.sig_alg_oid),
                                 s(f.ec_curve_oid),
                                 s(f.not_after_before),
                                 s(f.not_after_after),
                                 s(f.not_before_after),
                                 i(f.rsa_modulus_bits_lt),
                                 i(f.ec_order_bits_lt),
                                 b(f.is_ca),
                                 b(f.self_signed),
                                 s(f.agent_id),
                                 s(f.issuer_dn),
                                 s(f.issuer_dn_contains),
                                 s(f.subject_dn_contains),
                                 s(f.sha256),
                                 s(f.spki_sha256),
                                 s(f.aki_key_id)};
    std::string joined;
    for (const auto& part : parts)
        joined += std::to_string(part.size()) + ":" + part + model_detail::kSep;
    return fnv1a_hex16(joined);
}

std::string encode_cursor(const CertReadAfter& at, std::string_view fp) {
    std::string out = "c1:";
    out += fp;
    out += ':';
    out += keyset::b64url_encode(length_prefixed({&at.agent_id, &at.sha256}));
    return out;
}

std::expected<CertReadAfter, CursorError> decode_cursor(std::string_view token,
                                                         std::string_view fp) {
    if (!token.starts_with("c1:") || token.size() < 3 + 16 + 1 || token[3 + 16] != ':')
        return std::unexpected(CursorError::kMalformed);
    const auto got_fp = token.substr(3, 16);
    const auto payload = keyset::b64url_decode(token.substr(3 + 16 + 1));
    if (!is_lower_hex16(got_fp) || !payload)
        return std::unexpected(CursorError::kMalformed);
    const auto f = read_length_prefixed(*payload, 2);
    if (!f || !valid_text((*f)[0]) || !valid_text((*f)[1]) || (*f)[0].empty() || (*f)[1].empty())
        return std::unexpected(CursorError::kMalformed);
    if (got_fp != fp)
        return std::unexpected(CursorError::kFilterMismatch);
    return CertReadAfter{std::string((*f)[0]), std::string((*f)[1])};
}

// ── JSON ─────────────────────────────────────────────────────────────────────

namespace {

using Json = nlohmann::json;

Json opt(const std::optional<std::string>& v) { return v ? Json(*v) : Json(nullptr); }
Json opt(const std::optional<int>& v) { return v ? Json(*v) : Json(nullptr); }
Json opt(const std::optional<bool>& v) { return v ? Json(*v) : Json(nullptr); }

Json key_usage_json(const std::optional<std::string>& ku) {
    if (!ku)
        return nullptr;
    Json a = Json::array();
    std::string_view rest = *ku;
    while (!rest.empty()) {
        const auto comma = rest.find(',');
        auto piece = rest.substr(0, comma);
        while (!piece.empty() && piece.front() == ' ')
            piece.remove_prefix(1);
        while (!piece.empty() && piece.back() == ' ')
            piece.remove_suffix(1);
        if (!piece.empty())
            a.push_back(std::string(piece));
        if (comma == std::string_view::npos)
            break;
        rest.remove_prefix(comma + 1);
    }
    return a;
}

Json counts_json(const CertCounts& c) {
    return {{"device_count", c.device_count}, {"certificate_count", c.certificate_count}};
}

Json coverage_json(const CertCoverage& c) {
    return {{"devices_reporting", c.devices_reporting},
            {"devices_included", c.devices_included},
            {"confined", c.confined}};
}

Json blob_versions_json(const std::vector<std::string>& v) {
    Json a = Json::array();
    for (const auto& s : v) {
        int n = 0;
        const auto r = std::from_chars(s.data(), s.data() + s.size(), n);
        if (r.ec == std::errc{} && r.ptr == s.data() + s.size())
            a.push_back(n);
        else
            a.push_back(s);
    }
    return a;
}

Json constrained_json(const std::string& tokens) {
    Json a = Json::array();
    std::string_view rest = tokens;
    while (!rest.empty()) {
        const auto comma = rest.find(',');
        const auto piece = rest.substr(0, comma);
        if (!piece.empty())
            a.push_back(std::string(piece));
        if (comma == std::string_view::npos)
            break;
        rest.remove_prefix(comma + 1);
    }
    return a;
}

} // namespace

Json row_json(const CertReadRow& r) {
    Json j;
    j["agent_id"] = r.agent_id;
    j["hostname"] = r.hostname.empty() ? Json(nullptr) : Json(r.hostname);
    j["sha256"] = r.sha256;
    j["sha1"] = opt(r.sha1);
    j["tbs_sha256"] = opt(r.tbs_sha256);
    j["serial"] = opt(r.serial);
    j["subject_dn"] = opt(r.subject_dn);
    j["issuer_dn"] = opt(r.issuer_dn);
    j["not_before"] = opt(r.not_before);
    j["not_after"] = opt(r.not_after);
    j["key_alg_oid"] = opt(r.key_alg_oid);
    j["rsa_modulus_bits"] = opt(r.rsa_modulus_bits);
    j["ec_curve_oid"] = opt(r.ec_curve_oid);
    j["ec_order_bits"] = opt(r.ec_order_bits);
    j["sig_alg_oid"] = opt(r.sig_alg_oid);
    j["pss_hash_oid"] = opt(r.pss_hash_oid);
    j["spki_sha256"] = opt(r.spki_sha256);
    j["ski"] = opt(r.ski);
    j["aki_key_id"] = opt(r.aki_key_id);
    j["is_ca"] = opt(r.is_ca);
    j["path_len"] = opt(r.path_len);
    j["self_signed"] = opt(r.self_signed);
    j["key_usage"] = key_usage_json(r.key_usage);
    j["eku_oids"] = r.ekus;
    Json sans = Json::array();
    for (const auto& s : r.sans)
        sans.push_back({{"type", s.type}, {"value", s.value}});
    j["sans"] = std::move(sans);
    j["key_association"] = opt(r.key_association);
    j["key_provider"] = opt(r.key_provider);
    j["key_exportable"] = opt(r.key_exportable);
    Json locs = Json::array();
    for (const auto& l : r.locations)
        locs.push_back({{"store_id", l.store_id},
                        {"path", l.path},
                        {"store_status", l.store_status},
                        {"observed_at", opt(l.observed_at)},
                        {"last_seen", l.last_seen}});
    j["locations"] = std::move(locs);
    j["last_seen"] = r.last_seen;
    j["constrained_fields"] = constrained_json(r.constrained_fields);
    return j;
}

Json list_json(const CertPage& p) {
    Json certs = Json::array();
    for (const auto& r : p.rows)
        certs.push_back(row_json(r));
    Json stores = Json::array();
    for (const auto& s : p.stores)
        stores.push_back({{"agent_id", s.agent_id},
                          {"store_id", s.store_id},
                          {"status", s.status},
                          {"reason", s.reason},
                          {"observed_at", opt(s.observed_at)},
                          {"status_at", s.status_at}});
    Json nr = Json::array();
    for (const auto& s : not_read())
        nr.push_back(std::string(s));
    return {{"certificates", std::move(certs)},
            {"stores", std::move(stores)},
            {"not_read", std::move(nr)},
            {"coverage", coverage_json(p.coverage)},
            {"result_truncated", p.result_truncated},
            {"truncated_parts", p.truncated_parts},
            {"next_cursor", p.next_cursor.empty() ? Json(nullptr) : Json(p.next_cursor)},
            {"blob_versions", blob_versions_json(p.blob_versions)},
            {"count", p.rows.size()}};
}

Json summary_json(const CertSummary& s) {
    Json ka = Json::array();
    for (const auto& g : s.key_algorithms) {
        Json e = counts_json(g.counts);
        e["key_alg_oid"] = g.key_alg_oid;
        e["rsa_modulus_bits"] = opt(g.rsa_modulus_bits);
        e["ec_order_bits"] = opt(g.ec_order_bits);
        ka.push_back(std::move(e));
    }
    Json sa = Json::array();
    for (const auto& g : s.signature_algorithms) {
        Json e = counts_json(g.counts);
        e["sig_alg_oid"] = g.sig_alg_oid;
        e["pss_hash_oid"] = opt(g.pss_hash_oid);
        sa.push_back(std::move(e));
    }
    Json ec = Json::array();
    for (const auto& g : s.ec_curves) {
        Json e = counts_json(g.counts);
        e["ec_curve_oid"] = g.ec_curve_oid;
        ec.push_back(std::move(e));
    }
    Json is = Json::array();
    for (const auto& g : s.issuers) {
        Json e = counts_json(g.counts);
        e["issuer_dn"] = g.issuer_dn;
        is.push_back(std::move(e));
    }
    Json st = Json::array();
    for (const auto& g : s.stores) {
        Json e = counts_json(g.counts);
        e["store_id"] = g.store_id;
        st.push_back(std::move(e));
    }
    Json ss = Json::array();
    for (const auto& g : s.store_statuses)
        ss.push_back({{"status", g.status},
                      {"store_count", g.store_count},
                      {"device_count", g.device_count}});
    Json hist = Json::array();
    for (const auto& b : s.not_after_histogram) {
        Json e = counts_json(b.counts);
        e["from"] = opt(b.from);
        e["to"] = opt(b.to);
        e["unknown"] = b.unknown;
        hist.push_back(std::move(e));
    }
    Json nr = Json::array();
    for (const auto& n : not_read())
        nr.push_back(std::string(n));
    return {{"totals", counts_json(s.totals)},
            {"key_algorithms", std::move(ka)},
            {"signature_algorithms", std::move(sa)},
            {"ec_curves", std::move(ec)},
            {"issuers", std::move(is)},
            {"stores", std::move(st)},
            {"store_statuses", std::move(ss)},
            {"not_after_histogram", std::move(hist)},
            {"not_read", std::move(nr)},
            {"coverage", coverage_json(s.coverage)},
            {"result_truncated", s.result_truncated},
            {"truncated_parts", s.truncated_parts},
            {"issuers_note",
             "A self-signed or self-issued certificate that is not a CA is never an issuer group: its issuer "
             "repeats its subject, which can be a person's name."},
            {"blob_versions", blob_versions_json(s.blob_versions)}};
}

std::string dump_safe(const Json& j) {
    return j.dump(-1, ' ', false, Json::error_handler_t::replace);
}

// ── Truncation ───────────────────────────────────────────────────────────────

void finish_page(CertPage& page, std::string_view fp, std::size_t byte_budget) {
    std::vector<std::string> parts;
    const auto add = [&](const char* p) {
        if (std::ranges::find(parts, std::string_view(p)) == parts.end())
            parts.emplace_back(p);
    };
    // Stop at a whole certificate inside the byte budget (the first row is always kept, so a page
    // is never empty while rows exist).
    // The stores[] block rides in the same response, so it counts against the budget too.
    std::size_t used = 0;
    for (const auto& st : page.stores)
        used += st.agent_id.size() + st.store_id.size() + st.reason.size() + 96;
    std::size_t keep = page.rows.size();
    for (std::size_t i = 0; i < page.rows.size(); ++i) {
        used += dump_safe(row_json(page.rows[i])).size() + 1;
        if (used > byte_budget && i > 0) {
            keep = i;
            break;
        }
    }
    const bool byte_cut = keep < page.rows.size();
    if (byte_cut) {
        page.rows.resize(keep);
        add("byte_budget");
    }
    if (page.has_more)
        add("page_limit");
    page.next_cursor.clear();
    if ((page.has_more || byte_cut) && !page.rows.empty())
        page.next_cursor =
            encode_cursor({page.rows.back().agent_id, page.rows.back().sha256}, fp);
    // The stores of devices no longer on the page are dropped with their rows.
    if (byte_cut) {
        std::vector<std::string> agents;
        for (const auto& r : page.rows)
            if (agents.empty() || agents.back() != r.agent_id)
                agents.push_back(r.agent_id);
        std::erase_if(page.stores, [&](const CertStoreRead& s) {
            return std::ranges::find(agents, s.agent_id) == agents.end();
        });
        page.coverage.devices_included = static_cast<std::int64_t>(agents.size());
    }
    for (const auto& r : page.rows) {
        if (r.locations_truncated)
            add("locations_cap");
        if (r.sans_truncated)
            add("sans_cap");
        if (!r.constrained_fields.empty())
            add("constrained_certificate");
    }
    for (const auto& s : page.stores)
        if (s.status == "constrained")
            add("constrained_store");
    page.truncated_parts = std::move(parts);
    page.result_truncated = !page.truncated_parts.empty();
}

void finish_summary(CertSummary& s) { s.result_truncated = !s.truncated_parts.empty(); }

// ── Audit ────────────────────────────────────────────────────────────────────

std::string filter_names(const CertReadFilter& f) {
    std::string out;
    const auto add = [&](bool present, const char* name, const char* op) {
        if (!present)
            return;
        if (!out.empty())
            out += ',';
        out += name;
        out += '=';
        out += op;
    };
    add(f.store.has_value(), "store", "eq");
    add(f.scope.has_value(), "scope", "eq");
    add(f.key_alg_oid.has_value(), "key_alg_oid", "eq");
    add(f.sig_alg_oid.has_value(), "sig_alg_oid", "eq");
    add(f.ec_curve_oid.has_value(), "ec_curve_oid", "eq");
    add(f.not_after_before.has_value(), "not_after_before", "lt");
    add(f.not_after_after.has_value(), "not_after_after", "gt");
    add(f.not_before_after.has_value(), "not_before_after", "gt");
    add(f.rsa_modulus_bits_lt.has_value(), "rsa_modulus_bits_lt", "lt");
    add(f.ec_order_bits_lt.has_value(), "ec_order_bits_lt", "lt");
    add(f.is_ca.has_value(), "is_ca", "eq");
    add(f.self_signed.has_value(), "self_signed", "eq");
    add(f.agent_id.has_value(), "agent_id", "eq");
    add(f.issuer_dn.has_value(), "issuer_dn", "eq");
    add(f.issuer_dn_contains.has_value(), "issuer_dn_contains", "contains");
    add(f.subject_dn_contains.has_value(), "subject_dn_contains", "contains");
    add(f.sha256.has_value(), "sha256", "eq");
    add(f.spki_sha256.has_value(), "spki_sha256", "eq");
    add(f.aki_key_id.has_value(), "aki_key_id", "eq");
    return out.empty() ? std::string("none") : out;
}

std::string audit_detail(std::string_view cid, const CertReadFilter& f, std::size_t rows,
                         bool truncated, bool continuation, bool confined) {
    std::string d;
    if (!cid.empty())
        d += "cid=" + std::string(cid) + " ";
    d += std::string("scope=") + (confined ? "confined" : "fleet") + " rows=" +
         std::to_string(rows) + " truncated=" + (truncated ? "true" : "false") +
         " filters=" + filter_names(f);
    if (continuation)
        d += " page=continuation";
    return d;
}

std::string audit_detail_degraded(std::string_view cid, const CertReadFilter& f,
                                  CryptoReadCause cause, bool confined) {
    std::string d;
    if (!cid.empty())
        d += "cid=" + std::string(cid) + " ";
    d += std::string("scope=") + (confined ? "confined" : "fleet") + " filters=" + filter_names(f) +
         (cause == CryptoReadCause::kCapacity      ? " capacity in use"
          : cause == CryptoReadCause::kReconcileFailedTransient ? " reconcile failed (transient)"
          : cause == CryptoReadCause::kReconciling ? " reconciling"
                                                   : " store degraded");
    return d;
}

std::string_view degraded_message(CryptoReadCause cause) {
    return cause == CryptoReadCause::kCapacity      ? "crypto read capacity in use; retry"
           : cause == CryptoReadCause::kReconcileFailedTransient
               ? "certificate substring filters temporarily unavailable; retry later"
           : cause == CryptoReadCause::kReconciling ? "certificate substring filters reconciling; retry"
                                                    : "certificate inventory read degraded";
}

bool caller_priced_page(const CertReadFilter& f) {
    return f.store || f.key_alg_oid || f.sig_alg_oid || f.ec_curve_oid || f.not_after_before ||
           f.not_after_after || f.not_before_after || f.rsa_modulus_bits_lt || f.ec_order_bits_lt ||
           f.is_ca || f.self_signed || f.issuer_dn || f.issuer_dn_contains || f.subject_dn_contains ||
           f.spki_sha256 || f.aki_key_id;
}

std::string fleet_os_bucket(std::string_view reported_os) {
    if (reported_os == "windows" || reported_os == "linux" || reported_os == "darwin")
        return std::string(reported_os);
    return "other";
}

// ── D10 lint ─────────────────────────────────────────────────────────────────

namespace {
constexpr std::array<std::string_view, 14> kVerdictTokens = {
    "weak",   "strong",     "risk",     "score",    "expired", "expiring", "eol",
    "supported", "vulnerable", "pqc",   "quantum",  "safe",    "approved", "compliant"};

// True when any token of `key` (split on non-alphanumerics and lower-to-upper case changes, so
// snake_case, kebab-case and camelCase all split) is a verdict token.
bool key_is_verdict_shaped(const std::string& key) {
    std::string tok;
    bool hit = false;
    const auto flush = [&] {
        if (!tok.empty() &&
            std::ranges::find(kVerdictTokens, std::string_view(tok)) != kVerdictTokens.end())
            hit = true;
        tok.clear();
    };
    char prev = 0;
    for (const char c : key) {
        const auto u = static_cast<unsigned char>(c);
        if (!std::isalnum(u)) {
            flush();
        } else {
            if (std::islower(static_cast<unsigned char>(prev)) && std::isupper(u))
                flush();
            tok.push_back(static_cast<char>(std::tolower(u)));
        }
        prev = c;
    }
    flush();
    return hit;
}

void walk_keys(const Json& j, const std::string& path, std::vector<std::string>& out) {
    if (j.is_object()) {
        for (const auto& [k, v] : j.items()) {
            const std::string at = path.empty() ? k : path + "." + k;
            if (key_is_verdict_shaped(k))
                out.push_back(at);
            walk_keys(v, at, out);
        }
    } else if (j.is_array()) {
        for (const auto& e : j)
            walk_keys(e, path, out);
    }
}
} // namespace

std::span<const std::string_view> verdict_tokens() { return kVerdictTokens; }

std::vector<std::string> verdict_shaped_keys(const Json& j) {
    std::vector<std::string> out;
    walk_keys(j, "", out);
    return out;
}

} // namespace yuzu::server::cert_read
