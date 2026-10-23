#include "certificate_inventory_ingestion.hpp"

#include "agent.pb.h"
#include "utf8_sanitize.hpp" // sanitize_utf8_strict: rejects overlong/surrogate forms PG refuses

#include <yuzu/metrics.hpp>

#include <openssl/evp.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

namespace pb = ::yuzu::agent::v1;

constexpr const char* kSource = "certificate_inventory";
constexpr int kMaxSources = 64;

// ── Hashing and base64 ──────────────────────────────────────────────────────

std::string sha256_hex(std::string_view bytes) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return {};
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

// Strict standard-alphabet base64 with padding; nullopt on any defect.
std::optional<std::string> base64_decode(std::string_view in) {
    if (in.empty() || in.size() % 4 != 0)
        return std::nullopt;
    const auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z')
            return c - 'A';
        if (c >= 'a' && c <= 'z')
            return c - 'a' + 26;
        if (c >= '0' && c <= '9')
            return c - '0' + 52;
        if (c == '+')
            return 62;
        if (c == '/')
            return 63;
        return -1;
    };
    std::string out;
    out.reserve(in.size() / 4 * 3);
    for (std::size_t i = 0; i < in.size(); i += 4) {
        int v[4];
        int pad = 0;
        for (int k = 0; k < 4; ++k) {
            const char c = in[i + static_cast<std::size_t>(k)];
            if (c == '=') {
                // Padding only in the final quantum, last one or two positions.
                if (i + 4 != in.size() || k < 2)
                    return std::nullopt;
                v[k] = 0;
                ++pad;
            } else {
                if (pad > 0)
                    return std::nullopt;
                v[k] = val(c);
                if (v[k] < 0)
                    return std::nullopt;
            }
        }
        const std::uint32_t n = (static_cast<std::uint32_t>(v[0]) << 18) |
                                (static_cast<std::uint32_t>(v[1]) << 12) |
                                (static_cast<std::uint32_t>(v[2]) << 6) |
                                static_cast<std::uint32_t>(v[3]);
        out.push_back(static_cast<char>((n >> 16) & 0xff));
        if (pad < 2)
            out.push_back(static_cast<char>((n >> 8) & 0xff));
        if (pad < 1)
            out.push_back(static_cast<char>(n & 0xff));
    }
    return out;
}

// ── The record scanner ──────────────────────────────────────────────────────

// Stateful, left to right: each `\` is consumed together with the byte after it, so a delimiter
// is any `|` not consumed that way (`\\|` is an escaped backslash then a real delimiter).
// False on an unknown escape or a trailing unpaired `\`.
bool split_record(std::string_view rec, std::vector<std::string>& out) {
    out.clear();
    std::string cur;
    for (std::size_t i = 0; i < rec.size(); ++i) {
        const char c = rec[i];
        if (c == '\\') {
            if (i + 1 >= rec.size())
                return false;
            switch (rec[++i]) {
            case '\\':
                cur.push_back('\\');
                break;
            case '|':
                cur.push_back('|');
                break;
            case 'n':
                cur.push_back('\n');
                break;
            case 'r':
                cur.push_back('\r');
                break;
            default:
                return false;
            }
        } else if (c == '|') {
            out.push_back(std::move(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(std::move(cur));
    return true;
}

// ── Field validators ────────────────────────────────────────────────────────

bool is_hex(std::string_view s) {
    return !s.empty() && std::ranges::all_of(s, [](unsigned char c) { return std::isxdigit(c); });
}

std::string lower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string upper(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

bool is_oid(std::string_view s) {
    if (s.empty() || s.size() > 128 || s.front() == '.' || s.back() == '.')
        return false;
    bool prev_dot = false;
    for (char c : s) {
        if (c == '.') {
            if (prev_dot)
                return false;
            prev_dot = true;
        } else if (c >= '0' && c <= '9') {
            prev_dot = false;
        } else {
            return false;
        }
    }
    return true;
}

// `YYYY-MM-DDTHH:MM:SSZ`, a real calendar date.
bool is_rfc3339_utc_seconds(std::string_view s) {
    if (s.size() != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s[19] != 'Z')
        return false;
    const auto num = [&](std::size_t pos, std::size_t len, int& v) {
        v = 0;
        for (std::size_t i = pos; i < pos + len; ++i) {
            if (s[i] < '0' || s[i] > '9')
                return false;
            v = v * 10 + (s[i] - '0');
        }
        return true;
    };
    int y, mo, d, h, mi, se;
    if (!num(0, 4, y) || !num(5, 2, mo) || !num(8, 2, d) || !num(11, 2, h) || !num(14, 2, mi) ||
        !num(17, 2, se))
        return false;
    if (y < 1 || mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59)
        return false;
    static constexpr int kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int dim = kDays[mo - 1];
    if (mo == 2 && ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0))
        dim = 29;
    return d <= dim;
}

// A store reason: empty, or comma-joined tokens of [A-Za-z0-9_:.-], each at most 64 bytes
// (`open_failed:13`, `permission_denied`, `row_cap`, ...).
bool valid_reason(std::string_view r) {
    if (r.empty())
        return true;
    if (r.size() > 256)
        return false;
    std::size_t len = 0;
    for (char c : r) {
        if (c == ',') {
            if (len == 0)
                return false;
            len = 0;
            continue;
        }
        const unsigned char u = static_cast<unsigned char>(c);
        if (!(std::isalnum(u) || c == '_' || c == ':' || c == '.' || c == '-') || ++len > 64)
            return false;
    }
    return len > 0;
}

// ── The parser ──────────────────────────────────────────────────────────────

struct Group {
    bool open{false};
    bool bad{false};
    bool over_cap{false};
    std::string sha;
    CertFactRow fact;
    std::vector<std::pair<std::string, std::string>> locs; // store_id, path
    std::optional<std::size_t> want_sans, want_ekus, want_cdps;
};

class Parser {
public:
    CertBlobParse run(std::string_view blob) {
        if (blob.size() > kCertMaxBlobBytes) {
            out_.nack = CertBlobNack::kBlobTooLarge;
            return std::move(out_);
        }
        std::size_t pos = 0;
        bool saw_ver = false;
        std::vector<std::string> f;
        while (pos < blob.size()) {
            std::size_t end = blob.find('\n', pos);
            if (end == std::string_view::npos)
                end = blob.size();
            const std::string_view rec = blob.substr(pos, end - pos);
            pos = end + 1;
            if (rec.empty())
                continue;
            const bool scanned = split_record(rec, f);
            if (!saw_ver) {
                if (!scanned || f.size() < 2 || f[0] != "ver") {
                    out_.nack = CertBlobNack::kBadHeader;
                    return std::move(out_);
                }
                if (!parse_version(f[1]))
                    return std::move(out_);
                saw_ver = true;
                continue;
            }
            if (!scanned) {
                // The record cannot even be split, so its kind is unknown. A `store|` header
                // that will not scan nacks; anything else is an untied record.
                if (rec.starts_with("store|")) {
                    out_.nack = CertBlobNack::kBadHeader;
                    return std::move(out_);
                }
                refuse_untied(false);
                continue;
            }
            const std::string kind = f[0];
            if (kind == "store") {
                close_group();
                if (!parse_store(f))
                    return std::move(out_);
            } else if (kind == "cert") {
                close_group();
                if (out_.nack != CertBlobNack::kNone)
                    return std::move(out_);
                open_group(f);
            } else if (kind == "loc") {
                child_loc(f);
            } else if (kind == "san") {
                child_san(f);
            } else if (kind == "eku") {
                child_simple(f, true);
            } else if (kind == "cdp") {
                child_simple(f, false);
            } else if (kind == "der") {
                child_der(f);
            } // else: an unknown kind from a newer minor version: skipped.
            if (out_.nack != CertBlobNack::kNone)
                return std::move(out_);
        }
        if (!saw_ver) {
            out_.nack = CertBlobNack::kBadHeader;
            return std::move(out_);
        }
        close_group();
        if (out_.nack != CertBlobNack::kNone)
            return std::move(out_);
        if (out_.data.stores.empty()) { // never an empty blob: every store has a record
            out_.nack = CertBlobNack::kBadHeader;
            return std::move(out_);
        }
        finish();
        return std::move(out_);
    }

private:
    CertBlobParse out_;
    Group g_;
    std::map<std::string, std::size_t> store_index_;       // store_id -> out_.data.stores
    std::map<std::string, std::optional<std::size_t>> declared_; // declared cert_count
    std::map<std::string, std::set<std::string>> store_certs_;   // store_id -> distinct sha256
    std::unordered_map<std::string, std::size_t> fact_index_;    // sha256 -> out_.data.facts
    std::set<std::tuple<std::string, std::string, std::string>> seen_loc_;
    std::size_t der_total_{0};
    bool whole_report_error_{false};
    bool cap_hit_{false}; // the last failed clean() was a size cap, not a content defect

    bool parse_version(const std::string& v) {
        std::size_t dot = v.find('.');
        const std::string major = v.substr(0, dot);
        int m = -1;
        const auto r = std::from_chars(major.data(), major.data() + major.size(), m);
        if (major.empty() || r.ec != std::errc{} || r.ptr != major.data() + major.size()) {
            out_.nack = CertBlobNack::kBadHeader;
            return false;
        }
        if (m != 1) {
            out_.nack = CertBlobNack::kUnknownVersion;
            return false;
        }
        if (dot != std::string::npos) {
            const std::string minor = v.substr(dot + 1);
            if (minor.empty() || !std::ranges::all_of(minor, [](unsigned char c) {
                    return std::isdigit(c);
                })) {
                out_.nack = CertBlobNack::kBadHeader;
                return false;
            }
        }
        out_.data.blob_version = v;
        return true;
    }

    // Sanitise one text field. False (refuse) when over `cap` bytes after sanitising. A replaced
    // field is marked on the certificate and on the report.
    bool clean(const std::string& raw, std::size_t cap, std::string& out, const char* field,
               bool mark) {
        std::string s = sanitize_utf8_strict(raw);
        // PostgreSQL text cannot hold NUL, and neither can the libpq text protocol.
        if (s.find('\0') != std::string::npos) {
            std::string t;
            for (char c : s) {
                if (c == '\0')
                    t += "\xEF\xBF\xBD";
                else
                    t.push_back(c);
            }
            s = std::move(t);
        }
        if (s != raw) {
            out_.utf8_replaced = true;
            if (mark)
                add_token(std::string("utf8_replaced:") + field);
        }
        if (s.size() > cap) {
            cap_hit_ = true;
            return false;
        }
        out = std::move(s);
        return true;
    }

    void add_token(const std::string& t) {
        auto& cf = g_.fact.constrained_fields;
        if (!cf.empty())
            cf += ',';
        cf += t;
    }

    bool parse_store(const std::vector<std::string>& f) {
        // store|<store_id>|<scope>|<status>|<reason>|<cert_count>
        if (f.size() < 6) {
            out_.nack = CertBlobNack::kBadHeader;
            return false;
        }
        CertStoreReport s;
        std::string reason;
        if (!clean(f[1], 512, s.store_id, "store_id", false) || s.store_id.empty() ||
            !clean(f[4], 4096, reason, "reason", false)) {
            out_.nack = CertBlobNack::kBadHeader;
            return false;
        }
        s.scope = f[2];
        s.status = f[3];
        s.reason = std::move(reason);
        if (s.scope != "machine" ||
            (s.status != cert_status::kOk && s.status != cert_status::kAbsent &&
             s.status != cert_status::kUnreadable && s.status != cert_status::kConstrained) ||
            store_index_.contains(s.store_id)) {
            out_.nack = CertBlobNack::kBadHeader;
            return false;
        }
        std::optional<std::size_t> declared;
        if (f[5] != "?") {
            std::size_t n = 0;
            const auto r = std::from_chars(f[5].data(), f[5].data() + f[5].size(), n);
            if (f[5].empty() || r.ec != std::errc{} || r.ptr != f[5].data() + f[5].size()) {
                out_.nack = CertBlobNack::kBadHeader;
                return false;
            }
            declared = n;
        }
        if (out_.data.stores.size() >= kCertMaxStores) {
            out_.nack = CertBlobNack::kOverCap;
            return false;
        }
        // The reason is a comma-joined list of tokens stored verbatim (never a metric label), so
        // the writer can add tokens without a lockstep server change. Anything outside the
        // token charset is a parse error on this store, and the reason is not stored.
        const bool reason_ok = valid_reason(s.reason);
        if (!reason_ok)
            s.reason.clear();
        const std::string id = s.store_id;
        store_index_.emplace(id, out_.data.stores.size());
        declared_.emplace(id, declared);
        out_.data.stores.push_back(std::move(s));
        if (!reason_ok) {
            ++out_.refused_records;
            mark_store(id, "parse_error");
        }
        return true;
    }

    // `token` is the reason the store is constrained: "parse_error" for a defective record,
    // "row_cap" when a record was refused for a size cap (never labelled as a parse defect).
    void mark_store(const std::string& store_id, std::string_view token = "parse_error") {
        out_.any_parse_error = true;
        auto& s = out_.data.stores[store_index_.at(store_id)];
        if (s.status == cert_status::kUnreadable)
            return; // untouched whatever the defect: the more specific status stays
        if (s.status == cert_status::kConstrained) {
            if (s.reason.find(token) == std::string::npos)
                s.reason += (s.reason.empty() ? "" : ",") + std::string(token);
        } else {
            s.status = std::string(cert_status::kConstrained);
            s.reason = std::string(token);
        }
    }

    void refuse_untied(bool over_cap) {
        ++out_.refused_records;
        out_.any_parse_error = true;
        if (over_cap)
            out_.any_over_cap = true;
        whole_report_error_ = true;
    }

    // Refuse the current group; the stores its locations name read parse_error, and with no
    // location at all it cannot be tied to a store.
    void refuse_group(bool over_cap) {
        ++out_.refused_records;
        out_.any_parse_error = true;
        if (over_cap)
            out_.any_over_cap = true;
        bool tied = false;
        for (const auto& [store_id, path] : g_.locs) {
            if (store_index_.contains(store_id)) {
                mark_store(store_id, over_cap ? "row_cap" : "parse_error");
                tied = true;
            } else {
                whole_report_error_ = true;
            }
        }
        if (!tied)
            whole_report_error_ = true;
    }

    void open_group(const std::vector<std::string>& f) {
        g_ = Group{};
        g_.open = true;
        cap_hit_ = false;
        // Fields 0-10 are mandatory.
        if (f.size() < 12) {
            g_.bad = true;
            return;
        }
        const auto field = [&](std::size_t i) -> const std::string& { return f[i + 1]; };
        const auto has = [&](std::size_t i) { return f.size() > i + 1; };
        auto& c = g_.fact;

        const auto text = [&](std::size_t i, std::size_t cap, const char* name,
                              std::optional<std::string>& dst) -> bool {
            if (!has(i))
                return true;
            if (field(i) == "?")
                return true;
            std::string s;
            if (!clean(field(i), cap, s, name, true))
                return false;
            dst = std::move(s);
            return true;
        };
        const auto hexf = [&](std::size_t i, std::size_t len, std::optional<std::string>& dst,
                              bool to_upper = false) -> bool {
            if (!has(i) || field(i) == "?" || field(i).empty())
                return true;
            if (!is_hex(field(i)) || (len != 0 && field(i).size() != len) ||
                field(i).size() > 128)
                return false;
            dst = to_upper ? upper(field(i)) : lower(field(i));
            return true;
        };
        const auto oid = [&](std::size_t i, std::optional<std::string>& dst) -> bool {
            if (!has(i) || field(i) == "?" || field(i).empty())
                return true;
            if (!is_oid(field(i)))
                return false;
            dst = field(i);
            return true;
        };
        // `?` is "could not determine"; the typed column reads NULL either way, so the three fields
        // below whose unknown matters to a reader get a named token (empty = not applicable).
        const auto note_unknown = [&](std::size_t i, const char* name) {
            if (has(i) && field(i) == "?")
                add_token(std::string("unknown:") + name);
        };
        const auto integer = [&](std::size_t i, std::optional<int>& dst) -> bool {
            if (!has(i) || field(i) == "?" || field(i).empty())
                return true;
            int v = 0;
            const auto r = std::from_chars(field(i).data(), field(i).data() + field(i).size(), v);
            if (r.ec != std::errc{} || r.ptr != field(i).data() + field(i).size() || v < 0)
                return false;
            dst = v;
            return true;
        };
        const auto boolean = [&](std::size_t i, std::optional<bool>& dst) -> bool {
            if (!has(i) || field(i) == "?" || field(i).empty())
                return true;
            if (field(i) == "1" || field(i) == "true")
                dst = true;
            else if (field(i) == "0" || field(i) == "false")
                dst = false;
            else
                return false;
            return true;
        };
        const auto date = [&](std::size_t i, std::optional<std::string>& dst) -> bool {
            if (!has(i) || field(i) == "?" || field(i).empty())
                return true;
            if (!is_rfc3339_utc_seconds(field(i)))
                return false;
            dst = field(i);
            return true;
        };
        const auto count = [&](std::size_t i, const char* key,
                               std::optional<std::size_t>& dst) -> bool {
            if (!has(i))
                return true;
            const std::string prefix = std::string(key) + "=";
            if (!field(i).starts_with(prefix))
                return false;
            std::size_t n = 0;
            const char* b = field(i).data() + prefix.size();
            const char* e = field(i).data() + field(i).size();
            const auto r = std::from_chars(b, e, n);
            if (b == e || r.ec != std::errc{} || r.ptr != e)
                return false;
            dst = n;
            return true;
        };

        // sha256 is the row identity: it must be valid or nothing can be tied to this record.
        if (!is_hex(field(0)) || field(0).size() != 64) {
            g_.bad = true;
            return;
        }
        g_.sha = lower(field(0));
        c.sha256 = g_.sha;
        bool ok = hexf(1, 40, c.sha1) && hexf(2, 64, c.tbs_sha256) && integer(3, c.version) &&
                  hexf(4, 0, c.serial, true) &&
                  text(5, kCertMaxDnBytes, "subject_dn", c.subject_dn) &&
                  text(6, kCertMaxDnBytes, "issuer_dn", c.issuer_dn) &&
                  hexf(7, 64, c.subject_name_sha256) && hexf(8, 64, c.issuer_name_sha256) &&
                  date(9, c.not_before) && date(10, c.not_after) && oid(11, c.key_alg_oid) &&
                  integer(12, c.rsa_modulus_bits) && oid(13, c.ec_curve_oid) &&
                  integer(14, c.ec_order_bits) && oid(15, c.sig_alg_oid) &&
                  oid(16, c.pss_hash_oid) && oid(17, c.pss_mgf1_hash_oid) &&
                  hexf(18, 64, c.spki_sha256) && hexf(19, 0, c.ski, true) &&
                  hexf(20, 0, c.aki_key_id, true) && boolean(21, c.is_ca) &&
                  integer(22, c.path_len) && text(23, 256, "key_usage", c.key_usage) &&
                  boolean(24, c.self_signed) && text(25, 32, "key_association", c.key_association) &&
                  text(26, 256, "key_provider", c.key_provider) &&
                  text(27, 32, "key_exportable", c.key_exportable) &&
                  count(28, "sans", g_.want_sans) && count(29, "ekus", g_.want_ekus) &&
                  count(30, "cdps", g_.want_cdps) && text(31, 32, "der_omitted", c.der_omitted);
        if (ok && c.key_association && *c.key_association != "present" &&
            *c.key_association != "none" && *c.key_association != "unknown")
            ok = false;
        if (ok && c.der_omitted && !c.der_omitted->empty() && *c.der_omitted != "self_signed" &&
            *c.der_omitted != "oversize" && *c.der_omitted != "budget")
            ok = false;
        // flags: the agent's comma-joined tokens. They are kept verbatim in constrained_fields,
        // merged with the tokens this parse added; serial_negative is also a column.
        if (ok) {
            note_unknown(21, "is_ca");
            note_unknown(22, "path_len");
            note_unknown(24, "self_signed");
        }
        if (ok && has(32) && field(32) == "?") {
            add_token("flags_unknown"); // the writer could not determine its flags
        } else if (ok && has(32) && !field(32).empty()) {
            std::string s;
            if (!clean(field(32), 512, s, "flags", false))
                ok = false;
            else {
                c.serial_negative = (("," + s + ",").find(",serial_negative,") != std::string::npos);
                if (!g_.fact.constrained_fields.empty())
                    s += "," + g_.fact.constrained_fields;
                g_.fact.constrained_fields = std::move(s);
            }
        } else if (ok && has(32)) {
            c.serial_negative = false;
        }
        if (!ok) {
            g_.bad = true;
            g_.over_cap = cap_hit_;
        }
    }

    void child_loc(const std::vector<std::string>& f) {
        // loc|<sha256>|<store_id>|<path>
        if (!g_.open || f.size() < 4 || lower(f[1]) != g_.sha) {
            refuse_stray_child(f.size() >= 3 ? &f[2] : nullptr);
            return;
        }
        std::string store_id, path;
        if (!clean(f[2], 512, store_id, "store_id", false) ||
            !clean(f[3], 4096, path, "path", false)) {
            g_.bad = true;
            return;
        }
        g_.locs.emplace_back(std::move(store_id), std::move(path));
    }

    void child_san(const std::vector<std::string>& f) {
        if (!g_.open || f.size() < 4 || lower(f[1]) != g_.sha) {
            refuse_stray_child(nullptr);
            return;
        }
        static const std::set<std::string> kTypes = {"dns", "ip",  "rfc822",
                                                     "uri", "upn", "dirname", "other"};
        CertSan san;
        san.type = f[2];
        if (g_.bad)
            return;
        const bool type_ok = kTypes.contains(san.type);
        const bool count_over = g_.fact.sans.size() >= kCertMaxSans;
        if (!type_ok || count_over || !clean(f[3], kCertMaxSanBytes, san.value, "san", true)) {
            g_.bad = true;
            g_.over_cap = g_.over_cap || type_ok; // a bad type is a defect; the rest are caps
            return;
        }
        g_.fact.sans.push_back(std::move(san));
    }

    void child_simple(const std::vector<std::string>& f, bool eku) {
        if (!g_.open || f.size() < 3 || lower(f[1]) != g_.sha) {
            refuse_stray_child(nullptr);
            return;
        }
        if (g_.bad)
            return;
        auto& list = eku ? g_.fact.ekus : g_.fact.cdps;
        const std::size_t cap = eku ? kCertMaxEkus : kCertMaxCdps;
        std::string v;
        if (list.size() >= cap) {
            g_.bad = true;
            g_.over_cap = true;
            return;
        }
        if (eku ? !is_oid(f[2]) : !clean(f[2], kCertMaxCdpBytes, v, "cdp", true)) {
            g_.bad = true;
            g_.over_cap = g_.over_cap || !eku; // an over-long URI is a cap; a bad OID a defect
            return;
        }
        list.push_back(eku ? f[2] : std::move(v));
    }

    void child_der(const std::vector<std::string>& f) {
        if (!g_.open || f.size() < 3 || lower(f[1]) != g_.sha) {
            refuse_stray_child(nullptr);
            return;
        }
        if (g_.bad)
            return;
        auto der = base64_decode(f[2]);
        if (!der || g_.fact.der_base64) {
            g_.bad = true;
            return;
        }
        if (der->size() > kCertMaxDerBytes || der_total_ + der->size() > kCertMaxDerPerBlob) {
            g_.bad = true;
            g_.over_cap = true;
            return;
        }
        // The row identity is the SHA-256 of the whole DER: a DER that does not hash to it is
        // dropped (and the certificate marked), never stored under the wrong identity.
        if (sha256_hex(*der) != g_.sha) {
            add_token("der_hash_mismatch"); // keep the certificate, never store this DER
            out_.der_hash_mismatch = true;
            return;
        }
        der_total_ += der->size();
        g_.fact.der_base64 = f[2];
    }

    // A child record that is not in a matching group. It cannot be tied to a certificate; when
    // it names a known store only that store is marked, otherwise the whole report falls back.
    void refuse_stray_child(const std::string* maybe_store) {
        ++out_.refused_records;
        out_.any_parse_error = true;
        if (maybe_store != nullptr) {
            std::string s;
            if (clean(*maybe_store, 512, s, "store_id", false) && store_index_.contains(s)) {
                mark_store(s);
                return;
            }
        }
        whole_report_error_ = true;
    }

    void close_group() {
        if (!g_.open)
            return;
        Group g = std::move(g_);
        g_ = Group{};
        if (g.bad) {
            g_ = std::move(g);
            refuse_group(g_.over_cap);
            g_ = Group{};
            return;
        }
        if ((g.want_sans && *g.want_sans != g.fact.sans.size()) ||
            (g.want_ekus && *g.want_ekus != g.fact.ekus.size()) ||
            (g.want_cdps && *g.want_cdps != g.fact.cdps.size())) {
            g_ = std::move(g);
            refuse_group(false);
            g_ = Group{};
            return;
        }
        if (g.locs.empty()) {
            g_ = std::move(g);
            refuse_group(false);
            g_ = Group{};
            return;
        }
        // Distinct certificates in the blob.
        const bool known = fact_index_.contains(g.sha);
        if (!known && fact_index_.size() >= kCertMaxDistinctCerts) {
            out_.nack = CertBlobNack::kOverCap;
            return;
        }
        bool any_live = false;
        for (const auto& [store_id, path] : g.locs) {
            const auto it = store_index_.find(store_id);
            if (it == store_index_.end()) {
                // A location in a store the headers never named.
                ++out_.refused_records;
                out_.any_parse_error = true;
                whole_report_error_ = true;
                continue;
            }
            auto& s = out_.data.stores[it->second];
            if (s.status == cert_status::kUnreadable)
                continue; // the store could not be read; its rows are untouched
            if (s.status == cert_status::kAbsent) {
                // A certificate in a store the agent says does not exist.
                ++out_.refused_records;
                mark_store(store_id);
                continue;
            }
            auto& certs = store_certs_[store_id];
            if (!certs.contains(g.sha) && certs.size() >= kCertMaxCertsPerStore) {
                ++out_.refused_records;
                out_.any_over_cap = true;
                mark_store(store_id, "row_cap");
                continue;
            }
            certs.insert(g.sha);
            if (seen_loc_.emplace(store_id, path, g.sha).second)
                out_.data.locations.push_back({store_id, path, g.sha});
            any_live = true;
        }
        if (any_live && !known) {
            fact_index_.emplace(g.sha, out_.data.facts.size());
            out_.data.facts.push_back(std::move(g.fact));
        }
    }

    void finish() {
        // A store that reads ok must carry exactly the certificates its header declared.
        for (auto& s : out_.data.stores) {
            if (s.status != cert_status::kOk)
                continue;
            const auto d = declared_.at(s.store_id);
            if (d && *d != store_certs_[s.store_id].size()) {
                ++out_.refused_records;
                mark_store(s.store_id);
            }
        }
        if (whole_report_error_) {
            out_.any_parse_error = true;
            for (const auto& s : out_.data.stores)
                mark_store(s.store_id);
        }
    }
};

} // namespace

CertBlobParse parse_certificate_inventory_blob(std::string_view blob) {
    return Parser{}.run(blob);
}

std::string certificate_inventory_raw_hash(std::string_view blob) { return sha256_hex(blob); }

void cert_ingest_metric::register_metrics(::yuzu::MetricsRegistry& metrics) {
    metrics.describe(std::string(kName),
                     "Certificate-inventory daily-sync ingest outcomes by result (stored, touched, "
                     "need_full, rejected, deferred, error) and a closed reason set",
                     "counter");
    for (const auto& [result, reason] : kPairs)
        metrics.counter(std::string(kName),
                        {{"result", std::string(result)}, {"reason", std::string(reason)}});
}

void cert_ingest_metric::count_exception(::yuzu::MetricsRegistry* metrics) {
    if (!metrics)
        return;
    metrics
        ->counter(std::string(kName), {{"result", "error"}, {"reason", "exception"}})
        .increment();
    metrics->counter("yuzu_inventory_ingest_total", {{"source", kSource}, {"outcome", "error"}})
        .increment();
}

void cert_ingest_metric::handle_exception(const pb::InventoryReport& report, pb::InventoryAck& ack,
                                          ::yuzu::MetricsRegistry* metrics) {
    count_exception(metrics);
    if (report.plugin_data().find(kSource) != report.plugin_data().end())
        ack.add_need_full(kSource);
}

void ingest_certificate_inventory_report(CertificateInventoryStore& store,
                                         const std::string& agent_id, const pb::InventoryReport& report,
                                         pb::InventoryAck& ack, ::yuzu::MetricsRegistry* metrics) {
    // The source's own counter, plus the generic per-source family every typed source shares
    // (yuzu_inventory_ingest_total / _duration_seconds), so the pool alerts can attribute load.
    const auto emit = [&](std::string_view result, std::string_view reason) {
        if (!metrics)
            return;
        metrics
            ->counter(std::string(cert_ingest_metric::kName),
                      {{"result", std::string(result)}, {"reason", std::string(reason)}})
            .increment();
        // Map onto the generic family's EXISTING vocabulary so the shipped alerts and runbooks
        // mean what they say: an over-cap/unknown/malformed blob is `dropped` (the over-cap
        // blob alert), only a >64-source report is `rejected` (the report-rejected alert), and
        // a bad claim is `need_full` like the siblings' mismatch. `deferred` is this source's
        // own (described in server.cpp); it is a busy-lock deferral, not a failure.
        const char* outcome = result == "stored"      ? "stored"
                              : result == "touched"   ? "touched"
                              : result == "need_full" ? "need_full"
                              : result == "deferred"  ? "deferred"
                              : result == "rejected"  ? (reason == "too_many_sources" ? "rejected" : "dropped")
                                                      : "error";
        metrics
            ->counter("yuzu_inventory_ingest_total",
                      {{"source", kSource}, {"outcome", outcome}})
            .increment();
    };
    const auto observe = [&](const char* phase, std::chrono::steady_clock::time_point t0) {
        if (metrics)
            metrics
                ->histogram("yuzu_inventory_ingest_duration_seconds",
                            {{"source", kSource}, {"phase", phase}},
                            yuzu::Histogram::seconds_buckets_60s())
                .observe(std::chrono::duration<double>(std::chrono::steady_clock::now() - t0)
                             .count());
    };
    const auto need_full = [&] { ack.add_need_full(kSource); };
    // A refusal that would repeat byte-for-byte (too large, unknown version, bad header, over a
    // cap) is a TERMINAL acknowledgement, not a need_full: asking for the same bytes again would
    // loop the agent. It is counted, and the agent's next cycle starts cold.
    const auto reject = [&](std::string_view reason) { emit("rejected", reason); };
    if (agent_id.empty())
        return;
    if (report.content_hashes_size() > kMaxSources || report.plugin_data_size() > kMaxSources) {
        spdlog::warn("certificate_inventory: report from agent={} carries too many sources "
                     "(hashes={}, blobs={}, cap={}) — skipping",
                     agent_id, report.content_hashes_size(), report.plugin_data_size(),
                     kMaxSources);
        reject("too_many_sources");
        return;
    }
    const auto hit = report.content_hashes().find(kSource);
    if (hit == report.content_hashes().end())
        return; // not due this cycle
    const std::string& claimed_hash = hit->second;

    // `hash_only`: a hash-skip leg. Its failures do NOT ask for a full resend (that would turn a
    // transient store error into a 3 MiB upload); the agent simply retries the hash next cycle.
    const auto map_result = [&](const CertIngestResult& r, std::string_view stored_reason,
                                bool hash_only) {
        switch (r.outcome) {
        case CertIngestOutcome::kStored:
            emit("stored", stored_reason);
            return;
        case CertIngestOutcome::kTouched:
            emit("touched", "none");
            return;
        case CertIngestOutcome::kNeedFull:
            need_full();
            emit("need_full", r.need_full_cause == CertNeedFullCause::kCold ? "cold"
                                                                            : "hash_mismatch");
            return;
        case CertIngestOutcome::kBudgetExceeded:
            // Terminal ack: the same report would exceed again at once; the agent's next
            // interval starts cold (hash-only -> need_full -> one resend per interval).
            emit("error", "budget_exceeded");
            return;
        case CertIngestOutcome::kBusy:
            if (!hash_only)
                need_full();
            emit("deferred", "agent_busy");
            return;
        case CertIngestOutcome::kError:
            if (!hash_only)
                need_full();
            emit("error", "store_error");
            return;
        }
    };

    const auto bit = report.plugin_data().find(kSource);
    if (bit == report.plugin_data().end()) {
        // A claim that is not exactly 64 lowercase hex characters (empty included) can never
        // equal a stored hash, so it is answered need_full here and never reaches the store: no
        // agent claim may equal a stored sentinel (an empty stored hash means "pruned").
        if (claimed_hash.size() != 64 ||
            !std::ranges::all_of(claimed_hash, [](unsigned char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            })) {
            need_full();
            emit("need_full", "bad_claim");
            return;
        }
        // Hash-only leg: compare and touch inside the store's per-agent transaction.
        const auto t0 = std::chrono::steady_clock::now();
        const auto r = store.ingest_touch(agent_id, claimed_hash);
        observe("hash_only", t0);
        map_result(r, "none", /*hash_only=*/true);
        return;
    }

    // Full payload.
    const std::string& blob = bit->second;
    const std::string raw_hash = certificate_inventory_raw_hash(blob);
    if (raw_hash.empty()) {
        spdlog::warn("certificate_inventory: SHA-256 digest failed for agent={} — nacking",
                     agent_id);
        need_full();
        emit("error", "digest_error");
        return;
    }
    CertBlobParse parsed = parse_certificate_inventory_blob(blob);
    if (parsed.nack != CertBlobNack::kNone) {
        spdlog::warn("certificate_inventory: blob from agent={} refused (reason {}) — "
                     "acknowledged, not stored",
                     agent_id, static_cast<int>(parsed.nack));
        switch (parsed.nack) {
        case CertBlobNack::kBlobTooLarge:
            reject("blob_too_large");
            break;
        case CertBlobNack::kUnknownVersion:
            reject("unknown_version");
            break;
        case CertBlobNack::kOverCap:
            reject("over_cap");
            break;
        default:
            reject("bad_header");
            break;
        }
        return;
    }
    std::string_view stored_reason = "none";
    if (parsed.any_over_cap)
        stored_reason = "over_cap";
    else if (parsed.any_parse_error)
        stored_reason = "parse_error";
    else if (parsed.der_hash_mismatch)
        stored_reason = "der_hash_mismatch";
    else if (parsed.utf8_replaced)
        stored_reason = "utf8_replaced";
    if (parsed.any_parse_error)
        spdlog::warn("certificate_inventory: agent={} report stored with {} refused record(s)",
                     agent_id, parsed.refused_records);
    const auto t0 = std::chrono::steady_clock::now();
    const auto r = store.ingest_full(agent_id, parsed.data, raw_hash);
    observe("full", t0);
    map_result(r, stored_reason, /*hash_only=*/false);
}

} // namespace yuzu::server
