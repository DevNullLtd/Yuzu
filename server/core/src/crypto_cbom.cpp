#include "crypto_cbom.hpp"

#include "crypto_library_model.hpp"
#include "secure_random.hpp"

#include <yuzu/log_token.hpp>

#include <chrono>
#include <ctime>
#include <set>
#include <utility>

namespace yuzu::server::crypto_cbom {

namespace {

using nlohmann::json;
namespace cl = crypto_library;

constexpr char kHex[] = "0123456789abcdef";
constexpr char kPctHex[] = "0123456789ABCDEF"; // RFC 3986 percent-encoding is upper-case

// Percent-encode everything outside the unreserved set plus '+', byte-wise (UTF-8 safe).
std::string encode_segment(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (const unsigned char c : s) {
        const bool plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                           (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '~' ||
                           c == '+' || c == '-';
        if (plain) {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += kPctHex[c >> 4];
            out += kPctHex[c & 0x0F];
        }
    }
    return out;
}

json prop(std::string_view name, std::string value) {
    return json{{"name", std::string("yuzu:crypto:") + std::string(name)},
                {"value", std::move(value)}};
}

std::string boolean(bool b) { return b ? "true" : "false"; }

} // namespace

std::string uuid_urn_v4(std::array<std::uint8_t, 16> b) {
    b[6] = static_cast<std::uint8_t>((b[6] & 0x0F) | 0x40); // version 4
    b[8] = static_cast<std::uint8_t>((b[8] & 0x3F) | 0x80); // RFC 4122 variant
    std::string out = "urn:uuid:";
    for (std::size_t i = 0; i < b.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            out += '-';
        out += kHex[b[i] >> 4];
        out += kHex[b[i] & 0x0F];
    }
    return out;
}

std::string rfc3339_utc(std::int64_t epoch_seconds) {
    const std::time_t t = static_cast<std::time_t>(epoch_seconds);
    std::tm tm{};
#ifdef _WIN32
    const bool ok = static_cast<std::int64_t>(t) == epoch_seconds && gmtime_s(&tm, &t) == 0;
#else
    const bool ok = static_cast<std::int64_t>(t) == epoch_seconds && gmtime_r(&t, &tm) != nullptr;
#endif
    if (!ok)
        return "1970-01-01T00:00:00Z";
    char buf[32];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
        return "1970-01-01T00:00:00Z";
    return buf;
}

std::string audit_evidence(const CbomIdentity& id, const CryptoSummaryQuery& filters,
                           std::size_t components) {
    // `ecosystem=` only when the filter was given: a literal value can never be mistaken for
    // "no filter" (REST accepts free text, so no sentinel is safe).
    std::string out = " serial=" + ::yuzu::log_token(id.serial_number);
    if (filters.ecosystem)
        out += " ecosystem=" + ::yuzu::log_token(*filters.ecosystem);
    return out + " components=" + std::to_string(components);
}

void mark_audit_not_persisted(nlohmann::json& bom) {
    // Appended last, exactly where cbom_json puts it, so the result equals a document built
    // with `audit_persisted = false` (pinned by test_crypto_cbom.cpp) without a second build.
    bom.at("metadata").at("properties").push_back(prop("audit_persisted", "false"));
}

std::optional<CbomIdentity> make_identity(std::string_view tool_version) {
    std::array<std::uint8_t, 16> bytes{};
    if (!fill_random(bytes))
        return std::nullopt;
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    return CbomIdentity{uuid_urn_v4(bytes), rfc3339_utc(now), std::string(tool_version)};
}

json cbom_json(const CryptoSummary& s, const CbomIdentity& id, const CbomOptions& opts) {
    auto meta_props = json::array();
    meta_props.push_back(prop("table_version", std::to_string(cl::kCryptoTableVersion)));
    meta_props.push_back(prop("names_source", s.names_from_catalogue ? "catalogue" : "live"));
    // Live names have no refresh time: the property is absent, never a made-up zero.
    if (s.names_from_catalogue)
        meta_props.push_back(prop("names_as_of", std::to_string(s.names_as_of)));
    meta_props.push_back(prop("result_truncated", boolean(s.result_truncated)));
    std::string truncated_families;
    for (const auto& f : s.families)
        if (f.versions_truncated)
            truncated_families += (truncated_families.empty() ? "" : ",") + f.id;
    meta_props.push_back(prop("truncated_families", truncated_families));
    meta_props.push_back(
        prop("devices_reporting", std::to_string(s.coverage.devices_reporting_inventory)));
    meta_props.push_back(prop("devices_with_crypto_library",
                              std::to_string(s.coverage.devices_with_crypto_library)));
    meta_props.push_back(prop("filter_family", opts.filters.family.value_or("")));
    if (opts.filters.ecosystem)
        meta_props.push_back(prop("filter_ecosystem", *opts.filters.ecosystem));
    meta_props.push_back(prop("scope", opts.confined ? "confined" : "fleet"));
    meta_props.push_back(
        prop("evidence", "installed-package name match; presence and versions only, not judged"));
    if (!opts.audit_persisted)
        meta_props.push_back(prop("audit_persisted", "false"));

    auto components = json::array();
    std::set<std::string> refs;
    for (const auto& f : s.families) {
        const std::string display = f.display.empty() ? f.id : f.display;
        for (const auto& v : f.versions) {
            std::string ref = "yuzu-crypto-lib/" + encode_segment(f.id) + "/" +
                              encode_segment(v.version) + "/" + encode_segment(v.ecosystem);
            if (!refs.insert(ref).second) {
                for (int n = 2;; ++n) {
                    const std::string cand = ref + "#" + std::to_string(n);
                    if (refs.insert(cand).second) {
                        ref = cand;
                        break;
                    }
                }
            }
            auto props = json::array();
            props.push_back(prop("family_id", f.id));
            props.push_back(prop("ecosystem", v.ecosystem));
            props.push_back(prop("device_count", std::to_string(v.device_count)));
            props.push_back(prop("family_device_count", std::to_string(f.device_count)));
            props.push_back(prop("versions_truncated", boolean(f.versions_truncated)));
            props.push_back(prop("package_names_truncated", boolean(v.package_names_truncated)));
            for (const auto& n : v.package_names)
                props.push_back(prop("package_name", n));
            json c{{"type", "library"}, {"bom-ref", std::move(ref)}, {"name", display}};
            if (!v.version.empty())
                c["version"] = v.version;
            c["properties"] = std::move(props);
            components.push_back(std::move(c));
        }
    }

    return json{
        {"bomFormat", "CycloneDX"},
        {"specVersion", std::string(kSpecVersion)},
        {"serialNumber", id.serial_number},
        {"version", 1},
        {"metadata",
         {{"timestamp", id.timestamp},
          {"tools",
           {{"components",
             json::array({json{{"type", "application"},
                               {"name", "Yuzu"},
                               {"version", id.tool_version}}})}}},
          {"properties", std::move(meta_props)}}},
        {"components", std::move(components)},
        // A name match cannot see static / vendored / OS-bundled copies: incomplete by nature.
        {"compositions", json::array({json{{"aggregate", "incomplete"}}})}};
}

std::optional<std::string> strict_cbom_args_error(const nlohmann::json& args) {
    if (!args.is_object())
        return std::string(cl::kArgumentsNotObject);
    for (const auto& [k, v] : args.items()) {
        (void)v;
        if (k != "family" && k != "ecosystem")
            return "unknown argument (accepted: family, ecosystem)";
    }
    return cl::strict_summary_args_error(args);
}

} // namespace yuzu::server::crypto_cbom
