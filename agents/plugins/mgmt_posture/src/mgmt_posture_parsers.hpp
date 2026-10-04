#pragma once

// mgmt_posture_parsers.hpp -- pure parsers and row formatters for the mgmt_posture
// plugin: which management plane controls the device. Header-only and portable so
// the unit tests run on every host; no file I/O, no subprocess, no OS header.
//
// Linux: SSSD active-domain classification (sssd.conf + conf.d merged view) and the
// IPA default.conf realm check. macOS: `profiles status -type enrollment`.
// The deciding domain name is kept in the struct for tests only: device_identity
// owns the domain / OU / joined rows and they are never re-emitted here.
//
// The `status|posture|...` row is NOT built here; the legs' report_posture owns it.

#include <yuzu/string_utils.hpp>

#include <algorithm>
#include <cctype>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::mgmt_posture {

enum class Plane { none, workgroup, ad, aad, hybrid, ipa, unknown };

/// `unknown` is emitted only on a refused read.
inline std::string_view plane_token(Plane p) {
    switch (p) {
    case Plane::none:
        return "none";
    case Plane::workgroup:
        return "workgroup";
    case Plane::ad:
        return "ad";
    case Plane::aad:
        return "aad";
    case Plane::hybrid:
        return "hybrid";
    case Plane::ipa:
        return "ipa";
    case Plane::unknown:
        return "unknown";
    }
    return "unknown";
}

namespace detail {

inline std::string trim(std::string_view s) {
    constexpr std::string_view ws = " \t\r\n";
    const auto b = s.find_first_not_of(ws);
    if (b == std::string_view::npos)
        return {};
    const auto e = s.find_last_not_of(ws);
    return std::string(s.substr(b, e - b + 1));
}

inline std::string lower(std::string_view s) {
    std::string out(s);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

} // namespace detail

// ---------------------------------------------------------------------------
// Minimal INI model
// ---------------------------------------------------------------------------

struct IniDoc {
    std::vector<std::string> section_order; ///< first-seen order
    std::map<std::string, std::map<std::string, std::string>> sections;
};

/// `[section]` headers, `key = value` (trimmed), `#` / `;` comment lines and blank
/// lines skipped, CRLF tolerated, never throws. LAST value wins for a repeated
/// (section, key) and a re-opened section merges: that is how SSSD merges
/// sssd.conf with conf.d/*.conf (snippets later in alphabetical order override), so
/// a caller concatenating main + snippets in that order gets the merged view.
inline IniDoc parse_ini(std::string_view text) {
    IniDoc doc;
    std::string current;
    bool in_section = false;
    size_t pos = 0;
    while (pos <= text.size()) {
        auto nl = text.find('\n', pos);
        if (nl == std::string_view::npos)
            nl = text.size();
        const std::string line = detail::trim(text.substr(pos, nl - pos));
        pos = nl + 1;
        if (line.empty() || line[0] == '#' || line[0] == ';')
            continue;
        if (line.front() == '[') {
            const auto close = line.find(']');
            if (close == std::string::npos) {
                in_section = false; // malformed header: ignore its keys
                continue;
            }
            current = detail::trim(std::string_view(line).substr(1, close - 1));
            in_section = true;
            if (!doc.sections.contains(current))
                doc.section_order.push_back(current);
            doc.sections[current]; // create
            continue;
        }
        const auto eq = line.find('=');
        if (!in_section || eq == std::string::npos)
            continue;
        const std::string key = detail::trim(std::string_view(line).substr(0, eq));
        if (key.empty())
            continue;
        doc.sections[current][key] = detail::trim(std::string_view(line).substr(eq + 1));
    }
    return doc;
}

// ---------------------------------------------------------------------------
// SSSD
// ---------------------------------------------------------------------------

struct SssdFacts {
    std::vector<std::string> active_domains;                    ///< query order
    std::map<std::string, std::string> id_provider_by_domain;   ///< lowercased
    bool domains_key_present = false; ///< false -> caller reports linux:mgmt_posture:sssd_conf:no_domains_key
};

namespace detail {

inline const std::string* find_key(const IniDoc& doc, const std::string& section,
                                   const std::string& key) {
    const auto s = doc.sections.find(section);
    if (s == doc.sections.end())
        return nullptr;
    const auto k = s->second.find(key);
    return k == s->second.end() ? nullptr : &k->second;
}

} // namespace detail

/// Declared domains are the `[domain/<name>]` sections. ACTIVE domains, in order: the
/// names in `[sssd] domains = a, b` that have a declared section and are not
/// `enabled = false`, then any declared domain with `enabled = true` not already
/// listed. With no `domains` key every declared domain not `enabled = false` is
/// active in file order. `id_provider` under `[sssd]` is meaningless and ignored.
inline SssdFacts sssd_facts(const IniDoc& doc) {
    constexpr std::string_view prefix = "domain/";
    SssdFacts f;

    std::vector<std::string> declared;
    for (const auto& sec : doc.section_order) {
        if (sec.size() <= prefix.size() || sec.compare(0, prefix.size(), prefix) != 0)
            continue;
        const std::string name = sec.substr(prefix.size());
        declared.push_back(name);
        if (const auto* p = detail::find_key(doc, sec, "id_provider"))
            f.id_provider_by_domain[name] = detail::lower(*p);
    }

    const auto enabled_of = [&](const std::string& name) -> std::optional<bool> {
        const auto* e = detail::find_key(doc, std::string(prefix) + name, "enabled");
        if (!e)
            return std::nullopt;
        const auto v = detail::lower(*e);
        if (v == "false")
            return false;
        if (v == "true")
            return true;
        return std::nullopt;
    };
    const auto is_declared = [&](const std::string& n) {
        return std::ranges::find(declared, n) != declared.end();
    };
    const auto is_active = [&](const std::string& n) {
        return std::ranges::find(f.active_domains, n) != f.active_domains.end();
    };

    const auto* list = detail::find_key(doc, "sssd", "domains");
    f.domains_key_present = list != nullptr;
    if (!list) {
        for (const auto& n : declared)
            if (enabled_of(n) != false)
                f.active_domains.push_back(n);
        return f;
    }

    std::string tok;
    const auto flush = [&] {
        if (!tok.empty() && is_declared(tok) && enabled_of(tok) != false && !is_active(tok))
            f.active_domains.push_back(tok);
        tok.clear();
    };
    for (char c : *list) {
        if (c == ',' || c == ' ' || c == '\t')
            flush();
        else
            tok += c;
    }
    flush();
    for (const auto& n : declared)
        if (enabled_of(n) == true && !is_active(n))
            f.active_domains.push_back(n);
    return f;
}

/// True when `[global]` has a non-empty `realm` (ipa-client-install's default.conf).
inline bool parse_ipa_default_conf_has_realm(const IniDoc& doc) {
    const auto* r = detail::find_key(doc, "global", "realm");
    return r && !r->empty();
}

/// First active domain (SSSD query order) whose id_provider is ad or ipa decides;
/// otherwise an ipa default.conf means ipa; otherwise none.
inline Plane classify_linux(const std::optional<SssdFacts>& sssd,
                                          bool ipa_default_conf_present) {
    if (sssd) {
        for (const auto& dom : sssd->active_domains) {
            const auto it = sssd->id_provider_by_domain.find(dom);
            if (it == sssd->id_provider_by_domain.end())
                continue;
            if (it->second == "ad")
                return Plane::ad;
            if (it->second == "ipa")
                return Plane::ipa;
        }
    }
    return ipa_default_conf_present ? Plane::ipa : Plane::none;
}

// ---------------------------------------------------------------------------
// macOS `profiles status -type enrollment`
// ---------------------------------------------------------------------------

struct ProfilesEnrollment {
    std::optional<bool> dep_enrolled;
    std::optional<bool> mdm_enrolled;
    std::string mdm_server_host; ///< host component only, never the path (may hold a token)

    bool recognised() const { return dep_enrolled || mdm_enrolled; }
};

namespace detail {

inline std::string url_host(std::string_view url) {
    if (const auto s = url.find("://"); s != std::string_view::npos)
        url.remove_prefix(s + 3);
    url = url.substr(0, url.find_first_of("/?#"));
    if (const auto at = url.rfind('@'); at != std::string_view::npos)
        url.remove_prefix(at + 1);
    if (!url.empty() && url.front() == '[') {
        const auto close = url.find(']');
        return std::string(url.substr(0, close == std::string_view::npos ? url.size() : close + 1));
    }
    return std::string(url.substr(0, url.find(':')));
}

} // namespace detail

inline ProfilesEnrollment parse_profiles_status(std::string_view text) {
    ProfilesEnrollment out;
    size_t pos = 0;
    while (pos <= text.size()) {
        auto nl = text.find('\n', pos);
        if (nl == std::string_view::npos)
            nl = text.size();
        const std::string_view line = text.substr(pos, nl - pos);
        pos = nl + 1;
        const auto colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        const auto key = detail::lower(detail::trim(line.substr(0, colon)));
        const auto val = detail::trim(line.substr(colon + 1));
        const auto lv = detail::lower(val);
        std::optional<bool> yn;
        if (lv.starts_with("yes"))
            yn = true;
        else if (lv.starts_with("no"))
            yn = false;

        if (key == "enrolled via dep" || key == "mdm enrollment") {
            if (!yn)
                continue;
            (key == "mdm enrollment" ? out.mdm_enrolled : out.dep_enrolled) = yn;
        } else if (key == "mdm server") {
            out.mdm_server_host = detail::url_host(val);
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Row formatters (DATA rows only; no status row)
// ---------------------------------------------------------------------------

enum class Presence { present, absent, unknown };

inline std::string posture_row(std::string_view key, std::string_view value) {
    std::string r(key);
    r += '|';
    r += yuzu::util::safe_output_field(value);
    return r;
}

namespace detail {
inline std::string_view bool_token(std::optional<bool> b) {
    return b ? (*b ? "true" : "false") : "-";
}
inline std::string_view or_dash(const std::string& s) { return s.empty() ? std::string_view("-") : std::string_view(s);
}
} // namespace detail

/// [plane, mdm_enrolled|-, mdm_provider|-, tenant_id|-, krb5_keytab]
inline std::vector<std::string> linux_rows(Plane plane, Presence keytab) {
    const std::string_view kt = keytab == Presence::present  ? "present"
                                : keytab == Presence::absent ? "absent"
                                                             : "-";
    return {posture_row("plane", plane_token(plane)), posture_row("mdm_enrolled", "-"),
            posture_row("mdm_provider", "-"), posture_row("tenant_id", "-"),
            posture_row("krb5_keytab", kt)};
}

/// [plane|-, mdm_enrolled, mdm_provider, tenant_id|-]. plane is `-` because AD binding
/// is device_identity's `domain` action and is never re-emitted here.
inline std::vector<std::string> macos_rows(const ProfilesEnrollment& p) {
    return {posture_row("plane", "-"),
            posture_row("mdm_enrolled", detail::bool_token(p.mdm_enrolled)),
            posture_row("mdm_provider", detail::or_dash(p.mdm_server_host)),
            posture_row("tenant_id", "-")};
}

} // namespace yuzu::mgmt_posture
