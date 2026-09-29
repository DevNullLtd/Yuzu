#pragma once

/**
 * antivirus_parsers.hpp — pure parse/render helpers for the antivirus plugin:
 * the XProtect definition-bundle version (PlistBuddy output) and the
 * system-extension registry (`systemextensionsctl list`) on macOS, the
 * Windows Security Center `productState` bit-decode and WMI row-to-output
 * mapping on Windows, and the Defender exclusion value-name-to-output
 * mapping shared by all three platforms' acquisition shells.
 *
 * Header-only and OS-free so the parsing/rendering is unit-tested on every
 * host (test_antivirus_parsers.cpp — the licensing_parsers.hpp pattern); the
 * subprocess/WMI/registry acquisition in antivirus_plugin.cpp is the impure
 * shell. In particular the WMI row type here is a plain
 * `std::map<std::string, std::string>` rather than
 * `yuzu::shared::wmi::WmiRow` (Windows-only) — same shape, but this header
 * must compile and its tests must run on every host, including the two
 * (Linux, macOS) that can never call real WMI.
 *
 * Honest-status invariant: empty, truncated, or unrecognised output parses
 * to empty/absent results — the caller reports `unknown`/`not_available`,
 * never a false-safe "active".
 */

#include <charconv>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::antivirus {

/// Parse PlistBuddy's `Print :CFBundleShortVersionString` output: on success
/// it is exactly the version token (e.g. "5351", "1.93"). Anything containing
/// whitespace, quotes, or colons is error text, not a version — returns an
/// empty view (the caller maps that to unknown). The returned view aliases
/// `out` and must not outlive it.
[[nodiscard]] constexpr std::string_view parse_plist_version(
    std::string_view out [[clang::lifetimebound]]) {
    // Trim surrounding whitespace/newlines.
    while (!out.empty() && (out.front() == ' ' || out.front() == '\t' || out.front() == '\n' ||
                            out.front() == '\r'))
        out.remove_prefix(1);
    while (!out.empty() && (out.back() == ' ' || out.back() == '\t' || out.back() == '\n' ||
                            out.back() == '\r'))
        out.remove_suffix(1);
    if (out.empty() || out.size() > 64)
        return {};
    for (char c : out) {
        if (c == ' ' || c == '\t' || c == ':' || c == '"' || c == ',')
            return {}; // error prose, not a version token
    }
    return out;
}

/// One row of `systemextensionsctl list`.
struct SysExtension {
    std::string category;  // section, e.g. "endpoint_security", "network_extension"
    std::string team_id;   // signing team identifier column
    std::string bundle_id; // e.g. "com.crowdstrike.falcon.Agent"
    std::string version;   // as printed, e.g. "7.16.0/101.98.5"
    std::string name;      // display-name column
    std::string state;     // bracket contents, e.g. "activated enabled"
    bool enabled{false};   // leading '*' in the enabled column
    bool active{false};    // '*' in the active column
};

/// Parse `systemextensionsctl list`. Format (verified live, macOS 26):
///   N extension(s)
///   --- com.apple.system_extension.<category> (Go to 'System Settings…')
///   enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
///   *\t*\tTEAMID\tcom.vendor.product (1.2.3/4.5)\tProduct Name\t[activated enabled]
/// Rows are tab-separated; the enabled/active cells hold '*' or are empty.
/// Malformed rows are skipped; empty/garbage input yields an empty vector.
[[nodiscard]] inline std::vector<SysExtension> parse_sysext_list(std::string_view out) {
    std::vector<SysExtension> exts;
    std::string category;
    size_t start = 0;
    while (start <= out.size()) {
        const auto nl = out.find('\n', start);
        std::string_view line =
            out.substr(start, nl == std::string_view::npos ? out.size() - start : nl - start);
        start = nl == std::string_view::npos ? out.size() + 1 : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        if (line.rfind("--- ", 0) == 0) {
            // "--- com.apple.system_extension.<category> (…)" — take the token
            // after "--- " up to the first space, then the part after its
            // last dot.
            auto token = line.substr(4);
            if (auto sp = token.find(' '); sp != std::string_view::npos)
                token = token.substr(0, sp);
            if (auto dot = token.rfind('.'); dot != std::string_view::npos)
                token = token.substr(dot + 1);
            category.assign(token);
            continue;
        }
        if (line.find('\t') == std::string_view::npos)
            continue; // count line, blank line, or prose
        if (line.rfind("enabled\t", 0) == 0)
            continue; // column-header line

        // Tab-split, keeping empty fields (a disabled row starts "\t\t…").
        std::vector<std::string_view> cols;
        size_t cstart = 0;
        while (true) {
            const auto tab = line.find('\t', cstart);
            cols.push_back(line.substr(
                cstart, tab == std::string_view::npos ? line.size() - cstart : tab - cstart));
            if (tab == std::string_view::npos)
                break;
            cstart = tab + 1;
        }
        if (cols.size() < 6)
            continue; // not a data row

        SysExtension ext;
        ext.category = category;
        ext.enabled = cols[0] == "*";
        ext.active = cols[1] == "*";
        ext.team_id.assign(cols[2]);
        std::string_view bundle = cols[3];
        if (auto paren = bundle.find(" ("); paren != std::string_view::npos) {
            ext.bundle_id.assign(bundle.substr(0, paren));
            auto ver = bundle.substr(paren + 2);
            if (!ver.empty() && ver.back() == ')')
                ver.remove_suffix(1);
            ext.version.assign(ver);
        } else {
            ext.bundle_id.assign(bundle);
        }
        ext.name.assign(cols[4]);
        std::string_view state = cols[5];
        if (!state.empty() && state.front() == '[')
            state.remove_prefix(1);
        if (!state.empty() && state.back() == ']')
            state.remove_suffix(1);
        ext.state.assign(state);
        exts.push_back(std::move(ext));
    }
    return exts;
}

/// EDR/AV products register endpoint-security system extensions.
[[nodiscard]] inline bool is_endpoint_security(const SysExtension& ext) {
    return ext.category == "endpoint_security";
}

/// Map an extension's registry state onto the products row vocabulary:
/// activated+enabled is running protection ("active"); anything else is
/// present but not protecting ("installed").
[[nodiscard]] inline std::string_view sysext_av_state(const SysExtension& ext) {
    return ext.enabled && ext.active ? "active" : "installed";
}

/// The wire format is pipe-delimited, one record per line. A sysext name,
/// bundle id, or version (vendor-controlled — the same registry a rogue
/// extension could spoof) containing '|', CR, or LF would shift/split fields
/// on the server-side positional parser, so neutralise those bytes to a
/// space before emitting (the processes_plugin.cpp sanitize_field pattern).
[[nodiscard]] inline std::string sanitize_field(std::string s) {
    for (char& c : s)
        if (c == '|' || c == '\n' || c == '\r')
            c = ' ';
    return s;
}

/// Case-insensitive substring test (ASCII), for de-duplicating the pgrep
/// fallback against products already reported via the extension registry.
[[nodiscard]] constexpr bool contains_insensitive(std::string_view hay, std::string_view needle) {
    if (needle.empty() || hay.size() < needle.size())
        return needle.empty();
    auto lower = [](char c) constexpr {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    };
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        size_t j = 0;
        while (j < needle.size() && lower(hay[i + j]) == lower(needle[j]))
            ++j;
        if (j == needle.size())
            return true;
    }
    return false;
}

// ── Windows Security Center productState decode ────────────────────────────

/// Decoded `AntiVirusProduct.productState` (root\SecurityCenter2), the
/// 32-bit value the WSC has used since Vista to pack a product's live
/// status. Undocumented by Microsoft, but the layout below is the one
/// consistently reverse-engineered and reused across the SCCM/PowerShell AV-
/// inventory community for over a decade: format the value as a 6-hex-digit
/// string; the middle byte (hex digits 3-4, i.e. `(state >> 8) & 0xFF`) is
/// the real-time-protection status, and the low byte (hex digits 5-6, i.e.
/// `state & 0xFF`) is the definitions-freshness status.
///
///   mid byte 0x10 -> protection on
///   mid byte 0x11 -> protection on, temporarily snoozed by the user
///   anything else -> protection off (0x00/0x01 are the common "off" codes;
///                    vendors are not required to use only those two)
///   low byte 0x00 -> definitions up to date
///   anything else -> definitions stale
///
/// This is a widely-corroborated convention, not an officially documented
/// Win32 contract — MEDIUM confidence, not the HIGH confidence a
/// header-published Microsoft struct would carry. It replaces the previous
/// behaviour of passing the raw decimal productState straight through to
/// the operator unparsed.
struct WscProductState {
    bool enabled = false;
    bool snoozed = false; // enabled, but the user has temporarily paused it
    bool definitions_up_to_date = false;
};

[[nodiscard]] constexpr WscProductState decode_wsc_product_state(std::uint32_t state) noexcept {
    WscProductState out;
    const std::uint32_t rtp_byte = (state >> 8) & 0xFFu;
    const std::uint32_t definitions_byte = state & 0xFFu;
    out.enabled = (rtp_byte == 0x10u || rtp_byte == 0x11u);
    out.snoozed = (rtp_byte == 0x11u);
    out.definitions_up_to_date = (definitions_byte == 0x00u);
    return out;
}

// ── Windows WMI row -> output-line rendering ────────────────────────────────

/// One row from `SELECT displayName, productState FROM AntiVirusProduct`
/// (root\SecurityCenter2), rendered to this plugin's `av|<name>|<state>|
/// <definitions>` wire line. A missing/empty displayName renders as
/// "unknown" rather than an empty field (a positional-field consumer must
/// never see a blank column); a missing or non-numeric productState renders
/// both trailing fields as "unknown" rather than guessing — the previous
/// raw-hex passthrough at least didn't lie, and this must not either.
[[nodiscard]] inline std::string render_wsc_product_line(
    const std::map<std::string, std::string>& row) {
    std::string name = "unknown";
    if (auto it = row.find("displayName"); it != row.end() && !it->second.empty())
        name = sanitize_field(it->second);

    const auto it = row.find("productState");
    if (it == row.end() || it->second.empty())
        return "av|" + name + "|unknown|unknown";

    std::uint32_t state = 0;
    const auto& s = it->second;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), state);
    if (ec != std::errc{} || ptr != s.data() + s.size())
        return "av|" + name + "|unknown|unknown"; // non-numeric productState: honest, not guessed

    const auto decoded = decode_wsc_product_state(state);
    return "av|" + name + "|" + (decoded.enabled ? (decoded.snoozed ? "snoozed" : "enabled")
                                                 : "disabled") +
           "|" + (decoded.definitions_up_to_date ? "current" : "stale");
}

/// Maps every row from the AntiVirusProduct query to its output line, in
/// order. An empty `rows` (genuinely zero registered products, distinct from
/// the caller's own "namespace didn't answer at all" handling) yields an
/// empty vector — the caller writes the `av_count|0` sentinel for that case.
[[nodiscard]] inline std::vector<std::string> render_wsc_products(
    const std::vector<std::map<std::string, std::string>>& rows) {
    std::vector<std::string> lines;
    lines.reserve(rows.size());
    for (const auto& row : rows)
        lines.push_back(render_wsc_product_line(row));
    return lines;
}

/// One MSFT_MpComputerStatus row (root\Microsoft\Windows\Defender) rendered
/// to this plugin's existing status keys — the same four keys the old
/// `Get-MpComputerStatus | Select-Object ... | Format-List` text parser
/// produced, just sourced from a WMI row instead of parsed prose. A key
/// absent from the row (a WMI provider need not populate every requested
/// property) is simply omitted from the output, exactly as the old parser
/// skipped a `Format-List` block it didn't recognise — never fabricated.
[[nodiscard]] inline std::vector<std::string> render_defender_status(
    const std::map<std::string, std::string>& row) {
    std::vector<std::string> lines;

    if (auto it = row.find("RealTimeProtectionEnabled"); it != row.end() && !it->second.empty()) {
        std::string v = it->second;
        for (char& c : v)
            c = static_cast<char>((c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c);
        const bool enabled = (v == "true" || v == "1");
        lines.push_back(std::string("realtime_protection|") + (enabled ? "enabled" : "disabled"));
    }
    if (auto it = row.find("AntivirusSignatureVersion"); it != row.end() && !it->second.empty())
        lines.push_back("definition_version|" + sanitize_field(it->second));
    if (auto it = row.find("AntivirusSignatureLastUpdated"); it != row.end() && !it->second.empty())
        lines.push_back("last_update|" + sanitize_field(it->second));
    if (auto it = row.find("QuickScanEndTime"); it != row.end() && !it->second.empty())
        lines.push_back("last_quick_scan|" + sanitize_field(it->second));

    return lines;
}

// ── Defender exclusion value-name rendering (Windows) ───────────────────────

/// Windows Defender stores each excluded path/process/extension AS a
/// registry VALUE NAME under `HKLM\SOFTWARE\Microsoft\Windows
/// Defender\Exclusions\{Paths,Processes,Extensions}` — the value's DATA is
/// unused (typically a stray 0 DWORD). `kind` is one of "path", "process",
/// "extension"; a value name is vendor/operator-controlled free text (a
/// filesystem path can legally contain almost anything), so it is
/// sanitized exactly like every other untrusted field this plugin emits.
///
/// One exclusion entry with a resolved provenance: "local" (the
/// operator-editable `...\Windows Defender\Exclusions\*` hive only),
/// "policy" (the GPO/MDM-managed `...\Policies\Microsoft\Windows
/// Defender\Exclusions\*` hive only — the dominant enterprise
/// configuration plane, and enforced regardless of the local hive), or
/// "both" (present in both — reported once, not twice).
struct ExclusionEntry {
    std::string value;
    std::string source;
};

/// Merge a kind's locally-configured and policy-managed value names into
/// one deduplicated, provenance-tagged list. A name present in both
/// sources is "both", never emitted as two separate rows — this is what
/// keeps `av_exclusions`'s count honest when GPO and local configuration
/// overlap.
[[nodiscard]] inline std::vector<ExclusionEntry> merge_exclusion_sources(
    const std::vector<std::string>& local_names, const std::vector<std::string>& policy_names) {
    std::map<std::string, std::string> by_value; // value -> source
    for (const auto& name : local_names)
        by_value[name] = "local";
    for (const auto& name : policy_names) {
        auto it = by_value.find(name);
        by_value[name] = (it != by_value.end()) ? "both" : "policy";
    }
    std::vector<ExclusionEntry> out;
    out.reserve(by_value.size());
    for (auto& [value, source] : by_value)
        out.push_back(ExclusionEntry{value, source});
    return out;
}

[[nodiscard]] inline std::vector<std::string> render_exclusion_lines(
    const std::vector<ExclusionEntry>& entries, std::string_view kind) {
    std::vector<std::string> lines;
    lines.reserve(entries.size());
    for (const auto& entry : entries)
        lines.push_back("exclusion|" + std::string(kind) + "|" + entry.source + "|" +
                        sanitize_field(entry.value));
    return lines;
}

} // namespace yuzu::antivirus
