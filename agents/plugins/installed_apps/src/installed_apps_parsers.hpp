#pragma once

// installed_apps_parsers.hpp -- pure parse helpers for the `list`/`query`/
// `list_per_user` acquisition legs of installed_apps_plugin.cpp (the
// `list_inventory` v2-row parsers already live in installed_apps_inventory.hpp
// and are unchanged by this header).
//
// Header-only and OS-free so every parser here is fixture-tested on any host
// (the firewall_parsers.hpp / netprobe_stats.hpp pattern) -- the plugin's own
// run_bounded_subprocess acquisition is the impure shell; this header only
// ever sees an already-captured output blob.
//
// Wave 4 PR4.3a de-shells the Linux dpkg/rpm/pacman '|'-format line parsers
// (previously inline istringstream loops in installed_apps_plugin.cpp), the
// macOS `system_profiler SPApplicationsDataType -detailLevel mini` text
// parse (previously piped through `| grep` before reaching C++), the macOS
// `brew list --versions` line parse, and adds the #2273 macOS enrichment
// acquisition's own pure parsers (`pkgutil --pkgs` id list, `pkgutil
// --pkg-info <id>` version/install-time extraction).

#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <subprocess_degradation.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field

namespace yuzu::installed_apps::parsers {

// Re-exported from the shared header (agents/shared/subprocess_degradation.hpp)
// so this namespace's own callers and its existing unit test
// (test_installed_apps_parsers.cpp, `using namespace ...parsers`) are
// unaffected by the extraction -- see that header for the full rationale and
// the Gate-8 finding that prompted moving the canonical definition out of
// this plugin.
using yuzu::shared::is_degraded_run;

// Mirrors installed_apps_plugin.cpp's AppInfo shape (an alias of AppRowFields
// below), plus one parser-side field: `location` (macOS system_profiler's "Location:"
// line -- the app bundle's absolute path). As of ADR-0028's binding condition
// `location` is emitted as the `list` action's trailing `install_location`
// column (format_app_row below); it is still NOT part of the ADR-0016
// InvRecord (installed_apps_inventory.hpp), where it only feeds the #2273
// native CFBundle/SecStaticCode enrichment in installed_apps_macos_enrich.hpp.
// The `query` and `list_per_user` wire formats do not carry it. Honest-empty
// when the source format doesn't carry a given field (matches
// installed_apps_inventory.hpp's own convention) -- never synthesised by the
// parsers that read a source without one (format_app_row applies the "-" display
// convention at format time; parse_dpkg_list writes "-" for install_date and
// parse_rpm_list maps a "(none)" publisher to "-" themselves, where dpkg/rpm
// report none).
struct AppRecord {
    std::string name;
    std::string version;
    std::string publisher;
    std::string install_date;
    std::string location;
};

namespace detail {

inline void strip_trailing_cr(std::string& line) {
    if (!line.empty() && line.back() == '\r')
        line.pop_back();
}

// Value half of a `Key: value` system_profiler line, given the already-trimmed
// line. Returns empty for a valueless key ("Version:", "Location:") instead of
// running off the end: `string_view::substr` THROWS std::out_of_range once the
// offset passes size(), and a bare key makes `colon + 2` exactly size() + 1.
// system_profiler omits the key entirely rather than emitting a valueless one
// on the hosts checked, so this is a latent rather than live crash -- but it is
// reachable from parser input, and this header's sibling parsers promise
// "malformed/empty input yields an all-empty result, never a crash".
[[nodiscard]] inline std::string_view value_after_colon(std::string_view trimmed) {
    const auto colon = trimmed.find(':');
    if (colon == std::string_view::npos)
        return {};
    auto pos = colon + 1;
    while (pos < trimmed.size() && (trimmed[pos] == ' ' || trimmed[pos] == '\t'))
        ++pos;
    return trimmed.substr(pos);
}

} // namespace detail

// ── Linux: dpkg-query ───────────────────────────────────────────────────────

// One line of `dpkg-query -W -f='${Package}|${Version}|${Maintainer}|${Status}\n'`
// (the `\n` here is the LITERAL two-byte escape dpkg-query's own format-string
// interpreter expands -- see the plugin's argv construction comment). Only
// fully-installed packages are kept ("install ok installed"), matching the
// legacy shell-out this replaces exactly.
[[nodiscard]] inline std::vector<AppRecord> parse_dpkg_list(std::string_view output) {
    std::vector<AppRecord> apps;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        if (line.find("install ok installed") == std::string::npos)
            continue;
        std::istringstream ls(line);
        std::string name, version, publisher;
        std::getline(ls, name, '|');
        std::getline(ls, version, '|');
        std::getline(ls, publisher, '|');
        apps.push_back(AppRecord{std::move(name), std::move(version), std::move(publisher),
                                 "-", {}});
    }
    return apps;
}

// ── Linux: rpm ───────────────────────────────────────────────────────────

// One line of `rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}|%{VENDOR}|%{INSTALLTIME:date}\n'`.
[[nodiscard]] inline std::vector<AppRecord> parse_rpm_list(std::string_view output) {
    std::vector<AppRecord> apps;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        std::istringstream ls(line);
        std::string name, version, publisher, date;
        std::getline(ls, name, '|');
        std::getline(ls, version, '|');
        std::getline(ls, publisher, '|');
        std::getline(ls, date, '|');
        if (publisher == "(none)")
            publisher = "-";
        apps.push_back(AppRecord{std::move(name), std::move(version), std::move(publisher),
                                 std::move(date), {}});
    }
    return apps;
}

// ── Linux: pacman ───────────────────────────────────────────────────────

// One line of `pacman -Q` output: "name version".
[[nodiscard]] inline std::vector<AppRecord> parse_pacman_list(std::string_view output) {
    std::vector<AppRecord> apps;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        const auto sp = line.find(' ');
        if (sp != std::string::npos) {
            apps.push_back(
                AppRecord{line.substr(0, sp), line.substr(sp + 1), {}, {}, {}});
        }
    }
    return apps;
}

// ── macOS: system_profiler SPApplicationsDataType -detailLevel mini ──────

// Parses the RAW (un-grepped) mini-detail text block. The legacy shell-out
// piped this through
// `grep -E '^ {4}\w|Version:|Last Modified:'` before any C++ ever saw it;
// with that shell stage gone (rung 2: clean argv, no pipe), this function
// replicates that three-way selection in-process. `query`'s emitted rows are
// byte-identical to before FOR EVERY APP THE OLD GREP ADMITTED, and `list`'s are
// too for every value within the 4 KiB field bound and free of `\`, `|`, CR, LF
// and NUL (format_app_row now escapes and bounds every field), with TWO
// deliberate, documented deviations:
//   (1) the header-character WIDENING described below -- additive only;
//   (2) the header-BEFORE-attribute branch order (see the ordering comment in
//       the loop): an app named "Location"/"Version"/"Last Modified" is now
//       its own row instead of being swallowed as an attribute of the app
//       above it. That also changes the PRECEDING app's version/location back
//       to its own correct values, so unlike (1) it is not purely additive --
//       it is a correctness fix for a row that was previously wrong.
//   - a line with EXACTLY 4 leading spaces then a non-space, non-tab
//     character is an app-name header (e.g. "    Keynote:") -- ANY other
//     indent (0, the top-level "Applications:" line; 6, an attribute line)
//     is not a header.
//     WIDENING (Wave 4 PR4.3a): the old grep's `\w` is [A-Za-z0-9_] in the C
//     locale, so it silently DROPPED any app whose name begins with
//     punctuation or a non-ASCII byte -- ".hidden", "Ubersicht" spelled with
//     a leading U-umlaut, a CJK-named app. Those apps were missing from
//     `list`/`query` entirely. Matching on "not a space or tab" admits them.
//     This is a fix, not an accident: an inventory collector silently
//     omitting non-ASCII-named apps is a defect. It is additive only;
//   - a line containing the substring "Version:" carries the version;
//   - a line containing the substring "Last Modified:" carries the install
//     date;
//   - everything else (Obtained from/Kind/Signed by/Location, in the mini
//     detail's normal case) was never visible to the old grep and is
//     likewise skipped here for those three fields.
// "Location:" was added in Wave 4 PR4.3a (#2273) for the macOS list_inventory
// enrichment (installed_apps_macos_enrich.hpp), which calls CFBundleCreate/
// SecStaticCodeCreateWithPath against the app's absolute bundle path; it never
// enters the ADR-0016 InvRecord. Since ADR-0028's binding condition it is ALSO
// emitted by `list` as the trailing install_location column (format_app_row),
// so a change to its capture changes `list`'s rows; `query` and `list_per_user`
// still do not carry it.
[[nodiscard]] inline std::vector<AppRecord> parse_system_profiler_apps(std::string_view output) {
    std::vector<AppRecord> apps;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;

    std::string current_name, current_version, current_date, current_location;
    bool have_current = false;

    auto flush = [&]() {
        if (have_current && !current_name.empty()) {
            apps.push_back(AppRecord{current_name, current_version, {}, current_date,
                                     current_location});
        }
        current_name.clear();
        current_version.clear();
        current_date.clear();
        current_location.clear();
        have_current = false;
    };

    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);

        const bool four_space_header = line.size() > 4 && line.compare(0, 4, "    ") == 0 &&
                                       line[4] != ' ' && line[4] != '\t';
        const bool has_version = line.find("Version:") != std::string::npos;
        const bool has_last_modified = line.find("Last Modified:") != std::string::npos;
        const bool has_location = line.find("Location:") != std::string::npos;
        if (!four_space_header && !has_version && !has_last_modified && !has_location)
            continue;

        const auto start = line.find_first_not_of(" \t");
        if (start == std::string::npos)
            continue;
        const std::string_view trimmed = std::string_view(line).substr(start);

        // INDENT DECIDES, NOT THE KEY NAME. system_profiler puts app-name
        // headers at exactly 4 spaces and attributes deeper, so the indent is
        // an unambiguous discriminator -- and it must be tested FIRST.
        //
        // Testing the attribute prefixes first (as this did) misreads an app
        // literally named "Location", "Version" or "Last Modified": its header
        // line "    Location:" matches the attribute branch, so no flush()
        // happens. Both adversarial reviewers found this independently, and it
        // is worse than a dropped row: the app vanishes from list/query and the
        // inventory entirely, AND its Version/Last Modified/Location values
        // land on the PRECEDING app's record -- so that app is reported at the
        // wrong version and, because `Location` drives the #2273 enrichment,
        // with publisher and signature_status read from the impostor's bundle.
        // An unprivileged user dropping "Location.app" into /Applications gets
        // self-concealment plus attribution laundering onto a real app.
        if (four_space_header && !trimmed.empty() && trimmed.back() == ':') {
            flush();
            current_name = std::string(trimmed.substr(0, trimmed.size() - 1));
            have_current = true;
        } else if (trimmed.starts_with("Version:")) {
            current_version = std::string(detail::value_after_colon(trimmed));
        } else if (trimmed.starts_with("Last Modified:")) {
            current_date = std::string(detail::value_after_colon(trimmed));
        } else if (trimmed.starts_with("Location:")) {
            // Defence in depth, NOT a closure of the line-injection class (a
            // directory name may contain LF, so a planted bundle can print
            // well-formed extra lines; only a structured system_profiler
            // output closes that -- tracked issue). Accept only an absolute
            // path with no byte below 0x20 (DEL is not rejected): a relative
            // value would resolve against the agent's cwd in
            // CFURLCreateFromFileSystemRepresentation.
            const auto loc = detail::value_after_colon(trimmed);
            const bool absolute = !loc.empty() && loc.front() == '/';
            const bool clean = std::none_of(loc.begin(), loc.end(), [](char c) {
                return static_cast<unsigned char>(c) < 0x20;
            });
            current_location = (absolute && clean) ? std::string(loc) : std::string{};
        } else if (!trimmed.empty() && trimmed.back() == ':') {
            flush();
            current_name = std::string(trimmed.substr(0, trimmed.size() - 1));
            have_current = true;
        }
    }
    flush();
    return apps;
}

// ── macOS: brew list --versions ─────────────────────────────────────────

// One line of `brew list --versions`: "name version[ version...]". Only the
// first version token is kept (matches the legacy shell-out's own
// `line.substr(sp + 1)`, which keeps everything after the first space --
// a multi-version brew formula line's later tokens ride along as part of
// `version`, unchanged from the prior behaviour).
[[nodiscard]] inline std::vector<AppRecord> parse_brew_list(std::string_view output) {
    std::vector<AppRecord> apps;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        if (line.empty())
            continue;
        const auto sp = line.find(' ');
        AppRecord r;
        if (sp != std::string::npos) {
            r.name = line.substr(0, sp);
            r.version = line.substr(sp + 1);
        } else {
            r.name = line;
        }
        apps.push_back(std::move(r));
    }
    return apps;
}

// ── macOS: pkgutil (#2273 enrichment) ───────────────────────────────────

// `pkgutil --pkgs` -- one reverse-domain package identifier per line.
// Byte-for-byte the same split/trim shape as
// msi_packages_macos.hpp::parse_pkg_ids (duplicated rather than shared
// across the plugin boundary -- each plugin's pure-parser header is
// self-contained, matching every other plugin pair in this tree).
[[nodiscard]] inline std::vector<std::string> parse_pkgutil_pkgs(std::string_view output) {
    std::vector<std::string> ids;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        if (!line.empty())
            ids.push_back(line);
    }
    return ids;
}

// One `pkgutil --pkg-info <id>` receipt's version + install-time fields
// (`key: value` lines). `install_time` is pkgutil's raw UNIX-epoch-seconds
// string (its only time representation for a receipt -- no strftime here to
// avoid inventing a format the other ecosystems don't share; honest raw data,
// not synthesised). Malformed/empty input yields an all-empty result, never a
// crash or a fabricated value -- same discipline as
// msi_packages_macos.hpp::parse_pkg_info.
struct PkgutilInfo {
    std::string version;
    std::string install_time;
};

[[nodiscard]] inline PkgutilInfo parse_pkgutil_pkg_info(std::string_view output) {
    PkgutilInfo info;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        const auto sep = line.find(": ");
        if (sep == std::string::npos)
            continue;
        const std::string_view key = std::string_view(line).substr(0, sep);
        const std::string_view value = std::string_view(line).substr(sep + 2);
        if (key == "version")
            info.version = std::string(value);
        else if (key == "install-time")
            info.install_time = std::string(value);
    }
    return info;
}

// ── `list` row formatting ───────────────────────────────────────────────────

// Field set of one installed application: the `list` row's six columns. The
// plugin's AppInfo is an alias of this type, so the collectors, the Windows dedupe
// and the formatter share one record type and the header templates run in the
// plugin exactly as the tests run them.
struct AppRowFields {
    std::string name;
    std::string version;
    std::string publisher;
    std::string install_date;
    std::string install_location;
    std::string bundle_id;
};

// winnt.h REG_SZ / REG_EXPAND_SZ; literals so the predicate is testable on every host
// (installed_apps_registry_utf8.hpp static_asserts them on Windows).
constexpr unsigned long kRegSz = 1;
constexpr unsigned long kRegExpandSz = 2;

[[nodiscard]] constexpr bool reg_string_type_accepted(unsigned long type,
                                                      bool accept_expand_sz) noexcept {
    return type == kRegSz || (accept_expand_sz && type == kRegExpandSz);
}

// ── Windows: the name+version dedupe shared by list / query / inv| ──────────
// The three Uninstall hives (HKLM 64-bit, WoW6432Node, HKCU) can register one
// product several times. The sort comparator and the unique() predicate below
// are byte-for-byte the pre-ADR-0028 plugin code: unique() keeps the FIRST
// record of each equal (name, version) run, and that record's publisher/
// install_date feed the ADR-0016 hashed `inv|` rows and `query`. Equal keys have
// no defined order (std::sort is unstable), exactly as at base -- that survivor
// choice is NOT made deterministic here, because doing so could move a hashed
// row on a host with duplicates.
// The one `list`-only layer sits between the sort and unique(): the survivor's
// install_location becomes the lexicographically smallest populated location in
// its run, so the value is the same whatever order the sort left the run in and
// a '-' never shadows a path another hive holds. No other field moves.
// Templated because the plugin's AppInfo aliases AppRowFields; any record with
// name/version/install_location std::string members qualifies. Pure, so the
// whole pipeline is tested on every host with the plugin's own instantiation.
template <class Rec>
inline void dedupe_uninstall_records(std::vector<Rec>& apps) {
    std::sort(apps.begin(), apps.end(), [](const Rec& a, const Rec& b) {
        return a.name < b.name || (a.name == b.name && a.version < b.version);
    });
    for (std::size_t i = 0; i < apps.size();) {
        std::size_t end = i + 1;
        while (end < apps.size() && apps[end].name == apps[i].name &&
               apps[end].version == apps[i].version)
            ++end;
        std::size_t best = end; // "none populated"
        for (std::size_t k = i; k < end; ++k) {
            if (!apps[k].install_location.empty() &&
                (best == end || apps[k].install_location < apps[best].install_location))
                best = k;
        }
        if (best != end && best != i)
            apps[i].install_location = apps[best].install_location;
        i = end;
    }
    apps.erase(std::unique(apps.begin(), apps.end(),
                           [](const Rec& a, const Rec& b) {
                               return a.name == b.name && a.version == b.version;
                           }),
               apps.end());
}

// Per-field bound for `list` rows. Above every legitimate source: the Windows
// reader's 512-WCHAR buffer bounds a registry value at 1,536 UTF-8 bytes at most
// (512 WCHAR x 3), a macOS path at PATH_MAX (1,024); the longest field in the
// three reference captures is 135 bytes. It exists because CoreFoundation returns
// a hostile multi-MiB CFBundleIdentifier in full and one such row would exceed the
// 4 MiB gRPC receive default and tear the agent stream. The raw value is cut here,
// before escaping, so an emitted field can reach 8 KiB (every byte a `|`).
constexpr std::size_t kMaxListFieldBytes = 4096;

namespace detail {
// One `list` field on the wire: cut at the first NUL (write_output hands the row
// to a C string, so an interior NUL would otherwise truncate the whole ROW and
// strand the later columns), bound the length at a UTF-8 sequence boundary,
// then safe_output_field ('\' -> '/', '|' -> "\|", CR/LF -> ' '); "-" if empty.
// The NUL cut and the bound MUST precede the escape: escaping first can cut
// between a '\' and its '|', and the stranded '\' then swallows the delimiter.
inline std::string list_field(std::string_view v) {
    v = v.substr(0, v.find('\0'));
    if (v.size() > kMaxListFieldBytes) {
        std::size_t cut = kMaxListFieldBytes;
        while (cut > 0 && (static_cast<unsigned char>(v[cut]) & 0xC0) == 0x80)
            --cut;
        v = v.substr(0, cut);
    }
    return v.empty() ? std::string("-") : yuzu::util::safe_output_field(v);
}
} // namespace detail

// `app|name|version|publisher|install_date|install_location|bundle_id`.
// EVERY field goes through detail::list_field, so a row is always exactly seven
// escape-aware tokens (server/core/src/result_parsing.hpp find_unescaped_pipe
// grammar) whatever bytes a registry value, an Info.plist or a path carries; a
// value within the 4 KiB bound and free of '\', '|', CR, LF and NUL is emitted
// byte-identically (in the reference captures the new install_location is the
// exception: 59 of 241 Windows rows carry a populated one, its backslashes
// folded to '/'). `query`/`list_per_user` keep their own raw std::format rows
// and the ADR-0016 `inv|` rows never pass here.
// `name` stays "" when empty (the collectors never produce one; the sentinel
// row sets it); every other empty field renders "-". The caller applies
// sanitize_utf8 to the result (a no-op on the boundary-safe cut).
[[nodiscard]] inline std::string format_app_row(const AppRowFields& f) {
    std::string out = "app|";
    out += f.name.empty() ? std::string{} : detail::list_field(f.name);
    for (const auto* v : {&f.version, &f.publisher, &f.install_date, &f.install_location,
                          &f.bundle_id}) {
        out += '|';
        out += detail::list_field(*v);
    }
    return out;
}

} // namespace yuzu::installed_apps::parsers
