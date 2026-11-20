#pragma once

/**
 * dpkg_status_parsers.hpp -- pure parser for the dpkg status text database
 * (/var/lib/dpkg/status and the single-stanza control files of /var/lib/dpkg/status.d/).
 *
 * Header-only, no I/O: the caller hands over the file's text, so every case is
 * fixture-fed on any host (docs/testing/unit-test-conventions.md "pure core,
 * thin shell"). The directory walk and the no-follow opens live in the plugin's
 * shell (installed_apps_pkgdb_read.hpp).
 *
 * Grammar (deb-control(5), the subset this reader needs):
 *   - a stanza is a run of lines ended by an empty line or the end of the text;
 *   - `Name: value` starts a field; names match case-insensitively; the value
 *     is the text after the FIRST colon, trimmed of blanks;
 *   - a line starting with a space or tab continues the previous field and is
 *     ignored (Description, Conffiles ... are never read);
 *   - a line starting with '#' is a comment and is skipped (deb-control(5));
 *   - only Package, Version, Architecture, Maintainer and Status are read.
 *
 * Strictness (a degraded answer is loud, a guessed one is not): the whole text
 * is refused as `corrupt` for a NUL byte, a non-continuation line without a
 * colon, a continuation line before any field, a stanza without a Package, a
 * duplicate of a field this parser reads, and a Status that is not exactly
 * three space-separated words (`<want> <flag> <state>`). dpkg itself rejects
 * the same inputs, so a database dpkg can read is never refused here.
 *
 * A stanza with no Status field at all is the caller's policy (MissingStatus).
 * The status file is dpkg's own record and always carries one, so there the
 * answer is `corrupt` (the default). The files of status.d are plain control
 * stanzas, written by an image builder from each package's control file, and a
 * real minimal image's carry NO Status field: that caller asks for
 * MissingStatus::installed, because a package whose file is present in status.d
 * is installed by construction. A Status that IS present is checked by the same
 * three-word rule in both places, and `not-installed` is skipped in both.
 *
 * A stanza whose state word is `not-installed` is skipped (dpkg-query -W prints
 * none). Every other stanza is returned WITH its three words: which states count
 * as installed is the caller's rule (inv uses state == installed, `list` also
 * requires flag ok and an install/deinstall want), so the held, half-installed,
 * unpacked and config-files states stay visible to the next consumer.
 */

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "pkgdb_budget.hpp"

namespace yuzu::shared {

struct DpkgPackage {
    std::string name;
    std::string version;
    std::string architecture;
    std::string maintainer;
    std::string want;   ///< unknown | install | hold | deinstall | purge
    std::string flag;   ///< ok | reinstreq | hold | hold-reinstreq
    std::string status; ///< installed | not-installed | config-files | half-installed | ...
};

/// What a stanza with no Status field means. The status file requires one (`corrupt`); a status.d
/// control stanza has none and is installed (see the file comment).
enum class MissingStatus : std::uint8_t { corrupt, installed };

namespace dpkg_detail {

[[nodiscard]] constexpr char lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

[[nodiscard]] inline bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (lower(a[i]) != lower(b[i]))
            return false;
    return true;
}

[[nodiscard]] inline std::string_view trim_blanks(std::string_view v) noexcept {
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
        v.remove_prefix(1);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t'))
        v.remove_suffix(1);
    return v;
}

/// One stanza under construction. `seen` records which of the five read fields
/// already appeared (a duplicate is refused); `in_field` says a continuation
/// line has something to continue.
struct Stanza {
    DpkgPackage pkg;
    bool seen[5] = {false, false, false, false, false};
    bool started = false;  ///< at least one field line was read
    bool in_field = false; ///< a continuation is legal
    std::string status_raw;
};

inline constexpr std::string_view kFields[5] = {"Package", "Version", "Architecture", "Maintainer",
                                                "Status"};

/// The three words of a Status field.
struct StatusWords {
    std::string_view want;
    std::string_view flag;
    std::string_view state;
};

/// Splits "want flag state" on single spaces into exactly three non-empty words, or nullopt.
/// The words view `s`.
[[nodiscard]] inline std::optional<StatusWords> split_status(std::string_view s) {
    const std::size_t a = s.find(' ');
    if (a == std::string_view::npos || a == 0)
        return std::nullopt;
    const std::size_t b = s.find(' ', a + 1);
    if (b == std::string_view::npos || b == a + 1)
        return std::nullopt;
    const StatusWords w{s.substr(0, a), s.substr(a + 1, b - a - 1), s.substr(b + 1)};
    if (w.state.empty() || w.state.find(' ') != std::string_view::npos)
        return std::nullopt;
    for (const std::string_view v : {w.want, w.flag, w.state})
        if (v.find('\t') != std::string_view::npos)
            return std::nullopt;
    return w;
}

/// Closes a stanza: appends it unless it is `not-installed`. Charges one row per
/// stanza seen (a skipped one too: a hostile file of a million not-installed
/// stanzas is bounded by the row budget, not only by the byte cap). The references are the
/// streaming parser's running state (the stanza under construction, the output, the stanza
/// count), not results; the result is the returned std::expected.
[[nodiscard]] inline PkgDbVoid finish(Stanza& st, PkgDbBudget& budget,
                                      std::vector<DpkgPackage>& out, std::size_t& stanzas,
                                      MissingStatus missing) {
    if (!st.started)
        return {};
    if (auto r = budget.charge_row(); !r)
        return r;
    if ((++stanzas & 0xFFu) == 0)
        if (auto t = budget.check_time(); !t)
            return t;
    if (!st.seen[0] || st.pkg.name.empty())
        return std::unexpected(PkgDbCause::corrupt); // a stanza without a Package
    if (st.seen[4]) {
        const auto words = split_status(st.status_raw);
        if (!words)
            return std::unexpected(PkgDbCause::corrupt); // a Status that is not three words
        st.pkg.want.assign(words->want);
        st.pkg.flag.assign(words->flag);
        st.pkg.status.assign(words->state);
    } else if (missing == MissingStatus::installed) {
        st.pkg.want = "install"; // a status.d control stanza: present means installed
        st.pkg.flag = "ok";
        st.pkg.status = "installed";
    } else {
        return std::unexpected(PkgDbCause::corrupt); // the status file always has one
    }
    if (st.pkg.status != "not-installed")
        out.push_back(std::move(st.pkg));
    st = Stanza{};
    return {};
}

} // namespace dpkg_detail

/// Parses one status text. See the file comment for what is refused and for `missing`. The
/// budget's rows are charged per stanza and its clock is read every 256 stanzas.
[[nodiscard]] inline std::expected<std::vector<DpkgPackage>, PkgDbCause>
parse_dpkg_status(std::string_view text, PkgDbBudget& budget,
                  MissingStatus missing = MissingStatus::corrupt) {
    using namespace dpkg_detail;
    if (text.find('\0') != std::string_view::npos)
        return std::unexpected(PkgDbCause::corrupt);

    std::vector<DpkgPackage> out;
    Stanza st;
    std::size_t stanzas = 0;
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t eol = text.find('\n', pos);
        if (eol == std::string_view::npos)
            eol = text.size();
        std::string_view line = text.substr(pos, eol - pos);
        pos = eol + 1;
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        if (line.empty()) { // end of stanza
            if (auto r = finish(st, budget, out, stanzas, missing); !r)
                return std::unexpected(r.error());
            continue;
        }
        if (line.front() == '#') // comment line, not part of any field
            continue;
        if (line.front() == ' ' || line.front() == '\t') { // continuation: ignored
            if (!st.in_field)
                return std::unexpected(PkgDbCause::corrupt);
            continue;
        }
        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0)
            return std::unexpected(PkgDbCause::corrupt);
        st.started = true;
        st.in_field = true;
        const std::string_view name = line.substr(0, colon);
        for (std::size_t k = 0; k < 5; ++k) {
            if (!iequals(name, kFields[k]))
                continue;
            if (st.seen[k])
                return std::unexpected(PkgDbCause::corrupt); // duplicate of a field we read
            st.seen[k] = true;
            const std::string_view value = trim_blanks(line.substr(colon + 1));
            switch (k) {
            case 0: st.pkg.name.assign(value); break;
            case 1: st.pkg.version.assign(value); break;
            case 2: st.pkg.architecture.assign(value); break;
            case 3: st.pkg.maintainer.assign(value); break;
            default: st.status_raw.assign(value); break;
            }
            break;
        }
    }
    if (auto r = finish(st, budget, out, stanzas, missing); !r) // the last stanza needs no trailing blank line
        return std::unexpected(r.error());
    return out;
}

/// Merges the packages of status.d into those of the status file: a package
/// present in both keeps the status entry (the status file is dpkg's own record;
/// status.d is the layout minimal images use in its place). A package is its
/// (name, architecture) pair, so a multi-arch sibling is never mistaken for a
/// duplicate. Within status.d the first occurrence wins. Compared exactly.
inline void merge_dpkg_status_d(std::vector<DpkgPackage>& status,
                                std::vector<DpkgPackage>&& status_d) {
    const auto key = [](const DpkgPackage& p) { return p.name + '\x1f' + p.architecture; };
    std::unordered_set<std::string> have;
    have.reserve(status.size() + status_d.size());
    for (const auto& p : status)
        have.insert(key(p));
    for (auto& p : status_d)
        if (have.insert(key(p)).second)
            status.push_back(std::move(p));
}

} // namespace yuzu::shared
