#pragma once

/**
 * software_actions_parsers.hpp — pure parse helpers for the software_actions
 * plugin (winget/apt/yum/softwareupdate/dpkg-query output).
 *
 * Header-only and OS-free (no windows.h, no POSIX, no subprocesses) so the
 * parsing is unit-tested on every host (the firewall_parsers.hpp /
 * services_parsers.hpp pattern); the run_bounded_subprocess acquisition in
 * software_actions_plugin.cpp is the impure shell.
 *
 * Every emit string these feed stays byte-compatible with the plugin's
 * pre-migration `upgradable|...`/`count|N` output contract — only the
 * acquisition mechanism (popen -> bounded argv runner) changed. ONE
 * disclosed exception: Linux `installed_count` widened from the pre-
 * migration `dpkg --list | grep '^ii'` (installed-only) to also count `hi`
 * (installed, held) via count_dpkg_status_abbrev_installed below, matching
 * installed_apps' convention — a genuine value-level change, called out in
 * this branch's changelog, not a silent contract break.
 */

#include <cstddef>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::software_actions {

namespace detail {

/// Split `out` on '\n', stripping a trailing '\r' from each physical line
/// and dropping lines that are empty after that strip — matches the old
/// run_command_lines() popen helper's line contract exactly, so lifting the
/// parsing logic below out of the plugin changes nothing about what it sees.
[[nodiscard]] inline std::vector<std::string> split_nonblank_lines(std::string_view out) {
    std::vector<std::string> lines;
    std::string buf(out); // istringstream needs an owned string
    std::istringstream iss(buf);
    std::string line;
    while (std::getline(iss, line)) {
        while (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            lines.push_back(std::move(line));
    }
    return lines;
}

/// Offsets at which each whitespace-separated token of `header` begins.
/// winget renders a fixed-width table whose header names sit at the exact
/// column origins of the data beneath them, so the token starts ARE the
/// column boundaries. Only the positions are used, never the header text —
/// winget localises the column names, so reading the text would break on
/// every non-English Windows.
[[nodiscard]] inline std::vector<std::size_t> column_origins(std::string_view header) {
    std::vector<std::size_t> origins;
    bool in_token = false;
    std::size_t cell = 0;
    for (std::size_t i = 0; i < header.size(); ++i) {
        const auto ch = static_cast<unsigned char>(header[i]);
        if ((ch & 0xC0) == 0x80)
            continue; // UTF-8 continuation byte: same display cell
        const bool is_space = ch == ' ' || ch == '\t';
        if (!is_space && !in_token) {
            origins.push_back(cell);
            in_token = true;
        } else if (is_space) {
            in_token = false;
        }
        ++cell;
    }
    return origins;
}

/// Byte index of the start of each display cell in `line`, plus a trailing
/// entry for the end of the line.
///
/// winget pads its columns by DISPLAY width, so a header origin is a CELL
/// index, not a byte offset. Slicing raw bytes at that number shifts every
/// column right by one byte for each multi-byte character earlier in the row,
/// which for a name like "Bitwarden Passwort-Manager" silently pushed the
/// version column past its boundary and dropped the row. One cell per UTF-8
/// code point is exact for Latin/accented text; genuinely double-width (CJK)
/// code points still occupy two cells and are not modelled, so those rows fail
/// the boundary check and degrade honestly rather than mis-map.
[[nodiscard]] inline std::vector<std::size_t> cell_byte_offsets(std::string_view line) {
    std::vector<std::size_t> cells;
    cells.reserve(line.size() + 1);
    for (std::size_t i = 0; i < line.size(); ++i) {
        if ((static_cast<unsigned char>(line[i]) & 0xC0) != 0x80)
            cells.push_back(i);
    }
    cells.push_back(line.size());
    return cells;
}

/// `line[begin, end)` with surrounding blanks trimmed; empty when the slice
/// starts past the end of the line (a short row simply has empty tail columns).
[[nodiscard]] inline std::string slice_trimmed(const std::string& line, std::size_t begin,
                                               std::size_t end) {
    if (begin >= line.size())
        return {};
    end = end < line.size() ? end : line.size();
    const auto width = end - begin;
    const auto first = line.find_first_not_of(" \t", begin);
    if (first == std::string::npos || first >= begin + width)
        return {};
    const auto last = line.find_last_not_of(" \t", begin + width - 1);
    return line.substr(first, last - first + 1);
}

} // namespace detail

// ── Windows: winget upgrade ────────────────────────────────────────────────

/// winget upgrade renders five columns: Name / Id / Version / Available /
/// Source.
///
/// Positional slicing removes the dependency on the header TEXT, so a
/// translated header still parses -- but it assumes each localised column name
/// is a SINGLE token. A translation using a two-word column name yields more
/// than five origins and drops the table into the name-only degrade path. That
/// is an honest degrade, not a mis-parse, but it is not "localisation solved".
inline constexpr std::size_t kWingetColumnCount = 5;

struct WingetUpgradeRow {
    std::string name;
    std::string current_version;
    std::string available_version;
};

struct WingetUpgradeParse {
    std::vector<WingetUpgradeRow> rows;
    // True once the fixed-width header's dashed separator line was found —
    // distinguishes "winget ran but produced no recognisable table at all"
    // (separator_found stays false; the caller emits `upgradable|none|-|-`)
    // from "winget ran, found the table, and it has zero data rows" (a
    // genuine up-to-date system; the caller emits the "System is up to
    // date" line) — the same two-shape distinction the original popen-based
    // code made via `lines.empty()` vs `!found_any`.
    bool separator_found = false;
    // Post-separator lines that looked like data but could not be mapped onto
    // the header's columns. Trailer prose lands here too, so a nonzero value is
    // not by itself an error -- but a row silently vanishing from an upgrade
    // report IS, so the caller reports PARTIAL completeness once any line is
    // dropped beyond the trailers it recognises.
    std::size_t unmapped_lines = 0;
    // True when the header line above the separator did NOT yield exactly
    // kWingetColumnCount column origins, so positional slicing was not
    // possible and rows were emitted name-only (`name|-|-`). Never means a
    // version was guessed: a version is either read from its own column or
    // reported as "-". The caller surfaces this as a CONSTRAINED/partial
    // result so an operator can tell "no upgrades" from "could not read the
    // version columns".
    bool header_unrecognized = false;
};

/// winget's post-table trailer lines ("23 upgrades available.", "N package(s)
/// have version numbers that cannot be determined. …"). Recognised so they are
/// never counted as dropped data rows, and never emitted as a phantom package
/// in the degraded name-only path. English-only by nature -- winget localises
/// these too -- so it is used ONLY to classify lines already rejected as data,
/// never to admit one.
[[nodiscard]] inline bool is_winget_trailer(const std::string& line) {
    const bool upgrades_available =
        line.find("upgrade") != std::string::npos && line.find("available") != std::string::npos;
    const bool undetermined_versions = line.find("package(s)") != std::string::npos &&
                                       line.find("version") != std::string::npos;
    // winget's own "nothing matched" message: not data, and not a dropped row.
    const bool no_match = line.find("No installed package") != std::string::npos;
    return upgrades_available || undetermined_versions || no_match;
}

/// Parse `winget upgrade --accept-source-agreements` output.
///
/// winget renders a FIXED-WIDTH table (Name / Id / Version / Available /
/// Source), so columns are sliced by the byte offsets of the header's tokens
/// rather than guessed from runs of 2+ spaces. The old split-on-2+-spaces
/// heuristic silently mis-mapped every row whose content filled a column to
/// its full width and so was followed by a SINGLE space: those rows yielded
/// four fields instead of five, and reading `parts[3]` as the available
/// version handed back the *Source* column, emitting a literal
/// `available_version == "winget"`. Against a real 23-row capture from a
/// live Windows host, 4 rows reported "winget" as the available version and
/// a 5th collapsed to name-only — fabricated data of the same class as the
/// Wave-3 BitLocker/firewall false-state bugs. Positional slicing parses all
/// 23 of those rows exactly, including `Version == "< 17.14.35"` (a value
/// containing a space, which no space-delimited split can recover).
///
/// Only header token POSITIONS are used, never the header text: winget
/// localises the column names, so matching on "Name"/"Version" would break
/// on every non-English Windows.
///
/// Honesty contract: a line that does not map cleanly onto the header's
/// columns NEVER contributes a value borrowed from a neighbouring column. It
/// is either skipped (trailer lines such as "23 upgrades available." and the
/// "N package(s) have version numbers that cannot be determined" footer,
/// neither of which aligns to the Id column) or, when the header itself is
/// unreadable, emitted name-only as `name|-|-` with header_unrecognized set.
[[nodiscard]] inline WingetUpgradeParse parse_winget_upgrade(std::string_view output) {
    WingetUpgradeParse result;
    const auto lines = detail::split_nonblank_lines(output);

    std::size_t separator_index = lines.size();
    for (std::size_t i = 0; i < lines.size(); ++i) {
        bool is_sep = !lines[i].empty();
        for (char ch : lines[i]) {
            if (ch != '-' && ch != ' ') {
                is_sep = false;
                break;
            }
        }
        if (is_sep && lines[i].size() > 10) {
            separator_index = i;
            result.separator_found = true;
            break;
        }
    }
    if (!result.separator_found)
        return result;

    std::vector<std::size_t> origins;
    if (separator_index > 0)
        origins = detail::column_origins(lines[separator_index - 1]);
    const bool positional = origins.size() == kWingetColumnCount;
    result.header_unrecognized = !positional;

    for (std::size_t i = separator_index + 1; i < lines.size(); ++i) {
        const auto& line = lines[i];

        if (!positional) {
            // Header unreadable — emit the Name column only. The Name column
            // always begins at offset 0, so the text before the first run of
            // 2+ spaces is genuinely the name; the version columns are
            // reported as "-" rather than guessed.
            if (is_winget_trailer(line))
                continue;
            const auto gap = line.find("  ");
            auto name = detail::slice_trimmed(line, 0, gap == std::string::npos ? line.size() : gap);
            if (!name.empty())
                result.rows.push_back({std::move(name), "-", "-"});
            continue;
        }

        // Origins are DISPLAY-CELL indices; translate them to byte offsets
        // for this row so a multi-byte character earlier in the line does not
        // shift every later column.
        const auto cells = detail::cell_byte_offsets(line);
        auto byte_of = [&](std::size_t cell) {
            return cell < cells.size() ? cells[cell] : line.size();
        };

        // A data row must respect every column boundary: the cell immediately
        // before each column origin is a space (or the row ends before that
        // column). Trailer prose overflows its columns and fails this check, so
        // it can never become a phantom row.
        bool aligned = true;
        for (std::size_t c = 1; c < origins.size(); ++c) {
            const std::size_t origin_byte = byte_of(origins[c]);
            if (origin_byte >= line.size())
                continue; // row ends before this column
            const std::size_t prev_byte = byte_of(origins[c] - 1);
            if (prev_byte >= line.size() || line[prev_byte] != ' ') {
                aligned = false;
                break;
            }
        }
        if (!aligned) {
            // Either trailer prose (which overflows its columns) or a genuine
            // row whose padding this parser could not follow. It is NOT emitted
            // with borrowed values -- but it is counted, so a dropped package
            // cannot vanish silently.
            if (!is_winget_trailer(line))
                ++result.unmapped_lines;
            continue;
        }

        auto name = detail::slice_trimmed(line, byte_of(origins[0]), byte_of(origins[1]));
        const auto id = detail::slice_trimmed(line, byte_of(origins[1]), byte_of(origins[2]));
        auto current = detail::slice_trimmed(line, byte_of(origins[2]), byte_of(origins[3]));
        auto available = detail::slice_trimmed(line, byte_of(origins[3]), byte_of(origins[4]));
        // Id and Version are always populated on a genuine winget row; a
        // short trailer line ("23 upgrades available.") aligns trivially but
        // leaves them empty, which is what distinguishes it from data.
        if (name.empty() || id.empty() || current.empty())
            continue;
        if (available.empty())
            available = "-";
        result.rows.push_back({std::move(name), std::move(current), std::move(available)});
    }
    return result;
}

// ── Linux: apt list --upgradable ───────────────────────────────────────────

struct AptUpgradeRow {
    std::string name;
    std::string old_version;
    std::string new_version;
};

/// Parse `apt list --upgradable` output: "name/repo new_ver arch [upgradable
/// from: old_ver]" per line, "Listing..." banner skipped.
[[nodiscard]] inline std::vector<AptUpgradeRow> parse_apt_list_upgradable(std::string_view output) {
    std::vector<AptUpgradeRow> rows;
    for (const auto& line : detail::split_nonblank_lines(output)) {
        if (line.starts_with("Listing"))
            continue;
        auto slash = line.find('/');
        auto space = line.find(' ');
        if (slash != std::string::npos && space != std::string::npos) {
            auto name = line.substr(0, slash);
            auto rest = line.substr(space + 1);
            auto ver_end = rest.find(' ');
            auto new_ver = (ver_end != std::string::npos) ? rest.substr(0, ver_end) : rest;
            std::string old_ver = "-";
            auto from_pos = rest.find("from: ");
            if (from_pos != std::string::npos) {
                old_ver = rest.substr(from_pos + 6);
                auto bracket = old_ver.find(']');
                if (bracket != std::string::npos)
                    old_ver = old_ver.substr(0, bracket);
            }
            rows.push_back({std::move(name), std::move(old_ver), std::move(new_ver)});
        }
    }
    return rows;
}

// ── Linux: yum/dnf check-update ────────────────────────────────────────────

struct YumUpgradeRow {
    std::string name;
    std::string new_version;
};

/// yum/dnf `check-update` exit-code contract: 0 = ran, nothing to update
/// (success); 100 = ran, updates ARE available (ALSO success — "success with
/// data", not a failure); any other code is a genuine tool failure. The old
/// popen-based code never inspected the exit code at all (popen only exposes
/// stdout), so this is a strictly more honest decision than what it replaces
/// — the new runner-based call site must NOT regress by treating 100 as an
/// error.
[[nodiscard]] constexpr bool yum_checkupdate_is_success(int exit_code) {
    return exit_code == 0 || exit_code == 100;
}

/// Nonzero-exit-with-partial-data decision, shared by every list_upgradable
/// leg whose tool can exit nonzero while still printing usable data: true
/// when the tool exited nonzero but SOMETHING still parsed. Two call sites --
///   - winget (Windows): one configured source (`msstore`) is unreachable
///     while winget still prints what it could reach from the others, and
///     still exits nonzero for the source it couldn't reach.
///   - softwareupdate -l (macOS): observed to exit nonzero on some macOS
///     releases while still printing a valid, parseable table (the sibling
///     windows_updates_plugin.cpp's do_missing() makes the identical choice
///     for this exact tool, deliberately excluding exit_code from ITS
///     capture-usability test, for the same reason).
/// In both cases `capture_usable()` deliberately does not gate on the exit
/// code at all, so nothing else catches this: without this check, a caller
/// derives "ok" from an undeclared status, and a short/partial result is
/// indistinguishable from a complete one. Pure decision, tested directly
/// here rather than only through a real subprocess (this repo's test suite
/// deliberately never dispatches list_upgradable from a unit test).
[[nodiscard]] constexpr bool nonzero_exit_with_partial_rows(int exit_code, bool rows_empty) {
    return exit_code != 0 && !rows_empty;
}

/// May the caller assert "System is up to date" for this scan? Deliberately
/// separate from `nonzero_exit_with_partial_rows` above -- this is the
/// converse direction: THIS regression is a false-CLEAN claim coexisting with
/// a degraded status, not an undeclared-status partial. Governance Gate 4
/// (unhappy-path) found it live in do_list_upgradable's Windows leg: when
/// every post-separator line failed the column-alignment check, `rows` ends
/// up empty EXACTLY like a genuine clean scan, but for a DEGRADED reason (a
/// CONSTRAINED status was already set for the dropped rows) -- the code fell
/// through to "up to date" anyway, a positive assertion contradicting the
/// status it had just set. `table_incomplete` is the caller's OWN record of
/// whether it already reported a degrade for THIS parse (header_unrecognized,
/// unmapped_lines, or nonzero_exit_with_partial_rows) -- required because
/// CommandContext exposes no way to read back a status already set.
[[nodiscard]] constexpr bool winget_up_to_date_claimable(bool rows_empty, int exit_code,
                                                          bool separator_found,
                                                          bool table_incomplete) {
    return rows_empty && exit_code == 0 && separator_found && !table_incomplete;
}

/// Parse `yum check-update` / `dnf check-update` output: "package.arch
/// new_version repo" per line, "Loaded"/"Loading"/"Last metadata" banner
/// lines skipped.
[[nodiscard]] inline std::vector<YumUpgradeRow> parse_yum_checkupdate(std::string_view output) {
    std::vector<YumUpgradeRow> rows;
    bool in_obsoleting = false;
    for (const auto& line : detail::split_nonblank_lines(output)) {
        if (line.starts_with("Loaded") || line.starts_with("Loading"))
            continue;
        if (line.starts_with("Last metadata"))
            continue;
        // `dnf check-update` appends an "Obsoleting Packages" section after the
        // update list. Its heading is not a package, and its indented rows are
        // obsoletions rather than pending updates -- emitting either as an
        // upgradable package invents an update that does not exist.
        if (line.starts_with("Obsoleting"))
            in_obsoleting = true;
        if (in_obsoleting)
            continue;
        // A continuation line (leading whitespace) belongs to the previous
        // record, not a new package.
        if (line.front() == ' ' || line.front() == '\t')
            continue;
        std::string name, version;
        std::size_t pos = 0;
        while (pos < line.size() && line[pos] != ' ' && line[pos] != '\t')
            pos++;
        name = line.substr(0, pos);
        while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t'))
            pos++;
        auto ver_start = pos;
        while (pos < line.size() && line[pos] != ' ' && line[pos] != '\t')
            pos++;
        version = line.substr(ver_start, pos - ver_start);
        if (!name.empty())
            rows.push_back({std::move(name), std::move(version)});
    }
    return rows;
}

// ── macOS: softwareupdate -l ───────────────────────────────────────────────

/// Parse `softwareupdate -l` output into a list of upgradable labels/titles.
/// Boilerplate lines ("Software Update Tool", "Finding available software",
/// "No new software available.") are skipped; "* Label: X" lines yield X;
/// any other non-Title/Size/Recommended/Action line under a "*"-prefixed
/// entry is emitted verbatim, matching the pre-migration parser exactly.
[[nodiscard]] inline std::vector<std::string> parse_softwareupdate_list(std::string_view output) {
    std::vector<std::string> labels;
    for (const auto& line : detail::split_nonblank_lines(output)) {
        // Shape rule: only lines belonging to a "*"-marked entry are candidates.
        // The former allow-by-default behaviour emitted ANY unrecognised line as
        // a package name, so a diagnostic printed to stdout became
        // `upgradable|<diagnostic text>|-|-`.
        const auto marker = line.find_first_not_of(" \t");
        const bool entry_line = marker != std::string::npos && line[marker] == '*';
        const bool label_line = line.find("Label:") != std::string::npos;
        if (!entry_line && !label_line)
            continue;
        auto trimmed = line;
        auto start = trimmed.find_first_not_of(" \t*");
        if (start == std::string::npos)
            continue;
        trimmed = trimmed.substr(start);
        if (trimmed.empty())
            continue;
        if (trimmed.starts_with("Software Update") || trimmed.starts_with("Finding") ||
            trimmed.starts_with("No new"))
            continue;
        if (const auto label_pos = trimmed.find("Label:"); label_pos != std::string::npos) {
            // Take the text after THIS "Label:" -- not after the first colon in
            // the line, which need not be the same one. An unguarded
            // substr(find(':') + 2) also throws std::out_of_range on a bare
            // "Label:" line, and that exception would cross the plugin's C ABI
            // boundary out of execute(), which has no catch.
            const auto value = trimmed.find_first_not_of(" \t", label_pos + 6);
            if (value != std::string::npos)
                labels.push_back(trimmed.substr(value));
        } else if (!trimmed.starts_with("Title:") && !trimmed.starts_with("Size:") &&
                   !trimmed.starts_with("Recommended:") && !trimmed.starts_with("Action:")) {
            labels.push_back(trimmed);
        }
    }
    return labels;
}

// ── Linux: dpkg-query status-abbrev count ──────────────────────────────────

/// Count lines from `dpkg-query -W -f='${db:Status-Abbrev}\n'` output whose
/// 2nd character is 'i' — matches installed_apps_inventory.hpp's
/// parse_dpkg_inv_line: "ii" (want=install) and "hi" (want=hold) count, "rc"
/// (removed) and "un" (unknown) do not. NOT vuln_scan_plugin.cpp's own dpkg
/// query, which filters on the opposite convention (a `${Status}` ==
/// "install ok installed" substring match, excluding held packages) — a
/// pre-existing inconsistency between vuln_scan and its inventory sibling,
/// not something this file follows.
[[nodiscard]] inline std::size_t count_dpkg_status_abbrev_installed(std::string_view output) {
    std::size_t count = 0;
    for (const auto& line : detail::split_nonblank_lines(output)) {
        if (line.size() >= 2 && line[1] == 'i')
            ++count;
    }
    return count;
}

/// Generic "one record per non-empty line" count (`rpm -qa`, `pkgutil --pkgs`).
[[nodiscard]] inline std::size_t count_nonempty_lines(std::string_view output) {
    return detail::split_nonblank_lines(output).size();
}

/// Whether one tool invocation produced a COMPLETE, trustworthy capture that
/// a count or a row list may honestly be derived from. `exit_ok` is the
/// caller's own verdict on the exit code (runner_status.hpp leaves exit-code
/// semantics to the caller: yum/dnf's 100 is a success, most tools' nonzero is
/// not). Pure so every combination is unit-testable without a spawn.
[[nodiscard]] constexpr bool capture_is_complete(bool tool_ran, bool timed_out,
                                                 bool output_truncated, bool exit_ok) {
    return tool_ran && !timed_out && !output_truncated && exit_ok;
}

// ── installed_count emit decision (pure seam) ──────────────────────────────

/// The `count|N` line for a subkey/record count, or std::nullopt when the
/// count is unavailable (a negative sentinel — Windows'
/// registry_uninstall_subkey_count() returns -1 when the registry read
/// fails).
///
/// Pure so the FAILURE path is unit-testable on every host: the Windows
/// registry read it guards essentially never fails on a real machine, so
/// the honest-degrade branch would otherwise ship unexercised. A degraded
/// read must emit NO count line — `count|0` would assert "zero programs are
/// installed", the same false-clean shape the antivirus plugin's
/// `exclusion_count|0` invariant forbids.
[[nodiscard]] inline std::optional<std::string> installed_count_line(int count) {
    if (count < 0)
        return std::nullopt;
    return "count|" + std::to_string(count);
}

} // namespace yuzu::software_actions
