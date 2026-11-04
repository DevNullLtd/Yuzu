/**
 * disk_actions_partitions.hpp -- the pure layer of the Windows `partitions` leg.
 *
 * No OS call, no COM, no I/O: it turns the rows two bounded WMI queries returned
 * (Win32_DiskPartition, Win32_LogicalDiskToPartition) into the `partition|...` rows and one
 * leading `status|partitions|...` row, so the whole outcome contract is unit-tested on every
 * host. The Windows TU (disk_actions_win.cpp) owns the queries and nothing else.
 *
 *   status|partitions|<supported|constrained|unsupported>|<token or ->
 *   partition|<disk>|<partition>|<size_bytes>|<type>|<mount_points>|<detail>
 *
 * WHAT EACH COLUMN IS
 *   disk          `PhysicalDrive<DiskIndex>` -- the SAME spelling `smart` and `volumes` use for
 *                 their device column, so the three actions join on it.
 *   partition     the provider's own DeviceID ("Disk #0, Partition #1"). It is also the key the
 *                 association class names, which is why it is emitted verbatim: re-deriving a
 *                 name from the indexes would make the mount-point join depend on the provider
 *                 formatting it the way this file guesses. 0-based, unlike PowerShell's
 *                 PartitionNumber (1-based).
 *   size_bytes    Win32_DiskPartition.Size, or "-" when the provider did not give one.
 *   type          Win32_DiskPartition.Type verbatim ("GPT: Basic Data", "Installable File
 *                 System"). A provider string, not a GUID.
 *   mount_points  the drive letters Win32_LogicalDiskToPartition maps to the partition, sorted,
 *                 comma-separated, in the spelling `volumes` uses ("C:/" after
 *                 safe_output_field folds the backslash), or "-" for none. A folder mount point
 *                 is NOT visible through this class (README caveat).
 *   detail        a fixed token, never free text: "wmi"; "wmi,mount_points_unread" when the
 *                 association query failed (every "-" means UNKNOWN, not none); or
 *                 "wmi,mount_points_partial" on a row left unmatched by an association query
 *                 that returned a row it could not use, or hit its row cap (that "-" is UNKNOWN
 *                 too).
 *
 * KNOWN GAP, MEASURED: Win32_DiskPartition does not list the 16 MiB Microsoft Reserved
 * partition (a GPT disk shows one fewer partition than MSFT_Partition). The section is therefore
 * the partitions Windows exposes through Win32_DiskPartition, not a byte-exact map of the disk.
 *
 * OUTCOME CONTRACT (the same four levels as the hardware estate legs; rc is 0 for every one)
 *   supported / OK      both queries answered cleanly and returned at least one partition.
 *   constrained         a partial read: a row or an association the parser could not use, a row
 *                       cap, the association query failed (the partitions are kept, their mount
 *                       points are unknown and say so), or a clean read that returned NO
 *                       partitions (a booted Windows host always has one, so an empty answer is a
 *                       provider fault, not "no partitions": `windows:partitions:no_rows`).
 *   denied              the partition query was refused; no rows.
 *   unavailable         the class or namespace is reported missing; no rows. On a stock Windows
 *                       host this means a damaged WMI repository, not an OS that cannot answer
 *                       (the same limit firmware_posture documents, #4900).
 * A failed read is never rendered as an empty success, and a "-" mount point never stands for a
 * failed join.
 *
 * Determinism: rows are sorted by (disk, partition index, then DeviceID, size, type) so the
 * output is a pure function of the data. The daily-sync writer re-sorts the wire rows itself
 * (sync_source_device_ci.cpp), so this ordering is what makes the plugin's own output stable and
 * testable, not what protects the hashed blob.
 */
#pragma once

#include "disk_actions_legs.hpp"

#include <constraint_accumulator.hpp>
#include <inventory_status_row.hpp>
#include <wmi_error_token.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace yuzu::disk_actions::partitions {

/// One WMI row: property name -> value rendered as text (the shape wmi_bounded.hpp returns).
using Row = std::map<std::string, std::string>;

/// What one bounded query produced. `error` is the helper's token (empty on success);
/// `rows_before_error` is the helper's count of rows read before that failure (the shared
/// classifier needs it to tell a missing class from a fault after data came back).
struct QueryOutcome {
    std::vector<Row> rows;
    std::string error;
    bool truncated = false;
    std::size_t rows_before_error = 0;
};

enum class Level { Ok, Constrained, Denied, Unavailable };

/// The typed result status a Level maps to. `declare` is false for Ok: a clean read leaves the
/// status UNDECLARED so the agent derives OK with an empty provenance, exactly as `smart` and
/// `volumes` do -- an explicit OK/FULL would store a clean section with a reason, and FULL would
/// assert a completeness the descriptor (CONSTRAINED) says this class cannot give.
struct TypedStatus {
    bool declare = false;
    int status = YUZU_RESULT_STATUS_UNDECLARED;
    int completeness = YUZU_RESULT_COMPLETENESS_UNKNOWN;
};

[[nodiscard]] constexpr TypedStatus typed_status(Level level) noexcept {
    switch (level) {
    case Level::Ok:
        return {false, YUZU_RESULT_STATUS_UNDECLARED, YUZU_RESULT_COMPLETENESS_UNKNOWN};
    case Level::Constrained:
        return {true, YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL};
    case Level::Denied:
        return {true, YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL};
    case Level::Unavailable:
        return {true, YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL};
    }
    return {true, YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL};
}

struct Report {
    Level level = Level::Ok;
    std::string reason;                  // ConstraintAccumulator reason, "" when clean
    std::string status_row;              // always present, always first
    std::vector<std::string> data_rows;  // `partition|...`, sorted
};

namespace impl {

/// Strict unsigned decimal: digits only, no sign, no space, no overflow, non-empty.
[[nodiscard]] inline std::optional<std::uint64_t> parse_u64(std::string_view s) noexcept {
    if (s.empty())
        return std::nullopt;
    std::uint64_t v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9')
            return std::nullopt;
        const auto d = static_cast<std::uint64_t>(c - '0');
        if (v > (std::numeric_limits<std::uint64_t>::max() - d) / 10)
            return std::nullopt;
        v = v * 10 + d;
    }
    return v;
}

/// Classify a wmi_bounded.hpp error token with the SHARED stage-aware classifier
/// (agents/shared/wmi_error_token.hpp, the one firmware_posture and app_control use), so there
/// is a single WMI-token policy: a missing class counts as absent only at the stage and row
/// count where that answer is believable, everything unrecognised is a failed read.
[[nodiscard]] inline Level classify_error(std::string_view token, std::size_t rows_before_error) {
    switch (yuzu::shared::wmi_token::classify_wmi_error_token(token, rows_before_error)) {
    case yuzu::shared::wmi_token::WmiReadOutcome::denied:
        return Level::Denied;
    case yuzu::shared::wmi_token::WmiReadOutcome::absent:
        return Level::Unavailable;
    case yuzu::shared::wmi_token::WmiReadOutcome::ok:
    case yuzu::shared::wmi_token::WmiReadOutcome::failed:
        return Level::Constrained;
    }
    return Level::Constrained;
}

/// Pull the quoted value of `key` out of a CIM object path:
///   \\HOST\root\cimv2:Win32_LogicalDisk.DeviceID="C:"      -> C:
///   \\HOST\root\cimv2:Win32_DiskPartition.DeviceID="Disk #0, Partition #1"
/// The match is anchored to a key boundary (start of the string, or a preceding `.` or `,`), so
/// `XDeviceID="..."` is not `DeviceID`. CIM escapes `"` and `\` inside the quoted value with a
/// backslash; both are undone here. nullopt for a missing key, an unterminated string or a
/// dangling escape.
[[nodiscard]] inline std::optional<std::string> path_key_value(std::string_view path,
                                                               std::string_view key) {
    std::string needle(key);
    needle += "=\"";
    for (std::size_t at = path.find(needle); at != std::string_view::npos;
         at = path.find(needle, at + 1)) {
        if (at != 0 && path[at - 1] != '.' && path[at - 1] != ',')
            continue;
        std::string out;
        for (std::size_t i = at + needle.size(); i < path.size(); ++i) {
            const char c = path[i];
            if (c == '"')
                return out;
            if (c == '\\') {
                if (++i >= path.size())
                    return std::nullopt;
                out += path[i];
                continue;
            }
            out += c;
        }
        return std::nullopt; // unterminated
    }
    return std::nullopt;
}

/// "C:" (ASCII letter, any case) -> "C:\" ; anything else nullopt. ASCII only, with no
/// <cctype> call, so the answer cannot depend on the process locale. The trailing backslash is
/// added so the spelling matches GetVolumePathNamesForVolumeNameW, which `volumes` emits.
[[nodiscard]] inline std::optional<std::string> drive_letter_mount(std::string_view device_id) {
    if (device_id.size() != 2 || device_id[1] != ':')
        return std::nullopt;
    const char c = device_id[0];
    const bool upper = c >= 'A' && c <= 'Z';
    const bool lower = c >= 'a' && c <= 'z';
    if (!upper && !lower)
        return std::nullopt;
    std::string out;
    out += upper ? c : static_cast<char>(c - 'a' + 'A');
    out += ":\\";
    return out;
}

[[nodiscard]] inline std::string field(const Row& r, const char* key) {
    const auto it = r.find(key);
    return it == r.end() ? std::string{} : it->second;
}

struct Partition {
    std::uint64_t disk = 0;
    std::uint64_t index = 0;
    std::string device_id;
    std::optional<std::uint64_t> size;
    std::string type;
};

/// Fill `rep` from the accumulator and the level. Not a lambda: a captured-by-reference return
/// would copy the Report.
inline void finalize(Report& rep, const yuzu::shared::ConstraintAccumulator& acc, Level level) {
    rep.level = level;
    rep.reason = acc.reason();
    // The three-word row vocabulary has no "refused": a denied read is `constrained` (the OS can
    // answer, this account was not allowed to hear it) and only a source reported missing is
    // `unsupported`. The typed result status carries the exact four-way answer.
    const auto lv = level == Level::Ok
                        ? yuzu::shared::StatusLevel::supported
                        : (level == Level::Unavailable ? yuzu::shared::StatusLevel::unsupported
                                                       : yuzu::shared::StatusLevel::constrained);
    rep.status_row = yuzu::shared::format_status_row("partitions", lv, rep.reason);
}

} // namespace impl

/// Build the status row and the sorted data rows. `links` is consulted only when `parts`
/// succeeded; the Windows TU skips running it otherwise.
[[nodiscard]] inline Report build_report(const QueryOutcome& parts, const QueryOutcome& links) {
    Report rep;
    yuzu::shared::ConstraintAccumulator acc;

    if (!parts.error.empty()) {
        // A failed query never keeps rows (wmi_bounded.hpp clears them); the level says why.
        acc.add_failure("windows:partitions:" + parts.error);
        impl::finalize(rep, acc, impl::classify_error(parts.error, parts.rows_before_error));
        return rep;
    }

    // ── partitions ──────────────────────────────────────────────────────────
    std::vector<impl::Partition> list;
    bool row_unparsed = false;
    for (const Row& r : parts.rows) {
        const auto disk = impl::parse_u64(impl::field(r, "DiskIndex"));
        const auto index = impl::parse_u64(impl::field(r, "Index"));
        if (!disk || !index) {
            row_unparsed = true; // cannot name it, so it cannot be a row
            continue;
        }
        impl::Partition p;
        p.disk = *disk;
        p.index = *index;
        p.device_id = impl::field(r, "DeviceID");
        if (p.device_id.empty())
            p.device_id = "Disk #" + std::to_string(p.disk) + ", Partition #" + std::to_string(p.index);
        p.size = impl::parse_u64(impl::field(r, "Size"));
        p.type = impl::field(r, "Type");
        list.push_back(std::move(p));
    }
    if (row_unparsed)
        acc.add_failure("windows:partitions:row_unparsed");
    if (parts.truncated) {
        acc.add_failure("windows:partitions:row_cap");
        acc.mark_incomplete();
    }
    // A booted Windows host always has a system partition, so a clean answer with none is a
    // provider fault (a damaged repository answering S_OK with nothing). An unparsable row is
    // already reported above; this is the case where WMI returned nothing at all.
    if (parts.rows.empty())
        acc.add_failure("windows:partitions:no_rows");

    // ── drive letters ───────────────────────────────────────────────────────
    const bool links_ok = links.error.empty();
    bool mounts_partial = false; // some association rows were unusable, or the query hit its cap
    std::map<std::string, std::set<std::string>> mounts; // partition DeviceID -> sorted letters
    if (!links_ok) {
        acc.add_failure("windows:partitions:mount_points:" + links.error);
    } else {
        bool link_unparsed = false;
        for (const Row& r : links.rows) {
            const auto part = impl::path_key_value(impl::field(r, "Antecedent"), "DeviceID");
            const auto disk = impl::path_key_value(impl::field(r, "Dependent"), "DeviceID");
            const auto mount = disk ? impl::drive_letter_mount(*disk) : std::nullopt;
            if (!part || !mount) {
                link_unparsed = true;
                continue;
            }
            mounts[*part].insert(*mount);
        }
        if (link_unparsed) {
            acc.add_failure("windows:partitions:mount_points:link_unparsed");
            mounts_partial = true;
        }
        if (links.truncated) {
            acc.add_failure("windows:partitions:mount_points:row_cap");
            acc.mark_incomplete();
            mounts_partial = true;
        }
    }

    std::sort(list.begin(), list.end(), [](const impl::Partition& a, const impl::Partition& b) {
        return std::tie(a.disk, a.index, a.device_id, a.size, a.type) <
               std::tie(b.disk, b.index, b.device_id, b.size, b.type);
    });

    for (const impl::Partition& p : list) {
        std::string mount_points = "-";
        bool matched = false;
        if (links_ok) {
            if (const auto it = mounts.find(p.device_id); it != mounts.end()) {
                matched = true;
                mount_points.clear();
                for (const std::string& m : it->second) {
                    if (!mount_points.empty())
                        mount_points += ',';
                    mount_points += m;
                }
            }
        }
        std::string row = "partition|";
        row += yuzu::util::safe_output_field("PhysicalDrive" + std::to_string(p.disk));
        row += '|';
        row += yuzu::util::safe_output_field(p.device_id);
        row += '|';
        row += yuzu::disk_actions::detail::format_optional_bytes(p.size);
        row += '|';
        row += p.type.empty() ? std::string{"-"} : yuzu::util::safe_output_field(p.type);
        row += '|';
        row += yuzu::util::safe_output_field(mount_points);
        row += '|';
        if (!links_ok)
            row += "wmi,mount_points_unread";
        else if (mounts_partial && !matched)
            row += "wmi,mount_points_partial"; // this "-" may be a row we could not read
        else
            row += "wmi";
        rep.data_rows.push_back(std::move(row));
    }

    impl::finalize(rep, acc, acc.any_failure() || acc.incomplete() ? Level::Constrained : Level::Ok);
    return rep;
}

} // namespace yuzu::disk_actions::partitions
