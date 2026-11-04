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
 *   detail        a fixed token, never free text: "wmi", or "wmi,mount_points_unread" when the
 *                 association query failed so a "-" in mount_points means UNKNOWN, not none.
 *
 * KNOWN GAP, MEASURED: Win32_DiskPartition does not list the 16 MiB Microsoft Reserved
 * partition (a GPT disk shows one fewer partition than MSFT_Partition). The section is therefore
 * the partitions Windows exposes through Win32_DiskPartition, not a byte-exact map of the disk.
 *
 * OUTCOME CONTRACT (the same four levels as the hardware estate legs; rc is 0 for every one)
 *   supported / OK      both queries answered cleanly; zero rows means WMI reported no partitions.
 *   constrained         a partial read: a row or an association the parser could not use, a row
 *                       cap, or the association query failed (the partitions are kept, their
 *                       mount points are unknown and say so).
 *   denied              the partition query was refused; no rows.
 *   unavailable         the class or namespace does not exist; no rows.
 * A failed read is never rendered as an empty success, and a "-" mount point never stands for a
 * failed join.
 *
 * Determinism: rows are sorted by (disk, partition index), because the daily-sync blob is hashed
 * and an enumeration-order change must not read as a changed device.
 */
#pragma once

#include "disk_actions_legs.hpp"

#include <constraint_accumulator.hpp>
#include <inventory_status_row.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::disk_actions::partitions {

/// One WMI row: property name -> value rendered as text (the shape wmi_bounded.hpp returns).
using Row = std::map<std::string, std::string>;

/// What one bounded query produced. `error` is the helper's token (empty on success).
struct QueryOutcome {
    std::vector<Row> rows;
    std::string error;
    bool truncated = false;
};

enum class Level { Ok, Constrained, Denied, Unavailable };

struct Report {
    Level level = Level::Ok;
    std::string reason;                  // ConstraintAccumulator reason, "" when clean
    std::string status_row;              // always present, always first
    std::vector<std::string> data_rows;  // `partition|...`, sorted
};

namespace detail {

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

[[nodiscard]] inline std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/// Classify a wmi_bounded.hpp error token. The HRESULT is rendered `0x........` by the helper.
///   0x80041003 WBEM_E_ACCESS_DENIED, 0x80070005 E_ACCESSDENIED      -> Denied
///   0x80041010 WBEM_E_INVALID_CLASS, 0x8004100e WBEM_E_INVALID_NAMESPACE -> Unavailable
/// Everything else (timeout, transport, provider fault) is a failed read, never an absence.
[[nodiscard]] inline Level classify_error(std::string_view token) {
    const std::string t = lower(token);
    const auto has = [&](std::string_view needle) { return t.find(needle) != std::string::npos; };
    if (has("0x80041003") || has("0x80070005"))
        return Level::Denied;
    if (has("0x80041010") || has("0x8004100e"))
        return Level::Unavailable;
    return Level::Constrained;
}

/// Pull the quoted value of `key` out of a CIM object path:
///   \\HOST\root\cimv2:Win32_LogicalDisk.DeviceID="C:"      -> C:
///   \\HOST\root\cimv2:Win32_DiskPartition.DeviceID="Disk #0, Partition #1"
/// CIM escapes `"` and `\` inside the quoted value with a backslash; both are undone here.
/// nullopt for a missing key, an unterminated string or a dangling escape.
[[nodiscard]] inline std::optional<std::string> path_key_value(std::string_view path,
                                                               std::string_view key) {
    std::string needle(key);
    needle += "=\"";
    const auto at = path.find(needle);
    if (at == std::string_view::npos)
        return std::nullopt;
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

/// "C:" (any case) -> "C:\" ; anything else nullopt. The trailing backslash is added so the
/// spelling matches GetVolumePathNamesForVolumeNameW, which `volumes` emits.
[[nodiscard]] inline std::optional<std::string> drive_letter_mount(std::string_view device_id) {
    if (device_id.size() != 2 || device_id[1] != ':')
        return std::nullopt;
    const auto c = static_cast<unsigned char>(device_id[0]);
    if (!std::isalpha(c))
        return std::nullopt;
    std::string out;
    out += static_cast<char>(std::toupper(c));
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

} // namespace detail

/// Build the status row and the sorted data rows. `links` is consulted only when `parts`
/// succeeded; the Windows TU skips running it otherwise.
[[nodiscard]] inline Report build_report(const QueryOutcome& parts, const QueryOutcome& links) {
    Report rep;
    yuzu::shared::ConstraintAccumulator acc;
    const auto finish = [&](Level level) {
        rep.level = level;
        rep.reason = acc.reason();
        // The three-word row vocabulary has no "refused": a denied read is `constrained` (the
        // OS can answer, this account was not allowed to hear it) and only a source that does
        // not exist is `unsupported`. The typed result status carries the exact four-way answer.
        const auto lv = level == Level::Ok
                            ? yuzu::shared::StatusLevel::supported
                            : (level == Level::Unavailable ? yuzu::shared::StatusLevel::unsupported
                                                           : yuzu::shared::StatusLevel::constrained);
        rep.status_row = yuzu::shared::format_status_row("partitions", lv, rep.reason);
        return rep;
    };

    if (!parts.error.empty()) {
        // A failed query never keeps rows (wmi_bounded.hpp clears them); the level says why.
        acc.add_failure("windows:partitions:" + parts.error);
        return finish(detail::classify_error(parts.error));
    }

    // ── partitions ──────────────────────────────────────────────────────────
    std::vector<detail::Partition> list;
    bool row_unparsed = false;
    for (const Row& r : parts.rows) {
        const auto disk = detail::parse_u64(detail::field(r, "DiskIndex"));
        const auto index = detail::parse_u64(detail::field(r, "Index"));
        if (!disk || !index) {
            row_unparsed = true; // cannot name it, so it cannot be a row
            continue;
        }
        detail::Partition p;
        p.disk = *disk;
        p.index = *index;
        p.device_id = detail::field(r, "DeviceID");
        if (p.device_id.empty())
            p.device_id = "Disk #" + std::to_string(p.disk) + ", Partition #" + std::to_string(p.index);
        p.size = detail::parse_u64(detail::field(r, "Size"));
        p.type = detail::field(r, "Type");
        list.push_back(std::move(p));
    }
    if (row_unparsed)
        acc.add_failure("windows:partitions:row_unparsed");
    if (parts.truncated) {
        acc.add_failure("windows:partitions:row_cap");
        acc.mark_incomplete();
    }

    // ── drive letters ───────────────────────────────────────────────────────
    const bool links_ok = links.error.empty();
    std::map<std::string, std::set<std::string>> mounts; // partition DeviceID -> sorted letters
    if (!links_ok) {
        acc.add_failure("windows:partitions:mount_points:" + links.error);
    } else {
        bool link_unparsed = false;
        for (const Row& r : links.rows) {
            const auto part = detail::path_key_value(detail::field(r, "Antecedent"), "DeviceID");
            const auto disk = detail::path_key_value(detail::field(r, "Dependent"), "DeviceID");
            const auto mount = disk ? detail::drive_letter_mount(*disk) : std::nullopt;
            if (!part || !mount) {
                link_unparsed = true;
                continue;
            }
            mounts[*part].insert(*mount);
        }
        if (link_unparsed)
            acc.add_failure("windows:partitions:mount_points:link_unparsed");
        if (links.truncated) {
            acc.add_failure("windows:partitions:mount_points:row_cap");
            acc.mark_incomplete();
        }
    }

    std::sort(list.begin(), list.end(), [](const detail::Partition& a, const detail::Partition& b) {
        return a.disk != b.disk ? a.disk < b.disk : a.index < b.index;
    });

    for (const detail::Partition& p : list) {
        std::string mount_points = "-";
        if (links_ok) {
            if (const auto it = mounts.find(p.device_id); it != mounts.end()) {
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
        row += links_ok ? "wmi" : "wmi,mount_points_unread";
        rep.data_rows.push_back(std::move(row));
    }

    return finish(acc.any_failure() || acc.incomplete() ? Level::Constrained : Level::Ok);
}

} // namespace yuzu::disk_actions::partitions
