/**
 * bitlocker_linux_parsers.hpp — pure dm-crypt/LUKS state parsing for the
 * bitlocker plugin's Linux leg (rung-1 promotion off lsblk+cryptsetup
 * shell-outs).
 *
 * Acquisition (bitlocker_plugin.cpp's __linux__ branch) is two in-process
 * reads, no subprocess:
 *   - libblkid TYPE probing enumerates each raw "crypto_LUKS" superblock
 *     (blkid_get_tag_value(..., "TYPE", ...) == "crypto_LUKS", plus its
 *     "UUID" tag) — a system pkg-config library (util-linux), not vcpkg;
 *   - /sys/class/block/dm-N/dm/{name,uuid} plain file reads enumerate
 *     currently-open (mapped) dm-crypt devices. The kernel exposes the
 *     backing LUKS UUID and mapper name there natively — no cryptsetup
 *     subprocess needed to learn open/closed state.
 *
 * Everything past those two raw reads is pure and lives here: parsing the
 * dm-crypt uuid sysfs string, matching an open mapping back to the LUKS
 * device that backs it, and formatting the output row. Fixture-testable
 * without root, a real block device, or an open LUKS volume.
 *
 * dm-crypt's /sys/class/block/dm-N/dm/uuid format is
 * "CRYPT-<SUBSYS>-<uuid-no-dashes>-<mapper-name>" — documented in
 * cryptsetup's own libdevmapper naming (crypt_get_uuid / dm-crypt.c
 * DM_UUID_PREFIX "CRYPT-"), with SUBSYS one of "LUKS1"/"LUKS2" for a LUKS
 * volume ("PLAIN"/"TCRYPT"/"VERITY"/etc for other dm-crypt-family targets).
 * Confidence is HIGH for the "CRYPT-" prefix and the LUKS1/LUKS2 subsys
 * tokens — both are long-stable cryptsetup constants used verbatim in its
 * source and in kernel/distro documentation of the device-mapper uuid
 * convention. The fixtures below are SYNTHETIC, built to that documented
 * shape: a privileged Docker loopback-LUKS capture was attempted for this
 * migration, but no Docker daemon was reachable in the sandbox this was
 * written in (see the migration's commit message) — this is noted here
 * rather than silently presented as a real capture.
 */
#pragma once

#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::bitlocker::linux_dm {

/// A raw LUKS-formatted block device, as found by a libblkid
/// TYPE=="crypto_LUKS" scan. `uuid` is blkid's own canonical dashed form
/// (e.g. "a1b2c3d4-e5f6-47a1-b2c3-d4e5f6a7b8c9").
struct LuksBlockDevice {
    std::string dev_name; // e.g. "sda2" (basename only, no /dev/ prefix)
    std::string uuid;     // dashed LUKS UUID, as blkid reports it
};

/// One currently-open (mapped) dm-crypt device, decoded from
/// /sys/class/block/dm-N/dm/uuid.
struct DmCryptMapping {
    std::string dm_name;        // e.g. "dm-1" — the sysfs entry's own name
    std::string mapper_name;    // e.g. "cryptroot" — the /dev/mapper/<name> the caller sees
    std::string luks_version;   // "LUKS1" | "LUKS2" | "" (a non-LUKS dm-crypt target)
    std::string uuid_no_dashes; // 32 hex chars, straight from the uuid string
};

namespace detail {

inline bool is_hex32(std::string_view s) {
    if (s.size() != 32)
        return false;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c)))
            return false;
    }
    return true;
}

inline std::string normalize_uuid(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '-')
            continue;
        out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

} // namespace detail

/// Insert the canonical 8-4-4-4-12 dashes into a 32-character hex UUID.
/// Returns the input unchanged if it isn't exactly 32 hex characters —
/// never fabricates dashes into a malformed value.
inline std::string add_uuid_dashes(std::string_view hex32) {
    if (!detail::is_hex32(hex32))
        return std::string(hex32);
    std::string out;
    out.reserve(36);
    out += hex32.substr(0, 8);
    out += '-';
    out += hex32.substr(8, 4);
    out += '-';
    out += hex32.substr(12, 4);
    out += '-';
    out += hex32.substr(16, 4);
    out += '-';
    out += hex32.substr(20, 12);
    return out;
}

/// Parse one /sys/class/block/dm-N/dm/uuid file's content into a
/// DmCryptMapping. dm-crypt's naming convention is
/// "CRYPT-<SUBSYS>-<uuid-no-dashes>-<mapper-name>" — SUBSYS is "LUKS1",
/// "LUKS2", "PLAIN", "TCRYPT", etc; the mapper name itself may contain
/// dashes, so it is taken as everything after the second dash rather than
/// split further. A non-"CRYPT-" prefix (e.g. LVM's "LVM-...", multipath's
/// "mpath-...") returns std::nullopt — this function only classifies
/// dm-crypt targets. Trailing whitespace/newline, as sysfs files carry, is
/// trimmed first.
inline std::optional<DmCryptMapping> parse_dm_uuid(std::string_view dm_name,
                                                    std::string_view uuid_content) {
    std::string_view uuid = uuid_content;
    while (!uuid.empty() && (uuid.back() == '\n' || uuid.back() == '\r' || uuid.back() == ' '))
        uuid.remove_suffix(1);

    constexpr std::string_view kPrefix = "CRYPT-";
    if (uuid.substr(0, kPrefix.size()) != kPrefix)
        return std::nullopt;
    uuid.remove_prefix(kPrefix.size());

    auto first_dash = uuid.find('-');
    if (first_dash == std::string_view::npos)
        return std::nullopt;
    std::string_view subsys = uuid.substr(0, first_dash);
    uuid.remove_prefix(first_dash + 1);

    auto second_dash = uuid.find('-');
    if (second_dash == std::string_view::npos)
        return std::nullopt;
    std::string_view uuid_hex = uuid.substr(0, second_dash);
    std::string_view mapper_name = uuid.substr(second_dash + 1);

    if (!detail::is_hex32(uuid_hex) || mapper_name.empty())
        return std::nullopt;

    DmCryptMapping mapping;
    mapping.dm_name = std::string(dm_name);
    mapping.mapper_name = std::string(mapper_name);
    mapping.uuid_no_dashes = std::string(uuid_hex);
    if (subsys == "LUKS1" || subsys == "LUKS2")
        mapping.luks_version = std::string(subsys);
    // else: a real dm-crypt target (PLAIN/TCRYPT/etc) — leave luks_version
    // empty rather than guessing a LUKS generation that wasn't reported.
    return mapping;
}

/// Whether any of `mappings` is the open dm-crypt device backing `device`
/// — a UUID match, dashes-and-case normalized on both sides (blkid and
/// /sys have been observed to differ in hex letter case; dm/uuid never
/// carries dashes at all).
inline bool has_open_mapping(const LuksBlockDevice& device,
                             const std::vector<DmCryptMapping>& mappings) {
    const std::string device_norm = detail::normalize_uuid(device.uuid);
    for (const auto& m : mappings) {
        if (detail::normalize_uuid(m.uuid_no_dashes) == device_norm)
            return true;
    }
    return false;
}

/// Format one output row, in the plugin's pre-migration 4-token shape
/// (`volume|<name>|<type>|<state>`). `type` stays the literal
/// "crypto_LUKS" for every row (this plugin only ever reports LUKS
/// volumes, open or not) so an existing consumer keyed on that literal
/// keeps matching; `state` is "active" when an open dm-crypt mapping was
/// found for this device's UUID, "inactive" otherwise — the same two
/// states cryptsetup's own "is active"/"is inactive" reported, now derived
/// from /sys instead of a subprocess.
inline std::string format_volume_row(const std::string& dev_name, bool active) {
    return "volume|" + dev_name + "|crypto_LUKS|" + (active ? "active" : "inactive");
}

} // namespace yuzu::bitlocker::linux_dm
