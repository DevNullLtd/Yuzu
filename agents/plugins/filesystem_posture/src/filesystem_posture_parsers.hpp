/**
 * filesystem_posture_parsers.hpp — pure parsing/classification logic for the
 * filesystem_posture plugin (mounts/quotas/snapshots).
 *
 * Every function here is a pure, inline free function: no I/O, no logging,
 * no OS headers. Callers (the three per-OS leg TUs) do all the syscalls and
 * hand the raw bytes/values to these functions to decode or classify. This
 * keeps the parsing logic testable without a build dir, a live filesystem,
 * or root privilege — see tests/unit/test_filesystem_posture_parsers.cpp.
 */
#pragma once

#include <network_fstype.hpp> // yuzu::shared::is_network_fstype (agents/shared)

#include <cstddef> // std::size_t, std::byte -- previously transitive via <span>/<vector>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::filesystem_posture {

namespace detail {

// Splits on runs of ' '/'\t' (mountinfo's field separator). Octal-escaped
// bytes (e.g. \040 for a literal space in a path) never appear as raw
// whitespace in the source text, so a plain byte-wise split is correct here.
inline std::vector<std::string_view> split_ws(std::string_view line) {
    std::vector<std::string_view> out;
    std::size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
            ++i;
        if (i >= line.size())
            break;
        const std::size_t start = i;
        while (i < line.size() && line[i] != ' ' && line[i] != '\t')
            ++i;
        out.push_back(line.substr(start, i - start));
    }
    return out;
}

// Decimal-integer token parsers with no exceptions and no <charconv>
// dependency (kept out of this header's allowed-include list). A non-numeric
// token is reported via the bool return so the caller can treat the whole
// line as malformed rather than substituting a fabricated 0.
inline bool parse_int_token(std::string_view s, int& out) {
    if (s.empty())
        return false;
    std::size_t i = 0;
    bool neg = false;
    if (s[0] == '-') {
        neg = true;
        i = 1;
    }
    if (i >= s.size())
        return false;
    // Checked accumulation against the destination range -- an
    // out-of-range mountinfo field is rejected rather than silently
    // wrapped by a cast. Bounds computed from sizeof(int) rather than
    // <climits>/<limits> to keep this header's include list pure.
    constexpr long long kMax = (1LL << (sizeof(int) * 8 - 1)) - 1;
    constexpr long long kMinMag = 1LL << (sizeof(int) * 8 - 1);
    const long long limit = neg ? kMinMag : kMax;
    long long val = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        val = val * 10 + (s[i] - '0');
        if (val > limit)
            return false;
    }
    out = static_cast<int>(neg ? -val : val);
    return true;
}

inline bool parse_uint_token(std::string_view s, unsigned& out) {
    if (s.empty())
        return false;
    constexpr unsigned long long kMax = (1ull << (sizeof(unsigned) * 8)) - 1;
    unsigned long long val = 0;
    for (char c : s) {
        if (c < '0' || c > '9')
            return false;
        val = val * 10 + static_cast<unsigned long long>(c - '0');
        if (val > kMax)
            return false;
    }
    out = static_cast<unsigned>(val);
    return true;
}

inline std::uint32_t read_le_u32(std::span<const std::byte> buf, std::size_t offset) {
    std::uint32_t v = 0;
    std::memcpy(&v, buf.data() + offset, sizeof(v));
    return v;
}

inline std::int32_t read_le_i32(std::span<const std::byte> buf, std::size_t offset) {
    std::uint32_t raw = read_le_u32(buf, offset);
    std::int32_t v;
    std::memcpy(&v, &raw, sizeof(v));
    return v;
}

} // namespace detail

// ── mountinfo ────────────────────────────────────────────────────────────

struct MountinfoEntry {
    int mount_id;
    int parent_id;
    unsigned major;
    unsigned minor;
    std::string root;
    std::string mount_point;
    std::string mount_options;
    std::vector<std::string> optional_fields;
    std::string fstype;
    std::string mount_source;
    std::string super_options;
};

struct MountinfoParse {
    std::vector<MountinfoEntry> entries;
    std::size_t malformed_lines;
    bool truncated;
};

/**
 * Decode `\NNN` octal escapes mountinfo uses for bytes that can't appear raw
 * in a whitespace-delimited field (space, tab, newline, backslash). A
 * malformed or unrecognized escape (not a run of exactly three octal digits,
 * or a recognized-shape escape whose value isn't one of the four known ones)
 * is emitted LITERALLY — copied through byte for byte — never dropped, so a
 * decode surprise never silently loses bytes.
 */
inline std::string unescape_mountinfo_octal(std::string_view field) {
    std::string out;
    out.reserve(field.size());
    std::size_t i = 0;
    while (i < field.size()) {
        if (field[i] == '\\' && i + 3 < field.size() && field[i + 1] >= '0' &&
            field[i + 1] <= '7' && field[i + 2] >= '0' && field[i + 2] <= '7' &&
            field[i + 3] >= '0' && field[i + 3] <= '7') {
            const int val = (field[i + 1] - '0') * 64 + (field[i + 2] - '0') * 8 +
                            (field[i + 3] - '0');
            switch (val) {
            case 040: // octal 040 == 0x20 space
                out += ' ';
                break;
            case 011: // octal 011 == 0x09 tab
                out += '\t';
                break;
            case 012: // octal 012 == 0x0A newline
                out += '\n';
                break;
            case 0134: // octal 134 == 0x5C backslash
                out += '\\';
                break;
            default:
                // Well-formed 3-digit octal escape, but not one of the four
                // mountinfo actually emits -- pass it through literally.
                out.append(field.substr(i, 4));
                break;
            }
            i += 4;
        } else {
            out += field[i];
            ++i;
        }
    }
    return out;
}

/**
 * Parse /proc/self/mountinfo (or /proc/<pid>/mountinfo) text.
 *
 * Fields 1-6 are fixed (mount_id, parent_id, major:minor, root, mount_point,
 * mount_options), followed by a VARIABLE number of single-token optional
 * fields, a literal "-" separator, then exactly three trailing fields
 * (fstype, mount_source, super_options) -- each of those trailing three is
 * itself always a single whitespace-free token, so the separator's position
 * is exactly `tokens.size() - 4`: this both locates "the last standalone '-'
 * token before exactly three remaining fields" and pins it precisely,
 * without needing to search from the right for a bare "-".
 *
 * A line with too few tokens, or whose token at that fixed position isn't
 * "-", increments `malformed_lines` and is skipped -- the walk never aborts
 * on one bad line.
 */
inline MountinfoParse parse_proc_mountinfo(std::string_view text, std::size_t max_entries = 4096) {
    MountinfoParse result{{}, 0, false};
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const std::size_t nl = text.find('\n', pos);
        std::string_view line =
            (nl == std::string_view::npos) ? text.substr(pos) : text.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        if (!line.empty()) {
            if (result.entries.size() >= max_entries) {
                result.truncated = true;
                break;
            }

            auto tokens = detail::split_ws(line);
            if (tokens.size() < 10) {
                ++result.malformed_lines;
            } else {
                const std::size_t dash_index = tokens.size() - 4;
                if (dash_index < 6 || tokens[dash_index] != "-") {
                    ++result.malformed_lines;
                } else {
                    MountinfoEntry e;
                    unsigned dev_major = 0;
                    unsigned dev_minor = 0;
                    bool ok = detail::parse_int_token(tokens[0], e.mount_id) &&
                              detail::parse_int_token(tokens[1], e.parent_id);
                    if (ok) {
                        const auto colon = tokens[2].find(':');
                        ok = colon != std::string_view::npos &&
                             detail::parse_uint_token(tokens[2].substr(0, colon), dev_major) &&
                             detail::parse_uint_token(tokens[2].substr(colon + 1), dev_minor);
                    }
                    if (!ok) {
                        ++result.malformed_lines;
                    } else {
                        e.major = dev_major;
                        e.minor = dev_minor;
                        e.root = unescape_mountinfo_octal(tokens[3]);
                        e.mount_point = unescape_mountinfo_octal(tokens[4]);
                        e.mount_options = std::string(tokens[5]);
                        for (std::size_t k = 6; k < dash_index; ++k)
                            e.optional_fields.emplace_back(tokens[k]);
                        e.fstype = std::string(tokens[dash_index + 1]);
                        e.mount_source = std::string(tokens[dash_index + 2]);
                        e.super_options = std::string(tokens[dash_index + 3]);
                        result.entries.push_back(std::move(e));
                    }
                }
            }
        }

        if (nl == std::string_view::npos)
            break;
        pos = nl + 1;
    }
    return result;
}

// ── quota state classification ──────────────────────────────────────────

enum class QuotaState {
    Configured,
    None,
    NotEnabled,
    UnsupportedFs,
    NoBlockDevice,
    PermissionDenied,
    Unavailable
};

inline std::string_view quota_state_token(QuotaState state) {
    switch (state) {
    case QuotaState::Configured:
        return "configured";
    case QuotaState::None:
        return "none";
    case QuotaState::NotEnabled:
        return "not_enabled";
    case QuotaState::UnsupportedFs:
        return "unsupported_fs";
    case QuotaState::NoBlockDevice:
        return "no_block_device";
    case QuotaState::PermissionDenied:
        return "permission_denied";
    case QuotaState::Unavailable:
        return "unavailable";
    }
    return "unavailable";
}

/**
 * Classify a Linux quotactl(2) errno into a QuotaState. Evidence provenance
 * is deliberately split (peer M7): ESRCH/ENOSYS/ENOENT below were actually
 * observed on captures/linux-quotactl-probe.txt (2026-09-02, a privileged
 * VM probe against /dev/vda1, /dev/root, overlay and a nonexistent path).
 * ENOTBLK/EPERM/EACCES/other/0 are documented-inference from quotactl(2)'s
 * man page -- the probe never produced them on the one available VM. Both
 * groups are pinned test-side with distinct labels; see
 * test_filesystem_posture_parsers.cpp.
 */
inline QuotaState classify_quotactl_errno(int err) {
    if (err == 3) // ESRCH
        return QuotaState::NotEnabled;
    if (err == 38) // ENOSYS
        return QuotaState::UnsupportedFs;
    if (err == 2) // ENOENT
        return QuotaState::NoBlockDevice;
    if (err == 15) // ENOTBLK -- documented-inference, not capture-backed
        return QuotaState::NoBlockDevice;
    if (err == 1) // EPERM -- documented-inference
        return QuotaState::PermissionDenied;
    if (err == 13) // EACCES -- documented-inference
        return QuotaState::PermissionDenied;
    if (err == 0)
        return QuotaState::Configured;
    return QuotaState::Unavailable;
}

/**
 * Classify a macOS getattrlist(2) ATTR_VOL_QUOTA_SIZE/ATTR_VOL_RESERVED_SIZE
 * read (peer M14: `err` is meaningful here, unlike an earlier draft that
 * ignored it on failure). `rc`/`err` are the raw getattrlist() return value
 * and errno; `quota_size`/`reserved_size` are only meaningful when rc == 0.
 */
inline QuotaState classify_getattrlist_quota(int rc, int err, unsigned long long quota_size,
                                             unsigned long long reserved_size) {
    if (rc != 0) {
        if (err == 1 || err == 13) // EPERM / EACCES
            return QuotaState::PermissionDenied;
        if (err == 45) // ENOTSUP (macOS value; distinct from EOPNOTSUPP)
            return QuotaState::UnsupportedFs;
        return QuotaState::Unavailable;
    }
    if (quota_size == 0 && reserved_size == 0)
        return QuotaState::None;
    return QuotaState::Configured;
}

// ── btrfs / device-mapper detection ─────────────────────────────────────

struct BtrfsSubvolume {
    bool present;
    std::string subvol;
    std::string subvolid;
};

/// Parse a btrfs mount's comma-separated super_options field for
/// `subvol=<path>` and `subvolid=<id>`. Neither key present => !present.
inline BtrfsSubvolume parse_btrfs_super_options(std::string_view super_options) {
    BtrfsSubvolume out{false, {}, {}};
    std::size_t pos = 0;
    while (pos <= super_options.size()) {
        const std::size_t comma = super_options.find(',', pos);
        std::string_view tok = (comma == std::string_view::npos)
                                   ? super_options.substr(pos)
                                   : super_options.substr(pos, comma - pos);
        if (tok.rfind("subvolid=", 0) == 0) {
            out.subvolid = std::string(tok.substr(9));
            out.present = true;
        } else if (tok.rfind("subvol=", 0) == 0) {
            out.subvol = std::string(tok.substr(7));
            out.present = true;
        }
        if (comma == std::string_view::npos)
            break;
        pos = comma + 1;
    }
    return out;
}

/// Pinned predicate (peer M4): true iff `mount_source` begins with
/// "/dev/mapper/", OR matches "/dev/dm-<digits>" exactly.
inline bool is_device_mapper_source(std::string_view mount_source) {
    if (mount_source.rfind("/dev/mapper/", 0) == 0)
        return true;
    constexpr std::string_view kPrefix = "/dev/dm-";
    if (mount_source.rfind(kPrefix, 0) != 0)
        return false;
    auto rest = mount_source.substr(kPrefix.size());
    if (rest.empty())
        return false;
    for (char c : rest) {
        if (c < '0' || c > '9')
            return false;
    }
    return true;
}

// ── flags / fstype classification ───────────────────────────────────────

/**
 * Map a comma-separated mountinfo field-6 options list onto the fixed
 * output vocabulary `ro,rw,nosuid,nodev,noexec,noatime,relatime`, always
 * emitted in that order. Any token not in the vocabulary is DROPPED, never
 * passed through -- the wire flags column can never carry attacker text.
 */
inline std::string normalize_mount_flags(std::string_view options_csv) {
    bool has_ro = false, has_rw = false, has_nosuid = false, has_nodev = false, has_noexec = false,
         has_noatime = false, has_relatime = false;
    std::size_t pos = 0;
    while (pos <= options_csv.size()) {
        const std::size_t comma = options_csv.find(',', pos);
        std::string_view tok = (comma == std::string_view::npos)
                                   ? options_csv.substr(pos)
                                   : options_csv.substr(pos, comma - pos);
        if (tok == "ro")
            has_ro = true;
        else if (tok == "rw")
            has_rw = true;
        else if (tok == "nosuid")
            has_nosuid = true;
        else if (tok == "nodev")
            has_nodev = true;
        else if (tok == "noexec")
            has_noexec = true;
        else if (tok == "noatime")
            has_noatime = true;
        else if (tok == "relatime")
            has_relatime = true;
        if (comma == std::string_view::npos)
            break;
        pos = comma + 1;
    }
    std::string out;
    auto append = [&out](bool has, const char* name) {
        if (!has)
            return;
        if (!out.empty())
            out += ',';
        out += name;
    };
    append(has_ro, "ro");
    append(has_rw, "rw");
    append(has_nosuid, "nosuid");
    append(has_nodev, "nodev");
    append(has_noexec, "noexec");
    append(has_noatime, "noatime");
    append(has_relatime, "relatime");
    return out;
}

/// True for filesystem types whose `statvfs` can block indefinitely against an
/// unreachable server.
///
/// WHY THIS MATTERS MORE THAN A CAPACITY COLUMN (governance G4-04): every agent
/// command runs on ONE bounded pool shared with every other plugin, INCLUDING
/// quarantine/containment dispatch. An uninterruptible `statvfs` permanently
/// consumes a worker; a scheduled `mounts` instruction can exhaust the pool,
/// after which no command reaches the host at all. A name this list misses is
/// therefore an availability risk, not a missing number.
///
/// The deny-list itself (and its known gaps) lives in agents/shared/network_fstype.hpp, shared
/// with the runtimes plugin's directory walk.
using yuzu::shared::is_network_fstype;

// ── snapshot enumeration decoders ───────────────────────────────────────

struct SnapshotNames {
    std::vector<std::string> names;
    bool truncated;
    bool malformed;
};

/**
 * Decode a macOS fs_snapshot_list(2) result buffer (the exact record layout
 * verified byte-for-byte against captures/macos-fs_snapshot_list-root.hex):
 *
 *   [0..3]   uint32 record_length
 *   [4..23]  attribute_set_t (five uint32: common, vol, dir, file, fork)
 *   [24..27] int32  attr_dataoffset  (relative to offset 24)
 *   [28..31] uint32 attr_length      (name bytes INCLUDING the NUL)
 *   [24 + attr_dataoffset ...] the NUL-terminated name
 *
 * Walks `returned_count` records. Every offset derived from record fields is
 * bounds-checked against the remaining span BEFORE any dereference; a
 * violation sets `malformed = true` and stops the walk rather than reading
 * past the buffer or continuing over corrupt data.
 */
inline SnapshotNames parse_fs_snapshot_list_buffer(std::span<const std::byte> buf,
                                                   int returned_count,
                                                   std::size_t max_names = 1024) {
    SnapshotNames out{{}, false, false};
    std::size_t offset = 0;
    for (int i = 0; i < returned_count; ++i) {
        if (out.names.size() >= max_names) {
            out.truncated = true;
            break;
        }
        // Fixed 32-byte header: record_length(4) + attribute_set_t(20) +
        // attr_dataoffset(4) + attr_length(4).
        if (offset + 32 > buf.size()) {
            out.malformed = true;
            break;
        }
        const std::uint32_t record_length = detail::read_le_u32(buf, offset + 0);
        const std::int32_t attr_dataoffset = detail::read_le_i32(buf, offset + 24);
        const std::uint32_t attr_length = detail::read_le_u32(buf, offset + 28);

        // A record must be at least as long as its own fixed header, and must
        // fit in the buffer. Checking only `record_length == 0` lets a record
        // that does not CONTAIN its header through: with record_length=30,
        // attr_dataoffset=4, attr_length=2 the name span computes to
        // [28,30) -- inside the header's own attr_length field -- and
        // name_end_in_record (30) > record_length (30) is false, so the
        // fabricated bytes were accepted as a snapshot name with malformed=0.
        // Both external reviewers reproduced exactly that case.
        if (record_length < 32 || offset + record_length > buf.size()) {
            out.malformed = true;
            break;
        }
        if (attr_dataoffset < 0) {
            out.malformed = true;
            break;
        }
        const std::uint64_t name_start_in_record = 24ull + static_cast<std::uint64_t>(attr_dataoffset);
        const std::uint64_t name_end_in_record = name_start_in_record + attr_length;
        // attr_length includes the terminating NUL (pinned layout), so a
        // zero length is itself malformed -- there is no name to recover.
        // The name span must lie strictly BEYOND the 32-byte header as well as
        // within the record. Without the first clause a small dataoffset walks
        // the name back over the header fields themselves (see the record_length
        // guard above) -- the span would be in-bounds for the buffer and still
        // be pure fabrication.
        if (attr_length == 0 || name_start_in_record < 32 ||
            name_end_in_record > record_length) {
            out.malformed = true;
            break;
        }

        const std::size_t name_offset = offset + static_cast<std::size_t>(name_start_in_record);
        // The pinned layout requires the name span to be NUL-terminated at
        // its declared end; a non-NUL final byte means attr_length lied
        // about the span, so treat it as malformed rather than silently
        // accepting an unterminated name.
        if (buf[name_offset + attr_length - 1] != std::byte{0}) {
            out.malformed = true;
            break;
        }

        std::string name;
        name.reserve(attr_length - 1);
        for (std::uint32_t k = 0; k + 1 < attr_length; ++k) {
            const auto byte_val = std::to_integer<unsigned char>(buf[name_offset + k]);
            if (byte_val == 0)
                break;
            name.push_back(static_cast<char>(byte_val));
        }
        out.names.push_back(std::move(name));
        offset += record_length;
    }
    return out;
}

} // namespace yuzu::filesystem_posture
