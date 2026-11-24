/**
 * component_legs_win.hpp -- the decisions of the Windows leg of the component_inventory plugin: what it
 * walks (the two Program Files trees), what it keeps out, how a Windows path becomes the walk's
 * string and back, how a directory listing and a read are turned into the FsOps shapes
 * (component_walk.hpp), and the declarations of the three functions component_fs_win.cpp defines.
 *
 * PURE ABOVE THE GUARD, so every OS tests it: no Windows header, no I/O. component_fs_win.cpp is the
 * thin shell that feeds these functions what the OS answers (a known-folder path, a drive type, one
 * batch of directory records, one ReadFile) and holds the handles. No component logic lives in either
 * file: the walk, the limits, the scan, the archive reads and the answer are the portable code the
 * Linux and macOS legs already use, and the Windows leg only supplies the filesystem seam they are
 * written against.
 *
 * FOR THE FILE-SEARCH PROGRAMME. This is a thin binding of the FsOps seam, written so that a later
 * Windows filesystem layer (file-search plan PR 4, WinFs) can adopt it or replace it: the names it
 * hands the walk are lossless (WTF-8, below), the no-reparse rule is the shared primitive's
 * (agents/shared/win_no_reparse_open.hpp), and nothing here knows what a component is. It overlaps
 * that PR's intended scope by the owner's ruling of 2026-11-21.
 *
 * NAMES ARE LOSSLESS. The walk holds paths as `/`-joined strings, and a Windows file name is any
 * sequence of 16-bit units, including an unpaired surrogate that no UTF-8 string can carry. A lossy
 * conversion (an unpaired surrogate becomes U+FFFD, as yuzu::win::from_wide does) could make the walk
 * open a different file from the one it listed, one whose name really holds U+FFFD. The leg therefore
 * uses WTF-8: UTF-8, with an unpaired surrogate written as its own three-byte sequence, so the
 * listed name and the opened name are the same units. The row writer maps any byte that is not
 * well-formed UTF-8 to `?` (wire_field), so such a name never reaches a row as anything but `?`.
 *
 * The Windows-only declarations at the foot are the ones the plugin calls: scan_targets,
 * scan_native_targets and make_fs_ops, the same three names and shapes as the POSIX leg's
 * (component_legs.hpp).
 */
#pragma once

#include "component_java_parsers.hpp" // java_detail::iequals
#include "component_legs.hpp"
#include "component_walk.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::component_inventory {

// ---- names: UTF-16 <-> WTF-8 (lossless) ----

/// UTF-16 to WTF-8: well-formed UTF-8, except that an unpaired surrogate is written as its own
/// three-byte sequence (ED A0..BF xx) instead of being replaced.
[[nodiscard]] inline std::string wtf8_from_utf16(std::u16string_view in) {
    std::string out;
    out.reserve(in.size());
    const auto put = [&out](std::uint32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    };
    for (std::size_t i = 0; i < in.size(); ++i) {
        const std::uint32_t u = in[i];
        if (u >= 0xD800 && u <= 0xDBFF && i + 1 < in.size() && in[i + 1] >= 0xDC00 && in[i + 1] <= 0xDFFF) {
            put(0x10000 + ((u - 0xD800) << 10) + (static_cast<std::uint32_t>(in[i + 1]) - 0xDC00));
            ++i;
        } else {
            put(u); // a unit in D800..DFFF here is unpaired: the three-byte form
        }
    }
    return out;
}

/// WTF-8 to UTF-16; the exact inverse of wtf8_from_utf16. nullopt for anything that function cannot
/// have produced: a stray or missing continuation byte, an overlong form, a value past U+10FFFF, and a
/// high surrogate written three-byte directly before a low one (that pair has one valid spelling, four
/// bytes). The leg refuses such a name, it never guesses.
[[nodiscard]] inline std::optional<std::u16string> utf16_from_wtf8(std::string_view in) {
    std::u16string out;
    out.reserve(in.size());
    const auto byte_at = [&in](std::size_t i) { return static_cast<std::uint8_t>(in[i]); };
    const auto cont = [&](std::size_t i) { return i < in.size() && (byte_at(i) & 0xC0) == 0x80; };
    for (std::size_t i = 0; i < in.size();) {
        const std::uint8_t b = byte_at(i);
        std::uint32_t cp = 0;
        std::size_t n = 0;
        if (b < 0x80) {
            cp = b;
            n = 1;
        } else if (b >= 0xC2 && b <= 0xDF) {
            if (!cont(i + 1))
                return std::nullopt;
            cp = (static_cast<std::uint32_t>(b & 0x1F) << 6) | (byte_at(i + 1) & 0x3F);
            n = 2;
        } else if (b >= 0xE0 && b <= 0xEF) {
            if (!cont(i + 1) || !cont(i + 2))
                return std::nullopt;
            cp = (static_cast<std::uint32_t>(b & 0x0F) << 12) | (static_cast<std::uint32_t>(byte_at(i + 1) & 0x3F) << 6) |
                 (byte_at(i + 2) & 0x3F);
            if (cp < 0x800)
                return std::nullopt; // overlong
            n = 3;
            if (cp >= 0xD800 && cp <= 0xDBFF && i + 5 < in.size() && byte_at(i + 3) == 0xED &&
                (byte_at(i + 4) & 0xF0) == 0xB0 && cont(i + 5))
                return std::nullopt; // a surrogate pair spelled as two three-byte sequences
        } else if (b >= 0xF0 && b <= 0xF4) {
            if (!cont(i + 1) || !cont(i + 2) || !cont(i + 3))
                return std::nullopt;
            cp = (static_cast<std::uint32_t>(b & 0x07) << 18) | (static_cast<std::uint32_t>(byte_at(i + 1) & 0x3F) << 12) |
                 (static_cast<std::uint32_t>(byte_at(i + 2) & 0x3F) << 6) | (byte_at(i + 3) & 0x3F);
            if (cp < 0x10000 || cp > 0x10FFFF)
                return std::nullopt; // overlong, or past the last code point
            n = 4;
        } else {
            return std::nullopt;
        }
        if (cp >= 0x10000) {
            cp -= 0x10000;
            out += static_cast<char16_t>(0xD800 + (cp >> 10));
            out += static_cast<char16_t>(0xDC00 + (cp & 0x3FF));
        } else {
            out += static_cast<char16_t>(cp);
        }
        i += n;
    }
    return out;
}

// ---- paths ----

namespace win_detail {

[[nodiscard]] constexpr char ascii_upper(char c) noexcept {
    return c >= 'a' && c <= 'z' ? static_cast<char>(c - 'a' + 'A') : c;
}

[[nodiscard]] constexpr bool is_drive_letter(char c) noexcept {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/// `X:/` followed by at least one more character: a path below a drive root, never a bare root.
[[nodiscard]] constexpr bool is_drive_relative_walk_path(std::string_view p) noexcept {
    return p.size() > 3 && is_drive_letter(p[0]) && p[1] == ':' && p[2] == '/' && p.find('\0') == std::string_view::npos;
}

} // namespace win_detail

/// The walk's form of a native path (already WTF-8): every `\` becomes `/` (neither is legal inside a
/// Windows name, so nothing is lost) and trailing separators go. `C:\Program Files\` reads
/// `C:/Program Files`.
[[nodiscard]] inline std::string walk_path_from_native(std::string_view native) {
    std::string out(native);
    std::ranges::replace(out, '\\', '/');
    while (out.size() > 3 && out.back() == '/')
        out.pop_back();
    return out;
}

/// The wide, backslash-separated path the no-reparse open takes, from a walk path. nullopt unless the
/// path is `X:/` plus something and is valid WTF-8: a relative or UNC path, a bare drive root, an
/// embedded NUL. The open itself refuses the rest (an empty, `.` or `..` segment, a segment ending in
/// '.' or ' '): a refusal is a refusal there, never a quiet repair here.
[[nodiscard]] inline std::optional<std::u16string> native_path_from_walk(std::string_view walk_path) {
    if (!win_detail::is_drive_relative_walk_path(walk_path))
        return std::nullopt;
    auto wide = utf16_from_wtf8(walk_path);
    if (!wide)
        return std::nullopt;
    std::ranges::replace(*wide, u'/', u'\\');
    return wide;
}

// ---- roots, exclusions and the volume rule ----

/// What a known-folder path is to the Windows leg.
enum class KnownFolderPath {
    root,        ///< `X:` plus a separator plus something: a directory the walk can be given
    network,     ///< a UNC path (`\\server\share\...`): a network location, never walked, counted
    unnameable,  ///< anything else (empty, relative, a bare drive root, an extended `\\?\` path): cannot be walked
};

/// Pure. UNC means two separators followed by a name; `\\?\` and `\\.\` are device and extended-length
/// namespaces, not network shares, so they are unnameable, which constrains the answer.
[[nodiscard]] inline KnownFolderPath classify_known_folder_path(std::string_view native) {
    const auto sep = [](char c) { return c == '\\' || c == '/'; };
    if (native.size() >= 3 && sep(native[0]) && sep(native[1]) && !sep(native[2]) && native[2] != '?' &&
        native[2] != '.')
        return KnownFolderPath::network;
    return win_detail::is_drive_relative_walk_path(walk_path_from_native(native)) ? KnownFolderPath::root
                                                                                   : KnownFolderPath::unnameable;
}

/// The candidate roots from the two known-folder paths (FOLDERID_ProgramFilesX64 and
/// FOLDERID_ProgramFilesX86, as WTF-8; never an environment variable), in walk order: the 64-bit tree
/// first, each in the walk's form, as a Targets whose `roots` are not yet vetted against their volume
/// (plan_windows_targets does that). NO CANDIDATE IS DROPPED SILENTLY: a UNC path is counted in
/// roots_network_skipped, and a path that cannot name a walkable directory (empty, relative, a bare
/// drive root, which must never become a root because one walk has a single entry budget a whole drive
/// would spend) sets mount_table_unreadable, the constraining token. Only a repeat of an earlier root
/// (compared ASCII case-insensitively: the same tree seen twice) is left out without a count, because
/// nothing is lost by it.
[[nodiscard]] inline Targets windows_candidate_roots(std::string_view program_files,
                                                     std::string_view program_files_x86) {
    Targets out;
    for (const std::string_view native : {program_files, program_files_x86}) {
        switch (classify_known_folder_path(native)) {
        case KnownFolderPath::network:
            ++out.roots_network_skipped;
            continue;
        case KnownFolderPath::unnameable:
            out.mount_table_unreadable = true;
            continue;
        case KnownFolderPath::root:
            break;
        }
        std::string root = walk_path_from_native(native);
        const bool repeat = std::ranges::any_of(
            out.roots, [&](const std::string& kept) { return java_detail::iequals(kept, root); });
        if (!repeat)
            out.roots.push_back(std::move(root));
    }
    return out;
}

/// The directories the `scan` and `native` walks must not list, by exact path: `WindowsApps` directly
/// under each root. Those are the Store packages, owned by the package manager and unreadable to most accounts;
/// the walk counts each one it meets (WalkStats::dirs_excluded), it never skips one silently.
[[nodiscard]] inline std::vector<std::string> windows_excluded_dirs(const std::vector<std::string>& roots) {
    std::vector<std::string> out;
    out.reserve(roots.size());
    for (const auto& r : roots)
        out.push_back(r + "/WindowsApps");
    return out;
}

/// True when `dir` is one of `excluded`. Windows paths compare ASCII case-insensitively (the volume
/// is case-insensitive; a directory is listed under the case it was created with).
[[nodiscard]] inline bool is_windows_excluded_dir(const std::vector<std::string>& excluded, std::string_view dir) {
    return std::ranges::any_of(excluded,
                               [&](const std::string& e) { return java_detail::iequals(e, dir); });
}

/// The walk policy both Windows actions share: WindowsApps under each of `t`'s roots is skipped (and
/// counted by the walk). The candidate test is the default one, Java archives, which is the `scan`
/// action's; `native` replaces it. The plugin builds its policy here and the tests run this same
/// function, so a policy that dropped the exclusion would fail on every OS.
[[nodiscard]] inline WalkPolicy windows_walk_policy(const Targets& t) {
    WalkPolicy p;
    p.skip_dir = [excluded = windows_excluded_dirs(t.roots)](const std::string& dir) {
        return is_windows_excluded_dir(excluded, dir);
    };
    return p;
}

/// What a volume is to the one question the leg asks of it: may it be read. The three answers carry
/// three different consequences, so the leg never folds them into a bool.
enum class DriveClass {
    fixed,     ///< a local fixed disk (DRIVE_FIXED): the only kind the leg walks or opens
    not_fixed, ///< a network, removable, optical or RAM drive: never walked, counted (informational)
    unknown,   ///< the type cannot be told (DRIVE_UNKNOWN, DRIVE_NO_ROOT_DIR, an undocumented value): constrains
};

/// GetDriveTypeW's return values the leg tells apart (stable Windows constants, kept here so the rule
/// is testable on every OS; component_fs_win.cpp static_asserts them against the SDK's).
inline constexpr std::uint32_t kDriveRemovable = 2;
inline constexpr std::uint32_t kDriveFixed = 3;
inline constexpr std::uint32_t kDriveRemote = 4;
inline constexpr std::uint32_t kDriveCdrom = 5;
inline constexpr std::uint32_t kDriveRamdisk = 6;

/// Pure. GetDriveTypeW's answer as a DriveClass: only the five documented kinds that name a volume are
/// classified; DRIVE_UNKNOWN (0), DRIVE_NO_ROOT_DIR (1) and any value Windows never documented are
/// `unknown`, because a volume whose type cannot be told must not read as a skipped network drive.
[[nodiscard]] constexpr DriveClass drive_class_from_type(std::uint32_t drive_type) noexcept {
    switch (drive_type) {
    case kDriveFixed:
        return DriveClass::fixed;
    case kDriveRemovable:
    case kDriveRemote:
    case kDriveCdrom:
    case kDriveRamdisk:
        return DriveClass::not_fixed;
    default:
        return DriveClass::unknown;
    }
}

/// Test seam: the class of the volume of this drive letter (upper case). The live one is GetDriveTypeW
/// on `X:\`, through drive_class_from_type.
using DriveClassTest = std::function<DriveClass(char drive)>;

/// Pure. The upper-case drive letter of a walk path (`X:/` plus something), nullopt for any other path
/// (UNC, relative, a bare drive root, an embedded NUL).
[[nodiscard]] inline std::optional<char> drive_of_walk_path(std::string_view walk_path) {
    if (!win_detail::is_drive_relative_walk_path(walk_path))
        return std::nullopt;
    return win_detail::ascii_upper(walk_path[0]);
}

/// Pure. The per-open gate: true only when `walk_path` names a drive and that drive is a local fixed
/// disk RIGHT NOW. The shell asks it before every directory open and every file open, not once at
/// planning, because a drive letter can be re-pointed (SUBST, a disk swap, hot-plug) inside the scan
/// window (the `runtimes` plugin re-checks DRIVE_FIXED on every read for the same reason). Anything
/// but a fixed answer, `unknown` included, refuses the open.
[[nodiscard]] inline bool volume_is_fixed(std::string_view walk_path, const DriveClassTest& drive_class) {
    const auto drive = drive_of_walk_path(walk_path);
    return drive && drive_class(*drive) == DriveClass::fixed;
}

/// Pure. Vets `candidates` (the output of windows_candidate_roots) against their volumes: a root on a
/// fixed drive is kept, in order; a root on a network, removable, optical or RAM drive is dropped and
/// counted in roots_network_skipped (informational: it is not on a fixed local volume); a root whose
/// drive type cannot be told, or that does not name a drive at all, is dropped and sets
/// mount_table_unreadable (constraining), never an informational count. The counts and flag the
/// candidates already carry are kept. Every dropped candidate is therefore counted or constraining: no
/// plan answers supported with a tree it never walked and nothing said. The other Targets fields stay
/// clear: there is no mount table here, and a mount point or junction below a root is a reparse point
/// the walk never enters.
[[nodiscard]] inline Targets plan_windows_targets(const Targets& candidates, const DriveClassTest& drive_class) {
    Targets t;
    t.roots_network_skipped = candidates.roots_network_skipped;
    t.mount_table_unreadable = candidates.mount_table_unreadable;
    for (const auto& root : candidates.roots) {
        const auto drive = drive_of_walk_path(root);
        switch (drive ? drive_class(*drive) : DriveClass::unknown) {
        case DriveClass::fixed:
            t.roots.push_back(root);
            break;
        case DriveClass::not_fixed:
            ++t.roots_network_skipped;
            break;
        case DriveClass::unknown:
            t.mount_table_unreadable = true;
            break;
        }
    }
    if (t.mount_table_unreadable)
        t.roots.clear(); // Targets' contract: an unestablished root list walks nothing
    return t;
}

/// Pure. The roots of both actions from the two known-folder lookups (nullopt: that lookup failed),
/// the 64-bit tree first, in walk order. Both lookups must have answered; otherwise nothing is walked
/// and mount_table_unreadable is set, so a failed lookup is a constrained answer and never an empty
/// host (`drive_class` is not asked in that case). Past that, every candidate is walked, counted or
/// constraining (windows_candidate_roots, plan_windows_targets).
[[nodiscard]] inline Targets windows_targets_from_known_folders(const std::optional<std::string>& program_files,
                                                                const std::optional<std::string>& program_files_x86,
                                                                const DriveClassTest& drive_class) {
    if (!program_files || !program_files_x86) {
        Targets t;
        t.mount_table_unreadable = true;
        return t;
    }
    return plan_windows_targets(windows_candidate_roots(*program_files, *program_files_x86), drive_class);
}

// ---- one directory listing, from the records the OS returns ----

/// FILE_ATTRIBUTE_* values the leg reads (stable Windows constants, kept here so the rule is testable
/// on every OS; component_fs_win.cpp static_asserts them against the SDK's).
inline constexpr std::uint32_t kAttrDirectory = 0x00000010;
inline constexpr std::uint32_t kAttrDevice = 0x00000040;
inline constexpr std::uint32_t kAttrReparsePoint = 0x00000400;

/// A reparse point of any kind (a junction, a symbolic link, a mount point, a cloud placeholder, a
/// compressed-on-disk stub) is a link: counted, never listed through and never opened, whatever else
/// its attributes say. Then a directory is a dir, a device record is `other`, anything else a file.
[[nodiscard]] constexpr DirEntry::Type entry_type_from_attributes(std::uint32_t attributes) noexcept {
    if ((attributes & kAttrReparsePoint) != 0)
        return DirEntry::Type::link;
    if ((attributes & kAttrDirectory) != 0)
        return DirEntry::Type::dir;
    if ((attributes & kAttrDevice) != 0)
        return DirEntry::Type::other;
    return DirEntry::Type::file;
}

/// Layout of one FILE_ID_BOTH_DIR_INFO record, the batch GetFileInformationByHandleEx returns for
/// FileIdBothDirectoryInfo (little-endian). Offsets of the fields the leg reads; the shell
/// static_asserts them against the SDK struct on the host that compiles it.
inline constexpr std::size_t kDirInfoNextEntryOffset = 0;
inline constexpr std::size_t kDirInfoFileAttributes = 56;
inline constexpr std::size_t kDirInfoFileNameLength = 60;
inline constexpr std::size_t kDirInfoFileId = 96;
inline constexpr std::size_t kDirInfoFileName = 104;

/// What one batch of records did to the listing being built.
enum class BatchResult {
    more,      ///< every record taken; ask for the next batch
    truncated, ///< a record arrived past the cap: ListResult::truncated is set, stop asking
    malformed, ///< a record is not a record (runs past the batch, odd or empty name): refuse the listing
};

/// Appends the records of one batch to `out`: a record's name as WTF-8, its type from the attributes,
/// its file reference number. `.` and `..` are skipped. Records are chained by NextEntryOffset and the
/// chain ends at a record whose offset is 0, so bytes after the last record are never read; every
/// field is checked against `batch` first (the OS is trusted for the shape, never for the bound).
/// `cap` is the per-directory cap: the first real record past it sets out.truncated and stops.
[[nodiscard]] inline BatchResult append_dir_batch(std::span<const std::byte> batch, std::size_t cap, ListResult& out) {
    const auto load32 = [&batch](std::size_t at) {
        std::uint32_t v = 0;
        std::memcpy(&v, batch.data() + at, sizeof(v));
        return v;
    };
    const auto load64 = [&batch](std::size_t at) {
        std::uint64_t v = 0;
        std::memcpy(&v, batch.data() + at, sizeof(v));
        return v;
    };
    std::size_t at = 0;
    for (;;) {
        // The fixed part (through FileId) must be inside the batch, and so must the name it declares.
        if (batch.size() < kDirInfoFileName || at > batch.size() - kDirInfoFileName)
            return BatchResult::malformed;
        const std::uint32_t next = load32(at + kDirInfoNextEntryOffset);
        const std::uint32_t attributes = load32(at + kDirInfoFileAttributes);
        const std::uint32_t name_bytes = load32(at + kDirInfoFileNameLength);
        if (name_bytes == 0 || name_bytes % 2 != 0 || name_bytes > batch.size() - at - kDirInfoFileName)
            return BatchResult::malformed;

        std::u16string units(name_bytes / 2, u'\0');
        std::memcpy(units.data(), batch.data() + at + kDirInfoFileName, name_bytes);
        if (units != u"." && units != u"..") {
            if (out.entries.size() >= cap) {
                out.truncated = true;
                return BatchResult::truncated;
            }
            DirEntry e;
            e.name = wtf8_from_utf16(units);
            e.type = entry_type_from_attributes(attributes);
            e.file_id = load64(at + kDirInfoFileId);
            out.entries.push_back(std::move(e));
        }
        if (next == 0)
            return BatchResult::more;
        if (next < kDirInfoFileName || next > batch.size() - at)
            return BatchResult::malformed; // a record cannot start inside the previous one or past the batch
        at += next;
    }
}

/// The next batch of records: its bytes (valid until the next call), an empty span at the end of the
/// directory, nullopt when the OS failed.
using DirBatchSource = std::function<std::optional<std::span<const std::byte>>()>;

/// The whole listing from a batch source, in the shape component_fs_posix.cpp returns: entries sorted
/// by name (so the scan-wide caps cut the same rows on the same tree, whatever order the volume
/// answers in), `truncated` when a record existed past `cap`, and `error` with no entries when the
/// source failed or a batch was malformed: a half-read directory is never an answer.
[[nodiscard]] inline ListResult list_from_batches(const DirBatchSource& next_batch, std::size_t cap) {
    ListResult out;
    for (;;) {
        const auto batch = next_batch();
        if (!batch) {
            out.error = true;
            break;
        }
        if (batch->empty())
            break;
        const BatchResult r = append_dir_batch(*batch, cap, out);
        if (r == BatchResult::malformed) {
            out.error = true;
            break;
        }
        if (r == BatchResult::truncated)
            break;
    }
    if (out.error) {
        out.entries.clear();
        out.truncated = false;
    } else {
        std::ranges::sort(out.entries, {}, &DirEntry::name);
    }
    return out;
}

// ---- one file: times and ranged reads ----

/// A Windows FILETIME (100 ns ticks since 1601-01-01 UTC) as Unix seconds, rounded toward the past.
[[nodiscard]] constexpr std::int64_t unix_seconds_from_filetime(std::uint64_t filetime) noexcept {
    constexpr std::int64_t kSecondsFrom1601To1970 = 11644473600;
    return static_cast<std::int64_t>(filetime / 10000000u) - kSecondsFrom1601To1970;
}

/// The most one read_at call serves; a larger request is refused, never cut, because a short answer
/// means end of file to the caller (the POSIX leg's bound).
inline constexpr std::size_t kMaxReadAt = 16u * 1024 * 1024;

/// One positioned read of at most `len` bytes into `buf`: the count read (0 at end of file), nullopt
/// when the OS failed. component_fs_win.cpp's is ReadFile with an explicit offset.
using ReadOnce = std::function<std::optional<std::size_t>(std::uint64_t offset, char* buf, std::size_t len)>;

/// FileView::read_at over `read_once`: exactly `len` bytes unless the file ends first, in which case
/// the bytes that exist (fewer than asked only at end of file). nullopt for an I/O error and for a
/// request past what a signed 64-bit offset can address or past kMaxReadAt.
[[nodiscard]] inline std::optional<std::string> read_range(std::uint64_t offset, std::size_t len,
                                                           const ReadOnce& read_once) {
    constexpr auto kMaxOffset = static_cast<std::uint64_t>(INT64_MAX);
    if (len > kMaxReadAt || offset > kMaxOffset || len > kMaxOffset - offset)
        return std::nullopt;
    std::string out(len, '\0');
    std::size_t got = 0;
    while (got < len) {
        const auto n = read_once(offset + got, out.data() + got, len - got);
        if (!n)
            return std::nullopt;
        if (*n == 0)
            break;
        got += std::min(*n, len - got);
    }
    out.resize(got);
    return out;
}

/// NTSTATUS STATUS_ACCESS_DENIED: the DACL excludes the caller (no backup privilege is requested, so
/// completeness never depends on one).
inline constexpr std::uint32_t kNtStatusAccessDenied = 0xC0000022u;

/// What a failed directory open says about why: access denied is a permission refusal; every other
/// status (a reparse point on the way, a sharing violation, anything unknown, 0) stays unreadable.
[[nodiscard]] constexpr ListError list_cause_from_ntstatus(std::uint32_t status) noexcept {
    return status == kNtStatusAccessDenied ? ListError::permission_denied : ListError::none;
}

} // namespace yuzu::component_inventory

// ---- the Windows-only functions component_fs_win.cpp defines ----

#if defined(_WIN32)

namespace yuzu::component_inventory {

/// The roots of the `scan` action: the 64-bit and 32-bit Program Files directories from the shell's
/// known-folder lookup, on fixed drives only (GetDriveTypeW). A lookup that fails, a path that names no
/// walkable directory and a drive whose type cannot be told answer no roots and mount_table_unreadable:
/// a failed read is a constrained answer, never an empty success. A UNC path or a drive that is not a
/// fixed disk is counted in roots_network_skipped.
[[nodiscard]] Targets scan_targets();

/// The roots of the `native` action: the same Program Files trees. The WindowsApps directory under
/// each is excluded by the plugin's walk policy (windows_walk_policy), not by the roots; the `scan`
/// action's walk is given the same exclusion.
[[nodiscard]] Targets scan_native_targets();

/// The filesystem the walk goes through: every directory and file is opened relative to its volume
/// root with no reparse point followed at any component (yuzu::win::open_dir_no_reparse,
/// open_file_no_reparse), and an entry that is itself a reparse point is typed link and never opened.
/// The volume is re-checked before EVERY open (volume_is_fixed over GetDriveTypeW): a drive that is no
/// longer a fixed local disk answers as an unopenable path, which the walk reports as its error cause,
/// never as an empty directory. `targets` is unused (there is no mount table); the parameter keeps the
/// POSIX leg's shape.
[[nodiscard]] FsOps make_fs_ops(const Targets& targets);

/// make_fs_ops over an injected volume test in place of GetDriveTypeW: the test seam that lets a unit
/// test show the per-open volume check refuses a drive that is not fixed, over a real temporary tree.
[[nodiscard]] FsOps make_fs_ops(const Targets& targets, const DriveClassTest& drive_class);

} // namespace yuzu::component_inventory

#endif // _WIN32
