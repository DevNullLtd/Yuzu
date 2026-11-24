/**
 * file_search_win_rules.hpp -- every DECISION of the Windows leg, as pure functions. No OS header and no I/O:
 * attribute, tag and error values are spelled here (as fiemap_bits does), so every rule is unit-tested on
 * every OS; file_search_win.cpp only binds the Win32 and NT calls to them and decides nothing.
 *
 * THE PATH MODEL. One canonical '/'-joined LABEL, never handed to the OS: `/C:`, `/C:/Users/x`,
 * `/Volume{guid}/dir` (the drive letter upper-cased, the GUID lower-cased, components exactly as typed). The
 * leading '/' keeps the shared path tests, the volume plan and the walker's join untouched. The leg splits a
 * label, opens the volume root by its GUID path, then every hop parent-handle-relative with no reparse
 * followed.
 *
 * THE LISTING DECIDES FIRST. From the attributes and the reparse tag of a listing record (the same record,
 * no extra call) classify() says what an entry is, and extents_decision() whether it may be opened at all.
 * Nothing marked recall-on-open, recall-on-data-access or offline is ever opened, enumerated or read: that
 * is the invariant that keeps a search from bringing a cloud placeholder back. No open flag is relied on as
 * a recall barrier (FILE_OPEN_NO_RECALL was measured to protect nothing); what protects a file is that its
 * handle carries no data right, and what protects a directory is the listing decision plus the recheck of
 * its attributes on the opened handle before anything is enumerated.
 *
 * MEASURED VALUES, from a Windows 11 host (a synthetic cloud sync root with a real provider callback round
 * trip, as the interactive administrator and as SYSTEM): a populated folder is attributes 0x410 with tag
 * 0x9000601A in sync and 0x9000201A not in sync; the sync-root folder is 0x430 with 0x9000701A; a folder that
 * is not populated is 0x401410; an unhydrated file is 0x401620 (pinned variants 0x481620 and 0x501620); a
 * hydrated cloud file is 0x420 with 0x9000601A or 0x9000201A; an app-execution alias is 0x420 with
 * 0x8000001B; a `compact /exe` file is a plain file (0x20, no tag) whose retrieval pointers read as ONE hole;
 * a sparse hole is an lcn -1 run, a wholly sparse file answers success with one lcn -1 run, and a resident
 * or empty file answers ERROR_HANDLE_EOF; a buffer under 32 bytes answers ERROR_INSUFFICIENT_BUFFER, not
 * ERROR_MORE_DATA. NOT MEASURED, stated where each rule uses it: EFS (the `encrypted` flag follows the
 * documented attribute), deduplication (detected by its tag), ReFS, a commercial sync client, and a
 * recall-on-open directory.
 */
#pragma once

#include "file_search_extents.hpp"
#include "file_search_legs.hpp" // ci: the walker vocabulary (DirEntry::Type, RootState, ListError)
#include "file_search_request.hpp"
#include "file_search_rows.hpp"
#include "file_search_volumes.hpp"

#include "component_walk.hpp"

#include <file_search_position.hpp>
#include <wire_utf8.hpp>

#include <yuzu/agent/confined_fs_rules.hpp> // Reason, ReparseDirs and the cloud tag family: one definition

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::file_search::win_rules {

namespace cfs = yuzu::agent::confined_fs;

// ---- the values (spelled here: no OS header) ----

inline constexpr std::uint32_t kAttrCompressed = 0x00000800;
inline constexpr std::uint32_t kAttrEncrypted = 0x00004000;

inline constexpr std::uint32_t kTagSymlink = 0xA000000C;
inline constexpr std::uint32_t kTagMountPoint = 0xA0000003;
inline constexpr std::uint32_t kTagLxSymlink = 0xA000001D;
inline constexpr std::uint32_t kTagAfUnix = 0x80000023;
inline constexpr std::uint32_t kTagLxFifo = 0x80000024;
inline constexpr std::uint32_t kTagLxChr = 0x80000025;
inline constexpr std::uint32_t kTagLxBlk = 0x80000026;
inline constexpr std::uint32_t kTagWof = 0x80000017;
inline constexpr std::uint32_t kTagDedup = 0x80000013; // tag-driven and UNMEASURED: the feature is not on client Windows
inline constexpr std::uint32_t kTagAppExecLink = 0x8000001B;

inline constexpr std::uint32_t kErrorFileNotFound = 2;
inline constexpr std::uint32_t kErrorPathNotFound = 3;
inline constexpr std::uint32_t kErrorAccessDenied = 5;
inline constexpr std::uint32_t kErrorInvalidFunction = 1;
inline constexpr std::uint32_t kErrorNotSupported = 50;
inline constexpr std::uint32_t kErrorHandleEof = 38;
inline constexpr std::uint32_t kErrorInvalidParameter = 87;
inline constexpr std::uint32_t kErrorMoreData = 234;
inline constexpr std::uint32_t kErrorDirectory = 267;
inline constexpr std::uint32_t kErrorObjectNotExternallyBacked = 342;
inline constexpr std::uint32_t kErrorCloudFileProviderNotRunning = 362;

// ---- the root: normaliser and label ----

namespace detail {

[[nodiscard]] constexpr bool is_sep(char c) noexcept {
    return c == '\\' || c == '/';
}

[[nodiscard]] constexpr bool is_hex(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

[[nodiscard]] constexpr bool is_ascii_letter(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/// One path component as the OS would see it relative to an open directory: not empty, not "." or "..",
/// no trailing '.' or ' ' (the rule of win_no_reparse_open.hpp), none of `< > : " | ? *` (':' is the
/// alternate-stream syntax and must never reach an NT open) and no byte below 0x20.
[[nodiscard]] constexpr bool valid_windows_component(std::string_view c) noexcept {
    if (c.empty() || c == "." || c == ".." || c.back() == '.' || c.back() == ' ')
        return false;
    for (const char ch : c) {
        const auto u = static_cast<unsigned char>(ch);
        if (u < 0x20 || ch == '<' || ch == '>' || ch == ':' || ch == '"' || ch == '|' || ch == '?' || ch == '*')
            return false;
    }
    return true;
}

/// `<8>-<4>-<4>-<4>-<12>` hex digits.
[[nodiscard]] constexpr bool is_guid_text(std::string_view g) noexcept {
    if (g.size() != 36)
        return false;
    for (std::size_t i = 0; i < g.size(); ++i) {
        const bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash ? g[i] != '-' : !is_hex(g[i]))
            return false;
    }
    return true;
}

[[nodiscard]] constexpr bool starts_icase(std::string_view s, std::string_view prefix) noexcept {
    return s.size() >= prefix.size() && ascii_ieq(s.substr(0, prefix.size()), prefix);
}

/// The components of `rest`, the text after a root prefix: empty, or a separator followed by components
/// separated by single separators, with ONE trailing separator ignored. A doubled separator, an empty
/// component and every component the OS could misread is root_bad_component.
[[nodiscard]] inline std::expected<std::vector<std::string>, RequestError> components_of(std::string_view rest) {
    std::vector<std::string> out;
    if (rest.empty())
        return out;
    if (!is_sep(rest.front()))
        return std::unexpected(RequestError::root_bad_component);
    rest.remove_prefix(1);
    if (rest.empty())
        return out; // the root alone, with its one separator
    std::vector<std::string> pieces;
    for (;;) {
        std::size_t end = 0;
        while (end < rest.size() && !is_sep(rest[end]))
            ++end;
        pieces.emplace_back(rest.substr(0, end));
        if (end == rest.size())
            break;
        rest.remove_prefix(end + 1);
    }
    if (pieces.back().empty())
        pieces.pop_back(); // one trailing separator; a doubled one leaves an empty piece behind, refused below
    for (auto& p : pieces) {
        if (!valid_windows_component(p))
            return std::unexpected(RequestError::root_bad_component);
        out.push_back(std::move(p));
    }
    return out;
}

} // namespace detail

/// The root a Windows request may carry, as the canonical label, or the reason it may not. Accepted forms:
/// `<letter>:\...` or `<letter>:/...`, and `\\?\Volume{<guid>}\...` (the prefix case-insensitive). A UNC or
/// network root is root_unc; any other `\\?\`, `\\.\` or `\??\` form (including `\\?\C:\` and a malformed
/// volume GUID) is root_device_path; everything else that is not absolute (`C:`, `C:foo`, `\foo`, `/foo`, a
/// relative path) is root_not_absolute. A byte that is not well-formed UTF-8 is root_bad_component: the
/// confinement primitive converts each component to UTF-16 leniently, and a malformed byte would open a
/// directory other than the one the root names, reports and hashes.
[[nodiscard]] inline std::expected<std::string, RequestError> normalise_windows_root(std::string_view raw) {
    using detail::is_sep;
    if (raw.empty())
        return std::unexpected(RequestError::missing_root);
    if (raw.size() > kMaxRootBytes)
        return std::unexpected(RequestError::root_too_long);
    if (raw.find('\0') != std::string_view::npos)
        return std::unexpected(RequestError::root_bad_component);
    if (yuzu::shared::count_invalid_wire_bytes(raw) != 0)
        return std::unexpected(RequestError::root_bad_component);

    std::string label;
    std::string_view rest;
    if (raw.starts_with("\\\\?\\")) {
        const std::string_view after = raw.substr(4);
        if (detail::starts_icase(after, "UNC") && (after.size() == 3 || is_sep(after[3])))
            return std::unexpected(RequestError::root_unc);
        constexpr std::string_view kVolume = "Volume{";
        if (!detail::starts_icase(after, kVolume) || after.size() < kVolume.size() + 37 ||
            after[kVolume.size() + 36] != '}')
            return std::unexpected(RequestError::root_device_path);
        const std::string_view guid = after.substr(kVolume.size(), 36);
        if (!detail::is_guid_text(guid))
            return std::unexpected(RequestError::root_device_path);
        rest = after.substr(kVolume.size() + 37);
        if (!rest.empty() && !is_sep(rest.front()))
            return std::unexpected(RequestError::root_device_path);
        label = "/Volume{";
        for (const char c : guid)
            label += ascii_lower(c);
        label += '}';
    } else if (raw.starts_with("\\??\\") ||
               (raw.size() >= 4 && is_sep(raw[0]) && is_sep(raw[1]) && (raw[2] == '?' || raw[2] == '.') &&
                is_sep(raw[3]))) {
        // `\\.\`, `//?/`, `//./` and the mixed-separator spellings are device paths too, never a UNC root.
        // Only the exact `\\?\Volume{guid}\` spelling above is accepted.
        return std::unexpected(RequestError::root_device_path);
    } else if (raw.size() >= 2 && is_sep(raw[0]) && is_sep(raw[1])) {
        return std::unexpected(RequestError::root_unc); // \\server\share, //server/share
    } else if (raw.size() >= 3 && detail::is_ascii_letter(raw[0]) && raw[1] == ':' && is_sep(raw[2])) {
        label = "/";
        label += static_cast<char>(raw[0] >= 'a' ? raw[0] - 'a' + 'A' : raw[0]);
        label += ':';
        rest = raw.substr(2);
    } else {
        return std::unexpected(RequestError::root_not_absolute);
    }

    auto comps = detail::components_of(rest);
    if (!comps)
        return std::unexpected(comps.error());
    for (const std::string& c : *comps) {
        label += '/';
        label += c;
    }
    if (label.size() > kMaxRootBytes)
        return std::unexpected(RequestError::root_too_long);
    return label;
}

/// A label split into its volume (`C:` or `Volume{guid}`) and the components below it.
struct Label {
    std::string volume;
    std::vector<std::string> components;
};

/// nullopt for anything that is not a label of the shape above.
[[nodiscard]] inline std::optional<Label> split_label(std::string_view label) {
    if (label.size() < 2 || label.front() != '/')
        return std::nullopt;
    label.remove_prefix(1);
    Label out;
    for (std::size_t at = 0;;) {
        const std::size_t slash = label.find('/', at);
        const std::string_view piece =
            label.substr(at, slash == std::string_view::npos ? std::string_view::npos : slash - at);
        if (piece.empty())
            return std::nullopt;
        if (at == 0)
            out.volume = piece;
        else
            out.components.emplace_back(piece);
        if (slash == std::string_view::npos)
            return out;
        at = slash + 1;
    }
}

/// The root of a volume as the OS opens it: `C:\` for a drive, `\\?\Volume{guid}\` for a volume GUID path.
/// Empty for a string that is neither.
[[nodiscard]] inline std::string volume_root_path(std::string_view volume) {
    if (volume.size() == 2 && detail::is_ascii_letter(volume[0]) && volume[1] == ':')
        return std::string(volume) + "\\";
    if (volume.starts_with("Volume{") && volume.back() == '}')
        return "\\\\?\\" + std::string(volume) + "\\";
    return {};
}

/// The label of a profile directory inside the searched volume: the unit's mount point plus the components
/// of `profile_path` after `volume_mount_root` (both as the system answered them, UTF-8, either separator).
/// nullopt when the mount root is not an ASCII-case-insensitive prefix of the path (a profile path that
/// crosses a junction to another volume is answered with that volume's root: its components would label the
/// wrong directory), when a component is refused, or when there is none (a profile "at the volume root"
/// would read the whole volume as user data). Lexical on purpose: the leg opens nothing by path.
[[nodiscard]] inline std::optional<std::string> profile_root_label(std::string_view unit_mount_point,
                                                                    std::string_view volume_mount_root,
                                                                    std::string_view profile_path) {
    if (!detail::starts_icase(profile_path, volume_mount_root))
        return std::nullopt;
    std::string_view rest_on_volume = profile_path.substr(volume_mount_root.size());
    while (!rest_on_volume.empty() && detail::is_sep(rest_on_volume.front()))
        rest_on_volume.remove_prefix(1);
    std::string rest = "\\" + std::string(rest_on_volume);
    auto comps = detail::components_of(rest);
    if (!comps || comps->empty())
        return std::nullopt;
    std::string label(unit_mount_point);
    for (const std::string& c : *comps) {
        label += '/';
        label += c;
    }
    return label;
}

// ---- what a listed entry is ----

/// The reparse family of an entry that a leg treats as a file-like object, for the extents decision.
enum class TagFamily : std::uint8_t { none, cloud, wof, dedup, app_exec };

/// What a listing record's attributes and tag say about an entry.
struct Listed {
    ci::DirEntry::Type type{ci::DirEntry::Type::file};
    std::optional<fsr::GapCause> gap; // the leg cannot search it: reported with this cause, never opened
    TagFamily family{TagFamily::none};
};

/// `recall`: any of RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS, OFFLINE.
[[nodiscard]] constexpr bool has_recall(std::uint32_t attributes) noexcept {
    return (attributes & cfs::kAttrRecallOrOffline) != 0;
}

/// What the attributes and the reparse tag of an entry say it is:
///  - no reparse attribute: a directory with a recall or offline bit is a dir with a `dataless` gap (never
///    opened: the listing, not a handle, reports recall-on-open); any other directory is a dir; else a file;
///  - reparse: SYMLINK, MOUNT_POINT and LX_SYMLINK are links; AF_UNIX and the WSL special files are other;
///  - the cloud tag FAMILY (the mask, never one value): a file is a file of family cloud; a directory
///    without a recall or offline bit is a dir of family cloud and is entered (measured: 0x410 and 0x430);
///    a directory with one is a `dataless` gap (measured 0x401410: not populated, and enumerating it is what
///    populates it);
///  - WOF, DEDUP and APPEXECLINK: a file is a file of that family; a directory is a `reparse_unknown` gap;
///  - any other tag: a `reparse_unknown` gap.
/// The WOF tag row stays for a volume that shows the tag, but it is NOT how a CompactOS file is found (that
/// file lists as a plain file with no tag, measured): see external_backing_of.
[[nodiscard]] constexpr Listed classify_attributes(std::uint32_t attributes, std::uint32_t reparse_tag) noexcept {
    using Type = ci::DirEntry::Type;
    const bool dir = (attributes & cfs::kAttrDirectory) != 0;
    const bool recall = has_recall(attributes);
    Listed out;
    if ((attributes & cfs::kAttrReparsePoint) == 0) {
        out.type = dir ? Type::dir : Type::file;
        if (dir && recall)
            out.gap = fsr::GapCause::dataless;
        return out;
    }
    switch (reparse_tag) {
    case kTagSymlink:
    case kTagMountPoint:
    case kTagLxSymlink:
        out.type = Type::link;
        return out;
    case kTagAfUnix:
    case kTagLxFifo:
    case kTagLxChr:
    case kTagLxBlk:
        out.type = Type::other;
        return out;
    default:
        break;
    }
    out.type = dir ? Type::dir : Type::file;
    if (cfs::is_cloud_reparse_tag(reparse_tag)) {
        out.family = TagFamily::cloud;
        if (dir && recall)
            out.gap = fsr::GapCause::dataless;
        return out;
    }
    const TagFamily family = reparse_tag == kTagWof       ? TagFamily::wof
                             : reparse_tag == kTagDedup   ? TagFamily::dedup
                             : reparse_tag == kTagAppExecLink ? TagFamily::app_exec
                                                          : TagFamily::none;
    if (family == TagFamily::none || dir) {
        out.gap = fsr::GapCause::reparse_unknown;
        return out;
    }
    out.family = family;
    return out;
}

/// The one classification of a listed entry (the same function is applied to the attributes and tag read
/// from an opened handle). `name_invalid`: the entry's name cannot round-trip UTF-8 (its lossy form may equal
/// a real sibling's): whatever else it is, it is a `name_too_long` gap, and its type stays what the
/// attributes say.
[[nodiscard]] constexpr Listed classify(std::uint32_t attributes, std::uint32_t reparse_tag,
                                        bool name_invalid = false) noexcept {
    Listed out = classify_attributes(attributes, reparse_tag);
    if (name_invalid)
        out.gap = fsr::GapCause::name_too_long;
    return out;
}

// ---- extents: the decision before any open, and the readings of the two ioctls ----

/// The extents note of a file that CompactOS or another WOF provider backs: spelled once, read by the
/// decision from a listed tag and by the shell when FSCTL_GET_EXTERNAL_BACKING answers (a CompactOS file
/// lists with no tag at all).
inline constexpr std::string_view kNoteWofBacking = "wof_external_backing";

/// Whether a matched file is opened at all, whether the two ioctls are then asked, and the closed token the
/// extents row carries after its state (empty for an ordinary file).
struct ExtentsDecision {
    bool open{false};
    bool ioctl{false};
    std::string_view note{};
};

/// Decided from the LISTING attributes before any open. Any recall or offline bit: never opened, read as
/// `placeholder` (measured: an unhydrated file is 0x401620, pinned variants 0x481620 and 0x501620). WOF,
/// dedup and app-execution alias: opened for attributes, no ioctl, the note names the family
/// (`wof_external_backing`, `dedup_external_backing`, `app_exec_alias`). A cloud file with no recall bit is
/// fully local: opened, asked for extents, and flagged `cloud`. An ordinary file: opened, asked, no note.
[[nodiscard]] constexpr ExtentsDecision extents_decision(std::uint32_t attributes, TagFamily family) noexcept {
    if (has_recall(attributes))
        return {false, false, "placeholder"};
    switch (family) {
    case TagFamily::wof:
        return {true, false, kNoteWofBacking};
    case TagFamily::dedup:
        return {true, false, "dedup_external_backing"};
    case TagFamily::app_exec:
        return {true, false, "app_exec_alias"};
    case TagFamily::cloud:
        return {true, true, "cloud"};
    case TagFamily::none:
        break;
    }
    return {true, true, {}};
}

/// The decision taken again from the attributes and tag read on the OPENED handle: nullopt when the entry is
/// no longer a plain file-like entry (a link, a directory, an entry the leg cannot search, or any entry
/// whose type changed since it was listed): no ioctl, extents `failed`.
[[nodiscard]] constexpr std::optional<ExtentsDecision> handle_decision(std::uint32_t attributes,
                                                                       std::uint32_t reparse_tag) noexcept {
    const Listed now = classify(attributes, reparse_tag);
    if (now.type != ci::DirEntry::Type::file || now.gap)
        return std::nullopt;
    return extents_decision(attributes, now.family);
}

/// The reading of FSCTL_GET_EXTERNAL_BACKING's answer, asked on every file whose decision says `ioctl`,
/// BEFORE retrieval pointers (a CompactOS/WOF file lists as a plain file and its retrieval pointers read as
/// one hole, so backing is ruled out before any extent is trusted). 0: backed. ERROR_OBJECT_NOT_EXTERNALLY_BACKED
/// (measured on a plain file) and the three codes that mean "not implemented here" (1, 50, 87): not backed.
/// Any other error: unknown, and the extents read `failed`: an extent list is never reported for a file whose
/// backing could not be ruled out. The answer's bytes are not parsed (either WOF provider reads
/// wof_external_backing). What a FAT-family volume answers is not measured; the live run's FAT control
/// proves an ordinary file there still gets extents.
enum class Backing : std::uint8_t { backed, not_backed, unknown };

[[nodiscard]] constexpr Backing external_backing_of(std::uint32_t win32_error) noexcept {
    if (win32_error == 0)
        return Backing::backed;
    if (win32_error == kErrorObjectNotExternallyBacked || win32_error == kErrorInvalidFunction ||
        win32_error == kErrorNotSupported || win32_error == kErrorInvalidParameter)
        return Backing::not_backed;
    return Backing::unknown;
}

/// One retrieval-pointer run as the call returns it: the VCN where the NEXT run starts, and the LCN of this
/// one (-1 for a hole).
struct Run {
    std::uint64_t next_vcn{0};
    std::int64_t lcn{0};
};

/// How many runs of a retrieval-pointer answer may be read: the count the answer states, held to what lies
/// inside the `bytes` the call returned (after `header` bytes, `run_size` each) and to `cap`. This is the
/// bound on a read of a kernel-filled buffer: a stated count the bytes cannot hold, an answer shorter than
/// its header and a zero run size all read none. The shell binds the sizes of the system's own structure and
/// reads that many runs.
[[nodiscard]] constexpr std::size_t retrieval_runs_to_read(std::size_t bytes, std::size_t header,
                                                           std::size_t run_size, std::uint64_t stated,
                                                           std::size_t cap) noexcept {
    if (bytes < header || run_size == 0)
        return 0;
    const std::size_t fit = (bytes - header) / run_size;
    const std::uint64_t n = stated < fit ? stated : fit;
    return n < cap ? static_cast<std::size_t>(n) : cap;
}

/// What the shell hands over. `win32_error` is GetLastError() verbatim (0 when the call succeeded), `runs`
/// only the runs that lie inside the bytes returned. The mapper owns EVERY status decision; there is no
/// separate more-data or end-of-file flag that could disagree with the code.
struct RetrievalInput {
    std::uint32_t win32_error{0};
    std::uint64_t starting_vcn{0};
    std::span<const Run> runs;
    std::uint64_t cluster_bytes{0};
    std::uint64_t file_size{0};
    std::uint32_t attributes{0};
    std::string_view note{};
};

/// The extents of one file from the answer of FSCTL_GET_RETRIEVAL_POINTERS, mapped onto the existing flag
/// bits only. A cluster size of 0 fails. ERROR_HANDLE_EOF (measured for a resident file, a 0-byte file and an
/// app-exec alias): size 0 is ok with no extents, size > 0 is one resident extent. The three unsupported
/// codes read unsupported. 0 and ERROR_MORE_DATA BOTH map the returned runs (a partial answer is an answer,
/// never a failure): logical = previous vcn * cluster, physical = lcn * cluster, length = (next - previous) *
/// cluster; lcn -1 is unallocated with physical 0 (a wholly sparse file answers success with ONE such run);
/// the compressed attribute marks every extent compressed (a LZNT1 file alternates data runs and lcn -1 runs,
/// which therefore read compressed AND unallocated); the encrypted attribute marks every extent encrypted
/// (the documented attribute, NOT MEASURED on a real EFS file: a unit-level mapping only). A multiplication
/// that overflows 64 bits, a non-increasing vcn, an lcn below -1 or no run at all fails. ERROR_MORE_DATA also
/// sets total = runs + 1 and total_exact false. Any other error fails, ERROR_INSUFFICIENT_BUFFER (122)
/// included: a buffer under 32 bytes answers it, and the shell's buffer size rules that out. ONE call, no
/// paging: the row lists at most kMaxExtents runs and already reads `>=33` for a longer file, and a bounded
/// page loop would still answer a lower bound for the files that need it. `note` is carried on the two
/// answered returns only (end of file, mapped runs): a fully local cloud file reads `ok:cloud`, and a failed
/// or unsupported answer carries none, so no `failed:cloud` or `unsupported:cloud` is ever printed (the
/// README lists exactly the tokens that remain).
[[nodiscard]] inline FileExtents map_retrieval_pointers(const RetrievalInput& in) {
    FileExtents out;
    out.state = ExtentsState::failed;
    if (in.cluster_bytes == 0)
        return out;
    if (in.win32_error == kErrorHandleEof) {
        out.state = ExtentsState::ok;
        out.note = in.note;
        if (in.file_size > 0)
            out.add({0, 0, in.file_size, kResident});
        return out;
    }
    if (in.win32_error == kErrorInvalidFunction || in.win32_error == kErrorNotSupported ||
        in.win32_error == kErrorInvalidParameter) {
        out.state = ExtentsState::unsupported;
        return out;
    }
    if ((in.win32_error != 0 && in.win32_error != kErrorMoreData) || in.runs.empty())
        return out;

    std::uint32_t flags = 0;
    if ((in.attributes & kAttrCompressed) != 0)
        flags |= kCompressed;
    if ((in.attributes & kAttrEncrypted) != 0)
        flags |= kEncrypted;
    constexpr std::uint64_t kMax = ~std::uint64_t{0};
    std::uint64_t vcn = in.starting_vcn;
    FileExtents mapped;
    for (const Run& run : in.runs) {
        if (run.next_vcn <= vcn || vcn > kMax / in.cluster_bytes || run.next_vcn > kMax / in.cluster_bytes)
            return out;
        Extent e;
        e.logical = vcn * in.cluster_bytes;
        e.length = (run.next_vcn - vcn) * in.cluster_bytes;
        e.flags = flags;
        if (run.lcn == -1) {
            e.flags |= kUnallocated;
        } else if (run.lcn < -1 || static_cast<std::uint64_t>(run.lcn) > kMax / in.cluster_bytes) {
            return out;
        } else {
            e.physical = static_cast<std::uint64_t>(run.lcn) * in.cluster_bytes;
        }
        mapped.add(e);
        vcn = run.next_vcn;
    }
    mapped.state = ExtentsState::ok;
    mapped.note = in.note;
    if (in.win32_error == kErrorMoreData) {
        ++mapped.total;
        mapped.total_exact = false;
    }
    return mapped;
}

// ---- identity: ONE policy ----

/// Listing ids are stable on NTFS ONLY, decided by the filesystem NAME. ReFS ids are 128-bit; the FAT family's
/// listing ids are NON-ZERO, directory-position-derived and not stable (measured 0x400080 and 0x3b0a0, with
/// the root 0), so a zero test could never catch them.
[[nodiscard]] constexpr bool fs_has_stable_ids(std::string_view fs_name) noexcept {
    return fs_name == "NTFS";
}

/// The ONE id policy, for a listed directory's own id and every entry id: the low half when the filesystem
/// has stable ids, the high half is zero and the low half is neither 0 nor all ones; else 0 (unknown). On
/// NTFS the 64-bit listing id was measured equal to the low half of the 128-bit FileIdInfo, upper half zero
/// (11 of 11): that is the equality the walker's identity backstop relies on.
[[nodiscard]] constexpr std::uint64_t stable_id(bool stable_fs, std::uint64_t low, std::uint64_t high) noexcept {
    return stable_fs && high == 0 && low != 0 && low != ~std::uint64_t{0} ? low : 0;
}

// ---- volumes ----

inline constexpr std::uint32_t kDriveUnknown = 0;
inline constexpr std::uint32_t kDriveNoRootDir = 1;
inline constexpr std::uint32_t kDriveRemovable = 2;
inline constexpr std::uint32_t kDriveFixed = 3;
inline constexpr std::uint32_t kDriveRemote = 4;
inline constexpr std::uint32_t kDriveCdrom = 5;
inline constexpr std::uint32_t kDriveRamdisk = 6;

/// The `fstype` of a volume's mount entry: the filesystem name for a fixed drive that has a volume GUID and
/// answered, else a drive-type token that is NOT on the allow-list, so the unchanged plan refuses the volume
/// (`remote` reads network_mount through one Os::windows clause).
[[nodiscard]] inline std::string fstype_token(std::uint32_t drive_type, std::string_view fs_name, bool has_volume_guid,
                                              bool info_ok) {
    switch (drive_type) {
    case kDriveFixed:
        if (!has_volume_guid)
            return "not_a_volume"; // a SUBST drive
        return info_ok ? std::string(fs_name) : "unreadable";
    case kDriveRemovable:
        return "removable";
    case kDriveCdrom:
        return "cdrom";
    case kDriveRamdisk:
        return "ramdisk";
    case kDriveRemote:
        return std::string(kWindowsRemoteDrive);
    case kDriveNoRootDir:
        return "no_volume";
    default:
        return "unknown";
    }
}

// ---- the confinement primitive's refusals, read as the walk's own vocabulary ----

/// What a failed open of the root path (or a hop) means. A cloud-family tag is no link (a sync-root folder on
/// the root path that is not populated: the walk's own root gap then says `dataless`); any other refused
/// reparse is a link; not found and not-a-directory come from the OS error; the rest is `other`.
[[nodiscard]] constexpr ci::RootState root_state_of(cfs::Reason reason, std::uint32_t os_error,
                                                    std::uint32_t reparse_tag) noexcept {
    switch (reason) {
    case cfs::Reason::None:
        return ci::RootState::ok;
    case cfs::Reason::ReparseRejected:
        return cfs::is_cloud_reparse_tag(reparse_tag) ? ci::RootState::other : ci::RootState::is_link;
    case cfs::Reason::OsError:
        if (os_error == kErrorFileNotFound || os_error == kErrorPathNotFound)
            return ci::RootState::not_found;
        if (os_error == kErrorDirectory)
            return ci::RootState::not_a_directory;
        return ci::RootState::other;
    default:
        return ci::RootState::other;
    }
}

/// What a failed listing means: a refused cloud directory, and the platform's own answer for a folder whose
/// provider is not running (measured: listing a not-populated folder with no provider), are `dataless`;
/// access denied is `permission_denied`; the rest is `unreadable`.
[[nodiscard]] constexpr ci::ListError list_error_of(cfs::Reason reason, std::uint32_t os_error,
                                                    std::uint32_t reparse_tag) noexcept {
    if (reason == cfs::Reason::ReparseRejected && cfs::is_cloud_reparse_tag(reparse_tag))
        return ci::ListError::dataless;
    if (os_error == kErrorCloudFileProviderNotRunning)
        return ci::ListError::dataless;
    if (os_error == kErrorAccessDenied)
        return ci::ListError::permission_denied;
    return ci::ListError::unreadable;
}

} // namespace yuzu::file_search::win_rules
