#pragma once

/**
 * win_hive_file_guard.hpp -- the offline-hive FILE guard behind an injectable seam, shared by every
 * plugin that mounts a profile's NTUSER.DAT as SYSTEM (privacy_permissions' read arm, registry's
 * per-user write arm).
 *
 * windows.h-free by design. The Win32 shell (win_hive_file_probe.hpp's Win32HiveFileProbe) answers
 * one question per probe call -- an attribute word, a leaf's facts from its own handle, a directory
 * listing, a sidecar's link count -- and HiveFileGuard (the OfflineHiveFileCheck hooks' logic)
 * decides: its call order, every refusal token and the sidecar precedence are plain code over
 * HiveFileProbe, locked on every host by a fake probe in
 * tests/unit/test_privacy_permissions_win_walk.cpp. The pure decision block it routes through
 * (HiveFileFacts, the tokens, classify_hive_file) lives in this header too.
 *
 * Lifted verbatim from privacy_permissions (its privacy_permissions_hive_guard.hpp and the hive-file
 * block of privacy_permissions_win_parsers.hpp); behaviour is byte-identical. The guard is still
 * OPT-IN per with_user_hive call (the OfflineHiveFileCheck argument): making it the default for
 * every with_user_hive consumer is the separate tracker #5291, which this lift serves but does not
 * close.
 *
 * The deadline is INJECTED (`expired`), so the guard's API depends on neither a run's retention
 * budget nor any plugin's row model.
 *
 * The leaf's, every ancestor's and each sidecar's deciding facts come from a HANDLE opened for that
 * step; the two handle-less sources are the drive type (GetDriveTypeW) and the sidecar listing. A
 * listing "not a reparse point" is never final -- it is re-read from the sidecar's own handle; a
 * listing reparse hit and the entry count refuse on the listing alone.
 * RegLoadKeyW has no handle-relative form, so the load is by path and the SAME file identity is
 * re-verified from a fresh attribute-only handle after it.
 * Residual: the kernel parses whatever the path resolved to in that window (every `reg load`
 * carries it); swapping the path needs write access to the profile directory.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::win {

/// ERROR_FILE_NOT_FOUND, mirrored so this header stays windows.h-free (win_hive_file_probe.hpp
/// static_asserts it against the SDK).
inline constexpr long kHiveErrorFileNotFound = 2;

// ── offline hive-file guard (pure decisions; the Win32 facts are gathered in the shell) ──

inline constexpr std::uint32_t kDriveFixed = 3; // DRIVE_FIXED
inline constexpr std::size_t kMaxHivePathDepth = 32;
inline constexpr std::uint64_t kMaxHiveBytes = 512ull * 1024ull * 1024ull;
/// A stock profile directory holds a handful of `<hive>*` transaction-log sidecars (.LOG1/.LOG2,
/// .TM.blf, .TMContainer*.regtrans-ms); more than this is refused rather than walked.
inline constexpr std::size_t kMaxHiveSidecars = 64;

/// What the shell learned about one NTUSER.DAT, every handle-derived fact taken from an opened
/// HANDLE (the drive type and the sidecar listing are the two handle-less sources; the path facts
/// come from the requested path before any syscall). `final_path_matches` is the shell's verdict
/// that GetFinalPathNameByHandleW(VOLUME_NAME_DOS) equals `\\?\` + the requested path under
/// Windows' own ordinal case-insensitive comparison (CompareStringOrdinal on the wide
/// strings: a non-ASCII case-only difference is the same path, which byte-wise ASCII folding on
/// UTF-8 would misjudge). The default is the neutral `true`, so only the facts gathered so far can
/// trip a classification.
struct HiveFileFacts {
    bool path_is_unc = false;
    std::uint32_t drive_type = kDriveFixed;
    std::size_t depth = 0;
    bool ancestor_reparse = false;
    bool is_reparse = false;
    bool is_directory = false;
    bool is_disk_file = true;
    /// FILE_ATTRIBUTE_OFFLINE / RECALL_ON_OPEN / RECALL_ON_DATA_ACCESS: a cloud or tiered
    /// placeholder, which RegLoadKeyW would recall while the process-wide hive lock is held.
    /// Never FILE_ATTRIBUTE_SPARSE_FILE (a resident file can be sparse).
    bool not_resident = false;
    std::string owner_sid;
    std::string profile_sid;
    bool final_path_matches = true;
    std::uint64_t size = 0;
    /// Facts about the `<hive file name>*` sidecars beside the leaf (see read_sidecars).
    bool sidecar_reparse = false;
    bool sidecar_hardlinked = false;
    std::size_t sidecar_count = 0;
};

/// Hive-refusal token literals (the cause after `<profile>:`).
inline constexpr std::string_view kHivePathUnc = "hive_path_unc";
inline constexpr std::string_view kHivePathNotFixed = "hive_path_not_fixed";
inline constexpr std::string_view kHivePathTooDeep = "hive_path_too_deep";
inline constexpr std::string_view kHivePathReparseAncestor = "hive_path_reparse_ancestor";
inline constexpr std::string_view kHiveReparsePoint = "hive_reparse_point";
inline constexpr std::string_view kHiveNotRegular = "hive_not_regular";
inline constexpr std::string_view kHiveNotResident = "hive_not_resident";
inline constexpr std::string_view kHiveOwnerUnexpected = "hive_owner_unexpected";
inline constexpr std::string_view kHivePathRedirected = "hive_path_redirected";
inline constexpr std::string_view kHiveOversized = "hive_oversized";
inline constexpr std::string_view kHiveSidecarReparse = "hive_sidecar_reparse";
inline constexpr std::string_view kHiveSidecarHardlinked = "hive_sidecar_hardlinked";
inline constexpr std::string_view kHiveSidecarCount = "hive_sidecar_count";
inline constexpr std::string_view kHiveIdentityChanged = "hive_identity_changed";
inline constexpr std::string_view kHiveTimeout = "timeout";

/// A stock profile hive is owned by the profile's own user, LocalSystem or BUILTIN\Administrators;
/// any other owner is refused (widen only to an owner measured on a real host, never to "any").
[[nodiscard]] inline bool hive_owner_allowed(std::string_view owner_sid,
                                             std::string_view profile_sid) noexcept {
    return !owner_sid.empty() &&
           (owner_sid == profile_sid || owner_sid == "S-1-5-18" || owner_sid == "S-1-5-32-544");
}

/// The first refusal token for a hive file's facts, in this fixed order, or nullopt to proceed.
/// Path facts come first so a UNC/redirected target is refused before any leaf fact is trusted.
[[nodiscard]] inline std::optional<std::string> classify_hive_file(const HiveFileFacts& f) {
    if (f.path_is_unc) return std::string{kHivePathUnc};
    if (f.drive_type != kDriveFixed) return std::string{kHivePathNotFixed};
    if (f.depth > kMaxHivePathDepth) return std::string{kHivePathTooDeep};
    if (f.ancestor_reparse) return std::string{kHivePathReparseAncestor};
    if (f.is_reparse) return std::string{kHiveReparsePoint};
    if (f.is_directory || !f.is_disk_file) return std::string{kHiveNotRegular};
    if (f.not_resident) return std::string{kHiveNotResident};
    if (!hive_owner_allowed(f.owner_sid, f.profile_sid)) return std::string{kHiveOwnerUnexpected};
    if (!f.final_path_matches) return std::string{kHivePathRedirected};
    if (f.size > kMaxHiveBytes) return std::string{kHiveOversized};
    if (f.sidecar_reparse) return std::string{kHiveSidecarReparse};
    if (f.sidecar_hardlinked) return std::string{kHiveSidecarHardlinked};
    if (f.sidecar_count > kMaxHiveSidecars) return std::string{kHiveSidecarCount};
    return std::nullopt;
}

// Mirrored FILE_ATTRIBUTE_* bits (win_hive_file_probe.hpp static_asserts each against the SDK).
inline constexpr std::uint32_t kFileAttributeDirectory = 0x10;
inline constexpr std::uint32_t kFileAttributeReparsePoint = 0x400;
inline constexpr std::uint32_t kFileAttributeOffline = 0x1000;
inline constexpr std::uint32_t kFileAttributeRecallOnOpen = 0x40000;
inline constexpr std::uint32_t kFileAttributeRecallOnDataAccess = 0x400000;

[[nodiscard]] constexpr bool is_reparse_attribute(std::uint32_t attrs) noexcept {
    return (attrs & kFileAttributeReparsePoint) != 0;
}

/// Maps a leaf's attribute word to its HiveFileFacts bits. `not_resident` is OFFLINE,
/// RECALL_ON_OPEN or RECALL_ON_DATA_ACCESS -- never SPARSE_FILE (a resident file can be sparse).
inline void apply_attributes(std::uint32_t attrs, HiveFileFacts& f) noexcept {
    f.is_reparse = is_reparse_attribute(attrs);
    f.is_directory = (attrs & kFileAttributeDirectory) != 0;
    f.not_resident = (attrs & (kFileAttributeOffline | kFileAttributeRecallOnOpen |
                               kFileAttributeRecallOnDataAccess)) != 0;
}

/// A file's identity (volume serial + 128-bit file id; mirrors FILE_ID_INFO).
struct FileId {
    std::uint64_t volume_serial = 0;
    std::array<std::uint8_t, 16> file_id{};
    [[nodiscard]] bool operator==(const FileId&) const = default;
};

/// Everything read from the NTUSER.DAT leaf's own attribute-only handle.
struct LeafFacts {
    std::uint32_t attributes = 0;
    bool is_disk_file = true;
    std::uint64_t size = 0;
    std::string owner_sid;
    bool final_path_matches = true;
    FileId id;
};

/// One `<leaf>*` directory entry as the listing reported it.
struct SidecarEntry {
    std::wstring name;
    std::uint32_t find_attributes = 0;
};

/// The file system as the guard sees it. The code-returning methods each mirror one Win32 step and
/// return its code (0 = success; drive_type returns the drive type); `opens` counts the handle
/// opens an implementation made (a test proves the deadline-first order with it). Raw `long` codes
/// and out-parameters by design, an exception to cpp-conventions' std::expected rule: each method
/// mirrors one Win32 call, and list_sidecars returns a partial listing beside the code.
struct HiveFileProbe {
    HiveFileProbe() = default;
    HiveFileProbe(const HiveFileProbe&) = delete;
    HiveFileProbe& operator=(const HiveFileProbe&) = delete;
    virtual ~HiveFileProbe() = default;

    std::size_t opens = 0;

    [[nodiscard]] virtual std::uint32_t drive_type(const std::wstring& root) = 0;
    /// An ancestor directory's attribute word, from its own handle.
    virtual long path_attributes(const std::wstring& path, std::uint32_t& attrs) = 0;
    virtual long leaf_facts(const std::wstring& path, LeafFacts& out) = 0;
    /// Appends up to `limit` `<leaf>*` entries of `dir` (never `.`, `..` or the leaf itself) to
    /// `out`. A listing that fails part-way returns the entries collected so far AND the code; a
    /// directory with no match (FILE_NOT_FOUND / NO_MORE_FILES) is code 0.
    virtual long list_sidecars(const std::wstring& dir, const std::wstring& leaf, std::size_t limit,
                               std::vector<SidecarEntry>& out) = 0;
    /// A sidecar's link count and attribute word, from its own handle.
    virtual long sidecar_facts(const std::wstring& path, std::uint32_t& links,
                               std::uint32_t& attrs) = 0;
};

[[nodiscard]] inline std::string stat_failed(long code) {
    return "hive_stat_failed:win32_" + std::to_string(static_cast<unsigned long>(code));
}

/// Verifies the NTUSER.DAT an offline load is about to use (the OfflineHiveFileCheck hooks).
struct HiveFileGuard {
    HiveFileProbe& probe;
    std::function<bool()> expired; // the run's cooperative deadline (sticky in the caller)
    std::string profile_sid;
    std::optional<FileId> snapshot;

    /// Fills the sidecar facts from the `<leaf>*` entries of `dir` (the kernel's transaction-log
    /// sidecars: `<hive>.LOG1`, `<hive>{guid}.TM.blf`, ...; RegLoadKeyW opens or creates them
    /// following any link, so a link there is not safe to follow for a SYSTEM caller). A reparse
    /// point is read from the listing and AGAIN from the opened handle (the entry can be swapped
    /// between the two); a hard link needs the open. A sidecar that does not exist is fine. An
    /// entry's decision, made in listing order, outranks a later listing failure. "" or a token.
    std::string read_sidecars(const std::wstring& dir, const std::wstring& leaf, HiveFileFacts& f) {
        const std::wstring base = dir.ends_with(L'\\') ? dir : dir + L"\\";
        std::vector<SidecarEntry> entries;
        const long list_rc = probe.list_sidecars(dir, leaf, kMaxHiveSidecars + 1, entries);
        for (const auto& e : entries) {
            if (++f.sidecar_count > kMaxHiveSidecars) break; // classify_hive_file refuses
            if (is_reparse_attribute(e.find_attributes)) {
                f.sidecar_reparse = true;
                break;
            }
            std::uint32_t links = 0, attrs = 0;
            if (const long rc = probe.sidecar_facts(base + e.name, links, attrs); rc != 0) {
                if (rc == kHiveErrorFileNotFound) continue; // listed, then gone: absent is fine
                return stat_failed(rc);
            }
            if (is_reparse_attribute(attrs)) {
                f.sidecar_reparse = true;
                break;
            }
            if (links > 1) {
                f.sidecar_hardlinked = true;
                break;
            }
        }
        if (list_rc != 0 && f.sidecar_count <= kMaxHiveSidecars && !f.sidecar_reparse &&
            !f.sidecar_hardlinked)
            return stat_failed(list_rc);
        return {};
    }

    std::string before_load(const std::wstring& path) {
        // FIRST: the deadline (after the lock wait and privilege enable, before any file syscall).
        if (expired()) return std::string{kHiveTimeout};

        HiveFileFacts f;
        f.profile_sid = profile_sid;
        // Neutral leaf facts (owner = the profile, final_path_matches defaults true), so that only
        // the path facts can trip this early classification.
        f.owner_sid = profile_sid;
        f.path_is_unc = path.starts_with(L"\\\\");

        std::vector<std::wstring> parts;
        std::wstring root;
        if (!f.path_is_unc && path.size() >= 3 && path[1] == L':' && path[2] == L'\\') {
            root = path.substr(0, 3);
            f.drive_type = probe.drive_type(root);
            std::size_t pos = 3;
            while (pos <= path.size()) {
                const auto end = path.find(L'\\', pos);
                const auto part = path.substr(pos, end == std::wstring::npos ? end : end - pos);
                if (!part.empty()) parts.push_back(part);
                if (end == std::wstring::npos) break;
                pos = end + 1;
            }
        } else {
            f.drive_type = 0; // not kDriveFixed: classify_hive_file refuses (0 is DRIVE_UNKNOWN)
        }
        f.depth = parts.size();
        if (const auto t = classify_hive_file(f)) return *t;
        if (parts.empty()) return std::string{kHiveNotRegular};

        // Hop by hop from the drive root: no hop ever follows a junction/symlink.
        std::wstring cur = root;
        for (std::size_t i = 0; i + 1 < parts.size(); ++i) {
            cur += (i ? L"\\" : L"") + parts[i];
            std::uint32_t attrs = 0;
            if (const long rc = probe.path_attributes(cur, attrs); rc != 0) return stat_failed(rc);
            if (is_reparse_attribute(attrs)) {
                f.ancestor_reparse = true;
                break;
            }
        }
        if (f.ancestor_reparse) return std::string{kHivePathReparseAncestor};

        LeafFacts leaf;
        if (const long rc = probe.leaf_facts(path, leaf); rc != 0) return stat_failed(rc);
        apply_attributes(leaf.attributes, f);
        f.is_disk_file = leaf.is_disk_file;
        f.size = leaf.size;
        f.owner_sid = leaf.owner_sid;
        f.final_path_matches = leaf.final_path_matches;
        // `cur` is the leaf's directory, already hop-verified above.
        if (auto t = read_sidecars(cur, parts.back(), f); !t.empty()) return t;
        if (const auto t = classify_hive_file(f)) return *t;
        snapshot = leaf.id;
        return {}; // the leaf handle is closed here: RegLoadKeyW needs exclusive access
    }

    std::string after_load(const std::wstring& path) {
        if (!snapshot) return std::string{kHiveIdentityChanged};
        LeafFacts leaf;
        if (const long rc = probe.leaf_facts(path, leaf); rc != 0) return stat_failed(rc);
        if (!(leaf.id == *snapshot)) return std::string{kHiveIdentityChanged};
        return {};
    }
};

} // namespace yuzu::win
