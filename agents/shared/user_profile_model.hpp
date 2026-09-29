#pragma once

/**
 * user_profile_model.hpp — pure model for Windows user-profile / registry-hive
 * discovery (PR1.7).
 *
 * windows.h-free by design (mirrors tar_module_etw.hpp's EtwImageSample
 * split): the Win32 shell (agents/shared/win_profiles.hpp) gathers raw
 * ProfileList rows and HKEY_USERS subkey names into the plain structs below;
 * every classification and formatting decision here is a pure function over
 * that plain data, so the whole decision layer is unit-tested on every host
 * (test_user_profile_model.cpp) without linking advapi32.
 *
 * ADR-0024 D11 invariant (binds this header, not just license_scan's per-user
 * records): when a profile's display name cannot be resolved,
 * ProfileInfo::profile_name stays EMPTY — it must NEVER fall back to the SID.
 * installed_apps_plugin.cpp's do_list_per_user originally carried a
 * `username = sid` fallback that violated this rule; #2771 migrated it onto
 * this header (which renders the empty case as "-" for display, never the
 * SID) rather than cloning the old fallback.
 */

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::profiles {

/// Whether a HKEY_USERS-shaped hive for a SID is reachable right now.
enum class HiveState {
    loaded,              // HKU\<SID> is present (user logged in, or mounted elsewhere)
    loaded_classes_only, // only HKU\<SID>_Classes is present (rare: partial/COM-only load)
    not_loaded,          // neither present — an offline RegLoadKeyW mount is the only path in
};

[[nodiscard]] constexpr std::string_view hive_state_name(HiveState s) {
    switch (s) {
    case HiveState::loaded:
        return "loaded";
    case HiveState::loaded_classes_only:
        return "loaded_classes_only";
    case HiveState::not_loaded:
        return "not_loaded";
    }
    return "not_loaded"; // unreachable — cases are exhaustive so -Wswitch flags enum drift
}

/// One HKLM ProfileList subkey as read by the Win32 shell. profile_image_path
/// is ALREADY environment-expanded by the shell (two-pass
/// ExpandEnvironmentStringsW — see win_profiles.hpp) so this layer never
/// re-expands it; empty means ProfileImagePath was absent or unreadable.
struct RawProfileRecord {
    std::string sid;
    std::string profile_image_path;
    /// True when ProfileImagePath EXISTS but could not be read or decoded, as
    /// distinct from being absent — both leave profile_image_path empty, and
    /// before #2771 up-S2 the two were indistinguishable, so an over-long
    /// path silently became "no path" with no signal at all.
    bool profile_image_path_unreadable{false};
};

/// One resolved, classified profile.
struct ProfileInfo {
    std::string sid;
    std::string profile_name; // last path component of profile_image_path;
                              // EMPTY when unresolvable — NEVER the sid (ADR-0024 D11)
    std::string profile_path; // == the raw record's profile_image_path (already expanded)
    HiveState state{HiveState::not_loaded};
    bool profile_path_unreadable{false}; // carried from RawProfileRecord (#2771 up-S2)
};

/// The three well-known local-system profile SIDs ProfileList always carries
/// (LocalSystem / LocalService / NetworkService). Matches the existing
/// convention in tar_mapdrive_collector.cpp's is_system_sid and
/// licensing_win.cpp's enumerate_profiles verbatim — deliberately not a
/// general S-1-5-* classifier, so it stays in lockstep with those call sites.
[[nodiscard]] inline bool is_system_sid(std::string_view sid) {
    return sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20";
}

/// Ordinal (byte-wise ASCII) case-insensitive equality. Windows profile
/// folder names are case-insensitive by convention -- this deliberately
/// does NOT use locale-aware comparison; it matches Windows identifier
/// semantics, not natural-language casing rules.
[[nodiscard]] inline bool iequals_ascii(std::string_view a, std::string_view b) {
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

/// Last '\' or '/' separated component of `profile_image_path`, with any
/// trailing separators stripped first (so "C:\Users\alice\" yields "alice",
/// matching basename-style semantics). Returns "" only when the path is
/// empty or consists entirely of separators — the caller must never
/// substitute the sid for that empty result (ADR-0024 D11).
[[nodiscard]] inline std::string profile_name_from_path(std::string_view profile_image_path) {
    std::string_view p = profile_image_path;
    while (!p.empty() && (p.back() == '\\' || p.back() == '/'))
        p.remove_suffix(1);
    if (p.empty())
        return {};
    auto last_sep = p.find_last_of("\\/");
    std::string_view name = (last_sep == std::string_view::npos) ? p : p.substr(last_sep + 1);
    return std::string{name};
}

/// Classifies a SID's hive reachability from the live HKEY_USERS subkey list
/// (as returned by win_profiles.hpp's enumerate_hku_subkeys). `hku_subkeys`
/// holds exactly the subkey names under HKEY_USERS, e.g. {"S-1-5-21-...-1001",
/// "S-1-5-21-...-1001_Classes", ...}. The real hive outranks a Classes-only
/// sighting of the same SID.
[[nodiscard]] inline HiveState classify_hive_state(std::string_view sid,
                                                    std::span<const std::string> hku_subkeys) {
    bool loaded = false;
    bool classes_only = false;
    const std::string classes_suffix = std::string{sid} + "_Classes";
    for (const auto& subkey : hku_subkeys) {
        if (subkey == sid) {
            loaded = true;
            break;
        }
        if (subkey == classes_suffix)
            classes_only = true;
    }
    if (loaded)
        return HiveState::loaded;
    if (classes_only)
        return HiveState::loaded_classes_only;
    return HiveState::not_loaded;
}

/// Builds the classified profile list from raw ProfileList rows + the live
/// HKEY_USERS subkey snapshot. System SIDs (is_system_sid) are filtered
/// BEFORE any other work — filtering after reading profile data (as
/// installed_apps_plugin.cpp's do_list_per_user does) wastes the read.
/// Duplicate SIDs in `records` keep only the first occurrence.
[[nodiscard]] inline std::vector<ProfileInfo> build_profile_list(
    std::span<const RawProfileRecord> records, std::span<const std::string> hku_subkeys) {
    std::vector<ProfileInfo> out;
    out.reserve(records.size());
    for (const auto& rec : records) {
        if (is_system_sid(rec.sid))
            continue;
        bool already_seen = false;
        for (const auto& seen : out) {
            if (seen.sid == rec.sid) {
                already_seen = true;
                break;
            }
        }
        if (already_seen)
            continue;

        ProfileInfo info;
        info.sid = rec.sid;
        info.profile_path = rec.profile_image_path;
        info.profile_name = profile_name_from_path(rec.profile_image_path);
        info.state = classify_hive_state(rec.sid, hku_subkeys);
        info.profile_path_unreadable = rec.profile_image_path_unreadable;
        out.push_back(std::move(info));
    }
    return out;
}

/// Finds the SID whose resolved profile_name equals `username` (ordinal
/// case-insensitive match -- Windows profile folder names are case-
/// insensitive by convention; the pre-PR1.7 code built the NTUSER.DAT path
/// directly against a case-insensitive filesystem, so matching case-
/// sensitively here would regress that behaviour for no benefit) — the pure
/// half of registry.get_user_value's username-to-SID resolution. Returns
/// the FIRST match in `profiles` order when more than one profile resolves
/// to the same name (redirected/renamed profiles can collide); ambiguity is
/// resolved by discovery order, not reported. Never matches an entry whose
/// profile_name is empty — an unresolved name coincidentally equal to a
/// lookup would hide a real ambiguity rather than answer it.
[[nodiscard]] inline std::optional<std::string> find_sid_by_username(
    std::span<const ProfileInfo> profiles, std::string_view username) {
    if (username.empty())
        return std::nullopt;
    for (const auto& p : profiles) {
        if (!p.profile_name.empty() && iequals_ascii(p.profile_name, username))
            return p.sid;
    }
    return std::nullopt;
}

/// Strips '|', '\r', '\n' from a field before it is written into the
/// pipe-delimited plugin-output protocol, so a value containing one of those
/// cannot forge a column or row boundary. Same behaviour as
/// registry_plugin.cpp's local sanitize_field, which today applies only to
/// the unknown-action error string; every field this header renders goes
/// through this copy instead.
[[nodiscard]] inline std::string sanitize_field(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        out += (c == '|' || c == '\n' || c == '\r') ? '_' : c;
    return out;
}

/// Renders one profile as `<sid>|<name>|<path>|<state>`, with every field
/// sanitised and empty fields rendered as "-". No leading discriminator tag
/// (PR1.7 remediation, Gate 4 happy-path finding): list_profiles has exactly
/// one row shape, and the dashboard's split_fields (result_parsing.hpp) has
/// no per-plugin entry for "registry" so it falls to the generic
/// split-on-all-pipes path -- every other multi-column plugin (procfetch,
/// netstat, vuln_scan) emits raw pipe-joined field values with no
/// self-describing prefix for exactly this reason. A leading "profile|" tag
/// was an extra field split_fields didn't know to skip, shifting every real
/// column one position right of its header.
[[nodiscard]] inline std::string render_profile_row(const ProfileInfo& info) {
    auto field = [](std::string_view v) -> std::string {
        return v.empty() ? std::string{"-"} : sanitize_field(v);
    };
    std::string out = field(info.sid);
    out += '|';
    out += field(info.profile_name);
    out += '|';
    out += field(info.profile_path);
    out += '|';
    out += hive_state_name(info.state);
    return out;
}

// ---------------------------------------------------------------------------
// Hive-access outcome rendering (#2771 qa-S2 / up-S4)
//
// The status enum lives HERE, not in win_profiles.hpp, so the whole
// output-decision layer for the hive ladder is reachable off-Windows and
// unit-testable on every host. win_profiles.hpp aliases it back into
// yuzu::win, so existing `yuzu::win::HiveAccessStatus::ok` call sites are
// unchanged.
// ---------------------------------------------------------------------------

/// Outcome of the with_user_hive access ladder, rendered honestly by the
/// caller instead of collapsing every non-ok case to silence.
enum class HiveAccessStatus {
    ok,                // fn was called against a reachable root
    not_found,         // no live hive and no offline profile path to mount
    privilege_missing, // an offline mount was needed but SeBackup/SeRestore
                       // could not both be enabled
    mount_failed,      // an offline mount was attempted (privileges ok) and
                       // RegLoadKeyW (or the subsequent root open) failed
};

/// Outcome of resolving one value inside a reached user hive. Folds the
/// key-OPEN result into the value-READ result so a caller renders one honest
/// reason. `key_access_denied` is the #2771 up-S4 distinction: before it,
/// do_get_user_value's inner RegOpenKeyExW treated every non-ERROR_SUCCESS
/// alike, so an ACL'd or otherwise unreadable key was reported identically to
/// a genuinely absent one. Absence of a key and absence of a value stay
/// deliberately indistinguishable (the shipped string covers both) — up-S4
/// asks only that infrastructure errors be separated from absence.
enum class UserKeyStatus {
    ok,
    key_not_found,     // the subkey does not exist
    key_access_denied, // the subkey exists but could not be opened (ACL, stale handle, lock)
    value_not_found,   // the subkey opened; the value does not exist
    value_oversized,   // the value exists but exceeds the read cap
    value_malformed,   // declared numeric type with a size too small for that type
    value_changed_during_read, // the value exists but a concurrent writer
                              // grew it faster than the bounded retry could
                              // keep up (#2771 code-review CODEX-P1-02) --
                              // distinct from value_not_found because the
                              // value's EXISTENCE was never in doubt, only
                              // its size.
};

/// Renders the operator-facing lines for one hive-access outcome, in emission
/// order: the unload warning first (when set), then the terminal error (when
/// the status is not ok). Returns an empty vector for a clean success.
///
/// `mount_name` is the ACTUAL mount subkey the offline fallback used — it is
/// salted per call (win_reg_handle.hpp's unique_hive_mount_name), so the
/// remediation command must echo what was really mounted rather than
/// reconstructing "YUZU_HIVE_<sid>", which is no longer the whole name.
///
/// The unload warning is emitted independently of `status` and BEFORE it:
/// unload_failed can be true even on mount_failed (RegLoadKeyW can succeed
/// while the subsequent root re-open fails), so a status-first switch that
/// returned early would drop it.
[[nodiscard]] inline std::vector<std::string> render_hive_access_lines(HiveAccessStatus status,
                                                                       bool unload_failed,
                                                                       std::string_view mount_name,
                                                                       std::string_view sid) {
    std::vector<std::string> out;
    const std::string safe_sid = sanitize_field(sid);

    if (unload_failed) {
        // A leaked mount is system-wide, survives process death, and locks the
        // profile's NTUSER.DAT until it is unloaded or the host reboots — most
        // commonly a transient third-party handle (Search Indexer, AV, System
        // Restore) into the newly-mounted branch, recoverable without reboot
        // once that holder releases; a genuinely stuck holder is the rarer case
        // reboot actually resolves.
        const std::string safe_mount = sanitize_field(mount_name);
        out.push_back(std::format(
            "warning|hive_unload_failed: HKU\\{} for sid '{}' may remain mounted; retry "
            "`reg unload HKU\\{}` once any process holding the branch (Search Indexer, AV, "
            "System Restore) releases it",
            safe_mount, safe_sid, safe_mount));
    }

    switch (status) {
    case HiveAccessStatus::not_found:
        out.push_back(std::format(
            "error|no reachable hive for sid '{}' (not logged in and no profile path)", safe_sid));
        break;
    case HiveAccessStatus::privilege_missing:
        out.emplace_back(
            "error|privilege_missing: SeBackupPrivilege/SeRestorePrivilege could not be enabled");
        break;
    case HiveAccessStatus::mount_failed:
        out.push_back(std::format("error|failed to load hive for sid '{}'", safe_sid));
        break;
    case HiveAccessStatus::ok:
        break;
    }
    return out;
}

/// Renders the operator-facing error line for a non-ok UserKeyStatus.
/// Returns "" for `ok` — the caller emits its value rows instead.
[[nodiscard]] inline std::string render_user_key_error(UserKeyStatus status, std::string_view key) {
    switch (status) {
    case UserKeyStatus::ok:
        return {};
    case UserKeyStatus::key_access_denied:
        return std::format("error|access denied opening key '{}' in user hive", sanitize_field(key));
    case UserKeyStatus::value_oversized:
        return "error|value exceeds 1 MiB limit";
    case UserKeyStatus::value_malformed:
        return "error|value size too small for its declared type";
    case UserKeyStatus::value_changed_during_read:
        return "error|value changed while reading -- a concurrent writer kept growing it faster "
              "than the bounded retry could keep up; retry the read";
    case UserKeyStatus::key_not_found:
    case UserKeyStatus::value_not_found:
        return "error|key or value not found in user hive";
    }
    return "error|key or value not found in user hive"; // unreachable — see -Wswitch note above
}

/// The honest-truncation DECISION, extracted pure (#2771 code-review P2-N3):
/// "the record cap was reached" and "a record was actually dropped" are
/// different facts (C-M3) -- a host with EXACTLY kMaxProfiles subkeys hits
/// the former without the latter. Extracting the decision itself, rather
/// than leaving it inline beside the real RegEnumKeyExW probe call, is what
/// makes the boundary case (cap reached, probe finds nothing further) and
/// the genuine-drop case (cap reached, probe finds a next entry)
/// deterministically testable on every host -- a unit test cannot
/// fabricate exactly kMaxProfiles real registry subkeys, but it can call
/// this function with both bool combinations directly.
[[nodiscard]] constexpr bool profile_list_actually_truncated(bool cap_reached,
                                                              bool probe_found_more) {
    return cap_reached && probe_found_more;
}

/// Renders the `profile_list_truncated` warning every ProfileList-walking
/// consumer emits when enumerate_profile_records' `truncated` out-param is
/// true -- which means a record was actually dropped, confirmed by a probe,
/// not merely that the cap was reached (see that function's doc comment,
/// #2771 code-review C-M3). Deduplicated (Standards S6): registry.list_profiles
/// and installed_apps.list_per_user previously carried byte-identical
/// `std::format` calls independently.
[[nodiscard]] inline std::string render_profile_list_truncated_warning(std::size_t max_profiles) {
    return std::format("warning|profile_list_truncated at {} entries", max_profiles);
}

// ---------------------------------------------------------------------------
// Registry value decoding primitives (#2771 up-S3)
//
// Pure and windows.h-free so the decode DECISIONS (which branch, which type
// name, where a REG_MULTI_SZ record ends) are tested on every host; the Win32
// shell supplies only the bytes.
// ---------------------------------------------------------------------------

/// Registry value types, mirrored from winnt.h so this header stays
/// windows.h-free. Values are fixed by the Windows ABI and cannot drift.
inline constexpr std::uint32_t kRegNone = 0;
inline constexpr std::uint32_t kRegSz = 1;
inline constexpr std::uint32_t kRegExpandSz = 2;
inline constexpr std::uint32_t kRegBinary = 3;
inline constexpr std::uint32_t kRegDword = 4;
inline constexpr std::uint32_t kRegDwordBigEndian = 5;
inline constexpr std::uint32_t kRegLink = 6;
inline constexpr std::uint32_t kRegMultiSz = 7;
inline constexpr std::uint32_t kRegQword = 11;

/// Canonical name for a registry value type. Absorbs registry_plugin.cpp's
/// local copy; adds the three types up-S3 named, which previously fell into
/// the hex-dump default and were all reported as REG_BINARY/REG_UNKNOWN.
[[nodiscard]] constexpr std::string_view reg_type_name(std::uint32_t type) {
    switch (type) {
    case kRegNone:
        return "REG_NONE";
    case kRegSz:
        return "REG_SZ";
    case kRegExpandSz:
        return "REG_EXPAND_SZ";
    case kRegBinary:
        return "REG_BINARY";
    case kRegDword:
        return "REG_DWORD";
    case kRegDwordBigEndian:
        return "REG_DWORD_BIG_ENDIAN";
    case kRegLink:
        return "REG_LINK";
    case kRegMultiSz:
        return "REG_MULTI_SZ";
    case kRegQword:
        return "REG_QWORD";
    default:
        return "REG_UNKNOWN";
    }
}

/// Splits a REG_MULTI_SZ payload into its constituent records, returned as
/// (offset, length) pairs into `data`. A REG_MULTI_SZ is a run of
/// NUL-terminated strings closed by one extra NUL, so an EMPTY record
/// terminates the list — trailing padding after it is not data. A final
/// record with no terminating NUL (a malformed but observed shape) is still
/// returned rather than dropped: reporting it is more honest than silently
/// losing the last entry.
///
/// char16_t (not wchar_t) keeps this host-agnostic — wchar_t is 32-bit on
/// Linux/macOS, so a wchar_t signature would not model the Windows bytes.
[[nodiscard]] inline std::vector<std::pair<std::size_t, std::size_t>> multi_sz_records(
    std::span<const char16_t> data) {
    std::vector<std::pair<std::size_t, std::size_t>> out;
    std::size_t start = 0;
    while (start < data.size()) {
        std::size_t end = start;
        while (end < data.size() && data[end] != u'\0')
            ++end;
        if (end == start)
            break; // empty record — the list terminator
        out.emplace_back(start, end - start);
        if (end >= data.size())
            break; // unterminated final record, already captured
        start = end + 1;
    }
    return out;
}

/// Lowercase hex encoding, byte per two chars. Extracted verbatim from
/// win_profiles.hpp's read_reg_value default branch so the encoding is
/// testable without a registry.
[[nodiscard]] inline std::string hex_encode(std::span<const std::uint8_t> bytes) {
    constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (std::uint8_t b : bytes) {
        out += kHex[(b >> 4) & 0xF];
        out += kHex[b & 0xF];
    }
    return out;
}

} // namespace yuzu::profiles
