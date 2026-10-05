/**
 * privacy_permissions_win_parsers.hpp -- the Windows leg's PURE layer (OS-free: compiled and
 * unit-tested on every host; only the shell in privacy_permissions_win.cpp is Windows-only): the
 * CapabilityName -> category table, the ConsentStore `Value` string -> PermissionState decode, the
 * NonPackaged app-identity unescape, the LastUsedTime* QWORD decode, the profile-vs-HKLM precedence
 * merge and the per-run row assembly. Separate from privacy_permissions_parsers.hpp (the cross-OS pure layer), same split as
 * platform_security_win_parsers.hpp. windows.h-free: the Win32 codes it branches on are
 * mirrored below and static_asserted against the real macros in privacy_permissions_win.cpp.
 *
 * MEASURED on the-rig (Windows 11 Pro 10.0.26200, LocalSystem, read-only reg dumps,
 * 2026-09-23): the `Value` literals seen are `Allow`, `Deny` and `Prompt`; this file does NOT
 * assume that is the complete set -- any other value decodes as `prompt_undetermined` (a named,
 * visible state) and `unreadable` only when the type is wrong (not REG_SZ) or the value empty.
 * The same host showed the ConsentStore's three levels: HKLM `<capability>` `Value` (the device
 * toggle -- `Allow` on all 33 capabilities of this non-MDM host), the per-user `<capability>`
 * `Value`, and the per-user `<capability>\NonPackaged` `Value` (the "let desktop apps access"
 * toggle). A per-app NonPackaged child carries NO `Value` -- only LastUsedTimeStart/Stop -- so it
 * reads `absent` (no per-app decision; the NonPackaged toggle row governs it).
 */
#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "privacy_permissions_parsers.hpp"
#include "user_profile_model.hpp"

namespace yuzu::privacy_permissions::win {

// <profile hive>/HKLM ...\CapabilityAccessManager\ConsentStore\<CapabilityName>. Only the
// capabilities this plugin models are opened; every other CapabilityName Windows
// exposes (contacts, phoneCall, userAccountInformation, ...) is never opened at all -- a scope
// filter, not a decode failure.
struct CapabilityEntry {
    std::string_view capability_name; // the literal registry subkey name
    std::string_view category;        // one of kCategories
};

inline constexpr std::array<CapabilityEntry, 4> kCapabilities{{
    {"webcam", "camera"},
    {"microphone", "microphone"},
    {"location", "location"},
    {"broadFileSystemAccess", "full_disk_access"},
}};

/// `<capability>\NonPackaged` is both the container of per-app desktop keys and, through its own
/// `Value`, the "let desktop apps access" toggle. That toggle is reported as its own row under
/// this app_id (qualified `<user>\NonPackaged` per profile, bare on HKLM -- qualify_app_id).
inline constexpr std::string_view kNonPackagedToggleAppId = "NonPackaged";

/// NonPackaged children that are containers, not apps (measured on the-rig:
/// `NonPackaged\Executables\<exe>` holds only a `GlobalPromptShown` DWORD per executable, never
/// a `Value`). Skipped by name; any other child is read as an app key, so an unknown shape stays
/// a visible row rather than vanishing.
[[nodiscard]] constexpr bool is_nonpackaged_container_key(std::string_view name) noexcept {
    return name == "Executables";
}

/// The ConsentStore `Value` REG_SZ decoded to a PermissionState. `type_ok` = the registry
/// value was actually REG_SZ (a wrong type is unreadable regardless of its bytes).
[[nodiscard]] inline PermissionState decode_consent_value(std::string_view value, bool type_ok) noexcept {
    if (!type_ok || value.empty()) return PermissionState::unreadable;
    if (value == "Allow") return PermissionState::allowed;
    if (value == "Deny") return PermissionState::denied;
    // A real third literal the probe finds (Prompt, AllowedTemporary, ...) is visible and
    // distinct, never silently folded into allowed/denied.
    return PermissionState::prompt_undetermined;
}

/// `NonPackaged` subkey names are the app's executable path with `\` written as `#` and the drive
/// colon left literal (measured on the-rig: `C:#Program Files#...`). Nothing else is escaped.
[[nodiscard]] inline std::string unescape_nonpackaged_app_id(std::string_view escaped) {
    std::string out{escaped};
    std::replace(out.begin(), out.end(), '#', '\\');
    return out;
}

/// FILETIME (100ns ticks since 1601-01-01) -> Unix epoch milliseconds. Same conversion shape
/// as execution_artifacts_parsers.hpp's filetime helper (duplicated per this repo's
/// header-only-pure-function convention rather than cross-plugin-shared). 0 -> "-" (never set).
[[nodiscard]] inline std::string filetime_to_epoch_ms_string(std::uint64_t filetime_100ns) {
    if (filetime_100ns == 0) return "-";
    constexpr std::uint64_t kEpochDiff100ns = 116444736000000000ULL; // 1601 -> 1970, in 100ns ticks
    if (filetime_100ns < kEpochDiff100ns) return "-"; // before the Unix epoch: not a real timestamp
    return std::to_string((filetime_100ns - kEpochDiff100ns) / 10000ULL);
}

// ── Win32 codes (mirrored; privacy_permissions_win.cpp static_asserts each) ──

inline constexpr long kErrorSuccess = 0;
inline constexpr long kErrorFileNotFound = 2;
inline constexpr long kErrorAccessDenied = 5;
inline constexpr long kErrorNoMoreItems = 259;
inline constexpr std::uint32_t kRegSz = 1;
inline constexpr std::uint32_t kRegQword = 11;

/// `access_denied` or `win32_<rc>` -- the cause suffix every failed registry call reports.
[[nodiscard]] inline std::string win32_cause(long rc) {
    return rc == kErrorAccessDenied ? std::string{"access_denied"} : "win32_" + std::to_string(rc);
}

// ── retention bounds (the ConsentStore is under its owning user's write access) ──

/// Cap on one ConsentStore `Value`, in bytes as the registry reports them (UTF-16 + NUL). The
/// literals measured on the-rig are `Allow`/`Deny`/`Prompt` (at most 14 bytes); 64 bytes (31
/// characters) leaves room for a longer literal Windows may add without letting a profile owner
/// make the agent retain the generic 1 MiB registry cap per value. Over it is `value_oversized`.
inline constexpr std::uint32_t kMaxConsentValueBytes = 64;

/// One profile (or HKLM) may retain at most this much, so a single owner cannot use up the run's
/// time and memory and starve every later profile. The run-wide bound on what reaches the wire
/// is the shared OutputBudget (privacy_permissions_parsers.hpp), not a second copy here.
inline constexpr std::size_t kMaxProfileGrants = 8192;
inline constexpr std::size_t kMaxProfileBytes = 2u * 1024u * 1024u;

/// The run's cooperative wall-clock bound, checked before each profile, first thing in the
/// hive-file guard's before_load, and before each capability and each app key open. A single
/// blocking call (the offline-hive mutex wait behind a sibling plugin's offline arm,
/// RegLoadKeyW/RegUnLoadKeyW) is not interrupted, nor is one enumeration of at most 4,096
/// children, a capability-level key open, or one key's value reads, so a dispatch can overrun it:
/// a cooperative deadline, never a hard cap.
inline constexpr std::chrono::milliseconds kRunBudget{15'000};

/// The per-source retention budget. charge() is called BEFORE a grant is retained; once the
/// source's limit would be crossed it refuses, stays refused (sticky) and the walk of that one
/// source stops; begin_profile() starts the next source from zero. `deadline`/`expired(now)` are
/// injectable so a test never sleeps; expiry is sticky.
struct RetentionBudget {
    yuzu::shared::RowByteBudget source{kMaxProfileGrants, kMaxProfileBytes};
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::now() + kRunBudget;
    bool timed_out = false;

    void begin_profile() noexcept { source.reset(); }

    [[nodiscard]] bool expired(
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) noexcept {
        return timed_out = timed_out || now >= deadline;
    }

    /// Whether the walk of the current source must stop where it is.
    [[nodiscard]] bool walk_stopped() noexcept { return source.refused || expired(); }

    [[nodiscard]] bool charge(std::size_t n_bytes) noexcept {
        return !source.refused && source.charge(n_bytes); // refusal sticky per source
    }
};

inline constexpr std::string_view kTimeoutToken = "collection:timeout";
/// `<profile>:budget_exceeded` (or `hklm:budget_exceeded`): that one source's rows are truncated.
inline constexpr std::string_view kSourceBudgetExceededSuffix = "budget_exceeded";

// ── subkey enumeration outcome ─────────────────────────────────────────

enum class EnumOutcome { complete, truncated, failed };

struct EnumVerdict {
    EnumOutcome outcome;
    long rc = kErrorSuccess; // the failing code when `failed`
    /// Child names skipped for an embedded NUL (see enumerate_subkey_names); enum_failure reports them.
    std::size_t embedded_nul_names = 0;
};

/// How a capped RegEnumKeyExW walk ended. `last_rc` is the code that ended the loop: anything but
/// ERROR_SUCCESS means the walk stopped on its own (ERROR_NO_MORE_ITEMS is the only clean stop,
/// every other code a real failure); ERROR_SUCCESS means the loop stopped only because it hit
/// the cap, and `probe_rc` -- one extra RegEnumKeyExW at the next index -- decides: NO_MORE_ITEMS
/// = there were EXACTLY cap children (complete, never a failure), SUCCESS = a real next child
/// exists (truncated), anything else = the probe itself failed (failed, never read as complete).
[[nodiscard]] constexpr EnumVerdict classify_subkey_enum(long last_rc, long probe_rc) noexcept {
    if (last_rc != kErrorSuccess) {
        if (last_rc == kErrorNoMoreItems) return {EnumOutcome::complete, kErrorSuccess};
        return {EnumOutcome::failed, last_rc};
    }
    if (probe_rc == kErrorNoMoreItems) return {EnumOutcome::complete, kErrorSuccess};
    if (probe_rc == kErrorSuccess) return {EnumOutcome::truncated, kErrorSuccess};
    return {EnumOutcome::failed, probe_rc};
}

struct EnumFailure {
    std::string cause; // `<kind>_enum_truncated` or `<kind>_enum_<win32_cause>`
    bool denied = false;
};

/// The failure an enumeration contributes, or nullopt for a complete one -- a complete walk,
/// including one of exactly the cap, never produces a failure token, unless it skipped an
/// embedded-NUL name (`<kind>:name_embedded_nul`, one row per walk; a truncated or failed walk
/// already reports the source as incomplete).
[[nodiscard]] inline std::optional<EnumFailure> enum_failure(std::string_view kind,
                                                             const EnumVerdict& v) {
    switch (v.outcome) {
    case EnumOutcome::complete:
        if (v.embedded_nul_names > 0)
            return EnumFailure{std::string{kind} + ":name_embedded_nul", false};
        return std::nullopt;
    case EnumOutcome::truncated:
        return EnumFailure{std::string{kind} + "_enum_truncated", false};
    case EnumOutcome::failed:
        break;
    }
    return EnumFailure{std::string{kind} + "_enum_" + win32_cause(v.rc),
                       v.rc == kErrorAccessDenied};
}

/// How ProfileList discovery ended, as the one whole-source failure it contributes (nullopt: every
/// profile subkey was enumerated). `root_rc` opened ProfileList; `last_rc`/`probe_rc` are the walk's
/// terminating RegEnumKeyExW code and cap probe (classify_subkey_enum). A refused root or a refused
/// mid-walk enumeration is `denied` (PERMISSION_DENIED); any other root failure, terminating error
/// or a cap with more profiles is `unreadable` -- never a prefix read as the complete list.
[[nodiscard]] inline std::optional<EnumFailure> profile_discovery_failure(long root_rc, long last_rc,
                                                                          long probe_rc) {
    if (root_rc == kErrorAccessDenied) return EnumFailure{"profiles:profile_list_access_denied", true};
    if (root_rc != kErrorSuccess) return EnumFailure{"profiles:profile_list_unreadable", false};
    const auto v = classify_subkey_enum(last_rc, probe_rc);
    if (v.outcome == EnumOutcome::complete) return std::nullopt;
    if (v.outcome == EnumOutcome::truncated) return EnumFailure{"profiles:truncated", false};
    return EnumFailure{"profiles:enum_" + win32_cause(v.rc), v.rc == kErrorAccessDenied};
}

/// One ProfileList record whose SID key (`key_open`) or ProfileImagePath value failed to read.
/// A refusal is `denied` even when that profile's hive is still reached through HKU.
[[nodiscard]] inline EnumFailure profile_record_failure(bool key_open, long rc) {
    return {std::string{key_open ? "profiles:profile_key_" : "profiles:profile_image_path_"} +
                win32_cause(rc),
            rc == kErrorAccessDenied};
}

// ── profile SID validation ──────────────────────────────────────────────

/// A SID string of the `S-1-<authority>(-<subauthority>)*` shape, every component decimal
/// digits, within a sane length. Checked BEFORE the SID is appended to HKEY_USERS: an empty or
/// malformed string there would open the HKU root itself (or some other key), never the
/// profile's own hive.
[[nodiscard]] constexpr bool is_valid_sid_string(std::string_view sid) noexcept {
    constexpr std::size_t kMaxSidChars = 256;
    if (sid.size() > kMaxSidChars || !sid.starts_with("S-1-")) return false;
    std::size_t digits = 0;
    for (std::size_t i = 4; i < sid.size(); ++i) {
        const char c = sid[i];
        if (c >= '0' && c <= '9') {
            ++digits;
        } else if (c == '-' && digits > 0) {
            digits = 0;
        } else {
            return false;
        }
    }
    return digits > 0;
}

/// One LastUsedTimeStart/LastUsedTimeStop field. `value` is epoch-ms, "-" (the value is not
/// there -- never set), or `unreadable`; `cause` is non-empty exactly when it is `unreadable`
/// (`win32_<rc>`/`access_denied`, `type_<n>` or `size_<n>`); `denied` marks a refused read.
struct LastUsedField {
    std::string value = "-";
    std::string cause;
    bool denied = false;
};

/// Decodes one RegQueryValueExW(LastUsedTime*) into an 8-byte buffer. Only ERROR_FILE_NOT_FOUND
/// is "not there"; success counts only with BOTH type REG_QWORD AND a returned size of exactly
/// 8 bytes (a short REG_QWORD would leave stale buffer bytes read as a timestamp); every other
/// outcome is a visible `unreadable`, never a silent "-".
[[nodiscard]] inline LastUsedField decode_last_used(long rc, std::uint32_t type, std::uint32_t size,
                                                    std::uint64_t filetime_100ns) {
    if (rc == kErrorFileNotFound) return {"-", {}, false};
    if (rc != kErrorSuccess) return {"unreadable", win32_cause(rc), rc == kErrorAccessDenied};
    if (type != kRegQword) return {"unreadable", "type_" + std::to_string(type), false};
    if (size != sizeof(std::uint64_t)) return {"unreadable", "size_" + std::to_string(size), false};
    return {filetime_to_epoch_ms_string(filetime_100ns), {}, false};
}

/// The token a failed grant adds to the run's constraint set: `<source>:<category>:<cause>`, no
/// app. One token per kind of failure however many apps share it, so an owner-stuffed ConsentStore
/// cannot grow the set; the row's own `raw` still names the app. A cause embedding an
/// owner-chosen number (`..._type_<n>`, `..._size_<n>`) is cut before it for the same reason.
[[nodiscard]] inline std::string coarse_failure_token(std::string_view source,
                                                      std::string_view category,
                                                      std::string_view cause) {
    std::string c{cause};
    for (const std::string_view marker : {"_type_", "_size_"})
        if (const auto at = c.find(marker); at != std::string::npos)
            c.resize(at + marker.size() - 1);
    return std::string{source} + ":" + std::string{category} + ":" + c;
}

/// One (app_id, category) grant as read from ONE ConsentStore root (a profile hive or HKLM).
/// `app_id` is UNqualified here ("-" = the capability-level default / coverage entry); the
/// caller qualifies it per profile. `cause` is non-empty exactly when the Value read failed
/// (value_access_denied / value_oversized / value_empty / value_type_<n> / value_win32_<n>).
struct RawGrant {
    std::string app_id;
    std::string_view category; // a kCapabilities literal -- static storage, safe in a row
    PermissionState state;
    std::string raw_value;
    LastUsedField last_used_start{};
    LastUsedField last_used_stop{};
    std::string cause{};
    // The READ of this grant's `Value` was refused (ERROR_ACCESS_DENIED) -- NOT the same thing
    // as `state == PermissionState::denied` alone, which also (correctly) means "the read
    // succeeded and decoded to a stored `Deny` grant".
    bool read_denied = false;
};

[[nodiscard]] inline bool grant_failed(const RawGrant& g) noexcept {
    return g.read_denied || g.state == PermissionState::unreadable;
}

/// Every retained grant's owner-controlled text, charged against the per-source RetentionBudget.
[[nodiscard]] inline std::size_t retained_bytes(const RawGrant& g) noexcept {
    return g.app_id.size() + g.raw_value.size() + g.cause.size();
}

/// A category-level failure that is not one Value read (a key that refused/failed to open, an
/// enumeration that failed or hit its cap). Kept apart from the (app_id, category)-keyed grants
/// so the precedence merge can never overwrite or drop it.
[[nodiscard]] inline RawGrant structural_failure(std::string app_id, std::string_view category,
                                                 std::string cause, bool denied) {
    return {std::move(app_id), category,
            denied ? PermissionState::denied : PermissionState::unreadable, "-",
            {}, {}, std::move(cause), denied};
}

/// A `<capability>\NonPackaged` key that did not open. Genuinely missing is the desktop-apps
/// toggle row reading `absent` -- the toggle is its own row at every level, never omitted; any
/// other code is a `nonpackaged_container:<cause>` structural failure.
[[nodiscard]] inline RawGrant nonpackaged_open_failure(std::string_view category, long rc) {
    if (rc == kErrorFileNotFound)
        return {std::string{kNonPackagedToggleAppId}, category, PermissionState::absent, "-",
                {}, {}, {}, false};
    return structural_failure("-", category, "nonpackaged_container:" + win32_cause(rc),
                              rc == kErrorAccessDenied);
}

/// PRECEDENCE -- Microsoft's documented Settings model for the ConsentStore, confirmed on the-rig
/// (a non-MDM host carries HKLM `<capability>` `Value Allow` on every capability): the
/// machine-wide HKLM `Value` is the DEVICE toggle ("allow access on this device"). An HKLM `Deny`
/// blocks every user whatever their own value; an HKLM `Allow` blocks nothing and defers to each
/// user's own choice. So only a SUCCESSFULLY read and decoded HKLM `Deny` overrides a profile:
/// most restrictive wins, key by key -- the capability toggle (`-`) against the user's
/// capability toggle, the NonPackaged toggle against the user's NonPackaged toggle, an app
/// against the same app. An HKLM `Allow` or unmodelled value never overrides a user's Deny or
/// prompt (nor fills a key the user lacks -- that would invent a per-user grant); an absent,
/// unreadable or refused HKLM value says nothing. Rows below a toggle are reported as stored:
/// the toggle rows are what govern them, and the plugin does not compute an effective state.
[[nodiscard]] inline bool hklm_overrides_profile(const RawGrant& g) noexcept {
    return !grant_failed(g) && g.state == PermissionState::denied;
}

/// Whether an HKLM entry is emitted ONCE as HKLM's own unqualified row. An overriding `Deny` is
/// applied into each reachable profile's merge instead, so it is its own row only when no
/// profile was reachable to carry it. Everything else HKLM holds is its own row -- a
/// capability-level `absent` included: HKLM was read and definitively holds nothing there, and
/// that row must survive a profile-side whole-source failure (which suppresses
/// fill_uncovered_categories' backstop for every source).
[[nodiscard]] inline bool hklm_emitted_once(const RawGrant& g, bool any_profile_reachable) noexcept {
    return !hklm_overrides_profile(g) || !any_profile_reachable;
}

/// The profile's own grants with every overriding HKLM `Deny` applied (hklm_overrides_profile):
/// it replaces a successfully-read profile entry's state for the same (app_id, category) -- the
/// profile's last-used times are kept -- and fills a key the profile lacks. A FAILED profile entry is never overwritten -- its failure row is kept and
/// the HKLM value is added beside it, so a read failure is never hidden behind a policy value.
/// Every other HKLM entry is skipped here (the caller reports those once, hklm_emitted_once).
/// Two profile entries with the same (app_id, category) -- distinct registry keys that decode to
/// one id, e.g. a packaged key `X` and a NonPackaged key `X` -- are both kept as stored, plus one
/// `duplicate_app_id` unreadable row naming the collision; neither silently replaces the other.
/// Output sorted by (app_id, category).
[[nodiscard]] inline std::vector<RawGrant> merge_with_hklm(std::span<const RawGrant> profile,
                                                           std::span<const RawGrant> hklm) {
    std::map<std::pair<std::string, std::string_view>, RawGrant> merged;
    std::vector<RawGrant> extra; // duplicates, their collision rows, HKLM beside a failed entry
    for (const auto& g : profile) {
        if (merged.try_emplace({g.app_id, g.category}, g).second) continue;
        extra.push_back(g);
        extra.push_back(structural_failure(g.app_id, g.category, "duplicate_app_id", false));
    }
    for (const auto& h : hklm) {
        if (!hklm_overrides_profile(h)) continue;
        const auto it = merged.find({h.app_id, h.category});
        if (it != merged.end() && grant_failed(it->second)) {
            extra.push_back(h);
            continue;
        }
        RawGrant r = h;
        if (it != merged.end()) { // the profile's last-used times are facts HKLM does not carry
            r.last_used_start = it->second.last_used_start;
            r.last_used_stop = it->second.last_used_stop;
        }
        merged[{h.app_id, h.category}] = std::move(r);
    }
    std::vector<RawGrant> out;
    out.reserve(merged.size() + extra.size());
    for (auto& [key, g] : merged) out.push_back(std::move(g));
    for (auto& g : extra) out.push_back(std::move(g));
    std::stable_sort(out.begin(), out.end(), [](const RawGrant& a, const RawGrant& b) {
        return std::tie(a.app_id, a.category) < std::tie(b.app_id, b.category);
    });
    return out;
}

// ── offline hive-file guard (pure decisions; the Win32 facts are gathered in the shell) ──

inline constexpr std::uint32_t kDriveFixed = 3; // DRIVE_FIXED
inline constexpr std::size_t kMaxHivePathDepth = 32;
inline constexpr std::uint64_t kMaxHiveBytes = 512ull * 1024ull * 1024ull;
/// A stock profile directory holds a handful of `<hive>*` transaction-log sidecars (.LOG1/.LOG2,
/// .TM.blf, .TMContainer*.regtrans-ms); more than this is refused rather than walked.
inline constexpr std::size_t kMaxHiveSidecars = 64;
inline constexpr std::uint32_t kWaitObject0 = 0;  // WAIT_OBJECT_0
inline constexpr std::uint32_t kWaitTimeout = 258; // WAIT_TIMEOUT

/// What the shell learned about one NTUSER.DAT, every fact taken from an opened HANDLE (or, for
/// the path facts, from the requested path before any syscall). `final_path_matches` is the
/// shell's verdict that GetFinalPathNameByHandleW(VOLUME_NAME_DOS) equals `\\?\` + the requested
/// path under Windows' own ordinal case-insensitive comparison (CompareStringOrdinal on the wide
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

// ── change-notification stability ───────────────────────────────────────

/// The Win32 outcomes of arming and polling one RegNotifyChangeKeyValue watch. The ConsentStore
/// was read stable ONLY when the event was created, the watch armed and the zero-timeout wait
/// timed out; observing stability can fail, and a failed observation is never stability.
struct StabilityFacts {
    unsigned long create_gle = 0; // GetLastError after CreateEventW (0 = created)
    long arm_rc = 0;              // RegNotifyChangeKeyValue's return
    unsigned long wait_rc = kWaitTimeout;
    unsigned long wait_gle = 0;   // GetLastError after a WAIT_FAILED
};

[[nodiscard]] inline std::optional<std::string> classify_stability(const StabilityFacts& f) {
    if (f.create_gle != 0) return "notify_event_failed:win32_" + std::to_string(f.create_gle);
    if (f.arm_rc != 0) return "notify_failed:win32_" + std::to_string(f.arm_rc);
    if (f.wait_rc == kWaitTimeout) return std::nullopt;
    if (f.wait_rc == kWaitObject0) return std::string{"changed_during_read"};
    return "notify_wait_failed:win32_" + std::to_string(f.wait_gle);
}

// ── run assembly (pure: the shell injects what each source read produced) ─────

/// One ConsentStore root's walk (a profile hive or HKLM). `refused` is a classify_stability token:
/// the read was discarded unread.
struct ConsentWalk {
    long root_rc = kErrorSuccess;
    std::vector<RawGrant> grants;     // keyed by (app_id, category); "-" = capability level
    std::vector<RawGrant> structural; // never merged -- always emitted as their own rows
    std::string refused;
};

/// Emits one grant as a row. `source` is the profile name (or "hklm"); `qualify` = prefix the
/// row's app_id with it (false only for HKLM's own, machine-wide rows). A failed grant's row `raw`
/// is `<source>\<app_id>:<category>:<cause>`; the run's constraint set (the agent-log provenance)
/// gets only the app-less coarse_failure_token.
inline void emit_grant(std::string_view source, bool qualify, const RawGrant& g,
                       std::vector<PermissionRow>& rows,
                       yuzu::shared::ConstraintAccumulator& acc) {
    const std::string subject = qualify_app_id(source, g.app_id) + ":" + std::string{g.category};
    PermissionRow row{"windows",
                      qualify ? qualify_app_id(source, g.app_id) : g.app_id,
                      g.category,
                      g.state,
                      g.raw_value,
                      g.last_used_start.value,
                      g.last_used_stop.value,
                      g.read_denied};
    if (!g.cause.empty()) {
        row.raw = subject + ":" + g.cause;
        acc.add_failure(coarse_failure_token(source, g.category, g.cause));
    }
    if (!g.last_used_start.cause.empty())
        acc.add_failure(
            coarse_failure_token(source, g.category, "last_used_start_" + g.last_used_start.cause));
    if (!g.last_used_stop.cause.empty())
        acc.add_failure(
            coarse_failure_token(source, g.category, "last_used_stop_" + g.last_used_stop.cause));
    row.read_denied = row.read_denied || g.last_used_start.denied || g.last_used_stop.denied;
    rows.push_back(std::move(row));
}

/// The one whole-source row for a ConsentStore root that could not be opened (not "not there").
inline void emit_root_failure(std::string_view source, std::string app_id, long rc,
                              std::vector<PermissionRow>& rows,
                              yuzu::shared::ConstraintAccumulator& acc) {
    rows.push_back(failure_row("windows", std::move(app_id), "-", rc == kErrorAccessDenied,
                               std::string{source} + ":" + win32_cause(rc), acc));
}

/// What reading ONE profile produced: how its hive was (or was not) reached and, when it was, its
/// ConsentStore walk. `peek_rc` is the open code of the live HKU\<SID> root, which
/// with_user_hive's own `== ERROR_SUCCESS` test cannot tell from "not loaded": it recovers a
/// refused live hive whose offline fallback then also failed.
struct ProfileRead {
    profiles::HiveAccessStatus status = profiles::HiveAccessStatus::not_found;
    std::string refusal;          // the hive-file refusal token when status == file_refused
    bool unload_failed = false;   // the read completed; a mount was left behind
    long peek_rc = kErrorSuccess;
    ConsentWalk walk;             // meaningful only when status == ok
};

using ReadProfileFn = std::function<ProfileRead(const profiles::ProfileInfo&)>;

/// Assembles the run's rows from the HKLM walk and one injected read per profile -- every decision
/// the shell used to make inline, so each is unit-observable on every host: HKLM's rows are
/// RESERVED in the run-wide `output` before any profile is charged; a profile's rows are charged
/// as a unit and one that would cross the cap is not emitted; the run stops, with exactly one
/// `collection:budget_exceeded` row, when the cap is crossed OR already exactly filled with
/// profiles left (the bytes check at the loop top, not only the commit refusal); an expired
/// deadline stops it with one `collection:timeout` row; an overriding HKLM Deny is HKLM's own row
/// only when no profile was reachable to carry it (a profile whose ConsentStore was refused as
/// unstable is not reachable). `budget` is as the HKLM walk left it; `discovery_rows` (ProfileList
/// failures, built by the shell) lead the profile rows. The caller runs fill_uncovered_categories
/// and emits.
[[nodiscard]] inline std::vector<PermissionRow> assemble_windows_rows(
    const std::vector<profiles::ProfileInfo>& profile_list, const ConsentWalk& hklm,
    std::vector<PermissionRow> discovery_rows, const ReadProfileFn& read_profile,
    RetentionBudget& budget, OutputBudget& output, yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<PermissionRow> rows = std::move(discovery_rows);
    output.charge(rows); // ProfileList failures count toward the run's output bound like any row
    // A source that hit its own cap keeps the rows it charged; this row says it is incomplete.
    const auto truncated_row = [&](std::vector<PermissionRow>& into, const std::string& source,
                                   const std::string& row_id) {
        if (budget.source.refused)
            into.push_back(failure_row("windows", row_id, "-", false,
                                       source + ":" + std::string{kSourceBudgetExceededSuffix}, acc));
    };

    // HKLM: only its successfully read `Deny` grants override a profile (hklm_overrides_profile --
    // the device toggle, most restrictive wins) and are applied into each profile's merge;
    // everything else HKLM holds is reported once below as HKLM's own unqualified rows.
    std::vector<PermissionRow> hklm_grant_rows; // one per hklm.grants entry, same index
    std::vector<PermissionRow> hklm_tail;       // structural, root failure, refusal: always emitted
    std::vector<RawGrant> hklm_overriding;
    for (const auto& g : hklm.grants) {
        if (hklm_overrides_profile(g)) hklm_overriding.push_back(g);
        emit_grant("hklm", false, g, hklm_grant_rows, acc);
    }
    for (const auto& g : hklm.structural) emit_grant("hklm", false, g, hklm_tail, acc);
    if (hklm.root_rc != kErrorSuccess && hklm.root_rc != kErrorFileNotFound)
        emit_root_failure("hklm", "-", hklm.root_rc, hklm_tail, acc);
    if (!hklm.refused.empty())
        hklm_tail.push_back(failure_row("windows", "-", "-", false, "hklm:" + hklm.refused, acc));
    truncated_row(hklm_tail, "hklm", "-");
    // RESERVE HKLM's rows before any profile charges: an upper bound (hklm_emitted_once only
    // narrows it), so a profile can never starve the machine rows and the machine rows are never
    // charged twice.
    output.charge(hklm_grant_rows);
    output.charge(hklm_tail);

    // Profiles whose rows carried HKLM's overriding grants: when none did, those grants are
    // emitted directly (unqualified) rather than silently dropped.
    std::size_t reachable_profiles = 0;
    bool budget_hit = false;
    // One profile's rows are charged as a unit; one that would cross the cap is not emitted.
    const auto commit = [&](std::vector<PermissionRow>& prof, bool reachable) {
        if (output.would_exceed(prof)) {
            budget_hit = true;
            return false;
        }
        output.charge(prof);
        for (auto& r : prof) rows.push_back(std::move(r));
        if (reachable) ++reachable_profiles;
        return true;
    };

    for (const auto& profile : profile_list) {
        // A cap the previous profile filled EXACTLY is still the budget stopping the run with
        // profiles left: it must say so, never end silently short.
        if (output.exhausted()) {
            budget_hit = true;
            break;
        }
        if (budget.expired()) break; // `timed_out` is sticky: the run-level row is added below
        budget.begin_profile();
        const std::string pname = profile.profile_name.empty() ? "-" : profile.profile_name;
        const std::string profile_row_id = qualify_app_id(pname, "-");
        std::vector<PermissionRow> prof;

        // The SID is appended to HKEY_USERS by the shell (and by with_user_hive): a malformed or
        // empty one must never open the HKU root or some other key in place of this profile's own
        // hive, so it is refused here, before any read is injected.
        if (!is_valid_sid_string(profile.sid)) {
            prof.push_back(
                failure_row("windows", profile_row_id, "-", false, pname + ":invalid_sid", acc));
            if (!commit(prof, false)) break;
            continue;
        }

        ProfileRead rd = read_profile(profile);
        // The read itself completed; a failed unload is an operational residue (a mount left
        // behind), reported as a token, not a data gap.
        if (rd.unload_failed) acc.add_failure(pname + ":hive_unload_failed");

        // Exhaustive over the HiveAccessStatus outcomes: a profile whose hive was never opened
        // must never read as "this profile has no grants" -- each failure is its own row.
        // `refused`: the cause is itself a refusal (a missing privilege): denied, token unchanged.
        const auto profile_failed = [&](std::string_view cause, bool refused = false) {
            const bool peek_denied = (rd.peek_rc == kErrorAccessDenied);
            prof.push_back(failure_row("windows", profile_row_id, "-", peek_denied || refused,
                                       pname + ":" + (peek_denied ? std::string{"access_denied"}
                                                                  : std::string{cause}),
                                       acc));
        };
        bool reachable = false;
        switch (rd.status) {
        case profiles::HiveAccessStatus::ok:
            reachable = true;
            break;
        case profiles::HiveAccessStatus::privilege_missing:
            profile_failed("privilege_missing", true);
            break;
        case profiles::HiveAccessStatus::not_found:
            // `profile_path_unreadable` (carried from the raw ProfileList record) means even the
            // PATH itself couldn't be resolved -- named distinctly from "no hive to reach".
            profile_failed(profile.profile_path_unreadable ? "profile_path_unreadable"
                                                           : "hive_not_found");
            break;
        case profiles::HiveAccessStatus::mount_failed:
            profile_failed("hive_mount_failed");
            break;
        case profiles::HiveAccessStatus::file_refused:
            // A hive-file refusal alone is unreadable, not denied (an unsafe file is not an ACL
            // refusal); a refused live root beneath it is the denial. `timeout` also ends the run
            // (the guard marks the budget, not this branch).
            profile_failed(rd.refusal);
            break;
        }

        if (reachable) {
            const ConsentWalk& user = rd.walk;
            if (!user.refused.empty()) {
                prof.push_back(failure_row("windows", profile_row_id, "-", false,
                                           pname + ":" + user.refused, acc));
                reachable = false; // nothing merged: HKLM's Deny must not be lost with it
            } else {
                if (user.root_rc != kErrorSuccess && user.root_rc != kErrorFileNotFound)
                    emit_root_failure(pname, profile_row_id, user.root_rc, prof, acc);
                for (const auto& g : merge_with_hklm(user.grants, hklm_overriding))
                    emit_grant(pname, true, g, prof, acc);
                for (const auto& g : user.structural) emit_grant(pname, true, g, prof, acc);
                truncated_row(prof, pname, profile_row_id);
            }
        }
        if (!commit(prof, reachable)) break;
        if (budget.timed_out) break;
    }

    // HKLM's own rows, unqualified, once (hklm_emitted_once), already charged: everything it
    // holds -- failures, Allow and unmodelled values, app-level entries and its definitive
    // capability-level `absent`s -- and its overriding Deny grants only when no profile was
    // reachable to carry them.
    for (std::size_t i = 0; i < hklm.grants.size(); ++i)
        if (hklm_emitted_once(hklm.grants[i], reachable_profiles > 0))
            rows.push_back(std::move(hklm_grant_rows[i]));
    for (auto& r : hklm_tail) rows.push_back(std::move(r));
    // The run-wide output budget stopped the walk: every row read so far is above; what was never
    // walked is covered by this one whole-source row.
    if (budget_hit)
        rows.push_back(failure_row("windows", "-", "-", false, std::string{kBudgetExceededToken}, acc));
    if (budget.timed_out)
        rows.push_back(failure_row("windows", "-", "-", false, std::string{kTimeoutToken}, acc));
    return rows;
}

} // namespace yuzu::privacy_permissions::win
