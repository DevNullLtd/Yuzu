/**
 * privacy_permissions_win.cpp -- Windows leg: each real user profile's ConsentStore (reached
 * via the shared live-hive-first/offline-NTUSER.DAT-fallback ladder, NOT the process's own
 * HKEY_CURRENT_USER) plus the machine-wide HKLM mirror, walking
 * ...\CapabilityAccessManager\ConsentStore (rung 1, registry only, no spawn).
 *
 * The Windows agent service registers and runs as LocalSystem, not a per-user
 * identity (docs/agent-privilege-model.md TL;DR) -- HKEY_CURRENT_USER therefore
 * resolves to LocalSystem's own (irrelevant, near-always-empty) profile, never an interactive
 * user's real ConsentStore. Like license_scan's run_per_user_surfaces and registry's
 * do_get_user_value, this leg enumerates real profiles from HKLM ...\ProfileList
 * (agents/shared/win_profiles.hpp's enumerate_profile_list + build_profile_list, which
 * filters the LocalSystem/LocalService/NetworkService SIDs, cross-referenced with the HKU
 * subkey list) and reads each one's hive via with_user_hive: the loaded HKU\<SID> first, else an
 * offline RegLoadKeyW mount of <profile>\NTUSER.DAT under SeBackup/SeRestore (held for the
 * whole mount under the process-wide offline_hive_mutex()).
 *
 * OFFLINE HIVE-FILE GUARD (HiveFileGuard, opt-in through with_user_hive's OfflineHiveFileCheck;
 * the other offline-arm consumers are unchanged): before the load, a UNC or non-fixed-drive path
 * is refused, every ancestor directory is opened hop by hop from the drive root and refused if it
 * is a reparse point (no hop follows a junction/symlink), and the NTUSER.DAT leaf is checked from
 * its own handle (not a reparse point, a regular disk file, owner = the profile / LocalSystem /
 * Administrators, final path == requested path, size cap). RegLoadKeyW is path-based, so the same
 * file identity is re-verified after the load and a mismatch is unloaded unread
 * (`hive_identity_changed`). Residual: the kernel parses whatever the path resolved to in that
 * window, as it does for every `reg load`.
 *
 * STABILITY: a RegNotifyChangeKeyValue watch is armed on each ConsentStore root before its walk
 * and polled after; a change the API reports refuses that source (`changed_during_read`), and a
 * watch that cannot be created, armed or polled refuses it too -- failure to observe stability is
 * never stability. Residual: a RegRestoreKey-style whole-key replacement is not reported.
 *
 * DEADLINE: ~15 s, COOPERATIVE -- checked before each profile, first thing in the hive-file
 * guard's before_load and at every key read; there is no detached worker (a plugin must not defer
 * work past unload). One blocking call (the offline_hive_mutex wait behind a sibling plugin's
 * offline arm, RegLoadKeyW/RegUnLoadKeyW) is not interrupted, so a dispatch can overrun it.
 *
 * PRECEDENCE (win_parsers.hpp merge_with_hklm, unit-tested): Microsoft's documented Settings
 * model, confirmed on the-rig 2026-09-23 (a non-MDM Windows 11 host: HKLM `<capability>` `Value
 * Allow` on every capability) -- the HKLM ConsentStore `Value` is the device-wide toggle. Most
 * restrictive wins: only a successfully read and decoded HKLM `Deny` overrides a profile's entry
 * for the same (CapabilityName, app_id); an HKLM `Allow` defers to the user's own value and is
 * reported once as HKLM's own row; an absent/unreadable/refused HKLM value never displaces
 * anything; a FAILED profile entry is never hidden behind an HKLM value.
 *
 * THREE LEVELS per capability, each its own row: the capability `Value` (app_id `-`), the
 * NonPackaged toggle -- `<capability>\NonPackaged`'s own `Value`, "let desktop apps access"
 * (app_id `NonPackaged`) -- and each app key. A per-app NonPackaged key carries no `Value` (only
 * LastUsedTime*), so it reads `absent` with its timestamps: no per-app decision, governed by the
 * NonPackaged toggle row. `NonPackaged\Executables` is a container of per-exe prompt flags, not
 * an app, and is skipped (win::is_nonpackaged_container_key).
 * `app_id` is qualified with the owning profile's name (qualify_app_id, never the SID --
 * ADR-0024 D11); an unqualified app_id is HKLM's own row.
 *
 * EVERY outcome is a row: ProfileList discovery that was refused, failed, ended on an error or
 * hit its cap (and a refused/failed SID key or ProfileImagePath), a profile that could not be
 * reached or whose hive file was refused, a refused/failed ConsentStore root, a capability key or
 * app key that refused/failed to open, an enumeration that failed or hit its cap -- each is a
 * `denied` (refusal, PERMISSION_DENIED) or `unreadable` (CONSTRAINED) row carrying its own token
 * in `raw`; a capability or NonPackaged key that genuinely is not there is an `absent` row. One
 * source is capped on its own (win::RetentionBudget, `<profile>:budget_exceeded`, the walk goes
 * on); the run's output is bounded by the shared OutputBudget (`collection:budget_exceeded`,
 * HKLM's rows reserved first so a profile never starves them) and the run's time at ~15 s
 * (`collection:timeout`, hives unloaded normally). Only two failures are not rows of their own: a
 * failed hive UNLOAD (a token -- the read itself succeeded) and a LastUsedTime* failure (a token,
 * and the field itself reads `unreadable`; a refused one still promotes PERMISSION_DENIED).
 *
 * MEASURED on the-rig 2026-09-23 (Windows 11 Pro 10.0.26200, LocalSystem via a scheduled task,
 * one interactive profile with a live HKU hive): packaged per-app Allow/Deny/Prompt decode, the
 * NonPackaged `#` escape renders `C:#Program Files#...` as `C:\Program Files\...`, and the
 * LastUsedTime* QWORDs decode to plausible epoch-ms. The offline NTUSER.DAT arm with its
 * hive-file guard, the stability watch, and the hostile-path refusals are measured separately
 * (see the PR description); nothing in this file is claimed measured beyond that.
 */
#include "privacy_permissions_legs.hpp"
#include "privacy_permissions_win_parsers.hpp"

#if defined(_WIN32)

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <spdlog/spdlog.h>

#include <win_profiles.hpp>
#include <win_reg_handle.hpp>
#include <win_str.hpp>

#include <aclapi.h>
#include <sddl.h>

#ifndef REG_NOTIFY_THREAD_AGNOSTIC
#define REG_NOTIFY_THREAD_AGNOSTIC 0x10000000L // Windows 8+; older SDK headers omit it
#endif

namespace yuzu::privacy_permissions {

namespace {

using win::RawGrant;

static_assert(win::kErrorSuccess == ERROR_SUCCESS);
static_assert(win::kErrorFileNotFound == ERROR_FILE_NOT_FOUND);
static_assert(win::kErrorAccessDenied == ERROR_ACCESS_DENIED);
static_assert(win::kErrorNoMoreItems == ERROR_NO_MORE_ITEMS);
static_assert(win::kRegSz == REG_SZ);
static_assert(win::kRegQword == REG_QWORD);
static_assert(win::kDriveFixed == DRIVE_FIXED);
static_assert(win::kWaitObject0 == WAIT_OBJECT_0);
static_assert(win::kWaitTimeout == WAIT_TIMEOUT);

constexpr wchar_t kConsentStorePath[] =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore";

// A ConsentStore subtree is under the OWNING USER's write access (packaged/
// NonPackaged app keys), so an unbounded enumeration lets that same user pin the instruction
// worker -- and, on the offline-hive arm, hold the process-wide offline_hive_mutex() -- for as
// long as they can keep stuffing subkeys. Same shape and same order-of-magnitude as
// win_profiles.hpp's own kMaxEnumeratedValueNames (4096), the precedent this cap copies.
inline constexpr DWORD kMaxEnumeratedSubkeys = 4096;

struct SubkeyEnum {
    std::vector<std::wstring> names;
    win::EnumVerdict verdict;
};

/// Every child key name of `parent`, capped at kMaxEnumeratedSubkeys, plus how the walk ended
/// (win::classify_subkey_enum decides). The code that ended the walk is never
/// discarded -- a mid-enumeration ERROR_ACCESS_DENIED is not "every child enumerated".
/// When the loop stops at the cap, one extra, uncounted RegEnumKeyExW probe at
/// the next index tells "exactly cap children" (complete) from "more exist" (truncated) --
/// win_profiles.hpp's enumerate_profile_records/profile_list_actually_truncated precedent.
SubkeyEnum enumerate_subkey_names(HKEY parent) {
    SubkeyEnum out{{}, {win::EnumOutcome::complete}};
    constexpr DWORD kNameBufLen = 512;
    wchar_t buf[kNameBufLen]{};
    DWORD idx = 0, len = kNameBufLen;
    LONG rc = ERROR_SUCCESS;
    while (idx < kMaxEnumeratedSubkeys &&
           (rc = RegEnumKeyExW(parent, idx++, buf, &len, nullptr, nullptr, nullptr, nullptr)) ==
               ERROR_SUCCESS) {
        out.names.emplace_back(buf, len);
        len = kNameBufLen;
    }
    LONG probe_rc = ERROR_NO_MORE_ITEMS;
    if (rc == ERROR_SUCCESS) { // stopped by the cap alone
        DWORD probe_len = kNameBufLen;
        probe_rc = RegEnumKeyExW(parent, idx, buf, &probe_len, nullptr, nullptr, nullptr, nullptr);
    }
    out.verdict = win::classify_subkey_enum(rc, probe_rc);
    return out;
}

/// Reads one grant's `Value` (+ LastUsedTime*) from `app_key`. Every non-success outcome other
/// than "no Value here" (absent) sets a `cause`, so it is reported, never silently kept.
RawGrant read_one_grant(HKEY app_key, std::string app_id, std::string_view category) {
    RawGrant g{std::move(app_id), category, PermissionState::unreadable, "-"};

    DWORD type = 0, size = 0;
    const LONG probe_rc = RegQueryValueExW(app_key, L"Value", nullptr, &type, nullptr, &size);
    if (probe_rc == ERROR_SUCCESS && size > win::kMaxConsentValueBytes) {
        // This subtree is under the OWNING USER's write access, so an unbounded
        // allocation sized from a provider-reported DWORD would let that user make the
        // privileged agent retain an arbitrarily large buffer per value -- capped at the small
        // ConsentStore-literal bound (win::kMaxConsentValueBytes), reported, never truncated.
        g.cause = "value_oversized";
    } else if (probe_rc == ERROR_SUCCESS && size > 0) {
        std::vector<wchar_t> buf(size / sizeof(wchar_t) + 1, L'\0');
        DWORD sz = size;
        const LONG real_rc = RegQueryValueExW(app_key, L"Value", nullptr, &type,
                                              reinterpret_cast<BYTE*>(buf.data()), &sz);
        if (real_rc == ERROR_SUCCESS) {
            // `sz` (the size the SECOND read returned) bounds the decode, not the probe's size.
            const std::string val = yuzu::win::reg_sz_to_utf8(buf.data(), sz);
            g.state = win::decode_consent_value(val, type == REG_SZ);
            g.raw_value = val.empty() ? "-" : val;
            if (g.state == PermissionState::unreadable)
                g.cause = (type != REG_SZ) ? "value_type_" + std::to_string(type) : "value_empty";
        } else if (real_rc == ERROR_ACCESS_DENIED) {
            // The second read can itself be refused even though the size probe
            // succeeded (an ACL change between the two calls).
            g.state = PermissionState::denied;
            g.read_denied = true;
            g.cause = "value_access_denied";
        } else {
            // ERROR_MORE_DATA (the value grew between the two calls) or any other error.
            g.cause = "value_" + win::win32_cause(real_rc);
        }
    } else if (probe_rc == ERROR_SUCCESS) {
        g.cause = "value_empty"; // a zero-size Value: present, but carries nothing to decode
    } else if (probe_rc == ERROR_FILE_NOT_FOUND) {
        g.state = PermissionState::absent; // no Value under this key -- genuinely not there
    } else if (probe_rc == ERROR_ACCESS_DENIED) {
        g.state = PermissionState::denied; // the read was refused, never collapsed into absent
        g.read_denied = true;
        g.cause = "value_access_denied";
    } else {
        g.cause = "value_" + win::win32_cause(probe_rc);
    }

    const auto read_last_used = [&](const wchar_t* name) {
        std::uint64_t ft = 0;
        DWORD t = 0, sz = sizeof(ft);
        const LONG rc =
            RegQueryValueExW(app_key, name, nullptr, &t, reinterpret_cast<BYTE*>(&ft), &sz);
        return win::decode_last_used(rc, t, sz, ft);
    };
    g.last_used_start = read_last_used(L"LastUsedTimeStart");
    g.last_used_stop = read_last_used(L"LastUsedTimeStop");
    return g;
}

/// Arms a RegNotifyChangeKeyValue watch on a ConsentStore root before the walk and polls it
/// (zero timeout) after, so a change the API reports during the read is SHOWN, not assumed away.
/// Failure to observe is a fact classify_stability refuses on, never stability. Residual: the API
/// does not report a RegRestoreKey-style whole-key replacement.
struct StabilityWatch {
    HANDLE event = nullptr;
    win::StabilityFacts facts;

    explicit StabilityWatch(HKEY key) {
        event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!event) {
            const DWORD gle = GetLastError();
            facts.create_gle = gle ? gle : 1; // a failed create is never read as success
            return;
        }
        facts.arm_rc = RegNotifyChangeKeyValue(
            key, TRUE,
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC, event,
            TRUE);
    }
    ~StabilityWatch() {
        if (event) CloseHandle(event);
    }
    StabilityWatch(const StabilityWatch&) = delete;
    StabilityWatch& operator=(const StabilityWatch&) = delete;

    [[nodiscard]] win::StabilityFacts poll() {
        if (!event || facts.arm_rc != 0) return facts;
        facts.wait_rc = WaitForSingleObject(event, 0);
        facts.wait_gle = facts.wait_rc == WAIT_FAILED ? GetLastError() : 0;
        return facts;
    }
};

/// One ConsentStore root's walk.
struct ConsentWalk {
    LONG root_rc = ERROR_SUCCESS;
    std::vector<RawGrant> grants;     // keyed by (app_id, category); "-" = capability level
    std::vector<RawGrant> structural; // never merged -- always emitted as their own rows
    std::string refused;              // classify_stability token: the read is discarded unread
};

/// Walks every mapped CapabilityName under `hive`'s ConsentStore: the capability-level Value
/// (an `absent` entry when the capability key itself is not there, so every category is
/// represented) plus every packaged and NonPackaged app child. Every entry is charged against the
/// `budget` BEFORE it is retained; once the budget stops the walk (a limit, or the run's time) it
/// ends where it is and the collector reports which.
ConsentWalk walk_consent_store(HKEY hive, win::RetentionBudget& budget) {
    ConsentWalk w;
    const auto keep = [&](std::vector<RawGrant>& into, RawGrant g) {
        if (budget.charge(win::retained_bytes(g))) into.push_back(std::move(g));
    };
    yuzu::win::RegKey store;
    w.root_rc = RegOpenKeyExW(hive, kConsentStorePath, 0, KEY_READ, store.put());
    if (w.root_rc == ERROR_FILE_NOT_FOUND) {
        for (const auto& cap : win::kCapabilities)
            keep(w.grants, {"-", cap.category, PermissionState::absent, "-"});
        return w;
    }
    if (w.root_rc != ERROR_SUCCESS) return w; // the caller reports the whole-source row
    StabilityWatch watch(store.get());

    for (const auto& cap : win::kCapabilities) {
        if (budget.walk_stopped()) break;
        yuzu::win::RegKey cap_key;
        const LONG cap_rc = RegOpenKeyExW(store.get(), yuzu::win::to_wide(cap.capability_name).c_str(),
                                          0, KEY_READ, cap_key.put());
        if (cap_rc == ERROR_FILE_NOT_FOUND) {
            keep(w.grants, {"-", cap.category, PermissionState::absent, "-"});
            continue;
        }
        if (cap_rc != ERROR_SUCCESS) {
            keep(w.structural, win::structural_failure("-", cap.category,
                                                       "capability:" + win::win32_cause(cap_rc),
                                                       cap_rc == ERROR_ACCESS_DENIED));
            continue;
        }

        // The capability-level grant itself (no specific app -- "the global default").
        keep(w.grants, read_one_grant(cap_key.get(), "-", cap.category));

        // One app child: a key that vanished since enumeration (FILE_NOT_FOUND) is simply gone;
        // any other open failure is that app's own failure row.
        const auto read_app = [&](HKEY parent, const std::wstring& child, std::string app_id,
                                  std::string_view kind) {
            yuzu::win::RegKey app_key;
            const LONG rc = RegOpenKeyExW(parent, child.c_str(), 0, KEY_READ, app_key.put());
            if (rc == ERROR_SUCCESS)
                keep(w.grants, read_one_grant(app_key.get(), std::move(app_id), cap.category));
            else if (rc != ERROR_FILE_NOT_FOUND)
                keep(w.structural, win::structural_failure(
                                       std::move(app_id), cap.category,
                                       std::string{kind} + ":" + win::win32_cause(rc),
                                       rc == ERROR_ACCESS_DENIED));
        };
        // Enumeration completeness (win::enum_failure): a complete walk -- including one of
        // exactly the cap -- adds nothing; a truncated or failed one is a structural row.
        const auto note_enum = [&](std::string_view kind, const win::EnumVerdict& v) {
            if (const auto f = win::enum_failure(kind, v))
                keep(w.structural, win::structural_failure("-", cap.category, f->cause, f->denied));
        };

        // Packaged apps: direct children of the capability key OTHER than "NonPackaged".
        const auto packaged = enumerate_subkey_names(cap_key.get());
        for (const auto& child : packaged.names) {
            if (budget.walk_stopped()) break;
            if (child == L"NonPackaged") continue;
            read_app(cap_key.get(), child, yuzu::win::from_wide(child.c_str()), "packaged_app");
        }
        note_enum("packaged", packaged.verdict);

        // Win32 (non-packaged) apps, keyed by an escaped executable path.
        yuzu::win::RegKey nonpkg;
        const LONG nonpkg_rc =
            RegOpenKeyExW(cap_key.get(), L"NonPackaged", 0, KEY_READ, nonpkg.put());
        if (nonpkg_rc == ERROR_SUCCESS) {
            // The "let desktop apps access" toggle: the NonPackaged key's own Value, one row.
            keep(w.grants, read_one_grant(nonpkg.get(), std::string{win::kNonPackagedToggleAppId},
                                          cap.category));
            const auto nonpackaged = enumerate_subkey_names(nonpkg.get());
            for (const auto& child : nonpackaged.names) {
                if (budget.walk_stopped()) break;
                const std::string name = yuzu::win::from_wide(child.c_str());
                if (win::is_nonpackaged_container_key(name)) continue;
                read_app(nonpkg.get(), child, win::unescape_nonpackaged_app_id(name),
                         "nonpackaged_app");
            }
            note_enum("nonpackaged", nonpackaged.verdict);
        } else {
            // A missing NonPackaged key is the toggle row reading `absent`; any other code is a
            // structural failure (win::nonpackaged_open_failure decides).
            auto g = win::nonpackaged_open_failure(cap.category, nonpkg_rc);
            const bool toggle_absent = (g.state == PermissionState::absent);
            keep(toggle_absent ? w.grants : w.structural, std::move(g));
        }
    }
    if (const auto token = win::classify_stability(watch.poll())) {
        w.refused = *token;
        w.grants.clear();
        w.structural.clear();
    }
    return w;
}

// ── offline hive-file guard ───────────────────────────────────────────

struct UniqueHandle {
    HANDLE h = INVALID_HANDLE_VALUE;
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE x) noexcept : h(x) {}
    ~UniqueHandle() {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    [[nodiscard]] bool ok() const noexcept { return h != INVALID_HANDLE_VALUE; }
};

[[nodiscard]] std::string stat_failed(unsigned long code) {
    return "hive_stat_failed:win32_" + std::to_string(code);
}

/// Verifies the NTUSER.DAT an offline load is about to use (the OfflineHiveFileCheck hooks).
/// Every fact comes from an opened HANDLE. RegLoadKeyW has no handle-relative form, so the load
/// is by path and the SAME FILE_ID_INFO is re-verified from a fresh attribute-only handle after
/// it. Residual: the kernel parses whatever the path resolved to in that window (every
/// `reg load` carries it); swapping the path needs write access to the profile directory.
struct HiveFileGuard {
    win::RetentionBudget& budget;
    std::string profile_sid;
    std::size_t opens = 0; // CreateFileW calls made (a test proves the deadline-first order)
    std::optional<FILE_ID_INFO> snapshot;

    UniqueHandle open_attr(const std::wstring& path, DWORD access) {
        ++opens;
        return UniqueHandle{CreateFileW(path.c_str(), access,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        nullptr, OPEN_EXISTING,
                                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                                        nullptr)};
    }

    /// Fills the leaf facts and file identity from `path`'s attribute-only handle; "" or a token.
    std::string read_leaf(const std::wstring& path, win::HiveFileFacts& f, FILE_ID_INFO& id) {
        const UniqueHandle leaf = open_attr(path, FILE_READ_ATTRIBUTES | READ_CONTROL);
        if (!leaf.ok()) return stat_failed(GetLastError());

        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (!GetFileInformationByHandleEx(leaf.h, FileAttributeTagInfo, &tag, sizeof tag))
            return stat_failed(GetLastError());
        f.is_reparse = (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        f.is_directory = (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        f.is_disk_file = GetFileType(leaf.h) == FILE_TYPE_DISK;

        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(leaf.h, &info)) return stat_failed(GetLastError());
        f.size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;

        PSID owner = nullptr;
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (const DWORD rc = GetSecurityInfo(leaf.h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                             &owner, nullptr, nullptr, nullptr, &sd);
            rc != ERROR_SUCCESS)
            return stat_failed(rc);
        LPWSTR sid_str = nullptr;
        const BOOL converted = ConvertSidToStringSidW(owner, &sid_str);
        const DWORD convert_gle = converted ? 0 : GetLastError();
        if (converted) f.owner_sid = yuzu::win::from_wide(sid_str);
        if (sid_str) LocalFree(sid_str);
        if (sd) LocalFree(sd);
        if (!converted) return stat_failed(convert_gle);

        std::wstring fin(MAX_PATH, L'\0');
        DWORD n = GetFinalPathNameByHandleW(leaf.h, fin.data(), static_cast<DWORD>(fin.size()),
                                            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (n >= fin.size()) {
            fin.assign(static_cast<std::size_t>(n) + 1, L'\0');
            n = GetFinalPathNameByHandleW(leaf.h, fin.data(), static_cast<DWORD>(fin.size()),
                                          FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        }
        if (n == 0 || n >= fin.size()) return stat_failed(GetLastError());
        f.final_path = yuzu::win::from_wide(fin.c_str(), static_cast<int>(n));

        if (!GetFileInformationByHandleEx(leaf.h, FileIdInfo, &id, sizeof id))
            return stat_failed(GetLastError());
        return {};
    }

    std::string before_load(const std::wstring& path) {
        // FIRST: the deadline (after the lock wait and privilege enable, before any file syscall).
        if (budget.expired()) return std::string{win::kHiveTimeout};

        win::HiveFileFacts f;
        f.profile_sid = profile_sid;
        f.requested_path = yuzu::win::from_wide(path.c_str(), static_cast<int>(path.size()));
        // Neutral leaf facts, so that only the path facts can trip this early classification.
        f.owner_sid = profile_sid;
        f.final_path = "\\\\?\\" + f.requested_path;
        f.path_is_unc = path.starts_with(L"\\\\");

        std::vector<std::wstring> parts;
        std::wstring root;
        if (!f.path_is_unc && path.size() >= 3 && path[1] == L':' && path[2] == L'\\') {
            root = path.substr(0, 3);
            f.drive_type = GetDriveTypeW(root.c_str());
            std::size_t pos = 3;
            while (pos <= path.size()) {
                const auto end = path.find(L'\\', pos);
                const auto part = path.substr(pos, end == std::wstring::npos ? end : end - pos);
                if (!part.empty()) parts.push_back(part);
                if (end == std::wstring::npos) break;
                pos = end + 1;
            }
        } else {
            f.drive_type = DRIVE_UNKNOWN; // no drive-letter root: not a fixed local path
        }
        f.depth = parts.size();
        if (const auto t = win::classify_hive_file(f)) return *t;
        if (parts.empty()) return std::string{win::kHiveNotRegular};

        // Hop by hop from the drive root: no hop ever follows a junction/symlink.
        std::wstring cur = root;
        for (std::size_t i = 0; i + 1 < parts.size(); ++i) {
            cur += (i ? L"\\" : L"") + parts[i];
            const UniqueHandle dir = open_attr(cur, FILE_READ_ATTRIBUTES);
            if (!dir.ok()) return stat_failed(GetLastError());
            FILE_ATTRIBUTE_TAG_INFO tag{};
            if (!GetFileInformationByHandleEx(dir.h, FileAttributeTagInfo, &tag, sizeof tag))
                return stat_failed(GetLastError());
            if (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                f.ancestor_reparse = true;
                break;
            }
        }
        if (f.ancestor_reparse) return std::string{win::kHivePathReparseAncestor};

        FILE_ID_INFO id{};
        if (auto t = read_leaf(path, f, id); !t.empty()) return t;
        if (const auto t = win::classify_hive_file(f)) return *t;
        snapshot = id;
        return {}; // the leaf handle is closed here: RegLoadKeyW needs exclusive access
    }

    std::string after_load(const std::wstring& path) {
        if (!snapshot) return std::string{win::kHiveIdentityChanged};
        win::HiveFileFacts unused;
        FILE_ID_INFO id{};
        if (auto t = read_leaf(path, unused, id); !t.empty()) return t;
        if (id.VolumeSerialNumber != snapshot->VolumeSerialNumber ||
            std::memcmp(&id.FileId, &snapshot->FileId, sizeof id.FileId) != 0)
            return std::string{win::kHiveIdentityChanged};
        return {};
    }
};

/// Emits one grant as a row. `source` is the profile name (or "hklm"); `qualify` = prefix the
/// row's app_id with it (false only for HKLM's own, machine-wide rows). A failed grant's row `raw`
/// is `<source>\<app_id>:<category>:<cause>`; the run's constraint set (the agent-log provenance)
/// gets only the app-less win::coarse_failure_token.
void emit_grant(std::string_view source, bool qualify, const RawGrant& g,
                std::vector<PermissionRow>& rows, yuzu::shared::ConstraintAccumulator& acc) {
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
        acc.add_failure(win::coarse_failure_token(source, g.category, g.cause));
    }
    if (!g.last_used_start.cause.empty())
        acc.add_failure(win::coarse_failure_token(source, g.category,
                                                  "last_used_start_" + g.last_used_start.cause));
    if (!g.last_used_stop.cause.empty())
        acc.add_failure(win::coarse_failure_token(source, g.category,
                                                  "last_used_stop_" + g.last_used_stop.cause));
    row.read_denied = row.read_denied || g.last_used_start.denied || g.last_used_stop.denied;
    rows.push_back(std::move(row));
}

/// The one whole-source row for a ConsentStore root that could not be opened (not "not there").
void emit_root_failure(std::string_view source, std::string app_id, LONG rc,
                       std::vector<PermissionRow>& rows, yuzu::shared::ConstraintAccumulator& acc) {
    rows.push_back(failure_row("windows", std::move(app_id), "-", rc == ERROR_ACCESS_DENIED,
                               std::string{source} + ":" + win::win32_cause(rc), acc));
}

} // namespace

// Excluded under YUZU_PRIVACY_PERMISSIONS_WIN_UNIT_TEST_INTERNALS_ONLY: the seam
// test_privacy_permissions_win_internals.cpp uses to #include this TU and reach the
// internal-linkage helpers (mirrors privacy_permissions_macos.cpp). Never defined by the real build.
#ifndef YUZU_PRIVACY_PERMISSIONS_WIN_UNIT_TEST_INTERNALS_ONLY

int collect_windows_permissions(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;
    win::RetentionBudget budget; // per-source caps + the cooperative run deadline
    OutputBudget output;         // run-wide formatted-length bound, shared with the macOS leg
    // A source that hit its own cap keeps the rows it charged; this row says it is incomplete.
    const auto truncated_row = [&](std::vector<PermissionRow>& into, const std::string& source,
                                   const std::string& row_id) {
        if (budget.profile_exhausted)
            into.push_back(failure_row(
                "windows", row_id, "-", false,
                source + ":" + std::string{win::kSourceBudgetExceededSuffix}, acc));
    };

    // HKLM: machine-wide, collected once. Only its successfully read `Deny` grants override a
    // profile (win::hklm_overrides_profile -- the device toggle, most restrictive wins) and are
    // applied into each profile's merge; everything else HKLM holds is reported once below as
    // HKLM's own unqualified rows.
    budget.begin_profile();
    ConsentWalk hklm = walk_consent_store(HKEY_LOCAL_MACHINE, budget);
    std::vector<PermissionRow> hklm_grant_rows; // one per hklm.grants entry, same index
    std::vector<PermissionRow> hklm_tail;       // structural, root failure, refusal: always emitted
    std::vector<RawGrant> hklm_overriding;
    for (const auto& g : hklm.grants) {
        if (win::hklm_overrides_profile(g)) hklm_overriding.push_back(g);
        emit_grant("hklm", false, g, hklm_grant_rows, acc);
    }
    for (const auto& g : hklm.structural) emit_grant("hklm", false, g, hklm_tail, acc);
    if (hklm.root_rc != ERROR_SUCCESS && hklm.root_rc != ERROR_FILE_NOT_FOUND)
        emit_root_failure("hklm", "-", hklm.root_rc, hklm_tail, acc);
    if (!hklm.refused.empty())
        hklm_tail.push_back(
            failure_row("windows", "-", "-", false, "hklm:" + hklm.refused, acc));
    truncated_row(hklm_tail, "hklm", "-");
    // RESERVE HKLM's rows before any profile charges: an upper bound (hklm_emitted_once only
    // narrows it), so a profile can never starve the machine rows and the machine rows are never
    // charged twice.
    output.charge(hklm_grant_rows);
    output.charge(hklm_tail);

    // Real interactive users, not the agent process's own (LocalSystem) HKEY_CURRENT_USER --
    // see the file banner. Discovery keeps every code it saw and each is a row
    // (win::profile_discovery_failure / profile_record_failure decide); the profiles that WERE
    // enumerated are still walked.
    const auto discovery = yuzu::win::enumerate_profile_list();
    if (const auto f = win::profile_discovery_failure(discovery.root_rc, discovery.last_rc,
                                                      discovery.probe_rc))
        rows.push_back(failure_row("windows", "-", "-", f->denied, f->cause, acc));
    for (const auto& rf : discovery.record_failures) {
        if (yuzu::profiles::is_system_sid(rf.sid)) continue; // never walked (build_profile_list)
        const auto f = win::profile_record_failure(rf.key_open, rf.rc);
        rows.push_back(failure_row("windows", "-", "-", f.denied, f.cause, acc));
    }
    const auto hku_subkeys = yuzu::win::enumerate_hku_subkeys();
    const auto profiles = yuzu::profiles::build_profile_list(discovery.records, hku_subkeys);

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

    for (const auto& profile : profiles) {
        // The walk re-checks after with_user_hive's lock wait and mount, which count toward it.
        if (output.exhausted() || budget.expired()) break;
        budget.begin_profile();
        const std::string pname = profile.profile_name.empty() ? "-" : profile.profile_name;
        const std::string profile_row_id = qualify_app_id(pname, "-");
        std::vector<PermissionRow> prof;

        // The SID is appended to HKEY_USERS below (and by with_user_hive): a malformed or empty
        // one -- or one that converts to an empty wide string -- must never open the HKU root
        // or some other key in place of this profile's own hive.
        const std::wstring wsid = yuzu::win::to_wide(profile.sid);
        if (!win::is_valid_sid_string(profile.sid) || wsid.empty()) {
            prof.push_back(
                failure_row("windows", profile_row_id, "-", false, pname + ":invalid_sid", acc));
            if (!commit(prof, false)) break;
            continue;
        }

        // with_user_hive's live-hive check tests only `== ERROR_SUCCESS`, so a refused LIVE
        // HKU\<SID> root is indistinguishable from "not loaded" to its caller, and if the offline
        // fallback then also fails the denial would be lost. A cheap peek at the live root (never
        // gating or replacing the real call; benign TOCTOU) recovers it.
        LONG peek_rc = ERROR_SUCCESS;
        {
            yuzu::win::RegKey peek;
            peek_rc = RegOpenKeyExW(HKEY_USERS, wsid.c_str(), 0, KEY_READ, peek.put());
        }

        ConsentWalk user;
        yuzu::win::HiveAccessReport report;
        HiveFileGuard guard{budget, profile.sid, 0, std::nullopt};
        const yuzu::win::OfflineHiveFileCheck check{
            [&](const std::wstring& p) { return guard.before_load(p); },
            [&](const std::wstring& p) { return guard.after_load(p); }};
        // Synchronous, like every other with_user_hive consumer: no detached worker can outlive
        // the dispatch (sdk plugin.hpp: a plugin must not defer work past unload).
        const auto status = yuzu::win::with_user_hive(
            profile.sid, profile.profile_path,
            [&](HKEY root) { user = walk_consent_store(root, budget); }, &report, &check);
        // The read itself completed; a failed unload is an operational residue (a mount left
        // behind), reported as a token, not a data gap.
        if (report.unload_failed) {
            acc.add_failure(pname + ":hive_unload_failed");
            spdlog::error("privacy_permissions: hive unload failed for profile {} (HKU\\{}): its "
                          "NTUSER.DAT stays locked, and the user's next sign-in may not load the "
                          "profile, until `reg unload HKU\\{}` succeeds",
                          pname, report.mount_name, report.mount_name);
        }

        // Exhaustive over the HiveAccessStatus outcomes: a profile whose hive was never opened
        // must never read as "this profile has no grants" -- each failure is its own row.
        // `refused`: the cause is itself a refusal (a missing privilege): denied, token unchanged.
        const auto profile_failed = [&](std::string_view cause, bool refused = false) {
            const bool peek_denied = (peek_rc == ERROR_ACCESS_DENIED);
            prof.push_back(failure_row("windows", profile_row_id, "-", peek_denied || refused,
                                       pname + ":" + (peek_denied ? std::string{"access_denied"}
                                                                  : std::string{cause}),
                                       acc));
        };
        bool reachable = false;
        switch (status) {
        case yuzu::win::HiveAccessStatus::ok:
            reachable = true;
            break;
        case yuzu::win::HiveAccessStatus::privilege_missing:
            profile_failed("privilege_missing", true);
            break;
        case yuzu::win::HiveAccessStatus::not_found:
            // `profile_path_unreadable` (carried from the raw ProfileList record) means even the
            // PATH itself couldn't be resolved -- named distinctly from "no hive to reach".
            profile_failed(profile.profile_path_unreadable ? "profile_path_unreadable"
                                                           : "hive_not_found");
            break;
        case yuzu::win::HiveAccessStatus::mount_failed:
            profile_failed("hive_mount_failed");
            break;
        case yuzu::win::HiveAccessStatus::file_refused:
            // A hive-file refusal is unreadable, not denied (an unsafe file is not an ACL
            // refusal); `timeout` also ends the run (budget.expired() already marked it).
            prof.push_back(failure_row("windows", profile_row_id, "-", false,
                                       pname + ":" + report.refusal, acc));
            break;
        }

        if (reachable) {
            if (!user.refused.empty()) {
                prof.push_back(failure_row("windows", profile_row_id, "-", false,
                                           pname + ":" + user.refused, acc));
                reachable = false; // nothing merged: HKLM's Deny must not be lost with it
            } else {
                if (user.root_rc != ERROR_SUCCESS && user.root_rc != ERROR_FILE_NOT_FOUND)
                    emit_root_failure(pname, profile_row_id, user.root_rc, prof, acc);
                for (const auto& g : win::merge_with_hklm(user.grants, hklm_overriding))
                    emit_grant(pname, true, g, prof, acc);
                for (const auto& g : user.structural) emit_grant(pname, true, g, prof, acc);
                truncated_row(prof, pname, profile_row_id);
            }
        }
        if (!commit(prof, reachable)) break;
        if (budget.timed_out) break;
    }

    // HKLM's own rows, unqualified, once (win::hklm_emitted_once), already charged: everything it
    // holds -- failures, Allow and unmodelled values, app-level entries and its definitive
    // capability-level `absent`s -- and its overriding Deny grants only when no profile was
    // reachable to carry them.
    for (std::size_t i = 0; i < hklm.grants.size(); ++i)
        if (win::hklm_emitted_once(hklm.grants[i], reachable_profiles > 0))
            rows.push_back(std::move(hklm_grant_rows[i]));
    for (auto& r : hklm_tail) rows.push_back(std::move(r));
    // The run-wide output budget stopped the walk: every row read so far is above; what was never
    // walked is covered by this one whole-source row.
    if (budget_hit)
        rows.push_back(failure_row("windows", "-", "-", false,
                                   std::string{kBudgetExceededToken}, acc));
    if (budget.timed_out)
        rows.push_back(
            failure_row("windows", "-", "-", false, std::string{win::kTimeoutToken}, acc));

    // A category no row mentions is `absent` unless a whole-source failure row above already
    // stands for it; a token-only failure (hive_unload_failed, a LastUsedTime* read) covers none.
    fill_uncovered_categories("windows", rows);
    return emit_rows(ctx, rows, acc, false);
}

#endif // !YUZU_PRIVACY_PERMISSIONS_WIN_UNIT_TEST_INTERNALS_ONLY

} // namespace yuzu::privacy_permissions

#endif // defined(_WIN32)
