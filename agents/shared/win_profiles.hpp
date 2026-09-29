// win_profiles.hpp -- Win32 shell for user-profile / registry-hive discovery
// (PR1.7). Gathers raw ProfileList rows and HKEY_USERS subkey names into the
// plain structs user_profile_model.hpp classifies; every decision lives
// there -- this file is mechanical Reg*W plumbing only, deliberately kept
// free of branching logic so it stays thin.
//
// Ported from (not re-derived from) license_scan's licensing_win.cpp -- the
// governance-hardened reference for this exact ladder (ADR-0024, roadmap
// C-1/R15/R17) -- and specifically NOT from registry_plugin.cpp's
// do_get_user_value, which licensing_win.cpp's own header comment names as a
// known-broken precedent (issue I-5): it hard-codes
// C:\Users\<username>\NTUSER.DAT instead of reading ProfileImagePath, never
// enables SeBackup/SeRestore despite its own comment saying they are
// required, and its ERROR_SHARING_VIOLATION branch reads the mount point
// even when nothing was mounted there.
//
// R17: every registry read goes through wide Reg*W APIs + win_str.hpp
// (never the *A siblings).
//
// Windows-only by construction (#ifdef _WIN32); the header is empty
// elsewhere.

#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "user_profile_model.hpp"
#include "value_enumeration.hpp"
#include "win_reg_handle.hpp"
#include "win_str.hpp"

// Process-wide offline-mount serialisation, exported from the single
// yuzu_agent_core shared library every plugin links against -- see
// offline_hive_mutex() below and the header's own doc comment for why a
// header-local static cannot do this job (#2771 code-review CFX-1).
#include <yuzu/agent/offline_hive_mutex.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace yuzu::win {

/// Bounds on the profile walk. registry_plugin.cpp's original get_value
/// sized a value buffer from a RegQueryValueExW call whose return code was
/// ignored, then allocated unbounded -- these two caps replace that with an
/// explicit ceiling.
inline constexpr std::size_t kMaxProfiles = 512;
inline constexpr DWORD kMaxRegValueBytes = 1u * 1024u * 1024u; // 1 MiB

// Bound on enumerate_value_names()'s worst-case wall time: a key an
// operator (or an attacker with write access to the hive) has stuffed with
// an unbounded number of values must not pin the instruction worker
// enumerating forever. 4096 is well beyond any real Defender exclusion list
// this function was written for (antivirus/av_exclusions) while still being
// a hard ceiling.
inline constexpr DWORD kMaxEnumeratedValueNames = 4096;

// A registry value NAME (as opposed to its data) is capped by Win32 at
// 16383 WCHARs; this is a defensive ceiling on the name buffer this function
// allocates, independent of whatever RegQueryInfoKeyW reports as the key's
// actual max -- a corrupt or hostile hive should not make this function
// allocate an unbounded buffer.
inline constexpr DWORD kMaxValueNameChars = 16384;

// A Windows path is at most 32767 wchars; 64 KiB bounds the two-pass
// ProfileImagePath read without ever truncating a legitimate value.
inline constexpr DWORD kMaxProfilePathBytes = 64u * 1024u;

// Two-pass ExpandEnvironmentStringsW. The single-pass form SILENTLY
// TRUNCATES: on overflow the API does not fail -- it returns the required
// wchar count (including the terminating NUL), which a bare `> 0` test reads
// as success, so an over-long ProfileImagePath yields a valid-LOOKING but
// wrong path. Pass 1 sizes (dest=nullptr, size=0); pass 2 fills. Returns
// `in` unchanged if the API fails, or if the environment grew between the
// two calls -- an unexpanded literal is a VISIBLY wrong path, never a
// plausible-but-wrong one.
inline std::wstring expand_env_strings(const std::wstring& in) {
    const DWORD needed = ExpandEnvironmentStringsW(in.c_str(), nullptr, 0);
    if (needed == 0)
        return in;
    std::wstring buf(needed, L'\0'); // `needed` INCLUDES the terminating NUL
    const DWORD written = ExpandEnvironmentStringsW(in.c_str(), buf.data(), needed);
    if (written == 0 || written > needed)
        return in;
    buf.resize(written - 1); // drop the NUL from the string's size
    return buf;
}

// Reads HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList,
// returning one RawProfileRecord per subkey (SID) found, capped at
// kMaxProfiles, with ProfileImagePath already environment-expanded. `ok` is
// set false only when the ProfileList key itself could not be opened -- a
// per-profile ProfileImagePath read failure is reported as an empty
// profile_image_path on that one record, never a dropped record. `truncated`,
// if non-null, is set true when a record was ACTUALLY DROPPED -- the cap was
// reached AND a probe confirmed a further ProfileList subkey exists (#2771
// code-review C-M3: "cap reached" alone is not the same fact -- a host with
// exactly kMaxProfiles subkeys hits the cap without losing anything). A
// caller that cares about completeness (list_profiles) surfaces this; one
// that's looking up a single profile (get_user_value) may pass nullptr and
// ignore it.
inline std::vector<yuzu::profiles::RawProfileRecord> enumerate_profile_records(
    bool& ok, bool* truncated = nullptr) {
    std::vector<yuzu::profiles::RawProfileRecord> out;
    ok = false;
    if (truncated)
        *truncated = false;

    RegKey profiles;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS, profiles.put()) != ERROR_SUCCESS)
        return out;
    ok = true;

    constexpr DWORD kSidBufLen = 256; // WCHAR count, not bytes
    wchar_t sid_buf[kSidBufLen]{};
    DWORD idx = 0;
    DWORD sid_len = kSidBufLen;
    while (out.size() < kMaxProfiles &&
           RegEnumKeyExW(profiles.get(), idx++, sid_buf, &sid_len, nullptr, nullptr, nullptr,
                         nullptr) == ERROR_SUCCESS) {
        yuzu::profiles::RawProfileRecord rec;
        rec.sid = from_wide(sid_buf, static_cast<int>(sid_len));
        sid_len = kSidBufLen;

        RegKey sid_key;
        if (RegOpenKeyExW(profiles.get(), to_wide(rec.sid).c_str(), 0, KEY_READ, sid_key.put()) ==
            ERROR_SUCCESS) {
            // Two-pass (#2771 up-S2). The former fixed 512-wchar buffer made
            // RegQueryValueExW return ERROR_MORE_DATA for a longer
            // ProfileImagePath, which left profile_image_path empty and
            // therefore INDISTINGUISHABLE from "the value is absent" -- a
            // silent truncation with no signal, unlike the kMaxProfiles cap
            // which has always warned. Sizing first removes the truncation
            // outright; the flag covers whatever still fails to decode.
            DWORD type = 0, path_size = 0;
            const LSTATUS size_rc = RegQueryValueExW(sid_key.get(), L"ProfileImagePath", nullptr,
                                                     &type, nullptr, &path_size);
            if (size_rc == ERROR_SUCCESS && path_size > 0 && path_size <= kMaxProfilePathBytes &&
                (type == REG_SZ || type == REG_EXPAND_SZ)) {
                // Round up to a whole wchar_t: a malformed value can carry an
                // odd byte count, and the buffer must still hold every byte
                // the second call writes.
                std::vector<wchar_t> path_buf((path_size + sizeof(wchar_t) - 1) / sizeof(wchar_t) + 1,
                                              L'\0');
                DWORD read_size = static_cast<DWORD>(path_buf.size() * sizeof(wchar_t));
                if (RegQueryValueExW(sid_key.get(), L"ProfileImagePath", nullptr, &type,
                                     reinterpret_cast<LPBYTE>(path_buf.data()), &read_size) ==
                        ERROR_SUCCESS &&
                    (type == REG_SZ || type == REG_EXPAND_SZ)) {
                    std::size_t nch = read_size / sizeof(wchar_t);
                    if (nch > path_buf.size())
                        nch = path_buf.size();
                    while (nch > 0 && path_buf[nch - 1] == L'\0')
                        --nch;
                    // ProfileImagePath may be REG_EXPAND_SZ -- expand once,
                    // here, so every downstream consumer sees a literal path.
                    const std::wstring expanded =
                        expand_env_strings(std::wstring(path_buf.data(), nch));
                    rec.profile_image_path =
                        from_wide(expanded.c_str(), static_cast<int>(expanded.size()));
                } else {
                    // The value was there a moment ago and is not readable
                    // now (raced delete, ACL, corruption).
                    rec.profile_image_path_unreadable = true;
                }
            } else if (size_rc == ERROR_SUCCESS) {
                // Present but unusable: over the cap, zero-length, or a type
                // that is not a string.
                rec.profile_image_path_unreadable = true;
            } else if (size_rc != ERROR_FILE_NOT_FOUND) {
                // The sizing call itself failed for a reason other than
                // genuine absence -- e.g. ERROR_ACCESS_DENIED on the value.
                // #2771 code-review Spec F8: this branch previously stayed
                // silent for ANY non-SUCCESS size_rc, which contradicted the
                // documented behaviour ("exists but cannot be read or
                // decoded") for exactly this case. Only a genuinely absent
                // value (ERROR_FILE_NOT_FOUND) stays silent below -- a
                // profile with no ProfileImagePath is not an error.
                rec.profile_image_path_unreadable = true;
            }
        }
        out.push_back(std::move(rec));
    }
    if (truncated) {
        // The DECISION (cap reached AND a next entry actually exists) is
        // yuzu::profiles::profile_list_actually_truncated, extracted pure so
        // it is unit-tested without a real registry (#2771 code-review
        // C-M3 / P2-N3). This Win32 shell's job is only to gather the two
        // input facts: did we hit the cap, and does one extra RegEnumKeyExW
        // probe (nothing stored from it) find a next subkey.
        const bool cap_reached = (out.size() >= kMaxProfiles);
        if (cap_reached) {
            wchar_t probe_buf[kSidBufLen]{};
            DWORD probe_len = kSidBufLen;
            const bool probe_found_more =
                (RegEnumKeyExW(profiles.get(), idx, probe_buf, &probe_len, nullptr, nullptr,
                              nullptr, nullptr) == ERROR_SUCCESS);
            *truncated = yuzu::profiles::profile_list_actually_truncated(cap_reached,
                                                                         probe_found_more);
        } else {
            *truncated = false;
        }
    }
    return out;
}

// Subkey names directly under HKEY_USERS -- live-loaded hive roots, plus any
// "<SID>_Classes" siblings. This is the input to
// yuzu::profiles::classify_hive_state.
inline std::vector<std::string> enumerate_hku_subkeys() {
    std::vector<std::string> out;
    constexpr DWORD kNameBufLen = 256;
    wchar_t name_buf[kNameBufLen]{};
    DWORD idx = 0;
    DWORD name_len = kNameBufLen;
    while (RegEnumKeyExW(HKEY_USERS, idx++, name_buf, &name_len, nullptr, nullptr, nullptr,
                         nullptr) == ERROR_SUCCESS) {
        out.push_back(from_wide(name_buf, static_cast<int>(name_len)));
        name_len = kNameBufLen;
    }
    return out;
}

// Result of enumerate_value_names(): the names actually collected, plus
// whether the enumeration is known to be the COMPLETE set. `complete` is
// false when a value name exists but could not be confirmed collected --
// RegQueryInfoKeyW itself failed on an already-open key, the safety cap
// (kMaxEnumeratedValueNames) cut the walk short, or RegEnumValueW failed
// mid-enumeration. `names` is never fabricated: whatever is present is
// real data, `complete=false` is purely an "there may be more" signal so a
// caller doesn't present a possibly-truncated list as a verified-clean one
// (security-relevant for callers like Defender exclusion enumeration,
// where an under-reported list reads as a healthier posture than reality).
struct ValueNameEnumeration {
    std::vector<std::string> names;
    bool complete = true;
};

// Enumerates every VALUE NAME directly under `key` (not the values'
// data — some registry-driven configuration, e.g. Windows Defender's
// exclusion lists, stores each entry AS the value name itself, with the
// data unused). Returns an empty, complete result both when `key`
// genuinely has no values and when `key` is null — callers that need to
// distinguish "empty key" from "key could not be opened at all" check the
// RegOpenKeyExW result themselves before calling this (this function only
// ever sees an already-open key; a null `key` is therefore never itself a
// completeness failure of THIS function).
//
// Two-pass, same spirit as read_reg_value()'s size-then-fill idiom: first
// RegQueryInfoKeyW sizes the longest value name actually present so the
// buffer is neither a truncating fixed guess (a value name here can be a
// full filesystem path, unlike the short SID/profile key names
// enumerate_profile_records/enumerate_hku_subkeys size for) nor an
// unbounded allocation (kMaxValueNameChars caps it regardless of what the
// key reports). Enumeration itself is bounded at kMaxEnumeratedValueNames
// entries so a key stuffed with an unbounded number of values cannot pin
// this call indefinitely -- that cap, and any other short-collection, is
// reported via `complete`, never silently.
inline ValueNameEnumeration enumerate_value_names(HKEY key) {
    ValueNameEnumeration result;
    if (!key)
        return result;

    DWORD value_count = 0;
    DWORD max_name_len = 0; // WCHARs, NOT including the terminating NUL
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &value_count,
                         &max_name_len, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        result.complete = false;
        return result;
    }
    if (value_count == 0)
        return result;

    if (max_name_len >= kMaxValueNameChars)
        max_name_len = kMaxValueNameChars - 1;
    std::vector<wchar_t> name_buf(static_cast<std::size_t>(max_name_len) + 1, L'\0');

    const DWORD cap = value_count < kMaxEnumeratedValueNames ? value_count
                                                             : kMaxEnumeratedValueNames;
    result.names.reserve(cap);
    DWORD idx = 0;
    for (; idx < cap; ++idx) {
        // RegEnumValueW's lpcchValueName is WCHAR count and MUST include
        // room for the terminator on input, even though the count it writes
        // back on success does not include it (mirrors RegEnumKeyExW's
        // contract in enumerate_hku_subkeys above, just measured in the
        // opposite unit from read_reg_value's byte-oriented RegQueryValueExW).
        DWORD name_len = static_cast<DWORD>(name_buf.size());
        const LSTATUS rc = RegEnumValueW(key, idx, name_buf.data(), &name_len, nullptr, nullptr,
                                         nullptr, nullptr);
        if (rc != ERROR_SUCCESS) {
            // A value deleted mid-enumeration (index shifts under us) or any
            // other transient failure -- stop rather than loop past what the
            // key actually still has; whatever was collected so far is real.
            break;
        }
        result.names.push_back(from_wide(name_buf.data(), static_cast<int>(name_len)));
    }
    // The DECISION (cap reached AND the walk reached it, vs cut short by
    // either the cap or a mid-enumeration failure) is
    // yuzu::win::value_enumeration_is_complete, extracted pure so it is
    // unit-tested without a real registry (adversarial-review gate 2
    // finding: the prior inline `complete = false` assignments above were
    // never fixture-reachable). This Win32 shell's job is only to gather
    // the three input facts: the provider's reported count, the cap we
    // applied, and how far the walk actually got (`idx`).
    result.complete = value_enumeration_is_complete(value_count, cap, idx);
    return result;
}

// RAII scope that enables a token privilege the service account holds but
// which may start disabled -- RegLoadKeyW requires BOTH SeBackupPrivilege
// and SeRestorePrivilege enabled (granted by
// scripts/install-agent-user.ps1; a hardened install may strip them) -- and
// restores the token's PRIOR attributes for that privilege on scope exit.
// licensing_win.cpp's enable_privilege (the shape this ladder was ported
// from, and the process-wide privilege leak it carried) is deleted as of
// #2771 -- license_scan now calls this type via with_user_hive like every
// other consumer. Checks
// GetLastError()==ERROR_SUCCESS after the enabling AdjustTokenPrivileges,
// which "succeeds" even when the privilege is absent from the token
// entirely (ERROR_NOT_ALL_ASSIGNED) -- a bare return-value check would
// misreport that case as success. Move-only via deleted copy ops; not
// move-enabled either since every call site constructs it in place.
class PrivilegeScope {
public:
    explicit PrivilegeScope(const wchar_t* name) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_))
            return;

        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, name, &luid)) {
            CloseHandle(token_);
            token_ = nullptr;
            return;
        }

        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        // BUG FIX (code-review CFX/functional-BLOCK, orchestrator probe): when
        // PreviousState (the 5th arg) is non-NULL, ReturnLength (the 6th) MUST
        // also be non-NULL -- passing nullptr here made AdjustTokenPrivileges
        // fail outright with ERROR_NOACCESS on every call, so ok_ was FALSE
        // unconditionally and the offline-hive fallback has never actually
        // enabled the privilege since it shipped. Reproduced directly against
        // a real token: the identical call with ReturnLength=nullptr returns
        // adjusted=FALSE/gle=998 (ERROR_NOACCESS); with &returned_len it
        // returns adjusted=TRUE/gle=ERROR_SUCCESS. previous_len is otherwise
        // unused -- the buffer size that matters is BufferLength (sizeof(previous_)).
        DWORD previous_len = 0;
        const BOOL adjusted = AdjustTokenPrivileges(token_, FALSE, &tp, sizeof(previous_),
                                                    &previous_, &previous_len);
        ok_ = adjusted && GetLastError() == ERROR_SUCCESS;
        have_previous_ = adjusted;
    }

    PrivilegeScope(const PrivilegeScope&) = delete;
    PrivilegeScope& operator=(const PrivilegeScope&) = delete;

    ~PrivilegeScope() {
        // Restore whatever AdjustTokenPrivileges reported as the PRIOR
        // state, even when this scope failed to enable the privilege (a
        // partial/no-op adjustment still needs no undo, and previous_ is
        // zero-initialised in that case, making this a harmless no-op).
        if (token_ && have_previous_)
            AdjustTokenPrivileges(token_, FALSE, &previous_, 0, nullptr, nullptr);
        if (token_)
            CloseHandle(token_);
    }

    [[nodiscard]] bool ok() const { return ok_; }

private:
    HANDLE token_{};
    TOKEN_PRIVILEGES previous_{};
    bool have_previous_ = false;
    bool ok_ = false;
};

/// Outcome of with_user_hive's access ladder, rendered honestly by the
/// caller instead of collapsing every non-ok case to silence.
///
/// Defined in user_profile_model.hpp (portable) and aliased here so the
/// rendering decisions are testable off-Windows; every existing
/// `yuzu::win::HiveAccessStatus::...` call site is unaffected.
using HiveAccessStatus = yuzu::profiles::HiveAccessStatus;

/// What with_user_hive did, for callers that need to report it. `mount_name`
/// is the ACTUAL salted mount subkey, so a remediation message can name what
/// was really mounted; it is empty when no offline mount was attempted.
struct HiveAccessReport {
    HiveAccessStatus status{HiveAccessStatus::not_found};
    bool mounted_offline{false};
    bool unload_failed{false};
    std::string mount_name;
};

/// Serialises the OFFLINE arm of with_user_hive across the whole process.
///
/// PrivilegeScope adjusts the PROCESS token, not a thread token. Once more
/// than one plugin in the agent uses this ladder -- autoruns, registry,
/// installed_apps, license_scan and tar all load into one process, and
/// tar's collectors run on background threads -- two overlapping scopes race:
///
///   A.ctor(prev=disabled) -> B.ctor(prev=enabled) -> A.dtor(restores
///   disabled) -> B's RegLoadKeyW fails
///
/// and the loser degrades SILENTLY into mount_failed/privilege_missing. This
/// mutex makes the privilege-enable -> RegLoadKeyW -> fn -> unload -> restore
/// sequence atomic with respect to other callers. It also serialises the
/// exclusive hive-FILE lock two offline readers of the same profile would
/// otherwise contend for. The offline path is already file-I/O bound, so the
/// serialisation costs nothing measurable; the LIVE path (the common case)
/// never takes the lock.
///
/// This is `yuzu::agent::offline_hive_mutex()` from
/// agents/core/include/yuzu/agent/offline_hive_mutex.hpp, NOT a header-local
/// static (code-review CFX-1). Each plugin is a SEPARATE .dll/.so; a
/// function-local static `inline` mutex defined here would be instantiated
/// once per plugin binary -- five independent mutexes, not one process-wide
/// lock, confirmed by inspecting each built plugin's export table (each
/// exports only its required `yuzu_plugin_descriptor` symbol). Defining it in
/// agents/core -- the one shared library every plugin links against -- and
/// exporting it via YUZU_EXPORT (the fork_lock.hpp precedent) makes every
/// plugin's import resolve to the same address in the same already-loaded
/// module.
using yuzu::agent::offline_hive_mutex;

// The live-hive-first, offline-mount-fallback ladder (C-1): tries
// HKU\<sid> first; only if that is absent does it enable
// SeBackup/SeRestore and mount `<profile_path>\NTUSER.DAT` under a private,
// per-call salted name via ScopedUserHive. Calls fn(root_hkey) with
// whichever root it found, exactly once, iff a root was reachable.
//
// `report`, if non-null, receives what happened -- including
// `unload_failed`, set (never cleared) when the offline mount's
// RegUnLoadKeyW fails on the way out, and the `mount_name` that failed to
// unload. Read it AFTER this call returns. The caller must surface a set
// flag rather than drop it: a failed unload leaves a system-wide mount that
// survives process death and locks the profile's NTUSER.DAT until it is
// unloaded or the host reboots (see win_reg_handle.hpp's ScopedUserHive
// doc comment for the common transient-holder case reboot isn't actually
// required for). yuzu::profiles::render_hive_access_lines turns a report
// into the operator-facing lines.
//
// Two residuals, recorded explicitly per code-review C-L4/C-L5 (the
// fork_lock.hpp precedent for stating a lock's own residual rather than
// letting a reader assume it is airtight):
// - `fn` runs under offline_hive_mutex() for the WHOLE offline arm (privilege
//   enable through unload) -- it must not re-enter this function (self-
//   deadlock, non-recursive mutex) and must not block for long, the same
//   discipline fork_lock.hpp asks of its own callers.
// - PrivilegeScope enables SeBackup/SeRestore on the PROCESS token, not a
//   thread token, so for the duration of an offline mount every thread in
//   the agent process technically has those privileges available (e.g. to
//   FILE_FLAG_BACKUP_SEMANTICS opens elsewhere) -- a strict improvement over
//   the pre-#2771 license_scan, which left them enabled for the rest of the
//   process, but a thread-token-scoped enable (ImpersonateSelf +
//   OpenThreadToken) would confine this further. Not done here.
template <typename Fn>
HiveAccessStatus with_user_hive(const std::string& sid, const std::string& profile_path_utf8,
                                Fn&& fn, HiveAccessReport* report = nullptr) {
    auto finish = [&](HiveAccessStatus st) {
        if (report)
            report->status = st;
        return st;
    };

    const std::wstring wsid = to_wide(sid);

    RegKey live;
    if (RegOpenKeyExW(HKEY_USERS, wsid.c_str(), 0, KEY_READ, live.put()) == ERROR_SUCCESS) {
        fn(live.get());
        return finish(HiveAccessStatus::ok);
    }

    if (profile_path_utf8.empty())
        return finish(HiveAccessStatus::not_found);

    // Everything below mutates process-token privilege state and takes an
    // exclusive lock on the hive file -- see offline_hive_mutex(). The
    // ScopedOfflineHiveLock wrapper logs wait/hold time -- see
    // offline_hive_mutex.hpp's INSTRUMENTATION note.
    const yuzu::agent::ScopedOfflineHiveLock offline_lock("with_user_hive");

    // R15: the offline-hive fallback rides SeBackupPrivilege/SeRestorePrivilege,
    // which the agent account already holds (docs/agent-privilege-model.md) --
    // this introduces no new privilege grant. Scoped to this function so both
    // privileges revert to their PRIOR token attributes once the offline
    // mount is no longer needed, rather than staying enabled for the rest of
    // the process.
    PrivilegeScope backup_priv(L"SeBackupPrivilege");
    PrivilegeScope restore_priv(L"SeRestorePrivilege");
    if (!backup_priv.ok() || !restore_priv.ok())
        return finish(HiveAccessStatus::privilege_missing);

    const std::wstring ntuser = to_wide(profile_path_utf8) + L"\\NTUSER.DAT";
    const std::wstring mount = unique_hive_mount_name(wsid);
    // Recorded BEFORE the mount is attempted, so a load failure still names
    // the mount the operator should check for.
    if (report) {
        report->mounted_offline = true;
        report->mount_name = from_wide(mount.c_str(), static_cast<int>(mount.size()));
    }

    bool unload_failed = false;
    bool called = false;
    {
        ScopedUserHive hive(mount, ntuser, &unload_failed);
        hive.with_root([&](HKEY root) {
            fn(root);
            called = true;
        });
    } // ScopedUserHive unloads here -- unload_failed is only final after this scope
    if (report)
        report->unload_failed = unload_failed;

    return finish(called ? HiveAccessStatus::ok : HiveAccessStatus::mount_failed);
}

/// Outcome of read_reg_value -- distinct from a plain bool so the caller can
/// report an honest reason instead of collapsing every failure into "not
/// found" (an oversized value and a genuinely absent one are different
/// facts and deserve different error text).
enum class ReadValueStatus {
    ok,        // out_value/out_type_name populated
    not_found, // the key or value does not exist
    oversized, // exists but exceeds kMaxRegValueBytes
    malformed, // exists with a declared numeric type but a size too small
              // for that type (e.g. a REG_DWORD value under 4 bytes)
    changed_during_read, // exists -- a concurrent writer grew it faster
                        // than the bounded retry could keep up. Distinct
                        // from not_found (#2771 code-review CODEX-P1-02):
                        // the value demonstrably EXISTS, it just could not
                        // be pinned down; reporting it as absent would be
                        // exactly the kind of dishonest collapse this
                        // function exists to avoid.
};

// Reads a single string/DWORD/QWORD/binary value under `root`, formatting it
// the same way registry_plugin.cpp's existing do_get_value does (hex-encode
// for anything else). On ok, fills `out_value` and `out_type_name`. Bounded
// to kMaxRegValueBytes.
inline ReadValueStatus read_reg_value(HKEY root, const std::string& value_name,
                                      std::string& out_value, std::string& out_type_name) {
    const std::wstring wname = to_wide(value_name);
    DWORD type = 0, size = 0;
    if (RegQueryValueExW(root, wname.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
        return ReadValueStatus::not_found;

    bool exceeds_cap = size > kMaxRegValueBytes;
    if (exceeds_cap)
        size = kMaxRegValueBytes;

    // #2771 code-review P2-N5: NEVER allocate a zero-length buffer here, even
    // when the value is genuinely empty (size==0). std::vector<BYTE>::data()
    // on an empty vector is permitted by the standard to return nullptr, and
    // passing lpData==nullptr to RegQueryValueExW switches it into SIZE-QUERY
    // mode regardless of what *lpcbData held -- so a value that is 0 bytes at
    // this exact instant but grows before Win32 processes the call would
    // silently succeed as a size query, leaving `data` at its original
    // (possibly zero) capacity while `size` is overwritten with the NEW,
    // larger real size -- and every switch branch below would then read
    // `size` bytes from a buffer that never held them: an out-of-bounds read,
    // not merely a wrong answer. Allocating at least 1 byte keeps
    // `data.data()` a real, non-null pointer, so Win32 takes the DATA-QUERY
    // path (an actually-too-small buffer) and correctly reports
    // ERROR_MORE_DATA -- routing this exact race through the SAME bounded
    // retry loop below, rather than needing a second, separate defence.
    std::vector<BYTE> data(size > 0 ? size : 1);
    DWORD buffer_capacity = static_cast<DWORD>(data.size());
    LSTATUS read_rc =
        RegQueryValueExW(root, wname.c_str(), nullptr, &type, data.data(), &buffer_capacity);
    size = buffer_capacity; // downstream code treats `size` as the real byte count

    // #2771 code-review CODEX-P1-02 (both rounds): a value that GROWS between
    // the size query and the data query (an ordinary race with a concurrent
    // writer, not exotic) also returns ERROR_MORE_DATA here even though the
    // size we last saw was under the cap -- treating that identically to
    // "the value was deleted" would report a value that demonstrably EXISTS
    // as `not_found`, contradicting this function's whole "distinguish
    // absence from failure" purpose. A single retry only narrows the race
    // window; it does not close it, so this is a BOUNDED LOOP -- if the
    // value is still racing us after kMaxGrowthRetries consecutive attempts,
    // that is reported as its own honest outcome (changed_during_read)
    // rather than silently reusing not_found/oversized for a value we never
    // established either fact about.
    constexpr int kMaxGrowthRetries = 3;
    for (int attempt = 0; read_rc == ERROR_MORE_DATA && !exceeds_cap && attempt < kMaxGrowthRetries;
        ++attempt) {
        DWORD fresh_size = 0;
        if (RegQueryValueExW(root, wname.c_str(), nullptr, &type, nullptr, &fresh_size) !=
            ERROR_SUCCESS) {
            read_rc = ERROR_FILE_NOT_FOUND; // genuinely gone by this retry
            break;
        }
        exceeds_cap = fresh_size > kMaxRegValueBytes;
        size = exceeds_cap ? kMaxRegValueBytes : fresh_size;
        // Same zero-length guard as the first call (P2-N5) -- the value may
        // have shrunk back to empty by this retry.
        data.assign(size > 0 ? size : 1, BYTE{0});
        buffer_capacity = static_cast<DWORD>(data.size());
        read_rc =
            RegQueryValueExW(root, wname.c_str(), nullptr, &type, data.data(), &buffer_capacity);
        size = buffer_capacity;
    }
    if (read_rc == ERROR_MORE_DATA && !exceeds_cap) {
        // Retries exhausted and the value is STILL racing us -- honest
        // "could not pin down", not a claim of absence.
        return ReadValueStatus::changed_during_read;
    }
    if (read_rc != ERROR_SUCCESS) {
        // A capped buffer that was too small for the real value surfaces
        // here as ERROR_MORE_DATA -- an honestly oversized value, not a
        // missing one. Any other failure at this point is a genuine miss
        // (e.g. the value was deleted between the two queries).
        return exceeds_cap ? ReadValueStatus::oversized : ReadValueStatus::not_found;
    }

    switch (type) {
    case REG_SZ:
    case REG_EXPAND_SZ:
        out_value = reg_sz_to_utf8(reinterpret_cast<const wchar_t*>(data.data()), size);
        out_type_name = (type == REG_SZ) ? "REG_SZ" : "REG_EXPAND_SZ";
        break;
    case REG_DWORD: {
        if (size < sizeof(DWORD))
            return ReadValueStatus::malformed;
        DWORD v = 0;
        std::memcpy(&v, data.data(), sizeof(v));
        out_value = std::to_string(v);
        out_type_name = "REG_DWORD";
        break;
    }
    case REG_QWORD: {
        if (size < sizeof(std::uint64_t))
            return ReadValueStatus::malformed;
        std::uint64_t v = 0;
        std::memcpy(&v, data.data(), sizeof(v));
        out_value = std::to_string(v);
        out_type_name = "REG_QWORD";
        break;
    }
    case REG_MULTI_SZ: {
        // #2771 up-S3: a double-NUL-terminated list of strings used to fall
        // into the hex dump below, so a PATH-like value came back as an
        // unreadable blob. Records are joined with ';' and each is
        // sanitised -- a record containing '|' or a newline would otherwise
        // forge a column or row in the pipe protocol, and the multi-record
        // shape makes that materially more likely than for a scalar string.
        // Both the ';' join and the sanitisation are lossy for records that
        // themselves contain those characters; that is documented in the
        // operator error/type taxonomy rather than silently accepted.
        static_assert(sizeof(wchar_t) == sizeof(char16_t),
                      "REG_MULTI_SZ decoding assumes UTF-16 wchar_t (Windows)");
        // reinterpret_cast justification (code-review Standards S7, revised
        // twice per CODEX-P1-03 rounds 1 and 2 -- alignment AND object
        // lifetime, the two distinct questions a cast like this raises):
        //
        // Alignment: std::vector<BYTE>'s default allocator calls
        // operator new(size_t), which the standard guarantees returns
        // storage suitably aligned for any object of that size or smaller
        // ([basic.stc.dynamic.allocation]) -- the guarantee is SIZE-
        // dependent, not unconditional, but any allocation large enough to
        // hold a char16_t is therefore large enough to be guaranteed
        // alignof(char16_t)-aligned; RegQueryValueExW's actual REG_MULTI_SZ
        // payload always is. Empirically confirmed (20 trials, odd and even
        // sizes, always max_align_t-aligned in practice, consistent with the
        // guarantee). Win32 itself has no say either way -- it only knows it
        // was handed an LPBYTE.
        //
        // Object lifetime: reading BYTE-typed storage through a char16_t*
        // without an explicit lifetime-starting operation (placement-new,
        // std::start_lifetime_as, memcpy) is the real question C++'s object
        // model raises, separate from alignment. Since C++20's implicit
        // object creation for low-level storage manipulation ([intro.object]
        // p10-11, P0593), allocating storage via operator new implicitly
        // creates objects of implicit-lifetime type (char16_t, a scalar
        // type, qualifies) as needed to give the program defined behaviour --
        // this is precisely the rule that makes malloc/operator-new-backed
        // reinterpret_cast idioms well-defined in C++20/23, which is the
        // standard this codebase targets (CLAUDE.md: C++23).
        //
        // Read-only (const), no ownership transfer -- `chars` borrows
        // `data`'s lifetime for this function's duration only. Same cast
        // shape as the pre-existing, UNCHANGED REG_SZ branch two cases
        // above -- not a new risk profile this PR introduces, and not
        // something this PR's scope extends to fixing project-wide.
        const auto* chars = reinterpret_cast<const char16_t*>(data.data());
        const std::size_t nch = size / sizeof(wchar_t);
        out_value.clear();
        bool first = true;
        for (const auto& [off, len] :
             yuzu::profiles::multi_sz_records(std::span<const char16_t>(chars, nch))) {
            if (!first)
                out_value += ';';
            first = false;
            out_value += yuzu::profiles::sanitize_field(from_wide(
                reinterpret_cast<const wchar_t*>(chars + off), static_cast<int>(len)));
        }
        out_type_name = "REG_MULTI_SZ";
        break;
    }
    case REG_LINK:
        // A symbolic-link target: a string, not opaque bytes. Sanitised
        // (#2771 code-review CODEX-P1-01): before this PR, REG_LINK fell
        // into the hex-dump default branch below, which is inert against
        // pipe/newline injection by construction. Decoding it as a raw
        // string is what makes injection reachable here for the first
        // time, so it gets the same treatment as REG_MULTI_SZ's records --
        // a target containing '|' or a newline cannot forge a column or
        // row in the output protocol.
        out_value = yuzu::profiles::sanitize_field(
            reg_sz_to_utf8(reinterpret_cast<const wchar_t*>(data.data()), size));
        out_type_name = "REG_LINK";
        break;
    default:
        // REG_NONE, REG_BINARY, REG_DWORD_BIG_ENDIAN and anything unknown
        // stay hex — but are now NAMED honestly by the shared table rather
        // than collapsed into REG_BINARY/REG_UNKNOWN.
        out_value = yuzu::profiles::hex_encode(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.data()), size));
        out_type_name = yuzu::profiles::reg_type_name(static_cast<std::uint32_t>(type));
        break;
    }
    return ReadValueStatus::ok;
}

} // namespace yuzu::win

#endif // _WIN32
