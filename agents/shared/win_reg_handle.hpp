// win_reg_handle.hpp -- RAII owners for HKEY and RegLoadKeyW-mounted hives.
//
// Canonical home for the HKEY-RAII pattern (PR1.7). Originally eight
// independent copies of this shape existed across the tree (three
// HiveUnloadGuard-class mount/unload owners, three plain-HKEY closers, and
// two .put()-style wrappers, enumerated below); #2771 swept the
// three HiveUnloadGuard copies feeding the per-user hive ladder specifically
// (licensing_win.cpp's, installed_apps_plugin.cpp's, tar_mapdrive_collector
// .cpp's -- all deleted, replaced by ScopedUserHive) onto this header. Their
// sibling plain-HKEY closers remain as local types in three of those same
// files (licensing_win.cpp's HKeyCloser, installed_apps_plugin.cpp's
// function-local HKeyCloser, tar_mapdrive_collector.cpp's RegKeyGuard) --
// they are still used for OTHER (non-hive-mount) opens in those files, e.g.
// enumerate_uninstall_key, WinRegProbeHost, MRU/network-drive reads, and
// were out of this PR's scope. rdp_control_plugin.cpp's and
// tar_software_collector.cpp's .put()-style wrappers are likewise untouched.
// Sweeping any of these remaining copies onto RegKey is a separate
// follow-up, matching the win_sc_handle.hpp (#1822) precedent's own note
// about win_str.hpp/#1681.
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

#include <atomic>
#include <cstdint>
#include <random>
#include <string>
#include <utility>

namespace yuzu::win {

/// A process-unique HKEY_USERS mount name for `sid`, of the shape
/// `YUZU_HIVE_<sid>_<16 hex>_<n>`.
///
/// Salt scheme mirrors agents/core/src/agent_csr.cpp's random_suffix(): a
/// one-time random_device base (seeded once, no per-call fd churn) XORed with
/// a monotonic atomic counter — unique within the process, unpredictable
/// across processes, and not solely dependent on random_device entropy, which
/// degrades on some virtualised hosts. Deliberately NOT salted with a clock
/// or a thread id (CLAUDE.md standing rule; flake #473). The tests-only
/// yuzu::test::process_random_salt() is not reachable from agents/shared/, so
/// the idiom is mirrored rather than shared.
///
/// WHAT THIS FIXES, precisely (#2771 up-S1): two callers can no longer ALIAS
/// each other's mount, one caller's unload can no longer yank the hive out
/// from under another's open handles, and a crashed process's stale mount no
/// longer poisons a fixed name forever.
///
/// WHAT IT DOES NOT FIX ON ITS OWN: RegLoadKeyW opens the hive FILE with
/// exclusive access, so this salt alone would not let two concurrent
/// OFFLINE reads of the same logged-out profile both succeed -- the loser
/// would fail with ERROR_SHARING_VIOLATION instead of a name collision, a
/// different error, not a working read. That race IS closed, but by
/// with_user_hive's offline_hive_mutex (win_profiles.hpp), NOT by this
/// salt -- the mutex serialises the whole offline arm process-wide, so a
/// second in-process caller queues and then succeeds rather than racing
/// the file lock at all (#2771 code-review CODEX-P1-04). The residual this
/// salt-plus-mutex pair does NOT reach is a mount from OUTSIDE this
/// process -- a second agent instance, or an external `reg load` -- which
/// still contends for the same exclusive file lock unguarded.
[[nodiscard]] inline std::wstring unique_hive_mount_name(std::wstring_view sid) {
    static constexpr wchar_t kHex[] = L"0123456789abcdef";
    static const std::uint64_t base = [] {
        std::random_device rd;
        return (static_cast<std::uint64_t>(rd()) << 32) ^ rd();
    }();
    static std::atomic<std::uint64_t> counter{0};

    const std::uint64_t n = counter.fetch_add(1, std::memory_order_relaxed);
    std::uint64_t v = base ^ n;

    std::wstring out = L"YUZU_HIVE_";
    out += sid;
    out += L'_';
    for (int i = 0; i < 16; ++i) {
        out += kHex[v & 0xF];
        v >>= 4;
    }
    out += L'_';
    out += std::to_wstring(n);
    return out;
}

// RAII owner for a HKEY obtained from RegOpenKeyExW / RegCreateKeyExW /
// RegLoadKeyW's mount root. Closes via RegCloseKey on destruction.
// Non-copyable (copying would double-close); movable. Never wrap a
// predefined constant (HKEY_LOCAL_MACHINE, HKEY_USERS, ...) in this type --
// those are not owned handles and RegCloseKey on one is a no-op that masks
// a real bug if ever passed here by mistake.
class RegKey {
public:
    RegKey() = default;
    explicit RegKey(HKEY h) noexcept : h_(h) {}
    ~RegKey() { reset(); }

    RegKey(const RegKey&) = delete;
    RegKey& operator=(const RegKey&) = delete;

    RegKey(RegKey&& other) noexcept : h_(other.h_) { other.h_ = nullptr; }
    RegKey& operator=(RegKey&& other) noexcept {
        if (this != &other) {
            reset();
            h_ = other.h_;
            other.h_ = nullptr;
        }
        return *this;
    }

    void reset(HKEY h = nullptr) noexcept {
        if (h_ && h_ != h)
            RegCloseKey(h_);
        h_ = h;
    }

    [[nodiscard]] HKEY get() const noexcept { return h_; }

    /// Out-param target for RegOpenKeyExW / RegCreateKeyExW. Closes any
    /// handle this instance already owns first, so reusing a RegKey for a
    /// second open can never leak the handle it is about to overwrite.
    [[nodiscard]] HKEY* put() noexcept {
        reset();
        return &h_;
    }

    explicit operator bool() const noexcept { return h_ != nullptr; }

private:
    HKEY h_{nullptr};
};

// A private, process-scoped RegLoadKeyW mount of an offline hive file (e.g.
// a profile's NTUSER.DAT) under HKEY_USERS, unloaded on destruction.
//
// A leaked mount is SYSTEM-WIDE, survives process death, and locks the
// source file until it is unloaded or the host reboots -- most commonly a
// transient third-party handle (Search Indexer, AV, System Restore) into the
// mounted branch, recoverable without reboot once that holder releases; a
// genuinely stuck holder is the rarer case reboot actually resolves:
// installed_apps_plugin.cpp:165-166, licensing_win.cpp:70-104, and
// tar_mapdrive_collector.cpp each independently hit and documented exactly
// this failure mode. with_root() is the only
// sanctioned way to read the mounted hive through this type: it hands the
// caller a borrowed HKEY for the duration of one callback and closes that
// handle before returning, so a handle into the mount cannot accidentally
// outlive the mount -- there is no other way to obtain one.
//
// Callers should derive `mount_name` from unique_hive_mount_name() rather
// than a fixed string, so two callers cannot alias one another's mount.
// Within this agent process, `with_user_hive` (win_profiles.hpp) additionally
// serialises the whole offline arm through offline_hive_mutex(), so two
// in-process callers targeting the same profile queue rather than race the
// exclusive hive-file lock -- see that function's note and
// unique_hive_mount_name()'s doc comment for the residual this pair does
// NOT reach (a mount from outside this process).
class ScopedUserHive {
public:
    /// Attempts RegLoadKeyW(HKEY_USERS, mount_name, hive_file_path) immediately.
    /// `unload_failed`, if non-null, is set (never cleared) when
    /// RegUnLoadKeyW fails in the destructor -- read it AFTER this guard
    /// goes out of scope, since a destructor cannot throw or return a status
    /// (the same constraint licensing_win.cpp's now-retired HiveUnloadGuard
    /// -- one of the three #2771 swept onto this type -- was built around).
    ScopedUserHive(std::wstring mount_name, const std::wstring& hive_file_path,
                   bool* unload_failed = nullptr)
        : mount_name_(std::move(mount_name)), unload_failed_(unload_failed) {
        loaded_ = (RegLoadKeyW(HKEY_USERS, mount_name_.c_str(), hive_file_path.c_str()) ==
                   ERROR_SUCCESS);
    }

    ~ScopedUserHive() {
        if (loaded_ && RegUnLoadKeyW(HKEY_USERS, mount_name_.c_str()) != ERROR_SUCCESS &&
            unload_failed_)
            *unload_failed_ = true;
    }

    ScopedUserHive(const ScopedUserHive&) = delete;
    ScopedUserHive& operator=(const ScopedUserHive&) = delete;
    ScopedUserHive(ScopedUserHive&&) = delete;
    ScopedUserHive& operator=(ScopedUserHive&&) = delete;

    /// True iff RegLoadKeyW succeeded. with_root() is a no-op (returns
    /// false) when this is false.
    [[nodiscard]] bool ok() const noexcept { return loaded_; }

    /// Opens the mount's root key, calls fn(root), and closes the root --
    /// all synchronously, before returning -- so no handle into the mount
    /// survives past this call. Returns false without calling fn if the
    /// mount never loaded or the root could not be (re-)opened.
    template <typename Fn>
    bool with_root(Fn&& fn) {
        if (!loaded_)
            return false;
        RegKey root;
        if (RegOpenKeyExW(HKEY_USERS, mount_name_.c_str(), 0, KEY_READ, root.put()) !=
            ERROR_SUCCESS)
            return false;
        fn(root.get());
        return true;
    }

private:
    std::wstring mount_name_;
    bool* unload_failed_{nullptr};
    bool loaded_{false};
};

} // namespace yuzu::win

#endif // _WIN32
