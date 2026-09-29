/**
 * execution_artifacts_win.cpp — Windows leg entry points for the
 * execution_artifacts plugin (ShimCache, Amcache InventoryApplicationFile,
 * Prefetch). Implements the three declarations in execution_artifacts_legs.hpp
 * (P31); every parser this file calls into is the pure, OS-free
 * execution_artifacts_parsers.hpp — this TU owns ONLY the Win32 I/O that
 * gathers the raw bytes those parsers consume.
 *
 * A1's the-rig probe findings (2026-09-06,
 * tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md), quoted
 * verbatim for the two probes this package's legs consume (its third probe,
 * ITaskService/WMI, belongs to the autoruns package and is not used here):
 *
 * PROBE 1 (RtlDecompressBufferEx / MAM prefetch decompression) — "GetProc-
 * Address(GetModuleHandleW(L"ntdll"), "RtlGetCompressionWorkSpaceSize") and
 * "RtlDecompressBufferEx" both resolved to non-null addresses in every run
 * (admin and LocalSystem). ... All four decompression attempts returned
 * STATUS_SUCCESS (0x00000000) for both RtlGetCompressionWorkSpaceSize
 * (workspace size 166495 bytes in every case, format
 * COMPRESSION_FORMAT_XPRESS_HUFF = 4, engine standard) and
 * RtlDecompressBufferEx. Every decompressed payload's bytes 4-7 read 'SCCA'
 * as expected for a valid prefetch header."
 *
 * PROBE 2 (RegLoadAppKeyW / Amcache.hve) — "Copy-Item of
 * C:\Windows\appcompat\Programs\Amcache.hve succeeded as a plain copy in the
 * admin session (SeBackupPrivilege already Enabled) -- no sharing violation
 * was hit, so the CreateFile(FILE_SHARE_READ|WRITE|DELETE,
 * FILE_FLAG_BACKUP_SEMANTICS) + SeBackupPrivilege fallback path was never
 * exercised; it was not needed to obtain the copy. ... Key finding for
 * P32's locking design: RegLoadAppKeyW does NOT require SeBackupPrivilege.
 * It succeeded (LSTATUS 0x00000000 / ERROR_SUCCESS) with the privilege
 * explicitly disabled via AdjustTokenPrivileges, in both the admin session
 * and under LocalSystem. RegLoadAppKeyW loads a private, process-scoped
 * hive copy and does not go through the backup/restore privilege check that
 * RegLoadKey/RegRestoreKey do." (8889 real InventoryApplicationFile subkeys
 * in every one of the four probe runs.)
 *
 * Consequences for this file's design:
 *   - The Amcache copy tries plain CopyFileW FIRST; the SeBackupPrivilege +
 *     CreateFileW(FILE_FLAG_BACKUP_SEMANTICS) fallback is dead code on
 *     probe-representative hardware (unexercised there) but is kept for a
 *     host where the hive genuinely is exclusively locked (this package's
 *     spec: "not guaranteed on every host").
 *   - RegLoadAppKeyW itself never needs a PrivilegeScope.
 *
 * HOLD-TIME BOUND (acceptance criterion): collect_amcache's single
 * yuzu::agent::ScopedOfflineHiveLock("execution_artifacts") hold spans
 * PrivilegeScope construction (only taken on the ERROR_SHARING_VIOLATION
 * fallback path) through the copy, RegLoadAppKeyW, enumeration (capped at
 * kAmcacheMaxSubkeys = 20000 registry reads, each itself bounded by
 * win_profiles.hpp's kMaxRegValueBytes = 1 MiB), and RegCloseKey. Every step
 * in that span is bounded LOCAL disk/registry I/O (copy capped at
 * kAmcacheMaxBytes = 256 MiB) — never network, never user input — so the
 * hold time is bounded by those caps, not open-ended. The scratch
 * directory's own creation/verification and its later removal both run
 * OUTSIDE this lock (see SCRATCH DIRECTORY below) — neither is
 * privilege-bearing, so neither belongs inside the hold this bound
 * describes. offline_hive_mutex.hpp's own banner documents this as the
 * sixth plugin calling the shared lock directly (the other five go through
 * with_user_hive()).
 *
 * PROCESS-TOKEN DISCIPLINE (win_profiles.hpp:416-432): PrivilegeScope mutates
 * the PROCESS token, so this file follows with_user_hive's own discipline
 * (win_profiles.hpp:479-535) exactly — the privilege-bearing sequence is
 * fully nested inside ONE ScopedOfflineHiveLock, never split across two.
 *
 * SCRATCH DIRECTORY: collect_amcache stages the raw hive copy in a
 * per-dispatch directory created by yuzu_create_temp_dir() (temp_file.cpp)
 * under the operator-configured agent.data_dir — a 128-bit crypto-random
 * name, CREATE_NEW semantics (never reused), owner-only DACL, removed on
 * scope exit by this file's own ScratchDirGuard. An earlier revision of
 * this file instead reused ONE fixed path across dispatches and hand-rolled
 * a DACL-verification step to guard against a pre-planted directory; that
 * verifier could never pass (the owner-only SDDL it authored, D:P(A;;GA;;;OW),
 * stores the literal SDDL_OWNER_RIGHTS alias S-1-3-4 in the DACL — Windows
 * substitutes CREATOR_OWNER (CO) into the real owner's SID, but never does
 * that for Owner Rights (OW) — so the verifier's SID-equality checks matched
 * nothing and the action was permanently `constrained|dest_dir_acl` on
 * every real install). A random, never-reused directory needs no such
 * verifier: there is nothing to pre-plant a name for.
 *
 * ShimCache's local blob reader mirrors read_reg_value's size-then-fill +
 * changed_during_read bounded-retry idiom (win_profiles.hpp:560-620) at a
 * LOCAL 16 MiB cap — win_profiles.hpp's own kMaxRegValueBytes (1 MiB,
 * win_profiles.hpp:61) is a SHARED constant other callers rely on staying at
 * 1 MiB and is never raised here.
 *
 * Every entry point is wrapped in try/catch(...) -> constrained|internal_error
 * (this package's spec) since std::bad_alloc/std::length_error are always
 * possible around the untrusted-size-driven allocations below, even though
 * every size that reaches an allocation is bounds-checked first.
 *
 * Never emits file contents, never touches Layout.ini (the Prefetch
 * enumeration globs *.pf only), no VSS/esentutl/spawn.
 */

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h> // NTSTATUS (confined_fs_win.cpp precedent)

#include <win_profiles.hpp> // RegKey, PrivilegeScope, offline_hive_mutex, read_reg_value,
                            // enumerate_value_names, to_wide/from_wide

#include "execution_artifacts_legs.hpp" // also pulls in <yuzu/plugin.hpp> -- yuzu_create_temp_dir
#include "execution_artifacts_parsers.hpp"
#include "execution_artifacts_scratch_identity.hpp" // detail::scratch_dir_is_ours (A1: hoisted, also used by the sweep)

#include <constraint_accumulator.hpp>
#include <yuzu/agent/offline_hive_mutex.hpp> // ScopedOfflineHiveLock
#include <yuzu/string_utils.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <format>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace yuzu::execution_artifacts {

namespace {

// ── shared helpers ──────────────────────────────────────────────────────

/// Writes a `constrained|<token>` row, sets the CC-07 typed status, and
/// returns the leg's exit code for that status (1 — the legs.hpp contract:
/// 0 only on YUZU_RESULT_STATUS_OK).
int emit_constrained(yuzu::CommandContext& ctx, const std::string& token) {
    ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL, token);
    ctx.write_output("constrained|" + token);
    return 1;
}

std::string ntstatus_token(NTSTATUS status) {
    return std::format("ntstatus_{:x}", static_cast<uint32_t>(status));
}

/// Classifies a Win32 GetLastError() value from an Amcache hive copy
/// attempt into a diagnostic token, mirroring ShimCache's reg_<code> and
/// Prefetch's ntstatus_<hex> conventions in this same file. Only
/// ERROR_SHARING_VIOLATION maps to "hive_locked" -- every other failure
/// (disk full, access denied, bad path, etc.) gets its own win32_<code>
/// token so an operator isn't sent down the "it's locked" runbook for an
/// unrelated fault.
std::string amcache_copy_error_token(DWORD err) {
    if (err == ERROR_SHARING_VIOLATION)
        return "hive_locked";
    return "win32_" + std::to_string(err);
}

// Single-owner RAII for a Win32 HANDLE, released via `CloseFn` on
// destruction/move/reset. Both `nullptr` and `INVALID_HANDLE_VALUE` are
// treated as "empty" -- CreateFileW's failure sentinel is the latter, not
// the former, and every raw HANDLE in this file (the AmCache backup-copy
// src/dst, the Prefetch find handle, the per-file read handle) previously
// relied on a hand-matched CloseHandle/FindClose on every return path, which
// is exactly the shape that leaks on an exception thrown between open and
// close (this file's own header banner: parsers can throw std::bad_alloc on
// an untrusted size). Mirrors agents/core/src/guard_win_handle.hpp's
// ScopedWinHandle shape -- that header is core-internal and not on this
// plugin's include path, so this is a local specialisation rather than a
// cross-module include, same precedent as tar_netconn_win.cpp's EvtGuard.
template <void (*CloseFn)(HANDLE)>
class ScopedWinHandle {
public:
    ScopedWinHandle() = default;
    explicit ScopedWinHandle(HANDLE h) : h_(norm(h)) {}
    ~ScopedWinHandle() { reset(); }

    ScopedWinHandle(const ScopedWinHandle&) = delete;
    ScopedWinHandle& operator=(const ScopedWinHandle&) = delete;
    ScopedWinHandle(ScopedWinHandle&& other) noexcept : h_(other.h_) { other.h_ = nullptr; }
    ScopedWinHandle& operator=(ScopedWinHandle&& other) noexcept {
        if (this != &other) {
            reset();
            h_ = other.h_;
            other.h_ = nullptr;
        }
        return *this;
    }

    HANDLE get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }
    void reset(HANDLE h = nullptr) {
        if (h_)
            CloseFn(h_);
        h_ = norm(h);
    }

private:
    static HANDLE norm(HANDLE h) {
        return (h == nullptr || h == INVALID_HANDLE_VALUE) ? nullptr : h;
    }
    HANDLE h_ = nullptr;
};

inline void close_handle_(HANDLE h) { ::CloseHandle(h); }
inline void find_close_(HANDLE h) { ::FindClose(h); }

using ScopedHandle = ScopedWinHandle<&close_handle_>;     ///< CreateFileW
using ScopedFindHandle = ScopedWinHandle<&find_close_>;   ///< FindFirstFileW

// ── ShimCache ────────────────────────────────────────────────────────────

constexpr wchar_t kShimCacheSubkey[] =
    L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache";
constexpr wchar_t kShimCacheValueName[] = L"AppCompatCache";

// LOCAL bound, deliberately distinct from win_profiles.hpp's shared
// kMaxRegValueBytes (1 MiB, win_profiles.hpp:61) -- ShimCache blobs are
// legitimately larger than the general-purpose registry-value cap that
// constant protects, and raising the shared constant would loosen every
// other caller of read_reg_value in the tree. See this package's spec.
constexpr DWORD kShimCacheMaxBytes = 16u * 1024u * 1024u; // 16 MiB

enum class ShimBlobStatus { ok, not_found, oversized, changed_during_read };

/// Reads the AppCompatCache value under `key`, bounded at kShimCacheMaxBytes.
/// Same size-then-fill + bounded-growth-retry idiom as win_profiles.hpp's
/// read_reg_value (win_profiles.hpp:560-620), reimplemented locally rather
/// than reusing that function because the cap differs (16 MiB here vs its
/// shared 1 MiB) and read_reg_value's cap is not a parameter. `out_rc`
/// carries the last LSTATUS seen, for the not_found case's `reg_<status>`
/// token.
ShimBlobStatus read_shimcache_blob(HKEY key, std::vector<uint8_t>& out, LSTATUS& out_rc) {
    DWORD type = 0, size = 0;
    out_rc = RegQueryValueExW(key, kShimCacheValueName, nullptr, &type, nullptr, &size);
    if (out_rc != ERROR_SUCCESS)
        return ShimBlobStatus::not_found;

    bool exceeds_cap = size > kShimCacheMaxBytes;
    if (exceeds_cap)
        size = kShimCacheMaxBytes;

    // Never a zero-length allocation (win_profiles.hpp P2-N5): an empty
    // data() pointer would switch RegQueryValueExW into size-query mode
    // regardless of *lpcbData, misreading a value that grew concurrently.
    std::vector<BYTE> data(size > 0 ? size : 1);
    DWORD capacity = static_cast<DWORD>(data.size());
    LSTATUS read_rc =
        RegQueryValueExW(key, kShimCacheValueName, nullptr, &type, data.data(), &capacity);
    size = capacity;

    constexpr int kMaxGrowthRetries = 3;
    for (int attempt = 0; read_rc == ERROR_MORE_DATA && !exceeds_cap && attempt < kMaxGrowthRetries;
        ++attempt) {
        DWORD fresh_size = 0;
        if (RegQueryValueExW(key, kShimCacheValueName, nullptr, &type, nullptr, &fresh_size) !=
            ERROR_SUCCESS) {
            read_rc = ERROR_FILE_NOT_FOUND;
            break;
        }
        exceeds_cap = fresh_size > kShimCacheMaxBytes;
        size = exceeds_cap ? kShimCacheMaxBytes : fresh_size;
        data.assign(size > 0 ? size : 1, BYTE{0});
        capacity = static_cast<DWORD>(data.size());
        read_rc =
            RegQueryValueExW(key, kShimCacheValueName, nullptr, &type, data.data(), &capacity);
        size = capacity;
    }
    out_rc = read_rc;
    if (read_rc == ERROR_MORE_DATA && !exceeds_cap)
        return ShimBlobStatus::changed_during_read;
    if (read_rc != ERROR_SUCCESS)
        return exceeds_cap ? ShimBlobStatus::oversized : ShimBlobStatus::not_found;

    out.assign(data.begin(), data.begin() + size);
    return ShimBlobStatus::ok;
}

// ── Amcache ──────────────────────────────────────────────────────────────

constexpr wchar_t kAmcacheSourceHve[] = L"C:\\Windows\\appcompat\\Programs\\Amcache.hve";
constexpr uint64_t kAmcacheMaxBytes = 256ull * 1024 * 1024; // 256 MiB
constexpr DWORD kAmcacheMaxSubkeys = 20000;

/// Process-wide count of persistent scratch-directory cleanup failures
/// (e.g. an AV lock holding a file open past this action's own lifetime)
/// across every ScratchDirGuard instance in this plugin process. There is
/// no cap or alert path on the underlying accumulation -- that residual is
/// unchanged from this file's earlier per-file TempHiveCleanup -- but a
/// repeated failure is now at least observable via this counter's value in
/// the log line below, rather than each occurrence being an isolated,
/// uncorrelated `note|` row with no way to tell "happened once" from
/// "happening every run".
std::atomic<uint64_t> g_temp_cleanup_failed_total{0};

/// RAII owner of a per-dispatch scratch directory created by
/// yuzu_create_temp_dir() (temp_file.cpp): removes the directory and
/// everything in it (the raw hive copy, its .LOG1/.LOG2 sidecars, and
/// anything else this leg or RegLoadAppKeyW placed there) on scope exit,
/// regardless of which return path collect_amcache takes (this package's
/// spec: "temp copies always deleted (scope guard)"). A removal failure is
/// logged via a `note|` row, never silently dropped, but never fails the
/// action itself -- the action's own result was already decided by the
/// time cleanup runs.
///
/// Deliberately NOT yuzu::TempDir (sdk/include/yuzu/plugin.hpp): that
/// class's destructor calls std::filesystem::remove_all on a NARROW
/// std::string, which std::filesystem decodes via the ANSI code page on
/// MSVC -- but yuzu_create_temp_dir itself writes the path back as UTF-8
/// (temp_file.cpp's wide_to_utf8). A non-ASCII agent.data_dir would then
/// silently fail to resolve the real path and leak the raw hive with no
/// diagnostic. This guard instead keeps the path as a std::wstring (built
/// once, immediately after creation, via yuzu::win::to_wide on the UTF-8
/// buffer) and removes it through std::filesystem::path's wide-native
/// constructor, which never round-trips through a narrow encoding.
///
/// MUST be declared BEFORE the scratch-directory HANDLE and BEFORE the
/// offline-hive lock in collect_amcache -- see scratch_dir_is_ours's banner
/// for why: RemoveDirectoryW (what remove_all uses internally) fails with
/// ERROR_SHARING_VIOLATION while a HANDLE without FILE_SHARE_DELETE is
/// still open on the directory, so that handle must close (destruct)
/// before this guard's destructor runs. Declared before the lock too so
/// removal -- itself not privilege-bearing -- never happens while the
/// shared offline_hive_mutex is held (reverse-declaration-order
/// destruction: the lock releases, then the handle closes, then this
/// guard removes the directory).
class ScratchDirGuard {
public:
    ScratchDirGuard(yuzu::CommandContext& ctx, std::wstring path)
        : ctx_(ctx), path_(std::move(path)) {}

    ScratchDirGuard(const ScratchDirGuard&) = delete;
    ScratchDirGuard& operator=(const ScratchDirGuard&) = delete;

    const std::wstring& path() const { return path_; }

    ~ScratchDirGuard() {
        std::error_code ec;
        std::filesystem::remove_all(std::filesystem::path{path_}, ec);
        if (ec) {
            const uint64_t total =
                g_temp_cleanup_failed_total.fetch_add(1, std::memory_order_relaxed) + 1;
            // Diagnostics (allocation inside write_output/spdlog) must
            // never be allowed to throw out of a destructor -- that would
            // call std::terminate and kill the agent process mid-unwind,
            // losing every remaining cleanup and the in-flight result this
            // destructor was trying to report around. The removal attempt
            // and failure counter above are unconditional; only the
            // diagnostic emission itself is best-effort.
            try {
                ctx_.write_output("note|temp_cleanup_failed");
                spdlog::warn("execution_artifacts: scratch directory cleanup failed ({} total "
                             "this process)",
                             total);
            } catch (...) {
            }
        }
    }

private:
    yuzu::CommandContext& ctx_;
    std::wstring path_;
};

/// Opens `dir` (a just-created scratch directory) as a HANDLE, without
/// FILE_SHARE_DELETE -- this is what makes the verify-then-use sequence in
/// collect_amcache race-free rather than just re-checked-and-still-racy: as
/// long as this handle stays open, Windows itself refuses any delete or
/// rename of the underlying directory OBJECT (ERROR_SHARING_VIOLATION to
/// the would-be deleter), so the object scratch_dir_is_ours() verifies
/// below is PROVABLY the same object the raw hive is later copied into.
///
/// DELETE is REQUESTED (never exercised -- this handle only ever reads
/// attributes) specifically so this handle counts as one of the object's
/// "Deleters" in Windows' own share-access bookkeeping (IoCheckShareAccess's
/// per-object SHARE_ACCESS counters). Confirmed empirically on real
/// Windows/MSVC (governance's own DELETE-access gate-fix -- see
/// execution_artifacts_scratch_sweep_win.cpp's open_candidate_relative
/// banner -- was verified on this exact handle shape and found NOT
/// sufficient on its own): a handle whose DesiredAccess never claims DELETE
/// is never counted as a Deleter regardless of its ShareMode, so a LATER
/// opener that itself requests DELETE is never blocked by this handle's
/// lack of FILE_SHARE_DELETE -- the sharing violation this banner's own
/// prior revision claimed only fires once THIS side also claims DELETE.
/// FILE_FLAG_OPEN_REPARSE_POINT opens a junction/symlink AS the reparse
/// point itself rather than following it, so the reparse check below sees
/// the object actually being opened, never its target.
ScopedHandle open_scratch_dir_handle(const std::wstring& dir) {
    return ScopedHandle(CreateFileW(
        dir.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
}

/// The ERROR_SHARING_VIOLATION fallback: SeBackupPrivilege + backup-semantics
/// read, chunked into `dest`. Unexercised on A1's probe host (plain CopyFileW
/// always sufficed there — see the file banner) but kept for a host where the
/// hive genuinely is exclusively held elsewhere. Returns a token naming the
/// failure on any error; empty string on success.
std::string copy_amcache_via_backup_semantics(const wchar_t* dest) {
    // Kept inside the SAME offline_hive_mutex hold the caller already took --
    // this function is only ever called from inside that lock_guard's scope.
    yuzu::win::PrivilegeScope backup_priv(L"SeBackupPrivilege");
    (void)backup_priv; // ok() is not gated on -- CreateFileW below is the real test;
                       // a host that does not need the privilege for this
                       // particular file (probe finding) still benefits from a
                       // best-effort enable.

    ScopedHandle src(CreateFileW(kAmcacheSourceHve, GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                  OPEN_EXISTING,
                                  FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!src)
        return amcache_copy_error_token(GetLastError());

    ScopedHandle dst(CreateFileW(dest, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!dst)
        return amcache_copy_error_token(GetLastError());

    std::vector<uint8_t> buf(1u * 1024 * 1024);
    uint64_t total = 0;
    bool ok = true;
    std::string token;
    for (;;) {
        DWORD read_bytes = 0;
        if (!ReadFile(src.get(), buf.data(), static_cast<DWORD>(buf.size()), &read_bytes,
                      nullptr)) {
            ok = false;
            token = amcache_copy_error_token(GetLastError());
            break;
        }
        if (read_bytes == 0)
            break;
        total += read_bytes;
        if (total > kAmcacheMaxBytes) {
            ok = false;
            token = "hive_oversized";
            break;
        }
        DWORD written = 0;
        if (!WriteFile(dst.get(), buf.data(), read_bytes, &written, nullptr)) {
            ok = false;
            token = amcache_copy_error_token(GetLastError());
            break;
        }
        if (written != read_bytes) {
            ok = false;
            token = "hive_short_write";
            break;
        }
    }
    if (!ok)
        DeleteFileW(dest);
    return token; // empty on success
}

// real_enum_key/real_open_subkey wrap the two Win32 calls.
// walk_amcache_inventory below routes through AmcacheWalkFns, at the exact
// call shape collect_amcache used inline before this seam existed (#4392).
LSTATUS real_enum_key(HKEY root, DWORD idx, wchar_t* name, DWORD* name_len) {
    return RegEnumKeyExW(root, idx, name, name_len, nullptr, nullptr, nullptr, nullptr);
}

LSTATUS real_open_subkey(HKEY root, const wchar_t* name, HKEY* out) {
    return RegOpenKeyExW(root, name, 0, KEY_READ, out);
}

/// Injectable seam for collect_amcache's subkey walk (#4392): every Win32
/// call in the loop below is routed through `fns`, whose defaults bind to
/// the real Reg*W/enumerate_value_names/read_reg_value calls -- so the real
/// dispatch path (fns == {}) is byte-identical to this function's body
/// before this seam existed.
/// tests/unit/test_execution_artifacts_win_internals.cpp is the only caller
/// that ever passes a non-default `fns` or `max_subkeys`.
struct AmcacheWalkFns {
    LSTATUS (*enum_key)(HKEY root, DWORD idx, wchar_t* name, DWORD* name_len) = &real_enum_key;
    LSTATUS (*open_subkey)(HKEY root, const wchar_t* name, HKEY* out) = &real_open_subkey;
    yuzu::win::ValueNameEnumeration (*enum_values)(HKEY) = &yuzu::win::enumerate_value_names;
    yuzu::win::ReadValueStatus (*read_value)(HKEY, const std::string&, std::string&,
                                             std::string&) = &yuzu::win::read_reg_value;
};

using AmcacheSubkeys = std::vector<std::pair<std::string, std::map<std::string, std::string>>>;

/// Body moved verbatim (routed through `fns`/`max_subkeys`) out of
/// collect_amcache's inline loop -- see AmcacheWalkFns's docblock above for
/// why this split changes no production behaviour (fns == {} is
/// byte-identical to the old inline body).
AmcacheSubkeys walk_amcache_inventory(HKEY root_key, yuzu::shared::ConstraintAccumulator& acc,
                                      const AmcacheWalkFns& fns = {},
                                      DWORD max_subkeys = kAmcacheMaxSubkeys) {
    AmcacheSubkeys subkeys;
    constexpr DWORD kNameBufLen = 256;
    wchar_t name_buf[kNameBufLen];
    DWORD idx = 0;
    for (;;) {
        // Capped on attempted entries (idx), not on subkeys.size() --
        // a denied/vanished RegOpenKeyExW below still advances idx via
        // RegEnumKeyExW without ever growing subkeys, so gating on the
        // successful-open count let a subkey run with many denials
        // enumerate/open far more than kAmcacheMaxSubkeys times while
        // holding the shared offline-hive lock.
        if (idx >= max_subkeys) {
            acc.add_failure("subkey_cap");
            acc.mark_incomplete();
            break;
        }
        DWORD name_len = kNameBufLen;
        const LSTATUS enum_rc = fns.enum_key(root_key, idx, name_buf, &name_len);
        if (enum_rc != ERROR_SUCCESS) {
            if (enum_rc != ERROR_NO_MORE_ITEMS) { // a genuine mid-walk failure, not exhaustion
                acc.add_failure("enum_" + std::to_string(enum_rc));
                acc.mark_incomplete();
            }
            break;
        }
        ++idx;

        std::string subkey_name = yuzu::win::from_wide(name_buf, static_cast<int>(name_len));
        yuzu::win::RegKey subkey;
        if (fns.open_subkey(root_key, name_buf, subkey.put()) != ERROR_SUCCESS) {
            // vanished/denied mid-walk -- real loss, not silent
            acc.add_failure("subkey_open_failed");
            acc.mark_incomplete();
            continue;
        }

        auto value_names = fns.enum_values(subkey.get());
        if (!value_names.complete) {
            acc.add_failure("value_enum_incomplete");
            acc.mark_incomplete();
        }

        std::map<std::string, std::string> values;
        for (const auto& vname : value_names.names) {
            std::string out_value, out_type;
            if (fns.read_value(subkey.get(), vname, out_value, out_type) ==
                yuzu::win::ReadValueStatus::ok) {
                values.emplace(vname, std::move(out_value));
            } else {
                // win_profiles.hpp's ReadValueStatus exists specifically
                // so a caller can tell "value read failed" apart from
                // "value absent" -- collapsing every non-ok status
                // (denied, oversized, malformed, changed-during-read)
                // into silent omission throws that signal away and
                // reports a row with a missing field as if the read had
                // been complete (SYN-02).
                acc.add_failure("value_read_failed");
                acc.mark_incomplete();
            }
        }
        subkeys.emplace_back(std::move(subkey_name), std::move(values));
    }
    return subkeys;
}

// ── Prefetch ─────────────────────────────────────────────────────────────

constexpr wchar_t kPrefetchGlob[] = L"C:\\Windows\\Prefetch\\*.pf";
constexpr wchar_t kPrefetchDir[] = L"C:\\Windows\\Prefetch\\";
constexpr wchar_t kPrefetchParamsSubkey[] =
    L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters";
constexpr wchar_t kEnablePrefetcherValue[] = L"EnablePrefetcher";
constexpr size_t kPrefetchMaxFiles = 2048;
constexpr uint64_t kPrefetchPerFileMaxBytes = 8ull * 1024 * 1024;   // 8 MiB
constexpr uint64_t kPrefetchTotalMaxBytes = 256ull * 1024 * 1024;   // 256 MiB

// A1 probe evidence: RtlGetCompressionWorkSpaceSize reported format
// COMPRESSION_FORMAT_XPRESS_HUFF = 4 in every run. Defined locally rather
// than pulled from a Windows SDK header (whose availability under the
// NTDDI_VERSION guard this file does not want to depend on) since only the
// numeric value is needed.
constexpr USHORT kCompressionFormatXpressHuff = 4;

using RtlGetCompressionWorkSpaceSizeFn = NTSTATUS(NTAPI*)(USHORT, PULONG, PULONG);
using RtlDecompressBufferExFn = NTSTATUS(NTAPI*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG,
                                                 PVOID);

// Resolved ONCE via GetProcAddress(GetModuleHandleW(L"ntdll.dll"), ...) --
// this package's spec, "no #ifdef around the symbol": absence is a runtime
// outcome (ntdll_symbol_missing), never a compile-time exclusion of this
// leg. Magic-static idiom mirrors confined_fs_win.cpp's
// resolve_ntcreatefile/resolve_rtl_ntstatus_to_doserror.
RtlGetCompressionWorkSpaceSizeFn resolve_workspace_size_fn() {
    static const RtlGetCompressionWorkSpaceSizeFn resolved = []() -> RtlGetCompressionWorkSpaceSizeFn {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
            return nullptr;
        return reinterpret_cast<RtlGetCompressionWorkSpaceSizeFn>(
            reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlGetCompressionWorkSpaceSize")));
    }();
    return resolved;
}

RtlDecompressBufferExFn resolve_decompress_fn() {
    static const RtlDecompressBufferExFn resolved = []() -> RtlDecompressBufferExFn {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
            return nullptr;
        return reinterpret_cast<RtlDecompressBufferExFn>(
            reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlDecompressBufferEx")));
    }();
    return resolved;
}

/// Decompresses a MAM-compressed `.pf` payload into `out`. Returns an empty
/// token on success; a non-empty token (ntdll_symbol_missing, a parser
/// token from mam_uncompressed_size, or ntstatus_<hex>) on failure.
std::string decompress_mam(std::span<const uint8_t> raw, std::vector<uint8_t>& out) {
    const auto workspace_size_fn = resolve_workspace_size_fn();
    const auto decompress_fn = resolve_decompress_fn();
    if (!workspace_size_fn || !decompress_fn)
        return "ntdll_symbol_missing";

    auto usize = mam_uncompressed_size(raw); // parsers.hpp: bounds-checks against kMamMaxUncompressedSize
    if (!usize)
        return usize.error().token;

    ULONG workspace_bytes = 0, fragment_bytes = 0;
    const NTSTATUS ws_status =
        workspace_size_fn(kCompressionFormatXpressHuff, &workspace_bytes, &fragment_bytes);
    if (ws_status != 0)
        return ntstatus_token(ws_status);

    std::vector<uint8_t> workspace(workspace_bytes > 0 ? workspace_bytes : 1);
    out.assign(*usize, 0);

    // MAM header is 8 bytes (4-byte "MAM\x04" magic + 4-byte uncompressed
    // size, both validated by mam_uncompressed_size above) -- the compressed
    // payload starts immediately after it.
    //
    // const_cast safety: RtlDecompressBufferEx's CompressedBuffer parameter is
    // documented [in]-only (never written); and even in the hypothetical worst
    // case that it did write, `raw`/`payload`/`bytes` is never read again after
    // this call (payload is reassigned to `decompressed` immediately below), so
    // there is no downstream effect either way. Same pattern as auth.cpp:134.
    auto* compressed = const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(raw.data() + 8));
    const ULONG compressed_bytes = static_cast<ULONG>(raw.size() - 8);

    ULONG final_size = 0;
    const NTSTATUS dec_status =
        decompress_fn(kCompressionFormatXpressHuff, out.empty() ? nullptr : out.data(),
                     static_cast<ULONG>(out.size()), compressed, compressed_bytes, &final_size,
                     workspace.data());
    if (dec_status != 0)
        return ntstatus_token(dec_status);

    out.resize(final_size);
    return {};
}

HANDLE real_find_first(const wchar_t* glob, WIN32_FIND_DATAW* out) {
    return FindFirstFileW(glob, out);
}

BOOL real_find_next(HANDLE h, WIN32_FIND_DATAW* out) {
    return FindNextFileW(h, out);
}

/// Best-effort read of `EnablePrefetcher` (PrefetchParameters). Returns
/// nullopt on ANY failure -- missing key/value, wrong type, access denied --
/// never throws, never logs above debug. Used only to classify an already-
/// empty Prefetch directory (#4391); a populated directory never calls this.
/// Moved above collect_prefetch_from (dev merge, #4564): this used to sit
/// directly above the un-refactored collect_prefetch it was written for.
std::optional<uint32_t> read_enable_prefetcher() {
    DWORD value = 0;
    DWORD size = sizeof(value);
    LONG rc = RegGetValueW(HKEY_LOCAL_MACHINE, kPrefetchParamsSubkey, kEnablePrefetcherValue,
                           RRF_RT_REG_DWORD, nullptr, &value, &size);
    if (rc != ERROR_SUCCESS)
        return std::nullopt;
    return value;
}

/// Injectable seam for collect_prefetch's enumeration + caps (#4392):
/// FindFirstFileW/FindNextFileW route through `fns` (raw function pointers
/// wrapping the two calls, so the pointer type carries no WINAPI-convention
/// mismatch), the three caps route through `limits`. Defaults bind to the
/// real calls/constants, so the real dispatch path (fns == {}, limits == {})
/// is byte-identical to this function's body before this seam existed.
struct PrefetchEnumFns {
    HANDLE (*find_first)(const wchar_t* glob, WIN32_FIND_DATAW* out) = &real_find_first;
    BOOL (*find_next)(HANDLE h, WIN32_FIND_DATAW* out) = &real_find_next;
};

struct PrefetchLimits {
    size_t max_files = kPrefetchMaxFiles;
    uint64_t per_file_max_bytes = kPrefetchPerFileMaxBytes;
    uint64_t total_max_bytes = kPrefetchTotalMaxBytes;
};

/// Body moved (routed through `fns`/`limits`, and through the
/// `glob`/`dir_with_trailing_backslash` parameters in place of
/// kPrefetchGlob/kPrefetchDir) out of collect_prefetch, which becomes a
/// one-line wrapper over this function below. Zero-files absence
/// classification (dev merge, #4564) ported in alongside the move: a bare
/// `"prefetch_disabled"` literal can't distinguish the prefetcher being
/// genuinely off from it being on with no evidence yet or the registry
/// state being unreadable -- see prefetch_absence_token's own doc comment.
int collect_prefetch_from(yuzu::CommandContext& ctx, const wchar_t* glob,
                          const wchar_t* dir_with_trailing_backslash,
                          const PrefetchLimits& limits = {}, const PrefetchEnumFns& fns = {}) {
    try {
        WIN32_FIND_DATAW find_data{};
        ScopedFindHandle find(fns.find_first(glob, &find_data));
        if (!find) {
            const DWORD err = GetLastError();
            // Zero files could mean the prefetcher is off (expected), configured
            // on but with no evidence (prefetch_evidence_absent), or unknown
            // (registry unreadable / undocumented value) -- see
            // prefetch_absence_token's own comment for the forensic distinction.
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
                return emit_constrained(
                    ctx, std::string{prefetch_absence_token(read_enable_prefetcher())});
            return emit_constrained(ctx, "prefetch_enum_" + std::to_string(err));
        }

        size_t files_seen = 0;
        size_t rows_emitted = 0;
        uint64_t total_bytes = 0;
        // file_cap / byte_cap / a mid-walk enumeration fault -> acc.mark_incomplete()
        // (the enumeration was TRUNCATED); a single .pf skipped with a
        // prefetch_error| row -> acc.add_failure() only (enumeration completed).
        yuzu::shared::ConstraintAccumulator acc;

        do {
            if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                continue;

            if (files_seen >= limits.max_files) {
                acc.add_failure("file_cap");
                acc.mark_incomplete();
                break;
            }
            ++files_seen;

            const std::string fname =
                yuzu::util::safe_output_field(yuzu::win::from_wide(find_data.cFileName));
            const uint64_t file_bytes =
                (static_cast<uint64_t>(find_data.nFileSizeHigh) << 32) | find_data.nFileSizeLow;

            if (file_bytes > limits.per_file_max_bytes) {
                ctx.write_output("prefetch_error|" + fname + "|file_oversized");
                acc.add_failure("file_oversized");
                continue;
            }
            if (total_bytes + file_bytes > limits.total_max_bytes) {
                acc.add_failure("byte_cap");
                acc.mark_incomplete();
                break;
            }

            const std::wstring full_path =
                std::wstring{dir_with_trailing_backslash} + find_data.cFileName;
            ScopedHandle fh(CreateFileW(full_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
            if (!fh) {
                ctx.write_output("prefetch_error|" + fname + "|read_failed");
                acc.add_failure("read_failed");
                continue;
            }
            std::vector<uint8_t> bytes(static_cast<size_t>(file_bytes));
            DWORD read_bytes = 0;
            const bool read_ok =
                bytes.empty() || (ReadFile(fh.get(), bytes.data(), static_cast<DWORD>(bytes.size()),
                                          &read_bytes, nullptr) &&
                                 read_bytes == bytes.size());
            if (!read_ok) {
                ctx.write_output("prefetch_error|" + fname + "|read_failed");
                acc.add_failure("read_failed");
                continue;
            }
            total_bytes += bytes.size();

            std::vector<uint8_t> decompressed;
            std::span<const uint8_t> payload = bytes;
            if (is_mam_compressed(payload)) {
                const std::string dec_token = decompress_mam(payload, decompressed);
                if (!dec_token.empty()) {
                    ctx.write_output("prefetch_error|" + fname + "|" + dec_token);
                    acc.add_failure(dec_token);
                    continue;
                }
                payload = decompressed;
            }

            auto parsed = parse_prefetch(payload);
            if (!parsed) {
                ctx.write_output("prefetch_error|" + fname + "|" + parsed.error().token);
                acc.add_failure(parsed.error().token);
                continue;
            }

            ctx.write_output(format_prefetch_row(parsed->exe_name, parsed->hash_hex,
                                                 parsed->version, parsed->run_count,
                                                 parsed->last_runs_epoch_ms, parsed->volume_count,
                                                 parsed->file_ref_count));
            ++rows_emitted;
        } while (fns.find_next(find.get(), &find_data));

        // FindNextFileW returning false is ambiguous on its own --
        // ERROR_NO_MORE_FILES is the normal, expected end of enumeration,
        // but any other GetLastError() means a genuine I/O fault ended the
        // walk early, indistinguishable from clean exhaustion without this
        // check (SYN-03). Skip it when the loop instead exited via one of
        // the caps above (acc.incomplete() already set) -- that path breaks
        // out of the loop body before FindNextFileW runs again, so
        // GetLastError() would reflect a stale prior call, not the reason
        // the walk stopped.
        if (!acc.incomplete()) {
            const DWORD find_err = GetLastError();
            if (find_err != ERROR_NO_MORE_FILES) {
                acc.add_failure("prefetch_enum_" + std::to_string(find_err));
                acc.mark_incomplete();
            }
        }

        if (files_seen == 0 && !acc.any_failure())
            return emit_constrained(
                ctx, std::string{prefetch_absence_token(read_enable_prefetcher())});

        if (acc.incomplete())
            ctx.write_output("constrained|" + acc.reason());

        // Exit code agrees with the typed status (legs.hpp contract: 0 only on OK):
        //   - a cap fired -> the enumeration was TRUNCATED -> CONSTRAINED/PARTIAL, rc 1;
        //   - only per-file errors -> the enumeration COMPLETED and every skipped file
        //     is already on the stream as a prefetch_error| row -> OK/PARTIAL, rc 0
        //     (the-rig 2026-09-07: one truncated WERFAULT .pf must not fail 302 good rows);
        //   - neither -> OK/FULL, rc 0.
        const YuzuResultStatus status =
            acc.incomplete() ? YUZU_RESULT_STATUS_CONSTRAINED : YUZU_RESULT_STATUS_OK;
        const YuzuResultCompleteness completeness =
            acc.any_failure() ? YUZU_RESULT_COMPLETENESS_PARTIAL : YUZU_RESULT_COMPLETENESS_FULL;
        ctx.set_result_status(status, completeness, acc.reason());
        (void)rows_emitted; // kept for readability at call sites reading this function
        return acc.incomplete() ? 1 : 0;
    } catch (...) {
        return emit_constrained(ctx, "internal_error");
    }
}

} // namespace

// The three exported entry points below (through the end of
// collect_prefetch) are excluded when the guard macro just below is defined
// -- the seam tests/unit/test_execution_artifacts_win_internals.cpp uses to
// #include this TU directly and reach the internal-linkage
// AmcacheWalkFns/walk_amcache_inventory/PrefetchEnumFns/PrefetchLimits/
// collect_prefetch_from/ScratchDirGuard for a constructed-fixture unit test
// (#4392), without pulling collect_shimcache/collect_amcache/
// collect_prefetch's own symbols into a second definition. This TU never
// statically links the real plugin either way (the test binary loads the
// real DLL via PluginHandle at runtime for its own separate win_local/
// local_dispatcher cases), so a second compilation of the same free
// functions here creates no ODR/duplicate-symbol conflict. Never defined by
// this TU's own (real) build -- meson.build does not set it. Mirrors
// autoruns_macos.cpp's identical seam for
// YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY.
#ifndef YUZU_EXECUTION_ARTIFACTS_WIN_UNIT_TEST_INTERNALS_ONLY

// ═══════════════════════════════════════════════════════════ ShimCache ════

int collect_shimcache(yuzu::CommandContext& ctx) {
    try {
        yuzu::win::RegKey key;
        const LSTATUS open_rc =
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, kShimCacheSubkey, 0, KEY_READ, key.put());
        if (open_rc != ERROR_SUCCESS)
            return emit_constrained(ctx, "reg_" + std::to_string(open_rc));

        std::vector<uint8_t> blob;
        LSTATUS blob_rc = ERROR_SUCCESS;
        switch (read_shimcache_blob(key.get(), blob, blob_rc)) {
        case ShimBlobStatus::oversized:
            return emit_constrained(ctx, "oversized");
        case ShimBlobStatus::changed_during_read:
            return emit_constrained(ctx, "reg_changed_during_read");
        case ShimBlobStatus::not_found:
            return emit_constrained(ctx, "reg_" + std::to_string(blob_rc));
        case ShimBlobStatus::ok:
            break;
        }

        auto parsed = parse_shimcache(blob);
        if (!parsed) {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  parsed.error().token);
            ctx.write_output("constrained|" + parsed.error().token +
                             "|offset=" + std::to_string(parsed.error().offset));
            return 1;
        }
        if (parsed->rows.empty())
            return emit_constrained(ctx, "shimcache_empty");

        for (const auto& row : parsed->rows)
            ctx.write_output(format_shimcache_row(row.path, row.last_modified_epoch_ms, row.data_size));

        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        return 0;
    } catch (...) {
        return emit_constrained(ctx, "internal_error");
    }
}

// ═══════════════════════════════════════════════════════════════ Amcache ══

int collect_amcache(yuzu::CommandContext& ctx, std::string_view data_dir) {
    try {
        WIN32_FILE_ATTRIBUTE_DATA attr{};
        if (!GetFileAttributesExW(kAmcacheSourceHve, GetFileExInfoStandard, &attr))
            return emit_constrained(ctx, "hive_missing");
        const uint64_t src_bytes =
            (static_cast<uint64_t>(attr.nFileSizeHigh) << 32) | attr.nFileSizeLow;
        if (src_bytes > kAmcacheMaxBytes)
            return emit_constrained(ctx, "hive_oversized");

        // agent.data_dir is always set by the daemon before any plugin runs
        // (agent.cpp) -- an empty value here means this leg is running
        // outside that context (a test/tool that didn't configure it), not
        // a case worth guessing a fallback location for. See the file
        // banner's SCRATCH DIRECTORY note for why there is no hardcoded
        // literal to fall back to any more.
        if (data_dir.empty())
            return emit_constrained(ctx, "data_dir_unset");

        // 128-bit crypto-random name, CREATE_NEW semantics (never reused --
        // any failure including ERROR_ALREADY_EXISTS is a hard failure),
        // owner-only DACL: temp_file.cpp's yuzu_create_temp_dir(). See
        // ScratchDirGuard's banner for why its own RAII (not
        // yuzu::TempDir's) owns the removal.
        char scratch_path_utf8[512]{};
        if (yuzu_create_temp_dir("execution_artifacts-", std::string{data_dir}.c_str(),
                                  scratch_path_utf8, sizeof(scratch_path_utf8)) != 0)
            return emit_constrained(ctx, "dest_dir_create_" + std::to_string(GetLastError()));

        ScratchDirGuard scratch(ctx, yuzu::win::to_wide(scratch_path_utf8));

        // Open the directory ONCE, as a handle, and hold it (dest_dir_handle
        // stays in scope for the rest of this function, spanning the verify
        // below AND the copy further down) -- see open_scratch_dir_handle's
        // banner for why a held-open handle, not a second path-based check
        // right before the copy, is what makes this sequence race-free.
        ScopedHandle dest_dir_handle = open_scratch_dir_handle(scratch.path());
        if (!dest_dir_handle)
            return emit_constrained(ctx, "dest_dir_open_" + std::to_string(GetLastError()));

        if (!detail::scratch_dir_is_ours(dest_dir_handle.get()))
            return emit_constrained(ctx, "dest_dir_acl");

        const std::wstring dest_hve = scratch.path() + L"\\amcache.hve";

        // ENTIRE privilege-bearing sequence -- PrivilegeScope construction
        // (fallback path only), the copy, RegLoadAppKeyW, enumeration, and
        // RegCloseKey -- runs under this ONE lock, exactly as with_user_hive
        // (win_profiles.hpp:479-535) holds it for its whole offline arm. See
        // the file banner for the hold-time bound. `"execution_artifacts"`
        // is this leg's caller name for offline_hive_mutex.hpp's own
        // contention-attribution logging.
        const yuzu::agent::ScopedOfflineHiveLock offline_lock("execution_artifacts");

        if (!CopyFileW(kAmcacheSourceHve, dest_hve.c_str(), FALSE)) {
            const DWORD copy_err = GetLastError();
            if (copy_err != ERROR_SHARING_VIOLATION)
                return emit_constrained(ctx, amcache_copy_error_token(copy_err));

            const std::string fallback_token = copy_amcache_via_backup_semantics(dest_hve.c_str());
            if (!fallback_token.empty())
                return emit_constrained(ctx, fallback_token);
        }

        // Re-check the ACTUAL copied bytes against kAmcacheMaxBytes here,
        // under the lock, instead of trusting only the pre-lock src_bytes
        // stat above: that stat ran BEFORE this action waited to acquire
        // offline_hive_mutex, so the source hive can grow past the cap
        // during the wait, and plain CopyFileW -- unlike the backup-
        // semantics fallback's own streaming total-vs-cap check -- enforces
        // no byte limit of its own; it would copy an oversized file
        // straight through.
        {
            WIN32_FILE_ATTRIBUTE_DATA dest_attr{};
            if (GetFileAttributesExW(dest_hve.c_str(), GetFileExInfoStandard, &dest_attr)) {
                const uint64_t dest_bytes =
                    (static_cast<uint64_t>(dest_attr.nFileSizeHigh) << 32) | dest_attr.nFileSizeLow;
                if (dest_bytes > kAmcacheMaxBytes)
                    return emit_constrained(ctx, "hive_oversized");
            }
        }

        // .LOG1/.LOG2 -- best-effort only, plain copy, never the privilege
        // fallback: RegLoadAppKeyW's read of the main .hve is this leg's only
        // hard requirement (this package's spec: "+.LOG1/.LOG2 when present").
        // No per-file cleanup registration needed any more -- ScratchDirGuard
        // removes the whole scratch directory (partial sidecars included) on
        // scope exit regardless of which return path is taken (SYN-06).
        for (const wchar_t* ext : {L".LOG1", L".LOG2"}) {
            const std::wstring src_log = std::wstring{kAmcacheSourceHve} + ext;
            const std::wstring dst_log = dest_hve + ext;
            if (CopyFileW(src_log.c_str(), dst_log.c_str(), FALSE)) {
                // Sidecars have no size check of their own otherwise --
                // bound them by the same cap so a huge .LOG1/.LOG2 can't
                // defeat the advertised copy bound. Best-effort: drop the
                // oversized sidecar rather than failing the action over a
                // non-hard-requirement file.
                WIN32_FILE_ATTRIBUTE_DATA log_attr{};
                if (GetFileAttributesExW(dst_log.c_str(), GetFileExInfoStandard, &log_attr)) {
                    const uint64_t log_bytes = (static_cast<uint64_t>(log_attr.nFileSizeHigh) << 32) |
                                                log_attr.nFileSizeLow;
                    if (log_bytes > kAmcacheMaxBytes)
                        DeleteFileW(dst_log.c_str());
                }
            }
        }

        HKEY loaded_raw = nullptr;
        const LSTATUS load_rc =
            RegLoadAppKeyW(dest_hve.c_str(), &loaded_raw, KEY_READ, REG_PROCESS_APPKEY, 0);
        if (load_rc != ERROR_SUCCESS)
            return emit_constrained(ctx, "regload_" + std::to_string(load_rc));
        yuzu::win::RegKey loaded_key(loaded_raw);

        yuzu::win::RegKey root_key;
        if (RegOpenKeyExW(loaded_key.get(), L"Root\\InventoryApplicationFile", 0, KEY_READ,
                          root_key.put()) != ERROR_SUCCESS)
            return emit_constrained(ctx, "amcache_root_missing");

        yuzu::shared::ConstraintAccumulator acc;
        auto subkeys = walk_amcache_inventory(root_key.get(), acc);

        const AmCacheResult parsed = parse_amcache_inventory_application_file(subkeys);
        if (parsed.rows.empty())
            // Compose with acc.reason_with() rather than the bare token --
            // an empty result after e.g. subkey_cap/enum_*/subkey_open_failed
            // fired must still surface those accumulated reasons, not
            // silently discard them behind "amcache_empty".
            return emit_constrained(ctx, acc.reason_with("amcache_empty"));

        for (const auto& row : parsed.rows) {
            ctx.write_output(format_amcache_row(row.lower_case_long_path, row.sha1, row.size,
                                                row.link_date, row.publisher, row.binary_type,
                                                row.product_name, row.product_version));
        }

        // AmCacheResult::malformed_fields is computed but had no consumer
        // anywhere in the tree (SYN-01) -- its own doc comment promises it
        // is "never silently dropped". Surface it as its own note row
        // (same shape as this file's temp_cleanup_failed note) rather than
        // folding it into truncated/subkey_cap, which already means a
        // distinct thing (registry enumeration was incomplete).
        if (parsed.malformed_fields > 0)
            ctx.write_output("note|malformed_fileid_count=" +
                             std::to_string(parsed.malformed_fields));

        ctx.set_result_status(acc.incomplete() ? YUZU_RESULT_STATUS_CONSTRAINED
                                               : YUZU_RESULT_STATUS_OK,
                              acc.incomplete() ? YUZU_RESULT_COMPLETENESS_PARTIAL
                                               : YUZU_RESULT_COMPLETENESS_FULL,
                              acc.reason());
        return acc.incomplete() ? 1 : 0;
        // `root_key`, `loaded_key`, `offline_lock`, `dest_dir_handle` and
        // `scratch` (ScratchDirGuard) all destruct here in REVERSE
        // declaration order, on every return path above: RegCloseKey
        // (root_key, then loaded_key) runs first, then offline_lock
        // releases the shared mutex, then dest_dir_handle closes, then
        // scratch removes the whole directory tree -- matching
        // ScratchDirGuard's and scratch_dir_is_ours's banners exactly
        // (the handle must close before RemoveDirectoryW can succeed, and
        // removal must never happen while the lock is still held).
    } catch (...) {
        return emit_constrained(ctx, "internal_error");
    }
}

// ═══════════════════════════════════════════════════════════════ Prefetch ═

int collect_prefetch(yuzu::CommandContext& ctx) {
    return collect_prefetch_from(ctx, kPrefetchGlob, kPrefetchDir);
}

#endif // !YUZU_EXECUTION_ARTIFACTS_WIN_UNIT_TEST_INTERNALS_ONLY

} // namespace yuzu::execution_artifacts

#endif // defined(_WIN32)
