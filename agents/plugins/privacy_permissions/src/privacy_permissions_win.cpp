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
 * Administrators, final path == requested path, size cap) and the `<leaf>*` transaction-log
 * sidecars beside it (a link there would be followed by the load) are refused if a
 * reparse point (from the directory listing and again from the opened handle) or hard-linked, or
 * if there are more than 64. The guard's logic is privacy_permissions_hive_guard.hpp's
 * HiveFileGuard over a HiveFileProbe, implemented here by Win32HiveFileProbe. RegLoadKeyW is
 * path-based, so the same file identity is re-verified after the load and a mismatch is unloaded
 * unread (`hive_identity_changed`). Residual: the kernel parses whatever the path resolved to in that
 * window, as it does for every `reg load`; a sidecar swapped in after its check is likewise open.
 *
 * STABILITY: a RegNotifyChangeKeyValue watch is armed on each ConsentStore root before its walk
 * and polled after; a change the API reports discards that read and the source is walked ONCE more
 * (never once the deadline has passed); a source that changed again during its one re-walk, or
 * whose deadline left no time for one, is refused (`changed_during_read`), and a watch that cannot
 * be created, armed or polled refuses it too -- failure to observe stability is never stability. Residual: a RegRestoreKey-style whole-key replacement is not reported.
 *
 * DEADLINE: ~15 s, COOPERATIVE -- checked before each profile, first thing in the hive-file
 * guard's before_load, and before each capability and each app key open; there is no detached
 * worker (a plugin must not defer work past unload). One blocking call (the offline_hive_mutex
 * wait behind a sibling plugin's offline arm, RegLoadKeyW/RegUnLoadKeyW) is not interrupted, nor
 * is one enumeration of at most 4,096 children, the capability-level key opens, or one key's
 * value reads, so a dispatch can overrun it.
 *
 * SEAMS: the registry walk (privacy_permissions_win_walk.hpp) reads the OS through win::RegistryReader,
 * implemented here by Win32Registry; fake-registry tests lock its branches on every host.
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
 * an app, and is skipped by the registry's own (ordinal, case-insensitive) name compare.
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
#include "privacy_permissions_hive_guard.hpp"
#include "privacy_permissions_win_parsers.hpp"
#include "privacy_permissions_win_walk.hpp"

#if defined(_WIN32)

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
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

using win::ConsentWalk;
using win::RawGrant;

static_assert(win::kErrorSuccess == ERROR_SUCCESS);
static_assert(win::kErrorFileNotFound == ERROR_FILE_NOT_FOUND);
static_assert(win::kErrorAccessDenied == ERROR_ACCESS_DENIED);
static_assert(win::kErrorNoMoreItems == ERROR_NO_MORE_ITEMS);
static_assert(win::kErrorMoreData == ERROR_MORE_DATA);
static_assert(win::kRegSz == REG_SZ);
static_assert(win::kRegQword == REG_QWORD);
static_assert(win::kDriveFixed == DRIVE_FIXED);
static_assert(win::kWaitObject0 == WAIT_OBJECT_0);
static_assert(win::kWaitTimeout == WAIT_TIMEOUT);
static_assert(win::kFileAttributeDirectory == FILE_ATTRIBUTE_DIRECTORY);
static_assert(win::kFileAttributeReparsePoint == FILE_ATTRIBUTE_REPARSE_POINT);
static_assert(win::kFileAttributeOffline == FILE_ATTRIBUTE_OFFLINE);
static_assert(win::kFileAttributeRecallOnOpen == FILE_ATTRIBUTE_RECALL_ON_OPEN);
static_assert(win::kFileAttributeRecallOnDataAccess == FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS);
static_assert(sizeof(win::FileId::file_id) == sizeof(FILE_ID_128));

/// Arms a RegNotifyChangeKeyValue watch on a ConsentStore root before the walk and polls it
/// (zero timeout) after, so a change the API reports during the read is SHOWN, not assumed away.
/// Failure to observe is a fact classify_stability refuses on, never stability. Residual: the API
/// does not report a RegRestoreKey-style whole-key replacement.
struct StabilityWatch final : win::ConsentStoreWatch {
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
    ~StabilityWatch() override {
        if (event) CloseHandle(event);
    }
    StabilityWatch(const StabilityWatch&) = delete;
    StabilityWatch& operator=(const StabilityWatch&) = delete;

    [[nodiscard]] win::StabilityFacts poll() override {
        if (!event || facts.arm_rc != 0) return facts;
        facts.wait_rc = WaitForSingleObject(event, 0);
        facts.wait_gle = facts.wait_rc == WAIT_FAILED ? GetLastError() : 0;
        return facts;
    }
};

/// The OS side of the registry-walk seam (privacy_permissions_win_walk.hpp): each method is one
/// Win32 call, nothing else. The unit tests drive the walk through a fake registry; the rig tests
/// drive it through this one.
struct Win32Registry final : win::RegistryReader {
    long open_key(win::RegKeyHandle parent, const wchar_t* name, win::RegKeyHandle& out) override {
        HKEY k = nullptr;
        const LONG rc = RegOpenKeyExW(static_cast<HKEY>(parent), name, 0, KEY_READ, &k);
        if (rc == ERROR_SUCCESS) out = k;
        return rc;
    }
    void close_key(win::RegKeyHandle key) override { RegCloseKey(static_cast<HKEY>(key)); }
    long enum_key(win::RegKeyHandle parent, std::uint32_t idx, std::wstring& name) override {
        constexpr DWORD kNameBufLen = 512;
        wchar_t buf[kNameBufLen]{};
        DWORD len = kNameBufLen;
        const LONG rc = RegEnumKeyExW(static_cast<HKEY>(parent), idx, buf, &len, nullptr, nullptr,
                                      nullptr, nullptr);
        if (rc == ERROR_SUCCESS) name.assign(buf, len);
        return rc;
    }
    long query_value(win::RegKeyHandle key, const wchar_t* value_name, std::uint32_t& type,
                     std::span<std::byte> buf, std::uint32_t& size) override {
        DWORD t = 0;
        DWORD sz = static_cast<DWORD>(buf.size());
        const LONG rc = RegQueryValueExW(static_cast<HKEY>(key), value_name, nullptr, &t,
                                         buf.empty() ? nullptr : reinterpret_cast<BYTE*>(buf.data()),
                                         &sz);
        type = t;
        size = sz;
        return rc;
    }
    std::unique_ptr<win::ConsentStoreWatch> watch(win::RegKeyHandle root) override {
        return std::make_unique<StabilityWatch>(static_cast<HKEY>(root));
    }
    bool key_name_equals(std::wstring_view a, std::wstring_view b) const override {
        return CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b.data(),
                                    static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
    }
    std::string utf8(std::wstring_view s) const override {
        return yuzu::win::from_wide(s.data(), static_cast<int>(s.size()));
    }
    std::string reg_sz_utf8(std::span<const std::byte> payload) const override {
        return yuzu::win::reg_sz_to_utf8(reinterpret_cast<const wchar_t*>(payload.data()),
                                         static_cast<DWORD>(payload.size()));
    }
};

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

/// Owns a FindFirstFileExW search handle: FindClose (not CloseHandle) on every exit path.
struct FindHandle {
    HANDLE h;
    explicit FindHandle(HANDLE x) noexcept : h(x) {}
    ~FindHandle() {
        if (h != INVALID_HANDLE_VALUE) FindClose(h);
    }
    FindHandle(const FindHandle&) = delete;
    FindHandle& operator=(const FindHandle&) = delete;
    [[nodiscard]] bool ok() const noexcept { return h != INVALID_HANDLE_VALUE; }
};

/// Owns an allocation the OS handed back to be released with LocalFree (a security descriptor from
/// GetSecurityInfo, a string from ConvertSidToStringSidW); null is a no-op.
struct LocalFreeGuard {
    HLOCAL p;
    explicit LocalFreeGuard(HLOCAL x) noexcept : p(x) {}
    ~LocalFreeGuard() {
        if (p) LocalFree(p);
    }
    LocalFreeGuard(const LocalFreeGuard&) = delete;
    LocalFreeGuard& operator=(const LocalFreeGuard&) = delete;
};

/// Whether the path the kernel resolved a handle to (`final_path`, GetFinalPathNameByHandleW with
/// VOLUME_NAME_DOS) is the path that was asked for (`requested`, which gets the `\\?\` prefix a
/// DOS-volume final path carries). CompareStringOrdinal is the ordinal case-insensitive primitive
/// the file system itself is defined against, so a non-ASCII case-only difference is the same path.
/// A failed comparison (0) is "not equal": the safe side. Runs of `\` in `requested` collapse to
/// one first (a ProfileImagePath with a trailing separator yields `..\\NTUSER.DAT`; the kernel's
/// final path carries one): `requested` is a drive-letter path here (UNC was refused upstream), so
/// no `\\?\` or UNC prefix can be damaged. Only separator runs: never `.`/`..` or 8.3 names.
[[nodiscard]] bool final_path_matches(const std::wstring& requested, const std::wstring& final_path) {
    std::wstring collapsed = requested;
    collapsed.erase(std::unique(collapsed.begin(), collapsed.end(),
                                [](wchar_t a, wchar_t b) { return a == L'\\' && b == a; }),
                    collapsed.end());
    const std::wstring expected = L"\\\\?\\" + collapsed;
    return CompareStringOrdinal(expected.c_str(), static_cast<int>(expected.size()),
                                final_path.c_str(), static_cast<int>(final_path.size()),
                                TRUE) == CSTR_EQUAL;
}

/// A failing call's code as the seam reports it: never 0 (success), even if the call left no
/// last-error behind.
[[nodiscard]] long failure_code(DWORD gle) noexcept {
    return gle != 0 ? static_cast<long>(gle) : static_cast<long>(ERROR_GEN_FAILURE);
}

/// The OS side of the hive-file seam (privacy_permissions_hive_guard.hpp): each method is the
/// Win32 sequence for one question the guard asks, nothing more. The unit tests drive HiveFileGuard
/// through a fake probe; the rig tests drive it through this one.
struct Win32HiveFileProbe final : win::HiveFileProbe {
    UniqueHandle open_attr(const std::wstring& path, DWORD access) {
        ++opens;
        return UniqueHandle{CreateFileW(path.c_str(), access,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        nullptr, OPEN_EXISTING,
                                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                                        nullptr)};
    }

    std::uint32_t drive_type(const std::wstring& root) override {
        return GetDriveTypeW(root.c_str());
    }

    long path_attributes(const std::wstring& path, std::uint32_t& attrs) override {
        const UniqueHandle dir = open_attr(path, FILE_READ_ATTRIBUTES);
        if (!dir.ok()) return failure_code(GetLastError());
        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (!GetFileInformationByHandleEx(dir.h, FileAttributeTagInfo, &tag, sizeof tag))
            return failure_code(GetLastError());
        attrs = tag.FileAttributes;
        return 0;
    }

    long leaf_facts(const std::wstring& path, win::LeafFacts& out) override {
        const UniqueHandle leaf = open_attr(path, FILE_READ_ATTRIBUTES | READ_CONTROL);
        if (!leaf.ok()) return failure_code(GetLastError());

        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (!GetFileInformationByHandleEx(leaf.h, FileAttributeTagInfo, &tag, sizeof tag))
            return failure_code(GetLastError());
        out.attributes = tag.FileAttributes;
        out.is_disk_file = GetFileType(leaf.h) == FILE_TYPE_DISK;

        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(leaf.h, &info)) return failure_code(GetLastError());
        out.size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;

        PSID owner = nullptr;
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (const DWORD rc = GetSecurityInfo(leaf.h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                             &owner, nullptr, nullptr, nullptr, &sd);
            rc != ERROR_SUCCESS)
            return failure_code(rc);
        const LocalFreeGuard sd_guard{sd}; // `owner` points into it: alive until this scope ends
        LPWSTR sid_str = nullptr;
        const BOOL converted = ConvertSidToStringSidW(owner, &sid_str);
        const LocalFreeGuard sid_guard{sid_str};
        // The return value is evaluated before the guards run, so GetLastError is read first.
        if (!converted) return failure_code(GetLastError());
        out.owner_sid = yuzu::win::from_wide(sid_str);

        std::wstring fin(MAX_PATH, L'\0');
        DWORD n = GetFinalPathNameByHandleW(leaf.h, fin.data(), static_cast<DWORD>(fin.size()),
                                            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (n >= fin.size()) {
            fin.assign(static_cast<std::size_t>(n) + 1, L'\0');
            n = GetFinalPathNameByHandleW(leaf.h, fin.data(), static_cast<DWORD>(fin.size()),
                                          FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        }
        // n >= size is a sizing result (the path grew between the two calls), not an API failure:
        // GetLastError is stale then, so name the documented "buffer still too small" code.
        if (n == 0 || n >= fin.size())
            return n == 0 ? failure_code(GetLastError()) : static_cast<long>(ERROR_MORE_DATA);
        fin.resize(n);
        out.final_path_matches = final_path_matches(path, fin);

        FILE_ID_INFO id{};
        if (!GetFileInformationByHandleEx(leaf.h, FileIdInfo, &id, sizeof id))
            return failure_code(GetLastError());
        out.id.volume_serial = id.VolumeSerialNumber;
        std::memcpy(out.id.file_id.data(), &id.FileId, sizeof id.FileId);
        return 0;
    }

    long list_sidecars(const std::wstring& dir, const std::wstring& leaf, std::size_t limit,
                       std::vector<win::SidecarEntry>& out) override {
        const std::wstring base = dir.ends_with(L'\\') ? dir : dir + L"\\";
        WIN32_FIND_DATAW fd{};
        const FindHandle find{FindFirstFileExW((base + leaf + L"*").c_str(), FindExInfoBasic, &fd,
                                               FindExSearchNameMatch, nullptr, 0)};
        if (!find.ok()) {
            const DWORD rc = GetLastError();
            return (rc == ERROR_FILE_NOT_FOUND || rc == ERROR_NO_MORE_FILES) ? 0 : failure_code(rc);
        }
        do {
            const std::wstring name = fd.cFileName;
            if (name == L"." || name == L".." ||
                CompareStringOrdinal(name.c_str(), static_cast<int>(name.size()), leaf.c_str(),
                                     static_cast<int>(leaf.size()), TRUE) == CSTR_EQUAL)
                continue;
            out.push_back({name, fd.dwFileAttributes});
            if (out.size() >= limit) return 0;
        } while (FindNextFileW(find.h, &fd));
        const DWORD rc = GetLastError();
        return rc == ERROR_NO_MORE_FILES ? 0 : failure_code(rc);
    }

    long sidecar_facts(const std::wstring& path, std::uint32_t& links,
                       std::uint32_t& attrs) override {
        const UniqueHandle h = open_attr(path, FILE_READ_ATTRIBUTES);
        if (!h.ok()) return failure_code(GetLastError());
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(h.h, &info)) return failure_code(GetLastError());
        links = info.nNumberOfLinks;
        attrs = info.dwFileAttributes;
        return 0;
    }
};

} // namespace

// Excluded under YUZU_PRIVACY_PERMISSIONS_WIN_UNIT_TEST_INTERNALS_ONLY: the seam
// test_privacy_permissions_win_internals.cpp uses to #include this TU and reach the
// internal-linkage helpers (mirrors privacy_permissions_macos.cpp). Never defined by the real build.
#ifndef YUZU_PRIVACY_PERMISSIONS_WIN_UNIT_TEST_INTERNALS_ONLY

int collect_windows_permissions(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    win::RetentionBudget budget; // per-source caps + the cooperative run deadline
    OutputBudget output;         // run-wide formatted-length bound, shared with the macOS leg

    // HKLM: machine-wide, collected once (win::assemble_windows_rows decides what becomes of it).
    Win32Registry reg;
    budget.begin_profile();
    const ConsentWalk hklm = win::walk_consent_store(reg, HKEY_LOCAL_MACHINE, budget);

    // Real interactive users, not the agent process's own (LocalSystem) HKEY_CURRENT_USER --
    // see the file banner. Discovery keeps every code it saw and each is a row
    // (win::profile_discovery_failure / profile_record_failure decide); the profiles that WERE
    // enumerated are still walked.
    std::vector<PermissionRow> discovery_rows;
    const auto discovery = yuzu::win::enumerate_profile_list();
    if (const auto f = win::profile_discovery_failure(discovery.root_rc, discovery.last_rc,
                                                      discovery.probe_rc))
        discovery_rows.push_back(failure_row("windows", "-", "-", f->denied, f->cause, acc));
    for (const auto& rf : discovery.record_failures) {
        if (yuzu::profiles::is_system_sid(rf.sid)) continue; // never walked (build_profile_list)
        const auto f = win::profile_record_failure(rf.key_open, rf.rc);
        discovery_rows.push_back(failure_row("windows", "-", "-", f.denied, f.cause, acc));
    }
    const auto hku_subkeys = yuzu::win::enumerate_hku_subkeys();
    const auto profiles = yuzu::profiles::build_profile_list(discovery.records, hku_subkeys);

    // The one per-profile read. assemble_windows_rows has already validated the SID (a malformed or
    // empty one never reaches here), so it is safe to append to HKEY_USERS.
    const win::ReadProfileFn read_profile = [&](const yuzu::profiles::ProfileInfo& profile) {
        win::ProfileRead rd;
        yuzu::win::HiveAccessReport report;
        Win32HiveFileProbe probe;
        win::HiveFileGuard guard{probe, [&] { return budget.expired(); }, profile.sid, std::nullopt};
        const yuzu::win::OfflineHiveFileCheck check{
            [&](const std::wstring& p) { return guard.before_load(p); },
            [&](const std::wstring& p) { return guard.after_load(p); }};
        // Synchronous, like every other with_user_hive consumer: no detached worker can outlive
        // the dispatch (sdk plugin.hpp: a plugin must not defer work past unload). The walk
        // re-checks the deadline after with_user_hive's lock wait and mount, which count toward it.
        const auto log_unload_failed = [&] {
            const std::string pname = profile.profile_name.empty() ? "-" : profile.profile_name;
            spdlog::error("privacy_permissions: hive unload failed for profile {} (HKU\\{}): its "
                          "NTUSER.DAT stays locked, and the user's next sign-in may not load the "
                          "profile, until `reg unload HKU\\{}` succeeds",
                          pname, report.mount_name, report.mount_name);
        };
        try {
            rd.status = yuzu::win::with_user_hive(
                profile.sid, profile.profile_path,
                [&](HKEY root) { rd.walk = win::walk_consent_store(reg, root, budget); }, &report, &check);
        } catch (...) {
            // The ABI catch turns this into `internal_error`, which carries no row token, so the
            // agent log is the only place the mount name (the actionable fact) can go.
            if (report.unload_failed) log_unload_failed();
            throw;
        }
        rd.refusal = std::move(report.refusal);
        rd.live_open_rc = report.live_open_rc; // set by with_user_hive before anything can throw
        rd.unload_failed = report.unload_failed;
        if (report.unload_failed) log_unload_failed();
        return rd;
    };

    auto rows = win::assemble_windows_rows(profiles, hklm, std::move(discovery_rows), read_profile,
                                           budget, output, acc);

    // A category no row mentions is `absent` unless a whole-source failure row above already
    // stands for it; a token-only failure (hive_unload_failed, a LastUsedTime* read) covers none.
    fill_uncovered_categories("windows", rows);
    return emit_rows(ctx, rows, acc, false);
}

#endif // !YUZU_PRIVACY_PERMISSIONS_WIN_UNIT_TEST_INTERNALS_ONLY

} // namespace yuzu::privacy_permissions

#endif // defined(_WIN32)
