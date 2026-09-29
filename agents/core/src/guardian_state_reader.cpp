#include "guardian_state_reader.hpp"

#include "guardian_rule_eval.hpp"   // read_known / read_unknown + snapshot types
#include <yuzu/agent/file_hash.hpp> // sha256_from_fd / sha256_from_handle (#807)
#include <yuzu/agent/spark.hpp>     // SparkSpec / SparkType / spark_key (single-flight key)

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>

#ifndef _WIN32
#include <cerrno>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)
#include <cstdlib> // free
#include <optional>
#include <string_view>

#include <systemd/sd-bus.h>

#include <yuzu/agent/guard_systemd.hpp> // parse_active_state + pure systemd helpers
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Self-sufficient link (#1287): this TU calls advapi32 directly (RegOpenKeyExW,
// RegQueryValueExW, RegCloseKey, OpenSCManagerW, OpenServiceW,
// QueryServiceStatusEx). Don't rely on a sibling TU's pragma to carry advapi32
// across the whole yuzu_agent_core link line - mirrors guard_registry.cpp /
// guard_service.cpp.
#pragma comment(lib, "advapi32.lib")

#include <vector>

#include <win_sc_handle.hpp> // yuzu::win::ScHandle (RAII SC_HANDLE)
#include <win_str.hpp>       // yuzu::win::to_wide / from_wide
#endif

namespace yuzu::agent {
namespace {

// Bounded retries when a file mutates between the metadata read and the hash: a
// file that keeps changing across all attempts is reported Unknown (transient),
// never a stale digest.
constexpr int kHashAttempts = 3;

#ifndef _WIN32
// Close-on-scope guard for an owned fd (the reader opens and closes within one
// call; nothing escapes).
struct FdGuard {
    int fd;
    explicit FdGuard(int f) : fd(f) {}
    ~FdGuard() {
        if (fd >= 0)
            ::close(fd);
    }
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;
};

std::int64_t stat_mtime_ns(const struct stat& st) {
#ifdef __APPLE__
    return static_cast<std::int64_t>(st.st_mtimespec.tv_sec) * 1'000'000'000 + st.st_mtimespec.tv_nsec;
#else
    return static_cast<std::int64_t>(st.st_mtim.tv_sec) * 1'000'000'000 + st.st_mtim.tv_nsec;
#endif
}

// Inode change time: unlike mtime it also moves on a content write and cannot be
// restored by an unprivileged writer (there is no utimes for ctime), so adding it
// to the mutation-stability check closes a same-size + mtime-preserving in-place
// write that would otherwise pass revalidation with a stale/mixed digest.
std::int64_t stat_ctime_ns(const struct stat& st) {
#ifdef __APPLE__
    return static_cast<std::int64_t>(st.st_ctimespec.tv_sec) * 1'000'000'000 + st.st_ctimespec.tv_nsec;
#else
    return static_cast<std::int64_t>(st.st_ctim.tv_sec) * 1'000'000'000 + st.st_ctim.tv_nsec;
#endif
}

// Opaque change-detection token (device + inode); convergence uses it to spot a
// replace-in-place. NOT part of any verdict.
std::string file_identity(const struct stat& st) {
    return std::to_string(static_cast<std::uint64_t>(st.st_dev)) + ":" +
           std::to_string(static_cast<std::uint64_t>(st.st_ino));
}
#endif // !_WIN32

#ifdef _WIN32
// Close-on-scope guard for an owned HANDLE so an exception between a
// successful CreateFileW and the intended CloseHandle (e.g. bad_alloc from a
// std::to_string/string-concat while building a snapshot) cannot leak it.
struct HandleGuard {
    HANDLE h;
    explicit HandleGuard(HANDLE handle) : h(handle) {}
    ~HandleGuard() {
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
};

// Close-on-scope guard for an owned HKEY so an exception from the value loop
// (emplace / to_wide / vector alloc) cannot leak the key.
struct RegKeyGuard {
    HKEY h = nullptr;
    RegKeyGuard() = default; // a user-declared (deleted) copy ctor suppresses the implicit default
    ~RegKeyGuard() {
        if (h)
            RegCloseKey(h);
    }
    RegKeyGuard(const RegKeyGuard&) = delete;
    RegKeyGuard& operator=(const RegKeyGuard&) = delete;
};

// Mirrors guard_registry.cpp's parse_hive (anonymous there, reimplemented here).
HKEY parse_hive_local(const std::string& hive) {
    if (hive == "HKLM")
        return HKEY_LOCAL_MACHINE;
    if (hive == "HKCU")
        return HKEY_CURRENT_USER;
    if (hive == "HKCR")
        return HKEY_CLASSES_ROOT;
    if (hive == "HKU")
        return HKEY_USERS;
    return nullptr;
}

// Read ONE value under an already-open key and G4-encode it exactly as
// guard_registry.cpp's read_value does (REG_DWORD/QWORD -> decimal, REG_SZ/
// REG_EXPAND_SZ -> UTF-8 with trailing NULs stripped, any other type ->
// <unsupported-type> so a type the guard cannot compare drifts rather than
// falsely matches). A value that is not present is a KNOWN absent snapshot; a
// non-not-found Win32 error is a transient Unknown.
ReadResult<RegistrySnapshot> read_one_value(HKEY h, const std::string& value_name) {
    const std::wstring wv = yuzu::win::to_wide(value_name);
    DWORD type = 0;
    DWORD size = 0;
    LONG rc = RegQueryValueExW(h, wv.c_str(), nullptr, &type, nullptr, &size);
    if (rc == ERROR_FILE_NOT_FOUND)
        return read_known(RegistrySnapshot{}) /* default: present=false -> "<absent>" */;
    if (rc != ERROR_SUCCESS)
        return read_unknown<RegistrySnapshot>("RegQueryValueExW(size) rc=" + std::to_string(rc));

    std::vector<BYTE> data(size ? size : 1);
    DWORD data_size = size;
    rc = RegQueryValueExW(h, wv.c_str(), nullptr, &type, data.data(), &data_size);
    if (rc == ERROR_FILE_NOT_FOUND)
        return read_known(RegistrySnapshot{}) /* default: present=false -> "<absent>" */;
    if (rc != ERROR_SUCCESS)
        return read_unknown<RegistrySnapshot>("RegQueryValueExW(data) rc=" + std::to_string(rc));

    RegistrySnapshot snap;
    snap.present = true;
    switch (type) {
    case REG_DWORD: {
        // A malformed (short) payload must NOT decode as a fabricated 0 - that
        // would falsely comply with an expected value of "0". Require exactly the
        // declared width, else mark unsupported (fail-loud "<unsupported-type>").
        if (data_size != sizeof(DWORD)) {
            snap.supported = false;
            break;
        }
        DWORD dw = 0;
        std::memcpy(&dw, data.data(), sizeof(DWORD));
        snap.value = std::to_string(dw);
        break;
    }
    case REG_QWORD: {
        if (data_size != sizeof(std::uint64_t)) {
            snap.supported = false;
            break;
        }
        std::uint64_t qw = 0;
        std::memcpy(&qw, data.data(), sizeof(std::uint64_t));
        snap.value = std::to_string(qw);
        break;
    }
    case REG_SZ:
    case REG_EXPAND_SZ: {
        if (data_size % sizeof(wchar_t) != 0) { // not a whole number of UTF-16 units
            snap.supported = false;
            break;
        }
        // Copy into a wchar_t-aligned buffer (a vector<BYTE> is only byte-aligned,
        // so a typed reinterpret would be misaligned access), then strip trailing
        // NUL terminator(s).
        std::wstring w(data_size / sizeof(wchar_t), L'\0');
        if (!w.empty())
            std::memcpy(w.data(), data.data(), data_size);
        while (!w.empty() && w.back() == L'\0')
            w.pop_back();
        snap.value = yuzu::win::from_wide(w.c_str(), static_cast<int>(w.size()));
        break;
    }
    default:
        snap.supported = false; // -> "<unsupported-type>" drift, never a false match
        break;
    }
    return read_known(std::move(snap));
}
#endif // _WIN32

// ── read_file_blocking (cross-platform; runs on the executor's detached worker) ──
#ifndef _WIN32
ReadResult<FileSnapshot> read_file_blocking(const FileSparkParams& p, const FileReadPlan& plan) {
    // Follow symlinks (legacy sha256_file semantics), but pin the RESOLVED inode
    // for the whole read: we fstat + hash + revalidate on the SAME fd, so there
    // is no second path-open swap window (the #807 hazard applies to hash-then-
    // reopen-by-path, not to a single read). O_NONBLOCK so a FIFO/device cannot
    // hang the open; O_CLOEXEC so a fork never leaks the fd.
    const int fd = ::open(p.path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        const int e = errno;
        if (e == ENOENT || e == ENOTDIR)
            return read_known(FileSnapshot{}) /* default: exists=false -> "<absent>" */;
        if (e == EACCES || e == EPERM || e == ELOOP) {
            // We could not open the target for read (permission, or an unresolvable
            // symlink). Since we FOLLOW symlinks, establish the TARGET's state with
            // stat (which also follows) - lstat would only prove the LINK exists and
            // could report a dangling/looping link as present. stat succeeds ->
            // exists but unreadable (Known drift); stat ENOENT -> target absent
            // (Known); any other stat failure (a parent-dir search denial, a loop)
            // -> cannot determine (Unknown), never a fabricated present.
            struct stat ts{};
            if (::stat(p.path.c_str(), &ts) == 0) {
                FileSnapshot snap;
                snap.exists = true;
                snap.readable = false; // persistent: permission on an existing target
                snap.size = static_cast<std::uint64_t>(ts.st_size);
                snap.identity = file_identity(ts);
                snap.mtime_ns = stat_mtime_ns(ts);
                return read_known(std::move(snap));
            }
            if (errno == ENOENT || errno == ENOTDIR)
                return read_known(FileSnapshot{}) /* default: exists=false -> "<absent>" */;
            return read_unknown<FileSnapshot>(std::string{"open/stat: "} + std::strerror(e));
        }
        return read_unknown<FileSnapshot>(std::string{"open: "} + std::strerror(e));
    }
    const FdGuard guard{fd};

    struct stat st{};
    if (::fstat(fd, &st) != 0)
        return read_unknown<FileSnapshot>(std::string{"fstat: "} + std::strerror(errno));

    if (!S_ISREG(st.st_mode)) {
        // A directory / FIFO / device where a regular file is expected: it exists
        // but its content cannot be verified -> persistent "<unreadable>" drift.
        FileSnapshot snap;
        snap.exists = true;
        snap.readable = false;
        snap.size = static_cast<std::uint64_t>(st.st_size);
        snap.identity = file_identity(st);
        snap.mtime_ns = stat_mtime_ns(st);
        return read_known(std::move(snap));
    }

    FileSnapshot snap;
    snap.exists = true;
    snap.readable = true;
    snap.size = static_cast<std::uint64_t>(st.st_size);
    snap.identity = file_identity(st);
    snap.mtime_ns = stat_mtime_ns(st);

    // No hash requested (exists-only rules on the key), or the file is larger
    // than the largest admitting cap -> leave hash empty; the evaluator projects
    // oversize per rule off its own max_bytes.
    if (plan.hash_cap == 0 || snap.size > plan.hash_cap)
        return read_known(std::move(snap));

    std::int64_t ctime_ns = stat_ctime_ns(st); // stability input only; not in the snapshot
    for (int attempt = 0; attempt < kHashAttempts; ++attempt) {
        const std::string h = sha256_from_fd(fd, static_cast<std::size_t>(plan.hash_cap));
        struct stat st2{};
        if (::fstat(fd, &st2) != 0)
            return read_unknown<FileSnapshot>(std::string{"re-fstat: "} + std::strerror(errno));

        const bool stable = file_identity(st2) == snap.identity &&
                            static_cast<std::uint64_t>(st2.st_size) == snap.size &&
                            stat_mtime_ns(st2) == snap.mtime_ns && stat_ctime_ns(st2) == ctime_ns;
        if (stable) {
            // Metadata unchanged across the hash: an empty digest here means a
            // genuine read failure (size is <= cap, so it is not over-cap) ->
            // transient Unknown, never a false "<unreadable>".
            if (h.empty())
                return read_unknown<FileSnapshot>("hash read failed");
            snap.hash = h;
            return read_known(std::move(snap));
        }

        // Mutated during the hash: adopt the new metadata and retry. If it grew
        // past the cap it is now oversize for every rule -> Known, empty hash.
        snap.size = static_cast<std::uint64_t>(st2.st_size);
        snap.identity = file_identity(st2);
        snap.mtime_ns = stat_mtime_ns(st2);
        ctime_ns = stat_ctime_ns(st2);
        if (snap.size > plan.hash_cap)
            return read_known(std::move(snap));
    }
    return read_unknown<FileSnapshot>("file mutating during hash, retries exhausted");
}
#else  // _WIN32
ReadResult<FileSnapshot> read_file_blocking(const FileSparkParams& p, const FileReadPlan& plan) {
    // Follow reparse points (no OPEN_REPARSE_POINT) to match the POSIX
    // symlink-follow semantics; FILE_SHARE_* keeps us from blocking writers, and
    // hashing from the single owned HANDLE keeps the read consistent. BACKUP
    // semantics let a directory open so we can detect+report it as unreadable.
    const std::wstring wpath = yuzu::win::to_wide(p.path);
    HANDLE fh = CreateFileW(wpath.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (fh == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
            return read_known(FileSnapshot{}) /* default: exists=false -> "<absent>" */;
        if (e == ERROR_SHARING_VIOLATION) {
            // Held open by someone with a restrictive share mode: the target
            // demonstrably exists but we cannot read it -> unreadable drift.
            FileSnapshot snap;
            snap.exists = true;
            snap.readable = false;
            return read_known(std::move(snap));
        }
        if (e == ERROR_ACCESS_DENIED) {
            // A read denial does not itself prove the target exists (it may be a
            // traversal denial on a directory component, or a dangling reparse
            // point). Reopen for METADATA ONLY: desired access 0 still FOLLOWS the
            // reparse point (no OPEN_REPARSE_POINT) but needs no read permission,
            // so a successful open proves the FOLLOWED target exists;
            // ERROR_*_NOT_FOUND is absent; any other failure is Unknown (never a
            // fabricated present). GetFileAttributesExW is NOT used - its reparse
            // follow semantics are ambiguous and could pass on the link alone.
            HANDLE mh = CreateFileW(wpath.c_str(), 0,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (mh != INVALID_HANDLE_VALUE) {
                HandleGuard mguard{mh};
                FileSnapshot snap;
                snap.exists = true;
                snap.readable = false;
                BY_HANDLE_FILE_INFORMATION mbi{};
                if (GetFileInformationByHandle(mh, &mbi)) {
                    snap.size = (static_cast<std::uint64_t>(mbi.nFileSizeHigh) << 32) | mbi.nFileSizeLow;
                    snap.identity =
                        std::to_string(mbi.dwVolumeSerialNumber) + ":" +
                        std::to_string((static_cast<std::uint64_t>(mbi.nFileIndexHigh) << 32) |
                                       mbi.nFileIndexLow);
                    snap.mtime_ns = static_cast<std::int64_t>(
                        (static_cast<std::uint64_t>(mbi.ftLastWriteTime.dwHighDateTime) << 32) |
                        mbi.ftLastWriteTime.dwLowDateTime);
                }
                return read_known(std::move(snap));
            }
            const DWORD me = GetLastError();
            if (me == ERROR_FILE_NOT_FOUND || me == ERROR_PATH_NOT_FOUND)
                return read_known(FileSnapshot{}) /* target absent */;
            return read_unknown<FileSnapshot>(
                "CreateFileW ACCESS_DENIED + metadata-open error " + std::to_string(me));
        }
        return read_unknown<FileSnapshot>("CreateFileW error " + std::to_string(e));
    }
    HandleGuard guard{fh};

    auto info_of = [](HANDLE h, BY_HANDLE_FILE_INFORMATION& bi) -> bool {
        return GetFileInformationByHandle(h, &bi) != 0;
    };
    auto identity_of = [](const BY_HANDLE_FILE_INFORMATION& bi) -> std::string {
        return std::to_string(bi.dwVolumeSerialNumber) + ":" +
               std::to_string((static_cast<std::uint64_t>(bi.nFileIndexHigh) << 32) |
                              bi.nFileIndexLow);
    };
    auto size_of = [](const BY_HANDLE_FILE_INFORMATION& bi) -> std::uint64_t {
        return (static_cast<std::uint64_t>(bi.nFileSizeHigh) << 32) | bi.nFileSizeLow;
    };
    auto mtime_of = [](const BY_HANDLE_FILE_INFORMATION& bi) -> std::int64_t {
        return static_cast<std::int64_t>((static_cast<std::uint64_t>(bi.ftLastWriteTime.dwHighDateTime)
                                          << 32) |
                                         bi.ftLastWriteTime.dwLowDateTime);
    };
    // ChangeTime (metadata/content change time) is not in BY_HANDLE_FILE_INFORMATION;
    // it is the Windows analogue of POSIX ctime for the mutation-stability check
    // (a same-size + same-write-time in-place write still moves ChangeTime).
    auto changetime_of = [](HANDLE h) -> std::optional<std::int64_t> {
        FILE_BASIC_INFO fbi{};
        if (GetFileInformationByHandleEx(h, FileBasicInfo, &fbi, sizeof(fbi)))
            return static_cast<std::int64_t>(fbi.ChangeTime.QuadPart);
        return std::nullopt; // unavailable -> dropped from the stability comparison
    };

    BY_HANDLE_FILE_INFORMATION bi{};
    if (!info_of(fh, bi))
        return read_unknown<FileSnapshot>("GetFileInformationByHandle error " +
                                          std::to_string(GetLastError()));

    if (bi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        FileSnapshot snap;
        snap.exists = true;
        snap.readable = false; // a directory where a file is expected -> unverifiable
        snap.size = size_of(bi);
        snap.identity = identity_of(bi);
        snap.mtime_ns = mtime_of(bi);
        return read_known(std::move(snap));
    }

    FileSnapshot snap;
    snap.exists = true;
    snap.readable = true;
    snap.size = size_of(bi);
    snap.identity = identity_of(bi);
    snap.mtime_ns = mtime_of(bi);

    if (plan.hash_cap == 0 || snap.size > plan.hash_cap)
        return read_known(std::move(snap));

    std::optional<std::int64_t> change_time = changetime_of(fh); // stability input only
    for (int attempt = 0; attempt < kHashAttempts; ++attempt) {
        const std::string h = sha256_from_handle(fh, static_cast<std::size_t>(plan.hash_cap));
        BY_HANDLE_FILE_INFORMATION bi2{};
        if (!info_of(fh, bi2))
            return read_unknown<FileSnapshot>("re-GetFileInformationByHandle error " +
                                              std::to_string(GetLastError()));
        const std::optional<std::int64_t> ct2 = changetime_of(fh);
        // ChangeTime only vetoes stability when BOTH reads produced a value; if
        // either is unavailable it drops out (identity+size+mtime still gate), so a
        // transient info failure cannot false-mutate or force a spurious Unknown.
        const bool ct_stable = (!change_time || !ct2) ? true : (*ct2 == *change_time);
        const bool stable = identity_of(bi2) == snap.identity && size_of(bi2) == snap.size &&
                            mtime_of(bi2) == snap.mtime_ns && ct_stable;
        if (stable) {
            if (h.empty())
                return read_unknown<FileSnapshot>("hash read failed");
            snap.hash = h;
            return read_known(std::move(snap));
        }
        snap.size = size_of(bi2);
        snap.identity = identity_of(bi2);
        snap.mtime_ns = mtime_of(bi2);
        change_time = ct2;
        if (snap.size > plan.hash_cap)
            return read_known(std::move(snap));
    }
    return read_unknown<FileSnapshot>("file mutating during hash, retries exhausted");
}
#endif // _WIN32

// ── read_registry_blocking (Windows only; Unknown elsewhere) ─────────────────
RegistryRead read_registry_blocking(const RegistrySparkParams& p, const RegistryReadPlan& plan) {
    RegistryRead out;
#ifdef _WIN32
    HKEY root = parse_hive_local(p.hive);
    if (!root) {
        for (const auto& v : plan.value_names)
            out.values.emplace(v, read_unknown<RegistrySnapshot>("unknown hive: " + p.hive));
        return out;
    }
    RegKeyGuard kg;
    const LONG rc = RegOpenKeyExW(root, yuzu::win::to_wide(p.key).c_str(), 0, KEY_READ, &kg.h);
    if (rc != ERROR_SUCCESS) {
        // Key absent -> every requested value is a KNOWN absent snapshot; any
        // other open error is transient -> Unknown per value.
        const bool absent = (rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND);
        for (const auto& v : plan.value_names) {
            out.values.emplace(v, absent ? read_known(RegistrySnapshot{}) /* default: present=false -> "<absent>" */
                                         : read_unknown<RegistrySnapshot>("RegOpenKeyExW rc=" +
                                                                          std::to_string(rc)));
        }
        return out;
    }
    const auto t0 = std::chrono::steady_clock::now();
    for (const auto& v : plan.value_names)
        out.values.emplace(v, read_one_value(kg.h, v)); // kg closes the key (exception-safe)
    out.latency_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0)
            .count());
#else
    // The registry type never arms off Windows; a rule that somehow reaches here
    // cannot be evaluated -> Unknown (never a fabricated absent).
    for (const auto& v : plan.value_names)
        out.values.emplace(v, read_unknown<RegistrySnapshot>("registry unsupported on this platform"));
#endif
    return out;
}

// ── read_service_blocking (Linux sd_bus / Windows SCM; Unknown elsewhere) ─────
#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)
constexpr const char* kDest      = "org.freedesktop.systemd1";
constexpr const char* kMgrPath   = "/org/freedesktop/systemd1";
constexpr const char* kMgrIface  = "org.freedesktop.systemd1.Manager";
constexpr const char* kUnitIface = "org.freedesktop.systemd1.Unit";

// Total sd-bus budget for the whole read (LoadUnit + ActiveState). The executor
// already bounds the SUBMITTER at the service deadline; this bounds the WORKER's
// own wall time by splitting the budget across the two sequential method calls, so
// a wedged broker cannot leave the worker (and thus the service slot + key) held
// for ~2x the per-method timeout. The libsystemd default is ~25s.
constexpr std::uint64_t kSdBusTotalBudgetUs = 5'000'000; // 5s

// Reader-local absence classification. The shared systemd_error_name_is_absence
// folds org.freedesktop.DBus.Error.ServiceUnknown into "absent", but for calls
// addressed to the org.freedesktop.systemd1 destination ServiceUnknown means that
// DESTINATION is unavailable / not activatable (no systemd), NOT that the unit is
// gone. Treating it as absence would let a reachable bus with no systemd fabricate
// Known Stopped and falsely satisfy a service-stopped rule. Exclude it here (the
// genuine unit-gone names NoSuchUnit / UnknownObject / FileNotFound still count).
bool unit_error_is_absence(const char* name) {
    if (name == nullptr)
        return false;
    if (std::string_view{name} == "org.freedesktop.DBus.Error.ServiceUnknown")
        return false;
    return systemd_error_name_is_absence(name);
}

ReadResult<ServiceRunState> read_service_blocking(const ServiceSparkParams& p) {
    const std::string unit = normalize_unit_name(p.service_name);
    if (!valid_unit_name(unit))
        return read_unknown<ServiceRunState>("invalid unit name: " + p.service_name);

    sd_bus* bus = nullptr;
    int r = sd_bus_open_system(&bus);
    if (r < 0 || bus == nullptr)
        return read_unknown<ServiceRunState>(std::string{"sd_bus_open_system: "} +
                                             std::strerror(r < 0 ? -r : 0));
    struct BusGuard {
        sd_bus* b;
        ~BusGuard() {
            if (b)
                sd_bus_flush_close_unref(b);
        }
    } bus_guard{bus};

    // RAII for sd_bus_error/sd_bus_message/malloc'd C-string ownership so an
    // exception (e.g. bad_alloc from a std::string assignment) between a
    // successful sd-bus call and its manual cleanup call cannot leak the
    // reply/error payload - matches the ownership convention documented for
    // the other sd-bus resources in this function.
    struct SdBusErrorGuard {
        sd_bus_error* e;
        explicit SdBusErrorGuard(sd_bus_error* err) : e(err) {}
        ~SdBusErrorGuard() { sd_bus_error_free(e); }
        SdBusErrorGuard(const SdBusErrorGuard&) = delete;
        SdBusErrorGuard& operator=(const SdBusErrorGuard&) = delete;
    };
    struct SdBusMessageGuard {
        sd_bus_message* m;
        explicit SdBusMessageGuard(sd_bus_message* msg) : m(msg) {}
        ~SdBusMessageGuard() {
            if (m)
                sd_bus_message_unref(m);
        }
        SdBusMessageGuard(const SdBusMessageGuard&) = delete;
        SdBusMessageGuard& operator=(const SdBusMessageGuard&) = delete;
    };
    struct CStrGuard {
        char* s;
        explicit CStrGuard(char* str) : s(str) {}
        ~CStrGuard() {
            if (s)
                free(s);
        }
        CStrGuard(const CStrGuard&) = delete;
        CStrGuard& operator=(const CStrGuard&) = delete;
    };

    // Split the total budget across the two sequential calls: LoadUnit gets the
    // whole budget, ActiveState gets whatever remains.
    const auto t_start = std::chrono::steady_clock::now();
    sd_bus_set_method_call_timeout(bus, kSdBusTotalBudgetUs);

    // Resolve the unit object path (LoadUnit resolves even an inactive unit).
    sd_bus_error err = SD_BUS_ERROR_NULL;
    SdBusErrorGuard err_guard{&err};
    sd_bus_message* reply = nullptr;
    std::string obj_path;
    r = sd_bus_call_method(bus, kDest, kMgrPath, kMgrIface, "LoadUnit", &err, &reply, "s",
                           unit.c_str());
    SdBusMessageGuard reply_guard{reply};
    if (r >= 0 && reply) {
        const char* pth = nullptr;
        if (sd_bus_message_read(reply, "o", &pth) >= 0 && pth && *pth)
            obj_path = pth;
    }
    const bool load_absence = (r < 0) && unit_error_is_absence(err.name);
    if (obj_path.empty()) {
        if (load_absence)
            return read_known(ServiceRunState::Stopped); // R5: absent unit -> Stopped
        return read_unknown<ServiceRunState>("LoadUnit transient failure for " + unit);
    }

    // Bound the second call by the remaining budget; if none remains the whole read
    // has already used its wall-time allowance -> transient Unknown.
    const std::uint64_t elapsed_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() -
                                                              t_start)
            .count());
    if (elapsed_us >= kSdBusTotalBudgetUs)
        return read_unknown<ServiceRunState>("service read budget exhausted after LoadUnit for " +
                                             unit);
    sd_bus_set_method_call_timeout(bus, kSdBusTotalBudgetUs - elapsed_us);

    // Point-read the ActiveState property.
    sd_bus_error perr = SD_BUS_ERROR_NULL;
    SdBusErrorGuard perr_guard{&perr};
    char* s = nullptr;
    r = sd_bus_get_property_string(bus, kDest, obj_path.c_str(), kUnitIface, "ActiveState", &perr,
                                   &s);
    CStrGuard s_guard{s};
    std::optional<SystemdState> st;
    if (r >= 0 && s)
        st = parse_active_state(s);
    else if (unit_error_is_absence(perr.name))
        st = SystemdState::Absent;

    if (!st)
        return read_unknown<ServiceRunState>("ActiveState transient failure for " + unit);
    if (systemd_state_is_transitional(*st))
        // Mid-transition: no terminal verdict to give right now (the mechanism
        // holds on these too). Unknown, not a fabricated running/stopped.
        return read_unknown<ServiceRunState>(std::string{"service mid-transition: "} +
                                             std::string{systemd_state_token(*st)});
    // Terminal: Active -> Running; Inactive / Failed / Absent -> Stopped (R5).
    return read_known(*st == SystemdState::Active ? ServiceRunState::Running
                                                  : ServiceRunState::Stopped);
}
#elif defined(_WIN32)
ReadResult<ServiceRunState> read_service_blocking(const ServiceSparkParams& p) {
    yuzu::win::ScHandle scm;
    scm.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm)
        return read_unknown<ServiceRunState>("OpenSCManager error " +
                                             std::to_string(GetLastError()));
    yuzu::win::ScHandle svc;
    svc.reset(OpenServiceW(scm.get(), yuzu::win::to_wide(p.service_name).c_str(),
                           SERVICE_QUERY_STATUS));
    if (!svc) {
        const DWORD e = GetLastError();
        if (e == ERROR_SERVICE_DOES_NOT_EXIST)
            return read_known(ServiceRunState::Stopped); // R5: absent service -> Stopped
        return read_unknown<ServiceRunState>("OpenService error " + std::to_string(e));
    }
    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;
    const BOOL ok = QueryServiceStatusEx(svc.get(), SC_STATUS_PROCESS_INFO,
                                         reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed);
    if (!ok)
        return read_unknown<ServiceRunState>("QueryServiceStatusEx error " +
                                             std::to_string(GetLastError()));
    switch (ssp.dwCurrentState) {
    case SERVICE_RUNNING:
        return read_known(ServiceRunState::Running);
    case SERVICE_PAUSED:
        return read_known(ServiceRunState::Paused);
    case SERVICE_STOPPED:
        return read_known(ServiceRunState::Stopped);
    case SERVICE_START_PENDING:
    case SERVICE_STOP_PENDING:
    case SERVICE_CONTINUE_PENDING:
    case SERVICE_PAUSE_PENDING:
        return read_unknown<ServiceRunState>("service mid-transition: pending");
    default:
        return read_unknown<ServiceRunState>("unknown SCM state " +
                                             std::to_string(ssp.dwCurrentState));
    }
}
#else
ReadResult<ServiceRunState> read_service_blocking(const ServiceSparkParams&) {
    // No service backend on this platform (e.g. macOS in this rung); a service
    // rule never arms here, so this is only reached defensively -> Unknown.
    return read_unknown<ServiceRunState>("service reader unsupported on this platform");
}
#endif

// ── executor routing ──────────────────────────────────────────────────────────
// Per-class deadlines: file-hash is generous because the 64 MiB (default) cap, an
// unbounded authored max_bytes, and up to kHashAttempts re-hashes on a mutating
// file can exceed 5s on a healthy-but-slow disk (a permanent-Unknown trap);
// metadata-only / registry / service are 5s.
constexpr auto kFileHashDeadline = std::chrono::seconds(15);
constexpr auto kFileMetaDeadline = std::chrono::seconds(5);
constexpr auto kRegistryDeadline = std::chrono::seconds(5);
constexpr auto kServiceDeadline  = std::chrono::seconds(5);

// Map a bounded-I/O failure to a precise, bounded guard.unhealthy detail string.
std::string io_failure_detail(const char* kind, IoFailure f) {
    switch (f) {
    case IoFailure::Timeout:           return std::string{kind} + " read timed out (bounded I/O deadline)";
    case IoFailure::Stopped:           return std::string{kind} + " read cancelled (reader stopping)";
    case IoFailure::CapacityExhausted: return std::string{kind} + " read rejected (I/O executor at capacity)";
    case IoFailure::AlreadyRunning:    return std::string{kind} + " read already in flight (single-flight)";
    case IoFailure::LaunchFailed:      return std::string{kind} + " read worker launch failed";
    case IoFailure::WorkerThrew:       return std::string{kind} + " read worker failed";
    case IoFailure::CeilingExhausted:  return std::string{kind} + " read rejected (I/O executor alive-worker ceiling: completion callbacks outstanding)";
    }
    return std::string{kind} + " read failed";
}

} // namespace

// Public overrides: route each read through the bounded executor (single-flight on
// the canonical spark_key, bulkheaded per type, deadline captured at entry) and map
// any IoFailure to a precise Unknown. The closures capture params/plan BY VALUE, so
// a detached worker never touches `this` or a caller-stack reference.
ReadResult<FileSnapshot> GuardianStateReader::read_file(const FileSparkParams& p,
                                                        const FileReadPlan& plan) {
    const auto deadline = plan.hash_cap > 0 ? kFileHashDeadline : kFileMetaDeadline;
    auto r = executor_.run(IoClass::File, spark_key(SparkSpec{.type = SparkType::File, .params = p}),
                           deadline, [p, plan] { return read_file_blocking(p, plan); });
    if (r)
        return std::move(*r);
    return read_unknown<FileSnapshot>(io_failure_detail("file", r.error()));
}

RegistryRead GuardianStateReader::read_registry(const RegistrySparkParams& p,
                                                const RegistryReadPlan& plan) {
    auto r =
        executor_.run(IoClass::Registry, spark_key(SparkSpec{.type = SparkType::Registry, .params = p}),
                      kRegistryDeadline, [p, plan] { return read_registry_blocking(p, plan); });
    if (r)
        return std::move(*r);
    RegistryRead out;
    const std::string why = io_failure_detail("registry", r.error());
    for (const auto& v : plan.value_names)
        out.values.emplace(v, read_unknown<RegistrySnapshot>(why));
    return out;
}

ReadResult<ServiceRunState> GuardianStateReader::read_service(const ServiceSparkParams& p) {
    auto r =
        executor_.run(IoClass::Service, spark_key(SparkSpec{.type = SparkType::Service, .params = p}),
                      kServiceDeadline, [p] { return read_service_blocking(p); });
    if (r)
        return std::move(*r);
    return read_unknown<ServiceRunState>(io_failure_detail("service", r.error()));
}

} // namespace yuzu::agent
