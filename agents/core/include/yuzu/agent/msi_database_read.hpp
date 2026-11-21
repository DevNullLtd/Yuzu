#pragma once

/**
 * msi_database_read.hpp -- bounded, read-only read of the Property table of ONE
 * cached Windows Installer package (a `C:\Windows\Installer\<name>.msi`), for the
 * msi_packages plugin's `installer_records` action (SAM-46).
 *
 * WHY THIS LIVES IN AGENT-CORE AND NOT IN THE PLUGIN THAT NEEDS IT
 * ---------------------------------------------------------------
 * Same reason dism_bounded_call.hpp and passwd_lookup.hpp live here: the Installer
 * database API has no caller-supplied timeout, so the read runs on a DETACHED thread
 * that is ABANDONED, not cancelled, when the deadline passes. If the worker's code
 * (and its closure thunks, compiled into whichever TU constructs the lambda) lived in
 * the plugin's shared object, the agent's final shutdown could `FreeLibrary` the
 * plugin while the worker was still inside it. The whole worker body, the process-wide
 * single-flight slot and the bounded wait therefore live in agent-core, which is never
 * unloaded. The plugin keeps only: the registry reads, the path gate, the held file
 * handle, and turning a ReadResult into a row. Nothing in the plugin ever runs on a
 * thread that can outlive it.
 *
 * HANDLE RULE. The worker owns every MSIHANDLE it opens (RAII, closed on the worker's
 * own thread) and takes the path by value. After TimedOut the caller must not close
 * or reuse anything the worker captured, and has nothing to close: it never receives
 * a handle. After Rejected nothing ran. A caller that holds its own file handle on the
 * package (the plugin holds a no-reparse one) closes it on its own thread whatever
 * the status; that handle is not shared with the worker.
 *
 * SINGLE FLIGHT. At most ONE database worker is in flight per process. The slot is
 * taken on the DISPATCHING thread before any thread is created and released only by
 * the worker when it returns (or by the caller when the worker was never started), so
 * a timed-out worker keeps the slot until it really returns. A read asked for while
 * the slot is held answers Busy and starts no thread: a hung package pins at most one
 * detached worker however often the action is dispatched.
 *
 * READ ONLY, NOTHING EXECUTED. The database is opened read-only and only the
 * `Property` table is queried. No Installer API that repairs, installs, configures,
 * re-sequences or runs a custom action is called from here (pinned by a lexical case in
 * tests/unit/test_msi_installer_records.cpp).
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <atomic>
#include <chrono>
#include <cstddef>
#include <string>

namespace yuzu::agent::msi {

/// Wall-clock budget for one package read (the plugin passes min(this, what is left of
/// its per-dispatch budget)).
inline constexpr std::chrono::milliseconds kPackageDeadline{5000};

/// Property-table rows fetched at most, and characters read at most from one value.
/// A real package has well under a hundred rows; beyond either cap the package is
/// corrupt or planted and the read fails (never a partial answer presented as whole).
inline constexpr std::size_t kMaxPropertyRows = 4096;
inline constexpr std::size_t kMaxPropertyChars = 4096;

/// The five Property rows the plugin reads. Empty when the table has no such row.
struct PropertyTable {
    std::string product_code;
    std::string upgrade_code;
    std::string product_version;
    std::string manufacturer;
    std::string product_name;
};

struct Outcome {
    enum class Kind {
        Ok,
        ApiUnavailable, ///< not a Windows build
        OpenFailed,     ///< MsiOpenDatabaseW failed; `rc` is its code
        ViewFailed,     ///< open-view / execute failed; `rc` is its code
        ReadFailed,     ///< a fetch or a string read failed, or a row/char cap was exceeded
        Exception,
    } kind = Kind::Ok;
    unsigned rc = 0;
    PropertyTable props; ///< meaningful only when kind == Ok
};

enum class ReadStatus {
    Completed, ///< the worker finished inside the deadline; `outcome` is meaningful
    TimedOut,  ///< the worker is still running, holding the slot; `outcome` is not meaningful
    Busy,      ///< the slot was held by an earlier worker; no thread was started
    Rejected,  ///< the process-wide bounded-call ceiling (or thread creation) refused the
               ///< worker; it never ran and the slot was released
};

struct ReadResult {
    ReadStatus status = ReadStatus::Rejected;
    Outcome outcome;
    /// Wall time this call spent, for the caller's per-dispatch budget accounting.
    std::chrono::milliseconds elapsed{0};
};

/// One in-flight worker at a time. try_acquire() on the dispatching thread; release()
/// only by the worker when it returns (or by the caller when no worker was started).
class SingleFlightSlot {
public:
    [[nodiscard]] bool try_acquire() noexcept {
        return !busy_.exchange(true, std::memory_order_acq_rel);
    }
    void release() noexcept {
        busy_.store(false, std::memory_order_release);
        busy_.notify_all();
    }
    [[nodiscard]] bool in_flight() const noexcept { return busy_.load(std::memory_order_acquire); }
    /// Blocks until the slot is free (no polling). For quiesce and for tests.
    void wait_free() const noexcept { busy_.wait(true, std::memory_order_acquire); }

private:
    std::atomic<bool> busy_{false};
};

/// Reads the Property table of the package at `path_utf8` against the process-wide
/// slot. The caller is expected to have gated the path and to hold its own no-reparse
/// handle on the file for the duration of the call.
[[nodiscard]] YUZU_EXPORT ReadResult read_property_table(const std::string& path_utf8,
                                                         std::chrono::milliseconds deadline);

/// The same read against a caller-owned slot: the seam the unit test uses to hold the
/// slot without needing a genuinely hung read. The slot MUST outlive any worker it was
/// handed to (a TimedOut worker releases it when it returns).
[[nodiscard]] YUZU_EXPORT ReadResult read_property_table(SingleFlightSlot& slot,
                                                         const std::string& path_utf8,
                                                         std::chrono::milliseconds deadline);

/// True while a process-wide worker is in flight. For the plugin's shutdown quiesce.
[[nodiscard]] YUZU_EXPORT bool read_in_flight() noexcept;

} // namespace yuzu::agent::msi
