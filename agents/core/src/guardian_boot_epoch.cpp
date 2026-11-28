#include "guardian_boot_epoch.hpp"

#include <spdlog/spdlog.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <yuzu/agent/scoped_fd.hpp>
#endif

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <system_error>
#include <thread>

namespace yuzu::agent {

const char* guardian_boot_epoch_outcome_name(GuardianBootEpochClaim::Outcome o) noexcept {
    using Outcome = GuardianBootEpochClaim::Outcome;
    switch (o) {
    case Outcome::Claimed:
        return "claimed";
    case Outcome::Recovered:
        return "recovered";
    case Outcome::NoStore:
        return "no_store";
    case Outcome::ReadFailed:
        return "read_failed";
    case Outcome::WriteFailed:
        return "write_failed";
    case Outcome::OutOfRange:
        return "out_of_range";
    case Outcome::DurabilityBelowFull:
        return "durability_below_full";
    case Outcome::InstanceLockNotHeld:
        return "instance_lock_not_held";
    }
    return "unknown";
}

namespace {

using Outcome = GuardianBootEpochClaim::Outcome;

// What the stored row looked like. Kept for the log line only; never the raw bytes.
enum class Stored { Absent, Parsed, Unusable };

struct Detail {
    Stored stored = Stored::Absent;
    std::size_t stored_len = 0;
    std::uint64_t clock = 0;
    std::uint64_t candidate = 0;
    int synchronous = -2; // -2 = not read; -3 = the read threw
};

// Full-consume decimal parse. from_chars stops at the first non-digit, so a suffix or an
// embedded NUL leaves ptr short of end and is rejected; an empty string, a sign, leading
// whitespace and a value above uint64 max are rejected by the error code.
std::optional<std::uint64_t> parse_decimal(const std::string& s) noexcept {
    std::uint64_t v = 0;
    const char* const first = s.data();
    const char* const last = first + s.size();
    const auto [ptr, ec] = std::from_chars(first, last, v);
    if (ec != std::errc{} || ptr != last)
        return std::nullopt;
    return v;
}

GuardianBootEpochClaim claim_impl(IJournalStore* store, std::int64_t now_unix_s, Detail& d,
                                  Outcome& on_throw) {
    if (store == nullptr)
        return {0, Outcome::NoStore, 0};

    on_throw = Outcome::ReadFailed;
    auto entry = store->get_entry(kGuardianBootEpochNamespace, kGuardianBootEpochKey);
    if (!entry.has_value())
        return {0, Outcome::ReadFailed, 0};

    // Clock term: clamped to 0 when the clock reads at or before the epoch of time.
    d.clock = now_unix_s > 0 ? static_cast<std::uint64_t>(now_unix_s) : 0;

    std::uint64_t persisted = 0;
    bool recovered = false;
    if (entry->has_value()) {
        const std::string& raw = **entry;
        d.stored_len = raw.size();
        const auto parsed = parse_decimal(raw);
        // The ceiling check on the PERSISTED value precedes any "+ 1". A value whose
        // successor would reach the ceiling (2^62 - 1 and above, including uint64 max) is
        // unusable: it is re-claimed from the clock, never incremented, and never left to
        // fail the claim on every later boot.
        if (parsed.has_value() && *parsed < kGuardianBootEpochCeiling - 1) {
            persisted = *parsed;
            d.stored = Stored::Parsed;
        } else {
            recovered = true;
            d.stored = Stored::Unusable;
        }
    }

    // Safe: persisted < 2^62 - 1, so persisted + 1 is below the ceiling and cannot wrap. An
    // unusable row re-claims from the clock alone (floor 1, so the epoch is never 0 on a
    // successful claim). Only a clock term at or above the ceiling can still reach it.
    const std::uint64_t lower = recovered ? 1 : persisted + 1;
    d.candidate = std::max(lower, d.clock);

    if (d.candidate >= kGuardianBootEpochCeiling)
        return {0, Outcome::OutOfRange, persisted};

    // The epoch write must be durable, or the next boot can re-issue an equal or lower epoch
    // for events already emitted under this one. SQLite rolls back a committed but unsynced
    // transaction below FULL (OFF, or NORMAL in WAL), so the claim is refused unless the store
    // REPORTS FULL (2) or EXTRA (3). -1 means the store could not read the pragma at all: that is
    // a failed read, not a durability fact, so it is ReadFailed, not DurabilityBelowFull. A
    // throwing read is a failed read too (ReadFailed, nothing written); on_throw is already
    // ReadFailed immediately above the call and stays so until the write below.
    on_throw = Outcome::ReadFailed;
    d.synchronous = -3;
    d.synchronous = store->pragma_synchronous();
    if (d.synchronous == -1)
        return {0, Outcome::ReadFailed, persisted};
    if (d.synchronous < 2)
        return {0, Outcome::DurabilityBelowFull, persisted};

    on_throw = Outcome::WriteFailed;
    char buf[24];
    const auto [end, ec] = std::to_chars(buf, buf + sizeof(buf), d.candidate);
    (void)ec; // 20 digits at most; the buffer cannot overflow
    if (!store->set(kGuardianBootEpochNamespace, kGuardianBootEpochKey,
                    std::string_view(buf, static_cast<std::size_t>(end - buf))))
        return {0, Outcome::WriteFailed, persisted};

    return {d.candidate, recovered ? Outcome::Recovered : Outcome::Claimed, persisted};
}

void log_claim(IJournalStore* store, const GuardianBootEpochClaim& c, Detail& d,
               std::int64_t now_unix_s) noexcept {
    try {
        if (store != nullptr && d.synchronous == -2)
            d.synchronous = store->pragma_synchronous();
        const char* stored = d.stored == Stored::Absent   ? "absent"
                             : d.stored == Stored::Parsed ? "parsed"
                                                          : "unusable";
        const auto level =
            (c.outcome == Outcome::Claimed) ? spdlog::level::info : spdlog::level::err;
        // No raw stored bytes: an unusable row is described by its byte length only.
        spdlog::log(level,
                    "Guardian boot_epoch claim: outcome={} boot_epoch={} stored={} persisted={} "
                    "stored_len={} clock_unix_s={} candidate={} synchronous={}",
                    guardian_boot_epoch_outcome_name(c.outcome), c.boot_epoch, stored, c.persisted,
                    d.stored_len, now_unix_s, d.candidate, d.synchronous);
    } catch (...) {
        // Logging is best-effort and must never change the claim.
    }
}

} // namespace

GuardianBootEpochClaim claim_guardian_boot_epoch(IJournalStore* store,
                                                 std::int64_t now_unix_s) noexcept {
    Detail d;
    Outcome on_throw = Outcome::NoStore;
    GuardianBootEpochClaim claim;
    try {
        claim = claim_impl(store, now_unix_s, d, on_throw);
    } catch (...) {
        // A throwing store is a failed read or write: unordered, nothing invented.
        claim = {0, on_throw, 0};
    }
    log_claim(store, claim, d, now_unix_s);
    return claim;
}

namespace {

const char* lock_state_name(GuardianInstanceLock::State st) noexcept {
    switch (st) {
    case GuardianInstanceLock::State::NotAcquired:
        return "not_acquired";
    case GuardianInstanceLock::State::Held:
        return "held";
    case GuardianInstanceLock::State::Contended:
        return "contended";
    case GuardianInstanceLock::State::Failed:
        return "failed";
    }
    return "unknown";
}

constexpr std::intptr_t kNoHandle = -1;

// A held lock on a file that was unlinked or replaced after the open guards nothing: a second
// process creates and locks the new file. After locking, the path is re-resolved and must name
// the very file that was locked; a mismatch drops the lock and tries again, at most this often.
// POSIX only: on Windows share mode 0 forbids deleting or renaming the open file, so no attempt
// is ever Replaced there (the branch compiles on both legs and is dead on Windows).
constexpr int kMaxReplacedRetries = 5;
#ifdef _WIN32
constexpr int kReplacedError = ERROR_FILE_INVALID; // never reported: Replaced is POSIX only
#else
constexpr int kReplacedError = ESTALE;
#endif

enum class Attempt { Held, Contended, Failed, Replaced };

// One attempt. On Held the handle is stored; otherwise nothing is left open. `err` carries the
// errno / GetLastError of a Failed or Contended attempt (0 when none). `after_flock` is the
// test seam (POSIX): called once the lock is taken and before the path is re-resolved, so a
// test can unlink or replace the file at exactly the point the re-check exists for.
Attempt try_lock_once(const std::filesystem::path& path, std::intptr_t& handle, int& err,
                      [[maybe_unused]] const std::function<void()>* after_flock) noexcept {
    err = 0;
#ifdef _WIN32
    // Share mode 0: a second open of the same file fails with ERROR_SHARING_VIOLATION while
    // this handle lives (which also forbids deleting or renaming it), and the OS closes it at
    // process exit. Nothing between CreateFileW and the store can fail, so no cleanup path.
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = static_cast<int>(::GetLastError());
        return err == ERROR_SHARING_VIOLATION ? Attempt::Contended : Attempt::Failed;
    }
    handle = reinterpret_cast<std::intptr_t>(h);
    return Attempt::Held;
#else
    // O_NOFOLLOW: a planted symlink is refused rather than followed to a file elsewhere.
    // O_NOCTTY: a lock path that names a terminal never becomes the controlling terminal.
    ScopedFd fd;
    do {
        fd.reset(::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY, 0600));
    } while (!fd.valid() && errno == EINTR);
    if (!fd.valid()) {
        err = errno;
        return Attempt::Failed;
    }
    struct stat by_fd {};
    if (::fstat(fd.get(), &by_fd) != 0) {
        err = errno;
        return Attempt::Failed;
    }
    if (!S_ISREG(by_fd.st_mode)) {
        err = EINVAL; // a FIFO or device node (a directory already failed in open with EISDIR)
        return Attempt::Failed;
    }
    // flock locks belong to the open file description, so a second acquire in this same
    // process (a second object, or a test) contends exactly like a second process would.
    if (::flock(fd.get(), LOCK_EX | LOCK_NB) != 0) {
        err = errno;
        return err == EWOULDBLOCK ? Attempt::Contended : Attempt::Failed;
    }
    if (after_flock != nullptr && *after_flock) {
        try {
            (*after_flock)();
        } catch (...) {
            err = EINVAL;
            return Attempt::Failed;
        }
    }
    struct stat by_path {};
    if (::stat(path.c_str(), &by_path) != 0) {
        // ENOENT: unlinked after the open, so the locked file is no longer the lock file.
        // Any other failure (EACCES on a path component, EIO) says nothing about replacement
        // and is reported as what it is.
        if (errno != ENOENT) {
            err = errno;
            return Attempt::Failed;
        }
        return Attempt::Replaced; // fd closes here, which drops the lock
    }
    if (by_path.st_dev != by_fd.st_dev || by_path.st_ino != by_fd.st_ino)
        return Attempt::Replaced;
    handle = fd.release();
    return Attempt::Held;
#endif
}

} // namespace

GuardianInstanceLock::GuardianInstanceLock(GuardianInstanceLock&& other) noexcept
    : handle_(other.handle_), state_(other.state_), native_error_(other.native_error_) {
    other.handle_ = kNoHandle;
    other.state_ = State::NotAcquired;
    other.native_error_ = 0;
}

GuardianInstanceLock& GuardianInstanceLock::operator=(GuardianInstanceLock&& other) noexcept {
    if (this != &other) {
        release();
        handle_ = other.handle_;
        state_ = other.state_;
        native_error_ = other.native_error_;
        other.handle_ = kNoHandle;
        other.state_ = State::NotAcquired;
        other.native_error_ = 0;
    }
    return *this;
}

GuardianInstanceLock::~GuardianInstanceLock() {
    release();
}

void GuardianInstanceLock::release() noexcept {
    if (handle_ != kNoHandle) {
#ifdef _WIN32
        ::CloseHandle(reinterpret_cast<HANDLE>(handle_));
#else
        ::close(static_cast<int>(handle_)); // also drops the flock
#endif
    }
    handle_ = kNoHandle;
    state_ = State::NotAcquired;
    native_error_ = 0;
}

GuardianInstanceLock GuardianInstanceLock::acquire(const std::filesystem::path& path,
                                                   std::chrono::milliseconds wait) noexcept {
    return acquire_impl(path, wait, nullptr);
}

GuardianInstanceLock
GuardianInstanceLock::acquire_for_test(const std::filesystem::path& path,
                                       std::chrono::milliseconds wait,
                                       const std::function<void()>& after_flock) noexcept {
    return acquire_impl(path, wait, &after_flock);
}

GuardianInstanceLock
GuardianInstanceLock::acquire_impl(const std::filesystem::path& path,
                                   std::chrono::milliseconds wait,
                                   const std::function<void()>* after_flock) noexcept {
    GuardianInstanceLock lock;
    try {
        const auto deadline = std::chrono::steady_clock::now() + wait;
        int replaced = 0;
        for (;;) {
            const Attempt a = try_lock_once(path, lock.handle_, lock.native_error_, after_flock);
            if (a == Attempt::Held) {
                lock.state_ = State::Held;
                break;
            }
            if (a == Attempt::Replaced) {
                if (++replaced > kMaxReplacedRetries) {
                    lock.state_ = State::Failed;
                    lock.native_error_ = kReplacedError;
                    break;
                }
                continue; // the path now names a different file: lock that one
            }
            lock.state_ = a == Attempt::Contended ? State::Contended : State::Failed;
            if (a != Attempt::Contended || std::chrono::steady_clock::now() >= deadline)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        }
    } catch (...) {
        // sleep_for / clock cannot realistically throw; if they do the lock is not held.
        lock.release();
        lock.state_ = State::Failed;
    }
    return lock;
}

GuardianBootEpochClaim claim_guardian_boot_epoch(IJournalStore* store, std::int64_t now_unix_s,
                                                 const GuardianInstanceLock& lock) noexcept {
    if (store == nullptr || lock.held())
        return claim_guardian_boot_epoch(store, now_unix_s);
    try {
        // The wording follows the state. Contended means the lock is held by someone else: normally
        // a second agent process, but on Windows any program holding the file open (a backup or
        // security product) reports the same way, with native_error=32.
        const char* why =
            lock.state() == GuardianInstanceLock::State::Contended
                ? "the data directory's boot-epoch lock is held by another process (normally a "
                  "second agent; on Windows any program with the file open)"
            : lock.state() == GuardianInstanceLock::State::Failed
                ? "the boot-epoch lock file could not be opened or locked"
                : "the boot-epoch lock was never acquired";
        spdlog::error("Guardian boot_epoch claim: outcome={} boot_epoch=0 instance_lock={} "
                      "native_error={}; {}, so this process emits unordered (0/0) events",
                      guardian_boot_epoch_outcome_name(Outcome::InstanceLockNotHeld),
                      lock_state_name(lock.state()), lock.native_error(), why);
    } catch (...) {
        // Logging is best-effort and must never change the claim.
    }
    return {0, Outcome::InstanceLockNotHeld, 0};
}

} // namespace yuzu::agent
