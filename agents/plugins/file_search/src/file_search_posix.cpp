/**
 * file_search_posix.cpp -- the POSIX shell of the file_search plugin: the live mount table, the leg of each
 * searched unit, the worker thread's environment, the single-flight slot and the name rule of each OS.
 * Everything pure lives in the headers beside it; this file binds the operating system to them. Self-gated
 * to non-Windows (empty there, where the plugin answers `planned`).
 *
 * THREADS. Two kinds run here. The POOL thread is the one the agent called execute() on: it takes the
 * process-wide slot, reads the mount table, builds legs, writes every row and every heartbeat key, and
 * releases the slot. The WORKER is a fresh thread per slice (shared::bounded_call_ex) that runs the walk. A
 * worker touches only heap state it co-owns (its leg, its pattern, its done flag) and the operating system:
 * never the plugin context, the slot or the search state. On a timeout the pool thread stops waiting and the
 * worker runs on, abandoned, until its next syscall returns; the plugin module is pinned in memory at init
 * (file_search_plugin.cpp) so no worker can ever run unmapped code, and nothing here is touched after
 * shutdown() returns except by such a worker, through state it owns.
 *
 * THE CURSOR KEY. 32 random bytes from getentropy, drawn once per process on first use and held for the life
 * of the (pinned) module: init draws it and fails if it cannot, and a re-init never draws another. It is
 * never written anywhere. A cursor is a token the agent signs under it (file_search_volumes.hpp), so a
 * cursor is valid only in the agent process that issued it.
 *
 * THE SLOT. One atomic flag, taken with compare_exchange by run_slice on the pool thread before it reads any
 * state and released only by that pool thread's RAII guard (file_search_driver.hpp). A second concurrent call
 * answers busy at once. A worker never touches it: it sets only its own done flag.
 *
 * THE WORKER'S ENVIRONMENT (WorkerEnvironment), set before the walk and gone with the thread:
 *   Linux  CAP_DAC_READ_SEARCH dropped from the thread's effective set (kept permitted) and raised only
 *          around the lookups that need it, through the leg's around_lookup hook (ScopedCapRaise); the idle
 *          I/O class. The capability scope is HYGIENE, NOT A BOUNDARY: the bit stays permitted on the
 *          thread, so code on it could raise it, and every other thread of the agent holds it effective
 *          (linux_thread_caps.hpp; docs/agent-privilege-model.md).
 *   macOS  dataless materialisation off for the whole walk (a dataless file or directory then fails its open
 *          instead of downloading inside a call the deadline cannot interrupt), and the throttled disk class.
 *
 * NO CONTENT IS READ. A matched regular file is opened (O_RDONLY | O_NONBLOCK | O_NOFOLLOW) for its size,
 * time and extents and never read; no hash of anything is taken anywhere in this plugin.
 */
#include "file_search_execute.hpp"

#if !defined(_WIN32)

#include "component_legs.hpp"

#include <bounded_wait.hpp>
#include <linux_thread_caps.hpp>
#include <macos_dataless_off.hpp>
#include <macos_network_mounts.hpp>
#include <posix_secure_read.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <sys/random.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <yuzu/agent/scoped_cfref.hpp>

#include <CoreFoundation/CoreFoundation.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/resource.h>
#elif defined(__linux__)
#include <sys/syscall.h>
#endif

namespace yuzu::file_search {

namespace {

// ---- process-wide state: the slot, the stop flag, the in-memory search state ----

std::atomic<bool> g_slot{false};
std::atomic<bool> g_stop{false};

/// Touched only by the pool thread that holds the slot (run_slice), never by a worker.
[[nodiscard]] SearchState& search_state() {
    static SearchState state;
    return state;
}

/// The process's cursor key. Drawn once, by whichever call comes first; a failed draw is final for the
/// process, so init keeps failing rather than the plugin running with a key it cannot vouch for.
struct CursorKeyHolder {
    CursorKey key{};
    bool ok{false};
};

[[nodiscard]] const CursorKeyHolder& cursor_key_holder() {
    static const CursorKeyHolder holder = [] {
        CursorKeyHolder h;
        h.ok = ::getentropy(h.key.data(), h.key.size()) == 0;
        if (!h.ok)
            h.key.fill(0); // never leave a partial draw behind
        return h;
    }();
    return holder;
}

#if defined(__APPLE__)
constexpr Os kOs = Os::macos;
#else
constexpr Os kOs = Os::linux_os;
#endif

// ---- the mount table ----

/// The mounts one search reads: those at or under the root and those that contain it.
[[nodiscard]] ci::MountKeep keep_for(const std::string& root) {
    return [&root](const yuzu::shared::MountEntry& e) { return under(e.mount_point, root) || under(root, e.mount_point); };
}

#if defined(__linux__)

/// /proc/<pid>/mountinfo, reached hop by hop from "/" with no link followed (/proc/self is itself a link),
/// streamed through the keep rule: the table is never held whole. nullopt when it cannot be had in full.
[[nodiscard]] std::optional<yuzu::shared::MountTable> read_live_mounts(const std::string& root) {
    namespace sh = yuzu::shared;
    const sh::DirOpen top = sh::open_dir_no_follow("/");
    if (!top.opened())
        return std::nullopt;
    const sh::DirOpen proc = sh::open_dir_no_follow_at(top.dir.fd(), "proc");
    if (!proc.opened())
        return std::nullopt;
    const std::string pid = std::to_string(::getpid());
    const sh::DirOpen mine = sh::open_dir_no_follow_at(proc.dir.fd(), pid.c_str());
    if (!mine.opened())
        return std::nullopt;
    const sh::FileOpen table = sh::open_file_no_follow_at(mine.dir.fd(), "mountinfo");
    if (!table.opened())
        return std::nullopt;
    return ci::read_mount_entries_stream([fd = table.file.fd()](char* buf, std::size_t len) { return ::read(fd, buf, len); },
                                         keep_for(root));
}

#else // __APPLE__

/// getmntinfo_r_np(MNT_NOWAIT): the kernel's cache, answered without a call into any server. The same keep
/// rule as the Linux read; the plan itself lets a later entry for a mount point cover an earlier one. A
/// table of zero entries is a failed read (the root mount is always listed), as is one with more kept
/// mounts than ci::kMaxKeptMounts.
[[nodiscard]] std::optional<yuzu::shared::MountTable> read_live_mounts(const std::string& root) {
    struct statfs* raw = nullptr;
    const int n = ::getmntinfo_r_np(&raw, MNT_NOWAIT);
    const std::unique_ptr<struct statfs, decltype(&::free)> listed{raw, &::free};
    if (n <= 0 || raw == nullptr)
        return std::nullopt;
    yuzu::shared::MountTable table = yuzu::shared::macos_mount_entries(raw, n);
    const ci::MountKeep keep = keep_for(root);
    std::erase_if(table.entries, [&keep](const yuzu::shared::MountEntry& e) { return !keep(e); });
    if (table.entries.size() > ci::kMaxKeptMounts)
        return std::nullopt;
    return table;
}

#endif

} // namespace

// ---- the leg of one unit ----

/// The hook the leg wraps around every lookup that may need the capability. Linux: raise it for the lookup
/// and drop it after. macOS: none. Declared in file_search_execute.hpp: the shell test runs this one.
ci::AroundLookup around_lookup_hook() {
#if defined(__linux__)
    return [](const std::function<void()>& lookup) {
        const yuzu::shared::thread_caps::ScopedCapRaise raise;
        lookup();
    };
#else
    return {};
#endif
}

namespace {

[[nodiscard]] UnitLeg make_live_leg(const Unit& unit) {
    // The cell the extent hook fills while the leaf is open; the facts wrapper below reads it back. One walk
    // runs one leg at a time on one worker, so no lock is needed.
    const auto cell = std::make_shared<FileExtents>();
    ci::SearchHooks hooks;
    hooks.around_lookup = around_lookup_hook();
    hooks.read_extents = [cell](int fd, const struct stat& st) { *cell = read_file_extents(fd, st); };
    ci::SearchLeg leg = ci::make_search_leg(unit.prune, {}, std::move(hooks));

    UnitLeg out;
    out.ops = std::move(leg.ops);
    out.root_state = std::move(leg.root_state);
    out.facts = [facts = std::move(leg.facts), cell](const std::string& dir, const std::string& name) {
        *cell = FileExtents{};
        cell->state = ExtentsState::failed; // stays so when the leg never reached the extent reader
        FileFacts f;
        f.facts = facts(dir, name);
        if (f.facts.opened)
            f.extents = std::move(*cell);
        return f;
    };
    return out;
}

// ---- the worker ----

/// What the worker thread sets up before the walk. Linux settings die with the thread; the macOS dataless
/// guard is restored by its destructor, so it is held across the WHOLE walk by living in this object.
class WorkerEnvironment {
public:
    WorkerEnvironment() noexcept {
#if defined(__linux__)
        (void)yuzu::shared::thread_caps::drop_effective(yuzu::shared::thread_caps::kCapDacReadSearch);
        // IOPRIO_WHO_PROCESS with who 0 is the calling thread; class IDLE (3) in the class bits.
        (void)::syscall(SYS_ioprio_set, 1, 0, 3 << 13);
#elif defined(__APPLE__)
        (void)::setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_THREAD, IOPOL_THROTTLE);
#endif
    }

private:
#if defined(__APPLE__)
    yuzu::shared::DatalessMaterializationOff dataless_off_;
#endif
};

} // namespace

/// Runs `work` on a fresh worker thread for at most `timeout`. The work runs inside the worker environment,
/// whose scope is the whole call of `work`; a throw before or after it is a failed result, never a timeout.
/// Declared in file_search_execute.hpp: the shell test runs this one.
RunOutcome<WorkResult> run_on_worker(std::chrono::milliseconds timeout, std::function<WorkResult()> work) {
    auto ran = yuzu::shared::bounded_call_ex(timeout, [work = std::move(work)]() -> WorkResult {
        try {
            const WorkerEnvironment environment;
            return work();
        } catch (...) {
            WorkResult failed;
            failed.threw = true;
            return failed;
        }
    });
    RunOutcome<WorkResult> out;
    switch (ran.status) {
    case yuzu::shared::BoundedCallStatus::Completed:
        out.status = RunStatus::completed;
        out.value = std::move(ran.value);
        break;
    case yuzu::shared::BoundedCallStatus::TimedOut:
        out.status = RunStatus::timed_out;
        break;
    case yuzu::shared::BoundedCallStatus::Rejected:
        out.status = RunStatus::rejected;
        break;
    }
    return out;
}

// ---- names ----

#if defined(__APPLE__)

std::string macos_canonical_name(std::string_view name) {
    // The common case needs no CoreFoundation.
    if (std::ranges::all_of(name, [](unsigned char c) { return c < 0x80; })) {
        std::string out(name);
        for (auto& c : out)
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');
        return out;
    }
    using yuzu::agent::ScopedCFRef;
    // Not well-formed UTF-8: CoreFoundation refuses it, and the name compares as the bytes it is.
    // char to unsigned char: the aliasing every byte API permits; `name` outlives the call and CoreFoundation
    // copies the bytes.
    const ScopedCFRef<CFStringRef> text(CFStringCreateWithBytes(
        kCFAllocatorDefault, reinterpret_cast<const UInt8*>(name.data()), static_cast<CFIndex>(name.size()),
        kCFStringEncodingUTF8, false));
    if (!text)
        return std::string(name);
    ScopedCFRef<CFMutableStringRef> work(CFStringCreateMutableCopy(kCFAllocatorDefault, 0, text.get()));
    if (!work)
        return std::string(name);
    CFStringNormalize(work.get(), kCFStringNormalizationFormC);
    CFStringFold(work.get(), kCFCompareCaseInsensitive, nullptr);
    CFStringNormalize(work.get(), kCFStringNormalizationFormC); // folding can leave a sequence unnormalised
    const CFIndex room = CFStringGetMaximumSizeForEncoding(CFStringGetLength(work.get()), kCFStringEncodingUTF8) + 1;
    std::string out(static_cast<std::size_t>(room), '\0');
    if (CFStringGetCString(work.get(), out.data(), room, kCFStringEncodingUTF8) == 0)
        return std::string(name);
    out.resize(std::char_traits<char>::length(out.c_str()));
    return out;
}

fsr::NameSemantics posix_name_semantics() {
    return {"macos_nfc_casefold_v1", [](std::string_view s) { return macos_canonical_name(s); }};
}

#else

fsr::NameSemantics posix_name_semantics() {
    return fsr::byte_exact();
}

#endif

// ---- the slice ----

SliceResult run_posix_slice(const Request& req) {
    Boundaries b{.state = search_state(), .slot = g_slot};
    b.read_mounts = &read_live_mounts;
    b.make_leg = &make_live_leg;
    b.run_bounded = &run_on_worker;
    b.now = [] { return fsr::Clock::now(); };
    b.sleep = [](std::chrono::milliseconds d) { std::this_thread::sleep_for(d); };
    b.stop_requested = [] { return g_stop.load(std::memory_order_acquire); };
    b.os = kOs;
    b.cursor_key = cursor_key_holder().key; // all zero if the draw failed: run_slice refuses it
    return run_slice(req, b);
}

bool posix_init_cursor_key() noexcept {
    return cursor_key_holder().ok;
}

void posix_request_stop() noexcept {
    g_stop.store(true, std::memory_order_release);
}

void posix_clear_stop() noexcept {
    g_stop.store(false, std::memory_order_release);
}

} // namespace yuzu::file_search

#endif // !_WIN32
