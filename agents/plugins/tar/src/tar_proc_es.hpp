#pragma once

/**
 * tar_proc_es.hpp — gap-free process start/stop capture via Endpoint Security.
 *
 * The macOS parity peer of tar_proc_etw.hpp. Subscribes an Endpoint Security
 * client to ES_EVENT_TYPE_NOTIFY_EXEC (→ "started") and ES_EVENT_TYPE_NOTIFY_EXIT
 * (→ "stopped") and decodes each message into the shared bounded ProcEventRing
 * that the TAR plugin drains and persists in batches. This is the event-driven
 * replacement for the sysctl(KERN_PROC_ALL) snapshot-diff poll: the poll misses
 * anything that starts AND exits within an interval and truncates names to the
 * kernel's 15-char p_comm; Endpoint Security does neither (gap-free, full image
 * path, accurate ppid, exit status).
 *
 * Streaming-source parity note: process is the ONLY TAR source Windows streams
 * (ETW); tcp/service/user poll on Windows too, so they stay polls on macOS. This
 * collector closes the one real streaming gap.
 *
 * Entitlement / privilege (hard requirements, mirrored from Apple's contract):
 *   - The host binary must carry com.apple.developer.endpoint-security.client
 *     (an Apple-restricted entitlement) and be signed + notarized for production.
 *   - es_new_client requires root (the macOS agent LaunchDaemon already runs as
 *     root). Without the entitlement / privilege, es_new_client returns
 *     ERR_NOT_ENTITLED / ERR_NOT_PRIVILEGED and start() returns false — the caller
 *     falls back to the existing sysctl poll cleanly.
 * For dev validation on a SIP-disabled / amfi-bypassed host, an unentitled signed
 * binary can create a client; production ship is gated on the entitlement grant.
 *
 * Boot gap (known limitation, parity with ETW): a live client only sees events
 * once it is running, so processes already alive when the agent starts get no
 * "started" row until they exit. macOS has no AutoLogger .etl equivalent and the
 * collector does NOT seed a startup baseline — no worse than the snapshot-diff
 * poll it replaces, whose first tick likewise emits no "started" for the
 * already-running set.
 *
 * EndpointSecurity / libbsm headers are confined to the .cpp (pimpl). Off-macOS
 * every method is a no-op: start() returns false, the ring stays empty, drain()
 * yields nothing — callers degrade cleanly.
 */

#include "tar_proc_stream.hpp" // ProcEvent, ProcEventRing

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::tar {

/// Platform-agnostic projection of the fields read out of an Endpoint Security
/// process message. The macOS handler fills this from es_message_t; the pure
/// es_sample_to_proc_event() mapping turns it into a ProcEvent. Splitting the
/// projection from es_message_t keeps the mapping logic unit-testable without a
/// live ES client or macOS headers.
struct EsProcSample {
    bool is_exec{true};             ///< true = NOTIFY_EXEC (start); false = NOTIFY_EXIT (stop)
    std::int64_t ts_unix{0};        ///< es_message time, unix seconds
    std::uint32_t pid{0};           ///< from audit_token_to_pid
    std::uint32_t ppid{0};          ///< parent pid (exec only; 0 on exit)
    std::string executable_path;    ///< full path from es_process_t->executable
    std::uint32_t uid{0};           ///< audit-token real uid (resolved to user at drain)
    std::int32_t exit_status{0};    ///< raw wait(2) status (exit only)
};

/// Pure mapping from an extracted ES sample to a ProcEvent. Fills every field
/// except `user` (resolved from the audit token's uid by the collector, off this
/// pure path so getpwuid stays cacheable and testable code stays header-free):
///   - image_name = basename(executable_path) — full path collapsed to the leaf,
///     matching the names-only TAR posture (never the command line);
///   - is_start = is_exec; ppid carried on exec only; exit_code on exit only.
/// Defined in the .cpp but exercised on every platform by the unit tests.
ProcEvent es_sample_to_proc_event(const EsProcSample& sample);

/// Resolve a POSIX uid to a username through `lookup`, memoizing the result in
/// `cache`. The collector calls this at DRAIN (the plugin tick thread, never the
/// kernel-serial ES handler queue) with a getpwuid_r-backed lookup; factoring the
/// cache out behind an injectable lookup keeps it portable and unit-testable on
/// every platform without a live passwd database or macOS headers. `lookup` is
/// invoked at most once per distinct uid (skipped on a cache hit).
std::string resolve_uid_cached(std::unordered_map<std::uint32_t, std::string>& cache,
                               std::uint32_t uid,
                               const std::function<std::string(std::uint32_t)>& lookup);

/// Owns an Endpoint Security client subscribed to process exec/exit and decodes
/// each message into a ProcEventRing on the ES-managed handler queue. Single-owner
/// (non-copyable). macOS-only; every method is a no-op on other platforms and
/// start() returns false.
class ProcEsCollector : public ProcStreamCollector {
public:
    /// `ring_capacity` bounds buffered-but-not-yet-drained events. Sized for the
    /// drain cadence × peak spawn rate with headroom; overflow drops with a
    /// counter rather than growing (the ES handler must never block).
    explicit ProcEsCollector(std::size_t ring_capacity = 100000);
    ~ProcEsCollector() override;

    ProcEsCollector(const ProcEsCollector&) = delete;
    ProcEsCollector& operator=(const ProcEsCollector&) = delete;

    /// Create the ES client and subscribe to NOTIFY_EXEC / NOTIFY_EXIT. Returns
    /// false off-macOS, if already running, or on any es_new_client / es_subscribe
    /// failure (including ERR_NOT_ENTITLED / ERR_NOT_PRIVILEGED). A false return
    /// leaves nothing created so callers fall back to the poll cleanly.
    bool start() override;

    /// Unsubscribe and delete the client. Safe if not started.
    void stop() override;

    bool running() const noexcept override;

    /// Move buffered events out for the batched tar.db write (the drain tick).
    /// Returns empty when not running / off-macOS.
    std::vector<ProcEvent> drain() override;

    /// Count of events dropped due to ring overflow since construction.
    std::uint64_t dropped() const noexcept override;

    /// Count of events Endpoint Security dropped kernel-side before delivery
    /// (detected as `seq_num` gaps on the handler queue), distinct from the
    /// userspace ring overflow dropped() reports. 0 off-macOS / before start.
    std::uint64_t kernel_dropped() const noexcept override;

    /// True once the ES stream has been silent past the idle-fallback threshold
    /// while still nominally running — the plugin then re-arms the snapshot-diff
    /// poll (a NOTIFY-only ES client has no liveness API, so prolonged silence is
    /// the only "presumed dead" signal available). Always false off-macOS / before
    /// start. See tar_proc_es.cpp for the threshold and its quiet-host caveat.
    bool stalled() const noexcept override;

    /// Always "endpoint_security".
    const char* method_name() const noexcept override { return "endpoint_security"; }

private:
    struct Impl;                 ///< EndpointSecurity client state; defined only in the .cpp
    std::unique_ptr<Impl> impl_; ///< null off-macOS / when not running
    ProcEventRing ring_;
    /// uid → username cache for drain-time resolution. Touched only from drain()
    /// (the plugin tick thread), so getpwuid_r (which can block on NSS) stays off
    /// the kernel-serial ES handler queue. Bounded by the host's distinct uid count.
    std::unordered_map<std::uint32_t, std::string> uid_cache_;

    /// Cross-thread stream-health state. Deliberately kept on the COLLECTOR (which
    /// outlives impl_) rather than on Impl: kernel_dropped() is read by the status
    /// command thread WITHOUT the plugin's collect_mu_, so dereferencing impl_ there
    /// would race a self-heal stop()/impl_.reset(). Keeping these here also lets the
    /// counts persist across a stop()→re-arm. Written on the ES handler queue through
    /// pointers the Impl borrows; read (relaxed) on the tick/status thread.
    // [[maybe_unused]]: written/read only in the macOS ES build; the no-op build
    // (non-Apple / CLT SDK) never touches them, which would otherwise warn.
    [[maybe_unused]] std::atomic<std::uint64_t> kernel_dropped_{0}; ///< ES seq_num-gap drops
    [[maybe_unused]] std::atomic<std::int64_t> last_event_ts_{0};   ///< unix-sec of last decoded event; 0 = none
    [[maybe_unused]] std::atomic<std::int64_t> started_ts_{0};      ///< unix-sec the live stream started
};

} // namespace yuzu::tar
