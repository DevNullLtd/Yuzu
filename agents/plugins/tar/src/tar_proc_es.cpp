/**
 * tar_proc_es.cpp — Endpoint Security process collector (see tar_proc_es.hpp).
 *
 * macOS: creates an Endpoint Security client, subscribes to NOTIFY_EXEC /
 * NOTIFY_EXIT, decodes each message into the shared ProcEventRing on the
 * ES-managed (serial, per-client) handler queue, and resolves the owning user
 * from the audit token's uid via a handler-local cache.
 *
 * Off-macOS: every method is a no-op; start() returns false.
 *
 * The EndpointSecurity / libbsm headers are confined to this translation unit.
 */

#include "tar_proc_es.hpp"

#include <yuzu/agent/es_client.hpp> // yuzu::agent::{es_seq_gap,es_stream_is_stalled,kEsIdleFallbackSeconds} (A0 relocation)

#include <string>

namespace yuzu::tar {

// ── Pure mapping (cross-platform, unit-tested everywhere) ─────────────────────

namespace {

/// Leaf component of a POSIX path. "" for empty; the whole string if no '/'.
/// A trailing slash yields "" (degenerate, but never produced by ES which always
/// hands back a concrete executable path).
std::string path_basename(const std::string& path) {
    if (path.empty())
        return {};
    auto slash = path.find_last_of('/');
    if (slash == std::string::npos)
        return path;
    return path.substr(slash + 1);
}

} // namespace

ProcEvent es_sample_to_proc_event(const EsProcSample& sample) {
    ProcEvent ev;
    ev.ts_unix = sample.ts_unix;
    ev.is_start = sample.is_exec;
    ev.pid = sample.pid;
    // ppid is meaningful only on exec; an exit carries 0 (mirrors the ETW peer).
    ev.ppid = sample.is_exec ? sample.ppid : 0;
    ev.image_name = path_basename(sample.executable_path);
    // exit status is carried on stop only; not persisted by process_live today
    // (no exit_code column) but kept for parity / future use.
    ev.exit_code = sample.is_exec ? 0 : sample.exit_status;
    // Carry the raw uid; `user` is resolved at DRAIN (off the ES handler queue) so
    // getpwuid_r — which can do a blocking network NSS lookup on a directory-joined
    // Mac — never stalls the kernel-serial handler. `sid` is Windows-only, empty here.
    ev.uid = sample.uid;
    return ev;
}

std::string resolve_uid_cached(std::unordered_map<std::uint32_t, std::string>& cache,
                               std::uint32_t uid,
                               const std::function<std::string(std::uint32_t)>& lookup) {
    auto it = cache.find(uid);
    if (it != cache.end())
        return it->second;
    std::string name = lookup(uid);
    cache.emplace(uid, name);
    return name;
}

} // namespace yuzu::tar

// The real ES client compiles only where the ES SDK is detected by meson
// (-DYUZU_HAVE_ENDPOINT_SECURITY) -- the ES lib+header pair ships in BOTH the
// Command Line Tools and full Xcode SDKs ("needs full Xcode" is a myth; see
// docs/darwin-compat.md's EndpointSecurity row). On macOS with no ES SDK
// detected, and on every non-Apple platform, the no-op path below is used
// and start() returns false so the caller falls back to the sysctl process
// poll.
#if defined(__APPLE__) && defined(YUZU_HAVE_ENDPOINT_SECURITY)

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <pwd.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <ctime>
#include <unordered_map>
#include <vector>

#include <spdlog/spdlog.h>

namespace yuzu::tar {

namespace {

/// es_string_token_t (length-counted, not necessarily NUL-terminated) → std::string.
std::string es_str(const es_string_token_t& tok) {
    if (tok.data == nullptr || tok.length == 0)
        return {};
    return std::string(tok.data, tok.length);
}

/// es_new_client failure reason as a stable short string for the log line.
const char* es_new_client_err(es_new_client_result_t r) {
    switch (r) {
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:   return "not entitled";
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:  return "not permitted (TCC)";
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return "not privileged (needs root)";
    case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return "too many clients";
    case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: return "invalid argument";
    case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:       return "internal error";
    default:                                      return "unknown";
    }
}

// uid → username via getpwuid_r, with an ERANGE-driven growing buffer (a
// directory-joined Mac can return a passwd record larger than the initial guess).
// Numeric-uid fallback on an unknown user or an unrecoverable error (mirrors
// process_enum). Called only from drain() (the plugin tick thread) through
// resolve_uid_cached — never the kernel-serial ES handler queue.
std::string getpwuid_name(std::uint32_t uid) {
    std::size_t bufsz = 1024;
    if (const long hint = ::sysconf(_SC_GETPW_R_SIZE_MAX); hint > 0)
        bufsz = static_cast<std::size_t>(hint);
    std::vector<char> buf(bufsz);
    for (;;) {
        struct passwd pw {};
        struct passwd* result = nullptr;
        const int rc = ::getpwuid_r(uid, &pw, buf.data(), buf.size(), &result);
        if (rc == 0)
            return result != nullptr ? std::string(pw.pw_name) : std::to_string(uid);
        if (rc == ERANGE && buf.size() < (std::size_t{1} << 20)) {
            buf.resize(buf.size() * 2);
            continue;
        }
        return std::to_string(uid); // unknown uid or unrecoverable error
    }
}

} // namespace

struct ProcEsCollector::Impl {
    es_client_t* client{nullptr};
    ProcEventRing* ring{nullptr};

    // Borrowed (non-owning) pointers to the COLLECTOR's stream-health atomics. They
    // live on ProcEsCollector (which outlives this Impl), NOT here, so that
    // kernel_dropped() — read by the status command thread WITHOUT the plugin's
    // collect_mu_ — never dereferences impl_ (a concurrent self-heal
    // stop()/impl_.reset() could otherwise free the Impl under it). Keeping them on
    // the collector also lets the counts survive a stop()→re-arm. Written here on the
    // serial ES handler queue; read (relaxed) on the tick/status thread.
    std::atomic<std::uint64_t>* kernel_dropped{nullptr}; ///< → collector kernel_dropped_
    std::atomic<std::int64_t>* last_event_ts{nullptr};   ///< → collector last_event_ts_

    // Per-event-type last seq_num for kernel-drop detection. Touched ONLY on the
    // serial ES handler queue, so it needs no lock and no cross-thread home.
    std::unordered_map<es_event_type_t, std::uint64_t> last_seq;

    Impl(ProcEventRing* r, std::atomic<std::uint64_t>* kd, std::atomic<std::int64_t>* let)
        : ring(r), kernel_dropped(kd), last_event_ts(let) {}

    // Owns the es_client_t. Releasing here (rather than by hand in stop()) makes the
    // teardown structural: es_delete_client BLOCKS until every in-flight handler has
    // returned, so once ~Impl completes no handler can run. The owning
    // ProcEsCollector destroys impl_ (via stop()) BEFORE its `ring_` member destructs,
    // and the handler block only captures this Impl* and touches `ring` (a collector
    // member), the handler-owned `last_seq`, and the borrowed collector atomics via
    // `kernel_dropped`/`last_event_ts` (whose targets outlive the Impl) — never
    // `client` — so the use-after-free barrier is by construction.
    ~Impl() {
        if (client != nullptr) {
            es_unsubscribe_all(client);
            es_delete_client(client);
            client = nullptr;
        }
    }
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    // Count kernel-side drops from a seq_num gap. Runs only on the serial ES
    // handler queue, so last_seq needs no lock.
    void note_seq(es_event_type_t type, std::uint64_t seq) {
        auto it = last_seq.find(type);
        if (it != last_seq.end())
            kernel_dropped->fetch_add(yuzu::agent::es_seq_gap(it->second, seq),
                                      std::memory_order_relaxed);
        last_seq[type] = seq;
    }

    // Runs on the kernel-serial ES handler queue.
    //
    // noexcept + whole-body catch-all: this is invoked across the Endpoint Security
    // (C) handler-block frame, where an escaping C++ exception is undefined
    // behaviour. A std::bad_alloc from es_str() or the ring push (memory pressure /
    // spawn storm) must cost one event, never abort the agent — mirroring the ETW
    // on_event contract (tar_proc_etw.cpp). The ring ctor reserve()s its full
    // capacity so push() cannot reallocate here.
    //
    // MUST stay non-blocking: it only decodes the message and does one ring push.
    // The owning-user resolution (getpwuid_r, which can block on a network NSS
    // lookup on a directory-joined Mac) is deliberately NOT done here — the raw uid
    // is carried on the ProcEvent and resolved at drain (off this queue), mirroring
    // the ETW collector's sid→user-at-drain idiom.
    void handle(const es_message_t* msg) noexcept {
        try {
            if (msg == nullptr)
                return;
            // The exec/exit union is populated only for NOTIFY messages; never read
            // it on an AUTH message (defence-in-depth — we subscribe NOTIFY only).
            if (msg->action_type != ES_ACTION_TYPE_NOTIFY)
                return;

            // seq_num is populated only when the message version >= 2 (Apple's
            // versioned-struct contract); guard the kernel-drop detection on it.
            if (msg->version >= 2)
                note_seq(msg->event_type, msg->seq_num);

            EsProcSample sample;
            sample.ts_unix = static_cast<std::int64_t>(msg->time.tv_sec);

            if (msg->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
                const es_process_t* target = msg->event.exec.target;
                if (target == nullptr)
                    return;
                sample.is_exec = true;
                sample.pid = static_cast<std::uint32_t>(audit_token_to_pid(target->audit_token));
                sample.ppid = static_cast<std::uint32_t>(target->ppid);
                if (target->executable != nullptr)
                    sample.executable_path = es_str(target->executable->path);
                sample.uid = audit_token_to_ruid(target->audit_token);
            } else if (msg->event_type == ES_EVENT_TYPE_NOTIFY_EXIT) {
                const es_process_t* proc = msg->process;
                if (proc == nullptr)
                    return;
                sample.is_exec = false;
                sample.pid = static_cast<std::uint32_t>(audit_token_to_pid(proc->audit_token));
                if (proc->executable != nullptr)
                    sample.executable_path = es_str(proc->executable->path);
                // es_event_exit_t::stat is the raw wait(2) status; record the exit
                // code proper. (Not persisted today — no exit_code column — but kept
                // accurate for parity / future use.)
                const int raw = msg->event.exit.stat;
                sample.exit_status = WIFEXITED(raw) ? WEXITSTATUS(raw) : raw;
                sample.uid = audit_token_to_ruid(proc->audit_token);
            } else {
                return; // not a subscribed type (we never subscribe NOTIFY_FORK)
            }

            ProcEvent ev = es_sample_to_proc_event(sample);
            if (ev.ts_unix <= 0)
                return; // torn/zero kernel timestamp — never emit a bogus-dated row (ETW parity)
            if (ev.pid == 0)
                return; // pid 0 is never a real process (ETW parity)
            ring->push(std::move(ev)); // non-blocking; drops+counts on overflow
            // Liveness heartbeat — stamped only AFTER a successful decode + push, so
            // a stream that keeps delivering messages we cannot decode (persistent
            // bad_alloc, malformed token) does NOT read as alive: stalled() then
            // re-arms the poll instead of silently capturing nothing while every
            // health signal looks green. Read off-queue by stalled() (see the class).
            last_event_ts->store(sample.ts_unix, std::memory_order_relaxed);
        } catch (...) {
            // Never let an exception unwind across the Endpoint Security C frame.
        }
    }
};

ProcEsCollector::ProcEsCollector(std::size_t ring_capacity) : ring_(ring_capacity) {}

ProcEsCollector::~ProcEsCollector() { stop(); }

bool ProcEsCollector::start() {
    if (impl_)
        return false; // already running

    // Reset the collector's stream-health atomics for this (re)start BEFORE any
    // handler can fire (the handler can only run after es_subscribe below):
    // started_ts_ anchors the stall timer; last_event_ts_ = 0 means "no event yet"
    // so stalled() measures idle from start until the first delivery. kernel_dropped_
    // is a cumulative lifetime counter and is intentionally not reset.
    started_ts_.store(static_cast<std::int64_t>(::time(nullptr)), std::memory_order_relaxed);
    last_event_ts_.store(0, std::memory_order_relaxed);

    auto impl = std::make_unique<Impl>(&ring_, &kernel_dropped_, &last_event_ts_);
    Impl* raw = impl.get();

    // The handler block captures the borrowed Impl* and only ever touches state valid
    // before publication — `ring` (a collector member), the handler-owned `last_seq`,
    // and the borrowed collector atomics via `kernel_dropped` / `last_event_ts` (set
    // in the Impl ctor; their targets are collector members that outlive the Impl) —
    // NEVER `client` (published below, after es_new_client returns). es_new_client's
    // internal queue setup provides the happens-before edge to the first handler
    // dispatch, so the handler sees a fully-constructed Impl.
    es_client_t* client = nullptr;
    es_new_client_result_t res =
        es_new_client(&client, ^(es_client_t* c, const es_message_t* msg) {
            (void)c;
            raw->handle(msg);
        });

    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        spdlog::warn("TAR: Endpoint Security client unavailable ({}) — falling back "
                     "to the sysctl process poll",
                     es_new_client_err(res));
        return false;
    }

    es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT};
    if (es_subscribe(client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        spdlog::warn("TAR: es_subscribe(EXEC,EXIT) failed — falling back to the poll");
        es_delete_client(client);
        return false;
    }

    impl->client = client;
    impl_ = std::move(impl);
    spdlog::info("TAR: Endpoint Security process stream active (EXEC/EXIT)");
    return true;
}

void ProcEsCollector::stop() {
    // ~Impl unsubscribes + es_delete_client (which blocks until in-flight handlers
    // return) before this reset completes, and ring_ — a ProcEsCollector member —
    // outlives impl_, so the teardown is use-after-free-safe by construction.
    impl_.reset();
}

bool ProcEsCollector::running() const noexcept { return impl_ != nullptr; }

std::vector<ProcEvent> ProcEsCollector::drain() {
    if (!impl_)
        return {};
    // ring_.drain() takes the ring's own mutex. uid→user resolution happens HERE
    // (the plugin tick thread), not in the ES handler — getpwuid_r may block on a
    // network NSS lookup, which must never stall the kernel-serial ES queue.
    // uid_cache_ is owned by the collector and touched only from drain (single-thread).
    auto evs = ring_.drain();
    for (auto& e : evs) {
        e.user = resolve_uid_cached(uid_cache_, e.uid, getpwuid_name);
    }
    return evs;
}

std::uint64_t ProcEsCollector::dropped() const noexcept { return ring_.dropped(); }

std::uint64_t ProcEsCollector::kernel_dropped() const noexcept {
    // Reads a collector-owned atomic (NOT impl_), so the status command thread can
    // call this without the plugin's collect_mu_ and without racing a self-heal
    // stop()/impl_.reset(). Persists across a stop()→re-arm.
    return kernel_dropped_.load(std::memory_order_relaxed);
}

bool ProcEsCollector::stalled() const noexcept {
    if (!impl_)
        return false; // not running → running() owns that; nothing to fall back from
    // A NOTIFY-only ES client exposes no liveness API: if it is silently invalidated
    // (kernel back-pressure, client kill) the handler stops firing while the handle
    // stays valid and running() stays true — capture would go blind while
    // `tar.status` still reported endpoint_security. Treat prolonged TOTAL silence as
    // "presumed dead" and let the plugin re-arm the poll. CAVEAT (accepted tradeoff):
    // a legitimately quiet host can also go long without exec/exit, so the threshold
    // is sized well beyond any plausible quiet period (kEsIdleFallbackSeconds) to
    // avoid demoting a HEALTHY stream to the inferior poll until the agent restarts.
    // The health atomics are collector-owned, so reading them here is impl_-free.
    const std::int64_t now = static_cast<std::int64_t>(::time(nullptr));
    return yuzu::agent::es_stream_is_stalled(last_event_ts_.load(std::memory_order_relaxed),
                                             started_ts_.load(std::memory_order_relaxed), now,
                                             yuzu::agent::kEsIdleFallbackSeconds);
}

} // namespace yuzu::tar

#else // no Endpoint Security (non-Apple, or the build-time ES probe found no ES SDK)

namespace yuzu::tar {

struct ProcEsCollector::Impl {};

ProcEsCollector::ProcEsCollector(std::size_t ring_capacity) : ring_(ring_capacity) {}
ProcEsCollector::~ProcEsCollector() = default;

bool ProcEsCollector::start() { return false; }
void ProcEsCollector::stop() {}
bool ProcEsCollector::running() const noexcept { return false; }
std::vector<ProcEvent> ProcEsCollector::drain() { return {}; }
std::uint64_t ProcEsCollector::dropped() const noexcept { return ring_.dropped(); }
std::uint64_t ProcEsCollector::kernel_dropped() const noexcept { return 0; }
bool ProcEsCollector::stalled() const noexcept { return false; }

} // namespace yuzu::tar

#endif // __APPLE__
