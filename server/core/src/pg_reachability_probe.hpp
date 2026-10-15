#pragma once

/// @file pg_reachability_probe.hpp
/// HA WS-8 (ADR-2002 §12): the runtime "can this replica reach the `yuzu`
/// primary?" signal behind `/readyz`'s `pg_reachable` row. The decision rule is
/// in pg_reachability_rules.hpp (pure); this file is the I/O half.
///
/// THE CONTRACT (Gate 8 round 9, architecture review adopted by the operator).
/// `pg_reachable` is a ONE-SESSION signal. It is red when the probe's most
/// recent connect — made with the pool's own parameters (same DSN, environment,
/// service file and `connect_timeout` default; a single host capped at
/// kConnectDeadline) — could not establish a session to a server that accepts
/// writes; or when the probe's held session stops answering or turns read-only.
/// It keeps a healthy session open, so it does NOT observe the pool's other held
/// connections (the pool never re-validates them), nor anything that changed
/// after the probe last connected. Named residuals:
///   (1) held pool connections to a server demoted in place (#4942);
///   (2) anything that changes whether a NEW connection would succeed — a
///       service-file or environment edit, a password rotation or expiry, a
///       pg_hba or certificate change — seen only at the probe's next reconnect
///       (a connect failure, query failure, read-only answer or settings refusal
///       drops its session) (#4956);
///   (3) a multi-address host name with one silent address (#4954);
///   (4) `max_connections` exhaustion (the probe is refused first) (#4943);
///   (5) timing, accepted and untracked: about ±1 s against the pool's connect,
///       and a single host capped at kConnectDeadline (a pool connect slower than
///       that can succeed while the probe reads red — never green).
/// FREEZE RULE: no further emulation of libpq/pool behaviour lands here. A newly
/// found divergence is a tracked issue against this contract UNLESS it produces
/// a false GREEN for a fresh connect on a single-endpoint DSN or a read-write
/// multi-host DSN — that remains blocking.
///
/// WHY A DEDICATED CONNECTION, NOT A POOL LEASE. A probe that leases from
/// `pg_pool` false-negatives under saturation and would evict a busy-but-
/// healthy replica from the load balancer (the governance UP-2 precedent on the
/// `pg_pool` row). The probe owns ONE connection of its own (+1 connection per
/// replica against `max_connections`). It connects with the server's raw DSN,
/// built into parameters exactly as `PgPool` builds its own (see below) — not
/// through `build_coord_dsn`: every probe socket wait has its own client-side
/// deadline, so keepalives add nothing, and the pool's parameters are what
/// decide which host a connection reaches.
///
/// WHY NOT REUSE THE LEADERELECTOR'S PING (pre-implementation review Q1). The
/// elector is best-effort (boot continues without it), its `is_open()` takes a
/// mutex held across blocking libpq calls (#4013), and its cadence is a backoff
/// schedule, not a readiness clock. Leadership is also NOT a readiness
/// condition: a follower serves every operator-synchronous path (two dispatch
/// planes, leader_elector.hpp), so a follower is fully ready. That is the
/// recorded #4014 decision — the elector stays out of `/readyz`.
///
/// EVERY LIBPQ WAIT HAS A CLIENT-SIDE DEADLINE. The probe uses libpq's
/// non-blocking API (`PQconnectStartParams`/`PQconnectPoll`, `PQsendQuery` +
/// `poll()`/`PQconsumeInput`/`PQisBusy`) under `kConnectDeadline` /
/// `kQueryDeadline`, sliced so `stop()` is observed within ~200ms. This is
/// load-bearing: against a FROZEN backend (a `docker pause`d or black-holed
/// primary whose kernel still ACKs), a blocking `PQexec` measured 101s in this
/// tree (see `make_containment_gate` in server.cpp) — `statement_timeout` is
/// enforced server-side and `tcp_user_timeout`/keepalives never fire while the
/// peer ACKs. A blocking probe would make `stop()`'s join unbounded.
/// Residuals — synchronous work inside libpq that no slice can interrupt,
/// bounded by the system, not by us: the host-NAME lookup (getaddrinfo, so the
/// system resolver's timeouts), and on a libpq built with GSSAPI (or a server
/// choosing a huge SCRAM iteration count) the authentication exchange.
///
/// LIBPQ WALKS THE HOST LIST; THE PROBE ONLY ADDS A DEADLINE PER HOST. The
/// probe connects with exactly the pool's parameters (the DSN through `dbname`
/// with expand_dbname=1, the pool's `connect_timeout` default where the DSN and
/// PGCONNECT_TIMEOUT set none), so libpq alone decides the order, which
/// failures move on to the next host or address and which end the attempt —
/// as for the pool's own connections. Gate 8 rounds 2–5 found every probe that
/// re-implemented part of that walk diverging from the pool and reporting ready
/// while the pool could not connect (all reproduced). The one addition:
/// libpq's non-blocking connect never advances past a host that accepts TCP and
/// then goes silent (its blocking connect, which the pool uses, moves on after
/// `connect_timeout`), so in a host list a host address libpq has been on for
/// its effective `connect_timeout` — timed the way the linked libpq's blocking
/// connect times it (whole wall-clock seconds before libpq 17) — is given up
/// and the attempt restarted over the hosts it has not tried, once per host.
/// With no `connect_timeout` the pool waits for ever, so the probe reports the
/// failure after `kConnectDeadline` rather than moving on; a single host is
/// capped at `kConnectDeadline` (nothing to move on to). The host list is read
/// back from libpq (`PQconninfo`), so a `PGHOST` or `service=` list counts too.
/// A frozen first host of `host=n1,n2,n3` costs one timeout, not every tick
/// (Gate 4 UP-1, reproduced). Residual: a silent ADDRESS of a host name with
/// several addresses gives up that name's other addresses too, where the pool
/// would try them — it can err either way, so such names are documented as a
/// configuration to avoid. With `target_session_attrs=read-write` libpq itself
/// refuses a read-only host, so such a host reads `unreachable` (the log detail
/// says why), not `read_only`.
///
/// Any failure, AND reaching a server that does not accept writes, CLOSES the
/// connection so the next tick reconnects. The probe query checks both
/// `pg_is_in_recovery()` (a standby) and `transaction_read_only` (a primary
/// refusing writes via `default_transaction_read_only` — managed Postgres does
/// this on a full disk). Dropping the connection matters for the standby case:
/// a proxy, DNS name or read-any port can route a NEW connection to a standby,
/// and without the drop the probe would stay pinned there while a writable
/// primary exists — every replica stuck red (pre-implementation review,
/// finding 2).
///
/// PUBLICATION. `/readyz` and `/metrics` read a three-field snapshot under a
/// LEAF mutex held only to copy the fields — never across I/O, never while
/// logging — so a stalled probe can never stall a health check (the #4013
/// lesson), and a reader never sees a torn mix of two publications (Gate 4
/// UP-7: separate atomics let one read pair a new failure count with an old
/// failure kind).
///
/// LIFETIME (ServerImpl). The first probe runs SYNCHRONOUSLY in `run()` before
/// the HTTP listener binds (no `not_yet_probed` window after bind); `start()`
/// then spawns the loop. `stop()` signals and joins — bounded by one slice
/// (~200ms) because every wait checks the stop flag. `stop()` may run while
/// HTTP handlers are still executing (they keep running after
/// `web_server_->stop()` until `listen()` returns): that is safe because
/// `snapshot()` only copies fields under the probe's own leaf mutex (a member,
/// never held across I/O) and the publishing thread is already joined. The
/// OBJECT must therefore outlive the
/// web thread — ServerImpl keeps it as a member destroyed at `~ServerImpl`,
/// never `reset()` inside `stop()`.

#include "pg_reachability_rules.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace yuzu::server {

class PgReachabilityProbe {
public:
    /// Outcome of one probe.
    struct PingResult {
        enum class Kind : std::uint8_t { Ok, ReadOnly, Failed } kind{Kind::Failed};
        /// Operator-facing detail for the server log ONLY (may carry libpq
        /// text, host names). Never placed in an HTTP body.
        std::string detail;
    };

    /// One probe. MUST return promptly once `stop` reads true, and must bound
    /// its own blocking work. Called only from one thread at a time.
    using PingFn = std::function<PingResult(const std::atomic<bool>& stop)>;

    struct Observer {
        /// Every failed probe (Failed or ReadOnly) — feeds the failure counter.
        std::function<void()> on_failure;
    };

    /// The probe query. Must return exactly one boolean: `true` means "the
    /// connected server does not accept writes" — a standby, or a primary with
    /// `default_transaction_read_only` on.
    static constexpr const char* kProbeSql =
        "SELECT pg_is_in_recovery() OR current_setting('transaction_read_only')::boolean";

    /// Production: a real libpq probe against the server's raw `dsn` (the one the
    /// pool uses). Does not connect until `probe_once()`. `probe_sql`
    /// exists for tests only (e.g. `SELECT true` to simulate a standby without
    /// one); production always passes the default.
    /// `pool_connect_timeout_s` is the server pool's `connect_timeout` default
    /// (`PgPool::connect_timeout_s()`), applied exactly where the pool applies
    /// it, so the probe gives up on a host when the pool does.
    static std::unique_ptr<PgReachabilityProbe> make_libpq(std::string dsn, Observer obs = {},
                                                           std::string probe_sql = kProbeSql,
                                                           int pool_connect_timeout_s = 10);

    /// Test seam: any ping function, with an injectable interval so a loop test
    /// does not take seconds.
    PgReachabilityProbe(PingFn ping, Observer obs = {},
                        std::chrono::milliseconds interval = pg_reachability::kProbeInterval);
    ~PgReachabilityProbe();

    PgReachabilityProbe(const PgReachabilityProbe&) = delete;
    PgReachabilityProbe& operator=(const PgReachabilityProbe&) = delete;

    /// Run one probe on the CALLING thread and publish the result. Used for the
    /// synchronous first probe in `run()`, before `start()`. Must not be called
    /// concurrently with the loop thread.
    void probe_once();

    /// Spawn the probe loop. Idempotent; a no-op after `stop()`.
    void start();

    /// Signal and join the loop. Idempotent and sticky (no restart after stop),
    /// but not safe to call from two threads at once.
    void stop();

    /// The published state, copied under a leaf mutex (never held across I/O).
    pg_reachability::Snapshot snapshot() const noexcept;

    /// `classify(snapshot(), now_ns)`.
    pg_reachability::Verdict verdict_at(std::int64_t now_ns) const noexcept;
    pg_reachability::Verdict verdict() const noexcept;

    /// steady_clock ns since its epoch — the clock every timestamp here uses.
    static std::int64_t now_ns() noexcept;

private:
    void run_loop();
    void publish(const PingResult& r);

    PingFn ping_;
    Observer obs_;
    std::chrono::milliseconds interval_;

    mutable std::mutex snap_mu_; ///< leaf lock: guards snap_ only, never held across I/O
    pg_reachability::Snapshot snap_{};

    std::atomic<bool> stop_{false};
    std::mutex mu_; ///< guards the cv_ wait and thread_ start; the join is done outside it
    std::condition_variable cv_;
    std::thread thread_;
    bool started_{false};

    // Logging state — touched only by whichever single thread is probing
    // (the boot caller, then the loop thread; never both at once).
    pg_reachability::Verdict logged_verdict_{pg_reachability::Verdict::NotYetProbed};
    std::int64_t last_red_log_ns_{0};
};

} // namespace yuzu::server
