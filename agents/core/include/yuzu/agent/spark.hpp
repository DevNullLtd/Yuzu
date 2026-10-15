#pragma once

/**
 * spark.hpp — the Spark contract: the platform's use-case-agnostic detection
 * primitive (ADR-0021 Decision 1).
 *
 * A Spark is a type plus parameters describing a device condition to watch
 * (interval elapsed, agent startup, disk threshold crossing, file change,
 * service state change, registry change). Consumers (Guardian, DEX, Reflex)
 * subscribe to a SparkSpec and receive SparkEvents; they own the MEANING of
 * those events — a Spark never carries an assertion, an observation type, or
 * a Reaction. "Armed" means the SparkEngine is running a watcher for the spec;
 * consumers never see watcher instances (spark_engine.hpp).
 *
 * Two subscription tiers (ADR-0021 Decision 3):
 *   - Queued  — per-consumer queue + dispatch thread; consumer code NEVER runs
 *               on a watcher thread, so a blocked consumer cannot stall
 *               detection or a sibling consumer.
 *   - Inline  — synchronous on the watcher thread. µs-MEDIAN dispatch, NOT a
 *               hard worst-case bound (owner decision 2026-07-06 on the
 *               stage0-windows-spikes §1b probe: p99 can reach 100s of µs and
 *               a scheduler-quantum ~10ms outlier is possible on a shared
 *               pool). Enforce-class handlers only — non-blocking, never a
 *               plugin call. Core-internal: this API is not reachable from the
 *               plugin ABI, and Stage 2 narrows the handler's capability
 *               surface to the enforce context.
 *
 * Proto-free and windows.h-free by design (the guard.hpp rationale): this
 * header is the vocabulary shared by the engine, every consumer, and the
 * tests, so it must be includable anywhere.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>

namespace yuzu::agent {

// ── Spark types ───────────────────────────────────────────────────────────────

/// The detection mechanisms the platform offers. This is the full content-plane
/// vocabulary (stage0-trigger-inventory.md): interval / file_change /
/// service_status / registry_change / agent_startup, plus the DEX-originated
/// disk threshold. Which types are armable in a given build/slice is the
/// engine's concern (spark_engine.hpp), not the vocabulary's.
enum class SparkType {
    Interval, ///< fires every interval_ms
    Startup,  ///< fires once, at engine start (or at arm time if already started)
    Disk,     ///< threshold poll-and-latch on a volume/path — breach + recovery edges
    File,     ///< file/directory change (kernel-notified; mechanism PR 1b)
    Service,  ///< service/unit run-state change (multiplexed; mechanism PR 1c)
    Registry, ///< Windows registry key change (wait-pool; mechanism PR 1b)
};

/// Guardian convergence-scheduler lane cadences and jitter (ADR-0021 Stage 2 rung 4;
/// design doc `guardian_convergence_scheduler.hpp`). Hoisted here, out of
/// `ConvergenceScheduler::Config`'s struct defaults, so any OTHER site that needs to
/// reason about a lane's sweep interval - `guardian_spark_bridge.hpp`'s per-type
/// debounce default (#3388) is the first such site - single-sources them instead of
/// risking a silently-drifted duplicate copy of the same tuning constants.
inline constexpr std::uint64_t kGuardianServiceLaneCadenceMs = 60'000;
inline constexpr std::uint64_t kGuardianRegistryLaneCadenceMs = 60'000;
inline constexpr std::uint64_t kGuardianFileLaneCadenceMs = 600'000; ///< ~10 min (the 5-15 min band)
inline constexpr std::uint32_t kGuardianLaneJitterPct = 20;         ///< +/- this % of the cadence

/// The +/- jitter span (ms) applied to a cadence at the given jitter percentage -
/// the SAME formula `ConvergenceScheduler::jittered()` applies at runtime
/// (`guardian_convergence_scheduler.cpp`), hoisted here so a future edit to that
/// arithmetic can't silently desync the scheduler's own jitter from any other
/// site reasoning about a lane's worst-case sweep timing - starting with
/// `guardian_spark_bridge.hpp`'s per-type debounce default (#3388). Sharing only
/// the input CONSTANTS above (without also sharing this formula) would still
/// let the two drift apart on a rounding/behavior change to just one copy -
/// this closes that gap for real (Gate 3 cpp-expert finding).
///
/// NOT the same thing as `guardian_jitter_offset()` (`guardian_outbox_drain_worker.hpp`)
/// despite the near-identical name - that one draws a random `[0,upper)` SAMPLE
/// from an RNG for outbox-maintenance paging; this one is a deterministic BOUND
/// computation with no randomness at all (Gate 4 consistency-auditor: flagged as
/// a future grep-collision risk, naming disambiguated here rather than renamed).
[[nodiscard]] constexpr std::uint64_t guardian_jitter_span_ms(std::uint64_t cadence_ms,
                                                               std::uint32_t jitter_pct) noexcept {
    return (cadence_ms * jitter_pct) / 100;
}

/// #3388's debounce default (lane cadence + one jitter span) must stay BELOW the
/// two-sweep minimum (`2 * cadence * (1 - jitter_pct/100)`) - not merely above a
/// single sweep, which holds trivially for any positive jitter and proves
/// nothing - so a compliant-edge-then-redrift round trip across one sweep is
/// never silently swallowed by the first drift's debounce window, only delayed
/// (Gate 2 security-guardian derivation, corrected at Gate 8 after the same
/// wrong-inequality mistake showed up in this very comment: `1+j/100 < 2*(1-j/100)`
/// solves to `j < 33.3%`, comfortably true at 20%). A future jitter_pct raise
/// past that bound should fail loud here, not silently reintroduce
/// flap-suppression.
static_assert(kGuardianLaneJitterPct < 34,
             "raising jitter past ~1/3 needs re-deriving guardian_spark_bridge.hpp's "
             "debounce-vs-two-sweep-minimum margin (#3388), not just bumping this constant");

/// Stable token for logs, keys, and (later) the content plane.
[[nodiscard]] constexpr const char* spark_type_token(SparkType t) noexcept {
    switch (t) {
    case SparkType::Interval: return "interval";
    case SparkType::Startup:  return "startup";
    case SparkType::Disk:     return "disk";
    case SparkType::File:     return "file";
    case SparkType::Service:  return "service";
    case SparkType::Registry: return "registry";
    }
    return "unknown";
}

// ── Per-type parameters ───────────────────────────────────────────────────────

struct IntervalSparkParams {
    /// Fire cadence. The engine floors this (default 30s — the TriggerEngine
    /// minimum, lowerable only via the test seam) rather than rejecting, so a
    /// too-eager author degrades gracefully.
    std::uint64_t interval_ms{0};
    bool operator==(const IntervalSparkParams&) const = default;
};

struct StartupSparkParams {
    bool operator==(const StartupSparkParams&) const = default;
};

struct DiskSparkParams {
    std::string path;                      ///< volume root or any path on the filesystem to watch
    std::uint32_t used_pct_threshold{90};  ///< bad when used% >= this (1..100)
    std::uint64_t min_free_bytes{5ull * 1024 * 1024 * 1024}; ///< bad when free < this; 0 disables
    std::uint64_t poll_ms{600'000};        ///< poll cadence (floored like interval_ms)
    bool operator==(const DiskSparkParams&) const = default;
};

struct FileSparkParams {
    std::string path; ///< target file (watching mechanism lands in PR 1b)
    bool operator==(const FileSparkParams&) const = default;
};

struct ServiceSparkParams {
    std::string service_name; ///< SCM service / systemd unit name (mechanism PR 1c)
    bool operator==(const ServiceSparkParams&) const = default;
};

struct RegistrySparkParams {
    std::string hive; ///< "HKLM" | "HKCU" | "HKCR" | "HKU"
    std::string key;  ///< subkey path (mechanism PR 1b)
    bool operator==(const RegistrySparkParams&) const = default;
};

using SparkParams = std::variant<IntervalSparkParams, StartupSparkParams, DiskSparkParams,
                                 FileSparkParams, ServiceSparkParams, RegistrySparkParams>;

/// An authored detection spec: what to watch. Two specs with equal (type, params)
/// are the SAME armed spark — the engine dedups arming across consumers
/// (N subscriptions, 1 watcher).
struct SparkSpec {
    SparkType type{SparkType::Interval};
    SparkParams params{IntervalSparkParams{}};
    bool operator==(const SparkSpec&) const = default;
};

/// Canonical identity of an armed spark — deterministic over (type, params).
/// This is the dedup key and the event correlation handle consumers see.
[[nodiscard]] YUZU_EXPORT std::string spark_key(const SparkSpec& spec);

// ── Event payloads ────────────────────────────────────────────────────────────

/// One disk capacity reading. `valid == false` = the read failed (path gone,
/// permission, device error) — a failed reading must never read as a full OR a
/// healthy disk (gov UP-5).
struct DiskReading {
    bool valid{false};
    std::uint64_t total_bytes{0};
    std::uint64_t free_bytes{0};
    bool operator==(const DiskReading&) const = default;
};

/// Which latch edge a disk poll crossed. Breach = transition INTO the bad
/// state (emit once, suppressed while it persists); Recovery = a VALID reading
/// showed healthy again (re-arms the latch). Consumers own the meaning — DEX
/// maps Breach to `storage.low`; a Reflex episode opens on Breach and closes
/// on Recovery (ADR-0021 Decision 4 / Stage 3).
enum class DiskEdge { Breach, Recovery };

struct DiskSparkData {
    DiskReading reading;
    DiskEdge edge{DiskEdge::Breach};
    bool operator==(const DiskSparkData&) const = default;
};

/// Resolved run state of a watched service/unit — the TERMINAL vocabulary only.
/// Mapping (mirrors guard_systemd / guard_service, the governed precedents):
///   Linux  : active → Running; inactive / failed / absent(not-loaded) → Stopped;
///            activating / deactivating / reloading / maintenance / unknown →
///            TRANSITIONAL — HELD, never emitted (see rationale below).
///   Windows: SERVICE_RUNNING → Running; SERVICE_STOPPED / absent / deleted →
///            Stopped; SERVICE_PAUSED → Paused (a TERMINAL SCM state — the guard
///            compares and remediates on it, so the raw primitive must surface it
///            or a consumer goes blind to paused drift); *_PENDING →
///            TRANSITIONAL — HELD.
///   macOS  : `launchctl list` (see agents/shared/launchctl_list.hpp +
///            agents/core/include/yuzu/agent/launchd_state.hpp) — listed with a
///            pid → Running; listed without a pid, or absent from the snapshot
///            → Stopped. Paused is NEVER produced: launchd, like systemd, has
///            no analogue to the Windows SCM's SERVICE_PAUSED terminal state,
///            and there is no TRANSITIONAL concept either (a launchctl list
///            snapshot is a point-in-time terminal read, not a state machine).
/// Transitional states are held, not emitted: a consumer can neither assert over
/// nor enforce against a mid-transition state (the guards hold on exactly these),
/// and emitting them would make every stop/start a multi-event flap each consumer
/// must re-filter. The enum is deliberately open — a Transitional member can be
/// added later without breaking the wire tokens below.
enum class ServiceRunState : std::uint8_t {
    Running,
    Stopped, ///< includes failed (Linux) and absent/deleted (both platforms)
    Paused,  ///< Windows-only terminal state; never produced on Linux
};

/// Stable token for logs and (later) the content plane.
[[nodiscard]] constexpr const char* service_run_state_token(ServiceRunState s) noexcept {
    switch (s) {
    case ServiceRunState::Running: return "running";
    case ServiceRunState::Stopped: return "stopped";
    case ServiceRunState::Paused:  return "paused";
    }
    return "unknown";
}

/// Event payload for a Service spark: the resolved terminal state AFTER the
/// change. Unlike File/Registry (monostate — consumer re-reads), the service
/// spark carries state because a consumer has no independent read primitive
/// that doesn't duplicate the mechanism's own sd-bus/SCM connection — the exact
/// resource duplication this mechanism exists to remove. Emitted once on
/// successful watch-arm (the initial resolved state) and thereafter only on
/// terminal-state edges; transitional states never emit and never move the
/// edge-dedup baseline.
struct ServiceSparkData {
    ServiceRunState state{ServiceRunState::Stopped};
    bool operator==(const ServiceSparkData&) const = default;
};

/// Type-specific event facts. Interval/Startup (and the File/Registry
/// change-signal types) carry no payload — the event itself is the fact;
/// consumers re-read whatever state they assert over. Service is the one
/// event-driven type that DOES carry a payload (ServiceSparkData) — see its
/// doc comment for why.
using SparkData = std::variant<std::monostate, DiskSparkData, ServiceSparkData>;

/// #2818: what kind of notification a SparkEvent carries. `Fired` is a real detection
/// fire (every pre-existing call site — unaffected default). The other three ride the
/// SAME Inline/Queued dispatch channel a fire uses, so any consumer already registered
/// gets them via whatever handler it wired for `Fired` — no new registration surface.
enum class SparkEventKind : std::uint8_t {
    Fired,     ///< a real detection fire — `data` is meaningful, `subscription_id`/`detail` are not.
    Lost,      ///< the key's armed_ entry was torn down entirely (an in-flight watch arm
               ///< that could not be completed). PERMANENT for the subscription named by
               ///< `subscription_id`: no further event of any kind will ever arrive for it.
               ///< A fresh arm() is required — there is nothing to re-check.
    Faulted,   ///< the watch reported itself unhealthy AFTER a successful arm (B1). The
               ///< key is STILL armed (unlike Lost) — this may self-heal; watch for a
               ///< paired Recovered for the same key.
    Recovered, ///< a prior Faulted on this key has cleared.
};

/// What a consumer receives when an armed spark fires — or, since #2818, when a
/// subscription's underlying watch dies or changes health. A CONSUMER MUST SWITCH
/// ON `kind`: a handler that treats every SparkEvent as a fire (ignoring `kind`)
/// will silently misread a Lost/Faulted/Recovered notification as a real detection
/// fire with empty `data` (governance Gate 2 finding, PR-2d).
struct SparkEvent {
    std::string key;                          ///< spark_key() of the armed spec
    SparkType type{SparkType::Interval};
    std::uint64_t seq{0};                     ///< per-armed-spark, monotonically increasing
    std::chrono::system_clock::time_point at; ///< wall-clock fire time
    SparkData data{};
    SparkEventKind kind{SparkEventKind::Fired};
    /// Meaningful only for kind != Fired. One key-level condition is fanned out to
    /// potentially several differently-subscribed consumers, so a single shared
    /// SparkEvent object cannot itself name "the" subscription — deliver() stamps this
    /// per-recipient from Subscriber::id. 0 for Fired (a fire is key-scoped, never
    /// subscription-scoped).
    std::uint64_t subscription_id{0};
    /// Meaningful only for kind != Fired: the mechanism's watch-failure text (Lost) or
    /// the fault/recovery reason (Faulted/Recovered). Empty for Fired.
    std::string detail;
};

/// #2818: the liveness of a subscription id, as of the moment of the call. `Dead` means
/// no further event of any kind will ever arrive for it (a Lost notification either
/// already was, or — if this raced the drop — is about to be, delivered). Built on the
/// fact that SubscriptionIds are monotonic and never reused (SparkEngine's own
/// teardown_arm_race comment), so "is this id still live" is a complete, always-correct
/// existence check — no incarnation counter or graveyard bookkeeping needed. Lives here,
/// not in spark_engine.hpp, so GuardianSparkRuntime's ISparkBackend seam (deliberately
/// decoupled from spark_engine.hpp) can use it too.
enum class SubscriptionHealth {
    Dead,     ///< the id is no longer tracked — its key was torn down (or never armed).
    Faulted,  ///< the id's key is armed but reported unhealthy (B1).
    Healthy,  ///< armed, not faulted.
};

// ── Establishment signal (rung 9c PR-6 item 1) ─────────────────────────────────

/// Identity token for one armed watch, minted by the SparkEngine when a key
/// transitions from "not armed" to "armed" (a fresh key, or a key re-armed
/// after being fully torn down) — never on a dedup arm, which shares the
/// existing key's incarnation. Monotone, drawn from the engine's shared id
/// counter (the same source as ConsumerId/SubscriptionId); wrap is not
/// expected within any realistic process lifetime. `kNoSparkIncarnation` (0)
/// is never minted before wrap and marks "no incarnation" where one is
/// optional. Compared for EQUALITY at the engine (does this report still name
/// the CURRENT watch for this key) and for ORDER at a mechanism (is this
/// submission newer than what I already have — the forward-only rebind a
/// mechanism applies before adopting a new incarnation for an already-known
/// key).
using SparkIncarnation = std::uint64_t;
inline constexpr SparkIncarnation kNoSparkIncarnation = 0;

/// A mechanism's best current answer to "does live OS-level notification
/// coverage exist for this watch right now" — the fact `spark.hpp`'s "armed
/// means a watcher is running" does NOT by itself guarantee (arm() succeeding
/// only means a watch request was accepted, not that the OS confirmed it).
/// Tri-state, never a bool: `Poll` is a real, load-bearing middle state, not
/// a degraded `Notification` — a mechanism that has fallen back to (or has
/// not yet moved off) periodic polling for a key must say so rather than
/// claim event-driven coverage it does not have.
enum class SparkCoverage : std::uint8_t {
    None,         ///< no coverage at all — never established, or lost (fault, teardown, error).
    Notification, ///< live OS-level event notification is in effect for this key.
    Poll,         ///< the mechanism is watching this key by periodic re-check, not notification.
};

/// Stable token for logs and (later) the content plane.
[[nodiscard]] constexpr const char* spark_coverage_token(SparkCoverage c) noexcept {
    switch (c) {
    case SparkCoverage::None:         return "none";
    case SparkCoverage::Notification: return "notification";
    case SparkCoverage::Poll:         return "poll";
    }
    return "unknown";
}

/// Pull-query result for "has this subscription's watch achieved live coverage,
/// and when" (rung 9c PR-6 item 1) — a THIRD timestamp alongside R5.3's
/// accepted/resolved pair, not a correction to either: `armed_at` is when the
/// engine committed the arm, `established_at` is when a mechanism first
/// reported `Notification` coverage for the CURRENT incarnation (unset while
/// still pending, or while coverage has never reached `Notification` — e.g. a
/// mechanism that only ever offers `Poll`), and `coverage` is the mechanism's
/// most recently reported tri-state for this key, except that the engine answers
/// `None` while the type's mechanism reports itself inert (a conservative, not
/// coherent, snapshot; `established_at` is unchanged). RECOVERY DOES NOT RE-STAMP:
/// once `established_at` is set for an incarnation it stays set, even if
/// `coverage` later drops to `None` and comes back — first-wins, not
/// last-transition. Meaningless fields read as their defaults (`coverage`
/// `None`, `established_at` unset) for a spark type with no event-driven
/// mechanism (interval/startup/disk) — there is nothing wrong in that reading,
/// it simply means nothing has ever reported the contrary.
struct SubscriptionEstablishment {
    std::chrono::steady_clock::time_point armed_at{};
    std::optional<std::chrono::steady_clock::time_point> established_at;
    SparkCoverage coverage{SparkCoverage::None};
};

// ── Subscription tiers ────────────────────────────────────────────────────────

enum class SparkTier {
    Inline, ///< synchronous on the watcher thread — enforce-class only (see header comment)
    Queued, ///< per-consumer queue + thread — everything else
};

} // namespace yuzu::agent
