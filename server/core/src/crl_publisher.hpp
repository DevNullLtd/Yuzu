#pragma once

/// @file crl_publisher.hpp
/// HA WS-6 CRL follow-ups (#4828/#4829/#4830/#4831). Extracted from the former
/// `ServerImpl::publish_crl` (server.cpp) into an independently unit-testable,
/// dependency-injected class — `ServerImpl` constructed nothing in the test suite
/// (`grep -rln "ServerImpl(" tests/unit/server/*.cpp` was empty), so every existing test stubbed
/// the `PublishCrlFn` closure instead of exercising the real builder/retry/self-heal wiring
/// (#4828). Modeled on `QuarantineContainmentReconciler` (a `Deps`-injected class that already
/// owns its own system-principal audit write) rather than a pure-function extraction
/// (`dispatch_confined_arms.hpp`, `leader_gate.hpp`) — CA-key load + RAII zero + the retry loop +
/// metrics + audit make this a stateful component, not a pure decision function.
///
/// `CrlPublisher` remains the SOLE production caller of `CaStore::publish_next_crl` — the PKI
/// routed-concern row's "one publisher, extend it, never fork a second one" invariant is
/// preserved by construction: every `PublishCrlFn` closure (boot pre-publish, the freshness
/// pass, the REST/dashboard/MCP route handlers) forwards through this class.
///
/// WS-3 two-planes rule (routed-concern row, "Fenced leader election"): `CrlPublisher` NEVER
/// consults the leader elector or epoch-fences anything. `freshness_tick()` is the decision +
/// publish + backoff bookkeeping ONLY — the caller (server.cpp's health-recompute loop) is
/// responsible for `YUZU_ASSERT_BACKGROUND_JOB("ca.publish_crl")` and
/// `leader_gate_permits<background_job_class("ca.publish_crl")>(...)` BEFORE calling it. The
/// operator-synchronous revoke/import paths call `publish()` directly, on their own plane,
/// exactly as before this extraction — that asymmetry is deliberate (two-dispatch-planes rule),
/// not something this class arbitrates.

#include "ca_store.hpp"

#include <yuzu/metrics.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class AuditStore;
class KeyProvider;

/// Why a CRL publish was attempted (#4829) — drives whether `CrlPublisher` writes its own
/// system-principal `ca.crl.published` audit row. `Operator` means the caller (a REST/dashboard/
/// MCP handler with a live request) already owns its own audit row via its own `audit_fn` call —
/// `CrlPublisher` stays silent for that trigger, exactly as `publish_crl()` did before this
/// extraction (only the revoke path audited; the boot/freshness/self-heal paths did not — #4829
/// closes that gap for the three triggers `CrlPublisher` itself now understands).
enum class CrlTrigger { Startup, Freshness, SelfHeal, Operator };

class CrlPublisher {
public:
    struct Deps {
        CaStore* ca_store = nullptr;
        yuzu::MetricsRegistry* metrics = nullptr;
        AuditStore* audit_store = nullptr; // nullable — system-principal audit is best-effort,
                                            // same posture as QuarantineContainmentReconciler
        // Production wiring MUST be `auth_key_provider_.get()` (server.cpp) — an existing
        // FileKeyProvider over the identical `cfg_.ca_dir`/`auth::default_cert_dir()` directory
        // the old inline `publish_crl()` re-derived and re-opened on every call. Minting a
        // second FileKeyProvider over the same directory is the exact drift several other
        // call sites in server.cpp (webhook/runtime-config/offload secret codecs) carry an
        // explicit "never do this" comment about — this class must not reintroduce it.
        KeyProvider* key_provider = nullptr;
        // Unset = system_clock::now(). Overridable so a test can assert #4831's backdate
        // deterministically without racing the real clock.
        std::function<std::chrono::system_clock::time_point()> now_fn;
    };

    explicit CrlPublisher(Deps deps);

    /// Build + record a new CRL version over the current revoked set, signed by the CA, and
    /// return its DER. `background` = the freshness pass calling in: it skips (sets `*skipped`)
    /// rather than queuing behind another publish in this process, so it never delays whatever
    /// runs after it on the same background thread. A skip is not a failure — no counter
    /// increment, no audit row, no failure-mapped `CrlTrigger` outcome. Every other outcome
    /// (success, or a real failure) is reported exactly once, and — for `trigger` in
    /// {Startup, Freshness, SelfHeal} — audited exactly once.
    std::optional<std::vector<std::uint8_t>> publish(bool background, bool* skipped,
                                                      CrlTrigger trigger);

    /// The freshness pass's pure DECISION (#4828 AC4 / #4830): given the store's current state,
    /// should a background publish happen now, and why? No side effects, no clock mutation — a
    /// test can call this directly without going through `freshness_tick()`'s backoff
    /// bookkeeping. Mirrors the staleness/self-heal check that used to be inlined in
    /// server.cpp's health-recompute loop.
    struct FreshnessDecision {
        bool act{false};           // true => the caller should publish(true, ..., reason)
        CrlTrigger reason{CrlTrigger::Freshness}; // meaningful only when act == true
        // `has_unpublished_revocations()` itself failed (a genuine store-read error, not "no
        // revocation is missing") — act is false either way; the caller backs off the SAME as a
        // failed publish would, so the check is retried on a bounded cadence rather than every
        // 15s tick, but this is reported as its own outcome (not folded into "publish failed")
        // because no publish was even attempted.
        bool check_degraded{false};
    };
    [[nodiscard]] FreshnessDecision decide_freshness_tick() const;

    /// `decide_freshness_tick()` + `publish()` + the steady_clock backoff bookkeeping (1 minute
    /// on a degraded unpublished-revocation check, 5 minutes on any other publish failure, no
    /// change on a skip or a no-op tick). The CALLER (server.cpp) is responsible for the
    /// leader-gate check and any "is it even time to look" throttle against ITS OWN cadence
    /// BEFORE calling this — `CrlPublisher` never touches the leader elector (see this file's
    /// header banner) and applies only its OWN internal backoff, which exists to stop a
    /// persistent failure from spamming logs + the failure counter on every 15s tick, not to
    /// decide whether this replica is allowed to run the tick at all.
    void freshness_tick(std::chrono::steady_clock::time_point now_steady);

private:
    [[nodiscard]] std::chrono::system_clock::time_point now() const;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> fail(CaStore::PublishFailReason reason,
                                                                CrlTrigger trigger);
    void audit_publish(bool success, CrlTrigger trigger, std::optional<std::uint64_t> crl_number);

    Deps d_;
    // Backoff state, formerly `ServerImpl::crl_freshness_retry_after_`. Moved here because
    // `freshness_tick()` (which owns the decision this backoff paces) moved here too — the
    // tick-cadence throttle and the decision it protects belong to the same component.
    std::chrono::steady_clock::time_point retry_after_{};
};

} // namespace yuzu::server
