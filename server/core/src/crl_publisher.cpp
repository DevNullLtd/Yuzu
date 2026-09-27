#include "crl_publisher.hpp"

#include "audit_store.hpp"
#include "key_provider.hpp"
#include "scoped_key_zero.hpp"
#include "x509_ca.hpp"

#include <spdlog/spdlog.h>

#include <ctime>

namespace yuzu::server {

namespace {

std::string_view trigger_label(CrlTrigger t) {
    switch (t) {
    case CrlTrigger::Startup:
        return "startup";
    case CrlTrigger::Freshness:
        return "freshness";
    case CrlTrigger::SelfHeal:
        return "self_heal";
    case CrlTrigger::Operator:
        return "operator";
    }
    return "unknown";
}

} // namespace

CrlPublisher::CrlPublisher(Deps deps) : d_(std::move(deps)) {}

std::chrono::system_clock::time_point CrlPublisher::now() const {
    return d_.now_fn ? d_.now_fn() : std::chrono::system_clock::now();
}

void CrlPublisher::audit_publish(bool success, CrlTrigger trigger,
                                 std::optional<std::uint64_t> crl_number) {
    // Operator-triggered publishes are audited by the caller (a REST/dashboard/MCP handler with
    // a live request, which already has richer context — a serial, an import outcome — than
    // this class does) — see this file's header banner.
    if (trigger == CrlTrigger::Operator)
        return;
    if (!d_.audit_store || !d_.audit_store->is_open())
        return;
    AuditEvent ev;
    ev.timestamp =
        std::chrono::duration_cast<std::chrono::seconds>(now().time_since_epoch()).count();
    ev.principal = "system";
    ev.principal_role = "system";
    ev.action = "ca.crl.published";
    ev.target_type = "Security";
    ev.target_id = crl_number ? std::to_string(*crl_number) : "crl";
    ev.detail = "reason=" + std::string(trigger_label(trigger));
    ev.result = success ? "success" : "failure";
    // A failed audit WRITE must not be silent either — same rationale as
    // QuarantineContainmentReconciler::audit_event, whose shape this mirrors.
    if (!d_.audit_store->log(ev))
        spdlog::error("CrlPublisher: audit write failed for trigger={} result={}",
                      trigger_label(trigger), ev.result);
}

std::optional<std::vector<std::uint8_t>> CrlPublisher::fail(CaStore::PublishFailReason reason,
                                                             CrlTrigger trigger) {
    if (d_.metrics) {
        d_.metrics->counter("yuzu_server_ca_crl_publish_failures_total").increment();
        d_.metrics
            ->counter("yuzu_server_ca_crl_publish_failure_reason_total",
                     {{"reason",
                       std::string(CaStore::kPublishFailReasonLabels[static_cast<std::size_t>(
                           reason)])}})
            .increment();
    }
    audit_publish(/*success=*/false, trigger, std::nullopt);
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> CrlPublisher::publish(bool background, bool* skipped,
                                                                CrlTrigger trigger) {
    if (!d_.ca_store || !d_.ca_store->is_open())
        return std::nullopt;
    try {
        for (int attempt = 1; attempt <= 2; ++attempt) {
            auto root_or_err = d_.ca_store->get_root();
            if (!root_or_err) {
                spdlog::error("PKI: CRL publish aborted — ca_store read failed: {}",
                              root_or_err.error());
                return fail(CaStore::PublishFailReason::RootReadFailed, trigger);
            }
            auto& root = *root_or_err;
            if (!root)
                return std::nullopt; // genuinely no root configured — not a failure
            if (!d_.key_provider) {
                spdlog::error("PKI: no CA key provider configured — CRL not published");
                return fail(CaStore::PublishFailReason::KeyLoad, trigger);
            }
            auto ca_key = d_.key_provider->load_key(root->key_ref);
            if (!ca_key) {
                spdlog::error("PKI: cannot load CA issuing key — CRL not published");
                return fail(CaStore::PublishFailReason::KeyLoad, trigger);
            }
            detail::ScopedKeyZero ca_key_zero{*ca_key};

            // #1296: stamp the signing CA's identity on the CRL row — the issuance-time cert
            // fingerprint plus the STABLE key id (invariant across a subordinate re-key) so the
            // CRL history is attributable to the key, not just a cert.
            std::string issuer_key_id;
            if (auto kid = pki::issuer_key_id(root->cert_pem))
                issuer_key_id = *kid;

            auto build = [&](std::uint64_t number, const std::vector<IssuedCertRecord>& rows)
                -> std::optional<CaStore::BuiltCrl> {
                std::vector<pki::CrlRevocation> revoked;
                revoked.reserve(rows.size());
                for (const auto& r : rows) {
                    revoked.push_back({r.serial_hex, std::chrono::system_clock::time_point{
                                                         std::chrono::seconds{r.revoked_at}}});
                }
                // #4831: backdated by the same clock-skew allowance leaf certs already get
                // (pki::kClockSkewBackdate) — without it, a replica whose clock runs even
                // slightly ahead of another can publish a CRL other replicas' relying parties
                // (or a validator on a still-catching-up host) reject as CRL_NOT_YET_VALID.
                const auto build_now = now();
                const pki::Validity validity{build_now - pki::kClockSkewBackdate,
                                             build_now + std::chrono::hours(24 * 7)};
                auto der = pki::build_crl(root->cert_pem, *ca_key, revoked, validity, number);
                if (!der) {
                    spdlog::error("PKI: build_crl failed for CRL v{}", number);
                    return std::nullopt;
                }
                return CaStore::BuiltCrl{
                    std::move(*der),
                    std::chrono::duration_cast<std::chrono::seconds>(
                        validity.not_before.time_since_epoch())
                        .count(),
                    std::chrono::duration_cast<std::chrono::seconds>(
                        validity.not_after.time_since_epoch())
                        .count()};
            };

            auto rec = background
                           ? d_.ca_store->publish_next_crl(build, root->fingerprint_sha256,
                                                           issuer_key_id,
                                                           std::chrono::milliseconds{0})
                           : d_.ca_store->publish_next_crl(build, root->fingerprint_sha256,
                                                           issuer_key_id);
            if (rec) {
                audit_publish(/*success=*/true, trigger,
                              static_cast<std::uint64_t>(rec->version));
                return std::move(rec->der);
            }
            if (background && rec.error().kind == CaStore::PublishError::Busy) {
                if (skipped)
                    *skipped = true;
                return std::nullopt; // a skip is not a failure — no counter, no audit
            }
            if (rec.error().kind == CaStore::PublishError::RootChanged && attempt == 1) {
                spdlog::info(
                    "PKI: CA root changed during CRL publish — retrying with the new root");
                continue;
            }
            // B-1 (#1240): never report success unless the new CRL is durably recorded.
            spdlog::error("PKI: CRL publish failed — see the CaStore::publish_next_crl log line "
                          "above for the cause");
            // A foreground (background==false) Busy falls through to here too: the freshness
            // pass's "skip, let the next leader-gated tick retry" contract is specific to the
            // background caller — an operator-triggered publish (revoke/import) must report
            // failure rather than silently no-op. RootChanged surviving both attempts is
            // reported as its own, more specific reason (giving up, not just "a root read
            // disagreed once") than ca_store's own per-attempt PublishFailReason.
            const CaStore::PublishFailReason reason =
                rec.error().kind == CaStore::PublishError::RootChanged
                    ? CaStore::PublishFailReason::RootChangedTwice
                : rec.error().kind == CaStore::PublishError::Busy
                    ? CaStore::PublishFailReason::Busy
                    : rec.error().reason;
            return fail(reason, trigger);
        }
    } catch (const std::exception& e) {
        // The store rolled back; never let a builder exception escape a background thread.
        spdlog::error("PKI: CRL publish threw: {} — CRL not published", e.what());
        return fail(CaStore::PublishFailReason::Exception, trigger);
    } catch (...) {
        spdlog::error("PKI: CRL publish threw a non-standard exception — CRL not published");
        return fail(CaStore::PublishFailReason::Exception, trigger);
    }
    return fail(CaStore::PublishFailReason::Exception, trigger); // unreachable: every loop
                                                                  // iteration returns or continues
}

CrlPublisher::FreshnessDecision CrlPublisher::decide_freshness_tick() const {
    if (!d_.ca_store || !d_.ca_store->is_open() || !d_.ca_store->has_root())
        return {};
    // nextUpdate is a wall-clock epoch → compare with wall time (the injected `now_fn`, when
    // set, so a test can drive this deterministically — production leaves it unset and reads
    // the real clock, exactly as the pre-extraction inline check did with std::time()).
    const auto now_epoch =
        std::chrono::duration_cast<std::chrono::seconds>(now().time_since_epoch()).count();
    auto latest = d_.ca_store->latest_crl();
    const bool stale = !latest || (latest->next_update - now_epoch) < 24 * 3600;
    if (stale)
        return {.act = true, .reason = CrlTrigger::Freshness};
    // HA WS-6 6.1 (UP-1): also re-publish when the latest CRL was not built from the current
    // revoked set — a revoke whose own publish failed (lock timeout, pool exhaustion) would
    // otherwise stay out of the served CRL until the nextUpdate window.
    auto missing = d_.ca_store->has_unpublished_revocations();
    if (!missing) {
        spdlog::warn("PKI: unpublished-revocation check skipped: {}", missing.error());
        return {.check_degraded = true};
    }
    if (*missing)
        return {.act = true, .reason = CrlTrigger::SelfHeal};
    return {};
}

void CrlPublisher::freshness_tick(std::chrono::steady_clock::time_point now_steady) {
    // Backoff (steady_clock — immune to NTP jumps): after a failed publish or a degraded
    // unpublished-revocation check, don't retry every tick.
    if (now_steady < retry_after_)
        return;
    const auto decision = decide_freshness_tick();
    if (decision.check_degraded) {
        // Throttle: a persistent read failure retries once a minute, not every 15s tick.
        retry_after_ = now_steady + std::chrono::minutes(1);
        return;
    }
    if (!decision.act)
        return;
    bool skipped = false;
    if (publish(/*background=*/true, &skipped, decision.reason)) {
        spdlog::info("PKI: CRL re-published ({})",
                    decision.reason == CrlTrigger::Freshness
                        ? "nextUpdate window"
                        : "the latest CRL did not cover every revocation");
    } else if (!skipped) {
        // Another publish is running in this process; recheck next tick rather than backing off
        // — a skip is transient contention, not a failure.
        retry_after_ = now_steady + std::chrono::minutes(5);
    }
}

} // namespace yuzu::server
