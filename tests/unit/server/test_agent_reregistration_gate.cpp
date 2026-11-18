/**
 * test_agent_reregistration_gate.cpp - WP01: the pure decision both agent ingest paths share
 * (server/core/src/agent_reregistration_gate.hpp). The handler-level behaviour is pinned in
 * test_agent_service_impl.cpp; this file pins the truth table and the mode/option contract.
 */

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include <yuzu/server/server.hpp>

#include "agent_reregistration_apply.hpp"
#include "agent_reregistration_gate.hpp"

using namespace yuzu::server;

namespace {
constexpr AgentLeafState kLive{.has_live = true, .has_revoked_unexpired = false};
constexpr AgentLeafState kNone{.has_live = false, .has_revoked_unexpired = false};
constexpr AgentLeafState kRevoked{.has_live = false, .has_revoked_unexpired = true};
constexpr AgentLeafState kLiveAndRevoked{.has_live = true, .has_revoked_unexpired = true};

ReregistrationOutcome decide(const AgentLeafState& s, bool cert, bool token, bool can_prove = true) {
    return decide_reregistration(
        std::expected<AgentLeafState, std::string>{s},
        ReregistrationEvidence{.cert_proves_identity = cert,
                               .token_presented = token,
                               .transport_can_prove = can_prove});
}

std::string join_rows(const std::vector<std::string>& rows) {
    std::string out;
    for (const auto& r : rows)
        out += r + "\n";
    return out;
}
std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + 1))
        ++n;
    return n;
}
/// Number of ids listed in ONE chunk row (the text after `ids=`).
std::size_t ids_in_row(const std::string& row) {
    const auto at = row.find(" ids=");
    if (at == std::string::npos)
        return 0;
    const auto list = row.substr(at + 5);
    return list.empty() ? 0 : count_of(list, ",") + 1;
}
} // namespace

TEST_CASE("reregistration gate: an id with no live leaf is not the gate's business",
          "[reregistration_gate][wp01]") {
    for (bool cert : {false, true})
        for (bool token : {false, true})
            for (bool can_prove : {false, true})
                CHECK(decide(kNone, cert, token, can_prove) == ReregistrationOutcome::NoLeafOnRecord);
}

TEST_CASE("reregistration gate: a live leaf needs the current leaf or a token",
          "[reregistration_gate][wp01]") {
    CHECK(decide(kLive, true, false) == ReregistrationOutcome::ProvenByLeaf);
    CHECK(decide(kLive, true, true) == ReregistrationOutcome::ProvenByLeaf); // the leaf wins
    CHECK(decide(kLive, false, true) == ReregistrationOutcome::ViaToken);
    CHECK(decide(kLive, false, false) == ReregistrationOutcome::RefuseNoProof);
    // A listener that cannot witness is reported as such BEFORE the token is looked at, so a stale
    // token cannot disguise it as the healthy `via_token` outcome.
    CHECK(decide(kLive, false, false, /*can_prove=*/false) == ReregistrationOutcome::RefuseUnattested);
    CHECK(decide(kLive, false, true, /*can_prove=*/false) == ReregistrationOutcome::RefuseUnattested);
    // A live leaf beside an operator-revoked one (UP-5 / CH-7a): sign_agent_csr's HIGH-2 guard
    // would refuse the issuance, so a token must NOT be consumed for it: refuse BEFORE the token
    // block, token or not. Only the current leaf proves it.
    CHECK(decide(kLiveAndRevoked, false, false) == ReregistrationOutcome::RefuseRevokedIdentity);
    CHECK(decide(kLiveAndRevoked, false, true) == ReregistrationOutcome::RefuseRevokedIdentity);
    CHECK(decide(kLiveAndRevoked, true, false) == ReregistrationOutcome::ProvenByLeaf);
}

TEST_CASE("reregistration gate: a revoked identity with nothing live is refused, token or not",
          "[reregistration_gate][wp01]") {
    for (bool token : {false, true})
        for (bool can_prove : {false, true})
            CHECK(decide(kRevoked, false, token, can_prove) ==
                  ReregistrationOutcome::RefuseRevokedIdentity);
    // Evidence from the transport cannot override it either (an unrevoked-looking cert for a
    // revoked identity is a contradiction the cert checks already refuse upstream).
    CHECK(decide(kRevoked, true, true) == ReregistrationOutcome::RefuseRevokedIdentity);
}

TEST_CASE("reregistration gate: a lookup failure is its own outcome, never 'no leaf'",
          "[reregistration_gate][wp01]") {
    const auto o = decide_reregistration(std::unexpected(std::string("ca store down")),
                                         ReregistrationEvidence{.cert_proves_identity = true,
                                                                .token_presented = true});
    CHECK(o == ReregistrationOutcome::LookupFailed);
    CHECK_FALSE(is_refusal(o)); // the caller answers it UNAVAILABLE (retryable), not UNAUTHENTICATED
}

TEST_CASE("reregistration gate: exactly the three refusal outcomes refuse",
          "[reregistration_gate][wp01]") {
    CHECK(is_refusal(ReregistrationOutcome::RefuseNoProof));
    CHECK(is_refusal(ReregistrationOutcome::RefuseUnattested));
    CHECK(is_refusal(ReregistrationOutcome::RefuseRevokedIdentity));
    CHECK_FALSE(is_refusal(ReregistrationOutcome::NoLeafOnRecord));
    CHECK_FALSE(is_refusal(ReregistrationOutcome::ProvenByLeaf));
    CHECK_FALSE(is_refusal(ReregistrationOutcome::ViaToken));
    CHECK_FALSE(is_refusal(ReregistrationOutcome::LookupFailed));
}

TEST_CASE("reregistration proof mode: exact spellings only, a typo never weakens the mode",
          "[reregistration_gate][wp01]") {
    CHECK(parse_reregistration_proof_mode("off") == ReregistrationProofMode::Off);
    CHECK(parse_reregistration_proof_mode("audit") == ReregistrationProofMode::Audit);
    CHECK(parse_reregistration_proof_mode("enforce") == ReregistrationProofMode::Enforce);
    for (const char* bad : {"", "Enforce", "ENFORCE", "enforced", "on", "true", " audit", "audit "})
        CHECK_FALSE(parse_reregistration_proof_mode(bad).has_value());
    // The compiled-in default is audit (owner decision D3).
    Config cfg;
    CHECK(cfg.agent_reregistration_proof == "audit");
    CHECK(parse_reregistration_proof_mode(cfg.agent_reregistration_proof) ==
          ReregistrationProofMode::Audit);
}

TEST_CASE("reregistration refusal message does not name the reason", "[reregistration_gate][wp01]") {
    const std::string m(kReregistrationRefusalPublicMessage);
    for (const char* leak : {"revoked", "leaf", "certificate", "exists", "enrolled"})
        CHECK(m.find(leak) == std::string::npos);
}

TEST_CASE("unproven audit budget: exact numbers - per-source sub-cap, reserved bucket for first-ever "
          "ids, global backstop, distinct counts, time flush",
          "[reregistration_gate][wp01][audit_budget]") {
    using B = detail::UnprovenAuditBudget;
    B b;
    std::int64_t t = 1'000'000;
    const auto admit = [&](const std::string& id, const std::string& src) {
        return b.admit(id, src, t).admitted;
    };

    // W0: 300 ids, each from its OWN source: all admitted (reserved 250 + 50 general), and every id
    // becomes "recent" (no longer first-ever).
    for (int i = 0; i < 300; ++i)
        CHECK(admit("pre-" + std::to_string(i), "src-" + std::to_string(i)));
    t += B::kWindowMs + 1;

    // W1, per-SOURCE sub-cap: one attacker source naming 200 already-known (non-first-ever) ids is
    // cut to exactly kRowsPerSource rows.
    int admitted = 0;
    for (int i = 0; i < 200; ++i)
        admitted += admit("pre-" + std::to_string(i), "attacker") ? 1 : 0;
    CHECK(admitted == static_cast<int>(B::kRowsPerSource));
    // The reserved bucket: a first-ever victim id from ANOTHER source is admitted regardless.
    CHECK(admit("victim-first-ever", "victim-src"));

    // The attacker spends the GENERAL budget from 25 more sources (50 each... capped at the global
    // backstop); the reserved bucket still admits first-ever ids until its own cap.
    t += B::kWindowMs + 1;
    int general = 0;
    for (int srcn = 0; srcn < 30; ++srcn)
        for (int i = 0; i < 50; ++i)
            general += admit("pre-" + std::to_string((srcn * 50 + i) % 300), "bot-" + std::to_string(srcn)) ? 1 : 0;
    CHECK(general <= static_cast<int>(B::kGeneralRows));
    CHECK(admit("victim-2", "victim-src")); // first-ever: reserved bucket, not starved
    // Per-id repeats: exactly kRepeatRowsPerId rows.
    int repeats = 0;
    for (int i = 0; i < 10; ++i)
        repeats += admit("victim-2", "victim-src") ? 1 : 0;
    CHECK(repeats == static_cast<int>(B::kRepeatRowsPerId) - 1); // the first admit above was row 1

    // Time-based flush: the closed window's summary is available WITHOUT a later admit.
    CHECK(b.poll_closed(t + 1, /*force=*/false).empty()); // still open
    t += B::kWindowMs + 1;
    const std::string summary = join_rows(b.poll_closed(t, /*force=*/false));
    CHECK(summary.find("dropped_rows=") != std::string::npos);
    CHECK(summary.find("distinct_dropped_ids=") != std::string::npos);
    CHECK(summary.find("sources=") != std::string::npos);
    CHECK(summary.find("bot-") != std::string::npos); // per-source counts, not a caller identity
    CHECK(b.poll_closed(t, false).empty());           // delivered once
}

TEST_CASE("unproven audit budget: a legitimate restart storm, the shutdown flush and the global backstop",
          "[reregistration_gate][wp01][audit_budget]") {
    using B = detail::UnprovenAuditBudget;
    B b;
    std::int64_t t = 5'000'000;
    // 2000 distinct first-ever ids from 2000 sources in one window: kReservedRows + kGeneralRows
    // are written, the rest dropped and COUNTED as distinct ids.
    int admitted = 0;
    for (int i = 0; i < 2000; ++i)
        admitted += b.admit("storm-" + std::to_string(i), "s" + std::to_string(i), t).admitted ? 1 : 0;
    CHECK(admitted == static_cast<int>(B::kReservedRows + B::kGeneralRows));
    // Shutdown flush closes the OPEN window and reports it (otherwise lost on exit).
    const std::string summary = join_rows(b.poll_closed(t + 1, /*force=*/true));
    CHECK(summary.find("dropped_rows=750") != std::string::npos);
    CHECK(summary.find("distinct_dropped_ids=750") != std::string::npos);
    CHECK(b.poll_closed(t + 2, true).empty());
}

TEST_CASE("reregistration audit sink path: the aggregate row is a system row with no caller identity",
          "[reregistration_gate][wp01]") {
    const std::expected<AgentLeafState, std::string> live{AgentLeafState{.has_live = true}};
    AgentIdentityHooks hooks;
    hooks.leaf_state = [&](const std::string&) { return live; };
    int refusal_rows = 0, unproven_rows = 0, aggregate_rows = 0;
    std::string aggregate_extra;
    const ReregistrationAuditSink sink = [&](std::string_view action, std::string_view,
                                             std::string_view outcome, std::string_view,
                                             std::string_view extra) {
        if (outcome == "aggregate") {
            ++aggregate_rows;
            aggregate_extra = std::string(extra);
        } else if (action == kAuditActionReregistrationUnproven) {
            ++unproven_rows;
        } else {
            ++refusal_rows;
        }
    };
    yuzu::MetricsRegistry metrics;
    const ReregistrationEvidence ev{};
    auto audit_attempt = [&](const std::string& id, const std::string& src) {
        (void)apply_reregistration_gate(ReregistrationProofMode::Audit, &hooks, "direct", id, id, ev,
                                        &metrics, sink, src);
    };
    detail::reregistration_audit_clock_skew_ms() += 1'000'000;
    audit_attempt("window-reset", "x");
    detail::reregistration_audit_clock_skew_ms() += 11'000;
    audit_attempt("window-reset2", "x");
    unproven_rows = aggregate_rows = 0;
    // 100 repeats of one id from one source: 3 rows, 97 dropped and counted.
    for (int i = 0; i < 100; ++i)
        audit_attempt("victim-loop", "9.9.9.9");
    CHECK(unproven_rows == static_cast<int>(detail::UnprovenAuditBudget::kRepeatRowsPerId));
    CHECK(metrics.counter("yuzu_register_reregistration_audit_dropped_total",
                          {{"action", std::string(kAuditActionReregistrationUnproven)}})
              .value() == 97.0);
    // The summary is flushed by TIME (the server's tick), not by a later admit.
    detail::reregistration_audit_clock_skew_ms() += 11'000;
    const auto summary = join_rows(detail::reregistration_unproven_budget().poll_closed(
        detail::reregistration_audit_now_ms(), false));
    CHECK(summary.find("dropped_rows=97") != std::string::npos);
    CHECK(summary.find("9.9.9.9:97") != std::string::npos);
    CHECK(summary.find("victim-loop") != std::string::npos);
    // The decision counter is NOT sampled: every attempt above was counted.
    CHECK(metrics.counter("yuzu_register_reregistration_total",
                          {{"path", "direct"}, {"outcome", "no_proof"}, {"mode", "audit"}})
              .value() >= 102.0);
    CHECK(aggregate_rows == 0); // no later admit was needed to flush

    // enforce: a flood on ONE id is bounded to the refusal budget, still refused each time.
    for (int i = 0; i < 100; ++i) {
        const auto v = apply_reregistration_gate(ReregistrationProofMode::Enforce, &hooks, "direct",
                                                 "flood-id", "flood-id", ev, &metrics, sink);
        CHECK(v.route == ReregistrationVerdict::Route::Refuse);
    }
    CHECK(refusal_rows > 0);
    CHECK(refusal_rows <= static_cast<int>(kDefaultAuditMaxRows));
}

// ---- WP01 Gate 8 pass 4 (N3): every dropped id stays on record, in chunked rows --------------

namespace {
/// Admits `ids` from `src_of(i)` in the CURRENT window so they become "recent" (non-first-ever).
void seed_recent(detail::UnprovenAuditBudget& b, std::int64_t& t, int first, int last) {
    using B = detail::UnprovenAuditBudget;
    for (int i = first; i < last; ++i)
        REQUIRE(b.admit("live-" + std::to_string(i), "seed-" + std::to_string(i / 40), t).admitted);
    t += B::kWindowMs + 1;
}
} // namespace

TEST_CASE("unproven audit budget: ONE source naming 300 distinct live-leaf ids - every dropped id is "
          "on record (chunked, drop order)",
          "[reregistration_gate][wp01][audit_budget][audit]") {
    using B = detail::UnprovenAuditBudget;
    B b;
    std::int64_t t = 9'000'000;
    seed_recent(b, t, 0, 400); // 400 ids are now recent: the reserved bucket no longer shelters them
    int admitted = 0;
    for (int i = 0; i < 300; ++i)
        admitted += b.admit("live-" + std::to_string(i), "attacker", t).admitted ? 1 : 0;
    CHECK(admitted == static_cast<int>(B::kRowsPerSource));
    // A victim naming a recent id from ANOTHER source still gets a row.
    CHECK(b.admit("live-399", "victim-src", t).admitted);
    t += B::kWindowMs + 1;
    const auto rows = b.poll_closed(t, false);
    REQUIRE(rows.size() == 2); // 250 dropped ids: 200 + 50
    for (const auto& r : rows)
        CHECK(r.find("ids_truncated=0") != std::string::npos);
    CHECK(ids_in_row(rows[0]) == B::kSummaryIds);
    CHECK(ids_in_row(rows[1]) == 250 - B::kSummaryIds);
    const auto all = join_rows(rows);
    for (int i = static_cast<int>(B::kRowsPerSource); i < 300; ++i) // dropped, in DROP order
        CHECK((all.find("live-" + std::to_string(i) + ",") != std::string::npos ||
               all.find("live-" + std::to_string(i) + "\n") != std::string::npos));
    CHECK(rows[0].find("part=1/2") != std::string::npos);
    CHECK(rows[1].find("part=2/2") != std::string::npos);
    CHECK(rows[0].find(" ids=live-50,live-51,") != std::string::npos); // drop order, not sorted order
}

TEST_CASE("unproven audit budget: a restart storm behind one origin-less gateway shares ONE source",
          "[reregistration_gate][wp01][audit_budget][audit]") {
    using B = detail::UnprovenAuditBudget;
    B b;
    std::int64_t t = 12'000'000;
    seed_recent(b, t, 0, 300);
    for (int i = 0; i < 300; ++i)
        (void)b.admit("live-" + std::to_string(i), "10.1.2.3", t); // the gateway's IP for all of them
    t += B::kWindowMs + 1;
    const auto rows = b.poll_closed(t, false);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].find("dropped_rows=250") != std::string::npos);
    CHECK(rows[0].find("sources=10.1.2.3:250") != std::string::npos);
    CHECK(rows[0].find("distinct_dropped_ids=250") != std::string::npos);
    // Nothing the old 200-id cut dropped is missing: the last dropped id is named.
    CHECK(join_rows(rows).find("live-299") != std::string::npos);
}

TEST_CASE("unproven audit budget: 2000 rotating sources - the source table is bounded and every id is "
          "named",
          "[reregistration_gate][wp01][audit_budget][audit]") {
    using B = detail::UnprovenAuditBudget;
    B b;
    std::int64_t t = 15'000'000;
    seed_recent(b, t, 0, 1000);
    seed_recent(b, t, 1000, 2000);
    int admitted = 0;
    for (int i = 0; i < 2000; ++i)
        admitted += b.admit("live-" + std::to_string(i), "rot-" + std::to_string(i), t).admitted ? 1 : 0;
    CHECK(admitted == static_cast<int>(B::kGeneralRows));
    t += B::kWindowMs + 1;
    const auto rows = b.poll_closed(t, false);
    REQUIRE(rows.size() == 5); // 1000 dropped ids, 200 per chunk
    const auto all = join_rows(rows);
    for (int i = 1000; i < 2000; ++i)
        CHECK(all.find("live-" + std::to_string(i)) != std::string::npos);
    // The tracked source set is capped at kMaxSources; the rest share `other`.
    CHECK(all.find("other:") != std::string::npos);
    for (const auto& r : rows)
        CHECK(r.size() < 8192);
}

TEST_CASE("unproven audit budget: beyond 20000 distinct dropped ids the excess is COUNTED on every chunk, "
          "never silent",
          "[reregistration_gate][wp01][audit_budget][audit]") {
    using B = detail::UnprovenAuditBudget;
    B b;
    std::int64_t t = 20'000'000;
    (void)b.admit("opener", "x", t);
    for (int i = 0; i < 25'000; ++i)
        (void)b.admit("flood-" + std::to_string(i), "atk", t);
    t += B::kWindowMs + 1;
    const auto rows = b.poll_closed(t, false);
    // "opener" took one reserved slot; of the 25000 first-ever flood ids the other kReservedRows-1
    // reserved slots and kRowsPerSource source slots are admitted, the rest dropped.
    const std::size_t dropped = 25'000 - (B::kReservedRows - 1) - B::kRowsPerSource;
    REQUIRE(rows.size() == B::kMaxDroppedIds / B::kSummaryIds);
    const auto trunc = std::to_string(dropped - B::kMaxDroppedIds);
    for (const auto& r : rows) {
        CHECK(r.find(" ids_truncated=" + trunc + " ") != std::string::npos);
        CHECK(ids_in_row(r) <= B::kSummaryIds);
    }
    CHECK(rows[0].find("distinct_dropped_ids=" + std::to_string(dropped)) != std::string::npos);
    CHECK(b.take_ids_truncated() == dropped - B::kMaxDroppedIds);
    CHECK(b.take_ids_truncated() == 0);
}

TEST_CASE("unproven audit budget: the pending queue is bounded and a failing write is retried then counted",
          "[reregistration_gate][wp01][audit_budget][audit]") {
    using B = detail::UnprovenAuditBudget;
    B b;
    std::int64_t t = 30'000'000;
    for (int w = 0; w < 2; ++w) { // two full windows: 2 x 100 chunks into a 128-row queue
        (void)b.admit("opener", "x", t);
        for (int i = 0; i < 25'000; ++i)
            (void)b.admit("w" + std::to_string(w) + "-" + std::to_string(i), "atk", t);
        t += B::kWindowMs + 1;
        (void)b.poll_closed(t, false);
    }
    CHECK(b.pending_size() == B::kMaxPendingRows);
    CHECK(b.take_queue_full_dropped() == 200 - B::kMaxPendingRows);
    // A chunk that keeps failing is handed back kMaxWriteAttempts-1 times, then dropped.
    auto row = b.take_pending();
    REQUIRE(row.has_value());
    int requeued = 0;
    while (b.requeue_front(*row)) {
        ++requeued;
        row = b.take_pending();
        REQUIRE(row.has_value());
    }
    CHECK(requeued == B::kMaxWriteAttempts - 1);
    CHECK(b.discard_pending() == B::kMaxPendingRows - 1);
}

TEST_CASE("flush_reregistration_audit_summary: a closed/absent audit store is retried then counted, never "
          "silent; the shutdown flush drops the rest with a reason",
          "[reregistration_gate][wp01][audit_budget][audit]") {
    yuzu::MetricsRegistry metrics;
    auto& budget = detail::reregistration_unproven_budget();
    while (budget.take_pending()) {
    }
    (void)budget.take_ids_truncated();
    (void)budget.take_queue_full_dropped();
    detail::reregistration_audit_clock_skew_ms() += 5'000'000;
    (void)budget.admit("a", "s", detail::reregistration_audit_now_ms());
    while (budget.take_pending()) { // a stale window an earlier test left open closes here
    }
    for (int i = 0; i < 5; ++i)
        (void)budget.admit("recent-" + std::to_string(i), "s", detail::reregistration_audit_now_ms());
    detail::reregistration_audit_clock_skew_ms() += 11'000;
    // Make a window with drops: repeats of one id.
    for (int i = 0; i < 10; ++i)
        (void)budget.admit("rep", "s2", detail::reregistration_audit_now_ms());
    detail::reregistration_audit_clock_skew_ms() += 11'000;
    flush_reregistration_audit_summary(nullptr, &metrics, /*force=*/false);
    CHECK(budget.pending_size() == 1); // retried, not lost
    flush_reregistration_audit_summary(nullptr, &metrics, false);
    flush_reregistration_audit_summary(nullptr, &metrics, false); // third failed attempt: dropped
    CHECK(budget.pending_size() == 0);
    CHECK(metrics.counter("yuzu_register_reregistration_audit_summary_dropped_total",
                          {{"reason", "write_failed"}})
              .value() == 1.0);
}

TEST_CASE("unproven audit budget: the summary names the TOP 10 sources by count and neutralises ids",
          "[reregistration_gate][wp01][audit_budget][audit]") {
    using B = detail::UnprovenAuditBudget;
    B b;
    std::int64_t t = 40'000'000;
    char name[16];
    for (int k = 0; k < 12; ++k) { // source k drops k+1 repeats of its own id
        std::snprintf(name, sizeof name, "src-%02d", k);
        for (int i = 0; i < 4 + k; ++i)
            (void)b.admit("rep-" + std::to_string(k), name, t);
    }
    for (int i = 0; i < 5; ++i)
        (void)b.admit("a b/c-and-a-very-long-identifier-0123456789", "src-00", t);
    t += B::kWindowMs + 1;
    const auto rows = b.poll_closed(t, false);
    REQUIRE(rows.size() == 1);
    const auto& r = rows[0];
    CHECK(r.find("sources=src-11:12,src-10:11,") != std::string::npos); // descending
    CHECK(r.find("src-02:3") != std::string::npos);
    CHECK(r.find("src-01") == std::string::npos); // the 11th and 12th source are cut
    CHECK(r.find("src-00") == std::string::npos);
    CHECK(r.find(" ids_truncated=0 part=1/1 ids=") != std::string::npos);
    CHECK(count_of(r, "rep-11") == 1); // a dropped id is named ONCE however often it was dropped
    CHECK(r.find("a?b?c-and-a-very-long-id") != std::string::npos); // 24 chars, '?' for the rest
    CHECK(r.find("a?b?c-and-a-very-long-ide") == std::string::npos);    // cut at 24
}

TEST_CASE("unproven audit budget: the recent-id window is FIFO-bounded (an evicted id is first-ever again)",
          "[reregistration_gate][wp01][audit_budget][audit]") {
    using B = detail::UnprovenAuditBudget;
    B b;
    std::int64_t t = 50'000'000;
    for (int w = 0; w < 7; ++w) { // 7 x 1250 admissions > kRecentIds
        for (int i = 0; i < 1250; ++i)
            REQUIRE(b.admit("w" + std::to_string(w) + "-" + std::to_string(i),
                            "s" + std::to_string(i / 40), t)
                        .admitted);
        t += B::kWindowMs + 1;
    }
    // New window: "atk" spends its per-source slots on RECENT ids...
    int admitted = 0;
    for (int i = 0; i < 60; ++i)
        admitted += b.admit("w6-" + std::to_string(i), "atk", t).admitted ? 1 : 0;
    CHECK(admitted == static_cast<int>(B::kRowsPerSource));
    // ...a still-recent id is now dropped, an EVICTED one (oldest) is first-ever and uses the reserved bucket.
    CHECK_FALSE(b.admit("w6-100", "atk", t).admitted);
    CHECK(b.admit("w0-0", "atk", t).admitted);
}

TEST_CASE("unproven audit budget: the documented constants are pinned (docs and alerts quote them)",
          "[reregistration_gate][wp01][audit_budget][audit]") {
    using B = detail::UnprovenAuditBudget;
    CHECK(B::kRepeatRowsPerId == 3);
    CHECK(B::kReservedRows == 250);
    CHECK(B::kRowsPerSource == 50);
    CHECK(B::kGeneralRows == 1000);
    CHECK(B::kRecentIds == 8192);
    CHECK(B::kSummaryIds == 200);
    CHECK(B::kMaxSources == 1024);
    CHECK(B::kMaxDroppedIds == 20000);
    CHECK(B::kSummarySources == 10);
    CHECK(B::kMaxPendingRows == 128);
    CHECK(B::kMaxWriteAttempts == 3);
    CHECK(B::kWindowMs == 10'000);
    // A full window of dropped ids always fits the pending queue.
    CHECK(B::kMaxDroppedIds / B::kSummaryIds <= B::kMaxPendingRows);
}

TEST_CASE("unproven audit budget: sources past the table cap share ONE uncapped-per-source `other` bucket "
          "(still bounded by the global slot)",
          "[reregistration_gate][wp01][audit_budget][audit]") {
    using B = detail::UnprovenAuditBudget;
    B b;
    std::int64_t t = 60'000'000;
    seed_recent(b, t, 0, 400);
    // Fill the source table with DROP-only sources (one id repeated from 1100 different sources).
    for (int i = 0; i < 1100; ++i)
        (void)b.admit("spam", "sp-" + std::to_string(i), t);
    // 100 recent ids from 100 NEW sources: past the cap they share `other`, which has no per-source
    // slot limit, so all 100 are admitted (a per-source cap of 50 on `other` would admit 50).
    int admitted = 0;
    for (int i = 0; i < 100; ++i)
        admitted += b.admit("live-" + std::to_string(i), "new-" + std::to_string(i), t).admitted ? 1 : 0;
    CHECK(admitted == 100);
    t += B::kWindowMs + 1;
    const auto rows = b.poll_closed(t, false);
    REQUIRE(!rows.empty());
    CHECK(rows[0].find("other:") != std::string::npos);
}
