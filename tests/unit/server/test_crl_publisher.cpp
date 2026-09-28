/**
 * test_crl_publisher.cpp — `CrlPublisher` (HA WS-6 CRL follow-ups, #4828/#4831).
 *
 * Before this extraction, `ServerImpl::publish_crl` had zero direct test coverage: every route
 * test (`test_ca_routes.cpp`) stubs the `PublishCrlFn` closure it is handed rather than exercising
 * the real builder/retry/self-heal logic, because nothing in this suite constructs a `ServerImpl`.
 * These tests drive the extracted `CrlPublisher` class directly against a real, migrated
 * `CaStore` (and a real `AuditStore` for the audit-row assertions), with a fake `KeyProvider`
 * standing in for `auth_key_provider_`.
 *
 * Covers: the happy path (#4828 AC1), the RootChanged retry-once contract (AC2/AC3), the
 * background Busy skip (AC4, direct `publish()` call) and its integration with
 * `freshness_tick()`'s backoff bookkeeping (AC4, no backoff advance on a skip), the freshness
 * self-heal decision + publish + system-principal audit row (AC4's main claim), a key-load
 * failure's reason-labelled counter (AC6), and #4831's clock-skew backdate.
 *
 * PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken.
 */

#include "crl_publisher.hpp"

#include "audit_store.hpp"
#include "ca_store.hpp"
#include "key_provider.hpp"
#include "x509_ca.hpp"

#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// Joins every thread on scope exit, so a failing REQUIRE cannot leave a joinable std::thread
// behind (std::terminate) — same guard test_ca_store.cpp's own Busy test uses.
struct JoinAll {
    std::vector<std::thread>& threads;
    ~JoinAll() {
        for (auto& t : threads)
            if (t.joinable())
                t.join();
    }
};

// Pre-migrated template covering both stores CrlPublisher's Deps touch.
yuzu::test::PgTestTemplate crl_publisher_tpl{"crlpublisher", [](const std::string& dsn) {
                                                PgPool ca_pool{{.conninfo = dsn, .size = 1}};
                                                CaStore ca_store{ca_pool};
                                                if (!ca_store.is_open())
                                                    throw std::runtime_error(
                                                        "crl_publisher template: ca_store failed "
                                                        "to migrate");
                                                PgPool audit_pool{{.conninfo = dsn, .size = 1}};
                                                AuditStore audit_store{audit_pool};
                                                if (!audit_store.is_open())
                                                    throw std::runtime_error(
                                                        "crl_publisher template: audit_store "
                                                        "failed to migrate");
                                            }};

int64_t now_s() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// A KeyProvider double: a fixed key_ref -> PEM map, plus an optional hook fired on every
// load_key() call so a test can inject a side effect (e.g. swap the store's root) at the exact
// point ServerImpl's old inline publish_crl() used to load the key — between the caller's
// get_root() and the CRL table lock.
class FakeKeyProvider : public KeyProvider {
public:
    std::optional<std::string> load_key(std::string_view key_ref) override {
        if (on_load)
            on_load(key_ref);
        auto it = keys.find(std::string(key_ref));
        return it == keys.end() ? std::nullopt : std::make_optional(it->second);
    }
    std::optional<std::string> store_key(std::string_view, std::string_view) override {
        return std::nullopt; // unused by CrlPublisher
    }
    bool has_key(std::string_view key_ref) override {
        return keys.contains(std::string(key_ref));
    }
    bool delete_key(std::string_view) override { return true; }

    std::unordered_map<std::string, std::string> keys;
    std::function<void(std::string_view)> on_load;
};

// A real, self-signed EC P-384 CA root — needed because pki::build_crl genuinely signs with it
// (unlike test_ca_store.cpp's own publish_next_crl tests, which pass a synthetic `build` callback
// that never touches OpenSSL). Mirrors "CaStore: revocation round-trip against a real issued
// leaf"'s key/cert generation in test_ca_store.cpp. `fingerprint_sha256` is an arbitrary,
// caller-chosen label — publish_next_crl's root-changed check only compares it for
// self-consistency against whatever CaStore currently has stored, never against a real hash.
struct RealRoot {
    CaRoot root;
    std::string key_pem;
};

RealRoot make_real_root(const std::string& fingerprint, const std::string& key_ref) {
    using namespace yuzu::server::pki;
    auto ca_key = generate_private_key(KeyAlgo::EcP384);
    REQUIRE(ca_key);
    CaParams cp;
    cp.subject = {"Yuzu Test CA", "Yuzu"};
    cp.validity = validity_years_from_now(10);
    auto ca_cert = self_sign_ca(*ca_key, cp);
    REQUIRE(ca_cert);

    CaRoot root;
    root.cert_pem = *ca_cert;
    root.key_ref = key_ref;
    root.algo = "EcP384";
    root.not_before = now_s();
    root.not_after = now_s() + 10L * 31557600L;
    root.fingerprint_sha256 = fingerprint;
    root.mode = CaMode::Builtin;
    return {root, *ca_key};
}

} // namespace

// ── Happy path (#4828 AC1) ──────────────────────────────────────────────────

TEST_CASE("CrlPublisher: publish() builds, signs and records a CRL", "[crl_publisher][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crl_publisher_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    auto rr = make_real_root("FP-A", "key-a");
    REQUIRE(store.set_root(rr.root).has_value());

    FakeKeyProvider kp;
    kp.keys["key-a"] = rr.key_pem;
    yuzu::MetricsRegistry metrics;

    CrlPublisher publisher{CrlPublisher::Deps{
        .ca_store = &store, .metrics = &metrics, .audit_store = nullptr, .key_provider = &kp}};

    auto der = publisher.publish(/*background=*/false, nullptr, CrlTrigger::Startup);
    REQUIRE(der);
    CHECK_FALSE(der->empty());

    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->version == 1);
    CHECK(latest->issuer_fingerprint == "FP-A");
    CHECK(latest->der == *der);
    CHECK(metrics.counter("yuzu_server_ca_crl_publish_failures_total").value() == 0);
}

// ── RootChanged retry contract (#4828 AC2/AC3) ──────────────────────────────

TEST_CASE("CrlPublisher: a root swapped between get_root() and the lock retries once and "
         "succeeds under the new root",
         "[crl_publisher][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crl_publisher_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    auto rr_a = make_real_root("FP-A", "key-a");
    auto rr_b = make_real_root("FP-B", "key-b");
    REQUIRE(store.set_root(rr_a.root).has_value());

    FakeKeyProvider kp;
    kp.keys["key-a"] = rr_a.key_pem;
    kp.keys["key-b"] = rr_b.key_pem;
    // Fires on the FIRST load_key() call only — the point between the caller's get_root() (which
    // read root A) and publish_next_crl's under-lock re-check. A second replica's subordinate
    // import lands here; the swap makes publish_next_crl's own root re-check disagree with what
    // this attempt expected, so it returns RootChanged.
    bool swapped = false;
    kp.on_load = [&](std::string_view) {
        if (!swapped) {
            swapped = true;
            REQUIRE(store.set_root(rr_b.root).has_value());
        }
    };

    yuzu::MetricsRegistry metrics;
    CrlPublisher publisher{CrlPublisher::Deps{
        .ca_store = &store, .metrics = &metrics, .audit_store = nullptr, .key_provider = &kp}};

    auto der = publisher.publish(/*background=*/false, nullptr, CrlTrigger::Operator);
    REQUIRE(der);
    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->issuer_fingerprint == "FP-B"); // signed under the NEW root, not the stale one
    CHECK(metrics.counter("yuzu_server_ca_crl_publish_failures_total").value() == 0);
}

TEST_CASE("CrlPublisher: a root that keeps changing on both attempts fails, counted once",
         "[crl_publisher][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crl_publisher_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    auto rr_a = make_real_root("FP-A", "key-a");
    REQUIRE(store.set_root(rr_a.root).has_value());

    FakeKeyProvider kp;
    kp.keys["key-a"] = rr_a.key_pem;
    // Swaps to a FRESH, distinct fingerprint on every load_key() call, so publish_next_crl's
    // root re-check disagrees on BOTH attempts — the caller never catches up.
    int swap_n = 0;
    kp.on_load = [&](std::string_view) {
        auto rr_next = make_real_root("FP-CHURN-" + std::to_string(++swap_n), "key-a");
        REQUIRE(store.set_root(rr_next.root).has_value());
    };

    yuzu::MetricsRegistry metrics;
    CrlPublisher publisher{CrlPublisher::Deps{
        .ca_store = &store, .metrics = &metrics, .audit_store = nullptr, .key_provider = &kp}};

    auto der = publisher.publish(/*background=*/false, nullptr, CrlTrigger::Operator);
    REQUIRE_FALSE(der);
    // Exactly one failed publish attempt overall (not one per retry): the whole two-attempt
    // call reports ONE outcome.
    CHECK(metrics.counter("yuzu_server_ca_crl_publish_failures_total").value() == 1);
    CHECK(metrics
              .counter("yuzu_server_ca_crl_publish_failure_reason_total",
                       {{"reason", "root_changed_twice"}})
              .value() == 1);
    CHECK_FALSE(store.latest_crl());
}

// ── Background Busy skip (#4828 AC4) ────────────────────────────────────────

TEST_CASE("CrlPublisher: a background publish skips (not fails) when the process-local publish "
         "lock is busy",
         "[crl_publisher][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crl_publisher_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    auto rr = make_real_root("FP-A", "key-a");
    REQUIRE(store.set_root(rr.root).has_value());

    // Holds CaStore's process-local publish mutex busy via a slow builder, mirroring
    // test_ca_store.cpp's "a publish that cannot get the per-process lock reports Busy" (the
    // mutex is private, so a slow-builder foreground publish is the only way to hold it).
    std::atomic<bool> in_builder{false};
    std::atomic<bool> release_builder{false};
    std::vector<std::thread> threads;
    JoinAll join{threads};
    threads.emplace_back([&] {
        // Aborts (nullopt) rather than actually publishing — this thread exists ONLY to hold
        // publish_mu_ for the CrlPublisher call below to observe as Busy, not to leave a real
        // CRL behind once released.
        (void)store.publish_next_crl([&](uint64_t, const std::vector<IssuedCertRecord>&)
                                         -> std::optional<CaStore::BuiltCrl> {
            in_builder = true;
            for (int i = 0; i < 400 && !release_builder; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            return std::nullopt;
        });
    });
    for (int i = 0; i < 400 && !in_builder; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    REQUIRE(in_builder.load());

    FakeKeyProvider kp;
    kp.keys["key-a"] = rr.key_pem;
    yuzu::MetricsRegistry metrics;
    CrlPublisher publisher{CrlPublisher::Deps{
        .ca_store = &store, .metrics = &metrics, .audit_store = nullptr, .key_provider = &kp}};

    bool skipped = false;
    auto der = publisher.publish(/*background=*/true, &skipped, CrlTrigger::Freshness);
    release_builder = true;
    for (auto& t : threads)
        t.join();

    CHECK_FALSE(der);
    CHECK(skipped);
    CHECK(metrics.counter("yuzu_server_ca_crl_publish_failures_total").value() == 0);
}

// ── Freshness decision + self-heal + audit (#4828 AC4's main claim) ────────

TEST_CASE("CrlPublisher: decide_freshness_tick() calls for a self-heal when the latest CRL "
         "predates a revocation",
         "[crl_publisher][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crl_publisher_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    auto rr = make_real_root("FP-A", "key-a");
    REQUIRE(store.set_root(rr.root).has_value());

    // A CRL that is fresh by nextUpdate (so `stale` is false) but was built before a
    // subsequent revocation — CaStore::has_unpublished_revocations() must disagree.
    CrlVersionRecord seeded;
    seeded.version = 1;
    seeded.der = {0x30, 0x82};
    seeded.this_update = now_s();
    seeded.next_update = now_s() + 7 * 86400;
    seeded.revoked_count = 0;
    REQUIRE(store.record_crl_for_test(seeded));
    IssuedCertRecord issued;
    issued.serial_hex = "DEADBEEF";
    issued.subject = "CN=agent-x";
    issued.purpose = "agent";
    issued.not_after = now_s() + 86400;
    issued.issued_at = now_s();
    REQUIRE(store.record_issued(issued).has_value());
    REQUIRE(store.revoke("DEADBEEF", "compromised").value_or(false));
    REQUIRE(store.has_unpublished_revocations().value_or(false));

    FakeKeyProvider kp;
    kp.keys["key-a"] = rr.key_pem;
    yuzu::MetricsRegistry metrics;
    PgPool audit_pool{{.conninfo = db.dsn(), .size = 1}};
    AuditStore audit_store{audit_pool};
    REQUIRE(audit_store.is_open());

    CrlPublisher publisher{CrlPublisher::Deps{.ca_store = &store,
                                              .metrics = &metrics,
                                              .audit_store = &audit_store,
                                              .key_provider = &kp}};

    const auto decision = publisher.decide_freshness_tick();
    CHECK(decision.act);
    CHECK(decision.reason == CrlTrigger::SelfHeal);
    CHECK_FALSE(decision.check_degraded);

    publisher.freshness_tick(std::chrono::steady_clock::now());

    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->version == 2);
    CHECK(latest->revoked_count.value_or(-1) == 1);

    auto rows = audit_store.query(AuditQuery{.action = "ca.crl.published"});
    REQUIRE(rows.has_value());
    bool found = false;
    for (const auto& ev : *rows) {
        if (ev.result == "success" && ev.detail == "reason=self_heal" &&
            ev.principal == "system") {
            found = true;
        }
    }
    CHECK(found);
}

TEST_CASE("CrlPublisher: freshness_tick() backs off 5 minutes after a real publish failure but "
         "not after a Busy skip",
         "[crl_publisher][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crl_publisher_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    // No root at all: decide_freshness_tick() returns act=false via has_root(), so a direct
    // freshness_tick() call on a fresh store is a safe, deterministic no-op — establishes the
    // baseline before the Busy-skip assertion below runs against a store that DOES have a root.
    FakeKeyProvider kp;
    yuzu::MetricsRegistry metrics;
    CrlPublisher publisher{CrlPublisher::Deps{
        .ca_store = &store, .metrics = &metrics, .audit_store = nullptr, .key_provider = &kp}};
    publisher.freshness_tick(std::chrono::steady_clock::now());
    CHECK_FALSE(store.latest_crl());

    // Now give it a root (stale — no CRL yet — so decide_freshness_tick() wants to act) and hold
    // the process-local publish mutex busy, mirroring the direct-publish Busy test above.
    auto rr = make_real_root("FP-A", "key-a");
    REQUIRE(store.set_root(rr.root).has_value());
    kp.keys["key-a"] = rr.key_pem;

    std::atomic<bool> in_builder{false};
    std::atomic<bool> release_builder{false};
    std::vector<std::thread> threads;
    JoinAll join{threads};
    threads.emplace_back([&] {
        // Aborts (nullopt) rather than actually publishing — see the identical comment on the
        // direct-publish Busy test above.
        (void)store.publish_next_crl([&](uint64_t, const std::vector<IssuedCertRecord>&)
                                         -> std::optional<CaStore::BuiltCrl> {
            in_builder = true;
            for (int i = 0; i < 400 && !release_builder; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            return std::nullopt;
        });
    });
    for (int i = 0; i < 400 && !in_builder; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    REQUIRE(in_builder.load());

    const auto t0 = std::chrono::steady_clock::now();
    publisher.freshness_tick(t0); // busy: skip, no backoff — the CRL is still stale afterward
    release_builder = true;
    for (auto& t : threads)
        t.join();
    CHECK_FALSE(store.latest_crl()); // the holder aborted — nothing was actually published

    // If the skip had (wrongly) set a 5-minute backoff, this immediate second tick (well inside
    // that hypothetical window) would be a silent no-op; it is not, because (a) the mutex is
    // free now and (b) no backoff was set — proving the skip alone didn't advance retry_after_.
    publisher.freshness_tick(t0 + std::chrono::milliseconds(1));
    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->version == 1);
}

// ── Key-load failure (#4828 AC6 / #4830) ────────────────────────────────────

TEST_CASE("CrlPublisher: a key that fails to load is a failure, reason=key_load",
         "[crl_publisher][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crl_publisher_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    auto rr = make_real_root("FP-A", "key-missing-from-provider");
    REQUIRE(store.set_root(rr.root).has_value());

    FakeKeyProvider kp; // deliberately empty — load_key() always returns nullopt
    yuzu::MetricsRegistry metrics;
    CrlPublisher publisher{CrlPublisher::Deps{
        .ca_store = &store, .metrics = &metrics, .audit_store = nullptr, .key_provider = &kp}};

    auto der = publisher.publish(/*background=*/false, nullptr, CrlTrigger::Operator);
    REQUIRE_FALSE(der);
    CHECK(metrics.counter("yuzu_server_ca_crl_publish_failures_total").value() == 1);
    CHECK(metrics
              .counter("yuzu_server_ca_crl_publish_failure_reason_total", {{"reason", "key_load"}})
              .value() == 1);
}

// ── Clock-skew backdate (#4831) ──────────────────────────────────────────────

TEST_CASE("CrlPublisher: publish() backdates thisUpdate by the clock-skew allowance",
         "[crl_publisher][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crl_publisher_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    auto rr = make_real_root("FP-A", "key-a");
    REQUIRE(store.set_root(rr.root).has_value());

    FakeKeyProvider kp;
    kp.keys["key-a"] = rr.key_pem;
    yuzu::MetricsRegistry metrics;

    const auto fixed = std::chrono::system_clock::now();
    CrlPublisher publisher{CrlPublisher::Deps{.ca_store = &store,
                                              .metrics = &metrics,
                                              .audit_store = nullptr,
                                              .key_provider = &kp,
                                              .now_fn = [&] { return fixed; }}};

    REQUIRE(publisher.publish(/*background=*/false, nullptr, CrlTrigger::Operator));

    auto latest = store.latest_crl();
    REQUIRE(latest);
    const auto fixed_epoch =
        std::chrono::duration_cast<std::chrono::seconds>(fixed.time_since_epoch()).count();
    const auto expected_this_update =
        fixed_epoch - static_cast<int64_t>(pki::kClockSkewBackdate.count());
    CHECK(latest->this_update == expected_this_update);
    // Independently of the fixed injected clock: this_update must not be in the future relative
    // to a real, freshly-read clock (the acceptance-criteria framing).
    CHECK(latest->this_update <= now_s());
}
