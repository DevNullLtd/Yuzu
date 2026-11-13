/**
 * test_session_account_active.cpp -- the durable session cache is coherent across
 * a cache invalidation, and a session whose account is not active is rejected
 * (#7223).
 *
 * "Replica" below means a second AuthManager over the same SessionStore (one
 * process, one database); it is the stand-in for a second core replica. Behind
 * YUZU_TEST_ENABLE_PG (server suite only): skipped when the DSN is unset, and a
 * skipped PG case is not a pass.
 *
 * Account gate cases: a session built from a durable row is served only while its
 * LOCAL account is active (`AuthDB::user_exists`, active-only). A deactivation whose
 * session wipe failed (`SessionWipeFaultAfterDeactivation`, repaired afterwards so the
 * durable row survives and only the gate can refuse it) is the fixture throughout.
 *
 * Cache epoch cases: a validation that straddles the generation
 * poll's cache clear must not put its session back into the cache. The tests
 * hold ONE validation open at the pre-cache hook
 * (`AuthManager::set_validate_pre_cache_hook_for_test`), run the invalidation on
 * the other thread, and then let the held validation finish. No sleeps: the poll
 * is forced with `expire_session_generation_poll_for_test`.
 */

#include <yuzu/server/auth.hpp>

#include <yuzu/server/server.hpp> // Config (for the route-level harness)

#include "auth_routes.hpp"
#include "oidc_principal.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"
#include "session_store.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "test_auth_db_rbac_pg_template.hpp"
#include "test_principal_lock_gate.hpp" // SessionWipeFaultAfterDeactivation, SqlFault
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::SessionStore;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::RemoveUserOutcome;
using yuzu::server::auth::Role;
using yuzu::server::pg::PgPool;

namespace {

// Setup constructs the store (runs the migration), then closes all conns.
yuzu::test::PgTestTemplate sessacct_tpl{"sessacct", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    SessionStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("sessacct template: store failed to migrate");
}};

// A store-backed AuthManager with no AuthDB: just the session store, which is
// all the cache-epoch cases need.
std::unique_ptr<AuthManager> make_mgr(SessionStore& store) {
    auto mgr = std::make_unique<AuthManager>();
    mgr->set_session_store(&store);
    return mgr;
}

// Holds exactly one validation (the one whose thread sets `in_held_thread`) open at
// the pre-cache hook until released. Every other validation, including the test's
// own, passes straight through.
class HeldValidation {
public:
    // Installs the hook on `mgr`. The holder must outlive every validation on `mgr`.
    void install(AuthManager& mgr) {
        mgr.set_validate_pre_cache_hook_for_test([this] {
            if (!in_held_thread())
                return;
            std::unique_lock lk(mu_);
            reached_ = true;
            cv_.notify_all();
            cv_.wait(lk, [this] { return released_; });
        });
    }

    // Runs `fn` on a new thread that is the held one; returns once it is parked at the
    // hook. `fn`'s result is read with join().
    void start(std::function<std::optional<yuzu::server::auth::Session>()> fn) {
        worker_ = std::thread([this, fn = std::move(fn)] {
            in_held_thread() = true;
            result_ = fn();
        });
        std::unique_lock lk(mu_);
        cv_.wait(lk, [this] { return reached_; });
    }

    // Lets the held validation finish and returns its result.
    std::optional<yuzu::server::auth::Session> release_and_join() {
        {
            std::lock_guard lk(mu_);
            released_ = true;
        }
        cv_.notify_all();
        worker_.join();
        return result_;
    }

    ~HeldValidation() {
        // A failed REQUIRE must not leave the worker parked, or a joinable thread would
        // terminate the process.
        if (worker_.joinable())
            (void)release_and_join();
    }

private:
    static bool& in_held_thread() {
        thread_local bool v = false;
        return v;
    }

    std::mutex mu_;
    std::condition_variable cv_;
    bool reached_ = false;
    bool released_ = false;
    std::thread worker_;
    std::optional<yuzu::server::auth::Session> result_;
};

// Forces the next validate on `mgr` to poll the durable generation, then validates
// `token` once (the validate runs the poll and, if the generation moved, the clear).
std::optional<yuzu::server::auth::Session> poll_and_validate(AuthManager& mgr,
                                                             const std::string& token) {
    mgr.expire_session_generation_poll_for_test();
    return mgr.validate_session(token);
}

// Fixture SQL: delete a session's durable row WITHOUT the store's generation bump, so a
// later validate can tell a cached entry (served) from an uncached one (cold read, absent).
void delete_durable_row_silently(PgPool& pool, const std::string& token) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    yuzu::server::pg::exec_params(
        lease.get(), "DELETE FROM session_store.sessions WHERE token_hash = $1",
        std::vector<std::string>{AuthManager::sha256_hex(token)});
}

} // namespace

TEST_CASE("session cache epoch: a sign-out on another replica is not undone by a warm validation "
          "in flight (T-R4)",
          "[auth][session_store][account_active][cache_epoch][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sessacct_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 6}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    auto a = make_mgr(store);
    auto b = make_mgr(store);

    const auto token = a->create_local_session_for_test("alice", Role::admin, true);
    REQUIRE_FALSE(token.empty());
    REQUIRE(b->validate_session(token).has_value()); // B's cache is now warm

    HeldValidation held;
    held.install(*b);
    held.start([&] { return b->validate_session(token); }); // warm hit, parked before the insert

    REQUIRE(a->invalidate_session(token)); // the sign-out: durable delete + generation bump
    // B polls, sees the new generation and clears its cache; the held validation began
    // before that clear.
    CHECK_FALSE(poll_and_validate(*b, token).has_value());

    // The held validation was concurrent with the invalidation, so it is served ...
    const auto late = held.release_and_join();
    CHECK(late.has_value());

    // ... but must not have put the session back: it stays refused across further polls
    // that see an UNCHANGED generation (nothing else clears the cache).
    for (int i = 0; i < 3; ++i)
        CHECK_FALSE(poll_and_validate(*b, token).has_value());
    CHECK_FALSE(b->validate_session(token).has_value());
}

TEST_CASE("session cache epoch: a sign-out and the poll on the SAME replica are not undone by a "
          "warm validation in flight (T-R1, sign-out form)",
          "[auth][session_store][account_active][cache_epoch][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sessacct_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 6}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    auto b = make_mgr(store);

    const auto token = b->create_local_session_for_test("alice", Role::admin, true);
    REQUIRE_FALSE(token.empty());
    REQUIRE(b->validate_session(token).has_value()); // warm

    HeldValidation held;
    held.install(*b);
    held.start([&] { return b->validate_session(token); });

    // The replica does not write its own cached generation on a local mutation: it sees
    // its own bump through the next poll, which is the clear under test.
    REQUIRE(b->invalidate_session(token));
    CHECK_FALSE(poll_and_validate(*b, token).has_value());

    CHECK(held.release_and_join().has_value());
    for (int i = 0; i < 3; ++i)
        CHECK_FALSE(poll_and_validate(*b, token).has_value());
    CHECK_FALSE(b->validate_session(token).has_value());
}

TEST_CASE("session cache epoch: a cold validation in flight does not re-cache a signed-out "
          "session (T-R2, sign-out form)",
          "[auth][session_store][account_active][cache_epoch][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sessacct_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 6}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    auto a = make_mgr(store);
    auto b = make_mgr(store);

    const auto token = a->create_local_session_for_test("alice", Role::admin, true);
    REQUIRE_FALSE(token.empty());
    // Anchor B's generation view on something other than the token so its cache is cold for
    // this session (the validation below builds the candidate from the store row).
    const auto other = a->create_local_session_for_test("bob", Role::user, false);
    REQUIRE(b->validate_session(other).has_value());

    HeldValidation held;
    held.install(*b);
    held.start([&] { return b->validate_session(token); }); // cold: candidate from the row

    REQUIRE(a->invalidate_session(token));
    CHECK_FALSE(poll_and_validate(*b, token).has_value());

    CHECK(held.release_and_join().has_value());
    for (int i = 0; i < 3; ++i)
        CHECK_FALSE(poll_and_validate(*b, token).has_value());
    CHECK_FALSE(b->validate_session(token).has_value());
}

TEST_CASE("session cache epoch: a mismatch returns the session to that caller and leaves the "
          "cache without the key (T-E1)",
          "[auth][session_store][account_active][cache_epoch][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sessacct_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 6}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    auto a = make_mgr(store);
    auto b = make_mgr(store);

    const auto token = a->create_local_session_for_test("alice", Role::admin, true);
    REQUIRE_FALSE(token.empty());
    REQUIRE(b->validate_session(token).has_value()); // warm

    HeldValidation held;
    held.install(*b);
    held.start([&] { return b->validate_session(token); });

    // Any generation change clears B's whole cache (an unrelated sign-in is enough).
    const auto other = a->create_local_session_for_test("bob", Role::user, false);
    REQUIRE_FALSE(other.empty());
    REQUIRE(poll_and_validate(*b, other).has_value()); // the clear ran here

    const auto served = held.release_and_join();
    REQUIRE(served.has_value()); // the one caller is still served ...
    CHECK(served->username == "alice");

    // ... and the cache holds no entry for it: with the durable row removed behind the
    // cache's back (no generation bump), a cached entry would still be served and an
    // uncached one reads the row, finds it absent and refuses.
    delete_durable_row_silently(pool, token);
    CHECK_FALSE(b->validate_session(token).has_value());
}

// ═════════════════════════════════════════════════════════════════════════════════════════════
// Account gate (#7223)
// ═════════════════════════════════════════════════════════════════════════════════════════════

namespace {

constexpr const char* kInactiveCounter = "yuzu_auth_session_account_inactive_total";

// AuthDB + RbacStore + SessionStore on ONE pool (the production composition) and any number of
// AuthManagers over them: each extra manager is another replica with its own validate cache.
struct AcctFx {
    yuzu::test::AuthDbPg db{0, false, &yuzu::test::auth_db_rbac_pg_template};
    yuzu::server::RbacStore rbac;
    SessionStore sessions;
    yuzu::MetricsRegistry metrics;
    std::vector<std::unique_ptr<AuthManager>> mgrs;

    AcctFx() : rbac(db.pool()), sessions(db.pool()) {
        REQUIRE(rbac.is_open());
        REQUIRE(sessions.is_open());
    }
    ~AcctFx() {
        for (auto& m : mgrs) {
            m->set_metrics_registry(nullptr);
            m->set_rbac_store(nullptr);
            m->set_session_store(nullptr);
            m->set_auth_db(nullptr);
        }
    }
    AcctFx(const AcctFx&) = delete;
    AcctFx& operator=(const AcctFx&) = delete;

    // A new replica. `with_auth_db = false` is the store-wired, AuthDB-less test wiring.
    AuthManager& add(bool with_auth_db = true) {
        auto m = std::make_unique<AuthManager>();
        if (with_auth_db)
            m->set_auth_db(db.get());
        m->set_session_store(&sessions);
        m->set_metrics_registry(&metrics);
        if (with_auth_db)
            m->set_rbac_store(&rbac);
        mgrs.push_back(std::move(m));
        return *mgrs.back();
    }

    void seed(const std::string& name, Role role) {
        REQUIRE(db->upsert_user(name, "hash", "salt", role).has_value());
    }
    // One administrator so deactivating any other account is never a last-admin refusal.
    void seed_world(const std::string& user) {
        seed("acct_admin", Role::admin);
        seed(user, Role::user);
    }

    int durable_sessions_of(const std::string& user) {
        auto lease = db.pool().acquire();
        REQUIRE(lease);
        auto r = yuzu::server::pg::exec_params(
            lease.get(), "SELECT 1 FROM session_store.sessions WHERE username = $1",
            std::vector<std::string>{user});
        return PQntuples(r.get());
    }
    void exec_sql(const std::string& sql) {
        auto lease = db.pool().acquire();
        REQUIRE(lease);
        yuzu::server::pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    }
    double counter(const char* name) { return metrics.counter(name).value(); }
    double degrade(const char* op) {
        return metrics.counter("yuzu_auth_session_store_degrade_total", {{"op", op}}).value();
    }

    // Deactivate `user` through `by` while the durable session wipe is made to fail, then repair
    // the fault: the account is inactive, its durable session row SURVIVES, and every replica's
    // cache is still unaware. Only the generation bump and the account gate can refuse it now.
    void deactivate_leaving_session(AuthManager& by, const std::string& user) {
        yuzu::test::SessionWipeFaultAfterDeactivation fault{db.pool()};
        fault.arm();
        REQUIRE(by.remove_user_checked(user) == RemoveUserOutcome::RemovedSessionWipeFailed);
        fault.repair();
        REQUIRE(durable_sessions_of(user) == 1);
    }
};

// The same 3 unchanged-generation polls the cache-epoch cases use: nothing else clears the cache,
// so a session that was wrongly (re)cached would be served here.
void check_stays_refused(AuthManager& m, const std::string& token) {
    for (int i = 0; i < 3; ++i)
        CHECK_FALSE(poll_and_validate(m, token).has_value());
    CHECK_FALSE(m.validate_session(token).has_value());
}

} // namespace

TEST_CASE("account gate: a warm replica refuses the session of a deactivated account after a "
          "faulted wipe (T1)",
          "[auth][session_store][account_active][pg]") {
    AcctFx f;
    auto& a = f.add();
    auto& b = f.add();
    f.seed_world("alice");
    const auto token = a.create_local_session_for_test("alice", Role::user, false);
    REQUIRE_FALSE(token.empty());
    REQUIRE(a.validate_session(token).has_value());
    REQUIRE(b.validate_session(token).has_value()); // warm on both replicas

    f.deactivate_leaving_session(a, "alice");

    // B has not polled yet and would still serve its warm entry; after ONE poll (the generation
    // moved with the deactivation) it is refused, and stays refused.
    CHECK_FALSE(poll_and_validate(b, token).has_value());
    check_stays_refused(b, token);
    check_stays_refused(a, token);
    CHECK(f.counter(kInactiveCounter) >= 1.0);
}

TEST_CASE("account gate: a cold replica refuses the session of a deactivated account (T2)",
          "[auth][session_store][account_active][pg]") {
    AcctFx f;
    auto& a = f.add();
    f.seed_world("alice");
    const auto token = a.create_local_session_for_test("alice", Role::user, false);
    REQUIRE_FALSE(token.empty());
    f.deactivate_leaving_session(a, "alice");

    auto& c = f.add(); // never saw the session: the cache is cold, the row is read from the store
    const double before = f.counter(kInactiveCounter);
    CHECK_FALSE(c.validate_session(token).has_value());
    CHECK(f.counter(kInactiveCounter) == before + 1.0);
    CHECK(f.durable_sessions_of("alice") == 1); // refused, not deleted: the gate did it
    check_stays_refused(c, token);
}

TEST_CASE("account gate: an unreadable account store refuses, counts, and recovers without an "
          "unrelated mutation (T4 + T-R5)",
          "[auth][session_store][account_active][pg]") {
    AcctFx f;
    auto& a = f.add();
    f.seed_world("alice");
    const auto token = a.create_local_session_for_test("alice", Role::user, false);
    REQUIRE_FALSE(token.empty());
    auto& b = f.add(); // cold for this token

    const double inactive0 = f.counter(kInactiveCounter);
    const double degrade0 = f.degrade("account_state");
    {
        yuzu::test::SqlFault users_gone{f.db.pool(), "ALTER TABLE auth.users RENAME TO users_gone",
                                        "ALTER TABLE auth.users_gone RENAME TO users"};
        users_gone.arm();
        CHECK_FALSE(b.validate_session(token).has_value());
        CHECK(f.degrade("account_state") == degrade0 + 1.0);
        CHECK(f.counter(kInactiveCounter) == inactive0); // unreadable is not "inactive"
        CHECK(f.durable_sessions_of("alice") == 1);
        users_gone.repair();
    }
    // Nothing was cached by the refusal and the generation did not move, so the same cookie
    // validates again as soon as the store is readable: no unrelated mutation is needed.
    CHECK(b.validate_session(token).has_value());
    CHECK(f.counter(kInactiveCounter) == inactive0);
}

TEST_CASE("account gate: an active account is unaffected warm, cold and across a generation "
          "change (T5)",
          "[auth][session_store][account_active][pg]") {
    AcctFx f;
    auto& a = f.add();
    auto& b = f.add();
    f.seed_world("alice");
    for (auto& m : f.mgrs)
        m->set_session_inactivity(std::chrono::seconds(600));
    const auto token = a.create_local_session_for_test("alice", Role::user, false);
    REQUIRE_FALSE(token.empty());

    CHECK(a.validate_session(token).has_value()); // warm on the minting replica
    CHECK(b.validate_session(token).has_value()); // cold read, gated, active
    auto& c = f.add();
    CHECK(c.validate_session(token).has_value());

    // Any generation change (another sign-in) clears every cache; the next read is cold again.
    REQUIRE_FALSE(a.create_local_session_for_test("alice", Role::user, false).empty());
    for (auto* m : {&a, &b, &c})
        CHECK(poll_and_validate(*m, token).has_value());

    // The MFA proof and the idle window are untouched by the gate.
    REQUIRE(a.mark_session_mfa_verified(token));
    auto& d = f.add();
    const auto seen = d.validate_session(token);
    REQUIRE(seen.has_value());
    CHECK(seen->steady_mfa_verified.time_since_epoch().count() != 0);

    CHECK(f.counter(kInactiveCounter) == 0.0);
    CHECK(f.degrade("account_state") == 0.0);
}

TEST_CASE("account gate: a warm validation in flight across a deactivation is not re-cached "
          "(T-R1, deactivation form)",
          "[auth][session_store][account_active][cache_epoch][pg]") {
    AcctFx f;
    auto& a = f.add();
    auto& b = f.add();
    f.seed_world("alice");
    const auto token = a.create_local_session_for_test("alice", Role::user, false);
    REQUIRE_FALSE(token.empty());
    REQUIRE(b.validate_session(token).has_value()); // warm

    HeldValidation held;
    held.install(b);
    held.start([&] { return b.validate_session(token); });

    f.deactivate_leaving_session(a, "alice");
    CHECK_FALSE(poll_and_validate(b, token).has_value()); // the poll clears B's cache

    CHECK(held.release_and_join().has_value()); // concurrent with the invalidation: served once
    check_stays_refused(b, token);
}

TEST_CASE("account gate: a cold validation in flight across a deactivation is not re-cached "
          "(T-R2, deactivation form)",
          "[auth][session_store][account_active][cache_epoch][pg]") {
    AcctFx f;
    auto& a = f.add();
    auto& b = f.add();
    f.seed_world("alice");
    const auto token = a.create_local_session_for_test("alice", Role::user, false);
    REQUIRE_FALSE(token.empty());
    // Anchor B's generation view on something else so its cache is cold for this session.
    const auto other = a.create_local_session_for_test("acct_admin", Role::admin, false);
    REQUIRE(b.validate_session(other).has_value());

    HeldValidation held;
    held.install(b);
    // Cold: the candidate is built from the row and passes the gate (the account is active
    // now), then parks before the cache insert.
    held.start([&] { return b.validate_session(token); });

    f.deactivate_leaving_session(a, "alice");
    CHECK_FALSE(poll_and_validate(b, token).has_value());

    CHECK(held.release_and_join().has_value());
    check_stays_refused(b, token);
}

TEST_CASE("account gate: an idle re-read that crosses a deactivation is refused on the next "
          "request (T-R3)",
          "[auth][session_store][account_active][cache_epoch][pg]") {
    AcctFx f;
    auto& a = f.add();
    auto& b = f.add();
    f.seed_world("alice");
    b.set_session_inactivity(std::chrono::seconds(600));
    const auto token = a.create_local_session_for_test("alice", Role::user, false);
    REQUIRE_FALSE(token.empty());
    REQUIRE(b.validate_session(token).has_value()); // warm

    // The cached entry looks idle, so the next validation re-reads the durable row (a second,
    // store-derived session that is not passed through the cold-path gate), then parks.
    b.idle_session_for_test(token, std::chrono::minutes(11));
    HeldValidation held;
    held.install(b);
    held.start([&] { return b.validate_session(token); });

    f.deactivate_leaving_session(a, "alice");
    CHECK_FALSE(poll_and_validate(b, token).has_value());

    CHECK(held.release_and_join().has_value());
    check_stays_refused(b, token);
}

TEST_CASE("account gate: a deleted account row is refused on a COLD read (T8); a warm cache is "
          "outside the guarantee for direct SQL",
          "[auth][session_store][account_active][pg]") {
    // Direct SQL against auth.users bumps no generation, so a replica whose cache is warm keeps
    // serving the session until the next generation change. That is a documented limit, not
    // asserted here; the cold read is what the gate guarantees.
    AcctFx f;
    auto& a = f.add();
    f.seed_world("alice");
    const auto token = a.create_local_session_for_test("alice", Role::user, false);
    REQUIRE_FALSE(token.empty());
    f.exec_sql("DELETE FROM auth.users WHERE username = 'alice'");

    auto& c = f.add();
    CHECK_FALSE(c.validate_session(token).has_value());
    CHECK(f.counter(kInactiveCounter) == 1.0);
}

TEST_CASE("account gate: federated sessions are not gated on an account row (T9)",
          "[auth][session_store][account_active][pg]") {
    AcctFx f;
    auto& a = f.add();
    const std::string iss = "https://idp.example";

    // OIDC with no auth.users row for the stable principal: validates cold on another replica.
    const auto oidc = a.create_oidc_session("Fed One", "one@example.com", "sub-one", iss);
    REQUIRE_FALSE(oidc.empty());
    auto& b = f.add();
    CHECK(b.validate_session(oidc).has_value());

    // OIDC with a provisioned row.
    const auto oidc2 = a.create_oidc_session("Fed Two", "two@example.com", "sub-two", iss);
    REQUIRE_FALSE(oidc2.empty());
    a.provision_sso_identity(yuzu::server::oidc::oidc_principal_id(iss, "sub-two"), iss, "sub-two",
                             "Fed Two");
    auto& c = f.add();
    CHECK(c.validate_session(oidc2).has_value());

    // SAML never provisions a row.
    const auto saml = a.create_saml_session("saml.user@example.com", "https://sp.example");
    REQUIRE_FALSE(saml.empty());
    auto& d = f.add();
    CHECK(d.validate_session(saml).has_value());

    CHECK(f.counter(kInactiveCounter) == 0.0);
}

TEST_CASE("account gate: a store-wired process with no AuthDB still validates a local session "
          "cold (T10)",
          "[auth][session_store][account_active][pg]") {
    // Test wiring only: production wires both stores. The skip is pinned here so it cannot
    // silently become a refusal (or silently widen).
    AcctFx f;
    auto& a = f.add(/*with_auth_db=*/false);
    auto& b = f.add(/*with_auth_db=*/false);
    const auto token = a.create_local_session_for_test("nobody-in-auth-users", Role::user, false);
    REQUIRE_FALSE(token.empty());
    CHECK(b.validate_session(token).has_value());
    CHECK(f.counter(kInactiveCounter) == 0.0);
}

TEST_CASE("account gate: the old cookie answers 401 through the auth routes (T14)",
          "[auth][session_store][account_active][pg]") {
    AcctFx f;
    auto& a = f.add();
    auto& b = f.add();
    f.seed_world("alice");
    yuzu::server::Config cfg{};
    cfg.https_enabled = false;
    std::shared_mutex oidc_mu;
    std::unique_ptr<yuzu::server::oidc::OidcProvider> oidc_provider;
    // `routes` before `sink`: the handlers the sink captures hold `routes`' `this`.
    yuzu::server::AuthRoutes routes(cfg, b, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                                    oidc_mu, oidc_provider);
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink);

    const auto token = a.create_local_session_for_test("alice", Role::user, false);
    REQUIRE_FALSE(token.empty());
    const std::unordered_map<std::string, std::string> hdrs{{"Cookie", "yuzu_session=" + token}};
    // /api/v1/elevate/revoke resolves the cookie session first and answers 401 without one.
    auto ok = sink.dispatch("POST", "/api/v1/elevate/revoke", "", "application/json", hdrs);
    REQUIRE(ok);
    CHECK(ok->status == 200); // warms B's cache too

    f.deactivate_leaving_session(a, "alice");
    b.expire_session_generation_poll_for_test();
    auto denied = sink.dispatch("POST", "/api/v1/elevate/revoke", "", "application/json", hdrs);
    REQUIRE(denied);
    CHECK(denied->status == 401);
}

TEST_CASE("account gate: a replica that cannot read the generation distrusts its cache after the "
          "stale-serve bound and then refuses (T-R7)",
          "[auth][session_store][account_active][pg]") {
    AcctFx f;
    auto& a = f.add();
    auto& b = f.add();
    f.seed_world("alice");
    const auto token = a.create_local_session_for_test("alice", Role::user, false);
    REQUIRE_FALSE(token.empty());
    REQUIRE(b.validate_session(token).has_value()); // warm, generation view fresh

    f.deactivate_leaving_session(a, "alice"); // the bump is committed; B has not polled

    yuzu::test::SqlFault meta_gone{
        f.db.pool(), "ALTER TABLE session_store.session_meta RENAME TO session_meta_gone",
        "ALTER TABLE session_store.session_meta_gone RENAME TO session_meta"};
    meta_gone.arm();

    // Generation reads fail, session and account reads are healthy. Inside the 30 s bound the
    // warm entry is still served (the documented bound) ...
    b.expire_session_generation_poll_for_test();
    CHECK(b.validate_session(token).has_value());
    b.age_session_generation_refresh_for_test(std::chrono::seconds(20));
    b.expire_session_generation_poll_for_test();
    CHECK(b.validate_session(token).has_value());
    // ... and past it the cache is distrusted, the row is read cold, and the gate refuses.
    b.age_session_generation_refresh_for_test(std::chrono::seconds(11));
    b.expire_session_generation_poll_for_test();
    CHECK_FALSE(b.validate_session(token).has_value());
    meta_gone.repair();
}
