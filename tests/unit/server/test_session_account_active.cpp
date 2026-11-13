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
 * Cache epoch cases (this commit): a validation that straddles the generation
 * poll's cache clear must not put its session back into the cache. The tests
 * hold ONE validation open at the pre-cache hook
 * (`AuthManager::set_validate_pre_cache_hook_for_test`), run the invalidation on
 * the other thread, and then let the held validation finish. No sleeps: the poll
 * is forced with `expire_session_generation_poll_for_test`.
 */

#include <yuzu/server/auth.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "session_store.hpp"

#include "../test_helpers.hpp"

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
