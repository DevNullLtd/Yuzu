/**
 * test_auth.cpp — Unit tests for yuzu::server::auth::AuthManager
 *
 * Covers: crypto primitives, password auth, sessions, user CRUD,
 *         enrollment tokens, pending agents, config persistence.
 */

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "test_auth_db_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#if defined(__APPLE__)
#include <unistd.h> // geteuid()
#endif

namespace fs = std::filesystem;
using namespace yuzu::server::auth;
using yuzu::server::AuthDB;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Create an AuthManager configured to use a per-test config file.
///
/// Previously this used a hardcoded shared `yuzu_test_auth` directory and a
/// process-wide cleanup_guard, which meant any two tests running in the same
/// process saw each other's state via the on-disk file even though they
/// thought they had a clean AuthManager. Migrated to the canonical helper —
/// every call gets its own unique path so tests are independent.
/// (governance qe-B2; flake-class #473.)
static std::unique_ptr<AuthManager> make_temp_auth() {
    auto mgr = std::make_unique<AuthManager>();
    auto cfg = yuzu::test::unique_temp_path("yuzu-test-auth-");
    cfg += ".cfg";
    fs::create_directories(cfg.parent_path());
    fs::remove(cfg);
    mgr->load_config(cfg);
    return mgr;
}

// ── Crypto Primitives ────────────────────────────────────────────────────────

TEST_CASE("bytes_to_hex produces lowercase hex", "[auth][crypto]") {
    std::vector<uint8_t> data = {0x00, 0xFF, 0xAB, 0x12};
    auto hex = AuthManager::bytes_to_hex(data);
    REQUIRE(hex == "00ffab12");
}

TEST_CASE("hex_to_bytes roundtrip", "[auth][crypto]") {
    std::vector<uint8_t> original = {0xDE, 0xAD, 0xBE, 0xEF};
    auto hex = AuthManager::bytes_to_hex(original);
    auto roundtripped = AuthManager::hex_to_bytes(hex);
    REQUIRE(roundtripped == original);
}

TEST_CASE("hex_to_bytes with empty string", "[auth][crypto]") {
    auto result = AuthManager::hex_to_bytes("");
    REQUIRE(result.empty());
}

TEST_CASE("sha256_hex known vector", "[auth][crypto]") {
    // SHA-256 of empty string
    auto hash = AuthManager::sha256_hex("");
    REQUIRE(hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_CASE("sha256_hex known vector: hello", "[auth][crypto]") {
    auto hash = AuthManager::sha256_hex("hello");
    REQUIRE(hash == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

TEST_CASE("random_bytes returns requested size", "[auth][crypto]") {
    auto bytes = AuthManager::random_bytes(32);
    REQUIRE(bytes.size() == 32);
}

TEST_CASE("random_bytes produces unique outputs", "[auth][crypto]") {
    auto a = AuthManager::random_bytes(16);
    auto b = AuthManager::random_bytes(16);
    REQUIRE(a != b);
}

TEST_CASE("constant_time_compare: equal strings", "[auth][crypto]") {
    REQUIRE(AuthManager::constant_time_compare("abc", "abc"));
}

TEST_CASE("constant_time_compare: unequal strings", "[auth][crypto]") {
    REQUIRE_FALSE(AuthManager::constant_time_compare("abc", "def"));
}

TEST_CASE("constant_time_compare: different lengths", "[auth][crypto]") {
    REQUIRE_FALSE(AuthManager::constant_time_compare("abc", "abcd"));
}

TEST_CASE("pbkdf2_sha256 produces consistent output", "[auth][crypto]") {
    std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
    auto h1 = AuthManager::pbkdf2_sha256("password", salt, 1000);
    auto h2 = AuthManager::pbkdf2_sha256("password", salt, 1000);
    REQUIRE(h1 == h2);
    REQUIRE_FALSE(h1.empty());
}

TEST_CASE("pbkdf2_sha256 different passwords differ", "[auth][crypto]") {
    std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
    auto h1 = AuthManager::pbkdf2_sha256("password1", salt, 1000);
    auto h2 = AuthManager::pbkdf2_sha256("password2", salt, 1000);
    REQUIRE(h1 != h2);
}

// ── Role / Status Conversions ────────────────────────────────────────────────

TEST_CASE("role_to_string", "[auth][role]") {
    REQUIRE(role_to_string(Role::admin) == "admin");
    REQUIRE(role_to_string(Role::user) == "user");
}

TEST_CASE("string_to_role", "[auth][role]") {
    REQUIRE(string_to_role("admin") == Role::admin);
    REQUIRE(string_to_role("user") == Role::user);
    REQUIRE(string_to_role("unknown") == Role::user); // default
}

TEST_CASE("pending_status_to_string", "[auth][role]") {
    REQUIRE(pending_status_to_string(PendingStatus::pending) == "pending");
    REQUIRE(pending_status_to_string(PendingStatus::approved) == "approved");
    REQUIRE(pending_status_to_string(PendingStatus::denied) == "denied");
}

// ── Default Path Resolution — macOS non-root fallback ───────────────────────
//
// default_cert_dir() / default_config_path() must never resolve a root run to
// a per-user path: macOS `sudo` preserves $HOME by default, so an unqualified
// $HOME fallback would send "sudo yuzu-server" to write CA/KEK key material
// (or read/write the config file) inside an unprivileged user's home instead
// of the shared /etc/yuzu location. These tests branch on the ACTUAL euid of
// the test process (never skip) so they assert the correct behaviour whether
// CI runs as root or not — see docs/testing/unit-test-conventions.md's
// ScopedEnv precedent in test_server_ota_options.cpp.
#if defined(__APPLE__)
namespace {
// RAII save/restore of an environment variable, set OR unset for the scope's
// duration. The unset overload matters as much as the set one: a REQUIRE/SKIP
// between an inline unsetenv() and a manual restore leaks the mutated env
// across the rest of the test binary if anything in between throws (SKIP()
// does, via Catch::TestSkipException) — this guard's destructor always runs.
struct ScopedEnv {
    struct Unset {};
    std::string name;
    bool had_prev = false;
    std::string prev;
    ScopedEnv(std::string n, const std::string& v) : name(std::move(n)) {
        capture_prev();
        ::setenv(name.c_str(), v.c_str(), 1);
    }
    ScopedEnv(std::string n, Unset) : name(std::move(n)) {
        capture_prev();
        ::unsetenv(name.c_str());
    }
    ~ScopedEnv() {
        if (had_prev)
            ::setenv(name.c_str(), prev.c_str(), 1);
        else
            ::unsetenv(name.c_str());
    }

  private:
    void capture_prev() {
        if (const char* cur = std::getenv(name.c_str())) {
            had_prev = true;
            prev = cur;
        }
    }
};
} // namespace

TEST_CASE("default_cert_dir: root always resolves to /etc/yuzu/certs", "[auth][paths][macos]") {
    // This project's self-hosted macOS CI runner never runs as root
    // (deploy/macos/README.md), so this branch is SKIPPED, not passed, on
    // every real CI run today — SKIP is reported distinctly from a passing
    // REQUIRE, unlike SUCCEED, so the root path stays visibly unverified
    // rather than silently green (governance false-green floor, qe Gate 3).
    if (::geteuid() != 0) {
        SKIP("test process is not root — covered by the non-root case below");
    }
    yuzu::test::TempDir home;
    ScopedEnv env{"HOME", home.path.string()};
    REQUIRE(default_cert_dir() == fs::path{"/etc/yuzu/certs"});
}

TEST_CASE("default_cert_dir: non-root falls back to per-user Application Support",
          "[auth][paths][macos]") {
    if (::geteuid() == 0) {
        SKIP("test process is root — covered by the root case above");
    }
    yuzu::test::TempDir home;
    ScopedEnv env{"HOME", home.path.string()};
    REQUIRE(default_cert_dir() ==
            home.path / "Library/Application Support/Yuzu/certs");
}

TEST_CASE("default_cert_dir: non-root with HOME unset falls back to the fixed "
          "Application Support path",
          "[auth][paths][macos]") {
    if (::geteuid() == 0) {
        SKIP("test process is root — HOME-unset fallback is a non-root-only path");
    }
    ScopedEnv env{"HOME", ScopedEnv::Unset{}};
    REQUIRE(default_cert_dir() == fs::path{"/Library/Application Support/Yuzu/certs"});
}

TEST_CASE("default_config_path: root always resolves to /etc/yuzu/yuzu-server.cfg",
          "[auth][paths][macos]") {
    if (::geteuid() != 0) {
        SKIP("test process is not root — covered by the non-root case below");
    }
    yuzu::test::TempDir home;
    ScopedEnv env{"HOME", home.path.string()};
    REQUIRE(default_config_path() == fs::path{"/etc/yuzu/yuzu-server.cfg"});
}

TEST_CASE("default_config_path: non-root falls back to per-user Application Support",
          "[auth][paths][macos]") {
    if (::geteuid() == 0) {
        SKIP("test process is root — covered by the root case above");
    }
    yuzu::test::TempDir home;
    ScopedEnv env{"HOME", home.path.string()};
    REQUIRE(default_config_path() ==
            home.path / "Library/Application Support/Yuzu/yuzu-server.cfg");
}

TEST_CASE("default_config_path: non-root with HOME unset falls back to the fixed "
          "Application Support path",
          "[auth][paths][macos]") {
    if (::geteuid() == 0) {
        SKIP("test process is root — HOME-unset fallback is a non-root-only path");
    }
    ScopedEnv env{"HOME", ScopedEnv::Unset{}};
    REQUIRE(default_config_path() ==
            fs::path{"/Library/Application Support/Yuzu/yuzu-server.cfg"});
}
#endif // __APPLE__

// ── User Management ──────────────────────────────────────────────────────────

TEST_CASE("has_users returns false initially", "[auth][user]") {
    auto mgr = make_temp_auth();
    REQUIRE_FALSE(mgr->has_users());
}

TEST_CASE("upsert_user + list_users", "[auth][user]") {
    auto mgr = make_temp_auth();
    REQUIRE(mgr->upsert_user("alice", "password12345", Role::admin));
    REQUIRE(mgr->has_users());

    auto users = mgr->list_users();
    REQUIRE(users.size() == 1);
    REQUIRE(users[0].username == "alice");
    REQUIRE(users[0].role == Role::admin);
}

TEST_CASE("remove_user", "[auth][user]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "password1234", Role::admin);
    REQUIRE(mgr->remove_user("alice"));
    REQUIRE_FALSE(mgr->has_users());
}

TEST_CASE("remove_user returns false for nonexistent user", "[auth][user]") {
    auto mgr = make_temp_auth();
    REQUIRE_FALSE(mgr->remove_user("nonexistent"));
}

// ── remove_user: cold-cache DB truth (CC6.8, PR #2018 review response) ─────
//
// AuthManager::remove_user historically returned `users_.erase(username) > 0`
// — the in-memory cache's own erase result — even on the AuthDB-backed path,
// where the DB write is what actually matters. Nothing bulk-preloads `users_`
// at construction, so a freshly-booted server (or, as here, a second
// AuthManager wired to the same AuthDB, standing in for one) has an empty
// cache for any user it never itself upserted. Removing a pre-existing DB row
// through that cold manager did the soft-delete successfully but reported
// failure, because the erase against the never-populated cache trivially
// returned 0. SCIM's deprovision path treated that false as a hard failure
// (fail-closed 500), and — since the DB write already happened — a client
// retry re-hit the same false-failure every time. The fix returns the DB's
// own `std::expected<bool, AuthDBError>` truth instead of the cache-erase
// bool, with cache/session cleanup demoted to a best-effort side effect.
TEST_CASE("remove_user returns true for a cold-cache DB hit (CC6.8 cold cache)",
          "[pg][auth][user][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    // Seed the row directly through AuthDB, bypassing AuthManager entirely —
    // no AuthManager instance ever caches this username.
    auto salt = AuthManager::random_bytes(16);
    auto salt_hex = AuthManager::bytes_to_hex(salt);
    REQUIRE(auth_db
                ->upsert_user("cora", AuthManager::pbkdf2_sha256("password1234", salt, 1000),
                              salt_hex, Role::user)
                .has_value());

    // A fresh AuthManager over the SAME AuthDB, modeling a cold-booted
    // process: its in-memory users_ map has never seen "cora".
    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());

    REQUIRE(cold_mgr.remove_user("cora"));

    // The DB row is now soft-deleted (is_active = false) — get_user filters
    // is_active, so it now reports not-found.
    REQUIRE_FALSE(auth_db->get_user("cora").has_value());
}

TEST_CASE("remove_user returns false for a DB miss, no error (cold cache)",
          "[pg][auth][user][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());

    REQUIRE_FALSE(cold_mgr.remove_user("nonexistent"));
}

TEST_CASE("remove_user still succeeds and clears sessions on a warm cache",
          "[pg][auth][user][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager mgr;
    mgr.set_auth_db(auth_db.get());

    // upsert_user goes through AuthManager, so it warms the cache too.
    REQUIRE(mgr.upsert_user("dana", "password1234", Role::user));
    auto token = mgr.authenticate("dana", "password1234");
    REQUIRE(token.has_value());
    REQUIRE(mgr.validate_session(*token).has_value());

    REQUIRE(mgr.remove_user("dana"));

    // Sessions belonging to the removed user are invalidated (CHAOS-T1-001).
    REQUIRE_FALSE(mgr.validate_session(*token).has_value());
    REQUIRE_FALSE(auth_db->get_user("dana").has_value());
}

// ── update_role: cold-cache DB truth (CC6.7, SCIM hardening round) ─────────
//
// Same class of bug as CC6.8 above but for `update_role`: it historically
// gated its return on whether the in-memory `users_` cache happened to
// contain the username, even on the AuthDB-backed path where the DB write is
// authoritative. A cold-booted server (or, as here, a second AuthManager
// wired to the same AuthDB that never warmed its cache for this user) would
// durably update the role in AuthDB yet report failure back to the caller.
// SCIM's group->role sync audits `update_role`'s return value as
// `scim.user.role_changed` = success|failure — the false-negative meant a
// real, durable role change went unaudited post-restart. The fix returns the
// AuthDB `std::expected<void, AuthDBError>` truth, with cache/session
// cleanup demoted to a best-effort side effect (mirrors remove_user).
TEST_CASE("update_role returns true for a cold-cache DB hit and the DB row reflects the change",
          "[pg][auth][user][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    // Seed the row directly through AuthDB, bypassing AuthManager entirely —
    // no AuthManager instance ever caches this username.
    auto salt = AuthManager::random_bytes(16);
    auto salt_hex = AuthManager::bytes_to_hex(salt);
    REQUIRE(auth_db
                ->upsert_user("cora", AuthManager::pbkdf2_sha256("password1234", salt, 1000),
                              salt_hex, Role::user)
                .has_value());

    // A fresh AuthManager over the SAME AuthDB, modeling a cold-booted
    // process: its in-memory users_ map has never seen "cora".
    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());

    REQUIRE(cold_mgr.update_role("cora", Role::admin));

    // The DB row itself reflects the change — this is the assertion that
    // proves the fix (previously this would return false despite the DB
    // write above having already succeeded).
    auto entry = auth_db->get_user("cora");
    REQUIRE(entry.has_value());
    REQUIRE(entry->role == Role::admin);
}

TEST_CASE("update_role returns false for a DB miss, no error (cold cache)",
          "[pg][auth][user][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());

    REQUIRE_FALSE(cold_mgr.update_role("nonexistent", Role::admin));
}

TEST_CASE("update_role still succeeds and clears sessions on a warm cache",
          "[pg][auth][user][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager mgr;
    mgr.set_auth_db(auth_db.get());

    // upsert_user goes through AuthManager, so it warms the cache too.
    REQUIRE(mgr.upsert_user("dana", "password1234", Role::user));
    auto token = mgr.authenticate("dana", "password1234");
    REQUIRE(token.has_value());
    REQUIRE(mgr.validate_session(*token).has_value());

    REQUIRE(mgr.update_role("dana", Role::admin));

    // Sessions belonging to the role-changed user are invalidated so the
    // stale session role can't grant old privileges.
    REQUIRE_FALSE(mgr.validate_session(*token).has_value());
    REQUIRE(mgr.get_user_role("dana") == Role::admin);
    auto entry = auth_db->get_user("dana");
    REQUIRE(entry.has_value());
    REQUIRE(entry->role == Role::admin);
}

// ── authenticate / verify_password: cold-cache DB truth (#4020) ────────────
//
// Third member of the cold-cache family above. `users_` is warmed only by
// load_config() and by THIS process's own per-username writes, so an account
// created through AuthDB by another process (the dashboard's
// POST /api/settings/users before a restart, SCIM, another replica) was
// invisible to authenticate()/verify_password(): both did `users_.find()`
// and reported "unknown user" without ever asking AuthDB, so a
// dashboard-created operator permanently 401'd after any server restart,
// indistinguishable from a bad password. The fix hydrates `users_` from the
// authoritative AuthDB row on a cache miss (find_user_or_hydrate), mirroring
// the remove_user/update_role posture: the DB is the truth, the map is a
// read-optimisation.
//
// The "cold" AuthManager below is a SECOND manager over the same AuthDB that
// never upserted the user itself - the same stand-in for a freshly-booted
// process the CC6.8/CC6.7 cases use. The row is seeded through a WARM manager
// (not a hand-built hash) so it carries the production kPbkdf2Iterations
// digest a real dashboard create would have written.
TEST_CASE("authenticate succeeds for a cold-cache DB hit (#4020)",
          "[pg][auth][session][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("cora", "password1234", Role::admin));

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    // NOTE: get_user_role() is no longer a valid "is this cache cold" probe —
    // it became AuthDB-authoritative (Gate 3 governance BLOCKING fix), so it
    // now correctly finds "cora" via a direct DB read regardless of whether
    // users_ has ever cached her. `cold_mgr` genuinely never having cached
    // her is still true and still the point of this test — it's proven by
    // the call below succeeding via find_user_or_hydrate's own cold-cache
    // path, not by get_user_role() returning nullopt beforehand.

    auto token = cold_mgr.authenticate("cora", "password1234");
    REQUIRE(token.has_value());
    auto session = cold_mgr.validate_session(*token);
    REQUIRE(session.has_value());
    REQUIRE(session->username == "cora");
    REQUIRE(session->role == Role::admin);

    // The miss hydrated the cache: a cache-only reader now sees the account.
    REQUIRE(cold_mgr.get_user_role("cora") == Role::admin);
}

TEST_CASE("authenticate still rejects a bad password on a cold cache (#4020)",
          "[pg][auth][session][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("cora", "password1234", Role::user));

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    REQUIRE_FALSE(cold_mgr.authenticate("cora", "wrong-password").has_value());
    REQUIRE_FALSE(cold_mgr.verify_password("cora", "wrong-password").has_value());
}

TEST_CASE("verify_password returns the DB role for a cold-cache DB hit (#4020)",
          "[pg][auth][session][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("cora", "password1234", Role::admin));

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    // NOTE: get_user_role() is no longer a valid "is this cache cold" probe —
    // it became AuthDB-authoritative (Gate 3 governance BLOCKING fix), so it
    // now correctly finds "cora" via a direct DB read regardless of whether
    // users_ has ever cached her. `cold_mgr` genuinely never having cached
    // her is still true and still the point of this test — it's proven by
    // the call below succeeding via find_user_or_hydrate's own cold-cache
    // path, not by get_user_role() returning nullopt beforehand.

    auto role = cold_mgr.verify_password("cora", "password1234");
    REQUIRE(role.has_value());
    REQUIRE(role->role == Role::admin);
    REQUIRE(cold_mgr.get_user_role("cora") == Role::admin); // hydrated
}

TEST_CASE("cold-cache hydration never resurrects a soft-deleted user (#4020)",
          "[pg][auth][session][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("cora", "password1234", Role::user));
    REQUIRE(warm_mgr.remove_user("cora")); // is_active = false

    // get_user filters is_active, so the cold miss stays a miss - the removed
    // account must not come back to life through the hydration path.
    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    REQUIRE_FALSE(cold_mgr.authenticate("cora", "password1234").has_value());
    REQUIRE_FALSE(cold_mgr.verify_password("cora", "password1234").has_value());
    REQUIRE_FALSE(cold_mgr.get_user_role("cora").has_value()); // nothing cached
}

TEST_CASE("authenticate fails closed when AuthDB is pool-saturated on a cold-cache lookup "
          "(#4020 adversarial-review follow-up)",
          "[pg][auth][session][cold_cache]") {
    // Mirrors the #2396 pool-saturation precedent (test_auth_db_pg.cpp): the
    // UserLookupMiss::DbError branch find_user_or_hydrate takes on a genuine
    // AuthDB query failure (vs UserNotFound) was previously untested — nothing
    // pinned that a future change couldn't collapse it into the UserNotFound
    // branch instead. This proves the FUNCTIONAL fail-closed outcome (nullopt,
    // no credential check performed) on both entry points; it does NOT assert
    // anything about the unknown_user metrics histogram (metrics_ isn't wired
    // in this fixture) — the code-level distinction between the two
    // UserLookupMiss enum values (never conflated into one metrics label) is
    // verified by reading find_user_or_hydrate's implementation, not by this
    // test (Gate 3 quality-engineer follow-up: narrowed this test's own claim
    // to what it actually observes).
    yuzu::test::AuthDbPg auth_db;
    // Seeds through AuthManager (real kPbkdf2Iterations), not a DB-direct upsert at
    // the cheap test-only 1000 iterations the OTHER cold_cache tests use — this
    // test's own final "pool released" check re-authenticates for real.
    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("pool-target", "password1234", Role::user));

    AuthManager cold_mgr; // never caches "pool-target" itself
    cold_mgr.set_auth_db(auth_db.get());

    // Saturate the fixture's size-4 pool (mirrors test_auth_db_pg.cpp's #2396
    // pattern exactly) so find_user_or_hydrate's get_user() cannot acquire a
    // connection and returns QueryFailed, not UserNotFound.
    std::vector<yuzu::server::pg::PgPool::Lease> held;
    for (int i = 0; i < 4; ++i) {
        auto lease = auth_db.pool().try_acquire_for(std::chrono::seconds(2));
        REQUIRE(lease);
        held.push_back(std::move(lease));
    }

    // Fails closed - no credential check performed, no session minted - and
    // (unlike a genuine unknown user) this must NOT be treated as a bad
    // username; find_user_or_hydrate's DbError branch is what enforces that.
    CHECK_FALSE(cold_mgr.authenticate("pool-target", "password1234").has_value());
    CHECK_FALSE(cold_mgr.verify_password("pool-target", "password1234").has_value());

    // Releasing the pool restores normal service - a blip is transient.
    held.clear();
    CHECK(cold_mgr.authenticate("pool-target", "password1234").has_value());
}

TEST_CASE("authenticate on a cold cache is a plain miss for an unknown user (#4020)",
          "[pg][auth][session][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    REQUIRE_FALSE(cold_mgr.authenticate("nonexistent", "password1234").has_value());
    REQUIRE_FALSE(cold_mgr.verify_password("nonexistent", "password1234").has_value());
}

TEST_CASE("a NUL-mangled username never pollutes the cache or matches the real account "
          "(Gate 4 governance BLOCKING finding)",
          "[pg][auth][session][cold_cache][security]") {
    // The exact attack: url_decode("admin%00garbage") produces the C++
    // string "admin\0garbage" (an embedded NUL, legally representable in
    // std::string). Before this fix, AuthDB::get_user had no input
    // validation, so PQexecParams (paramLengths=nullptr, reads text params
    // as NUL-terminated C strings) matched the TRUNCATED "admin" row while
    // find_user_or_hydrate's try_emplace cached the result under the FULL
    // mangled string - an unauthenticated caller could grow AuthManager::
    // users_ without bound (a distinct cache entry per garbage suffix, no
    // eviction) using nothing but a known-valid username and zero
    // credentials, since the hydration happens BEFORE the password check.
    yuzu::test::AuthDbPg auth_db;
    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("admin", "password1234", Role::admin));

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    REQUIRE_FALSE(cold_mgr.has_users()); // genuinely empty cache to start

    const std::string mangled = std::string("admin", 5) + '\0' + "garbage";
    REQUIRE(mangled.size() == 13); // 5 + 1 (NUL) + 7 ("garbage")

    // No credentials needed to reach the hydration attempt - even a
    // deliberately wrong password exercises find_user_or_hydrate first.
    REQUIRE_FALSE(cold_mgr.authenticate(mangled, "wrong-password").has_value());
    REQUIRE_FALSE(cold_mgr.verify_password(mangled, "wrong-password").has_value());
    CHECK_FALSE(cold_mgr.has_users()); // still empty - nothing was cached

    // The real account is completely unaffected and still logs in normally.
    REQUIRE(cold_mgr.authenticate("admin", "password1234").has_value());
    CHECK(cold_mgr.has_users()); // now warmed, by the LEGITIMATE username only
}

// ── get_user_role(): AuthDB-authoritative on every call (Gate 3 governance
// BLOCKING finding, fix shape confirmed via Sol/codex opine) ────────────────
//
// get_user_role() previously had NO AuthDB fallback at all - it was a pure
// `users_` cache read, completely independent of authenticate()/
// verify_password() (the two functions #4020's other fixes touch). It is
// what auth_routes.cpp's legacy API-token session synthesis calls on EVERY
// request, so a stale cached role here was a live stale-privilege gap for
// any manager that ever cached the user, reachable without any further
// password login at all.

TEST_CASE("get_user_role reflects a cross-manager demotion immediately, no re-login needed",
          "[pg][auth][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager mgr_a;
    mgr_a.set_auth_db(auth_db.get());
    REQUIRE(mgr_a.upsert_user("cora", "password1234", Role::admin));
    REQUIRE(mgr_a.get_user_role("cora") == Role::admin);

    AuthManager mgr_b;
    mgr_b.set_auth_db(auth_db.get());
    REQUIRE(mgr_b.update_role("cora", Role::user)); // the "other replica" demotes

    // No re-login through mgr_a at all - get_user_role() itself must reflect
    // the demotion on its own next call.
    REQUIRE(mgr_a.get_user_role("cora") == Role::user);
}

TEST_CASE("get_user_role reflects a cross-manager removal immediately, no re-login needed",
          "[pg][auth][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager mgr_a;
    mgr_a.set_auth_db(auth_db.get());
    yuzu::MetricsRegistry metrics;
    mgr_a.set_metrics_registry(&metrics);
    REQUIRE(mgr_a.upsert_user("cora", "password1234", Role::admin));
    REQUIRE(mgr_a.get_user_role("cora") == Role::admin);

    AuthManager mgr_b;
    mgr_b.set_auth_db(auth_db.get());
    REQUIRE(mgr_b.remove_user("cora"));

    REQUIRE_FALSE(mgr_a.get_user_role("cora").has_value());
    // A genuine UserNotFound is NOT a store error - must not fire the
    // store-error counter (Gate 5 CH-3 re-review follow-up: this discrimination
    // is exactly what would drown the real signal if it ever regressed).
    CHECK(metrics.counter("yuzu_auth_get_user_role_store_error_total").value() == 0);

    // Same discrimination for an InvalidUsername rejection (a NUL-embedded
    // username is a rejected-shape input, not a store health signal - #4020's
    // own get_user()/is_valid_principal fix, bucketed with UserNotFound).
    REQUIRE_FALSE(mgr_a.get_user_role(std::string("cor") + '\0' + "a").has_value());
    CHECK(metrics.counter("yuzu_auth_get_user_role_store_error_total").value() == 0);
}

TEST_CASE("get_user_role fails closed (not cached-admin) when AuthDB is pool-saturated",
          "[pg][auth][cold_cache]") {
    // The critical negative case: a DB-backed manager must NEVER fall back to
    // a stale cached role on a store error - that would silently reopen the
    // exact gap this fix closes, at the one moment (a degraded store) it
    // matters most.
    yuzu::test::AuthDbPg auth_db;

    AuthManager mgr;
    mgr.set_auth_db(auth_db.get());
    yuzu::MetricsRegistry metrics;
    mgr.set_metrics_registry(&metrics);
    REQUIRE(mgr.upsert_user("cora", "password1234", Role::admin));
    REQUIRE(mgr.get_user_role("cora") == Role::admin);

    std::vector<yuzu::server::pg::PgPool::Lease> held;
    for (int i = 0; i < 4; ++i) {
        auto lease = auth_db.pool().try_acquire_for(std::chrono::seconds(2));
        REQUIRE(lease);
        held.push_back(std::move(lease));
    }

    REQUIRE_FALSE(mgr.get_user_role("cora").has_value()); // NOT Role::admin from cache
    // Gate 5 chaos-injector CH-3/UP-6 follow-up: the ONE caller-visible signal
    // that a legacy-token-authenticated request is about to be floored to
    // Role::user must fire, not just a log line invisible under load.
    CHECK(metrics.counter("yuzu_auth_get_user_role_store_error_total").value() == 1);

    held.clear();
    REQUIRE(mgr.get_user_role("cora") == Role::admin); // recovers once the pool frees
    // Recovery must not add a spurious second sample.
    CHECK(metrics.counter("yuzu_auth_get_user_role_store_error_total").value() == 1);
}

TEST_CASE("get_user_role stays cache-only in config-file (no AuthDB) mode",
          "[auth][cold_cache]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);
    REQUIRE(mgr->get_user_role("alice") == Role::admin);
    REQUIRE_FALSE(mgr->get_user_role("nobody").has_value());
}

TEST_CASE("authenticate mints a session at the CURRENT role after a cross-manager demotion "
          "(#4020 adversarial-review follow-up)",
          "[pg][auth][session][cold_cache]") {
    // A second AuthManager over the same AuthDB models a different replica (or a
    // concurrent request on this same process): its users_ cache is independent
    // of the manager that performs the demotion below. authenticate()'s existing
    // active-status AuthDB read must be authoritative for role too, not just
    // existence — otherwise a just-demoted operator's next login mints a fresh
    // session at their OLD (higher) role, since durable session invalidation only
    // protects ALREADY-issued sessions, not a brand-new one.
    yuzu::test::AuthDbPg auth_db;

    AuthManager mgr_a;
    mgr_a.set_auth_db(auth_db.get());
    REQUIRE(mgr_a.upsert_user("cora", "password1234", Role::admin));
    // Cache mgr_a's copy at admin (this call is what previously would have gone
    // stale) before the demotion below.
    REQUIRE(mgr_a.authenticate("cora", "password1234").has_value());

    AuthManager mgr_b;
    mgr_b.set_auth_db(auth_db.get());
    REQUIRE(mgr_b.update_role("cora", Role::user)); // the "other replica" demotes

    // mgr_a's cache still says admin at this point; the fix must not trust it.
    auto token = mgr_a.authenticate("cora", "password1234");
    REQUIRE(token.has_value());
    auto session = mgr_a.validate_session(*token);
    REQUIRE(session.has_value());
    REQUIRE(session->role == Role::user); // NOT the stale cached admin

    // The cache itself is refreshed too, not just this one session mint.
    REQUIRE(mgr_a.get_user_role("cora") == Role::user);
}

TEST_CASE("verify_password returns the CURRENT role after a cross-manager demotion "
          "(#4020 adversarial-review follow-up)",
          "[pg][auth][session][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager mgr_a;
    mgr_a.set_auth_db(auth_db.get());
    REQUIRE(mgr_a.upsert_user("cora", "password1234", Role::admin));
    REQUIRE(mgr_a.verify_password("cora", "password1234").has_value()); // caches admin

    AuthManager mgr_b;
    mgr_b.set_auth_db(auth_db.get());
    REQUIRE(mgr_b.update_role("cora", Role::user));

    auto role = mgr_a.verify_password("cora", "password1234");
    REQUIRE(role.has_value());
    REQUIRE(role->role == Role::user); // NOT the stale cached admin
    REQUIRE(mgr_a.get_user_role("cora") == Role::user);
}

TEST_CASE("a cross-manager removal evicts the stale cache entry, not just the login "
          "(Gate 2 governance follow-up)",
          "[pg][auth][session][cold_cache]") {
    // Companion to the demotion tests above: removing a user through a DIFFERENT
    // AuthManager never touches this manager's users_ map (the durable session
    // wipe that accompanies remove_user() is fleet-wide, but the in-memory cache
    // is per-process). Without evicting on the !db_user branch, get_user_role()
    // (cache-only, no AuthDB fallback) would keep reporting the removed user as
    // "active, pre-removal role" indefinitely on this manager - reachable via a
    // still-valid API token, since removing a user does not itself revoke their
    // tokens (auth_routes.cpp's synthesize_token_session falls back to
    // get_user_role() for legacy-role synthesis).
    yuzu::test::AuthDbPg auth_db;

    AuthManager mgr_a;
    mgr_a.set_auth_db(auth_db.get());
    REQUIRE(mgr_a.upsert_user("cora", "password1234", Role::admin));
    REQUIRE(mgr_a.authenticate("cora", "password1234").has_value()); // caches admin
    REQUIRE(mgr_a.get_user_role("cora") == Role::admin);

    AuthManager mgr_b;
    mgr_b.set_auth_db(auth_db.get());
    REQUIRE(mgr_b.remove_user("cora")); // the "other replica" removes the account

    // mgr_a's cache still says "active, admin" at this point; both credential
    // paths must evict it on discovering the removal, not just deny this login.
    REQUIRE_FALSE(mgr_a.authenticate("cora", "password1234").has_value());
    REQUIRE_FALSE(mgr_a.get_user_role("cora").has_value()); // evicted, not just denied
}

TEST_CASE("a cross-manager removal evicts the stale cache entry via verify_password too "
          "(Gate 3 authdb follow-up)",
          "[pg][auth][session][cold_cache]") {
    // Sibling of the authenticate() case above, exercised through
    // verify_password()'s OWN call site - both share
    // recheck_role_after_credential_check now, but this pins that shared
    // behavior against EACH entry point rather than trusting a single test to
    // stand in for both if they ever diverge again.
    yuzu::test::AuthDbPg auth_db;

    AuthManager mgr_a;
    mgr_a.set_auth_db(auth_db.get());
    REQUIRE(mgr_a.upsert_user("cora", "password1234", Role::admin));
    REQUIRE(mgr_a.verify_password("cora", "password1234").has_value()); // caches admin
    REQUIRE(mgr_a.get_user_role("cora") == Role::admin);

    AuthManager mgr_b;
    mgr_b.set_auth_db(auth_db.get());
    REQUIRE(mgr_b.remove_user("cora"));

    REQUIRE_FALSE(mgr_a.verify_password("cora", "password1234").has_value());
    REQUIRE_FALSE(mgr_a.get_user_role("cora").has_value()); // evicted, not just denied
}

TEST_CASE("authenticate fails closed WITHOUT evicting the cache on a genuine AuthDB store "
          "error (Gate 3 quality-engineer follow-up)",
          "[pg][auth][session][cold_cache]") {
    // Distinguishes a genuine removal (UserNotFound - evict) from a transient
    // store error (QueryFailed/StoreBusy on pool saturation - do NOT evict) on
    // the post-password re-check: only the FIRST call below saturates the
    // pool, so it fails closed but the cache entry survives; the SECOND call
    // (pool free again) succeeds normally, proving the entry was never lost.
    yuzu::test::AuthDbPg auth_db;

    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("cora", "password1234", Role::admin));
    REQUIRE(warm_mgr.authenticate("cora", "password1234").has_value()); // caches admin

    std::vector<yuzu::server::pg::PgPool::Lease> held;
    for (int i = 0; i < 4; ++i) {
        auto lease = auth_db.pool().try_acquire_for(std::chrono::seconds(2));
        REQUIRE(lease);
        held.push_back(std::move(lease));
    }

    // The PBKDF2 check itself succeeds (cache hit, no DB needed); only the
    // post-check AuthDB re-verify hits the saturated pool and fails closed.
    REQUIRE_FALSE(warm_mgr.authenticate("cora", "password1234").has_value());

    held.clear(); // release the pool
    // If the cache had been wrongly evicted above, this would still succeed
    // (find_user_or_hydrate would just re-hydrate) - the real assertion is
    // that the role survived UNTOUCHED, which get_user_role proves directly
    // without going through another credential check.
    REQUIRE(warm_mgr.get_user_role("cora") == Role::admin);
}

TEST_CASE("a hydrated entry is superseded by a later in-process role change (#4020)",
          "[pg][auth][session][cold_cache]") {
    // upsert_user against an AuthDB-backed store is create-only (INSERT ... ON
    // CONFLICT DO NOTHING — see its own doc comment) — a password CHANGE for an
    // existing user has no route through it, so the reachable "later in-process
    // write supersedes the hydrated cache entry" case is a role change.
    yuzu::test::AuthDbPg auth_db;

    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("cora", "password1234", Role::user));

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    auto role = cold_mgr.verify_password("cora", "password1234"); // hydrates
    REQUIRE(role.has_value());
    REQUIRE(role->role == Role::user);

    // A role change through THIS manager replaces the hydrated entry in place
    // (find_user_or_hydrate's try_emplace does not clobber it — update_role
    // mutates the existing map entry directly).
    REQUIRE(cold_mgr.update_role("cora", Role::admin));
    role = cold_mgr.verify_password("cora", "password1234");
    REQUIRE(role.has_value());
    REQUIRE(role->role == Role::admin);
}

TEST_CASE("a demote that completed before the recheck starts is correctly "
          "observed - including in the minted session (Gate 5 "
          "chaos-injector CH-1 / external adversarial review fjarvis C1, "
          "#4107 row-locking rewrite)",
          "[pg][auth][session][cold_cache]") {
    // Originally a race reproduction (the hook fired between an unlocked read
    // and a plain mu_ acquire); #4107's row-locking rewrite moved the hook's
    // firing point to BEFORE the row-locked re-check even starts (a
    // synchronous hook at the OLD point would now self-deadlock - see
    // set_role_recheck_race_hook_for_test's doc). This still proves a real,
    // load-bearing property (a completed write is picked up correctly, not
    // masked by a hydrate-time cache value) - the genuine mid-flight race is
    // covered by the row-lock-blocking test below instead.
    yuzu::test::AuthDbPg auth_db;

    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("cora", "password1234", Role::admin));

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    cold_mgr.set_role_recheck_race_hook_for_test(
        [&] { REQUIRE(cold_mgr.update_role("cora", Role::user)); });

    auto token = cold_mgr.authenticate("cora", "password1234");
    REQUIRE(token.has_value());

    CHECK(cold_mgr.cached_role_for_test("cora") == Role::user);
    CHECK(cold_mgr.get_user_role("cora") == Role::user);
    auto session = cold_mgr.validate_session(*token);
    REQUIRE(session.has_value());
    CHECK(session->role == Role::user);
}

TEST_CASE("recheck never trusts a stale in-process cache value, only its own "
          "row-locked AuthDB read (#4020 Gate 3 re-review, security-guardian "
          "+ authdb)",
          "[pg][auth][session][cold_cache]") {
    // An intermediate (pre-#4107) fix trusted the CACHE's current value on
    // detecting a version divergence, reasoning "the cache moved, so it must
    // be a DB-confirmed write." That was false when the write that moved it
    // was another concurrent call's own now-stale read. #4107's row-locking
    // rewrite has no "trust the cache" path left at all - reproduce a cache
    // that's simply WRONG relative to the DB and confirm recheck ignores it.
    yuzu::test::AuthDbPg auth_db;

    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("cora", "password1234", Role::admin));

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    REQUIRE(cold_mgr.authenticate("cora", "password1234").has_value()); // hydrates cache=admin

    cold_mgr.set_role_recheck_race_hook_for_test([&] {
        // Diverge cache from DB: bump the CACHE via cold_mgr first, then
        // change the DB directly UNDERNEATH it without touching the cache
        // again. update_role() writes its DB row before touching the cache,
        // so the direct write MUST come second or it would just be
        // overwritten back to "admin" by the first call.
        REQUIRE(cold_mgr.update_role("cora", Role::admin));
        REQUIRE(auth_db.get()->update_role("cora", Role::user).has_value());
        // Cache now says "admin" (stale), DB says "user" (current).
    });

    auto token = cold_mgr.authenticate("cora", "password1234");
    REQUIRE(token.has_value());

    CHECK(cold_mgr.cached_role_for_test("cora") == Role::user);
    CHECK(cold_mgr.get_user_role("cora") == Role::user);
    auto session = cold_mgr.validate_session(*token);
    REQUIRE(session.has_value());
    CHECK(session->role == Role::user);
}

TEST_CASE("the row lock genuinely blocks a concurrent update_role() until "
          "the recheck commits, and the check-then-mint gap is closed "
          "either by the post-mint recheck or by the demote's own sweep "
          "(#4107 fix - row-locking closes the same-process divergence "
          "residual by construction; post_mint_role_recheck closes the "
          "check-then-mint gap fjarvis's PR #4076 review raised)",
          "[pg][auth][session][cold_cache]") {
    // The one test in this file that proves SERIALIZATION, not just a
    // sequenced outcome: spawns a genuine writer thread INSIDE the row lock
    // (via set_role_recheck_inside_lock_hook_for_test, which fires while
    // AuthDB::recheck_role_locked's transaction is still open) and confirms
    // its update_role() call cannot complete until this hook returns and the
    // recheck's transaction commits. This is the row-lock mechanism itself,
    // not an inference from before/after state.
    yuzu::test::AuthDbPg auth_db;

    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("cora", "password1234", Role::admin));

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    REQUIRE(cold_mgr.authenticate("cora", "password1234").has_value()); // hydrates cache=admin

    // Side connection used ONLY to observe pg_stat_activity - never touches
    // auth.users itself. authdb Gate 8 finding: the original version of this
    // test signalled "writer has started" from thread entry, well before the
    // writer thread ever issues its UPDATE, so under real scheduling jitter
    // (observed empirically: one failure in two full-suite runs, the writer
    // thread not reaching the lock-contending statement within the 200ms
    // hold) the test could pass OR fail regardless of whether the row lock
    // actually works. Polling pg_stat_activity for a backend genuinely
    // WAITING on a lock is a direct observation of the mechanism under test,
    // not a wall-clock proxy for it.
    yuzu::server::pg::PgConn watch_conn{PQconnectdb(auth_db.dsn().c_str())};
    REQUIRE(PQstatus(watch_conn.get()) == CONNECTION_OK);

    std::atomic<bool> writer_finished{false};
    std::atomic<bool> writer_update_ok{false};
    bool writer_observed_blocked = false; // set on the main thread below
    std::thread writer;

    cold_mgr.set_role_recheck_inside_lock_hook_for_test([&] {
        // Fires while cold_mgr's OWN recheck holds the row lock. Spawn the
        // writer here (never call update_role() synchronously on THIS
        // thread - see the hook's own doc on the self-deadlock hazard).
        // Catch2 assertion macros are NOT safe to call from a non-main
        // thread - the spawned thread only sets plain atomics. NO throwing
        // assertion (REQUIRE) runs anywhere between spawning `writer` and
        // joining it below (cpp-safety Gate 8 catch, matching
        // test_baseline_store.cpp's own documented fix for the identical
        // hazard: a REQUIRE in this window would unwind past a still-
        // joinable std::thread on failure and call std::terminate, aborting
        // the whole shard instead of failing one test) - this hook only
        // ever writes plain bools/atomics.
        writer = std::thread([&] {
            writer_update_ok = cold_mgr.update_role("cora", Role::user);
            writer_finished = true;
        });
        // Bounded poll (up to 3s, 5ms interval - authdb Gate 8: padded a
        // beat above kWriteTimeout's own 2s so this poll's own budget can
        // never be the reason a genuinely-blocked writer goes unobserved)
        // for a backend on this test database genuinely WAITING on a lock
        // while running an UPDATE against auth.users - i.e. the writer
        // thread above, blocked inside Postgres on the row this recheck is
        // holding. This is a direct observation of the blocking mechanism,
        // not an inference from timing: if the row lock were broken (e.g.
        // FOR UPDATE silently dropped), the writer's UPDATE would never
        // appear in this state - it would complete before ever showing up
        // as waiting.
        for (int i = 0; i < 600 && !writer_observed_blocked; ++i) {
            // cpp-safety Gate 8 catch: scoped to THIS test's own database and
            // excludes this polling connection's own backend - pg_stat_activity
            // is CLUSTER-wide, and this repo runs many [pg] test shards
            // concurrently against one Postgres instance (each with its own
            // per-test database, but the same 'yuzu' role and the same
            // auth.users table name) - an unscoped query could match an
            // unrelated shard's own lock contention and report a false
            // positive even if THIS test's row lock were silently broken.
            yuzu::server::pg::PgResult res = yuzu::server::pg::exec_params(
                watch_conn.get(),
                "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                "AND query ILIKE '%UPDATE auth.users%' AND datname = current_database() "
                "AND pid <> pg_backend_pid()",
                std::vector<std::string>{});
            if (res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) == 1 &&
                std::string(PQgetvalue(res.get(), 0, 0)) != "0") {
                writer_observed_blocked = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        // authdb Gate 8: no extra hold here (an earlier draft slept 50ms
        // after observing the block) - pg_stat_activity reflects live
        // backend state synchronously, not an MVCC snapshot, so a positive
        // count above is already a real-time fact; padding it further
        // proves nothing more. Returning now releases the row lock.
    });

    auto token = cold_mgr.authenticate("cora", "password1234");
    // cpp-safety Gate 8 catch: several recheck_role_locked early-return paths
    // (lease-acquire timeout, the new set_config() lock_timeout failure, a
    // failed/empty SELECT) skip the hook entirely, leaving `writer` still
    // default-constructed (non-joinable) - join() on a non-joinable thread
    // throws std::system_error, which would otherwise abort this test with a
    // confusing "unexpected exception" instead of a clean assertion failure
    // under exactly the pool-contention conditions this commit hardens
    // against. Still runs BEFORE any assertion that could throw for the
    // NORMAL (hook-fired) path - see the hook's own comment above.
    if (writer.joinable())
        writer.join();
    // Primary evidence: pg_stat_activity directly observed the writer's
    // UPDATE waiting on the row lock - not a wall-clock proxy for it.
    CHECK(writer_observed_blocked);
    CHECK(writer_finished.load());
    CHECK(writer_update_ok.load());

    // #4107 check-then-mint gap (external adversarial review, fjarvis, PR
    // #4076): EXACTLY which of two independent, unordered operations
    // happens first once the row lock releases - this thread's
    // persist_new_session (mint) vs. the writer thread's own session sweep
    // (inside its update_role(), once it unblocks and its DB UPDATE
    // commits) - is a genuine, uncontrolled race. But by this point
    // (writer already joined - its ENTIRE update_role(), sweep included, is
    // done) exactly one of two outcomes is possible, and BOTH are correct:
    //
    // (a) The mint's own post_mint_role_recheck ran AFTER the writer's DB
    //     UPDATE had already committed (whether or not the mint happened-
    //     before or after the writer's sweep specifically) - it observes
    //     the demoted role directly and denies the mint outright:
    //     token has no value.
    // (b) The mint's post_mint_role_recheck ran BEFORE the writer's DB
    //     UPDATE committed - the mint succeeds (token has a value), but
    //     because the writer's sweep runs strictly after its own commit,
    //     and we've already joined it, ANY session sweep-vs-mint ordering
    //     that could have raced is now resolved: either the sweep ran
    //     after the mint (removed it - validate_session comes back empty)
    //     or the mint ran after a sweep that found nothing (impossible
    //     here, since a sweep before the mint would find no entry to
    //     remove, and post_mint_role_recheck already covers that ordering
    //     in case (a) via its own fresh read).
    //
    // Either way, "cora" must never come out of this race still validly
    // holding an admin session - that's the property this block proves,
    // not a specific outcome of the (a)/(b) split.
    if (token.has_value()) {
        auto session = cold_mgr.validate_session(*token);
        CHECK((!session.has_value() || session->role != Role::admin));
    } else {
        SUCCEED("post_mint_role_recheck denied the mint outright - the stronger of the "
                "two possible correct outcomes");
    }
    CHECK(cold_mgr.get_user_role("cora") == Role::user); // DB-authoritative, unaffected either way
}

TEST_CASE("post_mint_role_recheck denies a login when a demote lands strictly "
          "inside the check-then-mint window, deterministically - not a race "
          "(#4107 fix for the external adversarial review, fjarvis, PR #4076: "
          "\"an inherent check-then-mint gap no non-serialized recheck can "
          "close\" - closed via the same post-mint-recheck-and-revoke pattern "
          "docs/auth-architecture.md already uses for OIDC/SAML)",
          "[pg][auth][session][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("dana", "password1234", Role::admin));

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    REQUIRE(cold_mgr.authenticate("dana", "password1234").has_value()); // hydrates cache=admin

    bool demote_ok = false;
    // Fires AFTER the row-locked recheck has already returned "admin" (the
    // row lock is released by this point - see the hook's own doc) but
    // BEFORE persist_new_session mints the session. No lock is held here,
    // so this can safely demote SYNCHRONOUSLY and wait for it to fully
    // complete (unlike the row-lock-blocking test's hook, which must spawn
    // a separate thread to avoid a self-deadlock) - this is what makes the
    // race deterministic instead of timing-dependent: by the time this hook
    // returns, the demote (DB UPDATE + its own session sweep) has
    // unconditionally already committed.
    cold_mgr.set_post_mint_race_hook_for_test([&] { demote_ok = cold_mgr.update_role("dana", Role::user); });

    auto token = cold_mgr.authenticate("dana", "password1234");
    REQUIRE(demote_ok);
    // The demote committed strictly inside the check-then-mint window - the
    // recheck read "admin" before it, the mint's post_mint_role_recheck
    // fresh-reads AuthDB after it, sees the divergence, and denies the mint
    // outright. Deterministic: this is NOT the same non-deterministic race
    // the earlier row-lock-blocking test covers (there, the demote races the
    // mint after the lock releases; here, the hook forces the demote to be
    // 100% complete before the mint's own post-check ever runs).
    CHECK_FALSE(token.has_value());
    CHECK(cold_mgr.get_user_role("dana") == Role::user); // DB-authoritative
}

TEST_CASE("create_local_session's own post-mint recheck denies a stale-role "
          "mint too (#4107 fix - /login/mfa's TOTP/recovery verify reads a "
          "role from an earlier verify_password() call, potentially across "
          "an entire TOTP-verification round trip, then hands it to "
          "create_local_session as a plain parameter with no idea how "
          "stale it is)",
          "[pg][auth][session][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager mgr;
    mgr.set_auth_db(auth_db.get());
    // "frank" is genuinely a user - never admin. Simulates a role that
    // changed (or was simply wrong) somewhere in the gap between an earlier
    // verify_password() call and this create_local_session() call actually
    // minting - exactly the wider check-then-mint window /login/mfa's TOTP/
    // recovery verify has (auth_routes.cpp's create_local_session call
    // sites; NOT /login/mfa/stepup, which never calls create_local_session
    // at all), which has no row lock of its own to narrow it in the first
    // place.
    REQUIRE(mgr.upsert_user("frank", "password1234", Role::user));

    // Mint with a STALE "admin" role, as if an earlier check had returned it
    // before a demote (or simply a bug upstream) landed.
    auto token = mgr.create_local_session_for_test("frank", Role::admin, true);
    CHECK(token.empty()); // fail-safe empty-token contract (ADR-0007), same as a durable-write failure
    CHECK(mgr.get_user_role("frank") == Role::user); // DB-authoritative, unaffected
}

TEST_CASE("post_mint_role_recheck fails closed on a genuine AuthDB store "
          "error too, not only on an actual role divergence (#4107 Gate 8 "
          "coverage gap, cpp-safety)",
          "[pg][auth][session][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("greg", "password1234", Role::admin));

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    REQUIRE(cold_mgr.authenticate("greg", "password1234").has_value()); // hydrates cache

    // Saturate the fixture's size-4 pool from inside the check-then-mint
    // window (same #2396 pattern the pool-saturation cold_cache test above
    // uses) so post_mint_role_recheck's own auth_db_->get_user() call
    // cannot acquire a connection and fails QueryFailed, not UserNotFound -
    // proving the store-error branch denies too, not just the role-
    // divergence branch (post_mint_role_recheck's `!post` check folds both
    // into one deny path, but only the role-divergence half had a test).
    std::vector<yuzu::server::pg::PgPool::Lease> held;
    cold_mgr.set_post_mint_race_hook_for_test([&] {
        for (int i = 0; i < 4; ++i) {
            auto lease = auth_db.pool().try_acquire_for(std::chrono::seconds(2));
            REQUIRE(lease);
            held.push_back(std::move(lease));
        }
    });

    auto token = cold_mgr.authenticate("greg", "password1234");
    held.clear(); // release before any further assertion - restores normal service
    CHECK_FALSE(token.has_value());
    // A store error must fail closed WITHOUT wrongly evicting/demoting a
    // perfectly valid entry over a transient blip - same principle
    // recheck_role_after_credential_check's own store-error branch follows.
    CHECK(cold_mgr.get_user_role("greg") == Role::admin);
}

TEST_CASE("recheck_role_locked's own set_config() lock_timeout fails the "
          "recheck closed well under the pooled connection's 10s default "
          "when the row lock is already held elsewhere (#4107 Gate 8 "
          "coverage gap - authdb: nothing previously proved this path fires "
          "at all, only that it compiles)",
          "[pg][auth][session][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("greta", "password1234", Role::admin));

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    REQUIRE(cold_mgr.authenticate("greta", "password1234").has_value()); // hydrates cache

    // Hold a real row lock on greta's row from a SEPARATE, un-pooled
    // connection - never committed until after the timed call below
    // returns. Opened directly via PQconnectdb, so it never receives
    // AuthDbPg's pool's `-c lock_timeout=10000` startup option
    // (pg_pool.cpp) at all - it's irrelevant here either way, since this
    // connection never itself waits on a lock. What's under test is
    // cold_mgr's OWN pooled connection: its `lock_timeout` stays at that
    // pool's 10000ms default except inside recheck_role_locked's own
    // transaction, where its set_config('lock_timeout', ..., true) call
    // (SET LOCAL's parameterized equivalent) narrows it to kWriteTimeout.
    yuzu::server::pg::PgConn holder{PQconnectdb(auth_db.dsn().c_str())};
    REQUIRE(PQstatus(holder.get()) == CONNECTION_OK);
    {
        yuzu::server::pg::PgResult begin_res =
            yuzu::server::pg::exec_params(holder.get(), "BEGIN", std::vector<std::string>{});
        REQUIRE(begin_res.status() == PGRES_COMMAND_OK);
        yuzu::server::pg::PgResult lock_res = yuzu::server::pg::exec_params(
            holder.get(), "SELECT 1 FROM auth.users WHERE username = $1 FOR UPDATE",
            std::vector<std::string>{"greta"});
        REQUIRE(lock_res.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(lock_res.get()) == 1);
    }

    const auto call_start = std::chrono::steady_clock::now();
    auto token = cold_mgr.authenticate("greta", "password1234");
    const auto call_duration = std::chrono::steady_clock::now() - call_start;

    // Release the held lock - cleanup, taken after the timing measurement so
    // it can't shorten the window under test.
    yuzu::server::pg::exec_params(holder.get(), "ROLLBACK", std::vector<std::string>{});

    // Fails CLOSED: recheck_role_locked's own SELECT ... FOR UPDATE can't
    // get the lock, and its set_config()-set lock_timeout (2000ms, matching
    // kWriteTimeout) fires and denies the login rather than hanging toward
    // the connection's much larger 10000ms pooled default.
    CHECK_FALSE(token.has_value());
    // Bounded well under the connection's 10s default (proves set_config()
    // actually took effect, not just compiled), comfortably above near-zero
    // (proves the call genuinely waited on the lock and hit the timeout,
    // rather than failing instantly for some unrelated faster reason).
    // authdb Gate 8 confirmation round: measured 2011-2012ms across 6 direct
    // runs (a server-side timer interrupt, largely insensitive to client
    // scheduling jitter, not a client-side poll loop) - 8000ms leaves headroom
    // for a more jitter-prone runner (e.g. Wee Tam/Windows) without moving
    // the fix-absent discriminator, which is ~10011ms per the red run above.
    CHECK(call_duration >= std::chrono::milliseconds(1500));
    CHECK(call_duration < std::chrono::milliseconds(8000));
}

TEST_CASE("a concurrent remove_user() that completes before the recheck "
          "starts denies rather than trusting the stale pre-removal role "
          "(#4020 Gate 3 re-review, authdb Finding 3 coverage gap)",
          "[pg][auth][session][cold_cache]") {
    yuzu::test::AuthDbPg auth_db;

    AuthManager warm_mgr;
    warm_mgr.set_auth_db(auth_db.get());
    REQUIRE(warm_mgr.upsert_user("cora", "password1234", Role::user));

    AuthManager cold_mgr;
    cold_mgr.set_auth_db(auth_db.get());
    cold_mgr.set_role_recheck_race_hook_for_test(
        [&] { REQUIRE(cold_mgr.remove_user("cora")); });

    auto token = cold_mgr.authenticate("cora", "password1234");
    CHECK_FALSE(token.has_value());
}

TEST_CASE("reactivate_user() draws a fresh process-wide version stamp, never a "
          "reset that could re-match an earlier in-flight call's captured version "
          "(Gate 5 CH-1 re-review follow-up)",
          "[pg][auth][cold_cache]") {
    // security-guardian, authdb, cpp-safety and cpp-expert independently found
    // the same gap in this fix's first shape: a PER-USERNAME counter (carried
    // forward + bumped by upsert_user(), but NOT by reactivate_user(), which
    // wholesale-replaces the cache entry with a fresh AuthDB read that knows
    // nothing about role_version) resets to 0 across remove_user()+
    // reactivate_user() - a value a stale in-flight call's pre_check_version
    // could realistically already hold. The fix: a single process-wide
    // monotonic stamp (next_role_version_()), drawn fresh on every write
    // including reactivate_user()'s, so the post-reactivate version can never
    // equal ANY version this process has ever stamped before - not just "not
    // equal to 0."
    yuzu::test::AuthDbPg auth_db;

    AuthManager mgr;
    mgr.set_auth_db(auth_db.get());
    REQUIRE(mgr.upsert_user("cora", "password1234", Role::admin));
    REQUIRE(mgr.authenticate("cora", "password1234").has_value()); // hydrate + recheck bump
    auto version_before_removal = mgr.cached_role_version_for_test("cora");
    REQUIRE(version_before_removal.has_value());

    REQUIRE(mgr.remove_user("cora"));
    REQUIRE_FALSE(mgr.cached_role_version_for_test("cora").has_value()); // erased

    REQUIRE(mgr.reactivate_user("cora"));
    auto version_after_reactivate = mgr.cached_role_version_for_test("cora");
    REQUIRE(version_after_reactivate.has_value());
    CHECK(*version_after_reactivate > *version_before_removal);
}

// ── Authentication ───────────────────────────────────────────────────────────

TEST_CASE("authenticate succeeds with correct password", "[auth][session]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);

    auto token = mgr->authenticate("alice", "secret123456");
    REQUIRE(token.has_value());
    REQUIRE_FALSE(token->empty());
}

TEST_CASE("authenticate fails with wrong password", "[auth][session]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);

    auto token = mgr->authenticate("alice", "wrong");
    REQUIRE_FALSE(token.has_value());
}

TEST_CASE("authenticate fails for unknown user", "[auth][session]") {
    auto mgr = make_temp_auth();
    auto token = mgr->authenticate("nobody", "password1234");
    REQUIRE_FALSE(token.has_value());
}

TEST_CASE("validate_session returns correct user info", "[auth][session]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);

    auto token = mgr->authenticate("alice", "secret123456");
    REQUIRE(token.has_value());

    auto session = mgr->validate_session(*token);
    REQUIRE(session.has_value());
    REQUIRE(session->username == "alice");
    REQUIRE(session->role == Role::admin);
}

TEST_CASE("invalidate_session destroys session", "[auth][session]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);

    auto token = mgr->authenticate("alice", "secret123456");
    REQUIRE(token.has_value());

    CHECK(mgr->invalidate_session(*token)); // legacy in-memory: always true
    REQUIRE_FALSE(mgr->validate_session(*token).has_value());
}

// ── Idle (inactivity) session timeout — SOC 2 CC6.3 ──────────────────────────
// The window is a real steady_clock interval, so these use a short (1-2s)
// window + sleeps and are tagged [slow] (excludable with ~[slow]), matching the
// account-lockout expiry test.

TEST_CASE("idle timeout disabled by default: a session survives inactivity",
          "[auth][session][idle][slow]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);
    auto token = mgr->authenticate("alice", "secret123456");
    REQUIRE(token.has_value());
    // session_inactivity_ defaults to 0 (disabled) — a pause does not
    // invalidate the session (only the absolute 8h lifetime applies).
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    CHECK(mgr->validate_session(*token).has_value());
}

TEST_CASE("idle timeout invalidates and evicts an inactive session",
          "[auth][session][idle][slow]") {
    auto mgr = make_temp_auth();
    mgr->set_session_inactivity(std::chrono::seconds(1));
    mgr->upsert_user("alice", "secret123456", Role::admin);
    auto token = mgr->authenticate("alice", "secret123456");
    REQUIRE(token.has_value());
    CHECK(mgr->validate_session(*token).has_value()); // active immediately

    // Idle past the 1s window (1.6s for calendar-second margin / runner I/O).
    std::this_thread::sleep_for(std::chrono::milliseconds(1600));
    CHECK_FALSE(mgr->validate_session(*token).has_value());
    // Evicted, not merely rejected — a replayed cookie cannot be re-touched
    // back to life; a second check is still nullopt.
    CHECK_FALSE(mgr->validate_session(*token).has_value());
}

TEST_CASE("idle timeout slides forward on activity (active session stays alive)",
          "[auth][session][idle][slow]") {
    auto mgr = make_temp_auth();
    mgr->set_session_inactivity(std::chrono::seconds(2));
    mgr->upsert_user("alice", "secret123456", Role::admin);
    auto token = mgr->authenticate("alice", "secret123456");
    REQUIRE(token.has_value());

    // Validate every 0.7s for ~3.5s total. Each touch is within the 2s window,
    // so the session lives well past the original 2s-from-creation mark — the
    // window slides on every authenticated request.
    for (int i = 0; i < 5; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
        REQUIRE(mgr->validate_session(*token).has_value());
    }
    // Stop touching it; after > 2s idle it expires. 2.7s (vs the 2s window)
    // leaves a full 700ms margin over the touch cadence so a starved CI runner
    // can't dip the measured steady_clock gap below the eviction threshold.
    std::this_thread::sleep_for(std::chrono::milliseconds(2700));
    CHECK_FALSE(mgr->validate_session(*token).has_value());
}

TEST_CASE("invalidate_user_sessions wipes every session for a user (multi-token)",
          "[auth][session][invalidate_user_sessions]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);
    mgr->upsert_user("bob", "secret123456", Role::user);

    // Three concurrent alice sessions (different browsers/devices)
    // and one bob session.
    auto a1 = mgr->authenticate("alice", "secret123456");
    auto a2 = mgr->authenticate("alice", "secret123456");
    auto a3 = mgr->authenticate("alice", "secret123456");
    auto b1 = mgr->authenticate("bob", "secret123456");
    REQUIRE(a1);
    REQUIRE(a2);
    REQUIRE(a3);
    REQUIRE(b1);

    auto result = mgr->invalidate_user_sessions("alice");
    // All three alice sessions wiped.
    REQUIRE(result.count == 3);
    // db_persisted is true when AuthDB is configured and the DELETE
    // succeeds; legacy config-file-only path also reports true.
    REQUIRE(result.db_persisted);

    // bob's session unaffected.
    REQUIRE(mgr->validate_session(*b1).has_value());
    // Every alice token rejected.
    REQUIRE_FALSE(mgr->validate_session(*a1).has_value());
    REQUIRE_FALSE(mgr->validate_session(*a2).has_value());
    REQUIRE_FALSE(mgr->validate_session(*a3).has_value());
}

TEST_CASE("invalidate_user_sessions returns 0 for unknown user",
          "[auth][session][invalidate_user_sessions]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);
    auto a = mgr->authenticate("alice", "secret123456");
    REQUIRE(a);

    auto result = mgr->invalidate_user_sessions("ghost");
    REQUIRE(result.count == 0);
    REQUIRE(result.db_persisted);

    // Existing alice session still valid.
    REQUIRE(mgr->validate_session(*a).has_value());
}

TEST_CASE("invalidate_user_sessions is idempotent",
          "[auth][session][invalidate_user_sessions][idempotent]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);
    auto a1 = mgr->authenticate("alice", "secret123456");
    REQUIRE(a1);

    auto first = mgr->invalidate_user_sessions("alice");
    REQUIRE(first.count == 1);

    auto second = mgr->invalidate_user_sessions("alice");
    REQUIRE(second.count == 0);
    REQUIRE(second.db_persisted);
}

TEST_CASE("validate_session fails for garbage token", "[auth][session]") {
    auto mgr = make_temp_auth();
    REQUIRE_FALSE(mgr->validate_session("not-a-real-token").has_value());
}

TEST_CASE("validate_session rejects overly-long tokens (DoS protection #630)", "[auth][session]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("testuser", "secret123456", Role::admin); // min 12 chars

    // Get a valid token via normal auth flow
    auto valid_token = mgr->authenticate("testuser", "secret123456");
    REQUIRE(valid_token.has_value());
    REQUIRE(valid_token->size() == 64); // Should be exactly 64 hex chars

    // 65 chars — should be rejected
    std::string too_long_65 = *valid_token + "x";
    REQUIRE_FALSE(mgr->validate_session(too_long_65).has_value());

    // 128 chars — should be rejected
    REQUIRE_FALSE(mgr->validate_session(std::string(128, 'a')).has_value());

    // 1000 chars — should be rejected (DoS attempt)
    REQUIRE_FALSE(mgr->validate_session(std::string(1000, 'b')).has_value());
}

// ── Enrollment tokens + pending agents (WS-6 6.2) ────────────────────────────
//
// Since slice 6.2 enrollment state lives ONLY in AuthDB (Postgres): the pre-6.2
// in-memory maps and the enrollment-tokens.cfg / pending-agents.cfg files are
// gone, so every test here runs against a real PG-backed AuthDB. Tests that
// asserted file persistence (the UP-C1 "crash-replay from disk" case) and the
// read-only `validate_enrollment_token` probe (removed — it had no production
// caller) are deleted; the crash-replay guarantee is now covered by
// "state survives AuthManager re-construction over the same PG" below.

namespace {

/// An AuthManager wired to a fresh PG-backed AuthDB. `mgr` is what production
/// code drives; `db` lets a test reach the store/pool directly.
struct EnrollFixture {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    EnrollFixture() { mgr.set_auth_db(db.get()); }
};

using yuzu::server::StoreError;

/// Consume with the boilerplate agent metadata; the token/agent are what matter.
std::expected<ConsumeEnrollResult, StoreError> consume(AuthManager& mgr, std::string_view raw,
                                                       const std::string& agent) {
    return mgr.consume_and_enroll(raw, agent, "host-" + agent, "linux", "x86_64", "0.1.0");
}

/// Mint a token or fail the test.
CreatedEnrollmentToken mint(AuthManager& mgr, const std::string& label, int max_uses,
                            std::chrono::seconds ttl) {
    auto c = mgr.create_enrollment_token(label, max_uses, ttl, "tester");
    REQUIRE(c.has_value());
    return *c;
}

} // namespace

TEST_CASE("enrollment: create, list, revoke", "[auth][enrollment][pg]") {
    EnrollFixture f;
    auto t = mint(f.mgr, "test", 0, std::chrono::hours(1));
    CHECK(t.raw_token.size() == 64);
    CHECK(t.token_id.size() == 8);

    auto tokens = f.mgr.list_enrollment_tokens();
    REQUIRE(tokens.has_value());
    REQUIRE(tokens->size() == 1);
    CHECK((*tokens)[0].token_id == t.token_id);
    CHECK((*tokens)[0].label == "test");
    CHECK_FALSE((*tokens)[0].revoked);

    CHECK(f.mgr.revoke_enrollment_token(t.token_id).value());
    CHECK_FALSE(f.mgr.revoke_enrollment_token("ffffffff").value());
    CHECK(f.mgr.list_enrollment_tokens().value()[0].revoked);

    // A revoked token no longer admits.
    auto r = consume(f.mgr, t.raw_token, "agent-1");
    REQUIRE(r.has_value());
    CHECK(r->kind == ConsumeEnrollResult::Kind::token_rejected);
    CHECK(r->token_error == EnrollmentTokenError::revoked);
}

TEST_CASE("enrollment: many tokens are distinct and all listed", "[auth][enrollment][pg]") {
    // (was "batch token creation": the batch helper moved to the callers; the
    // property under test is that minted tokens never collide.)
    EnrollFixture f;
    std::vector<std::string> raws;
    for (int i = 0; i < 5; ++i)
        raws.push_back(mint(f.mgr, "batch-" + std::to_string(i + 1), 10, std::chrono::hours(1)).raw_token);
    for (size_t i = 0; i < raws.size(); ++i)
        for (size_t j = i + 1; j < raws.size(); ++j)
            REQUIRE(raws[i] != raws[j]);
    CHECK(f.mgr.list_enrollment_tokens().value().size() == 5);
}

TEST_CASE("consume_and_enroll returns a claim on success and enrolls the agent",
          "[auth][enrollment][atomic]") {
    EnrollFixture f;
    auto t = mint(f.mgr, "first-use", 5, std::chrono::hours(1));

    auto r = consume(f.mgr, t.raw_token, "agent-A");
    REQUIRE(r.has_value());
    REQUIRE(r->kind == ConsumeEnrollResult::Kind::enrolled);
    CHECK(r->claim.use_count_after == 1);
    CHECK(r->claim.max_uses == 5);
    CHECK_FALSE(r->claim.single_use);
    CHECK(r->claim.token_id == t.token_id);
    // The agent is approved as part of the SAME atomic call.
    auto st = f.mgr.get_pending_status("agent-A");
    REQUIRE(st.has_value());
    REQUIRE(st->has_value());
    CHECK(**st == PendingStatus::approved);

    // Multi-use: a second agent also wins.
    auto r2 = consume(f.mgr, t.raw_token, "agent-B");
    REQUIRE(r2.has_value());
    REQUIRE(r2->kind == ConsumeEnrollResult::Kind::enrolled);
    CHECK(r2->claim.use_count_after == 2);
    CHECK(f.mgr.list_enrollment_tokens().value()[0].last_consumed_by_agent_id == "agent-B");
}

TEST_CASE("consume_and_enroll: not_found on an unknown token, nobody enrolled",
          "[auth][enrollment][atomic]") {
    EnrollFixture f;
    mint(f.mgr, "decoy", 1, std::chrono::hours(1));
    auto r = consume(f.mgr, std::string(64, 'a'), "agent-X");
    REQUIRE(r.has_value());
    CHECK(r->kind == ConsumeEnrollResult::Kind::token_rejected);
    CHECK(r->token_error == EnrollmentTokenError::not_found);
    CHECK_FALSE(f.mgr.get_pending_status("agent-X").value().has_value());
}

TEST_CASE("consume_and_enroll: expired variant (expiry judged by the DB clock)",
          "[auth][enrollment][atomic]") {
    EnrollFixture f;
    auto t = mint(f.mgr, "expire", 0, std::chrono::hours(1));
    // Push expires_at into the PG past instead of sleeping: expiry is evaluated
    // in SQL against now(), so this is exactly what a lapsed TTL looks like.
    {
        auto lease = f.db.pool().try_acquire_for(std::chrono::seconds(2));
        REQUIRE(lease);
        auto upd = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE auth.enrollment_tokens SET expires_at = now() - interval '1 second' "
            "WHERE token_id = $1",
            std::vector<std::string>{t.token_id});
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
    }
    auto r = consume(f.mgr, t.raw_token, "agent-X");
    REQUIRE(r.has_value());
    CHECK(r->kind == ConsumeEnrollResult::Kind::token_rejected);
    CHECK(r->token_error == EnrollmentTokenError::expired);
}

TEST_CASE("consume_and_enroll: already_consumed after exhaustion names the winner",
          "[auth][enrollment][atomic]") {
    EnrollFixture f;
    auto t = mint(f.mgr, "once", 1, std::chrono::hours(1));

    auto first = consume(f.mgr, t.raw_token, "agent-A");
    REQUIRE(first.has_value());
    REQUIRE(first->kind == ConsumeEnrollResult::Kind::enrolled);
    CHECK(first->claim.single_use);
    CHECK(first->claim.use_count_after == 1);

    auto second = consume(f.mgr, t.raw_token, "agent-B");
    REQUIRE(second.has_value());
    CHECK(second->kind == ConsumeEnrollResult::Kind::token_rejected);
    CHECK(second->token_error == EnrollmentTokenError::already_consumed);
    // The lost-race audit detail stamps already_consumed_by=agent-A.
    CHECK(second->already_consumed_by == "agent-A");
}

TEST_CASE("consume_and_enroll: empty / oversize token is InvalidInput",
          "[auth][enrollment][atomic]") {
    EnrollFixture f;
    auto empty = consume(f.mgr, "", "agent-X");
    REQUIRE_FALSE(empty.has_value());
    CHECK(empty.error() == StoreError::InvalidInput);

    std::string oversize(kMaxEnrollmentTokenLength + 1, 'A');
    auto big = consume(f.mgr, oversize, "agent-X");
    REQUIRE_FALSE(big.has_value());
    CHECK(big.error() == StoreError::InvalidInput);
}

TEST_CASE("consume_and_enroll: an admin-denied agent is refused and the use is rolled back "
          "(#1135)",
          "[auth][enrollment][atomic]") {
    EnrollFixture f;
    auto t = mint(f.mgr, "once", 1, std::chrono::hours(1));
    REQUIRE(f.mgr.add_pending_agent("evil", "h", "linux", "x86_64", "0.1.0").value());
    REQUIRE(f.mgr.deny_pending_agent("evil", "admin").value());

    auto r = consume(f.mgr, t.raw_token, "evil");
    REQUIRE(r.has_value());
    CHECK(r->kind == ConsumeEnrollResult::Kind::admin_denied);
    CHECK(f.mgr.list_enrollment_tokens().value()[0].use_count == 0);
    CHECK(**f.mgr.get_pending_status("evil") == PendingStatus::denied);

    // The single use is still there for the legitimate agent.
    auto ok = consume(f.mgr, t.raw_token, "good");
    REQUIRE(ok.has_value());
    CHECK(ok->kind == ConsumeEnrollResult::Kind::enrolled);
}

namespace {
/// N threads race ONE token across a pool big enough that every thread holds its
/// own connection (the real cross-connection race). Returns {winners, race
/// losers, anything else}.
struct RaceOutcome {
    int winners{0};
    int race_losers{0};
    int other{0};
};
RaceOutcome race_consume(yuzu::test::AuthDbPg& db, int max_uses, int threads,
                         std::vector<yuzu::server::auth::EnrollmentToken>* tokens_after) {
    yuzu::server::pg::PgPool pool{
        yuzu::server::pg::PgPool::Options{.conninfo = db.dsn(), .size = static_cast<std::size_t>(threads)}};
    REQUIRE(pool.valid());
    // A SEPARATE codec chain: a SecretCodec registers the mfa column once, so it
    // cannot be shared with the fixture's own AuthDB. Enrollment never touches the
    // codec, so it needs no init().
    yuzu::test::TempDir race_keys;
    yuzu::server::FileKeyProvider race_provider(race_keys.path);
    yuzu::server::pg::SecretCodec race_codec(race_provider);
    yuzu::server::AuthDB adb{pool, race_codec, 0};
    REQUIRE(adb.is_open());
    AuthManager mgr;
    mgr.set_auth_db(&adb);
    auto t = mint(mgr, "race", max_uses, std::chrono::hours(1));

    std::atomic<bool> go{false};
    std::atomic<int> winners{0}, losers{0}, other{0};
    std::vector<std::thread> ts;
    for (int i = 0; i < threads; ++i) {
        ts.emplace_back([&, i] {
            while (!go.load())
                std::this_thread::yield();
            auto r = consume(mgr, t.raw_token, "agent-" + std::to_string(i));
            if (r.has_value() && r->kind == ConsumeEnrollResult::Kind::enrolled)
                winners.fetch_add(1);
            else if (r.has_value() && r->token_error == EnrollmentTokenError::already_consumed)
                losers.fetch_add(1);
            else
                other.fetch_add(1);
        });
    }
    go.store(true);
    for (auto& th : ts)
        th.join();
    *tokens_after = mgr.list_enrollment_tokens().value();
    return {winners.load(), losers.load(), other.load()};
}
} // namespace

TEST_CASE("consume_and_enroll: concurrent claim - exactly one winner",
          "[auth][enrollment][atomic][race]") {
    // The canonical #827 race-test, now across real PG connections: N threads try
    // to consume the same single-use token. Exactly one wins; everyone else sees
    // already_consumed; nothing else fires.
    yuzu::test::AuthDbPg db;
    std::vector<yuzu::server::auth::EnrollmentToken> tokens;
    const auto o = race_consume(db, 1, 16, &tokens);
    CHECK(o.winners == 1);
    CHECK(o.race_losers == 15);
    CHECK(o.other == 0);
    REQUIRE(tokens.size() == 1);
    CHECK(tokens[0].use_count == 1);
    CHECK_FALSE(tokens[0].last_consumed_by_agent_id.empty());
}

TEST_CASE("consume_and_enroll: concurrent claim on an N-use token - exactly N winners",
          "[auth][enrollment][atomic][race]") {
    yuzu::test::AuthDbPg db;
    std::vector<yuzu::server::auth::EnrollmentToken> tokens;
    const auto o = race_consume(db, 3, 16, &tokens);
    CHECK(o.winners == 3);
    CHECK(o.race_losers == 13);
    CHECK(o.other == 0);
    REQUIRE(tokens.size() == 1);
    CHECK(tokens[0].use_count == 3);
}

TEST_CASE("enrollment state survives AuthManager re-construction over the same PG",
          "[auth][enrollment][pg]") {
    // Replaces the pre-6.2 UP-C1 crash-replay-from-disk test: a consumed token,
    // a queued agent and a denial are durable in Postgres, so a brand-new
    // AuthManager (a restarted process, or a second replica) sees them.
    yuzu::test::AuthDbPg db;
    std::string raw;
    {
        AuthManager mgr_a;
        mgr_a.set_auth_db(db.get());
        raw = mint(mgr_a, "crash-replay", 1, std::chrono::hours(1)).raw_token;
        auto claim = consume(mgr_a, raw, "agent-pre-crash");
        REQUIRE(claim.has_value());
        REQUIRE(claim->kind == ConsumeEnrollResult::Kind::enrolled);
        REQUIRE(mgr_a.add_pending_agent("queued", "h", "linux", "x86_64", "0.1.0").value());
        REQUIRE(mgr_a.add_pending_agent("refused", "h", "linux", "x86_64", "0.1.0").value());
        REQUIRE(mgr_a.deny_pending_agent("refused", "admin").value());
    }
    AuthManager mgr_b;
    mgr_b.set_auth_db(db.get());
    auto tokens = mgr_b.list_enrollment_tokens();
    REQUIRE(tokens.has_value());
    REQUIRE(tokens->size() == 1);
    CHECK((*tokens)[0].use_count == 1);
    CHECK(**mgr_b.get_pending_status("agent-pre-crash") == PendingStatus::approved);
    CHECK(**mgr_b.get_pending_status("queued") == PendingStatus::pending);
    CHECK(**mgr_b.get_pending_status("refused") == PendingStatus::denied);

    // Replay against the fresh instance: token exhausted, agent already enrolled.
    auto replay = consume(mgr_b, raw, "agent-post-crash");
    REQUIRE(replay.has_value());
    CHECK(replay->kind == ConsumeEnrollResult::Kind::token_rejected);
    CHECK(replay->token_error == EnrollmentTokenError::already_consumed);
}

// ── Pending Agents ───────────────────────────────────────────────────────────

TEST_CASE("pending agent lifecycle", "[auth][pending][pg]") {
    EnrollFixture f;
    CHECK(f.mgr.add_pending_agent("agent-1", "host1", "linux", "x86_64", "0.1.0").value() == true);
    // A second add for the same agent is not "newly added".
    CHECK(f.mgr.add_pending_agent("agent-1", "host1", "linux", "x86_64", "0.1.0").value() == false);

    auto status = f.mgr.get_pending_status("agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    REQUIRE(**status == PendingStatus::pending);

    REQUIRE(f.mgr.approve_pending_agent("agent-1", "alice").value());
    status = f.mgr.get_pending_status("agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    REQUIRE(**status == PendingStatus::approved);
    CHECK_FALSE(f.mgr.approve_pending_agent("ghost", "alice").value());
}

TEST_CASE("deny pending agent", "[auth][pending][pg]") {
    EnrollFixture f;
    f.mgr.add_pending_agent("agent-2", "host2", "windows", "x86_64", "0.1.0").value();
    REQUIRE(f.mgr.deny_pending_agent("agent-2", "bob").value());
    auto status = f.mgr.get_pending_status("agent-2");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    REQUIRE(**status == PendingStatus::denied);
    // ensure_enrolled never overrides an admin denial.
    CHECK_FALSE(f.mgr.ensure_enrolled("agent-2", "host2", "windows", "x86_64", "0.1.0", "auto").value());
}

TEST_CASE("remove pending agent", "[auth][pending][pg]") {
    EnrollFixture f;
    f.mgr.add_pending_agent("agent-3", "host3", "linux", "arm64", "0.1.0").value();
    REQUIRE(f.mgr.remove_pending_agent("agent-3").value() == RemovePendingOutcome::removed);
    auto status = f.mgr.get_pending_status("agent-3");
    REQUIRE(status.has_value());
    REQUIRE_FALSE(status->has_value()); // absent
    // A second remove of the now-absent row is not_found, not removed again.
    REQUIRE(f.mgr.remove_pending_agent("agent-3").value() == RemovePendingOutcome::not_found);
}

TEST_CASE("remove pending agent refuses a denied or approved row", "[auth][pending][pg]") {
    EnrollFixture f;
    f.mgr.add_pending_agent("agent-4", "host4", "linux", "arm64", "0.1.0").value();
    REQUIRE(f.mgr.deny_pending_agent("agent-4", "alice").value());
    // Removing the DENIED row is refused — the denial holds (governance
    // Finding 1: it would otherwise delete the guard kEnrollUpsertSql's
    // `WHERE status <> 'denied'` depends on, with no audit trail).
    REQUIRE(f.mgr.remove_pending_agent("agent-4").value() == RemovePendingOutcome::wrong_status);
    auto status = f.mgr.get_pending_status("agent-4");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    REQUIRE(**status == PendingStatus::denied);

    f.mgr.add_pending_agent("agent-5", "host5", "linux", "arm64", "0.1.0").value();
    REQUIRE(f.mgr.approve_pending_agent("agent-5", "alice").value());
    // Removing the APPROVED row is refused too — no silent deregistration.
    REQUIRE(f.mgr.remove_pending_agent("agent-5").value() == RemovePendingOutcome::wrong_status);
    status = f.mgr.get_pending_status("agent-5");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    REQUIRE(**status == PendingStatus::approved);
}

TEST_CASE("list_pending_agents", "[auth][pending][pg]") {
    EnrollFixture f;
    f.mgr.add_pending_agent("a1", "h1", "linux", "x86_64", "0.1.0").value();
    f.mgr.add_pending_agent("a2", "h2", "windows", "x86_64", "0.1.0").value();
    auto agents = f.mgr.list_pending_agents();
    REQUIRE(agents.has_value());
    REQUIRE(agents->size() == 2);
}

// ── Fail-closed: no AuthDB attached (shutdown / never wired) ─────────────────

TEST_CASE("enrollment/pending methods fail CLOSED with no AuthDB attached",
          "[auth][enrollment][pending][failclosed]") {
    // server.cpp calls set_auth_db(nullptr) at shutdown while a Register may
    // still be in flight: it must get a typed store-unavailable, never an
    // empty/absent/rejected value (#3401).
    AuthManager mgr; // no set_auth_db
    auto unavailable = [](const auto& r) {
        return !r.has_value() && r.error() == StoreError::Unavailable;
    };
    CHECK(unavailable(mgr.create_enrollment_token("l", 1, std::chrono::hours(1), "tester")));
    CHECK(unavailable(mgr.consume_and_enroll(std::string(64, 'a'), "a", "h", "linux", "x", "1")));
    CHECK(unavailable(mgr.list_enrollment_tokens()));
    CHECK(unavailable(mgr.revoke_enrollment_token("deadbeef")));
    CHECK(unavailable(mgr.add_pending_agent("a", "h", "linux", "x", "1")));
    CHECK(unavailable(mgr.ensure_enrolled("a", "h", "linux", "x", "1", "by")));
    CHECK(unavailable(mgr.get_pending_status("a")));
    CHECK(unavailable(mgr.list_pending_agents()));
    CHECK(unavailable(mgr.approve_pending_agent("a", "p")));
    CHECK(unavailable(mgr.deny_pending_agent("a", "p")));
    CHECK(unavailable(mgr.remove_pending_agent("a")));
    CHECK(yuzu::server::is_store_unavailable(StoreError::Unavailable));
    CHECK_FALSE(yuzu::server::is_store_unavailable(StoreError::InvalidInput));
}

TEST_CASE("enrollment store failures are counted in yuzu_auth_enrollment_store_degrade_total",
          "[auth][enrollment][pending][failclosed]") {
    yuzu::MetricsRegistry metrics;
    AuthManager mgr;
    mgr.set_metrics_registry(&metrics);

    // No store attached -> reason=no_store.
    CHECK_FALSE(mgr.get_pending_status("a").has_value());
    CHECK(metrics.counter("yuzu_auth_enrollment_store_degrade_total",
                          {{"op", "pending_status"}, {"reason", "no_store"}})
              .value() == 1.0);

    // A query that RUNS and fails -> reason=query_error; bad INPUT is not a degrade.
    yuzu::test::AuthDbPg db;
    mgr.set_auth_db(db.get());
    {
        auto lease = db.pool().try_acquire_for(std::chrono::seconds(2));
        REQUIRE(lease);
        REQUIRE(yuzu::server::pg::exec_params(lease.get(), "DROP TABLE auth.pending_agents",
                                              std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
    }
    auto broken = mgr.get_pending_status("a");
    REQUIRE_FALSE(broken.has_value());
    CHECK(broken.error() == StoreError::QueryFailed);
    CHECK(metrics.counter("yuzu_auth_enrollment_store_degrade_total",
                          {{"op", "pending_status"}, {"reason", "query_error"}})
              .value() == 1.0);
    auto bad = mgr.approve_pending_agent("", "p");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error() == StoreError::InvalidInput);
    CHECK(metrics.counter("yuzu_auth_enrollment_store_degrade_total",
                          {{"op", "approve"}, {"reason", "query_error"}})
              .value() == 0.0);
}

// ── Config Persistence ───────────────────────────────────────────────────────

TEST_CASE("save and reload config preserves users", "[auth][config]") {
    auto tmp = yuzu::test::unique_temp_path("yuzu-test-auth-roundtrip-");
    tmp += ".cfg";
    fs::create_directories(tmp.parent_path());
    fs::remove(tmp);

    {
        AuthManager mgr;
        mgr.load_config(tmp);
        mgr.upsert_user("alice", "password1pass", Role::admin);
        mgr.upsert_user("bob", "password2pass", Role::user);
        REQUIRE(mgr.save_config());
    }

    {
        AuthManager mgr;
        REQUIRE(mgr.load_config(tmp));
        auto users = mgr.list_users();
        REQUIRE(users.size() == 2);

        // Verify we can still authenticate
        REQUIRE(mgr.authenticate("alice", "password1pass").has_value());
        REQUIRE(mgr.authenticate("bob", "password2pass").has_value());
    }

    fs::remove(tmp);
}
