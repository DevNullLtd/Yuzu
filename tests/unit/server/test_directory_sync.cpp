/**
 * test_directory_sync.cpp -- Unit tests for DirectorySync (ADR-0063,
 * migration-programme PR 3: SQLite directory-sync.db -> Postgres schema
 * `directory_sync`).
 *
 * Covers: open/migrate, store_user/group/membership (exercised via
 * apply_entra_sync -- the sole production call path; store_user/group/
 * membership/clear_memberships/store_memberships_bulk are file-local .cpp
 * helpers with no header declaration, mirroring how OffloadTargetStore's own
 * row_to_target is exercised only indirectly through its public API),
 * configure/remove_group_role_mapping, the group-role-mapping-preservation
 * regression test standing in for the SQLite-era self-deadlock fix (see
 * directory_sync.hpp's file header), get_synced_users's bulk membership
 * resolution (replacing the SQLite-era per-user N+1), the FK + ON DELETE
 * CASCADE added by this port, the non-user-member filter that keeps a Graph
 * device/service-principal id from aborting a sync via a foreign-key
 * violation, fetch_paginated's @odata.nextLink pagination and its
 * malformed-later-page hard-error (security review, 2026-08-29 -- against a
 * real local httplib::Server standing in for Graph, mirroring
 * test_nvd.cpp's LocalNvdServer pattern), and the closed-store degrade
 * contract.
 *
 * The Microsoft Graph OAuth2 token flow and the WinHTTP path are untouched
 * by this migration and are NOT exercised here. fetch_paginated (and, via
 * it, apply_entra_sync) IS exercised against a real local HTTP server --
 * apply_entra_sync is the seam this port introduced specifically so the
 * previously-deadlocking SQL-application logic is testable without a
 * live/stubbed Graph endpoint (friended via DirectorySyncTestAccess,
 * mirroring RbacStoreTestAccess's precedent in test_rbac_store.cpp).
 *
 * PG-gated ([pg] tag): skips when YUZU_TEST_POSTGRES_DSN is unset, fails
 * when it is set but broken (docs/postgres-store-playbook.md §7).
 */

#include "directory_sync.hpp"
#include "discovery_routes.hpp"
#include "integrations_sync_routes.hpp"
#include "test_route_sink.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_directory_sync_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
using yuzu::test::DirectorySyncPg;

namespace yuzu::server {

// Test-only friend seam (mirrors RbacStoreTestAccess in test_rbac_store.cpp)
// so the previously-deadlocking apply_entra_sync logic, and update_status,
// are directly testable without a live/stubbed Graph HTTP endpoint.
struct DirectorySyncTestAccess {
    DirectorySync& store;

    using EntraSyncData = DirectorySync::EntraSyncData;

    std::expected<void, std::string> apply_entra_sync(const EntraSyncData& data) {
        return store.apply_entra_sync(data);
    }
    void update_status(const std::string& provider, const std::string& status,
                       int user_count = 0, int group_count = 0,
                       const std::string& error = {}) {
        store.update_status(provider, status, user_count, group_count, error);
    }
    std::expected<void, std::string> fetch_paginated(
        const std::string& initial_url, const std::string& bearer_token,
        const std::function<void(const nlohmann::json&)>& on_item) {
        return store.fetch_paginated(initial_url, bearer_token, on_item);
    }
};

} // namespace yuzu::server

namespace {

DirectoryUser make_user(std::string id, std::string display_name, std::string email = "",
                        std::string upn = "") {
    DirectoryUser u;
    u.id = std::move(id);
    u.display_name = std::move(display_name);
    u.email = std::move(email);
    u.upn = std::move(upn);
    u.enabled = true;
    u.synced_at = 1000;
    return u;
}

DirectoryGroup make_group(std::string id, std::string display_name) {
    DirectoryGroup g;
    g.id = std::move(id);
    g.display_name = std::move(display_name);
    g.synced_at = 1000;
    return g;
}

} // namespace

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("DirectorySync[pg]: opens and migrates", "[directory_sync][pg]") {
    DirectorySyncPg store;
    REQUIRE(store->is_open());
}

// ── apply_entra_sync: stores users, groups, and memberships ────────────────

TEST_CASE("DirectorySync[pg]: apply_entra_sync stores users, groups, and memberships",
          "[directory_sync][pg]") {
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    DirectorySyncTestAccess::EntraSyncData data;
    data.users.push_back(make_user("u1", "Alice", "alice@example.com", "alice@example.com"));
    data.users.push_back(make_user("u2", "Bob", "bob@example.com", "bob@example.com"));
    data.groups.push_back(make_group("g1", "Engineering"));
    data.groups.push_back(make_group("g2", "Sales"));
    data.memberships["g1"] = {"u1", "u2"};
    data.memberships["g2"] = {"u2"};

    auto result = acc.apply_entra_sync(data);
    REQUIRE(result.has_value());

    auto users = store->get_synced_users();
    REQUIRE(users.size() == 2);

    auto groups = store->get_synced_groups();
    REQUIRE(groups.size() == 2);

    auto alice = store->get_user("u1");
    REQUIRE(alice.has_value());
    CHECK(alice->display_name == "Alice");
    REQUIRE(alice->groups.size() == 1);
    CHECK(alice->groups[0] == "Engineering");

    auto bob = store->get_user("u2");
    REQUIRE(bob.has_value());
    REQUIRE(bob->groups.size() == 2);
    CHECK(std::find(bob->groups.begin(), bob->groups.end(), "Engineering") != bob->groups.end());
    CHECK(std::find(bob->groups.begin(), bob->groups.end(), "Sales") != bob->groups.end());
}

// ── get_synced_users: bulk group-membership resolution (fixes the SQLite
//    era's per-user N+1 query) ───────────────────────────────────────────────

TEST_CASE("DirectorySync[pg]: get_synced_users resolves groups for every matched user",
          "[directory_sync][pg]") {
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    DirectorySyncTestAccess::EntraSyncData data;
    for (int i = 0; i < 5; ++i)
        data.users.push_back(make_user("u" + std::to_string(i), "User " + std::to_string(i)));
    data.groups.push_back(make_group("g1", "Everyone"));
    data.memberships["g1"] = {"u0", "u1", "u2", "u3", "u4"};
    REQUIRE(acc.apply_entra_sync(data).has_value());

    auto users = store->get_synced_users();
    REQUIRE(users.size() == 5);
    for (const auto& u : users) {
        REQUIRE(u.groups.size() == 1);
        CHECK(u.groups[0] == "Everyone");
    }

    auto filtered = store->get_synced_users("g1");
    CHECK(filtered.size() == 5);

    auto none = store->get_synced_users("no-such-group");
    CHECK(none.empty());
}

// ── Non-user membership filter (avoids a foreign-key violation aborting the
//    whole sync when Graph returns a device/service-principal id) ──────────

TEST_CASE("DirectorySync[pg]: apply_entra_sync drops non-user membership ids instead of failing",
          "[directory_sync][pg]") {
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    DirectorySyncTestAccess::EntraSyncData data;
    data.users.push_back(make_user("u1", "Alice"));
    data.groups.push_back(make_group("g1", "Engineering"));
    // "device-1" is not in data.users -- simulates Graph returning a device
    // or service-principal id in /groups/{id}/members. Must not FK-violate.
    data.memberships["g1"] = {"u1", "device-1"};

    auto result = acc.apply_entra_sync(data);
    REQUIRE(result.has_value());

    auto alice = store->get_user("u1");
    REQUIRE(alice.has_value());
    REQUIRE(alice->groups.size() == 1);
    CHECK(alice->groups[0] == "Engineering");
}

// ── Stale-identity deletion (adversarial review, 2026-08-28: the SQLite era
//    never deleted a user/group Entra had removed either, but this port's
//    own "complete snapshot" framing requires actually doing so now) ───────

TEST_CASE("DirectorySync[pg]: apply_entra_sync deletes users and groups no longer in the snapshot",
          "[directory_sync][pg]") {
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    DirectorySyncTestAccess::EntraSyncData first;
    first.users.push_back(make_user("u1", "Alice"));
    first.users.push_back(make_user("u2", "Bob"));
    first.groups.push_back(make_group("g1", "Engineering"));
    first.groups.push_back(make_group("g2", "Sales"));
    first.memberships["g1"] = {"u1", "u2"};
    first.memberships["g2"] = {"u2"};
    REQUIRE(acc.apply_entra_sync(first).has_value());

    REQUIRE(store->get_user("u1").has_value());
    REQUIRE(store->get_user("u2").has_value());
    REQUIRE(store->get_synced_groups().size() == 2);

    // Entra deletes u2 and g2 -- the next sync's snapshot only names u1/g1.
    DirectorySyncTestAccess::EntraSyncData second;
    second.users.push_back(make_user("u1", "Alice"));
    second.groups.push_back(make_group("g1", "Engineering"));
    second.memberships["g1"] = {"u1"};
    REQUIRE(acc.apply_entra_sync(second).has_value());

    CHECK(store->get_user("u1").has_value());
    CHECK_FALSE(store->get_user("u2").has_value());

    auto groups = store->get_synced_groups();
    REQUIRE(groups.size() == 1);
    CHECK(groups[0].id == "g1");
}

TEST_CASE("DirectorySync[pg]: apply_entra_sync with an empty snapshot deletes every user and group",
          "[directory_sync][pg]") {
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    DirectorySyncTestAccess::EntraSyncData first;
    first.users.push_back(make_user("u1", "Alice"));
    first.groups.push_back(make_group("g1", "Engineering"));
    first.memberships["g1"] = {"u1"};
    REQUIRE(acc.apply_entra_sync(first).has_value());
    REQUIRE(store->get_synced_users().size() == 1);
    REQUIRE(store->get_synced_groups().size() == 1);

    // A well-formed "tenant genuinely has zero users/groups" snapshot -- the
    // fetch phase (sync_entra) only ever reaches apply_entra_sync with an
    // empty EntraSyncData when the Graph "value" array was well-formed and
    // actually empty, never on a malformed/missing response (both users and
    // groups hard-error before this point on that shape).
    DirectorySyncTestAccess::EntraSyncData empty;
    REQUIRE(acc.apply_entra_sync(empty).has_value());

    CHECK(store->get_synced_users().empty());
    CHECK(store->get_synced_groups().empty());
}

// ── Role-mapping preservation across a re-sync -- the regression test for
//    the SQLite-era self-deadlock fix (see directory_sync.hpp's file header:
//    the buggy nested-lock code reached for get_group_role_mappings() at
//    exactly this point). mapped_role has no column of its own on
//    directory_groups -- get_synced_groups() resolves it via LEFT JOIN
//    directory_group_role_mappings at read time (adversarial review,
//    2026-08-28: an earlier COALESCE-subselect-on-upsert design raced a
//    concurrent configure_group_role_mapping under READ COMMITTED,
//    empirically reproduced with a two-connection libpq test; the JOIN has
//    no window to race because there is no second copy of the value) ──────

TEST_CASE("DirectorySync[pg]: group role mapping survives a re-sync", "[directory_sync][pg]") {
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    DirectorySyncTestAccess::EntraSyncData first;
    first.groups.push_back(make_group("g1", "Engineering"));
    REQUIRE(acc.apply_entra_sync(first).has_value());

    store->configure_group_role_mapping("g1", "Operator");

    auto groups = store->get_synced_groups();
    REQUIRE(groups.size() == 1);
    CHECK(groups[0].mapped_role == "Operator");

    // Re-sync the same group id with a changed display_name (simulating a
    // fresh Graph snapshot on the next scheduled sync).
    DirectorySyncTestAccess::EntraSyncData second;
    second.groups.push_back(make_group("g1", "Engineering (renamed)"));
    REQUIRE(acc.apply_entra_sync(second).has_value());

    auto groups2 = store->get_synced_groups();
    REQUIRE(groups2.size() == 1);
    CHECK(groups2[0].display_name == "Engineering (renamed)");
    CHECK(groups2[0].mapped_role == "Operator");

    auto mappings = store->get_group_role_mappings();
    REQUIRE(mappings.count("g1") == 1);
    CHECK(mappings.at("g1") == "Operator");
}

// ── configure/remove_group_role_mapping: single-statement writes to the
//    mapping table, reflected through get_synced_groups()'s JOIN ──────────

TEST_CASE("DirectorySync[pg]: configure_group_role_mapping updates mapping, reflected via JOIN",
          "[directory_sync][pg]") {
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    DirectorySyncTestAccess::EntraSyncData data;
    data.groups.push_back(make_group("g1", "Engineering"));
    REQUIRE(acc.apply_entra_sync(data).has_value());

    store->configure_group_role_mapping("g1", "Administrator");
    auto groups = store->get_synced_groups();
    REQUIRE(groups.size() == 1);
    CHECK(groups[0].mapped_role == "Administrator");
    auto mappings = store->get_group_role_mappings();
    REQUIRE(mappings.count("g1") == 1);
    CHECK(mappings.at("g1") == "Administrator");

    store->remove_group_role_mapping("g1");
    auto groups2 = store->get_synced_groups();
    REQUIRE(groups2.size() == 1);
    CHECK(groups2[0].mapped_role.empty());
    auto mappings2 = store->get_group_role_mappings();
    CHECK(mappings2.count("g1") == 0);
}

// ── FK ON DELETE CASCADE (new in this port -- the SQLite era had none) ─────

TEST_CASE("DirectorySync[pg]: deleting a user cascades to its memberships",
          "[directory_sync][pg]") {
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    DirectorySyncTestAccess::EntraSyncData data;
    data.users.push_back(make_user("u1", "Alice"));
    data.groups.push_back(make_group("g1", "Engineering"));
    data.memberships["g1"] = {"u1"};
    REQUIRE(acc.apply_entra_sync(data).has_value());

    REQUIRE(store->get_synced_users("g1").size() == 1);

    auto lease = store.pool().acquire();
    REQUIRE(lease);
    pg::PgResult del = pg::exec_params(lease.get(),
                                       "DELETE FROM directory_sync.directory_users WHERE id = $1",
                                       std::vector<std::string>{"u1"});
    REQUIRE(del.ok());

    CHECK(store->get_synced_users("g1").empty());
    CHECK_FALSE(store->get_user("u1").has_value());
}

// ── update_status / get_status ──────────────────────────────────────────────

TEST_CASE("DirectorySync[pg]: update_status is reflected by get_status", "[directory_sync][pg]") {
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    auto initial = store->get_status();
    CHECK(initial.provider == "entra");
    CHECK(initial.status == "idle");

    acc.update_status("entra", "running");
    auto running = store->get_status();
    CHECK(running.status == "running");

    acc.update_status("entra", "completed", 3, 2);
    auto completed = store->get_status();
    CHECK(completed.status == "completed");
    CHECK(completed.user_count == 3);
    CHECK(completed.group_count == 2);
    CHECK(completed.last_error.empty());

    acc.update_status("entra", "failed", 0, 0, "graph unreachable");
    auto failed = store->get_status();
    CHECK(failed.status == "failed");
    CHECK(failed.last_error == "graph unreachable");
}

TEST_CASE("DirectorySync[pg]: checked reads succeed on an open store and never-synced is a value",
          "[directory_sync][pg]") {
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    // No status row yet: a legitimate answer, not an error.
    auto never = store->get_status_checked();
    REQUIRE(never.has_value());
    CHECK(never->status == "idle");
    CHECK(never->last_sync_at == 0);
    REQUIRE(store->get_synced_users_checked().has_value());
    CHECK(store->get_synced_users_checked()->empty());
    REQUIRE(store->get_synced_user_count_checked().has_value());
    CHECK(*store->get_synced_user_count_checked() == 0);

    DirectorySyncTestAccess::EntraSyncData data;
    data.users.push_back(make_user("u1", "Alice"));
    data.users.push_back(make_user("u2", "Bob"));
    data.groups.push_back(make_group("g1", "Engineering"));
    data.memberships["g1"] = {"u1"};
    REQUIRE(acc.apply_entra_sync(data).has_value());

    CHECK(*store->get_synced_user_count_checked() == 2);
    REQUIRE(store->get_synced_groups_checked().has_value());
    CHECK(store->get_synced_groups_checked()->size() == 1);
    CHECK(store->get_synced_users_checked()->size() == 2);
    // `limit` caps the rows read (the Integrations users fragment asks for a page).
    auto one = store->get_synced_users_checked({}, 1);
    REQUIRE(one.has_value());
    CHECK(one->size() == 1);
    auto g1 = store->get_synced_users_checked("g1", 5);
    REQUIRE(g1.has_value());
    REQUIRE(g1->size() == 1);
    CHECK(g1->front().groups.size() == 1);

    // A failed sync's status row carries counts of a snapshot that was never
    // stored; the snapshot count must not follow it.
    acc.update_status("entra", "failed", 9999, 9999, "graph unreachable");
    CHECK(store->get_status_checked()->user_count == 9999);
    CHECK(*store->get_synced_user_count_checked() == 2);
}

// ── sync_entra / sync_ldap: pure-logic branches (no HTTP reached) ──────────

TEST_CASE("DirectorySync[pg]: sync_entra rejects an incomplete Entra config",
          "[directory_sync][pg]") {
    DirectorySyncPg store;
    EntraConfig cfg; // every field empty
    auto result = store->sync_entra(cfg);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("tenant_id") != std::string::npos);
}

TEST_CASE("DirectorySync[pg]: sync_entra refuses a concurrent call while one is in progress",
          "[directory_sync][pg]") {
    // ADR-1007. Deterministic via the test-only hook rather than a raw
    // thread race (external review, 2026-08-31): the hook fires
    // synchronously right after the re-entrancy guard is won, BEFORE any
    // network call, so the mutual-exclusion ASSERTION below never depends on
    // network I/O. The background thread, once released, does go on to make
    // a real (bound-to-fail, fake credentials) HTTPS call to Microsoft's
    // token endpoint — acquire_token has no injectable base URL (unlike
    // fetch_paginated's LocalGraphServer seam above, out of scope to add
    // here) — but `client.set_connection_timeout(10)`/`set_read_timeout(15)`
    // in acquire_token bound that call, and `first_call.join()` below waits
    // for it rather than detaching (cpp-safety's unjoined-thread floor), so
    // this test has a bounded, not unbounded, worst case.
    DirectorySyncPg store;
    EntraConfig cfg;
    cfg.tenant_id = "11111111-1111-1111-1111-111111111111";
    cfg.client_id = "22222222-2222-2222-2222-222222222222";
    cfg.client_secret = "not-a-real-secret";

    std::promise<void> guard_acquired;
    std::future<void> guard_acquired_future = guard_acquired.get_future();
    std::promise<void> release_first_call;
    std::future<void> release_first_call_future = release_first_call.get_future();

    store->test_hook_after_entra_guard_acquired_ = [&] {
        guard_acquired.set_value();
        release_first_call_future.wait();
    };

    std::thread first_call([&] {
        auto result = store->sync_entra(cfg); // will fail downstream (fake creds) — irrelevant
        (void)result;
    });

    guard_acquired_future.wait();
    // The first call now holds the guard, parked in the hook. A second call
    // MUST be refused immediately — this is the actual assertion, and it
    // does not touch the network at all.
    auto second_result = store->sync_entra(cfg);
    REQUIRE_FALSE(second_result.has_value());
    CHECK(second_result.error() == "sync already in progress");

    // Gate 3 cpp-safety NICE: release the hook body BEFORE clearing the
    // std::function that holds it — resetting it to nullptr while
    // first_call may still be mid-execution of the hook's own body (parked
    // on the wait() just above) destroys the callable's target during its
    // own call. Benign here (a trivially-destructible lambda touching
    // nothing after wait() returns) but the correct order is release then
    // join then reset, not reset-before-release.
    release_first_call.set_value();
    first_call.join(); // never detached — cpp-safety's unjoined-thread floor
    store->test_hook_after_entra_guard_acquired_ = nullptr;

    // The guard must have been released (RAII) once the first call finished,
    // whatever its outcome — a third call is not busy.
    auto third_result = store->sync_entra(cfg);
    if (!third_result.has_value())
        CHECK(third_result.error() != "sync already in progress");
}

TEST_CASE("DirectorySync[pg]: sync_ldap reports not-yet-implemented", "[directory_sync][pg]") {
    DirectorySyncPg store;
    LdapConfig cfg;
    cfg.server = "ldap.example.com";
    auto result = store->sync_ldap(cfg);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("not yet implemented") != std::string::npos);
}

// ── fetch_paginated: @odata.nextLink pagination (security review, 2026-08-29)
//    -- a tenant with >999 users/groups/members silently lost every entity
//    past page 1, which apply_entra_sync's stale-row deletion then treated
//    as "deleted in Entra". Mirrors test_nvd.cpp's LocalNvdServer pattern: a
//    real httplib::Server on an OS-assigned ephemeral port (no fixed port,
//    no shared-runner collision) standing in for Microsoft Graph. ────────────

namespace {
// Bring up a Graph-shaped server on 127.0.0.1:<ephemeral>. Binds first (so
// the port is known) and exposes url() for handlers to embed a
// self-referential @odata.nextLink; routes are registered by the caller,
// start() begins listening once every route is in place.
struct LocalGraphServer {
    httplib::Server svr;
    int port = 0;
    std::thread th;
    explicit LocalGraphServer() {
        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0); // bind failed -> fail loudly, don't spin forever below
    }
    std::string url(const std::string& path) const {
        return "http://127.0.0.1:" + std::to_string(port) + path;
    }
    void start() {
        th = std::thread([this] { svr.listen_after_bind(); });
        for (int i = 0; i < 2000 && !svr.is_running(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        REQUIRE(svr.is_running());
    }
    ~LocalGraphServer() {
        svr.stop();
        if (th.joinable())
            th.join();
    }
};
} // namespace

TEST_CASE("DirectorySync[pg]: fetch_paginated follows @odata.nextLink across pages",
          "[directory_sync][pg]") {
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    LocalGraphServer server;
    std::atomic<int> page1_hits{0};
    std::atomic<int> page2_hits{0};
    server.svr.Get("/users", [&](const httplib::Request&, httplib::Response& res) {
        ++page1_hits;
        res.set_content(
            R"({"value":[{"id":"u1"},{"id":"u2"}],"@odata.nextLink":")" +
                server.url("/users/page2") + R"("})",
            "application/json");
    });
    server.svr.Get("/users/page2", [&](const httplib::Request&, httplib::Response& res) {
        ++page2_hits;
        res.set_content(R"({"value":[{"id":"u3"}]})", "application/json");
    });
    server.start();

    std::vector<std::string> seen_ids;
    auto result = acc.fetch_paginated(server.url("/users"), "fake-token",
                                      [&seen_ids](const nlohmann::json& item) {
        seen_ids.push_back(item.value("id", ""));
    });

    REQUIRE(result.has_value());
    CHECK(page1_hits.load() == 1);
    CHECK(page2_hits.load() == 1); // the second page was actually fetched, not just the first
    CHECK(seen_ids == std::vector<std::string>{"u1", "u2", "u3"});
}

TEST_CASE("DirectorySync[pg]: fetch_paginated hard-errors on a malformed later page",
          "[directory_sync][pg]") {
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    LocalGraphServer server;
    std::atomic<int> page2_hits{0};
    server.svr.Get("/users", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(
            R"({"value":[{"id":"u1"}],"@odata.nextLink":")" + server.url("/users/page2") +
                R"("})",
            "application/json");
    });
    server.svr.Get("/users/page2", [&](const httplib::Request&, httplib::Response& res) {
        ++page2_hits;
        // Malformed -- no "value" array. A naive per-page apply would read
        // this as "the tenant now has zero more users", not as a fetch
        // failure; fetch_paginated must abort the whole fetch instead,
        // matching the single-page contract (security review, 2026-08-29).
        res.set_content(R"({"unexpected":"shape"})", "application/json");
    });
    server.start();

    std::vector<std::string> seen_ids;
    auto result = acc.fetch_paginated(server.url("/users"), "fake-token",
                                      [&seen_ids](const nlohmann::json& item) {
        seen_ids.push_back(item.value("id", ""));
    });

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("value") != std::string::npos);
    CHECK(page2_hits.load() == 1); // page 2 really was attempted, not a first-page-only fetch
}

TEST_CASE("DirectorySync[pg]: fetch_paginated hard-errors on a non-string @odata.nextLink",
          "[directory_sync][pg]") {
    // A malformed-but-PRESENT nextLink (cpp-expert review, 2026-08-30) is a
    // distinct failure shape from an absent one: "absent" means legitimate
    // end of pagination, "present but not a string" means the response is
    // corrupt. An earlier version of this fix conflated the two (both took
    // the `return {}` success path), silently truncating the fetch via the
    // exact same channel the pagination fix itself was meant to close.
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    LocalGraphServer server;
    std::atomic<int> hits{0};
    server.svr.Get("/users", [&](const httplib::Request&, httplib::Response& res) {
        ++hits;
        res.set_content(R"({"value":[{"id":"u1"}],"@odata.nextLink":12345})",
                        "application/json");
    });
    server.start();

    std::vector<std::string> seen_ids;
    auto result = acc.fetch_paginated(server.url("/users"), "fake-token",
                                      [&seen_ids](const nlohmann::json& item) {
        seen_ids.push_back(item.value("id", ""));
    });

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("nextLink") != std::string::npos);
    CHECK(hits.load() == 1); // must not silently treat this as "done, one page"
}

TEST_CASE("DirectorySync[pg]: fetch_paginated hard-errors instead of throwing on a "
          "present-but-null field",
          "[directory_sync][pg]") {
    // unhappy-path review, 2026-08-30: nlohmann::json's .value<T>(key, default)
    // only substitutes `default` when `key` is ABSENT -- a PRESENT-but-null
    // field (e.g. a guest/unlicensed Entra user's "mail": null, near-certain
    // on any real tenant) makes it throw nlohmann::json::type_error instead.
    // Left uncaught, this escaped all the way to the route handler as a bare
    // HTTP 500, skipping every update_status(..., "failed", ...) call site --
    // this test proves it now surfaces as a std::unexpected instead.
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    LocalGraphServer server;
    server.svr.Get("/users", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"value":[{"id":"u1","mail":null}]})", "application/json");
    });
    server.start();

    auto result = acc.fetch_paginated(server.url("/users"), "fake-token",
                                      [](const nlohmann::json& item) {
        (void)item.value("mail", std::string{}); // throws on a null "mail", not absent
    });

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("malformed item") != std::string::npos);
}

TEST_CASE("DirectorySync[pg]: fetch_paginated refuses an @odata.nextLink pointing off-host",
          "[directory_sync][pg]") {
    // unhappy-path review, 2026-08-30, MEDIUM defense-in-depth: a
    // response-supplied nextLink is followed verbatim with the live bearer
    // token attached -- pin it to the initial request's own host so a
    // Graph response can never redirect the fetch (and the token) elsewhere.
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};

    LocalGraphServer server;
    std::atomic<int> hits{0};
    server.svr.Get("/users", [&](const httplib::Request&, httplib::Response& res) {
        ++hits;
        res.set_content(
            R"({"value":[{"id":"u1"}],"@odata.nextLink":"http://evil.example.com/steal"})",
            "application/json");
    });
    server.start();

    auto result = acc.fetch_paginated(server.url("/users"), "fake-token",
                                      [](const nlohmann::json&) {});

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("host") != std::string::npos);
    CHECK(hits.load() == 1); // must not have attempted the off-host request
}

// ── Closed-store degrade contract (mirrors the SQLite-era plain-container
//    contract -- see directory_sync.hpp's file header) ──────────────────────

TEST_CASE("DirectorySync[pg]: a closed store degrades to empty/default, never crashes",
          "[directory_sync][pg]") {
    yuzu::server::pg::PgPool bad_pool{
        {.conninfo = "this is not a valid postgres conninfo!!!", .size = 1}};
    REQUIRE_FALSE(bad_pool.valid());

    DirectorySync store{bad_pool};
    REQUIRE_FALSE(store.is_open());

    CHECK(store.get_synced_users().empty());
    CHECK_FALSE(store.get_user("u1").has_value());
    CHECK(store.get_synced_groups().empty());
    auto status = store.get_status();
    CHECK(status.provider == "entra");
    CHECK(status.status == "idle");
    CHECK(store.get_group_role_mappings().empty());
    CHECK(store.get_group_role_mappings_checked().error() == DirectoryReadError::store_unavailable);

    // The checked reads report the failure instead of the default value, so a
    // page can tell "could not read" from "never synced" / "no users".
    CHECK(store.get_status_checked().error() == DirectoryReadError::store_unavailable);
    CHECK(store.get_synced_users_checked().error() == DirectoryReadError::store_unavailable);
    CHECK(store.get_synced_groups_checked().error() == DirectoryReadError::store_unavailable);
    CHECK(store.get_synced_user_count_checked().error() == DirectoryReadError::store_unavailable);

    // Void mutators must not crash on a closed store.
    store.configure_group_role_mapping("g1", "Operator");
    store.remove_group_role_mapping("g1");

    DirectorySyncTestAccess acc{store};
    DirectorySyncTestAccess::EntraSyncData data;
    data.users.push_back(make_user("u1", "Alice"));
    auto apply_result = acc.apply_entra_sync(data);
    REQUIRE_FALSE(apply_result.has_value());
}

TEST_CASE("DirectorySync[pg]: a failed membership lookup fails the checked read and not the legacy one",
          "[directory_sync][pg]") {
    DirectorySyncPg store;
    DirectorySyncTestAccess acc{*store};
    DirectorySyncTestAccess::EntraSyncData data;
    data.users.push_back(make_user("u1", "Alice"));
    data.users.push_back(make_user("u2", "Bob"));
    data.groups.push_back(make_group("g1", "Engineering"));
    data.memberships["g1"] = {"u1"};
    REQUIRE(acc.apply_entra_sync(data).has_value());

    {
        auto lease = store.pool().acquire();
        REQUIRE(lease);
        REQUIRE(pg::exec_params(lease.get(), "DROP TABLE directory_sync.directory_memberships",
                                std::vector<std::string>{}).ok());
    }
    // Without the groups the users would read as members of nothing.
    auto strict = store->get_synced_users_checked({}, 5);
    REQUIRE_FALSE(strict.has_value());
    CHECK(strict.error() == DirectoryReadError::query_failed);
    // Callers that never asked for the strict contract keep the best-effort read.
    auto loose = store->get_synced_users_checked({}, 5, /*require_groups=*/false);
    REQUIRE(loose.has_value());
    CHECK(loose->size() == 2);
    CHECK(store->get_synced_users().size() == 2);

    // The Integrations adapter passes the limit through and maps the failure.
    auto deps = integrations::bind_stores(nullptr, nullptr, store.get(), nullptr);
    auto page = deps.directory_users(1);
    REQUIRE_FALSE(page.has_value());
    CHECK(page.error() == integrations::ReadError::failed);
}

namespace {
/// DiscoveryRoutes over a real DirectorySync with a capturing audit sink.
struct DirectoryRouteHarness {
    struct Row {
        std::string action, result, target_id, detail;
    };
    std::vector<Row> audits;   // outcome rows
    std::vector<Row> attempts; // the audit-first `attempted` rows, written before any change
    bool audit_persists{true}; // false: the audit sink reports a failed write
    std::string fail_result;   // non-empty: only rows with this result report a failed write
    DiscoveryRoutes routes;
    yuzu::server::test::TestRouteSink sink; // declared after what its handlers capture

    explicit DirectoryRouteHarness(DirectorySync* store) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "dir-admin";
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            (result == "attempted" ? attempts : audits).push_back({action, result, target_id, detail});
            if (!fail_result.empty() && result == fail_result)
                return false;
            return audit_persists;
        };
        auto resolve_fn = [](const httplib::Request&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "dir-admin";
            s.auth_source = "local"; // a cookie session, so the same-site gate applies
            return s;
        };
        sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};
        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, store, nullptr, nullptr, nullptr,
                               WriteGate{resolve_fn, {}});
    }
    auto put_mappings(const std::string& body) {
        return sink.Put("/api/directory/group-mappings", body, "application/json");
    }
};
} // namespace

TEST_CASE("DiscoveryRoutes[pg]: directory sync failures are audited with fixed non-secret details",
          "[directory_sync][pg][routes]") {
    DirectorySyncPg store;
    DirectoryRouteHarness h{store.get()};

    auto bad = h.sink.Post("/api/directory/sync", "{", "application/json");
    REQUIRE(bad);
    CHECK(bad->status == 400);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "directory.sync");
    CHECK(h.audits[0].result == "failure");
    CHECK(h.audits[0].detail == "invalid_json");

    auto missing = h.sink.Post("/api/directory/sync",
                               R"({"provider":"entra","tenant_id":"t","client_id":"c"})",
                               "application/json");
    REQUIRE(missing);
    CHECK(missing->status == 400);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].result == "failure");
    CHECK(h.audits[1].target_id == "entra");
    CHECK(h.audits[1].detail == "missing_credentials");
}

TEST_CASE("DiscoveryRoutes[pg]: group mapping audit records what is stored and not what was asked",
          "[directory_sync][pg][routes]") {
    DirectorySyncPg store;
    DirectoryRouteHarness h{store.get()};

    // Stored as asked: one success row naming the pair.
    auto ok = h.put_mappings(R"({"mappings":[{"group_id":"g1","role_name":"Operator"}]})");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "directory.group_mapping.update");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].detail == "1 mappings updated: g1=Operator");
    REQUIRE(h.attempts.size() == 1); // audit-first: written before the change, names the pairs
    CHECK(h.attempts[0].action == "directory.group_mapping.update");
    CHECK(h.attempts[0].detail == "1 mappings requested: g1=Operator");

    // A group named twice ends with its last entry: audited once, as stored.
    h.audits.clear();
    auto dup = h.put_mappings(R"({"mappings":[{"group_id":"g2","role_name":"bogus"},)"
                              R"({"group_id":"g2","role_name":"Administrator"}]})");
    REQUIRE(dup);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].detail == "1 mappings updated: g2=Administrator");

    // A removal that took effect is a success.
    h.audits.clear();
    REQUIRE(h.put_mappings(R"({"mappings":[{"group_id":"g1","role_name":""}]})"));
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].detail == "1 mappings updated: g1=(removed)");

    // Break the table: the writes are swallowed and the read-back fails too.
    {
        auto lease = store.pool().acquire();
        REQUIRE(lease);
        REQUIRE(pg::exec_params(lease.get(),
                                "DROP TABLE directory_sync.directory_group_role_mappings",
                                std::vector<std::string>{}).ok());
    }
    h.audits.clear();
    REQUIRE(h.put_mappings(R"({"mappings":[{"group_id":"g2","role_name":"Operator"}]})"));
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "failure");
    CHECK(h.audits[0].detail == "1 mappings not confirmed by read-back: g2=Operator");

    // A removal must not read as confirmed just because nothing could be read.
    h.audits.clear();
    REQUIRE(h.put_mappings(R"({"mappings":[{"group_id":"g2","role_name":""}]})"));
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "failure");
    CHECK(h.audits[0].detail == "1 mappings not confirmed by read-back: g2=(removed)");
}

TEST_CASE("DiscoveryRoutes[pg]: a large mapping request is audited in full and over several rows",
          "[directory_sync][pg][routes]") {
    DirectorySyncPg store;
    DirectoryRouteHarness h{store.get()};

    // Decoys ahead of the pair that matters must not push it out of the trail.
    nlohmann::json body = {{"mappings", nlohmann::json::array()}};
    for (int i = 0; i < 120; ++i)
        body["mappings"].push_back({{"group_id", "decoy-group-" + std::to_string(i)},
                                    {"role_name", "Operator"}});
    body["mappings"].push_back({{"group_id", "the-real-group"}, {"role_name", "Administrator"}});
    REQUIRE(h.put_mappings(body.dump()));

    REQUIRE(h.audits.size() > 1);
    bool found = false;
    std::size_t pairs = 0;
    for (const auto& a : h.audits) {
        CHECK(a.action == "directory.group_mapping.update");
        CHECK(a.result == "success");
        CHECK(a.detail.size() <= 1000);
        found = found || a.detail.find("the-real-group=Administrator") != std::string::npos;
        for (std::size_t at = 0; (at = a.detail.find('=', at)) != std::string::npos; ++at)
            ++pairs;
    }
    CHECK(found);
    CHECK(pairs == 121);
    // The audit-first row states the TOTAL asked for, not the size of its first chunk.
    REQUIRE(h.attempts.size() == 1);
    CHECK(h.attempts[0].detail.starts_with("121 mappings requested (first listed): decoy-group-0="));
}

TEST_CASE("DiscoveryRoutes[pg]: a malformed mapping entry refuses the whole batch and stores nothing",
          "[directory_sync][pg][routes][security]") {
    DirectorySyncPg store;
    DirectoryRouteHarness h{store.get()};

    // The bad entry comes LAST: a loop that wrote as it read would store g1 first.
    for (const char* body : {R"({"mappings":[{"group_id":"g1","role_name":"Operator"},"oops"]})",
                             R"({"mappings":[{"group_id":"g1","role_name":"Operator"},)"
                             R"({"group_id":7,"role_name":"Operator"}]})",
                             R"({"mappings":[{"group_id":"g1","role_name":"Operator"},)"
                             R"({"group_id":"g2","role_name":["x"]}]})"}) {
        INFO(body);
        auto res = h.put_mappings(body);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->get_header_value("X-Correlation-Id") != "");
        CHECK(h.attempts.empty()); // validated before the audit-first row
        CHECK(h.audits.empty());
        auto stored = store.get()->get_group_role_mappings_checked();
        REQUIRE(stored);
        CHECK(stored->empty());
    }
}

TEST_CASE("DiscoveryRoutes[pg]: mapping save and sync fail closed when the attempted row cannot be "
          "written (mutation: mutate before auditing)",
          "[directory_sync][pg][routes][security]") {
    DirectorySyncPg store;
    DirectoryRouteHarness h{store.get()};
    h.audit_persists = false;

    auto save = h.put_mappings(R"({"mappings":[{"group_id":"g1","role_name":"Operator"}]})");
    REQUIRE(save);
    CHECK(save->status == 503);
    CHECK(save->get_header_value("Sec-Audit-Failed") == "true");
    auto sync = h.sink.Post("/api/directory/sync",
                            R"({"provider":"entra","tenant_id":"t","client_id":"c","client_secret":"s"})",
                            "application/json");
    REQUIRE(sync);
    CHECK(sync->status == 503);
    CHECK(sync->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.audits.empty()); // nothing followed the attempted rows
    REQUIRE(h.attempts.size() == 2);
    CHECK(h.attempts[1].action == "directory.sync");
    CHECK(h.attempts[1].detail.empty()); // the credentials never reach the row
    auto stored = store.get()->get_group_role_mappings_checked();
    REQUIRE(stored);
    CHECK(stored->empty());
}

TEST_CASE("DiscoveryRoutes[pg]: a cross-site or header-less cookie write is refused 403",
          "[directory_sync][pg][routes][security]") {
    DirectorySyncPg store;
    DirectoryRouteHarness h{store.get()};
    using Hdrs = std::unordered_map<std::string, std::string>;
    for (const auto& headers : {Hdrs{{"Host", "yuzu.test"}, {"Origin", "https://evil.test"}},
                                Hdrs{{"Host", "yuzu.test"}}}) {
        h.sink.default_headers = headers;
        auto save = h.put_mappings(R"({"mappings":[{"group_id":"g1","role_name":"Operator"}]})");
        REQUIRE(save);
        CHECK(save->status == 403);
        auto sync = h.sink.Post("/api/directory/sync", R"({"provider":"entra"})", "application/json");
        REQUIRE(sync);
        CHECK(sync->status == 403);
    }
    CHECK(h.attempts.empty());
    auto stored = store.get()->get_group_role_mappings_checked();
    REQUIRE(stored);
    CHECK(stored->empty());
}

TEST_CASE("DiscoveryRoutes[pg]: a lost outcome row keeps the 2xx and marks Sec-Audit-Failed",
          "[directory_sync][pg][routes][security]") {
    DirectorySyncPg store;
    DirectoryRouteHarness h{store.get()};
    h.fail_result = "success";
    auto save = h.put_mappings(R"({"mappings":[{"group_id":"g1","role_name":"Operator"}]})");
    REQUIRE(save);
    CHECK(save->status == 200);
    CHECK(save->get_header_value("Sec-Audit-Failed") == "true");
    auto stored = store.get()->get_group_role_mappings_checked();
    REQUIRE(stored);
    CHECK(stored->size() == 1); // the change was made
}

TEST_CASE("DiscoveryRoutes[pg]: a lost failure row still marks Sec-Audit-Failed on a refused sync",
          "[directory_sync][pg][routes][security]") {
    DirectorySyncPg store;
    DirectoryRouteHarness h{store.get()};
    h.fail_result = "failure";
    auto missing = h.sink.Post("/api/directory/sync",
                               R"({"provider":"entra","tenant_id":"t","client_id":"c"})",
                               "application/json");
    REQUIRE(missing);
    CHECK(missing->status == 400);
    CHECK(missing->get_header_value("Sec-Audit-Failed") == "true");
}
