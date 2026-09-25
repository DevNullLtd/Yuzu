// HA WS-5 (ADR-2002 §7a) — cross-replica presence merge into
// AgentRegistry::all_ids()/evaluate_scope(). A live OfflineEndpointStore is
// the presence source; register_agent alone simulates the LOCAL registry, a
// direct OfflineEndpointStore::upsert() (with no matching register_agent)
// simulates an agent connected to a DIFFERENT replica.

#include <catch2/catch_test_macros.hpp>

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "offline_endpoint_store.hpp"
#include "pg/pg_pool.hpp"
#include "scope_engine.hpp"
#include "tag_store.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>

using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
using yuzu::server::OfflineEndpointStore;
using yuzu::server::TagStore;
using yuzu::server::pg::PgPool;

namespace agent_pb = ::yuzu::agent::v1;

namespace {

agent_pb::AgentInfo make_agent_info(const std::string& id, const std::string& os,
                                    const std::string& hostname) {
    agent_pb::AgentInfo a;
    a.set_agent_id(id);
    a.set_hostname(hostname);
    a.mutable_platform()->set_os(os);
    a.mutable_platform()->set_arch("x86_64");
    a.set_agent_version("0.13.0");
    return a;
}

yuzu::test::PgTestTemplate presence_tpl{"agent_presence", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    OfflineEndpointStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("agent_presence template: store failed to migrate");
}};

bool contains(const std::vector<std::string>& v, const std::string& id) {
    return std::find(v.begin(), v.end(), id) != v.end();
}

} // namespace

TEST_CASE("HA WS-5: all_ids() merges live presence for a remote-only agent", "[pg][ha][presence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, presence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(make_agent_info("local-agent", "linux", "local-host"));

    SECTION("unconfigured presence: byte-identical to pre-WS-5 local-only behavior") {
        REQUIRE(store.upsert("remote-agent", "remote-host", "windows",
                             /*last_heartbeat_ms=*/0, /*agent_ts=*/0, "1.0.0", "x86_64",
                             "sess-remote"));
        auto ids = registry.all_ids();
        CHECK(contains(ids, "local-agent"));
        CHECK_FALSE(contains(ids, "remote-agent")); // presence never consulted
        CHECK(registry.local_agent_count() == ids.size());
    }

    SECTION("configured presence: a remote-only live row is merged in") {
        registry.configure_presence(&store, std::chrono::hours(1));
        REQUIRE(store.upsert("remote-agent", "remote-host", "windows", 0, 0, "1.0.0", "x86_64",
                             "sess-remote"));
        auto ids = registry.all_ids();
        CHECK(contains(ids, "local-agent"));
        CHECK(contains(ids, "remote-agent"));
        // local_agent_count() never includes presence, by construction.
        CHECK(registry.local_agent_count() == 1);
        CHECK(ids.size() == 2);
    }

    SECTION("local always wins: an id in BOTH is never duplicated") {
        registry.configure_presence(&store, std::chrono::hours(1));
        REQUIRE(store.upsert("local-agent", "stale-host-from-presence", "windows", 0, 0, "9.9.9",
                             "arm64", "sess-x"));
        auto ids = registry.all_ids();
        CHECK(std::count(ids.begin(), ids.end(), "local-agent") == 1);
        CHECK(ids.size() == 1);
    }

    SECTION("presence outside the TTL window is not merged") {
        registry.configure_presence(&store, std::chrono::seconds(0));
        REQUIRE(store.upsert("remote-agent", "remote-host", "windows", 0, 0, "", "", ""));
        auto ids = registry.all_ids();
        CHECK_FALSE(contains(ids, "remote-agent"));
    }
}

TEST_CASE("HA WS-5: evaluate_scope resolves a remote-only agent's identity attributes",
          "[pg][ha][presence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, presence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.configure_presence(&store, std::chrono::hours(1));
    (void)registry.register_agent(make_agent_info("local-agent", "linux", "local-host"));
    REQUIRE(store.upsert("remote-agent", "remote-host", "windows", 0, 0, "2.0.0", "arm64",
                         "sess-remote"));

    SECTION("ostype matches the presence-sourced value") {
        auto parsed = yuzu::scope::parse(R"(ostype == "windows")");
        REQUIRE(parsed.has_value());
        auto matched = registry.evaluate_scope(*parsed, nullptr);
        REQUIRE(matched.has_value());
        CHECK(contains(*matched, "remote-agent"));
        CHECK_FALSE(contains(*matched, "local-agent"));
    }

    SECTION("hostname/arch/agent_version all resolve for a presence-only id") {
        auto parsed = yuzu::scope::parse(
            R"((hostname == "remote-host") AND (arch == "arm64") AND (agent_version == "2.0.0"))");
        REQUIRE(parsed.has_value());
        auto matched = registry.evaluate_scope(*parsed, nullptr);
        REQUIRE(matched.has_value());
        CHECK(contains(*matched, "remote-agent"));
    }

    SECTION("a predicate matching neither agent returns an empty (non-null) result") {
        auto parsed = yuzu::scope::parse(R"(hostname == "nobody-here")");
        REQUIRE(parsed.has_value());
        auto matched = registry.evaluate_scope(*parsed, nullptr);
        REQUIRE(matched.has_value());
        CHECK(matched->empty());
    }
}

// HA WS-5 governance hardening (Gate 3 quality-engineer finding, 2026-09-22):
// the code comment on the presence-only resolver in agent_registry.cpp
// claims "tag:/props. already resolve correctly for these ids" since the
// bulk preloads (tag_values/props_values) are id-keyed, not scoped to local
// agents_ — that claim was previously unverified by test. This closes the
// tag: half with a REAL TagStore (the store-first #3295 precedence path);
// props. would need a CustomPropertiesStore fixture this file doesn't
// otherwise need, so is left for a follow-up if this pattern proves useful
// elsewhere.
TEST_CASE("HA WS-5: evaluate_scope resolves tag:<key> for a remote-only agent via "
          "the store-first bulk preload",
          "[pg][ha][presence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, presence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());
    TagStore tag_store{pool};
    REQUIRE(tag_store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.configure_presence(&store, std::chrono::hours(1));
    (void)registry.register_agent(make_agent_info("local-agent", "linux", "local-host"));
    REQUIRE(store.upsert("remote-agent", "remote-host", "windows", 0, 0, "", "", "sess-remote"));
    REQUIRE(tag_store.set_tag("remote-agent", "department", "finance").has_value());

    auto parsed = yuzu::scope::parse(R"(tag:department == "finance")");
    REQUIRE(parsed.has_value());
    // tag_store passed this time (unlike the sibling TEST_CASE above, which
    // deliberately passes nullptr) — this is exactly the STORE-FIRST path
    // (agent_registry.cpp's `tag:` resolver branch), not the in-memory
    // scopable_tags fallback, which a presence-only id has no source for at
    // all (no AgentSession exists for it).
    auto matched = registry.evaluate_scope(*parsed, &tag_store);
    REQUIRE(matched.has_value());
    CHECK(contains(*matched, "remote-agent"));
    CHECK_FALSE(contains(*matched, "local-agent"));
}

// HA WS-5 governance hardening (Gate 3 performance finding, 2026-09-22):
// live_presence()'s cache must not re-fetch on every call within its TTL
// window, and must fetch again once stale.
TEST_CASE("HA WS-5: live_presence() caches within its TTL window", "[pg][ha][presence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, presence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.configure_presence(&store, std::chrono::hours(1));

    REQUIRE(store.upsert("cache-agent-1", "h", "linux", 0, 0, "", "", "sess-1"));
    auto ids_first = registry.all_ids();
    CHECK(contains(ids_first, "cache-agent-1"));

    // A row added AFTER the first (now-cached) read must NOT appear until
    // the cache window (3s) elapses — proves the second call is served from
    // cache, not a fresh Postgres read.
    REQUIRE(store.upsert("cache-agent-2", "h", "linux", 0, 0, "", "", "sess-2"));
    auto ids_second = registry.all_ids();
    CHECK_FALSE(contains(ids_second, "cache-agent-2"));

    // 6s against a 3s TTL — a wider margin than the original 4s (external
    // review finding, 2026-09-22: 1s of margin is tight under contended CI
    // load, e.g. the 20-way concurrent-shard contention already observed on
    // this PR's own CI runs). A fake-clock injection would be the more
    // robust fix; not done this round — this is a low-risk mitigation.
    std::this_thread::sleep_for(std::chrono::seconds(6));
    auto ids_after_ttl = registry.all_ids();
    CHECK(contains(ids_after_ttl, "cache-agent-2"));
}

TEST_CASE("HA WS-5: a graceful disconnect's remove_if_session prevents zero-monolith-outcome drift",
          "[pg][ha][presence]") {
    // Simulates the decoy-row shape the WS-4 slices held themselves to: once
    // an agent is gone from BOTH the local registry (simulated here by never
    // registering it) AND presence (remove_if_session already ran), it must
    // not be resolvable via evaluate_scope — exactly the pre-WS-5 behavior
    // for a disconnected agent.
    YUZU_REQUIRE_PG_DB_TPL(db, presence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.configure_presence(&store, std::chrono::hours(1));

    REQUIRE(store.upsert("departed-agent", "h", "linux", 0, 0, "", "", "sess-departed"));
    REQUIRE(store.remove_if_session("departed-agent", "sess-departed")); // the disconnect handler's call

    auto parsed = yuzu::scope::parse(R"(ostype == "linux")");
    REQUIRE(parsed.has_value());
    auto matched = registry.evaluate_scope(*parsed, nullptr);
    REQUIRE(matched.has_value());
    CHECK_FALSE(contains(*matched, "departed-agent"));
}

// External review hardening (2026-09-22, @Doomgoose) — 3 more BLOCKING bugs
// in the same "silently narrower dispatch target set" class, found after the
// first governance round. Direct coverage for the two AgentRegistry-level
// fixes (has_any_reachable, remove_agent_if_session's gated durable delete);
// forward_legacy_command's route_unreadable branch fix is HTTP-handler-level
// and shares the same already-tested dispatch_confined_arms machinery, so is
// not independently re-tested here.

TEST_CASE("HA WS-5: has_any_reachable() checks presence, unlike has_any()",
          "[pg][ha][presence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, presence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.configure_presence(&store, std::chrono::hours(1));

    SECTION("zero local, zero presence: both report false") {
        CHECK_FALSE(registry.has_any());
        CHECK_FALSE(registry.has_any_reachable());
    }

    SECTION("zero local, but presence shows a live remote agent: has_any() misses it, "
            "has_any_reachable() does not") {
        REQUIRE(store.upsert("remote-only", "h", "linux", 0, 0, "", "", "sess-remote"));
        CHECK_FALSE(registry.has_any());
        CHECK(registry.has_any_reachable());
    }

    SECTION("a local agent alone: both report true") {
        (void)registry.register_agent(make_agent_info("local-agent", "linux", "local-host"));
        CHECK(registry.has_any());
        CHECK(registry.has_any_reachable());
    }
}

TEST_CASE("HA WS-5: remove_agent_if_session reports whether it removed the CURRENT session",
          "[ha]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);

    // session_id is not part of AgentInfo — it's assigned server-side via
    // map_session() once the Subscribe handshake completes, mirroring
    // production (register_agent, then map_session).
    (void)registry.register_agent(make_agent_info("agent-x", "linux", "host-x"));
    registry.map_session("sess-1", "agent-x");

    SECTION("a matching session_id removes it and returns true") {
        CHECK(registry.remove_agent_if_session("agent-x", "sess-1"));
        CHECK_FALSE(registry.has_any());
    }

    SECTION("a stale/mismatched session_id no-ops and returns false — "
            "the exact case the durable-presence-delete gate depends on") {
        // Simulates: agent-x reconnects under a NEW session (sess-2) on the
        // SAME replica before sess-1's disconnect handler runs. sess-1's
        // late cleanup must not report "removed" (which would otherwise
        // trigger a durable presence delete for a still-live agent).
        (void)registry.register_agent(make_agent_info("agent-x", "linux", "host-x"));
        registry.map_session("sess-2", "agent-x");

        CHECK_FALSE(registry.remove_agent_if_session("agent-x", "sess-1"));
        // agent-x is still registered, under sess-2.
        CHECK(registry.has_any());
    }
}

TEST_CASE("HA WS-5: has_remote_presence — direct single-lock membership check",
          "[pg][ha][presence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, presence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(make_agent_info("local-agent", "linux", "local-host"));

    SECTION("every id in the list is locally known: false (no widening)") {
        CHECK_FALSE(registry.has_remote_presence({"local-agent"}));
    }

    SECTION("a candidate list containing an id NOT in the local registry: true") {
        CHECK(registry.has_remote_presence({"local-agent", "remote-only"}));
    }

    SECTION("empty candidate list: false") {
        CHECK_FALSE(registry.has_remote_presence({}));
    }
}
