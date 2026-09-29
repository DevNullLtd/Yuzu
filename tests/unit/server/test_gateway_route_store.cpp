// test_gateway_route_store.cpp — HA WS-4 slice 4.1: the fenced agent->cluster
// routing directory. These [pg] tests bind the two structural guarantees the
// architecture review made load-bearing (see gateway_route_store.hpp):
//   1. register_fresh mints a strictly-increasing epoch per connection
//      attempt, and the guarded UPSERT's CAS rejects a lower-epoch (stale/
//      out-of-order) register — the anti-replay fence.
//   2. announce_connected/deregister are SESSION-guarded: a stale
//      notification from a superseded session must not overwrite or tear
//      down a newer re-home's row.
// Plus renew_leases' batched update and lookup_route's in-SQL is_stale.
//
// This store is INERT in 4.1 (written, not yet read for dispatch) — these
// tests exercise the writer path in isolation, no dispatch surface involved.

#include "gateway_route_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;

namespace {

// Build the 3-field declined-anchor marker "<anchor>:<direction>:<first_now_ms>"
// (PR #4299 round 4). `first_now_ms` is the reading the recovery persistence
// window (kMinReapRecoveryGapMs..kMaxReapRecoveryGapMs) is measured from — an
// immediate second pass is BELOW the floor and re-declines, so a test that
// wants the genuine-persistence RECOVERY seeds first_now_ms roughly one window
// (300s) in the past rather than sleeping real wall-clock minutes.
std::string marker3(const std::string& anchor, const std::string& dir, std::int64_t first_now_ms) {
    return anchor + ":" + dir + ":" + std::to_string(first_now_ms);
}

// One migration run, cloned per fixture.
yuzu::test::PgTestTemplate gateway_route_tpl{"gatewayroute", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::GatewayRouteStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("gateway_route template: store failed to migrate");
}};

// RAII bundle: ephemeral DB + pool + store.
class GatewayRoutePg {
public:
    GatewayRoutePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr)
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        db_.emplace(gateway_route_tpl);
        INFO("[GatewayRoutePg] fixture status (blank == OK): " << db_->error());
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<GatewayRouteStore>(*pool_);
        REQUIRE(store_->is_open());
    }

    GatewayRoutePg(const GatewayRoutePg&) = delete;
    GatewayRoutePg& operator=(const GatewayRoutePg&) = delete;

    GatewayRouteStore& store() noexcept { return *store_; }
    std::string dsn() const { return db_->dsn(); }

    // Directly overwrite a row's (connection_epoch, session_id) on a second
    // connection — for driving the anti-replay-fence scenario (a subsequent
    // register_fresh's freshly-minted epoch is LOWER than this artificially
    // bumped value) and for assertions the public API deliberately does not
    // expose.
    void raw_bump_epoch(const std::string& agent_id, std::int64_t epoch,
                        const std::string& session_id) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string epoch_s = std::to_string(epoch);
        const char* p1 = agent_id.c_str();
        const char* p2 = epoch_s.c_str();
        const char* p3 = session_id.c_str();
        const char* params[3] = {p1, p2, p3};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "UPDATE gateway_route_store.agent_routes SET connection_epoch=$2::bigint, "
            "session_id=$3 WHERE agent_id=$1",
            3, nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    // Directly rewrite a row's lease_until to `seconds_ago` seconds in the
    // past — for driving reap_stale_routes' grace-window scenarios without
    // waiting real wall-clock time.
    void raw_set_lease_until_ago(const std::string& agent_id, int seconds_ago) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string secs_s = std::to_string(seconds_ago);
        const char* p1 = agent_id.c_str();
        const char* p2 = secs_s.c_str();
        const char* params[2] = {p1, p2};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "UPDATE gateway_route_store.agent_routes SET "
            "  lease_until = now() - ($2 || ' seconds')::interval "
            "WHERE agent_id=$1",
            2, nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    // Directly rewrite a row's updated_at to `seconds_ago` seconds in the
    // past — for driving the tombstone-purge-age predicate.
    void raw_set_updated_at_ago(const std::string& agent_id, int seconds_ago) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string secs_s = std::to_string(seconds_ago);
        const char* p1 = agent_id.c_str();
        const char* p2 = secs_s.c_str();
        const char* params[2] = {p1, p2};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "UPDATE gateway_route_store.agent_routes SET "
            "  updated_at = now() - ($2 || ' seconds')::interval "
            "WHERE agent_id=$1",
            2, nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    // The DB clock in wall-clock epoch-millis (the same expression
    // reap_stale_routes reads) — mirrors test_session_store.cpp's db_now_ms.
    std::int64_t raw_db_now_ms() {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{
            PQexec(conn.get(), "SELECT (extract(epoch FROM now()) * 1000)::bigint")};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        return std::strtoll(PQgetvalue(r.get(), 0, 0), nullptr, 10);
    }

    // Write a RAW (un-sanitised) string into route_meta's reap_anchor_ms key —
    // models a hand-edited row / storage corruption / a poisoned anchor from a
    // prior forward-skewed pass. Mirrors test_session_store.cpp's
    // set_meta_raw (#3785) — the typed reap path cannot express these values.
    void raw_set_reap_anchor(const std::string& raw_value) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const char* p1 = raw_value.c_str();
        const char* params[1] = {p1};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "INSERT INTO gateway_route_store.route_meta (key, value) VALUES "
            "('reap_anchor_ms', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
            1, nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    // Write a RAW value into route_meta's reap_declined_anchor_ms key —
    // mirrors raw_set_reap_anchor above. Used to directly CONSTRUCT the
    // "declined_anchor == anchor" recovery precondition for a chosen anchor
    // value without depending on real wall-clock time to naturally produce
    // it (PR #4299 round-2 review, FIX C cross-type recovery test): a single
    // anchor scalar cannot naturally present as forward-skewed (anchor far
    // BEHIND now) on one pass and backward-skewed (anchor AHEAD of now) on a
    // later pass, since real time only advances between passes — so the
    // cross-type scenario is constructed directly via this helper plus
    // raw_set_reap_anchor, rather than waited-for.
    void raw_set_reap_declined_anchor(const std::string& raw_value) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const char* p1 = raw_value.c_str();
        const char* params[1] = {p1};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "INSERT INTO gateway_route_store.route_meta (key, value) VALUES "
            "('reap_declined_anchor_ms', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
            1, nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    // The persisted declined-anchor marker's raw string value, or nullopt if
    // not set — for asserting a recovered/accepted pass CLEARS it.
    std::optional<std::string> raw_get_reap_declined_anchor() {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{PQexec(
            conn.get(),
            "SELECT value FROM gateway_route_store.route_meta WHERE "
            "key='reap_declined_anchor_ms'")};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        if (PQntuples(r.get()) == 0)
            return std::nullopt;
        return std::string(PQgetvalue(r.get(), 0, 0));
    }

    // The persisted anchor's raw string value, or nullopt if never set — for
    // asserting a DECLINED pass leaves it byte-for-byte unchanged.
    std::optional<std::string> raw_get_reap_anchor() {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{PQexec(
            conn.get(),
            "SELECT value FROM gateway_route_store.route_meta WHERE key='reap_anchor_ms'")};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        if (PQntuples(r.get()) == 0)
            return std::nullopt;
        return std::string(PQgetvalue(r.get(), 0, 0));
    }

    // Row existence bypassing lookup_route (which reports a tombstone as a
    // present row) — for asserting a row was fully DELETED by the
    // tombstone-purge sweep.
    bool raw_row_exists(const std::string& agent_id) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const char* p1 = agent_id.c_str();
        const char* params[1] = {p1};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(), "SELECT 1 FROM gateway_route_store.agent_routes WHERE agent_id=$1", 1,
            nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        return PQntuples(r.get()) > 0;
    }

    // The stored `stream_home_id` column value, or nullopt if NULL — for
    // asserting announce_connected/register_fresh/deregister's #4324
    // stream_home_id writes; bypasses lookup_route/RouteRow, which do not
    // expose the column (#4324 is store-layer-only in this slice — see
    // gateway_route_store.hpp's SLICE #4324 note).
    std::optional<std::string> raw_get_stream_home_id(const std::string& agent_id) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const char* p1 = agent_id.c_str();
        const char* params[1] = {p1};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "SELECT stream_home_id FROM gateway_route_store.agent_routes WHERE agent_id=$1", 1,
            nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(r.get()) == 1);
        if (PQgetisnull(r.get(), 0, 0))
            return std::nullopt;
        return std::string(PQgetvalue(r.get(), 0, 0));
    }

    // Bulk-insert `count` rows with lease_until well in the past, directly
    // via SQL — looping register_fresh/announce_connected `count` times would
    // make the cap test the slow part of the suite (mirrors
    // test_result_set_store.cpp's GC-sweep-cap idiom).
    void raw_bulk_insert_expired(int count, const std::string& agent_prefix) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string count_s = std::to_string(count);
        const char* p1 = agent_prefix.c_str();
        const char* p2 = count_s.c_str();
        const char* params[2] = {p1, p2};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "INSERT INTO gateway_route_store.agent_routes "
            "  (agent_id, connection_epoch, session_id, lease_until, updated_at) "
            "SELECT $1 || lpad(g::text, 6, '0'), g, 'sess-capbulk', "
            "       now() - interval '1000 seconds', now() "
            "FROM generate_series(1, $2::int) AS g",
            2, nullptr, params, nullptr, nullptr, 0)};
        INFO(PQresultErrorMessage(r.get()));
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

private:
    std::optional<yuzu::test::PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<GatewayRouteStore> store_;
};

// Block until a backend OTHER than this polling connection is waiting on a
// lock, or give up. Mirrors test_settings_routes_ota_audit.cpp's
// wait_for_lock_waiter and the #4213 UP-3 self-heal side-lock rendezvous:
// polling pg_stat_activity for genuinely-observed lock contention, rather
// than sleeping a fixed duration, is what makes the rendezvous deterministic
// instead of a timing assumption. A bounded ceiling exists so a genuine
// absence of blocking FAILS the caller's REQUIRE rather than hanging.
[[nodiscard]] bool wait_for_lock_waiter(PGconn* conn) {
    for (int i = 0; i < 400; ++i) { // ~10s ceiling, far above any real wait
        yuzu::server::pg::PgResult r{
            PQexec(conn, "SELECT count(*) FROM pg_stat_activity "
                         "WHERE datname = current_database() "
                         "AND wait_event_type = 'Lock' "
                         "AND pid <> pg_backend_pid()")};
        if (r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == 1 &&
            std::string(PQgetvalue(r.get(), 0, 0)) != "0")
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return false;
}

} // namespace

TEST_CASE("GatewayRouteStore[pg]: opens and migrates", "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    CHECK(fx.store().is_open());
}

TEST_CASE("GatewayRouteStore[pg]: register_fresh mints strictly increasing epochs",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-1", "session-1");
    REQUIRE(r1.has_value());
    CHECK(r1->won);
    CHECK(r1->epoch > 0);

    // A second connection attempt for the same agent (e.g. a reconnect) mints
    // a HIGHER epoch and wins.
    auto r2 = fx.store().register_fresh("agent-1", "session-2");
    REQUIRE(r2.has_value());
    CHECK(r2->won);
    CHECK(r2->epoch > r1->epoch);

    auto row = fx.store().lookup_route("agent-1");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->connection_epoch == r2->epoch);
    CHECK((*row)->session_id == "session-2");
}

TEST_CASE("GatewayRouteStore[pg]: a lower-epoch register loses (anti-replay fence)",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-2", "session-1");
    REQUIRE(r1.has_value());
    REQUIRE(r1->won);

    // Artificially advance the stored row's epoch far beyond anything the
    // sequence has minted yet (simulating a NEWER connection's register that
    // already won), then attempt a register_fresh whose freshly-minted epoch
    // is only r1->epoch+1 or so — well below the bumped value. The guarded
    // UPSERT's `WHERE EXCLUDED.connection_epoch > agent_routes.connection_epoch`
    // clause must reject it: won == false, and the row is left exactly as
    // bumped (this is the anti-replay fence a delayed/out-of-order gateway
    // notification relies on).
    const std::int64_t bumped_epoch = r1->epoch + 1'000'000;
    fx.raw_bump_epoch("agent-2", bumped_epoch, "session-winner");

    auto stale = fx.store().register_fresh("agent-2", "session-stale-replay");
    REQUIRE(stale.has_value());
    CHECK_FALSE(stale->won);

    auto row = fx.store().lookup_route("agent-2");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->connection_epoch == bumped_epoch);
    CHECK((*row)->session_id == "session-winner");
}

TEST_CASE("GatewayRouteStore[pg]: announce_connected fills cluster/node when session matches",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-3", "session-1");
    REQUIRE(r1.has_value());
    REQUIRE(r1->won);

    auto ann = fx.store().announce_connected("agent-3", "session-1", "cluster-a", "node-1", 30);
    REQUIRE(ann.has_value());
    CHECK(ann->matched);

    auto row = fx.store().lookup_route("agent-3");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    REQUIRE((*row)->cluster_id.has_value());
    CHECK(*(*row)->cluster_id == "cluster-a");
    REQUIRE((*row)->gateway_node.has_value());
    CHECK(*(*row)->gateway_node == "node-1");
    REQUIRE((*row)->lease_until_ms.has_value());
    CHECK_FALSE((*row)->is_stale);
}

TEST_CASE("GatewayRouteStore[pg]: announce_connected is a no-op against a different session",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-4", "session-1");
    REQUIRE(r1.has_value());
    REQUIRE(r1->won);
    auto ann1 = fx.store().announce_connected("agent-4", "session-1", "cluster-a", "node-1", 30);
    REQUIRE(ann1.has_value());
    REQUIRE(ann1->matched);

    // A stale/duplicate CONNECTED for a DIFFERENT (losing or unrelated)
    // session must not overwrite the row the real winner holds.
    auto ann2 = fx.store().announce_connected("agent-4", "session-stale", "cluster-b", "node-2",
                                              30);
    REQUIRE(ann2.has_value());
    CHECK_FALSE(ann2->matched);

    auto row = fx.store().lookup_route("agent-4");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->session_id == "session-1");
    REQUIRE((*row)->cluster_id.has_value());
    CHECK(*(*row)->cluster_id == "cluster-a");
}

// ── #4669: agent<->cluster affinity ─────────────────────────────────────────

TEST_CASE("GatewayRouteStore[pg]: announce_connected BINDS home_cluster_id on first contact "
          "(TOFU) and a matching cluster_id on a later reconnect keeps succeeding",
          "[gateway_route][pg][store][affinity]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-affinity-1", "session-1").value().won);
    auto ann1 =
        fx.store().announce_connected("agent-affinity-1", "session-1", "cluster-x", "node-1", 30);
    REQUIRE(ann1.has_value());
    CHECK(ann1->matched);
    CHECK_FALSE(ann1->cluster_affinity_violation);
    // Gate 4 happy-path NICE (2026-09-21): AnnounceResult's doc comment
    // states matched/cluster_affinity_violation are mutually exclusive but
    // nothing asserted it — pin the invariant so a future refactor that
    // silently breaks it fails a test, not just a code review.
    CHECK_FALSE((ann1->matched && ann1->cluster_affinity_violation));

    auto row1 = fx.store().lookup_route("agent-affinity-1");
    REQUIRE(row1.has_value());
    REQUIRE(row1->has_value());
    REQUIRE((*row1)->home_cluster_id.has_value());
    CHECK(*(*row1)->home_cluster_id == "cluster-x");

    // A SECOND legitimate reconnect (fresh session, same real cluster) —
    // single-gateway/non-multi-cluster deployments look exactly like this:
    // the SAME stable cluster_id presented on every reconnect. Must keep
    // succeeding, unaffected by the new affinity guard.
    REQUIRE(fx.store().register_fresh("agent-affinity-1", "session-2").value().won);
    auto ann2 =
        fx.store().announce_connected("agent-affinity-1", "session-2", "cluster-x", "node-2", 30);
    REQUIRE(ann2.has_value());
    CHECK(ann2->matched);
    CHECK_FALSE(ann2->cluster_affinity_violation);

    auto row2 = fx.store().lookup_route("agent-affinity-1");
    REQUIRE(row2.has_value());
    REQUIRE(row2->has_value());
    REQUIRE((*row2)->cluster_id.has_value());
    CHECK(*(*row2)->cluster_id == "cluster-x");
    REQUIRE((*row2)->home_cluster_id.has_value());
    CHECK(*(*row2)->home_cluster_id == "cluster-x"); // unchanged
}

TEST_CASE("GatewayRouteStore[pg]: announce_connected REFUSES a same-session claim presenting a "
          "DIFFERENT cluster_id than the bound home affinity — #4669 the rogue-gateway shape",
          "[gateway_route][pg][store][affinity]") {
    GatewayRoutePg fx;
    // The REAL cluster (cluster-x) legitimately binds the agent's affinity.
    REQUIRE(fx.store().register_fresh("agent-affinity-2", "session-real").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-affinity-2", "session-real", "cluster-x", "node-real",
                                    30)
                .value()
                .matched);

    // A ROGUE gateway calls ProxyRegister for the SAME already-approved
    // agent_id (no per-agent secret required — #4669's finding) and its own
    // register_fresh wins the epoch race unconditionally (it always mints a
    // strictly higher epoch), installing a NEW session and NULLing
    // cluster_id/gateway_node — but NOT home_cluster_id (sticky, file
    // header). It then tries to CONFIRM its own cluster via
    // announce_connected.
    auto reg2 = fx.store().register_fresh("agent-affinity-2", "session-rogue");
    REQUIRE(reg2.has_value());
    CHECK(reg2->won); // register_fresh itself is NOT cluster-aware — this is the accepted,
                       // pre-existing DoS-shaped churn #4669 does not attempt to close.

    auto ann_rogue = fx.store().announce_connected("agent-affinity-2", "session-rogue",
                                                    "cluster-rogue", "node-rogue", 30);
    REQUIRE(ann_rogue.has_value());
    CHECK_FALSE(ann_rogue->matched);
    CHECK(ann_rogue->cluster_affinity_violation); // the mitigation: refused, not silently applied

    // The row is COMPLETELY UNTOUCHED by the rogue's claim: cluster_id stays
    // NULL (register_fresh's own NULLing, never confirmed by the refused
    // announce_connected), home_cluster_id stays cluster-x, and the row is
    // therefore NOT routable to the rogue's cluster.
    auto row = fx.store().lookup_route("agent-affinity-2");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->session_id == "session-rogue"); // register_fresh's own unconditional win
    CHECK_FALSE((*row)->cluster_id.has_value());   // never confirmed for the rogue
    REQUIRE((*row)->home_cluster_id.has_value());
    CHECK(*(*row)->home_cluster_id == "cluster-x"); // untouched

    // The REAL agent's own later reconnect (its own fresh register_fresh,
    // strictly higher epoch, always eventually wins) self-heals the row once
    // it announces the MATCHING cluster.
    REQUIRE(fx.store().register_fresh("agent-affinity-2", "session-real-2").value().won);
    auto ann_real = fx.store().announce_connected("agent-affinity-2", "session-real-2",
                                                   "cluster-x", "node-real-2", 30);
    REQUIRE(ann_real.has_value());
    CHECK(ann_real->matched);
    CHECK_FALSE(ann_real->cluster_affinity_violation);
    auto row2 = fx.store().lookup_route("agent-affinity-2");
    REQUIRE(row2.has_value());
    REQUIRE(row2->has_value());
    REQUIRE((*row2)->cluster_id.has_value());
    CHECK(*(*row2)->cluster_id == "cluster-x");
}

TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes' expired-lease sweep clears home_cluster_id "
          "too — the 'row expired' legitimate re-home trigger (#4669)",
          "[gateway_route][pg][store][affinity][reap]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-affinity-reap", "session-1").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-affinity-reap", "session-1", "cluster-x", "node-1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-affinity-reap", 200); // past the 180s grace

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->expired_leases_reaped == 1);

    auto row = fx.store().lookup_route("agent-affinity-reap");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->home_cluster_id.has_value()); // affinity cleared, not just placement

    // A DIFFERENT cluster can now legitimately bind the agent — genuine
    // staleness is a real re-home trigger, not a hijack.
    REQUIRE(fx.store().register_fresh("agent-affinity-reap", "session-2").value().won);
    auto ann = fx.store().announce_connected("agent-affinity-reap", "session-2", "cluster-y",
                                             "node-2", 30);
    REQUIRE(ann.has_value());
    CHECK(ann->matched);
    CHECK_FALSE(ann->cluster_affinity_violation);
}

TEST_CASE("GatewayRouteStore[pg]: clear_cluster_affinity is the explicit-operator-action "
          "re-home trigger (#4669) — clears ONLY home_cluster_id, leaves current placement "
          "untouched, and the next announce_connected can bind a new cluster",
          "[gateway_route][pg][store][affinity]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-affinity-op", "session-1").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-affinity-op", "session-1", "cluster-x", "node-1", 30)
                .value()
                .matched);

    auto cleared = fx.store().clear_cluster_affinity("agent-affinity-op");
    REQUIRE(cleared.has_value());
    CHECK(*cleared);

    // Current placement (cluster_id/gateway_node/session_id) is UNTOUCHED —
    // only the sticky affinity anchor is reset.
    auto row = fx.store().lookup_route("agent-affinity-op");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->session_id == "session-1");
    REQUIRE((*row)->cluster_id.has_value());
    CHECK(*(*row)->cluster_id == "cluster-x");
    CHECK_FALSE((*row)->home_cluster_id.has_value());

    // A DIFFERENT cluster's session can now legitimately (re-)bind.
    REQUIRE(fx.store().register_fresh("agent-affinity-op", "session-2").value().won);
    auto ann = fx.store().announce_connected("agent-affinity-op", "session-2", "cluster-z",
                                             "node-2", 30);
    REQUIRE(ann.has_value());
    CHECK(ann->matched);
    CHECK_FALSE(ann->cluster_affinity_violation);

    // clear_cluster_affinity against an unknown agent is a harmless no-op
    // (false, not an error).
    auto cleared_missing = fx.store().clear_cluster_affinity("agent-affinity-op-never-seen");
    REQUIRE(cleared_missing.has_value());
    CHECK_FALSE(*cleared_missing);
}

TEST_CASE("GatewayRouteStore[pg]: an ordinary deregister does NOT clear home_cluster_id — only "
          "genuine staleness or an explicit operator action does (#4669)",
          "[gateway_route][pg][store][affinity]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-affinity-dereg", "session-1").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-affinity-dereg", "session-1", "cluster-x", "node-1", 30)
                .value()
                .matched);
    REQUIRE(fx.store().deregister("agent-affinity-dereg", "session-1").value().removed);

    auto row = fx.store().lookup_route("agent-affinity-dereg");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value()); // tombstoned, still present
    CHECK_FALSE((*row)->session_id.has_value());
    REQUIRE((*row)->home_cluster_id.has_value()); // affinity SURVIVES an ordinary disconnect
    CHECK(*(*row)->home_cluster_id == "cluster-x");

    // An ordinary reconnect from a DIFFERENT cluster right after a plain
    // disconnect is STILL refused — a ProxyRegister/disconnect cycle is not,
    // on its own, one of the two legitimate re-home triggers.
    REQUIRE(fx.store().register_fresh("agent-affinity-dereg", "session-2").value().won);
    auto ann = fx.store().announce_connected("agent-affinity-dereg", "session-2", "cluster-rogue",
                                             "node-2", 30);
    REQUIRE(ann.has_value());
    CHECK_FALSE(ann->matched);
    CHECK(ann->cluster_affinity_violation);
}

TEST_CASE("GatewayRouteStore[pg]: deregister tombstones only when session matches",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-5", "session-1");
    REQUIRE(r1.has_value());
    REQUIRE(r1->won);
    REQUIRE(fx.store().announce_connected("agent-5", "session-1", "c1", "n1", 30).value().matched);

    // Wrong session: row intact (session/lease/cluster/node untouched).
    auto wrong = fx.store().deregister("agent-5", "session-wrong");
    REQUIRE(wrong.has_value());
    CHECK_FALSE(wrong->removed);
    auto still = fx.store().lookup_route("agent-5");
    REQUIRE(still.has_value());
    REQUIRE(still->has_value());
    CHECK((*still)->session_id == "session-1");
    CHECK((*still)->cluster_id.has_value());

    // Correct session: TOMBSTONED, not deleted — the row still exists (#4/#5,
    // gateway_route_store.hpp "SLICE 4.2a"): session_id/lease_until/cluster_id/
    // gateway_node -> NULL, connection_epoch RETAINED.
    auto right = fx.store().deregister("agent-5", "session-1");
    REQUIRE(right.has_value());
    CHECK(right->removed);
    auto tombstoned = fx.store().lookup_route("agent-5");
    REQUIRE(tombstoned.has_value());
    REQUIRE(tombstoned->has_value()); // row still present — a tombstone, not gone
    CHECK_FALSE((*tombstoned)->session_id.has_value());
    CHECK_FALSE((*tombstoned)->lease_until_ms.has_value());
    CHECK_FALSE((*tombstoned)->cluster_id.has_value());
    CHECK_FALSE((*tombstoned)->gateway_node.has_value());
    CHECK((*tombstoned)->connection_epoch == r1->epoch);

    // A second deregister for the same (now stale) session is a no-op:
    // session_id is NULL, so `session_id=$2` never matches it again.
    auto again = fx.store().deregister("agent-5", "session-1");
    REQUIRE(again.has_value());
    CHECK_FALSE(again->removed);
}

TEST_CASE("GatewayRouteStore[pg]: a late announce_connected does not resurrect a tombstoned route",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-tomb-1", "session-dead");
    REQUIRE(r1.has_value());
    REQUIRE(r1->won);
    REQUIRE(fx.store()
                .announce_connected("agent-tomb-1", "session-dead", "c1", "n1", 30)
                .value()
                .matched);
    REQUIRE(fx.store().deregister("agent-tomb-1", "session-dead").value().removed);

    // A reordered/late CONNECTED for the now-dead session arrives AFTER the
    // DISCONNECTED that tombstoned the row. Its session-guarded UPDATE misses
    // (NULL != 'session-dead'), and its fallback INSERT hits
    // `ON CONFLICT (agent_id) DO NOTHING` against the EXISTING tombstoned
    // row — it must NOT resurrect the route.
    auto late = fx.store().announce_connected("agent-tomb-1", "session-dead", "c-late", "n-late", 30);
    REQUIRE(late.has_value());
    CHECK_FALSE(late->matched);

    auto row = fx.store().lookup_route("agent-tomb-1");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value()); // still a tombstone, not resurrected
    CHECK_FALSE((*row)->session_id.has_value());
    CHECK_FALSE((*row)->lease_until_ms.has_value());
    CHECK_FALSE((*row)->cluster_id.has_value());
}

TEST_CASE("GatewayRouteStore[pg]: register_fresh after a tombstone mints a higher epoch and "
          "reuses the row",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-tomb-2", "session-old");
    REQUIRE(r1.has_value());
    REQUIRE(r1->won);
    REQUIRE(fx.store()
                .announce_connected("agent-tomb-2", "session-old", "c1", "n1", 30)
                .value()
                .matched);
    REQUIRE(fx.store().deregister("agent-tomb-2", "session-old").value().removed);

    auto tombstoned = fx.store().lookup_route("agent-tomb-2");
    REQUIRE(tombstoned.has_value());
    REQUIRE(tombstoned->has_value());
    CHECK((*tombstoned)->connection_epoch == r1->epoch);

    // A genuine reconnect: register_fresh mints a strictly higher epoch and
    // reuses the SAME primary-keyed row (not a fresh insert failure/conflict).
    auto r2 = fx.store().register_fresh("agent-tomb-2", "session-new");
    REQUIRE(r2.has_value());
    CHECK(r2->won);
    CHECK(r2->epoch > r1->epoch);

    auto row = fx.store().lookup_route("agent-tomb-2");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->connection_epoch == r2->epoch);
    REQUIRE((*row)->session_id.has_value());
    CHECK(*(*row)->session_id == "session-new");
}

// --- #4324: stream_home_id per-home generation fence (store layer) --------

TEST_CASE("GatewayRouteStore[pg]: announce_connected writes stream_home_id on a winning "
          "placement (#4324)",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-home-1", "session-1").value().won);
    auto ann =
        fx.store().announce_connected("agent-home-1", "session-1", "c1", "n1", 30, "home-abc");
    REQUIRE(ann.has_value());
    CHECK(ann->matched);

    auto home_id = fx.raw_get_stream_home_id("agent-home-1");
    REQUIRE(home_id.has_value());
    CHECK(*home_id == "home-abc");
}

TEST_CASE("GatewayRouteStore[pg]: register_fresh NULLs stream_home_id on a winning re-register, "
          "same as cluster_id/gateway_node (#4324)",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-home-2", "session-S1").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-home-2", "session-S1", "c1", "n1", 30, "home-old")
                .value()
                .matched);
    REQUIRE(fx.raw_get_stream_home_id("agent-home-2").has_value());

    auto r2 = fx.store().register_fresh("agent-home-2", "session-S2");
    REQUIRE(r2.has_value());
    CHECK(r2->won);

    CHECK_FALSE(fx.raw_get_stream_home_id("agent-home-2").has_value());
    // cluster_id/gateway_node are NULLed too (4.2b, pre-existing) — assert
    // the whole placement, not just the new column, dropped together.
    auto row = fx.store().lookup_route("agent-home-2");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->cluster_id.has_value());
}

TEST_CASE("GatewayRouteStore[pg]: deregister tombstones when the incoming stream_home_id "
          "EXACTLY matches the stored one (#4324)",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-home-3", "session-1").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-home-3", "session-1", "c1", "n1", 30, "home-match")
                .value()
                .matched);

    auto out = fx.store().deregister("agent-home-3", "session-1", "home-match");
    REQUIRE(out.has_value());
    CHECK(out->removed);

    auto row = fx.store().lookup_route("agent-home-3");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->session_id.has_value());
    CHECK_FALSE(fx.raw_get_stream_home_id("agent-home-3").has_value());
}

TEST_CASE("GatewayRouteStore[pg]: deregister does NOT tombstone when the incoming "
          "stream_home_id is a STALE mismatch against the stored one — the core "
          "asymmetric-fence case (#4324)",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-home-4", "session-1").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-home-4", "session-1", "c1", "n1", 30, "home-current")
                .value()
                .matched);

    // A stale DISCONNECTED carrying a DIFFERENT (superseded) home id for the
    // same session must not tear down the row's current placement.
    auto out = fx.store().deregister("agent-home-4", "session-1", "home-stale");
    REQUIRE(out.has_value());
    CHECK_FALSE(out->removed);

    auto row = fx.store().lookup_route("agent-home-4");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    REQUIRE((*row)->session_id.has_value());
    CHECK(*(*row)->session_id == "session-1");
    REQUIRE((*row)->cluster_id.has_value());
    CHECK(*(*row)->cluster_id == "c1");
    auto home_id = fx.raw_get_stream_home_id("agent-home-4");
    REQUIRE(home_id.has_value());
    CHECK(*home_id == "home-current");
}

TEST_CASE("GatewayRouteStore[pg]: deregister tombstones a legacy row when neither side ever "
          "carried a stream_home_id — backward compatibility (#4324)",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-home-5", "session-1").value().won);
    // Neither call passes stream_home_id — both default to empty ("legacy,
    // no home id"), so the stored column stays NULL, exactly as it would for
    // a gateway build predating #4324.
    REQUIRE(
        fx.store().announce_connected("agent-home-5", "session-1", "c1", "n1", 30).value().matched);
    CHECK_FALSE(fx.raw_get_stream_home_id("agent-home-5").has_value());

    auto out = fx.store().deregister("agent-home-5", "session-1");
    REQUIRE(out.has_value());
    CHECK(out->removed);

    auto row = fx.store().lookup_route("agent-home-5");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->session_id.has_value());
}

TEST_CASE("GatewayRouteStore[pg]: deregister ADMITS a STAMPED incoming stream_home_id against a "
          "register_fresh-only row (stored NULL, announce_connected never ran) — the reorder/"
          "lost-CONNECTED regression from PR #4492's review, HIGH",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    // register_fresh only — no announce_connected call, so stream_home_id
    // stays NULL. This is EXACTLY the state a fresh session is in if its own
    // paired DISCONNECTED reaches the server before its own paired CONNECTED
    // (the gateway dispatches the two as independently spawn_monitor'd RPC
    // workers with no ordering guarantee — see gateway_route_store.hpp's
    // PREDICATE FIX note). It is NOT distinguishable, at the store layer,
    // from a genuinely stale row whose home was cleared by a tombstone sweep
    // — both are safe to admit, because a stored-NULL home never represents
    // a live placement worth protecting.
    REQUIRE(fx.store().register_fresh("agent-home-7", "session-1").value().won);
    CHECK_FALSE(fx.raw_get_stream_home_id("agent-home-7").has_value());

    // The ORIGINAL predicate (`stream_home_id = $3 OR (stream_home_id IS
    // NULL AND $3 = '')`) required $3 to ALSO be empty here, so this call
    // returned removed=false — the bug. The fixed predicate
    // (`stream_home_id IS NULL OR stream_home_id = $3`) admits it.
    auto out = fx.store().deregister("agent-home-7", "session-1", "home-real");
    REQUIRE(out.has_value());
    CHECK(out->removed);

    auto row = fx.store().lookup_route("agent-home-7");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->session_id.has_value());
}

TEST_CASE("GatewayRouteStore[pg]: deregister with an EMPTY (old-build gateway) stream_home_id "
          "does NOT tombstone a row carrying a STAMPED stream_home_id — the asymmetry a naive "
          "symmetric predicate gets wrong (#4324, rolling gateway upgrade)",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-home-6", "session-1").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-home-6", "session-1", "c1", "n1", 30, "home-newbuild")
                .value()
                .matched);

    // An old-build gateway node's DISCONNECTED for the same session id
    // carries NO stream_home_id (empty — the pre-#4324 wire shape). It must
    // not be able to tear down a new-build node's stamped re-home reusing
    // that session id. The naive symmetric predicate
    // (`$3 = '' OR stream_home_id = $3`) would wrongly match here; the
    // shipped asymmetric predicate must not.
    auto out = fx.store().deregister("agent-home-6", "session-1", "");
    REQUIRE(out.has_value());
    CHECK_FALSE(out->removed);

    auto row = fx.store().lookup_route("agent-home-6");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    REQUIRE((*row)->session_id.has_value());
    CHECK(*(*row)->session_id == "session-1");
    REQUIRE((*row)->cluster_id.has_value());
    CHECK(*(*row)->cluster_id == "c1");
    auto home_id = fx.raw_get_stream_home_id("agent-home-6");
    REQUIRE(home_id.has_value());
    CHECK(*home_id == "home-newbuild");
}

TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes' expired-lease tombstone sweep clears "
          "stream_home_id too (#4324)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-reap-home-1", "session-1").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-reap-home-1", "session-1", "c1", "n1", 30, "home-x")
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-reap-home-1", 200); // past the 180s grace

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->expired_leases_reaped == 1);

    CHECK_FALSE(fx.raw_get_stream_home_id("agent-reap-home-1").has_value());
}

TEST_CASE("GatewayRouteStore[pg]: renew_leases bumps lease_until only for named sessions, batched",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-6", "session-a").value().won);
    REQUIRE(fx.store().register_fresh("agent-7", "session-b").value().won);
    REQUIRE(fx.store().register_fresh("agent-8", "session-c").value().won);
    REQUIRE(fx.store().announce_connected("agent-6", "session-a", "c1", "n1", 30).value().matched);
    REQUIRE(fx.store().announce_connected("agent-7", "session-b", "c1", "n1", 30).value().matched);
    REQUIRE(fx.store().announce_connected("agent-8", "session-c", "c1", "n1", 30).value().matched);

    // Renew only session-a and session-b, in ONE batched call.
    std::vector<std::string> agents{"agent-6", "agent-7"};
    std::vector<std::string> ids{"session-a", "session-b"};
    auto renewed = fx.store().renew_leases(agents, ids, 3600);
    REQUIRE(renewed.has_value());
    CHECK(*renewed == 2);

    auto ra = fx.store().lookup_route("agent-6");
    auto rb = fx.store().lookup_route("agent-7");
    auto rc = fx.store().lookup_route("agent-8");
    REQUIRE(ra.has_value());
    REQUIRE(rb.has_value());
    REQUIRE(rc.has_value());
    REQUIRE((*ra)->lease_until_ms.has_value());
    REQUIRE((*rb)->lease_until_ms.has_value());
    REQUIRE((*rc)->lease_until_ms.has_value());
    // session-c was NOT in the renewal batch, so its lease is still the
    // short 30s one from announce_connected — its expiry is well before
    // session-a/b's freshly-renewed 3600s expiry.
    CHECK(*(*rc)->lease_until_ms < *(*ra)->lease_until_ms);
    CHECK(*(*rc)->lease_until_ms < *(*rb)->lease_until_ms);
}

TEST_CASE("GatewayRouteStore[pg]: renew_leases renews a session id containing a comma and a "
          "double-quote (parameter binding, not string-splicing)",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    // A hand-rolled `{"..",".."}` literal would misparse a comma as an
    // element separator and a bare `"` as a premature quote-close; a real
    // ANY($1::text[]) parameter binding does neither.
    const std::string tricky_session = R"(sess,"a")";
    REQUIRE(fx.store().register_fresh("agent-tricky", tricky_session).value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-tricky", tricky_session, "c1", "n1", 30)
                .value()
                .matched);

    std::vector<std::string> agents{"agent-tricky"};
    std::vector<std::string> ids{tricky_session};
    auto renewed = fx.store().renew_leases(agents, ids, 3600);
    REQUIRE(renewed.has_value());
    CHECK(*renewed == 1);

    auto route = fx.store().lookup_route("agent-tricky");
    REQUIRE(route.has_value());
    REQUIRE((*route)->lease_until_ms.has_value());
}

TEST_CASE("GatewayRouteStore[pg]: renew_leases correlates agent_id AND session_id — a matching "
          "session with a MISMATCHED agent_id renews zero rows",
          "[gateway_route][pg][store]") {
    // #4246 #10: renew_leases used to match on session_id alone. A caller
    // (compromised/buggy gateway) that knows a session token but asserts the
    // WRONG agent_id for it must not be able to renew that agent's lease.
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-correlate-1", "session-correlate-1").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-correlate-1", "session-correlate-1", "c1", "n1", 30)
                .value()
                .matched);
    auto row_before = fx.store().lookup_route("agent-correlate-1");
    REQUIRE(row_before.has_value());
    REQUIRE(row_before->has_value());
    const auto lease_before = (*row_before)->lease_until_ms;
    REQUIRE(lease_before.has_value());

    // Right session, WRONG agent_id: matches zero rows, and the row's lease
    // is left completely untouched.
    std::vector<std::string> wrong_agents{"agent-correlate-WRONG"};
    std::vector<std::string> right_sessions{"session-correlate-1"};
    auto mismatched = fx.store().renew_leases(wrong_agents, right_sessions, 3600);
    REQUIRE(mismatched.has_value());
    CHECK(*mismatched == 0);

    auto row_after_mismatch = fx.store().lookup_route("agent-correlate-1");
    REQUIRE(row_after_mismatch.has_value());
    REQUIRE(row_after_mismatch->has_value());
    CHECK((*row_after_mismatch)->lease_until_ms == lease_before); // untouched

    // The CORRECT (agent_id, session_id) pair renews the row.
    std::vector<std::string> right_agents{"agent-correlate-1"};
    auto correct = fx.store().renew_leases(right_agents, right_sessions, 3600);
    REQUIRE(correct.has_value());
    CHECK(*correct == 1);

    auto row_after_correct = fx.store().lookup_route("agent-correlate-1");
    REQUIRE(row_after_correct.has_value());
    REQUIRE(row_after_correct->has_value());
    REQUIRE((*row_after_correct)->lease_until_ms.has_value());
    CHECK(*(*row_after_correct)->lease_until_ms > *lease_before); // genuinely renewed
}

TEST_CASE("GatewayRouteStore[pg]: renew_leases refuses a length-mismatched agent_ids/session_ids "
          "pair rather than silently misaligning them",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    std::vector<std::string> agents{"agent-a", "agent-b"};
    std::vector<std::string> sessions{"session-a"};
    auto result = fx.store().renew_leases(agents, sessions, 3600);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == GatewayRouteStoreError::db_error);
}

TEST_CASE("GatewayRouteStore[pg]: lookup_route reports is_stale for an expired lease",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-9", "session-1").value().won);
    // A negative TTL lands lease_until in the past.
    auto ann = fx.store().announce_connected("agent-9", "session-1", "c1", "n1", -3600);
    REQUIRE(ann.has_value());
    REQUIRE(ann->matched);

    auto row = fx.store().lookup_route("agent-9");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->is_stale);
}

TEST_CASE("GatewayRouteStore[pg]: lookup_route on an unknown agent returns nullopt",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto row = fx.store().lookup_route("no-such-agent");
    REQUIRE(row.has_value());
    CHECK_FALSE(row->has_value());
}

// --- 4.2b Task A: placement authority + lookup_routes -----------------------

TEST_CASE("GatewayRouteStore[pg]: register_fresh NULLs placement on a winning re-register",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    // Seed a live, fully-announced route: {S1, cluster=c1, node=n1}.
    auto r1 = fx.store().register_fresh("agent-4.2b-1", "session-S1");
    REQUIRE(r1.has_value());
    REQUIRE(r1->won);
    REQUIRE(
        fx.store().announce_connected("agent-4.2b-1", "session-S1", "c1", "n1", 30).value().matched);
    auto seeded = fx.store().lookup_route("agent-4.2b-1");
    REQUIRE(seeded.has_value());
    REQUIRE(seeded->has_value());
    REQUIRE((*seeded)->cluster_id.has_value());
    CHECK(*(*seeded)->cluster_id == "c1");

    // A fresh registration (a reconnect) under a NEW session wins the epoch
    // race. Pre-4.2b this COALESCE-preserved c1/n1 across the winning
    // re-register; 4.2b instead drops placement — announce_connected is now
    // the sole writer of it.
    auto r2 = fx.store().register_fresh("agent-4.2b-1", "session-S2");
    REQUIRE(r2.has_value());
    CHECK(r2->won);
    CHECK(r2->epoch > r1->epoch);

    auto row = fx.store().lookup_route("agent-4.2b-1");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->session_id == "session-S2");
    CHECK_FALSE((*row)->cluster_id.has_value());
    CHECK_FALSE((*row)->gateway_node.has_value());
}

TEST_CASE("GatewayRouteStore[pg]: lookup_routes computes the routable matrix in-SQL",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;

    // (a) a live, fully-announced route -> routable.
    REQUIRE(fx.store().register_fresh("agent-route-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-route-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);

    // (b) a tombstone (session_id IS NULL AND lease_until IS NULL) ->
    // not routable.
    REQUIRE(fx.store().register_fresh("agent-route-tomb", "s-tomb").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-route-tomb", "s-tomb", "c1", "n1", 30)
                .value()
                .matched);
    REQUIRE(fx.store().deregister("agent-route-tomb", "s-tomb").value().removed);

    // (c) an expired lease (still fully placed, but lease_until < now()) ->
    // not routable.
    REQUIRE(fx.store().register_fresh("agent-route-expired", "s-expired").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-route-expired", "s-expired", "c1", "n1", -3600)
                .value()
                .matched);

    // (d) a null-cluster, live-session row: register_fresh only, no
    // announce_connected yet -> not routable (placement unconfirmed).
    REQUIRE(fx.store().register_fresh("agent-route-unannounced", "s-unannounced").value().won);

    // (e) an absent agent — no row at all.
    const std::string absent_agent = "agent-route-absent-does-not-exist";

    std::vector<std::string> ids{"agent-route-live",         "agent-route-tomb",
                                 "agent-route-expired",       "agent-route-unannounced",
                                 absent_agent};
    auto routes = fx.store().lookup_routes(ids);
    REQUIRE(routes.has_value());
    // The absent agent contributes no row; the other four do.
    CHECK(routes->size() == 4);

    auto find = [&](const std::string& agent_id) -> const RoutableRoute* {
        for (const auto& rr : *routes)
            if (rr.route.agent_id == agent_id)
                return &rr;
        return nullptr;
    };

    const RoutableRoute* live = find("agent-route-live");
    REQUIRE(live != nullptr);
    CHECK(live->routable);
    CHECK_FALSE(live->route.is_stale);

    const RoutableRoute* tomb = find("agent-route-tomb");
    REQUIRE(tomb != nullptr);
    CHECK_FALSE(tomb->routable);

    const RoutableRoute* expired = find("agent-route-expired");
    REQUIRE(expired != nullptr);
    CHECK_FALSE(expired->routable);
    CHECK(expired->route.is_stale);

    const RoutableRoute* unannounced = find("agent-route-unannounced");
    REQUIRE(unannounced != nullptr);
    CHECK_FALSE(unannounced->routable);
    CHECK_FALSE(unannounced->route.cluster_id.has_value());

    CHECK(find(absent_agent) == nullptr);
}

TEST_CASE("GatewayRouteStore[pg]: lookup_routes on an empty span returns an empty result",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    std::vector<std::string> ids{};
    auto routes = fx.store().lookup_routes(ids);
    REQUIRE(routes.has_value());
    CHECK(routes->empty());
}

// --- reap_stale_routes ------------------------------------------------------

TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes tombstones an expired-lease row past grace",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-reap-1", "session-1").value().won);
    REQUIRE(fx.store().announce_connected("agent-reap-1", "session-1", "c1", "n1", 30).value().matched);
    // kStaleLeaseGraceSecs is 180s (2x the 90s TTL) — push well past it.
    fx.raw_set_lease_until_ago("agent-reap-1", 200);

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->expired_leases_reaped == 1);
    CHECK(out->tombstones_reaped == 0);
    CHECK_FALSE(out->clock_anomaly);

    // Reaped means TOMBSTONED (same shape as deregister), not deleted.
    auto row = fx.store().lookup_route("agent-reap-1");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->session_id.has_value());
    CHECK_FALSE((*row)->lease_until_ms.has_value());
    CHECK_FALSE((*row)->cluster_id.has_value());
}

TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes leaves an expired lease alone within grace",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-reap-2", "session-1").value().won);
    REQUIRE(fx.store().announce_connected("agent-reap-2", "session-1", "c1", "n1", 30).value().matched);
    // Lease is expired (30s TTL already elapsed logically, forced past via a
    // negative lookup below) but well WITHIN the 180s grace window.
    fx.raw_set_lease_until_ago("agent-reap-2", 60);

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->expired_leases_reaped == 0);
    CHECK(out->tombstones_reaped == 0);

    // Untouched: still session-1, lease still set (though logically expired —
    // is_stale is a separate, always-live signal from the reap grace).
    auto row = fx.store().lookup_route("agent-reap-2");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    REQUIRE((*row)->session_id.has_value());
    CHECK(*(*row)->session_id == "session-1");
    CHECK((*row)->lease_until_ms.has_value());
    CHECK((*row)->is_stale); // lease_until < now() — is_stale fires independent of grace
}

TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes purges a tombstone past the purge age "
          "(genuine tombstone — no confirmed cluster, so no affinity to protect)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    // Deliberately never calls announce_connected — home_cluster_id stays
    // NULL, so this is a genuine no-affinity tombstone and remains a
    // sweep-(b) hard-delete candidate under the #4669 pr-rev fix (which
    // excludes any row carrying a bound home_cluster_id from sweep (b) —
    // see "reap_stale_routes' tombstone-purge sweep does NOT purge a row
    // carrying a bound home_cluster_id" below for that coverage instead).
    REQUIRE(fx.store().register_fresh("agent-reap-3", "session-1").value().won);
    REQUIRE(fx.store().deregister("agent-reap-3", "session-1").value().removed); // tombstoned
    // kTombstonePurgeAgeSecs is 300s — push well past it.
    fx.raw_set_updated_at_ago("agent-reap-3", 400);

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->tombstones_reaped == 1);
    CHECK(out->expired_leases_reaped == 0);
    CHECK(out->affinity_preserved_soft_tombstones == 0);

    // Purged means fully GONE — not merely re-tombstoned.
    CHECK_FALSE(fx.raw_row_exists("agent-reap-3"));
    auto row = fx.store().lookup_route("agent-reap-3");
    REQUIRE(row.has_value());
    CHECK_FALSE(row->has_value());
}

TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes' tombstone-purge sweep does NOT purge a row "
          "carrying a bound home_cluster_id — an ordinary deregister leaves the row parked, "
          "affinity preserved, indefinitely (#4669 pr-rev Blocker 1)",
          "[gateway_route][pg][store][reap][affinity]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-reap-affinity-parked", "session-1").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-reap-affinity-parked", "session-1", "cluster-x",
                                    "node-1", 30)
                .value()
                .matched);
    REQUIRE(fx.store().deregister("agent-reap-affinity-parked", "session-1").value().removed);
    // Well past kTombstonePurgeAgeSecs (300s) — under the PRE-fix predicate
    // this would have been a sweep-(b) hard-delete candidate, wiping
    // home_cluster_id along with the row and re-opening a TOFU rebind window
    // for any cluster. Post-fix, a bound home_cluster_id excludes the row
    // from sweep (b) UNCONDITIONALLY, regardless of how it reached
    // session_id IS NULL (an ordinary deregister here, not just an
    // abandoned rogue claim — see the Blocker-1 falsifier test below for
    // that variant).
    fx.raw_set_updated_at_ago("agent-reap-affinity-parked", 400);

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->tombstones_reaped == 0);
    // session_id is already NULL (ordinary deregister), so sweep (b')'s
    // `session_id IS NOT NULL` guard also does not match this row — it is
    // parked untouched by either sweep, exactly as an already-tombstoned
    // row with nothing left to clear should be.
    CHECK(out->affinity_preserved_soft_tombstones == 0);

    REQUIRE(fx.raw_row_exists("agent-reap-affinity-parked")); // NOT purged
    auto row = fx.store().lookup_route("agent-reap-affinity-parked");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->session_id.has_value());
    REQUIRE((*row)->home_cluster_id.has_value());
    CHECK(*(*row)->home_cluster_id == "cluster-x"); // affinity survives indefinitely

    // The real agent can still reconnect and confirm the SAME cluster at any
    // time — parked is not abandoned.
    REQUIRE(fx.store().register_fresh("agent-reap-affinity-parked", "session-2").value().won);
    auto ann = fx.store().announce_connected("agent-reap-affinity-parked", "session-2",
                                             "cluster-x", "node-2", 30);
    REQUIRE(ann.has_value());
    CHECK(ann->matched);
    CHECK_FALSE(ann->cluster_affinity_violation);
}

TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes' affinity-preserving soft-tombstone closes "
          "the rogue-register-then-wait TOFU-rebind hijack (#4669 pr-rev Blocker 1, empirically "
          "reproduced by FortitudeEtc/Codex+Kimi)",
          "[gateway_route][pg][store][reap][affinity]") {
    GatewayRoutePg fx;
    // The real agent binds cluster-x first.
    REQUIRE(fx.store().register_fresh("agent-reap-hijack", "session-real").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-reap-hijack", "session-real", "cluster-x", "node-real",
                                    30)
                .value()
                .matched);

    // A rogue's ProxyRegister wins the epoch race unconditionally (register_fresh
    // is not cluster-aware) but never confirms via announce_connected — it just
    // sits there, exactly the exploit shape pr-rev reproduced against real
    // Postgres: claim, then wait out kTombstonePurgeAgeSecs.
    REQUIRE(fx.store().register_fresh("agent-reap-hijack", "session-rogue").value().won);
    fx.raw_set_updated_at_ago("agent-reap-hijack", 400); // past the 300s purge age

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    // THE DISCRIMINATING ASSERTION: pre-fix this counted as tombstones_reaped
    // (a hard DELETE, wiping home_cluster_id) — post-fix it is soft-
    // tombstoned instead, preserving the affinity.
    CHECK(out->tombstones_reaped == 0);
    CHECK(out->affinity_preserved_soft_tombstones == 1);

    auto row = fx.store().lookup_route("agent-reap-hijack");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->session_id.has_value()); // the rogue's claim is cleared
    CHECK_FALSE((*row)->cluster_id.has_value());
    REQUIRE((*row)->home_cluster_id.has_value());
    CHECK(*(*row)->home_cluster_id == "cluster-x"); // affinity SURVIVES the rogue's wait-out

    // A SECOND rogue attempt — fresh register_fresh, then try to confirm the
    // rogue's own cluster — is still refused: the reap never actually cleared
    // the affinity, so the hijack gains nothing from waiting.
    REQUIRE(fx.store().register_fresh("agent-reap-hijack", "session-rogue-2").value().won);
    auto ann_rogue = fx.store().announce_connected("agent-reap-hijack", "session-rogue-2",
                                                    "cluster-rogue", "node-rogue", 30);
    REQUIRE(ann_rogue.has_value());
    CHECK_FALSE(ann_rogue->matched);
    CHECK(ann_rogue->cluster_affinity_violation);

    // The REAL cluster can still reconnect and confirm at any time.
    REQUIRE(fx.store().register_fresh("agent-reap-hijack", "session-real-2").value().won);
    auto ann_real = fx.store().announce_connected("agent-reap-hijack", "session-real-2",
                                                   "cluster-x", "node-real-2", 30);
    REQUIRE(ann_real.has_value());
    CHECK(ann_real->matched);
    CHECK_FALSE(ann_real->cluster_affinity_violation);
}

TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes leaves a live lease untouched",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-reap-4", "session-1").value().won);
    // A generous future TTL: lease_until is well ahead of now(), so neither
    // predicate (a) (needs lease_until IS NOT NULL and past grace) nor (b)
    // (needs lease_until IS NULL) applies.
    REQUIRE(
        fx.store().announce_connected("agent-reap-4", "session-1", "c1", "n1", 3600).value().matched);

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->expired_leases_reaped == 0);
    CHECK(out->tombstones_reaped == 0);
    CHECK_FALSE(out->clock_anomaly);

    auto row = fx.store().lookup_route("agent-reap-4");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    REQUIRE((*row)->session_id.has_value());
    CHECK(*(*row)->session_id == "session-1");
    CHECK_FALSE((*row)->is_stale);
}

// Bulk-insert kReapCap(5000)+1 expired-lease rows directly via SQL — looping
// register_fresh/announce_connected 5001 times would make this test the slow
// part of the suite (test_result_set_store.cpp's GC-sweep-cap idiom, part 5
// of the clock-guarded-retention rule: the cap is the half that ALWAYS
// applies).
TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes caps the expired-lease sweep at kReapCap",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    fx.raw_bulk_insert_expired(5001, "agent-reapcap");

    auto first = fx.store().reap_stale_routes();
    REQUIRE(first.has_value());
    CHECK(first->expired_leases_reaped == 5000); // capped exactly at kReapCap
    CHECK_FALSE(first->clock_anomaly);
    // PR #4299 round 4: the cap-bound EXISTS probe fired (a sweep hit kReapCap)
    // and confirmed a real remainder (the 5001st row) — surfaced as
    // ReapRoutesResult::cap_bound (-> outcome="ok_capped"), observability only.
    CHECK(first->cap_bound);

    auto second = fx.store().reap_stale_routes();
    REQUIRE(second.has_value());
    CHECK(second->expired_leases_reaped == 1); // second pass drains the remainder
    CHECK_FALSE(second->cap_bound); // below the cap this pass -> no hidden backlog
}

// ---------------------------------------------------------------------------
// Governance fix #2 (cpp-safety/quality-engineer/unhappy-path): drive
// clock_anomaly == true via all four seeded-anchor scenarios the reviewers
// named. Every case first runs ONE clean pass to establish a real persisted
// anchor (part 6 PROCEEDs on the first/no-anchor pass, so the anomaly guards
// below need a pre-existing anchor to compare against), seeds a LIVE row
// (future lease) and a genuinely-STALE row (past grace) so a declined pass's
// "touches nothing" guarantee is checked against both shapes, then asserts:
// clock_anomaly, zero reaps, the anchor byte-for-byte unchanged, and both
// rows untouched.

TEST_CASE("GatewayRouteStore[pg]: reap declines a forward-skew anomaly ONCE, then RECOVERS "
          "and drains on an identical repeat (decline-once/drain-on-repeat, PR #4299 review "
          "BLOCKER 1)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes(); // establishes a real anchor
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-fwd-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-fwd-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);
    REQUIRE(fx.store().register_fresh("agent-fwd-stale", "s-stale").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-fwd-stale", "s-stale", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-fwd-stale", 200); // past the 180s grace

    // now_ms - anchor > kMaxPlausibleSkewMs (1 day): poison the anchor 2 days
    // behind the current DB clock.
    const std::string poisoned = std::to_string(fx.raw_db_now_ms() - 2LL * 24 * 3600 * 1000);
    fx.raw_set_reap_anchor(poisoned);

    // Pass 1: DECLINES — identical to the pre-fix behaviour. The anchor is
    // frozen and nothing is reaped.
    auto out1 = fx.store().reap_stale_routes();
    REQUIRE(out1.has_value());
    CHECK(out1->clock_anomaly);
    CHECK(out1->expired_leases_reaped == 0);
    CHECK(out1->tombstones_reaped == 0);

    auto anchor_after1 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after1.has_value());
    CHECK(*anchor_after1 == poisoned); // a declined pass never advances the anchor

    auto live1 = fx.store().lookup_route("agent-fwd-live");
    REQUIRE(live1.has_value());
    REQUIRE(live1->has_value());
    REQUIRE((*live1)->session_id.has_value());
    CHECK(*(*live1)->session_id == "s-live");
    auto stale1 = fx.store().lookup_route("agent-fwd-stale");
    REQUIRE(stale1.has_value());
    REQUIRE(stale1->has_value());
    REQUIRE((*stale1)->session_id.has_value());
    CHECK(*(*stale1)->session_id == "s-stale"); // NOT tombstoned by the declined pass

    // Reading-continuity window (PR #4299 round 4): an IMMEDIATE second pass is
    // BELOW the recovery floor (delta < kMinReapRecoveryGapMs) and would decline
    // again — the floor stops an e-later pass free-riding with no persistence
    // evidence. Pass 1 armed the marker at its own (real, ~now) first_now_ms;
    // push that reading ~300s into the past (still the SAME anchor:forward pair)
    // so pass 2's delta lands inside the window and recovery genuinely fires,
    // without sleeping 4.5 real minutes.
    {
        auto m1 = fx.raw_get_reap_declined_anchor();
        REQUIRE(m1.has_value());
        CHECK(m1->rfind(poisoned + ":forward:", 0) == 0); // 3-field, armed by pass 1
        fx.raw_set_reap_declined_anchor(marker3(poisoned, "forward", fx.raw_db_now_ms() - 300'000));
    }

    // Pass 2: the anchor is STILL the same poisoned value (pass 1 never
    // advanced it), and the anomaly has now PERSISTED a plausible interval —
    // exactly what BLOCKER 1's fix (+ the round-4 window) treats as genuine
    // elapsed downtime — this is the recovery this fix exists to provide;
    // without it, this pass would decline forever (the pre-fix wedge).
    auto out2 = fx.store().reap_stale_routes();
    REQUIRE(out2.has_value());
    CHECK_FALSE(out2->clock_anomaly); // recovered, not a further decline
    CHECK(out2->expired_leases_reaped == 1); // agent-fwd-stale, past grace
    CHECK(out2->tombstones_reaped == 0);

    auto live2 = fx.store().lookup_route("agent-fwd-live");
    REQUIRE(live2.has_value());
    REQUIRE(live2->has_value());
    REQUIRE((*live2)->session_id.has_value());
    CHECK(*(*live2)->session_id == "s-live"); // untouched — its lease is not expired

    auto stale2 = fx.store().lookup_route("agent-fwd-stale");
    REQUIRE(stale2.has_value());
    REQUIRE(stale2->has_value());
    CHECK_FALSE((*stale2)->session_id.has_value()); // tombstoned by the recovered pass

    // The anchor re-anchored to (approximately) the current DB clock —
    // UNCONDITIONALLY, not max(anchor, now_ms), which would have left it
    // stuck at the poisoned value forever.
    auto anchor_after2 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after2.has_value());
    const std::int64_t anchor2 = std::strtoll(anchor_after2->c_str(), nullptr, 10);
    const std::int64_t poisoned_val = std::strtoll(poisoned.c_str(), nullptr, 10);
    CHECK(anchor2 > poisoned_val + 1LL * 24 * 3600 * 1000); // re-anchored, not stuck
}

TEST_CASE("GatewayRouteStore[pg]: a routine >24h gap between accepted passes (weekend "
          "shutdown / DR failover / extended maintenance) declines once then recovers, "
          "draining ONLY the genuinely-expired row (PR #4299 review BLOCKER 1)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes(); // establishes a real anchor
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-gap-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-gap-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);
    REQUIRE(fx.store().register_fresh("agent-gap-expired", "s-expired").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-gap-expired", "s-expired", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-gap-expired", 200); // past the 180s grace

    // Simulate a routine >24h gap between accepted passes — NOT clock
    // corruption, just a server that was down/idle for a bit over a day, so
    // the last accepted anchor is now stale relative to the real DB clock.
    const std::int64_t now_before = fx.raw_db_now_ms();
    const std::string stale_anchor = std::to_string(now_before - 25LL * 3600 * 1000);
    fx.raw_set_reap_anchor(stale_anchor);

    // Pass 1: declines — the forward-skew guard cannot yet distinguish a
    // real gap from a clock glitch on the first observation.
    auto out1 = fx.store().reap_stale_routes();
    REQUIRE(out1.has_value());
    CHECK(out1->clock_anomaly);
    CHECK(out1->expired_leases_reaped == 0);
    CHECK(out1->tombstones_reaped == 0);
    auto anchor_after1 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after1.has_value());
    CHECK(*anchor_after1 == stale_anchor);

    // Round-4 recovery window: push pass 1's armed first_now_ms ~300s into the
    // past (same stale_anchor:forward pair) so the identical anomaly is now seen
    // to have PERSISTED a plausible interval, rather than recovering on an
    // immediate (below-floor) repeat.
    {
        auto m1 = fx.raw_get_reap_declined_anchor();
        REQUIRE(m1.has_value());
        CHECK(m1->rfind(stale_anchor + ":forward:", 0) == 0);
        fx.raw_set_reap_declined_anchor(marker3(stale_anchor, "forward", fx.raw_db_now_ms() - 300'000));
    }

    // Pass 2: the identical anomaly persisted a plausible interval — RECOVERS,
    // draining only the row that is genuinely past its grace window.
    auto out2 = fx.store().reap_stale_routes();
    REQUIRE(out2.has_value());
    CHECK_FALSE(out2->clock_anomaly);
    CHECK(out2->expired_leases_reaped == 1);
    CHECK(out2->tombstones_reaped == 0);

    auto live = fx.store().lookup_route("agent-gap-live");
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    REQUIRE((*live)->session_id.has_value());
    CHECK(*(*live)->session_id == "s-live"); // untouched

    auto expired = fx.store().lookup_route("agent-gap-expired");
    REQUIRE(expired.has_value());
    REQUIRE(expired->has_value());
    CHECK_FALSE((*expired)->session_id.has_value()); // tombstoned

    auto anchor_after2 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after2.has_value());
    const std::int64_t anchor2 = std::strtoll(anchor_after2->c_str(), nullptr, 10);
    CHECK(anchor2 >= now_before); // re-anchored to ~now, not stuck at the stale value
}

TEST_CASE("GatewayRouteStore[pg]: a single glitched forward-skew pass reaps NOTHING at all, "
          "even with many genuinely-expired rows present — the guard still prevents a "
          "mass-reap on the one declined pass (PR #4299 review BLOCKER 1)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes();
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    // Bulk-seed a pile of genuinely sweep-(a)-eligible rows — if the
    // decline-once/drain-on-repeat fix regressed into "decline only holds
    // back the first row" or some other partial-suppression bug, this shape
    // catches it: every one of these rows is a legitimate reap candidate.
    fx.raw_bulk_insert_expired(50, "agent-glitch-bulk-");
    REQUIRE(fx.store().register_fresh("agent-glitch-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-glitch-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);

    // A single forward-skew glitch (mirrors the existing forward-skew
    // poisoning shape): this ONE pass must decline outright and touch
    // nothing, regardless of how much genuinely-reapable data exists.
    const std::string poisoned = std::to_string(fx.raw_db_now_ms() - 2LL * 24 * 3600 * 1000);
    fx.raw_set_reap_anchor(poisoned);

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->clock_anomaly);
    CHECK(out->expired_leases_reaped == 0);
    CHECK(out->tombstones_reaped == 0);

    // Every one of the 50 genuinely-expired rows survives the single
    // declined pass untouched — the guard does not "let a few through".
    for (int i = 1; i <= 50; ++i) {
        char buf[16];
        std::snprintf(buf, sizeof buf, "%06d", i);
        CHECK(fx.raw_row_exists(std::string("agent-glitch-bulk-") + buf));
    }
    auto live = fx.store().lookup_route("agent-glitch-live");
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    REQUIRE((*live)->session_id.has_value());
    CHECK(*(*live)->session_id == "s-live");
}

TEST_CASE("GatewayRouteStore[pg]: reap declines when the anchor is AHEAD of the DB clock "
          "(backward/poisoned)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes();
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-bwd-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-bwd-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);
    REQUIRE(fx.store().register_fresh("agent-bwd-stale", "s-stale").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-bwd-stale", "s-stale", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-bwd-stale", 200);

    // Anchor 1h AHEAD of the DB clock -> now_ms < anchor -> backward decline.
    const std::string poisoned = std::to_string(fx.raw_db_now_ms() + 3600LL * 1000);
    fx.raw_set_reap_anchor(poisoned);

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->clock_anomaly);
    CHECK(out->expired_leases_reaped == 0);
    CHECK(out->tombstones_reaped == 0);

    auto anchor_after = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after.has_value());
    CHECK(*anchor_after == poisoned);

    auto live = fx.store().lookup_route("agent-bwd-live");
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    REQUIRE((*live)->session_id.has_value());
    CHECK(*(*live)->session_id == "s-live");
    auto stale = fx.store().lookup_route("agent-bwd-stale");
    REQUIRE(stale.has_value());
    REQUIRE(stale->has_value());
    REQUIRE((*stale)->session_id.has_value());
    CHECK(*(*stale)->session_id == "s-stale");
}

// PR #4299 round-2 EXTERNAL review, BLOCKER: recovery MUST be keyed on the
// PAIR (declined anchor value, anomaly DIRECTION), never the anchor value
// alone. The round-2 review's own "FIX C cross-type recovery" test (this
// comment block used to describe it, and used to assert the OPPOSITE of
// what the tests below assert) proved the exact defect this fix closes: a
// backward-skew decline (pass 1) followed by a DIFFERENT, unrelated
// forward-skew reading (pass 2) at the SAME frozen anchor satisfied a
// value-only match and RECOVERED — running the sweeps against pass 2's own
// forward-skewed (implausibly-huge) now_ms, which mass-tombstones live
// leased routes and lets sweep (b) hard-delete pre-existing NULL-lease
// (in-handshake register_fresh'd) rows. A single fresh forward anomaly that
// should decline-once instead drained because an unrelated backward decline
// happened to precede it at the same anchor.
//
// Marker format since round 4: `reap_declined_anchor_ms` stores
// `"<anchor>:<direction>:<first_now_ms>"` (direction in {forward, backward}) —
// see gateway_route_reap_rules.hpp's `parse_declined_marker`. Real forward/backward
// declines are driven exactly like the standalone single-decline tests
// above; a real anchor scalar cannot naturally flip which direction it
// presents on a shortly-after pass (real wall-clock time only advances
// between passes), so a SAME-anchor-DIFFERENT-direction precondition is
// constructed directly via raw_set_reap_anchor + raw_set_reap_declined_anchor
// — the same technique every decline/recover case in this file already uses
// for "whatever a prior pass would have left behind".
TEST_CASE("GatewayRouteStore[pg]: a backward-skew decline followed by a DIFFERENT forward-skew "
          "reading at the SAME anchor RE-DECLINES (never recovers), and a subsequent identical "
          "forward-skew repeat at that anchor then RECOVERS (PR #4299 round-2 external review, "
          "direction-keyed decline-once/drain-on-repeat)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes(); // establishes a real anchor
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);
    CHECK_FALSE(baseline->recovered);

    REQUIRE(fx.store().register_fresh("agent-dir-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-dir-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);
    REQUIRE(fx.store().register_fresh("agent-dir-expired", "s-expired").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-dir-expired", "s-expired", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-dir-expired", 200); // past the 180s grace

    // Pass 1 (REAL backward-skew decline): anchor implausibly AHEAD of the
    // DB clock. Identical mechanism to the standalone backward-decline test
    // above — not manufactured, the store's genuine decline behaviour.
    // Proves the marker is written as "<anchor>:backward".
    const std::string backward_poisoned =
        std::to_string(fx.raw_db_now_ms() + 3600LL * 1000);
    fx.raw_set_reap_anchor(backward_poisoned);

    auto out1 = fx.store().reap_stale_routes();
    REQUIRE(out1.has_value());
    CHECK(out1->clock_anomaly);
    CHECK_FALSE(out1->recovered);
    CHECK(out1->expired_leases_reaped == 0);
    CHECK(out1->tombstones_reaped == 0);
    auto declined_after1 = fx.raw_get_reap_declined_anchor();
    REQUIRE(declined_after1.has_value());
    CHECK(declined_after1->rfind(backward_poisoned + ":backward:", 0) == 0); // 3-field
    auto anchor_after1 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after1.has_value());
    CHECK(*anchor_after1 == backward_poisoned);

    // Construct pass 2's precondition directly: re-seed BOTH meta keys to
    // the SAME new anchor value, positioned FAR BEHIND the current DB clock
    // (forward-skew) — a DIFFERENT anomaly at that anchor than the one the
    // marker (fabricated here to stand in for "whatever pass 1 really
    // froze") records as "backward". Anchor matches; direction does not ->
    // MUST re-decline, never recover. The marker's first_now_ms is seeded
    // IN-WINDOW (~300s ago) so ONLY the direction mismatch — not the recovery
    // floor — can force this decline (round 4).
    const std::string mix_anchor = std::to_string(fx.raw_db_now_ms() - 2LL * 24 * 3600 * 1000);
    fx.raw_set_reap_anchor(mix_anchor);
    fx.raw_set_reap_declined_anchor(marker3(mix_anchor, "backward", fx.raw_db_now_ms() - 300'000));

    auto out2 = fx.store().reap_stale_routes();
    REQUIRE(out2.has_value());
    CHECK(out2->clock_anomaly);     // RE-DECLINES
    CHECK_FALSE(out2->recovered);   // never recovers on a direction mismatch
    CHECK(out2->expired_leases_reaped == 0);
    CHECK(out2->tombstones_reaped == 0);

    // The live row SURVIVES — a wrong recovery here would have run the
    // sweeps against the forward-skewed (implausibly huge) now_ms and
    // mass-tombstoned it.
    auto live_after2 = fx.store().lookup_route("agent-dir-live");
    REQUIRE(live_after2.has_value());
    REQUIRE(live_after2->has_value());
    REQUIRE((*live_after2)->session_id.has_value());
    CHECK(*(*live_after2)->session_id == "s-live");
    // The already-expired row is untouched too — a declined pass reaps
    // nothing, recovered or not.
    auto expired_after2 = fx.store().lookup_route("agent-dir-expired");
    REQUIRE(expired_after2.has_value());
    REQUIRE(expired_after2->has_value());
    REQUIRE((*expired_after2)->session_id.has_value());
    CHECK(*(*expired_after2)->session_id == "s-expired");

    // The marker is RE-ARMED against the new (mix_anchor, forward) pair —
    // never left at the stale "backward" claim.
    auto declined_after2 = fx.raw_get_reap_declined_anchor();
    REQUIRE(declined_after2.has_value());
    CHECK(declined_after2->rfind(mix_anchor + ":forward:", 0) == 0); // 3-field
    auto anchor_after2 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after2.has_value());
    CHECK(*anchor_after2 == mix_anchor); // anchor itself never moves on a decline

    // Pass 2 armed (mix_anchor, forward) at its own ~now first_now_ms; push it
    // ~300s into the past so pass 3's delta clears the recovery floor (round 4)
    // rather than declining on an immediate below-floor repeat.
    fx.raw_set_reap_declined_anchor(marker3(mix_anchor, "forward", fx.raw_db_now_ms() - 300'000));

    // Pass 3: the anchor is still mix_anchor (a decline never advances it) and
    // this pass reads the IDENTICAL forward-skew direction against the IDENTICAL
    // anchor, now PERSISTED a plausible interval -> matches the marker
    // -> RECOVERS this time.
    auto out3 = fx.store().reap_stale_routes();
    REQUIRE(out3.has_value());
    CHECK_FALSE(out3->clock_anomaly);
    CHECK(out3->recovered);
    // UNDER-reaps nothing extra: the recovery branch computes its cutoffs
    // from THIS pass's own (real, current, correct) now_ms, so it reaps
    // exactly what a normal pass would — the genuinely-expired row.
    CHECK(out3->expired_leases_reaped == 1);
    CHECK(out3->tombstones_reaped == 0);

    auto live3 = fx.store().lookup_route("agent-dir-live");
    REQUIRE(live3.has_value());
    REQUIRE(live3->has_value());
    REQUIRE((*live3)->session_id.has_value());
    CHECK(*(*live3)->session_id == "s-live"); // SURVIVES

    auto expired3 = fx.store().lookup_route("agent-dir-expired");
    REQUIRE(expired3.has_value());
    REQUIRE(expired3->has_value());
    CHECK_FALSE((*expired3)->session_id.has_value()); // tombstoned by the recovered pass

    // Recovery re-anchors UNCONDITIONALLY to this pass's real now_ms, moving
    // decisively off the artificially-past mix_anchor, and clears the
    // declined marker.
    auto anchor_after3 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after3.has_value());
    const std::int64_t anchor3 = std::strtoll(anchor_after3->c_str(), nullptr, 10);
    const std::int64_t mix_anchor_val = std::strtoll(mix_anchor.c_str(), nullptr, 10);
    CHECK(anchor3 > mix_anchor_val); // NOT max(anchor, now_ms) -- moved decisively off it
    CHECK_FALSE(fx.raw_get_reap_declined_anchor().has_value());
}

// Symmetry check for the fix above: a forward-skew decline followed by a
// DIFFERENT backward-skew reading at the same anchor must ALSO re-decline —
// the direction check is not one-sided.
TEST_CASE("GatewayRouteStore[pg]: a forward-skew decline followed by a DIFFERENT backward-skew "
          "reading at the SAME anchor RE-DECLINES (symmetry, PR #4299 round-2 external review)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes();
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-sym-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-sym-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);

    // Pass 1 (REAL forward-skew decline).
    const std::string forward_poisoned =
        std::to_string(fx.raw_db_now_ms() - 2LL * 24 * 3600 * 1000);
    fx.raw_set_reap_anchor(forward_poisoned);
    auto out1 = fx.store().reap_stale_routes();
    REQUIRE(out1.has_value());
    CHECK(out1->clock_anomaly);
    CHECK_FALSE(out1->recovered);
    auto declined_after1 = fx.raw_get_reap_declined_anchor();
    REQUIRE(declined_after1.has_value());
    CHECK(declined_after1->rfind(forward_poisoned + ":forward:", 0) == 0); // 3-field

    // Fabricate pass 2: SAME (re-seeded) anchor, now presented as
    // backward-skew, marker still claiming "forward" -> mismatch. first_now_ms
    // seeded IN-WINDOW so only the direction mismatch can force the decline.
    const std::string mix_anchor = std::to_string(fx.raw_db_now_ms() + 3600LL * 1000);
    fx.raw_set_reap_anchor(mix_anchor);
    fx.raw_set_reap_declined_anchor(marker3(mix_anchor, "forward", fx.raw_db_now_ms() - 300'000));

    auto out2 = fx.store().reap_stale_routes();
    REQUIRE(out2.has_value());
    CHECK(out2->clock_anomaly);
    CHECK_FALSE(out2->recovered);

    auto live_after2 = fx.store().lookup_route("agent-sym-live");
    REQUIRE(live_after2.has_value());
    REQUIRE(live_after2->has_value());
    REQUIRE((*live_after2)->session_id.has_value());
    CHECK(*(*live_after2)->session_id == "s-live");

    auto declined_after2 = fx.raw_get_reap_declined_anchor();
    REQUIRE(declined_after2.has_value());
    CHECK(declined_after2->rfind(mix_anchor + ":backward:", 0) == 0); // re-armed, CURRENT direction
}

// A 4-pass strict direction alternation must never accidentally recover:
// every pass declines and the live row survives throughout. PR #4299 round-3
// review caught the PRIOR revision as a FALSE GREEN — it only set the anchor
// per pass (each a fresh, distinct value), so an anchor-value mismatch alone
// always forced the decline and the DIRECTION check was never exercised:
// reverting the direction comparison to anchor-only keying left this test
// green. The fix, per the reviewer: on EVERY leg also seed the declined
// marker AT THE SAME ANCHOR this pass reads, but with the OPPOSITE direction
// to the one this pass will classify. Now the anchor MATCHES the marker on
// every leg, so only the direction comparison can force the decline — revert
// the direction check to anchor-only and each leg RECOVERS instead, flipping
// `recovered` to true and failing the `CHECK_FALSE(out->recovered)` below.
TEST_CASE("GatewayRouteStore[pg]: a 4-pass direction alternation never recovers — the marker's "
          "anchor MATCHES each pass (only the direction check can decline), the live row survives "
          "(PR #4299 round-2 external review; round-3 de-false-greened)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes();
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-alt-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-alt-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);

    const std::int64_t now0 = fx.raw_db_now_ms();
    // Each leg: {anchor value, the direction THIS pass will classify for that
    // anchor}. A value far behind now classifies forward; a value ahead of now
    // classifies backward.
    struct Leg {
        std::string anchor;
        std::string this_pass_direction;
    };
    const Leg legs[4] = {
        {std::to_string(now0 - 2LL * 24 * 3600 * 1000), "forward"},
        {std::to_string(now0 + 1LL * 3600 * 1000), "backward"},
        {std::to_string(now0 - 3LL * 24 * 3600 * 1000), "forward"},
        {std::to_string(now0 + 2LL * 3600 * 1000), "backward"},
    };
    for (const auto& leg : legs) {
        fx.raw_set_reap_anchor(leg.anchor);
        // Seed the marker at the SAME anchor but the OPPOSITE direction, with an
        // IN-WINDOW first_now_ms (~300s ago), so anchor equality holds AND the
        // recovery floor is cleared — leaving ONLY the direction mismatch able to
        // force the decline. (Anchor-only keying would recover here.)
        const std::string opposite = leg.this_pass_direction == "forward" ? "backward" : "forward";
        fx.raw_set_reap_declined_anchor(marker3(leg.anchor, opposite, fx.raw_db_now_ms() - 300'000));

        auto out = fx.store().reap_stale_routes();
        REQUIRE(out.has_value());
        CHECK(out->clock_anomaly);
        CHECK_FALSE(out->recovered); // DISCRIMINATING: true under anchor-only keying
        CHECK(out->expired_leases_reaped == 0);
        CHECK(out->tombstones_reaped == 0);
        // Re-armed with THIS pass's direction, at this anchor (3-field).
        auto marker = fx.raw_get_reap_declined_anchor();
        REQUIRE(marker.has_value());
        CHECK(marker->rfind(leg.anchor + ":" + leg.this_pass_direction + ":", 0) == 0);
    }

    auto live = fx.store().lookup_route("agent-alt-live");
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    REQUIRE((*live)->session_id.has_value());
    CHECK(*(*live)->session_id == "s-live");
}

// Mixed-version / self-heal safety: a LEGACY bare-integer marker (as written
// by a pre-fix binary, or by `raw_set_reap_declined_anchor` directly) is
// unparseable by `parse_declined_marker` (no `:direction` suffix) and MUST
// be treated as absent — re-arming in the new format and declining once
// more, never granting a recovery on anchor-value coincidence alone.
TEST_CASE("GatewayRouteStore[pg]: a legacy bare-integer declined-anchor marker is treated as "
          "absent — declines and re-arms in the new <anchor>:<direction>:<first_now_ms> format",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes();
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-legacy-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-legacy-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);

    // Anchor far behind the clock (forward-skew) with a LEGACY marker whose
    // anchor half matches EXACTLY — under the old anchor-only keying this
    // would have recovered; under the fix it must not, since the legacy
    // value carries no direction and is treated as absent.
    const std::string anchor = std::to_string(fx.raw_db_now_ms() - 2LL * 24 * 3600 * 1000);
    fx.raw_set_reap_anchor(anchor);
    fx.raw_set_reap_declined_anchor(anchor); // bare integer, no ":direction" suffix

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->clock_anomaly);
    CHECK_FALSE(out->recovered);

    auto live = fx.store().lookup_route("agent-legacy-live");
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    REQUIRE((*live)->session_id.has_value());
    CHECK(*(*live)->session_id == "s-live");

    // Re-armed in the NEW 3-field format.
    auto declined_after = fx.raw_get_reap_declined_anchor();
    REQUIRE(declined_after.has_value());
    CHECK(declined_after->rfind(anchor + ":forward:", 0) == 0);
}

// The self-heal path (corrupt/unparseable PERSISTED anchor) clears
// `reap_declined_anchor_ms` unconditionally, regardless of marker format —
// a pre-existing NEW-format (direction-suffixed) marker must not survive a
// self-heal any more than a legacy bare-integer one did before this fix.
TEST_CASE("GatewayRouteStore[pg]: self-heal on a corrupt persisted anchor clears a pre-existing "
          "direction-suffixed declined-anchor marker",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes();
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-selfheal-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-selfheal-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);

    // A stale NEW-format marker recorded against an anchor value that is
    // about to be discarded as corrupt.
    fx.raw_set_reap_declined_anchor("123456789:backward");
    fx.raw_set_reap_anchor("not-a-number");

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->clock_anomaly);
    CHECK_FALSE(out->recovered);

    // Self-heal must clear the combined (anchor, direction) marker exactly
    // as it cleared the legacy bare-anchor one — the freshly re-anchored
    // value must not be judged against a marker recorded against the
    // now-discarded corrupt anchor.
    CHECK_FALSE(fx.raw_get_reap_declined_anchor().has_value());

    auto live = fx.store().lookup_route("agent-selfheal-live");
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    REQUIRE((*live)->session_id.has_value());
    CHECK(*(*live)->session_id == "s-live");
}

// PR #4299 round-2 external review (SHOULD): the advisory lock switched from
// blocking `pg_advisory_xact_lock` to `pg_try_advisory_xact_lock`, matching
// the ReplicaSafe contract (background_jobs.hpp: "all but the holder skip")
// and every sibling single-sweeper store's idiom (response_store.cpp's
// equivalent test is the template for this one). A sibling replica already
// holding the fleet-wide advisory lock must make this pass skip quietly —
// never touching now()/the anchor/the sweeps — and report it via
// `ReapRoutesResult::skipped`, not `clock_anomaly`.
TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes skips quietly when a sibling holds the "
          "advisory lock",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;

    REQUIRE(fx.store().register_fresh("agent-lockskip-stale", "s-stale").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-lockskip-stale", "s-stale", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-lockskip-stale", 200); // past the 180s grace

    yuzu::server::pg::PgConn locker{PQconnectdb(fx.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    {
        yuzu::server::pg::PgResult begin{PQexec(locker.get(), "BEGIN")};
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        yuzu::server::pg::PgResult lock{PQexec(
            locker.get(),
            "SELECT pg_advisory_xact_lock(hashtext('gateway_route_store:reap'))")};
        REQUIRE(lock.status() == PGRES_TUPLES_OK);
    }

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->skipped);
    CHECK_FALSE(out->clock_anomaly);
    CHECK_FALSE(out->recovered);
    CHECK(out->expired_leases_reaped == 0);
    CHECK(out->tombstones_reaped == 0);

    // Nothing was touched — the sibling held the lock before this pass could
    // even read now()/the anchor.
    CHECK(fx.raw_row_exists("agent-lockskip-stale"));
    CHECK_FALSE(fx.raw_get_reap_anchor().has_value());

    yuzu::server::pg::PgResult rollback{PQexec(locker.get(), "ROLLBACK")};
    REQUIRE(rollback.status() == PGRES_COMMAND_OK);

    // With the lock released, a normal pass now runs and reaps the stale row.
    auto out2 = fx.store().reap_stale_routes();
    REQUIRE(out2.has_value());
    CHECK_FALSE(out2->skipped);
    CHECK(out2->expired_leases_reaped == 1);
}

// PR #4299 round-3 review (Codex + Kimi panel, both confirmed): a prior
// revision of this test asserted the persisted anchor stayed "not-a-number"
// forever, which was itself proof of the defect — an unparseable/negative
// PERSISTED anchor declined EVERY pass permanently (the decline-once/
// drain-on-repeat recovery below it is never reached, since this guard runs
// first and always takes the early `return true`). The fix SELF-HEALS: pass
// 1 re-anchors `reap_anchor_ms` to that pass's own sanitised `now_ms` and
// clears any stale `reap_declined_anchor_ms`, declining only that one pass;
// pass 2 then reads back a VALID anchor and runs as an ordinary accepted
// pass with a full grace window. This test proves both halves: the anchor
// is repaired (no longer the junk string) after pass 1, and pass 2 actually
// reaps the genuinely-expired row while leaving the live one untouched.
TEST_CASE("GatewayRouteStore[pg]: reap self-heals a non-numeric (junk) persisted anchor, "
          "then recovers on the next pass",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes();
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-junk-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-junk-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);
    REQUIRE(fx.store().register_fresh("agent-junk-stale", "s-stale").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-junk-stale", "s-stale", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-junk-stale", 200); // past the 180s grace

    fx.raw_set_reap_anchor("not-a-number");

    const std::int64_t now_before = fx.raw_db_now_ms();

    // Pass 1: DECLINES (this pass reaps nothing) but SELF-HEALS the anchor —
    // it must no longer be the junk string, and it must be a plausible
    // now()-based numeric value, not left corrupt for the guard to trip on
    // again next pass.
    auto out1 = fx.store().reap_stale_routes();
    REQUIRE(out1.has_value());
    CHECK(out1->clock_anomaly);
    CHECK_FALSE(out1->recovered);
    CHECK(out1->expired_leases_reaped == 0);
    CHECK(out1->tombstones_reaped == 0);

    auto anchor_after1 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after1.has_value());
    CHECK(*anchor_after1 != "not-a-number");
    const std::int64_t anchor1 = std::strtoll(anchor_after1->c_str(), nullptr, 10);
    CHECK(anchor1 >= now_before);
    CHECK(anchor1 < now_before + 60'000); // sane, not some other garbage value

    // Any stale declined-anchor marker must not survive the self-heal — it
    // was recorded (if at all) against the discarded junk anchor and would
    // otherwise cause a spurious recovery against the freshly re-anchored
    // value.
    CHECK_FALSE(fx.raw_get_reap_declined_anchor().has_value());

    // Neither row was touched by the declined pass.
    auto live1 = fx.store().lookup_route("agent-junk-live");
    REQUIRE(live1.has_value());
    REQUIRE(live1->has_value());
    REQUIRE((*live1)->session_id.has_value());
    CHECK(*(*live1)->session_id == "s-live");
    auto stale1 = fx.store().lookup_route("agent-junk-stale");
    REQUIRE(stale1.has_value());
    REQUIRE(stale1->has_value());
    REQUIRE((*stale1)->session_id.has_value());
    CHECK(*(*stale1)->session_id == "s-stale");

    // Pass 2: an ORDINARY accepted pass against the repaired anchor — reaps
    // the genuinely-expired row, leaves the live one alone. If the anchor
    // were still "not-a-number" this pass would decline again instead.
    auto out2 = fx.store().reap_stale_routes();
    REQUIRE(out2.has_value());
    CHECK_FALSE(out2->clock_anomaly);
    CHECK_FALSE(out2->recovered);
    CHECK(out2->expired_leases_reaped == 1);
    CHECK(out2->tombstones_reaped == 0);

    auto live2 = fx.store().lookup_route("agent-junk-live");
    REQUIRE(live2.has_value());
    REQUIRE(live2->has_value());
    REQUIRE((*live2)->session_id.has_value());
    CHECK(*(*live2)->session_id == "s-live"); // untouched

    auto stale2 = fx.store().lookup_route("agent-junk-stale");
    REQUIRE(stale2.has_value());
    REQUIRE(stale2->has_value());
    CHECK_FALSE((*stale2)->session_id.has_value()); // tombstoned
}

TEST_CASE("GatewayRouteStore[pg]: reap self-heals a negative persisted anchor, then recovers "
          "on the next pass",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes();
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-neg-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-neg-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);
    REQUIRE(fx.store().register_fresh("agent-neg-stale", "s-stale").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-neg-stale", "s-stale", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-neg-stale", 200); // past the 180s grace

    fx.raw_set_reap_anchor("-5");

    const std::int64_t now_before = fx.raw_db_now_ms();

    // Pass 1: DECLINES but SELF-HEALS — the anchor must no longer be
    // negative, and must be a plausible now()-based value.
    auto out1 = fx.store().reap_stale_routes();
    REQUIRE(out1.has_value());
    CHECK(out1->clock_anomaly);
    CHECK_FALSE(out1->recovered);
    CHECK(out1->expired_leases_reaped == 0);
    CHECK(out1->tombstones_reaped == 0);

    auto anchor_after1 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after1.has_value());
    CHECK(*anchor_after1 != "-5");
    const std::int64_t anchor1 = std::strtoll(anchor_after1->c_str(), nullptr, 10);
    CHECK(anchor1 >= now_before);
    CHECK(anchor1 < now_before + 60'000);

    CHECK_FALSE(fx.raw_get_reap_declined_anchor().has_value());

    auto live1 = fx.store().lookup_route("agent-neg-live");
    REQUIRE(live1.has_value());
    REQUIRE(live1->has_value());
    REQUIRE((*live1)->session_id.has_value());
    CHECK(*(*live1)->session_id == "s-live");
    auto stale1 = fx.store().lookup_route("agent-neg-stale");
    REQUIRE(stale1.has_value());
    REQUIRE(stale1->has_value());
    REQUIRE((*stale1)->session_id.has_value());
    CHECK(*(*stale1)->session_id == "s-stale");

    // Pass 2: an ORDINARY accepted pass against the repaired anchor.
    auto out2 = fx.store().reap_stale_routes();
    REQUIRE(out2.has_value());
    CHECK_FALSE(out2->clock_anomaly);
    CHECK_FALSE(out2->recovered);
    CHECK(out2->expired_leases_reaped == 1);
    CHECK(out2->tombstones_reaped == 0);

    auto live2 = fx.store().lookup_route("agent-neg-live");
    REQUIRE(live2.has_value());
    REQUIRE(live2->has_value());
    REQUIRE((*live2)->session_id.has_value());
    CHECK(*(*live2)->session_id == "s-live"); // untouched

    auto stale2 = fx.store().lookup_route("agent-neg-stale");
    REQUIRE(stale2.has_value());
    REQUIRE(stale2->has_value());
    CHECK_FALSE((*stale2)->session_id.has_value()); // tombstoned
}

// ---------------------------------------------------------------------------
// Governance fix #4 (cpp-safety + unhappy-path UP-4): the outer UPDATE in
// sweep (a) re-asserts the expired predicate, not just `agent_id IN (...)` —
// a row renewed to a future lease must never be tombstoned. A prior version
// of this case renewed and COMMITTED before calling reap_stale_routes(),
// which never exercises the re-assert at all: the inner subquery's own
// snapshot already excludes a row that was renewed and committed first, so
// the outer re-check is redundant with the subquery and the case passes
// identically with FIX 4 present or reverted (a false green).
//
// The genuine race needs the renew to land INSIDE the reaper's
// snapshot-to-row-lock window: a concurrent transaction commits a
// future-lease UPDATE only AFTER the reaper's row-lock attempt blocks on it,
// forcing PostgreSQL's EvalPlanQual to re-check the outer UPDATE's WHERE
// against the freshly-committed row version. Deterministic via the #4213
// UP-3 self-heal side-lock pattern: hold the row lock in an open
// transaction, launch the reaper on its own thread, poll pg_stat_activity
// until it is observed genuinely blocked, THEN commit.
TEST_CASE("GatewayRouteStore[pg]: reap does not tombstone a row renewed to a future lease "
          "(outer-UPDATE re-assert, governance fix #4)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-reap-epq", "session-1").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-reap-epq", "session-1", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-reap-epq", 200); // past the 180s grace, committed

    // Holder: BEGINs a future-lease UPDATE on the row and does NOT commit —
    // this takes the row lock while leaving the OLD (expired, committed)
    // lease_until the only version any OTHER transaction can see under READ
    // COMMITTED. The reaper's inner subquery therefore still legitimately
    // selects this agent_id as a candidate.
    yuzu::server::pg::PgConn holder{PQconnectdb(fx.dsn().c_str())};
    REQUIRE(PQstatus(holder.get()) == CONNECTION_OK);
    {
        yuzu::server::pg::PgResult begin{PQexec(holder.get(), "BEGIN")};
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        yuzu::server::pg::PgResult upd{PQexec(
            holder.get(), "UPDATE gateway_route_store.agent_routes SET "
                          "  lease_until = now() + interval '1 hour', updated_at = now() "
                          "WHERE agent_id = 'agent-reap-epq'")};
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
    }

    // Run the reaper on its own thread, against the SAME store (its pool has
    // spare connections beyond the one the holder above uses directly). Its
    // sweep-(a) outer UPDATE selects agent-reap-epq via the subquery, then
    // blocks taking the row lock the holder connection is sitting on.
    std::expected<ReapRoutesResult, GatewayRouteStoreError> out;
    std::thread reaper([&] { out = fx.store().reap_stale_routes(); });

    // Side connection used ONLY to observe pg_stat_activity — never touches
    // the row itself, so its own presence cannot perturb the race.
    yuzu::server::pg::PgConn watcher{PQconnectdb(fx.dsn().c_str())};
    REQUIRE(PQstatus(watcher.get()) == CONNECTION_OK);
    const bool blocked = wait_for_lock_waiter(watcher.get());
    REQUIRE(blocked); // if nothing ever blocks, nothing locked the row, and
                       // the race this test exists to force never happened.

    // Only now does the future-lease version become visible to the blocked
    // reaper — exactly the window governance fix #4's outer-WHERE re-assert
    // defends via EvalPlanQual.
    {
        yuzu::server::pg::PgResult commit{PQexec(holder.get(), "COMMIT")};
        REQUIRE(commit.status() == PGRES_COMMAND_OK);
    }

    reaper.join();

    REQUIRE(out.has_value());
    CHECK_FALSE(out->clock_anomaly);
    // The renewed-under-EPQ row must not be counted as reaped.
    CHECK(out->expired_leases_reaped == 0);

    auto row = fx.store().lookup_route("agent-reap-epq");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    REQUIRE((*row)->session_id.has_value());
    CHECK(*(*row)->session_id == "session-1");
    CHECK_FALSE((*row)->is_stale);
}

// ---------------------------------------------------------------------------
// PR #4299 review, BLOCKER 2 (mechanical): sweep (b) (the NULL-lease/
// tombstone-purge DELETE) was missing the outer-WHERE re-assert sweep (a)
// got from governance fix #4 above — its outer DELETE checked only
// `agent_id IN (...)`, so a route a concurrent register_fresh/
// announce_connected just revived (setting a fresh session_id/updated_at
// while the DELETE was blocked on the row lock) would still be deleted once
// the lock released. Same #4213 UP-3 self-heal side-lock rendezvous pattern
// as the sweep-(a) case above, driving the exact EvalPlanQual window: the
// holder's UPDATE mirrors register_fresh's real re-registration UPSERT
// shape (fresh session_id, lease_until reset to NULL, updated_at = now()) so
// the inner subquery's stale-snapshot candidate becomes, by the time the
// outer DELETE takes the row lock, a row that no longer matches either the
// `lease_until IS NULL`-past-purge-age shape's cutoff (updated_at is now
// fresh) — exactly the case the outer re-assert exists to catch.
TEST_CASE("GatewayRouteStore[pg]: reap does not purge a tombstoned row concurrently revived "
          "by a fresh register_fresh (outer-DELETE re-assert, PR #4299 review BLOCKER 2)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    // Deliberately NEVER calls announce_connected — `home_cluster_id` stays
    // NULL throughout, so this row is a genuine sweep-(b) hard-delete
    // candidate under the #4669 pr-rev fix above (which excludes any row
    // carrying a bound `home_cluster_id` from sweep (b) entirely — see that
    // fix's comment). A row that HAD confirmed a cluster would instead match
    // the new affinity-preserving sweep (b') and never take a row lock this
    // test's race depends on; see "reap_stale_routes' affinity-preserving
    // soft-tombstone" below for that coverage.
    REQUIRE(fx.store().register_fresh("agent-reap-epq-b", "session-b1").value().won);
    REQUIRE(fx.store().deregister("agent-reap-epq-b", "session-b1").value().removed);
    // Past the 300s tombstone purge age, committed — a genuine sweep-(b)
    // candidate as far as any snapshot taken before the revive below is
    // concerned.
    fx.raw_set_updated_at_ago("agent-reap-epq-b", 400);

    // Holder: BEGINs a revive UPDATE on the row and does NOT commit — this
    // takes the row lock while leaving the OLD (tombstoned, committed)
    // updated_at the only version any OTHER transaction can see under READ
    // COMMITTED. The reaper's inner subquery therefore still legitimately
    // selects this agent_id as a sweep-(b) candidate.
    yuzu::server::pg::PgConn holder{PQconnectdb(fx.dsn().c_str())};
    REQUIRE(PQstatus(holder.get()) == CONNECTION_OK);
    {
        yuzu::server::pg::PgResult begin{PQexec(holder.get(), "BEGIN")};
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        // Mirrors register_fresh's real re-registration UPSERT shape: a
        // fresh session_id, lease_until reset to NULL (register_fresh always
        // resets it — the winning connection's own announce_connected/renew
        // sets it later), updated_at = now().
        yuzu::server::pg::PgResult upd{PQexec(
            holder.get(), "UPDATE gateway_route_store.agent_routes SET "
                          "  connection_epoch = connection_epoch + 1, "
                          "  session_id = 'session-b2', lease_until = NULL, updated_at = now() "
                          "WHERE agent_id = 'agent-reap-epq-b'")};
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
    }

    // Run the reaper on its own thread, against the SAME store. Its
    // sweep-(b) outer DELETE selects agent-reap-epq-b via the subquery, then
    // blocks taking the row lock the holder connection is sitting on.
    std::expected<ReapRoutesResult, GatewayRouteStoreError> out;
    std::thread reaper([&] { out = fx.store().reap_stale_routes(); });

    yuzu::server::pg::PgConn watcher{PQconnectdb(fx.dsn().c_str())};
    REQUIRE(PQstatus(watcher.get()) == CONNECTION_OK);
    const bool blocked = wait_for_lock_waiter(watcher.get());

    // Commit (releasing the holder's row lock) and join the reaper thread
    // UNCONDITIONALLY, before any REQUIRE that could throw — an assertion
    // failure throws and unwinds past a still-joinable `std::thread`'s
    // destructor, which calls std::terminate() (SIGABRT) instead of
    // reporting a clean test failure. Only now does the revived version
    // become visible to the blocked reaper — exactly the window BLOCKER 2's
    // outer-WHERE re-assert defends via EvalPlanQual.
    yuzu::server::pg::PgResult commit{PQexec(holder.get(), "COMMIT")};
    const bool committed = commit.status() == PGRES_COMMAND_OK;
    reaper.join();

    REQUIRE(committed);
    REQUIRE(blocked); // if nothing ever blocks, the race this test exists to
                       // force never happened.

    REQUIRE(out.has_value());
    CHECK_FALSE(out->clock_anomaly);
    // The concurrently-revived row must not be counted as purged. THIS IS
    // THE DISCRIMINATING ASSERTION: revert the outer-WHERE re-assert (drop
    // the trailing `AND lease_until IS NULL AND (...) < $1::bigint` from
    // sweep (b)'s DELETE) and this goes to 1 with the row deleted — the test
    // fails without the fix and passes with it.
    CHECK(out->tombstones_reaped == 0);

    REQUIRE(fx.raw_row_exists("agent-reap-epq-b")); // NOT deleted
    auto row = fx.store().lookup_route("agent-reap-epq-b");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    REQUIRE((*row)->session_id.has_value());
    CHECK(*(*row)->session_id == "session-b2"); // the revived session, untouched
}

TEST_CASE("GatewayRouteStore[pg]: migrates from an empty database",
          "[gateway_route][pg][store][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    auto row = store.lookup_route("nonexistent");
    REQUIRE(row.has_value());
    CHECK_FALSE(row->has_value());

    // v2's route_meta anchor table applied too (not just v1's agent_routes).
    yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult r{
        PQexec(conn.get(), "SELECT 1 FROM gateway_route_store.route_meta LIMIT 1")};
    CHECK(r.status() == PGRES_TUPLES_OK); // table exists and is queryable (empty is fine)
}

TEST_CASE("GatewayRouteStore: fail-closed construction against a closed pool",
          "[gateway_route][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    // An unreachable conninfo (bogus port) never connects, so acquire() at
    // construction returns an empty lease and the store must report closed
    // rather than crash or silently pretend to be open (ADR-0012 fail-closed).
    yuzu::server::pg::PgPool pool{
        {.conninfo = "host=127.0.0.1 port=1 dbname=nonexistent connect_timeout=1", .size = 1}};
    GatewayRouteStore store{pool};
    CHECK_FALSE(store.is_open());
}

// Governance fix #5 (quality-engineer QE-5): reap_stale_routes() itself must
// report the same fail-closed store_unavailable a closed/unreachable pool
// gives every other method — mirrors the construction test directly above.
TEST_CASE("GatewayRouteStore: reap_stale_routes fails closed against a closed pool",
          "[gateway_route][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::server::pg::PgPool pool{
        {.conninfo = "host=127.0.0.1 port=1 dbname=nonexistent connect_timeout=1", .size = 1}};
    GatewayRouteStore store{pool};
    REQUIRE_FALSE(store.is_open());
    auto out = store.reap_stale_routes();
    REQUIRE_FALSE(out.has_value());
    CHECK(out.error() == GatewayRouteStoreError::store_unavailable);
}
