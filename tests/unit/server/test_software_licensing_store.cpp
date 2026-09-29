// SoftwareLicensingStore tests (ADR-0024 Decisions 3/4/7/8): the born-on-
// Postgres detected-licence store — migration-at-construction, the raw-blob
// hash-skip trichotomy primitives (stored/touched/need-full), atomic
// full-replace, the C-10 staleness read, the posture-rollup replace, the
// (product_key, kind) alert-dedup state, the decommission delete_agent, and
// the authoritative-read posture (nullopt/kDegraded on a degrade, never a
// silent empty).

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_licensing_store.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::AgentLicenseRow;
using yuzu::server::LicensingReadError;
using yuzu::server::SoftwareLicensingStore;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

std::int64_t epoch_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// A fully-populated detected-licence row (every §7.2 column non-trivial) for
// the round-trip fixtures — includes exe_hints (roadmap R6) and the per-user
// fields, plus text[]-literal metacharacters to exercise the batched-insert
// escaping end-to-end.
AgentLicenseRow full_row() {
    AgentLicenseRow r;
    r.product = "Office 365 ProPlus";
    r.vendor = "Microsoft, \"Inc\"\\{Corp}"; // array metacharacters must round-trip
    r.version = "16.0.1";
    r.license_type = "subscription";
    r.state = "subscription_active";
    r.expiry_at = 1893456000; // 2030-01-01
    r.channel = "KMS";
    r.key_hint = "XXXXX-B7GJQ";
    r.detector = "wmi_slp";
    r.confidence = "probable"; // closed §3.2 set — stored from migration v1
    r.exe_hints = "winword.exe;excel.exe";
    r.user_scope = "user";
    r.user_ref = "a1b2c3d4e5f60718"; // keyed-HMAC pseudonym form
    r.collected_at = 1751000000;
    return r;
}

AgentLicenseRow small_row(const std::string& product, const std::string& state,
                          std::int64_t expiry_at = 0) {
    AgentLicenseRow r;
    r.product = product;
    r.vendor = "V";
    r.license_type = "perpetual";
    r.state = state;
    r.expiry_at = expiry_at;
    r.user_scope = "machine";
    return r;
}

// ── Shared pre-migrated fixture (behaviour-preserving DB-provisioning swap) ──
// One migrated clone + one persistent pool for the whole FILE, TRUNCATE-reset
// between tests instead of a fresh CREATE DATABASE + new pool per test — the
// same substrate swap already applied in test_software_inventory_store.cpp.
// Behaviour-preserving: identical store calls + CHECKs; only the DB
// provisioning/isolation substrate changes. At testRunEnded the pool is drained
// and the clone dropped (keep_until_run_end), leaving static destruction inert. CARVE-OUTS
// that DROP SCHEMA / wipe public.schema_meta / hold a SESSION advisory lock are
// NOT converted — TRUNCATE cannot undo DDL and schema_meta lives in `public`,
// so they keep their own per-test database (YUZU_REQUIRE_PG_DB).
yuzu::test::PgTestTemplate sle_tpl{"slestore", [](const std::string& dsn) {
                                       PgPool pool{{.conninfo = dsn, .size = 1}};
                                       SoftwareLicensingStore store{pool};
                                       // Throw, don't return: a silently-unmigrated template would
                                       // make every clone fall back to in-test migration — correct
                                       // but slow, defeating the point.
                                       if (!store.is_open())
                                           throw std::runtime_error(
                                               "slestore template: store failed to migrate");
                                   }};

struct SleShared {
    yuzu::test::PostgresTestDb db{sle_tpl};
    std::optional<PgPool> pool;
    SleShared() {
        REQUIRE(db.available());
        pool.emplace(PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
SleShared& sle_shared() {
    static SleShared s;
    return s;
}

// Restore the shared DB to its fresh-clone state: TRUNCATE both data tables.
// public.schema_meta is deliberately untouched, so the per-test store ctor finds
// the schema current and skips migration (a cheap SELECT, no new backend).
void sle_reset() {
    auto lease = sle_shared().pool->acquire();
    REQUIRE(lease);
    auto trunc = pg::exec_params(lease.get(),
                                 "TRUNCATE software_licensing_store.agent_license_state, "
                                 "software_licensing_store.agent_licenses RESTART IDENTITY CASCADE",
                                 std::vector<std::string>{});
    REQUIRE(trunc.status() == PGRES_COMMAND_OK);
}

// Preamble for a convertible test: same skip contract as YUZU_REQUIRE_PG_DB,
// then TRUNCATE-reset the shared DB and bind `pool` (reference to the persistent
// pool) + `store` (fresh; the ctor's migration check is a no-op on the already-
// migrated clone). `pool` is [[maybe_unused]] — most tests only touch `store`.
#define SLE_SHARED(store, pool)                                                                    \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                              \
    sle_reset();                                                                                   \
    [[maybe_unused]] PgPool& pool = *sle_shared().pool;                                            \
    SoftwareLicensingStore store{pool};                                                            \
    REQUIRE(store.is_open())

} // namespace

TEST_CASE("SoftwareLicensingStore migrates at construction and reopens idempotently",
          "[pg][software_licensing]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    {
        SoftwareLicensingStore s1{pool};
        REQUIRE(s1.is_open());
    }
    SoftwareLicensingStore s2{pool};
    CHECK(s2.is_open());
    auto stale = s2.count_stale_agents(epoch_now());
    REQUIRE(stale.has_value());
    CHECK(*stale == 0);
}

TEST_CASE("SoftwareLicensingStore replace + read-back round-trips every §7.2 column",
          "[pg][software_licensing]") {
    SLE_SHARED(store, pool);

    const AgentLicenseRow in = full_row();
    REQUIRE(store.replace_agent_licenses("agent-a", {in}, "rawhash-1", "hash"));

    auto got = store.agent_licenses("agent-a");
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 1);
    const auto& g = (*got)[0];
    CHECK(g.product == in.product);
    CHECK(g.vendor == in.vendor); // metacharacters survived the text[] literal
    CHECK(g.version == in.version);
    CHECK(g.license_type == in.license_type);
    CHECK(g.state == in.state);
    CHECK(g.expiry_at == in.expiry_at);
    CHECK(g.channel == in.channel);
    CHECK(g.key_hint == in.key_hint);
    CHECK(g.detector == in.detector);
    CHECK(g.confidence == in.confidence); // persisted from migration v1 (ADR-0024 D1/2/7)
    CHECK(g.exe_hints == in.exe_hints);   // persisted from migration v1 (R6)
    CHECK(g.user_scope == in.user_scope);
    CHECK(g.user_ref == in.user_ref);
    CHECK(g.collected_at == in.collected_at);
    CHECK(g.first_seen > 0); // store-stamped server receipt time
    CHECK(g.last_seen == g.first_seen);

    // An empty agent_id is a precondition miss → empty VALUE, not a degrade.
    auto empty_id = store.agent_licenses("");
    REQUIRE(empty_id.has_value());
    CHECK(empty_id->empty());
}

TEST_CASE("SoftwareLicensingStore hash-skip trichotomy primitives (raw-blob hash, D-2)",
          "[pg][software_licensing]") {
    SLE_SHARED(store, pool);

    SECTION("cold cache: stored_hash returns an ABSENT value (→ the seam answers need_full)") {
        auto h = store.stored_hash("agent-cold");
        REQUIRE(h.has_value());      // read succeeded — not a degrade
        CHECK_FALSE(h->has_value()); // no state row yet
    }

    SECTION("stored: replace persists the seam's raw-byte hash VERBATIM — no recompute, "
            "no normalisation") {
        // Deliberately NOT a lowercase-hex digest: the store must persist the
        // seam-supplied bytes untouched (the raw-blob contract keeps hashing
        // entirely in the seam; a store-side canonicalisation would desync the
        // compare).
        const std::string raw = "RawBlobHash-MiXeDcAsE-0042";
        REQUIRE(store.replace_agent_licenses("agent-b", {small_row("P", "licensed")}, raw, "hash"));
        auto h = store.stored_hash("agent-b");
        REQUIRE(h.has_value());
        REQUIRE(h->has_value());
        CHECK(**h == raw);
    }

    SECTION("touched: touch bumps ONLY the state row's last_seen (server receipt time)") {
        REQUIRE(store.replace_agent_licenses("agent-c", {small_row("P", "licensed")}, "h1", "cfg"));
        const std::int64_t now = epoch_now();
        // Backdate the state row so the bump is observable without sleeping.
        {
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            pg::PgResult upd = pg::exec_params(
                lease.get(),
                "UPDATE software_licensing_store.agent_license_state SET last_seen = 1000 "
                "WHERE agent_id = 'agent-c'",
                std::vector<std::string>{});
            REQUIRE(upd.status() == PGRES_COMMAND_OK);
        }
        auto stale = store.count_stale_agents(now - 5);
        REQUIRE(stale.has_value());
        CHECK(*stale == 1); // backdated → stale
        REQUIRE(store.touch("agent-c"));
        auto fresh = store.count_stale_agents(now - 5);
        REQUIRE(fresh.has_value());
        CHECK(*fresh == 0); // touched back to ~now
        // The stored hash is untouched by a touch.
        auto h = store.stored_hash("agent-c");
        REQUIRE(h.has_value());
        REQUIRE(h->has_value());
        CHECK(**h == "h1");
    }

    SECTION("touch on a missing state row returns false (seam sequencing guard)") {
        CHECK_FALSE(store.touch("agent-never"));
    }
}

TEST_CASE("SoftwareLicensingStore full-replace is atomic per agent and preserves first_seen",
          "[pg][software_licensing]") {
    SLE_SHARED(store, pool);

    REQUIRE(store.replace_agent_licenses(
        "agent-r", {small_row("Old-A", "licensed"), small_row("Old-B", "trial")}, "h1", "hash"));
    // A bystander that must survive every replace/delete below — the minimal
    // proof the DELETE is agent-scoped.
    REQUIRE(store.replace_agent_licenses("agent-bystander", {small_row("Keep", "licensed")}, "hb",
                                         "omit"));

    SECTION("a second replace atomically swaps the row set — old rows gone") {
        REQUIRE(
            store.replace_agent_licenses("agent-r", {small_row("New-C", "grace")}, "h2", "hash"));
        auto got = store.agent_licenses("agent-r");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].product == "New-C");
        auto h = store.stored_hash("agent-r");
        REQUIRE(h.has_value());
        REQUIRE(h->has_value());
        CHECK(**h == "h2");
        auto by = store.agent_licenses("agent-bystander");
        REQUIRE(by.has_value());
        REQUIRE(by->size() == 1);
        CHECK((*by)[0].product == "Keep");
    }

    SECTION("replace-to-empty is a legitimate state: zero rows, state row intact") {
        REQUIRE(store.replace_agent_licenses("agent-r", {}, "h-empty", "hash"));
        auto got = store.agent_licenses("agent-r");
        REQUIRE(got.has_value());
        CHECK(got->empty()); // an empty VALUE — a genuine zero, not a degrade
        auto h = store.stored_hash("agent-r");
        REQUIRE(h.has_value());
        REQUIRE(h->has_value());
        CHECK(**h == "h-empty"); // the parent survived the wipe (hash-skip stays armed)
    }

    SECTION("the state row's first_seen survives replaces; last_seen refreshes") {
        { // backdate both stamps, then replace again
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            pg::PgResult upd = pg::exec_params(
                lease.get(),
                "UPDATE software_licensing_store.agent_license_state "
                "SET first_seen = 1000, last_seen = 1000 WHERE agent_id = 'agent-r'",
                std::vector<std::string>{});
            REQUIRE(upd.status() == PGRES_COMMAND_OK);
        }
        REQUIRE(
            store.replace_agent_licenses("agent-r", {small_row("New", "licensed")}, "h3", "hash"));
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult sel = pg::exec_params(
            lease.get(),
            "SELECT first_seen, last_seen FROM software_licensing_store.agent_license_state "
            "WHERE agent_id = 'agent-r'",
            std::vector<std::string>{});
        REQUIRE(sel.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(sel.get()) == 1);
        CHECK(std::string(PQgetvalue(sel.get(), 0, 0)) == "1000"); // first_seen preserved
        CHECK(std::string(PQgetvalue(sel.get(), 0, 1)) != "1000"); // last_seen refreshed
    }
}

TEST_CASE("SoftwareLicensingStore persists the effective user-ref mode on the state row (D-10)",
          "[pg][software_licensing]") {
    SLE_SHARED(store, pool);

    const auto read_mode = [&]() -> std::string {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult sel = pg::exec_params(
            lease.get(),
            "SELECT effective_user_ref_mode FROM software_licensing_store.agent_license_state "
            "WHERE agent_id = 'agent-m'",
            std::vector<std::string>{});
        REQUIRE(sel.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(sel.get()) == 1);
        return PQgetvalue(sel.get(), 0, 0);
    };

    REQUIRE(store.replace_agent_licenses("agent-m", {small_row("P", "licensed")}, "h1", "hash"));
    CHECK(read_mode() == "hash");
    // A config change on the agent flips the blob's cfg| record → the next
    // stored replace updates the persisted mode.
    REQUIRE(store.replace_agent_licenses("agent-m", {small_row("P", "licensed")}, "h2", "omit"));
    CHECK(read_mode() == "omit");
}

TEST_CASE("SoftwareLicensingStore distinct_products dedups (product, vendor) across the fleet",
          "[pg][software_licensing]") {
    SLE_SHARED(store, pool);

    REQUIRE(store.replace_agent_licenses(
        "agent-1", {small_row("Alpha", "licensed"), small_row("Beta", "trial")}, "h1", "hash"));
    REQUIRE(store.replace_agent_licenses("agent-2", {small_row("Alpha", "expired")}, "h2", "hash"));

    auto dp = store.distinct_products();
    REQUIRE(dp.has_value());
    REQUIRE(dp->size() == 2); // Alpha appears once despite two agents
    CHECK((*dp)[0].product == "Alpha");
    CHECK((*dp)[0].vendor == "V");
    CHECK((*dp)[1].product == "Beta");
}

TEST_CASE("SoftwareLicensingStore delete_agent removes child rows AND the state row, agent-scoped",
          "[pg][software_licensing]") {
    SLE_SHARED(store, pool);

    REQUIRE(store.replace_agent_licenses(
        "agent-del", {small_row("A", "licensed"), small_row("B", "expired")}, "hd", "hash"));
    REQUIRE(store.replace_agent_licenses("agent-bystander", {small_row("Keep", "licensed")}, "hb",
                                         "hash"));

    CHECK(store.delete_agent("agent-del")); // committed → true

    auto post = store.agent_licenses("agent-del");
    REQUIRE(post.has_value()); // store open + query OK → empty VALUE, not a degrade
    CHECK(post->empty());      // child rows gone
    auto h = store.stored_hash("agent-del");
    REQUIRE(h.has_value());
    CHECK_FALSE(h->has_value()); // state row gone → next hash-only report is a cold cache

    // Cross-agent isolation: the bystander survives with parent + children.
    auto by = store.agent_licenses("agent-bystander");
    REQUIRE(by.has_value());
    REQUIRE(by->size() == 1);
    auto bh = store.stored_hash("agent-bystander");
    REQUIRE(bh.has_value());
    REQUIRE(bh->has_value());
    CHECK(**bh == "hb");

    // Deleting an unknown agent is a best-effort no-op, not a throw — a 0-row
    // DELETE still commits, so it reports success.
    CHECK(store.delete_agent("agent-never-existed"));
}

TEST_CASE("SoftwareLicensingStore delete_agent serialises against an in-flight ingest via the "
          "SAME per-agent advisory lock (erasure race, D-11)",
          "[pg][software_licensing][decommission]") {
    // ADR-0024 Decision-11 erasure guarantee: a decommission racing an in-flight
    // full-replace ingest for the SAME agent must not let the ingest re-insert the
    // just-erased user_ref PII. delete_agent and replace_agent_licenses both take
    // the identical per-agent advisory lock ('software_licensing:' || agent_id);
    // this test holds that EXACT lock on a peer session and proves delete_agent
    // blocks on it. A drift in the key derivation — or a missing lock — would let
    // delete race past the peer and this assertion would flip.
    // Not a migration test (uses the pre-migrated template, not a fresh
    // migration) — kept off the Windows migration-skip list.
    YUZU_REQUIRE_PG_DB_TPL(db, sle_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareLicensingStore store{pool};
    REQUIRE(store.is_open());

    // Seed an agent carrying user_ref PII (full_row(): user_scope=user).
    REQUIRE(store.replace_agent_licenses("agent-erase", {full_row()}, "h1", "hash"));

    // Peer session holds the EXACT advisory lock replace_agent_licenses / delete_agent
    // derive. A session-level advisory lock conflicts across sessions with
    // delete_agent's transaction-level lock on the same key.
    auto holder = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(holder);
    REQUIRE(
        pg::exec_params(holder.get(),
                        "SELECT pg_advisory_lock(hashtextextended('software_licensing:' || $1, 0))",
                        std::vector<std::string>{"agent-erase"})
            .status() == PGRES_TUPLES_OK);

    std::atomic<bool> done{false};
    std::thread eraser([&] {
        // Return value deliberately ignored here: Catch2 assertion macros are not
        // thread-safe off the main thread, and this test asserts the LOCK-BLOCKING
        // behaviour via `done`, not the commit status.
        (void)store.delete_agent("agent-erase");
        done.store(true, std::memory_order_release);
    });

    // While the peer holds the lock, delete_agent MUST block on the same key — it
    // has not run any DELETE yet, so the PII is still present. If delete took no
    // lock it would have erased and finished immediately (done == true here).
    std::this_thread::sleep_for(std::chrono::milliseconds{400});
    CHECK_FALSE(done.load(std::memory_order_acquire));
    {
        auto mid = store.agent_licenses("agent-erase");
        REQUIRE(mid.has_value());
        CHECK(mid->size() == 1); // not yet erased — the delete is waiting on the lock
    }

    // Release the peer lock → delete_agent unblocks and completes the erasure.
    REQUIRE(pg::exec_params(
                holder.get(),
                "SELECT pg_advisory_unlock(hashtextextended('software_licensing:' || $1, 0))",
                std::vector<std::string>{"agent-erase"})
                .status() == PGRES_TUPLES_OK);
    eraser.join();
    CHECK(done.load(std::memory_order_acquire));

    // Erasure complete and deterministic: child PII rows gone, state row gone.
    auto gone = store.agent_licenses("agent-erase");
    REQUIRE(gone.has_value());
    CHECK(gone->empty());
    auto h = store.stored_hash("agent-erase");
    REQUIRE(h.has_value());
    CHECK_FALSE(h->has_value());
}

TEST_CASE("SoftwareLicensingStore count_stale_agents keys on server-receipt last_seen (C-10)",
          "[pg][software_licensing]") {
    SLE_SHARED(store, pool);

    const std::int64_t now = epoch_now();
    // A skewed agent claims a far-future collected_at — it must NOT drive the
    // freshness stamp (#1685 posture, baked in from day one).
    AgentLicenseRow skewed = small_row("P", "licensed");
    skewed.collected_at = now + 100'000'000;
    REQUIRE(store.replace_agent_licenses("agent-skew", {skewed}, "h1", "hash"));
    REQUIRE(
        store.replace_agent_licenses("agent-honest", {small_row("Q", "licensed")}, "h2", "hash"));

    auto fresh = store.count_stale_agents(now - 1000);
    REQUIRE(fresh.has_value());
    CHECK(*fresh == 0); // both last_seen ≈ now

    auto all = store.count_stale_agents(now + 50'000'000);
    REQUIRE(all.has_value());
    CHECK(*all == 2); // both below a future cutoff — the skewed collected_at is inert

    { // backdate one agent's SERVER last_seen 10 days
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::PgResult upd = pg::exec_params(
            lease.get(),
            "UPDATE software_licensing_store.agent_license_state SET last_seen = $2::bigint "
            "WHERE agent_id = $1",
            std::vector<std::string>{"agent-honest", std::to_string(now - 10 * 86'400)});
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
    }
    auto window = store.count_stale_agents(now - 2 * 86'400);
    REQUIRE(window.has_value());
    CHECK(*window == 1);
}

TEST_CASE("SoftwareLicensingStore reads are AUTHORITATIVE: degrade ≠ empty; writes fail soft",
          "[pg][software_licensing]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sle_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareLicensingStore store{pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    REQUIRE(store.replace_agent_licenses("agent-a", {small_row("P", "licensed")}, "h1", "hash"));

    SECTION("genuine zero-row reads are empty VALUES / absent, not degrades") {
        auto rows = store.agent_licenses("no-such-agent");
        REQUIRE(rows.has_value());
        CHECK(rows->empty());
    }

    SECTION("a backend failure (schema dropped) degrades every read — never a silent empty") {
        {
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            pg::PgResult drop =
                pg::exec_params(lease.get(), "DROP SCHEMA software_licensing_store CASCADE",
                                std::vector<std::string>{});
            REQUIRE(drop.status() == PGRES_COMMAND_OK);
        }
        CHECK_FALSE(store.agent_licenses("agent-a").has_value());
        CHECK_FALSE(store.distinct_products().has_value());
        auto h = store.stored_hash("agent-a");
        REQUIRE_FALSE(h.has_value()); // degrade → the seam nacks kError, NOT need_full
        CHECK(h.error() == LicensingReadError::kDegraded);
        CHECK_FALSE(store.count_stale_agents(1'000'000).has_value()); // never a false 0
        // Writes fail SOFT — false, never a throw across the API.
        CHECK_FALSE(
            store.replace_agent_licenses("agent-a", {small_row("P", "licensed")}, "h2", "hash"));
        CHECK_FALSE(store.touch("agent-a"));
        // delete_agent (the live DELETE /sle/agents/{id} erasure primitive) must also
        // fail SOFT on a degraded store — a rolled-back DELETE returns false, so the
        // decommission cascade records `Failed`, never falsely confirming a GDPR-Art.17
        // erasure that did not commit.
        CHECK_FALSE(store.delete_agent("agent-a"));
        // The degraded authoritative reads above bumped the shared read-degrade counter
        // under this source's label (#1675 convention) EXACTLY twice — agent_licenses
        // and distinct_products are the only two reads that emit the counter; stored_hash
        // and count_stale_agents log without bumping, and the writes (replace/touch/
        // delete_agent) are not read-degrades. Pin the exact value, not a lower bound.
        CHECK(metrics
                  .counter("yuzu_inventory_read_degrade_total",
                           {{"reason", "query_error"}, {"source", "software_licensing"}})
                  .value() == 2.0);
    }
}

TEST_CASE("SoftwareLicensingStore store_not_open: constructor failure degrades everything",
          "[pg][software_licensing]") {
    // Force open_=false via the sibling-suite recipe: wipe the schema_meta
    // version record so a fresh construction re-runs v1 DDL over live tables →
    // migration fails → !is_open().
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    {
        SoftwareLicensingStore s1{pool};
        REQUIRE(s1.is_open());
    }
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult del = pg::exec_params(
            lease.get(), "DELETE FROM public.schema_meta WHERE store = 'software_licensing_store'",
            std::vector<std::string>{});
        REQUIRE(del.status() == PGRES_COMMAND_OK);
    }
    SoftwareLicensingStore store{pool};
    REQUIRE_FALSE(store.is_open());
    CHECK_FALSE(store.agent_licenses("agent-a").has_value());
    CHECK_FALSE(store.distinct_products().has_value());
    CHECK_FALSE(store.stored_hash("agent-a").has_value());
    CHECK_FALSE(store.count_stale_agents(1).has_value());
    CHECK_FALSE(store.replace_agent_licenses("agent-a", {}, "h", "hash"));
    CHECK_FALSE(store.touch("agent-a"));
    CHECK_FALSE(store.delete_agent("agent-a")); // an unopened store never confirms erasure
}
