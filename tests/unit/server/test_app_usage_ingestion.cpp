// app_usage ingest seam tests (wave 7 PR7.2, mirrors
// test_software_licensing_ingestion.cpp): the wire parse (field order,
// trailing/extra tolerance, empty-exe_key drop), skip-unknown-record-kinds,
// negative-numeric clamp, the caps (blob/records/fields), the RAW-byte hash
// (stored == sha256(received bytes), NEVER the agent's claim), empty-blob =
// valid replace-to-empty, the hash-skip trichotomy through the store
// primitives, and fail-soft nacking on a degraded store.

#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h"
#include "app_usage_ingestion.hpp"
#include "app_usage_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using yuzu::server::AgentLastUsedRow;
using yuzu::server::AppUsageParse;
using yuzu::server::AppUsageStore;
using yuzu::server::app_usage_raw_hash;
using yuzu::server::ingest_app_usage_report;
using yuzu::server::parse_app_usage_blob;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;
namespace agentpb = yuzu::agent::v1;

namespace {

constexpr const char* kSource = "app_usage";

// Pinned SHA-256 of sample_blob()'s RAW bytes (computed independently via
// `printf ... | sha256sum`, NOT via app_usage_raw_hash, so the test pins the
// algorithm rather than echoing the implementation).
constexpr const char* kPinnedRawHash =
    "a91cd2f459222bd508b524ddd49b26c418c630c2748d4c350548601ae224dba8";
// sha256("") — the state hash after a valid replace-to-empty.
constexpr const char* kEmptyBlobHash =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

std::string rec(std::initializer_list<std::string_view> fields) {
    std::string r;
    bool first = true;
    for (std::string_view f : fields) {
        if (!first)
            r += '\x1f';
        first = false;
        r += f;
    }
    r += '\x1e';
    return r;
}

// A fully-populated `lu|` record — 5 fields after the kind, in wire order:
// exe_key|first_seen|last_seen|run_count_30d|total_seconds_30d.
std::string sample_lu() {
    return rec({"lu", "chrome.exe", "1699000000", "1700000500", "12", "43200"});
}

std::string sample_blob() {
    return rec({"cfg", "scope", "machine"}) + sample_lu();
}

agentpb::InventoryReport full_report(const std::string& claimed_hash, const std::string& blob) {
    agentpb::InventoryReport rpt;
    (*rpt.mutable_content_hashes())[kSource] = claimed_hash;
    (*rpt.mutable_plugin_data())[kSource] = blob;
    return rpt;
}

agentpb::InventoryReport hash_only_report(const std::string& claimed_hash) {
    agentpb::InventoryReport rpt;
    (*rpt.mutable_content_hashes())[kSource] = claimed_hash;
    return rpt;
}

// ── Shared pre-migrated fixture (behaviour-preserving DB-provisioning swap) ──
// One migrated clone + one persistent pool for the whole FILE, TRUNCATE-reset
// between the store-backed [pg] ingest tests instead of a fresh CREATE DATABASE
// + new pool per test (mirrors test_software_licensing_ingestion.cpp). SEPARATE
// template key from test_app_usage_store.cpp: same schema, but a cross-file
// shared-key replay-verification mismatch is an environmental risk on local
// PG16 (see test_software_licensing_ingestion.cpp's comment on the same
// choice) — a distinct key sidesteps it. Behaviour-preserving: identical
// ingest calls + CHECKs; only the DB provisioning/isolation changes. At
// testRunEnded the pool is drained before the clone is dropped
// (keep_until_run_end), leaving static destruction inert. The [parse]/[hash]
// tests need no DB and the degraded-store test uses a deliberately-broken DSN
// — neither is converted.
yuzu::test::PgTestTemplate ausg_ingest_tpl{"ausgingest", [](const std::string& dsn) {
                                               PgPool pool{{.conninfo = dsn, .size = 1}};
                                               AppUsageStore store{pool};
                                               if (!store.is_open())
                                                   throw std::runtime_error(
                                                       "ausgingest template: store failed to "
                                                       "migrate");
                                           }};

struct AusgIngestShared {
    yuzu::test::PostgresTestDb db{ausg_ingest_tpl};
    std::optional<PgPool> pool;
    AusgIngestShared() {
        REQUIRE(db.available());
        pool.emplace(PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
AusgIngestShared& ausg_ingest_shared() {
    static AusgIngestShared s;
    return s;
}

// TRUNCATE both data tables between tests; public.schema_meta is untouched, so
// the per-test store ctor finds the clone migrated and skips migration.
void ausg_ingest_reset() {
    auto lease = ausg_ingest_shared().pool->acquire();
    REQUIRE(lease);
    auto trunc =
        pg::exec_params(lease.get(),
                        "TRUNCATE app_usage_store.usage_state, "
                        "app_usage_store.agent_last_used RESTART IDENTITY CASCADE",
                        std::vector<std::string>{});
    REQUIRE(trunc.status() == PGRES_COMMAND_OK);
}

#define AUSG_INGEST_SHARED(store, pool)                                                            \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                               \
    ausg_ingest_reset();                                                                           \
    [[maybe_unused]] PgPool& pool = *ausg_ingest_shared().pool;                                    \
    AppUsageStore store{pool};                                                                     \
    REQUIRE(store.is_open())

} // namespace

// ── parse: wire shape ────────────────────────────────────────────────────────

TEST_CASE("parse: lu| records project exe_key/first_seen/last_seen/run_count/"
          "total_seconds",
          "[app_usage_ingest][parse]") {
    AppUsageParse p = parse_app_usage_blob(sample_lu());
    REQUIRE(p.rows.size() == 1);
    CHECK_FALSE(p.over_record_cap);
    const AgentLastUsedRow& r = p.rows[0];
    CHECK(r.exe_key == "chrome.exe");
    CHECK(r.first_seen == 1699000000);
    CHECK(r.last_seen == 1700000500);
    CHECK(r.run_count_30d == 12);
    CHECK(r.total_seconds_30d == 43200);
    CHECK(r.collected_at == 0); // the ingest entry point's job, not the parser's
}

TEST_CASE("parse: missing trailing fields default to 0; extra fields are dropped",
          "[app_usage_ingest][parse]") {
    SECTION("short record (old agent): trailing numeric fields default to 0") {
        AppUsageParse p = parse_app_usage_blob(rec({"lu", "chrome.exe", "1699000000"}));
        REQUIRE(p.rows.size() == 1);
        CHECK(p.rows[0].exe_key == "chrome.exe");
        CHECK(p.rows[0].first_seen == 1699000000);
        CHECK(p.rows[0].last_seen == 0);
        CHECK(p.rows[0].run_count_30d == 0);
        CHECK(p.rows[0].total_seconds_30d == 0);
    }
    SECTION("long record (future agent): tokens beyond the 5th are dropped") {
        AppUsageParse p = parse_app_usage_blob(
            rec({"lu", "chrome.exe", "1699000000", "1700000500", "12", "43200", "FUTURE-1"}));
        REQUIRE(p.rows.size() == 1);
        CHECK(p.rows[0].total_seconds_30d == 43200);
    }
}

TEST_CASE("parse: empty-exe_key rows are dropped", "[app_usage_ingest][parse]") {
    std::string blob = rec({"lu", "", "1699000000"}) + rec({"lu"}) + sample_lu();
    AppUsageParse p = parse_app_usage_blob(blob);
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].exe_key == "chrome.exe");
}

TEST_CASE("parse: negative numeric fields clamp to 0", "[app_usage_ingest][parse]") {
    AppUsageParse p = parse_app_usage_blob(rec({"lu", "chrome.exe", "-5", "-9", "-1", "-100"}));
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].first_seen == 0);
    CHECK(p.rows[0].last_seen == 0);
    CHECK(p.rows[0].run_count_30d == 0);
    CHECK(p.rows[0].total_seconds_30d == 0);
}

TEST_CASE("parse: a numeric field with a non-digit tail falls back to 0, not the leading-digit "
          "prefix",
          "[app_usage_ingest][parse]") {
    // std::from_chars parses as much of the token as it can and does not
    // itself reject unconsumed trailing characters — "12junk" parses to 12
    // with an end pointer short of the token's end. parse_nonneg_i64 must
    // check that end pointer and fall back to the documented
    // malformed-token-to-zero behavior rather than silently accepting the
    // prefix.
    AppUsageParse p =
        parse_app_usage_blob(rec({"lu", "chrome.exe", "12junk", "1700000500junk", "3x", "x4"}));
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].first_seen == 0);
    CHECK(p.rows[0].last_seen == 0);
    CHECK(p.rows[0].run_count_30d == 0);
    CHECK(p.rows[0].total_seconds_30d == 0);
}

TEST_CASE("parse: unknown record kinds are skipped without error (forward-compat)",
          "[app_usage_ingest][parse]") {
    std::string blob =
        rec({"cfg", "scope", "machine"}) + sample_lu() + rec({"totally_new_kind", "x", "y"});
    AppUsageParse p = parse_app_usage_blob(blob);
    REQUIRE(p.rows.size() == 1);
    CHECK_FALSE(p.over_record_cap);
}

TEST_CASE("parse: fields are UTF-8-scrubbed and §3.3-stripped", "[app_usage_ingest][parse]") {
    std::string exe = "ch\rrome\n.exe\xFF"
                      "N"; // CR/LF stripped (§3.3), 0xFF scrubbed to U+FFFD in place. 0x1F is the
                           // FIELD separator and can never appear inside a field (the agent-side
                           // clamp_field strips it), so it is not exercised here.
    AppUsageParse p = parse_app_usage_blob(rec({"lu", exe, "1699000000"}));
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].exe_key == "chrome.exe\xEF\xBF\xBDN");  // U+FFFD replaces 0xFF in place, before the trailing N
}

TEST_CASE("parse: over the record cap drops the whole blob (no truncate-and-store)",
          "[app_usage_ingest][parse]") {
    std::string blob;
    for (int i = 0; i < 5001; ++i)
        blob += rec({"lu", "exe" + std::to_string(i), "1699000000"});
    AppUsageParse p = parse_app_usage_blob(blob);
    CHECK(p.over_record_cap);
    CHECK(p.rows.empty());
}

// ── hash: raw bytes, never the claim ─────────────────────────────────────────

TEST_CASE("hash: app_usage_raw_hash is sha256 over the RAW received bytes",
          "[app_usage_ingest][hash]") {
    CHECK(app_usage_raw_hash(sample_blob()) == kPinnedRawHash);
    CHECK(app_usage_raw_hash("") == kEmptyBlobHash);
}

// ── ingest: not-due / malformed report guards ───────────────────────────────

TEST_CASE("ingest: an empty agent_id is a no-op", "[app_usage_ingest][pg]") {
    AUSG_INGEST_SHARED(store, pool);
    agentpb::InventoryReport rpt = full_report("claim", sample_blob());
    agentpb::InventoryAck ack;
    ingest_app_usage_report(store, "", rpt, ack);
    CHECK(ack.need_full_size() == 0);
    auto stored = store.stored_hash("");
    CHECK_FALSE(stored.has_value()); // empty id degrades stored_hash too — nothing written
}

// ── ingest: the hash-skip trichotomy, via the real store ───────────────────

TEST_CASE("ingest: trichotomy — cold cache -> need_full; full store -> stored; "
          "matching hash-only -> touched; drifted hash-only -> need_full",
          "[app_usage_ingest][pg]") {
    AUSG_INGEST_SHARED(store, pool);

    const std::string agent = "agent-app-usage-1";
    const std::string blob = sample_blob();
    const std::string raw_hash = app_usage_raw_hash(blob);

    SECTION("cold cache: a hash-only report before any full payload -> need_full") {
        agentpb::InventoryReport rpt = hash_only_report(raw_hash);
        agentpb::InventoryAck ack;
        ingest_app_usage_report(store, agent, rpt, ack);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == kSource);
    }

    SECTION("full payload stores the RAW-byte hash, never the agent's claim") {
        agentpb::InventoryReport rpt = full_report("bogus-claimed-hash-not-used", blob);
        agentpb::InventoryAck ack;
        ingest_app_usage_report(store, agent, rpt, ack);
        CHECK(ack.need_full_size() == 0);
        auto stored = store.stored_hash(agent);
        REQUIRE(stored.has_value());
        REQUIRE(stored->has_value());
        CHECK(**stored == raw_hash);
        CHECK(**stored != "bogus-claimed-hash-not-used");

        auto rows = store.get_agent_last_used(agent);
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        CHECK((*rows)[0].exe_key == "chrome.exe");

        SECTION("identical resend, hash-only -> touched (no need_full)") {
            agentpb::InventoryReport rpt2 = hash_only_report(raw_hash);
            agentpb::InventoryAck ack2;
            ingest_app_usage_report(store, agent, rpt2, ack2);
            CHECK(ack2.need_full_size() == 0);
        }

        SECTION("drifted hash-only claim -> need_full") {
            agentpb::InventoryReport rpt2 = hash_only_report("some-other-hash");
            agentpb::InventoryAck ack2;
            ingest_app_usage_report(store, agent, rpt2, ack2);
            REQUIRE(ack2.need_full_size() == 1);
            CHECK(ack2.need_full(0) == kSource);
        }

        SECTION("an empty full payload is a legitimate replace-to-empty") {
            agentpb::InventoryReport rpt2 = full_report("claim", "");
            agentpb::InventoryAck ack2;
            ingest_app_usage_report(store, agent, rpt2, ack2);
            CHECK(ack2.need_full_size() == 0);
            auto stored2 = store.stored_hash(agent);
            REQUIRE(stored2.has_value());
            REQUIRE(stored2->has_value());
            CHECK(**stored2 == kEmptyBlobHash);
            auto rows2 = store.get_agent_last_used(agent);
            REQUIRE(rows2.has_value());
            CHECK(rows2->empty());
        }
    }

    SECTION("over-cap payload is dropped + nacked, nothing stored") {
        std::string big_blob;
        for (int i = 0; i < 5001; ++i)
            big_blob += rec({"lu", "exe" + std::to_string(i), "1699000000"});
        agentpb::InventoryReport rpt = full_report("claim", big_blob);
        agentpb::InventoryAck ack;
        ingest_app_usage_report(store, agent, rpt, ack);
        REQUIRE(ack.need_full_size() == 1);
        auto stored = store.stored_hash(agent);
        REQUIRE(stored.has_value());
        CHECK_FALSE(stored->has_value()); // cold cache — nothing was ever stored
    }
}

TEST_CASE("ingest: a degraded (not-open) store nacks rather than throwing",
          "[app_usage_ingest]") {
    // A pool pointed at an unreachable DSN never opens.
    PgPool pool{{.conninfo = "host=127.0.0.1 port=1 dbname=nope connect_timeout=1", .size = 1}};
    AppUsageStore store{pool};
    REQUIRE_FALSE(store.is_open());
    agentpb::InventoryReport rpt = full_report("claim", sample_blob());
    agentpb::InventoryAck ack;
    ingest_app_usage_report(store, "agent-degraded", rpt, ack);
    REQUIRE(ack.need_full_size() == 1);
    CHECK(ack.need_full(0) == kSource);
}
