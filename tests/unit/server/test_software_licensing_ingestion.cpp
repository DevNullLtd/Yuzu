// software_licensing ingest seam tests (ADR-0024 Decisions 3/5, roadmap R5/
// D-2/C-7/G-8): the §3.1 lic|/cfg| wire parse (field order, trailing/extra
// tolerance, empty-product drop), skip-unknown-record-kinds, the closed §3.2
// whitelists at projection, the expires_at plausibility clamp, the §3.3 field
// scrub+clamp, the R5 caps (blob/records/fields), the RAW-byte hash (stored ==
// sha256(received bytes), NEVER the agent's claim), empty-blob = valid
// replace-to-empty, the hash-skip trichotomy through the store primitives, and
// fail-soft nacking on a degraded store.

#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "software_licensing_ingestion.hpp"
#include "software_licensing_store.hpp"

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

using yuzu::server::AgentLicenseRow;
using yuzu::server::ingest_software_licensing_report;
using yuzu::server::parse_software_licensing_blob;
using yuzu::server::software_licensing_raw_hash;
using yuzu::server::SoftwareLicensingParse;
using yuzu::server::SoftwareLicensingStore;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;
namespace agentpb = yuzu::agent::v1;

namespace {

constexpr const char* kSource = "software_licensing";

// Pinned SHA-256 of sample_blob()'s RAW bytes (D-2) — computed independently
// (`printf ... | sha256sum`), NOT via software_licensing_raw_hash, so the test
// pins the algorithm rather than echoing the implementation.
constexpr const char* kPinnedRawHash =
    "220977554324e77bcd9d897abb185443f975a0d7db38cd258fd026daf9ee7593";
// sha256("") — the state hash after a valid replace-to-empty.
constexpr const char* kEmptyBlobHash =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

std::int64_t epoch_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// One wire record: fields 0x1F-joined, record 0x1E-terminated (§3.1).
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

// A fully-populated §3.1 lic| record — 13 fields after the kind, in wire order:
// product|vendor|version|license_type|channel|status|expires_at|source|
// confidence|key_hint|exe_hints|user_scope|user_ref.
std::string sample_lic() {
    return rec({"lic", "Office 365 ProPlus", "Microsoft", "16.0.1", "subscription", "KMS",
                "subscription_active", "1893456000", "os_licensing_api", "authoritative",
                "XXXXX-B7GJQ", "winword.exe;excel.exe", "user", "a1b2c3d4e5f60718"});
}

// The pinned fixture blob: one lic record + the D-10 cfg record. MUST stay
// byte-stable — kPinnedRawHash pins its digest.
std::string sample_blob() {
    return sample_lic() + rec({"cfg", "user_ref", "hash"});
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
// + new pool per test (see test_software_inventory_store.cpp for the rationale).
// SEPARATE template key from test_software_licensing_store.cpp: same schema, but
// cross-file shared-key replay-verification mismatches environmentally on local
// PG16 (see test_software_catalog_rollup.cpp) — a distinct key sidesteps it.
// Behaviour-preserving: identical ingest calls + CHECKs; only the DB
// provisioning/isolation changes. At testRunEnded the pool is drained before
// the clone is dropped, leaving static destruction inert. The [parse]/[hash]
// tests need no DB and the degraded-store test uses a deliberately-broken DSN —
// none are converted.
yuzu::test::PgTestTemplate sleing_tpl{"sleingest", [](const std::string& dsn) {
                                          PgPool pool{{.conninfo = dsn, .size = 1}};
                                          SoftwareLicensingStore store{pool};
                                          if (!store.is_open())
                                              throw std::runtime_error(
                                                  "sleingest template: store failed to migrate");
                                      }};

struct SleingShared {
    yuzu::test::PostgresTestDb db{sleing_tpl};
    std::optional<PgPool> pool;
    SleingShared() {
        REQUIRE(db.available());
        pool.emplace(PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
SleingShared& sleing_shared() {
    static SleingShared s;
    return s;
}

// TRUNCATE both data tables between tests; public.schema_meta is untouched, so
// the per-test store ctor finds the clone migrated and skips migration.
void sleing_reset() {
    auto lease = sleing_shared().pool->acquire();
    REQUIRE(lease);
    auto trunc = pg::exec_params(lease.get(),
                                 "TRUNCATE software_licensing_store.agent_license_state, "
                                 "software_licensing_store.agent_licenses RESTART IDENTITY CASCADE",
                                 std::vector<std::string>{});
    REQUIRE(trunc.status() == PGRES_COMMAND_OK);
}

#define SLEING_SHARED(store, pool)                                                                 \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                              \
    sleing_reset();                                                                                \
    [[maybe_unused]] PgPool& pool = *sleing_shared().pool;                                         \
    SoftwareLicensingStore store{pool};                                                            \
    REQUIRE(store.is_open())

} // namespace

// ── parse: wire shape ────────────────────────────────────────────────────────

TEST_CASE("parse: lic| records project the §3.1 field order", "[sle_ingest][parse]") {
    SoftwareLicensingParse p = parse_software_licensing_blob(sample_blob());
    REQUIRE(p.rows.size() == 1);
    CHECK_FALSE(p.over_record_cap);
    const AgentLicenseRow& r = p.rows[0];
    CHECK(r.product == "Office 365 ProPlus");
    CHECK(r.vendor == "Microsoft");
    CHECK(r.version == "16.0.1");
    CHECK(r.license_type == "subscription");
    CHECK(r.channel == "KMS");
    CHECK(r.state == "subscription_active");
    CHECK(r.expiry_at == 1893456000);
    CHECK(r.detector == "os_licensing_api"); // wire `source` → store `detector`
    CHECK(r.confidence == "authoritative");  // field 9 of lic| — projected (ADR-0024 D1/2/7)
    CHECK(r.key_hint == "XXXXX-B7GJQ");
    CHECK(r.exe_hints == "winword.exe;excel.exe");
    CHECK(r.user_scope == "user");
    CHECK(r.user_ref == "a1b2c3d4e5f60718");
    // Row timestamps are the ingest entry point's / the store's job.
    CHECK(r.collected_at == 0);
    CHECK(p.effective_user_ref_mode == "hash");
}

TEST_CASE("parse: missing trailing fields stay empty; extra fields are dropped",
          "[sle_ingest][parse]") {
    SECTION("short record (old agent): trailing fields default") {
        SoftwareLicensingParse p = parse_software_licensing_blob(rec({"lic", "OnlyProduct", "V"}));
        REQUIRE(p.rows.size() == 1);
        CHECK(p.rows[0].product == "OnlyProduct");
        CHECK(p.rows[0].vendor == "V");
        CHECK(p.rows[0].version.empty());
        // Empty enum fields are outside the closed §3.2 sets → "unknown";
        // empty user_scope falls back to the conservative "machine".
        CHECK(p.rows[0].license_type == "unknown");
        CHECK(p.rows[0].state == "unknown");
        CHECK(p.rows[0].detector == "unknown");
        CHECK(p.rows[0].confidence == "unknown"); // missing trailing field → unknown
        CHECK(p.rows[0].expiry_at == 0);
        CHECK(p.rows[0].user_scope == "machine");
        CHECK(p.rows[0].user_ref.empty());
    }
    SECTION("long record (future agent): tokens beyond the 13th are dropped") {
        SoftwareLicensingParse p = parse_software_licensing_blob(
            rec({"lic", "P", "V", "1.0", "perpetual", "", "licensed", "0", "license_file",
                 "authoritative", "", "", "machine", "", "FUTURE-FIELD-1", "FUTURE-FIELD-2"}));
        REQUIRE(p.rows.size() == 1);
        CHECK(p.rows[0].user_ref.empty()); // the 13th field, not a future token
        CHECK(p.rows[0].user_scope == "machine");
    }
}

TEST_CASE("parse: empty-product rows are dropped", "[sle_ingest][parse]") {
    std::string blob = rec({"lic", "", "V", "1.0"}) + rec({"lic"}) + sample_lic();
    SoftwareLicensingParse p = parse_software_licensing_blob(blob);
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].product == "Office 365 ProPlus");
}

TEST_CASE("parse: unknown record kinds are skipped without error (forward-compat, ADR-0024 D3)",
          "[sle_ingest][parse]") {
    // ent| (PR2), probe_status| (live-only — never legitimately in a blob, but
    // the seam must still skip it gracefully), and arbitrary future kinds.
    std::string blob =
        rec({"ent", "P", "V", "feat", "10", "3", "subscription", "0", "flexlm", "srv:27000"}) +
        sample_lic() + rec({"probe_status", "wmi_slp", "ok", "12"}) +
        rec({"totally_new_kind", "x", "y"});
    SoftwareLicensingParse p = parse_software_licensing_blob(blob);
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].product == "Office 365 ProPlus");
    CHECK_FALSE(p.over_record_cap);
    CHECK(p.effective_user_ref_mode.empty()); // no cfg record in this blob
}

TEST_CASE("parse: cfg|user_ref mode extraction + whitelist (D-10)", "[sle_ingest][parse]") {
    SECTION("the three closed modes pass through") {
        for (const std::string mode : {"collect", "hash", "omit"}) {
            SoftwareLicensingParse p =
                parse_software_licensing_blob(rec({"cfg", "user_ref", mode}));
            CHECK(p.effective_user_ref_mode == mode);
        }
    }
    SECTION("an unrecognised mode maps to unknown") {
        SoftwareLicensingParse p = parse_software_licensing_blob(rec({"cfg", "user_ref", "raw"}));
        CHECK(p.effective_user_ref_mode == "unknown");
    }
    SECTION("absent cfg record leaves the mode empty (old agent)") {
        SoftwareLicensingParse p = parse_software_licensing_blob(sample_lic());
        CHECK(p.effective_user_ref_mode.empty());
    }
    SECTION("unknown cfg subkeys are skipped like unknown record kinds") {
        SoftwareLicensingParse p = parse_software_licensing_blob(rec({"cfg", "future_knob", "on"}));
        CHECK(p.effective_user_ref_mode.empty());
    }
    SECTION("one cfg record per blob — the first wins") {
        SoftwareLicensingParse p = parse_software_licensing_blob(
            rec({"cfg", "user_ref", "collect"}) + rec({"cfg", "user_ref", "omit"}));
        CHECK(p.effective_user_ref_mode == "collect");
    }
}

// ── parse: projection discipline ─────────────────────────────────────────────

TEST_CASE("parse: §3.2 enum whitelist at projection (C-7) — unrecognised → unknown",
          "[sle_ingest][parse]") {
    SoftwareLicensingParse p =
        parse_software_licensing_blob(rec({"lic", "P", "V", "1.0", "warez", "KMS", "cracked", "0",
                                           "magic8ball", "certain", "", "", "root", ""}));
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].license_type == "unknown");
    CHECK(p.rows[0].state == "unknown");
    CHECK(p.rows[0].detector == "unknown");
    CHECK(p.rows[0].confidence == "unknown"); // "certain" is outside the closed set
    CHECK(p.rows[0].user_scope == "machine"); // its own closed pair: machine|user
    CHECK(p.rows[0].channel == "KMS");        // free-text fields untouched
}

TEST_CASE("parse: expires_at plausibility clamp", "[sle_ingest][parse]") {
    const auto expiry_of = [](std::string_view raw) {
        SoftwareLicensingParse p = parse_software_licensing_blob(
            rec({"lic", "P", "V", "1.0", "perpetual", "", "licensed", raw}));
        REQUIRE(p.rows.size() == 1);
        return p.rows[0].expiry_at;
    };
    CHECK(expiry_of("1893456000") == 1893456000); // sane 2030 date kept
    CHECK(expiry_of("-1") == 0);                  // negative → 0
    CHECK(expiry_of("99999999999999") == 0);      // > now + 100 years → 0
    CHECK(expiry_of("soon") == 0);                // non-numeric → 0
    CHECK(expiry_of("") == 0);                    // absent → 0 ("no expiry")
}

TEST_CASE("parse: fields are UTF-8-scrubbed, §3.3-stripped and clamped (scrub-before-clamp)",
          "[sle_ingest][parse]") {
    SECTION("invalid UTF-8 byte → U+FFFD; §3.3 byte set stripped") {
        std::string product = "Pro|du\r\nct S\xFFN"; // pipe/CR/LF stripped, 0xFF scrubbed
        SoftwareLicensingParse p = parse_software_licensing_blob(rec({"lic", product,
                                                                      "V\x01"
                                                                      "endor"}));
        REQUIRE(p.rows.size() == 1);
        CHECK(p.rows[0].product == "Product S\xEF\xBF\xBDN");
        // Other C0 control bytes are NOT in the §3.3 strip set (framing +
        // newline + NUL only) — they pass through as valid UTF-8.
        CHECK(p.rows[0].vendor == "V\x01"
                                  "endor");
    }
    SECTION("over-long field clamps to ≤1024 B on a codepoint boundary") {
        // 1023 ASCII bytes + a 3-byte U+20AC would split at 1024 — the clamp
        // must back up to the boundary, not cut mid-sequence.
        std::string vendor = std::string(1023, 'v') + "\xE2\x82\xAC" + std::string(200, 'w');
        SoftwareLicensingParse p = parse_software_licensing_blob(rec({"lic", "P", vendor}));
        REQUIRE(p.rows.size() == 1);
        CHECK(p.rows[0].vendor.size() == 1023); // the euro sign fell off whole
        CHECK(p.rows[0].vendor == std::string(1023, 'v'));
    }
}

TEST_CASE("parse: R5 record cap — over-cap flags rejection, never a truncated projection",
          "[sle_ingest][parse][caps]") {
    std::string at_cap;
    at_cap.reserve(10000 * 8);
    for (int i = 0; i < 10000; ++i)
        at_cap += rec({"lic", "P" + std::to_string(i)});
    SECTION("exactly 10 000 records parse") {
        SoftwareLicensingParse p = parse_software_licensing_blob(at_cap);
        CHECK_FALSE(p.over_record_cap);
        CHECK(p.rows.size() == 10000);
    }
    SECTION("10 001 records flag over_record_cap with an empty projection") {
        SoftwareLicensingParse p = parse_software_licensing_blob(at_cap + rec({"lic", "straw"}));
        CHECK(p.over_record_cap);
        CHECK(p.rows.empty()); // no partial row set to mistakenly store
    }
}

// ── raw-byte hash (D-2) ──────────────────────────────────────────────────────

TEST_CASE("raw hash: pinned independent SHA-256 of the received bytes", "[sle_ingest][hash]") {
    CHECK(software_licensing_raw_hash(sample_blob()) == kPinnedRawHash);
    CHECK(software_licensing_raw_hash("") == kEmptyBlobHash);
    // Any byte change — even one inside a record kind the parser SKIPS —
    // changes the raw hash (it is over bytes, not parsed rows).
    CHECK(software_licensing_raw_hash(sample_blob() + rec({"ent", "x"})) != kPinnedRawHash);
}

// ── ingest end-to-end (store-backed, [pg]) ───────────────────────────────────

TEST_CASE("ingest: full payload stores rows + the RAW-byte hash, never the claim",
          "[pg][sle_ingest]") {
    SLEING_SHARED(store, pool);

    // The agent's claim is a LIE — storage must carry sha256(raw bytes).
    const std::string claimed = "claimed-hash-the-server-must-not-trust";
    agentpb::InventoryReport rpt = full_report(claimed, sample_blob());
    rpt.mutable_collected_at()->set_millis_epoch(1751000000000);
    agentpb::InventoryAck ack;
    ingest_software_licensing_report(store, "agent-a", rpt, ack, nullptr);
    CHECK(ack.need_full_size() == 0);

    auto rows = store.agent_licenses("agent-a");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].product == "Office 365 ProPlus");
    CHECK((*rows)[0].confidence == "authoritative"); // whitelisted + stored (D1/2/7)
    CHECK((*rows)[0].collected_at == 1751000000);    // proto millis → seconds

    auto stored = store.stored_hash("agent-a");
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK(**stored == kPinnedRawHash); // recomputed over the received bytes (D-2)
    CHECK(**stored != claimed);        // the claim was never stored

    // The cfg| effective mode reached the store's replace call (D-10).
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult sel = pg::exec_params(
            lease.get(),
            "SELECT effective_user_ref_mode FROM software_licensing_store.agent_license_state "
            "WHERE agent_id = 'agent-a'",
            std::vector<std::string>{});
        REQUIRE(sel.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(sel.get()) == 1);
        CHECK(std::string(PQgetvalue(sel.get(), 0, 0)) == "hash");
    }

    SECTION("hash-only claiming the RAW hash → touched, no nack (skip works)") {
        agentpb::InventoryAck ack2;
        ingest_software_licensing_report(store, "agent-a", hash_only_report(kPinnedRawHash), ack2,
                                         nullptr);
        CHECK(ack2.need_full_size() == 0);
    }
    SECTION("hash-only claiming anything else → drift, nacked (G-8 lever reachable)") {
        agentpb::InventoryAck ack2;
        ingest_software_licensing_report(store, "agent-a", hash_only_report(claimed), ack2,
                                         nullptr);
        REQUIRE(ack2.need_full_size() == 1);
        CHECK(ack2.need_full(0) == kSource);
    }
}

TEST_CASE("ingest: interleaved unknown record kinds store fine; the hash covers the raw bytes",
          "[pg][sle_ingest]") {
    SLEING_SHARED(store, pool);

    // A mixed-version blob: the lic record bracketed by kinds this server
    // doesn't know. Rows project identically to the plain blob, but the hash
    // is over the RAW bytes — unknown kinds are IN it, which is exactly what
    // keeps a mixed-version fleet loop-free (ADR-0024 Decision 3).
    const std::string mixed =
        rec({"ent", "P", "V", "feat", "10", "3", "subscription", "0", "flexlm", "srv:27000"}) +
        sample_lic() + rec({"future_kind", "x"});
    agentpb::InventoryAck ack;
    ingest_software_licensing_report(store, "agent-b", full_report("claim", mixed), ack, nullptr);
    CHECK(ack.need_full_size() == 0);

    auto rows = store.agent_licenses("agent-b");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1); // unknown kinds projected NO rows
    CHECK((*rows)[0].product == "Office 365 ProPlus");

    auto stored = store.stored_hash("agent-b");
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK(**stored == software_licensing_raw_hash(mixed));        // covers the raw bytes…
    CHECK(**stored != software_licensing_raw_hash(sample_lic())); // …not the parsed subset

    // Next cycle the mixed-version agent claims its own (raw) hash → touched,
    // no permanent full-resend loop.
    agentpb::InventoryAck ack2;
    ingest_software_licensing_report(
        store, "agent-b", hash_only_report(software_licensing_raw_hash(mixed)), ack2, nullptr);
    CHECK(ack2.need_full_size() == 0);
}

TEST_CASE("ingest: an empty blob is a VALID full replace-to-empty (ADR-0024 D3)",
          "[pg][sle_ingest]") {
    SLEING_SHARED(store, pool);

    agentpb::InventoryAck ack;
    ingest_software_licensing_report(store, "agent-c", full_report("x", sample_blob()), ack,
                                     nullptr);
    REQUIRE(ack.need_full_size() == 0);
    REQUIRE(store.agent_licenses("agent-c")->size() == 1);

    // Zero detected licences is a legitimate state — the empty-vs-error guard
    // is agent-side (a failed primary surface never reaches the wire); the
    // server accepts and replaces to empty, hash = sha256("").
    agentpb::InventoryAck ack2;
    ingest_software_licensing_report(store, "agent-c", full_report("y", ""), ack2, nullptr);
    CHECK(ack2.need_full_size() == 0);
    auto rows = store.agent_licenses("agent-c");
    REQUIRE(rows.has_value());
    CHECK(rows->empty()); // replaced to empty, NOT an error
    auto stored = store.stored_hash("agent-c");
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK(**stored == kEmptyBlobHash);
}

TEST_CASE("ingest: R5 caps — over-blob and over-records drop + nack, nothing stored",
          "[pg][sle_ingest][caps]") {
    SLEING_SHARED(store, pool);

    SECTION("blob over 1 MiB") {
        agentpb::InventoryAck ack;
        ingest_software_licensing_report(
            store, "agent-big", full_report("h", std::string(1024 * 1024 + 1, 'x')), ack, nullptr);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == kSource);
        auto stored = store.stored_hash("agent-big");
        REQUIRE(stored.has_value());
        CHECK_FALSE(stored->has_value()); // nothing stored
    }
    SECTION("blob over 10 000 records") {
        std::string blob;
        for (int i = 0; i < 10001; ++i)
            blob += rec({"lic", "P" + std::to_string(i)});
        agentpb::InventoryAck ack;
        ingest_software_licensing_report(store, "agent-many", full_report("h", blob), ack, nullptr);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == kSource);
        auto stored = store.stored_hash("agent-many");
        REQUIRE(stored.has_value());
        CHECK_FALSE(stored->has_value()); // nothing stored
    }
}

TEST_CASE("ingest: hash-only cold cache nacks; absent source is a no-op", "[pg][sle_ingest]") {
    SLEING_SHARED(store, pool);

    SECTION("hash-only with no stored state → need_full (cold cache)") {
        agentpb::InventoryAck ack;
        ingest_software_licensing_report(store, "agent-cold", hash_only_report(kPinnedRawHash), ack,
                                         nullptr);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == kSource);
    }
    SECTION("source absent from the report → no-op, no nack") {
        agentpb::InventoryReport other;
        (*other.mutable_content_hashes())["installed_software"] = "x";
        agentpb::InventoryAck ack;
        ingest_software_licensing_report(store, "agent-d", other, ack, nullptr);
        CHECK(ack.need_full_size() == 0);
    }
}

// ── fail-soft on a degraded store (no live PG needed) ────────────────────────

TEST_CASE("ingest: a degraded store nacks (fail-soft), an abusive report is rejected without one",
          "[sle_ingest]") {
    // Unreachable conninfo → the store never opens; every primitive degrades.
    PgPool pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1 dbname=x user=x", .size = 1}};
    SoftwareLicensingStore store{pool};
    REQUIRE(!store.is_open());

    SECTION("full payload → replace fails → error + nack (agent re-sends next cycle)") {
        agentpb::InventoryAck ack;
        ingest_software_licensing_report(store, "agent-e", full_report("h", sample_blob()), ack,
                                         nullptr);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == kSource);
    }
    SECTION("hash-only → stored_hash degrades → error + nack") {
        agentpb::InventoryAck ack;
        ingest_software_licensing_report(store, "agent-e", hash_only_report("h"), ack, nullptr);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == kSource);
    }
    SECTION("report over the source-count cap → whole-source reject, deliberately NO nack") {
        agentpb::InventoryReport rpt = full_report("h", sample_blob());
        for (int i = 0; i < 65; ++i)
            (*rpt.mutable_content_hashes())["src" + std::to_string(i)] = "x";
        agentpb::InventoryAck ack;
        ingest_software_licensing_report(store, "agent-f", rpt, ack, nullptr);
        CHECK(ack.need_full_size() == 0); // no resend amplification for abuse
    }
    SECTION("empty agent_id → no-op") {
        agentpb::InventoryAck ack;
        ingest_software_licensing_report(store, "", full_report("h", sample_blob()), ack, nullptr);
        CHECK(ack.need_full_size() == 0);
    }
}
