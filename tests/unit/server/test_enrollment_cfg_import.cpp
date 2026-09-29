/**
 * test_enrollment_cfg_import.cpp - the one-time import of the legacy per-replica
 * `enrollment-tokens.cfg` / `pending-agents.cfg` into Postgres (WS-6 slice 6.2).
 *
 * Two layers:
 *  - the PURE tolerant parsers + fingerprint (no PG, no I/O);
 *  - the DB write (`AuthDB::import_legacy_*`) and the orchestrator
 *    (`run_legacy_enrollment_import`) against a real PG-backed AuthDB.
 *
 * The PG cases use a PRIVATE database per test (yuzu::test::AuthDbPg), not the
 * shared clone: `auth.import_meta` is not in the shared fixture's TRUNCATE list, so
 * a stamped marker would leak into every later test.
 */

#include "test_auth_db_pg_helper.hpp"
#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/enrollment_cfg_import.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace ei = yuzu::server::enrollment_import;
namespace fs = std::filesystem;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::EnrollmentTokenError;
using yuzu::server::auth::PendingStatus;
using yuzu::server::auth::RemovePendingOutcome;
using CEK = yuzu::server::auth::ConsumeEnrollResult::Kind;

namespace {

/// A 64-hex "hash" whose first 8 chars are `prefix8` (for id-collision tests).
std::string fake_hash(const std::string& prefix8, char fill) {
    return prefix8 + std::string(56, fill);
}

std::string token_line(const std::string& hash, const std::string& label, int max_uses,
                       int use_count, long long created, long long expires, bool revoked) {
    return hash.substr(0, 8) + ":" + hash + ":" + label + ":" + std::to_string(max_uses) + ":" +
           std::to_string(use_count) + ":" + std::to_string(created) + ":" +
           std::to_string(expires) + ":" + (revoked ? "1" : "0");
}

std::string pending_line(const std::string& id, const std::string& host, const std::string& status,
                         long long epoch = 1700000000) {
    return id + ":" + host + ":linux:x86_64:1.0.0:" + std::to_string(epoch) + ":" + status;
}

const std::string kHeaderTokens =
    "# Yuzu Enrollment Tokens\n# Version: 1\n# Format: "
    "token_id:token_hash:label:max_uses:use_count:created_epoch:expires_epoch:revoked\n\n";
const std::string kHeaderPending =
    "# Yuzu Pending Agents\n# Version: 1\n# Format: "
    "agent_id:hostname:os:arch:version:requested_epoch:status\n\n";

void write_file(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << content;
}

bool file_present(const fs::path& p) {
    std::error_code ec;
    return fs::exists(p, ec);
}

std::string scalar(PGconn* conn, const char* sql) {
    yuzu::server::pg::PgResult res{PQexec(conn, sql)};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    if (PQntuples(res.get()) == 0 || PQgetisnull(res.get(), 0, 0))
        return {};
    return PQgetvalue(res.get(), 0, 0);
}

/// Private PG-backed AuthDB + two scratch dirs (the "config dir" and "data dir").
struct ImportFixture {
    yuzu::test::AuthDbPg db;
    yuzu::test::TempDir cfg_dir;
    yuzu::test::TempDir data_dir;
    yuzu::server::pg::PgConn side{}; // for raw SQL
    AuthManager mgr;

    ImportFixture() {
        mgr.set_auth_db(db.get());
        side = yuzu::server::pg::PgConn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(side.get()) == CONNECTION_OK);
    }
    ei::Locations both() const { return {data_dir.path, cfg_dir.path}; }
    ei::Locations cfg_only() const { return {fs::path{}, cfg_dir.path}; }
    ei::RunResult run(const ei::Locations& w, yuzu::MetricsRegistry* m = nullptr,
                      const ei::Options& o = {}) {
        return ei::run_legacy_enrollment_import(*db, w, m, o);
    }
    std::string sql(const char* q) { return scalar(side.get(), q); }
    const ei::KindReport& report(const ei::RunResult& r, const std::string& kind) const {
        for (const auto& k : r.reports)
            if (k.kind == kind)
                return k;
        FAIL("no report for kind " << kind);
        return r.reports.front();
    }
    std::expected<yuzu::server::auth::ConsumeEnrollResult, yuzu::server::StoreError>
    consume(const std::string& raw, const std::string& agent) {
        return mgr.consume_and_enroll(raw, agent, "h", "linux", "x86_64", "1");
    }
};

} // namespace

// ── pure parsers ────────────────────────────────────────────────────────────

TEST_CASE("parse_tokens_cfg: a well-formed row round-trips every field",
          "[enrollment_import][parse]") {
    const auto h = AuthManager::sha256_hex("raw");
    const auto p = ei::parse_tokens_cfg(kHeaderTokens + token_line(h, "NYC", 3, 1, 1700000000,
                                                                     1800000000, true) + "\n");
    REQUIRE(p.rows.size() == 1);
    CHECK(p.stats.garbled == 0);
    CHECK(p.stats.data_lines == 1);
    const auto& t = p.rows[0];
    CHECK(t.token_hash == h);
    CHECK(t.label == "NYC");
    CHECK(t.max_uses == 3);
    CHECK(t.use_count == 1);
    CHECK(t.created_epoch == 1700000000);
    CHECK(t.expires_epoch == 1800000000);
    CHECK(t.revoked);
    CHECK_FALSE(p.stats.unsupported_version);
}

TEST_CASE("parse_tokens_cfg: garbled lines are skipped and counted, good lines survive",
          "[enrollment_import][parse]") {
    const auto good = AuthManager::sha256_hex("good");
    std::string too_many_nul = token_line(AuthManager::sha256_hex("nul"), "x", 1, 0, 1, 0, false);
    too_many_nul[20] = '\0';
    const std::string content =
        kHeaderTokens +
        "only:three:fields\n" +                                                     // too few fields
        token_line("nothex" + std::string(58, 'a'), "bad-hash", 1, 0, 1, 0, false) + "\n" + // bad hash
        token_line(AuthManager::sha256_hex("u"), "UPPER", 1, 0, 1, 0, false).substr(0, 9) +
            std::string(64, 'A') + ":x:1:0:1:0:0\n" +                             // uppercase hash
        token_line(good, "neg", -1, 0, 1, 0, false) + "\n" +                        // negative max_uses
        token_line(good, "abc", 1, 0, 1, 0, false).replace(
            token_line(good, "abc", 1, 0, 1, 0, false).find(":1:0:"), 5, ":x:0:") + "\n" + // NaN
        token_line(good, "huge-epoch", 1, 0, 99999999999999LL, 0, false) + "\n" +   // epoch range
        token_line(good, std::string(300, 'L'), 1, 0, 1, 0, false) + "\n" +        // oversize label
        too_many_nul + "\n" +                                                       // NUL
        token_line(good, "bad-revoked", 1, 0, 1, 0, false).substr(0, 200).replace(
            token_line(good, "bad-revoked", 1, 0, 1, 0, false).size() - 1, 1, "2") + "\n" +
        token_line(good, "GOOD", 2, 0, 1700000000, 0, false) + "\n";
    const auto p = ei::parse_tokens_cfg(content);
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].label == "GOOD");
    CHECK(p.stats.garbled == p.stats.data_lines - 1);
    CHECK(p.stats.garbled >= 8);
}

TEST_CASE("parse_tokens_cfg: ':' inside a label is recovered unambiguously from the right",
          "[enrollment_import][parse]") {
    const auto h = AuthManager::sha256_hex("colon");
    // The old writer emitted the label verbatim, so "NYC: floor 3" adds 1 extra ':'.
    const std::string line = h.substr(0, 8) + ":" + h + ":NYC: floor:3:5:2:1700000000:0:0";
    const auto p = ei::parse_tokens_cfg(line + "\n");
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].label == "NYC: floor:3");
    CHECK(p.rows[0].max_uses == 5);
    CHECK(p.rows[0].use_count == 2);
    CHECK(p.stats.recovered == 1);
    CHECK(p.stats.garbled == 0);
}

TEST_CASE("parse: empty, header-only, CRLF and version handling", "[enrollment_import][parse]") {
    CHECK(ei::parse_tokens_cfg("").rows.empty());
    const auto header_only = ei::parse_tokens_cfg(kHeaderTokens);
    CHECK(header_only.rows.empty());
    CHECK(header_only.stats.data_lines == 0);
    CHECK(header_only.stats.garbled == 0);

    const auto h = AuthManager::sha256_hex("crlf");
    const auto crlf = ei::parse_tokens_cfg("# Version: 1\r\n" + token_line(h, "x", 1, 0, 1, 0, false) + "\r\n");
    CHECK(crlf.rows.size() == 1);

    const auto v2 = ei::parse_tokens_cfg("# Version: 2\n" + token_line(h, "x", 1, 0, 1, 0, false) + "\n");
    CHECK(v2.stats.unsupported_version);
    CHECK(v2.rows.size() == 1); // best effort, flagged
}

TEST_CASE("parse_pending_cfg: valid rows, and an ambiguous ':' or bad field is skipped + counted",
          "[enrollment_import][parse]") {
    const std::string content =
        kHeaderPending + pending_line("a1", "host1", "approved") + "\n" +
        pending_line("a2", "host2", "denied") + "\n" +
        pending_line("a3", "host3", "pending") + "\n" +
        "a4:host:with:colon:linux:x86_64:1.0:1700000000:pending\n" + // 9 fields: ambiguous
        pending_line("a5", "host5", "weird") + "\n" +                // unknown status
        "a6:h:linux:x86_64:1.0:notanumber:pending\n" +
        pending_line("", "nohost", "pending") + "\n" +               // empty agent_id
        pending_line("a7", std::string(300, 'h'), "pending") + "\n"; // oversize
    const auto p = ei::parse_pending_cfg(content);
    REQUIRE(p.rows.size() == 3);
    CHECK(p.rows[0].status == "approved");
    CHECK(p.rows[1].status == "denied");
    CHECK(p.stats.garbled == 5);
    CHECK(p.stats.recovered == 0);
}

TEST_CASE("content_fingerprint is a stable lowercase-hex sha256 that tracks the bytes",
          "[enrollment_import][parse]") {
    const auto a = ei::content_fingerprint("abc");
    CHECK(a.size() == 64);
    CHECK(a == ei::content_fingerprint("abc"));
    CHECK(a != ei::content_fingerprint("abd"));
    CHECK(a == AuthManager::sha256_hex("abc"));
}

// ── DB + orchestrator ───────────────────────────────────────────────────────

TEST_CASE("import: tokens + pending are imported, marked, renamed, counted and audited-as-report",
          "[pg][enrollment_import]") {
    ImportFixture f;
    yuzu::MetricsRegistry metrics;
    const auto h1 = AuthManager::sha256_hex("t1");
    write_file(f.cfg_dir.path / "enrollment-tokens.cfg",
               kHeaderTokens + token_line(h1, "NYC rollout", 2, 1, 1700000000, 0, false) + "\n" +
                   "garbage line\n");
    write_file(f.cfg_dir.path / "pending-agents.cfg",
               kHeaderPending + pending_line("ag-1", "host1", "approved") + "\n" +
                   pending_line("ag-2", "host2", "pending") + "\n");

    const auto r = f.run(f.cfg_only(), &metrics);
    CHECK_FALSE(r.fatal);
    const auto& t = f.report(r, "tokens");
    CHECK(t.outcome == ei::Outcome::imported);
    CHECK(t.counts.imported == 1);
    CHECK(t.parse.garbled == 1);
    CHECK(t.renamed);
    CHECK(t.fingerprint.size() == 64);
    const auto& p = f.report(r, "pending");
    CHECK(p.outcome == ei::Outcome::imported);
    CHECK(p.counts.imported == 2);

    // Files renamed, markers stamped with the file fingerprints.
    CHECK_FALSE(file_present(f.cfg_dir.path / "enrollment-tokens.cfg"));
    CHECK(file_present(f.cfg_dir.path / "enrollment-tokens.cfg.imported"));
    CHECK_FALSE(file_present(f.cfg_dir.path / "pending-agents.cfg"));
    CHECK(f.sql("SELECT count(*) FROM auth.import_meta") == "2");
    CHECK(f.sql("SELECT fingerprint FROM auth.import_meta WHERE key='enrollment-tokens.cfg'") ==
          t.fingerprint);

    // The row content survived.
    const auto tokens = f.mgr.list_enrollment_tokens().value();
    REQUIRE(tokens.size() == 1);
    CHECK(tokens[0].token_hash == h1);
    CHECK(tokens[0].label == "NYC rollout");
    CHECK(tokens[0].max_uses == 2);
    CHECK(tokens[0].use_count == 1);
    CHECK(tokens[0].token_id == h1.substr(0, 8));
    CHECK(tokens[0].expires_at == (std::chrono::system_clock::time_point::max)());
    CHECK(f.sql("SELECT extract(epoch FROM created_at)::bigint FROM auth.enrollment_tokens") ==
          "1700000000");
    CHECK(**f.mgr.get_pending_status("ag-1") == PendingStatus::approved);
    CHECK(**f.mgr.get_pending_status("ag-2") == PendingStatus::pending);

    // Metrics.
    CHECK(metrics.counter("yuzu_server_enrollment_import_total",
                          {{"kind", "tokens"}, {"outcome", "imported"}}).value() == 1.0);
    CHECK(metrics.counter("yuzu_server_enrollment_import_rows_total",
                          {{"kind", "tokens"}, {"result", "skipped_garbled"}}).value() == 1.0);
    CHECK(metrics.counter("yuzu_server_enrollment_import_rows_total",
                          {{"kind", "pending"}, {"result", "imported"}}).value() == 2.0);
}

TEST_CASE("import: imported tokens actually validate through consume_and_enroll",
          "[pg][enrollment_import]") {
    ImportFixture f;
    // Real raw tokens so the imported hashes are consumable.
    const std::string fresh_raw(64, 'a'), spent_raw(64, 'b'), revoked_raw(64, 'c'),
        expired_raw(64, 'd'), unlimited_raw(64, 'e');
    auto line = [](const std::string& raw, int max, int used, long long expires, bool revoked) {
        return token_line(AuthManager::sha256_hex(raw), "t", max, used, 1700000000, expires, revoked);
    };
    write_file(f.cfg_dir.path / "enrollment-tokens.cfg",
               kHeaderTokens + line(fresh_raw, 1, 0, 0, false) + "\n" +
                   line(spent_raw, 1, 1, 0, false) + "\n" + line(revoked_raw, 5, 0, 0, true) + "\n" +
                   line(expired_raw, 5, 0, 1000, false) + "\n" +
                   line(unlimited_raw, 0, 7, 0, false) + "\n");
    write_file(f.cfg_dir.path / "pending-agents.cfg",
               kHeaderPending + pending_line("approved-agent", "h", "approved") + "\n" +
                   pending_line("denied-agent", "h", "denied") + "\n");
    REQUIRE_FALSE(f.run(f.cfg_only()).fatal);

    // max_uses=1, use_count=0: works exactly once.
    auto first = f.consume(fresh_raw, "agent-a");
    REQUIRE(first.has_value());
    CHECK(first->kind == CEK::enrolled);
    auto second = f.consume(fresh_raw, "agent-b");
    REQUIRE(second.has_value());
    CHECK(second->token_error == EnrollmentTokenError::already_consumed);

    // use_count == max_uses at import: already consumed.
    auto spent = f.consume(spent_raw, "agent-c");
    REQUIRE(spent.has_value());
    CHECK(spent->kind == CEK::token_rejected);
    CHECK(spent->token_error == EnrollmentTokenError::already_consumed);
    // revoked / expired (epoch 1000 is long past) / unlimited-with-history.
    CHECK(f.consume(revoked_raw, "agent-d")->token_error == EnrollmentTokenError::revoked);
    CHECK(f.consume(expired_raw, "agent-e")->token_error == EnrollmentTokenError::expired);
    CHECK(f.consume(unlimited_raw, "agent-f")->kind == CEK::enrolled);

    // Imported pending state drives the Register fast path / denial pre-check.
    CHECK(**f.mgr.get_pending_status("approved-agent") == PendingStatus::approved);
    CHECK(**f.mgr.get_pending_status("denied-agent") == PendingStatus::denied);
    // A denied imported agent still rolls a valid token's use back.
    auto denied = f.consume(unlimited_raw, "denied-agent");
    REQUIRE(denied.has_value());
    CHECK(denied->kind == CEK::admin_denied);
}

TEST_CASE("import: a missing file stamps NOTHING, and a later boot with the file present imports",
          "[pg][enrollment_import]") {
    ImportFixture f;
    yuzu::MetricsRegistry metrics;
    auto r = f.run(f.both(), &metrics);
    CHECK_FALSE(r.fatal);
    CHECK(f.report(r, "tokens").outcome == ei::Outcome::absent);
    CHECK(f.report(r, "pending").outcome == ei::Outcome::absent);
    CHECK(f.sql("SELECT count(*) FROM auth.import_meta") == "0"); // never stamp on absence
    CHECK(metrics.counter("yuzu_server_enrollment_import_total",
                          {{"kind", "tokens"}, {"outcome", "absent"}}).value() == 1.0);

    write_file(f.data_dir.path / "enrollment-tokens.cfg",
               kHeaderTokens + token_line(AuthManager::sha256_hex("late"), "late", 1, 0, 1, 0, false) + "\n");
    r = f.run(f.both());
    CHECK(f.report(r, "tokens").outcome == ei::Outcome::imported);
    CHECK(f.report(r, "pending").outcome == ei::Outcome::absent);
    CHECK(f.sql("SELECT count(*) FROM auth.import_meta") == "1");
    CHECK(f.mgr.list_enrollment_tokens().value().size() == 1);
}

TEST_CASE("import: an empty or header-only file is imported as zero rows and still stamped",
          "[pg][enrollment_import]") {
    ImportFixture f;
    write_file(f.cfg_dir.path / "enrollment-tokens.cfg", "");
    write_file(f.cfg_dir.path / "pending-agents.cfg", kHeaderPending);
    const auto r = f.run(f.cfg_only());
    CHECK_FALSE(r.fatal);
    CHECK(f.report(r, "tokens").outcome == ei::Outcome::imported);
    CHECK(f.report(r, "tokens").counts.imported == 0);
    CHECK(f.report(r, "pending").outcome == ei::Outcome::imported);
    CHECK(f.sql("SELECT count(*) FROM auth.import_meta") == "2");
    CHECK(f.report(r, "tokens").renamed);
}

TEST_CASE("import: a failed rename is tolerated and the next boot is an idempotent no-op",
          "[pg][enrollment_import]") {
    ImportFixture f;
    write_file(f.cfg_dir.path / "pending-agents.cfg",
               kHeaderPending + pending_line("ag-1", "h", "pending") + "\n");
    ei::Options no_rename;
    no_rename.rename_fn = [](const fs::path&, const fs::path&) { return false; };

    auto r1 = f.run(f.cfg_only(), nullptr, no_rename);
    CHECK_FALSE(r1.fatal);
    CHECK(f.report(r1, "pending").outcome == ei::Outcome::imported);
    CHECK_FALSE(f.report(r1, "pending").renamed);
    CHECK(file_present(f.cfg_dir.path / "pending-agents.cfg")); // still there

    // Second boot: marker + equal fingerprint => skipped, and the rename is retried.
    auto r2 = f.run(f.cfg_only());
    CHECK_FALSE(r2.fatal);
    CHECK(f.report(r2, "pending").outcome == ei::Outcome::already_imported);
    CHECK(f.report(r2, "pending").counts.imported == 0);
    CHECK(f.report(r2, "pending").renamed);
    CHECK_FALSE(file_present(f.cfg_dir.path / "pending-agents.cfg"));
    CHECK(f.mgr.list_pending_agents().value().size() == 1);
}

TEST_CASE("import: restoring the SAME bytes after admin changes does NOT resurrect anything",
          "[pg][enrollment_import]") {
    ImportFixture f;
    const std::string raw(64, 'f');
    const auto h = AuthManager::sha256_hex(raw);
    const std::string tokens_file =
        kHeaderTokens + token_line(h, "t", 5, 0, 1700000000, 0, false) + "\n";
    // "gone" imports as still-pending — a hard remove only ever succeeds on a
    // pending row (removing an approved/denied row is refused, see
    // RemovePendingOutcome's doc comment).
    const std::string pending_file = kHeaderPending + pending_line("keep", "h", "approved") + "\n" +
                                     pending_line("gone", "h", "pending") + "\n" +
                                     pending_line("flip", "h", "pending") + "\n";
    write_file(f.cfg_dir.path / "enrollment-tokens.cfg", tokens_file);
    write_file(f.cfg_dir.path / "pending-agents.cfg", pending_file);
    REQUIRE_FALSE(f.run(f.cfg_only()).fatal);

    // The operator acts: remove a pending agent, deny another, revoke the token.
    REQUIRE(f.mgr.remove_pending_agent("gone").value() == RemovePendingOutcome::removed);
    REQUIRE(f.mgr.deny_pending_agent("flip", "admin").value());
    const auto token_id = f.mgr.list_enrollment_tokens().value()[0].token_id;
    REQUIRE(f.mgr.revoke_enrollment_token(token_id).value());

    // Someone restores the original files, byte for byte, and the server reboots.
    write_file(f.cfg_dir.path / "enrollment-tokens.cfg", tokens_file);
    write_file(f.cfg_dir.path / "pending-agents.cfg", pending_file);
    const auto r = f.run(f.cfg_only());
    CHECK_FALSE(r.fatal);
    CHECK(f.report(r, "tokens").outcome == ei::Outcome::already_imported);
    CHECK(f.report(r, "pending").outcome == ei::Outcome::already_imported);

    CHECK_FALSE(f.mgr.get_pending_status("gone").value().has_value()); // NOT resurrected
    CHECK(**f.mgr.get_pending_status("flip") == PendingStatus::denied);
    CHECK(**f.mgr.get_pending_status("keep") == PendingStatus::approved);
    CHECK(f.mgr.list_enrollment_tokens().value()[0].revoked);
    CHECK(f.consume(raw, "someone")->token_error == EnrollmentTokenError::revoked);
}

TEST_CASE("import: a DIFFERENT file after the first import is REFUSED - not merged, not fatal, "
          "left in place",
          "[pg][enrollment_import]") {
    ImportFixture f;
    yuzu::MetricsRegistry metrics;
    write_file(f.cfg_dir.path / "pending-agents.cfg",
               kHeaderPending + pending_line("orig", "h", "approved") + "\n");
    REQUIRE(f.run(f.cfg_only(), &metrics).reports.size() == 2);
    REQUIRE(f.mgr.list_pending_agents().value().size() == 1);

    // A restored OLD backup (different bytes) appears.
    write_file(f.cfg_dir.path / "pending-agents.cfg",
               kHeaderPending + pending_line("orig", "h", "approved") + "\n" +
                   pending_line("from-backup", "h", "approved") + "\n");
    const auto r = f.run(f.cfg_only(), &metrics);
    CHECK_FALSE(r.fatal); // boot continues
    const auto& p = f.report(r, "pending");
    CHECK(p.outcome == ei::Outcome::fingerprint_mismatch);
    CHECK_FALSE(p.renamed);
    CHECK(file_present(f.cfg_dir.path / "pending-agents.cfg")); // left for the operator
    CHECK_FALSE(f.mgr.get_pending_status("from-backup").value().has_value()); // not merged
    CHECK(metrics.counter("yuzu_server_enrollment_import_total",
                          {{"kind", "pending"}, {"outcome", "fingerprint_mismatch"}}).value() == 1.0);
    // Still mismatched (not silently accepted) on every later boot.
    CHECK(f.report(f.run(f.cfg_only()), "pending").outcome == ei::Outcome::fingerprint_mismatch);
}

TEST_CASE("import: at first import PG state ALWAYS wins over a stale file",
          "[pg][enrollment_import]") {
    ImportFixture f;
    const std::string raw(64, '1');
    const auto h = AuthManager::sha256_hex(raw);
    // Newer state already in PG: the token was used up and revoked; a agent was denied.
    f.sql("SELECT 1"); // side connection warm
    {
        auto created = f.mgr.create_enrollment_token("pg-label", 1, std::chrono::hours(1), "admin");
        REQUIRE(created.has_value());
    }
    // Force the SAME hash into PG with newer state via raw SQL.
    yuzu::server::pg::PgResult ins{PQexec(
        f.side.get(),
        ("INSERT INTO auth.enrollment_tokens (token_id, token_hash, label, max_uses, use_count, "
         "revoked, created_by) VALUES ('" + h.substr(0, 8) + "','" + h + "','pg-wins',5,5,true,'admin')")
            .c_str())};
    REQUIRE(ins.ok());
    REQUIRE(f.mgr.add_pending_agent("agent-x", "pg-host", "linux", "x86_64", "1").value());
    REQUIRE(f.mgr.deny_pending_agent("agent-x", "admin").value());

    write_file(f.cfg_dir.path / "enrollment-tokens.cfg",
               kHeaderTokens + token_line(h, "stale-file-label", 5, 0, 1700000000, 0, false) + "\n");
    write_file(f.cfg_dir.path / "pending-agents.cfg",
               kHeaderPending + pending_line("agent-x", "stale-host", "approved") + "\n" +
                   pending_line("agent-y", "new-host", "approved") + "\n");
    const auto r = f.run(f.cfg_only());
    CHECK_FALSE(r.fatal);
    CHECK(f.report(r, "tokens").counts.skipped_existing == 1);
    CHECK(f.report(r, "tokens").counts.imported == 0);
    CHECK(f.report(r, "pending").counts.skipped_existing == 1);
    CHECK(f.report(r, "pending").counts.imported == 1);

    CHECK(f.sql(("SELECT label || '/' || use_count || '/' || revoked FROM auth.enrollment_tokens "
                 "WHERE token_hash='" + h + "'").c_str()) == "pg-wins/5/true");
    CHECK(**f.mgr.get_pending_status("agent-x") == PendingStatus::denied);   // not "approved"
    CHECK(f.sql("SELECT hostname FROM auth.pending_agents WHERE agent_id='agent-x'") == "pg-host");
    CHECK(**f.mgr.get_pending_status("agent-y") == PendingStatus::approved); // new row imported
}

TEST_CASE("import: two importers racing the transaction produce exactly one import",
          "[pg][enrollment_import][race]") {
    ImportFixture f;
    std::vector<ei::LegacyToken> rows;
    for (int i = 0; i < 25; ++i) {
        ei::LegacyToken t;
        t.token_hash = AuthManager::sha256_hex("race-" + std::to_string(i));
        t.label = "r" + std::to_string(i);
        t.max_uses = 1;
        rows.push_back(t);
    }
    constexpr int kThreads = 4; // the fixture pool has 4 connections
    std::atomic<bool> go{false};
    std::atomic<int> imported{0}, already{0}, other{0};
    std::vector<std::thread> ts;
    for (int i = 0; i < kThreads; ++i) {
        ts.emplace_back([&] {
            while (!go.load())
                std::this_thread::yield();
            auto r = f.db->import_legacy_tokens("enrollment-tokens.cfg", "fp-same", rows, "test");
            if (r && r->status == ei::ImportStatus::imported && r->counts.imported == 25)
                imported.fetch_add(1);
            else if (r && r->status == ei::ImportStatus::already_imported)
                already.fetch_add(1);
            else
                other.fetch_add(1);
        });
    }
    go.store(true);
    for (auto& t : ts)
        t.join();
    CHECK(imported.load() == 1);
    CHECK(already.load() == kThreads - 1);
    CHECK(other.load() == 0);
    CHECK(f.mgr.list_enrollment_tokens().value().size() == 25);
    CHECK(f.sql("SELECT count(*) FROM auth.import_meta") == "1");
}

TEST_CASE("import: a token_id collision between DIFFERENT hashes keeps both tokens",
          "[pg][enrollment_import]") {
    ImportFixture f;
    const auto h1 = fake_hash("abcdef12", 'a');
    const auto h2 = fake_hash("abcdef12", 'b'); // same 8-hex id, different token
    const auto h3 = fake_hash("abcdef12", 'c'); // collides with a PRE-EXISTING PG token below
    yuzu::server::pg::PgResult pre{PQexec(
        f.side.get(),
        ("INSERT INTO auth.enrollment_tokens (token_id, token_hash, label, max_uses, created_by) "
         "VALUES ('abcdef12','" + fake_hash("abcdef12", 'z') + "','pg-owner',1,'admin')").c_str())};
    REQUIRE(pre.ok());
    write_file(f.cfg_dir.path / "enrollment-tokens.cfg",
               kHeaderTokens + token_line(h1, "one", 1, 0, 1, 0, false) + "\n" +
                   token_line(h2, "two", 1, 0, 1, 0, false) + "\n" +
                   token_line(h3, "three", 1, 0, 1, 0, false) + "\n");
    const auto r = f.run(f.cfg_only());
    CHECK_FALSE(r.fatal);
    const auto& t = f.report(r, "tokens");
    CHECK(t.counts.imported == 3);
    CHECK(t.counts.id_disambiguated == 3); // all three had to move off the taken 8-hex id
    CHECK(t.counts.failed == 0);
    CHECK(f.sql("SELECT count(*) FROM auth.enrollment_tokens") == "4");
    CHECK(f.sql("SELECT count(DISTINCT token_id) FROM auth.enrollment_tokens") == "4");
    CHECK(f.sql("SELECT label FROM auth.enrollment_tokens WHERE token_id='abcdef12'") == "pg-owner");
    // Each imported token remains addressable by its (longer) id and consumable.
    CHECK(f.sql(("SELECT token_id FROM auth.enrollment_tokens WHERE token_hash='" + h1 + "'").c_str()).size() > 8);
}

TEST_CASE("import: both locations hold a file - the data-dir copy wins, the config-dir copy is "
          "left and reported",
          "[pg][enrollment_import]") {
    ImportFixture f;
    write_file(f.cfg_dir.path / "pending-agents.cfg",
               kHeaderPending + pending_line("from-cfg-dir", "h", "approved") + "\n");
    write_file(f.data_dir.path / "pending-agents.cfg",
               kHeaderPending + pending_line("from-data-dir", "h", "approved") + "\n");
    const auto r = f.run(f.both());
    CHECK_FALSE(r.fatal);
    const auto& p = f.report(r, "pending");
    CHECK(p.outcome == ei::Outcome::imported);
    CHECK(p.source == f.data_dir.path / "pending-agents.cfg");
    CHECK(p.other_copy == f.cfg_dir.path / "pending-agents.cfg");
    CHECK(f.mgr.get_pending_status("from-data-dir").value().has_value());
    CHECK_FALSE(f.mgr.get_pending_status("from-cfg-dir").value().has_value());
    CHECK(file_present(f.cfg_dir.path / "pending-agents.cfg")); // untouched
    CHECK(file_present(f.data_dir.path / "pending-agents.cfg.imported"));
}

TEST_CASE("import: garbled / ':' / NUL / oversize lines never abort the import",
          "[pg][enrollment_import]") {
    ImportFixture f;
    const auto ok1 = AuthManager::sha256_hex("ok1"), ok2 = AuthManager::sha256_hex("ok2");
    std::string with_nul = token_line(AuthManager::sha256_hex("nul"), "n", 1, 0, 1, 0, false);
    with_nul[3] = '\0';
    write_file(f.cfg_dir.path / "enrollment-tokens.cfg",
               kHeaderTokens + token_line(ok1, "plain", 1, 0, 1, 0, false) + "\n" + "@@@@\n" +
                   ok2.substr(0, 8) + ":" + ok2 + ":has:colon:in:label:2:0:1700000000:0:0\n" +
                   token_line(AuthManager::sha256_hex("big"), std::string(400, 'x'), 1, 0, 1, 0, false) + "\n" +
                   with_nul + "\n");
    const auto r = f.run(f.cfg_only());
    CHECK_FALSE(r.fatal);
    const auto& t = f.report(r, "tokens");
    CHECK(t.outcome == ei::Outcome::imported);
    CHECK(t.counts.imported == 2);
    CHECK(t.parse.garbled == 3);
    CHECK(t.parse.recovered == 1);
    CHECK(f.sql(("SELECT label FROM auth.enrollment_tokens WHERE token_hash='" + ok2 + "'").c_str()) ==
          "has:colon:in:label");
}

TEST_CASE("import: a PG error with a file present is FATAL, rolls back, stamps nothing, keeps "
          "the file",
          "[pg][enrollment_import]") {
    ImportFixture f;
    write_file(f.cfg_dir.path / "pending-agents.cfg",
               kHeaderPending + pending_line("ag-1", "h", "approved") + "\n");
    yuzu::server::pg::PgResult drop{PQexec(f.side.get(), "DROP TABLE auth.import_meta")};
    REQUIRE(drop.ok());
    yuzu::MetricsRegistry metrics;
    const auto r = f.run(f.cfg_only(), &metrics); // must not throw
    CHECK(r.fatal);
    CHECK(f.report(r, "pending").outcome == ei::Outcome::error);
    CHECK(file_present(f.cfg_dir.path / "pending-agents.cfg"));
    CHECK(f.sql("SELECT count(*) FROM auth.pending_agents") == "0"); // rows rolled back too
    CHECK(metrics.counter("yuzu_server_enrollment_import_total",
                          {{"kind", "pending"}, {"outcome", "error"}}).value() == 1.0);
}

TEST_CASE("import: an unreadable/oversize file is fatal, not silently skipped",
          "[pg][enrollment_import]") {
    ImportFixture f;
    // A directory named like the file is "present" to is_regular_file? No - so use a
    // file over the size cap instead (sparse, cheap).
    const auto path = f.cfg_dir.path / "enrollment-tokens.cfg";
    write_file(path, "");
    std::error_code ec;
    fs::resize_file(path, ei::kMaxImportFileBytes + 1, ec);
    REQUIRE_FALSE(ec);
    const auto r = f.run(f.cfg_only());
    CHECK(r.fatal);
    CHECK(f.report(r, "tokens").outcome == ei::Outcome::error);
    CHECK(f.sql("SELECT count(*) FROM auth.import_meta") == "0");
}

TEST_CASE("import: two file tokens sharing an 8-hex id (the old map-overwrite bug) both survive",
          "[pg][enrollment_import]") {
    ImportFixture f;
    const auto h1 = fake_hash("deadbeef", 'a');
    const auto h2 = fake_hash("deadbeef", 'b');
    write_file(f.cfg_dir.path / "enrollment-tokens.cfg",
               kHeaderTokens + token_line(h1, "first", 1, 0, 1, 0, false) + "\n" +
                   token_line(h2, "second", 1, 0, 1, 0, false) + "\n");
    const auto r = f.run(f.cfg_only());
    const auto& t = f.report(r, "tokens");
    CHECK(t.counts.imported == 2);
    CHECK(t.counts.id_disambiguated == 1); // the first keeps the plain id, the second moves
    CHECK(f.sql(("SELECT token_id FROM auth.enrollment_tokens WHERE token_hash='" + h1 + "'").c_str()) ==
          "deadbeef");
    CHECK(f.sql(("SELECT length(token_id) FROM auth.enrollment_tokens WHERE token_hash='" + h2 + "'").c_str()) ==
          "12");
    CHECK(f.mgr.list_enrollment_tokens().value().size() == 2);
}
