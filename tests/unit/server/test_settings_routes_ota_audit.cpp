/// @file test_settings_routes_ota_audit.cpp
///
/// The OTA rollout route's audit row (#3692).
///
/// WHY THIS EXISTS. #3692 reports that the OTA package-management routes gate on
/// `admin_fn_` but never call `audit_fn_` — they only `spdlog::info`, which is
/// the application log, not the audit log. There is no compensating global
/// mechanism: `server.cpp`'s pre/post-routing handlers cover auth, quota, metrics
/// and security headers, not audit emission. So the row either comes from the
/// handler or it does not exist, and nothing but a test at this level can tell
/// the two apart.
///
/// The scenario the issue names is an admin — or a compromised admin session —
/// silently de-prioritising a mandatory security patch. What makes that
/// reconstructable is not "a rollout change happened" but the PRIOR value: 0%
/// alone cannot distinguish a patch pulled back from one never rolled out. These
/// cases therefore assert the `from=`/`to=` pair, not merely that a row landed.
///
/// This drives the real route through `TestRouteSink` against a real PG-backed
/// `UpdateRegistry`, because the value under test is what the HANDLER emits.
/// A pure-function test would pin the string and prove nothing about whether the
/// handler calls it.

#include "settings_routes.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_route_sink.hpp"
#include "update_registry.hpp"
#include "url_attr_scan.hpp"
#include "../test_helpers.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <libpq-fe.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <chrono>
#include <thread>
#include <string>
#include <stdexcept>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

/// Pre-migrated template: `UpdateRegistry`'s constructor runs its own migration,
/// and per-test migration DDL is what drove the 2026-07-12 Windows server-suite
/// timeout. Cloning an already-migrated database keeps this route test off that
/// path.
yuzu::test::PgTestTemplate ota_audit_tpl{"otaaudit", [](const std::string& dsn) {
    pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    if (!pool.valid())
        throw std::runtime_error("ota_audit_tpl: pool invalid");
    yuzu::test::TempDir dir{"yuzu_test_ota_tpl_"};
    UpdateRegistry reg{pool, dir.path};
    if (!reg.is_open())
        throw std::runtime_error("ota_audit_tpl: UpdateRegistry migration failed");
}};

struct AuditRow {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

struct OtaAuditHarness {
    yuzu::test::TempDir update_dir{"yuzu_test_ota_updates_"};
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty

    std::optional<pg::PgPool> pool;
    std::unique_ptr<UpdateRegistry> registry;
    SettingsRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    std::vector<AuditRow> audited;

    explicit OtaAuditHarness(const std::string& dsn) {
        pool.emplace(pg::PgPool::Options{.conninfo = dsn, .size = 4});
        REQUIRE(pool->valid());
        registry = std::make_unique<UpdateRegistry>(*pool, update_dir.path);
        REQUIRE(registry->is_open());
        register_on(routes, sink);
    }

    /// Registers the OTA routes on `r`/`s` with this harness's registry and audit capture.
    /// The TestRouteSink path (ctor) hands the handler a matches vector directly; a second
    /// registration on a real httplib::Server proves what the wire does to an encoded URL.
    void register_on(SettingsRoutes& r, HttpRouteSink& route_sink) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "admin";
            s.role = auth::Role::admin;
            return s;
        };
        auto admin_fn = [](const httplib::Request&, httplib::Response&) { return true; };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& ttype,
                               const std::string& tid, const std::string& detail) -> bool {
            audited.push_back(AuditRow{action, result, ttype, tid, detail});
            return true;
        };
        r.register_routes(route_sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve,
                               /*api_token_store=*/nullptr,
                               /*mgmt_group_store=*/nullptr,
                               /*tag_store=*/nullptr, registry.get(),
                               /*runtime_config_store=*/nullptr,
                               /*audit_store=*/nullptr,
                               /*gateway_enabled=*/false, []() -> std::size_t { return 0; },
                               []() -> std::string { return "[]"; }, oidc_mu, oidc_provider);
    }

    void seed(int rollout_pct, bool mandatory) {
        UpdatePackage pkg;
        pkg.platform = "linux";
        pkg.arch = "x86_64";
        pkg.version = "1.2.3";
        pkg.sha256 = std::string(64, 'a');
        pkg.filename = "yuzu-agent-1.2.3";
        pkg.mandatory = mandatory;
        pkg.rollout_pct = rollout_pct;
        pkg.file_size = 1024;
        (void)registry->upsert_package(pkg);
    }

    /// The content type is passed explicitly because `TestRouteSink`'s contract
    /// requires it for a form body. Note this route does NOT read `req.params` --
    /// it calls `extract_form_value(req.body, ...)`, which is body-only -- so the
    /// #1786 params-are-empty false-green does not apply here. Passing it anyway
    /// keeps the request shaped like the production one rather than relying on
    /// that implementation detail staying true.
    std::unique_ptr<httplib::Response> post_rollout(const std::string& version,
                                                    const std::string& pct) {
        return sink.Post("/api/settings/updates/linux/x86_64/" + version + "/rollout",
                         "rollout_pct=" + pct, "application/x-www-form-urlencoded");
    }
};

} // namespace

TEST_CASE("OTA rollout change is audited with the value it changed FROM (#3692)",
          "[ota][audit][settings_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/100, /*mandatory=*/true);

    auto res = h.post_rollout("1.2.3", "0");
    REQUIRE(res);
    CHECK(res->status == 200);

    REQUIRE(h.audited.size() == 1);
    const auto& row = h.audited.front();
    CHECK(row.action == "ota.package.rollout_changed");
    CHECK(row.result == "success");
    CHECK(row.target_type == "UpdatePackage");
    CHECK(row.target_id == "linux/x86_64/1.2.3");

    // The load-bearing assertion. Without the prior value the row cannot
    // distinguish a mandatory patch being pulled back from one that was never
    // rolled out, which is the whole scenario #3692 describes.
    CHECK(row.detail.find("from=100%") != std::string::npos);
    CHECK(row.detail.find("to=0%") != std::string::npos);
    CHECK(row.detail.find("mandatory=true") != std::string::npos);

    // And the change actually landed, so the row is not describing a no-op.
    auto pkgs = h.registry->list_packages();
    REQUIRE(pkgs.size() == 1);
    CHECK(pkgs.front().rollout_pct == 0);
}

TEST_CASE("OTA rollout on a package that does not exist records not_found, not success",
          "[ota][audit][settings_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/50, /*mandatory=*/false);

    auto res = h.post_rollout("9.9.9", "0");
    REQUIRE(res);
    CHECK(res->status == 200);

    // Recording a fictional success would put an event in the evidence store that
    // never happened. The token is `denied` with the reason in `detail`, matching
    // this file's own rejection branches (`user.delete` -> "denied" /
    // "invalid_username") -- and, decisively, matching the filter audit-log.md
    // tells operators to use for enumeration (`result == "denied"`). A bespoke
    // fourth token would be invisible to that rule.
    REQUIRE(h.audited.size() == 1);
    CHECK(h.audited.front().action == "ota.package.rollout_changed");
    CHECK(h.audited.front().result == "denied");
    CHECK(h.audited.front().detail == "not_found");
    CHECK(h.audited.front().target_id == "linux/x86_64/9.9.9");

    // The real package is untouched.
    auto pkgs = h.registry->list_packages();
    REQUIRE(pkgs.size() == 1);
    CHECK(pkgs.front().rollout_pct == 50);
}

TEST_CASE("OTA rollout change refuses an empty or above-100 percentage and changes nothing",
          "[ota][audit][settings_routes][pg][numeric_params]") {
    // Both used to become 100 (the empty default, and the clamp), i.e. a blank or typo'd
    // field flipped an existing package to a FULL-FLEET rollout. Now a 400 with the stored
    // percentage untouched; 0, 50 and 100 are still accepted.
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/10, /*mandatory=*/false);

    // "%205" is a form-encoded leading space (" 5"): whitespace is not part of a base-10 integer,
    // so it is refused rather than trimmed.
    for (const char* bad : {"", "101", "500", "%205"}) {
        INFO("rollout_pct='" << bad << "'");
        auto res = h.post_rollout("1.2.3", bad);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.registry->list_packages().front().rollout_pct == 10);
    }
    CHECK(h.audited.empty());

    for (const int ok : {0, 50, 100}) {
        INFO("rollout_pct=" << ok);
        auto res = h.post_rollout("1.2.3", std::to_string(ok));
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(h.registry->list_packages().front().rollout_pct == ok);
    }

    // A negative value keeps its documented clamp to 0 (the least exposure, never a full-fleet
    // value), and a percent-encoded digit is decoded before the parse.
    h.seed(/*rollout_pct=*/60, /*mandatory=*/false);
    auto neg = h.post_rollout("1.2.3", "-5");
    REQUIRE(neg);
    CHECK(neg->status == 200);
    CHECK(h.registry->list_packages().front().rollout_pct == 0);
    // The audit row reports the stored value, never the raw -5 the caller sent.
    REQUIRE_FALSE(h.audited.empty());
    CHECK(h.audited.back().detail.find("to=0%") != std::string::npos);
    CHECK(h.audited.back().detail.find("-5") == std::string::npos);
    auto encoded = h.post_rollout("1.2.3", "%37");
    REQUIRE(encoded);
    CHECK(encoded->status == 200);
    CHECK(h.registry->list_packages().front().rollout_pct == 7);
}

TEST_CASE("a rollout whose registry write does not commit is audited as failure, not success",
          "[ota][audit][settings_routes][pg]") {
    // The row reports a COMMITTED transition ("from=100% to=0%"). upsert_package
    // degrades on a closed store, a pool-acquire timeout or a query error, so
    // deriving the result from "we found the package" would let this row assert a
    // change that never reached the database — evidence that disagrees with
    // state, in the record an incident responder is supposed to be able to trust.
    //
    // THE INJECTION HAS TO BREAK THE WRITE AND LEAVE THE READ WORKING, or the
    // test proves nothing. A first version of this case dropped the table, which
    // also broke `list_packages` — so the handler took the package-not-found path
    // and the case passed against a deliberately broken build. A CHECK constraint
    // the new value violates fails the INSERT ... ON CONFLICT DO UPDATE while
    // SELECT keeps working, which is the state actually under test: found, not
    // committed.
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/100, /*mandatory=*/true);

    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult c{PQexec(conn.get(), "ALTER TABLE update_registry.update_packages "
                                          "ADD CONSTRAINT yuzu_test_no_zero_rollout "
                                          "CHECK (rollout_pct <> 0)")};
        REQUIRE(c.ok());
    }

    auto res = h.post_rollout("1.2.3", "0");
    REQUIRE(res);

    REQUIRE(h.audited.size() == 1);
    const auto& row = h.audited.front();
    CHECK(row.action == "ota.package.rollout_changed");
    // Found, so not `denied`; not committed, so emphatically not `success`.
    CHECK(row.result == "failure");
    // Pin the literal. Asserting only that "from=" is ABSENT would also pass on
    // an empty detail, which is the weaker claim.
    CHECK(row.detail == "attempted_from=100% attempted_to=0% mandatory=true "
                        "outcome=write_not_committed");

    // And the state genuinely did not change, which is what makes a `success`
    // row here a lie rather than a harmless imprecision.
    auto pkgs = h.registry->list_packages();
    REQUIRE(pkgs.size() == 1);
    CHECK(pkgs.front().rollout_pct == 100);
}

TEST_CASE("a rollout against a DEGRADED registry is audited as failure, never as not_found",
          "[ota][audit][settings_routes][pg]") {
    // The distinction this case exists for. The store's ordinary reads fail SOFT
    // (ADR-0061): a closed store, a pool timeout or a query error all return an
    // EMPTY list, indistinguishable from "no packages configured". Deriving the
    // audit result from that read would make a PG blip during a legitimate admin
    // rollout say `denied` / `not_found` -- which audit-log.md tells operators is
    // the filter for enumeration attempts. A database outage would manufacture
    // security alerts AND record, in the evidence trail, that a package which
    // exists did not.
    //
    // Dropping the table makes every read path degrade, which is exactly the
    // condition under test here (unlike the not-committed case, which must keep
    // the read working).
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/100, /*mandatory=*/true);

    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult drop{PQexec(conn.get(), "DROP TABLE update_registry.update_packages")};
        REQUIRE(drop.ok());
    }

    auto res = h.post_rollout("1.2.3", "0");
    REQUIRE(res);
    REQUIRE(h.audited.size() == 1);
    const auto& row = h.audited.front();
    CHECK(row.result == "failure");
    CHECK(row.result != "denied");            // the whole point
    CHECK(row.detail.find("not_found") == std::string::npos);
    CHECK(row.detail.find("store_unavailable") != std::string::npos);
    CHECK(row.detail.find("existence_unknown=true") != std::string::npos);
}

/// Block until a backend in this database is waiting on a lock, or give up.
///
/// The route runs on another thread and we must not commit the competing
/// transaction until it is genuinely blocked — otherwise it reads AFTER the
/// commit and the case passes whether or not the row was ever locked. (It did:
/// the first version of this test passed with `FOR UPDATE` deleted.)
///
/// Polling `pg_stat_activity` rather than sleeping a fixed time is what keeps
/// this a wait on OBSERVED STATE rather than a timing assumption; there is no
/// future or condition variable to wait on across a database connection. The
/// bound exists so a genuine absence of locking FAILS rather than hangs, and
/// returning false is itself a real assertion — see the call site.
[[nodiscard]] bool wait_for_lock_waiter(PGconn* conn) {
    for (int i = 0; i < 400; ++i) { // ~10s ceiling, far above any real wait
        pg::PgResult r{PQexec(conn, "SELECT count(*) FROM pg_stat_activity "
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

TEST_CASE("the audited from= is the value the commit replaced, not a stale snapshot",
          "[ota][audit][settings_routes][pg]") {
    // The falsifier for the round-1 blocker. The route used to read the prior
    // percentage on one autocommit statement and write on another, so a
    // concurrent write to the same key could land between them — and the row
    // then asserted `from=<a value this write did not replace>` under a
    // `result=success` that audit-log.md calls "the point of this row".
    //
    // A competing transaction changes the row to 55 and HOLDS the lock. The
    // route is then driven on another thread and must block; only once it is
    // observed blocked does the competing transaction commit. That ordering is
    // what makes the case decisive:
    //
    //   with the row lock — the route's SELECT ... FOR UPDATE waits, then reads
    //                       55, the value the commit left behind: from=55.
    //   without it        — the SELECT reads straight past the uncommitted row
    //                       and sees the OLD value (MVCC hands it the previous
    //                       version); only its UPDATE blocks. It then reports
    //                       from=100, a value it did not replace.
    //
    // Verified by mutation: deleting FOR UPDATE turns from=55 into from=100 and
    // reddens this case.
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/100, /*mandatory=*/true);

    pg::PgConn other{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(other.get()) == CONNECTION_OK);
    {
        pg::PgResult begin{PQexec(other.get(), "BEGIN")};
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        pg::PgResult upd{PQexec(other.get(),
                                "UPDATE update_registry.update_packages SET rollout_pct = 55 "
                                "WHERE platform = 'linux' AND arch = 'x86_64' "
                                "AND version = '1.2.3'")};
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
    }

    std::unique_ptr<httplib::Response> res;
    std::thread worker([&] { res = h.post_rollout("1.2.3", "7"); });

    // Not a courtesy wait: if nothing ever blocks, nothing locked the row, and
    // that is the defect this case exists to catch.
    const bool blocked = wait_for_lock_waiter(other.get());
    pg::PgResult commit{PQexec(other.get(), "COMMIT")};
    worker.join(); // happens-before for everything the worker wrote
    CHECK(blocked);
    REQUIRE(commit.status() == PGRES_COMMAND_OK);

    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.audited.size() == 1);
    const auto& row = h.audited.front();
    CHECK(row.result == "success");

    // 55, not 100: the value the committed write actually replaced.
    CHECK(row.detail.find("from=55%") != std::string::npos);
    CHECK(row.detail.find("from=100%") == std::string::npos);
    CHECK(row.detail.find("to=7%") != std::string::npos);

    auto pkgs = h.registry->list_packages();
    REQUIRE(pkgs.size() == 1);
    CHECK(pkgs.front().rollout_pct == 7);
}

TEST_CASE("a rollout write does not clobber a concurrent change to another column",
          "[ota][audit][settings_routes][pg]") {
    // The other half of the same defect. The old path wrote the WHOLE snapshot
    // back via upsert_package, so a rollout edit silently reverted any other
    // column a concurrent writer had changed — `mandatory` above all, which is
    // what makes a de-prioritisation consequential in the first place.
    // update_rollout_checked writes rollout_pct and nothing else.
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/100, /*mandatory=*/false);

    pg::PgConn other{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(other.get()) == CONNECTION_OK);
    {
        pg::PgResult begin{PQexec(other.get(), "BEGIN")};
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        pg::PgResult upd{PQexec(other.get(),
                                "UPDATE update_registry.update_packages SET mandatory = true "
                                "WHERE platform = 'linux' AND arch = 'x86_64' "
                                "AND version = '1.2.3'")};
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
    }

    std::unique_ptr<httplib::Response> res;
    std::thread worker([&] { res = h.post_rollout("1.2.3", "10"); });
    pg::PgResult commit{PQexec(other.get(), "COMMIT")};
    REQUIRE(commit.status() == PGRES_COMMAND_OK);
    worker.join();

    REQUIRE(res);
    auto pkgs = h.registry->list_packages();
    REQUIRE(pkgs.size() == 1);
    CHECK(pkgs.front().rollout_pct == 10);
    // The concurrent writer's change survives, and the audit row saw it.
    CHECK(pkgs.front().mandatory == true);
    REQUIRE(h.audited.size() == 1);
    CHECK(h.audited.front().detail.find("mandatory=true") != std::string::npos);
}

// #4644: a malformed rollout percentage must NOT fall back to 100 (a full-fleet rollout
// nobody asked for): 400, nothing stored, no audit row claiming a change happened.
TEST_CASE("OTA rollout with a malformed percentage is a 400 and changes nothing",
          "[ota][audit][settings_routes][pg][numeric_params]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/25, /*mandatory=*/false);
    for (const char* bad : {"50abc", "0x32", "1e1", "99999999999999999999"}) {
        INFO("rollout_pct=" << bad);
        auto res = h.post_rollout("1.2.3", bad);
        REQUIRE(res);
        CHECK(res->status == 400);
        // The dashboard drops 4xx bodies, so the operator only learns of the refusal from the toast.
        CHECK(res->get_header_value("HX-Trigger").find("nothing was changed") != std::string::npos);
    }
    CHECK(h.audited.empty());
    auto pkgs = h.registry->list_packages();
    REQUIRE(pkgs.size() == 1);
    CHECK(pkgs.front().rollout_pct == 25); // untouched, NOT 100
}

// ── Update-package row URLs: platform/arch/version are encoded segments ──────

TEST_CASE("update package rows encode each path part, and offer no action for an empty or "
          "dot-only part",
          "[ota][settings_routes][pg][url_path_segment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};

    auto put = [&](const std::string& platform, const std::string& arch,
                   const std::string& version) {
        UpdatePackage pkg;
        pkg.platform = platform;
        pkg.arch = arch;
        pkg.version = version;
        pkg.sha256 = std::string(64, 'a');
        pkg.filename = "f";
        pkg.file_size = 1024;
        REQUIRE(h.registry->upsert_package(pkg));
    };
    put("linux", "x86_64", "1.2.3+4/5?x#y");   // every delimiter in one part
    put("lin/ux", "x 86", "9.9.9");           // other parts
    put("..", "x86_64", "1.0.0");              // dot-only platform
    put("linux", ".", "1.0.1");                // dot-only arch
    put("linux", "x86_64", "..");              // dot-only version

    auto res = h.sink.Get("/fragments/settings/updates");
    REQUIRE(res);
    const auto urls = yuzu::test::url_attr_values(res->body);

    const std::string a = "/api/settings/updates/linux/x86_64/" +
                          yuzu::server::url_path_segment("1.2.3+4/5?x#y");
    const std::string b = "/api/settings/updates/" + yuzu::server::url_path_segment("lin/ux") +
                          "/" + yuzu::server::url_path_segment("x 86") + "/9.9.9";
    CHECK(yuzu::test::has_url(urls, a + "/rollout"));
    CHECK(yuzu::test::has_url(urls, a));
    CHECK(yuzu::test::has_url(urls, b + "/rollout"));
    CHECK(yuzu::test::has_url(urls, b));
    for (const auto& u : urls) {
        CHECK_FALSE(yuzu::test::path_has_dot_segment(u));
        if (u.rfind("/api/settings/updates/", 0) == 0 && u != "/api/settings/updates/upload") {
            // exactly /api/settings/updates/<p>/<a>/<v>[/rollout]; the upload form
            // posts to the fixed /api/settings/updates/upload and is not a package row
            const auto n = yuzu::test::path_slashes(u);
            CHECK((n == 6 || n == 7));
        }
    }
    // The three dot-only packages are listed but carry no rollout/delete action.
    CHECK(res->body.find("identifier not supported for actions") != std::string::npos);
}

// ── The hosted Agent Updates fragment (System > Plugins and updates, SYS-3) ───
//
// The same fragment backs /settings and /settings/plugins. These pin the form edits the
// System page relies on: a required number input prefilled with the current rollout (a
// blank value is read as 100 by the handler), no inline handler, percent-encoded package
// URLs, and the data-* the page's confirm listener reads.

TEST_CASE("updates fragment: rollout is a required whole-number input, prefilled, with no inline handler",
          "[ota][settings_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/37, /*mandatory=*/true);

    auto res = h.sink.Get("/fragments/settings/updates");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    const auto& b = res->body;
    CHECK(b.find("<input type=\"text\" inputmode=\"numeric\" name=\"rollout_pct\" "
                 "pattern=\"(100|[1-9]?[0-9])\" required value=\"37\"") != std::string::npos);
    CHECK(b.find("type=\"range\"") == std::string::npos);
    CHECK(b.find("onchange=") == std::string::npos);
    CHECK(b.find("hx-on") == std::string::npos);
    // What the page's confirm listener reads: the rollout form and the row it sits in.
    CHECK(b.find("data-confirm=\"rollout\"") != std::string::npos);
    CHECK(b.find("data-mandatory=\"yes\"") != std::string::npos);
    CHECK(b.find("data-signed=\"no\"") != std::string::npos);
    CHECK(b.find("<tr data-platform=\"linux\" data-arch=\"x86_64\" data-version=\"1.2.3\" "
                 "data-rollout=\"37\">") != std::string::npos);
    // The operator guidance the edit added: what names the version, the signature limits, and
    // what a rollout percentage means.
    CHECK(b.find("The file name becomes the version.") != std::string::npos);
    CHECK(b.find("PEM CMS block, up to 64 KB.") != std::string::npos);
    CHECK(b.find("chosen by device identity") != std::string::npos);
    // The upload form asks for confirmation too, and its rollout cannot be blank.
    CHECK(b.find("data-confirm=\"ota-upload\"") != std::string::npos);
    CHECK(b.find("inputmode=\"numeric\" name=\"rollout_pct\" pattern=\"(100|[1-9]?[0-9])\" required "
                 "value=\"100\"") !=
          std::string::npos);
}

TEST_CASE("updates fragment: package URLs are percent-encoded", "[ota][settings_routes][pg]") {
    // is_safe_package_filename refuses only empty, `.`, `..` and `/ \ :`, so `#`, `?`, `%`
    // and a space are legal in a version stem. html_escape alone sent Roll out / Delete to
    // the wrong URL for them.
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    UpdatePackage pkg;
    pkg.platform = "linux";
    pkg.arch = "x86_64";
    pkg.version = "1.2#3?x%y z";
    pkg.sha256 = std::string(64, 'b');
    pkg.filename = "yuzu-agent-odd";
    pkg.rollout_pct = 10;
    pkg.file_size = 1024;
    REQUIRE(h.registry->upsert_package(pkg));

    auto res = h.sink.Get("/fragments/settings/updates");
    REQUIRE(res);
    const auto& b = res->body;
    const std::string enc = "/api/settings/updates/linux/x86_64/1.2%233%3Fx%25y%20z";
    CHECK(b.find("hx-post=\"" + enc + "/rollout\"") != std::string::npos);
    CHECK(b.find("hx-delete=\"" + enc + "\"") != std::string::npos);
    // The displayed version and the data attribute stay human-readable, escaped.
    CHECK(b.find("data-version=\"1.2#3?x%y z\"") != std::string::npos);
}

TEST_CASE("updates fragment: an encoded package URL reaches the handler decoded, over a real socket",
          "[ota][settings_routes][pg]") {
    // The fragment emits url_encode(version). The route tests above hand the handler a
    // pre-split matches vector, which proves nothing about the wire. This drives the
    // encoded URL exactly as htmx sends it (%23 %3F %25 %20) through a real httplib::Server
    // and asserts the handler and the audit row see the original, decoded version.
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    UpdatePackage pkg;
    pkg.platform = "linux";
    pkg.arch = "x86_64";
    pkg.version = "1.2#3?x%y z";
    pkg.sha256 = std::string(64, 'c');
    pkg.filename = "yuzu-agent-odd";
    pkg.rollout_pct = 10;
    pkg.file_size = 1024;
    REQUIRE(h.registry->upsert_package(pkg));

    httplib::Server svr;
    SettingsRoutes wire_routes;
    HttplibRouteSink wire_sink{svr, yuzu::server::StageRequirement::ExemptNoStage};
    h.register_on(wire_routes, wire_sink);
    const int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread t([&svr] { svr.listen_after_bind(); });
    // A failing REQUIRE below throws; the guard stops and joins so it reports red instead of
    // terminating the whole test binary on a joinable thread.
    yuzu::test::ScopeExit stop_server{[&] {
        svr.stop();
        if (t.joinable())
            t.join();
    }};
    svr.wait_until_ready();

    httplib::Client cli("127.0.0.1", port);
    cli.set_read_timeout(10, 0); // a hung handler fails the case, not the CI job's patience
    const std::string enc = "/api/settings/updates/linux/x86_64/1.2%233%3Fx%25y%20z";
    auto roll = cli.Post(enc + "/rollout", "rollout_pct=55", "application/x-www-form-urlencoded");
    REQUIRE(roll);
    CHECK(roll->status == 200);
    const auto after_roll = h.registry->list_packages();
    auto del = cli.Delete(enc);
    REQUIRE(del);
    CHECK(del->status == 200);

    // Stop and join before reading what the worker threads wrote: that is the happens-before
    // edge a socket round-trip does not give a thread sanitizer.
    svr.stop();
    t.join();
    REQUIRE(after_roll.size() == 1);
    CHECK(after_roll.front().version == "1.2#3?x%y z");
    CHECK(after_roll.front().rollout_pct == 55);
    CHECK(h.registry->list_packages().empty());
    REQUIRE(h.audited.size() >= 2);
    const auto& rolled = h.audited[h.audited.size() - 2];
    CHECK(rolled.action == "ota.package.rollout_changed");
    CHECK(rolled.result == "success");
    CHECK(rolled.target_id == "linux/x86_64/1.2#3?x%y z");
    CHECK(h.audited.back().action == "ota.package.deleted");
    CHECK(h.audited.back().target_id == "linux/x86_64/1.2#3?x%y z");
}

// ── Upload and delete: input validation and honest write outcomes ───────────

namespace {

/// The OTA routes behind a real socket. The upload route reads a multipart body, which
/// `TestRouteSink` does not model, so these cases need a live `httplib::Server`.
struct OtaWireServer {
    httplib::Server svr;
    SettingsRoutes routes;
    HttplibRouteSink sink;
    std::thread th;
    int port{0};

    explicit OtaWireServer(OtaAuditHarness& h)
        : sink{svr, yuzu::server::StageRequirement::ExemptNoStage} {
        h.register_on(routes, sink);
        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        th = std::thread([this] { svr.listen_after_bind(); });
        svr.wait_until_ready();
    }
    /// Stop and join: the happens-before edge before the test reads what the workers wrote.
    void stop() {
        svr.stop();
        if (th.joinable())
            th.join();
    }
    ~OtaWireServer() { stop(); }
};

constexpr const char* kUploadUrl = "/api/settings/updates/upload";

std::size_t entries_in(const fs::path& dir) {
    std::size_t n = 0;
    std::error_code ec;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec))
        ++n;
    return n;
}

bool has_audit(const OtaAuditHarness& h, const std::string& action, const std::string& result) {
    for (const auto& r : h.audited)
        if (r.action == action && r.result == result)
            return true;
    return false;
}

void write_file(const fs::path& p, const std::string& content) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << content;
}

const std::string kTestCms =
    "-----BEGIN CMS-----\nQUJDRA==\n-----END CMS-----\n";

} // namespace

TEST_CASE("OTA upload refuses a NUL or control byte in platform or arch and writes nothing",
          "[ota][settings_routes][pg][validation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    OtaWireServer wire{h};
    httplib::Client cli("127.0.0.1", wire.port);
    cli.set_read_timeout(10, 0);
    const httplib::UploadFormDataItems items{
        {"file", "binary-bytes", "yuzu-agent-1.0.0", "application/octet-stream"}};

    for (const char* query : {"?platform=lin%00ux&arch=x86_64", "?platform=linux&arch=x86%00_64",
                              "?platform=lin%1bux&arch=x86_64", "?platform=linux&arch=x86%09_64",
                              "?platform=linux%7f&arch=x86_64"}) {
        INFO("query=" << query);
        auto res = cli.Post(std::string(kUploadUrl) + query, items);
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    wire.stop();

    // Every refusal is one denied row with a fixed token and no echo of the input.
    REQUIRE(h.audited.size() == 5);
    for (const auto& row : h.audited) {
        CHECK(row.action == "ota.package.uploaded");
        CHECK(row.result == "denied");
        CHECK(row.target_type == "UpdatePackage");
        CHECK(row.target_id.empty());
        CHECK(row.detail == "invalid_package_field");
    }
    CHECK_FALSE(has_audit(h, "ota.package.uploaded", "success"));
    // Nothing was written: no binary, no sidecar, no staging file, no registry row.
    CHECK(entries_in(h.update_dir.path) == 0);
    CHECK(h.registry->list_packages().empty());
}

TEST_CASE("OTA upload with clean fields still succeeds and audits success",
          "[ota][settings_routes][pg][validation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    OtaWireServer wire{h};
    httplib::Client cli("127.0.0.1", wire.port);
    cli.set_read_timeout(10, 0);
    const httplib::UploadFormDataItems items{
        {"file", "binary-bytes", "yuzu-agent-1.0.0", "application/octet-stream"}};

    auto res = cli.Post(std::string(kUploadUrl) + "?platform=linux&arch=x86_64", items);
    REQUIRE(res);
    CHECK(res->status == 200);
    wire.stop();

    REQUIRE(h.audited.size() == 1);
    CHECK(h.audited.front().action == "ota.package.uploaded");
    CHECK(h.audited.front().result == "success");
    CHECK(h.audited.front().target_id == "linux/x86_64/yuzu-agent-1.0.0");
    const auto pkgs = h.registry->list_packages();
    REQUIRE(pkgs.size() == 1);
    CHECK(pkgs.front().filename == "yuzu-agent-1.0.0");
    CHECK(fs::exists(h.update_dir.path / "yuzu-agent-1.0.0"));
}

TEST_CASE("OTA upload whose registry write fails reports failure and removes the files",
          "[ota][settings_routes][pg][validation]") {
    // A CHECK constraint the default 100% rollout violates fails the INSERT while reads keep
    // working, so the route reaches the registry write with the files already published.
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult c{PQexec(conn.get(), "ALTER TABLE update_registry.update_packages "
                                          "ADD CONSTRAINT yuzu_test_no_full_rollout "
                                          "CHECK (rollout_pct <> 100)")};
        REQUIRE(c.ok());
    }
    OtaWireServer wire{h};
    httplib::Client cli("127.0.0.1", wire.port);
    cli.set_read_timeout(10, 0);
    const httplib::UploadFormDataItems unsigned_items{
        {"file", "binary-bytes", "yuzu-agent-1.0.0", "application/octet-stream"}};
    const httplib::UploadFormDataItems signed_items{
        {"file", "binary-bytes", "yuzu-agent-2.0.0", "application/octet-stream"},
        {"signature", kTestCms, "yuzu-agent-2.0.0.cms", "application/octet-stream"}};

    auto r1 = cli.Post(std::string(kUploadUrl) + "?platform=linux&arch=x86_64", unsigned_items);
    REQUIRE(r1);
    CHECK(r1->status == 503);
    auto r2 = cli.Post(std::string(kUploadUrl) + "?platform=linux&arch=x86_64", signed_items);
    REQUIRE(r2);
    CHECK(r2->status == 503);
    wire.stop();

    REQUIRE(h.audited.size() == 2);
    for (const auto& row : h.audited) {
        CHECK(row.action == "ota.package.uploaded");
        CHECK(row.result == "failure");
        CHECK(row.detail == "store_error");
    }
    CHECK_FALSE(has_audit(h, "ota.package.uploaded", "success"));
    CHECK(h.registry->list_packages().empty());
    // The binaries and the signature sidecar published before the failed write are gone.
    CHECK(entries_in(h.update_dir.path) == 0);
}

TEST_CASE("OTA delete refuses a control byte in the package key and changes nothing",
          "[ota][settings_routes][pg][validation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/100, /*mandatory=*/false);
    write_file(h.update_dir.path / "yuzu-agent-1.2.3", "bytes");

    auto res = h.sink.Delete(std::string("/api/settings/updates/linux/x86_64/1.2.3") +
                             std::string(1, '\0') + "x");
    REQUIRE(res);
    CHECK(res->status == 400);

    REQUIRE(h.audited.size() == 1);
    CHECK(h.audited.front().action == "ota.package.deleted");
    CHECK(h.audited.front().result == "denied");
    CHECK(h.audited.front().target_id.empty());
    CHECK(h.audited.front().detail == "invalid_package_field");
    CHECK(h.registry->list_packages().size() == 1);
    CHECK(fs::exists(h.update_dir.path / "yuzu-agent-1.2.3"));
}

TEST_CASE("OTA delete of a package removes the row and files and audits success",
          "[ota][settings_routes][pg][validation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/100, /*mandatory=*/false);
    write_file(h.update_dir.path / "yuzu-agent-1.2.3", "bytes");
    write_file(h.update_dir.path / "yuzu-agent-1.2.3.sig", kTestCms);

    auto res = h.sink.Delete("/api/settings/updates/linux/x86_64/1.2.3");
    REQUIRE(res);
    CHECK(res->status == 200);

    REQUIRE(h.audited.size() == 1);
    CHECK(h.audited.front().action == "ota.package.deleted");
    CHECK(h.audited.front().result == "success");
    CHECK(h.audited.front().detail == "binary removed, signature sidecar removed");
    CHECK(h.registry->list_packages().empty());
    CHECK(entries_in(h.update_dir.path) == 0);
}

TEST_CASE("OTA delete whose registry delete fails reports failure and leaves the files",
          "[ota][settings_routes][pg][validation]") {
    // A BEFORE DELETE trigger that raises fails the DELETE while the package list keeps
    // reading, so the route matches the package and then cannot remove its row.
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/100, /*mandatory=*/false);
    write_file(h.update_dir.path / "yuzu-agent-1.2.3", "bytes");
    write_file(h.update_dir.path / "yuzu-agent-1.2.3.sig", kTestCms);
    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult fn{PQexec(
            conn.get(), "CREATE FUNCTION update_registry.yuzu_test_block_delete() "
                        "RETURNS trigger LANGUAGE plpgsql AS "
                        "$$ BEGIN RAISE EXCEPTION 'delete blocked'; END $$")};
        REQUIRE(fn.ok());
        pg::PgResult trg{PQexec(
            conn.get(), "CREATE TRIGGER yuzu_test_block_delete BEFORE DELETE ON "
                        "update_registry.update_packages FOR EACH ROW EXECUTE FUNCTION "
                        "update_registry.yuzu_test_block_delete()")};
        REQUIRE(trg.ok());
    }

    auto res = h.sink.Delete("/api/settings/updates/linux/x86_64/1.2.3");
    REQUIRE(res);
    CHECK(res->status == 503);

    REQUIRE(h.audited.size() == 1);
    CHECK(h.audited.front().action == "ota.package.deleted");
    CHECK(h.audited.front().result == "failure");
    CHECK(h.audited.front().detail == "store_error");
    CHECK(h.audited.front().target_id == "linux/x86_64/1.2.3");
    CHECK_FALSE(has_audit(h, "ota.package.deleted", "success"));
    CHECK(h.registry->list_packages().size() == 1);
    CHECK(fs::exists(h.update_dir.path / "yuzu-agent-1.2.3"));
    CHECK(fs::exists(h.update_dir.path / "yuzu-agent-1.2.3.sig"));
}

// ── Overwrite safety, text validity and the checked listing ─────────────────

namespace {

std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

/// One text cell from a single-row, single-column query on a fresh connection.
std::string scalar_sql(const std::string& dsn, const char* sql) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r{PQexec(conn.get(), sql)};
    REQUIRE(r.ok());
    REQUIRE(PQntuples(r.get()) == 1);
    return PQgetvalue(r.get(), 0, 0);
}

bool any_entry_contains(const fs::path& dir, const std::string& needle) {
    std::error_code ec;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec))
        if (it->path().filename().string().find(needle) != std::string::npos)
            return true;
    return false;
}

const std::string kNewCms = "-----BEGIN CMS-----\nRUZHSA==\n-----END CMS-----\n";

} // namespace

TEST_CASE("OTA upload whose registry write fails restores the previous package and signature",
          "[ota][settings_routes][pg][validation]") {
    // The first upload publishes a signed package. A CHECK constraint then makes the
    // registry write of any 50% upload fail while reads keep working, so a re-upload of
    // the same filename reaches the write with the old files already replaced.
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    OtaWireServer wire{h};
    httplib::Client cli("127.0.0.1", wire.port);
    cli.set_read_timeout(10, 0);
    const std::string url = std::string(kUploadUrl) + "?platform=linux&arch=x86_64";

    auto r0 = cli.Post(url, httplib::UploadFormDataItems{
                                {"file", "old-bytes", "yuzu-agent-1.0.0", "application/octet-stream"},
                                {"signature", kTestCms, "old.cms", "application/octet-stream"}});
    REQUIRE(r0);
    REQUIRE(r0->status == 200);
    const auto before = h.registry->list_packages();
    REQUIRE(before.size() == 1);
    const std::string old_sha = before.front().sha256;
    const auto dir_count = entries_in(h.update_dir.path);
    CHECK(dir_count == 2); // the binary and its sidecar

    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult c{PQexec(conn.get(), "ALTER TABLE update_registry.update_packages "
                                          "ADD CONSTRAINT yuzu_test_no_half_rollout "
                                          "CHECK (rollout_pct <> 50)")};
        REQUIRE(c.ok());
    }

    // A signed re-upload, then an unsigned one: both fail at the registry write.
    auto r1 = cli.Post(
        url + "&rollout_pct=50",
        httplib::UploadFormDataItems{
            {"file", "new-bytes", "yuzu-agent-1.0.0", "application/octet-stream"},
            {"signature", kNewCms, "new.cms", "application/octet-stream"}});
    REQUIRE(r1);
    CHECK(r1->status == 503);
    auto r2 = cli.Post(url + "&rollout_pct=50",
                       httplib::UploadFormDataItems{{"file", "newer-bytes", "yuzu-agent-1.0.0",
                                                     "application/octet-stream"}});
    REQUIRE(r2);
    CHECK(r2->status == 503);
    wire.stop();

    REQUIRE(h.audited.size() == 3);
    CHECK(h.audited[0].result == "success");
    for (std::size_t i = 1; i < 3; ++i) {
        CHECK(h.audited[i].action == "ota.package.uploaded");
        CHECK(h.audited[i].result == "failure");
        CHECK(h.audited[i].detail == "store_error");
    }

    // The registry row, the binary and the signature are exactly as before.
    const auto after = h.registry->list_packages();
    REQUIRE(after.size() == 1);
    CHECK(after.front().sha256 == old_sha);
    CHECK(after.front().rollout_pct == 100);
    CHECK(read_file(h.update_dir.path / "yuzu-agent-1.0.0") == "old-bytes");
    CHECK(read_file(h.update_dir.path / "yuzu-agent-1.0.0.sig") == kTestCms);
    // And no kept copy or staging file is left behind.
    CHECK(entries_in(h.update_dir.path) == dir_count);
    CHECK_FALSE(any_entry_contains(h.update_dir.path, "yuzu_prev_"));
}

TEST_CASE("OTA re-upload over an existing filename succeeds and leaves no kept copies",
          "[ota][settings_routes][pg][validation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    OtaWireServer wire{h};
    httplib::Client cli("127.0.0.1", wire.port);
    cli.set_read_timeout(10, 0);
    const std::string url = std::string(kUploadUrl) + "?platform=linux&arch=x86_64";

    auto r0 = cli.Post(url, httplib::UploadFormDataItems{
                                {"file", "old-bytes", "yuzu-agent-1.0.0", "application/octet-stream"},
                                {"signature", kTestCms, "old.cms", "application/octet-stream"}});
    REQUIRE(r0);
    CHECK(r0->status == 200);
    auto r1 = cli.Post(
        url, httplib::UploadFormDataItems{
                 {"file", "new-bytes", "yuzu-agent-1.0.0", "application/octet-stream"},
                 {"signature", kNewCms, "new.cms", "application/octet-stream"}});
    REQUIRE(r1);
    CHECK(r1->status == 200);
    CHECK(read_file(h.update_dir.path / "yuzu-agent-1.0.0") == "new-bytes");
    CHECK(read_file(h.update_dir.path / "yuzu-agent-1.0.0.sig") == kNewCms);
    CHECK(entries_in(h.update_dir.path) == 2);
    CHECK_FALSE(any_entry_contains(h.update_dir.path, "yuzu_prev_"));

    // An unsigned re-upload replaces the binary and drops the old signature.
    auto r2 = cli.Post(url, httplib::UploadFormDataItems{{"file", "newer-bytes", "yuzu-agent-1.0.0",
                                                          "application/octet-stream"}});
    REQUIRE(r2);
    CHECK(r2->status == 200);
    wire.stop();
    CHECK(read_file(h.update_dir.path / "yuzu-agent-1.0.0") == "newer-bytes");
    CHECK_FALSE(fs::exists(h.update_dir.path / "yuzu-agent-1.0.0.sig"));
    CHECK(entries_in(h.update_dir.path) == 1);
    CHECK_FALSE(any_entry_contains(h.update_dir.path, "yuzu_prev_"));

    REQUIRE(h.audited.size() == 3);
    for (const auto& row : h.audited)
        CHECK(row.result == "success");
    CHECK(h.registry->list_packages().size() == 1);
}

TEST_CASE("OTA upload refuses invalid UTF-8 in platform or arch and writes nothing",
          "[ota][settings_routes][pg][validation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    OtaWireServer wire{h};
    httplib::Client cli("127.0.0.1", wire.port);
    cli.set_read_timeout(10, 0);
    const httplib::UploadFormDataItems items{
        {"file", "binary-bytes", "yuzu-agent-1.0.0", "application/octet-stream"}};

    for (const char* query :
         {"?platform=%FFlinux&arch=x86_64", "?platform=linux&arch=x86_%C0%80",
          "?platform=lin%ED%A0%80ux&arch=x86_64", "?platform=linux&arch=x86%E2%82"}) {
        INFO("query=" << query);
        auto res = cli.Post(std::string(kUploadUrl) + query, items);
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    wire.stop();

    REQUIRE(h.audited.size() == 4);
    for (const auto& row : h.audited) {
        CHECK(row.action == "ota.package.uploaded");
        CHECK(row.result == "denied");
        CHECK(row.target_id.empty());
        CHECK(row.detail == "invalid_package_field");
    }
    CHECK_FALSE(has_audit(h, "ota.package.uploaded", "success"));
    CHECK(entries_in(h.update_dir.path) == 0);
    CHECK(h.registry->list_packages().empty());
}

TEST_CASE("OTA upload refuses invalid UTF-8 or a control byte in the filename and writes nothing",
          "[ota][settings_routes][pg][validation]") {
    // Whether the HTTP layer lets these bytes through in a multipart filename is its own
    // behaviour: if it refuses the request first, no handler runs and no audit row exists.
    // Either way the answer is a 400 and nothing is written. When the handler does run,
    // the row is the fixed denied token.
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    OtaWireServer wire{h};
    httplib::Client cli("127.0.0.1", wire.port);
    cli.set_read_timeout(10, 0);

    for (const std::string& name :
         {std::string("yuzu-agent-\xff"), std::string("yuzu-agent-\xc0\x80"),
          std::string("yuzu-agent-\xed\xa0\x80"), std::string("yuzu-agent-\x01") + "1",
          std::string("yuzu-agent-\x1b") + "[0m"}) {
        INFO("filename bytes=" << name.size());
        auto res = cli.Post(std::string(kUploadUrl) + "?platform=linux&arch=x86_64",
                            httplib::UploadFormDataItems{
                                {"file", "binary-bytes", name, "application/octet-stream"}});
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    wire.stop();

    for (const auto& row : h.audited) {
        CHECK(row.action == "ota.package.uploaded");
        CHECK(row.result == "denied");
        CHECK(row.target_id.empty());
        CHECK(row.detail == "invalid_package_field");
    }
    CHECK_FALSE(has_audit(h, "ota.package.uploaded", "success"));
    CHECK(entries_in(h.update_dir.path) == 0);
    CHECK(h.registry->list_packages().empty());
}

TEST_CASE("OTA delete refuses invalid UTF-8 in the package key and changes nothing",
          "[ota][settings_routes][pg][validation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/100, /*mandatory=*/false);
    write_file(h.update_dir.path / "yuzu-agent-1.2.3", "bytes");

    auto res = h.sink.Delete(std::string("/api/settings/updates/linux/x86_64/1.2.3") + "\xff");
    REQUIRE(res);
    CHECK(res->status == 400);

    REQUIRE(h.audited.size() == 1);
    CHECK(h.audited.front().action == "ota.package.deleted");
    CHECK(h.audited.front().result == "denied");
    CHECK(h.audited.front().target_id.empty());
    CHECK(h.audited.front().detail == "invalid_package_field");
    CHECK(h.registry->list_packages().size() == 1);
    CHECK(fs::exists(h.update_dir.path / "yuzu-agent-1.2.3"));
}

TEST_CASE("OTA delete whose package listing cannot be read reports failure and removes nothing",
          "[ota][settings_routes][pg][validation]") {
    // A column the listing selects is renamed: the list read fails while a DELETE by key
    // would still succeed, so a route that treated the failed listing as "no such package"
    // would remove the row and leave its files behind.
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/100, /*mandatory=*/false);
    write_file(h.update_dir.path / "yuzu-agent-1.2.3", "bytes");
    write_file(h.update_dir.path / "yuzu-agent-1.2.3.sig", kTestCms);
    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult ren{PQexec(conn.get(), "ALTER TABLE update_registry.update_packages "
                                            "RENAME COLUMN uploaded_at TO yuzu_test_uploaded_at")};
        REQUIRE(ren.ok());
    }

    auto res = h.sink.Delete("/api/settings/updates/linux/x86_64/1.2.3");
    REQUIRE(res);
    CHECK(res->status == 503);

    REQUIRE(h.audited.size() == 1);
    CHECK(h.audited.front().action == "ota.package.deleted");
    CHECK(h.audited.front().result == "failure");
    CHECK(h.audited.front().detail == "store_error");
    CHECK(h.audited.front().target_id == "linux/x86_64/1.2.3");
    CHECK_FALSE(has_audit(h, "ota.package.deleted", "success"));
    CHECK_FALSE(has_audit(h, "ota.package.deleted", "denied"));
    // The row is still there (read directly: the listing is the broken read) and so are
    // both files.
    CHECK(scalar_sql(db.dsn(), "SELECT count(*) FROM update_registry.update_packages") == "1");
    CHECK(fs::exists(h.update_dir.path / "yuzu-agent-1.2.3"));
    CHECK(fs::exists(h.update_dir.path / "yuzu-agent-1.2.3.sig"));
}
