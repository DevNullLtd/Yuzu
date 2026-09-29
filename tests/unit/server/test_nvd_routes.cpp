/// @file test_nvd_routes.cpp
/// HTTP-level coverage for the NVD CVE-feed route module (#2542 follow-up)
/// — driven in-process through TestRouteSink (no httplib acceptor, #438),
/// mirroring test_page_routes.cpp's Harness shape. None of these 3 routes
/// touches Postgres: `NvdDatabase` is SQLite (`:memory:` here) and
/// `NvdSyncManager` is exercised with a mock `INvdFetcher` so no real
/// network/background sync thread ever runs (the manager is constructed but
/// `start()` is deliberately never called — `status()`/`request_sync()` are
/// safe without it, see nvd_sync.cpp).

#include "nvd_routes.hpp"
#include "test_route_sink.hpp"

#include "nvd_client.hpp"
#include "nvd_db.hpp"
#include "nvd_sync.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <memory>
#include <string>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

/// A fetcher that never actually fetches — every test here only exercises
/// status()/request_sync(), never sync_now()/start(), so this is never
/// invoked; it exists solely to satisfy NvdSyncManager's mock-fetcher
/// constructor.
class NullFetcher : public INvdFetcher {
public:
    NvdFetchResult fetch_by_published_window(const std::string&, const std::string&) override {
        return {};
    }
    NvdFetchResult fetch_modified_between(const std::string&, const std::string&) override {
        return {};
    }
};

CveRecord make_cve(std::string id, std::string product, std::string end_excluding,
                   std::string severity = "HIGH") {
    CveRecord rec;
    rec.cve_id = std::move(id);
    rec.severity = std::move(severity);
    rec.description = "Test vulnerability";
    rec.source = "nvd";
    CpeMatch cm;
    cm.cpe_product = std::move(product);
    cm.version_end_excluding = std::move(end_excluding);
    rec.matches.push_back(std::move(cm));
    return rec;
}

/// All providers injected and re-read per call, mirroring
/// test_page_routes.cpp's Harness shape. Both store pointers default to
/// null — the null/closed-store cases rely on that.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct Harness {
    bool perm_allow{true};
    std::string last_perm_type, last_perm_op;

    NvdDatabase* nvd_db{nullptr};
    NvdSyncManager* nvd_sync{nullptr};

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        nvd::Deps deps;
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) {
            last_perm_type = type;
            last_perm_op = op;
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return false;
            }
            return true;
        };
        deps.nvd_db = nvd_db;
        deps.nvd_sync = nvd_sync;
        nvd::register_nvd_routes(sink, deps);
    }
};

} // namespace

// ── Registration shape ────────────────────────────────────────────────────

TEST_CASE("nvd_routes: registers exactly 3 routes", "[server][routes][nvd_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 3);
}

// ── GET /api/nvd/status: perm_fn(Infrastructure, Read) ────────────────────

TEST_CASE("nvd_routes: /api/nvd/status gates on Infrastructure:Read and denies without it",
          "[server][routes][nvd_routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();

    auto r = h.sink.Get("/api/nvd/status");
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(h.last_perm_type == "Infrastructure");
    CHECK(h.last_perm_op == "Read");
}

TEST_CASE("nvd_routes: /api/nvd/status reports enabled:false without a 503 when the db is null",
          "[server][routes][nvd_routes]") {
    Harness h; // nvd_db stays null
    h.wire();

    auto r = h.sink.Get("/api/nvd/status");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["enabled"] == false);
}

TEST_CASE("nvd_routes: /api/nvd/status reports enabled:false with total_cves when the db is open "
          "but sync is unset (--no-nvd-sync)",
          "[server][routes][nvd_routes]") {
    NvdDatabase db(":memory:");
    REQUIRE(db.is_open());
    db.upsert_cve(make_cve("CVE-2024-0001", "widget", "2.0.0"));

    Harness h;
    h.nvd_db = &db;
    h.wire();

    auto r = h.sink.Get("/api/nvd/status");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["enabled"] == false); // enabled reflects sync-manager presence, not db-open
    CHECK(j["total_cves"] == 1);
    CHECK_FALSE(j.contains("syncing"));
}

TEST_CASE("nvd_routes: /api/nvd/status reports the full sync status shape when both db and sync "
          "are wired",
          "[server][routes][nvd_routes]") {
    auto shared_db = std::make_shared<NvdDatabase>(":memory:");
    REQUIRE(shared_db->is_open());
    shared_db->upsert_cve(make_cve("CVE-2024-0002", "gadget", "3.0.0"));

    NvdSyncManager sync{shared_db, std::make_unique<NullFetcher>(), std::chrono::seconds(3600), 8};

    Harness h;
    h.nvd_db = shared_db.get();
    h.nvd_sync = &sync;
    h.wire();

    auto r = h.sink.Get("/api/nvd/status");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["enabled"] == true);
    CHECK(j["total_cves"] == 1);
    // Freshly-constructed, never-started manager: default SyncStatus shape.
    CHECK(j["syncing"] == false);
    CHECK(j["last_sync_time"] == "");
    CHECK(j["last_error"] == "");
    CHECK(j["backfill_complete"] == false);
    CHECK(j["backfill_oldest_published"] == "");
}

// ── POST /api/nvd/sync: perm_fn(Infrastructure, Execute) ──────────────────

TEST_CASE("nvd_routes: /api/nvd/sync gates on Infrastructure:Execute and denies without it",
          "[server][routes][nvd_routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();

    auto r = h.sink.Post("/api/nvd/sync", "");
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(h.last_perm_type == "Infrastructure");
    CHECK(h.last_perm_op == "Execute");
}

TEST_CASE("nvd_routes: /api/nvd/sync 503s when nvd_sync is unset", "[server][routes][nvd_routes]") {
    Harness h; // nvd_sync stays null
    h.wire();

    auto r = h.sink.Post("/api/nvd/sync", "");
    REQUIRE(r);
    CHECK(r->status == 503);
}

TEST_CASE("nvd_routes: /api/nvd/sync requests a sync and answers sync_started when wired",
          "[server][routes][nvd_routes]") {
    auto shared_db = std::make_shared<NvdDatabase>(":memory:");
    NvdSyncManager sync{shared_db, std::make_unique<NullFetcher>(), std::chrono::seconds(3600), 8};

    Harness h;
    h.nvd_sync = &sync;
    h.wire();

    auto r = h.sink.Post("/api/nvd/sync", "");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["status"] == "sync_started");
}

// ── POST /api/nvd/match: perm_fn(Infrastructure, Read) ─────────────────────

TEST_CASE("nvd_routes: /api/nvd/match gates on Infrastructure:Read and denies without it",
          "[server][routes][nvd_routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();

    auto r = h.sink.Post("/api/nvd/match", R"({"inventory":[]})");
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(h.last_perm_type == "Infrastructure");
    CHECK(h.last_perm_op == "Read");
}

TEST_CASE("nvd_routes: /api/nvd/match 503s when the db is null or closed",
          "[server][routes][nvd_routes]") {
    Harness h; // nvd_db stays null
    h.wire();

    auto r = h.sink.Post("/api/nvd/match", R"({"inventory":[]})");
    REQUIRE(r);
    CHECK(r->status == 503);
}

TEST_CASE("nvd_routes: /api/nvd/match rejects invalid JSON with 400",
          "[server][routes][nvd_routes]") {
    NvdDatabase db(":memory:");
    Harness h;
    h.nvd_db = &db;
    h.wire();

    auto r = h.sink.Post("/api/nvd/match", "not json");
    REQUIRE(r);
    CHECK(r->status == 400);
}

TEST_CASE("nvd_routes: /api/nvd/match finds a vulnerable inventory item and reports the CveMatch "
          "shape",
          "[server][routes][nvd_routes]") {
    NvdDatabase db(":memory:");
    REQUIRE(db.is_open());
    db.upsert_cve(make_cve("CVE-2024-0003", "widget", "2.0.0", "CRITICAL"));

    Harness h;
    h.nvd_db = &db;
    h.wire();

    auto r = h.sink.Post("/api/nvd/match",
                         R"({"inventory":[{"name":"widget","version":"1.0.0"}]})");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["count"] == 1);
    REQUIRE(j["findings"].size() == 1);
    auto& f = j["findings"][0];
    CHECK(f["cve_id"] == "CVE-2024-0003");
    CHECK(f["severity"] == "CRITICAL");
    CHECK(f["product"] == "widget");
    CHECK(f["installed_version"] == "1.0.0");
    CHECK(f["source"] == "nvd");
}

TEST_CASE("nvd_routes: /api/nvd/match reports zero findings for a non-vulnerable item",
          "[server][routes][nvd_routes]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0004", "widget", "2.0.0"));

    Harness h;
    h.nvd_db = &db;
    h.wire();

    // 3.0.0 is past the fixed (end-excluding) version — not vulnerable.
    auto r = h.sink.Post("/api/nvd/match",
                         R"({"inventory":[{"name":"widget","version":"3.0.0"}]})");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["count"] == 0);
    CHECK(j["findings"].empty());
}
