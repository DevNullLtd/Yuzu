/**
 * test_nvd.cpp — Unit tests for NVD database, version comparison, and JSON parsing
 *
 * Covers: compare_versions() (shared numeric comparator, unchanged),
 *         nvd_version_compare()/nvd_version_in_range() (NVD-grade),
 *         NvdDatabase CRUD + cpeMatch-range match_inventory(),
 *         NvdClient::parse_response().
 */

#include "nvd_client.hpp"
#include "nvd_db.hpp"
#include "nvd_version.hpp"
#include "nvd_sync.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <sqlite3.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {
// A CVE with a single product/version-end-excluding cpeMatch (the common case
// and the shape the builtin rules use).
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
} // namespace

// ── Shared numeric comparator (compare_versions) — unchanged, must stay green ──

TEST_CASE("compare_versions: equal versions", "[nvd][version]") {
    REQUIRE(compare_versions("1.0.0", "1.0.0") == 0);
}

TEST_CASE("compare_versions: numeric not lexicographic", "[nvd][version]") {
    REQUIRE(compare_versions("1.10.0", "1.9.0") > 0);
    REQUIRE(compare_versions("1.9.0", "1.10.0") < 0);
}

TEST_CASE("compare_versions: missing segments", "[nvd][version]") {
    REQUIRE(compare_versions("1.0", "1.0.0") == 0);
    REQUIRE(compare_versions("1", "1.0.0") == 0);
}

// ── NVD-grade comparator (nvd_version_compare) ───────────────────────────────

TEST_CASE("nvd_version_compare: basic ordering", "[nvd][version]") {
    REQUIRE(nvd_version_compare("1.0.0", "1.0.0") == 0);
    REQUIRE(nvd_version_compare("1.2.3", "1.2.4") < 0);
    REQUIRE(nvd_version_compare("2.0.0", "1.0.0") > 0);
    REQUIRE(nvd_version_compare("1.10.0", "1.9.0") > 0);
    REQUIRE(nvd_version_compare("124.0.6367.202", "124.0.6367.201") > 0);
}

TEST_CASE("nvd_version_compare: padding is equal", "[nvd][version]") {
    REQUIRE(nvd_version_compare("1.0", "1.0.0") == 0);
    REQUIRE(nvd_version_compare("1", "1.0.0") == 0);
    REQUIRE(nvd_version_compare("1.0.1", "1.0") > 0);
}

TEST_CASE("nvd_version_compare: pre-release ordering", "[nvd][version]") {
    REQUIRE(nvd_version_compare("1.0.0-alpha", "1.0.0-beta") < 0);
    REQUIRE(nvd_version_compare("1.0.0-beta", "1.0.0-rc1") < 0);
    REQUIRE(nvd_version_compare("1.0.0-rc1", "1.0.0") < 0);
    REQUIRE(nvd_version_compare("1.0.0-rc2", "1.0.0-rc1") > 0);
    REQUIRE(nvd_version_compare("1.0.0", "1.0.0-rc1") > 0);
}

TEST_CASE("nvd_version_compare: numeric outranks alpha at same position", "[nvd][version]") {
    // Vendor patch suffixes: a trailing non-prerelease alpha is HIGHER.
    REQUIRE(nvd_version_compare("9.8p1", "9.8") > 0);   // openssh
    REQUIRE(nvd_version_compare("1.0.2k", "1.0.2") > 0); // openssl letter releases
    REQUIRE(nvd_version_compare("1.9.5p2", "1.9.5p3") < 0);
}

TEST_CASE("nvd_version_compare: epoch stripped and ignored", "[nvd][version]") {
    REQUIRE(nvd_version_compare("1:1.0", "1.0") == 0);
    REQUIRE(nvd_version_compare("0:2.0", "2.0") == 0);
}

TEST_CASE("nvd_version_compare: empty strings", "[nvd][version]") {
    REQUIRE(nvd_version_compare("", "") == 0);
    REQUIRE(nvd_version_compare("1.0", "") > 0);
    REQUIRE(nvd_version_compare("", "1.0") < 0);
}

// ── Range predicate (nvd_version_in_range) ───────────────────────────────────
// VersionRange fields: {exact, start_including, start_excluding,
//                       end_including, end_excluding}

TEST_CASE("nvd_version_in_range: end excluding", "[nvd][range]") {
    VersionRange r{"", "", "", "", "3.0.7"};
    REQUIRE(nvd_version_in_range("3.0.6", r));
    REQUIRE_FALSE(nvd_version_in_range("3.0.7", r));
    REQUIRE_FALSE(nvd_version_in_range("3.1.0", r));
}

TEST_CASE("nvd_version_in_range: end including", "[nvd][range]") {
    VersionRange r{"", "", "", "3.0.7", ""};
    REQUIRE(nvd_version_in_range("3.0.7", r));
    REQUIRE_FALSE(nvd_version_in_range("3.0.8", r));
}

TEST_CASE("nvd_version_in_range: start+end band", "[nvd][range]") {
    VersionRange r{"", "2.0", "", "", "3.0"}; // [2.0, 3.0)
    REQUIRE(nvd_version_in_range("2.0", r));
    REQUIRE(nvd_version_in_range("2.5", r));
    REQUIRE_FALSE(nvd_version_in_range("1.9", r));
    REQUIRE_FALSE(nvd_version_in_range("3.0", r));
}

TEST_CASE("nvd_version_in_range: start excluding", "[nvd][range]") {
    VersionRange r{"", "", "2.0", "", ""}; // (2.0, )
    REQUIRE_FALSE(nvd_version_in_range("2.0", r));
    REQUIRE(nvd_version_in_range("2.1", r));
}

TEST_CASE("nvd_version_in_range: exact pin", "[nvd][range]") {
    VersionRange r{"1.2.3", "", "", "", ""};
    REQUIRE(nvd_version_in_range("1.2.3", r));
    REQUIRE_FALSE(nvd_version_in_range("1.2.4", r));
}

TEST_CASE("nvd_version_in_range: wildcard / no constraint means all versions", "[nvd][range]") {
    REQUIRE(nvd_version_in_range("9.9.9", VersionRange{"*", "", "", "", ""}));
    REQUIRE(nvd_version_in_range("9.9.9", VersionRange{"-", "", "", "", ""}));
    REQUIRE(nvd_version_in_range("9.9.9", VersionRange{"", "", "", "", ""}));
}

// ── NvdDatabase ──────────────────────────────────────────────────────────────

TEST_CASE("NvdDatabase: open in-memory", "[nvd][db]") {
    NvdDatabase db(":memory:");
    REQUIRE(db.is_open());
}

TEST_CASE("NvdDatabase: upsert and count", "[nvd][db]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));
    REQUIRE(db.total_cve_count() == 1);
}

TEST_CASE("NvdDatabase: upsert batch", "[nvd][db]") {
    NvdDatabase db(":memory:");
    std::vector<CveRecord> records;
    for (int i = 0; i < 5; ++i)
        records.push_back(make_cve("CVE-2024-000" + std::to_string(i), "test", "1.0"));
    REQUIRE(db.upsert_cves(records)); // returns true on a fully-persisted batch
    REQUIRE(db.total_cve_count() == 5);
}

TEST_CASE("NvdDatabase: upsert same ID replaces header, count stays 1", "[nvd][db]") {
    NvdDatabase db(":memory:");
    auto rec = make_cve("CVE-2024-0001", "test", "1.0", "LOW");
    db.upsert_cve(rec);
    rec.severity = "CRITICAL";
    db.upsert_cve(rec);
    REQUIRE(db.total_cve_count() == 1);
}

TEST_CASE("NvdDatabase: header-only CVE counted, never matches", "[nvd][db]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-5000";
    rec.severity = "HIGH";
    rec.description = "no cpe";
    rec.source = "nvd";
    db.upsert_cve(rec); // no matches
    REQUIRE(db.total_cve_count() == 1);
    REQUIRE(db.match_inventory({{"anything", "1.0"}}).empty());
}

TEST_CASE("NvdDatabase: metadata round-trip", "[nvd][db]") {
    NvdDatabase db(":memory:");
    db.set_meta("last_sync", "2024-01-01T00:00:00Z");
    REQUIRE(db.get_meta("last_sync") == "2024-01-01T00:00:00Z");
    REQUIRE(db.get_meta("nonexistent").empty());
}

TEST_CASE("NvdDatabase: seed_builtin_rules is idempotent", "[nvd][db]") {
    NvdDatabase db(":memory:");
    db.seed_builtin_rules();
    auto count1 = db.total_cve_count();
    db.seed_builtin_rules();
    auto count2 = db.total_cve_count();
    REQUIRE(count1 == count2);
    REQUIRE(count1 > 0);
}

// ── v1 -> v2 schema migration (real upgrade path) ────────────────────────────

TEST_CASE("NvdDatabase: v1 database with data upgrades to v2", "[nvd][db][migration]") {
    yuzu::test::TempDbFile tmp{std::string_view{"nvd-migration-"}};
    const std::string path = tmp.path.string();

    // 1. Hand-build a v1-schema database on disk: the OLD flat cve table with a
    //    real row, a sync cursor, and schema_meta pinned at version 1 — exactly
    //    what a persisted volume from before this change looks like.
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(path.c_str(), &raw) == SQLITE_OK);
        const char* v1 = R"(
            CREATE TABLE cve (
                cve_id TEXT PRIMARY KEY, product TEXT NOT NULL, vendor TEXT,
                affected_below TEXT NOT NULL, fixed_in TEXT, severity TEXT NOT NULL,
                description TEXT NOT NULL, published TEXT, last_modified TEXT,
                source TEXT DEFAULT 'nvd');
            CREATE INDEX idx_cve_product ON cve(product);
            CREATE TABLE sync_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE schema_meta (store TEXT PRIMARY KEY, version INTEGER NOT NULL,
                                      upgraded_at TEXT);
            INSERT INTO cve (cve_id, product, vendor, affected_below, fixed_in, severity, description)
                VALUES ('CVE-2014-0160','openssl','openssl','1.0.1g','1.0.1g','CRITICAL','Heartbleed');
            INSERT INTO sync_meta (key, value) VALUES ('last_sync_time','2024-01-01T00:00:00Z');
            INSERT INTO schema_meta (store, version, upgraded_at)
                VALUES ('nvd_database', 1, '2024-01-01T00:00:00Z');
        )";
        char* err = nullptr;
        REQUIRE(sqlite3_exec(raw, v1, nullptr, nullptr, &err) == SQLITE_OK);
        sqlite3_free(err);
        sqlite3_close(raw);
    }

    // 2. Opening through NvdDatabase runs the v2 migration.
    NvdDatabase db(path);
    REQUIRE(db.is_open());

    // 3. The old flat rows are dropped (reconstructable from the next sync). The
    //    header table is empty and the old product no longer matches — proving
    //    the migration ran, not that it silently kept the v1 table.
    REQUIRE(db.total_cve_count() == 0);
    REQUIRE(db.match_inventory({{"openssl", "1.0.1f"}}).empty()); // would have matched under v1

    // 4. The sync cursor must NOT survive: v2 dropped the catalog, so a preserved
    //    last_sync_time would make the next sync incremental and the dropped rows
    //    would never be re-fetched (silently gone from /api/nvd/match forever). An
    //    empty cursor routes do_sync() to the full initial sync the upgrade docs
    //    promise ("fully reconstructable / self-healing").
    REQUIRE(db.get_meta("last_sync_time").empty());

    // 5. The reshaped schema is fully functional post-upgrade.
    db.upsert_cve(make_cve("CVE-2024-0001", "nginx", "1.25.0"));
    REQUIRE(db.total_cve_count() == 1);
    REQUIRE(db.match_inventory({{"nginx", "1.24.0"}}).size() == 1);
}

// ── Inventory Matching ───────────────────────────────────────────────────────

TEST_CASE("NvdDatabase: match_inventory finds vulnerable version", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));

    auto matches = db.match_inventory({{"openssl", "3.0.6"}});
    REQUIRE(matches.size() == 1);
    REQUIRE(matches[0].cve_id == "CVE-2024-0001");
    REQUIRE(matches[0].installed_version == "3.0.6");
    REQUIRE(matches[0].fixed_in == "3.0.7");
}

TEST_CASE("NvdDatabase: match_inventory skips fixed version", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));
    REQUIRE(db.match_inventory({{"openssl", "3.0.7"}}).empty());
}

TEST_CASE("NvdDatabase: match_inventory empty inventory", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "test", "1.0"));
    REQUIRE(db.match_inventory({}).empty());
}

TEST_CASE("NvdDatabase: match_inventory case-insensitive product", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));
    REQUIRE(db.match_inventory({{"OpenSSL", "3.0.6"}}).size() == 1);
}

TEST_CASE("NvdDatabase: match_inventory honours a version band", "[nvd][match]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-0007";
    rec.severity = "HIGH";
    rec.description = "band";
    rec.source = "nvd";
    CpeMatch cm;
    cm.cpe_product = "nginx";
    cm.version_start_including = "1.20.0";
    cm.version_end_excluding = "1.24.0";
    rec.matches.push_back(cm);
    db.upsert_cve(rec);

    REQUIRE(db.match_inventory({{"nginx", "1.22.0"}}).size() == 1);
    REQUIRE(db.match_inventory({{"nginx", "1.19.0"}}).empty()); // below start
    REQUIRE(db.match_inventory({{"nginx", "1.24.0"}}).empty()); // at exclusive end
}

TEST_CASE("NvdDatabase: multi-product CVE preserved (row-loss regression)", "[nvd][match]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-9999";
    rec.severity = "HIGH";
    rec.description = "multi-product";
    rec.source = "nvd";
    rec.matches.push_back(CpeMatch{.cpe_product = "producta", .version_end_excluding = "1.0"});
    rec.matches.push_back(CpeMatch{.cpe_product = "productb", .version_end_excluding = "2.0"});
    db.upsert_cve(rec);

    // Both products are independently matchable — the old INSERT OR REPLACE bug
    // kept only the last row and would fail one of these.
    REQUIRE(db.match_inventory({{"producta", "0.9"}}).size() == 1);
    REQUIRE(db.match_inventory({{"productb", "1.5"}}).size() == 1);
    REQUIRE(db.match_inventory({{"productb", "2.0"}}).empty());
    REQUIRE(db.total_cve_count() == 1);
}

TEST_CASE("NvdDatabase: re-upsert replaces the match set", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));
    REQUIRE(db.match_inventory({{"openssl", "3.0.6"}}).size() == 1);

    // Re-sync the same CVE with a different product; the old openssl row must go.
    db.upsert_cve(make_cve("CVE-2024-0001", "nginx", "1.25.0"));
    REQUIRE(db.match_inventory({{"openssl", "3.0.6"}}).empty());
    REQUIRE(db.match_inventory({{"nginx", "1.24.0"}}).size() == 1);
    REQUIRE(db.total_cve_count() == 1);
}

// ── NVD JSON Parsing ─────────────────────────────────────────────────────────

TEST_CASE("parse_response: keeps cpeMatch range fields", "[nvd][parse]") {
    NvdClient client;
    std::string json = R"({
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0001",
                "descriptions": [{"lang": "en", "value": "Test vuln"}],
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-02T00:00:00.000",
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [{
                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "1.0.0",
                            "versionEndExcluding": "1.2.3"
                        }]
                    }]
                }]
            }
        }]
    })";

    auto result = client.parse_response(json);
    REQUIRE(result.total_results == 1);
    REQUIRE(result.records.size() == 1);
    REQUIRE(result.records[0].cve_id == "CVE-2024-0001");
    REQUIRE(result.records[0].description == "Test vuln");
    REQUIRE(result.records[0].source == "nvd");
    REQUIRE(result.records[0].matches.size() == 1);
    REQUIRE(result.records[0].matches[0].cpe_vendor == "vendor");
    REQUIRE(result.records[0].matches[0].cpe_product == "product");
    REQUIRE(result.records[0].matches[0].version_start_including == "1.0.0");
    REQUIRE(result.records[0].matches[0].version_end_excluding == "1.2.3");
}

TEST_CASE("parse_response: CVSS v3.1 severity extraction", "[nvd][parse]") {
    NvdClient client;
    std::string json = R"({
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0002",
                "descriptions": [{"lang": "en", "value": "Critical vuln"}],
                "metrics": { "cvssMetricV31": [{ "cvssData": { "baseSeverity": "CRITICAL" } }] }
            }
        }]
    })";
    auto result = client.parse_response(json);
    REQUIRE(result.records.size() == 1);
    REQUIRE(result.records[0].severity == "CRITICAL");
}

TEST_CASE("parse_response: CVSS v2 fallback", "[nvd][parse]") {
    NvdClient client;
    std::string json = R"({
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0003",
                "descriptions": [{"lang": "en", "value": "Old vuln"}],
                "metrics": { "cvssMetricV2": [{ "baseSeverity": "HIGH" }] }
            }
        }]
    })";
    auto result = client.parse_response(json);
    REQUIRE(result.records.size() == 1);
    REQUIRE(result.records[0].severity == "HIGH");
}

TEST_CASE("parse_response: empty vulnerabilities array", "[nvd][parse]") {
    NvdClient client;
    auto result = client.parse_response(R"({"totalResults": 0, "vulnerabilities": []})");
    REQUIRE(result.total_results == 0);
    REQUIRE(result.records.empty());
}

TEST_CASE("parse_response: malformed JSON", "[nvd][parse]") {
    NvdClient client;
    auto result = client.parse_response("this is not json");
    REQUIRE(result.records.empty());
    REQUIRE(result.total_results == 0);
}

TEST_CASE("parse_response: tracks latest lastModified", "[nvd][parse]") {
    NvdClient client;
    std::string json = R"({
        "totalResults": 2,
        "vulnerabilities": [
            {"cve": {"id": "CVE-2024-0001", "lastModified": "2024-01-01T00:00:00.000"}},
            {"cve": {"id": "CVE-2024-0002", "lastModified": "2024-06-15T12:00:00.000"}}
        ]
    })";
    auto result = client.parse_response(json);
    REQUIRE(result.last_modified_timestamp == "2024-06-15T12:00:00.000");
}

TEST_CASE("parse_response: multiple cpeMatch produce one record with many matches",
          "[nvd][parse]") {
    NvdClient client;
    std::string json = R"({
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0004",
                "descriptions": [{"lang": "en", "value": "Multi-product"}],
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [
                            {"criteria": "cpe:2.3:a:vendorA:productA:*:*:*:*:*:*:*:*", "versionEndExcluding": "1.0"},
                            {"criteria": "cpe:2.3:a:vendorB:productB:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0"}
                        ]
                    }]
                }]
            }
        }]
    })";

    auto result = client.parse_response(json);
    REQUIRE(result.records.size() == 1);
    REQUIRE(result.records[0].matches.size() == 2);
    REQUIRE(result.records[0].matches[0].cpe_product == "producta");
    REQUIRE(result.records[0].matches[1].cpe_product == "productb");
}

// ── Governance hardening round (c1735cd3 review) ─────────────────────────────

TEST_CASE("nvd_version_compare: attached letter-release is a patch, not pre-release",
          "[nvd][version]") {
    // Regression for cpp-expert S1: OpenSSL-style "1.0.2a" is a patch ABOVE
    // "1.0.2"; ranking single-letter a/b as pre-release flipped this and would
    // flip vulnerable<->fixed against a version bound.
    REQUIRE(nvd_version_compare("1.0.2a", "1.0.2") > 0);
    REQUIRE(nvd_version_compare("1.0.2b", "1.0.2a") > 0);
    REQUIRE(nvd_version_compare("1.0.2a", "1.0.2b") < 0);
    // Multi-letter pre-release words still rank as pre-release.
    REQUIRE(nvd_version_compare("1.0.0-dev", "1.0.0-alpha") < 0);
    REQUIRE(nvd_version_compare("1.0.0-pre", "1.0.0-rc") < 0);
    REQUIRE(nvd_version_compare("1.0.0-preview", "1.0.0") < 0);
}

TEST_CASE("nvd_version_compare: overflow-safe on huge numeric segments", "[nvd][version]") {
    // Digit runs far beyond a 64-bit integer must still order correctly (the
    // reason numeric_compare is string-length based, not stoll).
    REQUIRE(nvd_version_compare("99999999999999999999", "100000000000000000000") < 0);
    REQUIRE(nvd_version_compare("100000000000000000000", "99999999999999999999") > 0);
    REQUIRE(nvd_version_compare("007", "7") == 0); // leading zeros
}

TEST_CASE("nvd_version_in_range: bounds take precedence over exact when both set",
          "[nvd][range]") {
    // exact pinned to 1.2.3 but an end_excluding bound also present → bounds win.
    VersionRange r{"1.2.3", "", "", "", "9.9"};
    REQUIRE(nvd_version_in_range("1.2.4", r)); // in [,9.9) → vulnerable via bound
    REQUIRE_FALSE(nvd_version_in_range("9.9", r));
}

TEST_CASE("nvd_version_in_range: open-ended and both-inclusive bounds", "[nvd][range]") {
    REQUIRE(nvd_version_in_range("9.9", VersionRange{"", "2.0", "", "", ""}));      // [2.0, )
    REQUIRE_FALSE(nvd_version_in_range("1.0", VersionRange{"", "2.0", "", "", ""})); // below start
    VersionRange band{"", "1.0", "", "2.0", ""};                                    // [1.0, 2.0]
    REQUIRE(nvd_version_in_range("1.0", band));
    REQUIRE(nvd_version_in_range("2.0", band));
    REQUIRE_FALSE(nvd_version_in_range("2.1", band));
}

TEST_CASE("NvdDatabase: is_vulnerable=false rows are excluded from matches", "[nvd][match]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-8000";
    rec.severity = "HIGH";
    rec.description = "running-on platform node";
    rec.source = "nvd";
    rec.matches.push_back(
        CpeMatch{.cpe_product = "linux_kernel", .version_end_excluding = "9.9", .is_vulnerable = false});
    db.upsert_cve(rec);
    REQUIRE(db.match_inventory({{"linux_kernel", "1.0"}}).empty());
}

TEST_CASE("NvdDatabase: match_inventory skips empty name/version", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));
    // Empty fields are skipped; a valid item in the same batch still matches.
    auto m = db.match_inventory({{"", "1.0"}, {"openssl", ""}, {"openssl", "3.0.6"}});
    REQUIRE(m.size() == 1);
    REQUIRE(m[0].cve_id == "CVE-2024-0001");
}

TEST_CASE("NvdDatabase: LIKE metacharacters in name do not broaden the match", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));
    // '%' must be treated literally (escaped), not as a wildcard that matches
    // "openssl". A literal "a%b" product is not in the DB → no match.
    REQUIRE(db.match_inventory({{"a%b", "1.0"}}).empty());
    REQUIRE(db.match_inventory({{"%", "1.0"}}).empty());
}

TEST_CASE("NvdDatabase: v2 migration is idempotent across reopen", "[nvd][db][migration]") {
    yuzu::test::TempDbFile tmp{std::string_view{"nvd-remigrate-"}};
    const std::string path = tmp.path.string();
    {
        NvdDatabase db(path);
        db.upsert_cve(make_cve("CVE-2024-0001", "nginx", "1.25.0"));
        REQUIRE(db.total_cve_count() == 1);
    }
    // Reopen: schema_meta already at v2, so migration 2 must NOT re-run / wipe.
    NvdDatabase db2(path);
    REQUIRE(db2.total_cve_count() == 1);
    REQUIRE(db2.match_inventory({{"nginx", "1.24.0"}}).size() == 1);
}

TEST_CASE("NvdDatabase: a failed upsert rolls back atomically (no partial state)",
          "[nvd][match]") {
    yuzu::test::TempDbFile tmp{std::string_view{"nvd-atomic-"}};
    const std::string path = tmp.path.string();

    NvdDatabase db(path);
    db.upsert_cve(make_cve("CVE-A", "openssl", "3.0.7"));
    REQUIRE(db.total_cve_count() == 1);

    // Force a mid-upsert failure by dropping cve_match out from under the store
    // via a second connection: the header INSERT succeeds, the cve_match DELETE
    // then fails to prepare → the whole CVE must ROLLBACK TO the savepoint, so
    // the new header must NOT survive (UP-1: no partial commit).
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(path.c_str(), &raw) == SQLITE_OK);
        REQUIRE(sqlite3_exec(raw, "DROP TABLE cve_match;", nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    db.upsert_cve(make_cve("CVE-B", "nginx", "1.25.0")); // must roll back
    REQUIRE(db.total_cve_count() == 1); // CVE-B header did not survive the rollback
}

// ── Rate-limit wait (regression for the #1867 first-request overflow) ─────────

TEST_CASE("nvd_rate_limit_wait: first request never waits (overflow regression)",
          "[nvd][ratelimit]") {
    using namespace std::chrono;
    const auto now = steady_clock::now();
    const auto interval = milliseconds(6000);
    // No prior request (nullopt) — the old time_point::min() sentinel overflowed
    // here and slept ~292 years; must be zero.
    REQUIRE(nvd_rate_limit_wait(std::nullopt, now, interval) == steady_clock::duration::zero());
}

TEST_CASE("nvd_rate_limit_wait: throttles within the interval, not after", "[nvd][ratelimit]") {
    using namespace std::chrono;
    const auto now = steady_clock::now();
    const auto interval = milliseconds(6000);

    // A request 1s ago → wait exactly the remaining 5s (pure function, deterministic).
    const auto w = nvd_rate_limit_wait(now - milliseconds(1000), now, interval);
    REQUIRE(duration_cast<milliseconds>(w).count() == 5000);

    // A request well outside the interval → no wait.
    REQUIRE(nvd_rate_limit_wait(now - seconds(30), now, interval) == steady_clock::duration::zero());
    // Exactly at the interval boundary → no wait.
    REQUIRE(nvd_rate_limit_wait(now - milliseconds(6000), now, interval) ==
            steady_clock::duration::zero());
}

TEST_CASE("nvd_rate_limit_wait: non-positive elapsed never waits (overflow-class guard)",
          "[nvd][ratelimit]") {
    using namespace std::chrono;
    const auto now = steady_clock::now();
    const auto interval = milliseconds(6000);
    // A `last` in the future (backwards/non-monotonic clock) must return zero, not
    // `interval - negative` — the defence against the ~292yr overflow class.
    REQUIRE(nvd_rate_limit_wait(now + milliseconds(10), now, interval) ==
            steady_clock::duration::zero());
    REQUIRE(nvd_rate_limit_wait(now + hours(1000000), now, interval) ==
            steady_clock::duration::zero());
    // elapsed == 0 (same instant) → no wait.
    REQUIRE(nvd_rate_limit_wait(now, now, interval) == steady_clock::duration::zero());
}

// ── PR2b: prefix-anchored matching (perf-P1) ─────────────────────────────────

TEST_CASE("NvdDatabase: match is prefix-anchored (product starts with name), not substring",
          "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-A", "libopenssl", "3.0.7")); // product embeds 'openssl'

    // Under the old LIKE '%name%', inventory 'openssl' matched 'libopenssl'. Now
    // matching is prefix-anchored (index-usable), so the product must START WITH
    // the inventory name — 'openssl' no longer matches 'libopenssl'.
    REQUIRE(db.match_inventory({{"openssl", "3.0.6"}}).empty());
    // A genuine prefix still matches.
    REQUIRE(db.match_inventory({{"libopenssl", "3.0.6"}}).size() == 1);
    REQUIRE(db.match_inventory({{"lib", "3.0.6"}}).size() == 1); // 'lib' is a prefix
    // Escaped metacharacters still can't broaden the prefix.
    db.upsert_cve(make_cve("CVE-B", "openssl", "3.0.7"));
    REQUIRE(db.match_inventory({{"open_sl", "3.0.6"}}).empty()); // '_' is literal, not a wildcard
}

// ── PR2b: 120-day window splitter (pure) ─────────────────────────────────────

TEST_CASE("nvd_split_windows: partitions [start,end] into <=max windows, oldest-first",
          "[nvd][window]") {
    using namespace std::chrono;
    const auto base = system_clock::time_point{};
    const auto max = hours(24 * 120);

    // 300 days / 120 → 3 contiguous windows covering the whole span.
    auto w = nvd_split_windows(base, base + hours(24 * 300), max);
    REQUIRE(w.size() == 3);
    REQUIRE(w.front().first == base);
    REQUIRE(w.back().second == base + hours(24 * 300));
    REQUIRE(w[0].second == w[1].first); // contiguous
    REQUIRE(w[1].second == w[2].first);
    for (const auto& [s, e] : w)
        REQUIRE(e - s <= max);

    // Exactly one window at/under the cap.
    REQUIRE(nvd_split_windows(base, base + max, max).size() == 1);
    REQUIRE(nvd_split_windows(base, base + hours(24 * 10), max).size() == 1);

    // Degenerate inputs → empty.
    REQUIRE(nvd_split_windows(base + hours(1), base, max).empty()); // inverted
    REQUIRE(nvd_split_windows(base, base, max).empty());            // zero span
    REQUIRE(nvd_split_windows(base, base + max, hours(0)).empty()); // zero window
}

// ── PR2b: backfill / freshness state machine (mock fetcher) ──────────────────

namespace {
struct MockFetcher : INvdFetcher {
    std::vector<std::pair<std::string, std::string>> published_calls;
    std::vector<std::pair<std::string, std::string>> modified_calls;
    bool fail = false;
    bool empty_ok = false; // fetch succeeds (ok=true) but returns zero records (NVD outage shape)
    // Per-call override: given the 1-based published-window call index, return true for a
    // data window or false for an ok+empty window. Lets a test script "data then empty".
    std::function<bool(std::size_t)> data_predicate;
    NvdFailureReason fail_reason = NvdFailureReason::kConnection; // returned when fail==true

    static CveRecord one_cve(std::size_t n) {
        CveRecord rec;
        rec.cve_id = "CVE-MOCK-" + std::to_string(n);
        rec.severity = "HIGH";
        rec.description = "mock";
        rec.source = "nvd";
        CpeMatch cm;
        cm.cpe_product = "product" + std::to_string(n);
        cm.version_end_excluding = "9.9";
        rec.matches.push_back(cm);
        return rec;
    }
    NvdFetchResult make(std::size_t n) {
        NvdFetchResult r;
        if (fail) {
            r.ok = false;
            r.reason = fail_reason;
            return r;
        }
        r.ok = true;
        bool give_data = !empty_ok;
        if (give_data && data_predicate)
            give_data = data_predicate(n);
        if (give_data)
            r.records.push_back(one_cve(n));
        return r;
    }
    NvdFetchResult fetch_by_published_window(const std::string& s, const std::string& e) override {
        published_calls.emplace_back(s, e);
        return make(published_calls.size());
    }
    NvdFetchResult fetch_modified_between(const std::string& s, const std::string& e) override {
        modified_calls.emplace_back(s, e);
        NvdFetchResult r;
        if (fail) {
            r.ok = false;
            r.reason = fail_reason;
        }
        return r;
    }
};

long long secs_ago(int days) {
    const auto tp = std::chrono::system_clock::now() - std::chrono::days(days);
    return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
}
} // namespace

TEST_CASE("NvdSyncManager: backfill walks newest-first, contiguous, to the floor", "[nvd][backfill]") {
    auto db = std::make_shared<NvdDatabase>(":memory:");
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/1);

    mgr.sync_now(); // runs the whole backfill synchronously

    // ~1 year / 120 days → 3 full windows + a remainder = 4.
    REQUIRE(m->published_calls.size() >= 3);
    REQUIRE(m->published_calls.size() <= 4);
    // Newest-first: the first window ends later (lexicographically greater ISO) than the last.
    REQUIRE(m->published_calls.front().second > m->published_calls.back().second);
    // Contiguous: window[i].start == window[i+1].end (walking backward).
    for (std::size_t i = 0; i + 1 < m->published_calls.size(); ++i)
        REQUIRE(m->published_calls[i].first == m->published_calls[i + 1].second);
    // Completed + upserted; no freshness yet. Completion is derived (cursor vs floor).
    REQUIRE(mgr.status().backfill_complete);
    REQUIRE(db->total_cve_count() == m->published_calls.size());
    REQUIRE(m->modified_calls.empty());

    // Once complete, the next sync does freshness, not backfill.
    const auto before = m->published_calls.size();
    mgr.sync_now();
    REQUIRE(m->published_calls.size() == before); // no more backfill windows (freshness path)
}

TEST_CASE("NvdSyncManager: a failed backfill window leaves the cursor and doesn't complete",
          "[nvd][backfill]") {
    auto db = std::make_shared<NvdDatabase>(":memory:");
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    m->fail = true;
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, 1);

    mgr.sync_now();

    REQUIRE(m->published_calls.size() == 1);              // stopped after the first failure
    REQUIRE_FALSE(mgr.status().backfill_complete);        // not complete (no cursor to reach floor)
    REQUIRE(db->get_meta("backfill_oldest_published").empty()); // cursor never advanced (#1875)
}

TEST_CASE("NvdSyncManager: freshness splits a >120-day gap into windows", "[nvd][freshness]") {
    auto db = std::make_shared<NvdDatabase>(":memory:");
    // Completion is derived from the cursor vs the floor AND a non-empty catalog: a
    // cursor older than the 8-year floor (~9y ago) plus stored CVEs → complete.
    db->set_meta("backfill_oldest_published", std::to_string(secs_ago(365 * 9)));
    db->set_meta("last_freshness_check", std::to_string(secs_ago(300)));
    REQUIRE(db->upsert_cves({MockFetcher::one_cve(1)})); // content guard: complete requires CVEs
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, 8);

    mgr.sync_now();

    REQUIRE(m->published_calls.empty());       // backfill already complete → freshness path
    REQUIRE(m->modified_calls.size() == 3);    // 300 days / 120 → 3 windows
}

// ── PR2b governance Gate 7 — cursor integrity + parse-failure + index plan ───

TEST_CASE("NvdSyncManager: a corrupt/absurd cursor does NOT false-complete the backfill",
          "[nvd][backfill]") {
    // #1889 / UP-3: parse_cursor rejects a pre-catalog cursor (below NVD's fixed
    // 1999-01-01 start), so the backfill restarts from `now` and actually builds —
    // never jumps to ~1970 and false-completes with an empty store. These three are
    // all pre-1999 garbage. (A post-1999 value below the *configured* floor is NOT
    // garbage — it's a legitimately-deeper cursor — so it's tested separately as a
    // resume/complete case, not here.)
    for (const char* bad : {"-5" /* 1969 */, "0" /* 1970 */, "500000000" /* 1985 */}) {
        auto db = std::make_shared<NvdDatabase>(":memory:");
        db->set_meta("backfill_oldest_published", bad);
        auto mock = std::make_unique<MockFetcher>();
        auto* m = mock.get();
        NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, 1);
        mgr.sync_now();
        INFO("bad cursor = " << bad);
        REQUIRE(m->published_calls.size() >= 3);  // it walked from now, not false-completed
        REQUIRE(mgr.status().backfill_complete);   // legitimately reached the floor
        REQUIRE(db->total_cve_count() == m->published_calls.size());
    }
}

TEST_CASE("NvdSyncManager: a future cursor is clamped to now (no livelock)", "[nvd][backfill]") {
    // UP-4: a clock-skew future cursor must be clamped to `now`, else backfill asks
    // NVD for a future window forever. First window must end at ~now, not the future.
    const auto future =
        std::chrono::duration_cast<std::chrono::seconds>(
            (std::chrono::system_clock::now() + std::chrono::days(400)).time_since_epoch())
            .count();
    auto db = std::make_shared<NvdDatabase>(":memory:");
    db->set_meta("backfill_oldest_published", std::to_string(future));
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, 1);
    mgr.sync_now();
    REQUIRE(m->published_calls.size() >= 3);
    REQUIRE(mgr.status().backfill_complete);
    // Newest window's end (first call) is ~now, well before the +400d future.
    const auto now_iso_year = std::to_string(1900); // sanity: string compare below
    (void)now_iso_year;
    REQUIRE(m->published_calls.front().second < std::to_string(2100)); // not a year-2100+ future
}

TEST_CASE("NvdSyncManager: full-history (backfill_years=0) resumes from a valid in-catalog cursor",
          "[nvd][backfill]") {
    // #1889: a persisted cursor within the catalog (>= NVD's 1999 start) must RESUME,
    // not restart. Full-history floor is the fixed 1999 start; seed a 2005 cursor and
    // the next fetch window must resume near 2005, not jump back to `now`.
    using namespace std::chrono;
    const auto cursor_2005 =
        duration_cast<seconds>(sys_days{2005y / June / 1}.time_since_epoch()).count();
    auto db = std::make_shared<NvdDatabase>(":memory:");
    db->set_meta("backfill_oldest_published", std::to_string(cursor_2005));
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    m->fail = true; // stop after the first window so we can inspect the resume point
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/0);
    mgr.sync_now();
    REQUIRE(m->published_calls.size() == 1); // resumed and attempted exactly one window
    // Window END = the resumed cursor (~2005), NOT a restart from ~now.
    REQUIRE(m->published_calls.front().second.substr(0, 4) == "2005");
    // Fetch failed → cursor held unchanged (no false advance), proving pure resume.
    REQUIRE(db->get_meta("backfill_oldest_published") == std::to_string(cursor_2005));
}

TEST_CASE("NvdSyncManager: full-history REJECTS a pre-catalog garbage cursor (no false-complete)",
          "[nvd][backfill]") {
    // #1889 review r2 (Blocker 1): the full-history floor is anchored at NVD's fixed
    // 1999 catalog start, NOT now-100y (~1926, a negative epoch). So a garbage sub-1999
    // cursor like "-5" (→1969) must be REJECTED and the backfill restarted from `now` —
    // never walk 1969→1926 and mark itself complete, silently skipping 1969→present.
    auto db = std::make_shared<NvdDatabase>(":memory:");
    db->set_meta("backfill_oldest_published", "-5"); // parses to 1969: pre-catalog garbage
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    m->fail = true; // inspect the first (restarted) window, then stop
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/0);
    mgr.sync_now();
    REQUIRE(m->published_calls.size() == 1);
    // Restarted from ~now (recent year), NOT resumed at the garbage 1969 point.
    REQUIRE(m->published_calls.front().second.substr(0, 4) >= "2020");
    REQUIRE_FALSE(mgr.status().backfill_complete); // fetch failed → not falsely completed
}

TEST_CASE("NvdSyncManager: deepening backfill_years reopens a completed shallow backfill",
          "[nvd][backfill]") {
    // #1889 review r2 (Blocker 2): completion is derived from the stored cursor vs the
    // CURRENT floor, not a sticky flag. An 8-year backfill that completed, then restarts
    // as full-history (years=0), must RESUME fetching the older range — not run freshness
    // forever while reporting the catalog complete.
    using namespace std::chrono;
    const auto cursor_8y_ago =
        duration_cast<seconds>((system_clock::now() - years(8)).time_since_epoch()).count();
    auto db = std::make_shared<NvdDatabase>(":memory:");
    db->set_meta("backfill_oldest_published", std::to_string(cursor_8y_ago)); // shallow-complete
    db->set_meta("last_freshness_check", std::to_string(secs_ago(1)));         // freshness would be a no-op
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    m->fail = true; // one window is enough to prove backfill (not freshness) ran
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/0);
    mgr.sync_now();
    REQUIRE_FALSE(m->published_calls.empty()); // BACKFILL ran (older range reopened)...
    REQUIRE(m->modified_calls.empty());        // ...not the freshness-only path (the defect)
}

TEST_CASE("NvdSyncManager: an absurd backfill_years clamps the floor (no overflow/false-complete)",
          "[nvd][backfill]") {
    // Defensive: --nvd-backfill-years is unbounded at config parse; a huge value must
    // not overflow the years->clock subtraction into a garbage (far-future) floor that
    // would false-complete. The floor clamps to NVD's 1999 start, so a 2005 cursor is
    // still ABOVE the floor and resumes (not complete) rather than false-completing.
    using namespace std::chrono;
    const auto cursor_2005 =
        duration_cast<seconds>(sys_days{2005y / June / 1}.time_since_epoch()).count();
    auto db = std::make_shared<NvdDatabase>(":memory:");
    db->set_meta("backfill_oldest_published", std::to_string(cursor_2005));
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    m->fail = true;
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/100000);
    mgr.sync_now();
    REQUIRE_FALSE(mgr.status().backfill_complete);   // floor≈1999 < 2005 cursor → not complete
    REQUIRE(m->published_calls.size() == 1);          // resumed a real window (no false-complete)
    REQUIRE(m->published_calls.front().second.substr(0, 4) == "2005"); // resumed at the cursor
}

TEST_CASE("NvdSyncManager: a completed bounded backfill stays complete + displayed across drift",
          "[nvd][backfill]") {
    // #1889 review r2/S1: completion is derived from cursor <= current floor, and the
    // cursor display uses the fixed 1999 bound. A completed 8-year backfill whose cursor
    // sits below today's (wall-clock-drifted) floor must STILL report complete AND
    // display its cursor — never flip to "incomplete" (a re-backfill storm) or blank it.
    using namespace std::chrono;
    const auto cursor_9y_ago =
        duration_cast<seconds>((system_clock::now() - years(9)).time_since_epoch()).count();
    auto db = std::make_shared<NvdDatabase>(":memory:");
    db->set_meta("backfill_oldest_published", std::to_string(cursor_9y_ago));
    REQUIRE(db->upsert_cves({MockFetcher::one_cve(1)})); // content guard: complete requires CVEs
    auto mock = std::make_unique<MockFetcher>();
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/8);
    const auto st = mgr.status();
    REQUIRE(st.backfill_complete);                        // cursor (~9y) <= floor (~8y) + CVEs → complete
    REQUIRE_FALSE(st.backfill_oldest_published.empty());  // >= 1999 → displayed, not blanked
}

TEST_CASE("NvdSyncManager: an at-floor cursor with an EMPTY catalog is NOT complete (content guard)",
          "[nvd][backfill]") {
    // Governance Gate 4 UP-1/UP-2: completion must reflect stored CONTENT, not just
    // cursor position. A corrupt/at-floor cursor with zero CVEs — from a writable/corrupt
    // nvd.db, or an NVD outage returning empty windows — must NOT report the mirror
    // complete, or a vuln scan silently returns clean (false-negative). The content guard
    // keeps it "incomplete" so the backfill re-runs.
    auto db = std::make_shared<NvdDatabase>(":memory:");
    db->set_meta("backfill_oldest_published", std::to_string(secs_ago(365 * 9))); // below 8y floor
    auto mock = std::make_unique<MockFetcher>();
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/8);
    REQUIRE_FALSE(mgr.status().backfill_complete);        // empty catalog → not complete
    REQUIRE(db->upsert_cves({MockFetcher::one_cve(1)}));  // add content...
    REQUIRE(mgr.status().backfill_complete);              // ...now genuinely complete
}

TEST_CASE("NvdSyncManager: an emptied catalog with a stuck at-floor cursor re-fetches (recovery)",
          "[nvd][backfill]") {
    // Governance Gate 6 SRE: if the catalog is emptied out-of-band (corruption / manual
    // truncate / disk loss) while backfill_oldest_published is still pinned at the floor,
    // the walk would be a no-op and the mirror would sit incomplete forever. do_backfill
    // must detect empty+at-floor and reset the cursor to `now` to actually re-fetch.
    auto db = std::make_shared<NvdDatabase>(":memory:");
    db->set_meta("backfill_oldest_published", std::to_string(secs_ago(365 * 9))); // at/below 8y floor
    // catalog is EMPTY — no upsert
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/8);
    mgr.sync_now();
    REQUIRE_FALSE(m->published_calls.empty()); // it re-fetched instead of sitting idle
    REQUIRE(db->nvd_cve_count() > 0);           // real NVD catalog repopulated
    REQUIRE(mgr.status().backfill_complete);    // and is now genuinely complete
}

TEST_CASE("NvdSyncManager: built-in fallback rows do NOT satisfy the completion content guard",
          "[nvd][backfill]") {
    // #1889 review r4 Blocker 2: seed_builtin_rules() adds source='builtin' rows before
    // the first sync. total_cve_count() counts them, so an empty-NVD mirror with a cursor
    // at the floor would falsely report complete and skip straight to freshness. The guard
    // uses nvd_cve_count() (source='nvd'), so builtins alone never mark a mirror complete.
    auto db = std::make_shared<NvdDatabase>(":memory:");
    db->seed_builtin_rules();          // source='builtin' rows, zero real NVD data
    REQUIRE(db->total_cve_count() > 0); // builtins present...
    REQUIRE(db->nvd_cve_count() == 0);  // ...but zero NVD rows
    db->set_meta("backfill_oldest_published", std::to_string(secs_ago(365 * 9))); // at/below 8y floor
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    m->fail = true; // we only need the completeness verdict + proof it attempts a real fetch
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/8);
    REQUIRE_FALSE(mgr.status().backfill_complete); // builtins don't satisfy the guard
    mgr.sync_now();
    REQUIRE_FALSE(m->published_calls.empty());     // reached do_backfill (a real fetch), not freshness
    REQUIRE(m->modified_calls.empty());            // definitely not the freshness path
}

TEST_CASE("NvdSyncManager: empty-catalog recovery is bounded (no infinite re-walk)",
          "[nvd][backfill]") {
    // #1889 review r4 minor: if NVD returns well-formed-but-EMPTY windows during an outage
    // (result.ok true, zero records), the empty-catalog recovery must not re-walk the full
    // range on every tick forever — it is capped at kMaxEmptyCatalogResets.
    auto db = std::make_shared<NvdDatabase>(":memory:");
    db->set_meta("backfill_oldest_published", std::to_string(secs_ago(365 * 9))); // at floor
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    m->empty_ok = true; // every fetch succeeds but returns zero records
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/8);
    for (int i = 0; i < 20; ++i)
        mgr.sync_now();
    // Bounded: ~25 windows per walk × 5 capped resets ≈ ≤125, far below an uncapped
    // 20 passes × ~25 = ~500. And an all-empty catalog never falsely completes.
    REQUIRE(m->published_calls.size() < 200);
    REQUIRE_FALSE(mgr.status().backfill_complete);
}

TEST_CASE("NvdSyncManager: capped empty-catalog recovery resumes when NVD data returns",
          "[nvd][backfill]") {
    // The cap must NOT require a server restart to recover (grill-with-docs self-review):
    // once capped, do_backfill probes the newest window each tick, and when NVD returns
    // data it clears the cap and rebuilds the catalog to completion.
    auto db = std::make_shared<NvdDatabase>(":memory:");
    db->set_meta("backfill_oldest_published", std::to_string(secs_ago(365 * 9)));
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    m->empty_ok = true; // NVD outage: ok but empty windows
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/8);
    for (int i = 0; i < 10; ++i)
        mgr.sync_now(); // drive past the cap
    REQUIRE_FALSE(mgr.status().backfill_complete);
    m->empty_ok = false; // NVD recovers — real data again
    for (int i = 0; i < 3; ++i)
        mgr.sync_now(); // probe detects data → full re-walk → complete
    REQUIRE(mgr.status().backfill_complete);
    REQUIRE(db->nvd_cve_count() > 0);
}

TEST_CASE("NvdSyncManager: a suspicious empty window after real data is HELD, not skipped",
          "[nvd][backfill]") {
    // #1889 review r5 (Blocker): once real NVD data has landed, an ok+empty older window is
    // suspicious (a stale cache/proxy serving an empty page for a populated range). The walk
    // must HOLD at the last data window rather than advance past the empty one and risk
    // reporting the mirror complete over a hole.
    auto db = std::make_shared<NvdDatabase>(":memory:");
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    m->data_predicate = [](std::size_t call) { return call == 1; }; // window 1 data, rest ok+empty
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/1);
    mgr.sync_now();
    REQUIRE(m->published_calls.size() == 2);       // window 1 (data) + window 2 (empty → held)
    REQUIRE(db->nvd_cve_count() == 1);             // window 1's CVE persisted
    REQUIRE_FALSE(mgr.status().backfill_complete); // held at window 1; not complete over the hole
}

TEST_CASE("NvdSyncManager: a stably-empty window is accepted after re-confirmation (no wedge)",
          "[nvd][backfill]") {
    // The hold must not wedge on a GENUINELY-empty window (e.g. near the 1999 floor before
    // NVD's earliest published CVE): after kSuspiciousEmptyConfirmations checks it accepts the
    // empty and advances, so the backfill still reaches the floor and completes.
    auto db = std::make_shared<NvdDatabase>(":memory:");
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    m->data_predicate = [](std::size_t call) { return call == 1; }; // only window 1 ever has data
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/1);
    for (int i = 0; i < 12; ++i)
        mgr.sync_now(); // each empty window is re-confirmed then accepted
    REQUIRE(mgr.status().backfill_complete); // reached the floor — never wedged
    REQUIRE(db->nvd_cve_count() == 1);       // window 1 had data; the rest were genuinely empty
}

TEST_CASE("NvdSyncManager: a transient empty window recovers on retry — the hole is filled",
          "[nvd][backfill]") {
    // A window that returns ok+empty transiently (stale cache) then real data on retry must
    // NOT be skipped — the hold re-fetches it and fills the hole.
    auto db = std::make_shared<NvdDatabase>(":memory:");
    auto mock = std::make_unique<MockFetcher>();
    auto* m = mock.get();
    // Window 2's FIRST fetch (call 2) is empty; every other call — including its retry — has data.
    m->data_predicate = [](std::size_t call) { return call != 2; };
    NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, /*backfill_years=*/1);
    for (int i = 0; i < 6; ++i)
        mgr.sync_now();
    REQUIRE(mgr.status().backfill_complete);
    REQUIRE(db->nvd_cve_count() >= 2); // window 2's data was recovered on retry, not skipped
}

TEST_CASE("NvdClient::parse_response: totalResults>0 with empty vulnerabilities is a failure",
          "[nvd][parse]") {
    // #1889 review r5 (minor #3): a self-contradictory NVD response (claims results but returns
    // none — a stale cache/proxy or truncated body) must be a FAILURE so the caller holds and
    // retries, not treated as a verified-empty window. A genuine totalResults==0 stays ok=true.
    NvdClient client;
    REQUIRE_FALSE(client.parse_response(R"({"totalResults":100,"vulnerabilities":[]})").ok);
    REQUIRE(client.parse_response(R"({"totalResults":0,"vulnerabilities":[]})").ok); // genuinely empty
}

TEST_CASE("NvdClient::parse_response: out-of-range totalResults is a parse failure, not a silent wrap",
          "[nvd][parse]") {
    // PR #1912 review (HIGH): is_number_integer() checks JSON type, not C++ int range, so
    // get<int>() SILENTLY NARROWS an oversized value NEGATIVE (no throw). A negative total would
    // slip past the `total_results > 0` contradiction guard (false-"verifying" a stale/corrupt
    // empty page → permanent CVE false-negatives) and break `start_index >= total_results`
    // pagination. Every out-of-range/non-integer totalResults must be reason=kParse, ok=false.
    NvdClient c;
    // > INT_MAX (2^31): get<int>() wraps to INT_MIN without the range check.
    auto big = c.parse_response(R"({"totalResults":2147483648,"vulnerabilities":[]})");
    REQUIRE_FALSE(big.ok);
    REQUIRE(big.reason == NvdFailureReason::kParse);
    // INT64_MAX: wraps to -1.
    auto huge = c.parse_response(R"({"totalResults":9223372036854775807,"vulnerabilities":[]})");
    REQUIRE_FALSE(huge.ok);
    REQUIRE(huge.reason == NvdFailureReason::kParse);
    // A literal negative totalResults.
    auto neg = c.parse_response(R"({"totalResults":-5,"vulnerabilities":[]})");
    REQUIRE_FALSE(neg.ok);
    REQUIRE(neg.reason == NvdFailureReason::kParse);
    // A non-integer totalResults.
    auto str = c.parse_response(R"({"totalResults":"1000","vulnerabilities":[]})");
    REQUIRE_FALSE(str.ok);
    REQUIRE(str.reason == NvdFailureReason::kParse);
    // Exactly INT_MAX stays in range (accepted as a value; the contradiction guard then trips
    // because records are empty — but as a parse failure, NOT a silent negative wrap).
    auto max = c.parse_response(R"({"totalResults":2147483647,"vulnerabilities":[]})");
    REQUIRE_FALSE(max.ok);
    REQUIRE(max.reason == NvdFailureReason::kParse);
}

TEST_CASE("NvdDatabase::upsert_cves returns false when the DB is not open", "[nvd][db]") {
    // #1889 review r4 Blocker 1: the bool return is the signal do_backfill/do_freshness
    // use to hold the resume cursor on a persistence failure. A closed DB is the
    // deterministic, cross-platform failure case.
    NvdDatabase db("/proc/yuzu-nonexistent-dir/nvd.db"); // cannot be created/opened
    REQUIRE_FALSE(db.is_open());
    REQUIRE_FALSE(db.upsert_cves({MockFetcher::one_cve(1)})); // false, nothing persisted
}

TEST_CASE("NvdClient::parse_response: 200-with-bad-body is ok=false, empty window is ok=true",
          "[nvd][parse]") {
    NvdClient c;
    // Unparseable body (proxy/error page delivered as 200) → failure, not empty.
    auto bad = c.parse_response("<html>503 Service Unavailable</html>");
    REQUIRE_FALSE(bad.ok);
    // Well-formed but unexpected shape (no vulnerabilities array) → failure.
    auto weird = c.parse_response(R"({"message":"rate limited"})");
    REQUIRE_FALSE(weird.ok);
    // Genuinely-empty window → success with zero records.
    auto empty = c.parse_response(R"({"totalResults":0,"vulnerabilities":[]})");
    REQUIRE(empty.ok);
    REQUIRE(empty.records.empty());
}

TEST_CASE("cve_match NOCASE index turns the LIKE-prefix match into a seek, not a scan",
          "[nvd][perf]") {
    // Guards the perf-P1 fix: match_inventory's case-insensitive `LIKE 'name%'`
    // only uses an index when that index is COLLATE NOCASE (migration v3). Assert
    // the query planner seeks, exactly as match_inventory issues it.
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(":memory:", &db) == SQLITE_OK);
    const char* schema =
        "CREATE TABLE cve_match(id INTEGER PRIMARY KEY, cve_id TEXT, cpe_product TEXT NOT NULL,"
        " is_vulnerable INTEGER DEFAULT 1);"
        "CREATE INDEX idx_cve_match_product ON cve_match(cpe_product COLLATE NOCASE);";
    REQUIRE(sqlite3_exec(db, schema, nullptr, nullptr, nullptr) == SQLITE_OK);

    sqlite3_stmt* stmt = nullptr;
    const char* q =
        "EXPLAIN QUERY PLAN SELECT id FROM cve_match "
        "WHERE cpe_product LIKE 'openssl%' ESCAPE '\\' AND is_vulnerable = 1;";
    REQUIRE(sqlite3_prepare_v2(db, q, -1, &stmt, nullptr) == SQLITE_OK);
    std::string plan;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (const unsigned char* d = sqlite3_column_text(stmt, 3))
            plan += reinterpret_cast<const char*>(d);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    INFO("query plan: " << plan);
    REQUIRE(plan.find("idx_cve_match_product") != std::string::npos); // uses the index
    REQUIRE(plan.find("SCAN") == std::string::npos);                  // not a full scan
}

// ── PR2c: upsert dedupe-by-cve_id (#1882) ────────────────────────────────────

TEST_CASE("NvdDatabase: upsert_cves merges duplicate cve_id, losing no matches", "[nvd][db]") {
    NvdDatabase db(":memory:");
    // A batch with TWO records sharing a cve_id but DIFFERENT products — without
    // the merge, the second's delete-then-insert would wipe the first's match.
    std::vector<CveRecord> batch;
    batch.push_back(make_cve("CVE-2024-DUP", "productone", "2.0"));
    batch.push_back(make_cve("CVE-2024-DUP", "producttwo", "3.0"));
    REQUIRE(db.upsert_cves(batch));

    REQUIRE(db.total_cve_count() == 1);                                   // one distinct CVE
    REQUIRE(db.match_inventory({{"productone", "1.0"}}).size() == 1);     // first product kept
    REQUIRE(db.match_inventory({{"producttwo", "1.0"}}).size() == 1);     // second product kept
}

// ── PR2c: 429 backoff schedule + failure-reason callback (#1880) ─────────────

TEST_CASE("nvd_backoff_delay: Retry-After honoured, else exponential with cap", "[nvd][backoff]") {
    using namespace std::chrono;
    // Numeric Retry-After wins (capped at 30min).
    REQUIRE(nvd_backoff_delay(1, "45") == seconds(45));
    REQUIRE(nvd_backoff_delay(1, "999999") == seconds(1800)); // capped
    // Zero / non-numeric (HTTP-date) Retry-After falls through to exp backoff.
    REQUIRE(nvd_backoff_delay(3, "0") == seconds(120));
    REQUIRE(nvd_backoff_delay(1, "Wed, 21 Oct 2025 07:28:00 GMT") == seconds(30));
    // Exponential by attempt (1-based): 30, 60, 120, … capped at 1800.
    REQUIRE(nvd_backoff_delay(1, "") == seconds(30));
    REQUIRE(nvd_backoff_delay(2, "") == seconds(60));
    REQUIRE(nvd_backoff_delay(3, "") == seconds(120));
    REQUIRE(nvd_backoff_delay(10, "") == seconds(1800)); // capped
}

TEST_CASE("NvdSyncManager: a sync failure tallies its reason in status; cancel does not",
          "[nvd][failure]") {
    // Pull model (#1909): report_failure increments a per-reason counter surfaced via
    // status().failure_counts, which the /metrics scrape emits as
    // yuzu_nvd_sync_failures_total — no cross-thread callback.
    {
        auto db = std::make_shared<NvdDatabase>(":memory:");
        auto mock = std::make_unique<MockFetcher>();
        mock->fail = true;
        mock->fail_reason = NvdFailureReason::kHttp403;
        NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, 1);
        mgr.sync_now();
        const auto st = mgr.status();
        REQUIRE(st.failure_counts[nvd_reason_index(NvdFailureReason::kHttp403)] == 1);
        // Only the 403 series moved.
        REQUIRE(st.failure_counts[nvd_reason_index(NvdFailureReason::kConnection)] == 0);
    }
    // A cancellation is NOT a failure — no series moves.
    {
        auto db = std::make_shared<NvdDatabase>(":memory:");
        auto mock = std::make_unique<MockFetcher>();
        mock->fail = true;
        mock->fail_reason = NvdFailureReason::kCancelled;
        NvdSyncManager mgr(db, std::move(mock), std::chrono::seconds{3600}, 1);
        mgr.sync_now();
        for (auto n : mgr.status().failure_counts)
            REQUIRE(n == 0);
    }
}

// ── PR2c: reason→label + reason→index parity (yuzu_nvd_sync_failures_total) ───

TEST_CASE("nvd_reason_label maps every reason to its stable metric label", "[nvd][failure]") {
    // The SINGLE source of truth for the yuzu_nvd_sync_failures_total label set —
    // pinning the strings so they can't drift from describe()/docs/changelog.
    REQUIRE(std::string(nvd_reason_label(NvdFailureReason::kConnection)) == "connection");
    REQUIRE(std::string(nvd_reason_label(NvdFailureReason::kHttp429)) == "http_429");
    REQUIRE(std::string(nvd_reason_label(NvdFailureReason::kHttp403)) == "http_403");
    REQUIRE(std::string(nvd_reason_label(NvdFailureReason::kHttpOther)) == "http_other");
    REQUIRE(std::string(nvd_reason_label(NvdFailureReason::kParse)) == "parse");
    REQUIRE(std::string(nvd_reason_label(NvdFailureReason::kNone)) == "none");
    REQUIRE(std::string(nvd_reason_label(NvdFailureReason::kCancelled)) == "none");
}

TEST_CASE("nvd_reason_index: counted reasons are dense 0..N-1, cancel/none are -1",
          "[nvd][failure]") {
    // The index must stay in lockstep with nvd_reason_label's counted order and the
    // kNvdCountedFailureReasons-sized failure_counts array (a stale index would tally
    // the wrong series or index out of bounds).
    REQUIRE(nvd_reason_index(NvdFailureReason::kConnection) == 0);
    REQUIRE(nvd_reason_index(NvdFailureReason::kHttp429) == 1);
    REQUIRE(nvd_reason_index(NvdFailureReason::kHttp403) == 2);
    REQUIRE(nvd_reason_index(NvdFailureReason::kHttpOther) == 3);
    REQUIRE(nvd_reason_index(NvdFailureReason::kParse) == 4);
    REQUIRE(nvd_reason_index(NvdFailureReason::kNone) == -1);
    REQUIRE(nvd_reason_index(NvdFailureReason::kCancelled) == -1);
}

// ── #1879/#1880 in-fetch integration: 429 retry loop + mid-backoff cancellation ──
// These drive the real fetch_paginated retry/backoff/cancel paths against a local
// httplib::Server on an OS-assigned ephemeral port (no fixed port → no shared-runner
// collision). An API key keeps the inter-request throttle at 600ms; the tests use a
// small Retry-After so the backoff itself is short.

namespace {
// Bring up an NVD-shaped server on 127.0.0.1:<ephemeral>. handler owns the response.
struct LocalNvdServer {
    httplib::Server svr;
    int port = 0;
    std::thread th;
    template <typename Handler>
    explicit LocalNvdServer(Handler h) {
        svr.Get("/rest/json/cves/2.0", std::move(h));
        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0); // bind failed → fail loudly, don't spin forever below
        th = std::thread([this] { svr.listen_after_bind(); });
        // Bounded readiness wait (~2s) so a server that never comes up fails the test
        // with a diagnostic instead of hanging the whole suite.
        for (int i = 0; i < 2000 && !svr.is_running(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        REQUIRE(svr.is_running());
    }
    std::string url() const { return "http://127.0.0.1:" + std::to_string(port); }
    ~LocalNvdServer() {
        svr.stop();
        if (th.joinable())
            th.join();
    }
};
} // namespace

TEST_CASE("NvdClient::fetch_paginated: an HTTP 429 backs off and retries the same page",
          "[nvd][http]") {
    std::atomic<int> hits{0};
    LocalNvdServer server([&](const httplib::Request&, httplib::Response& res) {
        if (++hits == 1) {
            res.status = 429;
            res.set_header("Retry-After", "1"); // 1s backoff, then retry
        } else {
            res.status = 200;
            res.set_content(R"({"totalResults":0,"vulnerabilities":[]})", "application/json");
        }
    });
    NvdClient c("test-key", /*proxy=*/{}, server.url());
    auto r = c.fetch_by_published_window("2024-01-01T00:00:00.000", "2024-01-02T00:00:00.000");
    REQUIRE(r.ok);              // the retry after the 429 succeeded
    REQUIRE(hits.load() == 2);  // exactly one retry — the 429 didn't fail the window
}

TEST_CASE("NvdClient::fetch_paginated: a cancel during the 429 backoff aborts promptly",
          "[nvd][http]") {
    LocalNvdServer server([](const httplib::Request&, httplib::Response& res) {
        res.status = 429;
        res.set_header("Retry-After", "5"); // a 5s backoff we intend to interrupt
    });
    std::atomic<bool> cancel{false};
    NvdClient c("test-key", /*proxy=*/{}, server.url());
    c.set_cancel_flag(&cancel);
    std::thread canceller([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        cancel.store(true);
    });
    const auto t0 = std::chrono::steady_clock::now();
    auto r = c.fetch_by_published_window("2024-01-01T00:00:00.000", "2024-01-02T00:00:00.000");
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    canceller.join();
    REQUIRE_FALSE(r.ok);
    REQUIRE(r.reason == NvdFailureReason::kCancelled);
    // Woke mid-backoff (~400ms), nowhere near the full 5s Retry-After.
    REQUIRE(elapsed < std::chrono::seconds(3));
}

// ── PR1: assess() typed-identity API + vendor index (ADR-0018) ───────────────

namespace {
// A CVE whose single cpeMatch carries an explicit vendor, is_vulnerable flag, and
// versionEndExcluding upper bound (the shape assess() exercises). Distinct from the
// name-only make_cve above, which leaves cpe_vendor empty.
CveRecord make_cve_v(std::string id, std::string vendor, std::string product,
                     std::string end_excluding, bool vulnerable = true,
                     std::string severity = "HIGH") {
    CveRecord rec;
    rec.cve_id = std::move(id);
    rec.severity = std::move(severity);
    rec.description = "Test vulnerability";
    rec.published = "2024-01-01T00:00:00.000";
    rec.source = "nvd";
    CpeMatch cm;
    cm.cpe_vendor = std::move(vendor);
    cm.cpe_product = std::move(product);
    cm.version_end_excluding = std::move(end_excluding);
    cm.is_vulnerable = vulnerable;
    rec.matches.push_back(std::move(cm));
    return rec;
}
} // namespace

TEST_CASE("assess: product only in is_vulnerable=0 rows is not known", "[nvd][assess]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve_v("CVE-A", "acme", "widget", "9.9", /*vulnerable=*/false));
    auto r = db.assess({"acme", "widget", "1.0", true});
    REQUIRE_FALSE(r.product_known); // platform-only operand must never count as known
    REQUIRE(r.hits.empty());
}

TEST_CASE("assess: mixed vulnerable/platform rows yield only the vulnerable hit", "[nvd][assess]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve_v("CVE-VULN", "acme", "widget", "9.9", true));
    db.upsert_cve(make_cve_v("CVE-PLAT", "acme", "widget", "9.9", false));
    auto r = db.assess({"acme", "widget", "1.0", true});
    REQUIRE(r.product_known);
    REQUIRE(r.hits.size() == 1);
    REQUIRE(r.hits[0].cve_id == "CVE-VULN");
}

TEST_CASE("assess: known product with an out-of-range version is assessed-clean", "[nvd][assess]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve_v("CVE-A", "acme", "widget", "3.0.7", true));
    auto r = db.assess({"acme", "widget", "3.0.7", true}); // at the exclusive end → not vulnerable
    REQUIRE(r.product_known); // the identity is known...
    REQUIRE(r.hits.empty());  // ...and assessed clean (empty hits, not "unknown")
}

TEST_CASE("assess: an in-range hit carries severity/description/published/fixed_in",
          "[nvd][assess]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve_v("CVE-A", "acme", "widget", "3.0.7", true, "CRITICAL"));
    auto r = db.assess({"acme", "widget", "3.0.6", true});
    REQUIRE(r.product_known);
    REQUIRE(r.hits.size() == 1);
    REQUIRE(r.hits[0].cve_id == "CVE-A");
    REQUIRE(r.hits[0].severity == "CRITICAL");
    REQUIRE(r.hits[0].description == "Test vulnerability");
    REQUIRE(r.hits[0].published == "2024-01-01T00:00:00.000");
    REQUIRE(r.hits[0].fixed_in == "3.0.7");
}

TEST_CASE("assess: prefix path escapes the underscore wildcard (no sibling over-match)",
          "[nvd][assess]") {
    NvdDatabase db(":memory:");
    // Sibling product with an 'x' where the query has '_'. A raw LIKE '_' would match it.
    db.upsert_cve(make_cve_v("CVE-SIB", "", "linuxxkernel", "9.9", true));
    auto r = db.assess({"", "linux_kernel", "1.0", /*exact_product=*/false});
    REQUIRE_FALSE(r.product_known); // '_' is escaped to a literal → the sibling does NOT match
    REQUIRE(r.hits.empty());
    // The genuine linux_kernel row DOES match via the prefix path.
    db.upsert_cve(make_cve_v("CVE-REAL", "", "linux_kernel", "9.9", true));
    auto r2 = db.assess({"", "linux_kernel", "1.0", false});
    REQUIRE(r2.product_known);
    REQUIRE(r2.hits.size() == 1);
    REQUIRE(r2.hits[0].cve_id == "CVE-REAL");
}

TEST_CASE("assess: mixed-case vendor/product still hits (internal lowercasing)", "[nvd][assess]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve_v("CVE-A", "acme", "widget", "3.0.7", true));
    auto r = db.assess({"ACME", "WiDgEt", "3.0.6", true});
    REQUIRE(r.product_known);
    REQUIRE(r.hits.size() == 1);
    REQUIRE(r.hits[0].cve_id == "CVE-A");
}

TEST_CASE("assess: vendor disambiguates a shared product name", "[nvd][assess]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve_v("CVE-ACME", "acme", "widget", "9.9", true));
    db.upsert_cve(make_cve_v("CVE-GLOBEX", "globex", "widget", "9.9", true));
    auto a = db.assess({"acme", "widget", "1.0", true});
    REQUIRE(a.product_known);
    REQUIRE(a.hits.size() == 1);
    REQUIRE(a.hits[0].cve_id == "CVE-ACME"); // only the acme CVE, not globex's
    auto wrong = db.assess({"initech", "widget", "1.0", true});
    REQUIRE_FALSE(wrong.product_known); // wrong vendor → the identity is unknown
    REQUIRE(wrong.hits.empty());
}

TEST_CASE("assess: fixed_in is best-effort and deterministic regardless of row order",
          "[nvd][assess]") {
    NvdDatabase db(":memory:");
    // (a) versionEndExcluding populated → fixed_in carries it.
    db.upsert_cve(make_cve_v("CVE-VEE", "acme", "p1", "3.0.7", true));
    REQUIRE(db.assess({"acme", "p1", "1.0", true}).hits.at(0).fixed_in == "3.0.7");

    // (b) versionEndIncluding (no exclusive boundary) → fixed_in empty.
    {
        CveRecord rec;
        rec.cve_id = "CVE-VEI";
        rec.severity = "HIGH";
        rec.description = "d";
        rec.source = "nvd";
        CpeMatch cm;
        cm.cpe_vendor = "acme";
        cm.cpe_product = "p2";
        cm.version_end_including = "3.0.7";
        rec.matches.push_back(cm);
        db.upsert_cve(rec);
        auto r = db.assess({"acme", "p2", "1.0", true});
        REQUIRE(r.hits.size() == 1);
        REQUIRE(r.hits[0].fixed_in.empty());
    }
    // (c) exact CPE pin → fixed_in empty.
    {
        CveRecord rec;
        rec.cve_id = "CVE-PIN";
        rec.severity = "HIGH";
        rec.description = "d";
        rec.source = "nvd";
        CpeMatch cm;
        cm.cpe_vendor = "acme";
        cm.cpe_product = "p3";
        cm.cpe_version = "1.0";
        rec.matches.push_back(cm);
        db.upsert_cve(rec);
        auto r = db.assess({"acme", "p3", "1.0", true});
        REQUIRE(r.hits.size() == 1);
        REQUIRE(r.hits[0].fixed_in.empty());
    }
    // (d) two in-range rows for one CVE — one with vee, one without — must yield the same
    //     non-empty fixed_in regardless of which row was inserted first.
    auto two_rows = [](bool vee_first) {
        NvdDatabase d(":memory:");
        CveRecord rec;
        rec.cve_id = "CVE-MIX";
        rec.severity = "HIGH";
        rec.description = "d";
        rec.source = "nvd";
        CpeMatch with_vee;
        with_vee.cpe_vendor = "acme";
        with_vee.cpe_product = "p4";
        with_vee.version_end_excluding = "5.0";
        CpeMatch no_vee;
        no_vee.cpe_vendor = "acme";
        no_vee.cpe_product = "p4";
        no_vee.version_end_including = "9.9";
        if (vee_first) {
            rec.matches.push_back(with_vee);
            rec.matches.push_back(no_vee);
        } else {
            rec.matches.push_back(no_vee);
            rec.matches.push_back(with_vee);
        }
        d.upsert_cve(rec);
        auto r = d.assess({"acme", "p4", "1.0", true});
        REQUIRE(r.hits.size() == 1);
        REQUIRE(r.hits[0].fixed_in == "5.0"); // deterministic non-empty either way
    };
    two_rows(true);
    two_rows(false);
}

TEST_CASE("assess: empty product is not known even with a vendor set (guard order)",
          "[nvd][assess]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve_v("CVE-A", "acme", "widget", "9.9", true));
    auto r1 = db.assess({"", "", "1.0", true});
    REQUIRE_FALSE(r1.product_known);
    REQUIRE(r1.hits.empty());
    // Vendor set, product empty — guard 1 precedes the vendor branch.
    auto r2 = db.assess({"acme", "", "1.0", true});
    REQUIRE_FALSE(r2.product_known);
    REQUIRE(r2.hits.empty());
}

TEST_CASE("assess: an unqualified sub-3-char prefix is rejected (prefix floor)", "[nvd][assess]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve_v("CVE-A", "", "ab", "9.9", true));
    auto r = db.assess({"", "ab", "1.0", /*exact_product=*/false});
    REQUIRE_FALSE(r.product_known); // <3-char unqualified prefix → refused before any query
    REQUIRE(r.hits.empty());
    // Vendor scope lifts the floor — the same short prefix is allowed.
    db.upsert_cve(make_cve_v("CVE-B", "acme", "ab", "9.9", true));
    auto r2 = db.assess({"acme", "ab", "1.0", false});
    REQUIRE(r2.product_known);
    REQUIRE(r2.hits.size() == 1);
    REQUIRE(r2.hits[0].cve_id == "CVE-B");
}

TEST_CASE("assess: an empty installed version is known but never a hit", "[nvd][assess]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve_v("CVE-A", "acme", "widget", "9.9", true));
    auto r = db.assess({"acme", "widget", "", true});
    REQUIRE(r.product_known); // the identity exists...
    REQUIRE(r.hits.empty());  // ...but no version → no fabricated clean/vulnerable verdict
}

TEST_CASE("NvdDatabase: v4 composite index is created once and is idempotent across reopen",
          "[nvd][db][migration]") {
    yuzu::test::TempDbFile tmp{std::string_view{"nvd-v4-"}};
    const std::string path = tmp.path.string();
    {
        NvdDatabase db(path);
        REQUIRE(db.is_open());
    }
    // Reopen: schema_meta already at v4, so the migration must NOT re-run or error.
    {
        NvdDatabase db2(path);
        REQUIRE(db2.is_open());
    }

    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open(path.c_str(), &raw) == SQLITE_OK);
    // A fresh DB reaches v4.
    sqlite3_stmt* st = nullptr;
    REQUIRE(sqlite3_prepare_v2(raw, "SELECT version FROM schema_meta WHERE store='nvd_database'", -1,
                               &st, nullptr) == SQLITE_OK);
    REQUIRE(sqlite3_step(st) == SQLITE_ROW);
    REQUIRE(sqlite3_column_int(st, 0) == 4);
    sqlite3_finalize(st);
    // Exactly ONE composite index (idempotent — not created twice).
    st = nullptr;
    REQUIRE(sqlite3_prepare_v2(raw,
                               "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND "
                               "name='idx_cve_match_vendor_product'",
                               -1, &st, nullptr) == SQLITE_OK);
    REQUIRE(sqlite3_step(st) == SQLITE_ROW);
    REQUIRE(sqlite3_column_int(st, 0) == 1);
    sqlite3_finalize(st);
    // The v3 single-column index is KEPT alongside it (no regression).
    st = nullptr;
    REQUIRE(sqlite3_prepare_v2(raw,
                               "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND "
                               "name='idx_cve_match_product'",
                               -1, &st, nullptr) == SQLITE_OK);
    REQUIRE(sqlite3_step(st) == SQLITE_ROW);
    REQUIRE(sqlite3_column_int(st, 0) == 1);
    sqlite3_finalize(st);
    sqlite3_close(raw);
}

TEST_CASE("products_for_cves: DISTINCT + is_vulnerable=1 only, with cross-chunk dedup",
          "[nvd][db]") {
    NvdDatabase db(":memory:");
    REQUIRE(db.products_for_cves({}).empty()); // empty input → empty result

    db.upsert_cve(make_cve_v("CVE-VULN", "acme", "widget", "9.9", true));
    db.upsert_cve(make_cve_v("CVE-PLAT", "acme", "gadget", "9.9", false)); // is_vulnerable=0 excluded
    auto p = db.products_for_cves({"CVE-VULN", "CVE-PLAT"});
    REQUIRE(p.size() == 1);
    REQUIRE(p[0].first == "acme");
    REQUIRE(p[0].second == "widget");

    // The SAME vendor/product under 501 distinct cve_ids straddles the 500-id chunk
    // boundary; SQL DISTINCT is per-chunk, so cross-chunk dedup must collapse it to one.
    std::vector<std::string> ids;
    for (int i = 0; i < 501; ++i) {
        std::string id = "CVE-BULK-" + std::to_string(i);
        db.upsert_cve(make_cve_v(id, "bulkvendor", "bulkproduct", "9.9", true));
        ids.push_back(id);
    }
    auto q500 = db.products_for_cves(std::vector<std::string>(ids.begin(), ids.begin() + 500));
    REQUIRE(q500.size() == 1); // exactly at the chunk boundary
    auto q501 = db.products_for_cves(ids);
    REQUIRE(q501.size() == 1); // 501 ids → two chunks → dedup still holds
    REQUIRE(q501[0].first == "bulkvendor");
    REQUIRE(q501[0].second == "bulkproduct");
}

TEST_CASE("upsert_cves: changed_ids is opt-in and deduped; nullptr leaves the bool contract",
          "[nvd][db]") {
    NvdDatabase db(":memory:");
    // nullptr (the default) → persist bool unchanged, no delta collected.
    REQUIRE(db.upsert_cves({make_cve("CVE-N1", "p", "1.0")}));

    // Non-null → filled with the persisted cve_ids.
    std::vector<std::string> changed;
    std::vector<CveRecord> batch{make_cve("CVE-C1", "p1", "1.0"), make_cve("CVE-C2", "p2", "1.0")};
    REQUIRE(db.upsert_cves(batch, &changed));
    REQUIRE(changed.size() == 2);

    // A batch with a duplicate cve_id → the delta is deduped (the merge folds duplicates).
    std::vector<std::string> dchanged;
    std::vector<CveRecord> dup{make_cve("CVE-D", "pa", "1.0"), make_cve("CVE-D", "pb", "2.0")};
    REQUIRE(db.upsert_cves(dup, &dchanged));
    REQUIRE(dchanged.size() == 1);
    REQUIRE(dchanged[0] == "CVE-D");
}

TEST_CASE("assess/match query plans seek on the right index (two-index schema)", "[nvd][perf]") {
    // Mirrors the REAL cve_match schema after migration v4: BOTH the v3 single-column
    // idx_cve_match_product and the v4 composite idx_cve_match_vendor_product. Asserts
    // the planner picks the right seek per query shape and never full-scans.
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(":memory:", &db) == SQLITE_OK);
    const char* schema =
        "CREATE TABLE cve_match(id INTEGER PRIMARY KEY, cve_id TEXT, cpe_vendor TEXT,"
        " cpe_product TEXT NOT NULL, is_vulnerable INTEGER DEFAULT 1);"
        "CREATE INDEX idx_cve_match_product ON cve_match(cpe_product COLLATE NOCASE);"
        "CREATE INDEX idx_cve_match_vendor_product ON cve_match(cpe_vendor, cpe_product COLLATE "
        "NOCASE);";
    REQUIRE(sqlite3_exec(db, schema, nullptr, nullptr, nullptr) == SQLITE_OK);

    auto plan_of = [&](const char* q) {
        sqlite3_stmt* st = nullptr;
        REQUIRE(sqlite3_prepare_v2(db, q, -1, &st, nullptr) == SQLITE_OK);
        std::string plan;
        while (sqlite3_step(st) == SQLITE_ROW)
            if (const unsigned char* d = sqlite3_column_text(st, 3))
                plan += reinterpret_cast<const char*>(d);
        sqlite3_finalize(st);
        return plan;
    };

    // (a) vendor + exact product → composite index, no scan.
    {
        auto p = plan_of("EXPLAIN QUERY PLAN SELECT id FROM cve_match WHERE cpe_vendor='acme' AND "
                         "cpe_product='widget' COLLATE NOCASE AND is_vulnerable=1;");
        INFO("plan (a): " << p);
        REQUIRE(p.find("idx_cve_match_vendor_product") != std::string::npos);
        REQUIRE(p.find("SCAN") == std::string::npos);
    }
    // (b) vendor + prefix product → composite index, no scan.
    {
        auto p = plan_of("EXPLAIN QUERY PLAN SELECT id FROM cve_match WHERE cpe_vendor='acme' AND "
                         "cpe_product LIKE 'wid%' ESCAPE '\\' AND is_vulnerable=1;");
        INFO("plan (b): " << p);
        REQUIRE(p.find("idx_cve_match_vendor_product") != std::string::npos);
        REQUIRE(p.find("SCAN") == std::string::npos);
        // Assert the PRODUCT column is used as a range bound, not just the vendor
        // equality: dropping COLLATE NOCASE from the composite's product column
        // degrades the plan to `(cpe_vendor=?)` only — which STILL names the index and
        // has no SCAN, so the two checks above pass on that regression. `cpe_product>`
        // is present only when the LIKE-prefix range seek actually engages (FIX 4).
        REQUIRE(p.find("cpe_product>") != std::string::npos);
    }
    // (c) vendor-less prefix → the single-column index (no regression from v4).
    {
        auto p = plan_of("EXPLAIN QUERY PLAN SELECT id FROM cve_match WHERE cpe_product LIKE 'wid%' "
                         "ESCAPE '\\' AND is_vulnerable=1;");
        INFO("plan (c): " << p);
        REQUIRE(p.find("idx_cve_match_product") != std::string::npos);
        REQUIRE(p.find("SCAN") == std::string::npos);
        // Same collation-regression guard as (b): the product range bound must engage,
        // not a bare index name with no seek (FIX 4).
        REQUIRE(p.find("cpe_product>") != std::string::npos);
    }
    // (d) match_inventory's exact query shape still seeks.
    {
        auto p = plan_of("EXPLAIN QUERY PLAN SELECT id FROM cve_match WHERE cpe_product LIKE "
                         "'openssl%' ESCAPE '\\' AND is_vulnerable=1;");
        INFO("plan (d): " << p);
        REQUIRE(p.find("SCAN") == std::string::npos);
    }
    sqlite3_close(db);
}

// ── Adversarial tester — hostile cases the coder's own suite did not cover ───
// Attack angles from the PR1 review brief: is_vulnerable leak variants, LIKE-escape
// completeness (embedded backslash / literal '%'), vendor-collation asymmetry,
// exact-path floor exemption, fixed_in with TWO distinct non-empty candidates,
// products_for_cves with hostile ids, and a forced per-CVE savepoint rollback
// inside an otherwise-successful batch (changed_ids must exclude it).

TEST_CASE("assess(adversarial): an out-of-range vulnerable row plus an in-range platform "
          "row yields known-but-clean, never a fabricated hit",
          "[nvd][adversarial]") {
    NvdDatabase db(":memory:");
    // Same cve_id, two matches: the is_vulnerable=1 row's range does NOT cover the
    // installed version; the is_vulnerable=0 row's range DOES cover it. The WHERE
    // is_vulnerable=1 filter must exclude the second row entirely — it must never
    // surface as a hit just because its range happens to contain the version.
    CveRecord rec;
    rec.cve_id = "CVE-MIXED-RANGE";
    rec.severity = "HIGH";
    rec.description = "d";
    rec.published = "2024-01-01T00:00:00.000";
    rec.source = "nvd";
    CpeMatch vulnerable_out_of_range;
    vulnerable_out_of_range.cpe_vendor = "acme";
    vulnerable_out_of_range.cpe_product = "widget";
    vulnerable_out_of_range.version_end_excluding = "1.0"; // installed 5.0 is NOT < 1.0
    vulnerable_out_of_range.is_vulnerable = true;
    CpeMatch platform_in_range;
    platform_in_range.cpe_vendor = "acme";
    platform_in_range.cpe_product = "widget";
    platform_in_range.version_end_excluding = "9.9"; // installed 5.0 IS < 9.9
    platform_in_range.is_vulnerable = false;
    rec.matches.push_back(vulnerable_out_of_range);
    rec.matches.push_back(platform_in_range);
    db.upsert_cve(rec);

    auto r = db.assess({"acme", "widget", "5.0", true});
    REQUIRE(r.product_known);  // the is_vulnerable=1 row makes the identity known...
    REQUIRE(r.hits.empty());   // ...but neither row produces a hit (out-of-range / excluded)
}

TEST_CASE("assess(adversarial): a literal backslash in the stored product is matched "
          "only via its escaped form",
          "[nvd][adversarial]") {
    NvdDatabase db(":memory:");
    // Stored product contains a REAL backslash character. Vendor scope lifts the
    // 3-char prefix floor so a 2-char query ("a\") is legal.
    db.upsert_cve(make_cve_v("CVE-BACKSLASH", "acme", "a\\b", "9.9", true));
    // A sibling with NO backslash must not be swept in by a broken escape.
    db.upsert_cve(make_cve_v("CVE-SIBLING", "acme", "axb", "9.9", true));

    auto hit = db.assess({"acme", "a\\", "1.0", /*exact_product=*/false});
    REQUIRE(hit.product_known);
    REQUIRE(hit.hits.size() == 1);
    REQUIRE(hit.hits[0].cve_id == "CVE-BACKSLASH"); // "axb" must NOT appear
}

TEST_CASE("assess(adversarial): a literal '%' in the stored product requires a literal "
          "'%' in the query, not a wildcard",
          "[nvd][adversarial]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve_v("CVE-PCT", "acme", "100%cpu", "9.9", true));
    db.upsert_cve(make_cve_v("CVE-SIB", "acme", "100xcpu", "9.9", true));

    auto r = db.assess({"acme", "100%", "1.0", /*exact_product=*/false});
    REQUIRE(r.product_known);
    REQUIRE(r.hits.size() == 1);
    REQUIRE(r.hits[0].cve_id == "CVE-PCT"); // "100xcpu" must NOT match the escaped '%'
}

TEST_CASE("assess(adversarial): cpe_vendor stored non-lowercase is invisible to the "
          "BINARY vendor filter — asymmetric with the product path's COLLATE NOCASE",
          "[nvd][adversarial]") {
    NvdDatabase db(":memory:");
    // Simulate a producer that (unlike nvd_client.cpp's `lower()`) failed to
    // normalize case on cpe_vendor before it reached the store. nvd_db.cpp itself
    // enforces no such invariant — it only documents it as a comment.
    db.upsert_cve(make_cve_v("CVE-CASE", "ACME", "widget", "9.9", true));

    // The caller queries with a normal lowercase vendor, exactly as every real
    // caller (server-side CPE-identity resolution) would.
    //
    // REGRESSION GUARD for an ACCEPTED limitation, not a bug to 'fix' by editing this
    // test: cpe_vendor is BINARY-collated (the composite index seek depends on it);
    // producers MUST lowercase vendor at ingest (nvd_client.cpp does). If a future
    // producer regresses, fix it at ingest, NOT by relaxing this assertion. See
    // ADR-0023 / the assess() vendor-filter comment.
    auto r = db.assess({"acme", "widget", "1.0", true});
    // FINDING: this currently comes back product_known=false — a false "unknown"
    // verdict — because `m.cpe_vendor = ?` has no COLLATE NOCASE (unlike
    // `m.cpe_product = ? COLLATE NOCASE`, which forgives exactly this class of
    // mismatch). See the ranked findings for severity/exploitability discussion.
    REQUIRE_FALSE(r.product_known);
    REQUIRE(r.hits.empty());
}

TEST_CASE("assess(adversarial): exact_product with a 2-char product is exempt from the "
          "prefix floor even with an empty vendor",
          "[nvd][adversarial]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve_v("CVE-GO", "", "go", "9.9", true));
    auto r = db.assess({"", "go", "1.0", /*exact_product=*/true});
    REQUIRE(r.product_known); // floor only gates the LIKE-prefix path, never exact
    REQUIRE(r.hits.size() == 1);
}

TEST_CASE("assess(adversarial): fixed_in with TWO distinct non-empty in-range candidates "
          "resolves to the MINIMUM versionEndExcluding, order-independent",
          "[nvd][adversarial]") {
    // Unlike the coder's determinism test (exactly one row ever has a non-empty
    // fixed_in), here BOTH in-range rows for the same cve_id+product carry a
    // DIFFERENT non-empty version_end_excluding (3.0 and 8.0). The correct fix
    // boundary for an installed version in range of both is the SMALLEST upper
    // bound (3.0) — the least version that lifts the install out of range. The
    // reconciliation must compare with the NVD comparator (not string compare) and
    // must be independent of which row SQLite returns first.
    auto build = [](bool first_is_3_0) {
        NvdDatabase d(":memory:");
        CveRecord rec;
        rec.cve_id = "CVE-MULTI-FIX";
        rec.severity = "HIGH";
        rec.description = "d";
        rec.source = "nvd";
        CpeMatch fix_3_0;
        fix_3_0.cpe_vendor = "acme";
        fix_3_0.cpe_product = "widget";
        fix_3_0.version_end_excluding = "3.0";
        CpeMatch fix_8_0;
        fix_8_0.cpe_vendor = "acme";
        fix_8_0.cpe_product = "widget";
        fix_8_0.version_end_excluding = "8.0";
        if (first_is_3_0) {
            rec.matches.push_back(fix_3_0);
            rec.matches.push_back(fix_8_0);
        } else {
            rec.matches.push_back(fix_8_0);
            rec.matches.push_back(fix_3_0);
        }
        d.upsert_cve(rec);
        // Installed version 2.0 is in-range for BOTH candidate upper bounds.
        return d.assess({"acme", "widget", "2.0", true});
    };
    auto a = build(true);
    auto b = build(false);
    REQUIRE(a.hits.size() == 1);
    REQUIRE(b.hits.size() == 1);
    INFO("first_is_3_0=true  -> fixed_in=" << a.hits[0].fixed_in);
    INFO("first_is_3_0=false -> fixed_in=" << b.hits[0].fixed_in);
    // The minimum upper bound wins regardless of insertion order.
    REQUIRE(a.hits[0].fixed_in == "3.0");
    REQUIRE(b.hits[0].fixed_in == "3.0");
}

TEST_CASE("assess(adversarial): fixed_in min is NUMERIC not lexical (8.0 vs 10.0)",
          "[nvd][adversarial]") {
    // "10.0" < "8.0" lexically but 10.0 > 8.0 numerically. The reconciliation must
    // pick 8.0 (the true minimum), proving the NVD comparator — not string compare —
    // drives the min, in both insertion orders.
    auto build = [](bool eight_first) {
        NvdDatabase d(":memory:");
        CveRecord rec;
        rec.cve_id = "CVE-NUM-FIX";
        rec.severity = "HIGH";
        rec.description = "d";
        rec.source = "nvd";
        CpeMatch fix_8;
        fix_8.cpe_vendor = "acme";
        fix_8.cpe_product = "widget";
        fix_8.version_end_excluding = "8.0";
        CpeMatch fix_10;
        fix_10.cpe_vendor = "acme";
        fix_10.cpe_product = "widget";
        fix_10.version_end_excluding = "10.0";
        if (eight_first) {
            rec.matches.push_back(fix_8);
            rec.matches.push_back(fix_10);
        } else {
            rec.matches.push_back(fix_10);
            rec.matches.push_back(fix_8);
        }
        d.upsert_cve(rec);
        return d.assess({"acme", "widget", "2.0", true});
    };
    REQUIRE(build(true).hits.at(0).fixed_in == "8.0");
    REQUIRE(build(false).hits.at(0).fixed_in == "8.0");
}

TEST_CASE("products_for_cves(adversarial): a hostile/empty cve_id in the input neither "
          "crashes nor false-matches",
          "[nvd][adversarial]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve_v("CVE-REAL", "acme", "widget", "9.9", true));

    auto p = db.products_for_cves({"", "CVE-DOES-NOT-EXIST'; DROP TABLE cve_match; --"});
    REQUIRE(p.empty());
    // The store must still be fully functional afterward — no injection, no corruption.
    REQUIRE(db.total_cve_count() == 1);
    REQUIRE(db.assess({"acme", "widget", "1.0", true}).product_known);
}

TEST_CASE("upsert_cves(adversarial): changed_ids excludes a per-CVE savepoint rollback "
          "inside an otherwise-successful batch",
          "[nvd][adversarial]") {
    yuzu::test::TempDbFile tmp{std::string_view{"nvd-adv-partial-"}};
    const std::string path = tmp.path.string();

    {
        // Install a trigger that forces the insert for one specific product to fail,
        // simulating the "data-dependent per-record failure" the production code
        // comment says the current TEXT-only schema can't otherwise produce.
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(path.c_str(), &raw) == SQLITE_OK);
        // NvdDatabase hasn't created its tables yet on this raw handle — open+close
        // an NvdDatabase first so cve_match exists, then attach the trigger.
        sqlite3_close(raw);
    }
    { NvdDatabase warm(path); } // runs migrations, creates cve/cve_match, then closes

    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(path.c_str(), &raw) == SQLITE_OK);
        const char* trig = "CREATE TRIGGER poison_guard BEFORE INSERT ON cve_match "
                          "WHEN NEW.cpe_product = 'poison' "
                          "BEGIN SELECT RAISE(ABORT, 'blocked for test'); END;";
        REQUIRE(sqlite3_exec(raw, trig, nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    NvdDatabase db(path);
    std::vector<CveRecord> batch;
    batch.push_back(make_cve_v("CVE-GOOD", "acme", "safe", "9.9", true));
    batch.push_back(make_cve_v("CVE-POISON", "acme", "poison", "9.9", true));

    std::vector<std::string> changed;
    const bool ok = db.upsert_cves(batch, &changed);

    // FIX 3, RETAINED side: a per-CVE SAVEPOINT rollback fails one record while the
    // surrounding batch STILL commits the rest — so bool is false yet changed_ids is
    // non-empty with the ids that genuinely committed (CVE-GOOD). This is the ONLY
    // non-empty-on-false case FIX 3 leaves standing. The complementary CLEARED side
    // (an outer COMMIT failure wipes changed_ids, since nothing committed) is covered
    // by inspection: it is the `if (changed_ids) changed_ids->clear();` guard on the
    // txn.commit()!=SQLITE_OK branch in upsert_cves_impl. Forcing a WAL COMMIT to fail
    // deterministically needs an I/O-fault VFS shim (a COMMIT can't fail from external
    // contention in WAL), so it is not exercised at runtime here.
    REQUIRE_FALSE(ok); // the batch was NOT fully persisted
    REQUIRE(changed.size() == 1);
    REQUIRE(changed[0] == "CVE-GOOD"); // the rolled-back CVE must never appear here

    // CVE-GOOD's insert genuinely committed (per-CVE SAVEPOINT rollback is scoped to
    // the failing CVE only — the surrounding batch transaction still commits the rest).
    REQUIRE(db.assess({"acme", "safe", "1.0", true}).product_known);
    // CVE-POISON's header+matches must have rolled back together (UP-1 atomicity) —
    // it must not appear as a known identity at all.
    REQUIRE_FALSE(db.assess({"acme", "poison", "1.0", true}).product_known);
}

TEST_CASE("assess/products_for_cves: a DB fault THROWS, never a false absent/empty verdict "
          "(FIX 1)",
          "[nvd][adversarial]") {
    yuzu::test::TempDbFile tmp{std::string_view{"nvd-fault-throw-"}};
    const std::string path = tmp.path.string();

    NvdDatabase db(path);
    db.upsert_cve(make_cve_v("CVE-REAL", "acme", "widget", "9.9", true));
    REQUIRE(db.assess({"acme", "widget", "1.0", true}).product_known);   // healthy first
    REQUIRE(db.products_for_cves({"CVE-REAL"}).size() == 1);

    // Drop cve_match out from under the store via a second connection so the next
    // prepare fails with "no such table: cve_match" (same technique the atomic-rollback
    // test uses). Before FIX 1 both functions swallowed the prepare error and returned
    // an empty result — indistinguishable from a genuine no-rows/absent identity, i.e. a
    // fabricated product_known=false / an empty CVE→product inversion. FIX 1 makes them
    // THROW so the caller can distinguish a DB fault and abort, never record clean.
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(path.c_str(), &raw) == SQLITE_OK);
        REQUIRE(sqlite3_exec(raw, "DROP TABLE cve_match;", nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    // Prepare-failure throw path (forced deterministically above). The step-error path
    // (a mid-scan SQLITE_BUSY/IOERR/CORRUPT → rc != SQLITE_DONE → throw) shares the same
    // throw site and is covered by inspection — it cannot be forced without a VFS shim.
    REQUIRE_THROWS_AS(db.assess({"acme", "widget", "1.0", true}), std::runtime_error);
    REQUIRE_THROWS_AS(db.products_for_cves({"CVE-REAL"}), std::runtime_error);
}

// Regression test for issue #1908: rules out parse_response()/the move-iterator
// insert() as the source of a SIGSEGV heap-corruption crash in fetch_paginated().
// Deliberately does not construct an httplib::Client (see the CAVEAT below the
// JSON builders for why) — only the parse+append path is exercised here.
namespace {
std::string zero_pad6(int n) {
    std::string s = std::to_string(n);
    if (s.size() < 6) {
        s.insert(0, 6 - s.size(), '0');
    }
    return s;
}

// One synthetic "vulnerabilities[i]" entry shaped like a real NVD API response:
// cve.id, descriptions[lang=en], metrics.cvssMetricV31[0].cvssData.baseSeverity,
// published/lastModified, and configurations[].nodes[].cpeMatch[] (2 matches) —
// exactly the fields NvdClient::parse_response() reads.
std::string make_synthetic_vuln_json(int n) {
    const std::string suffix = zero_pad6(n);
    const std::string vendor = "vendor" + std::to_string(n);
    const std::string product = "product" + std::to_string(n);
    std::string s;
    s.reserve(650);
    s += R"({"cve":{"id":"CVE-2024-)" + suffix + R"(",)";
    s += R"("descriptions":[{"lang":"en","value":"Synthetic test vulnerability )" + suffix +
         R"("}],)";
    s += R"("metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"HIGH"}}]},)";
    s += R"("published":"2024-01-01T00:00:00.000",)";
    s += R"("lastModified":"2024-06-15T12:00:00.000",)";
    s += R"("configurations":[{"nodes":[{"cpeMatch":[)";
    s += R"({"criteria":"cpe:2.3:a:)" + vendor + ":" + product +
         R"(:1.0.0:*:*:*:*:*:*:*","versionStartIncluding":"1.0.0",)"
         R"("versionEndExcluding":"2.0.0","vulnerable":true},)";
    s += R"({"criteria":"cpe:2.3:a:)" + vendor + ":" + product +
         R"(b:2.0.0:*:*:*:*:*:*:*","versionEndExcluding":"3.0.0","vulnerable":true})";
    s += R"(]}]}]}})";
    return s;
}

std::string make_synthetic_page_json(int page_offset, int count, int total_results) {
    std::string body;
    body.reserve(static_cast<std::size_t>(count) * 650 + 64);
    body += R"({"totalResults":)" + std::to_string(total_results) + R"(,"vulnerabilities":[)";
    for (int i = 0; i < count; ++i) {
        if (i > 0) {
            body += ",";
        }
        body += make_synthetic_vuln_json(page_offset + i);
    }
    body += "]}";
    return body;
}
} // namespace

// CAVEAT (macOS/AppleClang only): Apple Clang 21 / Apple libc++'s "trivial
// relocation" vector-growth optimization desyncs ASan's container poisoning,
// producing a false-positive "container-overflow" inside nlohmann::json::parse()
// and independently inside httplib::Client's std::regex host:port parsing —
// neither involves Yuzu code. Locally this test needs
// `ASAN_OPTIONS=detect_container_overflow=0`; the checks that catch real
// allocator corruption (heap-buffer-overflow, use-after-free, double-free) stay
// active regardless. libstdc++ (the nightly sanitizer CI toolchain) doesn't use
// this relocation optimization, so the FP is not expected there.
TEST_CASE("NvdClient parse+append stays memory-clean across 2 synthetic 2000-CVE pages",
          "[nvd][parse][sanitizer]") {
    constexpr int kResultsPerPage = 2000; // mirrors nvd_client.cpp's kResultsPerPage
    constexpr int kTotalResults = 26935;  // mirrors the real crash's totalResults

    NvdClient client;
    NvdFetchResult combined;
    int start_index = 0;

    for (int page = 0; page < 2; ++page) {
        const std::string body =
            make_synthetic_page_json(start_index, kResultsPerPage, kTotalResults);

        auto page_result = client.parse_response(body);
        REQUIRE(page_result.ok);
        REQUIRE(page_result.records.size() == static_cast<std::size_t>(kResultsPerPage));

        combined.total_results = page_result.total_results;
        // The exact move-iterator insert fetch_paginated() uses to append a page.
        combined.records.insert(combined.records.end(),
                                std::make_move_iterator(page_result.records.begin()),
                                std::make_move_iterator(page_result.records.end()));

        start_index += kResultsPerPage;
    }

    REQUIRE(combined.records.size() == static_cast<std::size_t>(kResultsPerPage) * 2);
    REQUIRE(combined.total_results == kTotalResults);
    REQUIRE(combined.records.front().cve_id == "CVE-2024-000000");
    REQUIRE(combined.records.back().cve_id == "CVE-2024-003999");
    // Spot-check a match survived the parse+move+insert pipeline intact.
    REQUIRE(combined.records[500].matches.size() == 2);
    REQUIRE(combined.records[500].matches[0].cpe_vendor == "vendor500");
    REQUIRE(combined.records[3000].matches[1].cpe_product == "product3000b");
}

// ── parse_nvd_proxy_url: where the proxy points, and nothing of who configured it ──

TEST_CASE("parse_nvd_proxy_url: scheme, port and no-scheme shapes", "[nvd][proxy]") {
    struct Case {
        const char* url;
        const char* host;
        int port;
    };
    const Case cases[] = {
        {"http://proxy.lan:3128", "proxy.lan", 3128},
        {"https://proxy.lan:8443", "proxy.lan", 8443},
        {"proxy.lan:3128", "proxy.lan", 3128},         // no scheme
        {"proxy.lan", "proxy.lan", 8080},              // no port: the long-standing default
        {"http://proxy.lan:3128/", "proxy.lan", 3128}, // trailing slash
        {"http://proxy.lan:3128/some/path?x=1#f", "proxy.lan", 3128}, // path/query/fragment dropped
        {"http://proxy.lan:notaport", "proxy.lan", 8080},
        {"http://proxy.lan:0", "proxy.lan", 8080},
        {"http://proxy.lan:65536", "proxy.lan", 8080},
        {"http://proxy.lan:80x", "proxy.lan", 8080},
    };
    for (const auto& c : cases) {
        INFO("url: " << c.url);
        const auto ep = parse_nvd_proxy_url(c.url);
        CHECK(ep.host == c.host);
        CHECK(ep.port == c.port);
    }
    CHECK(parse_nvd_proxy_url("").host.empty());
}

TEST_CASE("parse_nvd_proxy_url: userinfo never reaches the host or the port",
          "[nvd][proxy][security]") {
    struct Case {
        const char* url;
        const char* host;
        int port;
    };
    const Case cases[] = {
        {"http://svc:hunter2@proxy.lan:3128", "proxy.lan", 3128}, // the reported case
        {"svc:hunter2@proxy.lan:3128", "proxy.lan", 3128},         // no scheme
        {"http://svc@proxy.lan:3128", "proxy.lan", 3128},          // user only
        {"http://svc:p@ss@proxy.lan:3128", "proxy.lan", 3128},     // '@' inside the password
        {"http://svc:p%40ss%3A@proxy.lan:3128", "proxy.lan", 3128}, // percent-encoded password
        {"http://svc:hunter2@proxy.lan", "proxy.lan", 8080},        // credentials, no port
        {"http://svc:hunter2@[::1]:3128", "::1", 3128},             // IPv6 literal
        {"http://svc:hunter2@[2001:db8::5]", "2001:db8::5", 8080},  // IPv6, no port
        {"[::1]:3128", "::1", 3128},                                // IPv6, no scheme or userinfo
        {"http://svc:hunter2@proxy.lan:3128/p@th", "proxy.lan", 3128}, // '@' in a path
    };
    for (const auto& c : cases) {
        INFO("url: " << c.url);
        const auto ep = parse_nvd_proxy_url(c.url);
        CHECK(ep.host == c.host);
        CHECK(ep.port == c.port);
        // The credential text appears nowhere in the parsed endpoint.
        CHECK(ep.host.find("hunter2") == std::string::npos);
        CHECK(ep.host.find("svc") == std::string::npos);
        CHECK(ep.host.find('@') == std::string::npos);
    }
}
