// MCP twin completeness: every registry-resident MCP tool (mcp_tools_<domain>.cpp records)
// must be wired into the two places a twin is pinned, so a new tool cannot ship half-registered.
//
//   1. The API-parity ledger (scripts/ci/api-parity/*.json): some row names the tool as its
//      `mcp_twin`.
//   2. kExpectedTwins (test_expected_twins.hpp): the (securable, operation) pin that
//      test_operator_surface_twins.cpp binds to the served security map.
//
// Not duplicated here (each has its own gate): the orientation family tether
// (test_mcp_server.cpp), every ledger `mcp_twin` claim resolving to a compiled tool
// (test_api_parity_ledger_catalogue.cpp, the converse direction), and the A5 floors
// (test_mcp_dispatch_coverage.cpp).
//
// Backfill sets are SHRINK-ONLY, after kShortDescriptionBackfill in test_mcp_dispatch_coverage.cpp:
// a tool listed in one must still be missing, otherwise the entry is stale and the test fails
// until it is deleted, and the set size is capped so a new gap is fixed rather than listed.
//
// Limit: this proves membership only. It does not prove the (securable, operation) in
// kExpectedTwins matches the tool's registry record (test_operator_surface_twins.cpp does) or
// that the ledger row's REST twin is real (check-api-parity.py does).
//
// The ledger directory arrives as YUZU_API_PARITY_LEDGER_DIR (tests/meson.build), the same define
// test_api_parity_ledger_catalogue.cpp uses. A missing, unreadable or empty ledger FAILS the
// test: it must never pass vacuously.

#include "mcp_server_testonly.hpp"
#include "test_expected_twins.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#ifndef YUZU_API_PARITY_LEDGER_DIR
#error "YUZU_API_PARITY_LEDGER_DIR must be injected by tests/meson.build (meson.project_source_root() / 'scripts' / 'ci' / 'api-parity') - see the server_test_exe cpp_args block."
#endif

namespace fs = std::filesystem;
using yuzu::server::mcp::registry_records_for_test;
using yuzu::server::twin_table::kExpectedTwins;

namespace {

// Registry tools that no ledger row names as its mcp_twin yet. Empty today: every registry tool
// is ledgered. Shrink-only: never add a name, ledger the tool.
const std::set<std::string> kLedgerBackfill{};
constexpr std::size_t kLedgerBackfillCap = 0;

// Registry tools with no kExpectedTwins row yet. discover_routes is ledgered (settings.json) but
// its gate is not pinned in the twin table. Shrink-only: delete the entry when the row lands.
const std::set<std::string> kExpectedTwinsBackfill{"discover_routes"};
constexpr std::size_t kExpectedTwinsBackfillCap = 1;

// Exact number of ledger domain files a healthy scan reads (one per DOMAINS entry in
// scripts/ci/check-api-parity.py, which also requires the set to match exactly). Equality, not
// a floor: a wrongly-pointed, truncated or silently grown directory cannot pass. The count is
// pinned in three places that move together: DOMAINS in that script, this constant, and
// kLedgerFiles in tests/unit/server/test_api_parity_ledger_catalogue.cpp, whenever a domain
// file is added or removed.
constexpr std::size_t kLedgerFiles = 24;

struct LedgerTwins {
    std::set<std::string> names; // every string-valued mcp_twin
    std::size_t files{0};
    std::vector<std::string> failures;
};

/// Collects every string `mcp_twin` value from the *.json files under `dir`. Each problem becomes
/// a failure line; nothing throws apart from allocation.
LedgerTwins read_ledger_twins(const fs::path& dir) {
    LedgerTwins out;
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) {
        out.failures.push_back("ledger directory is missing or not a directory: " +
                               dir.generic_string());
        return out;
    }
    std::vector<fs::path> files;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        if (it->path().extension() == ".json")
            files.push_back(it->path());
    }
    if (ec) {
        out.failures.push_back("cannot list ledger directory " + dir.generic_string() + ": " +
                               ec.message());
        return out;
    }
    std::sort(files.begin(), files.end());
    for (const auto& path : files) {
        const std::string file = path.filename().string();
        ++out.files;
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            out.failures.push_back(file + ": cannot open ledger file");
            continue;
        }
        const nlohmann::json doc = nlohmann::json::parse(in, nullptr, /*allow_exceptions=*/false);
        if (doc.is_discarded() || !doc.is_array()) {
            out.failures.push_back(file + ": not a JSON array of ledger rows");
            continue;
        }
        for (const auto& row : doc) {
            if (row.is_object() && row.contains("mcp_twin") && row["mcp_twin"].is_string())
                out.names.insert(row["mcp_twin"].get<std::string>());
        }
    }
    return out;
}

/// The predicate both gates share: every name in `names` must be in `present`, except those in
/// `backfill`; every `backfill` entry must still be a real miss (else it is stale). Returns one
/// human-readable line per defect, empty when the set is complete.
std::vector<std::string> membership_failures(const std::string& what,
                                             const std::vector<std::string>& names,
                                             const std::set<std::string>& present,
                                             const std::set<std::string>& backfill) {
    std::vector<std::string> failures;
    for (const auto& name : names) {
        if (!present.contains(name) && !backfill.contains(name))
            failures.push_back(name + ": registry tool is missing from " + what);
    }
    for (const auto& entry : backfill) {
        const bool known = std::find(names.begin(), names.end(), entry) != names.end();
        if (!known)
            failures.push_back(entry + ": backfill entry is not a registry tool (stale, delete it)");
        else if (present.contains(entry))
            failures.push_back(entry + ": backfill entry is now present in " + what +
                               " (stale, delete it)");
    }
    return failures;
}

std::vector<std::string> registry_names() {
    std::vector<std::string> names;
    for (const auto& r : registry_records_for_test())
        names.emplace_back(r.name);
    return names;
}

std::set<std::string> expected_twin_names() {
    std::set<std::string> names;
    for (const auto& row : kExpectedTwins)
        names.emplace(row.tool);
    return names;
}

std::string join(const std::vector<std::string>& lines) {
    std::string out;
    for (const auto& l : lines)
        out += "\n  " + l;
    return out;
}

} // namespace

TEST_CASE("MCP twin completeness: every registry tool is a ledger mcp_twin",
          "[mcp][twin_completeness]") {
    const auto names = registry_names();
    REQUIRE_FALSE(names.empty()); // an accessor regression must not read as a clean pass

    const auto ledger = read_ledger_twins(YUZU_API_PARITY_LEDGER_DIR);
    INFO("ledger dir: " << YUZU_API_PARITY_LEDGER_DIR);
    INFO("ledger read failures:" << join(ledger.failures));
    CHECK(ledger.failures.empty());
    INFO("ledger files read: " << ledger.files << " (expected " << kLedgerFiles
                               << "); if a domain file was added or removed, move kLedgerFiles "
                                  "together with DOMAINS in scripts/ci/check-api-parity.py and the same "
                                  "constant in test_api_parity_ledger_catalogue.cpp");
    REQUIRE(ledger.files == kLedgerFiles);
    REQUIRE_FALSE(ledger.names.empty());

    CHECK(kLedgerBackfill.size() == kLedgerBackfillCap); // shrink-only: a fix lowers the cap in the same change
    const auto failures =
        membership_failures("the API-parity ledger", names, ledger.names, kLedgerBackfill);
    INFO("failures:" << join(failures));
    INFO("To fix: add a ledger row with this tool as its mcp_twin in scripts/ci/api-parity/*.json "
         "(docs/api-twin-recipe.md). A stale backfill entry must be deleted from "
         "kLedgerBackfill.");
    CHECK(failures.empty());
}

TEST_CASE("MCP twin completeness: every registry tool has a kExpectedTwins row",
          "[mcp][twin_completeness]") {
    const auto names = registry_names();
    REQUIRE_FALSE(names.empty());
    const auto expected = expected_twin_names();
    REQUIRE_FALSE(expected.empty());

    CHECK(kExpectedTwinsBackfill.size() == kExpectedTwinsBackfillCap); // shrink-only: lower the cap with the entry
    const auto failures =
        membership_failures("kExpectedTwins", names, expected, kExpectedTwinsBackfill);
    INFO("failures:" << join(failures));
    INFO("To fix: add a row to tests/unit/server/test_expected_twins.hpp pinning the tool's "
         "securable and operation against its REST twin's gate. A stale backfill entry must be "
         "deleted from kExpectedTwinsBackfill.");
    CHECK(failures.empty());
}

TEST_CASE("MCP twin completeness: the predicate is not vacuous", "[mcp][twin_completeness]") {
    const std::vector<std::string> names{"tool_a", "tool_b"};
    const std::set<std::string> none;

    SECTION("a tool missing from the present set is reported by name") {
        const auto failures = membership_failures("X", names, {"tool_a"}, none);
        REQUIRE(failures.size() == 1);
        CHECK(failures[0].find("tool_b") != std::string::npos);
    }
    SECTION("a complete set reports nothing") {
        CHECK(membership_failures("X", names, {"tool_a", "tool_b"}, none).empty());
    }
    SECTION("a backfill entry silences exactly its own miss") {
        CHECK(membership_failures("X", names, {"tool_a"}, {"tool_b"}).empty());
    }
    SECTION("a backfill entry that is no longer missing is stale") {
        const auto failures = membership_failures("X", names, {"tool_a", "tool_b"}, {"tool_b"});
        REQUIRE(failures.size() == 1);
        CHECK(failures[0].find("stale") != std::string::npos);
    }
    SECTION("a backfill entry naming no registry tool is stale") {
        const auto failures = membership_failures("X", names, {"tool_a", "tool_b"}, {"gone"});
        REQUIRE(failures.size() == 1);
        CHECK(failures[0].find("gone") != std::string::npos);
    }
    SECTION("a synthetic ledger missing one tool fails end to end") {
        yuzu::test::TempDir tmp("yuzu_test_twin_completeness_");
        fs::create_directories(tmp.path);
        const std::string rows =
            R"([{"capability_id":"a","mcp_twin":"tool_a"},{"capability_id":"n","mcp_twin":null}])";
        std::ofstream(tmp.path / "rows.json", std::ios::binary) << rows;
        const auto ledger = read_ledger_twins(tmp.path);
        CHECK(ledger.failures.empty());
        CHECK(ledger.files == 1);
        const auto failures = membership_failures("the ledger", names, ledger.names, none);
        REQUIRE(failures.size() == 1);
        CHECK(failures[0].find("tool_b") != std::string::npos);
    }
    SECTION("an unreadable ledger directory is a failure, not an empty pass") {
        yuzu::test::TempDir tmp("yuzu_test_twin_completeness_");
        const auto ledger = read_ledger_twins(tmp.path / "absent");
        CHECK_FALSE(ledger.failures.empty());
        CHECK(ledger.names.empty());
    }
}
