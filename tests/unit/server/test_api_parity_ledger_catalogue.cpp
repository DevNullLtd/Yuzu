// Every `mcp_twin` claim in the API-parity ledger (scripts/ci/api-parity/*.json)
// must name something the compiled MCP catalogue actually serves.
//
// scripts/ci/check-api-parity.py validates the same claims against a TEXT scan
// of mcp_server.cpp's kTools[] / kResources[], which cannot see a block-commented
// entry or a '#'-leading line inside a raw-string schema. This test resolves the
// claims against the compiled tables instead (tool_names_for_test() and
// resource_uris_for_test()).
//
// Limit: this checks catalogue MEMBERSHIP only. It does not prove the tool's
// handler is equivalent to the REST route it is claimed to twin, nor that the
// two enforce the same authorization.
//
// The ledger directory arrives as YUZU_API_PARITY_LEDGER_DIR (tests/meson.build).
// A missing, unreadable or malformed ledger, or one that yields no rows or no
// claims, FAILS the test: it must never pass vacuously.

#include "mcp_server_testonly.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#ifndef YUZU_API_PARITY_LEDGER_DIR
#error "YUZU_API_PARITY_LEDGER_DIR must be injected by tests/meson.build (meson.project_source_root() / 'scripts' / 'ci' / 'api-parity') - see the server_test_exe cpp_args block."
#endif

namespace fs = std::filesystem;
using yuzu::server::mcp::resource_uris_for_test;
using yuzu::server::mcp::tool_names_for_test;

namespace {

// Same prefix the checker uses for a fixed kResources[] claim.
constexpr std::string_view kResourcePrefix = "resource:";

struct LedgerScan {
    std::size_t files{0};
    std::size_t rows{0};
    std::size_t claims{0};              // rows with a non-null mcp_twin
    std::vector<std::string> failures;  // one human-readable line each
};

std::string row_label(const nlohmann::json& row, const std::string& file) {
    std::string id = "<no capability_id>";
    if (row.is_object() && row.contains("capability_id") && row["capability_id"].is_string())
        id = row["capability_id"].get<std::string>();
    return file + ": " + id;
}

/// Reads every *.json file under `dir` and checks each non-null mcp_twin
/// (any row status) against the supplied catalogue. Never throws: every
/// problem becomes a failure line.
LedgerScan scan_ledger(const fs::path& dir, const std::set<std::string>& tools,
                       const std::set<std::string>& resources) {
    LedgerScan scan;

    std::error_code ec;
    if (!fs::is_directory(dir, ec)) {
        scan.failures.push_back("ledger directory is missing or not a directory: " +
                                dir.generic_string());
        return scan;
    }

    std::vector<fs::path> files;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json")
            files.push_back(entry.path());
    }
    if (ec) {
        scan.failures.push_back("cannot list ledger directory " + dir.generic_string() + ": " +
                                ec.message());
        return scan;
    }
    std::sort(files.begin(), files.end());

    for (const auto& path : files) {
        const std::string file = path.filename().string();
        ++scan.files;

        std::ifstream in(path, std::ios::binary);
        if (!in) {
            scan.failures.push_back(file + ": cannot open ledger file");
            continue;
        }
        nlohmann::json doc = nlohmann::json::parse(in, nullptr, /*allow_exceptions=*/false);
        if (doc.is_discarded() || !doc.is_array()) {
            scan.failures.push_back(file + ": not a JSON array of ledger rows");
            continue;
        }

        for (const auto& row : doc) {
            ++scan.rows;
            if (!row.is_object() || !row.contains("mcp_twin")) {
                scan.failures.push_back(row_label(row, file) +
                                        ": row is not an object with an mcp_twin field");
                continue;
            }
            const auto& twin = row["mcp_twin"];
            if (twin.is_null())
                continue;
            if (!twin.is_string()) {
                scan.failures.push_back(row_label(row, file) +
                                        ": mcp_twin is neither null nor a string");
                continue;
            }

            ++scan.claims;
            const std::string claim = twin.get<std::string>();
            if (claim.starts_with(kResourcePrefix)) {
                const std::string uri = claim.substr(kResourcePrefix.size());
                if (!resources.contains(uri))
                    scan.failures.push_back(row_label(row, file) + ": mcp_twin '" + claim +
                                            "' is not in the compiled kResources[]");
            } else if (!tools.contains(claim)) {
                scan.failures.push_back(row_label(row, file) + ": mcp_twin '" + claim +
                                        "' is not in the compiled kTools[]");
            }
        }
    }
    return scan;
}

std::set<std::string> to_set(const std::vector<std::string>& v) {
    return {v.begin(), v.end()};
}

std::string join(const std::vector<std::string>& lines) {
    std::string out;
    for (const auto& l : lines)
        out += "\n  " + l;
    return out;
}

void write_file(const fs::path& p, const std::string& body) {
    std::ofstream(p, std::ios::binary) << body;
}

} // namespace

TEST_CASE("API parity ledger: every mcp_twin claim is in the compiled MCP catalogue",
          "[mcp][parity]") {
    const auto tools = to_set(tool_names_for_test());
    const auto resources = to_set(resource_uris_for_test());
    // The catalogue itself must be non-empty, or every claim would fail for the
    // wrong reason (and an accessor regression would read as ledger rot).
    REQUIRE_FALSE(tools.empty());
    REQUIRE_FALSE(resources.empty());

    const auto scan = scan_ledger(YUZU_API_PARITY_LEDGER_DIR, tools, resources);

    INFO("ledger dir: " << YUZU_API_PARITY_LEDGER_DIR);
    INFO("files=" << scan.files << " rows=" << scan.rows << " claims=" << scan.claims);
    INFO("failures:" << join(scan.failures));
    // Sanity floors: an empty or wrongly-pointed directory must not pass.
    REQUIRE(scan.files > 0);
    REQUIRE(scan.rows > 0);
    REQUIRE(scan.claims > 0);

    CHECK(scan.failures.empty());
}

TEST_CASE("API parity ledger scan: rejects unusable input instead of passing vacuously",
          "[mcp][parity]") {
    const std::set<std::string> tools = {"real_tool"};
    const std::set<std::string> resources = {"yuzu://real"};

    SECTION("missing directory fails") {
        yuzu::test::TempDir tmp("yuzu_test_parity_ledger_");
        const auto scan = scan_ledger(tmp.path / "absent", tools, resources);
        CHECK_FALSE(scan.failures.empty());
    }
    SECTION("empty directory yields no rows and no claims") {
        yuzu::test::TempDir tmp("yuzu_test_parity_ledger_");
        fs::create_directories(tmp.path);
        const auto scan = scan_ledger(tmp.path, tools, resources);
        CHECK(scan.files == 0);
        CHECK(scan.rows == 0);
        CHECK(scan.claims == 0);
    }
    SECTION("malformed JSON fails") {
        yuzu::test::TempDir tmp("yuzu_test_parity_ledger_");
        fs::create_directories(tmp.path);
        write_file(tmp.path / "bad.json", "[{not json");
        const auto scan = scan_ledger(tmp.path, tools, resources);
        CHECK(scan.failures.size() == 1);
    }
    SECTION("a row without an mcp_twin field fails") {
        yuzu::test::TempDir tmp("yuzu_test_parity_ledger_");
        fs::create_directories(tmp.path);
        write_file(tmp.path / "rows.json", R"([{"capability_id":"no.twin.field"}])");
        const auto scan = scan_ledger(tmp.path, tools, resources);
        REQUIRE(scan.failures.size() == 1);
        CHECK(scan.failures[0].find("no.twin.field") != std::string::npos);
    }
    SECTION("a non-string mcp_twin fails") {
        yuzu::test::TempDir tmp("yuzu_test_parity_ledger_");
        fs::create_directories(tmp.path);
        write_file(tmp.path / "rows.json", R"([{"capability_id":"obj.twin","mcp_twin":{"a":1}}])");
        const auto scan = scan_ledger(tmp.path, tools, resources);
        REQUIRE(scan.failures.size() == 1);
        CHECK(scan.failures[0].find("obj.twin") != std::string::npos);
    }
    SECTION("unknown tool and unknown resource are reported by capability_id and claim") {
        yuzu::test::TempDir tmp("yuzu_test_parity_ledger_");
        fs::create_directories(tmp.path);
        write_file(tmp.path / "rows.json",
                   R"([{"capability_id":"ok.tool","mcp_twin":"real_tool"},
                       {"capability_id":"ok.res","mcp_twin":"resource:yuzu://real"},
                       {"capability_id":"null.twin","mcp_twin":null},
                       {"capability_id":"bad.tool","mcp_twin":"gone_tool","status":"retire"},
                       {"capability_id":"bad.res","mcp_twin":"resource:yuzu://gone"}])");
        const auto scan = scan_ledger(tmp.path, tools, resources);
        CHECK(scan.rows == 5);
        CHECK(scan.claims == 4);
        REQUIRE(scan.failures.size() == 2);
        CHECK(scan.failures[0].find("bad.tool") != std::string::npos);
        CHECK(scan.failures[0].find("gone_tool") != std::string::npos);
        CHECK(scan.failures[1].find("bad.res") != std::string::npos);
        CHECK(scan.failures[1].find("yuzu://gone") != std::string::npos);
    }
}
