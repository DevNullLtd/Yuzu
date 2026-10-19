// Every `mcp_twin` claim in the API-parity ledger (scripts/ci/api-parity/*.json)
// must name something the compiled MCP catalogue lists.
//
// scripts/ci/check-api-parity.py validates the same claims against a TEXT scan
// of mcp_server.cpp's kTools[] / kResources[], which counts a block-commented
// entry as a tool. This test resolves the claims against the compiled tables
// instead (tool_names_for_test() and resource_uris_for_test()), where a
// commented-out entry does not exist. The scan's refusal of a '#'-leading line
// inside a raw-string schema is a loud preflight failure and is not addressed
// here.
//
// This test runs in the unit suite; the preflight is the merge gate. It is
// stricter than the preflight on purpose:
//   - it checks a claim on a row of ANY status (the preflight checks only the
//     twinned* statuses), so a retire/exception row that still names a removed
//     tool must null its mcp_twin;
//   - an empty-string claim counts as a claim and fails on every row (the
//     preflight treats it as no twin: it skips it on a non-twinned row, errors
//     on twinned and twinned-mcp-only, and accepts it on twinned-rest-only).
// It does not check row shape, the status and twin requirements, the baselines,
// or which domain files exist beyond a minimum count. A ledger file that is an
// empty array is accepted, because the preflight's procedure for a new domain
// starts its file as [].
//
// Limit: this checks catalogue MEMBERSHIP only. "In the catalogue" means in the
// compiled kTools[] / kResources[], which tools/list and resources/list return
// in full (the --mcp-* runtime gates act at call time). It does not prove the
// tool's handler is equivalent to the REST route it is claimed to twin, that the
// two enforce the same authorization, or that a dispatch branch exists.
//
// The ledger directory arrives as YUZU_API_PARITY_LEDGER_DIR (tests/meson.build).
// A missing, unreadable or malformed ledger, or one that yields too few files or
// no rows or claims, FAILS the test: it must never pass vacuously.

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

// Same prefix the checker uses for a fixed kResources[] claim
// (RESOURCE_TWIN_PREFIX in scripts/ci/check-api-parity.py).
constexpr std::string_view kResourcePrefix = "resource:";

// Number of domain files the preflight declares (DOMAINS in check-api-parity.py).
// A floor, not an exact pin (the preflight enforces the exact set): a deleted or
// renamed ledger file silently drops its claims otherwise. Move it together with
// DOMAINS: raise it when a domain file is added, and lower it only when a domain
// is deliberately removed from DOMAINS.
constexpr std::size_t kMinLedgerFiles = 24;

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
/// (any row status) against the supplied catalogue. Every filesystem call uses
/// its error_code overload and the JSON parse does not throw, so every problem
/// becomes a failure line (apart from path-to-string conversion and allocation).
/// The extension compare is case-sensitive, like the preflight's `*.json` glob
/// on POSIX (Python's glob matches case-insensitively on Windows).
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
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        if (it->path().extension() != ".json")
            continue;
        std::error_code type_ec;
        const bool regular = it->is_regular_file(type_ec);
        if (type_ec || !regular) {
            scan.failures.push_back(it->path().filename().string() +
                                    ": ledger entry is not a readable regular file");
            continue;
        }
        files.push_back(it->path());
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
    INFO("To fix: edit the ledger row in scripts/ci/api-parity/*.json, or restore the tool or "
         "resource in kTools[] / kResources[]. If the files floor tripped, a ledger file "
         "is missing or a domain was removed: move kMinLedgerFiles together with DOMAINS in "
         "check-api-parity.py. This test is stricter than the preflight: it also checks "
         "non-twinned rows and empty claims.");
    // The failure lines are asserted first so a floor trip (for example a renamed
    // mcp_twin key) is reported with its cause rather than hiding it.
    CHECK(scan.failures.empty());
    // Sanity floors: an empty, truncated or wrongly-pointed directory must not pass.
    REQUIRE(scan.files >= kMinLedgerFiles);
    REQUIRE(scan.rows > 0);
    REQUIRE(scan.claims > 0);
}

TEST_CASE("API parity ledger scan: reports unusable input", "[mcp][parity]") {
    const std::set<std::string> tools = {"real_tool"};
    const std::set<std::string> resources = {"yuzu://real"};

    SECTION("missing directory fails") {
        yuzu::test::TempDir tmp("yuzu_test_parity_ledger_");
        const auto scan = scan_ledger(tmp.path / "absent", tools, resources);
        CHECK_FALSE(scan.failures.empty());
    }
    SECTION("empty directory yields no files, rows or claims (the first case's floors reject it)") {
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
    SECTION("an empty array is accepted (a new domain's file starts as [])") {
        yuzu::test::TempDir tmp("yuzu_test_parity_ledger_");
        fs::create_directories(tmp.path);
        write_file(tmp.path / "new-domain.json", "[]");
        const auto scan = scan_ledger(tmp.path, tools, resources);
        CHECK(scan.failures.empty());
        CHECK(scan.files == 1);
        CHECK(scan.rows == 0);
    }
    SECTION("a .json entry that is not a regular file fails") {
        yuzu::test::TempDir tmp("yuzu_test_parity_ledger_");
        fs::create_directories(tmp.path / "dir.json");
        const auto scan = scan_ledger(tmp.path, tools, resources);
        REQUIRE(scan.failures.size() == 1);
        CHECK(scan.failures[0].find("dir.json") != std::string::npos);
    }
    SECTION("an empty-string claim is a claim and fails") {
        yuzu::test::TempDir tmp("yuzu_test_parity_ledger_");
        fs::create_directories(tmp.path);
        write_file(tmp.path / "rows.json", R"([{"capability_id":"empty.twin","mcp_twin":""}])");
        const auto scan = scan_ledger(tmp.path, tools, resources);
        CHECK(scan.claims == 1);
        REQUIRE(scan.failures.size() == 1);
        CHECK(scan.failures[0].find("empty.twin") != std::string::npos);
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
