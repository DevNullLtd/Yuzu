/**
 * test_tar_retention_tiers_table.cpp — cross-checks the checked-in
 * docs/capability-registries/tar_retention_tiers.tsv against the live
 * capture_sources() registry.
 *
 * The server embeds that TSV (it does not link agent_core, where the real
 * registry lives) and publishes it on the data-retention API. This test IS
 * the drift catch: it fails when the table and the registry disagree in
 * EITHER direction (a row only one side has, or a kind/limit edited on one
 * side only).
 */

#include "tar_schema_registry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <tuple>
#include <vector>

namespace fs = std::filesystem;

using namespace yuzu::tar;

namespace {

using Row = std::tuple<std::string, std::string, std::string, std::int64_t>; // source, tier, kind, limit

/// Same lookup order as test_tar_capability_table.cpp's find_repo_file().
fs::path find_repo_file(const std::string& relative) {
    std::vector<fs::path> candidates;
    if (auto* src_root = std::getenv("MESON_SOURCE_ROOT"))
        candidates.emplace_back(fs::path{src_root} / relative);
    candidates.emplace_back(fs::path{relative});

    std::error_code ec;
    fs::path dir = fs::current_path(ec);
    for (int i = 0; !ec && i < 8 && !dir.empty(); ++i) {
        candidates.emplace_back(dir / relative);
        fs::path parent = dir.parent_path();
        if (parent == dir)
            break;
        dir = parent;
    }

    for (const auto& c : candidates) {
        std::error_code exist_ec;
        if (fs::exists(c, exist_ec) && !exist_ec)
            return fs::absolute(c, exist_ec);
    }
    return {};
}

std::string row_to_string(const Row& r) {
    std::ostringstream os;
    os << std::get<0>(r) << "/" << std::get<1>(r) << "/" << std::get<2>(r) << "/"
       << std::get<3>(r);
    return os.str();
}

} // namespace

TEST_CASE("tar_retention_tiers.tsv matches capture_sources() retention defaults",
          "[tar][capability][registries][retention]") {
    auto path = find_repo_file("docs/capability-registries/tar_retention_tiers.tsv");
    if (path.empty())
        FAIL("docs/capability-registries/tar_retention_tiers.tsv not found");

    std::ifstream f(path);
    REQUIRE(f.good());

    std::set<Row> table_rows;
    std::set<std::string> table_sources;
    std::string line;
    // Deliberately independent of server/core's parse_tar_retention_tiers: the tar
    // suite must not include server headers, and an independent reader cannot share
    // a parser bug.
    bool first = true;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        if (first) {
            first = false;
            continue; // header
        }
        std::vector<std::string> cells;
        std::size_t start = 0;
        while (true) {
            const auto tab = line.find('\t', start);
            if (tab == std::string::npos) {
                cells.push_back(line.substr(start));
                break;
            }
            cells.push_back(line.substr(start, tab - start));
            start = tab + 1;
        }
        REQUIRE(cells.size() == 4);
        table_rows.emplace(cells[0], cells[1], cells[2], std::stoll(cells[3]));
        table_sources.insert(cells[0]);
    }

    std::set<Row> code_rows;
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            code_rows.emplace(std::string{src.name}, std::string{g.suffix},
                              g.retention_type == RetentionType::kRowCount ? "rows" : "seconds",
                              g.retention_default);
        }
    }

    // Under-claim: a tier the registry declares but the table is missing.
    for (const auto& r : code_rows) {
        INFO("capture_sources() declares '" << row_to_string(r)
                                            << "' but the checked-in table does not");
        CHECK(table_rows.count(r) == 1);
    }
    // Over-claim: a row the table lists that the registry no longer has.
    for (const auto& r : table_rows) {
        INFO("the table claims '" << row_to_string(r)
                                  << "' but capture_sources() no longer declares it");
        CHECK(code_rows.count(r) == 1);
    }

    // Pin rows the retention surface leans on, so a lock-step edit still fails.
    CHECK(table_rows.count(Row{"process", "live", "rows", 100000}) == 1);
    CHECK(table_rows.count(Row{"perf", "live", "seconds", 604800}) == 1);
    CHECK(table_rows.count(Row{"process", "monthly", "seconds", 31536000}) == 1);
    CHECK(table_rows.count(Row{"netqual", "boot", "rows", 400}) == 1);
    CHECK(table_sources.size() == 17);
    CHECK(table_rows.size() == 37);
}
