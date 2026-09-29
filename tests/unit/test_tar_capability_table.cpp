/**
 * test_tar_capability_table.cpp — cross-checks the checked-in
 * docs/capability-registries/tar_capture_sources.tsv against the live
 * capture_sources() registry (#2204 point 4).
 *
 * capmatrix-gen (tools/capmatrix-gen) dlopens agent plugins and must never
 * link agent_core — TAR's real `capture_sources()` registry (build_sources()
 * in tar_schema_registry.cpp) lives inside exactly that library — so
 * capmatrix-gen's optional --registries mode reads a small checked-in TSV
 * mirror instead. That mirror is a second, hand-authored copy of every
 * (source, os, status, mechanism) row and can silently drift from the real
 * registry the moment a source's OsSupport changes and the TSV isn't
 * updated in the same change. This test IS the drift catch: it fails the
 * moment the table and capture_sources() disagree in EITHER direction —
 * demonstrated concretely by the two loops below, each of which would fail
 * if, say, a row were deleted from ONE side only (the table claiming a row
 * capture_sources() no longer has, or vice versa) or a `status`/`mechanism`
 * value were hand-edited in the table without touching the registry.
 */

#include "tar_schema_registry.hpp"

#include <catch2/catch_test_macros.hpp>

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

using Row = std::tuple<std::string, std::string, std::string, std::string>; // source, os, status, mechanism

/// See test_capability_registry_tables.cpp's find_repo_file() for why this
/// tries $MESON_SOURCE_ROOT, then CWD, then a bounded walk-up from CWD.
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
    os << std::get<0>(r) << "/" << std::get<1>(r) << "/" << std::get<2>(r) << "/" << std::get<3>(r);
    return os.str();
}

} // namespace

TEST_CASE("tar_capture_sources.tsv matches capture_sources()", "[tar][capability][registries]") {
    auto path = find_repo_file("docs/capability-registries/tar_capture_sources.tsv");
    if (path.empty())
        FAIL("docs/capability-registries/tar_capture_sources.tsv not found — capmatrix-gen's "
             "--registries mode has nothing to read");

    std::ifstream f(path);
    REQUIRE(f.good());

    std::set<Row> table_rows;
    std::string line;
    bool first = true;
    while (std::getline(f, line)) {
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
        table_rows.emplace(cells[0], cells[1], cells[2], cells[3]);
    }

    std::set<Row> code_rows;
    for (const auto& src : capture_sources()) {
        for (const auto& os : src.os_support) {
            code_rows.emplace(std::string{src.name}, std::string{os.os},
                              std::string{support_level_name(os.status)},
                              std::string{os.capture_method});
        }
    }

    // Under-claim: a row capture_sources() declares but the table is missing.
    for (const auto& r : code_rows) {
        INFO("capture_sources() declares '" << row_to_string(r)
                                            << "' but the checked-in table does not");
        CHECK(table_rows.count(r) == 1);
    }
    // Over-claim: a row the table lists that capture_sources() no longer has
    // (a stale entry, or a status/mechanism hand-edited out of sync).
    for (const auto& r : table_rows) {
        INFO("the table claims '" << row_to_string(r)
                                  << "' but capture_sources() no longer declares it");
        CHECK(code_rows.count(r) == 1);
    }

    // Wave-2 registry reconciliation: pin the three rows this package
    // flipped from planned to their real status, so a regression back
    // toward "planned" fails here even if both sides were edited in
    // lockstep (which the drift checks above would not catch).
    CHECK(table_rows.count(Row{"arp", "linux", "supported", "procfs"}) == 1);
    CHECK(table_rows.count(Row{"arp", "macos", "constrained", "route_sysctl"}) == 1);
    CHECK(table_rows.count(Row{"mapdrive", "macos", "constrained", "getfsstat"}) == 1);
}
