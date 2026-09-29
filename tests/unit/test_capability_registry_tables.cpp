/**
 * test_capability_registry_tables.cpp — cross-checks the checked-in
 * docs/capability-registries/*.tsv tables for the agent-side capability
 * registries — the two header-only Guardian arrays PLUS Spark's mechanism
 * factories — against their live C++ source (#2204 point 4).
 *
 * capmatrix-gen (tools/capmatrix-gen) dlopens agent plugins, so it must
 * never link agent_core — that is exactly the library these registries (and
 * the plugins themselves) are built against, and linking it into the host
 * tool would be a layering inversion. So capmatrix-gen's optional
 * --registries mode reads small checked-in TSV mirrors instead of including
 * guard_registry.hpp/guard_service.hpp/spark_mechanism.hpp directly. Each
 * mirror can silently drift from the source it copies (a hive added to
 * kHives but never added to registry_hives.tsv, a stale entry left behind
 * after a header change, a mechanism factory's platform gate changing
 * without the table following) with nothing catching it — this suite IS
 * that catch. Every TEST_CASE below fails the moment its checked-in table
 * and its C++ source disagree in EITHER direction: over-claim (the table
 * lists something the source doesn't declare) and under-claim (the source
 * declares something the table is missing) are both checked, so neither
 * kind of drift can land unnoticed.
 */

#include <yuzu/agent/guard_registry.hpp>
#include <yuzu/agent/guard_service.hpp>

#include "spark_mechanism.hpp" // agent_core-private header; same include path test_spark_mechanism.cpp uses

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace {

/// Locates a file by its repo-relative path without any build-time-injected
/// root: tries $MESON_SOURCE_ROOT (set by `meson test`), then CWD directly
/// (scripts/run-tests.sh's standing convention — CWD is the source root),
/// then walks up from CWD as a last-resort fallback for any other invocation
/// shape. Mirrors test_capability_descriptor.cpp's find_abi3_fixture()
/// multi-candidate approach, applied to a source-tree doc instead of a
/// build-tree artifact.
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

/// Reads a single-column TSV (header row + one value per line) into a set,
/// skipping the header.
std::set<std::string> read_single_column(const fs::path& p) {
    std::ifstream f(p);
    REQUIRE(f.good());
    std::set<std::string> values;
    std::string line;
    bool first = true;
    while (std::getline(f, line)) {
        if (line.empty())
            continue;
        if (first) {
            first = false;
            continue;
        }
        values.insert(line);
    }
    return values;
}

} // namespace

TEST_CASE("registry_hives.tsv matches registry_support::kHives", "[capability][registries]") {
    auto path = find_repo_file("docs/capability-registries/registry_hives.tsv");
    if (path.empty())
        FAIL("docs/capability-registries/registry_hives.tsv not found — capmatrix-gen's "
             "--registries mode has nothing to read");

    auto table = read_single_column(path);
    std::set<std::string> header;
    for (auto hive : yuzu::agent::registry_support::kHives)
        header.emplace(hive);

    // Under-claim: a hive the header declares but the table forgot.
    for (const auto& h : header) {
        INFO("registry_support::kHives declares '" << h << "' but the checked-in table does not");
        CHECK(table.count(h) == 1);
    }
    // Over-claim: a hive the table lists but the header no longer declares
    // (e.g. left behind after a kHives entry was removed).
    for (const auto& h : table) {
        INFO("the table claims hive '" << h
                                       << "' but registry_support::kHives no longer declares it");
        CHECK(header.count(h) == 1);
    }
}

TEST_CASE("service_states.tsv matches service_support::kStates", "[capability][registries]") {
    auto path = find_repo_file("docs/capability-registries/service_states.tsv");
    if (path.empty())
        FAIL("docs/capability-registries/service_states.tsv not found — capmatrix-gen's "
             "--registries mode has nothing to read");

    auto table = read_single_column(path);
    std::set<std::string> header;
    for (auto state : yuzu::agent::service_support::kStates)
        header.emplace(state);

    for (const auto& s : header) {
        INFO("service_support::kStates declares '" << s << "' but the checked-in table does not");
        CHECK(table.count(s) == 1);
    }
    for (const auto& s : table) {
        INFO("the table claims state '" << s
                                        << "' but service_support::kStates no longer declares it");
        CHECK(header.count(s) == 1);
    }
}

// Spark's factories are the one non-header-only registry that fits this
// suite (agents/core/src/spark_*.cpp, same library the two registries above
// live in) — capture_sources() and dex_obs_platforms() get their own suite
// homes (test_tar_capability_table.cpp, test_dex_obs_table.cpp) since they
// live in the tar plugin and server_core respectively.
TEST_CASE("spark_mechanisms.tsv matches the platform mechanism factories",
         "[capability][registries][spark]") {
    using namespace yuzu::agent;

    auto path = find_repo_file("docs/capability-registries/spark_mechanisms.tsv");
    if (path.empty())
        FAIL("docs/capability-registries/spark_mechanisms.tsv not found — capmatrix-gen's "
             "--registries mode has nothing to read");

    std::ifstream f(path);
    REQUIRE(f.good());

    // mechanism -> os -> status
    std::map<std::string, std::map<std::string, std::string>> table;
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
        REQUIRE(cells.size() == 4); // mechanism, os, status, notes
        table[cells[0]][cells[1]] = cells[2];
    }

    // Demonstrates the failure mode: this cross-checks the table's per-OS
    // status against the REAL factory's nullness on THIS build's platform
    // (mirrors test_spark_mechanism.cpp's own #ifdef matrix, the established
    // source of truth for what each factory returns where) — flipping either
    // side (a table status edited without touching the #ifdef, or a factory's
    // platform gate changed without updating the table) fails a CHECK below.
#if defined(_WIN32)
    CHECK(table.at("file").at("windows") != "unsupported");
    CHECK(table.at("registry").at("windows") != "unsupported");
    CHECK(table.at("service").at("windows") != "unsupported");
    CHECK(make_file_mechanism() != nullptr);
    CHECK(make_registry_mechanism() != nullptr);
    CHECK(make_service_mechanism() != nullptr);
#elif defined(__APPLE__)
    CHECK(table.at("file").at("macos") == "unsupported");
    CHECK(table.at("registry").at("macos") == "unsupported");
    CHECK(table.at("service").at("macos") == "unsupported");
    CHECK(make_file_mechanism() == nullptr);
    CHECK(make_registry_mechanism() == nullptr);
    CHECK(make_service_mechanism() == nullptr);
#elif defined(__linux__)
    CHECK(table.at("file").at("linux") == "unsupported");
    CHECK(table.at("registry").at("linux") == "unsupported");
    CHECK(make_file_mechanism() == nullptr);
    CHECK(make_registry_mechanism() == nullptr);
#if defined(YUZU_HAVE_LIBSYSTEMD)
    CHECK(table.at("service").at("linux") != "unsupported");
    CHECK(make_service_mechanism() != nullptr);
#else
    // The table's "constrained" (not "unsupported") is a per-OS capability
    // claim; a Linux build without libsystemd is a BUILD-option gap on top
    // of that, not a platform gap — the two are deliberately independent
    // here (see the table's notes column for this exact caveat).
    CHECK(table.at("service").at("linux") != "unsupported");
    CHECK(make_service_mechanism() == nullptr);
#endif
#else
    SUCCEED("unrecognized platform — nothing in spark_mechanisms.tsv to cross-check here");
#endif
}
