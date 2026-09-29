/**
 * test_dex_obs_table.cpp — cross-checks the checked-in
 * docs/capability-registries/dex_obs_platforms.tsv against the live
 * dex_obs_platforms() coverage map (#2204 point 4).
 *
 * capmatrix-gen (tools/capmatrix-gen) dlopens agent plugins and must never
 * link server_core — dex_obs_platforms() (server/core/src/dex_routes.cpp)
 * lives inside exactly that library, and server_core transitively drags
 * libpq/grpc besides — so capmatrix-gen's optional --registries mode reads
 * a small checked-in TSV mirror instead. That mirror is a second,
 * hand-authored copy of every obs_type's per-OS coverage claim and can
 * silently drift from dex_obs_platforms() the moment a signal is added,
 * removed, or moved between platforms without updating the TSV in the same
 * change. This test IS that drift catch: it fails the moment the table and
 * dex_obs_platforms() disagree on ANY obs_type/platform pair — demonstrated
 * concretely below, where each per-platform loop would fail if a single
 * `true`/`false` cell in the table were hand-flipped out of sync with the
 * code, or if an obs_type present in the catalogue were missing from the
 * table entirely.
 */

#include "dex_routes.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

using namespace yuzu::server;

namespace {

struct TableRow {
    bool windows{false};
    bool linux{false};
    bool macos{false};
};

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

bool parse_bool(const std::string& s) {
    return s == "true";
}

} // namespace

TEST_CASE("dex_obs_platforms.tsv matches dex_obs_platforms()", "[dex][capability][registries]") {
    auto path = find_repo_file("docs/capability-registries/dex_obs_platforms.tsv");
    if (path.empty())
        FAIL("docs/capability-registries/dex_obs_platforms.tsv not found — capmatrix-gen's "
             "--registries mode has nothing to read");

    std::ifstream f(path);
    REQUIRE(f.good());

    std::map<std::string, TableRow> table;
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
        table.emplace(cells[0], TableRow{parse_bool(cells[1]), parse_bool(cells[2]),
                                         parse_bool(cells[3])});
    }

    auto claims = [](const std::string& obs_type, const char* os) {
        const auto p = dex_obs_platforms(obs_type);
        return std::find(p.begin(), p.end(), os) != p.end();
    };

    std::size_t catalogued = 0;
    for (const auto& g : dex_signal_groups()) {
        for (const auto& t : g.types) {
            ++catalogued;
            auto it = table.find(t);
            {
                INFO("obs_type '" << t << "' is catalogued but missing from the checked-in table");
                CHECK(it != table.end());
            }
            if (it == table.end())
                continue;

            const auto& row = it->second;
            INFO("obs_type '" << t << "': table.windows=" << row.windows
                              << " dex_obs_platforms(windows)=" << claims(t, "windows"));
            CHECK(row.windows == claims(t, "windows"));
            INFO("obs_type '" << t << "': table.linux=" << row.linux
                              << " dex_obs_platforms(linux)=" << claims(t, "linux"));
            CHECK(row.linux == claims(t, "linux"));
            INFO("obs_type '" << t << "': table.macos=" << row.macos
                              << " dex_obs_platforms(macos)=" << claims(t, "macos"));
            CHECK(row.macos == claims(t, "macos"));
        }
    }

    // Over-claim: a stale row for an obs_type no longer in the catalogue.
    INFO("checked-in table row count must match the catalogued obs_type count");
    CHECK(table.size() == catalogued);
}
