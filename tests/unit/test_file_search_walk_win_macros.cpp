/**
 * test_file_search_walk_win_macros.cpp -- the #8272 acceptance for the Windows leg: the ordered walker and the
 * search driver compile and run in a translation unit where <windows.h>-style `min` and `max` are defined as
 * FUNCTION-LIKE MACROS (what <windows.h> does without NOMINMAX). An unparenthesised `std::min(a, b)` or
 * `std::max(a, b)` in either header expands the macro inside the qualified name and fails the build, and that
 * is the failure this TU exists to catch: component_walk.hpp:670 was one.
 *
 * The macros are defined only on Windows, before the product headers, and removed before the test framework
 * and the in-memory tree fixture are included (they are not under test). Elsewhere the TU is the same walk
 * with no macros, so it is never empty.
 *
 * MUTATION NOTE: writing `std::min(` back at the walk's entry cap fails the Windows build of this TU.
 */
#if defined(_WIN32)
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#include "component_walk.hpp"
#include "file_search_driver.hpp"

#if defined(_WIN32)
#undef min
#undef max
#endif

#include <catch2/catch_test_macros.hpp>

#include "component_fixture_tree.hpp"

#include <chrono>
#include <string>
#include <vector>

namespace ci = yuzu::component_inventory;
using ci::fixture::MemTree;
namespace fsr = yuzu::shared::file_search;

TEST_CASE("file_search walk: the walker and the driver compile with min and max defined as macros, and one walk completes",
          "[file_search][file_search_win_macros]") {
    MemTree tree;
    tree.add_file("/r/a.txt", "");
    tree.add_file("/r/sub/b.txt", "");
    const ci::FsOps ops = tree.ops();
    std::vector<std::string> visited;
    const auto result = ci::walk_ordered(
        "/r", fsr::Position{}, ci::WalkLimits{}, ops, tree.clock + std::chrono::hours{1},
        [&](const std::string& dir, const ci::DirEntry& e, std::uint64_t) {
            visited.push_back(ci::walk_detail::join(dir, e.name));
            return true;
        });
    CHECK(result.stop == ci::Stop::complete);
    CHECK(visited == std::vector<std::string>{"/r/a.txt", "/r/sub", "/r/sub/b.txt"});
}
