/**
 * test_component_pkg_scan.cpp -- tests for the component_inventory `python` and `node` actions
 * (agents/plugins/component_inventory/src/component_pkg_scan.hpp). Driven over an in-memory tree and a
 * fake clock (component_fixture_tree.hpp); nothing here touches the host. The roots are pinned with an
 * injected lister (POSIX only: the root functions live in the POSIX leg).
 *
 * MUTATION NOTES (each assertion below FAILS if the named wiring is removed):
 *  - python skip_dir: not consulting it lists a package's source directory (entries and `listed`).
 *  - owner shape: not dropping a METADATA outside a dist-info emits a row for it and opens it.
 *  - node prune: dropping node_policy().skip_dir lists a package's `src` and nesting 9.
 *  - read caps: reading more than 16 KiB / 64 KiB + 1 fails the reads assertions.
 *  - changed file: dropping the unchanged() check fails the archive_changed case.
 *  - truncated parent listing: dropping `|| lr.truncated` in make_child_lister fails the cut-listing roots case.
 *  - network-mount child: dropping Type::network_mount from make_child_lister fails the live-lister case.
 *  - dispatch: not clearing dirs_excluded puts `package_tree_skipped` on the status row; not calling
 *    on_pruned fails the logged-once case; walking on an unreadable table fails the guard case.
 */
#include <catch2/catch_test_macros.hpp>

#include "component_fixture_tree.hpp"
#include "component_pkg_scan.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include "component_legs.hpp"
#endif

using namespace yuzu::component_inventory;
using namespace yuzu::component_inventory::fixture;
using namespace std::chrono_literals;

namespace {

struct FakeTargets {
    std::vector<std::string> roots{"/r"};
    bool mount_table_unreadable{false};
    std::size_t roots_link_skipped{0};
    std::size_t roots_network_skipped{0};
};

/// Records what the dispatch reports as pruned.
struct Pruned {
    std::vector<std::pair<std::string, std::size_t>> calls;
    void operator()(std::string_view action, std::size_t n) { calls.emplace_back(std::string(action), n); }
};

constexpr const char* kPyMeta = "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n\nbody";

ScanResult py(MemTree& tree, const WalkLimits& limits = python_limits(),
              const std::vector<std::string>& roots = {"/r"}) {
    const FsOps fs = tree.ops();
    return scan_python(roots, limits, fs);
}

ScanResult nd(MemTree& tree, const WalkLimits& limits = WalkLimits{},
              const std::vector<std::string>& roots = {"/r"}) {
    const FsOps fs = tree.ops();
    return scan_node(roots, limits, fs);
}

std::vector<std::string> paths_of(const ScanResult& r) {
    std::vector<std::string> out;
    for (const auto& row : r.rows)
        out.push_back(row.path);
    std::ranges::sort(out);
    return out;
}

bool was_listed(const MemTree& tree, const std::string& dir) {
    return std::ranges::find(tree.listed, dir) != tree.listed.end();
}

std::string pkg_json(std::string_view name, std::string_view version) {
    return "{\"name\":\"" + std::string(name) + "\",\"version\":\"" + std::string(version) + "\"}";
}

} // namespace

// ---- python ----

TEST_CASE("python scan: a dist-info METADATA is one row with the documented wire shape",
          "[runtime][component_pkg_scan][component_inventory]") {
    MemTree tree;
    const std::string meta = "/r/site-packages/requests-2.31.0.dist-info/METADATA";
    tree.add_file(meta, kPyMeta);
    tree.mtimes[meta] = 1700000123;
    const auto r = py(tree);

    CHECK(r.stop == Stop::complete);
    REQUIRE(r.rows.size() == 1);
    CHECK(r.rows[0].kind == "python");
    CHECK(format_component_row(r.rows[0]) ==
          "comp|python|requests|2.31.0|metadata|" + meta + "|" + std::to_string(std::string(kPyMeta).size()) +
              "|1700000123|site-packages");
    CHECK(tree.total_opens == 1); // one open per candidate
    REQUIRE(tree.reads.size() == 1); // and one read through it
}

TEST_CASE("python scan: package source directories beside a dist-info are never listed",
          "[runtime][component_pkg_scan][component_inventory]") {
    MemTree tree;
    tree.add_file("/r/site-packages/requests-2.31.0.dist-info/METADATA", kPyMeta);
    tree.add_file("/r/site-packages/requests/__init__.py", "x");
    tree.add_file("/r/dist-packages/six/six.py", "x");
    tree.add_file("/r/dist-packages/six-1.16.0.egg-info/PKG-INFO", "Name: six\nVersion: 1.16.0\n");
    const auto r = py(tree);

    CHECK(r.stop == Stop::complete);
    CHECK(paths_of(r) == std::vector<std::string>{"/r/dist-packages/six-1.16.0.egg-info/PKG-INFO",
                                                  "/r/site-packages/requests-2.31.0.dist-info/METADATA"});
    CHECK_FALSE(was_listed(tree, "/r/site-packages/requests"));
    CHECK_FALSE(was_listed(tree, "/r/dist-packages/six"));
    CHECK(r.stats.dirs_excluded == 2); // counted by the walk, as its contract requires
    // /r: 2 directories; site-packages: requests, dist-info; dist-packages: six, egg-info;
    // the two metadata directories: 1 file each.
    CHECK(r.stats.entries == 8);
}

TEST_CASE("python scan: a METADATA outside a dist-info directory is no row and is never opened",
          "[runtime][component_pkg_scan][component_inventory]") {
    MemTree tree;
    tree.add_file("/r/METADATA", kPyMeta);
    tree.add_file("/r/stray/METADATA", kPyMeta);
    tree.add_file("/r/stray/PKG-INFO", kPyMeta); // PKG-INFO needs an .egg-info parent
    tree.add_file("/r/site-packages/x.dist-info/PKG-INFO", kPyMeta); // and METADATA a .dist-info one
    const auto r = py(tree);
    CHECK(r.rows.empty());
    CHECK(r.stop == Stop::complete);
    CHECK(tree.total_opens == 0);
}

TEST_CASE("python scan: egg-info forms and an unreadable file are rows, never a constraint",
          "[runtime][component_pkg_scan][component_inventory]") {
    MemTree tree;
    tree.add_file("/r/site-packages/legacy-0.9.egg-info", "Name: Legacy\nVersion: 0.9.1\n"); // single file
    tree.add_file("/r/site-packages/gone-1.0.dist-info/METADATA", kPyMeta);
    tree.unopenable.insert("/r/site-packages/gone-1.0.dist-info/METADATA");
    tree.add_file("/r/site-packages/weird.dist-info/METADATA", "no headers here");
    const auto r = py(tree);

    CHECK(r.stop == Stop::complete);
    REQUIRE(r.rows.size() == 3);
    std::map<std::string, Row> by_path;
    for (const auto& row : r.rows)
        by_path[row.path] = row;
    const auto& legacy = by_path.at("/r/site-packages/legacy-0.9.egg-info");
    CHECK(legacy.name == "Legacy");
    CHECK(legacy.version == "0.9.1");
    CHECK(legacy.version_source == "metadata");
    const auto& gone = by_path.at("/r/site-packages/gone-1.0.dist-info/METADATA");
    CHECK(gone.name == "gone"); // not openable: the directory name speaks, the size is unknown
    CHECK(gone.version == "1.0");
    CHECK(gone.version_source == "filename");
    CHECK(gone.size == 0);
    const auto& weird = by_path.at("/r/site-packages/weird.dist-info/METADATA");
    CHECK(weird.version.empty());
    CHECK(weird.version_source == "unreadable");
    CHECK(r.version_unreadable == 1);

    // The status stays supported; the gap is the informational token only.
    FakeTargets t;
    MemTree tree2 = tree;
    Pruned pruned;
    const auto a = answer_python("linux", t, [&](const FakeTargets&) { return tree2.ops(); }, pruned);
    CHECK(a.verdict.complete);
    CHECK(a.lines[0] == "status|python|supported|linux:component_inventory:version_unreadable");
}

TEST_CASE("python scan: only the first 16 KiB of a metadata file is read",
          "[runtime][component_pkg_scan][component_inventory]") {
    MemTree tree;
    std::string big = "Name: huge\nVersion: 3.0\n";
    big.resize(100000, 'x');
    tree.add_file("/r/site-packages/huge-3.0.dist-info/METADATA", big);
    const auto r = py(tree);
    REQUIRE(r.rows.size() == 1);
    CHECK(r.rows[0].version == "3.0");
    CHECK(r.rows[0].size == 100000);
    REQUIRE(tree.reads.size() == 1);
    CHECK(tree.reads[0].offset == 0);
    CHECK(tree.reads[0].len == kMaxPythonMetadataBytes);
    CHECK(tree.reads[0].len == 16384); // the documented 16 KiB, not only whatever the constant says
}

TEST_CASE("python scan: the bounds are pinned by value", "[runtime][component_pkg_scan][component_inventory]") {
    const auto p = python_limits();
    const WalkLimits d;
    CHECK(p.max_depth == 8);
    CHECK(p.max_entries == d.max_entries);
    CHECK(p.max_wall == d.max_wall);
    CHECK(p.max_rows == d.max_rows);
    CHECK(p.max_rows_per_anchor == d.max_rows_per_anchor);
    CHECK(p.max_dir_entries == d.max_dir_entries);
}

TEST_CASE("python scan: a tree deeper than eight directories is a depth stop, never a silent cut",
          "[runtime][component_pkg_scan][component_inventory]") {
    MemTree tree;
    tree.add_file("/r/a/b/c/d/e/f/g/h/i/METADATA", "x"); // i is the ninth directory below /r
    const auto r = py(tree);
    CHECK(r.stop == Stop::depth);
}

// ---- node ----

TEST_CASE("node scan: nested and scoped packages are rows, and a package's sources are never listed",
          "[runtime][component_pkg_scan][component_inventory]") {
    MemTree tree;
    tree.add_file("/r/node_modules/left-pad/package.json", pkg_json("left-pad", "1.3.0"));
    tree.add_file("/r/node_modules/left-pad/src/index.js", "x");
    tree.add_file("/r/node_modules/left-pad/node_modules/inner/package.json", pkg_json("inner", "0.1.0"));
    tree.add_file("/r/node_modules/@scope/pkg/package.json", pkg_json("@scope/pkg", "2.0.0"));
    tree.add_file("/r/node_modules/@scope/pkg/lib/x.js", "x");
    tree.add_file("/r/node_modules/.bin/tool", "x");
    tree.mtimes["/r/node_modules/@scope/pkg/package.json"] = 1700000999;
    const auto r = nd(tree);

    CHECK(r.stop == Stop::complete);
    CHECK(paths_of(r) == std::vector<std::string>{"/r/node_modules/@scope/pkg/package.json",
                                                  "/r/node_modules/left-pad/node_modules/inner/package.json",
                                                  "/r/node_modules/left-pad/package.json"});
    for (const auto& row : r.rows) {
        CHECK(row.kind == "node");
        CHECK(row.version_source == "package_json");
        CHECK(row.anchor_app == "node_modules");
    }
    CHECK_FALSE(was_listed(tree, "/r/node_modules/left-pad/src"));
    CHECK_FALSE(was_listed(tree, "/r/node_modules/@scope/pkg/lib"));
    CHECK_FALSE(was_listed(tree, "/r/node_modules/.bin"));
    CHECK(r.stats.dirs_excluded == 3);
    for (const auto& row : r.rows)
        if (row.name == "@scope/pkg")
            CHECK(format_component_row(row) == "comp|node|@scope/pkg|2.0.0|package_json|" + row.path + "|" +
                                                   std::to_string(pkg_json("@scope/pkg", "2.0.0").size()) +
                                                   "|1700000999|node_modules");
}

TEST_CASE("node scan: a package.json outside node_modules/<pkg> is no row", "[runtime][component_pkg_scan][component_inventory]") {
    MemTree tree;
    tree.add_file("/r/app/package.json", pkg_json("app", "1.0.0"));
    tree.add_file("/r/node_modules/@scope/package.json", pkg_json("x", "1.0.0"));
    const auto r = nd(tree);
    CHECK(r.rows.empty());
    CHECK(tree.total_opens == 0);
}

TEST_CASE("node scan: nesting past eight node_modules is pruned", "[runtime][component_pkg_scan][component_inventory]") {
    MemTree tree;
    std::string dir = "/r";
    for (int n = 1; n <= 9; ++n) {
        dir += "/node_modules/p" + std::to_string(n);
        tree.add_file(dir + "/package.json", pkg_json("p" + std::to_string(n), "1.0.0"));
    }
    const auto r = nd(tree);
    CHECK(r.stop == Stop::complete);
    CHECK(r.rows.size() == 8);
    CHECK(r.stats.dirs_excluded >= 1);
    for (const auto& row : r.rows)
        CHECK(row.name != "p9");
}

TEST_CASE("node scan: an oversized or non-object package.json is a row with source unreadable and the scan stays supported",
          "[runtime][component_pkg_scan][component_inventory]") {
    MemTree tree;
    std::string big = pkg_json("big", "1.0.0");
    big.resize(kMaxPackageJsonBytes + 5000, ' ');
    tree.add_file("/r/node_modules/big/package.json", big);
    tree.add_file("/r/node_modules/arr/package.json", "[1,2,3]");
    tree.add_file("/r/node_modules/bad/package.json", "{not json");
    tree.add_file("/r/node_modules/empty/package.json", "");
    const auto r = nd(tree);

    CHECK(r.stop == Stop::complete);
    REQUIRE(r.rows.size() == 4);
    for (const auto& row : r.rows) {
        CHECK(row.version.empty());
        CHECK(row.version_source == "unreadable");
        CHECK(row.name == row.path.substr(std::string("/r/node_modules/").size(),
                                          row.path.size() - std::string("/r/node_modules//package.json").size()));
    }
    CHECK(r.version_unreadable == 4);
    // At most 64 KiB + 1 byte, one read, through the one open.
    for (const auto& rd : tree.reads) {
        CHECK(rd.offset == 0);
        CHECK(rd.len <= kMaxPackageJsonBytes + 1);
    }
    CHECK(tree.total_opens == 4);
    // The documented 64 KiB + 1, as literal numbers: the oversized file is read to exactly the cap.
    CHECK(kMaxPackageJsonBytes == 65536);
    const auto big_read = std::ranges::find(tree.reads, "/r/node_modules/big/package.json", &MemTree::Read::path);
    REQUIRE(big_read != tree.reads.end());
    CHECK(big_read->len == 65537);

    FakeTargets t;
    Pruned pruned;
    const auto a = answer_node("linux", t, [&](const FakeTargets&) { return tree.ops(); }, pruned);
    CHECK(a.verdict.complete);
    CHECK(a.lines[0] == "status|node|supported|linux:component_inventory:version_unreadable");
}

TEST_CASE("node scan: a package.json with no usable name falls back to the directory name",
          "[runtime][component_pkg_scan][component_inventory]") {
    MemTree tree;
    tree.add_file("/r/node_modules/dirname/package.json", "{\"version\":\"4.5.6\"}");
    const auto r = nd(tree);
    REQUIRE(r.rows.size() == 1);
    CHECK(r.rows[0].name == "dirname");
    CHECK(r.rows[0].version == "4.5.6");
    CHECK(r.rows[0].version_source == "package_json");
}

TEST_CASE("pkg scan: a read that fails after a successful open is an unreadable row, never a constraint",
          "[runtime][component_pkg_scan][component_inventory]") {
    SECTION("python: the directory name speaks, as for a file that would not open") {
        MemTree tree;
        const std::string meta = "/r/site-packages/requests-2.31.0.dist-info/METADATA";
        tree.add_file(meta, kPyMeta);
        tree.fail_read = [](const std::string&, std::uint64_t, std::size_t) { return true; };
        const auto r = py(tree);
        CHECK(r.stop == Stop::complete);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].name == "requests");
        CHECK(r.rows[0].version == "2.31.0");
        CHECK(r.rows[0].version_source == "filename");
        CHECK(r.rows[0].size == std::string(kPyMeta).size()); // the open succeeded; only the read failed
        CHECK(tree.total_opens == 1);
        REQUIRE(tree.reads.size() == 1); // one read, no retry
    }
    SECTION("node: no version, source unreadable") {
        MemTree tree;
        tree.add_file("/r/node_modules/a/package.json", pkg_json("a", "1.0.0"));
        tree.fail_read = [](const std::string&, std::uint64_t, std::size_t) { return true; };
        const auto r = nd(tree);
        CHECK(r.stop == Stop::complete);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].name == "a");
        CHECK(r.rows[0].version.empty());
        CHECK(r.rows[0].version_source == "unreadable");
        CHECK(r.version_unreadable == 1);
        CHECK(tree.total_opens == 1);
        REQUIRE(tree.reads.size() == 1);
    }
}

// ---- shared completeness behaviour ----

TEST_CASE("pkg scan: a file that changes between open and read keeps its row and ends the scan archive_changed",
          "[runtime][component_pkg_scan][component_inventory]") {
    SECTION("python") {
        MemTree tree;
        tree.add_file("/r/site-packages/requests-2.31.0.dist-info/METADATA", kPyMeta);
        tree.changed.insert("/r/site-packages/requests-2.31.0.dist-info/METADATA");
        const auto r = py(tree);
        CHECK(r.stop == Stop::archive_changed);
        CHECK(r.rows.size() == 1);
    }
    SECTION("node") {
        MemTree tree;
        tree.add_file("/r/node_modules/a/package.json", pkg_json("a", "1.0.0"));
        tree.changed.insert("/r/node_modules/a/package.json");
        const auto r = nd(tree);
        CHECK(r.stop == Stop::archive_changed);
        CHECK(r.rows.size() == 1);
    }
}

TEST_CASE("pkg scan: the entry budget, the wall budget and the row caps give the scan's own tokens",
          "[runtime][component_pkg_scan][budget][component_inventory]") {
    const auto token_of = [](MemTree& tree, bool python, const WalkLimits& l) {
        FakeTargets t;
        Pruned pruned;
        const auto make = [&](const FakeTargets&) { return tree.ops(); };
        const auto a = python ? answer_python("linux", t, make, pruned, l) : answer_node("linux", t, make, pruned, l);
        CHECK_FALSE(a.verdict.complete);
        return a.lines[0];
    };
    const auto build_py = [](MemTree& tree) {
        for (int i = 0; i < 4; ++i)
            tree.add_file("/r/site-packages/p" + std::to_string(i) + "-1.0.dist-info/METADATA", kPyMeta);
    };
    SECTION("budget_entries") {
        MemTree tree;
        build_py(tree);
        WalkLimits l = python_limits();
        l.max_entries = 3;
        CHECK(token_of(tree, true, l) == "status|python|constrained|linux:component_inventory:budget_entries");
    }
    SECTION("budget_time") {
        MemTree tree;
        build_py(tree);
        tree.list_step = 30000ms;
        CHECK(token_of(tree, true, python_limits()) ==
              "status|python|constrained|linux:component_inventory:budget_time");
    }
    SECTION("section_rows") {
        MemTree tree;
        for (int i = 0; i < 4; ++i)
            tree.add_file("/r/node_modules/p" + std::to_string(i) + "/package.json", pkg_json("p", "1.0.0"));
        WalkLimits l;
        l.max_rows = 2;
        CHECK(token_of(tree, false, l) == "status|node|constrained|linux:component_inventory:section_rows");
    }
    SECTION("anchor_rows") {
        MemTree tree;
        for (int i = 0; i < 4; ++i)
            tree.add_file("/r/node_modules/p" + std::to_string(i) + "/package.json", pkg_json("p", "1.0.0"));
        WalkLimits l;
        l.max_rows_per_anchor = 2;
        CHECK(token_of(tree, false, l) == "status|node|constrained|linux:component_inventory:anchor_rows");
    }
    SECTION("the deadline is checked between files") {
        MemTree tree;
        build_py(tree);
        tree.open_step = 20000ms; // the walk finishes inside 45 s; the second open's check fails
        const auto r = py(tree);
        CHECK(r.stop == Stop::budget_time);
        CHECK(r.rows.size() < 4);
    }
}

// ---- the dispatch ----

TEST_CASE("pkg answer: an unreadable mount table walks nothing and says so, for both actions",
          "[runtime][component_pkg_scan][answer][component_inventory]") {
    int made = 0;
    FakeTargets t;
    t.mount_table_unreadable = true; // roots stay non-empty: the guard, not an empty list, stops the walk
    Pruned pruned;
    const auto make_fs = [&](const FakeTargets&) {
        ++made;
        return FsOps{};
    };
    const auto ap = answer_python("macos", t, make_fs, pruned);
    const auto an = answer_node("macos", t, make_fs, pruned);
    CHECK(made == 0);
    CHECK(pruned.calls.empty());
    REQUIRE(ap.lines.size() == 1);
    CHECK(ap.lines[0] == "status|python|constrained|macos:component_inventory:mount_table_unreadable");
    REQUIRE(an.lines.size() == 1);
    CHECK(an.lines[0] == "status|node|constrained|macos:component_inventory:mount_table_unreadable");
}

TEST_CASE("pkg answer: pruned directories are reported once to the logger and never as package_tree_skipped",
          "[runtime][component_pkg_scan][answer][component_inventory]") {
    SECTION("python") {
        MemTree tree;
        tree.add_file("/r/site-packages/requests-2.31.0.dist-info/METADATA", kPyMeta);
        tree.add_file("/r/site-packages/requests/__init__.py", "x");
        FakeTargets t;
        Pruned pruned;
        const auto a = answer_python("linux", t, [&](const FakeTargets&) { return tree.ops(); }, pruned);
        REQUIRE(pruned.calls.size() == 1);
        CHECK(pruned.calls[0].first == "python");
        CHECK(pruned.calls[0].second == 1);
        CHECK(a.verdict.complete);
        REQUIRE(a.lines.size() == 2);
        CHECK(a.lines[0] == "status|python|supported|-");
        CHECK(a.lines[0].find("package_tree_skipped") == std::string::npos);
        CHECK(a.lines[1].starts_with("comp|python|requests|2.31.0|metadata|"));
    }
    SECTION("node, with the targets' dropped roots still reported") {
        MemTree tree;
        tree.add_file("/r/node_modules/a/package.json", pkg_json("a", "1.0.0"));
        tree.add_file("/r/node_modules/a/src/x.js", "x");
        FakeTargets t;
        t.roots_link_skipped = 1;
        Pruned pruned;
        const auto a = answer_node("linux", t, [&](const FakeTargets&) { return tree.ops(); }, pruned);
        REQUIRE(pruned.calls.size() == 1);
        CHECK(pruned.calls[0] == std::pair<std::string, std::size_t>{"node", 1});
        CHECK(a.lines[0] == "status|node|supported|linux:component_inventory:root_link_skipped");
        CHECK(a.roots_skipped == 1);
    }
}

TEST_CASE("pkg answer: a link or network mount inside the tree is still reported",
          "[runtime][component_pkg_scan][answer][component_inventory]") {
    MemTree tree;
    tree.add_file("/r/node_modules/a/package.json", pkg_json("a", "1.0.0"));
    tree.add_link("/r/node_modules/linked");
    FakeTargets t;
    Pruned pruned;
    const auto a = answer_node("linux", t, [&](const FakeTargets&) { return tree.ops(); }, pruned);
    CHECK(a.lines[0] == "status|node|supported|linux:component_inventory:link_skipped");
}

// ---- roots ----

#if !defined(_WIN32)
TEST_CASE("python and node roots: per OS, with the one listing injected",
          "[runtime][component_pkg_scan][posix][component_inventory]") {
    std::vector<std::string> listed;
    const ChildLister lister = [&listed](const std::string& dir) -> std::optional<std::vector<std::string>> {
        listed.push_back(dir);
        return std::vector<std::string>{"python3.9", "python3", "python3.12", "python3.", "python3.x", "python",
                                        "python3.11-config", "python2.7", "libfoo.a", "python3.11"};
    };
    const auto roots = python_candidate_roots(lister);
#if defined(__APPLE__)
    CHECK(roots == std::vector<std::string>{"/Library/Frameworks/Python.framework/Versions",
                                            "/opt/homebrew/lib/python3.11", "/opt/homebrew/lib/python3.12",
                                            "/opt/homebrew/lib/python3.9", "/usr/local/lib/python3.11",
                                            "/usr/local/lib/python3.12", "/usr/local/lib/python3.9"});
    CHECK(listed == std::vector<std::string>{"/opt/homebrew/lib", "/usr/local/lib"});
    CHECK(node_candidate_roots() == std::vector<std::string>{"/opt/homebrew/lib/node_modules",
                                                             "/usr/local/lib/node_modules", "/Applications"});
#else
    CHECK(roots == std::vector<std::string>{"/usr/local/lib/python3", "/usr/local/lib/python3.11",
                                            "/usr/local/lib/python3.12", "/usr/local/lib/python3.9", "/opt"});
    CHECK(listed == std::vector<std::string>{"/usr/local/lib"}); // one single-level listing, nothing else
    CHECK(node_candidate_roots() ==
          std::vector<std::string>{"/usr/lib/node_modules", "/usr/local/lib/node_modules", "/opt"});
#endif
    // The package manager's interpreter trees are never python roots, and an empty parent adds nothing.
    for (const auto& root : roots)
        CHECK_FALSE((root == "/usr/lib" || root.starts_with("/usr/lib/")));
    const auto none = python_candidate_roots(
        [](const std::string&) -> std::optional<std::vector<std::string>> { return std::vector<std::string>{}; });
#if !defined(__APPLE__)
    CHECK(none == std::vector<std::string>{"/opt"});
#else
    CHECK(none == std::vector<std::string>{"/Library/Frameworks/Python.framework/Versions"});
#endif
}

TEST_CASE("python roots: a parent that cannot be listed is offered as a candidate, never dropped uncounted",
          "[runtime][component_pkg_scan][posix][component_inventory]") {
    const ChildLister unlistable = [](const std::string&) -> std::optional<std::vector<std::string>> {
        return std::nullopt;
    };
    const auto roots = python_candidate_roots(unlistable);
#if defined(__APPLE__)
    const std::vector<std::string> parents{"/opt/homebrew/lib", "/usr/local/lib"};
    CHECK(roots == std::vector<std::string>{"/Library/Frameworks/Python.framework/Versions", "/opt/homebrew/lib",
                                            "/usr/local/lib"});
#else
    const std::vector<std::string> parents{"/usr/local/lib"};
    CHECK(roots == std::vector<std::string>{"/usr/local/lib", "/opt"});
#endif

    SECTION("on a network mount it reaches plan_targets and is counted as skipped") {
        const auto t = plan_targets(roots, parents, true);
        CHECK(t.roots_network_skipped == parents.size());
        for (const auto& p : parents)
            CHECK(std::ranges::find(t.roots, p) == t.roots.end());
    }
    SECTION("under a network mount above it, it is counted too") {
        const auto t = plan_targets(roots, {"/usr/local"}, true);
        CHECK(t.roots_network_skipped == 1);
        CHECK(std::ranges::find(t.roots, "/usr/local/lib") == t.roots.end());
    }
    SECTION("off any mount it stays a root, for the open check to count, drop or report") {
        const auto t = plan_targets(roots, {}, true);
        CHECK(t.roots == roots);
        CHECK(t.roots_network_skipped == 0);
    }
    SECTION("only the parent that failed is offered; a parent that lists still yields its children") {
        const ChildLister half = [](const std::string& dir) -> std::optional<std::vector<std::string>> {
            if (dir == "/usr/local/lib")
                return std::nullopt;
            return std::vector<std::string>{"python3.12"};
        };
        const auto mixed = python_candidate_roots(half);
#if defined(__APPLE__)
        CHECK(mixed == std::vector<std::string>{"/Library/Frameworks/Python.framework/Versions",
                                                "/opt/homebrew/lib/python3.12", "/usr/local/lib"});
#else
        CHECK(mixed == std::vector<std::string>{"/usr/local/lib", "/opt"});
#endif
    }
}

TEST_CASE("python roots: a parent listing cut at the entry cap is offered as a root, never as a partial set of names",
          "[runtime][component_pkg_scan][posix][component_inventory]") {
    // MUTATION: ignoring ListResult::truncated in make_child_lister keeps python3.12 as a root and drops
    // the parent, so a partial set of names would read as the whole one.
    std::size_t cap_seen = 0;
    const auto list = [&cap_seen](const std::string&, std::size_t cap) {
        cap_seen = cap;
        ListResult r;
        r.entries = {{"python3.12", DirEntry::Type::dir}}; // what the cut listing happened to hold
        r.truncated = true;
        return r;
    };
    const auto lister = make_child_lister(list);
    CHECK_FALSE(lister("/usr/local/lib").has_value());
    CHECK(cap_seen == 50000); // the walk's own per-directory cap, as a literal

    const auto roots = python_candidate_roots(lister);
    CHECK(std::ranges::find(roots, "/usr/local/lib") != roots.end());
    for (const auto& root : roots)
        CHECK_FALSE(root.ends_with("/python3.12"));
}

TEST_CASE("python roots: the live lister keeps directories, links and network mounts, and nothing it could not list in full",
          "[runtime][component_pkg_scan][posix][component_inventory]") {
    using Type = DirEntry::Type;
    ListResult whole;
    whole.entries = {{"python3.10", Type::dir},   {"python3.11", Type::link},       {"python3.12", Type::network_mount},
                     {"python3.13", Type::file},  {"python3.14", Type::other}};
    const auto lister = make_child_lister([&](const std::string&, std::size_t) { return whole; });
    CHECK(lister("/x") == std::optional<std::vector<std::string>>{{"python3.10", "python3.11", "python3.12"}});

    ListResult failed;
    failed.error = true;
    CHECK_FALSE(make_child_lister([&](const std::string&, std::size_t) { return failed; })("/x").has_value());

    // A python3.N that is itself a network mount is never opened here, but it must be counted as skipped.
    const auto roots = python_candidate_roots(lister);
    std::vector<std::string> mounts;
    for (const auto& root : roots)
        if (root.ends_with("/python3.12"))
            mounts.push_back(root);
    REQUIRE_FALSE(mounts.empty());
    const auto t = plan_targets(roots, mounts, true);
    CHECK(t.roots_network_skipped == mounts.size());
    for (const auto& m : mounts)
        CHECK(std::ranges::find(t.roots, m) == t.roots.end());
}
#endif
