/**
 * test_component_walk.cpp -- tests for the component_inventory bounded walk
 * (agents/plugins/component_inventory/src/component_walk.hpp). The walk is driven over an in-memory
 * tree and a fake clock; no test touches a disk, a process or the wall clock, and the seam's
 * open_file is never called by the walk (asserted).
 *
 * MUTATION NOTES (each assertion below FAILS if the named wiring is removed):
 *  - entry cap: checking the budget once per directory instead of per entry fails the
 *    `stats.entries == cap` assertions (the fixture's directory is bigger than the cap).
 *  - completeness: dropping record(Stop::depth) fails the "deeper than max_depth" case, which would
 *    otherwise read `complete` with a jar silently missing; the same for dir_unreadable,
 *    dir_truncated and anchor_rows.
 *  - budget ends the walk: continuing after budget_time fails the `listed` assertions.
 *  - first cause wins: letting a later cause overwrite `stop` fails the two-cause cases.
 *  - no exclusion by name: skipping a directory by its name (System, Windows, System32) fails the
 *    ordinary-names case, which would otherwise read complete with its jars silently missing.
 *  - trailing separator: joining without the trailing-'/' check fails the join case (a doubled '/').
 *  - root index: leaving Candidate::root at 0 fails the multiple-roots case.
 */
#include <catch2/catch_test_macros.hpp>

#include "component_fixture_tree.hpp"
#include "component_walk.hpp"

#include <chrono>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::component_inventory;
using namespace yuzu::component_inventory::fixture;
using namespace std::chrono_literals;
using T = DirEntry::Type;

namespace {

/// A directory with the given listing. A directory named in a listing but never given one here is
/// one MemTree cannot list: dir_unreadable.
void dir(MemTree& t, const std::string& path, std::vector<DirEntry> entries) {
    t.dirs[path] = std::move(entries);
}

DirEntry D(std::string n) { return {std::move(n), T::dir}; }
DirEntry F(std::string n) { return {std::move(n), T::file}; }

std::vector<std::string> paths(const WalkResult& r) {
    std::vector<std::string> v;
    for (const auto& c : r.candidates)
        v.push_back(c.path);
    return v;
}

WalkResult run(MemTree& fs, const WalkLimits& lim, const std::vector<std::string>& roots,
               std::chrono::milliseconds budget = 1h) {
    auto ops = fs.ops();
    return walk(roots, lim, ops, fs.clock + budget);
}

} // namespace

TEST_CASE("component walk: finds jar, war and ear case-insensitively, breadth first, with anchors",
          "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    dir(fs, "/opt", {D("tomcat"), D("kafka"), F("top.JAR"), F("notes.txt"), F("jar")});
    dir(fs, "/opt/tomcat", {D("webapps"), F("boot.Jar")});
    dir(fs, "/opt/tomcat/webapps", {F("a.war"), F("b.EAR"), F("c.warx")});
    dir(fs, "/opt/kafka", {F("k.jar")});

    const auto r = run(fs, {}, {"/opt"});

    CHECK(r.stop == Stop::complete);
    CHECK(paths(r) == std::vector<std::string>{"/opt/top.JAR", "/opt/tomcat/boot.Jar", "/opt/kafka/k.jar",
                                               "/opt/tomcat/webapps/a.war", "/opt/tomcat/webapps/b.EAR"});
    // The first path component below the root; a root-level file is its own anchor.
    CHECK(r.candidates[0].anchor_app == "top.JAR");
    CHECK(r.candidates[1].anchor_app == "tomcat");
    CHECK(r.candidates[2].anchor_app == "kafka");
    CHECK(r.candidates[3].anchor_app == "tomcat");
    CHECK(r.stats.entries == 5 + 2 + 3 + 1);
    // Breadth first: every directory of one level is listed before any of the next.
    CHECK(fs.listed == std::vector<std::string>{"/opt", "/opt/tomcat", "/opt/kafka", "/opt/tomcat/webapps"});
    CHECK(fs.total_opens == 0);
}

TEST_CASE("component walk: joins with '/' and never doubles a trailing one", "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    dir(fs, "/apps/", {D("x")});
    dir(fs, "/apps/x", {F("a.jar")});

    const auto r = run(fs, {}, {"/apps/"});

    CHECK(r.stop == Stop::complete);
    CHECK(paths(r) == std::vector<std::string>{"/apps/x/a.jar"});
}

TEST_CASE("component walk: multiple roots, empty roots and dot entries", "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    dir(fs, "/a", {F("1.jar"), F("."), F(".."), D(".."), F("")});
    dir(fs, "/b", {F("2.jar")});

    CHECK(run(fs, {}, {}).stop == Stop::complete);
    const auto r = run(fs, {}, {"/a", "/b"});
    CHECK(r.stop == Stop::complete);
    CHECK(paths(r) == std::vector<std::string>{"/a/1.jar", "/b/2.jar"});
    CHECK(r.stats.entries == 2); // dot entries are not entries
    // Each candidate carries the index of its root: the scan keys an anchor's quota on it.
    REQUIRE(r.candidates.size() == 2);
    CHECK(r.candidates[0].root == 0);
    CHECK(r.candidates[1].root == 1);
}

TEST_CASE("component walk: the entry budget is never exceeded and stops the walk",
          "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    std::vector<DirEntry> big;
    for (int i = 0; i < 100; ++i)
        big.push_back(F("f" + std::to_string(i) + ".jar"));
    big.push_back(D("later"));
    dir(fs, "/r", big);
    dir(fs, "/r/later", {F("z.jar")});

    WalkLimits lim;
    lim.max_entries = 40; // smaller than ONE directory
    const auto r = run(fs, lim, {"/r"});

    CHECK(r.stop == Stop::budget_entries);
    CHECK(r.stats.entries == 40);
    CHECK(r.candidates.size() == 40);
    CHECK(fs.listed == std::vector<std::string>{"/r"});

    // A tree of exactly the cap is complete: the cap is a ceiling, not a trigger.
    WalkLimits exact;
    exact.max_entries = 102; // 101 entries in /r + 1 in /r/later
    const auto e = run(fs, exact, {"/r"});
    CHECK(e.stop == Stop::complete);
    CHECK(e.stats.entries == 102);
    exact.max_entries = 101;
    CHECK(run(fs, exact, {"/r"}).stop == Stop::budget_entries);
}

TEST_CASE("component walk: the entry budget spans directories", "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    dir(fs, "/r", {D("a"), D("b")});
    dir(fs, "/r/a", {F("1.jar"), F("2.jar")});
    dir(fs, "/r/b", {F("3.jar"), F("4.jar")});

    WalkLimits lim;
    lim.max_entries = 5; // /r (2) + /r/a (2) + one of /r/b
    const auto r = run(fs, lim, {"/r"});

    CHECK(r.stop == Stop::budget_entries);
    CHECK(r.stats.entries == 5);
    CHECK(paths(r) == std::vector<std::string>{"/r/a/1.jar", "/r/a/2.jar", "/r/b/3.jar"});
}

TEST_CASE("component walk: the fake clock passing the deadline between directories stops with budget_time",
          "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    fs.list_step = 10ms;
    dir(fs, "/r", {D("a"), D("b"), D("c")});
    dir(fs, "/r/a", {F("1.jar")});
    dir(fs, "/r/b", {F("2.jar")});
    dir(fs, "/r/c", {F("3.jar")});

    // /r lists at t=10, /r/a at t=20; before /r/b the clock reads 20 >= 15.
    const auto r = run(fs, {}, {"/r"}, 15ms);

    CHECK(r.stop == Stop::budget_time);
    CHECK(fs.listed == std::vector<std::string>{"/r", "/r/a"});
    CHECK(paths(r) == std::vector<std::string>{"/r/a/1.jar"}); // what was reachable is kept
}

TEST_CASE("component walk: a deadline that expires on the last directory is not an incomplete walk",
          "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    fs.list_step = 10ms;
    dir(fs, "/r", {F("1.jar")});

    const auto r = run(fs, {}, {"/r"}, 5ms); // clock is past the deadline once /r is listed

    CHECK(r.stop == Stop::complete);
    CHECK(paths(r) == std::vector<std::string>{"/r/1.jar"});
}

TEST_CASE("component walk: a deadline already passed lists nothing", "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    dir(fs, "/r", {F("1.jar")});

    const auto r = run(fs, {}, {"/r"}, 0ms);

    CHECK(r.stop == Stop::budget_time);
    CHECK(fs.listed.empty());
}

TEST_CASE("component walk: candidates beyond max_rows end the walk with section_rows and never exceed it",
          "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    std::vector<DirEntry> e;
    for (int i = 0; i < 8; ++i)
        e.push_back(F("j" + std::to_string(i) + ".jar"));
    e.push_back(D("later"));
    dir(fs, "/r", e);
    dir(fs, "/r/later", {F("z.jar")});

    WalkLimits lim;
    lim.max_rows = 5;
    const auto r = run(fs, lim, {"/r"});

    CHECK(r.stop == Stop::section_rows);
    CHECK(r.candidates.size() == 5);
    CHECK(fs.listed == std::vector<std::string>{"/r"}); // ended at once

    lim.max_rows = 9; // 8 + the jar in /r/later: exactly the cap is complete
    const auto ok = run(fs, lim, {"/r"});
    CHECK(ok.stop == Stop::complete);
    CHECK(ok.candidates.size() == 9);
}

TEST_CASE("component walk: an anchor past max_rows_per_anchor records anchor_rows and the walk goes on",
          "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    dir(fs, "/r", {D("big"), D("small")});
    dir(fs, "/r/big", {F("1.jar"), F("2.jar"), F("3.jar"), F("4.jar"), F("5.jar")});
    dir(fs, "/r/small", {F("a.jar"), F("b.jar")});

    WalkLimits lim;
    lim.max_rows_per_anchor = 3;
    const auto r = run(fs, lim, {"/r"});

    CHECK(r.stop == Stop::anchor_rows);
    CHECK(paths(r) == std::vector<std::string>{"/r/big/1.jar", "/r/big/2.jar", "/r/big/3.jar", "/r/small/a.jar",
                                               "/r/small/b.jar"});

    // Exactly the cap is complete.
    lim.max_rows_per_anchor = 5;
    CHECK(run(fs, lim, {"/r"}).stop == Stop::complete);
}

TEST_CASE("component walk: a jar deeper than max_depth is not returned and the result is depth",
          "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    // /r (depth 0) / d1 / d2 / d3 / d4
    dir(fs, "/r", {D("d1"), F("shallow.jar")});
    dir(fs, "/r/d1", {D("d2")});
    dir(fs, "/r/d1/d2", {D("d3"), F("ok.jar")});
    dir(fs, "/r/d1/d2/d3", {D("d4"), F("edge.jar")});
    dir(fs, "/r/d1/d2/d3/d4", {F("deep.jar")});

    WalkLimits lim;
    lim.max_depth = 3;
    const auto r = run(fs, lim, {"/r"});

    CHECK(r.stop == Stop::depth);
    CHECK(paths(r) == std::vector<std::string>{"/r/shallow.jar", "/r/d1/d2/ok.jar", "/r/d1/d2/d3/edge.jar"});
    CHECK(fs.listed.size() == 4); // d4 (depth 4) was never listed

    lim.max_depth = 4; // the same tree, one level of headroom
    const auto ok = run(fs, lim, {"/r"});
    CHECK(ok.stop == Stop::complete);
    CHECK(ok.candidates.size() == 4);
}

TEST_CASE("component walk: the default depth backstop of 32 reports depth, never complete",
          "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    std::string p = "/r";
    for (int i = 1; i <= 33; ++i) {
        dir(fs, p, {D("n")});
        p += "/n";
    }
    dir(fs, p, {F("deep.jar")});

    const auto r = run(fs, {}, {"/r"});

    CHECK(WalkLimits{}.max_depth == 32);
    CHECK(r.stop == Stop::depth);
    CHECK(r.candidates.empty());
}

TEST_CASE("component walk: an unlistable directory is dir_unreadable and its siblings are kept",
          "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    dir(fs, "/r", {D("locked"), D("open"), F("top.jar")}); // /r/locked has no listing
    dir(fs, "/r/open", {F("a.jar")});

    const auto r = run(fs, {}, {"/r"});

    CHECK(r.stop == Stop::dir_unreadable);
    CHECK(paths(r) == std::vector<std::string>{"/r/top.jar", "/r/open/a.jar"});
}

TEST_CASE("component walk: an unreadable root is dir_unreadable", "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    dir(fs, "/ok", {F("a.jar")}); // /gone has no listing

    const auto r = run(fs, {}, {"/gone", "/ok"});

    CHECK(r.stop == Stop::dir_unreadable);
    CHECK(paths(r) == std::vector<std::string>{"/ok/a.jar"});
}

TEST_CASE("component walk: a listing cut at max_dir_entries is dir_truncated with the rest intact",
          "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    dir(fs, "/r", {F("1.jar"), F("2.jar"), F("3.jar"), F("4.jar"), D("sub")});
    dir(fs, "/r/sub", {F("s.jar")});
    dir(fs, "/s", {F("a.jar"), F("b.jar")});

    WalkLimits lim;
    lim.max_dir_entries = 3;
    const auto r = run(fs, lim, {"/r", "/s"});

    CHECK(r.stop == Stop::dir_truncated);
    CHECK(paths(r) == std::vector<std::string>{"/r/1.jar", "/r/2.jar", "/r/3.jar", "/s/a.jar", "/s/b.jar"});
    CHECK(r.stats.entries == 5);

    lim.max_dir_entries = 5; // exactly the directory size is not a cut
    CHECK(run(fs, lim, {"/r"}).stop == Stop::complete);
}

TEST_CASE("component walk: a leg that over-delivers entries is still cut at max_dir_entries",
          "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    auto ops = fs.ops();
    ops.list = [](const std::string&, std::size_t) { // ignores the cap and does not say truncated
        ListResult r;
        r.entries = {F("1.jar"), F("2.jar"), F("3.jar")};
        return r;
    };
    WalkLimits lim;
    lim.max_dir_entries = 2;
    const std::vector<std::string> roots{"/r"};

    const auto r = walk(roots, lim, ops, fs.clock + 1h);

    CHECK(r.stop == Stop::dir_truncated);
    CHECK(r.candidates.size() == 2);
}

TEST_CASE("component walk: links, network mounts and other entries are counted and never listed",
          "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    dir(fs, "/r", {{"l1", T::link}, {"l2.jar", T::link}, {"nfs", T::network_mount}, {"smb", T::network_mount},
                  {"smb2", T::network_mount}, {"dev", T::other}, {"ok", T::dir}});
    dir(fs, "/r/ok", {F("a.jar")});
    dir(fs, "/r/l1", {F("hidden.jar")});
    dir(fs, "/r/nfs", {F("hidden.jar")});
    dir(fs, "/r/dev", {F("hidden.jar")});

    const auto r = run(fs, {}, {"/r"});

    CHECK(r.stop == Stop::complete); // counted skips are deliberate, not a gap
    CHECK(r.stats.links_skipped == 2);
    CHECK(r.stats.mounts_skipped == 3);
    CHECK(paths(r) == std::vector<std::string>{"/r/ok/a.jar"});
    CHECK(fs.listed == std::vector<std::string>{"/r", "/r/ok"});
    CHECK(r.stats.entries == 7 + 1);
}

TEST_CASE("component walk: no directory is excluded by name, whatever it is called",
          "[runtime][component_walk][component_inventory]") {
    MemTree fs;
    dir(fs, "/opt", {D("System"), D("Windows"), D("System32"), D("app")});
    dir(fs, "/opt/System", {F("bundle.jar")});
    dir(fs, "/opt/Windows", {F("w.jar")});
    dir(fs, "/opt/System32", {F("s.jar")});
    dir(fs, "/opt/app", {F("a.jar")});

    const auto r = run(fs, {}, {"/opt"});

    CHECK(r.stop == Stop::complete);
    CHECK(paths(r) == std::vector<std::string>{"/opt/System/bundle.jar", "/opt/Windows/w.jar",
                                               "/opt/System32/s.jar", "/opt/app/a.jar"});
    CHECK(fs.listed == std::vector<std::string>{"/opt", "/opt/System", "/opt/Windows", "/opt/System32",
                                                "/opt/app"});
}

TEST_CASE("component walk: the first cause recorded is the one reported", "[runtime][component_walk][component_inventory]") {
    SECTION("depth, then an unreadable directory, then an anchor cap") {
        MemTree fs;
        dir(fs, "/r", {D("a"), D("bad"), D("c")});
        dir(fs, "/r/a", {D("b")}); // listing /r/a (the 2nd list call) records depth first
        dir(fs, "/r/c", {F("1.jar"), F("2.jar")}); // /r/bad has no listing: recorded second
        WalkLimits lim;
        lim.max_depth = 1;
        lim.max_rows_per_anchor = 1;

        const auto r = run(fs, lim, {"/r"});

        CHECK(r.stop == Stop::depth);
        CHECK(paths(r) == std::vector<std::string>{"/r/c/1.jar"}); // later causes did not stop the walk
    }
    SECTION("an earlier cause is kept when a budget then ends the walk at once") {
        MemTree fs;
        dir(fs, "/r", {D("bad"), D("x"), D("y")});
        dir(fs, "/r/x", {F("1.jar"), F("2.jar"), F("3.jar")});
        dir(fs, "/r/y", {F("never.jar")}); // /r/bad has no listing
        WalkLimits lim;
        lim.max_entries = 5; // /r (3) + two of /r/x

        const auto r = run(fs, lim, {"/r"});

        CHECK(r.stop == Stop::dir_unreadable);
        CHECK(r.stats.entries == 5);
        CHECK(fs.listed == std::vector<std::string>{"/r", "/r/bad", "/r/x"}); // /r/y never listed
        CHECK(paths(r) == std::vector<std::string>{"/r/x/1.jar", "/r/x/2.jar"});
    }
    SECTION("a budget as the first cause is reported and ends the walk") {
        MemTree fs;
        dir(fs, "/r", {D("a"), D("b"), D("c")});
        dir(fs, "/r/a", {F("1.jar")});
        dir(fs, "/r/b", {F("2.jar"), F("3.jar")});
        dir(fs, "/r/c", {F("4.jar")});
        WalkLimits lim;
        lim.max_entries = 5; // /r (3) + /r/a (1) + 2.jar; 3.jar is over

        const auto r = run(fs, lim, {"/r"});

        CHECK(r.stop == Stop::budget_entries);
        CHECK(r.stats.entries == 5);
        CHECK(fs.listed == std::vector<std::string>{"/r", "/r/a", "/r/b"}); // /r/c never listed
    }
}

TEST_CASE("component walk: to_token covers every Stop value", "[runtime][component_walk][component_inventory]") {
    const std::vector<std::pair<Stop, std::string_view>> all{
        {Stop::complete, "complete"},
        {Stop::budget_entries, "budget_entries"},
        {Stop::budget_time, "budget_time"},
        {Stop::anchor_rows, "anchor_rows"},
        {Stop::section_rows, "section_rows"},
        {Stop::depth, "depth"},
        {Stop::dir_unreadable, "dir_unreadable"},
        {Stop::dir_truncated, "dir_truncated"},
        {Stop::archive_unenumerated, "archive_unenumerated"},
        {Stop::archive_changed, "archive_changed"},
    };
    std::set<std::string_view> seen;
    for (const auto& [s, tok] : all) {
        CHECK(to_token(s) == tok);
        seen.insert(to_token(s));
    }
    CHECK(seen.size() == all.size());
    // archive_changed is the last enumerator: a value appended after it is not in the list above.
    CHECK(static_cast<std::size_t>(Stop::archive_changed) + 1 == all.size());
}

TEST_CASE("component walk: default limits are the roadmap values", "[runtime][component_walk][component_inventory]") {
    const WalkLimits l;
    CHECK(l.max_entries == 400000);
    CHECK(l.max_wall == 45s);
    CHECK(l.max_rows_per_anchor == 3000);
    CHECK(l.max_rows == 20000);
    CHECK(l.max_depth == 32);
    CHECK(l.max_dir_entries == 50000);
}
