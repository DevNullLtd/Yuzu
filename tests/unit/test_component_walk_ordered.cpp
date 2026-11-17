/**
 * test_component_walk_ordered.cpp -- tests for walk_ordered(), the sorted depth-first resumable walk
 * of the on-demand file search (agents/plugins/component_inventory/src/component_walk.hpp). The walk is
 * driven over MemTree and its fake clock; identities (dev, file id) are stamped by a decorating
 * FsOps::list kept in this file. No test touches a disk, a process or the wall clock, and open_file is
 * never called (MemTree::total_opens stays 0).
 *
 * MUTATION NOTES (each assertion below FAILS if the named wiring is removed):
 *  - sort: trusting the listing order fails the order case (MemTree lists in insertion order) and the
 *    byte-order names ('B' < '_' < 'a' < a high byte).
 *  - directory before its subtree: visiting a directory after its entries fails the order case.
 *  - resume equivalence: skipping entries <= after, entering a named frame without the by-name match,
 *    visiting the entered directory a second time, or charging resume-path listings to max_entries each
 *    fail the property loop (a duplicate, an omission or a stall).
 *  - directory-row position: leaving the dir unpushed when the row cap or the deadline falls between its
 *    visit and its listing fails the boundary cases (the resumed slice would skip its entries or
 *    revisit it); stamping a listed identity onto an unlisted frame fails the 0/0 assertions.
 *  - per-entry deadline: checking the clock only before listings fails the flat 1,000-entry case.
 *  - gaps: dropping any one of the six gap records fails its case (the walk would read complete with
 *    entries silently unsearched); visiting the entries of a truncated, other-device or over-cap
 *    listing fails the `visits` assertions.
 *  - memory: not returning a listing's charge when the walk leaves the directory fails the sibling
 *    case; not checking the cap fails the chain case (peak over the cap).
 *  - replaced directory: ignoring the identity change fails the restarted assertions; a restart that
 *    keeps skipping below `after` fails the re-visit assertion. Comparing only file ids (dropping the
 *    device half of identity_changed) fails the device-only directory and root cases.
 *  - zero budget: letting a zero max_entries or max_rows walk the resume path fails the `tail` position
 *    of the zero-budget case (a completed directory would read as progress).
 *  - forged resume: joining a frame name that is not a directory entry of the real listing fails the
 *    `listed` assertions.
 *  - unknown identities: treating 0 as an identity fails the zero-identity cases (false restart, false
 *    other_device).
 *  - gap cap: not capping gaps fails the 1,000 / 5 split; opening a file fails total_opens == 0.
 */
#include <catch2/catch_test_macros.hpp>

#include "component_fixture_tree.hpp"
#include "component_walk.hpp"

#include <algorithm>
#include <chrono>
#include <compare>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::component_inventory;
using namespace yuzu::component_inventory::fixture;
using namespace std::chrono_literals;
namespace fsr = yuzu::shared::file_search;
using T = DirEntry::Type;
using Cause = OrderedGap::Cause;

// One default-cap listing of 255-byte names fits the default retained-bytes cap.
static_assert(50000 * (255 + sizeof(DirEntry)) <= kMaxOrderedRetainedBytes);

namespace {

struct Ident {
    std::uint64_t dev{0};
    std::uint64_t id{0};
};

/// MemTree plus identities and a recording visitor. Not movable: ops() captures `this`.
struct Rig {
    MemTree fs;
    std::map<std::string, Ident> ids;          // directory or entry path -> identity stamped on listings
    std::vector<std::string> visits;           // dir_path/name of every visit, in order
    std::map<std::string, std::uint64_t> dev_at;   // visit path -> the dir_dev the visitor was given
    std::map<std::string, std::uint64_t> id_at;    // visit path -> the entry's file_id
    std::function<void(const std::string& path)> hook; // runs inside the visitor

    void dir(const std::string& path, std::vector<DirEntry> entries) { fs.dirs[path] = std::move(entries); }

    [[nodiscard]] FsOps ops() {
        FsOps o = fs.ops();
        const auto inner = o.list;
        o.list = [this, inner](const std::string& d, std::size_t cap) {
            ListResult r = inner(d, cap);
            if (const auto it = ids.find(d); it != ids.end()) {
                r.dev = it->second.dev;
                r.file_id = it->second.id;
            }
            for (auto& e : r.entries)
                if (const auto it = ids.find(walk_detail::join(d, e.name)); it != ids.end())
                    e.file_id = it->second.id;
            return r;
        };
        return o;
    }

    [[nodiscard]] OrderedVisit visitor() {
        return [this](const std::string& d, const DirEntry& e, std::uint64_t dev) {
            const std::string p = walk_detail::join(d, e.name);
            visits.push_back(p);
            dev_at[p] = dev;
            id_at[p] = e.file_id;
            if (hook)
                hook(p);
            return true;
        };
    }
};

DirEntry D(std::string n) { return {std::move(n), T::dir}; }
DirEntry F(std::string n) { return {std::move(n), T::file}; }
DirEntry L(std::string n) { return {std::move(n), T::link}; }
DirEntry M(std::string n) { return {std::move(n), T::network_mount}; }

using Strs = std::vector<std::string>;

OrderedResult slice(Rig& r, const fsr::Position& resume, const WalkLimits& lim,
                    std::chrono::milliseconds budget = 1h, std::size_t max_retained = kMaxOrderedRetainedBytes) {
    auto ops = r.ops();
    return walk_ordered("/r", resume, lim, ops, r.fs.clock + budget, r.visitor(), max_retained);
}

std::size_t charge_of(const std::vector<DirEntry>& es) {
    std::size_t c = es.size() * sizeof(DirEntry);
    for (const auto& e : es)
        c += e.name.size();
    return c;
}

std::vector<std::string> tokens(const OrderedResult& r) {
    std::vector<std::string> v;
    for (const auto& g : r.gaps)
        v.push_back(std::string(to_token(g.cause)) + " " + g.path);
    return v;
}

bool later(const fsr::Position& a, const fsr::Position& b) { return std::is_gt(fsr::walk_order(a, b)); }
bool earlier(const fsr::Position& a, const fsr::Position& b) { return std::is_lt(fsr::walk_order(a, b)); }

// ---- deterministic pseudo-random trees ----

struct Lcg {
    std::uint64_t s;
    std::size_t below(std::size_t n) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return static_cast<std::size_t>((s >> 33) % n);
    }
};

void gen(Rig& r, Lcg& g, const std::string& path, std::size_t depth) {
    static const std::string pool = "aAbB09_-.z\xc3";
    std::set<std::string> seen;
    std::vector<DirEntry> es;
    std::vector<std::string> subdirs;
    const std::size_t n = g.below(8);
    for (std::size_t i = 0; i < n; ++i) {
        std::string name;
        for (std::size_t c = 0, len = 1 + g.below(3); c < len; ++c)
            name += pool[g.below(pool.size())];
        if (name == "." || name == ".." || !seen.insert(name).second)
            continue;
        const std::size_t k = g.below(100);
        if (k < 50) {
            es.push_back(F(name));
        } else if (k < 82 && depth < 4) {
            es.push_back(D(name));
            subdirs.push_back(name);
        } else if (k < 90) {
            es.push_back(L(name));
        } else if (k < 95) {
            es.push_back(M(name));
        } else {
            es.push_back({name, T::other});
        }
    }
    r.dir(path, std::move(es));
    r.ids[path] = {1, std::hash<std::string>{}(path) | 1};
    for (const auto& s : subdirs)
        if (g.below(20) != 0) // one in twenty is left unlistable: a dir_unreadable gap
            gen(r, g, walk_detail::join(path, s), depth + 1);
}

struct Concat {
    Strs visits;
    Strs gaps;
    std::size_t entries{0};
    std::size_t slices{0};
    bool ok{true};
};

/// Runs slices to completion, cutting by max_entries (kind 0), max_rows (1) or a fake-clock deadline of
/// `k` NEW listings per slice (2). Every non-complete slice must advance, forward, without a restart.
Concat run_sliced(Rig& r, int kind, std::size_t k) {
    Concat c;
    fsr::Position pos;
    r.fs.list_step = kind == 2 ? 1ms : 0ms;
    for (;;) {
        WalkLimits lim;
        std::chrono::milliseconds budget = 1h;
        if (kind == 0)
            lim.max_entries = k;
        else if (kind == 1)
            lim.max_rows = k;
        else
            budget = std::chrono::milliseconds(pos.dirs.size() + 1 + k); // the resume path re-reads this many
        r.visits.clear();
        const OrderedResult res = slice(r, pos, lim, budget);
        ++c.slices;
        c.entries += res.stats.entries;
        c.visits.insert(c.visits.end(), r.visits.begin(), r.visits.end());
        for (const auto& g : tokens(res))
            c.gaps.push_back(g);
        if (res.stop == Stop::complete)
            break;
        if (!res.advanced || res.restarted || !later(res.position, pos) || c.slices > 100000) {
            c.ok = false;
            break;
        }
        pos = res.position;
    }
    r.fs.list_step = 0ms;
    return c;
}

} // namespace

TEST_CASE("walk_ordered: the identity members are appended and defaulted",
          "[walk_ordered][file_search][component_walk]") {
    const DirEntry e{"x", T::file}; // positional and braced uses of the seam still compile
    CHECK(e.file_id == 0);
    const ListResult lr{};
    CHECK(lr.dev == 0);
    CHECK(lr.file_id == 0);
    CHECK(to_token(Cause::depth) == "depth");
    CHECK(to_token(Cause::dir_unreadable) == "dir_unreadable");
    CHECK(to_token(Cause::dir_truncated) == "dir_truncated");
    CHECK(to_token(Cause::other_device) == "other_device");
    CHECK(to_token(Cause::network_mount) == "network_mount");
    CHECK(to_token(Cause::memory_cap) == "memory_cap");
}

TEST_CASE("walk_ordered: visits arrive sorted by name bytes, depth first, a directory before its entries",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    // Listed out of order; "\xc3\xa9" sorts after every ASCII name, 'B' < '_' < 'a'.
    r.dir("/r", {F("a"), D("sub"), F("\xc3\xa9"), F("_"), L("lnk"), F("B"), {"dev", T::other}, F("."), F(""), F("..")});
    r.dir("/r/sub", {F("z"), D("in"), F("m")});
    r.dir("/r/sub/in", {F("q")});

    const auto res = slice(r, {}, {});

    CHECK(res.stop == Stop::complete);
    CHECK(res.advanced);
    CHECK(!res.restarted);
    CHECK(r.visits == Strs{"/r/B", "/r/_", "/r/a", "/r/sub", "/r/sub/in", "/r/sub/in/q", "/r/sub/m",
                           "/r/sub/z", "/r/\xc3\xa9"});
    CHECK(res.rows == 9);
    // ".", ".." and "" are ignored and uncounted; the link and the other entry count.
    CHECK(res.stats.entries == 7 + 3 + 1);
    CHECK(res.stats.links_skipped == 1);
    CHECK(res.gaps.empty());
    CHECK(r.fs.total_opens == 0);
    CHECK(r.fs.listed == Strs{"/r", "/r/sub", "/r/sub/in"});
}

TEST_CASE("walk_ordered: the visitor sees the listed directory's device and each entry's file id",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {F("f"), D("d")});
    r.dir("/r/d", {F("g")});
    r.ids["/r"] = {3, 100};
    r.ids["/r/d"] = {3, 101};
    r.ids["/r/f"] = {0, 55};

    const auto res = slice(r, {}, {});

    CHECK(res.stop == Stop::complete);
    CHECK(r.dev_at["/r/f"] == 3);
    CHECK(r.dev_at["/r/d"] == 3);
    CHECK(r.dev_at["/r/d/g"] == 3);
    CHECK(r.id_at["/r/f"] == 55);
    CHECK(r.id_at["/r/d"] == 101);
    CHECK(res.position.root_dev == 3);
    CHECK(res.position.root_file_id == 100);
}

TEST_CASE("walk_ordered: resume equivalence over pseudo-random trees, cut by entries, rows and listings",
          "[walk_ordered][file_search][component_walk]") {
    std::size_t total_visits = 0;
    for (std::uint64_t seed = 1; seed <= 40; ++seed) {
        Rig r;
        Lcg g{seed * 7919};
        gen(r, g, "/r", 0);

        const Concat whole = run_sliced(r, 0, 100000); // one uncut run
        REQUIRE(whole.ok);
        REQUIRE(whole.slices == 1);
        const std::size_t n = std::max<std::size_t>(whole.entries, whole.visits.size());
        total_visits += whole.visits.size();

        for (int kind = 0; kind < 3; ++kind) {
            for (std::size_t k = 1; k <= n; ++k) {
                INFO("seed " << seed << " kind " << kind << " k " << k);
                const Concat cut = run_sliced(r, kind, k);
                REQUIRE(cut.ok);
                CHECK(cut.visits == whole.visits);
                CHECK(cut.gaps == whole.gaps);
                CHECK(cut.entries == whole.entries);
            }
        }
    }
    CHECK(total_visits >= 500); // the trees are big enough to exercise nesting and gaps
}

TEST_CASE("walk_ordered: a zero budget returns advanced false and the same position",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {D("a"), F("z")});
    r.dir("/r/a", {D("b")});
    r.dir("/r/a/b", {F("f1"), F("f2")});
    const fsr::Position mid{0, 0, {{"a", 0, 0}, {"b", 0, 0}}, "f1"};
    // After the last entry of a/b with sibling "z" still pending: re-reading the resume path would
    // complete b and a without admitting an entry, which must not read as progress on a zero budget.
    const fsr::Position tail{0, 0, {{"a", 0, 0}, {"b", 0, 0}}, "f2"};

    for (const auto& resume : {fsr::Position{}, mid, tail}) {
        WalkLimits no_entries;
        no_entries.max_entries = 0;
        auto res = slice(r, resume, no_entries);
        CHECK(res.stop == Stop::budget_entries);
        CHECK(!res.advanced);
        CHECK(res.position == resume);

        WalkLimits no_rows;
        no_rows.max_rows = 0;
        res = slice(r, resume, no_rows);
        CHECK(res.stop == Stop::section_rows);
        CHECK(!res.advanced);
        CHECK(res.position == resume);

        res = slice(r, resume, {}, 0ms); // the deadline is already now
        CHECK(res.stop == Stop::budget_time);
        CHECK(!res.advanced);
        CHECK(res.position == resume);
    }
    CHECK(r.visits.empty());
}

TEST_CASE("walk_ordered: a row cap on a directory's own row leaves the position inside it, unlisted",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {F("b"), D("a")});
    r.dir("/r/a", {F("x"), F("y")});
    r.ids["/r/a"] = {1, 10};

    WalkLimits lim;
    lim.max_rows = 1;
    const auto first = slice(r, {}, lim);

    CHECK(first.stop == Stop::section_rows);
    CHECK(r.visits == Strs{"/r/a"});
    CHECK(first.position.dirs == std::vector<fsr::Frame>{{"a", 0, 0}}); // not listed: identity unknown
    CHECK(first.position.after.empty());
    CHECK(first.advanced);
    CHECK(r.fs.listed == Strs{"/r"}); // the row cap fell before the directory was listed

    r.visits.clear();
    const auto rest = slice(r, first.position, {});
    CHECK(rest.stop == Stop::complete);
    CHECK(!rest.restarted); // identity 0/0 never reads as a replaced directory
    CHECK(r.visits == Strs{"/r/a/x", "/r/a/y", "/r/b"});
}

TEST_CASE("walk_ordered: a deadline between a directory's visit and its listing leaves it unlisted",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {D("a"), F("b")});
    r.dir("/r/a", {F("x")});
    r.ids["/r/a"] = {1, 10};
    r.hook = [&r](const std::string& p) {
        if (p == "/r/a")
            r.fs.clock += 1h;
    };

    const auto first = slice(r, {}, {}, 5s);

    CHECK(first.stop == Stop::budget_time);
    CHECK(r.visits == Strs{"/r/a"});
    CHECK(first.position.dirs == std::vector<fsr::Frame>{{"a", 0, 0}});
    CHECK(first.position.after.empty());
    CHECK(first.advanced);

    r.hook = nullptr;
    r.visits.clear();
    const auto rest = slice(r, first.position, {});
    CHECK(rest.stop == Stop::complete);
    CHECK(r.visits == Strs{"/r/a/x", "/r/b"});
}

TEST_CASE("walk_ordered: an entry budget before a directory's first entry carries its listed identity",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {D("a"), F("b")});
    r.dir("/r/a", {F("x")});
    r.ids["/r/a"] = {1, 10};

    WalkLimits lim;
    lim.max_entries = 1;
    const auto first = slice(r, {}, lim);

    CHECK(first.stop == Stop::budget_entries);
    CHECK(first.position.dirs == std::vector<fsr::Frame>{{"a", 1, 10}});
    CHECK(first.position.after.empty());
    CHECK(first.advanced);

    r.visits.clear();
    const auto rest = slice(r, first.position, {});
    CHECK(rest.stop == Stop::complete);
    CHECK(!rest.restarted);
    CHECK(r.visits == Strs{"/r/a/x", "/r/b"});
}

TEST_CASE("walk_ordered: the deadline is read before every entry of a flat listing",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    std::vector<DirEntry> es;
    Strs expected;
    for (int i = 999; i >= 0; --i) { // listed descending
        char name[8];
        std::snprintf(name, sizeof name, "e%03d", i);
        es.push_back(F(name));
    }
    for (int i = 0; i < 1000; ++i) {
        char name[16];
        std::snprintf(name, sizeof name, "/r/e%03d", i);
        expected.push_back(name);
    }
    r.dir("/r", std::move(es));
    r.hook = [&r](const std::string&) { r.fs.clock += 1ms; }; // a slow visitor

    fsr::Position pos;
    Strs all;
    std::size_t slices = 0;
    for (;; ++slices) {
        REQUIRE(slices < 20);
        r.visits.clear();
        const auto res = slice(r, pos, {}, 100ms);
        all.insert(all.end(), r.visits.begin(), r.visits.end());
        if (res.stop == Stop::complete)
            break;
        CHECK(res.stop == Stop::budget_time);
        CHECK(r.visits.size() == 100); // stopped at the 101st entry, not at the end of the listing
        CHECK(res.advanced);
        pos = res.position;
    }
    CHECK(slices == 9); // nine cut slices, the tenth completes
    CHECK(all == expected);
}

TEST_CASE("walk_ordered: a truncated listing is one gap and none of its entries is visited",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {D("a"), D("b"), F("c")});
    r.dir("/r/a", {F("1"), F("2"), F("3"), F("4"), F("5")});
    r.dir("/r/b", {F("k")});
    WalkLimits lim;
    lim.max_dir_entries = 3;

    const auto res = slice(r, {}, lim);

    CHECK(res.stop == Stop::complete);
    CHECK(tokens(res) == Strs{"dir_truncated /r/a"});
    CHECK(r.visits == Strs{"/r/a", "/r/b", "/r/b/k", "/r/c"});
}

TEST_CASE("walk_ordered: an unreadable directory is one gap and the walk goes on",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {D("a"), D("b")});
    r.dir("/r/b", {F("k")}); // /r/a has no listing: MemTree reports an error
    const auto res = slice(r, {}, {});

    CHECK(res.stop == Stop::complete);
    CHECK(tokens(res) == Strs{"dir_unreadable /r/a"});
    CHECK(r.visits == Strs{"/r/a", "/r/b", "/r/b/k"});
}

TEST_CASE("walk_ordered: a directory past max_depth is one depth gap",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {D("a"), F("z")});
    r.dir("/r/a", {D("deep"), F("f")});
    r.dir("/r/a/deep", {F("hidden")});
    WalkLimits lim;
    lim.max_depth = 1;

    const auto res = slice(r, {}, lim);

    CHECK(res.stop == Stop::complete);
    CHECK(tokens(res) == Strs{"depth /r/a/deep"});
    CHECK(r.visits == Strs{"/r/a", "/r/a/deep", "/r/a/f", "/r/z"}); // the entry is a row, its contents are not
    CHECK(r.fs.listed == Strs{"/r", "/r/a"});
}

TEST_CASE("walk_ordered: a network mount is one gap, counted, never visited or listed",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {M("m"), F("f")});
    const auto res = slice(r, {}, {});

    CHECK(res.stop == Stop::complete);
    CHECK(tokens(res) == Strs{"network_mount /r/m"});
    CHECK(res.stats.mounts_skipped == 1);
    CHECK(r.visits == Strs{"/r/f"});
    CHECK(r.fs.listed == Strs{"/r"});
}

TEST_CASE("walk_ordered: a directory on another device is one gap and none of its entries is visited",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {D("a"), D("b")});
    r.dir("/r/a", {F("x")});
    r.dir("/r/b", {F("y")});
    r.ids["/r"] = {1, 1};
    r.ids["/r/a"] = {2, 2};
    r.ids["/r/b"] = {1, 3};

    const auto res = slice(r, {}, {});

    CHECK(res.stop == Stop::complete);
    CHECK(tokens(res) == Strs{"other_device /r/a"});
    CHECK(r.visits == Strs{"/r/a", "/r/b", "/r/b/y"});
}

TEST_CASE("walk_ordered: unknown identities never trigger other_device or restarted",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {D("a")});
    r.dir("/r/a", {F("x"), F("y")});

    SECTION("root device unknown, child device known") {
        r.ids["/r/a"] = {5, 5};
        const auto res = slice(r, {}, {});
        CHECK(res.gaps.empty());
        CHECK(r.visits == Strs{"/r/a", "/r/a/x", "/r/a/y"});
    }
    SECTION("child device unknown, root device known") {
        r.ids["/r"] = {1, 1};
        const auto res = slice(r, {}, {});
        CHECK(res.gaps.empty());
        CHECK(r.visits.size() == 3);
    }
    SECTION("recorded frame unknown, listing known") {
        r.ids["/r/a"] = {1, 9};
        const auto res = slice(r, fsr::Position{0, 0, {{"a", 0, 0}}, "x"}, {});
        CHECK(!res.restarted);
        CHECK(r.visits == Strs{"/r/a/y"});
    }
    SECTION("recorded frame known, listing unknown") {
        const auto res = slice(r, fsr::Position{0, 0, {{"a", 1, 9}}, "x"}, {});
        CHECK(!res.restarted);
        CHECK(r.visits == Strs{"/r/a/y"});
    }
    SECTION("recorded root known, listing unknown") {
        const auto res = slice(r, fsr::Position{4, 4, {{"a", 0, 0}}, "x"}, {});
        CHECK(!res.restarted);
        CHECK(r.visits == Strs{"/r/a/y"});
    }
}

TEST_CASE("walk_ordered: a listing that does not fit max_retained_bytes is a memory_cap gap, siblings continue",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    std::vector<DirEntry> big;
    for (int i = 0; i < 50; ++i)
        big.push_back(F("file" + std::to_string(i)));
    r.dir("/r", {D("a"), D("b"), F("c"), D("d")});
    r.dir("/r/a", big);
    r.dir("/r/b", {F("k")});
    r.dir("/r/d", {F("n")});
    // Root and one small child fit together, the root and /r/a do not; /r/d fits only because /r/b's
    // charge was returned when the walk left it.
    const std::size_t cap = charge_of(r.fs.dirs["/r"]) + charge_of(r.fs.dirs["/r/b"]);
    REQUIRE(charge_of(big) + charge_of(r.fs.dirs["/r"]) > cap);

    const auto res = slice(r, {}, {}, 1h, cap);

    CHECK(res.stop == Stop::complete);
    CHECK(tokens(res) == Strs{"memory_cap /r/a"});
    CHECK(r.visits == Strs{"/r/a", "/r/b", "/r/b/k", "/r/c", "/r/d", "/r/d/n"});
    CHECK(res.retained_bytes_peak == cap); // /a's charge was never held

    // The root alone over the cap: nothing is entered at all.
    r.visits.clear();
    const auto none = slice(r, {}, {}, 1h, charge_of(r.fs.dirs["/r"]) - 1);
    CHECK(tokens(none) == Strs{"memory_cap /r"});
    CHECK(r.visits.empty());
    CHECK(none.retained_bytes_peak == 0);
}

TEST_CASE("walk_ordered: a chain of nested large directories never takes the peak over the cap",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    std::vector<std::string> paths{"/r"};
    for (int i = 0; i < 6; ++i)
        paths.push_back(paths.back() + "/d" + std::to_string(i));
    std::vector<std::size_t> charge;
    for (std::size_t i = 0; i < 6; ++i) {
        std::vector<DirEntry> es;
        for (int f = 0; f < 20; ++f)
            es.push_back(F("f" + std::to_string(100 + f)));
        es.push_back(D("d" + std::to_string(i)));
        charge.push_back(charge_of(es));
        r.dir(paths[i], std::move(es));
    }
    r.dir(paths[6], {F("tail")});
    // Levels 0..2 fit, level 3 is one byte over.
    const std::size_t cap = charge[0] + charge[1] + charge[2] + charge[3] - 1;

    const auto res = slice(r, {}, {}, 1h, cap);

    CHECK(res.stop == Stop::complete);
    CHECK(res.retained_bytes_peak <= cap);
    CHECK(res.retained_bytes_peak == charge[0] + charge[1] + charge[2]);
    CHECK(tokens(res) == Strs{"memory_cap " + paths[3]});
    const std::size_t visited_files = static_cast<std::size_t>(std::count_if(
        r.visits.begin(), r.visits.end(), [](const std::string& v) { return v.find("/f1") != std::string::npos; }));
    CHECK(visited_files == 3 * 20); // levels 0..2 only; level 3 and below never listed
    CHECK(r.fs.listed.size() == 4);
}

TEST_CASE("walk_ordered: a replaced directory restarts that subtree, and the position may go back",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {D("a"), F("b")});
    r.dir("/r/a", {F("x"), F("y"), F("z")});
    r.ids["/r/a"] = {1, 10};

    WalkLimits cut;
    cut.max_entries = 3; // a, x, y
    const auto first = slice(r, {}, cut);
    REQUIRE(first.position.dirs == std::vector<fsr::Frame>{{"a", 1, 10}});
    REQUIRE(first.position.after == "y");

    r.ids["/r/a"] = {1, 11}; // the directory was replaced between slices
    r.visits.clear();
    WalkLimits one;
    one.max_entries = 1;
    const auto second = slice(r, first.position, one);

    CHECK(second.restarted);
    CHECK(r.visits == Strs{"/r/a/x"}); // from its first entry again
    CHECK(second.position.dirs == std::vector<fsr::Frame>{{"a", 1, 11}});
    CHECK(second.position.after == "x");
    CHECK(earlier(second.position, first.position));
    CHECK(!second.advanced);

    r.visits.clear();
    const auto third = slice(r, second.position, {});
    CHECK(third.stop == Stop::complete);
    CHECK(!third.restarted);
    CHECK(r.visits == Strs{"/r/a/y", "/r/a/z", "/r/b"});
}

TEST_CASE("walk_ordered: a directory whose device alone changed is replaced, not resumed past",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {D("a"), F("b")});
    r.dir("/r/a", {F("x"), F("y"), F("z")});
    r.ids["/r/a"] = {1, 10}; // the root's device stays unknown, so this is no other_device gap

    WalkLimits cut;
    cut.max_entries = 3; // a, x, y
    const auto first = slice(r, {}, cut);
    REQUIRE(first.position.dirs == std::vector<fsr::Frame>{{"a", 1, 10}});
    REQUIRE(first.position.after == "y");

    r.ids["/r/a"] = {2, 10}; // same file id, another device
    r.visits.clear();
    WalkLimits one;
    one.max_entries = 1;
    const auto second = slice(r, first.position, one);

    CHECK(second.restarted);
    CHECK(r.visits == Strs{"/r/a/x"}); // from its first entry again, never on from "y"
    CHECK(second.position.dirs == std::vector<fsr::Frame>{{"a", 2, 10}});
    CHECK(earlier(second.position, first.position));
}

TEST_CASE("walk_ordered: a directory deleted between slices continues at the next greater sibling",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {D("b"), F("c"), F("0")});
    r.dir("/r/b", {F("x")});
    const fsr::Position inside_a{0, 0, {{"a", 0, 0}}, "m"}; // "a" no longer exists

    const auto res = slice(r, inside_a, {});

    CHECK(res.stop == Stop::complete);
    CHECK(!res.restarted);
    CHECK(res.advanced);
    CHECK(r.visits == Strs{"/r/b", "/r/b/x", "/r/c"}); // "0" < "a" was done; "b" and "c" are not skipped
    CHECK(r.fs.listed == Strs{"/r", "/r/b"});
}

TEST_CASE("walk_ordered: a directory replaced by a file is treated as new and visited",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {F("a"), F("b")});
    const auto res = slice(r, fsr::Position{0, 0, {{"a", 0, 0}}, "q"}, {});

    CHECK(r.visits == Strs{"/r/a", "/r/b"});
    CHECK(res.stop == Stop::complete);
    CHECK(r.fs.listed == Strs{"/r"});
}

TEST_CASE("walk_ordered: a changed root identity restarts the whole root",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {D("a"), F("b")});
    r.dir("/r/a", {F("x")});
    r.ids["/r"] = {1, 5};

    WalkLimits cut;
    cut.max_entries = 3; // a, x, b
    const auto first = slice(r, {}, cut);
    REQUIRE(first.stop == Stop::complete);

    const fsr::Position resume{1, 5, {{"a", 0, 0}}, "x"};
    r.ids["/r"] = {1, 6};
    r.visits.clear();
    const auto res = slice(r, resume, {});

    CHECK(res.restarted);
    CHECK(res.stop == Stop::complete);
    CHECK(r.visits == Strs{"/r/a", "/r/a/x", "/r/b"});

    // The same resume against the unchanged root continues past it.
    r.ids["/r"] = {1, 5};
    r.visits.clear();
    const auto same = slice(r, resume, {});
    CHECK(!same.restarted);
    CHECK(r.visits == Strs{"/r/b"});

    // A restart that is then cut returns the root's NEW identity in the position.
    r.ids["/r"] = {1, 6};
    WalkLimits one;
    one.max_entries = 1;
    const auto cutres = slice(r, resume, one);
    CHECK(cutres.restarted);
    CHECK(cutres.position.root_file_id == 6);
    CHECK(earlier(cutres.position, resume));
}

TEST_CASE("walk_ordered: a root whose device alone changed restarts the whole root",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {F("a"), F("b"), F("n")});
    r.ids["/r"] = {2, 5}; // the position below recorded device 1, same file id

    const fsr::Position resume{1, 5, {}, "m"};
    const auto res = slice(r, resume, {});

    CHECK(res.restarted);
    CHECK(res.stop == Stop::complete);
    CHECK(r.visits == Strs{"/r/a", "/r/b", "/r/n"}); // "a" and "b" sort below "m" and are searched again

    // A restart that is then cut returns the root's NEW device in the position.
    r.visits.clear();
    WalkLimits one;
    one.max_entries = 1;
    const auto cutres = slice(r, resume, one);
    CHECK(cutres.restarted);
    CHECK(r.visits == Strs{"/r/a"});
    CHECK(cutres.position.root_dev == 2);
    CHECK(cutres.position.root_file_id == 5);
    CHECK(earlier(cutres.position, resume));

    // The same position against the unchanged device continues past "m".
    r.ids["/r"] = {1, 5};
    r.visits.clear();
    const auto same = slice(r, resume, {});
    CHECK(!same.restarted);
    CHECK(r.visits == Strs{"/r/n"});
}

TEST_CASE("walk_ordered: a forged resume never lists a path that was not a directory entry of a real listing",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    r.dir("/r", {F("f"), L("l"), D("a"), F("m")});
    r.dir("/r/a", {F("x")});

    const std::vector<fsr::Position> forged{
        {0, 0, {{"ghost", 0, 0}}, ""},
        {0, 0, {{"f", 0, 0}}, ""},
        {0, 0, {{"l", 0, 0}}, ""},
        {0, 0, {{"zzz", 0, 0}}, ""},
        {0, 0, {{"..", 0, 0}}, ""},
        {0, 0, {{"a/x", 0, 0}}, ""},
        {0, 0, {{"a", 0, 0}, {"ghost", 0, 0}}, ""},
        {0, 0, {{"a", 0, 0}, {"x", 0, 0}, {"deeper", 0, 0}}, "q"},
    };
    for (const auto& p : forged) {
        r.fs.listed.clear();
        r.visits.clear();
        const auto res = slice(r, p, {});
        CHECK(res.stop == Stop::complete);
        // "a" is listed only when the walk reaches it: named by a frame, or not yet passed (a frame name
        // below it). A ghost, file, link or later name never adds a listing of its own.
        const bool reaches_a = !p.dirs.empty() && p.dirs[0].name <= "a";
        CHECK(r.fs.listed == (reaches_a ? Strs{"/r", "/r/a"} : Strs{"/r"}));
    }

    // A file frame is dropped and its entry is walked as new; "a" sorts below it and is skipped.
    r.fs.listed.clear();
    r.visits.clear();
    const auto res = slice(r, {0, 0, {{"f", 0, 0}}, ""}, {});
    CHECK(res.stop == Stop::complete);
    CHECK(r.visits == Strs{"/r/f", "/r/m"});
    CHECK(r.fs.listed == Strs{"/r"});
}

TEST_CASE("walk_ordered: listings re-read on the resume path are not charged to max_entries",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    Strs paths{"/r"};
    for (int i = 1; i <= 5; ++i)
        paths.push_back(paths.back() + "/d" + std::to_string(i));
    for (int i = 0; i < 5; ++i)
        r.dir(paths[i], {D("d" + std::to_string(i + 1)), F("z")});
    r.dir(paths[5], {F("one"), F("two"), F("three")});
    const fsr::Position deep{0, 0, {{"d1", 0, 0}, {"d2", 0, 0}, {"d3", 0, 0}, {"d4", 0, 0}, {"d5", 0, 0}}, ""};

    WalkLimits one;
    one.max_entries = 1;
    const auto res = slice(r, deep, one);

    CHECK(res.stop == Stop::budget_entries);
    CHECK(r.visits == Strs{"/r/d1/d2/d3/d4/d5/one"});
    CHECK(res.stats.entries == 1);
    CHECK(res.advanced);
    CHECK(res.position.dirs.size() == 5);
    CHECK(res.position.after == "one");
}

TEST_CASE("walk_ordered: gaps past kMaxOrderedGaps are counted and no file is ever opened",
          "[walk_ordered][file_search][component_walk]") {
    Rig r;
    std::vector<DirEntry> es;
    for (std::size_t i = 0; i < kMaxOrderedGaps + 5; ++i)
        es.push_back(M("m" + std::to_string(i)));
    r.dir("/r", std::move(es));

    const auto res = slice(r, {}, {});

    CHECK(res.stop == Stop::complete);
    CHECK(res.gaps.size() == kMaxOrderedGaps);
    CHECK(res.gaps_dropped == 5);
    CHECK(res.stats.mounts_skipped == kMaxOrderedGaps + 5);
    CHECK(r.fs.total_opens == 0);
}
