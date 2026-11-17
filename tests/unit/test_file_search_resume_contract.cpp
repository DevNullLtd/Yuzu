/**
 * test_file_search_resume_contract.cpp -- the resume contract of the on-demand file search, proven with
 * its pieces TOGETHER: walk_ordered (component_walk.hpp), the cursor and its transition validator
 * (file_search_cursor.hpp), the slice governor (file_search_governor.hpp) and the coverage envelope
 * (file_search_coverage.hpp). Each of them passes its own unit tests alone; this file exists because a
 * legitimate restart (a directory replaced between slices) was once refused by the validator while every
 * leaf was green. `Search` below drives a search the way the plugin will; no real clock, no real sleep,
 * no thread and no filesystem is used (MemTree and its fake clock only; open_file is never called).
 *
 * MUTATION NOTES (each case FAILS if the named production rule is removed):
 *  - case 2 (subtree replaced): strictly_advances losing its RESTART transition fails `advances` (the
 *    restarted slice returns an earlier position under generation + 1); record_slice counting a restarted
 *    slice as a stall fails consecutive_stalls == 0; next_cursor not stepping the generation on
 *    `restarted` fails generation == 1.
 *  - case 3 (root replaced): a RESTART transition that constrains the root identity fails `advances`.
 *  - case 4 (replay and backward): a RESTART transition that accepts an unchanged generation with a
 *    backward position fails the forged-cursor CHECK; accepting an equal or earlier position, or a
 *    repeated sequence, fails the replay CHECKs.
 *  - case 5 (restart loop): record_slice not counting restarts, or not making unstable sticky, fails the
 *    health sequence; max_restarts not consulted fails the unstable-at-the-third-restart step.
 *  - case 6 (stall): record_slice counting a stall only on some slices, or not making stalled sticky,
 *    fails the health sequence; the walker reading a listing on a zero budget fails the same-position check.
 *  - case 7 (coverage carried): CoverageEnvelope::complete() ignoring prior_gaps, or next_cursor dropping
 *    the slice's gap count (or its saturating sum), makes the final envelope read complete.
 *  - case 8 (tokens): any of the six OrderedGap::Cause spellings drifting from its GapCause twin fails.
 *  - case 1b (completing slice): the driver validating a cursor on the slice that completes the walk fails
 *    the row-cap sweep (max_rows landing on the root's final entry), the empty root and the unlistable
 *    root, where that slice returns the resume position itself; a completing slice issuing a cursor
 *    fails issued.size() == results.size().
 *  - case 1 (unchanged tree): any resume, advancement, round-trip or governor rule rejecting an ordinary
 *    transition fails here first; total_opens == 0 fails if a file is ever opened.
 */
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "component_fixture_tree.hpp"
#include "component_walk.hpp"

#include <file_search_coverage.hpp>
#include <file_search_cursor.hpp>
#include <file_search_governor.hpp>
#include <file_search_names.hpp>

#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using namespace yuzu::component_inventory;
using namespace yuzu::component_inventory::fixture;
using namespace std::chrono_literals;
namespace fsr = yuzu::shared::file_search;
using T = DirEntry::Type;

namespace {

constexpr fsr::QueryHash kHash{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

DirEntry D(std::string n) { return {std::move(n), T::dir}; }
DirEntry F(std::string n) { return {std::move(n), T::file}; }

fsr::GapCause gap_cause(OrderedGap::Cause c) {
    switch (c) {
    case OrderedGap::Cause::depth: return fsr::GapCause::depth;
    case OrderedGap::Cause::dir_unreadable: return fsr::GapCause::dir_unreadable;
    case OrderedGap::Cause::dir_truncated: return fsr::GapCause::dir_truncated;
    case OrderedGap::Cause::other_device: return fsr::GapCause::other_device;
    case OrderedGap::Cause::network_mount: return fsr::GapCause::network_mount;
    case OrderedGap::Cause::memory_cap: return fsr::GapCause::memory_cap;
    }
    return fsr::GapCause::depth;
}

fsr::Reason reason_of(Stop s) {
    switch (s) {
    case Stop::complete: return fsr::Reason::none;
    case Stop::budget_entries: return fsr::Reason::budget_entries;
    case Stop::budget_time: return fsr::Reason::budget_time;
    case Stop::section_rows: return fsr::Reason::budget_rows;
    default: return fsr::Reason::unsupported;
    }
}

/// One search driven the way the plugin drives it. Not movable: the closures capture `this`.
struct Search {
    MemTree fs;
    std::map<std::string, std::pair<std::uint64_t, std::uint64_t>> ids; // dir path -> (dev, file id)
    std::uint64_t next_id{10};
    WalkLimits wl;
    fsr::GovernorLimits gl;
    fsr::GovernorState gov;
    fsr::Cursor cursor{kHash};
    std::vector<fsr::Cursor> issued{cursor}; // every cursor of the search, the first included
    std::vector<OrderedResult> results;
    std::vector<fsr::CoverageEnvelope> envs;
    std::vector<std::string> visits;
    std::vector<std::size_t> first_visit; // visits.size() when each slice began
    std::chrono::milliseconds visit_step{0};
    std::function<void(std::size_t slice)> before; // the world changes between slices here
    bool done{false};

    void dir(const std::string& path, std::vector<DirEntry> entries) {
        fs.dirs[path] = std::move(entries);
        ids[path] = {1, next_id++};
    }

    void step() {
        if (before)
            before(results.size());
        first_visit.push_back(visits.size());
        fsr::SliceGovernor g(gl, {[this] { return fs.clock; }, [this](std::chrono::milliseconds d) { fs.clock += d; }});
        FsOps ops = fs.ops();
        const auto inner = ops.list;
        ops.list = [this, &g, inner](const std::string& d, std::size_t cap) {
            g.pace();
            ListResult r = inner(d, cap); // the identity-stamping decorator over MemTree
            if (const auto it = ids.find(d); it != ids.end())
                std::tie(r.dev, r.file_id) = it->second;
            for (auto& e : r.entries)
                if (const auto it = ids.find(walk_detail::join(d, e.name)); it != ids.end())
                    e.file_id = it->second.second;
            return r;
        };
        const OrderedVisit visit = [this, &g](const std::string& d, const DirEntry& e, std::uint64_t) {
            g.pace();
            visits.push_back(walk_detail::join(d, e.name));
            fs.clock += visit_step;
            return true;
        };
        OrderedResult res = walk_ordered("/r", cursor.position, wl, ops, g.deadline(), visit);
        REQUIRE(fs.total_opens == 0);
        gov = fsr::record_slice(gov, gl, res.advanced, res.restarted);

        fsr::CoverageEnvelope env;
        env.prior_gaps = cursor.prior_gaps;
        env.has_cursor = res.stop != Stop::complete;
        env.slices = static_cast<std::uint32_t>(results.size() + 1);
        fsr::VolumeCoverage v;
        v.mount_point = "/r";
        v.fstype = "memfs";
        v.state = res.stop == Stop::complete ? fsr::VolumeState::complete : fsr::VolumeState::partial;
        v.reason = reason_of(res.stop);
        env.volumes.push_back(v);
        for (const auto& og : res.gaps)
            env.add_gap({og.path, gap_cause(og.cause)});
        env.gaps_dropped = res.gaps_dropped;
        REQUIRE(env.valid());

        // A slice that leaves a cursor and is not a stall issues the next one. A slice that completes the
        // walk issues none (there is nothing to resume), so its position is never validated: it may be the
        // resume position itself (the row cap landing on the final entry, an empty or unlistable root).
        if (res.stop != Stop::complete && (res.advanced || res.restarted)) {
            const fsr::Cursor next =
                fsr::next_cursor(cursor, res.position, res.restarted, res.gaps.size() + res.gaps_dropped);
            REQUIRE(fsr::strictly_advances(cursor, next));
            const auto back = fsr::decode_cursor(fsr::encode_cursor(next), kHash);
            REQUIRE(back.has_value());
            REQUIRE(*back == next);
            cursor = next;
            issued.push_back(next);
        } // a stall or a completing slice issues nothing: the caller retries `cursor` or is done
        done = res.stop == Stop::complete;
        envs.push_back(std::move(env));
        results.push_back(std::move(res));
    }

    void run(std::size_t max_slices = 60) {
        while (!done && results.size() < max_slices)
            step();
        REQUIRE(done);
    }

    std::vector<std::string> tail(std::size_t from_slice) const {
        return {visits.begin() + static_cast<std::ptrdiff_t>(first_visit[from_slice]), visits.end()};
    }
};

void basic_tree(Search& s) {
    s.dir("/r", {D("a"), F("b"), D("c"), F("d")});
    s.dir("/r/a", {F("f1"), F("f2"), D("s")});
    s.dir("/r/a/s", {F("g1"), F("g2")});
    s.dir("/r/c", {F("h1")});
}

// X ends with entries after "z" so a slice can stop inside X right after X/z.
void x_tree(Search& s) {
    s.dir("/r", {D("X"), F("Y")});
    s.dir("/r/X", {F("a"), F("m"), F("z"), F("zz")});
}

} // namespace

TEST_CASE("resume contract: an unchanged tree cut by entries, rows or the deadline is one ordinary search",
          "[file_search][walk_ordered][resume_contract]") {
    Search ref;
    basic_tree(ref);
    ref.run();
    REQUIRE(ref.visits.size() == 10);
    REQUIRE(ref.results.size() == 1);

    Search s;
    basic_tree(s);
    Stop expect = Stop::budget_entries;
    SECTION("entries") { s.wl.max_entries = 3; }
    SECTION("rows") {
        s.wl.max_rows = 3;
        expect = Stop::section_rows;
    }
    SECTION("fake-clock deadline") {
        s.gl.slice = 25ms;
        s.visit_step = 10ms;
        expect = Stop::budget_time;
    }
    s.run();
    CHECK(s.results.size() > 2);
    CHECK(s.results.front().stop == expect);
    REQUIRE(s.issued.size() == s.results.size()); // the completing slice issues no cursor
    for (std::size_t i = 0; i < s.results.size(); ++i) {
        CHECK_FALSE(s.results[i].restarted);
        CHECK(s.results[i].advanced);
        if (i + 1 < s.issued.size()) {
            CHECK(s.issued[i + 1].generation == 0);
            CHECK(s.issued[i + 1].sequence == i + 1);
        }
    }
    CHECK(s.gov.health == fsr::Health::ok);
    CHECK(s.gov.restarts == 0);
    CHECK(s.visits == ref.visits);
    CHECK(s.envs.back().complete());
    CHECK_FALSE(s.envs.front().complete());
}

TEST_CASE("resume contract: a subtree replaced between slices is a legitimate restart",
          "[file_search][walk_ordered][resume_contract]") {
    Search s;
    x_tree(s);
    s.wl.max_entries = 4;
    s.step(); // X, X/a, X/m, X/z: the slice ends INSIDE X, after z
    REQUIRE(s.results[0].stop == Stop::budget_entries);
    const fsr::Cursor before = s.cursor;
    REQUIRE(before.position.dirs.size() == 1);
    REQUIRE(before.position.after == "z");

    s.ids["/r/X"].second = 99; // X is replaced: new identity, new contents
    s.fs.dirs["/r/X"] = {F("a"), F("b"), F("m"), F("z"), F("zz")};
    s.wl.max_entries = 1;
    s.step(); // visits X/a and exhausts the budget
    const OrderedResult& r = s.results[1];
    CHECK(r.restarted);
    CHECK_FALSE(r.advanced);
    CHECK(std::is_lt(fsr::walk_order(s.cursor.position, before.position))); // earlier than the previous
    CHECK(s.cursor.generation == before.generation + 1);
    CHECK(fsr::strictly_advances(before, s.cursor)); // `advances`
    CHECK(s.gov.consecutive_stalls == 0);
    CHECK(s.gov.restarts == 1);
    CHECK(s.gov.health == fsr::Health::ok);

    s.wl.max_entries = 100;
    s.run();
    for (std::size_t i = 2; i < s.results.size(); ++i) {
        CHECK_FALSE(s.results[i].restarted);
        if (i + 1 < s.issued.size())
            CHECK(s.issued[i + 1].generation == 1);
    }
    CHECK(s.tail(1) == std::vector<std::string>{"/r/X/a", "/r/X/b", "/r/X/m", "/r/X/z", "/r/X/zz", "/r/Y"});
    CHECK(s.gov.health == fsr::Health::ok);
}

TEST_CASE("resume contract: a root replaced between slices is a legitimate restart",
          "[file_search][walk_ordered][resume_contract]") {
    Search ref;
    x_tree(ref);
    ref.run();

    Search s;
    x_tree(s);
    s.wl.max_entries = 4;
    s.step();
    const fsr::Cursor before = s.cursor;
    REQUIRE(before.position.root_file_id == s.ids["/r"].second);

    s.ids["/r"].second = 99; // a different root identity across the transition
    s.wl.max_entries = 1;
    s.step(); // the whole root starts again: X's own row, then the budget
    CHECK(s.results[1].restarted);
    CHECK(s.cursor.position.root_file_id == 99);
    CHECK(s.cursor.position.root_file_id != before.position.root_file_id);
    CHECK(std::is_lt(fsr::walk_order(s.cursor.position, before.position)));
    CHECK(s.cursor.generation == before.generation + 1);
    CHECK(fsr::strictly_advances(before, s.cursor)); // `advances`
    CHECK(s.gov.consecutive_stalls == 0);

    s.wl.max_entries = 100;
    s.run();
    for (std::size_t i = 2; i < s.results.size(); ++i)
        CHECK_FALSE(s.results[i].restarted);
    CHECK(s.tail(1) == ref.visits); // every entry of the new root is visited
    CHECK(s.gov.health == fsr::Health::ok);
}

TEST_CASE("resume contract: a slice that completes the walk issues no cursor, wherever the cut falls",
          "[file_search][walk_ordered][resume_contract]") {
    Search ref;
    basic_tree(ref);
    ref.run();
    REQUIRE(ref.visits.size() == 10);

    SECTION("the row cap lands on every entry, the root's final one included") {
        const int cap = GENERATE(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        Search s;
        basic_tree(s);
        s.wl.max_rows = static_cast<std::size_t>(cap);
        s.run();
        CHECK(s.gov.health == fsr::Health::ok);
        CHECK(s.visits == ref.visits);
        CHECK(s.results.back().stop == Stop::complete);
        CHECK(s.issued.size() == s.results.size());
        CHECK(s.envs.back().complete());
    }
    SECTION("an empty root") {
        Search s;
        s.dir("/r", {});
        s.run();
        CHECK(s.gov.health == fsr::Health::ok);
        CHECK(s.visits.empty());
        CHECK(s.results.size() == 1);
        CHECK(s.issued.size() == 1);
        CHECK(s.envs.back().complete());
    }
    SECTION("a root that cannot be listed is one dir_unreadable gap and a partial envelope") {
        Search s; // "/r" is never registered, so its listing fails
        s.run();
        CHECK(s.gov.health == fsr::Health::ok);
        CHECK(s.visits.empty());
        CHECK(s.results.size() == 1);
        CHECK(s.issued.size() == 1);
        REQUIRE(s.results[0].gaps.size() == 1);
        CHECK(s.results[0].gaps[0].cause == OrderedGap::Cause::dir_unreadable);
        CHECK_FALSE(s.envs.back().complete());
        CHECK(fsr::format_coverage_rows(s.envs.back()).back() ==
              "coverage|partial|slices=1|prior_gaps=0|consistency=single_pass");
    }
}

TEST_CASE("resume contract: replays and backward steps are never accepted",
          "[file_search][walk_ordered][resume_contract]") {
    Search s;
    basic_tree(s);
    s.wl.max_entries = 2;
    s.run();
    REQUIRE(s.issued.size() >= 5);
    for (std::size_t i = 1; i < s.issued.size(); ++i) {
        CHECK(fsr::strictly_advances(s.issued[i - 1], s.issued[i]));
        CHECK_FALSE(fsr::strictly_advances(s.issued[i], s.issued[i - 1]));
        CHECK_FALSE(fsr::strictly_advances(s.issued[i - 1], s.issued[i - 1]));
        CHECK_FALSE(fsr::strictly_advances(s.issued[i], s.issued[i]));
    }
    // An earlier position under the SAME generation: the next sequence number does not make it legal.
    const fsr::Cursor forged = fsr::next_cursor(s.issued[3], s.issued[2].position, false, 0);
    REQUIRE(forged.generation == s.issued[3].generation);
    REQUIRE(std::is_lt(fsr::walk_order(forged.position, s.issued[3].position)));
    CHECK_FALSE(fsr::strictly_advances(s.issued[3], forged));
}

TEST_CASE("resume contract: a directory replaced before every slice ends unstable and stays there",
          "[file_search][walk_ordered][resume_contract]") {
    Search s;
    s.dir("/r", {D("X")});
    s.dir("/r/X", {F("f1"), F("f2"), F("f3"), F("f4"), F("f5"), F("f6"), F("f7"), F("f8")});
    s.wl.max_entries = 2;
    s.before = [&s](std::size_t slice) {
        if (slice > 0)
            s.ids["/r/X"].second = 100 + slice;
    };
    for (unsigned i = 1; i <= 6; ++i) {
        s.step(); // every transition is a valid restart; the governor alone ends the search
        if (i > 1)
            CHECK(s.results.back().restarted);
        CHECK(s.gov.consecutive_stalls == 0);
        CHECK(s.gov.health == (i >= 4 ? fsr::Health::unstable : fsr::Health::ok)); // max_restarts = 3
    }
    CHECK(s.gov.restarts == 5);
    CHECK(s.cursor.generation == 5);
}

TEST_CASE("resume contract: zero-budget slices stall, issue no cursor and end stalled",
          "[file_search][walk_ordered][resume_contract]") {
    const bool rows = GENERATE(false, true);
    Search s;
    basic_tree(s);
    s.wl.max_entries = 3;
    s.step(); // one real slice so the cursor holds a position
    const fsr::Cursor held = s.cursor;
    REQUIRE_FALSE(held.position.dirs.empty());
    (rows ? s.wl.max_rows : s.wl.max_entries) = 0;
    for (unsigned i = 1; i <= 4; ++i) {
        s.step();
        const OrderedResult& r = s.results.back();
        CHECK(r.stop == (rows ? Stop::section_rows : Stop::budget_entries));
        CHECK_FALSE(r.advanced);
        CHECK_FALSE(r.restarted);
        CHECK(r.position == held.position); // the same position
        CHECK(s.issued.size() == 2);        // no new cursor: the driver retries the previous one
        CHECK(s.cursor == held);
        CHECK(s.gov.consecutive_stalls == i);
        CHECK(s.gov.health == (i >= 3 ? fsr::Health::stalled : fsr::Health::ok)); // max_stalls = 3
    }
    CHECK(s.gov.restarts == 0);
}

TEST_CASE("resume contract: a gap in an early slice keeps the final envelope partial",
          "[file_search][walk_ordered][resume_contract]") {
    const auto tree = [](Search& s, bool unreadable) {
        s.dir("/r", {D("a"), D("b"), F("z")});
        s.dir("/r/b", {F("b1"), F("b2"), F("b3")});
        if (!unreadable)
            s.dir("/r/a", {F("a1")});
        s.wl.max_entries = 2;
    };
    const auto last_row = [](const Search& s) { return fsr::format_coverage_rows(s.envs.back()).back(); };

    Search s;
    tree(s, true);
    s.run();
    REQUIRE(s.results.size() > 2);
    REQUIRE(s.results[0].gaps.size() == 1);
    bool gap_row = false;
    for (const auto& row : fsr::format_coverage_rows(s.envs[0]))
        gap_row = gap_row || row == "gap|" + fsr::encode_name("/r/a") + "|dir_unreadable";
    CHECK(gap_row);
    for (std::size_t i = 1; i < s.results.size(); ++i) {
        CHECK(s.results[i].gaps.empty()); // slice-local: later slices have no gap of their own
        if (i + 1 < s.issued.size())
            CHECK(s.issued[i + 1].prior_gaps == 1);
    }
    const fsr::CoverageEnvelope& fin = s.envs.back();
    CHECK(fin.gaps.empty());
    CHECK_FALSE(fin.has_cursor);
    CHECK(fin.prior_gaps >= 1);
    CHECK_FALSE(fin.complete());
    CHECK(last_row(s) == "coverage|partial|slices=" + std::to_string(s.results.size()) +
                             "|prior_gaps=1|consistency=not_a_snapshot");

    Search clean;
    tree(clean, false);
    clean.run();
    REQUIRE(clean.results.size() > 2);
    CHECK(clean.envs.back().complete());
    CHECK(last_row(clean) == "coverage|complete|slices=" + std::to_string(clean.results.size()) +
                                 "|prior_gaps=0|consistency=not_a_snapshot");
}

TEST_CASE("resume contract: every OrderedGap cause spells the token of its GapCause twin",
          "[file_search][walk_ordered][resume_contract]") {
    using C = OrderedGap::Cause;
    constexpr C all[] = {C::depth, C::dir_unreadable, C::dir_truncated,
                         C::other_device, C::network_mount, C::memory_cap};
    for (const C c : all)
        CHECK(std::string(to_token(c)) == fsr::to_token(gap_cause(c)));
    CHECK(std::size(all) == 6);
}
