/**
 * test_file_search_driver.cpp -- the request parser, the in-memory state and the one-slice driver of the
 * on-demand file search plugin (agents/plugins/file_search/src/file_search_{request,state,driver}.hpp),
 * proven over fakes only: an in-memory tree with a fake clock (MemTree), a mount table parsed from text, a
 * fake bounded runner and fake legs. No real filesystem, process, thread, clock or sleep is used; a
 * "worker that never returns" is a work function the fake runner keeps and never calls.
 *
 * MUTATION NOTES (each case FAILS if the named production rule is removed):
 *  - controls: a depth bound, a missing scope tag or a walk that skips the user directory fails the
 *    positive-control cases; matching a directory under files-only (or the reverse) fails the kinds case.
 *  - resume: a cursor that moves past an unsearched entry, or a volume advance that skips a unit, fails
 *    the cut-equals-uncut cases and the randomised sweep.
 *  - pruning: listing a pruned or refused mount point, opening a file beneath one, or opening anything on
 *    the far side of a network mount fails the access assertions (the fake leg erases pruned entries
 *    exactly as the real search leg does and records what was listed and opened).
 *  - refused rows: emitting one twice, with another reason, or not counting it into the verdict fails the
 *    refused cases; treating a refused mount's appearance as the end of the search fails the churn case;
 *    the macOS data volume under '/' stated as not_searched instead of partial fails the macOS case.
 *  - resumed root: a resumed slice whose unit root cannot be listed that ends with a cursor, no gap, or a
 *    complete verdict fails the resumed-root case.
 *  - single flight: the busy answer calling the runner or touching the state, or a release by anything but
 *    the slice that took the slot, fails the busy, late-completion and two-abandoned cases.
 *  - stall: a timeout not recorded as abandoned, a volume read as stalled after its worker returned, or a
 *    stall count shared between cursors fails the timeout, late-completion and lineage cases; a thrown worker read
 *    as a timeout fails the thrown case; a terminal verdict kept in the state (a later search of the same query
 *    inheriting `stalled`) fails the state case and the fresh-search case.
 *  - cancel: a stop request whose slice carries state, issues a cursor, or reads as anything but a
 *    partial, cancelled volume fails the cancelled case.
 *  - limits and caps: a governor built from invalid limits, a sequence past kMaxSlices, a per-directory
 *    match cap or a byte budget that drops a row instead of ending the slice fails its own case.
 *  - cursor: issuing a cursor the validator refuses, or one with no spelling, fails the unencodable case;
 *    emitting the walk position's names readable in a cursor row fails the no-name case.
 */
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "component_fixture_tree.hpp"
#include "file_search_driver.hpp"
#include "file_search_test_support.hpp"

#include <base64.hpp>
#include <bounded_wait.hpp>
#include <file_search_names.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yuzu::file_search;
using namespace yuzu::component_inventory::fixture;
using namespace yuzu::file_search_test;
namespace fsr = yuzu::shared::file_search;
using Type = yuzu::component_inventory::DirEntry::Type;
using yuzu::component_inventory::DirEntry;
using yuzu::component_inventory::ListResult;

namespace {

/// A fixed cursor key for the rig; `other` makes a key the agent under test does not hold.
CursorKey test_key(unsigned char fill = 0x42) {
    CursorKey k{};
    k.fill(fill);
    return k;
}

// ---- the world ----

struct Rig {
    MemTree fs;
    Mounts mounts;
    SearchState state;
    std::atomic<bool> slot{false};
    Boundaries b;

    // what the world did
    int mount_reads{0};
    int runner_calls{0};
    std::vector<std::string> legs;          // walk root of every leg built
    std::vector<std::string> facts_calls;   // every path facts() was asked about
    std::set<std::string> pruned_erased;    // pruned entries a leg removed from a listing
    std::set<std::string> link_paths;
    std::chrono::milliseconds last_timeout{};
    std::map<std::string, std::uint64_t> devs;
    std::uint64_t bump{0};

    // faults and hooks
    enum class Mode { run, timeout, reject, replace } mode{Mode::run};
    std::function<WorkResult()> held;               // the work of a worker the runner left behind
    std::function<void()> during_run;               // runs inside the runner, before the work
    std::function<WorkResult()> replacement;        // Mode::replace: what the runner hands back
    std::function<void(const std::string&)> facts_hook;
    std::function<void(const std::string&)> list_hook;
    // Replaces the leg's facts for an entry (extents state, notes); sees the listed entry like the real leg.
    std::function<FileFacts(const std::string& dir, const DirEntry& entry)> facts_override;
    std::map<std::string, std::uint64_t> hints_seen; // path -> the leg_hint facts() was handed
    std::function<std::vector<std::string>(const Unit&)> user_roots_fn;
    int user_root_reads{0};
    bool bump_root_identity{false};

    Rig() : b{.state = state, .slot = slot} {
        b.read_mounts = [this](const std::string&) {
            ++mount_reads;
            return std::optional<yuzu::shared::MountTable>(mounts.table());
        };
        b.make_leg = [this](const Unit& u) { return leg_for(u); };
        b.read_user_roots = [this](const Unit& u) {
            ++user_root_reads;
            return user_roots_fn ? user_roots_fn(u) : std::vector<std::string>{};
        };
        b.run_bounded = [this](std::chrono::milliseconds t, std::function<WorkResult()> work) {
            return run(t, std::move(work));
        };
        b.now = [this] { return fs.clock; };
        b.sleep = [this](std::chrono::milliseconds d) { fs.clock += d; };
        b.cursor_key = test_key();
        fs.add_dir("/r");
        mounts.add("/", "ext4", "8:1");
    }
    Rig(const Rig&) = delete;
    Rig& operator=(const Rig&) = delete;

    static std::uint64_t id_of(const std::string& path) {
        return (std::hash<std::string>{}(path) & 0x7fffffffffffULL) | 1;
    }

    RunOutcome<WorkResult> run(std::chrono::milliseconds t, std::function<WorkResult()> work) {
        ++runner_calls;
        last_timeout = t;
        if (during_run)
            during_run();
        switch (mode) {
        case Mode::reject:
            return {RunStatus::rejected, std::nullopt};
        case Mode::timeout:
            held = std::move(work);
            return {RunStatus::timed_out, std::nullopt};
        case Mode::replace:
            return {RunStatus::completed, replacement()};
        case Mode::run:
            break;
        }
        return {RunStatus::completed, work()};
    }

    UnitLeg leg_for(const Unit& u) {
        legs.push_back(u.walk_root);
        const auto [it, fresh] = devs.try_emplace(u.mount_point, 100 + devs.size());
        const std::uint64_t dev = it->second;
        const std::set<std::string> prune(u.prune.begin(), u.prune.end());
        UnitLeg l;
        l.ops = fs.ops();
        l.ops.list = [this, inner = l.ops.list, prune, dev](const std::string& d, std::size_t cap) {
            if (list_hook)
                list_hook(d);
            ListResult r = inner(d, cap);
            if (r.error)
                return r;
            r.dev = dev;
            r.file_id = bump_root_identity && d == "/r" ? ++bump : id_of(d);
            std::erase_if(r.entries, [&](const DirEntry& e) {
                const std::string p = yuzu::component_inventory::walk_detail::join(d, e.name);
                if (!prune.contains(p))
                    return false;
                pruned_erased.insert(p);
                return true;
            });
            for (auto& e : r.entries)
                e.file_id = id_of(yuzu::component_inventory::walk_detail::join(d, e.name));
            return r;
        };
        l.facts = [this](const std::string& dir, const DirEntry& entry) {
            const std::string p = yuzu::component_inventory::walk_detail::join(dir, entry.name);
            facts_calls.push_back(p);
            hints_seen[p] = entry.leg_hint;
            if (facts_hook)
                facts_hook(p);
            if (facts_override)
                return facts_override(dir, entry);
            FileFacts f;
            f.extents.state = ExtentsState::failed; // the leg owns its extents state: failed unless it read them
            const auto it = fs.files.find(p);
            if (it == fs.files.end())
                return f;
            f.facts.opened = true;
            f.facts.size = it->second.size();
            f.facts.mtime = MemTree::kDefaultMtime;
            f.extents = {};
            f.extents.state = ExtentsState::ok;
            f.extents.add({0, 4096, 4096, 0});
            return f;
        };
        l.root_state = [this](const std::string& path) {
            if (link_paths.contains(path))
                return yuzu::component_inventory::RootState::is_link;
            if (fs.dirs.contains(path))
                return yuzu::component_inventory::RootState::ok;
            if (fs.files.contains(path))
                return yuzu::component_inventory::RootState::not_a_directory;
            return yuzu::component_inventory::RootState::not_found;
        };
        return l;
    }

    void link(const std::string& path) {
        fs.add_link(path);
        link_paths.insert(path);
    }
    // A bulk add that does not scan the parent for a duplicate.
    void bulk_file(const std::string& dir, const std::string& name) {
        fs.dirs[dir].push_back({name, Type::file});
        fs.files[dir + "/" + name] = "";
    }
    void remove_file(const std::string& path) {
        const auto slash = path.rfind('/');
        auto& list = fs.dirs[path.substr(0, slash)];
        std::erase_if(list, [&](const DirEntry& e) { return e.name == path.substr(slash + 1); });
        fs.files.erase(path);
    }
    [[nodiscard]] VolumePlan plan(const std::string& root = "/r", Os os = Os::linux_os) const {
        return build_plan(mounts.table(), root, os);
    }
};

Request make_request(const std::string& pattern, const std::string& root = "/r", const std::string& kinds = "files",
                     const std::string& cursor = "", const fsr::NameSemantics& sem = fsr::byte_exact()) {
    auto r = parse_request(root, pattern, kinds, cursor, sem);
    REQUIRE(r.has_value());
    return std::move(*r);
}

/// Every driver answer has one shape, whatever happened: matches and the coverage block first, one
/// `cursor` row when (and only when) a cursor is issued, and ONE `search` trailer, last. An invalid or busy
/// answer is the trailer alone. Every slice in this file runs through here, so a rule that moves a row,
/// doubles one or drops the coverage block fails whichever case ran it.
SliceResult checked_slice(const Request& req, Boundaries& b) {
    SliceResult r = run_slice(req, b);
    const auto count = [&r](const std::string& prefix) {
        return static_cast<std::size_t>(std::ranges::count_if(r.rows, [&](const std::string& row) { return starts(row, prefix); }));
    };
    REQUIRE_FALSE(r.rows.empty());
    CHECK(starts(r.rows.back(), "search|"));
    CHECK(count("search|") == 1);
    CHECK(count("coverage|") == (r.rows.size() == 1 ? 0u : 1u)); // the trailer alone, or one coverage row
    if (r.status == Status::invalid || r.status == Status::busy)
        CHECK(r.rows.size() == 1);
    CHECK(count("cursor|") == (r.cursor.empty() ? 0u : 1u));
    if (!r.cursor.empty() && r.rows.size() >= 2)
        CHECK(r.rows[r.rows.size() - 2] == "cursor|" + r.cursor); // the row before the trailer, with the token
    return r;
}

struct Run {
    std::vector<SliceResult> slices;
    [[nodiscard]] const SliceResult& last() const { return slices.back(); }
};

/// Runs slices, following each cursor, until one ends the search (no cursor) or `before` is exhausted.
Run search(Rig& rig, const std::string& pattern, const std::string& root = "/r", const std::string& kinds = "files",
           const std::function<void(std::size_t slice)>& before = {}, std::size_t max_slices = 400) {
    Run run;
    std::string cursor;
    while (run.slices.size() < max_slices) {
        if (before)
            before(run.slices.size());
        SliceResult r = checked_slice(make_request(pattern, root, kinds, cursor), rig.b);
        cursor = r.cursor;
        run.slices.push_back(std::move(r));
        if (run.last().status != Status::ok || cursor.empty())
            break;
    }
    return run;
}

std::vector<std::string> found(const Run& run) {
    std::vector<std::string> out;
    for (const auto& s : run.slices)
        for (const auto& row : s.rows)
            if (starts(row, "match|")) {
                const auto d = fsr::decode_name(split(row)[1]);
                REQUIRE(d.has_value());
                out.push_back(*d);
            }
    return out;
}

std::size_t count_rows(const Run& run, const std::string& prefix) {
    std::size_t n = 0;
    for (const auto& s : run.slices)
        for (const auto& row : s.rows)
            n += starts(row, prefix) ? 1 : 0;
    return n;
}

std::string row_of(const SliceResult& s, const std::string& prefix) {
    for (const auto& r : s.rows)
        if (starts(r, prefix))
            return r;
    return {};
}

bool complete(const Run& run) { return starts(row_of(run.last(), "coverage|"), "coverage|complete|"); }

std::vector<std::string> sorted(std::vector<std::string> v) {
    std::ranges::sort(v);
    return v;
}
using Strs = std::vector<std::string>;

const std::string kCtl = "yuzu-fs-control-*.bin";

/// A cursor of the control search over `rig`'s plan: unit `index`, sequence `seq`, generation `gen`.
VolumeCursor cursor_at(const Rig& rig, std::size_t index, std::uint64_t seq, std::uint32_t gen = 0) {
    const VolumePlan plan = rig.plan();
    VolumeCursor c;
    c.index = index;
    c.units_hash = plan.units_hash;
    c.refused_hash = plan.refused_hash;
    c.inner.query_hash = fsr::query_hash(make_request(kCtl).query);
    c.inner.sequence = seq;
    c.inner.generation = gen;
    return c;
}

} // namespace

// ---- the request parser ----

TEST_CASE("file_search request: every refusal is a closed token and costs no syscall",
          "[file_search][file_search_driver][request]") {
    const auto err = [](std::string root, std::string pattern, std::string kinds = "", std::string cursor = "") {
        const auto r = parse_request(root, pattern, kinds, cursor, fsr::byte_exact());
        REQUIRE_FALSE(r.has_value());
        return std::string(to_token(r.error()));
    };
    CHECK(err("", "abc*") == "missing_root");
    CHECK(err("rel/x", "abc*") == "root_not_absolute");
    CHECK(err("/" + std::string(kMaxRootBytes, 'a'), "abc*") == "root_too_long");
    CHECK(err("/a//b", "abc*") == "root_bad_component");
    CHECK(err("//", "abc*") == "root_bad_component");
    CHECK(err("/a/./b", "abc*") == "root_bad_component");
    CHECK(err("/a/../b", "abc*") == "root_bad_component");
    CHECK(err("/a/..", "abc*") == "root_bad_component");
    CHECK(err(std::string("/a\0b", 4), "abc*") == "root_bad_component");
    CHECK(err("/a", "") == "missing_pattern");
    CHECK(err("/a", std::string(129, 'a')) == "pattern_too_long");
    CHECK(err("/a", "a*b*c*d*e*fgh") == "pattern_too_many_stars");
    CHECK(err("/a", "ab") == "pattern_too_few_literals");
    CHECK(err("/a", "a?b*") == "pattern_too_few_literals");
    CHECK(err("/a", "abc/d") == "pattern_forbidden_byte");
    CHECK(err("/a", std::string("ab\0c", 4)) == "pattern_forbidden_byte");
    CHECK(err("/a", "abc*", "dirs") == "bad_kinds");
    CHECK(err("/a", "abc*", "", std::string(kMaxRequestCursorBytes + 1, 'x')) == "bad_cursor");

    // the three tokens the driver emits from the leg are spelled too
    CHECK(std::string(to_token(RequestError::root_is_link)) == "root_is_link");
    CHECK(std::string(to_token(RequestError::root_not_found)) == "root_not_found");
    CHECK(std::string(to_token(RequestError::root_not_a_directory)) == "root_not_a_directory");
}

TEST_CASE("file_search request: a good request is normalised", "[file_search][file_search_driver][request]") {
    const auto ok = [](std::string root, std::string kinds = "") {
        const auto r = parse_request(root, "abc*", kinds, "", fsr::byte_exact());
        REQUIRE(r.has_value());
        return *r;
    };
    CHECK(ok("/").query.root == "/");
    CHECK(ok("/a/b").query.root == "/a/b");
    CHECK(ok("/a/b/").query.root == "/a/b"); // one trailing slash is stripped
    CHECK(ok("/a/b").query.kinds == fsr::Kinds::files);
    CHECK(ok("/a", "files").query.kinds == fsr::Kinds::files);
    CHECK(ok("/a", "directories").query.kinds == fsr::Kinds::directories);
    CHECK(ok("/a", "both").query.kinds == fsr::Kinds::both);
    CHECK(ok("/a").query.pattern.semantics_id() == "bytes");
    CHECK(ok("/a").cursor.empty());
}

TEST_CASE("file_search request: a canonicaliser that writes wildcards is refused, one that expands is a gap",
          "[file_search][file_search_driver][request]") {
    // five extra stars appended: over the star limit on the CANONICAL pattern
    const fsr::NameSemantics stars{"stars", [](std::string_view s) { return std::string(s) + "*****"; }};
    const auto r = parse_request("/a", "abc*", "", "", stars);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == RequestError::pattern_too_many_stars);

    // every literal byte five times: a long name's canonical form is past the matcher's bound
    const fsr::NameSemantics expand{"expand5", [](std::string_view s) {
                                        std::string out;
                                        for (const char c : s)
                                            out.append(c == '*' || c == '?' ? 1 : 5, c);
                                        return out;
                                    }};
    Rig rig;
    rig.fs.add_file("/r/abc.txt", "");
    rig.fs.add_file("/r/abc" + std::string(252, 'z'), ""); // 255 bytes: 1275 canonical
    const SliceResult res = checked_slice(make_request("abc*", "/r", "files", "", expand), rig.b);
    CHECK(res.status == Status::ok);
    CHECK(row_of(res, "match|").find("/r/abc.txt") != std::string::npos);
    CHECK(res.rows.size() > 0);
    std::size_t matches = 0;
    for (const auto& row : res.rows)
        matches += starts(row, "match|") ? 1 : 0;
    CHECK(matches == 1);
    CHECK(row_of(res, "gap|").find("name_too_long") != std::string::npos); // not evaluated: said, not dropped
    CHECK(row_of(res, "coverage|").find("partial") != std::string::npos);
}

// ---- the in-memory state ----

TEST_CASE("file_search state: a blocked volume query is recorded once per volume spelling and forgotten when it returns",
          "[file_search][file_search_driver][state]") {
    BlockedQueries q;
    CHECK_FALSE(q.blocked("C:"));

    const DoneFlag first = make_done_flag(), second = make_done_flag(), other = make_done_flag();
    q.add("C:", first);
    CHECK(q.blocked("C:"));
    CHECK_FALSE(q.blocked("D:")); // another volume is unaffected
    q.add("C:", second);          // one per spelling: the second is not recorded
    q.add("D:", other);
    CHECK(q.blocked("D:"));

    first->store(true); // the first query returns: with only one recorded for C:, the volume is free
    CHECK_FALSE(q.blocked("C:"));
    CHECK(q.blocked("D:"));
    q.add("C:", second); // a later query that blocks is recorded again
    CHECK(q.blocked("C:"));
    second->store(true);
    other->store(true);
    CHECK_FALSE(q.blocked("C:"));
    CHECK_FALSE(q.blocked("D:"));

    // nothing is recorded for a query that has already returned, or without a flag
    const DoneFlag finished = make_done_flag();
    finished->store(true);
    q.add("E:", finished);
    q.add("E:", nullptr);
    CHECK_FALSE(q.blocked("E:"));
}

TEST_CASE("file_search state: abandoned workers and stall counts are bounded and in memory only",
          "[file_search][file_search_driver][state]") {
    SearchState s;
    CHECK_FALSE(s.is_stalled("v"));
    CHECK(s.abandoned_count() == 0);
    CHECK(s.carried(Lineage{}).consecutive_stalls == 0);

    const DoneFlag a = make_done_flag(), b = make_done_flag(), c = make_done_flag();
    CHECK(s.add_abandoned("v1", a));
    CHECK(s.add_abandoned("v2", b));
    CHECK_FALSE(s.add_abandoned("v3", c)); // kMaxAbandoned
    CHECK_FALSE(s.add_abandoned("v4", nullptr));
    CHECK(s.abandoned_full());
    CHECK(s.is_stalled("v1"));
    CHECK_FALSE(s.is_stalled("v3"));

    a->store(true);
    CHECK_FALSE(s.is_stalled("v1")); // returned: not stalled, even before it is dropped
    CHECK(s.abandoned_count() == 2);
    s.drop_finished();
    CHECK(s.abandoned_count() == 1);
    CHECK(s.is_stalled("v2"));
    CHECK_FALSE(s.abandoned_full());

    // the same volume twice stays stalled until BOTH returned
    CHECK(s.add_abandoned("v2", c));
    b->store(true);
    CHECK(s.is_stalled("v2"));
    c->store(true);
    CHECK_FALSE(s.is_stalled("v2"));

    // lineages: newest kept, oldest evicted, nothing carried is forgotten
    SearchState t;
    fsr::GovernorState two;
    two.consecutive_stalls = 2;
    for (std::uint64_t i = 0; i < kMaxLineages + 5; ++i)
        t.store(Lineage{{}, i, 0}, two);
    CHECK(t.lineage_count() == kMaxLineages);
    CHECK(t.carried(Lineage{{}, 0, 0}).consecutive_stalls == 0); // evicted
    CHECK(t.carried(Lineage{{}, kMaxLineages + 4, 0}).consecutive_stalls == 2);
    CHECK(t.carried(Lineage{{}, kMaxLineages + 4, 1}).consecutive_stalls == 0); // generation is part of the key
    fsr::QueryHash other{};
    other[0] = 1;
    CHECK(t.carried(Lineage{other, kMaxLineages + 4, 0}).consecutive_stalls == 0); // so is the query
    t.store(Lineage{{}, kMaxLineages + 4, 0}, fsr::GovernorState{}); // a healthy state forgets
    CHECK(t.carried(Lineage{{}, kMaxLineages + 4, 0}).consecutive_stalls == 0);

    // a terminal verdict is delivered once and not kept: only a healthy count is
    for (const auto health : {fsr::Health::stalled, fsr::Health::unstable}) {
        fsr::GovernorState dead;
        dead.consecutive_stalls = 3;
        dead.health = health;
        const Lineage l{{}, kMaxLineages + 3, 0};
        t.store(l, two); // a count is there to be replaced
        t.store(l, dead);
        CHECK(t.carried(l).health == fsr::Health::ok);
        CHECK(t.carried(l).consecutive_stalls == 0);
    }
}

// ---- the mapping and the seeding ----

TEST_CASE("file_search driver: the governor limits map to the walk limits in one place",
          "[file_search][file_search_driver]") {
    const fsr::GovernorLimits defaults;
    const auto w = walk_limits_for(defaults);
    CHECK(w.max_depth == fsr::kMaxPositionDepth);
    CHECK(w.max_dir_entries == 50000); // the per-directory listing cap the plan fixes: the mapping leaves it alone
    fsr::GovernorLimits small;
    small.max_entries = 7;
    small.max_rows = 3;
    const auto v = walk_limits_for(small);
    CHECK(v.max_entries == 7);
    CHECK(v.max_rows == 3);

    VolumePlan plan;
    plan.volumes_dropped = 4;
    fsr::Cursor c;
    c.sequence = 9;
    c.prior_gaps = 6;
    const auto e = seed_envelope(c, plan);
    CHECK(e.slices == 10);
    CHECK(e.prior_gaps == 6);
    CHECK(e.volumes_dropped == 4);
    CHECK(e.volumes.empty());
    CHECK_FALSE(e.has_cursor);
}

// ---- finding things ----

TEST_CASE("file_search driver: controls at depth 1, depth 12 and under a user directory are found, the user one tagged",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_dir("/home");
    rig.fs.add_file("/home/yuzu-fs-control-1.bin", "x");  // personal-data-ok: synthetic test path
    std::string deep = "/home";
    for (const char* d : {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"})
        deep += std::string("/") + d;
    rig.fs.add_file(deep + "/yuzu-fs-control-2.bin", "xx");
    rig.fs.add_file("/home/alice/docs/yuzu-fs-control-3.bin", "xxx");
    rig.fs.add_file("/home/alice/docs/other.txt", "");

    const Run run = search(rig, kCtl, "/home");
    CHECK(sorted(found(run)) == Strs{"/home/a/b/c/d/e/f/g/h/i/j/k/yuzu-fs-control-2.bin",  // personal-data-ok: synthetic test path
                                     "/home/alice/docs/yuzu-fs-control-3.bin", "/home/yuzu-fs-control-1.bin"});  // personal-data-ok: synthetic test path
    for (const auto& s : run.slices)
        for (const auto& row : s.rows)
            if (starts(row, "match|")) {
                const auto cols = split(row);
                REQUIRE(cols.size() == 7);
                CHECK(cols[2] == "file");
                CHECK(cols[6] == (cols[1].find("/home/") == 0 ? "user" : "system"));
                CHECK(cols[4] != "-"); // size from the opened leaf
                CHECK(cols[5] == std::to_string(MemTree::kDefaultMtime));
            }
    CHECK(complete(run));
    CHECK(run.last().status == Status::ok);
    CHECK(run.last().cursor.empty());
    // every file match is followed by its extents row, which joins on the identity column
    CHECK(count_rows(run, "extents|") == 3);

    // outside a profile directory the tag is system
    Rig sys;
    sys.fs.add_file("/r/yuzu-fs-control-4.bin", "");
    const Run sysrun = search(sys, kCtl);
    CHECK(split(row_of(sysrun.last(), "match|"))[6] == "system");
}

TEST_CASE("file_search driver: a search cut by a budget and resumed by cursor finds what an uncut one finds, across two volumes",
          "[file_search][file_search_driver]") {
    const auto build = [](Rig& r) {
        r.mounts.add("/r/data", "ext4", "8:2");
        for (int i = 0; i < 5; ++i) {
            r.fs.add_file("/r/yuzu-fs-control-a" + std::to_string(i) + ".bin", "");
            r.fs.add_file("/r/sub/yuzu-fs-control-b" + std::to_string(i) + ".bin", "");
            r.fs.add_file("/r/data/yuzu-fs-control-c" + std::to_string(i) + ".bin", "");
            r.fs.add_file("/r/data/d/yuzu-fs-control-d" + std::to_string(i) + ".bin", "");
            r.fs.add_file("/r/noise" + std::to_string(i), "");
        }
    };
    Rig uncut;
    build(uncut);
    const Run whole = search(uncut, kCtl);
    CHECK(found(whole).size() == 20);
    CHECK(whole.slices.size() == 2); // one volume per slice
    CHECK(complete(whole));

    for (const std::size_t entries : {std::size_t{2}, std::size_t{3}, std::size_t{5}, std::size_t{9}}) {
        Rig cut;
        build(cut);
        cut.b.limits.max_entries = entries;
        const Run run = search(cut, kCtl);
        INFO("max_entries " << entries);
        CHECK(run.slices.size() > 2);
        CHECK(found(run) == found(whole)); // same rows, same order
        CHECK(complete(run));
        for (std::size_t i = 0; i + 1 < run.slices.size(); ++i) {
            CHECK(run.slices[i].status == Status::ok);
            CHECK_FALSE(run.slices[i].cursor.empty());
            CHECK(row_of(run.slices[i], "coverage|").find("consistency=not_a_snapshot") != std::string::npos);
        }
    }
    Rig by_rows;
    build(by_rows);
    by_rows.b.limits.max_rows = 3;
    CHECK(found(search(by_rows, kCtl)) == found(whole));
}

TEST_CASE("file_search driver: a 765-byte name resumes across a slice and a 766-byte one is a name_too_long gap",
          "[file_search][file_search_driver]") {
    const std::string wide(fsr::kMaxNameBytes, 'w');        // the longest name a Position holds
    const std::string wider(fsr::kMaxNameBytes + 1, 'x');   // one byte more: never placed
    Rig rig;
    rig.fs.add_file("/r/" + wide + "/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/" + wide + "/yuzu-fs-control-2.bin", "");
    rig.fs.add_file("/r/" + wider + "/yuzu-fs-control-9.bin", "");
    rig.b.limits.max_entries = 2; // every slice ends inside the wide directory
    const Run run = search(rig, kCtl);
    CHECK(run.slices.size() > 1);
    CHECK(found(run) == Strs{"/r/" + wide + "/yuzu-fs-control-1.bin", "/r/" + wide + "/yuzu-fs-control-2.bin"});
    CHECK(count_rows(run, "gap|") >= 1);
    for (const auto& s : run.slices)
        if (const auto g = row_of(s, "gap|"); !g.empty())
            CHECK(g.find("name_too_long") != std::string::npos);
    CHECK_FALSE(complete(run)); // the 766-byte directory was not searched, and the verdict says so
}

TEST_CASE("file_search driver: a unit nested in another is searched, never listed by its parent, with no gap",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r/data", "ext4", "8:2");
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/data/yuzu-fs-control-2.bin", "");
    const Run run = search(rig, kCtl);
    CHECK(sorted(found(run)) == Strs{"/r/data/yuzu-fs-control-2.bin", "/r/yuzu-fs-control-1.bin"});
    CHECK(rig.legs == Strs{"/r", "/r/data"});
    CHECK(rig.pruned_erased == std::set<std::string>{"/r/data"}); // the parent's leg erased it, so no gap
    CHECK(count_rows(run, "gap|") == 0);
    CHECK(count_rows(run, "gaps_dropped|") == 0);
    CHECK(complete(run));
    CHECK(row_of(run.slices[0], "volume|").find("volume|/|ext4|complete|none|") == 0);
    CHECK(row_of(run.slices[1], "volume|").find("volume|/r/data|ext4|complete|none|") == 0);
}

TEST_CASE("file_search driver: a refused mount beneath a unit is never listed, reported once with its own reason, and partial",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r/usb", "vfat", "8:9", "/", "/dev/sdb1").add("/r/more", "ext4", "8:3");
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/usb/yuzu-fs-control-2.bin", "");
    rig.fs.add_file("/r/more/yuzu-fs-control-3.bin", "");
    const Run run = search(rig, kCtl);
    CHECK(sorted(found(run)) == Strs{"/r/more/yuzu-fs-control-3.bin", "/r/yuzu-fs-control-1.bin"});
    CHECK(std::ranges::find(rig.fs.listed, "/r/usb") == rig.fs.listed.end());
    CHECK(sorted(rig.facts_calls) == Strs{"/r/more/yuzu-fs-control-3.bin", "/r/yuzu-fs-control-1.bin"}); // nothing else opened
    CHECK(count_rows(run, "volume|/r/usb|vfat|not_searched|fstype_not_allowed|") == 1); // once, never network_mount
    CHECK(count_rows(run, "volume|/r/usb|") == 1);
    CHECK_FALSE(complete(run)); // the refused row is carried into the verdict through the cursor
    CHECK(row_of(run.last(), "coverage|").find("prior_gaps=1") != std::string::npos);
}

TEST_CASE("file_search driver: a disk beneath a tmpfs is found without listing the tmpfs, one beneath a network mount is never opened",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r/t", "tmpfs", "0:7", "/", "tmpfs")
        .add("/r/t/disk", "ext4", "8:3")
        .add("/r/nfs", "nfs4", "0:40", "/", "srv:/x")
        .add("/r/nfs/disk", "ext4", "8:4");
    rig.fs.add_file("/r/t/yuzu-fs-control-0.bin", "");
    rig.fs.add_file("/r/t/disk/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/nfs/yuzu-fs-control-2.bin", "");
    rig.fs.add_file("/r/nfs/disk/yuzu-fs-control-3.bin", "");
    const Run run = search(rig, kCtl);
    CHECK(found(run) == Strs{"/r/t/disk/yuzu-fs-control-1.bin"});
    for (const char* never : {"/r/t", "/r/nfs", "/r/nfs/disk"})
        CHECK(std::ranges::find(rig.fs.listed, never) == rig.fs.listed.end());
    CHECK(rig.facts_calls == Strs{"/r/t/disk/yuzu-fs-control-1.bin"});
    CHECK(count_rows(run, "volume|/r/nfs|nfs4|not_searched|network_mount|") == 1);
    CHECK(count_rows(run, "volume|/r/nfs/disk|ext4|not_searched|behind_network_mount|") == 1);
    CHECK(count_rows(run, "volume|/r/t|tmpfs|not_searched|fstype_not_allowed|") == 1);
    CHECK_FALSE(complete(run));
}

TEST_CASE("file_search driver: every match row decodes to the original name bytes",
          "[file_search][file_search_driver]") {
    Rig rig;
    const Strs names = {std::string("yuzu-\xff-ctl.bin"), std::string("yuzu-\x01\x7f-ctl.bin"), "yuzu-%41|x-ctl.bin",
                        "yuzu-\xc3\xa9-ctl.bin", "yuzu-\\-ctl.bin"};
    Strs expected;
    for (const auto& n : names) {
        rig.fs.add_file("/r/" + n, "");
        expected.push_back("/r/" + n);
    }
    const Run run = search(rig, "yuzu-*-ctl.bin");
    CHECK(sorted(found(run)) == sorted(expected));
    for (const auto& s : run.slices)
        for (const auto& row : s.rows) {
            CHECK(row.find('\n') == std::string::npos);
            if (starts(row, "match|"))
                CHECK(split(row).size() == 7); // an encoded name never holds the delimiter
        }
}

TEST_CASE("file_search driver: kinds picks files, directories or both", "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/filexyz-ctl", "");
    rig.fs.add_dir("/r/dirxyz-ctl");
    rig.fs.add_file("/r/dirxyz-ctl/inside.txt", "");
    const auto kinds = [&](const std::string& k) { return found(search(rig, "*xyz-ctl", "/r", k)); };
    CHECK(kinds("files") == Strs{"/r/filexyz-ctl"});
    CHECK(kinds("directories") == Strs{"/r/dirxyz-ctl"});
    CHECK(sorted(kinds("both")) == Strs{"/r/dirxyz-ctl", "/r/filexyz-ctl"});
    // a directory row has no size and no time and no extents row; it is never opened
    const Run dirs = search(rig, "*xyz-ctl", "/r", "directories");
    const auto cols = split(row_of(dirs.last(), "match|"));
    CHECK(cols[2] == "directory");
    CHECK(cols[4] == "-");
    CHECK(cols[5] == "-");
    CHECK(count_rows(dirs, "extents|") == 0);
}

TEST_CASE("file_search driver: a true negative is complete with no gap and no cursor, beside a found control",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/other.txt", "");
    const Run none = search(rig, "nomatch-*.bin");
    CHECK(found(none).empty());
    CHECK(none.slices.size() == 1);
    CHECK(none.last().status == Status::ok);
    CHECK(none.last().reason == "none");
    CHECK(none.last().cursor.empty());
    CHECK(complete(none));
    CHECK(count_rows(none, "gap|") == 0);
    CHECK(row_of(none.last(), "search|").find("search|ok|none|bytes|seq=0|q=") == 0);
    CHECK(found(search(rig, kCtl)).size() == 1); // the same tree does hold a match
}

TEST_CASE("file_search driver: a FIFO, a link and a non-regular entry are never opened for facts",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.dirs["/r"].push_back({"yuzu-fs-control-fifo.bin", Type::other});
    rig.link("/r/yuzu-fs-control-loop.bin");
    rig.fs.add_dir("/r/yuzu-fs-control-dir.bin"); // a directory with a matching name, files-only search
    const Run run = search(rig, kCtl);
    CHECK(found(run) == Strs{"/r/yuzu-fs-control-1.bin"});
    CHECK(rig.facts_calls == Strs{"/r/yuzu-fs-control-1.bin"});
    CHECK(count_rows(run, "gap|") == 0);
    CHECK(row_of(run.last(), "search|").find("|links_skipped=1") != std::string::npos);
    CHECK(complete(run));
}

TEST_CASE("file_search driver: a root that is a link, missing or not a directory is invalid with its own token and no walk",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.link("/lnk");
    rig.fs.add_file("/r/plain.txt", "");
    const auto check = [&](const std::string& root, const std::string& token) {
        rig.fs.listed.clear();
        const SliceResult r = checked_slice(make_request(kCtl, root), rig.b);
        INFO(root);
        CHECK(r.status == Status::invalid);
        CHECK(r.reason == token);
        CHECK(r.rows.size() == 1);
        CHECK(starts(r.rows[0], "search|invalid|" + token + "|bytes|seq=0|q="));
        CHECK(r.cursor.empty());
        CHECK(rig.fs.listed.empty());
        CHECK_FALSE(rig.slot.load());
    };
    check("/lnk", "root_is_link");
    check("/nothere", "root_not_found");
    check("/r/plain.txt", "root_not_a_directory");
}

TEST_CASE("file_search driver: with no searchable mount in scope the answer is partial and says why",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r", "tmpfs", "0:7", "/", "tmpfs");
    const Run run = search(rig, kCtl);
    CHECK(run.slices.size() == 1);
    CHECK(run.last().status == Status::ok);
    CHECK(run.last().cursor.empty());
    CHECK(count_rows(run, "volume|/r|tmpfs|not_searched|fstype_not_allowed|") == 1);
    CHECK_FALSE(complete(run));
    CHECK(rig.runner_calls == 0);
}

TEST_CASE("file_search driver: on macOS a search from '/' reports the data volume as partial through the firmlinks, never not_searched",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.b.os = Os::macos;
    rig.mounts = Mounts{};
    rig.mounts.add("/", "apfs", "1:1", "/", "/dev/disk3s1s1").add("/System/Volumes/Data", "apfs", "1:2", "/", "/dev/disk3s5");
    rig.fs.dirs["/"] = {{"Users", Type::dir}, {"System", Type::dir}};
    rig.fs.add_dir("/Users");
    rig.fs.add_dir("/Users/alex");
    rig.fs.add_file("/Users/alex/yuzu-fs-control-1.bin", "");
    // The control for "never listed": the data volume IS in the tree, at its own mount point, with a twin of
    // the control beneath it. Only the prune set keeps the walk out, so a leg that listed it would find the
    // twin and the match below would be found twice.
    rig.fs.add_dir("/System/Volumes/Data");
    rig.fs.add_dir("/System/Volumes/Data/Users");
    rig.fs.add_dir("/System/Volumes/Data/Users/alex");
    rig.fs.add_file("/System/Volumes/Data/Users/alex/yuzu-fs-control-1.bin", "");
    const Run run = search(rig, kCtl, "/");
    CHECK(run.slices.size() == 1);
    CHECK(run.last().status == Status::ok);
    CHECK(run.last().cursor.empty());
    CHECK(found(run) == Strs{"/Users/alex/yuzu-fs-control-1.bin"}); // reached through the system volume, exactly once
    CHECK(count_rows(run, "volume|/System/Volumes/Data|apfs|partial|firmlinks_only|") == 1);
    CHECK(count_rows(run, "volume|/System/Volumes/Data|") == 1);
    CHECK(row_of(run.last(), "volume|/|").find("volume|/|apfs|complete|none|") == 0); // the '/' unit itself
    CHECK_FALSE(complete(run)); // the refused row is still carried into the verdict
    CHECK(starts(row_of(run.last(), "coverage|"), "coverage|partial|"));
    CHECK(std::ranges::find(rig.fs.listed, "/System/Volumes/Data") == rig.fs.listed.end());
    CHECK(rig.pruned_erased.contains("/System/Volumes/Data")); // listed in its parent, removed by the leg
}

// ---- single flight, stall and abandonment ----

TEST_CASE("file_search driver: a second concurrent slice answers busy without calling the runner or touching state",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    std::optional<SliceResult> inner;
    int reads_during = -1;
    rig.during_run = [&] {
        reads_during = rig.mount_reads;
        inner = checked_slice(make_request(kCtl), rig.b);
    };
    const SliceResult outer = checked_slice(make_request(kCtl), rig.b);
    REQUIRE(inner.has_value());
    CHECK(inner->status == Status::busy);
    CHECK(inner->reason == "busy");
    CHECK(inner->rows.size() == 1);
    CHECK(starts(inner->rows[0], "search|busy|busy|"));
    CHECK(rig.runner_calls == 1);
    CHECK(rig.mount_reads == reads_during); // the busy call read nothing
    CHECK(rig.legs.size() == 1);            // and made no leg: only the outer slice's worker did
    CHECK(rig.user_root_reads == 1);
    CHECK(outer.status == Status::ok);
    CHECK_FALSE(rig.slot.load()); // released by the slice that took it
}

TEST_CASE("file_search driver: a timeout abandons its worker, the volume reads stalled, the rest are searched",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r/data", "ext4", "8:2");
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/data/yuzu-fs-control-2.bin", "");
    const VolumePlan plan = rig.plan();
    const std::string key0 = plan.units[0].key();

    rig.mode = Rig::Mode::timeout;
    const SliceResult t = checked_slice(make_request(kCtl), rig.b);
    CHECK(t.status == Status::failed);
    CHECK(t.reason == "timed_out");
    CHECK(t.cursor.empty());
    CHECK(t.counters.timed_out == 1);
    CHECK(rig.last_timeout == rig.b.limits.slice + kSliceGrace);
    CHECK(rig.state.abandoned_count() == 1);
    CHECK(rig.state.is_stalled(key0));
    CHECK_FALSE(rig.slot.load());
    const auto qh = fsr::query_hash(make_request(kCtl).query);
    CHECK(rig.state.carried(Lineage{qh, 0, 0}).consecutive_stalls == 1); // record_failed_slice

    // the retry finds the volume stalled: emitted as such, one gap, on to the next volume, no runner call
    rig.mode = Rig::Mode::run;
    const int calls = rig.runner_calls;
    const SliceResult skip = checked_slice(make_request(kCtl), rig.b);
    CHECK(skip.status == Status::ok);
    CHECK(skip.reason == "stalled");
    CHECK(rig.runner_calls == calls);
    CHECK(row_of(skip, "volume|").find("volume|/|ext4|partial|stalled|") == 0);
    REQUIRE_FALSE(skip.cursor.empty());
    CHECK(skip.counters.stalled == 1);

    const SliceResult next = checked_slice(make_request(kCtl, "/r", "files", skip.cursor), rig.b);
    CHECK(next.status == Status::ok);
    CHECK(row_of(next, "match|").find("/r/data/yuzu-fs-control-2.bin") != std::string::npos);
    CHECK(next.cursor.empty());
    CHECK(starts(row_of(next, "coverage|"), "coverage|partial|")); // the stalled volume is in the verdict
    CHECK(row_of(next, "coverage|").find("prior_gaps=1") != std::string::npos);
}

TEST_CASE("file_search driver: a volume is stalled by its identity, not by the spelling of its mount point",
          "[file_search][file_search_driver]") {
    // one Windows volume is reached as `/C:` or as `/Volume{guid}`: same label, root and type, two spellings
    Unit a;
    a.mount_point = "/C:";
    a.fstype = "NTFS";
    a.label = "0:5";
    a.root_field = "\\\\?\\Volume{0f1e2d3c-1111-2222-3333-444455556666}\\";
    Unit b = a;
    b.mount_point = "/Volume{0f1e2d3c-1111-2222-3333-444455556666}";
    CHECK(a.key() == b.key());
    CHECK(units_hash({a}) != units_hash({b})); // a cursor's hash still covers the spelling
    Unit other_fs = a;
    other_fs.label = "0:6";
    CHECK(a.key() != other_fs.key());

    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.mode = Rig::Mode::timeout;
    const SliceResult t = checked_slice(make_request(kCtl), rig.b);
    CHECK(t.reason == "timed_out");
    REQUIRE(rig.state.abandoned_count() == 1);

    // the same filesystem again, reached through another mount point: it reads stalled and takes no second slot
    rig.mounts = Mounts{};
    rig.mounts.add("/r", "ext4", "8:1");
    const VolumePlan again = rig.plan();
    REQUIRE(again.units.size() == 1);
    CHECK(again.units[0].mount_point == "/r");
    rig.mode = Rig::Mode::run;
    const int calls = rig.runner_calls;
    const SliceResult skip = checked_slice(make_request(kCtl), rig.b);
    CHECK(skip.reason == "stalled");
    CHECK(rig.runner_calls == calls);
    CHECK(rig.state.abandoned_count() == 1);
}

TEST_CASE("file_search driver: with two workers still abandoned every slice answers busy and frees the slot",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r/data", "ext4", "8:2");
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/data/yuzu-fs-control-2.bin", "");
    rig.mode = Rig::Mode::timeout;
    CHECK(checked_slice(make_request(kCtl), rig.b).reason == "timed_out");                 // volume 0
    const SliceResult skip = checked_slice(make_request(kCtl), rig.b);                       // skips to volume 1
    REQUIRE_FALSE(skip.cursor.empty());
    CHECK(checked_slice(make_request(kCtl, "/r", "files", skip.cursor), rig.b).reason == "timed_out"); // volume 1
    REQUIRE(rig.state.abandoned_count() == 2);

    const int calls = rig.runner_calls;
    const int mount_reads = rig.mount_reads;
    for (int i = 0; i < 3; ++i) {
        const SliceResult busy = checked_slice(make_request(kCtl), rig.b);
        CHECK(busy.status == Status::busy);
        CHECK_FALSE(rig.slot.load());
        CHECK(checked_slice(make_request("other-*.bin"), rig.b).status == Status::busy); // any search
    }
    CHECK(rig.runner_calls == calls);
    CHECK(rig.mount_reads == mount_reads); // the busy slices read no mount table
    CHECK(rig.legs.empty()); // a held worker never ran its work: no leg was ever made, and the busy slices made none
    CHECK(rig.user_root_reads == 0);

    rig.state.abandoned()[0].done->store(true); // one comes back: there is room again
    rig.mode = Rig::Mode::run;
    CHECK(checked_slice(make_request(kCtl, "/r", "files", skip.cursor), rig.b).status == Status::ok);
}

TEST_CASE("file_search driver: an abandoned worker that completes late changes only its own flag",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r/data", "ext4", "8:2");
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/data/yuzu-fs-control-2.bin", "");
    rig.mode = Rig::Mode::timeout;
    CHECK(checked_slice(make_request(kCtl), rig.b).reason == "timed_out");
    REQUIRE(rig.held != nullptr);
    const SliceResult skip = checked_slice(make_request(kCtl), rig.b);
    REQUIRE_FALSE(skip.cursor.empty());

    // The next slice holds the slot; while it runs, the old worker finally returns.
    rig.mode = Rig::Mode::run;
    bool slot_during = false;
    std::size_t abandoned_during = 0;
    bool flag_during = false;
    rig.during_run = [&] {
        (void)rig.held(); // the late worker runs to the end, on its own copy of everything
        slot_during = rig.slot.load();
        abandoned_during = rig.state.abandoned_count();
        flag_during = rig.state.abandoned()[0].done->load();
    };
    const SliceResult r = checked_slice(make_request(kCtl, "/r", "files", skip.cursor), rig.b);
    CHECK(slot_during);              // the newer slice still holds the slot
    CHECK(abandoned_during == 1);    // the late worker removed nothing from the state
    CHECK(flag_during);              // it set its own flag, and only that
    CHECK(r.status == Status::ok);
    CHECK(found(Run{{r}}) == Strs{"/r/data/yuzu-fs-control-2.bin"});
    CHECK_FALSE(rig.slot.load());
    rig.during_run = nullptr;
    const SliceResult again = checked_slice(make_request(kCtl), rig.b); // the next slice drops it, volume 0 is searched
    CHECK(again.status == Status::ok);
    CHECK(found(Run{{again}}) == Strs{"/r/yuzu-fs-control-1.bin"});
    CHECK(rig.state.abandoned_count() == 0);
}

TEST_CASE("file_search driver: a refused worker abandons nothing and the third refusal on one cursor ends stalled",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r/data", "ext4", "8:2");
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.mode = Rig::Mode::reject;
    const SliceResult one = checked_slice(make_request(kCtl), rig.b);
    CHECK(one.status == Status::failed);
    CHECK(one.reason == "rejected");
    CHECK(one.counters.rejected == 1);
    CHECK(rig.state.abandoned_count() == 0);
    CHECK(row_of(one, "volume|/r/data|").empty()); // a retryable end: the previous cursor stands, nothing is named
    // A slice with no result reads partial/stalled (see no_result): the attempt did not advance.
    CHECK(starts(row_of(one, "volume|"), "volume|/|ext4|partial|stalled|"));
    const auto qh = fsr::query_hash(make_request(kCtl).query);
    CHECK(rig.state.carried(Lineage{qh, 0, 0}).consecutive_stalls == 1); // the failed-slice count rises
    CHECK(checked_slice(make_request(kCtl), rig.b).reason == "rejected");
    const SliceResult three = checked_slice(make_request(kCtl), rig.b);
    CHECK(three.status == Status::failed);
    CHECK(three.reason == "stalled"); // final
    CHECK(three.counters.stalled == 1);
    CHECK(starts(row_of(three, "volume|/r/data|"), "volume|/r/data|ext4|not_searched|stalled|")); // the unit never reached
    CHECK_FALSE(rig.slot.load());
}

TEST_CASE("file_search driver: a worker that throws is a failed slice, never a timeout",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.facts_hook = [](const std::string&) { throw std::runtime_error("boom"); };
    const SliceResult r = checked_slice(make_request(kCtl), rig.b);
    CHECK(r.status == Status::failed);
    CHECK(r.reason == "internal_error");
    CHECK(r.counters.timed_out == 0);
    CHECK(r.counters.failed == 1);
    CHECK(rig.state.abandoned_count() == 0);
    CHECK(starts(row_of(r, "volume|"), "volume|/|ext4|partial|stalled|")); // as for a refused worker
    CHECK_FALSE(rig.slot.load());
    // and the worker still set its flag on the way out
    rig.facts_hook = nullptr;
    CHECK(checked_slice(make_request(kCtl), rig.b).status == Status::ok);
}

TEST_CASE("file_search driver: a search that ended stalled leaves no verdict for the next search of the same query",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/other.txt", ""); // a second entry, so a one-entry budget cuts the walk
    rig.mode = Rig::Mode::reject;
    CHECK(checked_slice(make_request(kCtl), rig.b).reason == "rejected");
    CHECK(checked_slice(make_request(kCtl), rig.b).reason == "rejected");
    CHECK(checked_slice(make_request(kCtl), rig.b).reason == "stalled"); // the third: final
    CHECK(rig.state.lineage_count() == 0);                          // delivered once, not kept

    // a fresh search of the same query starts at the same lineage: its first slice is cut by a budget, which
    // is not a stall, and the search runs to the end with every control found
    rig.mode = Rig::Mode::run;
    rig.b.limits.max_entries = 1;
    const Run run = search(rig, kCtl);
    CHECK(run.slices.size() > 1);
    CHECK(found(run) == Strs{"/r/yuzu-fs-control-1.bin"});
    CHECK(complete(run));
}

TEST_CASE("file_search driver: a stall count belongs to one cursor, and an evicted one starts again at zero",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.mode = Rig::Mode::reject;
    const auto attempt = [&](std::uint64_t seq, std::uint32_t gen = 0) {
        const std::string token = encode_volume_cursor(cursor_at(rig, 0, seq, gen), rig.b.cursor_key);
        return checked_slice(make_request(kCtl, "/r", "files", token), rig.b).reason;
    };

    CHECK(attempt(1) == "rejected");
    CHECK(attempt(1) == "rejected"); // two on cursor 1
    CHECK(attempt(2) == "rejected"); // another sequence: its own count, not a third
    CHECK(attempt(1, 1) == "rejected"); // another generation: its own count too
    CHECK(attempt(1) == "stalled");    // the third on cursor 1

    // evict: cursor 5 twice, then 32 other lineages, then cursor 5 again
    CHECK(attempt(5) == "rejected");
    CHECK(attempt(5) == "rejected");
    for (std::uint64_t s = 100; s < 100 + kMaxLineages; ++s)
        CHECK(attempt(s) == "rejected");
    CHECK(attempt(5) == "rejected"); // its count was evicted: this is the first again, not the third
}

TEST_CASE("file_search driver: a stop request ends the slice cancelled, carrying and retrying nothing",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.b.stop_requested = [] { return true; };
    const SliceResult r = checked_slice(make_request(kCtl), rig.b);
    CHECK(r.status == Status::failed);
    CHECK(r.reason == "cancelled");
    CHECK(r.cursor.empty());
    CHECK(row_of(r, "cursor|").empty());
    CHECK(row_of(r, "volume|").find("volume|/|ext4|partial|cancelled|") == 0);
    CHECK(starts(row_of(r, "coverage|"), "coverage|partial|"));
    CHECK(starts(row_of(r, "search|"), "search|failed|cancelled|"));
    CHECK(rig.state.lineage_count() == 0);
    CHECK_FALSE(rig.slot.load());
}

TEST_CASE("file_search driver: an identity that changes on every call ends unstable within the restart bound",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r/data", "ext4", "8:2");
    for (int i = 0; i < 6; ++i)
        rig.fs.add_file("/r/noise" + std::to_string(i), "");
    rig.fs.add_file("/r/zzz-yuzu-fs-control-1.bin", "");
    rig.bump_root_identity = true;
    rig.b.limits.max_entries = 2;
    const Run run = search(rig, "zzz-*.bin");
    CHECK(run.slices.size() == rig.b.limits.max_restarts + 1);
    CHECK(run.last().status == Status::failed);
    CHECK(run.last().reason == "unstable");
    CHECK(run.last().counters.unstable == 1);
    CHECK(run.last().cursor.empty());
    CHECK(count_rows(run, "volume|/r/data|") == 1); // the last slice only: no earlier slice reached it
    CHECK(starts(row_of(run.last(), "volume|/r/data|"), "volume|/r/data|ext4|not_searched|unstable|"));
    for (const auto& s : run.slices)
        CHECK_FALSE(starts(row_of(s, "coverage|"), "coverage|complete|"));
    CHECK(found(run).empty());
}

TEST_CASE("file_search driver: a position no cursor can spell is never progress and never finished",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.mode = Rig::Mode::replace;
    rig.replacement = [] {
        WorkResult w;
        w.walk.stop = yuzu::component_inventory::Stop::budget_time;
        w.walk.advanced = true;
        w.walk.position.after = std::string(fsr::kMaxNameBytes + 1, 'a'); // longer than a name can be: not a valid position
        return w;
    };
    const SliceResult r = checked_slice(make_request(kCtl), rig.b);
    CHECK(r.status == Status::failed);
    CHECK(r.reason == "internal_error");
    CHECK(r.cursor.empty());
    CHECK(row_of(r, "cursor|").empty());
    CHECK(starts(row_of(r, "coverage|"), "coverage|partial|"));
}

TEST_CASE("file_search driver: the slice maximum ends the search with its own reason and no cursor",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r/data", "ext4", "8:2");
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/data/yuzu-fs-control-2.bin", "");
    rig.fs.add_file("/r/data/other.txt", ""); // a second entry, so a one-entry budget cuts the walk
    const auto cursor_at_seq = [&](std::size_t index, std::uint64_t seq) {
        return encode_volume_cursor(cursor_at(rig, index, seq), rig.b.cursor_key);
    };
    // the next cursor would be number kMaxSlices: the first unit finishes, the second is never searched
    const SliceResult end = checked_slice(make_request(kCtl, "/r", "files", cursor_at_seq(0, kMaxSlices - 1)), rig.b);
    CHECK(end.status == Status::failed);
    CHECK(end.reason == "max_slices");
    CHECK(end.cursor.empty());
    CHECK(row_of(end, "volume|/r/data|ext4|not_searched|max_slices|").size() > 0);
    CHECK(starts(row_of(end, "coverage|"), "coverage|partial|"));

    // a slice that finishes the last unit on that sequence is simply the end of the search
    const SliceResult last = checked_slice(make_request(kCtl, "/r", "files", cursor_at_seq(1, kMaxSlices - 1)), rig.b);
    CHECK(last.status == Status::ok);
    CHECK(last.reason == "none");
    CHECK(starts(row_of(last, "coverage|"), "coverage|complete|"));

    // a budget stop on that sequence is max_slices on the volume
    rig.b.limits.max_entries = 1;
    const SliceResult cut = checked_slice(make_request(kCtl, "/r", "files", cursor_at_seq(1, kMaxSlices - 1)), rig.b);
    CHECK(cut.status == Status::failed);
    CHECK(cut.reason == "max_slices");
    CHECK(row_of(cut, "volume|/r/data|ext4|partial|max_slices|").size() > 0);

    // and a cursor at or past the maximum is not a cursor
    const SliceResult past = checked_slice(make_request(kCtl, "/r", "files", cursor_at_seq(0, kMaxSlices)), rig.b);
    CHECK(past.status == Status::invalid);
    CHECK(past.reason == "bad_cursor");
}

TEST_CASE("file_search driver: invalid governor limits are refused before a governor, a mount read or a worker",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.b.limits.max_stalls = 0;
    const SliceResult a = checked_slice(make_request(kCtl), rig.b);
    CHECK(a.status == Status::failed);
    CHECK(a.reason == "internal_error");
    rig.b.limits = {};
    rig.b.limits.max_restarts = 0;
    CHECK(checked_slice(make_request(kCtl), rig.b).status == Status::failed);
    rig.b.limits = {};
    rig.b.limits.slice = std::chrono::milliseconds{0};
    CHECK(checked_slice(make_request(kCtl), rig.b).status == Status::failed);
    rig.b.limits = {};
    rig.b.limits.slow_list_ratio = 1; // a back-off limit that could never act is refused like any other
    CHECK(checked_slice(make_request(kCtl), rig.b).status == Status::failed);
    CHECK(rig.mount_reads == 0);
    CHECK(rig.runner_calls == 0);
    CHECK(rig.legs.empty());
    CHECK(rig.user_root_reads == 0);
}

// ---- pacing ----

TEST_CASE("file_search driver: a slice paces its own listings and entries",
          "[file_search][file_search_driver][pacing]") {
    // MUTATION: deleting the gov.pace() call in the list wrapper AND the one in the visitor leaves no nap.
    Rig rig;
    rig.fs.add_dir("/r/slow");
    rig.fs.add_file("/r/slow/yuzu-fs-control-2.bin", "");
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.list_step = std::chrono::milliseconds{60}; // every listing is a whole work quantum (50 ms) of work
    std::vector<std::chrono::milliseconds> sleeps;
    rig.b.sleep = [&rig, &sleeps](std::chrono::milliseconds d) {
        sleeps.push_back(d);
        rig.fs.clock += d;
    };
    const SliceResult r = checked_slice(make_request(kCtl), rig.b);
    CHECK(r.status == Status::ok);
    // Listing /r takes 60 ms; the next call (the entry `slow`) naps those 60 ms at 50 % duty. Listing
    // /r/slow takes 60 ms and is no slower than the 60 ms before it, so the nap at its first entry is the
    // plain duty nap again. Nothing after that has a whole quantum of work to pace.
    CHECK(sleeps == std::vector<std::chrono::milliseconds>{std::chrono::milliseconds{60}, std::chrono::milliseconds{60}});
}

TEST_CASE("file_search driver: a listing that turns slow lengthens the next nap",
          "[file_search][file_search_driver][pacing]") {
    // MUTATION: deleting the gov.note_listing call in the list wrapper leaves the plain duty nap (300 ms).
    Rig rig;
    rig.fs.add_dir("/r/slow");
    rig.fs.add_file("/r/slow/yuzu-fs-control-2.bin", "");
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.list_hook = [&rig](const std::string& dir) {
        if (dir == "/r/slow")
            rig.fs.clock += std::chrono::milliseconds{300}; // at or over the hard bound (250 ms)
    };
    std::vector<std::chrono::milliseconds> sleeps;
    rig.b.sleep = [&rig, &sleeps](std::chrono::milliseconds d) {
        sleeps.push_back(d);
        rig.fs.clock += d;
    };
    const SliceResult r = checked_slice(make_request(kCtl), rig.b);
    CHECK(r.status == Status::ok);
    // 300 ms of listing at 50 % duty is a 300 ms nap; the slow listing adds one quantum (50 ms) of back-off.
    CHECK(sleeps == std::vector<std::chrono::milliseconds>{std::chrono::milliseconds{350}});
    // and the two found files are both reported: pacing changes when a search finishes, never what it finds
    CHECK(count_rows(Run{{r}}, "match|") == 2);
}

TEST_CASE("file_search driver: the first slice judges its root listing",
          "[file_search][file_search_driver][pacing]") {
    // MUTATION: starting `judge` false in the driver (judging only after the first visit) leaves the plain
    // duty nap (300 ms): the root listing precedes the first visit, so in a slice with no resume position
    // nothing judges it.
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.list_hook = [&rig](const std::string& dir) {
        if (dir == "/r")
            rig.fs.clock += std::chrono::milliseconds{300}; // at or over the hard bound (250 ms)
    };
    std::vector<std::chrono::milliseconds> sleeps;
    rig.b.sleep = [&rig, &sleeps](std::chrono::milliseconds d) {
        sleeps.push_back(d);
        rig.fs.clock += d;
    };
    const SliceResult r = checked_slice(make_request(kCtl), rig.b);
    CHECK(r.status == Status::ok);
    // 300 ms of listing at 50 % duty is a 300 ms nap; the slow root listing adds one quantum (50 ms) of back-off.
    CHECK(sleeps == std::vector<std::chrono::milliseconds>{std::chrono::milliseconds{350}});
    CHECK(count_rows(Run{{r}}, "match|") == 1);
}

TEST_CASE("file_search driver: a slice resumed from the root re-lists it unjudged and judges the new work below",
          "[file_search][file_search_driver][pacing]") {
    // MUTATION: never setting `judge` in the visitor gives {300, 300} (the listing of `z` is new work and
    // is not judged); dropping the `after` term from the start test gives {350, 400} (the root re-listing
    // is judged too); starting `judge` true gives the same {350, 400}.
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/z/yuzu-fs-control-2.bin", "");
    rig.b.limits.max_entries = 1; // the first control: the first slice ends in the root itself
    const SliceResult first = checked_slice(make_request(kCtl), rig.b);
    REQUIRE(first.status == Status::ok);
    REQUIRE_FALSE(first.cursor.empty());
    CHECK(count_rows(Run{{first}}, "match|") == 1);

    rig.b.limits.max_entries = fsr::GovernorLimits{}.max_entries;
    rig.list_hook = [&rig](const std::string&) {
        rig.fs.clock += std::chrono::milliseconds{300}; // at or over the hard bound (250 ms): every listing is slow
    };
    rig.fs.listed.clear();
    std::vector<std::chrono::milliseconds> sleeps;
    rig.b.sleep = [&rig, &sleeps](std::chrono::milliseconds d) {
        sleeps.push_back(d);
        rig.fs.clock += d;
    };
    const SliceResult second = checked_slice(make_request(kCtl, "/r", "files", first.cursor), rig.b);
    CHECK(second.status == Status::ok);
    CHECK(count_rows(Run{{second}}, "match|") == 1);
    CHECK(rig.fs.listed == Strs{"/r", "/r/z"});
    // The nap at the entry `z` is the plain duty nap for the unjudged root re-listing (300 ms); the listing
    // of `z` is new work, judged slow, so the nap at its entry adds one quantum of back-off (300 + 50 ms).
    CHECK(sleeps == std::vector<std::chrono::milliseconds>{std::chrono::milliseconds{300}, std::chrono::milliseconds{350}});
}

TEST_CASE("file_search driver: the re-listings of a resumed slice are each paced by the duty cycle",
          "[file_search][file_search_driver][pacing]") {
    // MUTATION: deleting the gov.pace() call in the list wrapper leaves ONE nap (240 ms) for all four
    // listings: a resumed slice lists its ancestors with no visit between them, so the visitor's own
    // pace cannot take their naps.
    Rig rig;
    for (int i = 1; i <= 3; ++i)
        rig.fs.add_file("/r/a/b/c/yuzu-fs-control-" + std::to_string(i) + ".bin", "");
    rig.b.limits.max_entries = 4; // a, b, c and the first control: the first slice ends inside /r/a/b/c
    const SliceResult first = checked_slice(make_request(kCtl), rig.b);
    REQUIRE(first.status == Status::ok);
    REQUIRE_FALSE(first.cursor.empty());
    CHECK(count_rows(Run{{first}}, "match|") == 1);

    rig.b.limits.max_entries = fsr::GovernorLimits{}.max_entries;
    rig.fs.list_step = std::chrono::milliseconds{60}; // every listing is a whole work quantum (50 ms) of work
    rig.fs.listed.clear();
    std::vector<std::chrono::milliseconds> sleeps;
    rig.b.sleep = [&rig, &sleeps](std::chrono::milliseconds d) {
        sleeps.push_back(d);
        rig.fs.clock += d;
    };
    const SliceResult second = checked_slice(make_request(kCtl, "/r", "files", first.cursor), rig.b);
    CHECK(second.status == Status::ok);
    CHECK(count_rows(Run{{second}}, "match|") == 2);
    CHECK(rig.fs.listed == Strs{"/r", "/r/a", "/r/a/b", "/r/a/b/c"}); // the whole path back to the resume point
    // Three naps before the re-listings of /r/a, /r/a/b and /r/a/b/c, one at the first entry after them: the
    // plain duty nap of 60 ms each, with no back-off (the listings are evenly fast).
    CHECK(sleeps == std::vector<std::chrono::milliseconds>(4, std::chrono::milliseconds{60}));
}

TEST_CASE("file_search driver: slow re-listings of a resumed slice do not use up the slice before it reaches new work",
          "[file_search][file_search_driver][pacing]") {
    // MUTATION: handing every listing to the governor (starting `judge` true in the driver) lets eleven
    // 300 ms listings double the back-off to its cap and sleep the slice away before the first new entry:
    // the second slice finds nothing and the search can only stall. The first slice ends on entering d10
    // (budget 10: the cursor holds all ten `dirs` and no `after`) or inside it after one match (budget 11:
    // `after` is set too); dropping the `dirs` term from the driver's start test fails the first form.
    const std::size_t first_budget = static_cast<std::size_t>(GENERATE(10, 11));
    const std::size_t first_matches = first_budget - 10;
    Rig rig;
    const std::string deep = "/r/d1/d2/d3/d4/d5/d6/d7/d8/d9/d10";
    for (int i = 1; i <= 3; ++i)
        rig.fs.add_file(deep + "/yuzu-fs-control-" + std::to_string(i) + ".bin", "");
    rig.b.limits.max_entries = first_budget; // d1..d10, and with 11 the first control
    const SliceResult first = checked_slice(make_request(kCtl), rig.b);
    REQUIRE(first.status == Status::ok);
    REQUIRE_FALSE(first.cursor.empty());
    CHECK(count_rows(Run{{first}}, "match|") == first_matches);

    rig.b.limits.max_entries = fsr::GovernorLimits{}.max_entries;
    rig.list_hook = [&rig](const std::string&) {
        rig.fs.clock += std::chrono::milliseconds{300}; // over the hard bound (250 ms): every listing is slow
    };
    rig.fs.listed.clear();
    const SliceResult second = checked_slice(make_request(kCtl, "/r", "files", first.cursor), rig.b);
    CHECK(rig.fs.listed.size() == 11); // /r and the ten below it
    CHECK(second.status == Status::ok);
    CHECK(count_rows(Run{{second}}, "match|") == 3 - first_matches);
    CHECK(second.reason == "none");
}

TEST_CASE("file_search driver: no name the walk visited appears in an emitted cursor row",
          "[file_search][file_search_driver]") {
    const std::vector<std::string> names = {"home", "alice-smith", "tax-return-2025.pdf"};
    const auto qh = fsr::query_hash(make_request(kCtl).query);
    std::set<std::string> carried; // the names some issued cursor's own position held
    std::size_t cursors = 0;
    for (std::size_t entries = 1; entries <= 8; ++entries) {
        Rig rig;
        rig.fs.add_file("/r/home/alice-smith/tax-return-2025.pdf", "");
        rig.fs.add_file("/r/home/alice-smith/yuzu-fs-control-1.bin", "");
        rig.fs.add_file("/r/home/bob/yuzu-fs-control-2.bin", "");
        rig.b.limits.max_entries = entries;
        const Run run = search(rig, kCtl);
        for (const auto& slice : run.slices) {
            if (slice.cursor.empty())
                continue;
            ++cursors;
            const auto fields = split_volume_cursor(slice.cursor);
            REQUIRE(fields.has_value());
            const auto body = yuzu::shared::base64_decode(std::string_view(fields->inner).substr(4));
            REQUIRE(body.has_value());
            const std::string row = row_of(slice, "cursor|");
            CHECK(row == "cursor|" + slice.cursor);
            // what the cursor means to the agent that issued it
            const auto own = decode_volume_cursor(slice.cursor, qh, rig.b.cursor_key);
            REQUIRE(own.has_value());
            for (const auto& name : names) {
                if (own->inner.position.after == name)
                    carried.insert(name);
                for (const auto& dir : own->inner.position.dirs)
                    if (dir.name == name)
                        carried.insert(name);
                INFO("entries " << entries << " name " << name);
                CHECK(row.find(name) == std::string::npos);
                CHECK(slice.cursor.find(name) == std::string::npos);
                CHECK(body->find(name) == std::string::npos);
            }
        }
    }
    // the check above is not vacuous: across the sweep every canary name was in some cursor's position
    CHECK(cursors > 0);
    CHECK(carried == std::set<std::string>(names.begin(), names.end()));
}

TEST_CASE("file_search driver: a forged cursor is refused before any boundary is called",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    const VolumePlan plan = rig.plan();
    VolumeCursor good = cursor_at(rig, 0, 1);

    VolumeCursor foreign = good; // another query's cursor
    foreign.inner.query_hash[0] ^= 0xFF;
    const std::string good_token = encode_volume_cursor(good, rig.b.cursor_key);
    const std::size_t fs1_at = good_token.find("fs1:");
    const std::string inner = good_token.substr(fs1_at, good_token.rfind('.') - fs1_at); // without its mac
    const auto signed_with = [](const CursorKey& key, const std::string& text) {
        return text + "." + detail::cursor_mac(key, text);
    };
    const std::string body = good_token.substr(0, good_token.rfind('.'));
    std::string flipped_mac = good_token; // one digit of the mac changed
    flipped_mac.back() = flipped_mac.back() == '0' ? '1' : '0';
    const std::vector<std::string> forged = {
        "fs1:AAAA",
        "garbage",
        encode_volume_cursor(foreign, rig.b.cursor_key),
        // spelled as no token can be, even under the agent's own key
        signed_with(rig.b.cursor_key, "fsv1.64." + plan.units_hash + "." + plan.refused_hash + "." + inner), // kMaxVolumes
        signed_with(rig.b.cursor_key, "fsv1.0.ZZZZZZZZZZZZZZZZ." + plan.refused_hash + "." + inner),        // not hex
        // right spelling, but not signed by this agent process
        body,                                           // no mac at all
        signed_with(test_key(0x43), body),              // another process's key
        flipped_mac,
        good_token + "0",                               // a mac one digit too long
        good_token.substr(0, good_token.size() - 1),
    };
    for (const auto& c : forged) {
        const SliceResult r = checked_slice(make_request(kCtl, "/r", "files", c), rig.b);
        INFO(c);
        CHECK(r.status == Status::invalid);
        CHECK(r.reason == "bad_cursor");
        CHECK(r.rows.size() == 1);
    }
    CHECK(rig.mount_reads == 0);
    CHECK(rig.runner_calls == 0);
    CHECK(rig.legs.empty()); // no leg factory, no user-roots reader before the cursor is believed
    CHECK(rig.user_root_reads == 0);

    // The cursor is judged BEFORE the slot is taken: a forged one answers bad_cursor even while another
    // slice holds the slot, never busy, and it neither takes nor releases the slot.
    rig.slot = true;
    const SliceResult held = checked_slice(make_request(kCtl, "/r", "files", flipped_mac), rig.b);
    CHECK(held.status == Status::invalid);
    CHECK(held.reason == "bad_cursor");
    CHECK(rig.slot.load());
    CHECK(rig.mount_reads == 0);
    CHECK(rig.legs.empty());
    CHECK(rig.user_root_reads == 0);
    rig.slot = false;

    // a well-formed cursor of a changed unit set ends the search once the table has been read
    VolumeCursor moved = good;
    moved.units_hash = "ffffffffffffffff";
    const SliceResult changed =
        checked_slice(make_request(kCtl, "/r", "files", encode_volume_cursor(moved, rig.b.cursor_key)), rig.b);
    CHECK(changed.status == Status::failed);
    CHECK(changed.reason == "mount_table_changed");
    CHECK(changed.cursor.empty());
    CHECK(starts(row_of(changed, "coverage|"), "coverage|partial|"));
    CHECK(rig.runner_calls == 0);

    // the right hashes with a unit index past the plan are refused too
    VolumeCursor past = good;
    past.index = 5;
    CHECK(checked_slice(make_request(kCtl, "/r", "files", encode_volume_cursor(past, rig.b.cursor_key)), rig.b).status ==
          Status::invalid);
}

TEST_CASE("file_search driver: a cursor this agent did not issue cannot finish a search over volumes it never searched",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r/usb", "vfat", "8:9").add("/r/more", "ext4", "8:2");
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/more/yuzu-fs-control-2.bin", "");
    const VolumePlan plan = rig.plan();
    REQUIRE(plan.units.size() == 2);   // the root's mount, then /r/more
    REQUIRE(plan.refused.size() == 1); // the vfat mount at /r/usb

    // The honest search reads partial: the refused mount was never searched.
    const Run honest = search(rig, kCtl);
    REQUIRE(honest.slices.size() == 2);
    CHECK(starts(row_of(honest.last(), "coverage|"), "coverage|partial|"));
    CHECK(count_rows(honest, "volume|/r/usb|vfat|not_searched|fstype_not_allowed|") == 1);

    // A caller builds the token that would end the search at its last unit, with no gap carried and both
    // hashes read off the plan, and signs it with a key it holds. The agent refuses it: no mount table is
    // read, no worker is started, no coverage is stated.
    const VolumeCursor last_unit = cursor_at(rig, 1, 1);
    rig.mount_reads = 0;
    rig.runner_calls = 0;
    const SliceResult forged = checked_slice(
        make_request(kCtl, "/r", "files", encode_volume_cursor(last_unit, test_key(0x43))), rig.b);
    CHECK(forged.status == Status::invalid);
    CHECK(forged.reason == "bad_cursor");
    CHECK(forged.rows.size() == 1);
    CHECK(forged.cursor.empty());
    CHECK(rig.mount_reads == 0);
    CHECK(rig.runner_calls == 0);

    // Control: the same cursor signed with the agent's own key is believed. The key is the only barrier.
    const SliceResult trusted = checked_slice(
        make_request(kCtl, "/r", "files", encode_volume_cursor(last_unit, rig.b.cursor_key)), rig.b);
    CHECK(trusted.status == Status::ok);
    CHECK(rig.mount_reads == 1);
}

TEST_CASE("file_search driver: a cursor from before an agent restart is refused and the search starts again",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r/more", "ext4", "8:2");
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/more/yuzu-fs-control-2.bin", "");
    const SliceResult first = checked_slice(make_request(kCtl), rig.b);
    REQUIRE(first.status == Status::ok);
    REQUIRE_FALSE(first.cursor.empty());

    rig.b.cursor_key = test_key(0x77); // a new process draws a new key
    rig.mount_reads = 0;
    const SliceResult after = checked_slice(make_request(kCtl, "/r", "files", first.cursor), rig.b);
    CHECK(after.status == Status::invalid);
    CHECK(after.reason == "bad_cursor");
    CHECK(rig.mount_reads == 0);

    // Starting again needs no cursor and finishes the search under the new key.
    const Run again = search(rig, kCtl);
    CHECK(again.last().status == Status::ok);
    CHECK(again.last().cursor.empty());
    CHECK(starts(row_of(again.last(), "coverage|"), "coverage|complete|"));
}

TEST_CASE("file_search driver: a cursor key nobody set is refused before a cursor, a mount table or a worker",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.b.cursor_key = CursorKey{}; // the default: all zero
    const std::vector<std::string> cursors = {"", "fsv1.0.0123456789abcdef.fedcba9876543210.fs1:AAAA.00000000000000000000000000000000"};
    for (const std::string& cursor : cursors) {
        const SliceResult r = checked_slice(make_request(kCtl, "/r", "files", cursor), rig.b);
        CHECK(r.status == Status::failed);
        CHECK(r.reason == "internal_error");
        CHECK(r.cursor.empty());
    }
    CHECK(rig.mount_reads == 0);
    CHECK(rig.runner_calls == 0);
    CHECK(rig.legs.empty());
    CHECK(rig.user_root_reads == 0);
}

TEST_CASE("file_search driver: an unreadable or malformed mount table ends the slice with no walk",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.b.read_mounts = [&](const std::string&) { return std::optional<yuzu::shared::MountTable>{}; };
    const SliceResult none = checked_slice(make_request(kCtl), rig.b);
    CHECK(none.status == Status::failed);
    CHECK(none.reason == "mount_table_unreadable");
    CHECK(starts(row_of(none, "coverage|"), "coverage|partial|"));
    CHECK(rig.runner_calls == 0);

    rig.b.read_mounts = [&](const std::string&) {
        return std::optional<yuzu::shared::MountTable>(yuzu::shared::mount_entries("garbage line\n"));
    };
    CHECK(checked_slice(make_request(kCtl), rig.b).reason == "mount_table_unreadable");

    // a table with no mount that contains the root describes nothing
    rig.b.read_mounts = [&](const std::string&) {
        return std::optional<yuzu::shared::MountTable>(Mounts{}.add("/elsewhere", "ext4").table());
    };
    CHECK(checked_slice(make_request(kCtl), rig.b).reason == "mount_table_unreadable");
    CHECK(rig.runner_calls == 0);
}

// ---- caps ----

TEST_CASE("file_search driver: the per-directory match cap is one gap and a partial verdict",
          "[file_search][file_search_driver]") {
    Rig rig;
    for (int i = 0; i < 501; ++i) {
        std::string n = std::to_string(i);
        rig.bulk_file("/r", "yuzu-fs-control-" + std::string(3 - n.size(), '0') + n + ".bin");
    }
    rig.fs.add_file("/r/sub/yuzu-fs-control-x.bin", ""); // another directory is unaffected
    const Run run = search(rig, kCtl);
    CHECK(found(run).size() == kMaxMatchesPerDirectory + 1);
    CHECK(count_rows(run, "gap|/r|match_cap") == 1);
    CHECK(count_rows(run, "gap|") == 1);
    CHECK(run.last().status == Status::ok);
    CHECK_FALSE(complete(run));
}

TEST_CASE("file_search driver: a gap path over the bound is counted, never emitted",
          "[file_search][file_search_driver]") {
    Rig rig;
    std::string dir = "/r";
    for (int i = 0; i < 5; ++i)
        dir += "/" + std::string(200, static_cast<char>('a' + i));
    rig.fs.add_dir(dir);
    rig.fs.dangling_dir(dir + "/" + std::string(200, 'f')); // a listing error beneath a path of 1,200 bytes
    REQUIRE(dir.size() + 201 > kMaxGapPathBytes);
    const Run run = search(rig, kCtl);
    CHECK(count_rows(run, "gap|") == 0);
    CHECK(count_rows(run, "gaps_dropped|1") == 1);
    CHECK_FALSE(complete(run));
}

TEST_CASE("file_search driver: the byte budget ends a slice before a row would overflow, trailer and cursor intact",
          "[file_search][file_search_driver]") {
    Rig rig;
    // Long paths make big rows, so a few thousand files fill the byte budget: eight directories of 450
    // files (under the per-directory cap) beneath a root path of about 1,600 bytes.
    std::string base = "/r";
    for (int i = 0; i < 8; ++i)
        base += "/" + std::string(200, static_cast<char>('a' + i));
    constexpr int kDirs = 8, kPerDir = 450, kFiles = kDirs * kPerDir;
    for (int d = 0; d < kDirs; ++d) {
        const std::string dir = base + "/e" + std::to_string(d);
        rig.fs.add_dir(dir);
        for (int i = 0; i < kPerDir; ++i)
            rig.bulk_file(dir, "yuzu-" + std::to_string(1000 + i) + std::string(90, 'x') + ".bin");
    }
    rig.b.limits.max_rows = 1'000'000; // the row count never ends the slice: the bytes do
    const Run run = search(rig, "yuzu-*.bin");
    REQUIRE(run.slices.size() >= 2);
    const SliceResult& first = run.slices[0];
    CHECK(first.status == Status::ok);
    CHECK(first.reason == "budget_rows");
    REQUIRE_FALSE(first.cursor.empty());
    CHECK(starts(first.rows.back(), "search|ok|budget_rows|"));
    CHECK_FALSE(row_of(first, "cursor|").empty());
    CHECK_FALSE(row_of(first, "coverage|").empty());
    std::size_t bytes = 0;
    for (const auto& r : first.rows)
        bytes += r.size() + 1;
    CHECK(bytes < kSliceRowBytes);
    CHECK(bytes > kMatchRowBudget - 2 * kMaxMatchRowBytes - 4096); // it used what it had
    // nothing is dropped: every file is found exactly once across the slices
    const auto all = found(run);
    CHECK(all.size() == static_cast<std::size_t>(kFiles));
    CHECK(std::set<std::string>(all.begin(), all.end()).size() == static_cast<std::size_t>(kFiles));
    CHECK(complete(run));
}

// ---- churn between slices ----

TEST_CASE("file_search driver: a changed unit set between slices ends the search with mount_table_changed",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r/data", "ext4", "8:2");
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/data/yuzu-fs-control-2.bin", "");
    const SliceResult one = checked_slice(make_request(kCtl), rig.b);
    REQUIRE_FALSE(one.cursor.empty());
    rig.mounts.add("/r/more", "ext4", "8:3");
    const SliceResult two = checked_slice(make_request(kCtl, "/r", "files", one.cursor), rig.b);
    CHECK(two.status == Status::failed);
    CHECK(two.reason == "mount_table_changed");
    CHECK(two.cursor.empty());
    CHECK(starts(row_of(two, "coverage|"), "coverage|partial|"));
    CHECK(starts(row_of(two, "search|"), "search|failed|mount_table_changed|"));
}

TEST_CASE("file_search driver: a refused mount appearing between slices is reported, counted and does not end the search",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.mounts.add("/r/a", "ext4", "8:2").add("/r/b", "ext4", "8:3");
    rig.fs.add_file("/r/a/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/b/yuzu-fs-control-2.bin", "");
    const SliceResult one = checked_slice(make_request(kCtl), rig.b);
    REQUIRE_FALSE(one.cursor.empty());
    CHECK(count_rows(Run{{one}}, "volume|") == 1); // nothing refused yet

    rig.mounts.add("/r/tmpx", "tmpfs", "0:7", "/", "tmpfs"); // appears mid-search
    const SliceResult two = checked_slice(make_request(kCtl, "/r", "files", one.cursor), rig.b);
    CHECK(two.status == Status::ok);
    REQUIRE_FALSE(two.cursor.empty());
    CHECK(count_rows(Run{{two}}, "volume|/r/tmpx|tmpfs|not_searched|fstype_not_allowed|") == 1);
    const auto qh = fsr::query_hash(make_request(kCtl).query);
    const auto next = decode_volume_cursor(two.cursor, qh, rig.b.cursor_key);
    REQUIRE(next.has_value());
    CHECK(next->inner.prior_gaps == 1); // the count rose
    CHECK(next->refused_hash == rig.plan().refused_hash);

    const SliceResult three = checked_slice(make_request(kCtl, "/r", "files", two.cursor), rig.b);
    CHECK(three.status == Status::ok);
    CHECK(three.cursor.empty());
    CHECK(count_rows(Run{{three}}, "volume|/r/tmpx|") == 0); // not re-emitted: the set did not change again
    CHECK_FALSE(starts(row_of(three, "coverage|"), "coverage|complete|"));
}

TEST_CASE("file_search driver: a resumed slice whose unit root can no longer be listed completes with one gap and a partial verdict",
          "[file_search][file_search_driver]") {
    Rig rig;
    for (int i = 0; i < 4; ++i) {
        rig.fs.add_file("/r/a/yuzu-fs-control-a" + std::to_string(i) + ".bin", "");
        rig.fs.add_file("/r/b/yuzu-fs-control-b" + std::to_string(i) + ".bin", "");
    }
    rig.b.limits.max_entries = 3; // the first slice stops inside the unit
    const SliceResult one = checked_slice(make_request(kCtl), rig.b);
    REQUIRE(one.status == Status::ok);
    REQUIRE_FALSE(one.cursor.empty());
    const auto cursor = decode_volume_cursor(one.cursor, fsr::query_hash(make_request(kCtl).query), rig.b.cursor_key);
    REQUIRE(cursor.has_value());
    REQUIRE_FALSE(cursor->inner.position == fsr::Position{}); // a position inside the unit, not a fresh start

    rig.fs.dirs.erase("/r"); // replaced by something unreadable between the slices
    const SliceResult two = checked_slice(make_request(kCtl, "/r", "files", one.cursor), rig.b);
    CHECK(two.status == Status::ok);
    CHECK(two.reason == "none");
    CHECK(two.cursor.empty()); // the slice completed, so the search is finished
    CHECK(count_rows(Run{{two}}, "match|") == 0);
    CHECK(count_rows(Run{{two}}, "gap|") == 1);
    CHECK(row_of(two, "gap|") == "gap|/r|dir_unreadable");
    CHECK(row_of(two, "volume|").find("volume|/|ext4|complete|none|") == 0);
    CHECK(starts(row_of(two, "coverage|"), "coverage|partial|"));
    CHECK(starts(row_of(two, "search|"), "search|ok|none|"));
}

TEST_CASE("file_search driver: lost-response replays and a throwing slice leave a verdict that depends only on the issued cursors",
          "[file_search][file_search_driver]") {
    const auto build = [](Rig& r) {
        r.mounts.add("/r/data", "ext4", "8:2");
        for (int i = 0; i < 4; ++i) {
            r.fs.add_file("/r/yuzu-fs-control-a" + std::to_string(i) + ".bin", "");
            r.fs.add_file("/r/s/yuzu-fs-control-b" + std::to_string(i) + ".bin", "");
            r.fs.add_file("/r/data/yuzu-fs-control-c" + std::to_string(i) + ".bin", "");
        }
    };
    Rig clean;
    build(clean);
    clean.b.limits.max_entries = 3;
    const Run reference = search(clean, kCtl);
    REQUIRE(complete(reference));

    Rig noisy;
    build(noisy);
    noisy.b.limits.max_entries = 3;
    bool armed = false;
    noisy.list_hook = [&](const std::string&) {
        if (armed) {
            armed = false;
            throw std::runtime_error("lost");
        }
    };
    Run kept;
    std::string cursor;
    for (std::size_t i = 0; i < 100; ++i) {
        const Request req = make_request(kCtl, "/r", "files", cursor);
        const SliceResult lost = checked_slice(req, noisy.b);        // the response never arrives
        armed = true;
        const SliceResult thrown = checked_slice(req, noisy.b);      // the retry's worker throws
        CHECK(thrown.status == Status::failed);
        CHECK(thrown.reason == "internal_error");
        const SliceResult again = checked_slice(req, noisy.b);       // and the next retry gets through
        CHECK(again.rows == lost.rows);                          // a replay is the same answer
        CHECK(again.cursor == lost.cursor);
        cursor = again.cursor;
        kept.slices.push_back(again);
        if (cursor.empty())
            break;
    }
    CHECK(found(kept) == found(reference));
    CHECK(complete(kept));
    CHECK(kept.slices.size() == reference.slices.size());
    for (std::size_t i = 0; i < kept.slices.size(); ++i)
        CHECK(kept.slices[i].cursor == reference.slices[i].cursor);
}

// ---- a seeded sweep ----

namespace {

struct Lcg {
    std::uint64_t s;
    std::size_t below(std::size_t n) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return static_cast<std::size_t>((s >> 33) % n);
    }
};

struct World {
    Strs files;   // every file path
    Strs matches; // the ones the pattern matches, outside the refused mount
};

void grow(Rig& rig, Lcg& g, World& w, const std::string& dir, std::size_t depth, bool refused) {
    static const std::vector<std::pair<std::string, std::string>> stems = {
        {"ctl-a", ".bin"}, {"ctl-b", ".bin"}, {"ctl-c", ".bin"}, {"note", ".txt"}, {"ctlx", ".dat"}, {"z", ".bin"}};
    const std::size_t n = g.below(6);
    for (std::size_t i = 0; i < n; ++i) {
        const auto& [base, ext] = stems[g.below(stems.size())];
        const std::string name = base + (g.below(3) == 0 ? std::to_string(i) : "") + ext;
        const std::string path = dir + "/" + name;
        if (rig.fs.files.contains(path))
            continue;
        rig.fs.add_file(path, "");
        w.files.push_back(path);
        if (base.rfind("ctl-", 0) == 0 && ext == ".bin" && !refused)
            w.matches.push_back(path);
    }
    if (depth < 3)
        for (std::size_t i = 0, k = g.below(3); i < k; ++i)
            grow(rig, g, w, dir + "/d" + std::to_string(i), depth + 1, refused);
}

} // namespace

TEST_CASE("file_search driver: a seeded sweep over trees, budgets and mutations finds every surviving file once, never skips one",
          "[file_search][file_search_driver]") {
    for (std::uint64_t seed = 1; seed <= 40; ++seed) {
        INFO("seed " << seed);
        Lcg g{seed * 7919};
        Rig rig;
        World w;
        const bool m1 = g.below(2) == 0, tmp = g.below(2) == 0;
        const bool m2 = m1 && g.below(2) == 0;
        if (m1)
            rig.mounts.add("/r/m1", "ext4", "8:2");
        if (m2)
            rig.mounts.add("/r/m1/inner", "ext4", "8:3");
        if (tmp)
            rig.mounts.add("/r/tmp", "tmpfs", "0:7", "/", "tmpfs");
        grow(rig, g, w, "/r", 0, false);
        if (m1) {
            rig.fs.add_dir("/r/m1");
            grow(rig, g, w, "/r/m1", 1, false);
        }
        if (m2) {
            rig.fs.add_dir("/r/m1/inner");
            grow(rig, g, w, "/r/m1/inner", 2, false);
        }
        if (tmp) {
            rig.fs.add_dir("/r/tmp");
            grow(rig, g, w, "/r/tmp", 1, true);
        }

        const bool mutate = g.below(2) == 0;
        switch (g.below(3)) {
        case 0:
            rig.b.limits.max_entries = 2 + g.below(8);
            break;
        case 1:
            rig.b.limits.max_rows = 1 + g.below(4);
            break;
        default:
            break;
        }

        std::set<std::string> deleted;
        const Run run = search(rig, "ctl-*.bin", "/r", "files", [&](std::size_t slice) {
            if (!mutate || slice == 0 || w.matches.empty() || g.below(2) != 0)
                return;
            const std::string victim = w.matches[g.below(w.matches.size())];
            if (deleted.insert(victim).second)
                rig.remove_file(victim); // vanishes between slices
        });
        REQUIRE(run.last().status == Status::ok);
        REQUIRE(run.last().cursor.empty());

        const auto all = found(run);
        const std::multiset<std::string> seen(all.begin(), all.end());
        for (const auto& path : w.matches) {
            if (deleted.contains(path))
                continue;
            CHECK(seen.count(path) >= 1); // a surviving file is never silently skipped
            if (!mutate)
                CHECK(seen.count(path) == 1);
        }
        for (const auto& path : all)
            CHECK(std::ranges::find(w.matches, path) != w.matches.end()); // nothing else is reported
        if (!mutate)
            CHECK(complete(run) == !tmp);
    }
}

// ---- the entry gap, the leg's own extents state, the roots and the worker-made leg ----

namespace {

DirEntry gap_entry(std::string name, Type type, fsr::GapCause cause, std::uint64_t hint = 0) {
    DirEntry e{std::move(name), type};
    e.gap = cause;
    e.leg_hint = hint;
    return e;
}

/// A real bounded runner with a fixed 100 ms bound, so a test can drive a blocked worker.
RunOutcome<WorkResult> bounded_100ms(std::chrono::milliseconds, std::function<WorkResult()> work) {
    auto ran = yuzu::shared::bounded_call_ex(std::chrono::milliseconds{100}, std::move(work));
    RunOutcome<WorkResult> out;
    switch (ran.status) {
    case yuzu::shared::BoundedCallStatus::Completed:
        out.status = RunStatus::completed;
        out.value = std::move(ran.value);
        break;
    case yuzu::shared::BoundedCallStatus::TimedOut:
        out.status = RunStatus::timed_out;
        break;
    case yuzu::shared::BoundedCallStatus::Rejected:
        out.status = RunStatus::rejected;
        break;
    }
    return out;
}

std::vector<std::string> rows_of_kind(const Run& run, const std::string& prefix) {
    std::vector<std::string> out;
    for (const auto& s : run.slices)
        for (const auto& row : s.rows)
            if (starts(row, prefix))
                out.push_back(row);
    return out;
}

/// path -> scope of every match row of the run.
std::map<std::string, std::string> scopes_of(const Run& run) {
    std::map<std::string, std::string> out;
    for (const auto& row : rows_of_kind(run, "match|")) {
        const auto cols = split(row);
        const auto path = fsr::decode_name(cols[1]);
        REQUIRE(path.has_value());
        out[*path] = cols[6];
    }
    return out;
}

} // namespace

TEST_CASE("file_search driver: an entry with a gap is one gap row, never visited, entered, charged or carried in a cursor",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    rig.fs.add_file("/r/yuzu-fs-control-3.bin", "");
    rig.fs.add_file("/r/yuzu-fs-control-dir/inner.bin", ""); // must never be listed: its entry carries a gap
    auto& root = rig.fs.dirs["/r"];
    std::erase_if(root, [](const DirEntry& e) { return e.name == "yuzu-fs-control-dir"; });
    root.push_back(gap_entry("yuzu-fs-control-2.bin", Type::file, fsr::GapCause::reparse_unknown));
    root.push_back(gap_entry("yuzu-fs-control-dir", Type::dir, fsr::GapCause::dataless));
    rig.b.limits.max_entries = 1; // only a searchable entry is charged

    const Run run = search(rig, kCtl, "/r", "both");
    CHECK(sorted(found(run)) == Strs{"/r/yuzu-fs-control-1.bin", "/r/yuzu-fs-control-3.bin"});
    CHECK(sorted(rig.facts_calls) == Strs{"/r/yuzu-fs-control-1.bin", "/r/yuzu-fs-control-3.bin"}); // never opened
    CHECK(std::ranges::find(rig.fs.listed, "/r/yuzu-fs-control-dir") == rig.fs.listed.end());      // never entered
    const auto gaps = rows_of_kind(run, "gap|");
    CHECK(std::ranges::any_of(gaps, [](const std::string& g) { return g.find("reparse_unknown") != std::string::npos; }));
    CHECK(std::ranges::any_of(gaps, [](const std::string& g) { return g.find("dataless") != std::string::npos; }));
    CHECK_FALSE(complete(run)); // a gap makes the verdict partial
    // and no cursor of the search names an entry that carried a gap
    const auto qh = fsr::query_hash(make_request(kCtl, "/r", "both").query);
    for (const auto& s : run.slices) {
        if (s.cursor.empty())
            continue;
        const auto cursor = decode_volume_cursor(s.cursor, qh, rig.b.cursor_key);
        REQUIRE(cursor.has_value());
        const auto& pos = cursor->inner.position;
        CHECK(pos.after != "yuzu-fs-control-2.bin");
        CHECK(pos.after != "yuzu-fs-control-dir");
        for (const auto& f : pos.dirs)
            CHECK(f.name != "yuzu-fs-control-dir");
    }
}

TEST_CASE("file_search driver: facts receives the listed entry and its leg_hint",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    for (auto& e : rig.fs.dirs["/r"])
        if (e.name == "yuzu-fs-control-1.bin")
            e.leg_hint = 0x2000000000000420ULL;
    const Run run = search(rig, kCtl);
    CHECK(found(run) == Strs{"/r/yuzu-fs-control-1.bin"});
    CHECK(rig.hints_seen.at("/r/yuzu-fs-control-1.bin") == 0x2000000000000420ULL);
}

TEST_CASE("file_search driver: the leg's extents state and note are printed as the leg gave them",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-a.bin", "");
    rig.fs.add_file("/r/yuzu-fs-control-b.bin", "");
    rig.fs.add_file("/r/yuzu-fs-control-c.bin", "");
    rig.facts_override = [](const std::string&, const DirEntry& e) {
        FileFacts f;
        if (e.name == "yuzu-fs-control-a.bin") { // never opened: unsupported, and the note says why
            f.extents.state = ExtentsState::unsupported;
            f.extents.note = "placeholder";
        } else if (e.name == "yuzu-fs-control-b.bin") { // opened and fully local: real extents, flagged as cloud
            f.facts.opened = true;
            f.facts.size = 7;
            f.facts.mtime = MemTree::kDefaultMtime;
            f.extents.state = ExtentsState::ok;
            f.extents.note = "cloud";
            f.extents.add({0, 4096, 4096, 0});
        } else { // never opened, nothing said: failed, as on POSIX
            f.extents.state = ExtentsState::failed;
        }
        return f;
    };
    const Run run = search(rig, kCtl);
    const auto matches = rows_of_kind(run, "match|");
    const auto extents = rows_of_kind(run, "extents|");
    REQUIRE(matches.size() == 3);
    REQUIRE(extents.size() == 3);
    CHECK(extents[0].find("|unsupported:placeholder|0|-") != std::string::npos);
    CHECK(matches[0].ends_with("|-|-|system")); // size and time read '-'
    CHECK(extents[1].find("|ok:cloud|1|0:4096:4096:-") != std::string::npos);
    CHECK_FALSE(matches[1].ends_with("|-|-|system"));
    CHECK(extents[2].find("|failed|0|-") != std::string::npos);
    CHECK(extents[2].find("failed:") == std::string::npos); // no note: the state alone
}

TEST_CASE("file_search driver: an opened file whose facts carry no time prints `-` for the time and still prints its size",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-a.bin", "");
    rig.fs.add_file("/r/yuzu-fs-control-b.bin", "");
    rig.facts_override = [](const std::string&, const DirEntry& e) {
        FileFacts f;
        f.facts.opened = true;
        f.facts.size = 3;
        if (e.name == "yuzu-fs-control-b.bin")
            f.facts.mtime = 0; // a real 1970-01-01 time is a time, and prints as one
        f.extents.state = ExtentsState::failed;
        return f;
    };
    const Run run = search(rig, kCtl);
    const auto matches = rows_of_kind(run, "match|");
    REQUIRE(matches.size() == 2);
    CHECK(matches[0].ends_with("|3|-|system")); // no time: `-`, not `0`
    CHECK(matches[1].ends_with("|3|0|system"));
}

TEST_CASE("file_search driver: a Windows-labelled tree walks, reports label paths, and tags a relocated profile through the unit's roots",
          "[file_search][file_search_driver]") {
    for (const std::string label : {"/C:", "/Volume{0f1e2d3c-1111-2222-3333-444455556666}"}) {
        INFO(label);
        Rig rig;
        rig.b.os = Os::windows;
        rig.mounts = Mounts{};
        rig.mounts.add(label, "NTFS", "0:5");
        for (const char* dir : {"/Profiles/alice", "/Profilesx", "/Users/bob", "/Windows"})
            rig.fs.add_file(label + dir + "/yuzu-fs-control-1.bin", "");
        std::vector<std::string> units_seen;
        rig.user_roots_fn = [&](const Unit& u) {
            units_seen.push_back(u.mount_point);
            return std::vector<std::string>{u.mount_point + "/Profiles/alice"};
        };
        const Run run = search(rig, kCtl, label);
        REQUIRE(run.last().status == Status::ok);
        const auto scopes = scopes_of(run);
        REQUIRE(scopes.size() == 4);
        CHECK(scopes.at(label + "/Profiles/alice/yuzu-fs-control-1.bin") == "user");   // the relocated profile
        CHECK(scopes.at(label + "/Profilesx/yuzu-fs-control-1.bin") == "system");      // a sibling prefix is not it
        CHECK(scopes.at(label + "/Users/bob/yuzu-fs-control-1.bin") == "user");        // the built-in rule
        CHECK(scopes.at(label + "/Windows/yuzu-fs-control-1.bin") == "system");
        CHECK(units_seen == Strs{label}); // read once, for the unit that was searched
        CHECK(rig.user_root_reads == 1);

        // an unset reader tags by the built-in rule only
        Rig plain;
        plain.b.os = Os::windows;
        plain.b.read_user_roots = nullptr;
        plain.mounts = Mounts{};
        plain.mounts.add(label, "NTFS", "0:5");
        for (const char* dir : {"/Profiles/alice", "/Users/bob"})
            plain.fs.add_file(label + dir + "/yuzu-fs-control-1.bin", "");
        const auto plain_scopes = scopes_of(search(plain, kCtl, label));
        CHECK(plain_scopes.at(label + "/Profiles/alice/yuzu-fs-control-1.bin") == "system");
        CHECK(plain_scopes.at(label + "/Users/bob/yuzu-fs-control-1.bin") == "user");
    }
}

TEST_CASE("file_search driver: the leg and the user roots are made only inside the runner's work",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    const std::string key = rig.plan().units[0].key();

    rig.mode = Rig::Mode::reject; // refused: nothing ran
    CHECK(checked_slice(make_request(kCtl), rig.b).reason == "rejected");
    CHECK(rig.legs.empty());
    CHECK(rig.user_root_reads == 0);
    CHECK_FALSE(rig.slot.load());

    rig.mode = Rig::Mode::timeout; // held: the work was handed over and never started
    CHECK(checked_slice(make_request(kCtl), rig.b).reason == "timed_out");
    CHECK(rig.legs.empty());
    CHECK(rig.user_root_reads == 0);
    CHECK_FALSE(rig.slot.load());
    CHECK(rig.state.abandoned_count() == 1);
    CHECK(rig.state.is_stalled(key));

    // the held work is what builds the leg and reads the roots, when it finally runs
    REQUIRE(rig.held);
    const WorkResult late = rig.held();
    CHECK_FALSE(late.threw);
    CHECK(rig.legs == Strs{"/r"});
    CHECK(rig.user_root_reads == 1);
}

TEST_CASE("file_search driver: a refused root reads no user roots", "[file_search][file_search_driver]") {
    Rig rig;
    rig.link("/r");
    const SliceResult r = checked_slice(make_request(kCtl), rig.b);
    CHECK(r.status == Status::invalid);
    CHECK(r.reason == "root_is_link");
    CHECK(rig.legs == Strs{"/r"}); // the leg answered the root check
    CHECK(rig.user_root_reads == 0);
}

TEST_CASE("file_search driver: a leg factory that blocks is a timed-out slice, the slot is freed and the worker is abandoned",
          "[file_search][file_search_driver]") {
    Rig rig;
    rig.fs.add_file("/r/yuzu-fs-control-1.bin", "");
    const std::string key = rig.plan().units[0].key();
    // The factory owns only what it shares: the gate, and a throw once released, so the abandoned worker ends
    // without touching the rig.
    auto release = std::make_shared<std::promise<void>>();
    std::shared_future<void> gate = release->get_future().share();
    rig.b.make_leg = [gate](const Unit&) -> UnitLeg {
        gate.wait();
        throw std::runtime_error("factory released");
    };
    rig.b.run_bounded = &bounded_100ms;

    const SliceResult first = checked_slice(make_request(kCtl), rig.b);
    CHECK(first.status == Status::failed);
    CHECK(first.reason == "timed_out");
    CHECK_FALSE(rig.slot.load());
    CHECK(rig.state.abandoned_count() == 1);
    CHECK(rig.state.is_stalled(key));

    // the next slice finds that volume stalled and does not walk it
    const SliceResult next = checked_slice(make_request(kCtl), rig.b);
    CHECK(next.status == Status::ok);
    CHECK(next.reason == "stalled");
    CHECK(row_of(next, "volume|").find("volume|/|ext4|partial|stalled|") == 0);

    release->set_value(); // the test lets the factory go before it ends
}
