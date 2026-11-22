/**
 * test_file_search_cursor.cpp -- unit tests for agents/shared/file_search_position.hpp and
 * file_search_cursor.hpp: the walk position and its order, the resume-cursor wire token and the
 * transition validator of the on-demand file search. Pure and portable: no filesystem, process or
 * clock, so it runs unguarded on every OS.
 */
#include <catch2/catch_test_macros.hpp>

#include <base64.hpp>
#include <file_search_cursor.hpp>
#include <file_search_position.hpp>

#include <compare>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fs = yuzu::shared::file_search;

namespace {

constexpr std::uint32_t kU32Max = std::numeric_limits<std::uint32_t>::max();

fs::QueryHash hash_of(std::uint8_t seed) {
    fs::QueryHash h{};
    for (std::size_t i = 0; i < h.size(); ++i)
        h[i] = static_cast<std::uint8_t>(seed + i);
    return h;
}

fs::Position pos(std::initializer_list<std::string> dirs, std::string after = {}) {
    fs::Position p;
    for (const auto& d : dirs)
        p.dirs.push_back({d, 0, 0});
    p.after = std::move(after);
    return p;
}

fs::Cursor cursor_at(fs::Position p, std::uint64_t seq = 1, std::uint32_t gen = 0, std::uint32_t gaps = 0) {
    fs::Cursor c{hash_of(1)};
    c.sequence = seq;
    c.generation = gen;
    c.prior_gaps = gaps;
    c.position = std::move(p);
    return c;
}

fs::Cursor deep_cursor(std::size_t depth) {
    fs::Cursor c{hash_of(7)};
    c.sequence = 41;
    c.generation = 3;
    c.prior_gaps = 5;
    c.position.root_dev = 0x11;
    c.position.root_file_id = 0x22;
    for (std::size_t i = 0; i < depth; ++i)
        c.position.dirs.push_back({"d" + std::to_string(i), 100 + i, 200 + i});
    if (depth != 0)
        c.position.after = "last";
    return c;
}

std::string token_of_body(const std::string& body) {
    return std::string(fs::kCursorPrefix) + yuzu::shared::base64_encode(body);
}

std::string body_of(const fs::Cursor& c) { return fs::detail::cursor_body(c); }

} // namespace

// --- position ---------------------------------------------------------------------------------

TEST_CASE("valid_component / valid_position", "[file_search]") {
    CHECK(fs::valid_component("a"));
    CHECK(fs::valid_component(std::string(255, 'x')));
    CHECK(fs::valid_component(".hidden"));
    CHECK(fs::valid_component("..."));
    CHECK_FALSE(fs::valid_component(""));
    CHECK_FALSE(fs::valid_component(std::string(256, 'x')));
    CHECK_FALSE(fs::valid_component("."));
    CHECK_FALSE(fs::valid_component(".."));
    CHECK_FALSE(fs::valid_component("a/b"));
    CHECK_FALSE(fs::valid_component(std::string_view("a\0b", 3)));

    CHECK(fs::valid_position({}));
    CHECK(fs::valid_position(deep_cursor(fs::kMaxPositionDepth).position));
    CHECK_FALSE(fs::valid_position(deep_cursor(fs::kMaxPositionDepth + 1).position));
    CHECK_FALSE(fs::valid_position(pos({"ok", ".."})));
    CHECK_FALSE(fs::valid_position(pos({"ok"}, "a/b")));
    CHECK(fs::valid_position(pos({"ok"}, "fine")));
}

TEST_CASE("walk_order: depth-first vectors", "[file_search]") {
    const auto lt = [](const fs::Position& a, const fs::Position& b) {
        return fs::walk_order(a, b) < 0 && fs::walk_order(b, a) > 0;
    };
    // inside X at its start < X completed
    CHECK(lt(pos({"X"}), pos({}, "X")));
    // after W < inside X when W < X
    CHECK(lt(pos({}, "W"), pos({"X"})));
    // inside X after m < X completed
    CHECK(lt(pos({"X"}, "m"), pos({}, "X")));
    // inside X is later than a completed sibling that sorts before it, earlier than one after it
    CHECK(lt(pos({}, "W"), pos({"X"}, "m")));
    CHECK(lt(pos({"X"}, "m"), pos({}, "Y")));
    // empty `after` is the start of the directory: smallest
    CHECK(lt(pos({}), pos({}, "a")));
    CHECK(lt(pos({}), pos({"a"})));
    // same dir, byte order of `after` (unsigned bytes)
    CHECK(lt(pos({"X"}, "a"), pos({"X"}, "b")));
    CHECK(lt(pos({"X"}, "a"), pos({"X"}, "ab")));
    CHECK(lt(pos({"X"}, "a"), pos({"X"}, "\xc3\xa9")));
    // two dirs at one level compare by name, whatever is below
    CHECK(lt(pos({"A", "zz"}, "q"), pos({"B"})));
    // deeper: inside X/Y vs X completed-at-level-1
    CHECK(lt(pos({"X", "Y"}), pos({"X"}, "Y")));
    CHECK(lt(pos({"X"}, "Q"), pos({"X", "R"})));
    // reflexive equality
    for (const auto& p : {pos({}), pos({}, "a"), pos({"X", "Y"}, "z")})
        CHECK(std::is_eq(fs::walk_order(p, p)));
}

TEST_CASE("walk_order: identities do not affect the order", "[file_search]") {
    auto a = pos({"X", "Y"}, "m");
    auto b = a;
    b.root_dev = 9;
    b.root_file_id = 8;
    b.dirs[0].dev = 7;
    b.dirs[1].file_id = 6;
    CHECK(std::is_eq(fs::walk_order(a, b)));
    auto later = pos({"X", "Y"}, "n");
    later.dirs[0].dev = 99;
    CHECK(std::is_lt(fs::walk_order(a, later)));
}

TEST_CASE("walk_order: antisymmetric and transitive over a small universe", "[file_search]") {
    std::vector<fs::Position> u;
    for (const std::string& after : {std::string{}, std::string{"a"}, std::string{"b"}}) {
        u.push_back(pos({}, after));
        u.push_back(pos({"a"}, after));
        u.push_back(pos({"b"}, after));
        u.push_back(pos({"a", "a"}, after));
        u.push_back(pos({"a", "b"}, after));
    }
    int bad = 0;
    for (const auto& x : u)
        for (const auto& y : u) {
            const auto xy = fs::walk_order(x, y);
            const auto yx = fs::walk_order(y, x);
            if (!((xy < 0 && yx > 0) || (xy > 0 && yx < 0) || (xy == 0 && yx == 0)))
                ++bad;
            for (const auto& z : u)
                if (xy < 0 && fs::walk_order(y, z) < 0 && !(fs::walk_order(x, z) < 0))
                    ++bad;
        }
    CHECK(bad == 0);
}

// --- token round trip and errors --------------------------------------------------------------

TEST_CASE("cursor token: round-trips at depth 0, 1 and kMaxPositionDepth", "[file_search]") {
    for (const std::size_t depth : {std::size_t{0}, std::size_t{1}, fs::kMaxPositionDepth}) {
        const auto c = deep_cursor(depth);
        const auto token = fs::encode_cursor(c);
        REQUIRE(token.size() <= fs::kMaxCursorTokenBytes);
        const auto back = fs::decode_cursor(token, c.query_hash);
        REQUIRE(back);
        CHECK(*back == c);
        CHECK(fs::encode_cursor(*back) == token);
    }
    // A search start round-trips too.
    const fs::Cursor start{hash_of(3)};
    const auto back = fs::decode_cursor(fs::encode_cursor(start), start.query_hash);
    REQUIRE(back);
    CHECK(*back == start);
    // Maximal names and non-ASCII names.
    auto c = deep_cursor(fs::kMaxPositionDepth);
    for (auto& f : c.position.dirs)
        f.name = std::string(255, 'n');
    c.position.after = "caf\xc3\xa9";
    REQUIRE(fs::encode_cursor(c).size() <= fs::kMaxCursorTokenBytes);
    const auto big = fs::decode_cursor(fs::encode_cursor(c), c.query_hash);
    REQUIRE(big);
    CHECK(*big == c);
}

TEST_CASE("cursor token: framing errors", "[file_search]") {
    using E = fs::CursorError;
    const auto c = deep_cursor(2);
    const auto good = fs::encode_cursor(c);
    const auto err = [&](std::string_view t, const fs::QueryHash& h = hash_of(7)) {
        const auto r = fs::decode_cursor(t, h);
        REQUIRE_FALSE(r);
        return r.error();
    };
    CHECK(err(std::string(fs::kMaxCursorTokenBytes + 1, 'A')) == E::too_long);
    CHECK(err(std::string("fs1:") + std::string(fs::kMaxCursorTokenBytes, 'A')) == E::too_long);
    CHECK(err("") == E::bad_prefix);
    CHECK(err("fs2:" + good.substr(4)) == E::bad_prefix);
    CHECK(err("FS1:" + good.substr(4)) == E::bad_prefix);
    CHECK(err(good.substr(4)) == E::bad_prefix);
    CHECK(err(good, hash_of(8)) == E::query_mismatch);

    // version 2
    auto body = body_of(c);
    body[0] = 2;
    CHECK(err(token_of_body(body)) == E::bad_version);
    body[0] = 0;
    CHECK(err(token_of_body(body)) == E::bad_version);

    // every truncation point of the body
    const auto full = body_of(c);
    int not_truncated = 0;
    for (std::size_t n = 0; n < full.size(); ++n) {
        const auto r = fs::decode_cursor(token_of_body(full.substr(0, n)), hash_of(7));
        if (r || r.error() != E::truncated)
            ++not_truncated;
    }
    CHECK(not_truncated == 0);

    // one trailing byte (and the full body is accepted)
    CHECK(fs::decode_cursor(token_of_body(full), hash_of(7)));
    CHECK(err(token_of_body(full + '\0')) == E::trailing_bytes);
    CHECK(err(token_of_body(full + "xyz")) == E::trailing_bytes);

    // a declared name longer than the remaining body is truncated, never an over-read
    auto lying = full;
    lying[1 + 16 + 8 + 4 + 4 + 8 + 8 + 1] = '\xff';
    lying[1 + 16 + 8 + 4 + 4 + 8 + 8 + 2] = '\xff';
    CHECK(err(token_of_body(lying)) == E::truncated);
}

TEST_CASE("cursor token: position errors", "[file_search]") {
    using E = fs::CursorError;
    const auto err = [](const fs::Cursor& c) {
        const auto r = fs::decode_cursor(token_of_body(body_of(c)), c.query_hash);
        REQUIRE_FALSE(r);
        return r.error();
    };
    for (const std::string_view bad : {std::string_view("a/b"), std::string_view("a\0b", 3),
                                       std::string_view("."), std::string_view(".."), std::string_view()}) {
        auto in_dir = deep_cursor(1);
        in_dir.position.dirs[0].name = std::string(bad);
        CHECK(err(in_dir) == E::bad_position);
    }
    for (const std::string_view bad : {std::string_view("a/b"), std::string_view("a\0b", 3),
                                       std::string_view("."), std::string_view("..")}) {
        auto in_after = deep_cursor(1);
        in_after.position.after = std::string(bad);
        CHECK(err(in_after) == E::bad_position);
    }
    auto long_name = deep_cursor(1);
    long_name.position.dirs[0].name = std::string(256, 'x');
    CHECK(err(long_name) == E::bad_position);
    CHECK(err(deep_cursor(fs::kMaxPositionDepth + 1)) == E::bad_position);
    // encode_cursor refuses to write what the decoder would refuse.
    CHECK(fs::encode_cursor(deep_cursor(fs::kMaxPositionDepth + 1)).empty());
    CHECK(fs::encode_cursor(long_name).empty());
}

TEST_CASE("cursor token: non-canonical base64 spellings are bad_base64", "[file_search]") {
    // test_base64.cpp pins the decoder's rules; this pins that decode_cursor hands the token to that
    // strict decoder untouched: one spelling per class, no URL-safe mapping, trim or re-padding.
    const auto c = deep_cursor(1);
    const auto good = fs::encode_cursor(c);
    const auto bad_base64 = [&](const std::string& t) {
        const auto r = fs::decode_cursor(t, c.query_hash);
        REQUIRE_FALSE(r);
        CHECK(r.error() == fs::CursorError::bad_base64);
    };
    REQUIRE(fs::decode_cursor(good, c.query_hash));
    REQUIRE(good.ends_with("==")); // the body is 76 bytes, 1 mod 3

    for (const char bad : {'-', '_', '='}) { // URL-safe alphabet, padding mid-token
        auto t = good;
        t[10] = bad;
        bad_base64(t);
    }
    bad_base64(good + "\n");                          // whitespace
    bad_base64(good.substr(0, good.size() - 2));      // padding stripped
    auto slop = good;                                 // non-zero slop bit in the last data character
    ++slop[slop.size() - 3];
    bad_base64(slop);
}

TEST_CASE("cursor token: 20000-mutation sweep: accepted tokens are canonical", "[file_search]") {
    std::mt19937_64 rng(0xC0FFEE'5EED'0001ULL);
    std::vector<fs::Cursor> seeds = {deep_cursor(0), deep_cursor(1), deep_cursor(3), fs::Cursor{hash_of(7)}};
    const auto mutate = [&](std::string s) {
        for (int m = 0, n = 1 + static_cast<int>(rng() % 3); m < n; ++m) {
            const auto at = static_cast<std::size_t>(rng() % s.size());
            switch (rng() % 4) {
            case 0:
                s[at] = static_cast<char>(rng() & 0xFF);
                break;
            case 1:
                s.erase(at, 1);
                break;
            case 2:
                s.insert(at, 1, static_cast<char>(rng() & 0xFF));
                break;
            default:
                s.resize(at);
                break;
            }
            if (s.empty())
                s = "x";
        }
        return s;
    };
    int bad = 0;
    int accepted = 0;
    for (int i = 0; i < 20000; ++i) {
        const auto& c = seeds[rng() % seeds.size()];
        // even: damage the base64 text; odd: damage the body and re-encode, so it reaches the field parser
        const auto token = (i & 1) == 0 ? mutate(fs::encode_cursor(c)) : token_of_body(mutate(body_of(c)));
        const auto r = fs::decode_cursor(token, c.query_hash);
        if (r) {
            ++accepted;
            if (fs::encode_cursor(*r) != token)
                ++bad;
        }
    }
    CHECK(bad == 0);
    CHECK(accepted > 0); // the sweep does reach the accept path
}

// --- transitions ------------------------------------------------------------------------------

TEST_CASE("strictly_advances: ordinary transition", "[file_search]") {
    const fs::Cursor start{hash_of(1)};
    auto first = cursor_at(pos({}, "a"), 1);
    first.position.root_dev = 5;
    first.position.root_file_id = 6;
    CHECK(fs::strictly_advances(start, first)); // root identity not yet known: the first slice

    const auto step = [&](auto&& edit) {
        auto n = first;
        n.sequence = 2;
        n.position.after = "b";
        edit(n);
        return fs::strictly_advances(first, n);
    };
    CHECK(step([](fs::Cursor&) {}));
    CHECK(step([](fs::Cursor& n) { n.position.dirs.push_back({"z", 1, 2}); })); // deeper = later
    CHECK_FALSE(step([](fs::Cursor& n) { n.position.after = "a"; }));           // equal position
    CHECK_FALSE(step([](fs::Cursor& n) { n.position.after.clear(); }));         // backward
    CHECK_FALSE(step([](fs::Cursor& n) { n.sequence = 1; }));                   // repeats
    CHECK_FALSE(step([](fs::Cursor& n) { n.sequence = 3; }));                   // skips
    CHECK_FALSE(step([](fs::Cursor& n) { n.sequence = 0; }));
    CHECK_FALSE(step([](fs::Cursor& n) { n.query_hash = hash_of(2); }));

    // Root identity, 0 = unknown: a half may become known on any slice; a known half may neither
    // change nor go back to 0 without a generation step.
    const auto root = [&](std::uint64_t pd, std::uint64_t pi, std::uint64_t nd, std::uint64_t ni) {
        auto p = first;
        p.position.root_dev = pd;
        p.position.root_file_id = pi;
        auto n = p;
        n.sequence = 2;
        n.position.after = "b";
        n.position.root_dev = nd;
        n.position.root_file_id = ni;
        return fs::strictly_advances(p, n);
    };
    CHECK(root(5, 0, 5, 6));       // the file id is learned
    CHECK(root(0, 6, 5, 6));       // the device is learned
    CHECK(root(5, 0, 5, 0));       // nothing new learned
    CHECK_FALSE(root(5, 6, 0, 6)); // a known device goes back to unknown
    CHECK_FALSE(root(5, 6, 5, 0)); // a known file id goes back to unknown
    CHECK_FALSE(root(5, 0, 9, 6)); // a known device changes while the file id is learned
    CHECK_FALSE(root(0, 6, 5, 7)); // a known file id changes while the device is learned
    CHECK_FALSE(root(5, 6, 9, 6)); // a known device changes

    auto with_gaps = first;
    with_gaps.prior_gaps = 4;
    auto lower = with_gaps;
    lower.sequence = 2;
    lower.position.after = "b";
    lower.prior_gaps = 3;
    CHECK_FALSE(fs::strictly_advances(with_gaps, lower));
    lower.prior_gaps = 4;
    CHECK(fs::strictly_advances(with_gaps, lower));
    lower.prior_gaps = 9;
    CHECK(fs::strictly_advances(with_gaps, lower));

    // No sequence wrap.
    auto top = first;
    top.sequence = std::numeric_limits<std::uint64_t>::max();
    auto wrapped = top;
    wrapped.sequence = 0;
    wrapped.position.after = "b";
    CHECK_FALSE(fs::strictly_advances(top, wrapped));
}

TEST_CASE("strictly_advances: restart transition", "[file_search]") {
    auto prev = cursor_at(pos({"X"}, "m"), 4, 2);
    prev.position.root_dev = 5;
    prev.position.root_file_id = 6;

    auto restart = prev;
    restart.sequence = 5;
    restart.generation = 3;
    restart.position = pos({}, ""); // restarts from the start: EARLIER
    restart.position.root_dev = 5;
    restart.position.root_file_id = 6;
    CHECK(std::is_gt(fs::walk_order(prev.position, restart.position)));
    CHECK(fs::strictly_advances(prev, restart));

    auto new_root = restart;
    new_root.position.root_dev = 77; // a replaced root
    new_root.position.root_file_id = 78;
    CHECK(fs::strictly_advances(prev, new_root));

    auto down = restart;
    down.generation = 1;
    CHECK_FALSE(fs::strictly_advances(prev, down));
    auto skip = restart;
    skip.generation = 4;
    CHECK_FALSE(fs::strictly_advances(prev, skip));
    auto equal_backward = restart;
    equal_backward.generation = 2;
    CHECK_FALSE(fs::strictly_advances(prev, equal_backward)); // backward without a step
    auto equal_same_root_new = new_root;
    equal_same_root_new.generation = 2;
    CHECK_FALSE(fs::strictly_advances(prev, equal_same_root_new));

    // A restart still obeys the common rules.
    auto bad_seq = restart;
    bad_seq.sequence = 6;
    CHECK_FALSE(fs::strictly_advances(prev, bad_seq));
    auto bad_hash = restart;
    bad_hash.query_hash = hash_of(9);
    CHECK_FALSE(fs::strictly_advances(prev, bad_hash));
    auto less_gaps = restart;
    prev.prior_gaps = 2;
    less_gaps.prior_gaps = 1;
    CHECK_FALSE(fs::strictly_advances(prev, less_gaps));

    // No generation wrap.
    auto top = prev;
    top.generation = kU32Max;
    auto wrapped = restart;
    wrapped.generation = 0;
    wrapped.prior_gaps = 2;
    CHECK_FALSE(fs::strictly_advances(top, wrapped));
}

TEST_CASE("next_cursor: builds exactly the transitions strictly_advances accepts", "[file_search]") {
    auto p = cursor_at(pos({"X"}, "m"), 7, 1, 2);
    p.position.root_dev = 5;
    p.position.root_file_id = 6;
    const auto later = [&] {
        auto l = pos({}, "X");
        l.root_dev = 5;
        l.root_file_id = 6;
        return l;
    }();
    const auto earlier = [&] {
        auto e = pos({}, "");
        e.root_dev = 5;
        e.root_file_id = 6;
        return e;
    }();

    const auto ordinary = fs::next_cursor(p, later, false, 3);
    CHECK(ordinary.sequence == 8);
    CHECK(ordinary.generation == 1);
    CHECK(ordinary.prior_gaps == 5);
    CHECK(ordinary.query_hash == p.query_hash);
    CHECK(ordinary.position == later);
    CHECK(fs::strictly_advances(p, ordinary));

    const auto restarted = fs::next_cursor(p, earlier, true, 0);
    CHECK(restarted.generation == 2);
    CHECK(fs::strictly_advances(p, restarted));

    CHECK_FALSE(fs::strictly_advances(p, fs::next_cursor(p, earlier, false, 0)));
    CHECK_FALSE(fs::strictly_advances(p, fs::next_cursor(p, p.position, false, 0)));

    // from a search start
    const fs::Cursor start{hash_of(1)};
    CHECK(fs::strictly_advances(start, fs::next_cursor(start, pos({}, "a"), false, 0)));

    // prior_gaps saturates at UINT32_MAX and still advances
    auto high = p;
    high.prior_gaps = kU32Max - 1;
    CHECK(fs::next_cursor(high, later, false, 1).prior_gaps == kU32Max);
    CHECK(fs::next_cursor(high, later, false, 5).prior_gaps == kU32Max);
    CHECK(fs::next_cursor(p, later, false, std::numeric_limits<std::size_t>::max()).prior_gaps == kU32Max);
    auto at_max = p;
    at_max.prior_gaps = kU32Max;
    const auto sat = fs::next_cursor(at_max, later, false, 1);
    CHECK(sat.prior_gaps == kU32Max);
    CHECK(fs::strictly_advances(at_max, sat));
}
