/**
 * test_store_wiring_order.cpp -- #3261 regression guard: every
 * `agent_service_.set_X(member_.get())` / `gateway_service_->set_X(member_.get())`
 * call in server.cpp must run AFTER `member_`'s construction, never before.
 *
 * WHY THIS GUARD EXISTS. #3261: a wiring block ran at the top of the
 * ServerImpl constructor, guarded by `if (notification_store_)` /
 * `if (webhook_store_)` / `if (offload_target_store_)` -- but each of those
 * three members was constructed ~650 lines LATER in the same constructor.
 * The guards were unique_ptr members default-initialised to null, so they
 * were guaranteed-false on every boot, not merely racy: dashboard
 * notifications, webhook delivery, and response offload from the
 * AgentServiceImpl paths (Register / Subscribe / process_gateway_response)
 * were silently dead for the life of the process. Every use site
 * double-guards `ptr && ptr->is_open()` with silent skip, so nothing logged
 * or alerted -- the bug produced zero signal. A source-scan guard is the
 * only thing that would have caught it, because ServerImpl is not
 * unit-constructible (see test_default_certs.cpp's note that boot ordering
 * is exercised only by a live boot test, external to this suite).
 *
 * MECHANISM -- no hand-copied member list. This test opens server.cpp (via
 * `YUZU_SERVER_SRC_DIR`, injected by tests/meson.build) AT TEST RUN TIME and
 * regex-scans the raw source text for:
 *   - every `agent_service_.set_X(member_.get())` / `gateway_service_->
 *     set_X(member_.get())` call (the setter-call regex captures the member
 *     name from its `.get()` argument, so no separate list of members needs
 *     maintaining); and
 *   - every `member_ = std::make_unique<...>` construction.
 * For each setter call at line L wiring member M, the rule is: some
 * construction of M exists, and the EARLIEST such construction is on a line
 * strictly before L. Every member matched by the setter regex has exactly
 * one `std::make_unique` site today (verified at the time this test was
 * written) -- "earliest" is the chosen semantic for the day a member ever
 * gains a second construction site (e.g. a reconfigure/rebuild path).
 *
 * `//` line comments are stripped before scanning, defensively -- verified
 * at the time of writing that server.cpp's match counts are IDENTICAL with
 * and without stripping (no setter or construction call is presently
 * mentioned only inside a comment), so this costs nothing today and guards
 * against a future false match/miss inside commented-out code. The HA
 * ConfinedDispatchSink check further down is the exception: it needs the strip
 * (see the last bullet below).
 *
 * EXCLUDED BY THE REGEX, NOT BY AN ALLOWLIST: by-reference setter forms
 * (`set_health_store(&health_store_)`, `set_blast_radius_detector(&blast_
 * radius_detector_)`) since they take `&member_`, not `member_.get()`; every
 * `set_X(nullptr)` shutdown null-out in `stop()`, since `nullptr` is not
 * `\w+_\.get()`; and local-variable / config-value setters (e.g.
 * `set_agent_cert_signer(cert_signer)`), since the argument is not of the
 * form `<name>_.get()` bound to a `std::make_unique<...>`-constructed
 * member. A member wired from a helper or a non-`make_unique` factory would
 * be invisible to the construction regex; there are none in server.cpp
 * today (no `.reset(new` / `= std::unique_ptr<` assignment exists there),
 * and the sanity floor below fails loudly if the setter side of the scan
 * ever drifts to near-zero.
 *
 * A member wired anywhere in server.cpp -- new file location aside, since
 * this scan is server.cpp-specific, matching where every setter/construction
 * call for these three stores and their 25 correctly-ordered siblings
 * presently lives -- is picked up automatically on the next test run.
 * Nothing here needs updating when a setter or construction call is added
 * in the correct order; a failure means an ordering regression was
 * introduced, not that this file is stale.
 *
 * COST ON WINDOWS. server.cpp is loaded and comment-stripped once, by
 * cached_server_cpp_text() below: take the text from it rather than reading the
 * file in a new case. A whole-text std::regex over the ~0.76 MB stripped file can
 * be very slow on MSVC debug depending on the pattern's shape -- one with an
 * optional capture group at its head took 231 s there (about 1.5 s on libc++),
 * while the plain patterns in this file cost a few seconds per pass. For a new
 * scan prefer std::string_view::find plus a small matcher (see
 * confined_sink_scan.hpp), and time it on a Windows debug build.
 *
 * WHAT THIS SCAN DOES NOT CATCH (governance Gate 3 architect + quality-
 * engineer, both SHOULD, recorded here per docs-writer-owns-wording /
 * domain-agent-owns-truth so a reader trusts the guarantee this test
 * actually gives, not a stronger one):
 *   - A setter wired to the WRONG member, e.g. `set_webhook_store(
 *     offload_target_store_.get())`. The scan ties correctness to whichever
 *     member name literally appears in the call; it has no notion of which
 *     member a given setter is SUPPOSED to receive.
 *   - A setter or construction inside a branch that is never taken at
 *     runtime (dead code, an always-false `if`). This is pure text-position
 *     scanning with no control-flow awareness -- a setter genuinely gated on
 *     a runtime condition (e.g. NotificationStore's PG-fail-closed branch)
 *     is indistinguishable, from the regex's point of view, from one that
 *     can never execute at all.
 *   - PRESENCE. The order check only fires for setters that exist; deleting
 *     a setter (and its member's construction) outright does not fail this
 *     test as long as >= 25 setters remain (see the sanity floor below) --
 *     see the presence-pin TEST_CASE in this file, which pins presence of the
 *     three specific #3261 setters explicitly, for exactly this reason.
 *   - Only single-line `//`-style comments are stripped before scanning --
 *     C-style block comments are NOT stripped. Empirically harmless today
 *     (no setter or construction call is presently written inside one), and
 *     deliberately left unstripped rather than "fixed" with a naive
 *     block-comment-matching regex -- an early attempt at exactly that
 *     swallowed real code by opening a phantom block comment inside a
 *     string literal elsewhere in server.cpp that happens to contain a
 *     slash-star-shaped substring, losing ~2000 real lines including 5 live
 *     setters from the scan. A correct fix needs a string-literal-aware
 *     stripper, which this file does not attempt.
 *   - The HA WS-5 ConfinedDispatchSink scan is a separate, regex-free scan (the
 *     hand-written matcher in confined_sink_scan.hpp). It recognises one
 *     spelling, `[yuzu::server::]ConfinedDispatchSink [identifier] {`. A
 *     construction written with parentheses, `= {`, a type alias, or a block
 *     comment between the type and its brace is invisible to it, and so is one in
 *     any file other than server.cpp and dispatch_scope_ladder.hpp; the
 *     site-count pin cannot flag what the scan cannot see. It is purely lexical
 *     and runs on text with `//` comments stripped, which the ladder site needs
 *     (raw, its `has_remote_presence` lies 1533 bytes from the site's start, past
 *     the window, because 760 bytes of `//` comments sit inside its initialiser;
 *     stripped, it is 773 bytes in). The stripper also cuts a line at a `//`
 *     inside a string literal. A brace-shaped mention inside a block comment or a
 *     string literal is counted as a site, which fails the count pin loudly
 *     (unless a real site is lost in the same edit). Its two field markers,
 *     `has_remote_presence` and `->prepare(`, are
 *     searched as plain text in the next kFieldWindow (1200) bytes: one further
 *     away reads as missing and fails loudly, but one that belongs to whatever
 *     follows a site, or that sits inside a block comment or a string literal
 *     within the window, is credited to the site and passes silently (no real
 *     site is followed by one today). The check is presence-only:
 *     `prepare_route_fallback` and `presence_widens` share a type
 *     (`dispatch_confined_arms.hpp`), so a site with the two positional lambdas
 *     swapped still passes.
 */

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "confined_sink_scan.hpp"

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (meson.project_source_root() / 'server' / 'core' / 'src') -- see the server_test_exe cpp_args block."
#endif

using yuzu::test::wiring_scan::find_confined_dispatch_sink_sites;
using yuzu::test::wiring_scan::kFieldWindow;
using yuzu::test::wiring_scan::kTypeName;

namespace {

namespace fs = std::filesystem;

struct SetterCall {
    int line;
    std::string receiver; // "agent_service_" or "gateway_service_"
    std::string setter;   // e.g. "notification_store"
    std::string member;   // e.g. "notification_store_"
};

// Times cached_server_cpp_text() has loaded server.cpp. Plain int: Catch2 runs cases serially.
int g_server_cpp_loads = 0;

std::string read_text_file(const fs::path& path) {
    INFO("reading " << path.string());
    REQUIRE(fs::is_regular_file(path));
    std::ifstream in(path, std::ios::binary);
    REQUIRE(in.is_open());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

int line_of(const std::string& text, std::size_t pos) {
    return static_cast<int>(std::count(text.begin(), text.begin() + static_cast<long>(pos), '\n')) +
           1;
}

/// `agent_service_.set_X(member_.get())` / `gateway_service_->set_X(member_.get())`.
/// Group 1: receiver (the trailing `.`/`->` is stripped off below so both
/// spellings compare equal). Group 2: setter suffix. Group 3: member name.
std::vector<SetterCall> extract_setter_calls(const std::string& text) {
    static const std::regex re(
        R"regex(\b(agent_service_\.|gateway_service_->)set_(\w+)\(\s*(\w+_)\.get\(\)\s*\))regex");
    std::vector<SetterCall> out;
    for (auto it = std::sregex_iterator(text.begin(), text.end(), re); it != std::sregex_iterator();
         ++it) {
        const auto& m = *it;
        const std::string raw_receiver = m[1].str();
        const std::string receiver =
            raw_receiver == "agent_service_." ? "agent_service_" : "gateway_service_";
        out.push_back(
            {line_of(text, static_cast<std::size_t>(m.position(0))), receiver, m[2].str(), m[3].str()});
    }
    return out;
}

/// `member_ = std::make_unique<...>`. Returns every construction line per
/// member (a member with more than one site keeps every line; the rule
/// checked below uses the earliest).
std::map<std::string, std::vector<int>> extract_constructions(const std::string& text) {
    static const std::regex re(R"regex(\b(\w+_)\s*=\s*std::make_unique<)regex");
    std::map<std::string, std::vector<int>> out;
    for (auto it = std::sregex_iterator(text.begin(), text.end(), re); it != std::sregex_iterator();
         ++it) {
        const auto& m = *it;
        out[m[1].str()].push_back(line_of(text, static_cast<std::size_t>(m.position(0))));
    }
    return out;
}

std::string strip_line_comments(const std::string& text) {
    static const std::regex re(R"(//[^\n]*)");
    return std::regex_replace(text, re, "");
}

/// server.cpp, comment-stripped, loaded once per process and shared by every
/// real-source TEST_CASE: take the text from this accessor rather than reading the
/// file again (the strip alone is a whole-text regex pass, about 0.5 s on MSVC debug,
/// and each case used to repeat it). Function-local static: read-only input, and
/// Catch2 runs the cases serially in one process.
const std::string& cached_server_cpp_text() {
    static const std::string text = [] {
        std::string stripped =
            strip_line_comments(read_text_file(fs::path(YUZU_SERVER_SRC_DIR) / "server.cpp"));
        ++g_server_cpp_loads; // a failed read throws first, and the next call retries
        return stripped;
    }();
    return text;
}

} // namespace

// Only the #1712 case's `== 4` count depends on the strip (unstripped, a `//` mention
// makes it 5); the other cases pass either way. So pin the content directly: no `//`
// survives (the naive stripper removes them even inside string literals), and it is
// still server.cpp.
TEST_CASE("cached_server_cpp_text is server.cpp with every // comment stripped",
          "[wiring_order]") {
    const std::string& text = cached_server_cpp_text();
    CHECK(text.find("//") == std::string::npos);
    CHECK(text.find("ServerImpl") != std::string::npos);
}

// The count pins the memoisation: an accessor that reloaded on each call would
// fail. It cannot see a case that reads the file some other way.
TEST_CASE("cached_server_cpp_text loads server.cpp exactly once per process",
          "[wiring_order]") {
    (void)cached_server_cpp_text();
    (void)cached_server_cpp_text();
    (void)cached_server_cpp_text();
    CHECK(g_server_cpp_loads == 1);
}

TEST_CASE("server.cpp: every agent_service_/gateway_service_ store setter runs after "
          "its member's construction (#3261)",
          "[wiring_order]") {
    const std::string& text = cached_server_cpp_text();
    const auto setters = extract_setter_calls(text);
    const auto constructions = extract_constructions(text);

    // Sanity floor: measured 28 setter calls against server.cpp at the time
    // this test was written. A near-zero count means the SCAN is broken (a
    // receiver/method spelling drifted, or YUZU_SERVER_SRC_DIR points
    // somewhere unexpected), not that the wired-store surface shrank to
    // nothing -- fail loud rather than pass vacuously.
    REQUIRE(setters.size() >= 25);

    for (const auto& s : setters) {
        INFO("setter " << s.receiver << ".set_" << s.setter << "(" << s.member
                        << ".get()) at server.cpp:" << s.line);
        auto it = constructions.find(s.member);
        const bool has_construction = it != constructions.end() && !it->second.empty();
        CHECK(has_construction);
        if (!has_construction)
            continue;
        const int earliest_construction = *std::min_element(it->second.begin(), it->second.end());
        INFO("earliest construction of " << s.member << " at server.cpp:" << earliest_construction);
        CHECK(earliest_construction < s.line);
    }
}

TEST_CASE("server.cpp: the three #3261 setters specifically are still present "
          "(#3261 presence pin)",
          "[wiring_order]") {
    // Companion to the ordering test above (quality-engineer SHOULD, Gate
    // 3): that test only asserts ORDER for whatever setters happen to
    // exist, gated by a >= 25 sanity floor. Deleting all three of
    // #3261's setters outright (28 - 3 = 25) would still clear that
    // floor and pass silently -- exactly the literal symptom #3261 was.
    // Pin presence of these three explicitly so that regression can never
    // hide behind the floor.
    const std::string& text = cached_server_cpp_text();
    const auto setters = extract_setter_calls(text);

    auto has = [&](const char* receiver, const char* setter, const char* member) {
        return std::any_of(setters.begin(), setters.end(), [&](const SetterCall& s) {
            return s.receiver == receiver && s.setter == setter && s.member == member;
        });
    };
    CHECK(has("agent_service_", "notification_store", "notification_store_"));
    CHECK(has("agent_service_", "webhook_store", "webhook_store_"));
    CHECK(has("agent_service_", "offload_target_store", "offload_target_store_"));
}

// #1712 branch-review finding (Functional CDX-FV-01, HIGH): the production
// Response:Read visibility resolver `response_visible_set_fn` (defined
// ~server.cpp:16819, wired into DashboardRoutes::register_routes as its
// trailing argument ~server.cpp:18401) is referenced by ZERO test files --
// every dashboard route test injects its own synthetic VisibleSetFn. Dropping
// the production registration argument (e.g. reverting to the pre-#1712
// call, or replacing it with `{}`) would restore fleet-wide facet/scope
// disclosure in production while every existing #1712 test stayed green,
// because none of them exercise this composition. Following this file's own
// established mechanism (ServerImpl is not unit-constructible, so a source
// scan is the only thing that can catch a dropped composition at all) rather
// than inventing a second one.
TEST_CASE("server.cpp: response_visible_set_fn is both defined and passed to "
          "DashboardRoutes::register_routes (#1712)",
          "[wiring_order][1712]") {
    const std::string& text = cached_server_cpp_text();

    // Sanity floor: server.cpp is a six-figure-character file; a
    // suspiciously short read means YUZU_SERVER_SRC_DIR pointed somewhere
    // empty or mangled, not that the file legitimately shrank.
    REQUIRE(text.size() > 100000);

    // POSITIVE anchor 1: the resolver is defined, and its body is the real
    // decision ladder -- not a stub that always returns nullopt/fleet-wide.
    // Requiring both calls it actually makes (not just its name) means a
    // resolver silently downgraded to "return std::nullopt;" still fails
    // this, even though `response_visible_set_fn` itself would still exist.
    static const std::regex definition_re(R"(auto response_visible_set_fn =)");
    CHECK(std::regex_search(text, definition_re));
    static const std::regex global_check_re(
        R"(check_permission\(username, "Response", "Read"\))");
    CHECK(std::regex_search(text, global_check_re));
    static const std::regex scoped_check_re(
        R"(visible_agents_for_permission\(username, "Response", "Read")");
    CHECK(std::regex_search(text, scoped_check_re));

    // POSITIVE anchor 2: the resolver is actually PASSED to
    // register_routes, not merely defined and left unused. This is what
    // distinguishes "wired" from "defined but dropped at the call site" --
    // the failure mode a name-presence-only check would miss entirely. The
    // optional `std::move(...)` wrapper is tolerated -- moving the callback
    // into the by-value `VisibleSetFn` parameter is the correct idiom (it's
    // never used again after this call) and must not make this anchor a
    // false negative.
    static const std::regex wired_re(
        R"(,\s*(?:std::move\()?response_visible_set_fn\)?\s*\))");
    CHECK(std::regex_search(text, wired_re));

    // #4033 (#2146 Batch A): the SAME resolver instance now has THREE
    // consumers -- DashboardRoutes::register_routes (original, #1712),
    // RestApiV1::register_routes (GET /api/v1/management-groups/agent-count-
    // preview), and McpServer::set_response_visible_set_fn
    // (preview_management_group_agent_count) -- one definition + three uses =
    // 4 occurrences. This is deliberate CONVERGENCE, not the divergent-copy
    // anti-pattern the original 2-occurrence floor guarded against: all three
    // surfaces share the identical std::function so REST, MCP, and the
    // dashboard fragment cannot disagree on scope for the same caller
    // (docs/api-twin-recipe.md Rule 1). A FIFTH occurrence (a second,
    // independently-defined `response_visible_set_fn` variable, or a fourth
    // consumer wired to a DIFFERENT resolver under the same name) would still
    // be the anti-pattern this floor exists to catch.
    static const std::regex occurrence_re(R"(\bresponse_visible_set_fn\b)");
    auto count = static_cast<std::ptrdiff_t>(
        std::distance(std::sregex_iterator(text.begin(), text.end(), occurrence_re),
                      std::sregex_iterator()));
    CHECK(count == 4);
}

// HA WS-5 governance hardening (Gate 3 quality-engineer finding, 2026-09-22):
// `registry_.configure_presence(offline_endpoint_store_.get(), ...)` is the
// EXACT #3261 shape (a wiring call whose safety depends on running after its
// member's construction) but doesn't match this file's general setter regex
// — different receiver (`registry_`, not `agent_service_`/`gateway_service_
// ->`), a two-argument setter, and a name that isn't `set_X`. Rather than
// widen the general regex (risking exactly the false-match/false-miss class
// its own header comment warns block-comment-stripping already caused once),
// this is a dedicated bespoke-anchor test, following the same
// ServerImpl-is-not-unit-constructible / source-scan rationale as the
// #1712 test above.
TEST_CASE("server.cpp: registry_.configure_presence runs after "
          "offline_endpoint_store_'s construction (HA WS-5)",
          "[wiring_order][ha]") {
    const std::string& text = cached_server_cpp_text();

    static const std::regex construct_re(
        R"(offline_endpoint_store_\s*=\s*std::make_unique<)");
    std::smatch construct_match;
    REQUIRE(std::regex_search(text, construct_match, construct_re));
    const int construct_line = line_of(text, static_cast<std::size_t>(construct_match.position(0)));

    static const std::regex wire_re(
        R"(registry_\.configure_presence\(\s*offline_endpoint_store_\.get\(\))");
    std::smatch wire_match;
    REQUIRE(std::regex_search(text, wire_match, wire_re));
    const int wire_line = line_of(text, static_cast<std::size_t>(wire_match.position(0)));

    INFO("offline_endpoint_store_ constructed at server.cpp:" << construct_line);
    INFO("registry_.configure_presence(offline_endpoint_store_.get(), ...) at server.cpp:"
         << wire_line);
    CHECK(construct_line < wire_line);

    // The teardown null-out (`registry_.configure_presence(nullptr, ...)`)
    // must run BEFORE offline_endpoint_store_.reset() destroys the object
    // presence_store_ borrows — the inverse ordering requirement stop()
    // exists to satisfy (see agent_registry.hpp's presence_store_ doc
    // comment and the comment on this call site in server.cpp).
    static const std::regex null_wire_re(R"(registry_\.configure_presence\(\s*nullptr\s*,)");
    std::smatch null_wire_match;
    REQUIRE(std::regex_search(text, null_wire_match, null_wire_re));
    const int null_wire_line = line_of(text, static_cast<std::size_t>(null_wire_match.position(0)));

    static const std::regex reset_re(R"(offline_endpoint_store_\.reset\(\))");
    std::smatch reset_match;
    REQUIRE(std::regex_search(text, reset_match, reset_re));
    const int reset_line = line_of(text, static_cast<std::size_t>(reset_match.position(0)));

    INFO("registry_.configure_presence(nullptr, ...) at server.cpp:" << null_wire_line);
    INFO("offline_endpoint_store_.reset() at server.cpp:" << reset_line);
    CHECK(null_wire_line < reset_line);
}

// HA WS-5 governance hardening (external review finding, 2026-09-22): the
// PR's own body records that a THIRD production ConfinedDispatchSink
// construction site (dispatch_scope_ladder.hpp) was missed by the initial
// diff and found only on a second architect pass — the exact class of bug
// a source-scan guard exists to catch structurally, not rely on a human
// re-read to catch a second time. This scans EVERY production
// ConfinedDispatchSink{...} construction (server.cpp AND dispatch_scope_ladder.hpp
// — the two files known to construct one) and asserts each one wires BOTH
// the presence-widening check (has_remote_presence, the field that replaced
// the original racy local_agent_count design) and the gateway-directory
// fallback (prepare_route_fallback) — a sink missing either silently
// reintroduces the exact bug class this slice's governance rounds found
// three times (the missing third site, the un-fallback'd legacy forwarder,
// the un-widened fast path). A hardcoded count (not just "at least one")
// catches a site being REMOVED too, mirroring this file's own #3261
// presence-pin rationale above. The spelling the scan recognises, and what it
// cannot see, is listed in this file's header.
TEST_CASE("server.cpp + dispatch_scope_ladder.hpp: every production "
          "ConfinedDispatchSink wires has_remote_presence AND prepare_route_fallback (HA WS-5)",
          "[wiring_order][ha]") {
    const std::string& server_text = cached_server_cpp_text();
    const std::string ladder_text = strip_line_comments(
        read_text_file(fs::path(YUZU_SERVER_SRC_DIR) / "dispatch_scope_ladder.hpp"));

    int total_sites = 0;
    auto check_file = [&](const std::string& text, const char* label) {
        for (const auto& site : find_confined_dispatch_sink_sites(text)) {
            ++total_sites;
            INFO(label << ":" << line_of(text, site.start)
                       << " — ConfinedDispatchSink construction");
            INFO("has_remote_presence and ->prepare( are searched in the next " << kFieldWindow
                 << " bytes (see this file's header)");
            CHECK(site.has_remote_presence);
            CHECK(site.has_prepare_route_fallback);
        }
    };
    check_file(server_text, "server.cpp");
    check_file(ladder_text, "dispatch_scope_ladder.hpp");

    // Sanity floor+ceiling (not just ">= 1"): exactly 3 production sites as
    // of this slice (make_confined_dispatch_sink, forward_legacy_command,
    // wire_and_dispatch_confined). A 4th site in the recognised spelling (see this
    // file's header) added later without updating this count is flagged for review,
    // not silently passed; a site removed is caught the same way.
    CHECK(total_sites == 3);
}

// The matcher must not use the C++ regular-expression library: scanning server.cpp
// with it takes minutes on MSVC debug, and nothing else here notices a merely slow
// scan. Reading the header rather than timing the scan keeps this independent of
// the machine. It guards that one header only: it cannot see the regexes this file
// still uses, another header, a macro, or a slow scan that does not use one.
TEST_CASE("confined_sink_scan.hpp does not use the regular-expression library",
          "[wiring_order]") {
    // YUZU_SERVER_SRC_DIR is <repo>/server/core/src, so three `..` reach the repo root.
    std::string text = read_text_file(fs::path(YUZU_SERVER_SRC_DIR) / ".." / ".." / ".." /
                                      "tests" / "unit" / "server" / "confined_sink_scan.hpp");
    // Not vacuous: an empty read must not pass.
    REQUIRE(text.find("find_confined_dispatch_sink_sites") != std::string::npos);
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    INFO("the matcher header must not contain \"regex\" in any case, comments included");
    CHECK(text.find("regex") == std::string::npos);
}

// The matcher against small engineered inputs, independent of whatever
// server.cpp contains on a given day; each section pins one clause of its grammar.
TEST_CASE("find_confined_dispatch_sink_sites recognises the documented construction "
          "grammar and nothing else",
          "[wiring_order]") {
    const std::string fields = "{ has_remote_presence, [](auto& c){ c->prepare(z); } };";

    SECTION("named, anonymous and qualified constructions are each found once") {
        const std::string text =
            "yuzu::server::ConfinedDispatchSink sink{\n"
            "    .has_remote_presence = true,\n"
            "    fallback = [](auto& c){ return c->prepare(candidates); },\n"
            "};\n"
            "ConfinedDispatchSink{ has_remote_presence, [](auto& c){ c->prepare(x); } };\n";
        const auto sites = find_confined_dispatch_sink_sites(text);
        REQUIRE(sites.size() == 2);
        CHECK(sites[0].start == 0); // the qualifier belongs to the site
        CHECK(sites[1].start == text.find("ConfinedDispatchSink{"));
        for (const auto& site : sites) {
            CHECK(site.has_remote_presence);
            CHECK(site.has_prepare_route_fallback);
        }
    }

    SECTION("a mention that is not a construction neither counts nor hides a real site nearby") {
        // A plain return-type mention (no `->`): the name after it opens a
        // parameter list, not a brace. The real construction follows closely.
        const std::string text =
            "yuzu::server::ConfinedDispatchSink\n"
            "    make_confined_dispatch_sink(const Cmd& cmd) {\n"
            "  return build(cmd);\n"
            "}\n"
            "\n"
            "ConfinedDispatchSink real_one" + fields + "\n";
        const auto sites = find_confined_dispatch_sink_sites(text);
        REQUIRE(sites.size() == 1);
        CHECK(sites[0].start == text.find("ConfinedDispatchSink real_one"));
        CHECK(sites[0].has_remote_presence);
        CHECK(sites[0].has_prepare_route_fallback);
    }

    SECTION("a lambda trailing-return-type annotation is excluded however wide the gap "
            "after `->`") {
        for (const std::string& gap :
             {std::string(), std::string(" "), std::string("\n    "), std::string(15, ' '),
              std::string(40, ' '), std::string(400, ' ')}) {
            INFO("gap length after -> : " << gap.size());
            const std::string text = "auto f()\n    ->" + gap +
                                     "yuzu::server::ConfinedDispatchSink {\n  return build();\n}\n";
            CHECK(find_confined_dispatch_sink_sites(text).empty());
        }
    }

    SECTION("a construction stays visible however long the span from the type name to its brace") {
        for (const std::string& text :
             {"ConfinedDispatchSink " + std::string(200, 'a') + fields,
              "ConfinedDispatchSink" + std::string(161, ' ') + "sink" + fields,
              "ConfinedDispatchSink" + std::string(600, ' ') + fields}) {
            INFO("text length " << text.size());
            const auto sites = find_confined_dispatch_sink_sites(text);
            REQUIRE(sites.size() == 1);
            CHECK(sites[0].start == 0);
            CHECK(sites[0].has_remote_presence);
            CHECK(sites[0].has_prepare_route_fallback);
        }
    }

    SECTION("a match consumes its whole span, so a second type name inside it is not a "
            "second site") {
        CHECK(find_confined_dispatch_sink_sites("ConfinedDispatchSink ConfinedDispatchSink" +
                                                fields)
                  .size() == 1);
        CHECK(find_confined_dispatch_sink_sites("-> ConfinedDispatchSink ConfinedDispatchSink" +
                                                fields)
                  .empty());
        // The search resumes one past the brace, so a name right behind it is a second site.
        CHECK(find_confined_dispatch_sink_sites("ConfinedDispatchSink{ConfinedDispatchSink" +
                                                fields)
                  .size() == 2);
    }

    SECTION("every whitespace kind separates tokens; only word characters form the identifier") {
        for (const char ws : {' ', '\t', '\n', '\v', '\f', '\r'}) {
            INFO("whitespace char code " << static_cast<int>(ws));
            const std::string text =
                std::string("ConfinedDispatchSink") + ws + "sink" + ws + fields;
            CHECK(find_confined_dispatch_sink_sites(text).size() == 1);
        }
        // '-' and non-ASCII bytes end the identifier, so what follows is not the brace.
        CHECK(find_confined_dispatch_sink_sites("ConfinedDispatchSink foo-bar" + fields).empty());
        CHECK(find_confined_dispatch_sink_sites("ConfinedDispatchSink foo\xE2\x80\x94" + fields)
                  .empty());
    }

    SECTION("the whitespace and identifier classes are exactly the original `\\s` and `\\w`, "
            "byte by byte") {
        std::string arrow_wrong, suffix_wrong; // decimal codes of the bytes that disagree
        for (int b = 0; b < 256; ++b) {
            const char c = static_cast<char>(b);
            const bool space = b == ' ' || (b >= '\t' && b <= '\r');
            const bool word = (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') ||
                              (b >= 'a' && b <= 'z') || b == '_';
            // Only whitespace keeps a `->` attached to the type name.
            const auto arrowed = find_confined_dispatch_sink_sites(
                "->" + std::string(1, c) + "ConfinedDispatchSink" + fields);
            if (arrowed.empty() != space)
                arrow_wrong += " " + std::to_string(b);
            // Between the type name and the brace: whitespace, a word byte, or the brace itself.
            const auto suffixed = find_confined_dispatch_sink_sites(
                "ConfinedDispatchSink " + std::string(1, c) + fields);
            if ((suffixed.size() == 1) != (space || word || c == '{'))
                suffix_wrong += " " + std::to_string(b);
        }
        INFO("bytes classified differently from the original grammar, before `->`:" << arrow_wrong);
        CHECK(arrow_wrong.empty());
        INFO("bytes classified differently from the original grammar, before the brace:"
             << suffix_wrong);
        CHECK(suffix_wrong.empty());
    }

    SECTION("a type-name mention that fails to match hides nothing after it") {
        // The first type name's identifier run swallows the second and then meets
        // `foo`, not a brace; the second is a real site.
        const auto sites = find_confined_dispatch_sink_sites(
            "ConfinedDispatchSinkConfinedDispatchSink foo" + fields);
        REQUIRE(sites.size() == 1);
        CHECK(sites[0].start == kTypeName.size());
    }

    SECTION("a near-miss qualifier is not part of the site") {
        for (const std::string& prefix :
             {std::string("yuzu::server:X"), std::string("Xuzu::server::"),
              std::string("yuzu::server:: ")}) {
            INFO("prefix \"" << prefix << "\"");
            const auto sites =
                find_confined_dispatch_sink_sites(prefix + "ConfinedDispatchSink" + fields);
            REQUIRE(sites.size() == 1);
            CHECK(sites[0].start == prefix.size());
        }
    }

    SECTION("a bare mention of the type name, with no brace after it, is not a construction") {
        // The matcher is lexical: a brace-shaped mention inside a block comment or a
        // string literal would count as a site (the caller strips `//` comments).
        const std::string text =
            "// See the ConfinedDispatchSink design doc for background.\n"
            "std::string describe() { return \"ConfinedDispatchSink docs\"; }\n";
        CHECK(find_confined_dispatch_sink_sites(text).empty());
    }

    SECTION("a real site missing a required field is still found, with that field reported false") {
        const std::string text =
            "ConfinedDispatchSink sink{\n"
            "    // presence field intentionally omitted for this test\n"
            "    [](auto& c){ c->prepare(z); }\n"
            "};\n";
        const auto sites = find_confined_dispatch_sink_sites(text);
        REQUIRE(sites.size() == 1);
        CHECK_FALSE(sites[0].has_remote_presence);
        CHECK(sites[0].has_prepare_route_fallback);
    }

    SECTION("near-miss markers do not satisfy the field checks") {
        const std::string text =
            "ConfinedDispatchSink sink{ remote_presence, "
            "[](auto& c){ c>prepare(x); c.prepare(y); c->prepared(z); } };";
        const auto sites = find_confined_dispatch_sink_sites(text);
        REQUIRE(sites.size() == 1);
        CHECK_FALSE(sites[0].has_remote_presence);
        CHECK_FALSE(sites[0].has_prepare_route_fallback);
    }

    SECTION("markers are attributed to a site only within about 1200 bytes of its start") {
        // Absolute offsets on purpose: changing kFieldWindow should make this
        // test be revisited rather than silently follow it.
        const auto presence_seen_at = [](const std::string& qualifier, std::size_t offset) {
            std::string text = qualifier + "ConfinedDispatchSink sink{ ->prepare(";
            text += std::string(offset - text.size(), ' ') + "has_remote_presence };";
            const auto sites = find_confined_dispatch_sink_sites(text);
            REQUIRE(sites.size() == 1);
            return sites[0].has_remote_presence;
        };
        CHECK(presence_seen_at("", 1100));
        CHECK_FALSE(presence_seen_at("", 1300));
        // Measured from the start of the qualified spelling, not from the type
        // name: this marker ends 14 bytes past the window's edge.
        CHECK_FALSE(presence_seen_at("yuzu::server::", 1195));
        // And only forward: markers before the site's start are not part of its window.
        const auto before = find_confined_dispatch_sink_sites(
            "has_remote_presence ->prepare( ConfinedDispatchSink s{ };");
        REQUIRE(before.size() == 1);
        CHECK_FALSE(before[0].has_remote_presence);
        CHECK_FALSE(before[0].has_prepare_route_fallback);
    }

    SECTION("identifier, whitespace, arrow and window edges match the original grammar exactly") {
        CHECK(find_confined_dispatch_sink_sites("ConfinedDispatchSink sink2" + fields).size() == 1);
        CHECK(find_confined_dispatch_sink_sites("ConfinedDispatchSink ns::sink" + fields).empty());
        CHECK(find_confined_dispatch_sink_sites("ConfinedDispatchSinkX" + fields).size() == 1);
        for (const char c : {'\0', '\x01', '\x1f', '\x7f', '\x85', '\xa0'}) {
            INFO("byte " << static_cast<int>(static_cast<unsigned char>(c)));
            const std::string text = std::string("ConfinedDispatchSink") + c + fields;
            CHECK(find_confined_dispatch_sink_sites(text).empty());
        }
        CHECK(find_confined_dispatch_sink_sites("x > ConfinedDispatchSink s" + fields).size() == 1);
        CHECK(find_confined_dispatch_sink_sites("x - ConfinedDispatchSink s" + fields).size() == 1);
        CHECK(find_confined_dispatch_sink_sites("-sConfinedDispatchSink" + fields).size() == 1);
        CHECK(find_confined_dispatch_sink_sites("- > ConfinedDispatchSink" + fields).size() == 1);
        const auto seen_at = [](const std::string& q, const std::string& other,
                                const std::string& marker, std::size_t offset) {
            std::string text = q + "ConfinedDispatchSink sink{ " + other;
            text += std::string(offset - text.size(), ' ') + marker + " };";
            const auto sites = find_confined_dispatch_sink_sites(text);
            REQUIRE(sites.size() == 1);
            return marker == "has_remote_presence" ? sites[0].has_remote_presence
                                                   : sites[0].has_prepare_route_fallback;
        };
        const std::string presence = "has_remote_presence";
        const std::string prepare = "->prepare(";
        CHECK(seen_at("", prepare, presence, 1181));       // ends at the window edge: in
        CHECK_FALSE(seen_at("", prepare, presence, 1182)); // one byte past it: out
        CHECK(seen_at("", presence + ",", prepare, 1190));
        CHECK_FALSE(seen_at("", presence + ",", prepare, 1191));
        CHECK_FALSE(seen_at("", presence + ",", prepare, 5000));
        CHECK_FALSE(seen_at("yuzu::server::", presence + ",", prepare, 1191));
        CHECK(seen_at("yuzu::server::", prepare, presence, 1181)); // qualified: the same edges
        CHECK_FALSE(seen_at("yuzu::server::", prepare, presence, 1182));
        CHECK(seen_at("yuzu::server::", presence + ",", prepare, 1190));
    }

    SECTION("input that ends inside the suffix is a mention, and nothing is read past a view's "
            "end") {
        for (const char* text : {"", "ConfinedDispatchSink", "ConfinedDispatchSink ",
                                 "ConfinedDispatchSink x", "-> "}) {
            INFO("text \"" << text << "\"");
            CHECK(find_confined_dispatch_sink_sites(text).empty());
        }
        // Views into a longer buffer whose NEXT byte is the brace (not part of the view).
        const std::string a = "ConfinedDispatchSink{ x";
        const std::string b = "ConfinedDispatchSink   {";
        const std::string c = "ConfinedDispatchSink foo{";
        const std::string d = "ConfinedDispatchSink foo   {";
        CHECK(find_confined_dispatch_sink_sites(std::string_view(a).substr(0, 20)).empty());
        CHECK(find_confined_dispatch_sink_sites(std::string_view(b).substr(0, 23)).empty());
        CHECK(find_confined_dispatch_sink_sites(std::string_view(c).substr(0, 24)).empty());
        CHECK(find_confined_dispatch_sink_sites(std::string_view(d).substr(0, 27)).empty());
    }
}
