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
 *   - every `member_ = std::make_unique<...>` or `std::make_shared<...>` construction.
 * For each setter call at line L wiring member M, the rule is: some
 * construction of M exists, and the EARLIEST such construction is on a line
 * strictly before L. Every member matched by the setter regex has exactly
 * one `std::make_unique` or `std::make_shared` site today (verified at the time this test was
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
 * stripped_source("server.cpp") (source_scan.hpp): take the text from it rather than
 * reading the file in a new case. The strip is a linear find-and-copy; the whole-text
 * std::regex passes below are what is slow. A pattern over the ~0.76 MB stripped file can
 * be very slow on MSVC debug depending on the pattern's shape -- one with an
 * optional capture group at its head took 231 s there (about 1.5 s on libc++),
 * while the plain patterns in this file cost a few seconds per pass. Literal anchors
 * use std::string_view::find (the anchors in the #1712 and HA WS-5 cases, and the bounded
 * window find after the #1712 resolver definition). The setter and
 * construction scans and the `wired_re`, `occurrence_re`, `construct_re`, `wire_re` and
 * `null_wire_re` anchors are structural and still use the pattern library. For a
 * new scan prefer std::string_view::find plus a small matcher (see
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
#include <map>
#include <iterator>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#include "confined_sink_scan.hpp"
#include "source_scan.hpp"

using yuzu::test::wiring_scan::find_confined_dispatch_sink_sites;
using yuzu::test::wiring_scan::kFieldWindow;
using yuzu::test::wiring_scan::kTypeName;
using yuzu::test::source_scan::line_of;
using yuzu::test::source_scan::read_text_file;
using yuzu::test::source_scan::strip_comments;
using yuzu::test::source_scan::strip_line_comments;
using yuzu::test::source_scan::stripped_source;
using yuzu::test::source_scan::stripped_source_loads;

namespace {

namespace fs = std::filesystem;

struct SetterCall {
    int line;
    std::string receiver; // "agent_service_" or "gateway_service_"
    std::string setter;   // e.g. "notification_store"
    std::string member;   // e.g. "notification_store_"
};

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

/// `member_ = std::make_unique<...>` or `std::make_shared<...>`. Returns every construction
/// line per member (a member with more than one site keeps every line; the rule
/// checked below uses the earliest).
std::map<std::string, std::vector<int>> extract_constructions(const std::string& text) {
    static const std::regex re(R"regex(\b(\w+_)\s*=\s*std::make_(?:unique|shared)<)regex");
    std::map<std::string, std::vector<int>> out;
    for (auto it = std::sregex_iterator(text.begin(), text.end(), re); it != std::sregex_iterator();
         ++it) {
        const auto& m = *it;
        out[m[1].str()].push_back(line_of(text, static_cast<std::size_t>(m.position(0))));
    }
    return out;
}

} // namespace

// Only the #1712 case's `== 4` count depends on the strip (unstripped, a `//` mention
// makes it 5); the other cases pass either way. So pin the content directly: no `//`
// survives (the stripper removes them even inside string literals), and it is
// still server.cpp.
TEST_CASE("stripped_source(\"server.cpp\") is server.cpp with every // comment stripped",
          "[wiring_order]") {
    const std::string& text = stripped_source("server.cpp");
    CHECK(text.find("//") == std::string::npos);
    CHECK(text.find("ServerImpl") != std::string::npos);
}

// The counter pins the memoisation: an accessor that reloaded on each call would bump
// it. It cannot see a case that reads the file some other way. Other cases (and other
// translation units) may be the first to load a file, so the pin is "unchanged across
// repeat calls", not an absolute count.
TEST_CASE("stripped_source loads server.cpp once per process: repeat calls do not reload it",
          "[wiring_order]") {
    (void)stripped_source("server.cpp");
    const int loads_after_first = stripped_source_loads;
    (void)stripped_source("server.cpp");
    (void)stripped_source("server.cpp");
    (void)stripped_source("server.cpp");
    CHECK(stripped_source_loads == loads_after_first);
}

// The stripper's contract, on engineered input: a `//` cuts to the end of its line, the
// newline survives (line numbers are unchanged), and a `//` inside a string literal is
// cut too (documented limit in source_scan.hpp -- pinned so a "fix" that makes it
// string-aware is a deliberate change, not a silent one).
TEST_CASE("strip_line_comments cuts // to end of line, keeps the newline "
          "and cuts inside a string literal",
          "[wiring_order]") {
    CHECK(strip_line_comments("a // c\nb\n") == "a \nb\n");
    CHECK(strip_line_comments("x\n// whole line\ny") == "x\n\ny");
    CHECK(strip_line_comments("no comment") == "no comment");
    CHECK(strip_line_comments("tail //no newline") == "tail ");
    CHECK(strip_line_comments("a///b\nc") == "a\nc");
    CHECK(strip_line_comments("u(\"http://h\"); x\n") == "u(\"http:\n");
    // Block comments are not understood: the // inside one is cut, the rest survives.
    CHECK(strip_line_comments("/* a // b */ c\n") == "/* a \n");
}

TEST_CASE("server.cpp: every agent_service_/gateway_service_ store setter runs after "
          "its member's construction (#3261)",
          "[wiring_order]") {
    const std::string& text = stripped_source("server.cpp");
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
    const std::string& text = stripped_source("server.cpp");
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
    const std::string& text = stripped_source("server.cpp");

    // Sanity floor: server.cpp is a six-figure-character file; a
    // suspiciously short read means YUZU_SERVER_SRC_DIR pointed somewhere
    // empty or mangled, not that the file legitimately shrank.
    REQUIRE(text.size() > 100000);

    // POSITIVE anchor 1: the resolver is defined, and its body DELEGATES to the real decision
    // ladder (engine_aware_visibility.hpp's response_visible_set, which holds the
    // check_permission / visible_agents_for_permission calls and is tested behaviourally against
    // real stores in test_engine_aware_visibility.cpp, #6204). A resolver silently downgraded to
    // "return std::nullopt;" no longer contains the delegation, so it still fails here. Literal
    // anchors only: the delegation is looked for in a bounded window after the definition, not
    // by a pattern over the whole stripped file.
    const std::size_t resolver_def = text.find("auto response_visible_set_fn =");
    CHECK(resolver_def != std::string::npos);
    CHECK((resolver_def != std::string::npos &&
           text.substr(resolver_def, 800).find("visibility::response_visible_set(") !=
               std::string::npos));

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
    const std::string& text = stripped_source("server.cpp");

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
    // must run BEFORE offline_endpoint_store_.reset() destroys the object the
    // presence reader lambda captures (`offline_endpoint_store_`, bound by
    // configure_presence(OfflineEndpointStore*, ttl) into `presence_reader_`;
    // see that member's doc comment in agent_registry.hpp and the call site in
    // server.cpp). This pins the SOURCE order of the wiring/teardown calls,
    // not thread quiescence.
    static const std::regex null_wire_re(R"(registry_\.configure_presence\(\s*nullptr\s*,)");
    std::smatch null_wire_match;
    REQUIRE(std::regex_search(text, null_wire_match, null_wire_re));
    const int null_wire_line = line_of(text, static_cast<std::size_t>(null_wire_match.position(0)));

    const auto reset_pos = text.find("offline_endpoint_store_.reset()");
    REQUIRE(reset_pos != std::string::npos);
    const int reset_line = line_of(text, reset_pos);

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
    const std::string& server_text = stripped_source("server.cpp");
    const std::string& ladder_text = stripped_source("dispatch_scope_ladder.hpp");

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

// The matchers must not use the C++ regular-expression library: scanning server.cpp
// with it takes minutes on MSVC debug, and nothing else here notices a merely slow
// scan. Reading the headers rather than timing the scan keeps this independent of
// the machine. It guards those files only: it cannot see the regexes this file
// still uses, another header, a macro, or a slow scan that does not use one.
TEST_CASE("the source-scan headers and the step-up inventory do not use the regular-expression library",
          "[wiring_order]") {
    struct Header {
        const char* file;
        const char* marker; // proves the read is the real header, not an empty one
    };
    for (const Header& h :
         {Header{"confined_sink_scan.hpp", "find_confined_dispatch_sink_sites"},
          Header{"source_scan.hpp", "stripped_source"},
          Header{"route_registration_scan.hpp", "find_route_registrations"},
          Header{"route_inventory_scan.hpp", "discover_mutating_routes"},
          Header{"test_step_up_route_inventory.cpp", "find_step_up_calls"}}) {
        // YUZU_SERVER_SRC_DIR is <repo>/server/core/src, so three `..` reach the repo root.
        std::string text = read_text_file(fs::path(YUZU_SERVER_SRC_DIR) / ".." / ".." / ".." /
                                          "tests" / "unit" / "server" / h.file);
        INFO(h.file);
        // Not vacuous: an empty read must not pass.
        REQUIRE(text.find(h.marker) != std::string::npos);
        std::transform(text.begin(), text.end(), text.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        INFO("the scan file must not contain \"regex\" in any case, comments included");
        CHECK(text.find("regex") == std::string::npos);
    }
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

// #6204: ServerImpl must keep BINDING the engine-aware resolvers. The resolver logic itself lives in
// engine_aware_visibility.hpp and is tested behaviourally against real stores in
// test_engine_aware_visibility.cpp; ServerImpl is not unit-constructible, so this source scan pins
// the WIRING. Each seam is matched as a whole: the enclosing member or lambda, then the single
// delegation with its store arguments in order (rbac, then management groups, then the username).
// That catches a seam rebound to inline logic, a dropped call, a swapped or wrong store, and a
// delegation moved into dead code. It does not prove the seam is the one the routes receive; the
// response-visible-set seam is checked here and again by the [1712] case above; the use-site
// counts below cover the rest.
TEST_CASE("server.cpp: every username-keyed resolver seam delegates to the engine-aware "
          "resolver (#6204)",
          "[wiring_order][6204]") {
    const std::string& text = stripped_source("server.cpp");
    const auto count = [&text](std::string_view needle) {
        std::size_t n = 0;
        for (auto pos = text.find(needle); pos != std::string::npos;
             pos = text.find(needle, pos + needle.size()))
            ++n;
        return n;
    };
    // A seam matches when its anchor literal is followed, at that exact position, by the pattern.
    // Anchoring first keeps the regex off the whole stripped file (the banner above records what a
    // whole-file std::regex costs on MSVC debug).
    const auto seam = [&text](std::string_view anchor, const char* pattern) {
        const std::regex re(pattern);
        std::size_t n = 0;
        for (auto pos = text.find(anchor); pos != std::string::npos;
             pos = text.find(anchor, pos + anchor.size())) {
            const std::string window = text.substr(pos, 800);
            if (std::regex_search(window, re, std::regex_constants::match_continuous))
                ++n;
        }
        return n;
    };
    CHECK(count("yuzu::server::visibility::dispatch_permission(") == 1);
    CHECK(count("yuzu::server::visibility::response_agent_in_scope(") == 1);
    CHECK(count("yuzu::server::visibility::visible_agents_json(") == 1);
    CHECK(count("yuzu::server::visibility::infrastructure_visible_set(") == 1);
    CHECK(count("yuzu::server::visibility::response_visible_set(") == 1);
    // Each delegation sits directly inside its seam, with the right stores in the right order.
    {
        INFO("seam: dispatch_has_permission");
        CHECK(seam("dispatch_has_permission(",
                   R"(dispatch_has_permission\(\s*std::string_view principal,)"
                   R"(\s*std::string_view securable,\s*yuzu::server::authz::Operation op\s*\)\s*const\s*\{)"
                   R"(\s*return yuzu::server::visibility::dispatch_permission\(\s*rbac_store_\.get\(\),)"
                   R"(\s*principal,\s*securable,\s*op\s*\);)") == 1);
    }
    {
        INFO("seam: response_agent_in_scope");
        CHECK(seam("response_agent_in_scope(const",
                   R"(response_agent_in_scope\(\s*const std::string& username,)"
                   R"(\s*const std::string& agent_id\s*\)\s*const\s*\{)"
                   R"(\s*return yuzu::server::visibility::response_agent_in_scope\(\s*rbac_store_\.get\(\),)"
                   R"(\s*mgmt_group_store_\.get\(\),\s*username,\s*agent_id\s*\);)") == 1);
    }
    {
        INFO("seam: get_visible_agents_json");
        CHECK(seam("get_visible_agents_json(const",
                   R"(get_visible_agents_json\(\s*const std::string& username\s*\)\s*\{)"
                   R"(\s*return yuzu::server::visibility::visible_agents_json\(\s*registry_\.to_json_obj\(\),)"
                   R"(\s*rbac_store_\.get\(\),\s*mgmt_group_store_\.get\(\),\s*username\s*\);)") == 1);
    }
    {
        INFO("seam: visible_set_fn");
        CHECK(seam("auto visible_set_fn",
                   R"(auto\s+visible_set_fn\s*=\s*\[this\]\(const std::string& username\))"
                   R"(\s*->\s*std::optional<std::set<std::string>>\s*\{)"
                   R"(\s*return yuzu::server::visibility::infrastructure_visible_set\(\s*rbac_store_\.get\(\),)"
                   R"(\s*mgmt_group_store_\.get\(\),\s*username\s*\);)") == 1);
    }
    {
        INFO("seam: response_visible_set_fn");
        CHECK(seam("auto response_visible_set_fn",
                   R"(auto\s+response_visible_set_fn\s*=\s*\[this\]\(const std::string& username\))"
                   R"(\s*->\s*std::optional<std::set<std::string>>\s*\{)"
                   R"(\s*return yuzu::server::visibility::response_visible_set\(\s*rbac_store_\.get\(\),)"
                   R"(\s*mgmt_group_store_\.get\(\),\s*username\s*\);)") == 1);
    }
    // The seams are handed on: visible_set_fn to the two route registrations that take it, and the
    // dispatch binder to both classify_and_authorize_dispatch lambdas. (The response-visible-set seam
    // is also covered by the [1712] case above.)
    {
        INFO("use sites of visible_set_fn");
        std::size_t uses = 0;
        const std::regex use_re(R"([^_A-Za-z0-9]visible_set_fn\s*,)");
        for (auto it = std::sregex_iterator(text.begin(), text.end(), use_re);
             it != std::sregex_iterator(); ++it)
            ++uses;
        CHECK(uses == 2);
    }
    {
        INFO("use sites of dispatch_has_permission");
        CHECK(count("return dispatch_has_permission(principal, securable, op);") == 2);
    }
    // The exec-visible derivations (session-keyed and headless username-keyed) feed the composer.
    CHECK(count("facts.principal_is_engine = sess.is_engine();") == 1);
    CHECK(count("facts.principal_is_engine = yuzu::server::authz::is_engine_principal_name(username);") == 1);
    // No resolver was re-inlined: server.cpp holds no engine-prefix test of its own besides the one above.
    CHECK(count("authz::is_engine_principal_name(") == 1);
}

// #6204: ONE enforcement snapshot per decision. Two enforcement reads in one resolver can disagree
// across a concurrent toggle and let an engine fall through both branches. The header holds only
// these five resolvers, so the read count is pinned per function: a second read added to any of
// them fails here, with no store or thread timing involved. The scan counts the three ways to read
// the flag (`rbac_enforcement_in_effect`, `rbac_enforcement_label`, `is_rbac_enabled`); a read
// through some other helper is not seen, so this is a tripwire for the obvious regression, not a
// proof of one snapshot. A concurrent-toggle stress test was tried and dropped: with the second
// read reintroduced it still passed 3 of 3 runs, because the window between two reads
// (nanoseconds) is far narrower than a toggle (a Postgres write), so it could not fail on the
// defect it named.
namespace {
std::size_t count_enforcement_reads(const std::string& body) {
    static const std::regex re(R"(\b(?:rbac_enforcement_in_effect|rbac_enforcement_label|is_rbac_enabled)\s*\()");
    std::size_t n = 0;
    for (auto it = std::sregex_iterator(body.begin(), body.end(), re); it != std::sregex_iterator();
         ++it)
        ++n;
    return n;
}
} // namespace

TEST_CASE("the enforcement-read counter sees each spelling and ignores look-alikes (#6204)",
          "[wiring_order][6204][snapshot]") {
    CHECK(count_enforcement_reads("a = rbac_enforcement_in_effect(rbac);") == 1);
    CHECK(count_enforcement_reads("a = rbac_enforcement_in_effect (rbac);") == 1);
    CHECK(count_enforcement_reads("a = rbac_enforcement_in_effect\n    (rbac);") == 1);
    CHECK(count_enforcement_reads("a = rbac->is_rbac_enabled();") == 1);
    CHECK(count_enforcement_reads("a = rbac_enforcement_label(rbac);") == 1);
    CHECK(count_enforcement_reads("x = rbac_enforcement_in_effect(r); y = rbac->is_rbac_enabled();") == 2);
    CHECK(count_enforcement_reads("a = my_rbac_enforcement_in_effect_cached(rbac);") == 0);
    CHECK(count_enforcement_reads("a = rbac->check_permission(u, s, o);") == 0);
}

TEST_CASE("engine_aware_visibility.hpp: each resolver reads enforcement exactly once (#6204)",
          "[wiring_order][6204][snapshot]") {
    const std::string text =
        strip_line_comments(read_text_file(fs::path(YUZU_SERVER_SRC_DIR) / "engine_aware_visibility.hpp"));
    const std::string marker = "[[nodiscard]] inline";
    std::vector<std::size_t> starts;
    for (auto pos = text.find(marker); pos != std::string::npos;
         pos = text.find(marker, pos + marker.size()))
        starts.push_back(pos);
    REQUIRE(starts.size() == 5);
    starts.push_back(text.size());
    const char* names[] = {"dispatch_permission", "response_agent_in_scope", "visible_agents_json",
                           "infrastructure_visible_set", "response_visible_set"};
    for (std::size_t i = 0; i < std::size(names); ++i) {
        const std::string body = text.substr(starts[i], starts[i + 1] - starts[i]);
        INFO("resolver: " << names[i]);
        CHECK(body.find(names[i]) != std::string::npos);
        CHECK(count_enforcement_reads(body) == 1);
    }
}

// ── strip_comments self-test (#6079 qe-1, cs-N2) ────────────────────────────
// The comment-free scans (comment_free_source) are only as honest as this lexer, so it is
// pinned on engineered inputs, independent of whatever server.cpp contains on a given day.
namespace {
std::size_t newlines_in(std::string_view t) {
    return static_cast<std::size_t>(std::count(t.begin(), t.end(), '\n'));
}
} // namespace

TEST_CASE("strip_comments: comment markers inside literals are not comments",
          "[wiring_order][strip_comments]") {
    CHECK(strip_comments(R"T(s = "http://x /* y */"; // tail
int a;)T") == R"T(s = "http://x /* y */"; 
int a;)T");
    // A raw string whose body holds `)"` and a `//`: only its own delimiter closes it.
    CHECK(strip_comments(R"T(auto r = R"x(a )" // not a comment )x"; // real
)T") == R"T(auto r = R"x(a )" // not a comment )x"; 
)T");
    // Encoding-prefixed raw strings are raw strings.
    CHECK(strip_comments("a = u8R\"(p // q)\"; // c\n") == "a = u8R\"(p // q)\"; \n");
    CHECK(strip_comments("a = LR\"(p // q)\"; // c\n") == "a = LR\"(p // q)\"; \n");
}

TEST_CASE("strip_comments: character literals and escapes do not derail the lexer",
          "[wiring_order][strip_comments]") {
    // A quote character literal must not open a string, a backslash literal must not escape
    // its closing quote.
    CHECK(strip_comments("char a = '\"'; char b = '\\\\'; // c\nint z;") ==
          "char a = '\"'; char b = '\\\\'; \nint z;");
    // An escaped backslash before the closing quote: the comment after it is a comment.
    CHECK(strip_comments("s = \"\\\\\"; // c\nt;") == "s = \"\\\\\"; \nt;");
    // An encoding prefix on a character literal keeps it a literal.
    CHECK(strip_comments("x = L'\"'; // c\ny = \"z\"; // d") == "x = L'\"'; \ny = \"z\"; ");
}

TEST_CASE("strip_comments: a digit separator is not a character literal",
          "[wiring_order][strip_comments]") {
    CHECK(strip_comments("int n = 30'000; // note\nint k;") == "int n = 30'000; \nint k;");
    CHECK(strip_comments("int n = 0xFF'FF'00; // note\nint k;") == "int n = 0xFF'FF'00; \nint k;");
    CHECK(strip_comments("auto d = 1'000'000ull; /* x */ int k;") ==
          "auto d = 1'000'000ull;   int k;");
    // Had the separator opened a literal, the comment marker below would have been read as
    // literal text and survived.
    CHECK(strip_comments("n = 5'000; // \"quoted\"\nm;") == "n = 5'000; \nm;");
}

TEST_CASE("strip_comments: a raw-string opener needs a token boundary",
          "[wiring_order][strip_comments]") {
    // `BAR"(" ` is the identifier BAR then an ordinary string; reading `R"(` as a raw opener
    // would swallow the comment (and the next line) into a fake raw string.
    CHECK(strip_comments("BAR\"(\" // c\nx = \")\";") == "BAR\"(\" \nx = \")\";");
    // A malformed delimiter (a space) is not a raw opener either.
    CHECK(strip_comments("R\"a b(\" // c\n") == "R\"a b(\" \n");
}

TEST_CASE("strip_comments: a backslash continues a line comment onto the next line",
          "[wiring_order][strip_comments]") {
    const std::string in = "a; // c \\\nstill comment\nb;";
    const std::string out = strip_comments(in);
    CHECK(out == "a; \n\nb;");
    CHECK(newlines_in(out) == newlines_in(in));
    // CRLF line ends continue it too.
    CHECK(strip_comments("a; // c \\\r\nstill\r\nb;") == "a; \n\nb;");
    // A backslash that is not at the line end does not.
    CHECK(strip_comments("a; // c \\ d\nb;") == "a; \nb;");
}

TEST_CASE("strip_comments: block comments, an unterminated one, and line preservation",
          "[wiring_order][strip_comments]") {
    CHECK(strip_comments("a/* x\ny */b") == "a\n b");
    const std::string open = "a; /* never closed\nb;\nc;";
    const std::string out = strip_comments(open);
    CHECK(out == "a; \n\n ");
    CHECK(newlines_in(out) == newlines_in(open));
    CHECK(strip_comments("") == "");
    CHECK(strip_comments("/") == "/");
}

TEST_CASE("strip_comments: server.cpp keeps its line count and is a fixed point",
          "[wiring_order][strip_comments]") {
    const std::string raw = read_text_file(fs::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(raw.size() > 100000); // not vacuous: the real file
    const std::string once = strip_comments(raw);
    CHECK(newlines_in(once) == newlines_in(raw));
    CHECK(once.size() < raw.size());
    CHECK(strip_comments(once) == once);
}
