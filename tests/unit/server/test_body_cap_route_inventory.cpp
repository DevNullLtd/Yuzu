/**
 * test_body_cap_route_inventory.cpp — #2407 architect-mandated route-inventory
 * coverage: prove every ACTUALLY REGISTERED POST/PUT/PATCH route resolves to
 * a DELIBERATE `body_cap_policy.hpp` class, not a silent, unreviewed
 * fallthrough to the catch-all default.
 *
 * WHY test_body_cap_policy.cpp IS NOT ENOUGH. That sibling file locks
 * `kBodyCapTable`'s own contents against an independently hand-copied
 * expectation list — it proves the table is internally self-consistent, but
 * the table has no idea the real route surface exists. If a future route is
 * added to `rest_api_v1.cpp` (or any other route file) and nobody adds a
 * matching `kBodyCapTable` entry, test_body_cap_policy.cpp stays green — the
 * table it locks did not change. The new route silently inherits the 4 MiB
 * catch-all default and is refused in production with a 413 nobody
 * anticipated, at a layer (server.cpp's pre-routing handler) the route's
 * author never looked at. Only a comparison against the ACTUAL REGISTERED
 * ROUTE TABLE — this file — can catch that.
 *
 * MECHANISM — no hand-copied route list. A hand-copied list goes stale
 * exactly like the thing it's testing. This test opens every `*.cpp` AND
 * `*.inc` file under `server/core/src` (recursively, via
 * `YUZU_SERVER_SRC_DIR`, injected by tests/meson.build from
 * `meson.project_source_root()`) AT TEST RUN TIME and regex-scans the raw
 * source text for every `Post`/`Put`/`Patch`/`Delete` call on one of THREE
 * receiver spellings actually used in this codebase (verified against the
 * full source tree, not recalled):
 *   - `sink.Post(...)` / `sink.Put(...)` / ... — the `HttpRouteSink` seam
 *     (http_route_sink.hpp) that most route owners now register through;
 *   - `svr.Post(...)` / `svr.Put(...)` / ... — the small set of route
 *     owners not yet migrated onto that seam; or
 *   - `web_server_->Post(...)` / `web_server_->Put(...)` / ... — routes
 *     registered directly on the underlying `httplib::Server` member
 *     (server.cpp itself, plus any `.inc` file it textually `#include`s).
 *     A prior version of this scan matched only `sink.`/`svr.` and missed
 *     this receiver ENTIRELY — 39 of 176 POST/PUT/PATCH registrations (22%)
 *     were invisible to it, concentrated in server.cpp, the very file a
 *     route-inventory guard most needs to see. Do not narrow this back to
 *     two receivers without re-measuring that count is still zero.
 * A route added anywhere — a new file, a new `.inc`, or a new call on any of
 * the three receivers in an existing file — is picked up automatically on
 * the next test run. Nothing here needs updating when a route is ADDED;
 * something here needs updating only when a route's RESOLVED CLASS is new
 * and needs a considered decision (see `kDefaultIsCorrectFor` below).
 *
 * REGENERATING: nothing to regenerate by hand — the scan runs fresh every
 * test invocation (see the CACHING note below for what "fresh" actually
 * means per process). If you add a route and this test fails, it is telling
 * you the route resolves to the catch-all default and has not yet had a
 * decision recorded for it. Fix it one of two ways:
 *   (a) it genuinely needs its own cap — add an entry to `kBodyCapTable` in
 *       body_cap_policy.hpp (owned by that file, see its header for the
 *       chokepoint/matching rules); or
 *   (b) the 4 MiB default is the right, deliberate choice for it — add
 *       `{method, EXACT registered path text, one-line reason}` to
 *       `kDefaultIsCorrectFor` below.
 * If instead an *existing* `kDefaultIsCorrectFor` entry starts failing (the
 * "no stale allowlist entries" test case below), the route it names was
 * either removed or given its own `kBodyCapTable` entry — delete the
 * allowlist row.
 *
 * REGEX PATH PROBES. httplib regex-registered routes (e.g.
 * `sink.Put(R"(/api/v1/management-groups/([a-f0-9]+))", ...)`) are not
 * literal paths, but `resolve_body_cap` matches literal segment-boundary
 * prefixes (body_cap_policy.hpp's `body_cap_prefix_matches`). Each capture
 * group `(...)` in an extracted pattern is replaced with a fixed
 * placeholder segment ("X") to build a representative concrete PROBE path —
 * this codebase's httplib capture groups are a single level, never nested
 * (verified against every registration extant at the time of writing), so a
 * non-nested `\([^()]*\)` replacement is exact. Replacing in place (rather
 * than truncating at the first capture group) preserves every literal
 * segment BEFORE *and* AFTER the capture, which matters: an entry that is
 * only distinguishable by a literal suffix after an id segment (there is
 * none in `kBodyCapTable` today, but nothing stops one being added) would be
 * missed by a naive prefix-only probe.
 *
 * SCOPE. GET registrations carry no meaningful pre-auth body surface in
 * this codebase and stay out of the main inventory check, covered only by
 * the best-effort "GET reads req.body" shape-trap check below — a substring
 * heuristic over the handler's approximate source span, not a real parse.
 * It found zero hits when this file was written; a hit is a signal to go
 * read the route by hand, not an automatic verdict. DELETE is IN scope
 * (unlike an earlier version of this comment claimed): `resolve_body_cap`'s
 * catch-all default entry is `kBodyCapAnyMethod`-scoped, so it already caps
 * every DELETE registration at 4 MiB whether or not this test extracts
 * them — and at least one DELETE handler parses `req.body`
 * (`rest_api_v1.cpp`'s `DELETE /api/v1/management-groups/{id}/roles`,
 * `req.body` read at line 2112, and `DELETE /api/v1/engine-principals/{id}`
 * reads an optional `superseded_by` field). A route-inventory guard that
 * cannot see DELETE registrations cannot confirm either of those bodies
 * stays within the default it silently inherits, so DELETE is extracted
 * and checked exactly like POST/PUT/PATCH below.
 *
 * CACHING. The file corpus (`read_all_cpp_files`) and the extracted
 * mutating-route list (`discover_mutating_routes`) are each memoized behind
 * a function-local `static const`, computed once per test PROCESS rather
 * than once per `TEST_CASE` — this file has four `TEST_CASE`s and three of
 * them call `discover_mutating_routes()`, so the un-cached scan (a full
 * `std::regex` pass over every server source file) used to run 3-4x per
 * process for no reason: measured 8.2-8.5 s wall on Linux at `-O2` before
 * caching (worse under MSVC's slower `std::regex`, and worse again as the
 * source tree grows — this cost is O(tree size) and was unbounded). Both
 * caches assume every call in this TU passes the same `YUZU_SERVER_SRC_DIR`
 * directory, which is true today (there is exactly one call site for each
 * with a hard-coded argument) — do not reuse either helper with a different
 * directory without splitting the cache key.
 */

#include "body_cap_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (meson.project_source_root() / 'server' / 'core' / 'src') — see the server_test_exe cpp_args block."
#endif

using yuzu::server::resolve_body_cap;

namespace {

namespace fs = std::filesystem;

/// One mechanically-extracted `sink.<Method>(...)` / `svr.<Method>(...)`
/// route registration.
struct RegisteredRoute {
    std::string file; // basename, e.g. "rest_api_v1.cpp"
    int line;
    std::string method;   // "POST" / "PUT" / "PATCH"
    std::string raw_path; // exactly as it appears in source — may be an httplib regex pattern
};

/// Read every `.cpp` AND `.inc` file under `dir` (recursively — server/core/src
/// has a `pg/` subdirectory today; nothing forbids a route file landing
/// under a future one) and return `{basename, contents}` pairs. `.inc` is
/// scanned alongside `.cpp` because a route registration living in a
/// textually-`#include`d fragment is still source text this scan must not
/// silently skip; no `.inc` file exists under server/core/src today, but a
/// future one that IS live must not regress this guard back to invisible.
/// No other extension under server/core/src carries a route
/// registration (verified: `.cpp`/`.hpp`/`.inc` are the only three
/// extensions present, and no `.hpp` matches the route-registration regex).
///
/// Memoized (see the file header's CACHING note) — computed once per test
/// process, on the assumption every call site in this TU passes the same
/// `dir`.
std::vector<std::pair<std::string, std::string>> read_all_cpp_files(const fs::path& dir) {
    static const std::vector<std::pair<std::string, std::string>> cached = [&dir] {
        // F7: fs::recursive_directory_iterator throws filesystem_error on a
        // missing directory, which would otherwise surface as an opaque
        // Catch2 "unexpected exception" abort before the REQUIRE_FALSE
        // below ever runs — fail with an actionable message instead.
        REQUIRE(fs::is_directory(dir));

        std::vector<std::pair<std::string, std::string>> out;
        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (!entry.is_regular_file())
                continue;
            const auto ext = entry.path().extension();
            if (ext != ".cpp" && ext != ".inc")
                continue;
            std::ifstream in(entry.path(), std::ios::binary);
            REQUIRE(in.is_open());
            std::ostringstream ss;
            ss << in.rdbuf();
            out.emplace_back(entry.path().filename().string(), ss.str());
        }
        return out;
    }();
    return cached;
}

/// Extract every body-bearing route registration (`sink.`/`svr.`/
/// `web_server_->` receiver — see the file header's MECHANISM note —
/// Post/Put/Patch/Delete method) from one file's raw source text. Matches
/// either a plain `"..."` string literal or an `R"(...)"` raw string
/// literal as the first argument — the path/pattern is always a literal in
/// this codebase (never a computed std::string), which is exactly the
/// assumption the sanity floor in `discover_mutating_routes` exists to
/// catch if it ever stops being true.
std::vector<RegisteredRoute> extract_routes(const std::string& file, const std::string& text) {
    std::vector<RegisteredRoute> out;
    // The receiver alternation is non-capturing — `sink.`/`svr.` use `.`,
    // `web_server_` uses `->`, and neither spelling's IDENTITY is needed by
    // any caller, only which method/path it registered. Group 1: method.
    // Group 2: raw-string body (R"(...)"). Group 3: quoted-string body
    // ("...", escapes intact). A leading `\b` on each receiver alternative
    // keeps this from matching a CLIENT-side call sharing a method name on
    // an unrelated receiver (`cli.Post(...)`/`client.Post(...)` in
    // analytics_sinks.cpp/directory_sync.cpp/offload_target_store.cpp/
    // webhook_store.cpp — verified excluded: neither "cli" nor "client" ends
    // in "sink"/"svr", and "web_server_->" requires the literal receiver
    // name, not just any `->Post(`).
    static const std::regex re(
        R"regex((?:\b(?:sink|svr)\.|\bweb_server_->)(Post|Put|Patch|Delete)\(\s*(?:R"\(([\s\S]*?)\)"|"((?:[^"\\]|\\.)*)"))regex");
    for (auto it = std::sregex_iterator(text.begin(), text.end(), re); it != std::sregex_iterator();
         ++it) {
        const auto& m = *it;
        std::string method = m[1].str();
        std::transform(method.begin(), method.end(), method.begin(),
                        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        std::string path = m[2].matched ? m[2].str() : m[3].str();
        int line =
            static_cast<int>(std::count(text.begin(), text.begin() + m.position(0), '\n')) + 1;
        out.push_back({file, line, std::move(method), std::move(path)});
    }
    return out;
}

/// Build a representative concrete probe path for `resolve_body_cap` from a
/// (possibly regex) registered path: every `(...)` capture group is
/// replaced with a fixed placeholder segment. See the file header for why
/// this is exact for this codebase's route patterns today.
std::string probe_path(const std::string& raw_path) {
    static const std::regex group_re(R"(\([^()]*\))");
    return std::regex_replace(raw_path, group_re, "X");
}

/// Scan every `.cpp`/`.inc` under `YUZU_SERVER_SRC_DIR` and return every
/// POST/PUT/PATCH/DELETE route registration found. Shared by every
/// TEST_CASE below so the extraction logic — and its sanity floor — lives
/// in exactly one place. Memoized (see the file header's CACHING note).
std::vector<RegisteredRoute> discover_mutating_routes() {
    static const std::vector<RegisteredRoute> cached = [] {
        auto files = read_all_cpp_files(fs::path(YUZU_SERVER_SRC_DIR));
        REQUIRE_FALSE(files.empty());

        std::vector<RegisteredRoute> routes;
        for (const auto& [file, text] : files) {
            auto found = extract_routes(file, text);
            routes.insert(routes.end(), found.begin(), found.end());
        }
        // Sanity floor: this repo has 215 mutating route registrations as
        // measured against server/core/src at the time this floor was set
        // (137 pre-existing sink./svr. POST/PUT/PATCH + 39 web_server_->
        // POST/PUT/PATCH the F1 receiver fix newly sees + 39 DELETE the F3
        // method-widening newly sees, across both receiver families). Set
        // to 200 — comfortably above ordinary churn (a handful of routes
        // added/removed/renamed between runs) but close enough to 215 that
        // losing a whole receiver family or method again (as this scan
        // previously did, silently, for 22% of the surface) still trips it.
        // A near-zero count means the SCAN is broken (wrong directory, or a
        // receiver/method spelling drifted), not that the route surface
        // shrank to nothing — fail loud rather than pass vacuously on an
        // empty or badly-undercounted inventory.
        REQUIRE(routes.size() >= 200);
        return routes;
    }();
    return cached;
}

/// `{method, EXACT raw registered path text (as it appears in source —
/// regex patterns included verbatim), why the 4 MiB catch-all default is
/// the deliberate, reviewed choice for this route}`.
///
/// Every entry here was checked against the 4 MiB default it is landing on
/// — group reasons cite the shared shape (small control-plane JSON/HTMX
/// form body); routes with something specific worth recording (an internal
/// size check, a metadata-only handler, a known-deliberate gap already
/// documented elsewhere) get their own individual reason. Generated
/// 2026-08-07 against the route files listed in the header comment — see
/// that comment for the mechanical extraction this list was checked
/// against; this file's own "no stale entries" test case (below) keeps it
/// honest going forward.
struct DefaultAllow {
    std::string_view method;
    std::string_view raw_path;
    std::string_view reason;
};

// clang-format off
constexpr DefaultAllow kDefaultIsCorrectFor[] = {
    // auth_routes.cpp (9)
    {"POST", R"body_cap_path(/login)body_cap_path", "Auth flow control body: small JSON credential/token/session payload (login, MFA challenge, session revoke); no bulk content."},
    {"POST", R"body_cap_path(/login/mfa)body_cap_path", "Auth flow control body: small JSON credential/token/session payload (login, MFA challenge, session revoke); no bulk content."},
    {"POST", R"body_cap_path(/login/mfa/enroll)body_cap_path", "Auth flow control body: small JSON credential/token/session payload (login, MFA challenge, session revoke); no bulk content."},
    {"POST", R"body_cap_path(/login/mfa/stepup)body_cap_path", "Auth flow control body: small JSON credential/token/session payload (login, MFA challenge, session revoke); no bulk content."},
    {"POST", R"body_cap_path(/logout)body_cap_path", "Auth flow control body: small JSON credential/token/session payload (login, MFA challenge, session revoke); no bulk content."},
    {"POST", R"body_cap_path(/api/v1/users/([^/]+)/elevation-eligibility)body_cap_path", "Auth flow control body: small JSON credential/token/session payload (login, MFA challenge, session revoke); no bulk content."},
    {"POST", R"body_cap_path(/api/v1/users/elevation-eligibility)body_cap_path", "Auth flow control body: small JSON credential/token/session payload (login, MFA challenge, session revoke); no bulk content."},
    {"POST", R"body_cap_path(/api/v1/elevate)body_cap_path", "Auth flow control body: small JSON credential/token/session payload (login, MFA challenge, session revoke); no bulk content."},
    {"POST", R"body_cap_path(/api/v1/elevate/revoke)body_cap_path", "Auth flow control body: small JSON credential/token/session payload (login, MFA challenge, session revoke); no bulk content."},

    // ca_routes.cpp (1) -- the /api/v1/ twin now has its own ca_revoke
    // kBodyCapTable entry (governance fix round, C4); only the dashboard
    // variant still resolves to the catch-all default.
    {"POST", R"body_cap_path(/api/settings/ca/revoke)body_cap_path", "Revoke request: serial-scoped small JSON body, no certificate material (import carries its own dedicated ca_import_chain* entries)."},

    // compliance_routes.cpp (8)
    {"POST", R"body_cap_path(/api/policy-fragments)body_cap_path", "Accepts a raw/JSON-wrapped yaml_source body, but PolicyStore::create_fragment itself rejects anything over 1 MiB (policy_store.cpp:212) -- strictly below the 4 MiB default, so this pre-routing gate never rejects a body the handler would still admit."},
    {"POST", R"body_cap_path(/api/policies)body_cap_path", "Same shape as /api/policy-fragments: PolicyStore::create_policy enforces its own 1 MiB cap (policy_store.cpp:615), below the 4 MiB default."},
    {"POST", R"body_cap_path(/api/policies/([^/]+)/enable)body_cap_path", "Policy-fragment lifecycle op (enable/disable/invalidate/evaluate/remediate): small JSON body (policy id + flags), no bulk content."},
    {"POST", R"body_cap_path(/api/policies/([^/]+)/disable)body_cap_path", "Policy-fragment lifecycle op (enable/disable/invalidate/evaluate/remediate): small JSON body (policy id + flags), no bulk content."},
    {"POST", R"body_cap_path(/api/policies/([^/]+)/invalidate)body_cap_path", "Policy-fragment lifecycle op (enable/disable/invalidate/evaluate/remediate): small JSON body (policy id + flags), no bulk content."},
    {"POST", R"body_cap_path(/api/policies/invalidate-all)body_cap_path", "Policy-fragment lifecycle op (enable/disable/invalidate/evaluate/remediate): small JSON body (policy id + flags), no bulk content."},
    {"POST", R"body_cap_path(/api/policies/([^/]+)/evaluate)body_cap_path", "Policy-fragment lifecycle op (enable/disable/invalidate/evaluate/remediate): small JSON body (policy id + flags), no bulk content."},
    {"POST", R"body_cap_path(/api/policies/([^/]+)/remediate)body_cap_path", "Policy-fragment lifecycle op (enable/disable/invalidate/evaluate/remediate): small JSON body (policy id + flags), no bulk content."},

    // dashboard_routes.cpp (5)
    {"POST", R"body_cap_path(/api/dashboard/group-from-results)body_cap_path", "HTMX dashboard fragment: small form/JSON body (ids, flags, retention-scan triggers)."},
    {"POST", R"body_cap_path(/api/dashboard/execute)body_cap_path", "HTMX dashboard fragment: small form/JSON body (ids, flags, retention-scan triggers)."},
    {"POST", R"body_cap_path(/fragments/tar/retention-paused/scan)body_cap_path", "HTMX dashboard fragment: small form/JSON body (ids, flags, retention-scan triggers)."},
    {"POST", R"body_cap_path(/fragments/tar/retention-paused/reenable)body_cap_path", "HTMX dashboard fragment: small form/JSON body (ids, flags, retention-scan triggers)."},
    {"POST", R"body_cap_path(/fragments/tar/retention-paused/purge)body_cap_path", "HTMX dashboard fragment: small form/JSON body (ids, flags, retention-scan triggers)."},

    // deployment_routes.cpp (2)
    {"POST", R"body_cap_path(/fragments/auto/deploy/run)body_cap_path", "/auto Deploy trigger: small JSON body (run id / target selection) -- the installer itself travels via the content_dist plugin on the agent side, never through this route."},
    {"POST", R"body_cap_path(/fragments/auto/deploy/delete)body_cap_path", "/auto Deploy trigger: small JSON body (run id / target selection) -- the installer itself travels via the content_dist plugin on the agent side, never through this route."},

    // discovery_routes.cpp (6)
    {"POST", R"body_cap_path(/api/directory/sync)body_cap_path", "Directory sync / patch / discovery config or scan trigger: small JSON body."},
    {"PUT", R"body_cap_path(/api/directory/group-mappings)body_cap_path", "Directory sync / patch / discovery config or scan trigger: small JSON body."},
    {"POST", R"body_cap_path(/api/patches/deploy)body_cap_path", "Directory sync / patch / discovery config or scan trigger: small JSON body."},
    {"POST", R"body_cap_path(/api/patches/deployments/([a-f0-9]+)/cancel)body_cap_path", "Directory sync / patch / discovery config or scan trigger: small JSON body."},
    {"POST", R"body_cap_path(/api/deployment-jobs)body_cap_path", "Directory sync / patch / discovery config or scan trigger: small JSON body."},
    {"POST", R"body_cap_path(/api/discovery/scan)body_cap_path", "Directory sync / patch / discovery config or scan trigger: small JSON body."},

    // guardian_routes.cpp (6) -- HTMX dashboard fragments, distinct from the
    // REST /api/v1/guaranteed-state/rules authoring route (its own
    // guardian_rule_authoring kBodyCapTable entry).
    {"POST", R"body_cap_path(/fragments/guardian/guards)body_cap_path", "Guardian dashboard HTMX fragment: small form/JSON body (guard/baseline id + toggle) -- distinct from the REST /api/v1/guaranteed-state/rules authoring route, which already has its own guardian_rule_authoring entry."},
    {"POST", R"body_cap_path(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/enabled)body_cap_path", "Guardian dashboard HTMX fragment: small form/JSON body (guard/baseline id + toggle) -- distinct from the REST /api/v1/guaranteed-state/rules authoring route, which already has its own guardian_rule_authoring entry."},
    {"POST", R"body_cap_path(/fragments/guardian/baselines)body_cap_path", "Guardian dashboard HTMX fragment: small form/JSON body (guard/baseline id + toggle) -- distinct from the REST /api/v1/guaranteed-state/rules authoring route, which already has its own guardian_rule_authoring entry."},
    {"POST", R"body_cap_path(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/deploy)body_cap_path", "Guardian dashboard HTMX fragment: small form/JSON body (guard/baseline id + toggle) -- distinct from the REST /api/v1/guaranteed-state/rules authoring route, which already has its own guardian_rule_authoring entry."},
    {"POST", R"body_cap_path(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/delete)body_cap_path", "Guardian dashboard HTMX fragment: small form/JSON body (guard/baseline id + toggle) -- distinct from the REST /api/v1/guaranteed-state/rules authoring route, which already has its own guardian_rule_authoring entry."},
    {"POST", R"body_cap_path(/fragments/guardian/baseline/([A-Za-z0-9._\-]+))body_cap_path", "Guardian dashboard HTMX fragment: small form/JSON body (guard/baseline id + toggle) -- distinct from the REST /api/v1/guaranteed-state/rules authoring route, which already has its own guardian_rule_authoring entry."},

    // kek_routes.cpp (0) -- both /rotate and /rewrap are now covered by the
    // shared kek_ops kBodyCapTable entry on the /api/v1/secrets/kek/ prefix
    // (governance fix round, C4), so neither takes the catch-all default.

    // notification_routes.cpp (2)
    {"POST", R"body_cap_path(/api/notifications/(\d+)/read)body_cap_path", "Notification read/dismiss toggle: no meaningful body content."},
    {"POST", R"body_cap_path(/api/notifications/(\d+)/dismiss)body_cap_path", "Notification read/dismiss toggle: no meaningful body content."},

    // offload_routes.cpp (1)
    {"POST", R"body_cap_path(/api/v1/offload-targets)body_cap_path", "Offload-target config JSON: small body (endpoint URL + auth config)."},

    // preflight_routes.cpp (2)
    {"POST", R"body_cap_path(/fragments/auto/delete)body_cap_path", "/auto Pre-flight trigger: small JSON body (run id / cohort selection)."},
    {"POST", R"body_cap_path(/fragments/auto/run)body_cap_path", "/auto Pre-flight trigger: small JSON body (run id / cohort selection)."},

    // rest_api_v1.cpp (38)
    {"POST", R"body_cap_path(/api/v1/tar/retention-paused/purge)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/management-groups)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"PUT", R"body_cap_path(/api/v1/management-groups/([a-f0-9]+))body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/management-groups/([a-f0-9]+)/members)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/management-groups/([a-f0-9]+)/roles)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/engine-principals/([a-z0-9._-]+)/roles)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/tokens)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/tokens/([^/]+)/rotate)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/tokens/([^/]+)/confirm)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/engine-principals)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/engine-principals/([^/]+)/credentials)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/engine-principals/([^/]+)/credentials/rotate)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/engine-principals/([^/]+)/credentials/confirm)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/engine-principals/([^/]+)/transfer-owner)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/users/([^/]+)/unlock)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/quarantine)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/rbac/check)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"PUT", R"body_cap_path(/api/v1/tags)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/access-reviews)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/access-reviews/([^/]+)/attestations)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/access-reviews/([^/]+)/close)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/inventory/query)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/inventory/evaluate)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/result-sets)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/result-sets/from-inventory-query)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/result-sets/from-instruction-result)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/result-sets/(rs_[0-9a-f]+)/re-eval)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/result-sets/(rs_[0-9a-f]+)/pin)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/result-sets/(rs_[0-9a-f]+)/unpin)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/device-tokens)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/software-packages)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/software-deployments)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    // #2146 Batch B2 — versioned twins of validate_scope/preview_scope_targets:
    // a single {"expression": "..."} string field, no bulk content.
    {"POST", R"body_cap_path(/api/v1/scope/validate)body_cap_path", "Scope expression syntax check: a single {\"expression\": \"...\"} string field, no bulk content."},
    {"POST", R"body_cap_path(/api/v1/scope/preview)body_cap_path", "Scope expression preview: a single {\"expression\": \"...\"} string field, no bulk content."},
    {"POST", R"body_cap_path(/api/v1/software-deployments/([a-f0-9]+)/start)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/software-deployments/([a-f0-9]+)/rollback)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/software-deployments/([a-f0-9]+)/cancel)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/license)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/upload-grants)body_cap_path", "Mint request is a handful of small JSON fields (agent_id/declared_max_size/expected_sha256/retention_class -- file_retrieval_routes.cpp register_mint); the 4 MiB default is generous but bounded, and the mint route sits behind the operator auth session unlike the upload-session surface, which has its own upload_session row."},
    {"DELETE", R"body_cap_path(/api/v1/upload-grants/([a-f0-9]+))body_cap_path", "Revoke carries no body at all; the default cap is irrelevant to a bodyless DELETE and a dedicated row would publish a class no code path can meaningfully reach."},
    {"POST", R"body_cap_path(/api/v1/guaranteed-state/push)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},
    {"POST", R"body_cap_path(/api/v1/dex/devices/([^/]+)/live)body_cap_path", "REST management/config JSON body: ids, flags, small structured payloads (management groups, engine principals, tokens, tags, access reviews, inventory queries, result-set derivation, device tokens, software packages/deployments, license, guaranteed-state push, DEX live-snapshot trigger)."},

    // settings_routes.cpp (29)
    {"POST", R"body_cap_path(/api/settings/dex-alerts/routing)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/dex-alerts/blast)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/dex-alerts/cohort-export)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/plugin-signing/clear)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/plugin-signing/require)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/tls)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/cert-upload)body_cap_path", "Single PEM cert/key file via multipart (settings_routes.cpp:3736 SETTINGS_REQ_GET_FILE) -- no dedicated size check, but PEM certs/keys are KB-scale; 4 MiB default is generous headroom, not a false-413 risk."},
    {"POST", R"body_cap_path(/api/settings/cert-paste)body_cap_path", "Pasted PEM text form field -- same KB-scale reasoning as cert-upload immediately above."},
    {"POST", R"body_cap_path(/api/settings/oidc)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/oidc/test)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/users)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/users/(.+)/role)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/enrollment-tokens)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/enrollment-tokens/batch)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/api-tokens)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/pending-agents/bulk-approve)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/pending-agents/bulk-deny)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/pending-agents/(.+)/approve)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/pending-agents/(.+)/deny)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/auto-approve)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/auto-approve/mode)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/auto-approve/(\d+)/toggle)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/management-groups)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/mcp)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/updates/([^/]+)/([^/]+)/([^/]+)/rollout)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/mfa/init)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/mfa/verify)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/mfa/recovery-codes)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},
    {"POST", R"body_cap_path(/api/settings/mfa/disable)body_cap_path", "Admin settings JSON/form body: config toggles, ids, small structured payloads."},

    // tar_tree_routes.cpp (1)
    {"POST", R"body_cap_path(/fragments/tar/capture-sources/push)body_cap_path", "TAR capture-sources push: small JSON body."},

    // webhook_routes.cpp (1)
    {"POST", R"body_cap_path(/api/webhooks)body_cap_path", "Webhook registration: small JSON body (URL + delivery config)."},

    // workflow_routes.cpp (2) -- NOT the YAML-authoring routes (POST
    // /api/workflows, POST /api/product-packs), which already have their
    // own workflow_yaml/product_pack_yaml kBodyCapTable entries.
    {"POST", R"body_cap_path(/api/scope/estimate)body_cap_path", "Trigger body: small JSON (scope estimate params) -- not a YAML-authoring route."},
    {"POST", R"body_cap_path(/api/instructions/([^/]+)/execute)body_cap_path", "Trigger body: small JSON (instruction execution args) -- not a YAML-authoring route."},

    // ── Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up,
    // 2026-08-07): 68 routes went from invisible to this scan to resolving
    // to the catch-all default. 62 are recorded here as a deliberate,
    // reviewed default-is-correct choice (mostly server.cpp's web_server_->
    // receiver: single-id-segment DELETEs with no body, and small
    // JSON/form control bodies of the same shape already recorded above
    // for the sink./svr. routes). The remaining 6 are deliberately NOT
    // recorded here -- they plausibly need their own kBodyCapTable entry
    // (large/aggregate content: a multi-definition import bundle, three
    // single-YAML-authoring routes whose direct peers /api/workflows and
    // /api/product-packs already got 16 MiB, a whole-dataset JSON-to-CSV
    // export, and an inventory-array match endpoint) -- see the change
    // report for the full list; that decision belongs to whoever owns
    // body_cap_policy.hpp, not this allowlist. This test is EXPECTED to
    // fail by name for those 6 until they get a real entry there. ──
    {"DELETE", R"body_cap_path(/api/agents/([^/]+)/properties/([a-zA-Z0-9_.:-]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/deployment-jobs/([a-f0-9]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/instruction-sets/([^/]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/instructions/([^/]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/policies/([^/]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/policy-fragments/([^/]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/product-packs/([^/]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/schedules/([^/]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/settings/api-tokens/(.+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/settings/auto-approve/(\d+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/settings/enrollment-tokens/(.+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/settings/management-groups/([a-f0-9]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/settings/pending-agents/(.+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/settings/updates/([^/]+)/([^/]+)/([^/]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/settings/users/(.+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/definitions/([A-Za-z0-9._-]+)/response-templates/([A-Za-z0-9_-]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/device-tokens/([a-f0-9]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/engine-principals/([^/]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: DELETE /api/v1/engine-principals/{id} reads one optional 'superseded_by' string field (rest_api_v1.cpp:2922) -- small, well under the 4 MiB default."},
    {"DELETE", R"body_cap_path(/api/v1/engine-principals/([a-z0-9._-]+)/roles/([^/]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/license/([a-f0-9]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/management-groups/([a-f0-9]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/management-groups/([a-f0-9]+)/members/(.+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/management-groups/([a-f0-9]+)/roles)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: DELETE /api/v1/management-groups/{id}/roles reads a small JSON body (principal_type/principal_id/role_name -- rest_api_v1.cpp:2112), same shape as its sibling POST .../roles entry above."},
    {"DELETE", R"body_cap_path(/api/v1/offload-targets/(\d+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/quarantine/(.+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/result-sets/(rs_[0-9a-f]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/sessions)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/sessions/me)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/sle/agents/([^/]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/tags/([^/]+)/([^/]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/v1/tokens/(.+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/webhooks/(\d+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"DELETE", R"body_cap_path(/api/workflows/([^/]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix (#2407 follow-up): DELETE by id/path-segment. Mechanically verified (grep for req.body across the handler's source span) the handler never reads a request body -- matches this file's own header SCOPE note for DELETE registrations."},
    {"POST", R"body_cap_path(/api/approvals/([^/]+)/approve)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: approval decision -- a single 'comment' string field."},
    {"POST", R"body_cap_path(/api/approvals/([^/]+)/reject)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: approval decision -- a single 'comment' string field."},
    {"POST", R"body_cap_path(/api/chargen/start)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: forwarded legacy command trigger (forward_legacy_command) -- small JSON body, same shape as the dashboard/settings trigger routes above."},
    {"POST", R"body_cap_path(/api/chargen/stop)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: forwarded legacy command trigger (forward_legacy_command) -- small JSON body, same shape as the dashboard/settings trigger routes above."},
    {"POST", R"body_cap_path(/api/command)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: generic command dispatch -- plugin/action identifiers (128-byte bound, validated) plus an agent_ids array; bounded well under 4 MiB even for a full-fleet target list, and fan-out is confined separately via dispatch_confined_arms."},
    {"POST", R"body_cap_path(/api/executions/([^/]+)/cancel)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: execution id from the URL only -- no meaningful body."},
    {"POST", R"body_cap_path(/api/executions/([^/]+)/rerun)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: a single 'scope' string field ('failed_only' or empty)."},
    {"POST", R"body_cap_path(/api/instruction-sets)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: InstructionSet JSON body -- name + description only."},
    {"POST", R"body_cap_path(/api/instructions)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: single InstructionDefinition JSON body (id/name/version/type/plugin/action/description + a handful of flags) -- not the bulk-import route (see the report accompanying this change for /api/instructions/import, which is NOT in this allowlist)."},
    {"POST", R"body_cap_path(/api/inventory/query)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: small JSON filter body (agent_id/plugin/since/until/limit) -- same shape as the already-recorded /api/v1/inventory/query entry above."},
    {"POST", R"body_cap_path(/api/nvd/sync)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: trigger-only, no body read (background NVD sync request)."},
    {"POST", R"body_cap_path(/api/procfetch/fetch)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: forwarded legacy command trigger (forward_legacy_command) -- small JSON body, same shape as the dashboard/settings trigger routes above."},
    {"POST", R"body_cap_path(/api/property-schemas)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: CustomPropertySchema JSON body (key/display_name/type/description/validation_regex) -- small structured fields."},
    {"POST", R"body_cap_path(/api/schedules)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: Schedule JSON body (cron expression, scope, instruction reference) -- small structured payload; dispatch at execute time is a separate, already-gated surface."},
    {"POST", R"body_cap_path(/api/schedules/([^/]+)/enable)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: schedule id from the URL only -- no meaningful body."},
    {"POST", R"body_cap_path(/api/scope/validate)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: single scope-expression string JSON body."},
    {"POST", R"body_cap_path(/api/tags/delete)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: single agent_id/key tag operation -- small JSON body."},
    {"POST", R"body_cap_path(/api/tags/query)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: single key/value tag lookup -- small JSON body."},
    {"POST", R"body_cap_path(/api/tags/set)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: single agent_id/key/value tag operation -- small JSON body."},
    {"POST", R"body_cap_path(/fragments/result-sets/(rs_[0-9a-f]+)/delete)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: result-set id from the URL only -- handler never reads req.body."},
    {"POST", R"body_cap_path(/fragments/result-sets/(rs_[0-9a-f]+)/pin)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: result-set id from the URL only -- handler never reads req.body."},
    {"POST", R"body_cap_path(/fragments/result-sets/(rs_[0-9a-f]+)/unpin)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: result-set id from the URL only -- handler never reads req.body."},
    {"POST", R"body_cap_path(/fragments/result-sets/create)body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: dashboard CSV-paste-of-device-IDs form field -- bounded by ResultSetStore's own kMaxMembersPerSet member cap (create_materialized), not by this pre-routing gate."},
    {"PUT", R"body_cap_path(/api/agents/([^/]+)/properties/([a-zA-Z0-9_.:-]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: single custom-property value JSON body ({\"value\":..., \"type\":...})."},
    {"PUT", R"body_cap_path(/api/config/([a-z_]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: single runtime-config scalar value JSON body ({\"value\":...})."},
    {"PUT", R"body_cap_path(/api/instructions/([^/]+))body_cap_path", "Newly visible after the F1-F3 scan-coverage fix: same single-InstructionDefinition JSON body shape as the sibling POST /api/instructions entry above (partial-update variant)."},
};
// clang-format on

} // namespace

// ── 1. Every registered route resolves to a deliberate class ─────────────

TEST_CASE("body-cap route inventory: every registered mutating route resolves to a deliberate class",
          "[body_cap][inventory]") {
    const auto routes = discover_mutating_routes();

    for (const auto& r : routes) {
        const auto probe = probe_path(r.raw_path);
        const auto match = resolve_body_cap(r.method, probe);

        if (match.path_class != "default")
            continue; // Covered by its own named kBodyCapTable entry — that
                      // entry's own correctness is test_body_cap_policy.cpp's job.

        const bool allowed =
            std::any_of(std::begin(kDefaultIsCorrectFor), std::end(kDefaultIsCorrectFor),
                        [&](const DefaultAllow& a) {
                            return a.method == r.method && a.raw_path == r.raw_path;
                        });

        INFO("UNRECORDED default-cap route: " << r.method << " " << r.raw_path << " ("
             << r.file << ":" << r.line << ", probe=" << probe << ")\n"
             << "resolve_body_cap() currently returns the catch-all default (4 MiB, "
                "requires_measurable=false) for this route. Fix ONE of:\n"
             << "  (a) it needs its own cap -> add an entry to kBodyCapTable in "
                "body_cap_policy.hpp;\n"
             << "  (b) 4 MiB is the deliberate, correct choice -> add {\"" << r.method
             << "\", R\"(" << r.raw_path
             << ")\", \"<one-line reason>\"} to kDefaultIsCorrectFor in "
                "test_body_cap_route_inventory.cpp.");
        CHECK(allowed);
    }
}

// ── 2. kDefaultIsCorrectFor has no stale entries ──────────────────────────

TEST_CASE("body-cap route inventory: kDefaultIsCorrectFor has no stale entries",
          "[body_cap][inventory]") {
    // The inverse of test 1: every allowlist row must still name a route
    // that (a) is still actually registered, mechanically, in the source
    // tree, and (b) still resolves to the catch-all default. A row that
    // fails either check documents a route that no longer exists, or one
    // that has since earned its own kBodyCapTable entry — either way the
    // allowlist row is now dead weight that would silently hide a REAL new
    // unreviewed default-cap route sharing its (method, path) if one were
    // ever re-added, so it must be deleted, not left in place.
    const auto routes = discover_mutating_routes();

    std::set<std::pair<std::string, std::string>> still_default;
    for (const auto& r : routes) {
        const auto probe = probe_path(r.raw_path);
        const auto match = resolve_body_cap(r.method, probe);
        if (match.path_class == "default")
            still_default.insert({r.method, r.raw_path});
    }

    for (const auto& a : kDefaultIsCorrectFor) {
        INFO("STALE kDefaultIsCorrectFor entry: " << a.method << " " << a.raw_path
             << " -- this route was not found still resolving to the catch-all default by the "
                "mechanical scan (removed, renamed, or now has its own kBodyCapTable entry). "
                "Delete this row.");
        CHECK(still_default.contains({std::string(a.method), std::string(a.raw_path)}));
    }
}

// ── 3. The documented same-prefix/different-method shape trap ────────────

TEST_CASE("body-cap route inventory: create and edit of one resource resolve "
          "to the same class",
          "[body_cap][inventory]") {
    // CREATE/EDIT PARITY. rest_api_v1.cpp:7759's POST
    // /api/v1/guaranteed-state/rules and :7904's regex PUT on a path sharing
    // that literal prefix must resolve to the SAME class, or an operator can
    // author a rule they are then permanently unable to edit: the POST admits
    // 16 MiB, and if the PUT falls to the 4 MiB catch-all every rule between
    // those two sizes is create-once, edit-never.
    //
    // This case previously asserted the OPPOSITE — that the two deliberately
    // resolved to different classes — citing body_cap_policy.hpp's own comment
    // that the PUT "falls through to the catch-all default until it gets its
    // own reviewed entry". That comment described a PENDING gap; the test
    // froze it as intent. Governance found the wedge, the PUT got its reviewed
    // entry, and the assertion inverted. Kept as a regression guard so removing
    // the PUT entry re-breaks loudly rather than silently.
    //
    // Read from the MECHANICAL inventory, not hand-picked, so this stays true
    // if either registration moves.
    const auto routes = discover_mutating_routes();

    auto find = [&](std::string_view method, std::string_view raw_path) -> const RegisteredRoute* {
        for (const auto& r : routes)
            if (r.method == method && r.raw_path == raw_path)
                return &r;
        return nullptr;
    };

    const auto* post_rules = find("POST", "/api/v1/guaranteed-state/rules");
    const auto* put_rules =
        find("PUT", R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))");
    REQUIRE(post_rules != nullptr);
    REQUIRE(put_rules != nullptr);

    const auto post_class = resolve_body_cap("POST", post_rules->raw_path).path_class;
    const auto put_class =
        resolve_body_cap("PUT", probe_path(put_rules->raw_path)).path_class;
    CHECK(post_class == "guardian_rule_authoring");
    CHECK(put_class == "guardian_rule_authoring");
    // The invariant: whatever class create resolves to, edit resolves to the
    // same one. Asserted as an equality rather than against a literal so it
    // still holds if the class is ever renamed or re-sized.
    CHECK(post_class == put_class);

    // SCIM: all three of POST/PUT/PATCH on the shared "/scim/v2/" prefix also
    // share one class — the inventory should reflect that too.
    const auto* scim_post = find("POST", "/scim/v2/Users");
    const auto* scim_put = find("PUT", R"(/scim/v2/Users/([0-9a-fA-F]+))");
    const auto* scim_patch = find("PATCH", R"(/scim/v2/Users/([0-9a-fA-F]+))");
    REQUIRE(scim_post != nullptr);
    REQUIRE(scim_put != nullptr);
    REQUIRE(scim_patch != nullptr);
    CHECK(resolve_body_cap("POST", scim_post->raw_path).path_class == "scim");
    CHECK(resolve_body_cap("PUT", probe_path(scim_put->raw_path)).path_class == "scim");
    CHECK(resolve_body_cap("PATCH", probe_path(scim_patch->raw_path)).path_class == "scim");
}

// ── 4. Best-effort shape trap: a GET handler reading the request body ────

TEST_CASE("body-cap route inventory: no GET registration's handler references req.body",
          "[body_cap][inventory]") {
    // Heuristic, not a real parse: for every sink.Get(/svr.Get( registration
    // in a route file, look at the raw source text between that
    // registration and the NEXT sink./svr. registration call in the same
    // file, and flag it if that span contains the substring "req.body". A
    // pre-routing body cap is enforced by METHOD-AGNOSTIC path matching
    // today (the /mcp/ entry is kBodyCapAnyMethod; every method-scoped
    // entry only ever names POST/PUT/PATCH) — a GET route that quietly
    // started reading req.body would inherit whatever cap its path
    // resolves to under those OTHER methods' entries, or the catch-all
    // default, neither of which was sized with a GET body in mind. Zero
    // hits as of this writing; a hit here is a prompt to go read the route
    // by hand, not an automatic verdict — see the file header.
    static const std::regex reg_re(R"(\b(sink|svr)\.(Get|Post|Put|Patch|Delete|Options)\()");

    auto files = read_all_cpp_files(fs::path(YUZU_SERVER_SRC_DIR));
    REQUIRE_FALSE(files.empty());

    std::vector<std::string> suspects;
    for (const auto& [file, text] : files) {
        std::vector<std::pair<std::string, std::size_t>> matches; // (verb, position)
        for (auto it = std::sregex_iterator(text.begin(), text.end(), reg_re);
             it != std::sregex_iterator(); ++it) {
            matches.emplace_back((*it)[2].str(), static_cast<std::size_t>(it->position(0)));
        }
        for (std::size_t i = 0; i < matches.size(); ++i) {
            if (matches[i].first != "Get")
                continue;
            const auto start = matches[i].second;
            const auto end = (i + 1 < matches.size()) ? matches[i + 1].second : text.size();
            if (text.find("req.body", start) < end) {
                int line = static_cast<int>(std::count(text.begin(), text.begin() + start, '\n')) + 1;
                suspects.push_back(file + ":" + std::to_string(line));
            }
        }
    }

    INFO("GET registration(s) whose handler span references req.body — verify by hand whether "
         "this route actually reads a request body while registered as GET (a body-bearing "
         "route MUST be POST/PUT/PATCH to receive a body_cap_policy.hpp cap at all): "
         << [&] {
                std::string joined;
                for (const auto& s : suspects) joined += s + " ";
                return joined;
            }());
    CHECK(suspects.empty());
}
