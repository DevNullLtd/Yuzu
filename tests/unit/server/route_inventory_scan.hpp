#pragma once

/**
 * route_inventory_scan.hpp — a LEXICAL scan of the server route sources, shared by the route
 * inventory tests (test_body_cap_route_inventory.cpp, test_step_up_route_inventory.cpp).
 *
 * WHAT IT IS. It opens every `*.cpp` and `*.inc` under `YUZU_SERVER_SRC_DIR` (injected by
 * tests/meson.build from `meson.project_source_root()`) at test run time and regex-scans the raw
 * source text for `Post`/`Put`/`Patch`/`Delete` calls on the receiver spellings the codebase
 * uses (`sink.`, `svr.`, `web_server_->`), whose first argument is a string literal or a raw
 * string literal. No hand-copied route list, so nothing here goes stale when a route is added.
 *
 * WHAT IT IS NOT. It reads SOURCE TEXT, never the strings the compiler produced. It cannot see
 * a pattern built from a variable or a helper, an owner that registers through a differently
 * named receiver, or an escape sequence in a non-raw literal (it reports the escape's source
 * bytes, not the compiled character). A raw-string pattern is reported byte for byte, which is
 * what httplib stores. Tests that need the compiled pattern text register the owner against a
 * `TestRouteSink` instead (test_step_up_route_inventory.cpp's L1 layer); this scan is the lowest,
 * lexical layer that still sees registrations no in-process harness can construct.
 *
 * The file corpus and the extracted route list are each memoised behind a function-local
 * `static const` (one `std::regex` pass over the whole tree costs seconds), computed once per test
 * PROCESS and shared by every test case and translation unit that includes this header. Both
 * assume every call passes the same `YUZU_SERVER_SRC_DIR`, which is true today: do not call them
 * with a different directory without splitting the cache key.
 */

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (meson.project_source_root() / 'server' / 'core' / 'src') — see the server_test_exe cpp_args block."
#endif

namespace yuzu::server::test::route_scan {

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
/// Memoized (see this header's comment) — computed once per test
/// process, on the assumption every call site in this TU passes the same
/// `dir`.
inline std::vector<std::pair<std::string, std::string>> read_all_cpp_files(const fs::path& dir) {
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
/// `web_server_->` receiver — see this header's comment —
/// Post/Put/Patch/Delete method) from one file's raw source text. Matches
/// either a plain `"..."` string literal or an `R"(...)"` raw string
/// literal as the first argument — the path/pattern is always a literal in
/// this codebase (never a computed std::string), which is exactly the
/// assumption the sanity floor in `discover_mutating_routes` exists to
/// catch if it ever stops being true.
inline std::vector<RegisteredRoute> extract_routes(const std::string& file, const std::string& text) {
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
/// replaced with a fixed placeholder segment. See test_body_cap_route_inventory.cpp's header
/// for why this is exact for this codebase's route patterns today.
inline std::string probe_path(const std::string& raw_path) {
    static const std::regex group_re(R"(\([^()]*\))");
    return std::regex_replace(raw_path, group_re, "X");
}

/// Scan every `.cpp`/`.inc` under `YUZU_SERVER_SRC_DIR` and return every
/// POST/PUT/PATCH/DELETE route registration found. Shared by every
/// TEST_CASE below so the extraction logic — and its sanity floor — lives
/// in exactly one place. Memoized (see this header's comment).
inline std::vector<RegisteredRoute> discover_mutating_routes() {
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

} // namespace yuzu::server::test::route_scan
