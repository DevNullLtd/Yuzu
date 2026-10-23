#pragma once

/**
 * route_inventory_scan.hpp: a LEXICAL scan of the server route sources, shared by the route
 * inventory tests (test_body_cap_route_inventory.cpp, test_step_up_route_inventory.cpp).
 *
 * WHAT IT IS. It opens every `*.cpp` and `*.inc` under `YUZU_SERVER_SRC_DIR` (injected by
 * tests/meson.build from `meson.project_source_root()`) at test run time and scans the raw
 * source text for `Post`/`Put`/`Patch`/`Delete` calls on the receiver spellings the codebase
 * uses (`sink.`, `svr.`, `web_server_->`), whose first argument is a string literal or a raw
 * string literal. The matching is route_registration_scan.hpp: a literal find per method name,
 * no regular-expression library. No hand-copied route list, so nothing here goes stale when a
 * route is added.
 *
 * `find_literal_mutating_calls` is the receiver-agnostic companion: it reports a mutating verb
 * call with a literal route on ANY receiver, over the `.cpp`/`.inc` corpus and the separate
 * header corpus (`read_all_header_files`), so a registration through an aliased receiver or from
 * a header does not escape the named-receiver scan above unseen.
 *
 * WHAT IT IS NOT. It reads SOURCE TEXT, never the strings the compiler produced. It cannot see
 * a pattern built from a variable or a helper, an owner that registers through a differently
 * named receiver, a registration call wrapped in a macro (the expansion is not in the text it
 * scans), or an escape sequence in a non-raw literal (it reports the escape's source bytes, not
 * the compiled character). The production route inventory (the sink `HttplibRouteSink` records),
 * the boot sweep over it and the seal cover macro-wrapped registrations, because they see the
 * call at run time. A raw-string pattern is reported byte for byte, which is what httplib
 * stores. Tests that need the compiled pattern text register the owner against a
 * `TestRouteSink` instead (test_step_up_route_inventory.cpp's L1 layer); this scan is the lowest,
 * lexical layer that still sees registrations no in-process harness can construct.
 *
 * The file corpus and the extracted route list are each memoised behind a function-local
 * `static const` (the registration pass this replaced cost 24 s on macOS debug, and more on MSVC
 * debug where it was not measured; see tests/meson.build's shard-D note), computed once per test PROCESS and shared by
 * every test case and translation unit that includes this header. Both assume every call passes
 * the same `YUZU_SERVER_SRC_DIR`, which is true today: do not call them with a different
 * directory without splitting the cache key.
 *
 * Keep the C++ regular-expression library out of this file: test_store_wiring_order.cpp fails if
 * its short name appears here in any case, comments included.
 *
 * Namespaces: this header's names are in yuzu::server::test::route_scan; the pure scanners it calls
 * are in yuzu::test::route_scan and are named fully qualified here. Both end in `route_scan`, so a
 * test that aliases one must not also write `using namespace yuzu::server::test;`.
 */

#include "route_registration_scan.hpp"
#include "source_scan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (meson.project_source_root() / 'server' / 'core' / 'src'): see the server_test_exe cpp_args block."
#endif

namespace yuzu::server::test::route_scan {

namespace fs = std::filesystem;

/// One mechanically-extracted `sink.<Method>(...)` / `svr.<Method>(...)`
/// route registration.
struct RegisteredRoute {
    std::string file; // basename, e.g. "rest_api_v1.cpp"
    int line;
    std::string method;   // "POST" / "PUT" / "PATCH"
    std::string raw_path; // exactly as it appears in source, may be an httplib capture pattern
};

/// Read every `.cpp` AND `.inc` file under `dir` (recursively, server/core/src
/// has a `pg/` subdirectory today; nothing forbids a route file landing
/// under a future one) and return `{basename, contents}` pairs. `.inc` is
/// scanned alongside `.cpp` because a route registration living in a
/// textually-`#include`d fragment is still source text this scan must not
/// silently skip; no `.inc` file exists under server/core/src today, but a
/// future one that IS live must not regress this guard back to invisible.
/// No other extension under server/core/src carries a route
/// registration (verified: `.cpp`/`.hpp`/`.inc` are the only three
/// extensions present, and no `.hpp` carries a route registration).
///
/// Memoized (see this header's comment), computed once per test
/// process, on the assumption every call site in this test binary passes the same
/// `dir`.
inline const std::vector<std::pair<std::string, std::string>>& read_all_cpp_files(const fs::path& dir) {
    static const std::vector<std::pair<std::string, std::string>> cached = [&dir] {
        // F7: fs::recursive_directory_iterator throws filesystem_error on a
        // missing directory, which would otherwise surface as an opaque
        // Catch2 "unexpected exception" abort before the REQUIRE_FALSE
        // below ever runs, fail with an actionable message instead.
        INFO("source directory: " << dir.string());
        REQUIRE(fs::is_directory(dir));

        std::vector<std::pair<std::string, std::string>> out;
        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (!entry.is_regular_file())
                continue;
            const auto ext = entry.path().extension();
            if (ext != ".cpp" && ext != ".inc")
                continue;
            std::ifstream in(entry.path(), std::ios::binary);
            INFO("source file: " << entry.path().string());
            REQUIRE(in.is_open());
            std::ostringstream ss;
            ss << in.rdbuf();
            out.emplace_back(entry.path().filename().string(), ss.str());
        }
        return out;
    }();
    return cached;
}

/// Read every `.hpp` and `.h` file under `dir` (recursively) as `{basename, contents}` pairs.
/// Separate from `read_all_cpp_files` on purpose: that corpus (and so every test that reads it)
/// stays exactly as it was; only the tests that ask for headers see these. Memoised like it.
inline const std::vector<std::pair<std::string, std::string>>&
read_all_header_files(const fs::path& dir) {
    static const std::vector<std::pair<std::string, std::string>> cached = [&dir] {
        INFO("source directory: " << dir.string());
        REQUIRE(fs::is_directory(dir));
        std::vector<std::pair<std::string, std::string>> out;
        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (!entry.is_regular_file())
                continue;
            const auto ext = entry.path().extension();
            if (ext != ".hpp" && ext != ".h")
                continue;
            std::ifstream in(entry.path(), std::ios::binary);
            INFO("source file: " << entry.path().string());
            REQUIRE(in.is_open());
            std::ostringstream ss;
            ss << in.rdbuf();
            out.emplace_back(entry.path().filename().string(), ss.str());
        }
        return out;
    }();
    return cached;
}

/// One `<receiver>.Post|Put|Delete|Patch("literal"` or `<receiver>->...` call found in source
/// text, whatever the receiver.
struct LiteralMutatingCall {
    int line;
    std::string receiver; // the identifier before `.`/`->`; the single character (e.g. ")") when
                          // the receiver is an expression; empty when there is nothing before it
    std::string verb;     // "Post" / "Put" / "Delete" / "Patch"
};

/// Every call of a mutating httplib verb whose FIRST argument is a string literal (plain or raw)
/// on ANY receiver, in source order. A hand-rolled scan rather than a pattern pass: it runs
/// over the whole source tree (headers included), and a fixed set of four verbs does not need a
/// pattern engine. A call whose first argument is a variable (an outbound `httplib::Client`'s
/// `cli.Post(path, ...)`) is not a literal route registration and is not reported. Comments and
/// string contents are scanned like code, as everywhere in this header.
inline std::vector<LiteralMutatingCall> find_literal_mutating_calls(const std::string& text) {
    const auto is_space = [](char c) { return std::isspace(static_cast<unsigned char>(c)) != 0; };
    const auto is_ident = [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
    };
    std::vector<LiteralMutatingCall> out;
    for (const std::string_view verb : {"Post", "Put", "Delete", "Patch"}) {
        std::size_t pos = 0;
        while ((pos = text.find(verb, pos)) != std::string::npos) {
            const std::size_t at = pos;
            pos += verb.size();

            // Before the verb: `.` or `->`, optionally spaced.
            std::size_t b = at;
            while (b > 0 && is_space(text[b - 1]))
                --b;
            const bool dot = b > 0 && text[b - 1] == '.';
            const bool arrow = b > 1 && text[b - 1] == '>' && text[b - 2] == '-';
            if (!dot && !arrow)
                continue;

            // After the verb: `(`, then a plain or raw string literal.
            std::size_t a = pos;
            while (a < text.size() && is_space(text[a]))
                ++a;
            if (a >= text.size() || text[a] != '(')
                continue;
            ++a;
            while (a < text.size() && is_space(text[a]))
                ++a;
            const bool literal = text.compare(a, 1, "\"") == 0 || text.compare(a, 3, "R\"(") == 0;
            if (!literal)
                continue;

            std::size_t r_end = b - (arrow ? 2 : 1);
            while (r_end > 0 && is_space(text[r_end - 1]))
                --r_end;
            std::string receiver;
            if (r_end > 0 && is_ident(text[r_end - 1])) {
                std::size_t r_begin = r_end;
                while (r_begin > 0 && is_ident(text[r_begin - 1]))
                    --r_begin;
                receiver = text.substr(r_begin, r_end - r_begin);
            } else if (r_end > 0) {
                receiver = std::string(1, text[r_end - 1]);
            }
            const int line =
                static_cast<int>(std::count(text.begin(), text.begin() + static_cast<std::ptrdiff_t>(at),
                                            '\n')) + 1;
            out.push_back({line, std::move(receiver), std::string(verb)});
        }
    }
    std::sort(out.begin(), out.end(),
              [](const auto& x, const auto& y) { return x.line < y.line; });
    return out;
}

/// Extract every body-bearing route registration (`sink.`/`svr.`/`web_server_->` receiver, see
/// this header's comment, and a Post/Put/Patch/Delete method) from one file's raw source text.
/// The first argument is either a plain `"..."` string literal or an `R"(...)"` raw string
/// literal: the path is always a literal in this codebase (never a computed std::string), which
/// is exactly the assumption the sanity floor in `discover_mutating_routes` exists to catch if it
/// ever stops being true. The receiver must start at a word boundary, which keeps this from
/// matching a CLIENT-side call sharing a method name on an unrelated receiver
/// (`cli.Post(...)`/`client.Post(...)` in analytics_sinks.cpp/directory_sync.cpp/
/// offload_target_store.cpp/webhook_store.cpp: verified excluded: neither "cli" nor "client" ends
/// in "sink"/"svr", and "web_server_->" requires the literal receiver name, not just any `->Post(`).
inline std::vector<RegisteredRoute> extract_routes(const std::string& file, const std::string& text) {
    namespace scan = ::yuzu::test::route_scan;
    std::vector<RegisteredRoute> out;
    for (auto& reg : scan::find_route_registrations(text, scan::kMutatingMethods)) {
        std::string method = std::move(reg.method);
        std::transform(method.begin(), method.end(), method.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        out.push_back({file, ::yuzu::test::source_scan::line_of(text, reg.pos), std::move(method),
                       std::move(reg.raw_path)});
    }
    return out;
}

/// The linear probe-path builder, re-exported so the inventory tests find every scan helper here.
using ::yuzu::test::route_scan::probe_path;

/// Scan every `.cpp`/`.inc` under `YUZU_SERVER_SRC_DIR` and return every
/// POST/PUT/PATCH/DELETE route registration found. Shared by every
/// TEST_CASE below so the extraction logic, and its sanity floor, lives
/// in exactly one place. Memoized (see this header's comment).
inline std::vector<RegisteredRoute> discover_mutating_routes() {
    static const std::vector<RegisteredRoute> cached = [] {
        const auto& files = read_all_cpp_files(fs::path(YUZU_SERVER_SRC_DIR));
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
        // to 200, comfortably above ordinary churn (a handful of routes
        // added/removed/renamed between runs) but close enough to 215 that
        // losing a whole receiver family or method again (as this scan
        // previously did, silently, for 22% of the surface) still trips it.
        // A near-zero count means the SCAN is broken (wrong directory, or a
        // receiver/method spelling drifted), not that the route surface
        // shrank to nothing, fail loud rather than pass vacuously on an
        // empty or badly-undercounted inventory.
        REQUIRE(routes.size() >= 200);
        return routes;
    }();
    return cached;
}

} // namespace yuzu::server::test::route_scan
