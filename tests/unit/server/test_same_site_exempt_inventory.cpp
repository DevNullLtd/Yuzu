/**
 * test_same_site_exempt_inventory.cpp - cookie-session writes require a same-site Origin or
 * Referer. This file is the inventory half of the tripwire pair; the wiring half is
 * tests/test_same_site_wiring_lexical.py.
 *
 * WHAT IS BYPASSED. The pre-routing same-site gate runs after session resolution. Three early
 * returns in server.cpp's pre-routing handler run BEFORE session resolution and are therefore
 * PATH-ONLY bypasses of the gate for every method:
 *   - `yuzu::server::is_login_exempt_path(path)` (web_utils.hpp),
 *   - `yuzu::server::health::is_probe_path(path)` (health_routes.hpp), and
 *   - one literal path comparison for the metrics endpoint (kMetricsPath below).
 * A mutating registration (POST/PUT/PATCH/DELETE) reachable only through one of them is never
 * checked by the gate, so each one must be a reviewed, recorded decision.
 *
 * MECHANISM. Every `*.cpp` / `*.inc` under YUZU_SERVER_SRC_DIR (injected by tests/meson.build) is
 * read at test run time, every mutating registration on the three receiver spellings used by this
 * codebase is extracted, and the REAL predicates above (not a copy) are evaluated over a concrete
 * probe path built from the registered text. The set of bypassed `{method, registered path}` pairs
 * must equal `kBypassLedger` exactly: an unlisted bypassed registration fails, and so does a
 * ledger row with no live registration. Adding a literal to `is_login_exempt_path`, a probe path,
 * or a mutating registration under an already-exempt prefix therefore fails until a ledger row
 * with a reason is added in the same change.
 *
 * The wiring gate pins four early return statements (the two metrics conditions share one path
 * branch), which is why three predicates map to four returns.
 *
 * LIMITS. Source-text scan: it sees literal paths on `sink.` / `svr.` / `web_server_->`
 * receivers only, so a registration with a computed path or a new receiver spelling is invisible
 * (the sanity floor below catches a scan that finds nothing, not a partial miss), and a mutating
 * GET handler is invisible to both this scan and the gate. The metrics literal here is tied to
 * the production condition by the lexical wiring gate.
 *
 * The scan helpers below are private to this file; a shared scanner may replace them.
 */

#include "health_routes.hpp"
#include "web_utils.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (meson.project_source_root() / 'server' / 'core' / 'src')."
#endif

using yuzu::server::is_login_exempt_path;

namespace {

namespace fs = std::filesystem;

struct Registration {
    std::string file; // basename
    int line;
    std::string method;   // "POST" / "PUT" / "PATCH" / "DELETE"
    std::string raw_path; // exactly as written in source; may be an httplib regex pattern
};

bool is_ident_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
}

/// Every mutating registration in one file's text. Receivers: `sink.`, `svr.`, `web_server_->`,
/// each preceded by a non-identifier character (so `client.Post(` and `mysink.Post(` are not
/// registrations). The first argument must be a quoted or raw string literal.
std::vector<Registration> extract_registrations(const std::string& file, const std::string& text) {
    static constexpr std::array<std::string_view, 3> kReceivers{"sink.", "svr.", "web_server_->"};
    static constexpr std::array<std::string_view, 4> kMethods{"Post", "Put", "Patch", "Delete"};
    std::vector<Registration> out;
    for (const auto recv : kReceivers) {
        for (std::size_t at = text.find(recv); at != std::string::npos;
             at = text.find(recv, at + 1)) {
            if (at > 0 && is_ident_char(text[at - 1]))
                continue;
            const std::size_t mpos = at + recv.size();
            for (const auto m : kMethods) {
                if (text.compare(mpos, m.size(), m) != 0 || mpos + m.size() >= text.size() ||
                    text[mpos + m.size()] != '(')
                    continue;
                std::size_t p = mpos + m.size() + 1;
                while (p < text.size() && std::isspace(static_cast<unsigned char>(text[p])) != 0)
                    ++p;
                std::string path;
                if (text.compare(p, 3, "R\"(") == 0) {
                    const std::size_t end = text.find(")\"", p + 3);
                    if (end == std::string::npos)
                        break;
                    path = text.substr(p + 3, end - (p + 3));
                } else if (p < text.size() && text[p] == '"') {
                    std::size_t q = p + 1;
                    while (q < text.size() && text[q] != '"')
                        q += (text[q] == '\\' && q + 1 < text.size()) ? 2 : 1;
                    if (q >= text.size())
                        break;
                    path = text.substr(p + 1, q - (p + 1));
                } else {
                    break; // computed path: not extractable
                }
                std::string method(m);
                std::transform(method.begin(), method.end(), method.begin(),
                               [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
                const int line = static_cast<int>(std::count(
                                     text.begin(), text.begin() + static_cast<std::ptrdiff_t>(at),
                                     '\n')) +
                                 1;
                out.push_back({file, line, std::move(method), std::move(path)});
                break;
            }
        }
    }
    std::sort(out.begin(), out.end(),
              [](const Registration& a, const Registration& b) { return a.line < b.line; });
    return out;
}

/// Concrete probe path for a (possibly regex) registered path: each non-nested capture group
/// becomes a fixed placeholder segment.
std::string probe_path(const std::string& raw_path) {
    static const std::regex group_re(R"(\([^()]*\))");
    return std::regex_replace(raw_path, group_re, "X");
}

/// Memoized per process; assumes every call passes the same directory.
const std::vector<Registration>& discover_mutating_registrations() {
    static const std::vector<Registration> cached = [] {
        const fs::path dir(YUZU_SERVER_SRC_DIR);
        REQUIRE(fs::is_directory(dir));
        std::vector<Registration> out;
        std::size_t files_seen = 0;
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
            ++files_seen;
            auto found = extract_registrations(entry.path().filename().string(), ss.str());
            out.insert(out.end(), found.begin(), found.end());
        }
        REQUIRE(files_seen > 0);
        // Sanity floor: a scan that finds almost nothing is broken (wrong directory, a drifted
        // receiver spelling), not evidence of a small surface.
        REQUIRE(out.size() >= 200);
        return out;
    }();
    return cached;
}

constexpr std::string_view kMetricsPath = "/metrics";

/// True when a request to `probe` returns from the pre-routing handler before session
/// resolution, using the production predicates themselves.
bool is_path_only_bypass(const std::string& probe) {
    return is_login_exempt_path(probe) || yuzu::server::health::is_probe_path(probe) ||
           probe == kMetricsPath;
}

struct LedgerRow {
    std::string_view method;
    std::string_view path; // EXACT registered text
    std::string_view reason;
};

constexpr std::string_view kPreSessionReason = "pre-session login/MFA/SAML binding";
constexpr std::string_view kScimReason = "static SCIM bearer, pre-session";

// Reviewed bypassed mutating registrations. A new row needs a reason a reviewer accepted.
constexpr std::array<LedgerRow, 12> kBypassLedger{{
    {"POST", "/login", kPreSessionReason},
    {"POST", "/login/mfa", kPreSessionReason},
    {"POST", "/login/mfa/enroll", kPreSessionReason},
    {"POST", "/saml/acs", kPreSessionReason},
    {"POST", "/scim/v2/Users", kScimReason},
    {"PUT", "/scim/v2/Users/([0-9a-fA-F]+)", kScimReason},
    {"PATCH", "/scim/v2/Users/([0-9a-fA-F]+)", kScimReason},
    {"DELETE", "/scim/v2/Users/([0-9a-fA-F]+)", kScimReason},
    {"POST", "/scim/v2/Groups", kScimReason},
    {"PUT", "/scim/v2/Groups/([0-9a-fA-F]+)", kScimReason},
    {"PATCH", "/scim/v2/Groups/([0-9a-fA-F]+)", kScimReason},
    {"DELETE", "/scim/v2/Groups/([0-9a-fA-F]+)", kScimReason},
}};

using Key = std::pair<std::string, std::string>; // {method, registered path text}

std::set<Key> ledger_keys() {
    std::set<Key> out;
    for (const auto& r : kBypassLedger)
        out.emplace(std::string(r.method), std::string(r.path));
    return out;
}

std::set<Key> bypassed_keys() {
    std::set<Key> out;
    for (const auto& r : discover_mutating_registrations()) {
        if (is_path_only_bypass(probe_path(r.raw_path)))
            out.emplace(r.method, r.raw_path);
    }
    return out;
}

} // namespace

TEST_CASE("same-site inventory: bypassed mutating registrations equal the reviewed ledger",
          "[csrf][same_site][route_inventory]") {
    const auto live = bypassed_keys();
    const auto ledger = ledger_keys();

    std::vector<Key> unlisted;
    std::vector<Key> stale;
    std::set_difference(live.begin(), live.end(), ledger.begin(), ledger.end(),
                        std::back_inserter(unlisted));
    std::set_difference(ledger.begin(), ledger.end(), live.begin(), live.end(),
                        std::back_inserter(stale));

    for (const auto& [method, path] : unlisted)
        UNSCOPED_INFO("bypassed registration with no ledger row: " << method << " " << path);
    for (const auto& [method, path] : stale)
        UNSCOPED_INFO("ledger row with no live bypassed registration: " << method << " " << path);
    CHECK(unlisted.empty());
    CHECK(stale.empty());
    CHECK(live.size() == kBypassLedger.size());
}

TEST_CASE("same-site inventory: ledger rows are shaped and reasoned",
          "[csrf][same_site][route_inventory]") {
    std::set<Key> seen;
    for (const auto& r : kBypassLedger) {
        CAPTURE(r.method, r.path);
        CHECK_FALSE(r.reason.empty());
        CHECK(seen.emplace(std::string(r.method), std::string(r.path)).second); // no duplicates
        CHECK((r.method == "POST" || r.method == "PUT" || r.method == "PATCH" ||
               r.method == "DELETE"));
        // Every row is bypassed by the real exempt predicate, not by a probe or metrics path:
        // probe and metrics returns are path-only for any method, so a mutating registration
        // there is never a ledger row, it is a failure to fix.
        const std::string probe = probe_path(std::string(r.path));
        CHECK(is_login_exempt_path(probe));
        CHECK_FALSE(yuzu::server::health::is_probe_path(probe));
        CHECK(probe != kMetricsPath);
    }
}

TEST_CASE("same-site inventory: no mutating registration is a probe or metrics path",
          "[csrf][same_site][route_inventory]") {
    for (const auto& r : discover_mutating_registrations()) {
        const std::string probe = probe_path(r.raw_path);
        INFO(r.file << ":" << r.line << " " << r.method);
        CHECK_FALSE(yuzu::server::health::is_probe_path(probe));
        CHECK(probe != kMetricsPath);
    }
}

TEST_CASE("same-site inventory: bypassed registrations stay outside session-bearing prefixes",
          "[csrf][same_site][route_inventory]") {
    for (const auto& [method, path] : bypassed_keys()) {
        const std::string probe = probe_path(path);
        INFO(method << " " << path);
        CHECK_FALSE(probe.starts_with("/api/"));
        CHECK_FALSE(probe.starts_with("/fragments/"));
        CHECK_FALSE(probe.starts_with("/mcp/"));
    }
}

TEST_CASE("same-site inventory: the scan sees the surface",
          "[csrf][same_site][route_inventory]") {
    const auto& routes = discover_mutating_registrations();
    std::size_t gated = 0;
    for (const auto& r : routes) {
        if (!is_path_only_bypass(probe_path(r.raw_path)))
            ++gated;
    }
    // A floor, not a pin: the scan finding almost nothing means the scan broke.
    CAPTURE(routes.size(), gated);
    CHECK(routes.size() >= 200);
    CHECK(gated > 150);
}

TEST_CASE("same-site inventory: the scan helper handles registration spellings",
          "[csrf][same_site][route_inventory]") {
    const std::string text =
        "sink.Post(\"/a/b\", h);\n"
        "svr.Put(R\"(/c/([0-9]+))\", h);\n"
        "  web_server_->Delete(\n    \"/d\\\"e\", h);\n"
        "client.Post(\"/not-a-route\", body);\n"
        "mysink.Patch(\"/not-a-route\", h);\n"
        "sink.Get(\"/read-only\", h);\n"
        "sink.Postfix(\"/not-a-route\", h);\n"
        "sink.Post(computed_path, h);\n";
    const auto found = extract_registrations("x.cpp", text);
    REQUIRE(found.size() == 3);
    CHECK(found[0].method == "POST");
    CHECK(found[0].raw_path == "/a/b");
    CHECK(found[0].line == 1);
    CHECK(found[1].method == "PUT");
    CHECK(found[1].raw_path == "/c/([0-9]+)");
    CHECK(found[2].method == "DELETE");
    CHECK(found[2].line == 3);
    CHECK(probe_path(found[1].raw_path) == "/c/X");
}
