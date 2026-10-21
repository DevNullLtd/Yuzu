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
 * (the sanity floor below catches a scan that finds nothing, not a partial miss). The metrics
 * literal here is tied to the production condition by the lexical wiring gate.
 *
 * READS THAT DISPATCH WORK. A GET or HEAD request is gated only when its exact path is in
 * `kFetchMetadataGuardedPaths` (same_site_write_policy.hpp). The second half of this file checks
 * that table against the source: every table path must be a live GET registration (no stale
 * entry), and every GET registration whose handler text contains a dispatch marker must be in the
 * table or in the small reviewed `kKnownReadOnlyDispatchLike` ledger below (no unlisted new
 * dispatcher). LIMITS of that half: it is a pure lexical scan. The handler text is the balanced
 * parenthesis span of the registration call, expanded one hop into same-file functions defined
 * as `Class::name(...) {...}` that the span calls by name. A handler that reaches a dispatch
 * only through a computed path, a helper in another file, a second hop, a handler held in a
 * variable, or a marker spelling not in `kDispatchMarkers` is invisible. A registration whose
 * path is not a string literal is reported as unscannable when its text carries a marker. The
 * markers are derived from the existing handlers; a new dispatch entry point must be added to
 * the list in the same change. Comments are stripped before matching.
 *
 * The scan helpers below are private to this file; a shared scanner may replace them.
 */

#include "health_routes.hpp"
#include "same_site_write_policy.hpp"
#include "web_utils.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
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

// ---------------------------------------------------------------------------------------------
// Reads that dispatch work
// ---------------------------------------------------------------------------------------------

struct GetRegistration {
    std::string file; // basename
    int line;
    std::string path;   // exactly as written in source, or "<computed>"
    std::string handler; // balanced-paren span of the call, comments stripped, plus one hop
};

constexpr std::array<std::string_view, 5> kDispatchMarkers{
    "dispatch_fn_(", "dispatch_confined(", "advance_and_render(", "deployment::advance(",
    "->dispatch(",
};

constexpr std::string_view kComputedPath = "<computed>";

struct ReadLedgerRow {
    std::string_view path; // EXACT registered text
    std::string_view reason;
};

// Reviewed GET registrations whose handler text contains a dispatch marker but which are not in
// the guarded table. A new row needs a one-line reason a reviewer accepted. Empty: every marker
// hit in the current tree is a table entry.
constexpr std::array<ReadLedgerRow, 0> kKnownReadOnlyDispatchLike{};

/// Removes `//` comments (to end of line) where the `//` starts a line or follows whitespace, so
/// a scheme separator inside a string is left alone. Block comments are left as written.
std::string strip_line_comments(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    std::size_t i = 0;
    while (i < text.size()) {
        const bool at_comment = text[i] == '/' && i + 1 < text.size() && text[i + 1] == '/' &&
                                (i == 0 || std::isspace(static_cast<unsigned char>(text[i - 1])) != 0);
        if (at_comment) {
            while (i < text.size() && text[i] != '\n')
                ++i;
            continue;
        }
        out.push_back(text[i++]);
    }
    return out;
}

/// Index one past the `)` that balances the `(` at `open`, skipping string, raw string and char
/// literals; npos when unbalanced.
std::size_t balanced_paren_end(const std::string& text, std::size_t open) {
    int depth = 0;
    for (std::size_t j = open; j < text.size(); ++j) {
        const char c = text[j];
        if (c == 'R' && j + 2 < text.size() && text[j + 1] == '"' && text[j + 2] == '(' &&
            (j == 0 || !is_ident_char(text[j - 1]))) {
            const std::size_t end = text.find(")\"", j + 3);
            if (end == std::string::npos)
                return std::string::npos;
            j = end + 1;
        } else if (c == '"') {
            ++j;
            while (j < text.size() && text[j] != '"')
                j += (text[j] == '\\' && j + 1 < text.size()) ? 2 : 1;
        } else if (c == '\'') {
            ++j;
            while (j < text.size() && text[j] != '\'')
                j += (text[j] == '\\' && j + 1 < text.size()) ? 2 : 1;
        } else if (c == '(') {
            ++depth;
        } else if (c == ')') {
            if (--depth == 0)
                return j + 1;
        }
    }
    return std::string::npos;
}

/// Same-file function bodies keyed by unqualified name, for definitions spelled
/// `Qualifier::name(<params>) [const] [noexcept] {<body>}`. Overloads are concatenated.
std::map<std::string, std::string> function_bodies(const std::string& text) {
    std::map<std::string, std::string> out;
    for (std::size_t at = text.find("::"); at != std::string::npos; at = text.find("::", at + 2)) {
        std::size_t p = at + 2;
        const std::size_t name_begin = p;
        while (p < text.size() && is_ident_char(text[p]))
            ++p;
        if (p == name_begin || at == 0 || !is_ident_char(text[at - 1]))
            continue;
        std::size_t q = p;
        while (q < text.size() && std::isspace(static_cast<unsigned char>(text[q])) != 0)
            ++q;
        if (q >= text.size() || text[q] != '(')
            continue;
        const std::size_t params_end = balanced_paren_end(text, q);
        if (params_end == std::string::npos)
            continue;
        std::size_t r = params_end;
        for (;;) {
            while (r < text.size() && std::isspace(static_cast<unsigned char>(text[r])) != 0)
                ++r;
            if (text.compare(r, 5, "const") == 0)
                r += 5;
            else if (text.compare(r, 8, "noexcept") == 0)
                r += 8;
            else
                break;
        }
        if (r >= text.size() || text[r] != '{')
            continue;
        int depth = 0;
        std::size_t e = r;
        for (; e < text.size(); ++e) {
            if (text[e] == '{')
                ++depth;
            else if (text[e] == '}' && --depth == 0)
                break;
        }
        out[text.substr(name_begin, p - name_begin)] += text.substr(r, e - r);
    }
    return out;
}

/// Identifiers immediately followed (after optional whitespace) by `(`.
std::set<std::string> called_names(const std::string& text) {
    std::set<std::string> out;
    std::size_t i = 0;
    while (i < text.size()) {
        if (!is_ident_char(text[i])) {
            ++i;
            continue;
        }
        const std::size_t b = i;
        while (i < text.size() && is_ident_char(text[i]))
            ++i;
        std::size_t k = i;
        while (k < text.size() && std::isspace(static_cast<unsigned char>(text[k])) != 0)
            ++k;
        if (k < text.size() && text[k] == '(')
            out.insert(text.substr(b, i - b));
    }
    return out;
}

bool has_dispatch_marker(const std::string& text) {
    return std::any_of(kDispatchMarkers.begin(), kDispatchMarkers.end(),
                       [&](std::string_view m) { return text.find(m) != std::string::npos; });
}

/// Every GET registration in one file's text, on the same three receivers as the mutating scan.
/// A literal first argument gives the path; any other first argument gives kComputedPath.
std::vector<GetRegistration> extract_get_registrations(const std::string& file,
                                                       const std::string& raw_text) {
    static constexpr std::array<std::string_view, 3> kReceivers{"sink.", "svr.", "web_server_->"};
    const std::string text = strip_line_comments(raw_text);
    const auto bodies = function_bodies(text);
    std::vector<GetRegistration> out;
    for (const auto recv : kReceivers) {
        for (std::size_t at = text.find(recv); at != std::string::npos;
             at = text.find(recv, at + 1)) {
            if (at > 0 && is_ident_char(text[at - 1]))
                continue;
            const std::size_t mpos = at + recv.size();
            if (text.compare(mpos, 4, "Get(") != 0)
                continue;
            const std::size_t open = mpos + 3;
            const std::size_t end = balanced_paren_end(text, open);
            if (end == std::string::npos)
                continue;
            std::size_t p = open + 1;
            while (p < text.size() && std::isspace(static_cast<unsigned char>(text[p])) != 0)
                ++p;
            std::string path(kComputedPath);
            if (text.compare(p, 3, "R\"(") == 0) {
                const std::size_t pe = text.find(")\"", p + 3);
                if (pe != std::string::npos)
                    path = text.substr(p + 3, pe - (p + 3));
            } else if (p < text.size() && text[p] == '"') {
                std::size_t q = p + 1;
                while (q < text.size() && text[q] != '"')
                    q += (text[q] == '\\' && q + 1 < text.size()) ? 2 : 1;
                if (q < text.size())
                    path = text.substr(p + 1, q - (p + 1));
            }
            std::string handler = text.substr(open, end - open);
            for (const auto& name : called_names(handler)) {
                const auto it = bodies.find(name);
                if (it != bodies.end())
                    handler += it->second;
            }
            const int line = static_cast<int>(std::count(
                                 text.begin(), text.begin() + static_cast<std::ptrdiff_t>(at),
                                 '\n')) +
                             1;
            out.push_back({file, line, std::move(path), std::move(handler)});
        }
    }
    std::sort(out.begin(), out.end(),
              [](const GetRegistration& a, const GetRegistration& b) { return a.line < b.line; });
    return out;
}

/// Memoized per process; assumes every call passes the same directory.
const std::vector<GetRegistration>& discover_get_registrations() {
    static const std::vector<GetRegistration> cached = [] {
        const fs::path dir(YUZU_SERVER_SRC_DIR);
        REQUIRE(fs::is_directory(dir));
        std::vector<GetRegistration> out;
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
            auto found = extract_get_registrations(entry.path().filename().string(), ss.str());
            out.insert(out.end(), found.begin(), found.end());
        }
        // Sanity floor: a scan that finds almost nothing is broken, not evidence of a small surface.
        REQUIRE(out.size() >= 200);
        return out;
    }();
    return cached;
}

bool is_known_read_ledger_path(std::string_view path) {
    return std::any_of(kKnownReadOnlyDispatchLike.begin(), kKnownReadOnlyDispatchLike.end(),
                       [&](const ReadLedgerRow& r) { return r.path == path; });
}

bool is_guarded_table_path(std::string_view path) {
    return std::find(yuzu::server::kFetchMetadataGuardedPaths.begin(),
                     yuzu::server::kFetchMetadataGuardedPaths.end(),
                     path) != yuzu::server::kFetchMetadataGuardedPaths.end();
}

/// Registrations whose handler text carries a dispatch marker but whose path is neither in the
/// guarded table nor in the reviewed ledger, as "<file>:<line> <path>".
std::vector<std::string> unlisted_dispatching_reads(const std::vector<GetRegistration>& regs) {
    std::vector<std::string> out;
    for (const auto& r : regs) {
        if (!has_dispatch_marker(r.handler))
            continue;
        if (is_guarded_table_path(r.path) || is_known_read_ledger_path(r.path))
            continue;
        out.push_back(r.file + ":" + std::to_string(r.line) + " " + r.path);
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


TEST_CASE("same-site inventory: every guarded-table path is a live GET registration",
          "[csrf][same_site][route_inventory]") {
    const auto& regs = discover_get_registrations();
    for (const auto path : yuzu::server::kFetchMetadataGuardedPaths) {
        CAPTURE(path);
        const auto live = std::count_if(regs.begin(), regs.end(),
                                        [&](const GetRegistration& r) { return r.path == path; });
        CHECK(live >= 1);
        CHECK(yuzu::server::is_guarded_read("GET", path));
    }
}

TEST_CASE("same-site inventory: every dispatching GET registration is guarded or reviewed",
          "[csrf][same_site][route_inventory]") {
    const auto unlisted = unlisted_dispatching_reads(discover_get_registrations());
    for (const auto& s : unlisted)
        UNSCOPED_INFO("GET registration with a dispatch marker and no table or ledger entry: " << s);
    CHECK(unlisted.empty());
}

TEST_CASE("same-site inventory: every table path and ledger row is a dispatching GET registration",
          "[csrf][same_site][route_inventory]") {
    const auto& regs = discover_get_registrations();
    const auto dispatches = [&](std::string_view path) {
        return std::any_of(regs.begin(), regs.end(), [&](const GetRegistration& r) {
            return r.path == path && has_dispatch_marker(r.handler);
        });
    };
    for (const auto path : yuzu::server::kFetchMetadataGuardedPaths) {
        CAPTURE(path);
        CHECK(dispatches(path));
    }
    for (const auto& row : kKnownReadOnlyDispatchLike) {
        CAPTURE(row.path);
        CHECK(dispatches(row.path));
        CHECK_FALSE(is_guarded_table_path(row.path));
        CHECK_FALSE(row.reason.empty());
    }
}

TEST_CASE("same-site inventory: the GET scan sees the surface and the computed-path floor",
          "[csrf][same_site][route_inventory]") {
    const auto& regs = discover_get_registrations();
    std::size_t computed = 0;
    for (const auto& r : regs) {
        if (r.path == kComputedPath) {
            ++computed;
            // A registration the scan cannot name must not carry a marker: it would be invisible
            // to the table check.
            INFO(r.file << ":" << r.line);
            CHECK_FALSE(has_dispatch_marker(r.handler));
        }
    }
    CAPTURE(regs.size(), computed);
    CHECK(regs.size() >= 200);
}

TEST_CASE("same-site inventory: the GET scanner flags an unlisted dispatching handler",
          "[csrf][same_site][route_inventory]") {
    const std::string text =
        "void R::reg(Sink& sink) {\n"
        "  sink.Get(\"/synthetic/new\", [this](const Req& req, Res& res) {\n"
        "      const auto out = dispatch_fn_(\"p\", \"a\", {id}, \"\", {});\n"
        "  });\n"
        "  sink.Get(\n"
        "      R\"(/synthetic/regex/([0-9]+))\", [this](const Req&, Res& res) {\n"
        "      confine->dispatch_confined(x);\n"
        "  });\n"
        "  sink.Get(\"/synthetic/quiet\", [](const Req&, Res& res) { res.set_content(\"x\", \"t\"); });\n"
        "  sink.Get(\"/synthetic/commented\", [](const Req&, Res& res) {\n"
        "      // dispatch_fn_(\"p\", \"a\")\n"
        "      res.set_content(\"x\", \"t\");\n"
        "  });\n"
        "  sink.Get(\"/synthetic/hop\", [this](const Req&, Res& res) { helper_run(res); });\n"
        "  sink.Get(computed_path, [this](const Req&, Res& res) { dispatch_fn_(a); });\n"
        "  sink.Post(\"/synthetic/post\", [this](const Req&, Res&) { dispatch_fn_(a); });\n"
        "  client.Get(\"/synthetic/client\", [this] { dispatch_fn_(a); });\n"
        "}\n"
        "void R::helper_run(Res& res) const { auto o = dispatch_fn_(\"p\", \"a\", {}, \"\", {}); }\n";
    const auto regs = extract_get_registrations("x.cpp", text);
    REQUIRE(regs.size() == 6);
    CHECK(regs[0].path == "/synthetic/new");
    CHECK(regs[0].line == 2);
    CHECK(regs[1].path == "/synthetic/regex/([0-9]+)");
    CHECK(regs[4].path == "/synthetic/hop");
    CHECK(regs[5].path == kComputedPath);
    CHECK(has_dispatch_marker(regs[0].handler));
    CHECK(has_dispatch_marker(regs[1].handler));
    CHECK_FALSE(has_dispatch_marker(regs[2].handler)); // quiet
    CHECK_FALSE(has_dispatch_marker(regs[3].handler)); // marker only in a comment
    CHECK(has_dispatch_marker(regs[4].handler));       // the hop
    CHECK(has_dispatch_marker(regs[5].handler));       // computed path, still carries a marker

    const auto unlisted = unlisted_dispatching_reads(regs);
    REQUIRE(unlisted.size() == 4);
    CHECK(unlisted[0] == "x.cpp:2 /synthetic/new");
    CHECK(unlisted[1] == "x.cpp:5 /synthetic/regex/([0-9]+)");
    CHECK(unlisted[2].ends_with(" /synthetic/hop"));
    CHECK(unlisted[3].ends_with(" <computed>"));
}

TEST_CASE("same-site inventory: the GET scanner passes a guarded table path",
          "[csrf][same_site][route_inventory]") {
    const std::string text =
        "sink.Get(\"" + std::string(yuzu::server::kFetchMetadataGuardedPaths[0]) +
        "\", [this](const Req&, Res&) { dispatch_fn_(a); });\n";
    const auto regs = extract_get_registrations("x.cpp", text);
    REQUIRE(regs.size() == 1);
    CHECK(has_dispatch_marker(regs[0].handler));
    CHECK(unlisted_dispatching_reads(regs).empty());
}
