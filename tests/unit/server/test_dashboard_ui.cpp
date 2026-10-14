/// @file test_dashboard_ui.cpp
/// Page pins for the Dashboard (`/`) after the 2026-10-14 design delta: the row
/// order, the fragment placeholders that moved here from Home, the scope bar's
/// reference line, every control the console had before the move, and a source
/// scan proving no `/fragments/home/*` registration survived the rename.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <regex>
#include <string>
#include <vector>

extern const char* const kDashboardIndexHtml;

namespace {

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

std::string page() { return std::string(kDashboardIndexHtml); }

std::string read_source(const char* name) {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / name);
    REQUIRE(in.is_open());
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

} // namespace

TEST_CASE("dashboard page: rows appear in the delta's order", "[dashboard][ui]") {
    const std::string html = page();
    const std::vector<std::string> marks = {
        "class=\"page-header\"",
        "class=\"panel scope-bar\"",
        "class=\"kinds\"",
        "class=\"rw cons\"",
        "id=\"instr-form\"",
        "class=\"results panel\"",
        "class=\"history-panel panel\"",
        "id=\"dash-readout\"",
        "id=\"dash-attention\"",
        "id=\"dash-health\"",
        "id=\"dash-events\"",
        "id=\"dash-estate\"",
        "id=\"dash-policies\"",
        "class=\"dash-foot\"",
    };
    std::size_t last = 0;
    for (const auto& m : marks) {
        const auto at = html.find(m);
        INFO(m);
        REQUIRE(at != std::string::npos);
        CHECK(at >= last);
        CHECK(count_of(html, m) == 1);
        last = at;
    }
    CHECK(count_of(html, "<h1") == 1);
    CHECK(count_of(html, "<!--yuzu:shell-->") == 1);
}

TEST_CASE("dashboard page: the moved panels load from /fragments/dashboard/*", "[dashboard][ui]") {
    const std::string html = page();
    for (const char* frag : {"summary", "health", "activity", "policies"}) {
        const std::string get = std::string("hx-get=\"/fragments/dashboard/") + frag + "\"";
        INFO(frag);
        CHECK(count_of(html, get) == 1);
    }
    // Each placeholder is replaced whole; the two OOB targets carry no trigger of their own.
    CHECK(count_of(html, "hx-trigger=\"load\" hx-swap=\"outerHTML\"") == 4);
    CHECK(count_of(html, "hx-get=\"/fragments/home/") == 0);
    // The console's own loaders are unchanged: scope list, autocomplete, help, help trigger.
    CHECK(count_of(html, "hx-get=") == 8);
    CHECK(count_of(html, "hx-get=\"/fragments/scope-list\"") == 1);
}

TEST_CASE("dashboard page: the scope bar's reference line is the resolver's catalogue",
          "[dashboard][ui]") {
    const std::string html = page();
    const auto kinds = html.find("<div class=\"kinds\">");
    REQUIRE(kinds != std::string::npos);
    const std::string line = html.substr(kinds, html.find("</div>", kinds) - kinds);
    CHECK(line.find("__all__") != std::string::npos);
    CHECK(line.find("group:&lt;name&gt;") != std::string::npos);
    for (const char* kind : {"ostype", "hostname", "arch", "agent_version", "tag:&lt;key&gt;",
                             "props.&lt;key&gt;", "from_result_set:&lt;id&gt;"}) {
        INFO(kind);
        CHECK(line.find(std::string("<span>") + kind + "<b") != std::string::npos);
    }
    CHECK(line.find("All Agents targets every enrolled agent") != std::string::npos);
    // The line is a reference, not a control: no link, no handler, no request.
    CHECK(line.find("<a ") == std::string::npos);
    CHECK(line.find("hx-") == std::string::npos);
    CHECK(line.find(" on") == std::string::npos);
}

// Every control the console had before the row grid, by id, and every hx-/on*/
// sse- attribute occurrence, so a row move cannot silently drop or duplicate one.
TEST_CASE("dashboard page: the console's controls and their attributes survive the move",
          "[dashboard][ui]") {
    const std::string html = page();
    for (const char* id : {"instr-form", "instr-input", "ac-list", "scope-input", "btn-send",
                           "status-badge", "row-count", "stat-network", "stat-agent", "stat-total",
                           "result-context", "result-summary", "density-toggle", "density-label",
                           "chart-deck-host", "filter-bar", "results-loading", "results-table",
                           "results-thead", "results-tbody", "empty-row", "result-pagination",
                           "group-form-slot", "agent-count", "scope-list", "history-list",
                           "history-empty", "about-modal", "about-details", "cmd-palette",
                           "cmd-input", "cmd-results", "help-loader", "help-trigger",
                           "toast-container"}) {
        INFO(id);
        CHECK(count_of(html, std::string("id=\"") + id + "\"") == 1);
    }
    CHECK(count_of(html, "hx-post=\"/api/dashboard/execute\"") == 1);
    CHECK(count_of(html, "hx-ext=\"sse\" sse-connect=\"/events\"") == 1);
    CHECK(count_of(html, "sse-swap=\"") == 6);
    CHECK(count_of(html, "hx-trigger=\"load, every 5s, agentChanged from:body\"") == 1);
    CHECK(count_of(html, "onclick=\"clearResults()\"") == 1);
    CHECK(count_of(html, "onclick=\"toggleDensity()\"") == 1);
    CHECK(count_of(html, "onclick=\"clearHistory()\"") == 1);
    CHECK(count_of(html, "onclick=\"closeAbout(") == 2);
    CHECK(count_of(html, "name=\"instruction\"") == 1);
    CHECK(count_of(html, "name=\"scope\"") == 1);
    CHECK(count_of(html, "hx-on") == 0);
    // No gradient, glow or blur anywhere on the page (design ban list).
    CHECK(html.find("gradient") == std::string::npos);
    CHECK(html.find("blur(") == std::string::npos);
    CHECK(html.find("glow") == std::string::npos);
}

TEST_CASE("dashboard page: no sidebar scope-kinds panel, the page scrolls as a whole",
          "[dashboard][ui]") {
    const std::string html = page();
    CHECK(html.find("Scope kinds</summary>") == std::string::npos);
    CHECK(html.find("class=\"rail\"") == std::string::npos);
    CHECK(html.find("dash-grid") == std::string::npos);
    CHECK(html.find("height: 100vh") == std::string::npos);
}

// Mutation probe for the route rename: a `/fragments/home/*` registration left in any
// server source (the sibling pages included) would answer the old path with the old verb.
TEST_CASE("dashboard fragments: no /fragments/home/* route is registered anywhere",
          "[dashboard][ui][home]") {
    const std::regex reg(R"(\.(Get|Post|Put|Delete)\(\s*"/fragments/home/)");
    int scanned = 0;
    for (const auto& entry : std::filesystem::directory_iterator(YUZU_SERVER_SRC_DIR)) {
        if (entry.path().extension() != ".cpp") continue;
        std::ifstream in(entry.path());
        const std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
        ++scanned;
        INFO(entry.path().filename().string());
        CHECK_FALSE(std::regex_search(src, reg));
        CHECK(src.find("\"home.fragment.access_denied\"") == std::string::npos);
    }
    CHECK(scanned > 100);
    // And the four Dashboard registrations exist, by their exact paths.
    const std::string routes = read_source("home_routes.cpp") + read_source("home_panels_routes.cpp") +
                               read_source("health_routes.cpp");
    for (const char* frag : {"summary", "policies", "activity", "health"}) {
        INFO(frag);
        CHECK(routes.find(std::string("sink.Get(\"/fragments/dashboard/") + frag + "\"") !=
              std::string::npos);
    }
}

TEST_CASE("dashboard page: every template part is pinned under the MSVC literal cap",
          "[dashboard][ui]") {
    // The static_asserts in dashboard_ui.cpp are the gate; this reads them back so a
    // part added without one shows up here.
    const std::string src = read_source("dashboard_ui.cpp");
    const std::regex part(R"(constexpr char (kDash\w+)\[\] = R"HTM\()");
    std::vector<std::string> names;
    for (std::sregex_iterator it(src.begin(), src.end(), part), end; it != end; ++it)
        names.push_back((*it)[1].str());
    CHECK(names.size() >= 14);
    for (const auto& n : names) {
        INFO(n);
        CHECK(src.find("static_assert(sizeof(" + n + ") < kPartCap") != std::string::npos);
    }
    CHECK(src.find("constexpr std::size_t kPartCap = 15000;") != std::string::npos);
}
