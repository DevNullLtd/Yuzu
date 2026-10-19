/**
 * test_mcp_dispatch_coverage.cpp - every served MCP tool has exactly one handler,
 * and the legacy dispatch chain carries no orphan or dead branch.
 *
 * WHY. tools/call has two dispatch paths: the registry (a record carries its own
 * handler, so "a registry tool has a handler" is structural: a null handler is a
 * static_assert in its domain file) and the legacy `if (tool_name == "...")` chain
 * in mcp_server.cpp. The chain is lexical, so nothing ties it to the catalogue:
 *   - a legacy tool listed in kTools[] with no branch is served by tools/list but
 *     falls through every `if` (an "unknown tool" at call time);
 *   - a branch whose tool is not in the catalogue is unreachable (the knownness
 *     gate refuses the name first), i.e. an orphan;
 *   - a tool migrated to the registry whose old branch was left behind is a dead
 *     branch that silently diverges from the live handler.
 *
 * MECHANISM. The test reads mcp_server.cpp at run time (YUZU_SERVER_SRC_DIR,
 * injected by tests/meson.build, same precedent as test_body_cap_route_inventory.cpp),
 * extracts every `tool_name == "<literal>"` comparison and checks the three
 * relations below against the live merged catalogue.
 */

#include "mcp_server_testonly.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (meson.project_source_root() / 'server' / 'core' / 'src') - see the server_test_exe cpp_args block."
#endif

namespace {

namespace fs = std::filesystem;

std::string read_mcp_server_cpp() {
    const fs::path p = fs::path(YUZU_SERVER_SRC_DIR) / "mcp_server.cpp";
    std::ifstream in(p, std::ios::binary);
    REQUIRE(in.good());
    std::ostringstream ss;
    ss << in.rdbuf();
    std::string text = ss.str();
    // A CRLF checkout must not change what the regex sees.
    text.erase(std::remove(text.begin(), text.end(), '\r'), text.end());
    return text;
}

/// Every name compared as `tool_name == "<literal>"` anywhere in mcp_server.cpp.
std::set<std::string> dispatch_literals() {
    const std::string text = read_mcp_server_cpp();
    static const std::regex re(R"re(tool_name\s*==\s*"([A-Za-z0-9_]+)")re");
    std::set<std::string> out;
    for (auto it = std::sregex_iterator(text.begin(), text.end(), re);
         it != std::sregex_iterator(); ++it)
        out.insert((*it)[1].str());
    return out;
}

std::set<std::string> catalogue_names() {
    const auto v = yuzu::server::mcp::tool_names_for_test();
    return {v.begin(), v.end()};
}

std::set<std::string> registry_names() {
    const auto v = yuzu::server::mcp::registry_tool_names_for_test();
    return {v.begin(), v.end()};
}

std::string join(const std::vector<std::string>& v) {
    std::string s;
    for (const auto& x : v)
        s += (s.empty() ? "" : ", ") + x;
    return s;
}

} // namespace

TEST_CASE("MCP dispatch coverage: the scan sees the chain and the registry",
          "[mcp][dispatch_coverage]") {
    // Floors, so a moved file or a changed spelling cannot make the three relations
    // below pass vacuously over an empty set.
    CHECK(dispatch_literals().size() > 100);
    CHECK_FALSE(registry_names().empty());
    CHECK(registry_names().contains("discover_routes"));
}

TEST_CASE("MCP dispatch coverage: every legacy tool has a dispatch branch",
          "[mcp][dispatch_coverage]") {
    const auto literals = dispatch_literals();
    const auto registry = registry_names();
    std::vector<std::string> missing;
    for (const auto& name : catalogue_names())
        if (!registry.contains(name) && !literals.contains(name))
            missing.push_back(name);
    INFO("legacy tools with no `tool_name == \"...\"` branch in mcp_server.cpp: " << join(missing));
    CHECK(missing.empty());
}

TEST_CASE("MCP dispatch coverage: a registry tool has no legacy branch (no dead branch)",
          "[mcp][dispatch_coverage]") {
    const auto literals = dispatch_literals();
    std::vector<std::string> dead;
    for (const auto& name : registry_names())
        if (literals.contains(name))
            dead.push_back(name);
    INFO("registry tools that still have a dispatch branch in mcp_server.cpp: " << join(dead));
    CHECK(dead.empty());
}

TEST_CASE("MCP dispatch coverage: every dispatch branch names a served tool (no orphan)",
          "[mcp][dispatch_coverage]") {
    const auto catalogue = catalogue_names();
    std::vector<std::string> orphans;
    for (const auto& lit : dispatch_literals())
        if (!catalogue.contains(lit))
            orphans.push_back(lit);
    INFO("`tool_name == \"...\"` literals that name no served tool: " << join(orphans));
    CHECK(orphans.empty());
}
