/**
 * test_approval_dormant_code_tripwire.cpp -- a LEXICAL TRIPWIRE, not proof (#6062).
 *
 * ADR-1009 "Accepted dormant code, and what PR3 must satisfy first" accepts PR2's bound-approval
 * primitives (`submit_bound`, the caller-held-connection `consume_ticket`, the `kGuardianDeploy`
 * origin) on the condition that nothing in production calls them yet. This test fails the day a
 * production call site appears, so the first producer cannot land without someone consciously
 * extending the allow-list below AND the ADR's entry conditions. It reads source text only: it
 * cannot see a call through a function pointer, a macro or another directory, and it proves
 * nothing about what a caller does. Comments are skipped; strings are not.
 */

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct Hit {
    std::string file;
    int line;
};

std::string without_line_comment(const std::string& line) {
    const auto at = line.find("//");
    return at == std::string::npos ? line : line.substr(0, at);
}

// Every non-comment occurrence of `needle` under server/core/src, as file:line.
std::vector<Hit> find_uses(const std::string& needle) {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::vector<Hit> hits;
    for (const auto& e : std::filesystem::recursive_directory_iterator(YUZU_SERVER_SRC_DIR)) {
        const auto ext = e.path().extension().string();
        if (!e.is_regular_file() || (ext != ".cpp" && ext != ".hpp"))
            continue;
        std::ifstream in(e.path());
        std::string line;
        bool in_block = false;
        for (int n = 1; std::getline(in, line); ++n) {
            if (in_block) {
                in_block = line.find("*/") == std::string::npos;
                continue;
            }
            if (line.find("/*") != std::string::npos && line.find("*/") == std::string::npos)
                in_block = true;
            // `name()` with an empty argument list is prose ("consume_ticket() refuses ..."),
            // never a call: every real call passes at least an id.
            const auto code = without_line_comment(line);
            const auto at = code.find(needle);
            if (at != std::string::npos && (at + needle.size() >= code.size() ||
                                            code[at + needle.size()] != ')'))
                hits.push_back({e.path().filename().string(), n});
        }
    }
    return hits;
}

std::string render(const std::vector<Hit>& hits) {
    std::ostringstream o;
    for (const auto& h : hits)
        o << "\n    " << h.file << ":" << h.line;
    return o.str();
}

// Hits outside `allowed` file names (file -> max occurrences permitted there).
std::vector<Hit> unexpected(const std::vector<Hit>& hits, const std::map<std::string, int>& allowed) {
    std::map<std::string, int> seen;
    std::vector<Hit> bad;
    for (const auto& h : hits) {
        const auto it = allowed.find(h.file);
        if (it == allowed.end() || ++seen[h.file] > it->second)
            bad.push_back(h);
    }
    return bad;
}

constexpr const char* kWhy =
    "\n  A new production use of the bound-approval primitives appeared. ADR-1009 \"Accepted dormant "
    "code, and what PR3 must satisfy first\" accepts them ONLY while nothing calls them. Before "
    "extending the allow-list in this test, satisfy the ADR's PR3 entry conditions and update the "
    "ADR in the same change.";

} // namespace

TEST_CASE("bound-approval primitives still have no production caller (ADR-1009 tripwire, not proof)",
          "[approval_manager][bound][tripwire]") {
    SECTION("submit_bound is called by nothing but the store itself") {
        const auto bad = unexpected(find_uses("submit_bound("),
                                    {{"approval_manager.hpp", 99}, {"approval_manager.cpp", 99}});
        INFO(kWhy << render(bad));
        CHECK(bad.empty());
    }
    SECTION("consume_ticket has exactly one production caller: the MCP recall (pooled overload)") {
        const auto bad = unexpected(find_uses("consume_ticket("),
                                    {{"approval_manager.hpp", 99}, {"approval_manager.cpp", 99},
                                     {"mcp_server.cpp", 1}});
        INFO(kWhy << render(bad));
        CHECK(bad.empty());
    }
    SECTION("kGuardianDeploy appears only in the store, the id reservation and the metric pre-seed") {
        const auto bad = unexpected(find_uses("ApprovalOrigin::kGuardianDeploy"),
                                    {{"approval_manager.hpp", 99}, {"approval_manager.cpp", 99},
                                     {"reserved_definition_id.hpp", 99}, {"server.cpp", 1}});
        INFO(kWhy << render(bad));
        CHECK(bad.empty());
    }
}
