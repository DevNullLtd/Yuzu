/**
 * test_approval_dormant_code_tripwire.cpp -- a LEXICAL TRIPWIRE, not proof (#6062).
 *
 * ADR-1009 "Accepted dormant code, and what PR3 must satisfy first" accepts PR2's bound-approval
 * primitives (`submit_bound`, the caller-held-connection `consume_ticket`, the `kGuardianDeploy`
 * origin) on the condition that nothing in production uses them yet. This test fails the day a
 * production use appears, so the first producer cannot land without someone consciously
 * extending the allow-list below AND the ADR's entry conditions. It reads source text only: it
 * cannot see a call through a macro, a generated file or another directory, it cannot tell the
 * pooled `consume_ticket` overload from the held one, and it proves nothing about what a caller
 * does.
 *
 * It lexes each file (line and block comments, string, character and raw-string literals) and
 * looks for the identifiers in code only. An earlier version tested each raw line for a block
 * comment opener and so treated text such as `"/scim/v2/*"` as the start of a comment that
 * swallowed the following thousands of lines; the NON-VACUITY floors below (the store is
 * scanned, the known MCP call and the known metric pre-seed are each found exactly once) exist
 * so that a scanner which goes blind fails instead of passing.
 */

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

bool is_ident_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

// `text` with the CONTENT of every comment and every string, character and raw-string literal
// replaced by spaces (newlines kept, so line numbers survive).
std::string code_only(const std::string& text) {
    std::string out = text;
    const auto blank = [&](std::size_t from, std::size_t to) {
        for (std::size_t k = from; k < to && k < out.size(); ++k)
            if (out[k] != '\n')
                out[k] = ' ';
    };
    const std::size_t n = text.size();
    std::size_t i = 0;
    while (i < n) {
        const char c = text[i];
        const char next = i + 1 < n ? text[i + 1] : '\0';
        if (c == '/' && next == '/') {
            std::size_t end = text.find('\n', i);
            if (end == std::string::npos)
                end = n;
            blank(i, end);
            i = end;
        } else if (c == '/' && next == '*') {
            std::size_t end = text.find("*/", i + 2);
            end = end == std::string::npos ? n : end + 2;
            blank(i, end);
            i = end;
        } else if (c == 'R' && next == '"' && (i == 0 || !is_ident_char(text[i - 1]))) {
            // Raw string: R"delim( ... )delim"
            const std::size_t open = text.find('(', i + 2);
            if (open == std::string::npos || open - (i + 2) > 16) {
                ++i;
                continue;
            }
            const std::string close = ")" + text.substr(i + 2, open - (i + 2)) + "\"";
            std::size_t end = text.find(close, open + 1);
            end = end == std::string::npos ? n : end + close.size();
            blank(open + 1, end - 1);
            i = end;
        } else if (c == '"' || (c == '\'' && !(i > 0 && is_ident_char(text[i - 1])))) {
            // String or character literal (a `'` after an identifier character is a digit
            // separator, as in 1'000). Ends at the matching unescaped quote, or at the newline
            // if it is unterminated, so one stray quote cannot blind the rest of the file.
            std::size_t j = i + 1;
            while (j < n && text[j] != c && text[j] != '\n')
                j += text[j] == '\\' ? 2 : 1;
            blank(i + 1, j);
            i = j < n ? j + 1 : n;
        } else {
            ++i;
        }
    }
    return out;
}

struct Hit {
    std::string file; // path relative to the scanned root, '/' separated
    int line;
};

struct Scan {
    std::size_t files = 0;
    std::size_t lines = 0;
    std::set<std::string> scanned;
    std::map<std::string, std::vector<Hit>> hits; // identifier -> where it appears as code
};

const std::vector<std::string> kIdentifiers = {"submit_bound", "consume_ticket", "kGuardianDeploy",
                                               "set_consume_test_hook_for_test"};

Scan scan_tree(const fs::path& root) {
    REQUIRE(fs::is_directory(root));
    Scan scan;
    for (const auto& e : fs::recursive_directory_iterator(root)) {
        if (!e.is_regular_file())
            continue;
        const auto ext = e.path().extension().string();
        if (ext != ".cpp" && ext != ".hpp" && ext != ".inc" && ext != ".cc" && ext != ".h")
            continue;
        std::ifstream in(e.path(), std::ios::binary);
        REQUIRE(in.is_open()); // an unreadable file must not be silently skipped
        std::ostringstream ss;
        ss << in.rdbuf();
        const std::string rel = fs::relative(e.path(), root).generic_string();
        const std::string code = code_only(ss.str());
        ++scan.files;
        scan.scanned.insert(rel);
        std::istringstream lines(code);
        std::string line;
        for (int n = 1; std::getline(lines, line); ++n) {
            ++scan.lines;
            for (const auto& id : kIdentifiers) {
                for (auto at = line.find(id); at != std::string::npos; at = line.find(id, at + 1)) {
                    const bool left = at == 0 || !is_ident_char(line[at - 1]);
                    const bool right = at + id.size() >= line.size() || !is_ident_char(line[at + id.size()]);
                    if (left && right)
                        scan.hits[id].push_back({rel, n});
                }
            }
        }
    }
    return scan;
}

// file -> exactly this many uses is allowed (min == max pins the count both ways); max < 0 means
// unlimited and min is the floor.
struct Allow {
    int min;
    int max;
};
using Rules = std::map<std::string, std::map<std::string, Allow>>;

// The production allow-list. Extending it IS the act ADR-1009 asks for.
const Rules kRules = {
    {"submit_bound", {{"approval_manager.hpp", {1, -1}}, {"approval_manager.cpp", {1, -1}}}},
    // The one production caller is the MCP recall's pooled consume.
    {"consume_ticket",
     {{"approval_manager.hpp", {1, -1}}, {"approval_manager.cpp", {1, -1}}, {"mcp_server.cpp", {1, 1}}}},
    // The origin exists in the store, and one metric pre-seed names it.
    {"kGuardianDeploy",
     {{"approval_manager.hpp", {1, -1}}, {"approval_manager.cpp", {1, -1}}, {"server.cpp", {1, 1}}}},
    // The interleaving seam is declared by the store and used by tests only.
    {"set_consume_test_hook_for_test", {{"approval_manager.hpp", {1, 1}}}},
};

std::string violations(const Scan& scan, const Rules& rules) {
    std::ostringstream o;
    for (const auto& id : kIdentifiers) {
        std::map<std::string, int> per_file;
        for (const auto& h : scan.hits.count(id) ? scan.hits.at(id) : std::vector<Hit>{}) {
            const auto it = rules.at(id).find(h.file);
            const int seen = ++per_file[h.file];
            if (it == rules.at(id).end() || (it->second.max >= 0 && seen > it->second.max))
                o << "\n  unexpected use of `" << id << "` at " << h.file << ":" << h.line;
        }
        for (const auto& [file, allow] : rules.at(id)) {
            if (per_file[file] < allow.min)
                o << "\n  expected at least " << allow.min << " use(s) of `" << id << "` in " << file
                  << " but found " << per_file[file]
                  << " (a scanner gone blind, or the allow-list is stale)";
        }
    }
    return o.str();
}

std::string why(const Scan& scan, const std::string& v) {
    std::ostringstream o;
    o << "A production use of the bound-approval primitives appeared or the scan went blind. "
         "ADR-1009 \"Accepted dormant code, and what PR3 must satisfy first\" accepts them ONLY "
         "while nothing uses them: before extending kRules, satisfy the ADR's PR3 entry "
         "conditions and update the ADR in the same change. Scanned "
      << scan.files << " files, " << scan.lines << " lines." << v;
    return o.str();
}

fs::path src_dir() {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    return fs::path(YUZU_SERVER_SRC_DIR);
}

void write(const fs::path& p, const std::string& body) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    REQUIRE(out.is_open());
    out << body;
}

} // namespace

TEST_CASE("bound-approval primitives still have no production use (ADR-1009 tripwire, not proof)",
          "[approval_manager][bound][tripwire]") {
    const Scan scan = scan_tree(src_dir());

    // NON-VACUITY FLOORS: a scanner that cannot see the code it guards must fail, not pass.
    REQUIRE(scan.scanned.count("approval_manager.cpp") == 1);
    REQUIRE(scan.scanned.count("mcp_server.cpp") == 1);
    REQUIRE(scan.scanned.count("server.cpp") == 1);
    REQUIRE(scan.files >= 50);
    REQUIRE(scan.lines >= 50000);

    const std::string v = violations(scan, kRules);
    INFO(why(scan, v));
    CHECK(v.empty());
}

TEST_CASE("the tripwire lexer sees code that a naive line scan loses to a phantom comment",
          "[approval_manager][bound][tripwire]") {
    yuzu::test::TempDir tmp("yuzu_test_tripwire_");

    SECTION("a producer after text that merely LOOKS like a block comment opener is flagged") {
        // Each of these used to open a "block comment" that hid everything below it.
        write(tmp.path / "a" / "phantom.cpp",
              "const char* inc = \"grpcpp/security/*.h\";\n"
              "const char* route = \"/scim/v2/*\"; // see /scim/v2/* too\n"
              "char q = '\"';\n"
              "void f() { mgr.submit_bound(a); }\n");
        Scan scan = scan_tree(tmp.path);
        REQUIRE(scan.hits["submit_bound"].size() == 1);
        CHECK(scan.hits["submit_bound"][0].file == "a/phantom.cpp");
        CHECK(scan.hits["submit_bound"][0].line == 4);
        CHECK_FALSE(violations(scan, kRules).empty());
    }
    SECTION("a producer planted in a TEMP COPY of the real server.cpp, inside the span a naive "
            "scan masked, is flagged; the real tree is untouched") {
        std::ifstream in(src_dir() / "server.cpp", std::ios::binary);
        REQUIRE(in.is_open());
        std::ostringstream ss;
        ss << in.rdbuf();
        std::string body = ss.str();
        // Line 101 sits in the span (lines 9-3887) the naive scan treated as one comment.
        std::size_t at = 0;
        for (int line = 1; line < 101; ++line)
            at = body.find('\n', at) + 1;
        body.insert(at, "static auto planted = [](ApprovalManager& m) { return m.submit_bound(a); };\n");
        write(tmp.path / "server.cpp", body);
        Scan scan = scan_tree(tmp.path);
        bool found = false;
        for (const auto& h : scan.hits["submit_bound"])
            found = found || (h.file == "server.cpp" && h.line == 101);
        CHECK(found);
        CHECK_FALSE(violations(scan, kRules).empty());
    }
    SECTION("mentions in comments, strings and raw strings are not uses") {
        write(tmp.path / "ok.cpp",
              "// submit_bound( consume_ticket( kGuardianDeploy\n"
              "/* submit_bound(\n   consume_ticket( */\n"
              "const char* s = \"submit_bound( kGuardianDeploy\";\n"
              "const char* r = R\"X(consume_ticket( submit_bound()X\";\n"
              "int big = 1'000; // digit separator, not a char literal\n");
        Scan scan = scan_tree(tmp.path);
        CHECK(scan.hits["submit_bound"].empty());
        CHECK(scan.hits["consume_ticket"].empty());
        CHECK(scan.hits["kGuardianDeploy"].empty());
    }
    SECTION("forms a plain call grep misses are still seen: a split call and an address-of") {
        write(tmp.path / "forms.cpp",
              "auto a = &ApprovalManager::submit_bound;\n"
              "void f() { mgr.consume_ticket\n   (x); }\n"
              "using enum ApprovalOrigin; auto o = kGuardianDeploy;\n");
        Scan scan = scan_tree(tmp.path);
        CHECK(scan.hits["submit_bound"].size() == 1);
        CHECK(scan.hits["consume_ticket"].size() == 1);
        CHECK(scan.hits["kGuardianDeploy"].size() == 1);
    }
}
