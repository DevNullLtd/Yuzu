/**
 * test_approval_dormant_code_tripwire.cpp -- a LEXICAL TRIPWIRE, not proof (#6062).
 *
 * ADR-1009 "Accepted dormant code, and what PR3 must satisfy first" accepts PR2's bound-approval
 * primitives (`submit_bound`, the caller-held-connection `consume_ticket`, the `kGuardianDeploy`
 * origin) on the condition that nothing in production uses them yet. This test fails the day a
 * production use appears, so the first producer cannot land without someone consciously
 * extending the allow-list below AND the ADR's entry conditions.
 *
 * WHAT IT SCANS. Source text only, under `server/core/src` (YUZU_SERVER_SRC_DIR) and nowhere
 * else: files with the extensions .cpp .hpp .inc .cc .h. Not scanned: `tests/`, `server/core/
 * include`, `common/include`, `sdk/include`, `agents/`, generated files, any other extension.
 * A macro that pastes a name together, a generated file and anything the lexer cannot see are
 * invisible to it, and it proves nothing about what a caller does.
 *
 * WHAT IT COUNTS. Each identifier of kIdentifiers, in code only, per file. kRules gives the
 * EXACT count allowed in each file (min == max); a file with no entry for an identifier is
 * allowed none. Nothing is exempt: the store files (`approval_manager.hpp/.cpp`) are pinned like
 * every other, so a wrapper added there that calls a primitive raises the count and fails. What
 * it still cannot see: a wrapper that is merely CALLED from elsewhere under its own name (the
 * caller names the wrapper, not the primitive; only the wrapper's own use of the primitive is
 * counted), and the difference between the pooled `consume_ticket` overload and the held one
 * (it counts the identifier, so swapping the one MCP call for the held overload stays green).
 *
 * HOW IT LEXES. Line and block comments, string, character and raw-string literals, including
 * the encoding prefixes u8 u U L on each. An earlier version tested each raw line for a block
 * comment opener and so treated a route pattern ending in slash-star inside a string as the
 * start of a comment that swallowed the following thousands of lines; the NON-VACUITY floors
 * below (the store is scanned, the known MCP call and the known metric pre-seed are each found
 * exactly once) exist so that a scanner which goes blind fails instead of passing.
 */

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
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

// True when the encoding prefix (u8, u, U or L, possibly empty) that ends at `at` is a whole
// token: nothing identifier-like precedes it. `at` indexes the `R` of a raw string or the `'`
// of a character literal. An empty prefix means the character before `at` is not an identifier
// character. `1'000` and `FooL'x'` are not prefixes: the token is not exactly one.
bool starts_token_after_prefix(const std::string& text, std::size_t at) {
    std::size_t p = at;
    if (p >= 2 && text[p - 2] == 'u' && text[p - 1] == '8')
        p -= 2;
    else if (p >= 1 && (text[p - 1] == 'u' || text[p - 1] == 'U' || text[p - 1] == 'L'))
        p -= 1;
    return p == 0 || !is_ident_char(text[p - 1]);
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
        } else if (c == 'R' && next == '"' && starts_token_after_prefix(text, i)) {
            // Raw string: R"delim( ... )delim", with an optional u8 / u / U / L prefix.
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
        } else if (c == '"' || (c == '\'' && (i == 0 || !is_ident_char(text[i - 1]) ||
                                              starts_token_after_prefix(text, i)))) {
            // String or character literal (a `'` after an identifier character is a digit
            // separator, as in 1'000, unless that token is exactly an encoding prefix: L'x',
            // u8'x', u'x', U'x'). Ends at the matching unescaped quote, or at the newline
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

// file -> exactly this many uses is allowed (min == max pins the count both ways). A file with
// no entry for an identifier is allowed none. max < 0 would mean unlimited and is deliberately
// not used by any rule: an unlimited allowance is a blind spot (a wrapper added to the store).
struct Allow {
    int min;
    int max;
};
using Rules = std::map<std::string, std::map<std::string, Allow>>;

// The production allow-list, measured from the tree. Extending it IS the act ADR-1009 asks for.
const Rules kRules = {
    // The store declares and defines it; nothing calls it.
    {"submit_bound", {{"approval_manager.hpp", {1, 1}}, {"approval_manager.cpp", {1, 1}}}},
    // Two overloads, each declared once and defined once. The one production caller is the MCP
    // recall's pooled consume.
    {"consume_ticket",
     {{"approval_manager.hpp", {2, 2}}, {"approval_manager.cpp", {2, 2}}, {"mcp_server.cpp", {1, 1}}}},
    // The origin exists in the store (declaration plus its string conversions), and one metric
    // pre-seed names it.
    {"kGuardianDeploy",
     {{"approval_manager.hpp", {1, 1}}, {"approval_manager.cpp", {4, 4}}, {"server.cpp", {1, 1}}}},
    // The interleaving seam is declared by the store and used by tests only.
    {"set_consume_test_hook_for_test", {{"approval_manager.hpp", {1, 1}}}},
};

// The same table, written out independently of kRules so a test can pin kRules to it: a rule
// loosened or zeroed in kRules must fail a test, not just stop being exercised.
struct Expected {
    const char* id;
    const char* file;
    int count;
};
const Expected kExpected[] = {
    {"submit_bound", "approval_manager.hpp", 1},
    {"submit_bound", "approval_manager.cpp", 1},
    {"consume_ticket", "approval_manager.hpp", 2},
    {"consume_ticket", "approval_manager.cpp", 2},
    {"consume_ticket", "mcp_server.cpp", 1},
    {"kGuardianDeploy", "approval_manager.hpp", 1},
    {"kGuardianDeploy", "approval_manager.cpp", 4},
    {"kGuardianDeploy", "server.cpp", 1},
    {"set_consume_test_hook_for_test", "approval_manager.hpp", 1},
};

// One entry per violation, in a stable order, each naming the identifier and the place.
std::vector<std::string> violations(const Scan& scan, const Rules& rules) {
    std::vector<std::string> out;
    for (const auto& id : kIdentifiers) {
        std::map<std::string, int> per_file;
        for (const auto& h : scan.hits.count(id) ? scan.hits.at(id) : std::vector<Hit>{}) {
            const auto it = rules.at(id).find(h.file);
            const int seen = ++per_file[h.file];
            if (it == rules.at(id).end() || (it->second.max >= 0 && seen > it->second.max))
                out.push_back("unexpected use of `" + id + "` at " + h.file + ":" +
                              std::to_string(h.line));
        }
        for (const auto& [file, allow] : rules.at(id)) {
            if (per_file[file] < allow.min)
                out.push_back("expected at least " + std::to_string(allow.min) + " use(s) of `" +
                              id + "` in " + file + " but found " + std::to_string(per_file[file]) +
                              " (a scanner gone blind, or the allow-list is stale)");
        }
    }
    return out;
}

std::string joined(const std::vector<std::string>& v) {
    std::string o;
    for (const auto& m : v)
        o += "\n  " + m;
    return o;
}

std::string why(const Scan& scan, const std::vector<std::string>& violation_list) {
    std::ostringstream o;
    o << "A production use of the bound-approval primitives appeared or the scan went blind. "
         "ADR-1009 \"Accepted dormant code, and what PR3 must satisfy first\" accepts them ONLY "
         "while nothing uses them: before extending kRules, satisfy the ADR's PR3 entry "
         "conditions and update the ADR in the same change. Scanned "
      << scan.files << " files, " << scan.lines << " lines." << joined(violation_list);
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

    const auto v = violations(scan, kRules);
    INFO(why(scan, v));
    CHECK(v.empty());
}

bool has(const std::vector<std::string>& v, const std::string& message) {
    return std::find(v.begin(), v.end(), message) != v.end();
}

// The line the (e.count + 1)-th use of `e` lands on in write_expected_tree's file: uses of earlier
// kExpected entries in the same file come first, one per line.
int extra_use_line(const Expected& e) {
    int line = 0;
    for (const auto& other : kExpected) {
        if (&other == &e)
            break;
        if (std::string(other.file) == e.file)
            line += other.count;
    }
    return line + e.count + 1;
}

// A temp tree holding exactly the uses kExpected lists, one per line (`x.<id>();`), each file
// created only if it has a use. Nothing else: every plant below starts from a tree that
// violations() accepts, so a violation it reports is the plant's and no other.
void write_expected_tree(const fs::path& root, const Expected* skip = nullptr,
                         const Expected* extra = nullptr) {
    std::map<std::string, std::string> files;
    for (const auto& e : kExpected) {
        int n = e.count;
        if (&e == skip)
            --n;
        if (&e == extra)
            ++n;
        for (int k = 0; k < n; ++k)
            files[e.file] += std::string("void use() { x.") + e.id + "(); }\n";
    }
    for (const auto& [file, body] : files)
        write(root / file, body);
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
        CHECK(has(violations(scan, kRules), "unexpected use of `submit_bound` at a/phantom.cpp:4"));
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
        CHECK(has(violations(scan, kRules), "unexpected use of `submit_bound` at server.cpp:101"));
    }
    SECTION("mentions in comments, strings and raw strings are not uses") {
        write(tmp.path / "ok.cpp",
              "// submit_bound( consume_ticket( kGuardianDeploy\n"
              "/* submit_bound(\n   consume_ticket( */\n"
              "const char* s = \"submit_bound( kGuardianDeploy\";\n"
              "const char* r = R\"X(consume_ticket( submit_bound()X\";\n"
              "const auto* w = LR\"X(consume_ticket( submit_bound()X\";\n"
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

TEST_CASE("the tripwire lexer handles encoding-prefixed raw strings and character literals",
          "[approval_manager][bound][tripwire]") {
    yuzu::test::TempDir tmp("yuzu_test_tripwire_");
    // Each row: a literal whose body holds a quote (and, for raw strings, a block-comment
    // opener), then a REAL call on the same line. The call must be seen, once.
    struct Row {
        const char* name;
        const char* source;
        const char* id;
    };
    const Row rows[] = {
        {"LR", "auto s = LR\"(\")\"; m.submit_bound(a);\n", "submit_bound"},
        {"u8R", "auto s = u8R\"(a\"/*)\"; m.submit_bound(a);\n", "submit_bound"},
        {"uR", "auto s = uR\"(a\"/*)\"; m.submit_bound(a);\n", "submit_bound"},
        {"UR", "auto s = UR\"(a\"/*)\"; m.submit_bound(a);\n", "submit_bound"},
        {"R (control, no prefix)", "auto s = R\"(a\"/*)\"; m.submit_bound(a);\n", "submit_bound"},
        {"L char", "auto c = L'\"'; m.consume_ticket(x);\n", "consume_ticket"},
        {"u8 char", "auto c = u8'\"'; m.consume_ticket(x);\n", "consume_ticket"},
        {"u char", "auto c = u'\"'; m.consume_ticket(x);\n", "consume_ticket"},
        {"U char", "auto c = U'\"'; m.consume_ticket(x);\n", "consume_ticket"},
        {"char (control, no prefix)", "auto c = '\"'; m.consume_ticket(x);\n", "consume_ticket"},
        {"one digit separator, then a call", "auto n = 1'000; m.submit_bound(a);\n",
         "submit_bound"},
        {"several digit separators, then a call",
         "auto n = 1'000'000u + 0x1'0L + 0xFF'FFu; m.submit_bound(a);\n", "submit_bound"},
        {"prefixed literal, then a block comment, then a call",
         "auto s = LR\"(x)\"; /* c */ m.kGuardianDeploy;\n", "kGuardianDeploy"},
    };
    for (const auto& row : rows) {
        DYNAMIC_SECTION(row.name) {
            write(tmp.path / "row.cpp", row.source);
            Scan scan = scan_tree(tmp.path);
            REQUIRE(scan.hits[row.id].size() == 1);
            CHECK(scan.hits[row.id][0].line == 1);
        }
    }
    SECTION("the body of a prefixed raw string and the content of a prefixed char are not code") {
        write(tmp.path / "mentions.cpp",
              "auto a = u8R\"(m.submit_bound(a))\";\n"
              "auto b = LR\"d(m.consume_ticket(x) )\" )d\";\n"
              "auto c = L'k';\n");
        Scan scan = scan_tree(tmp.path);
        CHECK(scan.hits["submit_bound"].empty());
        CHECK(scan.hits["consume_ticket"].empty());
    }
}

TEST_CASE("the allow-list pins exact counts and is the table the ADR describes",
          "[approval_manager][bound][tripwire]") {
    // kRules must say exactly what kExpected says: no rule loosened (max != count), zeroed
    // (min != count), dropped or added.
    std::size_t rule_entries = 0;
    for (const auto& [id, files] : kRules)
        rule_entries += files.size();
    CHECK(rule_entries == std::size(kExpected));
    for (const auto& e : kExpected) {
        INFO(e.id << " in " << e.file);
        const auto id_it = kRules.find(e.id);
        REQUIRE(id_it != kRules.end());
        const auto file_it = id_it->second.find(e.file);
        REQUIRE(file_it != id_it->second.end());
        CHECK(file_it->second.min == e.count);
        CHECK(file_it->second.max == e.count);
    }
}

TEST_CASE("the tripwire names the specific violation for every way the allow-list can be broken",
          "[approval_manager][bound][tripwire]") {
    yuzu::test::TempDir tmp("yuzu_test_tripwire_");

    SECTION("control: the exact expected tree has no violation") {
        write_expected_tree(tmp.path);
        CHECK(violations(scan_tree(tmp.path), kRules).empty());
    }

    // One use too many in a file the rules allow: the cap arm. And one too few: the minimum arm.
    for (const auto& e : kExpected) {
        DYNAMIC_SECTION("one more `" << e.id << "` in " << e.file) {
            write_expected_tree(tmp.path, nullptr, &e);
            const auto v = violations(scan_tree(tmp.path), kRules);
            REQUIRE(v.size() == 1);
            CHECK(v[0] == std::string("unexpected use of `") + e.id + "` at " + e.file + ":" +
                              std::to_string(extra_use_line(e)));
        }
        DYNAMIC_SECTION("one fewer `" << e.id << "` in " << e.file) {
            write_expected_tree(tmp.path, &e);
            const auto v = violations(scan_tree(tmp.path), kRules);
            REQUIRE(v.size() == 1);
            CHECK(v[0].starts_with(std::string("expected at least ") + std::to_string(e.count) +
                                   " use(s) of `" + e.id + "` in " + e.file + " but found " +
                                   std::to_string(e.count - 1) + " "));
        }
    }

    SECTION("a use in a file the rules do not list is the unexpected-use arm") {
        write_expected_tree(tmp.path);
        write(tmp.path / "dashboard_routes.cpp", "void f() { mgr.submit_bound(a); }\n");
        const auto v = violations(scan_tree(tmp.path), kRules);
        REQUIRE(v.size() == 1);
        CHECK(v[0] == "unexpected use of `submit_bound` at dashboard_routes.cpp:1");
    }
    SECTION("a WRAPPER added to the store that calls a primitive is flagged (g8r5-sg2-1)") {
        // A future `submit_guardian_deploy` in the store calls `submit_bound`; the caller of the
        // wrapper names none of the four identifiers, so the store's own count is what sees it.
        // The expected tree's approval_manager.cpp is 7 lines (1 + 2 + 4 uses), so the wrapper's
        // body line is line 9.
        write_expected_tree(tmp.path);
        {
            std::ofstream out(tmp.path / "approval_manager.cpp", std::ios::binary | std::ios::app);
            REQUIRE(out.is_open());
            out << "auto ApprovalManager::submit_guardian_deploy(Req r) {\n"
                   "    return submit_bound(r.def, r.who, ApprovalOrigin::kGuardianDeploy);\n"
                   "}\n";
        }
        write(tmp.path / "guardian_routes.cpp", "void g() { mgr.submit_guardian_deploy(r); }\n");
        const auto v = violations(scan_tree(tmp.path), kRules);
        CHECK(has(v, "unexpected use of `submit_bound` at approval_manager.cpp:9"));
        CHECK(has(v, "unexpected use of `kGuardianDeploy` at approval_manager.cpp:9"));
        CHECK(v.size() == 2); // the wrapper's caller is, as documented, invisible
    }
    SECTION("the interleaving seam named in a production file is flagged") {
        write_expected_tree(tmp.path);
        write(tmp.path / "mcp_server.cpp", "void h() { m.set_consume_test_hook_for_test({}); }\n"
                                           "void use() { x.consume_ticket(); }\n");
        const auto v = violations(scan_tree(tmp.path), kRules);
        REQUIRE(v.size() == 1);
        CHECK(v[0] == "unexpected use of `set_consume_test_hook_for_test` at mcp_server.cpp:1");
    }
}
