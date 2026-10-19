/**
 * test_mcp_dispatch_coverage.cpp - every served MCP tool has exactly one handler,
 * the legacy dispatch chain carries no orphan or dead branch, and the registry
 * seam stays wired the way the security argument assumes.
 *
 * WHY. tools/call has two dispatch paths: the registry (a record carries its own
 * handler, so "a registry tool has a handler" is structural: a null handler is a
 * static_assert in its domain file and a boot throw in build_catalogue()) and the
 * legacy `if (tool_name == "...")` chain in mcp_server.cpp. The chain is lexical,
 * so nothing ties it to the catalogue:
 *   - a legacy tool listed in kTools[] with no branch is served by tools/list but
 *     falls through every `if` (an "unknown tool" at call time);
 *   - a branch whose tool is not in the catalogue is unreachable (the knownness
 *     gate refuses the name first), i.e. an orphan;
 *   - a tool migrated to the registry whose old branch was left behind is a dead
 *     branch that silently diverges from the live handler;
 *   - a domain file whose accessor is missing from registered_tool_records() has
 *     records nothing serves, and a refactor that feeds the boot validator from
 *     the wrong sequences, or moves the registry lookup ahead of a generic gate,
 *     silently removes a guard that nothing else tests lexically.
 *
 * MECHANISM. The test reads mcp_server.cpp and mcp_tools_*.cpp at run time
 * (YUZU_SERVER_SRC_DIR, injected by tests/meson.build, same precedent as
 * test_body_cap_route_inventory.cpp), strips comments and raw-string bodies so a
 * commented-out or quoted `tool_name == "x"` cannot count, and checks the
 * relations below against the live merged catalogue. The live McpTestServer
 * "no registry tool answers Unknown tool" case is in test_mcp_server.cpp.
 *
 * WHAT "HAS A BRANCH" MEANS. The branch relation is restricted to the DISPATCH
 * REGION: the code from the `if (tool_name == "list_agents")` branch (the first
 * branch of the chain, immediately after the registry lookup) to the last
 * "Unknown tool" backstop. Literals before it (the knownness gate, the C7/C8
 * pre-gates, approval sites, dispatch_pairs_for) are generic-gate or helper
 * literals and do not count as a branch, so deleting a branch while a gate still
 * names the tool is caught. The same restriction keeps the dead-branch relation
 * from blocking a FUTURE registry tool that needs a tool-keyed pre-gate: a
 * pre-gate lives before the region, so it is allowed; only a literal inside the
 * chain proper is a dead branch.
 *
 * REMAINING LIMITS (a lexical scan cannot close these): a literal inside the
 * region that is a helper comparison rather than the head of a branch still
 * counts as a branch (a tool deleted from the chain while another branch of the
 * region mentions its name passes); a branch reached by a set lookup rather than
 * a `tool_name == "..."` comparison is invisible; and the comment/raw-string
 * stripper is a mini lexer, not a C++ parser (an exotic literal prefix can mis-lex
 * and is the first thing to suspect if the floors below trip).
 */

#include "mcp_server_testonly.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifndef YUZU_SERVER_SRC_DIR
#error                                                                                             \
    "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (meson.project_source_root() / 'server' / 'core' / 'src') - see the server_test_exe cpp_args block."
#endif

namespace {

namespace fs = std::filesystem;

bool is_ident(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

/// Replace comments and raw-string BODIES with spaces (newlines kept, so offsets
/// and line structure survive); ordinary string and char literals are kept
/// verbatim because the scan needs the `"name"` after `tool_name ==`.
std::string strip_comments_and_raw_strings(const std::string& in) {
    std::string out = in;
    const std::size_t n = in.size();
    const auto blank = [&](std::size_t from, std::size_t to) {
        for (std::size_t k = from; k < to && k < n; ++k)
            if (out[k] != '\n')
                out[k] = ' ';
    };
    std::size_t i = 0;
    while (i < n) {
        const char c = in[i];
        if (c == '/' && i + 1 < n && in[i + 1] == '/') {
            std::size_t e = in.find('\n', i);
            if (e == std::string::npos)
                e = n;
            blank(i, e);
            i = e;
        } else if (c == '/' && i + 1 < n && in[i + 1] == '*') {
            std::size_t e = in.find("*/", i + 2);
            e = (e == std::string::npos) ? n : e + 2;
            blank(i, e);
            i = e;
        } else if (c == 'R' && i + 1 < n && in[i + 1] == '"' &&
                   (i == 0 || !is_ident(in[i - 1]) || in[i - 1] == '8' || in[i - 1] == 'u' ||
                    in[i - 1] == 'U' || in[i - 1] == 'L')) {
            // Raw string: R"delim( ... )delim"
            const std::size_t open = in.find('(', i + 2);
            if (open == std::string::npos || open - (i + 2) > 16) {
                ++i;
                continue;
            }
            const std::string close = ")" + in.substr(i + 2, open - (i + 2)) + "\"";
            std::size_t e = in.find(close, open + 1);
            if (e == std::string::npos) {
                blank(open + 1, n);
                i = n;
            } else {
                blank(open + 1, e);
                i = e + close.size();
            }
        } else if (c == '"') {
            ++i;
            while (i < n && in[i] != '"' && in[i] != '\n') {
                if (in[i] == '\\' && i + 1 < n)
                    ++i;
                ++i;
            }
            if (i < n)
                ++i;
        } else if (c == '\'' && !(i > 0 && is_ident(in[i - 1]))) {
            // Char literal (not a digit separator such as 1'000).
            ++i;
            while (i < n && in[i] != '\'' && in[i] != '\n') {
                if (in[i] == '\\' && i + 1 < n)
                    ++i;
                ++i;
            }
            if (i < n)
                ++i;
        } else {
            ++i;
        }
    }
    return out;
}

/// Read a source file once; strip CR so a CRLF checkout cannot change what the
/// scan sees. Returns the RAW text.
std::string read_source(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    REQUIRE(in.good());
    std::ostringstream ss;
    ss << in.rdbuf();
    std::string text = ss.str();
    text.erase(std::remove(text.begin(), text.end(), '\r'), text.end());
    return text;
}

/// `in` with every whitespace character removed. The source-text tripwires compare
/// squashed text on both sides, so a clang-format reflow of the scanned code (a
/// moved line break, a changed indent) cannot turn a pass into a confusing failure.
std::string squash(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (const char c : in)
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            out.push_back(c);
    return out;
}

/// mcp_server.cpp with comments and raw-string bodies stripped; read ONCE per
/// process (it is ~1.9MB and every case below needs it).
const std::string& server_code() {
    static const std::string text = strip_comments_and_raw_strings(
        read_source(fs::path(YUZU_SERVER_SRC_DIR) / "mcp_server.cpp"));
    return text;
}

/// Every name compared as `tool_name == "<literal>"` in `text` (a manual find loop:
/// no std::regex over a megabyte-sized buffer).
std::set<std::string> tool_name_literals(std::string_view text) {
    std::set<std::string> out;
    constexpr std::string_view kKey = "tool_name";
    for (std::size_t pos = text.find(kKey); pos != std::string_view::npos;
         pos = text.find(kKey, pos + 1)) {
        if (pos > 0 && is_ident(text[pos - 1]))
            continue;
        std::size_t i = pos + kKey.size();
        const auto skip_ws = [&] {
            while (i < text.size() && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n'))
                ++i;
        };
        skip_ws();
        if (i + 1 >= text.size() || text[i] != '=' || text[i + 1] != '=')
            continue;
        i += 2;
        skip_ws();
        if (i >= text.size() || text[i] != '"')
            continue;
        ++i;
        const std::size_t start = i;
        while (i < text.size() && is_ident(text[i]))
            ++i;
        if (i < text.size() && text[i] == '"' && i > start)
            out.emplace(text.substr(start, i - start));
    }
    return out;
}

constexpr std::string_view kChainStart = R"(if (tool_name == "list_agents"))";
constexpr std::string_view kUnknownBackstop =
    R"(error_response(id, kMethodNotFound, "Unknown tool: " + tool_name))";

/// The dispatch region of already-stripped code: the first branch of the legacy
/// chain to the last "Unknown tool" backstop. Empty when either anchor is missing.
std::string_view dispatch_region(std::string_view code) {
    const std::size_t a = code.find(kChainStart);
    const std::size_t b = code.rfind(kUnknownBackstop);
    if (a == std::string_view::npos || b == std::string_view::npos || b <= a)
        return {};
    return code.substr(a, b - a);
}

/// The same stripped text, squashed (see squash()); read ONCE per process.
const std::string& server_code_squashed() {
    static const std::string text = squash(server_code());
    return text;
}

const std::set<std::string>& chain_literals() {
    static const std::set<std::string> lits = tool_name_literals(dispatch_region(server_code()));
    return lits;
}

const std::set<std::string>& whole_file_literals() {
    static const std::set<std::string> lits = tool_name_literals(server_code());
    return lits;
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

bool valid_tool_name(std::string_view n) {
    if (n.empty() || n[0] < 'a' || n[0] > 'z')
        return false;
    return std::all_of(n.begin() + 1, n.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    });
}

/// The names declared in one domain file's `constexpr ToolRecord kToolRecords[]`
/// (the same grammar the lexical CI gates use). Every line of the slice that looks
/// like a record opener (4-space indent then `{"`) MUST yield a grammar-valid name;
/// a partial miss is reported through `problems`, never silently skipped.
std::vector<std::string> declared_record_names(const std::string& code, const std::string& file,
                                               std::vector<std::string>& problems) {
    std::vector<std::string> names;
    constexpr std::string_view kAnchor = "constexpr ToolRecord kToolRecords[] = {";
    const std::size_t a = code.find(kAnchor);
    if (a == std::string::npos) {
        problems.push_back(file + ": no `" + std::string(kAnchor) + "` anchor");
        return names;
    }
    if (code.find(kAnchor, a + 1) != std::string::npos)
        problems.push_back(file + ": more than one kToolRecords anchor");
    const std::size_t e = code.find("\n};", a);
    if (e == std::string::npos) {
        problems.push_back(file + ": kToolRecords slice has no closing `};`");
        return names;
    }
    std::istringstream slice(code.substr(a, e - a));
    std::string line;
    while (std::getline(slice, line)) {
        if (line.rfind("    {\"", 0) != 0)
            continue;
        const std::size_t q = line.find('"', 6);
        const std::string name = q == std::string::npos ? "" : line.substr(6, q - 6);
        if (!valid_tool_name(name))
            problems.push_back(file + ": record opener with an invalid name: " + line);
        else
            names.push_back(name);
    }
    if (names.empty())
        problems.push_back(file + ": kToolRecords slice declares no record");
    return names;
}

} // namespace

TEST_CASE("MCP dispatch coverage: the stripper and the scan behave as documented",
          "[mcp][dispatch_coverage]") {
    // A commented-out, block-commented or raw-string literal must not count; a real
    // literal after a `//` inside a string must still be seen.
    const std::string src =
        "// tool_name == \"in_line_comment\"\n"
        "/* tool_name == \"in_block\" */\n"
        "const char* u = \"http://x\"; if (tool_name == \"real_one\") {}\n"
        "auto j = R\"j(tool_name == \"in_raw\" // not a comment)j\"; char q = '\"';\n"
        "if (tool_name==\"no_space\") {} if (my_tool_name == \"other\") {}\n"
        "int big = 1'000'000; if (tool_name == \"after_digit_sep\") {}\n";
    const auto lits = tool_name_literals(strip_comments_and_raw_strings(src));
    CHECK(lits == std::set<std::string>{"real_one", "no_space", "after_digit_sep"});

    // Region: a pre-gate literal before the first chain branch is not a chain
    // literal, so a future registry tool may be named there without being "dead".
    const std::string code =
        "if (tool_name == \"pre_gate_only\") {}\n"
        "if (tool_name == \"list_agents\") {}\n"
        "if (tool_name == \"in_chain\") {}\n"
        "res.set_content(error_response(id, kMethodNotFound, \"Unknown tool: \" + tool_name), x);\n"
        "if (tool_name == \"after_backstop\") {}\n";
    const auto region = tool_name_literals(dispatch_region(code));
    CHECK(region == std::set<std::string>{"list_agents", "in_chain"});
    CHECK(dispatch_region("no anchors here").empty());
}

TEST_CASE("MCP dispatch coverage: the scan sees the chain and the registry",
          "[mcp][dispatch_coverage]") {
    // Floors, so a moved file or a changed spelling cannot make the relations
    // below pass vacuously over an empty set.
    //
    // The floors are RELATIVE to the live catalogue, so migrating a tool to the
    // registry (which shrinks the chain) does not need this test edited: the chain
    // must still carry a literal for (almost) every legacy tool. If a floor trips
    // after a deliberate change, first check the two anchors (kChainStart,
    // kUnknownBackstop) and the stripper, then adjust kFloorSlack.
    constexpr std::size_t kFloorSlack = 5;
    const auto region = dispatch_region(server_code());
    {
        INFO("dispatch region is empty: an anchor (kChainStart / kUnknownBackstop) moved or "
             "changed spelling, or the stripper mis-lexed");
        CHECK(region.size() > 0);
    }
    const auto registry = registry_names();
    const std::size_t legacy_tools = catalogue_names().size() - registry.size();
    CHECK(legacy_tools > 0);
    INFO("chain literals " << chain_literals().size() << " vs legacy tools " << legacy_tools
                           << " (slack " << kFloorSlack << ")");
    CHECK(chain_literals().size() + kFloorSlack >= legacy_tools);
    CHECK_FALSE(registry.empty());
    CHECK(registry.contains("discover_routes"));
}

TEST_CASE("MCP dispatch coverage: every legacy tool has a dispatch branch",
          "[mcp][dispatch_coverage]") {
    const auto& literals = chain_literals();
    const auto registry = registry_names();
    std::vector<std::string> missing;
    for (const auto& name : catalogue_names())
        if (!registry.contains(name) && !literals.contains(name))
            missing.push_back(name);
    INFO("legacy tools with no `tool_name == \"...\"` branch in the dispatch region: "
         << join(missing));
    CHECK(missing.empty());
}

TEST_CASE("MCP dispatch coverage: a registry tool has no legacy branch (no dead branch)",
          "[mcp][dispatch_coverage]") {
    const auto& literals = chain_literals();
    std::vector<std::string> dead;
    for (const auto& name : registry_names())
        if (literals.contains(name))
            dead.push_back(name);
    INFO("registry tools that still have a branch in the dispatch region: " << join(dead));
    CHECK(dead.empty());
}

TEST_CASE("MCP dispatch coverage: every dispatch branch names a served tool (no orphan)",
          "[mcp][dispatch_coverage]") {
    const auto catalogue = catalogue_names();
    std::vector<std::string> orphans;
    for (const auto& lit : whole_file_literals())
        if (!catalogue.contains(lit))
            orphans.push_back(lit);
    INFO("`tool_name == \"...\"` literals that name no served tool: " << join(orphans));
    CHECK(orphans.empty());
}

TEST_CASE("MCP dispatch coverage: every mcp_tools_*.cpp record is registered and has a handler",
          "[mcp][dispatch_coverage]") {
    std::vector<std::string> problems;
    std::vector<std::string> declared;
    std::size_t files = 0;
    for (const auto& entry : fs::directory_iterator(fs::path(YUZU_SERVER_SRC_DIR))) {
        const std::string fname = entry.path().filename().string();
        if (fname.rfind("mcp_tools_", 0) != 0 || entry.path().extension() != ".cpp")
            continue;
        ++files;
        const std::string code = strip_comments_and_raw_strings(read_source(entry.path()));
        const std::string flat = squash(code);
        // The compile-time half of the well-formedness rule: a new domain file
        // that omits it would only be checked at boot.
        if (flat.find(squash("static_assert(records_well_formed(kToolRecords")) ==
            std::string::npos)
            problems.push_back(
                fname + ": no `static_assert(records_well_formed(kToolRecords` over its array");
        for (const auto& name : declared_record_names(code, fname, problems)) {
            declared.push_back(name);
            const std::string def = "void handle_" + name + "(const ToolCallContext& ctx)";
            if (flat.find(squash(def)) == std::string::npos)
                problems.push_back(fname + ": no `" + def + "` definition");
        }
    }
    CHECK(files >= 1);

    // Set equality in both directions, and no name declared twice across files.
    std::set<std::string> declared_set(declared.begin(), declared.end());
    if (declared_set.size() != declared.size())
        problems.push_back("a record name is declared in more than one mcp_tools_*.cpp file");
    const auto registered = registry_names();
    for (const auto& n : declared_set)
        if (!registered.contains(n))
            problems.push_back("declared in a domain file but not in registered_tool_records(): " +
                               n);
    for (const auto& n : registered)
        if (!declared_set.contains(n))
            problems.push_back("registered but declared in no mcp_tools_*.cpp file: " + n);
    INFO(join(problems));
    CHECK(problems.empty());
}

TEST_CASE("MCP dispatch coverage: the ctor feeds the validator from the merged catalogue, and the "
          "registry lookup sits after every generic gate",
          "[mcp][dispatch_coverage]") {
    // Every comparison below is on whitespace-squashed text (see squash()).
    const std::string& code = server_code_squashed();

    // (1) The McpServer constructor builds its validator input from the MERGED
    // catalogue's raw sequences. A raw legacy table here would validate a set that
    // is not the served set (registry tools never checked, or a duplicate hidden).
    const std::size_t ctor = code.find(squash("McpServer::McpServer() {"));
    REQUIRE(ctor != std::string::npos);
    const std::size_t ctor_end = code.find("(void)compiled_input_schemas();", ctor);
    REQUIRE(ctor_end != std::string::npos);
    const std::string ctor_body = code.substr(ctor, ctor_end - ctor);
    CHECK(ctor_body.find(squash("const Catalogue& cat = catalogue();")) != std::string::npos);
    // `names` and `schemas` are built from cat.served just above the call.
    CHECK(ctor_body.find(squash("for (const auto& t : cat.served) names.push_back(t.name);")) !=
          std::string::npos);
    CHECK(ctor_body.find(squash("for (const auto& t : cat.served) "
                                "schemas.push_back({t.name, t.input_schema_json});")) !=
          std::string::npos);
    // The call's argument list, pinned token for token: `names` first (a different
    // first argument validates a different set), then the three raw sequences, the
    // schemas, and the annotation key set.
    const std::string expected_call =
        squash("validate_tool_security_registration(names, cat.raw_security, cat.raw_writes, "
               "schemas, std::span<const std::string_view>{cat.raw_annotation_names});");
    CHECK(ctor_body.find(expected_call) != std::string::npos);
    for (const char* raw : {"kTools", "kToolSecurityRows", "kWriteToolsRaw", "kToolAnnotation"})
        CHECK(ctor_body.find(raw) == std::string::npos);

    // (2) Dispatch order. The registry lookup must come AFTER knownness, the C7
    // read-only guard, the C8 security lookup and the #2405 schema pre-gate, and
    // BEFORE the first legacy branch (so a registered name never reaches the chain).
    const std::string lookup_text = squash("catalogue().handler(tool_name)");
    const std::size_t lookup = code.find(lookup_text);
    REQUIRE(lookup != std::string::npos);
    CHECK(code.find(lookup_text, lookup + 1) == std::string::npos);
    const std::size_t first_branch = code.find(squash(kChainStart));
    REQUIRE(first_branch != std::string::npos);
    CHECK(lookup < first_branch);
    for (const char* gate :
         {"classify_tool_security(tool_name, catalogue().names, catalogue().security)",
          "catalogue().writes.contains(tool_name)", "catalogue().security.find(tool_name)",
          "compiled_input_schemas().at(tool_name)"}) {
        const std::size_t g = code.find(squash(gate));
        INFO("generic gate: " << gate);
        REQUIRE(g != std::string::npos);
        CHECK(g < lookup);
    }

    // (3) The lookup site invokes the handler THROUGH the guard. A bare
    // `registry_handler(ctx)` would bypass the empty-response backstop.
    const std::string guarded =
        squash("dispatch_registry_handler(registry_handler, tool_name, ctx);");
    const std::size_t call_at = code.find(guarded, lookup);
    REQUIRE(call_at != std::string::npos);
    CHECK(call_at < first_branch);
    CHECK(code.find(guarded, call_at + 1) == std::string::npos);
    CHECK(code.find(squash("registry_handler(ctx)")) == std::string::npos);
}
