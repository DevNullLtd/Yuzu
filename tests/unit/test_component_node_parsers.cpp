/**
 * test_component_node_parsers.cpp — pure Node package parsers
 * (component_node_parsers.hpp). The package.json files are real captures from
 * an `npm ci` tree (tests/unit/fixtures/software-estate/components/node/,
 * provenance.txt); the malformed corpus is synthetic. No I/O beyond reading
 * the committed fixtures.
 */

#include "component_node_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::component_inventory;

namespace {

#ifndef YUZU_TEST_FIXTURE_DIR
#define YUZU_TEST_FIXTURE_DIR "tests/unit/fixtures"
#endif

std::string read_fixture(const std::string& name) {
    const auto path = fs::path{YUZU_TEST_FIXTURE_DIR} / "software-estate" / "components" / "node" / name;
    INFO("fixture path: " << path.string());
    REQUIRE(fs::exists(path));
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string nested(const char open, const char close, int n) {
    return std::string(static_cast<std::size_t>(n), open) + std::string(static_cast<std::size_t>(n), close);
}

} // namespace

TEST_CASE("node: real package.json captures give their name and version", "[runtime][component_inventory][node]") {
    struct Row {
        const char* file;
        const char* path;
        const char* dir_name;
        std::size_t nesting;
        const char* name;
        const char* version;
    };
    const Row rows[] = {
        {"semver.package.json", "app/node_modules/semver/package.json", "semver", 1, "semver", "5.7.2"},
        {"ms.package.json", "app/node_modules/ms/package.json", "ms", 1, "ms", "2.1.3"},
        {"debug.package.json", "app/node_modules/debug/package.json", "debug", 1, "debug", "4.4.3"},
        {"babel-core.package.json", "app/node_modules/@babel/core/package.json", "@babel/core", 1, "@babel/core",
         "7.24.0"},
        {"babel-core-nested-semver.package.json", "app/node_modules/@babel/core/node_modules/semver/package.json",
         "semver", 2, "semver", "6.3.2"},
        {"jridgewell-sourcemap-codec.package.json", "app/node_modules/@jridgewell/sourcemap-codec/package.json",
         "@jridgewell/sourcemap-codec", 1, "@jridgewell/sourcemap-codec", "1.6.0"},
        {"babel-helper-string-parser.package.json",
         "app/node_modules/@babel/helper-string-parser/package.json", "@babel/helper-string-parser", 1,
         "@babel/helper-string-parser", "7.29.15"},
    };
    for (const auto& r : rows) {
        INFO(r.file);
        const auto text = read_fixture(r.file);
        const auto meta = parse_package_json(text);
        REQUIRE(meta.has_value());
        CHECK(meta->name == r.name);
        CHECK(meta->version == r.version);

        const auto np = node_package_from_path(r.path);
        REQUIRE(np.has_value());
        CHECK(np->dir_name == r.dir_name);
        CHECK(np->nesting == r.nesting);

        const auto c = node_component(r.path, text);
        CHECK(c.name == r.name);
        CHECK(c.version == r.version);
        CHECK(c.version_source == NodeVersionSource::package_json);
    }
}

TEST_CASE("node: package paths", "[runtime][component_inventory][node]") {
    SECTION("scoped and unscoped") {
        const auto a = node_package_from_path("/srv/app/node_modules/@scope/name/package.json");
        REQUIRE(a.has_value());
        CHECK(a->dir_name == "@scope/name");
        CHECK(a->nesting == 1);
        const auto b = node_package_from_path("/srv/app/node_modules/left-pad/package.json");
        REQUIRE(b.has_value());
        CHECK(b->dir_name == "left-pad");
    }
    SECTION("nesting counts node_modules components") {
        const auto n = node_package_from_path("a/node_modules/b/node_modules/c/package.json");
        REQUIRE(n.has_value());
        CHECK(n->dir_name == "c");
        CHECK(n->nesting == 2);
        const auto s = node_package_from_path("a/node_modules/b/node_modules/@s/c/package.json");
        REQUIRE(s.has_value());
        CHECK(s->dir_name == "@s/c");
        CHECK(s->nesting == 2);
    }
    SECTION("everything else is not a package path") {
        for (const std::string_view p : {
                 "app/package.json",
                 "package.json",
                 "/package.json",
                 "",
                 "node_modules/package.json",
                 "node_modules/pkg/lib/package.json",
                 "node_modules/pkg/package.json.bak",
                 "node_modules/pkg/Package.json",
                 "node_modules/@scope/package.json",
                 "node_modules/.bin/package.json",
                 "node_modules/.cache/package.json",
                 "node_modules/@scope/.hidden/package.json",
                 "node_modules/@/pkg/package.json",
                 "node_modules/node_modules/package.json",
                 "x/node_modules/a/b/package.json",
                 "node_modules/@s/a/b/package.json",
             }) {
            INFO(p);
            CHECK_FALSE(node_package_from_path(p).has_value());
        }
    }
}

TEST_CASE("node: walk pruning", "[runtime][component_inventory][node]") {
    // Inside a package: never listed.
    CHECK(node_dir_prunable("x/node_modules/pkg/src"));
    CHECK(node_dir_prunable("x/node_modules/pkg/lib"));
    CHECK(node_dir_prunable("x/node_modules/pkg/dist"));
    CHECK(node_dir_prunable("x/node_modules/@scope/name/src"));
    CHECK(node_dir_prunable("x/node_modules/.bin"));
    CHECK(node_dir_prunable("x/node_modules/pkg/.bin"));
    // The walk must still reach these.
    CHECK_FALSE(node_dir_prunable("x/node_modules/pkg/node_modules"));
    CHECK_FALSE(node_dir_prunable("x/node_modules/@scope/name/node_modules"));
    CHECK_FALSE(node_dir_prunable("x/node_modules"));
    CHECK_FALSE(node_dir_prunable("x/node_modules/pkg"));
    CHECK_FALSE(node_dir_prunable("x/node_modules/@scope"));
    CHECK_FALSE(node_dir_prunable("x/node_modules/@scope/name"));
    CHECK_FALSE(node_dir_prunable("x/node_modules/pkg/node_modules/inner"));
    CHECK_FALSE(node_dir_prunable("x/src"));
    CHECK_FALSE(node_dir_prunable(""));

    // Depth cap.
    const auto at = [](std::size_t n) {
        std::string p = "app";
        for (std::size_t i = 0; i < n; ++i)
            p += "/node_modules/p" + std::to_string(i);
        return p;
    };
    CHECK_FALSE(node_dir_prunable(at(8)));
    CHECK(node_dir_prunable(at(9)));
    CHECK(node_dir_prunable(at(9) + "/node_modules"));
    CHECK_FALSE(node_dir_prunable(at(7) + "/node_modules"));
}

TEST_CASE("node: package.json defects", "[runtime][component_inventory][node]") {
    const auto defect = [](std::string_view t) {
        const auto r = parse_package_json(t);
        REQUIRE_FALSE(r.has_value());
        return r.error();
    };
    CHECK(defect("[]") == NodeDefect::not_object);
    CHECK(defect(R"("pkg")") == NodeDefect::not_object);
    CHECK(defect("42") == NodeDefect::not_object);
    CHECK(defect("null") == NodeDefect::not_object);
    CHECK(defect(R"({"name":"a","version":"1")") == NodeDefect::not_json);
    CHECK(defect("") == NodeDefect::not_json);
    CHECK(defect("not json") == NodeDefect::not_json);
    CHECK(defect(R"({"name":"a"} trailing)") == NodeDefect::not_json);
    CHECK(defect(std::string(1, '\xff')) == NodeDefect::not_json);

    SECTION("size cap is exact") {
        const std::string pad = R"({"name":"a","pad":")";
        std::string ok = pad + std::string(kMaxPackageJsonBytes - pad.size() - 2, 'x') + "\"}";
        REQUIRE(ok.size() == kMaxPackageJsonBytes);
        CHECK(parse_package_json(ok).has_value());
        ok.insert(ok.size() - 2, "x");
        REQUIRE(ok.size() == kMaxPackageJsonBytes + 1);
        CHECK(defect(ok) == NodeDefect::oversized);
        CHECK(defect(std::string(kMaxPackageJsonBytes + 1, ' ')) == NodeDefect::oversized);
    }

    SECTION("depth cap") {
        CHECK(parse_package_json(nested('[', ']', 64)).error() == NodeDefect::not_object);
        CHECK(defect(nested('[', ']', 65)) == NodeDefect::too_deep);
        CHECK(defect(nested('[', ']', 1000)) == NodeDefect::too_deep);
        // A top-level object counts as one level.
        const auto in_object = [](int arrays) { return R"({"x":)" + nested('[', ']', arrays) + "}"; };
        CHECK(parse_package_json(in_object(63)).has_value());
        CHECK(defect(in_object(64)) == NodeDefect::too_deep);
        // Objects count the same way.
        std::string objs = R"({"name":"a","k":)";
        for (int i = 0; i < 70; ++i)
            objs += R"({"k":)";
        objs += "1" + std::string(71, '}');
        CHECK(defect(objs) == NodeDefect::too_deep);
    }

    SECTION("too_deep is decided by the flag, not by what the parse keeps") {
        // The over-deep value sits under an unrelated key; name and version are intact and the
        // discarded value leaves a valid object behind, but the document is still too_deep.
        const std::string doc = R"({"name":"a","version":"1.0.0","dependencies":)" + nested('[', ']', 100) + "}";
        CHECK(defect(doc) == NodeDefect::too_deep);
        // Over-deep and otherwise malformed: still too_deep.
        CHECK(defect(nested('[', ']', 100) + "]") == NodeDefect::too_deep);
        // Deep and unterminated: the flag is set before the parse fails.
        CHECK(defect(std::string(100, '[')) == NodeDefect::too_deep);
    }

    SECTION("a deep text inside a string is not depth") {
        const std::string doc = R"({"name":"a","version":"1","description":")" + std::string(200, '[') + R"("})";
        const auto r = parse_package_json(doc);
        REQUIRE(r.has_value());
        CHECK(r->name == "a");
    }
}

TEST_CASE("node: name and version rules", "[runtime][component_inventory][node]") {
    const auto meta = [](std::string_view t) {
        const auto r = parse_package_json(t);
        REQUIRE(r.has_value());
        return *r;
    };
    CHECK(meta(R"({"name":"a","version":"1.2.3"})").version == "1.2.3");
    CHECK(meta("{}").name.empty());
    CHECK(meta("{}").version.empty());
    // Only strings count.
    CHECK(meta(R"({"name":"a","version":1.5})").version.empty());
    CHECK(meta(R"({"name":"a","version":1})").version.empty());
    CHECK(meta(R"({"name":"a","version":null})").version.empty());
    CHECK(meta(R"({"name":"a","version":["1.0.0"]})").version.empty());
    CHECK(meta(R"({"name":7,"version":"1"})").name.empty());
    // Other keys are never read.
    CHECK(meta(R"({"dependencies":{"name":"x","version":"9"}})").name.empty());
    // Control bytes (escaped, as JSON requires) drop the field.
    CHECK(meta(R"({"name":"a\u0001b","version":"1"})").name.empty());
    CHECK(meta(R"({"name":"a","version":"1\n2"})").version.empty());
    CHECK(meta(R"({"name":"a\u007fb"})").name.empty());
    CHECK(meta(R"({"name":"a\u0000b"})").name.empty());
    // Length caps.
    CHECK(meta(R"({"name":")" + std::string(kMaxNodeNameBytes, 'n') + R"("})").name.size() == kMaxNodeNameBytes);
    CHECK(meta(R"({"name":")" + std::string(kMaxNodeNameBytes + 1, 'n') + R"("})").name.empty());
    CHECK(meta(R"({"version":")" + std::string(kMaxNodeVersionBytes, '1') + R"("})").version.size() ==
          kMaxNodeVersionBytes);
    CHECK(meta(R"({"version":")" + std::string(kMaxNodeVersionBytes + 1, '1') + R"("})").version.empty());
    // Non-ASCII UTF-8 is kept; the last duplicate key wins.
    CHECK(meta("{\"name\":\"caf\xc3\xa9\"}").name == "caf\xc3\xa9");
    CHECK(meta(R"({"name":"first","name":"second"})").name == "second");
}

TEST_CASE("node: component outcome", "[runtime][component_inventory][node]") {
    const std::string path = "app/node_modules/@scope/dir-name/package.json";
    SECTION("declared name wins") {
        const auto c = node_component(path, std::string{R"({"name":"declared","version":"2.0.0"})"});
        CHECK(c.name == "declared");
        CHECK(c.version == "2.0.0");
        CHECK(c.version_source == NodeVersionSource::package_json);
    }
    SECTION("absent, empty or control-byte name falls back to the directory name") {
        for (const char* doc : {R"({"version":"1.0.0"})", R"({"name":"","version":"1.0.0"})",
                                R"({"name":"a\u0001b","version":"1.0.0"})", R"({"name":5,"version":"1.0.0"})"}) {
            INFO(doc);
            const auto c = node_component(path, std::string{doc});
            CHECK(c.name == "@scope/dir-name");
            CHECK(c.version == "1.0.0");
            CHECK(c.version_source == NodeVersionSource::package_json);
        }
    }
    SECTION("a numeric version is empty, not a defect") {
        const auto c = node_component(path, std::string{R"({"name":"a","version":1})"});
        CHECK(c.name == "a");
        CHECK(c.version.empty());
        CHECK(c.version_source == NodeVersionSource::package_json);
    }
    SECTION("unreadable file or any defect gives the directory name and no version") {
        const std::string deep = nested('[', ']', 100);
        const std::string big(kMaxPackageJsonBytes + 1, ' ');
        const std::optional<std::string> cases[] = {std::nullopt, std::string{"[]"}, std::string{"{"}, deep, big};
        for (const auto& text : cases) {
            const auto c = node_component(path, text);
            CHECK(c.name == "@scope/dir-name");
            CHECK(c.version.empty());
            CHECK(c.version_source == NodeVersionSource::unreadable);
        }
    }
    CHECK(to_token(NodeVersionSource::package_json) == "package_json");
    CHECK(to_token(NodeVersionSource::unreadable) == "unreadable");
}

TEST_CASE("node: no input throws", "[runtime][component_inventory][node]") {
    std::vector<std::string> corpus = {
        "",
        "{",
        "}",
        "[",
        "{\"name\":",
        "{\"name\":\"\\u12\"}",
        "{\"name\":\"\\ud800\"}",
        "{\"name\":\"a\xc3\"}",
        "{\"name\":\"a\x01\"}",
        std::string("{\"name\":\"a\0b\"}", 14),
        std::string(1, '\0'),
        "\xef\xbb\xbf{\"name\":\"bom\"}",
        "{\"name\":1e999999,\"version\":-}",
        "{'name':'a'}",
        "{\"name\":\"a\",}",
        "// c\n{}",
        "{\"a\":" + nested('[', ']', 5000) + "}",
        nested('{', '}', 5000),
        std::string(30000, '['),
        std::string(kMaxPackageJsonBytes + 1, '{'),
        std::string(kMaxPackageJsonBytes, '"'),
        read_fixture("semver.package.json").substr(0, 100),
    };
    for (std::size_t i = 0; i < 256; ++i)
        corpus.push_back(std::string("{\"name\":\"") + static_cast<char>(i) + "\",\"version\":\"1\"}");
    for (const auto& t : corpus) {
        CHECK_NOTHROW(parse_package_json(t));
        CHECK_NOTHROW(node_component("a/node_modules/b/package.json", t));
    }
    const std::vector<std::string_view> paths = {"",
                                                 "/",
                                                 "//",
                                                 "node_modules",
                                                 "node_modules/",
                                                 "/node_modules//x//package.json",
                                                 "@/@/@",
                                                 "a/node_modules/@/package.json",
                                                 std::string_view{"a\0b", 3}};
    for (const auto p : paths) {
        CHECK_NOTHROW(node_package_from_path(p));
        CHECK_NOTHROW(node_dir_prunable(p));
    }
}
