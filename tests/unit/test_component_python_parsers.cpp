/**
 * test_component_python_parsers.cpp — pure Python distribution metadata parsers
 * (component_python_parsers.hpp). Fixtures are real METADATA / PKG-INFO files
 * (tests/unit/fixtures/software-estate/components/python/, see provenance.txt).
 */

#include "component_python_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

#ifndef YUZU_TEST_FIXTURE_DIR
#define YUZU_TEST_FIXTURE_DIR "tests/unit/fixtures"
#endif

using namespace std::string_view_literals;
using namespace yuzu::component_inventory;
namespace fs = std::filesystem;

namespace {
std::string read_fixture(const char* name) {
    const auto p = fs::path{YUZU_TEST_FIXTURE_DIR} / "software-estate" / "components" / "python" / name;
    std::ifstream in(p, std::ios::binary);
    REQUIRE(in.good());
    std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (s.size() > kMaxPythonMetadataBytes)
        s.resize(kMaxPythonMetadataBytes);
    return s;
}
} // namespace

TEST_CASE("python metadata: real fixtures yield their name and version",
          "[runtime][component_inventory][python]") {
    struct Row {
        const char* file;
        const char* name;
        const char* version;
    };
    const Row rows[] = {
        {"venv-pip-25.0.1.METADATA", "pip", "25.0.1"},
        {"debian-setuptools-66.1.1.PKG-INFO", "setuptools", "66.1.1"},
        {"debian-six-1.16.0.PKG-INFO", "six", "1.16.0"},
    };
    for (const auto& r : rows) {
        const auto d = parse_python_metadata(read_fixture(r.file));
        REQUIRE(d.has_value());
        CHECK(d->name == r.name);
        CHECK(d->version == r.version);
    }
}

TEST_CASE("python metadata: headers only, first Name/Version, either line end",
          "[runtime][component_inventory][python]") {
    // A Version: in the body is never read.
    CHECK_FALSE(parse_python_metadata("Name: a\n\nVersion: 1.0\n"sv).has_value());
    // First occurrence wins; field names are case-insensitive; continuation ignored.
    auto d = parse_python_metadata("NAME: Foo_Bar\nVersion: 1.0\n  Version: 9\nversion: 2\n\nbody"sv);
    REQUIRE(d);
    CHECK(d->name == "Foo_Bar");
    CHECK(d->version == "1.0");
    d = parse_python_metadata("Name: a\r\nVersion:  2.0 \r\n\r\nbody"sv);
    REQUIRE(d);
    CHECK(d->name == "a");
    CHECK(d->version == "2.0");
    // The first Name: wins over a later one, as the first Version: does.
    d = parse_python_metadata("Name: first\nName: second\nVersion: 1\n"sv);
    REQUIRE(d);
    CHECK(d->name == "first");
    // Missing either field.
    CHECK_FALSE(parse_python_metadata("Name: a\n"sv).has_value());
    CHECK_FALSE(parse_python_metadata("Version: 1\n"sv).has_value());
    CHECK_FALSE(parse_python_metadata(""sv).has_value());
}

TEST_CASE("python metadata: a head that ends mid-line is bounded",
          "[runtime][component_inventory][python]") {
    CHECK(parse_python_metadata("Name: a\nVersion: 1.0\nSummary: tru"sv).has_value());
    const auto d = parse_python_metadata("Name: a\nVersion: 1."sv);
    REQUIRE(d);
    CHECK(d->version == "1.");
    // A buffer larger than the cap is clamped, never read past.
    std::string big = "Name: a\nSummary: ";
    big.append(kMaxPythonMetadataBytes, 'x');
    big += "\nVersion: 1.0\n";
    CHECK_FALSE(parse_python_metadata(big).has_value());
    // Mid-line cut inside the Version header.
    std::string cut = "Name: a\nVersion: 1.0";
    CHECK(parse_python_metadata(cut)->version == "1.0");
}

TEST_CASE("python metadata: the bounds are pinned by literal value", "[runtime][component_inventory][python]") {
    CHECK(kMaxPythonMetadataBytes == 16384);
    CHECK(kMaxPythonNameBytes == 256);
    CHECK(kMaxPythonVersionBytes == 128);
}

TEST_CASE("python metadata: a header line cut by the read cap is never taken as complete",
          "[runtime][component_inventory][python]") {
    // A head of exactly the cap whose last line has no newline ends inside that line.
    const auto head_of = [](std::size_t total, std::string_view prefix, std::string_view tail) {
        std::string s{prefix};
        s.append(total - prefix.size() - tail.size(), 'x');
        s += tail;
        REQUIRE(s.size() == total);
        return s;
    };
    const auto head_ending = [&head_of](std::string_view prefix, std::string_view tail) {
        return head_of(16384, prefix, tail);
    };
    // "Version: 1.2" is the front of a declared 1.2.3.4.5: no version, so the directory name speaks.
    const auto cut_version = head_ending("Name: a\nSummary: ", "\nVersion: 1.2");
    CHECK_FALSE(parse_python_metadata(cut_version).has_value());
    const auto c = python_component("/sp/a-1.2.3.4.5.dist-info/METADATA"sv, cut_version);
    CHECK(c.version == "1.2.3.4.5");
    CHECK(c.version_source == "filename");
    // The same for a Name: header cut short.
    CHECK_FALSE(parse_python_metadata(head_ending("Version: 1.0\nSummary: ", "\nName: ab")).has_value());
    // A buffer larger than the cap is clamped to it and is cut the same way.
    std::string big = head_ending("Name: a\nSummary: ", "\nVersion: 1.2");
    big += ".3.4.5\n\nbody";
    CHECK_FALSE(parse_python_metadata(big).has_value());

    // Controls: a newline-terminated final line, or a head shorter than the cap, is complete.
    CHECK(parse_python_metadata(head_ending("Name: a\nSummary: ", "\nVersion: 1.2\n"))->version == "1.2");
    CHECK(parse_python_metadata("Name: a\nVersion: 1.2"sv)->version == "1.2"); // a short file may end there
    CHECK(parse_python_metadata(head_of(16383, "Name: a\nSummary: ", "\nVersion: 1.2"))->version == "1.2");
}

TEST_CASE("python metadata: bad values are rejected", "[runtime][component_inventory][python]") {
    CHECK_FALSE(parse_python_metadata(std::string("Name: a\0b\nVersion: 1\n", 21)).has_value());
    CHECK_FALSE(parse_python_metadata("Name: a\nVersion: \t\n"sv).has_value());
    CHECK_FALSE(parse_python_metadata("Name: a\nVersion: 1\x1f\n"sv).has_value());
    CHECK_FALSE(parse_python_metadata("Name:\nVersion: 1\n"sv).has_value());
    CHECK_FALSE(parse_python_metadata("Name: " + std::string(257, 'n') + "\nVersion: 1\n").has_value());
    CHECK(parse_python_metadata("Name: " + std::string(256, 'n') + "\nVersion: 1\n").has_value());
    CHECK_FALSE(parse_python_metadata("Name: a\nVersion: " + std::string(129, '1') + "\n").has_value());
    CHECK(parse_python_metadata("Name: a\nVersion: " + std::string(128, '1') + "\n").has_value());
}

TEST_CASE("python dist directory names", "[runtime][component_inventory][python]") {
    struct Row {
        const char* dir;
        const char* name;
        const char* version;
    };
    const Row ok[] = {
        {"foo-1.0.dist-info", "foo", "1.0"},
        {"foo_bar-2.3.4-py3.11.egg-info", "foo_bar", "2.3.4"},
        {"foo-1.0.egg-info", "foo", "1.0"},
        {"six-1.16.0.egg-info", "six", "1.16.0"},
        {"zope-interface-5.0.dist-info", "zope-interface", "5.0"},
    };
    for (const auto& r : ok) {
        const auto d = python_dist_from_dir(r.dir);
        REQUIRE(d.has_value());
        CHECK(d->name == r.name);
        CHECK(d->version == r.version);
    }
    for (const auto* bad : {"dist-info", "-1.0.dist-info", "foo.dist-info", "foo-1.0", "foo-.dist-info", ""})
        CHECK_FALSE(python_dist_from_dir(bad).has_value());
}

TEST_CASE("python metadata leaf and owner", "[runtime][component_inventory][python]") {
    CHECK(is_python_metadata_leaf("METADATA"));
    CHECK(is_python_metadata_leaf("PKG-INFO"));
    CHECK(is_python_metadata_leaf("foo-1.0.egg-info"));
    CHECK_FALSE(is_python_metadata_leaf("metadata"));
    CHECK_FALSE(is_python_metadata_leaf("METADATA.json"));
    CHECK_FALSE(is_python_metadata_leaf("foo.dist-info"));

    CHECK(python_metadata_owner("/x/site-packages/foo-1.0.dist-info/METADATA") == "foo-1.0.dist-info"sv);
    CHECK(python_metadata_owner("/x/foo-1.0.egg-info/PKG-INFO") == "foo-1.0.egg-info"sv);
    CHECK(python_metadata_owner("/x/foo-1.0.egg-info") == "foo-1.0.egg-info"sv);
    CHECK(python_metadata_owner("C:\\x\\foo-1.0.dist-info\\METADATA") == "foo-1.0.dist-info"sv);
    CHECK_FALSE(python_metadata_owner("/x/other/METADATA").has_value());
    CHECK_FALSE(python_metadata_owner("/x/foo-1.0.egg-info/METADATA").has_value());
    CHECK_FALSE(python_metadata_owner("/x/foo-1.0.dist-info/PKG-INFO").has_value());
    CHECK_FALSE(python_metadata_owner("METADATA").has_value());
}

TEST_CASE("python component: metadata, filename, unreadable", "[runtime][component_inventory][python]") {
    const auto p = "/sp/Foo_Bar-1.0.dist-info/METADATA"sv;
    auto c = python_component(p, "Name: Foo.Bar\nVersion: 1.0.post1\n"sv);
    CHECK(c.name == "Foo.Bar"); // declared name, not normalised
    CHECK(c.version == "1.0.post1");
    CHECK(c.version_source == "metadata");

    c = python_component(p, std::nullopt);
    CHECK(c.name == "Foo_Bar");
    CHECK(c.version == "1.0");
    CHECK(c.version_source == "filename");

    c = python_component(p, "Name: only\n"sv);
    CHECK(c.version_source == "filename");

    c = python_component("/sp/weird.dist-info/METADATA"sv, std::nullopt);
    CHECK(c.name == "weird.dist-info");
    CHECK(c.version.empty());
    CHECK(c.version_source == "unreadable");

    c = python_component("/sp/other/METADATA"sv, std::nullopt);
    CHECK(c.name == "METADATA");
    CHECK(c.version_source == "unreadable");
}
