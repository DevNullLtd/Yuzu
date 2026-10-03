// Tests for yuzu::server::read_secret_file (server/core/src/secret_file.hpp),
// behind --postgres-dsn-file and --oidc-client-secret-file (#5272).

#include "secret_file.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>

using yuzu::server::kMaxSecretFileBytes;
using yuzu::server::read_secret_file;

namespace {

std::filesystem::path write_file(const yuzu::test::TempDir& dir, const std::string& name,
                                 const std::string& bytes) {
    std::filesystem::create_directories(dir.path);
    const auto p = dir.path / name;
    std::ofstream out(p, std::ios::binary);
    out << bytes;
    return p;
}

} // namespace

TEST_CASE("read_secret_file: returns the secret, trimming a final newline and a BOM",
          "[secret_file]") {
    yuzu::test::TempDir dir("yuzu_test_secret_");

    SECTION("plain") {
        auto r = read_secret_file(write_file(dir, "a", "host=db user=yuzu password=x"), "--f");
        REQUIRE(r);
        CHECK(*r == "host=db user=yuzu password=x");
    }
    SECTION("trailing CRLF, LF and spaces are dropped") {
        auto r = read_secret_file(write_file(dir, "b", "postgres://u:p@h/d \r\n\n"), "--f");
        REQUIRE(r);
        CHECK(*r == "postgres://u:p@h/d");
    }
    SECTION("a UTF-8 byte-order mark is dropped") {
        auto r = read_secret_file(write_file(dir, "c", "\xEF\xBB\xBFsecret\r\n"), "--f");
        REQUIRE(r);
        CHECK(*r == "secret");
    }
    SECTION("interior bytes, including spaces, colons and backslashes, are kept") {
        const std::string s = "host=h password='a b:c\\d'";
        auto r = read_secret_file(write_file(dir, "d", s + "\n"), "--f");
        REQUIRE(r);
        CHECK(*r == s);
    }
    SECTION("leading whitespace is kept (only trailing whitespace is trimmed)") {
        auto r = read_secret_file(write_file(dir, "e", "  x"), "--f");
        REQUIRE(r);
        CHECK(*r == "  x");
    }
}

TEST_CASE("read_secret_file: refuses, naming the flag and file but not the contents",
          "[secret_file]") {
    yuzu::test::TempDir dir("yuzu_test_secret_");

    SECTION("missing file") {
        std::filesystem::create_directories(dir.path);
        auto r = read_secret_file(dir.path / "nope", "--postgres-dsn-file");
        REQUIRE_FALSE(r);
        CHECK(r.error().find("--postgres-dsn-file") != std::string::npos);
        CHECK(r.error().find("does not exist") != std::string::npos);
    }
    SECTION("empty, or only whitespace") {
        auto r = read_secret_file(write_file(dir, "e", " \r\n\t"), "--f");
        REQUIRE_FALSE(r);
        CHECK(r.error().find("empty") != std::string::npos);
        auto r2 = read_secret_file(write_file(dir, "e2", "\xEF\xBB\xBF\n"), "--f");
        REQUIRE_FALSE(r2);
    }
    SECTION("a directory") {
        std::filesystem::create_directories(dir.path / "sub");
        auto r = read_secret_file(dir.path / "sub", "--f");
        REQUIRE_FALSE(r);
        CHECK(r.error().find("not a regular file") != std::string::npos);
    }
    SECTION("larger than the cap") {
        auto r = read_secret_file(write_file(dir, "big", std::string(kMaxSecretFileBytes + 1, 'x')),
                                  "--f");
        REQUIRE_FALSE(r);
        CHECK(r.error().find("larger than") != std::string::npos);
    }
    SECTION("exactly the cap is accepted") {
        auto r =
            read_secret_file(write_file(dir, "max", std::string(kMaxSecretFileBytes, 'y')), "--f");
        REQUIRE(r);
        CHECK(r->size() == kMaxSecretFileBytes);
    }
    SECTION("the error never contains the secret") {
        auto r = read_secret_file(write_file(dir, "s", std::string(kMaxSecretFileBytes + 1, 'Q')),
                                  "--f");
        REQUIRE_FALSE(r);
        CHECK(r.error().find("QQQQ") == std::string::npos);
    }
}
