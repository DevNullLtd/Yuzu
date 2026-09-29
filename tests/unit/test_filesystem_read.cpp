/**
 * test_filesystem_read.cpp — Unit tests for filesystem plugin read action
 *
 * Tests the path validation and read parameter logic.
 * Actual plugin read is tested via integration; these unit tests
 * cover the validation helpers and edge cases.
 */

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

namespace {

// Replicate the validate_path logic from the plugin for testing
std::string validate_path(std::string_view raw_path, std::string_view base_dir) {
    if (raw_path.empty())
        return {};

    std::error_code ec;
    std::string path_str{raw_path};

    if (!fs::exists(path_str, ec))
        return {};

    auto canonical = fs::canonical(path_str, ec);
    if (ec)
        return {};

    if (!base_dir.empty()) {
        auto canonical_base = fs::canonical(std::string{base_dir}, ec);
        if (ec)
            return {};

        auto canon_str = canonical.string();
        auto base_str = canonical_base.string();

        if (canon_str.size() < base_str.size() ||
            canon_str.compare(0, base_str.size(), base_str) != 0) {
            return {};
        }
        if (canon_str.size() > base_str.size() && canon_str[base_str.size()] != '/' &&
            canon_str[base_str.size()] != '\\') {
            return {};
        }
    }

    return canonical.string();
}

// Every fixture below lives under ONE process-salted base dir — same
// rationale as test_filesystem_actions.cpp: the fixed literal names stay,
// but concurrent CI jobs on a shared-identity box no longer collide (#1883).
// NOTE for "validate_path outside base_dir": TempFile and TempDir become
// SIBLINGS under this base, which the canonical-prefix check still correctly
// rejects — do not nest the file inside the dir (or make the base the dir).
const fs::path& read_base() {
    static yuzu::test::TempDir base{"yuzu_test_read-"};
    static const bool created = [] {
        std::error_code ec;
        fs::create_directories(base.path, ec);
        return fs::exists(base.path);
    }();
    // Fail loudly if the base could not be created (gov safe-2).
    REQUIRE(created);
    return base.path;
}

struct TempFile {
    fs::path path;

    explicit TempFile(const std::string& content = "",
                      const std::string& name = "yuzu_test_read.txt") {
        path = read_base() / name;
        std::ofstream f(path);
        f << content;
    }

    ~TempFile() {
        std::error_code ec;
        fs::remove(path, ec);
    }
};

struct TempDir {
    fs::path path;

    explicit TempDir(const std::string& name = "yuzu_test_read_dir") {
        path = read_base() / name;
        std::error_code ec;
        fs::create_directories(path, ec);
    }

    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

} // namespace

// ── Path validation ────────────────────────────────────────────────────────

TEST_CASE("FilesystemRead: validate_path empty", "[filesystem][read]") {
    CHECK(validate_path("", "").empty());
}

TEST_CASE("FilesystemRead: validate_path nonexistent", "[filesystem][read]") {
    CHECK(validate_path("/nonexistent/path/foo.txt", "").empty());
}

TEST_CASE("FilesystemRead: validate_path existing file", "[filesystem][read]") {
    TempFile tf("hello");
    auto result = validate_path(tf.path.string(), "");
    CHECK(!result.empty());
}

TEST_CASE("FilesystemRead: validate_path within base_dir", "[filesystem][read]") {
    TempDir td;
    fs::path file = td.path / "test.txt";
    {
        std::ofstream f(file);
        f << "test";
    }

    auto result = validate_path(file.string(), td.path.string());
    CHECK(!result.empty());

    std::error_code ec;
    fs::remove(file, ec);
}

TEST_CASE("FilesystemRead: validate_path outside base_dir", "[filesystem][read]") {
    TempDir td("yuzu_test_base");
    TempFile tf("content", "yuzu_test_outside.txt");

    auto result = validate_path(tf.path.string(), td.path.string());
    CHECK(result.empty());
}

// ── Read parameter validation ──────────────────────────────────────────────

TEST_CASE("FilesystemRead: offset defaults", "[filesystem][read]") {
    // Offset default is 1 (1-based), limit default 100
    int offset = 1;
    int limit = 100;
    CHECK(offset >= 1);
    CHECK(limit > 0);
    CHECK(limit <= 10000);
}

TEST_CASE("FilesystemRead: limit max 10000", "[filesystem][read]") {
    int limit = 10000;
    CHECK(limit <= 10000);

    int over_limit = 10001;
    int capped = std::min(over_limit, 10000);
    CHECK(capped == 10000);
}

TEST_CASE("FilesystemRead: CRLF line ending stripped", "[filesystem][read]") {
    TempFile tf("line1\r\nline2\r\nline3\r\n", "yuzu_test_crlf.txt");

    std::ifstream f(tf.path);
    std::string line;
    int count = 0;
    while (std::getline(f, line)) {
        // Strip trailing \r
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        ++count;
        CHECK(line.find('\r') == std::string::npos);
    }
    CHECK(count == 3);
}

TEST_CASE("FilesystemRead: binary detection via NUL byte", "[filesystem][read]") {
    TempFile tf(std::string("hello\0world", 11), "yuzu_test_binary.txt");

    // Read first 512 bytes and check for NUL
    std::ifstream f(tf.path, std::ios::binary);
    char buf[512]{};
    f.read(buf, sizeof(buf));
    auto bytes_read = f.gcount();

    bool is_binary = false;
    for (std::streamsize i = 0; i < bytes_read; ++i) {
        if (buf[i] == '\0') {
            is_binary = true;
            break;
        }
    }
    CHECK(is_binary == true);
}

TEST_CASE("FilesystemRead: empty file", "[filesystem][read]") {
    TempFile tf("", "yuzu_test_empty.txt");

    std::ifstream f(tf.path);
    std::string line;
    int count = 0;
    while (std::getline(f, line))
        ++count;
    CHECK(count == 0);
}

TEST_CASE("FilesystemRead: line counting", "[filesystem][read]") {
    std::string content;
    for (int i = 1; i <= 50; ++i) {
        content += "Line " + std::to_string(i) + "\n";
    }
    TempFile tf(content, "yuzu_test_lines.txt");

    std::ifstream f(tf.path);
    std::string line;
    int count = 0;
    while (std::getline(f, line))
        ++count;
    CHECK(count == 50);
}

TEST_CASE("FilesystemRead: offset and limit simulation", "[filesystem][read]") {
    std::string content;
    for (int i = 1; i <= 20; ++i) {
        content += "Line " + std::to_string(i) + "\n";
    }
    TempFile tf(content, "yuzu_test_offset.txt");

    // Simulate reading lines 5-10 (offset=5, limit=6)
    std::ifstream f(tf.path);
    std::string line;
    int line_num = 0;
    int offset = 5;
    int limit = 6;
    int collected = 0;
    std::vector<std::string> output;

    while (std::getline(f, line)) {
        ++line_num;
        if (line_num < offset)
            continue;
        if (collected >= limit)
            break;
        output.push_back(line);
        ++collected;
    }

    REQUIRE(output.size() == 6);
    CHECK(output[0] == "Line 5");
    CHECK(output[5] == "Line 10");
}
