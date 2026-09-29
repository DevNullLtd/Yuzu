#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;

// ── C ABI: yuzu_create_temp_file ────────────────────────────────────────────

TEST_CASE("create_temp_file returns 0 and creates a file", "[temp_file]") {
    char path[512]{};
    int rc = yuzu_create_temp_file(nullptr, nullptr, nullptr, path, sizeof(path));
    REQUIRE(rc == 0);
    REQUIRE(path[0] != '\0');

    fs::path p(path);
    REQUIRE(fs::exists(p));
    REQUIRE(fs::is_regular_file(p));

    // Cleanup
    fs::remove(p);
}

TEST_CASE("create_temp_file respects prefix and suffix", "[temp_file]") {
    char path[512]{};
    int rc = yuzu_create_temp_file("test-pfx-", ".dat", nullptr, path, sizeof(path));
    REQUIRE(rc == 0);

    fs::path p(path);
    REQUIRE(fs::exists(p));

    std::string filename = p.filename().string();
    REQUIRE(filename.starts_with("test-pfx-"));
    REQUIRE(filename.ends_with(".dat"));

    fs::remove(p);
}

TEST_CASE("create_temp_file respects custom directory", "[temp_file]") {
    // Process-salted scratch dir: the old fixed yuzu_test_custom_dir was
    // shared cross-job on the shared-identity CI pools — another job's
    // cleanup remove_all could delete this job's just-created file between
    // the create and the checks below (#1883). Fully qualified: this file
    // also exercises the PRODUCT yuzu::TempFile / yuzu::TempDir classes, so
    // never add `using namespace yuzu::test` here.
    yuzu::test::TempDir custom_dir{"yuzu_test_custom_dir-"};
    fs::create_directories(custom_dir.path);

    char path[512]{};
    int rc = yuzu_create_temp_file("custom-", ".tmp", custom_dir.path.string().c_str(), path,
                                   sizeof(path));
    REQUIRE(rc == 0);

    fs::path p(path);
    REQUIRE(fs::exists(p));
    REQUIRE(fs::canonical(p.parent_path()) == fs::canonical(custom_dir.path));

    fs::remove(p);
}

TEST_CASE("create_temp_file creates unique files", "[temp_file]") {
    char path1[512]{};
    char path2[512]{};

    REQUIRE(yuzu_create_temp_file(nullptr, nullptr, nullptr, path1, sizeof(path1)) == 0);
    REQUIRE(yuzu_create_temp_file(nullptr, nullptr, nullptr, path2, sizeof(path2)) == 0);

    REQUIRE(std::string(path1) != std::string(path2));

    fs::remove(path1);
    fs::remove(path2);
}

TEST_CASE("create_temp_file fails with null path_out", "[temp_file]") {
    REQUIRE(yuzu_create_temp_file(nullptr, nullptr, nullptr, nullptr, 0) != 0);
}

TEST_CASE("create_temp_file fails with buffer too small", "[temp_file]") {
    char path[2]{};
    REQUIRE(yuzu_create_temp_file(nullptr, nullptr, nullptr, path, sizeof(path)) != 0);
}

TEST_CASE("create_temp_file fails with nonexistent directory", "[temp_file]") {
    char path[512]{};
    REQUIRE(yuzu_create_temp_file(nullptr, nullptr, "/nonexistent/dir/xyz", path, sizeof(path)) !=
            0);
}

#ifndef _WIN32
TEST_CASE("create_temp_file sets restrictive permissions (POSIX)", "[temp_file]") {
    char path[512]{};
    REQUIRE(yuzu_create_temp_file(nullptr, nullptr, nullptr, path, sizeof(path)) == 0);

    struct stat st{};
    REQUIRE(stat(path, &st) == 0);
    // mkstemps creates with mode 0600
    REQUIRE((st.st_mode & 0777) == 0600);

    fs::remove(path);
}
#endif

// ── C ABI: yuzu_create_temp_dir ─────────────────────────────────────────────

TEST_CASE("create_temp_dir returns 0 and creates a directory", "[temp_dir]") {
    char path[512]{};
    int rc = yuzu_create_temp_dir(nullptr, nullptr, path, sizeof(path));
    REQUIRE(rc == 0);
    REQUIRE(path[0] != '\0');

    fs::path p(path);
    REQUIRE(fs::exists(p));
    REQUIRE(fs::is_directory(p));

    fs::remove(p);
}

TEST_CASE("create_temp_dir respects prefix", "[temp_dir]") {
    char path[512]{};
    int rc = yuzu_create_temp_dir("mydir-", nullptr, path, sizeof(path));
    REQUIRE(rc == 0);

    fs::path p(path);
    REQUIRE(fs::exists(p));
    REQUIRE(p.filename().string().starts_with("mydir-"));

    fs::remove(p);
}

TEST_CASE("create_temp_dir creates unique directories", "[temp_dir]") {
    char path1[512]{};
    char path2[512]{};

    REQUIRE(yuzu_create_temp_dir(nullptr, nullptr, path1, sizeof(path1)) == 0);
    REQUIRE(yuzu_create_temp_dir(nullptr, nullptr, path2, sizeof(path2)) == 0);

    REQUIRE(std::string(path1) != std::string(path2));

    fs::remove(path1);
    fs::remove(path2);
}

#ifndef _WIN32
TEST_CASE("create_temp_dir sets restrictive permissions (POSIX)", "[temp_dir]") {
    char path[512]{};
    REQUIRE(yuzu_create_temp_dir(nullptr, nullptr, path, sizeof(path)) == 0);

    struct stat st{};
    REQUIRE(stat(path, &st) == 0);
    // mkdtemp creates with mode 0700
    REQUIRE((st.st_mode & 0777) == 0700);

    fs::remove(path);
}
#endif

// ── C++ RAII: TempFile ──────────────────────────────────────────────────────

TEST_CASE("TempFile::create succeeds and file exists", "[temp_file][raii]") {
    auto result = yuzu::TempFile::create("raii-", ".tmp");
    REQUIRE(result.has_value());

    auto& tf = *result;
    REQUIRE(!tf.path().empty());
    REQUIRE(fs::exists(tf.path()));
}

TEST_CASE("TempFile destructor deletes non-persistent file", "[temp_file][raii]") {
    std::string saved_path;
    {
        auto result = yuzu::TempFile::create("del-", ".tmp");
        REQUIRE(result.has_value());
        saved_path = result->path();
        REQUIRE(fs::exists(saved_path));
    }
    // Destructor should have deleted it
    REQUIRE_FALSE(fs::exists(saved_path));
}

TEST_CASE("TempFile::release prevents deletion", "[temp_file][raii]") {
    std::string saved_path;
    {
        auto result = yuzu::TempFile::create("rel-", ".tmp");
        REQUIRE(result.has_value());
        result->release();
        saved_path = result->path();
    }
    REQUIRE(fs::exists(saved_path));
    fs::remove(saved_path);
}

TEST_CASE("TempFile persistent mode prevents deletion", "[temp_file][raii]") {
    std::string saved_path;
    {
        auto result = yuzu::TempFile::create("pers-", ".tmp", {}, true);
        REQUIRE(result.has_value());
        saved_path = result->path();
    }
    REQUIRE(fs::exists(saved_path));
    fs::remove(saved_path);
}

TEST_CASE("TempFile move constructor transfers ownership", "[temp_file][raii]") {
    auto result = yuzu::TempFile::create("mv-", ".tmp");
    REQUIRE(result.has_value());

    std::string original_path = result->path();
    yuzu::TempFile moved{std::move(*result)};

    REQUIRE(moved.path() == original_path);
    REQUIRE(result->path().empty());
    REQUIRE(fs::exists(original_path));
}

// ── C++ RAII: TempDir ───────────────────────────────────────────────────────

TEST_CASE("TempDir::create succeeds and directory exists", "[temp_dir][raii]") {
    auto result = yuzu::TempDir::create("raii-dir-");
    REQUIRE(result.has_value());

    auto& td = *result;
    REQUIRE(!td.path().empty());
    REQUIRE(fs::is_directory(td.path()));
}

TEST_CASE("TempDir destructor removes directory", "[temp_dir][raii]") {
    std::string saved_path;
    {
        auto result = yuzu::TempDir::create("del-dir-");
        REQUIRE(result.has_value());
        saved_path = result->path();

        // Create a file inside to verify remove_all behavior
        std::ofstream(fs::path(saved_path) / "testfile.txt") << "hello";
        REQUIRE(fs::exists(fs::path(saved_path) / "testfile.txt"));
    }
    REQUIRE_FALSE(fs::exists(saved_path));
}
