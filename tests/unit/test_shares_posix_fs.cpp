/**
 * test_shares_posix_fs.cpp -- the REAL make_posix_fs binding over a TempDir: the no-follow
 * reads, the bounded exports.d listing, dir-fd confinement and the lstat directory probe,
 * exercised through the same Paths struct the Linux and macOS legs use. POSIX only; the body
 * is compiled out on Windows (the registration is unconditional).
 *
 * Provenance: every file is written by the test (a SYNTHETIC tree); the stock-file rows in
 * the end-to-end case are RECONSTRUCTIONS, as in test_shares_parsers.cpp.
 */
#include <catch2/catch_test_macros.hpp>

#if !defined(_WIN32)

#include "shares_posix_fs.hpp"

#include "test_helpers.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::shares;

namespace {

struct Tree {
    yuzu::test::TempDir dir{"yuzu_test_shares_"};
    Tree() { fs::create_directories(dir.path); }
    fs::path at(const std::string& n) const { return dir.path / n; }
    Paths paths() const {
        return Paths{at("exports").string(), at("exports.d").string(), at("smb.conf").string(),
                     at("usershares").string()};
    }
    void write(const fs::path& p, const std::string& text) const {
        std::ofstream(p, std::ios::binary) << text;
    }
};

} // namespace

TEST_CASE("shares posix fs: regular file reads back, a missing one is ENOENT", "[shares][posix_fs]") {
    Tree t;
    t.write(t.at("exports"), "/srv/a host(rw)\n");
    const auto fsb = make_posix_fs(t.paths());
    const auto r = fsb.read(fsb.exports_path);
    CHECK(r.error == ReadErr::none);
    CHECK(r.data == "/srv/a host(rw)\n");
    const auto m = fsb.read(fsb.smb_conf_path);
    CHECK(m.error == ReadErr::io);
    CHECK(m.err == ENOENT);
}

TEST_CASE("shares posix fs: a symlink leaf is refused", "[shares][posix_fs]") {
    Tree t;
    t.write(t.at("real"), "x");
    fs::create_symlink(t.at("real"), t.at("exports"));
    fs::create_symlink(t.at("real"), t.at("smb.conf"));
    const auto fsb = make_posix_fs(t.paths());
    CHECK(fsb.read(fsb.exports_path).error == ReadErr::symlink_refused);
    CHECK(fsb.read(fsb.smb_conf_path).error == ReadErr::symlink_refused);
}

TEST_CASE("shares posix fs: a FIFO is not_regular and never blocks", "[shares][posix_fs]") {
    Tree t;
    REQUIRE(::mkfifo(t.at("smb.conf").c_str(), 0600) == 0);
    const auto fsb = make_posix_fs(t.paths());
    CHECK(fsb.read(fsb.smb_conf_path).error == ReadErr::not_regular);
}

TEST_CASE("shares posix fs: a file over the cap is oversized with no data", "[shares][posix_fs]") {
    Tree t;
    t.write(t.at("exports"), std::string(kFileCap + 1, 'a'));
    t.write(t.at("smb.conf"), std::string(kFileCap, 'a'));
    const auto fsb = make_posix_fs(t.paths());
    const auto big = fsb.read(fsb.exports_path);
    CHECK(big.error == ReadErr::oversized);
    CHECK(big.data.empty());
    CHECK(fsb.read(fsb.smb_conf_path).error == ReadErr::none); // exactly at the cap is fine
}

TEST_CASE("shares posix fs: exports.d listing filters, sorts and caps", "[shares][posix_fs]") {
    Tree t;
    fs::create_directory(t.at("exports.d"));
    for (int i = 0; i < 70; ++i) {
        char name[32];
        std::snprintf(name, sizeof name, "e%02d.exports", i);
        t.write(t.at("exports.d") / name, "/srv/x h\n");
    }
    t.write(t.at("exports.d") / ".hidden.exports", "x");
    t.write(t.at("exports.d") / "x.conf", "x");
    fs::create_directory(t.at("exports.d") / "sub");
    const auto fsb = make_posix_fs(t.paths());
    std::vector<std::string> names;
    bool too_many = false;
    REQUIRE(fsb.list_exports_d(names, too_many) == 0);
    CHECK(too_many);
    REQUIRE(names.size() == kMaxExportsFiles);
    CHECK(std::ranges::is_sorted(names));
    CHECK(names.front() == "e00.exports");
    CHECK(names.back() == "e63.exports");
    CHECK(std::ranges::none_of(names, [](const std::string& n) { return n[0] == '.' || n == "x.conf" || n == "sub"; }));
}

TEST_CASE("shares posix fs: exports.d that is absent, a symlink or a file", "[shares][posix_fs]") {
    std::vector<std::string> names;
    bool too_many = false;
    {
        Tree t;
        const auto fsb = make_posix_fs(t.paths());
        CHECK(fsb.list_exports_d(names, too_many) == ENOENT);
    }
    {
        Tree t;
        fs::create_directory(t.at("real_d"));
        fs::create_directory_symlink(t.at("real_d"), t.at("exports.d"));
        const auto fsb = make_posix_fs(t.paths());
        CHECK(fsb.list_exports_d(names, too_many) == ENOTDIR); // never ENOENT, never followed
    }
    {
        Tree t;
        t.write(t.at("exports.d"), "x");
        const auto fsb = make_posix_fs(t.paths());
        CHECK(fsb.list_exports_d(names, too_many) == ENOTDIR);
    }
}

TEST_CASE("shares posix fs: snippets are read through the retained directory descriptor",
          "[shares][posix_fs]") {
    Tree t;
    fs::create_directory(t.at("exports.d"));
    t.write(t.at("exports.d") / "a.exports", "/srv/a h(rw)\n");
    t.write(t.at("elsewhere"), "outside");
    fs::create_symlink(t.at("elsewhere"), t.at("exports.d") / "link.exports");
    const auto fsb = make_posix_fs(t.paths());
    std::vector<std::string> names;
    bool too_many = false;
    REQUIRE(fsb.list_exports_d(names, too_many) == 0);
    REQUIRE(names.size() == 2);
    // Replace the directory after the listing: a path join would now read the wrong tree.
    fs::rename(t.at("exports.d"), t.at("moved_d"));
    fs::create_directory(t.at("exports.d"));
    t.write(t.at("exports.d") / "a.exports", "/srv/IMPOSTOR h\n");
    const auto r = fsb.read_exports_d_file("a.exports");
    CHECK(r.error == ReadErr::none);
    CHECK(r.data == "/srv/a h(rw)\n");
    CHECK(fsb.read_exports_d_file("link.exports").error == ReadErr::symlink_refused);
    CHECK(fsb.read_exports_d_file("../elsewhere").error == ReadErr::io); // not a single component
}

TEST_CASE("shares posix fs: dir_exists is an lstat", "[shares][posix_fs]") {
    Tree t;
    fs::create_directory(t.at("usershares"));
    fs::create_directory(t.at("real_dir"));
    fs::create_directory_symlink(t.at("real_dir"), t.at("link_dir"));
    fs::create_directory(t.at("locked"));
    REQUIRE(::chmod(t.at("locked").c_str(), 0) == 0);
    const auto fsb = make_posix_fs(t.paths());
    CHECK(fsb.dir_exists(t.at("usershares").string()));
    CHECK_FALSE(fsb.dir_exists(t.at("link_dir").string())); // a symlink is not followed
    CHECK_FALSE(fsb.dir_exists(t.at("absent").string()));
    CHECK(fsb.dir_exists(t.at("locked").string())); // lstat needs no read permission
    ::chmod(t.at("locked").c_str(), 0700);
}

TEST_CASE("shares posix fs: list_linux end to end over a seeded tree", "[shares][posix_fs]") {
    Tree t;
    t.write(t.at("exports"), "# stock: comments only\n");
    fs::create_directory(t.at("exports.d"));
    t.write(t.at("exports.d") / "web.exports", "/srv/web 10.0.0.0/24(ro)\n");
    // RECONSTRUCTION of the Debian [homes] section.
    t.write(t.at("smb.conf"), "[global]\nworkgroup = WORKGROUP\n[homes]\n  browseable = no\n"
                              "  read only = yes\n");
    const auto l = list_linux(make_posix_fs(t.paths()));
    CHECK(l.status == StatusState::supported);
    CHECK(l.rows == std::vector<std::string>{
                        "source|exports|read|0",
                        "source|exports_d|read|1",
                        "source|smb_conf|read|1",
                        "share|nfs|-|/srv/web|ro|false|clients_1|exports_d",
                        "share|smb|homes|-|ro|false|hidden,special|smb_conf",
                    });
}

#endif // !defined(_WIN32)
