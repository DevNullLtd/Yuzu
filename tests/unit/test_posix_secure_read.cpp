/**
 * test_posix_secure_read.cpp -- tests for the shared no-follow directory
 * open and bounded file read primitives (agents/shared/posix_secure_read.hpp,
 * #4866). Real syscalls against a real temp tree only: no process spawn, no
 * sleeps.
 */
#if !defined(_WIN32)

#include <catch2/catch_test_macros.hpp>

#include "test_helpers.hpp"

#include <posix_dir_walk.hpp>
#include <posix_secure_read.hpp>

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace yuzu::shared;
using namespace std::string_literals;

namespace {

void write_file(const fs::path& p, const std::string& body) {
    std::ofstream f(p, std::ios::binary);
    f << body;
}

} // namespace

TEST_CASE("posix_secure_read: directory opens and walks", "[shared][posix_secure_read]") {
    yuzu::test::TempDir tmp{"yuzu_test_psr_"};
    REQUIRE(fs::create_directory(tmp.path));
    write_file(tmp.path / "a.txt", "a");
    write_file(tmp.path / "b.txt", "b");

    auto r = open_dir_no_follow(tmp.path.string());
    REQUIRE(r.opened());
    CHECK(r.err == 0);
    CHECK(r.dir.fd() >= 0);

    std::set<std::string> seen;
    auto walk = walk_dir_capped(r.dir.get(), 100, [&](struct dirent* e) {
        seen.insert(e->d_name);
        return true;
    });
    CHECK_FALSE(walk.enumeration_error);
    CHECK(seen == std::set<std::string>{"a.txt", "b.txt"});
}

TEST_CASE("posix_secure_read: symlink to directory at the leaf is refused", "[shared][posix_secure_read]") {
    yuzu::test::TempDir tmp{"yuzu_test_psr_"};
    REQUIRE(fs::create_directory(tmp.path));
    fs::create_directory(tmp.path / "real");
    fs::create_directory_symlink(tmp.path / "real", tmp.path / "link");

    // O_DIRECTORY|O_NOFOLLOW answers ENOTDIR for a symlink leaf, not ELOOP.
    auto p = open_dir_no_follow((tmp.path / "link").string());
    CHECK_FALSE(p.opened());
    CHECK(p.err == ENOTDIR);

    auto root = open_dir_no_follow(tmp.path.string());
    REQUIRE(root.opened());
    auto a = open_dir_no_follow_at(root.dir.fd(), "link");
    CHECK_FALSE(a.opened());
    CHECK(a.err == ENOTDIR);
}

TEST_CASE("posix_secure_read: hop-by-hop refuses a swapped intermediate symlink",
          "[shared][posix_secure_read]") {
    yuzu::test::TempDir tmp{"yuzu_test_psr_"};
    REQUIRE(fs::create_directory(tmp.path));
    fs::create_directories(tmp.path / "real" / "inner");
    fs::create_directory(tmp.path / "root");
    fs::create_directory_symlink(tmp.path / "real", tmp.path / "root" / "mid");

    auto root = open_dir_no_follow((tmp.path / "root").string());
    REQUIRE(root.opened());
    auto hop = open_dir_no_follow_at(root.dir.fd(), "mid");
    CHECK_FALSE(hop.opened());
    CHECK(hop.err == ENOTDIR);

    // The joined-path form follows intermediates: documented difference.
    auto joined = open_dir_no_follow((tmp.path / "root" / "mid" / "inner").string());
    CHECK(joined.opened());
}

TEST_CASE("posix_secure_read: single-component contract", "[shared][posix_secure_read]") {
    yuzu::test::TempDir tmp{"yuzu_test_psr_"};
    REQUIRE(fs::create_directory(tmp.path));
    fs::create_directories(tmp.path / "sub" / "inner");
    write_file(tmp.path / "sub" / "inner" / "f", "x");
    write_file(tmp.path / "marker", "secret");

    auto sub = open_dir_no_follow((tmp.path / "sub").string());
    REQUIRE(sub.opened());
    const int fd = sub.dir.fd();

    for (const char* bad : {"inner/f", "..", "/etc", "", "."}) {
        INFO("name=\"" << bad << "\"");
        auto d = open_dir_no_follow_at(fd, bad);
        CHECK_FALSE(d.opened());
        CHECK(d.err == EINVAL);
        auto f = read_file_no_follow_at(fd, bad, 1024);
        CHECK(f.error == ReadError::io);
        CHECK(f.err == EINVAL);
        CHECK(f.data.empty());
    }
    auto d = open_dir_no_follow_at(fd, "sub/inner");
    CHECK(d.err == EINVAL);

    // `..` must not reach the parent: marker lives there and stays unreadable.
    auto viaDotDot = read_file_no_follow_at(fd, "../marker", 1024);
    CHECK_FALSE(viaDotDot.ok());
    CHECK(viaDotDot.err == EINVAL);
    CHECK(viaDotDot.data.empty());

    // A null name is rejected too.
    CHECK(open_dir_no_follow_at(fd, nullptr).err == EINVAL);
}

TEST_CASE("posix_secure_read: directory open errno is verbatim", "[shared][posix_secure_read]") {
    yuzu::test::TempDir tmp{"yuzu_test_psr_"};
    REQUIRE(fs::create_directory(tmp.path));
    write_file(tmp.path / "file", "x");

    auto missing = open_dir_no_follow((tmp.path / "nope").string());
    CHECK_FALSE(missing.opened());
    CHECK(missing.err == ENOENT);

    auto notdir = open_dir_no_follow((tmp.path / "file").string());
    CHECK_FALSE(notdir.opened());
    CHECK(notdir.err == ENOTDIR);

    auto root = open_dir_no_follow(tmp.path.string());
    REQUIRE(root.opened());
    CHECK(open_dir_no_follow_at(root.dir.fd(), "nope").err == ENOENT);
    CHECK(open_dir_no_follow_at(root.dir.fd(), "file").err == ENOTDIR);
}

TEST_CASE("posix_secure_read: file read and cap boundary", "[shared][posix_secure_read]") {
    yuzu::test::TempDir tmp{"yuzu_test_psr_"};
    REQUIRE(fs::create_directory(tmp.path));
    const std::string body = "hello\0world"s;
    write_file(tmp.path / "f", body);

    auto root = open_dir_no_follow(tmp.path.string());
    REQUIRE(root.opened());

    auto exact = read_file_no_follow_at(root.dir.fd(), "f", body.size());
    CHECK(exact.ok());
    CHECK(exact.data == body);

    auto over = read_file_no_follow_at(root.dir.fd(), "f", body.size() - 1);
    CHECK(over.error == ReadError::oversized);
    CHECK(over.data.empty());

    auto viaPath = read_file_no_follow((tmp.path / "f").string(), body.size());
    CHECK(viaPath.ok());
    CHECK(viaPath.data == body);

    // Larger than one 8 KiB chunk: read must go to EOF across chunks.
    const std::string big(20000, 'z');
    write_file(tmp.path / "big", big);
    auto bigOk = read_file_no_follow_at(root.dir.fd(), "big", big.size());
    CHECK(bigOk.ok());
    CHECK(bigOk.data == big);
    auto bigOver = read_file_no_follow_at(root.dir.fd(), "big", big.size() - 1);
    CHECK(bigOver.error == ReadError::oversized);
    CHECK(bigOver.data.empty());

    // Read goes to EOF, never to st_size: procfs files report st_size 0.
#if defined(__linux__)
    auto proc = read_file_no_follow("/proc/version", 1 << 20);
    CHECK(proc.ok());
    CHECK_FALSE(proc.data.empty());
    CHECK(read_file_no_follow("/proc/version", 1).error == ReadError::oversized);
#endif

    auto missing = read_file_no_follow_at(root.dir.fd(), "nope", 10);
    CHECK(missing.error == ReadError::io);
    CHECK(missing.err == ENOENT);
}

TEST_CASE("posix_secure_read: non-regular and symlink leaves are refused", "[shared][posix_secure_read]") {
    yuzu::test::TempDir tmp{"yuzu_test_psr_"};
    REQUIRE(fs::create_directory(tmp.path));
    write_file(tmp.path / "real", "x");
    fs::create_symlink(tmp.path / "real", tmp.path / "link");
    fs::create_directory(tmp.path / "dir");
    REQUIRE(::mkfifo((tmp.path / "fifo").c_str(), 0600) == 0);

    auto root = open_dir_no_follow(tmp.path.string());
    REQUIRE(root.opened());
    const int fd = root.dir.fd();

    auto link = read_file_no_follow_at(fd, "link", 10);
    CHECK(link.error == ReadError::symlink_refused);
    CHECK(link.err == ELOOP);
    CHECK(read_file_no_follow((tmp.path / "link").string(), 10).error == ReadError::symlink_refused);

    // O_NONBLOCK: a FIFO with no writer must not hang the open.
    CHECK(read_file_no_follow_at(fd, "fifo", 10).error == ReadError::not_regular);
    CHECK(read_file_no_follow((tmp.path / "fifo").string(), 10).error == ReadError::not_regular);

    CHECK(read_file_no_follow_at(fd, "dir", 10).error == ReadError::not_regular);
}

TEST_CASE("posix_secure_read: unreadable file reports EACCES", "[shared][posix_secure_read]") {
    if (::geteuid() == 0) SKIP("root bypasses mode bits");
    yuzu::test::TempDir tmp{"yuzu_test_psr_"};
    REQUIRE(fs::create_directory(tmp.path));
    write_file(tmp.path / "locked", "x");
    REQUIRE(::chmod((tmp.path / "locked").c_str(), 0) == 0);

    auto root = open_dir_no_follow(tmp.path.string());
    REQUIRE(root.opened());
    auto r = read_file_no_follow_at(root.dir.fd(), "locked", 10);
    CHECK(r.error == ReadError::io);
    CHECK(r.err == EACCES);
}

TEST_CASE("posix_secure_read: fdopendir failure closes its descriptor",
          "[shared][posix_secure_read]") {
    yuzu::test::TempDir tmp{"yuzu_test_psr_"};
    REQUIRE(fs::create_directory(tmp.path));
    write_file(tmp.path / "regular", "x");
    const int raw = ::open((tmp.path / "regular").c_str(), O_RDONLY | O_CLOEXEC);
    REQUIRE(raw >= 0);

    auto result = detail::finish_dir_open(raw);
    const int state = ::fcntl(raw, F_GETFD);
    const int state_errno = errno;
    if (state != -1) ::close(raw);

    CHECK_FALSE(result.opened());
    CHECK(result.err == ENOTDIR);
    CHECK(state == -1);
    CHECK(state_errno == EBADF);
}

#endif // !_WIN32
