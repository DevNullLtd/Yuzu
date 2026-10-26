/**
 * test_license_scan_probe_host_posix.cpp -- the errno-aware ProbeHost
 * primitives read_file_capped / list_dir (SAM.10), exercised against a real
 * temp tree so the contract the Linux entitlement_certs surface relies on is
 * pinned: an ABSENT path (ENOENT/ENOTDIR) and a REFUSED one (EACCES/EPERM) are
 * distinguishable, an oversized file is never a truncated read, and a listing
 * that hits its entry budget says so.
 *
 * POSIX only (the bodies under test are the posix_secure_read.hpp-backed
 * ones); the whole TU is a no-op on Windows. The chmod-0 cases need an
 * unprivileged user: root passes every permission check, so they WARN and skip
 * at euid 0 (test_shares_posix_fs.cpp precedent) -- the refusal evidence on a
 * root lane is the runuser probe recorded in the PR, not this suite.
 */

#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include "licensing_probes.hpp"
#include "test_helpers.hpp"

#include <algorithm>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using yuzu::license_scan::CappedRead;
using yuzu::license_scan::DirListing;
using yuzu::license_scan::ProbeHost;

namespace {

struct Tree {
    yuzu::test::TempDir tmp{"yuzu_test_license_scan_"};
    Tree() { fs::create_directories(tmp.path); }
    [[nodiscard]] fs::path at(const char* name) const { return tmp.path / name; }
    void write(const fs::path& p, const std::string& content) const {
        std::ofstream(p, std::ios::binary) << content;
    }
};

// Restores a permissive mode on scope exit so TempDir's remove_all can clean up.
struct ModeRestore {
    fs::path path;
    mode_t mode;
    ~ModeRestore() { ::chmod(path.c_str(), mode); }
};

std::vector<std::string> sorted(std::vector<std::string> v) {
    std::sort(v.begin(), v.end());
    return v;
}

} // namespace

TEST_CASE("probe host read_file_capped: a readable regular file is returned whole",
          "[license_scan][probe_host][posix]") {
    Tree t;
    t.write(t.at("cert.pem"), "0123456789");
    ProbeHost host;
    const CappedRead r = host.read_file_capped(t.at("cert.pem").string(), 64);
    REQUIRE(r.data.has_value());
    CHECK(*r.data == "0123456789");
    CHECK(r.err == 0);
    CHECK_FALSE(r.oversized);
}

TEST_CASE("probe host read_file_capped: the cap is exact and oversized is never a partial read",
          "[license_scan][probe_host][posix]") {
    Tree t;
    t.write(t.at("ten.bin"), "0123456789");
    ProbeHost host;

    const CappedRead at_cap = host.read_file_capped(t.at("ten.bin").string(), 10);
    REQUIRE(at_cap.data.has_value()); // exactly the cap is accepted
    CHECK(at_cap.data->size() == 10);
    CHECK_FALSE(at_cap.oversized);

    const CappedRead over = host.read_file_capped(t.at("ten.bin").string(), 9);
    CHECK_FALSE(over.data.has_value()); // one byte over: no truncated parse
    CHECK(over.oversized);
    CHECK(over.err == 0);
}

TEST_CASE("probe host read_file_capped: absent is ENOENT, a directory or FIFO is refused unread",
          "[license_scan][probe_host][posix]") {
    Tree t;
    ProbeHost host;

    const CappedRead absent = host.read_file_capped(t.at("nope.pem").string(), 64);
    CHECK_FALSE(absent.data.has_value());
    CHECK(absent.err == ENOENT);
    CHECK_FALSE(absent.oversized);

    fs::create_directory(t.at("subdir"));
    const CappedRead dir = host.read_file_capped(t.at("subdir").string(), 64);
    CHECK_FALSE(dir.data.has_value());
    CHECK(dir.err == EINVAL); // not a regular file

    // A FIFO must be refused without blocking for a writer (O_NONBLOCK open).
    REQUIRE(::mkfifo(t.at("pipe.pem").c_str(), 0600) == 0);
    const CappedRead fifo = host.read_file_capped(t.at("pipe.pem").string(), 64);
    CHECK_FALSE(fifo.data.has_value());
    CHECK(fifo.err == EINVAL);
}

TEST_CASE("probe host read_file_capped: a symlinked leaf is followed",
          "[license_scan][probe_host][posix]") {
    Tree t;
    t.write(t.at("real.pem"), "payload");
    fs::create_symlink(t.at("real.pem"), t.at("link.pem"));
    ProbeHost host;
    const CappedRead r = host.read_file_capped(t.at("link.pem").string(), 64);
    REQUIRE(r.data.has_value());
    CHECK(*r.data == "payload");
}

TEST_CASE("probe host read_file_capped: a file the user may not read is EACCES, not absent",
          "[license_scan][probe_host][posix]") {
    if (::geteuid() == 0) {
        WARN("skipped: euid 0 passes every permission check, so a chmod-0 file is not refused");
        return;
    }
    Tree t;
    t.write(t.at("locked.pem"), "secret");
    REQUIRE(::chmod(t.at("locked.pem").c_str(), 0) == 0);
    ModeRestore restore{t.at("locked.pem"), 0600};
    ProbeHost host;
    const CappedRead r = host.read_file_capped(t.at("locked.pem").string(), 64);
    CHECK_FALSE(r.data.has_value());
    CHECK(r.err == EACCES);
    CHECK_FALSE(r.oversized);
}

TEST_CASE("probe host list_dir: names only, no filtering, dot entries excluded",
          "[license_scan][probe_host][posix]") {
    Tree t;
    t.write(t.at("a.pem"), "x");
    t.write(t.at("b-key.pem"), "x");
    t.write(t.at("c.txt"), "x");
    fs::create_directory(t.at("sub"));
    ProbeHost host;
    const DirListing d = host.list_dir(t.tmp.path.string(), 100);
    CHECK(d.err == 0);
    CHECK_FALSE(d.truncated);
    CHECK(sorted(d.names) ==
          std::vector<std::string>{"a.pem", "b-key.pem", "c.txt", "sub"}); // filtering is the caller's job
}

TEST_CASE("probe host list_dir: absent is ENOENT and a regular file is ENOTDIR",
          "[license_scan][probe_host][posix]") {
    Tree t;
    t.write(t.at("file"), "x");
    ProbeHost host;

    const DirListing absent = host.list_dir(t.at("nope").string(), 100);
    CHECK(absent.err == ENOENT);
    CHECK(absent.names.empty());

    const DirListing not_dir = host.list_dir(t.at("file").string(), 100);
    CHECK(not_dir.err == ENOTDIR);
    CHECK(not_dir.names.empty());
}

TEST_CASE("probe host list_dir: a symlinked directory leaf is followed",
          "[license_scan][probe_host][posix]") {
    Tree t;
    fs::create_directory(t.at("real"));
    t.write(t.at("real") / "x.pem", "x");
    fs::create_directory_symlink(t.at("real"), t.at("link"));
    ProbeHost host;
    const DirListing d = host.list_dir(t.at("link").string(), 100);
    CHECK(d.err == 0);
    CHECK(d.names == std::vector<std::string>{"x.pem"});
}

TEST_CASE("probe host list_dir: a directory the user may not list is EACCES, never an empty listing",
          "[license_scan][probe_host][posix]") {
    if (::geteuid() == 0) {
        WARN("skipped: euid 0 passes every permission check, so a chmod-0 directory is not refused");
        return;
    }
    Tree t;
    fs::create_directory(t.at("locked"));
    t.write(t.at("locked") / "cert.pem", "x");
    REQUIRE(::chmod(t.at("locked").c_str(), 0) == 0);
    ModeRestore restore{t.at("locked"), 0700};
    ProbeHost host;
    const DirListing d = host.list_dir(t.at("locked").string(), 100);
    CHECK(d.err == EACCES);
    CHECK(d.names.empty());
    CHECK_FALSE(d.truncated);
}

TEST_CASE("probe host list_dir: the entry budget is exact and truncation is reported",
          "[license_scan][probe_host][posix]") {
    Tree t;
    for (const char* n : {"1.pem", "2.pem", "3.pem", "4.pem", "5.pem"})
        t.write(t.at(n), "x");
    ProbeHost host;

    const DirListing under = host.list_dir(t.tmp.path.string(), 3);
    CHECK(under.names.size() == 3);
    CHECK(under.truncated); // entries remain beyond the budget
    CHECK(under.err == 0);

    const DirListing one_short = host.list_dir(t.tmp.path.string(), 4);
    CHECK(one_short.names.size() == 4);
    CHECK(one_short.truncated);

    const DirListing exact = host.list_dir(t.tmp.path.string(), 5);
    CHECK(exact.names.size() == 5);
    CHECK_FALSE(exact.truncated); // exactly the budget: nothing was left unread

    const DirListing roomy = host.list_dir(t.tmp.path.string(), 6);
    CHECK(roomy.names.size() == 5);
    CHECK_FALSE(roomy.truncated);
}

#endif // !_WIN32
