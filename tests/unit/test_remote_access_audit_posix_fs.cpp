/**
 * test_remote_access_audit_posix_fs.cpp -- the REAL make_posix_fs binding over a TempDir: the
 * no-follow reads, the bounded Include listing, hop-by-hop dir-fd confinement under an opened
 * home, the home lister's uid filter, and the mount-table parser, exercised through the same
 * Paths struct the Linux and macOS legs use. POSIX only; the body is compiled out on Windows
 * (the registration is unconditional).
 *
 * Real files, not a fake: O_NOFOLLOW/ENOTDIR answers, a FIFO under O_NONBLOCK, and dir-fd
 * confinement across a rename are kernel behaviour no in-memory fake reproduces; the tree is a
 * few KiB (plus two 1 MiB files for the cap boundary) under a yuzu_test_ TempDir.
 *
 * Provenance: every file is written by the test (a SYNTHETIC tree). The mountinfo lines are
 * CONSTRUCTED from proc(5) (the field layout) with the filesystem names of the shared deny-list.
 */
#include <catch2/catch_test_macros.hpp>

#if !defined(_WIN32)

#include "remote_access_audit_posix_fs.hpp"

#include "test_helpers.hpp"

#include <algorithm>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::remote_access_audit;

namespace {

struct Tree {
    yuzu::test::TempDir dir{"yuzu_test_raa_"};
    Tree() { fs::create_directories(dir.path); }
    fs::path at(const std::string& n) const { return dir.path / n; }
    void write(const fs::path& p, const std::string& text) const {
        fs::create_directories(p.parent_path());
        std::ofstream(p, std::ios::binary) << text;
    }
    Paths paths() const {
        Paths p;
        p.os = "linux";
        p.config = at("sshd_config").string();
        p.home_parents = {at("home").string()};
        p.single_homes = {at("rootsingle").string()};
        p.mounts = [] { return std::optional<std::vector<std::string>>{std::vector<std::string>{}}; };
        return p;
    }
};

} // namespace

TEST_CASE("remote_access_audit posix fs: a config reads back, a missing one is ENOENT, a symlinked config is followed (NixOS shape)",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    t.write(t.at("sshd_config"), "Port 22\n");
    t.write(t.at("real"), "x");
    fs::create_symlink(t.at("real"), t.at("linked_config"));
    const auto b = make_posix_fs(t.paths());
    const auto r = b.read_config(b.config_path);
    CHECK(r.error == ReadErr::none);
    CHECK(r.data == "Port 22\n");
    const auto m = b.read_config(t.at("absent").string());
    CHECK(m.error == ReadErr::io);
    CHECK(m.err == ENOENT);
    const auto l = b.read_config(t.at("linked_config").string());
    CHECK(l.error == ReadErr::none);
    CHECK(l.data == "x");
}

TEST_CASE("remote_access_audit posix fs: key files under a home refuse symlinks, FIFOs and oversize",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    t.write(t.at("home/alice/.ssh/authorized_keys"), "key\n");
    t.write(t.at("elsewhere/secret"), "outside");
    fs::create_symlink(t.at("elsewhere/secret"), t.at("home/alice/.ssh/authorized_keys2"));
    ::mkfifo(t.at("home/alice/.ssh/fifo").c_str(), 0600);
    t.write(t.at("home/alice/.ssh/exactly_cap"), std::string(kKeyFileCap, 'x'));
    t.write(t.at("home/alice/.ssh/over_cap"), std::string(kKeyFileCap + 1, 'x'));
    const auto b = make_posix_fs(t.paths());
    REQUIRE(b.open_home({"alice", t.at("home/alice").string()}) == 0);

    const auto ok = b.read_key_file({".ssh", "authorized_keys"});
    CHECK(ok.error == ReadErr::none);
    CHECK(ok.data == "key\n");
    CHECK(b.read_key_file({".ssh", "authorized_keys2"}).error == ReadErr::symlink_refused); // the leaf
    CHECK(b.read_key_file({".ssh", "fifo"}).error == ReadErr::not_regular); // and never blocks
    CHECK(b.read_key_file({".ssh", "exactly_cap"}).error == ReadErr::none);
    CHECK(b.read_key_file({".ssh", "over_cap"}).error == ReadErr::oversized);
    const auto gone = b.read_key_file({".ssh", "nope"});
    CHECK(gone.error == ReadErr::io);
    CHECK(gone.err == ENOENT);
    CHECK(b.read_key_file({"nodir", "authorized_keys"}).err == ENOENT);
}

TEST_CASE("remote_access_audit posix fs: a symlinked .ssh directory is never followed",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    t.write(t.at("elsewhere/authorized_keys"), "outside");
    t.write(t.at("home/alice/placeholder"), "");
    fs::create_directory_symlink(t.at("elsewhere"), t.at("home/alice/.ssh"));
    const auto b = make_posix_fs(t.paths());
    REQUIRE(b.open_home({"alice", t.at("home/alice").string()}) == 0);
    const auto r = b.read_key_file({".ssh", "authorized_keys"});
    CHECK(r.error != ReadErr::none);
    CHECK(r.data.empty());
    // a symlinked HOME is refused at the open
    fs::create_directory_symlink(t.at("elsewhere"), t.at("home/linkhome"));
    CHECK(b.open_home({"linkhome", t.at("home/linkhome").string()}) != 0);
}

TEST_CASE("remote_access_audit posix fs: reads are confined to the opened home by descriptor",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    t.write(t.at("home/alice/.ssh/authorized_keys"), "original");
    t.write(t.at("outside/.ssh/authorized_keys"), "attacker-chosen");
    const auto b = make_posix_fs(t.paths());
    REQUIRE(b.open_home({"alice", t.at("home/alice").string()}) == 0);
    // After the open, the home is swapped for a symlink to somewhere else: a path join would
    // follow it; the descriptor still names the directory that was opened.
    fs::rename(t.at("home/alice"), t.at("home/alice.moved"));
    fs::create_directory_symlink(t.at("outside"), t.at("home/alice"));
    const auto r = b.read_key_file({".ssh", "authorized_keys"});
    CHECK(r.error == ReadErr::none);
    CHECK(r.data == "original");
}

TEST_CASE("remote_access_audit posix fs: the Include listing is sorted, matched with FNM_PERIOD and capped",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    t.write(t.at("d/20-b.conf"), "b");
    t.write(t.at("d/10-a.conf"), "a");
    t.write(t.at("d/.hidden.conf"), "h");
    t.write(t.at("d/notes.txt"), "n");
    auto b = make_posix_fs(t.paths());
    std::vector<std::string> names;
    bool too_many = false;
    REQUIRE(b.list_include_dir(t.at("d").string(), "*.conf", names, too_many) == 0);
    CHECK(names == std::vector<std::string>{"10-a.conf", "20-b.conf"}); // sorted; the dotfile is not matched by *
    CHECK_FALSE(too_many);
    CHECK(b.read_include_at("10-a.conf").data == "a");
    names.clear();
    REQUIRE(b.list_include_dir(t.at("d").string(), ".*.conf", names, too_many) == 0);
    CHECK(names == std::vector<std::string>{".hidden.conf"}); // an explicit leading dot does match

    for (std::size_t i = 0; i < kMaxIncludeFiles + 8; ++i)
        t.write(t.at("many/" + std::to_string(100 + i) + ".conf"), "");
    names.clear();
    REQUIRE(b.list_include_dir(t.at("many").string(), "*.conf", names, too_many) == 0);
    CHECK(names.size() == kMaxIncludeFiles);
    CHECK(too_many);

    // the examined-entry cap truncates a huge directory and says so
    auto p = t.paths();
    p.max_dir_entries = 5;
    auto small = make_posix_fs(p);
    names.clear();
    too_many = false;
    REQUIRE(small.list_include_dir(t.at("many").string(), "*.conf", names, too_many) == 0);
    CHECK(too_many);
    CHECK(names.size() == 5);

    // a symlinked Include directory is followed (config side); a missing one answers an errno
    fs::create_directory_symlink(t.at("d"), t.at("dlink"));
    names.clear();
    REQUIRE(b.list_include_dir(t.at("dlink").string(), "*.conf", names, too_many) == 0);
    CHECK(names == std::vector<std::string>{"10-a.conf", "20-b.conf"});
    CHECK(b.list_include_dir(t.at("nodir").string(), "*", names, too_many) == ENOENT);
}

TEST_CASE("remote_access_audit posix fs: the home lister filters on uid, includes single homes, sorts",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    fs::create_directories(t.at("home/bob"));
    fs::create_directories(t.at("home/alice"));
    t.write(t.at("home/.DS_Store"), "");         // a regular file is not a home
    fs::create_directory_symlink(t.at("home/bob"), t.at("home/linked"));
    fs::create_directories(t.at("rootsingle"));
    auto b = make_posix_fs(t.paths());
    std::vector<HomeEntry> homes;
    bool too_many = false;
    REQUIRE(b.list_homes(b.home_roots, homes, too_many) == 0);
    std::vector<std::string> names;
    for (const auto& h : homes)
        names.push_back(h.name);
    CHECK(names == std::vector<std::string>{"alice", "bob", "linked", "rootsingle"}); // links stay visible: they are refused later
    CHECK(homes.back().path == t.at("rootsingle").string());

    // a uid floor above the owner filters every parent entry; the single home is still listed
    auto p = t.paths();
    p.min_uid = static_cast<unsigned>(::geteuid()) + 1;
    auto high = make_posix_fs(p);
    homes.clear();
    REQUIRE(high.list_homes(high.home_roots, homes, too_many) == 0);
    REQUIRE(homes.size() == 1);
    CHECK(homes[0].name == "rootsingle");
    // a floor at the owner's uid keeps them (>=)
    if (::geteuid() != 0) {
        p.min_uid = static_cast<unsigned>(::geteuid());
        auto eq = make_posix_fs(p);
        homes.clear();
        REQUIRE(eq.list_homes(eq.home_roots, homes, too_many) == 0);
        CHECK(homes.size() == 3); // alice, bob and the single home; the symlinked entry cannot be opened to be checked
    }

    // errno surfaces: a root that is a regular file, and a root that does not exist
    auto q = t.paths();
    q.home_parents = {t.at("home/.DS_Store").string()};
    auto bad = make_posix_fs(q);
    homes.clear();
    CHECK(bad.list_homes({q.home_parents[0]}, homes, too_many) == ENOTDIR);
    CHECK(bad.list_homes({t.at("nope").string()}, homes, too_many) == ENOENT);

    // the home cap
    for (int i = 0; i < 3; ++i)
        fs::create_directories(t.at("cap/h" + std::to_string(i)));
    auto r = t.paths();
    r.home_parents = {t.at("cap").string()};
    r.single_homes = {};
    r.max_dir_entries = 2;
    auto capped = make_posix_fs(r);
    homes.clear();
    too_many = false;
    REQUIRE(capped.list_homes(capped.home_roots, homes, too_many) == 0);
    CHECK(too_many);
    CHECK(homes.size() == 2);
}

TEST_CASE("remote_access_audit posix fs: an absolute key path outside any home is read by path",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    t.write(t.at("keys/shared"), "k");
    fs::create_symlink(t.at("keys/shared"), t.at("keys/link"));
    const auto b = make_posix_fs(t.paths());
    CHECK(b.read_key_file_abs(t.at("keys/shared").string()).data == "k");
    CHECK(b.read_key_file_abs(t.at("keys/link").string()).error == ReadErr::symlink_refused);
    CHECK(b.read_key_file_abs(t.at("keys/none").string()).err == ENOENT);
}

TEST_CASE("remote_access_audit posix fs: network mount points come from the mount table",
          "[remote_access_audit][posix_fs]") {
    // CONSTRUCTED from proc(5): mount id, parent id, major:minor, root, mount point, options,
    // optional fields, the standalone "-", fstype, source, super options.
    const std::string table =
        "36 35 98:0 / / rw,relatime shared:1 - ext4 /dev/root rw\n"
        "40 36 0:35 / /home/remote rw,relatime shared:5 - nfs4 srv:/export rw,vers=4.2\n"
        "41 36 0:36 / /mnt/with\\040space rw - cifs //h/s rw\n"
        "42 36 0:37 / /mnt/opts rw,x=a-b - ext4 /dev/sdb rw,note=- - nfs\n"
        "43 36 0:38 / /srv/fuse rw - fuse.sshfs u@h:/ rw\n"
        "44 36 0:39 / /srv/localfuse rw - fuse x rw\n"
        "garbage line\n";
    const auto m = yuzu::shared::network_mount_points(table);
    CHECK(m == std::vector<std::string>{"/home/remote", "/mnt/with space", "/srv/fuse"});
    CHECK(yuzu::shared::network_mount_points("").empty()); // a table with no lines is empty, not unreadable
    CHECK(yuzu::shared::network_mount_points("36 35 98:0 / /only rw - tmpfs none rw\n").empty());

    Tree t;
    t.write(t.at("mountinfo"), table);
    const auto read = linux_mountinfo_prefixes(t.at("mountinfo").string());
    REQUIRE(read.has_value());
    CHECK(read->size() == 3);
    CHECK_FALSE(linux_mountinfo_prefixes(t.at("absent").string()).has_value()); // unreadable != empty
}

namespace {

yuzu::agent::SubprocessResult service_enabled(const std::vector<std::string>&, const yuzu::agent::SubprocessOptions&) {
    yuzu::agent::SubprocessResult r;
    r.tool_ran = true;
    r.exit_code = 0;
    r.termination_reason = yuzu::agent::TerminationReason::exited;
    r.output = "enabled\n";
    return r;
}

} // namespace

TEST_CASE("remote_access_audit posix fs: config-side symlinks are followed as sshd follows them, key-side never",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    fs::create_directories(t.at("home"));
    fs::create_directories(t.at("rootsingle"));
    const auto dir = t.at("sshd_config.d").string();
    t.write(t.at("sshd_config"), "Include " + dir + "/*\n");
    t.write(t.at("sshd_config.d/100-macos.conf"), "UsePAM yes\nInclude " + t.at("crypto.conf").string() + "\n");
    auto list = [&] {
        auto p = t.paths();
        p.run = service_enabled;
        return list_posix(make_posix_fs(p));
    };
    auto has = [](const Listing& l, const std::string& row) {
        return std::ranges::find(l.rows, row) != l.rows.end();
    };

    SECTION("stock macOS shape: crypto.conf is a link to crypto/apple.conf") {
        t.write(t.at("crypto/apple.conf"), "PubkeyAuthentication yes\n");
        fs::create_symlink("crypto/apple.conf", t.at("crypto.conf"));
        const auto l = list();
        CHECK(l.status == StatusState::supported);
        CHECK(l.reason.empty());
        CHECK(has(l, "source|sshd_config|read|3"));
        CHECK(has(l, "config|pubkeyauthentication|yes|include:crypto.conf")); // the declared name, not the target
        CHECK(has(l, "config|usepam|yes|include:100-macos.conf"));
    }
    SECTION("a listed link that escapes the tree is read as sshd reads it") {
        t.write(t.at("crypto.conf"), "");
        t.write(t.at("outside/escape.conf"), "PermitRootLogin no\n");
        fs::create_symlink(t.at("outside/escape.conf"), t.at("sshd_config.d/90-escape.conf"));
        const auto l = list();
        CHECK(l.status == StatusState::supported);
        CHECK(l.reason.empty());
        CHECK(has(l, "config|permitrootlogin|no|include:90-escape.conf"));
    }
    SECTION("a dangling listed link is include:enoent (sshd exits) and the other includes still parse") {
        t.write(t.at("crypto.conf"), "");
        fs::create_symlink(t.at("nowhere"), t.at("sshd_config.d/95-dangling.conf"));
        const auto l = list();
        CHECK(l.status == StatusState::constrained);
        CHECK(l.reason.find("linux:remote_access_audit:include:enoent") != std::string::npos);
        CHECK(has(l, "config|usepam|yes|include:100-macos.conf"));
    }
    SECTION("a link loop is include:eloop, not a refusal") {
        t.write(t.at("crypto.conf"), "");
        fs::create_symlink("97-loop.conf", t.at("sshd_config.d/97-loop.conf"));
        const auto l = list();
        CHECK(l.status == StatusState::constrained);
        CHECK(l.reason.find("include:eloop") != std::string::npos);
        CHECK(l.reason.find("symlink_refused") == std::string::npos);
    }
    SECTION("a FIFO behind a link is not_regular and never blocks") {
        t.write(t.at("crypto.conf"), "");
        REQUIRE(::mkfifo(t.at("fifo").c_str(), 0600) == 0);
        fs::create_symlink(t.at("fifo"), t.at("sshd_config.d/98-fifo.conf"));
        const auto l = list();
        CHECK(l.status == StatusState::constrained);
        CHECK(l.reason.find("include:not_regular") != std::string::npos);
    }
}

TEST_CASE("remote_access_audit posix fs: end to end over a real tree", "[remote_access_audit][posix_fs]") {
    Tree t;
    t.write(t.at("sshd_config"), "Include " + t.at("sshd_config.d").string() + "/*.conf\nPermitRootLogin yes\n");
    t.write(t.at("sshd_config.d/10.conf"), "PermitRootLogin no\n");
    t.write(t.at("home/alice/.ssh/authorized_keys"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEfwkBaM2u8m02IuUZ4wuvCPggDaq5R5MqdQWA82+WdV a\n");
    t.write(t.at("rootsingle/.ssh/authorized_keys"), "");
    auto p = t.paths();
    p.run = [](const std::vector<std::string>&, const yuzu::agent::SubprocessOptions&) {
        yuzu::agent::SubprocessResult r;
        r.tool_ran = true;
        r.exit_code = 0;
        r.termination_reason = yuzu::agent::TerminationReason::exited;
        r.output = "enabled\n";
        return r;
    };
    const auto l = list_posix(make_posix_fs(p));
    CHECK(l.status == StatusState::supported);
    CHECK(l.rows[0] == "source|sshd_config|read|2");
    CHECK(l.rows[1] == "source|homes|read|2");
    CHECK(std::ranges::find(l.rows, "config|permitrootlogin|no|include:10.conf") != l.rows.end());
    CHECK(std::ranges::find(l.rows, "file|alice|authorized_keys|read|1|0|0") != l.rows.end());
    CHECK(std::ranges::find(l.rows, "file|rootsingle|authorized_keys|read|0|0|0") != l.rows.end());
    CHECK(std::ranges::find(l.rows, "file|alice|authorized_keys2|absent|-|-|-") != l.rows.end());
}

#else

TEST_CASE("remote_access_audit posix fs: not applicable on Windows", "[remote_access_audit][posix_fs]") {
    SUCCEED("the POSIX binding is compiled out on Windows");
}

#endif // !defined(_WIN32)
