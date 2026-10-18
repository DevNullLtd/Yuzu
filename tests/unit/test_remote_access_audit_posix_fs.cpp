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

yuzu::agent::SubprocessResult service_enabled(const std::vector<std::string>&, const yuzu::agent::SubprocessOptions&) {
    yuzu::agent::SubprocessResult r;
    r.tool_ran = true;
    r.exit_code = 0;
    r.termination_reason = yuzu::agent::TerminationReason::exited;
    r.output = "enabled\n";
    return r;
}

constexpr const char* kAliceKey =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEfwkBaM2u8m02IuUZ4wuvCPggDaq5R5MqdQWA82+WdV alice@laptop\n";
constexpr const char* kAliceFp = "SHA256:BPH4QduMtDlX59CWZCda5Zf0U0jseMmFVimvek7EMhA";

struct Tree {
    yuzu::test::TempDir dir{"yuzu_test_raa_"};
    fs::path root; ///< canonical: list_homes opens its roots link-free from "/", and macOS's temp dir sits under the /var link
    Tree() {
        fs::create_directories(dir.path);
        root = fs::canonical(dir.path);
    }
    fs::path at(const std::string& n) const { return root / n; }
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

TEST_CASE("remote_access_audit posix fs: the home lister lists names only, includes single homes, sorts, caps",
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
    CHECK_FALSE(b.is_account_home); // no uid floor on this binding

    // a uid floor changes eligibility (is_account_home), never what is listed
    auto p = t.paths();
    p.min_uid = static_cast<unsigned>(::geteuid()) + 1;
    auto high = make_posix_fs(p);
    homes.clear();
    REQUIRE(high.list_homes(high.home_roots, homes, too_many) == 0);
    CHECK(homes.size() == 4);

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

TEST_CASE("remote_access_audit posix fs: account eligibility is a path lstat, false only on a confirmed lower owner",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    fs::create_directories(t.at("home/alice"));
    fs::create_directories(t.at("rootsingle"));
    fs::create_directory_symlink(t.at("home/alice"), t.at("home/linked"));

    auto p = t.paths();
    p.min_uid = static_cast<unsigned>(::geteuid()) + 1; // every file here is owned by euid: below the floor
    const auto high = make_posix_fs(p);
    REQUIRE(high.is_account_home);
    const HomeEntry alice{"alice", t.at("home/alice").string()};
    const HomeEntry linked{"linked", t.at("home/linked").string()};
    CHECK_FALSE(high.is_account_home(alice));
    // a link is never judged by its own owner: eligible even under a floor its owner misses
    // (a root-owned /Users/alice -> /Volumes/Data/Users/alice), and refused loudly at open
    CHECK(high.is_account_home(linked));
    // a single home (/root, /private/var/root) is never filtered: it is root's own home by definition
    CHECK(high.is_account_home({"rootsingle", t.at("rootsingle").string()}));
    // a failed stat is not a confirmed owner: eligible, so open_home reports the errno
    CHECK(high.is_account_home({"ghost", t.at("home/ghost").string()}));

    if (::geteuid() != 0) { // with euid 0 the floor would be 0 = no filter, no predicate bound
        p.min_uid = static_cast<unsigned>(::geteuid());
        const auto eq = make_posix_fs(p);
        REQUIRE(eq.is_account_home);
        CHECK(eq.is_account_home(alice)); // a floor at the owner's uid keeps it (>=)
        // lstat, not stat: a link is never opened or followed, and never judged by its owner
        CHECK(eq.is_account_home(linked));
    }
}

TEST_CASE("remote_access_audit posix fs: an unopenable home is listed and refused at open, not dropped",
          "[remote_access_audit][posix_fs]") {
    if (::geteuid() == 0)
        SKIP("root opens a mode-000 directory");
    Tree t;
    fs::create_directories(t.at("home/alice"));
    fs::create_directories(t.at("home/locked"));
    fs::create_directory_symlink(t.at("home/alice"), t.at("home/linked"));
    struct Restore { // let the TempDir clean up even when a REQUIRE below aborts the case
        fs::path dir;
        ~Restore() { ::chmod(dir.c_str(), 0700); }
    } restore{t.at("home/locked")};
    REQUIRE(::chmod(t.at("home/locked").c_str(), 0) == 0);
    auto p = t.paths();
    p.min_uid = static_cast<unsigned>(::geteuid()); // the macOS shape: a floor the owner meets
    const auto b = make_posix_fs(p);

    std::vector<HomeEntry> homes;
    bool too_many = false;
    REQUIRE(b.list_homes(b.home_roots, homes, too_many) == 0);
    std::vector<std::string> names;
    for (const auto& h : homes)
        names.push_back(h.name);
    CHECK(names == std::vector<std::string>{"alice", "linked", "locked", "rootsingle"}); // locked is NOT dropped

    const auto find = [&](const std::string& n) { return *std::ranges::find(homes, n, &HomeEntry::name); };
    REQUIRE(b.is_account_home(find("locked")));      // owned by us: eligible even though unopenable
    CHECK(b.open_home(find("locked")) == EACCES);    // ... and the open reports the refusal
    CHECK(b.open_home(find("alice")) == 0);
    CHECK(b.open_home(find("linked")) != 0);         // a symlinked home is refused at the open (ELOOP or ENOTDIR by OS)

    // and the whole listing says so: a refused file row plus the homes token, never a vanished account
    p.run = [](const std::vector<std::string>&, const yuzu::agent::SubprocessOptions&) {
        yuzu::agent::SubprocessResult r;
        r.tool_ran = true;
        r.termination_reason = yuzu::agent::TerminationReason::exited;
        r.output = "enabled\n";
        return r;
    };
    const auto l = list_posix(make_posix_fs(p));
    CHECK(std::ranges::find(l.rows, "file|locked|authorized_keys|refused|-|-|-") != l.rows.end());
    CHECK(l.reason.find("linux:remote_access_audit:homes:permission_denied") != std::string::npos);
}

TEST_CASE("remote_access_audit posix fs: a symlinked home parent is resolved by one readlink hop and opened link-free",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    // the Fedora Atomic shape: /home -> var/home. The parent is root-owned like /etc/ssh.
    fs::create_directories(t.at("real_homes/alice/.ssh"));
    fs::create_directories(t.at("real_homes/bob"));
    t.write(t.at("real_homes/alice/.ssh/authorized_keys"), kAliceKey);
    t.write(t.at("elsewhere/secret"), "outside");
    fs::create_directory_symlink(t.at("elsewhere"), t.at("real_homes/evil"));
    fs::create_directory_symlink(t.at("real_homes"), t.at("homes"));
    fs::create_directories(t.at("realroot"));
    fs::create_directory_symlink(t.at("realroot"), t.at("rootlink"));

    auto p = t.paths();
    p.home_parents = {t.at("homes").string()};
    p.single_homes = {t.at("rootlink").string()};
    p.run = service_enabled;
    const auto b = make_posix_fs(p);
    REQUIRE(b.resolve_root);

    SECTION("the link names its target; a single home is a home and stays as written") {
        CHECK(b.resolve_root(t.at("homes").string()) == t.at("real_homes").string());
        CHECK(b.resolve_root(t.at("rootlink").string()) == t.at("rootlink").string());
    }
    SECTION("the resolved root lists alice and bob, and alice's key is read through the one hop") {
        std::vector<std::string> roots;
        for (const auto& r : b.home_roots)
            roots.push_back(b.resolve_root(r));
        std::vector<HomeEntry> homes;
        bool too_many = false;
        REQUIRE(b.list_homes(roots, homes, too_many) == 0);
        std::vector<std::string> names;
        for (const auto& h : homes)
            names.push_back(h.name);
        CHECK(names == std::vector<std::string>{"alice", "bob", "evil", "rootlink"});
        const auto find = [&](const std::string& n) { return *std::ranges::find(homes, n, &HomeEntry::name); };
        CHECK(find("alice").path == t.at("real_homes/alice").string()); // the real path, by construction
        REQUIRE(b.open_home(find("alice")) == 0);
        const auto k = b.read_key_file({".ssh", "authorized_keys"});
        CHECK(k.error == ReadErr::none);
        CHECK(k.data == kAliceKey);
        CHECK(b.open_home(find("evil")) != 0);     // a symlinked ENTRY is still refused
        CHECK(b.open_home(find("rootlink")) != 0); // a single home is a home, not a parent: no-follow
    }
    SECTION("the lister never follows the unresolved alias itself") {
        std::vector<HomeEntry> homes;
        bool too_many = false;
        CHECK(b.list_homes({t.at("homes").string()}, homes, too_many) == ELOOP);
        CHECK(homes.empty());
    }
    SECTION("the whole listing reads alice's key") {
        const auto l = list_posix(b);
        CHECK(std::ranges::find(l.rows, "file|alice|authorized_keys|read|1|0|0") != l.rows.end());
        const auto key = std::ranges::find_if(l.rows, [](const std::string& r) { return r.rfind("key|alice|", 0) == 0; });
        REQUIRE(key != l.rows.end());
        CHECK(key->find(kAliceFp) != std::string::npos);
        CHECK(std::ranges::find(l.rows, "source|homes|read|4|-") != l.rows.end()); // alice, bob, evil, rootlink
        CHECK(std::ranges::find(l.rows, "file|evil|authorized_keys|failed|-|-|-") != l.rows.end()); // refused, never followed
        // the linked entries are reported (ELOOP or ENOTDIR by OS); the linked PARENT raised no refusal
        CHECK(l.reason.find("linux:remote_access_audit:homes:") != std::string::npos);
    }
}

TEST_CASE("remote_access_audit posix fs: a home parent linked into a network mount is skipped before anything is opened",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    t.write(t.at("network/alice/.ssh/authorized_keys"), kAliceKey);
    fs::create_directory_symlink(t.at("network"), t.at("homes"));
    auto p = t.paths();
    p.home_parents = {t.at("homes").string()};
    p.single_homes = {};
    p.mounts = [net = t.at("network").string()] {
        return std::optional<std::vector<std::string>>{std::vector<std::string>{net}};
    };
    p.run = service_enabled;
    const auto b = make_posix_fs(p);
    // the alias is not under the mount; its readlink target is
    CHECK(b.resolve_root(t.at("homes").string()) == t.at("network").string());

    const auto l = list_posix(b);
    CHECK(l.reason.find("linux:remote_access_audit:keys:network_mount_skipped") != std::string::npos);
    CHECK(l.status == StatusState::constrained);
    CHECK(std::ranges::find(l.rows, "source|homes|absent|-|-") != l.rows.end()); // never listed, so never read
    for (const auto& r : l.rows)
        CHECK(r.find("alice") == std::string::npos); // nothing under the target was listed, opened or read
}

TEST_CASE("remote_access_audit posix fs: a link chain or a linked component under a home parent is refused, not walked",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    t.write(t.at("real_homes/alice/.ssh/authorized_keys"), kAliceKey);
    auto p = t.paths();
    p.single_homes = {};
    p.run = service_enabled;
    const auto refused_loudly = [&](const Listing& l) {
        CHECK(std::ranges::find(l.rows, "source|homes|failed|-|-") != l.rows.end());
        CHECK(l.reason.find("linux:remote_access_audit:homes:eloop") != std::string::npos);
        CHECK(l.status == StatusState::constrained);
        for (const auto& r : l.rows)
            CHECK(r.find("alice") == std::string::npos);
    };

    SECTION("a chain: homes -> h2 -> real_homes resolves one hop and then refuses the second") {
        fs::create_directory_symlink(t.at("real_homes"), t.at("h2"));
        fs::create_directory_symlink(t.at("h2"), t.at("homes"));
        p.home_parents = {t.at("homes").string()};
        const auto b = make_posix_fs(p);
        CHECK(b.resolve_root(t.at("homes").string()) == t.at("h2").string());
        refused_loudly(list_posix(b));
    }
    SECTION("a linked intermediate component: lnk/homes with lnk -> real") {
        fs::create_directories(t.at("real/homes/alice/.ssh"));
        t.write(t.at("real/homes/alice/.ssh/authorized_keys"), kAliceKey);
        fs::create_directory_symlink(t.at("real"), t.at("lnk"));
        p.home_parents = {t.at("lnk/homes").string()};
        const auto b = make_posix_fs(p);
        refused_loudly(list_posix(b));
    }
}

TEST_CASE("remote_access_audit posix fs: a single home reached through an aliased ancestor is refused, not matched or walked",
          "[remote_access_audit][posix_fs]") {
    // The macOS shape: /var is a link to private/var, getmntinfo names the CANONICAL spelling,
    // and the configured home is spelled through the link. The configured spelling can never
    // match the mount table, so the open itself must refuse the link. RECONSTRUCTION: the
    // target is named by the run-start mount table and holds a valid key.
    Tree t;
    t.write(t.at("real/root/.ssh/authorized_keys"), kAliceKey);
    fs::create_directory_symlink(t.at("real"), t.at("alias"));
    const auto net = [&] {
        return std::optional<std::vector<std::string>>{std::vector<std::string>{t.at("real/root").string()}};
    };
    auto p = t.paths();
    p.home_parents = {};
    p.run = service_enabled;
    p.mounts = net;
    const auto no_key_read = [&](const Listing& l) {
        for (const auto& r : l.rows) {
            CHECK(r.find(kAliceFp) == std::string::npos);
            CHECK(r.rfind("key|", 0) != 0);
            if (r.rfind("file|", 0) == 0) // a file row that read one key (the homes source row also says `read|1|`)
                CHECK(r.find("|read|1|") == std::string::npos);
        }
        CHECK(l.status == StatusState::constrained);
    };

    SECTION("the aliased spelling opens hop by hop, answers ELOOP, and reads nothing") {
        p.single_homes = {t.at("alias/root").string()};
        const auto b = make_posix_fs(p);
        CHECK(b.open_home({"root", t.at("alias/root").string()}) == ELOOP);
        const auto l = list_posix(b);
        no_key_read(l);
        CHECK(std::ranges::find(l.rows, "file|root|authorized_keys|failed|-|-|-") != l.rows.end());
        CHECK(l.reason.find("linux:remote_access_audit:homes:eloop") != std::string::npos);
    }
    SECTION("the canonical spelling is matched by the mount guard and never opened") {
        p.single_homes = {t.at("real/root").string()};
        const auto l = list_posix(make_posix_fs(p));
        no_key_read(l);
        CHECK(std::ranges::find(l.rows, "source|homes|absent|-|-") != l.rows.end()); // never listed, so never opened
        CHECK(l.reason.find("linux:remote_access_audit:keys:network_mount_skipped") != std::string::npos);
    }
    SECTION("the canonical spelling off any mount is read") {
        p.single_homes = {t.at("real/root").string()};
        p.mounts = [] { return std::optional<std::vector<std::string>>{std::vector<std::string>{}}; };
        const auto l = list_posix(make_posix_fs(p));
        CHECK(std::ranges::find(l.rows, "file|root|authorized_keys|read|1|0|0") != l.rows.end());
    }
}

TEST_CASE("remote_access_audit posix fs: resolve_root normalises a relative target and leaves everything else as written",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    fs::create_directories(t.at("var/home"));
    fs::create_directories(t.at("sub"));
    fs::create_directories(t.at("plain"));
    fs::create_directories(t.at("rootsingle"));
    fs::create_directory_symlink("var/home", t.at("homeRel"));        // the /home -> var/home shape
    fs::create_directory_symlink("../var/home/", t.at("sub/up"));     // dot-dot and a trailing slash
    fs::create_directory_symlink(t.at("rootsingle"), t.at("singlelink"));
    auto p = t.paths();
    p.single_homes = {t.at("singlelink").string()};
    const auto b = make_posix_fs(p);

    CHECK(b.resolve_root(t.at("homeRel").string()) == t.at("var/home").string());
    CHECK(b.resolve_root(t.at("sub/up").string()) == t.at("var/home").string());
    CHECK(b.resolve_root(t.at("plain").string()) == t.at("plain").string());               // not a link
    CHECK(b.resolve_root(t.at("singlelink").string()) == t.at("singlelink").string());     // a single home
    CHECK(b.resolve_root(t.at("absent").string()) == t.at("absent").string());             // lstat fails
}

TEST_CASE("remote_access_audit posix fs: an absolute key path outside any home is read by path, no link followed anywhere in it",
          "[remote_access_audit][posix_fs]") {
    Tree t;
    t.write(t.at("keys/shared"), "k");
    t.write(t.at("protected/shared"), "secret");
    fs::create_symlink(t.at("keys/shared"), t.at("keys/link"));
    fs::create_directory_symlink(t.at("protected"), t.at("keys/dirlink"));
    const auto b = make_posix_fs(t.paths());
    CHECK(b.read_key_file_abs(t.at("keys/shared").string()).data == "k");
    CHECK(b.read_key_file_abs(t.at("keys/link").string()).error == ReadErr::symlink_refused); // a leaf link
    CHECK(b.read_key_file_abs(t.at("keys/none").string()).err == ENOENT);
    // an INTERMEDIATE link is refused too (ELOOP on every OS), never walked to the target's file
    const auto via_dir = b.read_key_file_abs(t.at("keys/dirlink/shared").string());
    CHECK(via_dir.error == ReadErr::symlink_refused);
    CHECK(via_dir.data.empty());
    // a relative path and a path with no leaf name are refused as invalid, not resolved against the cwd
    CHECK(b.read_key_file_abs("keys/shared").err == EINVAL);
    CHECK(b.read_key_file_abs("/").err == EINVAL);
}

TEST_CASE("remote_access_audit posix fs: an absolute AuthorizedKeysFile through a subject-writable link is refused for the other account",
          "[remote_access_audit][posix_fs]") {
    // The two-account shape: alice's home holds `link -> protected`. sshd_config names
    // <home>/alice/link/keys; for alice it is home-relative, for bob it is absolute. Neither may
    // follow the link to the file the subject could not otherwise reach.
    Tree t;
    t.write(t.at("sshd_config"), "AuthorizedKeysFile " + t.at("home/alice/link/keys").string() + "\n");
    t.write(t.at("protected/keys"), kAliceKey);
    fs::create_directories(t.at("home/alice"));
    fs::create_directories(t.at("home/bob"));
    fs::create_directory_symlink(t.at("protected"), t.at("home/alice/link"));
    auto p = t.paths();
    p.single_homes = {};
    p.run = service_enabled;
    p.mounts = [net = t.at("protected").string()] {
        return std::optional<std::vector<std::string>>{std::vector<std::string>{net}};
    };
    const auto l = list_posix(make_posix_fs(p));
    for (const auto& r : l.rows)
        CHECK(r.find(kAliceFp) == std::string::npos); // the protected file's fingerprint never appears
    CHECK(std::ranges::find_if(l.rows, [](const std::string& r) { return r.rfind("key|", 0) == 0; }) == l.rows.end());
    CHECK(std::ranges::find(l.rows, "file|alice|custom|failed|-|-|-") != l.rows.end());
    CHECK(std::ranges::find(l.rows, "file|bob|custom|failed|-|-|-") != l.rows.end()); // absolute arm: failed, not read
    CHECK(l.reason.find("linux:remote_access_audit:keys:symlink_refused") != std::string::npos);
    CHECK(l.status == StatusState::constrained);
}

TEST_CASE("remote_access_audit posix fs: an unnormalised absolute AuthorizedKeysFile cannot slip past the network-mount guard",
          "[remote_access_audit][posix_fs]") {
    // The mount table names <root>/protected. `//`, `/./` and a trailing `/` are the same
    // file to the kernel; they must be the same string to the guard, so none is opened.
    Tree t;
    const std::string root = t.root.string();
    t.write(t.at("sshd_config"), "AuthorizedKeysFile " + root + "//protected/keys " + root + "/./protected/keys " +
                                     root + "/protected/keys/\n");
    t.write(t.at("protected/keys"), kAliceKey);
    fs::create_directories(t.at("home/alice"));
    fs::create_directories(t.at("home/bob"));
    auto p = t.paths();
    p.single_homes = {};
    p.run = service_enabled;
    p.mounts = [net = t.at("protected").string()] {
        return std::optional<std::vector<std::string>>{std::vector<std::string>{net}};
    };
    const auto l = list_posix(make_posix_fs(p));
    CHECK(std::ranges::find_if(l.rows, [](const std::string& r) { return r.rfind("key|", 0) == 0; }) == l.rows.end());
    for (const auto& r : l.rows)
        CHECK(r.find(kAliceFp) == std::string::npos);
    for (const char* who : {"alice", "bob"}) {
        const auto failed = std::string("file|") + who + "|custom|failed|-|-|-";
        CHECK(std::ranges::count(l.rows, failed) == 3); // one per spelling, none read
    }
    CHECK(l.reason.find("linux:remote_access_audit:keys:network_mount_skipped") != std::string::npos);
    CHECK(l.status == StatusState::constrained);
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

    // The bound: a table over the cap is unreadable (the guard then reports mounts_unreadable),
    // never a silently truncated list. The cap is a parameter so the boundary needs no big file.
    std::string dense;
    while (dense.size() < 6000)
        dense += "40 36 0:35 / /home/remote rw,relatime shared:5 - nfs4 srv:/export rw,vers=4.2\n";
    t.write(t.at("dense"), dense);
    CHECK_FALSE(linux_mountinfo_prefixes(t.at("dense").string(), 4096).has_value());
    const auto fits = linux_mountinfo_prefixes(t.at("dense").string(), 8192);
    REQUIRE(fits.has_value());
    CHECK(fits->size() == dense.size() / std::string{"40 36 0:35 / /home/remote rw,relatime shared:5 - nfs4 srv:/export rw,vers=4.2\n"}.size());
    // MUTATION: restoring the old 1 MiB default drops a container-dense node's guard entirely.
    // The default holds fs.mount-max (100,000 mounts at ~160 bytes a line) in full.
    static_assert(kMountinfoCap >= 100000 * 160);
}

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
    CHECK(l.rows[1] == "source|homes|read|2|-");
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
