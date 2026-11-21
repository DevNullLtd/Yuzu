/**
 * test_component_fs_posix.cpp -- tests for the POSIX leg of the component_inventory filesystem seam
 * (agents/plugins/component_inventory/src/component_fs_posix.cpp, component_legs.hpp). Real syscalls
 * against a real temporary tree only: no process spawn, no sleeps, no live mount table. The races a
 * link-planting account could win are staged in two explicit steps (list, replace, then the second
 * call), never by timing.
 *
 * The temporary tree is resolved with realpath-equivalent canonicalisation first: the system temp
 * directory is itself reached through a link on macOS (/var -> /private/var), and a leg that follows
 * no link would otherwise refuse the test's own root.
 *
 * The mount table is driven through read_mountinfo_stream and scan_targets(candidates, reader) with
 * scripted reads, so a read that fails part-way (EIO after a chunk of local mounts) is exercised
 * through the same code the live /proc reader runs, not just as a boolean handed to plan_targets. The
 * candidate roots are injected too: the cases open directories of their own temporary tree and never
 * the host's real machine roots (only candidate_roots() itself is read, for its list).
 *
 * MUTATION NOTES (each assertion below FAILS if the named wiring is removed):
 *  - returning what read_mountinfo_stream has accumulated when a read fails (instead of nullopt) fails
 *    the part-way-failure cases: the scan would plan against a table missing the network mounts.
 *  - dropping the total-size guard in read_mountinfo_stream (or checking it with >= instead of >) fails the
 *    boundary case: a table of exactly max_total passes, one byte more is nullopt, never the part read.
 *  - length-checking only the unfinished tail of the stream (not each completed line) fails the
 *    over-limit-line case whose newline arrives in the same read as its last bytes.
 *  - opening a directory by its joined path instead of hop by hop fails the intermediate-link cases
 *    (the link is followed and the secret under its target is listed / opened).
 *  - dropping the network-mount check from classify_dirent() or from the hop loop fails the `log` assertions
 *    (the mount point is stat'ed or opened) and the typed-network_mount assertions.
 *  - dropping the S_ISLNK probe from the failing hop makes a linked root read as merely missing and
 *    fails the roots_link_skipped counts.
 *  - replacing the descriptor compare in unchanged() with nothing fails the append and time cases.
 *  - adding, dropping or renaming a machine root in candidate_roots() fails the exact-set case.
 */
#if !defined(_WIN32)

#include <catch2/catch_test_macros.hpp>

#include "test_helpers.hpp"

#include "component_legs.hpp"
#include "component_walk.hpp"

#include <network_fstype.hpp>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace yuzu::component_inventory;
using namespace std::chrono_literals;
using Type = DirEntry::Type;

namespace {

void write_file(const fs::path& p, const std::string& body) {
    std::ofstream f(p, std::ios::binary);
    f << body;
}

struct Tree {
    yuzu::test::TempDir tmp{"yuzu_test_cfp_"};
    fs::path root; // canonical: no component of it is a link

    Tree() {
        REQUIRE(fs::create_directory(tmp.path));
        root = fs::canonical(tmp.path);
    }
};

[[nodiscard]] std::map<std::string, Type> by_name(const ListResult& r) {
    std::map<std::string, Type> m;
    for (const auto& e : r.entries)
        m[e.name] = e.type;
    return m;
}

[[nodiscard]] FsOps plain_ops() {
    return make_fs_ops(Targets{});
}

constexpr std::size_t kMiB = 1024 * 1024;
const std::string kLocalMount = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n";
const std::string kNfsMount = "40 22 0:40 / /opt/share rw,relatime shared:5 - nfs4 srv:/x rw\n";

// A mount table served in reads of at most `slice` bytes, then end of table (err == 0) or a failed
// read with errno = err.
[[nodiscard]] ReadChunk serve(std::string table, std::size_t slice, int err = 0) {
    return [table = std::move(table), pos = std::size_t{0}, slice, err](char* buf, std::size_t len) mutable -> ssize_t {
        if (pos >= table.size()) {
            if (err == 0)
                return 0;
            errno = err;
            return -1;
        }
        const std::size_t n = std::min({slice, len, table.size() - pos});
        std::memcpy(buf, table.data() + pos, n);
        pos += n;
        return static_cast<ssize_t>(n);
    };
}

[[nodiscard]] MountTableReader table_of(ReadChunk rc) {
    return [rc = std::move(rc)] { return read_mountinfo_stream(rc); };
}

struct Fd {
    int fd;
    explicit Fd(const fs::path& dir) : fd(::open(dir.c_str(), O_RDONLY | O_DIRECTORY)) {}
    ~Fd() {
        if (fd >= 0)
            ::close(fd);
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};

[[nodiscard]] struct dirent entry(const char* name, unsigned char d_type) {
    struct dirent e {};
    std::strncpy(e.d_name, name, sizeof e.d_name - 1);
    e.d_type = d_type;
    return e;
}

} // namespace

TEST_CASE("component_legs: candidate_roots are absolute, unslashed machine roots",
          "[runtime][component_inventory][legs]") {
    // The machine allowlist of installed_software_v3.cpp keeps /opt, /usr, /Applications, /Library.
    const auto roots = candidate_roots();
    CHECK_FALSE(roots.empty());
    for (const auto& r : roots) {
        INFO("root=" << r);
        REQUIRE(r.size() > 1);
        CHECK(r.front() == '/');
        CHECK(r.back() != '/');
        const bool allowed = r.starts_with("/opt") || r.starts_with("/usr/") || r.starts_with("/Applications") ||
                             r.starts_with("/Library");
        CHECK(allowed);
    }
}

TEST_CASE("component_legs: candidate_roots is exactly the documented machine-root set for this OS",
          "[runtime][component_inventory][legs]") {
    // The machine-scope boundary of ADR-0028 Decision 1, copied by hand into the README, the user
    // manual, the privilege model, the definition and the descriptor: a root added or dropped here
    // must change this list and those documents together.
#if defined(__APPLE__)
    // In walk order, which is part of the contract: cheap roots first, because the walk has one entry
    // budget and /Applications (macOS) or /opt (Linux) can spend all of it.
    const std::vector<std::string> want{"/Library/Java", "/usr/local", "/opt/homebrew", "/Applications"};
#else
    const std::vector<std::string> want{"/usr/lib/jvm",     "/usr/share/java",  "/usr/share/maven",
                                        "/usr/local/lib", "/usr/local/share", "/opt"};
#endif
    CHECK(candidate_roots() == want);
}

TEST_CASE("component_legs: plan_targets drops a root on or under a network mount",
          "[runtime][component_inventory][legs]") {
    SECTION("a root ON a network mount is dropped and counted") {
        const auto t = plan_targets({"/opt", "/usr/lib/jvm"}, {"/opt"}, true);
        CHECK(t.roots == std::vector<std::string>{"/usr/lib/jvm"});
        CHECK(t.roots_network_skipped == 1);
        CHECK(t.network_mounts.empty());
        CHECK_FALSE(t.mount_table_unreadable);
    }
    SECTION("a root UNDER a network mount is dropped and counted") {
        const auto t = plan_targets({"/mnt/nfs/java"}, {"/mnt/nfs"}, true);
        CHECK(t.roots.empty());
        CHECK(t.roots_network_skipped == 1);
        CHECK(t.network_mounts.empty());
    }
    SECTION("a root ABOVE a network mount is kept and the mount is guarded") {
        const auto t = plan_targets({"/opt"}, {"/opt/share", "/srv/elsewhere"}, true);
        CHECK(t.roots == std::vector<std::string>{"/opt"});
        CHECK(t.roots_network_skipped == 0);
        CHECK(t.network_mounts == std::vector<std::string>{"/opt/share"});
    }
    SECTION("the match is on whole segments") {
        const auto t = plan_targets({"/opt/java2", "/optical"}, {"/opt/java", "/opt"}, true);
        // /optical is not under /opt and /opt/java2 is not under /opt/java; but /opt/java2 IS under /opt.
        CHECK(t.roots == std::vector<std::string>{"/optical"});
        CHECK(t.roots_network_skipped == 1);
        const auto u = plan_targets({"/opt/java2"}, {"/opt/java"}, true);
        CHECK(u.roots == std::vector<std::string>{"/opt/java2"});
        CHECK(u.network_mounts.empty());
    }
    SECTION("a mount point with a trailing slash or empty is normalised, a duplicate is kept once") {
        const auto t = plan_targets({"/opt"}, {"/opt/share/", "", "/opt/share"}, true);
        CHECK(t.roots == std::vector<std::string>{"/opt"});
        CHECK(t.network_mounts == std::vector<std::string>{"/opt/share"});
    }
    SECTION("a network-mounted / drops every root") {
        const auto t = plan_targets({"/opt", "/usr/lib/jvm"}, {"/"}, true);
        CHECK(t.roots.empty());
        CHECK(t.roots_network_skipped == 2);
    }
    SECTION("no mounts keeps every root") {
        const auto t = plan_targets({"/opt", "/usr/lib/jvm"}, {}, true);
        CHECK(t.roots.size() == 2);
        CHECK(t.roots_network_skipped == 0);
        CHECK_FALSE(t.mount_table_unreadable);
    }
}

TEST_CASE("component_legs: an unreadable mount table yields no roots and says so",
          "[runtime][component_inventory][legs]") {
    // MUTATION: treating table_ok == false as "no mounts" would walk with no guard at all.
    const auto t = plan_targets({"/opt", "/usr/lib/jvm"}, {"/opt"}, false);
    CHECK(t.mount_table_unreadable);
    CHECK(t.roots.empty());
    CHECK(t.network_mounts.empty());
    CHECK(t.roots_network_skipped == 0);
    CHECK(t.roots_link_skipped == 0);
}

TEST_CASE("component_legs: read_mountinfo_stream finds the network mounts however the table is cut into reads",
          "[runtime][component_inventory][legs]") {
    const std::string table = kLocalMount + kNfsMount;
    const std::vector<std::string> want{"/opt/share"};
    CHECK(read_mountinfo_stream(serve(table, 4096)) == want);
    // A line split across reads, one byte at a time.
    CHECK(read_mountinfo_stream(serve(table, 1)) == want);
    // No trailing newline on the last line.
    CHECK(read_mountinfo_stream(serve(kLocalMount + kNfsMount.substr(0, kNfsMount.size() - 1), 7)) == want);
    // Only local mounts: readable, and nothing to guard.
    const auto local = read_mountinfo_stream(serve(kLocalMount, 4096));
    REQUIRE(local.has_value());
    CHECK(local->empty());

    // An interrupted read is retried, not a failure.
    auto inner = serve(table, 4096);
    bool interrupted = false;
    const auto eintr_once = [&](char* buf, std::size_t len) -> ssize_t {
        if (!interrupted) {
            interrupted = true;
            errno = EINTR;
            return -1;
        }
        return inner(buf, len);
    };
    CHECK(read_mountinfo_stream(eintr_once) == want);
}

TEST_CASE("component_legs: a mount table that fails part-way is unreadable, never the part read so far",
          "[runtime][component_inventory][legs]") {
    // MUTATION: returning the accumulated vector on a failed read hands back a table missing the
    // network mounts that follow, and the scan would walk into them.
    SECTION("a chunk of local mounts, then EIO, with an NFS mount still unread") {
        CHECK_FALSE(read_mountinfo_stream(serve(kLocalMount, 4096, EIO)).has_value());
    }
    SECTION("a chunk that already named a network mount, then EIO") {
        CHECK_FALSE(read_mountinfo_stream(serve(kNfsMount + kLocalMount, 4096, EIO)).has_value());
    }
    SECTION("a failure on the very first read") {
        CHECK_FALSE(read_mountinfo_stream(serve("", 4096, EIO)).has_value());
    }
}

TEST_CASE("component_legs: a mount-table line over 1 MiB is a failure however it arrives",
          "[runtime][component_inventory][legs]") {
    // MUTATION: checking only the unfinished tail accepts the second case (the newline arrives in the
    // same read as the last bytes, so the line is complete before any tail check sees it).
    SECTION("exactly 1 MiB is accepted, and a mount after it is still read") {
        const auto got = read_mountinfo_stream(serve(std::string(kMiB, 'x') + "\n" + kNfsMount, 64 * 1024));
        REQUIRE(got.has_value());
        CHECK(*got == std::vector<std::string>{"/opt/share"});
    }
    SECTION("1 MiB + 1 completed by a short final read") {
        CHECK_FALSE(read_mountinfo_stream(serve(std::string(kMiB + 1, 'x') + "\n", 64 * 1024)).has_value());
    }
    SECTION("1 MiB + 1 completed in the middle of a read that carries further lines") {
        CHECK_FALSE(
            read_mountinfo_stream(serve(std::string(kMiB + 1, 'x') + "\n" + kLocalMount, 64 * 1024)).has_value());
    }
    SECTION("1 MiB + 1 with no newline at all") {
        CHECK_FALSE(read_mountinfo_stream(serve(std::string(kMiB + 1, 'x'), 64 * 1024)).has_value());
    }
}

TEST_CASE("component_legs: a mount table past the total ceiling is a failure, never the part read so far",
          "[runtime][component_inventory][legs]") {
    // The ceiling is a defaulted parameter so the boundary is tested at the table's own size.
    const std::string table = kNfsMount + kLocalMount;
    // The NFS line is parsed before the last read, so a nullopt here also proves the part read so far
    // is never returned.
    const auto at = read_mountinfo_stream(serve(table, 7), table.size());
    REQUIRE(at.has_value());
    CHECK(*at == std::vector<std::string>{"/opt/share"});
    CHECK_FALSE(read_mountinfo_stream(serve(table, 7), table.size() - 1).has_value());
}

TEST_CASE("component_legs: scan_targets over a table that fails part-way yields no roots and touches nothing",
          "[runtime][component_inventory][legs]") {
    Tree tree;
    REQUIRE(fs::create_directories(tree.root / "app"));
    const std::vector<std::string> cands{(tree.root / "app").string()};
    std::vector<std::string> log;
    const auto on_access = [&log](const std::string& p) { log.push_back(p); };

    // The production acquisition path: partial read, then EIO, then planning.
    const auto t = scan_targets(cands, table_of(serve(kLocalMount, 4096, EIO)), on_access);
    CHECK(t.mount_table_unreadable);
    CHECK(t.roots.empty());
    CHECK(t.network_mounts.empty());
    CHECK(t.roots_network_skipped == 0);
    CHECK(t.roots_link_skipped == 0);
    CHECK(log.empty()); // no candidate root was opened

    // The reader that reports nullopt itself (the macOS shape) is the same.
    const auto u = scan_targets(
        cands, []() -> std::optional<std::vector<std::string>> { return std::nullopt; }, on_access);
    CHECK(u.mount_table_unreadable);
    CHECK(u.roots.empty());
    CHECK(log.empty());

    // Control: the same stream read in full plans the candidate, and opens it.
    const auto ok = scan_targets(cands, table_of(serve(kLocalMount, 4096)), on_access);
    CHECK_FALSE(ok.mount_table_unreadable);
    CHECK(ok.roots == cands);
    CHECK_FALSE(log.empty());
}

TEST_CASE("component_legs: scan_targets drops a candidate root on a mount named by the stream, unopened",
          "[runtime][component_inventory][legs]") {
    Tree tree;
    REQUIRE(fs::create_directories(tree.root / "local"));
    REQUIRE(fs::create_directories(tree.root / "shared" / "sub"));
    const std::string local = (tree.root / "local").string();
    const std::string shared = (tree.root / "shared").string();
    std::vector<std::string> log;
    const auto t = scan_targets(
        {local, shared},
        table_of(serve(kLocalMount + "41 22 0:41 / " + shared + " rw - nfs4 srv:/y rw\n", 100)),
        [&log](const std::string& p) { log.push_back(p); });
    CHECK_FALSE(t.mount_table_unreadable);
    CHECK(t.roots_network_skipped == 1);
    CHECK(t.roots == std::vector<std::string>{local});
    CHECK_FALSE(log.empty()); // the local candidate was opened
    CHECK(std::ranges::none_of(log, [&](const std::string& p) { return p == shared || p.starts_with(shared + "/"); }));
}

TEST_CASE("component_legs: a root reached through a link at any component is dropped and counted",
          "[runtime][component_inventory][legs]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "real" / "lib"));
    fs::create_directory_symlink(t.root / "real", t.root / "linked");           // intermediate component
    fs::create_directory_symlink(t.root / "real" / "lib", t.root / "leaf_link"); // the root itself
    write_file(t.root / "file", "x");

    const auto ok = (t.root / "real" / "lib").string();
    auto targets = plan_targets({(t.root / "leaf_link").string(), (t.root / "linked" / "lib").string(),
                                 (t.root / "missing").string(), (t.root / "file").string(), ok},
                                {}, true);
    REQUIRE(targets.roots.size() == 5);
    drop_unreachable_roots(targets);

    CHECK(targets.roots == std::vector<std::string>{ok});
    // The leaf link and the intermediate link are counted; the missing root and the plain file are not.
    CHECK(targets.roots_link_skipped == 2);
    CHECK(targets.roots_network_skipped == 0);
}

TEST_CASE("component_legs: a root that cannot be opened for another reason stays, so the walk reports it",
          "[runtime][component_inventory][legs]") {
    if (::geteuid() == 0)
        SKIP("root bypasses mode bits");
    Tree t;
    REQUIRE(fs::create_directories(t.root / "locked" / "inner"));
    REQUIRE(::chmod((t.root / "locked").c_str(), 0) == 0);
    const auto root = (t.root / "locked" / "inner").string();

    auto targets = plan_targets({root}, {}, true);
    drop_unreachable_roots(targets);
    const bool kept = targets.roots == std::vector<std::string>{root};
    const auto listing = make_fs_ops(targets).list(root, 100);
    ::chmod((t.root / "locked").c_str(), 0700); // so the TempDir can remove it

    CHECK(kept);
    CHECK(targets.roots_link_skipped == 0);
    CHECK(listing.error);
}

TEST_CASE("component_fs_posix: list types every entry from d_type", "[runtime][component_inventory][fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "d" / "sub"));
    write_file(t.root / "d" / "a.jar", "a");
    fs::create_directory_symlink(t.root / "d" / "sub", t.root / "d" / "dir_link");
    fs::create_symlink(t.root / "d" / "a.jar", t.root / "d" / "file_link");
    REQUIRE(::mkfifo((t.root / "d" / "pipe").c_str(), 0600) == 0);

    const auto ops = plain_ops();
    const auto r = ops.list((t.root / "d").string(), 100);
    CHECK_FALSE(r.error);
    CHECK_FALSE(r.truncated);
    CHECK(by_name(r) == std::map<std::string, Type>{{"a.jar", Type::file},
                                                    {"sub", Type::dir},
                                                    {"dir_link", Type::link},
                                                    {"file_link", Type::link},
                                                    {"pipe", Type::other}});

    // The cap cuts the listing and says so.
    const auto cut = ops.list((t.root / "d").string(), 2);
    CHECK_FALSE(cut.error);
    CHECK(cut.entries.size() == 2);
    CHECK(cut.truncated);
}

TEST_CASE("component_fs_posix: list returns entries sorted by name", "[runtime][component_inventory][fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "d"));
    for (const char* n :
         {"m.jar", "c.jar", "x.jar", "a.jar", "t.jar", "f.jar", "z.jar", "b.jar", "q.jar", "h.jar", "k.jar"})
        write_file(t.root / "d" / n, "x");

    const auto r = plain_ops().list((t.root / "d").string(), 100);
    CHECK_FALSE(r.error);
    CHECK(r.entries.size() == 11);
    // MUTATION: without the sort in the listing this fails wherever readdir is not name-ordered (APFS),
    // and the scan-wide caps would cut different rows on the same tree.
    CHECK(std::ranges::is_sorted(r.entries, {}, &DirEntry::name));
}

TEST_CASE("component_fs_posix: list refuses a path that is missing, relative or holds a NUL",
          "[runtime][component_inventory][fs_posix]") {
    Tree t;
    const auto ops = plain_ops();
    CHECK(ops.list((t.root / "nope").string(), 100).error);
    CHECK(ops.list("relative/path", 100).error);
    CHECK(ops.list(std::string("/tmp\0junk", 9), 100).error);
    CHECK(ops.list("", 100).error);
    CHECK_FALSE(ops.open_file("relative.jar").has_value());
    CHECK_FALSE(ops.open_file(std::string("/tmp/a\0b.jar", 12)).has_value());
    CHECK_FALSE(ops.open_file((t.root / "nope.jar").string()).has_value());
}

TEST_CASE("component_fs_posix: a directory swapped for a link after its listing is refused",
          "[runtime][component_inventory][fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "app" / "sub"));
    REQUIRE(fs::create_directories(t.root / "app" / "inner"));
    REQUIRE(fs::create_directories(t.root / "elsewhere"));
    write_file(t.root / "elsewhere" / "secret.jar", "S");
    write_file(t.root / "app" / "inner" / "kept.jar", "K");

    const auto ops = plain_ops();
    const auto app = (t.root / "app").string();

    // Step 1: the listing says `sub` is a directory.
    CHECK(by_name(ops.list(app, 100)).at("sub") == Type::dir);

    // Step 2: the directory is replaced by a link to somewhere else, then listed itself.
    fs::remove_all(t.root / "app" / "sub");
    fs::create_directory_symlink(t.root / "elsewhere", t.root / "app" / "sub");
    const auto swapped = ops.list((t.root / "app" / "sub").string(), 100);
    CHECK(swapped.error);
    CHECK(swapped.entries.empty()); // nothing under the link's target

    // A link ABOVE the directory is refused too, at an intermediate component.
    fs::create_directory_symlink(t.root / "app", t.root / "app_link");
    const auto via_link = ops.list((t.root / "app_link" / "inner").string(), 100);
    CHECK(via_link.error);
    CHECK(via_link.entries.empty());
    CHECK(ops.list((t.root / "app_link").string(), 100).error); // and at the leaf
    // Control: the real path still lists.
    CHECK(by_name(ops.list((t.root / "app" / "inner").string(), 100)).at("kept.jar") == Type::file);
}

TEST_CASE("component_fs_posix: a file swapped for a link after its listing is not opened",
          "[runtime][component_inventory][fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "app"));
    write_file(t.root / "app" / "a.jar", "AAAA");
    write_file(t.root / "other.jar", "BBBB");
    fs::create_directory(t.root / "app" / "dir.jar");
    REQUIRE(::mkfifo((t.root / "app" / "pipe.jar").c_str(), 0600) == 0);

    const auto ops = plain_ops();
    const auto path = (t.root / "app" / "a.jar").string();

    // Step 1: the listing says `a.jar` is a file, and it opens.
    CHECK(by_name(ops.list((t.root / "app").string(), 100)).at("a.jar") == Type::file);
    CHECK(ops.open_file(path).has_value());

    // Step 2: the file is replaced by a link to another file, then opened.
    fs::remove(t.root / "app" / "a.jar");
    fs::create_symlink(t.root / "other.jar", t.root / "app" / "a.jar");
    CHECK_FALSE(ops.open_file(path).has_value());

    // A link above the file is refused, and so are a directory and a FIFO (which must not hang).
    fs::create_directory_symlink(t.root / "app", t.root / "app_link");
    CHECK_FALSE(ops.open_file((t.root / "app_link" / "dir.jar").string()).has_value());
    CHECK_FALSE(ops.open_file((t.root / "app" / "dir.jar").string()).has_value());
    CHECK_FALSE(ops.open_file((t.root / "app" / "pipe.jar").string()).has_value());
    // Control: a plain file opens.
    CHECK(ops.open_file((t.root / "other.jar").string()).has_value());
}

TEST_CASE("component_fs_posix: read_at serves ranges from one descriptor", "[runtime][component_inventory][fs_posix]") {
    Tree t;
    std::string body(40000, '\0');
    for (std::size_t i = 0; i < body.size(); ++i)
        body[i] = static_cast<char>('a' + (i * 7) % 26);
    const auto path = (t.root / "big.bin").string();
    write_file(path, body);

    const auto ops = plain_ops();
    auto v = ops.open_file(path);
    REQUIRE(v.has_value());
    CHECK(v->size == 40000);
    CHECK(v->mtime > 0);

    const auto read = [&](std::uint64_t off, std::size_t len) { return v->read_at(off, len); };
    // A file larger than 16 KiB can have its first 16 KiB read.
    REQUIRE(read(0, 16384).has_value());
    CHECK(*read(0, 16384) == body.substr(0, 16384));
    // A middle range, the tail, and a short read at end of file.
    CHECK(*read(12345, 678) == body.substr(12345, 678));
    CHECK(*read(39000, 1000) == body.substr(39000));
    CHECK(*read(39990, 100) == body.substr(39990)); // 10 bytes, not 100
    CHECK(read(39990, 100)->size() == 10);
    // At and past the end: empty, not an error.
    REQUIRE(read(40000, 10).has_value());
    CHECK(read(40000, 10)->empty());
    CHECK(read(50000, 10)->empty());
    CHECK(read(0, 0)->empty());
    // An oversized request or an offset no file offset can hold is refused, never cut short: a short
    // answer means end of file to the caller.
    CHECK_FALSE(read(0, 16u * 1024 * 1024 + 1).has_value());
    CHECK_FALSE(read(UINT64_MAX, 1).has_value());
    CHECK(read(0, 16u * 1024 * 1024)->size() == 40000);

    // The view reads the descriptor it opened: replacing the name afterwards changes nothing.
    write_file(t.root / "decoy.bin", std::string(40000, 'D'));
    fs::remove(path);
    fs::create_symlink(t.root / "decoy.bin", path);
    CHECK(*read(0, 4) == body.substr(0, 4));
}

TEST_CASE("component_fs_posix: unchanged() detects an in-place change of size or time",
          "[runtime][component_inventory][fs_posix]") {
    Tree t;
    const auto grown = (t.root / "grown.bin").string();
    const auto touched = (t.root / "touched.bin").string();
    write_file(grown, std::string(100, 'x'));
    write_file(touched, std::string(100, 'x'));

    const auto ops = plain_ops();
    auto g = ops.open_file(grown);
    auto m = ops.open_file(touched);
    REQUIRE(g.has_value());
    REQUIRE(m.has_value());
    CHECK(g->unchanged());
    CHECK(m->unchanged());

    {
        std::ofstream f(grown, std::ios::binary | std::ios::app);
        f << "tail";
    }
    CHECK_FALSE(g->unchanged()); // size changed

    fs::last_write_time(touched, fs::last_write_time(touched) + 10s);
    CHECK(fs::file_size(touched) == 100);
    CHECK_FALSE(m->unchanged()); // same size, new time
}

TEST_CASE("component_fs_posix: a network mount point is typed from its path and never stat'ed or opened",
          "[runtime][component_inventory][fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "mnt"));
    REQUIRE(fs::create_directories(t.root / "plain"));
    write_file(t.root / "mnt" / "z.jar", "Z");
    write_file(t.root / "x.jar", "X");
    const auto mnt = (t.root / "mnt").string();

    Targets targets;
    targets.network_mounts = {mnt};
    std::vector<std::string> log;
    const auto ops = make_fs_ops(targets, [&log](const std::string& p) { log.push_back(p); });

    const auto touched_mount = [&] {
        return std::ranges::any_of(log, [&](const std::string& p) { return p == mnt || p.starts_with(mnt + "/"); });
    };

    const auto listing = ops.list(t.root.string(), 100);
    CHECK_FALSE(listing.error);
    CHECK(by_name(listing) ==
          std::map<std::string, Type>{{"mnt", Type::network_mount}, {"plain", Type::dir}, {"x.jar", Type::file}});
    CHECK_FALSE(touched_mount());
    // The seam is live: the listed directory's own hops were recorded.
    CHECK(std::ranges::find(log, t.root.string()) != log.end());

    // Asking to enter it directly is refused without a syscall for any path through it.
    CHECK(ops.list(mnt, 100).error);
    CHECK_FALSE(ops.open_file(mnt).has_value());
    CHECK_FALSE(ops.open_file(mnt + "/z.jar").has_value());
    CHECK_FALSE(touched_mount());

    // Control: a file beside it opens and is recorded.
    CHECK(ops.open_file((t.root / "x.jar").string()).has_value());
    CHECK(std::ranges::find(log, (t.root / "x.jar").string()) != log.end());
    CHECK_FALSE(touched_mount());
}

TEST_CASE("component_fs_posix: classify_dirent never stats a network mount, whatever d_type says",
          "[runtime][component_inventory][fs_posix]") {
    // MUTATION: moving the mount check below the DT_UNKNOWN fstatat fails the first two checks (the
    // mount point is stat'ed, which can block on a dead server or trigger an automount).
    Tree t;
    REQUIRE(fs::create_directories(t.root / "mnt"));
    const Fd dir{t.root};
    REQUIRE(dir.fd >= 0);
    const std::unordered_set<std::string> mounts{(t.root / "mnt").string()};
    std::vector<std::string> log;
    const AccessLog on_access = [&log](const std::string& p) { log.push_back(p); };
    const auto root = t.root.string();

    CHECK(classify_dirent(dir.fd, root, entry("mnt", DT_UNKNOWN), mounts, on_access) == Type::network_mount);
    CHECK(classify_dirent(dir.fd, root, entry("mnt", DT_DIR), mounts, on_access) == Type::network_mount);
    CHECK(classify_dirent(dir.fd, root, entry("mnt", DT_LNK), mounts, on_access) == Type::network_mount);
    CHECK(log.empty()); // nothing stat'ed or recorded
}

TEST_CASE("component_fs_posix: classify_dirent resolves DT_UNKNOWN with a no-follow stat",
          "[runtime][component_inventory][fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "d"));
    write_file(t.root / "f.jar", "x");
    fs::create_directory_symlink(t.root / "d", t.root / "lnk");
    REQUIRE(::mkfifo((t.root / "pipe").c_str(), 0600) == 0);
    const Fd dir{t.root};
    REQUIRE(dir.fd >= 0);
    const std::unordered_set<std::string> none;
    std::vector<std::string> log;
    const AccessLog on_access = [&log](const std::string& p) { log.push_back(p); };
    const auto root = t.root.string();
    const auto type_of = [&](const char* name) {
        return classify_dirent(dir.fd, root, entry(name, DT_UNKNOWN), none, on_access);
    };

    CHECK(type_of("d") == Type::dir);
    CHECK(type_of("f.jar") == Type::file);
    CHECK(type_of("lnk") == Type::link); // not followed: a link to a directory is still a link
    CHECK(type_of("pipe") == Type::other);
    CHECK(std::ranges::find(log, (t.root / "d").string()) != log.end()); // the seam saw the stat

    // An entry that vanished between readdir and the stat is `other`, not a failed listing.
    CHECK(type_of("gone") == Type::other);

    // Any other failure to learn the type fails the listing: here a descriptor that is not open.
    CHECK_FALSE(classify_dirent(-1, root, entry("d", DT_UNKNOWN), none, on_access).has_value());
}

TEST_CASE("component_fs_posix: the walk over the real leg skips links and mounts and reaches the jars",
          "[runtime][component_inventory][fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "app" / "lib"));
    REQUIRE(fs::create_directories(t.root / "app" / "mnt"));
    REQUIRE(fs::create_directories(t.root / "outside"));
    write_file(t.root / "app" / "lib" / "x.jar", "X");
    write_file(t.root / "app" / "mnt" / "z.jar", "Z");
    write_file(t.root / "outside" / "y.jar", "Y");
    fs::create_directory_symlink(t.root / "outside", t.root / "app" / "planted");

    Targets targets;
    targets.roots = {(t.root / "app").string()};
    targets.network_mounts = {(t.root / "app" / "mnt").string()};
    const auto ops = make_fs_ops(targets);

    const auto r = walk(std::span<const std::string>{targets.roots}, WalkLimits{}, ops, ops.now() + 1h);
    CHECK(r.stop == Stop::complete);
    REQUIRE(r.candidates.size() == 1);
    CHECK(r.candidates[0].path == (t.root / "app" / "lib" / "x.jar").string());
    CHECK(r.stats.links_skipped == 1);
    CHECK(r.stats.mounts_skipped == 1);
}


// ---- the on-demand file search leg ----

namespace {

using shared_mount = yuzu::shared::MountEntry;

[[nodiscard]] std::uint64_t device_of(const struct stat& st) {
    return static_cast<std::uint64_t>(static_cast<std::make_unsigned_t<decltype(st.st_dev)>>(st.st_dev));
}

[[nodiscard]] SearchLeg search_leg(std::vector<std::string> prune = {}, AccessLog log = {}, SearchHooks hooks = {},
                                   ReadDirFn read_dir = {}) {
    return make_search_leg(std::move(prune), std::move(log), std::move(hooks), std::move(read_dir));
}

// Restores a directory's permissions so the temporary tree can be removed.
struct ModeGuard {
    fs::path p;
    ~ModeGuard() { ::chmod(p.c_str(), 0700); }
};

[[nodiscard]] bool equal_entry(const shared_mount& a, const shared_mount& b) {
    return a.mount_point == b.mount_point && a.root == b.root && a.fstype == b.fstype && a.source == b.source &&
           a.dev_major == b.dev_major && a.dev_minor == b.dev_minor;
}

} // namespace

TEST_CASE("component_fs_posix: list fills the device and inode of the directory and the inode of every entry",
          "[runtime][component_inventory][fs_posix][component_fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "d" / "sub"));
    write_file(t.root / "d" / "a.jar", "a");
    fs::create_symlink(t.root / "d" / "a.jar", t.root / "d" / "lnk");

    const std::string dir = (t.root / "d").string();
    const auto r = plain_ops().list(dir, 100);
    REQUIRE_FALSE(r.error);
    struct stat st {};
    REQUIRE(::stat(dir.c_str(), &st) == 0);
    CHECK(r.dev != 0);
    CHECK(r.dev == device_of(st));
    CHECK(r.file_id == static_cast<std::uint64_t>(st.st_ino));
    REQUIRE(r.entries.size() == 3);
    for (const auto& e : r.entries) {
        struct stat es {};
        REQUIRE(::lstat((t.root / "d" / e.name).c_str(), &es) == 0);
        CHECK(e.file_id != 0);
        CHECK(e.file_id == static_cast<std::uint64_t>(es.st_ino));
    }
    // a directory that cannot be reached has no identity and no pretence of one
    const auto missing = plain_ops().list((t.root / "nope").string(), 100);
    CHECK(missing.error);
    CHECK(missing.dev == 0);
    CHECK(missing.file_id == 0);
}

TEST_CASE("component_fs_posix: a directory the account may not open is a permission_denied listing",
          "[runtime][component_inventory][fs_posix][component_fs_posix]") {
    if (::geteuid() == 0) {
        WARN("running as root: a mode 000 directory is still readable, the refusal cannot be staged here");
        return;
    }
    Tree t;
    REQUIRE(fs::create_directories(t.root / "locked"));
    REQUIRE(fs::create_directories(t.root / "open"));
    const ModeGuard guard{t.root / "locked"};
    REQUIRE(::chmod((t.root / "locked").c_str(), 0000) == 0);

    const auto denied = plain_ops().list((t.root / "locked").string(), 100);
    CHECK(denied.error);
    CHECK(denied.cause == ListError::permission_denied);
    const auto gone = plain_ops().list((t.root / "nope").string(), 100);
    CHECK(gone.error);
    CHECK(gone.cause == ListError::unreadable); // missing is not a refusal
    CHECK_FALSE(plain_ops().list((t.root / "open").string(), 100).error);
    CHECK(plain_ops().list((t.root / "open").string(), 100).cause == ListError::none);
}

TEST_CASE("component_fs_posix: with the descriptor stack on, sibling and child listings open only the missing components",
          "[runtime][component_inventory][fs_posix][component_fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "a" / "b" / "c"));
    REQUIRE(fs::create_directories(t.root / "a" / "b" / "d"));
    REQUIRE(fs::create_directories(t.root / "a" / "e"));
    write_file(t.root / "a" / "b" / "x.jar", "x");
    write_file(t.root / "a" / "b" / "c" / "y.jar", "y");
    const auto p = [&](const char* rel) { return (t.root / rel).string(); };

    std::vector<std::string> log;
    const auto leg = search_leg({}, [&log](const std::string& s) { log.push_back(s); });
    const auto plain = plain_ops();

    const auto same_as_plain = [&](const std::string& dir) {
        const auto a = leg.ops.list(dir, 100);
        const auto b = plain.list(dir, 100);
        CHECK_FALSE(a.error);
        CHECK(by_name(a) == by_name(b));
        CHECK(a.dev == b.dev);
        CHECK(a.file_id == b.file_id);
        return a;
    };

    same_as_plain(p("a/b"));
    CHECK(std::ranges::find(log, "/") != log.end()); // the first listing opened every hop
    CHECK(std::ranges::find(log, p("a/b")) != log.end());
    log.clear();

    same_as_plain(p("a/b/c")); // a child: one hop
    CHECK(log == std::vector<std::string>{p("a/b/c")});
    log.clear();
    same_as_plain(p("a/b/d")); // a sibling: the old leaf is dropped, one hop opened
    CHECK(log == std::vector<std::string>{p("a/b/d")});
    log.clear();
    const auto again = same_as_plain(p("a/b")); // an ancestor: nothing is opened, the stream is read from its start
    CHECK(log.empty());
    CHECK(by_name(again).count("x.jar") == 1);
    same_as_plain(p("a/e")); // an uncle: one hop
    CHECK(log == std::vector<std::string>{p("a/e")});
    log.clear();
    same_as_plain(p("a/b/c")); // back down: a/b is gone from the stack, so a/b and a/b/c are opened again
    CHECK(log == (std::vector<std::string>{p("a/b"), p("a/b/c")}));
}

TEST_CASE("component_fs_posix: with the stack on, a directory swapped for a link after its parent was cached is refused",
          "[runtime][component_inventory][fs_posix][component_fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "app" / "sub"));
    REQUIRE(fs::create_directories(t.root / "app" / "inner"));
    REQUIRE(fs::create_directories(t.root / "elsewhere"));
    write_file(t.root / "elsewhere" / "secret.jar", "S");
    write_file(t.root / "app" / "inner" / "kept.jar", "K");
    const auto leg = search_leg();
    const auto app = (t.root / "app").string();

    CHECK(by_name(leg.ops.list(app, 100)).at("sub") == Type::dir); // `app` is now held

    fs::remove_all(t.root / "app" / "sub");
    fs::create_directory_symlink(t.root / "elsewhere", t.root / "app" / "sub");
    const auto swapped = leg.ops.list((t.root / "app" / "sub").string(), 100);
    CHECK(swapped.error);
    CHECK(swapped.entries.empty()); // nothing under the link's target
    CHECK(leg.root_state((t.root / "app" / "sub").string()) == RootState::is_link);

    // the failure left the stack sound: the real sibling still lists, a link above is refused
    CHECK(by_name(leg.ops.list((t.root / "app" / "inner").string(), 100)).at("kept.jar") == Type::file);
    fs::create_directory_symlink(t.root / "app", t.root / "app_link");
    CHECK(leg.ops.list((t.root / "app_link" / "inner").string(), 100).error);
}

TEST_CASE("component_fs_posix: a pruned mount point is never passed to stat or open, never listed, and costs no gap",
          "[runtime][component_inventory][fs_posix][component_fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "mnt"));
    REQUIRE(fs::create_directories(t.root / "plain"));
    write_file(t.root / "mnt" / "z.jar", "Z");
    write_file(t.root / "x.jar", "X");
    write_file(t.root / "plain" / "p.jar", "P");
    const std::string mnt = (t.root / "mnt").string();

    std::vector<std::string> log;
    const auto leg = search_leg({mnt}, [&log](const std::string& s) { log.push_back(s); });
    const auto touched = [&] {
        return std::ranges::any_of(log, [&](const std::string& p) { return p == mnt || p.starts_with(mnt + "/"); });
    };

    // the listing does not name it
    CHECK(by_name(leg.ops.list(t.root.string(), 100)) ==
          std::map<std::string, Type>{{"plain", Type::dir}, {"x.jar", Type::file}});
    CHECK_FALSE(touched());

    // and a walk over the leg sees neither the mount point nor anything below it, counts it nowhere
    std::vector<std::string> visits;
    const auto res = walk_ordered(t.root.string(), {}, WalkLimits{}, leg.ops, std::chrono::steady_clock::now() + 1h,
                                  [&visits](const std::string& d, const DirEntry& e, std::uint64_t) {
                                      visits.push_back(walk_detail::join(d, e.name));
                                      return true;
                                  });
    CHECK(res.stop == Stop::complete);
    CHECK(res.stats.mounts_skipped == 0);
    CHECK(res.gaps.empty());
    CHECK(visits == (std::vector<std::string>{(t.root / "plain").string(), (t.root / "plain" / "p.jar").string(),
                                              (t.root / "x.jar").string()}));
    CHECK_FALSE(touched());

    // asking for it directly is refused without a syscall for any path through it
    CHECK(leg.ops.list(mnt, 100).error);
    CHECK_FALSE(leg.facts(mnt, "z.jar").opened);
    CHECK_FALSE(leg.facts(t.root.string(), "mnt").opened);
    CHECK(leg.root_state(mnt + "/anything") != RootState::ok);
    CHECK_FALSE(touched());

    // the leg never opens a file through FsOps
    CHECK_FALSE(leg.ops.open_file((t.root / "x.jar").string()).has_value());
}

TEST_CASE("component_fs_posix: a root whose ancestor is a mount point is acquired when the prune set holds only descendants",
          "[runtime][component_inventory][fs_posix][component_fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "mnt" / "inner" / "deep"));
    write_file(t.root / "mnt" / "inner" / "f.jar", "F");
    const std::string mnt = (t.root / "mnt").string();
    const std::string inner = (t.root / "mnt" / "inner").string();
    const std::string deep = (t.root / "mnt" / "inner" / "deep").string();

    // the mount point `mnt` is an ancestor of the root: not in the prune set, so the walk reaches the root
    const auto ok = search_leg({deep});
    const auto r = ok.ops.list(inner, 100);
    CHECK_FALSE(r.error);
    CHECK(by_name(r) == std::map<std::string, Type>{{"f.jar", Type::file}}); // `deep` is erased
    CHECK(ok.root_state(inner) == RootState::ok);

    // the rule is real: put the ancestor in the prune set and the root cannot be reached at all
    const auto refused = search_leg({mnt});
    CHECK(refused.ops.list(inner, 100).error);
    CHECK(refused.root_state(inner) != RootState::ok);
}

TEST_CASE("component_fs_posix: every lookup runs inside around_lookup and nothing else does",
          "[runtime][component_inventory][fs_posix][component_fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "d" / "sub"));
    write_file(t.root / "d" / "f.bin", "abc");
    fs::create_directory_symlink(t.root / "d", t.root / "lnk");
    const std::string d = (t.root / "d").string();

    int depth = 0;
    int enters = 0;
    bool extents_inside = false;
    int extents_calls = 0;
    std::vector<std::string> outside; // every access-logged lookup made while the hook was not held
    std::vector<std::string> logged;
    SearchHooks hooks;
    hooks.around_lookup = [&](const std::function<void()>& lookup) {
        ++depth;
        ++enters;
        lookup();
        --depth;
    };
    hooks.read_extents = [&](int, const struct stat&) {
        extents_inside = extents_inside || depth != 0;
        ++extents_calls;
    };
    // every entry is reported untyped, so classify_dirent stats it: that stat must be inside the hook too
    const ReadDirFn untyped = [](DIR* dir) {
        struct dirent* e = ::readdir(dir);
        if (e != nullptr)
            e->d_type = DT_UNKNOWN;
        return e;
    };
    const auto leg = search_leg(
        {},
        [&](const std::string& p) {
            logged.push_back(p);
            if (depth == 0)
                outside.push_back(p);
        },
        hooks, untyped);

    int before = enters;
    const auto listing = leg.ops.list(d, 100);
    CHECK(enters - before == 2); // the acquisition and the enumeration
    CHECK(by_name(listing) == std::map<std::string, Type>{{"f.bin", Type::file}, {"sub", Type::dir}});
    CHECK(std::ranges::find(logged, (t.root / "d" / "f.bin").string()) != logged.end()); // the untyped stat ran

    before = enters;
    const auto facts = leg.facts(d, "f.bin");
    CHECK(enters - before == 2); // the acquisition (cached) and the leaf open
    CHECK(facts.opened);
    CHECK(extents_calls == 1);
    CHECK_FALSE(extents_inside); // the extent read is not a lookup

    before = enters;
    CHECK(leg.root_state(d) == RootState::ok);
    CHECK(enters - before == 1);
    CHECK(leg.root_state((t.root / "lnk").string()) == RootState::is_link); // the link probe is a lookup too

    CHECK(outside.empty());
    CHECK(depth == 0);
}

TEST_CASE("component_fs_posix: root_state tells a link at any component, a missing path and a non-directory apart",
          "[runtime][component_inventory][fs_posix][component_fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "d" / "sub"));
    write_file(t.root / "d" / "f.txt", "f");
    fs::create_directory_symlink(t.root / "d", t.root / "lnk");
    fs::create_symlink(t.root / "d" / "f.txt", t.root / "flnk");
    const auto leg = search_leg();
    const auto st = [&](const std::string& p) { return leg.root_state(p); };

    CHECK(st((t.root / "d").string()) == RootState::ok);
    CHECK(st((t.root / "d" / "sub").string()) == RootState::ok);
    CHECK(st("/") == RootState::ok);
    CHECK(st((t.root / "lnk").string()) == RootState::is_link);                // at the leaf
    CHECK(st((t.root / "lnk" / "sub").string()) == RootState::is_link);        // at an intermediate component
    CHECK(st((t.root / "flnk").string()) == RootState::is_link);               // a link to a file
    CHECK(st((t.root / "d" / "missing").string()) == RootState::not_found);
    CHECK(st((t.root / "nope" / "deeper").string()) == RootState::not_found);
    CHECK(st((t.root / "d" / "f.txt").string()) == RootState::not_a_directory);
    CHECK(st((t.root / "d" / "f.txt" / "x").string()) == RootState::not_a_directory);
    CHECK(st("relative") == RootState::other);
}

TEST_CASE("component_fs_posix: facts opens the leaf under the cached parent, follows no link, waits on no FIFO",
          "[runtime][component_inventory][fs_posix][component_fs_posix]") {
    Tree t;
    REQUIRE(fs::create_directories(t.root / "d" / "sub"));
    write_file(t.root / "d" / "f.bin", "abc");
    fs::create_symlink(t.root / "d" / "f.bin", t.root / "d" / "lnk");
    REQUIRE(::mkfifo((t.root / "d" / "pipe").c_str(), 0600) == 0);
    const std::string d = (t.root / "d").string();

    std::vector<std::pair<std::uint64_t, bool>> seen; // size from the descriptor's own stat, descriptor valid
    SearchHooks hooks;
    hooks.read_extents = [&](int fd, const struct stat& st) {
        seen.emplace_back(static_cast<std::uint64_t>(st.st_size), ::fcntl(fd, F_GETFD) != -1);
    };
    std::vector<std::string> log;
    const auto leg = search_leg({}, [&log](const std::string& s) { log.push_back(s); }, hooks);

    const auto f = leg.facts(d, "f.bin");
    CHECK(f.opened);
    CHECK(f.size == 3);
    struct stat st {};
    REQUIRE(::stat((t.root / "d" / "f.bin").c_str(), &st) == 0);
    CHECK(f.mtime == static_cast<std::int64_t>(st.st_mtime));
    REQUIRE(seen.size() == 1);
    CHECK(seen[0].first == 3);
    CHECK(seen[0].second);
    CHECK(std::ranges::find(log, (t.root / "d" / "f.bin").string()) != log.end());

    const auto link = leg.facts(d, "lnk");
    CHECK_FALSE(link.opened);
    const auto pipe = leg.facts(d, "pipe"); // opened without blocking, then refused as not regular
    CHECK_FALSE(pipe.opened);
    const auto dir = leg.facts(d, "sub");
    CHECK_FALSE(dir.opened);
    const auto gone = leg.facts(d, "missing");
    CHECK_FALSE(gone.opened);
    CHECK_FALSE(leg.facts(d, "a/b").opened); // not a single component
    CHECK_FALSE(leg.facts(d, "").opened);
    CHECK_FALSE(leg.facts((t.root / "nope").string(), "x").opened);
    CHECK(seen.size() == 1); // the extent reader saw the one regular file and nothing else
}

TEST_CASE("component_legs: read_mount_entries_stream equals mount_entries on the whole text however it is read",
          "[runtime][component_inventory][legs][component_fs_posix]") {
    const std::string text = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
                             "30 22 8:2 /@home /home rw,relatime shared:2 - btrfs /dev/sda2 rw\n"
                             "40 22 0:40 / /mnt/nfs rw shared:5 - nfs4 srv:/x rw\n"
                             "41 22 0:41 / /tmp rw - tmpfs  rw\n";
    const auto whole = yuzu::shared::mount_entries(text);
    REQUIRE(whole.malformed == 0);
    for (const std::size_t slice : {std::size_t{1}, std::size_t{7}, std::size_t{4096}}) {
        INFO("slice " << slice);
        const auto got = read_mount_entries_stream(serve(text, slice), {});
        REQUIRE(got.has_value());
        REQUIRE(got->entries.size() == whole.entries.size());
        for (std::size_t i = 0; i < whole.entries.size(); ++i)
            CHECK(equal_entry(got->entries[i], whole.entries[i]));
        CHECK(got->malformed == 0);
    }
    // no trailing newline on the last line
    const auto cut = read_mount_entries_stream(serve(text.substr(0, text.size() - 1), 5), {});
    REQUIRE(cut.has_value());
    CHECK(cut->entries.size() == whole.entries.size());
}

TEST_CASE("component_legs: read_mount_entries_stream keeps what the filter keeps, a later entry covers an earlier, malformed lines add up",
          "[runtime][component_inventory][legs][component_fs_posix]") {
    const std::string text = "1 0 8:1 / / rw - ext4 /dev/a rw\n"
                             "2 1 8:2 / /data rw - ext4 /dev/b rw\n"
                             "not a mount line\n"
                             "3 1 8:3 / /skip rw - ext4 /dev/c rw\n"
                             "4 2 0:7 / /data rw - tmpfs tmpfs rw\n"
                             "also not a mount line\n";
    const MountKeep keep = [](const shared_mount& e) { return e.mount_point != "/skip"; };
    for (const std::size_t slice : {std::size_t{1}, std::size_t{4096}}) {
        INFO("slice " << slice);
        const auto got = read_mount_entries_stream(serve(text, slice), keep);
        REQUIRE(got.has_value());
        REQUIRE(got->entries.size() == 2);
        CHECK(got->entries[0].mount_point == "/");
        CHECK(got->entries[1].mount_point == "/data");
        CHECK(got->entries[1].fstype == "tmpfs"); // the later mount of the point covers the earlier
        CHECK(got->malformed == 2);
    }
}

TEST_CASE("component_legs: read_mount_entries_stream fails closed, never returning the part it had read",
          "[runtime][component_inventory][legs][component_fs_posix]") {
    const std::string line = "1 0 8:1 / / rw - ext4 /dev/a rw\n";
    const std::string table = line + "2 1 8:2 / /data rw - ext4 /dev/b rw\n" + "3 1 8:3 / /more rw - ext4 /dev/c rw\n";

    // a read that fails after some of the table was parsed
    CHECK_FALSE(read_mount_entries_stream(serve(table, line.size(), EIO), {}).has_value());
    // an interrupted read is retried, not a failure
    auto inner = serve(table, 4096);
    bool interrupted = false;
    const auto eintr_once = [&](char* buf, std::size_t len) -> ssize_t {
        if (!interrupted) {
            interrupted = true;
            errno = EINTR;
            return -1;
        }
        return inner(buf, len);
    };
    REQUIRE(read_mount_entries_stream(eintr_once, {}).has_value());

    // a table over the total ceiling: exactly the ceiling passes, one byte more does not
    CHECK(read_mount_entries_stream(serve(table, 16), {}, table.size()).has_value());
    CHECK_FALSE(read_mount_entries_stream(serve(table, 16), {}, table.size() - 1).has_value());

    // a line over 1 MiB, however it arrives
    const std::string huge = "1 0 8:1 / / rw - ext4 /dev/a " + std::string(kMiB + 16, 'x') + "\n";
    CHECK_FALSE(read_mount_entries_stream(serve(huge + line, 64 * 1024), {}).has_value());
    CHECK_FALSE(read_mount_entries_stream(serve(huge, 7 * 1024 + 1), {}).has_value());

    // more than max_kept distinct mount points; re-mounting a point does not count again
    CHECK(read_mount_entries_stream(serve(table, 4096), {}, kMaxMountTable, 3).has_value());
    CHECK_FALSE(read_mount_entries_stream(serve(table, 4096), {}, kMaxMountTable, 2).has_value());
    const std::string remount = line + "2 1 8:2 / / rw - tmpfs tmpfs rw\n" + "3 1 8:3 / / rw - xfs /dev/c rw\n";
    CHECK(read_mount_entries_stream(serve(remount, 4096), {}, kMaxMountTable, 1).has_value());
    // entries the filter drops do not count either
    const MountKeep only_root = [](const shared_mount& e) { return e.mount_point == "/"; };
    CHECK(read_mount_entries_stream(serve(table, 4096), only_root, kMaxMountTable, 1).has_value());
}

#endif // !_WIN32
