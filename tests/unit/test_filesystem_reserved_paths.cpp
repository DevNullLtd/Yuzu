// WP06 F55: the filesystem plugin refuses the agent's own data dir, log file and TLS key paths
// (FileRetrieval:Read must not reach bytes the catalogue reserves for PluginSecret), and the agent
// no longer logs the raw session id. Pure decision tests + the real plugin through
// LocalDispatcher with the agent config keys injected.

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "filesystem_dispatcher_test_support.hpp"
#include "filesystem_reserved_paths.hpp"
#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace rsv = yuzu::filesystem::reserved;
namespace sup = yuzu::test::filesystem_dispatcher_support;

TEST_CASE("is_agent_reserved_path: dirs match themselves and descendants on a segment boundary",
          "[agent][filesystem_plugin][reserved]") {
    rsv::Set s;
    s.dirs = {"/var/lib/yuzu"};
    CHECK(rsv::is_agent_reserved_path(s, "/var/lib/yuzu"));
    CHECK(rsv::is_agent_reserved_path(s, "/var/lib/yuzu/"));
    CHECK(rsv::is_agent_reserved_path(s, "/var/lib/yuzu/certs/agent-client.key"));
    CHECK_FALSE(rsv::is_agent_reserved_path(s, "/var/lib/yuzu-backup/x"));
    CHECK_FALSE(rsv::is_agent_reserved_path(s, "/var/lib"));
    CHECK_FALSE(rsv::is_agent_reserved_path(s, "/etc/passwd"));
    CHECK_FALSE(rsv::is_agent_reserved_path(s, ""));
}

TEST_CASE("is_agent_reserved_path: a reserved file matches exactly and its rotated siblings",
          "[agent][filesystem_plugin][reserved]") {
    rsv::Set s;
    s.files = {"/var/log/yuzu-agent.log", "/etc/yuzu/agent.key"};
    CHECK(rsv::is_agent_reserved_path(s, "/var/log/yuzu-agent.log"));
    CHECK(rsv::is_agent_reserved_path(s, "/var/log/yuzu-agent.log.1"));
    CHECK(rsv::is_agent_reserved_path(s, "/etc/yuzu/agent.key"));
    CHECK_FALSE(rsv::is_agent_reserved_path(s, "/var/log/yuzu-agent.logger"));
    CHECK_FALSE(rsv::is_agent_reserved_path(s, "/var/log/syslog"));
    CHECK_FALSE(rsv::is_agent_reserved_path(s, "/etc/yuzu/agent.keys")); // '.' suffix only
}

TEST_CASE("is_agent_reserved_path: an empty set reserves nothing; windows separators normalise",
          "[agent][filesystem_plugin][reserved]") {
    CHECK_FALSE(rsv::is_agent_reserved_path(rsv::Set{}, "/anything"));
    rsv::Set s;
    s.dirs = {"C:/ProgramData/Yuzu"};
    CHECK(rsv::is_agent_reserved_path(s, "C:\\ProgramData\\Yuzu\\yuzu-agent.log"));
}

TEST_CASE("is_dev_fd_path: /dev/fd/N and the stdio aliases are refused (macOS has no /proc)",
          "[agent][filesystem_plugin][reserved]") {
    CHECK(rsv::is_dev_fd_path("/dev/fd/3"));
    CHECK(rsv::is_dev_fd_path("/dev/fd"));
    CHECK(rsv::is_dev_fd_path("/dev/stdin"));
    CHECK(rsv::is_dev_fd_path("/dev/stdout"));
    CHECK(rsv::is_dev_fd_path("/dev/stderr"));
    CHECK_FALSE(rsv::is_dev_fd_path("/dev/null"));
    CHECK_FALSE(rsv::is_dev_fd_path("/dev/fdx/3"));
    CHECK_FALSE(rsv::is_dev_fd_path("/home/u/dev/fd/3"));
    // macOS volumes are case-insensitive by default.
    CHECK(rsv::is_dev_fd_path("/DEV/FD/3"));
    CHECK(rsv::is_dev_fd_path("/Dev/Stdin"));
}

TEST_CASE("is_apple_vol_path / contains_nul: pure decisions", "[agent][filesystem_plugin][reserved]") {
    CHECK(rsv::is_apple_vol_path("/.vol/16777220/12345"));
    CHECK(rsv::is_apple_vol_path("/.VOL/1/2"));
    CHECK(rsv::is_apple_vol_path("/.vol"));
    CHECK_FALSE(rsv::is_apple_vol_path("/.volume/1"));
    CHECK_FALSE(rsv::is_apple_vol_path("/home/.vol/x"));
    CHECK(rsv::contains_nul(std::string_view("/var/lib/yuzu\0/x", 16)));
    CHECK_FALSE(rsv::contains_nul("/var/lib/yuzu/x"));
}

TEST_CASE("is_proc_secret_path: the agent's own /proc entries and any pid's secret files are refused",
          "[agent][filesystem_plugin][reserved]") {
    CHECK(rsv::is_proc_secret_path("/proc/4242/environ", 4242));
    CHECK(rsv::is_proc_secret_path("/proc/4242/status", 4242));        // own pid: everything
    CHECK(rsv::is_proc_secret_path("/proc/4242/task/4243/environ", 4242));
    CHECK(rsv::is_proc_secret_path("/proc/self/environ", 1));          // literal spellings
    CHECK(rsv::is_proc_secret_path("/proc/thread-self/mem", 1));
    CHECK(rsv::is_proc_secret_path("/proc/77/environ", 4242));         // any pid's secret files
    CHECK(rsv::is_proc_secret_path("/proc/77/task/78/cmdline", 4242));
    CHECK(rsv::is_proc_secret_path("/proc/77/fd", 4242));
    CHECK(rsv::is_proc_secret_path("/proc/77/maps", 4242));
    CHECK_FALSE(rsv::is_proc_secret_path("/proc/77/status", 4242));    // ordinary introspection
    CHECK_FALSE(rsv::is_proc_secret_path("/proc/cpuinfo", 4242));
    CHECK_FALSE(rsv::is_proc_secret_path("/proc/4242x/status", 4242));
    CHECK_FALSE(rsv::is_proc_secret_path("/home/u/proc/77/environ", 4242));
}

TEST_CASE("filesystem plugin: read/search/file_hash/get_acl refuse the agent's own paths",
          "[agent][filesystem_plugin][reserved]") {
    const auto plugin_path = sup::find_plugin();
    if (plugin_path.empty()) {
        SKIP("filesystem plugin library not found");
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value() || !handle->descriptor()) {
        SKIP("filesystem plugin did not load");
    }

    yuzu::test::TempDir root{"yuzu_test_fs_reserved_"};
    std::error_code ec;
    const auto data_dir = root.path / "data";
    const auto other = root.path / "other";
    fs::create_directories(data_dir / "certs", ec);
    fs::create_directories(other, ec);
    const auto key = data_dir / "certs" / "agent-client.key";
    const auto log = root.path / "custom-agent.log";
    const auto ok_file = other / "ok.txt";
    for (const auto& f : {key, log, ok_file}) {
        std::ofstream o(f);
        o << "SECRET-SENTINEL\n";
    }
    for (const char* n : {"enroll.tok", "trust.pem"}) {
        std::ofstream o(other / n);
        o << "SECRET-SENTINEL\n";
    }
    // A symlink from an innocent place to the key must not bypass the guard.
    const auto link = other / "innocent.txt";
    std::error_code lec;
    fs::create_symlink(key, link, lec);

    yuzu::agent::StandalonePluginContext ctx{
        "filesystem",
        {{"agent.data_dir", data_dir.string()},
         {"agent.log_file", log.string()},
         {"agent.tls_client_key", (root.path / "elsewhere.key").string()},
         {"agent.enrollment_token_file", (other / "enroll.tok").string()},
         {"agent.plugin_trust_bundle", (other / "trust.pem").string()}}};
    REQUIRE(handle->descriptor()->init(ctx.get()) == 0);

    auto dispatch = [&](const char* action, const fs::path& p) {
        const std::string ps = p.string();
        const std::array<YuzuParam, 2> params{{{"path", ps.c_str()}, {"pattern", "SECRET"}}};
        yuzu::agent::LocalDispatcher d;
        return d.run(handle->descriptor(), action, params);
    };

    for (const char* action : {"read", "search", "file_hash"}) {
        INFO(action);
        auto r1 = dispatch(action, key);
        CHECK(r1.rc != 0);
        CHECK(r1.captured.find("SECRET-SENTINEL") == std::string::npos);
        auto r2 = dispatch(action, log);
        CHECK(r2.rc != 0);
        CHECK(r2.captured.find("SECRET-SENTINEL") == std::string::npos);
        if (!lec) {
            auto r3 = dispatch(action, link);
            CHECK(r3.rc != 0);
            CHECK(r3.captured.find("SECRET-SENTINEL") == std::string::npos);
        }
    }
    // The enrolment token file and the trust bundle (WP06 F55 review), a `..` variant of the
    // key path, and the refusal never echoes the path.
    const auto dotdot = other / ".." / "data" / "certs" / ".." / "certs" / "agent-client.key";
    for (const auto& p : {other / "enroll.tok", other / "trust.pem", dotdot}) {
        auto r = dispatch("read", p);
        CHECK(r.rc != 0);
        CHECK(r.captured.find("SECRET-SENTINEL") == std::string::npos);
        CHECK(r.captured.find("enroll.tok") == std::string::npos);
        CHECK(r.captured.find("agent-client") == std::string::npos);
    }
    // A path outside the reserved set still reads.
    auto good = dispatch("read", ok_file);
    CHECK(good.rc == 0);
    CHECK(good.captured.find("SECRET-SENTINEL") != std::string::npos);

    handle->descriptor()->shutdown(ctx.get());
}

#ifndef _WIN32
TEST_CASE("filesystem plugin: identity, /proc, exists, walkers and shutdown (WP06 F55 review)",
          "[agent][filesystem_plugin][reserved]") {
    const auto plugin_path = sup::find_plugin();
    if (plugin_path.empty()) {
        SKIP("filesystem plugin library not found");
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value() || !handle->descriptor()) {
        SKIP("filesystem plugin did not load");
    }
    yuzu::test::TempDir root{"yuzu_test_fs_reserved2_"};
    std::error_code ec;
    const auto data_dir = root.path / "data";
    fs::create_directories(data_dir, ec);
    const auto key = data_dir / "agent-client.key";
    {
        std::ofstream o(key);
        o << "SECRET-SENTINEL\n";
    }
    // A hard link OUTSIDE the data dir to the key: a string compare cannot see it.
    const auto hard = root.path / "innocent-hardlink.txt";
    std::error_code hec;
    fs::create_hard_link(key, hard, hec);

    yuzu::agent::StandalonePluginContext ctx{"filesystem", {{"agent.data_dir", data_dir.string()}}};
    REQUIRE(handle->descriptor()->init(ctx.get()) == 0);
    auto run = [&](const char* action, std::initializer_list<std::pair<const char*, std::string>> kv) {
        std::vector<std::pair<std::string, std::string>> own(kv.begin(), kv.end());
        std::vector<YuzuParam> ps;
        for (auto& [k, v] : own)
            ps.push_back({k.c_str(), v.c_str()});
        yuzu::agent::LocalDispatcher d;
        return d.run(handle->descriptor(), action, ps);
    };

    if (!hec) {
        auto r = run("read", {{"path", hard.string()}});
        CHECK(r.rc != 0);
        CHECK(r.captured.find("SECRET-SENTINEL") == std::string::npos);
    }
    // The agent's own /proc entries: the environment held the enrolment token.
    auto env = run("search", {{"path", "/proc/self/environ"}, {"pattern", "."}, {"regex", "true"}});
    CHECK(env.rc != 0);
    CHECK(env.captured.find("match|") == std::string::npos);
    auto env2 = run("read", {{"path", "/proc/" + std::to_string(::getpid()) + "/environ"}});
    CHECK(env2.rc != 0);
    // exists: no existence, type or size for a reserved path, even with no base_dir.
    auto ex = run("exists", {{"path", key.string()}});
    CHECK(ex.captured.find("exists|true") == std::string::npos);
    CHECK(ex.captured.find("size|") == std::string::npos);
    auto exh = run("exists", {{"path", hard.string()}});
    if (!hec)
        CHECK(exh.captured.find("exists|true") == std::string::npos);
    // Walkers: a walk that STARTS above the data dir never reports or hashes anything inside it.
    auto sd = run("search_dir", {{"root", root.path.string()}, {"pattern", "*"}, {"match_type", "files"}});
    CHECK(sd.captured.find("agent-client.key") == std::string::npos);
    // The reserved set is not cleared by shutdown (fail closed): still refused afterwards.
    handle->descriptor()->shutdown(ctx.get());
    auto after = run("read", {{"path", key.string()}});
    CHECK(after.rc != 0);
    CHECK(after.captured.find("SECRET-SENTINEL") == std::string::npos);
}

namespace {
std::optional<yuzu::agent::PluginHandle> load_fs_plugin() {
    const auto plugin_path = sup::find_plugin();
    if (plugin_path.empty()) {
        SKIP("filesystem plugin library not found");
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value() || !handle->descriptor()) {
        SKIP("filesystem plugin did not load");
    }
    return std::move(*handle);
}

auto make_runner(yuzu::agent::PluginHandle& handle) {
    return [&handle](const char* action, std::initializer_list<std::pair<const char*, std::string>> kv) {
        std::vector<std::pair<std::string, std::string>> own(kv.begin(), kv.end());
        std::vector<YuzuParam> ps;
        for (auto& [k, v] : own)
            ps.push_back({k.c_str(), v.c_str()});
        yuzu::agent::LocalDispatcher d;
        return d.run(handle.descriptor(), action, ps);
    };
}
} // namespace

TEST_CASE("filesystem plugin: a hard link to a file in an UNREADABLE reserved subdirectory is refused",
          "[agent][filesystem_plugin][reserved][hardlink]") {
    if (::geteuid() == 0) {
        SKIP("running as root: chmod does not hide a directory from root");
    }
    auto handle = load_fs_plugin();
    REQUIRE(handle);
    yuzu::test::TempDir root{"yuzu_test_fs_reserved_hl_"};
    std::error_code ec;
    const auto data_dir = root.path / "data";
    const auto locked = data_dir / "locked";
    fs::create_directories(locked, ec);
    const auto key = locked / "agent-client.key";
    {
        std::ofstream o(key);
        o << "SECRET-SENTINEL\n";
    }
    const auto hard = root.path / "innocent-hardlink.txt";
    std::error_code hec;
    fs::create_hard_link(key, hard, hec);
    REQUIRE_FALSE(hec);
    fs::permissions(locked, fs::perms::none, ec);
    REQUIRE_FALSE(ec);

    yuzu::agent::StandalonePluginContext ctx{"filesystem", {{"agent.data_dir", data_dir.string()}}};
    REQUIRE(handle->descriptor()->init(ctx.get()) == 0);
    auto run = make_runner(*handle);
    auto r = run("read", {{"path", hard.string()}});
    // Restore before any assertion can unwind, so TempDir can clean up.
    std::error_code rec;
    fs::permissions(locked, fs::perms::owner_all, rec);
    CHECK(r.rc != 0);
    CHECK(r.captured.find("SECRET-SENTINEL") == std::string::npos);
    handle->descriptor()->shutdown(ctx.get());
}

namespace {
// Plants a hard link to a reserved key, applies a permission change that hides the reserved tree
// from THIS non-root process after init, reads the link, restores permissions.
// The link's own name and parent are innocent; only the identity scan can refuse it.
void run_hardlink_shape(const char* label, bool key_in_subdir, fs::perms data_dir_perms,
                        fs::perms subdir_perms, bool lock_parent) {
    if (::geteuid() == 0)
        SKIP("running as root: chmod does not hide a directory from root");
    auto handle = load_fs_plugin();
    REQUIRE(handle);
    yuzu::test::TempDir root{"yuzu_test_fs_reserved_shape_"};
    std::error_code ec;
    const auto parent = root.path / "parent";
    const auto data_dir = parent / "data";
    const auto sub = data_dir / "sub";
    fs::create_directories(key_in_subdir ? sub : data_dir, ec);
    const auto key = (key_in_subdir ? sub : data_dir) / "agent-client.key";
    {
        std::ofstream o(key);
        o << "SECRET-SENTINEL\n";
    }
    const auto hard = root.path / "innocent-hardlink.txt";
    std::error_code hec;
    fs::create_hard_link(key, hard, hec);
    REQUIRE_FALSE(hec);

    yuzu::agent::StandalonePluginContext ctx{"filesystem", {{"agent.data_dir", data_dir.string()}}};
    REQUIRE(handle->descriptor()->init(ctx.get()) == 0);
    if (key_in_subdir)
        fs::permissions(sub, subdir_perms, ec);
    fs::permissions(data_dir, data_dir_perms, ec);
    if (lock_parent)
        fs::permissions(parent, fs::perms::none, ec);

    auto run = make_runner(*handle);
    auto r = run("read", {{"path", hard.string()}});
    // Restore before any assertion can unwind, so TempDir can clean up.
    std::error_code rec;
    fs::permissions(parent, fs::perms::owner_all, rec);
    fs::permissions(data_dir, fs::perms::owner_all, rec);
    if (key_in_subdir)
        fs::permissions(sub, fs::perms::owner_all, rec);
    INFO(label);
    CHECK(r.rc != 0);
    CHECK(r.captured.find("SECRET-SENTINEL") == std::string::npos);
    handle->descriptor()->shutdown(ctx.get());
}
} // namespace

TEST_CASE("filesystem plugin: a hard link into a reserved dir that is readable but not searchable (0444) is refused",
          "[agent][filesystem_plugin][reserved][hardlink]") {
    run_hardlink_shape("data dir 0444, no subdir", false,
                       fs::perms::owner_read | fs::perms::group_read | fs::perms::others_read, fs::perms::all,
                       false);
}

TEST_CASE("filesystem plugin: a hard link into a reserved dir that is readable but not searchable (0400) is refused",
          "[agent][filesystem_plugin][reserved][hardlink]") {
    run_hardlink_shape("data dir 0400, no subdir", false, fs::perms::owner_read, fs::perms::all, false);
}

TEST_CASE("filesystem plugin: a hard link into a listable but unenterable reserved subdirectory (0644) is refused",
          "[agent][filesystem_plugin][reserved][hardlink]") {
    run_hardlink_shape("subdir 0644", true, fs::perms::owner_all,
                       fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read |
                           fs::perms::others_read,
                       false);
}

TEST_CASE("filesystem plugin: a hard link into a reserved dir whose PARENT cannot be searched is refused",
          "[agent][filesystem_plugin][reserved][hardlink]") {
    run_hardlink_shape("parent 0000", false, fs::perms::owner_all, fs::perms::all, true);
}

// NOTE: on Linux these refuse through the /proc rule (the aliases are symlinks into /proc/self), so
// this runtime case does not discriminate the /dev/fd rule itself: that is pinned by the pure
// is_dev_fd_path cases above. It exercises the macOS spelling end to end where a macOS run is owed.
TEST_CASE("filesystem plugin: /dev/fd, /dev/stdin and friends are refused on POSIX",
          "[agent][filesystem_plugin][reserved]") {
    auto handle = load_fs_plugin();
    REQUIRE(handle);
    yuzu::agent::StandalonePluginContext ctx{"filesystem", {}};
    REQUIRE(handle->descriptor()->init(ctx.get()) == 0);
    auto run = make_runner(*handle);
    for (const char* p : {"/dev/fd/0", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/fd/1"}) {
        INFO(p);
        auto r = run("read", {{"path", p}});
        CHECK(r.rc != 0);
    }
    handle->descriptor()->shutdown(ctx.get());
}

TEST_CASE("filesystem plugin: write_content refuses a dangling symlink leaf; list_dir skips reserved entries",
          "[agent][filesystem_plugin][reserved][symlink]") {
    auto handle = load_fs_plugin();
    REQUIRE(handle);
    yuzu::test::TempDir root{"yuzu_test_fs_reserved_dl_"};
    std::error_code ec;
    const auto data_dir = root.path / "data";
    const auto other = root.path / "other";
    fs::create_directories(data_dir, ec);
    fs::create_directories(other, ec);
    const auto key = data_dir / "agent-client.key";
    {
        std::ofstream o(key);
        o << "SECRET-SENTINEL\n";
    }
    {
        std::ofstream o(other / "ok.txt");
        o << "fine\n";
    }
    // A name inside the reserved dir that does not exist yet, reached through a dangling link.
    const auto planted = data_dir / "trust-planted.pem";
    const auto dangle = other / "dangle";
    std::error_code lec;
    fs::create_symlink(planted, dangle, lec);
    REQUIRE_FALSE(lec);
    const auto hard = other / "hardlink.key";
    std::error_code hec;
    fs::create_hard_link(key, hard, hec);
    const auto symkey = other / "symkey";
    fs::create_symlink(key, symkey, lec);

    yuzu::agent::StandalonePluginContext ctx{"filesystem", {{"agent.data_dir", data_dir.string()}}};
    REQUIRE(handle->descriptor()->init(ctx.get()) == 0);
    auto run = make_runner(*handle);

    auto w = run("write_content", {{"path", dangle.string()}, {"content", "EVIL"}, {"create", "true"}});
    CHECK(w.rc != 0);
    CHECK_FALSE(fs::exists(planted));

    auto ls = run("list_dir", {{"path", other.string()}});
    CHECK(ls.captured.find("ok.txt") != std::string::npos);
    CHECK(ls.captured.find("symkey") == std::string::npos);
    if (!hec)
        CHECK(ls.captured.find("hardlink.key") == std::string::npos);
    auto ls2 = run("list_dir", {{"path", root.path.string()}});
    CHECK(ls2.captured.find("entry|data|") == std::string::npos);
    CHECK(ls2.captured.find("entry|other|") != std::string::npos);
    handle->descriptor()->shutdown(ctx.get());
}

TEST_CASE("filesystem plugin: a reserved path that did not exist at init is followed through a symlink "
          "planted afterwards (WP06 F55)",
          "[agent][filesystem_plugin][reserved][symlink]") {
    auto handle = load_fs_plugin();
    REQUIRE(handle);
    yuzu::test::TempDir root{"yuzu_test_fs_reserved_late_"};
    std::error_code ec;
    const auto other = root.path / "other";
    fs::create_directories(other, ec);
    const auto target = other / "planted.pem"; // does not exist: the reserved name will dangle to it
    const auto reserved_name = root.path / "elsewhere.key"; // does not exist at init
    yuzu::agent::StandalonePluginContext ctx{
        "filesystem", {{"agent.tls_client_key", reserved_name.string()}}};
    REQUIRE(handle->descriptor()->init(ctx.get()) == 0);
    std::error_code lec;
    fs::create_symlink(target, reserved_name, lec); // planted AFTER the reserved set was built
    REQUIRE_FALSE(lec);
    auto run = make_runner(*handle);
    // The candidate does not exist, so there is no object to compare: only the re-resolved reserved
    // path (elsewhere.key -> planted.pem) can refuse it. A write would plant the agent's own key file.
    auto w = run("write_content", {{"path", target.string()}, {"content", "EVIL"}, {"create", "true"}});
    CHECK(w.rc != 0);
    CHECK_FALSE(fs::exists(target));
    handle->descriptor()->shutdown(ctx.get());
}

TEST_CASE("filesystem plugin: a reserved path the agent cannot stat does not deny unrelated paths "
          "(WP06 F55)",
          "[agent][filesystem_plugin][reserved][hardlink]") {
    if (::geteuid() == 0)
        SKIP("running as root: chmod does not hide a directory from root");
    auto handle = load_fs_plugin();
    REQUIRE(handle);
    yuzu::test::TempDir root{"yuzu_test_fs_reserved_unrel_"};
    std::error_code ec;
    const auto parent = root.path / "parent";
    const auto data_dir = parent / "data";
    fs::create_directories(data_dir, ec);
    {
        std::ofstream o(data_dir / "agent-client.key");
        o << "SECRET-SENTINEL\n";
    }
    const auto ok = root.path / "ok.txt";
    {
        std::ofstream o(ok);
        o << "fine\n";
    }
    yuzu::agent::StandalonePluginContext ctx{"filesystem", {{"agent.data_dir", data_dir.string()}}};
    REQUIRE(handle->descriptor()->init(ctx.get()) == 0);
    fs::permissions(parent, fs::perms::none, ec);
    auto run = make_runner(*handle);
    auto r = run("read", {{"path", ok.string()}});
    std::error_code rec;
    fs::permissions(parent, fs::perms::owner_all, rec);
    CHECK(r.rc == 0);
    CHECK(r.captured.find("fine") != std::string::npos);
    handle->descriptor()->shutdown(ctx.get());
}

#endif // !_WIN32

#ifdef _WIN32
// WP06 F55 (Windows only; run on a Windows host): MSVC reports a dangling NTFS junction as
// file_type::junction, so the dangling-symlink guard alone would let ofstream follow it.
TEST_CASE("filesystem plugin: write_content refuses a dangling NTFS junction leaf",
          "[agent][filesystem_plugin][reserved][junction]") {
    const auto plugin_path = sup::find_plugin();
    if (plugin_path.empty())
        SKIP("filesystem plugin library not found");
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value() || !handle->descriptor())
        SKIP("filesystem plugin did not load");
    yuzu::test::TempDir root{"yuzu_test_fs_reserved_jn_"};
    std::error_code ec;
    const auto data_dir = root.path / "data";
    const auto other = root.path / "other";
    const auto target = data_dir / "trust-planted-dir";
    fs::create_directories(other, ec);
    fs::create_directories(target, ec);
    const auto junction = other / "jn";
    const std::string cmd = "cmd /c mklink /J \"" + junction.string() + "\" \"" + target.string() + "\" >nul";
    REQUIRE(std::system(cmd.c_str()) == 0);
    fs::remove(target, ec); // the junction now dangles
    yuzu::agent::StandalonePluginContext ctx{"filesystem", {{"agent.data_dir", data_dir.string()}}};
    REQUIRE(handle->descriptor()->init(ctx.get()) == 0);
    const std::string jp = junction.string();
    const std::array<YuzuParam, 3> params{{{"path", jp.c_str()}, {"content", "EVIL"}, {"create", "true"}}};
    yuzu::agent::LocalDispatcher d;
    auto w = d.run(handle->descriptor(), "write_content", params);
    CHECK(w.rc != 0);
    CHECK_FALSE(fs::exists(target));
    handle->descriptor()->shutdown(ctx.get());
}
#endif
