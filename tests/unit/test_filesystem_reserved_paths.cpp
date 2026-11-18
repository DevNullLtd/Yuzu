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
#include <filesystem>
#include <fstream>
#include <string>

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
        WARN("filesystem plugin library not found -- skipping");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value() || !handle->descriptor()) {
        WARN("filesystem plugin did not load -- skipping");
        return;
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
        WARN("filesystem plugin library not found -- skipping");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value() || !handle->descriptor()) {
        WARN("filesystem plugin did not load -- skipping");
        return;
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
#endif
