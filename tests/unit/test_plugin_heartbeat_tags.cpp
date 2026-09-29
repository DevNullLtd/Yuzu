/**
 * test_plugin_heartbeat_tags.cpp -- plugin KV -> heartbeat tag bridge (#1567).
 * Fed by lambdas: no KvStore, no disk.
 */

#include "plugin_heartbeat_tags.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <optional>
#include <string>
#include <vector>

using yuzu::agent::emit_plugin_heartbeat_tags;
using yuzu::agent::emit_plugins_failed_tag;

namespace {
using Kv = std::map<std::string, std::map<std::string, std::string>>;

std::map<std::string, std::string> run(const Kv& kv, const std::vector<std::string>& plugins,
                                       std::vector<std::string>* prefixes_seen = nullptr) {
    std::map<std::string, std::string> tags;
    emit_plugin_heartbeat_tags(
        tags, plugins,
        [&](std::string_view p, std::string_view prefix) {
            if (prefixes_seen)
                prefixes_seen->emplace_back(prefix);
            std::vector<std::string> keys;
            auto it = kv.find(std::string{p});
            if (it == kv.end())
                return keys;
            for (const auto& [k, v] : it->second)
                if (k.rfind(std::string{prefix}, 0) == 0)
                    keys.push_back(k);
            return keys;
        },
        [&](std::string_view p, std::string_view k) -> std::optional<std::string> {
            auto it = kv.find(std::string{p});
            if (it == kv.end())
                return std::nullopt;
            auto j = it->second.find(std::string{k});
            if (j == it->second.end())
                return std::nullopt;
            return j->second;
        });
    return tags;
}
} // namespace

TEST_CASE("heartbeat bridge: heartbeat.* keys become yuzu.plugin.<plugin>.<key> tags",
          "[agent][heartbeat_tags]") {
    Kv kv;
    kv["tar"]["heartbeat.db_corruption_total"] = "1";
    kv["tar"]["heartbeat.db_quarantine_last"] = "1700000000:tar.db.corrupt-1700000000";
    kv["tar"]["other_key"] = "ignored"; // no heartbeat. prefix
    kv["wmi"]["unrelated"] = "x";
    std::vector<std::string> prefixes;
    auto tags = run(kv, {"tar", "wmi"}, &prefixes);
    CHECK(tags.size() == 2);
    CHECK(tags["yuzu.plugin.tar.db_corruption_total"] == "1");
    CHECK(tags["yuzu.plugin.tar.db_quarantine_last"] == "1700000000:tar.db.corrupt-1700000000");
    for (const auto& p : prefixes)
        CHECK(p == "heartbeat.");
}

TEST_CASE("heartbeat bridge: caps on key count, key shape and value size",
          "[agent][heartbeat_tags]") {
    Kv kv;
    for (int i = 0; i < 9; ++i)
        kv["p"]["heartbeat.k" + std::to_string(i)] = "v";
    auto tags = run(kv, {"p"});
    CHECK(tags.size() == 8); // first 8 in sorted order
    CHECK(tags.contains("yuzu.plugin.p.k0"));
    CHECK_FALSE(tags.contains("yuzu.plugin.p.k8"));

    Kv bad;
    bad["p"]["heartbeat.Upper"] = "v";
    bad["p"]["heartbeat.da-sh"] = "v";
    bad["p"]["heartbeat." + std::string(33, 'a')] = "v";
    bad["p"]["heartbeat.big"] = std::string(65, 'x');
    bad["p"]["heartbeat.ok"] = std::string(64, 'x');
    auto t2 = run(bad, {"p"});
    CHECK(t2.size() == 1);
    CHECK(t2.contains("yuzu.plugin.p.ok"));
}

TEST_CASE("heartbeat bridge: a vanished key or empty plugin list emits nothing",
          "[agent][heartbeat_tags]") {
    std::map<std::string, std::string> tags;
    emit_plugin_heartbeat_tags(
        tags, {"p"},
        [](std::string_view, std::string_view) { return std::vector<std::string>{"heartbeat.gone"}; },
        [](std::string_view, std::string_view) -> std::optional<std::string> { return std::nullopt; });
    CHECK(tags.empty());
    CHECK(run({}, {}).empty());
}

TEST_CASE("heartbeat bridge: plugins_failed tag joins names, omitted when none",
          "[agent][heartbeat_tags]") {
    std::map<std::string, std::string> tags;
    emit_plugins_failed_tag(tags, {});
    CHECK(tags.empty());
    emit_plugins_failed_tag(tags, {"tar"});
    CHECK(tags["yuzu.plugins_failed"] == "tar");
    emit_plugins_failed_tag(tags, {"tar", "wmi"});
    CHECK(tags["yuzu.plugins_failed"] == "tar,wmi");
}
