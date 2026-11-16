// Pure tests for collection_settings_agent.hpp: the agent side of the fleet collection settings
// (`__sync__` action `settings`). Fed by fixture strings and a fake KV: no gRPC, no process, no
// clock, no sleep. The golden vectors below are the SAME two document texts and versions the
// server package asserts (server/core/src/collection_settings_resolve.hpp canonical text), so a
// drift on either side fails a test on that side.
//
// The scheduler and collector halves live in test_inventory_sync.cpp ([collection_settings]).

#include "collection_settings_agent.hpp"
#include "sync_canonical.hpp"
#include "sync_source_installed_software.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yuzu::agent;

namespace {

using Params = std::map<std::string, std::string>;

// (A) interval 86400, window none, tz empty, the six collectors all on.
const std::string kDocA =
    "v1\ninterval=86400\nwindow=none\ntz=\n"
    "plugin.installed_apps=1\nplugin.middleware=1\nplugin.msi_packages=1\n"
    "plugin.pkg_inventory=1\nplugin.runtimes=1\nplugin.windows_optional_features=1\n";
const std::string kVersionA = "666dcf4bcd68fb46f953c27319ea5711cb71023ead925bcd1531a1510f329431";

// (B) A with registered-apps collection kill-switched.
const std::string kDocB =
    "v1\ninterval=86400\nwindow=none\ntz=\n"
    "plugin.installed_apps=0\nplugin.middleware=1\nplugin.msi_packages=1\n"
    "plugin.pkg_inventory=1\nplugin.runtimes=1\nplugin.windows_optional_features=1\n";
const std::string kVersionB = "99e0dc3e698549c6cb149543982d0753c6401cbbd5408c29c060d767b3724561";

// A document whose hash matches by construction, so a refusal can only be about its shape.
Params self_consistent(const std::string& doc) {
    return {{"version", sha256_hex(doc)}, {"document", doc}};
}

std::string refusal(const Params& p) {
    const auto r = parse_settings_command(p);
    REQUIRE_FALSE(r.has_value());
    return r.error();
}

bool contains(const std::string& s, std::string_view needle) {
    return s.find(needle) != std::string::npos;
}

// A fake KV with a switch to fail the Nth write.
struct FakeKv {
    std::map<std::string, std::string> data;
    std::vector<std::string> writes; // keys, in order
    int fail_on_write{0};            // 1-based; 0 = never

    bool set(std::string_view key, std::string_view value) {
        writes.emplace_back(key);
        if (fail_on_write != 0 && static_cast<int>(writes.size()) == fail_on_write)
            return false;
        data[std::string{key}] = std::string{value};
        return true;
    }
    std::optional<std::string> get(const std::string& key) const {
        const auto it = data.find(key);
        return it == data.end() ? std::nullopt : std::optional<std::string>{it->second};
    }
};

struct Rig {
    FakeKv kv;
    std::optional<AgentCollectionSettings> applied;
    int applies{0};

    SettingsHooks hooks() {
        return {[this](std::string_view k, std::string_view v) { return kv.set(k, v); },
                [this](const AgentCollectionSettings& s) {
                    applied = s;
                    ++applies;
                }};
    }
    SyncNowDecision run(const Params& p, bool running = true, bool inventory_disable = false) {
        return decide_sync_settings(p, inventory_disable, running, hooks());
    }
};

} // namespace

TEST_CASE("settings: both golden vectors parse and their recomputed hash equals the version",
          "[collection_settings]") {
    CHECK(sha256_hex(kDocA) == kVersionA);
    CHECK(sha256_hex(kDocB) == kVersionB);

    const auto a = parse_settings_command(Params{{"version", kVersionA}, {"document", kDocA}});
    REQUIRE(a.has_value());
    CHECK(a->version == kVersionA);
    CHECK(a->interval_s == 86400);
    CHECK_FALSE(a->window.has_value());
    CHECK(a->timezone.empty());
    CHECK(a->plugins.size() == 6);
    for (const auto& [name, on] : a->plugins) {
        INFO(name);
        CHECK(on);
    }

    // B is applied as sent: the agent adds no override for installed_apps.
    const auto b = parse_settings_command(Params{{"version", kVersionB}, {"document", kDocB}});
    REQUIRE(b.has_value());
    CHECK(b->version == kVersionB);
    CHECK_FALSE(b->plugins.at("installed_apps"));
    CHECK(b->plugins.at("middleware"));
}

TEST_CASE("settings: a window, a time zone and an unknown collector are all read as sent",
          "[collection_settings]") {
    const std::string doc =
        "v1\ninterval=172800\nwindow=60-300\ntz=Europe/London\n"
        "plugin.installed_apps=1\nplugin.middleware=0\nplugin.msi_packages=1\n"
        "plugin.pkg_inventory=1\nplugin.runtimes=1\nplugin.windows_optional_features=1\n"
        "plugin.zzz_future=0\n";
    const auto r = parse_settings_command(self_consistent(doc));
    REQUIRE(r.has_value());
    CHECK(r->interval_s == 172800);
    REQUIRE(r->window.has_value());
    CHECK(r->window->start_min == 60);
    CHECK(r->window->end_min == 300);
    CHECK(r->timezone == "Europe/London");
    CHECK_FALSE(r->plugins.at("middleware"));
    CHECK(r->plugins.contains("zzz_future")); // kept, otherwise ignored
}

TEST_CASE("settings: every refusal has its own reason", "[collection_settings]") {
    SECTION("a missing parameter") {
        const std::string a = refusal(Params{{"document", kDocA}});
        const std::string b = refusal(Params{{"version", kVersionA}});
        CHECK(contains(a, "version"));
        CHECK(contains(b, "document"));
        CHECK(a != b);
    }
    SECTION("a document over 4096 bytes") {
        std::string big = kDocA;
        big.append(4096, 'x');
        CHECK(contains(refusal(Params{{"version", sha256_hex(big)}, {"document", big}}), "4096"));
    }
    SECTION("a version that is not 64 lower-case hex") {
        for (const auto& v : {std::string{}, kVersionA.substr(1), kVersionA + "0",
                                    std::string(64, 'G'), std::string(64, 'A')}) {
            INFO(v);
            CHECK(contains(refusal(Params{{"version", v}, {"document", kDocA}}), "version"));
        }
    }
    SECTION("a version that does not equal the document's hash") {
        CHECK(contains(refusal(Params{{"version", kVersionB}, {"document", kDocA}}), "SHA-256"));
    }
    SECTION("interval out of range or not a plain integer") {
        for (const char* iv : {"3599", "604801", "0", "abc", "", "-1", "+86400", "086400"}) {
            std::string doc = kDocA;
            doc.replace(doc.find("86400"), 5, iv);
            INFO(iv);
            CHECK(contains(refusal(self_consistent(doc)), "interval"));
        }
    }
    SECTION("a window that fails 0 <= start < end <= 1440") {
        for (const char* w : {"300-60", "60-60", "0-1441", "-5-10", "a-b", "60", "60-", "-300"}) {
            std::string doc = kDocA;
            doc.replace(doc.find("none"), 4, w);
            INFO(w);
            CHECK(contains(refusal(self_consistent(doc)), "window"));
        }
    }
    SECTION("a window with an interval that is not a whole number of days") {
        const std::string doc =
            "v1\ninterval=90000\nwindow=60-300\ntz=\n"
            "plugin.installed_apps=1\nplugin.middleware=1\nplugin.msi_packages=1\n"
            "plugin.pkg_inventory=1\nplugin.runtimes=1\nplugin.windows_optional_features=1\n";
        CHECK(contains(refusal(self_consistent(doc)), "whole-day"));
        // ...but the same interval without a window is fine.
        std::string no_window = doc;
        no_window.replace(no_window.find("60-300"), 6, "none");
        CHECK(parse_settings_command(self_consistent(no_window)).has_value());
    }
    SECTION("a document that is not newline-terminated") {
        std::string doc = kDocA;
        doc.pop_back();
        CHECK(contains(refusal(self_consistent(doc)), "newline"));
        CHECK(contains(refusal(self_consistent("")), "newline"));
    }
    SECTION("a missing window=, tz= or interval= line, hash matching") {
        for (const char* gone : {"window=none\n", "tz=\n", "interval=86400\n", "v1\n"}) {
            std::string doc = kDocA;
            doc.erase(doc.find(gone), std::string{gone}.size());
            INFO(gone);
            const std::string why = refusal(self_consistent(doc));
            // The reason names the slot that is wrong: the line that took its place.
            CHECK((contains(why, "interval") || contains(why, "window") || contains(why, "tz") ||
                   contains(why, "v1")));
        }
    }
    SECTION("lines out of order or repeated") {
        const std::string head = "v1\ninterval=86400\nwindow=none\ntz=\n";
        const std::string tail =
            "plugin.installed_apps=1\nplugin.middleware=1\nplugin.msi_packages=1\n"
            "plugin.pkg_inventory=1\nplugin.runtimes=1\nplugin.windows_optional_features=1\n";
        CHECK(contains(refusal(self_consistent("v1\nwindow=none\ninterval=86400\ntz=\n" + tail)),
                       "interval"));
        CHECK(contains(refusal(self_consistent("v1\ninterval=86400\ntz=\nwindow=none\n" + tail)),
                       "window"));
        CHECK(contains(refusal(self_consistent("v1\nv1\ninterval=86400\nwindow=none\ntz=\n" + tail)),
                       "interval"));
        CHECK(contains(refusal(self_consistent(head + "window=none\n" + tail)),
                       "plugin.<name>=0|1"));
        // Plugin lines: out of order, repeated.
        CHECK(contains(refusal(self_consistent(head + "plugin.middleware=1\nplugin.installed_apps=1\n" +
                                               "plugin.msi_packages=1\nplugin.pkg_inventory=1\n" +
                                               "plugin.runtimes=1\nplugin.windows_optional_features=1\n")),
                       "out of order"));
        CHECK(contains(refusal(self_consistent(head + tail + "plugin.windows_optional_features=1\n")),
                       "repeated"));
    }
    SECTION("an unknown or malformed line, a bad switch value") {
        CHECK(contains(refusal(self_consistent(kDocA + "priority=3\n")), "priority=3"));
        CHECK(contains(refusal(self_consistent(kDocA + "\n")), "plugin.<name>=0|1"));
        CHECK(contains(refusal(self_consistent(kDocA + "plugin.zzz=2\n")), "plugin.zzz"));
        CHECK(contains(refusal(self_consistent(kDocA + "plugin.Zzz=1\n")), "plugin name"));
        CHECK(contains(refusal(self_consistent(kDocA + "plugin.=1\n")), "plugin name"));
        CHECK(contains(refusal(self_consistent(kDocA + "plugin.zzz\n")), "plugin.<name>=0|1"));
    }
    SECTION("a document that lacks the line of any collector this agent has") {
        for (const auto required : kSettingsCollectors) {
            std::string doc = kDocA;
            const std::string line = "plugin." + std::string{required} + "=1\n";
            doc.erase(doc.find(line), line.size());
            INFO(required);
            const std::string why = refusal(self_consistent(doc));
            CHECK(contains(why, "plugin." + std::string{required}));
            CHECK(contains(why, "missing"));
        }
        // ...also when there is no collector line at all.
        CHECK(contains(refusal(self_consistent("v1\ninterval=86400\nwindow=none\ntz=\n")),
                       "plugin.installed_apps"));
    }
    SECTION("a time zone that is too long or carries a stray character") {
        for (const auto& tz : {std::string(65, 'a'), std::string{"Europe/Lon don"},
                                     std::string{"Europe\\London"}}) {
            std::string doc = kDocA;
            doc.replace(doc.find("tz="), 3, "tz=" + tz);
            INFO(tz);
            CHECK(contains(refusal(self_consistent(doc)), "tz"));
        }
    }
    SECTION("a refused line is echoed bounded and printable") {
        const std::string why =
            refusal(self_consistent(kDocA + "junk" + std::string(100, '\x01') + "\n"));
        CHECK(why.size() < 300);
        for (const char c : why)
            CHECK((c >= 0x20 && c < 0x7f));
    }
}

TEST_CASE("settings: the refusals are told apart, no two share a reason", "[collection_settings]") {
    std::string no_runtimes = kDocA;
    no_runtimes.erase(no_runtimes.find("plugin.runtimes=1\n"), 18);
    std::string big = kDocA;
    big.append(4096, 'x');
    std::string no_nl = kDocA;
    no_nl.pop_back();
    std::string iv = kDocA;
    iv.replace(iv.find("86400"), 5, "10");
    std::string win = kDocA;
    win.replace(win.find("none"), 4, "300-60");
    std::string day = kDocA;
    day.replace(day.find("86400"), 5, "90000");
    day.replace(day.find("none"), 4, "60-300");
    std::string no_tz = kDocA;
    no_tz.erase(no_tz.find("tz=\n"), 4);
    const std::vector<Params> bad = {
        {{"document", kDocA}},
        {{"version", kVersionA}},
        {{"version", kVersionA}, {"document", big}},
        {{"version", "xyz"}, {"document", kDocA}},
        {{"version", kVersionB}, {"document", kDocA}},
        self_consistent(no_nl),
        self_consistent(iv),
        self_consistent(win),
        self_consistent(day),
        self_consistent(no_tz),
        self_consistent(no_runtimes),
        self_consistent(kDocA + "plugin.aaa=1\n"),   // out of order
        self_consistent(kDocA + "plugin.zzz=7\n"),   // bad value
        self_consistent(kDocA + "junk\n"),           // unknown line
    };
    std::set<std::string> reasons;
    for (const auto& p : bad)
        reasons.insert(refusal(p));
    CHECK(reasons.size() == bad.size());
}

TEST_CASE("settings: the collector list matches the installed-software collector table",
          "[collection_settings]") {
    std::set<std::string_view> table;
    for (const auto& [plugin, action, limit] : installed_software_actions()) {
        (void)action;
        (void)limit;
        table.insert(plugin);
    }
    // Every switch names a plugin the collector really has (an out-of-date name would be a switch
    // that does nothing), and the list is sorted: it is also the canonical document order.
    for (const auto name : kSettingsCollectors)
        CHECK(table.contains(name));
    for (std::size_t i = 1; i < kSettingsCollectors.size(); ++i)
        CHECK(kSettingsCollectors[i - 1] < kSettingsCollectors[i]);
}

TEST_CASE("settings: a valid command persists both keys, replies applied|version, and the tag follows",
          "[collection_settings]") {
    Rig r;
    const auto d = r.run(Params{{"version", kVersionB}, {"document", kDocB}});
    CHECK(d.status == SyncNowDecision::Status::Success);
    CHECK(d.exit_code == 0);
    CHECK(d.output == "applied|" + kVersionB);
    CHECK(r.kv.data.at("settings.document") == kDocB);
    CHECK(r.kv.data.at("settings.version") == kVersionB);
    // Document first, version second: a crash between them leaves a non-matching pair.
    CHECK(r.kv.writes == std::vector<std::string>{"settings.document", "settings.version"});
    CHECK(r.applies == 1);
    REQUIRE(r.applied.has_value());
    CHECK_FALSE(r.applied->plugins.at("installed_apps"));

    std::map<std::string, std::string> tags;
    emit_settings_tags(tags, r.applied);
    CHECK(tags.at("yuzu.inv_settings_version") == kVersionB);
    CHECK_FALSE(tags.contains("yuzu.inv_settings_tz"));
}

TEST_CASE("settings: every refusal leaves the KV and the live settings unchanged, exit 2",
          "[collection_settings]") {
    Rig r;
    REQUIRE(r.run(Params{{"version", kVersionA}, {"document", kDocA}}).exit_code == 0);
    const auto kv_before = r.kv.data;
    const auto writes_before = r.kv.writes;

    std::string incomplete = kDocB;
    incomplete.erase(incomplete.find("plugin.runtimes=1\n"), 18);
    for (const Params& bad : {Params{{"document", kDocB}},                                   // no version
                              Params{{"version", kVersionB}, {"document", kDocA}},           // hash
                              Params{{"version", sha256_hex(incomplete)}, {"document", incomplete}}}) {
        const auto d = r.run(bad);
        CHECK(d.status == SyncNowDecision::Status::Failure);
        CHECK(d.exit_code == 2);
        CHECK_FALSE(d.output.empty());
        CHECK(r.kv.data == kv_before);
        CHECK(r.kv.writes == writes_before);
        CHECK(r.applies == 1);
        CHECK(r.applied->version == kVersionA);
    }
}

TEST_CASE("settings: a KV write failure is FAILURE exit 1 and the previous settings stay live",
          "[collection_settings]") {
    for (int failing_write : {1, 2}) {
        Rig r;
        REQUIRE(r.run(Params{{"version", kVersionA}, {"document", kDocA}}).exit_code == 0);
        r.kv.writes.clear();
        r.kv.fail_on_write = failing_write;
        const auto d = r.run(Params{{"version", kVersionB}, {"document", kDocB}});
        INFO("failing write " << failing_write);
        CHECK(d.status == SyncNowDecision::Status::Failure);
        CHECK(d.exit_code == 1);
        CHECK(r.applies == 1); // B never reached the scheduler or the collector
        CHECK(r.applied->version == kVersionA);
    }
}

TEST_CASE("settings: with no scheduler running the command fails exit 1 and changes nothing",
          "[collection_settings]") {
    Rig r;
    const Params p{{"version", kVersionA}, {"document", kDocA}};
    const auto not_connected = r.run(p, /*running=*/false);
    CHECK(not_connected.status == SyncNowDecision::Status::Failure);
    CHECK(not_connected.exit_code == 1);
    CHECK(contains(not_connected.output, "not connected"));
    const auto disabled = r.run(p, /*running=*/false, /*inventory_disable=*/true);
    CHECK(disabled.exit_code == 1);
    CHECK(contains(disabled.output, "--inventory-disable"));
    CHECK(r.kv.writes.empty());
    CHECK(r.applies == 0);
}

TEST_CASE("settings: restart applies a valid stored pair and discards a mismatched one",
          "[collection_settings]") {
    Rig r;
    REQUIRE(r.run(Params{{"version", kVersionB}, {"document", kDocB}}).exit_code == 0);
    const auto get = [&](const std::string& k) { return r.kv.get(k); };

    SECTION("a valid stored pair is applied as sent") {
        const auto stored = load_stored_settings(get);
        REQUIRE(stored.has_value());
        CHECK(stored->version == kVersionB);
        CHECK_FALSE(stored->plugins.at("installed_apps"));
        std::map<std::string, std::string> tags;
        emit_settings_tags(tags, stored.has_value() ? std::optional{*stored} : std::nullopt);
        CHECK(tags.at("yuzu.inv_settings_version") == kVersionB);
    }
    SECTION("a crash between the two writes: new document, old version") {
        r.kv.data["settings.document"] = kDocA; // the document write landed, the version write did not
        const auto stored = load_stored_settings(get);
        REQUIRE_FALSE(stored.has_value());
        CHECK(stored.error() != kNoStoredSettings);
        CHECK(contains(stored.error(), "SHA-256"));
        std::map<std::string, std::string> tags;
        emit_settings_tags(tags, std::nullopt);
        CHECK(tags.at("yuzu.inv_settings_version") == "none");
    }
    SECTION("a stored pair that is self-consistent but incomplete is not applied") {
        std::string incomplete = kDocB;
        incomplete.erase(incomplete.find("plugin.runtimes=1\n"), 18);
        r.kv.data["settings.document"] = incomplete;
        r.kv.data["settings.version"] = sha256_hex(incomplete);
        const auto stored = load_stored_settings(get);
        REQUIRE_FALSE(stored.has_value());
        CHECK(contains(stored.error(), "plugin.runtimes"));
    }
    SECTION("no stored pair at all is not an error to log") {
        FakeKv empty;
        const auto stored = load_stored_settings([&](const std::string& k) { return empty.get(k); });
        REQUIRE_FALSE(stored.has_value());
        CHECK(stored.error() == kNoStoredSettings);
    }
    SECTION("one key without the other is discarded") {
        r.kv.data.erase("settings.version");
        const auto stored = load_stored_settings(get);
        REQUIRE_FALSE(stored.has_value());
        CHECK(stored.error() != kNoStoredSettings);
    }
}

TEST_CASE("settings: a non-empty tz is reported, and only then", "[collection_settings]") {
    const std::string doc =
        "v1\ninterval=86400\nwindow=60-300\ntz=Europe/London\n"
        "plugin.installed_apps=1\nplugin.middleware=1\nplugin.msi_packages=1\n"
        "plugin.pkg_inventory=1\nplugin.runtimes=1\nplugin.windows_optional_features=1\n";
    const auto with_tz = parse_settings_command(self_consistent(doc));
    REQUIRE(with_tz.has_value());
    std::map<std::string, std::string> tags;
    emit_settings_tags(tags, std::optional<AgentCollectionSettings>{*with_tz});
    CHECK(tags.at("yuzu.inv_settings_version") == with_tz->version);
    CHECK(tags.at("yuzu.inv_settings_tz") == "machine_local");

    tags.clear();
    emit_settings_tags(tags, std::optional<AgentCollectionSettings>{});
    CHECK(tags.at("yuzu.inv_settings_version") == "none"); // always present
    CHECK_FALSE(tags.contains("yuzu.inv_settings_tz"));
}
