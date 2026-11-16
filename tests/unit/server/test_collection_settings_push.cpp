/**
 * test_collection_settings_push.cpp - heartbeat-driven delivery of the effective software
 * collection settings (SAM-39): the pure `decide_push` table and `CollectionSettingsPusher` with
 * fake reads, a fake clock and a recording send. No Postgres, no sleeps, no real I/O. The
 * interleavings are driven by a fake read or send that re-enters `on_heartbeat` (no lock is held
 * across either, so the re-entry is legal and deterministic).
 */

#include "collection_settings_push.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace cs = yuzu::server::collection_settings;
using cs::PushVerdict;

namespace {

// Golden vectors shared with the agent suite (the agent applies the document exactly as sent).
// A: interval 86400, no window, no zone, every collector on.
// B: the same with the registered apps collector kill-switched.
constexpr const char* kGoldenAText =
    "v1\ninterval=86400\nwindow=none\ntz=\nplugin.installed_apps=1\nplugin.middleware=1\n"
    "plugin.msi_packages=1\nplugin.pkg_inventory=1\nplugin.runtimes=1\n"
    "plugin.windows_optional_features=1\n";
constexpr const char* kGoldenAVersion =
    "666dcf4bcd68fb46f953c27319ea5711cb71023ead925bcd1531a1510f329431";
constexpr const char* kGoldenBText =
    "v1\ninterval=86400\nwindow=none\ntz=\nplugin.installed_apps=0\nplugin.middleware=1\n"
    "plugin.msi_packages=1\nplugin.pkg_inventory=1\nplugin.runtimes=1\n"
    "plugin.windows_optional_features=1\n";
constexpr const char* kGoldenBVersion =
    "99e0dc3e698549c6cb149543982d0753c6401cbbd5408c29c060d767b3724561";

const std::string kRoot{cs::kRootGroupId};
const std::string kNone{cs::kNoSettingsTag};

cs::EffectiveSettings golden_a() {
    cs::EffectiveSettings e;
    e.interval_s = 86400;
    for (const auto p : cs::kCollectionPlugins)
        e.plugins[std::string{p}] = true;
    return e;
}

cs::StoredDocument doc_for(const std::string& group, int interval_s) {
    cs::StoredDocument d;
    d.group_id = group;
    d.settings = cs::kFleetDefault;
    d.settings.interval_s = interval_s;
    d.settings.window = std::nullopt;
    return d;
}

std::string version_for_interval(int interval_s) {
    auto e = golden_a();
    e.interval_s = interval_s;
    return *cs::effective_version(e);
}

struct Sent {
    std::string agent;
    std::string version;
    std::string document;
};

/// One pusher wired to fakes. Tree: root, g1 and g2 under it. Agents default to the root group.
struct Fake {
    std::int64_t t{1'000'000};
    std::optional<std::vector<cs::StoredDocument>> docs{std::vector<cs::StoredDocument>{}};
    std::optional<std::vector<cs::GroupNode>> tree{std::vector<cs::GroupNode>{
        {kRoot, "", 0}, {"g1", kRoot, 1}, {"g2", kRoot, 2}}};
    std::optional<std::map<std::string, bool>> killed{std::map<std::string, bool>{}};
    std::map<std::string, std::vector<std::string>> groups; // agent -> membership (default root)
    bool membership_fails{false};
    bool send_ok{true};

    int docs_reads{0};
    int membership_reads{0};
    std::vector<Sent> sent;
    std::map<std::string, int> degrades;
    std::map<std::string, int> results;

    // One-shot hooks run inside the named fake before it answers.
    std::function<void()> in_membership;
    std::function<void()> in_send;

    // Lock probe: while set, every fake checks that another thread can enter the pusher.
    bool lock_probe{false};
    bool in_probe{false};
    bool probe_all_free{true};
    int probes{0};

    std::unique_ptr<cs::CollectionSettingsPusher> pusher;

    Fake() {
        cs::CollectionSettingsPusher::Deps d;
        d.read_docs = [this] {
            ++docs_reads;
            probe();
            return docs;
        };
        d.read_tree = [this] {
            probe();
            return tree;
        };
        d.read_killed = [this] {
            probe();
            return killed;
        };
        d.read_membership = [this](const std::string& agent) -> std::optional<std::vector<std::string>> {
            ++membership_reads;
            probe();
            run_once(in_membership);
            if (membership_fails)
                return std::nullopt;
            const auto it = groups.find(agent);
            return it == groups.end() ? std::vector<std::string>{kRoot} : it->second;
        };
        d.now = [this] { return t; };
        d.send = [this](const std::string& agent, const std::string& version,
                        const std::string& document) {
            probe();
            sent.push_back({agent, version, document});
            run_once(in_send);
            return send_ok;
        };
        d.on_degrade = [this](std::string_view r) { ++degrades[std::string{r}]; };
        d.on_result = [this](std::string_view r) { ++results[std::string{r}]; };
        pusher = std::make_unique<cs::CollectionSettingsPusher>(std::move(d));
    }

    void hb(const std::string& agent, const std::string& tag = kNone) {
        pusher->on_heartbeat(agent, tag);
    }

    /// Sends to a real agent (the lock probe's own agent is excluded).
    std::vector<Sent> sent_to_agents() const {
        std::vector<Sent> out;
        for (const auto& s : sent)
            if (s.agent != "probe-agent")
                out.push_back(s);
        return out;
    }

    static void run_once(std::function<void()>& hook) {
        if (!hook)
            return;
        auto h = std::move(hook);
        hook = nullptr;
        h();
    }

    void probe() {
        if (!lock_probe || in_probe)
            return;
        in_probe = true;
        ++probes;
        auto fut = std::async(std::launch::async, [this] { pusher->on_heartbeat("probe-agent", kNone); });
        if (fut.wait_for(std::chrono::seconds(10)) != std::future_status::ready)
            probe_all_free = false;
        fut.wait();
        in_probe = false;
    }
};

} // namespace

TEST_CASE("decide_push table", "[collection_settings][push]") {
    const std::string v1(64, 'a');
    const std::string v2(64, 'b');
    const std::optional<cs::LastPush> none_pushed;

    SECTION("equal versions are up to date") {
        CHECK(cs::decide_push(v1, v1, false, none_pushed, 100) == PushVerdict::UpToDate);
        CHECK(cs::decide_push(v1, v1, true, cs::LastPush{v1, 99}, 100) == PushVerdict::UpToDate);
    }
    SECTION("none against the built-in default is up to date") {
        CHECK(cs::decide_push(kNone, v1, true, none_pushed, 100) == PushVerdict::UpToDate);
    }
    SECTION("none against a non-default document is pushed") {
        CHECK(cs::decide_push(kNone, v1, false, none_pushed, 100) == PushVerdict::Push);
    }
    SECTION("a stale version is pushed, even against the default") {
        CHECK(cs::decide_push(v2, v1, false, none_pushed, 100) == PushVerdict::Push);
        CHECK(cs::decide_push(v2, v1, true, none_pushed, 100) == PushVerdict::Push);
    }
    SECTION("the same version is suppressed inside the gap and pushed again after it") {
        const cs::LastPush last{v1, 1000};
        CHECK(cs::decide_push(v2, v1, false, last, 1000) == PushVerdict::Suppressed);
        CHECK(cs::decide_push(v2, v1, false, last, 1000 + cs::kMinRepushGapSecs - 1) ==
              PushVerdict::Suppressed);
        CHECK(cs::decide_push(v2, v1, false, last, 1000 + cs::kMinRepushGapSecs) ==
              PushVerdict::Push);
    }
    SECTION("a different version is pushed inside the gap") {
        const cs::LastPush last{v2, 1000};
        CHECK(cs::decide_push(kNone, v1, false, last, 1001) == PushVerdict::Push);
    }
    SECTION("a clock that stepped back does not suppress forever") {
        CHECK(cs::decide_push(v2, v1, false, cs::LastPush{v1, 5000}, 1000) == PushVerdict::Push);
    }
}

TEST_CASE("is_reportable_tag accepts only none and 64 lower-case hex",
          "[collection_settings][push]") {
    CHECK(cs::is_reportable_tag("none"));
    CHECK(cs::is_reportable_tag(kGoldenAVersion));
    CHECK_FALSE(cs::is_reportable_tag(""));
    CHECK_FALSE(cs::is_reportable_tag("None"));
    CHECK_FALSE(cs::is_reportable_tag(std::string(63, 'a')));
    CHECK_FALSE(cs::is_reportable_tag(std::string(65, 'a')));
    CHECK_FALSE(cs::is_reportable_tag(std::string(64, 'A')));
    CHECK_FALSE(cs::is_reportable_tag(std::string(63, 'a') + "g"));
}

TEST_CASE("golden vectors: canonical text and version", "[collection_settings][push]") {
    const auto a = golden_a();
    CHECK(cs::canonical_text(a) == kGoldenAText);
    CHECK(*cs::effective_version(a) == kGoldenAVersion);

    auto b = a;
    b.plugins["installed_apps"] = false;
    CHECK(cs::canonical_text(b) == kGoldenBText);
    CHECK(*cs::effective_version(b) == kGoldenBVersion);
    CHECK(cs::canonical_text(b).find("plugin.installed_apps=0") != std::string::npos);
}

TEST_CASE("the pusher sends golden A, and golden B when a collector is kill-switched",
          "[collection_settings][push]") {
    Fake f;
    f.docs = std::vector<cs::StoredDocument>{doc_for(kRoot, 86400)};

    SECTION("A") {
        f.hb("agent-1");
        REQUIRE(f.sent.size() == 1);
        CHECK(f.sent[0].document == kGoldenAText);
        CHECK(f.sent[0].version == kGoldenAVersion);
    }
    SECTION("B: the kill switch is the server's decision and the document carries it") {
        f.killed = std::map<std::string, bool>{{"installed_apps", true}};
        f.hb("agent-1");
        REQUIRE(f.sent.size() == 1);
        CHECK(f.sent[0].document == kGoldenBText);
        CHECK(f.sent[0].version == kGoldenBVersion);
        CHECK(f.sent[0].document.find("plugin.installed_apps=0") != std::string::npos);
    }
}

TEST_CASE("a stale agent is sent the document once and not again inside the gap",
          "[collection_settings][push]") {
    Fake f;
    f.docs = std::vector<cs::StoredDocument>{doc_for("g1", 172800)};
    f.groups["a"] = {"g1"};
    const auto v = version_for_interval(172800);

    f.hb("a", std::string(64, 'c'));
    REQUIRE(f.sent.size() == 1);
    CHECK(f.sent[0].version == v);
    CHECK(f.results["sent"] == 1);

    f.t += 10;
    f.hb("a", std::string(64, 'c')); // still stale: the send may be in flight
    f.t += cs::kMinRepushGapSecs - 11;
    f.hb("a", kNone);
    CHECK(f.sent.size() == 1);
    CHECK(f.results["suppressed"] == 2);

    f.t += 2; // the gap has passed and the agent still reports the old version
    f.hb("a", kNone);
    CHECK(f.sent.size() == 2);

    f.hb("a", v); // applied
    CHECK(f.sent.size() == 2);
}

TEST_CASE("an agent on the built-in default or already current is sent nothing",
          "[collection_settings][push]") {
    Fake f; // no documents: the built-in fleet default applies
    f.hb("a", kNone);
    CHECK(f.sent.empty());
    CHECK(f.results.empty());

    // A stale non-none version is moved back to the default.
    f.hb("a", std::string(64, 'd'));
    REQUIRE(f.sent.size() == 1);
    CHECK(f.sent[0].version == *cs::effective_version(cs::kFleetDefault.effective()));

    Fake g;
    g.docs = std::vector<cs::StoredDocument>{doc_for("g1", 172800)};
    g.groups["a"] = {"g1"};
    g.hb("a", version_for_interval(172800));
    CHECK(g.sent.empty());
}

TEST_CASE("a killed collector turns the default into a document that is pushed",
          "[collection_settings][push]") {
    Fake f; // built-in default, but with one collector off it is no longer the default
    f.killed = std::map<std::string, bool>{{"runtimes", true}};
    f.hb("a", kNone);
    REQUIRE(f.sent.size() == 1);
    CHECK(f.sent[0].document.find("plugin.runtimes=0") != std::string::npos);
}

TEST_CASE("a changed document reaches the next heartbeat after the snapshot TTL, inside the gap",
          "[collection_settings][push]") {
    Fake f;
    f.docs = std::vector<cs::StoredDocument>{doc_for("g1", 172800)};
    f.groups["a"] = {"g1"};
    const auto v1 = version_for_interval(172800);
    const auto v2 = version_for_interval(259200);

    f.hb("a", kNone);
    REQUIRE(f.sent.size() == 1);
    CHECK(f.sent[0].version == v1);

    f.docs = std::vector<cs::StoredDocument>{doc_for("g1", 259200)};
    f.t += cs::kSnapshotTtlSecs - 1;
    f.hb("a", v1); // still the old snapshot
    CHECK(f.sent.size() == 1);

    f.t += 1; // 60 s: the snapshot is re-read; 60 s is well inside the 300 s re-push gap
    f.hb("a", v1);
    REQUIRE(f.sent.size() == 2);
    CHECK(f.sent[1].version == v2);
    CHECK(f.docs_reads == 2);
}

TEST_CASE("a membership change is seen after the membership TTL", "[collection_settings][push]") {
    Fake f;
    f.docs = std::vector<cs::StoredDocument>{doc_for("g1", 172800), doc_for("g2", 259200)};
    f.groups["a"] = {"g1"};
    const auto v1 = version_for_interval(172800);
    const auto v2 = version_for_interval(259200);

    f.hb("a", kNone);
    REQUIRE(f.sent.size() == 1);
    CHECK(f.membership_reads == 1);

    f.groups["a"] = {"g2"};
    f.t += cs::kSnapshotTtlSecs + 1; // a new snapshot epoch re-resolves from the cached membership
    f.hb("a", v1);
    CHECK(f.sent.size() == 1);
    CHECK(f.membership_reads == 1);

    f.t = 1'000'000 + cs::kMembershipTtlSecs; // the membership read has expired
    f.hb("a", v1);
    REQUIRE(f.sent.size() == 2);
    CHECK(f.sent[1].version == v2);
    CHECK(f.membership_reads == 2);
}

TEST_CASE("a degraded read pushes nothing, counts a degrade and the previous snapshot keeps serving",
          "[collection_settings][push]") {
    Fake f;
    f.docs = std::vector<cs::StoredDocument>{doc_for(kRoot, 172800)};

    SECTION("no snapshot yet: nothing is pushed until a read succeeds") {
        const auto good = *f.docs;
        for (int which = 0; which < 3; ++which) {
            Fake g;
            g.docs = good;
            if (which == 0)
                g.docs = std::nullopt;
            if (which == 1)
                g.tree = std::nullopt;
            if (which == 2)
                g.killed = std::nullopt;
            g.hb("a", kNone);
            CHECK(g.sent.empty());
            CHECK(g.degrades["snapshot"] == 1);
        }
        f.hb("a", kNone);
        CHECK(f.sent.size() == 1);
    }
    SECTION("a failed refresh is retried after the TTL, not on every heartbeat") {
        f.docs = std::nullopt;
        f.hb("a", kNone);
        f.hb("b", kNone);
        CHECK(f.docs_reads == 1);
        CHECK(f.degrades["snapshot"] == 1);
        f.docs = std::vector<cs::StoredDocument>{doc_for(kRoot, 172800)};
        f.t += cs::kSnapshotTtlSecs;
        f.hb("a", kNone);
        CHECK(f.sent.size() == 1);
    }
    SECTION("a failed refresh keeps the previous snapshot") {
        f.hb("a", kNone);
        REQUIRE(f.sent.size() == 1);
        f.docs = std::nullopt;
        f.t += cs::kSnapshotTtlSecs;
        f.hb("b", kNone); // refresh fails; the old document still applies
        CHECK(f.degrades["snapshot"] == 1);
        REQUIRE(f.sent.size() == 2);
        CHECK(f.sent[1].version == version_for_interval(172800));
    }
    SECTION("a failed membership read pushes nothing") {
        f.membership_fails = true;
        f.hb("a", kNone);
        CHECK(f.sent.empty());
        CHECK(f.degrades["membership"] == 1);
        f.membership_fails = false;
        f.hb("a", kNone);
        CHECK(f.sent.size() == 1);
    }
}

TEST_CASE("a send that returns false keeps its stamp", "[collection_settings][push]") {
    Fake f;
    f.docs = std::vector<cs::StoredDocument>{doc_for(kRoot, 172800)};
    f.send_ok = false;

    f.hb("a", kNone);
    CHECK(f.results["undelivered"] == 1);
    f.t += 5;
    f.hb("a", kNone);
    CHECK(f.sent.size() == 1);
    CHECK(f.results["suppressed"] == 1);

    f.t += cs::kMinRepushGapSecs;
    f.send_ok = true;
    f.hb("a", kNone);
    CHECK(f.sent.size() == 2);
    CHECK(f.results["sent"] == 1);
}

TEST_CASE("memo entries not seen for an hour are evicted at a snapshot refresh",
          "[collection_settings][push]") {
    Fake f;
    f.docs = std::vector<cs::StoredDocument>{doc_for(kRoot, 172800)};
    f.hb("a", kNone);
    f.hb("b", kNone);
    CHECK(f.pusher->tracked_agents() == 2);

    f.t += cs::kMemoEvictSecs - 1;
    f.hb("b", kNone); // refresh happens here, but a was seen 3599 s ago
    CHECK(f.pusher->tracked_agents() == 2);

    f.t += cs::kMemoEvictSecs - 1;
    f.hb("b", kNone); // refresh: a was last seen 7198 s ago, b 3599 s ago
    CHECK(f.pusher->tracked_agents() == 1);
}

TEST_CASE("no store read and no send happens while the mutex is held",
          "[collection_settings][push]") {
    Fake f;
    f.lock_probe = true;
    f.docs = std::vector<cs::StoredDocument>{doc_for(kRoot, 172800)};
    f.hb("a", kNone);
    REQUIRE(f.sent_to_agents().size() == 1);
    // docs, tree, killed, membership and send were each probed.
    CHECK(f.probes >= 5);
    CHECK(f.probe_all_free);
}

TEST_CASE("interleaving: a snapshot refreshed during a membership read sends the newer version once",
          "[collection_settings][push]") {
    Fake f;
    f.docs = std::vector<cs::StoredDocument>{doc_for(kRoot, 172800)};
    const auto v1 = version_for_interval(172800);
    const auto v2 = version_for_interval(259200);

    // The first heartbeat of agent "a" resolves against epoch 1 (document 172800). While its
    // membership is being read, the document changes, a minute passes and a second heartbeat of
    // the same agent runs to completion against epoch 2.
    f.in_membership = [&] {
        f.docs = std::vector<cs::StoredDocument>{doc_for(kRoot, 259200)};
        f.t += cs::kSnapshotTtlSecs;
        f.hb("a", kNone);
    };
    f.hb("a", kNone);

    // The outer computation (epoch 1) is discarded: the newer memo is the one decided on and the
    // inner heartbeat's stamp suppresses it. One send, of the newer version.
    REQUIRE(f.sent.size() == 1);
    CHECK(f.sent[0].version == v2);
    CHECK(f.results["sent"] == 1);
    CHECK(f.results["suppressed"] == 1);

    // The memo still holds the newer version: an agent that applied it is up to date, and the
    // older version is never sent.
    f.hb("a", v2);
    CHECK(f.sent.size() == 1);
    f.t += cs::kMinRepushGapSecs;
    f.hb("a", v2);
    CHECK(f.sent.size() == 1);
    for (const auto& s : f.sent)
        CHECK(s.version != v1);
}

TEST_CASE("interleaving: a memo computed from an older epoch never replaces a newer one",
          "[collection_settings][push]") {
    Fake f;
    f.docs = std::vector<cs::StoredDocument>{doc_for(kRoot, 172800)};
    const auto v2 = version_for_interval(259200);

    f.in_membership = [&] {
        f.docs = std::vector<cs::StoredDocument>{doc_for(kRoot, 259200)};
        f.t += cs::kSnapshotTtlSecs;
        f.hb("a", v2); // the inner heartbeat reports the newer version: up to date, memo stored
    };
    f.hb("a", v2);
    CHECK(f.sent.empty()); // had the epoch-1 memo replaced it, the outer would have pushed 172800

    f.hb("a", v2);
    CHECK(f.sent.empty());
}

TEST_CASE("interleaving: two overlapping heartbeats for one agent produce one send",
          "[collection_settings][push]") {
    Fake f;
    f.docs = std::vector<cs::StoredDocument>{doc_for(kRoot, 172800)};
    // The send is in flight (outside the mutex) when the same agent's next heartbeat arrives.
    f.in_send = [&] { f.hb("a", kNone); };
    f.hb("a", kNone);
    CHECK(f.sent.size() == 1);
    CHECK(f.results["sent"] == 1);
    CHECK(f.results["suppressed"] == 1);
}
