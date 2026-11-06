/**
 * test_collection_settings_resolve.cpp - the pure per-group collection settings core
 * (collection_settings_resolve.hpp): validator, canonical text, version hashes and the resolver.
 * No store, no I/O, no clock, no Postgres.
 */

#include "collection_settings_resolve.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

namespace cs = yuzu::server::collection_settings;

namespace {

const std::string kRoot{cs::kRootGroupId};

cs::CollectionSettings make(int interval = 86400, std::optional<cs::Window> window = std::nullopt,
                            int priority = 0) {
    cs::CollectionSettings s = cs::kFleetDefault;
    s.interval_s = interval;
    s.window = window;
    s.priority = priority;
    return s;
}

cs::StoredDocument doc(const std::string& group, cs::CollectionSettings s) {
    cs::StoredDocument d;
    d.group_id = group;
    d.settings = std::move(s);
    return d;
}

cs::GroupNode node(const std::string& id, const std::string& parent, std::int64_t created) {
    return cs::GroupNode{id, parent, created};
}

const std::map<std::string, bool> kNoKills{};

bool invalid(const cs::CollectionSettings& s, bool is_root = false) {
    return !cs::validate(s, is_root).has_value();
}

} // namespace

TEST_CASE("collection settings validate: interval bounds", "[collection_settings][resolve]") {
    CHECK(invalid(make(3599, std::nullopt)));
    CHECK_FALSE(invalid(make(3600, std::nullopt)));
    CHECK_FALSE(invalid(make(604800, std::nullopt)));
    CHECK(invalid(make(604801, std::nullopt)));
}

TEST_CASE("collection settings validate: a window needs a whole-day interval",
          "[collection_settings][resolve]") {
    const cs::Window w{60, 300};
    CHECK(invalid(make(86399, w)));
    CHECK_FALSE(invalid(make(86400, w)));
    CHECK(invalid(make(90000, w))); // 25 h
    CHECK_FALSE(invalid(make(172800, w)));
    CHECK(invalid(make(86400, cs::Window{300, 300})));
    CHECK(invalid(make(86400, cs::Window{300, 60})));
    CHECK(invalid(make(86400, cs::Window{0, 1441})));
    CHECK(invalid(make(86400, cs::Window{-1, 60})));
    CHECK_FALSE(invalid(make(86400, cs::Window{0, 1440})));
    // No window: a non-whole-day interval is fine.
    CHECK_FALSE(invalid(make(90000, std::nullopt)));
}

TEST_CASE("collection settings validate: plugin switches", "[collection_settings][resolve]") {
    auto off = make();
    off.plugins["installed_apps"] = false;
    const auto r = cs::validate(off, false);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("registered apps") != std::string::npos);

    auto unknown = make();
    unknown.plugins["evidence"] = true;
    CHECK(invalid(unknown));

    auto missing = make();
    missing.plugins.erase("runtimes");
    CHECK(invalid(missing));

    auto runtimes_off = make();
    runtimes_off.plugins["runtimes"] = false;
    CHECK_FALSE(invalid(runtimes_off));
}

TEST_CASE("collection settings validate: priority and root", "[collection_settings][resolve]") {
    CHECK(invalid(make(86400, std::nullopt, 1001)));
    CHECK(invalid(make(86400, std::nullopt, -1)));
    CHECK_FALSE(invalid(make(86400, std::nullopt, 1000)));
    CHECK(invalid(make(86400, std::nullopt, 1), /*is_root=*/true));
    CHECK_FALSE(invalid(make(86400, std::nullopt, 0), /*is_root=*/true));
}

TEST_CASE("collection settings validate: timezone shape only", "[collection_settings][resolve]") {
    auto s = make();
    s.timezone = "Europe/London";
    CHECK_FALSE(invalid(s));
    s.timezone = "Etc/GMT+5";
    CHECK_FALSE(invalid(s));
    s.timezone = std::string(65, 'a');
    CHECK(invalid(s));
    s.timezone = "Europe London";
    CHECK(invalid(s));
    s.timezone = "Europe/London\n";
    CHECK(invalid(s));
    // Shape only: a well-formed name that is not a zone passes here; the store checks existence.
    s.timezone = "Mars/Olympus";
    CHECK_FALSE(invalid(s));
}

TEST_CASE("collection settings resolve: no documents gives the fleet default",
          "[collection_settings][resolve]") {
    const auto r = cs::resolve({"aa"}, {node(kRoot, "", 1), node("aa", "", 2)}, {}, kNoKills);
    REQUIRE(r.has_value());
    CHECK(r->source_group_id.empty());
    CHECK(r->effective == cs::kFleetDefault.effective());
    CHECK(r->version == "e27b0298c4ad0aabc3963e6dfa2ca5a3d60b687fa15315557385a020816d1696");
}

TEST_CASE("collection settings resolve: the root document is the default layer",
          "[collection_settings][resolve]") {
    const auto r = cs::resolve({kRoot, "aa"}, {node(kRoot, "", 1), node("aa", "", 2)},
                               {doc(kRoot, make(7200))}, kNoKills);
    REQUIRE(r.has_value());
    CHECK(r->source_group_id == kRoot);
    CHECK(r->effective.interval_s == 7200);
}

TEST_CASE("collection settings resolve: a top-level group beats an older root document",
          "[collection_settings][resolve]") {
    // Root is older and at depth 0 like a top-level group; it must never compete.
    const auto r = cs::resolve({kRoot, "aa"}, {node(kRoot, "", 1), node("aa", "", 2)},
                               {doc(kRoot, make(7200)), doc("aa", make(10800))}, kNoKills);
    REQUIRE(r.has_value());
    CHECK(r->source_group_id == "aa");
    CHECK(r->effective.interval_s == 10800);
}

TEST_CASE("collection settings resolve: inheritance and nearest ancestor",
          "[collection_settings][resolve]") {
    const std::vector<cs::GroupNode> tree{node("gp", "", 1), node("pa", "gp", 2),
                                          node("lf", "pa", 3)};
    SECTION("document on the grandparent only") {
        const auto r = cs::resolve({"lf"}, tree, {doc("gp", make(7200))}, kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "gp");
    }
    SECTION("the nearest ancestor wins over a farther one") {
        const auto r = cs::resolve({"lf"}, tree, {doc("gp", make(7200)), doc("pa", make(10800))},
                                   kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "pa");
        CHECK(r->effective.interval_s == 10800);
    }
}

TEST_CASE("collection settings resolve: priority is cross-branch only",
          "[collection_settings][resolve]") {
    SECTION("a member of an ancestor and its descendant resolves to the descendant") {
        const std::vector<cs::GroupNode> tree{node("pa", "", 1), node("ch", "pa", 2)};
        const auto r = cs::resolve({"pa", "ch"}, tree,
                                   {doc("pa", make(7200, std::nullopt, 50)),
                                    doc("ch", make(10800, std::nullopt, 0))},
                                   kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "ch");
    }
    SECTION("unrelated branches: higher priority wins regardless of depth") {
        const std::vector<cs::GroupNode> tree{node("t1", "", 1), node("t2", "", 2),
                                              node("d2", "t2", 3)};
        const auto r = cs::resolve({"t1", "d2"}, tree,
                                   {doc("t1", make(7200, std::nullopt, 10)),
                                    doc("d2", make(10800, std::nullopt, 5))},
                                   kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "t1");
    }
}

// Branches are MEMBERSHIP groups, not documents: a membership group that is an ancestor of
// another membership group is dropped (the nearer one stands for that branch); each remaining
// membership group's branch winner is the nearest group with a document (itself first, root
// excluded); the branch winners compete by priority, depth, created_at, id.
TEST_CASE("collection settings resolve: membership branches", "[collection_settings][resolve]") {
    SECTION("sibling memberships under one ancestor: the ancestor's document competes for its "
            "own branch") {
        // X has a document (900); member of G1 (no document) and G2 (document, 0). G1's branch
        // winner is X, G2's is G2: X outranks G2.
        const std::vector<cs::GroupNode> tree{node("xx", "", 1), node("g1", "xx", 2),
                                              node("g2", "xx", 3)};
        const auto r = cs::resolve({"g1", "g2"}, tree,
                                   {doc("xx", make(7200, std::nullopt, 900)),
                                    doc("g2", make(10800, std::nullopt, 0))},
                                   kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "xx");
        CHECK(r->effective.interval_s == 7200);
    }
    SECTION("sibling memberships under one ancestor: a higher-priority sibling still wins") {
        const std::vector<cs::GroupNode> tree{node("xx", "", 1), node("g1", "xx", 2),
                                              node("g2", "xx", 3)};
        const auto r = cs::resolve({"g1", "g2"}, tree,
                                   {doc("xx", make(7200, std::nullopt, 0)),
                                    doc("g2", make(10800, std::nullopt, 5))},
                                   kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "g2");
    }
    SECTION("sibling memberships under one ancestor: equal priority, the deeper document wins") {
        const std::vector<cs::GroupNode> tree{node("xx", "", 1), node("g1", "xx", 2),
                                              node("g2", "xx", 3)};
        const auto r = cs::resolve({"g1", "g2"}, tree,
                                   {doc("xx", make(7200)), doc("g2", make(10800))}, kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "g2");
    }
    SECTION("member of P and its descendant C: C's branch decides whatever the priorities") {
        const std::vector<cs::GroupNode> tree{node("pp", "", 1), node("cc", "pp", 2)};
        const auto r = cs::resolve({"pp", "cc"}, tree,
                                   {doc("pp", make(7200, std::nullopt, 1000)),
                                    doc("cc", make(10800, std::nullopt, 0))},
                                   kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "cc");
        // C without a document inherits P's through the same single branch.
        const auto inherit = cs::resolve({"pp", "cc"}, tree,
                                         {doc("pp", make(7200, std::nullopt, 1000))}, kNoKills);
        REQUIRE(inherit.has_value());
        CHECK(inherit->source_group_id == "pp");
    }
    SECTION("a chain with documents at several depths: the nearest document wins its branch") {
        const std::vector<cs::GroupNode> tree{node("d0", "", 1), node("d1", "d0", 2),
                                              node("d2", "d1", 3), node("d3", "d2", 4)};
        const auto r = cs::resolve({"d3"}, tree,
                                   {doc("d0", make(7200, std::nullopt, 1000)),
                                    doc("d1", make(10800, std::nullopt, 500)),
                                    doc("d2", make(14400, std::nullopt, 1))},
                                   kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "d2");
        CHECK(r->effective.interval_s == 14400);
        // A membership at every depth collapses to the deepest one.
        const auto all = cs::resolve({"d0", "d1", "d3", "d2"}, tree,
                                     {doc("d0", make(7200, std::nullopt, 1000)),
                                      doc("d1", make(10800, std::nullopt, 500)),
                                      doc("d2", make(14400, std::nullopt, 1))},
                                     kNoKills);
        REQUIRE(all.has_value());
        CHECK(all->source_group_id == "d2");
    }
    SECTION("two branches reaching one ancestor's document compete once") {
        const std::vector<cs::GroupNode> tree{node("xx", "", 1), node("g1", "xx", 2),
                                              node("g2", "xx", 3), node("t2", "", 4)};
        const auto r = cs::resolve({"g1", "g2", "t2"}, tree,
                                   {doc("xx", make(7200, std::nullopt, 3)),
                                    doc("t2", make(10800, std::nullopt, 2))},
                                   kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "xx");
    }
    SECTION("no membership: the root document, else the built-in default") {
        const std::vector<cs::GroupNode> tree{node(kRoot, "", 1), node("aa", "", 2)};
        const auto with_root =
            cs::resolve({}, tree, {doc(kRoot, make(7200)), doc("aa", make(10800))}, kNoKills);
        REQUIRE(with_root.has_value());
        CHECK(with_root->source_group_id == kRoot);
        const auto none = cs::resolve({}, tree, {doc("aa", make(10800))}, kNoKills);
        REQUIRE(none.has_value());
        CHECK(none->source_group_id.empty());
        CHECK(none->effective == cs::kFleetDefault.effective());
    }
    SECTION("memberships in a parent cycle both stand") {
        const std::vector<cs::GroupNode> tree{node("aa", "bb", 1), node("bb", "aa", 2)};
        const auto r = cs::resolve({"aa", "bb"}, tree,
                                   {doc("aa", make(7200, std::nullopt, 1)),
                                    doc("bb", make(10800, std::nullopt, 2))},
                                   kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "bb");
    }
}

TEST_CASE("collection settings resolve: tie-break chain", "[collection_settings][resolve]") {
    SECTION("equal priority: deeper wins") {
        const std::vector<cs::GroupNode> tree{node("t1", "", 1), node("t2", "", 1),
                                              node("d2", "t2", 1)};
        const auto r = cs::resolve({"t1", "d2"}, tree, {doc("t1", make(7200)), doc("d2", make(10800))},
                                   kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "d2");
    }
    SECTION("equal depth: older group wins") {
        const std::vector<cs::GroupNode> tree{node("t1", "", 5), node("t2", "", 3)};
        const auto r = cs::resolve({"t1", "t2"}, tree, {doc("t1", make(7200)), doc("t2", make(10800))},
                                   kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "t2");
    }
    SECTION("equal created_at: smaller id wins") {
        const std::vector<cs::GroupNode> tree{node("bb", "", 3), node("aa", "", 3)};
        const auto r = cs::resolve({"bb", "aa"}, tree, {doc("bb", make(7200)), doc("aa", make(10800))},
                                   kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id == "aa");
    }
}

TEST_CASE("collection settings resolve: kill switches always win", "[collection_settings][resolve]") {
    const std::vector<cs::GroupNode> tree{node("aa", "", 1)};
    SECTION("a killed plugin is off though the document says on") {
        const auto r = cs::resolve({"aa"}, tree, {doc("aa", make())}, {{"runtimes", true}});
        REQUIRE(r.has_value());
        CHECK_FALSE(r->effective.plugins.at("runtimes"));
        CHECK(r->effective.plugins.at("middleware"));
        CHECK(r->effective.plugins.at("installed_apps"));
    }
    SECTION("the kill switch beats forced-on registered apps") {
        const auto r = cs::resolve({"aa"}, tree, {doc("aa", make())}, {{"installed_apps", true}});
        REQUIRE(r.has_value());
        CHECK_FALSE(r->effective.plugins.at("installed_apps"));
    }
    SECTION("a kill entry that is false changes nothing") {
        const auto r = cs::resolve({"aa"}, tree, {doc("aa", make())}, {{"runtimes", false}});
        REQUIRE(r.has_value());
        CHECK(r->effective.plugins.at("runtimes"));
    }
}

TEST_CASE("collection settings resolve: registered apps forced on", "[collection_settings][resolve]") {
    auto bad = make();
    bad.plugins["installed_apps"] = false; // a row the validator would have refused
    const auto r = cs::resolve({"aa"}, {node("aa", "", 1)}, {doc("aa", bad)}, kNoKills);
    REQUIRE(r.has_value());
    CHECK(r->effective.plugins.at("installed_apps"));
}

TEST_CASE("collection settings resolve: unknown membership and cycles",
          "[collection_settings][resolve]") {
    SECTION("a membership id not in the tree is ignored") {
        const auto r = cs::resolve({"ghost"}, {node("aa", "", 1)}, {doc("aa", make(7200))}, kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id.empty());
    }
    SECTION("an orphan document (group not in the tree) is ignored") {
        const auto r = cs::resolve({"aa"}, {node("aa", "", 1)}, {doc("ghost", make(7200))}, kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id.empty());
    }
    SECTION("a parent cycle terminates") {
        const std::vector<cs::GroupNode> tree{node("aa", "bb", 1), node("bb", "aa", 2)};
        const auto r = cs::resolve({"aa"}, tree, {}, kNoKills);
        REQUIRE(r.has_value());
        CHECK(r->source_group_id.empty());
        const auto r2 = cs::resolve({"aa"}, tree, {doc("bb", make(7200))}, kNoKills);
        REQUIRE(r2.has_value());
        CHECK(r2->source_group_id == "bb");
    }
}

TEST_CASE("collection settings version: golden vectors", "[collection_settings][resolve]") {
    SECTION("canonical text of the fleet default") {
        CHECK(cs::canonical_text(cs::kFleetDefault, true) ==
              "v1\ninterval=86400\nwindow=60-300\ntz=\nplugin.installed_apps=1\n"
              "plugin.middleware=1\nplugin.msi_packages=1\nplugin.pkg_inventory=1\n"
              "plugin.runtimes=1\nplugin.windows_optional_features=1\npriority=0\n");
        CHECK(cs::canonical_text(cs::kFleetDefault.effective()) ==
              "v1\ninterval=86400\nwindow=60-300\ntz=\nplugin.installed_apps=1\n"
              "plugin.middleware=1\nplugin.msi_packages=1\nplugin.pkg_inventory=1\n"
              "plugin.runtimes=1\nplugin.windows_optional_features=1\n");
        CHECK(*cs::document_version(cs::kFleetDefault) ==
              "2d1db1cb07eadbd2cd54767386b4f4b43f7644330069874ba80823e32fdce05f");
        CHECK(*cs::effective_version(cs::kFleetDefault.effective()) ==
              "e27b0298c4ad0aabc3963e6dfa2ca5a3d60b687fa15315557385a020816d1696");
    }
    SECTION("a windowless seven-day document") {
        auto s = make(604800, std::nullopt, 5);
        s.plugins["runtimes"] = false;
        CHECK(cs::canonical_text(s, true).find("window=none\n") != std::string::npos);
        CHECK(*cs::document_version(s) ==
              "29d5fe0cdc505d02225fce6d7a6da07bd4abe43cbd28a57104e547fc7604f293");
        CHECK(*cs::effective_version(s.effective()) ==
              "c17eee6c694f0ab12b0213357bf6f7b0321e61daef6dd0d0912186c3f89cf739");
    }
    SECTION("a document with a zone") {
        auto s = make(172800, cs::Window{120, 180}, 10);
        s.timezone = "Europe/London";
        CHECK(*cs::document_version(s) ==
              "f812e51ad2d0198cdf1fa0b3a3b4abb71a382df5ee79f094c7879001fe04f7bf");
        CHECK(*cs::effective_version(s.effective()) ==
              "d4d101cd0ef844777e42f4f68597413c0492372b65b52dd2ac6bbeed581cf106");
    }
}

TEST_CASE("collection settings version: priority is in the document hash only",
          "[collection_settings][resolve]") {
    auto a = make(604800, std::nullopt, 5);
    a.plugins["runtimes"] = false;
    auto b = a;
    b.priority = 9;
    CHECK(*cs::document_version(a) != *cs::document_version(b));
    CHECK(*cs::effective_version(a.effective()) == *cs::effective_version(b.effective()));
    CHECK(*cs::document_version(b) ==
          "dfcbff52d183e4636009dbd47fa60c5f21777c763760a8afe3aeac6732a976de");
}

TEST_CASE("collection settings canonical text: the audit form differs only by separator",
          "[collection_settings][resolve]") {
    const auto hash_form = cs::canonical_text(cs::kFleetDefault, true);
    auto audit_form = cs::canonical_text(cs::kFleetDefault, true, ';');
    CHECK(audit_form.find('\n') == std::string::npos);
    std::replace(audit_form.begin(), audit_form.end(), ';', '\n');
    CHECK(audit_form == hash_form);
}
