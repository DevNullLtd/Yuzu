/**
 * test_enablement_state_core.cpp — truth tables of the pure half of the durable
 * enablement store (enablement_state_core.hpp, sha256_hex.hpp, ADR-3006):
 * wire spellings, hashes, boundary caps, the continuity anchor and the loader.
 *
 * Pure: no database, no file, no clock, no process.
 */

#include "agent_registry.hpp" // detail::scope_kind_catalog (the durable attribute kinds)
#include "capability_decls/all_fragments.hpp"
#include "enablement_state_core.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::enablement;

namespace {

const UnitOverlay& real_overlay() {
    static const UnitOverlay ov = [] {
        auto r = build_unit_overlay({YUZU_ALL_CAPABILITY_FRAGMENTS}, kProtectivePredicate);
        REQUIRE(r.has_value());
        return std::move(*r);
    }();
    return ov;
}

const std::vector<std::string_view>& kinds() {
    static const auto k = durable_attribute_kinds(yuzu::server::detail::scope_kind_catalog());
    return k;
}

RuleRow stored(std::string id, std::vector<std::string> units, std::string selector,
               std::string prov = "operator") {
    RuleRow r;
    r.id = std::move(id);
    r.units = std::move(units);
    r.selector = std::move(selector);
    r.provenance = std::move(prov);
    return r;
}

const std::string kStoreId = "123e4567-e89b-12d3-a456-426614174000";

} // namespace

TEST_CASE("enablement state: provenance wire spellings are frozen and exact", "[enablement][scope]") {
    CHECK(to_wire(Provenance::Operator) == "operator");
    CHECK(to_wire(Provenance::CarriedOver) == "carried_over");
    CHECK(to_wire(Provenance::System) == "system");
    for (const auto p : {Provenance::Operator, Provenance::CarriedOver, Provenance::System}) {
        const auto back = parse_provenance(to_wire(p));
        REQUIRE(back.has_value());
        CHECK(*back == p);
    }
    for (const char* bad : {"Operator", "OPERATOR", "carried-over", "carriedover", "", " operator",
                            "system ", "carried_over\n"}) {
        INFO(bad);
        CHECK_FALSE(parse_provenance(bad).has_value());
    }
}

TEST_CASE("enablement state: sha256_hex matches the standard vector", "[enablement][scope]") {
    CHECK(sha256_hex("abc") ==
          std::optional<std::string>{
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"});
}

TEST_CASE("enablement state: desired_hash is stable, sensitive, and distinguishes never-resolved",
          "[enablement][scope]") {
    const std::vector<std::string> a{"p.x", "p.y"};
    const std::vector<std::string> b{"p.x", "p.z"};
    const std::vector<std::string> empty;
    const auto ha = desired_hash(a);
    REQUIRE(ha.has_value());
    CHECK(desired_hash(a) == ha);
    CHECK(desired_hash(b) != ha);
    CHECK(desired_hash(std::vector<std::string>{"p.x"}) != ha);
    // A resolved-empty row has a real hash; a never-resolved row carries '' - they differ.
    CHECK(desired_hash(empty) == std::optional<std::string>{std::string(kEmptySetHash)});
    CHECK(std::string(kEmptySetHash) != "");
    // Joined by '\n': ["a.b","c"] and ["a","b.c"] cannot collide.
    CHECK(desired_hash(std::vector<std::string>{"a.b", "c"}) !=
          desired_hash(std::vector<std::string>{"a", "b.c"}));
    // The failure seam: a failing digest is nullopt, never a hash.
    CHECK_FALSE(desired_hash(a, [](std::string_view) { return std::optional<std::string>{}; })
                    .has_value());
}

TEST_CASE("enablement state: overlay_hash covers units AND requirement edges", "[enablement][scope]") {
    const UnitOverlay& base = real_overlay();
    REQUIRE_FALSE(base.requirements.empty());
    const auto h = overlay_hash(base);
    REQUIRE(h.has_value());
    CHECK(overlay_hash(base) == h);

    // An edge added, removed or retargeted changes the hash (resolve() closes over edges).
    UnitOverlay added = base;
    added.requirements.emplace_back("wol.wake", "wol.check");
    CHECK(overlay_hash(added) != h);
    UnitOverlay removed = base;
    removed.requirements.pop_back();
    CHECK(overlay_hash(removed) != h);
    UnitOverlay retargeted = base;
    retargeted.requirements.front().second = "wmi.query";
    CHECK(overlay_hash(retargeted) != h);

    // A unit's OS bits are part of the hash too.
    UnitOverlay os_changed = base;
    os_changed.units.front().os = static_cast<std::uint8_t>(os_changed.units.front().os ^ kMac);
    CHECK(overlay_hash(os_changed) != h);

    // Identical units and edges in a different order hash identically.
    UnitOverlay reordered = base;
    std::reverse(reordered.units.begin(), reordered.units.end());
    std::reverse(reordered.requirements.begin(), reordered.requirements.end());
    CHECK(overlay_hash(reordered) == h);

    CHECK_FALSE(overlay_hash(base, [](std::string_view) { return std::optional<std::string>{}; })
                    .has_value());
}

TEST_CASE("enablement state: check_identity bounds every registration field", "[enablement][scope]") {
    CHECK(check_identity("host", "linux", "x86_64", "1.2.3"));
    CHECK(check_identity("", "", "", ""));
    CHECK(check_identity(std::string(256, 'h'), std::string(32, 'o'), std::string(32, 'a'),
                         std::string(64, 'v')));
    CHECK_FALSE(check_identity(std::string(257, 'h'), "linux", "x", "1"));
    CHECK_FALSE(check_identity("h", std::string(33, 'o'), "x", "1"));
    CHECK_FALSE(check_identity("h", "linux", std::string(33, 'a'), "1"));
    CHECK_FALSE(check_identity("h", "linux", "x", std::string(65, 'v')));
    for (const char* bad : {"a\nb", "a\x7f", "a\x01", "a\r"}) {
        INFO(bad);
        CHECK_FALSE(check_identity(bad, "linux", "x", "1"));
        CHECK_FALSE(check_identity("h", bad, "x", "1"));
        CHECK_FALSE(check_identity("h", "linux", bad, "1"));
        CHECK_FALSE(check_identity("h", "linux", "x", bad));
    }
    // An OS outside the closed vocabulary is stored (the job reports it), not refused.
    CHECK(check_identity("h", "solaris", "x", "1"));
    CHECK(check_boot_id("srv-0123456789abcdef"));
    CHECK_FALSE(check_boot_id(""));
    CHECK_FALSE(check_boot_id(std::string(65, 'b')));
    CHECK_FALSE(check_boot_id("a\nb"));
}

TEST_CASE("enablement state: check_report accepts only well-formed report fields",
          "[enablement][scope]") {
    const std::string h64(64, 'a');
    CHECK(check_report(0, 0, ""));
    CHECK(check_report(1, 7, h64));
    CHECK(check_report(1, 7, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    CHECK_FALSE(check_report(-1, 0, ""));
    CHECK_FALSE(check_report(0, -1, ""));
    CHECK_FALSE(check_report(1, 1, std::string(63, 'a')));
    CHECK_FALSE(check_report(1, 1, std::string(65, 'a')));
    CHECK_FALSE(check_report(1, 1, std::string(64, 'A')));
    CHECK_FALSE(check_report(1, 1, std::string(63, 'a') + "g"));
}

TEST_CASE("enablement state: classify_continuity is the binding anchor rule", "[enablement][scope]") {
    const Anchor store{kStoreId, 2, 10};
    CHECK(classify_continuity(Anchor{kStoreId, 2, 10}, store).kind == Continuity::Ok);
    CHECK(classify_continuity(Anchor{kStoreId, 2, 4}, store).kind == Continuity::Ok); // crash-lag
    CHECK(classify_continuity(Anchor{kStoreId, 1, 999}, store).kind == Continuity::Ok); // older epoch

    const auto behind = classify_continuity(Anchor{kStoreId, 2, 11}, store);
    CHECK(behind.kind == Continuity::Regressed);
    CHECK(behind.reason == "store_behind");
    CHECK(classify_continuity(Anchor{kStoreId, 3, 0}, store).kind == Continuity::Regressed);

    const auto other = classify_continuity(Anchor{"00000000-0000-0000-0000-000000000000", 1, 0}, store);
    CHECK(other.kind == Continuity::Regressed);
    CHECK(other.reason == "store_id_mismatch");

    // A MISSING file is unwitnessed, never regressed - whatever the store's counter.
    for (const Anchor& s : {Anchor{kStoreId, 1, 0}, store}) {
        const auto missing = classify_continuity(std::nullopt, s);
        CHECK(missing.kind == Continuity::Unwitnessed);
        CHECK(missing.reason == "anchor_missing");
    }
}

TEST_CASE("enablement state: the anchor file grammar", "[enablement][scope]") {
    const Anchor a{kStoreId, 3, 41};
    const std::string text = render_anchor(a);
    CHECK(text == kStoreId + "\n3\n41\n");
    CHECK(parse_anchor(text) == std::optional<Anchor>{a});
    CHECK(parse_anchor(kStoreId + "\n3\n41") == std::optional<Anchor>{a}); // final newline optional

    CHECK_FALSE(parse_anchor(kStoreId + "\n3\n")); // two lines
    CHECK_FALSE(parse_anchor(kStoreId + "\n3"));
    CHECK_FALSE(parse_anchor(""));
    CHECK_FALSE(parse_anchor(kStoreId + "\n3\nx\n"));      // non-numeric counter
    CHECK_FALSE(parse_anchor(kStoreId + "\n-3\n41\n"));    // sign
    CHECK_FALSE(parse_anchor(kStoreId + "\n3\n41\nextra\n")); // trailing garbage
    CHECK_FALSE(parse_anchor(kStoreId + "\n3\n41\n\n"));
    CHECK_FALSE(parse_anchor("not-a-uuid\n3\n41\n"));
    CHECK_FALSE(parse_anchor(kStoreId + "\n3\n9999999999999999999\n")); // would overflow
    // Untrusted bytes are bounded: 513 bytes is unparseable even if it starts well.
    std::string big = text;
    big.append(kMaxAnchorBytes + 1 - big.size(), '0');
    REQUIRE(big.size() == 513);
    CHECK_FALSE(parse_anchor(big));
}

TEST_CASE("enablement state: check_rule_caps", "[enablement][scope]") {
    const std::vector<std::string> one{"p.x"};
    CHECK(check_rule_caps("r1", one, "__all__", ""));
    CHECK(check_rule_caps(std::string(64, 'r'), std::vector<std::string>(64, "p.x"),
                          std::string(4096, 's'), std::string(128, 'a')));
    CHECK_FALSE(check_rule_caps(std::string(65, 'r'), one, "__all__", ""));
    CHECK_FALSE(check_rule_caps("R1", one, "__all__", ""));
    CHECK_FALSE(check_rule_caps("r1", std::vector<std::string>(65, "p.x"), "__all__", ""));
    CHECK_FALSE(check_rule_caps("r1", one, std::string(4097, 's'), ""));
    CHECK_FALSE(check_rule_caps("r1", one, "__all__", std::string(129, 'a')));
}

TEST_CASE("enablement state: load_rule_row keeps stale unit names and never splits known/vanished",
          "[enablement][scope]") {
    // gone.x is a unit no release knows; wol.wake is real.
    auto mixed = load_rule_row(stored("m1", {"gone.x", "wol.wake"}, "__all__"), kinds());
    REQUIRE(mixed.has_value());
    CHECK(mixed->units == std::vector<std::string>{"gone.x", "wol.wake"});

    // resolve() keeps the surviving unit off and reports the stale name.
    std::vector<Rule> rules;
    rules.push_back(std::move(*mixed));
    const auto res = resolve(rules, real_overlay(), "windows",
                             [](std::string_view) { return std::string{}; });
    REQUIRE(res.has_value());
    bool wol_off = false;
    for (const auto& o : res->off)
        wol_off = wol_off || o.unit == "wol.wake";
    CHECK(wol_off);
    CHECK(res->unresolved_units == std::vector<std::string>{"gone.x"});

    // A rule naming only a vanished unit loads (it is NOT quarantined).
    CHECK(load_rule_row(stored("g1", {"gone.x"}, "__all__"), kinds()).has_value());

    // Refused: no-shape unit names, a bad selector, an unknown attribute kind, an ostype
    // outside the closed set.
    for (const char* bad_unit : {"", "A.b", "a.b.c", "a/b"}) {
        INFO(bad_unit);
        const auto r = load_rule_row(stored("b1", {bad_unit}, "__all__"), kinds());
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == QuarantineLabel::Refused);
    }
    for (const char* bad_sel : {"", "ostype ==", R"(nosuchattr == "x")", R"(ostype == "plan9")",
                                R"(from_result_set:rs_1 == "x")"}) {
        INFO(bad_sel);
        const auto r = load_rule_row(stored("b2", {"wol.wake"}, bad_sel), kinds());
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == QuarantineLabel::Refused);
    }
    CHECK(load_rule_row(stored("b3", {}, "__all__"), kinds()).error() == QuarantineLabel::Refused);

    // A bad provenance text is its own label; an over-cap row is `caps`.
    CHECK(load_rule_row(stored("b4", {"wol.wake"}, "__all__", "admin"), kinds()).error() ==
          QuarantineLabel::Provenance);
    CHECK(load_rule_row(stored(std::string(65, 'r'), {"wol.wake"}, "__all__"), kinds()).error() ==
          QuarantineLabel::Caps);
    CHECK(load_rule_row(stored("r\nx", {"wol.wake"}, "__all__"), kinds()).error() ==
          QuarantineLabel::Caps);
    CHECK(load_rule_row(stored("b5", std::vector<std::string>(65, "wol.wake"), "__all__"), kinds())
              .error() == QuarantineLabel::Caps);

    // The label set is exactly {refused, provenance, caps}.
    CHECK(to_label(QuarantineLabel::Refused) == "refused");
    CHECK(to_label(QuarantineLabel::Provenance) == "provenance");
    CHECK(to_label(QuarantineLabel::Caps) == "caps");
}

TEST_CASE("enablement state: unresolved_units uses resolve()'s predicate, independent of any endpoint",
          "[enablement][scope]") {
    std::vector<Rule> rules;
    rules.push_back(*load_rule_row(stored("a", {"gone.z", "wol.wake"}, R"(ostype == "linux")"), kinds()));
    rules.push_back(*load_rule_row(stored("b", {"gone.a", "gone.z"}, "__all__"), kinds()));
    // quarantine.whitelist is a recorded non-unit (protective): known, so not unresolved.
    rules.push_back(*load_rule_row(stored("c", {"quarantine.whitelist"}, "__all__"), kinds()));
    CHECK(unresolved_units(rules, real_overlay()) == std::vector<std::string>{"gone.a", "gone.z"});
    CHECK(unresolved_units({}, real_overlay()).empty());
}
