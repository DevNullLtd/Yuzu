/**
 * test_policy_dispatch_seam.cpp: the refusal seam policy evaluation applies before it
 * dispatches a pair (policy_dispatch.hpp).
 *
 * No store and no Postgres: the seam is pure. Two registries are used:
 *   - the FULL production registry (`YUZU_ALL_CAPABILITY_FRAGMENTS`) for the real pairs and
 *     the sweep, so a row added by another change is covered without editing this file;
 *   - the fixture registry (test_policy_capability_fixture.hpp) for the behaviours no
 *     production row has (reserved and gated, an unspecified gate, ambiguity).
 */

#include "capability_fragments.hpp"
#include "command_capability.hpp"
#include "instruction_definition_model.hpp"
#include "policy_dispatch.hpp"
#include "test_policy_capability_fixture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <initializer_list>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

using namespace yuzu::server;
using yuzu::server::test::policy_fixture_registry;
using Reason = PolicyDispatchDenialReason;

namespace {

const CommandCapabilityRegistry& full_registry() {
    static const CommandCapabilityRegistry registry{YUZU_ALL_CAPABILITY_FRAGMENTS};
    return registry;
}

// The reason the seam gave, or nullopt when it allowed the pair.
std::optional<Reason> refusal(const CommandCapabilityRegistry& reg, std::string_view plugin,
                              std::string_view action) {
    auto r = authorize_policy_dispatch(reg, plugin, action);
    if (r)
        return std::nullopt;
    return r.error().reason;
}

} // namespace

static_assert(noexcept(authorize_policy_dispatch(std::declval<const CommandCapabilityRegistry&>(),
                                                 std::string_view{}, std::string_view{})),
              "the seam is noexcept: it runs on the dispatch path and allocates nothing");

TEST_CASE("policy dispatch seam: each denial reason has its own lowercase token",
          "[policy][dispatch_seam]") {
    CHECK(to_string(Reason::Unclassified) == "unclassified");
    CHECK(to_string(Reason::Ambiguous) == "ambiguous");
    CHECK(to_string(Reason::Gated) == "gated");
    CHECK(to_string(Reason::Destructive) == "destructive");
    CHECK(to_string(Reason::Reserved) == "reserved");
    CHECK(to_string(Reason::Unwired) == "unwired");
    CHECK(to_string(Reason::DispatchIdentifierInvalid) == "dispatch_identifier_invalid");
}

TEST_CASE("policy dispatch seam: the identifier rule is the one instruction authoring applies",
          "[policy][dispatch_seam]") {
    CHECK(kMaxPolicyDispatchIdentifierLen == kMaxDefinitionDispatchIdentifierLen);

    // Every single byte value, as a one-character identifier.
    for (int b = 0; b < 256; ++b) {
        const std::string one(1, static_cast<char>(b));
        INFO("byte " << b);
        CHECK(dispatch_identifier_part_ok(one) == !check_dispatch_identifier("plugin", one));
    }
    // Length limits and a few mixed strings.
    for (const std::size_t n : {std::size_t{0}, std::size_t{1}, std::size_t{127}, std::size_t{128},
                                std::size_t{129}, std::size_t{4096}}) {
        const std::string s(n, 'a');
        INFO("length " << n);
        CHECK(dispatch_identifier_part_ok(s) == !check_dispatch_identifier("plugin", s));
    }
    for (const std::string_view s : {"a.b-c_D9", "a b", "a/b", "a:b", "ab\n", "caf\xC3\xA9", "-", ".", "_",
                                     "0"}) {
        INFO("value " << s);
        CHECK(dispatch_identifier_part_ok(s) == !check_dispatch_identifier("action", s));
    }
}

TEST_CASE("policy dispatch seam: an empty part is not an identifier failure",
          "[policy][dispatch_seam]") {
    CHECK(dispatch_pair_well_formed("", ""));
    CHECK(dispatch_pair_well_formed("echo", ""));
    CHECK(dispatch_pair_well_formed("", "status"));
    CHECK(dispatch_pair_well_formed("echo", "status"));
    CHECK_FALSE(dispatch_pair_well_formed("ec ho", "status"));
    CHECK_FALSE(dispatch_pair_well_formed("echo", "sta/tus"));
    CHECK_FALSE(dispatch_pair_well_formed(std::string(129, 'a'), "run"));
    CHECK_FALSE(dispatch_pair_well_formed("echo", std::string(129, 'a')));
    CHECK(dispatch_pair_well_formed(std::string(128, 'a'), std::string(128, 'b')));
}

TEST_CASE("policy dispatch seam: real pairs are refused for the right reason",
          "[policy][dispatch_seam]") {
    const auto& reg = full_registry();

    // Gated, and also Destructive: the gate is reported first.
    const auto row = reg.classify("content_dist", "execute_staged");
    REQUIRE(row.has_value());
    REQUIRE(row->execute_gate != ExecuteGate::None);
    REQUIRE(row->dispatch_class == DispatchClass::Destructive);
    CHECK(refusal(reg, "content_dist", "execute_staged") == Reason::Gated);

    // Destructive with no gate.
    const auto purge = reg.classify("echo", "purge_source");
    REQUIRE(purge.has_value());
    REQUIRE(purge->execute_gate == ExecuteGate::None);
    CHECK(refusal(reg, "echo", "purge_source") == Reason::Destructive);

    // Reserved rows are refused although none has a gate (ruling A), Mutating ones included.
    CHECK(refusal(reg, "__guard__", "push_rules") == Reason::Reserved);
    CHECK(refusal(reg, "asset_tags", "sync") == Reason::Reserved);
    CHECK(refusal(reg, "echo", "fleet_snapshot") == Reason::Reserved);

    // A read-only pair with no gate is allowed.
    CHECK_FALSE(refusal(reg, "echo", "status").has_value());
    // Mutating with no gate and not reserved is allowed (the design's D1b).
    CHECK_FALSE(refusal(reg, "tags", "set").has_value());

    // Case-insensitive on both halves, as `classify` is.
    CHECK(refusal(reg, "CONTENT_DIST", "Execute_Staged") == Reason::Gated);
    CHECK_FALSE(refusal(reg, "Echo", "STATUS").has_value());

    // Not a row at all.
    CHECK(refusal(reg, "no_such_plugin", "run") == Reason::Unclassified);
    CHECK(refusal(reg, "echo", "no_such_action") == Reason::Unclassified);
}

TEST_CASE("policy dispatch seam: precedence between reasons", "[policy][dispatch_seam]") {
    const auto& reg = policy_fixture_registry();

    CHECK(refusal(reg, "gatedp", "run") == Reason::Gated);
    CHECK(refusal(reg, "destrp", "run") == Reason::Destructive);
    CHECK(refusal(reg, "resvp", "run") == Reason::Reserved);
    // Reserved and gated: reserved first.
    CHECK(refusal(reg, "resgatedp", "run") == Reason::Reserved);
    // An unspecified gate is a classification failure, as at the interactive chokepoint.
    CHECK(refusal(reg, "unspecp", "run") == Reason::Unclassified);
    // Two rows for one pair.
    CHECK(refusal(reg, "dupp", "run") == Reason::Ambiguous);

    // The five rows the evaluator tests use.
    for (const std::string_view plugin :
         {std::string_view{"checkp"}, std::string_view{"verifyp"}, std::string_view{"checkp2"},
          std::string_view{"fixp"}, yuzu::server::test::kFixtureForensicsPlugin}) {
        INFO("fixture plugin " << plugin);
        CHECK_FALSE(refusal(reg, plugin, "run").has_value());
    }
}

TEST_CASE("policy dispatch seam: an identifier that is over-length or off the authoring charset "
          "is refused before classification",
          "[policy][dispatch_seam]") {
    const auto& reg = full_registry();

    CHECK(refusal(reg, std::string(129, 'a'), "run") == Reason::DispatchIdentifierInvalid);
    CHECK(refusal(reg, "echo", std::string(129, 'a')) == Reason::DispatchIdentifierInvalid);
    // 128 bytes is within the limit: it is well formed, then simply not a row.
    CHECK(refusal(reg, std::string(128, 'a'), "run") == Reason::Unclassified);
    CHECK(refusal(reg, "echo", std::string(128, 'a')) == Reason::Unclassified);

    // Off the charset, whatever the length.
    CHECK(refusal(reg, "bad plugin", "status") == Reason::DispatchIdentifierInvalid);
    CHECK(refusal(reg, "echo", "sta/tus") == Reason::DispatchIdentifierInvalid);
    CHECK(refusal(reg, "content_dist", std::string("execute_staged\n")) ==
          Reason::DispatchIdentifierInvalid);
    CHECK(refusal(reg, "content_dist", std::string("execute_staged\0", 15)) ==
          Reason::DispatchIdentifierInvalid);
    CHECK(refusal(reg, "caf\xC3\xA9", "status") == Reason::DispatchIdentifierInvalid);

    // The identifier check comes before classification: an invalid part never reports
    // gated or unclassified.
    CHECK(refusal(reg, "content_dist ", "execute_staged") == Reason::DispatchIdentifierInvalid);

    // An empty part is not an identifier failure: it falls to classification.
    CHECK(refusal(reg, "echo", "") == Reason::Unclassified);
    CHECK(refusal(reg, "", "status") == Reason::Unclassified);
    CHECK(refusal(reg, "", "") == Reason::Unclassified);
}

TEST_CASE("policy dispatch seam: a registry with no sources classifies nothing",
          "[policy][dispatch_seam]") {
    const CommandCapabilityRegistry empty(std::initializer_list<std::span<const CommandCapability>>{});
    CHECK(refusal(empty, "echo", "status") == Reason::Unclassified);
}

TEST_CASE("policy dispatch seam: sweep over every production capability row",
          "[policy][dispatch_seam][sweep]") {
    // A property, never a count: for every row the seam refuses exactly when the execute
    // gate is not None, or the class is Destructive, or the row is reserved; it allows every
    // other row. A row another change adds is covered without editing this test.
    const auto& reg = full_registry();
    std::size_t rows = 0;
    std::size_t refused = 0;
    std::size_t allowed = 0;
    std::set<std::string> ambiguous_pairs;

    reg.for_each_row([&](const CommandCapability& cap) {
        ++rows;
        INFO("row " << cap.plugin << "." << cap.action);

        // Every production row is a well-formed identifier, so none can be refused as
        // dispatch_identifier_invalid.
        CHECK(dispatch_pair_well_formed(cap.plugin, cap.action));

        const bool should_refuse = cap.execute_gate != ExecuteGate::None ||
                                   cap.dispatch_class == DispatchClass::Destructive ||
                                   cap.system_reserved;
        const auto result = authorize_policy_dispatch(reg, cap.plugin, cap.action);

        if (!result && result.error().reason == Reason::Ambiguous) {
            // The same pair declared twice: refused, and `classify` agrees it is ambiguous.
            ambiguous_pairs.insert(std::string(cap.plugin) + "." + std::string(cap.action));
            CHECK(reg.classify(cap.plugin, cap.action).error() == ClassificationError::Ambiguous);
            ++refused;
            return;
        }

        if (should_refuse) {
            CHECK_FALSE(result.has_value());
            ++refused;
        } else {
            CHECK(result.has_value());
            if (result) {
                CHECK(result->plugin == cap.plugin);
                CHECK(result->action == cap.action);
            }
            ++allowed;
        }
    });

    CHECK(rows > 0);
    CHECK(refused > 0);
    CHECK(allowed > 0);
    CHECK(rows == refused + allowed);
}
