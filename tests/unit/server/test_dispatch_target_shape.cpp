/**
 * test_dispatch_target_shape.cpp — the pure targeting rule shared by MCP
 * `execute_instruction` (#2492) and the two REST twins (#2500).
 *
 * THE RULE: an OMITTED targeting argument means "the whole fleet"; a SUPPLIED
 * one that resolves to nothing is an ERROR. Collapsing the two is the defect
 * both issues describe — `{"agent_ids":[1,2,3]}` from a client emitting numeric
 * device ids, and `{"agent_ids":[]}` from a device filter that matched nothing,
 * each became a fleet-wide dispatch that returned success.
 *
 * This file pins the rule at the level it is DECIDED, so a route that forgets
 * to call it fails its own route test rather than quietly disagreeing with the
 * other surfaces about what a target is. The reason labels are asserted, not
 * just the reject/accept verdict, because they are the closed metric label set
 * — `server.cpp` pre-seeds `yuzu_server_dispatch_target_rejected_total` by
 * iterating `kTargetingShapeReasons`, so a reason renamed here and not there is
 * emitted-but-unseeded and silently breaks `absent()` alerting.
 */

#include "dispatch_target_shape.hpp"
#include "on_behalf_guard.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <string>

using yuzu::server::check_targeting_shape;
using yuzu::server::kRouteRejectReasons;
using yuzu::server::kTargetingShapeReasons;
using yuzu::server::classify_dispatch_arm;
using yuzu::server::DispatchArm;
using yuzu::server::targeting_supplied;

namespace {

/// The violated reason for `body`, or "" when the shape is accepted.
std::string reason_for(const std::string& body) {
    auto bv = check_targeting_shape(nlohmann::json::parse(body));
    return bv ? std::string(bv->reason) : std::string{};
}

} // namespace

TEST_CASE("#2500 — every widening shape from the issue is refused, with its own reason",
          "[targeting][security][dispatch]") {
    // Row for row, the table in issue #2500. Each of these dispatched to the
    // entire fleet on at least one of the two REST routes before the fix.
    CHECK(reason_for(R"({"agent_ids":[1,2,3]})") == "agent_id_type");
    CHECK(reason_for(R"({"agent_ids":[]})") == "agent_ids_empty");
    CHECK(reason_for(R"({"agent_ids":"dev-01"})") == "agent_ids_type");
    CHECK(reason_for(R"({"agent_ids":null})") == "agent_ids_type");
    CHECK(reason_for(R"({"scope":5})") == "scope_type");
    CHECK(reason_for(R"({"scope":""})") == "scope_empty");

    // A mixed array — one good id, one number — is refused whole rather than
    // silently reduced to the ids that happened to parse. Dropping the bad
    // entry would dispatch to a NARROWER set than the caller asked for, which
    // is the same class of surprise pointing the other way.
    CHECK(reason_for(R"({"agent_ids":["agent-1",2]})") == "agent_id_type");
}

TEST_CASE("#2500 — a genuinely omitted target is accepted (the over-broadness guard)",
          "[targeting][dispatch]") {
    // The half of the rule that is not a refusal. A fix that rejected
    // everything would satisfy every assertion in the case above.
    CHECK(reason_for(R"({})").empty());
    CHECK(reason_for(R"({"plugin":"service","action":"restart"})").empty());
    CHECK(reason_for(R"({"agent_ids":["agent-1"]})").empty());
    CHECK(reason_for(R"({"scope":"tag:prod"})").empty());
    // (agent_ids + a REAL scope is now `target_conflict` - see the dedicated
    // case below. `__all__` is the one legal pairing.)
    CHECK(reason_for(R"({"agent_ids":["a","b"],"scope":"__all__"})").empty());

    // `params` and unrelated keys are none of this function's business — it
    // decides targeting only. The size bounds live with the surface that
    // publishes them (mcp_input_bounds.hpp), deliberately not here.
    CHECK(reason_for(R"({"params":{"k":"v"},"agent_ids":["a"]})").empty());
}

TEST_CASE("#2500 — targeting_supplied distinguishes omitted from resolved-to-nothing",
          "[targeting][dispatch]") {
    // This is the fact a SINK cannot recover on its own: by the time targeting
    // has been extracted into a vector and a string, "" and {} mean both
    // "omitted" and "supplied and thrown away". That erasure is why the guard
    // has to see the parsed body.
    CHECK_FALSE(targeting_supplied(nlohmann::json::parse(R"({})")));
    CHECK_FALSE(targeting_supplied(nlohmann::json::parse(R"({"plugin":"p","action":"a"})")));
    CHECK(targeting_supplied(nlohmann::json::parse(R"({"agent_ids":[]})")));
    CHECK(targeting_supplied(nlohmann::json::parse(R"({"scope":""})")));
    CHECK(targeting_supplied(nlohmann::json::parse(R"({"agent_ids":["a"]})")));
}

TEST_CASE("#2500 — agent_ids is decided before scope, so a denial is reproducible",
          "[targeting][dispatch]") {
    // The function documents a deterministic first-violation order. A body
    // violating both must always name the same one, or the same request logs a
    // different reason label on different builds and the metric becomes noise.
    CHECK(reason_for(R"({"agent_ids":[],"scope":""})") == "agent_ids_empty");
    CHECK(reason_for(R"({"agent_ids":"x","scope":5})") == "agent_ids_type");
}

TEST_CASE("#2500 — agent_ids and a real scope together are refused as ambiguous",
          "[targeting][dispatch][security]") {
    // The two selectors used to resolve by PRECEDENCE - scope won and the
    // explicit id list was discarded - so a caller naming one device ran on
    // every device the scope matched. The executed set was not the requested
    // set, which is the same invariant as the rest of this issue, reached by
    // disagreement between selectors rather than by an erased one.
    CHECK(reason_for(R"({"agent_ids":["dev-a"],"scope":"tag:prod"})") == "target_conflict");
    CHECK(reason_for(R"({"agent_ids":["dev-a"],"scope":"group:servers"})") == "target_conflict");

    // `__all__` is NOT a narrowing selector - it is the broadcast request, and
    // classify_dispatch_arm already resolves ids-beat-broadcast in the safe
    // direction. Refusing this pair would break the dashboard's own dialog.
    CHECK(reason_for(R"({"agent_ids":["dev-a"],"scope":"__all__"})").empty());

    // Either one alone is still fine.
    CHECK(reason_for(R"({"agent_ids":["dev-a"]})").empty());
    CHECK(reason_for(R"({"scope":"tag:prod"})").empty());
}

TEST_CASE("#2500 — every emitted reason is a member of the closed label set",
          "[targeting][dispatch][metrics]") {
    // The boot pre-seed iterates kTargetingShapeReasons. A reason emitted from
    // this function but absent from that array creates its series on first use,
    // which passes the emitting test while the dashboard reads zero until the
    // first refusal — exactly the absent()-alerting break the single-array
    // discipline exists to prevent.
    const std::string bodies[] = {
        R"({"agent_ids":[1]})",  R"({"agent_ids":[]})",   R"({"agent_ids":"x"})",
        R"({"scope":5})",        R"({"scope":""})",
    };
    for (const auto& b : bodies) {
        const auto r = reason_for(b);
        REQUIRE_FALSE(r.empty());
        CHECK(std::find(kTargetingShapeReasons.begin(), kTargetingShapeReasons.end(), r) !=
              kTargetingShapeReasons.end());
    }
    // And the set is exactly the five this function can produce — a sixth added
    // to the array without an emit site would leave a permanently-zero series
    // that reads as "this can never happen".
    CHECK(kTargetingShapeReasons.size() == 6); // +target_conflict (#2500)
}

// ── classify_dispatch_arm — the branch selection with fleet-wide blast radius ──
//
// Extracted from the dispatch closures during governance for one reason: it was
// the highest-consequence decision in the change and nothing tested it. The
// closures live inside `Server::start()`, unreachable by any harness (#2557 —
// NOT #1786, which is the TAR dashboard fragments, closed by #2534),
// and the route tests assert against STUB dispatch closures — so reverting the
// real sink's default would have broken no test at all.

TEST_CASE("#2500 — an explicit agent_ids list wins over a broadcast request",
          "[targeting][dispatch][security]") {
    // THE regression this exists for. The first version of the sink inversion
    // put Broadcast first in the chain, so {agent_ids:["a"], scope:"__all__"}
    // reached the ENTIRE FLEET on the shared closure while the MCP closure
    // reached exactly agent "a" — a widening introduced by the change that
    // exists to remove widenings, and a fourth dialect of a token that already
    // had three. A contradictory request resolves to the SPECIFIC reading.
    CHECK(classify_dispatch_arm(/*has_agent_ids=*/true, "__all__") == DispatchArm::Ids);
    CHECK(classify_dispatch_arm(/*has_agent_ids=*/false, "__all__") == DispatchArm::Broadcast);
}

TEST_CASE("#2500 — nothing named selects None, which reaches nobody",
          "[targeting][dispatch][security]") {
    // The inversion itself: empty ids + empty scope used to fall into
    // send_to_all on the shared closure. Eight of its ten callers were safe
    // only because eight authors each remembered to guard their own inputs.
    CHECK(classify_dispatch_arm(false, "") == DispatchArm::None);
}

TEST_CASE("#2500 — a real scope expression outranks both ids and broadcast",
          "[targeting][dispatch]") {
    // Pre-existing precedence, pinned so the #2500 reshuffle cannot have
    // changed it silently: a scope expression has always won over agent_ids on
    // these closures, and `group:` is dispatched by member lookup rather than
    // through the scope engine.
    // NOTE the `has_agent_ids=true` rows below describe the CLASSIFIER only.
    // A caller can no longer reach them: `check_targeting_shape` rejects
    // agent_ids + a real scope as `target_conflict` (#2500). They remain
    // meaningful for INTERNAL callers, which pass exactly one selector by
    // construction. An earlier revision pinned this precedence as if it were a
    // caller-facing contract, which is how preserving a behaviour becomes
    // endorsing it - an independent review caught that the pinned behaviour was
    // itself a widening: {"agent_ids":["dev-a"],"scope":"tag:prod"} ran on every
    // device matching tag:prod, not on dev-a.
    CHECK(classify_dispatch_arm(true, "tag:prod") == DispatchArm::Scope);
    CHECK(classify_dispatch_arm(false, "tag:prod") == DispatchArm::Scope);
    CHECK(classify_dispatch_arm(true, "group:servers") == DispatchArm::Group);
    CHECK(classify_dispatch_arm(false, "from_result_set:rs_1") == DispatchArm::Scope);

    // `__all__` is deliberately NOT a scope expression — it short-circuits
    // per-device evaluation and never reaches the parser, which is what
    // /discover/scope-kinds documents. Treating it as one is what made
    // /api/command answer 400 "invalid scope" on the exact string its sibling
    // route broadcast on. A `group:` prefix on the sentinel is still the
    // sentinel, not a group named "__all__".
    CHECK(classify_dispatch_arm(false, "__all__") == DispatchArm::Broadcast);
}

TEST_CASE("#2500 — ids-only and the empty-string scope are unchanged",
          "[targeting][dispatch]") {
    CHECK(classify_dispatch_arm(true, "") == DispatchArm::Ids);
}

TEST_CASE("#2500 — the route-level reason set matches what the routes actually emit",
          "[targeting][dispatch][metrics]") {
    // `kRouteRejectReasons` was flagged in review as an INERT tether: nothing
    // referenced it, and the boot pre-seed spells its literals out by hand
    // (deliberately — each applies to a different route subset, so one loop
    // would seed unreachable pairs). An array nothing checks is documentation
    // wearing a constant's clothes, and the seed comment claimed it was
    // iterated. This binds the two: a reason emitted by a route without a home
    // here, or a reason added here that no route emits, fails.
    //
    // Keep in step with the emit sites: `body_type` (command_routes.cpp
    // /api/command, workflow_routes.cpp execute), `parent_id_type`/`parent_id_empty`
    // (rest_api_v1.cpp run_async + from-inventory-query), `closure_no_target`
    // (server.cpp shared command_dispatch_fn), `destructive_untargeted`
    // (#3685: command_routes.cpp /api/command Destructive RefuseUntargeted arm AND
    // mcp_server.cpp execute_instruction's C8 pre-mint + main-handler sites —
    // the one reason in this array with more than one owning surface),
    // `destructive_no_visible_target` (#2557: command_routes.cpp's Destructive
    // gate, the confine-to-visible-agents 404 arm).
    const std::array<std::string_view, 7> emitted_by_routes{
        "body_type",          "parent_id_type",
        "parent_id_empty",    "closure_no_target",
        "scope_unsupported",  "destructive_untargeted",
        "destructive_no_visible_target"};

    CHECK(kRouteRejectReasons.size() == emitted_by_routes.size());
    for (const auto r : emitted_by_routes) {
        CHECK(std::find(kRouteRejectReasons.begin(), kRouteRejectReasons.end(), r) !=
              kRouteRejectReasons.end());
    }
    // And the two halves stay disjoint — a reason in both arrays would be
    // pre-seeded twice under different routes and read as two distinct causes.
    for (const auto r : kRouteRejectReasons) {
        CHECK(std::find(kTargetingShapeReasons.begin(), kTargetingShapeReasons.end(), r) ==
              kTargetingShapeReasons.end());
    }
}

TEST_CASE("#2500 — audit-detail truncation never severs a UTF-8 character",
          "[targeting][dispatch][security]") {
    // The round-3 fix routed caller-supplied `plugin`/`action` through
    // `sanitize_for_log` to stop audit-detail forgery — and in doing so
    // introduced a new way to corrupt the same field. The cap counts BYTES, so
    // a cut landing mid-character used to leave a lone lead byte in the audit
    // row. `/api/v1/audit` serialises detail through `json_escape`, which passes
    // bytes >= 0x20 through unvalidated, so ONE truncated device name made the
    // whole audit page undecodable to a strict UTF-8 client.
    //
    // Repro from the review: 127 ASCII bytes then 'é' (0xC3 0xA9) at a cap of
    // 128 — the 0xC3 fits, the 0xA9 does not.
    const std::string bad = std::string(127, 'a') + "\xC3\xA9";
    const auto cut = yuzu::server::onbehalf::sanitize_for_log(bad, 128);
    CHECK(cut.find('\xC3') == std::string::npos); // the lone lead byte is gone

    // A COMPLETE character that fits must survive — a fix that just lopped the
    // tail off would pass the assertion above and quietly mangle valid text.
    const std::string good = std::string(126, 'a') + "\xC3\xA9";
    const auto kept = yuzu::server::onbehalf::sanitize_for_log(good, 128);
    CHECK(kept.find("\xC3\xA9") != std::string::npos);

    // Every byte of the result is part of a well-formed sequence.
    const auto well_formed = [](const std::string& v) {
        for (size_t i = 0; i < v.size();) {
            const auto c = static_cast<unsigned char>(v[i]);
            size_t need = 1;
            if ((c & 0x80) == 0) need = 1;
            else if ((c & 0xE0) == 0xC0) need = 2;
            else if ((c & 0xF0) == 0xE0) need = 3;
            else if ((c & 0xF8) == 0xF0) need = 4;
            else return false; // stray continuation byte
            if (i + need > v.size()) return false;
            for (size_t k = 1; k < need; ++k)
                if ((static_cast<unsigned char>(v[i + k]) & 0xC0) != 0x80) return false;
            i += need;
        }
        return true;
    };
    CHECK(well_formed(cut));
    CHECK(well_formed(kept));

    // Control characters and CR/LF still become '?' — the forgery guard the
    // truncation fix must not regress.
    CHECK(yuzu::server::onbehalf::sanitize_for_log("a\nb\rc", 128) == "a?b?c");

    // 3-byte and 4-byte sequences cut at EVERY offset. The 2-byte case above
    // would pass even if the `need` arms for 0xE0/0xF0 were wrong, so these are
    // what actually pin the classification. Lifted from the property set of an
    // ASan/UBSan probe that ran 25.2M inputs against this function during
    // review; these are the cases a regression would slip through.
    for (int cut = 1; cut <= 2; ++cut) {
        const std::string euro = std::string(128 - cut, 'a') + "\xE2\x82\xAC";
        CHECK(well_formed(yuzu::server::onbehalf::sanitize_for_log(euro, 128)));
    }
    for (int cut = 1; cut <= 3; ++cut) {
        const std::string emoji = std::string(128 - cut, 'a') + "\xF0\x9F\x98\x80";
        CHECK(well_formed(yuzu::server::onbehalf::sanitize_for_log(emoji, 128)));
    }
    // A tail of pure continuation bytes exits the walk by loop condition rather
    // than by return — the one path that does not hit the erase branch.
    const std::string orphans = std::string(126, 'a') + "\x80\x80\x80\x80";
    const auto orphan_out = yuzu::server::onbehalf::sanitize_for_log(orphans, 128);
    CHECK(orphan_out.size() <= 128 + 3); // no growth, no hang

    // At most ONE character is ever removed: a fix that lopped the tail harder
    // would satisfy every well-formedness check above while eating valid text.
    const std::string full = std::string(124, 'a') + "\xF0\x9F\x98\x80";
    CHECK(yuzu::server::onbehalf::sanitize_for_log(full, 128).find("\xF0\x9F\x98\x80") !=
          std::string::npos);
}
