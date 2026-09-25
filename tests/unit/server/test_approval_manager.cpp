/**
 * test_approval_manager.cpp — Unit tests for ApprovalManager
 *
 * Covers: submit, query by status/submitted_by, pending_count, approve,
 *         reject, self-approval prevention, double-review prevention,
 *         approve nonexistent.
 */

#include <array>
#include "approval_manager.hpp"
#include "mcp_approval_error.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg_error_class.hpp"
#include "reserved_definition_id.hpp"
#include "test_approval_manager_pg_helper.hpp"
#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <chrono>
#include <expected>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: construction migrates and opens the store",
          "[pg][approval_manager][db]") {
    // The fixture's own constructor already REQUIREs is_open() — this test
    // exists so a construction failure surfaces here by name rather than as
    // an opaque fixture assertion inside the first unrelated test that
    // happens to run.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    REQUIRE(mgr_bundle->is_open());
}

// ── Submit ─────────────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: submit creates pending approval", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto result =
        mgr.submit("def-001", "operator1", "ostype = 'windows'", "", ApprovalOrigin::kInstruction);
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("ApprovalManager: submitted approval has pending status", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto result =
        mgr.submit("def-001", "operator1", "ostype = 'windows'", "", ApprovalOrigin::kInstruction);
    REQUIRE(result.has_value());

    // Verify via query
    ApprovalQuery q;
    q.status = "pending";
    auto pending = mgr.query(q);
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].id == *result);
    CHECK(pending[0].definition_id == "def-001");
    CHECK(pending[0].submitted_by == "operator1");
    CHECK(pending[0].status == "pending");
    CHECK(pending[0].scope_expression == "ostype = 'windows'");
    CHECK(pending[0].reviewed_by.empty());
}

TEST_CASE("ApprovalManager: submit multiple approvals", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    mgr.submit("def-001", "operator1", "scope-1", "", ApprovalOrigin::kInstruction);
    mgr.submit("def-002", "operator2", "scope-2", "", ApprovalOrigin::kInstruction);
    mgr.submit("def-003", "operator1", "scope-3", "", ApprovalOrigin::kInstruction);

    auto all = mgr.query();
    REQUIRE(all.size() == 3);
}

// ── Query by Status ────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: query by status — pending", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    mgr.submit("def-1", "operator1", "scope-1", "", ApprovalOrigin::kInstruction);
    mgr.submit("def-2", "operator1", "scope-2", "", ApprovalOrigin::kInstruction);
    auto r3 = mgr.submit("def-3", "operator1", "scope-3", "", ApprovalOrigin::kInstruction);
    REQUIRE(r3.has_value());
    mgr.approve(*r3, "admin1", "approved");

    ApprovalQuery q;
    q.status = "pending";
    auto pending = mgr.query(q);
    REQUIRE(pending.size() == 2);
}

TEST_CASE("ApprovalManager: query by status — approved", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto r1 = mgr.submit("def-1", "operator1", "scope-1", "", ApprovalOrigin::kInstruction);
    mgr.submit("def-2", "operator1", "scope-2", "", ApprovalOrigin::kInstruction);
    REQUIRE(r1.has_value());
    mgr.approve(*r1, "admin1", "looks good");

    ApprovalQuery q;
    q.status = "approved";
    auto approved = mgr.query(q);
    REQUIRE(approved.size() == 1);
    CHECK(approved[0].definition_id == "def-1");
}

TEST_CASE("ApprovalManager: query empty returns empty", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    ApprovalQuery q;
    q.status = "pending";
    auto results = mgr.query(q);
    CHECK(results.empty());
}

// ── Query by submitted_by ──────────────────────────────────────────────────

TEST_CASE("ApprovalManager: query by submitted_by", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    mgr.submit("def-1", "operator1", "scope-1", "", ApprovalOrigin::kInstruction);
    mgr.submit("def-2", "operator2", "scope-2", "", ApprovalOrigin::kInstruction);
    mgr.submit("def-3", "operator1", "scope-3", "", ApprovalOrigin::kInstruction);

    ApprovalQuery q;
    q.submitted_by = "operator1";
    auto results = mgr.query(q);
    REQUIRE(results.size() == 2);
}

// ── Pending Count ──────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: pending_count starts at zero", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    CHECK(mgr.pending_count() == 0);
}

TEST_CASE("ApprovalManager: pending_count increments and decrements", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    mgr.submit("def-1", "operator1", "scope-1", "", ApprovalOrigin::kInstruction);
    mgr.submit("def-2", "operator1", "scope-2", "", ApprovalOrigin::kInstruction);
    mgr.submit("def-3", "operator1", "scope-3", "", ApprovalOrigin::kInstruction);
    CHECK(mgr.pending_count() == 3);

    // Approve one
    ApprovalQuery q;
    q.status = "pending";
    auto pending = mgr.query(q);
    REQUIRE(!pending.empty());
    mgr.approve(pending[0].id, "admin1", "ok");
    CHECK(mgr.pending_count() == 2);
}

// ── Approve ────────────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: approve sets status, reviewer, timestamp", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kInstruction);
    REQUIRE(result.has_value());

    auto approve_result = mgr.approve(*result, "admin_user", "Approved for deployment");
    REQUIRE(approve_result.has_value());

    ApprovalQuery q;
    q.status = "approved";
    auto approved = mgr.query(q);
    REQUIRE(approved.size() == 1);
    CHECK(approved[0].status == "approved");
    CHECK(approved[0].reviewed_by == "admin_user");
    CHECK(approved[0].reviewed_at > 0);
    CHECK(approved[0].review_comment == "Approved for deployment");
}

TEST_CASE("ApprovalManager: approve with empty comment", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kInstruction);
    REQUIRE(result.has_value());

    auto approve_result = mgr.approve(*result, "admin_user", "");
    REQUIRE(approve_result.has_value());
}

// ── Reject ─────────────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: reject sets status, reviewer, comment", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kInstruction);
    REQUIRE(result.has_value());

    auto reject_result = mgr.reject(*result, "admin_user", "Too risky");
    REQUIRE(reject_result.has_value());

    ApprovalQuery q;
    q.status = "rejected";
    auto rejected = mgr.query(q);
    REQUIRE(rejected.size() == 1);
    CHECK(rejected[0].status == "rejected");
    CHECK(rejected[0].reviewed_by == "admin_user");
    CHECK(rejected[0].review_comment == "Too risky");
    CHECK(rejected[0].reviewed_at > 0);
}

// ── Self-Approval Prevention ───────────────────────────────────────────────

TEST_CASE("ApprovalManager: self-approval prevented", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto result = mgr.submit("def-1", "operator1", "scope", "", ApprovalOrigin::kInstruction);
    REQUIRE(result.has_value());

    // Same user cannot approve their own request
    auto approve_result = mgr.approve(*result, "operator1", "self-approve");
    CHECK(!approve_result.has_value());

    // Verify request is still pending
    CHECK(mgr.pending_count() == 1);
}

// ── Cannot Approve/Reject Already-Reviewed ─────────────────────────────────

TEST_CASE("ApprovalManager: cannot approve already approved", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kInstruction);
    REQUIRE(result.has_value());
    mgr.approve(*result, "admin1", "ok");

    auto approve2 = mgr.approve(*result, "admin2", "also ok");
    CHECK(!approve2.has_value());
}

TEST_CASE("ApprovalManager: cannot reject already approved", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kInstruction);
    REQUIRE(result.has_value());
    mgr.approve(*result, "admin1", "ok");

    auto reject_result = mgr.reject(*result, "admin2", "too late");
    CHECK(!reject_result.has_value());
}

TEST_CASE("ApprovalManager: cannot approve already rejected", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kInstruction);
    REQUIRE(result.has_value());
    mgr.reject(*result, "admin1", "denied");

    auto approve_result = mgr.approve(*result, "admin2", "wait, let me reconsider");
    CHECK(!approve_result.has_value());
}

TEST_CASE("ApprovalManager: cannot reject already rejected", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kInstruction);
    REQUIRE(result.has_value());
    mgr.reject(*result, "admin1", "denied");

    auto reject2 = mgr.reject(*result, "admin2", "also denied");
    CHECK(!reject2.has_value());
}

// ── Approve/Reject Nonexistent ─────────────────────────────────────────────

TEST_CASE("ApprovalManager: approve nonexistent ID fails", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto result = mgr.approve("nonexistent-id", "admin1", "approving nothing");
    CHECK(!result.has_value());
}

TEST_CASE("ApprovalManager: reject nonexistent ID fails", "[pg][approval_manager]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto result = mgr.reject("nonexistent-id", "admin1", "rejecting nothing");
    CHECK(!result.has_value());
}

// ── Consumption traceability (PR #1796 H3/N2, SOC-2 CC7.2) ─────────────────

TEST_CASE("ApprovalManager: consume_ticket stamps consumed_by with the recalling principal",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{\"agent_id\":\"a1\"}", "",
                         ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "ok").has_value());

    auto consumed = mgr.consume_ticket(*id, "operator1", {});
    REQUIRE(consumed.has_value());

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_at > 0);
    CHECK(row->consumed_by == "operator1"); // who and when agree (same CAS UPDATE)
}

TEST_CASE("ApprovalManager: consume_ticket without a principal fails closed",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    // An unattributable consumption would be a CC7.2 evidence hole.
    auto consumed = mgr.consume_ticket(*id, "", {});
    CHECK(!consumed.has_value());
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_at == 0); // ticket untouched — still consumable
}

TEST_CASE("ApprovalManager: consume_ticket replay is rejected and keeps the original consumer",
          "[pg][approval_manager][approval]") {
    // Replay by the SAME submitter, deliberately (#2442 submitter binding,
    // added after this test was written): a replay by a DIFFERENT principal
    // would now be refused by the binding check as kForeignSubmitter, BEFORE
    // ever reaching the CAS this test exists to pin — so using a different
    // principal here would silently stop testing replay protection at all
    // (the CAS's already-consumed guard could be deleted and this test would
    // still pass, refused for the wrong reason).
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.quarantine_device", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    REQUIRE(mgr.consume_ticket(*id, "operator1", {}).has_value());

    auto replay = mgr.consume_ticket(*id, "operator1", {});
    REQUIRE(!replay.has_value());
    CHECK(replay.error().kind == ConsumeFailure::kNotConsumable);
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_by == "operator1"); // the losing recall never overwrites
}

// ── Mint-surface origin + reserved namespace (#2442) ───────────────────────
// The MCP recall matches a ticket on (definition_id, scope_expression) and
// does not bind the submitter, so a ticket minted elsewhere under an `mcp.`
// definition id is a ticket the MCP gate would accept.

TEST_CASE("ApprovalManager: minting into the mcp. namespace is deliberately NOT refused",
          "[pg][approval_manager][approval][security]") {
    // This asserts an ABSENCE on purpose, so that restoring the mint-time
    // refusal fails here rather than silently stranding operator content.
    //
    // #2442 is defended at REDEMPTION (see the foreign-origin cases below), not
    // at mint. Refusing here looks stricter and is worse: a pre-existing
    // definition under `mcp.` with a schedule re-submits via kSchedule on every
    // fire, so a mint-time refusal stops that schedule permanently, and moving a
    // schedule between definitions is not supported (#2742). Authoring a NEW
    // definition under the prefix is still refused, at the two authoring sites
    // that call `is_reserved_definition_id`.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto forged = mgr.submit("mcp.quarantine_device", "attacker", "{\"agent_id\":\"a1\"}", "",
                             ApprovalOrigin::kInstruction);
    REQUIRE(forged.has_value());

    auto from_schedule = mgr.submit("mcp.delete_tag", "operator1", "{}", "sched-1",
                                    ApprovalOrigin::kSchedule);
    REQUIRE(from_schedule.has_value());

    // Both were written, and both carry the surface they actually came from —
    // which is what the redemption guard reads.
    auto rows = mgr.query({});
    REQUIRE(rows.size() == 2);
    CHECK(mgr.get(*forged)->origin == ApprovalOrigin::kInstruction);
    CHECK(mgr.get(*from_schedule)->origin == ApprovalOrigin::kSchedule);
}

TEST_CASE("ApprovalManager: a declared origin is recorded on the ticket",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto instr = mgr.submit("inventory.audit", "operator1", "{}", "", ApprovalOrigin::kInstruction);
    REQUIRE(instr.has_value());
    auto sched = mgr.submit("inventory.audit", "operator2", "{}", "sched-1",
                            ApprovalOrigin::kSchedule);
    REQUIRE(sched.has_value());
    auto mcp = mgr.submit("mcp.delete_tag", "operator3", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(mcp.has_value());

    CHECK(mgr.get(*instr)->origin == ApprovalOrigin::kInstruction);
    CHECK(mgr.get(*sched)->origin == ApprovalOrigin::kSchedule);
    CHECK(mgr.get(*mcp)->origin == ApprovalOrigin::kMcp);
    CHECK(mgr.query({.submitted_by = "operator1"}).at(0).origin == ApprovalOrigin::kInstruction);
}

TEST_CASE("ApprovalManager: an undeclared submit still records kUnspecified, and it is "
          "refused at redemption",
          "[pg][approval_manager][approval][security]") {
    // Formerly the TETHER on the kUnspecified exemption ("an undeclared mint
    // records no origin and keeps the mcp. prefix"), back when the MCP gate
    // itself minted through this same undeclared path and the test asserted
    // that grant. #2442's closing half removed that exemption: the MCP mint
    // now declares ApprovalOrigin::kMcp explicitly (mcp_server.cpp), so no
    // production caller reaches this path any more. What remains worth
    // pinning is the DEFENSIVE property for a future caller that regresses —
    // omitting `origin` is now a compile error (no default), so this can only
    // happen via an explicit kUnspecified, and that must still decode and
    // still refuse, exactly like kUnrecognised.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{\"agent_id\":\"a1\"}", "",
                         ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->origin == ApprovalOrigin::kUnspecified); // still recorded honestly, not folded

    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    auto denied = mgr.consume_ticket(*id, "operator1", {});
    REQUIRE(!denied.has_value());
    CHECK(denied.error().kind == ConsumeFailure::kForeignOrigin); // refused, not granted
    CHECK(mgr.get(*id)->consumed_at == 0);
}

TEST_CASE("ApprovalManager: origin round-trips through its column text",
          "[pg][approval_manager][approval]") {
    CHECK(std::string_view(to_string(ApprovalOrigin::kInstruction)) == "instruction");
    CHECK(std::string_view(to_string(ApprovalOrigin::kSchedule)) == "schedule");
    CHECK(std::string_view(to_string(ApprovalOrigin::kMcp)) == "mcp");
    CHECK(std::string_view(to_string(ApprovalOrigin::kUnspecified)).empty());

    CHECK(approval_origin_from_string("instruction") == ApprovalOrigin::kInstruction);
    CHECK(approval_origin_from_string("schedule") == ApprovalOrigin::kSchedule);
    CHECK(approval_origin_from_string("mcp") == ApprovalOrigin::kMcp);
    // Empty is an undeclared mint — genuinely "no declared origin". It is not
    // the pre-column row: v7 rewrote those to the sentinel. Anything
    // unrecognised is NOT the same thing and must not decode as it.
    CHECK(approval_origin_from_string("") == ApprovalOrigin::kUnspecified);
    // NOT kUnspecified: both refuse at redemption today, but they are
    // different FACTS ("declared nothing" vs. "this build cannot attribute
    // it to any surface"), and folding an unknown string into kUnspecified
    // would erase that distinction in the stored evidence even though it
    // would not currently change whether the ticket redeems. See the
    // kUnrecognised case below.
    CHECK(approval_origin_from_string("MCP") == ApprovalOrigin::kUnrecognised);
    CHECK(approval_origin_from_string("nonsense") == ApprovalOrigin::kUnrecognised);
}

// "a pre-column row is back-filled to a fail-closed sentinel" (the SQLite v4
// -> v5/v6/v7 migration-ladder back-fill test) is DELETED, not ported —
// ADR-0065 folds the whole v1..v7 SQLite ladder into one PG v1 DDL
// (approval_manager.cpp's migrations()), so there is no pre-v5/pre-column
// intermediate state a fresh Postgres schema can ever be in, and nothing left
// for a back-fill migration to run against. The DECODE-side property this
// test also touched (an unrecognised stored value refuses, not grants) is
// pinned directly below by "a pre-v5 ticket cannot be redeemed" and by
// "an unrecognised origin column value is refused, not exempted" further down.

TEST_CASE("ApprovalManager: a pre-v5 ticket cannot be redeemed at the MCP recall",
          "[pg][approval_manager][approval][security]") {
    // THE POPULATION THE GUARD MISSED. A governance reviewer built this by
    // probe: mint through the REST instruction gate under an `mcp.`-prefixed
    // definition id, set origin to the sentinel v7 back-fills, and the recall
    // CONSUMED it — the exact cross-surface redemption #2442 exists to refuse,
    // still open for every row that predates the column.
    //
    // Driven through the store rather than the migration so it fails if the
    // DECODE ever folds an unknown value back into the granting case, not only
    // if the back-fill regresses. The migration half is pinned above.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.quarantine_device", "attacker", "{\"agent_id\":\"a1\"}", "",
                         ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "ok").has_value());

    // Rewrite the column to exactly what the SQLite-era v7 migration used to
    // back-fill (ADR-0065's port has no such migration on a fresh schema —
    // see the deleted-test note above — but the STORED VALUE this decodes is
    // still real data a future binary/corruption could produce).
    {
        auto lease = mgr_bundle.pool().acquire();
        REQUIRE(lease);
        pg::PgResult res = pg::exec_params(
            lease.get(), "UPDATE approval_manager.approvals SET origin = 'legacy' WHERE id = $1",
            std::vector<std::string>{*id});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }
    REQUIRE(mgr.get(*id)->origin == ApprovalOrigin::kUnrecognised);

    auto denied = mgr.consume_ticket(*id, "operator1", {});
    REQUIRE(!denied.has_value());
    CHECK(denied.error().kind == ConsumeFailure::kForeignOrigin);
    CHECK(mgr.get(*id)->consumed_at == 0); // untouched — still evidence
}

// ── Pre-consume recheck (#2443) ────────────────────────────────────────────
// A ticket can sit approved-but-unconsumed for up to the 7-day TTL, so the
// state its effect assumes may drift. The recheck runs between the match and
// the CAS: a denial must leave the ticket RECALLABLE, because burning a
// human-approved capability on a no-op is the defect being fixed.

TEST_CASE("ApprovalManager: a failing pre-consume recheck denies WITHOUT consuming",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.confirm_engine_rotation", "operator1", "{\"token_id\":\"t1\"}", "",
                         ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "ok").has_value());

    auto consumed = mgr.consume_ticket(*id, "operator1", [](const Approval&) {
        return std::expected<void, std::string>(
            std::unexpected("rotation t1 already resolved; mint a fresh ticket"));
    });
    REQUIRE(!consumed.has_value());
    CHECK(consumed.error().kind == ConsumeFailure::kPrecondition);
    CHECK(consumed.error().message == "rotation t1 already resolved; mint a fresh ticket");

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "approved");
    CHECK(row->consumed_at == 0); // the CAS never ran
    CHECK(row->consumed_by.empty());
}

TEST_CASE("ApprovalManager: a ticket denied by the recheck is still consumable afterwards",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.confirm_engine_rotation", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    bool drifted = true;
    ConsumePrecondition recheck = [&drifted](const Approval&) -> std::expected<void, std::string> {
        if (drifted)
            return std::unexpected("state drifted");
        return {};
    };

    REQUIRE(!mgr.consume_ticket(*id, "operator1", recheck).has_value());
    drifted = false; // operator resolved the drift — the SAME ticket still works
    REQUIRE(mgr.consume_ticket(*id, "operator1", recheck).has_value());

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_at > 0);
    CHECK(row->consumed_by == "operator1");
}

TEST_CASE("ApprovalManager: the pre-consume recheck sees the matched ticket's own row",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{\"agent_id\":\"a1\"}", "",
                         ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "ok").has_value());

    Approval seen;
    auto consumed = mgr.consume_ticket(*id, "operator1",
                                       [&seen](const Approval& a) -> std::expected<void, std::string> {
                                           seen = a;
                                           return {};
                                       });
    REQUIRE(consumed.has_value());
    CHECK(seen.id == *id);
    CHECK(seen.definition_id == "mcp.delete_tag");
    CHECK(seen.scope_expression == "{\"agent_id\":\"a1\"}");
    CHECK(seen.submitted_by == "operator1");
    CHECK(seen.status == "approved"); // pre-CAS snapshot, so not yet consumed
    CHECK(seen.consumed_at == 0);
}

TEST_CASE("ApprovalManager: a non-consumable ticket is declined without running the recheck",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    REQUIRE(mgr.consume_ticket(*id, "operator1", {}).has_value());

    // Replay by the SAME submitter, deliberately — a replay by a DIFFERENT
    // principal is refused earlier, by the #2442 submitter-binding check, as
    // kForeignSubmitter (see the submitter-binding test group below); this
    // case exists to pin the NotConsumable path specifically, which a
    // foreign-submitter replay would never reach.
    bool ran = false;
    auto replay = mgr.consume_ticket(*id, "operator1",
                                     [&ran](const Approval&) -> std::expected<void, std::string> {
                                         ran = true;
                                         return {};
                                     });
    REQUIRE(!replay.has_value());
    CHECK(replay.error().kind == ConsumeFailure::kNotConsumable);
    CHECK(!ran); // the recheck may be costly or emit audit — spent tickets skip it

    // Same for a pending (never-approved) ticket and for an absent id.
    auto pending =
        mgr.submit("mcp.delete_tag", "operator1", "{\"n\":1}", "", ApprovalOrigin::kMcp);
    REQUIRE(pending.has_value());
    ran = false; // reset per sub-case so a regression names WHICH one regressed
    auto on_pending = mgr.consume_ticket(*pending, "operator1",
                                         [&ran](const Approval&) -> std::expected<void, std::string> {
                                             ran = true;
                                             return {};
                                         });
    REQUIRE(!on_pending.has_value());
    CHECK(on_pending.error().kind == ConsumeFailure::kNotConsumable);

    ran = false;
    auto absent = mgr.consume_ticket("does-not-exist", "operator1",
                                     [&ran](const Approval&) -> std::expected<void, std::string> {
                                         ran = true;
                                         return {};
                                     });
    REQUIRE(!absent.has_value());
    CHECK(absent.error().kind == ConsumeFailure::kNotConsumable);
    CHECK(!ran);
}

TEST_CASE("ApprovalManager: an empty precondition consumes exactly like the two-argument overload",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    REQUIRE(mgr.consume_ticket(*id, "operator1", {}).has_value());
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_by == "operator1");
}

TEST_CASE("ApprovalManager: a missing principal fails closed on the recheck overload too",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    bool ran = false;
    auto consumed = mgr.consume_ticket(*id, "",
                                       [&ran](const Approval&) -> std::expected<void, std::string> {
                                           ran = true;
                                           return {};
                                       });
    REQUIRE(!consumed.has_value());
    CHECK(consumed.error().kind == ConsumeFailure::kStoreError);
    CHECK(!ran); // argument validation precedes any callback
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_at == 0);
}

TEST_CASE("ApprovalManager: the CAS still wins when the row is consumed during the recheck",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    // The window the design deliberately accepts: row read, lock released,
    // callback runs, lock retaken, CAS runs. Force that exact interleaving by
    // consuming the ticket from inside the callback. The outer consume must
    // LOSE — a denial, never a second consume. The inner consume uses the
    // SAME principal as the outer one (#2442 submitter binding, added after
    // this test was written): a different principal would now be refused by
    // the binding check before ever reaching the CAS this test exercises,
    // which is a different property than the one under test here.
    auto outer =
        mgr.consume_ticket(*id, "operator1",
                           [&mgr, &id](const Approval&) -> std::expected<void, std::string> {
                               (void)mgr.consume_ticket(*id, "operator1", {});
                               return {};
                           });
    REQUIRE(!outer.has_value());
    CHECK(outer.error().kind == ConsumeFailure::kNotConsumable);

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_by == "operator1"); // consumed exactly once, by the winner
}

TEST_CASE("ApprovalManager: a throwing recheck denies without consuming and does not escape",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    // The callback is caller code running on an httplib worker. A throw must
    // not leave a store method as an exception, and must not be reported as a
    // decision the callback never made.
    auto threw = mgr.consume_ticket(
        *id, "operator1", [](const Approval&) -> std::expected<void, std::string> {
            throw std::runtime_error("rotation lookup failed");
        });
    REQUIRE(!threw.has_value());
    CHECK(threw.error().kind == ConsumeFailure::kStoreError); // NOT kPrecondition
    CHECK(threw.error().message.find("pre-consume recheck failed") != std::string::npos);
    // The callback's own text must NOT ride along: this message reaches the MCP
    // envelope, and e.what() is unvetted. Asserting only the inclusion above
    // would still pass if someone appended it again.
    CHECK(threw.error().message.find("rotation lookup failed") == std::string::npos);
    CHECK(mgr.get(*id)->consumed_at == 0); // still recallable

    // A non-std throw takes the same path.
    auto odd = mgr.consume_ticket(
        *id, "operator1",
        [](const Approval&) -> std::expected<void, std::string> { throw 42; });
    REQUIRE(!odd.has_value());
    CHECK(odd.error().kind == ConsumeFailure::kStoreError);
    CHECK(mgr.get(*id)->consumed_at == 0);
}

TEST_CASE("ApprovalManager: a store failure during the recheck is not reported as spent",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    // The defect this whole seam re-introduced once: the pre-consume read used
    // get(), which reports a FAILED read and a missing row identically. Drop
    // the table to force a real read failure and confirm the caller is told the
    // store broke, NOT that its human-approved capability is spent.
    {
        auto lease = mgr_bundle.pool().acquire();
        REQUIRE(lease);
        pg::PgResult res =
            pg::exec_params(lease.get(), "DROP TABLE approval_manager.approvals",
                            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    bool ran = false;
    auto r = mgr.consume_ticket(*id, "operator1",
                                [&ran](const Approval&) -> std::expected<void, std::string> {
                                    ran = true;
                                    return {};
                                });
    REQUIRE(!r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kStoreError); // NOT kNotConsumable
    CHECK(!ran); // no row to hand the callback
    // The fault hit BEFORE the precondition block ever runs: consume_ticket's
    // unconditional #2442 origin+submitter binding-check read
    // (approval_manager.cpp's get_checked call ahead of the CAS) sees the
    // dropped table first, and this refusal is exactly what #2786 arm 1 says
    // must never be silently indistinguishable from an ordinary store error —
    // the flag and a real SQLSTATE must ride along.
    CHECK(r.error().binding_check_unevaluated);
    CHECK(!r.error().sqlstate.empty());

    // And the same read through get_checked directly.
    CHECK(!mgr.get_checked(*id).has_value());
}

// "migration v6 applies to an existing v5 store" is DELETED, not ported —
// same reason as the pre-column back-fill test above: ADR-0065's single PG
// v1 DDL has no v5/v6 intermediate state, and both indexes it pinned are
// simply part of that one DDL now (verified by inspection of
// approval_manager.cpp's migrations(), and exercised incidentally by every
// other test in this file that hits an indexed query path). The origin/dev
// SQLite-era counterpart also asserted `current_version(...) == 8` for the
// #1398 target_plugin/target_action columns — moot for the same reason.

TEST_CASE("ApprovalManager: the recheck may read the store without deadlocking",
          "[pg][approval_manager][approval]") {
    // The callback runs with mtx_ fully released (ADR-0065: mtx_ now scopes
    // ONLY submit()'s compound cap-check+sweep+insert — see approval_manager.hpp
    // — so consume_ticket and every read method it calls back into never touch
    // it at all), so a precondition that consults the approval store (a
    // plausible shape: "no newer ticket supersedes this one") is safe. The
    // SQLite-era version of this test needed a background thread + a bounded
    // timeout because a lock-held design would have self-deadlocked on a
    // non-recursive mutex; that hazard is now structurally impossible
    // (consume_ticket's CAS is a single atomic Postgres statement, needing no
    // app-level lock at all), so a synchronous call suffices to pin the
    // behavior.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    auto consumed = mgr.consume_ticket(
        *id, "operator1", [&mgr](const Approval& a) -> std::expected<void, std::string> {
            (void)mgr.get(a.id);
            (void)mgr.pending_count();
            (void)mgr.query({});
            return {};
        });
    CHECK(consumed.has_value());
}

// ── Expiry sweep (PR #1796 N3 + L2) ────────────────────────────────────────
// The sweep runs lazily inside submit(). One shared 7-day window: pending
// tickets age out from submitted_at; approved-but-unconsumed tickets (leaked
// one-time capabilities) age out from reviewed_at. Counts come from stepping
// RETURNING rows, never sqlite3_changes() after step (#1033).

namespace {
/// Backdate a timestamp column directly — the sweep triggers on the NEXT
/// submit(), exactly like production (no test-only sweep entry point).
/// `column` is a fixed literal at every call site (never caller-supplied
/// text), so interpolating it into the SQL string carries no injection risk.
void backdate(pg::PgPool& pool, const std::string& id, const char* column, int64_t seconds_ago) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto sql = std::string("UPDATE approval_manager.approvals SET ") + column + " = " + column +
               " - $1 WHERE id = $2";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(), std::vector<std::string>{std::to_string(seconds_ago), id});
    REQUIRE(res.status() == PGRES_COMMAND_OK);
}
constexpr int64_t k8Days = 8 * 24 * 3600;
} // namespace

namespace {
/// Bulk-inserts `count` pending approvals directly via SQL (bypassing
/// `submit()`'s own cap, which would refuse past 1000) so cap-boundary tests
/// stay fast — one INSERT instead of `count` round-trips through submit().
void seed_pending(pg::PgPool& pool, const std::string& id_prefix, int count, int64_t age_seconds) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto sql = std::string(
                   "INSERT INTO approval_manager.approvals "
                   "(id, definition_id, status, submitted_by, submitted_at) "
                   "SELECT '") +
               id_prefix +
               "' || gs, 'def-seeded', 'pending', 'operator1', "
               "extract(epoch from now())::bigint - $1 "
               "FROM generate_series(1, $2) AS gs";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{std::to_string(age_seconds), std::to_string(count)});
    REQUIRE(res.status() == PGRES_COMMAND_OK);
}
} // namespace

TEST_CASE("ApprovalManager: a full stale pending queue self-heals on the next submit "
          "(governance adversarial review 2026-08-31 — was permanently wedged)",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    // At the cap, all 8 days old and expirable.
    seed_pending(mgr_bundle.pool(), "stale-", ApprovalManager::kMaxPendingApprovals, k8Days);

    // Before the fix, this returned "approval queue is full" and never ran
    // the expiry sweep, permanently wedging the store.
    auto id = mgr.submit("def-new", "operator1", "scope", "", ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "pending");

    // The stale queue was swept, not just tolerated once.
    auto pending = mgr.pending_count();
    CHECK(pending == 1); // only the new one — all kMaxPendingApprovals stale rows expired
}

TEST_CASE("ApprovalManager: a full queue of NON-stale pending approvals still rejects",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    // At the cap, fresh (not expirable) — the cap must still bind when there
    // is genuinely nothing for the sweep to clear.
    seed_pending(mgr_bundle.pool(), "fresh-", ApprovalManager::kMaxPendingApprovals,
                /*age_seconds=*/60);

    auto id = mgr.submit("def-new", "operator1", "scope", "", ApprovalOrigin::kInstruction);
    REQUIRE(!id.has_value());
    CHECK(id.error().find("queue is full") != std::string::npos);
}

TEST_CASE("ApprovalManager: stale pending approvals expire on the next submit",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto stale = mgr.submit("def-old", "operator1", "scope", "", ApprovalOrigin::kInstruction);
    REQUIRE(stale.has_value());
    backdate(mgr_bundle.pool(), *stale, "submitted_at", k8Days);

    REQUIRE(mgr.submit("def-new", "operator1", "scope", "", ApprovalOrigin::kInstruction)
                .has_value()); // triggers the sweep

    auto row = mgr.get(*stale);
    REQUIRE(row.has_value());
    CHECK(row->status == "expired");
}

TEST_CASE("ApprovalManager: approved-but-unconsumed tickets expire 7 days after review",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.quarantine_device", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "ok").has_value());
    backdate(mgr_bundle.pool(), *id, "reviewed_at", k8Days);

    REQUIRE(mgr.submit("def-new", "operator1", "scope", "", ApprovalOrigin::kInstruction)
                .has_value()); // triggers the sweep

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "expired"); // the leaked capability token is dead

    // An expired ticket is no longer consumable.
    auto consumed = mgr.consume_ticket(*id, "operator1", {});
    CHECK(!consumed.has_value());
}

TEST_CASE("ApprovalManager: consumed tickets are history, never expired",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    REQUIRE(mgr.consume_ticket(*id, "operator1", {}).has_value());
    backdate(mgr_bundle.pool(), *id, "reviewed_at", k8Days);

    REQUIRE(mgr.submit("def-new", "operator1", "scope", "", ApprovalOrigin::kInstruction)
                .has_value()); // triggers the sweep

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "approved");        // untouched — it is evidence, not a capability
    CHECK(row->consumed_by == "operator1");  // trail intact
}

// ── Mint-surface origin + the redemption guard (#2442) ─────────────────────
// The MCP recall matches a ticket on (definition_id, scope_expression) and
// does not bind the submitter, so a ticket minted elsewhere under an `mcp.`
// definition id is a ticket the MCP gate would otherwise accept. The refusal
// lives at REDEMPTION, keyed on the recorded origin — minting is a legitimate
// act, redeeming on a foreign surface is not. These cases are the tether on
// that: they are what stops the guard being dropped or narrowed unnoticed.

TEST_CASE("ApprovalManager: a ticket minted by a declared non-MCP surface cannot be redeemed",
          "[pg][approval_manager][approval][security]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    // The REST instruction gate: definition id caller-influenced, scope
    // expression caller-supplied verbatim. The mint SUCCEEDS — refusing it here
    // is what stranded pre-existing operator content, and is deliberately gone.
    auto forged = mgr.submit("mcp.quarantine_device", "attacker", "{\"agent_id\":\"a1\"}", "",
                             ApprovalOrigin::kInstruction);
    REQUIRE(forged.has_value());
    REQUIRE(mgr.approve(*forged, "admin1", "").has_value());

    // The redemption is where it dies. This is the MCP recall's call shape.
    auto redeemed = mgr.consume_ticket(*forged, "attacker", {});
    REQUIRE(!redeemed.has_value());

    // And the ticket is UNTOUCHED — a refused forgery must not burn it.
    auto row = mgr.get(*forged);
    REQUIRE(row.has_value());
    CHECK(row->consumed_at == 0);
    CHECK(row->consumed_by.empty());
    CHECK(row->status == "approved");

    // Same for the scheduler surface.
    auto sched = mgr.submit("mcp.delete_tag", "attacker", "{}", "sched-1",
                            ApprovalOrigin::kSchedule);
    REQUIRE(sched.has_value());
    REQUIRE(mgr.approve(*sched, "admin1", "").has_value());
    CHECK(!mgr.consume_ticket(*sched, "attacker", {}).has_value());
    CHECK(mgr.get(*sched)->consumed_at == 0);
}

TEST_CASE("ApprovalManager: the redemption refusal is a distinct kind but not a distinct message",
          "[pg][approval_manager][approval][security]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto forged = mgr.submit("mcp.quarantine_device", "attacker", "{}", "",
                             ApprovalOrigin::kInstruction);
    REQUIRE(forged.has_value());
    REQUIRE(mgr.approve(*forged, "admin1", "").has_value());

    auto denied = mgr.consume_ticket(*forged, "attacker", {});
    REQUIRE(!denied.has_value());
    // The KIND separates a forgery attempt from a replay, so the log and any
    // future audit row can tell them apart.
    CHECK(denied.error().kind == ConsumeFailure::kForeignOrigin);

    // The MESSAGE deliberately does not. A spent ordinary ticket and a refused
    // forgery must read identically to a remote caller, or the recall becomes an
    // oracle for which definition ids exist and which surface minted them.
    auto spent = mgr.submit("inventory.audit", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(spent.has_value());
    REQUIRE(mgr.approve(*spent, "admin1", "").has_value());
    REQUIRE(mgr.consume_ticket(*spent, "operator1", {}).has_value()); // first use succeeds
    auto replay = mgr.consume_ticket(*spent, "operator1", {});    // second does not
    REQUIRE(!replay.has_value());
    CHECK(replay.error().kind == ConsumeFailure::kNotConsumable);
    CHECK(denied.error().message == replay.error().message);
}

TEST_CASE("ApprovalManager: an MCP-minted ticket under the reserved prefix still redeems",
          "[pg][approval_manager][approval][security]") {
    // The positive control. Without it, a guard that refused EVERYTHING would
    // pass every assertion above.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto declared = mgr.submit("mcp.quarantine_device", "operator1", "{\"agent_id\":\"a1\"}", "",
                               ApprovalOrigin::kMcp);
    REQUIRE(declared.has_value());
    REQUIRE(mgr.approve(*declared, "admin1", "").has_value());
    CHECK(mgr.consume_ticket(*declared, "operator1", {}).has_value());
    CHECK(mgr.get(*declared)->consumed_at != 0);

    // The undeclared mint used to be what the frozen MCP gate actually did,
    // and had to still redeem or the guard broke the live MCP flow. #2442's
    // closing half removed that carve-out (mcp_server.cpp now always declares
    // kMcp), so an undeclared submit is no longer a live production path —
    // see "an undeclared submit still records kUnspecified, and it is refused
    // at redemption" above for the negative coverage that replaced this.
}

TEST_CASE("ApprovalManager: an ordinary non-MCP ticket is refused at redemption too",
          "[pg][approval_manager][approval][security]") {
    // The guard is keyed on ORIGIN, not on the `mcp.` id prefix — so a REST-
    // minted ticket for an ordinary definition is equally unredeemable through
    // the recall. This is the property that survives the MCP mint changing how
    // it builds its ids, which the prefix rule did not. It costs nothing: no
    // legitimate flow redeems a REST-minted ticket here (the REST gate matches
    // its own approvals by field comparison, it does not call consume_ticket).
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto rest = mgr.submit("inventory.audit", "operator1", "{}", "", ApprovalOrigin::kInstruction);
    REQUIRE(rest.has_value());
    REQUIRE(mgr.approve(*rest, "admin1", "").has_value());
    auto denied = mgr.consume_ticket(*rest, "operator1", {});
    REQUIRE(!denied.has_value());
    CHECK(denied.error().kind == ConsumeFailure::kForeignOrigin);
    CHECK(mgr.get(*rest)->consumed_at == 0);
}

// ── Submitter binding (#2442) ───────────────────────────────────────────────
// An approval id is a bearer capability, and a Viewer holding `Approval:Read`
// can list another operator's ticket id via GET /api/approvals (the id is
// returned in full, unredacted). The recall must not be redeemable by anyone
// but the principal it was granted to, even when the origin is correctly MCP.
// Checked in the SAME store read as the origin check above, not a new one.

TEST_CASE("ApprovalManager: a ticket recalls for the principal it was submitted by",
          "[pg][approval_manager][approval][security]") {
    // The positive control. Without it, a guard that refused EVERYTHING would
    // pass every negative assertion below.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.quarantine_device", "operator1", "{\"agent_id\":\"a1\"}", "",
                         ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    CHECK(mgr.consume_ticket(*id, "operator1", {}).has_value());
    CHECK(mgr.get(*id)->consumed_by == "operator1");
}

TEST_CASE("ApprovalManager: a ticket recalled by a different principal is refused, "
          "even with the correct origin",
          "[pg][approval_manager][approval][security]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    // Correctly MCP-declared, so this isolates the submitter check from the
    // origin check above it in the same block.
    auto id = mgr.submit("mcp.quarantine_device", "operator1", "{\"agent_id\":\"a1\"}", "",
                         ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    // The scenario this closes: operator2 read operator1's ticket id off
    // GET /api/approvals (Approval:Read, seeded to Viewer) and also holds the
    // target tool's own RBAC permission.
    auto redeemed = mgr.consume_ticket(*id, "operator2", {});
    REQUIRE(!redeemed.has_value());
    CHECK(redeemed.error().kind == ConsumeFailure::kForeignSubmitter);
    // Same message as every other "not consumable" outcome — see
    // kNotConsumableMessage's anti-oracle doc comment. Reusing the ORIGIN
    // test's sibling assertion below pins this identically.
    CHECK(redeemed.error().message == kNotConsumableMessage);

    // Untouched — a refused forgery must not burn a live human-approved
    // capability the rightful submitter can still redeem.
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_at == 0);
    CHECK(row->consumed_by.empty());
    CHECK(row->status == "approved");
}

TEST_CASE("ApprovalManager: the foreign-submitter refusal is a distinct kind but not a "
          "distinct message",
          "[pg][approval_manager][approval][security]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    auto denied = mgr.consume_ticket(*id, "operator2", {});
    REQUIRE(!denied.has_value());
    CHECK(denied.error().kind == ConsumeFailure::kForeignSubmitter);

    auto spent = mgr.submit("mcp.quarantine_device", "operator3", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(spent.has_value());
    REQUIRE(mgr.approve(*spent, "admin1", "").has_value());
    REQUIRE(mgr.consume_ticket(*spent, "operator3", {}).has_value()); // first use succeeds
    auto replay = mgr.consume_ticket(*spent, "operator3", {});        // second does not
    REQUIRE(!replay.has_value());
    CHECK(replay.error().kind == ConsumeFailure::kNotConsumable);
    CHECK(denied.error().message == replay.error().message);
}

TEST_CASE("ApprovalManager: a ticket wrong on BOTH origin and submitter reports "
          "kForeignOrigin, the more specific fact",
          "[pg][approval_manager][approval][security]") {
    // The origin check runs first in the shared binding block, so it wins
    // when both are true — pinned here rather than left as a claim in a
    // comment. Not a security-relevant choice (both kinds are refused
    // identically to the caller; this only affects which audit token is
    // written), but a future reordering that silently flips it should fail a
    // test, not just a review.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    // Declared non-MCP surface AND a different submitter than the one
    // recalling it — wrong on both axes at once.
    auto id = mgr.submit("mcp.quarantine_device", "operator1", "{\"agent_id\":\"a1\"}", "",
                         ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    auto denied = mgr.consume_ticket(*id, "operator2", {});
    REQUIRE(!denied.has_value());
    CHECK(denied.error().kind == ConsumeFailure::kForeignOrigin);
    CHECK(denied.error().message == kNotConsumableMessage);
    CHECK(mgr.get(*id)->consumed_at == 0); // untouched either way
}

TEST_CASE("ApprovalManager: a store fault AT the binding check masks a foreign-submitter "
          "ticket's kind — until the fault clears",
          "[pg][approval_manager][approval][security]") {
    // Sibling to the origin-check chaos test below (#2786 arm 1), same
    // mechanism, ported to Postgres (ADR-0065): a second raw connection holds
    // an ACCESS EXCLUSIVE table lock, and the store's own pool is built with
    // a short `lock_timeout_ms` so its blocked read fails with a real,
    // deterministic SQLSTATE 55P03 (lock_not_available) rather than hanging
    // (the `test_engine_principal_store.cpp` #2456 precedent for this
    // technique — a real non-42 SQLSTATE with no sleep/retry loop needed).
    // This time the origin is correctly kMcp and only the submitter is
    // wrong, isolating that the flag and the eventual kForeignSubmitter kind
    // both survive sharing the read with the origin check.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::approval_manager_pg_template);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(pool.valid());
    ApprovalManager mgr{pool};
    REQUIRE(mgr.is_open());

    auto id = mgr.submit("mcp.quarantine_device", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    pg::PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(locker.get(),
                            "LOCK TABLE approval_manager.approvals IN ACCESS EXCLUSIVE MODE",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    auto faulted = mgr.consume_ticket(*id, "operator2", {});
    REQUIRE(!faulted.has_value());
    CHECK(faulted.error().kind == ConsumeFailure::kStoreError);
    CHECK(faulted.error().sqlstate == "55P03");
    CHECK(faulted.error().binding_check_unevaluated);

    REQUIRE(pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    locker.reset();

    CHECK(mgr.get(*id)->consumed_at == 0); // untouched

    auto cleared = mgr.consume_ticket(*id, "operator2", {});
    REQUIRE(!cleared.has_value());
    CHECK(cleared.error().kind == ConsumeFailure::kForeignSubmitter);
    CHECK(!cleared.error().binding_check_unevaluated);
    CHECK(mgr.get(*id)->consumed_at == 0);

    // And the rightful submitter can still redeem it — the fault and the
    // forged recall attempt did not burn the ticket.
    CHECK(mgr.consume_ticket(*id, "operator1", {}).has_value());
}

TEST_CASE("ApprovalManager: an empty precondition consumes with no precondition supplied",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    REQUIRE(mgr.consume_ticket(*id, "operator1", {}).has_value());
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_by == "operator1");
}

TEST_CASE("ApprovalManager: a missing principal fails closed on the recheck path too",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    bool ran = false;
    auto consumed = mgr.consume_ticket(*id, "",
                                       [&ran](const Approval&) -> std::expected<void, std::string> {
                                           ran = true;
                                           return {};
                                       });
    REQUIRE(!consumed.has_value());
    CHECK(consumed.error().kind == ConsumeFailure::kStoreError);
    CHECK(!ran); // argument validation precedes any callback
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_at == 0);
}

TEST_CASE("ApprovalManager: a store failure is not reported as spent in the message either",
          "[pg][approval_manager][approval]") {
    // The case above pins the KIND on a store failure. This pins the MESSAGE.
    // The kind is what drives the branch: the sole production caller is the MCP
    // recall (grep `consume_ticket(` in server/core/src — one production hit),
    // and it reads `.kind` four times and `.message` never. The message is pinned anyway because it is the field a future
    // caller would surface to a human, and a store failure described as a spent
    // ticket is the wrong thing to tell them — but do not read this test as
    // evidence that anything reads it today.
    //
    // This used to test a two-argument overload that returned the message alone
    // and discarded the kind. That overload was removed (adversarial review,
    // K3/CDX-P2-003) because a future caller picking it would have lost the
    // cross-surface distinction #2442 added. The property it protected is kept
    // here against the typed error.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    {
        auto lease = mgr_bundle.pool().acquire();
        REQUIRE(lease);
        pg::PgResult res =
            pg::exec_params(lease.get(), "DROP TABLE approval_manager.approvals",
                            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto flat = mgr.consume_ticket(*id, "operator1", {});
    REQUIRE(!flat.has_value());
    // The property that matters is the negative: it must NOT read as spent, or
    // an operator is told to discard a live human-approved capability. (The
    // dropped-table query fails inside get_checked's own read, so the text is
    // "read failed: ..." — still kStoreError either way.)
    CHECK(flat.error().message.find("not consumable") == std::string::npos);
    CHECK(flat.error().message.find("already used") == std::string::npos);
    CHECK(flat.error().message.find("failed") != std::string::npos);

    // And the kind agrees with the message.
    CHECK(flat.error().kind == ConsumeFailure::kStoreError);
}

TEST_CASE("ApprovalManager: an unrecognised origin column value is refused, not exempted",
          "[pg][approval_manager][approval][security]") {
    // The decode used to fold anything unknown into kUnspecified. At the time
    // #2442 first shipped, kUnspecified was the value that GRANTED redemption,
    // so that fold would have made the composite fail OPEN even though the
    // predicate fails closed. kUnspecified stopped granting once the MCP mint
    // declared kMcp explicitly (#2442's closing half) — kept apart from
    // kUnrecognised regardless, since folding still erases a real evidentiary
    // distinction even though both refuse today.
    CHECK(approval_origin_from_string("") == ApprovalOrigin::kUnspecified);
    CHECK(approval_origin_from_string("mcp") == ApprovalOrigin::kMcp);
    CHECK(approval_origin_from_string("MCP") == ApprovalOrigin::kUnrecognised); // case-sensitive
    CHECK(approval_origin_from_string("nonsense") == ApprovalOrigin::kUnrecognised);
    CHECK(declares_non_mcp_surface(ApprovalOrigin::kUnrecognised));

    // End to end: a row written by a newer binary, read back by this one.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;
    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    {
        auto lease = mgr_bundle.pool().acquire();
        REQUIRE(lease);
        pg::PgResult res = pg::exec_params(
            lease.get(), "UPDATE approval_manager.approvals SET origin = 'future_surface'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto denied = mgr.consume_ticket(*id, "operator1", {});
    REQUIRE(!denied.has_value());
    CHECK(denied.error().kind == ConsumeFailure::kForeignOrigin);
    CHECK(mgr.get(*id)->consumed_at == 0);
}

TEST_CASE("ApprovalManager: find_pending skips a ticket the recall would refuse",
          "[pg][approval_manager][approval][security]") {
    // sec-F-03. The MCP mint dedups on (definition_id, submitted_by,
    // scope_expression). Since the mint-time namespace refusal was removed, a
    // ticket carrying a declared non-MCP surface can occupy that key — and
    // handing it back returns a ticket the MCP recall will refuse as
    // kForeignOrigin. The admin then reviews and approves a request that can
    // never complete, spending a human approval on a dead flow.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto foreign = mgr.submit("mcp.quarantine_device", "operator1", "{\"agent_id\":\"a1\"}", "",
                              ApprovalOrigin::kInstruction);
    REQUIRE(foreign.has_value());

    // Same dedup key, and the row really is there and really is pending —
    // otherwise this asserts nothing.
    REQUIRE(mgr.get(*foreign)->status == "pending");
    REQUIRE(mgr.get(*foreign)->origin == ApprovalOrigin::kInstruction);

    CHECK(!mgr.find_pending("mcp.quarantine_device", "operator1", "{\"agent_id\":\"a1\"}")
               .has_value());
}

TEST_CASE("ApprovalManager: find_pending walks past a foreign ticket to a usable one",
          "[pg][approval_manager][approval][security]") {
    // The filter must WALK, not just reject the newest. An older MCP-origin
    // ticket under the same key is a perfectly good dedup hit; skipping it
    // mints a duplicate and re-opens the flooding this dedup exists to bound.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto usable = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(usable.has_value());
    backdate(mgr_bundle.pool(), *usable, "submitted_at", 60); // older, so the foreign one sorts first

    auto foreign = mgr.submit("mcp.delete_tag", "operator1", "{}", "",
                              ApprovalOrigin::kInstruction);
    REQUIRE(foreign.has_value());

    auto found = mgr.find_pending("mcp.delete_tag", "operator1", "{}");
    REQUIRE(found.has_value());
    CHECK(found->id == *usable); // NOT the newer foreign one
    CHECK(found->origin == ApprovalOrigin::kMcp);
}

// "migration v7 reaches a store already at v5" is DELETED, not ported — same
// reason as the other two SQLite migration-ladder tests above: ADR-0065's
// single PG v1 DDL has no v5-vs-fresh distinction to reach a population
// through. The DECODE-side property (an undeclared/unrecognised origin
// refuses, a declared one doesn't) is pinned directly by "a pre-v5 ticket
// cannot be redeemed" and "an unrecognised origin column value is refused,
// not exempted" elsewhere in this file — those exercise the same code path
// this test exercised through a migration-shaped fixture.

TEST_CASE("consume_denial_reason: every kind maps to its own audit token",
          "[approval_manager][approval][security]") {
    // The audit taxonomy had NO regression barrier: a governance reviewer
    // swapped the "foreign_origin" and "not_consumable" tokens and the entire
    // suite stayed green. The -Wswitch pragma guards a MISSING arm; it cannot
    // see a WRONG one, and a swap is exactly that.
    //
    // This matters because the tokens are the whole deliverable of the audit
    // change: a cross-surface forgery attempt must not be recorded identically
    // to a benign replay. Swapping them silently restores the defect.
    CHECK(std::string(consume_denial_reason(ConsumeFailure::kForeignOrigin)) == "foreign_origin");
    CHECK(std::string(consume_denial_reason(ConsumeFailure::kNotConsumable)) == "not_consumable");
    CHECK(std::string(consume_denial_reason(ConsumeFailure::kStoreError)) == "store_error");
    CHECK(std::string(consume_denial_reason(ConsumeFailure::kPrecondition)) == "precondition");
    CHECK(std::string(consume_denial_reason(ConsumeFailure::kForeignSubmitter)) ==
          "foreign_submitter");

    // Distinctness is the property, stated separately from the exact spellings
    // so a rename stays cheap while a collision stays caught.
    const std::array<const char*, 5> tokens{
        consume_denial_reason(ConsumeFailure::kForeignOrigin),
        consume_denial_reason(ConsumeFailure::kNotConsumable),
        consume_denial_reason(ConsumeFailure::kStoreError),
        consume_denial_reason(ConsumeFailure::kPrecondition),
        consume_denial_reason(ConsumeFailure::kForeignSubmitter),
    };
    for (size_t i = 0; i < tokens.size(); ++i)
        for (size_t j = i + 1; j < tokens.size(); ++j)
            CHECK(std::string(tokens[i]) != std::string(tokens[j]));
}

// ── is_permanent_pg_error (ADR-0065 port of #2786 "PR 1c") ──────────────────

static_assert(yuzu::server::is_permanent_pg_error("42P01")); // undefined_table
static_assert(yuzu::server::is_permanent_pg_error("42501")); // insufficient_privilege
static_assert(yuzu::server::is_permanent_pg_error("XX001")); // data_corrupted
static_assert(yuzu::server::is_permanent_pg_error("XX002")); // index_corrupted
static_assert(yuzu::server::is_permanent_pg_error("53100")); // disk_full
static_assert(yuzu::server::is_permanent_pg_error("25006")); // read_only_sql_transaction

static_assert(!yuzu::server::is_permanent_pg_error("55P03")); // lock_not_available
static_assert(!yuzu::server::is_permanent_pg_error("40001")); // serialization_failure
static_assert(!yuzu::server::is_permanent_pg_error("40P01")); // deadlock_detected
static_assert(!yuzu::server::is_permanent_pg_error("57014")); // query_canceled
static_assert(!yuzu::server::is_permanent_pg_error("08006")); // connection_failure
static_assert(!yuzu::server::is_permanent_pg_error("P0001")); // raise_exception
static_assert(!yuzu::server::is_permanent_pg_error("")); // not a Postgres fault

// ── #2786 arm 1: the origin check's own fault must not mask a forgery ──────

TEST_CASE("ApprovalManager: a genuinely transient fault at the origin check is flagged, "
          "and the forgery signal fires once it clears",
          "[pg][approval_manager][approval][security]") {
    // CH-5 (governance Gate 5 chaos design), ported to Postgres (ADR-0065):
    // fault-inject the origin check's SELECT with a real, deterministic
    // SQLSTATE 55P03 (see the submitter-chaos test above for the technique),
    // on a NON-MCP-origin ticket, and confirm the flag/sqlstate ride along,
    // and that redemption still correctly reports kForeignOrigin once the
    // fault clears.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::approval_manager_pg_template);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(pool.valid());
    ApprovalManager mgr{pool};
    REQUIRE(mgr.is_open());

    auto forged = mgr.submit("mcp.quarantine_device", "attacker", "{}", "",
                             ApprovalOrigin::kInstruction);
    REQUIRE(forged.has_value());
    REQUIRE(mgr.approve(*forged, "admin1", "").has_value());

    // A second raw connection holds an ACCESS EXCLUSIVE table lock, so the
    // pooled connection's read inside consume_ticket's origin+submitter
    // binding check blocks and times out deterministically at 100ms.
    pg::PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(locker.get(),
                            "LOCK TABLE approval_manager.approvals IN ACCESS EXCLUSIVE MODE",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    auto faulted = mgr.consume_ticket(*forged, "attacker", {});
    REQUIRE(!faulted.has_value());
    CHECK(faulted.error().kind == ConsumeFailure::kStoreError);
    CHECK(faulted.error().sqlstate == "55P03");
    CHECK(faulted.error().binding_check_unevaluated);
    CHECK(!yuzu::server::is_permanent_pg_error(faulted.error().sqlstate));
    // Cannot check "untouched" here: `locker` still holds the exclusive lock,
    // so a read would fault identically to the write above. Checked below,
    // once the lock releases.

    REQUIRE(pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    locker.reset();

    // Untouched: the fault must not have burned the ticket.
    CHECK(mgr.get(*forged)->consumed_at == 0);

    // Once the fault clears, the forgery signal is NOT lost: the same ticket
    // now correctly reports kForeignOrigin, not a repeat of kStoreError.
    auto cleared = mgr.consume_ticket(*forged, "attacker", {});
    REQUIRE(!cleared.has_value());
    CHECK(cleared.error().kind == ConsumeFailure::kForeignOrigin);
    CHECK(!cleared.error().binding_check_unevaluated);
    CHECK(mgr.get(*forged)->consumed_at == 0);
}

TEST_CASE("ApprovalManager: a CAS-step fault after a passing binding check does NOT flag "
          "the binding as unevaluated",
          "[pg][approval_manager][approval][security]") {
    // Negative control: binding_check_unevaluated must be scoped to the
    // origin+submitter binding check's own read, not to "consume_ticket
    // failed for any store reason". A fault that hits only the consuming
    // UPDATE, after the binding check already passed, must not trip the
    // masked-denial signal. Ported to Postgres (ADR-0065) via a real
    // BEFORE UPDATE trigger — the direct analogue of the SQLite
    // `RAISE(ABORT, ...)` trigger this replaces, and unlike the two chaos
    // tests above, works regardless of which connection issues the UPDATE
    // (a trigger fires for every writer, not just one blocked on a lock).
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    {
        // PQexecParams (what pg::exec_params wraps) accepts exactly ONE SQL
        // command per call, unlike PQexec — two statements each.
        auto lease = mgr_bundle.pool().acquire();
        REQUIRE(lease);
        pg::PgResult fn = pg::exec_params(
            lease.get(),
            "CREATE OR REPLACE FUNCTION approval_manager.block_update() RETURNS trigger AS $$ "
            "BEGIN RAISE EXCEPTION 'fault injected'; END; $$ LANGUAGE plpgsql",
            std::vector<std::string>{});
        REQUIRE(fn.status() == PGRES_COMMAND_OK);
        pg::PgResult trig = pg::exec_params(
            lease.get(),
            "CREATE TRIGGER approvals_block_update BEFORE UPDATE ON approval_manager.approvals "
            "FOR EACH ROW EXECUTE FUNCTION approval_manager.block_update()",
            std::vector<std::string>{});
        REQUIRE(trig.status() == PGRES_COMMAND_OK);
    }

    auto faulted = mgr.consume_ticket(*id, "operator1", {});
    REQUIRE(!faulted.has_value());
    CHECK(faulted.error().kind == ConsumeFailure::kStoreError);
    CHECK(!faulted.error().sqlstate.empty());
    CHECK(faulted.error().sqlstate == "P0001"); // plpgsql RAISE EXCEPTION
    CHECK(!faulted.error().binding_check_unevaluated); // binding check passed before the CAS ran
    CHECK(mgr.get(*id)->consumed_at == 0);
}

// ── approval_store_error_body (#2786) ───────────────────────────────────────
// The branch these pin had ZERO coverage in either direction: a governance
// reviewer deleted it wholesale once and no assertion moved, which is how a
// permanent failure shipped telling the caller to "retry this call unchanged"
// forever, with an audit row written per attempt.

namespace {
// #2880 review F1 (fjarvis/Codex/Kimi panel, reproduced on GCC): the concept
// used to declare its operand as non-const `A4Error a4_error`, but
// `approval_store_error_body` invokes it through `const A4Error&`. A
// mutable-only callable satisfied the concept and then failed deep inside
// template instantiation - exactly the failure mode the concept exists to
// avoid at the declaration instead. Pin both directions: a const-callable
// type still satisfies the concept, and a mutable-only-call-operator type
// does not.
struct ConstCallableProbe {
    std::string operator()(int, std::string_view, std::string_view, long = -1,
                           std::string_view = {}) const {
        return "body";
    }
};
static_assert(yuzu::server::mcp::ApprovalA4Error<ConstCallableProbe>);

struct MutableOnlyProbe {
    std::string operator()(int, std::string_view, std::string_view, long = -1,
                           std::string_view = {}) {
        return "body";
    }
};
static_assert(!yuzu::server::mcp::ApprovalA4Error<MutableOnlyProbe>);
} // namespace

TEST_CASE("approval_store_error_body: a permanent failure is not described as temporary",
          "[approval_manager][approval][security]") {
    // A store that never opened, ported to Postgres (ADR-0065): an
    // unreachable port fails construction's own connect attempt
    // deterministically (test_engine_principal_store.cpp's #2456 precedent)
    // — no live database needed, so this test carries no [pg] tag.
    pg::PgPool unreachable{{.conninfo = "host=127.0.0.1 port=1 dbname=yuzu connect_timeout=1",
                            .size = 1,
                            .connect_timeout_s = 1}};
    REQUIRE(unreachable.valid()); // conninfo parses; the host is just unreachable
    ApprovalManager closed(unreachable);
    REQUIRE(!closed.is_open());

    int seen_code = 0;
    std::string seen_message, seen_remediation;
    long seen_retry = -7; // sentinel distinct from the production default (-1)
    auto probe = [&](int code, std::string_view message, std::string_view remediation = {},
                     long retry_after_ms = -1, std::string_view = {}) {
        seen_code = code;
        seen_message = std::string(message);
        seen_remediation = std::string(remediation);
        seen_retry = retry_after_ms;
        return std::string("body");
    };

    (void)yuzu::server::mcp::approval_store_error_body(closed, probe, /*sqlstate=*/"");

    CHECK(seen_code == yuzu::server::mcp::kInternalError);
    CHECK(seen_message.find("temporarily") == std::string::npos);
    CHECK(seen_remediation.find("retry this call unchanged") == std::string::npos);
    // -1 is the production a4_error default, which the caller's envelope
    // serialises as JSON `null` (present in the body, not a missing key) -
    // this file's encoding for "not retryable". A concrete value here is an
    // instruction to loop on a condition that never clears.
    CHECK(seen_retry == -1);
}

TEST_CASE("approval_store_error_body: an OPEN store failing permanently is also not "
          "described as temporary",
          "[pg][approval_manager][approval][security]") {
    // ADR-0065 port of #2786 "PR 1c": the store handle itself is fine, but a
    // read against it is failing in a way an unchanged retry cannot clear.
    // Same permanent body as a never-opened store — see
    // mcp_approval_error.hpp's discriminator.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& open = *mgr_bundle;
    REQUIRE(open.is_open());

    int seen_code = 0;
    std::string seen_message, seen_remediation;
    long seen_retry = -7;
    auto probe = [&](int code, std::string_view message, std::string_view remediation = {},
                     long retry_after_ms = -1, std::string_view = {}) {
        seen_code = code;
        seen_message = std::string(message);
        seen_remediation = std::string(remediation);
        seen_retry = retry_after_ms;
        return std::string("body");
    };

    (void)yuzu::server::mcp::approval_store_error_body(open, probe, "42P01");

    CHECK(seen_code == yuzu::server::mcp::kInternalError);
    CHECK(seen_message.find("temporarily") == std::string::npos);
    CHECK(seen_remediation.find("retry this call unchanged") == std::string::npos);
    CHECK(seen_retry == -1);
}

TEST_CASE("approval_store_error_body: a transient failure carries a machine-readable retry",
          "[pg][approval_manager][approval][security]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& open = *mgr_bundle;
    REQUIRE(open.is_open());

    std::string seen_message, seen_remediation;
    long seen_retry = -1;
    auto probe = [&](int, std::string_view message, std::string_view remediation = {},
                     long retry_after_ms = -1, std::string_view = {}) {
        seen_message = std::string(message);
        seen_remediation = std::string(remediation);
        seen_retry = retry_after_ms;
        return std::string("body");
    };

    (void)yuzu::server::mcp::approval_store_error_body(open, probe, /*sqlstate=*/"");

    CHECK(seen_message.find("temporarily") != std::string::npos);
    CHECK(seen_remediation.find("do NOT request a fresh one") != std::string::npos);
    // Invariant A5: the retry directive must be machine metadata, not prose.
    // Pinned EXACT, not `> 0`: a mutant that swaps 5000 for any other
    // positive constant must still be caught (QA-3).
    CHECK(seen_retry == 5000);
}

TEST_CASE("approval_store_error_body: a genuinely transient sqlstate still gets the "
          "retryable arm",
          "[pg][approval_manager][approval][security]") {
    // Negative control for the ADR-0065 port of the #2786 "PR 1c" classifier:
    // a lock-contention SQLSTATE must NOT be swept into the permanent arm
    // alongside the schema-drift/corruption/disk-full/read-only classes.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& open = *mgr_bundle;
    REQUIRE(open.is_open());

    std::string seen_message, seen_remediation;
    long seen_retry = -1;
    auto probe = [&](int, std::string_view message, std::string_view remediation = {},
                     long retry_after_ms = -1, std::string_view = {}) {
        seen_message = std::string(message);
        seen_remediation = std::string(remediation);
        seen_retry = retry_after_ms;
        return std::string("body");
    };

    (void)yuzu::server::mcp::approval_store_error_body(open, probe, "55P03");

    CHECK(seen_message.find("temporarily") != std::string::npos);
    CHECK(seen_retry == 5000);
}

// ── query_checked / pending_count_checked (#2146 A2-R4) ────────────────────
// query()/pending_count() collapse three degraded conditions -- store not
// open, pool-lease timeout, query failure -- into the SAME empty vector / 0
// a genuinely empty store returns. These checked twins must distinguish
// them, mirroring get_checked's own established shape in this class.

TEST_CASE("ApprovalManager: query_checked and pending_count_checked fail closed "
          "when the store never opened",
          "[pg][approval_manager][approval]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);

    // Force a migration failure the same way test_schedule_engine.cpp's
    // sibling "not open" test does: pre-seed the store's schema with a
    // conflicting table so PgMigrationRunner cannot apply approval_manager's
    // v1 DDL, leaving is_open() false.
    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult s{PQexec(conn.get(), "CREATE SCHEMA approval_manager")};
        REQUIRE(s.ok());
        pg::PgResult t{PQexec(conn.get(), "CREATE TABLE approval_manager.bogus (x int)")};
        REQUIRE(t.ok());
    }

    pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ApprovalManager mgr{pool};
    CHECK_FALSE(mgr.is_open());

    // The pre-existing unchecked methods collapse this into empty/0 -- pinned
    // here only as the CONTRAST the checked twins below exist to fix.
    CHECK(mgr.query().empty());
    CHECK(mgr.pending_count() == 0);

    auto list_checked = mgr.query_checked();
    REQUIRE_FALSE(list_checked.has_value());
    CHECK(list_checked.error().message.find("not open") != std::string::npos);

    auto count_checked = mgr.pending_count_checked();
    REQUIRE_FALSE(count_checked.has_value());
    CHECK(count_checked.error().message.find("not open") != std::string::npos);
}

TEST_CASE("ApprovalManager: query_checked and pending_count_checked report a genuine "
          "query failure, not a false empty result",
          "[pg][approval_manager][approval]") {
    // Same technique as "a store failure during the recheck is not reported
    // as spent" above: drop the table out from under an OPEN store so the
    // next query genuinely fails (PGRES_TUPLES_OK check fails), distinct
    // from the "never migrated" (!open_) case pinned above.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;
    REQUIRE(mgr.is_open());

    {
        auto lease = mgr_bundle.pool().acquire();
        REQUIRE(lease);
        pg::PgResult res =
            pg::exec_params(lease.get(), "DROP TABLE approval_manager.approvals",
                            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto list_checked = mgr.query_checked();
    REQUIRE_FALSE(list_checked.has_value());
    CHECK(list_checked.error().message.find("read failed") != std::string::npos);
    CHECK(!list_checked.error().sqlstate.empty());

    auto count_checked = mgr.pending_count_checked();
    REQUIRE_FALSE(count_checked.has_value());
    CHECK(count_checked.error().message.find("read failed") != std::string::npos);
    CHECK(!count_checked.error().sqlstate.empty());
}

TEST_CASE("ApprovalManager: query_checked happy path matches query()'s fields",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    auto id = mgr.submit("def-checked", "operator1", "scope-1", "", ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());

    auto list_checked = mgr.query_checked();
    REQUIRE(list_checked.has_value());
    REQUIRE(list_checked->approvals.size() == 1);
    CHECK(list_checked->approvals[0].id == *id);
    CHECK(list_checked->approvals[0].definition_id == "def-checked");
    CHECK_FALSE(list_checked->truncated);

    auto count_checked = mgr.pending_count_checked();
    REQUIRE(count_checked.has_value());
    CHECK(*count_checked == 1);
}

TEST_CASE("ApprovalManager: query_checked at exactly the list cap is not misreported "
          "as truncated (#2146 A2-R4 boundary)",
          "[pg][approval_manager][approval]") {
    // Mirrors ScheduleEngine::query_schedules_checked's identical boundary
    // test (test_schedule_engine.cpp) -- the query-one-past-the-cap
    // technique must not false-positive when the true count is EXACTLY the
    // cap. seed_pending bypasses submit()'s own 1000-row cap so this stays a
    // fast bulk INSERT.
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    seed_pending(mgr_bundle.pool(), "cap-", 100, /*age_seconds=*/60);

    auto list_checked = mgr.query_checked();
    REQUIRE(list_checked.has_value());
    CHECK(list_checked->approvals.size() == 100);
    CHECK_FALSE(list_checked->truncated);
}

TEST_CASE("ApprovalManager: query_checked truncates and flags a queue one over "
          "the list cap (#2146 A2-R4 boundary)",
          "[pg][approval_manager][approval]") {
    yuzu::test::ApprovalManagerPg mgr_bundle;
    ApprovalManager& mgr = *mgr_bundle;

    seed_pending(mgr_bundle.pool(), "cap-", 101, /*age_seconds=*/60);

    auto list_checked = mgr.query_checked();
    REQUIRE(list_checked.has_value());
    CHECK(list_checked->approvals.size() == 100);
    CHECK(list_checked->truncated);
}
