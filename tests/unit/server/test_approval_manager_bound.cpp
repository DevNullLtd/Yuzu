/**
 * test_approval_manager_bound.cpp -- the bound-approval primitive (#6062, four-eyes
 * MVP PR2): migration v2 columns and old-row compatibility; origin-declared consume
 * (origin mismatch, kUnspecified/kUnrecognised, the caller-held-connection overload);
 * submit_bound's frozen request/digest/excluded roots and its refusals; approve()'s
 * excluded-root refusal; and the precondition-denial counter + audit observer.
 *
 * Every TEST_CASE here needs Postgres and SKIPs silently without
 * YUZU_TEST_POSTGRES_DSN (see test_approval_manager_pg_helper.hpp).
 */

#include "approval_denial_audit.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "reserved_definition_id.hpp"
#include "sha256_hex.hpp"
#include "test_approval_manager_pg_helper.hpp"
#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <yuzu/metrics.hpp>

#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

// Direct SQL on a leased connection. The caller REQUIREs the status it expects.
pg::PgResult run_sql(pg::PgPool& pool, const std::string& sql,
                     const std::vector<std::string>& params = {}) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    return pg::exec_params(lease.get(), sql.c_str(), params);
}

} // namespace

// -- Migration v2 / old-row compatibility -------------------------------------

TEST_CASE("ApprovalManager bound: a row minted before migration v2 survives it and reads "
          "as binding nothing",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    auto& pool = bundle.pool();

    // Rewind the live schema to its v1 shape: drop the three v2 columns and reset
    // the recorded version, then mint an "old" row with only the v1 columns.
    REQUIRE(run_sql(pool,
                    "ALTER TABLE approval_manager.approvals DROP COLUMN request_json, "
                    "DROP COLUMN request_digest, DROP COLUMN excluded_roots")
                .status() == PGRES_COMMAND_OK);
    REQUIRE(run_sql(pool, "UPDATE public.schema_meta SET version = 1 WHERE store = "
                          "'approval_manager'")
                .status() == PGRES_COMMAND_OK);
    REQUIRE(run_sql(pool,
                    "INSERT INTO approval_manager.approvals (id, definition_id, status, "
                    "submitted_by, submitted_at, reviewed_by, reviewed_at, scope_expression, "
                    "origin) VALUES ('old-row','mcp.tool','approved','alice',1,'bob',"
                    "extract(epoch from now())::bigint,'{}','mcp')")
                .status() == PGRES_COMMAND_OK);

    // A fresh manager re-runs the ladder: v2 applies to a POPULATED table.
    ApprovalManager upgraded{pool};
    REQUIRE(upgraded.is_open());

    auto old = upgraded.get("old-row");
    REQUIRE(old.has_value());
    CHECK(old->request_json.empty());
    CHECK(old->request_digest.empty());
    CHECK(old->excluded_roots.empty());
    CHECK_FALSE(old->excluded_roots_unreadable);

    // ...and it is still redeemable through the normal MCP path.
    auto consumed = upgraded.consume_ticket("old-row", "alice", ApprovalOrigin::kMcp, {});
    CHECK(consumed.has_value());
}

// -- Reserved definition-id namespaces ----------------------------------------

TEST_CASE("reserved definition ids: guardian. is reserved beside mcp., with its own message",
          "[approval_manager][bound][reserved]") {
    CHECK(is_reserved_definition_id("mcp.quarantine_device"));
    CHECK(is_reserved_definition_id("guardian.deploy.rules"));
    CHECK(is_mcp_definition_id("mcp.x"));
    // A guardian id is reserved but is NOT an MCP tool call: the page keys its MCP
    // tag and its tool-name display off is_mcp_definition_id.
    CHECK_FALSE(is_mcp_definition_id("guardian.deploy.rules"));

    // Exact, case-sensitive prefix; the dot is part of it.
    CHECK_FALSE(is_reserved_definition_id("guardian"));
    CHECK_FALSE(is_reserved_definition_id("guardianx.y"));
    CHECK_FALSE(is_reserved_definition_id("Guardian.x"));
    CHECK_FALSE(is_reserved_definition_id("my.guardian.x"));
    CHECK(reserved_definition_id_error("plain").empty());

    // The #2442 SIEM token is unchanged; guardian has a distinct one.
    CHECK(reserved_definition_id_error("mcp.x") == kReservedDefinitionIdError);
    CHECK(reserved_definition_id_error("guardian.x") == kReservedGuardianDefinitionIdError);
    CHECK(kReservedGuardianDefinitionIdError != kReservedDefinitionIdError);
}

// -- Origin-declared consume --------------------------------------------------

namespace {

// Mint an approved ticket on `origin` (submitted by alice, approved by bob).
std::string approved_ticket(ApprovalManager& mgr, ApprovalOrigin origin,
                            const std::string& def = "def-1") {
    auto id = mgr.submit(def, "alice", "scope", "", origin);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "bob", "").has_value());
    return *id;
}

} // namespace

TEST_CASE("consume_ticket: kUnspecified / kUnrecognised as the declared surface ALWAYS refuse",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    for (const auto declared : {ApprovalOrigin::kUnspecified, ApprovalOrigin::kUnrecognised}) {
        auto r = mgr.consume_ticket(id, "alice", declared, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kForeignOrigin);
        // Same uniform wording as every other refusal: no oracle on WHY.
        CHECK(r.error().message == kNotConsumableMessage);
    }
    // The refusals touched nothing: the rightful surface still redeems it.
    REQUIRE(mgr.get(id).has_value());
    CHECK(mgr.get(id)->consumed_at == 0);
    CHECK(mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, {}).has_value());
}

TEST_CASE("consume_ticket: a ticket redeems only on the surface that minted it",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    for (const auto declared : {ApprovalOrigin::kInstruction, ApprovalOrigin::kSchedule,
                                ApprovalOrigin::kGuardianDeploy}) {
        auto r = mgr.consume_ticket(id, "alice", declared, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kForeignOrigin);
    }
    CHECK(mgr.get(id)->consumed_at == 0);
    CHECK(mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, {}).has_value());

    // And the other direction: an instruction-origin ticket is not an MCP ticket.
    const auto inst = approved_ticket(mgr, ApprovalOrigin::kInstruction, "def-2");
    auto cross = mgr.consume_ticket(inst, "alice", ApprovalOrigin::kMcp, {});
    REQUIRE_FALSE(cross.has_value());
    CHECK(cross.error().kind == ConsumeFailure::kForeignOrigin);
    CHECK(mgr.consume_ticket(inst, "alice", ApprovalOrigin::kInstruction, {}).has_value());
}

TEST_CASE("consume_ticket: a stored kUnspecified / kUnrecognised origin refuses whoever asks",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    // A row minted with no declared surface ('') and one written by a "newer binary".
    for (const char* stored : {"", "some_future_surface"}) {
        const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp, std::string("def-") + stored);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET origin = $1 WHERE id = $2",
                        {stored, id})
                    .status() == PGRES_COMMAND_OK);
        for (const auto declared : {ApprovalOrigin::kMcp, ApprovalOrigin::kInstruction,
                                    ApprovalOrigin::kGuardianDeploy}) {
            auto r = mgr.consume_ticket(id, "alice", declared, {});
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error().kind == ConsumeFailure::kForeignOrigin);
        }
    }
}

// -- Caller-held-connection overload ------------------------------------------

namespace {
// Run `body(conn)` inside BEGIN ... then ROLLBACK or COMMIT.
template <typename F>
void in_txn(pg::PgPool& pool, bool commit, F&& body) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    REQUIRE(pg::exec_params(lease.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    body(lease.get());
    REQUIRE(pg::exec_params(lease.get(), commit ? "COMMIT" : "ROLLBACK",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
}
} // namespace

TEST_CASE("consume_ticket(PGconn*): the caller's rollback rolls the consume back; commit keeps it",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    in_txn(bundle.pool(), /*commit=*/false, [&](PGconn* conn) {
        auto r = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kMcp, {});
        CHECK(r.has_value());
    });
    // Rolled back: the one-time capability is NOT spent.
    REQUIRE(mgr.get(id).has_value());
    CHECK(mgr.get(id)->consumed_at == 0);
    CHECK(mgr.get(id)->consumed_by.empty());

    in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
        CHECK(mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kMcp, {}).has_value());
    });
    CHECK(mgr.get(id)->consumed_at != 0);
    CHECK(mgr.get(id)->consumed_by == "alice");

    // Spent for good: a replay (pooled or held) loses.
    auto replay = mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, {});
    REQUIRE_FALSE(replay.has_value());
    CHECK(replay.error().kind == ConsumeFailure::kNotConsumable);
}

TEST_CASE("consume_ticket(PGconn*): refusals leave the caller's transaction healthy and the row "
          "untouched",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
        // Wrong surface, no surface, wrong principal, failed precondition.
        auto foreign = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kGuardianDeploy, {});
        REQUIRE_FALSE(foreign.has_value());
        CHECK(foreign.error().kind == ConsumeFailure::kForeignOrigin);
        auto none = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kUnspecified, {});
        REQUIRE_FALSE(none.has_value());
        CHECK(none.error().kind == ConsumeFailure::kForeignOrigin);
        auto other = mgr.consume_ticket(conn, id, "mallory", ApprovalOrigin::kMcp, {});
        REQUIRE_FALSE(other.has_value());
        CHECK(other.error().kind == ConsumeFailure::kForeignSubmitter);
        auto pre = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kMcp,
                                      [](const Approval&) -> std::expected<void, std::string> {
                                          return std::unexpected("state moved");
                                      });
        REQUIRE_FALSE(pre.has_value());
        CHECK(pre.error().kind == ConsumeFailure::kPrecondition);

        // None of that aborted the transaction: it can still run SQL and consume.
        CHECK(pg::exec_params(conn, "SELECT 1", std::vector<std::string>{}).status() ==
              PGRES_TUPLES_OK);
        CHECK(mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kMcp, {}).has_value());
    });
    CHECK(mgr.get(id)->consumed_at != 0);
}

TEST_CASE("consume_ticket(PGconn*): a null connection is refused, never an autocommit consume",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    auto r = mgr.consume_ticket(static_cast<PGconn*>(nullptr), id, "alice", ApprovalOrigin::kMcp, {});
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kStoreError);
    CHECK(mgr.get(id)->consumed_at == 0);
}

TEST_CASE("consume_ticket(PGconn*): the row lock is held to the caller's end of transaction",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    auto holder = bundle.pool().acquire();
    auto other = bundle.pool().acquire();
    REQUIRE(holder);
    REQUIRE(other);
    REQUIRE(pg::exec_params(holder.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(mgr.consume_ticket(holder.get(), id, "alice", ApprovalOrigin::kMcp, {}).has_value());
    // A second connection cannot take the row while the first transaction is open.
    auto probe = pg::exec_params(other.get(),
                                 "SELECT 1 FROM approval_manager.approvals WHERE id = $1 "
                                 "FOR UPDATE NOWAIT",
                                 std::vector<std::string>{id});
    CHECK(probe.status() == PGRES_FATAL_ERROR); // 55P03 lock_not_available
    REQUIRE(pg::exec_params(holder.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
}

// -- submit_bound: the frozen request, digest and excluded roots -------------------

namespace {

const char* const kRequest =
    R"({"definition":{"name":"Block RDP","hash":"abc123"},"params":{"port":3389},"targets":["host-1"]})";

BoundRequest bound_request(std::vector<std::string> excluded = {}) {
    return BoundRequest{kRequest, std::move(excluded)};
}

} // namespace

TEST_CASE("submit_bound: freezes request_json, its digest and the excluded roots on the row",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;

    auto id = mgr.submit_bound("guardian.deploy.r1", "alice", "scope", "",
                               ApprovalOrigin::kGuardianDeploy,
                               bound_request({"carol", "dave"}));
    REQUIRE(id.has_value());

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->origin == ApprovalOrigin::kGuardianDeploy);
    CHECK(row->request_json == kRequest);
    REQUIRE(sha256_hex(kRequest).has_value());
    CHECK(row->request_digest == *sha256_hex(kRequest));
    CHECK(row->request_digest.size() == 64);
    CHECK(row->excluded_roots == std::vector<std::string>{"carol", "dave"});
    CHECK_FALSE(row->excluded_roots_unreadable);

    // Frozen: review and consumption never touch the three columns.
    REQUIRE(mgr.approve(*id, "bob", "").has_value());
    REQUIRE(mgr.consume_ticket(*id, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
    auto after = mgr.get(*id);
    CHECK(after->request_json == row->request_json);
    CHECK(after->request_digest == row->request_digest);
    CHECK(after->excluded_roots == row->excluded_roots);
}

TEST_CASE("submit_bound: the same bytes always digest the same; different bytes differ",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    auto a = mgr.submit_bound("guardian.a", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                              BoundRequest{R"({"k":1})", {}});
    auto b = mgr.submit_bound("guardian.b", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                              BoundRequest{R"({"k":1})", {}});
    auto c = mgr.submit_bound("guardian.c", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                              BoundRequest{R"({"k":2})", {}});
    REQUIRE((a && b && c));
    CHECK(mgr.get(*a)->request_digest == mgr.get(*b)->request_digest);
    CHECK(mgr.get(*a)->request_digest != mgr.get(*c)->request_digest);
}

TEST_CASE("submit_bound: a bound ticket redeems only on its declared surface",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    auto id = mgr.submit_bound("guardian.deploy.r1", "alice", "", "",
                               ApprovalOrigin::kGuardianDeploy, bound_request());
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "bob", "").has_value());

    auto as_mcp = mgr.consume_ticket(*id, "alice", ApprovalOrigin::kMcp, {});
    REQUIRE_FALSE(as_mcp.has_value());
    CHECK(as_mcp.error().kind == ConsumeFailure::kForeignOrigin);
    CHECK(mgr.consume_ticket(*id, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
}

TEST_CASE("submit: an origin that requires a bound request cannot be minted unbound",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    CHECK(requires_bound_request(ApprovalOrigin::kGuardianDeploy));
    CHECK_FALSE(requires_bound_request(ApprovalOrigin::kMcp));

    auto r = mgr.submit("guardian.deploy.r1", "alice", "", "", ApprovalOrigin::kGuardianDeploy);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == kBoundRequestRequiredMessage);
    CHECK(mgr.pending_count() == 0);
}

TEST_CASE("submit_bound: an engine principal cannot submit a gated effect (typed refusal)",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;

    for (const char* engine : {"engine:vuln", "engine:x"}) {
        auto r = mgr.submit_bound("guardian.deploy.r1", engine, "", "",
                                  ApprovalOrigin::kGuardianDeploy, bound_request());
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == SubmitFailure::kEnginePrincipal);
        CHECK(r.error().message == kEnginePrincipalSubmitMessage);
    }
    CHECK(mgr.pending_count() == 0); // nothing written

    // A human whose name merely CONTAINS the word is not an engine principal.
    auto human = mgr.submit_bound("guardian.deploy.r1", "engineer:ann", "", "",
                                  ApprovalOrigin::kGuardianDeploy, bound_request());
    CHECK(human.has_value());
}

TEST_CASE("submit_bound: malformed requests and undeclared origins are refused, nothing written",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto refused = [&](BoundRequest b, ApprovalOrigin origin = ApprovalOrigin::kGuardianDeploy) {
        auto r = mgr.submit_bound("guardian.d", "alice", "", "", origin, std::move(b));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == SubmitFailure::kInvalidRequest);
    };

    refused(BoundRequest{"", {}});                                    // empty
    refused(BoundRequest{"not json", {}});                            // not JSON
    refused(BoundRequest{"[1,2]", {}});                               // not an object
    refused(BoundRequest{"\"str\"", {}});                             // not an object
    refused(BoundRequest{std::string(R"({"k":")") + std::string(kMaxRequestJsonBytes, 'a') + "\"}", {}});
    {   // nested one level past the limit
        std::string deep = R"({"k":)";
        for (std::size_t i = 0; i < kMaxRequestJsonDepth; ++i) deep += "[";
        deep += "1";
        for (std::size_t i = 0; i < kMaxRequestJsonDepth; ++i) deep += "]";
        deep += "}";
        refused(BoundRequest{deep, {}});
    }
    refused(BoundRequest{R"({"k":1})", {""}});                        // empty root
    refused(BoundRequest{R"({"k":1})", {std::string(kMaxExcludedRootBytes + 1, 'r')}});
    refused(BoundRequest{R"({"k":1})", std::vector<std::string>(kMaxExcludedRoots + 1, "r")});
    refused(BoundRequest{R"({"k":1})", {std::string("bad\xff\xfe")}});  // invalid UTF-8
    refused(bound_request(), ApprovalOrigin::kUnspecified);
    refused(bound_request(), ApprovalOrigin::kUnrecognised);
    CHECK(mgr.pending_count() == 0);

    // Exactly at the bounds is accepted (depth: object -> limit-1 arrays -> scalar).
    {
        std::string ok = R"({"k":)";
        for (std::size_t i = 0; i + 1 < kMaxRequestJsonDepth; ++i) ok += "[";
        ok += "1";
        for (std::size_t i = 0; i + 1 < kMaxRequestJsonDepth; ++i) ok += "]";
        ok += "}";
        CHECK(mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                               BoundRequest{ok, {}})
                  .has_value());
    }
    CHECK(mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                           BoundRequest{R"({"k":1})",
                                        std::vector<std::string>(kMaxExcludedRoots, "r")})
              .has_value());
}

TEST_CASE("submit_bound: a NUL byte in request_json or a control character in a root is "
          "refused, nothing written",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto refused = [&](BoundRequest b) {
        auto r = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy, b);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == SubmitFailure::kInvalidRequest);
    };

    // The parser reads a NUL after a complete value as end of input, so this PARSES as
    // {"k":1}; the digest would cover all 8 bytes while the column keeps 7.
    refused(BoundRequest{std::string(R"({"k":1})") + '\0' + "tail", {}});
    refused(BoundRequest{std::string(R"({"k":1})") + '\0', {}});
    refused(BoundRequest{std::string("\0", 1) + R"({"k":1})", {}});
    // A raw NUL inside a string literal is not valid JSON either; still refused.
    refused(BoundRequest{std::string("{\"k\":\"a") + '\0' + "b\"}", {}});
    // A control character or NUL inside an excluded root.
    refused(BoundRequest{R"({"k":1})", {std::string("car") + '\0' + "ol"}});
    refused(BoundRequest{R"({"k":1})", {"car\nol"}});
    refused(BoundRequest{R"({"k":1})", {"car\x7f"}});
    refused(BoundRequest{R"({"k":1})", {"ok", "tab\there"}});
    CHECK(mgr.pending_count() == 0);

    // Still-valid inputs are unchanged: an ESCAPED NUL (the six characters \u0000) is
    // ordinary text, and a root with punctuation or non-ASCII UTF-8 is fine.
    auto escaped = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                                    BoundRequest{R"({"k":"a\u0000b"})", {"oidc:carol@example.org",
                                                                          "d\xC3\xA9j\xC3\xA0"}});
    REQUIRE(escaped.has_value());
    auto row = mgr.get(*escaped);
    REQUIRE(row.has_value());
    CHECK(row->request_json == R"({"k":"a\u0000b"})");
    CHECK(row->request_digest == *sha256_hex(row->request_json));
    CHECK(row->excluded_roots.size() == 2);
}

TEST_CASE("submit_bound: the pending cap refuses with the typed queue-full kind",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    yuzu::test::seed_pending(bundle.pool(), "cap-", ApprovalManager::kMaxPendingApprovals,
                             /*age_seconds=*/60);
    auto r = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                              bound_request());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == SubmitFailure::kQueueFull);
}

// -- approve(): excluded roots -------------------------------------------------

TEST_CASE("approve: a reviewer in excluded_roots is refused; others are not",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    auto id = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                               bound_request({"carol", "dave"}));
    REQUIRE(id.has_value());

    for (const char* barred : {"carol", "dave"}) {
        auto r = mgr.approve(*id, barred, "");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == kExcludedReviewerMessage);
    }
    // The submitter stays barred by the original rule.
    auto self = mgr.approve(*id, "alice", "");
    REQUIRE_FALSE(self.has_value());
    CHECK(self.error() == "reviewer cannot be the same as the submitter");
    CHECK(mgr.get(*id)->status == "pending");

    // Byte-for-byte: a case variant is a different account, so it is not excluded.
    // (It would be if the compare folded case; see same_human_root.)
    CHECK(mgr.approve(*id, "Carol", "").has_value());
}

TEST_CASE("reviewer_is_excluded: byte-for-byte membership, the one predicate approve() and the "
          "dashboard share",
          "[approval_manager][bound]") {
    const std::vector<std::string> roots{"carol", "oidc:dave"};
    CHECK(reviewer_is_excluded("carol", roots));
    CHECK(reviewer_is_excluded("oidc:dave", roots));
    CHECK_FALSE(reviewer_is_excluded("Carol", roots)); // case-sensitive: a different account
    CHECK_FALSE(reviewer_is_excluded("dave", roots));
    CHECK_FALSE(reviewer_is_excluded("carol ", roots));
    CHECK_FALSE(reviewer_is_excluded("carol", {}));
    CHECK_FALSE(reviewer_is_excluded("", roots));
}

TEST_CASE("reject: an excluded root may still reject", "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    auto id = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                               bound_request({"carol"}));
    REQUIRE(id.has_value());
    CHECK(mgr.reject(*id, "carol", "withdrawn").has_value());
    CHECK(mgr.get(*id)->status == "rejected");
}

TEST_CASE("approve: an unreadable excluded_roots column fails CLOSED", "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    for (const char* garbage : {"not json", R"({"a":1})", R"(["ok", 3])"}) {
        auto id = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                                   bound_request({"carol"}));
        REQUIRE(id.has_value());
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET excluded_roots = $1 WHERE id = $2",
                        {garbage, *id})
                    .status() == PGRES_COMMAND_OK);
        auto row = mgr.get(*id);
        REQUIRE(row.has_value());
        CHECK(row->excluded_roots_unreadable);

        auto r = mgr.approve(*id, "bob", "");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == kExcludedRootsUnreadableMessage);
        CHECK(mgr.get(*id)->status == "pending");
        // Rejecting is still possible: it grants nothing.
        CHECK(mgr.reject(*id, "bob", "").has_value());
    }
}

TEST_CASE("approve: a bound request that cannot be read or verified is refused; reject still works",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const std::string deep(kMaxRequestJsonDepth + 2, '[');
    const std::vector<std::pair<std::string, std::string>> edits = {
        {"request_json", "not json"},
        {"request_json", "[1,2]"},
        {"request_json", R"({"k":2})"},                                  // digest now stale
        {"request_json", std::string(R"({"k":)") + deep + std::string(deep.size(), ']') + "}"},
        {"request_digest", std::string(64, '0')},
        {"request_digest", ""},
    };
    for (const auto& [column, value] : edits) {
        auto id = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                                   bound_request());
        REQUIRE(id.has_value());
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET " + column + " = $1 WHERE id = $2",
                        {value, *id})
                    .status() == PGRES_COMMAND_OK);
        auto r = mgr.approve(*id, "bob", "");
        INFO(column << " = " << value.substr(0, 40));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == kBoundRequestUnreadableMessage);
        CHECK(mgr.get(*id)->status == "pending");
        CHECK(mgr.reject(*id, "bob", "").has_value()); // the way to clear it from the queue
    }
    // And an untouched bound ticket still approves.
    auto ok = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                               bound_request());
    REQUIRE(ok.has_value());
    CHECK(mgr.approve(*ok, "bob", "").has_value());
}

TEST_CASE("approve: an unbound ticket is unaffected by the exclusion machinery",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    auto id = mgr.submit("def", "alice", "", "", ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());
    CHECK(mgr.approve(*id, "carol", "").has_value());
}

// -- consume: the stored approval is re-checked, not trusted --------------------

namespace {

// An approved, unconsumed bound ticket (alice -> bob) excluding carol.
std::string approved_bound(ApprovalManager& mgr, const std::string& def = "guardian.d") {
    auto id = mgr.submit_bound(def, "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                               bound_request({"carol"}));
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "bob", "").has_value());
    return *id;
}

// Both overloads must refuse with the same kind and message and leave the row unspent.
void check_refused_on_both_overloads(yuzu::test::ApprovalManagerPg& bundle, const std::string& id) {
    ApprovalManager& mgr = *bundle;
    auto pooled = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {});
    REQUIRE_FALSE(pooled.has_value());
    CHECK(pooled.error().kind == ConsumeFailure::kForeignOrigin);
    CHECK(pooled.error().message == kNotConsumableMessage); // uniform: no oracle
    in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
        auto held = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kGuardianDeploy, {});
        REQUIRE_FALSE(held.has_value());
        CHECK(held.error().kind == ConsumeFailure::kForeignOrigin);
        CHECK(held.error().message == kNotConsumableMessage);
        // A refusal that is not a store error leaves the caller's transaction healthy.
        CHECK(pg::exec_params(conn, "SELECT 1", std::vector<std::string>{}).status() ==
              PGRES_TUPLES_OK);
    });
    CHECK(mgr.get(id)->consumed_at == 0);
}

} // namespace

TEST_CASE("consume: a sound bound ticket still redeems on both overloads",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto pooled = approved_bound(mgr, "guardian.p");
    CHECK(mgr.consume_ticket(pooled, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
    const auto held = approved_bound(mgr, "guardian.h");
    in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
        CHECK(mgr.consume_ticket(conn, held, "alice", ApprovalOrigin::kGuardianDeploy, {})
                  .has_value());
    });
    CHECK(mgr.get(held)->consumed_at != 0);
}

TEST_CASE("consume: a ticket whose stored reviewer is an excluded root or the submitter is "
          "refused, whoever reviewed it",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    for (const char* forced : {"carol", "alice"}) {
        // A row approved by something that did not run approve()'s checks: forced by SQL.
        const auto id = approved_bound(mgr, std::string("guardian.") + forced);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET reviewed_by = $1 WHERE id = $2",
                        {forced, id})
                    .status() == PGRES_COMMAND_OK);
        check_refused_on_both_overloads(bundle, id);
    }
}

TEST_CASE("consume: an unreadable excluded_roots column on an approved ticket refuses",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    const auto id = approved_bound(*bundle);
    REQUIRE(run_sql(bundle.pool(),
                    "UPDATE approval_manager.approvals SET excluded_roots = 'not json' "
                    "WHERE id = $1",
                    {id})
                .status() == PGRES_COMMAND_OK);
    check_refused_on_both_overloads(bundle, id);
}

TEST_CASE("consume: a request_json that no longer hashes to request_digest refuses",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    SECTION("tampered digest") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET request_digest = repeat('0', 64) "
                        "WHERE id = $1",
                        {id})
                    .status() == PGRES_COMMAND_OK);
        check_refused_on_both_overloads(bundle, id);
    }
    SECTION("tampered request") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET request_json = '{\"k\":2}' "
                        "WHERE id = $1",
                        {id})
                    .status() == PGRES_COMMAND_OK);
        check_refused_on_both_overloads(bundle, id);
    }
    SECTION("digest cleared while the request stays") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET request_digest = '' WHERE id = $1",
                        {id})
                    .status() == PGRES_COMMAND_OK);
        check_refused_on_both_overloads(bundle, id);
    }
    SECTION("a digest with no request behind it") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET request_json = '' WHERE id = $1",
                        {id})
                    .status() == PGRES_COMMAND_OK);
        check_refused_on_both_overloads(bundle, id);
    }
}

TEST_CASE("consume: a legacy row (no request, no digest, no roots) is not re-checked into "
          "a refusal",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto pooled = approved_ticket(mgr, ApprovalOrigin::kMcp, "def-pooled");
    CHECK(mgr.consume_ticket(pooled, "alice", ApprovalOrigin::kMcp, {}).has_value());
    const auto held = approved_ticket(mgr, ApprovalOrigin::kMcp, "def-held");
    in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
        CHECK(mgr.consume_ticket(conn, held, "alice", ApprovalOrigin::kMcp, {}).has_value());
    });
}

TEST_CASE("consume: a replay of a SPENT ticket whose row was later tampered still reads as "
          "an ordinary replay",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_bound(mgr);
    REQUIRE(mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
    REQUIRE(run_sql(bundle.pool(),
                    "UPDATE approval_manager.approvals SET request_digest = repeat('0', 64) "
                    "WHERE id = $1",
                    {id})
                .status() == PGRES_COMMAND_OK);
    auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {});
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kNotConsumable);
}

// -- kPrecondition denial: counted and observed at the store --------------------

namespace {
const ConsumePrecondition kDeny = [](const Approval&) -> std::expected<void, std::string> {
    return std::unexpected("state moved");
};
} // namespace

TEST_CASE("a precondition denial is counted per origin and reported to the observer, for every "
          "origin and both overloads",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    yuzu::MetricsRegistry reg;
    std::vector<PreconditionDenial> seen;
    mgr.set_metrics(&reg);
    mgr.set_precondition_denial_observer(
        [&](const PreconditionDenial& d) { seen.push_back(d); });

    const auto count = [&](const char* origin) {
        return reg.counter("yuzu_approval_precondition_denied_total", {{"origin", origin}})
            .value();
    };

    const auto mcp = approved_ticket(mgr, ApprovalOrigin::kMcp, "def-m");
    auto d1 = mgr.consume_ticket(mcp, "alice", ApprovalOrigin::kMcp, kDeny);
    REQUIRE_FALSE(d1.has_value());
    CHECK(d1.error().kind == ConsumeFailure::kPrecondition);
    CHECK(count("mcp") == 1);
    CHECK(count("guardian_deploy") == 0);
    REQUIRE(seen.size() == 1);
    CHECK(seen[0].approval_id == mcp);
    CHECK(seen[0].origin == ApprovalOrigin::kMcp);
    CHECK(seen[0].consumed_by == "alice");
    CHECK(seen[0].reason == "state moved");

    auto g = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                              bound_request());
    REQUIRE(g.has_value());
    REQUIRE(mgr.approve(*g, "bob", "").has_value());
    in_txn(bundle.pool(), /*commit=*/false, [&](PGconn* conn) {
        auto d2 = mgr.consume_ticket(conn, *g, "alice", ApprovalOrigin::kGuardianDeploy, kDeny);
        REQUIRE_FALSE(d2.has_value());
        CHECK(d2.error().kind == ConsumeFailure::kPrecondition);
    });
    CHECK(count("guardian_deploy") == 1);
    REQUIRE(seen.size() == 2);
    CHECK(seen[1].origin == ApprovalOrigin::kGuardianDeploy);

    // Neither denial consumed anything.
    CHECK(mgr.get(mcp)->consumed_at == 0);
    CHECK(mgr.get(*g)->consumed_at == 0);
}

TEST_CASE("only a precondition denial is counted: other refusals and successes are not",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    yuzu::MetricsRegistry reg;
    int observed = 0;
    mgr.set_metrics(&reg);
    mgr.set_precondition_denial_observer([&](const PreconditionDenial&) { ++observed; });

    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);
    CHECK_FALSE(mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, kDeny).has_value());
    CHECK_FALSE(mgr.consume_ticket(id, "mallory", ApprovalOrigin::kMcp, kDeny).has_value());
    CHECK_FALSE(mgr.consume_ticket(id, "alice", ApprovalOrigin::kUnspecified, kDeny).has_value());
    CHECK(mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, {}).has_value());
    // Spent: the precondition does not even run on a replay.
    CHECK_FALSE(mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, kDeny).has_value());

    CHECK(observed == 0);
    CHECK(reg.counter("yuzu_approval_precondition_denied_total", {{"origin", "mcp"}}).value() == 0);
}

TEST_CASE("a throwing denial observer never escapes consume_ticket and the denial stands",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    yuzu::MetricsRegistry reg;
    mgr.set_metrics(&reg);
    mgr.set_precondition_denial_observer(
        [](const PreconditionDenial&) { throw std::runtime_error("audit store down"); });

    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);
    auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, kDeny);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kPrecondition);
    CHECK(reg.counter("yuzu_approval_precondition_denied_total", {{"origin", "mcp"}}).value() == 1);
    CHECK(mgr.get(id)->consumed_at == 0);
}

TEST_CASE("a precondition denial works with no metrics and no observer installed",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);
    auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, kDeny);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kPrecondition);
}

TEST_CASE("a precondition denial writes an approval.precondition_denied audit row that survives "
          "the redeemer's rollback",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    AuditStore audit{bundle.pool()};
    REQUIRE(audit.is_open());
    mgr.set_precondition_denial_observer(
        make_precondition_denial_audit_observer([&audit]() -> AuditStore* { return &audit; }));

    auto g = mgr.submit_bound("guardian.secret-def", "alice", "secret-scope", "",
                              ApprovalOrigin::kGuardianDeploy, bound_request());
    REQUIRE(g.has_value());
    REQUIRE(mgr.approve(*g, "bob", "").has_value());

    // The denial happens inside a caller transaction that is then ROLLED BACK.
    in_txn(bundle.pool(), /*commit=*/false, [&](PGconn* conn) {
        auto r = mgr.consume_ticket(conn, *g, "alice", ApprovalOrigin::kGuardianDeploy, kDeny);
        REQUIRE_FALSE(r.has_value());
    });

    auto rows = audit.query(AuditQuery{.action = kApprovalPreconditionDeniedAction});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    const auto& ev = (*rows)[0];
    CHECK(ev.principal == "alice");
    CHECK(ev.result == "denied");
    CHECK(ev.target_type == "approval");
    CHECK(ev.target_id == *g);
    CHECK(ev.detail.find("origin=guardian_deploy") != std::string::npos);
    CHECK(ev.detail.find("reason=state moved") != std::string::npos);
    // Caller-supplied ticket text never reaches the audit detail.
    CHECK(ev.detail.find("secret-def") == std::string::npos);
    CHECK(ev.detail.find("secret-scope") == std::string::npos);
}

TEST_CASE("the denial audit observer tolerates an absent or closed audit store",
          "[approval_manager][bound]") {
    // No Postgres needed: the provider yields nullptr, so the observer returns quietly.
    auto obs = make_precondition_denial_audit_observer([]() -> AuditStore* { return nullptr; });
    REQUIRE(obs);
    CHECK_NOTHROW(obs(PreconditionDenial{"id", ApprovalOrigin::kMcp, "alice", "why"}));
    auto none = make_precondition_denial_audit_observer({});
    CHECK_NOTHROW(none(PreconditionDenial{"id", ApprovalOrigin::kMcp, "alice", "why"}));
}
