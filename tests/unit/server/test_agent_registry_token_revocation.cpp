/**
 * test_agent_registry_token_revocation.cpp — W1.5 / #823, corrected by #3401.
 *
 * AgentRegistry::register_agent MUST revoke any device tokens bound to a
 * re-registering agent_id. Without this, an attacker who briefly
 * impersonated the agent (mTLS-disabled flow, #779) keeps replay access to
 * every token bound to that identity, because the prior tokens stay
 * `revoked = false` in `device_auth_tokens`.
 *
 * #3401: the sweep is keyed on `device_id` (`revoke_by_device`), the column
 * `validate_token` actually binds the presenter against — NOT `principal_id`
 * (`revoke_by_principal`), which is the issuing OPERATOR's username on every
 * production issuance path. Fixtures below therefore use distinct operator
 * and device identifiers (`create_token(name, "<operator>", "<agent_id>",
 * ...)`) rather than the pre-#3401 shape where principal_id == device_id ==
 * agent_id — that shape cannot distinguish a correct device-keyed sweep from
 * the pre-#3401 bug (both "pass" against it).
 *
 * register_agent also now fails CLOSED (ADR-0012 §1): a genuine revoke
 * failure refuses the registration rather than installing a session the
 * sweep could not clear stale tokens for (#3401 Gap 2, closes #3419's
 * previously-untested error-log branch).
 *
 * Scope of this file: the wiring contract between AgentRegistry and
 * DeviceTokenStore. Pure store behaviour (idempotency, empty-device-id
 * guard, cross-operator/cross-device isolation) lives in
 * `test_device_token_store.cpp`.
 */

#include "agent_registry.hpp"
#include "device_token_store.hpp"
#include "event_bus.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include "agent.pb.h"

#include <libpq-fe.h>

#include <stdexcept>
#include <string>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
// `pb` is already bound to `::yuzu::agent::v1` by agent_registry.hpp inside
// `namespace yuzu::server::detail`. We can't use a file-scope alias of the
// same name without "redefinition of 'pb'"; use `agent_pb` here instead.
namespace agent_pb = ::yuzu::agent::v1;

namespace {

agent_pb::AgentInfo make_info(const std::string& id, const std::string& host = "host.local") {
    agent_pb::AgentInfo info;
    info.set_agent_id(id);
    info.set_hostname(host);
    return info;
}

// Shares the "devicetokenstore" key with test_device_token_store.cpp's,
// test_rest_api_t2.cpp's, and test_rest_api_tokens.cpp's own templates
// (identical setup, replay-verified per docs/postgres-store-playbook.md
// step 7).
yuzu::test::PgTestTemplate device_token_store_tpl{
    "devicetokenstore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        DeviceTokenStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("device_token_store template: store failed to migrate");
    }};

} // namespace

TEST_CASE("AgentRegistry: re-registering an agent revokes that agent's device tokens",
          "[agent_registry][823][3401][token_revocation][pg]") {
    // Threat model: attacker re-registers under endpoint-99 (mTLS-disabled
    // impersonation, #779). The token an operator (alice) issued for the
    // legitimate endpoint-99 must be revoked before the attacker's session
    // is live, so the attacker cannot replay the stolen token against any
    // device-token-authenticated REST endpoint. principal_id ("alice") is
    // deliberately NOT the agent_id — the production REST issuance shape
    // (rest_api_v1.cpp:8134) that the pre-#3401 fixture masked.
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore tokens(pool);
    REQUIRE(tokens.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.set_device_token_store(&tokens);

    // Legitimate endpoint-99 lifecycle: register, then operator issues a
    // device-bound token, then validate succeeds.
    REQUIRE(registry.register_agent(make_info("endpoint-99")).has_value());
    auto raw = tokens.create_token("legit", "alice", "endpoint-99", "", 0);
    REQUIRE(raw.has_value());
    REQUIRE(tokens.validate_token(*raw, "endpoint-99").has_value());

    // Attacker re-registers as endpoint-99. Per the W1.5/#3401 wiring, every
    // device token bound to that agent_id must be revoked before the new
    // session is installed.
    REQUIRE(registry.register_agent(make_info("endpoint-99", "attacker.local")).has_value());

    auto reval = tokens.validate_token(*raw, "endpoint-99");
    REQUIRE(!reval.has_value());
    CHECK(reval.error().error == DeviceTokenValidateError::revoked);
    CHECK(reval.error().bound_principal_id == "alice");
    CHECK(reval.error().bound_device_id == "endpoint-99");
}

TEST_CASE("AgentRegistry: first-time registration does NOT revoke pre-issued tokens",
          "[agent_registry][823][3401][token_revocation][pg]") {
    // Operator workflow: pre-issue a device-bound token for an agent_id
    // that has not registered yet (legitimate enrollment automation). The
    // first-ever register_agent for that id must leave the pre-issued
    // token alone — only re-registration is the attack surface #823 closes.
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore tokens(pool);
    REQUIRE(tokens.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.set_device_token_store(&tokens);

    auto raw = tokens.create_token("preissued", "alice", "endpoint-7", "", 0);
    REQUIRE(raw.has_value());

    // No prior register — this is the first time the registry sees endpoint-7.
    REQUIRE(registry.register_agent(make_info("endpoint-7")).has_value());

    // The pre-issued token must survive: validate still succeeds.
    REQUIRE(tokens.validate_token(*raw, "endpoint-7").has_value());
}

TEST_CASE("AgentRegistry: re-registering one device revokes only that device's tokens — "
          "same operator, two devices (discriminates a device-keyed sweep from a "
          "principal-keyed one)",
          "[agent_registry][823][3401][token_revocation][pg]") {
    // The case a principal-keyed sweep cannot express correctly: BOTH tokens
    // below share principal_id="alice" (one operator issuing tokens for two
    // of her devices). A sweep keyed on principal_id would revoke both (or,
    // pre-#3401, revoke neither — since it was actually called with an
    // agent_id, which never equals "alice"). Only a device-keyed sweep gets
    // this right: re-registering endpoint-A must revoke ONLY endpoint-A's
    // token, leaving endpoint-B's token (same operator) untouched.
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore tokens(pool);
    REQUIRE(tokens.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.set_device_token_store(&tokens);

    REQUIRE(registry.register_agent(make_info("endpoint-A")).has_value());
    REQUIRE(registry.register_agent(make_info("endpoint-B")).has_value());
    auto tok_a = tokens.create_token("a", "alice", "endpoint-A", "", 0);
    auto tok_b = tokens.create_token("b", "alice", "endpoint-B", "", 0);
    REQUIRE(tok_a.has_value());
    REQUIRE(tok_b.has_value());

    // Re-register endpoint-A. endpoint-B's token — same operator, different
    // device — must not be touched.
    REQUIRE(registry.register_agent(make_info("endpoint-A")).has_value());

    auto a_after = tokens.validate_token(*tok_a, "endpoint-A");
    REQUIRE(!a_after.has_value());
    CHECK(a_after.error().error == DeviceTokenValidateError::revoked);

    REQUIRE(tokens.validate_token(*tok_b, "endpoint-B").has_value());
}

TEST_CASE("AgentRegistry: register_agent without a DeviceTokenStore wired is safe",
          "[agent_registry][823][3401][token_revocation]") {
    // Defensive default: if `set_device_token_store` was never called (the
    // current production path — server.cpp doesn't yet construct a
    // DeviceTokenStore), register_agent must behave exactly as before:
    // no crash, no revoke, always succeeds. The W1.5 wiring exists so the
    // invariant is in place the moment production wires the store up.
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);

    REQUIRE(registry.register_agent(make_info("endpoint-X")).has_value());
    REQUIRE(registry.register_agent(make_info("endpoint-X")).has_value()); // re-register — must not crash
    CHECK(registry.agent_count() == 1);
}

// #3401 Gap 2: fail-closed on a genuine revoke failure. Mirrors
// test_rest_api_tokens.cpp's "answer 503, never leaking the raw Postgres
// error" schema-drop technique (itself precedented from PR #3174) — the
// established way to force a genuine store-level failure in this test
// harness without a fault-injection seam.
TEST_CASE("AgentRegistry: register_agent refuses the registration when the device-token "
          "revoke sweep itself fails, and leaves the prior session untouched",
          "[agent_registry][823][3401][token_revocation][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore tokens(pool);
    REQUIRE(tokens.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.set_device_token_store(&tokens);

    yuzu::Labels refused_labels{{"reason", "device_token_revoke_failed"}};
    REQUIRE(metrics.counter("yuzu_agents_registration_refused_total", refused_labels).value() ==
           0.0);

    // First-time registration — establishes the prior session that must
    // survive the refused re-registration below.
    REQUIRE(registry.register_agent(make_info("endpoint-99", "legit.local")).has_value());
    CHECK(registry.agent_count() == 1);

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{
            PQexec(conn.get(), "DROP SCHEMA device_token_store CASCADE")};
        REQUIRE(r.ok());
    }

    // Re-registration now hits a genuine store failure on the revoke sweep —
    // must be REFUSED, not installed.
    auto refused = registry.register_agent(make_info("endpoint-99", "attacker.local"));
    REQUIRE(!refused.has_value());

    // The prior (legitimate) session must still be the one on record.
    CHECK(registry.agent_count() == 1);

    // #3419: the refusal branch is now behaviorally observable, not just logged — pin it via the
    // Prometheus counter rather than a log-line scrape.
    CHECK(metrics.counter("yuzu_agents_registration_refused_total", refused_labels).value() ==
         1.0);
}

// Gate 5 CH-1a: verifies the phase-2 supersede check. Splitting the revoke off mu_ (this same
// diff) opened a window the OLD single-locked implementation didn't have: a second
// register_agent for the SAME agent_id can now run to completion — including mapping a live
// stream — while a first, slower call's revoke is still in flight. Without the pointer-identity
// check, the slower call's phase 2 would then overwrite the map with a fresh, unmapped session,
// silently orphaning the live stream (dispatch would reach nothing). Uses the deterministic
// interleave hook rather than real threads — the property under test is "what does phase 2 do
// when the entry changed under it", not "can we reproduce OS scheduling", and a real race would
// make this test flaky for no additional coverage.
TEST_CASE("AgentRegistry: register_agent detects a concurrent registration that already won "
          "and yields instead of orphaning its live session (Gate 5 CH-1a)",
          "[agent_registry][823][3401][token_revocation][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore tokens(pool);
    REQUIRE(tokens.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.set_device_token_store(&tokens);

    SECTION("a newer registration already installed a session -> superseded, yield") {
        // Establishes prior_exists=true for the slow call below.
        REQUIRE(registry.register_agent(make_info("endpoint-99", "original.local")).has_value());

        std::string winner_session_id;
        registry.set_register_agent_interleave_hook_for_test([&] {
            // Runs synchronously inside the SLOW call, after its revoke, before its phase 2 —
            // exactly the window a genuinely concurrent registration would land in.
            REQUIRE(registry.register_agent(make_info("endpoint-99", "winner.local")).has_value());
            winner_session_id = "winner-stream-session";
            registry.map_session(winner_session_id, "endpoint-99"); // simulates Subscribe
        });

        auto slow_result = registry.register_agent(make_info("endpoint-99", "slow.local"));
        REQUIRE(!slow_result.has_value());

        // The winner's session — live stream mapped — must still be the one on record.
        CHECK(registry.agent_count() == 1);
        auto current = registry.get_session("endpoint-99");
        REQUIRE(current != nullptr);
        CHECK(current->hostname == "winner.local");
        CHECK(current->session_id == winner_session_id);
        // Dispatch (find_by_session) must still reach the winner's live stream.
        auto by_session = registry.find_by_session(winner_session_id);
        REQUIRE(by_session != nullptr);
        CHECK(by_session->hostname == "winner.local");

        // Discriminable from a revoke failure — its own reason label, not conflated.
        yuzu::Labels superseded_labels{{"reason", "superseded_by_concurrent_registration"}};
        CHECK(metrics.counter("yuzu_agents_registration_refused_total", superseded_labels)
                  .value() == 1.0);
        yuzu::Labels revoke_failed_labels{{"reason", "device_token_revoke_failed"}};
        CHECK(metrics.counter("yuzu_agents_registration_refused_total", revoke_failed_labels)
                  .value() == 0.0);
    }

    SECTION("the prior entry was instead REMOVED (disconnect) -> not superseded, installs") {
        REQUIRE(registry.register_agent(make_info("endpoint-99", "original.local")).has_value());

        // gov Gate 8 (quality-engineer): without this flag, every assertion below is
        // indistinguishable from the hook silently never firing at all (a dead hook also leaves
        // agents_ unchanged since phase 1, so phase 2 would see it as unchanged and install
        // normally regardless) — pin that the hook actually ran, not just the end state.
        bool hook_fired = false;
        registry.set_register_agent_interleave_hook_for_test([&] {
            hook_fired = true;
            // A concurrent disconnect tears the entry down entirely — nothing live to protect.
            registry.remove_agent("endpoint-99");
        });

        auto result = registry.register_agent(make_info("endpoint-99", "reconnect.local"));
        REQUIRE(hook_fired);
        REQUIRE(result.has_value());
        CHECK(registry.agent_count() == 1);
        auto current = registry.get_session("endpoint-99");
        REQUIRE(current != nullptr);
        CHECK(current->hostname == "reconnect.local");

        yuzu::Labels superseded_labels{{"reason", "superseded_by_concurrent_registration"}};
        CHECK(metrics.counter("yuzu_agents_registration_refused_total", superseded_labels)
                  .value() == 0.0);
    }
}
