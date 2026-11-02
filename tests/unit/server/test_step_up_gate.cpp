/**
 * test_step_up_gate.cpp - the MFA step-up decide/render split and the request chokepoint
 * (server/core/src/step_up_gate.{hpp,cpp}).
 *
 * Two layers:
 *
 *   [stepup][gate]        PURE. The MFA store is injected through `MfaStatusFn`, so every branch
 *                         of `decide_step_up`, the renderer and `apply_step_up_chokepoint` runs
 *                         without Postgres.
 *   [pg][mfa][stepup]     The equivalence matrix: for every (identity source x enforcement mode x
 *                         proof state) cell, `decide_step_up` and the historical
 *                         `require_mfa_step_up` entry point agree with each other AND with a
 *                         hand-written table of the status each cell produces, against a real
 *                         AuthDB (the engine_token cell is the one deliberate change from the
 *                         pre-chokepoint gate: it was a 401, it is now a 403 engine denial).
 *                         test_mfa_step_up.cpp (unchanged) pins the wire shape.
 */

#include "../../../server/core/src/step_up_gate.hpp"
#include "../../../server/core/src/step_up_wiring.hpp"
#include "../../../server/core/src/step_up_policy.hpp"
#include "../../../server/core/src/totp.hpp"

#include "auth_routes.hpp"
#include "oidc_provider.hpp"
#include "session_store.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_approver_route_fixture.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/server.hpp>

#include "../test_log_capture.hpp"
#include "test_auth_db_pg_helper.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <expected>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;
using namespace std::chrono_literals;

namespace {

struct AuditRow {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

// A chokepoint refusal's audit detail ends ` cid=<correlation id> stage=pre_authz`. The id differs
// per call, so exact-string assertions compare the detail with the cid token removed and a
// dedicated case ties the id to the response's X-Correlation-Id.
std::string cid_of(const std::string& detail) {
    const auto pos = detail.find(" cid=");
    REQUIRE(pos != std::string::npos);
    const auto end = detail.find(' ', pos + 1);
    return detail.substr(pos + 5, end == std::string::npos ? end : end - pos - 5);
}
std::string without_cid(std::string detail) {
    const auto pos = detail.find(" cid=");
    REQUIRE(pos != std::string::npos);
    const auto end = detail.find(' ', pos + 1);
    REQUIRE(end != std::string::npos); // ` stage=pre_authz` follows, so cid is never the last token
    detail.erase(pos, end - pos);
    return detail;
}

constexpr std::string_view kTokensPattern = "/api/v1/tokens";
constexpr std::string_view kTokensLabel = "POST /api/v1/tokens";

std::chrono::system_clock::time_point ago(std::chrono::seconds s) {
    return std::chrono::system_clock::now() - s;
}

// Populates the session through derive_session_deadlines, exactly as the sibling
// test_mfa_step_up.cpp does: the gate ages the proof against the monotonic anchor.
auth::Session make_session(const std::string& user, const std::string& source, Role role,
                           std::chrono::system_clock::time_point verified_at = {}) {
    auth::Session s;
    s.username = user;
    s.role = role;
    s.auth_source = source;
    const std::int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
    const std::int64_t verified_ms =
        verified_at.time_since_epoch().count() == 0
            ? 0
            : std::chrono::duration_cast<std::chrono::milliseconds>(verified_at.time_since_epoch())
                  .count();
    AuthManager::derive_session_deadlines(s, now, now + 3600'000, now, verified_ms,
                                          /*elevated_until*/ 0, /*issued*/ 0, now);
    return s;
}

MfaStatusFn status_enrolled(std::int64_t factor_gen = 1) {
    return [factor_gen](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        AuthDB::MfaStatus st;
        st.enrolled = true;
        st.factor_gen = factor_gen;
        return st;
    };
}
MfaStatusFn status_not_enrolled() {
    return [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        return AuthDB::MfaStatus{};
    };
}
MfaStatusFn status_error(AuthDBError e) {
    return [e](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        return std::unexpected(e);
    };
}

// The synthetic database clock every stored proof below is read against.
constexpr std::int64_t kDbNowMs = 4'000'000'000'000;

// A stored proof that agrees with `session`'s cached anchor: bound to `gen` and aged the same on
// the synthetic database clock. A session with no cached proof has a stored row with none either.
auth::DurableMfaProof durable_matching(const auth::Session& s, std::int64_t gen = 1) {
    auth::DurableMfaProof d;
    d.source = auth::DurableMfaProof::Source::kRow;
    d.db_now_ms = kDbNowMs;
    if (s.steady_mfa_verified.time_since_epoch().count() != 0) {
        const auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - s.steady_mfa_verified)
                                .count();
        d.mfa_verified_ms = kDbNowMs - age_ms;
        d.mfa_factor_gen = gen;
    }
    return d;
}

// decide_step_up over a provider that agrees with the session's own proof (see above): the shape
// the pre-binding tests were written against, so they keep asserting the cached-age behaviour.
StepUpVerdict decide_matching(const auth::Session& s, const MfaStatusFn& status, int window,
                              std::string_view mode, StepUpClass cls = StepUpClass::kRequired,
                              StepUpAdmission* admitted = nullptr) {
    const DurableProofReadFn read = [&s] {
        return durable_matching(s);
    };
    return decide_step_up(s, status, read, window, mode, cls, admitted);
}

// A wired chokepoint over an injected MFA store and a fixed session.
struct Rig {
    std::optional<auth::Session> session;
    MfaStatusFn mfa_status = status_enrolled();
    bool wire_store = true;
    bool wire_resolver = true;
    bool resolver_throws = false;
    int window_secs = 300;
    std::string enforcement = "optional";
    std::vector<AuditRow> audits;
    yuzu::MetricsRegistry metrics;
    // Empty means the seam is not wired, as in production.
    std::function<void(StepUpFaultPoint)> fault_hook;
    // The stored-proof read: by default a bound proof that agrees with the resolved session's own
    // cached anchor. `wire_durable = false` leaves the provider null, as an unwired server.
    bool wire_durable = true;
    DurableProofFn durable = [](const httplib::Request&, const auth::Session& s) {
        return durable_matching(s);
    };

    // The pass stash is a thread_local shared by every test on this thread. A Rig clears it on the
    // way in and on the way out, so a test that fails (or throws) between arming and consuming
    // cannot leak a stash into the next test, and a test never starts on another's leftovers.
    // A test that needs a stash to SURVIVE a Rig (arming one "as a previous request would have
    // left it") must keep that Rig alive for the duration, not scope it in a block.
    Rig() { detail::clear_step_up_pass(); }
    ~Rig() { detail::clear_step_up_pass(); }
    Rig(const Rig&) = delete;
    Rig& operator=(const Rig&) = delete;

    StepUpSessionFn resolver = [this](const httplib::Request&) -> std::optional<auth::Session> {
        if (resolver_throws)
            throw std::runtime_error("resolver failure");
        return session;
    };
    StepUpAuditFn audit = [this](const httplib::Request&, const std::string& a,
                                 const std::string& r, const std::string& tt, const std::string& ti,
                                 const std::string& d) -> bool {
        audits.push_back({a, r, tt, ti, d});
        return true;
    };

    StepUpChokepointDeps deps() {
        return StepUpChokepointDeps{.resolve_session = wire_resolver ? &resolver : nullptr,
                                    .auth_db = nullptr,
                                    .mfa_status = wire_store ? &mfa_status : nullptr,
                                    .durable_proof = wire_durable ? &durable : nullptr,
                                    .audit_fn = &audit,
                                    .metrics = &metrics,
                                    .window_secs = window_secs,
                                    .mfa_enforcement = enforcement,
                                    .fault_hook = fault_hook ? &fault_hook : nullptr};
    }

    double gate_count(std::string_view outcome, std::string_view source, std::string_view surface) {
        return metrics
            .counter("yuzu_auth_mfa_step_up_gate_total", {{"outcome", std::string(outcome)},
                                                          {"source", std::string(source)},
                                                          {"surface", std::string(surface)}})
            .value();
    }
};

httplib::Request make_request(std::string method, std::string_view pattern, std::string path) {
    httplib::Request req;
    req.method = std::move(method);
    req.matched_route = std::string(pattern);
    req.path = std::move(path);
    return req;
}

nlohmann::json body_of(const httplib::Response& res) {
    return nlohmann::json::parse(res.body);
}

} // namespace

// ── decide_step_up: the pure decision ────────────────────────────────────────

TEST_CASE("decide_step_up: window <= 0, bearer principals and un-enrolled users pass",
          "[stepup][gate]") {
    const auto stale = make_session("alice", "local", Role::admin, ago(1h));
    CHECK(decide_matching(stale, status_enrolled(), 0, "optional").passed());
    CHECK(decide_matching(stale, status_enrolled(), -1, "optional").passed());
    CHECK(decide_matching(make_session("t", "api_token", Role::admin), status_enrolled(), 300,
                          "optional")
              .passed());
    CHECK(decide_matching(make_session("t", "mcp_token", Role::admin), status_enrolled(), 300,
                          "optional")
              .passed());
    CHECK(decide_matching(make_session("bob", "local", Role::user), status_not_enrolled(), 300,
                          "optional")
              .passed());
}

TEST_CASE("decide_step_up: window <= 0 does not consult the store at all", "[stepup][gate]") {
    bool called = false;
    const MfaStatusFn probe =
        [&](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        called = true;
        return AuthDB::MfaStatus{};
    };
    CHECK(decide_matching(make_session("alice", "local", Role::admin), probe, 0, "optional")
              .passed());
    CHECK_FALSE(called);
}

TEST_CASE("decide_step_up: local enrolled session is judged on proof age", "[stepup][gate]") {
    SECTION("fresh proof passes") {
        CHECK(decide_matching(make_session("alice", "local", Role::admin, ago(10s)),
                              status_enrolled(), 300, "optional")
                  .passed());
    }
    SECTION("stale proof is a challenge carrying the age and window") {
        const auto v = decide_matching(make_session("alice", "local", Role::admin, ago(1h)),
                                       status_enrolled(), 300, "optional");
        CHECK(v.decision == StepUpDecision::kChallenge);
        CHECK_FALSE(v.is_oidc);
        CHECK(v.age_secs >= 3500);
        CHECK(v.window_secs == 300);
        CHECK(v.user == "alice");
    }
    SECTION("no proof at all is a challenge with age -1") {
        const auto v = decide_matching(make_session("alice", "local", Role::admin),
                                       status_enrolled(), 300, "optional");
        CHECK(v.decision == StepUpDecision::kChallenge);
        CHECK(v.age_secs == -1);
    }
}

TEST_CASE("decide_step_up: a proof older than the 24h ceiling never counts", "[stepup][gate]") {
    // window_secs is far above the ceiling; a 25 h old proof must still be refused.
    const auto v = decide_matching(make_session("alice", "local", Role::admin, ago(25h)),
                                   status_enrolled(), 7 * 24 * 3600, "optional");
    CHECK(v.decision == StepUpDecision::kChallenge);
}

TEST_CASE("decide_step_up: store failures fail closed and are told apart", "[stepup][gate]") {
    const auto s = make_session("alice", "local", Role::admin, ago(10s));
    for (const auto e : {AuthDBError::SecretUnavailable, AuthDBError::QueryFailed,
                         AuthDBError::WriteFailed, AuthDBError::StoreBusy}) {
        CHECK(decide_matching(s, status_error(e), 300, "optional").decision ==
              StepUpDecision::kStoreUnavailable);
    }
    // Not a store outage: a missing row and a name the store rejects before any read both fail
    // closed as a 401.
    for (const auto e : {AuthDBError::UserNotFound, AuthDBError::InvalidUsername}) {
        CHECK_FALSE(is_store_unavailable(e));
        CHECK(decide_matching(s, status_error(e), 300, "optional").decision ==
              StepUpDecision::kStatusFailed);
    }
}

TEST_CASE("decide_step_up: an engine principal is denied before any store read",
          "[stepup][gate]") {
    // Engines are operator-less non-interactive bearers: denied on every gated route whatever
    // grant they hold, in every mode and at every window (the operator hatch included), and
    // without touching the store.
    int store_reads = 0;
    const MfaStatusFn probe =
        [&](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        ++store_reads;
        return std::unexpected(AuthDBError::InvalidUsername);
    };
    for (const char* mode : {"optional", "admin-only", "required"}) {
        // The auth_source discriminator and the persisted principal_kind discriminator each
        // suffice on their own (the S1 two-predicate check).
        auto by_source = make_session("engine:x", "engine_token", Role::user);
        auto by_kind = make_session("engine:y", "other", Role::user);
        by_kind.principal_kind = "engine";
        for (const auto& session : {by_source, by_kind}) {
            for (const int window : {300, 0, -1}) {
                const auto v = decide_matching(session, probe, window, mode);
                CHECK(v.decision == StepUpDecision::kEngineDenied);
                CHECK_FALSE(v.passed());
                CHECK_FALSE(v.is_oidc);
                CHECK(v.user == session.username);
            }
        }
    }
    CHECK(store_reads == 0);
}

TEST_CASE("decide_step_up: SAML is an honest denial in every mode", "[stepup][gate]") {
    for (const char* mode : {"optional", "admin-only", "required"}) {
        const auto v = decide_matching(make_session("saml-user", "saml", Role::admin, ago(1s)),
                                       status_enrolled(), 300, mode);
        CHECK(v.decision == StepUpDecision::kSamlDenied);
    }
}

TEST_CASE("decide_step_up: OIDC never takes the local lookup", "[stepup][gate]") {
    bool called = false;
    const MfaStatusFn probe =
        [&](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        called = true;
        return AuthDB::MfaStatus{.enrolled = true};
    };
    CHECK(decide_matching(make_session("oidc:iss#sub", "oidc", Role::admin, ago(10s)), probe, 300,
                          "optional")
              .passed());
    CHECK_FALSE(called);
}

TEST_CASE("decide_step_up: OIDC amr-less session depends on enforcement and role",
          "[stepup][gate]") {
    const auto admin = make_session("oidc:iss#a", "oidc", Role::admin);
    const auto user = make_session("oidc:iss#u", "oidc", Role::user);
    CHECK(decide_matching(admin, status_enrolled(), 300, "optional").passed());
    CHECK(decide_matching(user, status_enrolled(), 300, "optional").passed());
    CHECK(decide_matching(admin, status_enrolled(), 300, "admin-only").decision ==
          StepUpDecision::kChallenge);
    CHECK(decide_matching(user, status_enrolled(), 300, "admin-only").passed());
    CHECK(decide_matching(admin, status_enrolled(), 300, "required").decision ==
          StepUpDecision::kChallenge);
    CHECK(decide_matching(user, status_enrolled(), 300, "required").decision ==
          StepUpDecision::kChallenge);
    const auto challenge = decide_matching(admin, status_enrolled(), 300, "required");
    CHECK(challenge.is_oidc);
}

TEST_CASE("decide_step_up: OIDC session with a seeded proof takes the freshness check in any mode",
          "[stepup][gate]") {
    for (const char* mode : {"optional", "admin-only", "required"}) {
        CHECK(decide_matching(make_session("oidc:iss#a", "oidc", Role::admin, ago(10s)),
                              status_enrolled(), 300, mode)
                  .passed());
        CHECK(decide_matching(make_session("oidc:iss#a", "oidc", Role::admin, ago(1h)),
                              status_enrolled(), 300, mode)
                  .decision == StepUpDecision::kChallenge);
    }
}

// ── decide_step_up: the factor binding of a local enrolled caller (#6079) ───────────────────────

namespace {

// A stored proof built field by field, for the cases that control each input.
auth::DurableMfaProof proof_row(std::int64_t verified_ms, std::int64_t db_now_ms,
                                std::int64_t gen) {
    return {auth::DurableMfaProof::Source::kRow, verified_ms, db_now_ms, gen};
}

// decide_step_up over a provider that returns `row` and counts its calls.
StepUpVerdict decide_with(const auth::Session& s, const MfaStatusFn& status,
                          const auth::DurableMfaProof& row, int& calls, int window,
                          StepUpClass cls = StepUpClass::kRequired,
                          StepUpAdmission* admitted = nullptr, std::string_view mode = "optional") {
    const DurableProofReadFn read = [&] {
        ++calls;
        return row;
    };
    return decide_step_up(s, status, read, window, mode, cls, admitted);
}

} // namespace

TEST_CASE("decide_step_up (binding): a bound fresh proof passes and records what it admitted",
          "[stepup][gate][binding]") {
    int calls = 0;
    StepUpAdmission admitted;
    const auto s = make_session("alice", "local", Role::admin, ago(10s));
    const auto v = decide_with(s, status_enrolled(7), durable_matching(s, 7), calls, 300,
                               StepUpClass::kRequired, &admitted);
    CHECK(v.passed());
    CHECK(v.reason.empty());
    CHECK(calls == 1);
    CHECK(admitted.local);
    CHECK(admitted.factor_gen == 7);
}

TEST_CASE("decide_step_up (binding): a refused proof names its cause", "[stepup][gate][binding]") {
    const auto s = make_session("alice", "local", Role::admin, ago(10s));
    const auto fresh = durable_matching(s, 4); // bound to generation 4, aged like the session
    StepUpAdmission admitted;

    SECTION("no generation on the stored proof: proof_factor_unbound") {
        int calls = 0;
        auto row = fresh;
        row.mfa_factor_gen = 0;
        const auto v =
            decide_with(s, status_enrolled(4), row, calls, 300, StepUpClass::kRequired, &admitted);
        CHECK(v.decision == StepUpDecision::kChallenge);
        CHECK(v.reason == "proof_factor_unbound");
        CHECK(v.age_secs >= 0); // the stored proof's own age is reported
        CHECK_FALSE(admitted.local);
    }
    SECTION("another generation, lower or higher: proof_factor_mismatch") {
        for (const std::int64_t current : {3, 5, 400}) {
            int calls = 0;
            const auto v = decide_with(s, status_enrolled(current), fresh, calls, 300);
            CHECK(v.decision == StepUpDecision::kChallenge);
            CHECK(v.reason == "proof_factor_mismatch");
            CHECK_FALSE(v.is_oidc);
        }
    }
    SECTION("an unreadable current generation is undecidable: a 503, not a re-prove loop") {
        for (const std::int64_t current : {0, -1}) {
            int calls = 0;
            const auto v = decide_with(s, status_enrolled(current), fresh, calls, 300);
            CHECK(v.decision == StepUpDecision::kStoreUnavailable);
            CHECK(v.reason == "mfa_proof_unavailable");
        }
    }
    SECTION("no stored session, or a stored row with no proof: mfa_proof_missing, age -1") {
        int calls = 0;
        auto v = decide_with(
            s, status_enrolled(4),
            auth::DurableMfaProof{.source = auth::DurableMfaProof::Source::kAbsent}, calls, 300);
        CHECK(v.decision == StepUpDecision::kChallenge);
        CHECK(v.reason == "mfa_proof_missing");
        CHECK(v.age_secs == -1);
        v = decide_with(s, status_enrolled(4), proof_row(0, kDbNowMs, 4), calls, 300);
        CHECK(v.decision == StepUpDecision::kChallenge);
        CHECK(v.reason == "mfa_proof_missing");
    }
}

TEST_CASE("decide_step_up (binding): an undecidable binding is a 503, never a challenge or a pass",
          "[stepup][gate][binding]") {
    const auto s = make_session("alice", "local", Role::admin, ago(10s));
    int calls = 0;

    SECTION("a degraded or absent durable read") {
        const auto v = decide_with(s, status_enrolled(4), auth::DurableMfaProof{}, calls, 300);
        CHECK(v.decision == StepUpDecision::kStoreUnavailable);
        CHECK(v.reason == "mfa_proof_unavailable");
    }
    SECTION("a row whose database clock is not positive") {
        const auto v = decide_with(s, status_enrolled(4), proof_row(1'000, 0, 4), calls, 300);
        CHECK(v.decision == StepUpDecision::kStoreUnavailable);
        CHECK(v.reason == "mfa_proof_unavailable");
    }
    SECTION("an unenforced generation trigger, bound or not") {
        const MfaStatusFn unenforced =
            [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            AuthDB::MfaStatus st;
            st.enrolled = true;
            st.factor_gen = 4;
            st.binding_enforced = false;
            return st;
        };
        for (const std::int64_t gen : {4, 0}) {
            const auto v = decide_with(s, unenforced, durable_matching(s, gen), calls, 300);
            CHECK(v.decision == StepUpDecision::kStoreUnavailable);
            CHECK(v.reason == "mfa_binding_unenforced");
        }
    }
    SECTION("no provider wired is the unwired 503, same as a missing store") {
        const auto v = decide_step_up(s, status_enrolled(4), DurableProofReadFn{}, 300, "optional",
                                      StepUpClass::kRequired);
        CHECK(v.decision == StepUpDecision::kUnwired);
        // ...but a caller that needs no durable read never notices the provider is missing.
        CHECK(decide_step_up(make_session("bob", "local", Role::user), status_not_enrolled(),
                             DurableProofReadFn{}, 300, "optional", StepUpClass::kRequired)
                  .passed());
        CHECK(decide_step_up(s, status_enrolled(4), DurableProofReadFn{}, 0, "optional",
                             StepUpClass::kRequired)
                  .passed());
        CHECK(decide_step_up(make_session("t", "api_token", Role::admin), status_enrolled(4),
                             DurableProofReadFn{}, 300, "optional", StepUpClass::kRequired)
                  .passed());
    }
}

TEST_CASE("decide_step_up (binding): only a local enrolled caller reads the stored proof",
          "[stepup][gate][binding]") {
    struct Row {
        const char* what;
        std::string source;
        std::string user;
        Role role;
        int window;
        MfaStatusFn status;
        int expect_calls;
    };
    const std::vector<Row> rows = {
        {"local enrolled", "local", "alice", Role::admin, 300, status_enrolled(1), 1},
        {"window 0 (the hatch)", "local", "alice", Role::admin, 0, status_enrolled(1), 0},
        {"negative window", "local", "alice", Role::admin, -1, status_enrolled(1), 0},
        {"local un-enrolled", "local", "bob", Role::user, 300, status_not_enrolled(), 0},
        {"api_token", "api_token", "t", Role::admin, 300, status_enrolled(1), 0},
        {"mcp_token", "mcp_token", "t", Role::admin, 300, status_enrolled(1), 0},
        {"saml", "saml", "saml-user", Role::admin, 300, status_enrolled(1), 0},
        {"oidc", "oidc", "oidc:i#a", Role::admin, 300, status_enrolled(1), 0},
        {"engine_token", "engine_token", "engine:x", Role::user, 300, status_enrolled(1), 0},
    };
    for (const auto& r : rows) {
        INFO(r.what);
        int calls = 0;
        const auto s = make_session(r.user, r.source, r.role, ago(10s));
        (void)decide_with(s, r.status, durable_matching(s, 1), calls, r.window);
        CHECK(calls == r.expect_calls);
    }
}

TEST_CASE("decide_step_up (binding): the durable age is a second, database-clock condition",
          "[stepup][gate][binding]") {
    // Cached anchor 10 s old (fresh), stored proof 400 s old on the database clock: the cached
    // anchor is suspend-blind, so the stored age decides.
    const auto s = make_session("alice", "local", Role::admin, ago(10s));
    int calls = 0;
    SECTION("cached fresh, durable stale: challenged, reporting the larger age") {
        const auto v = decide_with(s, status_enrolled(1),
                                   proof_row(kDbNowMs - 400'000, kDbNowMs, 1), calls, 300);
        CHECK(v.decision == StepUpDecision::kChallenge);
        CHECK(v.reason.empty()); // stale, not unbound or mismatched
        CHECK(v.age_secs >= 400);
        CHECK(v.window_secs == 300);
    }
    SECTION("cached stale, durable fresh: challenged (both clocks must agree)") {
        const auto old = make_session("alice", "local", Role::admin, ago(1h));
        const auto v = decide_with(old, status_enrolled(1),
                                   proof_row(kDbNowMs - 5'000, kDbNowMs, 1), calls, 300);
        CHECK(v.decision == StepUpDecision::kChallenge);
        CHECK(v.age_secs >= 3500);
    }
    SECTION("the window is inclusive to the millisecond on the database clock") {
        CHECK(decide_with(s, status_enrolled(1), proof_row(kDbNowMs - 300'000, kDbNowMs, 1), calls,
                          300)
                  .passed());
        CHECK(decide_with(s, status_enrolled(1), proof_row(kDbNowMs - 300'001, kDbNowMs, 1), calls,
                          300)
                  .decision == StepUpDecision::kChallenge);
    }
    SECTION("a future-dated stored proof is not fresh") {
        const auto v = decide_with(s, status_enrolled(1), proof_row(kDbNowMs + 60'000, kDbNowMs, 1),
                                   calls, 300);
        CHECK(v.decision == StepUpDecision::kChallenge);
    }
    SECTION("an OIDC session keeps the cached-only check: no stored proof is read") {
        const auto oidc = make_session("oidc:i#a", "oidc", Role::admin, ago(10s));
        // A stored row that would fail every durable condition changes nothing for OIDC.
        CHECK(
            decide_with(oidc, status_enrolled(1), proof_row(1, kDbNowMs, 0), calls, 300).passed());
        CHECK(calls == 0);
    }
}

// ── decide_step_up: the two factor-credential rows (#6079) ──────────────────────────────────────

TEST_CASE("decide_step_up (kFactorCredential): the window is the approver window and the hatch "
          "never applies",
          "[stepup][gate][binding][factor_credential]") {
    const auto bound = [](const auth::Session& s) {
        return durable_matching(s, 1);
    };
    constexpr auto kFc = StepUpClass::kFactorCredential;

    SECTION("window 0 reads the proof; a bound fresh session passes") {
        int calls = 0;
        const auto s = make_session("alice", "local", Role::admin, ago(10s));
        StepUpAdmission admitted;
        CHECK(decide_with(s, status_enrolled(1), bound(s), calls, 0, kFc, &admitted).passed());
        CHECK(calls == 1);
        CHECK(admitted.local);
        CHECK(admitted.factor_gen == 1);
    }
    SECTION("a survivor of a factor replacement is refused at window 0, -1 and the default") {
        const auto s = make_session("alice", "local", Role::admin, ago(10s));
        for (const int window : {0, -1, 300}) {
            int calls = 0;
            const auto v = decide_with(s, status_enrolled(3), bound(s), calls, window, kFc);
            CHECK(v.decision == StepUpDecision::kChallenge);
            CHECK(v.reason == "proof_factor_mismatch");
            CHECK(v.window_secs == 300);
        }
    }
    SECTION("a password-only session (no proof) is refused at window 0") {
        int calls = 0;
        const auto s = make_session("alice", "local", Role::admin);
        const auto v = decide_with(s, status_enrolled(1), bound(s), calls, 0, kFc);
        CHECK(v.decision == StepUpDecision::kChallenge);
        CHECK(v.reason == "mfa_proof_missing");
    }
    SECTION("an un-enrolled account passes at window 0 (cancelling a provisional enrolment) and "
            "the admission carries the generation as read") {
        int calls = 0;
        StepUpAdmission admitted;
        const MfaStatusFn never_enrolled =
            [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            AuthDB::MfaStatus st;
            st.factor_gen = 2; // cleared twice, not enrolled now
            return st;
        };
        const auto s = make_session("bob", "local", Role::user);
        CHECK(decide_with(s, never_enrolled, bound(s), calls, 0, kFc, &admitted).passed());
        CHECK(calls == 0);
        CHECK(admitted.local);
        CHECK(admitted.factor_gen == 2);
    }
    SECTION("the window is min(configured, 300): a 400 s old stored proof fails even under a "
            "day-long window, where an ordinary row passes it") {
        int calls = 0;
        const auto s = make_session("alice", "local", Role::admin, ago(10s));
        const auto old_row = proof_row(kDbNowMs - 400'000, kDbNowMs, 1);
        CHECK(decide_with(s, status_enrolled(1), old_row, calls, 86400, kFc).decision ==
              StepUpDecision::kChallenge);
        CHECK(decide_with(s, status_enrolled(1), old_row, calls, 86400).passed());
        // A smaller configured window tightens it.
        CHECK(decide_with(s, status_enrolled(1), proof_row(kDbNowMs - 100'000, kDbNowMs, 1), calls,
                          60, kFc)
                  .decision == StepUpDecision::kChallenge);
    }
    SECTION("the control: an ordinary row at window 0 passes with no proof and reads nothing") {
        int calls = 0;
        const auto s = make_session("alice", "local", Role::admin);
        CHECK(decide_with(s, status_enrolled(1), bound(s), calls, 0).passed());
        CHECK(calls == 0);
    }
}

TEST_CASE("decide_step_up (kFactorCredential): only a local interactive session may pass",
          "[stepup][gate][binding][factor_credential]") {
    struct Row {
        const char* source;
        const char* user;
    };
    const std::vector<Row> rows = {{"api_token", "t"},
                                   {"mcp_token", "t"},
                                   {"oidc", "oidc:i#a"},
                                   {"saml", "saml-user"},
                                   {"other", "someone"}};
    for (const int window : {300, 0}) {
        for (const auto& r : rows) {
            INFO(r.source << " window=" << window);
            int status_reads = 0;
            const MfaStatusFn counting =
                [&](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
                ++status_reads;
                return AuthDB::MfaStatus{.enrolled = true, .factor_gen = 1};
            };
            int calls = 0;
            const auto s = make_session(r.user, r.source, Role::admin, ago(1s)); // fresh proof
            StepUpAdmission admitted;
            const auto v = decide_with(s, counting, durable_matching(s, 1), calls, window,
                                       StepUpClass::kFactorCredential, &admitted);
            CHECK(v.decision == StepUpDecision::kFactorCredentialNonLocal);
            CHECK(v.reason == "factor_credential_requires_local_session");
            CHECK_FALSE(v.passed());
            CHECK(status_reads == 0);
            CHECK(calls == 0);
            CHECK_FALSE(admitted.local);
        }
    }
    // An engine principal is still the first answer, whatever the class.
    int calls = 0;
    const auto engine = make_session("engine:x", "engine_token", Role::user);
    CHECK(decide_with(engine, status_enrolled(1), durable_matching(engine, 1), calls, 0,
                      StepUpClass::kFactorCredential)
              .decision == StepUpDecision::kEngineDenied);
}

TEST_CASE("kFactorCredentialNonLocal renders a 403 that names no grant and offers no challenge",
          "[stepup][gate][binding][factor_credential]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kFactorCredentialNonLocal;
    v.user = "t";
    v.reason = "factor_credential_requires_local_session";
    auto req = make_request("POST", "/api/settings/mfa/disable", "/api/settings/mfa/disable");
    httplib::Response res;
    render_step_up_refusal(req, res, v, StepUpSurface::kDashboard);
    CHECK(res.status == 403);
    const auto body = body_of(res);
    CHECK(body["error"]["code"] == 403);
    CHECK(body["error"]["message"] ==
          "managing an account's second factor requires a local interactive session");
    CHECK(body["meta"]["mfa_step_up_required"] == false);
    CHECK_FALSE(body["meta"].contains("challenge_url"));
    CHECK(body["error"]["remediation"].get<std::string>().find("permission") == std::string::npos);

    std::vector<AuditRow> audits;
    const StepUpAuditFn audit = [&](const httplib::Request&, const std::string& a,
                                    const std::string& r, const std::string& tt,
                                    const std::string& ti, const std::string& d) {
        audits.push_back({a, r, tt, ti, d});
        return true;
    };
    emit_step_up_refusal_effects(req, v, audit, "POST /api/settings/mfa/disable", {}, nullptr);
    REQUIRE(audits.size() == 1);
    CHECK(audits[0].action == "mfa.step_up.required");
    CHECK(audits[0].detail == "user=t reason=factor_credential_requires_local_session");
}

TEST_CASE("a store-unavailable refusal counts its own series when it is a binding decision",
          "[stepup][gate][binding]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    const StepUpAuditFn no_audit;
    SECTION("an unreadable stored proof: route=mfa_binding, reason in the audit row") {
        yuzu::MetricsRegistry metrics;
        std::vector<AuditRow> audits;
        const StepUpAuditFn audit = [&](const httplib::Request&, const std::string& a,
                                        const std::string& r, const std::string& tt,
                                        const std::string& ti, const std::string& d) {
            audits.push_back({a, r, tt, ti, d});
            return true;
        };
        StepUpVerdict v;
        v.decision = StepUpDecision::kStoreUnavailable;
        v.user = "alice";
        v.reason = "mfa_proof_unavailable";
        emit_step_up_refusal_effects(req, v, audit, "POST /api/v1/tokens", {}, &metrics);
        REQUIRE(audits.size() == 1);
        CHECK(audits[0].detail == "user=alice reason=mfa_proof_unavailable");
        CHECK(metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_binding"}})
                  .value() == 1.0);
        CHECK(metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_stepup"}})
                  .value() == 0.0);
    }
    SECTION("an enrolment-status outage keeps the historical token and series") {
        yuzu::MetricsRegistry metrics;
        std::vector<AuditRow> audits;
        const StepUpAuditFn audit = [&](const httplib::Request&, const std::string& a,
                                        const std::string& r, const std::string& tt,
                                        const std::string& ti, const std::string& d) {
            audits.push_back({a, r, tt, ti, d});
            return true;
        };
        StepUpVerdict v;
        v.decision = StepUpDecision::kStoreUnavailable;
        v.user = "alice";
        emit_step_up_refusal_effects(req, v, audit, "POST /api/v1/tokens", {}, &metrics);
        REQUIRE(audits.size() == 1);
        CHECK(audits[0].detail == "user=alice reason=mfa_status_unavailable");
        CHECK(metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_stepup"}})
                  .value() == 1.0);
        CHECK(metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_binding"}})
                  .value() == 0.0);
    }
}

// ── render_step_up_refusal ───────────────────────────────────────────────────

TEST_CASE("render_step_up_refusal: stale local session is the 401 challenge envelope",
          "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kChallenge;
    httplib::Request req;
    httplib::Response res;
    render_step_up_refusal(req, res, v, StepUpSurface::kRest);
    CHECK(res.status == 401);
    const auto j = body_of(res);
    CHECK(j["error"]["code"] == 401);
    CHECK(j["error"]["message"] == "MFA step-up required");
    CHECK(j["meta"]["api_version"] == "v1");
    CHECK(j["meta"]["mfa_step_up_required"] == true);
    CHECK(j["meta"]["challenge_url"] == "/login/mfa/stepup");
}

TEST_CASE("render_step_up_refusal: OIDC challenge points at SSO", "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kChallenge;
    v.is_oidc = true;
    httplib::Request req;
    httplib::Response res;
    render_step_up_refusal(req, res, v, StepUpSurface::kRest);
    CHECK(body_of(res)["meta"]["challenge_url"] == "/auth/oidc/start");
}

TEST_CASE("render_step_up_refusal: SAML is 403 with no challenge", "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kSamlDenied;
    httplib::Request req;
    httplib::Response res;
    render_step_up_refusal(req, res, v, StepUpSurface::kRest);
    CHECK(res.status == 403);
    const auto j = body_of(res);
    CHECK(j["meta"]["mfa_step_up_required"] == false);
    CHECK_FALSE(j["meta"].contains("challenge_url"));
    // The remediation must not send a SAML caller back to a sign-in that cannot help.
    const auto remediation = j["error"]["remediation"].get<std::string>();
    CHECK(remediation ==
          "SAML sessions cannot satisfy step-up in this release (re-authenticating does not help); "
          "use an existing untiered, unscoped API token where the route accepts one, or ask an "
          "administrator");
    CHECK(remediation.find("/auth/saml/start") == std::string::npos);
}

TEST_CASE("render_step_up_refusal: an engine denial is 403 with no challenge on every surface",
          "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kEngineDenied;
    v.user = "engine:x";

    SECTION("REST: A4 envelope, 403, correlation id in header and body, no challenge") {
        httplib::Request req;
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kRest);
        CHECK(res.status == 403);
        const auto j = body_of(res);
        CHECK(j["error"]["code"] == 403);
        CHECK(j["error"]["message"] == "engine principals cannot perform this operation");
        CHECK(j["meta"]["api_version"] == "v1");
        CHECK(j["meta"]["mfa_step_up_required"] == false);
        CHECK_FALSE(j["meta"].contains("challenge_url"));
        CHECK_FALSE(res.has_header("HX-Trigger"));
        REQUIRE(res.has_header("X-Correlation-Id"));
        CHECK(j["error"]["correlation_id"] == res.get_header_value("X-Correlation-Id"));
    }
    SECTION("dashboard + HX-Request: the same 403 and the standard toast with the message") {
        httplib::Request req;
        req.set_header("HX-Request", "true");
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kDashboard);
        CHECK(res.status == 403);
        REQUIRE(res.has_header("HX-Trigger"));
        const auto t = nlohmann::json::parse(res.get_header_value("HX-Trigger"));
        CHECK(t["showToast"]["message"] == "engine principals cannot perform this operation");
        CHECK(t["showToast"]["level"] == "error");
    }
    SECTION("dashboard without HX-Request: 403, no toast") {
        httplib::Request req;
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kDashboard);
        CHECK(res.status == 403);
        CHECK_FALSE(res.has_header("HX-Trigger"));
    }
    SECTION("MCP: a JSON-RPC permission error whose data carries http_status 403") {
        httplib::Request req;
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kMcp);
        CHECK(res.status == 200);
        const auto j = body_of(res);
        CHECK(j["error"]["code"] == -32003);
        CHECK(j["error"]["data"]["http_status"] == 403);
        CHECK(j["error"]["data"]["mfa_step_up_required"] == false);
        CHECK_FALSE(j["error"]["data"].contains("challenge_url"));
    }
}

TEST_CASE("render_step_up_refusal: 503 for store outage, unwired store and unsupported class",
          "[stepup][gate]") {
    for (const auto d : {StepUpDecision::kStoreUnavailable, StepUpDecision::kUnwired,
                         StepUpDecision::kUnsupportedClass, StepUpDecision::kEvaluationFailed}) {
        StepUpVerdict v;
        v.decision = d;
        httplib::Request req;
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kRest);
        CHECK(res.status == 503);
        const auto j = body_of(res);
        CHECK(j["error"]["message"] == "authentication store is temporarily unavailable");
        CHECK_FALSE(j["meta"].contains("challenge_url"));
    }
}

TEST_CASE("render_step_up_refusal: status-read failure is a 401 that still names the challenge",
          "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kStatusFailed;
    httplib::Request req;
    httplib::Response res;
    render_step_up_refusal(req, res, v, StepUpSurface::kRest);
    CHECK(res.status == 401);
    CHECK(body_of(res)["meta"]["challenge_url"] == "/login/mfa/stepup");
}

TEST_CASE("render_step_up_refusal: the htmx toast needs HX-Request and is never on MCP",
          "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kChallenge;

    SECTION("dashboard + HX-Request carries the toast with the envelope's own message") {
        httplib::Request req;
        req.set_header("HX-Request", "true");
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kDashboard);
        REQUIRE(res.has_header("HX-Trigger"));
        const auto t = nlohmann::json::parse(res.get_header_value("HX-Trigger"));
        CHECK(t["showToast"]["message"] == "MFA step-up required");
        CHECK(t["showToast"]["level"] == "error");
        CHECK(res.status == 401);
    }
    SECTION(
        "the toast never carries the remediation (it names API-caller steps the form cannot do)") {
        StepUpVerdict saml;
        saml.decision = StepUpDecision::kSamlDenied;
        httplib::Request req;
        req.set_header("HX-Request", "true");
        httplib::Response res;
        render_step_up_refusal(req, res, saml, StepUpSurface::kDashboard);
        const auto t = nlohmann::json::parse(res.get_header_value("HX-Trigger"));
        // The remediation is read from the real response body, so the check cannot go vacuous
        // when the remediation wording changes.
        const auto remediation = body_of(res)["error"]["remediation"].get<std::string>();
        REQUIRE_FALSE(remediation.empty());
        CHECK(t["showToast"]["message"] ==
              "MFA step-up is not available for SAML sessions in this release");
        CHECK(res.get_header_value("HX-Trigger").find(remediation) == std::string::npos);
        CHECK(t["showToast"]["message"].get<std::string>() != remediation);
    }
    SECTION("dashboard without HX-Request has no toast") {
        httplib::Request req;
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kDashboard);
        CHECK_FALSE(res.has_header("HX-Trigger"));
    }
    SECTION("REST + HX-Request carries the same toast (a dashboard control can hx-delete an "
            "/api/v1/ route)") {
        httplib::Request req;
        req.set_header("HX-Request", "true");
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kRest);
        CHECK(res.status == 401);
        REQUIRE(res.has_header("HX-Trigger"));
        const auto t = nlohmann::json::parse(res.get_header_value("HX-Trigger"));
        CHECK(t["showToast"]["message"] == "MFA step-up required");
        CHECK(t["showToast"]["level"] == "error");
        // The JSON envelope is unchanged by the toast.
        CHECK(body_of(res)["meta"]["challenge_url"] == "/login/mfa/stepup");
    }
    SECTION("REST without HX-Request has no toast") {
        httplib::Request req;
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kRest);
        CHECK_FALSE(res.has_header("HX-Trigger"));
    }
    SECTION("MCP never toasts, even with HX-Request") {
        httplib::Request req;
        req.set_header("HX-Request", "true");
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kMcp);
        CHECK_FALSE(res.has_header("HX-Trigger"));
    }
}

TEST_CASE("render_step_up_refusal: MCP surface is a JSON-RPC permission error, not an HTTP 401",
          "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kChallenge;
    httplib::Request req;
    httplib::Response res;
    render_step_up_refusal(req, res, v, StepUpSurface::kMcp);
    CHECK(res.status == 200);
    const auto j = body_of(res);
    CHECK(j["jsonrpc"] == "2.0");
    CHECK(j["id"].is_null());
    CHECK(j["error"]["code"] == -32003);
    CHECK(j["error"]["data"]["mfa_step_up_required"] == true);
    CHECK(j["error"]["data"]["challenge_url"] == "/login/mfa/stepup");
    // The bare error object (for a caller that wraps it with the real request id) is the same.
    const auto bare = nlohmann::json::parse(step_up_refusal_json_rpc_error(v));
    CHECK(bare["code"] == -32003);
}

TEST_CASE("step-up labels: source and surface sets are closed", "[stepup][gate]") {
    for (const char* s : {"local", "oidc", "saml", "api_token", "mcp_token", "engine_token"})
        CHECK(step_up_source_label(s) == s);
    CHECK(step_up_source_label("attacker-chosen") == "other");
    CHECK(step_up_source_label("") == "other");
    CHECK(step_up_surface_for_path("/api/v1/tokens") == StepUpSurface::kRest);
    CHECK(step_up_surface_for_path("/api/settings/api-tokens") == StepUpSurface::kDashboard);
    CHECK(step_up_surface_for_path("/fragments/guardian/guard/x/update") ==
          StepUpSurface::kDashboard);
    CHECK(step_up_surface_for_path("/mcp/v1/") == StepUpSurface::kMcp);
}

TEST_CASE("seed_step_up_gate_metrics: every closed label combination exists at zero",
          "[stepup][gate]") {
    yuzu::MetricsRegistry metrics;
    seed_step_up_gate_metrics(metrics);
    const auto text = metrics.serialize();
    CHECK(text.find("# TYPE yuzu_auth_mfa_step_up_gate_total counter") != std::string::npos);

    // The pre-seed IS the series set: 4 outcomes x 8 sources x 3 surfaces = 96, each a distinct
    // sample line at zero, and nothing outside that set.
    std::vector<std::string> samples;
    {
        std::size_t pos = 0;
        while (pos < text.size()) {
            auto eol = text.find('\n', pos);
            if (eol == std::string::npos)
                eol = text.size();
            const std::string line = text.substr(pos, eol - pos);
            if (line.starts_with("yuzu_auth_mfa_step_up_gate_total{"))
                samples.push_back(line);
            pos = eol + 1;
        }
    }
    constexpr std::array<std::string_view, 4> kOutcomes{"pass", "refused", "unavailable",
                                                        "handler_skipped"};
    constexpr std::array<std::string_view, 8> kSources{"local",     "oidc",         "saml",
                                                       "api_token", "mcp_token",    "engine_token",
                                                       "other",     "none"};
    constexpr std::array<std::string_view, 3> kSurfaces{"rest", "dashboard", "mcp"};
    CHECK(samples.size() == kOutcomes.size() * kSources.size() * kSurfaces.size());
    CHECK(samples.size() == 96);

    std::size_t matched = 0;
    for (const auto outcome : kOutcomes) {
        for (const auto source : kSources) {
            for (const auto surface : kSurfaces) {
                const std::string o = "outcome=\"" + std::string(outcome) + "\"";
                const std::string src = "source=\"" + std::string(source) + "\"";
                const std::string sf = "surface=\"" + std::string(surface) + "\"";
                std::size_t hits = 0;
                for (const auto& line : samples) {
                    if (line.find(o) != std::string::npos && line.find(src) != std::string::npos &&
                        line.find(sf) != std::string::npos && line.ends_with(" 0"))
                        ++hits;
                }
                INFO(o << " " << src << " " << sf);
                CHECK(hits == 1);
                matched += hits;
            }
        }
    }
    // Every sample line is one of the 96 combinations: nothing outside the closed sets.
    CHECK(matched == samples.size());
}

// ── apply_step_up_chokepoint ─────────────────────────────────────────────────

TEST_CASE("chokepoint: a route with no table row is not applicable and reads nothing",
          "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    bool resolved = false;
    rig.resolver = [&](const httplib::Request&) {
        resolved = true;
        return rig.session;
    };
    auto req = make_request("POST", "/api/v1/not-in-the-table", "/api/v1/not-in-the-table");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kNotApplicable);
    CHECK_FALSE(resolved);
    CHECK(res.status == -1);
    CHECK(rig.audits.empty());
}

TEST_CASE("chokepoint: no matched route, or a non-mutating verb, is not applicable",
          "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    httplib::Response res;
    auto no_route = make_request("POST", "", "/api/v1/tokens");
    CHECK(detail::apply_step_up_chokepoint(no_route, res, rig.deps()) ==
          StepUpChokepointResult::kNotApplicable);
    auto get = make_request("GET", kTokensPattern, "/api/v1/tokens");
    CHECK(detail::apply_step_up_chokepoint(get, res, rig.deps()) ==
          StepUpChokepointResult::kNotApplicable);
}

TEST_CASE("chokepoint: the verb is part of the key", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    httplib::Response res;
    // PUT /api/v1/tokens is not a registered row (only POST is).
    auto req = make_request("PUT", kTokensPattern, "/api/v1/tokens");
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kNotApplicable);
}

TEST_CASE("chokepoint: kOwnGate rows are skipped even for a stale session", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    for (const char* pattern : {R"(/api/v1/elevate)", R"(/api/v1/users/elevation-eligibility)",
                                R"(/api/v1/users/([^/]+)/elevation-eligibility)"}) {
        auto req = make_request("POST", pattern, "/api/v1/elevate");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kNotApplicable);
        CHECK(res.status == -1);
    }
    CHECK(rig.audits.empty());
}

TEST_CASE("chokepoint: stale proof on a kRequired row is refused before the handler",
          "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 401);
    CHECK(body_of(res)["meta"]["mfa_step_up_required"] == true);

    SECTION("the audit row keeps today's action label and is tagged pre_authz") {
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].action == "mfa.step_up.required");
        CHECK(rig.audits[0].result == "error");
        CHECK(rig.audits[0].target_type == "Endpoint");
        CHECK(rig.audits[0].target_id == kTokensLabel);
        CHECK(rig.audits[0].detail.find("user=alice") != std::string::npos);
        CHECK(rig.audits[0].detail.ends_with(" stage=pre_authz"));
    }
    SECTION("the gate metric counts a refusal by source and surface") {
        CHECK(rig.gate_count("refused", "local", "rest") == 1);
        CHECK(rig.gate_count("pass", "local", "rest") == 0);
    }
    SECTION("a refusal arms no pass stash") {
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
}

TEST_CASE("chokepoint: the audit row carries the response's correlation id, with stage last",
          "[stepup][gate]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");

    SECTION("a REST refusal: cid equals X-Correlation-Id and the body's correlation_id") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(1h));
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kRefused);
        REQUIRE(rig.audits.size() == 1);
        const auto cid = cid_of(rig.audits[0].detail);
        CHECK_FALSE(cid.empty());
        CHECK(cid == res.get_header_value("X-Correlation-Id"));
        CHECK(cid == body_of(res)["error"]["correlation_id"].get<std::string>());
        CHECK(rig.audits[0].detail.ends_with(" cid=" + cid + " stage=pre_authz"));
    }
    SECTION("a no-proof refusal: user, age_secs, window_secs, reason, cid, stage in that order") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, {}); // no proof at all
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kRefused);
        REQUIRE(rig.audits.size() == 1);
        const auto cid = res.get_header_value("X-Correlation-Id");
        CHECK(rig.audits[0].detail == "user=alice age_secs=-1 window_secs=300 "
                                      "reason=mfa_proof_missing cid=" +
                                          cid + " stage=pre_authz");
    }
    SECTION("an aged proof records its age; the rest of the row is the same exact grammar") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(1h));
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kRefused);
        REQUIRE(rig.audits.size() == 1);
        const auto cid = res.get_header_value("X-Correlation-Id");
        // The age is derived from a monotonic clock a moment after `ago(1h)` was taken, so it is
        // 3600 plus a scheduling blip: accept a small band, pin everything else exactly.
        bool matched = false;
        for (int age = 3600; age <= 3610; ++age) {
            matched = matched || rig.audits[0].detail == "user=alice age_secs=" +
                                                              std::to_string(age) +
                                                              " window_secs=300 cid=" + cid +
                                                              " stage=pre_authz";
        }
        INFO("detail=" << rig.audits[0].detail);
        CHECK(matched);
    }
    SECTION("a store outage names mfa_status_unavailable with no parenthetical") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.mfa_status = status_error(AuthDBError::SecretUnavailable);
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kRefused);
        REQUIRE(rig.audits.size() == 1);
        const auto cid = res.get_header_value("X-Correlation-Id");
        CHECK(rig.audits[0].detail ==
              "user=alice reason=mfa_status_unavailable cid=" + cid + " stage=pre_authz");
    }
    SECTION("a status failure that is not an outage records the same reason token") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.mfa_status = status_error(AuthDBError::UserNotFound);
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kRefused);
        REQUIRE(rig.audits.size() == 1);
        const auto cid = res.get_header_value("X-Correlation-Id");
        CHECK(rig.audits[0].detail ==
              "user=alice reason=mfa_status_unavailable cid=" + cid + " stage=pre_authz");
    }
    SECTION("a refusal with a named reason: user, reason, cid, stage in that order") {
        Rig rig;
        rig.session = make_session("alice", "saml", Role::admin, ago(1s));
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kRefused);
        REQUIRE(rig.audits.size() == 1);
        const auto cid = res.get_header_value("X-Correlation-Id");
        CHECK(rig.audits[0].detail ==
              "user=alice reason=saml_session_no_mfa_this_release cid=" + cid +
                  " stage=pre_authz");
    }
    SECTION("a correlation id an upstream gate already set is the one recorded") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(1h));
        httplib::Response res;
        res.set_header("X-Correlation-Id", "req-upstream-7");
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kRefused);
        REQUIRE(rig.audits.size() == 1);
        CHECK(cid_of(rig.audits[0].detail) == "req-upstream-7");
        CHECK(res.get_header_value("X-Correlation-Id") == "req-upstream-7");
    }
    SECTION("the fail-closed fallback records the same id it returns") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.fault_hook = [](StepUpFaultPoint p) {
            if (p == StepUpFaultPoint::kBeforeDecide)
                throw 42; // NOLINT(hicpp-exception-baseclass): the point of the test
        };
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kRefused);
        REQUIRE(rig.audits.size() == 1);
        const auto cid = cid_of(rig.audits[0].detail);
        CHECK(cid == res.get_header_value("X-Correlation-Id"));
        CHECK(rig.audits[0].detail.ends_with(" cid=" + cid + " stage=pre_authz"));
    }
}

TEST_CASE("chokepoint: a dashboard route on an htmx request gets the toast", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    auto req = make_request("POST", R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/update)",
                            "/fragments/guardian/guard/g1/update");
    req.set_header("HX-Request", "true");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 401);
    CHECK(res.has_header("HX-Trigger"));
    CHECK(rig.gate_count("refused", "local", "dashboard") == 1);
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].target_id == "POST /fragments/guardian/guard/{id}/update");
}

TEST_CASE("chokepoint: a REST route carries the toast only on an htmx request", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    SECTION("with HX-Request (Settings Users 'Revoke sessions' is an hx-delete to /api/v1/)") {
        auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
        req.set_header("HX-Request", "true");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
        REQUIRE(res.has_header("HX-Trigger"));
        const auto t = nlohmann::json::parse(res.get_header_value("HX-Trigger"));
        CHECK(t["showToast"]["message"] == "MFA step-up required");
        CHECK(rig.gate_count("refused", "local", "rest") == 1);
    }
    SECTION("without HX-Request") {
        auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK_FALSE(res.has_header("HX-Trigger"));
    }
}

// The two MFA settings routes that mint or remove the factor the gate itself checks: a hijacked
// admin cookie must not be able to mint a recovery code (which satisfies a step-up challenge) or
// strip MFA (after which an un-enrolled caller passes every gate) without a fresh proof.
TEST_CASE("chokepoint: the MFA recovery-codes and disable routes are gated",
          "[stepup][gate]") {
    struct MfaRoute {
        const char* pattern;
        const char* label;
    };
    // GENERATE, not a loop around SECTIONs: Catch2 tracks a section by name and line, so a
    // SECTION inside a for-loop only ever runs for the first element. Each generated value
    // re-runs the whole test case, so every section below runs for BOTH routes.
    const auto route = GENERATE(values<MfaRoute>({
        MfaRoute{"/api/settings/mfa/recovery-codes", "POST /api/settings/mfa/recovery-codes"},
        MfaRoute{"/api/settings/mfa/disable", "POST /api/settings/mfa/disable"},
    }));
    CAPTURE(route.pattern);
    const auto* row = step_up_policy_for("POST", route.pattern);
    REQUIRE(row != nullptr);
    CHECK(row->cls == StepUpClass::kFactorCredential);
    CHECK(row->action_label == route.label);
    CHECK(step_up_surface_for_path(route.pattern) == StepUpSurface::kDashboard);

    SECTION("a stale proof is refused with the toast on an htmx request") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(1h));
        auto req = make_request("POST", route.pattern, route.pattern);
        req.set_header("HX-Request", "true");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
        CHECK(res.has_header("HX-Trigger"));
        CHECK(body_of(res)["meta"]["mfa_step_up_required"] == true);
        CHECK(rig.gate_count("refused", "local", "dashboard") == 1);
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].target_id == route.label);
        CHECK(rig.audits[0].detail.ends_with(" stage=pre_authz"));
    }
    SECTION("a fresh proof passes and arms the stash for the in-handler call") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(5s));
        auto req = make_request("POST", route.pattern, route.pattern);
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kPassed);
        CHECK(res.status == -1);
        CHECK(rig.gate_count("pass", "local", "dashboard") == 1);
        CHECK(detail::consume_step_up_pass(req, *rig.session, route.label, nullptr));
    }
    SECTION("an un-enrolled caller passes whatever the proof age") {
        Rig rig;
        rig.session = make_session("bob", "local", Role::admin, ago(1h));
        rig.mfa_status = status_not_enrolled();
        auto req = make_request("POST", route.pattern, route.pattern);
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kPassed);
        CHECK(rig.audits.empty());
        detail::clear_step_up_pass();
    }
}

// ── the chokepoint over the two factor-credential rows (#6079) ──────────────────────────────────

namespace {

struct FcRoute {
    const char* pattern;
    const char* label;
};

constexpr std::array<FcRoute, 2> kFcRoutes = {
    FcRoute{"/api/settings/mfa/recovery-codes", "POST /api/settings/mfa/recovery-codes"},
    FcRoute{"/api/settings/mfa/disable", "POST /api/settings/mfa/disable"}};

bool has(const std::string& text, std::string_view what) {
    return text.find(what) != std::string::npos;
}

} // namespace

TEST_CASE("chokepoint (kFactorCredential): the window-0 hatch admits neither a survivor nor a "
          "password-only session",
          "[stepup][gate][binding][factor_credential]") {
    const auto route = GENERATE(values<FcRoute>({kFcRoutes[0], kFcRoutes[1]}));
    CAPTURE(route.pattern);
    auto req = make_request("POST", route.pattern, route.pattern);

    SECTION("a session bound to a factor since replaced: 401 proof_factor_mismatch, no pass") {
        Rig rig;
        rig.window_secs = 0;
        rig.mfa_status = status_enrolled(3); // the account is now at generation 3
        rig.session = make_session("alice", "local", Role::admin, ago(5s));
        rig.durable = [](const httplib::Request&, const auth::Session& s) {
            return durable_matching(s, 1); // the proof was made under generation 1
        };
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
        CHECK(body_of(res)["meta"]["mfa_step_up_required"] == true);
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].target_id == route.label);
        CHECK(has(rig.audits[0].detail, "reason=proof_factor_mismatch"));
        CHECK(has(rig.audits[0].detail, "window_secs=300")); // the approver window, not 0
        CHECK(rig.audits[0].detail.ends_with(" stage=pre_authz"));
        CHECK_FALSE(detail::consume_step_up_pass(req, *rig.session, route.label, nullptr));
    }
    SECTION("a password-only session with no proof: 401 mfa_proof_missing") {
        Rig rig;
        rig.window_secs = 0;
        rig.session = make_session("alice", "local", Role::admin);
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
        REQUIRE(rig.audits.size() == 1);
        CHECK(has(rig.audits[0].detail, "reason=mfa_proof_missing"));
    }
    SECTION("a bound proof outside the approver window is refused whatever the configured window") {
        Rig rig;
        rig.window_secs = 86400;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.durable = [](const httplib::Request&, const auth::Session& s) {
            auto d = durable_matching(s, 1);
            d.mfa_verified_ms = kDbNowMs - 400'000;
            return d;
        };
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
        REQUIRE(rig.audits.size() == 1);
        CHECK(has(rig.audits[0].detail, "window_secs=300"));
    }
    SECTION("a bound fresh proof passes at window 0 and hands the admission to the earning "
            "principal only") {
        Rig rig;
        rig.window_secs = 0;
        rig.mfa_status = status_enrolled(6);
        rig.session = make_session("alice", "local", Role::admin, ago(5s));
        rig.durable = [](const httplib::Request&, const auth::Session& s) {
            return durable_matching(s, 6);
        };
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kPassed);
        CHECK(rig.gate_count("pass", "local", "dashboard") == 1);

        // Another principal presenting the same request gets neither the pass nor the admission,
        // and the pass is spent doing so.
        StepUpAdmission stolen{false, 99};
        CHECK_FALSE(detail::consume_step_up_pass(req, make_session("mallory", "local", Role::admin),
                                                 route.label, &stolen));
        CHECK_FALSE(stolen.local);
        CHECK(stolen.factor_gen == 99);

        // Arm again and consume as the earning principal.
        detail::clear_step_up_pass();
        httplib::Response res2;
        REQUIRE(detail::apply_step_up_chokepoint(req, res2, rig.deps()) ==
                StepUpChokepointResult::kPassed);
        StepUpAdmission got;
        CHECK(detail::consume_step_up_pass(req, *rig.session, route.label, &got));
        CHECK(got.local);
        CHECK(got.factor_gen == 6);
        // A nullptr out-parameter is allowed for the 35 rows that ignore it.
        detail::clear_step_up_pass();
        httplib::Response res3;
        REQUIRE(detail::apply_step_up_chokepoint(req, res3, rig.deps()) ==
                StepUpChokepointResult::kPassed);
        CHECK(detail::consume_step_up_pass(req, *rig.session, route.label, nullptr));
    }
    SECTION("an un-enrolled account passes at window 0 (it may cancel a provisional enrolment) "
            "with the generation as read") {
        Rig rig;
        rig.window_secs = 0;
        rig.mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            AuthDB::MfaStatus st;
            st.factor_gen = 2;
            return st;
        };
        rig.session = make_session("bob", "local", Role::user);
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kPassed);
        StepUpAdmission got;
        CHECK(detail::consume_step_up_pass(req, *rig.session, route.label, &got));
        CHECK(got.local);
        CHECK(got.factor_gen == 2);
    }
}

TEST_CASE("chokepoint (kFactorCredential): a bearer, SSO or SAML session is a 403 with an audit "
          "row, and the same principal still passes an ordinary row",
          "[stepup][gate][binding][factor_credential]") {
    const auto route = GENERATE(values<FcRoute>({kFcRoutes[0], kFcRoutes[1]}));
    const std::string source =
        GENERATE(as<std::string>{}, "api_token", "mcp_token", "oidc", "saml");
    CAPTURE(route.pattern, source);
    auto req = make_request("POST", route.pattern, route.pattern);

    Rig rig;
    // An untiered administrator token (or an SSO admin) with a fresh proof and the gate enabled:
    // every other row would let the bearer through, or judge the SSO proof; these two do neither.
    rig.session = make_session(source == "oidc" ? "oidc:i#a" : "tok", source, Role::admin, ago(2s));
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 403);
    const auto body = body_of(res);
    CHECK(body["meta"]["mfa_step_up_required"] == false);
    CHECK_FALSE(body["meta"].contains("challenge_url"));
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].action == "mfa.step_up.required");
    CHECK(rig.audits[0].target_id == route.label);
    CHECK(has(rig.audits[0].detail, "reason=factor_credential_requires_local_session"));
    CHECK(rig.audits[0].detail.ends_with(" stage=pre_authz"));
    CHECK(rig.gate_count("refused", source, "dashboard") == 1);
    CHECK_FALSE(detail::consume_step_up_pass(req, *rig.session, route.label, nullptr));

    // No collateral: an ordinary kRequired row decides this principal exactly as before.
    if (source == "api_token" || source == "mcp_token") {
        Rig other;
        other.session = make_session("tok", source, Role::admin);
        auto tokens = make_request("POST", kTokensPattern, "/api/v1/tokens");
        httplib::Response ok;
        CHECK(detail::apply_step_up_chokepoint(tokens, ok, other.deps()) ==
              StepUpChokepointResult::kPassed);
        detail::clear_step_up_pass();
    }
}

TEST_CASE("chokepoint: a local enrolled caller with no stored-proof provider wired is a 503; a "
          "caller that needs no stored proof is unaffected",
          "[stepup][gate][binding]") {
    auto tokens = make_request("POST", kTokensPattern, "/api/v1/tokens");
    SECTION("kRequired row, local enrolled, no provider") {
        Rig rig;
        rig.wire_durable = false;
        rig.session = make_session("alice", "local", Role::admin, ago(5s));
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(tokens, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        REQUIRE(rig.audits.size() == 1);
        CHECK(has(rig.audits[0].detail, "reason=auth_store_unwired"));
        CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
    }
    SECTION("the same wiring passes the hatch, a bearer and an un-enrolled local account") {
        Rig hatch;
        hatch.wire_durable = false;
        hatch.window_secs = 0;
        hatch.session = make_session("alice", "local", Role::admin);
        httplib::Response a;
        CHECK(detail::apply_step_up_chokepoint(tokens, a, hatch.deps()) ==
              StepUpChokepointResult::kPassed);
        detail::clear_step_up_pass();

        Rig bearer;
        bearer.wire_durable = false;
        bearer.session = make_session("t", "api_token", Role::admin);
        httplib::Response b;
        CHECK(detail::apply_step_up_chokepoint(tokens, b, bearer.deps()) ==
              StepUpChokepointResult::kPassed);
        detail::clear_step_up_pass();

        Rig fresh;
        fresh.wire_durable = false;
        fresh.mfa_status = status_not_enrolled();
        fresh.session = make_session("bob", "local", Role::user);
        httplib::Response c;
        CHECK(detail::apply_step_up_chokepoint(tokens, c, fresh.deps()) ==
              StepUpChokepointResult::kPassed);
        detail::clear_step_up_pass();
    }
}

TEST_CASE("chokepoint: a kRequired row judges the binding of a local enrolled caller and "
          "reports an unreadable one as 503",
          "[stepup][gate][binding]") {
    auto tokens = make_request("POST", kTokensPattern, "/api/v1/tokens");
    SECTION("an unbound stored proof: 401 proof_factor_unbound") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(5s));
        rig.durable = [](const httplib::Request&, const auth::Session& s) {
            return durable_matching(s, 0);
        };
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(tokens, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
        REQUIRE(rig.audits.size() == 1);
        CHECK(has(rig.audits[0].detail, "reason=proof_factor_unbound"));
    }
    SECTION("a degraded stored-proof read: 503, counted on route=mfa_binding") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(5s));
        rig.durable = [](const httplib::Request&, const auth::Session&) {
            return auth::DurableMfaProof{}; // kUnavailable
        };
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(tokens, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        REQUIRE(rig.audits.size() == 1);
        CHECK(has(rig.audits[0].detail, "reason=mfa_proof_unavailable"));
        CHECK(rig.metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_binding"}})
                  .value() == 1.0);
    }
    SECTION("the provider is handed the request and the resolved session") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(5s));
        const httplib::Request* seen_req = nullptr;
        std::string seen_user;
        rig.durable = [&](const httplib::Request& r, const auth::Session& s) {
            seen_req = &r;
            seen_user = s.username;
            return durable_matching(s, 1);
        };
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(tokens, res, rig.deps()) ==
                StepUpChokepointResult::kPassed);
        CHECK(seen_req == &tokens);
        CHECK(seen_user == "alice");
        detail::clear_step_up_pass();
    }
}

TEST_CASE("chokepoint: SAML session is a 403 on a kRequired row", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("saml-user", "saml", Role::admin, ago(1s));
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 403);
    CHECK(rig.gate_count("refused", "saml", "rest") == 1);
}

TEST_CASE("chokepoint: a bearer principal passes", "[stepup][gate]") {
    for (const char* source : {"api_token", "mcp_token"}) {
        Rig rig;
        rig.session = make_session("t", source, Role::admin);
        auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kPassed);
        CHECK(res.status == -1);
        CHECK(rig.audits.empty());
        CHECK(rig.gate_count("pass", source, "rest") == 1);
        detail::clear_step_up_pass();
    }
}

TEST_CASE("chokepoint: an engine session is refused 403 before the handler and any store read",
          "[stepup][gate]") {
    struct Surface {
        const char* path;
        const char* surface;
    };
    for (const auto& sf :
         {Surface{"/api/v1/tokens", "rest"}, Surface{"/api/settings/api-tokens", "dashboard"},
          Surface{"/mcp/v1/", "mcp"}}) {
        CAPTURE(sf.surface);
        Rig rig;
        rig.session = make_session("engine:x", "engine_token", Role::admin);
        int store_reads = 0;
        rig.mfa_status = [&](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            ++store_reads;
            return std::unexpected(AuthDBError::InvalidUsername);
        };
        auto req = make_request("POST", kTokensPattern, sf.path);
        req.set_header("HX-Request", "true");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(store_reads == 0);
        if (std::string_view(sf.surface) == "mcp") {
            CHECK(res.status == 200);
            CHECK(body_of(res)["error"]["data"]["http_status"] == 403);
        } else {
            CHECK(res.status == 403);
            CHECK(body_of(res)["error"]["message"] ==
                  "engine principals cannot perform this operation");
        }
        // The handler is never reached: no pass stash is armed for it.
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].action == "mfa.step_up.required");
        CHECK(rig.audits[0].result == "error");
        CHECK(rig.audits[0].target_id == kTokensLabel);
        CHECK(without_cid(rig.audits[0].detail) ==
              "user=engine:x reason=engine_principal_denied stage=pre_authz");
        CHECK(rig.gate_count("refused", "engine_token", sf.surface) == 1);
        CHECK(rig.gate_count("pass", "engine_token", sf.surface) == 0);
        CHECK(rig.gate_count("unavailable", "engine_token", sf.surface) == 0);
    }
}

TEST_CASE("chokepoint: an engine is refused by principal_kind alone, and past the operator hatch",
          "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("engine:y", "other", Role::admin);
    rig.session->principal_kind = "engine";
    rig.window_secs = 0; // gate disabled: an engine still never reaches the handler
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 403);
    REQUIRE(rig.audits.size() == 1);
    CHECK(without_cid(rig.audits[0].detail) ==
          "user=engine:y reason=engine_principal_denied stage=pre_authz");
    CHECK(rig.gate_count("refused", "other", "rest") == 1);
}

TEST_CASE("chokepoint: an engine on an unwired store gets the 503, not the 403", "[stepup][gate]") {
    // The null-store check precedes the decision, so the unwired fail-closed answer is the same
    // for every caller class.
    Rig rig;
    rig.session = make_session("engine:x", "engine_token", Role::admin);
    rig.wire_store = false;
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 503);
    CHECK(rig.gate_count("unavailable", "engine_token", "rest") == 1);
    CHECK(rig.gate_count("refused", "engine_token", "rest") == 0);
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].detail.find("reason=auth_store_unwired") != std::string::npos);
}

TEST_CASE("chokepoint: a kOwnGate row is not the chokepoint's, so an engine is left to its handler",
          "[stepup][gate]") {
    // The elevation rows are kOwnGate: the chokepoint evaluates nothing. Their in-handler gate
    // (`require_mfa_step_up`) shares decide_step_up, so it answers an engine 403 there.
    Rig rig;
    rig.session = make_session("engine:x", "engine_token", Role::admin);
    auto req = make_request("POST", R"(/api/v1/elevate)", "/api/v1/elevate");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kNotApplicable);
    CHECK(res.status == -1);
    CHECK(rig.audits.empty());
}

TEST_CASE("chokepoint: a store outage is a 503, counted unavailable", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    rig.mfa_status = status_error(AuthDBError::SecretUnavailable);
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 503);
    CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
    CHECK(rig.metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_stepup"}})
              .value() == 1);
}

TEST_CASE("chokepoint: an unwired auth store fails CLOSED with a 503, never a pass",
          "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s)); // fresh: would pass
    rig.wire_store = false;
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 503);
    CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].detail.find("reason=auth_store_unwired") != std::string::npos);
    CHECK(rig.audits[0].detail.ends_with(" stage=pre_authz"));
    // Distinct from the 401 challenge and the 403 SAML refusal.
    CHECK(res.status != 401);
    CHECK(res.status != 403);
}

TEST_CASE("chokepoint: an unwired store is a 503 for a bearer principal too", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("t", "api_token", Role::admin);
    rig.wire_store = false;
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 503);
}

TEST_CASE("chokepoint: window <= 0 passes a kRequired row (operator hatch)", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    rig.window_secs = 0;
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kPassed);
    detail::clear_step_up_pass();
}

TEST_CASE("chokepoint: no session, an unwired resolver and a throwing resolver all refuse",
          "[stepup][gate]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");

    SECTION("no session is a 401 unauthorized") {
        Rig rig;
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
        CHECK(body_of(res)["error"]["message"] == "unauthorized");
        CHECK(rig.gate_count("refused", "none", "rest") == 1);
    }
    SECTION("an unwired resolver fails closed") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.wire_resolver = false;
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
    }
    SECTION("a resolver that throws is a 503, never a pass") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.resolver_throws = true;
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK(body_of(res)["meta"]["mfa_step_up_required"] == true);
        // No session resolved, so there is no source to report.
        CHECK(rig.gate_count("unavailable", "other", "rest") == 1);
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
        // No session had resolved, so the row has no user; the reason token is still recorded.
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].action == "mfa.step_up.required");
        CHECK(rig.audits[0].result == "error");
        CHECK(without_cid(rig.audits[0].detail) ==
              "user= reason=chokepoint_exception stage=pre_authz");
    }
    SECTION("an MFA status read that throws is a 503 with an audit row, never a pass") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s)); // fresh: would pass
        rig.mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            throw std::runtime_error("status read failure");
        };
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        const auto j = body_of(res);
        CHECK(j["error"]["message"] == "authentication store is temporarily unavailable");
        CHECK_FALSE(j["meta"].contains("challenge_url"));
        CHECK(j["meta"]["mfa_step_up_required"] == true);
        CHECK_FALSE(res.has_header("HX-Trigger"));
        // The session resolved before the throw, so its own source labels the metric.
        CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
        CHECK(rig.gate_count("unavailable", "other", "rest") == 0);
        CHECK(rig.gate_count("pass", "local", "rest") == 0);
        // The pass stash is not armed: a handler-side consume finds nothing.
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].action == "mfa.step_up.required");
        CHECK(rig.audits[0].result == "error");
        CHECK(rig.audits[0].target_id == kTokensLabel);
        CHECK(without_cid(rig.audits[0].detail) ==
              "user=alice reason=chokepoint_exception stage=pre_authz");
    }
    SECTION("the dashboard surface gets the toast and the real source label") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            throw std::runtime_error("status read failure");
        };
        auto dash = make_request("POST", kTokensPattern, "/api/settings/api-tokens");
        dash.set_header("HX-Request", "true");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(dash, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK(body_of(res)["meta"]["mfa_step_up_required"] == true);
        REQUIRE(res.has_header("HX-Trigger"));
        const auto t = nlohmann::json::parse(res.get_header_value("HX-Trigger"));
        CHECK(t["showToast"]["message"] == "authentication store is temporarily unavailable");
        CHECK(t["showToast"]["level"] == "error");
        CHECK(rig.gate_count("unavailable", "local", "dashboard") == 1);
        REQUIRE(rig.audits.size() == 1);
        CHECK(without_cid(rig.audits[0].detail) ==
              "user=alice reason=chokepoint_exception stage=pre_authz");
    }
    SECTION("the dashboard surface without HX-Request has no toast") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            throw std::runtime_error("status read failure");
        };
        auto dash = make_request("POST", kTokensPattern, "/api/settings/api-tokens");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(dash, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK_FALSE(res.has_header("HX-Trigger"));
    }
    SECTION("the MCP surface gets the JSON-RPC shape, not the REST envelope") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            throw std::runtime_error("status read failure");
        };
        auto mcp_req = make_request("POST", kTokensPattern, "/mcp/v1/");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(mcp_req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        const auto j = body_of(res);
        CHECK(j["jsonrpc"] == "2.0");
        CHECK(j["error"]["data"]["mfa_step_up_required"] == true);
        CHECK(j["error"]["data"]["http_status"] == 503);
        CHECK(rig.gate_count("unavailable", "local", "mcp") == 1);
    }
    SECTION("a bearer-class session keeps its own source label on the metric") {
        // Bearer-class sessions (engine included) never reach the store lookup, so the throw is
        // injected at the fault point that follows session resolution.
        Rig rig;
        rig.session = make_session("engine-1", "engine_token", Role::admin, ago(10s));
        rig.fault_hook = [](StepUpFaultPoint p) {
            if (p == StepUpFaultPoint::kBeforeDecide)
                throw std::runtime_error("evaluation failure");
        };
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK(rig.gate_count("unavailable", "engine_token", "rest") == 1);
        CHECK(rig.gate_count("unavailable", "other", "rest") == 0);
    }
    SECTION("an audit writer that throws inside the fallback cannot escape or soften the 503") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            throw std::runtime_error("status read failure");
        };
        rig.audit = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) -> bool {
            throw std::runtime_error("audit failure");
        };
        httplib::Response res;
        CHECK_NOTHROW(detail::apply_step_up_chokepoint(req, res, rig.deps()));
        CHECK(res.status == 503);
        CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
}

TEST_CASE("chokepoint: an evaluation that throws after the session resolves keeps the real "
          "source label",
          "[stepup][gate]") {
    // `decide_step_up` itself reads no store for these sources, so the fault hook is the only way
    // to make their evaluation throw. Every session below has a fresh proof, or is exempt, and
    // so would not be refused for any reason other than the throw (SAML is refused 403).
    const auto source = GENERATE(as<std::string>{}, "oidc", "saml", "api_token", "mcp_token");
    CAPTURE(source);
    Rig rig;
    rig.session = make_session("carol", source, Role::admin, ago(10s));
    std::vector<StepUpFaultPoint> seen;
    rig.fault_hook = [&seen](StepUpFaultPoint p) {
        seen.push_back(p);
        if (p == StepUpFaultPoint::kBeforeDecide)
            throw std::runtime_error("evaluation failure");
    };
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");

    // Arm a pass stash first, as a previous request on this worker thread would have left it, so
    // the check below proves the fallback clears it rather than that it was never set. `passing`
    // stays alive to the end of the case: a Rig clears the stash when it is destroyed.
    Rig passing;
    passing.session = make_session("carol", "api_token", Role::admin);
    {
        httplib::Response ok;
        REQUIRE(detail::apply_step_up_chokepoint(req, ok, passing.deps()) ==
                StepUpChokepointResult::kPassed);
    }

    httplib::Response res;
    StepUpChokepointResult result{};
    REQUIRE_NOTHROW(result = detail::apply_step_up_chokepoint(req, res, rig.deps()));
    CHECK(result == StepUpChokepointResult::kRefused);
    CHECK(res.status == 503);
    CHECK(body_of(res)["meta"]["mfa_step_up_required"] == true);
    // The throw is observed once before the decision and the fallback then renders once.
    CHECK(seen == std::vector<StepUpFaultPoint>{StepUpFaultPoint::kBeforeDecide,
                                                StepUpFaultPoint::kFallbackRender});
    // The session resolved, so its own bounded source label counts the refusal; "other" is for a
    // resolver that itself threw.
    CHECK(rig.gate_count("unavailable", source, "rest") == 1);
    CHECK(rig.gate_count("unavailable", "other", "rest") == 0);
    CHECK(rig.gate_count("pass", source, "rest") == 0);
    CHECK_FALSE(
        detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].action == "mfa.step_up.required");
    CHECK(rig.audits[0].result == "error");
    CHECK(rig.audits[0].target_id == kTokensLabel);
    CHECK(without_cid(rig.audits[0].detail) ==
          "user=carol reason=chokepoint_exception stage=pre_authz");
}

TEST_CASE("chokepoint: a refusal renderer that throws still ends in a 503", "[stepup][gate]") {
    // The hook throws at both points, so the evaluation fails and then the fallback's render
    // fails too. The last-resort branch sets the status and writes no body, and here the hook
    // throws before the renderer writes anything, so only the status is asserted: the code
    // guarantees a 503, not a body.
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    rig.fault_hook = [](StepUpFaultPoint) { throw std::runtime_error("injected failure"); };

    // A stash left armed by an earlier request on this thread must not survive the fallback.
    Rig passing;
    passing.session = make_session("alice", "api_token", Role::admin);
    {
        httplib::Response ok;
        REQUIRE(detail::apply_step_up_chokepoint(req, ok, passing.deps()) ==
                StepUpChokepointResult::kPassed);
    }

    SECTION("REST") {
        httplib::Response res;
        StepUpChokepointResult result{};
        REQUIRE_NOTHROW(result = detail::apply_step_up_chokepoint(req, res, rig.deps()));
        CHECK(result == StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
        REQUIRE(rig.audits.size() == 1);
        CHECK(without_cid(rig.audits[0].detail) ==
              "user=alice reason=chokepoint_exception stage=pre_authz");
    }
    SECTION("MCP: the status is 503 although the MCP renderer would have answered 200") {
        auto mcp_req = make_request("POST", kTokensPattern, "/mcp/v1/");
        httplib::Response res;
        REQUIRE_NOTHROW(detail::apply_step_up_chokepoint(mcp_req, res, rig.deps()));
        CHECK(res.status == 503);
        CHECK(rig.gate_count("unavailable", "local", "mcp") == 1);
        REQUIRE(rig.audits.size() == 1);
    }
    SECTION("the audit writer throwing as well changes nothing") {
        rig.audit = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) -> bool {
            throw std::runtime_error("audit failure");
        };
        httplib::Response res;
        StepUpChokepointResult result{};
        REQUIRE_NOTHROW(result = detail::apply_step_up_chokepoint(req, res, rig.deps()));
        CHECK(result == StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
}

namespace {
std::size_t count_occurrences(const std::string& haystack, std::string_view needle) {
    std::size_t n = 0;
    for (auto pos = haystack.find(needle); pos != std::string::npos;
         pos = haystack.find(needle, pos + needle.size()))
        ++n;
    return n;
}
} // namespace

TEST_CASE("chokepoint: an exception's what() is logged and the answer is still a fail-closed 503",
          "[stepup][gate]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");

    SECTION("a std::exception: its what() reaches the log") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.fault_hook = [](StepUpFaultPoint p) {
            if (p == StepUpFaultPoint::kBeforeDecide)
                throw std::runtime_error("yuzu_test_distinctive_what_text");
        };
        yuzu::test::LogCapture capture;
        // The log line is sampled (the first of every 100 is written), and the sampling counter
        // is process-wide, so drive a full period: at least one line is guaranteed.
        for (int i = 0; i < 100; ++i) {
            httplib::Response res;
            REQUIRE_NOTHROW(detail::apply_step_up_chokepoint(req, res, rig.deps()));
            CHECK(res.status == 503);
        }
        capture.stop();
        const auto logs = capture.text();
        CHECK(logs.find("yuzu_test_distinctive_what_text") != std::string::npos);
        CHECK(logs.find(std::string(kTokensLabel)) != std::string::npos);
        CHECK(rig.gate_count("unavailable", "local", "rest") == 100);
        // ONE line per sampled exception: a window of 100 hits holds exactly one multiple of 100,
        // and the fallback's audit/metric effects add no second line of their own.
        CHECK(count_occurrences(logs, "step-up gate: evaluating") == 1);
        CHECK(count_occurrences(logs, "yuzu_test_distinctive_what_text") == 1);
        // The audit rows are NOT sampled: one per exception.
        CHECK(rig.audits.size() == 100);
    }
    SECTION("what() is sanitised: control characters never reach the log verbatim") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.fault_hook = [](StepUpFaultPoint p) {
            if (p == StepUpFaultPoint::kBeforeDecide)
                throw std::runtime_error("yuzu_test_line_one\nFORGED yuzu_test_line_two\x01");
        };
        yuzu::test::LogCapture capture;
        for (int i = 0; i < 100; ++i) {
            httplib::Response res;
            REQUIRE_NOTHROW(detail::apply_step_up_chokepoint(req, res, rig.deps()));
        }
        capture.stop();
        const auto logs = capture.text();
        CHECK(logs.find("yuzu_test_line_one?FORGED yuzu_test_line_two?") != std::string::npos);
        CHECK(logs.find("yuzu_test_line_one\n") == std::string::npos);
    }
    SECTION("a non-std exception takes the same fail-closed answer") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.fault_hook = [](StepUpFaultPoint p) {
            if (p == StepUpFaultPoint::kBeforeDecide)
                throw 42; // NOLINT(hicpp-exception-baseclass): the point of the test
        };
        httplib::Response res;
        StepUpChokepointResult result{};
        REQUIRE_NOTHROW(result = detail::apply_step_up_chokepoint(req, res, rig.deps()));
        CHECK(result == StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
        REQUIRE(rig.audits.size() == 1);
        CHECK(without_cid(rig.audits[0].detail) ==
              "user=alice reason=chokepoint_exception stage=pre_authz");
    }
}

TEST_CASE("chokepoint: a throwing audit emission is logged once per hundred, sanitised, and the "
          "refusal still stands",
          "[stepup][gate]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    Rig rig;
    // A stale proof: the chokepoint refuses with a challenge and tries to write the audit row.
    rig.session = make_session("alice", "local", Role::admin, ago(2h));

    SECTION("a std::exception: one sanitised line per 100 refusals") {
        rig.audit = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) -> bool {
            throw std::runtime_error("yuzu_test_audit_one\nFORGED yuzu_test_audit_two\x01");
        };
        yuzu::test::LogCapture capture;
        // The sampling counter is process-wide: a window of 100 hits holds exactly one multiple
        // of 100, so exactly one line is written whatever the counter held on entry.
        for (int i = 0; i < 100; ++i) {
            httplib::Response res;
            REQUIRE_NOTHROW(detail::apply_step_up_chokepoint(req, res, rig.deps()));
            CHECK(res.status == 401);
        }
        capture.stop();
        const auto logs = capture.text();
        CHECK(count_occurrences(logs, "mfa_step_up: audit emission threw:") == 1);
        CHECK(logs.find("yuzu_test_audit_one?FORGED yuzu_test_audit_two?") != std::string::npos);
        CHECK(logs.find("yuzu_test_audit_one\n") == std::string::npos);
        CHECK(rig.gate_count("refused", "local", "rest") == 100);
    }
    SECTION("a non-std exception: one line per 100 refusals") {
        rig.audit = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) -> bool {
            throw 42; // NOLINT(hicpp-exception-baseclass): the point of the test
        };
        yuzu::test::LogCapture capture;
        for (int i = 0; i < 100; ++i) {
            httplib::Response res;
            REQUIRE_NOTHROW(detail::apply_step_up_chokepoint(req, res, rig.deps()));
            CHECK(res.status == 401);
        }
        capture.stop();
        CHECK(count_occurrences(capture.text(), "audit emission threw non-std exception") == 1);
    }
}

TEST_CASE("chokepoint: a refusal storm is logged once per hundred but counted every time",
          "[stepup][gate]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    // UserNotFound is the 401 "status read failed" refusal, which logs at error level.
    rig.mfa_status = status_error(AuthDBError::UserNotFound);

    constexpr int kRefusals = 250;
    yuzu::test::LogCapture capture;
    for (int i = 0; i < kRefusals; ++i) {
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kRefused);
    }
    capture.stop();
    const auto lines = count_occurrences(capture.text(), "failing closed");
    // The sampling counter is process-wide: a window of 250 hits holds 2 or 3 multiples of 100.
    CHECK(lines >= 2);
    CHECK(lines <= 3);
    CHECK(rig.gate_count("refused", "local", "rest") == kRefusals);
    CHECK(rig.audits.size() == static_cast<std::size_t>(kRefusals));
}

TEST_CASE("render_step_up_refusal: X-Correlation-Id equals the body's correlation_id",
          "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kChallenge;
    v.user = "alice";
    httplib::Request req;

    SECTION("REST and dashboard envelopes") {
        for (const auto surface : {StepUpSurface::kRest, StepUpSurface::kDashboard}) {
            httplib::Response res;
            render_step_up_refusal(req, res, v, surface);
            const auto cid = res.get_header_value("X-Correlation-Id");
            CHECK_FALSE(cid.empty());
            CHECK(body_of(res)["error"]["correlation_id"] == cid);
        }
    }
    SECTION("the MCP error carries it in data") {
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kMcp);
        const auto cid = res.get_header_value("X-Correlation-Id");
        CHECK_FALSE(cid.empty());
        CHECK(body_of(res)["error"]["data"]["correlation_id"] == cid);
    }
    SECTION("a correlation id an upstream gate already set is reused, not replaced") {
        httplib::Response res;
        res.set_header("X-Correlation-Id", "req-upstream-1");
        render_step_up_refusal(req, res, v, StepUpSurface::kRest);
        CHECK(res.get_header_value("X-Correlation-Id") == "req-upstream-1");
        CHECK(body_of(res)["error"]["correlation_id"] == "req-upstream-1");
    }
    SECTION("the chokepoint's own refusals, including its no-session 401 and its fallback") {
        auto choke_req = make_request("POST", kTokensPattern, "/api/v1/tokens");
        {
            Rig rig; // no session
            httplib::Response res;
            REQUIRE(detail::apply_step_up_chokepoint(choke_req, res, rig.deps()) ==
                    StepUpChokepointResult::kRefused);
            CHECK(res.status == 401);
            CHECK(body_of(res)["error"]["correlation_id"] == res.get_header_value("X-Correlation-Id"));
            CHECK_FALSE(res.get_header_value("X-Correlation-Id").empty());
        }
        {
            Rig rig;
            rig.session = make_session("alice", "local", Role::admin, ago(10s));
            rig.fault_hook = [](StepUpFaultPoint p) {
                if (p == StepUpFaultPoint::kBeforeDecide)
                    throw std::runtime_error("evaluation failure");
            };
            httplib::Response res;
            REQUIRE(detail::apply_step_up_chokepoint(choke_req, res, rig.deps()) ==
                    StepUpChokepointResult::kRefused);
            CHECK(res.status == 503);
            CHECK(body_of(res)["error"]["correlation_id"] == res.get_header_value("X-Correlation-Id"));
        }
    }
}

TEST_CASE("chokepoint: OIDC proof states and enforcement modes", "[stepup][gate]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");

    SECTION("amr-less OIDC admin passes under optional, is refused under admin-only") {
        Rig rig;
        rig.session = make_session("oidc:iss#a", "oidc", Role::admin);
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kPassed);
        detail::clear_step_up_pass();

        rig.enforcement = "admin-only";
        httplib::Response res2;
        CHECK(detail::apply_step_up_chokepoint(req, res2, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res2.status == 401);
        CHECK(body_of(res2)["meta"]["challenge_url"] == "/auth/oidc/start");
    }
    SECTION("fresh amr proof passes in every mode") {
        for (const char* mode : {"optional", "admin-only", "required"}) {
            Rig rig;
            rig.session = make_session("oidc:iss#a", "oidc", Role::admin, ago(5s));
            rig.enforcement = mode;
            httplib::Response res;
            CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                  StepUpChokepointResult::kPassed);
            detail::clear_step_up_pass();
        }
    }
}

// ── the pass stash ───────────────────────────────────────────────────────────

TEST_CASE("pass stash: consumed once, for this request and this label only", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
            StepUpChokepointResult::kPassed);

    SECTION("a different action label does not consume it") {
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, "DELETE /api/v1/tokens/{id}", nullptr));
        CHECK(detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
    SECTION("a different request object does not consume it") {
        auto other = make_request("POST", kTokensPattern, "/api/v1/tokens");
        CHECK_FALSE(
            detail::consume_step_up_pass(other, *rig.session, std::string(kTokensLabel), nullptr));
        CHECK(detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
    SECTION("it is single-use: the second call re-evaluates") {
        CHECK(detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
    SECTION("a cleared stash (pre-routing / post-routing) is gone") {
        detail::clear_step_up_pass();
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
    detail::clear_step_up_pass();
}

namespace {
auth::Session engine_session(const std::string& user) {
    auto e = make_session(user, "engine_token", Role::admin, ago(5s));
    e.principal_kind = "engine";
    return e;
}
} // namespace

// A step-up pass is honoured only for the principal that earned it: the handler resolves its own
// session, and the identity of that session (exact principal class, plus a fingerprint of
// principal kind, auth source and username) must equal the one the chokepoint decided on.
TEST_CASE("pass identity: consumed only by the principal that earned it", "[stepup][gate][identity]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    const auto earned = *rig.session;
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
            StepUpChokepointResult::kPassed);

    // A mismatch refuses AND spends the pass: the earning principal cannot consume it afterwards
    // either. (That the spent pass is not reported as a skipped gate is pinned separately below,
    // where nothing consumes it before the post-routing report.)
    const auto refused_and_spent = [&](const auth::Session& handler_session) {
        CHECK_FALSE(
            detail::consume_step_up_pass(req, handler_session, std::string(kTokensLabel), nullptr));
        CHECK_FALSE(detail::consume_step_up_pass(req, earned, std::string(kTokensLabel), nullptr));
    };

    SECTION("the same identity consumes it, once") {
        CHECK(detail::consume_step_up_pass(req, earned, std::string(kTokensLabel), nullptr));
        CHECK_FALSE(detail::consume_step_up_pass(req, earned, std::string(kTokensLabel), nullptr));
    }
    SECTION("an equal-but-distinct session object (same fields) consumes it") {
        auto copy = make_session("alice", "local", Role::user, ago(1h));
        CHECK(detail::consume_step_up_pass(req, copy, std::string(kTokensLabel), nullptr));
    }
    SECTION("a different username is refused and the pass is spent") {
        refused_and_spent(make_session("bob", "local", Role::admin, ago(10s)));
    }
    SECTION("a different auth source is refused and the pass is spent") {
        refused_and_spent(make_session("alice", "oidc", Role::admin, ago(10s)));
    }
    SECTION("an API-token session of the same username is refused and the pass is spent") {
        refused_and_spent(make_session("alice", "api_token", Role::admin, ago(10s)));
    }
    SECTION("a different principal kind is refused and the pass is spent") {
        auto other = make_session("alice", "local", Role::admin, ago(10s));
        other.principal_kind = "engine";
        refused_and_spent(other);
    }
    SECTION("a different non-engine principal kind is refused on the fingerprint alone") {
        auto other = make_session("alice", "local", Role::admin, ago(10s));
        other.principal_kind = "service";
        refused_and_spent(other);
    }
    SECTION("an engine session behind a local pass is refused and the pass is spent") {
        refused_and_spent(engine_session("alice"));
    }
    SECTION("an engine session with a different name is refused too") {
        refused_and_spent(engine_session("engine:ci"));
    }
    SECTION("a refused pass is not reported as a skipped gate") {
        // Nothing consumes the pass after the mismatch, so the count below is decided by the
        // refusal alone: an unspent pass on this 2xx would be counted once.
        CHECK_FALSE(detail::consume_step_up_pass(req, make_session("bob", "local", Role::admin),
                                                 std::string(kTokensLabel), nullptr));
        httplib::Response done;
        done.status = 200;
        detail::finish_step_up_pass(req, done, &rig.metrics);
        CHECK(rig.gate_count("handler_skipped", "local", "rest") == 0);
    }
    SECTION("a refusal on identity leaves a later request's pass unaffected") {
        refused_and_spent(make_session("bob", "local", Role::admin, ago(10s)));
        httplib::Response res2;
        REQUIRE(detail::apply_step_up_chokepoint(req, res2, rig.deps()) ==
                StepUpChokepointResult::kPassed);
        CHECK(detail::consume_step_up_pass(req, earned, std::string(kTokensLabel), nullptr));
    }
}

TEST_CASE("pass identity: the engine class is an exact compare, never hash-only",
          "[stepup][gate][identity]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
            StepUpChokepointResult::kPassed);

    // Set the stashed fingerprint so every hash word equals the engine session's, leaving only
    // the exact class flag to tell them apart.
    const auto engine = engine_session("alice");
    detail::StepUpPassIdentity stashed;
    REQUIRE(detail::step_up_identity_of(engine, stashed));
    stashed.engine = false;
    detail::tls_step_up_pass().identity = stashed;
    CHECK_FALSE(detail::consume_step_up_pass(req, engine, std::string(kTokensLabel), nullptr));
}

TEST_CASE("pass identity: the fingerprint separates fields and is deterministic",
          "[stepup][gate][identity]") {
    const auto fp = [](const std::string& kind, const std::string& source, const std::string& user) {
        auth::Session s;
        s.principal_kind = kind;
        s.auth_source = source;
        s.username = user;
        detail::StepUpPassIdentity id;
        REQUIRE(detail::step_up_identity_of(s, id));
        return id;
    };
    CHECK(fp("human", "local", "alice") == fp("human", "local", "alice"));
    CHECK_FALSE(fp("human", "local", "alice") == fp("human", "local", "alicf"));
    CHECK_FALSE(fp("human", "local", "alice") == fp("human", "oidc", "alice"));
    CHECK_FALSE(fp("human", "local", "alice") == fp("engine", "local", "alice"));
    CHECK_FALSE(fp("human", "local", "alice") == fp("service", "local", "alice"));
    // The length prefix keeps a boundary shift between fields from producing the same encoding.
    CHECK_FALSE(fp("human", "local", "x") == fp("human", "loca", "lx"));
    CHECK_FALSE(fp("human", "", "local") == fp("human", "local", ""));
    CHECK(fp("engine", "local", "a").engine);
    CHECK(fp("human", "engine_token", "a").engine); // the engine auth source is an engine class
}

// ── the per-request principal binding ────────────────────────────────────────

namespace {
// Holds the digest-failure test seam on for one scope.
struct IdentityFault {
    IdentityFault() { detail::step_up_identity_fault_for_test().store(true); }
    ~IdentityFault() { detail::step_up_identity_fault_for_test().store(false); }
    IdentityFault(const IdentityFault&) = delete;
    IdentityFault& operator=(const IdentityFault&) = delete;
};
} // namespace

// One principal per request: once the chokepoint passes a gated request, a later session
// resolution for that request is admitted only for the principal the check was made for.
TEST_CASE("binding: later resolutions for a gated request are admitted only for its principal",
          "[stepup][gate][stepbind]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    const auto alice = *rig.session;
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");

    SECTION("no stash: every session is admitted") {
        CHECK(detail::step_up_binding_admits(req, alice));
        CHECK(detail::step_up_binding_admits(req, make_session("bob", "local", Role::user)));
    }

    httplib::Response res;
    // The section above leaves nothing armed; the rest arm the stash for alice first.
    const auto arm = [&] {
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kPassed);
    };

    SECTION("armed: the same identity is admitted, whatever its role or proof age") {
        arm();
        CHECK(detail::step_up_binding_admits(req, alice));
        CHECK(detail::step_up_binding_admits(req, make_session("alice", "local", Role::user,
                                                               ago(2h))));
    }
    SECTION("armed: a different username, auth source, principal kind or engine class is refused") {
        arm();
        CHECK_FALSE(detail::step_up_binding_admits(req, make_session("bob", "local", Role::admin)));
        CHECK_FALSE(detail::step_up_binding_admits(req, make_session("alice", "oidc", Role::admin)));
        CHECK_FALSE(
            detail::step_up_binding_admits(req, make_session("alice", "api_token", Role::admin)));
        auto other_kind = make_session("alice", "local", Role::admin);
        other_kind.principal_kind = "service";
        CHECK_FALSE(detail::step_up_binding_admits(req, other_kind));
        CHECK_FALSE(detail::step_up_binding_admits(req, engine_session("alice")));
        CHECK_FALSE(detail::step_up_binding_admits(req, engine_session("engine:ci")));
        // A refusal does not disarm the binding: the bound principal is still admitted.
        CHECK(detail::step_up_binding_admits(req, alice));
    }
    SECTION("armed for another request address: this request is unbound") {
        arm();
        auto other = make_request("POST", kTokensPattern, "/api/v1/tokens");
        REQUIRE(&other != &req);
        CHECK(detail::step_up_binding_admits(other, make_session("bob", "local", Role::admin)));
    }
    SECTION("the binding outlives the pass: it holds after the pass is spent") {
        arm();
        REQUIRE(detail::consume_step_up_pass(req, alice, std::string(kTokensLabel), nullptr));
        CHECK(detail::step_up_binding_admits(req, alice));
        CHECK_FALSE(detail::step_up_binding_admits(req, make_session("bob", "local", Role::admin)));
        CHECK_FALSE(detail::step_up_binding_admits(req, engine_session("engine:ci")));
    }
    SECTION("the binding also outlives a pass refused for identity") {
        arm();
        CHECK_FALSE(detail::consume_step_up_pass(req, make_session("bob", "local", Role::admin),
                                                 std::string(kTokensLabel), nullptr));
        CHECK(detail::step_up_binding_admits(req, alice));
        CHECK_FALSE(detail::step_up_binding_admits(req, make_session("bob", "local", Role::admin)));
    }
    SECTION("the end-of-request clears drop the binding") {
        arm();
        SECTION("pre-routing / fail-closed clear") {
            detail::clear_step_up_pass();
        }
        SECTION("post-routing report") {
            httplib::Response done;
            done.status = 200;
            detail::finish_step_up_pass(req, done, &rig.metrics);
        }
        CHECK(detail::step_up_binding_admits(req, make_session("bob", "local", Role::admin)));
    }
    SECTION("a refused request arms no binding") {
        rig.session = make_session("alice", "local", Role::admin, ago(1h));
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kRefused);
        CHECK(detail::step_up_binding_admits(req, make_session("bob", "local", Role::admin)));
    }
    detail::clear_step_up_pass();
}

TEST_CASE("binding: a refusal logs one fixed-text warning per hundred and never names the principal",
          "[stepup][gate][stepbind]") {
    Rig rig;
    rig.session = make_session("yuzu_test_alice", "local", Role::admin, ago(10s));
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
            StepUpChokepointResult::kPassed);
    const auto other = make_session("yuzu_test_carol", "local", Role::admin, ago(10s));

    yuzu::test::LogCapture capture;
    // The line is sampled and the counter is process-wide, so drive a full period.
    for (int i = 0; i < 100; ++i)
        REQUIRE_FALSE(detail::step_up_binding_admits(req, other));
    capture.stop();
    const auto logs = capture.text();
    CHECK(count_occurrences(logs, "not the principal the step-up check was made for") == 1);
    CHECK(logs.find("yuzu_test_alice") == std::string::npos);
    CHECK(logs.find("yuzu_test_carol") == std::string::npos);
    detail::clear_step_up_pass();
}

// A digest that cannot be computed fails closed at every site that needs one.
TEST_CASE("binding: an identity digest failure fails closed at the chokepoint, consume and binding",
          "[stepup][gate][stepbind]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    const auto alice = *rig.session;
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;

    SECTION("chokepoint: the request is refused 503 and nothing is armed") {
        {
            const IdentityFault fault;
            REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                    StepUpChokepointResult::kRefused);
        }
        CHECK(res.status == 503);
        // Counted as an unavailable evaluation, never as a pass.
        CHECK(rig.gate_count("pass", "local", "rest") == 0);
        CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].detail.find("reason=chokepoint_exception") != std::string::npos);
        // No pass and no binding: a later resolution is unconstrained, and a consume finds nothing.
        CHECK(detail::step_up_binding_admits(req, make_session("bob", "local", Role::admin)));
        CHECK_FALSE(detail::consume_step_up_pass(req, alice, std::string(kTokensLabel), nullptr));
    }
    SECTION("consume: false, and the pass is spent") {
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kPassed);
        {
            const IdentityFault fault;
            CHECK_FALSE(
                detail::consume_step_up_pass(req, alice, std::string(kTokensLabel), nullptr));
        }
        // Spent: the principal that earned it cannot consume it once the digest works again.
        CHECK_FALSE(detail::consume_step_up_pass(req, alice, std::string(kTokensLabel), nullptr));
        // The binding is untouched.
        CHECK(detail::step_up_binding_admits(req, alice));
        CHECK_FALSE(detail::step_up_binding_admits(req, make_session("bob", "local", Role::admin)));
    }
    SECTION("binding check: an armed binding admits nobody while the digest fails") {
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kPassed);
        {
            const IdentityFault fault;
            CHECK_FALSE(detail::step_up_binding_admits(req, alice));
            CHECK_FALSE(detail::step_up_binding_admits(req, make_session("bob", "local", Role::admin)));
        }
        CHECK(detail::step_up_binding_admits(req, alice));
    }
    SECTION("binding check: with no binding armed the digest is never needed") {
        const IdentityFault fault;
        CHECK(detail::step_up_binding_admits(req, alice));
    }
    detail::clear_step_up_pass();
}

// ── the binding applied by the real AuthRoutes::resolve_session ──────────────

namespace {
// A real AuthRoutes over a real AuthManager with no Postgres: cookie sessions only. An optional
// ApiTokenStore (Postgres) adds the Bearer and X-Yuzu-Token credential paths.
struct ResolveBindingFixture {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> routes;

    explicit ResolveBindingFixture(ApiTokenStore* tokens = nullptr) {
        routes = std::make_unique<AuthRoutes>(cfg, auth_mgr, /*rbac_store=*/nullptr, tokens,
                                              /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr,
                                              /*tag_store=*/nullptr, /*analytics_store=*/nullptr,
                                              oidc_mu, oidc_provider);
    }

    // Mints a cookie session and returns its token.
    std::string mint(const std::string& user) {
        REQUIRE(auth_mgr.upsert_user(user, "password1234", Role::admin));
        return auth_mgr.create_local_session_for_test(user, Role::admin, /*mfa_verified=*/true);
    }

    // A request on a kRequired row carrying the given headers.
    static httplib::Request gated_request(
        std::initializer_list<std::pair<const char*, std::string>> headers) {
        auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
        for (const auto& [k, v] : headers)
            req.headers.emplace(k, v);
        return req;
    }

    // Arms the stash for `req` as the central check does, on the principal `req` resolves to now.
    StepUpChokepointResult arm_for(Rig& rig, const httplib::Request& req) {
        rig.session = routes->resolve_session(req);
        REQUIRE(rig.session.has_value());
        rig.mfa_status = status_not_enrolled();
        httplib::Response res;
        return detail::apply_step_up_chokepoint(req, res, rig.deps());
    }
};
} // namespace

TEST_CASE("resolve_session: a gated request resolves to the principal it was passed for, or none",
          "[stepup][gate][stepbind][auth_routes]") {
    ResolveBindingFixture fix;
    const auto alice_cookie = fix.mint("yuzu_test_alice");
    const auto bob_cookie = fix.mint("yuzu_test_bob");
    Rig rig;

    SECTION("control: with no binding armed each credential resolves to its own principal") {
        const auto req = ResolveBindingFixture::gated_request({{"Cookie", "yuzu_session=" + bob_cookie}});
        const auto s = fix.routes->resolve_session(req);
        REQUIRE(s.has_value());
        CHECK(s->username == "yuzu_test_bob");
    }
    SECTION("armed for alice: her own credential still resolves, on every later resolution") {
        const auto req =
            ResolveBindingFixture::gated_request({{"Cookie", "yuzu_session=" + alice_cookie}});
        REQUIRE(fix.arm_for(rig, req) == StepUpChokepointResult::kPassed);
        for (int i = 0; i < 3; ++i) {
            const auto s = fix.routes->resolve_session(req);
            REQUIRE(s.has_value());
            CHECK(s->username == "yuzu_test_alice");
        }
    }
    SECTION("armed for alice: a resolution that lands on bob's cookie is no session") {
        auto req = ResolveBindingFixture::gated_request({{"Cookie", "yuzu_session=" + alice_cookie}});
        REQUIRE(fix.arm_for(rig, req) == StepUpChokepointResult::kPassed);
        // The same request object now presents bob's credential, as a later resolution would see
        // after the first credential stops validating and another takes its place.
        req.headers.clear();
        req.headers.emplace("Cookie", "yuzu_session=" + bob_cookie);
        CHECK_FALSE(fix.routes->resolve_session(req).has_value());
    }
    SECTION("armed for alice: require_auth answers its ordinary 401 for another principal") {
        auto req = ResolveBindingFixture::gated_request({{"Cookie", "yuzu_session=" + alice_cookie}});
        REQUIRE(fix.arm_for(rig, req) == StepUpChokepointResult::kPassed);
        req.headers.clear();
        req.headers.emplace("Cookie", "yuzu_session=" + bob_cookie);
        httplib::Response res;
        CHECK_FALSE(fix.routes->require_auth(req, res).has_value());
        CHECK(res.status == 401);
    }
    SECTION("armed for alice: another request is not constrained") {
        const auto req =
            ResolveBindingFixture::gated_request({{"Cookie", "yuzu_session=" + alice_cookie}});
        REQUIRE(fix.arm_for(rig, req) == StepUpChokepointResult::kPassed);
        const auto other =
            ResolveBindingFixture::gated_request({{"Cookie", "yuzu_session=" + bob_cookie}});
        const auto s = fix.routes->resolve_session(other);
        REQUIRE(s.has_value());
        CHECK(s->username == "yuzu_test_bob");
    }
    SECTION("the end-of-request clear lifts the binding") {
        auto req = ResolveBindingFixture::gated_request({{"Cookie", "yuzu_session=" + alice_cookie}});
        REQUIRE(fix.arm_for(rig, req) == StepUpChokepointResult::kPassed);
        detail::clear_step_up_pass();
        req.headers.clear();
        req.headers.emplace("Cookie", "yuzu_session=" + bob_cookie);
        const auto s = fix.routes->resolve_session(req);
        REQUIRE(s.has_value());
        CHECK(s->username == "yuzu_test_bob");
    }
}

TEST_CASE("resolve_session: the binding holds on the Bearer and X-Yuzu-Token paths and across a "
          "credential change",
          "[pg][stepup][gate][stepbind][auth_routes]") {
    yuzu::test::ApiTokenStorePg api_tokens;
    ResolveBindingFixture fix(api_tokens.get());
    const auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
    const auto alice_cookie = fix.mint("yuzu_test_alice");
    REQUIRE(fix.auth_mgr.upsert_user("yuzu_test_bob", "password1234", Role::admin));
    const auto bob_raw =
        api_tokens->create_token("binding-bob", "yuzu_test_bob", now_s + 3600, "", "");
    REQUIRE(bob_raw.has_value());
    Rig rig;

    const auto header_name = GENERATE(as<std::string>{}, "Authorization", "X-Yuzu-Token");
    INFO("credential header: " << header_name);
    const auto bob_credential = header_name == "Authorization" ? "Bearer " + *bob_raw : *bob_raw;

    SECTION("control: with no binding armed the token resolves to bob") {
        const auto req = ResolveBindingFixture::gated_request({{header_name.c_str(), bob_credential}});
        const auto s = fix.routes->resolve_session(req);
        REQUIRE(s.has_value());
        CHECK(s->username == "yuzu_test_bob");
    }
    SECTION("armed for alice: a token credential for another principal is no session") {
        auto req = ResolveBindingFixture::gated_request({{"Cookie", "yuzu_session=" + alice_cookie}});
        REQUIRE(fix.arm_for(rig, req) == StepUpChokepointResult::kPassed);
        req.headers.clear();
        req.headers.emplace(header_name, bob_credential);
        CHECK_FALSE(fix.routes->resolve_session(req).has_value());
    }
    SECTION("armed for alice: when her cookie stops validating, the fall-through to bob's token "
            "is no session") {
        const auto req = ResolveBindingFixture::gated_request(
            {{"Cookie", "yuzu_session=" + alice_cookie}, {header_name.c_str(), bob_credential}});
        REQUIRE(fix.arm_for(rig, req) == StepUpChokepointResult::kPassed);
        REQUIRE(fix.auth_mgr.invalidate_session(alice_cookie));
        CHECK_FALSE(fix.routes->resolve_session(req).has_value());
    }
    SECTION("control: the same fall-through with no binding armed resolves to bob") {
        const auto req = ResolveBindingFixture::gated_request(
            {{"Cookie", "yuzu_session=" + alice_cookie}, {header_name.c_str(), bob_credential}});
        const auto first = fix.routes->resolve_session(req);
        REQUIRE(first.has_value());
        CHECK(first->username == "yuzu_test_alice");
        REQUIRE(fix.auth_mgr.invalidate_session(alice_cookie));
        const auto second = fix.routes->resolve_session(req);
        REQUIRE(second.has_value());
        CHECK(second->username == "yuzu_test_bob");
    }
}

TEST_CASE("pass stash: an unconsumed pass on a 2xx response is counted handler_skipped",
          "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
            StepUpChokepointResult::kPassed);

    SECTION("2xx and never consumed: counted, then cleared") {
        httplib::Response out;
        out.status = 200;
        detail::finish_step_up_pass(req, out, &rig.metrics);
        CHECK(rig.gate_count("handler_skipped", "local", "rest") == 1);
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
    SECTION("a consumed pass is not counted") {
        REQUIRE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
        httplib::Response out;
        out.status = 200;
        detail::finish_step_up_pass(req, out, &rig.metrics);
        CHECK(rig.gate_count("handler_skipped", "local", "rest") == 0);
    }
    SECTION("a non-2xx response is not counted, but the stash is still cleared") {
        httplib::Response out;
        out.status = 403;
        detail::finish_step_up_pass(req, out, &rig.metrics);
        CHECK(rig.gate_count("handler_skipped", "local", "rest") == 0);
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
}

// The stash is a thread_local, and successive requests on one httplib worker thread can share a
// `httplib::Request` address, so the address is not a key. These cases run the sequences the
// clear sites in server.cpp (pre-routing top, post-routing) and the chokepoint's fail-closed
// path exist for, through the same `detail::` entry points those sites call. Consume is not a
// clear site: it spends the pass and leaves the binding armed.
// server.cpp's own calls are pinned by test_step_up_wiring.cpp.
TEST_CASE("pass stash lifecycle: a pass armed by request A is not consumable by request B at the "
          "same address",
          "[stepup][gate][lifecycle]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    // ONE object stands for both requests: B reuses A's address, as the next request on a worker
    // thread can. Only its fields change between them.
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res_a;
    REQUIRE(detail::apply_step_up_chokepoint(req, res_a, rig.deps()) ==
            StepUpChokepointResult::kPassed);
    const httplib::Request* const address_of_a = &req;

    // B: same address, same registered row (so the same action label).
    auto become_request_b = [&] {
        req.path = "/api/v1/tokens";
        req.matched_route = std::string(kTokensPattern);
        REQUIRE(&req == address_of_a);
    };

    SECTION("control: with NO clear between them the address and label alone admit B") {
        // This is why the clears exist: nothing in the stash distinguishes A from B.
        become_request_b();
        CHECK(detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
    SECTION("the post-routing handler of A clears it (and reports it once if A skipped its gate)") {
        httplib::Response a_done;
        a_done.status = 200;
        detail::finish_step_up_pass(req, a_done, &rig.metrics);
        CHECK(rig.gate_count("handler_skipped", "local", "rest") == 1);
        become_request_b();
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
    SECTION("post-routing clears on a non-2xx response too, without reporting it") {
        httplib::Response a_failed;
        a_failed.status = 500;
        detail::finish_step_up_pass(req, a_failed, &rig.metrics);
        CHECK(rig.gate_count("handler_skipped", "local", "rest") == 0);
        become_request_b();
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
    SECTION("the pre-routing top of B clears a pass A left (A's post-routing never ran)") {
        // What the first statements of server.cpp's pre-routing handler do for a request that
        // follows one which bypassed post-routing.
        detail::clear_step_up_pass();
        become_request_b();
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
    SECTION("a refused request B does not inherit A's pass, and its post-routing clears it") {
        rig.session = make_session("alice", "local", Role::admin, ago(1h));
        httplib::Response res_b;
        become_request_b();
        REQUIRE(detail::apply_step_up_chokepoint(req, res_b, rig.deps()) ==
                StepUpChokepointResult::kRefused);
        // A refused B is Handled, so no handler runs; post-routing must still leave nothing armed.
        detail::finish_step_up_pass(req, res_b, &rig.metrics);
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
        CHECK(rig.gate_count("handler_skipped", "local", "rest") == 0);
    }
    SECTION("a different action label at the same address never consumes it, and keeps it") {
        CHECK_FALSE(
            detail::consume_step_up_pass(req, *rig.session, "DELETE /api/v1/tokens/{id}", nullptr));
        // The refused attempt did not burn A's pass: only a matching consume or a clear does.
        CHECK(detail::consume_step_up_pass(req, *rig.session, std::string(kTokensLabel), nullptr));
    }
}

TEST_CASE("pass stash lifecycle: a Rig leaves no stash behind for the next test",
          "[stepup][gate][lifecycle]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    {
        Rig first;
        first.session = make_session("alice", "local", Role::admin, ago(10s));
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(req, res, first.deps()) ==
                StepUpChokepointResult::kPassed);
        // Deliberately neither consumed nor cleared: a failing REQUIRE would leave exactly this.
    }
    const auto alice = make_session("alice", "local", Role::admin, ago(10s));
    CHECK_FALSE(detail::consume_step_up_pass(req, alice, std::string(kTokensLabel), nullptr));
}

TEST_CASE("pass stash lifecycle: a Rig starts with an empty stash", "[stepup][gate][lifecycle]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    // Arm the thread_local directly, as a stash leaked by a test that has no Rig would be.
    auto& stash = detail::tls_step_up_pass();
    stash.req = &req;
    stash.row = step_up_policy_for("POST", kTokensPattern);
    REQUIRE(stash.row != nullptr);
    Rig next;
    const auto alice = make_session("alice", "local", Role::admin, ago(10s));
    CHECK_FALSE(detail::consume_step_up_pass(req, alice, std::string(kTokensLabel), nullptr));
}

// ── in-handler fail-closed helper ────────────────────────────────────────────

TEST_CASE("refuse_step_up_store_unwired: 503 + audit + metric", "[stepup][gate]") {
    Rig rig;
    const auto session = make_session("alice", "local", Role::admin, ago(10s));
    httplib::Request req;
    httplib::Response res;
    refuse_step_up_store_unwired(req, res, session, rig.audit, "POST /api/v1/elevate",
                                 &rig.metrics);
    CHECK(res.status == 503);
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].target_id == "POST /api/v1/elevate");
    CHECK(rig.audits[0].detail == "user=alice reason=auth_store_unwired");
    CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
}

// An OIDC `sub` or SAML NameID reaches session.username with spaces, '=' and ',' intact. The
// refusal row is read as space-delimited key=value by SIEM rules, so the subject must not be
// able to add tokens: a hostile subject must not forge `reason=engine_principal_denied` (#6079).
TEST_CASE("refusal audit: a hostile subject is neutralised in every decision's detail",
          "[stepup][gate]") {
    const std::string hostile = "evil reason=engine_principal_denied,x";
    const std::string safe = "evil_reason_engine_principal_denied_x";
    for (const auto decision : {StepUpDecision::kChallenge, StepUpDecision::kSamlDenied,
                                StepUpDecision::kStoreUnavailable, StepUpDecision::kStatusFailed,
                                StepUpDecision::kUnwired, StepUpDecision::kUnsupportedClass,
                                StepUpDecision::kEvaluationFailed, StepUpDecision::kEngineDenied}) {
        Rig rig;
        StepUpVerdict v;
        v.decision = decision;
        v.user = hostile;
        v.age_secs = 5;
        v.window_secs = 300;
        httplib::Request req;
        emit_step_up_refusal_effects(req, v, rig.audit, "POST /api/v1/elevate", {}, &rig.metrics);
        REQUIRE(rig.audits.size() == 1);
        INFO("decision " << static_cast<int>(decision));
        CHECK(rig.audits[0].detail.rfind("user=" + safe, 0) == 0);
        // Exactly one reason= token at most: the forged one is gone.
        const auto first = rig.audits[0].detail.find("reason=");
        if (first != std::string::npos)
            CHECK(rig.audits[0].detail.find("reason=", first + 1) == std::string::npos);
        CHECK(rig.audits[0].detail.find(hostile) == std::string::npos);
    }
}

// ── equivalence matrix against a real AuthDB ─────────────────────────────────

namespace {

struct EquivFixture {
    yuzu::test::AuthDbPg db;
    std::vector<AuditRow> audits;
    StepUpAuditFn audit_fn;

    EquivFixture() {
        auto salt_a = AuthManager::random_bytes(16);
        auto hash_a = AuthManager::pbkdf2_sha256("pw", salt_a, 1000);
        REQUIRE(db->upsert_user("alice", hash_a, AuthManager::bytes_to_hex(salt_a), Role::admin)
                    .has_value());
        auto salt_b = AuthManager::random_bytes(16);
        auto hash_b = AuthManager::pbkdf2_sha256("pw", salt_b, 1000);
        REQUIRE(db->upsert_user("bob", hash_b, AuthManager::bytes_to_hex(salt_b), Role::user)
                    .has_value());
        auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
        REQUIRE(init.has_value());
        auto bytes = mfa::base32_decode(init->secret_base32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
        REQUIRE(db->mfa_verify_enrollment("alice", code, std::nullopt).has_value());

        audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                          const std::string& tt, const std::string& ti,
                          const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return true;
        };
    }
};

struct Cell {
    const char* name;
    std::string user;
    std::string source;
    Role role;
    std::chrono::system_clock::time_point verified_at;
    std::string mode;
    int window;
    int expected_status; // 200 = pass
};

} // namespace

TEST_CASE_METHOD(EquivFixture,
                 "step-up equivalence matrix: decide_step_up, require_mfa_step_up and the "
                 "historical status agree for every cell",
                 "[pg][mfa][stepup]") {
    const auto fresh = ago(10s);
    const auto stale = ago(1h);
    const auto none = std::chrono::system_clock::time_point{};

    std::vector<Cell> cells;
    for (const char* mode : {"optional", "admin-only", "required"}) {
        const std::string m = mode;
        // local, MFA-enrolled alice
        cells.push_back(
            {"local enrolled fresh", "alice", "local", Role::admin, fresh, m, 300, 200});
        cells.push_back(
            {"local enrolled stale", "alice", "local", Role::admin, stale, m, 300, 401});
        cells.push_back(
            {"local enrolled no proof", "alice", "local", Role::admin, none, m, 300, 401});
        // local, un-enrolled bob passes in every mode (enrolment is forced at login, not here)
        cells.push_back(
            {"local un-enrolled stale", "bob", "local", Role::user, stale, m, 300, 200});
        cells.push_back(
            {"local un-enrolled no proof", "bob", "local", Role::user, none, m, 300, 200});
        // a user with no row fails closed
        cells.push_back({"local unknown user", "ghost", "local", Role::user, fresh, m, 300, 401});
        // OIDC: proof states
        cells.push_back(
            {"oidc fresh amr proof", "oidc:i#a", "oidc", Role::admin, fresh, m, 300, 200});
        cells.push_back(
            {"oidc stale amr proof", "oidc:i#a", "oidc", Role::admin, stale, m, 300, 401});
        // OIDC with no amr proof: depends on the mode and the role
        const bool admin_protected = (m != "optional");
        const bool user_protected = (m == "required");
        cells.push_back({"oidc admin no amr", "oidc:i#a", "oidc", Role::admin, none, m, 300,
                         admin_protected ? 401 : 200});
        cells.push_back({"oidc user no amr", "oidc:i#u", "oidc", Role::user, none, m, 300,
                         user_protected ? 401 : 200});
        // SAML is a 403 in every mode
        cells.push_back({"saml", "saml-user", "saml", Role::admin, fresh, m, 300, 403});
        // API and MCP token principals pass; an engine principal is a 403 whatever its role
        cells.push_back({"api_token", "tok", "api_token", Role::admin, none, m, 300, 200});
        cells.push_back({"mcp_token", "tok", "mcp_token", Role::admin, none, m, 300, 200});
        cells.push_back(
            {"engine_token", "engine:x", "engine_token", Role::user, none, m, 300, 403});
        cells.push_back(
            {"engine_token admin", "engine:x", "engine_token", Role::admin, fresh, m, 300, 403});
        // the window hatch passes every identity that would refuse, except an engine, which the
        // hatch does not admit
        for (const int w : {0, -1}) {
            cells.push_back({"hatch local stale", "alice", "local", Role::admin, stale, m, w, 200});
            cells.push_back({"hatch saml", "saml-user", "saml", Role::admin, fresh, m, w, 200});
            cells.push_back(
                {"hatch engine", "engine:x", "engine_token", Role::user, none, m, w, 403});
        }
    }

    for (const auto& c : cells) {
        DYNAMIC_SECTION(c.name << " / user=" << c.user << " mode=" << c.mode
                               << " window=" << c.window) {
            const auto session = make_session(c.user, c.source, c.role, c.verified_at);

            // A stored proof bound to alice's real generation and aged like the session's own.
            const auto alice_gen = db->mfa_status("alice").value().factor_gen;
            const DurableProofReadFn read = [&] {
                return durable_matching(session, alice_gen);
            };
            const DurableProofFn durable_fn = [&](const httplib::Request&, const auth::Session& s) {
                return durable_matching(s, alice_gen);
            };

            const auto verdict =
                decide_step_up(session, *db, read, c.window, c.mode, StepUpClass::kRequired);

            httplib::Request req;
            httplib::Response res;
            res.status = 200;
            audits.clear();
            const bool passed =
                require_mfa_step_up(req, res, session, *db, c.window, audit_fn,
                                    "POST /api/v1/whatever", c.mode, nullptr, &durable_fn, nullptr);

            // Both entry points against the hand-written expectation, never against each other.
            CHECK(verdict.passed() == (c.expected_status == 200));
            CHECK(passed == (c.expected_status == 200));
            if (!passed) {
                CHECK(res.status == c.expected_status);
                // The renderer, called directly, writes the status the table expects.
                httplib::Response direct;
                render_step_up_refusal(req, direct, verdict, StepUpSurface::kRest);
                CHECK(direct.status == c.expected_status);
                auto a = body_of(direct);
                auto b = body_of(res);
                a["error"].erase("correlation_id");
                b["error"].erase("correlation_id");
                CHECK(a == b);
                // One audit row per refusal, none on a pass.
                CHECK(audits.size() == 1);
            } else {
                CHECK(res.status == 200);
                CHECK(res.body.empty());
                CHECK(audits.empty());
            }
        }
    }
}

TEST_CASE_METHOD(EquivFixture,
                 "step-up chokepoint over a real AuthDB: stale refused, fresh passes, un-enrolled "
                 "passes",
                 "[pg][mfa][stepup]") {
    yuzu::MetricsRegistry metrics;
    std::optional<auth::Session> session;
    const StepUpSessionFn resolver = [&](const httplib::Request&) {
        return session;
    };
    const auto alice_gen = db->mfa_status("alice").value().factor_gen;
    const DurableProofFn durable_fn = [alice_gen](const httplib::Request&, const auth::Session& s) {
        return durable_matching(s, alice_gen);
    };
    auto make_deps = [&] {
        return StepUpChokepointDeps{.resolve_session = &resolver,
                                    .auth_db = db.get(),
                                    .mfa_status = nullptr,
                                    .durable_proof = &durable_fn,
                                    .audit_fn = &audit_fn,
                                    .metrics = &metrics,
                                    .window_secs = 300,
                                    .mfa_enforcement = "optional"};
    };
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");

    session = make_session("alice", "local", Role::admin, ago(1h));
    httplib::Response stale_res;
    CHECK(detail::apply_step_up_chokepoint(req, stale_res, make_deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(stale_res.status == 401);
    REQUIRE(audits.size() == 1);
    CHECK(audits[0].detail.ends_with(" stage=pre_authz"));

    audits.clear();
    session = make_session("alice", "local", Role::admin, ago(5s));
    httplib::Response fresh_res;
    CHECK(detail::apply_step_up_chokepoint(req, fresh_res, make_deps()) ==
          StepUpChokepointResult::kPassed);
    CHECK(fresh_res.status == -1);
    CHECK(audits.empty());
    detail::clear_step_up_pass();

    session = make_session("bob", "local", Role::user, ago(1h));
    httplib::Response bob_res;
    CHECK(detail::apply_step_up_chokepoint(req, bob_res, make_deps()) ==
          StepUpChokepointResult::kPassed);
    detail::clear_step_up_pass();
}

// ── both gates over real stores: the chain, the legacy interleaving, the mixed version (#6079) ──
//
// A real AuthDB, a real SessionStore behind a real AuthManager, the chokepoint wired the way
// server.cpp wires it (the cookie resolves the session, the stored proof is read through the same
// cookie), and the REAL approval routes behind the REAL approver gate. The factor-credential
// handler is a stub that does what the Settings handler does once the gate has admitted it: it
// regenerates the recovery codes at the admitted generation. Nothing here ends a session, so the
// survivors are exactly what a partial hygiene delete leaves behind.

namespace {

struct ChainFixture {
    yuzu::test::AuthDbPg db;
    SessionStore store{db.pool()};
    AuthManager mgr;
    std::vector<AuditRow> audits;
    StepUpAuditFn audit_fn;
    yuzu::MetricsRegistry metrics;

    ChainFixture() {
        REQUIRE(store.is_open());
        mgr.set_auth_db(db.get());
        mgr.set_session_store(&store);
        const auto salt = AuthManager::random_bytes(16);
        const auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
        REQUIRE(db->upsert_user("alice", hash, AuthManager::bytes_to_hex(salt), Role::admin)
                    .has_value());
        enroll("alice");
        audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                          const std::string& tt, const std::string& ti,
                          const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return true;
        };
    }
    ~ChainFixture() { mgr.set_session_store(nullptr); }
    ChainFixture(const ChainFixture&) = delete;
    ChainFixture& operator=(const ChainFixture&) = delete;

    void enroll(const std::string& user) {
        auto init = db->mfa_init_enrollment(user, "Yuzu", std::nullopt);
        REQUIRE(init.has_value());
        auto bytes = mfa::base32_decode(init->secret_base32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
        REQUIRE(db->mfa_verify_enrollment(user, code, std::nullopt).has_value());
    }

    // The clear + re-enrol of a factor replacement, WITHOUT ending any session.
    void replace_factor(const std::string& user) {
        REQUIRE(db->mfa_disable_report(user, std::nullopt).has_value());
        enroll(user);
    }

    // A cookie session carrying a proof bound to the account's current factor.
    std::string session_bound(const std::string& user = "alice") {
        auto token = mgr.create_local_session_for_test(user, Role::admin, /*mfa_verified=*/true);
        REQUIRE_FALSE(token.empty());
        return token;
    }

    std::int64_t gen_of(const std::string& user) {
        const auto st = db->mfa_status(user);
        REQUIRE(st.has_value());
        return st->factor_gen;
    }

    yuzu::test::ApproverRouteFixture::DurableFn durable_fn() {
        return [this](const httplib::Request& req, const auth::Session& s) {
            return mgr.read_durable_mfa_proof(AuthRoutes::extract_session_cookie(req), s.username);
        };
    }

    // The central chokepoint for `pattern`, with the cookie `token`, on the real stores.
    StepUpChokepointResult gate(const std::string& token, std::string_view pattern,
                                httplib::Response& res, int window_secs = 300) {
        // The pass stash is keyed on the request's address, so the request outlives this call.
        pass_req =
            std::make_unique<httplib::Request>(make_request("POST", pattern, std::string(pattern)));
        auto& req = *pass_req;
        req.set_header("Cookie", "yuzu_session=" + token);
        const StepUpSessionFn resolver = [this](const httplib::Request& r) {
            return mgr.validate_session(AuthRoutes::extract_session_cookie(r));
        };
        const DurableProofFn durable = durable_fn();
        const StepUpChokepointDeps deps{.resolve_session = &resolver,
                                        .auth_db = db.get(),
                                        .mfa_status = nullptr,
                                        .durable_proof = &durable,
                                        .audit_fn = &audit_fn,
                                        .metrics = &metrics,
                                        .window_secs = window_secs,
                                        .mfa_enforcement = "optional"};
        return detail::apply_step_up_chokepoint(req, res, deps);
    }
    std::unique_ptr<httplib::Request> pass_req;
    int in_handler_durable_reads{0};

    // What the Settings recovery-codes handler does behind an admitting gate. Returns the new
    // codes, or nullopt when the gate refused (nothing is written then).
    std::optional<std::vector<std::string>> regenerate_behind_gate(const std::string& token) {
        httplib::Response res;
        const auto result = gate(token, "/api/settings/mfa/recovery-codes", res);
        if (result != StepUpChokepointResult::kPassed)
            return std::nullopt;
        StepUpAdmission admitted;
        const auto session = mgr.validate_session(token);
        REQUIRE(session.has_value());
        REQUIRE(detail::consume_step_up_pass(*pass_req, *session,
                                             "POST /api/settings/mfa/recovery-codes", &admitted));
        REQUIRE(admitted.local);
        auto codes = db->mfa_regenerate_recovery_codes("alice", admitted.factor_gen);
        REQUIRE(codes.has_value());
        return *codes;
    }

    // What the production in-handler wrapper does for a kFactorCredential route after the
    // chokepoint armed a pass: `run_in_handler_step_up` must consume that pass AND hand the
    // admission back. A wrapper that forwards `nullptr` instead of the caller's `admitted`
    // leaves the handler without the admitted generation, so both factor-credential routes
    // answer 403 "not local" in production while every other test stays green (qe-Q1).
    bool run_in_handler_admits(const std::string& token, StepUpAdmission& admitted) {
        httplib::Response res;
        const auto result = gate(token, "/api/settings/mfa/recovery-codes", res);
        if (result != StepUpChokepointResult::kPassed)
            return false;
        const auto session = mgr.validate_session(token);
        REQUIRE(session.has_value());
        httplib::Response in_handler_res;
        // Counts the stored-proof reads the in-handler wrapper performs: a consumed pass reads
        // none, whereas a wrapper that skipped the pass and re-evaluated would read it (and also
        // fill `admitted`, which is why `admitted` alone cannot tell the two apart).
        const DurableProofFn durable = [this](const httplib::Request& r, const auth::Session& s) {
            ++in_handler_durable_reads;
            return durable_fn()(r, s);
        };
        return detail::run_in_handler_step_up(
            *pass_req, in_handler_res, *session, "POST /api/settings/mfa/recovery-codes", db.get(),
            /*window_secs=*/300, audit_fn, "optional", &metrics, &durable, &admitted);
    }

    // The ids of alice's stored recovery codes, in order: unchanged iff nothing was regenerated.
    std::string code_ids(const std::string& user = "alice") {
        auto lease = db.pool().acquire();
        REQUIRE(lease);
        auto r = yuzu::server::pg::exec_params(
            lease.get(),
            "SELECT COALESCE(string_agg(id::text, ',' ORDER BY id), '') FROM "
            "auth.mfa_recovery_codes WHERE username = $1",
            std::vector<std::string>{user});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        return PQgetvalue(r.get(), 0, 0);
    }

    // origin/dev's SessionStore::mark_mfa text, verbatim: it names no bind sequence, so the
    // session store's guard trigger unbinds the proof.
    void legacy_mark_mfa(const std::string& token) {
        auto lease = db.pool().acquire();
        REQUIRE(lease);
        auto r = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE session_store.sessions s SET mfa_verified_ms = n.ms "
            "FROM (SELECT (extract(epoch from now())*1000)::bigint AS ms) n "
            "WHERE s.token_hash = $1",
            std::vector<std::string>{AuthManager::sha256_hex(token)});
        INFO(PQresultErrorMessage(r.get()));
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    // The upgraded step-up stamp: a proof for the account's current factor, as /login/mfa/stepup
    // writes it after a recovery-code or TOTP verification.
    void upgraded_stamp(const std::string& token, const std::string& user = "alice") {
        const auto st = db->mfa_status(user);
        REQUIRE(st.has_value());
        REQUIRE(mgr.mark_session_mfa_verified(
            token, LocalMfaProof{.factor_gen = st->factor_gen, .verified_ms = st->db_now_ms}));
    }

    bool audit_has(std::string_view what) const {
        for (const auto& a : audits)
            if (a.detail.find(what) != std::string::npos)
                return true;
        return false;
    }
};

std::string approve_or_reject(yuzu::test::ApproverRouteFixture& fx, const std::string& verb,
                              const std::string& token, int& status, std::string& ticket) {
    ticket = fx.submit();
    auto res = fx.decide(verb, ticket, token);
    REQUIRE(res);
    status = res->status;
    return fx.status_of(ticket);
}

} // namespace

TEST_CASE("the chain: a survivor of a factor replacement cannot regenerate the recovery codes, so "
          "it never reaches a bound proof or an approval (#6079 T9)",
          "[pg][stepup][gate][binding][chain]") {
    ChainFixture f;
    yuzu::test::ApproverRouteFixture fx(f.mgr, *f.db.get(), f.durable_fn());

    const auto survivor = f.session_bound(); // proof bound to factor 1
    f.replace_factor("alice");               // factor 2; the survivor's session is NOT deleted
    const auto ids_before = f.code_ids();
    REQUIRE_FALSE(ids_before.empty());

    // Step 1 of the chain: the survivor is refused before the handler, under the default window...
    {
        httplib::Response res;
        CHECK(f.gate(survivor, "/api/settings/mfa/recovery-codes", res) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
        CHECK(f.audit_has("reason=proof_factor_mismatch"));
        CHECK_FALSE(f.regenerate_behind_gate(survivor).has_value());
        CHECK(f.code_ids() == ids_before); // no code regenerated, none revealed
    }
    // ...and under the operator hatch, which this row ignores.
    {
        httplib::Response res;
        CHECK(f.gate(survivor, "/api/settings/mfa/recovery-codes", res, /*window_secs=*/0) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
        CHECK(f.code_ids() == ids_before);
    }
    // The survivor decides nothing: approve and reject both 401, the ticket stays pending.
    for (const char* verb : {"approve", "reject"}) {
        int status = 0;
        std::string ticket;
        CHECK(approve_or_reject(fx, verb, survivor, status, ticket) == "pending");
        CHECK(status == 401);
    }

    // The control chain, from a session bound to factor 2: regenerate, consume one code through
    // the step-up verification, and decide an approval.
    const auto legit = f.session_bound();
    const auto codes = f.regenerate_behind_gate(legit);
    REQUIRE(codes.has_value());
    REQUIRE(codes->size() == 10);
    CHECK(f.code_ids() != ids_before); // a new set exists now
    auto verified = f.db->mfa_consume_recovery_code("alice", codes->front());
    REQUIRE(verified.has_value());
    REQUIRE(verified->ok);
    REQUIRE(f.mgr.mark_session_mfa_verified(
        legit,
        LocalMfaProof{.factor_gen = verified->factor_gen, .verified_ms = verified->verified_ms}));
    int status = 0;
    std::string ticket;
    CHECK(approve_or_reject(fx, "approve", legit, status, ticket) == "approved");
    CHECK(status == 200);
}

TEST_CASE("the central 503 for an unverifiable binding names the runbook and does not ask the "
          "caller to re-prove (a plain store outage keeps its old text)",
          "[stepup][gate][refusal_text]") {
    for (const char* reason : {"mfa_proof_unavailable", "mfa_binding_unenforced"}) {
        INFO(reason);
        StepUpVerdict v;
        v.decision = StepUpDecision::kStoreUnavailable;
        v.reason = reason;
        const auto err = nlohmann::json::parse(step_up_refusal_json_rpc_error(v, "cid-1"));
        CHECK(err["message"] ==
              "this account's second-factor state cannot be verified; if it persists, ask an "
              "administrator to follow the MFA binding enforcement runbook");
        CHECK(err["data"]["http_status"] == 503);
        CHECK(err["data"]["mfa_step_up_required"] == false);
        const std::string remediation = err["data"]["remediation"].get<std::string>();
        CHECK(remediation.find("runbook") != std::string::npos);
        CHECK(remediation.find("--mfa-reset <user>") != std::string::npos);
        CHECK(remediation.find("retrying helps only if") != std::string::npos);
        CHECK(remediation.find("retry shortly") == std::string::npos);
        CHECK_FALSE(err["data"].contains("challenge_url"));
    }
    // No reason: an ordinary store outage keeps the historical text and its retry promise.
    StepUpVerdict plain;
    plain.decision = StepUpDecision::kStoreUnavailable;
    const auto err = nlohmann::json::parse(step_up_refusal_json_rpc_error(plain, "cid-2"));
    CHECK(err["message"] == "authentication store is temporarily unavailable");
    CHECK(err["data"]["mfa_step_up_required"] == true);
}

TEST_CASE("run_in_handler_step_up hands the armed pass's admission back to a factor-credential "
          "handler (qe-Q1)",
          "[pg][stepup][gate][binding][chain]") {
    ChainFixture f; // alice is enrolled by the fixture
    const auto token = f.session_bound();
    StepUpAdmission admitted;
    REQUIRE(f.run_in_handler_admits(token, admitted));
    CHECK(f.in_handler_durable_reads == 0); // the armed pass was consumed, not re-evaluated
    CHECK(admitted.local);
    CHECK(admitted.factor_gen == f.gen_of("alice"));
    CHECK(admitted.factor_gen > 0);
}

TEST_CASE("the legacy interleaving: a proof written by a replica that cannot bind is refused by "
          "both gates until the user re-proves (#6079 T7, T8)",
          "[pg][stepup][gate][binding][chain]") {
    ChainFixture f;
    yuzu::test::ApproverRouteFixture fx(f.mgr, *f.db.get(), f.durable_fn());
    const auto token = f.session_bound(); // bound to the current factor, fresh
    {
        httplib::Response res;
        REQUIRE(f.gate(token, "/api/settings/mfa/recovery-codes", res) ==
                StepUpChokepointResult::kPassed); // sanity: bound passes the generic gate
        detail::clear_step_up_pass();
        int status = 0;
        std::string ticket;
        REQUIRE(approve_or_reject(fx, "approve", token, status, ticket) == "approved");
    }

    // A legacy replica stamps the session: fresh instant, generation 0.
    f.legacy_mark_mfa(token);
    const auto stored = f.mgr.read_durable_mfa_proof(token, "alice");
    REQUIRE(stored.source == auth::DurableMfaProof::Source::kRow);
    CHECK(stored.mfa_verified_ms > 0);
    CHECK(stored.mfa_factor_gen == 0);

    f.audits.clear();
    for (const char* pattern :
         {"/api/settings/mfa/recovery-codes", "/api/settings/mfa/disable", "/api/v1/tokens"}) {
        INFO(pattern);
        httplib::Response res;
        CHECK(f.gate(token, pattern, res) == StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
    }
    CHECK(f.audit_has("reason=proof_factor_unbound"));
    for (const char* verb : {"approve", "reject"}) {
        int status = 0;
        std::string ticket;
        CHECK(approve_or_reject(fx, verb, token, status, ticket) == "pending");
        CHECK(status == 401);
    }
    bool approver_reason = false;
    for (const auto& a : fx.audits)
        approver_reason |= a.detail.find("reason=proof_factor_unbound") != std::string::npos;
    CHECK(approver_reason);

    // Re-proving through the upgraded stamp admits both gates again.
    f.upgraded_stamp(token);
    {
        httplib::Response res;
        CHECK(f.gate(token, "/api/settings/mfa/recovery-codes", res) ==
              StepUpChokepointResult::kPassed);
        detail::clear_step_up_pass();
        int status = 0;
        std::string ticket;
        CHECK(approve_or_reject(fx, "approve", token, status, ticket) == "approved");
        CHECK(status == 200);
        CHECK(approve_or_reject(fx, "reject", token, status, ticket) == "rejected");
    }
}

TEST_CASE("a proof stamped fresh but durably old is refused by the generic gate even though its "
          "cached anchor reads fresh (#6079 T13)",
          "[pg][stepup][gate][binding][chain]") {
    ChainFixture f;
    const auto token = f.session_bound();
    // This replica's cache entry, populated BEFORE the stored instant moves: a raw write does not
    // advance the session write generation, so the cache keeps serving its seconds-old anchor,
    // exactly the state of a replica whose monotonic clock paused.
    const auto cached = f.mgr.validate_session(token);
    REQUIRE(cached.has_value());
    REQUIRE(cached->steady_mfa_verified.time_since_epoch().count() != 0);
    CHECK(std::chrono::steady_clock::now() - cached->steady_mfa_verified < 30s);
    // Move the stored instant 400 s into the past WITH the bind sequence, so the guard keeps the
    // binding.
    {
        auto lease = f.db.pool().acquire();
        REQUIRE(lease);
        auto r = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE session_store.sessions SET mfa_verified_ms = "
            "(extract(epoch from now())*1000)::bigint - 400000, mfa_bind_seq = mfa_bind_seq + 1 "
            "WHERE token_hash = $1",
            std::vector<std::string>{AuthManager::sha256_hex(token)});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    for (const char* pattern : {"/api/settings/mfa/recovery-codes", "/api/v1/tokens"}) {
        INFO(pattern);
        f.audits.clear();
        httplib::Response res;
        CHECK(f.gate(token, pattern, res) == StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
        REQUIRE(f.audits.size() == 1);
        const auto& detail = f.audits[0].detail;
        const auto pos = detail.find("age_secs=");
        REQUIRE(pos != std::string::npos);
        CHECK(std::stoi(detail.substr(pos + 9)) >= 400);
        CHECK(detail.find("reason=") == std::string::npos); // stale, not unbound or mismatched
    }
}
