// test_gateway_mgmt_stub_pool.cpp — HA WS-4 "rest of 4.3" (cross-cluster
// gateway fan-out) coverage for the two pure/near-pure pieces:
//
//   parse_gateway_cluster_addrs: pure `--gateway-cluster-addr` CLI parser.
//   GatewayMgmtStubPool::resolve: the two-mode resolution rule (Fable
//     pre-implementation review, finding 3 — single-cluster mode ignores
//     the announced cluster_id entirely and always resolves to the legacy
//     default; multi-cluster mode resolves it against the configured map,
//     auto-aliasing "default", and reports an unmapped id distinctly).
//
// resolve() is exercised via an injectable ChannelFactory so these tests
// never dial a real network address (grpc::CreateChannel is itself
// lazy-connecting, so even the real factory wouldn't need one — but an
// injected factory keeps the test hermetic and fast regardless).

#include "gateway_mgmt_stub_pool.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::server::GatewayMgmtStubPool;
using yuzu::server::kDefaultGatewayClusterKey;
using yuzu::server::kUnknownGatewayClusterLabel;
using yuzu::server::parse_gateway_cluster_addrs;

namespace {

// A fixed, valid, insecure local channel — never actually connected to in
// these tests (grpc::CreateChannel doesn't connect eagerly either; this
// factory just avoids depending on that laziness explicitly).
std::shared_ptr<grpc::Channel> fake_channel_factory(const std::string&,
                                                    std::shared_ptr<grpc::ChannelCredentials>) {
    return grpc::CreateChannel("127.0.0.1:0", grpc::InsecureChannelCredentials());
}

} // namespace

// ── parse_gateway_cluster_addrs ─────────────────────────────────────────

TEST_CASE("parse_gateway_cluster_addrs: well-formed entries parse into a map",
          "[server][gateway_mgmt_stub_pool]") {
    auto result = parse_gateway_cluster_addrs(
        {"us-east=10.0.1.5:50063", "eu-west=10.1.1.5:50063"}, /*max_cluster_id_len=*/64);
    REQUIRE(result.has_value());
    CHECK(result->size() == 2);
    CHECK(result->at("us-east") == "10.0.1.5:50063");
    CHECK(result->at("eu-west") == "10.1.1.5:50063");
}

TEST_CASE("parse_gateway_cluster_addrs: empty input is a valid empty map (single-cluster mode)",
          "[server][gateway_mgmt_stub_pool]") {
    auto result = parse_gateway_cluster_addrs({}, 64);
    REQUIRE(result.has_value());
    CHECK(result->empty());
}

TEST_CASE("parse_gateway_cluster_addrs: an entry with no '=' is rejected",
          "[server][gateway_mgmt_stub_pool]") {
    auto result = parse_gateway_cluster_addrs({"us-east-10.0.1.5:50063"}, 64);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("missing '='") != std::string::npos);
}

TEST_CASE("parse_gateway_cluster_addrs: an empty cluster_id is rejected",
          "[server][gateway_mgmt_stub_pool]") {
    auto result = parse_gateway_cluster_addrs({"=10.0.1.5:50063"}, 64);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("empty cluster_id") != std::string::npos);
}

TEST_CASE("parse_gateway_cluster_addrs: an empty address is rejected",
          "[server][gateway_mgmt_stub_pool]") {
    auto result = parse_gateway_cluster_addrs({"us-east="}, 64);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("empty address") != std::string::npos);
}

TEST_CASE("parse_gateway_cluster_addrs: a cluster_id exceeding the length bound is rejected",
          "[server][gateway_mgmt_stub_pool]") {
    std::string long_id(65, 'a');
    auto result = parse_gateway_cluster_addrs({long_id + "=10.0.1.5:50063"}, /*max=*/64);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("exceeds the maximum length") != std::string::npos);
}

TEST_CASE("parse_gateway_cluster_addrs: a duplicate cluster_id is rejected",
          "[server][gateway_mgmt_stub_pool]") {
    auto result =
        parse_gateway_cluster_addrs({"us-east=10.0.1.5:50063", "us-east=10.0.1.6:50063"}, 64);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("duplicate cluster_id") != std::string::npos);
}

// ── GatewayMgmtStubPool::resolve — single-cluster mode ──────────────────

TEST_CASE("GatewayMgmtStubPool: single-cluster mode (no --gateway-cluster-addr) resolves EVERY "
          "cluster_id to the legacy default, regardless of its value — the upgrade-safety "
          "property Fable's pre-implementation review centered on",
          "[server][gateway_mgmt_stub_pool]") {
    GatewayMgmtStubPool pool("legacy-host:50063", /*cluster_addresses=*/{},
                             grpc::InsecureChannelCredentials(), fake_channel_factory);
    CHECK_FALSE(pool.multi_cluster_mode());
    CHECK_FALSE(pool.empty());

    // A gateway build defaulting YUZU_GW_CLUSTER_ID to "default"
    // (yuzu_gw_upstream.erl) — the real-world common case.
    auto r1 = pool.resolve(std::optional<std::string>("default"));
    REQUIRE(r1.stub != nullptr);
    CHECK(r1.label == kDefaultGatewayClusterKey);

    // Some other operator-chosen cluster_id — STILL resolves to the one
    // legacy stub in single-cluster mode; this is the exact case the
    // plan's original "empty means default, non-empty unmapped means drop"
    // rule would have broken on upgrade.
    auto r2 = pool.resolve(std::optional<std::string>("whatever-the-gateway-announces"));
    REQUIRE(r2.stub != nullptr);
    CHECK(r2.stub == r1.stub); // same single entry

    // No cluster identity at all (nullopt) — also resolves to the default.
    auto r3 = pool.resolve(std::nullopt);
    REQUIRE(r3.stub != nullptr);
    CHECK(r3.stub == r1.stub);
}

TEST_CASE("GatewayMgmtStubPool: single-cluster mode with NO default address configured is "
          "empty — nothing is dispatchable, matching pre-4.3 behavior when "
          "--gateway-command-addr is unset",
          "[server][gateway_mgmt_stub_pool]") {
    GatewayMgmtStubPool pool("", {}, grpc::InsecureChannelCredentials(), fake_channel_factory);
    CHECK(pool.empty());
    auto r = pool.resolve(std::optional<std::string>("default"));
    CHECK(r.stub == nullptr);
}

// ── GatewayMgmtStubPool::resolve — multi-cluster mode ────────────────────

TEST_CASE("GatewayMgmtStubPool: multi-cluster mode resolves a known cluster_id to its own stub",
          "[server][gateway_mgmt_stub_pool]") {
    GatewayMgmtStubPool pool("legacy-host:50063",
                             {{"us-east", "10.0.1.5:50063"}, {"eu-west", "10.1.1.5:50063"}},
                             grpc::InsecureChannelCredentials(), fake_channel_factory);
    CHECK(pool.multi_cluster_mode());

    auto r_east = pool.resolve(std::optional<std::string>("us-east"));
    REQUIRE(r_east.stub != nullptr);
    CHECK(r_east.label == "us-east");

    auto r_west = pool.resolve(std::optional<std::string>("eu-west"));
    REQUIRE(r_west.stub != nullptr);
    CHECK(r_west.label == "eu-west");
    CHECK(r_west.stub != r_east.stub); // distinct channels/stubs
}

TEST_CASE("GatewayMgmtStubPool: multi-cluster mode auto-aliases 'default' to the legacy address "
          "when not already an explicit key",
          "[server][gateway_mgmt_stub_pool]") {
    GatewayMgmtStubPool pool("legacy-host:50063", {{"us-east", "10.0.1.5:50063"}},
                             grpc::InsecureChannelCredentials(), fake_channel_factory);
    CHECK(pool.known_clusters().contains(std::string(kDefaultGatewayClusterKey)));

    auto r = pool.resolve(std::optional<std::string>("default"));
    REQUIRE(r.stub != nullptr);
    CHECK(r.label == kDefaultGatewayClusterKey);

    // nullopt / no cluster identity ALSO resolves to "default" in
    // multi-cluster mode — mirrors single-cluster mode's own nullopt
    // handling, just now against the auto-aliased entry instead of the
    // pool's only entry.
    auto r_none = pool.resolve(std::nullopt);
    REQUIRE(r_none.stub != nullptr);
    CHECK(r_none.stub == r.stub);
}

TEST_CASE("GatewayMgmtStubPool: multi-cluster mode does NOT overwrite an explicit 'default' key "
          "with the auto-alias",
          "[server][gateway_mgmt_stub_pool]") {
    GatewayMgmtStubPool pool(
        "legacy-host:50063",
        {{"default", "explicit-default-host:50063"}, {"us-east", "10.0.1.5:50063"}},
        grpc::InsecureChannelCredentials(), fake_channel_factory);

    auto r = pool.resolve(std::optional<std::string>("default"));
    REQUIRE(r.stub != nullptr);
    auto r_east = pool.resolve(std::optional<std::string>("us-east"));
    REQUIRE(r_east.stub != nullptr);
    CHECK(r.stub != r_east.stub);
}

TEST_CASE("GatewayMgmtStubPool: multi-cluster mode reports an unmapped cluster_id as unresolved, "
          "labelled 'unknown' — never the raw gateway-asserted value (cardinality risk)",
          "[server][gateway_mgmt_stub_pool]") {
    GatewayMgmtStubPool pool("legacy-host:50063", {{"us-east", "10.0.1.5:50063"}},
                             grpc::InsecureChannelCredentials(), fake_channel_factory);

    auto r = pool.resolve(std::optional<std::string>("attacker-controlled-nonsense-id"));
    CHECK(r.stub == nullptr);
    CHECK(r.label == kUnknownGatewayClusterLabel);
}

TEST_CASE("GatewayMgmtStubPool: multi-cluster mode with no default address configured is still "
          "valid — every cluster named explicitly, no legacy fallback",
          "[server][gateway_mgmt_stub_pool]") {
    GatewayMgmtStubPool pool("", {{"us-east", "10.0.1.5:50063"}},
                             grpc::InsecureChannelCredentials(), fake_channel_factory);
    CHECK(pool.multi_cluster_mode());
    CHECK_FALSE(pool.known_clusters().contains(std::string(kDefaultGatewayClusterKey)));

    auto r = pool.resolve(std::optional<std::string>("us-east"));
    CHECK(r.stub != nullptr);
    // "default" was never aliased (no legacy address to alias it to).
    auto r_default = pool.resolve(std::optional<std::string>("default"));
    CHECK(r_default.stub == nullptr);
    CHECK(r_default.label == kUnknownGatewayClusterLabel);
}

TEST_CASE("GatewayMgmtStubPool: resolve treats a present-but-empty cluster_id identically to "
          "nullopt in both modes",
          "[server][gateway_mgmt_stub_pool]") {
    GatewayMgmtStubPool single("legacy-host:50063", {}, grpc::InsecureChannelCredentials(),
                               fake_channel_factory);
    auto r_none = single.resolve(std::nullopt);
    auto r_empty = single.resolve(std::optional<std::string>(""));
    REQUIRE(r_none.stub != nullptr);
    CHECK(r_empty.stub == r_none.stub);
    CHECK(r_empty.label == r_none.label);

    GatewayMgmtStubPool multi("legacy-host:50063", {{"us-east", "10.0.1.5:50063"}},
                              grpc::InsecureChannelCredentials(), fake_channel_factory);
    auto m_none = multi.resolve(std::nullopt);
    auto m_empty = multi.resolve(std::optional<std::string>(""));
    REQUIRE(m_none.stub != nullptr);
    CHECK(m_empty.stub == m_none.stub);
    CHECK(m_empty.label == m_none.label);
    CHECK(m_empty.label == kDefaultGatewayClusterKey);
}

// ── classify_gateway_forward_response ────────────────────────────────────

TEST_CASE("classify_gateway_forward_response: a matching agent_id with a genuine SUCCESS is "
          "kApply",
          "[server][gateway_mgmt_stub_pool]") {
    ::yuzu::server::v1::SendCommandResponse resp;
    resp.set_agent_id("agent-1");
    resp.mutable_response()->set_status(::yuzu::agent::v1::CommandResponse::SUCCESS);
    CHECK(yuzu::server::classify_gateway_forward_response(resp, "agent-1") ==
         yuzu::server::GatewayForwardOutcome::kApply);
}

TEST_CASE("classify_gateway_forward_response: a matching agent_id with an ORDINARY plugin "
          "FAILURE (not the gateway's synthetic not_connected shape) is kApply, not "
          "kNotConnected",
          "[server][gateway_mgmt_stub_pool]") {
    ::yuzu::server::v1::SendCommandResponse resp;
    resp.set_agent_id("agent-1");
    resp.mutable_response()->set_status(::yuzu::agent::v1::CommandResponse::FAILURE);
    resp.mutable_response()->set_exit_code(1); // a REAL plugin exit code, not the sentinel -1
    resp.mutable_response()->set_output("plugin exploded");
    CHECK(yuzu::server::classify_gateway_forward_response(resp, "agent-1") ==
         yuzu::server::GatewayForwardOutcome::kApply);
}

TEST_CASE("classify_gateway_forward_response: the gateway's synthetic not_connected error shape "
          "(FAILURE, exit_code -1, output 'not_connected') is kNotConnected",
          "[server][gateway_mgmt_stub_pool]") {
    ::yuzu::server::v1::SendCommandResponse resp;
    resp.set_agent_id("agent-1");
    resp.mutable_response()->set_status(::yuzu::agent::v1::CommandResponse::FAILURE);
    resp.mutable_response()->set_exit_code(-1);
    resp.mutable_response()->set_output("not_connected");
    CHECK(yuzu::server::classify_gateway_forward_response(resp, "agent-1") ==
         yuzu::server::GatewayForwardOutcome::kNotConnected);
}

TEST_CASE("classify_gateway_forward_response: agent_disconnected is ALSO kNotConnected "
          "(yuzu_gw_agent.erl's own disconnected-mid-command shape)",
          "[server][gateway_mgmt_stub_pool]") {
    ::yuzu::server::v1::SendCommandResponse resp;
    resp.set_agent_id("agent-1");
    resp.mutable_response()->set_status(::yuzu::agent::v1::CommandResponse::FAILURE);
    resp.mutable_response()->set_exit_code(-1);
    resp.mutable_response()->set_output("agent_disconnected");
    CHECK(yuzu::server::classify_gateway_forward_response(resp, "agent-1") ==
         yuzu::server::GatewayForwardOutcome::kNotConnected);
}

TEST_CASE("classify_gateway_forward_response: a mismatched agent_id is kAgentMismatch "
          "REGARDLESS of the response's own status/output — the forgery guard fires before "
          "any content is inspected",
          "[server][gateway_mgmt_stub_pool]") {
    ::yuzu::server::v1::SendCommandResponse resp;
    resp.set_agent_id("agent-attacker-controlled");
    resp.mutable_response()->set_status(::yuzu::agent::v1::CommandResponse::SUCCESS);
    CHECK(yuzu::server::classify_gateway_forward_response(resp, "agent-1") ==
         yuzu::server::GatewayForwardOutcome::kAgentMismatch);

    // Even a response that LOOKS like the not_connected shape is still a
    // mismatch first, never silently reclassified as kNotConnected.
    ::yuzu::server::v1::SendCommandResponse resp2;
    resp2.set_agent_id("agent-attacker-controlled");
    resp2.mutable_response()->set_status(::yuzu::agent::v1::CommandResponse::FAILURE);
    resp2.mutable_response()->set_exit_code(-1);
    resp2.mutable_response()->set_output("not_connected");
    CHECK(yuzu::server::classify_gateway_forward_response(resp2, "agent-1") ==
         yuzu::server::GatewayForwardOutcome::kAgentMismatch);
}

TEST_CASE("classify_gateway_forward_response: a FAILURE with exit_code -1 but output NOT "
          "matching either sentinel string is kApply (an ordinary failure with a coincidentally "
          "-1 exit code, not the gateway's synthetic shape)",
          "[server][gateway_mgmt_stub_pool]") {
    ::yuzu::server::v1::SendCommandResponse resp;
    resp.set_agent_id("agent-1");
    resp.mutable_response()->set_status(::yuzu::agent::v1::CommandResponse::FAILURE);
    resp.mutable_response()->set_exit_code(-1);
    resp.mutable_response()->set_output("some other plugin error");
    CHECK(yuzu::server::classify_gateway_forward_response(resp, "agent-1") ==
         yuzu::server::GatewayForwardOutcome::kApply);
}

// ── build_gateway_forward_terminal_failure (#4672) ──────────────────────────
//
// Pure builder for the synthetic terminal FAILURE `forward_gateway_pending`
// applies on its `unauthenticated` / exhausted `unavailable` /
// `unknown_cluster` / no-legitimate-resolution `agent_mismatch` branches, so
// the dispatching operator's command_id always resolves instead of being
// silently dropped. See server.cpp's `apply_gateway_forward_terminal_failure`
// (the ONE call site, feeding every branch through `process_gateway_response`
// — integration coverage for that half lives in
// test_agent_service_impl.cpp, which cannot see this static ServerImpl
// helper directly).

TEST_CASE("build_gateway_forward_terminal_failure: sets command_id, FAILURE status, "
          "the synthetic exit_code sentinel, and the reason/detail on error",
          "[server][gateway_mgmt_stub_pool][4672]") {
    auto resp = yuzu::server::build_gateway_forward_terminal_failure(
        "cmd-123", "gateway_unauthenticated", "rejected by mgmt-plane peer pin");
    CHECK(resp.command_id() == "cmd-123");
    CHECK(resp.status() == ::yuzu::agent::v1::CommandResponse::FAILURE);
    // -1 matches the same synthetic-terminal sentinel
    // classify_gateway_forward_response's kNotConnected branch already
    // recognizes elsewhere on this forwarding path — never a real agent's
    // exit code.
    CHECK(resp.exit_code() == -1);
    REQUIRE(resp.has_error());
    CHECK(resp.error().code() == "gateway_unauthenticated");
    // pr-rev finding (FortitudeEtc/Codex+Kimi, SHOULD, 2026-09-22):
    // error().code() is never read back anywhere under server/core/src, so
    // the reason code is ALSO prefixed onto the persisted message — the
    // field that actually reaches an operator/agentic worker.
    CHECK(resp.error().message() == "[gateway_unauthenticated] rejected by mgmt-plane peer pin");
}

TEST_CASE("build_gateway_forward_terminal_failure: each of the five #4672 reason codes "
          "round-trips distinctly",
          "[server][gateway_mgmt_stub_pool][4672]") {
    // Mirrors the reason_code literals server.cpp's forward_gateway_pending
    // passes at each of its five terminal-failure call sites (four named in
    // #4672's own issue, plus the pre-existing unnamed generic grpc-status
    // branch the same PR also fixed, "gateway_forward_failed") — a change to
    // one of those literals without updating this list is a doc/observability
    // drift, not a functional break, but pinning the set here catches an
    // accidental typo/duplicate at the source of truth. Gate 4 consistency-
    // auditor SHOULD (2026-09-21): this list previously omitted
    // "gateway_forward_failed", the one code the diff's own commit message
    // said it also closed.
    const std::vector<std::string> reasons = {
        "gateway_unauthenticated",
        "gateway_unavailable",
        "gateway_unknown_cluster",
        "gateway_agent_mismatch",
        "gateway_forward_failed",
    };
    for (const auto& reason : reasons) {
        INFO("reason=" << reason);
        auto resp = yuzu::server::build_gateway_forward_terminal_failure("cmd-x", reason, "d");
        CHECK(resp.error().code() == reason);
        CHECK(resp.status() == ::yuzu::agent::v1::CommandResponse::FAILURE);
    }
}

TEST_CASE("is_terminal_command_status: RUNNING is the ONLY non-terminal status "
          "(pr-rev finding FortitudeEtc/Codex+Kimi, BLOCKER, 2026-09-22)",
          "[server][gateway_mgmt_stub_pool][4672]") {
    // The exact guard matrix requested by the review: every CommandResponse::
    // Status value, and whether applying a frame carrying it should suppress
    // a later synthetic terminal-failure write. Only RUNNING must not.
    using S = ::yuzu::agent::v1::CommandResponse;
    CHECK_FALSE(yuzu::server::is_terminal_command_status(S::RUNNING));
    CHECK(yuzu::server::is_terminal_command_status(S::SUCCESS));
    CHECK(yuzu::server::is_terminal_command_status(S::FAILURE));
    CHECK(yuzu::server::is_terminal_command_status(S::TIMEOUT));
    CHECK(yuzu::server::is_terminal_command_status(S::REJECTED));
}
