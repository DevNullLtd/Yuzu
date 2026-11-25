/**
 * test_approval_continuation.cpp — the pure rules behind "one approval covers a whole multi-slice
 * read" (approval_continuation.hpp): which row may use a cover, what counts as a token, and what
 * the ticket is bound to. The store-side half (`ApprovalManager::covers_continuation`) is in
 * test_approval_manager.cpp; the C8 gate that ties them together is in test_mcp_server.cpp.
 */

#include "approval_continuation.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <string>

using namespace yuzu::server;
using namespace yuzu::server::approval_continuation;
using nlohmann::json;

namespace {

CommandCapability read_row(ExecuteGate gate, std::string_view continuation = "cursor") {
    return CommandCapability{.plugin = "any_plugin",
                             .action = "any_action",
                             .dispatch_class = DispatchClass::ReadOnly,
                             .mutability = Mutability::None,
                             .securable = "Inventory",
                             .operation = authz::Operation::Read,
                             .risk_tier = authz::RiskTier::High,
                             .execute_gate = gate,
                             .continuation_param = continuation};
}

json call(const std::string& cursor_value_json = R"("tok123")") {
    return json::parse(R"({"plugin":"any_plugin","action":"any_action","agent_ids":["a1"],)"
                       R"("params":{"root":"/data","pattern":"*.bin","cursor":)" +
                       cursor_value_json + "}}");
}

} // namespace

TEST_CASE("covered_param honours the declaration only for a read gated None or AdminOrApproval",
          "[server][approval_continuation]") {
    CHECK(covered_param(read_row(ExecuteGate::AdminOrApproval)) == "cursor");
    CHECK(covered_param(read_row(ExecuteGate::None)) == "cursor");

    // No declaration: no cover (the omitted default fails closed).
    CHECK(covered_param(read_row(ExecuteGate::AdminOrApproval, "")).empty());
    // AlwaysApproval is never covered, whatever it declares.
    CHECK(covered_param(read_row(ExecuteGate::AlwaysApproval)).empty());
    CHECK(covered_param(read_row(ExecuteGate::Unspecified)).empty());

    // A mutating or destructive row is never covered, whatever it declares.
    auto mutating = read_row(ExecuteGate::AdminOrApproval);
    mutating.dispatch_class = DispatchClass::Mutating;
    mutating.mutability = Mutability::Reversible;
    CHECK(covered_param(mutating).empty());
    auto destructive = read_row(ExecuteGate::AdminOrApproval);
    destructive.dispatch_class = DispatchClass::Destructive;
    destructive.mutability = Mutability::Irreversible;
    CHECK(covered_param(destructive).empty());
    // Read-only by class but with a mutability other than None is still refused.
    auto odd = read_row(ExecuteGate::AdminOrApproval);
    odd.mutability = Mutability::Reversible;
    CHECK(covered_param(odd).empty());
}

TEST_CASE("carries_token is true only for a non-empty string of printable non-space ASCII",
          "[server][approval_continuation]") {
    CHECK(carries_token(call(), "cursor"));
    CHECK(carries_token(call(R"("fsv1.AbC-_09~!")"), "cursor"));

    // Not a token: empty, wrong type, absent.
    CHECK_FALSE(carries_token(call(R"("")"), "cursor"));
    CHECK_FALSE(carries_token(call("5"), "cursor"));
    CHECK_FALSE(carries_token(call("null"), "cursor"));
    CHECK_FALSE(carries_token(call("true"), "cursor"));
    CHECK_FALSE(carries_token(call(R"(["tok"])"), "cursor"));
    CHECK_FALSE(carries_token(call(R"({"a":"b"})"), "cursor"));
    CHECK_FALSE(carries_token(json::parse(R"({"params":{"root":"/data"}})"), "cursor"));
    CHECK_FALSE(carries_token(json::parse(R"({"plugin":"p"})"), "cursor"));
    CHECK_FALSE(carries_token(json::parse(R"({"params":"cursor"})"), "cursor"));
    CHECK_FALSE(carries_token(json::parse("[]"), "cursor"));
    CHECK_FALSE(carries_token(call(), ""));

    // Only the declared parameter counts.
    CHECK_FALSE(carries_token(call(), "other"));
}

TEST_CASE("carries_token refuses a space, a control byte, a NUL and a high byte anywhere in the value",
          "[server][approval_continuation]") {
    // A value starting with NUL reads as EMPTY on the agent (C-string ABI): it would start a new
    // search under the cover, so it must not count as a token.
    CHECK_FALSE(carries_token(call(R"("\u0000abc")"), "cursor"));
    CHECK_FALSE(carries_token(call(R"("abc\u0000def")"), "cursor"));
    CHECK_FALSE(carries_token(call(R"("a b")"), "cursor"));
    CHECK_FALSE(carries_token(call(R"(" abc")"), "cursor"));
    CHECK_FALSE(carries_token(call(R"("abc ")"), "cursor"));
    CHECK_FALSE(carries_token(call(R"("a\tb")"), "cursor"));
    CHECK_FALSE(carries_token(call(R"("a\nb")"), "cursor"));
    CHECK_FALSE(carries_token(call(R"("a\u007fb")"), "cursor")); // DEL
    CHECK_FALSE(carries_token(call(R"("café")"), "cursor")); // a non-ASCII byte

    // The edges of the accepted range.
    CHECK(carries_token(call(R"("!")"), "cursor"));  // 0x21
    CHECK(carries_token(call(R"("~")"), "cursor"));  // 0x7E
}

TEST_CASE("ticket_subject leaves out approval_id and the continuation parameter, whatever its value",
          "[server][approval_continuation]") {
    const auto first = ticket_subject(call(R"("")"), "cursor");
    // Equal across every cursor value, absent, or of another type.
    CHECK(ticket_subject(call(R"("tok-1")"), "cursor") == first);
    CHECK(ticket_subject(call(R"("tok-2")"), "cursor") == first);
    CHECK(ticket_subject(call("7"), "cursor") == first);
    CHECK(ticket_subject(call("null"), "cursor") == first);
    CHECK(ticket_subject(call(R"("\u0000x")"), "cursor") == first);

    auto with_id = call();
    with_id["approval_id"] = "an-approval";
    CHECK(ticket_subject(with_id, "cursor") == first);

    auto no_cursor = call();
    no_cursor["params"].erase("cursor");
    CHECK(ticket_subject(no_cursor, "cursor") == first);

    // Key order of the caller does not matter.
    const auto reordered = json::parse(
        R"({"params":{"pattern":"*.bin","cursor":"x","root":"/data"},"agent_ids":["a1"],)"
        R"("action":"any_action","plugin":"any_plugin"})");
    CHECK(ticket_subject(reordered, "cursor") == first);
}

TEST_CASE("ticket_subject differs when the search itself differs",
          "[server][approval_continuation]") {
    const auto base = ticket_subject(call(), "cursor");

    auto other_root = call();
    other_root["params"]["root"] = "/elsewhere";
    CHECK(ticket_subject(other_root, "cursor") != base);

    auto other_pattern = call();
    other_pattern["params"]["pattern"] = "*.txt";
    CHECK(ticket_subject(other_pattern, "cursor") != base);

    auto other_action = call();
    other_action["action"] = "different";
    CHECK(ticket_subject(other_action, "cursor") != base);

    auto other_target = call();
    other_target["agent_ids"] = json::array({"a2"});
    CHECK(ticket_subject(other_target, "cursor") != base);

    // One device widened to the fleet.
    auto fleet = call();
    fleet.erase("agent_ids");
    fleet["scope"] = "__all__";
    CHECK(ticket_subject(fleet, "cursor") != base);
}

TEST_CASE("ticket_subject is one marker line, a newline, then the canonical arguments",
          "[server][approval_continuation]") {
    const auto subject = ticket_subject(call(), "cursor");
    const auto newline = subject.find('\n');
    REQUIRE(newline != std::string::npos);
    CHECK(subject.substr(0, newline) == "continuation=cursor window_s=86400");
    CHECK(kCoverSeconds == 86400);
    const auto body = subject.substr(newline + 1);
    CHECK(body.find('\n') == std::string::npos);
    CHECK(body.find("cursor") == std::string::npos);
    CHECK(body.find("approval_id") == std::string::npos);
    CHECK(body.find("\"root\":\"/data\"") != std::string::npos);

    // A ticket for a row that does not cover carries no marker, so the two can never match.
    CHECK(subject != call().dump());
}

TEST_CASE("ticket_subject tolerates arguments with no params object",
          "[server][approval_continuation]") {
    const auto bare = json::parse(R"({"plugin":"p","action":"a","params":"not-an-object"})");
    const auto subject = ticket_subject(bare, "cursor");
    CHECK(subject.find("\"params\":\"not-an-object\"") != std::string::npos);
    CHECK_FALSE(ticket_subject(json::parse("[1,2]"), "cursor").empty());
}
