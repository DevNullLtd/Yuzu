// #5513: AgentRegistry::register_agent prints the claimed agent id and agent-supplied free text
// (hostname, scopable-tag key) in its log lines. Both callers hand it ids and text from the wire,
// so every line must carry them in neutralised form (log_id_token / log_key_token,
// common/include/yuzu/log_token.hpp): no raw control byte, so one call can never forge a second
// log line, and no raw space or '=' inside the claimed id, so it cannot forge extra key=value
// tokens. These tests capture the real log output of the sites that are reachable without a
// device-token store: the service-tag drop, the invalid-tag drop, the superseded refusal and the
// "Agent registered" line. The revoke-failure line is held by the PG test in
// test_agent_registry_token_revocation.cpp.
//
// Not vacuous: the assertions name the neutralised forms, which exist only if the wrap is in
// place, and the newline count is the number of log calls (a raw '\n' in a printed value would add
// one).

#include "agent_registry.hpp"
#include "event_bus.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include "../test_log_capture.hpp"

#include "agent.pb.h"

#include <algorithm>
#include <cstddef>
#include <string>

using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
namespace agent_pb = ::yuzu::agent::v1;

namespace {

// Passes AuthDB's id check (it refuses control bytes and ',' only) yet carries a space and '='
// that log_id_token must fold.
constexpr const char* kSpacedId = "agent x=1 fake=2";
constexpr const char* kSpacedIdToken = "agent_x_1_fake_2";

agent_pb::AgentInfo make_info(const std::string& id, const std::string& hostname) {
    agent_pb::AgentInfo info;
    info.set_agent_id(id);
    info.set_hostname(hostname);
    info.mutable_platform()->set_os("linux");
    info.mutable_platform()->set_arch("x86_64");
    return info;
}

std::size_t count_char(const std::string& s, char c) {
    return static_cast<std::size_t>(std::count(s.begin(), s.end(), c));
}

// Every byte below 0x20 other than the one trailing '\n' per log line, and DEL.
std::size_t stray_control_bytes(const std::string& s) {
    return static_cast<std::size_t>(std::count_if(s.begin(), s.end(), [](char ch) {
        const auto c = static_cast<unsigned char>(ch);
        return (c < 0x20 && c != '\n') || c == 0x7F;
    }));
}

} // namespace

TEST_CASE("AgentRegistry::register_agent: logs the claimed id, hostname and a bad tag key "
          "neutralised",
          "[agent_registry][log_injection][5513]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);

    auto info = make_info(kSpacedId, "h\nFORGED x='1");
    // An invalid key with a control byte (the "dropping invalid scopable_tag" log) and a service
    // key (the "dropping self-reported 'service' tag" log, which prints only the id).
    (*info.mutable_scopable_tags())["bad\nkey x='1"] = "v";
    (*info.mutable_scopable_tags())["service"] = "v";

    yuzu::test::LogCapture cap;
    auto result = registry.register_agent(info);
    cap.stop();

    REQUIRE(result.has_value());
    const std::string text = cap.text();

    // Neutralised forms: the id folds space and '=' to '_', the hostname and the tag key fold the
    // control byte but keep their space, quote and '='.
    CHECK(text.find(std::string("register_agent(") + kSpacedIdToken +
                    "): dropping invalid scopable_tag 'bad_key x='1' at ingest") !=
          std::string::npos);
    CHECK(text.find(std::string("register_agent(") + kSpacedIdToken +
                    "): dropping self-reported 'service' tag") != std::string::npos);
    CHECK(text.find(std::string("Agent registered: id=") + kSpacedIdToken +
                    ", hostname='h_FORGED x='1'") != std::string::npos);

    // None of the raw forms, and no raw control byte beyond the single trailing newline per log
    // line: three log calls, so exactly three newlines.
    CHECK(text.find(kSpacedId) == std::string::npos);
    CHECK(text.find("h\nFORGED") == std::string::npos);
    CHECK(text.find("bad\nkey") == std::string::npos);
    CHECK(stray_control_bytes(text) == 0);
    CHECK(count_char(text, '\n') == 3);
}

TEST_CASE("AgentRegistry::register_agent: the superseded refusal logs the claimed id neutralised",
          "[agent_registry][log_injection][5513]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);

    // The interleave hook registers the same id from inside the first call, after its revoke
    // window and before its install, so the first call finds a newer session and yields.
    bool hook_fired = false;
    registry.set_register_agent_interleave_hook_for_test([&] {
        hook_fired = true;
        REQUIRE(registry.register_agent(make_info(kSpacedId, "winner")).has_value());
    });

    yuzu::test::LogCapture cap;
    auto result = registry.register_agent(make_info(kSpacedId, "slow"));
    cap.stop();

    REQUIRE(hook_fired);
    REQUIRE_FALSE(result.has_value());
    const std::string text = cap.text();

    CHECK(text.find(std::string("superseded by a concurrent registration for '") +
                    kSpacedIdToken + "', not installing") != std::string::npos);
    CHECK(text.find(std::string("Agent registered: id=") + kSpacedIdToken +
                    ", hostname='winner'") != std::string::npos);
    CHECK(text.find(kSpacedId) == std::string::npos);
    CHECK(stray_control_bytes(text) == 0);
    // The winner's "Agent registered" line and the superseded warning: two log calls.
    CHECK(count_char(text, '\n') == 2);
}
