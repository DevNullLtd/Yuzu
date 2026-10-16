// #5513: AgentRegistry::register_agent prints the claimed agent id and agent-supplied free text
// (hostname, scopable-tag key) in its log lines. Both callers hand it ids and text from the wire,
// so every line must carry them in neutralised form (log_id_token / log_key_token,
// common/include/yuzu/log_token.hpp): no raw control byte, so one call can never forge a second
// log line, and no raw space or '=' inside the claimed id or the hostname, so neither can forge
// extra key=value tokens (the hostname takes the closed-set id fold; the tag key keeps its space
// and '=' under the key-token fold). These tests capture the real log output of the sites that
// are reachable without a device-token store: the service-tag drop, the invalid-tag drop, the
// superseded refusal and the "Agent registered" line. The revoke-failure line is held by the PG
// test in test_agent_registry_token_revocation.cpp.
//
// Not vacuous: the assertions name the neutralised forms, which exist only if the wrap is in
// place, and the newline count is the number of log calls (a raw '\n' in a printed value would add
// one).

#include "agent_registry.hpp"
#include "command_capability.hpp"
#include "command_capability_parsers.hpp"
#include "event_bus.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include "../test_log_capture.hpp"

#include "agent.pb.h"

#include <algorithm>
#include <cstddef>
#include <string>

using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::ClassifiedCommandTestAccess;
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

using yuzu::test::stray_control_bytes;

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

    // Neutralised forms: the id and the hostname fold space, '=' and the control byte to '_'
    // (the quote survives); the tag key folds the control byte but keeps its space, quote and '='.
    CHECK(text.find(std::string("register_agent(") + kSpacedIdToken +
                    "): dropping invalid scopable_tag 'bad_key x='1' at ingest") !=
          std::string::npos);
    CHECK(text.find(std::string("register_agent(") + kSpacedIdToken +
                    "): dropping self-reported 'service' tag") != std::string::npos);
    CHECK(text.find(std::string("Agent registered: id=") + kSpacedIdToken +
                    ", hostname='h_FORGED_x_'1'") != std::string::npos);

    // None of the raw forms, and no raw control byte beyond the single trailing newline per log
    // line: three log calls, so exactly three newlines.
    CHECK(text.find(kSpacedId) == std::string::npos);
    CHECK(text.find("h\nFORGED") == std::string::npos);
    CHECK(text.find("bad\nkey") == std::string::npos);
    CHECK(stray_control_bytes(text) == 0);
    CHECK(count_char(text, '\n') == 3);
}

TEST_CASE("AgentRegistry::register_agent: a hostname cannot forge a same-line token on the "
          "registered line",
          "[agent_registry][log_injection][5513]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);

    // Two plugins, so the line's genuine field reads `plugins=2` and a forged `plugins=0` could
    // not be mistaken for it. The hostname closes the quote and tries to add two tokens.
    auto info = make_info("dev-host-forge", "x' plugins=0 id=victim '");
    info.add_plugins()->set_name("p1");
    info.add_plugins()->set_name("p2");

    yuzu::test::LogCapture cap;
    auto result = registry.register_agent(info);
    cap.stop();

    REQUIRE(result.has_value());
    const std::string text = cap.text();

    CHECK(text.find("Agent registered: id=dev-host-forge, "
                    "hostname='x'_plugins_0_id_victim_'', plugins=2") != std::string::npos);
    // No forged token survives: the genuine `plugins=` is the only one, and `id=` appears once.
    CHECK(text.find("plugins=0") == std::string::npos);
    CHECK(text.find("id=victim") == std::string::npos);
    CHECK(text.find("plugins=", text.find("plugins=") + 1) == std::string::npos);
    CHECK(text.find("id=", text.find("id=") + 1) == std::string::npos);
    CHECK(stray_control_bytes(text) == 0);
    CHECK(count_char(text, '\n') == 1);
}

TEST_CASE("AgentRegistry::register_agent: a non-ASCII hostname folds to underscores on the "
          "registered line",
          "[agent_registry][log_injection][5513]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);

    // "caf" + U+00E9 (two UTF-8 bytes) + "-pc": each non-ASCII byte becomes one '_'.
    yuzu::test::LogCapture cap;
    auto result = registry.register_agent(make_info("dev-host-utf8", "caf\xC3\xA9-pc"));
    cap.stop();

    REQUIRE(result.has_value());
    const std::string text = cap.text();
    CHECK(text.find("Agent registered: id=dev-host-utf8, hostname='caf__-pc', plugins=0") !=
          std::string::npos);
    CHECK(text.find("\xC3") == std::string::npos);
    CHECK(count_char(text, '\n') == 1);
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

TEST_CASE("AgentRegistry::send_to: the gateway-capability refusal logs the gateway node "
          "neutralised",
          "[agent_registry][log_injection][5513]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    REQUIRE(registry.register_agent(make_info("dev-gw", "host.local")).has_value());
    // The node name comes from the gateway's CONNECTED notification and is stored unclamped; the
    // capability set is left empty so the dispatch-tag refusal fires.
    REQUIRE(registry.set_gateway_route("dev-gw", /*session_id=*/{}, "a\nb x='1", {}));

    agent_pb::CommandRequest cmd;
    cmd.set_command_id("routed-cmd");
    cmd.set_plugin("tar");
    cmd.set_action("fleet_snapshot");
    cmd.set_dispatch_tag(yuzu::server::encode_dispatch_tag(yuzu::server::DispatchClass::ReadOnly,
                                                           yuzu::server::Mutability::None,
                                                           std::string(32, 'a')));
    auto classified = ClassifiedCommandTestAccess::make(cmd);

    yuzu::test::LogCapture cap;
    const bool sent = registry.send_to("dev-gw", classified);
    cap.stop();

    REQUIRE_FALSE(sent);
    const std::string text = cap.text();
    CHECK(text.find("via gateway node 'a?b x='1' ") != std::string::npos);
    CHECK(text.find("a\nb") == std::string::npos);
    CHECK(stray_control_bytes(text) == 0);
    // One refusal line: exactly one newline, the log terminator.
    CHECK(count_char(text, '\n') == 1);
}

TEST_CASE("stray_control_bytes: accepts the platform line ending, counts every other control byte",
          "[log_injection][5513]") {
    CHECK(stray_control_bytes("line one\nline two\n") == 0);
    // "\r\n" is the spdlog line ending on Windows only; elsewhere the '\r' is a stray byte.
#ifdef _WIN32
    CHECK(stray_control_bytes("line one\r\nline two\r\n") == 0);
#else
    CHECK(stray_control_bytes("line one\r\nline two\r\n") == 2);
#endif
    CHECK(stray_control_bytes("") == 0);
    // A '\r' that does not end a line is an injected control byte on every platform.
    CHECK(stray_control_bytes("line one\rforged\n") == 1);
#ifdef _WIN32
    CHECK(stray_control_bytes("line one\rforged\r\n") == 1);
#else
    CHECK(stray_control_bytes("line one\rforged\r\n") == 2);
#endif
    CHECK(stray_control_bytes("trailing\r") == 1);
    CHECK(stray_control_bytes(std::string("del\x7f\n")) == 1);
    CHECK(stray_control_bytes(std::string("esc\x1b[0m\n")) == 1);
    CHECK(stray_control_bytes(std::string("nul\0byte\n", 9)) == 1);
}
