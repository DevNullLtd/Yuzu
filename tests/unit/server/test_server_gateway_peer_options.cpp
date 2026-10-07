/**
 * test_server_gateway_peer_options.cpp: the operator-facing contract for the
 * gateway-upstream peer authorization knobs (server_gateway_peer_options.hpp):
 * flag names, env spellings, defaults, validation, and the boolean environment
 * semantics of --insecure-gateway-peer.
 *
 * Parsing runs in process against a real CLI::App, like test_server_ota_options.cpp.
 */

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

#include "../scoped_env.hpp"
#include "server_gateway_peer_options.hpp"

using yuzu::server::Config;
using yuzu::server::normalize_gateway_peer_options;
using yuzu::server::register_gateway_peer_options;

namespace {

bool parse(const std::vector<std::string>& args, Config& cfg) {
    CLI::App app{"test"};
    register_gateway_peer_options(app, cfg);
    std::vector<const char*> argv;
    argv.push_back("yuzu-server");
    for (const auto& a : args)
        argv.push_back(a.c_str());
    try {
        app.parse(static_cast<int>(argv.size()), const_cast<char**>(argv.data()));
        return true;
    } catch (const CLI::ParseError&) {
        return false;
    }
}

} // namespace

TEST_CASE("gateway peer options: names and env spellings are the documented contract",
          "[gateway_peer][options]") {
    CHECK(yuzu::server::kGatewayPeerPinFlag == "--gateway-peer-pin");
    CHECK(yuzu::server::kGatewayPeerPinFileFlag == "--gateway-peer-pin-file");
    CHECK(yuzu::server::kInsecureGatewayPeerFlag == "--insecure-gateway-peer");
    CHECK(yuzu::server::kGatewayPeerPinEnv == "YUZU_GATEWAY_PEER_PINS");
    CHECK(yuzu::server::kGatewayPeerPinFileEnv == "YUZU_GATEWAY_PEER_PIN_FILE");
    CHECK(yuzu::server::kInsecureGatewayPeerEnv == "YUZU_INSECURE_GATEWAY_PEER");
}

TEST_CASE("gateway peer options: defaults are safe and documented", "[gateway_peer][options]") {
    Config cfg;
    REQUIRE(parse({}, cfg));
    CHECK(cfg.gateway_peer_pins.empty());
    CHECK(cfg.gateway_peer_pin_files.empty());
    CHECK_FALSE(cfg.insecure_gateway_peer); // the acknowledgement is OFF unless asked for
}

TEST_CASE("gateway peer options: flags bind to the right Config fields", "[gateway_peer][options]") {
    Config cfg;
    const std::string a(64, 'a');
    const std::string b(64, 'b');
    REQUIRE(parse({"--gateway-peer-pin", a, "--gateway-peer-pin", b, "--gateway-peer-pin-file",
                   "/etc/yuzu/gw1.pem", "--gateway-peer-pin-file", "/etc/yuzu/gw2.pem",
                   "--insecure-gateway-peer"},
                  cfg));
    CHECK(cfg.gateway_peer_pins == std::vector<std::string>{a, b});
    CHECK(cfg.gateway_peer_pin_files ==
          std::vector<std::string>{"/etc/yuzu/gw1.pem", "/etc/yuzu/gw2.pem"});
    CHECK(cfg.insecure_gateway_peer);
}

TEST_CASE("gateway peer options: there is no reload option", "[gateway_peer][options]") {
    // Pins are fixed at boot; a reload knob must not exist (removing the pin means a restart).
    Config cfg;
    CHECK_FALSE(parse({"--gateway-peer-pin-reload-interval", "30"}, cfg));
}

TEST_CASE("gateway peer options: comma-separated pins are split exactly once", "[gateway_peer][options]") {
    Config cfg;
    const std::string a(64, 'a');
    const std::string b(64, 'b');
    const std::string c(64, 'c');
    REQUIRE(parse({"--gateway-peer-pin", a + "," + b + " , ,", "--gateway-peer-pin", c}, cfg));
    normalize_gateway_peer_options(cfg);
    CHECK(cfg.gateway_peer_pins == std::vector<std::string>{a, b, c});
}

TEST_CASE("gateway peer options: environment forms", "[gateway_peer][options]") {
    const std::string a(64, 'a');
    const std::string b(64, 'b');

    SECTION("comma-separated pins") {
        yuzu::test::ScopedEnv env("YUZU_GATEWAY_PEER_PINS", a + "," + b);
        Config cfg;
        REQUIRE(parse({}, cfg));
        normalize_gateway_peer_options(cfg);
        CHECK(cfg.gateway_peer_pins == std::vector<std::string>{a, b});
    }
    SECTION("a single pin file path") {
        yuzu::test::ScopedEnv env("YUZU_GATEWAY_PEER_PIN_FILE", "/etc/yuzu/gw.pem");
        Config cfg;
        REQUIRE(parse({}, cfg));
        CHECK(cfg.gateway_peer_pin_files == std::vector<std::string>{"/etc/yuzu/gw.pem"});
    }
    SECTION("the acknowledgement honours boolean values: 1 enables") {
        yuzu::test::ScopedEnv env("YUZU_INSECURE_GATEWAY_PEER", "1");
        Config cfg;
        REQUIRE(parse({}, cfg));
        CHECK(cfg.insecure_gateway_peer);
    }
    SECTION("the acknowledgement honours boolean values: 0 does NOT enable") {
        yuzu::test::ScopedEnv env("YUZU_INSECURE_GATEWAY_PEER", "0");
        Config cfg;
        REQUIRE(parse({}, cfg));
        CHECK_FALSE(cfg.insecure_gateway_peer);
    }
    SECTION("the acknowledgement honours boolean values: false does NOT enable") {
        yuzu::test::ScopedEnv env("YUZU_INSECURE_GATEWAY_PEER", "false");
        Config cfg;
        REQUIRE(parse({}, cfg));
        CHECK_FALSE(cfg.insecure_gateway_peer);
    }
}

TEST_CASE("gateway peer options: the acknowledgement flag forms",
          "[gateway_peer][options]") {
    // The bare flag enables it and an explicit `=false` on the command line does not.
    Config on;
    REQUIRE(parse({"--insecure-gateway-peer"}, on));
    CHECK(on.insecure_gateway_peer);
    Config off;
    REQUIRE(parse({"--insecure-gateway-peer=false"}, off));
    CHECK_FALSE(off.insecure_gateway_peer);
}

TEST_CASE("gateway peer options: the command line wins over the environment",
          "[gateway_peer][options]") {
    yuzu::test::ScopedEnv env("YUZU_INSECURE_GATEWAY_PEER", "1");
    Config cfg;
    REQUIRE(parse({"--insecure-gateway-peer=false"}, cfg));
    CHECK_FALSE(cfg.insecure_gateway_peer);
}
