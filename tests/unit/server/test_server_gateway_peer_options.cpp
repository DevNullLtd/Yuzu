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
#include "gateway_peer_resolution.hpp"
#include "server_gateway_peer_options.hpp"

using yuzu::server::Config;
using yuzu::server::normalize_gateway_peer_options;
using yuzu::server::register_gateway_peer_options;

namespace gp = yuzu::server::gateway_peer;

namespace {

bool parse(const std::vector<std::string>& args, Config& cfg) {
    CLI::App app{"test"};
    register_gateway_peer_options(app, cfg);
    std::vector<const char*> argv;
    argv.push_back("yuzu-server");
    for (const auto& a : args)
        argv.push_back(a.c_str());
    try {
        app.parse(static_cast<int>(argv.size()), argv.data());
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

TEST_CASE("gateway peer options: a command-line pin makes the environment pins ignored, not merged",
          "[gateway_peer][options]") {
    // CLI11 semantics: an option given on the command line is not also read from its environment
    // variable. During a pin rotation, list BOTH pins in the same source.
    const std::string cli(64, 'a');
    const std::string env(64, 'b');
    yuzu::test::ScopedEnv e("YUZU_GATEWAY_PEER_PINS", env);
    Config cfg;
    REQUIRE(parse({"--gateway-peer-pin", cli}, cfg));
    normalize_gateway_peer_options(cfg);
    CHECK(cfg.gateway_peer_pins == std::vector<std::string>{cli}); // the env pin is NOT here

    Config env_only;
    REQUIRE(parse({}, env_only));
    normalize_gateway_peer_options(env_only);
    CHECK(env_only.gateway_peer_pins == std::vector<std::string>{env});

    // The same holds for the pin file option.
    yuzu::test::ScopedEnv ef("YUZU_GATEWAY_PEER_PIN_FILE", "/etc/yuzu/from-env.pem");
    Config files;
    REQUIRE(parse({"--gateway-peer-pin-file", "/etc/yuzu/from-cli.pem"}, files));
    CHECK(files.gateway_peer_pin_files == std::vector<std::string>{"/etc/yuzu/from-cli.pem"});
}

TEST_CASE("gateway peer options: normalize keeps a supplied-but-blank pin value visible",
          "[gateway_peer][options]") {
    const std::string a(64, 'a');
    const auto normalized = [](std::vector<std::string> args) {
        Config cfg;
        REQUIRE(parse(args, cfg));
        normalize_gateway_peer_options(cfg);
        return cfg.gateway_peer_pins;
    };

    SECTION("a value with no pin in it becomes one empty element") {
        CHECK(normalized({"--gateway-peer-pin", ""}) == std::vector<std::string>{""});
        CHECK(normalized({"--gateway-peer-pin", " "}) == std::vector<std::string>{""});
        CHECK(normalized({"--gateway-peer-pin", ","}) == std::vector<std::string>{""});
        CHECK(normalized({"--gateway-peer-pin", " , ,"}) == std::vector<std::string>{""});
    }
    SECTION("blank pieces NEXT TO a pin are harmless and add nothing") {
        CHECK(normalized({"--gateway-peer-pin", a + ",,"}) == std::vector<std::string>{a});
        CHECK(normalized({"--gateway-peer-pin", ", " + a + " ,"}) == std::vector<std::string>{a});
    }
    SECTION("a blank repeat next to a good one is kept, so the whole option is refused") {
        CHECK(normalized({"--gateway-peer-pin", a, "--gateway-peer-pin", ","}) ==
              (std::vector<std::string>{a, ""}));
    }
    SECTION("not supplied stays not supplied") {
        CHECK(normalized({}).empty());
    }
    SECTION("an EMPTY environment variable is unset to CLI11, a blank-but-non-empty one is supplied") {
        {
            yuzu::test::ScopedEnv e("YUZU_GATEWAY_PEER_PINS", "");
            Config cfg;
            REQUIRE(parse({}, cfg));
            normalize_gateway_peer_options(cfg);
            CHECK(cfg.gateway_peer_pins.empty()); // CLI11 does not treat an empty variable as set
        }
        for (const char* blank : {" ", ",", " , "}) {
            yuzu::test::ScopedEnv e("YUZU_GATEWAY_PEER_PINS", blank);
            Config cfg;
            REQUIRE(parse({}, cfg));
            normalize_gateway_peer_options(cfg);
            INFO("env value [" << blank << "]");
            CHECK(cfg.gateway_peer_pins == std::vector<std::string>{""});
        }
    }
}

namespace {

/// What the server does with a parsed Config on a TLS gateway-upstream deployment: resolve the
/// mode, then build the pins. Returns the refusal text, or "" when it would boot. The pin file
/// reader is the real one, so a path that does not exist is the real "does not exist" error.
std::string boot_refusal(const Config& cfg, bool default_creds, bool ack = false) {
    gp::ResolutionInputs in;
    in.service_enabled = true;
    in.tls_enabled = true;
    in.ca_present = true;
    in.grpc_creds_are_default = default_creds;
    // A path that cannot exist: a default certificate that WOULD auto-pin must never be reached.
    in.default_gateway_cert_path = "/nonexistent/yuzu_test_gwpeer/default-gateway.pem";
    in.hex_pins = cfg.gateway_peer_pins;
    in.pin_files = cfg.gateway_peer_pin_files;
    in.insecure_ack = ack;
    const auto res = gp::resolve_gateway_peer_authz(in);
    if (res.mode == gp::AuthzMode::Refuse)
        return res.refusal;
    if (res.mode != gp::AuthzMode::Enforce)
        return {};
    const auto boot = gp::build_boot_pins(in, res);
    return boot ? std::string{} : boot.error();
}

constexpr const char* kBlankPinText = "gateway peer pin option supplied but contains no pin";

} // namespace

TEST_CASE("gateway peer options: a supplied-but-blank pin value refuses at boot in every form, "
          "never reads as 'not supplied'",
          "[gateway_peer][options][boot]") {
    for (const bool default_creds : {true, false}) {
        INFO("default gRPC credentials: " << default_creds);
        for (const char* blank : {"", " ", ",", " , "}) {
            INFO("--gateway-peer-pin [" << blank << "]");
            Config cfg;
            REQUIRE(parse({"--gateway-peer-pin", blank}, cfg));
            normalize_gateway_peer_options(cfg);
            const std::string refusal = boot_refusal(cfg, default_creds);
            CHECK(refusal.find(kBlankPinText) != std::string::npos);
            // With the acknowledgement it is the contradiction, still a refusal.
            CHECK(boot_refusal(cfg, default_creds, /*ack=*/true).find("contradict") !=
                  std::string::npos);
        }
        for (const char* blank : {" ", ",", " , "}) {
            INFO("YUZU_GATEWAY_PEER_PINS [" << blank << "]");
            yuzu::test::ScopedEnv e("YUZU_GATEWAY_PEER_PINS", blank);
            Config cfg;
            REQUIRE(parse({}, cfg));
            normalize_gateway_peer_options(cfg);
            CHECK(boot_refusal(cfg, default_creds).find(kBlankPinText) != std::string::npos);
            CHECK(boot_refusal(cfg, default_creds, /*ack=*/true).find("contradict") !=
                  std::string::npos);
        }
    }
    SECTION("an empty pin FILE path stays its own error") {
        Config cfg;
        REQUIRE(parse({"--gateway-peer-pin-file", ""}, cfg));
        normalize_gateway_peer_options(cfg);
        for (const bool default_creds : {true, false})
            CHECK(boot_refusal(cfg, default_creds).find("was given an empty path") !=
                  std::string::npos);
    }
    SECTION("a blank-but-non-empty pin file variable names a file that does not exist") {
        yuzu::test::ScopedEnv e("YUZU_GATEWAY_PEER_PIN_FILE", " ");
        Config cfg;
        REQUIRE(parse({}, cfg));
        normalize_gateway_peer_options(cfg);
        CHECK_FALSE(boot_refusal(cfg, true).empty());
    }
    SECTION("a real pin with trailing commas boots (the control)") {
        Config cfg;
        REQUIRE(parse({"--gateway-peer-pin", std::string(64, 'a') + ",,"}, cfg));
        normalize_gateway_peer_options(cfg);
        CHECK(boot_refusal(cfg, false).empty());
    }
}
