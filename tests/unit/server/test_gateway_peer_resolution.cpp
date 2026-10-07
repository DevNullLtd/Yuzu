/**
 * test_gateway_peer_resolution.cpp: the boot decision for gateway-upstream peer
 * authorization (gateway_peer_resolution.hpp) and the boot pin set builder.
 *
 * Pure: no sockets, no sleeps. The boot pin cases use an injected file reader and a PEM
 * generated in the test.
 */

#include <catch2/catch_test_macros.hpp>

#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include "gateway_peer_audit.hpp"
#include "gateway_peer_cert.hpp"
#include "gateway_peer_resolution.hpp"
#include "gateway_peer_test_pki.hpp"
#include "server_gateway_peer_options.hpp"
#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

namespace gp = yuzu::server::gateway_peer;
namespace gwt = yuzu::test::gwpeer;
using gp::AuthzMode;
using gp::ResolutionInputs;

namespace {

constexpr const char* kDefaultGw = "/etc/yuzu/certs/default-gateway.pem";

std::string hex_pin(char c) { return std::string(64, c); }

/// A gateway-upstream deployment on TLS with a client CA, on the generated default
/// certificate set, nothing explicit: the auto-pin row. Tests mutate one input.
ResolutionInputs defaults_tls() {
    ResolutionInputs in;
    in.service_enabled = true;
    in.tls_enabled = true;
    in.ca_present = true;
    in.grpc_creds_are_default = true;
    in.default_gateway_cert_path = kDefaultGw;
    return in;
}

/// Operator certificates, nothing explicit: refuses until a pin is added.
ResolutionInputs operator_tls() {
    ResolutionInputs in = defaults_tls();
    in.grpc_creds_are_default = false;
    in.default_gateway_cert_path.clear();
    return in;
}

bool mentions(const std::string& text, std::string_view needle) {
    return text.find(needle) != std::string::npos;
}

bool any_warning_mentions(const gp::Resolution& r, std::string_view needle) {
    for (const auto& w : r.warnings)
        if (mentions(w, needle))
            return true;
    return false;
}

} // namespace

// -- the decision table ---------------------------------------------------------------

TEST_CASE("gateway_peer_resolution: service disabled resolves to nothing", "[gateway_peer][resolution]") {
    ResolutionInputs in; // service_enabled=false, everything else default
    auto r = gp::resolve_gateway_peer_authz(in);
    CHECK(r.mode == AuthzMode::Disabled);
    CHECK(r.refusal.empty());
    CHECK(r.warnings.empty());
    CHECK_FALSE(r.auto_pin);

    SECTION("an acknowledgement with the service disabled is ignored with a warning") {
        in.insecure_ack = true;
        r = gp::resolve_gateway_peer_authz(in);
        CHECK(r.mode == AuthzMode::Disabled);
        CHECK(any_warning_mentions(r, "--insecure-gateway-peer"));
    }
    SECTION("pins with the service disabled are ignored with a warning, never an error") {
        in.hex_pins = {hex_pin('a')};
        r = gp::resolve_gateway_peer_authz(in);
        CHECK(r.mode == AuthzMode::Disabled);
        CHECK(r.refusal.empty());
        CHECK(any_warning_mentions(r, "ignored"));
    }
}

TEST_CASE("gateway_peer_resolution: acknowledgement alone runs insecure with one loud alarm",
          "[gateway_peer][resolution]") {
    ResolutionInputs in;
    in.service_enabled = true;
    in.tls_enabled = false;
    in.insecure_ack = true;
    const auto r = gp::resolve_gateway_peer_authz(in);
    CHECK(r.mode == AuthzMode::InsecureAck);
    CHECK(r.refusal.empty());
    // ONE alarm carries the "disabled" wording, and the warnings list does not repeat it.
    CHECK(mentions(r.alarm, "GATEWAY PEER AUTHORIZATION IS DISABLED"));
    CHECK(mentions(r.alarm, "--insecure-gateway-peer"));
    CHECK_FALSE(any_warning_mentions(r, "DISABLED"));
    CHECK(r.warnings.empty()); // plaintext: nothing about pinning being available
    CHECK(gp::to_label(r.mode) == "insecure_ack");
}

TEST_CASE("gateway_peer_resolution: an acknowledgement with TLS and a client CA is its own mode",
          "[gateway_peer][resolution]") {
    auto in = defaults_tls(); // TLS on, client CA present
    in.insecure_ack = true;
    const auto r = gp::resolve_gateway_peer_authz(in);
    CHECK(r.mode == AuthzMode::InsecureAckTls);
    CHECK(gp::to_label(r.mode) == "insecure_ack_tls");
    CHECK_FALSE(r.auto_pin);
    CHECK(r.refusal.empty());
    CHECK(mentions(r.alarm, "GATEWAY PEER AUTHORIZATION IS DISABLED"));
    CHECK(any_warning_mentions(r, "pinning is available"));

    SECTION("with operator certificates too: the mode keys on TLS and the CA, not on the certificate set") {
        in = operator_tls();
        in.insecure_ack = true;
        const auto r2 = gp::resolve_gateway_peer_authz(in);
        CHECK(r2.mode == AuthzMode::InsecureAckTls);
    }
}

TEST_CASE("gateway_peer_resolution: an acknowledgement without TLS or without a client CA stays "
          "insecure_ack",
          "[gateway_peer][resolution]") {
    auto in = defaults_tls();
    in.insecure_ack = true;
    SECTION("no client CA") {
        in.ca_present = false;
        const auto r = gp::resolve_gateway_peer_authz(in);
        CHECK(r.mode == AuthzMode::InsecureAck);
        CHECK(mentions(r.alarm, "DISABLED"));
        CHECK_FALSE(any_warning_mentions(r, "pinning is available")); // it is not
    }
    SECTION("no TLS") {
        in.tls_enabled = false;
        const auto r = gp::resolve_gateway_peer_authz(in);
        CHECK(r.mode == AuthzMode::InsecureAck);
    }
    SECTION("the service disabled sets no alarm") {
        in.service_enabled = false;
        const auto r = gp::resolve_gateway_peer_authz(in);
        CHECK(r.mode == AuthzMode::Disabled);
        CHECK(r.alarm.empty());
    }
}

TEST_CASE("gateway_peer_resolution: an acknowledgement never overrides configured pins",
          "[gateway_peer][resolution]") {
    for (const bool tls : {false, true}) {
        INFO("tls=" << tls);
        auto in = defaults_tls();
        in.tls_enabled = tls;
        in.insecure_ack = true;
        SECTION("hex pin") {
            in.hex_pins = {hex_pin('a')};
            const auto r = gp::resolve_gateway_peer_authz(in);
            CHECK(r.mode == AuthzMode::Refuse);
            CHECK(mentions(r.refusal, "contradict"));
            CHECK(mentions(r.refusal, "--insecure-gateway-peer"));
            CHECK(mentions(r.refusal, "--gateway-peer-pin"));
        }
        SECTION("pin file") {
            in.pin_files = {"/etc/yuzu/gw.pem"};
            const auto r = gp::resolve_gateway_peer_authz(in);
            CHECK(r.mode == AuthzMode::Refuse);
            CHECK(mentions(r.refusal, "contradict"));
        }
    }
}

TEST_CASE("gateway_peer_resolution: --no-tls without an acknowledgement refuses", "[gateway_peer][resolution]") {
    auto in = defaults_tls();
    in.tls_enabled = false;
    auto r = gp::resolve_gateway_peer_authz(in);
    CHECK(r.mode == AuthzMode::Refuse);
    CHECK(mentions(r.refusal, "--no-tls"));
    CHECK(mentions(r.refusal, "not an acknowledgement"));
    CHECK(mentions(r.refusal, "--insecure-gateway-peer"));
    CHECK(mentions(r.refusal, "Refusing to start"));
    CHECK(mentions(r.refusal, "omit --gateway-upstream"));

    SECTION("pins cannot rescue it: they could never match") {
        in.hex_pins = {hex_pin('a')};
        r = gp::resolve_gateway_peer_authz(in);
        CHECK(r.mode == AuthzMode::Refuse);
        CHECK(mentions(r.refusal, "--no-tls"));
    }
}

TEST_CASE("gateway_peer_resolution: no client CA (skip-verify) without an acknowledgement refuses",
          "[gateway_peer][resolution]") {
    auto in = operator_tls();
    in.ca_present = false;
    in.hex_pins = {hex_pin('a')}; // present, and still useless
    auto r = gp::resolve_gateway_peer_authz(in);
    CHECK(r.mode == AuthzMode::Refuse);
    CHECK(mentions(r.refusal, "no client CA"));
    CHECK(mentions(r.refusal, "--ca-cert"));
    CHECK(mentions(r.refusal, "--insecure-gateway-peer"));
    CHECK_FALSE(mentions(r.refusal, "or see:")); // reads as one sentence, not a dangling pointer
    CHECK(mentions(r.refusal, "omit --gateway-upstream"));

    SECTION("also on the default-certificate path") {
        in = defaults_tls();
        in.ca_present = false;
        r = gp::resolve_gateway_peer_authz(in);
        CHECK(r.mode == AuthzMode::Refuse);
    }
}

TEST_CASE("gateway_peer_resolution: operator certificates without a pin refuse", "[gateway_peer][resolution]") {
    const auto r = gp::resolve_gateway_peer_authz(operator_tls());
    CHECK(r.mode == AuthzMode::Refuse);
    CHECK(mentions(r.refusal, "operator-supplied"));
    CHECK(mentions(r.refusal, "--gateway-peer-pin"));
    CHECK(mentions(r.refusal, "--gateway-peer-pin-file"));
    CHECK(mentions(r.refusal, "openssl x509 -pubkey"));
    CHECK(mentions(r.refusal, "awk '{print $NF}'")); // the hint is paste-ready
    CHECK(mentions(r.refusal, "Refusing to start"));
    // An install that runs no gateway has a way out that is not "pin something".
    CHECK(mentions(r.refusal, "omit --gateway-upstream"));
    CHECK_FALSE(r.auto_pin);
}

TEST_CASE("gateway_peer_resolution: default gRPC certificates auto-pin the default gateway certificate",
          "[gateway_peer][resolution]") {
    const auto r = gp::resolve_gateway_peer_authz(defaults_tls());
    CHECK(r.mode == AuthzMode::Enforce);
    CHECK(r.auto_pin);
    CHECK(r.auto_pin_file == kDefaultGw);
    CHECK(r.refusal.empty());
    CHECK(r.warnings.empty()); // no --cert-group, nothing to say
    CHECK(gp::to_label(r.mode) == "enforce");
}

TEST_CASE("gateway_peer_resolution: HTTPS on defaults while gRPC uses operator certificates does NOT auto-pin",
          "[gateway_peer][resolution][mixed]") {
    // The caller derives grpc_creds_are_default from the gRPC credentials, not from
    // using_default_certs; HTTPS-only defaults leave it false. Pinned here at the
    // seam: with that input false, the default gateway path is irrelevant.
    auto in = operator_tls();
    in.default_gateway_cert_path = kDefaultGw; // exists on disk because HTTPS bootstrapped defaults
    const auto r = gp::resolve_gateway_peer_authz(in);
    CHECK(r.mode == AuthzMode::Refuse);
    CHECK_FALSE(r.auto_pin);
    CHECK(r.auto_pin_file.empty());
}

TEST_CASE("gateway_peer_resolution: explicit pins always win over the auto-pin", "[gateway_peer][resolution]") {
    auto in = defaults_tls();
    SECTION("hex pin") {
        in.hex_pins = {hex_pin('b')};
        const auto r = gp::resolve_gateway_peer_authz(in);
        CHECK(r.mode == AuthzMode::Enforce);
        CHECK_FALSE(r.auto_pin);
        CHECK(r.auto_pin_file.empty());
    }
    SECTION("pin file") {
        in.pin_files = {"/etc/yuzu/gw.pem"};
        const auto r = gp::resolve_gateway_peer_authz(in);
        CHECK(r.mode == AuthzMode::Enforce);
        CHECK_FALSE(r.auto_pin);
    }
    SECTION("operator certificates with a pin enforce") {
        auto op = operator_tls();
        op.hex_pins = {hex_pin('c')};
        const auto r = gp::resolve_gateway_peer_authz(op);
        CHECK(r.mode == AuthzMode::Enforce);
        CHECK_FALSE(r.auto_pin);
    }
}

TEST_CASE("gateway_peer_resolution: the auto-pin needs to know the default gateway certificate",
          "[gateway_peer][resolution]") {
    auto in = defaults_tls();
    in.default_gateway_cert_path.clear();
    const auto r = gp::resolve_gateway_peer_authz(in);
    CHECK(r.mode == AuthzMode::Refuse);
    CHECK(mentions(r.refusal, "default gateway certificate path is unknown"));
}

TEST_CASE("gateway_peer_resolution: --cert-group warns about key sharing whenever the default key is in play",
          "[gateway_peer][resolution]") {
    auto in = defaults_tls();
    in.cert_group = "yuzu-pki";
    SECTION("auto-pin") {
        const auto r = gp::resolve_gateway_peer_authz(in);
        REQUIRE(r.mode == AuthzMode::Enforce);
        REQUIRE(r.warnings.size() == 1);
        CHECK(mentions(r.warnings[0], "any process in that group holds gateway authority"));
        CHECK(mentions(r.warnings[0], "gateway-only certificate with a 0600 key"));
        CHECK(mentions(r.warnings[0], "pin it explicitly"));
    }
    SECTION("explicit pin on default gRPC certificates still warns") {
        in.hex_pins = {hex_pin('d')};
        const auto r = gp::resolve_gateway_peer_authz(in);
        REQUIRE(r.mode == AuthzMode::Enforce);
        CHECK(any_warning_mentions(r, "any process in that group"));
    }
    SECTION("no warning when the service is off") {
        in.service_enabled = false;
        CHECK(gp::resolve_gateway_peer_authz(in).warnings.empty());
    }
}

TEST_CASE("gateway_peer_resolution: the boot decision matrix, one row per line",
          "[gateway_peer][resolution][matrix]") {
    // Mirrors the table in the file banner of gateway_peer_resolution.hpp row for row.
    struct Row {
        const char* name;
        bool service, ack, explicit_pins, tls, ca, default_creds;
        AuthzMode mode;
        bool auto_pin;
    };
    const std::vector<Row> rows{
        {"service off", false, true, true, false, false, false, AuthzMode::Disabled, false},
        {"ack + explicit pins", true, true, true, true, true, true, AuthzMode::Refuse, false},
        {"ack + explicit pins, plaintext", true, true, true, false, false, false, AuthzMode::Refuse, false},
        {"ack, tls, ca", true, true, false, true, true, true, AuthzMode::InsecureAckTls, false},
        {"ack, tls, ca, operator certs", true, true, false, true, true, false, AuthzMode::InsecureAckTls, false},
        {"ack, plaintext", true, true, false, false, false, false, AuthzMode::InsecureAck, false},
        {"ack, tls, no ca", true, true, false, true, false, false, AuthzMode::InsecureAck, false},
        {"no ack, plaintext (--no-tls is not an ack)", true, false, false, false, false, false, AuthzMode::Refuse, false},
        {"no ack, plaintext, pins", true, false, true, false, false, false, AuthzMode::Refuse, false},
        {"no ack, tls, no ca", true, false, false, true, false, true, AuthzMode::Refuse, false},
        {"no ack, explicit pins, tls, ca", true, false, true, true, true, false, AuthzMode::Enforce, false},
        {"no ack, explicit pins, default creds", true, false, true, true, true, true, AuthzMode::Enforce, false},
        {"no ack, no pins, default creds: auto-pin", true, false, false, true, true, true, AuthzMode::Enforce, true},
        {"no ack, no pins, operator certs", true, false, false, true, true, false, AuthzMode::Refuse, false},
    };
    for (const auto& row : rows) {
        INFO(row.name);
        ResolutionInputs in;
        in.service_enabled = row.service;
        in.insecure_ack = row.ack;
        in.tls_enabled = row.tls;
        in.ca_present = row.ca;
        in.grpc_creds_are_default = row.default_creds;
        in.default_gateway_cert_path = kDefaultGw;
        if (row.explicit_pins)
            in.hex_pins = {hex_pin('a')};
        const auto r = gp::resolve_gateway_peer_authz(in);
        CHECK(r.mode == row.mode);
        CHECK(r.auto_pin == row.auto_pin);
        CHECK(r.refusal.empty() == (row.mode != AuthzMode::Refuse));
        CHECK(r.alarm.empty() ==
              (row.mode != AuthzMode::InsecureAck && row.mode != AuthzMode::InsecureAckTls));
    }
}

TEST_CASE("gateway_peer_resolution: an acknowledgement suppresses the auto-pin on default certificates",
          "[gateway_peer][resolution]") {
    auto in = defaults_tls();
    in.insecure_ack = true;
    const auto r = gp::resolve_gateway_peer_authz(in);
    CHECK(r.mode == AuthzMode::InsecureAckTls);
    CHECK_FALSE(r.auto_pin);
    CHECK(r.auto_pin_file.empty());
}

TEST_CASE("gateway_peer_resolution: a default-constructed Resolution refuses", "[gateway_peer][resolution]") {
    const gp::Resolution r;
    CHECK(r.mode == AuthzMode::Refuse);
}

TEST_CASE("gateway_peer_resolution: the mode labels are the closed gauge set", "[gateway_peer][resolution]") {
    std::vector<std::string_view> labels;
    for (const auto m : gp::kRunnableAuthzModes)
        labels.push_back(gp::to_label(m));
    CHECK(labels == std::vector<std::string_view>{"enforce", "insecure_ack", "insecure_ack_tls",
                                                  "disabled"});
}

TEST_CASE("gateway_peer_resolution: every mode label is pinned to its literal",
          "[gateway_peer][resolution][literals]") {
    const std::vector<std::pair<AuthzMode, std::string_view>> table{
        {AuthzMode::Disabled, "disabled"},
        {AuthzMode::Enforce, "enforce"},
        {AuthzMode::InsecureAck, "insecure_ack"},
        {AuthzMode::InsecureAckTls, "insecure_ack_tls"},
        {AuthzMode::Refuse, "refused"},
    };
    for (const auto& [mode, label] : table) {
        INFO("label " << label);
        CHECK(gp::to_label(mode) == label);
    }
}

TEST_CASE("gateway_peer_resolution: the boot audit row for an acknowledged mode",
          "[gateway_peer][resolution][audit][literals]") {
    CHECK(std::string{gp::kAuthzDisabledAuditAction} == "server.gateway_peer_authz_disabled");
    struct Row {
        AuthzMode mode;
        bool tls;
        const char* detail;
    };
    for (const Row& row : {Row{AuthzMode::InsecureAck, false, "mode=insecure_ack tls=false"},
                           Row{AuthzMode::InsecureAckTls, true, "mode=insecure_ack_tls tls=true"},
                           Row{AuthzMode::InsecureAck, true, "mode=insecure_ack tls=true"}}) {
        INFO(row.detail);
        const auto ev = gp::make_authz_disabled_audit_event(row.mode, row.tls);
        CHECK(ev.principal == "system");
        CHECK(ev.action == "server.gateway_peer_authz_disabled");
        CHECK(ev.target_type == "GatewayUpstream");
        CHECK(ev.target_id == "peer_authorization");
        CHECK(ev.detail == row.detail);
        CHECK(ev.result == "success");
        CHECK(ev.timestamp > 0);
    }
}

TEST_CASE("gateway_peer_resolution: an audit row that is skipped or fails is warned about",
          "[gateway_peer][resolution][audit]") {
    // The boot posture row goes through this helper, so a missing audit trail is a log line and
    // never a silent skip.
    const auto ev = gp::make_authz_disabled_audit_event(AuthzMode::InsecureAck, false);
    int written = 0;
    const std::function<bool(const yuzu::server::AuditEvent&)> ok = [&](const yuzu::server::AuditEvent&) {
        ++written;
        return true;
    };

    const auto count = [](const std::string& text, const std::string& needle) {
        std::size_t n = 0;
        for (auto at = text.find(needle); at != std::string::npos; at = text.find(needle, at + 1))
            ++n;
        return n;
    };

    SECTION("written: no warning") {
        yuzu::test::LogCapture cap;
        CHECK(gp::write_audit_row_or_warn(true, ok, ev));
        cap.stop();
        CHECK(written == 1);
        CHECK(cap.text().find("[warning]") == std::string::npos);
    }
    SECTION("the audit store is not open: skipped, warned, the action named") {
        yuzu::test::LogCapture cap;
        CHECK_FALSE(gp::write_audit_row_or_warn(false, ok, ev));
        cap.stop();
        CHECK(written == 0);
        const std::string text = cap.text();
        CHECK(count(text, "[warning]") == 1);
        CHECK(text.find("server.gateway_peer_authz_disabled") != std::string::npos);
        CHECK(text.find("audit store is not open") != std::string::npos);
    }
    SECTION("log() returned false: warned") {
        yuzu::test::LogCapture cap;
        const std::function<bool(const yuzu::server::AuditEvent&)> bad =
            [](const yuzu::server::AuditEvent&) { return false; };
        CHECK_FALSE(gp::write_audit_row_or_warn(true, bad, ev));
        cap.stop();
        const std::string text = cap.text();
        CHECK(count(text, "[warning]") == 1);
        CHECK(text.find("server.gateway_peer_authz_disabled") != std::string::npos);
        CHECK(text.find("write failed") != std::string::npos);
    }
    SECTION("log() threw: contained, warned") {
        yuzu::test::LogCapture cap;
        const std::function<bool(const yuzu::server::AuditEvent&)> boom =
            [](const yuzu::server::AuditEvent&) -> bool { throw std::runtime_error("db down"); };
        CHECK_FALSE(gp::write_audit_row_or_warn(true, boom, ev));
        cap.stop();
        CHECK(count(cap.text(), "[warning]") == 1);
    }
}

// -- boot pin set ------------------------------------------------------------------

namespace {

struct Files {
    std::map<std::string, std::string> content;
    gp::FileReader reader() {
        return [this](const std::string& path, std::size_t) {
            gp::FileReadResult r;
            const auto it = content.find(path);
            if (it == content.end()) {
                r.status = gp::FileReadResult::Status::Missing;
                return r;
            }
            r.status = gp::FileReadResult::Status::Ok;
            r.content = it->second;
            return r;
        };
    }
};

std::string spki_of(const std::string& pem) {
    const auto facts = gp::parse_cert_facts(pem);
    REQUIRE(facts.has_value());
    return facts->spki_sha256_hex;
}

} // namespace

TEST_CASE("gateway_peer_resolution: boot pins for the auto-pin loads the default gateway certificate",
          "[gateway_peer][resolution][boot]") {
    const auto ca = gwt::make_ca("Boot CA");
    const auto gw = gwt::make_gateway_leaf(ca);
    Files files;
    files.content[kDefaultGw] = gw.cert_pem;

    const auto in = defaults_tls();
    const auto res = gp::resolve_gateway_peer_authz(in);
    REQUIRE(res.auto_pin);
    auto boot = gp::build_boot_pins(in, res, files.reader());
    REQUIRE(boot.has_value());
    REQUIRE(boot->pins);
    CHECK(boot->pins->contains(spki_of(gw.cert_pem)));
    CHECK(boot->pins->size() == 1);
    CHECK(boot->warnings.empty());
}

TEST_CASE("gateway_peer_resolution: zero resolvable pins at boot refuses", "[gateway_peer][resolution][boot]") {
    Files files; // the default gateway certificate is missing
    const auto in = defaults_tls();
    const auto res = gp::resolve_gateway_peer_authz(in);
    auto boot = gp::build_boot_pins(in, res, files.reader());
    REQUIRE_FALSE(boot.has_value());
    CHECK(mentions(boot.error(), "pin configuration is invalid"));
    CHECK(mentions(boot.error(), kDefaultGw));
    CHECK(mentions(boot.error(), "does not exist"));
    CHECK(mentions(boot.error(), "automatic pin")); // names what to restore
    CHECK(mentions(boot.error(), "Refusing to start"));
}

TEST_CASE("gateway_peer_resolution: a broken explicit source never falls back to the auto-pin",
          "[gateway_peer][resolution][boot]") {
    const auto ca = gwt::make_ca("Boot CA");
    const auto gw = gwt::make_gateway_leaf(ca);
    Files files;
    files.content[kDefaultGw] = gw.cert_pem; // a perfectly good default certificate exists
    files.content["/etc/yuzu/gw-explicit.pem"] = "this is not a pin file\n";

    auto in = defaults_tls();
    in.pin_files = {"/etc/yuzu/gw-explicit.pem"};
    const auto res = gp::resolve_gateway_peer_authz(in);
    REQUIRE(res.mode == AuthzMode::Enforce);
    REQUIRE_FALSE(res.auto_pin);
    auto boot = gp::build_boot_pins(in, res, files.reader());
    REQUIRE_FALSE(boot.has_value()); // malformed at boot is an operator error
    CHECK(mentions(boot.error(), "gw-explicit.pem"));
}

TEST_CASE("gateway_peer_resolution: a missing explicit pin file with no other pin refuses, not auto-pins",
          "[gateway_peer][resolution][boot]") {
    const auto ca = gwt::make_ca("Boot CA");
    const auto gw = gwt::make_gateway_leaf(ca);
    Files files;
    files.content[kDefaultGw] = gw.cert_pem;

    auto in = defaults_tls();
    in.pin_files = {"/etc/yuzu/absent.pem"};
    const auto res = gp::resolve_gateway_peer_authz(in);
    auto boot = gp::build_boot_pins(in, res, files.reader());
    REQUIRE_FALSE(boot.has_value());
    CHECK(mentions(boot.error(), "absent.pem"));
    CHECK(mentions(boot.error(), "does not exist"));
}

TEST_CASE("gateway_peer_resolution: a malformed hex pin is rejected at boot", "[gateway_peer][resolution][boot]") {
    Files files;
    auto in = operator_tls();
    in.hex_pins = {hex_pin('a'), "not-a-pin"};
    const auto res = gp::resolve_gateway_peer_authz(in);
    REQUIRE(res.mode == AuthzMode::Enforce);
    auto boot = gp::build_boot_pins(in, res, files.reader());
    REQUIRE_FALSE(boot.has_value());
    CHECK(mentions(boot.error(), "not-a-pi")); // the loader names a truncated prefix of the entry
    CHECK(mentions(boot.error(), "Refusing to start"));
}

TEST_CASE("gateway_peer_resolution: one missing file among valid pins still refuses",
          "[gateway_peer][resolution][boot]") {
    // Boot-fixed pins: a source that cannot be read is an operator error, never a warning that
    // quietly shrinks the set.
    Files files;
    auto in = operator_tls();
    in.hex_pins = {hex_pin('a')};
    in.pin_files = {"/etc/yuzu/absent.pem"};
    const auto res = gp::resolve_gateway_peer_authz(in);
    auto boot = gp::build_boot_pins(in, res, files.reader());
    REQUIRE_FALSE(boot.has_value());
    CHECK(mentions(boot.error(), "absent.pem"));
    CHECK(mentions(boot.error(), "--gateway-peer-pin")); // names the flags to fix it
}

TEST_CASE("gateway_peer_resolution: a pin file whose certificate lacks serverAuth boots with a warning",
          "[gateway_peer][resolution][boot]") {
    const auto ca = gwt::make_ca("Boot CA");
    const auto agent = gwt::make_agent_leaf(ca);
    Files files;
    files.content["/etc/yuzu/agent-as-gw.pem"] = agent.cert_pem;
    auto in = operator_tls();
    in.pin_files = {"/etc/yuzu/agent-as-gw.pem"};
    const auto res = gp::resolve_gateway_peer_authz(in);
    auto boot = gp::build_boot_pins(in, res, files.reader());
    REQUIRE(boot.has_value());
    CHECK(boot->pins->size() == 1);
    REQUIRE(boot->warnings.size() == 1);
    CHECK(mentions(boot->warnings.front(), "without serverAuth"));
    CHECK(mentions(boot->warnings.front(), "deny"));
}

TEST_CASE("gateway_peer_resolution: a gateway certificate with serverAuth boots without a warning",
          "[gateway_peer][resolution][boot]") {
    const auto ca = gwt::make_ca("Boot CA");
    const auto gw = gwt::make_gateway_leaf(ca);
    Files files;
    files.content["/etc/yuzu/gw.pem"] = gw.cert_pem;
    auto in = operator_tls();
    in.pin_files = {"/etc/yuzu/gw.pem"};
    const auto res = gp::resolve_gateway_peer_authz(in);
    auto boot = gp::build_boot_pins(in, res, files.reader());
    REQUIRE(boot.has_value());
    CHECK(boot->warnings.empty());
}

TEST_CASE("gateway_peer_resolution: the union of hex pins and pin files boots",
          "[gateway_peer][resolution][boot]") {
    const auto ca = gwt::make_ca("Boot CA");
    const auto gw = gwt::make_gateway_leaf(ca);
    Files files;
    files.content["/etc/yuzu/gw.pem"] = gw.cert_pem;
    auto in = operator_tls();
    in.hex_pins = {hex_pin('a')};
    in.pin_files = {"/etc/yuzu/gw.pem"};
    const auto res = gp::resolve_gateway_peer_authz(in);
    auto boot = gp::build_boot_pins(in, res, files.reader());
    REQUIRE(boot.has_value());
    CHECK(boot->pins->size() == 2);
    CHECK(boot->pins->contains(hex_pin('a')));
    CHECK(boot->pins->contains(spki_of(gw.cert_pem)));
}

TEST_CASE("gateway_peer_resolution: an explicit pin keeps the auto-pin certificate out of the set",
          "[gateway_peer][resolution][boot]") {
    // Default gRPC credentials AND an explicit pin: the explicit pin wins outright, the default
    // gateway certificate is NOT added to the set.
    const auto ca = gwt::make_ca("Boot CA");
    const auto gw = gwt::make_gateway_leaf(ca);
    Files files;
    files.content[kDefaultGw] = gw.cert_pem;
    auto in = defaults_tls();
    in.hex_pins = {hex_pin('c')};
    const auto res = gp::resolve_gateway_peer_authz(in);
    REQUIRE(res.mode == AuthzMode::Enforce);
    REQUIRE_FALSE(res.auto_pin);
    auto boot = gp::build_boot_pins(in, res, files.reader());
    REQUIRE(boot.has_value());
    CHECK(boot->pins->size() == 1);
    CHECK_FALSE(boot->pins->contains(spki_of(gw.cert_pem)));
}

TEST_CASE("gateway_peer_resolution: the boot pins are built only for an Enforce resolution",
          "[gateway_peer][resolution][boot]") {
    gp::Resolution refuse; // default: Refuse
    auto boot = gp::build_boot_pins(ResolutionInputs{}, refuse);
    CHECK_FALSE(boot.has_value());
}

TEST_CASE("gateway_peer_resolution: explicit hex pins boot with no files at all", "[gateway_peer][resolution][boot]") {
    auto in = operator_tls();
    in.hex_pins = {hex_pin('e'), hex_pin('f')};
    const auto res = gp::resolve_gateway_peer_authz(in);
    auto boot = gp::build_boot_pins(in, res);
    REQUIRE(boot.has_value());
    CHECK(boot->pins->size() == 2);
}

// -- listener posture ---------------------------------------------------------------------

namespace {

/// The default-certificate deployment: agent listener on the generated set, no
/// management override.
gp::ListenerFacts default_listener() {
    gp::ListenerFacts f;
    f.tls_enabled = true;
    f.using_default_certs = true;
    f.using_default_agent_certs = true;
    f.agent_ca_present = true;
    f.agent_creds_are_default_files = true;
    return f;
}

} // namespace

TEST_CASE("gateway_peer_resolution: posture of the default gRPC credential set", "[gateway_peer][resolution][posture]") {
    const auto p = gp::derive_listener_posture(default_listener());
    CHECK(p.ca_present);
    CHECK(p.grpc_creds_are_default);
}

TEST_CASE("gateway_peer_resolution: HTTPS on defaults with operator gRPC certificates is NOT the default set",
          "[gateway_peer][resolution][posture][mixed]") {
    auto f = default_listener();
    f.using_default_agent_certs = false; // the gRPC agent listener has operator certs
    f.using_default_certs = true;        // ...but HTTPS bootstrapped the defaults
    f.agent_creds_are_default_files = false;
    const auto p = gp::derive_listener_posture(f);
    CHECK(p.ca_present);
    CHECK_FALSE(p.grpc_creds_are_default);

    // End to end through the resolver: no auto-pin, operator certificates need a pin.
    ResolutionInputs in = defaults_tls();
    in.grpc_creds_are_default = p.grpc_creds_are_default;
    CHECK(gp::resolve_gateway_peer_authz(in).mode == AuthzMode::Refuse);
}

TEST_CASE("gateway_peer_resolution: default certificate with an operator CA is not the default set",
          "[gateway_peer][resolution][posture]") {
    auto f = default_listener();
    f.agent_creds_are_default_files = false; // default server cert, operator --ca-cert
    CHECK_FALSE(gp::derive_listener_posture(f).grpc_creds_are_default);
}

TEST_CASE("gateway_peer_resolution: a management override replaces the credentials and the CA",
          "[gateway_peer][resolution][posture]") {
    auto f = default_listener();
    f.mgmt_override = true;
    f.mgmt_ca_present = false; // override without its own CA: the listener cannot verify clients
    auto p = gp::derive_listener_posture(f);
    CHECK_FALSE(p.ca_present);
    CHECK_FALSE(p.grpc_creds_are_default);

    f.mgmt_ca_present = true;
    f.agent_ca_present = false; // the agent CA is irrelevant to the overridden listener
    p = gp::derive_listener_posture(f);
    CHECK(p.ca_present);
    CHECK_FALSE(p.grpc_creds_are_default);
}

TEST_CASE("gateway_peer_resolution: plaintext and no-CA postures", "[gateway_peer][resolution][posture]") {
    auto f = default_listener();
    f.tls_enabled = false;
    auto p = gp::derive_listener_posture(f);
    CHECK_FALSE(p.ca_present);
    CHECK_FALSE(p.grpc_creds_are_default);

    f = default_listener();
    f.agent_ca_present = false; // --insecure-skip-client-verify with no --ca-cert
    f.using_default_agent_certs = false;
    f.agent_creds_are_default_files = false;
    p = gp::derive_listener_posture(f);
    CHECK_FALSE(p.ca_present);
}
