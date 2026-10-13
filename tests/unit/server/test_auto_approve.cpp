/**
 * test_auto_approve.cpp — Unit tests for yuzu::server::auth::AutoApproveEngine
 *
 * Covers: hostname glob matching, CIDR subnet matching, rule evaluation modes,
 *         config persistence.
 */

#include <yuzu/server/auto_approve.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <memory>

namespace fs = std::filesystem;
using namespace yuzu::server::auth;

// ── Helpers ──────────────────────────────────────────────────────────────────

static std::unique_ptr<AutoApproveEngine> make_engine() {
    return std::make_unique<AutoApproveEngine>();
}

static ApprovalContext make_ctx(const std::string& hostname = "", const std::string& ip = "",
                                const std::string& ca_fp = "", const std::string& attest = "") {
    return ApprovalContext{hostname, ip, ca_fp, attest};
}

// ── Hostname Glob Matching ───────────────────────────────────────────────────

TEST_CASE("hostname glob: exact match", "[auto_approve][glob]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::hostname_glob, "server1.prod.com", "exact"});

    REQUIRE_FALSE(engine->evaluate(make_ctx("server1.prod.com")).empty());
    REQUIRE(engine->evaluate(make_ctx("server2.prod.com")).empty());
}

TEST_CASE("hostname glob: wildcard prefix", "[auto_approve][glob]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::hostname_glob, "*.prod.com", "wildcard"});

    REQUIRE_FALSE(engine->evaluate(make_ctx("server1.prod.com")).empty());
    REQUIRE_FALSE(engine->evaluate(make_ctx("db.prod.com")).empty());
    REQUIRE(engine->evaluate(make_ctx("server1.dev.com")).empty());
}

TEST_CASE("hostname glob: match-all wildcard", "[auto_approve][glob]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::hostname_glob, "*", "all"});

    REQUIRE_FALSE(engine->evaluate(make_ctx("anything.example.com")).empty());
}

TEST_CASE("hostname glob: empty hostname does not match pattern", "[auto_approve][glob]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::hostname_glob, "*.prod.com", "test"});

    REQUIRE(engine->evaluate(make_ctx("")).empty());
}

// ── CIDR Subnet Matching ─────────────────────────────────────────────────────

TEST_CASE("CIDR: /8 match", "[auto_approve][cidr]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::ip_subnet, "10.0.0.0/8", "private"});

    REQUIRE_FALSE(engine->evaluate(make_ctx("", "10.1.2.3")).empty());
    REQUIRE(engine->evaluate(make_ctx("", "192.168.1.1")).empty());
}

TEST_CASE("CIDR: /24 match", "[auto_approve][cidr]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::ip_subnet, "192.168.1.0/24", "subnet"});

    REQUIRE_FALSE(engine->evaluate(make_ctx("", "192.168.1.100")).empty());
    REQUIRE(engine->evaluate(make_ctx("", "192.168.2.1")).empty());
}

TEST_CASE("CIDR: /32 exact IP", "[auto_approve][cidr]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::ip_subnet, "10.0.0.1/32", "exact"});

    REQUIRE_FALSE(engine->evaluate(make_ctx("", "10.0.0.1")).empty());
    REQUIRE(engine->evaluate(make_ctx("", "10.0.0.2")).empty());
}

TEST_CASE("CIDR: /0 matches everything", "[auto_approve][cidr]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::ip_subnet, "0.0.0.0/0", "all"});

    REQUIRE_FALSE(engine->evaluate(make_ctx("", "1.2.3.4")).empty());
    REQUIRE_FALSE(engine->evaluate(make_ctx("", "255.255.255.255")).empty());
}

TEST_CASE("CIDR: a blank rule value never matches, even an empty peer IP (#4644)",
          "[auto_approve][cidr]") {
    auto engine = make_engine();
    (void)engine->add_rule({AutoApproveRuleType::ip_subnet, "", "blank"});
    REQUIRE(engine->evaluate(make_ctx("", "")).empty());
    REQUIRE(engine->evaluate(make_ctx("", "10.0.0.1")).empty());
}

TEST_CASE("CIDR: invalid IP returns no match", "[auto_approve][cidr]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::ip_subnet, "10.0.0.0/8", "test"});

    REQUIRE(engine->evaluate(make_ctx("", "not-an-ip")).empty());
}

// ── Trusted CA ───────────────────────────────────────────────────────────────

TEST_CASE("trusted_ca matches CA fingerprint", "[auto_approve][ca]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::trusted_ca, "abcdef1234567890", "corp-ca"});

    REQUIRE_FALSE(engine->evaluate(make_ctx("", "", "abcdef1234567890")).empty());
    REQUIRE(engine->evaluate(make_ctx("", "", "different-fingerprint")).empty());
}

// ── Cloud Provider ───────────────────────────────────────────────────────────

TEST_CASE("cloud_provider matches attestation", "[auto_approve][cloud]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::cloud_provider, "aws", "aws-only"});

    REQUIRE_FALSE(engine->evaluate(make_ctx("", "", "", "aws")).empty());
    REQUIRE(engine->evaluate(make_ctx("", "", "", "gcp")).empty());
}

// ── Rule Evaluation Modes ────────────────────────────────────────────────────

TEST_CASE("any mode: first matching rule wins", "[auto_approve][evaluate]") {
    auto engine = make_engine();
    engine->set_require_all(false);
    engine->add_rule({AutoApproveRuleType::hostname_glob, "*.prod.com", "rule-a"});
    engine->add_rule({AutoApproveRuleType::ip_subnet, "10.0.0.0/8", "rule-b"});

    // Only hostname matches
    auto result = engine->evaluate(make_ctx("server.prod.com", "192.168.1.1"));
    REQUIRE(result == "rule-a");
}

TEST_CASE("all mode: all enabled rules must match", "[auto_approve][evaluate]") {
    auto engine = make_engine();
    engine->set_require_all(true);
    engine->add_rule({AutoApproveRuleType::hostname_glob, "*.prod.com", "host"});
    engine->add_rule({AutoApproveRuleType::ip_subnet, "10.0.0.0/8", "net"});

    // Only hostname matches — should fail in all mode
    REQUIRE(engine->evaluate(make_ctx("server.prod.com", "192.168.1.1")).empty());

    // Both match — should succeed
    REQUIRE_FALSE(engine->evaluate(make_ctx("server.prod.com", "10.1.2.3")).empty());
}

TEST_CASE("disabled rules are skipped", "[auto_approve][evaluate]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::hostname_glob, "*", "disabled-rule", false});

    REQUIRE(engine->evaluate(make_ctx("anything")).empty());
}

TEST_CASE("empty rules returns empty", "[auto_approve][evaluate]") {
    auto engine = make_engine();
    REQUIRE(engine->evaluate(make_ctx("host", "10.0.0.1")).empty());
}

// ── Rule CRUD ────────────────────────────────────────────────────────────────

TEST_CASE("add and list rules", "[auto_approve][crud]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::hostname_glob, "*.test.com", "a"});
    engine->add_rule({AutoApproveRuleType::ip_subnet, "10.0.0.0/8", "b"});

    auto rules = engine->list_rules();
    REQUIRE(rules.size() == 2);
    REQUIRE(rules[0].label == "a");
    REQUIRE(rules[1].label == "b");
}

TEST_CASE("remove_rule", "[auto_approve][crud]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::hostname_glob, "a", "first"});
    engine->add_rule({AutoApproveRuleType::hostname_glob, "b", "second"});

    engine->remove_rule(0);
    auto rules = engine->list_rules();
    REQUIRE(rules.size() == 1);
    REQUIRE(rules[0].label == "second");
}

TEST_CASE("set_enabled toggles rule", "[auto_approve][crud]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::hostname_glob, "*", "toggle"});

    engine->set_enabled(0, false);
    REQUIRE(engine->evaluate(make_ctx("host")).empty());

    engine->set_enabled(0, true);
    REQUIRE_FALSE(engine->evaluate(make_ctx("host")).empty());
}

TEST_CASE("remove_rule and toggle_enabled return the rule they changed, nullopt out of range",
          "[auto_approve][crud]") {
    auto engine = make_engine();
    engine->add_rule({AutoApproveRuleType::hostname_glob, "a", "first"});
    engine->add_rule({AutoApproveRuleType::hostname_glob, "b", "second"});

    const auto off = engine->toggle_enabled(1);
    REQUIRE(off.has_value());
    CHECK(off->value == "b");
    CHECK_FALSE(off->enabled);
    const auto on = engine->toggle_enabled(1);
    REQUIRE(on.has_value());
    CHECK(on->enabled);
    CHECK_FALSE(engine->toggle_enabled(2).has_value());

    const auto removed = engine->remove_rule(0);
    REQUIRE(removed.has_value());
    CHECK(removed->value == "a");
    CHECK_FALSE(engine->remove_rule(1).has_value());
    CHECK(engine->list_rules().size() == 1);
}

// ── Config Persistence ───────────────────────────────────────────────────────

TEST_CASE("save and reload auto-approve config", "[auto_approve][config]") {
    // Process-salted path: with the previous fixed name, a concurrent CI job
    // on the same box could ingest THIS job's just-persisted rules (writer
    // load() reads whatever exists at the path) or delete them mid-round-trip
    // (#1883). Both engines must keep sharing the ONE path — the write→reload
    // round-trip through the same file is the behaviour under test. The RAII
    // guard replaces both manual fs::remove calls (unique_temp_path guarantees
    // the path does not pre-exist). TempDbFile on a plain .cfg is deliberate:
    // there is no generic TempFile guard, and its -wal/-shm removes are
    // harmless no-ops here.
    yuzu::test::TempDbFile cfg{"yuzu_test_auto_approve-"};
    const auto& tmp = cfg.path;

    {
        AutoApproveEngine engine;
        engine.load(tmp); // sets config_path_ (file doesn't exist yet, returns false)
        engine.set_require_all(true);
        engine.add_rule({AutoApproveRuleType::hostname_glob, "*.prod.com", "prod"});
        engine.add_rule({AutoApproveRuleType::ip_subnet, "10.0.0.0/8", "private", false});
        // add_rule calls save_locked() internally, so config should be persisted
    }

    {
        AutoApproveEngine engine;
        REQUIRE(engine.load(tmp));
        REQUIRE(engine.require_all());

        auto rules = engine.list_rules();
        REQUIRE(rules.size() == 2);
        REQUIRE(rules[0].value == "*.prod.com");
        REQUIRE(rules[0].enabled == true);
        REQUIRE(rules[1].value == "10.0.0.0/8");
        REQUIRE(rules[1].enabled == false);
    }
}

// ── Malformed ip_subnet rule values (#4644) ──────────────────────────────────

// `std::stoi` on the prefix threw out of evaluate() (so out of Register/ProxyRegister), read
// `1e3` as /1, and a prefix above 32 made the mask shift undefined. A malformed rule must never
// throw and never match (fail closed): nothing is auto-approved because of it.
static const char* const kMalformedSubnets[] = {
    "10.0.0.0/abc",        "10.0.0.0/",          "10.0.0.0/33",       "10.0.0.0/-1",
    "10.0.0.0/1e3",        "10.0.0.0/+8",        "10.0.0.0/8x",       "10.0.0.0/ 8",
    "10.0.0.0/0x8",        "10.0.0.0/99999999999", "10.0.0.0/4294967297",
    "10.0.0.0/18446744073709551615", "10.0.0.0/-0", "10.0.0.0/-00", "10.0.0.0/+0",
    "10.0.0.0/8/8", "/8", "garbage/8", "10.0.0/8", "1.2.3.4.5/8",
};

TEST_CASE("ip_subnet: a malformed prefix or address never throws and never matches",
          "[auto_approve][cidr][numeric_params]") {
    for (const char* bad : kMalformedSubnets) {
        INFO(bad);
        AutoApproveEngine engine;
        engine.add_rule({AutoApproveRuleType::ip_subnet, bad, "bad"});
        for (const char* ip : {"10.1.2.3", "0.0.0.1", "255.255.255.255", "", "not-an-ip"}) {
            INFO(ip);
            REQUIRE_NOTHROW(engine.evaluate(make_ctx("host", ip)));
            CHECK(engine.evaluate(make_ctx("host", ip)).empty());
        }
    }
}

TEST_CASE("ip_subnet: a malformed rule blocks require-all mode and does not shadow a valid rule "
          "in any-mode",
          "[auto_approve][cidr][numeric_params]") {
    AutoApproveEngine all;
    all.set_require_all(true);
    all.add_rule({AutoApproveRuleType::ip_subnet, "10.0.0.0/8", "good"});
    CHECK_FALSE(all.evaluate(make_ctx("host", "10.1.2.3")).empty());
    all.add_rule({AutoApproveRuleType::ip_subnet, "10.0.0.0/abc", "bad"});
    CHECK(all.evaluate(make_ctx("host", "10.1.2.3")).empty());

    AutoApproveEngine any;
    any.add_rule({AutoApproveRuleType::ip_subnet, "10.0.0.0/abc", "bad"});
    any.add_rule({AutoApproveRuleType::ip_subnet, "10.0.0.0/8", "good"});
    CHECK(any.evaluate(make_ctx("host", "10.1.2.3")) == "good");
}

TEST_CASE("ip_subnet: a malformed rule loaded from the config file does not throw on evaluate",
          "[auto_approve][cidr][config][numeric_params]") {
    yuzu::test::TempDbFile cfg{"yuzu_test_auto_approve_bad-"};
    {
        std::ofstream f(cfg.path);
        f << "mode:any\n"
          << "ip_subnet:10.0.0.0/abc:bad:1\n"
          << "ip_subnet:10.0.0.0/33:toolong:1\n";
    }
    AutoApproveEngine engine;
    REQUIRE(engine.load(cfg.path));
    REQUIRE(engine.list_rules().size() == 2);
    REQUIRE_NOTHROW(engine.evaluate(make_ctx("host", "10.1.2.3")));
    CHECK(engine.evaluate(make_ctx("host", "10.1.2.3")).empty());
}

TEST_CASE("ip_subnet: is_valid_ip_subnet_value accepts exactly what the matcher can match",
          "[auto_approve][cidr][numeric_params]") {
    for (const char* ok : {"10.0.0.0/8", "10.0.0.0/0", "10.0.0.1/32", "192.168.1.5", "10.0.0.0/08"})
        CHECK(AutoApproveEngine::is_valid_ip_subnet_value(ok));
    for (const char* bad : kMalformedSubnets)
        CHECK_FALSE(AutoApproveEngine::is_valid_ip_subnet_value(bad));
    for (const char* bad : {"", "::1", "2001:db8::/32", "10.0.0.256", "host.example.com"})
        CHECK_FALSE(AutoApproveEngine::is_valid_ip_subnet_value(bad));
}

// ── Rule text that would change meaning on reload ────────────────────────────

// The file is `type:value:label:enabled`, one rule per line. ':' and any control character in a
// value or label would reload as a different rule; add_rule refuses them for every rule type.
TEST_CASE("is_valid_rule_text rejects ':' and control characters, nothing else",
          "[auto_approve][config][numeric_params]") {
    for (const char* ok : {"", "*.prod.example.com", "Prod (EU) #1", "10.0.0.0/8", "caf\xC3\xA9",
                           "tab-free label", "ab12cd34"})
        CHECK(AutoApproveEngine::is_valid_rule_text(ok));
    for (const char* bad : {"a:b", ":", "a\nb", "a\rb", "a\tb", "a\x1f" "b", "a\x01" "b"})
        CHECK_FALSE(AutoApproveEngine::is_valid_rule_text(bad));
    CHECK_FALSE(AutoApproveEngine::is_valid_rule_text(std::string("a\0b", 3)));
    // A NUL inside a subnet value is not read up to the NUL by inet_pton.
    CHECK_FALSE(AutoApproveEngine::is_valid_ip_subnet_value(std::string("10.0.0.0\0junk", 13)));
    CHECK_FALSE(AutoApproveEngine::is_valid_ip_subnet_value(std::string("10.0.0.0/8\0", 11)));
}

TEST_CASE("add_rule refuses a value or label that would reload as a different rule",
          "[auto_approve][config][numeric_params]") {
    AutoApproveEngine engine;
    for (auto type : {AutoApproveRuleType::hostname_glob, AutoApproveRuleType::ip_subnet,
                      AutoApproveRuleType::trusted_ca, AutoApproveRuleType::cloud_provider}) {
        const std::string ok_value = type == AutoApproveRuleType::ip_subnet ? "10.0.0.0/8" : "ok";
        CHECK_FALSE(engine.add_rule({type, ok_value, "x\nip_subnet:0.0.0.0/0:inj"}));
        CHECK_FALSE(engine.add_rule({type, ok_value, "lab:el"}));
        CHECK_FALSE(engine.add_rule({type, ok_value, std::string("a\0b", 3)}));
        CHECK_FALSE(engine.add_rule({type, "a:b", "label"}));
        CHECK_FALSE(engine.add_rule({type, "a\nb", "label"}));
    }
    CHECK(engine.list_rules().empty());
    CHECK(engine.add_rule({AutoApproveRuleType::hostname_glob, "*.prod.com", "Prod (EU) #1"}));
    CHECK(engine.list_rules().size() == 1);
}

// add_rule refuses a control character, so the shapes below cannot reach the engine that way. They
// CAN arrive in a hand-edited file through load(), which keeps the rule: the whitespace refusal in
// parse_prefix_len is what stops them matching, and this keeps a test behind it.
TEST_CASE("ip_subnet: a control-character prefix loaded from a file never matches",
          "[auto_approve][cidr][numeric_params]") {
    yuzu::test::TempDir dir{"yuzu_test_auto_approve_ws-"};
    REQUIRE(fs::create_directories(dir.path));
    const auto file = dir.path / "auto-approve.conf";
    {
        std::ofstream out(file, std::ios::binary);
        out << "ip_subnet:10.0.0.0/\t8:tab\n"
            << "ip_subnet:10.0.0.0/\v8:vtab\n"
            << "ip_subnet:10.0.0.0/8\t:trailing\n";
    }
    AutoApproveEngine engine;
    REQUIRE(engine.load(file));
    REQUIRE(engine.list_rules().size() == 3);
    for (const char* ip : {"10.1.2.3", "0.0.0.1", "255.255.255.255"}) {
        INFO(ip);
        REQUIRE_NOTHROW(engine.evaluate(make_ctx("host", ip)));
        CHECK(engine.evaluate(make_ctx("host", ip)).empty());
    }
}

// The saved-then-reloaded list must equal the audited (admitted) list after rejected injection
// attempts: a label like `x\nip_subnet:0.0.0.0/0:inj` used to reload as a second, enabled
// match-all rule, and `lab:el` as a disabled rule.
TEST_CASE("auto-approve: rules reloaded from disk equal the admitted rules after rejected "
          "injection attempts",
          "[auto_approve][config][numeric_params]") {
    yuzu::test::TempDir dir{"yuzu_test_auto_approve_rt-"};
    REQUIRE(fs::create_directories(dir.path));
    const auto file = dir.path / "auto-approve.conf";

    AutoApproveEngine engine;
    engine.load(file); // sets config_path_ (the file does not exist yet)
    REQUIRE(engine.add_rule({AutoApproveRuleType::hostname_glob, "*.prod.com", "prod"}));
    REQUIRE(engine.add_rule({AutoApproveRuleType::ip_subnet, "10.0.0.0/8", "lan", false}));
    CHECK_FALSE(engine.add_rule(
        {AutoApproveRuleType::hostname_glob, "*.evil.com", "x\nip_subnet:0.0.0.0/0:inj"}));
    CHECK_FALSE(engine.add_rule({AutoApproveRuleType::cloud_provider, "aws", "lab:el"}));
    CHECK_FALSE(engine.add_rule({AutoApproveRuleType::trusted_ca, "ab12", std::string("a\0b", 3)}));
    REQUIRE(engine.add_rule({AutoApproveRuleType::cloud_provider, "aws", "Prod (EU) #1"}));
    const auto admitted = engine.list_rules();
    REQUIRE(admitted.size() == 3);

    AutoApproveEngine reloaded;
    REQUIRE(reloaded.load(file));
    const auto after = reloaded.list_rules();
    REQUIRE(after.size() == admitted.size());
    for (std::size_t i = 0; i < admitted.size(); ++i) {
        INFO(i);
        CHECK(after[i].type == admitted[i].type);
        CHECK(after[i].value == admitted[i].value);
        CHECK(after[i].label == admitted[i].label);
        CHECK(after[i].enabled == admitted[i].enabled);
    }
    // And nothing the attempts carried became a rule that matches everything.
    CHECK(reloaded.evaluate(make_ctx("host.example.org", "192.0.2.1")).empty());
}
