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
