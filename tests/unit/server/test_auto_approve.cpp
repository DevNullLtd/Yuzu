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

    engine->toggle_rule(0); // enabled -> disabled
    REQUIRE(engine->evaluate(make_ctx("host")).empty());

    engine->toggle_rule(0); // disabled -> enabled
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

// ── Hardening (B4): fail closed, validate before persisting ──────────────────

TEST_CASE("CIDR: malformed or out-of-range prefix never throws and never matches",
          "[auto_approve][cidr][hardening]") {
    // evaluate() runs under the engine mutex on every agent Register that reaches
    // the rule; std::stoi on these used to throw (or, for 33+, shift by a negative).
    for (const char* bad : {"10.0.0.0/abc", "10.0.0.0/", "10.0.0.0/33", "10.0.0.0/-1",
                            "10.0.0.0/99999999999999999999", "10.0.0.0/8x", "/8"}) {
        AutoApproveEngine engine;
        engine.add_rule({AutoApproveRuleType::ip_subnet, bad, "bad"});
        std::string label;
        REQUIRE_NOTHROW(label = engine.evaluate(make_ctx("", "10.1.2.3")));
        INFO(bad);
        CHECK(label.empty());
    }
}

TEST_CASE("CIDR: a blank ip_subnet value never matches, including an empty peer IP",
          "[auto_approve][cidr][hardening]") {
    // The gateway-proxied Register path sets no peer IP, so an empty rule value used to equal it
    // and auto-approve every such agent. load() accepts the line; the match is the last guard.
    AutoApproveEngine engine;
    engine.add_rule({AutoApproveRuleType::ip_subnet, "", "blank"});
    CHECK(engine.evaluate(make_ctx("", "")).empty());
    CHECK(engine.evaluate(make_ctx("", "10.1.2.3")).empty());
}

TEST_CASE("validate_auto_approve_rule: accepts well-formed rules",
          "[auto_approve][hardening]") {
    using T = AutoApproveRuleType;
    CHECK(validate_auto_approve_rule(T::hostname_glob, "*.prod.com", "prod").empty());
    CHECK(validate_auto_approve_rule(T::hostname_glob, "host1", "").empty());
    CHECK(validate_auto_approve_rule(T::ip_subnet, "10.0.0.0/8", "lan").empty());
    CHECK(validate_auto_approve_rule(T::ip_subnet, "10.0.0.0/32", "").empty());
    CHECK(validate_auto_approve_rule(T::ip_subnet, "192.168.1.5", "").empty());
    CHECK(validate_auto_approve_rule(T::trusted_ca, std::string(64, 'a'), "ca").empty());
    CHECK(validate_auto_approve_rule(T::cloud_provider, "aws", "").empty());
}

TEST_CASE("validate_auto_approve_rule: rejects delimiters, control chars and malformed values",
          "[auto_approve][hardening]") {
    using T = AutoApproveRuleType;
    CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, "", "x").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, "a:b", "x").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, "a\nb", "x").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, "a\rb", "x").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, "a\tb", "x").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, "ok", "has:colon").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, "ok",
                                           "line\nhostname_glob:*:injected:1")
                    .empty());
    CHECK_FALSE(validate_auto_approve_rule(T::ip_subnet, "10.0.0.0/abc", "").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::ip_subnet, "10.0.0.0/33", "").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::ip_subnet, "10.0.0.0/", "").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::ip_subnet, "not-an-ip/8", "").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::ip_subnet, "/8", "").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::trusted_ca, std::string(63, 'a'), "").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::trusted_ca, std::string(64, 'g'), "").empty());
}

TEST_CASE("parse_auto_approve_rule_type: unknown names are rejected, not defaulted",
          "[auto_approve][hardening]") {
    CHECK(parse_auto_approve_rule_type("ip_subnet") == AutoApproveRuleType::ip_subnet);
    CHECK_FALSE(parse_auto_approve_rule_type("").has_value());
    CHECK_FALSE(parse_auto_approve_rule_type("HOSTNAME_GLOB").has_value());
    CHECK_FALSE(parse_auto_approve_rule_type("subnet").has_value());
}

// Writes `body` to a fresh temp config and loads it; returns the engine.
static std::unique_ptr<AutoApproveEngine> load_body(const yuzu::test::TempDbFile& cfg,
                                                    const std::string& body) {
    {
        std::ofstream f(cfg.path, std::ios::binary);
        f << body;
    }
    auto engine = make_engine();
    REQUIRE(engine->load(cfg.path));
    return engine;
}

TEST_CASE("load: a file with an unknown-type line activates ZERO rules and is kept aside",
          "[auto_approve][config][hardening]") {
    // Under `all` the dropped line used to vanish from the conjunction, widening admission to
    // whatever rule survived; under `any` it merely narrowed. Either way the whole file is
    // refused, so nothing is admitted until an operator re-creates the rules.
    for (const char* mode : {"mode:any\n", "mode:all\n"}) {
        yuzu::test::TempDbFile cfg{"yuzu_test_auto_approve_unk-"};
        const fs::path rejected = cfg.path.string() + ".rejected";
        std::error_code ec;
        fs::remove(rejected, ec);
        const auto engine = load_body(
            cfg, std::string(mode) + "subnet:*:oops:1\nhostname_glob:*.prod.com:prod:1\n");
        INFO(mode);
        CHECK(engine->list_rules().empty());
        CHECK_FALSE(engine->require_all());
        CHECK(engine->evaluate(make_ctx("a.prod.com")).empty());
        CHECK(fs::exists(rejected));  // the original bytes survive for the operator
        CHECK_FALSE(fs::exists(cfg.path)); // ... and the live name is free for a clean save
        fs::remove(rejected, ec);
    }
}

TEST_CASE("load: a torn mode line is malformed, never read as `any`",
          "[auto_approve][config][hardening]") {
    for (const char* body : {"mode:al\nhostname_glob:a:b:1\n", "mode:\nhostname_glob:a:b:1\n",
                             "mode:ALL\nhostname_glob:a:b:1\n", "mode:any \nhostname_glob:a:b:1\n",
                             "hostname_glob\n"}) {
        yuzu::test::TempDbFile cfg{"yuzu_test_auto_approve_mode-"};
        const fs::path rejected = cfg.path.string() + ".rejected";
        const auto engine = load_body(cfg, body);
        INFO(body);
        CHECK(engine->list_rules().empty());
        CHECK(engine->evaluate(make_ctx("a")).empty());
        std::error_code ec;
        fs::remove(rejected, ec);
    }
}

TEST_CASE("load: a well-formed file (including CRLF line endings) loads in full",
          "[auto_approve][config][hardening]") {
    yuzu::test::TempDbFile cfg{"yuzu_test_auto_approve_ok-"};
    const auto engine = load_body(cfg, "# c\r\nmode:all\r\nhostname_glob:*.prod.com:prod:1\r\n"
                                        "ip_subnet:10.0.0.0/8:lan:0\r\n");
    CHECK(engine->require_all());
    const auto rules = engine->list_rules();
    REQUIRE(rules.size() == 2);
    CHECK(rules[0].value == "*.prod.com");
    CHECK_FALSE(rules[1].enabled);
}

TEST_CASE("mutations are commit-or-nothing: a failed write leaves memory unchanged",
          "[auto_approve][config][hardening]") {
    // A config path whose directory does not exist: the temp file cannot be created.
    AutoApproveEngine engine;
    engine.load(fs::temp_directory_path() / "yuzu_test_no_such_dir_auto_approve" / "aa.cfg");
    CHECK_FALSE(engine.add_rule({AutoApproveRuleType::hostname_glob, "a", "x"}));
    CHECK(engine.list_rules().empty());
    CHECK_FALSE(engine.set_require_all(true));
    CHECK_FALSE(engine.require_all());
    CHECK_FALSE(engine.save());
}

TEST_CASE("mutations persist through a temp file + rename, and report the rule acted on",
          "[auto_approve][config][hardening]") {
    yuzu::test::TempDbFile cfg{"yuzu_test_auto_approve_rw-"};
    AutoApproveEngine engine;
    engine.load(cfg.path); // does not exist yet: sets the path
    REQUIRE(engine.add_rule({AutoApproveRuleType::hostname_glob, "a.corp", "A"}));
    REQUIRE(engine.add_rule({AutoApproveRuleType::cloud_provider, "aws", "B"}));
    CHECK_FALSE(fs::exists(cfg.path.string() + ".tmp")); // renamed over, not left behind

    auto t = engine.toggle_rule(1);
    CHECK(t.status == RuleEdit::Status::ok);
    CHECK(t.rule.value == "aws");
    CHECK_FALSE(t.rule.enabled); // post-toggle state
    CHECK(engine.toggle_rule(9).status == RuleEdit::Status::not_found);

    auto r = engine.remove_rule(0);
    CHECK(r.status == RuleEdit::Status::ok);
    CHECK(r.rule.value == "a.corp");
    CHECK(engine.remove_rule(5).status == RuleEdit::Status::not_found);
    REQUIRE(engine.set_require_all(true));

    AutoApproveEngine reloaded;
    REQUIRE(reloaded.load(cfg.path));
    CHECK(reloaded.require_all());
    const auto rules = reloaded.list_rules();
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].value == "aws");
    CHECK_FALSE(rules[0].enabled);
}

TEST_CASE("toggle and remove verify a stated rule identity under the engine lock",
          "[auto_approve][crud]") {
    AutoApproveEngine engine;
    REQUIRE(engine.add_rule({AutoApproveRuleType::hostname_glob, "a.corp", "A"}));
    REQUIRE(engine.add_rule({AutoApproveRuleType::ip_subnet, "10.0.0.0/8", "B"}));

    RuleExpectation wrong_value;
    wrong_value.value = "b.corp";
    RuleExpectation wrong_type;
    wrong_type.type = AutoApproveRuleType::ip_subnet;
    RuleExpectation stale_state;
    stale_state.enabled = false;
    for (const auto& e : {wrong_value, wrong_type, stale_state}) {
        CHECK(engine.toggle_rule(0, e).status == RuleEdit::Status::mismatch);
        CHECK(engine.remove_rule(0, e).status == RuleEdit::Status::mismatch);
    }
    REQUIRE(engine.list_rules().size() == 2);
    CHECK(engine.list_rules()[0].enabled); // nothing changed

    // Every stated field matches: it acts. A not_found index stays not_found, whatever is stated.
    RuleExpectation right;
    right.type = AutoApproveRuleType::hostname_glob;
    right.value = "a.corp";
    right.enabled = true;
    CHECK(engine.toggle_rule(0, right).status == RuleEdit::Status::ok);
    CHECK_FALSE(engine.list_rules()[0].enabled);
    CHECK(engine.toggle_rule(7, right).status == RuleEdit::Status::not_found);
    right.enabled = std::nullopt;
    CHECK(engine.remove_rule(0, right).status == RuleEdit::Status::ok);
    REQUIRE(engine.list_rules().size() == 1);
    CHECK(engine.list_rules()[0].value == "10.0.0.0/8");
}

TEST_CASE("validate_auto_approve_rule: bounds the text and refuses match-everything rules",
          "[auto_approve][hardening]") {
    using T = AutoApproveRuleType;
    CHECK(validate_auto_approve_rule(T::hostname_glob, std::string(kMaxRuleValueLen, 'a'),
                                     std::string(kMaxRuleLabelLen, 'b'))
              .empty());
    CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, std::string(kMaxRuleValueLen + 1, 'a'), "")
                    .empty());
    CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, "ok", std::string(kMaxRuleLabelLen + 1, 'b'))
                    .empty());
    CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, "*", "").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, "***", "").empty());
    CHECK(validate_auto_approve_rule(T::hostname_glob, "*.corp", "").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::ip_subnet, "0.0.0.0/0", "").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::ip_subnet, "10.0.0.0/0", "").empty());
    CHECK(validate_auto_approve_rule(T::ip_subnet, "10.0.0.0/1", "").empty());
    // Spaces, '=' and commas pass validation by design; the audit sink tokenises them.
    CHECK(validate_auto_approve_rule(T::hostname_glob, "x result=denied by=other", "").empty());
}

TEST_CASE("parse_auto_approve_rule_type: all four known names map to their enum",
          "[auto_approve][hardening]") {
    CHECK(parse_auto_approve_rule_type("trusted_ca") == AutoApproveRuleType::trusted_ca);
    CHECK(parse_auto_approve_rule_type("hostname_glob") == AutoApproveRuleType::hostname_glob);
    CHECK(parse_auto_approve_rule_type("ip_subnet") == AutoApproveRuleType::ip_subnet);
    CHECK(parse_auto_approve_rule_type("cloud_provider") == AutoApproveRuleType::cloud_provider);
}

TEST_CASE("validate_auto_approve_rule: every control byte and DEL is rejected in value and label",
          "[auto_approve][hardening]") {
    using T = AutoApproveRuleType;
    for (int c = 0; c < 0x20; ++c) {
        const std::string bad = std::string("a") + static_cast<char>(c) + "b";
        INFO("byte " << c);
        CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, bad, "ok").empty());
        CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, "ok", bad).empty());
    }
    const std::string del = std::string("a") + '\x7f' + "b";
    CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, del, "ok").empty());
    CHECK_FALSE(validate_auto_approve_rule(T::hostname_glob, "ok", del).empty());
}
