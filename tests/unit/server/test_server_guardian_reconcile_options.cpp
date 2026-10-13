/**
 * test_server_guardian_reconcile_options.cpp: the operator-facing contract for the Guardian
 * heartbeat-reconcile admission budget knobs (#5513): flag names, defaults, env spellings,
 * validation. Same shape and same reason as test_server_ota_options.cpp: a misspelled envname(),
 * a default drifted from docs/user-manual/server-admin.md, a binding pointed at the wrong Config
 * field, or a dropped validator would otherwise ship with the whole suite green.
 *
 * Parsing runs in process against a real CLI::App (no subprocess).
 */

#include "server_guardian_reconcile_options.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cmath>
#include <cstdlib> // setenv/unsetenv (POSIX), _putenv_s (MSVC)
#include <limits>
#include <optional>
#include <string>
#include <vector>

using yuzu::server::Config;
using yuzu::server::guardian_reconcile_options_error;
using yuzu::server::register_guardian_reconcile_options;

namespace {

bool parse(const std::vector<std::string>& args, Config& cfg) {
    CLI::App app{"test"};
    register_guardian_reconcile_options(app, cfg);
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

std::optional<std::string> get_env(const std::string& name) {
#ifdef _WIN32
    char* buf = nullptr;
    std::size_t len = 0;
    if (_dupenv_s(&buf, &len, name.c_str()) != 0 || buf == nullptr)
        return std::nullopt;
    std::string v(buf);
    std::free(buf);
    return v;
#else
    if (const char* v = std::getenv(name.c_str()))
        return std::string(v);
    return std::nullopt;
#endif
}

void put_env(const std::string& name, const std::optional<std::string>& value) {
#ifdef _WIN32
    (void)_putenv_s(name.c_str(), value ? value->c_str() : "");
#else
    if (value)
        ::setenv(name.c_str(), value->c_str(), 1);
    else
        ::unsetenv(name.c_str());
#endif
}

// RAII environment override that RESTORES the previous state (value or absence) on exit, so a
// test cannot leak into, or be perturbed by, the surrounding environment. nullopt unsets the
// variable for the scope. The platform split is load-bearing: setenv/unsetenv are POSIX only
// and this file is built on every platform (see test_server_ota_options.cpp for the full reason).
struct ScopedEnv {
    std::string name;
    std::optional<std::string> previous;
    ScopedEnv(const std::string& n, const std::optional<std::string>& v)
        : name(n), previous(get_env(n)) {
        put_env(name, v);
    }
    ScopedEnv(const ScopedEnv&) = delete;
    ScopedEnv& operator=(const ScopedEnv&) = delete;
    ~ScopedEnv() { put_env(name, previous); }
};

} // namespace

TEST_CASE("Guardian reconcile options: defaults match the documented values",
          "[guardian][reconcile][options]") {
    // The defaults must not depend on the environment the test runs in.
    ScopedEnv a("YUZU_GUARDIAN_RECONCILE_BUDGET_MS_PER_S", std::nullopt);
    ScopedEnv b("YUZU_GUARDIAN_RECONCILE_BURST_MS", std::nullopt);
    ScopedEnv c("YUZU_GUARDIAN_RECONCILE_MAX_PER_S", std::nullopt);
    Config cfg;
    REQUIRE(parse({}, cfg));
    // These are the defaults published in docs/user-manual/server-admin.md.
    CHECK(cfg.guardian_reconcile_budget_ms_per_s == 500.0);
    CHECK(cfg.guardian_reconcile_burst_ms == 1000.0);
    CHECK(cfg.guardian_reconcile_max_per_s == 1000u);
    CHECK(guardian_reconcile_options_error(cfg).empty());
}

TEST_CASE("Guardian reconcile options: each flag binds to its own Config field",
          "[guardian][reconcile][options]") {
    // Every value distinct, so a binding pointed at the wrong field cannot pass by coincidence.
    Config cfg;
    REQUIRE(parse({"--guardian-reconcile-budget-ms-per-s=123.5",
                   "--guardian-reconcile-burst-ms=456.25", "--guardian-reconcile-max-per-s=789"},
                  cfg));
    CHECK(cfg.guardian_reconcile_budget_ms_per_s == 123.5);
    CHECK(cfg.guardian_reconcile_burst_ms == 456.25);
    CHECK(cfg.guardian_reconcile_max_per_s == 789u);
    CHECK(guardian_reconcile_options_error(cfg).empty());
}

TEST_CASE("Guardian reconcile options: zero and negative values are refused at parse time",
          "[guardian][reconcile][options]") {
    Config cfg;
    CHECK_FALSE(parse({"--guardian-reconcile-budget-ms-per-s=0"}, cfg));
    CHECK_FALSE(parse({"--guardian-reconcile-budget-ms-per-s=-5"}, cfg));
    CHECK_FALSE(parse({"--guardian-reconcile-burst-ms=0"}, cfg));
    CHECK_FALSE(parse({"--guardian-reconcile-burst-ms=-1"}, cfg));
    CHECK_FALSE(parse({"--guardian-reconcile-max-per-s=0"}, cfg));
}

TEST_CASE("Guardian reconcile options: what the CLI parser itself lets through or refuses",
          "[guardian][reconcile][options]") {
    // Measured against the CLI11 in use, not assumed: NaN passes CLI::PositiveNumber (so only
    // guardian_reconcile_options_error() stops it); infinity, a negative value, a value that does
    // not fit the unsigned --guardian-reconcile-max-per-s, and a fraction for it are all refused
    // by the parser itself.
    {
        Config cfg;
        REQUIRE(parse({"--guardian-reconcile-budget-ms-per-s=nan"}, cfg));
        CHECK(std::isnan(cfg.guardian_reconcile_budget_ms_per_s));
        CHECK(guardian_reconcile_options_error(cfg).find("--guardian-reconcile-budget-ms-per-s") !=
              std::string::npos);
    }
    {
        Config cfg;
        REQUIRE(parse({"--guardian-reconcile-burst-ms=nan"}, cfg));
        CHECK(guardian_reconcile_options_error(cfg).find("--guardian-reconcile-burst-ms") !=
              std::string::npos);
    }
    {
        Config cfg;
        CHECK_FALSE(parse({"--guardian-reconcile-budget-ms-per-s=inf"}, cfg));
        CHECK_FALSE(parse({"--guardian-reconcile-burst-ms=inf"}, cfg));
    }
    {
        Config cfg;
        CHECK_FALSE(parse({"--guardian-reconcile-max-per-s=-1"}, cfg));
        CHECK_FALSE(parse({"--guardian-reconcile-max-per-s=4294967296"}, cfg));  // 2^32
        CHECK_FALSE(parse({"--guardian-reconcile-max-per-s=1.5"}, cfg));
    }
}

TEST_CASE("Guardian reconcile options: the post-parse check also refuses NaN and infinity",
          "[guardian][reconcile][options]") {
    // CLI::PositiveNumber lets NaN through at parse time (the next test pins that against the real
    // parser); the second line of defence is guardian_reconcile_options_error(). These cases fill
    // Config directly, so they also cover infinity regardless of what the parser does with it.
    Config cfg;
    cfg.guardian_reconcile_budget_ms_per_s = std::numeric_limits<double>::quiet_NaN();
    CHECK(guardian_reconcile_options_error(cfg).find("--guardian-reconcile-budget-ms-per-s") !=
          std::string::npos);

    cfg = Config{};
    cfg.guardian_reconcile_budget_ms_per_s = std::numeric_limits<double>::infinity();
    CHECK(guardian_reconcile_options_error(cfg).find("--guardian-reconcile-budget-ms-per-s") !=
          std::string::npos);

    cfg = Config{};
    cfg.guardian_reconcile_burst_ms = std::numeric_limits<double>::infinity();
    CHECK(guardian_reconcile_options_error(cfg).find("--guardian-reconcile-burst-ms") !=
          std::string::npos);

    cfg = Config{};
    cfg.guardian_reconcile_burst_ms = 0.0;
    CHECK_FALSE(guardian_reconcile_options_error(cfg).empty());

    cfg = Config{};
    cfg.guardian_reconcile_max_per_s = 0;
    CHECK(guardian_reconcile_options_error(cfg).find("--guardian-reconcile-max-per-s") !=
          std::string::npos);
}

TEST_CASE("Guardian reconcile options: the environment spellings are bound",
          "[guardian][reconcile][options]") {
    ScopedEnv a("YUZU_GUARDIAN_RECONCILE_BUDGET_MS_PER_S", "321");
    ScopedEnv b("YUZU_GUARDIAN_RECONCILE_BURST_MS", "654");
    ScopedEnv c("YUZU_GUARDIAN_RECONCILE_MAX_PER_S", "987");
    Config cfg;
    REQUIRE(parse({}, cfg));
    CHECK(cfg.guardian_reconcile_budget_ms_per_s == 321.0);
    CHECK(cfg.guardian_reconcile_burst_ms == 654.0);
    CHECK(cfg.guardian_reconcile_max_per_s == 987u);

    // The command line wins over the environment.
    Config cfg2;
    REQUIRE(parse({"--guardian-reconcile-max-per-s=55"}, cfg2));
    CHECK(cfg2.guardian_reconcile_max_per_s == 55u);
}
