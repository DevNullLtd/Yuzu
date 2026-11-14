// test_pg_collation_check.cpp: the collation version check (pg/pg_collation_check.{hpp,cpp}).
// The decision is a pure function over three facts and is tested over every combination; the
// state machine that turns a stream of verdicts into a gauge, a counter and log lines is a second
// pure function, tested over every (previous state, verdict) pair; the I/O function is tested
// against a real PostgreSQL (the recorded version of a throwaway database is overwritten to force
// a mismatch) and against an unreachable pool (Unreadable, never a throw); the reporting function
// is tested for its log lines, for logging only on a transition (a Mismatch that becomes
// NotApplicable, which removes the gauge series, logs one INFO line), and for the gauge being
// absent, not zero, when nothing was learned; the counter pre-seed is tested over every verdict.

#include "pg/pg_collation_check.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <initializer_list>
#include <chrono>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server::pg;

namespace {

CollationFacts facts(bool column, std::optional<std::string> recorded,
                     std::optional<std::string> actual) {
    return CollationFacts{column, std::move(recorded), std::move(actual)};
}

CollationReport report(CollationVerdict v, std::string recorded = "", std::string actual = "") {
    CollationReport r;
    r.verdict = v;
    r.database = "yuzu_prod";
    r.recorded = std::move(recorded);
    r.actual = std::move(actual);
    r.failure = v == CollationVerdict::Unreadable ? "the probe failed" : "";
    return r;
}

// True when the gauge has a SAMPLE line. The family's HELP and TYPE lines survive
// clear_gauge_family(), so a substring search for the name would read "present" after a removal.
bool has_series(yuzu::MetricsRegistry& m) {
    const std::string text = m.serialize();
    const std::string sample = std::string("\n") + kCollationMismatchGauge + " ";
    return ("\n" + text).find(sample) != std::string::npos;
}

// A state reached by a conclusive verdict, optionally followed by an unreadable spell.
CollationState st(CollationLast last, bool unreadable = false) {
    return CollationState{last, unreadable};
}

constexpr CollationVerdict kAllVerdicts[] = {CollationVerdict::Ok, CollationVerdict::NotApplicable,
                                             CollationVerdict::Mismatch,
                                             CollationVerdict::Unreadable};
const CollationState kAllStates[] = {st(CollationLast::None),
                                     st(CollationLast::None, true),
                                     st(CollationLast::Ok),
                                     st(CollationLast::Ok, true),
                                     st(CollationLast::Mismatch),
                                     st(CollationLast::Mismatch, true),
                                     st(CollationLast::NotApplicable),
                                     st(CollationLast::NotApplicable, true)};

} // namespace

TEST_CASE("collation verdict: every combination of the three facts", "[pg_collation][decision]") {
    // no column (PostgreSQL before 15): nothing to compare, whatever else is set
    CHECK(decide_collation_verdict(facts(false, std::nullopt, std::nullopt)) ==
          CollationVerdict::NotApplicable);
    CHECK(decide_collation_verdict(facts(false, "2.36", "2.36")) ==
          CollationVerdict::NotApplicable);
    CHECK(decide_collation_verdict(facts(false, "2.36", "2.39")) ==
          CollationVerdict::NotApplicable);
    // column present, recorded NULL (C/POSIX/builtin): no version to drift
    CHECK(decide_collation_verdict(facts(true, std::nullopt, std::nullopt)) ==
          CollationVerdict::NotApplicable);
    CHECK(decide_collation_verdict(facts(true, std::nullopt, "2.39")) ==
          CollationVerdict::NotApplicable);
    // recorded set, the operating system reports none: cannot compare
    CHECK(decide_collation_verdict(facts(true, "2.36", std::nullopt)) ==
          CollationVerdict::Unreadable);
    // both known
    CHECK(decide_collation_verdict(facts(true, "2.36", "2.36")) == CollationVerdict::Ok);
    CHECK(decide_collation_verdict(facts(true, "2.36", "2.39")) == CollationVerdict::Mismatch);
    CHECK(decide_collation_verdict(facts(true, "2.39", "2.36")) == CollationVerdict::Mismatch);
    // the comparison is exact text equality, not a prefix or numeric one
    CHECK(decide_collation_verdict(facts(true, "2.36", "2.36.1")) == CollationVerdict::Mismatch);
    CHECK(decide_collation_verdict(facts(true, "153.14", "153.14")) == CollationVerdict::Ok);
    CHECK(decide_collation_verdict(facts(true, "", "")) == CollationVerdict::Ok);
    CHECK(decide_collation_verdict(facts(true, "", "2.36")) == CollationVerdict::Mismatch);
}

TEST_CASE("collation verdict: fixed names", "[pg_collation][decision]") {
    CHECK(std::string(to_string(CollationVerdict::Ok)) == "ok");
    CHECK(std::string(to_string(CollationVerdict::NotApplicable)) == "not_applicable");
    CHECK(std::string(to_string(CollationVerdict::Mismatch)) == "mismatch");
    CHECK(std::string(to_string(CollationVerdict::Unreadable)) == "unreadable");
}

TEST_CASE("collation state machine: every (previous state, verdict) pair",
          "[pg_collation][state]") {
    for (const CollationState& prev : kAllStates) {
        INFO("prev.last=" << static_cast<int>(prev.last) << " prev.unreadable=" << prev.unreadable);
        for (const CollationVerdict v : kAllVerdicts) {
            INFO("verdict=" << to_string(v));
            const CollationStep step = next_collation_state(prev, v);
            switch (v) {
            case CollationVerdict::Ok:
                CHECK(step.next == st(CollationLast::Ok));
                CHECK(step.gauge == GaugeAction::SetZero);
                // A standing mismatch that clears is announced; a repeat is silent; a first
                // conclusive Ok (or Ok after NotApplicable) is announced once.
                CHECK(step.log == (prev.last == CollationLast::Mismatch ? LogAction::InfoCleared
                                   : prev.last == CollationLast::Ok     ? LogAction::None
                                                                        : LogAction::InfoMatches));
                break;
            case CollationVerdict::Mismatch:
                CHECK(step.next == st(CollationLast::Mismatch));
                CHECK(step.gauge == GaugeAction::SetOne);
                // The ERROR is logged on entry only: a mismatch seen again, even across an
                // unreadable spell, is the same mismatch.
                CHECK(step.log == (prev.last == CollationLast::Mismatch
                                       ? LogAction::None
                                       : LogAction::ErrorMismatch));
                break;
            case CollationVerdict::NotApplicable:
                CHECK(step.next == st(CollationLast::NotApplicable));
                CHECK(step.gauge == GaugeAction::Remove);
                // A repeat is silent; a Mismatch that becomes NotApplicable (the series is removed
                // without ever reading 0) is announced at INFO; any other entry says once, at INFO,
                // that the check does not apply.
                CHECK(step.log == (prev.last == CollationLast::NotApplicable ? LogAction::None
                                   : prev.last == CollationLast::Mismatch
                                       ? LogAction::InfoMismatchNoLongerApplies
                                       : LogAction::InfoNotApplicable));
                break;
            case CollationVerdict::Unreadable:
                // Never flips the gauge, remembers the last conclusive finding, and warns once
                // per spell.
                CHECK(step.next == st(prev.last, true));
                CHECK(step.gauge == GaugeAction::Leave);
                CHECK(step.log == (prev.unreadable ? LogAction::None : LogAction::WarnUnreadable));
                break;
            }
        }
    }
}

TEST_CASE("collation state machine: named sequences", "[pg_collation][state]") {
    const auto run = [](std::initializer_list<CollationVerdict> seq) {
        CollationState state;
        std::vector<LogAction> logs;
        std::vector<GaugeAction> gauges;
        for (const auto v : seq) {
            const CollationStep step = next_collation_state(state, v);
            state = step.next;
            logs.push_back(step.log);
            gauges.push_back(step.gauge);
        }
        return std::pair{logs, gauges};
    };
    using V = CollationVerdict;
    using L = LogAction;
    SECTION("a standing mismatch interrupted by an unreadable spell is one mismatch") {
        const auto [logs, gauges] = run({V::Mismatch, V::Unreadable, V::Unreadable, V::Mismatch});
        CHECK(logs == std::vector<L>{L::ErrorMismatch, L::WarnUnreadable, L::None, L::None});
        CHECK(gauges.back() == GaugeAction::SetOne);
    }
    SECTION("a mismatch that is fixed during an unreadable spell is announced as cleared") {
        const auto [logs, gauges] = run({V::Mismatch, V::Unreadable, V::Ok});
        CHECK(logs == std::vector<L>{L::ErrorMismatch, L::WarnUnreadable, L::InfoCleared});
    }
    SECTION("a healthy database that is briefly unreadable logs one warning and no cleared line") {
        const auto [logs, gauges] = run({V::Ok, V::Unreadable, V::Ok, V::Ok});
        CHECK(logs == std::vector<L>{L::InfoMatches, L::WarnUnreadable, L::None, L::None});
    }
    SECTION("an unreadable first check leaves the series absent and warns once") {
        const auto [logs, gauges] = run({V::Unreadable, V::Unreadable, V::Ok});
        CHECK(logs == std::vector<L>{L::WarnUnreadable, L::None, L::InfoMatches});
        CHECK(gauges == std::vector<GaugeAction>{GaugeAction::Leave, GaugeAction::Leave,
                                                 GaugeAction::SetZero});
    }
    SECTION("a mismatch that stops applying is announced once, then silent") {
        const auto [logs, gauges] = run({V::Mismatch, V::NotApplicable, V::NotApplicable});
        CHECK(logs == std::vector<L>{L::ErrorMismatch, L::InfoMismatchNoLongerApplies, L::None});
        CHECK(gauges.back() == GaugeAction::Remove);
    }
    SECTION("a second spell warns again") {
        const auto [logs, gauges] = run({V::Ok, V::Unreadable, V::Ok, V::Unreadable});
        CHECK(logs ==
              std::vector<L>{L::InfoMatches, L::WarnUnreadable, L::None, L::WarnUnreadable});
    }
}

TEST_CASE("collation report drives the gauge through Mismatch, Unreadable, Ok and NotApplicable",
          "[pg_collation][state][metrics]") {
    yuzu::MetricsRegistry m;
    CollationState state;
    const auto gauge = [&] {
        return m.gauge(kCollationMismatchGauge).value();
    };

    report_collation_check(report(CollationVerdict::Mismatch, "2.36", "2.39"), &m, state);
    REQUIRE(has_series(m));
    CHECK(gauge() == 1.0);

    // An unreadable check does not flip the gauge, in either direction.
    report_collation_check(report(CollationVerdict::Unreadable), &m, state);
    REQUIRE(has_series(m));
    CHECK(gauge() == 1.0);

    report_collation_check(report(CollationVerdict::Ok, "2.39", "2.39"), &m, state);
    CHECK(gauge() == 0.0);
    report_collation_check(report(CollationVerdict::Unreadable), &m, state);
    CHECK(gauge() == 0.0);

    // NotApplicable removes the series (a sample line; the HELP/TYPE lines may remain).
    report_collation_check(report(CollationVerdict::NotApplicable), &m, state);
    CHECK_FALSE(has_series(m));
}

TEST_CASE("collation report counts every check by result, the start-time one included",
          "[pg_collation][state][metrics]") {
    yuzu::MetricsRegistry m;
    CollationState state;
    const auto count = [&](const char* result) {
        return m.counter(kCollationCheckCounter, {{"result", result}}).value();
    };
    report_collation_check(report(CollationVerdict::Ok, "a", "a"), &m, state);
    report_collation_check(report(CollationVerdict::Ok, "a", "a"), &m, state);
    report_collation_check(report(CollationVerdict::Mismatch, "a", "b"), &m, state);
    report_collation_check(report(CollationVerdict::Unreadable), &m, state);
    report_collation_check(report(CollationVerdict::Unreadable), &m, state);
    report_collation_check(report(CollationVerdict::Unreadable), &m, state);
    report_collation_check(report(CollationVerdict::NotApplicable), &m, state);
    CHECK(count("ok") == 2);
    CHECK(count("mismatch") == 1);
    CHECK(count("unreadable") == 3);
    CHECK(count("not_applicable") == 1);
}

TEST_CASE("collation report logs on a transition only", "[pg_collation][state][log]") {
    yuzu::test::LogCapture cap(spdlog::level::info);
    CollationState state;
    for (int i = 0; i < 3; ++i)
        report_collation_check(report(CollationVerdict::Mismatch, "2.36", "2.39"), nullptr, state);
    for (int i = 0; i < 3; ++i)
        report_collation_check(report(CollationVerdict::Unreadable), nullptr, state);
    report_collation_check(report(CollationVerdict::Ok, "2.39", "2.39"), nullptr, state);
    for (int i = 0; i < 3; ++i)
        report_collation_check(report(CollationVerdict::Ok, "2.39", "2.39"), nullptr, state);
    cap.stop();
    const std::string logs = cap.text();
    const auto count = [&](const std::string& needle) {
        std::size_t n = 0;
        for (auto at = logs.find(needle); at != std::string::npos; at = logs.find(needle, at + 1))
            ++n;
        return n;
    };
    CHECK(count("[error]") == 1);                         // the mismatch, once
    CHECK(count("[warning]") == 1);                       // the unreadable spell, once
    CHECK(count("the earlier mismatch is cleared") == 1); // the fix, once
    // The clearing line says it compares versions only (a REFRESH alone also clears it).
    CHECK(count("it does not show that the indexes were rebuilt") == 1);
}

TEST_CASE("collation report: entering not-applicable says so once at INFO", "[pg_collation][log]") {
    yuzu::test::LogCapture cap(spdlog::level::info);
    CollationState state;
    for (int i = 0; i < 3; ++i)
        report_collation_check(report(CollationVerdict::NotApplicable), nullptr, state);
    cap.stop();
    const std::string logs = cap.text();
    std::size_t n = 0;
    for (auto at = logs.find("check not applicable"); at != std::string::npos;
         at = logs.find("check not applicable", at + 1))
        ++n;
    CHECK(n == 1);
    CHECK(logs.find("[info]") != std::string::npos);
}

TEST_CASE("collation report: the last-completed time is set by every verdict and absent before "
          "the first",
          "[pg_collation][metrics]") {
    yuzu::MetricsRegistry m;
    const auto has_series = [&] {
        return ("\n" + m.serialize())
                   .find(std::string("\n") + kCollationLastCompletedGauge + " ") !=
               std::string::npos;
    };
    CollationState state;
    CHECK_FALSE(has_series()); // nothing has completed yet
    const double before =
        static_cast<double>(std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count());
    // The first report creates the series by itself (no gauge() call has touched it before).
    report_collation_check(report(CollationVerdict::Unreadable), &m, state);
    CHECK(has_series());
    for (const auto v : {CollationVerdict::Unreadable, CollationVerdict::Ok,
                         CollationVerdict::Mismatch, CollationVerdict::NotApplicable}) {
        m.gauge(kCollationLastCompletedGauge)
            .set(0.0); // would stay 0 if the verdict did not stamp it
        report_collation_check(report(v, "a", v == CollationVerdict::Mismatch ? "b" : "a"), &m,
                               state);
        const double stamped = m.gauge(kCollationLastCompletedGauge).value();
        INFO("verdict " << to_string(v));
        CHECK(stamped >= before);
        CHECK(stamped <= before + 60.0);
    }
    CHECK(has_series()); // and a not-applicable verdict does not remove it
}

TEST_CASE("collation report: Mismatch, not applicable, Mismatch again re-creates the gauge series",
          "[pg_collation][metrics]") {
    yuzu::MetricsRegistry m;
    CollationState state;
    const auto sample = [&] {
        return ("\n" + m.serialize()).find(std::string("\n") + kCollationMismatchGauge + " ") !=
               std::string::npos;
    };
    report_collation_check(report(CollationVerdict::Mismatch, "a", "b"), &m, state);
    REQUIRE(sample());
    CHECK(m.gauge(kCollationMismatchGauge).value() == 1.0);
    report_collation_check(report(CollationVerdict::NotApplicable), &m, state);
    // gauge() creates the series, so look at the exposition text only
    CHECK_FALSE(("\n" + m.serialize()).find(std::string("\n") + kCollationMismatchGauge + " ") !=
                std::string::npos);
    report_collation_check(report(CollationVerdict::Mismatch, "a", "b"), &m, state);
    CHECK(sample());
    CHECK(m.gauge(kCollationMismatchGauge).value() == 1.0);
}

TEST_CASE("collation report: a mismatch that stops applying logs one INFO line and removes "
          "the series",
          "[pg_collation][state][log]") {
    yuzu::test::LogCapture cap(spdlog::level::info);
    yuzu::MetricsRegistry m;
    CollationState state;
    report_collation_check(report(CollationVerdict::Mismatch, "2.36", "2.39"), &m, state);
    REQUIRE(has_series(m));
    report_collation_check(report(CollationVerdict::NotApplicable), &m, state);
    report_collation_check(report(CollationVerdict::NotApplicable), &m, state);
    cap.stop();
    const std::string logs = cap.text();
    const auto count = [&](const std::string& needle) {
        std::size_t n = 0;
        for (auto at = logs.find(needle); at != std::string::npos; at = logs.find(needle, at + 1))
            ++n;
        return n;
    };
    CHECK_FALSE(has_series(m));
    CHECK(count("[error]") == 1); // the mismatch entry only
    CHECK(count("mismatch no longer applies") == 1);
    CHECK(count("[info]") == 1);
}

TEST_CASE("collation metrics: the counter pre-seed covers every verdict, and the names are the "
          "label set",
          "[pg_collation][metrics]") {
    // The list is closed at four, and every enumerator is in it exactly once.
    CHECK(all_collation_verdicts().size() == 4);
    for (const CollationVerdict v : kAllVerdicts) {
        std::size_t seen = 0;
        for (const auto& entry : all_collation_verdicts())
            seen += entry.verdict == v ? 1 : 0;
        CHECK(seen == 1);
    }

    yuzu::MetricsRegistry m;
    seed_collation_metrics(m);
    const std::string text = "\n" + m.serialize();
    for (const auto& entry : all_collation_verdicts()) {
        INFO("verdict=" << entry.name);
        // The label value is to_string(verdict): the same text the report path increments.
        CHECK(std::string(to_string(entry.verdict)) == entry.name);
        const std::string sample =
            std::string("\n") + kCollationCheckCounter + "{result=\"" + entry.name + "\"} 0";
        CHECK(text.find(sample) != std::string::npos);
    }
    // Only the counter is pre-seeded: the gauge stays absent until a check concludes something.
    CHECK_FALSE(has_series(m));
    seed_collation_metrics(m); // idempotent
    CHECK(m.counter(kCollationCheckCounter, {{"result", "ok"}}).value() == 0);
}

TEST_CASE("quote_identifier doubles embedded quotes and wraps in double quotes",
          "[pg_collation][quote]") {
    CHECK(quote_identifier("yuzu") == "\"yuzu\"");
    CHECK(quote_identifier("my\"db") == "\"my\"\"db\"");
    CHECK(quote_identifier("\"") == "\"\"\"\"");
    CHECK(quote_identifier("a\"\"b") == "\"a\"\"\"\"b\"");
    CHECK(quote_identifier("") == "\"\"");
    // A control byte passes through: quoting is not the place that neutralises it.
    CHECK(quote_identifier(std::string("a\nb", 3)) == std::string("\"a\nb\"", 5));
    CHECK(quote_identifier(std::string("a\0b", 3)) == std::string("\"a\0b\"", 5));
}

TEST_CASE("unreadable failure text: a failed COMMIT is not blamed on the pool", "[pg_collation]") {
    // The statement text wins whenever there is one.
    CHECK(unreadable_failure_text("syntax error", false, "pool says x") == "syntax error");
    CHECK(unreadable_failure_text("syntax error", true, "pool says x") == "syntax error");
    // Facts read, no statement failure, the transaction still failed: that is the COMMIT, and an
    // earlier pool error must not be echoed as its cause.
    CHECK(unreadable_failure_text("", true, "connection refused earlier") == "commit failed");
    CHECK(unreadable_failure_text("", true, "") == "commit failed");
    // Facts not read: the pool's own error (the acquire or BEGIN failed), marked as possibly from
    // an earlier attempt because the pool keeps only its latest error; else a fixed text.
    CHECK(unreadable_failure_text("", false, "pool acquire timeout") ==
          "the pool's last error (may be from an earlier attempt): pool acquire timeout");
    CHECK(unreadable_failure_text("", false, "") == "could not run the collation version query");
}

TEST_CASE("collation check on an unreachable pool is Unreadable, never a throw", "[pg_collation]") {
    PgPool pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1 dbname=x user=x", .size = 1}};
    CollationReport r;
    REQUIRE_NOTHROW(r = check_collation_version(pool));
    CHECK(r.verdict == CollationVerdict::Unreadable);
    CHECK_FALSE(r.failure.empty());
}

TEST_CASE("collation report: the gauge is set on Ok and Mismatch and absent otherwise",
          "[pg_collation][metrics]") {
    SECTION("Ok sets 0") {
        yuzu::MetricsRegistry m;
        CollationState state;
        report_collation_check(report(CollationVerdict::Ok, "2.36", "2.36"), &m, state);
        REQUIRE(has_series(m));
        CHECK(m.gauge(kCollationMismatchGauge).value() == 0.0);
    }
    SECTION("Mismatch sets 1") {
        yuzu::MetricsRegistry m;
        CollationState state;
        report_collation_check(report(CollationVerdict::Mismatch, "2.36", "2.39"), &m, state);
        REQUIRE(has_series(m));
        CHECK(m.gauge(kCollationMismatchGauge).value() == 1.0);
    }
    SECTION("NotApplicable and Unreadable leave the series absent") {
        yuzu::MetricsRegistry m;
        CollationState state;
        report_collation_check(report(CollationVerdict::NotApplicable), &m, state);
        report_collation_check(report(CollationVerdict::Unreadable), &m, state);
        CHECK_FALSE(has_series(m));
    }
    SECTION("a null registry is accepted") {
        CollationState state;
        REQUIRE_NOTHROW(
            report_collation_check(report(CollationVerdict::Mismatch, "a", "b"), nullptr, state));
        CHECK(state == st(CollationLast::Mismatch));
    }
}

TEST_CASE(
    "collation report: a mismatch logs one error naming the database, both versions and the remedy",
    "[pg_collation][log]") {
    yuzu::test::LogCapture cap(spdlog::level::warn);
    CollationState state;
    report_collation_check(report(CollationVerdict::Mismatch, "2.36", "2.39"), nullptr, state);
    report_collation_check(report(CollationVerdict::Unreadable), nullptr, state);
    cap.stop();
    const std::string logs = cap.text();
    const auto err = logs.find("[error]");
    REQUIRE(err != std::string::npos);
    CHECK(logs.find("[error]", err + 1) == std::string::npos); // one error line
    CHECK(logs.find("yuzu_prod") != std::string::npos);
    CHECK(logs.find("2.36") != std::string::npos);
    CHECK(logs.find("2.39") != std::string::npos);
    CHECK(logs.find("REINDEX DATABASE") != std::string::npos);
    CHECK(logs.find("REINDEX DATABASE CONCURRENTLY \"yuzu_prod\"") != std::string::npos);
    CHECK(logs.find("ALTER DATABASE \"yuzu_prod\" REFRESH COLLATION VERSION") != std::string::npos);
    CHECK(logs.find("REFRESH COLLATION VERSION") != std::string::npos);
    // The docs quote these strings, so they are pinned here.
    CHECK(logs.find("records collation version 2.36 but the operating system now reports 2.39") !=
          std::string::npos);
    CHECK(logs.find("[warning]") != std::string::npos); // the Unreadable report
    CHECK(logs.find("could not check the database collation version") != std::string::npos);
    CHECK(logs.find("the probe failed") != std::string::npos);
}

TEST_CASE("collation report: a database name the log token changes gets no pasteable remedy",
          "[pg_collation][log]") {
    // A newline in a quoted database name is folded to '_' by the log token. Quoting that token
    // would print commands for a different database ("prod_blue" instead of "prod\nblue").
    auto run = [](const std::string& name) {
        yuzu::test::LogCapture cap(spdlog::level::warn);
        CollationState state;
        auto r = report(CollationVerdict::Mismatch, "2.36", "2.39");
        r.database = name;
        report_collation_check(r, nullptr, state);
        cap.stop();
        return cap.text();
    };
    SECTION("an unusual name prints a placeholder and the way to get the exact name") {
        const std::string logs = run(std::string{"prod\nblue"});
        CHECK(logs.find("REINDEX DATABASE CONCURRENTLY <name>") != std::string::npos);
        CHECK(logs.find("ALTER DATABASE <name> REFRESH COLLATION VERSION") != std::string::npos);
        CHECK(logs.find("SELECT quote_ident(current_database())") != std::string::npos);
        CHECK(logs.find("\"prod_blue\"") == std::string::npos);
    }
    SECTION("a name longer than the log token cap prints the placeholder too") {
        const std::string logs = run(std::string(400, 'a'));
        CHECK(logs.find("ALTER DATABASE <name> REFRESH COLLATION VERSION") != std::string::npos);
        CHECK(logs.find("SELECT quote_ident(current_database())") != std::string::npos);
    }
    SECTION("an ordinary name keeps the pasteable commands and no placeholder") {
        const std::string logs = run("yuzu_prod");
        CHECK(logs.find("ALTER DATABASE \"yuzu_prod\" REFRESH COLLATION VERSION") !=
              std::string::npos);
        CHECK(logs.find("<name>") == std::string::npos);
        CHECK(logs.find("quote_ident") == std::string::npos);
    }
}

TEST_CASE("collation check against a real database: Ok, then Mismatch once the recorded version is "
          "changed",
          "[pg][pg_collation]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());

    const CollationReport first = check_collation_version(pool);
    INFO("verdict=" << to_string(first.verdict) << " failure=" << first.failure
                    << " database=" << first.database << " recorded=" << first.recorded
                    << " actual=" << first.actual);
    if (first.verdict == CollationVerdict::NotApplicable)
        SKIP("this PostgreSQL has no recorded collation version for the test database (C/POSIX "
             "locale "
             "or a server before 15)");
    // A cluster whose template database was created under an older library carries a recorded
    // version that already differs, so a database cloned from it starts as a Mismatch. That is the
    // condition under test, not a failure of this test.
    // Skip only on a genuine mismatch: both versions known and different. A Mismatch verdict with
    // an empty field would be a fetch defect, and must fail the REQUIRE below, not hide here.
    if (first.verdict == CollationVerdict::Mismatch && !first.recorded.empty() &&
        !first.actual.empty() && first.recorded != first.actual)
        SKIP("this cluster's template database already has a collation version mismatch "
             "(recorded="
             << first.recorded << " actual=" << first.actual << "); a clean start is needed");
    REQUIRE(first.verdict == CollationVerdict::Ok);
    CHECK(first.database == db.db_name());
    CHECK_FALSE(first.recorded.empty());
    CHECK(first.recorded == first.actual);

    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = exec_params(lease.get(),
                               "UPDATE pg_database SET datcollversion = '0.0.bogus' "
                               "WHERE datname = current_database()",
                               std::vector<std::string>{});
        if (res.status() != PGRES_COMMAND_OK)
            SKIP("the test role cannot update pg_database (not a superuser): "
                 << PQerrorMessage(lease.get()));
    }

    const CollationReport second = check_collation_version(pool);
    CHECK(second.verdict == CollationVerdict::Mismatch);
    CHECK(second.recorded == "0.0.bogus");
    CHECK(second.actual == first.actual);
    CHECK(second.database == db.db_name());
}
