/**
 * test_echo_retention_tiers.cpp — pure tests for the Echo retention tier TSV
 * parser and the bucket / guaranteed-depth arithmetic, plus the real embedded
 * table.
 */

#include "echo_retention_tiers.hpp"
#include "result_set_matcher.hpp"

#include <catch2/catch_test_macros.hpp>

#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <string>

namespace yuzu::server {
extern const std::string kEchoRetentionTiersTsv;
}

using namespace yuzu::server::echo_retention;

namespace {

constexpr const char* kHeader = "source\ttier\tlimit_kind\tlimit\n";

std::string with_header(const std::string& body) {
    return std::string(kHeader) + body;
}

const EchoRetentionTier* find(const std::vector<EchoRetentionTier>& v, const char* src,
                             const char* tier) {
    for (const auto& t : v)
        if (t.source == src && t.tier == tier)
            return &t;
    return nullptr;
}

constexpr std::int64_t kDay = 86400;

} // namespace

TEST_CASE("parse_echo_retention_tiers accepts a small table", "[echo][retention]") {
    auto r = parse_echo_retention_tiers(with_header("process\thourly\trows\t100000\r\n"
                                                   "\n"
                                                   "process\tdaily\tseconds\t86400\n"
                                                   "perf\tmonthly\tseconds\t604800\n"));
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 3);
    CHECK((*r)[0].source == "process");
    CHECK((*r)[0].row_count);
    CHECK((*r)[0].limit == 100000);
    CHECK_FALSE((*r)[1].row_count);
    CHECK((*r)[2].limit == 604800);
}

TEST_CASE("parse_echo_retention_tiers skips a live row without error", "[echo][retention]") {
    // Inline fixture on purpose: the embedded table is not counted here.
    auto r = parse_echo_retention_tiers(with_header("process\tlive\trows\t100000\n"
                                                   "process\thourly\tseconds\t86400\n"
                                                   "perf\tlive\tseconds\t604800\n"
                                                   "perf\tdaily\tseconds\t2678400\n"));
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 2);
    CHECK(find(*r, "process", "live") == nullptr);
    CHECK(find(*r, "perf", "live") == nullptr);
    CHECK(find(*r, "process", "hourly") != nullptr);
    CHECK(find(*r, "perf", "daily") != nullptr);
}

TEST_CASE("a skipped live row is still validated", "[echo][retention]") {
    auto bad_live = parse_echo_retention_tiers(with_header("process\tlive\trows\t0\n"
                                                           "process\thourly\tseconds\t5\n"));
    REQUIRE_FALSE(bad_live.has_value());
    CHECK(bad_live.error().find("line 2") != std::string::npos);
    auto dup = parse_echo_retention_tiers(with_header("process\tlive\trows\t5\n"
                                                      "process\tlive\trows\t6\n"
                                                      "process\thourly\tseconds\t5\n"));
    REQUIRE_FALSE(dup.has_value());
    CHECK(dup.error().find("line 3") != std::string::npos);
    // A table holding only live rows has no usable tier.
    auto only_live = parse_echo_retention_tiers(with_header("process\tlive\trows\t5\n"));
    REQUIRE_FALSE(only_live.has_value());
    CHECK(only_live.error().find("no tier rows") != std::string::npos);
}

TEST_CASE("parse_echo_retention_tiers accepts exactly the roll-up vocabulary", "[echo][retention]") {
    for (const char* tier : {"hourly", "daily", "monthly", "boot"}) {
        auto r = parse_echo_retention_tiers(
            with_header(std::string("process\t") + tier + "\tseconds\t5\n"));
        INFO(tier);
        REQUIRE(r.has_value());
        CHECK(r->size() == 1);
    }
    auto r = parse_echo_retention_tiers(with_header("process\tweekly\tseconds\t5\n"));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("unknown tier") != std::string::npos);
}

TEST_CASE("budget_dependent is true only for the hourly tier", "[echo][retention]") {
    CHECK(budget_dependent("hourly"));
    CHECK_FALSE(budget_dependent("daily"));
    CHECK_FALSE(budget_dependent("monthly"));
    CHECK_FALSE(budget_dependent("boot"));
    CHECK_FALSE(budget_dependent("live"));
}

TEST_CASE("parse_echo_retention_tiers rejects malformed tables naming the line",
          "[echo][retention]") {
    const auto bad = [](const std::string& tsv, const char* needle) {
        auto r = parse_echo_retention_tiers(tsv);
        INFO(tsv);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find(needle) != std::string::npos);
    };
    bad("src\ttier\tlimit_kind\tlimit\n", "line 1");
    bad("", "line 1");
    bad(with_header("process\thourly\trows\n"), "line 2");
    bad(with_header("process\thourly\tdays\t5\n"), "line 2");
    bad(with_header("process\thourlly\tseconds\t5\n"), "line 2");
    bad(with_header("process\thourly\trows\tabc\n"), "line 2");
    bad(with_header("process\thourly\trows\t0\n"), "line 2");
    bad(with_header("process\thourly\trows\t-5\n"), "line 2");
    bad(with_header("process\thourly\trows\t5x\n"), "line 2");
    bad(with_header("process\thourly\trows\t5\nprocess\thourly\trows\t6\n"), "line 3");
    bad(with_header("process\thourly\trows\t99999999999999999999\n"), "line 2");
    bad(with_header("process\thourly\trows\t+5\n"), "line 2");
    bad(with_header("process\thourly\trows\t 5\n"), "line 2");
    bad(with_header("process\thourly\trows\t5 \n"), "line 2");
    bad(with_header("process\thourly\trows\t5\textra\n"), "line 2");
    bad(kHeader, "no tier rows"); // an empty table must not read as a valid empty answer
}

TEST_CASE("parse_echo_retention_tiers tolerates framing quirks", "[echo][retention]") {
    const auto good = [](const std::string& tsv) {
        auto r = parse_echo_retention_tiers(tsv);
        INFO(tsv);
        REQUIRE(r.has_value());
        CHECK(r->size() == 1);
    };
    good("source\ttier\tlimit_kind\tlimit\r\nprocess\thourly\trows\t5\n"); // CRLF header
    good(with_header("process\thourly\trows\t5"));                           // no trailing newline
    good(std::string("\n\n") + with_header("process\thourly\trows\t5\n")); // leading blank lines
}

TEST_CASE("the embedded Echo retention table parses", "[echo][retention]") {
    // Holds on a table that still carries `live` rows (the parser skips them) and on one that has
    // none: it pins what the parser guarantees, not the row count of the shipped table.
    auto r = parse_echo_retention_tiers(yuzu::server::kEchoRetentionTiersTsv);
    REQUIRE(r.has_value());
    REQUIRE_FALSE(r->empty());
    for (const auto& t : *r)
        CHECK(t.tier != "live");
    CHECK(find(*r, "process", "live") == nullptr);
    CHECK(find(*r, "perf", "live") == nullptr);
    const auto* hourly = find(*r, "process", "hourly");
    REQUIRE(hourly);
    CHECK_FALSE(hourly->row_count);
    CHECK(hourly->limit > 0);
    CHECK(find(*r, "process", "daily"));
    CHECK(find(*r, "process", "monthly"));
}

TEST_CASE("bucket_seconds per tier", "[echo][retention]") {
    CHECK(bucket_seconds("live") == 0);
    CHECK(bucket_seconds("boot") == 0);
    CHECK(bucket_seconds("hourly") == 3600);
    CHECK(bucket_seconds("daily") == kDay);
    CHECK(bucket_seconds("monthly") == 2678400);
}

TEST_CASE("guaranteed_depth_seconds is limit minus bucket; null for row counts",
          "[echo][retention]") {
    CHECK(guaranteed_depth_seconds({"process", "hourly", false, 86400}) == 82800);
    CHECK(guaranteed_depth_seconds({"process", "daily", false, 2678400}) == 2592000);
    CHECK(guaranteed_depth_seconds({"process", "monthly", false, 31536000}) == 28857600);
    CHECK(guaranteed_depth_seconds({"perf", "live", false, 604800}) == 604800);
    CHECK(guaranteed_depth_seconds({"process", "live", true, 100000}) == std::nullopt);
    CHECK(guaranteed_depth_seconds({"x", "hourly", false, 60}) == 0); // never negative
    CHECK(guaranteed_depth_seconds({"x", "daily", false, 86400}) == 0); // limit == bucket
    CHECK(guaranteed_depth_seconds({"netqual", "boot", false, 400}) == 400); // boot: bucket 0
}

TEST_CASE("worked ages for the process source", "[echo][retention]") {
    auto r = parse_echo_retention_tiers(yuzu::server::kEchoRetentionTiersTsv);
    REQUIRE(r.has_value());
    const auto holds = [&](const char* tier, std::int64_t age_days) {
        const auto* t = find(*r, "process", tier);
        REQUIRE(t);
        const auto d = guaranteed_depth_seconds(*t);
        REQUIRE(d.has_value());
        return age_days * kDay < *d;
    };
    // 3 days: hourly gone, daily and monthly hold.
    CHECK_FALSE(holds("hourly", 3));
    CHECK(holds("daily", 3));
    CHECK(holds("monthly", 3));
    // Exactly on the boundary does not hold (strict <): daily depth is 30 d.
    CHECK_FALSE(holds("daily", 30));
    // 6 weeks: hourly and daily gone, monthly holds.
    CHECK_FALSE(holds("hourly", 42));
    CHECK_FALSE(holds("daily", 42));
    CHECK(holds("monthly", 42));
    // 10 months: only monthly holds.
    CHECK_FALSE(holds("hourly", 304));
    CHECK_FALSE(holds("daily", 304));
    CHECK(holds("monthly", 304));
    // 14 months: nothing holds.
    CHECK_FALSE(holds("hourly", 426));
    CHECK_FALSE(holds("daily", 426));
    CHECK_FALSE(holds("monthly", 426));
}

// ── Canned definitions read the roll-up tiers ───────────────────────────────────────────────────
// Source-tripwire: reads the committed definitions from the source tree (YUZU_SERVER_SRC_DIR is
// server/core/src), so a canned query that names a raw capture table again fails here.
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif

namespace {

std::string read_definition(const char* name) {
    std::ifstream in(std::string(YUZU_SERVER_SRC_DIR) + "/../../../content/definitions/" + name,
                     std::ios::binary);
    REQUIRE(in.good());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

} // namespace

TEST_CASE("canned Echo definitions name no raw capture table", "[echo][retention][definitions]") {
    for (const char* file : {"echo.yaml", "echo_warehouse.yaml"}) {
        const auto text = read_definition(file);
        INFO(file);
        CHECK(text.find("_Live") == std::string::npos);
        CHECK(text.find("live data") == std::string::npos);
    }
}

TEST_CASE("every canned default SQL reads a roll-up tier", "[echo][retention][definitions]") {
    const auto text = read_definition("echo_warehouse.yaml");
    const std::regex default_sql(R"(default: "(SELECT [^"]*)\")");
    const std::regex dollar(R"(\$([A-Za-z]+)_([A-Za-z]+))");
    int canned = 0;
    for (std::sregex_iterator it(text.begin(), text.end(), default_sql), end; it != end; ++it) {
        const std::string sql = (*it)[1].str();
        ++canned;
        INFO(sql);
        int tables = 0;
        for (std::sregex_iterator t(sql.begin(), sql.end(), dollar), tend; t != tend; ++t) {
            ++tables;
            const std::string tier = (*t)[2].str();
            CHECK((tier == "Hourly" || tier == "Daily" || tier == "Monthly"));
        }
        CHECK(tables >= 1);
    }
    CHECK(canned >= 12);
}

TEST_CASE("process tree canned query covers the last complete hour bucket",
          "[echo][retention][definitions]") {
    // A bucket is keyed by its start, so a bound of one hour back drops the last complete bucket
    // for most of the hour (at 10:05 the 09:00 bucket sits before 09:05); two hours back keeps it.
    const auto text = read_definition("echo_warehouse.yaml");
    const auto at = text.find("id: crossplatform.echo.process_tree");
    REQUIRE(at != std::string::npos);
    const auto block = text.substr(at, text.find("\n---\n", at) - at);
    const auto sql_at = block.find("default: \"SELECT");
    REQUIRE(sql_at != std::string::npos);
    const auto sql = block.substr(sql_at, block.find('\n', sql_at) - sql_at);
    CHECK(sql.find("$Process_Hourly") != std::string::npos);
    CHECK(sql.find("hour_ts > strftime('%s','now','-2 hours')") != std::string::npos);
    CHECK(sql.find("'-1 hours'") == std::string::npos);
}

TEST_CASE("the raw capture table predicate names every source of the retention table",
          "[echo][retention][definitions][result_set]") {
    // Drift tripwire for the sixteen hard-coded `<source>_live` names: every source the embedded
    // retention table declares, `usage` aside (its open-runs table is not a raw capture table),
    // must be refused; nothing else is pinned to the agent's registry here. The source column is
    // read from the table text itself: the parser skips `live` rows, and on this branch's base
    // four sources still have no other tier.
    std::set<std::string> sources;
    std::istringstream in(yuzu::server::kEchoRetentionTiersTsv);
    for (std::string line; std::getline(in, line);) {
        const auto tab = line.find('\t');
        if (tab != std::string::npos && line.substr(0, tab) != "source")
            sources.insert(line.substr(0, tab));
    }
    REQUIRE(sources.erase("usage") == 1);
    CHECK(sources.size() == 16);
    for (const auto& s : sources) {
        INFO(s);
        CHECK(yuzu::server::rs_matcher::references_raw_capture_table("SELECT 1 FROM " + s + "_live"));
        CHECK_FALSE(yuzu::server::rs_matcher::references_raw_capture_table("SELECT 1 FROM " + s +
                                                                           "_hourly"));
    }
}

TEST_CASE("listening ports canned query reads the listening-socket counters",
          "[echo][retention][definitions]") {
    const auto text = read_definition("echo_warehouse.yaml");
    const auto at = text.find("id: crossplatform.echo.listening_ports");
    REQUIRE(at != std::string::npos);
    const auto next = text.find("\n---\n", at);
    const auto block = text.substr(at, next - at);
    CHECK(block.find("$TCP_Hourly") != std::string::npos);
    CHECK(block.find("listen_open_count") != std::string::npos);
    CHECK(block.find("listen_close_count") != std::string::npos);
    const auto sql_at = block.find("default: \"SELECT");
    REQUIRE(sql_at != std::string::npos);
    CHECK(block.substr(sql_at, block.find('\n', sql_at) - sql_at).find("pid") ==
          std::string::npos); // the roll-up keeps no pid
}
