/**
 * test_echo_retention_tiers.cpp — pure tests for the Echo retention tier TSV
 * parser and the bucket / guaranteed-depth arithmetic, plus the real embedded
 * table.
 */

#include "echo_retention_tiers.hpp"

#include <catch2/catch_test_macros.hpp>

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
    auto r = parse_echo_retention_tiers(with_header("process\tlive\trows\t100000\r\n"
                                                   "\n"
                                                   "process\thourly\tseconds\t86400\n"
                                                   "perf\tlive\tseconds\t604800\n"));
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 3);
    CHECK((*r)[0].source == "process");
    CHECK((*r)[0].row_count);
    CHECK((*r)[0].limit == 100000);
    CHECK_FALSE((*r)[1].row_count);
    CHECK((*r)[2].limit == 604800);
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
    bad(with_header("process\tlive\trows\n"), "line 2");
    bad(with_header("process\tlive\tdays\t5\n"), "line 2");
    bad(with_header("process\thourlly\tseconds\t5\n"), "line 2");
    bad(with_header("process\tlive\trows\tabc\n"), "line 2");
    bad(with_header("process\tlive\trows\t0\n"), "line 2");
    bad(with_header("process\tlive\trows\t-5\n"), "line 2");
    bad(with_header("process\tlive\trows\t5x\n"), "line 2");
    bad(with_header("process\tlive\trows\t5\nprocess\tlive\trows\t6\n"), "line 3");
    bad(with_header("process\tlive\trows\t99999999999999999999\n"), "line 2");
    bad(with_header("process\tlive\trows\t+5\n"), "line 2");
    bad(with_header("process\tlive\trows\t 5\n"), "line 2");
    bad(with_header("process\tlive\trows\t5 \n"), "line 2");
    bad(with_header("process\tlive\trows\t5\textra\n"), "line 2");
    bad(kHeader, "no tier rows"); // an empty table must not read as a valid empty answer
}

TEST_CASE("parse_echo_retention_tiers tolerates framing quirks", "[echo][retention]") {
    const auto good = [](const std::string& tsv) {
        auto r = parse_echo_retention_tiers(tsv);
        INFO(tsv);
        REQUIRE(r.has_value());
        CHECK(r->size() == 1);
    };
    good("source\ttier\tlimit_kind\tlimit\r\nprocess\tlive\trows\t5\n"); // CRLF header
    good(with_header("process\tlive\trows\t5"));                           // no trailing newline
    good(std::string("\n\n") + with_header("process\tlive\trows\t5\n")); // leading blank lines
}

TEST_CASE("the embedded Echo retention table parses", "[echo][retention]") {
    auto r = parse_echo_retention_tiers(yuzu::server::kEchoRetentionTiersTsv);
    REQUIRE(r.has_value());
    const auto* live = find(*r, "process", "live");
    REQUIRE(live);
    CHECK(live->row_count);
    CHECK(live->limit == 100000);
    const auto* perf = find(*r, "perf", "live");
    REQUIRE(perf);
    CHECK_FALSE(perf->row_count);
    CHECK(perf->limit == 604800);
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
