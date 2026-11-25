/// @file test_live_read_poll.cpp
/// live_read_poll.{hpp,cpp}: the shared poll rule behind the REST live route and the MCP tool.
/// The pure reducer and the loop (with an injected read and sleep, so nothing sleeps) are
/// tested without a store; one PG-backed case pins the store wiring (agent scoped in SQL,
/// tier filter applied).

#include "live_read_poll.hpp"

#include "forensics_plugin_set.hpp"
#include "live_model.hpp"
#include "live_result_json.hpp"
#include "pg/pg_pool.hpp"
#include "response_store.hpp"
#include "utf8_clamp.hpp"
#include "test_forensics_tier_fixture.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace live = yuzu::server::live;

namespace {

StoredResponse row(std::int64_t id, std::int64_t ts, int status, std::string output,
                   std::string agent = "agent-1", std::string error = "") {
    StoredResponse r;
    r.id = id;
    r.timestamp = ts;
    r.status = status;
    r.output = std::move(output);
    r.agent_id = std::move(agent);
    r.error_detail = std::move(error);
    return r;
}

} // namespace

// ── reduce_rows (pure) ───────────────────────────────────────────────────────────

TEST_CASE("reduce_rows: no rows decides nothing (timeout)", "[live][poll]") {
    const auto v = live::reduce_rows({}, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kTimeout);
    CHECK(v.output.empty());
    CHECK_FALSE(v.partial);
}

TEST_CASE("reduce_rows: output without a terminal row is NOT an answer", "[live][poll]") {
    // A RUNNING chunk can land before the terminal frame: the poll must keep reading, never
    // answer the partial list as complete.
    const std::vector<StoredResponse> rows{row(1, 100, 0, "proc|1|a\n")};
    const auto v = live::reduce_rows(rows, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kTimeout);
    CHECK(v.partial);
    CHECK(v.output == "proc|1|a\n"); // handed back only for the loop's early over-cap exit
}

TEST_CASE("reduce_rows: the answer is decided once ANY row is terminal, in either ingest shape", "[live][poll]") {
    SECTION("direct Subscribe path: a separate empty terminal row follows the RUNNING chunks") {
        const std::vector<StoredResponse> rows{
            row(1, 100, 0, "proc|1|a\n"), row(2, 100, 0, "proc|2|b\n"), row(3, 101, 1, "")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "proc|1|a\nproc|2|b\n");
    }
    SECTION("gateway/proxy path: the terminal frame updated the RUNNING rows in place, no extra row") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "proc|1|a\n"), row(2, 100, 1, "proc|2|b\n")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "proc|1|a\nproc|2|b\n");
    }
    SECTION("gateway/proxy path: only the LAST row updated in place is still a terminal row") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "proc|1|a\n"), row(2, 100, 1, "proc|2|b\n")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kOk);
    }
}

TEST_CASE("reduce_rows: a RUNNING row with output plus a terminal failure row is a failure", "[live][poll]") {
    const std::vector<StoredResponse> rows{
        row(1, 100, 0, "partial output\n"),
        row(2, 101, 2, "", "agent-1", "plugin crashed"),
    };
    const auto v = live::reduce_rows(rows, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kDeviceFailed);
    CHECK(v.detail == "plugin crashed");
    CHECK(v.output.empty());
}

TEST_CASE("reduce_rows: a failure row wins at once, with or without partial output and a success row", "[live][poll]") {
    SECTION("failure alone") {
        const std::vector<StoredResponse> rows{row(1, 100, 2, "", "agent-1", "boom")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kDeviceFailed);
    }
    SECTION("failure beside a success row") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "ok\n"), row(2, 101, 2, "", "agent-1", "boom")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kDeviceFailed);
    }
}

TEST_CASE("reduce_rows: failure detail is bounded to 200 bytes", "[live][poll]") {
    const std::vector<StoredResponse> rows{row(1, 100, 3, "", "agent-1", std::string(5000, 'x'))};
    const auto v = live::reduce_rows(rows, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kDeviceFailed);
    CHECK(v.detail.size() == live::kLiveDetailMaxBytes);
    CHECK(live::kLiveDetailMaxBytes == 200);
}

TEST_CASE("reduce_rows: detail cuts land on a UTF-8 boundary", "[live][poll]") {
    // 199 ASCII bytes, then a 3-byte character straddling the 200-byte cut: the whole character
    // is dropped, never half of it.
    const std::string text = std::string(199, 'a') + "\xE2\x82\xAC" + "tail"; // euro sign
    SECTION("failure text") {
        const std::vector<StoredResponse> rows{row(1, 100, 2, "", "agent-1", text)};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.detail == std::string(199, 'a'));
    }
    SECTION("error| text, cut at an offset that also shifts by the 6-byte prefix") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "error|" + text)};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kDeviceError);
        CHECK(v.detail == std::string(199, 'a'));
    }
    SECTION("a multi-byte character that fits whole is kept") {
        const std::string fits = std::string(197, 'a') + "\xE2\x82\xAC" + "tail"; // 197 + 3 = 200
        const std::vector<StoredResponse> rows{row(1, 100, 2, "", "agent-1", fits)};
        CHECK(live::reduce_rows(rows, "agent-1").detail == std::string(197, 'a') + "\xE2\x82\xAC");
    }
}

TEST_CASE("reduce_rows: rows join in id order whatever order they arrive in or their timestamps say", "[live][poll]") {
    SECTION("ids decide, the timestamp does not: a clock step back must not reorder chunks") {
        const std::vector<StoredResponse> rows{
            row(9, 100, 0, "C"), row(1, 300, 0, "A"), row(5, 200, 0, "B"), row(10, 50, 1, "")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "A\nB\nC");
    }
    SECTION("equal timestamps concatenate in id order") {
        const std::vector<StoredResponse> rows{
            row(30, 100, 0, "3"), row(10, 100, 0, "1"), row(20, 100, 0, "2"), row(40, 100, 1, "")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "1\n2\n3");
    }
    SECTION("empty outputs contribute nothing") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "X"), row(2, 101, 0, ""), row(3, 102, 1, "Y")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "X\nY");
    }
}

TEST_CASE("reduce_rows: chunks are joined at a line boundary, never fused", "[live][poll]") {
    SECTION("two chunks with no trailing newline are separated by one newline") {
        const std::vector<StoredResponse> rows{
            row(1, 100, 0, "proc|1|a|h1|/p1"), row(2, 101, 1, "proc|2|b|h2|/p2")};
        const auto v = live::reduce_rows(rows, "agent-1");
        REQUIRE(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "proc|1|a|h1|/p1\nproc|2|b|h2|/p2");
    }
    SECTION("a chunk that already ends in a newline gets no second one") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "proc|1|a\n"), row(2, 101, 1, "proc|2|b\n")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "proc|1|a\nproc|2|b\n");
    }
    SECTION("a CRLF-ended chunk gets no second separator") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "proc|1|a\r\n"), row(2, 101, 1, "proc|2|b\r\n")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "proc|1|a\r\nproc|2|b\r\n");
    }
    SECTION("an empty chunk between two chunks adds no separator and no blank line") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "A"), row(2, 101, 0, ""), row(3, 102, 1, "B")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "A\nB");
    }
    SECTION("the first chunk is never prefixed and a single chunk is unchanged") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "only")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "only");
    }
    SECTION("the parsed rows are correct: no row is fused with its neighbour") {
        const std::vector<StoredResponse> rows{
            row(1, 100, 0, "proc|1|alpha|aa|/bin/alpha"), row(2, 101, 1, "proc|2|beta|bb|/bin/beta")};
        const auto v = live::reduce_rows(rows, "agent-1");
        const auto parsed = live::parse_processes(v.output);
        REQUIRE(parsed.size() == 2);
        CHECK(parsed[0].path == "/bin/alpha");
        CHECK(parsed[1].pid == 2);
        CHECK(parsed[1].name == "beta");
        CHECK(parsed[1].path == "/bin/beta");
    }
}

TEST_CASE("reduce_rows: another agent's rows are ignored", "[live][poll]") {
    SECTION("a foreign row alone decides nothing") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "secret\n", "agent-2")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kTimeout);
        CHECK_FALSE(v.partial);
    }
    SECTION("a foreign failure does not fail this agent's answer") {
        const std::vector<StoredResponse> rows{
            row(1, 100, 2, "", "agent-2", "boom"), row(2, 101, 1, "mine\n", "agent-1")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "mine\n");
    }
    SECTION("a foreign terminal row does not make this agent's partial output an answer") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "mine\n", "agent-1"), row(2, 101, 1, "", "agent-2")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kTimeout);
    }
    SECTION("a foreign row's output is never joined") {
        const std::vector<StoredResponse> rows{
            row(1, 100, 0, "mine|", "agent-1"), row(2, 100, 0, "theirs|", "agent-2"), row(3, 101, 1, "more", "agent-1")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "mine|\nmore");
    }
}

TEST_CASE("reduce_rows: an `error|` prefix on the joined output is a device error", "[live][poll]") {
    SECTION("first row") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "error|plugin not loaded")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kDeviceError);
        CHECK(v.detail == "plugin not loaded");
    }
    SECTION("the detail is bounded") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "error|" + std::string(5000, 'e'))};
        CHECK(live::reduce_rows(rows, "agent-1").detail.size() == live::kLiveDetailMaxBytes);
    }
    SECTION("without a terminal row an `error|` line is still undecided") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "error|plugin not loaded")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kTimeout);
        CHECK(v.partial);
    }
    SECTION("a prefix split over two rows is two lines, not an error") {
        // Chunks are joined at a line boundary, so "err" + "or|late" is two lines.
        const std::vector<StoredResponse> rows{row(1, 100, 0, "err"), row(2, 101, 1, "or|late")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "err\nor|late");
    }
    SECTION("`error|` inside a later row is data, not an error") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "proc|1|a\n"), row(2, 101, 1, "error|x")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "proc|1|a\nerror|x");
    }
    SECTION("`error|` from a foreign agent's row is ignored") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "error|nope", "agent-2"), row(2, 101, 1, "ok\n")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kOk);
    }
    SECTION("a failure row wins over an error| answer") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "error|x"), row(2, 101, 2, "", "agent-1", "died")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kDeviceFailed);
    }
}

TEST_CASE("reduce_rows: a success terminal with no output is an empty success, not a timeout", "[live][poll]") {
    const std::vector<StoredResponse> rows{row(1, 100, 1, "")};
    const auto v = live::reduce_rows(rows, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kOk);
    CHECK(v.output.empty());
}

TEST_CASE("reduce_rows: a RUNNING row with no output is still undecided and not partial", "[live][poll]") {
    const std::vector<StoredResponse> rows{row(1, 100, 0, "")};
    const auto v = live::reduce_rows(rows, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kTimeout);
    CHECK_FALSE(v.partial);
}

// G-UP-1: decision facts cover rows the bounded read cut. The facts come from the store, over every
// permitted row, so the reducer must decide from them when the rows it was handed are thinned.
TEST_CASE("reduce_rows: decision facts decide over rows the bounded read left out", "[live][poll][2146]") {
    BoundedFacts facts;
    SECTION("a failure the cut dropped still answers, with the facts' text") {
        // The surviving rows are late RUNNING chunks; the failing row is not among them.
        const std::vector<StoredResponse> rows{row(90, 100, 0, "late|1\n"), row(91, 100, 0, "late|2\n")};
        facts.any_failed = true;
        facts.any_terminal = true;
        facts.failed_detail = "agent exploded";
        const auto v = live::reduce_rows(rows, "agent-1", &facts, /*rows_cut=*/true);
        CHECK(v.outcome == live::LiveOutcome::kDeviceFailed);
        CHECK(v.detail == "agent exploded");
        CHECK(v.output.empty());
    }
    SECTION("the facts' failure text is bounded like a row's") {
        facts.any_failed = true;
        facts.failed_detail = std::string(500, 'e');
        const auto v = live::reduce_rows({}, "agent-1", &facts, true);
        CHECK(v.outcome == live::LiveOutcome::kDeviceFailed);
        CHECK(v.detail.size() == live::kLiveDetailMaxBytes);
    }
    SECTION("a terminal row the cut dropped still makes the answer decidable") {
        const std::vector<StoredResponse> rows{row(90, 100, 0, "late|1\n")};
        facts.any_terminal = true;
        const auto v = live::reduce_rows(rows, "agent-1", &facts, true);
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK_FALSE(v.partial);
    }
    SECTION("no facts: the same rows are undecided, as before") {
        const std::vector<StoredResponse> rows{row(90, 100, 0, "late|1\n")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kTimeout);
        CHECK(v.partial);
    }
    SECTION("facts that show nothing change nothing") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "proc|1|a\n")};
        const auto v = live::reduce_rows(rows, "agent-1", &facts, false);
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "proc|1|a\n");
    }
}

TEST_CASE("reduce_rows: when the oldest rows were cut, the true head chunk decides `error|`", "[live][poll][2146]") {
    BoundedFacts facts;
    facts.any_terminal = true;
    const std::vector<StoredResponse> rows{row(90, 100, 0, "later|1\n"), row(91, 100, 1, "")};
    SECTION("the head chunk was an error| answer the cut dropped") {
        facts.head_output = "error|device said no";
        const auto v = live::reduce_rows(rows, "agent-1", &facts, /*rows_cut=*/true);
        CHECK(v.outcome == live::LiveOutcome::kDeviceError);
        CHECK(v.detail == "device said no");
    }
    SECTION("a surviving chunk that starts with error| is data when the true head is not an error") {
        const std::vector<StoredResponse> data{row(90, 100, 0, "error|looks-like-one\n"), row(91, 100, 1, "")};
        facts.head_output = "proc|1|a";
        const auto v = live::reduce_rows(data, "agent-1", &facts, true);
        CHECK(v.outcome == live::LiveOutcome::kOk);
    }
    SECTION("no terminal row yet, the head chunk was an error| answer the cut dropped: decided as a device error") {
        const std::vector<StoredResponse> open{row(90, 100, 0, "later|1\n")};
        facts.any_terminal = false;
        facts.head_output = "error|device said no";
        const auto v = live::reduce_rows(open, "agent-1", &facts, true);
        CHECK(v.outcome == live::LiveOutcome::kDeviceError);
        CHECK(v.detail == "device said no");
        // Nothing was cut: an error| line without a terminal row is still undecided.
        const auto uncut = live::reduce_rows(open, "agent-1", &facts, false);
        CHECK(uncut.outcome == live::LiveOutcome::kTimeout);
    }
    SECTION("a multi-byte failure text from the facts is clamped to 200 bytes on a character boundary") {
        BoundedFacts f;
        f.any_failed = true;
        for (int i = 0; i < 100; ++i)
            f.failed_detail += "\xE2\x82\xAC"; // U+20AC, 3 bytes: byte 200 falls inside a character
        const auto v = live::reduce_rows({}, "agent-1", &f, true);
        CHECK(v.outcome == live::LiveOutcome::kDeviceFailed);
        CHECK(v.detail.size() == 198); // 66 whole characters, never a split one
        CHECK(v.detail == f.failed_detail.substr(0, 198));
    }
    SECTION("nothing was cut: the joined output decides, as before") {
        facts.head_output = "error|ignored"; // would flip the answer if it were read without a cut
        const std::vector<StoredResponse> whole{row(1, 100, 1, "proc|1|a\n")};
        const auto v = live::reduce_rows(whole, "agent-1", &facts, /*rows_cut=*/false);
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "proc|1|a\n");
    }
}

TEST_CASE("utf8_clamp_prefix: never ends inside a multi-byte character", "[live][poll][utf8]") {
    using yuzu::server::utf8_clamp_prefix;
    const std::string euro = "\xE2\x82\xAC"; // 3 bytes
    const std::string four = "\xF0\x9F\x98\x80"; // 4 bytes
    SECTION("a string that fits is returned whole") {
        CHECK(utf8_clamp_prefix("abc", 3) == "abc");
        CHECK(utf8_clamp_prefix("abc", 10) == "abc");
        CHECK(utf8_clamp_prefix("", 0) == "");
    }
    SECTION("ASCII is cut exactly at the bound") {
        CHECK(utf8_clamp_prefix("abcdef", 4) == "abcd");
        CHECK(utf8_clamp_prefix("abcdef", 0) == "");
    }
    SECTION("a cut inside a 3-byte character drops the whole character") {
        const std::string s = "ab" + euro + "cd";
        CHECK(utf8_clamp_prefix(s, 3) == "ab"); // would end after the lead byte
        CHECK(utf8_clamp_prefix(s, 4) == "ab"); // would end after the second byte
        CHECK(utf8_clamp_prefix(s, 5) == "ab" + euro);
    }
    SECTION("a cut inside a 4-byte character drops the whole character") {
        const std::string s = "a" + four + "b";
        CHECK(utf8_clamp_prefix(s, 2) == "a");
        CHECK(utf8_clamp_prefix(s, 3) == "a");
        CHECK(utf8_clamp_prefix(s, 4) == "a");
        CHECK(utf8_clamp_prefix(s, 5) == "a" + four);
    }
    SECTION("a bound smaller than the first character gives an empty prefix") {
        CHECK(utf8_clamp_prefix(four, 2).empty());
    }
    SECTION("stray continuation bytes with no lead byte back up to nothing, never past the start") {
        CHECK(utf8_clamp_prefix("\x80\x80\x80\x80", 2).empty());
    }
}

// ── the loop (injected read and sleep) ───────────────────────────────────────────

namespace {
live::LivePollLimits fast_limits(int polls = 5) {
    live::LivePollLimits l;
    l.max_polls = polls;
    l.interval = std::chrono::milliseconds(500);
    return l;
}
using Rows = std::optional<live::LiveRowsRead>;
const auto no_sleep = [](std::chrono::milliseconds) {};
} // namespace

TEST_CASE("poll_live_output: answers on the first read without sleeping", "[live][poll]") {
    int reads = 0, sleeps = 0;
    const auto out = live::poll_live_output(
        [&]() -> Rows {
            ++reads;
            return live::LiveRowsRead{{row(1, 1, 1, "hello\n")}};
        },
        "agent-1", fast_limits(), [&](std::chrono::milliseconds) { ++sleeps; });
    CHECK(out.outcome == live::LiveOutcome::kOk);
    CHECK(out.output == "hello\n");
    CHECK(reads == 1);
    CHECK(sleeps == 0);
}

TEST_CASE("poll_live_output: a partial answer is not returned; the poll waits for the terminal row", "[live][poll]") {
    int reads = 0;
    std::vector<std::chrono::milliseconds> slept;
    const auto out = live::poll_live_output(
        [&]() -> Rows {
            ++reads;
            if (reads == 1)
                return std::vector<StoredResponse>{};
            if (reads == 2) // the first chunk lands, the terminal frame has not
                return std::vector<StoredResponse>{row(1, 1, 0, "proc|1|a\n")};
            return std::vector<StoredResponse>{row(1, 1, 0, "proc|1|a\n"), row(2, 1, 0, "proc|2|b\n"),
                                               row(3, 2, 1, "")};
        },
        "agent-1", fast_limits(), [&](std::chrono::milliseconds d) { slept.push_back(d); });
    CHECK(out.outcome == live::LiveOutcome::kOk);
    CHECK(out.output == "proc|1|a\nproc|2|b\n"); // the whole answer, never the first chunk alone
    CHECK(reads == 3);
    REQUIRE(slept.size() == 2);
    CHECK(slept[0] == std::chrono::milliseconds(500));
}

TEST_CASE("poll_live_output: no rows for the whole budget is a timeout", "[live][poll]") {
    int reads = 0;
    const auto out = live::poll_live_output(
        [&]() -> Rows {
            ++reads;
            return std::vector<StoredResponse>{};
        },
        "agent-1", fast_limits(7), no_sleep);
    CHECK(out.outcome == live::LiveOutcome::kTimeout);
    CHECK(out.detail.empty());
    CHECK(reads == 7);
}

TEST_CASE("poll_live_output: output with no terminal row for the whole budget is incomplete, not a timeout", "[live][poll]") {
    int reads = 0;
    const auto out = live::poll_live_output(
        [&]() -> Rows {
            ++reads;
            return std::vector<StoredResponse>{row(1, 1, 0, "proc|1|a\n")};
        },
        "agent-1", fast_limits(6), no_sleep);
    CHECK(out.outcome == live::LiveOutcome::kIncomplete);
    CHECK(out.detail == "the device began to answer but did not finish");
    CHECK(out.output.empty()); // the partial output is discarded
    CHECK_FALSE(out.truncated);
    CHECK(reads == 6);
}

TEST_CASE("poll_live_output: partial output that later vanishes still reads as incomplete", "[live][poll]") {
    int reads = 0;
    const auto out = live::poll_live_output(
        [&]() -> Rows {
            if (++reads == 1)
                return std::vector<StoredResponse>{row(1, 1, 0, "x\n")};
            return std::vector<StoredResponse>{};
        },
        "agent-1", fast_limits(3), no_sleep);
    CHECK(out.outcome == live::LiveOutcome::kIncomplete);
}

TEST_CASE("poll_live_output: every read degraded is store_degraded, not a timeout", "[live][poll]") {
    int reads = 0;
    const auto out = live::poll_live_output(
        [&]() -> Rows {
            ++reads;
            return std::nullopt;
        },
        "agent-1", fast_limits(4), no_sleep);
    CHECK(out.outcome == live::LiveOutcome::kStoreDegraded);
    CHECK(reads == 4);
}

TEST_CASE("poll_live_output: a degrade followed by an empty read is a timeout; a later answer wins", "[live][poll]") {
    SECTION("degrade then empty reads: the store did answer, so timeout") {
        int reads = 0;
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                if (++reads == 1)
                    return std::nullopt;
                return std::vector<StoredResponse>{};
            },
            "agent-1", fast_limits(3), no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kTimeout);
    }
    SECTION("degrade then an answer: the answer is returned") {
        int reads = 0;
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                if (++reads == 1)
                    return std::nullopt;
                return std::vector<StoredResponse>{row(1, 1, 1, "x\n")};
            },
            "agent-1", fast_limits(3), no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output == "x\n");
    }
}

TEST_CASE("poll_live_output: failure, device error and empty success pass through", "[live][poll]") {
    const auto failed = live::poll_live_output(
        []() -> Rows {
            return std::vector<StoredResponse>{row(1, 1, 0, "partial"), row(2, 2, 2, "", "agent-1", "bad")};
        },
        "agent-1", fast_limits(), no_sleep);
    CHECK(failed.outcome == live::LiveOutcome::kDeviceFailed);
    CHECK(failed.detail == "bad");

    const auto err = live::poll_live_output(
        []() -> Rows { return std::vector<StoredResponse>{row(1, 1, 1, "error|nope")}; }, "agent-1",
        fast_limits(), no_sleep);
    CHECK(err.outcome == live::LiveOutcome::kDeviceError);
    CHECK(err.detail == "nope");

    const auto empty = live::poll_live_output(
        []() -> Rows { return std::vector<StoredResponse>{row(1, 1, 1, "")}; }, "agent-1", fast_limits(),
        no_sleep);
    CHECK(empty.outcome == live::LiveOutcome::kOk);
    CHECK(empty.output.empty());
}

TEST_CASE("poll_live_output: an unwired read seam degrades rather than crashing", "[live][poll]") {
    const auto out = live::poll_live_output(live::LiveRowsFn{}, "agent-1", fast_limits(2), no_sleep);
    CHECK(out.outcome == live::LiveOutcome::kStoreDegraded);
}

TEST_CASE("poll_live_output: zero polls is a timeout, never a degrade", "[live][poll]") {
    const auto out = live::poll_live_output([]() -> Rows { return std::nullopt; }, "agent-1", fast_limits(0),
                                            no_sleep);
    CHECK(out.outcome == live::LiveOutcome::kTimeout);
}

TEST_CASE("poll_live_output: the output byte cap refuses (REST) or cuts at a newline (MCP)", "[live][poll]") {
    const std::string big = "aaaa\nbbbb\ncccc\n"; // 15 bytes
    const auto read = [&]() -> Rows { return std::vector<StoredResponse>{row(1, 1, 1, big)}; };

    auto limits = fast_limits();
    limits.max_output_bytes = 12;

    SECTION("refuse") {
        limits.over_cap = live::OverCapPolicy::kRefuse;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOutputTooLarge);
        CHECK(out.output.empty());
    }
    SECTION("cut at the last newline inside the cap") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output == "aaaa\nbbbb");
        CHECK(out.truncated);
    }
    SECTION("a cap that lands exactly on a newline keeps the rows before it") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        limits.max_output_bytes = 10; // "aaaa\nbbbb\n" is 10 bytes; the newline at index 9 is inside
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.output == "aaaa\nbbbb");
        CHECK(out.truncated);
    }
    SECTION("no newline inside the cap: nothing whole fits") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        limits.max_output_bytes = 3;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output.empty());
        CHECK(out.truncated);
    }
    SECTION("at or under the cap nothing is cut") {
        limits.max_output_bytes = big.size();
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.output == big);
    }
}

TEST_CASE("poll_live_output: a CRLF answer cut at a newline leaves no stray carriage return", "[live][poll]") {
    const std::string crlf = "proc|1|a|h|/p1\r\nproc|2|b|h|/p2\r\nproc|3|c|h|/p3\r\n";
    auto limits = fast_limits();
    limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
    limits.max_output_bytes = 31; // inside the second line, 15 bytes after the first newline
    const auto out = live::poll_live_output(
        [&]() -> Rows { return std::vector<StoredResponse>{row(1, 1, 1, crlf)}; }, "agent-1", limits, no_sleep);
    REQUIRE(out.outcome == live::LiveOutcome::kOk);
    CHECK(out.truncated);
    CHECK(out.output == "proc|1|a|h|/p1");
    CHECK(out.output.find('\r') == std::string::npos);
    // And the rendered JSON carries neither a raw nor an escaped carriage return.
    const auto rendered = live::live_result_json("processes", out.output);
    REQUIRE(rendered);
    CHECK(rendered->body.find('\r') == std::string::npos);
    CHECK(rendered->body.find("\\r") == std::string::npos);
}

TEST_CASE("poll_live_output: output past the cap decides at once, without waiting for a terminal row", "[live][poll]") {
    auto limits = fast_limits(40);
    limits.max_output_bytes = 12;
    int reads = 0;
    const auto read = [&]() -> Rows {
        ++reads;
        return std::vector<StoredResponse>{row(1, 1, 0, "aaaa\nbbbb\ncccc\n")}; // 15 bytes, still RUNNING
    };
    SECTION("refuse") {
        limits.over_cap = live::OverCapPolicy::kRefuse;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOutputTooLarge);
        CHECK(reads == 1);
    }
    SECTION("truncate") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output == "aaaa\nbbbb");
        CHECK(out.truncated);
        CHECK(reads == 1);
    }
    SECTION("a failure row still wins over the cap") {
        const auto out = live::poll_live_output(
            []() -> Rows {
                return std::vector<StoredResponse>{row(1, 1, 0, "aaaa\nbbbb\ncccc\n"), row(2, 2, 2, "", "agent-1", "x")};
            },
            "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kDeviceFailed);
    }
    SECTION("output within the cap and no terminal row keeps polling") {
        limits.max_output_bytes = 100;
        const auto out = live::poll_live_output(read, "agent-1", fast_limits(3), no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kIncomplete);
    }
}

TEST_CASE("poll_live_output: a read the store cut (its head is missing) is over the cap", "[live][poll]") {
    auto limits = fast_limits();
    const auto read = [&]() -> Rows {
        return live::LiveRowsRead{{row(7, 1, 1, "proc|9|tail\n")}, /*capped=*/true};
    };
    SECTION("refuse") {
        limits.over_cap = live::OverCapPolicy::kRefuse;
        CHECK(live::poll_live_output(read, "agent-1", limits, no_sleep).outcome ==
              live::LiveOutcome::kOutputTooLarge);
    }
    SECTION("truncate: what survived is returned and flagged") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output == "proc|9|tail\n");
        CHECK(out.truncated);
    }
}

TEST_CASE("poll_live_output: the wall deadline ends a poll that is slow rather than long", "[live][poll]") {
    // Each read costs 10 s of steady-clock time; the 25 s deadline ends the poll after the third
    // read, long before max_polls.
    auto t = std::chrono::steady_clock::time_point{} + std::chrono::hours(1);
    const auto now = [&]() { return t; };
    int reads = 0;
    auto limits = fast_limits(40);
    SECTION("nothing seen: timeout") {
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                ++reads;
                t += std::chrono::seconds(10);
                return std::vector<StoredResponse>{};
            },
            "agent-1", limits, no_sleep, {}, now);
        CHECK(out.outcome == live::LiveOutcome::kTimeout);
        CHECK(reads == 3);
    }
    SECTION("output but no terminal row: incomplete") {
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                ++reads;
                t += std::chrono::seconds(10);
                return std::vector<StoredResponse>{row(1, 1, 0, "x\n")};
            },
            "agent-1", limits, no_sleep, {}, now);
        CHECK(out.outcome == live::LiveOutcome::kIncomplete);
        CHECK(reads == 3);
    }
    SECTION("every read degraded: store_degraded") {
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                ++reads;
                t += std::chrono::seconds(10);
                return std::nullopt;
            },
            "agent-1", limits, no_sleep, {}, now);
        CHECK(out.outcome == live::LiveOutcome::kStoreDegraded);
        CHECK(reads == 3);
    }
    SECTION("the first read always happens, even with a zero budget") {
        limits.deadline = std::chrono::milliseconds(0);
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                ++reads;
                return std::vector<StoredResponse>{row(1, 1, 1, "ok\n")};
            },
            "agent-1", limits, no_sleep, {}, now);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(reads == 1);
    }
}

TEST_CASE("poll_live_output: the stop predicate abandons the poll with shutting_down", "[live][poll]") {
    SECTION("already stopping: no read at all") {
        int reads = 0;
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                ++reads;
                return std::vector<StoredResponse>{};
            },
            "agent-1", fast_limits(), no_sleep, []() { return true; });
        CHECK(out.outcome == live::LiveOutcome::kShuttingDown);
        CHECK(out.output.empty());
        CHECK(reads == 0);
    }
    SECTION("stop raised between reads") {
        int reads = 0;
        bool stop = false;
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                if (++reads == 2)
                    stop = true; // raised while the second read is in flight
                return std::vector<StoredResponse>{};
            },
            "agent-1", fast_limits(40), no_sleep, [&]() { return stop; });
        CHECK(out.outcome == live::LiveOutcome::kShuttingDown);
        CHECK(reads == 2);
    }
    SECTION("stop raised during the sleep is seen straight after it") {
        int reads = 0;
        bool stop = false;
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                ++reads;
                return std::vector<StoredResponse>{};
            },
            "agent-1", fast_limits(40), [&](std::chrono::milliseconds) { stop = true; },
            [&]() { return stop; });
        CHECK(out.outcome == live::LiveOutcome::kShuttingDown);
        CHECK(reads == 1);
    }
    SECTION("a decided answer is not turned into shutting_down when the stop never fires") {
        const auto out = live::poll_live_output(
            []() -> Rows { return std::vector<StoredResponse>{row(1, 1, 1, "x\n")}; }, "agent-1",
            fast_limits(), no_sleep, []() { return false; });
        CHECK(out.outcome == live::LiveOutcome::kOk);
    }
}

TEST_CASE("poll_live_output: the default limits are the ruled 40 x 500 ms, 25 s and 4 MiB refusal", "[live][poll]") {
    const live::LivePollLimits l;
    CHECK(l.max_polls == 40);
    CHECK(l.interval == std::chrono::milliseconds(500));
    CHECK(l.deadline == std::chrono::milliseconds(25000));
    CHECK(l.max_output_bytes == 4u * 1024u * 1024u);
    CHECK(l.over_cap == live::OverCapPolicy::kRefuse);
}

// ── store wiring (PG) ────────────────────────────────────────────────────────────

namespace {
// Shares the "responsestore" key with the other ResponseStore tests (identical resulting schema).
yuzu::test::PgTestTemplate live_poll_tpl{
    "responsestore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        ResponseStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("responsestore template: store failed to migrate");
    }};

void seed(ResponseStore& store, const std::string& cmd, const std::string& agent, int status,
          const std::string& output, const std::string& plugin = "os_info", const std::string& err = "",
          std::int64_t timestamp = 0) {
    StoredResponse r;
    r.timestamp = timestamp; // 0 = the store stamps its own clock
    r.instruction_id = cmd;
    r.agent_id = agent;
    r.status = status;
    r.output = output;
    r.error_detail = err;
    r.plugin = plugin;
    // A refused row (the per-agent cap) would silently weaken a cut test: fail loudly instead.
    REQUIRE(store.store(r) == StoreOutcome::Stored);
}
} // namespace

TEST_CASE("poll_live_output [pg]: reads scoped to the target agent and joins a multi-row answer", "[live][poll][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());

    seed(store, "cmd-1", "agent-1", 0, "proc|1|a\n");
    seed(store, "cmd-1", "agent-2", 1, "proc|99|foreign\n");
    seed(store, "cmd-1", "agent-1", 1, "proc|2|b\n");
    seed(store, "cmd-other", "agent-1", 1, "proc|3|other-command\n");

    auto limits = fast_limits(1);
    const auto out = live::poll_live_output(store, "cmd-1", "agent-1",
                                            &yuzu::server::test::forensics_plugin_set(), limits,
                                            [](std::chrono::milliseconds) {});
    CHECK(out.outcome == live::LiveOutcome::kOk);
    CHECK(out.output.find("foreign") == std::string::npos);
    CHECK(out.output.find("other-command") == std::string::npos);
    CHECK(out.output.find("proc|1|a") != std::string::npos);
    CHECK(out.output.find("proc|2|b") != std::string::npos);
}

TEST_CASE("poll_live_output [pg]: a Forensics-plugin row and a null plugin set both yield nothing", "[live][poll][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());

    seed(store, "cmd-f", "agent-1", 1, "secret\n", yuzu::server::test::kForensicsPlugin);
    seed(store, "cmd-n", "agent-1", 1, "visible\n");

    auto limits = fast_limits(1);
    const auto sleep = [](std::chrono::milliseconds) {};
    CHECK(live::poll_live_output(store, "cmd-f", "agent-1", &yuzu::server::test::forensics_plugin_set(),
                                 limits, sleep)
              .outcome == live::LiveOutcome::kTimeout);
    // An unwired plugin set refuses every row rather than reading unfiltered.
    CHECK(live::poll_live_output(store, "cmd-n", "agent-1", nullptr, limits, sleep).outcome ==
          live::LiveOutcome::kTimeout);
}

TEST_CASE("poll_live_output [pg]: the agent scope is applied in SQL, before the row limit", "[live][poll][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());

    // One target row, then MORE foreign rows than the poll's row limit, all NEWER than it. A
    // read that applied the limit before the agent filter would fill its page with foreign rows
    // (newest first) and never see the target row; only the SQL `agent_id` scope keeps it. The
    // per-row filter inside reduce_rows cannot rescue a row the page never contained.
    seed(store, "cmd-scope", "agent-1", 1, "proc|1|mine|h|/mine\n", "os_info", "", 1000);
    for (int i = 0; i < live::kLivePollRowLimit + 8; ++i)
        seed(store, "cmd-scope", "foreign-" + std::to_string(i), 1, "proc|99|theirs\n", "os_info", "", 2000 + i);

    auto limits = fast_limits(1);
    const auto out = live::poll_live_output(store, "cmd-scope", "agent-1",
                                            &yuzu::server::test::forensics_plugin_set(), limits, no_sleep);
    REQUIRE(out.outcome == live::LiveOutcome::kOk);
    CHECK(out.output == "proc|1|mine|h|/mine\n");
    CHECK(out.output.find("theirs") == std::string::npos);
}

TEST_CASE("poll_live_output [pg]: chunks join in ingest order and a partial answer waits for its terminal row", "[live][poll][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());
    const auto* plugins = &yuzu::server::test::forensics_plugin_set();

    // The second chunk is stamped with an EARLIER timestamp (a clock step back): ids, not
    // timestamps, give the order.
    seed(store, "cmd-order", "agent-1", 0, "proc|1|a|h|/p1", "os_info", "", 500);
    seed(store, "cmd-order", "agent-1", 0, "proc|2|b|h|/p2", "os_info", "", 400);

    SECTION("no terminal row yet: incomplete after the budget, nothing returned") {
        const auto out = live::poll_live_output(store, "cmd-order", "agent-1", plugins, fast_limits(2), no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kIncomplete);
        CHECK(out.output.empty());
    }
    SECTION("terminal row present: the whole answer, in ingest order, line separated") {
        seed(store, "cmd-order", "agent-1", 1, "", "os_info", "", 600);
        const auto out = live::poll_live_output(store, "cmd-order", "agent-1", plugins, fast_limits(1), no_sleep);
        REQUIRE(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output == "proc|1|a|h|/p1\nproc|2|b|h|/p2");
    }
}

TEST_CASE("poll_live_output [pg]: a stored answer over the byte cap is cut by the bounded read", "[live][poll][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());

    for (int i = 0; i < 5; ++i)
        seed(store, "cmd-big", "agent-1", i == 4 ? 1 : 0, std::string(100, 'a' + i) + "\n");

    auto limits = fast_limits(1);
    limits.max_output_bytes = 250; // the newest rows are kept until the cap, the older ones are cut
    const auto* plugins = &yuzu::server::test::forensics_plugin_set();

    SECTION("refuse") {
        limits.over_cap = live::OverCapPolicy::kRefuse;
        CHECK(live::poll_live_output(store, "cmd-big", "agent-1", plugins, limits, no_sleep).outcome ==
              live::LiveOutcome::kOutputTooLarge);
    }
    SECTION("truncate: the surviving (newest) rows are returned, in id order, and flagged truncated") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        const auto out = live::poll_live_output(store, "cmd-big", "agent-1", plugins, limits, no_sleep);
        REQUIRE(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.truncated);
        // The two oldest rows ('a', 'b') were cut by the store; the three newest ('c', 'd', 'e')
        // joined to 305 bytes, over the cap, so the last whole line inside 250 bytes ends the answer.
        CHECK(out.output == std::string(100, 'c') + "\n" + std::string(100, 'd'));
    }
}

// The bounded read ranked rows by `timestamp DESC, id DESC`, so a terminal
// row stamped with an OLDER timestamp than the chunks before it (a clock step back) was the first
// row cut at the row limit or the byte cap, and the id-ordered reducer never saw it: a stored device
// failure was answered `ok` + `truncated`. The poll now ranks by id alone, so the newest row by id
// (the terminal row) is always kept.
TEST_CASE("poll_live_output [pg]: a terminal failure with an older timestamp than its chunks survives the cut",
          "[live][poll][pg][2146]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());
    const auto* plugins = &yuzu::server::test::forensics_plugin_set();

    SECTION("row limit: more than 64 chunk rows, the failing terminal row newest by id, oldest by timestamp") {
        for (int i = 0; i < live::kLivePollRowLimit + 6; ++i)
            seed(store, "cmd-step-rows", "agent-1", 0, "proc|" + std::to_string(i) + "|x\n", "os_info", "",
                 1000 + i);
        seed(store, "cmd-step-rows", "agent-1", 2, "", "os_info", "agent exploded", 500);

        auto limits = fast_limits(1);
        limits.over_cap = GENERATE(live::OverCapPolicy::kTruncateAtNewline, live::OverCapPolicy::kRefuse);
        const auto out = live::poll_live_output(store, "cmd-step-rows", "agent-1", plugins, limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kDeviceFailed);
        CHECK(out.detail == "agent exploded");
    }
    SECTION("byte cap: large chunks fill the cap, the failing terminal row is newest by id, oldest by timestamp") {
        for (int i = 0; i < 5; ++i)
            seed(store, "cmd-step-bytes", "agent-1", 0, std::string(100, 'a' + i) + "\n", "os_info", "",
                 1000 + i);
        seed(store, "cmd-step-bytes", "agent-1", 2, "", "os_info", "agent exploded", 500);

        auto limits = fast_limits(1);
        limits.max_output_bytes = 150;
        limits.over_cap = GENERATE(live::OverCapPolicy::kTruncateAtNewline, live::OverCapPolicy::kRefuse);
        const auto out = live::poll_live_output(store, "cmd-step-bytes", "agent-1", plugins, limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kDeviceFailed);
        CHECK(out.detail == "agent exploded");
    }
}

// The dominant failure shape: the terminal frame has no output, so the gateway/proxy ingest path
// finalizes the existing RUNNING chunk rows IN PLACE (every chunk row then carries the failure).
// Over the row limit the poll must still report the failure under the id ranking.
TEST_CASE("poll_live_output [pg]: chunks finalized in place as a failure answer device_failed over the row limit",
          "[live][poll][pg][2146]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());

    for (int i = 0; i < live::kLivePollRowLimit + 6; ++i)
        seed(store, "cmd-final", "agent-1", 0, "proc|" + std::to_string(i) + "|x\n", "os_info", "", 1000 + i);
    REQUIRE(store.finalize_terminal_status("cmd-final", "agent-1", 2, "agent exploded", "", 0) ==
            ResponseStore::FinalizeResult::Updated);

    auto limits = fast_limits(1);
    limits.over_cap = GENERATE(live::OverCapPolicy::kTruncateAtNewline, live::OverCapPolicy::kRefuse);
    const auto out = live::poll_live_output(store, "cmd-final", "agent-1",
                                            &yuzu::server::test::forensics_plugin_set(), limits, no_sleep);
    CHECK(out.outcome == live::LiveOutcome::kDeviceFailed);
    CHECK(out.detail == "agent exploded");
}

// G-UP-1: rows that reach the store AFTER the answer was decided (a late or redelivered chunk) must
// not hide it. The failure, the terminal row and an `error|` head chunk are read as facts over every
// permitted row, so the row limit and the byte cut cannot drop them.
TEST_CASE("poll_live_output [pg]: late chunks past the cut cannot hide a stored device failure",
          "[live][poll][pg][2146]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());
    const auto* plugins = &yuzu::server::test::forensics_plugin_set();

    SECTION("chunks finalized in place as a failure, then more than the row limit of late RUNNING rows") {
        for (int i = 0; i < 5; ++i)
            seed(store, "cmd-late-fail", "agent-1", 0, "proc|" + std::to_string(i) + "|x\n");
        REQUIRE(store.finalize_terminal_status("cmd-late-fail", "agent-1", 2, "agent exploded", "", 0) ==
                ResponseStore::FinalizeResult::Updated);
        for (int i = 0; i < live::kLivePollRowLimit + 6; ++i)
            seed(store, "cmd-late-fail", "agent-1", 0, "late|" + std::to_string(i) + "\n");

        auto limits = fast_limits(1);
        limits.over_cap = GENERATE(live::OverCapPolicy::kTruncateAtNewline, live::OverCapPolicy::kRefuse);
        const auto out = live::poll_live_output(store, "cmd-late-fail", "agent-1", plugins, limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kDeviceFailed);
        CHECK(out.detail == "agent exploded");
    }
    SECTION("a separately inserted failing terminal row, then more than the row limit of late RUNNING rows") {
        seed(store, "cmd-late-sep", "agent-1", 0, "proc|1|x\n");
        seed(store, "cmd-late-sep", "agent-1", 2, "", "os_info", "agent exploded");
        for (int i = 0; i < live::kLivePollRowLimit + 6; ++i)
            seed(store, "cmd-late-sep", "agent-1", 0, "late|" + std::to_string(i) + "\n");

        auto limits = fast_limits(1);
        limits.over_cap = GENERATE(live::OverCapPolicy::kTruncateAtNewline, live::OverCapPolicy::kRefuse);
        const auto out = live::poll_live_output(store, "cmd-late-sep", "agent-1", plugins, limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kDeviceFailed);
        CHECK(out.detail == "agent exploded");
    }
    SECTION("byte cap: large late chunks fill the cap after the failing row") {
        seed(store, "cmd-late-bytes", "agent-1", 2, "", "os_info", "agent exploded");
        for (int i = 0; i < 5; ++i)
            seed(store, "cmd-late-bytes", "agent-1", 0, std::string(100, 'a' + i) + "\n");

        auto limits = fast_limits(1);
        limits.max_output_bytes = 150;
        limits.over_cap = GENERATE(live::OverCapPolicy::kTruncateAtNewline, live::OverCapPolicy::kRefuse);
        const auto out = live::poll_live_output(store, "cmd-late-bytes", "agent-1", plugins, limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kDeviceFailed);
        CHECK(out.detail == "agent exploded");
    }
    SECTION("the NEWEST failing row's text wins, over a row the cut dropped") {
        seed(store, "cmd-two-fail", "agent-1", 2, "", "os_info", "first failure");
        seed(store, "cmd-two-fail", "agent-1", 2, "", "os_info", "second failure");
        for (int i = 0; i < live::kLivePollRowLimit + 6; ++i)
            seed(store, "cmd-two-fail", "agent-1", 0, "late|" + std::to_string(i) + "\n");

        const auto out = live::poll_live_output(store, "cmd-two-fail", "agent-1", plugins, fast_limits(1), no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kDeviceFailed);
        CHECK(out.detail == "second failure");
    }
}

TEST_CASE("poll_live_output [pg]: a terminal row or an error| head chunk the cut dropped still decides",
          "[live][poll][pg][2146]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());
    const auto* plugins = &yuzu::server::test::forensics_plugin_set();

    SECTION("a success terminal finalized in place, then late rows with NO output: decided, never a timeout") {
        // The late rows are empty, so the surviving rows are neither a partial answer nor a terminal row:
        // without the facts this poll reads nothing decisive and ends as a timeout.
        for (int i = 0; i < 3; ++i)
            seed(store, "cmd-late-ok", "agent-1", 0, "proc|" + std::to_string(i) + "|x\n");
        REQUIRE(store.finalize_terminal_status("cmd-late-ok", "agent-1", 1, "", "", 0) ==
                ResponseStore::FinalizeResult::Updated);
        for (int i = 0; i < live::kLivePollRowLimit + 6; ++i)
            seed(store, "cmd-late-ok", "agent-1", 0, "");

        auto limits = fast_limits(1);
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        const auto cut = live::poll_live_output(store, "cmd-late-ok", "agent-1", plugins, limits, no_sleep);
        CHECK(cut.outcome == live::LiveOutcome::kOk);
        CHECK(cut.truncated); // the head is missing, and the answer says so
        limits.over_cap = live::OverCapPolicy::kRefuse;
        const auto refused = live::poll_live_output(store, "cmd-late-ok", "agent-1", plugins, limits, no_sleep);
        CHECK(refused.outcome == live::LiveOutcome::kOutputTooLarge);
    }
    SECTION("an error| head chunk, then more than the row limit of RUNNING rows and NO terminal row") {
        seed(store, "cmd-head-err-open", "agent-1", 0, "error|device said no");
        for (int i = 0; i < live::kLivePollRowLimit + 6; ++i)
            seed(store, "cmd-head-err-open", "agent-1", 0, "later|" + std::to_string(i) + "\n");

        auto limits = fast_limits(1);
        limits.over_cap = GENERATE(live::OverCapPolicy::kTruncateAtNewline, live::OverCapPolicy::kRefuse);
        const auto out = live::poll_live_output(store, "cmd-head-err-open", "agent-1", plugins, limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kDeviceError);
        CHECK(out.detail == "device said no");
    }
    SECTION("an error| head chunk, then more than the row limit of later rows and a terminal row") {
        seed(store, "cmd-head-err", "agent-1", 0, "error|device said no");
        for (int i = 0; i < live::kLivePollRowLimit + 6; ++i)
            seed(store, "cmd-head-err", "agent-1", 0, "later|" + std::to_string(i) + "\n");
        seed(store, "cmd-head-err", "agent-1", 1, "");

        auto limits = fast_limits(1);
        limits.over_cap = GENERATE(live::OverCapPolicy::kTruncateAtNewline, live::OverCapPolicy::kRefuse);
        const auto out = live::poll_live_output(store, "cmd-head-err", "agent-1", plugins, limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kDeviceError);
        CHECK(out.detail == "device said no");
    }
    SECTION("a data head chunk is not turned into an error by a surviving error| line") {
        seed(store, "cmd-head-data", "agent-1", 0, "proc|1|a\n");
        for (int i = 0; i < live::kLivePollRowLimit + 6; ++i)
            seed(store, "cmd-head-data", "agent-1", 0, "error|row-" + std::to_string(i) + "\n");
        seed(store, "cmd-head-data", "agent-1", 1, "");

        auto limits = fast_limits(1);
        limits.over_cap = GENERATE(live::OverCapPolicy::kTruncateAtNewline, live::OverCapPolicy::kRefuse);
        const auto out = live::poll_live_output(store, "cmd-head-data", "agent-1", plugins, limits, no_sleep);
        if (limits.over_cap == live::OverCapPolicy::kRefuse) {
            CHECK(out.outcome == live::LiveOutcome::kOutputTooLarge); // never a device error
        } else {
            CHECK(out.outcome == live::LiveOutcome::kOk);
            CHECK(out.truncated);
        }
    }
}

// The facts ride the same WHERE as the rows: another agent's failure and a Forensics-tier failure
// must never reach any fact, however new, and the cut never changes them.
TEST_CASE("ResponseStore::query_bounded [pg]: decision facts cover every permitted row, only the permitted rows",
          "[live][poll][pg][2146]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());

    const auto tier = ResponseTierFilter::for_fixed_plugin_poll(&yuzu::server::test::forensics_plugin_set());
    ResponseQuery q;
    q.agent_id = "agent-1";
    q.order_by_id = true;
    q.limit = 1; // the cut keeps ONE row; the facts must still see the rest

    SECTION("a failure the cut dropped, the head chunk, and the newest failure's text") {
        seed(store, "cmd-facts", "agent-1", 0, "head|chunk\n");
        seed(store, "cmd-facts", "agent-1", 2, "", "os_info", "older failure");
        seed(store, "cmd-facts", "agent-1", 2, "", "os_info", std::string(400, 'f'));
        seed(store, "cmd-facts", "agent-1", 0, "late\n");

        q.with_decision_facts = true;
        const auto got = store.query_bounded("cmd-facts", tier, q, std::nullopt, 1u << 20);
        REQUIRE(got.has_value());
        REQUIRE(got->rows.size() == 1);
        CHECK(got->rows[0].output == "late\n"); // the cut kept only the newest row
        CHECK(got->row_cap_hit);
        REQUIRE(got->facts.has_value());
        CHECK(got->facts->any_failed);
        CHECK(got->facts->any_terminal);
        CHECK(got->facts->failed_detail == std::string(kBoundedFactsTextChars, 'f')); // newest failure, cut
        CHECK(got->facts->head_output == "head|chunk\n"); // oldest non-empty output
    }
    SECTION("the head is the oldest NON-EMPTY output") {
        seed(store, "cmd-facts-empty", "agent-1", 0, "");
        seed(store, "cmd-facts-empty", "agent-1", 0, "second\n");
        seed(store, "cmd-facts-empty", "agent-1", 0, "third\n");
        q.with_decision_facts = true;
        const auto got = store.query_bounded("cmd-facts-empty", tier, q, std::nullopt, 1u << 20);
        REQUIRE(got.has_value());
        REQUIRE(got->facts.has_value());
        CHECK(got->facts->head_output == "second\n");
        CHECK_FALSE(got->facts->any_failed);
        CHECK_FALSE(got->facts->any_terminal);
        CHECK(got->facts->failed_detail.empty());
    }
    SECTION("another agent's failure and a Forensics-tier failure reach no fact") {
        // The withheld rows hold the LOWEST ids, so an unscoped head (the oldest row with output) would
        // be one of them.
        seed(store, "cmd-facts-vis", "agent-2", 0, "error|foreign secret\n");
        seed(store, "cmd-facts-vis", "agent-1", 0, "error|forensics secret\n", yuzu::server::test::kForensicsPlugin);
        seed(store, "cmd-facts-vis", "agent-1", 0, "mine\n");
        seed(store, "cmd-facts-vis", "agent-2", 2, "", "os_info", "foreign failure");
        seed(store, "cmd-facts-vis", "agent-1", 2, "", yuzu::server::test::kForensicsPlugin, "secret failure");
        seed(store, "cmd-facts-vis", "agent-2", 1, "foreign head\n");
        q.with_decision_facts = true;
        const auto got = store.query_bounded("cmd-facts-vis", tier, q, std::nullopt, 1u << 20);
        REQUIRE(got.has_value());
        REQUIRE(got->facts.has_value());
        CHECK_FALSE(got->facts->any_failed);
        CHECK_FALSE(got->facts->any_terminal);
        CHECK(got->facts->failed_detail.empty());
        CHECK(got->facts->head_output == "mine\n");
        CHECK_FALSE(got->row_cap_hit); // the withheld rows set no cap flag either
    }
    SECTION("an unwired plugin set (every row refused): facts are present and empty") {
        seed(store, "cmd-facts-unwired", "agent-1", 2, "x\n", "os_info", "boom");
        const auto refused = ResponseTierFilter::for_fixed_plugin_poll(nullptr);
        q.with_decision_facts = true;
        const auto got = store.query_bounded("cmd-facts-unwired", refused, q, std::nullopt, 1u << 20);
        REQUIRE(got.has_value());
        CHECK(got->rows.empty());
        REQUIRE(got->facts.has_value());
        CHECK_FALSE(got->facts->any_failed);
        CHECK_FALSE(got->facts->any_terminal);
        CHECK(got->facts->head_output.empty());
    }
    SECTION("an empty agent_id would span every agent: no facts are returned") {
        seed(store, "cmd-facts-noagent", "agent-2", 2, "", "os_info", "foreign failure");
        q.agent_id.clear();
        q.with_decision_facts = true;
        const auto got = store.query_bounded("cmd-facts-noagent", tier, q, std::nullopt, 1u << 20);
        REQUIRE(got.has_value());
        CHECK_FALSE(got->facts.has_value());
    }
    SECTION("the cut is in characters: 300 two-byte characters cut to 256, no character split") {
        // left() counts characters only in a UTF8 database; a SQL_ASCII cluster would count bytes.
        {
            auto lease = pool.acquire();
            REQUIRE(lease);
            pg::PgResult enc{PQexec(lease.get(), "SHOW server_encoding")};
            if (enc.status() != PGRES_TUPLES_OK || std::string(PQgetvalue(enc.get(), 0, 0)) != "UTF8")
                SKIP("the test database is not UTF8");
        }
        std::string text;
        for (int i = 0; i < 300; ++i)
            text += "\xC3\xA9";
        seed(store, "cmd-facts-mb", "agent-1", 2, text, "os_info", text);
        q.with_decision_facts = true;
        const auto got = store.query_bounded("cmd-facts-mb", tier, q, std::nullopt, 1u << 20);
        REQUIRE(got.has_value());
        REQUIRE(got->facts.has_value());
        CHECK(got->facts->failed_detail.size() == 2u * kBoundedFactsTextChars);
        CHECK(got->facts->head_output.size() == 2u * kBoundedFactsTextChars);
        CHECK(got->facts->failed_detail == text.substr(0, 2u * kBoundedFactsTextChars));
    }
        SECTION("a status filter narrows the facts as it narrows the rows") {
        seed(store, "cmd-facts-filter", "agent-1", 0, "head|chunk\n");
        seed(store, "cmd-facts-filter", "agent-1", 2, "", "os_info", "boom");
        q.with_decision_facts = true;
        q.status = 2;
        const auto got = store.query_bounded("cmd-facts-filter", tier, q, std::nullopt, 1u << 20);
        REQUIRE(got.has_value());
        REQUIRE(got->facts.has_value());
        CHECK(got->rows.size() == 1);
        CHECK(got->facts->any_failed);
        CHECK(got->facts->failed_detail == "boom");
        CHECK(got->facts->head_output.empty()); // the status filter left the head row out of the facts too
    }
    SECTION("a since and until window narrows the facts as it narrows the rows") {
        seed(store, "cmd-facts-window", "agent-1", 2, "old|head\n", "os_info", "old failure", 100);
        seed(store, "cmd-facts-window", "agent-1", 2, "mid|head\n", "os_info", "mid failure", 200);
        seed(store, "cmd-facts-window", "agent-1", 2, "new|head\n", "os_info", "new failure", 300);
        q.with_decision_facts = true;
        q.since = 150;
        q.until = 250;
        const auto got = store.query_bounded("cmd-facts-window", tier, q, std::nullopt, 1u << 20);
        REQUIRE(got.has_value());
        REQUIRE(got->facts.has_value());
        CHECK(got->rows.size() == 1);
        CHECK(got->facts->failed_detail == "mid failure");
        CHECK(got->facts->head_output == "mid|head\n"); // neither the older nor the newer row reaches a fact
    }
    SECTION("a status outside 0..4: >= 1 is terminal, >= 2 a failure, a negative status neither") {
        seed(store, "cmd-facts-neg", "agent-1", -1, "x\n");
        q.with_decision_facts = true;
        const auto neg = store.query_bounded("cmd-facts-neg", tier, q, std::nullopt, 1u << 20);
        REQUIRE(neg.has_value());
        REQUIRE(neg->facts.has_value());
        CHECK_FALSE(neg->facts->any_terminal);
        CHECK_FALSE(neg->facts->any_failed);
        seed(store, "cmd-facts-big", "agent-1", 99, "x\n", "os_info", "odd status");
        const auto big = store.query_bounded("cmd-facts-big", tier, q, std::nullopt, 1u << 20);
        REQUIRE(big.has_value());
        REQUIRE(big->facts.has_value());
        CHECK(big->facts->any_terminal);
        CHECK(big->facts->any_failed);
    }
    SECTION("a single success row: terminal, not failed") {
        seed(store, "cmd-facts-ok", "agent-1", 1, "x\n");
        q.with_decision_facts = true;
        const auto got = store.query_bounded("cmd-facts-ok", tier, q, std::nullopt, 1u << 20);
        REQUIRE(got.has_value());
        REQUIRE(got->facts.has_value());
        CHECK(got->facts->any_terminal);
        CHECK_FALSE(got->facts->any_failed);
    }
    SECTION("no rows: facts are present and empty") {
        q.with_decision_facts = true;
        const auto got = store.query_bounded("cmd-facts-none", tier, q, std::nullopt, 1u << 20);
        REQUIRE(got.has_value());
        REQUIRE(got->facts.has_value());
        CHECK_FALSE(got->facts->any_failed);
        CHECK(got->facts->head_output.empty());
    }
    SECTION("not requested: no facts, and the rows are unchanged") {
        seed(store, "cmd-facts-off", "agent-1", 2, "", "os_info", "boom");
        const auto got = store.query_bounded("cmd-facts-off", tier, q, std::nullopt, 1u << 20);
        REQUIRE(got.has_value());
        CHECK_FALSE(got->facts.has_value());
        CHECK(got->rows.size() == 1);
    }
}

TEST_CASE("ResponseStore::query_bounded [pg]: order_by_id ranks by id alone, the default still ranks by timestamp",
          "[live][poll][pg][2146]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());

    // Row 1 has the NEWEST timestamp, row 3 the newest id and the oldest timestamp.
    seed(store, "cmd-rank", "agent-1", 0, "one", "os_info", "", 3000);
    seed(store, "cmd-rank", "agent-1", 0, "two", "os_info", "", 2000);
    seed(store, "cmd-rank", "agent-1", 1, "three", "os_info", "", 1000);

    const auto tier = ResponseTierFilter::for_fixed_plugin_poll(&yuzu::server::test::forensics_plugin_set());
    ResponseQuery q;
    q.agent_id = "agent-1";
    q.limit = 2; // one row short of the three, so the cut decides which survive

    q.order_by_id = false;
    const auto by_ts = store.query_bounded("cmd-rank", tier, q, std::nullopt, 1u << 20);
    REQUIRE(by_ts.has_value());
    REQUIRE(by_ts->rows.size() == 2);
    CHECK(by_ts->rows[0].output == "one"); // newest timestamp first: the terminal row is the one cut
    CHECK(by_ts->rows[1].output == "two");
    CHECK(by_ts->row_cap_hit);

    q.order_by_id = true;
    const auto by_id = store.query_bounded("cmd-rank", tier, q, std::nullopt, 1u << 20);
    REQUIRE(by_id.has_value());
    REQUIRE(by_id->rows.size() == 2);
    CHECK(by_id->rows[0].output == "three"); // newest id first: the terminal row survives
    CHECK(by_id->rows[1].output == "two");
    CHECK(by_id->row_cap_hit);
}

// The id ranking must not widen what is visible: the agent scope and the Forensics tier stay in the
// WHERE clause, ahead of the limit and the cut. Newer-id rows that are filtered out must neither
// displace a permitted row nor set a cap flag.
TEST_CASE("ResponseStore::query_bounded [pg]: order_by_id keeps the scope and tier filters ahead of the cut",
          "[live][poll][pg][2146]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());

    seed(store, "cmd-vis", "agent-1", 0, "first", "os_info", "", 100);
    seed(store, "cmd-vis", "agent-1", 1, "second", "os_info", "", 200);
    // Newer ids that must stay invisible: another agent's row and a Forensics-tier row.
    seed(store, "cmd-vis", "agent-2", 1, "foreign", "os_info", "", 300);
    seed(store, "cmd-vis", "agent-1", 1, "secret", yuzu::server::test::kForensicsPlugin, "", 400);

    const auto tier = ResponseTierFilter::for_fixed_plugin_poll(&yuzu::server::test::forensics_plugin_set());
    ResponseQuery q;
    q.agent_id = "agent-1";
    q.order_by_id = true;
    q.limit = 2; // exactly the two permitted rows: no row cap may be reported

    const auto got = store.query_bounded("cmd-vis", tier, q, std::nullopt, 1u << 20);
    REQUIRE(got.has_value());
    REQUIRE(got->rows.size() == 2);
    CHECK(got->rows[0].output == "second");
    CHECK(got->rows[1].output == "first");
    CHECK_FALSE(got->row_cap_hit);
    CHECK_FALSE(got->byte_cap_hit);

    // The byte cut under id ranking: a row is kept while the bytes BEFORE it are under the cap, so
    // a cap of 6 keeps the newest row ("second", 6 bytes) and cuts the older one, and the first row
    // is always kept even when it alone exceeds the cap (cap 1).
    const auto cut = store.query_bounded("cmd-vis", tier, q, std::nullopt, 6);
    REQUIRE(cut.has_value());
    REQUIRE(cut->rows.size() == 1);
    CHECK(cut->rows[0].output == "second");
    CHECK(cut->byte_cap_hit);
    const auto tiny = store.query_bounded("cmd-vis", tier, q, std::nullopt, 1);
    REQUIRE(tiny.has_value());
    REQUIRE(tiny->rows.size() == 1);
    CHECK(tiny->rows[0].output == "second");
}

TEST_CASE("live_read_timeout_retry_ms: processes is priced at the plugin's action budget, other kinds at 3 s",
          "[live][retry][2146]") {
    namespace mcp = yuzu::server::mcp;
    CHECK(mcp::live_read_timeout_retry_ms("uptime") == mcp::kMcpLiveReadDeviceTimeoutRetryMs);
    CHECK(mcp::live_read_timeout_retry_ms("uptime") == 3000);
    CHECK(mcp::live_read_timeout_retry_ms("processes") == mcp::kLiveReadProcessesTimeoutRetryMs);
    // The processes plugin's own action budget (`kActionBudget`, processes_plugin.cpp) is 120 s; a
    // retry sooner than that can land inside the first run's hashing.
    CHECK(mcp::kLiveReadProcessesTimeoutRetryMs == 120000);
    // An unresolved token never reaches the hint, but the default must be the short quick-kind price.
    CHECK(mcp::live_read_timeout_retry_ms("") == mcp::kMcpLiveReadDeviceTimeoutRetryMs);
}

TEST_CASE("live_read_incomplete_retry_ms: processes is priced at its run budget, other kinds at the poll deadline",
          "[live][retry][2146]") {
    namespace mcp = yuzu::server::mcp;
    CHECK(mcp::live_read_incomplete_retry_ms("uptime") == mcp::kLiveReadIncompleteRetryMs);
    CHECK(mcp::live_read_incomplete_retry_ms("uptime") == 25000);
    CHECK(mcp::live_read_incomplete_retry_ms("processes") == mcp::kLiveReadProcessesTimeoutRetryMs);
    CHECK(mcp::live_read_incomplete_retry_ms("") == mcp::kLiveReadIncompleteRetryMs);
    // A processes read that finished its first run is never told to retry sooner than a read that
    // sent nothing at all: the two hints agree for it.
    CHECK(mcp::live_read_incomplete_retry_ms("processes") == mcp::live_read_timeout_retry_ms("processes"));
}

// S3: the helper the REST and MCP error text goes through. Invalid bytes cannot reach those sites
// through the response store (it scrubs at ingest), so this pins the helper itself: repair first,
// THEN cut, so the bound holds after U+FFFD (3 bytes) replaces a 1-byte fault.
TEST_CASE("utf8_clean_clamp: invalid bytes become U+FFFD, then the text is cut within the bound at a "
          "character boundary",
          "[live][utf8][2146]") {
    using yuzu::server::utf8_clean_clamp;
    // Valid text that fits is returned unchanged.
    CHECK(utf8_clean_clamp("plain", 200) == "plain");
    CHECK(utf8_clean_clamp("caf\xc3\xa9", 200) == "caf\xc3\xa9");
    // A lone invalid byte is replaced by U+FFFD (EF BF BD).
    CHECK(utf8_clean_clamp("a\xff" "b", 200) == "a\xef\xbf\xbd" "b");
    // An orphan lead byte at the end is repaired too.
    CHECK(utf8_clean_clamp("ok\xc3", 200) == "ok\xef\xbf\xbd");
    // Sanitise BEFORE clamp: ten faults become 30 bytes, and the bound still holds, on a boundary.
    const std::string faults(10, '\xff');
    const auto cut = utf8_clean_clamp(faults, 7);
    CHECK(cut.size() <= 7);
    CHECK(cut == "\xef\xbf\xbd\xef\xbf\xbd"); // two whole replacement characters, never a third partial one
    // A valid multi-byte character straddling the bound is dropped whole.
    CHECK(utf8_clean_clamp(std::string(199, 'a') + "\xc3\xa9\xc3\xa9", 200) == std::string(199, 'a'));
    // A zero bound is empty.
    CHECK(utf8_clean_clamp("abc", 0).empty());
}
