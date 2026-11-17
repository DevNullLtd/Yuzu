/**
 * test_echo_open_retry.cpp -- #7290: Echo loads offline when its database cannot be opened and
 * retries in the background. The pure pieces: the back-off schedule, the per-attempt v10
 * migration deadline, the classification of an open failure into an offline reason, the status
 * lines, and the stoppable retry loop.
 *
 * Nothing here sleeps or polls: the loop is driven with a zero delay and waited on through
 * futures, and the long-delay and blocked-attempt cases are woken by stop().
 */

#include "echo_open_retry.hpp"
#include "echo_status_format.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::echo;
using namespace std::chrono_literals;

namespace {
// Generous: only a hang would reach it; every wait below is released by the code under test.
constexpr auto kBound = 30s;
} // namespace

TEST_CASE("open_retry_delay: 1, 5 and 15 minutes, then hourly for ever", "[echo][open_retry]") {
    CHECK(open_retry_delay(1) == 60s);
    CHECK(open_retry_delay(2) == 300s);
    CHECK(open_retry_delay(3) == 900s);
    CHECK(open_retry_delay(4) == 3600s);
    CHECK(open_retry_delay(1000) == 3600s);
}

TEST_CASE("v10_migration_deadline: 60 s plus 2 s per MiB, doubled per deadline hit, capped at an hour",
          "[echo][open_retry]") {
    constexpr std::int64_t kMiB = 1024 * 1024;
    CHECK(v10_migration_deadline(0) == 60s);
    CHECK(v10_migration_deadline(-5) == 60s); // a negative size counts as 0
    CHECK(v10_migration_deadline(100 * kMiB) == 260s);
    // the one measured migration (55 s on a 242 MB file) fits inside the first attempt's bound
    CHECK(v10_migration_deadline(242'000'000) > 55s);
    CHECK(v10_migration_deadline(242'000'000) == 60s + 2s * (242'000'000 / kMiB));
    CHECK(v10_migration_deadline(100'000 * kMiB) == 3600s); // a huge file hits the cap
    // each earlier attempt that ended on the deadline doubles the next one, up to the cap
    CHECK(v10_migration_deadline(100 * kMiB, 1) == 520s);
    CHECK(v10_migration_deadline(100 * kMiB, 2) == 1040s);
    CHECK(v10_migration_deadline(100 * kMiB, 3) == 2080s);
    CHECK(v10_migration_deadline(100 * kMiB, 4) == 3600s);
    CHECK(v10_migration_deadline(100 * kMiB, 50) == 3600s);
}

TEST_CASE("classify_open_failure: only the free-space and v10 migration failures are retried",
          "[echo][open_retry]") {
    const std::string free_space =
        "v10 roll-up migration failed (the schema stays at v9; the retired tables are intact): "
        "not enough free disk space to migrate the Echo database to its roll-up tables: 10 bytes are free";
    CHECK(classify_open_failure(free_space) == OfflineReason::free_space); // nested in the wrapper
    CHECK(classify_open_failure("v10 roll-up migration failed (the schema stays at v9; the retired "
                                "tables are intact): daily bucket out of range") ==
          OfflineReason::migration_failed);
    CHECK(classify_open_failure("schema v8: an earlier migration step did not finish (see the log); "
                                "the roll-up step waits for it and the next open retries both") ==
          OfflineReason::migration_failed);
    // every other open failure stays a plugin init failure
    CHECK(classify_open_failure("failed to open echo.db: unable to open database file") == OfflineReason::none);
    CHECK(classify_open_failure("echo.db is a symbolic link; refusing to open it") == OfflineReason::none);
    CHECK(classify_open_failure("echo.db is corrupt and could not be moved aside") == OfflineReason::none);
    CHECK(classify_open_failure("") == OfflineReason::none);
}

TEST_CASE("retry_failure_reason: a failure on a retry is never 'none', it falls back to open_failed",
          "[echo][open_retry]") {
    // the classified kinds keep their reason ...
    CHECK(retry_failure_reason("v10 roll-up migration failed (the schema stays at v9; the retired tables "
                               "are intact): not enough free disk space to migrate the Echo database") ==
          OfflineReason::free_space);
    CHECK(retry_failure_reason("v10 roll-up migration failed (the schema stays at v9; the retired tables "
                               "are intact): daily bucket out of range") == OfflineReason::migration_failed);
    CHECK(retry_failure_reason("schema v8: an earlier migration step did not finish (see the log)") ==
          OfflineReason::migration_failed);
    // ... and any other failure (which fails a first open outright) stays offline as open_failed
    CHECK(retry_failure_reason("failed to open echo.db: unable to open database file") == OfflineReason::open_failed);
    CHECK(retry_failure_reason("echo.db is a symbolic link; refusing to open it") == OfflineReason::open_failed);
    CHECK(retry_failure_reason("") == OfflineReason::open_failed);
}

TEST_CASE("is_deadline_hit: only a migration that ran into its deadline counts, not a shutdown cancel",
          "[echo][open_retry]") {
    // The producer's own wording is pinned against the real text in test_echo_v10_migration.cpp.
    CHECK(is_deadline_hit("v10 roll-up migration failed (the schema stays at v9; the retired tables are "
                          "intact): the migration did not finish inside its 60 s deadline and was rolled back"));
    CHECK_FALSE(is_deadline_hit("v10 roll-up migration failed (the schema stays at v9; the retired tables are "
                                "intact): the migration was cancelled by shutdown and rolled back"));
    CHECK_FALSE(is_deadline_hit("v10 roll-up migration failed: daily bucket out of range"));
    CHECK_FALSE(is_deadline_hit(""));
}

TEST_CASE("free_space_still_short: the retry skips the open until twice the file plus the log is free",
          "[echo][open_retry]") {
    constexpr std::uintmax_t kFile = 1000;
    constexpr std::uintmax_t kWal = 300;
    constexpr std::uintmax_t kNeed = 2 * kFile + kWal;
    CHECK(free_space_still_short(kNeed - 1, kFile, kWal)); // one byte under is short
    CHECK_FALSE(free_space_still_short(kNeed, kFile, kWal)); // exactly enough is not short
    CHECK_FALSE(free_space_still_short(kNeed + 1, kFile, kWal));
    // the log counts: the same free space is enough without it and short with it
    CHECK_FALSE(free_space_still_short(2 * kFile, kFile, 0));
    CHECK(free_space_still_short(2 * kFile, kFile, 1));
    // an empty file with no log needs nothing
    CHECK_FALSE(free_space_still_short(0, 0, 0));
}

TEST_CASE("offline_reason_token: the literals the server's gauge parser mirrors", "[echo][open_retry]") {
    CHECK(offline_reason_token(OfflineReason::free_space) == "free_space");
    CHECK(offline_reason_token(OfflineReason::migration_failed) == "migration_failed");
    CHECK(offline_reason_token(OfflineReason::open_failed) == "open_failed");
    CHECK(offline_reason_token(OfflineReason::none).empty());
    CHECK(kStorageOfflineKey == "heartbeat.storage_offline");
}

TEST_CASE("format_storage_refused_lines: error| first, then the reason token, with the retry wait",
          "[echo][open_retry]") {
    for (const auto reason : {OfflineReason::free_space, OfflineReason::migration_failed,
                              OfflineReason::open_failed}) {
        const auto lines = format_storage_refused_lines(reason, "the detail", 90s);
        REQUIRE(lines.size() == 2);
        CHECK(lines[0].starts_with("error|")); // the server gates on a leading error|
        CHECK(lines[0].find("the detail") != std::string::npos);
        CHECK(lines[0].find("in about 90 s") != std::string::npos);
        CHECK(lines[1] == std::string{"storage_state|offline|"} + std::string{offline_reason_token(reason)});
    }
    CHECK(format_storage_refused_lines(OfflineReason::free_space, "d", 0s)[1] == "storage_state|offline|free_space");
    CHECK(format_storage_refused_lines(OfflineReason::migration_failed, "d", 0s)[1] ==
          "storage_state|offline|migration_failed");
    CHECK(format_storage_refused_lines(OfflineReason::open_failed, "d", 0s)[1] == "storage_state|offline|open_failed");
}

TEST_CASE("format_storage_refused_lines: a wait of zero or less reads 'Retrying now', never a number",
          "[echo][open_retry]") {
    for (const auto wait : {0s, -5s}) {
        const auto lines = format_storage_refused_lines(OfflineReason::migration_failed, "d", wait);
        CHECK(lines[0].find("Retrying now.") != std::string::npos);
        CHECK(lines[0].find("in about") == std::string::npos);
        CHECK(lines[0].find('-') == std::string::npos);
    }
}

TEST_CASE("format_storage_refused_lines: no scheduled retry asks for a restart and never promises one",
          "[echo][open_retry]") {
    const auto lines = format_storage_refused_lines(OfflineReason::open_failed, "collection start failed: boom",
                                                    std::nullopt);
    REQUIRE(lines.size() == 2);
    CHECK(lines[0].starts_with("error|")); // the server gates on a leading error|
    CHECK(lines[0].find("collection start failed: boom") != std::string::npos);
    CHECK(lines[0].find("restart the agent") != std::string::npos);
    CHECK(lines[0].find("retried automatically") == std::string::npos);
    CHECK(lines[0].find("next attempt") == std::string::npos);
    CHECK(lines[0].find("Retrying now") == std::string::npos);
    CHECK(lines[1] == "storage_state|offline|open_failed"); // the tag is unchanged
}

TEST_CASE("OpenRetryLoop: attempts run after each back-off until one succeeds",
          "[echo][open_retry]") {
    OpenRetryLoop loop;
    std::vector<unsigned> delays_asked;
    std::vector<unsigned> attempts_seen;
    std::promise<void> done;
    auto finished = done.get_future();
    loop.start(
        [&](unsigned attempt, const std::function<bool()>&) {
            attempts_seen.push_back(attempt);
            if (attempt < 4)
                return false;
            done.set_value();
            return true;
        },
        [&](unsigned failed) {
            delays_asked.push_back(failed);
            return std::chrono::milliseconds{0};
        },
        /*initial_failures=*/1);
    REQUIRE(finished.wait_for(kBound) == std::future_status::ready);
    loop.stop(); // joins; the thread ended on its own after the success
    // init's own try counts as failed attempt 1, so the first retry is attempt 2
    CHECK(attempts_seen == std::vector<unsigned>{2, 3, 4});
    CHECK(delays_asked == std::vector<unsigned>{1, 2, 3});
}

TEST_CASE("OpenRetryLoop: stop() during a long back-off returns without running an attempt",
          "[echo][open_retry]") {
    OpenRetryLoop loop;
    std::atomic<int> attempts{0};
    loop.start(
        [&](unsigned, const std::function<bool()>&) {
            ++attempts;
            return true;
        },
        [](unsigned) { return std::chrono::milliseconds{std::chrono::hours{1}}; });
    auto stopped = std::async(std::launch::async, [&] { loop.stop(); });
    REQUIRE(stopped.wait_for(kBound) == std::future_status::ready);
    CHECK(attempts.load() == 0);
    loop.stop(); // idempotent
}

TEST_CASE("OpenRetryLoop: stop() cancels an attempt that is blocked on cancelled()",
          "[echo][open_retry]") {
    OpenRetryLoop loop;
    std::promise<void> entered;
    auto in_attempt = entered.get_future();
    std::atomic<int> attempts{0};
    std::atomic<bool> saw_cancel{false};
    loop.start(
        [&](unsigned, const std::function<bool()>& cancelled) {
            ++attempts;
            entered.set_value();
            while (!cancelled()) {
                std::this_thread::yield(); // a stand-in for the migration's progress-handler poll
            }
            saw_cancel = true;
            return false; // would be retried, but the loop is stopped
        },
        [](unsigned) { return std::chrono::milliseconds{0}; });
    REQUIRE(in_attempt.wait_for(kBound) == std::future_status::ready);
    auto stopped = std::async(std::launch::async, [&] { loop.stop(); });
    REQUIRE(stopped.wait_for(kBound) == std::future_status::ready);
    CHECK(saw_cancel.load());
    CHECK(attempts.load() == 1); // no attempt after the cancel
}

TEST_CASE("OpenRetryLoop: an attempt that throws counts as failed and the loop carries on",
          "[echo][open_retry]") {
    OpenRetryLoop loop;
    std::promise<void> done;
    auto finished = done.get_future();
    std::atomic<int> calls{0};
    loop.start(
        [&](unsigned, const std::function<bool()>&) -> bool {
            if (++calls == 1)
                throw std::runtime_error("boom");
            done.set_value();
            return true;
        },
        [](unsigned) { return std::chrono::milliseconds{0}; });
    REQUIRE(finished.wait_for(kBound) == std::future_status::ready);
    loop.stop();
    CHECK(calls.load() == 2);
}

TEST_CASE("OpenRetryLoop: with the default back-off the first attempt is a minute away and stop() ends the wait",
          "[echo][open_retry]") {
    OpenRetryLoop loop;
    std::atomic<int> attempts{0};
    loop.start([&](unsigned, const std::function<bool()>&) {
        ++attempts;
        return true;
    });
    auto stopped = std::async(std::launch::async, [&] { loop.stop(); });
    REQUIRE(stopped.wait_for(kBound) == std::future_status::ready);
    CHECK(attempts.load() == 0);
}
