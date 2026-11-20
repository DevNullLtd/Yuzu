// proc_stat.hpp: a recycled pid is detected by the process start time (field 22 of /proc/<pid>/stat),
// so a processes row never pairs one process's name with another's image hash.

#include "proc_stat.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#if defined(__linux__)
#include <fstream>
#include <unistd.h>
#endif

using yuzu::shared::classify_pid;
using yuzu::shared::is_sha256_digest;
using yuzu::shared::parse_stat_start_ticks;
using yuzu::shared::PidState;
using yuzu::shared::same_process;
using yuzu::shared::settle_row_for;

TEST_CASE("parse_stat_start_ticks: field 22, command names with spaces and parentheses",
          "[proc_stat][processes]") {
    // pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime
    // cutime cstime priority nice threads itrealvalue starttime ...
    CHECK(parse_stat_start_ticks("1 (init) S 0 1 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 12345 999 8 18446744073709551615") == 12345u);
    CHECK(parse_stat_start_ticks("42 (my (odd) name) R 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 987654321 1 1") == 987654321u);
    CHECK(parse_stat_start_ticks("7 (a b) S 1 7 7 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 0") == 5u);
    CHECK_FALSE(parse_stat_start_ticks("").has_value());
    CHECK_FALSE(parse_stat_start_ticks("no parens").has_value());
    CHECK_FALSE(parse_stat_start_ticks("1 (x) S 0 1").has_value());                      // too few fields
    CHECK_FALSE(parse_stat_start_ticks("1 (x) S 0 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 abc 1").has_value());
}

TEST_CASE("same_process: only an equal, known start time keeps a row", "[proc_stat][processes]") {
    CHECK(same_process(100u, 100u));
    CHECK_FALSE(same_process(100u, 101u)); // a recycled pid
    CHECK_FALSE(same_process(std::nullopt, 100u));
    CHECK_FALSE(same_process(100u, std::nullopt));
    CHECK_FALSE(same_process(std::nullopt, std::nullopt)); // unknown fails closed
}

TEST_CASE("parse_stat_start_ticks: a start time above 2^64 - 1 is refused, never wrapped",
          "[proc_stat][processes]") {
    auto line = [](const std::string& ticks) {
        return "1 (x) S 0 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 " + ticks + " 1 1";
    };
    CHECK(parse_stat_start_ticks(line("18446744073709551615")) == 18446744073709551615ull); // 2^64 - 1
    CHECK_FALSE(parse_stat_start_ticks(line("18446744073709551616")).has_value());          // 2^64 would wrap to 0
    CHECK_FALSE(parse_stat_start_ticks(line("36893488147419103232")).has_value());          // 2^65
    CHECK_FALSE(parse_stat_start_ticks(line("000000000000000000001")).has_value());          // 21 digits
}

TEST_CASE("classify_pid: same, recycled, or exited", "[proc_stat][processes]") {
    CHECK(classify_pid(5u, 5u) == PidState::Same);
    CHECK(classify_pid(5u, 6u) == PidState::Reused);
    CHECK(classify_pid(std::nullopt, 6u) == PidState::Unverified); // first reading unknown: not claimed reused
    CHECK(classify_pid(5u, std::nullopt) == PidState::Exited);
    CHECK(classify_pid(std::nullopt, std::nullopt) == PidState::Exited);
}

TEST_CASE("settle_row_for: only a real digest is converted, a marker keeps its own reading",
          "[proc_stat][processes]") {
    const std::string digest(64, 'a');
    CHECK_FALSE(settle_row_for(PidState::Same, digest).drop_path);
    CHECK(settle_row_for(PidState::Same, digest).hash_cause.empty());

    const auto reused = settle_row_for(PidState::Reused, digest);
    CHECK(reused.drop_path);
    CHECK(reused.hash_cause == "pid_reused");
    const auto unverified = settle_row_for(PidState::Unverified, digest);
    CHECK(unverified.drop_path);
    CHECK(unverified.hash_cause == "pid_unverified"); // never labelled a recycled pid
    const auto exited = settle_row_for(PidState::Exited, digest);
    CHECK(exited.drop_path);
    CHECK(exited.hash_cause == "pid_exited"); // a process that legitimately exited is its own token

    for (const char* marker : {"hash_unavailable:timeout", "hash_unavailable:skipped", ""}) {
        const auto r = settle_row_for(PidState::Reused, marker);
        CHECK(r.drop_path);              // the path may be another process's: always dropped
        CHECK(r.hash_cause.empty());     // but the existing marker is never overwritten
    }
    CHECK_FALSE(is_sha256_digest(std::string(63, 'a')));
    CHECK_FALSE(is_sha256_digest(std::string(64, 'A'))); // lowercase hex only
    CHECK_FALSE(is_sha256_digest(std::string(64, 'g')));
}

#if defined(__linux__)
TEST_CASE("parse_stat_start_ticks: this process's own /proc/self/stat parses and is stable",
          "[proc_stat][processes][linux]") {
    auto read = [] {
        std::ifstream f("/proc/self/stat");
        std::string line;
        std::getline(f, line);
        return parse_stat_start_ticks(line);
    };
    const auto a = read();
    REQUIRE(a.has_value());
    CHECK(same_process(a, read()));
}
#endif
