// proc_stat.hpp: a recycled pid is detected by the process start time (field 22 of /proc/<pid>/stat),
// so a processes row never pairs one process's name with another's image hash.

#include "proc_stat.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#if defined(__linux__)
#include <fstream>
#include <unistd.h>
#endif

using yuzu::shared::parse_stat_start_ticks;
using yuzu::shared::same_process;

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
