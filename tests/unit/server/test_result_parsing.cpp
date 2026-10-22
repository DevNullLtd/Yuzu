/**
 * test_result_parsing.cpp — pins the `interaction` plugin's registration in
 * result_parsing.hpp's kKeyValuePlugins (macOS parity 1.3).
 *
 * Before this registration, `interaction` fell to the generic 2-name
 * {Agent, Output} default schema while its rows are key|value shaped
 * (`status|not_reachable`, `response|ok`, ...) — split_fields() still split
 * on every pipe, so a 2-field row landed under a 2-header table with an
 * extra unlabeled cell. Registering it routes rows through the bounded
 * key/value split (matching firewall/antivirus), so header and cell counts
 * agree and the new message_box `status` column actually renders correctly.
 */

#include "result_parsing.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

TEST_CASE("interaction is registered as a key/value plugin", "[result_parsing]") {
    const auto& cols = columns_for_plugin("interaction");
    REQUIRE(cols.size() == 3);
    CHECK(cols == std::vector<std::string>{"Agent", "Key", "Value"});
}

TEST_CASE("interaction rows split into exactly key + value", "[result_parsing]") {
    CHECK(split_fields("interaction", "status|not_reachable") ==
          std::vector<std::string>{"status", "not_reachable"});
    CHECK(split_fields("interaction", "response|ok") ==
          std::vector<std::string>{"response", "ok"});
    // A free-text answer containing a literal pipe stays intact in Value —
    // the bounded (first-pipe-only) split, not the unbounded default.
    CHECK(split_fields("interaction", "response|yes | no maybe") ==
          std::vector<std::string>{"response", "yes | no maybe"});
}

// ── cell_hint_for (#4187) ────────────────────────────────────────────────

TEST_CASE("cell_hint_for returns the autoruns enabled=unknown hint for an "
          "autorun row's field 7",
          "[result_parsing]") {
    const std::vector<std::string> fields = {
        "autorun", "lnx_systemd_timers_user", "1", "/etc/systemd/system/foo.timer",
        "foo.timer", "", "", "unknown", "user", "alice", "not_checked", "0"};
    const auto hint = cell_hint_for("autoruns", fields, 7);
    CHECK_FALSE(hint.empty());
    CHECK(hint.find("not the same as disabled") != std::string_view::npos);
}

TEST_CASE("cell_hint_for returns empty for a non-unknown enabled value",
          "[result_parsing]") {
    std::vector<std::string> fields = {
        "autorun", "win_run_hklm", "1", "loc", "entry", "target", "args",
        "enabled", "system", "-", "not_checked", "0"};
    CHECK(cell_hint_for("autoruns", fields, 7).empty());
}

TEST_CASE("cell_hint_for returns empty for a source| row -- the row_kind guard, "
          "since source| and autorun| rows share one stream and field 7 there "
          "is not the enabled column at all",
          "[result_parsing]") {
    std::vector<std::string> fields = {"source", "win_run_hklm", "supported", "0", "ok"};
    CHECK(cell_hint_for("autoruns", fields, 7).empty());
}

TEST_CASE("cell_hint_for returns empty for a different plugin's field 7, even if "
          "its value happens to be the literal string 'unknown'",
          "[result_parsing]") {
    std::vector<std::string> fields = {"autorun", "x", "x", "x", "x", "x", "x", "unknown"};
    CHECK(cell_hint_for("not_autoruns", fields, 7).empty());
}

TEST_CASE("cell_hint_for is safe against a field_index past the end of a short "
          "fields vector",
          "[result_parsing]") {
    const std::vector<std::string> fields = {"autorun"};
    CHECK(cell_hint_for("autoruns", fields, 7).empty());
}

TEST_CASE("installed_apps rows split as key|remainder (pre-existing server decode; a "
          "definition-aware splitter is a tracked follow-up)",
          "[result_parsing]") {
    // Mutation: removing installed_apps from kKeyValuePlugins makes this a
    // seven-cell split and fails both checks.
    CHECK(split_fields("installed_apps",
                       "app|7-Zip 26.02 (x64)|26.02|Igor Pavlov|-|C:/Program Files/7-Zip/|-") ==
          std::vector<std::string>{"app",
                                   "7-Zip 26.02 (x64)|26.02|Igor Pavlov|-|C:/Program Files/7-Zip/|-"});
    // An escaped pipe inside a column decodes inside the remainder, never as a cell.
    CHECK(split_fields("installed_apps", "app|X|-|-|-|a\\|b|-") ==
          std::vector<std::string>{"app", "X|-|-|-|a|b|-"});
}

TEST_CASE("filesystem find_by_hash rows: a path ending in a backslash is folded so the size separator "
          "stays a delimiter (#5624)",
          "[result_parsing]") {
    // The decoder undoes exactly one backslash before a pipe. `match|foo\|3` (an unfolded path
    // ending in a backslash) reads as an ESCAPED pipe, gluing the size onto the path; the plugin
    // therefore folds a trailing backslash to '/', giving `match|foo/|3`.
    //
    // filesystem is a key/value plugin here (kKeyValuePlugins): key = the row kind, value = the
    // rest of the row with escaped pipes undone. The folded row keeps path and size apart by an
    // unescaped pipe; the unfolded one collapses them into one pipe-containing token.
    CHECK(split_fields("filesystem", "match|foo/|3") ==
          std::vector<std::string>{"match", "foo/|3"});
    CHECK(split_fields("filesystem", "match|foo\\|3") ==
          std::vector<std::string>{"match", "foo|3"});

    // A reader that splits on EVERY unescaped pipe (any plugin outside the key/value set) shows
    // the same defect as a field count: three fields folded, two unfolded.
    CHECK(split_fields("an_all_pipes_plugin", "match|foo/|3") ==
          std::vector<std::string>{"match", "foo/", "3"});
    CHECK(split_fields("an_all_pipes_plugin", "match|foo\\|3").size() == 2);
}

TEST_CASE("split_fields to a declared width cuts a key/value plugin at the declared column count "
          "(#5624)",
          "[result_parsing]") {
    // A key/value plugin's DEFINITION may declare more columns than the fixed key + remainder
    // schema (find_by_hash: row_kind, path, size). The matcher splits to that declared width.
    using V = std::vector<std::string>;
    CHECK(split_fields("filesystem", "match|/etc/hosts|413", 3) == V{"match", "/etc/hosts", "413"});

    // The last cell is the unescaped remainder, so a truncated row's counters stay in one cell.
    CHECK(split_fields("filesystem", "truncated|none|visited=1|hashed=2|skipped_unreadable=0", 3) ==
          V{"truncated", "none", "visited=1|hashed=2|skipped_unreadable=0"});

    // A short row is not padded: the caller's width check rejects it.
    CHECK(split_fields("filesystem", "matches_found|1", 3) == V{"matches_found", "1"});

    // An escaped pipe inside a field does not consume a cut.
    CHECK(split_fields("filesystem", "match|a\\|b|3", 3) == V{"match", "a|b", "3"});

    // Width 0 or 1 is no cut at all: the whole unescaped line is one cell.
    CHECK(split_fields("filesystem", "match|a\\|b|3", 1) == V{"match|a|b|3"});
    CHECK(split_fields("filesystem", "match|a\\|b|3", 0) == V{"match|a|b|3"});
}

TEST_CASE("split_fields to a declared width of 2, or for a non-key/value plugin, is the "
          "2-argument split (#5624)",
          "[result_parsing]") {
    for (const char* line : {"status|ok", "match|/etc/hosts|413", "no_pipe_at_all", "a\\|b|c|d"}) {
        CAPTURE(line);
        CHECK(split_fields("filesystem", line, 2) == split_fields("filesystem", line));
        for (std::size_t w : {std::size_t{1}, std::size_t{2}, std::size_t{3}, std::size_t{5}}) {
            CAPTURE(w);
            CHECK(split_fields("an_all_pipes_plugin", line, w) ==
                  split_fields("an_all_pipes_plugin", line));
            CHECK(split_fields("vuln_scan", line, w) == split_fields("vuln_scan", line));
        }
    }
    // Spot-check one non-key/value result is the all-pipes split, not just self-consistent.
    CHECK(split_fields("an_all_pipes_plugin", "match|/etc/hosts|413", 2) ==
          std::vector<std::string>{"match", "/etc/hosts", "413"});
}
