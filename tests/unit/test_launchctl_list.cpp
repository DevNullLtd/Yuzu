/**
 * test_launchctl_list.cpp -- fixture-fed tests for agents/shared/
 * launchctl_list.hpp's pure `launchctl list` row parser. Same discipline as
 * test_tar_service.cpp: every case feeds a fixed std::vector<std::string>
 * straight to the pure parser, no spawn, no sleep. Real-capture fixture rows
 * are the same ones test_tar_service.cpp documents the provenance of
 * (launchctl rows captured 2026-08-24 on a macOS arm64 dev host -- see that
 * file's header comment) -- reused here rather than re-documented, since
 * it's the identical wire shape.
 */
#include <launchctl_list.hpp>

#include <catch2/catch_test_macros.hpp>

using yuzu::shared::decode_launchctl_row;
using yuzu::shared::parse_launchctl_list;

// ── decode_launchctl_row (CH-2 fixtures, A0 governance fix round) ────────────

TEST_CASE("decode_launchctl_row: a hex-looking PID is rejected, not truncated",
          "[launchctl_list]") {
    auto row = decode_launchctl_row("0x1A\t0\tcom.example.svc");
    CHECK_FALSE(row.pid.has_value()); // from_chars stops at 'x' -- partial match rejected
    CHECK(row.status == 0);
    CHECK(row.label == "com.example.svc");
}

TEST_CASE("decode_launchctl_row: a trailing-garbage PID is rejected, not truncated "
          "to its numeric prefix",
          "[launchctl_list]") {
    auto row = decode_launchctl_row("12abc\t0\tcom.example.svc");
    CHECK_FALSE(row.pid.has_value()); // stoll would have silently accepted "12"
}

TEST_CASE("decode_launchctl_row: a PID exceeding int64_t range is rejected, "
          "not wrapped or truncated (qe4-1, governance A0 round-4)",
          "[launchctl_list]") {
    // from_chars's own result_out_of_range branch -- distinct from the
    // partial-match branch the two tests above exercise (res.ec == std::errc{}
    // fails here for a different reason: the digits are all valid, but the
    // value itself doesn't fit int64_t). Previously unexercised.
    auto row = decode_launchctl_row("99999999999999999999\t0\tcom.example.svc");
    CHECK_FALSE(row.pid.has_value());
    CHECK(row.label == "com.example.svc");
}

TEST_CASE("decode_launchctl_row: a dash status decodes to 0, not a parse attempt",
          "[launchctl_list]") {
    auto row = decode_launchctl_row("1190\t-\tcom.example.svc");
    REQUIRE(row.pid.has_value());
    CHECK(*row.pid == 1190);
    CHECK(row.status == 0);
}

TEST_CASE("decode_launchctl_row: a 1-field row (no tabs) decodes with an empty "
          "label and no pid, never throws",
          "[launchctl_list]") {
    auto row = decode_launchctl_row("1190");
    CHECK(row.label.empty());
    CHECK_FALSE(row.pid.has_value());
    CHECK(row.status == 0);
}

TEST_CASE("decode_launchctl_row: a 4-field row folds the extra field into the "
          "label verbatim, tab included",
          "[launchctl_list]") {
    auto row = decode_launchctl_row("1190\t0\tcom.example.svc\textra");
    REQUIRE(row.pid.has_value());
    CHECK(*row.pid == 1190);
    CHECK(row.label == "com.example.svc\textra");
}

TEST_CASE("decode_launchctl_row: a literal tab inside the label is preserved "
          "verbatim, not treated as a field boundary",
          "[launchctl_list]") {
    auto row = decode_launchctl_row("1190\t0\tcom.example\tweird.label");
    REQUIRE(row.pid.has_value());
    CHECK(*row.pid == 1190);
    CHECK(row.label == "com.example\tweird.label");
}

TEST_CASE("parse_launchctl_list: empty input (zero lines) is malformed, not a "
          "genuine zero-services answer",
          "[launchctl_list]") {
    // UP2-2 (governance A0 fix round, HIGH): a real exit-0 capture always
    // has at least the header row, so zero lines signals a corrupted
    // capture -- treating it as valid-empty would storm TAR's diff (every
    // known service reads as removed, then re-added next tick).
    auto result = parse_launchctl_list({});
    CHECK(result.rows.empty());
    CHECK(result.malformed);
}

TEST_CASE("parse_launchctl_list: header-only input yields empty rows, not malformed",
          "[launchctl_list]") {
    std::vector<std::string> lines = {"PID\tStatus\tLabel"};
    auto result = parse_launchctl_list(lines);
    CHECK(result.rows.empty());
    CHECK_FALSE(result.malformed);
}

TEST_CASE("parse_launchctl_list: real macOS host capture -- raw fields preserved",
          "[launchctl_list]") {
    std::vector<std::string> lines = {
        "PID\tStatus\tLabel",
        "-\t0\tcom.apple.SafariHistoryServiceAgent",
        "1190\t0\tcom.apple.progressd",
        "93175\t-9\tcom.apple.knowledgeconstructiond",
    };

    auto result = parse_launchctl_list(lines);
    CHECK_FALSE(result.malformed);
    REQUIRE(result.rows.size() == 3);
    const auto& rows = result.rows;

    CHECK(rows[0].label == "com.apple.SafariHistoryServiceAgent");
    CHECK_FALSE(rows[0].pid.has_value());
    CHECK(rows[0].status == 0);

    CHECK(rows[1].label == "com.apple.progressd");
    REQUIRE(rows[1].pid.has_value());
    CHECK(*rows[1].pid == 1190);
    CHECK(rows[1].status == 0);

    // A negative (signal-killed) status code with a real pid still decodes
    // both fields verbatim -- unlike the historical ServiceInfo-collapsing
    // parser, this one never discards the status code.
    CHECK(rows[2].label == "com.apple.knowledgeconstructiond");
    REQUIRE(rows[2].pid.has_value());
    CHECK(*rows[2].pid == 93175);
    CHECK(rows[2].status == -9);
}

TEST_CASE("parse_launchctl_list: a truncated row with no LABEL field decodes "
          "with an empty label rather than throwing",
          "[launchctl_list]") {
    std::vector<std::string> lines = {
        "PID\tStatus\tLabel",
        "1190\t0", // synthetic: truncated row, LABEL column missing
    };
    auto result = parse_launchctl_list(lines);
    CHECK_FALSE(result.malformed);
    REQUIRE(result.rows.size() == 1);
    CHECK(result.rows[0].label.empty());
    REQUIRE(result.rows[0].pid.has_value());
    CHECK(*result.rows[0].pid == 1190);
}

// ── header-row structural check (UP-6, governance A0 fix round) ─────────────

TEST_CASE("parse_launchctl_list: a preamble line before the real header is "
          "malformed, not decoded as if line 0 were the header",
          "[launchctl_list]") {
    std::vector<std::string> lines = {
        "launchctl: some warning banner", // CH-2: preamble before the header
        "PID\tStatus\tLabel",
        "1190\t0\tcom.apple.progressd",
    };
    auto result = parse_launchctl_list(lines);
    CHECK(result.malformed);
    CHECK(result.rows.empty());
}

TEST_CASE("parse_launchctl_list: a header-less capture (first line is already "
          "data) is malformed, not decoded from the wrong offset",
          "[launchctl_list]") {
    std::vector<std::string> lines = {
        "1190\t0\tcom.apple.progressd", // CH-2: no header row at all
        "93175\t-9\tcom.apple.knowledgeconstructiond",
    };
    auto result = parse_launchctl_list(lines);
    CHECK(result.malformed);
    CHECK(result.rows.empty());
}
