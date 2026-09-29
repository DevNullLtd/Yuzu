/**
 * test_windows_optional_features_parsers.cpp — pure parser tests for the
 * windows_optional_features plugin, plus DismSlot's pure busy/timeout
 * sequencing. Runs on every OS: nothing here touches <windows.h>, a DISM
 * handle, a thread, or a clock.
 *
 * The feature-name/state-int coverage below reads P92-1's real DISM
 * capture (tests/unit/fixtures/wave9/windows_optional_features/
 * dism_features_system.txt, the-rig, NT AUTHORITY\SYSTEM, 2026-09-08) --
 * never a hand-invented fixture (feedback-fixtures-must-come-from-real-captures).
 */
#include <catch2/catch_test_macros.hpp>

#include "../../agents/shared/windows_optional_features_parsers.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;
using yuzu::wof::DismSlot;
using yuzu::wof::FeatureState;

namespace {

#ifndef YUZU_TEST_FIXTURE_DIR
#define YUZU_TEST_FIXTURE_DIR "tests/unit/fixtures/wave9/windows_optional_features"
#endif

fs::path find_dism_features_fixture() {
    const char* names[] = {"dism_features_system.txt"};
    std::vector<fs::path> candidates{
        fs::path{YUZU_TEST_FIXTURE_DIR} / names[0],
        fs::path{"tests"} / "unit" / "fixtures" / "wave9" / "windows_optional_features" / names[0],
        fs::path{".."} / "tests" / "unit" / "fixtures" / "wave9" / "windows_optional_features" /
            names[0],
    };
    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return p;
    }
    return candidates.front(); // fall through to the REQUIRE(fs::exists(...)) below
}

std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

} // namespace

TEST_CASE("windows_optional_features parsers: real DISM capture -- every state int maps to a "
          "named state, real feature names appear",
          "[windows_optional_features][parsers]") {
    const auto path = find_dism_features_fixture();
    INFO("fixture path: " << path.string());
    REQUIRE(fs::exists(path));

    const auto text = read_file(path);
    const auto rows = yuzu::wof::parse_probe_features_dump(text);
    REQUIRE(rows.size() == 137);

    bool saw_net_fx3 = false;
    bool saw_smb1 = false;
    bool saw_telnet = false;
    for (const auto& row : rows) {
        const auto state = yuzu::wof::state_from_dism(row.state_int);
        // Every int this real capture holds (0,2,3,4 per the-rig-dism-findings.md)
        // must map to a NAMED state -- never `unknown`, since unknown is
        // reserved for an int outside the documented 0-7 range.
        CHECK(state != FeatureState::unknown);
        CHECK_FALSE(yuzu::wof::state_name(state).empty());

        if (row.name == "NetFx3")
            saw_net_fx3 = true;
        if (row.name == "SMB1Protocol")
            saw_smb1 = true;
        if (row.name == "TelnetClient")
            saw_telnet = true;
    }
    CHECK(saw_net_fx3);
    CHECK(saw_smb1);
    CHECK(saw_telnet);
}

TEST_CASE("windows_optional_features parsers: parse_probe_features_dump's documented resilience "
          "-- a missing start marker returns empty, malformed/non-tab lines inside the body are "
          "skipped rather than aborting the whole parse",
          "[windows_optional_features][parsers]") {
    // No start marker at all.
    CHECK(yuzu::wof::parse_probe_features_dump("just some unrelated text\nno markers here\n")
              .empty());
    CHECK(yuzu::wof::parse_probe_features_dump("").empty());

    // A well-formed body interleaved with lines this parser's own contract
    // says to skip: no tab at all, an empty line, and a non-integer state
    // field (std::from_chars fails, res.ec != std::errc{}).
    constexpr std::string_view text =
        "preamble\n"
        "--- feature list (name<TAB>state_int) ---\n"
        "GoodOne\t4\n"
        "no_tab_on_this_line\n"
        "\n"
        "BadState\tnotanumber\n"
        "GoodTwo\t0\n"
        "--- end feature list ---\n"
        "trailer, ignored\n";
    const auto rows = yuzu::wof::parse_probe_features_dump(text);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].name == "GoodOne");
    CHECK(rows[0].state_int == 4);
    CHECK(rows[1].name == "GoodTwo");
    CHECK(rows[1].state_int == 0);
}

TEST_CASE("windows_optional_features parsers: state_from_dism covers the full documented range, "
          "unknown never throws",
          "[windows_optional_features][parsers]") {
    CHECK(yuzu::wof::state_from_dism(0) == FeatureState::not_present);
    CHECK(yuzu::wof::state_from_dism(1) == FeatureState::uninstall_pending);
    CHECK(yuzu::wof::state_from_dism(2) == FeatureState::staged);
    CHECK(yuzu::wof::state_from_dism(3) == FeatureState::removed);
    CHECK(yuzu::wof::state_from_dism(4) == FeatureState::installed);
    CHECK(yuzu::wof::state_from_dism(5) == FeatureState::install_pending);
    CHECK(yuzu::wof::state_from_dism(6) == FeatureState::superseded);
    CHECK(yuzu::wof::state_from_dism(7) == FeatureState::partially_installed);

    CHECK(yuzu::wof::state_from_dism(8) == FeatureState::unknown);
    CHECK(yuzu::wof::state_from_dism(-1) == FeatureState::unknown);
    CHECK(yuzu::wof::state_from_dism(9999) == FeatureState::unknown);
}

TEST_CASE("windows_optional_features parsers: pending_restart is true only for the two pending "
          "states",
          "[windows_optional_features][parsers]") {
    for (int i = 0; i <= 8; ++i) {
        const auto state = yuzu::wof::state_from_dism(i);
        const bool expected =
            state == FeatureState::install_pending || state == FeatureState::uninstall_pending;
        INFO("state int: " << i);
        CHECK(yuzu::wof::pending_restart(state) == expected);
    }
}

TEST_CASE("windows_optional_features parsers: restart_type_name maps the three documented ints",
          "[windows_optional_features][parsers]") {
    CHECK(yuzu::wof::restart_type_name(0) == "no");
    CHECK(yuzu::wof::restart_type_name(1) == "possible");
    CHECK(yuzu::wof::restart_type_name(2) == "required");
    CHECK(yuzu::wof::restart_type_name(99) == "unknown");
}

TEST_CASE("windows_optional_features parsers: row formatting shape", "[windows_optional_features]"
                                                                      "[parsers]") {
    CHECK(yuzu::wof::format_feature_row("NetFx3", FeatureState::installed, false) ==
         "feature|NetFx3|enabled|0");
    CHECK(yuzu::wof::format_feature_row("SMB1Protocol", FeatureState::staged, false) ==
         "feature|SMB1Protocol|disabled|0");
    CHECK(yuzu::wof::format_feature_row("Foo", FeatureState::install_pending, true) ==
         "feature|Foo|pending_enable|1");

    CHECK(yuzu::wof::format_feature_info_row("NetFx3", "Display", FeatureState::installed, 1,
                                             "Desc") == "feature_info|NetFx3|Display|enabled|"
                                                        "possible|Desc");

    CHECK(yuzu::wof::format_unsupported_row("list", "linux:dism:unsupported") ==
         "feature|unsupported|linux:dism:unsupported");
    CHECK(yuzu::wof::format_unsupported_row("info", "macos:dism:unsupported") ==
         "feature_info|unsupported|macos:dism:unsupported");
    CHECK(yuzu::wof::format_unavailable_row("list", "windows:dism:busy") ==
         "feature|unavailable|windows:dism:busy");
    CHECK(yuzu::wof::format_unavailable_row("info", "windows:dism:feature_not_found") ==
         "feature_info|unavailable|windows:dism:feature_not_found");
}

TEST_CASE("windows_optional_features parsers: validate_feature_name rejects traversal, "
          "whitespace, backslashes, and over-length values",
          "[windows_optional_features][parsers]") {
    CHECK(yuzu::wof::validate_feature_name("NetFx3").has_value());
    CHECK(yuzu::wof::validate_feature_name("SMB1Protocol-Client").has_value());
    CHECK(yuzu::wof::validate_feature_name("A.B_C-1").has_value());

    CHECK_FALSE(yuzu::wof::validate_feature_name("").has_value());
    CHECK_FALSE(yuzu::wof::validate_feature_name("..").has_value());
    CHECK_FALSE(yuzu::wof::validate_feature_name("../evil").has_value());
    CHECK_FALSE(yuzu::wof::validate_feature_name("has space").has_value());
    CHECK_FALSE(yuzu::wof::validate_feature_name("back\\slash").has_value());
    CHECK_FALSE(yuzu::wof::validate_feature_name(std::string(257, 'a')).has_value());
    CHECK(yuzu::wof::validate_feature_name(std::string(256, 'a')).has_value());

    // Boundary cases quality-engineer flagged as untested (governance Gate 3,
    // Wave 9 PR9.2 C1-fix round): a single-character name (the 1-char end of
    // the 1..256 range) and a LONE '.' -- legal per the character allowlist
    // and not a ".." run, distinct from the traversal case above.
    CHECK(yuzu::wof::validate_feature_name("A").has_value());
    CHECK(yuzu::wof::validate_feature_name(".").has_value());
}

TEST_CASE("windows_optional_features parsers: parse_state_filter maps the three closed tokens",
          "[windows_optional_features][parsers]") {
    auto enabled = yuzu::wof::parse_state_filter("enabled");
    REQUIRE(enabled.has_value());
    CHECK(*enabled == std::unordered_set<FeatureState>{FeatureState::installed});

    auto disabled = yuzu::wof::parse_state_filter("disabled");
    REQUIRE(disabled.has_value());
    CHECK(*disabled == std::unordered_set<FeatureState>{FeatureState::not_present,
                                                         FeatureState::removed,
                                                         FeatureState::staged});

    auto pending = yuzu::wof::parse_state_filter("pending");
    REQUIRE(pending.has_value());
    CHECK(*pending == std::unordered_set<FeatureState>{FeatureState::install_pending,
                                                        FeatureState::uninstall_pending});

    CHECK_FALSE(yuzu::wof::parse_state_filter("bogus").has_value());
    CHECK_FALSE(yuzu::wof::parse_state_filter("").has_value());
}

// ── DismSlot: pure busy/abandoned/timed-out sequencing (peer H2) ────────

TEST_CASE("DismSlot: a fresh slot acquires", "[windows_optional_features][dism_slot]") {
    DismSlot slot;
    CHECK(slot.try_acquire() == DismSlot::Acquire::acquired);
}

TEST_CASE("DismSlot: acquired then try_acquire again reports busy",
          "[windows_optional_features][dism_slot]") {
    DismSlot slot;
    REQUIRE(slot.try_acquire() == DismSlot::Acquire::acquired);
    CHECK(slot.try_acquire() == DismSlot::Acquire::busy);
}

TEST_CASE("DismSlot: acquired, then mark_timed_out with no release, reports abandoned",
          "[windows_optional_features][dism_slot]") {
    DismSlot slot;
    REQUIRE(slot.try_acquire() == DismSlot::Acquire::acquired);
    slot.mark_timed_out();
    CHECK(slot.try_acquire() == DismSlot::Acquire::abandoned);
    // mark_timed_out() never clears the slot -- it is still in flight.
    CHECK(slot.in_flight());
}

TEST_CASE("DismSlot: release after a timed-out acquisition clears the slot -- the next "
          "try_acquire is `acquired`",
          "[windows_optional_features][dism_slot]") {
    DismSlot slot;
    REQUIRE(slot.try_acquire() == DismSlot::Acquire::acquired);
    slot.mark_timed_out();
    REQUIRE(slot.try_acquire() == DismSlot::Acquire::abandoned);

    slot.release();
    CHECK_FALSE(slot.in_flight());
    CHECK(slot.try_acquire() == DismSlot::Acquire::acquired);
}

TEST_CASE("DismSlot: mark_timed_out on a free slot, followed by release, leaves the slot free",
          "[windows_optional_features][dism_slot]") {
    DismSlot slot;
    slot.mark_timed_out();
    slot.release();
    CHECK_FALSE(slot.in_flight());
    CHECK(slot.try_acquire() == DismSlot::Acquire::acquired);
}

TEST_CASE("DismSlot: a release that beats a stale mark_timed_out leaves no abandoned residue "
          "(adversarial review C3, Wave 9 PR9.2) -- a worker finishing right at the dispatching "
          "thread's deadline must not leave the next acquisition looking abandoned",
          "[windows_optional_features][dism_slot]") {
    DismSlot slot;
    REQUIRE(slot.try_acquire() == DismSlot::Acquire::acquired);
    // Simulates the exact race: the worker's release() (inside fn(), before
    // bounded_call_ex's TimedOut/Completed decision is made) wins, and the
    // dispatching thread's mark_timed_out() call -- already in flight --
    // lands AFTER it. With two independent bools this used to leave
    // in_use=false, timed_out=true; the CAS'd single-state design makes
    // mark_timed_out() a no-op once the slot is no longer Busy.
    slot.release();
    slot.mark_timed_out();
    CHECK_FALSE(slot.in_flight());

    // The next acquisition must be a clean `acquired`, not a stale
    // `abandoned` -- and a THIRD concurrent caller arriving while that new
    // call is genuinely in flight must see `busy`, never `abandoned`.
    REQUIRE(slot.try_acquire() == DismSlot::Acquire::acquired);
    CHECK(slot.try_acquire() == DismSlot::Acquire::busy);
}
