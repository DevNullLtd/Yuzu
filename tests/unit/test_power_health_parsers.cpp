/**
 * test_power_health_parsers.cpp — pure power_health parse/interpretation
 * helpers (power_health_parsers.hpp), Wave 6 W1B.
 *
 * Every fixture is labeled REAL CAPTURE (host/date/command) or
 * RECONSTRUCTION (with the reason) per the standing rule. The Windows
 * battery-PRESENT fixture is a deliberate drop-in seam
 * (kReconstructedPresentBattery) — see docs/user-manual/power-health.md's
 * "Hardware checks needed from you" for the reviewer's laptop capture that
 * replaces it; the test's assertions do not need to change when it does.
 */

#include "power_health_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::power_health;

// ─────────────────────────────────────────────────────── Windows battery ──

TEST_CASE("classify_windows_battery: no-system-battery — REAL CAPTURE the-rig, "
          "2026-09-04, GetSystemPowerStatus",
          "[power_health][battery][windows]") {
    // ACLineStatus=1 BatteryFlag=128 BatteryLifePercent=255 BatteryLifeTime=-1
    // (runDir/fixtures/wave2-windows.txt)
    WindowsBatteryRaw raw;
    raw.ac_line_status = 1;
    raw.battery_flag = 128;
    raw.battery_life_percent = 255;
    raw.battery_life_time = -1;
    raw.nt_info_valid = false;

    const auto row = classify_windows_battery(raw);
    CHECK_FALSE(row.present);
    CHECK(row.state == BatteryState::ac_no_battery);
    CHECK(row.percent == -1);
    CHECK(row.time_to_empty_min == -1);
    CHECK(row.cycle_count == -1);
    CHECK(row.health_percent == -1);
}

TEST_CASE("classify_windows_battery: BatteryFlag=255 is UNKNOWN, not no-battery, despite also "
          "satisfying the 0x80 bitmask — RECONSTRUCTION (PH-009; per the SYSTEM_POWER_STATUS "
          "contract, 255 means \"unable to read the battery flag information\")",
          "[power_health][battery][windows]") {
    WindowsBatteryRaw raw;
    raw.ac_line_status = 255;
    raw.battery_flag = 255;
    raw.battery_life_percent = 255;
    raw.battery_life_time = -1;
    raw.nt_info_valid = false;

    const auto row = classify_windows_battery(raw);
    CHECK(row.present); // never claim confirmed absence from an explicitly-unknown flag
    CHECK(row.state == BatteryState::unknown);
    CHECK(row.percent == -1);
}

TEST_CASE("classify_windows_battery: BatteryFlag=255 defers to valid NT corroboration — "
          "RECONSTRUCTION (PH-009)",
          "[power_health][battery][windows]") {
    WindowsBatteryRaw raw;
    raw.battery_flag = 255;
    raw.battery_life_percent = 255;
    raw.nt_info_valid = true;
    raw.nt_battery_present = false;

    const auto row = classify_windows_battery(raw);
    CHECK_FALSE(row.present);
    CHECK(row.state == BatteryState::ac_no_battery);
}

TEST_CASE("classify_windows_battery: CallNtPowerInformation agrees BatteryPresent=false even if "
          "BatteryFlag somehow disagreed — RECONSTRUCTION (defensive; no host observed this "
          "combination)",
          "[power_health][battery][windows]") {
    WindowsBatteryRaw raw;
    raw.ac_line_status = 1;
    raw.battery_flag = 0; // does NOT itself claim no-battery
    raw.battery_life_percent = 0;
    raw.battery_life_time = -1;
    raw.nt_info_valid = true;
    raw.nt_battery_present = false;

    const auto row = classify_windows_battery(raw);
    CHECK_FALSE(row.present);
    CHECK(row.state == BatteryState::ac_no_battery);
}

// RECONSTRUCTION: no laptop venue in this run (probe-findings.md — "no
// venue"). This literal is the drop-in seam: a reviewer's real
// GetSystemPowerStatus/CallNtPowerInformation capture from a battery-bearing
// Windows laptop replaces the four fields below without touching the
// TEST_CASEs that reference it.
constexpr WindowsBatteryRaw kReconstructedPresentBattery{
    /* ac_line_status    = */ 0, // on battery
    /* battery_flag      = */ 1, // "high" bit — plausible discharging value
    /* battery_life_percent = */ 62,
    /* battery_life_time = */ 5400, // 90 minutes
    /* nt_info_valid     = */ true,
    /* nt_battery_present = */ true,
    /* nt_charging       = */ false,
    /* nt_discharging     = */ true,
};

TEST_CASE("classify_windows_battery: battery-PRESENT, discharging — RECONSTRUCTION (no laptop "
          "venue in this run; reviewer's laptop run replaces this fixture)",
          "[power_health][battery][windows]") {
    const auto row = classify_windows_battery(kReconstructedPresentBattery);
    CHECK(row.present);
    CHECK(row.state == BatteryState::discharging);
    // Derived invariants, not literals: the whole point of this seam is that a
    // reviewer can paste a REAL laptop capture over kReconstructedPresentBattery
    // without touching a single assertion. Pinning percent==62 would have forced
    // exactly the edit the protocol says must not be needed.
    CHECK(row.percent >= 0);
    CHECK(row.percent <= 100);
    CHECK(row.percent == kReconstructedPresentBattery.battery_life_percent);
    CHECK(row.time_to_empty_min == kReconstructedPresentBattery.battery_life_time / 60);
}

TEST_CASE("classify_windows_battery: battery-PRESENT, charging — RECONSTRUCTION",
          "[power_health][battery][windows]") {
    auto raw = kReconstructedPresentBattery;
    raw.nt_charging = true;
    raw.nt_discharging = false;
    raw.ac_line_status = 1;

    const auto row = classify_windows_battery(raw);
    CHECK(row.present);
    CHECK(row.state == BatteryState::charging);
}

TEST_CASE("classify_windows_battery: battery-PRESENT, full — RECONSTRUCTION",
          "[power_health][battery][windows]") {
    auto raw = kReconstructedPresentBattery;
    raw.nt_charging = false;
    raw.nt_discharging = false;
    raw.battery_life_percent = 100;
    raw.ac_line_status = 1;

    const auto row = classify_windows_battery(raw);
    CHECK(row.present);
    CHECK(row.state == BatteryState::full);
    CHECK(row.percent == 100);
}

// ───────────────────────────────────────────────────────── macOS battery ──

TEST_CASE("interpret_iops_source: absent power source — RECONSTRUCTION (this Mac has no "
          "battery-bearing host in this run; kIOPSIsPresentKey's documented false-value shape)",
          "[power_health][battery][macos]") {
    IopsSourceView v;
    v.present = false;
    const auto row = interpret_iops_source(v);
    CHECK_FALSE(row.present);
    CHECK(row.state == BatteryState::ac_no_battery);
}

TEST_CASE("interpret_iops_source: present, charging — RECONSTRUCTION (no macOS battery-bearing "
          "host in this run; IOPSKeys.h-documented dictionary values)",
          "[power_health][battery][macos]") {
    IopsSourceView v;
    v.present = true;
    v.is_charging = true;
    v.is_ac_power = true;
    v.current_capacity = 55;
    v.max_capacity = 100;
    v.time_to_empty_min = -1;

    const auto row = interpret_iops_source(v);
    CHECK(row.present);
    CHECK(row.state == BatteryState::charging);
    CHECK(row.percent == 55);
}

TEST_CASE("interpret_iops_source: present, discharging on battery power — RECONSTRUCTION (no "
          "macOS battery-bearing host in this run)",
          "[power_health][battery][macos]") {
    IopsSourceView v;
    v.present = true;
    v.is_charging = false;
    v.is_ac_power = false;
    v.current_capacity = 40;
    v.max_capacity = 100;
    v.time_to_empty_min = 120;

    const auto row = interpret_iops_source(v);
    CHECK(row.state == BatteryState::discharging);
    CHECK(row.percent == 40);
    CHECK(row.time_to_empty_min == 120);
}

TEST_CASE("interpret_iops_source: present, full on AC — RECONSTRUCTION (no macOS battery-bearing "
          "host in this run)",
          "[power_health][battery][macos]") {
    IopsSourceView v;
    v.present = true;
    v.is_charging = false;
    v.is_ac_power = true;
    v.current_capacity = 100;
    v.max_capacity = 100;

    const auto row = interpret_iops_source(v);
    CHECK(row.state == BatteryState::full);
    CHECK(row.percent == 100);
}

// ───────────────────────────────────────────────────────── Linux battery ──

// RECONSTRUCTION: no Linux venue in this run (probe-findings.md). Shape
// matches a real kernel power_supply uevent for a discharging laptop
// battery.
constexpr std::string_view kLinuxBatteryUevent =
    "POWER_SUPPLY_NAME=BAT0\n"
    "POWER_SUPPLY_TYPE=Battery\n"
    "POWER_SUPPLY_STATUS=Discharging\n"
    "POWER_SUPPLY_PRESENT=1\n"
    "POWER_SUPPLY_CAPACITY=71\n"
    "POWER_SUPPLY_CYCLE_COUNT=142\n"
    "POWER_SUPPLY_CHARGE_FULL=4800000\n"
    "POWER_SUPPLY_CHARGE_FULL_DESIGN=5000000\n"
    "POWER_SUPPLY_TIME_TO_EMPTY_NOW=7200\n";

TEST_CASE("parse_linux_power_supply_uevent: battery, discharging — RECONSTRUCTION (no Linux "
          "venue in this run)",
          "[power_health][battery][linux]") {
    auto row = parse_linux_power_supply_uevent(kLinuxBatteryUevent);
    REQUIRE(row.has_value());
    CHECK(row->present);
    CHECK(row->state == BatteryState::discharging);
    CHECK(row->percent == 71);
    CHECK(row->cycle_count == 142);
    CHECK(row->health_percent == 96); // 4800000/5000000
    CHECK(row->time_to_empty_min == 120);
}

TEST_CASE("parse_linux_power_supply_uevent: a Mains supply is not a battery — nullopt, not a "
          "fabricated row",
          "[power_health][battery][linux]") {
    constexpr std::string_view mains = "POWER_SUPPLY_NAME=AC\nPOWER_SUPPLY_TYPE=Mains\n"
                                       "POWER_SUPPLY_ONLINE=1\n";
    CHECK_FALSE(parse_linux_power_supply_uevent(mains).has_value());
}

TEST_CASE("parse_linux_power_supply_uevent: present=0 — honest ac_no_battery, not fabricated",
          "[power_health][battery][linux]") {
    constexpr std::string_view absent =
        "POWER_SUPPLY_TYPE=Battery\nPOWER_SUPPLY_PRESENT=0\n";
    auto row = parse_linux_power_supply_uevent(absent);
    REQUIRE(row.has_value());
    CHECK_FALSE(row->present);
    CHECK(row->state == BatteryState::ac_no_battery);
}

// ──────────────────────────────────────────────────── Windows thermal PDH ─

TEST_CASE("interpret_windows_pdh_thermal: zero instances — REAL CAPTURE the-rig, 2026-09-04 "
          "(counter set registered, 0 live instances; typeperf -> \"Error: No valid counters.\")",
          "[power_health][thermal][windows]") {
    const auto r = interpret_windows_pdh_thermal({}, /*query_opened_ok=*/true);
    CHECK(r.status == "constrained");
    CHECK(r.detail == "no_thermal_zones_exposed");
    CHECK(r.zones.empty());
}

TEST_CASE("interpret_windows_pdh_thermal: PDH query itself failed to open — unavailable, not "
          "constrained",
          "[power_health][thermal][windows]") {
    const auto r = interpret_windows_pdh_thermal({}, /*query_opened_ok=*/false);
    CHECK(r.status == "unavailable");
}

TEST_CASE("interpret_windows_pdh_thermal: non-zero instances — RECONSTRUCTION (the-rig has none; "
          "hardware-conditional per probe-findings.md; PH-003 — \\Thermal Zone Information's "
          "native unit is degrees Kelvin directly, NOT tenths, per Microsoft's thermal "
          "performance-counter documentation)",
          "[power_health][thermal][windows]") {
    // 310.0 K -> 36.85 C — a plausible laptop thermal-zone reading.
    const std::array<PdhThermalSample, 1> samples{{{"TZ00", 310.0}}};
    const auto r = interpret_windows_pdh_thermal(samples, /*query_opened_ok=*/true);
    CHECK(r.status == "ok");
    REQUIRE(r.zones.size() == 1);
    CHECK(r.zones[0].first == "TZ00");
    CHECK(r.zones[0].second > 36.7);
    CHECK(r.zones[0].second < 37.0);
}

// ────────────────────────────────────────────────────────── macOS thermal ─

TEST_CASE("interpret_macos_thermal: kIOReturnNotFound — REAL CAPTURE, 2026-09-04 (`pmset -g "
          "therm` -> \"No thermal warning level has been recorded\" on an idle host) maps to "
          "Normal, never an error",
          "[power_health][thermal][macos]") {
    const auto r = interpret_macos_thermal(/*ns_thermal_state=*/0, /*iopm_found=*/false, 0);
    CHECK(r.status == "ok");
    CHECK(r.detail == "nominal");
}

TEST_CASE("interpret_macos_thermal: thermalState is the 4-level enum, never degrees — "
          "RECONSTRUCTION (SDK-documented NSProcessInfoThermalState enumerator values, not "
          "machine-measured; only level 0 was observed live — see the REAL CAPTURE case above)",
          "[power_health][thermal][macos]") {
    CHECK(interpret_macos_thermal(0, false, 0).detail == "nominal");
    CHECK(interpret_macos_thermal(1, false, 0).detail == "fair");
    CHECK(interpret_macos_thermal(2, false, 0).detail == "serious");
    CHECK(interpret_macos_thermal(3, false, 0).detail == "critical");
    CHECK(interpret_macos_thermal(99, false, 0).detail == "unknown"); // future SDK level
}

TEST_CASE("interpret_macos_thermal: IOPM warning level found and non-zero adds a note, never "
          "replaces the primary thermalState signal — RECONSTRUCTION (idle-host capture above "
          "measured iopm_found=false; a non-zero found+level combination has no venue in this run)",
          "[power_health][thermal][macos]") {
    const auto r = interpret_macos_thermal(1, /*iopm_found=*/true, /*iopm_warning_level=*/5);
    CHECK(r.detail.find("fair") != std::string::npos);
    CHECK(r.detail.find("iopm_warning=5") != std::string::npos);
}

// ────────────────────────────────────────────────────────── Linux thermal ─

TEST_CASE("parse_linux_thermal_temp: millidegrees Celsius — RECONSTRUCTION (no Linux venue in "
          "this run)",
          "[power_health][thermal][linux]") {
    auto c = parse_linux_thermal_temp("45000\n");
    REQUIRE(c.has_value());
    CHECK(*c == 45.0);
}

TEST_CASE("parse_linux_thermal_temp: malformed content — nullopt, not a fabricated zero",
          "[power_health][thermal][linux]") {
    CHECK_FALSE(parse_linux_thermal_temp("").has_value());
    CHECK_FALSE(parse_linux_thermal_temp("not-a-number").has_value());
}

// ───────────────────────────────────────────────────────────── GUID/GUIDs ─

TEST_CASE("format_guid / parse_guid: round-trip — REAL CAPTURE the-rig, 2026-09-04, powercfg "
          "/list (Balanced scheme GUID)",
          "[power_health][power_plan]") {
    auto g = parse_guid("381b4222-f694-41f0-9685-ff5bb260df2e");
    REQUIRE(g.has_value());
    CHECK(format_guid(*g) == "381b4222-f694-41f0-9685-ff5bb260df2e");
}

TEST_CASE("parse_guid: accepts braces and mixed case; rejects malformed input",
          "[power_health][power_plan]") {
    CHECK(parse_guid("{381B4222-F694-41F0-9685-FF5BB260DF2E}").has_value());
    CHECK_FALSE(parse_guid("not-a-guid").has_value());
    CHECK_FALSE(parse_guid("381b4222-f694-41f0-9685").has_value());
    CHECK_FALSE(parse_guid("").has_value());
}

TEST_CASE("guids_equal: case/brace-insensitive identity via the parsed struct",
          "[power_health][power_plan]") {
    auto a = parse_guid("381b4222-f694-41f0-9685-ff5bb260df2e");
    auto b = parse_guid("{381B4222-F694-41F0-9685-FF5BB260DF2E}");
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    CHECK(guids_equal(*a, *b));
}

// ──────────────────────────────────────────────────── power scheme resolve ─

// REAL CAPTURE the-rig, 2026-09-04, `powercfg /list` (runDir/fixtures/wave2-windows.txt):
//   381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced) *
//   8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)
//   a1841308-3541-4fab-bc81-f71556f20b4a  (Power saver)
//   b1000fa2-4bc5-4da1-b3b1-27c753763a67  (AMD RyzenT Balanced)
const std::array<PowerScheme, 4> kTheRigSchemes{{
    {*parse_guid("381b4222-f694-41f0-9685-ff5bb260df2e"), "Balanced"},
    {*parse_guid("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"), "High performance"},
    {*parse_guid("a1841308-3541-4fab-bc81-f71556f20b4a"), "Power saver"},
    {*parse_guid("b1000fa2-4bc5-4da1-b3b1-27c753763a67"), "AMD RyzenT Balanced"},
}};

TEST_CASE("resolve_power_scheme: exact case-insensitive friendly-name match, REAL CAPTURE the-rig "
          "4-scheme fixture — \"Balanced\" is NOT ambiguous against \"AMD RyzenT Balanced\" "
          "(exact match, not substring)",
          "[power_health][power_plan]") {
    auto r = resolve_power_scheme(kTheRigSchemes, "balanced");
    REQUIRE(r.has_value());
    CHECK(format_guid(*r) == "381b4222-f694-41f0-9685-ff5bb260df2e");
}

TEST_CASE("resolve_power_scheme: GUID-shaped query passes through without list validation",
          "[power_health][power_plan]") {
    auto r = resolve_power_scheme(kTheRigSchemes, "8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C");
    REQUIRE(r.has_value());
    CHECK(format_guid(*r) == "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c");
}

TEST_CASE("resolve_power_scheme: zero matches -> NoMatch, never a silent guess",
          "[power_health][power_plan]") {
    auto r = resolve_power_scheme(kTheRigSchemes, "Ultra Performance");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == SchemeResolveError::NoMatch);
}

TEST_CASE("resolve_power_scheme: more than one match -> Ambiguous, never first-wins — synthetic "
          "two-scheme fixture (P-012; the-rig's real names don't collide under exact match)",
          "[power_health][power_plan]") {
    const std::array<PowerScheme, 2> ambiguous_fixture{{
        {*parse_guid("11111111-1111-1111-1111-111111111111"), "Custom"},
        {*parse_guid("22222222-2222-2222-2222-222222222222"), "custom"},
    }};
    auto r = resolve_power_scheme(ambiguous_fixture, "CUSTOM");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == SchemeResolveError::Ambiguous);
}

// ───────────────────────────────────────── do_set_power_plan_sequence ─────
//
// PH-005: drives the pure sequencing logic (power_health_plugin.cpp's
// do_set_power_plan binds this to real bounded PowrProf calls) through
// every enumerated failure branch and a full success path, asserting call
// order and count via a small logging mock — never a live PowrProf call.

namespace {

const std::array<PowerScheme, 2> kSeqSchemes{{
    {*parse_guid("11111111-1111-1111-1111-111111111111"), "Balanced"},
    {*parse_guid("22222222-2222-2222-2222-222222222222"), "High performance"},
}};

/// A small call-order-logging mock: every boundary op appends its name to
/// `log` before returning its scripted result, so a test can assert BOTH
/// the outcome AND the exact sequence/count of calls that produced it
/// (e.g. that `set_active` is never called before `read_active`, and never
/// called at all on a pre-set failure).
struct SequenceMock {
    std::vector<std::string> log;
    std::optional<EnumerateResult> enumerate_result{EnumerateResult{
        std::vector<PowerScheme>(kSeqSchemes.begin(), kSeqSchemes.end()), /*complete=*/true}};
    std::optional<std::optional<GuidBytes>> prior_result{kSeqSchemes[0].guid};
    std::optional<std::optional<GuidBytes>> readback_result{kSeqSchemes[1].guid};
    std::optional<bool> set_result{true};
    bool read_active_called_once_already{false};

    SetPowerPlanOps ops() {
        return SetPowerPlanOps{
            /* .enumerate   = */
            [this] {
                log.push_back("enumerate");
                return enumerate_result;
            },
            /* .read_active = */
            [this] {
                // First call is the pre-mutation read (`prior_result`);
                // every subsequent call is the post-set read-back
                // (`readback_result`) — the sequence never calls
                // read_active a third time.
                if (!read_active_called_once_already) {
                    read_active_called_once_already = true;
                    log.push_back("read_active(prior)");
                    return prior_result;
                }
                log.push_back("read_active(readback)");
                return readback_result;
            },
            /* .set_active  = */
            [this](const GuidBytes&) {
                log.push_back("set_active");
                return set_result;
            },
        };
    }
};

} // namespace

TEST_CASE("do_set_power_plan_sequence: empty scheme param -> MissingParam, no boundary op called",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    const auto r = do_set_power_plan_sequence("", mock.ops());
    CHECK(r.outcome == SetPowerPlanOutcome::MissingParam);
    CHECK(mock.log.empty());
}

TEST_CASE("do_set_power_plan_sequence: enumerate times out -> Timeout, nothing past it runs",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    mock.enumerate_result = std::nullopt;
    const auto r = do_set_power_plan_sequence("Balanced", mock.ops());
    CHECK(r.outcome == SetPowerPlanOutcome::Timeout);
    CHECK(mock.log == std::vector<std::string>{"enumerate"});
}

TEST_CASE("do_set_power_plan_sequence: incomplete enumeration -> EnumerationIncomplete, name is "
          "NEVER resolved against a partial list (PH-004)",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    mock.enumerate_result = EnumerateResult{
        std::vector<PowerScheme>(kSeqSchemes.begin(), kSeqSchemes.end()), /*complete=*/false};
    const auto r = do_set_power_plan_sequence("Balanced", mock.ops());
    CHECK(r.outcome == SetPowerPlanOutcome::EnumerationIncomplete);
    CHECK(mock.log == std::vector<std::string>{"enumerate"});
}

TEST_CASE("do_set_power_plan_sequence: no name match -> NoMatch, no mutation attempted",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    const auto r = do_set_power_plan_sequence("Ultra Performance", mock.ops());
    CHECK(r.outcome == SetPowerPlanOutcome::NoMatch);
    CHECK(mock.log == std::vector<std::string>{"enumerate"});
}

TEST_CASE("do_set_power_plan_sequence: ambiguous name -> Ambiguous, no mutation attempted",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    mock.enumerate_result = EnumerateResult{
        {{*parse_guid("11111111-1111-1111-1111-111111111111"), "Custom"},
         {*parse_guid("22222222-2222-2222-2222-222222222222"), "custom"}},
        /*complete=*/true};
    const auto r = do_set_power_plan_sequence("CUSTOM", mock.ops());
    CHECK(r.outcome == SetPowerPlanOutcome::Ambiguous);
    CHECK(mock.log == std::vector<std::string>{"enumerate"});
}

TEST_CASE("do_set_power_plan_sequence: prior-scheme read fails -> ReadPriorFailed BEFORE "
          "set_active is ever called (P-012 ordering)",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    mock.prior_result = std::optional<GuidBytes>{std::nullopt}; // read succeeded, value absent
    const auto r = do_set_power_plan_sequence("Balanced", mock.ops());
    CHECK(r.outcome == SetPowerPlanOutcome::ReadPriorFailed);
    CHECK(mock.log == std::vector<std::string>{"enumerate", "read_active(prior)"});
}

TEST_CASE("do_set_power_plan_sequence: prior-scheme read TIMES OUT -> ReadPriorFailed, same as an "
          "ordinary read failure (a bounded-call timeout at any step is a typed error)",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    mock.prior_result = std::nullopt;
    const auto r = do_set_power_plan_sequence("Balanced", mock.ops());
    CHECK(r.outcome == SetPowerPlanOutcome::ReadPriorFailed);
    CHECK(mock.log == std::vector<std::string>{"enumerate", "read_active(prior)"});
}

TEST_CASE("do_set_power_plan_sequence: PowerSetActiveScheme fails -> SetFailed, previous_guid IS "
          "captured (the read already succeeded) but new_guid is not",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    mock.set_result = false;
    const auto r = do_set_power_plan_sequence("Balanced", mock.ops());
    CHECK(r.outcome == SetPowerPlanOutcome::SetFailed);
    REQUIRE(r.previous_guid.has_value());
    CHECK(guids_equal(*r.previous_guid, kSeqSchemes[0].guid));
    CHECK_FALSE(r.new_guid.has_value());
    CHECK(mock.log == std::vector<std::string>{"enumerate", "read_active(prior)", "set_active"});
}

TEST_CASE("do_set_power_plan_sequence: PowerSetActiveScheme TIMES OUT -> SetFailed, no mutation "
          "CONFIRMED but the call itself may have landed -- same typed status as an ordinary "
          "set failure",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    mock.set_result = std::nullopt;
    const auto r = do_set_power_plan_sequence("Balanced", mock.ops());
    CHECK(r.outcome == SetPowerPlanOutcome::SetFailed);
    CHECK(mock.log == std::vector<std::string>{"enumerate", "read_active(prior)", "set_active"});
}

TEST_CASE("do_set_power_plan_sequence: post-set read-back fails -> ReadbackFailed; previous_guid "
          "is still reported for manual revert, new_guid is not (final state genuinely unknown)",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    mock.readback_result = std::optional<GuidBytes>{std::nullopt};
    const auto r = do_set_power_plan_sequence("Balanced", mock.ops());
    CHECK(r.outcome == SetPowerPlanOutcome::ReadbackFailed);
    REQUIRE(r.previous_guid.has_value());
    CHECK(guids_equal(*r.previous_guid, kSeqSchemes[0].guid));
    CHECK_FALSE(r.new_guid.has_value());
    CHECK(mock.log == std::vector<std::string>{"enumerate", "read_active(prior)", "set_active",
                                                "read_active(readback)"});
}

TEST_CASE("do_set_power_plan_sequence: post-set read-back TIMES OUT -> ReadbackFailed, same "
          "typed status as an ordinary read-back failure",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    mock.readback_result = std::nullopt;
    const auto r = do_set_power_plan_sequence("Balanced", mock.ops());
    CHECK(r.outcome == SetPowerPlanOutcome::ReadbackFailed);
}

TEST_CASE("do_set_power_plan_sequence: post-set read-back does not match the target -> "
          "ReadbackMismatch naming BOTH the mismatched new_guid and the target_guid",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    // readback_result defaults to kSeqSchemes[1] -- but the target the test
    // resolves is kSeqSchemes[0] ("Balanced"), so this IS the mismatch.
    const auto r = do_set_power_plan_sequence("Balanced", mock.ops());
    CHECK(r.outcome == SetPowerPlanOutcome::ReadbackMismatch);
    REQUIRE(r.target_guid.has_value());
    REQUIRE(r.new_guid.has_value());
    CHECK(guids_equal(*r.target_guid, kSeqSchemes[0].guid));
    CHECK(guids_equal(*r.new_guid, kSeqSchemes[1].guid));
}

TEST_CASE("do_set_power_plan_sequence: full success -> Ok, previous_guid/new_guid both reported, "
          "call order is exactly enumerate -> read(prior) -> set -> read(readback)",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    mock.readback_result = kSeqSchemes[0].guid; // matches the resolved target this time
    const auto r = do_set_power_plan_sequence("balanced", mock.ops()); // case-insensitive
    CHECK(r.ok());
    CHECK(r.outcome == SetPowerPlanOutcome::Ok);
    REQUIRE(r.previous_guid.has_value());
    REQUIRE(r.new_guid.has_value());
    CHECK(guids_equal(*r.previous_guid, kSeqSchemes[0].guid));
    CHECK(guids_equal(*r.new_guid, kSeqSchemes[0].guid));
    CHECK(mock.log == std::vector<std::string>{"enumerate", "read_active(prior)", "set_active",
                                                "read_active(readback)"});
}

TEST_CASE("do_set_power_plan_sequence: a GUID-shaped param resolves without enumeration "
          "membership, same as resolve_power_scheme itself",
          "[power_health][power_plan][set_power_plan]") {
    SequenceMock mock;
    mock.readback_result = *parse_guid("33333333-3333-3333-3333-333333333333");
    const auto r =
        do_set_power_plan_sequence("33333333-3333-3333-3333-333333333333", mock.ops());
    CHECK(r.ok());
    REQUIRE(r.target_guid.has_value());
    CHECK(format_guid(*r.target_guid) == "33333333-3333-3333-3333-333333333333");
}

// ─────────────────────────────────────────────────────────── row shapes ───

TEST_CASE("format_battery_row: schema shape — 6 pipe-delimited fields after the discriminator",
          "[power_health][battery]") {
    const auto line = format_battery_row(BatteryRow{true, BatteryState::charging, 55, 30, -1, -1});
    CHECK(line == "battery|1|charging|55|30|-1|-1");
}

TEST_CASE("format_thermal_line: constrained line is the explicit success shape",
          "[power_health][thermal]") {
    const ThermalReport r{"constrained", "no_thermal_zones_exposed", {}};
    CHECK(format_thermal_line(r) == "thermal|constrained|no_thermal_zones_exposed");
}

TEST_CASE("set_power_plan row: every branch emits exactly four fields after the discriminator "
          "so the positional result columns cannot shift",
          "[power_health][set_power_plan][columns]") {
    using yuzu::power_health::format_set_power_plan_row;

    // content/definitions/power_health.yaml declares, positionally:
    //   status, reason, previous_guid, new_guid
    // The success row previously carried only three payload fields, so the
    // server bound reason=<previous_guid> and previous_guid=<new_guid> and left
    // new_guid empty — silently corrupting the value an operator reverts with.
    auto field_count = [](const std::string& row) {
        return static_cast<int>(std::count(row.begin(), row.end(), '|'));
    };

    const std::string ok = format_set_power_plan_row("ok", "", "{prev-guid}", "{new-guid}");
    CHECK(ok == "set_power_plan|ok|-|{prev-guid}|{new-guid}");
    CHECK(field_count(ok) == 4);

    const std::string mismatch =
        format_set_power_plan_row("error", "readback_mismatch", "{prev-guid}", "{observed-guid}");
    CHECK(mismatch == "set_power_plan|error|readback_mismatch|{prev-guid}|{observed-guid}");
    CHECK(field_count(mismatch) == 4);

    // Sparse error branches still pad rather than shorten.
    for (std::string_view reason : {"missing_param", "timeout", "enumeration_incomplete",
                                     "ambiguous", "no_match", "read_prior_failed"}) {
        const std::string row = format_set_power_plan_row("error", reason, "", "");
        INFO("reason: " << reason);
        CHECK(field_count(row) == 4);
        CHECK(row.ends_with("|-|-"));
    }

    // A partially-known branch pads only the unknown tail field.
    const std::string set_failed = format_set_power_plan_row("error", "set_failed", "{prev}", "");
    CHECK(set_failed == "set_power_plan|error|set_failed|{prev}|-");
    CHECK(field_count(set_failed) == 4);
}

TEST_CASE("classify_windows_battery: present + AC + neither charging nor discharging is "
          "not_charging — REAL CAPTURE, HP ZBook Firefly, PR #4009 review",
          "[power_health][battery][windows]") {
    // The row the reviewer's physical laptop produced, which this plugin used
    // to report as `unknown`: battery|1|unknown|99|-1|-1|-1. Every fact in it
    // came from the OS — present, on AC, not charging, not discharging, 99% —
    // so `unknown` (the "the OS told us nothing" sentinel) was wrong, and wrong
    // in the modal state of a plugged-in laptop rather than a corner case.
    // Windows firmware defers charging at a stop threshold to preserve cells.
    WindowsBatteryRaw raw;
    raw.ac_line_status = 1; // on AC
    raw.battery_flag = 1;   // high, no charging bit
    raw.battery_life_percent = 99;
    raw.battery_life_time = -1;
    raw.nt_info_valid = true;
    raw.nt_battery_present = true;
    raw.nt_charging = false;
    raw.nt_discharging = false;

    const auto row = classify_windows_battery(raw);
    CHECK(row.present);
    CHECK(row.state == BatteryState::not_charging);
    CHECK(to_string(row.state) != "unknown");
    CHECK(row.percent == 99);
}

TEST_CASE("classify_windows_battery: resting with NO known power source stays unknown",
          "[power_health][battery][windows]") {
    // ACLineStatus 255 is the OS declining to say whether we are on AC. A
    // battery that is neither charging nor discharging, with no known power
    // source, genuinely is unclassifiable — so `not_charging` must NOT widen
    // to cover it. This is the boundary that keeps `unknown` meaningful.
    WindowsBatteryRaw raw;
    raw.ac_line_status = 255; // unknown
    raw.battery_flag = 1;
    raw.battery_life_percent = 99;
    raw.nt_info_valid = true;
    raw.nt_battery_present = true;
    raw.nt_charging = false;
    raw.nt_discharging = false;

    const auto row = classify_windows_battery(raw);
    CHECK(row.present);
    CHECK(row.state == BatteryState::unknown);
}

TEST_CASE("classify_windows_battery: the legacy BatteryFlag path reports the same resting state",
          "[power_health][battery][windows]") {
    // Same firmware charge-hold, reached through the no-NT-info fallback: it
    // used to land on `unknown` for exactly the same reason.
    WindowsBatteryRaw raw;
    raw.ac_line_status = 1;
    raw.battery_flag = 1; // high, charging bit (0x08) clear
    raw.battery_life_percent = 80;
    raw.nt_info_valid = false;

    const auto row = classify_windows_battery(raw);
    CHECK(row.present);
    CHECK(row.state == BatteryState::not_charging);

    // ...and the same fallback with no known power source is still unknown.
    raw.ac_line_status = 255;
    CHECK(classify_windows_battery(raw).state == BatteryState::unknown);
}

TEST_CASE("interpret_iops_source: present + AC + not charging + below full is not_charging",
          "[power_health][battery][macos]") {
    // The macOS analogue of the ZBook row — macOS surfaces this in its own UI
    // as "Battery Not Charging". IOPS answered present/charging/AC, so this
    // branch can never be `unknown`.
    IopsSourceView v;
    v.present = true;
    v.is_charging = false;
    v.is_ac_power = true;
    v.current_capacity = 88;
    v.max_capacity = 100;

    const auto row = interpret_iops_source(v);
    CHECK(row.present);
    CHECK(row.state == BatteryState::not_charging);
    CHECK(to_string(row.state) != "unknown");
    CHECK(row.percent == 88);
}

TEST_CASE("parse_linux_power_supply_uevent: the kernel's own \"Not charging\" is not_charging",
          "[power_health][battery][linux]") {
    // POWER_SUPPLY_STATUS is a closed set of five values in the kernel's
    // power_supply.h — Unknown, Charging, Discharging, Not charging, Full — and
    // "Not charging" is the sysfs spelling of the same firmware charge-hold the
    // Windows and macOS legs report. It was falling into `unknown`, the same
    // information loss PR #4009's review caught on the other two platforms;
    // this is the third leg of that sweep.
    //
    // Linux is the easy case precisely because the kernel states the status
    // outright instead of leaving it to be inferred from two booleans.
    static constexpr std::string_view kNotCharging =
        "POWER_SUPPLY_NAME=BAT0\n"
        "POWER_SUPPLY_TYPE=Battery\n"
        "POWER_SUPPLY_PRESENT=1\n"
        "POWER_SUPPLY_STATUS=Not charging\n"
        "POWER_SUPPLY_CAPACITY=80\n";
    auto row = parse_linux_power_supply_uevent(kNotCharging);
    REQUIRE(row.has_value());
    CHECK(row->present);
    CHECK(row->state == BatteryState::not_charging);
    CHECK(to_string(row->state) != "unknown");
    CHECK(row->percent == 80);
}

TEST_CASE("parse_linux_power_supply_uevent: the kernel's own \"Unknown\" stays unknown",
          "[power_health][battery][linux]") {
    // The boundary that keeps `unknown` meaningful on this leg: the kernel has
    // an explicit Unknown, and it must not be absorbed by not_charging. Same
    // role as the ACLineStatus==255 case on Windows.
    static constexpr std::string_view kUnknown =
        "POWER_SUPPLY_NAME=BAT0\n"
        "POWER_SUPPLY_TYPE=Battery\n"
        "POWER_SUPPLY_PRESENT=1\n"
        "POWER_SUPPLY_STATUS=Unknown\n"
        "POWER_SUPPLY_CAPACITY=80\n";
    auto row = parse_linux_power_supply_uevent(kUnknown);
    REQUIRE(row.has_value());
    CHECK(row->state == BatteryState::unknown);

    // ...and so does a status outside the documented set.
    static constexpr std::string_view kBogus =
        "POWER_SUPPLY_NAME=BAT0\n"
        "POWER_SUPPLY_TYPE=Battery\n"
        "POWER_SUPPLY_PRESENT=1\n"
        "POWER_SUPPLY_STATUS=Nonsense\n";
    auto bogus = parse_linux_power_supply_uevent(kBogus);
    REQUIRE(bogus.has_value());
    CHECK(bogus->state == BatteryState::unknown);
}
