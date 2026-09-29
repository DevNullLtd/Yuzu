/**
 * test_dex_macos.cpp — pure macOS DEX signal extractors (dex_macos_signals).
 *
 * The macOS analogue of the Windows extractor tests in test_dex_signals.cpp:
 * pins the .ips / .diag / sysctl parsers against REAL captured records (a crash
 * and a JetsamEvent harvested from a live macOS 26.5 / Apple Silicon box, plus a
 * real cpu_resource .diag) and synthetic specimens for the report types that are
 * too rare to capture on demand (spin/hang 288, kernel panic 210). These run on
 * EVERY host (incl. MSVC) because the parsers are framework-free by design.
 *
 * Covers the data-minimisation contract: a crash report's procPath / parentProc
 * / image paths are NEVER surfaced — only basenames + the signal/exception name.
 */

#include "dex_macos_iokit.hpp"
#include "dex_macos_oslog.hpp"
#include "dex_macos_signals.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cmath>
#include <string>

using namespace yuzu::agent;

// ── Real captured records ────────────────────────────────────────────────────

// Real crash (bug_type 309) from the live box — trimmed to the fields the
// extractor reads, structure preserved (note the escaped \/ in paths, valid JSON).
static const char* kRealCrashIps = R"IPS({"app_name":"yz_crash","timestamp":"2026-06-11 15:02:29.00 +0100","bug_type":"309","os_version":"macOS 26.5 (25F71)","incident_id":"94DB6BB2-A96A-493A-9332-5CEBB8C61E19","name":"yz_crash"}
{
  "pid" : 55982,
  "procName" : "yz_crash",
  "procPath" : "\/private\/tmp\/yz_crash",
  "parentProc" : "zsh",
  "exception" : {"codes":"0x0000000000000001, 0x0000000000000000","type":"EXC_BAD_ACCESS","signal":"SIGSEGV","subtype":"KERN_INVALID_ADDRESS at 0x0000000000000000"},
  "termination" : {"flags":0,"code":11,"namespace":"SIGNAL","indicator":"Segmentation fault: 11"},
  "faultingThread" : 0,
  "threads" : [{"triggered":true,"id":893249,"frames":[{"imageOffset":832,"symbol":"main","imageIndex":0},{"imageOffset":130560,"symbol":"start","imageIndex":1}]}],
  "usedImages" : [
    {"arch":"arm64","base":4342841344,"name":"yz_crash","path":"\/private\/tmp\/yz_crash","uuid":"59df683a-da77-31c4-9b11-4d818c8eee70"},
    {"arch":"arm64e","base":6553649152,"name":"dyld","path":"\/usr\/lib\/dyld"}
  ]
})IPS";

// Real JetsamEvent (bug_type 298) — memory pressure.
static const char* kRealJetsamIps = R"IPS({"bug_type":"298","timestamp":"2026-06-06 17:41:41.00 +0100","os_version":"macOS 26.5 (25F71)","incident_id":"D7D558F0-E560-409F-8887-DA5BE1ECCC32"}
{
  "build" : "macOS 26.5 (25F71)",
  "bug_type" : "298",
  "largestProcess" : "com.apple.WebKit.WebContent",
  "memoryStatus" : { "pageSize" : 16384 },
  "processes" : [ {"uuid":"8b19e4ea-231c-352f-833d-9d3974d921d6","rpages":104} ]
})IPS";

// Real cpu_resource .diag (plain text).
static const char* kRealCpuDiag = R"DIAG(Date/Time:        2026-06-11 11:54:37.123 +0100
OS Version:       macOS 26.5 (Build 25F71)
Architecture:     arm64e
Command:          system_installd
Path:             /System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/Resources/system_installd
PID:              809

Event:            cpu usage
Action taken:     none
CPU:              90 seconds cpu time over 179 seconds (50% cpu average), exceeding limit of 50% cpu over 180 seconds
CPU used:         90s
Duration:         179.37s
)DIAG";

// ── Crash (process.crashed) ──────────────────────────────────────────────────

TEST_CASE("real crash .ips maps to process.crashed", "[dex_macos][crash]") {
    const auto obs = macos::parse_ips_report(kRealCrashIps);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "process.crashed");
    CHECK(obs->subject == "yz_crash");
    CHECK(obs->reason == "SIGSEGV");
    CHECK(obs->symbolic == "EXC_BAD_ACCESS");
    CHECK(obs->component == "yz_crash"); // faulting image basename
    CHECK(obs->pid == 55982u);
    CHECK(obs->kind == "exception");
    CHECK(obs->sentence.find("crashed") != std::string::npos);
    // platform + timestamp are stamped by the collector engine, NOT the parser.
    CHECK(obs->platform.empty());
    CHECK(obs->timestamp_unix == 0);
    // yz_crash is a bare/unsigned CLI binary — neither header app_version nor
    // body bundleInfo carries a version, so it falls into the shared unknown
    // bucket rather than an empty-but-present quad.
    CHECK(obs->version.empty());
}

TEST_CASE("crash .ips routes header app_version into canon_version",
          "[dex_macos][crash][version]") {
    const std::string ips = R"({"bug_type":"309","app_version":"3.2.1","name":"SomeApp"})"
                            "\n"
                            R"({"pid":1,"procName":"SomeApp"})";
    const auto obs = macos::parse_ips_report(ips);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "process.crashed");
    CHECK(obs->version == "3.2.1.0"); // canon_version pads to the 4-group quad
}

TEST_CASE("crash .ips falls back to body bundleInfo.CFBundleShortVersionString when header "
          "app_version is absent",
          "[dex_macos][crash][version]") {
    const std::string ips = R"({"bug_type":"309","name":"SomeApp"})"
                            "\n"
                            R"({"pid":1,"procName":"SomeApp","bundleInfo":{"CFBundleShortVersionString":"1.0"}})";
    const auto obs = macos::parse_ips_report(ips);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "process.crashed");
    CHECK(obs->version == "1.0.0.0");
}

TEST_CASE("crash .ips prefers header app_version over body bundleInfo when both are present",
          "[dex_macos][crash][version]") {
    const std::string ips = R"({"bug_type":"309","app_version":"3.2.1","name":"SomeApp"})"
                            "\n"
                            R"({"pid":1,"procName":"SomeApp","bundleInfo":{"CFBundleShortVersionString":"9.9"}})";
    const auto obs = macos::parse_ips_report(ips);
    REQUIRE(obs.has_value());
    // The header value must win; a regression inverting ips_app_version's
    // preference (or letting bundleInfo unconditionally override) yields 9.9.0.0.
    CHECK(obs->version == "3.2.1.0");
}

TEST_CASE("crash extractor leaks no path / user content", "[dex_macos][crash][privacy]") {
    const auto obs = macos::parse_ips_report(kRealCrashIps);
    REQUIRE(obs.has_value());
    // procPath, parentProc, image paths must never appear in any surfaced field.
    for (const std::string& f : {obs->subject, obs->reason, obs->symbolic, obs->component}) {
        CHECK(f.find('/') == std::string::npos);
        CHECK(f.find("tmp") == std::string::npos);
    }
    CHECK(obs->sentence.find("/private") == std::string::npos);
    CHECK(obs->sentence.find("zsh") == std::string::npos); // parentProc not leaked
}

TEST_CASE("crash with unparseable body still counts via header", "[dex_macos][crash]") {
    // bug_type recognised in the header, body truncated/garbage — degrade to a
    // counted occurrence with the header's process name, never drop the crash.
    const std::string ips = R"({"bug_type":"309","name":"BrokenApp"})"
                            "\n{ this is not json";
    const auto obs = macos::parse_ips_report(ips);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "process.crashed");
    CHECK(obs->subject == "BrokenApp");
}

// ── Hang / panic / jetsam ────────────────────────────────────────────────────

TEST_CASE("spin/hang .ips maps to process.hung", "[dex_macos][hang]") {
    const std::string ips = R"({"bug_type":"288","name":"SomeApp"})"
                            "\n"
                            R"({"pid":4242,"procName":"SomeApp"})";
    const auto obs = macos::parse_ips_report(ips);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "process.hung");
    CHECK(obs->subject == "SomeApp");
    CHECK(obs->kind == "hang");
    CHECK(obs->pid == 4242u);
}

TEST_CASE("hang .ips also routes version (both branches, not just crash)",
          "[dex_macos][hang][version]") {
    // Pins version routing on the HANG branch specifically — the crash and hang
    // branches are edited independently, so a regression that drops the
    // assignment from just the hang branch must fail here even though every
    // crash-side version test still passes.
    const std::string via_header = R"({"bug_type":"288","app_version":"2.0","name":"SomeApp"})"
                                   "\n"
                                   R"({"pid":4242,"procName":"SomeApp"})";
    const auto o1 = macos::parse_ips_report(via_header);
    REQUIRE(o1.has_value());
    CHECK(o1->obs_type == "process.hung");
    CHECK(o1->version == "2.0.0.0");

    const std::string via_bundle = R"({"bug_type":"388","name":"OtherApp"})"
                                   "\n"
                                   R"({"pid":9,"procName":"OtherApp","bundleInfo":{"CFBundleShortVersionString":"5.1.2"}})";
    const auto o2 = macos::parse_ips_report(via_bundle);
    REQUIRE(o2.has_value());
    CHECK(o2->obs_type == "process.hung");
    CHECK(o2->version == "5.1.2.0");
}

TEST_CASE("panic .ips maps to os.bugcheck without shipping panicString",
          "[dex_macos][panic][privacy]") {
    const std::string ips =
        R"({"bug_type":"210","os_version":"macOS 26.5"})"
        "\n"
        R"({"panicString":"panic(cpu 2 caller 0xfff...): secret pointer soup\n@xnu","product":"Mac17,5"})";
    const auto obs = macos::parse_ips_report(ips);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "os.bugcheck");
    CHECK(obs->subject == "kernel");
    // The raw panic string (pointer-laden) must not be surfaced.
    CHECK(obs->sentence.find("pointer soup") == std::string::npos);
    CHECK(obs->reason.find("0xfff") == std::string::npos);
}

TEST_CASE("real jetsam .ips maps to memory.exhausted", "[dex_macos][jetsam]") {
    const auto obs = macos::parse_ips_report(kRealJetsamIps);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "memory.exhausted");
    CHECK(obs->subject == "com.apple.WebKit.WebContent");
    CHECK(obs->reason == "memory_pressure");
}

TEST_CASE("unknown bug_type is not a DEX signal", "[dex_macos]") {
    const std::string ips = R"({"bug_type":"199","name":"x"})"
                            "\n{\"foo\":1}";
    CHECK_FALSE(macos::parse_ips_report(ips).has_value());
}

// ── .diag resource report ────────────────────────────────────────────────────

TEST_CASE("real cpu_resource .diag maps to process.resource_limit", "[dex_macos][diag]") {
    const auto obs = macos::parse_diag_report(kRealCpuDiag);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "process.resource_limit");
    CHECK(obs->subject == "system_installd");
    CHECK(obs->reason == "cpu");
    CHECK(obs->metric == 90.0);
}

TEST_CASE("disk-writes .diag normalises to a stable reason token", "[dex_macos][diag]") {
    const std::string diag = "Command:          cloudd\nPID:              101\n\nEvent:            disk "
                             "writes\nWrites caused:    14 MB\n";
    const auto obs = macos::parse_diag_report(diag);
    REQUIRE(obs.has_value());
    CHECK(obs->subject == "cloudd");
    CHECK(obs->reason == "disk_writes");
}

// ── Uptime scalar ────────────────────────────────────────────────────────────

TEST_CASE("uptime_observation computes the uptime metric", "[dex_macos][uptime]") {
    const auto obs = macos::uptime_observation(1000, 1000 + 423266);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "os.uptime_report");
    CHECK(obs->subject == "host");
    CHECK(obs->metric == 423266.0);
}

TEST_CASE("uptime_observation guards bad inputs", "[dex_macos][uptime]") {
    CHECK_FALSE(macos::uptime_observation(0, 1000).has_value());     // no boot time
    CHECK_FALSE(macos::uptime_observation(-5, 1000).has_value());    // negative
    const auto clamped = macos::uptime_observation(2000, 1000);      // clock skew (now < boot)
    REQUIRE(clamped.has_value());
    CHECK(clamped->metric == 0.0);
}

// ── Robustness (these run on an OS watcher thread — must never throw) ─────────

TEST_CASE("malformed inputs return nullopt, never throw", "[dex_macos][robust]") {
    CHECK_FALSE(macos::parse_ips_report("").has_value());
    CHECK_FALSE(macos::parse_ips_report("not json at all").has_value());
    CHECK_FALSE(macos::parse_ips_report("{}").has_value());
    CHECK_FALSE(macos::parse_diag_report("").has_value());
    CHECK_FALSE(macos::parse_diag_report("Microstackshots header only\n").has_value());
}

// ── Unified log (OSLog) — service.crashed via launchd ────────────────────────

// Real launchd-exit ndjson line captured from the live box (a crash-looping
// service); structure preserved, the fields the extractor reads are intact.
static const char* kRealLaunchdExit =
    R"({"messageType":"Default","subsystem":"system\/com.apple.threadradiod [2699]",)"
    R"("processImagePath":"\/sbin\/launchd","timestamp":"2026-06-09 16:03:20.238403+0100",)"
    R"("eventMessage":"exited due to exit(1), ran for 2761ms","processID":1})";

TEST_CASE("real launchd abnormal exit maps to service.crashed", "[dex_macos][oslog]") {
    const auto obs = macos::parse_oslog_event(kRealLaunchdExit);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "service.crashed");
    CHECK(obs->subject == "com.apple.threadradiod"); // label from subsystem, no "[pid]"
    CHECK(obs->reason == "exit(1)");
    CHECK(obs->kind == "exit");
    CHECK(obs->metric == 2761.0); // ran for 2761ms
    CHECK(obs->platform.empty()); // engine stamps platform/timestamp, not the parser
}

TEST_CASE("launchd crash signal maps to service.crashed with the signal name",
          "[dex_macos][oslog]") {
    const std::string l =
        R"({"subsystem":"system\/com.apple.WindowServer [123]","processImagePath":"\/sbin\/launchd",)"
        R"("timestamp":"2026-06-11 10:00:00.0+0100","eventMessage":"exited due to signal SIGSEGV, ran for 50123ms"})";
    const auto obs = macos::parse_oslog_event(l);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "service.crashed");
    CHECK(obs->subject == "com.apple.WindowServer");
    CHECK(obs->reason == "SIGSEGV");
    CHECK(obs->kind == "signal");
}

TEST_CASE("clean exit(0) and intentional stops are NOT service crashes",
          "[dex_macos][oslog]") {
    const std::string clean =
        R"({"processImagePath":"\/sbin\/launchd","subsystem":"system\/com.apple.foo [1]",)"
        R"("timestamp":"2026-06-11 10:00:00.0+0100","eventMessage":"exited due to exit(0), ran for 10ms"})";
    CHECK_FALSE(macos::parse_oslog_event(clean).has_value());
    const std::string term =
        R"({"processImagePath":"\/sbin\/launchd","subsystem":"system\/com.apple.foo [1]",)"
        R"("timestamp":"2026-06-11 10:00:00.0+0100","eventMessage":"exited due to signal SIGTERM, ran for 9999ms"})";
    CHECK_FALSE(macos::parse_oslog_event(term).has_value()); // managed stop, not a crash
}

TEST_CASE("non-launchd / unparseable oslog lines are dropped", "[dex_macos][oslog][robust]") {
    CHECK_FALSE(macos::parse_oslog_event("").has_value());
    CHECK_FALSE(macos::parse_oslog_event("not json").has_value());
    CHECK_FALSE(macos::parse_oslog_event(R"({"processImagePath":"/usr/bin/other","eventMessage":"hi"})")
                    .has_value());
    // the predicate is non-empty and references each source class it understands
    for (const char* needle : {"launchd", "symptomsd", "softwareupdated", "apfs"})
        CHECK(macos::oslog_predicate().find(needle) != std::string::npos);
}

TEST_CASE("oslog_predicate requests Fault level alongside Error on both clauses",
          "[dex_macos][oslog][predicate]") {
    // logd only delivers what the predicate asks for — parse_oslog_event already
    // accepts Fault (line 169), but a clause left bare-Error means Fault records
    // from that clause never reach the parser. Count occurrences rather than a
    // plain substring("fault") check: that would pass even if only ONE of the
    // two error/fault clauses (process-group, com.apple.apfs) was converted,
    // leaving the other clause bare-error.
    const std::string pred = macos::oslog_predicate();
    const auto count = [&](const std::string& needle) {
        std::size_t n = 0, pos = 0;
        while ((pos = pred.find(needle, pos)) != std::string::npos) {
            ++n;
            pos += needle.size();
        }
        return n;
    };
    const std::size_t error_count = count(R"(messageType == "error")");
    const std::size_t fault_count = count(R"(messageType == "fault")");
    CHECK(error_count >= 2);
    CHECK(fault_count == error_count); // no bare error-without-fault clause remains
}

TEST_CASE("oslog non-finite runtime metric is clamped to 0 (no gauge poison)",
          "[dex_macos][oslog][robust]") {
    // std::stod("inf"/"nan") returns ±Inf/NaN WITHOUT throwing — governance B2.
    // A poisoned "ran for" value must not reach the metric gauge; the crash is
    // still reported, just with metric 0.
    for (const char* runtime : {"infms", "nanms", "1e400ms"}) {
        const std::string l =
            std::string(R"({"processImagePath":"\/sbin\/launchd",)") +
            R"("subsystem":"system\/com.apple.foo [1]","timestamp":"2026-06-11 10:00:00.0+0100",)" +
            R"("eventMessage":"exited due to signal SIGSEGV, ran for )" + runtime + R"("})";
        const auto obs = macos::parse_oslog_event(l);
        REQUIRE(obs.has_value());
        CHECK(obs->reason == "SIGSEGV");
        CHECK(std::isfinite(obs->metric));
        CHECK(obs->metric == 0.0);
    }
}

TEST_CASE("malformed launchd termination drops rather than leaking the message tail",
          "[dex_macos][oslog][privacy]") {
    // UP-6: when the signal/exit token is not a recognisable short form, the
    // parser must DROP (return nullopt) instead of shipping the raw tail — which
    // can carry a path or username — as `reason`.
    const char* base =
        R"({"processImagePath":"\/sbin\/launchd","subsystem":"system\/com.apple.foo [1]",)"
        R"("timestamp":"2026-06-11 10:00:00.0+0100","eventMessage":")";
    // a "signal " with a non-SIG tail (simulated PII) must not be emitted
    CHECK_FALSE(macos::parse_oslog_event(
                    std::string(base) + R"(exited due to signal /Users/alice/secret leaked"})")
                    .has_value());
    // an "exit(" with a non-numeric / unclosed code must not be emitted
    CHECK_FALSE(macos::parse_oslog_event(
                    std::string(base) + R"(exited due to exit(/Users/bob/path"})")
                    .has_value());
    // the legitimate short forms still parse (no false negatives)
    CHECK(macos::parse_oslog_event(std::string(base) + R"(exited due to signal SIGSEGV"})")
              .has_value()); // no trailing ", ran for" — still valid
}

// ── OSLog breadth: symptomsd network degradation + system-process errors ─────

TEST_CASE("symptomsd LQM degradation maps to network.wifi_drop", "[dex_macos][oslog][network]") {
    // Real symptomsd format from the live box (negative LQM + data-stalls = degraded).
    const std::string l =
        R"({"processImagePath":"\/usr\/libexec\/symptomsd","subsystem":"com.apple.symptomsd",)"
        R"("messageType":"Default","timestamp":"2026-06-11 07:41:29.0+0100",)"
        R"("eventMessage":"Realtime LQM changed: new-lqm -2 old-lqm 0 data-stalls 33.00 known-good 1 hot-spot 0 interface-type 3"})";
    const auto obs = macos::parse_oslog_event(l);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "network.wifi_drop");
    CHECK(obs->subject == "Wi-Fi");
    CHECK(obs->metric == 33.0); // data-stalls
}

TEST_CASE("symptomsd healthy LQM transition is not a signal", "[dex_macos][oslog][network]") {
    const std::string l =
        R"({"subsystem":"com.apple.symptomsd","messageType":"Default",)"
        R"("eventMessage":"Realtime LQM changed: new-lqm 1 old-lqm 0 data-stalls 0.00 known-good 1"})";
    CHECK_FALSE(macos::parse_oslog_event(l).has_value());
}

TEST_CASE("error-level system-process events map to their heading signal",
          "[dex_macos][oslog]") {
    struct Case {
        const char* proc;
        const char* subsystem;
        const char* expect;
    };
    const Case cases[] = {
        {"\\/usr\\/libexec\\/softwareupdated", "com.apple.SoftwareUpdate", "update.failed"},
        {"\\/usr\\/sbin\\/cupsd", "org.cups", "print.failed"},
        {"\\/usr\\/libexec\\/mdmclient", "com.apple.ManagedClient", "mgmt.mdm_error"},
        {"\\/usr\\/libexec\\/opendirectoryd", "com.apple.opendirectoryd", "logon.no_dc"},
    };
    for (const auto& c : cases) {
        const std::string l = std::string(R"({"messageType":"Error","processImagePath":")") +
                              c.proc + R"(","subsystem":")" + c.subsystem +
                              R"(","eventMessage":"some failure"})";
        const auto obs = macos::parse_oslog_event(l);
        REQUIRE(obs.has_value());
        CHECK(obs->obs_type == c.expect);
        // privacy: the raw eventMessage is NOT shipped (occurrence-based)
        CHECK(obs->reason.empty());
        CHECK(obs->sentence.find("some failure") == std::string::npos);
    }
}

TEST_CASE("apfs subsystem error maps to fs.corruption", "[dex_macos][oslog]") {
    const std::string l =
        R"({"messageType":"Error","processImagePath":"\/kernel","subsystem":"com.apple.apfs",)"
        R"("eventMessage":"apfs error"})";
    const auto obs = macos::parse_oslog_event(l);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "fs.corruption");
}

TEST_CASE("apfs subsystem Fault-level event maps to fs.corruption", "[dex_macos][oslog][issue-1372]") {
    // Issue #1372: fs.corruption was reachable only via Error-level records
    // because the predicate never requested Fault; parse_oslog_event itself
    // already accepted Fault, so this pins the previously-unreachable path
    // end to end once the predicate change lands.
    const std::string l =
        R"({"messageType":"Fault","processImagePath":"\/kernel","subsystem":"com.apple.apfs",)"
        R"("eventMessage":"apfs error"})";
    const auto obs = macos::parse_oslog_event(l);
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "fs.corruption");
}

TEST_CASE("non-DEX error-level process is dropped", "[dex_macos][oslog]") {
    const std::string l =
        R"({"messageType":"Error","processImagePath":"\/usr\/sbin\/bluetoothd","eventMessage":"x"})";
    CHECK_FALSE(macos::parse_oslog_event(l).has_value());
}

// ── IOKit hardware health: SMART + battery ───────────────────────────────────

TEST_CASE("healthy SMART + battery produce no signal", "[dex_macos][iokit]") {
    // Real outputs from the live box (healthy).
    CHECK(macos::parse_smart_status("   SMART Status:              Verified\n") == "Verified");
    CHECK_FALSE(macos::smart_observation("Verified", "disk0").has_value());
    CHECK_FALSE(macos::smart_observation("Not Supported", "disk0").has_value()); // no SMART != failure

    // Real `system_profiler SPPowerDataType` Health block, captured verbatim from
    // the macOS 26.5 box (note the deeper indentation — field() trims it).
    const auto h = macos::parse_battery_health(
        "      Health Information:\n          Cycle Count: 1\n          Condition: Normal\n"
        "          Maximum Capacity: 100%\n");
    CHECK(h.valid);
    CHECK(h.max_capacity_pct == 100);
    CHECK(h.cycle_count == 1);
    CHECK_FALSE(macos::battery_observation(h).has_value());
}

TEST_CASE("failing SMART maps to disk.smart_failure", "[dex_macos][iokit]") {
    const auto obs = macos::smart_observation("Failing", "disk0");
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "disk.smart_failure");
    CHECK(obs->reason == "Failing");
}

TEST_CASE("degraded battery maps to hw.error (battery)", "[dex_macos][iokit]") {
    auto bad_cond = macos::parse_battery_health(
        "      Cycle Count: 1200\n      Condition: Service Battery\n      Maximum Capacity: 81%\n");
    auto o1 = macos::battery_observation(bad_cond);
    REQUIRE(o1.has_value());
    CHECK(o1->obs_type == "hw.error");
    CHECK(o1->subject == "battery");
    CHECK(o1->reason == "Service Battery");

    auto low_cap = macos::parse_battery_health(
        "      Cycle Count: 900\n      Condition: Normal\n      Maximum Capacity: 72%\n");
    auto o2 = macos::battery_observation(low_cap);
    REQUIRE(o2.has_value());
    CHECK(o2->reason.find("72%") != std::string::npos);
}

TEST_CASE("no battery (desktop) produces no signal", "[dex_macos][iokit]") {
    const auto h = macos::parse_battery_health("Power:\n\n    AC Power:\n");
    CHECK_FALSE(h.valid);
    CHECK_FALSE(macos::battery_observation(h).has_value());
}

// ── Resource pressure: disk / thermal / memory ───────────────────────────────

TEST_CASE("healthy disk produces no storage.low", "[dex_macos][iokit][resource]") {
    // Real `df -k /System/Volumes/Data` line (macOS 26.5; note the inode columns).
    const char* df =
        "Filesystem    1024-blocks      Used Available Capacity iused      ifree %iused  Mounted on\n"
        "/dev/disk3s5    239311296  65734056 138099176    33%  616214 1380991760    0%   /System/Volumes/Data\n";
    const auto u = macos::parse_disk_usage(df);
    REQUIRE(u.valid);
    CHECK(u.capacity_pct == 33);          // first %-token, not the trailing %iused
    CHECK(u.available_kb == 138099176LL); // token before capacity
    CHECK_FALSE(macos::disk_observation(u, "Macintosh HD").has_value());
}

TEST_CASE("nearly-full disk maps to storage.low", "[dex_macos][iokit][resource]") {
    const char* by_pct =
        "/dev/disk3s5 239311296 230000000 9311296 96% 1 2 0% /System/Volumes/Data\n";
    const auto u1 = macos::parse_disk_usage(by_pct);
    auto o1 = macos::disk_observation(u1, "Macintosh HD");
    REQUIRE(o1.has_value());
    CHECK(o1->obs_type == "storage.low");
    CHECK(o1->reason == "96% full");
    CHECK(o1->metric == 96.0);

    // Triggered by absolute free bytes (<5 GiB) even at a modest capacity %.
    const char* by_free =
        "/dev/disk3s5 239311296 235000000 4000000 61% 1 2 0% /System/Volumes/Data\n";
    const auto u2 = macos::parse_disk_usage(by_free);
    CHECK(macos::disk_observation(u2, "Macintosh HD").has_value());
}

TEST_CASE("thermal throttle maps to hw.cpu_throttled", "[dex_macos][iokit][resource]") {
    // Real healthy pmset output.
    CHECK_FALSE(
        macos::thermal_observation("Note: No thermal warning level has been recorded\n").has_value());
    // Throttled form.
    const auto o = macos::thermal_observation(
        "CPU_Scheduler_Limit \t= 100\nCPU_Available_CPUs \t= 8\nCPU_Speed_Limit \t= 70\n");
    REQUIRE(o.has_value());
    CHECK(o->obs_type == "hw.cpu_throttled");
    CHECK(o->metric == 70.0);
    // Full speed (100) is not throttled.
    CHECK_FALSE(macos::thermal_observation("CPU_Speed_Limit \t= 100\n").has_value());
}

TEST_CASE("low memory maps to memory.exhausted", "[dex_macos][iokit][resource]") {
    // Real healthy output.
    CHECK_FALSE(
        macos::memory_pressure_observation("System-wide memory free percentage: 54%\n").has_value());
    const auto o =
        macos::memory_pressure_observation("System-wide memory free percentage: 6%\n");
    REQUIRE(o.has_value());
    CHECK(o->obs_type == "memory.exhausted");
    CHECK(o->subject == "system");
    CHECK(o->metric == 6.0);
}
