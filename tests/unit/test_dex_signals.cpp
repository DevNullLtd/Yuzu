/**
 * test_dex_signals.cpp — Guardian DEX multi-signal catalogue + observer + wire.
 *
 * Covers the cross-platform, pure pieces (testable on every host even though real
 * data only flows on Windows):
 *   - catalogue integrity (20 distinct obs_types, channels, caps, extractors)
 *   - extract_named_data() / extract_system_fields() XML parsing + tolerance
 *   - per-signal extractors via extract_signal(), INCLUDING the privacy drops
 *     (DNS queried name, print document name/owner, profile username — works-
 *     council/data-minimisation contract: user content never leaves the device)
 *   - signal_observation_to_event() maps to a RULELESS DEX event (sentinel
 *     rule_id + event_type, no guard_category, no expected_value) — pins the
 *     taxonomy decision; uniform detail_json keys + crash legacy-key dual-emit
 *   - make_dex_observer() is never null; off-Windows it is a no-op
 */

#include <yuzu/agent/dex_observer.hpp>
#include <yuzu/agent/dex_signal_catalog.hpp>

#include "dex_event.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <iterator> // std::size
#include <set>
#include <string>
#include <vector>

using namespace yuzu::agent;

// ── Catalogue integrity ──────────────────────────────────────────────────────

// THE 70-type taxonomy — the drift net. This list is mirrored (as labels +
// groups) in tests/unit/server/test_dex_routes.cpp; adding a catalogue signal
// fails this count until both sides are updated together.
static const char* kAllObsTypes[] = {
    // wave 1
    "process.crashed", "process.hung", "service.crashed", "service.start_failed", "os.bugcheck",
    "os.power_loss", "display.driver_reset", "hw.error", "disk.error", "fs.corruption",
    "memory.exhausted", "os.boot", "update.failed", "app_install.failed", "logon.temp_profile",
    "gpo.failed", "network.wifi_drop", "network.dns_timeout", "network.ip_conflict",
    "print.failed",
    // wave 2
    "boot.degraded_app", "boot.degraded_driver", "boot.degraded_service", "boot.degraded_device",
    "os.shutdown", "shutdown.degraded", "os.standby", "os.standby_degraded",
    "logon.slow_subscriber", "os.uptime_report", "os.dirty_shutdown", "os.time_unsynced",
    "os.activation_failed", "os.vss_error", "fs.hive_recovered", "fs.autochk_ran",
    "process.crashed_managed", "app.sxs_error", "app.activation_failed", "app.com_failed",
    "app.error_popup", "app.shutdown_blocked", "service.hung", "service.start_timeout",
    "service.logon_failed", "service.recovery_failed", "disk.smart_failure", "disk.port_reset",
    "fs.write_lost", "fs.database_corrupt", "hw.device_start_failed", "hw.cpu_throttled",
    "network.wifi_connect_failed", "network.dhcp_failed", "network.vpn_failed",
    "network.smb_failed", "network.name_conflict", "logon.no_dc", "security.kerberos_error",
    "logon.profile_locked", "logon.folder_redirect_failed", "security.rtp_disabled",
    "security.threat_detected", "security.av_update_failed", "security.tamper_blocked",
    "app_uninstall.failed", "app_install.appx_failed", "update.transfer_failed",
    "print.driver_install_failed", "print.plugin_failed",
    // wave 3
    "boot.fast_startup_failed", "os.resume_report", "os.restart_initiated",
    "os.shadow_copies_lost", "os.crashdump_disabled", "display.dwm_exited",
    "process.file_access_failure", "app.push_notification_error", "app.file_association_reset",
    "app.staterepo_error", "service.dependency_failed", "fs.flush_failed",
    "hw.user_driver_error", "hw.tpm_error", "network.port_exhaustion", "network.smb_write_lost",
    "network.dns_register_failed", "session.rdp_disconnected", "logon.winlogon_terminated",
    "logon.machine_trust_failed", "logon.biometric_error", "logon.hello_error",
    "logon.aad_token_error", "security.auth_error", "security.tls_alert",
    "security.threat_action_failed", "security.rtp_error", "security.bitlocker_error",
    "security.cert_enroll_failed", "update.check_failed", "update.download_failed",
    "gpo.cse_failed", "mgmt.mdm_error",
    // wave 4 (2026-06-22) — power-management + driver reliability
    "os.modern_standby_exit", "network.adapter_driver_dump", "hw.driver_load_failed",
    "hw.battery_error",
    // wave 4 batch 2 — cheap additions on already-armed channels
    "service.unresponsive", "service.shutdown_failed", "network.adapter_reset",
};

TEST_CASE("catalogue: 110 distinct obs_types, every spec complete", "[dex][catalog]") {
    const auto& cat = dex_signal_catalog();
    std::set<std::string> types;
    for (const auto& s : cat) {
        types.insert(s.obs_type);
        CHECK_FALSE(std::string(s.obs_type).empty());
        CHECK_FALSE(std::string(s.channel).empty());
        CHECK_FALSE(std::string(s.provider).empty());
        CHECK(s.max_per_hour > 0);          // every signal is rate-capped
        CHECK(s.extract != nullptr);
        // An any-id spec must carry a level filter (WHEA) — otherwise it would
        // subscribe to a provider's whole firehose.
        if (s.event_ids.empty())
            CHECK(s.max_level > 0);
    }
    // The Windows AGENT event catalogue contract: exactly 110 obs_types. The
    // SERVER's display catalogue (dex_signal_groups(), pinned at 114 by
    // test_dex_routes.cpp) is intentionally larger — it adds the POLL-sourced
    // types that never enter this EvtSubscribe catalogue: `storage.low`
    // (macOS df poll + Windows state poll) and the three A3 `perf.*` breach
    // types (dex_perf_breach via the state poller). The two counts therefore
    // differ BY DESIGN; each side's drift-net still bites for its own additions.
    CHECK(types.size() == std::size(kAllObsTypes)); // 110 Windows signals
    // Absolute pin (governance consistency N1): the array-relative check above passes
    // at ANY count if kAllObsTypes and the catalogue drift together. Bind the
    // documented 110 directly so a silent +1/-1 to both still fails here.
    CHECK(types.size() == 110u);
    CHECK(std::size(kAllObsTypes) == 110u);
    for (const char* t : kAllObsTypes)
        CHECK(types.count(t) == 1);
}

TEST_CASE("catalogue: every extractor degrades gracefully on empty fields",
          "[dex][catalog]") {
    // A drifted/forged event yields empty or reordered fields — every extractor
    // must NEVER THROW. The norm is a well-formed observation (obs_type stamped by
    // extract_signal) so the occurrence still counts. A few extractors are
    // intentionally selective: a matched event that empty fields cannot confirm as
    // a real signal (the benign-mostly types below) cleanly SUPPRESSES (nullopt)
    // rather than counting a non-event. Both outcomes are valid; a throw is not.
    static const std::set<std::string> kMaySuppressOnEmpty = {
        "hw.battery_error", // KP521 fires on every battery-count change; only Error/
                            // Abandoned > 0 is a signal — empty fields ⇒ not a fault
    };
    for (const auto& s : dex_signal_catalog()) {
        const int id = s.event_ids.empty() ? 1 : s.event_ids.front();
        const int level = s.max_level > 0 ? s.max_level : 2;
        std::optional<SignalObservation> o;
        REQUIRE_NOTHROW(o = extract_signal(s.channel, s.provider, id, level, {}));
        if (!o) {
            CHECK(kMaySuppressOnEmpty.count(s.obs_type) == 1); // only the listed types may suppress
            continue;
        }
        CHECK(o->obs_type == s.obs_type);
        CHECK_FALSE(o->sentence.empty()); // detected_value never blank
    }
}

TEST_CASE("catalogue: channels + per-channel QueryList structure", "[dex][catalog]") {
    const auto channels = dex_channels();
    CHECK(channels.size() == 22);
    CHECK(std::find(channels.begin(), channels.end(), "Application") != channels.end());
    CHECK(std::find(channels.begin(), channels.end(), "System") != channels.end());

    for (const auto& ch : channels) {
        const std::string q = dex_channel_query(ch);
        CHECK(q.starts_with("<QueryList>"));
        CHECK(q.ends_with("</QueryList>"));
        CHECK(q.find("Path=\"" + ch + "\"") != std::string::npos);
        CHECK(q.find("<Select") != std::string::npos);
    }
    // The System query carries the SCM + WHEA clauses (one Select per spec, so no
    // single XPath approaches winevt's 32-expression limit).
    const std::string sys = dex_channel_query("System");
    CHECK(sys.find("Provider[@Name='Service Control Manager']") != std::string::npos);
    CHECK(sys.find("EventID=7031 or EventID=7034") != std::string::npos);
    CHECK(sys.find("Provider[@Name='Microsoft-Windows-WHEA-Logger']") != std::string::npos);
    CHECK(sys.find("Level=1 or Level=2 or Level=3") != std::string::npos);
}

// ── NTSTATUS mapping (unchanged from slice 1) ───────────────────────────────

TEST_CASE("symbolic_exception_name maps known NTSTATUS codes", "[crash][parse]") {
    CHECK(symbolic_exception_name(0xC0000005) == "ACCESS_VIOLATION");
    CHECK(symbolic_exception_name(0xC0000409) == "STACK_BUFFER_OVERRUN");
    CHECK(symbolic_exception_name(0xC0000602) == "FAIL_FAST_EXCEPTION");
    CHECK(symbolic_exception_name(0x80000003) == "BREAKPOINT");
    CHECK(symbolic_exception_name(0xE0434352) == "CLR_EXCEPTION"); // managed (.NET) escape
    CHECK(symbolic_exception_name(0x00000001).empty()); // unknown -> ""
}

// A REAL Application Error (Event ID 1000) record captured from a Win11 box
// (10.0.26100) via `wevtutil qe Application "/q:*[System[(EventID=1000)]]"`. The
// Data elements are NAMED (not unnamed positional) and ProcessId is hex with a
// 0x prefix — exactly the assumptions this verifies end-to-end (XML -> fields ->
// SignalObservation), the path that never runs off a live event log.
constexpr const char* kRealEvent1000Xml =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Application Error'/><EventID>1000</EventID><Level>2</Level>"
    "<TimeCreated SystemTime='2026-05-12T11:41:12.8358842Z'/><Channel>Application</Channel>"
    "</System><EventData>"
    "<Data Name='AppName'>AOTListenerService.exe</Data>"
    "<Data Name='AppVersion'>25.11.10.8</Data>"
    "<Data Name='AppTimeStamp'>684a0000</Data>"
    "<Data Name='ModuleName'>KERNELBASE.dll</Data>"
    "<Data Name='ModuleVersion'>10.0.26100.8246</Data>"
    "<Data Name='ModuleTimeStamp'>2614674e</Data>"
    "<Data Name='ExceptionCode'>c0000005</Data>"
    "<Data Name='FaultingOffset'>00164644</Data>"
    "<Data Name='ProcessId'>0x297c</Data>"
    "<Data Name='ProcessCreationTime'>0x1dce20439beaba3</Data>"
    "<Data Name='AppPath'>C:\\Program Files (x86)\\Citrix\\ICA Client\\AOTListenerService.exe</Data>"
    "<Data Name='ModulePath'>C:\\WINDOWS\\System32\\KERNELBASE.dll</Data>"
    "<Data Name='IntegratorReportId'>d2848160-2b5d-4ac6-b12e-5d430fe29fff</Data>"
    "<Data Name='PackageFullName'></Data>"
    "<Data Name='PackageRelativeAppId'></Data>"
    "</EventData></Event>";

// ── XML parsing (named data + system fields) ─────────────────────────────────

TEST_CASE("extract_named_data on a real Event 1000 XML", "[crash][parse]") {
    const auto fields = extract_named_data(kRealEvent1000Xml);
    // 15 named Data elements (incl. two empty package fields).
    REQUIRE(fields.size() == 15);
    CHECK(fields[0].first == "AppName");
    CHECK(fields[0].second == "AOTListenerService.exe");
    CHECK(fields.back().first == "PackageRelativeAppId");
    CHECK(fields.back().second.empty()); // empty <Data Name='...'></Data>
}

TEST_CASE("extract_system_fields on a real Event 1000 XML", "[dex][parse]") {
    const auto sys = extract_system_fields(kRealEvent1000Xml);
    CHECK(sys.provider == "Application Error");
    CHECK(sys.event_id == 1000);
    CHECK(sys.level == 2);
    CHECK(sys.channel == "Application");
}

TEST_CASE("extract_system_fields tolerates Qualifiers attr, quotes, and absence",
          "[dex][parse]") {
    // Classic events render <EventID Qualifiers='49152'>7031</EventID>.
    const auto a = extract_system_fields(
        "<Event><System><Provider Name=\"Service Control Manager\"/>"
        "<EventID Qualifiers='49152'>7031</EventID><Channel>System</Channel></System></Event>");
    CHECK(a.provider == "Service Control Manager");
    CHECK(a.event_id == 7031);
    CHECK(a.level == 0); // absent -> default
    CHECK(a.channel == "System");

    // Malformed / empty input must never throw.
    CHECK_NOTHROW(extract_system_fields(""));
    CHECK_NOTHROW(extract_system_fields("<Event><System><EventID>oops</EventID>"));
    CHECK(extract_system_fields("").event_id == 0);
}

TEST_CASE("extract_named_data handles double-quoted attrs and self-closing Data",
          "[crash][parse]") {
    // EvtRender may use either quote style; a self-closing empty Data must not break.
    const auto f = extract_named_data(
        "<EventData><Data Name=\"AppName\">a.exe</Data><Data Name=\"X\"/></EventData>");
    REQUIRE(f.size() == 2);
    CHECK(f[0].first == "AppName");
    CHECK(f[0].second == "a.exe");
    CHECK(f[1].first == "X");
    CHECK(f[1].second.empty());
}

TEST_CASE("extract_named_data tolerates malformed XML without crashing", "[crash][parse]") {
    // The Application channel is world-writable: any local process can emit a crafted
    // Event 1000. The parser must never crash on malformed input — it returns what it
    // could parse (or nothing) and the caller defaults the rest.
    CHECK(extract_named_data("").empty());                         // empty input
    CHECK(extract_named_data("<EventData></EventData>").empty());  // no Data elements
    // Unterminated tag (no closing '>') — stop, don't read out of bounds.
    CHECK_NOTHROW(extract_named_data("<EventData><Data Name='X'"));
    // Missing </Data> — return what was parsed so far without overrunning.
    CHECK_NOTHROW(extract_named_data("<EventData><Data Name='X'>val"));
    // A Data element with no Name= attribute -> empty name, value preserved
    // (classic positional events rely on exactly this).
    const auto noname = extract_named_data("<EventData><Data>v</Data></EventData>");
    REQUIRE(noname.size() == 1);
    CHECK(noname[0].first.empty());
    CHECK(noname[0].second == "v");
}

// ── Per-signal extractors (via the single extract_signal entry) ──────────────

TEST_CASE("extract_signal: crash (real Event 1000) fills the uniform shape", "[crash][parse]") {
    const auto fields = extract_named_data(kRealEvent1000Xml);
    const auto o = extract_signal("Application", "Application Error", 1000, 2, fields);
    REQUIRE(o);
    CHECK(o->obs_type == "process.crashed");
    CHECK(o->subject == "AOTListenerService.exe");
    CHECK(o->version == "25.11.10.8"); // AppVersion → joins to procperf (name, version)
    CHECK(o->component == "KERNELBASE.dll");
    CHECK(o->reason == "0xC0000005");
    CHECK(o->symbolic == "ACCESS_VIOLATION");
    CHECK(o->pid == 0x297cu);
    CHECK(o->kind == "exception");
    CHECK(o->platform == "windows");
    // Sentence format kept byte-compatible with slice 1 for /events continuity.
    CHECK(o->sentence.find("AOTListenerService.exe pid=10620 code=0xC0000005") !=
          std::string::npos);
    CHECK(o->sentence.find("module=KERNELBASE.dll") != std::string::npos);
    // PRIVACY: AppPath present in the event but never extracted.
    CHECK(o->sentence.find("Citrix") == std::string::npos);
}

TEST_CASE("extract_signal: crash tolerates missing/garbage fields", "[crash][parse]") {
    const auto empty = extract_signal("Application", "Application Error", 1000, 2, {});
    REQUIRE(empty);
    CHECK(empty->subject.empty());
    CHECK(empty->pid == 0u);
    CHECK(empty->reason == "0x00000000");

    const EventFields garbage = {
        {"AppName", "x.exe"}, {"ProcessId", "not-a-pid"}, {"ExceptionCode", "0xZZZZ"}};
    const auto o = extract_signal("Application", "Application Error", 1000, 2, garbage);
    REQUIRE(o);
    CHECK(o->subject == "x.exe");
    CHECK(o->pid == 0u);
    CHECK(o->reason == "0x00000000"); // garbage hex -> 0, never throws
}

TEST_CASE("extract_signal: hang (1002, classic positional)", "[dex][parse]") {
    // Application Hang renders UNNAMED positional Data.
    const EventFields f = {{"", "Teams.exe"}, {"", "1.6.0"}, {"", "11c8"}};
    const auto o = extract_signal("Application", "Application Hang", 1002, 2, f);
    REQUIRE(o);
    CHECK(o->obs_type == "process.hung");
    CHECK(o->subject == "Teams.exe");
    CHECK(o->version == "1.6.0.0"); // positional [1] = hung app's version, padded to the 4-group quad
    CHECK(o->kind == "hang");
    CHECK(o->symbolic == "NOT_RESPONDING");
    CHECK(o->pid == 0x11c8u);
    CHECK(o->sentence.find("Teams.exe stopped responding") != std::string::npos);
}

TEST_CASE("extract_signal: crash version canonicalizes to the procperf quad", "[crash][parse]") {
    auto ver = [](const std::string& v) {
        const EventFields f = {{"AppName", "a.exe"}, {"AppVersion", v}, {"ExceptionCode", "0x1"}};
        return extract_signal("Application", "Application Error", 1000, 2, f)->version;
    };
    // WER's normal case: already the fixed quad → unchanged (joins to procperf).
    CHECK(ver("6.15.101.7085") == "6.15.101.7085");
    // StringFileInfo suffix (live-observed on explorer.exe) → leading quad only.
    CHECK(ver("10.0.26100.8457 (WinBuild.160101.0800)") == "10.0.26100.8457");
    // "no version resource" sentinel and empty both → "" (the single unknown bucket).
    CHECK(ver("0.0.0.0").empty());
    CHECK(ver("").empty());
    // Store/packaged apps report no AppVersion in event 1000 → "" (honest blank).
    CHECK(ver("not.a.version").empty());     // non-numeric → no leading group → ""
    // ARITY FIX (UP-2): a short WER version pads to the 4-group quad so it joins
    // procperf (which always emits 4 groups). Was "3.2" — a silent join miss.
    CHECK(ver("3.2") == "3.2.0.0");
}

TEST_CASE("extract_signal: service crash 7031/7034 + start failure 7000", "[dex][parse]") {
    const EventFields named = {{"param1", "Print Spooler"}, {"param2", "1"}};
    const auto a = extract_signal("System", "Service Control Manager", 7031, 2, named);
    REQUIRE(a);
    CHECK(a->obs_type == "service.crashed");
    CHECK(a->subject == "Print Spooler");
    CHECK(a->sentence.find("terminated unexpectedly") != std::string::npos);

    const auto b = extract_signal("System", "Service Control Manager", 7034, 2, named);
    REQUIRE(b);
    CHECK(b->obs_type == "service.crashed");
    CHECK(b->sentence.find("no recovery") != std::string::npos);

    // Positional fallback (classic rendering without param names).
    const EventFields positional = {{"", "Windows Search"}, {"", "The service did not respond"}};
    const auto c = extract_signal("System", "Service Control Manager", 7000, 2, positional);
    REQUIRE(c);
    CHECK(c->obs_type == "service.start_failed");
    CHECK(c->subject == "Windows Search");
    CHECK(c->reason.find("did not respond") != std::string::npos);

    // The raw message-resource form ("%%1053", live-observed on Win11 for the
    // start-timeout path) is surfaced as the error number it encodes.
    const EventFields msgref = {{"param1", "YuzuDexCanarySvc"}, {"param2", "%%1053"}};
    const auto d = extract_signal("System", "Service Control Manager", 7000, 2, msgref);
    REQUIRE(d);
    CHECK(d->reason == "error 1053");
    CHECK(d->sentence.find("error 1053") != std::string::npos);
}

TEST_CASE("extract_signal: bugcheck under both provider spellings", "[dex][parse]") {
    const EventFields f = {{"param1", "0x0000007e (0xffffffffc0000005, 0x0, 0x0, 0x0)"}};
    const auto a =
        extract_signal("System", "Microsoft-Windows-WER-SystemErrorReporting", 1001, 2, f);
    REQUIRE(a);
    CHECK(a->obs_type == "os.bugcheck");
    CHECK(a->reason == "0x0000007e"); // first token only
    const auto b = extract_signal("System", "BugCheck", 1001, 2, f);
    REQUIRE(b);
    CHECK(b->obs_type == "os.bugcheck");
}

TEST_CASE("extract_signal: kernel-power 41 distinguishes bugcheck vs power loss",
          "[dex][parse]") {
    const auto power = extract_signal("System", "Microsoft-Windows-Kernel-Power", 41, 1,
                                      {{"BugcheckCode", "0"}});
    REQUIRE(power);
    CHECK(power->obs_type == "os.power_loss");
    CHECK(power->reason == "power loss");

    const auto bug = extract_signal("System", "Microsoft-Windows-Kernel-Power", 41, 1,
                                    {{"BugcheckCode", "126"}});
    REQUIRE(bug);
    CHECK(bug->reason == "bugcheck 126");
}

TEST_CASE("extract_signal: WHEA any-id + level filter", "[dex][parse]") {
    // Any event id from the provider matches (the spec has an empty id list)…
    const auto hit = extract_signal("System", "Microsoft-Windows-WHEA-Logger", 18, 2, {});
    REQUIRE(hit);
    CHECK(hit->obs_type == "hw.error");
    CHECK(hit->reason == "whea-18");
    // …but only at warning level or worse: an informational (level 4) corrected-
    // error record is filtered out (the pure mirror of the kernel-side filter).
    CHECK_FALSE(extract_signal("System", "Microsoft-Windows-WHEA-Logger", 18, 4, {}));
    CHECK_FALSE(extract_signal("System", "Microsoft-Windows-WHEA-Logger", 18, 0, {}));
}

TEST_CASE("extract_signal: disk errors map per-id symbolics", "[dex][parse]") {
    const EventFields f = {{"", "\\Device\\Harddisk0\\DR0"}};
    const auto bad = extract_signal("System", "disk", 7, 2, f);
    REQUIRE(bad);
    CHECK(bad->obs_type == "disk.error");
    CHECK(bad->symbolic == "BAD_BLOCK");
    const auto paging = extract_signal("System", "disk", 51, 3, f);
    REQUIRE(paging);
    CHECK(paging->symbolic == "PAGING_ERROR");
    const auto retried = extract_signal("System", "disk", 153, 3, f);
    REQUIRE(retried);
    CHECK(retried->symbolic == "IO_RETRIED");
}

TEST_CASE("extract_signal: boot report carries the duration metric", "[dex][parse]") {
    const auto o = extract_signal("Microsoft-Windows-Diagnostics-Performance/Operational",
                                  "Microsoft-Windows-Diagnostics-Performance", 100, 3,
                                  {{"BootTime", "43210"}, {"MainPathBootTime", "12345"}});
    REQUIRE(o);
    CHECK(o->obs_type == "os.boot");
    CHECK(o->metric == 43210.0);
    CHECK(o->sentence.find("43210 ms") != std::string::npos);

    // Garbage / non-finite durations must not poison the fleet aggregate.
    const auto inf = extract_signal("Microsoft-Windows-Diagnostics-Performance/Operational",
                                    "Microsoft-Windows-Diagnostics-Performance", 100, 3,
                                    {{"BootTime", "inf"}});
    REQUIRE(inf);
    CHECK(inf->metric == 0.0);
    const auto neg = extract_signal("Microsoft-Windows-Diagnostics-Performance/Operational",
                                    "Microsoft-Windows-Diagnostics-Performance", 100, 3,
                                    {{"BootTime", "-5"}});
    REQUIRE(neg);
    CHECK(neg->metric == 0.0);
}

TEST_CASE("extract_signal: update + MSI install failures", "[dex][parse]") {
    const auto u = extract_signal("System", "Microsoft-Windows-WindowsUpdateClient", 20, 2,
                                  {{"errorCode", "0x80070643"},
                                   {"updateTitle", "2026-06 Cumulative Update (KB5055555)"}});
    REQUIRE(u);
    CHECK(u->obs_type == "update.failed");
    CHECK(u->subject.find("KB5055555") != std::string::npos);
    CHECK(u->reason == "0x80070643");

    const auto m = extract_signal("Application", "MsiInstaller", 11708, 2,
                                  {{"", "Product: Contoso CRM 11 -- Installation failed."}});
    REQUIRE(m);
    CHECK(m->obs_type == "app_install.failed");
    CHECK(m->subject == "Contoso CRM 11"); // parsed between "Product: " and " -- "
}

// ── Privacy drops (works-council / data-minimisation contract) ───────────────

TEST_CASE("PRIVACY: dns timeout never extracts the queried name", "[dex][parse][privacy]") {
    // The 1014 event carries the queried hostname — browsing behavior. The
    // extractor must not read the field: nothing the user typed may appear in
    // ANY output field.
    const auto o = extract_signal("System", "Microsoft-Windows-DNS Client Events", 1014, 3,
                                  {{"QueryName", "very-private-website.example.com"},
                                   {"AddressLength", "16"}});
    REQUIRE(o);
    CHECK(o->obs_type == "network.dns_timeout");
    for (const std::string& field :
         {o->subject, o->reason, o->symbolic, o->component, o->sentence})
        CHECK(field.find("very-private-website") == std::string::npos);
    CHECK(o->sentence.find("withheld") != std::string::npos); // says so explicitly
}

TEST_CASE("PRIVACY: print failure keeps the printer, drops document + owner",
          "[dex][parse][privacy]") {
    const auto o = extract_signal("Microsoft-Windows-PrintService/Admin",
                                  "Microsoft-Windows-PrintService", 372, 2,
                                  {{"Param1", "57"},
                                   {"Param2", "my_resignation_letter.docx"},
                                   {"Param3", "DOMAIN\\dave.rae"},
                                   {"Param4", "HQ-Laser-3"}});
    REQUIRE(o);
    CHECK(o->obs_type == "print.failed");
    CHECK(o->subject == "HQ-Laser-3"); // printer = infrastructure, kept
    for (const std::string& field :
         {o->subject, o->reason, o->symbolic, o->component, o->sentence}) {
        CHECK(field.find("resignation") == std::string::npos);
        CHECK(field.find("dave.rae") == std::string::npos);
    }
}

TEST_CASE("PRIVACY: temp profile never extracts the username", "[dex][parse][privacy]") {
    const auto o = extract_signal("Application", "Microsoft-Windows-User Profiles Service", 1511,
                                  2, {{"", "DOMAIN\\jane.doe"}});
    REQUIRE(o);
    CHECK(o->obs_type == "logon.temp_profile");
    CHECK(o->symbolic == "TEMP_PROFILE");
    for (const std::string& field :
         {o->subject, o->reason, o->symbolic, o->component, o->sentence})
        CHECK(field.find("jane.doe") == std::string::npos);
}

TEST_CASE("extract_signal: wifi drop keeps SSID + reason; ip conflict positional",
          "[dex][parse]") {
    const auto w = extract_signal("Microsoft-Windows-WLAN-AutoConfig/Operational",
                                  "Microsoft-Windows-WLAN-AutoConfig", 8003, 4,
                                  {{"SSID", "CorpNet"},
                                   {"Reason", "The network is disconnected by the driver"},
                                   {"InterfaceDescription", "Intel(R) Wi-Fi 6E AX211"}});
    REQUIRE(w);
    CHECK(w->obs_type == "network.wifi_drop");
    CHECK(w->subject == "CorpNet");
    CHECK(w->component.find("AX211") != std::string::npos);

    const auto ip = extract_signal("System", "Tcpip", 4199, 2,
                                   {{"", "10.0.0.15"}, {"", "00-1B-44-11-3A-B7"}});
    REQUIRE(ip);
    CHECK(ip->obs_type == "network.ip_conflict");
    CHECK(ip->subject == "10.0.0.15");
    CHECK(ip->component == "00-1B-44-11-3A-B7");
}

TEST_CASE("extract_signal: uncatalogued events return nullopt", "[dex][parse]") {
    CHECK_FALSE(extract_signal("Application", "Some Random Provider", 1000, 2, {}));
    CHECK_FALSE(extract_signal("System", "Service Control Manager", 9999, 2, {}));
    CHECK_FALSE(extract_signal("", "", 0, 0, {}));
}

TEST_CASE("extract_signal: provider/channel match is case-insensitive (Windows semantics)",
          "[dex][parse][real]") {
    // LIVE-CAUGHT (injection sweep 2026-06-11): the spec says "volsnap" but the
    // log renders Provider Name='Volsnap' — Windows name matching is
    // case-insensitive and delivered the event; a case-sensitive lookup dropped
    // it post-delivery. Pin the rendered casing end-to-end.
    const auto o = extract_signal("System", "Volsnap", 25, 2, {{"", "C:"}});
    REQUIRE(o);
    CHECK(o->obs_type == "os.shadow_copies_lost");
    // Channel casing too.
    const auto c = extract_signal("SYSTEM", "service control manager", 7031, 2,
                                  {{"param1", "Svc"}});
    REQUIRE(c);
    CHECK(c->obs_type == "service.crashed");
}

// ── REAL captured records (Win11 26100, harvested 2026-06-10) ────────────────
// Full-chain pins (XML -> system fields + named data -> extract_signal) against
// REAL event-log records from a live box — the same discipline as the crash
// fixture. These are the records that promoted their extractors from
// "manifest-best-effort" to "verified against a real capture".

namespace {
// SCM 7031 — a real service crash ("HP Insights Analytics"): named param1..param5.
constexpr const char* kReal7031 =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' "
    "EventSourceName='Service Control Manager'/><EventID Qualifiers='49152'>7031</EventID>"
    "<Version>0</Version><Level>2</Level><Channel>System</Channel></System><EventData>"
    "<Data Name='param1'>HP Insights Analytics</Data><Data Name='param2'>1</Data>"
    "<Data Name='param3'>30000</Data><Data Name='param4'>1</Data>"
    "<Data Name='param5'>Restart the service</Data>"
    "<Binary>480070005400</Binary></EventData></Event>";

// Kernel-Power 41 — a real unexpected reboot with BugcheckCode 0 (pure power loss).
constexpr const char* kReal41 =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-Kernel-Power' Guid='{331c3b3a-2005-44c2-ac5e-77220c37d6b4}'/>"
    "<EventID>41</EventID><Version>10</Version><Level>1</Level><Channel>System</Channel></System>"
    "<EventData><Data Name='BugcheckCode'>0</Data><Data Name='BugcheckParameter1'>0x0</Data>"
    "<Data Name='SleepInProgress'>0</Data><Data Name='PowerButtonTimestamp'>0</Data>"
    "<Data Name='LidState'>1</Data><Data Name='WHEABootErrorCount'>0</Data></EventData></Event>";

// Diagnostics-Performance 100 — a real 64.9 s boot (BootTime in ms, named).
constexpr const char* kReal100 =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-Diagnostics-Performance' "
    "Guid='{cfc18ec0-96b1-4eba-961b-622caee05b0a}'/><EventID>100</EventID><Version>2</Version>"
    "<Level>2</Level><Channel>Microsoft-Windows-Diagnostics-Performance/Operational</Channel>"
    "</System><EventData><Data Name='BootTsVersion'>2</Data>"
    "<Data Name='BootStartTime'>2026-06-09T14:00:12.7424637Z</Data>"
    "<Data Name='SystemBootInstance'>11</Data><Data Name='BootTime'>64934</Data>"
    "<Data Name='MainPathBootTime'>29434</Data><Data Name='BootKernelInitTime'>33</Data>"
    "<Data Name='BootIsDegradation'>false</Data><Data Name='UserLogonWaitDuration'>5375</Data>"
    "</EventData></Event>";

// WindowsUpdateClient 20 — a real store-app update failure (named errorCode/title).
constexpr const char* kReal20 =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-WindowsUpdateClient' "
    "Guid='{945a8954-c147-4acd-923f-40c45405a658}'/><EventID>20</EventID><Version>1</Version>"
    "<Level>2</Level><Channel>System</Channel></System><EventData>"
    "<Data Name='errorCode'>0x80073d02</Data>"
    "<Data Name='updateTitle'>9MSSGKG348SP-MicrosoftWindows.Client.WebExperience</Data>"
    "<Data Name='updateGuid'>{6cfae217-28ff-4d71-9d9b-ebbc16a3041c}</Data>"
    "<Data Name='updateRevisionNumber'>1</Data></EventData></Event>";

// MsiInstaller 11708 — a real MSI install failure: classic UNNAMED positional Data
// (plus (NULL) filler + a Binary element the parser must skip).
constexpr const char* kReal11708 =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='MsiInstaller'/><EventID Qualifiers='0'>11708</EventID><Version>0</Version>"
    "<Level>4</Level><Channel>Application</Channel></System><EventData>"
    "<Data>Product: Zoom VDI Plugin Management(64bit) -- Installation failed.</Data>"
    "<Data>(NULL)</Data><Data>(NULL)</Data><Data>(NULL)</Data>"
    "<Binary>7B4432383537</Binary></EventData></Event>";

// WLAN-AutoConfig 8003 — a real Wi-Fi disconnect. NOTE: Level 4 (informational) —
// pins that the wifi spec carries NO level filter (a max_level would silence it).
constexpr const char* kReal8003 =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-WLAN-AutoConfig' "
    "Guid='{9580d7dd-0379-4658-9870-d5be7d52d6de}'/><EventID>8003</EventID><Version>0</Version>"
    "<Level>4</Level><Channel>Microsoft-Windows-WLAN-AutoConfig/Operational</Channel></System>"
    "<EventData><Data Name='InterfaceGuid'>{61bf35ae-4999-4499-a618-0d74fab75d8d}</Data>"
    "<Data Name='InterfaceDescription'>Intel(R) Wi-Fi 6 AX201 160MHz</Data>"
    "<Data Name='ConnectionMode'>Automatic connection with a profile</Data>"
    "<Data Name='ProfileName'>Samsung Smart Fridge</Data>"
    "<Data Name='SSID'>Samsung Smart Fridge</Data><Data Name='BSSType'>Infrastructure</Data>"
    "<Data Name='Reason'>The network is disconnected by the driver.</Data>"
    "<Data Name='ReasonCode'>0</Data></EventData></Event>";

// disk 11 — a real controller error: classic UNNAMED positional device path. This
// record is WHY event 11 joined the disk.error id list (real Win11 disk failures
// landed there, not in the manifest-guessed 7/51/153).
constexpr const char* kRealDisk11 =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='disk'/><EventID Qualifiers='49156'>11</EventID><Version>0</Version>"
    "<Level>2</Level><Channel>System</Channel></System><EventData>"
    "<Data>\\Device\\Harddisk1\\DR1</Data><Binary>0F008000</Binary></EventData></Event>";

// ── Wave 4 (2026-06-22): real records captured from a live HP ZBook Firefly 14
// G8 (Win11 26100). Power-button hang, modern-standby exit, Intel Wi-Fi D3 dump,
// PnP driver-load failure, battery-count change. ──

// Kernel-Power 41 with a NON-ZERO PowerButtonTimestamp — the machine was held off
// by the power button after a hard hang (vs kReal41's pure power loss, ts 0).
constexpr const char* kReal41Button =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-Kernel-Power' Guid='{331c3b3a-2005-44c2-ac5e-77220c37d6b4}'/>"
    "<EventID>41</EventID><Version>10</Version><Level>1</Level><Channel>System</Channel></System>"
    "<EventData><Data Name='BugcheckCode'>0</Data><Data Name='SleepInProgress'>0</Data>"
    "<Data Name='PowerButtonTimestamp'>134266075744470540</Data>"
    "<Data Name='LongPowerButtonPressDetected'>false</Data>"
    "<Data Name='LidState'>1</Data></EventData></Event>";

// Kernel-Power 507 — a real Modern-standby exit. DripsResidencyInUs 0 of a
// 17.37 s DurationInUs ⇒ 0% deep-idle residency (the platform never reached deep
// idle while "asleep").
constexpr const char* kReal507 =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-Kernel-Power' Guid='{331c3b3a-2005-44c2-ac5e-77220c37d6b4}'/>"
    "<EventID>507</EventID><Version>12</Version><Level>4</Level><Channel>System</Channel></System>"
    "<EventData><Data Name='EnergyDrain'>21552</Data><Data Name='DripsResidencyInUs'>0</Data>"
    "<Data Name='DurationInUs'>17371560</Data><Data Name='Reason'>32</Data>"
    "<Data Name='ExitLatencyInUs'>450115</Data></EventData></Event>";

// Netwtw10 7025 — a real Intel Wi-Fi D3 diagnostic dump. CLASSIC source: UNNAMED
// positional Data ([0]=NDIS device, [1]=adapter) + a Binary the parser skips.
// Qualifiers attr + no Provider Guid (the classic-source shape).
constexpr const char* kRealNetwtw7025 =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Netwtw10'/><EventID Qualifiers='16384'>7025</EventID><Version>0</Version>"
    "<Level>4</Level><Channel>System</Channel></System><EventData>"
    "<Data>\\Device\\NDMP5</Data><Data>Intel(R) Wi-Fi 6 AX201 160MHz</Data>"
    "<Binary>000004000200340000000000711B0040</Binary></EventData></Event>";

// Kernel-PnP 219 — a real driver-load failure (WUDFRd failed to load for a HID
// device; Status decimal 3221226341 = 0xC0000365).
constexpr const char* kRealPnP219 =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-Kernel-PnP' Guid='{9c205a39-1250-487d-abd7-e831c6290539}'/>"
    "<EventID>219</EventID><Version>0</Version><Level>3</Level><Channel>System</Channel></System>"
    "<EventData><Data Name='DriverNameLength'>39</Data>"
    "<Data Name='DriverName'>HID\\Vid_8087&amp;Pid_0AC2\\6&amp;11d64d0d&amp;0&amp;0000</Data>"
    "<Data Name='Status'>3221226341</Data><Data Name='FailureNameLength'>14</Data>"
    "<Data Name='FailureName'>\\Driver\\WUDFRd</Data><Data Name='Version'>0</Data>"
    "</EventData></Event>";

// Kernel-Power 521 — a real (healthy) battery-count change: all-zero error counts,
// which the extractor SUPPRESSES (not a signal).
constexpr const char* kReal521Healthy =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-Kernel-Power' Guid='{331c3b3a-2005-44c2-ac5e-77220c37d6b4}'/>"
    "<EventID>521</EventID><Version>0</Version><Level>4</Level><Channel>System</Channel></System>"
    "<EventData><Data Name='ValidBatteryCount'>1</Data><Data Name='ErrorBatteryCount'>0</Data>"
    "<Data Name='AbandonedBatteryCount'>0</Data></EventData></Event>";

// SCM 7011 — service unresponsive. Params REVERSED (param1 = timeout ms, param2 =
// service), like 7009 — pins that the extractor reads param2, not param1.
constexpr const char* kRealScm7011 =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' "
    "EventSourceName='Service Control Manager'/><EventID Qualifiers='49152'>7011</EventID>"
    "<Version>0</Version><Level>2</Level><Channel>System</Channel></System><EventData>"
    "<Data Name='param1'>30000</Data><Data Name='param2'>HPAudioAnalytics</Data></EventData></Event>";

// SCM 7043 — service did not shut down properly. Normal layout (param1 = service),
// plus a Binary the parser must skip.
constexpr const char* kRealScm7043 =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' "
    "EventSourceName='Service Control Manager'/><EventID Qualifiers='49152'>7043</EventID>"
    "<Version>0</Version><Level>2</Level><Channel>System</Channel></System><EventData>"
    "<Data Name='param1'>Windows Biometric Service</Data>"
    "<Binary>5700620069006F0053007200760063000000</Binary></EventData></Event>";

// NDIS 10317 — a network miniport fatal/reset event (named fields). Vendor-neutral.
constexpr const char* kRealNdis10317 =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-NDIS' Guid='{cdead503-17f5-4a3e-b7ae-df8cc2902eb9}'/>"
    "<EventID>10317</EventID><Version>0</Version><Level>2</Level><Channel>System</Channel></System>"
    "<EventData><Data Name='IfGuid'>{ece3eb1c-2f80-47a2-b40c-1a5906358546}</Data>"
    "<Data Name='IfIndex'>21</Data><Data Name='IfLuid'>19985273135824896</Data>"
    "<Data Name='AdapterName'>Microsoft Wi-Fi Direct Virtual Adapter #2</Data>"
    "<Data Name='MiniportEventEnum'>74</Data></EventData></Event>";

// Run one real record through the FULL chain, exactly as the engine does.
std::optional<SignalObservation> run_chain(const char* xml) {
    const auto sys = extract_system_fields(xml);
    return extract_signal(sys.channel, sys.provider, sys.event_id, sys.level,
                          extract_named_data(xml));
}
} // namespace

TEST_CASE("REAL records: service crash 7031 (full chain)", "[dex][parse][real]") {
    const auto o = run_chain(kReal7031);
    REQUIRE(o);
    CHECK(o->obs_type == "service.crashed");
    CHECK(o->subject == "HP Insights Analytics");
    CHECK(o->sentence.find("terminated unexpectedly") != std::string::npos);
}

TEST_CASE("REAL records: kernel-power 41 power loss (full chain)", "[dex][parse][real]") {
    const auto o = run_chain(kReal41);
    REQUIRE(o);
    CHECK(o->obs_type == "os.power_loss");
    CHECK(o->reason == "power loss"); // BugcheckCode 0 -> the pure power-loss path
    CHECK(o->symbolic == "UNEXPECTED_REBOOT");
}

TEST_CASE("REAL records: kernel-power 41 power button held — hard-hang discriminator",
          "[dex][parse][real]") {
    // BugcheckCode 0 + a NON-ZERO PowerButtonTimestamp ⇒ the button was pressed
    // (the classic hold-to-recover from a hard hang), distinct from pure power
    // loss. We surface the FACT; we never infer WHY it hung.
    const auto o = run_chain(kReal41Button);
    REQUIRE(o);
    CHECK(o->obs_type == "os.power_loss");
    CHECK(o->reason == "power button");
    CHECK(o->sentence.find("power button pressed") != std::string::npos); // not a 4s force hold
    CHECK(o->symbolic == "UNEXPECTED_REBOOT");
}

TEST_CASE("REAL records: kernel-power 507 modern standby exit carries DRIPS residency %",
          "[dex][parse][real]") {
    const auto o = run_chain(kReal507);
    REQUIRE(o);
    CHECK(o->obs_type == "os.modern_standby_exit");
    CHECK(o->metric == 0.0); // DripsResidencyInUs 0 / DurationInUs 17371560 -> 0% deep idle
    CHECK(o->reason == "32"); // provider exit-reason code, verbatim
    CHECK(o->sentence.find("DRIPS") != std::string::npos);
    CHECK(o->sentence.find("17s") != std::string::npos); // 17371560 us -> 17 s

    // A drifted/forged residency > duration is clamped to 100, never absurd.
    const auto clamped = extract_signal(
        "System", "Microsoft-Windows-Kernel-Power", 507, 4,
        {{"DripsResidencyInUs", "200"}, {"DurationInUs", "100"}, {"Reason", "0"}});
    REQUIRE(clamped);
    CHECK(clamped->metric == 100.0);

    // DurationInUs=0 (a firmware edge logging an instantaneous standby) must not
    // divide-by-zero — the extractor guards dur>0 and yields 0%, never UB (governance QE).
    const auto zero_dur = extract_signal(
        "System", "Microsoft-Windows-Kernel-Power", 507, 4,
        {{"DripsResidencyInUs", "0"}, {"DurationInUs", "0"}, {"Reason", "0"}});
    REQUIRE(zero_dur);
    CHECK(zero_dur->metric == 0.0);
}

TEST_CASE("REAL records: Netwtw10 7025 adapter D3 dump (positional, vendor-coupled)",
          "[dex][parse][real]") {
    const auto o = run_chain(kRealNetwtw7025);
    REQUIRE(o);
    CHECK(o->obs_type == "network.adapter_driver_dump");
    CHECK(o->subject == "Intel(R) Wi-Fi 6 AX201 160MHz"); // positional Data[1]
    CHECK(o->component == "\\Device\\NDMP5");              // positional Data[0]
    CHECK(o->reason == "d3-dump");
    CHECK(o->symbolic == "ADAPTER_DRIVER_DUMP");
    // 7026 is the paired completion — deliberately NOT catalogued (would double-count).
    CHECK_FALSE(extract_signal("System", "Netwtw10", 7026, 4, {}).has_value());
}

TEST_CASE("REAL records: Kernel-PnP 219 driver-load failure (status hexified)",
          "[dex][parse][real]") {
    const auto o = run_chain(kRealPnP219);
    REQUIRE(o);
    CHECK(o->obs_type == "hw.driver_load_failed");
    CHECK(o->subject == "WUDFRd");          // FailureName basename
    CHECK(o->reason == "0xC0000365");       // decimal 3221226341 -> hex
    CHECK(o->symbolic == "DRIVER_LOAD_FAILED");
    CHECK(o->component.find("Vid_8087") != std::string::npos); // device id kept (hw identity)
    // Distinct from the device-START-failure signal (PnP 411).
    CHECK(o->obs_type != "hw.device_start_failed");
}

TEST_CASE("REAL records: Kernel-Power 521 battery — healthy change suppressed, fault emits",
          "[dex][parse][real]") {
    // The real captured record is a healthy battery-count change (all-zero error
    // counts) → suppressed, no observation.
    CHECK_FALSE(run_chain(kReal521Healthy).has_value());

    // A non-zero error/abandoned count IS a signal.
    const auto err = extract_signal("System", "Microsoft-Windows-Kernel-Power", 521, 4,
                                    {{"ValidBatteryCount", "1"},
                                     {"ErrorBatteryCount", "1"},
                                     {"AbandonedBatteryCount", "0"}});
    REQUIRE(err);
    CHECK(err->obs_type == "hw.battery_error");
    CHECK(err->subject == "battery");
    CHECK(err->reason == "error");
    CHECK(err->metric == 1.0);

    const auto aband = extract_signal("System", "Microsoft-Windows-Kernel-Power", 521, 4,
                                      {{"ValidBatteryCount", "0"},
                                       {"ErrorBatteryCount", "0"},
                                       {"AbandonedBatteryCount", "2"}});
    REQUIRE(aband);
    CHECK(aband->reason == "abandoned");
    CHECK(aband->metric == 2.0);

    // A forged/drifted count near INT_MAX must not overflow when summed (parse_int
    // upper-clamps each count to 1e6; the metric is the clamped, non-negative sum,
    // never signed-overflow UB — governance cpp-expert S1).
    const auto forged = extract_signal("System", "Microsoft-Windows-Kernel-Power", 521, 4,
                                       {{"ErrorBatteryCount", "2000000000"},
                                        {"AbandonedBatteryCount", "2000000000"}});
    REQUIRE(forged);
    CHECK(forged->obs_type == "hw.battery_error");
    CHECK(forged->metric > 0.0);        // still a signal, not suppressed
    CHECK(forged->metric <= 2000000.0); // clamped sum (2 × 1e6 ceiling), no overflow
}

TEST_CASE("REAL records: SCM 7011 service unresponsive — params reversed (param2=service)",
          "[dex][parse][real]") {
    const auto o = run_chain(kRealScm7011);
    REQUIRE(o);
    CHECK(o->obs_type == "service.unresponsive");
    CHECK(o->subject == "HPAudioAnalytics");   // param2 — NOT param1 (which is the timeout)
    CHECK(o->reason == "timeout 30000 ms");
    CHECK(o->symbolic == "SERVICE_UNRESPONSIVE");
}

TEST_CASE("REAL records: SCM 7043 service shutdown failure — param1=service, Binary skipped",
          "[dex][parse][real]") {
    const auto o = run_chain(kRealScm7043);
    REQUIRE(o);
    CHECK(o->obs_type == "service.shutdown_failed");
    CHECK(o->subject == "Windows Biometric Service");
    CHECK(o->symbolic == "SERVICE_SHUTDOWN_FAILED");
}

TEST_CASE("REAL records: NDIS 10317 adapter reset — vendor-neutral, named AdapterName",
          "[dex][parse][real]") {
    const auto o = run_chain(kRealNdis10317);
    REQUIRE(o);
    CHECK(o->obs_type == "network.adapter_reset");
    CHECK(o->subject == "Microsoft Wi-Fi Direct Virtual Adapter #2");
    CHECK(o->reason == "miniport-event 74");
    CHECK(o->symbolic == "ADAPTER_RESET");
}

TEST_CASE("SAFETY: wave-4 extractors clip + strip control chars from untrusted subject AND reason",
          "[dex][parse][privacy]") {
    // A forged event (compromised endpoint) with control bytes + an oversized field
    // must NOT carry NUL/control chars or an unbounded blob into the projection —
    // esc() neutralizes HTML metachars but NOT control bytes (the "control-char 400"
    // precedent). BOTH subject and reason are clipped at the edge (gov Gate-8 MEDIUM).
    auto no_ctrl = [](const std::string& s) {
        for (unsigned char c : s)
            if (c < 0x20 || c == 0x7F)
                return false;
        return true;
    };
    const std::string evil = std::string(500, 'A') + std::string("\x01\x1f\x7f", 3); // C0 + DEL
    // service.unresponsive: subject=param2 (clip 80), reason from param1 timeout (clip 16)
    const auto su = extract_signal("System", "Service Control Manager", 7011, 2,
                                   {{"param1", std::string("30000\x07", 6)}, {"param2", evil}});
    REQUIRE(su);
    CHECK(su->subject.size() < 200); // bounded, not 503
    CHECK(no_ctrl(su->subject));
    CHECK(no_ctrl(su->reason)); // the \x07 in the timeout is stripped
    // adapter_reset: subject=AdapterName (clip 120), reason=MiniportEventEnum (clip 16)
    const auto ar = extract_signal("System", "Microsoft-Windows-NDIS", 10317, 2,
                                   {{"AdapterName", evil}, {"MiniportEventEnum", std::string("74\x1b", 3)}});
    REQUIRE(ar);
    CHECK(ar->subject.size() < 200);
    CHECK(no_ctrl(ar->subject));
    CHECK(no_ctrl(ar->reason));
}

TEST_CASE("REAL records: boot 100 duration metric (full chain)", "[dex][parse][real]") {
    const auto o = run_chain(kReal100);
    REQUIRE(o);
    CHECK(o->obs_type == "os.boot");
    CHECK(o->metric == 64934.0); // a real 64.9 s boot
}

TEST_CASE("REAL records: update failure 20 (full chain)", "[dex][parse][real]") {
    const auto o = run_chain(kReal20);
    REQUIRE(o);
    CHECK(o->obs_type == "update.failed");
    CHECK(o->subject == "9MSSGKG348SP-MicrosoftWindows.Client.WebExperience");
    CHECK(o->reason == "0x80073d02");
}

TEST_CASE("REAL records: MSI 11708 positional parse (full chain)", "[dex][parse][real]") {
    const auto o = run_chain(kReal11708);
    REQUIRE(o);
    CHECK(o->obs_type == "app_install.failed");
    CHECK(o->subject == "Zoom VDI Plugin Management(64bit)");
}

TEST_CASE("REAL records: wifi 8003 at informational level (full chain)",
          "[dex][parse][real]") {
    const auto o = run_chain(kReal8003);
    REQUIRE(o);
    CHECK(o->obs_type == "network.wifi_drop");
    CHECK(o->subject == "Samsung Smart Fridge");
    CHECK(o->reason.find("disconnected by the driver") != std::string::npos);
    CHECK(o->component.find("AX201") != std::string::npos);
}

TEST_CASE("REAL records: disk controller error 11 (full chain)", "[dex][parse][real]") {
    const auto o = run_chain(kRealDisk11);
    REQUIRE(o);
    CHECK(o->obs_type == "disk.error");
    CHECK(o->subject == "\\Device\\Harddisk1\\DR1");
    CHECK(o->symbolic == "CONTROLLER_ERROR");
}

// ── Wave-2 real-record + privacy pins (Win11 26100, harvested 2026-06-10) ────

TEST_CASE("REAL records: boot degradation 101 (Name + DegradationTime; Path dropped)",
          "[dex][parse][real][privacy]") {
    // Real layout: named Name/FriendlyName/TotalTime/DegradationTime/Path.
    const EventFields f = {{"StartTime", "2026-06-09T14:00:12Z"},
                           {"Name", "TiWorker.exe"},
                           {"FriendlyName", "Windows Modules Installer Worker"},
                           {"TotalTime", "2682"},
                           {"DegradationTime", "182"},
                           {"Path", "C:\\Users\\dave\\secret\\TiWorker.exe"}};
    const auto o = extract_signal("Microsoft-Windows-Diagnostics-Performance/Operational",
                                  "Microsoft-Windows-Diagnostics-Performance", 101, 2, f);
    REQUIRE(o);
    CHECK(o->obs_type == "boot.degraded_app");
    CHECK(o->subject == "TiWorker.exe");
    CHECK(o->metric == 182.0); // DegradationTime preferred over TotalTime
    for (const std::string& field : {o->subject, o->reason, o->component, o->sentence})
        CHECK(field.find("secret") == std::string::npos); // PRIVACY: Path never extracted
}

TEST_CASE("REAL records: shutdown 200 carries ShutdownTime", "[dex][parse][real]") {
    const auto o = extract_signal("Microsoft-Windows-Diagnostics-Performance/Operational",
                                  "Microsoft-Windows-Diagnostics-Performance", 200, 2,
                                  {{"ShutdownTsVersion", "1"}, {"ShutdownTime", "17733"}});
    REQUIRE(o);
    CHECK(o->obs_type == "os.shutdown");
    CHECK(o->metric == 17733.0);
}

TEST_CASE("REAL records: SCM 7009 start timeout (params REVERSED vs 7000)",
          "[dex][parse][real]") {
    const auto o = extract_signal("System", "Service Control Manager", 7009, 2,
                                  {{"param1", "30000"}, {"param2", "YuzuDexCanarySvc"}});
    REQUIRE(o);
    CHECK(o->obs_type == "service.start_timeout");
    CHECK(o->subject == "YuzuDexCanarySvc"); // param2, not param1
    CHECK(o->reason == "timeout 30000 ms");
}

TEST_CASE("REAL records: time-service 36 unsynchronized seconds", "[dex][parse][real]") {
    const auto o = extract_signal("System", "Microsoft-Windows-Time-Service", 36, 3,
                                  {{"UnsynchronizedTimeSeconds", "51254"}});
    REQUIRE(o);
    CHECK(o->obs_type == "os.time_unsynced");
    CHECK(o->metric == 51254.0);
}

TEST_CASE("REAL records: .NET 1026 blob — app + exception type only, no stack/paths",
          "[dex][parse][real][privacy]") {
    // Real 1026: ONE positional blob with app, exception, and stack frames.
    const EventFields f = {
        {"", "Application: AOTListenerService.exe\nCoreCLR Version: 8.0.1625.21506\n"
             "Description: The process was terminated due to an unhandled exception.\n"
             "Exception Info: System.ArgumentNullException: Value cannot be null.\n"
             "   at CtxLogFileService.Cli.MachineIdentityCli.ToNative(MachineIdentity*)\n"}};
    const auto o = extract_signal("Application", ".NET Runtime", 1026, 2, f);
    REQUIRE(o);
    CHECK(o->obs_type == "process.crashed_managed");
    CHECK(o->subject == "AOTListenerService.exe");
    CHECK(o->reason == "System.ArgumentNullException");
    // PRIVACY/size: the stack frames are never shipped.
    for (const std::string& field : {o->subject, o->reason, o->component, o->sentence})
        CHECK(field.find("MachineIdentityCli") == std::string::npos);
}

TEST_CASE("REAL records: Application Popup 26 caption + message", "[dex][parse][real]") {
    const auto o = extract_signal("System", "Application Popup", 26, 4,
                                  {{"Caption", "Windows - Virtual Memory Minimum Too Low"},
                                   {"Message", "Your system is low on virtual memory."}});
    REQUIRE(o);
    CHECK(o->obs_type == "app.error_popup");
    CHECK(o->subject.find("Virtual Memory") != std::string::npos);
    CHECK(o->sentence.find("low on virtual memory") != std::string::npos);
}

TEST_CASE("REAL records: Kernel-PnP 411 device start failure", "[dex][parse][real]") {
    const auto o = extract_signal("Microsoft-Windows-Kernel-PnP/Configuration",
                                  "Microsoft-Windows-Kernel-PnP", 411, 2,
                                  {{"DeviceInstanceId", "ROOT\\VMS_VSMP\\0001"},
                                   {"DriverName", "wvms_mp_windows.inf"},
                                   {"Status", "0xc0000001"}});
    REQUIRE(o);
    CHECK(o->obs_type == "hw.device_start_failed");
    CHECK(o->subject == "ROOT\\VMS_VSMP\\0001");
    CHECK(o->component == "wvms_mp_windows.inf");
    CHECK(o->reason == "0xc0000001");
}

TEST_CASE("REAL records: WLAN 8002 connect failure (Level 4 — no level filter)",
          "[dex][parse][real]") {
    const auto o = extract_signal(
        "Microsoft-Windows-WLAN-AutoConfig/Operational", "Microsoft-Windows-WLAN-AutoConfig",
        8002, 4,
        {{"SSID", "Samsung Smart Fridge"},
         {"FailureReason", "Failed to connect because no connectable Access Point was visible"},
         {"InterfaceDescription", "Intel(R) Wi-Fi 6 AX201 160MHz"}});
    REQUIRE(o);
    CHECK(o->obs_type == "network.wifi_connect_failed");
    CHECK(o->subject == "Samsung Smart Fridge");
    CHECK(o->reason.find("no connectable Access Point") != std::string::npos);
}

TEST_CASE("REAL records: Defender 2001 — spaced field names; user fields dropped",
          "[dex][parse][real][privacy]") {
    // Real layout: Data names contain SPACES ('Error Code'); Domain/User present.
    const EventFields f = {{"Product Name", "Microsoft Defender Antivirus"},
                           {"Update Source", "Microsoft Update Server"},
                           {"Domain", "CONTOSO"},
                           {"User", "jane.doe"},
                           {"Error Code", "0x8024402c"}};
    const auto o = extract_signal("Microsoft-Windows-Windows Defender/Operational",
                                  "Microsoft-Windows-Windows Defender", 2001, 2, f);
    REQUIRE(o);
    CHECK(o->obs_type == "security.av_update_failed");
    CHECK(o->reason == "0x8024402c");
    for (const std::string& field : {o->subject, o->reason, o->component, o->sentence})
        CHECK(field.find("jane.doe") == std::string::npos); // PRIVACY
}

TEST_CASE("REAL records: AppX 404 + BITS 61 (url dropped, hr hexified)",
          "[dex][parse][real][privacy]") {
    const auto a = extract_signal("Microsoft-Windows-AppXDeploymentServer/Operational",
                                  "Microsoft-Windows-AppXDeployment-Server", 404, 2,
                                  {{"PackageFullName", "MdOdrMcpFilterPackage_1.0.0.0_neutral"},
                                   {"ErrorCode", "0x80073cf9"}});
    REQUIRE(a);
    CHECK(a->obs_type == "app_install.appx_failed");
    CHECK(a->subject.find("MdOdrMcpFilterPackage") != std::string::npos);
    CHECK(a->reason == "0x80073cf9");

    const auto b = extract_signal("Microsoft-Windows-Bits-Client/Operational",
                                  "Microsoft-Windows-Bits-Client", 61, 2,
                                  {{"name", "PreSignInSettingsConfigJSON"},
                                   {"url", "https://g.live.com/odclientsettings/ProdV2"},
                                   {"hr", "2147954407"}});
    REQUIRE(b);
    CHECK(b->obs_type == "update.transfer_failed");
    CHECK(b->subject == "PreSignInSettingsConfigJSON");
    CHECK(b->reason == "0x80072EE7"); // decimal hr rendered as the HRESULT it is
    for (const std::string& field : {b->subject, b->reason, b->component, b->sentence})
        CHECK(field.find("g.live.com") == std::string::npos); // PRIVACY: url dropped
}

TEST_CASE("REAL records: EventLog 6013 uptime + 6008 dirty shutdown (positional)",
          "[dex][parse][real]") {
    // Real 6013: leading empty positional fields, uptime seconds at index 4.
    const EventFields up = {{"", ""}, {"", ""}, {"", ""}, {"", ""},
                            {"", "75587"}, {"", "60"}, {"", "0 GMT Standard Time"}};
    const auto u = extract_signal("System", "EventLog", 6013, 4, up);
    REQUIRE(u);
    CHECK(u->obs_type == "os.uptime_report");
    CHECK(u->metric == 75587.0); // first numeric field

    const auto d = extract_signal("System", "EventLog", 6008, 2,
                                  {{"", "14:45:39"}, {"", "09/06/2026"}});
    REQUIRE(d);
    CHECK(d->obs_type == "os.dirty_shutdown");
    CHECK(d->sentence.find("unexpected") != std::string::npos);
}

TEST_CASE("PRIVACY: VPN 20227 never reads the dialing user (insert %1)",
          "[dex][parse][privacy]") {
    const auto o = extract_signal("Application", "RasClient", 20227, 2,
                                  {{"", "CONTOSO\\dave.rae"}, {"", "Corp VPN"}, {"", "691"}});
    REQUIRE(o);
    CHECK(o->obs_type == "network.vpn_failed");
    CHECK(o->subject == "Corp VPN");
    CHECK(o->reason == "691");
    for (const std::string& field : {o->subject, o->reason, o->component, o->sentence})
        CHECK(field.find("dave.rae") == std::string::npos);
}

TEST_CASE("PRIVACY: Defender 1116 keeps the threat name, drops path + user",
          "[dex][parse][privacy]") {
    const auto o = extract_signal("Microsoft-Windows-Windows Defender/Operational",
                                  "Microsoft-Windows-Windows Defender", 1116, 3,
                                  {{"Threat Name", "Trojan:Win32/Wacatac.B!ml"},
                                   {"Path", "file:_C:\\Users\\dave\\Downloads\\keygen.exe"},
                                   {"Detection User", "CONTOSO\\dave.rae"}});
    REQUIRE(o);
    CHECK(o->obs_type == "security.threat_detected");
    CHECK(o->subject == "Trojan:Win32/Wacatac.B!ml");
    for (const std::string& field : {o->subject, o->reason, o->component, o->sentence}) {
        CHECK(field.find("Downloads") == std::string::npos);
        CHECK(field.find("dave.rae") == std::string::npos);
    }
}

TEST_CASE("PRIVACY: service logon failure 7038 drops the account name",
          "[dex][parse][privacy]") {
    const auto o = extract_signal("System", "Service Control Manager", 7038, 2,
                                  {{"param1", "MyAgentSvc"}, {"param2", "CONTOSO\\dave.rae"}});
    REQUIRE(o);
    CHECK(o->obs_type == "service.logon_failed");
    CHECK(o->subject == "MyAgentSvc");
    for (const std::string& field : {o->subject, o->reason, o->component, o->sentence})
        CHECK(field.find("dave.rae") == std::string::npos);
}

TEST_CASE("PRIVACY: ESENT corruption keeps the process, drops the db path",
          "[dex][parse][privacy]") {
    const auto o = extract_signal("Application", "ESENT", 447, 2,
                                  {{"", "svchost"}, {"", "Instance:"},
                                   {"", "C:\\Users\\dave\\AppData\\Local\\db.jet"}});
    REQUIRE(o);
    CHECK(o->obs_type == "fs.database_corrupt");
    CHECK(o->subject == "svchost");
    for (const std::string& field : {o->subject, o->reason, o->component, o->sentence})
        CHECK(field.find("AppData") == std::string::npos);
}

// ── Wave-3 real-record + privacy pins (Win11 26100, harvested 2026-06-10) ────

TEST_CASE("REAL records: Power-Troubleshooter 1 resume metric", "[dex][parse][real]") {
    // Real layout: WakeDuration (ms) named alongside SleepTime/WakeTime stamps.
    const auto o = extract_signal("System", "Microsoft-Windows-Power-Troubleshooter", 1, 4,
                                  {{"SleepTime", "2026-06-09T19:55:32Z"},
                                   {"WakeTime", "2026-06-10T09:22:29Z"},
                                   {"WakeDuration", "2719"},
                                   {"BiosInitDuration", "7588"}});
    REQUIRE(o);
    CHECK(o->obs_type == "os.resume_report");
    CHECK(o->metric == 2719.0);
    CHECK(o->sentence.find("2719 ms") != std::string::npos);
}

TEST_CASE("PRIVACY + REAL: User32 1074 restart — process + reason kept, user dropped",
          "[dex][parse][real][privacy]") {
    // Real layout: param1 = "path\app.exe (HOST)", param3 = reason, param5 =
    // action, param7 = the initiating USER ("CONTOSO\jsmith") — never read.
    const EventFields f = {
        {"param1", "C:\\Windows\\SystemApps\\Host\\StartMenuExperienceHost.exe (WORKSTATION01)"},
        {"param2", "WORKSTATION01"},
        {"param3", "Other (Unplanned)"},
        {"param4", "0x0"},
        {"param5", "restart"},
        {"param6", ""},
        {"param7", "CONTOSO\\jsmith"}};
    const auto o = extract_signal("System", "User32", 1074, 4, f);
    REQUIRE(o);
    CHECK(o->obs_type == "os.restart_initiated");
    CHECK(o->subject == "StartMenuExperienceHost.exe"); // basename, host suffix cut
    CHECK(o->sentence.find("restart") != std::string::npos);
    for (const std::string& field : {o->subject, o->reason, o->component, o->sentence})
        CHECK(field.find("jsmith") == std::string::npos);
}

TEST_CASE("REAL records: any-error specs catch live ids (TPM 1801, Biometrics 1014, MDM 844)",
          "[dex][parse][real]") {
    // The any-id + level-filter pattern, validated against three real errors.
    const auto tpm = extract_signal("System", "Microsoft-Windows-TPM-WMI", 1801, 2, {});
    REQUIRE(tpm);
    CHECK(tpm->obs_type == "hw.tpm_error");
    CHECK(tpm->reason == "tpm-1801");

    const auto bio = extract_signal(
        "Microsoft-Windows-Biometrics/Operational", "Microsoft-Windows-Biometrics", 1014, 2,
        {{"BiometricSensor", "Synaptics FS7605 Touch Fingerprint Sensor"}});
    REQUIRE(bio);
    CHECK(bio->obs_type == "logon.biometric_error");
    CHECK(bio->subject.find("Synaptics") != std::string::npos);

    const auto mdm = extract_signal(
        "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
        "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider", 844, 2,
        {{"Message1", "Inbox"}, {"HRESULT", "0x3f"}});
    REQUIRE(mdm);
    CHECK(mdm->obs_type == "mgmt.mdm_error");
    CHECK(mdm->reason == "0x3f");

    // …and the level filter still drops informational records from those channels.
    CHECK_FALSE(extract_signal("System", "Microsoft-Windows-TPM-WMI", 1801, 4, {}));
}

TEST_CASE("REAL records: AAD 1097 decimal error rendered as hex; no message text shipped",
          "[dex][parse][real][privacy]") {
    // Real layout: Error decimal + ErrorMessage free text (can embed UPNs in
    // some failure shapes — never shipped).
    const auto o = extract_signal("Microsoft-Windows-AAD/Operational", "Microsoft-Windows-AAD",
                                  1097, 3,
                                  {{"Error", "2325807322"},
                                   {"ErrorMessage", "Token failure for dave.rae@contoso.com"}});
    REQUIRE(o);
    CHECK(o->obs_type == "logon.aad_token_error");
    CHECK(o->reason == "0x8AA100DA"); // 2325807322 in hex
    for (const std::string& field : {o->subject, o->reason, o->component, o->sentence})
        CHECK(field.find("dave.rae") == std::string::npos);
}

TEST_CASE("PRIVACY: RDP disconnect never reads user or client address",
          "[dex][parse][privacy]") {
    const auto o = extract_signal(
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager", 40, 4,
        {{"Session", "3"}, {"User", "CONTOSO\\dave.rae"}, {"Address", "82.13.5.77"},
         {"Reason", "5"}});
    REQUIRE(o);
    CHECK(o->obs_type == "session.rdp_disconnected");
    CHECK(o->reason == "5");
    for (const std::string& field : {o->subject, o->reason, o->component, o->sentence}) {
        CHECK(field.find("dave.rae") == std::string::npos);
        CHECK(field.find("82.13") == std::string::npos);
    }
}

TEST_CASE("PRIVACY: app file-access failure 1005 drops the file path",
          "[dex][parse][privacy]") {
    const auto o = extract_signal("Application", "Application Error", 1005, 2,
                                  {{"", "C:\\Program Files\\Acme\\acme.exe"},
                                   {"", "\\\\share\\users\\dave\\salary_review.xlsx"}});
    REQUIRE(o);
    CHECK(o->obs_type == "process.file_access_failure");
    CHECK(o->subject == "acme.exe"); // basename of the app only
    for (const std::string& field : {o->subject, o->reason, o->component, o->sentence})
        CHECK(field.find("salary_review") == std::string::npos);
}

TEST_CASE("wave 3: dependency failure + port exhaustion + update download", "[dex][parse]") {
    const auto dep = extract_signal("System", "Service Control Manager", 7001, 2,
                                    {{"param1", "Print Spooler"}, {"param2", "HTTP Service"}});
    REQUIRE(dep);
    CHECK(dep->obs_type == "service.dependency_failed");
    CHECK(dep->subject == "Print Spooler");
    CHECK(dep->component == "HTTP Service");

    const auto port = extract_signal("System", "Tcpip", 4231, 3, {});
    REQUIRE(port);
    CHECK(port->obs_type == "network.port_exhaustion");

    const auto dl = extract_signal("System", "Microsoft-Windows-WindowsUpdateClient", 31, 2,
                                   {{"errorCode", "0x80244018"},
                                    {"updateTitle", "2026-06 Cumulative Update"}});
    REQUIRE(dl);
    CHECK(dl->obs_type == "update.download_failed");
    CHECK(dl->subject == "2026-06 Cumulative Update");
    CHECK(dl->reason == "0x80244018");
}

TEST_CASE("PRIVACY/SAFETY: clip() of an over-long multibyte string yields valid JSON (cpp-B1)",
          "[dex][parse][json]") {
    // Governance cpp-B1: clip() must trim to a UTF-8 codepoint boundary before
    // appending the ellipsis — a torn sequence would make signal_detail_json's
    // dump() throw, and the OS-callback catch(...) would silently drop the whole
    // observation. A localized update title (CJK, 3 bytes/char) longer than the
    // 120-byte clip cap forces the cut mid-codepoint at many offsets.
    std::string cjk = "x"; // leading ASCII byte forces the 120-byte cut to land
    for (int i = 0; i < 80; ++i)                  // mid-codepoint in the CJK run
        cjk += "更新"; // 6 bytes each → 481 bytes, well over the 120 cap
    const auto o = extract_signal("System", "Microsoft-Windows-WindowsUpdateClient", 20, 2,
                                  {{"errorCode", "0x80070643"}, {"updateTitle", cjk}});
    REQUIRE(o);
    CHECK(o->obs_type == "update.failed");
    // The whole wire mapping must round-trip without throwing on the clipped value.
    const auto ev = signal_observation_to_event(*o, "evt-cjk");
    auto j = nlohmann::json::parse(ev.detail_json()); // must not throw
    const std::string subj = j.at("subject").get<std::string>();
    CHECK(subj.size() <= 123); // clipped to <=120 byte boundary + 3-byte ellipsis
    // No U+FFFD means clip() trimmed to a codepoint boundary — NOT that dump()'s
    // replace handler papered over a torn sequence.
    CHECK(subj.find("\xEF\xBF\xBD") == std::string::npos);
}

// ── Wire mapping (dex_event) ─────────────────────────────────────────────────

namespace {
SignalObservation make_crash_obs() {
    SignalObservation o;
    o.obs_type = "process.crashed";
    o.subject = "notepad.exe";
    o.reason = "0xC0000005";
    o.symbolic = "ACCESS_VIOLATION";
    o.component = "ntdll.dll";
    o.pid = 1234;
    o.kind = "exception";
    o.sentence = "notepad.exe pid=1234 code=0xC0000005 ACCESS_VIOLATION module=ntdll.dll";
    o.timestamp_unix = 1718000000;
    o.platform = "windows";
    return o;
}
} // namespace

TEST_CASE("signal_observation_to_event maps to a ruleless DEX event", "[crash][event]") {
    const auto ev = signal_observation_to_event(make_crash_obs(), "evt-id-1");
    CHECK(ev.event_id() == "evt-id-1");
    CHECK(ev.rule_id() == std::string(kObservationRuleSentinel)); // ruleless sentinel
    CHECK(ev.event_type() == "process.crashed");
    CHECK(ev.guard_type() == "process"); // first dot-segment of the obs_type
    CHECK(ev.severity() == "info");
    CHECK(ev.guard_category().empty()); // the discriminator is NOT a category field
    CHECK(ev.expected_value().empty()); // an observation has no desired state
    CHECK(ev.detected_value().find("0xC0000005") != std::string::npos);
    CHECK(ev.detected_value().find("ACCESS_VIOLATION") != std::string::npos);
    CHECK(ev.detected_value().find("ntdll.dll") != std::string::npos);
    CHECK(ev.timestamp().seconds() == 1718000000);
    CHECK(ev.platform() == "windows");
}

TEST_CASE("signal_detail_json: uniform keys + crash legacy dual-emit", "[crash][event]") {
    const auto ev = signal_observation_to_event(make_crash_obs(), "evt-id-3");
    auto j = nlohmann::json::parse(ev.detail_json());
    // Uniform core keys — what the multi-signal projection reads.
    CHECK(j.at("subject") == "notepad.exe");
    CHECK(j.at("reason") == "0xC0000005");
    CHECK(j.at("symbolic") == "ACCESS_VIOLATION");
    CHECK(j.at("component") == "ntdll.dll");
    CHECK(j.at("pid") == 1234);
    CHECK(j.at("kind") == "exception");
    // Legacy slice-1 crash keys (PR #1311 transition compat) — crash only.
    CHECK(j.at("process") == "notepad.exe");
    CHECK(j.at("exception_code") == "0xC0000005");
    CHECK(j.at("faulting_module") == "ntdll.dll");
    CHECK_FALSE(j.contains("image_path")); // data-minimisation: never extracted, never sent
}

TEST_CASE("signal_detail_json: non-crash types are uniform-only + carry metric",
          "[dex][event]") {
    SignalObservation o;
    o.obs_type = "os.boot";
    o.subject = "boot";
    o.metric = 43210.0;
    o.sentence = "boot completed in 43210 ms";
    o.platform = "windows";
    const auto ev = signal_observation_to_event(o, "evt-id-4");
    CHECK(ev.event_type() == "os.boot");
    CHECK(ev.guard_type() == "os");
    auto j = nlohmann::json::parse(ev.detail_json());
    CHECK(j.at("subject") == "boot");
    CHECK(j.at("metric") == 43210.0);
    CHECK_FALSE(j.contains("process"));        // legacy keys are crash-only
    CHECK_FALSE(j.contains("exception_code"));
    // Optional keys omitted when empty (compact wire payloads).
    CHECK_FALSE(j.contains("reason"));
    CHECK_FALSE(j.contains("component"));
}

TEST_CASE("signal_detail_json escapes nasty subjects", "[crash][event][json]") {
    SignalObservation o;
    o.obs_type = "process.crashed";
    // Quotes, backslashes, a brace, and non-ASCII — the kind of name that breaks a
    // hand-rolled encoder. The JSON lib must escape it so the result still parses.
    o.subject = R"(My "App".exe \ {weird} café)";
    o.reason = "0xC0000374";
    o.symbolic = "HEAP_CORRUPTION";
    o.pid = 42;
    const std::string detail = signal_detail_json(o);
    auto j = nlohmann::json::parse(detail); // must not throw
    CHECK(j.at("subject") == R"(My "App".exe \ {weird} café)");
    CHECK(j.at("pid") == 42);
    CHECK(j.at("symbolic") == "HEAP_CORRUPTION");
    CHECK_FALSE(j.contains("component")); // omitted when empty
}

TEST_CASE("signal_observation_to_event leaves timestamp unset when unknown", "[crash][event]") {
    SignalObservation o;
    o.obs_type = "service.crashed";
    o.subject = "Spooler";
    // timestamp_unix left 0 -> server stamps ingest time (mirrors drift events).
    const auto ev = signal_observation_to_event(o, "evt-id-2");
    CHECK_FALSE(ev.has_timestamp());
    CHECK(ev.guard_type() == "service");
}

// ── Factory ──────────────────────────────────────────────────────────────────

TEST_CASE("make_dex_observer is never null", "[crash][factory]") {
    auto obs = make_dex_observer();
    REQUIRE(obs != nullptr);
    CHECK(obs->armed_channels() == 0); // not started yet
#if defined(__APPLE__)
    // The macOS collector slice has landed, so make_dex_observer() is no longer a
    // no-op off Windows — it returns the kqueue/sysctl/OSLog collector. Whether
    // start() actually arms depends on the runtime (a DiagnosticReports directory
    // must be watchable), so we don't assert its return; we exercise the
    // start()/stop() lifecycle to confirm it neither crashes nor hangs (the
    // EVFILT_USER stop path — governance cs-S1). The signal parsers themselves
    // are covered by the [dex_macos] suite.
    bool fired = false;
    (void)obs->start([&](const SignalObservation&) { fired = true; });
    obs->stop();
#elif defined(__linux__)
    // The Linux collector slice (PR3) has landed: make_dex_observer() returns the
    // /proc poll collector, no longer a no-op. start() always arms on Linux (/proc
    // is always present), so exercise the start()/stop() lifecycle to confirm the
    // poll thread spins up and joins cleanly. The /proc parsers are covered by the
    // [proc] suite.
    bool fired = false;
    CHECK(obs->start([&](const SignalObservation&) { fired = true; }));
    obs->stop();
#elif !defined(_WIN32)
    // Other non-Windows platforms remain a no-op until a collector slice lands.
    bool fired = false;
    CHECK_FALSE(obs->start([&](const SignalObservation&) { fired = true; }));
    obs->stop();
    CHECK_FALSE(fired);
#endif
}
