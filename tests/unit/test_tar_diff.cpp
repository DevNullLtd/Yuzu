/**
 * test_tar_diff.cpp -- Unit tests for TAR diff engine
 *
 * Covers: process birth/death, network connect/disconnect, service state
 * changes, user login/logout, empty snapshots, command-line redaction.
 */

#include "tar_collectors.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace yuzu::tar;
using yuzu::agent::ProcessInfo;

// =============================================================================
// Process diff tests
// =============================================================================

TEST_CASE("TAR diff: process birth detected", "[tar][diff][process]") {
    std::vector<ProcessInfo> prev;
    std::vector<ProcessInfo> curr = {{42, 1, "firefox", "firefox --new-tab", "user1"}};

    auto events = compute_process_diff(prev, curr, 1000, 1);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "process");
    CHECK(events[0].event_action == "started");
    CHECK(events[0].timestamp == 1000);
    CHECK(events[0].snapshot_id == 1);
    CHECK(events[0].detail_json.find("\"pid\":42") != std::string::npos);
    CHECK(events[0].detail_json.find("\"name\":\"firefox\"") != std::string::npos);
}

TEST_CASE("TAR diff: process death detected", "[tar][diff][process]") {
    std::vector<ProcessInfo> prev = {{42, 1, "firefox", "firefox --new-tab", "user1"}};
    std::vector<ProcessInfo> curr;

    auto events = compute_process_diff(prev, curr, 2000, 2);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "process");
    CHECK(events[0].event_action == "stopped");
    CHECK(events[0].detail_json.find("\"pid\":42") != std::string::npos);
}

TEST_CASE("TAR diff: unchanged processes produce no events", "[tar][diff][process]") {
    std::vector<ProcessInfo> both = {
        {1, 0, "init", "/sbin/init", "root"},
        {42, 1, "firefox", "firefox", "user1"},
    };

    auto events = compute_process_diff(both, both, 3000, 3);
    CHECK(events.empty());
}

TEST_CASE("TAR diff: empty process snapshots produce no events", "[tar][diff][process]") {
    std::vector<ProcessInfo> empty;
    auto events = compute_process_diff(empty, empty, 4000, 4);
    CHECK(events.empty());
}

// =============================================================================
// Network diff tests
// =============================================================================

TEST_CASE("TAR diff: new connection detected", "[tar][diff][network]") {
    std::vector<NetConnection> prev;
    NetConnection nc;
    nc.proto = "tcp";
    nc.local_addr = "192.168.1.1";
    nc.local_port = 12345;
    nc.remote_addr = "10.0.0.1";
    nc.remote_port = 443;
    nc.state = "ESTABLISHED";
    nc.pid = 100;
    std::vector<NetConnection> curr = {nc};

    auto events = compute_network_diff(prev, curr, 5000, 5);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "network");
    CHECK(events[0].event_action == "connected");
    CHECK(events[0].detail_json.find("\"proto\":\"tcp\"") != std::string::npos);
    CHECK(events[0].detail_json.find("\"remote_port\":443") != std::string::npos);
}

TEST_CASE("TAR diff: closed connection detected", "[tar][diff][network]") {
    NetConnection nc;
    nc.proto = "tcp";
    nc.local_addr = "192.168.1.1";
    nc.local_port = 12345;
    nc.remote_addr = "10.0.0.1";
    nc.remote_port = 443;
    nc.state = "ESTABLISHED";
    nc.pid = 100;
    std::vector<NetConnection> prev = {nc};
    std::vector<NetConnection> curr;

    auto events = compute_network_diff(prev, curr, 6000, 6);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "network");
    CHECK(events[0].event_action == "disconnected");
}

TEST_CASE("TAR diff: empty network snapshots produce no events", "[tar][diff][network]") {
    std::vector<NetConnection> empty;
    auto events = compute_network_diff(empty, empty, 7000, 7);
    CHECK(events.empty());
}

TEST_CASE("TAR diff: remote_host appears in network event JSON", "[tar][diff][network]") {
    std::vector<NetConnection> prev;
    NetConnection nc;
    nc.proto = "tcp";
    nc.local_addr = "192.168.1.1";
    nc.local_port = 54321;
    nc.remote_addr = "93.184.216.34";
    nc.remote_host = "example.com";
    nc.remote_port = 443;
    nc.state = "ESTABLISHED";
    nc.pid = 200;
    nc.process_name = "curl";
    std::vector<NetConnection> curr = {nc};

    auto events = compute_network_diff(prev, curr, 8000, 8);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_action == "connected");
    CHECK(events[0].detail_json.find("\"remote_host\":\"example.com\"") != std::string::npos);
    CHECK(events[0].detail_json.find("\"remote_addr\":\"93.184.216.34\"") != std::string::npos);
}

TEST_CASE("TAR diff: empty remote_host produces empty string in JSON", "[tar][diff][network]") {
    std::vector<NetConnection> prev;
    NetConnection nc;
    nc.proto = "tcp";
    nc.local_addr = "10.0.0.1";
    nc.local_port = 12345;
    nc.remote_addr = "172.16.0.1";
    // remote_host left empty (no PTR record)
    nc.remote_port = 80;
    nc.state = "ESTABLISHED";
    nc.pid = 300;
    std::vector<NetConnection> curr = {nc};

    auto events = compute_network_diff(prev, curr, 9000, 9);

    REQUIRE(events.size() == 1);
    CHECK(events[0].detail_json.find("\"remote_host\":\"\"") != std::string::npos);
}

TEST_CASE("TAR diff: remote_host in disconnected event", "[tar][diff][network]") {
    NetConnection nc;
    nc.proto = "tcp";
    nc.local_addr = "10.0.0.1";
    nc.local_port = 12345;
    nc.remote_addr = "93.184.216.34";
    nc.remote_host = "example.com";
    nc.remote_port = 443;
    nc.state = "ESTABLISHED";
    nc.pid = 400;
    std::vector<NetConnection> prev = {nc};
    std::vector<NetConnection> curr;

    auto events = compute_network_diff(prev, curr, 10000, 10);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_action == "disconnected");
    CHECK(events[0].detail_json.find("\"remote_host\":\"example.com\"") != std::string::npos);
}

// =============================================================================
// Service diff tests
// =============================================================================

TEST_CASE("TAR diff: service state change detected", "[tar][diff][service]") {
    ServiceInfo running;
    running.name = "sshd";
    running.display_name = "OpenSSH Server";
    running.status = "running";
    running.startup_type = "automatic";

    ServiceInfo stopped = running;
    stopped.status = "stopped";

    std::vector<ServiceInfo> prev = {running};
    std::vector<ServiceInfo> curr = {stopped};

    auto events = compute_service_diff(prev, curr, 8000, 8);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "service");
    CHECK(events[0].event_action == "state_changed");
    CHECK(events[0].detail_json.find("\"status\":\"stopped\"") != std::string::npos);
    CHECK(events[0].detail_json.find("\"prev_status\":\"running\"") != std::string::npos);
}

TEST_CASE("TAR diff: new service detected", "[tar][diff][service]") {
    std::vector<ServiceInfo> prev;
    ServiceInfo svc;
    svc.name = "nginx";
    svc.display_name = "NGINX";
    svc.status = "running";
    svc.startup_type = "automatic";
    std::vector<ServiceInfo> curr = {svc};

    auto events = compute_service_diff(prev, curr, 9000, 9);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_action == "started");
}

TEST_CASE("TAR diff: removed service detected", "[tar][diff][service]") {
    ServiceInfo svc;
    svc.name = "nginx";
    svc.display_name = "NGINX";
    svc.status = "running";
    svc.startup_type = "automatic";
    std::vector<ServiceInfo> prev = {svc};
    std::vector<ServiceInfo> curr;

    auto events = compute_service_diff(prev, curr, 10000, 10);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_action == "stopped");
}

// ── Finding 3 (adversarial-review round 5): a Windows per-service
// OpenServiceW/QueryServiceConfigW failure must never manufacture a
// diffable startup_type change. ServiceInfo::startup_type_query_failed
// marks a row whose startup_type came from a FAILED query rather than a
// genuine observation; compute_service_diff/compute_service_events must
// both exclude such a row's startup_type from the change comparison, in
// both directions (the transient failure, and the recovery on the next
// successful read).

TEST_CASE("TAR diff: a startup_type-query-failure row does NOT produce a "
          "state_changed event even though startup_type literally differs "
          "(compute_service_diff)",
          "[tar][diff][service][finding3]") {
    ServiceInfo automatic;
    automatic.name = "spooler";
    automatic.display_name = "Print Spooler";
    automatic.status = "running";
    automatic.startup_type = "automatic";
    automatic.startup_type_query_failed = false;

    ServiceInfo query_failed = automatic;
    query_failed.startup_type = "unknown";
    query_failed.startup_type_query_failed = true; // transient per-service query failure

    std::vector<ServiceInfo> prev = {automatic};
    std::vector<ServiceInfo> curr = {query_failed};

    auto events = compute_service_diff(prev, curr, 11000, 11);
    CHECK(events.empty());
}

TEST_CASE("TAR diff: recovery from a startup_type-query-failure row does NOT "
          "produce a false inverse state_changed event "
          "(compute_service_diff)",
          "[tar][diff][service][finding3]") {
    ServiceInfo query_failed;
    query_failed.name = "spooler";
    query_failed.display_name = "Print Spooler";
    query_failed.status = "running";
    query_failed.startup_type = "unknown";
    query_failed.startup_type_query_failed = true;

    ServiceInfo automatic = query_failed;
    automatic.startup_type = "automatic";
    automatic.startup_type_query_failed = false; // the query succeeded this time

    std::vector<ServiceInfo> prev = {query_failed};
    std::vector<ServiceInfo> curr = {automatic};

    auto events = compute_service_diff(prev, curr, 12000, 12);
    CHECK(events.empty());
}

TEST_CASE("TAR diff: a status change still fires alongside a suppressed "
          "startup_type-query-failure (compute_service_diff)",
          "[tar][diff][service][finding3]") {
    ServiceInfo running;
    running.name = "spooler";
    running.display_name = "Print Spooler";
    running.status = "running";
    running.startup_type = "automatic";
    running.startup_type_query_failed = false;

    ServiceInfo stopped_query_failed = running;
    stopped_query_failed.status = "stopped";
    stopped_query_failed.startup_type = "unknown";
    stopped_query_failed.startup_type_query_failed = true;

    std::vector<ServiceInfo> prev = {running};
    std::vector<ServiceInfo> curr = {stopped_query_failed};

    auto events = compute_service_diff(prev, curr, 13000, 13);
    REQUIRE(events.size() == 1);
    CHECK(events[0].event_action == "state_changed");
    CHECK(events[0].detail_json.find("\"status\":\"stopped\"") != std::string::npos);
}

TEST_CASE("TAR diff: same startup_type_query_failed guard holds for "
          "compute_service_events, the real production call site "
          "do_snapshot uses",
          "[tar][diff][service][finding3]") {
    ServiceInfo automatic;
    automatic.name = "spooler";
    automatic.display_name = "Print Spooler";
    automatic.status = "running";
    automatic.startup_type = "automatic";
    automatic.startup_type_query_failed = false;

    ServiceInfo query_failed = automatic;
    query_failed.startup_type = "unknown";
    query_failed.startup_type_query_failed = true;

    std::vector<ServiceInfo> prev = {automatic};
    std::vector<ServiceInfo> curr = {query_failed};

    auto events = compute_service_events(prev, curr, 14000, 14);
    CHECK(events.empty());
}

// =============================================================================
// User diff tests
// =============================================================================

TEST_CASE("TAR diff: user login detected", "[tar][diff][user]") {
    std::vector<UserSession> prev;
    UserSession us;
    us.user = "admin";
    us.domain = "CORP";
    us.logon_type = "interactive";
    us.session_id = "1";
    std::vector<UserSession> curr = {us};

    auto events = compute_user_diff(prev, curr, 11000, 11);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "user");
    CHECK(events[0].event_action == "login");
    CHECK(events[0].detail_json.find("\"user\":\"admin\"") != std::string::npos);
}

TEST_CASE("TAR diff: user logout detected", "[tar][diff][user]") {
    UserSession us;
    us.user = "admin";
    us.domain = "CORP";
    us.logon_type = "interactive";
    us.session_id = "1";
    std::vector<UserSession> prev = {us};
    std::vector<UserSession> curr;

    auto events = compute_user_diff(prev, curr, 12000, 12);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "user");
    CHECK(events[0].event_action == "logout");
}

TEST_CASE("TAR diff: empty user snapshots produce no events", "[tar][diff][user]") {
    std::vector<UserSession> empty;
    auto events = compute_user_diff(empty, empty, 13000, 13);
    CHECK(events.empty());
}

// =============================================================================
// Redaction tests
// =============================================================================

TEST_CASE("TAR redaction: password in cmdline is redacted", "[tar][diff][redaction]") {
    auto patterns = kDefaultRedactionPatterns;

    CHECK(should_redact("myapp --password=hunter2", patterns));
    CHECK(should_redact("curl -H 'Authorization: Bearer TOKEN_VALUE'", patterns));
    CHECK(should_redact("export API_KEY=abc123", patterns));
    CHECK(should_redact("vault read secret/database", patterns));
    CHECK(should_redact("app --credential-file=/path", patterns));

    CHECK_FALSE(should_redact("ls -la /tmp", patterns));
    CHECK_FALSE(should_redact("firefox https://example.com", patterns));
    CHECK_FALSE(should_redact("", patterns));
}

TEST_CASE("TAR redaction: redact_cmdline returns sentinel", "[tar][diff][redaction]") {
    auto patterns = kDefaultRedactionPatterns;

    auto result = redact_cmdline("myapp --password=hunter2", patterns);
    CHECK(result == "[REDACTED by TAR]");

    auto safe = redact_cmdline("ls -la", patterns);
    CHECK(safe == "ls -la");
}

TEST_CASE("TAR diff: process with sensitive cmdline is redacted in events", "[tar][diff][redaction]") {
    std::vector<ProcessInfo> prev;
    std::vector<ProcessInfo> curr = {
        {99, 1, "myapp", "myapp --password=hunter2", "root"}};

    auto events = compute_process_diff(prev, curr, 14000, 14);

    REQUIRE(events.size() == 1);
    CHECK(events[0].detail_json.find("[REDACTED by TAR]") != std::string::npos);
    CHECK(events[0].detail_json.find("hunter2") == std::string::npos);
}

TEST_CASE("TAR redaction: ensure_redaction_defaults is fail-closed for every input (#1532)",
          "[tar][diff][redaction][issue1532]") {
    // fjarvis HIGH: no loaded set may disable the baseline redaction. load_redaction_patterns
    // routes the parse_pattern_config result through ensure_redaction_defaults; the fail-open
    // was that a valid array whose elements all get dropped (`[]`, `[1,2,3]`, all-over-long, or
    // `["*"]`) yields an EMPTY loaded vector. Prove every such loaded vector still redacts.
    auto contains_all_defaults = [](const std::vector<std::string>& v) {
        for (const auto& def : kDefaultRedactionPatterns)
            if (std::find(v.begin(), v.end(), def) == v.end())
                return false;
        return true;
    };

    SECTION("empty loaded set (the all-dropped / empty-array fail-open) still redacts") {
        auto merged = ensure_redaction_defaults({});
        CHECK(contains_all_defaults(merged));
        CHECK(should_redact("myapp --password=hunter2", merged));
        CHECK(should_redact("export API_KEY=abc123", merged));
        CHECK(should_redact("vault read secret/database", merged));
    }

    SECTION("operator-custom patterns are ADDED to, never REPLACE, the defaults") {
        auto merged = ensure_redaction_defaults({"*myorg_session*"});
        CHECK(contains_all_defaults(merged));
        CHECK(std::find(merged.begin(), merged.end(), "*myorg_session*") != merged.end());
        CHECK(should_redact("svc --myorg_session=xyz", merged)); // custom still applies
        CHECK(should_redact("svc --password=p", merged));        // default still applies
    }

    SECTION("a loaded set already holding a default is not duplicated") {
        auto merged = ensure_redaction_defaults({"*password*"});
        CHECK(contains_all_defaults(merged));
        CHECK(std::count(merged.begin(), merged.end(), std::string{"*password*"}) == 1);
    }
}

// =============================================================================
// L3: Edge case tests — empty redaction patterns, long cmdline, unicode username
// =============================================================================

TEST_CASE("TAR redaction: empty patterns list never redacts", "[tar][diff][redaction][edge]") {
    std::vector<std::string> empty_patterns;
    CHECK_FALSE(should_redact("myapp --password=hunter2", empty_patterns));
    CHECK_FALSE(should_redact("export API_KEY=abc123", empty_patterns));
    CHECK_FALSE(should_redact("", empty_patterns));

    auto result = redact_cmdline("myapp --password=hunter2", empty_patterns);
    CHECK(result == "myapp --password=hunter2");
}

TEST_CASE("TAR diff: long cmdline (1KB+) is handled correctly", "[tar][diff][process][edge]") {
    // Build a command line longer than 1KB
    std::string long_cmdline = "java -jar app.jar";
    for (int i = 0; i < 100; ++i) {
        long_cmdline += " --option-" + std::to_string(i) + "=value" + std::to_string(i);
    }
    REQUIRE(long_cmdline.size() > 1024);

    std::vector<ProcessInfo> prev;
    std::vector<ProcessInfo> curr = {{500, 1, "java", long_cmdline, "appuser"}};

    auto events = compute_process_diff(prev, curr, 15000, 15);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "process");
    CHECK(events[0].event_action == "started");
    // The long cmdline should appear in detail_json (not truncated silently)
    CHECK(events[0].detail_json.find("java") != std::string::npos);
}

TEST_CASE("TAR diff: unicode username in process events", "[tar][diff][process][edge]") {
    std::vector<ProcessInfo> prev;
    // Use a username with multi-byte UTF-8 characters
    std::vector<ProcessInfo> curr = {
        {77, 1, "editor", "editor /tmp/file.txt", "\xc3\xa9\x6d\x69\x6c\x65"}};  // "emile" with accented e

    auto events = compute_process_diff(prev, curr, 16000, 16);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "process");
    CHECK(events[0].event_action == "started");
    // The unicode username should be preserved in the JSON
    CHECK(events[0].detail_json.find("\xc3\xa9\x6d\x69\x6c\x65") != std::string::npos);
}

// ── #541: should_redact is case-insensitive SUBSTRING, not real glob ────────

TEST_CASE("TAR should_redact: case-insensitive substring, not glob", "[tar][diff][redact][issue541]") {
    // Plain substring containment, case-insensitive.
    CHECK(should_redact("PASSWORD=hunter2", {"password"}));
    CHECK(should_redact("api --Token=abc", {"token"}));
    CHECK_FALSE(should_redact("nothing here", {"secret"}));

    // Leading/trailing '*' are stripped to the core substring (a readability
    // affordance), then matched as substring.
    CHECK(should_redact("my secret value", {"*secret*"}));
    CHECK(should_redact("prefix-token", {"*token"}));

    // '?' and '[abc]' are LITERALS, not glob metacharacters.
    CHECK(should_redact("run with ?flag", {"?flag"}));      // literal '?'
    CHECK_FALSE(should_redact("run with xflag", {"?flag"})); // '?' is NOT "any char"
    CHECK(should_redact("path [abc] here", {"[abc]"}));      // literal bracket
    CHECK_FALSE(should_redact("path a here", {"[abc]"}));    // not a char class

    // A pattern that strips to an empty core matches nothing (no-op).
    CHECK_FALSE(should_redact("anything", {"*"}));
}

// =============================================================================
// Typed warehouse events — macOS names-only (B-heavy)
// =============================================================================

TEST_CASE("TAR compute_process_events: macOS is names-only; cmdline kept elsewhere",
          "[tar][diff][process]") {
    // On macOS the poll path blanks cmdline (parity with the Endpoint Security
    // stream and the works-council / data-minimization posture); Linux/Windows keep
    // the (redacted) command line. Locks the #if defined(__APPLE__) branch in
    // compute_process_events so the macOS names-only guarantee can't silently regress.
    std::vector<ProcessInfo> prev; // empty previous → current process is a 'started'
    std::vector<ProcessInfo> curr = {
        {4242, 1, "python3", "/usr/bin/python3 --token=secret", "alice"}};

    auto events = compute_process_events(prev, curr, 1000, 7, /*redaction_patterns=*/{});
    REQUIRE(events.size() == 1);
    CHECK(events[0].action == "started");
    CHECK(events[0].pid == 4242);
    CHECK(events[0].name == "python3");
#if defined(__APPLE__)
    CHECK(events[0].cmdline.empty()); // names-only on macOS — both ES stream and poll
#else
    CHECK(events[0].cmdline == "/usr/bin/python3 --token=secret"); // populated on Linux/Windows
#endif
}

// =============================================================================
// Software install/uninstall diff tests (compute_software_events)
// =============================================================================

namespace {
SoftwareInfo sw(std::string name, std::string version) {
    SoftwareInfo s;
    s.name = std::move(name);
    s.version = std::move(version);
    s.publisher = "Acme";
    s.install_date = "20260101";
    return s;
}
} // namespace

TEST_CASE("TAR software diff: install detected", "[tar][diff][software]") {
    std::vector<SoftwareInfo> prev;
    std::vector<SoftwareInfo> curr = {sw("7-Zip", "23.01")};

    auto events = compute_software_events(prev, curr, 1000, 1);

    REQUIRE(events.size() == 1);
    CHECK(events[0].action == "installed");
    CHECK(events[0].name == "7-Zip");
    CHECK(events[0].version == "23.01");
    CHECK(events[0].prev_version.empty());
    CHECK(events[0].ts == 1000);
    CHECK(events[0].snapshot_id == 1);
}

TEST_CASE("TAR software diff: removal detected", "[tar][diff][software]") {
    std::vector<SoftwareInfo> prev = {sw("7-Zip", "23.01")};
    std::vector<SoftwareInfo> curr;

    auto events = compute_software_events(prev, curr, 2000, 2);

    REQUIRE(events.size() == 1);
    CHECK(events[0].action == "removed");
    CHECK(events[0].name == "7-Zip");
}

TEST_CASE("TAR software diff: version change is one upgrade, not remove+install",
          "[tar][diff][software]") {
    std::vector<SoftwareInfo> prev = {sw("7-Zip", "23.01")};
    std::vector<SoftwareInfo> curr = {sw("7-Zip", "24.00")};

    auto events = compute_software_events(prev, curr, 3000, 3);

    REQUIRE(events.size() == 1);
    CHECK(events[0].action == "upgraded");
    CHECK(events[0].version == "24.00");
    CHECK(events[0].prev_version == "23.01");
}

TEST_CASE("TAR software diff: same version produces no event", "[tar][diff][software]") {
    std::vector<SoftwareInfo> prev = {sw("7-Zip", "23.01")};
    std::vector<SoftwareInfo> curr = {sw("7-Zip", "23.01")};

    auto events = compute_software_events(prev, curr, 4000, 4);

    CHECK(events.empty());
}

TEST_CASE("TAR software diff: empty snapshots produce no events (cold-start contract)",
          "[tar][diff][software]") {
    // The plugin seeds the baseline silently on first run; at the diff level an
    // empty-vs-empty comparison must produce nothing.
    std::vector<SoftwareInfo> prev;
    std::vector<SoftwareInfo> curr;

    auto events = compute_software_events(prev, curr, 7000, 7);

    CHECK(events.empty());
}

TEST_CASE("TAR software diff: an unchanged entry is inert while a sibling changes",
          "[tar][diff][software]") {
    // An entry byte-identical in previous and current must emit NO event even when
    // another entry in the same snapshot genuinely changes — only the real change
    // is reported.
    std::vector<SoftwareInfo> prev = {sw("Notepad++", "8.6"), sw("7-Zip", "23.01")};
    std::vector<SoftwareInfo> curr = {sw("Notepad++", "8.6"),  // unchanged
                                      sw("7-Zip", "24.00")};    // real upgrade

    auto events = compute_software_events(prev, curr, 8000, 8);

    REQUIRE(events.size() == 1); // only the upgrade — the unchanged entry is inert
    CHECK(events[0].action == "upgraded");
    CHECK(events[0].name == "7-Zip");
}

// =============================================================================
// ARP diff tests (ADR-0015) — keyed on (iface, ip, mac); entry_type not keyed
// =============================================================================

TEST_CASE("ARP diff: appeared and removed bindings", "[tar][diff][arp]") {
    std::vector<ArpEntry> prev = {{"Ethernet", "192.168.1.1", "aa:bb:cc:dd:ee:ff", "dynamic"}};
    std::vector<ArpEntry> cur = {{"Ethernet", "192.168.1.1", "aa:bb:cc:dd:ee:ff", "dynamic"},
                                 {"Ethernet", "192.168.1.2", "11:22:33:44:55:66", "static"}};
    auto ev = compute_arp_events(prev, cur, 100, 7);
    REQUIRE(ev.size() == 1);
    CHECK(ev[0].action == "appeared");
    CHECK(ev[0].ip_address == "192.168.1.2");
    CHECK(ev[0].snapshot_id == 7);

    auto removed = compute_arp_events(cur, prev, 101, 8);
    REQUIRE(removed.size() == 1);
    CHECK(removed[0].action == "removed");
    CHECK(removed[0].ip_address == "192.168.1.2");
}

TEST_CASE("ARP diff: entry_type change on same binding is not churn", "[tar][diff][arp]") {
    std::vector<ArpEntry> prev = {{"Ethernet", "10.0.0.1", "aa:bb:cc:dd:ee:ff", "dynamic"}};
    std::vector<ArpEntry> cur = {{"Ethernet", "10.0.0.1", "aa:bb:cc:dd:ee:ff", "static"}};
    CHECK(compute_arp_events(prev, cur, 100, 1).empty());
}

// =============================================================================
// DNS diff tests (ADR-0015) — keyed on (name, type, data); TTL not keyed
// =============================================================================

TEST_CASE("DNS diff: appeared and removed resolutions", "[tar][diff][dns]") {
    std::vector<DnsEntry> prev = {{"example.com", "A", "93.184.216.34", 60, "cache"}};
    std::vector<DnsEntry> cur = {{"example.com", "A", "93.184.216.34", 60, "cache"},
                                 {"evil.test", "A", "10.0.0.9", 10, "cache"}};
    auto ev = compute_dns_events(prev, cur, 100, 5);
    REQUIRE(ev.size() == 1);
    CHECK(ev[0].action == "appeared");
    CHECK(ev[0].name == "evil.test");

    auto removed = compute_dns_events(cur, prev, 101, 6);
    REQUIRE(removed.size() == 1);
    CHECK(removed[0].action == "removed");
    CHECK(removed[0].name == "evil.test");
}

TEST_CASE("DNS diff: TTL decrement on same resolution is not churn", "[tar][diff][dns]") {
    std::vector<DnsEntry> prev = {{"example.com", "A", "93.184.216.34", 60, "cache"}};
    std::vector<DnsEntry> cur = {{"example.com", "A", "93.184.216.34", 30, "cache"}};
    CHECK(compute_dns_events(prev, cur, 100, 1).empty());
}

// =============================================================================
// Mapped-drive diff tests (§3.8) — keyed on (direction, local_mount,
// remote_path, remote_host, username); provider is value-only.
// MapDriveEntry field order: {direction, local_mount, remote_path, remote_host,
// username, provider}.
// =============================================================================

TEST_CASE("mapdrive diff: outbound appeared and removed", "[tar][diff][mapdrive]") {
    std::vector<MapDriveEntry> prev = {
        {"outbound", "Z:", "\\\\srv\\share", "srv", "alice", "SMB"}};
    std::vector<MapDriveEntry> cur = {
        {"outbound", "Z:", "\\\\srv\\share", "srv", "alice", "SMB"},
        {"outbound", "Y:", "\\\\nas\\home", "nas", "bob", "SMB"}};
    auto ev = compute_mapdrive_events(prev, cur, 100, 7);
    REQUIRE(ev.size() == 1);
    CHECK(ev[0].action == "appeared");
    CHECK(ev[0].local_mount == "Y:");
    CHECK(ev[0].direction == "outbound");
    CHECK(ev[0].origin == "live"); // never blank; historical rows bypass the diff
    CHECK(ev[0].snapshot_id == 7);

    auto removed = compute_mapdrive_events(cur, prev, 101, 8);
    REQUIRE(removed.size() == 1);
    CHECK(removed[0].action == "removed");
    CHECK(removed[0].local_mount == "Y:");
    CHECK(removed[0].origin == "live");
}

TEST_CASE("mapdrive diff: provider change on same mapping is not churn",
          "[tar][diff][mapdrive]") {
    std::vector<MapDriveEntry> prev = {
        {"outbound", "Z:", "\\\\srv\\share", "srv", "alice", "SMB"}};
    std::vector<MapDriveEntry> cur = {
        {"outbound", "Z:", "\\\\srv\\share", "srv", "alice", "WebDAV"}};
    CHECK(compute_mapdrive_events(prev, cur, 100, 1).empty());
}

TEST_CASE("mapdrive diff: direction is keyed — outbound and inbound do not collide",
          "[tar][diff][mapdrive]") {
    // Same host+user on both sides: an outbound map to `peer` and an inbound
    // session from `peer` must be two distinct mappings, not a collision.
    std::vector<MapDriveEntry> prev;
    std::vector<MapDriveEntry> cur = {
        {"outbound", "Z:", "\\\\peer\\share", "peer", "alice", "SMB"},
        {"inbound", "", "", "peer", "alice", "SMB"}};
    auto ev = compute_mapdrive_events(prev, cur, 100, 1);
    REQUIRE(ev.size() == 2);
    CHECK(ev[0].origin == "live");
    CHECK(ev[1].origin == "live");
}

TEST_CASE("mapdrive diff: re-credentialed mount is removed + appeared",
          "[tar][diff][mapdrive]") {
    // username is keyed: remapping Z: under new creds is a genuine transition —
    // a single diff yields one appeared (new creds) + one removed (old creds).
    std::vector<MapDriveEntry> prev = {
        {"outbound", "Z:", "\\\\srv\\share", "srv", "alice", "SMB"}};
    std::vector<MapDriveEntry> cur = {
        {"outbound", "Z:", "\\\\srv\\share", "srv", "bob", "SMB"}};
    auto ev = compute_mapdrive_events(prev, cur, 100, 1);
    REQUIRE(ev.size() == 2);
    bool saw_appeared_bob = false, saw_removed_alice = false;
    for (const auto& e : ev) {
        if (e.action == "appeared" && e.username == "bob")
            saw_appeared_bob = true;
        if (e.action == "removed" && e.username == "alice")
            saw_removed_alice = true;
        CHECK(e.origin == "live");
    }
    CHECK(saw_appeared_bob);
    CHECK(saw_removed_alice);
}
