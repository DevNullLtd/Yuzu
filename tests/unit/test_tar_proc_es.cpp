// Tests for tar_proc_es — the Endpoint Security process collector's
// deterministic parts. The live ES client (es_new_client/subscribe/decode) needs
// the com.apple.developer.endpoint-security.client entitlement + root and is
// exercised on a SIP-disabled validation host + agent UAT, not here. What IS
// unit-testable everywhere is the pure es_sample_to_proc_event() mapping and the
// clean-fallback contract: an unentitled (CI) / off-macOS host must yield
// start()==false with no events.

#include "tar_proc_es.hpp"
#include "tar_proc_stream.hpp" // ProcStreamCollector (polymorphism test)

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

using yuzu::tar::EsProcSample;
using yuzu::tar::es_sample_to_proc_event;
using yuzu::tar::ProcEsCollector;
using yuzu::tar::ProcEvent;

TEST_CASE("es_sample_to_proc_event maps an exec to a 'started' event", "[tar][proces]") {
    EsProcSample s;
    s.is_exec = true;
    s.ts_unix = 1'700'000'000;
    s.pid = 4242;
    s.ppid = 1;
    s.executable_path = "/usr/bin/python3";
    s.uid = 501;

    ProcEvent ev = es_sample_to_proc_event(s);
    REQUIRE(ev.is_start);
    REQUIRE(ev.ts_unix == 1'700'000'000);
    REQUIRE(ev.pid == 4242);
    REQUIRE(ev.ppid == 1);
    REQUIRE(ev.image_name == "python3"); // basename only — names-only posture
    REQUIRE(ev.exit_code == 0);
    REQUIRE(ev.uid == 501);     // carried for drain-time user resolution
    REQUIRE(ev.user.empty());   // resolved at drain, not in the pure mapping
    REQUIRE(ev.sid.empty());    // Windows-only field
}

TEST_CASE("es_sample_to_proc_event maps an exit to a 'stopped' event", "[tar][proces]") {
    EsProcSample s;
    s.is_exec = false;
    s.ts_unix = 1'700'000'500;
    s.pid = 4242;
    s.ppid = 1;             // present on the sample but must be dropped on stop
    s.executable_path = "/Applications/Foo.app/Contents/MacOS/Foo";
    s.exit_status = 9;

    ProcEvent ev = es_sample_to_proc_event(s);
    REQUIRE_FALSE(ev.is_start);
    REQUIRE(ev.pid == 4242);
    REQUIRE(ev.ppid == 0);  // ppid is meaningful only on exec (mirrors the ETW peer)
    REQUIRE(ev.image_name == "Foo");
    REQUIRE(ev.exit_code == 9);
}

TEST_CASE("es_sample_to_proc_event basename handles pathless and root inputs", "[tar][proces]") {
    EsProcSample s;
    s.is_exec = true;
    s.executable_path = "bare-name"; // no slash
    REQUIRE(es_sample_to_proc_event(s).image_name == "bare-name");

    s.executable_path = ""; // empty → empty leaf
    REQUIRE(es_sample_to_proc_event(s).image_name.empty());

    s.executable_path = "/"; // root → empty leaf
    REQUIRE(es_sample_to_proc_event(s).image_name.empty());

    s.executable_path = "/usr/bin/"; // trailing slash → empty leaf (degenerate; ES never emits)
    REQUIRE(es_sample_to_proc_event(s).image_name.empty());

    s.executable_path = "//bin/sh"; // doubled separators → last component
    REQUIRE(es_sample_to_proc_event(s).image_name == "sh");
}

TEST_CASE("ProcEsCollector yields nothing before start", "[tar][proces]") {
    ProcEsCollector c(16);
    REQUIRE_FALSE(c.running());
    REQUIRE(c.drain().empty());
    REQUIRE(c.dropped() == 0);
}

TEST_CASE("ProcEsCollector start/stop lifecycle is consistent", "[tar][proces]") {
    // CI runners are unentitled (and non-Apple hosts have no ES at all), so start()
    // returns false there and the collector stays inert → caller falls back to the
    // sysctl poll. A signed+entitled SIP-disabled validation host is the only place
    // start() returns true. Assert the contract that holds in BOTH worlds rather than
    // hard-coding start()==false (which would spuriously fail on the validation host):
    // running() must mirror start(), and stop()+drain must leave the ring empty.
    ProcEsCollector c(16);
    const bool started = c.start();
    REQUIRE(c.running() == started);
    c.stop();
    REQUIRE_FALSE(c.running());
    REQUIRE(c.drain().empty());
}

TEST_CASE("ProcEsCollector is usable through the ProcStreamCollector interface",
          "[tar][proces]") {
    // The plugin holds a unique_ptr<ProcStreamCollector>; exercise the vtable so an
    // accidental object-slice or missing override (from the proc_etw_→proc_stream_
    // rename) is caught. Platform-independent: the no-op build satisfies all asserts.
    std::unique_ptr<yuzu::tar::ProcStreamCollector> col =
        std::make_unique<ProcEsCollector>(8);
    REQUIRE(col->drain().empty());
    REQUIRE(col->dropped() == 0);
    REQUIRE_FALSE(col->running());
    REQUIRE(std::string(col->method_name()) == "endpoint_security");
    col->stop(); // safe before start
}

TEST_CASE("ProcEsCollector stop is idempotent; drain-after-stop is empty", "[tar][proces]") {
    ProcEsCollector c(8);
    c.stop(); // safe before start
    c.stop();
    REQUIRE(c.drain().empty());
}

TEST_CASE("es_sample_to_proc_event preserves the inputs the handler guards on",
          "[tar][proces]") {
    // The ES handler drops events with ts_unix <= 0 or pid == 0 BEFORE the ring
    // push (parity with the ETW peer; the drop itself lives in the macOS-only
    // handler and is exercised on the Windows ETW CI leg). These locks pin the pure
    // mapping that feeds those guards so a refactor cannot silently change the
    // values the guards inspect.
    EsProcSample zero_ts;
    zero_ts.is_exec = true;
    zero_ts.ts_unix = 0;
    zero_ts.pid = 4242;
    REQUIRE(es_sample_to_proc_event(zero_ts).ts_unix == 0); // handler drops (ts <= 0)

    EsProcSample neg_ts = zero_ts;
    neg_ts.ts_unix = -1;
    REQUIRE(es_sample_to_proc_event(neg_ts).ts_unix == -1); // handler drops (ts <= 0)

    EsProcSample zero_pid;
    zero_pid.is_exec = true;
    zero_pid.ts_unix = 1'700'000'000;
    zero_pid.pid = 0;
    REQUIRE(es_sample_to_proc_event(zero_pid).pid == 0); // handler drops (pid == 0)
}

TEST_CASE("resolve_uid_cached memoizes and calls the lookup once per uid",
          "[tar][proces]") {
    // The drain-time uid→user resolution is factored behind an injectable lookup so
    // it is testable on every platform without a live passwd DB or macOS headers
    // (the production lookup is getpwuid_r, on the tick thread, off the ES queue).
    std::unordered_map<std::uint32_t, std::string> cache;
    int calls = 0;
    std::function<std::string(std::uint32_t)> lookup = [&](std::uint32_t uid) {
        ++calls;
        return uid == 0 ? std::string("root") : "uid:" + std::to_string(uid);
    };

    REQUIRE(yuzu::tar::resolve_uid_cached(cache, 0, lookup) == "root");
    REQUIRE(yuzu::tar::resolve_uid_cached(cache, 501, lookup) == "uid:501");
    REQUIRE(calls == 2);

    // Repeat lookups are served from the cache — the lookup is not invoked again.
    REQUIRE(yuzu::tar::resolve_uid_cached(cache, 0, lookup) == "root");
    REQUIRE(yuzu::tar::resolve_uid_cached(cache, 501, lookup) == "uid:501");
    REQUIRE(calls == 2);
}
