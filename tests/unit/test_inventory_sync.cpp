// Agent daily-sync tests (ADR-0016): the canonical-hash cross-pin with the
// server, installed_apps output parsing, and the SyncScheduler hash-skip /
// need_full / first-run state machine (gRPC + KV injected — no network).

#include <catch2/catch_test_macros.hpp>

#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // sha256_hex
#include "sync_scheduler.hpp"
#include "middleware_runner.hpp" // yuzu::middleware::run_leg: the REAL runner feeds the middleware cases
#include "msi_packages_inventory.hpp"
#include "pkg_inventory_parsers.hpp"
#include "runtimes_parsers.hpp"
#include "runtimes_python_parsers.hpp"
#include "sync_source_installed_software.hpp"
#include "windows_optional_features_parsers.hpp"

#include <inventory_status_row.hpp>

#include <yuzu/plugin.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using yuzu::agent::AdaptedRows;
using yuzu::agent::ConstrainedPolicy;
using yuzu::agent::installed_software_canonical_blob;
using yuzu::agent::make_installed_software_source;
using yuzu::agent::parse_middleware_output;
using yuzu::agent::parse_msi_packages_list_inventory_output;
using yuzu::agent::parse_pkg_inventory_managers_output;
using yuzu::agent::parse_pkg_inventory_packages_output;
using yuzu::agent::parse_pkg_inventory_store_packages_output;
using yuzu::agent::parse_runtimes_dotnet_output;
using yuzu::agent::parse_runtimes_jvm_output;
using yuzu::agent::parse_runtimes_python_output;
using yuzu::agent::parse_windows_optional_features_output;
using yuzu::agent::parse_installed_apps_output;
using yuzu::agent::sha256_hex;
using yuzu::agent::SwEntry;
using yuzu::agent::SyncPluginMap;
using yuzu::agent::SyncScheduler;
using yuzu::agent::SyncSource;

namespace {
// THE cross-side pin (ADR-0016 §4, blob contract v2 — 12 fields): the server
// computes the SAME hash for the SAME input
// (tests/unit/server/test_software_inventory_store.cpp — identical constant).
// A one-byte drift in either canonicalisation fails one assertion.
constexpr const char* kCrossPinHash =
    "430dc97e02b5d217276a9558393d702366bcd3b5415d5867c9efd4e95a02c848";

// Fully-populated v2 entry — the identical fixture the server pin test uses.
SwEntry full_v2_entry() {
    SwEntry e;
    e.name = "bash";
    e.version = "5.2.21";
    e.publisher = "Fedora Project";
    e.install_date = "Mon 01 Jan 2026";
    e.kind = "package";
    e.ecosystem = "rpm";
    e.epoch = "0";
    e.release = "3.fc40";
    e.arch = "x86_64";
    e.signature_status = "signed";
    e.distro_id = "fedora";
    e.distro_version = "40";
    return e;
}
} // namespace

TEST_CASE("installed_software canonical hash matches the cross-pin", "[sync][hash]") {
    // Unsorted + duplicate + one entry populating ALL 12 v2 fields:
    // canonical_blob must sort + dedup to the exact bytes the constant was
    // computed from.
    std::vector<SwEntry> e = {
        {"Zeta", "9", "", ""},
        full_v2_entry(),
        {"Acme Reader", "1.2", "Acme", "2026-01-02"},
        {"Acme Reader", "1.2", "Acme", "2026-01-02"},
    };
    CHECK(sha256_hex(installed_software_canonical_blob(e)) == kCrossPinHash);
}

TEST_CASE("parse_installed_apps_output keeps inv| rows only (blob v2)", "[sync][parse]") {
    const std::string out =
        "inv|bash|5.2.21|Fedora Project|Mon 01 Jan 2026|package|rpm|0|3.fc40|x86_64|signed|"
        "fedora|40\n"
        "app|Chrome|119|Google|2026-01-01\n"            // legacy list row → dropped
        "user_app|bob|UserThing|1|Acme|2026-01-01\n"    // per-user → dropped
        "error|something failed\n"                      // error → dropped
        "inv|Google Chrome|126.0|Google LLC||app|windows||||||\n";
    auto entries = parse_installed_apps_output(out);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].name == "bash");
    CHECK(entries[0].version == "5.2.21");
    CHECK(entries[0].publisher == "Fedora Project");
    CHECK(entries[0].kind == "package");
    CHECK(entries[0].ecosystem == "rpm");
    CHECK(entries[0].epoch == "0");
    CHECK(entries[0].release == "3.fc40");
    CHECK(entries[0].arch == "x86_64");
    CHECK(entries[0].signature_status == "signed");
    CHECK(entries[0].distro_id == "fedora");
    CHECK(entries[0].distro_version == "40");
    CHECK(entries[1].name == "Google Chrome");
    CHECK(entries[1].kind == "app");
    CHECK(entries[1].ecosystem == "windows");
    CHECK(entries[1].install_date.empty()); // honest-empty, no "-" placeholder
    CHECK(entries[1].signature_status.empty());
}

TEST_CASE("parse_installed_apps_output tolerates short and over-long inv rows",
          "[sync][parse]") {
    SECTION("missing trailing tokens read as empty fields") {
        auto entries = parse_installed_apps_output("inv|OnlyName|1.0\n");
        REQUIRE(entries.size() == 1);
        CHECK(entries[0].name == "OnlyName");
        CHECK(entries[0].version == "1.0");
        CHECK(entries[0].publisher.empty());
        CHECK(entries[0].kind.empty());
        CHECK(entries[0].distro_version.empty());
    }
    SECTION("tokens past the 12th field are dropped, fields do not shift") {
        auto entries = parse_installed_apps_output(
            "inv|N|v|p|d|package|deb|1|2|amd64|sig|debian|12|EXTRA\n");
        REQUIRE(entries.size() == 1);
        CHECK(entries[0].name == "N");
        CHECK(entries[0].distro_id == "debian");
        CHECK(entries[0].distro_version == "12"); // EXTRA dropped — mirrors the
                                                  // server's parse past field 12
    }
    SECTION("empty-name rows are dropped") {
        CHECK(parse_installed_apps_output("inv||1.0\n").empty());
    }
}

namespace {

// A live agent wakes at least every kMaxTickSeconds. A single tick() far past a source's
// next_fire is a resume from sleep (SAM-19: re-armed with a spread, not fired at once), so a
// test that means "one interval later" walks the clock the way the agent's own loop does.
std::int64_t live_advance(SyncScheduler& sched, std::int64_t from, std::int64_t to,
                          const std::function<bool()>& done = {}) {
    std::int64_t t = from;
    while (t < to) {
        t = std::min(t + SyncScheduler::kMaxTickSeconds.count(), to);
        sched.tick(t);
        if (done && done())
            break;
    }
    return t;
}

} // namespace

TEST_CASE("SyncScheduler: first-run jitter, hash-skip, change, need_full", "[sync][scheduler]") {
    std::map<std::string, std::string> kv;
    auto kv_get = [&](const std::string& k) {
        auto it = kv.find(k);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto kv_set = [&](const std::string& k, const std::string& v) { kv[k] = v; };

    int calls = 0;
    bool last_had_blob = false;
    std::vector<std::string> next_need; // what the server returns as need_full
    auto sender = [&](const std::vector<std::pair<std::string, std::string>>& /*hashes*/,
                      const std::vector<std::pair<std::string, std::string>>& blobs)
        -> std::optional<std::vector<std::string>> {
        ++calls;
        last_had_blob = !blobs.empty();
        return next_need; // non-nullopt = RPC success
    };

    std::string cur_hash = "h1";
    std::string cur_blob = "b1";
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::seconds{86400};
    src.collect = [&]() -> std::optional<std::pair<std::string, std::string>> {
        return std::make_pair(cur_blob, cur_hash);
    };

    SyncScheduler sched("agent-1", kv_get, kv_set, sender);
    sched.add_source(src);

    // First tick only schedules the startup-jittered first fire — not yet due.
    sched.tick(1000);
    CHECK(calls == 0);

    // Past the max startup-jitter window (10 min) → due; first send is FULL
    // (no last_hash yet).
    sched.tick(1000 + 700);
    REQUIRE(calls == 1);
    CHECK(last_had_blob);

    // Unchanged content one interval later → hash-only (no blob).
    std::int64_t t2 = 1000 + 700 + 86400 + 1;
    live_advance(sched, 1700, t2);
    REQUIRE(calls == 2);
    CHECK_FALSE(last_had_blob);

    // Changed content → FULL.
    cur_hash = "h2";
    cur_blob = "b2";
    std::int64_t t3 = t2 + 86400 + 1;
    live_advance(sched, t2, t3);
    REQUIRE(calls == 3);
    CHECK(last_had_blob);

    // Server asks for a resend (need_full): this cycle is hash-only (unchanged),
    // but the scheduler then force-fulls on the next pass.
    next_need = {"installed_software"};
    std::int64_t t4 = t3 + 86400 + 1;
    t4 = live_advance(sched, t3, t4, [&] { return calls == 4; }); // stop at the nacked send
    REQUIRE(calls == 4);
    CHECK_FALSE(last_had_blob); // hash-only send that the server nacked

    next_need = {}; // server satisfied now
    // Past the jittered need_full reschedule (kMinTickSeconds + up to
    // kNeedFullJitterWindow).
    std::int64_t t5 = t4 + SyncScheduler::kMinTickSeconds.count() +
                      SyncScheduler::kNeedFullJitterWindow.count() + 1;
    sched.tick(t5);
    REQUIRE(calls == 5);
    CHECK(last_had_blob); // forced FULL resend
}

TEST_CASE("SyncScheduler: RPC failure does not advance state (retries)", "[sync][scheduler]") {
    std::map<std::string, std::string> kv;
    auto kv_get = [&](const std::string& k) {
        auto it = kv.find(k);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto kv_set = [&](const std::string& k, const std::string& v) { kv[k] = v; };

    int calls = 0;
    bool fail = true;
    auto sender = [&](const std::vector<std::pair<std::string, std::string>>&,
                      const std::vector<std::pair<std::string, std::string>>&)
        -> std::optional<std::vector<std::string>> {
        ++calls;
        if (fail)
            return std::nullopt; // RPC failure
        return std::vector<std::string>{};
    };

    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::seconds{86400};
    src.collect = [&]() -> std::optional<std::pair<std::string, std::string>> {
        return std::make_pair(std::string{"b"}, std::string{"h"});
    };
    SyncScheduler sched("agent-2", kv_get, kv_set, sender);
    sched.add_source(src);

    sched.tick(1000);          // schedule
    sched.tick(1000 + 700);    // due → send, but RPC fails
    REQUIRE(calls == 1);
    // State not advanced: a soon retry (within the clamped tick window) sends again.
    fail = false;
    sched.tick(1000 + 700 + SyncScheduler::kMinTickSeconds.count());
    CHECK(calls == 2);
}

// --- Parsing edge cases (clamp / separators / empty-name / empty inventory) ---

TEST_CASE("clamp_field strips framing separators and truncates over-long fields",
          "[sync][parse]") {
    // 0x1F (field sep) and 0x1E (record sep) embedded in a field must be stripped
    // so a value can never corrupt the canonical wire structure the server splits
    // on. (octal \037 == 0x1F, \036 == 0x1E. Literals are split after an escape
    // where a digit follows: MSVC C4125, #5334.)
    auto e = parse_installed_apps_output(std::string("inv|na\037me|1\036" "2|pub|d\n"));
    REQUIRE(e.size() == 1);
    CHECK(e[0].name == "name");    // 0x1F stripped
    CHECK(e[0].version == "12");   // 0x1E stripped

    std::string longname(2000, 'x');
    auto e2 = parse_installed_apps_output("inv|" + longname + "|1|p|d\n");
    REQUIRE(e2.size() == 1);
    CHECK(e2[0].name.size() == 1024); // truncated to kMaxFieldLen
}

TEST_CASE("clamp_field truncates on a UTF-8 codepoint boundary, not mid-sequence (UP-10)",
          "[sync][parse]") {
    // A 2-byte 'é' (0xC3 0xA9) straddling the 1024-byte cut must be dropped WHOLE,
    // not split into a lone lead byte 0xC3 — invalid UTF-8 would make PostgreSQL's
    // TEXT column reject the row → permanent need_full loop (governance UP-10).
    std::string name = std::string(1023, 'a') + "\xc3\xa9"; // 1025 bytes; é at [1023,1024]
    auto e = parse_installed_apps_output("inv|" + name + "|1|p|d\n");
    REQUIRE(e.size() == 1);
    CHECK(e[0].name == std::string(1023, 'a')); // é dropped whole; no trailing 0xC3
    CHECK(e[0].name.size() == 1023);
}

TEST_CASE("clamp_field scrubs invalid UTF-8 to U+FFFD before hashing (UP-IN1)",
          "[sync][parse]") {
    // cp1252 "Café" = 43 61 66 E9; the lone 0xE9 is invalid UTF-8 and PostgreSQL's
    // TEXT column rejects it (22021) → the whole full-replace rolls back → kError →
    // the agent resends the identical poison forever. clamp_field must replace any
    // invalid byte with U+FFFD (EF BF BD) so the canonical blob the agent hashes is
    // valid UTF-8 and the server stores it. This scrub MUST run before truncation
    // and match the server's parse_software_blob byte-for-byte.
    auto e = parse_installed_apps_output(std::string("inv|Caf\xe9|1|Acme|2020\n"));
    REQUIRE(e.size() == 1);
    CHECK(e[0].name == std::string("Caf\xef\xbf\xbd")); // 0xE9 → U+FFFD
    CHECK(e[0].name.find('\xe9') == std::string::npos); // no raw byte survives
    // The whole canonical blob is valid UTF-8 (no stray invalid byte).
    CHECK(installed_software_canonical_blob(e).find('\xe9') == std::string::npos);
}

// Raw bytes exercising EVERY PG-strict rejection branch (overlong, surrogate,
// > U+10FFFF, stray lead) plus valid 2- and 4-byte passthrough, and the EXACT
// expected scrub output. These two literals are duplicated verbatim in the server
// suite (test_software_inventory_store.cpp) — the whole anti-loop contract rests on
// the agent's clamp_field and the server's parse_software_blob scrubbing IDENTICALLY,
// and this pins both copies to the same spec so editing one without the other fails
// a test (gov Gate-8 cpp-safety/unhappy-path drift guard).
namespace {
const std::string kScrubVectorRaw = std::string("X") + "\xc0\x80" + // overlong NUL → 2× U+FFFD
                                    "\xed\xa0\x80" +                 // lone surrogate U+D800 → 3×
                                    "\xf4\x90\x80\x80" +             // > U+10FFFF → 4×
                                    "\xc3\xa9" +                     // é valid 2-byte (passthrough)
                                    "\xf0\x9f\x98\x80" +             // 😀 valid 4-byte (passthrough)
                                    "\xf5";                          // invalid lead → 1×
const std::string kScrubVectorExpected =
    std::string("X") + "\xef\xbf\xbd\xef\xbf\xbd" +                       // C0 80
    "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" +                              // ED A0 80
    "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" +                  // F4 90 80 80
    "\xc3\xa9" + "\xf0\x9f\x98\x80" + "\xef\xbf\xbd";                     // é 😀 F5
} // namespace

TEST_CASE("clamp_field scrub: PG-strict edge-branch parity vector (UP-IN1 drift guard)",
          "[sync][parse]") {
    auto e = parse_installed_apps_output("inv|" + kScrubVectorRaw + "|1|p|d\n");
    REQUIRE(e.size() == 1);
    CHECK(e[0].name == kScrubVectorExpected);
}

TEST_CASE("collect skips an empty inventory rather than wiping stored rows (UP-IN6)",
          "[sync][parse]") {
    // A transient empty parse (plugin hiccup / "No applications found" sentinel) must
    // NOT be turned into an empty full payload — that would DELETE the agent's stored
    // inventory and the server would record the wipe as a successful store. The
    // collector returns nullopt on an empty parse; here we assert the parse itself is
    // empty for the sentinel so the guard upstream fires.
    auto e = parse_installed_apps_output("app|No applications found|-|-|-|-|-\n");
    CHECK(e.empty());
}

TEST_CASE("a name that becomes empty after clamping is dropped (UP-1 hash parity)",
          "[sync][parse]") {
    // A separator-only name clamps to "" — the server's parse_software_blob drops
    // empty-name rows, so the agent must too, or the two canonical hashes diverge
    // and the source is stuck always-full.
    auto e = parse_installed_apps_output(std::string("inv|\037|1|p|d\ninv|Real|2|q|e\n"));
    REQUIRE(e.size() == 1);
    CHECK(e[0].name == "Real");
}

TEST_CASE("canonical blob is the exact wire format the server parses", "[sync][hash]") {
    // Pins the byte layout (not just the hash): sorted, 0x1F between the 12 v2
    // fields, 0x1E terminating each entry. The server's parse_software_blob
    // reads this same form (tests/unit/server/test_software_inventory_store.cpp).
    std::vector<SwEntry> e = {{"B", "2", "", ""}, {"A", "1", "P", "D"}}; // unsorted
    // A|1|P|D|×8-empty<rec>  B|2|×10-empty<rec>  (| == 0x1F, <rec> == 0x1E);
    // 11 separators per record regardless of how many trailing fields are empty.
    CHECK(installed_software_canonical_blob(e) ==
          std::string("A\037" "1\037P\037D\037\037\037\037\037\037\037\037\036"
                      "B\037" "2\037\037\037\037\037\037\037\037\037\037\036"));
}

TEST_CASE("empty inventory parses to no entries and a stable empty hash",
          "[sync][parse]") {
    // A host with zero machine-scope apps must still hash-skip cleanly, not look
    // broken: empty list → empty canonical blob → the well-known SHA-256 of "".
    auto e = parse_installed_apps_output(
        "user_app|x|y|1|p|d\napp|No applications found|-|-|-|-|-\n");
    CHECK(e.empty());
    CHECK(installed_software_canonical_blob({}) == "");
    CHECK(sha256_hex("") ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

// --- LocalDispatcher capture_cap plumbing (regression: the parameter must
//     actually reach CommandContextImpl's enforcement point, not just widen
//     the call signature) ---

namespace {
// A minimal, statically-allocated plugin descriptor whose "bulk" action
// writes ~3 MiB of output via the real yuzu_ctx_write_output C ABI path —
// enough to exceed LocalDispatcher::kCaptureMaxBytes (2 MiB) but stay under
// the 3.5 MiB cap the installed_software sync source passes for its own
// dispatch (sync_source_installed_software.cpp).
int bulk_execute(YuzuCommandContext* ctx, const char* /*action*/, const YuzuParam* /*params*/,
                 std::size_t /*param_count*/) {
    const std::string chunk(65536, 'x'); // 64 KiB
    for (int i = 0; i < 48; ++i)         // 48 * 64 KiB = 3 MiB
        yuzu_ctx_write_output(ctx, chunk.c_str());
    return 0;
}

const char* const kBulkActions[] = {"bulk", nullptr};

const YuzuPluginDescriptor kBulkDescriptor = {
    /*abi_version=*/YUZU_PLUGIN_ABI_VERSION,
    /*name=*/"bulk_test_fixture",
    /*version=*/"1.0.0",
    /*description=*/"test-only bulk-output fixture",
    /*actions=*/kBulkActions,
    /*init=*/nullptr,
    /*shutdown=*/nullptr,
    /*execute=*/bulk_execute,
    /*sdk_version=*/nullptr,
};
} // namespace

TEST_CASE("LocalDispatcher::run's capture_cap parameter actually bounds capture "
          "(regression: dispatch_with_capture must not discard it)",
          "[sync][local_dispatcher]") {
    using yuzu::agent::LocalDispatcher;

    SECTION("default cap (2 MiB) truncates a ~3 MiB payload") {
        LocalDispatcher dispatcher;
        LocalDispatcher::Result r = dispatcher.run(&kBulkDescriptor, "bulk");
        CHECK(r.rc == 0);
        CHECK(r.truncated);
    }

    SECTION("an explicit larger cap (3.5 MiB) accepts the same ~3 MiB payload untruncated") {
        LocalDispatcher dispatcher;
        constexpr std::size_t kInventoryCaptureCap = 3'670'016; // matches the sync source's cap
        LocalDispatcher::Result r = dispatcher.run(&kBulkDescriptor, "bulk", {}, kInventoryCaptureCap);
        CHECK(r.rc == 0);
        CHECK_FALSE(r.truncated);
        CHECK(r.captured.size() > 2u * 1024 * 1024); // genuinely exceeds the default cap
    }
}

// --- Scheduler edge cases (phase spread, full-floor, collect-nothing) ---

namespace {
// First scheduled fire (epoch s) for a fresh agent at now=1000, read straight
// from the injected KV — exercises the startup-jitter offset path.
std::int64_t first_fire_for(const std::string& agent) {
    std::map<std::string, std::string> kv;
    auto g = [&](const std::string& k) {
        auto it = kv.find(k);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto s = [&](const std::string& k, const std::string& v) { kv[k] = v; };
    SyncScheduler sched(agent, g, s,
                        [](const std::vector<std::pair<std::string, std::string>>&,
                           const std::vector<std::pair<std::string, std::string>>&)
                            -> std::optional<std::vector<std::string>> {
                            return std::vector<std::string>{};
                        });
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::seconds{86400};
    src.collect = []() -> std::optional<std::pair<std::string, std::string>> {
        return std::make_pair(std::string{"b"}, std::string{"h"});
    };
    sched.add_source(src);
    sched.tick(1000); // schedules the startup-jittered first fire (does not send)
    return std::strtoll(kv["sync.installed_software.next_fire"].c_str(), nullptr, 10);
}
} // namespace

TEST_CASE("SyncScheduler: per-agent phase offset spreads the fleet, stable per agent",
          "[sync][scheduler]") {
    // Reboot stability: the same agent_id always lands on the same offset (a
    // restart must not re-cluster the fleet — ADR-0016 §3).
    CHECK(first_fire_for("agent-stable") == first_fire_for("agent-stable"));

    // Spread: many agents land on many distinct first-fire times, all within the
    // startup-jitter window.
    std::set<std::int64_t> fires;
    for (int i = 0; i < 50; ++i)
        fires.insert(first_fire_for("agent-" + std::to_string(i)));
    // FNV-1a over the fixed ids "agent-0".."agent-49" is deterministic — this is
    // not a probabilistic check; it yields the same distinct count every run.
    CHECK(fires.size() > 20);
    for (auto f : fires) {
        CHECK(f >= 1000);
        CHECK(f < 1000 + SyncScheduler::kStartupJitterWindow.count());
    }
}

TEST_CASE("SyncScheduler: weekly full-floor resends a full payload even when unchanged",
          "[sync][scheduler]") {
    std::map<std::string, std::string> kv;
    auto g = [&](const std::string& k) {
        auto it = kv.find(k);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto s = [&](const std::string& k, const std::string& v) { kv[k] = v; };
    int calls = 0;
    bool last_had_blob = false;
    auto sender = [&](const std::vector<std::pair<std::string, std::string>>&,
                      const std::vector<std::pair<std::string, std::string>>& blobs)
        -> std::optional<std::vector<std::string>> {
        ++calls;
        last_had_blob = !blobs.empty();
        return std::vector<std::string>{};
    };
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::seconds{86400};
    src.collect = []() -> std::optional<std::pair<std::string, std::string>> {
        return std::make_pair(std::string{"b"}, std::string{"h"}); // never changes
    };
    SyncScheduler sched("agent-floor", g, s, sender);
    sched.add_source(src);

    sched.tick(1000);
    sched.tick(1000 + 700); // first send → FULL (last_full = 1700)
    REQUIRE(calls == 1);
    REQUIRE(last_had_blob);

    live_advance(sched, 1700, 1700 + 86400 + 1); // unchanged, within the floor → hash-only
    REQUIRE(calls == 2);
    REQUIRE_FALSE(last_had_blob);

    // Daily hash-only syncs through the week, never a blob while inside the floor.
    bool any_blob = false;
    std::int64_t t = 1700 + 86400 + 1;
    const std::int64_t floor_at = 1700 + SyncScheduler::kFullFloor.count();
    while (t < floor_at) {
        const int before = calls;
        t = std::min(t + SyncScheduler::kMaxTickSeconds.count(), floor_at);
        sched.tick(t);
        any_blob = any_blob || (calls != before && last_had_blob);
    }
    CHECK_FALSE(any_blob);

    // Past last_full + kFullFloor, still unchanged → the next sync is a forced FULL.
    live_advance(sched, floor_at, floor_at + 86400 + 1, [&] { return last_had_blob; });
    CHECK(last_had_blob);
}

TEST_CASE("SyncScheduler: collect returning nothing sends no RPC and retries next interval",
          "[sync][scheduler]") {
    std::map<std::string, std::string> kv;
    auto g = [&](const std::string& k) {
        auto it = kv.find(k);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto s = [&](const std::string& k, const std::string& v) { kv[k] = v; };
    int calls = 0;
    auto sender = [&](const std::vector<std::pair<std::string, std::string>>&,
                      const std::vector<std::pair<std::string, std::string>>&)
        -> std::optional<std::vector<std::string>> {
        ++calls;
        return std::vector<std::string>{};
    };
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::seconds{86400};
    src.collect = []() -> std::optional<std::pair<std::string, std::string>> {
        return std::nullopt; // source unavailable (e.g. plugin not loaded)
    };
    SyncScheduler sched("agent-nocollect", g, s, sender);
    sched.add_source(src);

    sched.tick(1000);       // schedule
    sched.tick(1000 + 700); // due, but collect yields nothing → no send
    CHECK(calls == 0);
    // Retry is rescheduled one interval out (now + interval), not hammered.
    CHECK(std::strtoll(kv["sync.installed_software.next_fire"].c_str(), nullptr, 10) ==
          1700 + 86400);
    // The skip is visible: counted, with no reason (this source cannot classify).
    CHECK(kv["sync.installed_software.skip_streak"] == "1");
    CHECK(kv["sync.installed_software.last_skip"] == "");
}

namespace {
// Fake KV + sender + a source whose collect skips or succeeds on demand.
struct SkipRig {
    std::map<std::string, std::string> kv;
    std::vector<std::pair<std::string, std::string>> writes;
    int sends{0};
    int collects{0};
    bool skip{true};
    std::string reason;
    std::function<void()> on_send;

    SyncScheduler::KvGetFn getter() {
        return [this](const std::string& k) {
            auto it = kv.find(k);
            return it == kv.end() ? std::string{} : it->second;
        };
    }
    SyncScheduler::KvSetFn setter() {
        return [this](const std::string& k, const std::string& v) {
            kv[k] = v;
            writes.emplace_back(k, v);
        };
    }
    SyncScheduler::SenderFn sender() {
        return [this](const std::vector<std::pair<std::string, std::string>>&,
                      const std::vector<std::pair<std::string, std::string>>&)
                   -> std::optional<std::vector<std::string>> {
            ++sends;
            if (on_send)
                on_send();
            return std::vector<std::string>{};
        };
    }
    SyncSource source(bool backoff, std::int64_t interval_s) {
        SyncSource src;
        src.name = "installed_software";
        src.interval = std::chrono::seconds{interval_s};
        src.skip_backoff = backoff;
        src.collect = [this]() -> std::optional<std::pair<std::string, std::string>> {
            ++collects;
            if (skip)
                return std::nullopt;
            return std::make_pair(std::string{"b"}, std::string{"h"});
        };
        src.skip_reason = [this] { return reason; };
        return src;
    }
    std::int64_t next_fire() {
        return std::strtoll(kv["sync.installed_software.next_fire"].c_str(), nullptr, 10);
    }
    std::optional<std::string> get_opt(const std::string& k) {
        auto it = kv.find(k);
        if (it == kv.end())
            return std::nullopt;
        return it->second;
    }
};

std::map<std::string, std::string> skip_tags(SkipRig& rig) {
    std::map<std::string, std::string> tags;
    yuzu::agent::emit_sync_skip_tags(
        tags, std::vector<std::string>{"installed_software", "other"},
        [&rig](const std::string& k) { return rig.get_opt(k); });
    return tags;
}
} // namespace

TEST_CASE("sanitize_skip_reason keeps the token alphabet and bounds the length",
          "[sync][scheduler][skip]") {
    using yuzu::agent::sanitize_skip_reason;
    CHECK(sanitize_skip_reason("bad status") == "bad_status");
    CHECK(sanitize_skip_reason("pkg_inventory.packages:rc=1") == "pkg_inventory.packages:rc=1");
    CHECK(sanitize_skip_reason("a,b-c.D:9=_") == "a,b-c.D:9=_");
    CHECK(sanitize_skip_reason("x/y z\n\t") == "x_y_z__");
    CHECK(sanitize_skip_reason(std::string(70, 'a')) == std::string(64, 'a'));
    CHECK(sanitize_skip_reason("") == "");
}

TEST_CASE("SyncScheduler: a skip persists the sanitised reason and bumps the streak",
          "[sync][scheduler][skip]") {
    SkipRig rig;
    rig.reason = "pkg_inventory.packages: bad status";
    SyncScheduler sched("agent-skip", rig.getter(), rig.setter(), rig.sender());
    sched.add_source(rig.source(false, 86400));
    sched.tick(1000);
    sched.tick(1700);
    CHECK(rig.kv["sync.installed_software.skip_streak"] == "1");
    CHECK(rig.kv["sync.installed_software.last_skip"] == "pkg_inventory.packages:_bad_status");
}

TEST_CASE("SyncScheduler: a successful collect clears the skip before the send and restarts "
          "the budget",
          "[sync][scheduler][skip]") {
    const std::string agent = "agent-recover";
    SkipRig rig;
    rig.reason = "r:1";
    SyncScheduler sched(agent, rig.getter(), rig.setter(), rig.sender());
    sched.add_source(rig.source(true, 86400));
    sched.tick(1000);
    std::int64_t now = 1700;
    for (int i = 0; i < 3; ++i) {
        sched.tick(now);
        now = rig.next_fire();
    }
    REQUIRE(rig.kv["sync.installed_software.skip_streak"] == "3");

    rig.skip = false;
    bool cleared_before_send = false;
    rig.on_send = [&] {
        cleared_before_send = rig.kv["sync.installed_software.skip_streak"] == "0" &&
                              rig.kv["sync.installed_software.last_skip"].empty();
    };
    sched.tick(now);
    REQUIRE(rig.sends == 1);
    CHECK(cleared_before_send);
    CHECK(rig.kv["sync.installed_software.skip_streak"] == "0");
    CHECK(rig.kv["sync.installed_software.last_skip"] == "");

    rig.skip = true;
    now = rig.next_fire();
    sched.tick(now);
    CHECK(rig.kv["sync.installed_software.skip_streak"] == "1");
    // Fresh budget: 1 h again (the success put next_fire on a phase slot, a full day ahead).
    CHECK(rig.next_fire() == now + 3600);
}

TEST_CASE("SyncScheduler: a forced skip records nothing itself; the next batch pass records it "
          "once",
          "[sync][scheduler][skip]") {
    SkipRig rig;
    rig.reason = "r:forced";
    SyncScheduler sched("agent-forced", rig.getter(), rig.setter(), rig.sender());
    sched.add_source(rig.source(true, 86400));
    sched.tick(1000);
    REQUIRE_FALSE(sched.request_now("installed_software").empty());
    sched.tick(1700);
    CHECK(rig.collects == 1);
    CHECK(rig.kv["sync.installed_software.skip_streak"] == "0"); // the forced path records no skip
    CHECK(rig.next_fire() == 1700);                              // still due: retries next tick
    // The batch pass re-collects and records the skip exactly once, so one click costs one
    // backoff rung and one extra collection.
    sched.tick(1701);
    CHECK(rig.collects == 2);
    CHECK(rig.kv["sync.installed_software.skip_streak"] == "1");
    CHECK(rig.kv["sync.installed_software.last_skip"] == "r:forced");
}

TEST_CASE("SyncScheduler: skip_backoff from a phase slot retries at literal 1h 2h 4h 8h "
          "then the next slot",
          "[sync][scheduler][skip]") {
    const std::string agent = "agent-literal";
    const std::int64_t interval = 86400;
    SkipRig rig;
    rig.reason = "r:1";
    SyncScheduler sched(agent, rig.getter(), rig.setter(), rig.sender());
    sched.add_source(rig.source(true, interval));
    sched.tick(1000);

    // Start exactly on a daily phase slot so the next slot is a full day away: a
    // successful collect leaves next_fire on one (apply_ack), taken from production.
    rig.skip = false;
    sched.tick(rig.next_fire());
    REQUIRE(rig.sends == 1);
    rig.skip = true;
    const std::int64_t start = rig.next_fire(); // apply_ack put next_fire on a phase slot
    sched.tick(start);
    CHECK(rig.next_fire() == start + 3600);
    sched.tick(start + 3600);
    CHECK(rig.next_fire() == start + 3600 + 7200);
    sched.tick(start + 3 * 3600);
    CHECK(rig.next_fire() == start + 3 * 3600 + 14400);
    sched.tick(start + 7 * 3600);
    CHECK(rig.next_fire() == start + 7 * 3600 + 28800);
    sched.tick(start + 15 * 3600);
    CHECK(rig.next_fire() == start + interval); // 16h would overshoot: the slot wins
    sched.tick(start + interval);
    CHECK(rig.next_fire() == start + 2 * interval); // budget spent: one attempt per day
    CHECK(rig.kv["sync.installed_software.skip_streak"] == "6");
    for (int day = 2; day <= 5; ++day) { // streak uncapped, still exactly one attempt per slot
        sched.tick(start + day * interval);
        INFO("day " << day);
        CHECK(rig.next_fire() == start + (day + 1) * interval);
        CHECK(rig.kv["sync.installed_software.skip_streak"] == std::to_string(5 + day));
    }
}

TEST_CASE("SyncScheduler: an off-slot first skip is capped at the slot and then the doubling "
          "continues",
          "[sync][scheduler][skip]") {
    const std::string agent = "agent-offslot";
    const std::int64_t interval = 86400;
    const std::int64_t h = 3600;

    // A probe scheduler learns this agent's daily phase slot from production: a
    // successful collect leaves next_fire on one (apply_ack).
    SkipRig probe;
    probe.skip = false;
    SyncScheduler s0(agent, probe.getter(), probe.setter(), probe.sender());
    s0.add_source(probe.source(true, interval));
    s0.tick(10 * interval);
    s0.tick(probe.next_fire());
    REQUIRE(probe.sends == 1);
    const std::int64_t slot = probe.next_fire();
    const std::int64_t start = slot - 10 * h; // the first skip lands 10 h before that slot

    // A second scheduler (same agent id, so the same phase) over a KV pre-seeded to be due at
    // `start`. Expected next_fire = min(next slot, now + (1 h << (streak - 1))):
    //   streak 1: min(slot, start + 1 h)           = start + 1 h
    //   streak 2: min(slot, start + 1 h + 2 h)     = start + 3 h
    //   streak 3: min(slot, start + 3 h + 4 h)     = start + 7 h
    //   streak 4: min(slot, start + 7 h + 8 h)     = slot (start + 10 h < start + 15 h)
    //   streak 5: at the slot, min(slot + 24 h, slot + 16 h) = slot + 16 h (not capped)
    //   streak 6: budget spent -> the next slot after slot + 16 h = slot + 24 h
    SkipRig rig;
    rig.reason = "r:1";
    rig.kv["sync.installed_software.next_fire"] = std::to_string(start);
    SyncScheduler sched(agent, rig.getter(), rig.setter(), rig.sender());
    sched.add_source(rig.source(true, interval));
    sched.tick(start);
    CHECK(rig.next_fire() == start + 1 * h);
    sched.tick(start + 1 * h);
    CHECK(rig.next_fire() == start + 3 * h);
    sched.tick(start + 3 * h);
    CHECK(rig.next_fire() == start + 7 * h);
    sched.tick(start + 7 * h);
    CHECK(rig.next_fire() == slot); // 8 h would overshoot: the slot wins
    sched.tick(slot);
    CHECK(rig.next_fire() == slot + 16 * h); // the fifth wait is NOT capped from an off-slot start
    sched.tick(slot + 16 * h);
    CHECK(rig.next_fire() == slot + interval); // budget spent: the next slot
    CHECK(rig.kv["sync.installed_software.skip_streak"] == "6");
}

TEST_CASE("SyncScheduler: forced recovery clears skip state before a failed RPC",
          "[sync][scheduler][skip]") {
    SkipRig rig;
    rig.reason = "r:1";
    bool saw_send = false;
    SyncScheduler sched(
        "agent-forced-recovery", rig.getter(), rig.setter(),
        [&](const std::vector<std::pair<std::string, std::string>>&,
            const std::vector<std::pair<std::string, std::string>>&)
            -> std::optional<std::vector<std::string>> {
            saw_send = true;
            CHECK(rig.kv["sync.installed_software.skip_streak"] == "0");
            CHECK(rig.kv["sync.installed_software.last_skip"].empty());
            return std::nullopt; // RPC failure
        });
    sched.add_source(rig.source(true, 86400));
    sched.tick(1000);
    sched.tick(1700);
    REQUIRE(rig.kv["sync.installed_software.skip_streak"] == "1");
    REQUIRE_FALSE(skip_tags(rig).empty());

    rig.skip = false;
    REQUIRE_FALSE(sched.request_now("installed_software").empty());
    sched.tick(1701);
    REQUIRE(saw_send);
    CHECK(rig.kv["sync.installed_software.skip_streak"] == "0");
    CHECK(rig.kv["sync.installed_software.last_skip"].empty());
    CHECK(skip_tags(rig).empty());
}

TEST_CASE("SyncScheduler: skip state is written skip_streak then last_skip then next_fire and "
          "survives an interrupted write",
          "[sync][scheduler][skip]") {
    SkipRig rig;
    rig.reason = "r:1";
    SyncScheduler sched("agent-order", rig.getter(), rig.setter(), rig.sender());
    sched.add_source(rig.source(false, 86400));
    sched.tick(1000);
    const auto pre_kv = rig.kv; // pre-skip state, next_fire still in the past at 1700
    const std::size_t before = rig.writes.size();
    sched.tick(1700);
    REQUIRE(rig.writes.size() >= before + 3);
    CHECK(rig.writes[before].first == "sync.installed_software.skip_streak");
    CHECK(rig.writes[before + 1].first == "sync.installed_software.last_skip");
    CHECK(rig.writes[before + 2].first == "sync.installed_software.next_fire");

    // Kill after the first two writes: next_fire never advanced.
    SkipRig rig2;
    rig2.kv = pre_kv;
    rig2.kv[rig.writes[before].first] = rig.writes[before].second;
    rig2.kv[rig.writes[before + 1].first] = rig.writes[before + 1].second;
    rig2.reason = "r:1";
    const auto tags = skip_tags(rig2);
    CHECK(tags.at("yuzu.sync.installed_software.skip_streak") == "1");
    CHECK(tags.at("yuzu.sync.installed_software.last_skip") == "r:1");
    SyncScheduler sched2("agent-order", rig2.getter(), rig2.setter(), rig2.sender());
    sched2.add_source(rig2.source(false, 86400));
    sched2.tick(1701);
    CHECK(rig2.collects == 1); // fires again: the stale next_fire was still due
}

TEST_CASE("SyncScheduler: the persisted skip streak and reason survive a restart",
          "[sync][scheduler][skip]") {
    const std::string agent = "agent-restart";
    const std::string streak = "sync.installed_software.skip_streak";
    const std::string last = "sync.installed_software.last_skip";
    SkipRig rig;
    rig.reason = "r:1";
    SyncScheduler first(agent, rig.getter(), rig.setter(), rig.sender());
    first.add_source(rig.source(true, 86400));
    first.tick(1000);
    rig.skip = false;
    first.tick(rig.next_fire()); // a success leaves next_fire on a phase slot, a day ahead
    REQUIRE(rig.sends == 1);
    rig.skip = true;
    const std::int64_t start = rig.next_fire();
    first.tick(start);
    REQUIRE(rig.kv[streak] == "1");
    REQUIRE(rig.next_fire() == start + 3600);

    // A new scheduler over the same KV (an agent restart) continues the ladder: the loaded
    // streak is 1, so this skip is the second, waits 2 h, and replaces the reason.
    rig.reason = "r:2";
    SyncScheduler second(agent, rig.getter(), rig.setter(), rig.sender());
    second.add_source(rig.source(true, 86400));
    second.tick(start + 3600);
    CHECK(rig.kv[streak] == "2");
    CHECK(rig.kv[last] == "r:2");
    CHECK(rig.next_fire() == start + 3600 + 7200);

    // A third life recovers: a success after a restart leaves no skip state behind.
    rig.skip = false;
    SyncScheduler third(agent, rig.getter(), rig.setter(), rig.sender());
    third.add_source(rig.source(true, 86400));
    third.tick(rig.next_fire());
    REQUIRE(rig.sends == 2);
    CHECK(rig.kv[streak] == "0");
    CHECK(rig.kv[last].empty());
    CHECK(skip_tags(rig).empty());
}

TEST_CASE("SyncScheduler: a success clears a reason left behind a zero streak by an interrupted "
          "clear",
          "[sync][scheduler][skip]") {
    SkipRig rig;
    rig.kv["sync.installed_software.next_fire"] = "1000"; // due now
    rig.kv["sync.installed_software.skip_streak"] = "0";  // the streak write landed...
    rig.kv["sync.installed_software.last_skip"] = "r:old"; // ...the last_skip write did not
    rig.skip = false;
    SyncScheduler sched("agent-interrupted-clear", rig.getter(), rig.setter(), rig.sender());
    sched.add_source(rig.source(true, 86400));
    sched.tick(1000);
    REQUIRE(rig.sends == 1);
    CHECK(rig.kv["sync.installed_software.skip_streak"] == "0");
    CHECK(rig.kv["sync.installed_software.last_skip"].empty());
}

TEST_CASE("SyncScheduler: a corrupt negative skip streak is clamped on load",
          "[sync][scheduler][skip]") {
    const std::string agent = "agent-clamp";
    SkipRig rig;
    rig.reason = "r:1";
    SyncScheduler first(agent, rig.getter(), rig.setter(), rig.sender());
    first.add_source(rig.source(true, 86400));
    first.tick(1000);
    rig.skip = false;
    first.tick(rig.next_fire());
    REQUIRE(rig.sends == 1);
    rig.skip = true;
    const std::int64_t start = rig.next_fire();

    rig.kv["sync.installed_software.skip_streak"] = "-5"; // never reaches the backoff shift
    SyncScheduler second(agent, rig.getter(), rig.setter(), rig.sender());
    second.add_source(rig.source(true, 86400));
    second.tick(start);
    CHECK(rig.kv["sync.installed_software.skip_streak"] == "1"); // clamped to 0, then this skip
    CHECK(rig.next_fire() == start + 3600);
}

TEST_CASE("emit_sync_skip_tags publishes only a positive streak with a bounded reason",
          "[sync][scheduler][skip]") {
    SkipRig rig;
    const std::string sk = "sync.installed_software.skip_streak";
    const std::string lr = "sync.installed_software.last_skip";
    CHECK(skip_tags(rig).empty()); // nothing recorded

    rig.kv[sk] = "3";
    rig.kv[lr] = "pkg_inventory.packages:rc=1";
    auto tags = skip_tags(rig);
    CHECK(tags.size() == 2);
    CHECK(tags["yuzu.sync.installed_software.skip_streak"] == "3");
    CHECK(tags["yuzu.sync.installed_software.last_skip"] == "pkg_inventory.packages:rc=1");

    for (const char* bad : {"0", "abc", "-1", "1234567", ""}) {
        rig.kv[sk] = bad;
        INFO("streak " << bad);
        CHECK(skip_tags(rig).empty());
    }
    rig.kv[sk] = "7";
    rig.kv[lr] = "";
    CHECK(skip_tags(rig).empty());
    rig.kv.erase(lr);
    CHECK(skip_tags(rig).empty());
    rig.kv[lr] = std::string(65, 'x');
    CHECK(skip_tags(rig).empty());
    for (const char* bad : {"bad reason", "r:\xff", "r:\n"}) { // outside the write-time alphabet
        rig.kv[lr] = bad;
        INFO("reason " << bad);
        CHECK(skip_tags(rig).empty());
    }
    // The boundaries the sanitiser and the emitter agree on are published: a 64 B reason, a
    // 6-digit streak.
    rig.kv[sk] = "999999";
    rig.kv[lr] = std::string(64, 'x');
    tags = skip_tags(rig);
    CHECK(tags.size() == 2);
    CHECK(tags["yuzu.sync.installed_software.skip_streak"] == "999999");
    CHECK(tags["yuzu.sync.installed_software.last_skip"] == std::string(64, 'x'));
}

TEST_CASE("SyncScheduler: consecutive need_full nacks back off, reset on clean sync",
          "[sync][scheduler]") {
    // UP-5: a sustained server cold-cache / store outage must NOT resend full at a
    // flat 30s cadence forever. Each consecutive need_full doubles the delay; a
    // clean sync resets it. The per-(agent,source) jitter is constant across ticks
    // (same FNV input), so the delay GROWS monotonically across nacks.
    std::map<std::string, std::string> kv;
    auto g = [&](const std::string& k) {
        auto it = kv.find(k);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto s = [&](const std::string& k, const std::string& v) { kv[k] = v; };
    bool nack = true;
    auto sender = [&](const std::vector<std::pair<std::string, std::string>>&,
                      const std::vector<std::pair<std::string, std::string>>&)
        -> std::optional<std::vector<std::string>> {
        return nack ? std::vector<std::string>{"installed_software"} : std::vector<std::string>{};
    };
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::seconds{86400};
    src.collect = []() -> std::optional<std::pair<std::string, std::string>> {
        return std::make_pair(std::string{"b"}, std::string{"h"});
    };
    SyncScheduler sched("agent-backoff", g, s, sender);
    sched.add_source(src);

    auto next_fire = [&]() {
        return std::strtoll(kv["sync.installed_software.next_fire"].c_str(), nullptr, 10);
    };

    sched.tick(1000); // schedule first-run fire

    // Drive consecutive nacks, each tick exactly at the scheduled fire, recording
    // the rescheduled delay (next_fire - now).
    std::vector<std::int64_t> delays;
    std::int64_t t = next_fire();
    for (int i = 0; i < 4; ++i) {
        sched.tick(t);
        std::int64_t nf = next_fire();
        delays.push_back(nf - t);
        t = nf;
    }
    // Strictly increasing: 30+J, 60+J, 120+J, 240+J (jitter J constant).
    REQUIRE(delays.size() == 4);
    CHECK(delays[0] < delays[1]);
    CHECK(delays[1] < delays[2]);
    CHECK(delays[2] < delays[3]);
    // Bounded: never exceeds kMaxTickSeconds.
    for (auto d : delays)
        CHECK(d <= SyncScheduler::kMaxTickSeconds.count());

    // A clean sync resets the ladder back to zero.
    nack = false;
    sched.tick(t); // clean → streak reset, next_fire jumps ~a day out
    CHECK(std::strtoll(kv["sync.installed_software.nf_streak"].c_str(), nullptr, 10) == 0);
    // The next nack restarts the ladder at the floor (streak 1), not where it left off.
    nack = true;
    std::int64_t after_reset = next_fire();
    sched.tick(after_reset);
    CHECK(std::strtoll(kv["sync.installed_software.nf_streak"].c_str(), nullptr, 10) == 1);
    CHECK((next_fire() - after_reset) == delays[0]); // same delay as the very first nack
}

// Round-3 item 4 (sync-speed fix): a forced source (request_now) is sent in its
// OWN immediate RPC, decoupled from any other cadence-due source's collect() in
// the same tick — so an operator forcing the slow installed_software source no
// longer makes a fast, ALSO-forced-or-due source wait behind it, and vice versa.
namespace {
// A three-source fixture (fast_a, fast_b, slow) with a shared call log — each
// sender_ invocation records exactly which source names it carried, so a test
// can assert both the CALL COUNT (one per forced source, not one shared batch)
// and per-call CONTENTS (never more than one source unless it's the genuine
// cadence-due batch pass).
struct SchedulerFixture {
    std::map<std::string, std::string> kv;
    std::vector<std::vector<std::string>> calls; // one entry per sender_() invocation
    std::vector<int> collect_counts{0, 0, 0};    // fast_a, fast_b, slow
    bool fail_next = false;

    // Returns a heap-allocated scheduler — SyncScheduler holds a std::mutex
    // (pending_mu_) and is therefore neither copyable nor movable, so it can't
    // be returned by value from a factory function.
    std::unique_ptr<SyncScheduler> make() {
        auto kv_get = [this](const std::string& k) {
            auto it = kv.find(k);
            return it == kv.end() ? std::string{} : it->second;
        };
        auto kv_set = [this](const std::string& k, const std::string& v) { kv[k] = v; };
        auto sender = [this](const std::vector<std::pair<std::string, std::string>>& hashes,
                             const std::vector<std::pair<std::string, std::string>>&)
            -> std::optional<std::vector<std::string>> {
            std::vector<std::string> names;
            for (const auto& [n, h] : hashes)
                names.push_back(n);
            calls.push_back(names);
            if (fail_next) {
                fail_next = false;
                return std::nullopt;
            }
            return std::vector<std::string>{}; // no need_full
        };
        auto sched = std::make_unique<SyncScheduler>("agent-forced", kv_get, kv_set, sender);
        SyncSource fast_a;
        fast_a.name = "fast_a";
        fast_a.interval = std::chrono::seconds{86400};
        fast_a.collect = [this]() -> std::optional<std::pair<std::string, std::string>> {
            ++collect_counts[0];
            return std::make_pair(std::string{"ba"}, std::string{"ha"});
        };
        SyncSource fast_b;
        fast_b.name = "fast_b";
        fast_b.interval = std::chrono::seconds{86400};
        fast_b.collect = [this]() -> std::optional<std::pair<std::string, std::string>> {
            ++collect_counts[1];
            return std::make_pair(std::string{"bb"}, std::string{"hb"});
        };
        SyncSource slow;
        slow.name = "slow";
        slow.interval = std::chrono::seconds{86400};
        slow.collect = [this]() -> std::optional<std::pair<std::string, std::string>> {
            ++collect_counts[2];
            return std::make_pair(std::string{"bs"}, std::string{"hs"});
        };
        sched->add_source(fast_a);
        sched->add_source(fast_b);
        sched->add_source(slow);
        return sched;
    }
};
} // namespace

TEST_CASE("SyncScheduler: request_now(source) fires that source alone, "
          "not folded into a shared batch",
          "[sync][scheduler]") {
    SchedulerFixture fx;
    auto sched = fx.make();  // unique_ptr<SyncScheduler>
    sched->tick(1000); // schedule the startup-jittered first fire for all three — not due yet
    CHECK(fx.calls.empty());

    // Force only "slow" — nothing else is due yet at this timestamp.
    auto armed = sched->request_now("slow");
    REQUIRE(armed == std::vector<std::string>{"slow"});
    sched->tick(1000);

    REQUIRE(fx.calls.size() == 1);
    CHECK(fx.calls[0] == std::vector<std::string>{"slow"});
    // Only the forced source's collect() ran this tick — the other two are not
    // yet due and were never touched.
    CHECK(fx.collect_counts == std::vector<int>{0, 0, 1});
}

TEST_CASE("SyncScheduler: request_now(kAllSources) fires ONE RPC per source, "
          "fast sources before the slow one (registration order)",
          "[sync][scheduler]") {
    SchedulerFixture fx;
    auto sched = fx.make();  // unique_ptr<SyncScheduler>
    sched->tick(1000);
    CHECK(fx.calls.empty());

    auto armed = sched->request_now(SyncScheduler::kAllSources);
    REQUIRE(armed.size() == 3);
    sched->tick(1000);

    // THREE separate sender_ calls — never one shared batch of three — each
    // carrying exactly its own source, in REGISTRATION order (fast_a, fast_b,
    // slow) so a slow source registered last never blocks an earlier one's own
    // immediate RPC in the same tick.
    REQUIRE(fx.calls.size() == 3);
    CHECK(fx.calls[0] == std::vector<std::string>{"fast_a"});
    CHECK(fx.calls[1] == std::vector<std::string>{"fast_b"});
    CHECK(fx.calls[2] == std::vector<std::string>{"slow"});
    CHECK(fx.collect_counts == std::vector<int>{1, 1, 1}); // one collect() per source, no re-attempt
}

TEST_CASE("SyncScheduler: a forced source's own RPC failure retries next tick, "
          "without a second collect() attempt via the batch pass this tick",
          "[sync][scheduler]") {
    SchedulerFixture fx;
    auto sched = fx.make();  // unique_ptr<SyncScheduler>
    sched->tick(1000);
    (void)sched->request_now("slow");
    fx.fail_next = true; // the forced source's OWN RPC fails
    sched->tick(1000);

    REQUIRE(fx.calls.size() == 1);
    CHECK(fx.calls[0] == std::vector<std::string>{"slow"});
    // Exactly one collect() this tick — the failed forced send is NOT retried a
    // second time via the batch pass in the SAME tick.
    CHECK(fx.collect_counts == std::vector<int>{0, 0, 1});
    // force_full/next_fire were persisted by drain_pending BEFORE the send (so a
    // failed RPC still retries as forced on the next tick, matching the
    // pre-existing "persist before send" contract for the batch path).
    CHECK(fx.kv["sync.slow.force_full"] == "1");
    CHECK(std::strtoll(fx.kv["sync.slow.next_fire"].c_str(), nullptr, 10) == 1000);

    // Next tick at the same due time: the forced source is due again (next_fire
    // == now still) and is NOT re-armed via request_now — this exercises the
    // ordinary cadence-due batch path picking up a source whose next_fire is
    // already <= now, proving the earlier failure didn't wedge it.
    sched->tick(1000);
    REQUIRE(fx.calls.size() == 2);
    CHECK(fx.calls[1] == std::vector<std::string>{"slow"});
    CHECK(fx.collect_counts == std::vector<int>{0, 0, 2});
}

// ============================================================================
// Extended tail pins, action adapters and the multi-action collector
// ============================================================================

#ifndef YUZU_TEST_FIXTURE_DIR
#define YUZU_TEST_FIXTURE_DIR "tests/unit/fixtures"
#endif

namespace {
namespace fs = std::filesystem;
namespace pkg = yuzu::pkg_inventory;
namespace msi = yuzu::msi_packages::inventory;
using Status = AdaptedRows::Status;
// The ConstrainedPolicy each action's table row carries in the collector
// (sync_source_installed_software.cpp kInventoryActions): managers keeps a constrained answer's
// rows when a present row was seen, every other status-row action fails the cycle.
constexpr ConstrainedPolicy kKeepPolicy = ConstrainedPolicy::keep_rows_if_present_seen;
constexpr ConstrainedPolicy kFailPolicy = ConstrainedPolicy::fail;

// Server-side fixtures, copied verbatim from
// tests/unit/server/test_software_inventory_store.cpp: the agent builder and the
// server's canonical_hash must produce these exact digests (blob v2 + 4-slot tail).
constexpr const char* kCrossPinHashExtended =
    "371b647c95b0f48a039ff98790c6085947ef71fcfd40a399c3cd70d70321291d";
constexpr const char* kTailOrderPinHash =
    "ab2abf993a2b0868b9c69397497799920773fd44c29cde86380e8c4369ccbe8d";
constexpr const char* kMixedBlobHash =
    "7b37bca935f3ae92a042949ef4280d69b25edc8ee6e518f993ded0eeec7e76f3";

SwEntry full_extended_entry() {
    SwEntry e = full_v2_entry();
    e.package_id = "bash-5.2.21-3.fc40.x86_64";
    e.source = "installed_apps.list_inventory";
    return e;
}

// Lines strictly between `== action=<action>` and the next `== action=` /
// `[result_status]` line of a committed real capture. Never skips: a missing
// sample is a failure. The record counts pinned in the collector tests below are
// tied to the committed captures: re-measure them when a sample is refreshed.
std::string capture_section(const char* plugin, const char* sample, std::string_view action) {
    const fs::path p = fs::path(YUZU_PLUGIN_SRC_DIR) / plugin / "docs" / "samples" / sample;
    REQUIRE(fs::exists(p));
    std::ifstream in(p);
    std::string line;
    std::string out;
    bool on = false;
    const std::string want = "== action=" + std::string(action);
    while (std::getline(in, line)) {
        if (line.rfind("== action=", 0) == 0) {
            on = (line == want);
            continue;
        }
        if (line.rfind("[result_status]", 0) == 0) {
            on = false;
            continue;
        }
        if (on)
            out += line + '\n';
    }
    REQUIRE_FALSE(out.empty());
    return out;
}

std::string nl(std::initializer_list<std::string> lines) {
    std::string out;
    for (const auto& l : lines)
        out += l + '\n';
    return out;
}

std::vector<std::string> records_of(const std::string& blob) {
    std::vector<std::string> recs;
    std::size_t pos = 0;
    while (pos < blob.size()) {
        const std::size_t e = blob.find('\x1e', pos);
        recs.push_back(blob.substr(pos, e - pos));
        pos = e + 1;
    }
    return recs;
}

std::vector<std::string> fields_of(const std::string& rec) {
    std::vector<std::string> f;
    std::size_t pos = 0;
    for (;;) {
        const std::size_t e = rec.find('\x1f', pos);
        if (e == std::string::npos) {
            f.push_back(rec.substr(pos));
            return f;
        }
        f.push_back(rec.substr(pos, e - pos));
        pos = e + 1;
    }
}

// --- fake in-process plugins: canned output per action, test-set rc ---
struct FakeOut {
    std::map<std::string, std::string> out;
    std::map<std::string, std::string> overflow; // optional 2nd write, after `out`
    std::map<std::string, int> rc;
    // Typed result status a fake plugin declares for an action (applied in fake_execute).
    std::map<std::string, std::tuple<YuzuResultStatus, YuzuResultCompleteness, std::string>>
        result_status;
};
FakeOut g_fake[6]; // 0 installed_apps, 1 pkg_inventory, 2 windows_optional_features, 3 msi_packages,
                   // 4 runtimes, 5 middleware (not in all_plugins())

template <int I>
int fake_execute(YuzuCommandContext* ctx, const char* action, const YuzuParam* /*params*/,
                 std::size_t /*param_count*/) {
    const auto it = g_fake[I].out.find(action);
    if (it != g_fake[I].out.end())
        yuzu_ctx_write_output(ctx, it->second.c_str());
    const auto more = g_fake[I].overflow.find(action);
    if (more != g_fake[I].overflow.end())
        yuzu_ctx_write_output(ctx, more->second.c_str());
    const auto rs = g_fake[I].result_status.find(action);
    if (rs != g_fake[I].result_status.end())
        yuzu_ctx_set_result_status(ctx, std::get<0>(rs->second), std::get<1>(rs->second),
                                   std::get<2>(rs->second).c_str());
    const auto rc = g_fake[I].rc.find(action);
    return rc == g_fake[I].rc.end() ? 0 : rc->second;
}

const char* const kFakeIaActions[] = {"list_inventory", nullptr};
const char* const kFakePkgActions[] = {"managers", "packages", "store_packages", nullptr};
const char* const kFakeWofActions[] = {"list", nullptr};
const char* const kFakeMsiActions[] = {"list_inventory", nullptr};
const char* const kFakeRtActions[] = {"python", "dotnet", "jvm", nullptr};
const char* const kFakeMiddlewareActions[] = {"ibm_mq", nullptr};

#define YUZU_FAKE_DESC(var, plugin_name, actions, idx)                                            \
    const YuzuPluginDescriptor var = {YUZU_PLUGIN_ABI_VERSION, plugin_name, "1.0.0", "test fake", \
                                      actions,                 nullptr,     nullptr,  fake_execute<idx>, \
                                      nullptr}
YUZU_FAKE_DESC(kFakeIa, "installed_apps", kFakeIaActions, 0);
YUZU_FAKE_DESC(kFakePkg, "pkg_inventory", kFakePkgActions, 1);
YUZU_FAKE_DESC(kFakeWof, "windows_optional_features", kFakeWofActions, 2);
YUZU_FAKE_DESC(kFakeMsi, "msi_packages", kFakeMsiActions, 3);
YUZU_FAKE_DESC(kFakeRt, "runtimes", kFakeRtActions, 4);
YUZU_FAKE_DESC(kFakeMiddleware, "middleware", kFakeMiddlewareActions, 5);
#undef YUZU_FAKE_DESC

SyncPluginMap all_plugins() {
    return {{"installed_apps", &kFakeIa},
            {"pkg_inventory", &kFakePkg},
            {"windows_optional_features", &kFakeWof},
            {"msi_packages", &kFakeMsi},
            {"runtimes", &kFakeRt}};
}

void reset_fakes() {
    for (auto& f : g_fake) {
        f.out.clear();
        f.overflow.clear();
        f.rc.clear();
        f.result_status.clear();
    }
    // runtimes.python, .dotnet and .jvm default to a clean empty read (the sample-shaped runs below
    // pin digests that carry none of their rows); the runtimes cases override them.
    for (const char* a : {"python", "dotnet", "jvm"})
        g_fake[4].out[a] =
            yuzu::shared::format_status_row(a, yuzu::shared::StatusLevel::supported, "") + "\n";
}

void fake_mac() {
    reset_fakes();
    g_fake[0].out["list_inventory"] =
        capture_section("installed_apps", "macos.txt", "list_inventory");
    g_fake[1].out["managers"] = capture_section("pkg_inventory", "macos.txt", "managers");
    g_fake[1].out["packages"] = capture_section("pkg_inventory", "macos.txt", "packages");
    g_fake[1].out["store_packages"] =
        capture_section("pkg_inventory", "macos.txt", "store_packages");
    g_fake[2].out["list"] = yuzu::wof::format_unsupported_row("list", "macos:dism:unsupported") + "\n";
    g_fake[3].out["list_inventory"] = msi::unsupported_status_row("macos:owned_by_installed_apps") + "\n";
}

void fake_windows() {
    reset_fakes();
    g_fake[0].out["list_inventory"] =
        capture_section("installed_apps", "windows.txt", "list_inventory");
    g_fake[1].out["managers"] =
        pkg::unsupported_status_row("managers", "windows:planned") + "\n";
    g_fake[1].out["packages"] =
        pkg::unsupported_status_row("packages", "windows:planned") + "\n";
    g_fake[1].out["store_packages"] =
        pkg::unsupported_status_row("store_packages", "windows:planned") + "\n";
    g_fake[2].out["list"] = capture_section("windows_optional_features", "windows.txt", "list");
    g_fake[3].out["list_inventory"] = capture_section("msi_packages", "windows.txt", "list_inventory");
}

// Number of MSI products in the committed Windows sample that the collector maps (a non-empty
// name), counted from the sample itself so a recapture does not break the pinned totals.
std::size_t msi_sample_mapped_rows() {
    return parse_msi_packages_list_inventory_output(
               capture_section("msi_packages", "windows.txt", "list_inventory"), kFailPolicy)
        .entries.size();
}

std::optional<std::pair<std::string, std::string>> collect_with(SyncPluginMap plugins) {
    return make_installed_software_source(std::move(plugins)).collect();
}

std::string supported_status(std::string_view action) {
    return yuzu::shared::format_status_row(action, yuzu::shared::StatusLevel::supported, "");
}

// `n` machine-scope `inv|name|version|` rows; names are padded with 'x' to `name_width`.
std::string inv_lines(std::size_t n, std::size_t name_width = 0) {
    std::string out;
    for (std::size_t i = 0; i < n; ++i) {
        std::string name = "n" + std::to_string(i);
        if (name.size() < name_width)
            name.append(name_width - name.size(), 'x');
        out += "inv|" + name + "|1|\n";
    }
    return out;
}

// A ceiling on canonical bytes/record for the real-capture runs; the measured
// figures (logged below) are what the cap comments in the .cpp quote.
constexpr double kMaxBytesPerRecord = 200.0;

void check_blob_size(const std::string& blob, std::size_t records) {
    const double per = static_cast<double>(blob.size()) / static_cast<double>(records);
    INFO("canonical blob " << blob.size() << " B / " << records << " records = " << per
                           << " B/record");
    CHECK(blob.size() < 3u * 1024 * 1024);
    CHECK(per <= kMaxBytesPerRecord);
}
} // namespace

TEST_CASE("extended tail: agent blob hashes to the server's three contract pins",
          "[sync][hash][extended_row]") {
    CHECK(sha256_hex(installed_software_canonical_blob({full_extended_entry()})) ==
          kCrossPinHashExtended);

    SwEntry first = full_extended_entry();
    first.source = "installed_apps.list_apps";
    CHECK(sha256_hex(installed_software_canonical_blob({full_extended_entry(), first})) ==
          kTailOrderPinHash);

    SwEntry alpha;
    alpha.name = "alpha";
    alpha.version = "1.0";
    alpha.publisher = "AlphaCo";
    alpha.install_date = "2026-01-01";
    alpha.kind = "app";
    SwEntry zed;
    zed.name = "zed";
    zed.version = "1";
    zed.source = "installed_apps.list_inventory"; // source-only tail
    CHECK(sha256_hex(installed_software_canonical_blob({zed, full_extended_entry(), alpha})) ==
          kMixedBlobHash);
}

TEST_CASE("extended tail rule: the tail enters the blob only when package_id or source is set",
          "[sync][hash][extended_row]") {
    const std::vector<SwEntry> v2 = {
        {"Zeta", "9", "", ""},
        full_v2_entry(),
        {"Acme Reader", "1.2", "Acme", "2026-01-02"},
    };
    CHECK(sha256_hex(installed_software_canonical_blob(v2)) == kCrossPinHash);

    auto with_source = v2;
    with_source[0].source = "installed_apps.list_apps";
    const auto h_src = sha256_hex(installed_software_canonical_blob(with_source));
    CHECK(h_src != kCrossPinHash);

    auto only_pkg = v2;
    only_pkg[0].package_id = "x-1";
    const auto h_pkg = sha256_hex(installed_software_canonical_blob(only_pkg));
    CHECK(h_pkg != kCrossPinHash);
    CHECK(h_pkg != h_src);

    const SwEntry base = full_extended_entry();
    const auto one = sha256_hex(installed_software_canonical_blob({base}));
    for (auto field : {&SwEntry::package_id, &SwEntry::source}) {
        SwEntry other = base;
        other.*field = "zz-different";
        const auto both = sha256_hex(installed_software_canonical_blob({other, base}));
        CHECK(both != one); // distinct rows never collapse
        CHECK(both == sha256_hex(installed_software_canonical_blob({base, other})));
    }
    CHECK(sha256_hex(installed_software_canonical_blob({base, base})) == one); // exact dup dedups
}

TEST_CASE("extended tail order: package_id sorts before source, even when they disagree",
          "[sync][hash][extended_row]") {
    // Same v2 fields, so the tail decides: a{pid a, src z} vs b{pid b, src a}. A
    // comparator that swapped the two would put b first.
    SwEntry a;
    a.name = "same";
    a.package_id = "a";
    a.source = "z";
    SwEntry b = a;
    b.package_id = "b";
    b.source = "a";
    for (const auto& in : {std::vector<SwEntry>{a, b}, std::vector<SwEntry>{b, a}}) {
        const auto recs = records_of(installed_software_canonical_blob(in));
        REQUIRE(recs.size() == 2);
        CHECK(fields_of(recs[0])[14] == "a");
        CHECK(fields_of(recs[0])[15] == "z");
        CHECK(fields_of(recs[1])[14] == "b");
        CHECK(fields_of(recs[1])[15] == "a");
    }
}

TEST_CASE("pkg_inventory packages adapter: real macOS capture", "[sync][parse][adapter]") {
    const auto r = parse_pkg_inventory_packages_output(
        capture_section("pkg_inventory", "macos.txt", "packages"), kFailPolicy);
    REQUIRE(r.status == Status::ok);
    REQUIRE(r.entries.size() == 70);
    CHECK(r.entries[0].name == "actionlint");
    CHECK(r.entries[0].version == "1.7.12");
    CHECK(r.entries[0].kind == "pkg");
    CHECK(r.entries[0].ecosystem == "brew");
    for (const auto& e : r.entries) {
        CHECK((e.kind == "pkg" || e.kind == "app"));
        CHECK(e.ecosystem == "brew");
        CHECK(e.source.empty()); // the collector stamps source
    }
}

TEST_CASE("pkg_inventory packages adapter maps casks to kind app", "[sync][parse][adapter]") {
    const auto r = parse_pkg_inventory_packages_output(
        nl({supported_status("packages"),
            pkg::format_package_row("wget", "1.24", pkg::PackageKind::formula),
            pkg::format_package_row("firefox", "130.0", pkg::PackageKind::cask)}),
        kFailPolicy);
    REQUIRE(r.status == Status::ok);
    REQUIRE(r.entries.size() == 2);
    CHECK(r.entries[0].kind == "pkg");
    CHECK(r.entries[1].kind == "app");
}

TEST_CASE("pkg_inventory managers adapter: one Homebrew presence row", "[sync][parse][adapter]") {
    const auto r = parse_pkg_inventory_managers_output(
        capture_section("pkg_inventory", "macos.txt", "managers"), kKeepPolicy);
    REQUIRE(r.status == Status::ok);
    REQUIRE(r.entries.size() == 1);
    CHECK(r.entries[0].name == "homebrew");
    CHECK(r.entries[0].version.empty()); // "-" in the row
    CHECK(r.entries[0].kind == "app");
    CHECK(r.entries[0].ecosystem == "brew");
}

TEST_CASE("pkg_inventory managers adapter: presence semantics and Homebrew-only", "[sync][parse][adapter]") {
    const auto hb_row = [](const char* prefix) {
        return pkg::format_manager_row(pkg::Manager::homebrew, pkg::Presence::present, "", prefix,
                                       "-", "");
    };
    SECTION("two prefixes parse to two identical entries; the collector yields ONE record") {
        const std::string managers = nl({supported_status("managers"), hb_row("/opt/homebrew"),
                                         hb_row("/usr/local")});
        const auto r = parse_pkg_inventory_managers_output(managers, kKeepPolicy);
        REQUIRE(r.status == Status::ok);
        REQUIRE(r.entries.size() == 2);
        CHECK(r.entries[0].name == r.entries[1].name);

        fake_mac();
        g_fake[1].out["managers"] = managers;
        g_fake[1].out["packages"] = supported_status("packages") + "\n";
        const auto got = collect_with(all_plugins());
        REQUIRE(got.has_value());
        std::size_t homebrew = 0;
        for (const auto& rec : records_of(got->first))
            if (fields_of(rec)[0] == "homebrew")
                ++homebrew;
        CHECK(homebrew == 1);
    }
    SECTION("a non-homebrew manager is dropped") {
        const auto r = parse_pkg_inventory_managers_output(
            nl({supported_status("managers"),
                pkg::format_manager_row(pkg::Manager::dpkg, pkg::Presence::present, "1.22", "/",
                                        "-", "")}),
            kKeepPolicy);
        CHECK(r.status == Status::ok);
        CHECK(r.entries.empty());
    }
    SECTION("an unavailable manager emits nothing") {
        const auto r = parse_pkg_inventory_managers_output(
            nl({supported_status("managers"),
                pkg::format_manager_row(pkg::Manager::homebrew, pkg::Presence::unavailable, "",
                                        "/usr/local", "-",
                                        "macos:homebrew_cellar:permission_denied")}),
            kKeepPolicy);
        CHECK(r.status == Status::ok);
        CHECK(r.entries.empty());
    }
}

TEST_CASE("pkg_inventory adapters: status grammar", "[sync][parse][adapter]") {
    const std::string good_row = pkg::format_package_row("wget", "1.24", pkg::PackageKind::formula);

    SECTION("no status row") {
        CHECK(parse_pkg_inventory_packages_output(nl({good_row}), kFailPolicy).status ==
              Status::failed);
    }
    SECTION("constrained carries the reason") {
        const auto r = parse_pkg_inventory_packages_output(
            nl({yuzu::shared::format_status_row("packages", yuzu::shared::StatusLevel::constrained,
                                                "x"),
                good_row}),
            kFailPolicy);
        CHECK(r.status == Status::failed);
        CHECK(r.reason == "x");
    }
    SECTION("two status rows") {
        CHECK(parse_pkg_inventory_packages_output(
                  nl({supported_status("packages"), supported_status("packages"), good_row}),
                  kFailPolicy)
                  .status == Status::failed);
    }
    SECTION("an unknown level") {
        CHECK(parse_pkg_inventory_packages_output(
                  nl({std::string("status|packages|") + "bogus" + "|-", good_row}), kFailPolicy)
                  .status == Status::failed);
    }
    SECTION("a malformed data row is dropped; status decides") {
        const auto r = parse_pkg_inventory_packages_output(
            nl({supported_status("packages"), good_row, "package|homebrew|onlythree"}),
            kFailPolicy);
        REQUIRE(r.status == Status::ok);
        CHECK(r.entries.size() == 1);
    }
    SECTION("a status row for the other action is not accepted") {
        CHECK(parse_pkg_inventory_packages_output(nl({supported_status("managers"), good_row}),
                                                  kFailPolicy)
                  .status == Status::failed);
        CHECK(parse_pkg_inventory_managers_output(nl({supported_status("packages"), good_row}),
                                                  kKeepPolicy)
                  .status == Status::failed);
    }
    SECTION("empty input") {
        CHECK(parse_pkg_inventory_packages_output("", kFailPolicy).status == Status::failed);
        CHECK(parse_pkg_inventory_managers_output("", kKeepPolicy).status == Status::failed);
    }
}

TEST_CASE("pkg_inventory adapters: the Linux sample (a toolchain container with no snapd or flatpak)",
          "[sync][parse][adapter]") {
    // managers: supported, with present dpkg/apt rows that map to nothing.
    const auto m = parse_pkg_inventory_managers_output(
        capture_section("pkg_inventory", "linux.txt", "managers"), kKeepPolicy);
    CHECK(m.status == Status::ok);
    CHECK(m.entries.empty());
    // packages: unsupported by design (installed_apps owns the Linux roster).
    const auto p = parse_pkg_inventory_packages_output(
        capture_section("pkg_inventory", "linux.txt", "packages"), kFailPolicy);
    CHECK(p.status == Status::unsupported);
    CHECK(p.entries.empty());
    // store_packages: supported, zero rows (the container has neither snapd nor flatpak).
    const auto s = parse_pkg_inventory_store_packages_output(
        capture_section("pkg_inventory", "linux.txt", "store_packages"), kFailPolicy);
    CHECK(s.status == Status::ok);
    CHECK(s.entries.empty());
}

namespace {
// Capture values (tests/unit/fixtures/wave10/pkg_inventory/linux/provenance.txt) through the
// real row emitter.
const char* const kCalcCommit = "00516a24d410ad62ed3e955fa5deb5af221ab6b181ed5549103f3670d10d2fca";

std::string snap_store_row(std::string_view id, std::string_view version, std::string_view kind,
                           std::string_view rev, pkg::StoreState state = pkg::StoreState::active) {
    return pkg::format_store_row(pkg::Store::snap, id, version, kind, rev, "", "", state);
}
std::string flatpak_store_row(std::string_view id, std::string_view kind, std::string_view commit,
                              pkg::StoreState state = pkg::StoreState::active) {
    return pkg::format_store_row(pkg::Store::flatpak, id, "", kind, commit, "x86_64", "stable", state);
}
} // namespace

TEST_CASE("pkg_inventory store_packages adapter: active rows map, the rest are seen but unmapped",
          "[sync][parse][adapter]") {
    const auto r = parse_pkg_inventory_store_packages_output(
        nl({supported_status("store_packages"), snap_store_row("btop", "1.4.7", "app", "1073"),
            snap_store_row("core24", "20260824", "base", "2124"),
            flatpak_store_row("org.gnome.Calculator", "app", kCalcCommit),
            flatpak_store_row("org.gnome.Platform", "runtime", kCalcCommit),
            // A degraded ACTIVE row (unreadable snap.yaml): still collected, version honest-empty.
            snap_store_row("jq", "", "unknown", "6"),
            // Present on disk but not installed software.
            snap_store_row("oldsnap", "1.0", "app", "1", pkg::StoreState::inactive),
            snap_store_row("mystery", "1.0", "app", "1", pkg::StoreState::unknown),
            // Not nine tokens, and an unknown store token: dropped.
            "package|snap|short|1.0|app|1|-|active", "package|apt|x|1.0|app|1|-|-|active"}),
        kFailPolicy);
    REQUIRE(r.status == Status::ok);
    REQUIRE(r.entries.size() == 5);
    CHECK(r.reason.empty());

    CHECK(r.entries[0].name == "btop");
    CHECK(r.entries[0].version == "1.4.7");
    CHECK(r.entries[0].release == "1073");
    CHECK(r.entries[0].kind == "app");
    CHECK(r.entries[0].ecosystem == "snap");
    CHECK(r.entries[0].arch.empty());
    CHECK(r.entries[1].kind == "pkg"); // base, not app
    CHECK(r.entries[1].version == "20260824");

    CHECK(r.entries[2].name == "org.gnome.Calculator");
    CHECK(r.entries[2].ecosystem == "flatpak");
    CHECK(r.entries[2].kind == "app");
    CHECK(r.entries[2].version.empty()); // the branch is a ref, not a version
    CHECK(r.entries[2].release == kCalcCommit);
    CHECK(r.entries[2].arch == "x86_64");
    CHECK(r.entries[3].kind == "pkg"); // a runtime

    CHECK(r.entries[4].name == "jq");
    CHECK(r.entries[4].version.empty());
    CHECK(r.entries[4].kind == "pkg");
    CHECK(r.entries[4].release == "6");
    for (const auto& e : r.entries) CHECK(e.source.empty()); // the collector stamps source
}

TEST_CASE("pkg_inventory store_packages adapter: an over-wide row is dropped, never truncated",
          "[sync][parse][adapter]") {
    // MUTATION: split_tokens(line, 9) truncates a 10-token row to a valid nine-token one and
    // maps it with its extra column silently lost.
    const std::string good = snap_store_row("btop", "1.4.7", "app", "1073");
    for (const std::string extra : {"|x", "|x|y"}) {
        const auto r = parse_pkg_inventory_store_packages_output(
            nl({supported_status("store_packages"), good + extra}), kFailPolicy);
        CHECK(r.status == Status::ok);
        CHECK(r.entries.empty());
    }
    const auto ok = parse_pkg_inventory_store_packages_output(
        nl({supported_status("store_packages"), good}), kFailPolicy);
    CHECK(ok.entries.size() == 1);
}

TEST_CASE("pkg_inventory store_packages adapter: status grammar", "[sync][parse][adapter]") {
    const std::string row = snap_store_row("btop", "1.4.7", "app", "1073");
    SECTION("constrained fails (a partial roster would delete stored rows)") {
        const auto r = parse_pkg_inventory_store_packages_output(
            nl({yuzu::shared::format_status_row("store_packages",
                                                yuzu::shared::StatusLevel::constrained,
                                                "linux:flatpak_app:permission_denied"),
                row}),
            kFailPolicy);
        CHECK(r.status == Status::failed);
        CHECK(r.reason == "linux:flatpak_app:permission_denied");
    }
    SECTION("unsupported") {
        const auto r = parse_pkg_inventory_store_packages_output(
            nl({pkg::unsupported_status_row("store_packages", "macos:owned_by_installed_apps")}),
            kFailPolicy);
        CHECK(r.status == Status::unsupported);
        CHECK(r.entries.empty());
    }
    SECTION("a status row for another action, no status row, empty input") {
        CHECK(parse_pkg_inventory_store_packages_output(nl({supported_status("packages"), row}),
                                                        kFailPolicy)
                  .status == Status::failed);
        CHECK(parse_pkg_inventory_store_packages_output(nl({row}), kFailPolicy).status ==
              Status::failed);
        CHECK(parse_pkg_inventory_store_packages_output("", kFailPolicy).status == Status::failed);
    }
    SECTION("supported with zero rows is a legitimate answer") {
        const auto r = parse_pkg_inventory_store_packages_output(
            nl({supported_status("store_packages")}), kFailPolicy);
        CHECK(r.status == Status::ok);
        CHECK(r.entries.empty());
    }
}

TEST_CASE("pkg_inventory managers adapter: a constrained answer that names a present manager keeps "
          "the cycle even when the row maps to nothing",
          "[sync][parse][adapter]") {
    // The first constrained Linux `managers` answer carries dpkg/apt rows, which map to no
    // installed_software entry. MUTATION: counting MAPPED entries (the old `entries.empty()`
    // rule) instead of present rows fails the first section and skips every Linux cycle.
    const std::string token = "linux:apt_sources_d:permission_denied";
    const auto constrained =
        yuzu::shared::format_status_row("managers", yuzu::shared::StatusLevel::constrained, token);
    SECTION("an unmapped present row: ok, zero entries, reason = the token") {
        const auto r = parse_pkg_inventory_managers_output(
            nl({constrained, pkg::format_manager_row(pkg::Manager::dpkg, pkg::Presence::present, "",
                                                     "", "-", "")}),
            kKeepPolicy);
        CHECK(r.status == Status::ok);
        CHECK(r.entries.empty());
        CHECK(r.reason == token);
    }
    SECTION("zero data rows still fails") {
        CHECK(parse_pkg_inventory_managers_output(nl({constrained}), kKeepPolicy).status ==
              Status::failed);
    }
    SECTION("only an unavailable row still fails") {
        CHECK(parse_pkg_inventory_managers_output(
                  nl({constrained,
                      pkg::format_manager_row(pkg::Manager::homebrew, pkg::Presence::unavailable,
                                              "", "/usr/local", "-", token)}),
                  kKeepPolicy)
                  .status == Status::failed);
    }
}

TEST_CASE("collector: Linux store_packages rows are collected, and a degraded row does not skip the cycle",
          "[sync][collector]") {
    fake_mac();
    // A Linux-shaped pkg_inventory answer layered on the Mac fakes: supported status, active
    // capture-valued rows, PLUS one degraded ACTIVE row (version `-`, kind unknown) under a
    // SUPPORTED status. MUTATION: a status token on the degraded row makes the adapter fail it
    // and skips the whole report.
    g_fake[1].out["store_packages"] =
        nl({supported_status("store_packages"), snap_store_row("btop", "1.4.7", "app", "1073"),
            snap_store_row("jq", "", "unknown", "6"),
            flatpak_store_row("org.gnome.Calculator", "app", kCalcCommit)});
    const auto got = collect_with(all_plugins());
    REQUIRE(got.has_value());
    const auto recs = records_of(got->first);
    CHECK(recs.size() == 393 + 70 + 1 + 3);
    std::map<std::string, std::string> eco_by_name;
    std::size_t store = 0;
    for (const auto& rec : recs) {
        const auto f = fields_of(rec);
        REQUIRE(f.size() == 16);
        if (f[15] != "pkg_inventory.store_packages") continue;
        ++store;
        eco_by_name[f[0]] = f[5];
    }
    CHECK(store == 3);
    CHECK(eco_by_name["btop"] == "snap");
    CHECK(eco_by_name["jq"] == "snap");
    CHECK(eco_by_name["org.gnome.Calculator"] == "flatpak");

    // A constrained store_packages answer (an incomplete LIST) skips the cycle: nothing is deleted.
    g_fake[1].out["store_packages"] = nl(
        {yuzu::shared::format_status_row("store_packages", yuzu::shared::StatusLevel::constrained,
                                         "linux:snapd_snaps:permission_denied"),
         snap_store_row("btop", "1.4.7", "app", "1073")});
    CHECK_FALSE(collect_with(all_plugins()).has_value());
}

TEST_CASE("windows_optional_features adapter: real capture keeps every feature with its state",
          "[sync][parse][adapter]") {
    const auto r = parse_windows_optional_features_output(
        capture_section("windows_optional_features", "windows.txt", "list"));
    REQUIRE(r.status == Status::ok);
    REQUIRE(r.entries.size() == 137);
    std::size_t enabled = 0;
    std::size_t disabled = 0;
    std::map<std::string, std::string> state;
    for (const auto& e : r.entries) {
        CHECK(e.kind == "feat");
        CHECK(e.ecosystem == "optional_feature");
        CHECK(e.publisher.empty());
        state[e.name] = e.version;
        enabled += e.version == "enabled";
        disabled += e.version == "disabled";
    }
    CHECK(enabled == 17);
    CHECK(disabled == 120);
    CHECK(state["NetFx3"] == "enabled");
    CHECK(state["VirtualMachinePlatform"] == "enabled");
    CHECK(state["TelnetClient"] == "disabled");

    // The restart flag is dropped; a pending state keeps its token.
    const auto p = parse_windows_optional_features_output(
        yuzu::wof::format_feature_row("X", yuzu::wof::FeatureState::install_pending, true) + "\n");
    REQUIRE(p.status == Status::ok);
    REQUIRE(p.entries.size() == 1);
    CHECK(p.entries[0].version == "pending_enable");
}

TEST_CASE("windows_optional_features adapter: sentinels and empty input", "[sync][parse][adapter]") {
    CHECK(parse_windows_optional_features_output(
              yuzu::wof::format_unsupported_row("list", "macos:dism:unsupported") + "\n")
              .status == Status::unsupported);
    const auto u = parse_windows_optional_features_output(
        yuzu::wof::format_unavailable_row("list", "windows:dism:busy") + "\n");
    CHECK(u.status == Status::failed);
    CHECK(u.reason == "windows:dism:busy");
    CHECK(parse_windows_optional_features_output("").status == Status::failed);

    // Only the disabled features: still a successful, non-empty answer.
    const std::string real = capture_section("windows_optional_features", "windows.txt", "list");
    std::istringstream in(real);
    std::string line;
    std::string only_disabled;
    while (std::getline(in, line))
        if (line.find("|disabled|") != std::string::npos)
            only_disabled += line + '\n';
    const auto d = parse_windows_optional_features_output(only_disabled);
    REQUIRE(d.status == Status::ok);
    CHECK(d.entries.size() == 120);
    for (const auto& e : d.entries)
        CHECK(e.version == "disabled");
}

TEST_CASE("new adapters clamp every field like parse_installed_apps_output",
          "[sync][parse][adapter]") {
    const std::string too_long(2000, 'v');

    SECTION("packages: 0x1F stripped from the name, version truncated") {
        const auto r = parse_pkg_inventory_packages_output(
            nl({supported_status("packages"),
                std::string("package|homebrew|wg\037et|") + too_long + "|formula"}),
            kFailPolicy);
        REQUIRE(r.status == Status::ok);
        REQUIRE(r.entries.size() == 1);
        CHECK(r.entries[0].name == "wget");
        CHECK(r.entries[0].version.size() == 1024);
    }
    SECTION("managers: over-length version truncated") {
        const auto r = parse_pkg_inventory_managers_output(
            nl({supported_status("managers"),
                "manager|homebrew|present|" + too_long + "|/opt/homebrew|-|-"}),
            kKeepPolicy);
        REQUIRE(r.status == Status::ok);
        REQUIRE(r.entries.size() == 1);
        CHECK(r.entries[0].version.size() == 1024);
    }
    SECTION("msi: every field truncated, invalid UTF-8 in the name becomes U+FFFD") {
        const auto r = parse_msi_packages_list_inventory_output(
            nl({"status|list_inventory|supported|-",
                "inv|" + too_long + "|Caf\xe9|" + too_long + "|" + too_long}),
            kFailPolicy);
        REQUIRE(r.status == Status::ok);
        REQUIRE(r.entries.size() == 1);
        CHECK(r.entries[0].package_id.size() == 1024);
        CHECK(r.entries[0].name == std::string("Caf\xef\xbf\xbd"));
        CHECK(r.entries[0].version.size() == 1024);
        CHECK(r.entries[0].publisher.size() == 1024);
    }
    SECTION("optional features: invalid UTF-8 in the name becomes U+FFFD") {
        const auto r = parse_windows_optional_features_output(
            std::string("feature|Caf\xe9|enabled|0\n"));
        REQUIRE(r.status == Status::ok);
        REQUIRE(r.entries.size() == 1);
        CHECK(r.entries[0].name == std::string("Caf\xef\xbf\xbd"));
    }
}

// --- msi_packages.list_inventory ---

namespace {
// The machine-context (ctx 4) rows of the committed Kingsley capture, rendered by the REAL
// builder (msi::render), so the adapter is fed exactly what the plugin emits.
// products-system.txt columns: code|ctx|sid|name|version|publisher|location.
std::string msi_rendered_fixture(std::size_t* machine_rows = nullptr) {
    const fs::path p = fs::path(YUZU_TEST_FIXTURE_DIR) / "software-estate" / "msi_packages" /
                       "windows" / "products-system.txt";
    std::ifstream in(p);
    REQUIRE(in.is_open());
    msi::Inventory inv;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line.front() == '#')
            continue;
        std::vector<std::string> f;
        std::size_t pos = 0;
        for (;;) {
            const auto bar = line.find('|', pos);
            if (bar == std::string::npos) {
                f.push_back(line.substr(pos));
                break;
            }
            f.push_back(line.substr(pos, bar - pos));
            pos = bar + 1;
        }
        REQUIRE(f.size() == 7);
        if (f[1] != "4")
            continue; // the per-user row (ctx 2) is never listed
        inv.products.push_back({f[0], f[3], f[4], f[5]});
    }
    if (machine_rows)
        *machine_rows = inv.products.size();
    std::string out;
    for (const auto& row : msi::render(inv))
        out += row + '\n';
    return out;
}
} // namespace

TEST_CASE("msi_packages adapter: maps the builder-rendered Kingsley capture",
          "[sync][parse][adapter][msi_packages]") {
    std::size_t n = 0;
    const auto r = parse_msi_packages_list_inventory_output(msi_rendered_fixture(&n), kFailPolicy);
    REQUIRE(r.status == Status::ok);
    REQUIRE(n == 118);
    REQUIRE(r.entries.size() == 118);
    CHECK(r.reason.empty());

    const auto& e = r.entries[0];
    CHECK(e.name == "Python Launcher");
    CHECK(e.version == "3.14.6150.0");
    CHECK(e.publisher == "Python Software Foundation");
    CHECK(e.kind == "pkg");
    CHECK(e.ecosystem == "msi");
    CHECK(e.package_id == "{0B1B5000-3C0E-41C0-83C4-4C914420AE93}");
    // a lower-case registered code is carried verbatim (no GUID case normalisation)
    CHECK(std::any_of(r.entries.begin(), r.entries.end(), [](const SwEntry& x) {
        return x.package_id == "{41120dd7-deb4-4bca-be34-265fc243d4f3}";
    }));
    CHECK(e.install_date.empty());
    CHECK(e.epoch.empty());
    CHECK(e.release.empty());
    CHECK(e.arch.empty());
    CHECK(e.signature_status.empty());
    CHECK(e.distro_id.empty());
    CHECK(e.distro_version.empty());
    CHECK(e.source.empty()); // the collector stamps source
    for (const auto& x : r.entries)
        CHECK(x.package_id != "{665A0435-D5D5-4A49-9DE0-FBC23C5425ED}");
    check_blob_size(installed_software_canonical_blob(r.entries), 118);
}

TEST_CASE("msi_packages adapter: a pipe-bearing product survives the producer/collector round trip",
          "[sync][parse][adapter][msi_packages]") {
    // SYNTHETIC product (no captured name contains a pipe). MUTATION: a producer that escapes the
    // fields with safe_output_field emits `\|`, which the raw-pipe splitter sees as a 7-token row;
    // the adapter drops it and entries.size() == 1 fails.
    msi::Inventory inv;
    inv.products.push_back({"{11111111-2222-3333-4444-555555555555}", "Foo | Bar Agent", "1.0",
                            "Foo | Bar Ltd"});
    std::string out;
    for (const auto& row : msi::render(inv))
        out += row + '\n';
    const auto r = parse_msi_packages_list_inventory_output(out, kFailPolicy);
    REQUIRE(r.status == Status::ok);
    REQUIRE(r.entries.size() == 1);
    CHECK(r.entries[0].name == "Foo  Bar Agent");
    CHECK(r.entries[0].publisher == "Foo  Bar Ltd");
    CHECK(r.entries[0].package_id == "{11111111-2222-3333-4444-555555555555}");
}

TEST_CASE("msi_packages adapter: the real Windows sample", "[sync][parse][adapter][msi_packages]") {
    const auto r = parse_msi_packages_list_inventory_output(
        capture_section("msi_packages", "windows.txt", "list_inventory"), kFailPolicy);
    REQUIRE(r.status == Status::ok);
    REQUIRE_FALSE(r.entries.empty());
    for (const auto& e : r.entries) {
        CHECK(e.kind == "pkg");
        CHECK(e.ecosystem == "msi");
        REQUIRE(e.package_id.size() == 38);
        CHECK(e.package_id.front() == '{');
        CHECK(e.package_id.back() == '}');
        CHECK_FALSE(e.name.empty());
    }
}

TEST_CASE("msi_packages adapter: status grammar", "[sync][parse][adapter][msi_packages]") {
    const std::string row = "inv|{AAAAAAAA-0000-0000-0000-000000000001}|App|1.0|Pub";
    const auto status = [](std::string_view level, std::string_view tokens) {
        return "status|list_inventory|" + std::string{level} + "|" + std::string{tokens};
    };
    SECTION("constrained fails (a partial roster would delete stored msi rows)") {
        const auto r = parse_msi_packages_list_inventory_output(
            nl({status("constrained", "windows:msi_enum:1610"), row}), kFailPolicy);
        CHECK(r.status == Status::failed);
        CHECK(r.reason == "windows:msi_enum:1610");
    }
    SECTION("unsupported on macOS and Linux") {
        for (const char* token : {"macos:owned_by_installed_apps", "linux:no_msi"}) {
            const auto r = parse_msi_packages_list_inventory_output(
                nl({status("unsupported", token)}), kFailPolicy);
            CHECK(r.status == Status::unsupported);
            CHECK(r.entries.empty());
        }
    }
    SECTION("no status row, another action's status row, empty input") {
        CHECK(parse_msi_packages_list_inventory_output(nl({row}), kFailPolicy).status ==
              Status::failed);
        CHECK(parse_msi_packages_list_inventory_output(nl({"status|packages|supported|-", row}),
                                                       kFailPolicy)
                  .status == Status::failed);
        CHECK(parse_msi_packages_list_inventory_output("", kFailPolicy).status == Status::failed);
    }
    SECTION("supported with zero rows is a legitimate answer") {
        const auto r =
            parse_msi_packages_list_inventory_output(nl({status("supported", "-")}), kFailPolicy);
        CHECK(r.status == Status::ok);
        CHECK(r.entries.empty());
    }
    SECTION("two status rows fail") {
        CHECK(parse_msi_packages_list_inventory_output(
                  nl({status("supported", "-"), status("supported", "-")}), kFailPolicy)
                  .status == Status::failed);
    }
}

TEST_CASE("msi_packages adapter: row shape", "[sync][parse][adapter][msi_packages]") {
    const std::string ok_status = "status|list_inventory|supported|-";
    const std::string good = "inv|{AAAAAAAA-0000-0000-0000-000000000001}|App|1.0|Pub";
    SECTION("a 4-token and a 6-token inv row are dropped, never truncated or padded") {
        // MUTATION: split_tokens truncation to 5 would map the 6-token row.
        const auto r = parse_msi_packages_list_inventory_output(
            nl({ok_status, "inv|{AAAAAAAA-0000-0000-0000-000000000001}|App|1.0", good + "|extra",
                good + "|extra|more"}),
            kFailPolicy);
        CHECK(r.status == Status::ok);
        CHECK(r.entries.empty());
    }
    SECTION("an empty code is mapped with an empty package_id (the adapter invents no key)") {
        const auto r = parse_msi_packages_list_inventory_output(nl({ok_status, "inv||name|1|pub"}),
                                                                kFailPolicy);
        REQUIRE(r.entries.size() == 1);
        CHECK(r.entries[0].package_id.empty());
    }
    SECTION("an empty name is seen but not mapped") {
        const auto r = parse_msi_packages_list_inventory_output(
            nl({ok_status, "inv|{AAAAAAAA-0000-0000-0000-000000000001}||1|pub"}), kFailPolicy);
        CHECK(r.status == Status::ok);
        CHECK(r.entries.empty());
    }
    SECTION("legacy list rows and product_codes rows are ignored") {
        const auto r = parse_msi_packages_list_inventory_output(
            nl({ok_status, "msi|{AAAAAAAA-0000-0000-0000-000000000001}|App|1.0|-",
                "product_code|{AAAAAAAA-0000-0000-0000-000000000001}|App", good}),
            kFailPolicy);
        REQUIRE(r.entries.size() == 1);
        CHECK(r.entries[0].name == "App");
    }
}

TEST_CASE("collector: msi_packages rows ride the extended tail and a constrained answer skips",
          "[sync][collector][msi_packages]") {
    SECTION("Windows-shaped run: msi records carry package_id and source, slots 13-14 stay empty") {
        fake_windows();
        const auto got = collect_with(all_plugins());
        REQUIRE(got.has_value());
        std::size_t msi_records = 0;
        for (const auto& rec : records_of(got->first)) {
            const auto f = fields_of(rec);
            REQUIRE(f.size() == 16);
            if (f[15] != "msi_packages.list_inventory")
                continue;
            ++msi_records;
            CHECK(f[4] == "pkg");
            CHECK(f[5] == "msi");
            CHECK(f[12].empty()); // install_location (reserved, #5186)
            CHECK(f[13].empty()); // uninstall_string (reserved, #5186)
            CHECK(f[14].size() == 38); // {GUID}
        }
        CHECK(msi_records == msi_sample_mapped_rows());
        CHECK(msi_records > 0);
    }
    SECTION("a constrained enumeration skips the whole cycle with the named reason") {
        fake_windows();
        g_fake[3].out["list_inventory"] =
            "status|list_inventory|constrained|windows:msi_enum:5\n"
            "inv|{AAAAAAAA-0000-0000-0000-000000000001}|App|1.0|Pub\n";
        auto src = make_installed_software_source(all_plugins());
        REQUIRE(src.skip_reason);
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason() == "msi_packages.list_inventory:windows:msi_enum:5");
    }
    SECTION("macOS: the unsupported answer is skipped silently and the cycle collects") {
        fake_mac();
        const auto got = collect_with(all_plugins());
        REQUIRE(got.has_value());
        for (const auto& rec : records_of(got->first))
            CHECK(fields_of(rec)[15] != "msi_packages.list_inventory");
    }
}

TEST_CASE("extended tail: an msi entry's package_id participates in the canonical blob",
          "[sync][hash][extended_row][msi_packages]") {
    SwEntry with_id;
    with_id.name = "CMake";
    with_id.version = "4.3.4";
    with_id.publisher = "Kitware";
    with_id.kind = "pkg";
    with_id.ecosystem = "msi";
    with_id.package_id = "{B7526150-1C45-45B5-932D-A4CF5A23403C}";
    with_id.source = "msi_packages.list_inventory";
    SwEntry without_id = with_id;
    without_id.package_id.clear();
    CHECK(sha256_hex(installed_software_canonical_blob({with_id})) !=
          sha256_hex(installed_software_canonical_blob({without_id})));
    // Two products with the same name/version/publisher but different codes stay two rows.
    SwEntry other = with_id;
    other.package_id = "{B7526150-1C45-45B5-932D-A4CF5A23403D}";
    CHECK(records_of(installed_software_canonical_blob({with_id, other})).size() == 2);
}

TEST_CASE("collector: Mac-shaped run merges apps, brew packages and the presence row",
          "[sync][collector]") {
    fake_mac();
    const auto got = collect_with(all_plugins());
    REQUIRE(got.has_value());
    const auto recs = records_of(got->first);
    CHECK(recs.size() == 393 + 70 + 1);
    const std::set<std::string> sources = {"installed_apps.list_inventory",
                                           "pkg_inventory.packages", "pkg_inventory.managers"};
    std::vector<SwEntry> parsed;
    std::map<std::string, std::size_t> per_source;
    for (const auto& rec : recs) {
        const auto f = fields_of(rec);
        REQUIRE(f.size() == 16);
        CHECK(f[12].empty());
        CHECK(f[13].empty());
        CHECK(sources.count(f[15]) == 1);
        ++per_source[f[15]];
        SwEntry e;
        e.name = f[0];
        e.version = f[1];
        e.publisher = f[2];
        e.install_date = f[3];
        e.kind = f[4];
        e.ecosystem = f[5];
        e.epoch = f[6];
        e.release = f[7];
        e.arch = f[8];
        e.signature_status = f[9];
        e.distro_id = f[10];
        e.distro_version = f[11];
        e.package_id = f[14];
        e.source = f[15];
        parsed.push_back(std::move(e));
    }
    CHECK(per_source["installed_apps.list_inventory"] == 393);
    CHECK(per_source["pkg_inventory.packages"] == 70);
    CHECK(per_source["pkg_inventory.managers"] == 1);
    CHECK(installed_software_canonical_blob(parsed) == got->first); // sorted, stable
    CHECK(got->second == sha256_hex(got->first));
    check_blob_size(got->first, recs.size());
}

TEST_CASE("collector: an absent plugin is skipped", "[sync][collector]") {
    fake_mac();
    SyncPluginMap m = all_plugins();
    m.erase("pkg_inventory");
    m.erase("windows_optional_features");
    const auto got = collect_with(m);
    REQUIRE(got.has_value());
    const auto recs = records_of(got->first);
    CHECK(recs.size() == 393);
    for (const auto& rec : recs)
        CHECK(fields_of(rec)[15] == "installed_apps.list_inventory");
}

TEST_CASE("collector: installed_apps absent idles the source (UP-IN6)", "[sync][collector]") {
    fake_mac();
    SyncPluginMap m = all_plugins();
    m.erase("installed_apps");
    CHECK_FALSE(collect_with(m).has_value());
}

TEST_CASE("collector: one failing action skips the whole cycle", "[sync][collector]") {
    SECTION("pkg_inventory rc != 0") {
        fake_mac();
        g_fake[1].rc["packages"] = 1;
        CHECK_FALSE(collect_with(all_plugins()).has_value());
    }
    SECTION("pkg_inventory constrained") {
        fake_mac();
        g_fake[1].out["packages"] =
            yuzu::shared::format_status_row("packages", yuzu::shared::StatusLevel::constrained,
                                            "macos:x") +
            "\n";
        CHECK_FALSE(collect_with(all_plugins()).has_value());
    }
    SECTION("windows_optional_features unavailable") {
        fake_windows();
        g_fake[2].out["list"] =
            yuzu::wof::format_unavailable_row("list", "windows:dism:timeout") + "\n";
        CHECK_FALSE(collect_with(all_plugins()).has_value());
    }
    SECTION("installed_apps empty while brew has rows (UP-IN6 per plugin)") {
        fake_mac();
        g_fake[0].out["list_inventory"] = "";
        CHECK_FALSE(collect_with(all_plugins()).has_value());
    }
    SECTION("a truncated capture (rc 0, over the capture cap)") {
        fake_mac();
        // A first write the adapter accepts, then one write past kInventoryCaptureCap
        // (3'670'016): the real capture path drops it and flags truncation, leaving a
        // parseable prefix, so only the collector's truncation check can skip the cycle.
        g_fake[1].out["packages"] = supported_status("packages") + "\n";
        g_fake[1].overflow["packages"] = std::string(3'700'000, 'x');
        CHECK_FALSE(collect_with(all_plugins()).has_value());
    }
}

TEST_CASE("collector: successful-empty answers are not failures", "[sync][collector]") {
    fake_mac();
    const auto full = collect_with(all_plugins());
    REQUIRE(full.has_value());

    SECTION("brew with no formulae and no managers: the apps stay") {
        g_fake[1].out["packages"] = supported_status("packages") + "\n";
        g_fake[1].out["managers"] = supported_status("managers") + "\n";
        const auto got = collect_with(all_plugins());
        REQUIRE(got.has_value());
        const auto recs = records_of(got->first);
        CHECK(recs.size() == 393);
        for (const auto& rec : recs)
            CHECK(fields_of(rec)[15] == "installed_apps.list_inventory");
        CHECK(got->second != full->second);
    }
    SECTION("Windows: every feature is reported, enabled and disabled hash differently") {
        fake_windows();
        const auto got = collect_with(all_plugins());
        REQUIRE(got.has_value());
        const auto recs = records_of(got->first);
        CHECK(recs.size() == 241 + 137 + msi_sample_mapped_rows());
        std::size_t disabled = 0;
        std::size_t enabled = 0;
        for (const auto& rec : recs) {
            const auto f = fields_of(rec);
            if (f[5] != "optional_feature")
                continue;
            CHECK(f[4] == "feat");
            CHECK(f[15] == "windows_optional_features.list");
            disabled += f[1] == "disabled";
            enabled += f[1] == "enabled";
        }
        CHECK(disabled == 120);
        CHECK(enabled == 17);
        check_blob_size(got->first, recs.size());

        SwEntry on;
        on.name = "F";
        on.version = "enabled";
        SwEntry off = on;
        off.version = "disabled";
        CHECK(sha256_hex(installed_software_canonical_blob({on})) !=
              sha256_hex(installed_software_canonical_blob({off})));
    }
}

TEST_CASE("collector: Windows-shaped run with the real captures", "[sync][collector]") {
    fake_windows();
    g_fake[2].out["list"] = [] {
        std::string enabled_only;
        std::istringstream in(capture_section("windows_optional_features", "windows.txt", "list"));
        std::string line;
        while (std::getline(in, line))
            if (line.find("|enabled|") != std::string::npos)
                enabled_only += line + '\n';
        return enabled_only;
    }();
    const auto got = collect_with(all_plugins());
    REQUIRE(got.has_value());
    CHECK(records_of(got->first).size() == 241 + 17 + msi_sample_mapped_rows());
}

TEST_CASE("entry cap: the splitter reads one past kMaxEntries and the collector skips above it",
          "[sync][collector][cap]") {
    CHECK(parse_installed_apps_output(inv_lines(20001)).size() == 20001);

    reset_fakes();
    SyncPluginMap only_ia = {{"installed_apps", &kFakeIa}};
    g_fake[0].out["list_inventory"] = inv_lines(20001);
    CHECK_FALSE(collect_with(only_ia).has_value());

    g_fake[0].out["list_inventory"] = inv_lines(20000);
    const auto got = collect_with(only_ia);
    REQUIRE(got.has_value());
    CHECK(records_of(got->first).size() == 20000);

    // 20,001 RAW rows where one is an exact duplicate: the splitter stopped at the
    // cap, so the deduped count (20,000) must not launder a truncated read.
    g_fake[0].out["list_inventory"] = inv_lines(20000) + "inv|n0|1|\n";
    CHECK_FALSE(collect_with(only_ia).has_value());

    // Byte cap: the entry cap runs first, so the over-cap input stays <= 20,000
    // rows and under the raw capture cap, but its canonical blob exceeds kMaxBlobBytes.
    // 12,000 x 200 B names is proven under the cap by the test itself.
    const std::string under = inv_lines(12000, 200);
    CHECK(installed_software_canonical_blob(parse_installed_apps_output(under)).size() <
          3u * 1024 * 1024);
    g_fake[0].out["list_inventory"] = under;
    REQUIRE(collect_with(only_ia).has_value());

    // The capture itself must not be truncated (that would skip for the wrong reason).
    const std::string over = inv_lines(16000, 200);
    CHECK(over.size() < 3'670'016); // kInventoryCaptureCap
    g_fake[0].out["list_inventory"] = over;
    CHECK_FALSE(collect_with(only_ia).has_value());
}

// --- constrained managers, typed PARTIAL guard ---

namespace {
// Real emitters: a constrained managers status row carrying one present Homebrew row.
std::string constrained_managers_with_present_row() {
    return nl({yuzu::shared::format_status_row("managers", yuzu::shared::StatusLevel::constrained,
                                               "macos:homebrew_taps:permission_denied"),
               pkg::format_manager_row(pkg::Manager::homebrew, pkg::Presence::present, "",
                                       "/opt/homebrew", "-", "")});
}
} // namespace

TEST_CASE("collector: constrained managers keeps a present row", "[sync][collector]") {
    SECTION("present row: the cycle succeeds with one managers record") {
        fake_mac();
        g_fake[1].out["managers"] = constrained_managers_with_present_row();
        const auto got = collect_with(all_plugins());
        REQUIRE(got.has_value());
        const auto recs = records_of(got->first);
        CHECK(recs.size() == 393 + 70 + 1);
        std::size_t managers = 0;
        for (const auto& rec : recs)
            if (fields_of(rec)[15] == "pkg_inventory.managers")
                ++managers;
        CHECK(managers == 1);
    }
    SECTION("only an unavailable row: skipped") {
        fake_mac();
        g_fake[1].out["managers"] =
            nl({yuzu::shared::format_status_row("managers", yuzu::shared::StatusLevel::constrained,
                                                "macos:homebrew_taps:permission_denied"),
                pkg::format_manager_row(pkg::Manager::homebrew, pkg::Presence::unavailable, "",
                                        "/usr/local", "-",
                                        "macos:homebrew_cellar:permission_denied")});
        CHECK_FALSE(collect_with(all_plugins()).has_value());
    }
}

TEST_CASE("pkg_inventory adapters: constrained managers with a present row is ok and carries "
          "its reason",
          "[sync][parse][adapter]") {
    const std::string token = "macos:homebrew_taps:permission_denied";
    const auto m =
        parse_pkg_inventory_managers_output(constrained_managers_with_present_row(), kKeepPolicy);
    CHECK(m.status == AdaptedRows::Status::ok);
    CHECK(m.entries.size() == 1);
    CHECK(m.reason == token);
}

// The skip on a typed PARTIAL is pinned in the skip_reason case below (collect() is nullopt with
// the `:partial` token); this case pins the paths that must NOT skip.
TEST_CASE("collector: typed completeness - FULL collected; an opted-in PARTIAL accepted; in-band "
          "unsupported wins",
          "[sync][collector]") {
    constexpr auto kPartial = YUZU_RESULT_COMPLETENESS_PARTIAL;
    SECTION("packages OK/FULL: collected") {
        fake_mac();
        g_fake[1].result_status["packages"] = {YUZU_RESULT_STATUS_OK,
                                               YUZU_RESULT_COMPLETENESS_FULL, ""};
        CHECK(collect_with(all_plugins()).has_value());
    }
    SECTION("managers CONSTRAINED/PARTIAL with a present row: opt-in accepts") {
        fake_mac();
        g_fake[1].out["managers"] = constrained_managers_with_present_row();
        g_fake[1].result_status["managers"] = {YUZU_RESULT_STATUS_CONSTRAINED, kPartial, "x"};
        CHECK(collect_with(all_plugins()).has_value());
    }
    SECTION("in-band unsupported wins over UNAVAILABLE/PARTIAL (WOF on mac)") {
        fake_mac();
        g_fake[2].result_status["list"] = {YUZU_RESULT_STATUS_UNAVAILABLE, kPartial, "r"};
        const auto got = collect_with(all_plugins());
        REQUIRE(got.has_value());
        CHECK(records_of(got->first).size() == 393 + 70 + 1);
    }
}

TEST_CASE("collector: installed_software carries the 01:00-05:00 local nightly window",
          "[sync][collector][window]") {
    // The only place the window is set: every other source keeps a plain 24 h phase slot.
    fake_mac();
    const auto src = make_installed_software_source(all_plugins());
    REQUIRE(src.window);
    CHECK(src.window->start_min == 60);
    CHECK(src.window->end_min == 300);
}

TEST_CASE("collector: skip_reason names the cause of each skip and clears on success",
          "[sync][collector]") {
    fake_mac();
    auto src = make_installed_software_source(all_plugins());
    CHECK(src.skip_backoff);
    REQUIRE(src.skip_reason);
    SECTION("an action's non-zero rc") {
        g_fake[1].rc["packages"] = 1;
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason() == "pkg_inventory.packages:rc=1");
        g_fake[1].rc.clear();
        CHECK(src.collect().has_value());
        CHECK(src.skip_reason() == "");
    }
    SECTION("the anchor plugin absent") {
        SyncPluginMap m = all_plugins();
        m.erase("installed_apps");
        auto s2 = make_installed_software_source(std::move(m));
        CHECK_FALSE(s2.collect().has_value());
        CHECK(s2.skip_reason() == "installed_apps:not_loaded");
    }
    SECTION("an adapter failure reason") {
        fake_windows();
        g_fake[2].out["list"] =
            yuzu::wof::format_unavailable_row("list", "windows:dism:timeout") + "\n";
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason() == "windows_optional_features.list:windows:dism:timeout");
    }
    SECTION("typed PARTIAL completeness") {
        g_fake[1].result_status["packages"] = {YUZU_RESULT_STATUS_CONSTRAINED,
                                               YUZU_RESULT_COMPLETENESS_PARTIAL, "x"};
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason() == "pkg_inventory.packages:partial");
    }
    SECTION("the anchor emits no rows") {
        // The anchor adapter fails an empty listing ("an empty parse is a plugin
        // hiccup, not everything uninstalled"), before the merged no-rows check.
        g_fake[0].out["list_inventory"] = "";
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason() == "installed_apps.list_inventory:no inv rows");
    }
    SECTION("a truncated capture") {
        // A parseable first write, then one past kInventoryCaptureCap (3'670'016).
        g_fake[1].out["packages"] = supported_status("packages") + "\n";
        g_fake[1].overflow["packages"] = std::string(3'700'000, 'x');
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason() == "pkg_inventory.packages:truncated");
    }
    SECTION("one action reads more than kMaxEntries raw rows") {
        g_fake[0].out["list_inventory"] = inv_lines(20001);
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason() == "installed_apps.list_inventory:row_cap");
    }
    SECTION("the merged inventory exceeds kMaxEntries") {
        // Each action is under the raw-row cap (12,000 applications, 9,000 formulae); the
        // merge (plus the managers presence row) is over it.
        g_fake[0].out["list_inventory"] = inv_lines(12000);
        std::string formulae = supported_status("packages") + "\n";
        for (int i = 0; i < 9000; ++i)
            formulae += pkg::format_package_row("f" + std::to_string(i), "1.0",
                                                pkg::PackageKind::formula) + "\n";
        g_fake[1].out["packages"] = formulae;
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason() == "installed_software:entry_cap");
    }
    SECTION("an over-long adapter reason is cut at the heartbeat bound") {
        fake_windows();
        g_fake[2].out["list"] =
            yuzu::wof::format_unavailable_row("list", std::string(100, 'x')) + "\n";
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason().size() == 64);
        CHECK(src.skip_reason().starts_with("windows_optional_features.list:"));
    }
    SECTION("the canonical blob exceeds kMaxBlobBytes") {
        g_fake[0].out["list_inventory"] = inv_lines(16000, 200);
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason() == "installed_software:blob_cap");
    }
}

// --- Adapter characterisation: the whole observable result of each status-row adapter ---
//
// Every cell asserts the whole observable result of an adapter: status, reason, entry count and
// ALL fourteen fields of every entry. The cells reach the adapters only through the four binders
// below, so the way the constrained policy reaches an adapter is the binders' concern alone and
// the expectations stay put. Status rows are written as raw text (not through a formatter) so
// they are independent of the producer.

namespace {

std::string show_entry(const SwEntry& e) {
    std::string s;
    for (const std::string* f : {&e.name, &e.version, &e.publisher, &e.install_date, &e.kind,
                                 &e.ecosystem, &e.epoch, &e.release, &e.arch, &e.signature_status,
                                 &e.distro_id, &e.distro_version, &e.package_id, &e.source}) {
        s += *f;
        s += ',';
    }
    return s;
}

std::string show(const AdaptedRows& r) {
    std::string s = r.status == Status::ok            ? "ok"
                    : r.status == Status::unsupported ? "unsupported"
                    : r.status == Status::withheld    ? "withheld"
                                                      : "failed";
    s += "|reason=" + r.reason + "|n=" + std::to_string(r.entries.size());
    for (const auto& e : r.entries)
        s += "|" + show_entry(e);
    return s;
}

// Expected-result builders (the entry text is built through show_entry, so a dropped or
// reordered field is a visible difference, not a silently shorter string).
std::string res(std::string_view status, std::string_view reason,
                std::initializer_list<SwEntry> es = {}) {
    std::string s =
        std::string(status) + "|reason=" + std::string(reason) + "|n=" + std::to_string(es.size());
    for (const auto& e : es)
        s += "|" + show_entry(e);
    return s;
}

SwEntry entry_of(std::string name, std::string version, std::string publisher, std::string kind,
                 std::string ecosystem, std::string package_id = {}, std::string release = {},
                 std::string arch = {}) {
    SwEntry e;
    e.name = std::move(name);
    e.version = std::move(version);
    e.publisher = std::move(publisher);
    e.kind = std::move(kind);
    e.ecosystem = std::move(ecosystem);
    e.package_id = std::move(package_id);
    e.release = std::move(release);
    e.arch = std::move(arch);
    return e;
}

std::string st(std::string_view action, std::string_view level, std::string_view tokens) {
    return "status|" + std::string(action) + "|" + std::string(level) + "|" + std::string(tokens);
}

std::string crlf(std::string s) {
    std::string out;
    for (char c : s) {
        if (c == '\n')
            out += '\r';
        out += c;
    }
    return out;
}

// The four binders: the ONLY place the cells touch an adapter.
AdaptedRows bind_managers(const std::string& s) {
    return parse_pkg_inventory_managers_output(s, kKeepPolicy);
}
AdaptedRows bind_packages(const std::string& s) {
    return parse_pkg_inventory_packages_output(s, kFailPolicy);
}
AdaptedRows bind_store(const std::string& s) {
    return parse_pkg_inventory_store_packages_output(s, kFailPolicy);
}
AdaptedRows bind_msi(const std::string& s) {
    return parse_msi_packages_list_inventory_output(s, kFailPolicy);
}

struct Grammar {
    std::string action;
    std::function<AdaptedRows(const std::string&)> bind;
    std::string mapped; // one row the adapter maps to exactly `entry`
    SwEntry entry;
    std::string unmapped;        // a row that is SEEN but maps to nothing
    std::string notseen;         // a row of the wrong shape: neither seen nor mapped
    bool keeps_constrained_rows; // managers: a constrained answer keeps its rows iff one was seen
};

// Every status-grammar cell, shared by the four adapters that read `status|<action>|...`.
void check_status_matrix(const Grammar& g) {
    INFO("action=" << g.action);
    const std::string other = g.action == "packages" ? "managers" : "packages";
    const auto run = [&](std::initializer_list<std::string> lines) {
        return show(g.bind(nl(lines)));
    };
    const auto ok1 = res("ok", "", {g.entry});

    // supported: reason stays empty at 4 fields and at 5+ (field 4 is parsed, not surfaced)
    CHECK(run({st(g.action, "supported", "-"), g.mapped}) == ok1);
    CHECK(run({st(g.action, "supported", "tok"), g.mapped}) == ok1);
    CHECK(run({st(g.action, "supported", "tok|extra"), g.mapped}) == ok1);
    CHECK(run({st(g.action, "supported", "-|a|b|c"), g.mapped}) == ok1);
    CHECK(run({st(g.action, "supported", "-")}) == res("ok", ""));
    // order independence, blank lines, a trailing status row
    CHECK(show(g.bind(g.mapped + "\n\n" + st(g.action, "supported", "-") + "\n")) == ok1);
    // CRLF
    CHECK(show(g.bind(crlf(nl({st(g.action, "supported", "-"), g.mapped})))) == ok1);

    // unsupported clears entries, whatever followed; reason empty
    CHECK(run({st(g.action, "unsupported", "linux:no_such")}) == res("unsupported", ""));
    CHECK(run({st(g.action, "unsupported", "linux:no_such"), g.mapped}) == res("unsupported", ""));
    CHECK(run({st(g.action, "unsupported", "t|extra"), g.mapped}) == res("unsupported", ""));

    // constrained: field 4 is the reason
    if (g.keeps_constrained_rows) {
        CHECK(run({st(g.action, "constrained", "tok"), g.mapped}) == res("ok", "tok", {g.entry}));
        CHECK(run({st(g.action, "constrained", "tok|extra"), g.mapped}) ==
              res("ok", "tok", {g.entry}));
        CHECK(show(g.bind(crlf(nl({st(g.action, "constrained", "tok"), g.mapped})))) ==
              res("ok", "tok", {g.entry}));
        // seen-but-unmapped counts as evidence the read worked
        CHECK(run({st(g.action, "constrained", "tok"), g.unmapped}) == res("ok", "tok"));
    } else {
        CHECK(run({st(g.action, "constrained", "tok"), g.mapped}) == res("failed", "tok"));
        CHECK(run({st(g.action, "constrained", "tok|extra"), g.mapped}) == res("failed", "tok"));
        CHECK(show(g.bind(crlf(nl({st(g.action, "constrained", "tok"), g.mapped})))) ==
              res("failed", "tok"));
        CHECK(run({st(g.action, "constrained", "tok"), g.unmapped}) == res("failed", "tok"));
    }
    // zero rows, or only rows that are not even seen, fail on every adapter
    CHECK(run({st(g.action, "constrained", "tok")}) == res("failed", "tok"));
    CHECK(run({st(g.action, "constrained", "tok"), g.notseen}) == res("failed", "tok"));
    // an escaped pipe in a status token is cut at the raw split (format escapes, parse does not)
    CHECK(run({"status|" + g.action + "|constrained|a\\|b", g.mapped}) ==
          (g.keeps_constrained_rows ? res("ok", "a\\", {g.entry}) : res("failed", "a\\")));

    // bad status: zero or two counted status rows, a short row, an unknown level
    const std::string bad = res("failed", "bad status");
    CHECK(run({g.mapped}) == bad);
    CHECK(run({}) == bad);
    CHECK(run({"status|" + g.action + "|supported", g.mapped}) == bad);
    CHECK(run({"status", g.mapped}) == bad);
    CHECK(run({"status|", g.mapped}) == bad);
    CHECK(run({"status|" + g.action, g.mapped}) == bad);
    CHECK(run({st(g.action, "supported", "-"), st(g.action, "supported", "-"), g.mapped}) == bad);
    CHECK(run({st(g.action, "supported", "-"), st(g.action, "constrained", "t"), g.mapped}) == bad);
    CHECK(run({st(g.action, "supported", "-"), st(g.action, "unsupported", "t")}) == bad);
    CHECK(run({st(other, "supported", "-"), g.mapped}) == bad);
    for (const char* level : {"bogus", "", "Supported", "supported ", "SUPPORTED", "constrained2"})
        CHECK(run({st(g.action, level, "-"), g.mapped}) == bad);
    // an unknown-level row still counts: beside a valid one that is two status rows
    CHECK(run({st(g.action, "bogus", "-"), st(g.action, "supported", "-"), g.mapped}) == bad);
    // a status row for another action, or a too-short one, is not counted: it neither fails the
    // action nor stands in for its own status row
    CHECK(run({st(other, "supported", "-"), st(g.action, "supported", "-"), g.mapped}) == ok1);
    CHECK(run({"status|" + g.action + "|supported", st(g.action, "supported", "-"), g.mapped}) ==
          ok1);

    // data rows: a wrong-shaped row is dropped, status still decides
    CHECK(run({st(g.action, "supported", "-"), g.notseen, g.mapped, g.notseen}) == ok1);
    CHECK(run({st(g.action, "supported", "-"), g.unmapped}) == res("ok", ""));
    CHECK(run({st(g.action, "supported", "-"), g.unmapped, g.mapped}) == ok1);
    CHECK(run({st(g.action, "supported", "-"), "", "garbage", "|", "||||", g.mapped}) == ok1);
    // a ten-token status row for this action still counts as a status row (a second one: bad)
    CHECK(run({st(g.action, "supported", "-"),
               "status|" + g.action + "|supported|-|-|-|-|-|-|-"}) == bad);
}

} // namespace

TEST_CASE("characterisation: packages", "[sync][characterisation][adapter]") {
    Grammar g{"packages",
              bind_packages,
              "package|homebrew|wget|1.24|formula",
              entry_of("wget", "1.24", "", "pkg", "brew"),
              "package|homebrew|mystery|1.0|bogus",
              "package|homebrew|onlythree",
              false};
    check_status_matrix(g);

    const auto run = [](std::initializer_list<std::string> lines) {
        return show(bind_packages(nl(lines)));
    };
    const std::string sup = st("packages", "supported", "-");
    SECTION("row mapping") {
        CHECK(run({sup, "package|homebrew|firefox|130.0|cask"}) ==
              res("ok", "", {entry_of("firefox", "130.0", "", "app", "brew")}));
        CHECK(run({sup, "package|homebrew|a|1|formula", "package|homebrew|a|1|formula"}) ==
              res("ok", "",
                  {entry_of("a", "1", "", "pkg", "brew"), entry_of("a", "1", "", "pkg", "brew")}));
        // an empty version is carried, an empty name is seen and not mapped
        CHECK(run({sup, "package|homebrew|a||formula"}) ==
              res("ok", "", {entry_of("a", "", "", "pkg", "brew")}));
        CHECK(run({sup, "package|homebrew||1|formula"}) == res("ok", ""));
    }
    SECTION("rows that are not mapped") {
        CHECK(run({sup, "package|snap|x|1|formula"}) == res("ok", ""));
        CHECK(run({sup, "package|homebrew|a|1|formula|extra"}) == res("ok", ""));
        CHECK(run({sup, "package|homebrew|a|1"}) == res("ok", ""));
        CHECK(run({sup, "manager|homebrew|present|-|/|-|-"}) == res("ok", ""));
        CHECK(run({sup, "inv|homebrew|a|1|formula"}) == res("ok", ""));
        CHECK(run({sup, "package|Homebrew|a|1|formula"}) == res("ok", ""));
        CHECK(run({sup, "package|homebrew|a|1|Formula"}) == res("ok", ""));
    }
    SECTION("a long field is clamped to the wire cap") {
        const auto r = bind_packages(nl({sup, "package|homebrew|" + std::string(2000, 'n') + "|" +
                                                  std::string(2000, 'v') + "|formula"}));
        REQUIRE(r.entries.size() == 1);
        CHECK(r.entries[0].name == std::string(1024, 'n'));
        CHECK(r.entries[0].version == std::string(1024, 'v'));
    }
    SECTION("only keep_rows_if_present_seen keeps a constrained answer's rows") {
        // A scoped enum admits values that are neither enumerator; keeping rows is the opt-in,
        // so an out-of-range policy fails closed even though a mapped row was seen.
        const auto out =
            nl({st("packages", "constrained", "tok"), "package|homebrew|wget|1.24|formula"});
        CHECK(show(parse_pkg_inventory_packages_output(out, kKeepPolicy)) ==
              res("ok", "tok", {entry_of("wget", "1.24", "", "pkg", "brew")}));
        CHECK(show(parse_pkg_inventory_packages_output(out, static_cast<ConstrainedPolicy>(9))) ==
              res("failed", "tok"));
    }
}

TEST_CASE("characterisation: store_packages", "[sync][characterisation][adapter]") {
    Grammar g{"store_packages",
              bind_store,
              "package|snap|btop|1.4.7|app|1073|-|-|active",
              entry_of("btop", "1.4.7", "", "app", "snap", "", "1073"),
              "package|snap|btop|1|app|1|-|-|inactive",
              "package|snap|btop|1|app|1|-|-",
              false};
    check_status_matrix(g);

    const auto run = [](std::initializer_list<std::string> lines) {
        return show(bind_store(nl(lines)));
    };
    const std::string sup = st("store_packages", "supported", "-");
    SECTION("row mapping") {
        CHECK(
            run({sup, "package|flatpak|org.x.App|-|app|abc|x86_64|stable|active"}) ==
            res("ok", "", {entry_of("org.x.App", "", "", "app", "flatpak", "", "abc", "x86_64")}));
        // flatpak never carries a version, even when the row has one
        CHECK(run({sup, "package|flatpak|org.x.App|9.9|runtime|abc|-|stable|active"}) ==
              res("ok", "", {entry_of("org.x.App", "", "", "pkg", "flatpak", "", "abc", "")}));
        // snap: version `-` is honest-empty, kind other than `app` is pkg, release `-` is empty
        CHECK(run({sup, "package|snap|core22|-|base|-|-|-|active"}) ==
              res("ok", "", {entry_of("core22", "", "", "pkg", "snap")}));
        // snap ignores arch (field 6)
        CHECK(run({sup, "package|snap|x|2|app|7|amd64|-|active"}) ==
              res("ok", "", {entry_of("x", "2", "", "app", "snap", "", "7", "")}));
    }
    SECTION("seen but not mapped") {
        CHECK(run({sup, "package|homebrew|a|1|app|1|-|-|active"}) == res("ok", ""));
        CHECK(run({sup, "package|snap|a|1|app|1|-|-|unknown"}) == res("ok", ""));
        CHECK(run({sup, "package|snap||1|app|1|-|-|active"}) == res("ok", ""));
        // a constrained answer still fails: the policy for this action is fail whatever was seen
        CHECK(run({st("store_packages", "constrained", "tok"),
                   "package|homebrew|a|1|app|1|-|-|active"}) == res("failed", "tok"));
    }
    SECTION("over-wide and short rows are dropped, not truncated") {
        CHECK(run({sup, "package|snap|a|1|app|1|-|-|active|extra"}) == res("ok", ""));
        CHECK(run({sup, "package|snap|a|1|app|1|-|active"}) == res("ok", ""));
    }
}

TEST_CASE("characterisation: managers", "[sync][characterisation][adapter]") {
    Grammar g{"managers",
              bind_managers,
              "manager|homebrew|present|-|/opt/homebrew|-|-",
              entry_of("homebrew", "", "", "app", "brew"),
              "manager|snap|present|2.60|/|-|-",
              "manager|homebrew|present|-|/opt/homebrew|-",
              true};
    check_status_matrix(g);

    const auto run = [](std::initializer_list<std::string> lines) {
        return show(bind_managers(nl(lines)));
    };
    const std::string sup = st("managers", "supported", "-");
    const std::string hb = "manager|homebrew|present|4.1|/opt/homebrew|-|-";
    SECTION("presence row fields") {
        CHECK(run({sup, hb}) == res("ok", "", {entry_of("homebrew", "4.1", "", "app", "brew")}));
        CHECK(run({sup, hb, "manager|homebrew|present|-|/usr/local|-|-"}) ==
              res("ok", "",
                  {entry_of("homebrew", "4.1", "", "app", "brew"),
                   entry_of("homebrew", "", "", "app", "brew")}));
    }
    SECTION("a present non-homebrew manager is seen and dropped") {
        for (const char* m :
             {"dpkg", "apt", "rpm", "dnf", "pacman", "apk", "snap", "flatpak", "something_new"}) {
            const std::string row = std::string("manager|") + m + "|present|1.0|/|-|-";
            INFO(m);
            CHECK(run({sup, row}) == res("ok", ""));
            CHECK(run({st("managers", "constrained", "tok"), row}) == res("ok", "tok"));
        }
        // a dropped manager next to a mapped one: only the mapped one is an entry
        CHECK(run({st("managers", "constrained", "tok"), "manager|snap|present|1|/|-|-", hb}) ==
              res("ok", "tok", {entry_of("homebrew", "4.1", "", "app", "brew")}));
    }
    SECTION("an unavailable manager is neither seen nor mapped") {
        const std::string un =
            "manager|homebrew|unavailable|-|/usr/local|-|macos:homebrew_cellar:permission_denied";
        CHECK(run({sup, un}) == res("ok", ""));
        CHECK(run({st("managers", "constrained", "tok"), un}) == res("failed", "tok"));
        CHECK(run({st("managers", "constrained", "tok"), un, "manager|snap|present|1|/|-|-"}) ==
              res("ok", "tok"));
        CHECK(run({st("managers", "constrained", "tok"), "manager|homebrew|bogus|-|/|-|-"}) ==
              res("failed", "tok"));
    }
    SECTION("over-wide rows are dropped, not truncated") {
        CHECK(run({sup, hb + "|extra"}) == res("ok", ""));
        CHECK(run({st("managers", "constrained", "tok"), hb + "|extra"}) == res("failed", "tok"));
    }
    SECTION("supported keeps no reason, whatever field 4 holds") {
        CHECK(run({st("managers", "supported", "tok|more"), hb}) ==
              res("ok", "", {entry_of("homebrew", "4.1", "", "app", "brew")}));
    }
    SECTION("unknown level fails even with a present row") {
        CHECK(run({st("managers", "bogus", "tok"), hb}) == res("failed", "bad status"));
    }
}

TEST_CASE("characterisation: msi list_inventory",
          "[sync][characterisation][adapter][msi_packages]") {
    const std::string code = "{AAAAAAAA-0000-0000-0000-000000000001}";
    Grammar g{"list_inventory",
              bind_msi,
              "inv|" + code + "|App|1.0|Pub",
              entry_of("App", "1.0", "Pub", "pkg", "msi", code),
              "inv|" + code + "||1.0|Pub",
              "inv|" + code + "|App|1.0",
              false};
    check_status_matrix(g);

    const auto run = [](std::initializer_list<std::string> lines) {
        return show(bind_msi(nl(lines)));
    };
    const std::string sup = st("list_inventory", "supported", "-");
    SECTION("row mapping") {
        // an empty code is mapped with an empty package_id; case is carried verbatim
        CHECK(run({sup, "inv||n|1|p"}) == res("ok", "", {entry_of("n", "1", "p", "pkg", "msi")}));
        CHECK(run({sup, "inv|{aaaaaaaa-0000-0000-0000-000000000001}|n||"}) ==
              res("ok", "",
                  {entry_of("n", "", "", "pkg", "msi", "{aaaaaaaa-0000-0000-0000-000000000001}")}));
    }
    SECTION("rows that are not mapped") {
        CHECK(run({sup, "inv|" + code + "|App|1.0|Pub|extra"}) == res("ok", ""));
        CHECK(run({sup, "msi|" + code + "|App|1.0|-"}) == res("ok", ""));
        CHECK(run({sup, "package|homebrew|a|1|formula"}) == res("ok", ""));
        CHECK(run({sup, "INV|" + code + "|App|1.0|Pub"}) == res("ok", ""));
    }
    SECTION("a status row for the pkg_inventory `packages` action is not this action's") {
        CHECK(run({st("packages", "supported", "-"), "inv|" + code + "|App|1.0|Pub"}) ==
              res("failed", "bad status"));
    }
}

// Collector level: the whole blob, pinned. The blob is hashed byte-identically on agent and
// server (ADR-0016), so any movement here is a one-sided change. Re-measure ONLY on a sample
// recapture, the same rule as the record counts above.
TEST_CASE("characterisation: collector blob digests are byte-pinned",
          "[sync][characterisation][collector]") {
    constexpr const char* kMac = "db0a9878010b71264fced3df9cb00e4703093e50cb59314d171a3227b929f2bf";
    constexpr const char* kWindows =
        "fe9619361232be03c99ea7e0dc4059c988344734d91d18cb24dc30ec0b1e61e5";
    constexpr const char* kLinuxManagers =
        "522b8d64c16e2f503bdff8f68d2ba21989e534234da2c7174b7f11b38b955561";
    const auto digest = [](const char* what) {
        const auto got = collect_with(all_plugins());
        INFO(what);
        REQUIRE(got.has_value());
        CHECK(sha256_hex(got->first) == got->second);
        return got->second;
    };
    SECTION("Mac-shaped run") {
        fake_mac();
        CHECK(digest("mac") == kMac);
    }
    SECTION("Windows-shaped run") {
        fake_windows();
        CHECK(digest("windows") == kWindows);
    }
    SECTION("Mac-shaped run with a constrained managers answer that keeps its present row") {
        fake_mac();
        g_fake[1].out["managers"] = constrained_managers_with_present_row();
        // Same digest as the Mac-shaped run: the kept present row maps to the one homebrew
        // record the capture already carries, so the constrained answer must not move a byte.
        CHECK(digest("mac+constrained managers") == kMac);
    }
    SECTION("Linux-shaped managers answer: present dpkg/apt rows under a constrained status") {
        fake_mac();
        g_fake[1].out["managers"] =
            nl({st("managers", "constrained", "linux:apt_sources_d:permission_denied"),
                "manager|dpkg|present|1.22|/|-|-", "manager|apt|present|2.7|/|-|-"});
        CHECK(digest("mac+linux managers") == kLinuxManagers);
    }
}

TEST_CASE("characterisation: collector skip reasons per status mix",
          "[sync][characterisation][collector]") {
    struct Case {
        int fake;
        const char* plugin;
        const char* action;
        bool windows;       // which sample set the other actions come from
        const char* mapped; // a valid row the action maps; empty for managers (they keep it)
        bool withholds = false; // table policy drop_source: constrained withholds the rows, not the cycle
        bool keeps = false;     // keep_rows_if_present_seen: a constrained answer WITH a mapped row keeps it
    };
    const Case cases[] = {
        {1, "pkg_inventory", "packages", false, "package|homebrew|wget|1.24|formula"},
        {1, "pkg_inventory", "store_packages", false,
         "package|snap|btop|1.4.7|app|1073|-|-|active"},
        {1, "pkg_inventory", "managers", false, ""},
        {3, "msi_packages", "list_inventory", true,
         "inv|{AAAAAAAA-0000-0000-0000-000000000001}|App|1.0|Pub"},
        {4, "runtimes", "python", false, "python|cpython|3.14.6|C:/P/|PythonCore", true},
        {4, "runtimes", "dotnet", false, "dotnet|runtime|8.0.33|C:/Program Files/dotnet/|Microsoft", false,
         true},
        {4, "runtimes", "jvm", false, "jvm|jdk|21.0.12.1|C:/Program Files/Microsoft/jdk-21.0.12.101-hotspot/|Microsoft", false,
         true}};
    for (const auto& c : cases) {
        INFO(c.plugin << "." << c.action);
        const std::string source = std::string(c.plugin) + "." + c.action;
        const auto setup = [&] {
            c.windows ? fake_windows() : fake_mac();
        };
        const auto skip_with = [&](const std::string& output) {
            setup();
            g_fake[c.fake].out[c.action] = output;
            auto src = make_installed_software_source(all_plugins());
            const bool collected = src.collect().has_value();
            return std::make_pair(collected, src.skip_reason());
        };
        const std::string a = c.action;
        // What a constrained answer does to the cycle, per the action table's `constrained` column:
        // fail skips it with the status token as the reason; drop_source (runtimes.python) lets it
        // continue with only that source's rows withheld (the collector-level case in the
        // runtimes.python test below pins the rows).
        const auto constrained_outcome = c.withholds ? std::make_pair(true, std::string{})
                                                     : std::make_pair(false, source + ":tok");
        // constrained with no data row
        CHECK(skip_with(nl({st(a, "constrained", "tok")})) == constrained_outcome);
        // constrained with a row of the wrong shape: the same outcome
        CHECK(skip_with(nl({st(a, "constrained", "tok"), "garbage|row"})) == constrained_outcome);
        // constrained with a row the adapter MAPS: the same outcome, so the action table's
        // `constrained` column is what is pinned, not just the zero-row fallback.
        // Managers is the one action that keeps such a cycle (cases below).
        if (c.mapped[0] != '\0') {
            CHECK(skip_with(nl({st(a, "constrained", "tok"), c.mapped})) ==
                  (c.keeps ? std::make_pair(true, std::string{}) : constrained_outcome));
        }
        // zero, two, short and mis-levelled status rows
        CHECK(skip_with("") == std::make_pair(false, source + ":bad status"));
        CHECK(skip_with(nl({"status|" + a + "|supported"})) ==
              std::make_pair(false, source + ":bad status"));
        CHECK(skip_with(nl({st(a, "supported", "-"), st(a, "supported", "-")})) ==
              std::make_pair(false, source + ":bad status"));
        CHECK(skip_with(nl({st(a, "wrong", "-")})) ==
              std::make_pair(false, source + ":bad status"));
        // unsupported is silently skipped (the cycle succeeds, nothing recorded as a skip)
        CHECK(skip_with(nl({st(a, "unsupported", "tok")})) == std::make_pair(true, std::string{}));
        // supported with zero rows is a legitimate answer
        CHECK(skip_with(nl({st(a, "supported", "-")})) == std::make_pair(true, std::string{}));
    }
    SECTION("managers: a constrained answer with only a present, unmapped row keeps the cycle") {
        fake_mac();
        g_fake[1].out["managers"] =
            nl({st("managers", "constrained", "tok"), "manager|dpkg|present|1.0|/|-|-"});
        auto src = make_installed_software_source(all_plugins());
        CHECK(src.collect().has_value());
        CHECK(src.skip_reason().empty());
    }
    SECTION("managers: a constrained answer with only an unavailable row skips") {
        fake_mac();
        g_fake[1].out["managers"] =
            nl({st("managers", "constrained", "tok"), "manager|homebrew|unavailable|-|/|-|why"});
        auto src = make_installed_software_source(all_plugins());
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason() == "pkg_inventory.managers:tok");
    }
}

// The collector's manager -> ecosystem table (kManagerEcosystems), pinned through the adapters it
// serves: every row reaches the wire with its ecosystem, and the three rows that must NOT map stay
// unmapped. The published-value half (every emitted ecosystem is in the vocabulary) is
// tests/test_software_vocabulary_consistency.py, which reads the table's `.ecosystem = "..."`.
TEST_CASE("manager-ecosystem table: each row maps through its own action only",
          "[sync][characterisation][adapter]") {
    SECTION("homebrew -> brew, through packages and the managers presence row") {
        CHECK(show(bind_packages(
                  nl({st("packages", "supported", "-"), "package|homebrew|wget|1.24|formula"}))) ==
              res("ok", "", {entry_of("wget", "1.24", "", "pkg", "brew")}));
        CHECK(show(bind_managers(nl({st("managers", "supported", "-"),
                                     "manager|homebrew|present|4.1|/opt/homebrew|-|-"}))) ==
              res("ok", "", {entry_of("homebrew", "4.1", "", "app", "brew")}));
    }
    SECTION("snap -> snap and flatpak -> flatpak, through store_packages") {
        CHECK(show(bind_store(nl({st("store_packages", "supported", "-"),
                                  "package|snap|btop|1.4.7|app|1073|-|-|active"}))) ==
              res("ok", "", {entry_of("btop", "1.4.7", "", "app", "snap", "", "1073")}));
        CHECK(
            show(bind_store(nl({st("store_packages", "supported", "-"),
                                "package|flatpak|org.x.App|-|app|abc|x86_64|stable|active"}))) ==
            res("ok", "", {entry_of("org.x.App", "", "", "app", "flatpak", "", "abc", "x86_64")}));
    }
    SECTION("a manager is never mapped through another manager's action") {
        // snap inside `packages`: not even seen. homebrew inside `store_packages`: seen, unmapped.
        CHECK(show(bind_packages(nl({st("packages", "supported", "-"),
                                     "package|snap|x|1|formula"}))) == res("ok", ""));
        CHECK(show(bind_store(nl({st("store_packages", "supported", "-"),
                                  "package|homebrew|x|1|app|1|-|-|active"}))) == res("ok", ""));
        // snap and flatpak have no presence row: dropped from `managers`
        for (const char* m : {"snap", "flatpak"}) {
            CHECK(show(bind_managers(nl({st("managers", "supported", "-"),
                                         std::string("manager|") + m + "|present|1|/|-|-"}))) ==
                  res("ok", ""));
        }
    }
    SECTION("a dropped manager still counts as seen under a constrained managers answer") {
        for (const char* m : {"snap", "flatpak", "dpkg"}) {
            CHECK(show(bind_managers(nl({st("managers", "constrained", "tok"),
                                         std::string("manager|") + m + "|present|1|/|-|-"}))) ==
                  res("ok", "tok"));
        }
    }
}

// runtimes.python through the COLLECTOR (the adapter cases below call the parser directly): the
// table row is what wires the plugin in, so removing it, or flipping its ConstrainedPolicy away
// from drop_source, turns a section here red.
TEST_CASE("collector: runtimes.python contributes sourced rows, a constrained Python read withholds "
          "only them and a PARTIAL one aborts the cycle",
          "[sync][collector][runtimes]") {
    const std::string python_row =
        "python|cpython|3.13.1|/Library/Frameworks/Python.framework/Versions/3.13|org.python.python";
    const auto python_records = [](const std::string& blob) {
        std::size_t n = 0;
        for (const auto& rec : records_of(blob)) {
            const auto f = fields_of(rec);
            REQUIRE(f.size() == 16);
            // Every record sourced runtimes.python is a python-ecosystem Python entry, and back.
            CHECK((f[15] == "runtimes.python") == (f[5] == "python"));
            if (f[15] != "runtimes.python") continue;
            ++n;
            CHECK(f[0] == "Python");
            CHECK(f[1] == "3.13.1");
            CHECK(f[4] == "app");
        }
        return n;
    };
    SECTION("a python row becomes one sourced python record beside the other sources") {
        fake_mac();
        g_fake[4].out["python"] = nl({supported_status("python"), python_row});
        const auto got = collect_with(all_plugins());
        REQUIRE(got.has_value());
        CHECK(python_records(got->first) == 1);
        CHECK(records_of(got->first).size() == 393 + 70 + 1 + 1);
    }
    SECTION("escaped pipes in the free-text fields do not cost the sourced row") {
        // Built by the real producer: vendor and install_path go through safe_output_field, so a
        // literal pipe reaches the collector as `\|` and must not read as a sixth field.
        yuzu::runtimes::PythonRecord rec;
        rec.flavour = yuzu::runtimes::PythonFlavour::cpython;
        rec.version = "3.13.1";
        rec.install_path = "C:\\Python|313\\";
        rec.vendor = "org.python|custom";
        const auto piped = yuzu::runtimes::python_row(rec);
        REQUIRE(piped.find("\\|") != std::string::npos);
        fake_mac();
        g_fake[4].out["python"] = nl({supported_status("python"), piped});
        const auto got = collect_with(all_plugins());
        REQUIRE(got.has_value());
        CHECK(python_records(got->first) == 1);
        CHECK(records_of(got->first).size() == 393 + 70 + 1 + 1);
    }
    SECTION("a clean empty read contributes nothing and does not skip the cycle") {
        fake_mac();
        const auto got = collect_with(all_plugins());
        REQUIRE(got.has_value());
        CHECK(python_records(got->first) == 0);
        CHECK(records_of(got->first).size() == 393 + 70 + 1);
    }
    SECTION("a constrained status withholds the python rows only, even one that carries a row") {
        fake_mac();
        g_fake[4].out["python"] =
            nl({st("python", "constrained", "linux:runtimes:permission_denied"), python_row});
        // The real leg also types the answer CONSTRAINED + PARTIAL (runtimes_legs.hpp emit_read):
        // the withheld verdict must win over the PARTIAL skip, which would cost the whole cycle.
        g_fake[4].result_status["python"] = {YUZU_RESULT_STATUS_CONSTRAINED,
                                             YUZU_RESULT_COMPLETENESS_PARTIAL,
                                             "linux:runtimes:permission_denied"};
        auto src = make_installed_software_source(all_plugins());
        REQUIRE(src.skip_reason);
        const auto got = src.collect();
        REQUIRE(got.has_value()); // the cycle continues
        CHECK(src.skip_reason().empty());
        CHECK(python_records(got->first) == 0);
        CHECK(records_of(got->first).size() == 393 + 70 + 1); // every other source's rows survive
    }
    SECTION("a supported status with typed PARTIAL completeness skips the cycle") {
        fake_mac();
        g_fake[4].out["python"] = nl({supported_status("python"), python_row});
        g_fake[4].result_status["python"] = {YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                             "x"};
        auto src = make_installed_software_source(all_plugins());
        REQUIRE(src.skip_reason);
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason() == "runtimes.python:partial");
    }
}

// runtimes.python adapter
TEST_CASE("runtimes python adapter: real-capture rows map to Python / app / python",
          "[sync][parse][adapter][runtimes]") {
    using Status = AdaptedRows::Status;
    // Rows as the plugin emits them over the committed captures: the debian:bookworm listing
    // (major.minor only on Linux), the python.org 3.13.1 framework plist (macOS) and a Windows
    // PythonCore tag (flavour/path/vendor are dropped: no installed_software slot).
    const auto r = parse_runtimes_python_output(
        nl({"status|python|supported|-",
            "python|unmodelled|3.11|/usr/bin/python3.11|-",
            "python|cpython|3.13.1|/Library/Frameworks/Python.framework/Versions/3.13|org.python.python",
            "python|cpython|3.14.6|C:/Python314/|PythonCore"}),
        kFailPolicy);
    REQUIRE(r.status == Status::ok);
    REQUIRE(r.entries.size() == 3);
    const char* versions[] = {"3.11", "3.13.1", "3.14.6"};
    for (std::size_t i = 0; i < 3; ++i) {
        CHECK(r.entries[i].name == "Python");
        CHECK(r.entries[i].version == versions[i]);
        CHECK(r.entries[i].kind == "app");
        CHECK(r.entries[i].ecosystem == "python");
        CHECK(r.entries[i].publisher.empty());
    }
}

TEST_CASE("runtimes python adapter: rows built by the producer round-trip through escaped pipes",
          "[sync][parse][adapter][runtimes]") {
    using Status = AdaptedRows::Status;
    yuzu::runtimes::PythonRecord rec;
    rec.flavour = yuzu::runtimes::PythonFlavour::cpython;
    rec.version = "3.13.1";
    rec.install_path = "C:\\Python|313\\"; // a literal backslash folds to '/', a pipe to `\|`
    rec.vendor = "org.python|custom";
    const auto row = yuzu::runtimes::python_row(rec);
    // Pin the wire form the adapter has to read, so a producer change shows up here.
    REQUIRE(row == "python|cpython|3.13.1|C:/Python\\|313/|org.python\\|custom");
    SECTION("one piped vendor and path: one entry, version unchanged") {
        const auto r = parse_runtimes_python_output(nl({"status|python|supported|-", row}), kFailPolicy);
        REQUIRE(r.status == Status::ok);
        REQUIRE(r.entries.size() == 1);
        CHECK(r.entries[0].version == "3.13.1");
        CHECK(r.entries[0].ecosystem == "python");
    }
    SECTION("more escaped pipes than the split width still read as five logical fields") {
        rec.vendor = "a|b|c|d|e|f|g|h|i|j|k|l";
        const auto r = parse_runtimes_python_output(
            nl({"status|python|supported|-", yuzu::runtimes::python_row(rec)}), kFailPolicy);
        REQUIRE(r.status == Status::ok);
        REQUIRE(r.entries.size() == 1);
        CHECK(r.entries[0].version == "3.13.1");
    }
}

TEST_CASE("runtimes python adapter: `-` version is empty; malformed rows are dropped",
          "[sync][parse][adapter][runtimes]") {
    using Status = AdaptedRows::Status;
    const auto r = parse_runtimes_python_output(
        nl({"status|python|supported|-", "python|unmodelled|-|/usr/bin/python3.x|-",
            "python|cpython|3.1|/p", "jvm|jdk|17|/x|-", "python|cpython|3.2|/p|v|extra"}),
        kFailPolicy);
    REQUIRE(r.status == Status::ok);
    REQUIRE(r.entries.size() == 1);
    CHECK(r.entries[0].version.empty());
    CHECK(r.entries[0].ecosystem == "python");
}

TEST_CASE("runtimes python adapter: status grammar decides the answer", "[sync][parse][adapter][runtimes]") {
    using Status = AdaptedRows::Status;
    // No status row, or one for another action: bad status.
    CHECK(parse_runtimes_python_output(nl({"python|cpython|3.14.6|C:/P/|PythonCore"}), kFailPolicy).status ==
          Status::failed);
    CHECK(parse_runtimes_python_output(nl({"status|jvm|supported|-"}), kFailPolicy).status ==
          Status::failed);
    // constrained under the table row's drop_source policy: status withheld, zero entries even
    // though a row was present, reason = the status tokens (what the collector logs).
    const auto w = parse_runtimes_python_output(
        nl({"status|python|constrained|linux:runtimes:permission_denied",
            "python|unmodelled|3.11|/usr/bin/python3.11|-"}),
        ConstrainedPolicy::drop_source);
    CHECK(show(w) == res("withheld", "linux:runtimes:permission_denied"));
    // the adapter still honours an explicit fail policy
    const auto c = parse_runtimes_python_output(
        nl({"status|python|constrained|linux:runtimes:permission_denied",
            "python|unmodelled|3.11|/usr/bin/python3.11|-"}),
        ConstrainedPolicy::fail);
    CHECK(c.status == Status::failed);
    CHECK(c.reason == "linux:runtimes:permission_denied");
    // unsupported is skipped with no entries.
    const auto u = parse_runtimes_python_output(nl({"status|python|unsupported|macos:planned"}), kFailPolicy);
    CHECK(u.status == Status::unsupported);
    CHECK(u.entries.empty());
}

// --- middleware (SAM.2): the generic product adapter, ConstrainedPolicy::drop_source ---

namespace {
constexpr ConstrainedPolicy kDropPolicy = ConstrainedPolicy::drop_source;

// REAL-CAPTURE-shaped row (IBM MQ 9.4.5.0 registered install; the leg reports VRM, 9.4.5):
// <id>|<title>|<name>|<version or ->|<install_path>|<edition or ->
constexpr const char* kMqRow = "ibm_mq|IBM MQ|Installation1|9.4.5|/opt/mqm|-";

AdaptedRows bind_mq(const std::string& s) { return parse_middleware_output(s, "ibm_mq", kDropPolicy); }

SyncPluginMap with_middleware() {
    SyncPluginMap m = all_plugins();
    m["middleware"] = &kFakeMiddleware;
    return m;
}

std::size_t count_source(const std::string& blob, std::string_view source) {
    std::size_t n = 0;
    for (const auto& rec : records_of(blob))
        if (fields_of(rec)[15] == source)
            ++n;
    return n;
}
} // namespace

TEST_CASE("middleware adapter: a row maps to the product table's entry",
          "[sync][parse][adapter][middleware]") {
    CHECK(show(bind_mq(nl({st("ibm_mq", "supported", "-"), kMqRow}))) ==
          res("ok", "", {entry_of("IBM MQ", "9.4.5", "IBM", "app", "ibm_mq")}));
    // `-` is the wire spelling of "no version": the honest-empty field is the empty string.
    CHECK(show(bind_mq(nl({st("ibm_mq", "supported", "-"),
                           "ibm_mq|IBM MQ|Installation2|-|/opt/mqm2|-"}))) ==
          res("ok", "", {entry_of("IBM MQ", "", "IBM", "app", "ibm_mq")}));
    // the edition column is not carried
    CHECK(show(bind_mq(nl({st("ibm_mq", "supported", "-"),
                           "ibm_mq|IBM MQ|Installation3|9.3.5.0|/opt/mqm3|Advanced"}))) ==
          res("ok", "", {entry_of("IBM MQ", "9.3.5.0", "IBM", "app", "ibm_mq")}));
    // two installations are two entries
    CHECK(bind_mq(nl({st("ibm_mq", "supported", "-"), kMqRow,
                      "ibm_mq|IBM MQ|Installation2|9.3.5.0|/opt/mqm2|-"}))
              .entries.size() == 2);
    // zero rows + supported is a legitimate "none installed"
    CHECK(show(bind_mq(nl({st("ibm_mq", "supported", "-")}))) == res("ok", ""));
}

TEST_CASE("middleware adapter: an action that is not in the product table fails",
          "[sync][parse][adapter][middleware]") {
    CHECK(show(parse_middleware_output(nl({st("nope", "supported", "-"), "nope|IBM MQ|n|1|/p|-"}),
                                       "nope", kDropPolicy)) ==
          res("failed", "unknown middleware product"));
    CHECK(show(parse_middleware_output("", "", kDropPolicy)) ==
          res("failed", "unknown middleware product"));
}

TEST_CASE("middleware adapter: a row is accepted only when its title equals the table title",
          "[sync][parse][adapter][middleware]") {
    const std::string good = kMqRow;
    CHECK(show(bind_mq(nl({st("ibm_mq", "supported", "-"), good}))) ==
          res("ok", "", {entry_of("IBM MQ", "9.4.5", "IBM", "app", "ibm_mq")}));
    for (const char* title : {"-", "", "ibm mq", "IBM MQ ", " IBM MQ", "IBM  MQ", "Oracle"}) {
        INFO("title=[" << title << "]");
        const std::string bad = std::string("ibm_mq|") + title + "|InstallationX|1.0|/opt/x|-";
        // dropped, siblings kept, the source stays ok
        CHECK(show(bind_mq(nl({st("ibm_mq", "supported", "-"), bad, good, bad}))) ==
              res("ok", "", {entry_of("IBM MQ", "9.4.5", "IBM", "app", "ibm_mq")}));
        CHECK(show(bind_mq(nl({st("ibm_mq", "supported", "-"), bad}))) == res("ok", ""));
        // dropped rows are COUNTED (seen, not mapped): under keep_rows_if_present_seen a
        // constrained answer holding only such rows is kept, not failed
        CHECK(show(parse_middleware_output(nl({st("ibm_mq", "constrained", "tok"), bad}), "ibm_mq",
                                           ConstrainedPolicy::keep_rows_if_present_seen)) ==
              res("ok", "tok"));
    }
}

TEST_CASE("middleware adapter: an escaped pipe in a free-text field is one field and not two",
          "[sync][parse][adapter][middleware]") {
    // safe_output_field writes a literal '|' as `\|`; a raw-pipe split would see seven tokens
    // and silently drop the row although the status is supported.
    CHECK(show(bind_mq(nl({st("ibm_mq", "supported", "-"),
                           "ibm_mq|IBM MQ|Inst\\|1|9.4.5.0|/opt/mq\\|east|-"}))) ==
          res("ok", "", {entry_of("IBM MQ", "9.4.5.0", "IBM", "app", "ibm_mq")}));
    // an escaped pipe does not hide a real extra field: still seven tokens, still rejected
    CHECK(bind_mq(nl({st("ibm_mq", "supported", "-"), "ibm_mq|IBM MQ|I\\|1|9.4|/p|-|extra"}))
              .entries.empty());
}

TEST_CASE("middleware adapter: status grammar and row shape and the drop_source policy",
          "[sync][parse][adapter][middleware]") {
    const std::string bad = res("failed", "bad status");
    // bad or missing status fails the cycle (it is not a constrained answer)
    CHECK(show(bind_mq(nl({kMqRow}))) == bad);
    CHECK(show(bind_mq("")) == bad);
    CHECK(show(bind_mq(nl({"status|ibm_mq|supported", kMqRow}))) == bad);
    CHECK(show(bind_mq(nl({st("ibm_mq", "bogus", "-"), kMqRow}))) == bad);
    CHECK(show(bind_mq(nl({st("oracle", "supported", "-"), kMqRow}))) == bad);
    CHECK(show(bind_mq(nl({st("ibm_mq", "supported", "-"), st("ibm_mq", "supported", "-"), kMqRow}))) ==
          bad);
    // unsupported: skipped silently, zero entries, no reason
    CHECK(show(bind_mq(nl({st("ibm_mq", "unsupported", "macos:planned"), kMqRow}))) ==
          res("unsupported", ""));
    // constrained under drop_source: zero entries, reason = the tokens, status withheld --
    // with rows, without rows, and with a row the adapter would not even see
    const std::string tok = "linux:middleware:mqinst_ini:permission_denied";
    CHECK(show(bind_mq(nl({st("ibm_mq", "constrained", tok), kMqRow}))) == res("withheld", tok));
    CHECK(show(bind_mq(nl({st("ibm_mq", "constrained", tok)}))) == res("withheld", tok));
    CHECK(show(bind_mq(nl({st("ibm_mq", "constrained", tok), "garbage"}))) == res("withheld", tok));
    CHECK(show(bind_mq(crlf(nl({st("ibm_mq", "constrained", tok), kMqRow})))) ==
          res("withheld", tok));
    // row shape: only exactly six tokens with this action's tag are rows
    const std::string r = kMqRow;
    CHECK(bind_mq(nl({st("ibm_mq", "supported", "-"), r + "|extra"})).entries.empty()); // 7 tokens
    CHECK(bind_mq(nl({st("ibm_mq", "supported", "-"), r.substr(0, r.rfind('|'))})).entries.empty()); // 5
    CHECK(bind_mq(nl({st("ibm_mq", "supported", "-"), "oracle" + r.substr(6)})).entries.empty());
    // over-wide rows (more than the splitter's ten tokens) are rejected, never truncated
    CHECK(bind_mq(nl({st("ibm_mq", "supported", "-"), r + "|1|2|3|4|5|6|7"})).entries.empty());
    // the policy is the only difference: the same constrained answer fails under `fail`
    CHECK(show(parse_middleware_output(nl({st("ibm_mq", "constrained", "tok"), kMqRow}), "ibm_mq",
                                       kFailPolicy)) == res("failed", "tok"));
}

TEST_CASE("collector: middleware.ibm_mq publishes its mapped fields; a withheld one contributes "
          "nothing and the cycle continues",
          "[sync][collector][middleware]") {
    SECTION("a supported answer publishes IBM MQ with source middleware.ibm_mq") {
        fake_windows();
        g_fake[5].out["ibm_mq"] = nl({st("ibm_mq", "supported", "-"), kMqRow});
        auto src = make_installed_software_source(with_middleware());
        const auto got = src.collect();
        REQUIRE(got.has_value());
        CHECK(count_source(got->first, "middleware.ibm_mq") == 1);
        CHECK(count_source(got->first, "msi_packages.list_inventory") > 0);
        for (const auto& rec : records_of(got->first)) {
            const auto f = fields_of(rec);
            if (f[15] != "middleware.ibm_mq")
                continue;
            CHECK(f[0] == "IBM MQ");
            CHECK(f[1] == "9.4.5");
            CHECK(f[2] == "IBM");
            CHECK(f[4] == "app");
            CHECK(f[5] == "ibm_mq");
        }
    }
    SECTION("a constrained answer is withheld: the blob equals the no-middleware baseline") {
        fake_windows();
        const auto baseline = collect_with(all_plugins());
        REQUIRE(baseline.has_value());
        g_fake[5].out["ibm_mq"] = nl({st("ibm_mq", "constrained", "linux:middleware:mqinst_ini:permission_denied"),
                                      kMqRow});
        // the typed answer a constrained read carries; a withheld source never reaches the
        // PARTIAL check, so the cycle is not skipped for it
        g_fake[5].result_status["ibm_mq"] = {YUZU_RESULT_STATUS_CONSTRAINED,
                                             YUZU_RESULT_COMPLETENESS_PARTIAL,
                                             "linux:middleware:mqinst_ini:permission_denied"};
        auto src = make_installed_software_source(with_middleware());
        const auto got = src.collect();
        REQUIRE(got.has_value());
        CHECK(got->second == baseline->second); // identical hash: nothing from middleware
        CHECK(got->first == baseline->first);
        REQUIRE(src.skip_reason);
        CHECK(src.skip_reason().empty());
    }
    SECTION("an unsupported answer contributes nothing and the cycle continues") {
        fake_windows();
        const auto baseline = collect_with(all_plugins());
        REQUIRE(baseline.has_value());
        g_fake[5].out["ibm_mq"] = nl({st("ibm_mq", "unsupported", "macos:planned")});
        const auto got = collect_with(with_middleware());
        REQUIRE(got.has_value());
        CHECK(got->first == baseline->first);
    }
    SECTION("a failing source still skips the cycle beside a healthy middleware") {
        fake_windows();
        g_fake[5].out["ibm_mq"] = nl({st("ibm_mq", "supported", "-"), kMqRow});
        g_fake[3].out["list_inventory"] = "status|list_inventory|constrained|windows:msi_enum:5\n";
        auto src = make_installed_software_source(with_middleware());
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason() == "msi_packages.list_inventory:windows:msi_enum:5");
    }
    SECTION("a malformed middleware status is a failure and not a withheld source") {
        fake_windows();
        g_fake[5].out["ibm_mq"] = nl({kMqRow}); // no status row
        auto src = make_installed_software_source(with_middleware());
        CHECK_FALSE(src.collect().has_value());
        CHECK(src.skip_reason() == "middleware.ibm_mq:bad status");
    }
    SECTION("a middleware rc != 0 skips the cycle") {
        fake_windows();
        g_fake[5].out["ibm_mq"] = nl({st("ibm_mq", "supported", "-")});
        g_fake[5].rc["ibm_mq"] = 1;
        CHECK_FALSE(collect_with(with_middleware()).has_value());
    }
}

TEST_CASE("collector: populated -> constrained -> recovered middleware cycles",
          "[sync][collector][middleware]") {
    // Each cycle replaces the agent's whole stored inventory server-side, so a constrained cycle
    // must publish the no-middleware blob (the IBM MQ rows go away) and recovery must restore it.
    fake_windows();
    const auto baseline = collect_with(all_plugins());
    REQUIRE(baseline.has_value());
    // No log assertions: the collector lives in libyuzu_agent_core, whose spdlog registry is a
    // separate image from this binary's on macOS (test_log_capture.hpp, #3355), so a capture here
    // would pass or fail by platform. The withheld status and reason are pinned at the adapter
    // level above (parse_middleware_output); this case pins the published blob.
    const auto populated = [] {
        g_fake[5].out["ibm_mq"] = nl({st("ibm_mq", "supported", "-"), kMqRow});
        g_fake[5].result_status.erase("ibm_mq");
    };

    populated();
    const auto c1 = collect_with(with_middleware());
    REQUIRE(c1.has_value());
    CHECK(count_source(c1->first, "middleware.ibm_mq") == 1);
    CHECK(c1->second != baseline->second);

    g_fake[5].out["ibm_mq"] = nl({st("ibm_mq", "constrained", "linux:middleware:mqinst_ini:permission_denied")});
    const auto c2 = collect_with(with_middleware());
    REQUIRE(c2.has_value());
    CHECK(count_source(c2->first, "middleware.ibm_mq") == 0);
    CHECK(c2->second == baseline->second);
    CHECK(c2->first == baseline->first);
    CHECK(count_source(c2->first, "msi_packages.list_inventory") > 0); // the other sources stayed

    populated();
    const auto c3 = collect_with(with_middleware());
    REQUIRE(c3.has_value());
    CHECK(c3->second == c1->second);
    CHECK(c3->first == c1->first);
}

// --- the REAL runner's output through the collector (data faults keep their siblings) ---

namespace {
namespace mwr = yuzu::middleware;

/// A minimal in-memory Fs for the generic middleware runner: one scripted read of the enumerator
/// file, every installation directory absent (versions stay `-`: this case is about rows, not
/// versions).
struct MwFakeFs {
    mwr::Read ini;
    mwr::Read read_abs(std::string_view, std::size_t) { return ini; }
    mwr::Listing list_under(std::string_view, std::string_view) {
        return mwr::Listing{{}, false, false, mwr::Read::Outcome::absent};
    }
    bool exhausted() const { return false; }
    std::string_view os() const { return "linux"; }
};

/// What the real ibm_mq Linux leg writes for `fs`: the composed rows (status row first), one per line.
std::string run_ibm_mq(MwFakeFs& fs) {
    const mwr::Product& p = *mwr::find_product("ibm_mq");
    yuzu::shared::ConstraintAccumulator acc;
    auto budget = mwr::make_row_budget();
    const auto data = mwr::run_leg(p, p.linux, fs, acc, budget,
                                   [](std::string_view, std::string_view, mwr::ItemReason,
                                      std::string_view) {});
    std::string out;
    for (const auto& row : mwr::compose_output(p.id, data, acc))
        out += row + "\n";
    return out;
}

constexpr const char* kBrokenStanza = "Installation:\n   Name=Broken\n";
constexpr const char* kGoodStanza = "Installation:\n   Name=Installation1\n   FilePath=/opt/mqm\n";
} // namespace

TEST_CASE("collector: a malformed mqinst.ini stanza beside a valid one still publishes IBM MQ",
          "[sync][collector][middleware]") {
    fake_windows();
    const auto baseline = collect_with(all_plugins());
    REQUIRE(baseline.has_value());
    const std::string denied = "linux:middleware:mqinst_ini:permission_denied";

    SECTION("a dropped stanza and a valid sibling: supported, the sibling's row is published") {
        MwFakeFs fs;
        fs.ini = {mwr::Read::Outcome::ok, std::string{kBrokenStanza} + kGoodStanza};
        const std::string out = run_ibm_mq(fs);
        REQUIRE(out.starts_with("status|ibm_mq|supported|-\n"));
        // the adapter keeps the answer (not withheld) and maps the one row
        CHECK(show(bind_mq(out)) == res("ok", "", {entry_of("IBM MQ", "", "IBM", "app", "ibm_mq")}));

        g_fake[5].out["ibm_mq"] = out; // no typed status: the leg declares OK/FULL
        const auto got = collect_with(with_middleware());
        REQUIRE(got.has_value());
        CHECK(count_source(got->first, "middleware.ibm_mq") == 1);
        CHECK(got->second != baseline->second);
    }
    SECTION("every stanza dropped: constrained, malformed, withheld (never an empty supported)") {
        MwFakeFs fs;
        fs.ini = {mwr::Read::Outcome::ok, kBrokenStanza};
        const std::string out = run_ibm_mq(fs);
        const std::string token = "linux:middleware:mqinst_ini:malformed";
        REQUIRE(out == "status|ibm_mq|constrained|" + token + "\n");
        CHECK(show(bind_mq(out)) == res("withheld", token));

        g_fake[5].out["ibm_mq"] = out;
        g_fake[5].result_status["ibm_mq"] = {YUZU_RESULT_STATUS_CONSTRAINED,
                                             YUZU_RESULT_COMPLETENESS_PARTIAL, token};
        const auto got = collect_with(with_middleware());
        REQUIRE(got.has_value());
        CHECK(count_source(got->first, "middleware.ibm_mq") == 0);
        CHECK(got->second == baseline->second);
    }
    SECTION("positive control: a permission fault on the same file still withholds the source") {
        MwFakeFs fs;
        fs.ini = {mwr::Read::Outcome::denied, {}};
        const std::string out = run_ibm_mq(fs);
        REQUIRE(out == "status|ibm_mq|constrained|" + denied + "\n");
        CHECK(show(bind_mq(out)) == res("withheld", denied));

        g_fake[5].out["ibm_mq"] = out;
        g_fake[5].result_status["ibm_mq"] = {YUZU_RESULT_STATUS_CONSTRAINED,
                                             YUZU_RESULT_COMPLETENESS_PARTIAL, denied};
        const auto got = collect_with(with_middleware());
        REQUIRE(got.has_value());
        CHECK(count_source(got->first, "middleware.ibm_mq") == 0);
        CHECK(got->second == baseline->second);
    }
}

TEST_CASE("middleware adapter: the leg's own escaped rows round-trip through the adapter",
          "[sync][parse][adapter][middleware]") {
    // mw::format_row (the leg) and the collector's escape-aware split are two implementations of one
    // grammar. A pipe in the installation name or path must leave the row six fields wide, so the
    // entry is the one a plain name and path would give. Hand-written escaped literals (the case
    // above) cannot catch the leg's writer drifting from the collector's reader.
    const std::string plain = mwr::format_row("ibm_mq", "IBM MQ", "Installation1", "9.4.5", "/opt/mqm", "");
    const std::string piped = mwr::format_row("ibm_mq", "IBM MQ", "Inst|1", "9.4.5", "/opt/mq|east", "");
    const std::string tricky = mwr::format_row("ibm_mq", "IBM MQ", "a\\|b", "9.4.5", "C:\\mq\\|x", "");
    REQUIRE(piped.find("\\|") != std::string::npos); // the pipe really was escaped on the wire
    const AdaptedRows want = bind_mq(nl({st("ibm_mq", "supported", "-"), plain}));
    REQUIRE(want.entries.size() == 1);
    for (const std::string* row : {&piped, &tricky}) {
        CAPTURE(*row);
        const AdaptedRows got = bind_mq(nl({st("ibm_mq", "supported", "-"), *row}));
        CHECK(show(got) == show(want));
    }
}

TEST_CASE("middleware adapter and collector: a leg row built from NUL-bearing installer text still maps",
          "[sync][parse][adapter][collector][middleware]") {
    // mw::format_row scrubs a NUL to '?' (scrub_wire_bytes), so the row reaches the collector whole.
    // Unscrubbed, the plugin ABI's C string would end the row at the NUL while the status row stays
    // `supported`; the adapter then rejects the short row and the source's stored rows are erased.
    const std::string row = mwr::format_row("ibm_mq", "IBM MQ", std::string{"In\0st", 5}, "9.4.5",
                                            std::string{"/opt/m\0qm", 9}, "");
    REQUIRE(row.find('\0') == std::string::npos);
    const std::string out = nl({st("ibm_mq", "supported", "-"), row});
    CHECK(show(bind_mq(out)) == res("ok", "", {entry_of("IBM MQ", "9.4.5", "IBM", "app", "ibm_mq")}));

    fake_windows();
    g_fake[5].out["ibm_mq"] = out;
    const auto got = collect_with(with_middleware());
    REQUIRE(got.has_value());
    CHECK(count_source(got->first, "middleware.ibm_mq") == 1);
}

TEST_CASE("collector: one drop_source source withheld does not touch the other",
          "[sync][collector][runtimes][middleware]") {
    // python and ibm_mq both withhold on a CONSTRAINED answer (each its own `continue` in the
    // collector loop). Withholding one must leave the other's rows in the blob, in both directions.
    const std::string python_row = "python|cpython|3.13.1|/Library/Frameworks/Python.framework/Versions/3.13|org.python.python";
    const std::string tok = "linux:middleware:mqinst_ini:permission_denied";
    const auto constrain = [](std::size_t slot, const char* action, const std::string& token) {
        g_fake[slot].result_status[action] = {YUZU_RESULT_STATUS_CONSTRAINED,
                                              YUZU_RESULT_COMPLETENESS_PARTIAL, token};
    };

    SECTION("python withheld, ibm_mq kept") {
        fake_mac();
        g_fake[4].out["python"] = nl({st("python", "constrained", "linux:runtimes:permission_denied"), python_row});
        constrain(4, "python", "linux:runtimes:permission_denied");
        g_fake[5].out["ibm_mq"] = nl({st("ibm_mq", "supported", "-"), kMqRow});
        const auto got = collect_with(with_middleware());
        REQUIRE(got.has_value());
        CHECK(count_source(got->first, "runtimes.python") == 0);
        CHECK(count_source(got->first, "middleware.ibm_mq") == 1);
    }
    SECTION("ibm_mq withheld, python kept") {
        fake_mac();
        g_fake[4].out["python"] = nl({supported_status("python"), python_row});
        g_fake[5].out["ibm_mq"] = nl({st("ibm_mq", "constrained", tok), kMqRow});
        constrain(5, "ibm_mq", tok);
        const auto got = collect_with(with_middleware());
        REQUIRE(got.has_value());
        CHECK(count_source(got->first, "runtimes.python") == 1);
        CHECK(count_source(got->first, "middleware.ibm_mq") == 0);
    }
}

// --- runtimes dotnet / jvm adapters (SAM-32) ---

TEST_CASE("runtimes dotnet and jvm: a constrained answer keeps its rows, and with none never deletes",
          "[sync][parse][adapter][runtimes]") {
    using Status = AdaptedRows::Status;
    const std::string tok = "windows:runtimes:jvm:release_unreadable";
    // Constrained WITH a row: the row is kept (status ok, reason = the token).
    CHECK(show(parse_runtimes_jvm_output(
              nl({st("jvm", "constrained", tok), "jvm|jdk|17|/x|Acme"}), kKeepPolicy)) ==
          res("ok", tok, {entry_of("Java JDK", "17", "Acme", "app", "jvm")}));
    CHECK(show(parse_runtimes_dotnet_output(
              nl({st("dotnet", "constrained", tok), "dotnet|runtime|8.0.1|/p|Microsoft"}),
              kKeepPolicy)) ==
          res("ok", tok, {entry_of(".NET Runtime", "8.0.1", "Microsoft", "app", "dotnet")}));
    // Constrained with NO row: failed (the collector skips the cycle, so stored rows stay), never
    // withheld (which would delete them) and never an ok-and-empty answer.
    for (const char* a : {"jvm", "dotnet"}) {
        const auto parse = std::string(a) == "jvm" ? parse_runtimes_jvm_output
                                                   : parse_runtimes_dotnet_output;
        for (const auto& out : {nl({st(a, "constrained", tok)}),
                                nl({st(a, "constrained", tok), "garbage|row"})}) {
            const auto r = parse(out, kKeepPolicy);
            CHECK(r.status == Status::failed);
            CHECK(r.entries.empty());
            CHECK(r.reason == tok);
        }
    }
}

TEST_CASE("collector: a constrained dotnet/jvm answer keeps its rows; with none the cycle is skipped",
          "[sync][collector][runtimes]") {
    // The real leg types the answer CONSTRAINED + PARTIAL; the table row opts in to PARTIAL.
    const auto constrain_leg = [](const char* action) {
        g_fake[4].result_status[action] = {YUZU_RESULT_STATUS_CONSTRAINED,
                                           YUZU_RESULT_COMPLETENESS_PARTIAL, "tok"};
    };
    struct Leg {
        const char* a;
        const char* row;
        const char* src_name;
    };
    const Leg legs[] = {
        {"dotnet", "dotnet|runtime|8.0.33|C:/Program Files/dotnet/|Microsoft", "runtimes.dotnet"},
        {"jvm", "jvm|jdk|21.0.12.1|C:/Program Files/Microsoft/jdk/|Microsoft", "runtimes.jvm"}};
    for (const auto& leg : legs) {
        const char* const a = leg.a;
        const char* const row = leg.row;
        const char* const src_name = leg.src_name;
        INFO(a);
        const auto count = [&](const std::string& blob) {
            std::size_t n = 0;
            for (const auto& rec : records_of(blob))
                if (fields_of(rec).at(15) == src_name)
                    ++n;
            return n;
        };
        SECTION(std::string(a) + " constrained with a row: the row is in the blob") {
            fake_mac();
            g_fake[4].out[a] = nl({st(a, "constrained", "tok"), row});
            constrain_leg(a);
            const auto got = collect_with(all_plugins());
            REQUIRE(got.has_value());
            CHECK(count(got->first) == 1);
        }
        SECTION(std::string(a) + " constrained with no row: the cycle is skipped, not a delete") {
            fake_mac();
            g_fake[4].out[a] = nl({st(a, "constrained", "tok")});
            constrain_leg(a);
            auto src = make_installed_software_source(all_plugins());
            CHECK_FALSE(src.collect().has_value());
            CHECK(src.skip_reason() == std::string("runtimes.") + a + ":tok");
        }
    }
}

TEST_CASE("runtimes dotnet adapter: rows from all three OS legs map to .NET / app / dotnet",
          "[sync][parse][adapter][runtimes]") {
    using Status = AdaptedRows::Status;
    // Windows rows from the kingsley capture (registry runtime rows), a Windows .NET Framework and SDK
    // row (flavours netfx / sdk; no SDK was installed on the host, so those two are synthetic), a
    // Linux directory-walk row (flavour core, vendor `-`) and a macOS Microsoft-installer row.
    const auto r = parse_runtimes_dotnet_output(
        nl({"status|dotnet|supported|-",
            "dotnet|runtime|8.0.33|C:/Program Files/dotnet/|Microsoft",
            "dotnet|runtime|9.0.22|C:/Program Files/dotnet/|Microsoft",
            "dotnet|sdk|9.0.100|C:/Program Files/dotnet/|Microsoft",
            "dotnet|netfx|4.8.1|-|Microsoft",
            "dotnet|core|8.0.31|/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.31|-",
            "dotnet|sdk|8.0.404|/usr/local/share/dotnet/sdk/8.0.404|-",
            "dotnet|unmodelled|7.0.1|/usr/share/dotnet/shared/Other.App/7.0.1|-",
            "dotnet|runtime|-|-|-"}),
        kFailPolicy);
    REQUIRE(r.status == Status::ok);
    CHECK(show(r) ==
          res("ok", "",
              {entry_of(".NET Runtime", "8.0.33", "Microsoft", "app", "dotnet"),
               entry_of(".NET Runtime", "9.0.22", "Microsoft", "app", "dotnet"),
               entry_of(".NET SDK", "9.0.100", "Microsoft", "app", "dotnet"),
               entry_of(".NET Framework", "4.8.1", "Microsoft", "app", "dotnet"),
               entry_of(".NET Runtime", "8.0.31", "Microsoft", "app", "dotnet"),
               entry_of(".NET SDK", "8.0.404", "Microsoft", "app", "dotnet"),
               entry_of(".NET", "7.0.1", "Microsoft", "app", "dotnet"),
               entry_of(".NET Runtime", "", "Microsoft", "app", "dotnet")}));
}

TEST_CASE("runtimes jvm adapter: rows from all three OS legs map to Java / app / jvm",
          "[sync][parse][adapter][runtimes]") {
    using Status = AdaptedRows::Status;
    // The Microsoft row is the kingsley capture (release IMPLEMENTOR). The Temurin Windows row is
    // synthetic: its release file was not read in the capture, the vendor is the Uninstall publisher.
    // The Linux row is the measured Temurin container home; the macOS row is a fixture-tree shape
    // (no JDK is installed on the development Mac).
    const auto r = parse_runtimes_jvm_output(
        nl({"status|jvm|supported|-",
            "jvm|jdk|21.0.12.1|C:/Program Files/Microsoft/jdk-21.0.12.101-hotspot/|Microsoft",
            "jvm|jdk|21.0.13|C:/Program Files/Temurin/|Eclipse Adoptium",
            "jvm|jdk|17.0.20|/opt/java/openjdk|Eclipse Adoptium",
            "jvm|jre|11.0.2|/Library/Java/JavaVirtualMachines/x.jdk|Oracle Corporation",
            "jvm|unmodelled|-|/usr/lib/jvm/java-8-openjdk-amd64|-"}),
        kFailPolicy);
    REQUIRE(r.status == Status::ok);
    CHECK(show(r) ==
          res("ok", "",
              {entry_of("Java JDK", "21.0.12.1", "Microsoft", "app", "jvm"),
               entry_of("Java JDK", "21.0.13", "Eclipse Adoptium", "app", "jvm"),
               entry_of("Java JDK", "17.0.20", "Eclipse Adoptium", "app", "jvm"),
               entry_of("Java JRE", "11.0.2", "Oracle Corporation", "app", "jvm"),
               entry_of("Java", "", "", "app", "jvm")}));
}

TEST_CASE("runtimes dotnet and jvm adapters: producer rows round-trip; bad shapes and statuses",
          "[sync][parse][adapter][runtimes]") {
    using Status = AdaptedRows::Status;
    // A vendor with a literal pipe is escaped by the producer; width stays five logical fields.
    const auto row = yuzu::runtimes::format_runtime_row("jvm", "jdk", "17.0.1", "/opt/j", "A|B");
    REQUIRE(row == "jvm|jdk|17.0.1|/opt/j|A\\|B");
    const auto r = parse_runtimes_jvm_output(nl({"status|jvm|supported|-", row}), kFailPolicy);
    REQUIRE(r.status == Status::ok);
    REQUIRE(r.entries.size() == 1);
    CHECK(r.entries[0].version == "17.0.1");
    // malformed width and another action's tag are dropped, the status keeps the cycle ok
    const auto d = parse_runtimes_dotnet_output(
        nl({"status|dotnet|supported|-", "dotnet|runtime|8.0.1|/p", "jvm|jdk|17|/x|-",
            "dotnet|runtime|8.0.1|/p|Microsoft|extra"}),
        kFailPolicy);
    REQUIRE(d.status == Status::ok);
    CHECK(d.entries.empty());
    // status grammar: a status row for the wrong action fails; constrained is withheld under
    // drop_source (the adapter still honours it for any caller); unsupported is skipped.
    CHECK(parse_runtimes_dotnet_output(nl({"status|jvm|supported|-"}), kFailPolicy).status ==
          Status::failed);
    CHECK(show(parse_runtimes_jvm_output(
              nl({"status|jvm|constrained|windows:runtimes:jvm_reg:access_denied",
                  "jvm|jdk|17|/x|Acme"}),
              ConstrainedPolicy::drop_source)) ==
          res("withheld", "windows:runtimes:jvm_reg:access_denied"));
    const auto u = parse_runtimes_dotnet_output(nl({"status|dotnet|unsupported|macos:planned"}), kFailPolicy);
    CHECK(u.status == Status::unsupported);
    CHECK(u.entries.empty());
}

// ---------------------------------------------------------------------------
// SAM-19: delay_max on request_now, source lists, maintenance windows, catch-up.
// ---------------------------------------------------------------------------

namespace {

// UTC as the "local" zone: deterministic and DST-free (the DST edges are pinned in
// test_sync_window.cpp). from_local normalises an out-of-range day like mktime does.
yuzu::agent::LocalClock utc_clock() {
    namespace c = std::chrono;
    yuzu::agent::LocalClock clock;
    clock.to_local = [](std::int64_t t) {
        const c::sys_seconds tp{c::seconds{t}};
        const c::sys_days d = c::floor<c::days>(tp);
        const c::year_month_day ymd{d};
        const c::hh_mm_ss<c::seconds> hms{tp - d};
        std::tm l{};
        l.tm_year = static_cast<int>(ymd.year()) - 1900;
        l.tm_mon = static_cast<int>(static_cast<unsigned>(ymd.month())) - 1;
        l.tm_mday = static_cast<int>(static_cast<unsigned>(ymd.day()));
        l.tm_hour = static_cast<int>(hms.hours().count());
        l.tm_min = static_cast<int>(hms.minutes().count());
        l.tm_sec = static_cast<int>(hms.seconds().count());
        return l;
    };
    clock.from_local = [](const std::tm& l) {
        const c::sys_days d = c::sys_days{c::year{l.tm_year + 1900} /
                                          c::month{static_cast<unsigned>(l.tm_mon + 1)} / 1} +
                              c::days{l.tm_mday - 1};
        return static_cast<std::int64_t>(
            c::duration_cast<c::seconds>(d.time_since_epoch() + c::hours{l.tm_hour} +
                                         c::minutes{l.tm_min} + c::seconds{l.tm_sec})
                .count());
    };
    return clock;
}

struct Sam19Rig {
    std::map<std::string, std::string> kv;
    int calls{0};
    bool last_had_blob{false};
    std::map<std::string, int> collects; // per source
    std::unique_ptr<SyncScheduler> sched;

    Sam19Rig() { reset_scheduler(); }

    void reset_scheduler() { // a "restart": new scheduler over the same persisted KV
        sched = std::make_unique<SyncScheduler>(
            "agent-sam19",
            [this](const std::string& k) {
                auto it = kv.find(k);
                return it == kv.end() ? std::string{} : it->second;
            },
            [this](const std::string& k, const std::string& v) { kv[k] = v; },
            [this](const std::vector<std::pair<std::string, std::string>>&,
                   const std::vector<std::pair<std::string, std::string>>& blobs)
                -> std::optional<std::vector<std::string>> {
                ++calls;
                last_had_blob = !blobs.empty();
                return std::vector<std::string>{};
            },
            utc_clock());
    }

    void add(const std::string& name, std::optional<yuzu::agent::SyncWindow> window = {},
             bool skips = false) {
        SyncSource src;
        src.name = name;
        src.interval = std::chrono::seconds{86400};
        src.window = window;
        src.skip_backoff = skips;
        src.collect = [this, name, skips]() -> std::optional<std::pair<std::string, std::string>> {
            ++collects[name];
            if (skips)
                return std::nullopt;
            return std::make_pair(std::string{"blob"}, std::string{"hash"});
        };
        sched->add_source(src);
    }

    std::int64_t next_fire(const std::string& name) const {
        return std::stoll(kv.at("sync." + name + ".next_fire"));
    }
};

constexpr std::int64_t kNoon = 1'781'092'800; // 2026-06-10 12:00:00Z
int utc_minutes(std::int64_t t) {
    const auto l = utc_clock().to_local(t);
    return l.tm_hour * 60 + l.tm_min;
}

} // namespace

TEST_CASE("SAM-19: request_now(delay_max) arms a stable spread and fires in a later tick",
          "[sync][scheduler][sam19]") {
    Sam19Rig r;
    r.add("a");
    r.sched->tick(kNoon);
    r.sched->tick(kNoon + 700); // first send
    REQUIRE(r.calls == 1);

    const std::int64_t t0 = kNoon + 5000;
    auto armed = r.sched->request_now("a", std::chrono::seconds{600});
    REQUIRE(armed == std::vector<std::string>{"a"});
    r.sched->tick(t0);
    const std::int64_t due = r.next_fire("a");
    REQUIRE(due > t0); // this agent's offset is non-zero, so it does not fire in the same tick
    REQUIRE(due < t0 + 600);
    CHECK(r.calls == 1);
    CHECK(r.kv.at("sync.a.force_full") == "1");

    r.sched->tick(due);
    CHECK(r.calls == 2);
    CHECK(r.last_had_blob); // force_full carried through the delayed path

    // Stable: the same request a day later spreads by the same offset.
    const std::int64_t t1 = due + 86400;
    (void)r.sched->request_now("a", std::chrono::seconds{600});
    r.sched->tick(t1);
    CHECK(r.next_fire("a") - t1 == due - t0);
}

TEST_CASE("SAM-19: a source requested twice keeps the smaller delay", "[sync][scheduler][sam19]") {
    for (bool delayed_first : {true, false}) {
        Sam19Rig r;
        r.add("a");
        r.sched->tick(kNoon);
        r.sched->tick(kNoon + 700);
        REQUIRE(r.calls == 1);
        if (delayed_first) {
            (void)r.sched->request_now("a", std::chrono::seconds{600});
            (void)r.sched->request_now("a");
        } else {
            (void)r.sched->request_now("a");
            (void)r.sched->request_now("a", std::chrono::seconds{600});
        }
        r.sched->tick(kNoon + 5000);
        INFO("delayed_first=" << delayed_first);
        CHECK(r.calls == 2); // immediate wins in both orders
    }
}

TEST_CASE("SAM-19: request_now takes a source list, all-or-nothing", "[sync][scheduler][sam19]") {
    Sam19Rig r;
    r.add("a");
    r.add("b");
    r.add("c");
    r.sched->tick(kNoon);
    r.sched->tick(kNoon + 700); // all three first-sent in one batch
    REQUIRE(r.calls == 1);
    const auto before = r.collects;

    SECTION("a list arms each name, reported in registration order") {
        auto armed = r.sched->request_now("c,a");
        CHECK(armed == std::vector<std::string>{"a", "c"});
        r.sched->tick(kNoon + 5000);
        CHECK(r.collects["a"] == before.at("a") + 1);
        CHECK(r.collects["c"] == before.at("c") + 1);
        CHECK(r.collects["b"] == before.at("b"));
    }
    SECTION("one unknown name arms nothing and returns empty") {
        CHECK(r.sched->request_now("a,zzz").empty());
        CHECK(r.sched->request_now("zzz,a").empty());
        CHECK(r.sched->request_now("a,").empty());
        CHECK(r.sched->request_now(",a").empty());
        CHECK(r.sched->request_now("").empty());
        r.sched->tick(kNoon + 5000);
        CHECK(r.collects == before);
    }
    SECTION("a duplicated name is armed once") {
        CHECK(r.sched->request_now("a,a") == std::vector<std::string>{"a"});
    }
}

TEST_CASE("SAM-19: a windowed source lands every sync inside its window",
          "[sync][scheduler][sam19]") {
    Sam19Rig r;
    r.add("w", yuzu::agent::SyncWindow{60, 300});
    r.sched->tick(kNoon);
    r.sched->tick(kNoon + 700); // first send at 12:11
    REQUIRE(r.calls == 1);
    const std::int64_t first = r.next_fire("w");
    CHECK(first > kNoon + 700);
    CHECK(first <= kNoon + 700 + 86400);
    CHECK(utc_minutes(first) >= 60);
    CHECK(utc_minutes(first) < 300);

    r.sched->tick(first - 1); // not before the window moment
    CHECK(r.calls == 1);
    r.sched->tick(first);
    CHECK(r.calls == 2);
    const std::int64_t second = r.next_fire("w");
    CHECK(second - first == 86400); // the same moment tomorrow
}

TEST_CASE("SAM-19: a windowed source's skip ladder is capped at the window fire",
          "[sync][scheduler][sam19]") {
    Sam19Rig r;
    const std::int64_t now = kNoon + 10 * 3600; // 22:00Z
    r.kv["sync.w.next_fire"] = std::to_string(now);
    r.kv["sync.w.skip_streak"] = "3"; // the next skip is streak 4: a plain 8 h delay = 06:00
    r.kv["sync.w.last_skip"] = "x";
    r.add("w", yuzu::agent::SyncWindow{60, 300}, /*skips=*/true);
    r.sched->tick(now);
    REQUIRE(r.collects["w"] == 1);
    const std::int64_t nf = r.next_fire("w");
    CHECK(nf >= now + 3 * 3600); // not before 01:00
    CHECK(nf < now + 7 * 3600);  // capped under the 06:00 an 8 h backoff would give
    CHECK(utc_minutes(nf) >= 60);
    CHECK(utc_minutes(nf) < 300);
}

TEST_CASE("SAM-19: a source without a window keeps its phase-slot cadence",
          "[sync][scheduler][sam19]") {
    Sam19Rig r;
    r.add("p");
    r.sched->tick(kNoon);
    r.sched->tick(kNoon + 700);
    REQUIRE(r.calls == 1);
    const std::int64_t first = r.next_fire("p");
    CHECK(first > kNoon + 700);
    CHECK(first <= kNoon + 700 + 86400);
    r.sched->tick(first);
    CHECK(r.next_fire("p") - first == 86400); // slot-aligned: exactly one interval on
}

TEST_CASE("SAM-19: an overdue source is spread on restart and on resume, not fired at once",
          "[sync][scheduler][sam19]") {
    const std::int64_t later = kNoon + 3 * 86400;
    SECTION("restart: a fresh scheduler over state persisted days ago") {
        Sam19Rig r;
        r.add("a");
        r.sched->tick(kNoon);
        r.sched->tick(kNoon + 700);
        REQUIRE(r.calls == 1);

        r.reset_scheduler();
        r.add("a");
        r.sched->tick(later);
        CHECK(r.calls == 1);
        CHECK(r.next_fire("a") >= later);
        CHECK(r.next_fire("a") < later + SyncScheduler::kCatchUpWindow.count());
        r.sched->tick(r.next_fire("a"));
        CHECK(r.calls == 2);
    }
    SECTION("resume: the same scheduler ticked far past next_fire") {
        Sam19Rig r;
        r.add("a");
        r.sched->tick(kNoon);
        r.sched->tick(kNoon + 700);
        REQUIRE(r.calls == 1);

        r.sched->tick(later);
        CHECK(r.calls == 1);
        CHECK(r.next_fire("a") >= later);
        CHECK(r.next_fire("a") < later + SyncScheduler::kCatchUpWindow.count());
        r.sched->tick(r.next_fire("a"));
        CHECK(r.calls == 2);
    }
}

TEST_CASE("SAM-19: a delayed request_now still pending at a restart is re-armed by the catch-up "
          "spread and still sends a full report",
          "[sync][scheduler][sam19]") {
    Sam19Rig r;
    r.add("a");
    r.sched->tick(kNoon);
    r.sched->tick(kNoon + 700); // first send
    REQUIRE(r.calls == 1);

    const std::int64_t t0 = kNoon + 5000;
    REQUIRE(r.sched->request_now("a", std::chrono::seconds{600}) == std::vector<std::string>{"a"});
    r.sched->tick(t0); // persists the arm: next_fire in (t0, t0 + 600), force_full = 1
    const std::int64_t armed = r.next_fire("a");
    REQUIRE(armed > t0);
    REQUIRE(r.kv.at("sync.a.force_full") == "1");

    // The agent is back more than one clamped sleep after the armed moment.
    r.reset_scheduler();
    r.add("a");
    const std::int64_t reboot = armed + SyncScheduler::kMaxTickSeconds.count() + 1;
    r.sched->tick(reboot);
    CHECK(r.calls == 1); // not fired at once
    const std::int64_t rearmed = r.next_fire("a");
    CHECK(rearmed >= reboot); // the catch-up spread replaced the request's offset
    CHECK(rearmed < reboot + SyncScheduler::kCatchUpWindow.count());
    CHECK(r.kv.at("sync.a.force_full") == "1");

    r.last_had_blob = false; // an unforced second send would be hash-only (same hash, < 7 d)
    r.sched->tick(rearmed);
    CHECK(r.calls == 2);
    CHECK(r.last_had_blob); // force_full survived the restart and the re-arm
}

TEST_CASE("SAM-19: a persisted next_fire the agent could not have written is re-armed, not trusted",
          "[sync][scheduler][sam19]") {
    // A clock stepped back, a VM restore, or a corrupt KV value: the schedule is far in the
    // future (or saturated by strtoll) and, left alone, would stall the source until the wall
    // clock caught up.
    auto persist = [](Sam19Rig& r, const std::string& next_fire) {
        r.kv["sync.a.next_fire"] = next_fire;
        r.kv["sync.a.last_hash"] = "hash";
        r.kv["sync.a.last_full"] = std::to_string(kNoon);
        r.kv["sync.a.force_full"] = "0";
    };

    SECTION("a far-future next_fire is re-armed inside the catch-up window") {
        for (const std::string& far : {std::to_string(kNoon + 10 * 86400),
                                       std::to_string(kNoon + 2 * 86400 + 1)}) {
            Sam19Rig r;
            persist(r, far);
            r.add("a");
            r.sched->tick(kNoon);
            INFO("persisted next_fire=" << far);
            CHECK(r.calls == 0); // not at once
            CHECK(r.next_fire("a") >= kNoon);
            CHECK(r.next_fire("a") < kNoon + SyncScheduler::kCatchUpWindow.count());
            CHECK(r.kv.at("sync.a.last_hash") == "hash"); // only the schedule was corrected
            CHECK(r.kv.at("sync.a.force_full") == "0");

            r.sched->tick(r.next_fire("a")); // and it syncs once the spread offset passes
            CHECK(r.calls == 1);
            CHECK_FALSE(r.last_had_blob); // hash-only: unchanged, inside the weekly floor
        }
    }
    SECTION("a saturated value (strtoll clamps to LLONG_MIN / LLONG_MAX) does not overflow") {
        for (const char* saturated : {"-9223372036854775808", "9223372036854775807",
                                      "99999999999999999999", "-99999999999999999999"}) {
            Sam19Rig r;
            persist(r, saturated);
            r.add("a");
            r.sched->tick(kNoon);
            INFO("persisted next_fire=" << saturated);
            CHECK(r.calls == 0);
            CHECK(r.next_fire("a") >= kNoon);
            CHECK(r.next_fire("a") < kNoon + SyncScheduler::kCatchUpWindow.count());
        }
    }
    SECTION("a normally armed next_fire a day ahead is left alone") {
        Sam19Rig r;
        const std::int64_t tomorrow = kNoon + 86400;
        persist(r, std::to_string(tomorrow));
        r.add("a");
        r.sched->tick(kNoon);
        CHECK(r.calls == 0);
        CHECK(r.next_fire("a") == tomorrow); // not rewritten
    }
}

TEST_CASE("SAM-19: a repeated delayed request never pushes an earlier armed fire later",
          "[sync][scheduler][sam19]") {
    const std::int64_t t0 = kNoon + 5000;
    constexpr std::chrono::seconds kDelay{86400};

    // Persist `persisted_next_fire`, request a kDelay-delayed sync of "a" and run one tick at t0.
    auto request_at = [&](Sam19Rig& r, std::int64_t persisted_next_fire) {
        r.kv["sync.a.next_fire"] = std::to_string(persisted_next_fire);
        r.add("a");
        REQUIRE(r.sched->request_now("a", kDelay) == std::vector<std::string>{"a"});
        r.sched->tick(t0);
    };

    // This agent's stable offset for a delay of kDelay: a past next_fire is replaced by it.
    std::int64_t offset = 0;
    {
        Sam19Rig probe;
        request_at(probe, t0 - 100);
        offset = probe.next_fire("a") - t0;
    }
    REQUIRE(offset > 2);
    REQUIRE(offset < kDelay.count());

    SECTION("a future fire already sooner than the offset is kept, and the sync is still forced full") {
        Sam19Rig r;
        const std::int64_t sooner = t0 + offset / 2; // e.g. a skip-ladder retry
        request_at(r, sooner);
        CHECK(r.next_fire("a") == sooner);
        CHECK(r.kv.at("sync.a.force_full") == "1");
        CHECK(r.calls == 0);
    }
    SECTION("a future fire later than the offset is pulled earlier to it") {
        Sam19Rig r;
        request_at(r, t0 + kDelay.count() + offset); // inside the two-day sanity bound
        CHECK(r.next_fire("a") == t0 + offset);
        CHECK(r.kv.at("sync.a.force_full") == "1");
    }
    SECTION("a past fire is replaced by the offset, not kept") {
        Sam19Rig r;
        request_at(r, t0 - 100); // due but not yet sent, within one clamped sleep
        CHECK(r.next_fire("a") == t0 + offset);
        CHECK(r.kv.at("sync.a.force_full") == "1");
        CHECK(r.calls == 0);
    }
}
