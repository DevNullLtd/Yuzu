// Agent daily-sync tests (ADR-0016): the canonical-hash cross-pin with the
// server, installed_apps output parsing, and the SyncScheduler hash-skip /
// need_full / first-run state machine (gRPC + KV injected — no network).

#include <catch2/catch_test_macros.hpp>

#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // sha256_hex
#include "sync_scheduler.hpp"
#include "msi_packages_inventory.hpp"
#include "pkg_inventory_parsers.hpp"
#include "sync_source_installed_software.hpp"
#include "windows_optional_features_parsers.hpp"

#include <inventory_status_row.hpp>

#include <yuzu/plugin.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
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
using yuzu::agent::parse_msi_packages_list_inventory_output;
using yuzu::agent::parse_pkg_inventory_managers_output;
using yuzu::agent::parse_pkg_inventory_packages_output;
using yuzu::agent::parse_pkg_inventory_store_packages_output;
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
    sched.tick(t2);
    REQUIRE(calls == 2);
    CHECK_FALSE(last_had_blob);

    // Changed content → FULL.
    cur_hash = "h2";
    cur_blob = "b2";
    std::int64_t t3 = t2 + 86400 + 1;
    sched.tick(t3);
    REQUIRE(calls == 3);
    CHECK(last_had_blob);

    // Server asks for a resend (need_full): this cycle is hash-only (unchanged),
    // but the scheduler then force-fulls on the next pass.
    next_need = {"installed_software"};
    std::int64_t t4 = t3 + 86400 + 1;
    sched.tick(t4);
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

    sched.tick(1700 + 86400 + 1); // unchanged, within the floor → hash-only
    REQUIRE(calls == 2);
    REQUIRE_FALSE(last_had_blob);

    // Past last_full + kFullFloor, still unchanged → forced FULL.
    sched.tick(1700 + SyncScheduler::kFullFloor.count() + 1);
    REQUIRE(calls == 3);
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
FakeOut g_fake[4]; // 0 installed_apps, 1 pkg_inventory, 2 windows_optional_features, 3 msi_packages

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

#define YUZU_FAKE_DESC(var, plugin_name, actions, idx)                                            \
    const YuzuPluginDescriptor var = {YUZU_PLUGIN_ABI_VERSION, plugin_name, "1.0.0", "test fake", \
                                      actions,                 nullptr,     nullptr,  fake_execute<idx>, \
                                      nullptr}
YUZU_FAKE_DESC(kFakeIa, "installed_apps", kFakeIaActions, 0);
YUZU_FAKE_DESC(kFakePkg, "pkg_inventory", kFakePkgActions, 1);
YUZU_FAKE_DESC(kFakeWof, "windows_optional_features", kFakeWofActions, 2);
YUZU_FAKE_DESC(kFakeMsi, "msi_packages", kFakeMsiActions, 3);
#undef YUZU_FAKE_DESC

SyncPluginMap all_plugins() {
    return {{"installed_apps", &kFakeIa},
            {"pkg_inventory", &kFakePkg},
            {"windows_optional_features", &kFakeWof},
            {"msi_packages", &kFakeMsi}};
}

void reset_fakes() {
    for (auto& f : g_fake) {
        f.out.clear();
        f.overflow.clear();
        f.rc.clear();
        f.result_status.clear();
    }
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

// --- M.10c characterisation: today's adapter output, pinned BEFORE the status-row refactor ---
//
// Every cell asserts the whole observable result of an adapter: status, reason, entry count and
// ALL fourteen fields of every entry. The cells reach the adapters only through the four binders
// below, so the refactor that moves the constrained policy into the action table changes the
// binders and nothing else; the expectations never move. Status rows are written as raw text
// (not through a formatter) so they are independent of the producer being refactored.

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
                                                      : "failed";
    s += "|reason=" + r.reason + "|n=" + std::to_string(r.entries.size());
    for (const auto& e : r.entries)
        s += "|" + show_entry(e);
    return s;
}

// Expected-result builders (the entry text is built through show_entry, so a field the refactor
// drops or reorders is a visible difference, not a silently shorter string).
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

// Collector level: the whole blob, pinned. The digests were MEASURED on the unrefactored tree
// (merge-base 6468fc11d) and are the wire-contract proof of this refactor: the blob is hashed
// byte-identically on agent and server (ADR-0016), so any movement here is a one-sided change.
// Re-measure ONLY on a sample recapture, the same rule as the record counts above.
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
        // Same digest as the Mac run: the kept present row maps to the one homebrew record the
        // capture already carries, so the constrained answer must not move a byte.
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
    };
    const Case cases[] = {
        {1, "pkg_inventory", "packages", false, "package|homebrew|wget|1.24|formula"},
        {1, "pkg_inventory", "store_packages", false,
         "package|snap|btop|1.4.7|app|1073|-|-|active"},
        {1, "pkg_inventory", "managers", false, ""},
        {3, "msi_packages", "list_inventory", true,
         "inv|{AAAAAAAA-0000-0000-0000-000000000001}|App|1.0|Pub"}};
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
        // constrained with no data row: skipped, the status token is the reason
        CHECK(skip_with(nl({st(a, "constrained", "tok")})) ==
              std::make_pair(false, source + ":tok"));
        // constrained with a row of the wrong shape: still skipped
        CHECK(skip_with(nl({st(a, "constrained", "tok"), "garbage|row"})) ==
              std::make_pair(false, source + ":tok"));
        // constrained with a row the adapter MAPS: still skipped, so the action table's
        // `constrained` column (fail) is what is pinned, not just the zero-row fallback.
        // Managers is the one action that keeps such a cycle (cases below).
        if (*c.mapped != '\0') {
            CHECK(skip_with(nl({st(a, "constrained", "tok"), c.mapped})) ==
                  std::make_pair(false, source + ":tok"));
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
