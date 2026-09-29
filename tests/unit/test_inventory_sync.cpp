// Agent daily-sync tests (ADR-0016): the canonical-hash cross-pin with the
// server, installed_apps output parsing, and the SyncScheduler hash-skip /
// need_full / first-run state machine (gRPC + KV injected — no network).

#include <catch2/catch_test_macros.hpp>

#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // sha256_hex
#include "sync_scheduler.hpp"
#include "sync_source_installed_software.hpp"

#include <yuzu/plugin.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using yuzu::agent::installed_software_canonical_blob;
using yuzu::agent::parse_installed_apps_output;
using yuzu::agent::sha256_hex;
using yuzu::agent::SwEntry;
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
    // on. (octal \037 == 0x1F, \036 == 0x1E.)
    auto e = parse_installed_apps_output(std::string("inv|na\037me|1\0362|pub|d\n"));
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
          std::string("A\0371\037P\037D\037\037\037\037\037\037\037\037\036"
                      "B\0372\037\037\037\037\037\037\037\037\037\037\036"));
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
