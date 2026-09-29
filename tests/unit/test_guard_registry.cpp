/**
 * test_guard_registry.cpp — RegistryGuard enforcement (write-back) behaviour.
 *
 * Proves the enforce path restores a drifted value via a single in-process
 * registry syscall (RegSetValueExW) — NO shell, NO subprocess — and that audit
 * mode observes without writing. Windows-only (the guard is a no-op elsewhere);
 * exercises a real HKCU scratch key the running user can always write.
 */

#include <yuzu/agent/guard_registry.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "test_helpers.hpp" // process_random_salt (#486 UP-R12)

using namespace yuzu::agent;

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace {

// Process-salted unique-id generator — the same salt+counter scheme as
// yuzu::test::unique_temp_path(), sharing its process_random_salt()
// (tests/unit/test_helpers.hpp), extended from the filesystem to the registry. The Windows CI pool runs 4 runner agents on ONE physical box, all
// as LOCAL SYSTEM (deploy/windows/README.md) — SYSTEM's HKCU is one shared
// hive keyed by SID S-1-5-18, so a fixed registry path is a cross-JOB shared
// mutable resource (two unrelated CI jobs on the same box can genuinely
// watch/write/delete the same key at the same time), not just a cross-test
// one (#1871). Never salt with std::hash<std::thread::id> or steady_clock —
// that formula is the proven cause of flake #473.
struct UniqueTag {
    std::uint64_t salt;
    std::uint64_t n;
};
UniqueTag next_unique_tag() {
    static std::atomic<std::uint64_t> counter{0};
    return {yuzu::test::process_random_salt(), counter.fetch_add(1, std::memory_order_relaxed)};
}

// RAII per-test HKCU scratch key for the "enforce"/"audit" single-value tests.
// Each instance gets a unique subkey, so two concurrent test processes (e.g.
// two CI jobs sharing the Wee Tam box) can never collide.
struct TempEnforceKey {
    std::wstring key_w;
    std::string key_a;

    TempEnforceKey() {
        const auto tag = next_unique_tag();
        key_w = L"SOFTWARE\\YuzuTest\\GuardEnforceTest_" + std::to_wstring(tag.salt) + L"_" +
                std::to_wstring(tag.n);
        key_a = "SOFTWARE\\YuzuTest\\GuardEnforceTest_" + std::to_string(tag.salt) + "_" +
                std::to_string(tag.n);
    }
    ~TempEnforceKey() { RegDeleteKeyW(HKEY_CURRENT_USER, key_w.c_str()); }
    TempEnforceKey(const TempEnforceKey&) = delete;
    TempEnforceKey& operator=(const TempEnforceKey&) = delete;

    void set_dword(const wchar_t* name, DWORD v) const {
        HKEY k{};
        if (RegCreateKeyExW(HKEY_CURRENT_USER, key_w.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                            &k, nullptr) == ERROR_SUCCESS) {
            RegSetValueExW(k, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
            RegCloseKey(k);
        }
    }
    DWORD get_dword(const wchar_t* name) const {
        HKEY k{};
        if (RegOpenKeyExW(HKEY_CURRENT_USER, key_w.c_str(), 0, KEY_READ, &k) != ERROR_SUCCESS)
            return 0xFFFFFFFFu;
        DWORD v = 0, sz = sizeof(v), type = 0;
        RegQueryValueExW(k, name, nullptr, &type, reinterpret_cast<BYTE*>(&v), &sz);
        RegCloseKey(k);
        return v;
    }
};

// Arm `guard`, block up to 5s for the first drift report, then stop.
RegistryDrift run_once(RegistryGuard& guard, std::mutex& m, std::condition_variable& cv, bool& got,
                       RegistryDrift& captured) {
    REQUIRE(guard.start());
    {
        std::unique_lock lk(m);
        REQUIRE(cv.wait_for(lk, std::chrono::seconds(5), [&] { return got; }));
    }
    guard.stop();
    return captured;
}

// ── Resilience harness (C1) ──────────────────────────────────────────────────
// A dedicated, quiet, per-test key tree so the guard's nearest-ancestor watch
// never sees unrelated churn from another test OR another concurrent process
// on the same shared-SYSTEM-account box (which would make the quiescence
// assertion flaky — #1871). The leaf `K` is the watched key; the parent stays
// put across K's delete/recreate so the ancestor we fall back to watching is
// always quiet. RAII: the destructor cleans up even if a REQUIRE aborts the
// test — declare this before the RegistryGuard in each test so it's destroyed
// AFTER the guard stops (reverse construction order), never before.
struct TempRegKey {
    std::wstring parent_w;
    std::wstring leaf_w;
    std::string leaf_a;

    TempRegKey() {
        const auto tag = next_unique_tag();
        const std::wstring suffix_w = std::to_wstring(tag.salt) + L"_" + std::to_wstring(tag.n);
        const std::string suffix_a = std::to_string(tag.salt) + "_" + std::to_string(tag.n);
        parent_w = L"SOFTWARE\\YuzuGuardResilience_" + suffix_w;
        leaf_w = parent_w + L"\\K";
        leaf_a = "SOFTWARE\\YuzuGuardResilience_" + suffix_a + "\\K";
        make_parent();
    }
    ~TempRegKey() { cleanup(); }
    TempRegKey(const TempRegKey&) = delete;
    TempRegKey& operator=(const TempRegKey&) = delete;

    void make_parent() const {
        HKEY k{};
        if (RegCreateKeyExW(HKEY_CURRENT_USER, parent_w.c_str(), 0, nullptr, 0, KEY_READ, nullptr,
                            &k, nullptr) == ERROR_SUCCESS)
            RegCloseKey(k);
    }
    void set_flag(DWORD v) const {
        HKEY k{};
        if (RegCreateKeyExW(HKEY_CURRENT_USER, leaf_w.c_str(), 0, nullptr, 0, KEY_SET_VALUE,
                            nullptr, &k, nullptr) == ERROR_SUCCESS) {
            RegSetValueExW(k, L"Flag", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
            RegCloseKey(k);
        }
    }
    DWORD get_flag() const { // 0xFFFFFFFF = key/value absent
        HKEY k{};
        if (RegOpenKeyExW(HKEY_CURRENT_USER, leaf_w.c_str(), 0, KEY_READ, &k) != ERROR_SUCCESS)
            return 0xFFFFFFFFu;
        DWORD v = 0, sz = sizeof(v), type = 0;
        LONG rc = RegQueryValueExW(k, L"Flag", nullptr, &type, reinterpret_cast<BYTE*>(&v), &sz);
        RegCloseKey(k);
        return rc == ERROR_SUCCESS ? v : 0xFFFFFFFFu;
    }
    void delete_leaf() const { RegDeleteKeyW(HKEY_CURRENT_USER, leaf_w.c_str()); } // K + its values
    void cleanup() const {
        RegDeleteKeyW(HKEY_CURRENT_USER, leaf_w.c_str());
        RegDeleteKeyW(HKEY_CURRENT_USER, parent_w.c_str());
    }
};

// Captures EVERY drift (not just the first) so we can assert survival across a
// delete -> recreate cycle. wait_detected_after() waits for a drift carrying a
// given detected_value at or after a baseline index — robust to the 1s sink
// debounce and to the create-then-set race when a key is recreated.
struct DriftCollector {
    std::mutex m;
    std::condition_variable cv;
    std::vector<RegistryDrift> events;

    void operator()(const RegistryDrift& d) {
        std::lock_guard lk(m);
        events.push_back(d);
        cv.notify_all();
    }
    std::size_t size() {
        std::lock_guard lk(m);
        return events.size();
    }
    bool wait_detected_after(std::size_t from, const std::string& val,
                             std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        return cv.wait_for(lk, to, [&] {
            for (std::size_t i = from; i < events.size(); ++i)
                if (events[i].detected_value == val)
                    return true;
            return false;
        });
    }
    RegistryDrift find_detected(const std::string& val) { // most-recent matching drift
        std::lock_guard lk(m);
        for (auto it = events.rbegin(); it != events.rend(); ++it)
            if (it->detected_value == val)
                return *it;
        return {};
    }
    bool wait_size(std::size_t n, std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        return cv.wait_for(lk, to, [&] { return events.size() >= n; });
    }
    RegistryDrift at(std::size_t i) {
        std::lock_guard lk(m);
        return events.at(i);
    }
};

} // namespace

TEST_CASE("RegistryGuard enforce: restores a drifted DWORD via RegSetValueExW",
          "[guardian][guard][enforce][registry]") {
    TempEnforceKey key;
    key.set_dword(L"Flag", 0); // currently WRONG (expected 1)

    RegistryGuard::Config cfg;
    cfg.rule_id = "enforce-test";
    cfg.rule_name = "enforce flag";
    cfg.hive = "HKCU";
    cfg.key = key.key_a;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = true;

    std::mutex m;
    std::condition_variable cv;
    RegistryDrift captured;
    bool got = false;
    RegistryGuard guard(std::move(cfg), [&](const RegistryDrift& d) {
        std::lock_guard lk(m);
        captured = d;
        got = true;
        cv.notify_all();
    });

    // Arming runs an initial compare → detects 0 != 1 → enforces (writes 1 back)
    // BEFORE reporting, so by the time the sink fires the value is already fixed.
    auto d = run_once(guard, m, cv, got, captured);

    CHECK(key.get_dword(L"Flag") == 1u); // the syscall write restored it
    CHECK(d.detected_value == "0");
    CHECK(d.expected_value == "1");
    CHECK(d.remediation_attempted);
    CHECK(d.remediation_success);
    CHECK(d.remediation_action == "registry-write");
    INFO("remediation latency = " << d.remediation_latency_us << " us");
    CHECK(d.remediation_success); // (latency printed above on any failure)
}

TEST_CASE("RegistryGuard audit: observes drift but does NOT write back",
          "[guardian][guard][audit][registry]") {
    TempEnforceKey key;
    key.set_dword(L"Flag2", 7); // WRONG (expected 1), but audit must leave it alone

    RegistryGuard::Config cfg;
    cfg.rule_id = "audit-test";
    cfg.hive = "HKCU";
    cfg.key = key.key_a;
    cfg.value_name = "Flag2";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = false; // observe only

    std::mutex m;
    std::condition_variable cv;
    RegistryDrift captured;
    bool got = false;
    RegistryGuard guard(std::move(cfg), [&](const RegistryDrift& d) {
        std::lock_guard lk(m);
        captured = d;
        got = true;
        cv.notify_all();
    });

    auto d = run_once(guard, m, cv, got, captured);

    CHECK(d.detected_value == "7");
    CHECK_FALSE(d.remediation_attempted);
    CHECK(key.get_dword(L"Flag2") == 7u); // unchanged — audit never writes
}

TEST_CASE("RegistryGuard compliant edge: emits guard.compliant on arm + on drift-clear (Slice B)",
          "[guardian][guard][registry][compliant]") {
    // The compliance census (Slice B) needs the agent to report a Guard reaching /
    // returning to compliant, not just drifting. Observe mode so the signal is the
    // guard's own edge, not a self-write's re-read. event_debounce_ms=0 keeps the
    // edges deterministic.
    TempRegKey key;
    key.set_flag(1); // compliant on arm (expected 1)

    RegistryGuard::Config cfg;
    cfg.rule_id = "compliant-edge";
    cfg.rule_name = "compliant edge";
    cfg.hive = "HKCU";
    cfg.key = key.leaf_a;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = false; // observe
    cfg.event_debounce_ms = 0;

    DriftCollector col;
    RegistryGuard guard(std::move(cfg), [&col](const RegistryDrift& d) { col(d); });
    REQUIRE(guard.start());
    using namespace std::chrono_literals;

    // (a) arm compliant → exactly one guard.compliant edge (detected == expected).
    REQUIRE(col.wait_size(1, 5s));
    CHECK(col.at(0).compliant);
    CHECK(col.at(0).detected_value == "1");

    // (b) drift → a NON-compliant drift report.
    key.set_flag(0);
    REQUIRE(col.wait_detected_after(1, "0", 5s));
    CHECK_FALSE(col.find_detected("0").compliant);
    const auto after_drift = col.size();

    // (c) clear the drift (a manual fix in observe mode) → a fresh compliant edge.
    // This is the observe-staleness self-heal: a manual fix fires a change notify
    // → reconcile → compliant, so the server learns the rule went green again.
    key.set_flag(1);
    REQUIRE(col.wait_detected_after(after_drift, "1", 5s));
    CHECK(col.find_detected("1").compliant);

    guard.stop();
}

TEST_CASE("RegistryGuard resilience: survives key deletion and re-detects after recreate",
          "[guardian][guard][registry][resilience]") {
    TempRegKey key;
    key.set_flag(1); // compliant on arm — emits a guard.compliant edge, no drift

    RegistryGuard::Config cfg;
    cfg.rule_id = "resilience-test";
    cfg.rule_name = "resilience flag";
    cfg.hive = "HKCU";
    cfg.key = key.leaf_a;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = false;       // audit: observe only — no write-back to muddy the signal
    cfg.event_debounce_ms = 0; // deterministic — no debounce window to race against

    DriftCollector col;
    RegistryGuard guard(std::move(cfg), [&col](const RegistryDrift& d) { col(d); });
    REQUIRE(guard.start());

    using namespace std::chrono_literals;

    // (a) value drift while the key exists — baseline that the watch is live.
    key.set_flag(0);
    REQUIRE(col.wait_detected_after(0, "0", 5s));
    const auto n1 = col.size();

    // (b) delete the WHOLE key — the pre-C1 watch thread died at this point.
    key.delete_leaf();
    REQUIRE(col.wait_detected_after(n1, "<absent>", 5s));
    const auto n2 = col.size();

    // (c) recreate (compliant) so the guard re-arms on the new key, then drift it
    // again. ONLY a guard that SURVIVED the deletion and re-armed can report this
    // post-recreate drift — the C1 proof. (Re-detecting via a clean value change on
    // the re-armed key sidesteps the create-then-set race of recreate-with-drift.)
    key.set_flag(1); // recreate K, compliant (re-arm; compliant edge, no drift)
    key.set_flag(0); // clean value drift on the re-armed key
    REQUIRE(col.wait_detected_after(n2, "0", 5s));

    guard.stop();
}

TEST_CASE("RegistryGuard resilience: survives whole-chain delete + atomic recreate",
          "[guardian][guard][registry][resilience]") {
    TempRegKey key;
    key.set_flag(1); // K present, compliant

    RegistryGuard::Config cfg;
    cfg.rule_id = "wholechain-test";
    cfg.rule_name = "wholechain flag";
    cfg.hive = "HKCU";
    cfg.key = key.leaf_a;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = false;       // audit: observe only
    cfg.event_debounce_ms = 0; // deterministic — no debounce window to race against

    DriftCollector col;
    RegistryGuard guard(std::move(cfg), [&col](const RegistryDrift& d) { col(d); });
    REQUIRE(guard.start());
    using namespace std::chrono_literals;

    // Delete K AND its parent — the whole chain below HKCU\SOFTWARE is gone, so the
    // guard must walk PAST the dead parent to the nearest existing ancestor
    // (HKCU\SOFTWARE) to keep watching. That ancestor is busy, so assert
    // re-detection, not quiescence.
    key.cleanup();
    REQUIRE(col.wait_detected_after(0, "<absent>", 5s)); // detected via ancestor walk-up
    const auto n = col.size();

    // key.set_flag's RegCreateKeyExW recreates parent + K in ONE atomic call — the
    // multi-level create that reconcile()-from-scratch (not incremental descend)
    // exists to tolerate. Recreate compliant, let the guard re-arm, then drift it.
    key.set_flag(1);
    key.set_flag(0);
    REQUIRE(col.wait_detected_after(n, "0", 5s)); // re-detected despite whole-chain recreate

    guard.stop();
}

TEST_CASE("RegistryGuard resilience: absent state is quiescent (no busy-spin)",
          "[guardian][guard][registry][resilience][quiescent]") {
    TempRegKey key;
    key.set_flag(0); // drift on arm so the first event proves the watch armed

    RegistryGuard::Config cfg;
    cfg.rule_id = "quiescent-test";
    cfg.hive = "HKCU";
    cfg.key = key.leaf_a;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = false;
    cfg.event_debounce_ms = 0; // deterministic — no debounce window to race against

    DriftCollector col;
    RegistryGuard guard(std::move(cfg), [&col](const RegistryDrift& d) { col(d); });
    REQUIRE(guard.start());

    using namespace std::chrono_literals;
    REQUIRE(col.wait_detected_after(0, "0", 5s)); // armed + initial drift seen
    const auto n1 = col.size();

    key.delete_leaf();
    REQUIRE(col.wait_detected_after(n1, "<absent>", 5s)); // deletion detected
    const auto settled = col.size();

    // Key gone, the (quiet) ancestor armed → the thread must BLOCK on
    // WaitForMultipleObjects, not spin reconcile(). A spin would emit a fresh
    // absent drift every ~1s (the debounce window). Assert no new events arrive.
    std::this_thread::sleep_for(2500ms);
    CHECK(col.size() == settled);

    guard.stop();
}

TEST_CASE("RegistryGuard enforce key-restore: recreates a deleted key + value (C2)",
          "[guardian][guard][registry][enforce][restore]") {
    TempRegKey key;
    key.set_flag(1); // key exists, compliant (expected 1)

    RegistryGuard::Config cfg;
    cfg.rule_id = "restore-test";
    cfg.rule_name = "restore flag";
    cfg.hive = "HKCU";
    cfg.key = key.leaf_a;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = true; // enforce: must recreate the key when it's deleted

    DriftCollector col;
    RegistryGuard guard(std::move(cfg), [&col](const RegistryDrift& d) { col(d); });
    REQUIRE(guard.start());
    using namespace std::chrono_literals;

    // Delete the WHOLE key — enforce must RegCreateKeyExW it back + rewrite Flag.
    key.delete_leaf();
    REQUIRE(col.wait_detected_after(0, "<absent>", 5s));

    // Remediation runs inside emit() before the sink fires, so the key + value are
    // already restored by the time we observe the event.
    CHECK(key.get_flag() == 1u);
    auto d = col.find_detected("<absent>");
    CHECK(d.remediation_attempted);
    CHECK(d.remediation_success);
    CHECK(d.remediation_action == "registry-create");

    guard.stop();
}

TEST_CASE("RegistryGuard audit: does NOT recreate a deleted key (C2 invariant)",
          "[guardian][guard][registry][audit][restore]") {
    TempRegKey key;
    key.set_flag(1); // key exists, compliant

    RegistryGuard::Config cfg;
    cfg.rule_id = "audit-norestore";
    cfg.hive = "HKCU";
    cfg.key = key.leaf_a;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = false; // audit: observe only — must NOT recreate

    DriftCollector col;
    RegistryGuard guard(std::move(cfg), [&col](const RegistryDrift& d) { col(d); });
    REQUIRE(guard.start());
    using namespace std::chrono_literals;

    key.delete_leaf();
    REQUIRE(col.wait_detected_after(0, "<absent>", 5s)); // detects the deletion

    CHECK(key.get_flag() == 0xFFFFFFFFu); // audit left the key gone
    CHECK_FALSE(col.find_detected("<absent>").remediation_attempted);

    guard.stop();
}

TEST_CASE("RegistryGuard Bounded: stops fixing after the cap (give-up flows through the guard)",
          "[guardian][guard][registry][resilience][bounded]") {
    TempRegKey key;
    key.set_flag(0); // drift initially (expected 1)

    RegistryGuard::Config cfg;
    cfg.rule_id = "bounded-guard";
    cfg.rule_name = "bounded guard";
    cfg.hive = "HKCU";
    cfg.key = key.leaf_a;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = true;
    cfg.resilience.mode = ResilienceMode::Bounded;
    cfg.resilience.max_attempts = 1;        // fix once, then give up
    cfg.resilience.quiet_reset_ms = 60'000; // keep the two drifts "consecutive"
    cfg.resilience.resume_after_ms = 0;     // stay given up
    cfg.event_debounce_ms = 0;              // emit every drift (deterministic for the test)

    DriftCollector col;
    RegistryGuard guard(std::move(cfg), [&col](const RegistryDrift& d) { col(d); });
    REQUIRE(guard.start());
    using namespace std::chrono_literals;

    // Cycle 1: drift → remediated (within the cap of 1). The fix lands inside emit()
    // before the event fires, so the value is already restored.
    REQUIRE(col.wait_size(1, 5s));
    CHECK(col.at(0).remediation_attempted);
    CHECK(col.at(0).remediation_success);
    CHECK(key.get_flag() == 1u);

    // Cycle 2: drift again → exceeds the cap → GIVE UP: still detected + reported,
    // but the strategy withholds the write, so the value stays wrong.
    key.set_flag(0);
    REQUIRE(col.wait_size(2, 5s));
    CHECK_FALSE(col.at(1).remediation_attempted); // give-up gated the write
    std::this_thread::sleep_for(300ms);           // give any erroneous write time to land
    CHECK(key.get_flag() == 0u);                  // still wrong — Bounded gave up

    guard.stop();
}

#else // ── Non-Windows: the guard is a no-op ─────────────────────────────────

TEST_CASE("RegistryGuard is a no-op off Windows", "[guardian][guard][registry]") {
    RegistryGuard::Config cfg;
    cfg.hive = "HKCU";
    cfg.enforce = true;
    RegistryGuard guard(std::move(cfg), [](const RegistryDrift&) {});
    CHECK_FALSE(guard.start());
}

#endif
