/**
 * test_echo_registry_source.cpp -- the `registry` cursor-model Echo source
 * (echo_registry_parsers.hpp pure core + echo_registry_source.{hpp,cpp}).
 *
 * Three layers: (1) the pure core -- paths, rendering, baselines, windows, the diff,
 * correlation, the stitch with its settle hold and loss epochs, the dirty table, the
 * seq-identified event buffer, record keys and codecs; (2) the collect() state machine
 * over an injected reader and a real ephemeral EchoDatabase, on every platform; (3) the
 * [windows] live cases (kingsley, elevated) that run the real key watch and the real
 * Kernel-Registry ETW session. No test sleeps: a live notification or event is awaited
 * on a condition variable with a deadline, and time is the injected clock.
 */

#include "echo_cursor.hpp"
#include "echo_db.hpp"
#include "echo_registry_parsers.hpp"
#include "echo_registry_source.hpp"
#include "echo_schema_registry.hpp"
#include "test_helpers.hpp"
#include "test_log_capture.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <filesystem>
#include <format>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <evntrace.h> // ControlTraceW QUERY: no session may outlive stop()
#include <sddl.h>
#include <win_profiles.hpp> // enumerate_hku_subkeys, PrivilegeScope: the offline-hive cases
#include <win_str.hpp>
#include "echo_hive_mount_gate.hpp"  // g_mount_workers_in_flight
#include "echo_win_process_name.hpp" // process_basename_for_pid
#endif

namespace fs = std::filesystem;
using namespace yuzu::echo;
using Catch::Matchers::ContainsSubstring;

namespace {

constexpr std::int64_t SEC = 10'000'000;           // 100 ns ticks per second
constexpr std::int64_t T0 = 133'000'000'000'000'000LL; // a plausible FILETIME

// ── builders ────────────────────────────────────────────────────────────────

std::string dword(std::uint32_t v) {
    std::string b(4, '\0');
    for (int i = 0; i < 4; ++i)
        b[static_cast<std::size_t>(i)] = static_cast<char>((v >> (8 * i)) & 0xFF);
    return b;
}

std::string utf16(std::string_view ascii, bool nul = true) {
    std::string b;
    for (char c : ascii) {
        b += c;
        b += '\0';
    }
    if (nul)
        b.append(2, '\0');
    return b;
}

RegistryValueRead vread(std::uint32_t type, std::string bytes) {
    RegistryValueRead v;
    v.type = type;
    v.full_size = bytes.size();
    v.bytes = std::move(bytes);
    return v;
}

SubtreeRead complete(std::map<std::string, std::map<std::string, RegistryValueRead>> keys) {
    SubtreeRead r;
    r.status = RegistryReadStatus::Complete;
    r.keys = std::move(keys);
    return r;
}

RegistryCandidate cand(std::string action, std::string value, std::uint32_t type,
                       std::uint64_t size, std::int64_t lo, std::int64_t hi) {
    RegistryCandidate c;
    c.root = "HKLM\\SOFTWARE\\r";
    c.key = "HKLM\\SOFTWARE\\r\\Svc";
    c.value = std::move(value);
    c.action = std::move(action);
    c.type = type;
    c.size = size;
    c.data = "x";
    c.observed_at = hi;
    c.window_lo = lo;
    c.window_hi = hi;
    c.source = "notify";
    return c;
}

RegistryEtwEvent ev(std::int64_t ts, std::uint32_t pid, RegistryEtwOp op, std::string value,
                    std::uint32_t type = 4, std::uint32_t size = 4,
                    std::string image = "svc.exe") {
    RegistryEtwEvent e;
    e.ts100ns = ts;
    e.pid = pid;
    e.image = std::move(image);
    e.op = op;
    e.value_key = value_name_key(value);
    e.type = type;
    e.size = size;
    return e;
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// Pure core
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("normalise_registry_path maps only the current control set", "[echo][registry][pure]") {
    CHECK(normalise_registry_path("HKLM\\SYSTEM\\ControlSet001\\Services", 1) ==
          "HKLM\\SYSTEM\\CurrentControlSet\\Services");
    CHECK(normalise_registry_path("HKLM\\SYSTEM\\ControlSet001\\Services", 2) ==
          "HKLM\\SYSTEM\\ControlSet001\\Services");
    CHECK(normalise_registry_path("HKLM\\SYSTEM\\controlset002\\Services", 2) ==
          "HKLM\\SYSTEM\\CurrentControlSet\\Services"); // comparison is case-insensitive
    CHECK(normalise_registry_path("HKU\\S-1-5-21-1\\Software\\Run", 1) ==
          "HKU\\S-1-5-21-1\\Software\\Run"); // case and content preserved
}

TEST_CASE("default_registry_scope: curated roots; per-user roots skip non-profile hives",
          "[echo][registry][pure]") {
    const auto scope = default_registry_scope();
    // Two profile hives pass the filter (an interactive SID and LocalSystem); the
    // dot-prefixed default hive, both `_Classes` spellings and a sibling plugin's temporary
    // profile mount do not.
    const auto roots = scope.roots_for({"S-1-5-21-1", ".DEFAULT", "S-1-5-21-1_Classes",
                                         "S-1-5-21-1_CLASSES", "S-1-5-18",
                                         "YUZU_HIVE_S-1-5-21-2_0123456789abcdef_1"});
    const std::set<std::string> got(roots.begin(), roots.end());
    CHECK(got.size() == roots.size()); // every root once

    // The curated watch scope, spelled out: a silent drop or rename of any entry is a
    // change to what the source promises to observe (and to what the manual lists).
    std::set<std::string> want = {
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution "
        "Options",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
        "HKLM\\SOFTWARE\\Policies",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
        "HKLM\\SOFTWARE\\Microsoft\\Windows Defender",
    };
    CHECK(want.size() == 14);
    for (const char* sid : {"S-1-5-21-1", "S-1-5-18"})
        for (const char* suffix : {
                 "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                 "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                 "Software\\Policies",
                 "Software\\Microsoft\\Windows\\CurrentVersion\\Policies",
                 "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
             })
            want.insert(std::string{"HKU\\"} + sid + "\\" + suffix);
    CHECK(want.size() == 14 + 2 * 5);
    CHECK(got == want);

    CHECK_FALSE(got.contains("HKU\\.DEFAULT\\Software\\Policies"));
    CHECK_FALSE(got.contains("HKU\\S-1-5-21-1_Classes\\Software\\Policies"));
}

TEST_CASE("is_user_hive_name accepts SID-named hives only", "[echo][registry][pure]") {
    CHECK(is_user_hive_name("S-1-5-21-1111111111-2222222222-3333333333"));
    CHECK(is_user_hive_name("S-1-5-18"));
    // Not user profiles: the default hive, the classes hives, and the temporary mounts
    // (agents/shared/win_reg_handle.hpp) sibling plugins load for a logged-out profile and
    // unload without force -- a watch handle open on one would fail that unload.
    CHECK_FALSE(is_user_hive_name(".DEFAULT"));
    CHECK_FALSE(is_user_hive_name("S-1-5-21-1_Classes"));
    CHECK_FALSE(is_user_hive_name("S-1-5-21-1_CLASSES"));
    CHECK_FALSE(is_user_hive_name("YUZU_HIVE_S-1-5-21-1_0123456789abcdef_1"));
    CHECK_FALSE(is_user_hive_name(""));
    CHECK_FALSE(is_user_hive_name("S-1-"));
    CHECK_FALSE(is_user_hive_name("S-1-5-x"));
    CHECK_FALSE(is_user_hive_name("alice"));
}

TEST_CASE("render_reg_data renders each registry type", "[echo][registry][pure]") {
    namespace P = yuzu::profiles;
    CHECK(render_reg_data(P::kRegSz, utf16("hello"), 100).text == "hello");
    CHECK(render_reg_data(P::kRegSz, utf16("hello", false), 100).text == "hello"); // no trailing NUL
    CHECK(render_reg_data(P::kRegExpandSz, utf16("%SystemRoot%\\x"), 100).text == "%SystemRoot%\\x");
    CHECK(render_reg_data(P::kRegMultiSz, utf16("a", false) + std::string(2, '\0') +
                                              utf16("bc", false) + std::string(4, '\0'),
                          100).text == "a\nbc");
    CHECK(render_reg_data(P::kRegDword, dword(4294967295u), 100).text == "4294967295");
    CHECK(render_reg_data(P::kRegQword, std::string("\x01\0\0\0\0\0\0\0", 8), 100).text == "1");
    CHECK(render_reg_data(P::kRegBinary, std::string("\x00\xAB\xff", 3), 100).text == "00abff");
    // cap -> truncated flag, on the TEXT
    const auto cut = render_reg_data(P::kRegSz, utf16("abcdefghij"), 4);
    CHECK(cut.text == "abcd");
    CHECK(cut.truncated);
    CHECK(render_reg_data(P::kRegBinary, std::string(100, 'a'), 10).truncated);
    // an odd-length UTF-16 payload does not crash
    CHECK_NOTHROW(render_reg_data(P::kRegSz, std::string("a\0b", 3), 100));
    // type tokens come from the shared model
    CHECK(P::reg_type_name(P::kRegDword) == "REG_DWORD");
    CHECK(P::reg_type_name(P::kRegSz) == "REG_SZ");
}

TEST_CASE("baseline_entry_from_bytes hashes every byte read (R8)", "[echo][registry][pure]") {
    namespace P = yuzu::profiles;
    std::string a(100 * 1024, 'x');
    std::string b = a;
    b.back() = 'y'; // changed only in its last byte
    const auto ea = baseline_entry_from_bytes(P::kRegBinary, a.size(), a, false);
    const auto eb = baseline_entry_from_bytes(P::kRegBinary, b.size(), b, false);
    CHECK(ea.h != eb.h);
    CHECK(ea.s == eb.s);
    CHECK(ea == baseline_entry_from_bytes(P::kRegBinary, a.size(), a, false)); // identical bytes
    CHECK(ea.d.size() <= kBaselineRenderCap);
    const auto big = baseline_entry_from_bytes(P::kRegBinary, 9'000'000, a, true);
    CHECK(big.dt); // hash covers a prefix only
    CHECK(big.s == 9'000'000);
}

TEST_CASE("candidate_window tightens on notify, never on a reconcile read (R5)",
          "[echo][registry][pure]") {
    const std::int64_t slack = kEtwWindowSlack100ns;
    auto w = candidate_window(100 * SEC, 200 * SEC, 0, 0, slack); // reconcile: the whole interval
    CHECK(w.lo == 100 * SEC);
    CHECK(w.hi == 200 * SEC);
    w = candidate_window(100 * SEC, 200 * SEC, 150 * SEC, 152 * SEC, slack); // notify burst +/- 1 s
    CHECK(w.lo == 149 * SEC);
    CHECK(w.hi == 153 * SEC);
    w = candidate_window(100 * SEC, 200 * SEC, 100 * SEC, 300 * SEC, slack); // last later than read_end
    CHECK(w.lo == 100 * SEC); // never before the root's last complete read
    CHECK(w.hi == 200 * SEC); // clamped to read_end
    w = candidate_window(100 * SEC, 200 * SEC, 190 * SEC, 150 * SEC, slack); // inconsistent stamps
    CHECK(w.lo == 100 * SEC); // fell back to the wide window rather than narrow on them
    CHECK(w.hi == 200 * SEC);
    w = candidate_window(500 * SEC, 200 * SEC, 0, 0, slack); // base after the end collapses
    CHECK(w.lo == w.hi);
}

TEST_CASE("diff_registry_snapshot: added/changed/removed values and the four read statuses",
          "[echo][registry][pure]") {
    namespace P = yuzu::profiles;
    const std::string root = "HKLM\\SOFTWARE\\r";
    const RegistryWindow win{10, 20};
    auto read1 = complete({{root + "\\A", {{"ImagePath", vread(P::kRegSz, utf16("c:\\a.exe"))}}},
                           {root + "\\B", {{"ImagePath", vread(P::kRegSz, utf16("c:\\b.exe"))}}}});
    const auto first = diff_registry_snapshot({}, read1, root, "reconcile", win, 20, /*suppress=*/true);
    CHECK(first.candidates.empty()); // the first read of a root reports nothing
    CHECK(first.baseline.keys.size() == 2);

    SECTION("two subkeys holding the same value name are distinct entries; nothing changed") {
        const auto same = diff_registry_snapshot(first.baseline, read1, root, "notify", win, 20);
        CHECK(same.candidates.empty());
        CHECK_FALSE(same.changed); // identical snapshots -> no StateWrite
    }

    SECTION("added / changed / removed value on a Complete read carry the window and prev_*") {
        auto read2 = complete(
           {{root + "\\A", {{"ImagePath", vread(P::kRegSz, utf16("c:\\a2.exe"))},
                            {"Start", vread(P::kRegDword, dword(2))}}},
            {root + "\\B", {}}}); // B lost ImagePath
        const auto d = diff_registry_snapshot(first.baseline, read2, root, "notify", win, 20);
        REQUIRE(d.candidates.size() == 3);
        std::map<std::string, RegistryCandidate> by;
        for (const auto& c : d.candidates)
            by[c.action + ":" + c.key.substr(root.size() + 1) + ":" + c.value] = c;
        const auto& changed = by.at("changed:A:ImagePath");
        CHECK(changed.data == "c:\\a2.exe");
        CHECK(changed.has_prev);
        CHECK(changed.prev_data == "c:\\a.exe");
        CHECK(changed.root == root);
        CHECK(changed.window_lo == 10);
        CHECK(changed.window_hi == 20);
        CHECK(by.at("added:A:Start").data == "2");
        CHECK_FALSE(by.at("added:A:Start").has_prev);
        CHECK(by.at("removed:B:ImagePath").prev_data == "c:\\b.exe");
        CHECK(d.changed);
    }

    SECTION("an Absent root removes every value, then the key") {
        SubtreeRead gone;
        gone.status = RegistryReadStatus::Absent;
        const auto d = diff_registry_snapshot(first.baseline, gone, root, "reconcile", win, 20);
        int removed = 0, key_removed = 0;
        for (const auto& c : d.candidates) {
            removed += c.action == "removed";
            key_removed += c.action == "key_removed";
        }
        CHECK(removed == 2);
        CHECK(key_removed == 2);
        CHECK(d.baseline.keys.empty());
    }

    SECTION("Unreadable changes nothing: no candidates, baseline byte-identical") {
        SubtreeRead bad;
        bad.status = RegistryReadStatus::Unreadable;
        const auto d = diff_registry_snapshot(first.baseline, bad, root, "reconcile", win, 20);
        CHECK(d.candidates.empty());
        CHECK(encode_registry_baseline(d.baseline) == encode_registry_baseline(first.baseline));
        CHECK_FALSE(d.changed);
    }

    SECTION("Capped adds and updates what it visited, retains the rest, removes nothing") {
        SubtreeRead part;
        part.status = RegistryReadStatus::Capped;
        part.keys = {{root + "\\A", {{"ImagePath", vread(P::kRegSz, utf16("c:\\a3.exe"))}}}};
        const auto d = diff_registry_snapshot(first.baseline, part, root, "reconcile", win, 20);
        REQUIRE(d.candidates.size() == 1);
        CHECK(d.candidates[0].action == "changed");
        CHECK(d.baseline.keys.contains(root + "\\B")); // unvisited prior entries retained
        CHECK(d.baseline.keys.at(root + "\\B").contains("ImagePath"));
    }

    SECTION("a denied child key keeps what the baseline holds beneath it; the rest of the root still diffs") {
        const std::string a = root + "\\A";
        const auto base_read = complete({{a, {{"ImagePath", vread(P::kRegSz, utf16("c:\\a.exe"))}}},
                                         {a + "\\Denied", {{"x", vread(P::kRegDword, dword(1))}}},
                                         {a + "\\Denied\\Deep", {{"y", vread(P::kRegDword, dword(2))}}},
                                         {a + "\\Denied2", {{"z", vread(P::kRegDword, dword(3))}}}});
        const auto base = diff_registry_snapshot({}, base_read, root, "reconcile", win, 20, /*suppress=*/true).baseline;

        // A lost its ImagePath, Denied can no longer be read, Denied2 (a sibling whose name only
        // starts the same) is really gone.
        SubtreeRead now = complete({{a, {}}});
        now.skipped = {a + "\\Denied"};
        const auto d = diff_registry_snapshot(base, now, root, "notify", win, 20);
        std::set<std::string> got;
        for (const auto& c : d.candidates)
            got.insert(c.action + ":" + c.key.substr(root.size() + 1) + ":" + c.value);
        CHECK(got == std::set<std::string>{"removed:A:ImagePath", "removed:A\\Denied2:z",
                                           "key_removed:A\\Denied2:"});
        CHECK(d.baseline.keys.at(a + "\\Denied") == base.keys.at(a + "\\Denied"));
        CHECK(d.baseline.keys.at(a + "\\Denied\\Deep") == base.keys.at(a + "\\Denied\\Deep"));
        CHECK_FALSE(d.baseline.keys.contains(a + "\\Denied2"));

        // Readable again, it diffs against what was kept: x changed, y removed.
        const auto back = complete({{a, {}},
                                    {a + "\\Denied", {{"x", vread(P::kRegDword, dword(9))}}},
                                    {a + "\\Denied\\Deep", {}}});
        const auto d2 = diff_registry_snapshot(d.baseline, back, root, "notify", win, 21);
        got.clear();
        for (const auto& c : d2.candidates)
            got.insert(c.action + ":" + c.key.substr(root.size() + 1) + ":" + c.value);
        CHECK(got == std::set<std::string>{"changed:A\\Denied:x", "removed:A\\Denied\\Deep:y"});
    }

    SECTION("new data is truncated at kRegistryDataCap and the stored size is the full size") {
        RegistryValueRead big;
        big.type = P::kRegBinary;
        big.full_size = 10'000;
        big.bytes = std::string(10'000, 'a');
        auto read3 = complete({{root + "\\A", {{"Blob", big}}}});
        const auto d = diff_registry_snapshot(first.baseline, read3, root, "notify", win, 20);
        for (const auto& c : d.candidates)
            if (c.value == "Blob") {
                CHECK(c.data.size() <= kRegistryDataCap);
                CHECK(c.data_truncated);
                CHECK(c.size == 10'000);
            }
    }
}

TEST_CASE("RegistryReadBudget caps keys and values and bytes (R9)", "[echo][registry][pure]") {
    {
        RegistryReadBudget b;
        bool all_admitted = true;
        for (std::size_t i = 0; i < kBaselineKeyCap; ++i)
            all_admitted = b.admit_key() && all_admitted; // every call is made
        CHECK(all_admitted);       // the first 20,000 keys are admitted ...
        CHECK_FALSE(b.admit_key()); // ... the 20,001st is not
    }
    {
        RegistryReadBudget b;
        CHECK(b.admit_value(kBaselineBytesCap));
        CHECK_FALSE(b.admit_value(1)); // per-root byte cap exceeded -> the reader returns Capped
    }
    CHECK(RegistryReadBudget::depth_ok(kBaselineDepthCap));
    CHECK_FALSE(RegistryReadBudget::depth_ok(kBaselineDepthCap + 1));
}

TEST_CASE("RegistryDirtyTable stamps the burst at notify time and its bounded wait sees a mark",
          "[echo][registry][pure]") {
    RegistryDirtyTable d;
    const std::string r = "HKLM\\SOFTWARE\\yuzu_test_r";
    CHECK_FALSE(d.peek_dirty(r));
    CHECK(d.last(r) == 0);
    d.mark(r, 5);
    d.mark(r, 7); // a second notify in the same burst never moves `first`, but moves `last`
    d.mark(r, 6); // and `last` only moves forward
    CHECK(d.peek_dirty(r));
    CHECK(d.last(r) == 7);
    const auto snap = d.take(r);
    CHECK(snap.dirty);
    CHECK(snap.first == 5);
    CHECK_FALSE(d.peek_dirty(r)); // taken: clean until the next notify
    CHECK(d.last(r) == 7);        // a notify during a read still extends that read's window
    d.restore(r, snap);           // a failed commit puts the burst back
    CHECK(d.peek_dirty(r));
    CHECK(d.take(r).first == 5);

    // The wait is bounded and never polls: a deadline already past returns false at once ...
    CHECK_FALSE(d.wait_dirty_for_test(r, std::chrono::steady_clock::now()));
    // ... and a mark from another thread wakes it, whichever side runs first.
    std::thread marker([&] { d.mark(r, 20); });
    CHECK(d.wait_dirty_for_test(r, std::chrono::steady_clock::now() + std::chrono::seconds(30)));
    marker.join();
}

TEST_CASE("attribute_candidate: correlation on value name, type, size and window",
          "[echo][registry][pure]") {
    const auto c = cand("changed", "Start", 4, 4, 100, 200);

    SECTION("a single writer is named") {
        const auto a = attribute_candidate(
           c, {ev(150, 812, RegistryEtwOp::Set, "Start", 4, 4, "services.exe")});
        CHECK(a.kind == AttributionKind::Corr);
        CHECK(a.pid == 812);
        CHECK(a.image == "services.exe");
    }
    SECTION("two writers of the same signature -> Ambiguous, never guessed") {
        const auto a = attribute_candidate(c, {ev(120, 1, RegistryEtwOp::Set, "Start"),
                                                ev(130, 2, RegistryEtwOp::Set, "Start")});
        CHECK(a.kind == AttributionKind::Ambiguous);
        CHECK(a.n_pids == 2);
        CHECK(a.pid == 0);
        CHECK(a.image.empty());
    }
    SECTION("one pid twice -> the LAST event, events counted") {
        const auto a = attribute_candidate(
           c, {ev(120, 7, RegistryEtwOp::Set, "Start", 4, 4, "old.exe"),
               ev(180, 7, RegistryEtwOp::Set, "Start", 4, 4, "new.exe")});
        CHECK(a.kind == AttributionKind::Corr);
        CHECK(a.image == "new.exe");
        CHECK(a.n_events == 2);
    }
    SECTION("signature mismatch, op mismatch, case-insensitive name") {
        CHECK(attribute_candidate(c, {ev(150, 1, RegistryEtwOp::Set, "Start", 1, 4)}).kind ==
              AttributionKind::None); // different type
        CHECK(attribute_candidate(c, {ev(150, 1, RegistryEtwOp::Set, "Start", 4, 8)}).kind ==
              AttributionKind::None); // different size
        CHECK(attribute_candidate(c, {ev(150, 1, RegistryEtwOp::DeleteValue, "Start")}).kind ==
              AttributionKind::None); // a changed value matches only Set events
        CHECK(attribute_candidate(c, {ev(150, 1, RegistryEtwOp::Set, "start")}).kind ==
              AttributionKind::Corr); // `start` event vs `Start` candidate
        const auto removed = cand("removed", "Start", 4, 0, 100, 200);
        CHECK(attribute_candidate(removed, {ev(150, 1, RegistryEtwOp::Set, "Start")}).kind ==
              AttributionKind::None);
        CHECK(attribute_candidate(removed, {ev(150, 3, RegistryEtwOp::DeleteValue, "Start")}).pid == 3);
    }
    SECTION("names match by a folded digest: both sides canonicalise, and nothing is clipped") {
        CHECK(value_name_key("Start") == value_name_key("sTART"));
        CHECK(value_name_key("Start") != value_name_key("Starts"));
        CHECK(value_name_key("") != value_name_key("Start")); // the default value is a name too
        // an UPPERCASE event name against a lowercase candidate: the reverse of the case above
        CHECK(attribute_candidate(cand("changed", "start", 4, 4, 100, 200),
                                  {ev(150, 1, RegistryEtwOp::Set, "START")})
                 .kind == AttributionKind::Corr);
        // two 16383-character names (the registry maximum) that differ only in their last
        // character are two names: a clipped key would conflate them into a wrong attribution
        const std::string long_a(16383, 'n');
        std::string long_b = long_a;
        long_b.back() = 'm';
        const auto lc = cand("changed", long_a, 4, 4, 100, 200);
        CHECK(attribute_candidate(lc, {ev(150, 1, RegistryEtwOp::Set, long_a)}).kind ==
              AttributionKind::Corr);
        CHECK(attribute_candidate(lc, {ev(150, 1, RegistryEtwOp::Set, long_b)}).kind ==
              AttributionKind::None);
        static_assert(sizeof(ValueNameKey) == 32); // an event is a fixed size whatever its name
    }
    SECTION("the window is (lo, hi]") {
        CHECK(attribute_candidate(c, {ev(100, 1, RegistryEtwOp::Set, "Start")}).kind ==
              AttributionKind::None); // ts == lo is NOT matched
        CHECK(attribute_candidate(c, {ev(200, 1, RegistryEtwOp::Set, "Start")}).kind ==
              AttributionKind::Corr); // ts == hi IS matched
        CHECK(attribute_candidate(c, {ev(201, 1, RegistryEtwOp::Set, "Start")}).kind ==
              AttributionKind::None);
    }
    SECTION("documented residual: a change with NO true event correlates to one unrelated writer") {
        // The candidate was produced by a hive load or a restore (no value-write event). One
        // unrelated process wrote the same signature elsewhere in the registry in the window,
        // so it is correlated. This is the limit docs/user-manual/echo.md states: attr:corr is a
        // lead to verify against $Process_Live, not proof.
        const auto a = attribute_candidate(c, {ev(150, 4242, RegistryEtwOp::Set, "Start")});
        CHECK(a.kind == AttributionKind::Corr);
        CHECK(a.pid == 4242);
    }
    SECTION("key_removed is never attributed, even beside a DeleteKey and a matching DeleteValue") {
        const auto kr = cand("key_removed", "", 0, 0, 100, 200);
        CHECK(attribute_candidate(kr, {ev(150, 9, RegistryEtwOp::DeleteKey, "", 0, 0, "x.exe"),
                                       ev(150, 9, RegistryEtwOp::DeleteValue, "", 0, 0, "x.exe")})
                 .kind == AttributionKind::None);
    }
}

TEST_CASE("stitch_registry_tick: rows, counters, the settle hold and what is NOT recorded",
          "[echo][registry][pure]") {
    const StitchFlags on{true, 0};
    const std::int64_t now = 1000 * SEC;
    const auto c = cand("changed", "Start", 4, 4, 100 * SEC, 110 * SEC);

    SECTION("no candidate, no row: an event with nothing to explain is unused") {
        const auto r = stitch_registry_tick({}, {ev(105 * SEC, 1, RegistryEtwOp::Set, "Start")}, {},
                                            on, now, 1);
        CHECK(r.rows.empty());
        CHECK(r.counters.attributed + r.counters.ambiguous + r.counters.none == 0);
    }
    SECTION("two keys, one pid: only the in-scope candidate is attributed, `Secret` gets no row") {
        const auto evs = std::vector<RegistryEtwEvent>{
           ev(101 * SEC, 5, RegistryEtwOp::Set, "Start", 4, 4, "p.exe"),
           ev(102 * SEC, 5, RegistryEtwOp::Set, "Start", 4, 4, "p.exe"),
           ev(103 * SEC, 5, RegistryEtwOp::Set, "Secret", 1, 8, "p.exe")};
        const auto r = stitch_registry_tick({c}, evs, {}, on, now, 1);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].actor_pid == 5);
        CHECK(r.rows[0].actor_image == "p.exe");
        CHECK(r.rows[0].detail == "attr:corr;events:2");
        CHECK(r.rows[0].value_name == "Start");
    }
    SECTION("two pids: attr:ambiguous:2 and no actor") {
        const auto r = stitch_registry_tick({c},
                                            {ev(101 * SEC, 5, RegistryEtwOp::Set, "Start"),
                                             ev(102 * SEC, 6, RegistryEtwOp::Set, "Start")},
                                            {}, on, now, 1);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].detail == "attr:ambiguous:2");
        CHECK(r.rows[0].actor_pid == 0);
        CHECK(r.rows[0].actor_image.empty());
        CHECK(r.counters.ambiguous == 1);
    }
    SECTION("key_removed stays attr:none even with an in-window DeleteKey from the same handle") {
        const auto kr = cand("key_removed", "", 0, 0, 100 * SEC, 110 * SEC);
        const auto r = stitch_registry_tick(
           {kr}, {ev(105 * SEC, 9, RegistryEtwOp::DeleteKey, "", 0, 0, "x.exe")}, {}, on, now, 1);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].detail == "attr:none");
        CHECK(r.rows[0].actor_pid == 0);
    }
    SECTION("settle hold: 4 s after the window stays held, 5 s finalises") {
        const auto held = stitch_registry_tick({c}, {}, {}, on, c.window_hi + 4 * SEC, 1);
        CHECK(held.rows.empty());
        CHECK(held.held_next.size() == 1);
        const auto done = stitch_registry_tick({c}, {}, {}, on, c.window_hi + 5 * SEC, 1);
        CHECK(done.rows.size() == 1);
        CHECK(done.held_next.empty());
    }
    SECTION("off and lost-restart are written at once; a loss epoch or a clean window keeps waiting") {
        const std::int64_t at = c.window_hi + SEC; // 1 s after the window closed: inside the settle
        const auto off = stitch_registry_tick({c}, {}, {}, StitchFlags{false, 0}, at, 1);
        REQUIRE(off.rows.size() == 1);
        CHECK(off.rows[0].detail == "attr:off");
        CHECK(off.held_next.empty());
        const auto lost = stitch_registry_tick({c}, {}, {}, StitchFlags{true, c.window_lo + 1}, at, 1);
        REQUIRE(lost.rows.size() == 1);
        CHECK(lost.rows[0].detail == "attr:lost-restart");
        CHECK(lost.held_next.empty());
        // neither of those consults an event, so waiting cannot change them; a loss epoch can
        // still be recorded by a later tick, so a degraded candidate is held like any other
        const auto degraded = stitch_registry_tick({c}, {}, {LossEpoch{c.window_lo + 1, c.window_hi}}, on,
                                                   at, 1);
        CHECK(degraded.rows.empty());
        CHECK(degraded.held_next.size() == 1);
        // events_since 0 means "n/a", never a restart
        CHECK(stitch_registry_tick({c}, {}, {}, on, at, 1).held_next.size() == 1);
    }
    SECTION("loss epochs degrade a window they intersect, whenever they were recorded") {
        const auto evs = std::vector<RegistryEtwEvent>{ev(105 * SEC, 5, RegistryEtwOp::Set, "Start")};
        auto r = stitch_registry_tick({c}, evs, {LossEpoch{101 * SEC, 102 * SEC}}, on, now, 1);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].detail == "attr:degraded");
        CHECK(r.rows[0].actor_pid == 0); // never an actor from a degraded window
        r = stitch_registry_tick({c}, evs, {LossEpoch{500 * SEC, 600 * SEC}}, on, now, 1);
        CHECK(r.rows[0].detail == "attr:corr"); // a disjoint epoch changes nothing
    }
    SECTION("precedence: lost-restart > off > degraded > the correlation outcome") {
        const auto evs = std::vector<RegistryEtwEvent>{ev(105 * SEC, 5, RegistryEtwOp::Set, "Start")};
        const std::vector<LossEpoch> hit{{101 * SEC, 102 * SEC}};
        auto r = stitch_registry_tick({c}, evs, hit, StitchFlags{false, 0}, now, 1);
        CHECK(r.rows[0].detail == "attr:off"); // off beats degraded
        CHECK(r.rows[0].actor_pid == 0);
        // the buffer began after the window opened -> the early part of the window is unobserved
        r = stitch_registry_tick({c}, evs, hit, StitchFlags{false, 105 * SEC}, now, 1);
        CHECK(r.rows[0].detail == "attr:lost-restart"); // lost-restart beats off
        r = stitch_registry_tick({c}, evs, {}, StitchFlags{true, 105 * SEC}, now, 1);
        CHECK(r.rows[0].detail == "attr:lost-restart");
        CHECK(r.rows[0].actor_pid == 0);
    }
    SECTION("counters") {
        const auto r = stitch_registry_tick(
           {c, cand("changed", "Other", 4, 4, 100 * SEC, 110 * SEC)},
           {ev(105 * SEC, 5, RegistryEtwOp::Set, "Start")}, {}, on, now, 1);
        CHECK(r.counters.attributed == 1);
        CHECK(r.counters.none == 1);
    }
    SECTION("the row keeps the diff's record_key whatever the attribution") {
        const auto corr = stitch_registry_tick({c}, {ev(105 * SEC, 5, RegistryEtwOp::Set, "Start")}, {},
                                               on, now, 1);
        const auto none = stitch_registry_tick({c}, {}, {}, on, now, 1);
        const auto off = stitch_registry_tick({c}, {}, {}, StitchFlags{false, 0}, now, 1);
        REQUIRE(corr.rows.size() == 1);
        CHECK(corr.rows[0].record_key == none.rows[0].record_key);
        CHECK(corr.rows[0].record_key == off.rows[0].record_key);
        CHECK(corr.rows[0].record_key ==
              registry_diff_record_key(c.source, c.observed_at, c.action, c.key, c.value));
    }
}

TEST_CASE("loss epochs: age out, intersect on a (lo, hi] window, collapse past the cap",
          "[echo][registry][pure]") {
    std::vector<LossEpoch> epochs{{1, 2}, {10, 20}};
    age_loss_epochs(epochs, 5);
    CHECK(epochs == std::vector<LossEpoch>{{10, 20}});
    for (std::int64_t i = 0; i < 64; ++i) // 1 + 64 = 65 epochs
        append_loss_epoch(epochs, {100 + i * 10, 105 + i * 10});
    REQUIRE(epochs.size() == 1); // past kLossEpochCap: one covering interval
    CHECK(epochs[0].lo == 10);
    CHECK(epochs[0].hi == 100 + 63 * 10 + 5);

    const auto w = cand("changed", "v", 4, 4, 100, 200); // the window (100, 200]
    CHECK(intersects_loss(w, {LossEpoch{200, 300}}));       // the epoch starts at the window's end
    CHECK_FALSE(intersects_loss(w, {LossEpoch{201, 300}})); // after it
    CHECK_FALSE(intersects_loss(w, {LossEpoch{50, 100}}));  // ends where the window opens
    CHECK(intersects_loss(w, {LossEpoch{50, 101}}));
}

TEST_CASE("RegistryEtwBuffer retires by sequence identity and counts what it evicts (R4)",
          "[echo][registry][pure]") {
    RegistryEtwBuffer buf(4);
    for (int i = 1; i <= 4; ++i)
        buf.push(ev(i * 10, 1, RegistryEtwOp::Set, "v"));
    const auto batch = buf.snapshot();
    REQUIRE(batch.items.size() == 4);
    buf.push(ev(50, 1, RegistryEtwOp::Set, "v")); // evicts ts=10, which IS in the batch
    CHECK(buf.drop_info().count == 1);
    CHECK(buf.drop_info().ts_lo == 10);
    CHECK(buf.drop_info().ts_hi == 10);
    buf.retire(batch.last_seq, [](const RegistryEtwEvent&) { return true; });
    // Position-based retirement would erase the first 4 of the 4 survivors, i.e. take the
    // post-snapshot entry with it. By sequence, only the batch's survivors go.
    const auto left = buf.snapshot();
    REQUIRE(left.items.size() == 1);
    CHECK(left.items[0].ts100ns == 50);

    SECTION("the drop range widens, and resets only when nothing newer was evicted") {
        RegistryEtwBuffer b(1);
        b.push(ev(100, 1, RegistryEtwOp::Set, "v"));
        b.push(ev(200, 1, RegistryEtwOp::Set, "v")); // evicts 100
        b.push(ev(300, 1, RegistryEtwOp::Set, "v")); // evicts 200
        const auto d = b.drop_info();
        CHECK(d.count == 2);
        CHECK(d.ts_lo == 100);
        CHECK(d.ts_hi == 200);
        b.push(ev(400, 1, RegistryEtwOp::Set, "v")); // evicts 300 after `d` was read
        b.reset_drop_range(d.count);                 // stale count: the newer eviction keeps its range
        CHECK(b.drop_info().ts_hi == 300);
        b.reset_drop_range(b.drop_info().count);
        CHECK(b.drop_info().ts_lo == 0);
        CHECK(b.drop_info().ts_hi == 0);
        CHECK(b.drop_info().count == 3); // the count is cumulative
    }
    SECTION("pause discards and refuses; resume accepts again") {
        RegistryEtwBuffer b;
        b.push(ev(1, 1, RegistryEtwOp::Set, "v"));
        b.pause();
        CHECK(b.size() == 0);
        b.push(ev(2, 1, RegistryEtwOp::Set, "v"));
        CHECK(b.size() == 0);
        CHECK(b.pushed() == 1); // a refused push is not counted
        b.resume();
        b.push(ev(3, 1, RegistryEtwOp::Set, "v"));
        CHECK(b.size() == 1);
    }
    SECTION("the bounded wait sees a matching event and never polls") {
        RegistryEtwBuffer b;
        const auto is_v = [](const RegistryEtwEvent& e) { return e.value_key == value_name_key("v"); };
        CHECK_FALSE(b.wait_for_event(is_v, std::chrono::steady_clock::now())); // past deadline: at once
        b.push(ev(1, 1, RegistryEtwOp::Set, "v"));
        CHECK(b.wait_for_event(is_v, std::chrono::steady_clock::now() + std::chrono::seconds(30)));
        CHECK_FALSE(b.wait_for_event(
           [](const RegistryEtwEvent& e) { return e.value_key == value_name_key("w"); },
           std::chrono::steady_clock::now()));
    }
}

TEST_CASE("retention rule (R5): the watermark and held windows decide what is released",
          "[echo][registry][pure]") {
    constexpr auto kMax = std::numeric_limits<std::int64_t>::max();
    const std::map<std::string, std::int64_t> none; // no root has an unread notify
    std::map<std::string, RegistryRootState> roots;
    CHECK(retention_watermark(roots, none) == kMax); // no roots
    roots["a"].window_base = 100;
    roots["b"].window_base = 0; // never completely read, idle: it holds nothing back (see the rule)
    CHECK(retention_watermark(roots, none) == 100);
    roots["a"].window_base = 0;
    CHECK(retention_watermark(roots, none) == kMax); // none to protect
    roots["a"].window_base = 100;
    roots["b"].window_base = 200;
    CHECK(retention_watermark(roots, none) == 100);

    RegistryEtwBuffer buf;
    for (std::int64_t ts : {50, 90, 100, 150})
        buf.push(ev(ts, 1, RegistryEtwOp::Set, "v"));
    std::vector<RegistryCandidate> held{cand("changed", "v", 4, 4, 80, 95)};
    const auto batch = buf.snapshot();
    buf.retire(batch.last_seq, [&](const RegistryEtwEvent& e) {
        return release_event(e, retention_watermark(roots, none), held);
    });
    std::set<std::int64_t> kept;
    for (const auto& e : buf.snapshot().items)
        kept.insert(e.ts100ns);
    // 50: older than the watermark and outside every held window -> released.
    // 90: older than the watermark but inside the held window (80, 95] -> kept.
    // 100: at the watermark -> released. 150: newer than the watermark -> kept even with no
    // held window (root `a` may still produce a candidate whose window reaches it).
    CHECK(kept == std::set<std::int64_t>{90, 150});
}

TEST_CASE("retention floor: a never-complete root holds it only while it has an unread notify",
          "[echo][registry][pure]") {
    constexpr std::int64_t kSlack = kEtwWindowSlack100ns;
    const std::map<std::string, std::int64_t> none;
    std::map<std::string, RegistryRootState> roots;
    roots["a"].window_base = 5 * kSlack;
    roots["b"].window_base = 0;

    // b's next read builds a narrow candidate from `first`, so its window starts at
    // first - slack: the floor drops to exactly that, and no lower
    CHECK(retention_watermark(roots, {{"b", 3 * kSlack}}) == 2 * kSlack);
    // a burst starting within a slack of 0 floors at 0: nothing of it can be released
    CHECK(retention_watermark(roots, {{"b", kSlack / 2}}) == 0);
    // read (or never marked): the complete roots alone again
    CHECK(retention_watermark(roots, none) == 5 * kSlack);
    // a stamp for a root that left the scope does not take part
    CHECK(retention_watermark(roots, {{"gone", 1}}) == 5 * kSlack);
    // every root idle and never complete: nothing to protect
    roots["a"].window_base = 0;
    CHECK(retention_watermark(roots, none) == std::numeric_limits<std::int64_t>::max());

    // An unread notify never lowers a root that has a window_base: its next window is
    // max(window_base, first - slack) >= window_base, which is already counted.
    roots["a"].window_base = 100 * kSlack;
    roots["b"].window_base = 0;
    CHECK(retention_watermark(roots, {{"a", 50 * kSlack}}) == 100 * kSlack);
    CHECK(retention_watermark(roots, {{"a", 500 * kSlack}}) == 100 * kSlack);
}

TEST_CASE("record keys are length-framed and never carry a NUL", "[echo][registry][pure]") {
    const auto k1 = registry_diff_record_key("notify", 5, "added", "A:B", "C");
    const auto k2 = registry_diff_record_key("notify", 5, "added", "A", "B:C");
    CHECK(k1 != k2);
    CHECK(registry_diff_record_key("notify", 5, "added", "K", "a\\b") !=
          registry_diff_record_key("notify", 5, "added", "K", "a\\\\b"));
    const auto nul = registry_diff_record_key("notify", 5, "added", std::string("K\0x", 3), "v");
    CHECK(nul.find('\0') == std::string::npos);
    CHECK(registry_diff_record_key("notify", 5, "added", "K", "v") ==
          registry_diff_record_key("notify", 5, "added", "K", "v")); // stable, no attribution input
    CHECK(registry_gap_record_key("restart", "123") == "gap:restart:123");
    CHECK(registry_gap_record_key("loss", "123") == "gap:loss:123");
    CHECK(registry_gap_record_key("baselinelost", "HKLM\\R:5") !=
          registry_gap_record_key("restart", "HKLM\\R:5"));

    // The row's key is the diff key of what changed, never a function of the actor columns.
    RegistryCandidate c;
    c.key = "HKLM\\SOFTWARE\\r\\Svc";
    c.value = "Start";
    c.action = "changed";
    c.source = "notify";
    c.observed_at = T0;
    const auto plain = registry_row_from_candidate(c, 0, {}, "attr:none", 1);
    CHECK(plain.actor_pid == 0);
    CHECK(plain.actor_image.empty());
    CHECK(plain.detail == "attr:none");
    CHECK(plain.record_key == registry_diff_record_key("notify", T0, "changed", c.key, c.value));
    CHECK(plain.record_key ==
          registry_row_from_candidate(c, 812, "p.exe", "attr:corr", 1).record_key);
}

TEST_CASE("cursor and baseline codecs", "[echo][registry][pure]") {
    RegistryCursor cur;
    cur.present = true;
    cur.tick = 7;
    cur.ccs = "ControlSet001";
    cur.hku = {"S-1-5-21-1"};
    cur.roots["HKLM\\R"] = RegistryRootState{
       true, 100, 110, 120, "complete", false, {"HKLM\\R\\Denied", "HKLM\\R\\Denied2"}};
    cur.loss = {{5, 9}};
    auto held = cand("changed", "Start", 4, 4, 10, 20);
    held.has_prev = true;
    held.prev_data = "1";
    held.data = std::string("a\xff") + "b"; // not valid UTF-8: must not stop the cursor being written
    cur.held = {held};
    const auto json = encode_registry_cursor(cur);
    // A held candidate or a loss epoch makes this version 2: a build that predates them reads
    // only version 1, so it takes the cursor as lost (a gap row and a re-baseline) instead of
    // re-encoding it without the changes it holds. Without either it stays version 1. Each of
    // the two alone must select version 2: a held candidate with no loss epoch is the common
    // case, and an encoder keyed on the loss list alone would write it as version 1. The
    // old-reader half (a version-1-only decode taking version 2 as malformed) cannot run in
    // this tree, which has the one codec; its analogues are the version-3 check below and the
    // malformed-cursor case in the lost-cursor lifecycle test (one gap:cursorlost row).
    CHECK(nlohmann::json::parse(json).at("v").get<int>() == 2);
    auto bare = cur;
    bare.held.clear();
    CHECK(nlohmann::json::parse(encode_registry_cursor(bare)).at("v").get<int>() == 2); // loss alone
    auto held_only = cur;
    held_only.loss.clear();
    CHECK(nlohmann::json::parse(encode_registry_cursor(held_only)).at("v").get<int>() == 2); // held alone
    bare.loss.clear();
    CHECK(nlohmann::json::parse(encode_registry_cursor(bare)).at("v").get<int>() == 1);
    CHECK_FALSE(decode_registry_cursor(encode_registry_cursor(bare)).malformed);
    auto future = nlohmann::json::parse(json);
    future["v"] = 3; // a version this build does not know
    CHECK(decode_registry_cursor(future.dump()).malformed);
    const auto back = decode_registry_cursor(json);
    CHECK_FALSE(back.malformed);
    CHECK(back.tick == 7);
    CHECK(back.ccs == "ControlSet001");
    CHECK(back.roots.at("HKLM\\R") == cur.roots.at("HKLM\\R"));
    CHECK(back.loss == cur.loss);
    REQUIRE(back.held.size() == 1);
    CHECK(back.held[0].root == held.root);
    CHECK(back.held[0].key == held.key);
    CHECK(back.held[0].prev_data == "1");
    CHECK(back.held[0].window_lo == 10);
    CHECK(back.held[0].window_hi == 20);
    CHECK(back.hku == cur.hku);
    // the invalid byte became U+FFFD on the way out; from then on the text is stable
    CHECK(encode_registry_cursor(back) == encode_registry_cursor(decode_registry_cursor(encode_registry_cursor(back))));

    CHECK_FALSE(decode_registry_cursor(std::nullopt).present); // absent, not malformed
    CHECK_FALSE(decode_registry_cursor(std::nullopt).malformed);
    for (const char* bad : {"", "garbage", "{\"v\":1}", "[]"})
        CHECK(decode_registry_cursor(std::string(bad)).malformed);
    // a cursor written before `skipped` existed decodes with the set empty
    auto older = nlohmann::json::parse(json);
    older["roots"]["HKLM\\R"].erase("skipped");
    CHECK(decode_registry_cursor(older.dump()).roots.at("HKLM\\R").skipped.empty());
    // a cursor written before window_base, held and loss existed (the key-watch-only source)
    // decodes as present and not malformed -- a malformed one would re-baseline every root
    auto v1 = nlohmann::json::parse(json);
    v1["v"] = 1;
    v1.erase("held");
    v1.erase("loss");
    v1["roots"]["HKLM\\R"].erase("window_base");
    const auto upgraded = decode_registry_cursor(v1.dump());
    CHECK(upgraded.present);
    CHECK_FALSE(upgraded.malformed);
    CHECK(upgraded.held.empty());
    CHECK(upgraded.loss.empty());
    CHECK(upgraded.roots.at("HKLM\\R").window_base == 0);
    CHECK(upgraded.tick == 7);
    // ... but a held or loss element that is present and unusable is a lost cursor
    auto bad_held = nlohmann::json::parse(json);
    bad_held["held"] = nlohmann::json::array({nlohmann::json::object({{"r", "x"}})});
    CHECK(decode_registry_cursor(bad_held.dump()).malformed);
    auto bad_loss = nlohmann::json::parse(json);
    bad_loss["loss"] = nlohmann::json::array({nlohmann::json::array({1})});
    CHECK(decode_registry_cursor(bad_loss.dump()).malformed);
    // an unknown field is ignored, so a later build can add state to this cursor
    auto j = nlohmann::json::parse(json);
    j["later_field"] = nlohmann::json::array({1, 2});
    CHECK_FALSE(decode_registry_cursor(j.dump()).malformed);
    // a window that is negative or inverted (a corrupt or tampered row) is clamped to a valid
    // one, so the stitch's `now - window_hi` can never overflow
    auto tampered = nlohmann::json::parse(json);
    tampered["held"][0]["lo"] = std::numeric_limits<std::int64_t>::min();
    tampered["held"][0]["hi"] = std::numeric_limits<std::int64_t>::min();
    auto clamped = decode_registry_cursor(tampered.dump());
    REQUIRE(clamped.held.size() == 1);
    CHECK(clamped.held[0].window_lo == 0);
    CHECK(clamped.held[0].window_hi == 0);
    tampered["held"][0]["lo"] = 50;
    tampered["held"][0]["hi"] = 10;
    clamped = decode_registry_cursor(tampered.dump());
    REQUIRE(clamped.held.size() == 1);
    CHECK(clamped.held[0].window_hi == clamped.held[0].window_lo);
    // bytes that are not valid UTF-8 must never decide whether the cursor can be written
    cur.hku.push_back(std::string("S-\xff"));
    CHECK_NOTHROW(encode_registry_cursor(cur));

    RegistryBaseline b;
    b.keys["K"]["v"] = baseline_entry_from_bytes(4, 4, dword(1), false);
    const auto bj = encode_registry_baseline(b);
    const auto bd = decode_registry_baseline(bj);
    CHECK_FALSE(bd.malformed);
    CHECK(bd.baseline == b);
    CHECK_FALSE(decode_registry_baseline(std::nullopt).malformed);
    CHECK(decode_registry_baseline(std::string("{\"v\":1")).malformed);
    CHECK(decode_registry_baseline(std::string("{\"v\":1,\"keys\":{\"K\":{\"v\":{\"t\":\"x\"}}}}")).malformed);
    b.keys["K"]["v"].d = std::string("a\xff") + "b"; // a rendered prefix that is not valid UTF-8
    CHECK_NOTHROW(encode_registry_baseline(b));
}


// ── Offline (unloaded) hives: the pure core ─────────────────────────────────

namespace {

const std::string kSidA = "S-1-5-21-1";
const std::string kSidB = "S-1-5-21-2";
const std::string kSuffix = "Software\\yuzu_test_u";
const std::string kSuffix2 = "Software\\yuzu_test_u2";

std::string uroot(const std::string& sid, const std::string& suffix = kSuffix) {
    return "HKU\\" + sid + "\\" + suffix;
}
OfflineProfile prof(const std::string& sid) { return {sid, "C:\\Users\\" + sid}; }

} // namespace

TEST_CASE("roots_for: loaded sids, then offline sids, same suffixes, each sid once",
          "[echo][registry][pure]") {
    const RegistryScope sc{{"SOFTWARE\\yuzu_test_r"}, {kSuffix, kSuffix2}};
    const auto roots = sc.roots_for({kSidA}, {prof(kSidB)});
    REQUIRE(roots.size() == 5);
    CHECK(roots[0] == "HKLM\\SOFTWARE\\yuzu_test_r");
    CHECK(roots[1] == uroot(kSidA));
    CHECK(roots[2] == uroot(kSidA, kSuffix2));
    CHECK(roots[3] == uroot(kSidB)); // the offline root is named exactly like a loaded one
    CHECK(roots[4] == uroot(kSidB, kSuffix2));

    // a sid in BOTH lists (and an offline duplicate) is emitted once, from the loaded list
    CHECK(sc.roots_for({kSidA}, {prof(kSidA), prof(kSidB), prof(kSidB)}).size() == 5);
    // the one-argument overload is the loaded list alone
    CHECK(sc.roots_for({kSidA}).size() == 3);

    // `.bak`, `_Classes`, `.DEFAULT` and the temporary mounts sibling plugins make are not profiles
    const auto none = sc.roots_for({}, {prof(kSidA + ".bak"), prof(kSidA + "_Classes"),
                                        prof(".DEFAULT"), prof("YUZU_HIVE_" + kSidA + "_1_2")});
    CHECK(none.size() == 1); // HKLM only

    CHECK(is_offline_root(uroot(kSidB), {prof(kSidB)}));
    CHECK_FALSE(is_offline_root(uroot(kSidA), {prof(kSidB)}));
    CHECK_FALSE(is_offline_root("HKLM\\SOFTWARE\\yuzu_test_r", {prof(kSidB)}));
    CHECK_FALSE(is_offline_root(uroot(kSidB + "9"), {prof(kSidB)})); // sid component, not a prefix
}

TEST_CASE("reconcile_offline: a complete walk replaces, an incomplete one keeps, a loaded sid never stays",
          "[echo][registry][pure]") {
    const std::vector<OfflineProfile> known{prof(kSidA), prof(kSidB)};

    OfflineDiscovery complete;
    complete.profiles = {prof(kSidA)};
    CHECK(reconcile_offline(known, {}, {}, complete) == std::vector<OfflineProfile>{prof(kSidA)});

    OfflineDiscovery incomplete;
    incomplete.complete = false;
    CHECK(reconcile_offline(known, {}, {}, incomplete) == known);

    // a sid whose record exists but whose path was unreadable keeps its cursor entry
    OfflineDiscovery partial;
    partial.partial = {kSidB};
    partial.profiles = {prof(kSidA)};
    CHECK(reconcile_offline(known, {}, {}, partial) == known);
    // ... but not when it is NOT named: a complete walk that omits it says the profile is gone
    CHECK(reconcile_offline(known, {}, {}, complete).size() == 1);

    // a loaded sid is removed in every case
    CHECK(reconcile_offline(known, {}, {kSidA}, incomplete) ==
          std::vector<OfflineProfile>{prof(kSidB)});
    CHECK(reconcile_offline(known, {}, {kSidA}, partial) ==
          std::vector<OfflineProfile>{prof(kSidB)});
    complete.profiles = {prof(kSidA), prof(kSidB)};
    CHECK(reconcile_offline(known, {}, {kSidA, kSidB}, complete).empty());
}

TEST_CASE("reconcile_offline: a sid loaded last tick and gone now is a known profile with no path yet, unless a complete walk names it nowhere",
          "[echo][registry][pure]") {
    const OfflineProfile unpathed{kSidA, ""};
    const std::vector<std::string> was_loaded{kSidA};

    // incomplete walk: carried with an empty path
    OfflineDiscovery incomplete;
    incomplete.complete = false;
    CHECK(reconcile_offline({}, was_loaded, {}, incomplete) ==
          std::vector<OfflineProfile>{unpathed});

    // complete walk whose record for it failed to read: carried
    OfflineDiscovery partial;
    partial.partial = {kSidA};
    CHECK(reconcile_offline({}, was_loaded, {}, partial) == std::vector<OfflineProfile>{unpathed});

    // complete walk that lists it: the walk's path replaces the empty one
    OfflineDiscovery listed;
    listed.profiles = {prof(kSidA)};
    CHECK(reconcile_offline({}, was_loaded, {}, listed) ==
          std::vector<OfflineProfile>{prof(kSidA)});

    // complete walk that names it nowhere: authoritative, the profile left ProfileList
    CHECK(reconcile_offline({}, was_loaded, {}, OfflineDiscovery{}).empty());

    // still loaded: never offline
    CHECK(reconcile_offline({}, was_loaded, was_loaded, incomplete).empty());

    // a real known entry wins over the empty one, on an incomplete walk and on a complete one
    // that names the sid in `partial` (its record failed to read this time)
    CHECK(reconcile_offline({prof(kSidA)}, was_loaded, {}, incomplete) ==
          std::vector<OfflineProfile>{prof(kSidA)});
    CHECK(reconcile_offline({prof(kSidA)}, was_loaded, {}, partial) ==
          std::vector<OfflineProfile>{prof(kSidA)});

    // HKU names that are not profiles (`<sid>_Classes`, `.DEFAULT`) leave HKU at logoff too
    CHECK(reconcile_offline({}, {kSidA + "_Classes", ".DEFAULT"}, {}, incomplete).empty());
}

TEST_CASE("reconcile_offline: an incomplete walk ADDS the profiles it listed and never removes one",
          "[echo][registry][pure]") {
    // A host with more ProfileList entries than the walk's cap is incomplete on every walk, yet the
    // profiles it does reach must be discovered; only a complete walk may remove scope.
    OfflineDiscovery cut;
    cut.complete = false;
    cut.profiles = {prof(kSidA), prof(kSidB)};
    CHECK(reconcile_offline({}, {}, {}, cut) == std::vector<OfflineProfile>{prof(kSidA), prof(kSidB)});

    // a known profile the cut walk did not reach stays; one it listed is not duplicated
    const std::string sid_c = "S-1-5-21-3";
    CHECK(reconcile_offline({prof(sid_c), prof(kSidA)}, {}, {}, cut) ==
          std::vector<OfflineProfile>{prof(sid_c), prof(kSidA), prof(kSidB)});

    // a known entry keeps its own path (an incomplete walk does not re-point it) ...
    const OfflineProfile moved{kSidA, "D:\\moved"};
    CHECK(reconcile_offline({prof(kSidA)}, {}, {}, OfflineDiscovery{false, {}, {moved}}) ==
          std::vector<OfflineProfile>{prof(kSidA)});
    // ... unless it has none yet (it logged off while the walk was cut short): the walk supplies it
    CHECK(reconcile_offline({{kSidA, ""}}, {}, {}, OfflineDiscovery{false, {}, {moved}}) ==
          std::vector<OfflineProfile>{moved});

    // a loaded sid is never added
    CHECK(reconcile_offline({}, {}, {kSidA}, cut) == std::vector<OfflineProfile>{prof(kSidB)});
}

TEST_CASE("is_virtual_service_sid: service, app-pool, VM, Window Manager and Font Driver Host SIDs, not users",
          "[echo][registry][pure]") {
    for (const char* sid : {"S-1-5-80-1-2-3", "S-1-5-82-1-2", "S-1-5-83-0-1", "S-1-5-90-0-1", "S-1-5-96-0-1"})
        CHECK(is_virtual_service_sid(sid));
    for (const char* sid : {"S-1-5-21-1-2-3-1001", "S-1-12-1-1-2-3-4", "S-1-5-18", "S-1-5-8", "S-1-5-800-1",
                            "S-1-5-82", ""})
        CHECK_FALSE(is_virtual_service_sid(sid));
}

TEST_CASE("classify_offline_discovery: a <sid>.bak record is its base sid's partial, never a profile; a virtual service SID is never offline",
          "[echo][registry][pure]") {
    using yuzu::profiles::HiveState;
    using yuzu::profiles::ProfileInfo;
    const std::string entra = "S-1-12-1-1-2-3-4";
    const auto info = [](const std::string& sid, std::string path) {
        return ProfileInfo{sid, "", std::move(path), HiveState::not_loaded, false};
    };
    const std::vector<ProfileInfo> profiles{
       info(kSidA + ".bak", "C:\\Users\\a.bak"), // the temporary-profile leftover of A
       info(kSidB, "C:\\Users\\b"),
       info(entra, "C:\\Users\\entra"),          // an Entra user: S-1-12-1-*, listed
       info("S-1-5-82-1-2", "C:\\Users\\DefaultAppPool"),
       info("S-1-5-80-9", "C:\\Windows\\ServiceProfiles\\x"),
    };
    const std::vector<std::string> failed{"S-1-5-82-7", kSidB + ".bak"};
    const auto d = classify_offline_discovery(true, false, false, profiles, failed);
    CHECK(d.complete);
    CHECK(d.profiles == std::vector<OfflineProfile>{{kSidB, "C:\\Users\\b"}, {entra, "C:\\Users\\entra"}});
    // A is proved to exist by its .bak record (partial: its known entry stands), but is not a
    // profile of this walk; the virtual service SIDs are in neither list
    CHECK(d.partial == std::vector<std::string>{kSidA, kSidB + ".bak"});
    // so a complete walk that saw only A's .bak (mid-rename) keeps A's known baseline scope
    CHECK(reconcile_offline({prof(kSidA)}, {}, {}, d) ==
          std::vector<OfflineProfile>{{kSidB, "C:\\Users\\b"}, {entra, "C:\\Users\\entra"}, prof(kSidA)});
}

TEST_CASE("classify_offline_discovery: a loaded profile is skipped, an unreadable path is partial, a cut walk or a failed root is incomplete",
          "[echo][registry][pure]") {
    using yuzu::profiles::HiveState;
    using yuzu::profiles::ProfileInfo;
    const std::string sid_c = "S-1-5-21-3", sid_d = "S-1-5-21-4", sid_e = "S-1-5-21-5",
                      sid_f = "S-1-5-21-6";
    const auto info = [](const std::string& sid, HiveState st, std::string path,
                         bool unreadable = false) {
        return ProfileInfo{sid, "", std::move(path), st, unreadable};
    };
    const std::vector<ProfileInfo> profiles{
       info(kSidA, HiveState::loaded, "C:\\Users\\a"),               // logged in: not offline
       info(kSidB, HiveState::not_loaded, "C:\\Users\\b"),           // offline
       info(sid_c, HiveState::loaded_classes_only, "C:\\Users\\c"),  // its NTUSER.DAT is not loaded
       info(sid_d, HiveState::not_loaded, "C:\\Users\\d", true),     // path unreadable: partial
       info(sid_e, HiveState::not_loaded, ""),                         // no path: partial
    };
    const std::vector<std::string> none;

    // a complete walk: loaded skipped, a path-less profile partial (its cursor entry stands)
    const auto d = classify_offline_discovery(true, false, false, profiles, none);
    CHECK(d.complete);
    CHECK(d.profiles ==
          std::vector<OfflineProfile>{{kSidB, "C:\\Users\\b"}, {sid_c, "C:\\Users\\c"}});
    CHECK(d.partial == std::vector<std::string>{sid_d, sid_e});
    const std::vector<OfflineProfile> known{prof(sid_d), prof(sid_f)};
    CHECK(reconcile_offline(known, {}, {}, d) ==
          std::vector<OfflineProfile>{
             {kSidB, "C:\\Users\\b"}, {sid_c, "C:\\Users\\c"}, prof(sid_d)});

    // a record that failed to read is partial too, once (named by the walk and by the list)
    const std::vector<std::string> failed{sid_d, sid_f};
    CHECK(classify_offline_discovery(true, false, false, profiles, failed).partial ==
          std::vector<std::string>{sid_d, sid_e, sid_f});

    // a walk cut short, or stopped at the profile cap, is incomplete but still lists what it saw
    for (const auto& [walk_complete, truncated] :
         {std::pair{false, false}, std::pair{true, true}}) {
        INFO("walk_complete=" << walk_complete << " truncated=" << truncated);
        const auto cut =
           classify_offline_discovery(walk_complete, false, truncated, profiles, none);
        CHECK_FALSE(cut.complete);
        CHECK(cut.profiles.size() == 2);
        CHECK(cut.partial == std::vector<std::string>{sid_d, sid_e});
    }

    // ProfileList could not be opened: nothing was walked, so nothing is reported
    const auto root = classify_offline_discovery(false, true, false, profiles, failed);
    CHECK_FALSE(root.complete);
    CHECK(root.profiles.empty());
    CHECK(root.partial.empty());

    // an empty, complete walk is a real answer: no logged-off profile exists
    const auto empty = classify_offline_discovery(true, false, false, {}, none);
    CHECK(empty.complete);
    CHECK(empty.profiles.empty());
    CHECK(empty.partial.empty());
}

TEST_CASE("cursor codec carries `offline` and `deferred`, both optional on decode",
          "[echo][registry][pure]") {
    RegistryCursor cur;
    cur.present = true;
    cur.tick = 3;
    cur.hku = {kSidA};
    cur.offline = {prof(kSidB), {kSidA + "9", "D:\\profiles\\x"}};
    RegistryRootState st;
    st.baselined = true;
    st.status = "unreadable";
    st.deferred = true;
    cur.roots[uroot(kSidB)] = st;
    const auto back = decode_registry_cursor(encode_registry_cursor(cur));
    REQUIRE_FALSE(back.malformed);
    CHECK(back.offline == cur.offline);
    CHECK(back.roots.at(uroot(kSidB)).deferred);
    CHECK(back.roots.at(uroot(kSidB)) == st);

    // not written when empty / false: a cursor without either decodes as before
    RegistryCursor plain;
    plain.present = true;
    plain.roots["HKLM\\R"] = RegistryRootState{};
    const auto json = nlohmann::json::parse(encode_registry_cursor(plain));
    CHECK_FALSE(json.contains("offline"));
    CHECK_FALSE(json.at("roots").at("HKLM\\R").contains("deferred"));
    const auto old = decode_registry_cursor(encode_registry_cursor(plain));
    REQUIRE_FALSE(old.malformed);
    CHECK(old.offline.empty());
    CHECK_FALSE(old.roots.at("HKLM\\R").deferred);

    // a malformed element is a lost cursor, never a half-read scope
    for (const char* bad : {R"({"v":1,"tick":0,"roots":{},"hku":[],"offline":[["S-1-5-21-1"]]})",
                            R"({"v":1,"tick":0,"roots":{},"hku":[],"offline":[["a","b","c"]]})",
                            R"({"v":1,"tick":0,"roots":{},"hku":[],"offline":["S-1-5-21-1"]})",
                            R"({"v":1,"tick":0,"roots":{},"hku":[],"offline":[[1,2]]})"}) {
        INFO(bad);
        CHECK(decode_registry_cursor(std::string{bad}).malformed);
    }
}

TEST_CASE("stitch_registry_tick: an offline candidate is written at once as attr:offline, never correlated",
          "[echo][registry][pure]") {
    auto c = cand("changed", "Start", 4, 4, 100 * SEC, 110 * SEC);
    c.source = "offline";
    // a matching write event inside the window, a loss epoch over it, the session down and a
    // restart floor after it: none of them changes the marker
    const auto evs = std::vector<RegistryEtwEvent>{ev(105 * SEC, 7, RegistryEtwOp::Set, "Start")};
    const std::vector<LossEpoch> epochs{{100 * SEC, 110 * SEC}};
    for (const bool etw : {true, false}) {
        INFO("etw=" << etw);
        const auto r = stitch_registry_tick({c}, evs, epochs, StitchFlags{etw, 200 * SEC},
                                            111 * SEC /* inside the settle hold */, 1);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.held_next.empty());
        CHECK(r.rows[0].detail == "attr:offline");
        CHECK(r.rows[0].actor_pid == 0);
        CHECK(r.rows[0].source == "offline");
        CHECK(r.rows[0].record_key.starts_with("offline:"));
        CHECK(r.counters.none == 1);
        CHECK(r.counters.attributed == 0);
    }
}

TEST_CASE("registry schema constants agree with the registry", "[echo][registry][pure]") {
    const CaptureSourceDef* def = nullptr;
    for (const auto& s : capture_sources())
        if (s.name == "registry")
            def = &s;
    REQUIRE(def != nullptr);
    CHECK(def->default_enabled);
    CHECK(def->unique_key_column == "record_key");
    REQUIRE(def->granularities.size() == 1);
    CHECK(def->granularities[0].suffix == "live");
    CHECK(def->granularities[0].retention_type == RetentionType::kRowCount);
    CHECK(kEtwKeywordMask == 0x4300); // SetValueKey | DeleteValueKey | DeleteKey, never OpenKey/CreateKey
    CHECK(supported_capture_method("registry", "windows") == "regnotify+etw");
    CHECK(generate_warehouse_ddl().find("registry_live_record_key_uq") != std::string::npos);
}

#ifndef _WIN32
TEST_CASE("off Windows the production factory is null and the source list is unchanged",
          "[echo][registry]") {
    CHECK(make_registry_cursor_source() == nullptr);
    CHECK(make_cursor_sources().size() == 2);
}
#endif

// ═══════════════════════════════════════════════════════════════════════════
// collect() over an injected reader
// ═══════════════════════════════════════════════════════════════════════════

namespace {

struct TestDb {
    EchoDatabase db;
    fs::path path;
    ~TestDb() {
        { EchoDatabase discard = std::move(db); }
        std::error_code ec;
        for (const char* sfx : {"", "-wal", "-shm", "-journal"})
            fs::remove(fs::path{path.string() + sfx}, ec);
    }
};

TestDb make_db() {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_registry_");
    auto r = EchoDatabase::open(tmp);
    REQUIRE(r.has_value());
    return TestDb{std::move(*r), tmp};
}

const std::string kRoot = "HKLM\\SOFTWARE\\yuzu_test_r";
const std::string kRoot2 = "HKLM\\SOFTWARE\\yuzu_test_r2";

/// A reader over a scripted "registry". Records the arguments of every call.
struct Fake {
    std::map<std::string, SubtreeRead> reads;
    std::vector<std::string> read_calls;
    std::vector<std::int64_t> deadlines;
    std::int64_t clock{T0};
    SessionLoss loss;
    std::function<void()> on_loss_query; // runs inside session_loss(): the callback thread never stops
    bool etw{true}; // the write-event session is delivering
    std::vector<std::string> sids;
    int loaded_sids_calls{0}; // the HKU enumerations collect() made
    OfflineDiscovery offline_discovery; // complete, no logged-off profile
    std::deque<OfflineDiscovery> offline_discovery_queue; // answers consumed one per walk, before the line above
    std::int64_t offline_mount_cost{0}; // clock a read_offline_hive call advances
    int offline_profile_calls{0};
    std::vector<std::vector<std::string>> offline_loaded_args; // `loaded` of each discovery call
    std::map<std::string, OfflineHiveRead> offline_reads; // by sid; unscripted = every root Absent
    struct OfflineCall {
        std::string sid, path;
        std::vector<std::string> roots;
        std::int64_t deadline{0};
    };
    std::vector<OfflineCall> offline_calls;
    int ccs{1};
    std::set<std::string> unarmed;
    std::vector<std::vector<std::string>> watch_calls;
    std::shared_ptr<RegistryDirtyTable> dirty = std::make_shared<RegistryDirtyTable>();
    std::shared_ptr<RegistryEtwBuffer> buffer = std::make_shared<RegistryEtwBuffer>();

    RegistryReader reader() {
        RegistryReader r;
        r.dirty = dirty;
        r.buffer = buffer;
        r.read_subtree = [this](const std::string& root, std::int64_t deadline) {
            read_calls.push_back(root);
            deadlines.push_back(deadline);
            const auto it = reads.find(root);
            if (it == reads.end()) {
                SubtreeRead absent;
                absent.status = RegistryReadStatus::Absent;
                return absent;
            }
            return it->second;
        };
        r.loaded_sids = [this] {
            ++loaded_sids_calls;
            return sids;
        };
        r.offline_profiles = [this](const std::vector<std::string>& loaded) {
            ++offline_profile_calls;
            offline_loaded_args.push_back(loaded);
            if (!offline_discovery_queue.empty()) {
                auto d = std::move(offline_discovery_queue.front());
                offline_discovery_queue.pop_front();
                return d;
            }
            return offline_discovery;
        };
        r.read_offline_hive = [this](const std::string& sid, const std::string& path,
                                     const std::vector<std::string>& roots, std::int64_t deadline) {
            offline_calls.push_back({sid, path, roots, deadline});
            clock += offline_mount_cost;
            const auto it = offline_reads.find(sid);
            if (it != offline_reads.end())
                return it->second;
            OfflineHiveRead absent;
            for (const auto& root : roots) {
                SubtreeRead a;
                a.status = RegistryReadStatus::Absent;
                absent.roots[root] = a;
            }
            return absent;
        };
        r.now_ts = [this] { return clock += 1000; }; // strictly increasing
        r.etw_running = [this] { return etw; };
        r.session_loss = [this] {
            if (on_loss_query)
                on_loss_query();
            return loss;
        };
        r.current_control_set = [this] { return ccs; };
        r.watch_roots = [this](const std::vector<std::string>& roots) { watch_calls.push_back(roots); };
        r.root_armed = [this](const std::string& root) { return !unarmed.contains(root); };
        r.rearm = [this](const std::string& root) { return !unarmed.contains(root); };
        r.start = [] {};
        r.stop = [] {};
        return r;
    }
};

RegistryScope scope1() { return RegistryScope{{"SOFTWARE\\yuzu_test_r"}, {}}; }
RegistryScope scope2() {
    return RegistryScope{{"SOFTWARE\\yuzu_test_r", "SOFTWARE\\yuzu_test_r2"}, {}};
}

SubtreeRead svc(std::uint32_t start) {
    return complete({{kRoot + "\\Svc", {{"Start", vread(4, dword(start))}}}});
}

CursorCollectResult tick(EchoDatabase& db, CursorSource& src) {
    const auto cur = db.get_cursor("registry");
    REQUIRE(cur.has_value());
    return src.collect(db, *cur);
}

QueryResult q(EchoDatabase& db, const std::string& sql) {
    auto r = db.execute_query(sql);
    REQUIRE(r.has_value());
    return *r;
}

std::int64_t count_rows(EchoDatabase& db) {
    return std::stoll(q(db, "SELECT COUNT(*) FROM registry_live").rows.at(0).at(0));
}

RegistryCursor read_cursor(EchoDatabase& db) {
    const auto c = db.get_cursor("registry");
    REQUIRE(c.has_value());
    return decode_registry_cursor(*c);
}

// Fails every INSERT into registry_live from a second connection until released.
struct InsertTrap {
    sqlite3* h{nullptr};
    explicit InsertTrap(const fs::path& p) {
        REQUIRE(sqlite3_open(p.string().c_str(), &h) == SQLITE_OK);
        REQUIRE(sqlite3_exec(h,
                             "CREATE TRIGGER yuzu_test_trap BEFORE INSERT ON registry_live "
                             "BEGIN SELECT RAISE(ABORT, 'trap'); END",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    }
    void release() {
        sqlite3_exec(h, "DROP TRIGGER IF EXISTS yuzu_test_trap", nullptr, nullptr, nullptr);
    }
    ~InsertTrap() {
        release();
        sqlite3_close(h);
    }
};

// A notify burst on `root`: the dirty table keeps the first stamp and the last.
void burst(Fake& f, const std::string& root, std::int64_t first, std::int64_t last) {
    f.dirty->mark(root, first);
    f.dirty->mark(root, last);
}

// One tick, then a second one after the settle interval with nothing dirty: the rows of the
// changes the first tick saw land in the second. Returns the rows both emitted.
std::size_t tick_settled(EchoDatabase& db, Fake& f, CursorSource& src) {
    const auto n = tick(db, src).events_emitted;
    f.clock += kEtwSettle100ns + SEC;
    return n + tick(db, src).events_emitted;
}

// Baseline `before`, then one observed change to `after` under a notify burst: the change is
// HELD (nothing written yet). Returns the held candidate.
RegistryCandidate baseline_then_change(TestDb& t, Fake& f, RegistryCursorSource& src,
                                       std::uint32_t before, std::uint32_t after) {
    f.reads[kRoot] = svc(before);
    REQUIRE(tick(t.db, src).outcome == CursorOutcome::Baseline);
    f.clock = T0 + 100 * SEC;
    f.reads[kRoot] = svc(after);
    burst(f, kRoot, T0 + 97 * SEC, T0 + 98 * SEC);
    tick(t.db, src);
    const auto cur = read_cursor(t.db);
    REQUIRE(cur.held.size() == 1);
    return cur.held[0];
}

} // namespace

TEST_CASE("registry source: baseline tick writes baselines and no rows; a change is held, then lands",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto reader = f.reader();
    auto inner = reader.read_subtree;
    reader.read_subtree = [&f, inner](const std::string& root, std::int64_t deadline) {
        auto r = inner(root, deadline);
        f.clock += 2 * SEC; // the read itself takes two seconds
        return r;
    };
    auto src = make_registry_cursor_source(scope1(), std::move(reader));

    f.reads[kRoot] = svc(1);
    const auto first = tick(t.db, *src);
    CHECK(first.outcome == CursorOutcome::Baseline);
    CHECK(first.events_emitted == 0);
    REQUIRE(f.read_calls.size() == 1);
    CHECK(f.read_calls[0] == kRoot); // the normalised root, once
    CHECK(f.deadlines.at(0) == T0 + 1000 + kSnapshotBudget100ns); // the budget starts at the tick's first reading
    CHECK(count_rows(t.db) == 0);
    const auto base_row = t.db.try_get_state("registry:" + kRoot);
    REQUIRE(base_row.has_value());
    CHECK(base_row->has_value());
    CHECK(f.watch_calls.size() == 1);
    CHECK(read_cursor(t.db).roots.at(kRoot).window_base != 0); // the next window starts at this read

    // A change under a notify burst is HELD with the burst's window (first notify and last,
    // each +/- 1 s): nothing is written yet, and only that root's baseline is rewritten.
    f.clock = T0 + 100 * SEC;
    f.reads[kRoot] = svc(2);
    burst(f, kRoot, T0 + 97 * SEC, T0 + 98 * SEC);
    const auto second = tick(t.db, *src);
    CHECK(second.outcome == CursorOutcome::Advanced);
    CHECK(second.events_emitted == 0);
    CHECK(count_rows(t.db) == 0);
    const auto cur = read_cursor(t.db);
    REQUIRE(cur.held.size() == 1);
    // The end of that read, as the cursor recorded it (the loss query takes a stamp after it).
    const std::int64_t read_end = cur.roots.at(kRoot).read_end;
    CHECK(cur.held[0].window_lo == T0 + 96 * SEC); // first notify - 1 s slack
    CHECK(cur.held[0].window_hi == T0 + 99 * SEC); // last notify + 1 s slack, inside read_end
    CHECK(cur.held[0].source == "notify");
    CHECK(cur.held[0].root == kRoot);
    CHECK(cur.held[0].observed_at == read_end);
    const auto after = t.db.try_get_state("registry:" + kRoot);
    REQUIRE(after.has_value());
    CHECK(*after != *base_row); // the baseline moved with the change

    // Past the settle the row lands, stamped with the end of the read that saw it (not the
    // notify time), carrying no actor: no event matched, and it says so.
    f.clock = T0 + 300 * SEC;
    const auto third = tick(t.db, *src);
    CHECK(third.events_emitted == 1);
    const auto rows = q(t.db, "SELECT action, hive, key_path, value_name, data, prev_data, "
                              "actor_pid, actor_image, detail, observed_at, source FROM registry_live");
    REQUIRE(rows.rows.size() == 1);
    const auto& r = rows.rows[0];
    CHECK(r[0] == "changed");
    CHECK(r[1] == "HKLM");
    CHECK(r[2] == "SOFTWARE\\yuzu_test_r\\Svc");
    CHECK(r[3] == "Start");
    CHECK(r[4] == "2");
    CHECK(r[5] == "1");
    CHECK(r[6] == "0");  // no writer named ...
    CHECK(r[7].empty()); // ... no image ...
    CHECK(r[8] == "attr:none"); // ... and the row says why
    CHECK(r[9] == std::to_string(filetime_to_unix_ms(read_end)));
    CHECK(r[9] != std::to_string(filetime_to_unix_ms(T0 + 98 * SEC)));  // not the notify time
    CHECK(r[9] != std::to_string(filetime_to_unix_ms(T0 + 300 * SEC))); // nor the finalising tick
    CHECK(r[10] == "notify");
    CHECK(read_cursor(t.db).held.empty());

    f.clock = T0 + 400 * SEC;
    CHECK(tick(t.db, *src).events_emitted == 0); // nothing dirty, nothing held: nothing more
    CHECK(count_rows(t.db) == 1);
}

TEST_CASE("registry source: a burst well before the tick is written in that same tick",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto src = make_registry_cursor_source(scope1(), f.reader());
    f.reads[kRoot] = svc(1);
    REQUIRE(tick(t.db, *src).outcome == CursorOutcome::Baseline);

    // The burst ended 50 s before the tick: its window closed (last notify + 1 s) far more
    // than the settle interval ago, so the writer's events are all in and nothing is held.
    f.clock = T0 + 100 * SEC;
    f.reads[kRoot] = svc(2);
    burst(f, kRoot, T0 + 49 * SEC, T0 + 50 * SEC);
    src->push_event_for_test(ev(T0 + 49 * SEC + SEC / 2, 812, RegistryEtwOp::Set, "Start", 4, 4, "services.exe"));
    CHECK(tick(t.db, *src).events_emitted == 1);
    CHECK(read_cursor(t.db).held.empty());
    const auto rows = q(t.db, "SELECT actor_pid, detail FROM registry_live");
    REQUIRE(rows.rows.size() == 1);
    CHECK(rows.rows[0][0] == "812");
    CHECK(rows.rows[0][1] == "attr:corr");
}

TEST_CASE("registry source: a pushed event attributes by correlation; two pids are ambiguous",
          "[echo][registry][lifecycle]") {
    for (const bool two_pids : {false, true}) {
        INFO("two_pids=" << two_pids);
        auto t = make_db();
        Fake f;
        auto src = make_registry_cursor_source(scope1(), f.reader());
        const auto held = baseline_then_change(t, f, *src, 1, 2);
        const std::int64_t in_window = held.window_lo + SEC / 2;
        src->push_event_for_test(ev(in_window, 812, RegistryEtwOp::Set, "Start", 4, 4, "services.exe"));
        if (two_pids)
            src->push_event_for_test(ev(in_window + 1, 900, RegistryEtwOp::Set, "Start", 4, 4, "evil.exe"));
        // an event for another value, and one outside the window, are not this change's
        src->push_event_for_test(ev(in_window, 77, RegistryEtwOp::Set, "Other", 4, 4, "x.exe"));
        src->push_event_for_test(ev(held.window_hi + SEC, 78, RegistryEtwOp::Set, "Start", 4, 4, "y.exe"));
        f.clock = T0 + 300 * SEC;
        tick(t.db, *src);
        const auto rows = q(t.db, "SELECT actor_pid, actor_image, detail FROM registry_live");
        REQUIRE(rows.rows.size() == 1);
        if (two_pids) {
            CHECK(rows.rows[0][0] == "0"); // never a writer named when it is ambiguous
            CHECK(rows.rows[0][1].empty());
            CHECK(rows.rows[0][2] == "attr:ambiguous:2");
            CHECK(t.db.get_config("registry_attr_ambiguous", "") == "1");
        } else {
            CHECK(rows.rows[0][0] == "812");
            CHECK(rows.rows[0][1] == "services.exe");
            CHECK(rows.rows[0][2] == "attr:corr");
            CHECK(t.db.get_config("registry_attr_attributed", "") == "1");
        }
    }
}

TEST_CASE("registry source: with the session down a change lands as attr:off at once and the method is notify",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    f.etw = false;
    auto src = make_registry_cursor_source(scope1(), f.reader());
    f.reads[kRoot] = svc(1);
    REQUIRE(tick(t.db, *src).outcome == CursorOutcome::Baseline);
    f.clock = T0 + 100 * SEC;
    f.reads[kRoot] = svc(2);
    burst(f, kRoot, T0 + 97 * SEC, T0 + 98 * SEC);
    src->push_event_for_test(ev(T0 + 97 * SEC + SEC / 2, 812, RegistryEtwOp::Set, "Start")); // never used
    // attr:off does not depend on any later event, so there is nothing to wait for: the row is
    // written by the tick that saw the change and nothing is held in the cursor.
    CHECK(tick(t.db, *src).events_emitted == 1);
    CHECK(read_cursor(t.db).held.empty());
    const auto rows = q(t.db, "SELECT actor_pid, detail FROM registry_live");
    REQUIRE(rows.rows.size() == 1);
    CHECK(rows.rows[0][0] == "0");
    CHECK(rows.rows[0][1] == "attr:off");
    CHECK(t.db.get_config("registry_capture_method", "") == "notify");
}

TEST_CASE("registry source: the buffer keeps events newer than the watermark, then releases them",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto src = make_registry_cursor_source(scope1(), f.reader());
    f.reads[kRoot] = svc(1);
    tick(t.db, *src);
    const auto base = read_cursor(t.db).roots.at(kRoot).window_base;
    src->push_event_for_test(ev(base + 5 * SEC, 1, RegistryEtwOp::Set, "x")); // newer than the watermark
    src->push_event_for_test(ev(base - SEC, 1, RegistryEtwOp::Set, "y"));     // older
    CHECK(src->buffer_for_test().size() == 2);
    f.clock = base + 2 * SEC;
    tick(t.db, *src); // nothing dirty or due: no read, the watermark stays put
    CHECK(src->buffer_for_test().size() == 1); // the old one released, the newer one retained
    // Read the root again so its window_base moves past the event.
    f.clock = base + 20 * SEC;
    burst(f, kRoot, f.clock, f.clock);
    f.clock += SEC;
    tick(t.db, *src);
    CHECK(src->buffer_for_test().size() == 0); // the watermark passed it and no held window covers it
}

TEST_CASE("registry source: a failed commit rolls back in memory and replays cleanly (R7)",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto src = make_registry_cursor_source(scope1(), f.reader());
    const auto held = baseline_then_change(t, f, *src, 1, 2);
    src->push_event_for_test(ev(held.window_lo + SEC / 2, 5, RegistryEtwOp::Set, "Start", 4, 4, "a.exe"));
    const std::string cursor_before = *t.db.get_cursor("registry").value();
    const std::string baseline_before = *t.db.try_get_state("registry:" + kRoot).value();
    const auto buffered = src->buffer_for_test().size();

    // The next tick finalises the held candidate (a row to insert) and re-reads the root,
    // under a loss the session reports; the commit fails.
    f.clock = T0 + 300 * SEC;
    f.loss.events_lost = 3;
    burst(f, kRoot, T0 + 290 * SEC, T0 + 291 * SEC);
    {
        InsertTrap trap(t.path);
        CHECK_THROWS_AS(tick(t.db, *src), IncompleteCaptureError);
    }
    CHECK(*t.db.get_cursor("registry").value() == cursor_before); // cursor untouched
    CHECK(*t.db.try_get_state("registry:" + kRoot).value() == baseline_before); // and the baseline
    CHECK(count_rows(t.db) == 0);
    CHECK(src->buffer_for_test().size() == buffered); // nothing retired from the buffer
    CHECK(f.dirty->peek_dirty(kRoot));                // the root is dirty again (R7)
    const auto retaken = f.dirty->take(kRoot);
    CHECK(retaken.first == T0 + 290 * SEC); // with its original burst start
    f.dirty->restore(kRoot, retaken);

    f.clock += SEC;
    tick(t.db, *src); // the trap is gone: re-reads, re-derives everything, commits
    const auto rows = q(t.db, "SELECT actor_pid, detail, record_key FROM registry_live "
                              "WHERE action <> 'capture_gap'");
    REQUIRE(rows.rows.size() == 1);
    CHECK(rows.rows[0][0] == "5");
    CHECK(rows.rows[0][1] == "attr:corr");
    // the totals advanced once, by the committed replay, not also by the trapped tick
    CHECK(t.db.get_config("registry_attr_attributed", "") == "1");
    // the key is the diff's identity, whatever the replay attributed
    CHECK(rows.rows[0][2] ==
          registry_diff_record_key(held.source, held.observed_at, held.action, held.key, held.value));
    // the loss counter was not absorbed by the failed tick: the replay reports it, once
    const auto gaps = q(t.db, "SELECT detail FROM registry_live WHERE record_key LIKE 'gap:loss:%'");
    REQUIRE(gaps.rows.size() == 1);
    CHECK(gaps.rows[0][0] == "gap:loss:3");
}

TEST_CASE("registry source: lost cursor; restart; baseline loss; storage errors",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto src = make_registry_cursor_source(scope1(), f.reader());
    f.reads[kRoot] = svc(1);

    SECTION("malformed stored cursor -> CursorLost, one gap row, every root re-baselined") {
        const auto r = src->collect(t.db, std::optional<std::string>{"{not json"});
        CHECK(r.outcome == CursorOutcome::CursorLost);
        const auto rows = q(t.db, "SELECT action, detail FROM registry_live");
        REQUIRE(rows.rows.size() == 1);
        CHECK(rows.rows[0][0] == "capture_gap");
        CHECK_THAT(rows.rows[0][1], ContainsSubstring("gap:cursorlost"));
        CHECK(f.read_calls.size() == 1);
    }

    SECTION("restart with a valid cursor: Advanced + gap:restart, and a change made while down is found") {
        REQUIRE(tick(t.db, *src).outcome == CursorOutcome::Baseline);
        // A new process: a fresh source over the same database, started against the cursor.
        Fake f2;
        f2.clock = T0 + 400 * SEC;
        f2.reads[kRoot] = svc(2); // changed while the agent was down
        auto src2 = make_registry_cursor_source(scope1(), f2.reader());
        src2->start(t.db);
        f2.clock = T0 + 500 * SEC;
        const auto r = tick(t.db, *src2);
        CHECK(r.outcome == CursorOutcome::Advanced);
        CHECK(f2.read_calls.size() == 1); // the first tick after a restart reads every root
        // The writer's events were never seen, and the row says that rather than naming nobody
        // quietly. It does not wait for the settle: the marker cannot depend on a later event.
        CHECK(read_cursor(t.db).held.empty());
        f2.clock = T0 + 600 * SEC;
        CHECK(tick(t.db, *src2).events_emitted == 0);
        const auto rows = q(t.db, "SELECT action, detail, source FROM registry_live ORDER BY id");
        REQUIRE(rows.rows.size() == 2);
        CHECK(rows.rows[0][0] == "capture_gap");
        CHECK(rows.rows[0][1].find("gap:restart") == 0);
        CHECK_THAT(rows.rows[0][1], ContainsSubstring("writers were never observed"));
        CHECK(rows.rows[1][0] == "changed");
        CHECK(rows.rows[1][1] == "attr:lost-restart");
        CHECK(rows.rows[1][2] == "reconcile"); // no notify survives a restart
    }

    SECTION("restart: a change made after start() is attributed, one found at the restart is not") {
        REQUIRE(tick(t.db, *src).outcome == CursorOutcome::Baseline);
        Fake f2;
        f2.clock = T0 + 400 * SEC;
        f2.reads[kRoot] = svc(2); // changed while the agent was down
        auto src2 = make_registry_cursor_source(scope1(), f2.reader());
        src2->start(t.db);
        f2.clock = T0 + 410 * SEC;
        CHECK(tick(t.db, *src2).outcome == CursorOutcome::Advanced); // reconcile finds 1 -> 2: written

        // A change made after the restart, under a notify burst whose window opens after
        // start(): the buffer saw all of it, so the writer is named once it settles. The
        // restart change was already written (lost-restart) by the reconcile tick above.
        f2.clock = T0 + 500 * SEC;
        f2.reads[kRoot] = svc(3);
        burst(f2, kRoot, T0 + 497 * SEC, T0 + 498 * SEC);
        src2->push_event_for_test(ev(T0 + 497 * SEC + SEC / 2, 812, RegistryEtwOp::Set, "Start", 4, 4, "services.exe"));
        tick(t.db, *src2);
        f2.clock = T0 + 600 * SEC;
        tick(t.db, *src2);
        const auto rows = q(t.db, "SELECT data, actor_pid, detail FROM registry_live "
                                  "WHERE action = 'changed' ORDER BY id");
        REQUIRE(rows.rows.size() == 2);
        CHECK(rows.rows[0][0] == "2");
        CHECK(rows.rows[0][1] == "0");
        CHECK(rows.rows[0][2] == "attr:lost-restart");
        CHECK(rows.rows[1][0] == "3");
        CHECK(rows.rows[1][1] == "812");
        CHECK(rows.rows[1][2] == "attr:corr"); // events_since_ is the start, not each tick
    }

    SECTION("restart with a candidate still held: its attribution is lost and says so") {
        const auto held = baseline_then_change(t, f, *src, 1, 2);
        Fake f2;
        f2.clock = T0 + 400 * SEC;
        f2.reads[kRoot] = svc(2);
        auto src2 = make_registry_cursor_source(scope1(), f2.reader());
        src2->start(t.db);
        // The old process's buffer is gone with it. Even an event that reaches the NEW buffer
        // for the held window cannot name the writer: the new session began after the window
        // opened, so the early part of the window is unobserved.
        src2->push_event_for_test(ev(held.window_lo + SEC / 2, 5, RegistryEtwOp::Set, "Start"));
        f2.clock = T0 + 500 * SEC;
        CHECK(tick(t.db, *src2).outcome == CursorOutcome::Advanced);
        const auto rows = q(t.db, "SELECT action, actor_pid, detail FROM registry_live ORDER BY id");
        REQUIRE(rows.rows.size() == 2);
        CHECK(rows.rows[0][2].find("gap:restart") == 0);
        CHECK(rows.rows[1][0] == "changed");
        CHECK(rows.rows[1][1] == "0");
        CHECK(rows.rows[1][2] == "attr:lost-restart");
        CHECK(read_cursor(t.db).held.empty());
    }

    SECTION("a cursor written by the key-watch-only source decodes: no re-baseline, no gap") {
        REQUIRE(tick(t.db, *src).outcome == CursorOutcome::Baseline);
        auto j = nlohmann::json::parse(*t.db.get_cursor("registry").value());
        j.erase("held");
        j.erase("loss");
        for (auto& [name, root] : j.at("roots").items())
            root.erase("window_base");
        Fake f2;
        f2.clock = T0 + 400 * SEC;
        f2.reads[kRoot] = svc(1);
        auto src2 = make_registry_cursor_source(scope1(), f2.reader());
        const auto r = src2->collect(t.db, std::optional<std::string>{j.dump()});
        CHECK(r.outcome == CursorOutcome::Advanced); // CursorLost here would re-baseline every root
        CHECK(count_rows(t.db) == 0);
        CHECK(read_cursor(t.db).roots.at(kRoot).baselined);
    }

    SECTION("a missing baseline for a baselined root -> gap:baselinelost and a fresh baseline") {
        tick(t.db, *src);
        REQUIRE(t.db.execute_sql("DELETE FROM echo_state WHERE collector LIKE 'registry:%'"));
        f.clock = T0 + 100 * SEC;
        f.dirty->mark(kRoot, f.clock);
        f.reads[kRoot] = svc(2);
        tick(t.db, *src);
        const auto rows = q(t.db, "SELECT detail FROM registry_live");
        REQUIRE(rows.rows.size() == 1); // the gap only: no change was invented from the lost baseline
        CHECK_THAT(rows.rows[0][0], ContainsSubstring("gap:baselinelost"));
        // a malformed baseline is treated the same way
        REQUIRE(t.db.set_state("registry:" + kRoot, "{\"v\":1"));
        f.dirty->mark(kRoot, f.clock + SEC);
        f.clock += 10 * SEC;
        tick(t.db, *src);
        CHECK(count_rows(t.db) == 2);
    }

    SECTION("an unreadable baseline store is a transient failure, never a re-baseline") {
        tick(t.db, *src);
        sqlite3* h = nullptr;
        REQUIRE(sqlite3_open(t.path.string().c_str(), &h) == SQLITE_OK);
        REQUIRE(sqlite3_exec(h, "ALTER TABLE echo_state RENAME TO echo_state_away", nullptr, nullptr,
                             nullptr) == SQLITE_OK);
        f.dirty->mark(kRoot, f.clock);
        f.clock += 10 * SEC;
        CHECK_THROWS_AS(tick(t.db, *src), IncompleteCaptureError);
        sqlite3_exec(h, "ALTER TABLE echo_state_away RENAME TO echo_state", nullptr, nullptr, nullptr);
        sqlite3_close(h);
    }
}

TEST_CASE("registry source: disable discards the paused window; re-enable re-baselines with a gap",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto src = make_registry_cursor_source(scope1(), f.reader());
    f.reads[kRoot] = svc(1);
    tick(t.db, *src);
    src->push_event_for_test(ev(T0, 1, RegistryEtwOp::Set, "x"));
    src->on_enabled_changed(false);
    CHECK(src->buffer_for_test().size() == 0); // what the buffer held is discarded ...
    src->push_event_for_test(ev(T0, 2, RegistryEtwOp::Set, "x"));
    CHECK(src->buffer_for_test().size() == 0); // ... and an event pushed while paused is never stored
    f.reads[kRoot] = svc(9); // changed while paused
    f.dirty->mark(kRoot, T0 + 50 * SEC); // the watcher stays warm
    src->on_enabled_changed(true);
    src->push_event_for_test(ev(T0 + 90 * SEC, 3, RegistryEtwOp::Set, "x")); // accepted again
    CHECK(src->buffer_for_test().size() == 1);
    f.clock = T0 + 100 * SEC;
    const auto r = tick(t.db, *src);
    CHECK(r.outcome == CursorOutcome::CursorLost);
    const auto rows = q(t.db, "SELECT detail FROM registry_live");
    REQUIRE(rows.rows.size() == 1); // the gap; the paused-window change is NOT reported
    CHECK_THAT(rows.rows[0][0], ContainsSubstring("gap:disabled"));
    CHECK(read_cursor(t.db).held.empty());
}

TEST_CASE("registry source: a candidate held across a disable finalises as lost-restart",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto src = make_registry_cursor_source(scope1(), f.reader());
    const auto held = baseline_then_change(t, f, *src, 1, 2); // read while enabled, not yet settled
    src->push_event_for_test(ev(held.window_lo + SEC / 2, 5, RegistryEtwOp::Set, "Start"));
    src->on_enabled_changed(false); // the buffer, and with it the writer's event, is discarded
    src->on_enabled_changed(true);
    f.clock = T0 + 300 * SEC;
    tick(t.db, *src);
    const auto rows = q(t.db, "SELECT actor_pid, detail FROM registry_live WHERE action = 'changed'");
    REQUIRE(rows.rows.size() == 1);
    CHECK(rows.rows[0][0] == "0");
    CHECK(rows.rows[0][1] == "attr:lost-restart");
}

TEST_CASE("registry source: buffer overflow becomes a loss epoch that degrades only the windows it touches",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    f.buffer = std::make_shared<RegistryEtwBuffer>(3);
    auto src = make_registry_cursor_source(scope2(), f.reader());
    auto b_read = [&](std::uint32_t n) {
        return complete({{kRoot2 + "\\S", {{"Count", vread(4, dword(n))}}}});
    };
    f.reads[kRoot] = svc(1);
    f.reads[kRoot2] = b_read(1);
    tick(t.db, *src);

    f.clock = T0 + 100 * SEC;
    f.reads[kRoot] = svc(2);     // root A: Start changes
    f.reads[kRoot2] = b_read(2); // root B: Count changes
    burst(f, kRoot, T0 + 95 * SEC + SEC / 5, T0 + 95 * SEC + SEC / 2);
    burst(f, kRoot2, T0 + 98 * SEC, T0 + 98 * SEC + SEC / 2);
    // Oldest first: A's event is evicted by the overflow; B's survives.
    src->push_event_for_test(ev(T0 + 95 * SEC + SEC / 2, 11, RegistryEtwOp::Set, "Start"));
    src->push_event_for_test(ev(T0 + 98 * SEC + SEC / 5, 22, RegistryEtwOp::Set, "Count"));
    src->push_event_for_test(ev(T0 + 99 * SEC, 33, RegistryEtwOp::Set, "Other"));
    src->push_event_for_test(ev(T0 + 99 * SEC + 1, 33, RegistryEtwOp::Set, "Other"));
    tick(t.db, *src);

    const auto cur = read_cursor(t.db);
    REQUIRE(cur.loss.size() == 1);
    CHECK(cur.loss[0].lo == T0 + 95 * SEC + SEC / 2); // the evicted event's own timestamp
    CHECK(cur.loss[0].hi == T0 + 95 * SEC + SEC / 2);
    CHECK(cur.held.size() == 2); // the settle hold keeps both
    const auto gap = q(t.db, "SELECT detail FROM registry_live");
    REQUIRE(gap.rows.size() == 1);
    CHECK(gap.rows[0][0] == "gap:loss:1");
    CHECK(t.db.get_config("registry_etw_dropped", "") == "1");

    // A later tick (no new loss): the epoch recorded at the previous tick still degrades the
    // candidate it overlaps, and the disjoint one attributes.
    f.clock = T0 + 200 * SEC;
    tick(t.db, *src);
    const auto rows = q(t.db, "SELECT key_path, actor_pid, detail FROM registry_live "
                              "WHERE action != 'capture_gap' ORDER BY value_name");
    REQUIRE(rows.rows.size() == 2);
    CHECK(rows.rows[0][2] == "attr:corr"); // Count, root B: its window is disjoint from the epoch
    CHECK(rows.rows[0][1] == "22");
    CHECK(rows.rows[1][2] == "attr:degraded"); // Start, root A: the evicted event lay in its window
    CHECK(rows.rows[1][1] == "0");
    // The eviction was reported by the first tick and absorbed with its commit: the second tick
    // (no new eviction) writes no second gap row.
    CHECK(std::stoll(q(t.db, "SELECT COUNT(*) FROM registry_live WHERE record_key LIKE 'gap:loss:%'")
                        .rows.at(0).at(0)) == 1);
}

TEST_CASE("registry source: kernel loss and a failed loss query are loss, reported once",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto src = make_registry_cursor_source(scope1(), f.reader());
    f.reads[kRoot] = svc(1);
    tick(t.db, *src);

    f.clock = T0 + 100 * SEC;
    f.loss.events_lost = 3;
    tick(t.db, *src);
    auto gap = q(t.db, "SELECT detail FROM registry_live");
    REQUIRE(gap.rows.size() == 1);
    CHECK(gap.rows[0][0] == "gap:loss:3");
    CHECK(t.db.get_config("registry_etw_lost", "") == "3");
    f.clock = T0 + 200 * SEC;
    tick(t.db, *src);
    CHECK(count_rows(t.db) == 1); // the counter is cumulative: nothing new since, no second gap

    f.loss.query_ok = false; // the query failing is itself loss ...
    f.clock = T0 + 300 * SEC;
    tick(t.db, *src);
    gap = q(t.db, "SELECT detail FROM registry_live ORDER BY id");
    REQUIRE(gap.rows.size() == 2);
    CHECK(gap.rows[1][0] == "gap:loss:1");
    f.loss.query_ok = true; // ... and recovering is not
    f.clock = T0 + 400 * SEC;
    tick(t.db, *src);
    CHECK(count_rows(t.db) == 2);
    CHECK(t.db.get_config("registry_etw_lost", "") == "4"); // 3 lost + 1 failed query, monotone

    f.loss.decode_failed = 2; // callback decode failures are loss too
    f.clock = T0 + 500 * SEC;
    tick(t.db, *src);
    gap = q(t.db, "SELECT detail FROM registry_live ORDER BY id");
    REQUIRE(gap.rows.size() == 3);
    CHECK(gap.rows[2][0] == "gap:loss:2");
}

TEST_CASE("registry source: loss over a held window degrades it (kernel counters, decode failures, failed loss query)",
          "[echo][registry][lifecycle]") {
    enum class Loss { None, Kernel, DecodeFailed, FailedQuery };
    for (const Loss mode : {Loss::None, Loss::Kernel, Loss::DecodeFailed, Loss::FailedQuery}) {
        INFO("mode=" << static_cast<int>(mode));
        auto t = make_db();
        Fake f;
        auto src = make_registry_cursor_source(scope1(), f.reader());
        f.reads[kRoot] = svc(1);
        REQUIRE(tick(t.db, *src).outcome == CursorOutcome::Baseline);

        // The change is read at the end of a burst, so its window (first notify - 1 s, read end]
        // reaches past this tick's start -- which is where the NEXT tick's kernel-loss interval
        // begins -- and a clean writer sits inside it.
        f.clock = T0 + 100 * SEC;
        f.reads[kRoot] = svc(2);
        burst(f, kRoot, T0 + 99 * SEC, T0 + 100 * SEC);
        src->push_event_for_test(
           ev(T0 + 99 * SEC + SEC / 2, 812, RegistryEtwOp::Set, "Start", 4, 4, "services.exe"));
        tick(t.db, *src);
        REQUIRE(read_cursor(t.db).held.size() == 1);

        f.clock = T0 + 300 * SEC;
        if (mode == Loss::Kernel)
            f.loss.events_lost = 3;
        if (mode == Loss::DecodeFailed)
            f.loss.decode_failed = 1;
        if (mode == Loss::FailedQuery)
            f.loss.query_ok = false;
        tick(t.db, *src);
        const auto rows = q(t.db, "SELECT actor_pid, detail FROM registry_live WHERE action = 'changed'");
        REQUIRE(rows.rows.size() == 1);
        if (mode == Loss::None) { // the control: the same setup attributes when nothing was lost
            CHECK(rows.rows[0][0] == "812");
            CHECK(rows.rows[0][1] == "attr:corr");
        } else {
            CHECK(rows.rows[0][0] == "0"); // never a writer named across reported loss
            CHECK(rows.rows[0][1] == "attr:degraded");
        }
    }
}

TEST_CASE("registry source: an eviction during loss sampling cannot select the surviving writer",
          "[echo][registry][lifecycle]") {
    // collect() reads the buffer BEFORE the session's loss counters. The callback thread keeps
    // pushing while the counters are sampled, so an eviction in that gap is in neither this
    // tick's batch nor its drop count. With room for two events, one push removes one of two
    // competing writers: sampling the counters first would leave the survivor alone in the
    // batch and name it, with no loss recorded. Sampling the buffer first keeps both in the
    // batch (ambiguous), and the eviction is counted by the next tick.
    auto t = make_db();
    Fake f;
    f.buffer = std::make_shared<RegistryEtwBuffer>(2);
    auto src = make_registry_cursor_source(scope1(), f.reader());
    const auto held = baseline_then_change(t, f, *src, 1, 2);
    const std::int64_t in_window = held.window_lo + SEC / 2;
    src->push_event_for_test(ev(in_window, 11, RegistryEtwOp::Set, "Start", 4, 4, "first.exe"));
    src->push_event_for_test(ev(in_window + 1, 22, RegistryEtwOp::Set, "Start", 4, 4, "second.exe"));
    bool fired = false;
    f.on_loss_query = [&] {
        if (fired)
            return;
        fired = true;
        // not this change's value: it only takes the place of the oldest event (pid 11's)
        f.buffer->push(ev(in_window + 2, 77, RegistryEtwOp::Set, "Other", 4, 4, "x.exe"));
    };
    f.clock = T0 + 300 * SEC;
    tick(t.db, *src);
    REQUIRE(fired);
    REQUIRE(f.buffer->drop_info().count == 1); // the positive control: the eviction happened mid-tick

    const auto rows = q(t.db, "SELECT actor_pid, actor_image, detail FROM registry_live WHERE action = 'changed'");
    REQUIRE(rows.rows.size() == 1);
    CHECK(rows.rows[0][0] == "0"); // never the survivor
    CHECK(rows.rows[0][1].empty());
    CHECK(rows.rows[0][2] == "attr:ambiguous:2");
}

TEST_CASE("registry source: a kernel loss counted after the reads lies inside its epoch",
          "[echo][registry][lifecycle]") {
    // `now` is taken before the per-root reads, which can run to the snapshot deadline; the
    // session's counters are read after them. A loss that query reports happened in between,
    // so the epoch must end at a stamp taken AFTER the query. Ended at `now`, it leaves
    // (now, query] in no epoch, and a window that opens after `now` (a notify that arrived
    // during the reads) then correlates to its one same-signature bystander with no loss
    // recorded, though the true writer's event may be the one lost.
    for (const bool lose : {false, true}) {
        INFO("lose=" << lose);
        auto t = make_db();
        Fake f;
        auto reader = f.reader();
        auto inner = reader.read_subtree;
        reader.read_subtree = [&f, inner](const std::string& root, std::int64_t deadline) {
            auto r = inner(root, deadline);
            f.clock += 5 * SEC; // a slow read
            return r;
        };
        auto src = make_registry_cursor_source(scope1(), std::move(reader));
        f.reads[kRoot] = svc(1);
        REQUIRE(tick(t.db, *src).outcome == CursorOutcome::Baseline);

        f.clock = T0 + 100 * SEC; // this tick's `now` is just after it
        f.reads[kRoot] = svc(2);
        // The notify arrived while the root was being read: the change's window is
        // (T0 + 102 s, T0 + 105 s], entirely after `now`.
        burst(f, kRoot, T0 + 103 * SEC, T0 + 104 * SEC);
        src->push_event_for_test(
           ev(T0 + 104 * SEC, 77, RegistryEtwOp::Set, "Start", 4, 4, "bystander.exe"));
        bool fired = false;
        f.on_loss_query = [&] {
            if (fired)
                return;
            fired = true;
            f.clock += 2 * SEC; // the counters are read later than `now`
            if (lose)
                f.loss.events_lost = 3; // a loss somewhere in the interval since the last query
        };
        tick(t.db, *src);
        REQUIRE(fired);
        const auto cur = read_cursor(t.db);
        REQUIRE(cur.held.size() == 1);
        REQUIRE(cur.held[0].window_lo > T0 + 100 * SEC + 10'000); // opens after `now`
        if (lose) {
            // the positive control: the loss was counted this tick, and as an epoch ...
            CHECK(t.db.get_config("registry_etw_lost", "") == "3");
            REQUIRE(cur.loss.size() == 1);
            // ... that reaches past the end of the held window (it ended at `now` before)
            CHECK(cur.loss[0].hi >= cur.held[0].window_hi);
        } else {
            CHECK(cur.loss.empty());
        }

        f.clock = T0 + 300 * SEC; // the window has settled; no new loss is reported
        tick(t.db, *src);
        const auto rows = q(t.db, "SELECT actor_pid, detail FROM registry_live WHERE action = 'changed'");
        REQUIRE(rows.rows.size() == 1);
        if (lose) {
            CHECK(rows.rows[0][0] == "0"); // never the bystander across a reported loss
            CHECK(rows.rows[0][1] == "attr:degraded");
        } else { // the control: the same setup names the bystander when nothing was lost
            CHECK(rows.rows[0][0] == "77");
            CHECK(rows.rows[0][1] == "attr:corr");
        }
    }
}

TEST_CASE("registry source: an idle root that stays Capped does not pin the event buffer",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto src = make_registry_cursor_source(scope2(), f.reader());
    SubtreeRead capped = complete({{kRoot + "\\A", {{"v", vread(4, dword(1))}}}});
    capped.status = RegistryReadStatus::Capped;
    f.reads[kRoot] = capped;
    f.reads[kRoot2] = complete({{kRoot2 + "\\S", {{"Count", vread(4, dword(1))}}}});
    tick(t.db, *src);
    const auto cur = read_cursor(t.db);
    REQUIRE(cur.roots.at(kRoot).window_base == 0); // never completely read
    const auto base2 = cur.roots.at(kRoot2).window_base;
    REQUIRE(base2 != 0);

    // An event older than the one completely-read root's last read can never be matched again;
    // the Capped root, which has no unread notify, must not keep it. (With an unread notify
    // it does: see the budget-deferral case below.)
    src->push_event_for_test(ev(base2 - SEC, 1, RegistryEtwOp::Set, "old"));
    REQUIRE(src->buffer_for_test().size() == 1);
    f.clock = base2 + 10 * SEC;
    tick(t.db, *src);
    CHECK(src->buffer_for_test().size() == 0);
}

namespace {

// kRoot (Capped, never complete) and kRoot2 (complete) are both notified. Tick 2's first read
// (kRoot2, by the fair rotation) spends the read budget, so kRoot is deferred: still unread,
// with a second writer's event and a fresh notify arriving during that read. Construction
// runs both ticks; `kernel_loss` reports a kernel loss during tick 2.
struct BudgetDeferral {
    TestDb t = make_db();
    Fake f;
    bool exhaust{false};
    std::unique_ptr<RegistryCursorSource> src;

    explicit BudgetDeferral(bool kernel_loss) {
        auto r = f.reader();
        auto read = r.read_subtree;
        r.read_subtree = [this, read](const std::string& root, std::int64_t deadline) {
            auto result = read(root, deadline);
            if (exhaust && root == kRoot2) {
                f.buffer->push(ev(T0 + 102 * SEC, 22, RegistryEtwOp::Set, "Start"));
                f.dirty->mark(kRoot, T0 + 102 * SEC);
                f.clock += kSnapshotBudget100ns + SEC; // the budget is spent: kRoot is not reached
            }
            return result;
        };
        src = make_registry_cursor_source(scope2(), std::move(r));
        src->start(t.db);
        auto capped = svc(1);
        capped.status = RegistryReadStatus::Capped;
        f.reads[kRoot] = capped;
        f.reads[kRoot2] = complete({{kRoot2 + "\\S", {{"Count", vread(4, dword(1))}}}});
        tick(t.db, *src);
        REQUIRE(read_cursor(t.db).roots.at(kRoot).window_base == 0);

        f.clock = T0 + 101 * SEC;
        capped = svc(2);
        capped.status = RegistryReadStatus::Capped;
        f.reads[kRoot] = capped;
        burst(f, kRoot, T0 + 100 * SEC, T0 + 100 * SEC);
        burst(f, kRoot2, T0 + 100 * SEC, T0 + 100 * SEC);
        src->push_event_for_test(ev(T0 + 100 * SEC, 11, RegistryEtwOp::Set, "Start"));
        f.loss.events_lost = kernel_loss ? 1 : 0;
        exhaust = true;
        f.read_calls.clear();
        tick(t.db, *src);
        exhaust = false;
        REQUIRE(f.read_calls == std::vector<std::string>{kRoot2}); // kRoot was deferred
        REQUIRE(f.dirty->peek_dirty(kRoot));                       // ... and is still unread
        REQUIRE(f.buffer->pushed() == 2);
        REQUIRE(f.buffer->drop_info().count == 0);
    }
};

} // namespace

// A never-complete root the read budget deferred has an unread notify but no candidate yet,
// so no held window protects its events: the retention floor must.
TEST_CASE("registry source: a budget-deferred never-complete root keeps its pending window's events",
          "[echo][registry][lifecycle]") {
    BudgetDeferral d(false);
    // the positive control: kRoot2's read advanced the watermark past pid 11's event, and the
    // pending window (burst start less the slack) still holds both writers' events
    CHECK(d.src->buffer_for_test().size() == 2);

    d.f.clock = T0 + 401 * SEC;
    tick(d.t.db, *d.src);
    const auto rows = q(d.t.db, "SELECT actor_pid, detail FROM registry_live WHERE action = 'changed'");
    REQUIRE(rows.rows.size() == 1);
    CHECK(rows.rows[0][0] == "0"); // two writers: never the survivor
    CHECK(rows.rows[0][1] == "attr:ambiguous:2");
    CHECK(q(d.t.db, "SELECT COUNT(*) FROM registry_live WHERE record_key LIKE 'gap:loss:%'")
             .rows.at(0).at(0) == "0");
}

TEST_CASE("registry source: a budget-deferred never-complete root keeps the loss epochs its window reaches",
          "[echo][registry][lifecycle]") {
    BudgetDeferral d(true);
    // the positive control: tick 2 recorded the epoch (one gap:loss row), and the deferred
    // root's pending window still reaches it, so it is not aged out
    REQUIRE(read_cursor(d.t.db).loss.size() == 1);

    d.f.clock = T0 + 401 * SEC;
    tick(d.t.db, *d.src);
    const auto rows = q(d.t.db, "SELECT actor_pid, detail FROM registry_live WHERE action = 'changed'");
    REQUIRE(rows.rows.size() == 1);
    CHECK(rows.rows[0][0] == "0");
    CHECK(rows.rows[0][1] == "attr:degraded");
    CHECK(q(d.t.db, "SELECT COUNT(*) FROM registry_live WHERE record_key LIKE 'gap:loss:%'")
             .rows.at(0).at(0) == "1");
}

TEST_CASE("registry source: read statuses; status keys; fair root scheduling",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto src = make_registry_cursor_source(scope2(), f.reader());

    SECTION("Unreadable root writes nothing and stays due; Capped adds only") {
        SubtreeRead bad;
        bad.status = RegistryReadStatus::Unreadable;
        f.reads[kRoot] = bad;
        f.reads[kRoot2] = complete({{kRoot2 + "\\S", {{"Count", vread(4, dword(1))}}}});
        tick(t.db, *src);
        f.clock = T0 + 100 * SEC;
        f.reads[kRoot2] = complete({{kRoot2 + "\\S", {{"Count", vread(4, dword(2))}}}});
        f.dirty->mark(kRoot2, T0 + 97 * SEC);
        f.read_calls.clear();
        tick(t.db, *src);
        CHECK(std::count(f.read_calls.begin(), f.read_calls.end(), kRoot) == 1); // still due
        const auto cur = read_cursor(t.db);
        CHECK_FALSE(cur.roots.at(kRoot).baselined);
        CHECK(cur.roots.at(kRoot).window_base == 0); // never completely read: its window stays wide
        // a change only for the readable root (held), plus the ONE gap for the root that went
        // unreadable (it was already unreadable on the second tick: nothing more)
        CHECK(count_rows(t.db) == 1);
        REQUIRE(cur.held.size() == 1);
        CHECK(cur.held[0].root == kRoot2);
        CHECK(t.db.get_config("registry_roots_unreadable", "") == "1");
        CHECK(t.db.get_config("registry_capture_method", "") == "notify+etw");
        CHECK_FALSE(t.db.try_get_state("registry:" + kRoot).value().has_value());

        SubtreeRead capped = complete({{kRoot + "\\A", {{"v", vread(4, dword(1))}}}});
        capped.status = RegistryReadStatus::Capped;
        f.reads[kRoot] = capped;
        f.clock = T0 + 200 * SEC;
        tick(t.db, *src);
        CHECK(t.db.get_config("registry_roots_capped", "") == "1");
        CHECK(t.db.get_config("registry_roots_unreadable", "") == "0");
        CHECK(t.db.get_config("registry_watch_roots", "") == "2");
        CHECK(read_cursor(t.db).roots.at(kRoot).window_base == 0); // a Capped read does not advance it
        // ... and the held change lands, the only non-gap row
        CHECK(std::stoll(q(t.db, "SELECT COUNT(*) FROM registry_live WHERE action <> 'capture_gap'")
                            .rows.at(0).at(0)) == 1);
    }

    SECTION("status keys: the session state, the attribution counters and the buffer's counters") {
        f.reads[kRoot] = svc(1);
        f.reads[kRoot2] = svc(1);
        tick(t.db, *src);
        CHECK(t.db.get_config("registry_capture_method", "") == "notify+etw");
        CHECK(t.db.get_config("registry_etw_events", "") == "0");
        CHECK(t.db.get_config("registry_attr_attributed", "") == "0");

        f.etw = false; // the session went down: the key watch is all that is left
        f.clock = T0 + 50 * SEC;
        tick(t.db, *src);
        CHECK(t.db.get_config("registry_capture_method", "") == "notify");
        f.etw = true;
        f.clock = T0 + 60 * SEC;
        tick(t.db, *src);
        CHECK(t.db.get_config("registry_capture_method", "") == "notify+etw");

        // The non-zero path: one change explained by a pushed event, then one that no event
        // explains. The event count reports the buffer's pushes, and the attribution counters
        // accumulate across committed ticks.
        f.clock = T0 + 100 * SEC;
        f.reads[kRoot] = svc(2);
        burst(f, kRoot, T0 + 97 * SEC, T0 + 98 * SEC);
        tick(t.db, *src);
        const auto held = read_cursor(t.db).held;
        REQUIRE(held.size() == 1);
        src->push_event_for_test(ev(held[0].window_lo + SEC / 2, 5, RegistryEtwOp::Set, "Start"));
        src->push_event_for_test(ev(held[0].window_lo + SEC / 2, 5, RegistryEtwOp::Set, "Unrelated"));
        f.clock = T0 + 300 * SEC;
        tick(t.db, *src);
        CHECK(t.db.get_config("registry_etw_events", "") == "2");
        CHECK(t.db.get_config("registry_attr_attributed", "") == "1");
        f.clock = T0 + 400 * SEC;
        f.reads[kRoot] = svc(3);
        burst(f, kRoot, T0 + 390 * SEC, T0 + 391 * SEC);
        tick(t.db, *src);
        f.clock = T0 + 600 * SEC;
        tick(t.db, *src);
        CHECK(t.db.get_config("registry_attr_attributed", "") == "1");
        CHECK(t.db.get_config("registry_attr_none", "") == "1"); // the second change had no event
        CHECK(t.db.get_config("registry_attr_ambiguous", "") == "0");
    }

    SECTION("an unarmed root is reported and read every tick (R13)") {
        f.unarmed.insert(kRoot);
        f.reads[kRoot] = svc(1);
        f.reads[kRoot2] = svc(1);
        tick(t.db, *src);
        f.read_calls.clear();
        f.clock = T0 + 50 * SEC;
        tick(t.db, *src);
        CHECK(std::count(f.read_calls.begin(), f.read_calls.end(), kRoot) == 1);
        CHECK(std::count(f.read_calls.begin(), f.read_calls.end(), kRoot2) == 0);
        CHECK(t.db.get_config("registry_watch_roots_unarmed", "") == "1");
    }
}

TEST_CASE("registry source: an unreadable root and a denied child set that gains a member each write one gap row",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto src = make_registry_cursor_source(scope1(), f.reader());
    const std::string locked = kRoot + "\\Locked";
    auto gap_count = [&] {
        return std::stoll(q(t.db, "SELECT COUNT(*) FROM registry_live WHERE record_key LIKE 'gap:unreadable:%'")
                             .rows.at(0).at(0));
    };
    auto last_gap = [&] {
        return q(t.db, "SELECT detail FROM registry_live WHERE record_key LIKE 'gap:unreadable:%' "
                       "ORDER BY id DESC LIMIT 1").rows.at(0).at(0);
    };
    // A read of the root with Svc\Start = `start`, optionally with Locked readable and holding a value.
    auto read = [&](std::uint32_t start, bool locked_readable, std::vector<std::string> denied) {
        auto r = svc(start);
        if (locked_readable)
            r.keys[locked] = {{"Hidden", vread(4, dword(7))}};
        r.skipped = std::move(denied);
        return r;
    };
    // One step of the script: the read changes, a tick sees it, and a second one after the
    // settle interval lands the change row. The result carries the rows of both.
    struct Stepped {
        std::size_t events_emitted;
    };
    auto next_tick = [&](SubtreeRead r) {
        f.reads[kRoot] = std::move(r);
        f.clock += 100 * SEC;
        f.dirty->mark(kRoot, f.clock);
        return Stepped{tick_settled(t.db, f, *src)};
    };

    f.reads[kRoot] = read(1, /*locked_readable=*/true, {});
    REQUIRE(tick(t.db, *src).outcome == CursorOutcome::Baseline);
    CHECK(gap_count() == 0);
    const std::string baseline_before = *t.db.try_get_state("registry:" + kRoot).value();
    CHECK_THAT(baseline_before, ContainsSubstring("Locked"));

    // Locked becomes unreadable: the rest of the root still diffs, the denied key's stored
    // values are kept (no `removed` rows), the root is NOT unreadable, and ONE gap names it.
    CHECK(next_tick(read(2, false, {locked})).events_emitted == 2);
    CHECK(count_rows(t.db) == 2);
    CHECK(std::stoll(q(t.db, "SELECT COUNT(*) FROM registry_live WHERE action IN ('removed','key_removed')")
                        .rows.at(0).at(0)) == 0);
    CHECK(gap_count() == 1);
    CHECK_THAT(last_gap(), ContainsSubstring("gap:unreadable:" + kRoot));
    CHECK_THAT(last_gap(), ContainsSubstring(locked));
    CHECK_THAT(*t.db.try_get_state("registry:" + kRoot).value(), ContainsSubstring("Hidden"));
    CHECK(read_cursor(t.db).roots.at(kRoot).status == "complete");
    CHECK(read_cursor(t.db).roots.at(kRoot).skipped == std::vector<std::string>{locked});
    CHECK(t.db.get_config("registry_roots_unreadable", "") == "0");

    // The same denied set on the next read: the change still lands, no new gap.
    CHECK(next_tick(read(3, false, {locked})).events_emitted == 1);
    CHECK(gap_count() == 1);

    // The denied set grows: one more gap, naming how many.
    CHECK(next_tick(read(3, false, {locked, kRoot + "\\Other"})).events_emitted == 1);
    CHECK(gap_count() == 2);
    CHECK_THAT(last_gap(), ContainsSubstring("2 child key(s)"));

    // Access is restored: Locked reads again and is diffed against what was kept (Hidden is
    // unchanged), nothing is reported as a gap.
    CHECK(next_tick(read(3, true, {})).events_emitted == 0);
    CHECK(gap_count() == 2);
    CHECK(read_cursor(t.db).roots.at(kRoot).skipped.empty());

    // The root itself becomes unreadable: one gap, the baseline is untouched, it is counted.
    const std::string baseline_ok = *t.db.try_get_state("registry:" + kRoot).value();
    SubtreeRead bad;
    bad.status = RegistryReadStatus::Unreadable;
    CHECK(next_tick(bad).events_emitted == 1);
    CHECK(gap_count() == 3);
    CHECK_THAT(last_gap(), ContainsSubstring("the root could not be read"));
    CHECK(*t.db.try_get_state("registry:" + kRoot).value() == baseline_ok);
    CHECK(t.db.get_config("registry_roots_unreadable", "") == "1");

    // Still unreadable on the next ticks (it is due every tick): nothing more.
    CHECK(next_tick(bad).events_emitted == 0);
    CHECK(next_tick(bad).events_emitted == 0);
    CHECK(gap_count() == 3);

    // Readable again, then unreadable again: the second loss is a new transition.
    CHECK(next_tick(read(4, true, {})).events_emitted == 1); // the change since the kept baseline
    CHECK(t.db.get_config("registry_roots_unreadable", "") == "0");
    CHECK(next_tick(bad).events_emitted == 1);
    CHECK(gap_count() == 4);
}

TEST_CASE("registry source: the denied child set writes a gap only when it gains a member; a Capped read never shrinks it",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto src = make_registry_cursor_source(scope1(), f.reader());
    const std::string a = kRoot + "\\A", b = kRoot + "\\B", c = kRoot + "\\C", d = kRoot + "\\D";
    auto gap_count = [&] {
        return std::stoll(q(t.db, "SELECT COUNT(*) FROM registry_live WHERE record_key LIKE 'gap:unreadable:%'")
                             .rows.at(0).at(0));
    };
    auto last_gap = [&] {
        return q(t.db, "SELECT detail FROM registry_live WHERE record_key LIKE 'gap:unreadable:%' "
                       "ORDER BY id DESC LIMIT 1").rows.at(0).at(0);
    };
    auto stored = [&] { return read_cursor(t.db).roots.at(kRoot).skipped; };
    // One tick over an unchanged root whose read has the given status and denied children.
    auto next_tick = [&](RegistryReadStatus status, std::vector<std::string> denied) {
        auto r = svc(1);
        r.status = status;
        r.skipped = std::move(denied);
        f.reads[kRoot] = std::move(r);
        f.clock += 100 * SEC;
        f.dirty->mark(kRoot, f.clock);
        return tick(t.db, *src);
    };
    using S = RegistryReadStatus;

    SECTION("Complete{A,B} -> Capped{A} -> Complete{A,B} writes ONE gap row, and the Capped tick keeps {A,B}") {
        next_tick(S::Complete, {a, b});
        CHECK(gap_count() == 1);
        CHECK_THAT(last_gap(), ContainsSubstring("2 child key(s)"));

        // The Capped walk stopped early and only reached A: B is not proven readable.
        CHECK(next_tick(S::Capped, {a}).events_emitted == 0);
        CHECK(stored() == std::vector<std::string>{a, b});
        CHECK(read_cursor(t.db).roots.at(kRoot).status == "capped");

        CHECK(next_tick(S::Complete, {a, b}).events_emitted == 0); // the unchanged set is not re-reported
        CHECK(gap_count() == 1);
        CHECK(stored() == std::vector<std::string>{a, b});
    }

    SECTION("a Capped read that reaches a new denied child adds it and writes one gap naming the stored set") {
        next_tick(S::Complete, {a, b});
        CHECK(next_tick(S::Capped, {a, c}).events_emitted == 1);
        CHECK(gap_count() == 2);
        CHECK_THAT(last_gap(), ContainsSubstring("3 child key(s)"));
        CHECK(stored() == std::vector<std::string>{a, b, c});
        CHECK(next_tick(S::Complete, {a, b, c}).events_emitted == 0);
        CHECK(gap_count() == 2);
    }

    SECTION("a shrink writes nothing, to a different non-empty set or to none; a member denied again is a new gain") {
        next_tick(S::Complete, {a, b});
        CHECK(gap_count() == 1);
        CHECK(next_tick(S::Complete, {a}).events_emitted == 0);
        CHECK(gap_count() == 1);
        CHECK(stored() == std::vector<std::string>{a});
        CHECK(next_tick(S::Complete, {}).events_emitted == 0);
        CHECK(gap_count() == 1);
        CHECK(stored().empty());
        CHECK(next_tick(S::Complete, {b}).events_emitted == 1);
        CHECK(gap_count() == 2);
        CHECK(stored() == std::vector<std::string>{b});
    }

    SECTION("the detail names the first three denied children and counts the rest") {
        next_tick(S::Complete, {d, c, b, a}); // the reader's order is not the display order
        REQUIRE(gap_count() == 1);
        const std::string detail = last_gap();
        CHECK_THAT(detail, ContainsSubstring("(4 child key(s) denied read access"));
        CHECK_THAT(detail, ContainsSubstring(a + "; " + b + "; " + c + "; +1 more"));
        CHECK_THAT(detail, !ContainsSubstring(d));
    }

    SECTION("a denied child's name is key text a user chose: control bytes never reach the stored detail") {
        next_tick(S::Complete, {kRoot + "\\x\r\n\x1b[31mred", kRoot + "\\tab\there"});
        REQUIRE(gap_count() == 1);
        const std::string detail = last_gap();
        CHECK(detail.find_first_of("\r\n\t\x1b") == std::string::npos);
        // CR, LF and ESC each fold to one underscore; the TAB too. Names list in sorted order.
        CHECK_THAT(detail, ContainsSubstring("tab_here; " + kRoot + "\\x___[31mred"));
    }

    SECTION("a root that stays Capped cannot grow the stored denied set past kSkippedCap") {
        // Every Capped read brings kSkippedCap names the stored set has not seen. Each still
        // gains (its one gap row), but the persisted set holds the sorted first kSkippedCap.
        for (int round = 0; round < 3; ++round) {
            std::vector<std::string> fresh;
            for (std::size_t i = 0; i < kSkippedCap; ++i)
                fresh.push_back(std::format("{}\\D{}_{:03}", kRoot, round, i));
            CHECK(next_tick(S::Capped, fresh).events_emitted == 1);
            CHECK(stored().size() == kSkippedCap);
        }
        CHECK(gap_count() == 3);
        CHECK(stored().front() == kRoot + "\\D0_000");
        CHECK(stored().back() == kRoot + "\\D0_031");
    }
}

TEST_CASE("registry source: with a budget admitting one root per tick every root is read within n ticks (R15)",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    const std::vector<std::string> roots{"HKLM\\SOFTWARE\\yuzu_test_a", "HKLM\\SOFTWARE\\yuzu_test_b",
                                         "HKLM\\SOFTWARE\\yuzu_test_c"};
    auto reader = f.reader();
    auto inner = reader.read_subtree;
    reader.read_subtree = [&f, inner](const std::string& root, std::int64_t deadline) {
        auto r = inner(root, deadline);
        f.clock += 11 * SEC; // exhausts the 10 s budget after every root
        return r;
    };
    auto src = make_registry_cursor_source(
       RegistryScope{{"SOFTWARE\\yuzu_test_a", "SOFTWARE\\yuzu_test_b", "SOFTWARE\\yuzu_test_c"}, {}},
       std::move(reader));
    SubtreeRead bad;
    bad.status = RegistryReadStatus::Unreadable; // always due
    for (const auto& r : roots)
        f.reads[r] = bad;
    std::set<std::string> seen;
    for (int i = 0; i < 3; ++i) {
        f.read_calls.clear();
        tick(t.db, *src);
        REQUIRE(f.read_calls.size() == 1); // the budget admitted exactly one
        seen.insert(f.read_calls[0]);
    }
    CHECK(seen == std::set<std::string>(roots.begin(), roots.end()));
}

TEST_CASE("registry source: a root that stays Unreadable under budget pressure keeps its status and writes ONE gap (R15)",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto reader = f.reader();
    auto inner = reader.read_subtree;
    reader.read_subtree = [&f, inner](const std::string& root, std::int64_t deadline) {
        auto r = inner(root, deadline);
        f.clock += 11 * SEC; // exhausts the 10 s budget after every root
        return r;
    };
    auto src = make_registry_cursor_source(scope2(), std::move(reader));
    SubtreeRead bad;
    bad.status = RegistryReadStatus::Unreadable;
    f.reads[kRoot] = bad; // A: unreadable on every read
    f.reads[kRoot2] = complete({{kRoot2 + "\\S", {{"Count", vread(4, dword(1))}}}}); // B: readable, due every tick

    // The budget admits one root per tick and the start index rotates, so A is read on ticks
    // 0 and 2 and deadline-skipped on ticks 1 and 3. A skipped Unreadable root must stay
    // "unreadable": if it flapped to "due", its next Unreadable read would look like a new
    // loss and write the gap again.
    for (int i = 0; i < 4; ++i) {
        f.read_calls.clear();
        f.dirty->mark(kRoot2, f.clock);
        tick(t.db, *src);
        REQUIRE(f.read_calls.size() == 1);
        CHECK(f.read_calls[0] == (i % 2 == 0 ? kRoot : kRoot2));
        CHECK(read_cursor(t.db).roots.at(kRoot).status == "unreadable");
    }
    const auto gaps = q(t.db, "SELECT detail FROM registry_live WHERE record_key LIKE 'gap:unreadable:%'");
    REQUIRE(gaps.rows.size() == 1);
    CHECK_THAT(gaps.rows[0][0], ContainsSubstring("gap:unreadable:" + kRoot + " (the root could not be read"));
    CHECK(count_rows(t.db) == 1); // B's unchanged reads wrote nothing
}

TEST_CASE("registry source: a control-set switch re-baselines CurrentControlSet roots; a failed read does not",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    const std::string svc_root = "HKLM\\SYSTEM\\CurrentControlSet\\Services";
    auto src = make_registry_cursor_source(RegistryScope{{"SYSTEM\\CurrentControlSet\\Services"}, {}},
                                           f.reader());
    f.reads[svc_root] = complete({{svc_root + "\\A", {{"Start", vread(4, dword(2))}}}});
    tick(t.db, *src);
    CHECK(read_cursor(t.db).ccs == "ControlSet001");

    f.ccs = 0; // Select\Current unreadable this tick: not a switch
    f.clock = T0 + 100 * SEC;
    f.dirty->mark(svc_root, f.clock);
    tick(t.db, *src);
    CHECK(count_rows(t.db) == 0);
    CHECK(read_cursor(t.db).ccs == "ControlSet001");

    f.ccs = 2; // the machine now runs from ControlSet002: the same path holds different keys
    f.reads[svc_root] = complete({{svc_root + "\\B", {{"Start", vread(4, dword(3))}}}});
    f.clock = T0 + 200 * SEC;
    f.dirty->mark(svc_root, f.clock);
    tick(t.db, *src);
    const auto rows = q(t.db, "SELECT detail FROM registry_live");
    REQUIRE(rows.rows.size() == 1); // one gap; no removed/added storm
    CHECK_THAT(rows.rows[0][0], ContainsSubstring("control set changed"));
    CHECK(read_cursor(t.db).ccs == "ControlSet002");
}

TEST_CASE("registry source: a logged-off user's roots leave scope without a removal storm",
          "[echo][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    f.sids = {"S-1-5-21-1"};
    const std::string user_root = "HKU\\S-1-5-21-1\\Software\\yuzu_test_u";
    auto src = make_registry_cursor_source(RegistryScope{{}, {"Software\\yuzu_test_u"}}, f.reader());
    f.reads[user_root] = complete({{user_root, {{"v", vread(4, dword(1))}}}});
    tick(t.db, *src);
    CHECK(f.watch_calls.back() == std::vector<std::string>{user_root});
    const std::string empty_baseline = R"({"v":1,"keys":{}})";
    CHECK(*t.db.try_get_state("registry:" + user_root).value() != empty_baseline);
    f.sids.clear();
    f.clock = T0 + 100 * SEC;
    f.dirty->mark_hku();
    f.reads.erase(user_root); // the hive is unloaded: the path reads Absent
    tick(t.db, *src);
    CHECK(f.watch_calls.back().empty());
    CHECK(count_rows(t.db) == 0); // not read, so no mass removal
    CHECK(*t.db.try_get_state("registry:" + user_root).value() == empty_baseline); // and no values kept
    CHECK(read_cursor(t.db).roots.empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Offline (unloaded) hives over an injected reader
// ═══════════════════════════════════════════════════════════════════════════

namespace {

const std::string kEmptyBaseline = R"({"v":1,"keys":{}})";

SubtreeRead uread(const std::string& root, std::uint32_t v) {
    return complete({{root, {{"v", vread(4, dword(v))}}}});
}

OfflineHiveRead hive_read(std::map<std::string, SubtreeRead> roots) {
    OfflineHiveRead h;
    h.roots = std::move(roots);
    return h;
}

// What read_offline_hive answers when the guard refuses the hive: every root Unreadable, the
// refusal token on the hive and on each root.
OfflineHiveRead refused_hive(const std::vector<std::string>& roots, const std::string& reason) {
    OfflineHiveRead h;
    h.reason = reason;
    for (const auto& root : roots) {
        SubtreeRead u;
        u.status = RegistryReadStatus::Unreadable;
        u.reason = reason;
        h.roots[root] = u;
    }
    return h;
}

// One scripted reader, one database, the source over them.
struct OfflineRig {
    TestDb t = make_db();
    Fake f;
    std::unique_ptr<RegistryCursorSource> src;

    explicit OfflineRig(RegistryScope scope = RegistryScope{{}, {kSuffix}}) {
        src = make_registry_cursor_source(std::move(scope), f.reader());
    }
    // Ordinary ticks until the persisted cursor says `cursor_tick` ticks have run (the next
    // tick is then the one with cur.tick == cursor_tick: 12 is the hourly reconcile).
    void tick_to(std::int64_t cursor_tick) {
        while (read_cursor(t.db).tick < cursor_tick) {
            f.clock += SEC;
            tick(t.db, *src);
        }
    }
    CursorCollectResult next() {
        f.clock += SEC;
        return tick(t.db, *src);
    }
    std::string state(const std::string& root) {
        const auto r = t.db.try_get_state("registry:" + root);
        REQUIRE(r.has_value());
        return r->value_or("");
    }
    std::string config(const std::string& key) { return t.db.get_config(key, ""); }
    std::int64_t gap_unreadable_rows() {
        return std::stoll(
           q(t.db, "SELECT COUNT(*) FROM registry_live WHERE record_key LIKE 'gap:unreadable:%'")
              .rows.at(0).at(0));
    }
};

} // namespace

TEST_CASE("registry offline: first sight baselines silently; one mount per hive per hour, and discovery only when the loaded list is re-enumerated",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});

    CHECK(r.next().outcome == CursorOutcome::Baseline);
    CHECK(r.f.offline_profile_calls == 1);
    REQUIRE(r.f.offline_calls.size() == 1);
    CHECK(r.f.offline_calls[0].sid == kSidA);
    CHECK(r.f.offline_calls[0].path == prof(kSidA).path);
    CHECK(r.f.offline_calls[0].roots == std::vector<std::string>{root});
    CHECK(r.f.offline_calls[0].deadline > T0);
    CHECK(count_rows(r.t.db) == 0);
    CHECK(r.state(root) != kEmptyBaseline);
    CHECK(r.f.read_calls.empty()); // the loaded-hive reader is not used for an offline root

    r.tick_to(12); // eleven ordinary ticks: no hive mount and no profile walk
    CHECK(r.f.offline_profile_calls == 1);
    CHECK(r.f.offline_calls.size() == 1);

    // the hourly reconcile re-walks and re-reads; a changed value lands in THAT tick
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 2)}});
    CHECK(r.next().events_emitted == 1);
    CHECK(r.f.offline_profile_calls == 2);
    CHECK(r.f.offline_calls.size() == 2);
    const auto rows = q(r.t.db, "SELECT action, hive, key_path, data, prev_data, actor_pid, "
                                "detail, source, record_key FROM registry_live");
    REQUIRE(rows.rows.size() == 1);
    const auto& row = rows.rows[0];
    CHECK(row[0] == "changed");
    CHECK(row[1] == "HKU");
    CHECK(row[2] == kSidA + "\\" + kSuffix); // the logical name, never a salted mount name
    CHECK(row[3] == "2");
    CHECK(row[4] == "1");
    CHECK(row[5] == "0");
    CHECK(row[6] == "attr:offline");
    CHECK(row[7] == "offline");
    CHECK_THAT(row[8], ContainsSubstring("offline:"));
    CHECK(read_cursor(r.t.db).held.empty());
    CHECK(r.state(root) != kEmptyBaseline);

    // an HKU name-watch mark re-walks too; the cursor's list otherwise stands
    r.f.dirty->mark_hku();
    r.next();
    CHECK(r.f.offline_profile_calls == 3);
    CHECK(r.f.offline_calls.size() == 2);
}

TEST_CASE("registry offline: offline roots are never watched, never counted as watch roots; a capped read stays visible",
          "[echo][registry][lifecycle]") {
    OfflineRig r(RegistryScope{{"SOFTWARE\\yuzu_test_r"}, {kSuffix}});
    const auto live = uroot(kSidB);
    const auto off = uroot(kSidA);
    r.f.sids = {kSidB};
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.reads[kRoot] = svc(1);
    r.f.reads[live] = uread(live, 1);
    SubtreeRead capped = uread(off, 1);
    capped.status = RegistryReadStatus::Capped;
    r.f.offline_reads[kSidA] = hive_read({{off, capped}});
    r.next();

    REQUIRE_FALSE(r.f.watch_calls.empty());
    for (const auto& call : r.f.watch_calls)
        CHECK(std::find(call.begin(), call.end(), off) == call.end());
    CHECK(r.f.watch_calls.back() == std::vector<std::string>{kRoot, live});
    CHECK(r.config("registry_watch_roots") == "2");
    CHECK(r.config("registry_watch_roots_unarmed") == "0");
    CHECK(r.config("registry_offline_roots") == "1");
    CHECK(r.config("registry_offline_roots_unreadable") == "0");
    CHECK(r.config("registry_offline_discovery_incomplete") == "0");
    CHECK(r.config("registry_roots_capped") == "1"); // aggregate: the capped offline read counts
    CHECK(read_cursor(r.t.db).roots.at(off).armed);
}

TEST_CASE("registry offline: a sid in both snapshots is live - watched, dirty-driven, never in cursor.offline",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.sids = {kSidA};
    r.f.offline_discovery.profiles = {prof(kSidA)}; // the profile list lags the HKU snapshot
    r.f.reads[root] = uread(root, 1);
    r.next();
    CHECK(r.f.offline_calls.empty());
    CHECK(r.f.read_calls == std::vector<std::string>{root});
    CHECK(r.f.watch_calls.back() == std::vector<std::string>{root});
    CHECK(read_cursor(r.t.db).offline.empty());
    CHECK(r.config("registry_watch_roots") == "1");
    CHECK(r.config("registry_offline_roots") == "0");

    // dirty-driven like any loaded root
    r.f.read_calls.clear();
    r.f.dirty->mark(root, r.f.clock);
    r.f.reads[root] = uread(root, 2);
    r.next();
    CHECK(r.f.read_calls == std::vector<std::string>{root});
    CHECK(r.f.offline_calls.empty());
}

TEST_CASE("registry offline: a hive with several roots is mounted once, and a re-enable re-baselines every one of its roots silently",
          "[echo][registry][lifecycle]") {
    OfflineRig r(RegistryScope{{"SOFTWARE\\yuzu_test_r"}, {kSuffix, kSuffix2}});
    r.f.offline_discovery.profiles = {prof(kSidA), prof(kSidB)};
    r.f.reads[kRoot] = svc(1);
    const auto a1 = uroot(kSidA), a2 = uroot(kSidA, kSuffix2);
    const auto b1 = uroot(kSidB), b2 = uroot(kSidB, kSuffix2);
    const auto script = [&](std::uint32_t a_second_root) {
        r.f.offline_reads[kSidA] = hive_read({{a1, uread(a1, 1)}, {a2, uread(a2, a_second_root)}});
        r.f.offline_reads[kSidB] = hive_read({{b1, uread(b1, 1)}, {b2, uread(b2, 1)}});
    };
    script(1);
    r.next();
    REQUIRE(r.f.offline_calls.size() == 2); // exactly one mount per sid, each carrying both roots
    CHECK(r.f.offline_calls[0].sid != r.f.offline_calls[1].sid);
    CHECK(r.f.offline_calls[0].roots.size() == 2);
    CHECK(r.f.offline_calls[1].roots.size() == 2);
    const auto before = r.state(a2);
    REQUIRE(before != kEmptyBaseline);

    // the SECOND root of A changes while the source is disabled: the re-enable must re-baseline it
    // together with the first (a member left baselined would report the change as a row)
    script(2);
    r.src->on_enabled_changed(false);
    r.src->on_enabled_changed(true);
    r.next();
    CHECK(r.f.offline_calls.size() == 4); // one more mount per sid, in THAT tick
    CHECK(q(r.t.db, "SELECT COUNT(*) FROM registry_live WHERE action = 'changed'")
             .rows.at(0).at(0) == "0");
    CHECK(count_rows(r.t.db) == 1); // only the disabled-window gap
    CHECK(r.state(a2) != before);   // the new state is the baseline
    const auto cur = read_cursor(r.t.db);
    for (const auto& root : {a1, a2, b1, b2}) {
        CHECK(cur.roots.at(root).baselined);
        CHECK(r.state(root) != kEmptyBaseline);
    }

    // a refusal is one gap row PER ROOT: both of A's roots report it
    r.f.offline_reads[kSidA] = refused_hive({a1, a2}, "offline:hive_path_unc");
    r.tick_to(12);
    r.next();
    CHECK(r.gap_unreadable_rows() == 2);
}

TEST_CASE("registry offline: a refused hive keeps its baseline, writes one gap row per root naming the reason (one here: a single-root scope), and costs one attempt an hour",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    const std::string why = "offline:hive_path_unc";
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next();
    const auto baseline = r.state(root);

    r.f.offline_reads[kSidA] = refused_hive({root}, why);
    r.tick_to(12);
    CHECK(r.f.offline_calls.size() == 1); // between reconciles: no attempt
    r.next();                             // the reconcile
    CHECK(r.f.offline_calls.size() == 2);
    CHECK(r.gap_unreadable_rows() == 1);
    const auto gap = q(r.t.db, "SELECT action, detail FROM registry_live "
                               "WHERE record_key LIKE 'gap:unreadable:%'");
    CHECK(gap.rows.at(0).at(0) == "capture_gap");
    CHECK_THAT(gap.rows.at(0).at(1), ContainsSubstring(why));
    CHECK_THAT(gap.rows.at(0).at(1), ContainsSubstring(root));
    CHECK(r.state(root) == baseline); // kept
    CHECK(r.config("registry_offline_roots_unreadable") == "1");
    CHECK(r.config("registry_roots_unreadable") == "1");

    r.tick_to(24);
    CHECK(r.f.offline_calls.size() == 2);
    r.next(); // the next hour: tried again, still refused, no second row
    CHECK(r.f.offline_calls.size() == 3);
    CHECK(r.gap_unreadable_rows() == 1);
    CHECK(count_rows(r.t.db) == 1);
}

TEST_CASE("registry offline: a refused hive the budget defers keeps status unreadable and is retried NEXT tick, with no second gap row per root",
          "[echo][registry][lifecycle]") {
    OfflineRig r(RegistryScope{{"SOFTWARE\\yuzu_test_r"}, {kSuffix}});
    const auto root = uroot(kSidA);
    bool burn = false;
    auto reader = r.f.reader();
    auto read = reader.read_subtree;
    reader.read_subtree = [&r, &burn, read](const std::string& rt, std::int64_t deadline) {
        auto res = read(rt, deadline);
        if (burn && rt == kRoot)
            r.f.clock += kSnapshotBudget100ns + SEC; // the budget is spent by the first read
        return res;
    };
    r.src = make_registry_cursor_source(RegistryScope{{"SOFTWARE\\yuzu_test_r"}, {kSuffix}},
                                        std::move(reader));
    r.f.reads[kRoot] = svc(1);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next();
    r.f.offline_reads[kSidA] = refused_hive({root}, "offline:hive_path_unc");
    r.tick_to(12);
    r.next(); // reconcile: refused, one row
    REQUIRE(r.f.offline_calls.size() == 2);
    REQUIRE(r.gap_unreadable_rows() == 1);

    r.tick_to(24);
    burn = true;
    r.next(); // reconcile: the HKLM root spends the budget, the refused hive is deferred
    burn = false;
    CHECK(r.f.offline_calls.size() == 2);
    const auto deferred = read_cursor(r.t.db).roots.at(root);
    CHECK(deferred.deferred);
    CHECK(deferred.status == "unreadable"); // untouched: one gap row per transition
    r.next();                               // NEXT tick, not the next reconcile
    CHECK(r.f.offline_calls.size() == 3);
    CHECK_FALSE(read_cursor(r.t.db).roots.at(root).deferred);
    CHECK(r.gap_unreadable_rows() == 1);
    r.next();
    CHECK(r.f.offline_calls.size() == 3); // back to hourly
}

TEST_CASE("registry offline: a mount that was not attempted writes no baseline and no row, and is retried next tick",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    OfflineHiveRead skipped;
    skipped.attempted = false;
    skipped.reason = "offline:skipped_after_timeout";
    r.f.offline_reads[kSidA] = skipped;
    r.next();
    CHECK(r.f.offline_calls.size() == 1);
    const auto st = r.t.db.try_get_state("registry:" + root);
    REQUIRE(st.has_value());
    CHECK_FALSE(st->has_value()); // no baseline written
    CHECK(count_rows(r.t.db) == 0);
    const auto cur = read_cursor(r.t.db);
    CHECK(cur.roots.at(root).deferred);
    CHECK_FALSE(cur.roots.at(root).baselined);

    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next(); // not the next reconcile: the next tick
    CHECK(r.f.offline_calls.size() == 2);
    const auto after = read_cursor(r.t.db).roots.at(root);
    CHECK_FALSE(after.deferred);
    CHECK(after.baselined);
    CHECK(r.state(root) != kEmptyBaseline);
    CHECK(count_rows(r.t.db) == 0);
}

TEST_CASE("registry offline: a re-enable re-baselines an offline root in THAT tick, silently",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next();
    r.tick_to(3);
    REQUIRE(r.f.offline_calls.size() == 1);
    const auto before = r.state(root);

    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 2)}}); // changed while disabled
    r.src->on_enabled_changed(false);
    r.src->on_enabled_changed(true);
    r.next();
    CHECK(r.f.offline_calls.size() == 2); // not the next hourly reconcile
    CHECK(r.state(root) != before);       // the new state is the baseline ...
    CHECK(count_rows(r.t.db) == 1);       // ... and only the disabled-window gap was written
    CHECK(q(r.t.db, "SELECT COUNT(*) FROM registry_live WHERE action = 'changed'")
             .rows.at(0).at(0) == "0");
}

TEST_CASE("registry offline: logoff keeps scope, resets the retention term and consumes the stale notify; a failed commit restores it",
          "[echo][registry][lifecycle]") {
    OfflineRig r(RegistryScope{{"SOFTWARE\\yuzu_test_r"}, {kSuffix}});
    const auto root = uroot(kSidA);
    r.f.sids = {kSidA};
    r.f.reads[kRoot] = svc(1);
    r.f.reads[root] = uread(root, 1);
    r.next();
    const auto live = read_cursor(r.t.db);
    REQUIRE(live.roots.at(root).window_base != 0);
    REQUIRE(live.roots.at(kRoot).window_base != 0);
    const auto baseline = r.state(root);

    // an unread notify on the user's root, then the user logs off
    const std::int64_t notify = r.f.clock + 5 * SEC;
    r.f.dirty->mark(root, notify);
    r.f.sids.clear();
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.dirty->mark_hku();
    r.f.loss.events_lost = 1; // a gap:loss row, so the commit has a row to fail on
    r.f.clock += 10 * SEC;
    {
        InsertTrap trap(r.t.path);
        CHECK_THROWS_AS(r.next(), IncompleteCaptureError);
    }
    CHECK(r.f.dirty->first(root) == notify); // the take was restored
    CHECK(r.f.dirty->peek_dirty(root));

    r.next(); // the retry commits
    CHECK(r.f.dirty->first(root) == 0);        // consumed
    CHECK_FALSE(r.f.dirty->peek_dirty(root));
    CHECK(r.f.offline_calls.empty());          // no hive read: it is not due
    const auto cur = read_cursor(r.t.db);
    REQUIRE(cur.roots.contains(root));         // still in scope ...
    CHECK(cur.roots.at(root).window_base == 0); // ... with nothing from its loaded life
    CHECK(cur.roots.at(root).baselined);
    CHECK(cur.offline == std::vector<OfflineProfile>{prof(kSidA)});
    CHECK(r.state(root) == baseline);          // no leave-scope drop
    CHECK(q(r.t.db, "SELECT COUNT(*) FROM registry_live WHERE action != 'capture_gap'")
             .rows.at(0).at(0) == "0");
    // the retention floor is the other root's base alone
    CHECK(retention_watermark(cur.roots, {}) == cur.roots.at(kRoot).window_base);

    // A notify that lands on the root AFTER the logoff take is never read (nothing watches an
    // unloaded hive) and must not hold the floor: an event older than the loaded root's base is
    // still released, though the offline root's unread notify is older still.
    const std::int64_t base = cur.roots.at(kRoot).window_base;
    r.src->push_event_for_test(ev(base - 1, 9, RegistryEtwOp::Set, "late"));
    r.f.dirty->mark(root, base - 500 * SEC);
    r.next();
    CHECK(r.src->buffer_for_test().size() == 0);
    CHECK(read_cursor(r.t.db).roots.at(kRoot).window_base == base); // that tick read nothing

    // the hourly offline read diffs against the baseline the loaded hive left behind
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 2)}});
    r.tick_to(12);
    r.next();
    REQUIRE(r.f.offline_calls.size() == 1);
    const auto rows = q(r.t.db, "SELECT prev_data, data, detail FROM registry_live "
                                "WHERE action = 'changed'");
    REQUIRE(rows.rows.size() == 1);
    CHECK(rows.rows[0][0] == "1");
    CHECK(rows.rows[0][1] == "2");
    CHECK(rows.rows[0][2] == "attr:offline");
}

TEST_CASE("registry offline: logon reads the loaded hive at once against the offline baseline (a RunOnce consumed at logon is removed, lost-restart)",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    r.src->start(r.t.db); // the buffer holds nothing from before this instant
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] =
       hive_read({{root, complete({{root, {{"once", vread(4, dword(1))}}}})}});
    r.next();
    REQUIRE(r.f.offline_calls.size() == 1);
    REQUIRE(read_cursor(r.t.db).roots.at(root).window_base == 0);

    // the user logs on: the value is gone, no notify was ever marked
    r.f.sids = {kSidA};
    r.f.offline_discovery.profiles.clear();
    r.f.dirty->mark_hku();
    r.f.reads[root] = complete({{root, {}}});
    r.next();
    CHECK(r.f.read_calls == std::vector<std::string>{root}); // read in THIS tick
    CHECK(r.f.offline_calls.size() == 1);
    CHECK(r.f.watch_calls.back() == std::vector<std::string>{root});
    const auto rows = q(r.t.db, "SELECT action, value_name, detail, source FROM registry_live");
    REQUIRE(rows.rows.size() == 1);
    CHECK(rows.rows[0][0] == "removed");
    CHECK(rows.rows[0][1] == "once");
    CHECK(rows.rows[0][2] == "attr:lost-restart"); // window_base 0, so the floor says it
    CHECK(rows.rows[0][3] == "reconcile");
    const auto cur = read_cursor(r.t.db);
    CHECK(cur.roots.at(root).window_base != 0); // advances from here
    CHECK(cur.offline.empty());
}

TEST_CASE("registry offline: an offline read never advances window_base and leaves the retention floor to the loaded roots",
          "[echo][registry][lifecycle]") {
    OfflineRig r(RegistryScope{{"SOFTWARE\\yuzu_test_r"}, {kSuffix}});
    const auto root = uroot(kSidA);
    r.f.reads[kRoot] = svc(1);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next();
    const auto first_base = read_cursor(r.t.db).roots.at(kRoot).window_base;
    REQUIRE(first_base != 0);
    r.tick_to(12);

    // one event the live root's base has already passed, one far ahead of it
    r.src->push_event_for_test(ev(first_base + 1, 1, RegistryEtwOp::Set, "old"));
    r.src->push_event_for_test(ev(first_base + 100000 * SEC, 2, RegistryEtwOp::Set, "new"));
    r.next(); // reconcile: both roots are read; the offline one at an hour's age
    const auto cur = read_cursor(r.t.db);
    CHECK(r.f.offline_calls.size() == 2);
    CHECK(cur.roots.at(root).window_base == 0); // an offline read never advances it
    CHECK(retention_watermark(cur.roots, {}) == cur.roots.at(kRoot).window_base);
    CHECK(cur.roots.at(kRoot).window_base > first_base + 1);
    CHECK(r.src->buffer_for_test().size() == 1); // the old event was released, the new one kept
}

TEST_CASE("registry offline: an incomplete profile walk keeps the known scope and is flagged; a complete one clears the flag",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next();
    const auto baseline = r.state(root);
    r.tick_to(12);

    // the reconcile's walk fails (ProfileList unopenable, cut short, ...) and the hive changed
    r.f.offline_discovery = OfflineDiscovery{false, {}, {}};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 2)}});
    r.next();
    CHECK(r.config("registry_offline_discovery_incomplete") == "1");
    CHECK(read_cursor(r.t.db).offline ==
          std::vector<OfflineProfile>{prof(kSidA)}); // no scope removal
    CHECK(read_cursor(r.t.db).roots.contains(root));
    CHECK(r.state(root) != kEmptyBaseline); // the baseline was not erased
    CHECK(r.state(root) != baseline);       // the known path was still read: the change is not lost
    const auto rows = q(r.t.db, "SELECT prev_data, data, detail FROM registry_live");
    REQUIRE(rows.rows.size() == 1);
    CHECK(rows.rows[0][0] == "1");
    CHECK(rows.rows[0][1] == "2");
    CHECK(rows.rows[0][2] == "attr:offline");

    // the next complete walk lists it again: the flag clears, nothing is re-baselined or repeated
    r.f.offline_discovery = OfflineDiscovery{};
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.dirty->mark_hku();
    r.next();
    CHECK(r.config("registry_offline_discovery_incomplete") == "0");
    CHECK(read_cursor(r.t.db).offline == std::vector<OfflineProfile>{prof(kSidA)});
    CHECK(count_rows(r.t.db) == 1);
}

TEST_CASE("registry offline: a user who logs off on a tick whose walk is incomplete keeps the baseline, is not read without a path, and is read the tick a complete walk supplies it",
          "[echo][registry][lifecycle]") {
    // The walk fails outright, or is complete but the user's own record failed to read.
    for (const OfflineDiscovery& walk :
         {OfflineDiscovery{false, {}, {}}, OfflineDiscovery{true, {kSidA}, {}}}) {
        INFO("complete=" << walk.complete << " partial=" << walk.partial.size());
        OfflineRig r;
        const auto root = uroot(kSidA);
        r.f.sids = {kSidA};
        r.f.reads[root] = uread(root, 1);
        r.next(); // A is loaded and baselined
        const auto baseline = r.state(root);
        REQUIRE(baseline != kEmptyBaseline);
        REQUIRE(read_cursor(r.t.db).roots.at(root).window_base != 0);

        // A logs off on the tick the walk is bad: nothing says A's profile is gone
        r.f.sids.clear();
        r.f.offline_discovery = walk;
        r.f.dirty->mark_hku();
        r.next();
        auto cur = read_cursor(r.t.db);
        REQUIRE(cur.roots.contains(root));
        CHECK(cur.roots.at(root).baselined);
        CHECK(cur.roots.at(root).window_base == 0);
        CHECK(cur.roots.at(root).deferred); // due the moment a path is known
        CHECK(cur.offline == std::vector<OfflineProfile>{{kSidA, ""}});
        CHECK(r.state(root) == baseline);   // not emptied
        CHECK(r.f.offline_calls.empty());   // no path, so no mount
        CHECK(count_rows(r.t.db) == 0);
        CHECK(r.config("registry_offline_discovery_incomplete") == (walk.complete ? "0" : "1"));

        // The next ORDINARY tick walks again (the path is unknown), the complete walk lists A,
        // and A is read at once -- not at the next hourly reconcile -- against the loaded baseline.
        const int walks = r.f.offline_profile_calls;
        r.f.offline_discovery = OfflineDiscovery{};
        r.f.offline_discovery.profiles = {prof(kSidA)};
        r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 2)}});
        r.next();
        CHECK(r.f.offline_profile_calls == walks + 1);
        REQUIRE(r.f.offline_calls.size() == 1);
        CHECK(r.f.offline_calls[0].path == prof(kSidA).path);
        const auto rows = q(r.t.db, "SELECT action, prev_data, data, detail FROM registry_live");
        REQUIRE(rows.rows.size() == 1);
        CHECK(rows.rows[0][0] == "changed");
        CHECK(rows.rows[0][1] == "1");
        CHECK(rows.rows[0][2] == "2");
        CHECK(rows.rows[0][3] == "attr:offline");
        cur = read_cursor(r.t.db);
        CHECK_FALSE(cur.roots.at(root).deferred);
        CHECK(cur.offline == std::vector<OfflineProfile>{prof(kSidA)});
        CHECK(r.config("registry_offline_discovery_incomplete") == "0");

        r.next(); // settled: no more walks, no more mounts until the hour
        CHECK(r.f.offline_profile_calls == walks + 1);
        CHECK(r.f.offline_calls.size() == 1);
    }
}

TEST_CASE("registry offline: an incomplete walk is retried on the next ordinary tick, not at the next hour",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next();
    r.tick_to(12);
    r.f.offline_discovery.complete = false;
    r.next(); // the reconcile: the walk is incomplete, the known list (with its path) stands
    REQUIRE(r.config("registry_offline_discovery_incomplete") == "1");
    const int walks = r.f.offline_profile_calls;

    r.next(); // an ordinary tick, no HKU mark: walks again, still incomplete
    CHECK(r.f.offline_profile_calls == walks + 1);
    r.f.offline_discovery.complete = true;
    r.next(); // and again: now complete, the flag clears
    CHECK(r.f.offline_profile_calls == walks + 2);
    CHECK(r.config("registry_offline_discovery_incomplete") == "0");
    r.next(); // settled
    CHECK(r.f.offline_profile_calls == walks + 2);
    CHECK(read_cursor(r.t.db).offline == std::vector<OfflineProfile>{prof(kSidA)});
}

TEST_CASE("registry offline: a user who logs off while the walk stays incomplete stays in scope and is walked again every tick, then dropped by the first complete walk that omits it",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.sids = {kSidA};
    r.f.reads[root] = uread(root, 1);
    r.next();
    r.f.sids.clear();
    r.f.offline_discovery = OfflineDiscovery{false, {}, {}};
    r.f.dirty->mark_hku();
    r.next();
    const int walks = r.f.offline_profile_calls;
    for (int i = 1; i <= 3; ++i) { // ordinary ticks, no HKU mark: the walk repeats anyway
        r.next();
        CHECK(r.f.offline_profile_calls == walks + i);
        CHECK(read_cursor(r.t.db).offline == std::vector<OfflineProfile>{{kSidA, ""}});
        CHECK(r.state(root) != kEmptyBaseline);
    }
    CHECK(r.f.offline_calls.empty());
    CHECK(count_rows(r.t.db) == 0);

    // a complete walk that names it nowhere is authoritative: the profile left ProfileList
    r.f.offline_discovery = OfflineDiscovery{};
    r.next();
    CHECK(read_cursor(r.t.db).roots.empty());
    CHECK(read_cursor(r.t.db).offline.empty());
    CHECK(r.state(root) == kEmptyBaseline);
    CHECK(count_rows(r.t.db) == 0);
    CHECK(r.f.offline_calls.empty());
}

TEST_CASE("registry offline: collect enumerates HKU once per tick and hands that one list to the profile walk",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const std::string sid_c = "S-1-5-21-3";
    r.f.offline_discovery.profiles = {prof(kSidA)};
    std::vector<std::vector<std::string>> expected;
    const auto tick_with = [&](std::vector<std::string> loaded) {
        r.f.sids = loaded;
        r.f.dirty->mark_hku();
        expected.push_back(std::move(loaded));
        r.next();
    };
    const auto enumerations_so_far = [&] { return r.f.loaded_sids_calls; };
    tick_with({kSidB}); // the first tick walks
    CHECK(enumerations_so_far() == 1);
    tick_with({kSidB, sid_c});
    CHECK(enumerations_so_far() == 2);
    tick_with({});
    CHECK(enumerations_so_far() == 3);
    tick_with({kSidB});
    CHECK(enumerations_so_far() == 4);
    // exactly one HKU enumeration per tick (the profile walk is handed its result, never a second
    // snapshot), and one walk per tick, each handed the exact list collect() took for that tick
    CHECK(r.f.offline_loaded_args == expected);
    CHECK(r.f.offline_profile_calls == 4);
}

TEST_CASE("classify_offline_discovery: a profile missing from collect's HKU snapshot is offline, even if it has logged on since",
          "[echo][registry][pure]") {
    using yuzu::profiles::RawProfileRecord;
    // The ProfileList record exists. collect()'s snapshot was taken before A's hive loaded, so A
    // is not in it: classified against that snapshot A is offline and is carried, not dropped.
    // (A logon after the snapshot is handled by the next tick: the HKU name watch moves A to
    // the loaded list, and the live arm of the mount reads the loaded hive meanwhile.)
    const std::vector<RawProfileRecord> records{{kSidA, "C:\\Users\\a", false}};
    const std::vector<std::string> snapshot{kSidB};
    const std::vector<std::string> none;
    const auto profiles = yuzu::profiles::build_profile_list(records, snapshot);
    const auto d = classify_offline_discovery(true, false, false, profiles, none);
    CHECK(d.complete);
    CHECK(d.profiles == std::vector<OfflineProfile>{{kSidA, "C:\\Users\\a"}});
    CHECK(reconcile_offline({}, {}, snapshot, d) == d.profiles);
    // the same record against a snapshot that holds A classifies it loaded, not offline
    const auto loaded =
       yuzu::profiles::build_profile_list(records, std::vector<std::string>{kSidA});
    CHECK(classify_offline_discovery(true, false, false, loaded, none).profiles.empty());
}

TEST_CASE("registry offline: a re-enable does not retry a refused offline hive until the next hour, keeps its baseline state, and writes no second unreadable row",
          "[echo][registry][lifecycle]") {
    // Both a hive that was baselined before the guard refused it and one refused on first sight.
    // A refused root is not due on the re-enable tick (its status is `unreadable`, so the
    // `!baselined` clause does not fire); it waits for the reconcile like any refused hive.
    for (const bool baselined_first : {true, false}) {
        INFO("baselined before the refusal: " << baselined_first);
        OfflineRig r;
        const auto root = uroot(kSidA);
        const std::string why = "offline:hive_path_unc";
        r.f.offline_discovery.profiles = {prof(kSidA)};
        if (baselined_first) {
            r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
            r.next();
            r.tick_to(12);
        }
        r.f.offline_reads[kSidA] = refused_hive({root}, why);
        r.next(); // the reconcile (baselined) or the first sight (never baselined): refused
        const auto attempts = r.f.offline_calls.size();
        const auto kept = r.state(root);
        REQUIRE(r.gap_unreadable_rows() == 1);
        REQUIRE(kept.empty() == !baselined_first);

        r.src->on_enabled_changed(false);
        r.src->on_enabled_changed(true);
        r.next(); // the re-enable tick
        CHECK(r.f.offline_calls.size() == attempts);          // not re-attempted
        CHECK(r.state(root) == kept);                         // baseline (or its absence) kept
        CHECK(r.gap_unreadable_rows() == 1);                  // the refusal row, once
        CHECK(q(r.t.db, "SELECT COUNT(*) FROM registry_live WHERE record_key LIKE 'gap:disabled:%'")
                 .rows.at(0).at(0) == "1");                   // the pause row
        CHECK(count_rows(r.t.db) == 2);
        const auto after = read_cursor(r.t.db).roots.at(root);
        CHECK_FALSE(after.baselined); // cleared by the re-enable; the next successful read sets it
        CHECK(after.status == "unreadable");

        // the next reconcile reads it once; readable now, it is re-baselined silently
        // (the paused window's change is never stored)
        r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 2)}});
        r.tick_to((read_cursor(r.t.db).tick / 12 + 1) * 12);
        CHECK(r.f.offline_calls.size() == attempts);
        r.next();
        CHECK(r.f.offline_calls.size() == attempts + 1);
        CHECK(read_cursor(r.t.db).roots.at(root).baselined);
        CHECK(r.state(root) != kEmptyBaseline);
        CHECK(r.state(root) != kept);
        CHECK(count_rows(r.t.db) == 2);
    }
}

TEST_CASE("registry offline: a record with an unreadable path keeps its entry; a complete walk that omits the profile drops it without a removal storm",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next();
    r.tick_to(12);

    // complete walk, the record is there, its ProfileImagePath was not readable this time
    r.f.offline_discovery = OfflineDiscovery{true, {kSidA}, {}};
    r.next();
    REQUIRE(r.f.offline_calls.size() == 2);
    CHECK(r.f.offline_calls.back().path == prof(kSidA).path); // the cursor's path was used
    CHECK(read_cursor(r.t.db).offline == std::vector<OfflineProfile>{prof(kSidA)});

    // complete walk that does not list it at all: the profile left ProfileList
    r.tick_to(24);
    r.f.offline_discovery = OfflineDiscovery{};
    r.next();
    CHECK(r.f.offline_calls.size() == 2); // not read
    CHECK(read_cursor(r.t.db).roots.empty());
    CHECK(read_cursor(r.t.db).offline.empty());
    CHECK(r.state(root) == kEmptyBaseline); // shrunk, not a removal storm
    CHECK(count_rows(r.t.db) == 0);
}

TEST_CASE("registry offline: a hive refused on first sight is retried only at reconcile",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    const std::string why = "offline:hive_path_unc";
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = refused_hive({root}, why);
    r.next(); // first sight: refused, so never baselined
    CHECK(r.f.offline_calls.size() == 1);
    CHECK(r.gap_unreadable_rows() == 1);
    CHECK(r.state(root).empty());
    CHECK_FALSE(read_cursor(r.t.db).roots.at(root).baselined);

    r.tick_to(11); // eleven ordinary ticks: a refusal costs one attempt an hour, not one a tick
    CHECK(r.f.offline_calls.size() == 1);
    CHECK(r.gap_unreadable_rows() == 1);
    r.tick_to(12);
    r.next(); // the reconcile retries once, still refused, no second row
    CHECK(r.f.offline_calls.size() == 2);
    CHECK(r.gap_unreadable_rows() == 1);

    // once the guard lets it through, the next reconcile baselines it silently
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.tick_to(24);
    CHECK(r.f.offline_calls.size() == 2);
    r.next();
    CHECK(r.f.offline_calls.size() == 3);
    CHECK(read_cursor(r.t.db).roots.at(root).baselined);
    CHECK(r.state(root) != kEmptyBaseline);
    CHECK(count_rows(r.t.db) == 1); // only the first-sight gap row
}

TEST_CASE("registry offline: the incomplete-walk warning fires once per transition into incomplete",
          "[echo][registry][lifecycle]") {
    yuzu::test::LogCapture logs;
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next();

    // incomplete, incomplete, complete, incomplete: two transitions into incomplete. An HKU
    // name-watch mark forces a walk on each tick.
    for (const bool complete : {false, false, true, false}) {
        r.f.offline_discovery.complete = complete;
        r.f.dirty->mark_hku();
        r.next();
        CHECK(r.config("registry_offline_discovery_incomplete") == (complete ? "0" : "1"));
    }
    logs.stop();
    const std::string text = logs.text();
    const std::string needle = "profile list could not be read completely";
    std::size_t warnings = 0;
    for (auto at = text.find(needle); at != std::string::npos; at = text.find(needle, at + 1))
        ++warnings;
    CHECK(warnings == 2);
    CHECK(r.f.offline_profile_calls == 5);          // the walk ran on every one of the five ticks
    CHECK(count_rows(r.t.db) == 0);                 // a failed walk is a status key and a log line
    CHECK(read_cursor(r.t.db).offline == std::vector<OfflineProfile>{prof(kSidA)}); // scope kept
}

TEST_CASE("registry offline: the deferred retry marker survives a source restart",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next(); // baselined at first sight
    r.tick_to(12);

    // the reconcile's mount is not attempted (an earlier mount this tick timed out)
    OfflineHiveRead skipped;
    skipped.attempted = false;
    skipped.reason = "offline:skipped_after_timeout";
    r.f.offline_reads[kSidA] = skipped;
    r.next();
    REQUIRE(r.f.offline_calls.size() == 2);
    const auto parked = read_cursor(r.t.db).roots.at(root);
    REQUIRE(parked.baselined);
    REQUIRE(parked.status == "complete");
    REQUIRE(parked.deferred); // the only thing that makes the root due before the next hour

    // A new source over the same database and reader. start() is not called: it would force a
    // reconcile and read the hive whatever the flag says.
    r.src = make_registry_cursor_source(RegistryScope{{}, {kSuffix}}, r.f.reader());
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 2)}});
    r.next(); // not a reconcile tick: the persisted flag alone makes the hive due
    CHECK(r.f.offline_calls.size() == 3);
    const auto after = read_cursor(r.t.db).roots.at(root);
    CHECK_FALSE(after.deferred);
    CHECK(after.baselined);
    CHECK(count_rows(r.t.db) == 1); // the change since the persisted baseline
    CHECK(q(r.t.db, "SELECT detail FROM registry_live").rows.at(0).at(0) == "attr:offline");

    r.next();
    CHECK(r.f.offline_calls.size() == 3); // back to hourly
}

TEST_CASE("registry offline: an empty complete discovery (an older build lists no logged-off profile) drops the roots without a removal storm, and the next walk that finds the profile re-baselines it silently",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next();
    REQUIRE(r.state(root) != kEmptyBaseline);
    REQUIRE(read_cursor(r.t.db).offline == std::vector<OfflineProfile>{prof(kSidA)});

    // An older build never lists a logged-off profile. An empty, complete discovery answer stands
    // in for it here (this drives collect(), not that build's code), so the roots leave scope
    // through the existing path and the cursor written has no `offline` field.
    r.tick_to(12);
    r.f.offline_discovery = OfflineDiscovery{};
    r.next();
    CHECK(read_cursor(r.t.db).roots.empty());
    CHECK(read_cursor(r.t.db).offline.empty());
    CHECK(r.state(root) == kEmptyBaseline); // shrunk, so a later logon cannot diff against it
    CHECK(count_rows(r.t.db) == 0);
    CHECK(q(r.t.db, "SELECT COUNT(*) FROM registry_live WHERE action = 'removed'")
             .rows.at(0).at(0) == "0");
    const auto cursor = r.t.db.get_cursor("registry");
    REQUIRE(cursor.has_value());
    REQUIRE(cursor->has_value());
    CHECK_FALSE(nlohmann::json::parse(**cursor).contains("offline"));

    // Walking again: the cursor holds no offline list, so the next ordinary tick walks, finds
    // the profile and baselines it from scratch, silently.
    r.f.offline_discovery.profiles = {prof(kSidA)};
    const auto calls = r.f.offline_calls.size();
    r.next();
    CHECK(r.f.offline_calls.size() == calls + 1);
    CHECK(read_cursor(r.t.db).offline == std::vector<OfflineProfile>{prof(kSidA)});
    CHECK(r.state(root) != kEmptyBaseline);
    CHECK(count_rows(r.t.db) == 0);
}

TEST_CASE("registry offline: a queue of logged-off hives cannot starve a loaded root, and the hive read longest ago is mounted first",
          "[echo][registry][lifecycle]") {
    OfflineRig r(RegistryScope{{"SOFTWARE\\yuzu_test_r"}, {kSuffix}});
    const std::vector<std::string> sids{"S-1-5-21-101", "S-1-5-21-102", "S-1-5-21-103",
                                        "S-1-5-21-104", "S-1-5-21-105", "S-1-5-21-106"};
    for (const auto& sid : sids) {
        r.f.offline_discovery.profiles.push_back(prof(sid));
        r.f.offline_reads[sid] = hive_read({{uroot(sid), uread(uroot(sid), 1)}});
    }
    r.f.reads[kRoot] = svc(1);
    r.f.offline_mount_cost = 6 * SEC; // two mounts fit the 10 s tick budget, a third does not

    const auto mounted_since = [&](std::size_t from) {
        std::vector<std::string> out;
        for (std::size_t i = from; i < r.f.offline_calls.size(); ++i)
            out.push_back(r.f.offline_calls[i].sid);
        return out;
    };
    const auto step = [&] {
        const auto from = r.f.offline_calls.size();
        r.next();
        return mounted_since(from);
    };
    using V = std::vector<std::string>;

    // First sight: two hives a tick; a deferred hive goes first next tick, the sid breaking ties.
    CHECK(step() == V{sids[0], sids[1]});
    CHECK(r.config("registry_offline_roots_deferred") == "4");
    CHECK(step() == V{sids[2], sids[3]});
    CHECK(r.config("registry_offline_roots_deferred") == "2");
    CHECK(step() == V{sids[4], sids[5]});
    CHECK(r.config("registry_offline_roots_deferred") == "0");
    r.tick_to(12);
    REQUIRE(r.f.offline_calls.size() == 6);

    // The hourly tick: a notified loaded root AND six hives due at once. With a rotation over one
    // list (start = tick % n) the walk began inside the hives, spent the budget on two mounts and
    // left the loaded root unread; now the loaded root is read first, in this tick.
    r.f.read_calls.clear();
    r.f.dirty->mark(kRoot, r.f.clock);
    CHECK(step() == V{sids[0], sids[1]}); // the two read longest ago, not the last two in the list
    CHECK(r.f.read_calls == V{kRoot});
    CHECK_FALSE(r.f.dirty->peek_dirty(kRoot)); // consumed, not left pinning the ETW floor
    CHECK(read_cursor(r.t.db).roots.at(kRoot).status == "complete");
    CHECK(r.config("registry_offline_roots_deferred") == "4"); // visible, not silent
    for (const auto& sid : {sids[2], sids[3], sids[4], sids[5]})
        CHECK(read_cursor(r.t.db).roots.at(uroot(sid)).deferred);

    // A profile that appears now, whose sid sorts AFTER the deferred ones, has never been read: it
    // queues behind the four deferred hives, and among the deferred the one never read goes first.
    const std::string fresh = "S-1-5-21-107";
    r.f.offline_discovery.profiles.push_back(prof(fresh));
    r.f.offline_reads[fresh] = hive_read({{uroot(fresh), uread(uroot(fresh), 1)}});
    r.f.dirty->mark_hku(); // a walk this tick finds it
    CHECK(step() == V{sids[2], sids[3]});          // deferred first, oldest read first
    CHECK(r.config("registry_offline_roots_deferred") == "3");
    CHECK(step() == V{fresh, sids[4]});            // never read beats read at the third tick; not sid order
    CHECK(r.config("registry_offline_roots_deferred") == "1");
    CHECK(step() == V{sids[5]});
    CHECK(r.config("registry_offline_roots_deferred") == "0");
    CHECK(step().empty());
    CHECK(count_rows(r.t.db) == 0);
}

TEST_CASE("registry offline: a Capped first read is not trusted - the hive is read again next tick and the complete read is a silent baseline",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    // The read ran out of time after the top key: it saw nothing of what the hive holds.
    SubtreeRead capped = complete({{root, {}}});
    capped.status = RegistryReadStatus::Capped;
    r.f.offline_reads[kSidA] = hive_read({{root, capped}});
    r.next();
    CHECK(r.f.offline_calls.size() == 1);
    CHECK_FALSE(read_cursor(r.t.db).roots.at(root).baselined);
    CHECK(read_cursor(r.t.db).roots.at(root).status == "capped");
    CHECK(r.config("registry_roots_capped") == "1");

    // Three values that were there all along, read completely on the NEXT ordinary tick.
    r.f.offline_reads[kSidA] = hive_read(
       {{root, complete({{root, {{"a", vread(4, dword(1))}, {"b", vread(4, dword(2))}, {"c", vread(4, dword(3))}}}})}});
    r.next();
    CHECK(r.f.offline_calls.size() == 2); // not the next hour
    CHECK(count_rows(r.t.db) == 0);       // pre-existing values are not `added`
    CHECK(read_cursor(r.t.db).roots.at(root).baselined);
    CHECK(read_cursor(r.t.db).roots.at(root).status == "complete");
    CHECK(r.config("registry_roots_capped") == "0");
    r.next();
    CHECK(r.f.offline_calls.size() == 2); // settled: hourly again
}

TEST_CASE("registry offline: a read that is Capped on an already-baselined hive is retried next tick and a persistently Capped one costs one mount a tick",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next();
    const auto baseline = r.state(root);
    r.tick_to(12);

    SubtreeRead capped = uread(root, 1);
    capped.status = RegistryReadStatus::Capped;
    r.f.offline_reads[kSidA] = hive_read({{root, capped}});
    r.next(); // the hourly read hits the cap
    REQUIRE(r.f.offline_calls.size() == 2);
    CHECK(read_cursor(r.t.db).roots.at(root).baselined); // the earlier baseline stands
    CHECK(r.state(root) == baseline);
    for (int i = 3; i <= 5; ++i) { // still Capped: one mount per tick, never more
        r.next();
        CHECK(r.f.offline_calls.size() == static_cast<std::size_t>(i));
    }
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next();
    CHECK(r.f.offline_calls.size() == 6);
    r.next();
    CHECK(r.f.offline_calls.size() == 6); // complete again: back to hourly
    CHECK(count_rows(r.t.db) == 0);
    CHECK(r.config("registry_roots_capped") == "0");
}

TEST_CASE("registry offline: a removal needs two agreeing complete walks, so a concurrent ProfileList change cannot drop a healthy profile",
          "[echo][registry][lifecycle]") {
    const auto listing = [](const std::string& sid) {
        OfflineDiscovery d;
        d.profiles = {prof(sid)};
        return d;
    };
    struct Case {
        const char* name;
        OfflineDiscovery second;
        bool kept;
        const char* incomplete;
    };
    OfflineDiscovery cut;
    cut.complete = false;
    for (const auto& c : {Case{"the second walk lists it", listing(kSidA), true, "0"},
                          Case{"the second walk omits it too", OfflineDiscovery{}, false, "0"},
                          Case{"the second walk is incomplete", cut, true, "1"}}) {
        INFO(c.name);
        OfflineRig r;
        const auto root = uroot(kSidA);
        r.f.offline_discovery.profiles = {prof(kSidA)};
        r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
        r.next();
        r.tick_to(12);
        const auto baseline = r.state(root);
        const int walks = r.f.offline_profile_calls;
        const int enumerations = r.f.loaded_sids_calls;

        // the hourly walk misses A (a rename in flight): complete, but wrong
        r.f.offline_discovery_queue = {OfflineDiscovery{}, c.second};
        r.next();
        CHECK(r.f.offline_profile_calls == walks + 2); // confirmed with ONE more walk
        CHECK(r.f.loaded_sids_calls == enumerations + 1); // the HKU snapshot is not retaken
        REQUIRE(r.f.offline_loaded_args.size() == static_cast<std::size_t>(walks) + 2);
        CHECK(r.f.offline_loaded_args[static_cast<std::size_t>(walks)] ==
              r.f.offline_loaded_args[static_cast<std::size_t>(walks) + 1]);
        CHECK(r.config("registry_offline_discovery_incomplete") == c.incomplete);
        CHECK(count_rows(r.t.db) == 0); // no removal storm either way
        if (c.kept) {
            CHECK(read_cursor(r.t.db).offline == std::vector<OfflineProfile>{prof(kSidA)});
            CHECK(r.state(root) == baseline);
            CHECK(r.f.offline_calls.size() == 2); // and the hourly read still happened
        } else {
            CHECK(read_cursor(r.t.db).roots.empty());
            CHECK(r.state(root) == kEmptyBaseline);
            CHECK(r.f.offline_calls.size() == 1);
        }

        // a walk that drops nothing is never repeated
        const int after = r.f.offline_profile_calls;
        r.f.dirty->mark_hku();
        r.next();
        CHECK(r.f.offline_profile_calls == after + 1);
    }
}

TEST_CASE("registry offline: an incomplete walk that lists a profile discovers it, and every tick walks at most once",
          "[echo][registry][lifecycle]") {
    // The walk is cut short on every tick (a host with more ProfileList entries than the cap), yet
    // the profile it does reach is read and baselined: incomplete means "do not remove", not "see nothing".
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery = OfflineDiscovery{false, {}, {prof(kSidA)}};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next();
    CHECK(r.config("registry_offline_discovery_incomplete") == "1");
    CHECK(read_cursor(r.t.db).offline == std::vector<OfflineProfile>{prof(kSidA)});
    CHECK(r.f.offline_calls.size() == 1);
    CHECK(r.state(root) != kEmptyBaseline);
    CHECK(count_rows(r.t.db) == 0);

    for (int i = 1; i <= 3; ++i) {
        r.next();
        CHECK(r.f.offline_profile_calls == 1 + i); // one walk a tick while it stays incomplete
        CHECK(r.f.offline_calls.size() == 1);      // but the hive is mounted hourly
    }
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 2)}});
    r.tick_to(12);
    r.next();
    CHECK(r.f.offline_calls.size() == 2);
    CHECK(count_rows(r.t.db) == 1); // the change is reported, as for any offline hive
}

TEST_CASE("registry offline: the empty-path deferral keeps the root's saved status and the unreadable counters",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.sids = {kSidA};
    r.f.reads[root] = uread(root, 1);
    r.next(); // loaded and baselined
    // the loaded root then becomes unreadable (status unreadable, baseline kept)
    SubtreeRead denied;
    denied.status = RegistryReadStatus::Unreadable;
    r.f.reads[root] = denied;
    r.f.dirty->mark(root, r.f.clock);
    r.next();
    REQUIRE(read_cursor(r.t.db).roots.at(root).status == "unreadable");
    REQUIRE(r.config("registry_roots_unreadable") == "1");
    const auto gaps = r.gap_unreadable_rows();

    // A logs off on a tick whose walk fails: no path, so no mount; the saved status must survive
    // this tick and the next unresolved ones, and the counters must keep saying so.
    r.f.sids.clear();
    r.f.offline_discovery = OfflineDiscovery{false, {}, {}};
    r.f.dirty->mark_hku();
    for (int i = 0; i < 3; ++i) {
        r.next();
        const auto cur = read_cursor(r.t.db);
        INFO("unresolved tick " << i);
        CHECK(cur.roots.at(root).status == "unreadable");
        CHECK(cur.roots.at(root).deferred);
        CHECK(r.config("registry_roots_unreadable") == "1");
        CHECK(r.config("registry_offline_roots_unreadable") == "1");
        CHECK(r.config("registry_offline_roots_deferred") == "1");
        CHECK(r.f.offline_calls.empty());
        CHECK(r.gap_unreadable_rows() == gaps);
    }
}

TEST_CASE("registry offline: a budget-deferred loaded root that then logs off is read at once, not at the next hour",
          "[echo][registry][lifecycle]") {
    const RegistryScope scope{{"SOFTWARE\\yuzu_test_r"}, {kSuffix}};
    OfflineRig r(scope);
    const auto root = uroot(kSidA);
    bool burn = false;
    auto reader = r.f.reader();
    auto read = reader.read_subtree;
    reader.read_subtree = [&r, &burn, read](const std::string& rt, std::int64_t deadline) {
        auto res = read(rt, deadline);
        if (burn)
            r.f.clock += kSnapshotBudget100ns + SEC; // the first read spends the whole budget
        return res;
    };
    r.src = make_registry_cursor_source(scope, std::move(reader));
    r.f.sids = {kSidA};
    r.f.reads[kRoot] = svc(1);
    r.f.reads[root] = uread(root, 1);
    r.next();
    r.next(); // two ticks done: the next walks the loaded roots from the first (tick 2 % 2 == 0)

    // both roots are notified; HKLM is read first and spends the budget, so A's root is deferred
    burn = true;
    r.f.dirty->mark(kRoot, r.f.clock);
    r.f.dirty->mark(root, r.f.clock);
    r.next();
    burn = false;
    REQUIRE(read_cursor(r.t.db).roots.at(root).status == "due");

    // A logs off: its root goes offline carrying `due`, which makes the hive due this very tick
    r.f.sids.clear();
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 2)}});
    r.f.dirty->mark_hku();
    r.next();
    CHECK(r.f.offline_calls.size() == 1);
    CHECK(read_cursor(r.t.db).roots.at(root).status == "complete");
}

TEST_CASE("registry offline: a sid in the loaded list that the cursor still lists as offline is treated as loaded (nobody was logged on, the name-watch mark was missed)",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next(); // nobody is logged on; A is a settled offline profile
    r.next();
    REQUIRE(r.f.offline_profile_calls == 1); // no walk on an ordinary tick: the cursor's list stands

    // A logs on, but the HKU name watch never fired. cur.hku is empty, so collect() re-enumerates
    // the loaded list anyway; A is then in both the loaded list and the cursor's offline list.
    r.f.sids = {kSidA};
    r.f.reads[root] = uread(root, 1);
    r.f.read_calls.clear();
    r.next();
    CHECK(r.f.offline_profile_calls == 1);                 // still no walk
    CHECK(r.f.offline_calls.size() == 1);                  // not mounted as an offline hive
    CHECK(r.f.read_calls == std::vector<std::string>{root}); // read as a loaded root, this tick
    CHECK(r.f.watch_calls.back() == std::vector<std::string>{root});
    CHECK(read_cursor(r.t.db).offline.empty());
    CHECK(r.config("registry_offline_roots") == "0");
}

TEST_CASE("registry offline: a stop mid-pass mounts no further hive and writes no row for it; a start clears it",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.src->stop(); // the agent is shutting down while a pass is about to mount
    r.next();
    CHECK(r.f.offline_calls.empty());
    CHECK(count_rows(r.t.db) == 0);
    CHECK(read_cursor(r.t.db).roots.at(root).deferred); // owed, so read the first tick after a start
    CHECK(r.config("registry_offline_roots_deferred") == "1");

    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.src->start(r.t.db);
    r.next();
    CHECK(r.f.offline_calls.size() == 1);
    CHECK_FALSE(read_cursor(r.t.db).roots.at(root).deferred);
    CHECK(r.state(root) != kEmptyBaseline);
}

TEST_CASE("registry offline: a restart does not mount a settled offline hive again - the restart reconcile is for loaded roots",
          "[echo][registry][lifecycle]") {
    OfflineRig r;
    const auto root = uroot(kSidA);
    r.f.offline_discovery.profiles = {prof(kSidA)};
    r.f.offline_reads[kSidA] = hive_read({{root, uread(root, 1)}});
    r.next();
    r.tick_to(3);
    REQUIRE(r.f.offline_calls.size() == 1);

    r.src = make_registry_cursor_source(RegistryScope{{}, {kSuffix}}, r.f.reader());
    r.src->start(r.t.db); // a persisted cursor: force_all_ makes the first tick a reconcile
    r.next();
    CHECK(r.f.offline_calls.size() == 1);   // no mount: it is not the hourly tick
    CHECK(r.f.offline_profile_calls == 2);  // the profile list IS re-walked (cheap, no mount)
    CHECK(r.state(root) != kEmptyBaseline);
}


// ═══════════════════════════════════════════════════════════════════════════
// [windows] live cases: the real key watch and the real Kernel-Registry ETW session.
// Writing HKLM and opening the session need an elevated token; each case SKIPs with a
// named reason otherwise, so a green run under a non-elevated task proves nothing --
// check the report says RUN.
// ═══════════════════════════════════════════════════════════════════════════
#ifdef _WIN32

namespace {

// Added to the source's clock for the ONE tick that finalises a change, so the settle
// interval elapses without a sleep. That tick reads nothing (nothing is dirty), so no
// window_base or read stamp ever carries the offset; it is reset straight after.
std::atomic<std::int64_t> g_clock_offset{0};

// Is this process's token elevated? The ETW cases SKIP when it is not, and FAIL when it is and
// the session still did not open, so a broken session can never pass as "not elevated".
bool is_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION e{};
    DWORD len = 0;
    const bool ok = GetTokenInformation(token, TokenElevation, &e, sizeof(e), &len) != 0;
    CloseHandle(token);
    return ok && e.TokenIsElevated != 0;
}

std::string salt() { return std::to_string(::GetCurrentProcessId()) + "_" + std::to_string(::GetTickCount64()); }

struct TestKey {
    std::wstring path; // below HKLM
    HKEY h{nullptr};
    explicit TestKey(const std::string& leaf) : path(L"SOFTWARE\\" + yuzu::win::to_wide(leaf)) {}
    LONG create() {
        return RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS,
                               nullptr, &h, nullptr);
    }
    ~TestKey() {
        if (h != nullptr)
            RegCloseKey(h);
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, path.c_str());
    }
};

// A registry symbolic-link key under `parent`. RegDeleteKeyW cannot delete one (it opens the
// subkey without REG_OPTION_OPEN_LINK, so it never reaches the link itself), and a surviving
// link makes the parent TestKey's RegDeleteTreeW fail, stranding the salted HKLM key for every
// later job on the shared CI identity. remove() opens the link AS the link and deletes it with
// ntdll's NtDeleteKey. It is idempotent, and the destructor calls it, so a REQUIRE that fails
// between the link's creation and the end of the test still removes it. Declare it AFTER the
// TestKey that owns `parent`, so it is destroyed first.
struct LinkKey {
    HKEY parent;
    std::wstring name;
    bool removed{false};
    LinkKey(HKEY p, std::wstring n) : parent(p), name(std::move(n)) {}
    LinkKey(const LinkKey&) = delete;
    LinkKey& operator=(const LinkKey&) = delete;
    ~LinkKey() { remove(); }

    // 0 on success, or when the link does not exist; else the Win32 error from the open or
    // the NTSTATUS from NtDeleteKey.
    LONG remove() {
        if (removed)
            return 0;
        HKEY h = nullptr;
        const LONG opened = RegOpenKeyExW(parent, name.c_str(), REG_OPTION_OPEN_LINK, DELETE, &h);
        if (opened == ERROR_FILE_NOT_FOUND) {
            removed = true;
            return 0;
        }
        if (opened != ERROR_SUCCESS)
            return opened;
        using NtDeleteKeyFn = LONG(NTAPI*)(HANDLE); // NTSTATUS is a LONG
        const auto nt_delete_key = reinterpret_cast<NtDeleteKeyFn>(
            reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDeleteKey")));
        const LONG status = nt_delete_key != nullptr ? nt_delete_key(h) : ERROR_PROC_NOT_FOUND;
        RegCloseKey(h); // the key goes when its last handle closes
        if (status == 0)
            removed = true;
        return status;
    }
};

// The production reader over the real mechanism, with a clock a test can step.
RegistryReader live_reader() {
    auto r = make_windows_registry_reader();
    auto inner = r.now_ts;
    r.now_ts = [inner] { return inner() + g_clock_offset.load(); };
    return r;
}

struct LiveRun {
    TestDb t = make_db();
    std::shared_ptr<RegistryDirtyTable> dirty;
    std::function<bool()> etw_running; // the reader's own answer: is the session delivering?
    std::string root;                  // the watched root, as the dirty table names it
    std::unique_ptr<RegistryCursorSource> src;
    explicit LiveRun(const std::string& hklm_root, bool etw = true) : root("HKLM\\" + hklm_root) {
        g_clock_offset = 0;
        auto reader = live_reader();
        if (!etw) { // the test seam: the session is treated as never having opened
            reader.start = [] {};
            reader.etw_running = [] { return false; };
        }
        dirty = reader.dirty;
        etw_running = reader.etw_running;
        src = make_registry_cursor_source(RegistryScope{{hklm_root}, {}}, std::move(reader));
        src->start(t.db);
    }
    ~LiveRun() { src->stop(); }

    // Write -> await the key-watch notification and, when asked, this write's own event
    // (the session is system-wide: "some event arrived" proves nothing) -> collect (the
    // read; the change is held) -> step the clock past the settle with nothing dirty ->
    // collect (the row lands).
    template <class Write>
    void transition(Write&& write, std::function<bool(const RegistryEtwEvent&)> await_event = {}) {
        write();
        REQUIRE(dirty->wait_dirty_for_test(root, std::chrono::steady_clock::now() + std::chrono::seconds(15)));
        if (await_event && etw_running())
            REQUIRE(src->buffer_for_test().wait_for_event(
               await_event, std::chrono::steady_clock::now() + std::chrono::seconds(15)));
        tick(t.db, *src);
        g_clock_offset = kEtwSettle100ns + SEC;
        tick(t.db, *src);
        g_clock_offset = 0;
    }
};

// This process's own write of `value`, as the session reports it.
std::function<bool(const RegistryEtwEvent&)> mine(std::string value, RegistryEtwOp op) {
    return [key = value_name_key(value), op](const RegistryEtwEvent& e) {
        return e.pid == ::GetCurrentProcessId() && e.op == op && e.value_key == key;
    };
}

} // namespace

TEST_CASE("registry live: set, change and delete through a pre-opened handle are attributed to this process",
          "[echo][registry][windows]") {
    const std::string leaf = "yuzu_test_reg_" + salt();
    TestKey key(leaf);
    if (key.create() != ERROR_SUCCESS)
        SKIP("cannot write HKLM (not elevated)");
    LiveRun run("SOFTWARE\\" + leaf); // the handle above was opened BEFORE start()
    tick(run.t.db, *run.src); // baseline
    if (std::stoi(run.t.db.get_config("registry_watch_roots", "0")) == 0)
        FAIL("the watch did not arm");
    if (const auto method = run.t.db.get_config("registry_capture_method", ""); method != "notify+etw") {
        if (is_elevated())
            FAIL("the token is elevated but the ETW session did not open: registry_capture_method="
                 << method);
        SKIP("ETW session unavailable (not elevated)");
    }

    DWORD one = 1, two = 2;
    run.transition([&] { RegSetValueExW(key.h, L"LiveVal", 0, REG_DWORD, reinterpret_cast<BYTE*>(&one), 4); },
                   mine("LiveVal", RegistryEtwOp::Set));
    run.transition([&] { RegSetValueExW(key.h, L"LiveVal", 0, REG_DWORD, reinterpret_cast<BYTE*>(&two), 4); },
                   mine("LiveVal", RegistryEtwOp::Set));
    run.transition([&] { RegDeleteValueW(key.h, L"LiveVal"); }, mine("LiveVal", RegistryEtwOp::DeleteValue));

    const auto rows = q(run.t.db, "SELECT action, data, prev_data, actor_pid, actor_image, detail, source "
                                  "FROM registry_live WHERE value_name = 'LiveVal' ORDER BY id");
    REQUIRE(rows.rows.size() == 3);
    CHECK(rows.rows[0][0] == "added");
    CHECK(rows.rows[0][1] == "1");
    CHECK(rows.rows[1][0] == "changed");
    CHECK(rows.rows[1][1] == "2");
    CHECK(rows.rows[1][2] == "1"); // prev
    CHECK(rows.rows[2][0] == "removed");
    CHECK(rows.rows[2][2] == "2");
    const auto me = std::to_string(::GetCurrentProcessId());
    for (const auto& r : rows.rows) {
        CHECK(r[3] == me); // this process wrote it
        CHECK_FALSE(r[4].empty());
        CHECK_THAT(r[5], ContainsSubstring("attr:corr"));
        CHECK(r[6] == "notify"); // the read was triggered by the key watch
    }
    CHECK(std::stoll(run.t.db.get_config("registry_attr_attributed", "0")) >= 3);
}

TEST_CASE("registry live: with the ETW leg disabled the same transitions land as attr:off",
          "[echo][registry][windows]") {
    const std::string leaf = "yuzu_test_reg_" + salt();
    TestKey key(leaf);
    if (key.create() != ERROR_SUCCESS)
        SKIP("cannot write HKLM (not elevated)");
    LiveRun run("SOFTWARE\\" + leaf, /*etw=*/false);
    tick(run.t.db, *run.src); // baseline
    DWORD v = 7;
    run.transition([&] { RegSetValueExW(key.h, L"OffVal", 0, REG_DWORD, reinterpret_cast<BYTE*>(&v), 4); });
    const auto rows = q(run.t.db, "SELECT actor_pid, actor_image, detail FROM registry_live "
                                  "WHERE value_name = 'OffVal'");
    REQUIRE(rows.rows.size() == 1);
    CHECK(rows.rows[0][0] == "0");
    CHECK(rows.rows[0][1].empty());
    CHECK(rows.rows[0][2] == "attr:off");
    CHECK(run.t.db.get_config("registry_capture_method", "") == "notify");
}

TEST_CASE("registry live: stop leaves no ETW session behind", "[echo][registry][windows]") {
    // ControlTraceW QUERY by name: success means the session exists.
    const auto session_exists = [] {
        const std::wstring name = registry_etw_session_name();
        std::vector<BYTE> buf(sizeof(EVENT_TRACE_PROPERTIES) + (name.size() + 1) * sizeof(wchar_t) + 1024, 0);
        auto* p = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
        p->Wnode.BufferSize = static_cast<ULONG>(buf.size());
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        return ControlTraceW(0, name.c_str(), p, EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS;
    };
    g_clock_offset = 0;
    auto reader = live_reader();
    auto etw_running = reader.etw_running;
    auto src = make_registry_cursor_source(RegistryScope{{"SOFTWARE\\yuzu_test_reg_none"}, {}}, std::move(reader));
    TestDb t = make_db();
    src->start(t.db); // ~RegistryCursorSource() stops the session even if a REQUIRE below throws
    if (!etw_running()) {
        if (is_elevated())
            FAIL("the token is elevated but the ETW session did not open");
        SKIP("ETW session unavailable (not elevated)");
    }
    REQUIRE(session_exists()); // the positive control: the lookup does find a running session
    // A collect samples the session's loss (ControlTraceW QUERY), which writes into the block the
    // STOP below reuses: STOP must follow a production QUERY, not a fresh start.
    tick(t.db, *src);
    src->stop();
    CHECK_FALSE(session_exists());
    CHECK_FALSE(etw_running());
    REQUIRE_NOTHROW(src->stop()); // idempotent
    CHECK_FALSE(session_exists());
}

TEST_CASE("registry live: a deleted and recreated root re-arms (R13)", "[echo][registry][windows]") {
    const std::string leaf = "yuzu_test_reg_" + salt();
    TestKey key(leaf);
    if (key.create() != ERROR_SUCCESS)
        SKIP("cannot write HKLM (not elevated)");
    LiveRun run("SOFTWARE\\" + leaf);
    tick(run.t.db, *run.src); // baseline
    DWORD v = 1;
    run.transition([&] { RegSetValueExW(key.h, L"Seed", 0, REG_DWORD, reinterpret_cast<BYTE*>(&v), 4); });
    RegCloseKey(key.h);
    key.h = nullptr;
    // Deleting the watched key is itself a notification (the delete signals the watch).
    run.transition([&] {
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, key.path.c_str());
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, key.path.c_str());
    }); // Absent: values and the key removed
    const auto removed = q(run.t.db, "SELECT COUNT(*) FROM registry_live WHERE action IN ('removed','key_removed')");
    CHECK(std::stoi(removed.rows[0][0]) >= 1);

    // Recreated: the root is unarmed, so this tick re-opens it and arms it again ...
    REQUIRE(key.create() == ERROR_SUCCESS);
    tick(run.t.db, *run.src);
    CHECK(run.t.db.get_config("registry_watch_roots_unarmed", "") == "0"); // armed again
    // ... and a write after that is reported by the key watch itself, not by a hand-made mark.
    run.transition([&] { RegSetValueExW(key.h, L"Again", 0, REG_DWORD, reinterpret_cast<BYTE*>(&v), 4); });
    CHECK(std::stoi(q(run.t.db, "SELECT COUNT(*) FROM registry_live WHERE value_name = 'Again' AND action = 'added'")
                       .rows[0][0]) == 1);
}

TEST_CASE("registry live: the reader returns Capped; reports denied children; sees a last-byte change and a 16383-character name (R8/R9)",
          "[echo][registry][windows]") {
    const std::string leaf = "yuzu_test_reg_" + salt();
    TestKey key(leaf);
    if (key.create() != ERROR_SUCCESS)
        SKIP("cannot write HKLM (not elevated)");
    auto reader = make_windows_registry_reader();
    const std::string root = "HKLM\\SOFTWARE\\" + leaf;

    // The longest legal value name (16383 characters) is read under its full name.
    const std::string long_name(16383, 'n');
    DWORD one = 1;
    REQUIRE(RegSetValueExW(key.h, yuzu::win::to_wide(long_name).c_str(), 0, REG_DWORD,
                           reinterpret_cast<BYTE*>(&one), 4) == ERROR_SUCCESS);
    const auto named = reader.read_subtree(root, reader.now_ts() + kSnapshotBudget100ns);
    REQUIRE(named.status == RegistryReadStatus::Complete);
    CHECK(named.keys.at(root).contains(long_name));

    // A 100 KiB binary changed only in its last byte: the stored size is equal, the hash differs.
    std::vector<BYTE> blob(100 * 1024, 0x41);
    RegSetValueExW(key.h, L"Blob", 0, REG_BINARY, blob.data(), static_cast<DWORD>(blob.size()));
    auto r1 = reader.read_subtree(root, reader.now_ts() + kSnapshotBudget100ns);
    blob.back() = 0x42;
    RegSetValueExW(key.h, L"Blob", 0, REG_BINARY, blob.data(), static_cast<DWORD>(blob.size()));
    auto r2 = reader.read_subtree(root, reader.now_ts() + kSnapshotBudget100ns);
    REQUIRE(r1.status == RegistryReadStatus::Complete);
    const auto d = diff_registry_snapshot(baseline_from_read(r1), r2, root, "notify", {0, 1}, 1);
    REQUIRE(d.candidates.size() == 1);
    CHECK(d.candidates[0].action == "changed");

    // An ACL-denied subkey hides only itself: the read stays Complete, names the denied key in
    // `skipped`, and still returns the root's own values and the readable sibling.
    HKEY open_key = nullptr;
    REQUIRE(RegCreateKeyExW(key.h, L"Open", 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &open_key, nullptr) ==
            ERROR_SUCCESS);
    DWORD seen = 5;
    RegSetValueExW(open_key, L"Seen", 0, REG_DWORD, reinterpret_cast<BYTE*>(&seen), 4);
    RegCloseKey(open_key);
    HKEY denied = nullptr;
    PSECURITY_DESCRIPTOR deny = nullptr;
    REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:PAI(D;;KR;;;WD)(A;;KA;;;SY)(A;;KA;;;BA)",
                                                                  SDDL_REVISION_1, &deny, nullptr));
    REQUIRE(RegCreateKeyExW(key.h, L"Denied", 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &denied, nullptr) ==
            ERROR_SUCCESS);
    RegSetKeySecurity(denied, DACL_SECURITY_INFORMATION, deny);
    LocalFree(deny);
    RegCloseKey(denied);
    const auto with_denied = reader.read_subtree(root, reader.now_ts() + kSnapshotBudget100ns);
    // restore access so the cleanup can delete the subtree
    PSECURITY_DESCRIPTOR allow = nullptr;
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:PAI(A;;KA;;;WD)", SDDL_REVISION_1, &allow,
                                                          nullptr);
    HKEY again = nullptr;
    if (RegOpenKeyExW(key.h, L"Denied", 0, WRITE_DAC, &again) == ERROR_SUCCESS) {
        RegSetKeySecurity(again, DACL_SECURITY_INFORMATION, allow);
        RegCloseKey(again);
    }
    LocalFree(allow);
    CHECK(with_denied.status == RegistryReadStatus::Complete);
    CHECK(with_denied.skipped == std::vector<std::string>{root + "\\Denied"});
    CHECK_FALSE(with_denied.keys.contains(root + "\\Denied"));
    CHECK(with_denied.keys.at(root).contains("Blob"));
    CHECK(with_denied.keys.at(root + "\\Open").contains("Seen"));

    // More subkeys than the key cap: Capped within the budget, not a stall.
    RegDeleteTreeW(key.h, L"Denied");
    for (std::size_t i = 0; i < kBaselineKeyCap + 10; ++i) {
        HKEY k = nullptr;
        if (RegCreateKeyExW(key.h, yuzu::win::to_wide("k" + std::to_string(i)).c_str(), 0, nullptr, 0,
                            KEY_READ, nullptr, &k, nullptr) != ERROR_SUCCESS)
            break;
        RegCloseKey(k);
    }
    const auto started = std::chrono::steady_clock::now();
    const auto capped = reader.read_subtree(root, reader.now_ts() + kSnapshotBudget100ns);
    CHECK(capped.status == RegistryReadStatus::Capped);
    CHECK(std::chrono::steady_clock::now() - started < std::chrono::seconds(30));
}

TEST_CASE("registry live: a symbolic-link key is read as the link and never followed",
          "[echo][registry][windows]") {
    const std::string leaf = "yuzu_test_reg_" + salt();
    TestKey key(leaf);
    if (key.create() != ERROR_SUCCESS)
        SKIP("cannot write HKLM (not elevated)");

    // Target holds a value the link must not expose.
    HKEY target = nullptr;
    REQUIRE(RegCreateKeyExW(key.h, L"Target", 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &target, nullptr) ==
            ERROR_SUCCESS);
    DWORD secret = 7;
    RegSetValueExW(target, L"Secret", 0, REG_DWORD, reinterpret_cast<BYTE*>(&secret), 4);
    RegCloseKey(target);

    // A volatile link key `Link` pointing at Target (the link's value is the NT path, no NUL).
    // The owner exists before the key does, so every exit path below removes the link.
    LinkKey link_key(key.h, L"Link");
    const std::wstring nt_target = L"\\Registry\\Machine\\" + key.path + L"\\Target";
    HKEY link = nullptr;
    REQUIRE(RegCreateKeyExW(key.h, L"Link", 0, nullptr, REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE,
                            KEY_ALL_ACCESS | KEY_CREATE_LINK, nullptr, &link, nullptr) == ERROR_SUCCESS);
    REQUIRE(RegSetValueExW(link, L"SymbolicLinkValue", 0, REG_LINK,
                           reinterpret_cast<const BYTE*>(nt_target.data()),
                           static_cast<DWORD>(nt_target.size() * sizeof(wchar_t))) == ERROR_SUCCESS);
    RegCloseKey(link);

    auto reader = make_windows_registry_reader();
    const std::string root = "HKLM\\SOFTWARE\\" + leaf;
    const auto r = reader.read_subtree(root, reader.now_ts() + kSnapshotBudget100ns);
    REQUIRE(r.status == RegistryReadStatus::Complete);
    // The link is a key of its own holding its SymbolicLinkValue ...
    REQUIRE(r.keys.contains(root + "\\Link"));
    const auto& link_values = r.keys.at(root + "\\Link");
    REQUIRE(link_values.contains("SymbolicLinkValue"));
    CHECK(link_values.at("SymbolicLinkValue").type == REG_LINK);
    // ... and what it points at is not read through it.
    CHECK_FALSE(link_values.contains("Secret"));
    CHECK(r.keys.at(root + "\\Target").contains("Secret")); // read once, as the key it is

    // Remove the link itself (as the link, never through it) before the parent's tree delete.
    REQUIRE(link_key.remove() == 0);
}

TEST_CASE("registry live: stop is idempotent and destruction after stop is clean",
          "[echo][registry][windows]") {
    {
        auto src = make_registry_cursor_source(RegistryScope{{"SOFTWARE\\yuzu_test_reg_none"}, {}},
                                         make_windows_registry_reader());
        TestDb t = make_db();
        src->start(t.db);
        REQUIRE_NOTHROW(src->stop());
        REQUIRE_NOTHROW(src->stop()); // idempotent
    } // ~RegistryCursorSource() after stop() must neither throw nor hang
}

TEST_CASE("registry live: a pid is named only if its process already existed when the event was stamped",
          "[echo][registry][windows]") {
    // This process always opens (PROCESS_QUERY_LIMITED_INFORMATION on itself), so no elevation is
    // needed. The FILETIME arithmetic and the GetProcessTimes call are what can be wrong, which
    // is why the boundary is driven through the real function and not a copy of its comparison.
    FILETIME created{}, exited{}, kernel{}, user{};
    REQUIRE(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user));
    const auto created_at = static_cast<std::int64_t>(
       (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime);
    constexpr std::int64_t kSlack = 1'000'000; // 100 ms: process_basename_for_pid's clock allowance
    const auto pid = ::GetCurrentProcessId();

    CHECK_FALSE(process_basename_for_pid(pid, 0).empty());                  // 0: unchecked
    CHECK_FALSE(process_basename_for_pid(pid, created_at).empty());         // stamped at creation
    CHECK_FALSE(process_basename_for_pid(pid, created_at - kSlack).empty()); // exactly the slack: named
    CHECK(process_basename_for_pid(pid, created_at - kSlack - 1).empty());   // past it: the pid was reused
}

// ── Offline (unloaded) hives: the real guarded mount ─────────────────────────
// A hive file is saved from a scratch HKCU key (RegSaveKeyExW under SeBackupPrivilege) and
// read back through the production read_offline_hive: the real with_user_hive ladder, the real
// default hive-file guard, the real bounded worker. Each case SKIPs, naming the reason, when the
// token cannot save or load a hive or the guard (correctly) refuses a fixture owned by an
// account outside its allow-set; the run that counts as evidence reports RUN, not SKIP.

namespace {

// A SID no real profile carries, salted per process (a fixed width, so no SID is a prefix of
// another): concurrent jobs on a shared runner never see each other's mounts (CLAUDE.md #1871).
const std::string& offline_fake_sid() {
    static const std::string sid = [] {
        const auto salted = 1'000'000'000u + yuzu::test::process_random_salt() % 3'000'000'000u;
        return "S-1-5-21-1-2-3-" + std::to_string(salted); // always 10 digits
    }();
    return sid;
}

// Any HKEY_USERS subkey CONTAINING the fake sid: the mount name is salted
// (unique_hive_mount_name), so an exact-name check would never see a leak.
bool offline_fake_mount_present() {
    for (const auto& n : yuzu::win::enumerate_hku_subkeys())
        if (n.find(offline_fake_sid()) != std::string::npos)
            return true;
    return false;
}

// Unconditional on every exit path: the shared box must never keep a mount of ours.
struct OfflineMountSweep {
    ~OfflineMountSweep() {
        if (!offline_fake_mount_present())
            return;
        const yuzu::win::PrivilegeScope restore(L"SeRestorePrivilege");
        const yuzu::win::PrivilegeScope backup(L"SeBackupPrivilege");
        for (const auto& n : yuzu::win::enumerate_hku_subkeys())
            if (n.find(offline_fake_sid()) != std::string::npos)
                RegUnLoadKeyW(HKEY_USERS, yuzu::win::to_wide(n).c_str());
    }
};

// A per-process-salted non-volatile HKCU scratch key, removed on exit.
struct ScratchHiveKey {
    std::wstring path;
    HKEY h{nullptr};
    ScratchHiveKey()
        : path(L"Software\\yuzu_test_regoff_" + yuzu::win::to_wide(salt())) {
        REQUIRE(RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr,
                                REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &h,
                                nullptr) == ERROR_SUCCESS);
    }
    ~ScratchHiveKey() {
        if (h != nullptr)
            RegCloseKey(h);
        RegDeleteTreeW(HKEY_CURRENT_USER, path.c_str());
    }
    ScratchHiveKey(const ScratchHiveKey&) = delete;
    ScratchHiveKey& operator=(const ScratchHiveKey&) = delete;
};

// stop() is idempotent and safe on a reader that never started.
struct ReaderStop {
    RegistryReader& r;
    ~ReaderStop() { r.stop(); }
};

} // namespace

TEST_CASE("registry live: an offline hive is mounted once through the guarded ladder, read under its logical name, and unloaded",
          "[echo][registry][windows]") {
    OfflineMountSweep sweep;
    ScratchHiveKey scratch;
    {
        yuzu::win::RegKey run;
        REQUIRE(RegCreateKeyExW(scratch.h, L"Software\\yuzu_test_u\\Run", 0, nullptr,
                                REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, run.put(),
                                nullptr) == ERROR_SUCCESS);
        const std::wstring v = L"1";
        REQUIRE(RegSetValueExW(run.get(), L"v", 0, REG_SZ,
                               reinterpret_cast<const BYTE*>(v.c_str()),
                               static_cast<DWORD>((v.size() + 1) * sizeof(wchar_t))) ==
                ERROR_SUCCESS);
    }
    yuzu::test::TempDir tmp("yuzu_test_regoffline_");
    fs::create_directories(tmp.path);
    {
        const yuzu::win::PrivilegeScope backup(L"SeBackupPrivilege");
        if (!backup.ok())
            SKIP("saving a mountable hive needs SeBackupPrivilege: not held here");
        const LONG rc = RegSaveKeyExW(scratch.h, (tmp.path / "NTUSER.DAT").c_str(), nullptr,
                                      REG_LATEST_FORMAT);
        if (rc == ERROR_PRIVILEGE_NOT_HELD)
            SKIP("RegSaveKeyExW: privilege not held");
        REQUIRE(rc == ERROR_SUCCESS);
    }
    const std::string profile = yuzu::win::from_wide(tmp.path.c_str());
    const std::string sid = offline_fake_sid();
    const std::string logical = "HKU\\" + sid + "\\Software\\yuzu_test_u\\Run";

    auto reader = make_windows_registry_reader();
    const ReaderStop stop{reader};
    const auto hv = reader.read_offline_hive(sid, profile, {logical}, reader.now_ts() + 60 * SEC);
    if (hv.reason == "offline:privilege_missing")
        SKIP("the offline arm needs SeBackupPrivilege and SeRestorePrivilege: not held here");
    if (hv.reason.starts_with("offline:hive_owner"))
        SKIP("the default guard refuses a fixture hive owned by an account outside its allow-set "
             "(run elevated)");
    if (hv.reason.starts_with("offline:hive_path_"))
        SKIP("the default guard refuses this runner's temp path (an 8.3 short name, a junction or a "
             "path deeper than the guard allows): run where TEMP is a plain fixed-drive path");
    INFO("reason=" << hv.reason);
    REQUIRE(hv.attempted);
    REQUIRE(hv.roots.contains(logical));
    const auto& rd = hv.roots.at(logical);
    REQUIRE(rd.status == RegistryReadStatus::Complete);
    REQUIRE(rd.keys.contains(logical));
    const auto& values = rd.keys.at(logical);
    REQUIRE(values.contains("v"));
    CHECK(values.at("v").type == 1); // REG_SZ
    CHECK(values.at("v").bytes == utf16("1"));
    for (const auto& [key, _] : rd.keys) { // labelled with the logical name, never the salted mount
        CHECK(key.starts_with("HKU\\" + sid + "\\"));
        CHECK(key.find("YUZU_HIVE") == std::string::npos);
    }
    CHECK_FALSE(offline_fake_mount_present());
    CHECK(g_mount_workers_in_flight.load() == 0);

    // The same hive read with a deadline that has already passed (a mount that landed late in the
    // tick budget, or waited behind a sibling plugin's hold of the offline-hive lock): the reader
    // answers Capped with nothing read, so the source must not keep it as a baseline (see
    // "a Capped first read is not trusted" above, which pins what the source does with that answer).
    const auto late = reader.read_offline_hive(sid, profile, {logical}, reader.now_ts() - SEC);
    INFO("late reason=" << late.reason);
    REQUIRE(late.attempted);
    REQUIRE(late.roots.contains(logical));
    CHECK(late.roots.at(logical).status == RegistryReadStatus::Capped);
    CHECK(late.roots.at(logical).keys.empty());
    CHECK_FALSE(offline_fake_mount_present());
    CHECK(g_mount_workers_in_flight.load() == 0);
}

TEST_CASE("registry live: a profile path with no NTUSER.DAT answers every root Unreadable with an offline: reason and leaves no mount",
          "[echo][registry][windows]") {
    OfflineMountSweep sweep;
    yuzu::test::TempDir tmp("yuzu_test_regoffline_empty_");
    fs::create_directories(tmp.path);
    const std::string profile = yuzu::win::from_wide(tmp.path.c_str());
    const std::string sid = offline_fake_sid();
    const std::string a = "HKU\\" + sid + "\\Software\\yuzu_test_u\\Run";
    const std::string b = "HKU\\" + sid + "\\Software\\yuzu_test_u\\RunOnce";

    auto reader = make_windows_registry_reader();
    const ReaderStop stop{reader};
    const auto hv = reader.read_offline_hive(sid, profile, {a, b}, reader.now_ts() + 60 * SEC);
    if (hv.reason == "offline:privilege_missing")
        SKIP("the offline arm needs SeBackupPrivilege and SeRestorePrivilege: not held here");
    INFO("reason=" << hv.reason);
    CHECK(hv.reason.starts_with("offline:"));
    CHECK(hv.reason != "offline:ok");
    for (const auto& root : {a, b}) {
        REQUIRE(hv.roots.contains(root));
        CHECK(hv.roots.at(root).status == RegistryReadStatus::Unreadable);
        CHECK(hv.roots.at(root).reason.starts_with("offline:"));
    }
    CHECK_FALSE(offline_fake_mount_present());
    CHECK(g_mount_workers_in_flight.load() == 0);
}

// Scoped owners for what process_user_sid() acquires: the process token and the LocalAlloc'd SID
// string (an allocating call between acquire and release must not leak either).
using TokenPtr = std::unique_ptr<void, decltype(&::CloseHandle)>;
using LocalPtr = std::unique_ptr<void, decltype(&::LocalFree)>;

// The SID of the account this process runs as.
static std::string process_user_sid() {
    HANDLE raw_token = nullptr;
    REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token));
    const TokenPtr token{raw_token, ::CloseHandle};
    DWORD len = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &len);
    std::vector<BYTE> buf(len);
    REQUIRE(GetTokenInformation(token.get(), TokenUser, buf.data(), len, &len));
    LPWSTR raw = nullptr;
    // Aligned cast: vector<BYTE>::data() is a heap block aligned to the default new alignment.
    REQUIRE(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &raw));
    const LocalPtr guard{raw, ::LocalFree};
    return yuzu::win::from_wide(raw);
}

TEST_CASE("registry live: the production profile discovery lists unloaded SID-named profiles with a path, and drops exactly the profile it is told is loaded",
          "[echo][registry][windows]") {
    auto reader = make_windows_registry_reader();
    const ReaderStop stop{reader};
    const auto loaded = yuzu::win::enumerate_hku_subkeys();
    const auto d = reader.offline_profiles(loaded);
    INFO("profiles=" << d.profiles.size() << " partial=" << d.partial.size());
    CHECK(d.complete); // a healthy host's ProfileList walk is complete
    const std::string self = process_user_sid();
    for (const auto& p : d.profiles) {
        INFO("sid=" << p.sid << " path=" << p.path);
        CHECK(is_user_hive_name(p.sid));
        CHECK_FALSE(is_virtual_service_sid(p.sid));
        CHECK_FALSE(p.path.empty());
        CHECK(std::find(loaded.begin(), loaded.end(), p.sid) == loaded.end()); // disjoint
        if (std::find(loaded.begin(), loaded.end(), self) != loaded.end())
            CHECK(p.sid != self); // this session's own hive is loaded: never offline
    }
    if (d.profiles.empty())
        SKIP("no unloaded profile with a recorded path on this host: there is nothing to tell the "
             "walk is loaded");

    // The argument is what decides: handed one more sid as loaded, the same walk loses exactly that
    // profile and keeps every other it listed (compared as sets, so a profile that appears between
    // the two walks on this shared box cannot fail the case).
    const std::string victim = d.profiles.front().sid;
    auto told = loaded;
    told.push_back(victim);
    const auto d2 = reader.offline_profiles(told);
    std::set<std::string> after;
    for (const auto& p : d2.profiles)
        after.insert(p.sid);
    CHECK_FALSE(after.contains(victim));
    for (const auto& p : d.profiles)
        if (p.sid != victim) {
            INFO("kept sid=" << p.sid);
            CHECK(after.contains(p.sid));
        }
}

#endif // _WIN32
